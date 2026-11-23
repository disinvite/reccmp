"""Detect changes to the files that make up a reccmp target.

inputs:
    0. staleness check, not part of the input stream
        stale = any code file newer than the oldest artifact
        a missing artifact counts as older than every code file
        runs in a worker thread (asyncio.to_thread); never blocks aiohttp
        runs at startup and after every CONFIG_CHANGED
        the watches start first and their events queue up; the stat result
        sets the build state before any queued event is applied

    each input below guards its own watched roots by inode.
    a root that is missing or replaced raises FileNotFoundError:
        emit CONFIG_FAILED
        retry every RETRY_MS until the roots exist or a yml changes, then reload as in 1

    1. watching yml config files
        on change, reload the project:
            exception:
                emit CONFIG_FAILED
            new target != old target, or previous state CONFIG_FAILED:
                restart the watches with the new paths, rerun 0
                emit CONFIG_CHANGED
            otherwise:
                nothing

    2. watching binary artifacts
        on write of exe or pdb:
            add it to the written set
            emit ARTIFACT_CHANGED
            if both are in the written set, start (or restart) the SETTLE_MS cooldown
        on delete of exe or pdb:
            remove it from the written set
            abort the cooldown
            emit ARTIFACT_DELETED
        cooldown finishes (exe and pdb both written, then quiet for SETTLE_MS):
            emit RECOMPILED
            clear the written set

    3. watching csv files
        emit DATA_CHANGED

    4. watching code paths/files
        emit CODE_CHANGED

state machine (no timing; inputs in, events out):
    build state: READY | STALE | PENDING | FAILED

    FAILED: drop everything except CONFIG_CHANGED and CONFIG_FAILED

    CODE_CHANGED       -> STALE; pass through
    ARTIFACT_CHANGED   -> PENDING; internal
    ARTIFACT_DELETED   -> PENDING; internal
    RECOMPILED         PENDING: -> READY; pass through
                       STALE: drop
    DATA_CHANGED       READY: pass through
                       otherwise: drop
    CONFIG_CHANGED     -> READY or STALE from 0; pass through
    CONFIG_FAILED      -> FAILED; pass through; error stays on watcher.error
"""

import asyncio
import contextlib
import enum
import logging
import os
import traceback
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from watchfiles import awatch
from reccmp.dir import is_file_c_like, source_code_search
from reccmp.project.common import RECCMP_USER_CONFIG
from reccmp.project.detect import RecCmpProject, RecCmpTarget

logger = logging.getLogger(__name__)


class WatchEvent(enum.Enum):
    CODE_CHANGED = enum.auto()
    RECOMPILED = enum.auto()
    DATA_CHANGED = enum.auto()
    CONFIG_CHANGED = enum.auto()
    CONFIG_FAILED = enum.auto()
    ARTIFACT_CHANGED = enum.auto()
    ARTIFACT_DELETED = enum.auto()


class BuildState(enum.Enum):
    READY = enum.auto()
    STALE = enum.auto()
    PENDING = enum.auto()
    FAILED = enum.auto()


class BuildTracker:
    """It hears the inputs, one by one,
    and passes what the server needs done."""

    state: BuildState

    def __init__(self):
        self.state = BuildState.READY

    @property
    def stale(self) -> bool:
        return self.state in (BuildState.STALE, BuildState.PENDING)

    def clear_stale(self):
        if self.state is BuildState.STALE:
            self.state = BuildState.READY

    def step(self, event: WatchEvent) -> WatchEvent | None:
        """Returns the event for the server, or None if it is dropped."""
        if event is WatchEvent.CONFIG_FAILED:
            self.state = BuildState.FAILED
        elif event is WatchEvent.CONFIG_CHANGED:
            # When watches start on paths anew,
            # the mtimes say if code is new.
            self.state = BuildState.READY
        elif self.state is BuildState.FAILED:
            return None
        elif event is WatchEvent.CODE_CHANGED:
            self.state = BuildState.STALE
        elif event in (WatchEvent.ARTIFACT_CHANGED, WatchEvent.ARTIFACT_DELETED):
            self.state = BuildState.PENDING
            return None
        elif event is WatchEvent.RECOMPILED:
            # The exe and pdb only count as a recompile if written after the code change.
            if self.state is not BuildState.PENDING:
                return None
            self.state = BuildState.READY
        elif event is WatchEvent.DATA_CHANGED and self.state is not BuildState.READY:
            # Wait for the recompile if there is one coming. The reset will read the data then.
            return None
        return event


@dataclass
class TargetFiles:
    """Resolved paths of the files that affect the reccmp results for one target."""

    binaries: set[Path]
    ymls: set[Path]
    csvs: set[Path]
    sources: tuple[Path, ...]

    @classmethod
    def from_target(cls, project: RecCmpProject, target: RecCmpTarget) -> "TargetFiles":
        ymls = {
            path.resolve()
            for path in (project.project_config_path, project.build_config_path)
            if path is not None
        }

        # Watch for the user config even if it does not exist yet.
        if project.project_config_path is not None:
            ymls.add(
                (project.project_config_path.parent / RECCMP_USER_CONFIG).resolve()
            )

        return cls(
            binaries={
                target.recompiled_path.resolve(),
                target.recompiled_pdb.resolve(),
            },
            ymls=ymls,
            csvs={path.resolve() for path in target.data_sources},
            sources=tuple(path.resolve() for path in target.source_paths),
        )


def inode(path: Path) -> int | None:
    try:
        return os.stat(path).st_ino
    except FileNotFoundError:
        return None


def check_watched(ids: dict[Path, int | None]):
    """awatch() goes quiet without an error when a watched directory is deleted,
    and stays quiet if the directory is created again."""
    for root, ino in ids.items():
        if ino is None or inode(root) != ino:
            raise FileNotFoundError(f"Watched path was removed or replaced: {root}")


def watch_roots(files: TargetFiles) -> set[Path]:
    return set(files.sources) | {
        path.parent for path in files.binaries | files.csvs | files.ymls
    }


async def watch_changes(
    roots: Iterable[Path], path_filter: Callable[[Path], bool], recursive: bool
) -> AsyncIterator[set[Path]]:
    """Yield the resolved paths that changed and pass the filter."""
    ids = {root: inode(root) for root in roots}
    check_watched(ids)
    if not ids:
        return

    # The timeout's yield, though nothing's new,
    # lets us check the roots are true.
    async for changes in awatch(
        *ids,
        watch_filter=lambda _, path: path_filter(Path(path).resolve()),
        recursive=recursive,
        yield_on_timeout=True,
    ):
        check_watched(ids)
        if changes:
            yield {Path(path).resolve() for _, path in changes}


async def watch_files(paths: set[Path]) -> AsyncIterator[set[Path]]:
    """Watch the directories that hold the given files without recursion."""
    async for changed in watch_changes(
        {path.parent for path in paths}, lambda path: path in paths, recursive=False
    ):
        yield changed


def watch_streams(files: TargetFiles) -> list[AsyncIterator[set[Path]]]:
    """The source dirs are watched deep;
    the listed files, one level keep."""
    for path in files.sources:
        if not path.exists():
            raise FileNotFoundError(f"Source path does not exist: {path}")
    # A file that's listed lives in its dir,
    # so saves that swap it won't lose the bit.
    source_dirs = tuple(path for path in files.sources if path.is_dir())
    listed = (
        files.csvs
        | files.ymls
        | {
            path
            for path in files.sources
            if path not in source_dirs and is_file_c_like(path)
        }
    )
    streams = [watch_files(listed)]
    if source_dirs:
        streams.append(watch_changes(source_dirs, is_file_c_like, recursive=True))
    return streams


def mtime(path: Path) -> int:
    """A file that's gone, we say instead,
    is older than the rest by a thread."""
    try:
        return path.stat().st_mtime_ns
    except FileNotFoundError:
        return -1


def is_stale(files: TargetFiles) -> bool:
    """Whether the code changed while nothing was watching, judged by mtime."""
    # A missing exe or pdb is older than every source file.
    oldest = min(mtime(path) for path in files.binaries)
    return any(mtime(path) > oldest for path in source_code_search(files.sources))


async def watch_artifacts(
    changes: AsyncIterator[set[Path]],
    binaries: set[Path],
    settle_seconds: float,
    emit: Callable[[WatchEvent], None],
):
    loop = asyncio.get_running_loop()
    # The exe and pdb written since the last recompile.
    written: set[Path] = set()
    cooldown: asyncio.TimerHandle | None = None

    def on_cooldown():
        written.clear()
        emit(WatchEvent.RECOMPILED)

    try:
        async for changed in changes:
            for path in sorted(changed):
                if cooldown is not None:
                    cooldown.cancel()
                    cooldown = None
                if path.exists():
                    written.add(path)
                    emit(WatchEvent.ARTIFACT_CHANGED)
                    if written >= binaries:
                        cooldown = loop.call_later(settle_seconds, on_cooldown)
                else:
                    written.discard(path)
                    emit(WatchEvent.ARTIFACT_DELETED)
    finally:
        if cooldown is not None:
            cooldown.cancel()


class WatchSession:
    def __init__(
        self,
        files: TargetFiles,
        reload: Callable[[], WatchEvent | None],
        settle_seconds: float,
    ):
        self.files = files
        self.reload = reload
        self.settle_seconds = settle_seconds
        self.queue: asyncio.Queue[WatchEvent | Exception] = asyncio.Queue()
        self.ended = False

    def emit(self, item: WatchEvent | Exception):
        self.queue.put_nowait(item)

    def on_changes(self, changed: set[Path]):
        for path in sorted(changed):
            if self.ended:
                return
            if path in self.files.csvs:
                self.emit(WatchEvent.DATA_CHANGED)
            elif path in self.files.ymls:
                self.on_yml()
            else:
                self.emit(WatchEvent.CODE_CHANGED)

    def on_yml(self):
        event = self.reload()
        if event is not None:
            self.emit(event)
        self.ended = event is WatchEvent.CONFIG_CHANGED

    async def forward(self, stream: AsyncIterator[set[Path]]):
        async for changed in stream:
            self.on_changes(changed)

    async def guard(self, producer: Awaitable[None]):
        try:
            await producer
        except Exception as ex:  # pylint: disable=broad-exception-caught
            self.emit(ex)

    async def run(
        self, streams: Iterable[AsyncIterator[set[Path]]]
    ) -> AsyncIterator[WatchEvent]:
        """It names each path the streams report,
        and ends when config's changed its sort."""
        producers = [
            watch_artifacts(
                watch_files(self.files.binaries),
                self.files.binaries,
                self.settle_seconds,
                self.emit,
            ),
            *(self.forward(stream) for stream in streams),
        ]
        # A timeout leaves the wait in place;
        # to cancel it would close the stream for good.
        tasks = [asyncio.create_task(self.guard(producer)) for producer in producers]
        try:
            # Each task, once it gets a turn,
            # has its watch in place to learn.
            await asyncio.sleep(0)
            if await asyncio.to_thread(is_stale, self.files):
                yield WatchEvent.CODE_CHANGED

            while True:
                item = await self.queue.get()
                if isinstance(item, Exception):
                    raise item
                yield item
                if item is WatchEvent.CONFIG_CHANGED:
                    return
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


class TargetWatcher:
    """Watches the files for a target and reports the changes that affect the reccmp results.
    Reloads the project config when a yml file changes."""

    project: RecCmpProject
    target: RecCmpTarget
    tracker: BuildTracker

    error: str | None
    """Traceback from the last failed config reload."""

    SETTLE_MS = 1000
    """The build is done when exe and pdb
    stay quiet for this long, you see."""

    RETRY_MS = 1000
    """A path is gone, so check this often
    to see if it's come back again."""

    def __init__(self, project: RecCmpProject, target: RecCmpTarget):
        self.project = project
        self.target = target
        self.tracker = BuildTracker()
        self.error = None

    def reload(self) -> WatchEvent | None:
        """Returns None if the target is the same and the last load did not fail."""
        assert self.project.build_config_path is not None
        try:
            project = RecCmpProject.from_directory(
                self.project.build_config_path.parent, alert=False
            )
            target = project.get(self.target.target_id)
        except Exception:  # pylint: disable=broad-exception-caught
            return self._fail("Failed to reload the project config")

        if target == self.target and self.error is None:
            return None

        self.project = project
        self.target = target
        self.error = None
        return WatchEvent.CONFIG_CHANGED

    def _fail(self, message: str) -> WatchEvent:
        logger.exception(message)
        self.error = traceback.format_exc()
        return WatchEvent.CONFIG_FAILED

    def _watch(
        self, files: TargetFiles, streams: Iterable[AsyncIterator[set[Path]]]
    ) -> AsyncIterator[WatchEvent]:
        session = WatchSession(files, self.reload, self.SETTLE_MS / 1000)
        return session.run(streams)

    async def _wait_for_files(self, files: TargetFiles):
        ymls = [mtime(path) for path in files.ymls]
        roots = watch_roots(files)
        while not all(root.exists() for root in roots):
            await asyncio.sleep(self.RETRY_MS / 1000)
            if [mtime(path) for path in files.ymls] != ymls:
                return

    async def _raw_events(self) -> AsyncIterator[WatchEvent]:
        while True:
            files = TargetFiles.from_target(self.project, self.target)
            try:
                async with contextlib.aclosing(
                    self._watch(files, watch_streams(files))
                ) as raws:
                    async for raw in raws:
                        yield raw
            except FileNotFoundError:
                yield self._fail("A watched path is missing")
                await self._wait_for_files(files)
                event = self.reload()
                if event is not None:
                    yield event

    async def events(self) -> AsyncIterator[WatchEvent]:
        async for raw in self._raw_events():
            event = self.tracker.step(raw)
            if event is not None:
                yield event
