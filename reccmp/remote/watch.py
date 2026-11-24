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
import traceback
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from pathlib import Path
from reccmp.project.detect import RecCmpProject, RecCmpTarget
from reccmp.remote.fswatch import (
    TargetFiles,
    is_stale,
    wait_for_files,
    watch_presence,
    watch_streams,
)

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


async def watch_artifacts(
    changes: AsyncIterator[tuple[Path, bool]],
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
        async for path, exists in changes:
            if cooldown is not None:
                cooldown.cancel()
                cooldown = None
            if exists:
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
                watch_presence(self.files.binaries),
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

    async def raw_events(self) -> AsyncIterator[WatchEvent]:
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
                await wait_for_files(files, self.RETRY_MS / 1000)
                event = self.reload()
                if event is not None:
                    yield event

    async def events(self) -> AsyncIterator[WatchEvent]:
        async for raw in self.raw_events():
            event = self.tracker.step(raw)
            if event is not None:
                yield event
