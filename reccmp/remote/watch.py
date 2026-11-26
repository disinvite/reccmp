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
        retry every CONFIG_RETRY_S until the roots exist or a yml changes, then reload as in 1

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
            if both are in the written set, start (or restart) the ARTIFACT_DELAY_S cooldown
        on delete of exe or pdb:
            remove it from the written set
            abort the cooldown
            emit ARTIFACT_DELETED
        cooldown finishes (exe and pdb both written, then quiet for ARTIFACT_DELAY_S):
            emit RECOMPILED
            clear the written set

    3. watching csv files
        emit DATA_CHANGED

    4. watching code paths/files
        emit CODE_CHANGED

The build state machine that consumes these events is in reccmp.remote.server.
"""

import asyncio
import contextlib
import enum
import logging
import traceback
from collections.abc import AsyncGenerator, AsyncIterator, Awaitable, Callable
from pathlib import Path
from reccmp.project.detect import RecCmpProject, RecCmpTarget
from reccmp.remote.fswatch import (
    TargetFiles,
    is_stale,
    wait_for_files,
    watch_listed,
    watch_presence,
    watch_source_dirs,
)

logger = logging.getLogger(__name__)

ARTIFACT_DELAY_S = 1.0
"""Time delay until we report that a recompile has occurred. The compiler/linker
may write to the PDB incrementally. We don't want to report until this is
finished and the file is stable."""

CONFIG_RETRY_S = 1.0
"""Time delay between attempts to retry loading a reccmp target.
We will enter the retry loop if a watched directory is deleted or if we
cannot load the selected target from altered YML config files."""


class WatchEvent(enum.Enum):
    CODE_CHANGED = enum.auto()
    RECOMPILED = enum.auto()
    DATA_CHANGED = enum.auto()
    CONFIG_CHANGED = enum.auto()
    CONFIG_FAILED = enum.auto()
    ARTIFACT_CHANGED = enum.auto()
    ARTIFACT_DELETED = enum.auto()


class WatchSession:
    def __init__(
        self,
        files: TargetFiles,
        reload: Callable[[], WatchEvent | None],
    ):
        self.files = files
        self.reload = reload
        self.queue: asyncio.Queue[WatchEvent | Exception] = asyncio.Queue()
        self.ended = False

    def emit(self, item: WatchEvent | Exception):
        self.queue.put_nowait(item)

    async def watch_artifacts(self):
        loop = asyncio.get_running_loop()
        binaries = self.files.binaries
        # The exe and pdb written since the last recompile.
        written: set[Path] = set()
        cooldown: asyncio.TimerHandle | None = None

        def on_cooldown():
            written.clear()
            self.emit(WatchEvent.RECOMPILED)

        try:
            async for path, exists in watch_presence(binaries):
                if cooldown is not None:
                    cooldown.cancel()
                    cooldown = None
                if exists:
                    written.add(path)
                    self.emit(WatchEvent.ARTIFACT_CHANGED)
                    if written >= binaries:
                        cooldown = loop.call_later(ARTIFACT_DELAY_S, on_cooldown)
                else:
                    written.discard(path)
                    self.emit(WatchEvent.ARTIFACT_DELETED)
        finally:
            if cooldown is not None:
                cooldown.cancel()

    async def forward(self, stream: AsyncIterator[set[Path]]):
        async for changed in stream:
            for path in sorted(changed):
                if self.ended:
                    break
                if path in self.files.csvs:
                    self.emit(WatchEvent.DATA_CHANGED)
                elif path in self.files.ymls:
                    event = self.reload()
                    if event is not None:
                        self.emit(event)
                    self.ended = event is WatchEvent.CONFIG_CHANGED
                else:
                    self.emit(WatchEvent.CODE_CHANGED)

    async def guard(self, producer: Awaitable[None]):
        try:
            await producer
        except Exception as ex:  # pylint: disable=broad-exception-caught
            self.emit(ex)

    async def run(self) -> AsyncGenerator[WatchEvent, None]:
        """It names each path the streams report,
        and ends when config's changed its sort."""
        listed = watch_listed(self.files)
        source_dirs = watch_source_dirs(self.files)
        producers = [
            self.watch_artifacts(),
            self.forward(listed),
            self.forward(source_dirs),
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

    error: str | None
    """Traceback from the last failed config reload."""

    def __init__(self, project: RecCmpProject, target: RecCmpTarget):
        self.project = project
        self.target = target
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

    async def events(self) -> AsyncGenerator[WatchEvent, None]:
        while True:
            files = TargetFiles.from_target(self.project, self.target)
            session = WatchSession(files, self.reload)
            try:
                async with contextlib.aclosing(session.run()) as raws:
                    async for raw in raws:
                        yield raw
            except FileNotFoundError:
                yield self._fail("A watched path is missing")
                await wait_for_files(files, CONFIG_RETRY_S)
                event = self.reload()
                if event is not None:
                    yield event
