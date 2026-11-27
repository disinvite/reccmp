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
    TargetPoller,
    is_stale,
)

logger = logging.getLogger(__name__)

ARTIFACT_DELAY_S = 1.0
"""Time delay until we report that a recompile has occurred. The compiler/linker
may write to the PDB incrementally. We don't want to report until this is
finished and the file is stable."""

POLL_S = 0.25
"""Time delay between scans of the target's files."""


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
        self.poller = TargetPoller(files, POLL_S)
        self.queue: asyncio.Queue[WatchEvent | Exception] = asyncio.Queue()
        # The exe and pdb written since the last recompile.
        self.written: set[Path] = set()
        self.cooldown: asyncio.TimerHandle | None = None

    def emit(self, item: WatchEvent | Exception):
        self.queue.put_nowait(item)

    def cancel_cooldown(self):
        if self.cooldown is not None:
            self.cooldown.cancel()
            self.cooldown = None

    def on_cooldown(self):
        self.cooldown = None
        self.written.clear()
        self.emit(WatchEvent.RECOMPILED)

    def on_artifact(self, path: Path):
        self.cancel_cooldown()
        # Each changed path comes with true
        # if it is there, as writes will do.
        if path.exists():
            self.written.add(path)
            self.emit(WatchEvent.ARTIFACT_CHANGED)
            if self.written >= self.files.binaries:
                # CLAUDE SAYS: A change made during the cooldown is reported up
                # to one scan late, so the cooldown waits that much longer.
                loop = asyncio.get_running_loop()
                self.cooldown = loop.call_later(
                    ARTIFACT_DELAY_S + POLL_S, self.on_cooldown
                )
        else:
            self.written.discard(path)
            self.emit(WatchEvent.ARTIFACT_DELETED)

    def on_config(self):
        event = self.reload()
        if event is not None:
            self.emit(event)
        # CLAUDE SAYS: The client starts over from a config change, so it hears
        # again about code that is newer than the build.
        if event is WatchEvent.CONFIG_CHANGED and is_stale(
            self.files, self.poller.stats
        ):
            self.emit(WatchEvent.CODE_CHANGED)

    async def forward(self, stream: AsyncIterator[set[Path]]):
        async for changed in stream:
            for path in sorted(changed):
                if path in self.files.binaries:
                    self.on_artifact(path)
                elif path in self.files.csvs:
                    self.emit(WatchEvent.DATA_CHANGED)
                elif path in self.files.ymls:
                    self.on_config()
                else:
                    self.emit(WatchEvent.CODE_CHANGED)

    async def guard(self, producer: Awaitable[None]):
        try:
            await producer
        except Exception as ex:  # pylint: disable=broad-exception-caught
            self.emit(ex)

    async def run(self) -> AsyncGenerator[WatchEvent, None]:
        # CLAUDE SAYS: The first scan comes before the staleness check. An edit
        # made before the scan is newer than the build, and one made after it
        # differs from the scan.
        stats = await self.poller.start()
        # A timeout leaves the wait in place;
        # to cancel it would close the stream for good.
        task = asyncio.create_task(self.guard(self.forward(self.poller.changes())))
        try:
            if is_stale(self.files, stats):
                yield WatchEvent.CODE_CHANGED

            while True:
                item = await self.queue.get()
                if isinstance(item, Exception):
                    raise item
                yield item
        finally:
            self.cancel_cooldown()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


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

    def files(self) -> TargetFiles:
        return TargetFiles.from_target(self.project, self.target)

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
            files = self.files()
            session = WatchSession(files, self.reload)
            async with contextlib.aclosing(session.run()) as raws:
                async for raw in raws:
                    yield raw
                    # CLAUDE SAYS: Start a new session only if the config
                    # change moved the files we watch.
                    if raw is WatchEvent.CONFIG_CHANGED and self.files() != files:
                        break
