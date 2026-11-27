import asyncio
import contextlib
import enum
import logging
import traceback
from collections.abc import AsyncGenerator, Callable, Iterator
from pathlib import Path
from reccmp.project.detect import RecCmpProject, RecCmpTarget
from reccmp.remote.fswatch import (
    Stats,
    TargetFiles,
    changed_paths,
    is_stale,
    scan_target,
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


class WatchSession:
    def __init__(
        self,
        files: TargetFiles,
        reload: Callable[[], WatchEvent | None],
    ):
        self.files = files
        self.reload = reload
        self.stats: Stats = {}
        # The exe and pdb written since the last recompile.
        self.written: set[Path] = set()
        # CLAUDE SAYS: Loop time at which the written exe and pdb count as a
        # recompile, if no artifact changes before then.
        self.deadline: float | None = None

    def on_artifact(self, path: Path):
        self.deadline = None
        # Each changed path comes with true
        # if it is there, as writes will do.
        if path.exists():
            self.written.add(path)
            if self.written >= self.files.binaries:
                self.deadline = asyncio.get_running_loop().time() + ARTIFACT_DELAY_S
        else:
            self.written.discard(path)

    def on_change(self, path: Path) -> Iterator[WatchEvent]:
        if path in self.files.binaries:
            self.on_artifact(path)
            yield WatchEvent.ARTIFACT_CHANGED
        elif path in self.files.csvs:
            yield WatchEvent.DATA_CHANGED
        elif path in self.files.ymls:
            event = self.reload()
            if event is not None:
                yield event
            # CLAUDE SAYS: The client starts over from a config change, so it hears
            # again about code that is newer than the build.
            if event is WatchEvent.CONFIG_CHANGED and is_stale(self.files, self.stats):
                yield WatchEvent.CODE_CHANGED
        else:
            yield WatchEvent.CODE_CHANGED

    async def run(self) -> AsyncGenerator[WatchEvent, None]:
        # CLAUDE SAYS: The first scan comes before the staleness check. An edit
        # made before the scan is newer than the build, and one made after it
        # differs from the scan.
        self.stats = await asyncio.to_thread(scan_target, self.files)
        if is_stale(self.files, self.stats):
            yield WatchEvent.CODE_CHANGED

        loop = asyncio.get_running_loop()
        while True:
            await asyncio.sleep(POLL_S)
            old = self.stats
            self.stats = await asyncio.to_thread(scan_target, self.files)
            for path in sorted(changed_paths(old, self.stats)):
                logger.info("Change detected: %s", path)
                for event in self.on_change(path):
                    yield event

            # CLAUDE SAYS: The deadline is checked after the scan, so an
            # artifact written since the last scan restarts it first.
            if self.deadline is not None and loop.time() >= self.deadline:
                self.deadline = None
                self.written.clear()
                yield WatchEvent.RECOMPILED


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
            logger.exception("Failed to reload the project config")
            self.error = traceback.format_exc()
            return WatchEvent.CONFIG_FAILED

        if target == self.target and self.error is None:
            return None

        self.project = project
        self.target = target
        self.error = None
        return WatchEvent.CONFIG_CHANGED

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
