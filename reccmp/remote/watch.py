"""Monitoring the status of files for a target."""

import asyncio
import enum
import logging
import traceback
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from pathlib import Path
from reccmp.dir import source_code_search
from reccmp.project.common import RECCMP_USER_CONFIG
from reccmp.project.detect import RecCmpProject, RecCmpTarget

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


@dataclass
class TargetFiles:
    """Collect resolved paths of related files for a reccmp target."""

    binaries: set[Path]
    ymls: set[Path]
    csvs: set[Path]
    sources: tuple[Path, ...]

    @classmethod
    def from_target(cls, project: RecCmpProject, target: RecCmpTarget) -> "TargetFiles":
        ymls = [project.build_config_path]
        config = project.project_config_path
        if config is not None:
            # Watch for the user config even if it does not exist yet.
            ymls += [config, config.parent / RECCMP_USER_CONFIG]

        return cls(
            binaries={
                target.recompiled_path.resolve(),
                target.recompiled_pdb.resolve(),
            },
            ymls={path.resolve() for path in ymls if path is not None},
            csvs={path.resolve() for path in target.data_sources},
            sources=tuple(path.resolve() for path in target.source_paths),
        )


FileSnapshot = dict[Path, tuple[int, int]]


def scan_target(files: TargetFiles) -> FileSnapshot:
    """CLAUDE SAYS: The mtime and size of each binary, csv, yml, and code file
    under the sources that exists. A missing source path contributes no files."""
    snapshot: FileSnapshot = {}
    for path in (
        *files.binaries,
        *files.csvs,
        *files.ymls,
        *source_code_search(files.sources),
    ):
        try:
            st = path.stat()
        except FileNotFoundError:
            continue
        snapshot[path] = (st.st_mtime_ns, st.st_size)
    return snapshot


def changed_paths(old: FileSnapshot, new: FileSnapshot) -> set[Path]:
    """CLAUDE SAYS: The paths added, removed, or with a new mtime or size."""
    return {path for path in old.keys() | new.keys() if old.get(path) != new.get(path)}


def binaries_of(files: TargetFiles, snapshot: FileSnapshot) -> FileSnapshot:
    """CLAUDE SAYS: The exe and pdb entries of the snapshot."""
    return {path: snapshot[path] for path in files.binaries if path in snapshot}


def is_rebuilt(
    files: TargetFiles, last_build: FileSnapshot, snapshot: FileSnapshot
) -> bool:
    """CLAUDE SAYS: Whether the exe and pdb have both been written since last_build."""
    return all(
        path in snapshot and snapshot[path] != last_build.get(path)
        for path in files.binaries
    )


def is_stale(files: TargetFiles, snapshot: FileSnapshot) -> bool:
    """Whether the code changed while nothing was watching, judged by mtime."""
    # A missing exe or pdb is older than every source file.
    oldest = min(snapshot.get(path, (-1, 0))[0] for path in files.binaries)
    listed = files.binaries | files.csvs | files.ymls
    return any(
        st_mtime > oldest
        for path, (st_mtime, _) in snapshot.items()
        if path not in listed
    )


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
        # pylint: disable=too-many-branches
        loop = asyncio.get_running_loop()
        files: TargetFiles | None = None
        snapshot: FileSnapshot = {}
        # CLAUDE SAYS: The exe and pdb as of the last recompile.
        last_build: FileSnapshot = {}
        # CLAUDE SAYS: Loop time at which the exe and pdb count as a recompile,
        # if no artifact changes before then.
        deadline: float | None = None

        while True:
            if files is None:
                # CLAUDE SAYS: The first scan comes before the staleness check. An
                # edit made before the scan is newer than the build, and one made
                # after it differs from the scan.
                files = self.files()
                snapshot = await asyncio.to_thread(scan_target, files)
                last_build = binaries_of(files, snapshot)
                deadline = None
                if is_stale(files, snapshot):
                    yield WatchEvent.CODE_CHANGED

            await asyncio.sleep(POLL_S)
            old = snapshot
            snapshot = await asyncio.to_thread(scan_target, files)
            for path in sorted(changed_paths(old, snapshot)):
                logger.info("Change detected: %s", path)
                if path in files.binaries:
                    deadline = None
                    if is_rebuilt(files, last_build, snapshot):
                        deadline = loop.time() + ARTIFACT_DELAY_S
                    yield WatchEvent.ARTIFACT_CHANGED

                elif path in files.csvs:
                    yield WatchEvent.DATA_CHANGED

                elif path in files.ymls:
                    event = self.reload()
                    if event is not None:
                        yield event
                    if event is not WatchEvent.CONFIG_CHANGED:
                        continue
                    # CLAUDE SAYS: Start over only if the config change moved the
                    # files we watch. The rest of this scan is for the old files.
                    if self.files() != files:
                        files = None
                        break
                    # CLAUDE SAYS: The client starts over from a config change, so
                    # it hears again about code that is newer than the build.
                    if is_stale(files, snapshot):
                        yield WatchEvent.CODE_CHANGED

                else:
                    yield WatchEvent.CODE_CHANGED

            # CLAUDE SAYS: The deadline is checked after the scan, so an
            # artifact written since the last scan restarts it first.
            if files is not None and deadline is not None and loop.time() >= deadline:
                deadline = None
                last_build = binaries_of(files, snapshot)
                yield WatchEvent.RECOMPILED
