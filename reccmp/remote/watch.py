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
    BUILD_STALE = enum.auto()
    BUILD_CURRENT = enum.auto()
    DATA_CHANGED = enum.auto()
    CONFIG_CHANGED = enum.auto()
    CONFIG_FAILED = enum.auto()
    ARTIFACT_CHANGED = enum.auto()


@dataclass
class TargetFiles:
    """Collect resolved paths of related files for a reccmp target."""

    artifacts: set[Path]
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
            artifacts={
                target.recompiled_path.resolve(),
                target.recompiled_pdb.resolve(),
            },
            ymls={path.resolve() for path in ymls if path is not None},
            csvs={path.resolve() for path in target.data_sources},
            sources=tuple(path.resolve() for path in target.source_paths),
        )


FileSnapshot = dict[Path, tuple[int, int]]


def scan_target(files: TargetFiles) -> FileSnapshot:
    """CLAUDE SAYS: The mtime and size of each artifact, csv, yml, and code file
    under the sources that exists. A missing source path contributes no files."""
    snapshot: FileSnapshot = {}
    for path in (
        *files.artifacts,
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


def all_artifacts_updated(
    files: TargetFiles, last_build: FileSnapshot, snapshot: FileSnapshot
) -> bool:
    """CLAUDE SAYS: Whether the exe and pdb have both been written since last_build."""
    return all(
        path in snapshot and snapshot[path] != last_build.get(path)
        for path in files.artifacts
    )


def rebuild_required(files: TargetFiles, snapshot: FileSnapshot) -> bool:
    """Whether the code changed while nothing was watching, judged by mtime."""
    # A missing exe or pdb is older than every source file.
    if not files.artifacts <= snapshot.keys():
        return True

    oldest = min(snapshot[path][0] for path in files.artifacts)
    listed = files.artifacts | files.csvs | files.ymls
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

    def target_watchlist(self) -> TargetFiles:
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
        watchlist: TargetFiles | None = None
        snapshot: FileSnapshot = {}
        last_build: FileSnapshot = {}
        recompile_timeout: float | None = None

        while True:
            if watchlist is None:
                # Startup or reset: decide which files we need to watch.
                watchlist = self.target_watchlist()
                snapshot = await asyncio.to_thread(scan_target, watchlist)
                last_build = snapshot
                recompile_timeout = None

                # Decide whether we need to rebuild based on the
                # last modified date of each watched file.
                if rebuild_required(watchlist, snapshot):
                    yield WatchEvent.BUILD_STALE
                else:
                    yield WatchEvent.BUILD_CURRENT

            await asyncio.sleep(POLL_S)

            last_snapshot = snapshot
            snapshot = await asyncio.to_thread(scan_target, watchlist)

            changed = changed_paths(last_snapshot, snapshot)
            for path in sorted(changed):
                logger.info("Change detected: %s", path)

            # Batch all yml changes together.
            if changed & watchlist.ymls:
                event = self.reload()
                # If None: no real change to the target.
                if event is not None:
                    yield event

                if event is WatchEvent.CONFIG_CHANGED:
                    watchlist = None
                    continue

            for path in sorted(changed - watchlist.ymls):
                if path in watchlist.artifacts:
                    # Cancel pending recompile timer.
                    recompile_timeout = None

                    if all_artifacts_updated(watchlist, last_build, snapshot):
                        # Start (or restart) the countdown.
                        recompile_timeout = loop.time() + ARTIFACT_DELAY_S

                    yield WatchEvent.ARTIFACT_CHANGED

                elif path in watchlist.csvs:
                    yield WatchEvent.DATA_CHANGED

                else:
                    yield WatchEvent.BUILD_STALE

            # Artifact files are stable. Report a recompile.
            if recompile_timeout is not None and loop.time() >= recompile_timeout:
                recompile_timeout = None
                last_build = snapshot
                yield WatchEvent.BUILD_CURRENT
