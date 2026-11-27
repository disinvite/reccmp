"""Monitoring the status of files for a target."""

import asyncio
import logging
from collections.abc import AsyncGenerator, Iterable
from dataclasses import dataclass
from pathlib import Path
from reccmp.dir import source_code_search
from reccmp.project.common import RECCMP_USER_CONFIG
from reccmp.project.detect import RecCmpProject, RecCmpTarget

logger = logging.getLogger(__name__)


@dataclass
class TargetFiles:
    """Collect resolved paths of related files for a reccmp target."""

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


Stats = dict[Path, tuple[int, int]]


def stat_paths(paths: Iterable[Path]) -> Stats:
    """CLAUDE SAYS: The mtime and size of each path that exists."""
    stats: Stats = {}
    for path in paths:
        try:
            st = path.stat()
        except FileNotFoundError:
            continue
        stats[path] = (st.st_mtime_ns, st.st_size)
    return stats


def scan_target(files: TargetFiles) -> Stats:
    """CLAUDE SAYS: Stats for the binaries, csvs, ymls, and every code file under
    the sources. A missing source path contributes no files."""
    return stat_paths(
        [
            *files.binaries,
            *files.csvs,
            *files.ymls,
            *source_code_search(files.sources),
        ]
    )


class TargetPoller:
    """CLAUDE SAYS: Reports changes to a target's files by scanning them on an
    interval. A file that is added, removed, or has a new mtime or size since
    the previous scan counts as changed."""

    def __init__(self, files: TargetFiles, interval: float):
        self.files = files
        self.interval = interval
        self.stats: Stats = {}

    async def start(self) -> Stats:
        """CLAUDE SAYS: Returns the first scan. Changes made after it are
        reported by changes()."""
        self.stats = await asyncio.to_thread(scan_target, self.files)
        return self.stats

    async def changes(self) -> AsyncGenerator[set[Path], None]:
        while True:
            await asyncio.sleep(self.interval)
            new = await asyncio.to_thread(scan_target, self.files)
            old, self.stats = self.stats, new
            changed = {
                path
                for path in old.keys() | new.keys()
                if old.get(path) != new.get(path)
            }
            for path in sorted(changed):
                logger.info("Change detected: %s", path)
            if changed:
                yield changed


def is_stale(files: TargetFiles, stats: Stats) -> bool:
    """Whether the code changed while nothing was watching, judged by mtime."""
    # A missing exe or pdb is older than every source file.
    oldest = min(stats.get(path, (-1, 0))[0] for path in files.binaries)
    listed = files.binaries | files.csvs | files.ymls
    return any(
        st_mtime > oldest for path, (st_mtime, _) in stats.items() if path not in listed
    )
