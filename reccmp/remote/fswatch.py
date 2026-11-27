"""Monitoring the status of files for a target."""

from dataclasses import dataclass
from pathlib import Path
from reccmp.dir import source_code_search
from reccmp.project.common import RECCMP_USER_CONFIG
from reccmp.project.detect import RecCmpProject, RecCmpTarget


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


Stats = dict[Path, tuple[int, int]]


def scan_target(files: TargetFiles) -> Stats:
    """CLAUDE SAYS: The mtime and size of each binary, csv, yml, and code file
    under the sources that exists. A missing source path contributes no files."""
    stats: Stats = {}
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
        stats[path] = (st.st_mtime_ns, st.st_size)
    return stats


def changed_paths(old: Stats, new: Stats) -> set[Path]:
    """CLAUDE SAYS: The paths added, removed, or with a new mtime or size."""
    return {path for path in old.keys() | new.keys() if old.get(path) != new.get(path)}


def is_stale(files: TargetFiles, stats: Stats) -> bool:
    """Whether the code changed while nothing was watching, judged by mtime."""
    # A missing exe or pdb is older than every source file.
    oldest = min(stats.get(path, (-1, 0))[0] for path in files.binaries)
    listed = files.binaries | files.csvs | files.ymls
    return any(
        st_mtime > oldest for path, (st_mtime, _) in stats.items() if path not in listed
    )
