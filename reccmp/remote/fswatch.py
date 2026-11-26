"""Monitoring the status of files for a target."""

import asyncio
import os
from collections.abc import AsyncGenerator, Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from watchfiles import Change, awatch
from reccmp.dir import is_file_c_like, source_code_search
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


def verify_inodes(ids: dict[Path, int | None]):
    """Report if any stat() inodes have changed for any path.
    This will occur if a path is deleted then recreated at the same location.
    We are checking this to cover a gap in `watchfiles` monitoring: if we are watching for changes in a path
    and the path or any parent path is deleted, we can no longer see changes in that location.
    """
    for root, ino in ids.items():
        if ino is None or inode(root) != ino:
            raise FileNotFoundError(f"Watched path was removed or replaced: {root}")


def watch_roots(files: TargetFiles) -> set[Path]:
    return set(files.sources) | {
        path.parent for path in files.binaries | files.csvs | files.ymls
    }


async def watch_changes(
    roots: Iterable[Path], path_filter: Callable[[Path], bool], recursive: bool
) -> AsyncGenerator[set[Path], None]:
    """Yield the resolved paths that changed and pass the filter."""
    ids = {root: inode(root) for root in roots}
    verify_inodes(ids)
    if not ids:
        return

    def is_root_deleted(change: Change, path: Path) -> bool:
        return change == Change.deleted and path in ids

    # CLAUDE SAYS: Linux filesystems can hand a recreated directory the same
    # inode, so verify_inodes() alone misses it. inotify does report the
    # deletion of a watched root, so let that event through the filter.
    def keep(change: Change, raw: str) -> bool:
        path = Path(raw).resolve()
        return is_root_deleted(change, path) or path_filter(path)

    # The timeout's yield, though nothing's new,
    # lets us check the roots are true.
    async for changes in awatch(
        *ids,
        watch_filter=keep,
        recursive=recursive,
        yield_on_timeout=True,
    ):
        verify_inodes(ids)
        resolved = {(change, Path(path).resolve()) for change, path in changes}
        for change, path in resolved:
            if is_root_deleted(change, path):
                raise FileNotFoundError(f"Watched path was removed: {path}")
        if resolved:
            yield {path for _, path in resolved}


async def watch_files(paths: set[Path]) -> AsyncGenerator[set[Path], None]:
    """Watch the directories that hold the given files without recursion."""
    async for changed in watch_changes(
        {path.parent for path in paths}, lambda path: path in paths, recursive=False
    ):
        yield changed


async def watch_presence(paths: set[Path]) -> AsyncGenerator[tuple[Path, bool], None]:
    """Each changed path comes with true
    if it is there, as writes will do."""
    async for changed in watch_files(paths):
        for path in sorted(changed):
            yield path, path.exists()


# The source dirs are watched deep;
# the listed files, one level keep.


def watch_listed(files: TargetFiles) -> AsyncGenerator[set[Path], None]:
    for path in files.sources:
        if not path.exists():
            raise FileNotFoundError(f"Source path does not exist: {path}")
    # A file that's listed lives in its dir,
    # so saves that swap it won't lose the bit.
    listed = {
        path for path in files.sources if not path.is_dir() and is_file_c_like(path)
    }
    return watch_files(files.csvs | files.ymls | listed)


def watch_source_dirs(files: TargetFiles) -> AsyncGenerator[set[Path], None]:
    return watch_changes(
        tuple(path for path in files.sources if path.is_dir()),
        is_file_c_like,
        recursive=True,
    )


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


async def wait_for_files(files: TargetFiles, retry_seconds: float):
    """It waits until the roots are there,
    or till a yml's changed somewhere."""
    ymls = [mtime(path) for path in files.ymls]
    roots = watch_roots(files)
    while not all(root.exists() for root in roots):
        await asyncio.sleep(retry_seconds)
        if [mtime(path) for path in files.ymls] != ymls:
            return
