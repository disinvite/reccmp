import asyncio
import contextlib
import os
import shutil
from typing import Any
from collections.abc import AsyncGenerator, Callable
from pathlib import Path
from watchfiles import Change
from reccmp.remote.fswatch import TargetFiles


class FakeWatch:
    """CLAUDE SAYS: One running fake awatch. It queues each change under its roots
    that passes its filter."""

    def __init__(self, roots: tuple[Path, ...], watch_filter, recursive: bool):
        self.roots = roots
        self.watch_filter = watch_filter
        self.recursive = recursive
        self.changes: asyncio.Queue[tuple[Change, str]] = asyncio.Queue()

    def covers(self, path: Path) -> bool:
        if path in self.roots:
            return True
        if self.recursive:
            return any(root in path.parents for root in self.roots)
        return path.parent in self.roots

    def send(self, change: Change, path: Path):
        if self.covers(path) and self.watch_filter(change, str(path)):
            self.changes.put_nowait((change, str(path)))

    async def batch(self) -> set[tuple[Change, str]]:
        """CLAUDE SAYS: Every change queued by the time the watch resumes."""
        batch = {await self.changes.get()}
        while not self.changes.empty():
            batch.add(self.changes.get_nowait())
        return batch


class DiskTarget:
    """Real files for a target, with mtimes set by hand."""

    def __init__(self, root: Path):
        self.exe = root / "build" / "ISLE.EXE"
        self.pdb = root / "build" / "ISLE.PDB"
        self.csv = root / "project" / "isle.csv"
        self.code = root / "project" / "src" / "isle.cpp"
        # The code goes first, so the build starts up to date.
        for path in (self.code, self.csv, self.exe, self.pdb):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("")
        self.files = TargetFiles(
            binaries={self.exe, self.pdb},
            ymls=set(),
            csvs={self.csv},
            sources=(self.code.parent,),
        )
        self.watches: list[FakeWatch] = []

    def set_mtime(self, path: Path, seconds: int):
        os.utime(path, (seconds, seconds))

    async def awatch(
        self, *roots: Path, watch_filter, recursive: bool, yield_on_timeout: bool
    ):
        """CLAUDE SAYS: Stands in for watchfiles.awatch. It sees only the changes
        made through this DiskTarget."""
        assert yield_on_timeout
        watch = FakeWatch(roots, watch_filter, recursive)
        self.watches.append(watch)
        try:
            while True:
                yield await watch.batch()
        finally:
            self.watches.remove(watch)

    def changed(self, change: Change, path: Path):
        for watch in self.watches:
            watch.send(change, path)

    def write(self, path: Path, text: str):
        change = Change.modified if path.exists() else Change.added
        path.write_text(text)
        self.changed(change, path)

    def unlink(self, path: Path):
        path.unlink()
        self.changed(Change.deleted, path)

    def replace(self, src: Path, dst: Path):
        os.replace(src, dst)
        self.changed(Change.deleted, src)
        self.changed(Change.added, dst)

    def mkdir(self, path: Path):
        path.mkdir()
        self.changed(Change.added, path)

    def rmtree(self, path: Path):
        removed = [*path.rglob("*"), path]
        shutil.rmtree(path)
        for gone in removed:
            self.changed(Change.deleted, gone)


def first_after(events: AsyncGenerator[Any, None], action: Callable[[], object]):
    """The first item from a real watch, once the action has run."""

    async def run():
        async with contextlib.aclosing(events) as stream:
            pending = asyncio.create_task(anext(stream))
            await asyncio.sleep(0.1)
            action()
            return await pending

    return asyncio.run(asyncio.wait_for(run(), timeout=30))
