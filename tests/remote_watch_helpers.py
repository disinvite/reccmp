import asyncio
import contextlib
import os
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from reccmp.remote.fswatch import TargetFiles


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

    def set_mtime(self, path: Path, seconds: int):
        os.utime(path, (seconds, seconds))


def first_after(events: AsyncIterator, action: Callable[[], None]):
    """The first item from a real watch, once the action has run."""

    async def run():
        async with contextlib.aclosing(events) as stream:
            pending = asyncio.ensure_future(anext(stream))
            await asyncio.sleep(0.1)
            action()
            return await pending

    return asyncio.run(asyncio.wait_for(run(), timeout=30))
