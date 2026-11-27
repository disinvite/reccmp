import os
import shutil
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

    def write(self, path: Path, text: str):
        path.write_text(text)

    def unlink(self, path: Path):
        path.unlink()

    def replace(self, src: Path, dst: Path):
        os.replace(src, dst)

    def mkdir(self, path: Path):
        path.mkdir()

    def rmtree(self, path: Path):
        shutil.rmtree(path)
