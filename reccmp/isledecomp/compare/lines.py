"""Database used to match (filename, line_number) pairs
between FUNCTION markers and PDB analysis."""

import logging
from functools import cache
from pathlib import Path, PurePath, PureWindowsPath


logger = logging.getLogger(__name__)


def path_to_reverse_parts(path: PurePath) -> tuple[str, ...]:
    return tuple(p.lower() for p in path.parts)[::-1]


def score_match(purepath: PureWindowsPath, path: Path) -> tuple[int, Path]:
    score = 0
    for wp, rp in zip(path_to_reverse_parts(purepath), path_to_reverse_parts(path)):
        if wp != rp or wp == ".." or rp == "..":
            break

        score += 1

    return (score, path)


@cache
def purepath_to_path(purepath: PureWindowsPath, paths: tuple[Path]) -> Path | None:
    if not purepath.is_absolute():
        return None

    scored = [score_match(purepath, p) for p in paths]
    scored.sort(reverse=True)

    (_, path) = scored[0]
    return path


class LinesDb:
    def __init__(self, code_files: list[str | Path]) -> None:
        self.code_files = tuple(map(Path, code_files))
        self.filenames: dict[str, list[Path]] = {}
        for path in self.code_files:
            self.filenames.setdefault(path.name.lower(), []).append(path)

        self.map: dict[Path, dict[int, int]] = {}

    def add_line(self, cvdump_path: str, line_no: int, addr: int):
        """To be added from the LINES section of cvdump."""
        purepath = PureWindowsPath(cvdump_path)
        candidates = self.filenames.get(purepath.name.lower())
        if candidates is None:
            return

        # Convert to hashable type for caching
        sourcepath = purepath_to_path(purepath, tuple(candidates))
        if sourcepath is None:
            return

        self.map.setdefault(sourcepath, {})[line_no] = addr

    def search_line(
        self, path: str, line_start: int, line_end: int | None = None
    ) -> int | None:
        """The database contains the first line of each function, as verified by
        reducing the starting list of line-offset pairs using other information from the pdb.
        We want to know if exactly one function exists between line start and line end
        in the given file."""

        # We might not capture the end line of a function. If not, search for the start line only.
        if line_end is None:
            line_end = line_start

        bucket = self.map.get(Path(path))
        if bucket is None:
            return None

        lines = [*bucket.items()]
        lines.sort()

        possible_functions = [
            addr for (line, addr) in lines if line_start <= line <= line_end
        ]
        if len(possible_functions) == 1:
            return possible_functions[0]

        # The file has been edited since the last compile.
        if len(possible_functions) > 1:
            logger.error(
                "Debug data out of sync with function near: %s:%d",
                path,
                line_start,
            )
            return None

        # No functions matched. This could mean the file is out of sync, or that
        # the function was eliminated or inlined by compiler optimizations.
        logger.error(
            "Failed to find function symbol with filename and line: %s:%d",
            path,
            line_start,
        )
        return None
