"""Database used to match (filename, line_number) pairs
between FUNCTION markers and PDB analysis."""

import logging
from typing import Iterable
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

        self.map: dict[Path, list[tuple[int, int]]] = {}

        self.functions: set[int] = set()

    def add_lines(self, filename: str, lines: Iterable[tuple[int, int]]):
        """To be added from the LINES section of cvdump."""
        purepath = PureWindowsPath(filename)
        candidates = self.filenames.get(purepath.name.lower())
        if candidates is None:
            return

        # Convert to hashable type for caching
        sourcepath = purepath_to_path(purepath, tuple(candidates))
        if sourcepath is None:
            return

        self.map.setdefault(sourcepath, []).extend(lines)

    def add_function_starts(self, addrs: Iterable[int]):
        self.functions.update(addrs)

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

        lines = self.map.get(Path(path))
        if lines is None:
            return None

        lines.sort()

        possible_functions = [
            addr
            for (line_no, addr) in lines
            if addr in self.functions and line_start <= line_no <= line_end
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
