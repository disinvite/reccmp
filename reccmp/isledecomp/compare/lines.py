"""Database used to match (filename, line_number) pairs
between FUNCTION markers and PDB analysis."""

import logging
from typing import Iterable
from functools import cache
from pathlib import Path, PurePath, PureWindowsPath


logger = logging.getLogger(__name__)


def path_to_reverse_parts(path: PurePath) -> tuple[str, ...]:
    return tuple(p.lower() for p in path.parts)[::-1]


def score_match(remote_path: PurePath, local_path: PurePath) -> tuple[int, PurePath]:
    score = 0
    for rp, lp in zip(
        path_to_reverse_parts(remote_path), path_to_reverse_parts(local_path)
    ):
        if rp != lp or rp in (".", "..") or lp in (".", ".."):
            break

        score += 1

    return (score, local_path)


@cache
def purepath_to_path(
    remote_path: PurePath, local_paths: tuple[PurePath]
) -> PurePath | None:
    scored = [score_match(remote_path, p) for p in local_paths]
    scored.sort(reverse=True)

    if len(scored) >= 2:
        [(top_score, top_path), (next_score, _)] = scored[:2]
        # Return if this is the best match above all others
        if top_score > next_score:
            return top_path

    elif len(scored) == 1:
        (top_score, top_path) = scored[0]
        # Return only if we matched at least one part
        if top_score > 0:
            return top_path

    return None


class LinesDb:
    def __init__(self, code_files: list[str | Path]) -> None:
        self.code_files = tuple(map(Path, code_files))
        self.filenames: dict[str, list[Path]] = {}
        for path in self.code_files:
            self.filenames.setdefault(path.name.lower(), []).append(path)

        self.map: dict[Path, list[tuple[int, int]]] = {}

        self.functions: set[int] = set()

        self.functions_map: dict[Path, list[tuple[int, int]]] | None = None

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

        assert isinstance(sourcepath, Path)

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

        if self.functions_map is None:
            self.functions_map = {
                filename: [
                    (line, addr) for line, addr in pairs if addr in self.functions
                ]
                for filename, pairs in self.map.items()
            }

        # TODO: hack
        assert self.functions_map is not None

        # We might not capture the end line of a function. If not, search for the start line only.
        if line_end is None:
            line_end = line_start

        lines = self.functions_map.get(Path(path))
        if lines is None:
            return None

        lines.sort()

        possible_functions = [
            addr for (line_no, addr) in lines if line_start <= line_no <= line_end
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
