import re
from pathlib import PureWindowsPath
from typing import NamedTuple


r_sections_header = re.compile(r" Start\s+Length\s+Name\s+Class\n")
r_symbol_name_header = re.compile(r"\n  Address         Publics by Value\n")
r_addr_public = re.compile(r"\s*(\w{4}):(\w{4})\s{7}(\S+)")
r_line_number = re.compile(r"Line numbers for \S+\((\S+)\) segment (\S+)\n")
r_line_pairs = re.compile(r"(\d+) (\w{4}):(\w{4})")


class LineNumbers(NamedTuple):
    path: PureWindowsPath
    segment: str
    lines: list[tuple[tuple[int, int], int]]


class MsvcMap:
    symbols: dict[tuple[int, int], str]
    lines: list[LineNumbers]

    def __init__(self, text: str):
        self.symbols = {}
        self.lines = []

        if (match := r_symbol_name_header.search(text)) is not None:
            end = text.index("\n\n", match.end())
            symbols_text = text[match.end() : end]
            self.symbols = {
                (int(section, 16), int(offset, 16)): symbol
                for section, offset, symbol in r_addr_public.findall(symbols_text)
            }

        for match in r_line_number.finditer(text):
            end = text.index("\n\n", match.end())
            lines_text = text[match.end() : end]

            lines = [
                ((int(section, 16), int(offset, 16)), int(line_no))
                for line_no, section, offset in r_line_pairs.findall(lines_text)
            ]

            self.lines.append(
                LineNumbers(
                    path=PureWindowsPath(match.group(1)),
                    segment=match.group(2),
                    lines=lines,
                )
            )
