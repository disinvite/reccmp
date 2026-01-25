import re
from pathlib import PureWindowsPath
from typing import NamedTuple
from reccmp.cvdump.analysis import CvdumpNode
from reccmp.types import EntityType


r_sections_header = re.compile(r" Start\s+Length\s+Name\s+Class\n")

r_symbol_name_header = re.compile(r"\n  Address         Publics by Value\n")
r_addr_public = re.compile(r"\s*(\w{4}):(\w{4})\s{7}(\S+)")

r_symbol_name_header_modern = re.compile(
    r"\n  Address         Publics by Value              Rva\+Base   Lib:Object\n"
)
r_addr_public_modern = re.compile(r"\s*(\w{4}):(\w{8})\s{7}(\S+)\s+\w+\s(.?)\s(\S+)")

r_line_number = re.compile(r"Line numbers for \S+\((\S+)\) segment (\S+)\n")
r_line_pairs = re.compile(r"(\d+) (\w{4}):(\w{4})")


class LineNumbers(NamedTuple):
    path: PureWindowsPath
    segment: str
    lines: list[tuple[tuple[int, int], int]]


class MsvcMap:
    nodes: dict[tuple[int, int], CvdumpNode]
    lines: list[LineNumbers]

    def get_node(self, seg_str: int, ofs_str: int) -> CvdumpNode:
        seg = int(seg_str, 16)
        ofs = int(ofs_str, 16)
        if (seg, ofs) in self.nodes:
            node = self.nodes[(seg, ofs)]
        else:
            node = CvdumpNode(seg, ofs)
            self.nodes[(seg, ofs)] = node

        return node

    def __init__(self, text: str):
        self.nodes = {}
        self.lines = []

        # MSVC 1.x (16-bit) format.
        if (match := r_symbol_name_header.search(text)) is not None:
            end = text.index("\n\n", match.end())
            symbols_text = text[match.end() : end]
            for section, offset, symbol in r_addr_public.findall(symbols_text):
                node = self.get_node(section, offset)
                node.decorated_name = symbol

        # MSVC 2.x+ (32-bit) format
        if (match := r_symbol_name_header_modern.search(text)) is not None:
            end = text.index("\n\n", match.end())
            symbols_text = text[match.end() : end]
            for (
                section,
                offset,
                symbol,
                func_flag,
                _,
            ) in r_addr_public_modern.findall(symbols_text):
                node = self.get_node(section, offset)
                node.decorated_name = symbol
                if func_flag == "f":
                    node.node_type = EntityType.FUNCTION

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
