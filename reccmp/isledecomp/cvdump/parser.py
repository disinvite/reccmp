import re
from pathlib import PureWindowsPath
from typing import NamedTuple
from .types import CvdumpTypesParser
from .symbols import CvdumpSymbolsParser


# e.g. `     27 00034EC0     28 00034EE2     29 00034EE7     30 00034EF4`
_line_addr_pairs_findall = re.compile(r"\s+(?P<line_no>\d+) (?P<addr>[A-F0-9]{8})")

# We assume no spaces in the file name
# e.g. `  Z:\lego-island\isle\LEGO1\viewmanager\viewroi.cpp (None), 0001:00034E90-00034E97, line/addr pairs = 2`
_lines_subsection_header = re.compile(
    r"^\s*(?P<filename>\S+).*?, (?P<section>[A-F0-9]{4}):(?P<start>[A-F0-9]{8})-(?P<end>[A-F0-9]{8}), line/addr pairs = (?P<len>\d+)"
)

# e.g. `S_PUB32: [0001:0003FF60], Flags: 00000000, __read`
_publics_line_regex = re.compile(
    r"^(?P<type>\w+): \[(?P<section>\w{4}):(?P<offset>\w{8})], Flags: (?P<flags>\w{8}), (?P<name>\S+)"
)

# e.g. `         Debug start: 00000008, Debug end: 0000016E`
_gproc_debug_regex = re.compile(
    r"\s*Debug start: (?P<start>\w{8}), Debug end: (?P<end>\w{8})"
)

# e.g. `  00DA  0001:00000000  00000073  60501020`
_section_contrib_regex = re.compile(
    r"\s*(?P<module>\w{4})  (?P<section>\w{4}):(?P<offset>\w{8})  (?P<size>\w{8})  (?P<flags>\w{8})"
)

# e.g. `S_GDATA32: [0003:000004A4], Type:   T_32PRCHAR(0470), g_set`
_gdata32_regex = re.compile(
    r"S_GDATA32: \[(?P<section>\w{4}):(?P<offset>\w{8})\], Type:\s*(?P<type>\S+), (?P<name>.+)"
)

# e.g. 0003 "CMakeFiles/isle.dir/ISLE/res/isle.rc.res"
# e.g. 0004 "C:\work\lego-island\isle\3rdparty\smartheap\SHLW32MT.LIB" "check.obj"
_module_regex = re.compile(r"(?P<id>\w{4})(?: \"(?P<lib>.+?)\")?(?: \"(?P<obj>.+?)\")")


class LinesEntry(NamedTuple):
    """User functions only"""

    filename: str
    line_no: int
    section: int
    offset: int


class PublicsEntry(NamedTuple):
    """
    - Strings, vtables, functions
    - superset of everything else
    - only place you can find the C symbols (library functions, smacker, etc)
    """

    type: str
    section: int
    offset: int
    flags: int
    name: str


class SizeRefEntry(NamedTuple):
    """(Estimated) size of any symbol"""

    module: int
    section: int
    offset: int
    size: int


class GdataEntry(NamedTuple):
    """global variables"""

    section: int
    offset: int
    type: str
    name: str


class ModuleEntry(NamedTuple):
    id: int
    lib: str
    obj: str


class NodeKey(NamedTuple):
    section: int
    offset: int


class LineValue(NamedTuple):
    line_number: int
    section: int
    offset: int


class LinesFunction(NamedTuple):
    filename: PureWindowsPath
    section: int


class CvdumpParser:
    # pylint: disable=too-many-instance-attributes
    def __init__(self) -> None:
        self._lines_function = LinesFunction(PureWindowsPath(), 0)

        self.lines: dict[PureWindowsPath, list[LineValue]] = {}
        self.publics: list[PublicsEntry] = []
        self.sizerefs: list[SizeRefEntry] = []
        self.globals: list[GdataEntry] = []
        self.modules: list[ModuleEntry] = []

        self.types = CvdumpTypesParser()
        self.symbols_parser = CvdumpSymbolsParser()

    @property
    def symbols(self):
        return self.symbols_parser.symbols

    def _lines_section(self, line: str):
        """Parsing entries from the LINES section. We only care about the pairs of
        line_number and address and the subsection header to indicate which code file
        we are in."""

        # Subheader indicates a new function and possibly a new code filename.
        # Save the section here because it is not given on the lines that follow.
        if (match := _lines_subsection_header.match(line)) is not None:
            self._lines_function = LinesFunction(
                PureWindowsPath(match.group("filename")),
                int(match.group("section"), 16),
            )
            return

        # Match any pairs as we find them
        for line_no, offset in _line_addr_pairs_findall.findall(line):
            self.lines.setdefault(self._lines_function.filename, []).append(
                LineValue(int(line_no), self._lines_function.section, int(offset, 16))
            )

    def _publics_section(self, line: str):
        """Match each line from PUBLICS and pull out the symbol information.
        These are MSVC mangled symbol names. String constants and vtable
        addresses can only be found here."""
        if (match := _publics_line_regex.match(line)) is not None:
            self.publics.append(
                PublicsEntry(
                    type=match.group("type"),
                    section=int(match.group("section"), 16),
                    offset=int(match.group("offset"), 16),
                    flags=int(match.group("flags"), 16),
                    name=match.group("name"),
                )
            )

    def _globals_section(self, line: str):
        """S_PROCREF may be useful later.
        Right now we just want S_GDATA32 symbols because it is the simplest
        way to access global variables."""
        if (match := _gdata32_regex.match(line)) is not None:
            self.globals.append(
                GdataEntry(
                    section=int(match.group("section"), 16),
                    offset=int(match.group("offset"), 16),
                    type=match.group("type"),
                    name=match.group("name"),
                )
            )

    def _section_contributions(self, line: str):
        """Gives the size of elements across all sections of the binary.
        This is the easiest way to get the data size for .data and .rdata
        members that do not have a primitive data type."""
        if (match := _section_contrib_regex.match(line)) is not None:
            self.sizerefs.append(
                SizeRefEntry(
                    module=int(match.group("module"), 16),
                    section=int(match.group("section"), 16),
                    offset=int(match.group("offset"), 16),
                    size=int(match.group("size"), 16),
                )
            )

    def _modules_section(self, line: str):
        """Record the object file (and lib file, if used) linked into the binary.
        The auto-incrementing id is cross-referenced in SECTION CONTRIBUTIONS
        (and perhaps other locations)"""
        if (match := _module_regex.match(line)) is not None:
            self.modules.append(
                ModuleEntry(
                    id=int(match.group("id"), 16),
                    lib=match.group("lib"),
                    obj=match.group("obj"),
                )
            )

    def read_section(self, name: str, section: str):
        if name == "TYPES":
            self.types.read_all(section)

        elif name == "SYMBOLS":
            for line in section.splitlines():
                self.symbols_parser.read_line(line)

        elif name == "LINES":
            for line in section.splitlines():
                self._lines_section(line)

        elif name == "PUBLICS":
            for line in section.splitlines():
                self._publics_section(line)

        elif name == "SECTION CONTRIBUTIONS":
            for line in section.splitlines():
                self._section_contributions(line)

        elif name == "GLOBALS":
            for line in section.splitlines():
                self._globals_section(line)

        elif name == "MODULES":
            for line in section.splitlines():
                self._modules_section(line)
