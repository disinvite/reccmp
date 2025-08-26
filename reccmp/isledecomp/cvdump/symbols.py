from dataclasses import dataclass, field
import logging
import re
from typing import NamedTuple


logger = logging.getLogger(__name__)


class StackOrRegisterSymbol(NamedTuple):
    symbol_type: str
    location: str
    """Should always be set/converted to lowercase."""
    data_type: str
    name: str


class LdataEntry(NamedTuple):
    """local static variables"""

    section: int
    offset: int
    type: str
    name: str


# S_GPROC32 = functions
@dataclass
class SymbolsEntry:
    # pylint: disable=too-many-instance-attributes
    type: str
    section: int
    offset: int
    size: int
    func_type: str
    name: str
    stack_symbols: list[StackOrRegisterSymbol] = field(default_factory=list)
    static_variables: list[LdataEntry] = field(default_factory=list)
    frame_pointer_present: bool = False
    addr: int | None = None  # Absolute address. Will be set later, if at all


class CvdumpSymbolsParser:
    """Parser for cvdump output, SYMBOLS section."""

    _symbol_line_function_regex = re.compile(
        r"\[(?P<section>\w{4}):(?P<offset>\w{8})\], Cb: (?P<size>\w+), Type:\s+(?P<func_type>[^\s,]+), (?P<name>.+)"
    )
    """
    Parses the second part of a function symbol, e.g.
    `[0001:00034E90], Cb: 00000007, Type:             0x1024, ViewROI::IntrinsicImportance`
    """

    # the second part of e.g.
    _stack_register_symbol_regex = re.compile(
        r": (?P<location>[a-z]+|\[\w+\]), Type:\s+(?P<data_type>[\w()]+), (?P<name>.+)"
    )
    """
    Parses the second part of a stack or register symbol, e.g.
    `esi, Type:             0x1E14, this`
    """

    _debug_start_end_regex = re.compile(
        r"\s*Debug start: (?P<debug_start>\w+), Debug end: (?P<debug_end>\w+)"
    )

    _parent_end_next_regex = re.compile(
        r"\s*Parent: (?P<parent_addr>\w+), End: (?P<end_addr>\w+), Next: (?P<next_addr>\w+)"
    )

    _register_stack_symbols = ["S_BPREL32", "S_REGISTER"]

    """
    Parse the second part of static variable, e.g.
    `S_LDATA32: [0003:000004A4], Type:   T_32PRCHAR(0470), set`
    """
    _ldata32_regex = re.compile(
        r"\[(?P<section>\w{4}):(?P<offset>\w{8})\], Type:\s*(?P<type>\S+), (?P<name>.+)"
    )

    # List the unhandled types so we can check exhaustiveness
    _unhandled_symbols = [
        "S_COMPILE",
        "S_COMPILE2",
        "S_CONSTANT",
        "S_OBJNAME",
        "S_THUNK32",
        "S_LABEL32",
        "S_REGREL32",  # TODO: Seen as early as MSVC 7.00; might be relevant to Ghidra and/or stackcmp
        "S_UDT",
    ]

    def __init__(self):
        self.symbols: list[SymbolsEntry] = []
        self.current_function: SymbolsEntry | None = None
        # If we read an S_BLOCK32 node, increment this level.
        # This is so we do not end the proc early by reading an S_END
        # that indicates the end of the block.
        self.block_level: int = 0

    def read_register(self, leaf: str, symbol_type: str):
        if self.current_function is None:
            logger.error("Found stack/register outside of function: %s", leaf)
            return

        match = self._stack_register_symbol_regex.search(leaf)
        if match is None:
            logger.error("Invalid stack/register symbol: %s", leaf)
            return

        new_symbol = StackOrRegisterSymbol(
            symbol_type=symbol_type,
            location=match.group("location").lower(),
            data_type=match.group("data_type"),
            name=match.group("name"),
        )
        self.current_function.stack_symbols.append(new_symbol)

    def read_proc(self, leaf: str, symbol_type: str):
        match = self._symbol_line_function_regex.search(leaf)
        if match is None:
            logger.error("Invalid function symbol: %s", leaf)  # TODO: truncate
            return

        self.current_function = SymbolsEntry(
            type=symbol_type,
            section=int(match.group("section"), 16),
            offset=int(match.group("offset"), 16),
            size=int(match.group("size"), 16),
            func_type=match.group("func_type"),
            name=match.group("name"),
        )

        if self._parent_end_next_regex.search(leaf) is not None:
            # We do not need this info at the moment, might be useful in the future
            pass

        if self._debug_start_end_regex.search(leaf) is not None:
            # We do not need this info at the moment, might be useful in the future
            pass

        if "Flags: Frame Ptr Present" in leaf:
            self.current_function.frame_pointer_present = True

        self.symbols.append(self.current_function)

    def read_data(self, leaf: str):
        match = self._ldata32_regex.search(leaf)
        if match is None:
            return

        new_var = LdataEntry(
            section=int(match.group("section"), 16),
            offset=int(match.group("offset"), 16),
            type=match.group("type"),
            name=match.group("name"),
        )

        # An S_LDATA32 that appears between S_GPROC32 and S_END blocks then
        # we consider it to be a static variable from the enclosing function.
        # If S_LDATA32 appears outside a function, ignore it.
        if self.current_function is not None:
            self.current_function.static_variables.append(new_var)

    def read_all(self, text: str):
        r_module_start = re.compile(r"\n(?=\*{2} Module:)")
        r_sect_leaf = re.compile(r"\n(?=\(\w{6}\))")
        r_leaf_header = re.compile(r"\((?P<offset>\w{6})\)(?P<tab>\s+)(?P<type>S_\w+)")

        for module in r_module_start.split(text):
            for leaf in r_sect_leaf.split(module):
                if not leaf or leaf.startswith("**"):
                    continue

                match = r_leaf_header.match(leaf)
                if match is None:
                    logger.error("Symbols leaf not in expected format: %s", leaf)
                    continue

                symbol_type = match.group("type")

                if symbol_type in ("S_GPROC32", "S_LPROC32"):
                    self.read_proc(leaf, symbol_type)

                elif symbol_type in self._register_stack_symbols:
                    self.read_register(leaf, symbol_type)

                elif symbol_type == "S_LDATA32":
                    self.read_data(leaf)

                elif symbol_type == "S_BLOCK32":
                    self.block_level += 1

                elif symbol_type == "S_END":
                    if self.block_level > 0:
                        self.block_level = max(0, self.block_level - 1)
                    else:
                        self.current_function = None

                # i.e. if this is not one of the symbol types we choose to ignore for now:
                elif symbol_type not in self._unhandled_symbols:
                    logger.error("Unhandled symbol type: %s", leaf)  # TODO: truncate
