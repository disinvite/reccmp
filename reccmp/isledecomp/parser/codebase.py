"""For aggregating decomp markers read from an entire directory and for a single module."""

from pathlib import Path, PurePath
from typing import Callable, Iterator
from .parser import DecompParser
from .node import (
    ParserLineSymbol,
    ParserSymbol,
    ParserFunction,
    ParserVtable,
    ParserVariable,
    ParserString,
)


class DecompCodebase:
    files: dict[PurePath, str]
    symbols: dict[PurePath, list[ParserSymbol]]
    module: str

    def __init__(self, module: str) -> None:
        self.module = module
        self.files = {}
        self.symbols = {}

    def set_file(self, path: Path, text: str):
        self.files[path] = text

        parser = DecompParser()
        parser.reset_and_set_filename(str(path))
        parser.read(text)

        self.symbols[path] = list(parser.iter_symbols(self.module))

    def read_file(self, path: Path):
        with open(path, "r", encoding="utf-8") as f:
            self.set_file(path, f.read())

    def iter_symbols(self) -> Iterator[ParserSymbol]:
        """To keep order consistent, sort paths and return symbols from each"""
        paths = sorted(self.symbols.keys())
        for path in paths:
            yield from iter(self.symbols[path])

    def prune_invalid_addrs(
        self, is_valid: Callable[[int], bool]
    ) -> list[ParserSymbol]:
        """Some decomp annotations might have an invalid address.
        Return the list of addresses where we fail the is_valid check,
        and remove those from our list of symbols."""
        invalid_symbols = []

        for path, symbols in self.symbols.items():
            invalid_symbols.extend([sym for sym in symbols if not is_valid(sym.offset)])
            self.symbols[path] = [sym for sym in symbols if is_valid(sym.offset)]

        return invalid_symbols

    def prune_reused_addrs(self) -> list[ParserSymbol]:
        """We are focused on annotations for a single module, so each address should be used only once.
        Keep only the first occurrence of an address and discard the others.
        Return the duplicates in a list for error reporting."""
        used_addr = set()
        duplicates = []

        for path, symbols in self.symbols.items():
            unique = []

            for s in symbols:
                if s.offset in used_addr:
                    duplicates.append(s)
                else:
                    unique.append(s)
                    used_addr.add(s.offset)

            self.symbols[path] = unique

        return duplicates

    def iter_line_functions(self) -> Iterator[ParserFunction]:
        """Return lineref functions separately from nameref. Assuming the PDB matches
        the state of the source code, a line reference is a guaranteed match, even if
        multiple functions share the same name. (i.e. polymorphism)"""
        return (
            s
            for s in self.iter_symbols()
            if isinstance(s, ParserFunction) and not s.is_nameref()
        )

    def iter_name_functions(self) -> Iterator[ParserFunction]:
        return (
            s
            for s in self.iter_symbols()
            if isinstance(s, ParserFunction) and s.is_nameref()
        )

    def iter_vtables(self) -> Iterator[ParserVtable]:
        return (s for s in self.iter_symbols() if isinstance(s, ParserVtable))

    def iter_variables(self) -> Iterator[ParserVariable]:
        return (s for s in self.iter_symbols() if isinstance(s, ParserVariable))

    def iter_strings(self) -> Iterator[ParserString]:
        return (s for s in self.iter_symbols() if isinstance(s, ParserString))

    def iter_line_symbols(self) -> Iterator[ParserLineSymbol]:
        return (s for s in self.iter_symbols() if isinstance(s, ParserLineSymbol))
