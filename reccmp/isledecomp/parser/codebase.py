"""For aggregating decomp markers read from an entire directory and for a single module."""

from pathlib import PurePath
from typing import Callable, Iterable, Iterator
from reccmp.isledecomp.types import TextFile
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
    _symbols: dict[PurePath, tuple[ParserSymbol, ...]]
    module: str
    is_valid_fn: Callable[[int], bool] | None = None

    def __init__(self, module: str, files: Iterable[TextFile] | None = None) -> None:
        self._symbols = {}
        self.module = module

        if files:
            for file in files:
                self.read_file(file)

    def read_file(self, file: TextFile):
        parser = DecompParser()
        parser.reset_and_set_filename(str(file.path))
        parser.read(file.text)

        self._symbols[file.path] = tuple(parser.iter_symbols(self.module))

    def iter_paths(self) -> Iterator[PurePath]:
        yield from sorted(self._symbols.keys())

    def iter_symbols(self) -> Iterator[ParserSymbol]:
        # Sort paths before returning parser items so we have a predictable order.
        for path in self.iter_paths():
            yield from iter(self._symbols[path])

    def iter_valid_symbols(self) -> Iterator[ParserSymbol]:
        if not callable(self.is_valid_fn):
            gen = self.iter_symbols()
        else:
            gen = (
                symbol
                for symbol in self.iter_symbols()
                if self.is_valid_fn(symbol.offset)
            )

        used = set()
        for symbol in gen:
            if symbol.offset not in used:
                yield symbol
                used.add(symbol.offset)

    def iter_invalid_symbols(self) -> Iterator[ParserSymbol]:
        if not callable(self.is_valid_fn):
            return

        for symbol in self.iter_symbols():
            if not self.is_valid_fn(symbol.offset):
                yield symbol

    def iter_line_functions(self) -> Iterator[ParserFunction]:
        """Return lineref functions separately from nameref. Assuming the PDB matches
        the state of the source code, a line reference is a guaranteed match, even if
        multiple functions share the same name. (i.e. polymorphism)"""
        return (
            s
            for s in self.iter_valid_symbols()
            if isinstance(s, ParserFunction) and not s.is_nameref()
        )

    def iter_name_functions(self) -> Iterator[ParserFunction]:
        return (
            s
            for s in self.iter_valid_symbols()
            if isinstance(s, ParserFunction) and s.is_nameref()
        )

    def iter_vtables(self) -> Iterator[ParserVtable]:
        return (s for s in self.iter_valid_symbols() if isinstance(s, ParserVtable))

    def iter_variables(self) -> Iterator[ParserVariable]:
        return (s for s in self.iter_valid_symbols() if isinstance(s, ParserVariable))

    def iter_strings(self) -> Iterator[ParserString]:
        return (s for s in self.iter_valid_symbols() if isinstance(s, ParserString))

    def iter_line_symbols(self) -> Iterator[ParserLineSymbol]:
        return (s for s in self.iter_valid_symbols() if isinstance(s, ParserLineSymbol))
