import struct
from functools import cache
from typing import Callable, Protocol
from reccmp.isledecomp.formats.exceptions import (
    InvalidVirtualAddressError,
    InvalidVirtualReadError,
)
from reccmp.isledecomp.compare.db import ReccmpEntity
from reccmp.isledecomp.types import SymbolType


class AddrTestProtocol(Protocol):
    def __call__(self, addr: int) -> bool:
        pass


class NameReplacementProtocol(Protocol):
    def __call__(self, addr: int, exact: bool = False) -> str | None:
        pass


def create_name_lookup(
    db_getter: Callable[[int, bool], ReccmpEntity | None],
    bin_read: Callable[[int], bytes],
    addr_attribute: str,
) -> NameReplacementProtocol:
    """Function generator for name replacement"""

    @cache
    def lookup(addr: int, exact: bool = False, indirect: bool = False) -> str | None:
        # pylint: disable=too-many-return-statements
        # indirect implies exact
        m = db_getter(addr, indirect or exact)
        if indirect:
            if m is not None:
                # If the indirect call points at a variable initialized to a function,
                # prefer the variable name as this is more useful.
                if m.compare_type == SymbolType.DATA:
                    return m.match_name()

                # TODO: SymbolType.IMPORT
                if m.compare_type == SymbolType.POINTER:
                    return "->" + m.match_name()  # TODO: dll name

            try:
                # TODO: variable pointer size
                (addr,) = struct.unpack("<L", bin_read(addr, 4))
            except (struct.error, InvalidVirtualAddressError, InvalidVirtualReadError):
                return None

            m = db_getter(addr, True)

        if m is None:
            return None

        if getattr(m, addr_attribute) == addr:
            best_name = m.match_name()

            if indirect and best_name is not None:
                return "->" + best_name

            return best_name

        offset = addr - getattr(m, addr_attribute)
        if m.compare_type != SymbolType.DATA or offset >= m.size:
            return None

        return m.offset_name(offset)

    return lookup
