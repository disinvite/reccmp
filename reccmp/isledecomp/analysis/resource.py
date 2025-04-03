"""Extracting Windows resources"""
from enum import Enum, IntFlag
from typing import Iterator, NamedTuple
import struct
from reccmp.isledecomp.formats import NEImage


class WinResourceType(Enum):
    """See WINUSER.H"""

    RT_CURSOR = 1
    RT_BITMAP = 2
    RT_ICON = 3
    RT_MENU = 4
    RT_DIALOG = 5
    RT_STRING = 6
    RT_FONTDIR = 7
    RT_FONT = 8
    RT_ACCELERATOR = 9
    RT_RCDATA = 10
    RT_MESSAGETABLE = 11
    RT_GROUP_CURSOR = 12
    RT_GROUP_ICON = 14
    RT_NAMETABLE = 15
    RT_VERSION = 16
    RT_DLGINCLUDE = 17


class WinResourceFlags(IntFlag):
    MOVEABLE = 0x10
    PURE = 0x20
    PRELOAD = 0x40
    DISCARDABLE = 0x1000


class WinResource(NamedTuple):
    type: WinResourceType | str
    id: int | str
    offset: int
    size: int
    flags: WinResourceFlags


def ne_resource_table(img: NEImage) -> Iterator[WinResource]:
    # Resource table offset is relative to start of NE header.
    view = img.view[
        img.mz_header.e_lfanew
        + img.header.ne_rsrctab : img.mz_header.e_lfanew
        + img.header.ne_restab
    ]

    (alignment_shift,) = struct.unpack_from("<H", view, offset=0)
    offset = 2

    def pascal_string(buf, ofs):
        (length,) = struct.unpack_from("B", buf, offset=ofs)
        (string,) = struct.unpack_from(f"{length}s", buf, offset=ofs + 1)
        return string.decode("ascii")

    try:
        # Not using resource count (ne_cres) as bounds for the table.
        while offset < len(view):
            (type_id, count) = struct.unpack_from("<2H", view, offset=offset)
            if type_id == 0:
                break

            offset += 8  # Skip reserved dword

            if type_id & 0x8000:
                type_id = WinResourceType(type_id & 0x7FFF)
            else:
                type_id = pascal_string(view, type_id)

            for _ in range(count):
                (res_offset, res_size, res_flags, res_id) = struct.unpack_from(
                    "<4H", view, offset=offset
                )

                if res_id & 0x8000:
                    res_id &= 0x7FFF
                else:
                    res_id = pascal_string(view, res_id)

                # Are these the only flags of interest?
                res_flags = WinResourceFlags(res_flags & 0x70)

                yield WinResource(
                    type=type_id,
                    id=res_id,
                    offset=res_offset << alignment_shift,
                    size=res_size << alignment_shift,
                    flags=res_flags,
                )

                offset += 12  # Skip reserved dword

    except struct.error:
        # If we run off the end of the the table
        pass
