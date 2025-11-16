"""
Based on the following resources:
- https://github.com/bitwiseworks/os2tk45/blob/master/h/newexe.h
- https://github.com/qb40/exe-format/blob/master/README.txt
"""

import dataclasses
import struct
from pathlib import Path
from typing import Iterator
from enum import IntEnum, IntFlag

from .exceptions import (
    InvalidVirtualAddressError,
    SectionNotFoundError,
)
from .image import Image, ImageRegion
from .mz import ImageDosHeader


class NESegmentFlags(IntFlag):
    # pylint: disable=implicit-flag-alias
    NESOLO = 0x0001  # Solo data
    NEINST = 0x0002  # Instance data
    NEPPLI = 0x0004  # Per-Process Library Initialization
    NEPROT = 0x0008  # Runs in protected mode only
    NEI086 = 0x0010  # 8086 instructions
    NEI286 = 0x0020  # 286 instructions
    NEI386 = 0x0040  # 386 instructions
    NEFLTP = 0x0080  # Floating-point instructions
    NENOTWINCOMPAT = 0x0100  # Not compatible with P.M. Windowing
    NEWINCOMPAT = 0x0200  # Compatible with P.M. Windowing
    NEWINAPI = 0x0300  # Uses P.M. Windowing API
    NEAPPTYP = 0x0700  # Application type mask
    NEBOUND = 0x0800  # Bound Family/API
    NEIERR = 0x2000  # Errors in image
    NEPRIVLIB = 0x4000  # A one customer Windows 3.0 library
    NENOTP = 0x8000  # Not a process


class NETargetOSFlags(IntEnum):
    NE_UNKNOWN = 0  # Unknown (any "new-format" OS)
    NE_OS2 = 1  # OS/2 (default)
    NE_WINDOWS = 2  # Windows
    NE_DOS = 3  # DOS 4.x
    NE_DEV386 = 4  # Windows 386


@dataclasses.dataclass(frozen=True)
class NESegmentTableEntry:
    ns_sector: int  # File sector of start of segment
    ns_cbseg: int  # Number of bytes in file
    ns_flags: int  # Attribute flags
    ns_minalloc: int  # Minimum allocation in bytes

    def has_reloc(self) -> bool:
        return self.ns_flags & 0x100 == 0x100

    @classmethod
    def from_memory(
        cls, data: bytes, offset: int, count: int
    ) -> tuple[tuple["NESegmentTableEntry", ...], int]:
        struct_fmt = "<4H"
        struct_size = struct.calcsize(struct_fmt)
        items = tuple(
            cls(*items)
            for items in struct.iter_unpack(
                struct_fmt, data[offset : offset + count * struct_size]
            )
        )
        return items, offset + count * struct_size


class NERelocationFlag(IntEnum):
    INTERNALREF = 0
    IMPORTORDINAL = 1
    IMPORTNAME = 2
    OSFIXUP = 3
    ADDITIVE = 4


@dataclasses.dataclass(frozen=True)
class NESegmentRelocation:
    type: int
    flag: NERelocationFlag
    offset: int
    value0: int
    value1: int

    @classmethod
    def from_memory(cls, data: bytes, offset: int) -> tuple["NESegmentRelocation", ...]:
        (n_reloc,) = struct.unpack_from("<H", data, offset=offset)
        offset += 2

        relocs: list[tuple[int, int, int, int, int]] = [
            struct.unpack_from("<BBHHH", data, offset + 8 * i) for i in range(n_reloc)
        ]

        return tuple(
            cls(
                type=type_,
                flag=NERelocationFlag(flag),
                offset=offset,
                value0=value0,
                value1=value1,
            )
            for type_, flag, offset, value0, value1 in relocs
        )


@dataclasses.dataclass(frozen=True)
class NEEntry:
    ordinal: int
    movable: bool
    exported: bool
    g_dataseg: bool
    segment: int
    offset: int

    @classmethod
    def from_memory(cls, data: bytes, offset: int) -> tuple["NEEntry", ...]:
        ordinal = 0
        entries = []

        while True:
            (n_entries, indicator) = struct.unpack_from("<2B", data, offset)
            if n_entries == 0:
                break

            offset += 2
            for _ in range(n_entries):
                ordinal += 1  # Ordinals start at 1.
                if indicator == 255:
                    (flag, entry_seg, entry_ofs) = struct.unpack_from(
                        "<BxxBH", data, offset
                    )
                    entry = cls(
                        ordinal=ordinal,
                        movable=True,
                        exported=flag & 1 == 1,
                        g_dataseg=flag & 2 == 2,
                        segment=entry_seg,
                        offset=entry_ofs,
                    )
                    entries.append(entry)
                    # print(ordinal, "mov", entry_seg, hex(entry_ofs))
                    offset += 6

                elif indicator > 0:
                    # Indicator is the segment number for all in this bundle.
                    (flag, entry_ofs) = struct.unpack_from("<BH", data, offset)
                    entry = cls(
                        ordinal=ordinal,
                        movable=False,
                        exported=flag & 1 == 1,
                        g_dataseg=flag & 2 == 2,
                        segment=indicator,
                        offset=entry_ofs,
                    )
                    entries.append(entry)
                    # print(ordinal, "fix", indicator, hex(entry_ofs))
                    offset += 3

        return tuple(entries)


@dataclasses.dataclass(frozen=True)
class NewExeHeader:
    # pylint: disable=too-many-instance-attributes
    ne_magic: bytes  # Magic number NE_MAGIC
    ne_ver: int  # Version number
    ne_rev: int  # Revision number
    ne_enttab: int  # Offset of Entry Table
    ne_cbenttab: int  # Number of bytes in Entry Table
    ne_crc: int  # Checksum of whole file
    ne_flags: NESegmentFlags  # Flag word
    ne_autodata: int  # Automatic data segment number
    ne_heap: int  # Initial heap allocation
    ne_stack: int  # Initial stack allocation
    ne_csip: tuple[int, int]  # Initial CS:IP setting
    ne_sssp: tuple[int, int]  # Initial SS:SP setting
    ne_cseg: int  # Count of file segments
    ne_cmod: int  # Entries in Module Reference Table
    ne_cbnrestab: int  # Size of non-resident name table
    ne_segtab: int  # Offset of Segment Table (Relative to NE header)
    ne_rsrctab: int  # Offset of Resource Table (Relative to NE header)
    ne_restab: int  # Offset of resident name Table (Relative to NE header)
    ne_modtab: int  # Offset of Module Reference Table (Relative to NE header)
    ne_imptab: int  # Offset of Imported Names Table (Relative to NE header)
    ne_nrestab: int  # Offset of Non-resident Names Table (File offset)
    ne_cmovent: int  # Count of movable entries
    ne_align: int  # Segment alignment shift count
    ne_cres: int  # Count of resource entries
    ne_exetyp: NETargetOSFlags  # Target operating system
    ne_flagsothers: int  # Other .EXE flags
    ne_pretthunks: int  # Windows 3.0 - offset to return thunks
    ne_psegrefbytes: int  # Windows 3.0 - offset to segment ref. bytes
    ne_swaparea: int  # Windows 3.0 - minimum code swap size
    ne_expver: int  # Windows 3.0 - expected windows version number

    @classmethod
    def from_memory(cls, data: bytes, offset: int) -> tuple["NewExeHeader", int]:
        if not cls.taste(data, offset):
            raise ValueError
        struct_fmt = "<2s2B2HI16HI3H2B4H"
        struct_size = struct.calcsize(struct_fmt)
        # fmt: off
        items: tuple[bytes, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int] = (
            struct.unpack_from(struct_fmt, data, offset)
        )
        # fmt: on
        result = cls(
            *items[:6],
            NESegmentFlags(items[6]),
            *items[7:10],
            (items[11], items[10]),  # CS:IP
            (items[13], items[12]),  # SS:SP
            *items[14:26],
            NETargetOSFlags(items[26]),
            *items[27:],
        )
        return result, offset + struct_size

    @classmethod
    def taste(cls, data: bytes, offset: int) -> bool:
        (magic,) = struct.unpack_from("<2s", data, offset)
        return magic == b"NE"


@dataclasses.dataclass
class NEImage(Image):
    mz_header: ImageDosHeader
    header: NewExeHeader
    segments: tuple[NESegmentTableEntry, ...]

    @classmethod
    def from_memory(
        cls, data: bytes, mz_header: ImageDosHeader, filepath: Path
    ) -> "NEImage":
        offset = mz_header.e_lfanew
        # n.b. The memoryview must be writeable for reloc replacement.
        view = memoryview(bytearray(data))
        header, _ = NewExeHeader.from_memory(data, offset=offset)
        segments, _ = NESegmentTableEntry.from_memory(
            data, offset=offset + header.ne_segtab, count=header.ne_cseg
        )

        # Hack. There is no 'self' at this stage.
        def get_abs_addr(section: int, offset: int) -> int:
            return ((0x1000 + (8 * (section - 1))) << 16) + offset

        entry_table = NEEntry.from_memory(view, offset + header.ne_enttab)

        # TODO: We just need something. Recalculate later using Ghidra technique.
        import_seg = 0x2000

        for segment in segments:
            if segment.has_reloc():
                seg_data = view[segment.ns_sector * 16 :][: segment.ns_cbseg]

                reloc = NESegmentRelocation.from_memory(
                    view, segment.ns_sector * 16 + segment.ns_cbseg
                )

                # Sorted by import module number, ordinal number.
                reloc_ordinals = sorted(
                    (r for r in reloc if r.flag == NERelocationFlag.IMPORTORDINAL),
                    key=lambda v: (v.value0, v.value1),
                )

                for i, r in enumerate(reloc_ordinals):
                    # print(f"{r.type:02x} {r.flag:1x}   {r.offset:4x} {r.value0:4x} {r.value1:4x}")

                    # Walk linked list of import offsets in this seg.
                    value = r.offset
                    while value != 0xFFFF:
                        # print(hex(value))
                        (next_value,) = struct.unpack_from("<H", seg_data, value)
                        # TODO: patch with whatever mock address we are using for the import.
                        seg_data[value : value + 4] = struct.pack(
                            "<HH", 4 * i, import_seg
                        )
                        value = next_value

                    # All the offset we just printed correspond to this import:
                    # print(f" --> {r.value0:4x} {r.value1:4x}")

                ####

                reloc_internals = sorted(
                    (r for r in reloc if r.flag == NERelocationFlag.INTERNALREF),
                    key=lambda v: (v.value0, v.value1),
                )

                for i, r in enumerate(reloc_internals):
                    if r.value0 == 255:
                        # Movable segment. Lookup using 1-based ordinal number.
                        entry = entry_table[r.value1 - 1]
                        seg_data[r.offset : r.offset + 4] = struct.pack(
                            "<I", get_abs_addr(entry.segment, entry.offset)
                        )
                    else:
                        seg_data[r.offset : r.offset + 4] = struct.pack(
                            "<I", get_abs_addr(r.value0, r.value1)
                        )

        return cls(
            filepath=filepath,
            # We made a copy of the view and made changes.
            # Therefore we need to use that as our data member.
            data=bytes(view),
            view=view.toreadonly(),
            mz_header=mz_header,
            header=header,
            segments=segments,
        )

    @property
    def imagebase(self):
        return 0x10000000

    @property
    def entry(self) -> int:
        return self.get_abs_addr(*self.header.ne_csip)

    def _get_segment(self, index: int) -> NESegmentTableEntry:
        try:
            assert index > 0
            return self.segments[index - 1]
        except (AssertionError, IndexError) as ex:
            raise SectionNotFoundError(index) from ex

    def is_valid_vaddr(self, _: int) -> bool:
        return True  # TODO

    def get_relative_addr(self, addr: int) -> tuple[int, int]:
        assert addr >= 0x10000000

        segment = (addr >> 19) & 0x1FF
        offset = addr & 0xFFFF
        return (segment + 1, offset)

    def get_abs_addr(self, section: int, offset: int) -> int:
        return ((0x1000 + (8 * (section - 1))) << 16) + offset

    def seek(self, vaddr: int) -> tuple[bytes, int]:
        (segment, offset) = self.get_relative_addr(vaddr)
        seg = self._get_segment(segment)

        # 64k if either value is 0
        physical_size = seg.ns_cbseg if seg.ns_cbseg else 0x10000
        virtual_size = seg.ns_minalloc if seg.ns_minalloc else 0x10000

        if offset > virtual_size:
            raise InvalidVirtualAddressError(f"{segment:04x}:{offset:04x}")

        if seg.ns_sector == 0:
            # No physical data
            return (b"", virtual_size - offset)

        start = 16 * seg.ns_sector
        end = start + physical_size
        return (self.view[start + offset : end], virtual_size - offset)

    def get_code_regions(self) -> Iterator[ImageRegion]:
        raise NotImplementedError

    def get_data_regions(self) -> Iterator[ImageRegion]:
        raise NotImplementedError

    def get_const_regions(self) -> Iterator[ImageRegion]:
        raise NotImplementedError
