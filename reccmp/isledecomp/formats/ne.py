"""
Based on the following resources:
- https://github.com/bitwiseworks/os2tk45/blob/master/h/newexe.h
- https://github.com/qb40/exe-format/blob/master/README.txt
"""

import dataclasses
import struct
from pathlib import Path
from typing import Iterator
from enum import Enum, IntEnum, IntFlag

from .exceptions import (
    InvalidVirtualAddressError,
    SectionNotFoundError,
)
from .image import Image, ImageImport, ImageRegion
from .mz import ImageDosHeader


def index_to_seg(index: int) -> int:
    return 0x1000 + (8 * (index - 1))


def pascal_string(data: bytes) -> str:
    strlen = data[0]
    return bytes(data[1 : strlen + 1]).decode("ascii")


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


class NERelocationType(Enum):
    LOBYTE = 0x00
    SEGMENT = 0x02
    FAR_ADDR = 0x03
    OFFSET = 0x05


class NERelocationFlag(Enum):
    INTERNALREF = 0
    IMPORTORDINAL = 1
    IMPORTNAME = 2
    OSFIXUP = 3


@dataclasses.dataclass(frozen=True)
class NERelocation:
    type: NERelocationType
    flag: NERelocationFlag
    offsets: tuple[int, ...]
    value0: int
    value1: int


@dataclasses.dataclass(frozen=True)
class NESegment:
    address: int
    physical_offset: int
    physical_size: int
    virtual_size: int
    relocations: tuple[NERelocation, ...]
    mock: bool = False  # ?

    @property
    def range(self) -> range:
        return range(
            self.address, self.address + max(self.physical_size, self.virtual_size)
        )


def iter_relocations(
    data: bytes, offset: int = 0
) -> Iterator[tuple[int, int, int, int, int]]:
    (n_reloc,) = struct.unpack_from("<H", data, offset=offset)
    offset += 2

    for _ in range(n_reloc):
        yield struct.unpack_from("<BBHHH", data, offset=offset)
        offset += 8


def iter_reloc_chain(data: bytes, start: int) -> Iterator[int]:
    value = start
    while value != 0xFFFF:
        yield value
        (value,) = struct.unpack_from("<H", data, offset=value)


def iter_segments(
    data: bytes, seg_tab_offset: int, seg_count: int, sector_size: int
) -> Iterator[NESegment]:
    segment_table, _ = NESegmentTableEntry.from_memory(
        data, offset=seg_tab_offset, count=seg_count
    )

    for i, entry in enumerate(segment_table):
        # Per ghidra
        virtual_address = (0x1000 + 8 * i) << 16
        physical_offset = entry.ns_sector * sector_size

        # TODO: entry.ns_sector == 0

        # 64k if either value is 0
        physical_size = entry.ns_cbseg if entry.ns_cbseg else 0x10000
        virtual_size = entry.ns_minalloc if entry.ns_minalloc else 0x10000

        seg_data = data[physical_offset:][:physical_size]

        relocs = []

        if entry.has_reloc():
            reloc_table = data[physical_offset + physical_size :]

            for reloc_type, reloc_flag, start, value0, value1 in iter_relocations(
                reloc_table
            ):
                additive = reloc_flag & 4 == 4

                offsets: tuple[int, ...]
                # Do not follow the chain if the additive flag is set.
                if additive:
                    # TODO: Skip this for now. Even Ghidra doesn't handle it.
                    offsets = tuple()
                else:
                    offsets = tuple(iter_reloc_chain(seg_data, start))

                reloc = NERelocation(
                    type=NERelocationType(reloc_type),
                    flag=NERelocationFlag(reloc_flag & 3),
                    offsets=offsets,
                    value0=value0,
                    value1=value1,
                )
                relocs.append(reloc)

        yield NESegment(
            address=virtual_address,
            physical_offset=physical_offset,
            physical_size=physical_size,
            virtual_size=virtual_size,
            relocations=tuple(relocs),
            mock=False,
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
    def from_memory(cls, data: bytes, offset: int = 0) -> tuple["NEEntry", ...]:
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
                    offset += 6

                elif indicator == 0:
                    # Skip this ordinal number.
                    offset += 1

                else:
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
    ne_align: int  # Segment alignment shift count (Sector size is 1 << ne_align)
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
    segments: tuple[NESegment, ...]
    _imports: tuple[ImageImport, ...] = tuple()

    @classmethod
    def from_memory(
        cls, data: bytes, mz_header: ImageDosHeader, filepath: Path
    ) -> "NEImage":
        offset = mz_header.e_lfanew
        # n.b. The memoryview must be writeable for reloc replacement.
        view = memoryview(bytearray(data))
        header, _ = NewExeHeader.from_memory(data, offset=offset)
        segments = tuple(
            iter_segments(
                view,
                seg_tab_offset=offset + header.ne_segtab,
                seg_count=header.ne_cseg,
                sector_size=(1 << header.ne_align),
            )
        )

        return cls(
            filepath=filepath,
            data=data,
            view=view,
            mz_header=mz_header,
            header=header,
            segments=segments,
        )

    def __post_init__(self):
        entry_table = NEEntry.from_memory(
            self.view, self.mz_header.e_lfanew + self.header.ne_enttab
        )

        entry_map = {entry.ordinal: entry for entry in entry_table}

        modules_raw = self.view[
            self.mz_header.e_lfanew
            + self.header.ne_modtab : self.mz_header.e_lfanew
            + self.header.ne_imptab
        ]

        import_names_raw = self.view[
            self.mz_header.e_lfanew
            + self.header.ne_imptab : self.mz_header.e_lfanew
            + self.header.ne_enttab
        ]

        imported_names = [
            # Reloc lookups are 1-based, so add a blank for alignment.
            "",
            *(
                pascal_string(import_names_raw[ofs:])
                for ofs, in struct.iter_unpack("<H", modules_raw)
            ),
        ]

        # TODO: We just need something. Recalculate later using Ghidra technique.
        import_seg = 0x2000

        all_imports = [
            r
            for seg in self.segments
            for r in seg.relocations
            # TODO: We need an example of IMPORTNAME to see how they fit into the order.
            if r.flag in (NERelocationFlag.IMPORTORDINAL,)
        ]
        all_imports.sort(key=lambda v: (v.value0, v.value1))

        import_map = {
            (reloc.value0, reloc.value1): ImageImport(
                module=imported_names[reloc.value0],
                ordinal=reloc.value1,
                addr=(import_seg << 16) + (4 * i),
            )
            for i, reloc in enumerate(all_imports)
        }

        self._imports = tuple(import_map.values())

        for seg in self.segments:
            seg_data = self.view[seg.physical_offset :][: seg.physical_size]

            # Each location to patch in this segment.
            reloc_values: list[tuple[int, bytes]] = []

            reloc_values.extend(
                [
                    (
                        offset,
                        struct.pack(
                            "<I", import_map[(reloc.value0, reloc.value1)].addr
                        ),
                    )
                    for reloc in seg.relocations
                    for offset in reloc.offsets
                    if reloc.flag == NERelocationFlag.IMPORTORDINAL
                ]
            )

            reloc_internals = sorted(
                (r for r in seg.relocations if r.flag == NERelocationFlag.INTERNALREF),
                key=lambda v: (v.value0, v.value1),
            )

            for reloc in reloc_internals:
                (replacement_seg, replacement_ofs) = (reloc.value0, reloc.value1)

                if reloc.value0 == 255:
                    # Movable segment. Lookup using 1-based ordinal number.
                    if reloc.value1 not in entry_map:
                        raise ValueError  # TODO

                    entry = entry_map[reloc.value1]
                    (replacement_seg, replacement_ofs) = (entry.segment, entry.offset)

                if reloc.type == NERelocationType.OFFSET:
                    replacement = struct.pack("<H", replacement_ofs)

                elif reloc.type == NERelocationType.SEGMENT:
                    replacement = struct.pack("<H", index_to_seg(replacement_seg))

                elif reloc.type == NERelocationType.FAR_ADDR:
                    replacement = struct.pack(
                        "<I", self.get_abs_addr(replacement_seg, replacement_ofs)
                    )

                reloc_values.extend([(offset, replacement) for offset in reloc.offsets])

            # Now apply the patches
            for offset, patch in reloc_values:
                # print(
                #     f"{seg.address + offset:8x}:  {seg_data[offset : offset + len(patch)].hex()}  {patch.hex()}"
                # )
                seg_data[offset : offset + len(patch)] = patch

        # The data has been changed: update underlying value.
        self.data = bytes(self.view)

    @property
    def imagebase(self):
        return 0x10000000

    @property
    def imports(self) -> Iterator[ImageImport]:
        return iter(self._imports)

    @property
    def entry(self) -> int:
        return self.get_abs_addr(*self.header.ne_csip)

    def _get_segment(self, index: int) -> NESegment:
        try:
            assert index > 0
            return self.segments[index - 1]
        except (AssertionError, IndexError) as ex:
            raise SectionNotFoundError(index) from ex

    def is_valid_vaddr(self, _: int) -> bool:
        return True  # TODO

    def get_relative_addr(self, addr: int) -> tuple[int, int]:
        for i, segment in enumerate(self.segments):
            if addr in segment.range:
                return (i + 1, addr - segment.address)

        raise InvalidVirtualAddressError(f"{self.filepath} : 0x{addr:x}")

    def get_abs_addr(self, section: int, offset: int) -> int:
        try:
            segment = self.segments[section - 1]
            return segment.address + offset
        except IndexError as ex:
            raise InvalidVirtualAddressError(f"{section:04x}:{offset:04x}") from ex

    def seek(self, vaddr: int) -> tuple[bytes, int]:
        (segment, offset) = self.get_relative_addr(vaddr)
        seg = self._get_segment(segment)

        if offset > seg.virtual_size:
            raise InvalidVirtualAddressError(f"{segment:04x}:{offset:04x}")

        if seg.physical_size == 0:
            return (b"", seg.virtual_size - offset)

        start = seg.physical_offset
        end = start + seg.physical_size
        return (self.view[start + offset : end], seg.virtual_size - offset)

    def get_code_regions(self) -> Iterator[ImageRegion]:
        raise NotImplementedError

    def get_data_regions(self) -> Iterator[ImageRegion]:
        raise NotImplementedError

    def get_const_regions(self) -> Iterator[ImageRegion]:
        raise NotImplementedError
