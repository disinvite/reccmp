# pylint:disable=invalid-name
from functools import cached_property
from pathlib import PureWindowsPath
from struct import iter_unpack, unpack_from
from typing import Iterator
from reccmp.formats.pdb import MSFContainer, StreamIndex
from reccmp.formats.pdb.codeview import CodeViewRecord
from reccmp.formats.pdb.common import read_pascal_string, read_sz_string
from reccmp.formats.pdb.dbi import DebugInfomation, ModuleInfo
from reccmp.formats.pdb.tpi import TPIHeader
from .cvinfo import CvdumpTypeKey
from .parser import (
    GdataEntry,
    LineValue,
    ModuleEntry,
    PublicsEntry,
    SizeRefEntry,
)
from .symbols import LdataEntry, StackOrRegisterSymbol, SymbolsEntry
from .types import CvdumpTypesParser

# TPI version for MSVC 4.1. cvdump converts 16-bit types if the version is this or lower.
_TPI_IMPV41 = 19951122

# Symbol record types. The 16t types are from MSVC 4.x PDBs. The ST types have
# 32-bit type indices and pascal string names. The rest have zero-terminated names.
S_REGISTER_16t = 0x0002
S_END = 0x0006
S_BPREL32_16t = 0x0200
S_LDATA32_16t = 0x0201
S_GDATA32_16t = 0x0202
S_PUB32_16t = 0x0203
S_LPROC32_16t = 0x0204
S_GPROC32_16t = 0x0205
S_BLOCK32_16t = 0x0207
S_REGISTER_ST = 0x1001
S_BPREL32_ST = 0x1006
S_LDATA32_ST = 0x1007
S_GDATA32_ST = 0x1008
S_PUB32_ST = 0x1009
S_LPROC32_ST = 0x100A
S_GPROC32_ST = 0x100B
S_BLOCK32 = 0x1103
S_REGISTER = 0x1106
S_BPREL32 = 0x110B
S_LDATA32 = 0x110C
S_GDATA32 = 0x110D
S_PUB32 = 0x110E
S_LPROC32 = 0x110F
S_GPROC32 = 0x1110

_PASCAL_NAME_TYPES = frozenset(
    (
        S_REGISTER_16t,
        S_BPREL32_16t,
        S_GDATA32_16t,
        S_LDATA32_16t,
        S_PUB32_16t,
        S_LPROC32_16t,
        S_GPROC32_16t,
        S_REGISTER_ST,
        S_BPREL32_ST,
        S_LDATA32_ST,
        S_GDATA32_ST,
        S_PUB32_ST,
        S_LPROC32_ST,
        S_GPROC32_ST,
    )
)

_GLOBAL_DATA_TYPES = frozenset((S_GDATA32_16t, S_GDATA32_ST, S_GDATA32))
_LOCAL_DATA_TYPES = frozenset((S_LDATA32_16t, S_LDATA32_ST, S_LDATA32))
_PUBLIC_TYPES = frozenset((S_PUB32_16t, S_PUB32_ST, S_PUB32))
_GLOBAL_PROC_TYPES = frozenset((S_GPROC32_16t, S_GPROC32_ST, S_GPROC32))
_LOCAL_PROC_TYPES = frozenset((S_LPROC32_16t, S_LPROC32_ST, S_LPROC32))
_BPREL_TYPES = frozenset((S_BPREL32_16t, S_BPREL32_ST, S_BPREL32))
_REGISTER_TYPES = frozenset((S_REGISTER_16t, S_REGISTER_ST, S_REGISTER))
_BLOCK_TYPES = frozenset((S_BLOCK32_16t, S_BLOCK32))

# CV_HREG_e, cvconst.h. x86 only.
_REGISTER_NAMES = {
    1: "al",
    2: "cl",
    3: "dl",
    4: "bl",
    5: "ah",
    6: "ch",
    7: "dh",
    8: "bh",
    9: "ax",
    10: "cx",
    11: "dx",
    12: "bx",
    13: "sp",
    14: "bp",
    15: "si",
    16: "di",
    17: "eax",
    18: "ecx",
    19: "edx",
    20: "ebx",
    21: "esp",
    22: "ebp",
    23: "esi",
    24: "edi",
    128: "st(0)",
    129: "st(1)",
    130: "st(2)",
    131: "st(3)",
    132: "st(4)",
    133: "st(5)",
    134: "st(6)",
    135: "st(7)",
}


def _register_name(reg: int) -> str:
    # The 16t record can hold a register pair: high byte and low byte.
    if reg > 0xFF:
        return f"{_register_name(reg >> 8)}:{_register_name(reg & 0xFF)}"

    return _REGISTER_NAMES.get(reg, f"reg{reg}")


def _read_name(data: bytes, offset: int, record_type: int) -> str:
    if record_type in _PASCAL_NAME_TYPES:
        name, _ = read_pascal_string(data, offset)
    else:
        name, _ = read_sz_string(data, offset)
    return name


def _read_data_sym(data: bytes, offset: int, record_type: int):
    """For S_GDATA32, S_LDATA32, and S_PUB32.
    Returns (section, offset, type or flags, name)."""
    offset += 4
    if record_type < 0x1000:
        off, seg, typ = unpack_from("<IHH", data, offset=offset)
        offset += 8
    else:
        typ, off, seg = unpack_from("<IIH", data, offset=offset)
        offset += 10

    return (seg, off, typ, _read_name(data, offset, record_type))


def _read_proc_sym(data: bytes, offset: int, record_type: int):
    """For S_GPROC32 and S_LPROC32.
    Returns (section, offset, size, type, flags, name)."""
    offset += 4
    if record_type < 0x1000:
        size, off, seg, typ, flags = unpack_from("<12xI8xIHHB", data, offset=offset)
        offset += 33
    else:
        size, typ, off, seg, flags = unpack_from("<12xI8xIIHB", data, offset=offset)
        offset += 35

    return (seg, off, size, typ, flags, _read_name(data, offset, record_type))


def _gsi_hash_offsets(data: bytes) -> list[int]:
    """Returns the symbol record offsets from a GSI hash table, in the order
    of the hash buckets. This is the order cvdump uses. See GSI1::readHash, gsi.cpp."""
    # The newer format starts with GSIHashHdr, signature -1.
    if data[:4] == b"\xff\xff\xff\xff":
        (hr_size,) = unpack_from("<8xI", data)
        records = data[16:][:hr_size]
    else:
        # The records are followed by 4096 + 1 bucket offsets.
        records = data[: len(data) - 4 * 4097]

    # HRFile, gsi.h. The offset is one more than the record offset.
    return [off - 1 for off, _ in iter_unpack("<2i", records)]


class PdbParser:
    """Each attribute is read from the PDB the first time it is used."""

    def __init__(self, data: bytes) -> None:
        # TODO: The leaves in reccmp.formats.pdb.tpi are not converted to the
        # format used by CvdumpTypesParser, so this only knows the primitive types.
        self.types = CvdumpTypesParser()

        self._msf = MSFContainer.from_bytes(data)

    @classmethod
    def from_file(cls, filename: str) -> "PdbParser":
        with open(filename, "rb") as f:
            return cls(f.read())

    @cached_property
    def is_16bit_type_pool(self) -> bool:
        header = TPIHeader.from_bytes(self._msf.get_stream(StreamIndex.TPI))
        return header.version <= _TPI_IMPV41

    @cached_property
    def _dbi(self) -> DebugInfomation:
        return DebugInfomation.from_bytes(self._msf.get_stream(StreamIndex.DBI))

    @cached_property
    def _symbol_records(self) -> bytes:
        return self._msf.get_stream(self._dbi.header.symbol_stream_id)

    @cached_property
    def modules(self) -> list[ModuleEntry]:
        return [
            ModuleEntry(
                id=i,
                lib=module.obj_name if module.obj_name != module.name else None,
                obj=module.name,
            )
            for i, module in enumerate(self._dbi.modules, start=1)
        ]

    @cached_property
    def sizerefs(self) -> list[SizeRefEntry]:
        return [
            SizeRefEntry(
                # cvdump numbers the modules from 1.
                module=sc.moduleindex + 1,
                section=sc.section,
                offset=sc.offset,
                size=sc.size,
            )
            for sc in self._dbi.section_contributions
        ]

    @cached_property
    def publics(self) -> list[PublicsEntry]:
        public_stream = self._msf.get_stream(self._dbi.header.public_stream_id)
        return list(self._read_publics(public_stream, self._symbol_records))

    @cached_property
    def globals(self) -> list[GdataEntry]:
        global_stream = self._msf.get_stream(self._dbi.header.global_stream_id)
        return list(self._read_globals(global_stream, self._symbol_records))

    def _module_streams(self) -> Iterator[tuple[ModuleInfo, bytes]]:
        for module in self._dbi.modules:
            if module.stream_id != -1:
                yield (module, self._msf.get_stream(module.stream_id))

    @cached_property
    def symbols(self) -> list[SymbolsEntry]:
        return [
            symbol
            for module, stream in self._module_streams()
            # The symbol size includes the 4-byte CV signature.
            for symbol in self._read_module_symbols(stream[4 : module.symbol_size])
        ]

    @cached_property
    def lines(self) -> dict[PureWindowsPath, list[LineValue]]:
        file_blocks = [
            file_block
            for module, stream in self._module_streams()
            for file_block in self._read_c11_lines(
                stream[module.symbol_size :][: module.c11_lines_size]
            )
            # TODO: C13 lines
        ]

        lines: dict[PureWindowsPath, list[LineValue]] = {
            path: [] for path, _ in file_blocks
        }
        for path, file_lines in file_blocks:
            lines[path].extend(file_lines)

        return lines

    def _read_publics(
        self, data: bytes, symbol_records: bytes
    ) -> Iterator[PublicsEntry]:
        """The public symbol stream has a hash table and an address map, both of
        which point into the symbol record stream. The record stream can have
        public symbols that are in neither one, so we cannot read it directly.
        The address map can have publics that are not in the hash table.
        cvdump lists the publics in hash table order, so we do the same."""
        # PSGSIHDR, gsi.h
        (sym_hash_size,) = unpack_from("<I", data)

        for record_offset in _gsi_hash_offsets(data[28:][:sym_hash_size]):
            (record_type,) = unpack_from("<2xH", symbol_records, offset=record_offset)
            if record_type not in _PUBLIC_TYPES:
                continue

            section, offset, flags, name = _read_data_sym(
                symbol_records, record_offset, record_type
            )
            yield PublicsEntry(
                type="S_PUB32",
                section=section,
                offset=offset,
                flags=flags,
                name=name,
            )

    def _read_globals(self, data: bytes, symbol_records: bytes) -> Iterator[GdataEntry]:
        """The global symbol stream is a hash table that points into the symbol
        record stream. cvdump lists the globals in hash table order, so we do the same.
        """
        for record_offset in _gsi_hash_offsets(data):
            (record_type,) = unpack_from("<2xH", symbol_records, offset=record_offset)
            if record_type in _GLOBAL_DATA_TYPES or record_type in _LOCAL_DATA_TYPES:
                section, offset, typ, name = _read_data_sym(
                    symbol_records, record_offset, record_type
                )
                yield GdataEntry(
                    section=section,
                    offset=offset,
                    type=CvdumpTypeKey(typ),
                    name=name,
                    is_global=record_type in _GLOBAL_DATA_TYPES,
                )

    def _read_module_symbols(self, data: bytes) -> Iterator[SymbolsEntry]:
        """Mirrors the logic in CvdumpSymbolsParser."""
        current_function: SymbolsEntry | None = None
        block_level = 0

        for record in CodeViewRecord.from_bytes(data):
            rtype = record.type

            if rtype in _GLOBAL_PROC_TYPES or rtype in _LOCAL_PROC_TYPES:
                section, offset, size, typ, flags, name = _read_proc_sym(
                    data, record.offset, rtype
                )
                current_function = SymbolsEntry(
                    type="S_GPROC32" if rtype in _GLOBAL_PROC_TYPES else "S_LPROC32",
                    section=section,
                    offset=offset,
                    size=size,
                    func_type=CvdumpTypeKey(typ),
                    name=name,
                    # CV_PFLAG_NOFPO
                    frame_pointer_present=bool(flags & 1),
                )
                # The entry is filled in by the records that follow.
                yield current_function

            elif rtype in _BPREL_TYPES:
                if current_function is None:
                    continue
                if rtype < 0x1000:
                    off, typ = unpack_from("<iH", data, offset=record.offset + 4)
                    name_offset = record.offset + 10
                else:
                    off, typ = unpack_from("<iI", data, offset=record.offset + 4)
                    name_offset = record.offset + 12

                current_function.symbols.append(
                    StackOrRegisterSymbol(
                        symbol_type="S_BPREL32",
                        location=f"[{off & 0xFFFFFFFF:08x}]",
                        data_type=CvdumpTypeKey(typ),
                        name=_read_name(data, name_offset, rtype),
                    )
                )

            elif rtype in _REGISTER_TYPES:
                if current_function is None:
                    continue
                if rtype < 0x1000:
                    typ, reg = unpack_from("<HH", data, offset=record.offset + 4)
                    name_offset = record.offset + 8
                else:
                    typ, reg = unpack_from("<IH", data, offset=record.offset + 4)
                    name_offset = record.offset + 10

                current_function.symbols.append(
                    StackOrRegisterSymbol(
                        symbol_type="S_REGISTER",
                        location=_register_name(reg),
                        data_type=CvdumpTypeKey(typ),
                        name=_read_name(data, name_offset, rtype),
                    )
                )

            elif rtype in _BLOCK_TYPES:
                block_level += 1

            elif rtype == S_END:
                if block_level > 0:
                    block_level -= 1
                else:
                    current_function = None

            elif rtype in _LOCAL_DATA_TYPES:
                if current_function is None:
                    continue
                section, offset, typ, name = _read_data_sym(data, record.offset, rtype)
                # Switch jump tables have an S_LDATA32 record with no name.
                # The regex in CvdumpSymbolsParser does not match these.
                if not name:
                    continue
                current_function.static_variables.append(
                    LdataEntry(
                        section=section,
                        offset=offset,
                        type=CvdumpTypeKey(typ),
                        name=name,
                    )
                )

    def _read_c11_lines(
        self, data: bytes
    ) -> Iterator[tuple[PureWindowsPath, list[LineValue]]]:
        """sstSrcModule from the CodeView 4 spec.
        Yields the filename and lines for each file block."""
        if not data:
            return

        (n_files,) = unpack_from("<H", data)
        file_offsets = unpack_from(f"<{n_files}I", data, offset=4)

        for file_offset in file_offsets:
            (n_segs,) = unpack_from("<H", data, offset=file_offset)
            line_offsets = unpack_from(f"<{n_segs}I", data, offset=file_offset + 4)
            filename, _ = read_pascal_string(data, file_offset + 4 + 12 * n_segs)

            lines: list[LineValue] = []
            for line_offset in line_offsets:
                section, n_pairs = unpack_from("<2H", data, offset=line_offset)
                addr_start = line_offset + 4
                line_start = addr_start + 4 * n_pairs
                addrs = unpack_from(f"<{n_pairs}I", data, offset=addr_start)
                line_nos = unpack_from(f"<{n_pairs}H", data, offset=line_start)
                lines.extend(
                    LineValue(line_no, section, addr)
                    for addr, line_no in zip(addrs, line_nos)
                )

            yield (PureWindowsPath(filename), lines)
