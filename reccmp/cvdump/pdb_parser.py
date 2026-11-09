# pylint:disable=invalid-name
from pathlib import PureWindowsPath
from struct import iter_unpack, unpack_from
from reccmp.formats.pdb import MSFContainer, StreamIndex
from reccmp.formats.pdb.codeview import CodeViewRecord
from reccmp.formats.pdb.common import read_pascal_string, read_sz_string
from reccmp.formats.pdb.dbi import DebugInfomation
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


class PdbParser:
    # pylint: disable=too-many-instance-attributes
    def __init__(self, data: bytes) -> None:
        self.lines: dict[PureWindowsPath, list[LineValue]] = {}
        self.publics: list[PublicsEntry] = []
        self.sizerefs: list[SizeRefEntry] = []
        self.globals: list[GdataEntry] = []
        self.modules: list[ModuleEntry] = []
        self.symbols: list[SymbolsEntry] = []

        # TODO: The leaves in reccmp.formats.pdb.tpi are not converted to the
        # format used by CvdumpTypesParser, so this only knows the primitive types.
        self.types = CvdumpTypesParser()

        self.is_16bit_type_pool: bool | None = None

        self._msf = MSFContainer.from_bytes(data)
        self._read_types()
        self._read_dbi()

    @classmethod
    def from_file(cls, filename: str) -> "PdbParser":
        with open(filename, "rb") as f:
            return cls(f.read())

    def _read_types(self):
        header = TPIHeader.from_bytes(self._msf.get_stream(StreamIndex.TPI))
        self.is_16bit_type_pool = header.version <= _TPI_IMPV41

    def _read_dbi(self):
        info = DebugInfomation.from_bytes(self._msf.get_stream(StreamIndex.DBI))
        header = info.header

        for i, module in enumerate(info.modules, start=1):
            self.modules.append(
                ModuleEntry(
                    id=i,
                    lib=module.obj_name if module.obj_name != module.name else "",
                    obj=module.name,
                )
            )

        for sc in info.section_contributions:
            self.sizerefs.append(
                SizeRefEntry(
                    # cvdump numbers the modules from 1.
                    module=sc.moduleindex + 1,
                    section=sc.section,
                    offset=sc.offset,
                    size=sc.size,
                )
            )

        symbol_records = self._msf.get_stream(header.symbol_stream_id)
        self._read_publics(
            self._msf.get_stream(header.public_stream_id), symbol_records
        )
        self._read_globals(symbol_records)

        for module in info.modules:
            if module.stream_id == -1:
                continue

            stream = self._msf.get_stream(module.stream_id)
            # The symbol size includes the 4-byte CV signature.
            self._read_module_symbols(stream[4 : module.symbol_size])
            self._read_c11_lines(stream[module.symbol_size :][: module.c11_lines_size])
            # TODO: C13 lines

    def _read_publics(self, data: bytes, symbol_records: bytes):
        """The public symbol stream has a hash table and an address map, both of
        which point into the symbol record stream. The record stream can have
        public symbols that are in neither one, so we cannot read it directly.
        cvdump lists the publics in hash table order. Here they are in address map order.
        """
        # PSGSIHDR, gsi.h
        sym_hash_size, addr_map_size = unpack_from("<2I", data)
        addr_map = data[28 + sym_hash_size :][:addr_map_size]

        for (record_offset,) in iter_unpack("<I", addr_map):
            (record_type,) = unpack_from("<2xH", symbol_records, offset=record_offset)
            if record_type not in _PUBLIC_TYPES:
                continue

            section, offset, flags, name = _read_data_sym(
                symbol_records, record_offset, record_type
            )
            self.publics.append(
                PublicsEntry(
                    type="S_PUB32",
                    section=section,
                    offset=offset,
                    flags=flags,
                    name=name,
                )
            )

    def _read_globals(self, data: bytes):
        """cvdump lists the globals in hash table order from the global symbol stream.
        Here they are read from the symbol record stream in stream order.
        TODO: Read the hash table instead. The record stream can have public symbols
        that are not in the hash table, so this may be true for globals too."""
        for record in CodeViewRecord.from_bytes(data, align=True):
            if record.type in _GLOBAL_DATA_TYPES or record.type in _LOCAL_DATA_TYPES:
                section, offset, typ, name = _read_data_sym(
                    data, record.offset, record.type
                )
                self.globals.append(
                    GdataEntry(
                        section=section,
                        offset=offset,
                        type=CvdumpTypeKey(typ),
                        name=name,
                        is_global=record.type in _GLOBAL_DATA_TYPES,
                    )
                )

    def _read_module_symbols(self, data: bytes):
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
                self.symbols.append(current_function)

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

    def _read_c11_lines(self, data: bytes):
        """sstSrcModule from the CodeView 4 spec."""
        if not data:
            return

        (n_files,) = unpack_from("<H", data)
        file_offsets = unpack_from(f"<{n_files}I", data, offset=4)

        for file_offset in file_offsets:
            (n_segs,) = unpack_from("<H", data, offset=file_offset)
            line_offsets = unpack_from(f"<{n_segs}I", data, offset=file_offset + 4)
            name_offset = file_offset + 4 + 12 * n_segs
            filename, _ = read_pascal_string(data, name_offset)
            lines = self.lines.setdefault(PureWindowsPath(filename), [])

            for line_offset in line_offsets:
                section, n_pairs = unpack_from("<2H", data, offset=line_offset)
                addr_start = line_offset + 4
                line_start = addr_start + 4 * n_pairs
                addrs = iter_unpack("<I", data[addr_start:line_start])
                line_nos = iter_unpack("<H", data[line_start:][: 2 * n_pairs])
                lines.extend(
                    LineValue(line_no, section, addr)
                    for (addr,), (line_no,) in zip(addrs, line_nos)
                )
