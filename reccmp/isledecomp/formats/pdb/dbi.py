from dataclasses import dataclass
from struct import unpack_from
from .common import align_to, read_sz_string
from .debug import debug_print


@dataclass(frozen=True)
class DBIHeader:
    # pylint: disable=too-many-instance-attributes
    version: int
    global_stream_id: int
    public_stream_id: int
    symbol_stream_id: int
    module_info_size: int
    section_contribution_size: int
    section_map_size: int
    source_info_size: int

    @classmethod
    def from_bytes(cls, data: bytes) -> tuple["DBIHeader", int]:
        (hdr_signature,) = unpack_from("<i", data)
        if hdr_signature == -1:
            # New style header: NewDBIHdr
            (
                version,
                global_stream_id,
                public_stream_id,
                symbol_stream_id,
                module_info_size,
                section_contribution_size,
                section_map_size,
                source_info_size,
            ) = unpack_from("<I4xH2xH2xH2x4I", data, offset=4)
            offset = 64

        else:
            # Old style header: DBIHdr
            version = 0  # TODO: new magic number?
            (
                global_stream_id,
                public_stream_id,
                symbol_stream_id,
                module_info_size,
                section_contribution_size,
                section_map_size,
                source_info_size,
            ) = unpack_from("<3H2x4I", data, offset=0)
            offset = 24

        return (
            cls(
                version,
                global_stream_id,
                public_stream_id,
                symbol_stream_id,
                module_info_size,
                section_contribution_size,
                section_map_size,
                source_info_size,
            ),
            offset,
        )


@dataclass(frozen=True)
class SectionContribution:
    section: int
    offset: int
    size: int
    characteristics: int
    moduleindex: int
    data_crc: int
    reloc_crc: int

    @classmethod
    def from_bytes(
        cls, data: bytes, offset: int = 0, *, new: bool = False
    ) -> tuple["SectionContribution", int]:
        if new:
            (
                section,
                sc_offset,
                size,
                characteristics,
                moduleindex,
                data_crc,
                reloc_crc,
            ) = unpack_from("<H2x2iIH2x2I", data, offset=offset)
            offset += 28
        else:
            (section, sc_offset, size, characteristics, moduleindex) = unpack_from(
                "<4IH2x", data, offset=offset
            )
            data_crc = 0
            reloc_crc = 0
            offset += 20

        return (
            cls(
                section,
                sc_offset,
                size,
                characteristics,
                moduleindex,
                data_crc,
                reloc_crc,
            ),
            offset,
        )


@dataclass(frozen=True)
class ModuleInfo:
    # MODI50
    sc: SectionContribution
    stream_id: int
    symbol_size: int
    c11_lines_size: int
    c13_lines_size: int
    module_name: str
    obj_name: str

    @classmethod
    def from_bytes(
        cls, data: bytes, offset: int = 0, *, new: bool = False
    ) -> tuple["ModuleInfo", int]:
        offset = align_to(offset, 4)
        offset += 4  # skip unused
        (sc, offset) = SectionContribution.from_bytes(data, offset=offset, new=new)

        if new:
            (stream_id, symbol_size, c11_lines_size, c13_lines_size) = unpack_from(
                "<2xh2x3I", data, offset=offset
            )
            offset += 32  # skip TODO
        else:
            (stream_id, symbol_size, c11_lines_size) = unpack_from(
                "<2xh2x2I", data, offset=offset
            )
            c13_lines_size = 0
            offset += 24  # skip TODO

        (module_name, offset) = read_sz_string(data, offset)
        (obj_name, offset) = read_sz_string(data, offset)

        return (
            cls(
                sc,
                stream_id,
                symbol_size,
                c11_lines_size,
                c13_lines_size,
                module_name,
                obj_name,
            ),
            offset,
        )


def parse_modules(data: bytes):
    (header, offset) = DBIHeader.from_bytes(data)
    debug_print(data, size=offset)

    # MODI50 or MODI60
    new_modi = header.version >= 19970606

    # debug_print(dbi, offset=offset, size=header.module_info_size)

    idx = 1
    while offset < header.module_info_size:
        # start = offset
        (module, offset) = ModuleInfo.from_bytes(data, offset=offset, new=new_modi)
        # print()
        # debug_print(data, offset=start, size=offset-start)
        print(
            f'{idx:04X} {module.stream_id} {max(module.c11_lines_size, module.c13_lines_size)} "{module.obj_name}" "{module.module_name}"'
        )
        idx += 1
