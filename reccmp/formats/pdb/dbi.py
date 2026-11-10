from dataclasses import dataclass
from enum import Enum, auto
from struct import unpack_from
from .common import align_to, read_sz_string
from .debug import debug_print

# DBI header version (DBIImpvV60, dbi.h)
_DBI_IMPV_V60 = 19970606

# Section contribution substream versions (DBISCImpv and DBISCImpv2, dbi.h)
_DBI_SC_IMPV = 0xEFFE0000 + 19970605
_DBI_SC_IMPV2 = 0xEFFE0000 + 20140516


class SectionContributionVersion(Enum):
    # Struct names from dbicommon.h
    SC40 = auto()
    SC = auto()
    SC2 = auto()


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
        cls,
        data: bytes,
        offset: int = 0,
        *,
        version: SectionContributionVersion = SectionContributionVersion.SC40,
    ) -> tuple["SectionContribution", int]:
        if version == SectionContributionVersion.SC2:
            (
                section,
                sc_offset,
                size,
                characteristics,
                moduleindex,
                data_crc,
                reloc_crc,
            ) = unpack_from("<H2x2iIH2x2I4x", data, offset=offset)
            offset += 32
        elif version == SectionContributionVersion.SC:
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
            section, sc_offset, size, characteristics, moduleindex = unpack_from(
                "<H2xIiIH2x", data, offset=offset
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
    name: str
    obj_name: str

    @classmethod
    def from_bytes(
        cls, data: bytes, offset: int = 0, *, new: bool = False
    ) -> tuple["ModuleInfo", int]:
        offset = align_to(offset, 4)
        offset += 4  # skip unused
        sc, offset = SectionContribution.from_bytes(
            data,
            offset=offset,
            version=(
                SectionContributionVersion.SC
                if new
                else SectionContributionVersion.SC40
            ),
        )

        if new:
            stream_id, symbol_size, c11_lines_size, c13_lines_size = unpack_from(
                "<2xh3I", data, offset=offset
            )
            offset += 32  # skip TODO
        else:
            stream_id, symbol_size, c11_lines_size = unpack_from(
                "<2xh2I", data, offset=offset
            )
            c13_lines_size = 0
            offset += 24  # skip TODO

        name, offset = read_sz_string(data, offset)
        obj_name, offset = read_sz_string(data, offset)

        return (
            cls(
                sc,
                stream_id,
                symbol_size,
                c11_lines_size,
                c13_lines_size,
                name,
                obj_name,
            ),
            offset,
        )


@dataclass(frozen=True)
class DebugInfomation:
    header: DBIHeader
    modules: tuple[ModuleInfo, ...]
    section_contributions: tuple[SectionContribution, ...]

    @classmethod
    def from_bytes(cls, data: bytes) -> "DebugInfomation":
        header, offset = DBIHeader.from_bytes(data)
        modi_end = offset + header.module_info_size
        sc_data = data[modi_end:][: header.section_contribution_size]

        new_modi = header.version >= _DBI_IMPV_V60
        modules = []
        # Each module record is aligned to 4 bytes, including padding after the last one.
        while align_to(offset, 4) < modi_end:
            module, offset = ModuleInfo.from_bytes(data, offset=offset, new=new_modi)
            modules.append(module)

        return cls(header, tuple(modules), _read_section_contributions(sc_data))


def _read_section_contributions(data: bytes) -> tuple[SectionContribution, ...]:
    if not data:
        return ()

    # If the header does not match any known magic numbers,
    # assume the substream format is SC40, starting at offset=0.
    (sc_version,) = unpack_from("<I", data)
    if sc_version == _DBI_SC_IMPV2:
        version = SectionContributionVersion.SC2
        offset = 4
    elif sc_version == _DBI_SC_IMPV:
        version = SectionContributionVersion.SC
        offset = 4
    else:
        version = SectionContributionVersion.SC40
        offset = 0

    contributions = []
    while offset < len(data):
        sc, offset = SectionContribution.from_bytes(data, offset, version=version)
        contributions.append(sc)

    return tuple(contributions)


def parse_modules(data: bytes):
    header, offset = DBIHeader.from_bytes(data)
    debug_print(data, size=offset)

    # MODI50 or MODI60
    new_modi = header.version >= 19970606

    # debug_print(dbi, offset=offset, size=header.module_info_size)

    idx = 1
    modi_end = offset + header.module_info_size
    while align_to(offset, 4) < modi_end:
        # start = offset
        module, offset = ModuleInfo.from_bytes(data, offset=offset, new=new_modi)
        # print()
        # debug_print(data, offset=start, size=offset-start)
        print(
            f'{idx:04X} {module.stream_id} {max(module.c11_lines_size, module.c13_lines_size)} "{module.obj_name}" "{module.name}"'
        )
        idx += 1
