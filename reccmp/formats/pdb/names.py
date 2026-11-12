from struct import unpack_from
from .common import read_map, read_sz_string

# PDBImpvVC70Dep, pdb.h. Later versions add a GUID to the PDB stream header.
_PDB_IMPV_VC70_DEP = 19990604

# NMT::VHdr, nmt.h
_NMT_MAGIC = 0xEFFEEFFE


def read_named_streams(data: bytes) -> dict[str, int]:
    """Map stream name to stream number, from the PDB info stream (stream 1).
    PDB1::loadPdbStream, pdb.cpp and NMTNI::reload, nmtni.h"""
    (impv,) = unpack_from("<I", data)
    offset = 28 if impv > _PDB_IMPV_VC70_DEP else 12

    (size,) = unpack_from("<i", data, offset=offset)
    offset += 4
    strings = data[offset : offset + size]
    offset += size

    return {
        read_sz_string(strings, string_offset)[0]: stream
        for string_offset, stream in read_map(data, offset)
    }


class NameTable:
    """The /names stream. A name index (NI) is an offset into its string buffer.
    NMT::reload and NMT::szForNiInternal, nmt.h"""

    def __init__(self, data: bytes) -> None:
        offset = 0
        magic, version = unpack_from("<2I", data)
        if magic == _NMT_MAGIC and version != 0:
            offset = 8

        (size,) = unpack_from("<i", data, offset=offset)
        offset += 4
        self._strings = data[offset : offset + size]

    def __getitem__(self, ni: int) -> str:
        return read_sz_string(self._strings, ni)[0]
