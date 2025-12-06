# from reccmp.isledecomp.formats.pdb.enum import LeafEnum
from reccmp.isledecomp.formats.pdb.tpi import (
    LfArray,
    LfEnum,
)


def test_array_16():
    data = b"\x0a\x00\x03\x00\xbe\x78\x11\x00\x90\x00\x00\xf1"
    leaf = LfArray.from_bytes(data)
    # assert leaf.leaf_type == LeafEnum.LF_ARRAY_16t
    assert leaf.elemtype == 0x78BE
    assert leaf.idxtype == 0x11
    assert leaf.count == 144


def test_enum_16():
    data = b"\x1a\x00\x07\x00\x04\x00t\x005\x10\x00\x00\x0e_D3DVERTEXTYPE\xf1"
    leaf = LfEnum.from_bytes(data)
    # assert leaf.leaf_type == LeafEnum.LF_ENUM_16t
    assert leaf.name == "_D3DVERTEXTYPE"
    assert leaf.count == 4
    assert leaf.index == 0x1035
    assert leaf.utype == 0x74


def test_enum_32():
    data = b"\x1a\x00\x07\x10\x04\x00\x00\x00\x74\x00\x00\x00\x50\x11\x00\x00\x0aSTUB_PHASE\xf1"
    leaf = LfEnum.from_bytes(data)
    # assert leaf.leaf_type == LeafEnum.LF_ENUM_ST
    assert leaf.name == "STUB_PHASE"
    assert leaf.count == 4
    assert leaf.index == 0x1150
    assert leaf.utype == 0x74
