# from reccmp.formats.pdb.enum import LeafEnum
from reccmp.formats.pdb.tpi import (
    LfArray,
    LfEnum,
    TypeLookup,
    get_udt_definitions,
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


ARRAY_16 = b"\x0a\x00\x03\x00\xbe\x78\x11\x00\x90\x00\x00\xf1"
ENUM_16 = b"\x1a\x00\x07\x00\x04\x00t\x005\x10\x00\x00\x0e_D3DVERTEXTYPE\xf1"

# TPI v4.1 header: types 0x1000 to 0x1002, 52 bytes of leaves.
TPI_16 = (
    b"\x12n0\x01\x00\x10\x03\x104\x00\x00\x00\x05\x00\x00\x00"
    + ARRAY_16
    + ENUM_16
    + ARRAY_16
)


def test_lookup_16():
    types = TypeLookup(TPI_16)
    assert types[0x1000] == ARRAY_16
    assert types[0x1001] == ENUM_16
    assert types[0x1002] == ARRAY_16


def test_lookup_out_of_range():
    types = TypeLookup(TPI_16)
    assert 0xFFF not in types
    assert 0x1003 not in types


def test_lookup_iterates_type_indices():
    assert list(TypeLookup(TPI_16)) == [0x1000, 0x1001, 0x1002]


# From ISLE.pdb
ISLEAPP_FWDREF = (
    b"\x16\x00\x04\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x07IsleApp"
)
ISLEAPP_1 = b"\x16\x00\x04\x00/\x00\xc2\x10\x02\x00\x00\x00\x00\x00\x8c\x00\x07IsleApp"
ISLEAPP_2 = b"\x16\x00\x04\x00/\x00\x9b\x1d\x02\x00\x00\x00\x00\x00\x8c\x00\x07IsleApp"
ANON_ENUM = b'"\x00\x07\x00\n\x00t\x00G\x10\x08\x00\x15MxDSAction::__unnamed\xf2\xf1'


def test_udt_skips_forward_ref():
    types = {0x1011: ISLEAPP_FWDREF, 0x10C3: ISLEAPP_1}
    assert get_udt_definitions(types) == {"IsleApp": 0x10C3}


def test_udt_last_definition_wins():
    types = {0x10C3: ISLEAPP_1, 0x1D9C: ISLEAPP_2}
    assert get_udt_definitions(types) == {"IsleApp": 0x1D9C}


def test_udt_skips_anonymous():
    assert not get_udt_definitions({0x1048: ANON_ENUM})
