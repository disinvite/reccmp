# from reccmp.isledecomp.formats.pdb.enum import LeafEnum
from reccmp.isledecomp.formats.pdb.tpi import LfArray


def test_array_16():
    data = b"\x0a\x00\x03\x00\xbe\x78\x11\x00\x90\x00\x00\xf1"
    leaf = LfArray.from_bytes(data)
    # assert leaf.leaf_type == LeafEnum.LF_ARRAY_16t
    assert leaf.elemtype == 0x78BE
    assert leaf.idxtype == 0x11
    assert leaf.count == 144
