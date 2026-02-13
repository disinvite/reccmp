from reccmp.formats.pdb.enum import LeafEnum
from reccmp.formats.pdb.fieldlist import (
    LfEnumerate,
    LfNestType,
    LfOneMethod,
    LfMember,
)


def test_enumerate_16():
    data = b"\x03\x04\x03\x00\x00\x00\x0dc_MusicTheme1\xf1"
    (leaf, offset) = LfEnumerate.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_ENUMERATE_ST
    # assert leaf.attr is public
    assert leaf.value == 0
    assert leaf.name == "c_MusicTheme1"
    assert offset == 20


def test_enumerate_16_char():
    """Packed value of type (LF_CHAR)"""
    data = b"\x03\x04\x03\x00\x00\x80\xff\x0dc_noneJukebox\xf1"
    (leaf, offset) = LfEnumerate.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_ENUMERATE_ST
    # assert leaf.attr is public
    assert leaf.value == -1
    assert leaf.name == "c_noneJukebox"
    assert offset == 21


def test_enumerate_16_ushort():
    """Packed value of type (LF_USHORT)"""
    data = b"\x03\x04\x03\x00\x02\x80\x00\x80\x04test\xf3\xf2\xf1"
    (leaf, offset) = LfEnumerate.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_ENUMERATE_ST
    # assert leaf.attr is public
    assert leaf.value == 32768
    assert leaf.name == "test"
    assert offset == 13


def test_enumerate_16_long():
    """Packed value of type (LF_LONG)"""
    data = b"\x03\x04\x03\x00\x03\x80\x00\x00\x00\x80\x04test\xf1"
    (leaf, offset) = LfEnumerate.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_ENUMERATE_ST
    # assert leaf.attr is public
    assert leaf.value == -2147483648
    assert leaf.name == "test"
    assert offset == 15


def test_enumerate_16_ulong():
    """Packed value of type (LF_ULONG)"""
    data = b"\x03\x04\x03\x00\x04\x80\x00\x00\x01\x00\x04test\xf2\xf1"
    (leaf, offset) = LfEnumerate.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_ENUMERATE_ST
    # assert leaf.attr is public
    assert leaf.value == 65536
    assert leaf.name == "test"
    assert offset == 15


def test_nested_type_16():
    data = b"\x09\x04\x75\x00\x09size_type\xf2\xf1"
    (leaf, offset) = LfNestType.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_NESTTYPE_16t
    assert leaf.index == 0x75
    assert leaf.name == "size_type"
    assert offset == 14


def test_nested_type_32():
    data = b"\x08\x14\x00\x00\x75\x00\x00\x00\x09size_type\xf2\xf1"
    (leaf, offset) = LfNestType.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_NESTTYPE_ST
    assert leaf.index == 0x75
    assert leaf.name == "size_type"
    assert offset == 18


def test_onemethod_32():
    data = b"\x0b\x14\x03\x00\x46\x15\x00\x00\x12CreateLight_504EE0\xf3\xf2\xf1"
    (leaf, offset) = LfOneMethod.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_ONEMETHOD_ST
    # assert leaf.attr is public, vanilla
    assert leaf.index == 0x1546
    assert offset == 27


def test_onemethod_32_intro_virtual():
    data = b"\x0b\x14\x12\x00\x41\x19\x00\x00\x08\x00\x00\x00\x08_Doraise\xf1"
    (leaf, offset) = LfOneMethod.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_ONEMETHOD_ST
    # assert leaf.attr is protected, intro
    assert leaf.index == 0x1941
    assert leaf.name == "_Doraise"
    assert leaf.vbaseoff == 8
    assert offset == 21


def test_onemethod_32_pure_intro():
    data = b"\x0b\x14\x1b\x00.\x18\x00\x00\x04\x00\x00\x00\x06AddRef\xf1"
    (leaf, offset) = LfOneMethod.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_ONEMETHOD_ST
    # assert leaf.attr is public, pure intro
    assert leaf.index == 0x182E
    assert leaf.name == "AddRef"
    assert leaf.vbaseoff == 4
    assert offset == 19


def test_member_32():
    data = b"\x05\x14\x03\x00\x12\x04\x00\x00\x04\x00\x06pElems\xf1"
    (leaf, offset) = LfMember.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_MEMBER_ST
    # assert leaf.attr is public
    assert leaf.index == 0x412
    assert leaf.name == "pElems"
    assert leaf.field_offset == 4
    assert offset == 17
