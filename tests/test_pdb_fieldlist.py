from reccmp.formats.pdb.enum import LeafEnum
from reccmp.formats.pdb.fieldlist import (
    FieldAccess,
    MethodProp,
    LfEnumerate,
    LfMember,
    LfMethod,
    LfNestType,
    LfOneMethod,
    LfStaticMember,
    LfVBClass,
    LfVFuncTab,
)


def test_enumerate_16():
    data = b"\x03\x04\x03\x00\x00\x00\x0dc_MusicTheme1\xf1"
    leaf, offset = LfEnumerate.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_ENUMERATE_ST
    assert leaf.access == FieldAccess.PUBLIC
    assert leaf.value == 0
    assert leaf.name == "c_MusicTheme1"
    assert offset == 20


def test_enumerate_16_char():
    """Packed value of type (LF_CHAR)"""
    data = b"\x03\x04\x03\x00\x00\x80\xff\x0dc_noneJukebox\xf1"
    leaf, offset = LfEnumerate.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_ENUMERATE_ST
    assert leaf.access == FieldAccess.PUBLIC
    assert leaf.value == -1
    assert leaf.name == "c_noneJukebox"
    assert offset == 21


def test_enumerate_16_ushort():
    """Packed value of type (LF_USHORT)"""
    data = b"\x03\x04\x03\x00\x02\x80\x00\x80\x04test\xf3\xf2\xf1"
    leaf, offset = LfEnumerate.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_ENUMERATE_ST
    assert leaf.access == FieldAccess.PUBLIC
    assert leaf.value == 32768
    assert leaf.name == "test"
    assert offset == 13


def test_enumerate_16_long():
    """Packed value of type (LF_LONG)"""
    data = b"\x03\x04\x03\x00\x03\x80\x00\x00\x00\x80\x04test\xf1"
    leaf, offset = LfEnumerate.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_ENUMERATE_ST
    assert leaf.access == FieldAccess.PUBLIC
    assert leaf.value == -2147483648
    assert leaf.name == "test"
    assert offset == 15


def test_enumerate_16_ulong():
    """Packed value of type (LF_ULONG)"""
    data = b"\x03\x04\x03\x00\x04\x80\x00\x00\x01\x00\x04test\xf2\xf1"
    leaf, offset = LfEnumerate.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_ENUMERATE_ST
    assert leaf.access == FieldAccess.PUBLIC
    assert leaf.value == 65536
    assert leaf.name == "test"
    assert offset == 15


def test_nested_type_16():
    data = b"\x09\x04\x75\x00\x09size_type\xf2\xf1"
    leaf, offset = LfNestType.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_NESTTYPE_16t
    assert leaf.index == 0x75
    assert leaf.name == "size_type"
    assert offset == 14


def test_nested_type_32():
    data = b"\x08\x14\x00\x00\x75\x00\x00\x00\x09size_type\xf2\xf1"
    leaf, offset = LfNestType.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_NESTTYPE_ST
    assert leaf.index == 0x75
    assert leaf.name == "size_type"
    assert offset == 18


def test_onemethod_32():
    data = b"\x0b\x14\x03\x00\x46\x15\x00\x00\x12CreateLight_504EE0\xf3\xf2\xf1"
    leaf, offset = LfOneMethod.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_ONEMETHOD_ST
    assert leaf.access == FieldAccess.PUBLIC
    assert leaf.mprop == MethodProp.VANILLA
    assert leaf.index == 0x1546
    assert offset == 27


def test_onemethod_32_intro_virtual():
    data = b"\x0b\x14\x12\x00\x41\x19\x00\x00\x08\x00\x00\x00\x08_Doraise\xf1"
    leaf, offset = LfOneMethod.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_ONEMETHOD_ST
    assert leaf.access == FieldAccess.PROTECTED
    assert leaf.mprop == MethodProp.INTRODUCING_VIRTUAL
    assert leaf.index == 0x1941
    assert leaf.name == "_Doraise"
    assert leaf.vbaseoff == 8
    assert offset == 21


def test_onemethod_32_pure_intro():
    data = b"\x0b\x14\x1b\x00.\x18\x00\x00\x04\x00\x00\x00\x06AddRef\xf1"
    leaf, offset = LfOneMethod.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_ONEMETHOD_ST
    assert leaf.access == FieldAccess.PUBLIC
    assert leaf.mprop == MethodProp.PURE_INTRO
    assert leaf.index == 0x182E
    assert leaf.name == "AddRef"
    assert leaf.vbaseoff == 4
    assert offset == 19


def test_member_16():
    data = b"\x06\x04\x75\x00\x02\x00\x2c\x00\x0cm_sizeOnDisk\xf1"
    leaf, offset = LfMember.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_MEMBER_16t
    assert leaf.access == FieldAccess.PROTECTED
    assert leaf.index == 0x75
    assert leaf.name == "m_sizeOnDisk"
    assert leaf.field_offset == 44
    assert offset == 21


def test_member_32():
    data = b"\x05\x14\x03\x00\x12\x04\x00\x00\x04\x00\x06pElems\xf1"
    leaf, offset = LfMember.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_MEMBER_ST
    assert leaf.access == FieldAccess.PUBLIC
    assert leaf.index == 0x412
    assert leaf.name == "pElems"
    assert leaf.field_offset == 4
    assert offset == 17


def test_static_member_16():
    data = b"\x07\x04\x75\x00\x01\x00\x0cg_nextCoreId\xf1"
    leaf, offset = LfStaticMember.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_STMEMBER_16t
    assert leaf.access == FieldAccess.PRIVATE
    assert leaf.index == 0x75
    assert leaf.name == "g_nextCoreId"
    assert offset == 19


def test_static_member_32():
    data = b"\x06\x14\x03\x00\xf6\x11\x00\x00\x0atable_size\xf1"
    leaf, offset = LfStaticMember.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_STMEMBER_ST
    assert leaf.access == FieldAccess.PUBLIC
    assert leaf.index == 0x11F6
    assert leaf.name == "table_size"
    assert offset == 19


def test_method_16():
    data = b"\x08\x04\x02\x00\x46\x12\x08MxAtomId\xf2\xf1"
    leaf, offset = LfMethod.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_METHOD_16t
    assert leaf.count == 2
    assert leaf.index == 0x1246
    assert leaf.name == "MxAtomId"
    assert offset == 15


def test_method_32():
    data = b"\x07\x14\x02\x00\xd1\x11\x00\x00\x11IRpcChannelBuffer\xf1"
    leaf, offset = LfMethod.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_METHOD_ST
    assert leaf.count == 2
    assert leaf.index == 0x11D1
    assert leaf.name == "IRpcChannelBuffer"
    assert offset == 26


def test_vbclass_16():
    """
    list[0] = LF_VBCLASS, public, direct base type = 0x1479
        virtual base ptr = 0x444B, vbpoff = 4, vbind = 2
    """
    data = b"\x01\x04\x79\x14\x4b\x44\x03\x00\x04\x00\x02\x00\xf2\xf1"
    leaf, offset = LfVBClass.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_VBCLASS_16t
    assert leaf.index == 0x1479
    assert leaf.access == FieldAccess.PUBLIC
    assert leaf.vbptr == 0x444B
    assert leaf.vbpoff == 4
    assert leaf.vbind == 2
    assert offset == 12


def test_vbclass_32():
    """
    list[0] = LF_VBCLASS, public, direct base type = 0x249D
        virtual base ptr = 0x249F, vbpoff = 0, vbind = 1
    """
    data = b"\x01\x14\x03\x00\x9d\x24\x00\x00\x9f\x24\x00\x00\x00\x00\x01\x00"
    leaf, offset = LfVBClass.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_VBCLASS
    assert leaf.index == 0x249D
    assert leaf.access == FieldAccess.PUBLIC
    assert leaf.vbptr == 0x249F
    assert leaf.vbpoff == 0
    assert leaf.vbind == 1
    assert offset == 16


def test_ivbclass_16():
    """
    list[1] = LF_IVBCLASS, public, indirect base type = 0x10F6
        virtual base ptr = 0x444B, vbpoff = 4, vbind = 1
    """
    data = b"\x02\x04\xf6\x10\x4b\x44\x03\x00\x04\x00\x01\x00\xf3\xf2\xf1"
    leaf, offset = LfVBClass.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_IVBCLASS_16t
    assert leaf.index == 0x10F6
    assert leaf.access == FieldAccess.PUBLIC
    assert leaf.vbptr == 0x444B
    assert leaf.vbpoff == 4
    assert leaf.vbind == 1
    assert offset == 12


def test_ivbclass_32():
    """
    list[1] = LF_IVBCLASS, public, indirect base type = 0x3942
        virtual base ptr = 0x249F, vbpoff = 0, vbind = 1
    """
    data = b"\x02\x14\x03\x00\x42\x39\x00\x00\x9f\x24\x00\x00\x00\x00\x01\x00"
    leaf, offset = LfVBClass.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_IVBCLASS
    assert leaf.index == 0x3942
    assert leaf.access == FieldAccess.PUBLIC
    assert leaf.vbptr == 0x249F
    assert leaf.vbpoff == 0
    assert leaf.vbind == 1
    assert offset == 16


def test_vfunctab_16():
    """
    list[2] = LF_VFUNCTAB, type = 0x2BEB
    """
    data = b"\x0a\x04\xeb\x2b"
    leaf, offset = LfVFuncTab.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_VFUNCTAB_16t
    assert leaf.index == 0x2BEB
    assert offset == 4


def test_vfunctab_32():
    """
    list[0] = LF_VFUNCTAB, type = 0x1831
    """
    data = b"\x09\x14\x00\x00\x31\x18\x00\x00"
    leaf, offset = LfVFuncTab.from_bytes(data)
    assert leaf.leaf_type == LeafEnum.LF_VFUNCTAB
    assert leaf.index == 0x1831
    assert offset == 8
