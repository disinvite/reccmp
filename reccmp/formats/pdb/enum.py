from enum import IntEnum


class LeafEnum(IntEnum):
    # pylint:disable=invalid-name

    # leaf indices starting records but referenced from symbol records
    LF_MODIFIER_16t = 0x0001
    LF_POINTER_16t = 0x0002
    LF_ARRAY_16t = 0x0003
    LF_CLASS_16t = 0x0004
    LF_STRUCTURE_16t = 0x0005
    LF_UNION_16t = 0x0006
    LF_ENUM_16t = 0x0007
    LF_PROCEDURE_16t = 0x0008
    LF_MFUNCTION_16t = 0x0009

    # leaf indices starting records but referenced only from type records
    LF_BCLASS_16t = 0x0400
    LF_VBCLASS_16t = 0x0401
    LF_IVBCLASS_16t = 0x0402
    LF_ENUMERATE_ST = 0x0403
    LF_MEMBER_16t = 0x0406
    LF_STMEMBER_16t = 0x0407
    LF_METHOD_16t = 0x0408
    LF_NESTTYPE_16t = 0x0409
    LF_VFUNCTAB_16t = 0x040A
    LF_ONEMETHOD_16t = 0x040C

    # 32-bit type index versions of leaves, all have the 0x1000 bit set
    LF_MODIFIER = 0x1001
    LF_POINTER = 0x1002
    LF_ARRAY_ST = 0x1003
    LF_CLASS_ST = 0x1004
    LF_STRUCTURE_ST = 0x1005
    LF_UNION_ST = 0x1006
    LF_ENUM_ST = 0x1007
    LF_PROCEDURE = 0x1008
    LF_MFUNCTION = 0x1009

    # leaf indices starting records but referenced only from type records
    LF_BCLASS = 0x1400
    LF_VBCLASS = 0x1401
    LF_IVBCLASS = 0x1402
    LF_MEMBER_ST = 0x1405
    LF_STMEMBER_ST = 0x1406
    LF_METHOD_ST = 0x1407
    LF_NESTTYPE_ST = 0x1408
    LF_VFUNCTAB = 0x1409
    LF_ONEMETHOD_ST = 0x140B

    # Types w/ SZ names
    LF_ENUMERATE = 0x1502
