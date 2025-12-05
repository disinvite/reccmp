from struct import calcsize, unpack_from


PACKED_VALUE_MAP = {
    0x8000: "b",  # LF_CHAR
    0x8001: "h",  # LF_SHORT
    0x8002: "H",  # LF_USHORT
    0x8003: "l",  # LF_LONG
    0x8004: "L",  # LF_ULONG
    0x8005: "f",  # LF_REAL32
    0x8006: "d",  # LF_REAL64
}


def read_packed_value(data: bytes, offset: int) -> tuple[int, int]:
    """CbExtractNumeric? No code available in the microsoft-pdb repo.
    Returns (value, new_offset)"""
    (x,) = unpack_from("<H", data, offset=offset)
    offset += 2
    if x & 0x8000 == 0:
        return (x, offset)

    assert x in PACKED_VALUE_MAP, "Variable length fail"
    fmt = PACKED_VALUE_MAP[x]
    (x,) = unpack_from(fmt, data, offset=offset)
    return (x, offset + calcsize(fmt))


def read_pascal_string(data: bytes, offset: int) -> tuple[str, int]:
    strlen = data[offset]
    value = data[offset + 1 : offset + 1 + strlen].decode("ascii")
    return (value, offset + strlen + 1)
