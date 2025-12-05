"""TPI (Types) section: LF_FIELDLIST sub-lists"""

from dataclasses import dataclass
from enum import IntEnum
from struct import calcsize, unpack_from
from typing import Any
from .common import read_packed_value, read_pascal_string
from .debug import debug_print


class FieldAccess(IntEnum):
    NONE = 0
    PRIVATE = 1
    PROTECTED = 2
    PUBLIC = 3


class MethodProp(IntEnum):
    VANILLA = 0
    VIRTUAL = 1
    STATIC = 2
    FRIEND = 3
    INTRODUCING_VIRTUAL = 4
    PURE_VIRTUAL = 5
    PURE_INTRO = 6


@dataclass(frozen=True)
class FieldAttr:
    """CV_fldattr_t, cvinfo.h. With macros from typeinfo.h"""

    access: int
    mprop: int

    @classmethod
    def from_bytes(cls, data: bytes, offset: int) -> tuple["FieldAttr", int]:
        (raw,) = unpack_from("<H", data, offset=offset)
        # access = FieldAccess(raw & 3)
        # mprop = MethodProp((raw >> 2) & 7)
        access = raw & 3
        mprop = (raw >> 2) & 7
        # TODO: Remaining bitflags.

        return (cls(access, mprop), offset + 2)


@dataclass(frozen=True)
class LfBClass:
    """0400: lfBClass / lfBClass_16t, cvinfo.h"""

    index: int
    attr: FieldAttr
    base_offset: int

    @classmethod
    def from_bytes(
        cls, data: bytes, *, is32: bool = False, offset: int = 0
    ) -> tuple["LfBClass", int]:
        # n.b. attr/index order is swapped between 16 and 32-bit structs.
        (_,) = unpack_from("<H", data, offset=offset)
        offset += 2

        if is32:
            (attr, offset) = FieldAttr.from_bytes(data, offset)
            (index,) = unpack_from("<I", data, offset=offset)
            offset += 4
        else:
            (index,) = unpack_from("<H", data, offset=offset)
            offset += 2
            (attr, offset) = FieldAttr.from_bytes(data, offset)

        (base_offset, offset) = read_packed_value(data, offset)

        return (cls(index, attr, base_offset), offset)


@dataclass(frozen=True)
class LfVBClass:
    """0401/0402: lfVBClass / lfVBClass_16t, cvinfo.h"""

    index: int
    attr: FieldAttr
    vbptr: int
    vbpoff: int
    vbind: int

    @classmethod
    def from_bytes(
        cls, data: bytes, *, is32: bool = False, offset: int = 0
    ) -> tuple["LfVBClass", int]:
        # n.b. attr/index order is swapped between 16 and 32-bit structs.
        (_,) = unpack_from("<H", data, offset=offset)
        offset += 2

        if is32:
            (attr, offset) = FieldAttr.from_bytes(data, offset)
            (index, vbptr) = unpack_from("<2I", data, offset=offset)
            offset += 8
        else:
            (index, vbptr) = unpack_from("<2H", data, offset=offset)
            offset += 4
            (attr, offset) = FieldAttr.from_bytes(data, offset)

        # TODO: order?
        (vbpoff, offset) = read_packed_value(data, offset)
        (vbind, offset) = read_packed_value(data, offset)

        return (cls(index, attr, vbptr, vbpoff, vbind), offset)


@dataclass(frozen=True)
class LFEnumerate:
    """0403: lfEnumerate, cvinfo.h"""

    attr: FieldAttr
    value: int
    name: str

    @classmethod
    def from_bytes(
        cls, data: bytes, *, offset: int = 0, **_
    ) -> tuple["LFEnumerate", int]:
        (__,) = unpack_from("<H", data, offset=offset)
        offset += 2

        (attr, offset) = FieldAttr.from_bytes(data, offset)
        (value, offset) = read_packed_value(data, offset)
        (name, offset) = read_pascal_string(data, offset)

        return (cls(attr, value, name), offset)


@dataclass(frozen=True)
class LfMember:
    """0406: lfMember / lfMember_16t, cvinfo.h"""

    index: int
    attr: FieldAttr
    field_offset: int
    name: str

    @classmethod
    def from_bytes(
        cls, data: bytes, *, is32: bool = False, offset: int = 0
    ) -> tuple["LfMember", int]:
        # n.b. attr/index order is swapped between 16 and 32-bit structs.
        (_,) = unpack_from("<H", data, offset=offset)
        offset += 2

        if is32:
            (attr, offset) = FieldAttr.from_bytes(data, offset)
            (index,) = unpack_from("<I", data, offset=offset)
            offset += 4
        else:
            (index,) = unpack_from("<H", data, offset=offset)
            offset += 2
            (attr, offset) = FieldAttr.from_bytes(data, offset)

        (field_offset, offset) = read_packed_value(data, offset)
        (name, offset) = read_pascal_string(data, offset)

        return (cls(index, attr, field_offset, name), offset)


@dataclass(frozen=True)
class LfStaticMember:
    """0407: lfMember / lfMember_16t, cvinfo.h"""

    index: int
    attr: FieldAttr
    name: str

    @classmethod
    def from_bytes(
        cls, data: bytes, *, is32: bool = False, offset: int = 0
    ) -> tuple["LfStaticMember", int]:
        # n.b. attr/index order is swapped between 16 and 32-bit structs.
        (_,) = unpack_from("<H", data, offset=offset)
        offset += 2

        if is32:
            (attr, offset) = FieldAttr.from_bytes(data, offset)
            (index,) = unpack_from("<I", data, offset=offset)
            offset += 4
            fmt = "2xHI"
            (attr, index) = unpack_from(fmt, data, offset=offset)
        else:
            (index,) = unpack_from("<H", data, offset=offset)
            offset += 2
            (attr, offset) = FieldAttr.from_bytes(data, offset)

        (name, offset) = read_pascal_string(data, offset)

        return (cls(index, attr, name), offset)


@dataclass(frozen=True)
class LfMethod:
    """0408: lfMethod / lfMethod_16t, cvinfo.h"""

    count: int
    index: int
    name: str

    @classmethod
    def from_bytes(
        cls, data: bytes, *, is32: bool = False, offset: int = 0
    ) -> tuple["LfMethod", int]:
        fmt = "2HI" if is32 else "3H"
        (_, count, index) = unpack_from(fmt, data, offset=offset)
        offset += calcsize(fmt)
        (name, offset) = read_pascal_string(data, offset)

        return (cls(count, index, name), offset)


@dataclass(frozen=True)
class LfNestType:
    """0409: lfNestType / lfNestType_16t, cvinfo.h"""

    index: int
    name: str

    @classmethod
    def from_bytes(
        cls, data: bytes, *, is32: bool = False, offset: int = 0
    ) -> tuple["LfNestType", int]:
        fmt = "HI" if is32 else "2H"
        (_, index) = unpack_from(fmt, data, offset=offset)
        offset += calcsize(fmt)
        (name, offset) = read_pascal_string(data, offset)

        return (cls(index, name), offset)


@dataclass(frozen=True)
class LfVFuncTab:
    """040a: lfVFuncTab / lfVFuncTab_16t, cvinfo.h"""

    index: int

    @classmethod
    def from_bytes(
        cls, data: bytes, *, is32: bool = False, offset: int = 0
    ) -> tuple["LfVFuncTab", int]:
        fmt = "HI" if is32 else "2H"
        (_, index) = unpack_from(fmt, data, offset=offset)
        offset += calcsize(fmt)

        return (cls(index), offset)


@dataclass(frozen=True)
class LfOneMethod:
    """040c: lfOneMethod / lfOneMethod_16t, cvinfo.h"""

    attr: FieldAttr
    index: int
    vbaseoff: int
    name: str

    @classmethod
    def from_bytes(
        cls, data: bytes, *, is32: bool = False, offset: int = 0
    ) -> tuple["LfOneMethod", int]:
        (_,) = unpack_from("<H", data, offset=offset)
        offset += 2

        (attr, offset) = FieldAttr.from_bytes(data, offset)

        fmt = "I" if is32 else "H"
        (index,) = unpack_from(fmt, data, offset=offset)
        offset += calcsize(fmt)

        if attr.mprop in (MethodProp.INTRODUCING_VIRTUAL, MethodProp.PURE_INTRO):
            (vbaseoff,) = unpack_from("<I", data, offset=offset)
            offset += 4
        else:
            vbaseoff = 0

        try:
            (name, offset) = read_pascal_string(data, offset)
        except Exception as ex:
            debug_print(data[offset:])
            raise ex

        return (cls(attr, index, vbaseoff, name), offset)


@dataclass(frozen=True)
class LfFieldList:
    """lfFieldList / lfFieldList_16t, cvinfo.h"""

    leaves: tuple

    @classmethod
    def from_bytes(cls, data: bytes, *, is32: bool = False) -> "LfFieldList":
        offset = 0
        leaves = []
        finished = False

        while offset < len(data):
            # 4-byte alignment. Skip padding bytes.
            if data[offset] in (0xF3, 0xF2, 0xF1):
                offset += data[offset] & 3
                continue

            (leaf_type,) = unpack_from("<H", data, offset=offset)

            # Save offset before it's changed after reading the leaf.
            # This is so we can print the raw bytes where reading caused an exception.
            debug_offset = offset

            try:
                is32 = leaf_type & 0x1000 == 0x1000  # oversimplified?

                leaf: Any  # TODO

                match leaf_type:
                    case 0x400 | 0x1400:
                        (leaf, offset) = LfBClass.from_bytes(
                            data, is32=is32, offset=offset
                        )
                    case 0x401 | 0x402 | 0x1401 | 0x1402:
                        (leaf, offset) = LfVBClass.from_bytes(
                            data, is32=is32, offset=offset
                        )
                    case 0x403 | 0x1502:
                        (leaf, offset) = LFEnumerate.from_bytes(
                            data, is32=is32, offset=offset
                        )
                    case 0x406 | 0x1405:
                        (leaf, offset) = LfMember.from_bytes(
                            data, is32=is32, offset=offset
                        )
                    case 0x407 | 0x1406:
                        (leaf, offset) = LfStaticMember.from_bytes(
                            data, is32=is32, offset=offset
                        )
                    case 0x408 | 0x1407:
                        (leaf, offset) = LfMethod.from_bytes(
                            data, is32=is32, offset=offset
                        )
                    case 0x409 | 0x1408:
                        (leaf, offset) = LfNestType.from_bytes(
                            data, is32=is32, offset=offset
                        )
                    case 0x40A | 0x1409:
                        (leaf, offset) = LfVFuncTab.from_bytes(
                            data, is32=is32, offset=offset
                        )
                    case 0x40C | 0x140B:
                        (leaf, offset) = LfOneMethod.from_bytes(
                            data, is32=is32, offset=offset
                        )

                    case _:
                        break
                leaves.append(leaf)

            except Exception as ex:
                print("FAILED ON THIS LEAF:")
                debug_print(data[debug_offset : debug_offset + 256])
                raise ex

        else:
            # Ran to end.
            finished = True

        # Show remaining bytes
        if not finished:
            debug_print(data[offset : offset + 16])

        return cls(tuple(leaves))
