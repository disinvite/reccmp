from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from enum import Enum, Flag
from struct import calcsize, iter_unpack, unpack_from
from typing import Any
from .codeview import CodeViewRecord
from .common import read_map, read_packed_value, read_pascal_string
from .fieldlist import LfFieldList
from .debug import debug_print
from .leaf import CodeViewLeaf
from .msf import PDBStreams, StreamIndex
from .names import NameTable, read_named_streams


@dataclass(frozen=True)
class TPIHeader:
    # pylint: disable=too-many-instance-attributes
    version: int
    id_start: int
    id_end: int
    size: int
    header_size: int
    # TpiHash, tpi.h. Only in the MSVC 5+ header.
    hash_stream: int | None = None
    hash_adj_offset: int = 0
    hash_adj_size: int = 0

    @classmethod
    def from_bytes(cls, data: bytes) -> "TPIHeader":
        (version,) = unpack_from("<I", data)
        match version:
            # n.b. The TPI stream in a real PDB 1.00 file has no version data.
            # This is mocked by PDB100File.
            case 920924:
                id_start, id_end, size = unpack_from("<HHI", data, offset=4)
                return cls(version, id_start, id_end, size, header_size=12)

            # MSVC 4.1+
            case 19951122:
                id_start, id_end, size = unpack_from("<HHI", data, offset=4)
                return cls(version, id_start, id_end, size, header_size=16)

            # MSVC 5+
            case 19961031:
                header_size, id_start, id_end, size = unpack_from(
                    "<IIII", data, offset=4
                )
                (hash_stream,) = unpack_from("<H", data, offset=20)
                hash_adj_offset, hash_adj_size = unpack_from("<ii", data, offset=48)
                return cls(
                    version,
                    id_start,
                    id_end,
                    size,
                    header_size=header_size,
                    hash_stream=hash_stream,
                    hash_adj_offset=hash_adj_offset,
                    hash_adj_size=hash_adj_size,
                )

            case _:
                raise ValueError("TPI header format not supported")


def _strip_record_prefixes(leaves: bytes) -> Iterator[bytes]:
    """Skip 16-bit hash in PDB 1.00 type records (struct RTPDB10HASHEDTI)."""
    offset = 0
    while offset < len(leaves):
        (size,) = unpack_from("<H", leaves, offset=offset + 2)
        yield leaves[offset + 2 : offset + 4 + size]
        offset += 4 + size


class TypeLookup(Mapping[int, bytes]):
    def __init__(self, data: bytes) -> None:
        self.header = TPIHeader.from_bytes(data)
        leaves = data[self.header.header_size :][: self.header.size]
        if self.header.version == 920924:
            self._leaves = tuple(_strip_record_prefixes(leaves))
        else:
            self._leaves = tuple(
                leaves[record.offset : record.offset + record.size]
                for record in CodeViewRecord.from_bytes(leaves)
            )

    def __getitem__(self, ti: int) -> bytes:
        if not self.header.id_start <= ti < self.header.id_start + len(self._leaves):
            raise KeyError(ti)
        return self._leaves[ti - self.header.id_start]

    def __iter__(self) -> Iterator[int]:
        return iter(range(self.header.id_start, self.header.id_start + len(self)))

    def __len__(self) -> int:
        return len(self._leaves)


class PtrType(Enum):
    """CV_ptrtype_e, cvinfo.h"""

    CV_PTR_NEAR = 0x00  # 16 bit pointer
    CV_PTR_FAR = 0x01  # 16:16 far pointer
    CV_PTR_HUGE = 0x02  # 16:16 huge pointer
    CV_PTR_BASE_SEG = 0x03  # based on segment
    CV_PTR_BASE_VAL = 0x04  # based on value of base
    CV_PTR_BASE_SEGVAL = 0x05  # based on segment value of base
    CV_PTR_BASE_ADDR = 0x06  # based on address of base
    CV_PTR_BASE_SEGADDR = 0x07  # based on segment address of base
    CV_PTR_BASE_TYPE = 0x08  # based on type
    CV_PTR_BASE_SELF = 0x09  # based on self
    CV_PTR_NEAR32 = 0x0A  # 32 bit pointer
    CV_PTR_FAR32 = 0x0B  # 16:32 pointer
    CV_PTR_64 = 0x0C  # 64 bit pointer
    CV_PTR_UNUSEDPTR = 0x0D  # first unused pointer type


class PtrMode(Enum):
    """CV_ptrmode_e, cvinfo.h"""

    CV_PTR_MODE_PTR = 0x00  # "normal" pointer
    CV_PTR_MODE_LVREF = 0x01  # l-value reference
    CV_PTR_MODE_PMEM = 0x02  # pointer to data member
    CV_PTR_MODE_PMFUNC = 0x03  # pointer to member function
    CV_PTR_MODE_RVREF = 0x04  # r-value reference
    CV_PTR_MODE_RESERVED = 0x05  # first unused pointer mode


class LfPointerAttr(Flag):
    """lfPointerAttr_16t, cvinfo.h"""

    FLAT32 = 0x01
    VOLATILE = 0x02
    CONST = 0x04
    UNALIGNED = 0x08


@dataclass(frozen=True)
class MethodListMethod:
    attr: int  # TODO: FieldAttr
    index: int
    vbaseoff: int

    @classmethod
    def from_bytes(
        cls, data: bytes, offset: int = 0, *, is32: bool = False
    ) -> Iterator["MethodListMethod"]:
        while offset < len(data):
            if is32:
                attr, index = unpack_from("<H2xI", data, offset=offset)
                offset += 8
            else:
                attr, index = unpack_from("<2H", data, offset=offset)
                offset += 4

            vbaseoff = 0

            # TODO: pure intro
            if attr & 24 in (24, 16):
                (vbaseoff,) = unpack_from("<L", data, offset=offset)
                offset += 4

            yield cls(attr, index, vbaseoff)


@dataclass(frozen=True)
class LfMethodList(CodeViewLeaf):
    """lfArray_16t, cvinfo.h"""

    methods: tuple[MethodListMethod, ...]

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> "LfMethodList":
        leaf_size, leaf_type = unpack_from("<2H", data, offset=offset)
        offset += 4
        is32 = leaf_type & 0x1000 == 0x1000

        methods = tuple(
            MethodListMethod.from_bytes(data[: leaf_size + 2], offset=offset, is32=is32)
        )
        return cls(leaf_type, methods)


@dataclass(frozen=True)
class LfArray(CodeViewLeaf):
    """lfArray_16t, cvinfo.h"""

    elemtype: int
    idxtype: int
    count: int
    name: str

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> "LfArray":
        (leaf_type,) = unpack_from("<2xH", data, offset=offset)
        offset += 4
        is32 = leaf_type & 0x1000 == 0x1000

        if is32:
            elemtype, idxtype = unpack_from("<2I", data, offset=offset)
            offset += 8
        else:
            elemtype, idxtype = unpack_from("<2H", data, offset=offset)
            offset += 4

        count, offset = read_packed_value(data, offset)
        name, _ = read_pascal_string(data, offset)

        return cls(leaf_type, elemtype, idxtype, count, name)


@dataclass(frozen=True)
class LfUnion(CodeViewLeaf):
    """lfUnion_16t, cvinfo.h"""

    count: int
    field: int
    prop: int
    size: int
    name: str

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> "LfUnion":
        (leaf_type,) = unpack_from("<2xH", data, offset=offset)
        offset += 4
        is32 = leaf_type & 0x1000 == 0x1000

        if is32:
            count, prop, field = unpack_from("<2HI", data, offset=offset)
            offset += 8
        else:
            count, field, prop = unpack_from("<3H", data, offset=offset)
            offset += 6

        length, offset = read_packed_value(data, offset)
        name, _ = read_pascal_string(data, offset)

        return cls(leaf_type, count, field, prop, length, name)


@dataclass(frozen=True)
class LfModifier(CodeViewLeaf):
    """lfModifier_16t, cvinfo.h"""

    attr: int
    index: int

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> "LfModifier":
        (leaf_type,) = unpack_from("<2xH", data, offset=offset)
        offset += 4
        is32 = leaf_type & 0x1000 == 0x1000

        if is32:
            index, attr = unpack_from("<IH", data, offset=offset)
        else:
            attr, index = unpack_from("<2H", data, offset=offset)

        return cls(leaf_type, attr, index)


@dataclass(frozen=True)
class LfPointer(CodeViewLeaf):
    """lfPointer_16t, cvinfo.h"""

    attr: int
    ref_type: int

    @property
    def ptr_type(self) -> PtrType:
        return PtrType(self.attr & 0x1F)

    @property
    def ptr_mode(self) -> PtrMode:
        return PtrMode((self.attr & 0xE0) >> 5)

    @property
    def flags(self) -> LfPointerAttr:
        return LfPointerAttr((self.attr & 0x700) >> 8)

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> "LfPointer":
        (leaf_type,) = unpack_from("<2xH", data, offset=offset)
        offset += 4
        is32 = leaf_type & 0x1000 == 0x1000

        if is32:
            index, attr = unpack_from("<2I", data, offset=offset)
        else:
            attr, index = unpack_from("<2H", data, offset=offset)

        return cls(leaf_type, attr, index)

    def __str__(self) -> str:
        return "".join(
            [
                f"LF_POINTER: Element type: {self.ref_type:4x}\n",
                f"  Flags: {self.flags}\n" if self.flags else "",
                f"  Type: {self.ptr_type}\n",
                (
                    f"  Mode: {self.ptr_mode}\n"
                    if self.ptr_mode != PtrMode.CV_PTR_MODE_PTR
                    else ""
                ),
            ]
        )


class FuncAttr(Flag):
    """CV_funcattr_t, cvinfo.h"""

    CXXRETURNUDT = 0x01
    CTOR = 0x02
    CTROVBASE = 0x03


# pylint:disable=too-many-instance-attributes
@dataclass(frozen=True)
class LfMFunction(CodeViewLeaf):
    """lfMFunc / lfMFunc_16t, cvinfo.h"""

    return_type: int
    class_type: int
    this_type: int
    call_type: int  # TODO: call_t enum here.
    raw_attr: int
    parmcount: int
    arglist: int
    this_adjust: int

    @property
    def attr(self) -> FuncAttr:
        return FuncAttr(self.raw_attr)

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> "LfMFunction":
        (leaf_type,) = unpack_from("<2xH", data, offset=offset)
        offset += 4
        is32 = leaf_type & 0x1000 == 0x1000

        if is32:
            fmt = "<3I2BH2I"
        else:
            fmt = "<3H2B2HI"

        raw: tuple[int, int, int, int, int, int, int, int] = unpack_from(
            fmt, data, offset=offset
        )
        return cls(leaf_type, *raw)


@dataclass(frozen=True)
class LfProcedure(CodeViewLeaf):
    """lfProc / lfProc_16t, cvinfo.h"""

    return_type: int
    call_type: int  # TODO: call_t enum here.
    raw_attr: int
    parmcount: int
    arglist: int

    @property
    def attr(self) -> FuncAttr:
        return FuncAttr(self.raw_attr)

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> "LfProcedure":
        (leaf_type,) = unpack_from("<2xH", data, offset=offset)
        offset += 4
        is32 = leaf_type & 0x1000 == 0x1000

        if is32:
            fmt = "<I2BHI"
        else:
            fmt = "<H2B2H"

        raw: tuple[int, int, int, int, int] = unpack_from(fmt, data, offset=offset)
        return cls(leaf_type, *raw)


class PropAttr(Flag):
    """CV_prop_t, cvinfo.h"""

    PACKED = 0x0001  # true if structure is packed
    CTOR = 0x0002  # true if constructors or destructors present
    OVLOPS = 0x0004  # true if overloaded operators present
    ISNESTED = 0x0008  # true if this is a nested class
    CNESTED = 0x0010  # true if this class contains nested types
    OPASSIGN = 0x0020  # true if overloaded assignment (=)
    OPCAST = 0x0040  # true if casting methods
    FWDREF = 0x0080  # true if forward reference (incomplete defn)
    SCOPED = 0x0100  # scoped definition
    HASUNIQUENAME = (
        0x0200  # true if there is a decorated name following the regular name
    )
    SEALED = 0x0400  # true if class cannot be used as a base class
    HFA = 0x0800  # CV_HFA_e (2 bits)
    _DUMMY = 0x1000  # TODO
    INTRINSIC = 0x2000  # true if class is an intrinsic type (e.g. __m128d)
    MOCOM = 0x4000  # CV_MOCOM_UDT_e (2 bits)


@dataclass(frozen=True)
class LfClass(CodeViewLeaf):
    """lfClass_16t, cvinfo.h"""

    element_count: int
    field: int
    raw_prop_attr: int
    derived: int
    vshape: int
    size: int
    name: str

    @property
    def prop_attr(self) -> PropAttr:
        return PropAttr(self.raw_prop_attr)

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> "LfClass":
        (leaf_type,) = unpack_from("<2xH", data, offset=offset)
        offset += 4
        is32 = leaf_type & 0x1000 == 0x1000

        # Derivation list type always zero?
        if is32:
            fmt = "<2H3I"
            count, attr, field, derived, vshape = unpack_from(fmt, data, offset=offset)
        else:
            fmt = "<5H"
            count, field, attr, derived, vshape = unpack_from(fmt, data, offset=offset)

        # Pascal string with the name of the class follows the leaf data.
        offset += calcsize(fmt)
        size, offset = read_packed_value(data, offset)
        name, _ = read_pascal_string(data, offset)

        return cls(leaf_type, count, field, attr, derived, vshape, size, name)

    def __str__(self) -> str:
        return f"LF_CLASS {self.name[:32]:32} {self.element_count:3} mem.  vshape: {self.vshape:4x}  size: {self.size:3}  attr: {self.prop_attr}"


@dataclass(frozen=True)
class LfEnum(CodeViewLeaf):
    """lfEnum_16t / lfEnum, cvinfo.h"""

    count: int
    prop: int
    utype: int
    index: int
    name: str

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> "LfEnum":
        (leaf_type,) = unpack_from("<2xH", data, offset=offset)
        offset += 4
        is32 = leaf_type & 0x1000 == 0x1000

        if is32:
            count, prop, utype, index = unpack_from("<2H2I", data, offset=offset)
            offset += 12
        else:
            count, utype, index, prop = unpack_from("<4H", data, offset=offset)
            offset += 8

        name, _ = read_pascal_string(data, offset)

        return cls(leaf_type, count, prop, utype, index, name)


@dataclass(frozen=True)
class LfArglist(CodeViewLeaf):
    """lfArgList_16t / lfArgList, cvinfo.h"""

    args: tuple[int, ...]

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> "LfArglist":
        (leaf_type,) = unpack_from("<2xH", data, offset=offset)
        offset += 4
        is32 = leaf_type & 0x1000 == 0x1000

        if is32:
            (count,) = unpack_from("<I", data, offset=offset)
            offset += 4
            arg_data = data[offset : offset + 4 * count]
            args = tuple(arg for arg, in iter_unpack("<I", arg_data))
        else:
            (count,) = unpack_from("<H", data, offset=offset)
            offset += 2
            arg_data = data[offset : offset + 2 * count]
            args = tuple(arg for arg, in iter_unpack("<H", arg_data))

        return cls(leaf_type, args)


@dataclass(frozen=True)
class LfBitfield(CodeViewLeaf):
    """lfBitfield_16t / lfBitfield, cvinfo.h"""

    length: int
    position: int
    type: int

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> "LfBitfield":
        (leaf_type,) = unpack_from("<2xH", data, offset=offset)
        offset += 4
        is32 = leaf_type & 0x1000 == 0x1000

        if is32:
            bit_type, length, position = unpack_from("<I2B", data, offset=offset)
        else:
            length, position, bit_type = unpack_from("<2BH", data, offset=offset)

        return cls(leaf_type, length, position, bit_type)


def _is_anonymous_udt(name: str) -> bool:
    """fUDTAnon, tm.cpp"""
    return name in ("<unnamed-tag>", "__unnamed") or name.endswith(
        ("::<unnamed-tag>", "::__unnamed")
    )


def read_hash_heads(pdb: PDBStreams) -> dict[str, int]:
    """Map UDT name to the type index the linker put at the head of its hash chain.
    TPI1::fInitHashToPchnMap, tpi.cpp"""
    header = TPIHeader.from_bytes(pdb.get_stream(StreamIndex.TPI))
    if header.hash_stream is None or header.hash_adj_size <= 0:
        return {}

    hash_data = pdb.get_stream(header.hash_stream)
    adjusters = read_map(hash_data, header.hash_adj_offset)

    named_streams = read_named_streams(pdb.get_stream(StreamIndex.PDB))
    names = NameTable(pdb.get_stream(named_streams["/names"]))
    return {names[ni]: ti for ni, ti in adjusters}


def resolve_forward_refs(
    types: Mapping[int, bytes], hash_heads: Mapping[str, int] | None = None
) -> dict[int, int]:
    """Map the type index of each class, struct, union, and enum forward ref
    to the type index of its definition. Forward refs with no definition are left out.
    If there is more than one definition with the same name, the one in hash_heads wins.
    Otherwise the last one wins. This matches QueryTiForUDT, tpi.cpp."""
    udts: dict[str, int] = {}
    forward_refs: list[tuple[int, str]] = []

    for ti, data in types.items():
        (leaf_type,) = unpack_from("<H", data, offset=2)
        leaf: LfClass | LfUnion | LfEnum

        match leaf_type:
            case 4 | 5 | 0x1004 | 0x1005:
                leaf = LfClass.from_bytes(data)
                prop = leaf.raw_prop_attr
            case 6 | 0x1006:
                leaf = LfUnion.from_bytes(data)
                prop = leaf.prop
            case 7 | 0x1007:
                leaf = LfEnum.from_bytes(data)
                prop = leaf.prop
            case _:
                continue

        # Scoped types are not found by name. See REC::fIsGlobalDefnUdt.
        if prop & PropAttr.SCOPED.value:
            continue

        if prop & PropAttr.FWDREF.value:
            forward_refs.append((ti, leaf.name))

        elif not _is_anonymous_udt(leaf.name):
            udts[leaf.name] = ti

    if hash_heads:
        udts.update(hash_heads)

    return {ti: udts[name] for ti, name in forward_refs if name in udts}


def parse_types(data: bytes):
    debug_print(data, size=64)
    header = TPIHeader.from_bytes(data)
    print(header)

    leaves = data[header.header_size :][: header.size]
    unhandled_types: dict[int, set[int]] = {}

    for i, record in enumerate(
        CodeViewRecord.from_bytes(leaves), start=header.id_start
    ):
        leaf: Any = None  # TODO

        try:
            match record.type:
                case 1 | 0x1001:
                    leaf = LfModifier.from_bytes(leaves, record.offset)
                case 2 | 0x1002:
                    leaf = LfPointer.from_bytes(leaves, record.offset)
                case 3 | 0x1003:
                    leaf = LfArray.from_bytes(leaves, record.offset)
                case 4 | 5 | 0x1004 | 0x1005:
                    leaf = LfClass.from_bytes(leaves, record.offset)
                case 6 | 0x1006:
                    leaf = LfUnion.from_bytes(leaves, record.offset)
                case 7 | 0x1007:
                    leaf = LfEnum.from_bytes(leaves, record.offset)
                case 8 | 0x1008:
                    leaf = LfProcedure.from_bytes(leaves, record.offset)
                case 9 | 0x1009:
                    leaf = LfMFunction.from_bytes(leaves, record.offset)
                case 0x201 | 0x1201:
                    leaf = LfArglist.from_bytes(leaves, record.offset)
                case 0x204 | 0x1203:
                    leaf = LfFieldList.from_bytes(leaves, record.offset)
                case 0x207 | 0x1206:
                    leaf = LfMethodList.from_bytes(leaves, record.offset)

                case _:
                    unhandled_types.setdefault(record.type, set()).add(i)

        except Exception as ex:
            print("FAILED ON THIS DATA:")
            debug_print(leaves[record.offset : record.offset + record.size])
            raise ex

        if leaf:
            print(f"{i:4x} -> {leaf}")

    if unhandled_types:
        print("Unhandled types:")

    for type_id, count in sorted(
        unhandled_types.items(), key=lambda v: len(v[1]), reverse=True
    ):
        print(f"{type_id:4x} ... {len(count)}")
