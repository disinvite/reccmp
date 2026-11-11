import logging
from struct import calcsize, unpack_from
from reccmp.formats.pdb.common import (
    read_packed_value,
    read_pascal_string,
    read_sz_string,
)
from reccmp.formats.pdb.fieldlist import MethodProp
from reccmp.formats.pdb.leaf import LeafEnum
from reccmp.formats.pdb.tpi import PropAttr, TypeLookup, resolve_forward_refs
from .cvinfo import CvdumpTypeKey
from .type_leaves import (
    CvdumpParsedType,
    EnumItem,
    FieldListItem,
    TypeLeafString,
    VirtualBaseClass,
    VirtualBasePointer,
)
from .types import CvdumpKeyError, CvdumpTypesParser

logger = logging.getLogger(__name__)

# rgszCallConventionNames, cvdump type7.cpp
CALL_TYPE_NAMES = (
    "C Near",
    "C Far",
    "Pascal Near",
    "Pascal Far",
    "Fast Near",
    "Fast Far",
    "???",
    "STD Near",
    "STD Far",
    "SYS Near",
    "SYS Far",
    "ThisCall",
    "MIPS CALL",
    "Generic",
    "Alpha Call",
    "PPC Call",
    "SH Call",
    "ARM Call",
    "AM33 Call",
    "TriCore Call",
    "SH5 Call",
    "M32R Call",
    "CLR Call",
    "No callconv; always Inlined",
    "Vector Near",
)


def _skip_pascal_string(data: bytes, offset: int) -> int:
    return offset + data[offset] + 1


def _read_udt(
    data: bytes,
    leaf_type: TypeLeafString,
    is32: bool,
    fmt: str,
    udt: int | None,
) -> CvdumpParsedType:
    """For LF_CLASS, LF_STRUCTURE, and LF_UNION. The size field is at a different
    offset for classes and unions, but the fields before it are the same."""
    if is32:
        prop, field = unpack_from(fmt, data)
    else:
        field, prop = unpack_from(fmt, data)

    size, offset = read_packed_value(data, calcsize(fmt))
    name, _ = read_pascal_string(data, offset)
    obj: CvdumpParsedType = {"type": leaf_type, "name": name, "size": size}

    if prop & PropAttr.FWDREF.value:
        obj["is_forward_ref"] = True
        if udt is not None:
            obj["udt"] = CvdumpTypeKey(udt)
    else:
        obj["field_list_type"] = CvdumpTypeKey(field)

    return obj


def _read_enum(data: bytes, is32: bool, udt: int | None) -> CvdumpParsedType:
    if is32:
        fmt = "<6xH2I"
        prop, utype, field = unpack_from(fmt, data)
    else:
        fmt = "<6x3H"
        utype, field, prop = unpack_from(fmt, data)

    name, _ = read_pascal_string(data, calcsize(fmt))

    obj: CvdumpParsedType = {
        "type": TypeLeafString.ENUM,
        "name": name,
        "underlying_type": CvdumpTypeKey(utype),
        "field_list_type": CvdumpTypeKey(field),
    }

    if prop & PropAttr.FWDREF.value:
        obj["is_forward_ref"] = True
        if udt is not None:
            obj["udt"] = CvdumpTypeKey(udt)

    return obj


def _read_fieldlist(data: bytes) -> CvdumpParsedType:
    obj: CvdumpParsedType = {"type": TypeLeafString.FIELDLIST}
    members: list[FieldListItem] = []
    super_classes: dict[CvdumpTypeKey, int] = {}
    vbases: list[VirtualBaseClass] = []
    vboffset: int | None = None
    variants: list[EnumItem] = []

    offset = 4
    while offset < len(data):
        # LF_PAD1 through LF_PAD15: skip this many bytes.
        if data[offset] > 0xF0:
            offset += data[offset] & 0x0F
            continue

        (sub_type,) = unpack_from("<H", data, offset=offset)
        offset += 2

        match sub_type:
            case LeafEnum.LF_BCLASS_16t | LeafEnum.LF_BCLASS:
                fmt = "<2xI" if sub_type & 0x1000 else "<H2x"
                (index,) = unpack_from(fmt, data, offset=offset)
                base_offset, offset = read_packed_value(data, offset + calcsize(fmt))
                super_classes[CvdumpTypeKey(index)] = base_offset

            case (
                LeafEnum.LF_VBCLASS_16t
                | LeafEnum.LF_IVBCLASS_16t
                | LeafEnum.LF_VBCLASS
                | LeafEnum.LF_IVBCLASS
            ):
                fmt = "<2xI4x" if sub_type & 0x1000 else "<H4x"
                (index,) = unpack_from(fmt, data, offset=offset)
                vbpoff, offset = read_packed_value(data, offset + calcsize(fmt))
                vbind, offset = read_packed_value(data, offset)
                if vboffset is None:
                    vboffset = vbpoff
                vbases.append(
                    VirtualBaseClass(
                        type=CvdumpTypeKey(index),
                        index=vbind,
                        direct=sub_type
                        in (LeafEnum.LF_VBCLASS_16t, LeafEnum.LF_VBCLASS),
                    )
                )

            case LeafEnum.LF_ENUMERATE_ST | LeafEnum.LF_ENUMERATE:
                read_name = (
                    read_sz_string
                    if sub_type == LeafEnum.LF_ENUMERATE
                    else read_pascal_string
                )
                value, offset = read_packed_value(data, offset + 2)
                name, offset = read_name(data, offset)
                variants.append(EnumItem(name=name, value=value))

            case LeafEnum.LF_MEMBER_16t | LeafEnum.LF_MEMBER_ST:
                fmt = "<2xI" if sub_type & 0x1000 else "<H2x"
                (index,) = unpack_from(fmt, data, offset=offset)
                field_offset, offset = read_packed_value(data, offset + calcsize(fmt))
                name, offset = read_pascal_string(data, offset)
                members.append(
                    FieldListItem(
                        offset=field_offset, name=name, type=CvdumpTypeKey(index)
                    )
                )

            case LeafEnum.LF_STMEMBER_16t | LeafEnum.LF_METHOD_16t:
                offset = _skip_pascal_string(data, offset + 4)

            case (
                LeafEnum.LF_STMEMBER_ST
                | LeafEnum.LF_METHOD_ST
                | LeafEnum.LF_NESTTYPE_ST
            ):
                offset = _skip_pascal_string(data, offset + 6)

            case LeafEnum.LF_NESTTYPE_16t:
                offset = _skip_pascal_string(data, offset + 2)

            case LeafEnum.LF_VFUNCTAB_16t:
                obj["has_vftable"] = True
                offset += 2

            case LeafEnum.LF_VFUNCTAB:
                obj["has_vftable"] = True
                offset += 6

            case LeafEnum.LF_ONEMETHOD_16t | LeafEnum.LF_ONEMETHOD_ST:
                (attr,) = unpack_from("<H", data, offset=offset)
                offset += 4 if sub_type == LeafEnum.LF_ONEMETHOD_16t else 6
                # Introducing virtual and pure introducing virtual methods
                # have the vtable offset.
                if (attr >> 2) & 7 in (
                    MethodProp.INTRODUCING_VIRTUAL,
                    MethodProp.PURE_INTRO,
                ):
                    offset += 4
                offset = _skip_pascal_string(data, offset)

            case _:
                logger.error("Unhandled field list leaf type %#x", sub_type)
                break

    if members:
        obj["members"] = members

    if super_classes:
        obj["super"] = super_classes

    if vboffset is not None:
        obj["vbase"] = VirtualBasePointer(
            vboffset=vboffset, bases=sorted(vbases, key=lambda base: base.index)
        )

    if variants:
        obj["variants"] = variants

    return obj


def _read_modifier(data: bytes, is32: bool) -> CvdumpParsedType:
    (index,) = unpack_from("<I" if is32 else "<2xH", data, offset=4)
    return {
        "type": TypeLeafString.MODIFIER,
        "is_forward_ref": True,  # TODO: #574
        "modifies": CvdumpTypeKey(index),
    }


def _read_pointer(data: bytes, is32: bool) -> CvdumpParsedType:
    (index,) = unpack_from("<I" if is32 else "<2xH", data, offset=4)
    return {
        "type": TypeLeafString.POINTER,
        "element_type": CvdumpTypeKey(index),
    }


def _read_array(data: bytes, is32: bool) -> CvdumpParsedType:
    fmt = "<4xI4x" if is32 else "<4xH2x"
    (elemtype,) = unpack_from(fmt, data)
    size, _ = read_packed_value(data, calcsize(fmt))
    return {
        "type": TypeLeafString.ARRAY,
        "array_type": CvdumpTypeKey(elemtype),
        "size": size,
    }


def _read_class(
    data: bytes, leaf_type: TypeLeafString, is32: bool, udt: int | None
) -> CvdumpParsedType:
    """For LF_CLASS and LF_STRUCTURE."""
    fmt = "<6xHI8x" if is32 else "<6x2H4x"
    return _read_udt(data, leaf_type, is32, fmt, udt)


def _read_union(data: bytes, is32: bool, udt: int | None) -> CvdumpParsedType:
    fmt = "<6xHI" if is32 else "<6x2H"
    return _read_udt(data, TypeLeafString.UNION, is32, fmt, udt)


def _read_procedure(data: bytes, is32: bool) -> CvdumpParsedType:
    if is32:
        return_type, call_type, arglist = unpack_from("<IB3xI", data, offset=4)
    else:
        return_type, call_type, arglist = unpack_from("<HB3xH", data, offset=4)

    return {
        "type": TypeLeafString.PROCEDURE,
        "return_type": CvdumpTypeKey(return_type),
        "call_type": CALL_TYPE_NAMES[call_type],
        "arg_list_type": CvdumpTypeKey(arglist),
    }


def _read_mfunction(data: bytes, is32: bool) -> CvdumpParsedType:
    fmt = "<2I4xB3xII" if is32 else "<2H2xB3xHI"
    return_type, class_type, call_type, arglist, this_adjust = unpack_from(
        fmt, data, offset=4
    )
    return {
        "type": TypeLeafString.MFUNCTION,
        "return_type": CvdumpTypeKey(return_type),
        "class_type": CvdumpTypeKey(class_type),
        "call_type": CALL_TYPE_NAMES[call_type],
        "arg_list_type": CvdumpTypeKey(arglist),
        "this_adjust": this_adjust,
    }


def _read_arglist(data: bytes, is32: bool) -> CvdumpParsedType:
    if is32:
        (count,) = unpack_from("<I", data, offset=4)
        args = unpack_from(f"<{count}I", data, offset=8)
    else:
        (count,) = unpack_from("<H", data, offset=4)
        args = unpack_from(f"<{count}H", data, offset=6)

    obj: CvdumpParsedType = {"type": TypeLeafString.ARGLIST, "argcount": count}
    if args:
        obj["args"] = [CvdumpTypeKey(arg) for arg in args]
    return obj


def _read_bitfield(data: bytes, is32: bool) -> CvdumpParsedType:
    (bit_type,) = unpack_from("<I" if is32 else "<2xH", data, offset=4)
    return {
        "type": TypeLeafString.BITFIELD,
        "bit_type": CvdumpTypeKey(bit_type),
    }


def _read_leaf(data: bytes, udt: int | None) -> CvdumpParsedType | None:
    (leaf_type,) = unpack_from("<H", data, offset=2)
    is32 = leaf_type & 0x1000 == 0x1000
    obj: CvdumpParsedType

    match leaf_type:
        case LeafEnum.LF_MODIFIER_16t | LeafEnum.LF_MODIFIER:
            obj = _read_modifier(data, is32)

        case LeafEnum.LF_POINTER_16t | LeafEnum.LF_POINTER:
            obj = _read_pointer(data, is32)

        case LeafEnum.LF_ARRAY_16t | LeafEnum.LF_ARRAY_ST:
            obj = _read_array(data, is32)

        case LeafEnum.LF_CLASS_16t | LeafEnum.LF_CLASS_ST:
            obj = _read_class(data, TypeLeafString.CLASS, is32, udt)

        case LeafEnum.LF_STRUCTURE_16t | LeafEnum.LF_STRUCTURE_ST:
            obj = _read_class(data, TypeLeafString.STRUCTURE, is32, udt)

        case LeafEnum.LF_UNION_16t | LeafEnum.LF_UNION_ST:
            obj = _read_union(data, is32, udt)

        case LeafEnum.LF_ENUM_16t | LeafEnum.LF_ENUM_ST:
            obj = _read_enum(data, is32, udt)

        case LeafEnum.LF_PROCEDURE_16t | LeafEnum.LF_PROCEDURE:
            obj = _read_procedure(data, is32)

        case LeafEnum.LF_MFUNCTION_16t | LeafEnum.LF_MFUNCTION:
            obj = _read_mfunction(data, is32)

        case LeafEnum.LF_ARGLIST_16t | LeafEnum.LF_ARGLIST:
            obj = _read_arglist(data, is32)

        case LeafEnum.LF_FIELDLIST_16t | LeafEnum.LF_FIELDLIST:
            obj = _read_fieldlist(data)

        case LeafEnum.LF_BITFIELD_16t | LeafEnum.LF_BITFIELD:
            obj = _read_bitfield(data, is32)

        case _:
            return None

    return obj


class PdbTypesParser(CvdumpTypesParser):
    """Reads types from the PDB TPI stream instead of cvdump output."""

    def __init__(self, data: bytes) -> None:
        super().__init__()
        self._types = TypeLookup(data)
        self._forward_refs = resolve_forward_refs(self._types)

    def _parse_raw(self, leaf_id: CvdumpTypeKey) -> CvdumpParsedType:
        try:
            data = self._types[leaf_id]
        except KeyError as ex:
            raise CvdumpKeyError(leaf_id) from ex

        leaf = _read_leaf(data, self._forward_refs.get(leaf_id))
        if leaf is None:
            raise CvdumpKeyError(leaf_id)

        self._keys[leaf_id] = leaf
        return leaf
