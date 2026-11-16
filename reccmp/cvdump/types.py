import re
import logging
from dataclasses import dataclass
from enum import Enum, auto
from typing import Mapping, NamedTuple
from .cvinfo import (
    CvInfoType,
    CvdumpTypeKey,
    CvdumpTypeMap,
)
from .type_leaves import (
    CvdumpParsedType,
    EnumItem,
    FieldListItem,
    TypeLeafString,
    VirtualBaseClass,
    read_arglist,
    read_array,
    read_bitfield,
    read_class_or_struct,
    read_enum,
    read_fieldlist,
    read_mfunction,
    read_modifier,
    read_pointer,
    read_procedure,
    read_udt_name,
    read_union,
)

logger = logging.getLogger(__name__)


class CvdumpValueError(ValueError):
    """The type key is incorrect for this operation."""


class CvdumpKeyError(KeyError):
    """The type key does not exist in the database."""


def get_primitive(key: CvdumpTypeKey) -> CvInfoType:
    """Throw CvdumpKeyError if we get a KeyError from the primitive map.
    Log an error for the invalid type whether the exception is caught or not."""
    try:
        return CvdumpTypeMap[key]
    except KeyError as ex:
        logger.error("Unknown scalar type 0x%x", key)
        raise CvdumpKeyError(key) from ex


def _is_anonymous_udt(name: str) -> bool:
    """fUDTAnon, tm.cpp"""
    return name in ("<unnamed-tag>", "__unnamed") or name.endswith(
        ("::<unnamed-tag>", "::__unnamed")
    )


class UdtProps(NamedTuple):
    """The attributes of a class, struct, union, or enum leaf that decide
    whether it can be found by name."""

    name: str
    is_forward_ref: bool
    is_scoped: bool
    udt: CvdumpTypeKey | None
    """The definition cvdump found for this name, if any."""


def build_udt_name_map(
    udts: Mapping[CvdumpTypeKey, UdtProps], overrides: Mapping[str, CvdumpTypeKey]
) -> dict[str, CvdumpTypeKey]:
    """Map each UDT name to the key of its definition.
    If there is more than one definition with the same name, the one in overrides wins.
    Otherwise the last one wins. This matches QueryTiForUDT, tpi.cpp."""
    names: dict[str, CvdumpTypeKey] = {}

    for key, udt in udts.items():
        # Scoped types are not found by name. See REC::fIsGlobalDefnUdt.
        if udt.is_scoped or udt.is_forward_ref or _is_anonymous_udt(udt.name):
            continue

        names[udt.name] = key

    names.update(overrides)
    return names


def resolve_udt_forward_refs(
    udts: Mapping[CvdumpTypeKey, UdtProps], names: Mapping[str, CvdumpTypeKey]
) -> dict[CvdumpTypeKey, CvdumpTypeKey]:
    """Map the key of each forward ref to the key of its definition.
    Forward refs with no definition are left out."""
    return {
        key: names[udt.name]
        for key, udt in udts.items()
        if udt.is_forward_ref and not udt.is_scoped and udt.name in names
    }


class TypeKind(Enum):
    SCALAR = auto()
    POINTER = auto()
    ARRAY = auto()
    STRUCT = auto()
    CLASS = auto()
    UNION = auto()
    ENUM = auto()
    BITFIELD = auto()
    FUNCTION = auto()


LEAF_KINDS: dict[str, TypeKind] = {
    TypeLeafString.POINTER: TypeKind.POINTER,
    TypeLeafString.ARRAY: TypeKind.ARRAY,
    TypeLeafString.CLASS: TypeKind.CLASS,
    TypeLeafString.STRUCTURE: TypeKind.STRUCT,
    TypeLeafString.UNION: TypeKind.UNION,
    TypeLeafString.ENUM: TypeKind.ENUM,
    TypeLeafString.BITFIELD: TypeKind.BITFIELD,
    TypeLeafString.PROCEDURE: TypeKind.FUNCTION,
    TypeLeafString.MFUNCTION: TypeKind.FUNCTION,
}


class TypeInfo(NamedTuple):
    key: CvdumpTypeKey
    """The unique identifier from the PDB."""
    kind: TypeKind
    """The category for this data type."""
    size: int | None
    """Total size of this type in bytes."""
    name: str | None
    """Optional name for this complex type."""


@dataclass
class FunctionInfo:
    call_type: str
    return_type: CvdumpTypeKey
    args: list[CvdumpTypeKey]
    class_type: CvdumpTypeKey | None
    this_adjust: int


@dataclass
class ClassInfo:
    has_vftable: bool
    vbptr_offset: int | None
    """vbpoff from the field list, or None if the class has no virtual bases."""
    virtual_bases: list[VirtualBaseClass]
    """Direct and indirect virtual base classes, sorted by vbind index."""


class CvdumpTypesParser:
    """Parser for cvdump output, TYPES section.
    Tricky enough that it demands its own parser."""

    # Marks the start of a new type
    INDEX_RE = re.compile(r"(?P<key>0x\w+) : .* (?P<type>LF_\w+)")

    MODES_OF_INTEREST = {e.value for e in TypeLeafString}

    UDT_LEAVES = {
        TypeLeafString.CLASS,
        TypeLeafString.STRUCTURE,
        TypeLeafString.UNION,
        TypeLeafString.ENUM,
    }

    def __init__(self) -> None:
        self._keys: dict[CvdumpTypeKey, CvdumpParsedType] = {}
        self._raw: dict[CvdumpTypeKey, tuple[str, str]] = {}
        self._udt_props: dict[CvdumpTypeKey, UdtProps] = {}
        self._udt_by_name: dict[str, CvdumpTypeKey] = {}
        self._forward_refs: dict[CvdumpTypeKey, CvdumpTypeKey] = {}
        self.alerted_types: set[int] = set()

    def from_key(self, type_key: CvdumpTypeKey) -> CvdumpParsedType:
        try:
            return self._keys[type_key]
        except KeyError:
            pass

        return self._parse_raw(type_key)

    def get_udt_props(self) -> dict[CvdumpTypeKey, UdtProps]:
        return self._udt_props

    def get_type_by_name(self, name: str) -> CvdumpTypeKey | None:
        """Returns the key of the class, struct, union, or enum with this name."""
        return self._udt_by_name.get(name)

    def _primitive(self, type_key: CvdumpTypeKey) -> CvInfoType:
        cvinfo = get_primitive(type_key)
        # We have seen some of the primitive types so far, but not all.
        # The information in cvinfo.h is probably fine for most cases
        # but warn users if we are dealing with an unseen type.
        # (If you see this message in your project, we want to hear about it!)
        if not cvinfo.verified and cvinfo.key not in self.alerted_types:
            self.alerted_types.add(cvinfo.key)
            logger.info(
                "Unverified primitive type 0x%04x '%s'",
                cvinfo.key,
                cvinfo.name,
            )

        return cvinfo

    def _resolved_leaf(self, type_key: CvdumpTypeKey) -> CvdumpParsedType:
        leaf = self.from_key(type_key)
        if leaf.get("is_forward_ref", False):
            raise CvdumpKeyError(f"Type {type_key} is a forward ref. Call get() first.")

        return leaf

    def _expect_leaf(
        self, type_key: CvdumpTypeKey, *leaf_types: str
    ) -> CvdumpParsedType:
        """Make sure that the given type key is backed by a specific leaf type."""
        if type_key.is_scalar():
            raise CvdumpValueError(f"{type_key} is scalar, expected {str(leaf_types)}")

        leaf = self._resolved_leaf(type_key)
        if leaf["type"] not in leaf_types:
            raise CvdumpValueError(
                f"{type_key} is {leaf['type']}, expected {str(leaf_types)}"
            )

        return leaf

    def _field_list(self, type_key: CvdumpTypeKey) -> CvdumpParsedType:
        leaf = self._expect_leaf(
            type_key,
            TypeLeafString.CLASS,
            TypeLeafString.STRUCTURE,
            TypeLeafString.UNION,
            TypeLeafString.ENUM,
        )
        return self.from_key(leaf["field_list_type"])

    # pylint:disable=too-many-return-statements
    def get(self, type_key: CvdumpTypeKey) -> TypeInfo:
        """Returns vital information (name, size, kind) for the type key.
        All processing should start here. Forward references are resolved if possible.
        The returned `key` value should be used in place of the input argument.
        If we cannot resolve the forward reference, return a `TypeInfo` with null size.
        """
        leaf: CvdumpParsedType | None = None

        # Follow any number of forward reference indirection hops.
        # TODO: Fix shortcut: LF_MODIFIER is considered a forward reference. (GH #574)
        # No consumer uses the `const` or `volatile` modifier options.
        while not type_key.is_scalar():
            leaf = self.from_key(type_key)
            if not leaf.get("is_forward_ref", False):
                break

            # For LF_CLASS/LF_STRUCTURE/LF_UNION/LF_ENUM, follow the UDT value.
            # For LF_MODIFIER, it is the type being modified.
            forward_ref = self._forward_refs.get(type_key) or leaf.get("modifies")
            if forward_ref is None:
                # Example: HWND__
                kind = LEAF_KINDS.get(leaf["type"])
                if kind is None:
                    raise CvdumpKeyError(f"Null forward ref for type {type_key}")

                return TypeInfo(type_key, kind, None, leaf.get("name"))

            type_key = forward_ref

        if type_key.is_scalar():
            cvinfo = self._primitive(type_key)
            if cvinfo.pointer is not None:
                return TypeInfo(type_key, TypeKind.POINTER, cvinfo.size, None)

            return TypeInfo(type_key, TypeKind.SCALAR, cvinfo.size, None)

        assert leaf is not None
        kind = LEAF_KINDS.get(leaf["type"])
        match kind:
            case TypeKind.POINTER:
                # TODO: Assumes 32-bit pointers. (GH #573)
                return TypeInfo(type_key, kind, 4, None)

            case TypeKind.ARRAY:
                return TypeInfo(type_key, kind, leaf["size"], None)

            case TypeKind.STRUCT | TypeKind.CLASS | TypeKind.UNION:
                return TypeInfo(type_key, kind, leaf["size"], leaf.get("name"))

            case TypeKind.ENUM:
                size = self.get(leaf["underlying_type"]).size
                return TypeInfo(type_key, kind, size, leaf.get("name"))

            case TypeKind.BITFIELD:
                size = self.get(leaf["bit_type"]).size
                return TypeInfo(type_key, kind, size, None)

            case TypeKind.FUNCTION:
                return TypeInfo(type_key, kind, None, None)

        raise CvdumpValueError(f"{type_key} is {leaf['type']}, cannot resolve")

    def element_type(self, type_key: CvdumpTypeKey) -> CvdumpTypeKey:
        """Return the type being referenced by the pointer or array."""
        if type_key.is_scalar():
            pointee_type = self._primitive(type_key).pointer
            if pointee_type is None:
                raise CvdumpValueError(f"{type_key} is not a pointer")

            return pointee_type

        leaf = self._expect_leaf(type_key, TypeLeafString.POINTER, TypeLeafString.ARRAY)
        if leaf["type"] == TypeLeafString.ARRAY:
            return leaf["array_type"]

        return leaf["element_type"]

    def underlying_type(self, type_key: CvdumpTypeKey) -> CvdumpTypeKey:
        """Returns the type footprint of the given enum or bitfield."""
        leaf = self._expect_leaf(type_key, TypeLeafString.ENUM, TypeLeafString.BITFIELD)
        if leaf["type"] == TypeLeafString.BITFIELD:
            return leaf["bit_type"]

        return leaf["underlying_type"]

    def members(self, type_key: CvdumpTypeKey) -> list[FieldListItem]:
        """Returns members of a struct or union. Order is not guaranteed. Callers should sort.
        Call `base_classes()` to access members from direct base classes."""
        self._expect_leaf(
            type_key,
            TypeLeafString.CLASS,
            TypeLeafString.STRUCTURE,
            TypeLeafString.UNION,
        )

        return list(self._field_list(type_key).get("members", []))

    def base_classes(self, type_key: CvdumpTypeKey) -> dict[CvdumpTypeKey, int]:
        """Returns the type and offset of direct base classes for the given class."""
        self._expect_leaf(type_key, TypeLeafString.CLASS, TypeLeafString.STRUCTURE)

        return dict(self._field_list(type_key).get("super", {}))

    def class_info(self, type_key: CvdumpTypeKey) -> ClassInfo:
        """Returns class-specific information for the given class."""
        self._expect_leaf(type_key, TypeLeafString.CLASS, TypeLeafString.STRUCTURE)

        field_list = self._field_list(type_key)
        vbase = field_list.get("vbase")
        return ClassInfo(
            has_vftable=field_list.get("has_vftable", False),
            vbptr_offset=vbase.vboffset if vbase is not None else None,
            virtual_bases=list(vbase.bases) if vbase is not None else [],
        )

    def enum_variants(self, type_key: CvdumpTypeKey) -> list[EnumItem]:
        """Returns all variants for the given enum type."""
        self._expect_leaf(type_key, TypeLeafString.ENUM)

        return list(self._field_list(type_key).get("variants", []))

    def function_info(self, type_key: CvdumpTypeKey) -> FunctionInfo:
        """Returns function-specific information for this function type."""
        leaf = self._expect_leaf(
            type_key, TypeLeafString.PROCEDURE, TypeLeafString.MFUNCTION
        )

        arg_list = self.from_key(leaf["arg_list_type"])
        args = arg_list.get("args", [])
        assert arg_list["argcount"] == len(args)

        return FunctionInfo(
            call_type=leaf["call_type"],
            return_type=leaf["return_type"],
            args=args,
            class_type=leaf.get("class_type"),
            this_adjust=leaf.get("this_adjust", 0),
        )

    def _parse_raw(self, leaf_id: CvdumpTypeKey) -> CvdumpParsedType:
        try:
            leaf, leaf_type = self._raw[leaf_id]
        except KeyError as ex:
            raise CvdumpKeyError from ex

        try:
            match leaf_type:
                case TypeLeafString.MODIFIER:
                    self._keys[leaf_id] = read_modifier(leaf, leaf_type)

                case TypeLeafString.ARRAY:
                    self._keys[leaf_id] = read_array(leaf, leaf_type)

                case TypeLeafString.FIELDLIST:
                    self._keys[leaf_id] = read_fieldlist(leaf, leaf_type)

                case TypeLeafString.ARGLIST:
                    self._keys[leaf_id] = read_arglist(leaf, leaf_type)

                case TypeLeafString.MFUNCTION:
                    self._keys[leaf_id] = read_mfunction(leaf, leaf_type)

                case TypeLeafString.PROCEDURE:
                    self._keys[leaf_id] = read_procedure(leaf, leaf_type)

                case TypeLeafString.CLASS | TypeLeafString.STRUCTURE:
                    self._keys[leaf_id] = read_class_or_struct(leaf, leaf_type)

                case TypeLeafString.POINTER:
                    self._keys[leaf_id] = read_pointer(leaf, leaf_type)

                case TypeLeafString.ENUM:
                    self._keys[leaf_id] = read_enum(leaf, leaf_type)

                case TypeLeafString.UNION:
                    self._keys[leaf_id] = read_union(leaf, leaf_type)

                case TypeLeafString.BITFIELD:
                    self._keys[leaf_id] = read_bitfield(leaf, leaf_type)

                case _:
                    # Check for exhaustiveness
                    logger.error("Unhandled leaf type: %s", leaf_type)

        except AssertionError:
            logger.error("Failed to parse PDB types leaf:\n%s", leaf)

        return self._keys[leaf_id]

    def read_all(self, section: str):
        r_leafsplit = re.compile(r"\n(?=0x\w{4,8} : )")
        for leaf in r_leafsplit.split(section):
            if (match := self.INDEX_RE.match(leaf)) is None:
                continue

            leaf_id_str, leaf_type = match.groups()
            if leaf_type in self.MODES_OF_INTEREST:
                leaf_id = CvdumpTypeKey.from_str(leaf_id_str)
                self._raw[leaf_id] = (leaf, leaf_type)

                if leaf_type in self.UDT_LEAVES:
                    self._read_udt_attributes(leaf_id, leaf)

        self._udt_by_name = build_udt_name_map(self._udt_props, {})

        # The UDT values from cvdump win over the forward refs we resolve by name.
        self._forward_refs = resolve_udt_forward_refs(
            self._udt_props, self._udt_by_name
        )
        self._forward_refs.update(
            (key, udt.udt)
            for key, udt in self._udt_props.items()
            if udt.udt is not None and udt.udt != key
        )

    def _read_udt_attributes(self, leaf_id: CvdumpTypeKey, leaf: str):
        name, udt = read_udt_name(leaf)

        # Property flags (PRINT_PROP, type7.cpp) come before the name.
        # cvdump prints the `scoped` property as LOCAL.
        flags = leaf[: leaf.index(" name = ")]
        self._udt_props[leaf_id] = UdtProps(
            name=name,
            is_forward_ref="FORWARD REF," in flags,
            is_scoped="LOCAL," in flags,
            udt=CvdumpTypeKey.from_str(udt) if udt is not None else None,
        )

    def resolve_forward_refs(self) -> dict[CvdumpTypeKey, CvdumpTypeKey]:
        """Map each class, struct, union, and enum forward ref to the key of the
        definition with the same name. Forward refs with no definition are left out.
        If there is more than one definition, the last one wins.
        Same rules as PdbTypesParser, without the UDT values from cvdump."""
        names = build_udt_name_map(self._udt_props, {})
        return resolve_udt_forward_refs(self._udt_props, names)
