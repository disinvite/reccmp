"""Parsing LF_FIELDLIST leaves"""

import re
from dataclasses import dataclass

# LF_FIELDLIST class/struct member
LIST_RE = re.compile(
    r"list\[(?P<index>\d+)\] = LF_MEMBER, (?P<scope>\w+), type = (?P<type>[^,]*), offset = (?P<offset>\d+)\s+member name = '(?P<name>[^']*)'"
)

# LF_FIELDLIST vtable indicator
VTABLE_RE = re.compile(r"list\[(?P<index>\d+)\] = LF_VFUNCTAB")

# LF_FIELDLIST superclass indicator
SUPERCLASS_RE = re.compile(
    r"list\[(?P<index>\d+)\] = LF_BCLASS, (?P<scope>\w+), type = (?P<type>[^,]*), offset = (?P<offset>\d+)"
)

# LF_FIELDLIST virtual direct/indirect base pointer
VBCLASS_RE = re.compile(
    r"list\[(?P<index>\d+)\] = LF_(?P<indirect>I?)VBCLASS, .* base type = (?P<type>[^,]*)\n\s+virtual base ptr = [^,]+, vbpoff = (?P<vboffset>\d+), vbind = (?P<vbindex>\d+)"
)

LF_FIELDLIST_ENUMERATE = re.compile(
    r"list\[(?P<index>\d+)\] = LF_ENUMERATE,.*value = (?P<value>\d+), name = '(?P<name>[^']+)'"
)


@dataclass(frozen=True)
class FieldListItem:
    index: int


@dataclass(frozen=True)
class LfBClass(FieldListItem):
    # scope: str
    type: str
    offset: int


@dataclass(frozen=True)
class LfMember(FieldListItem):
    # scope: str
    type: str
    offset: int
    name: str


@dataclass(frozen=True)
class LfVBClass(FieldListItem):
    direct: bool
    type: str
    vboffset: int
    vbindex: int


@dataclass(frozen=True)
class LfEnumerate(FieldListItem):
    value: int
    name: str


@dataclass(frozen=True)
class LfVFuncTab(FieldListItem):
    pass


@dataclass(frozen=True)
class LfFieldlist:
    bases: list[LfBClass]
    members: list[LfMember]
    virtual_bases: list[LfVBClass]
    variants: list[LfEnumerate]
    vfunctabs: list[LfVFuncTab]


def normalize_type_id(key: str) -> str:
    # DUPE
    if key[0] == "0":
        return f"0x{key[-4:].lower()}"

    # Remove numeric value for "T_" type. We don't use this.
    return key.partition("(")[0]


def parse_fieldlist(leaf: str) -> LfFieldlist:
    bases = [
        LfBClass(
            index=int(index_str),
            type=normalize_type_id(type_str),
            offset=int(offset_str),
        )
        for (index_str, _, type_str, offset_str) in SUPERCLASS_RE.findall(leaf)
    ]

    members = [
        LfMember(
            index=int(index_str),
            type=normalize_type_id(type_str),
            offset=int(offset_str),
            name=name,
        )
        for (index_str, _, type_str, offset_str, name) in LIST_RE.findall(leaf)
    ]

    virtual_bases = [
        LfVBClass(
            index=int(index_str),
            direct=indirect_char != "I",
            type=type_str,
            vboffset=int(vboffset_str),
            vbindex=int(vbindex_str),
        )
        for (
            index_str,
            indirect_char,
            type_str,
            vboffset_str,
            vbindex_str,
        ) in VBCLASS_RE.findall(leaf)
    ]

    variants = [
        LfEnumerate(index=int(index_str), value=int(value_str), name=name)
        for (index_str, value_str, name) in LF_FIELDLIST_ENUMERATE.findall(leaf)
    ]

    vfunctabs = [
        LfVFuncTab(
            index=int(index_str),
        )
        for index_str in VTABLE_RE.findall(leaf)
    ]

    return LfFieldlist(
        bases=bases,
        members=members,
        virtual_bases=virtual_bases,
        variants=variants,
        vfunctabs=vfunctabs,
    )
