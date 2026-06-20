import re
from typing import NamedTuple
from enum import Enum


class MarkerCategory(Enum):
    """For the purposes of grouping multiple different DecompMarkers together,
    assign a rough "category" for the MarkerType values below.
    It's really only the function types that have to get folded down, but
    we'll do that in a structured way to permit future expansion."""

    FUNCTION = 1
    VARIABLE = 2
    STRING = 3
    VTABLE = 4
    LINE = 5
    ADDRESS = 100  # i.e. no comparison required or possible


class MarkerType(Enum):
    UNKNOWN = -100
    FUNCTION = 1
    STUB = 2
    SYNTHETIC = 3
    TEMPLATE = 4
    GLOBAL = 5
    VTABLE = 6
    STRING = 7
    LIBRARY = 8
    LINE = 9


newMarkerRegex = re.compile(
    r"//\s*(?P<type>\w+):\s*(?P<module>\w+)\s+(?P<offset>0x[a-f0-9]+) *(?P<extra>\S.+\S)?",
    flags=re.I,
)


markerExactRegex = re.compile(
    r"\s*// (?P<type>[A-Z]+): (?P<module>[A-Z0-9]+) (?P<offset>0x[a-f0-9]+)(?: (?P<extra>\S.+\S))?\n?$"
)


class DecompMarker(NamedTuple):
    pos: int
    type: MarkerType
    module: str
    offset: int
    extra: str | None = None


def new_match_marker(pos: int, groups: tuple[str, ...]) -> DecompMarker:
    marker_type, module, offset_str, extra = groups

    try:
        enum_type = MarkerType[marker_type.upper()]
    except KeyError:
        enum_type = MarkerType.UNKNOWN

    return DecompMarker(
        pos=pos,
        type=enum_type,
        # Convert to upper here. A lot of other analysis depends on this name
        # being consistent and predictable. If the name is _not_ capitalized
        # we will emit a syntax error.
        module=module.upper(),
        offset=int(offset_str, 16),
        extra=extra,
    )


def is_marker_exact(line: str) -> bool:
    return markerExactRegex.match(line) is not None
