"""Tests for the format rules of a decomp marker block.

A marker block has one or more markers in sequence. Most blocks end with a
completion token. The completion token is the code line or the comment line
that the markers refer to.

The tests for a rule that the parser does not obey now have the xfail mark.
"""

from textwrap import dedent
import pytest
from reccmp.parser.parser import DecompParser
from reccmp.parser.error import AlertCode
from reccmp.parser.marker import MarkerType


@pytest.fixture(name="parser")
def fixture_parser() -> DecompParser:
    """Give a new parser to each test."""
    return DecompParser()


def symbol_tuples(parser: DecompParser) -> list[tuple[MarkerType, str, int]]:
    """The type, module, and offset of each symbol from the parser."""
    return [(s.type, s.module, s.offset) for s in parser.iter_symbols()]


def symbol_names(parser: DecompParser) -> list[str]:
    """The name of each symbol from the parser."""
    return [s.name for s in parser.iter_symbols()]


# The completion token for each marker type.
FUNCTION_TOKEN = "void function_one() {}"
VARIABLE_TOKEN = 'char* g_variable = "hello";'
VTABLE_TOKEN = "class Test {};"
NAMEREF_TOKEN = "// Test::Function"

# The marker types that refer to a function by its name.
NAMEREF_TYPES = (MarkerType.SYNTHETIC, MarkerType.TEMPLATE, MarkerType.LIBRARY)

TOKENS = {
    MarkerType.FUNCTION: FUNCTION_TOKEN,
    MarkerType.STUB: FUNCTION_TOKEN,
    MarkerType.GLOBAL: VARIABLE_TOKEN,
    MarkerType.STRING: VARIABLE_TOKEN,
    MarkerType.VTABLE: VTABLE_TOKEN,
    MarkerType.SYNTHETIC: NAMEREF_TOKEN,
    MarkerType.TEMPLATE: NAMEREF_TOKEN,
    MarkerType.LIBRARY: NAMEREF_TOKEN,
}

# One marker type for each category.
ALL_TYPES = [
    MarkerType.FUNCTION,
    MarkerType.GLOBAL,
    MarkerType.VTABLE,
    MarkerType.SYNTHETIC,
]


####
# 1a. Single marker horizontally aligned to completion token.
####


@pytest.mark.parametrize("marker_type", ALL_TYPES)
def test_horizontal_alignment_single_marker(
    parser: DecompParser, marker_type: MarkerType
):
    """Single marker aligned to completion token. No warning."""
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234
        {TOKENS[marker_type]}
        """))
    assert not parser.alerts
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
    ]


@pytest.mark.xfail(reason="Horizontal alignment not verified.")
@pytest.mark.parametrize("marker_type", ALL_TYPES)
def test_horizontal_alignment_single_marker_warning(
    parser: DecompParser, marker_type: MarkerType
):
    """Single marker NOT aligned to completion token. Warn but accept marker."""
    parser.read(dedent(f"""\
          // {marker_type.name}: TEST 0x1234
        {TOKENS[marker_type]}
        """))
    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == AlertCode.MARKER_NOT_ALIGNED
    # Alerts point to the markers not aligned to the completion token.
    assert parser.alerts[0].line_number == 1
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
    ]


####
# 1b. Single marker horizontally aligned to completion token. Completion token is indented.
####


@pytest.mark.parametrize("marker_type", ALL_TYPES)
def test_horizontal_alignment_single_marker_indented(
    parser: DecompParser, marker_type: MarkerType
):
    """Single marker aligned to completion token. Completion token indented."""
    parser.read(dedent(f"""\
        class Test {{
          // {marker_type.name}: TEST 0x1234
          {TOKENS[marker_type]}
        }};
        """))
    assert not parser.alerts
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
    ]


@pytest.mark.xfail(reason="Horizontal alignment not verified.")
@pytest.mark.parametrize("marker_type", ALL_TYPES)
def test_horizontal_alignment_single_marker_indented_warning(
    parser: DecompParser, marker_type: MarkerType
):
    """Single marker NOT aligned to completion token. Completion token indented. Warn but accept marker."""
    parser.read(dedent(f"""\
        class Test {{
            // {marker_type.name}: TEST 0x1234
          {TOKENS[marker_type]}
        }};
        """))
    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == AlertCode.MARKER_NOT_ALIGNED
    assert parser.alerts[0].line_number == 2
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
    ]


@pytest.mark.xfail(reason="Horizontal alignment not verified.")
@pytest.mark.parametrize("marker_type", ALL_TYPES)
def test_horizontal_alignment_single_marker_indented_different_whitespace(
    parser: DecompParser, marker_type: MarkerType
):
    """Single marker NOT aligned to completion token: marker uses soft tabs,
    completion token indented with hard tabs. Warn but accept marker."""
    parser.read(dedent(f"""\
        class Test {{
         // {marker_type.name}: TEST 0x1234
        \t{TOKENS[marker_type]}
        }};
        """))
    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == AlertCode.MARKER_NOT_ALIGNED
    # Alerts point to the markers not aligned to the completion token.
    assert parser.alerts[0].line_number == 2
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
    ]


####
# 1c. Horizontal alignment of grouped markers to completion token.
####


@pytest.mark.parametrize("marker_type", ALL_TYPES)
def test_horizontal_alignment_marker_group(
    parser: DecompParser, marker_type: MarkerType
):
    """Marker group all aligned to completion token. No warnings."""
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234
        // {marker_type.name}: HELLO 0x5555
        {TOKENS[marker_type]}
        """))
    assert not parser.alerts
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
        (marker_type, "HELLO", 0x5555),
    ]


@pytest.mark.xfail(reason="Horizontal alignment not verified.")
@pytest.mark.parametrize("marker_type", ALL_TYPES)
def test_horizontal_alignment_marker_group_unequal_first(
    parser: DecompParser, marker_type: MarkerType
):
    """Marker group with first marker NOT aligned to other tokens. Warn but accept markers."""
    parser.read(dedent(f"""\
          // {marker_type.name}: TEST 0x1234
        // {marker_type.name}: HELLO 0x5555
        {TOKENS[marker_type]}
        """))
    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == AlertCode.MARKER_NOT_ALIGNED
    assert parser.alerts[0].line_number == 1
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
        (marker_type, "HELLO", 0x5555),
    ]


@pytest.mark.xfail(reason="Horizontal alignment not verified.")
@pytest.mark.parametrize("marker_type", ALL_TYPES)
def test_horizontal_alignment_marker_group_unequal_second(
    parser: DecompParser, marker_type: MarkerType
):
    """Marker group with second marker NOT aligned to other tokens. Warn but accept markers."""
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234
          // {marker_type.name}: HELLO 0x5555
        {TOKENS[marker_type]}
        """))
    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == AlertCode.MARKER_NOT_ALIGNED
    assert parser.alerts[0].line_number == 2
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
        (marker_type, "HELLO", 0x5555),
    ]


@pytest.mark.xfail(reason="Horizontal alignment not verified.")
@pytest.mark.parametrize("marker_type", ALL_TYPES)
def test_horizontal_alignment_marker_group_unequal_both(
    parser: DecompParser, marker_type: MarkerType
):
    """Marker group with completion token NOT aligned to markers. Warn but accept markers."""
    parser.read(dedent(f"""\
          // {marker_type.name}: TEST 0x1234
          // {marker_type.name}: HELLO 0x5555
        {TOKENS[marker_type]}
        """))
    assert len(parser.alerts) == 2
    assert parser.alerts[0].code == AlertCode.MARKER_NOT_ALIGNED
    assert parser.alerts[1].code == AlertCode.MARKER_NOT_ALIGNED
    assert parser.alerts[0].line_number == 1
    assert parser.alerts[1].line_number == 2
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
        (marker_type, "HELLO", 0x5555),
    ]


####
# 2. Horizontal alignment of the markers with the completion token.
####


@pytest.mark.parametrize("marker_type", ALL_TYPES)
def test_completion_token_alignment_ok(parser: DecompParser, marker_type: MarkerType):
    """The marker and the completion token have the same indentation.
    The parser gives no alert. The class shows that the indentation
    of the block itself is not important."""
    parser.read(dedent(f"""\
        class Outer {{
          // {marker_type.name}: TEST 0x1234
          {TOKENS[marker_type]}
        }};
        """))
    assert not parser.alerts
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
    ]


@pytest.mark.xfail(reason="The parser does not check the alignment now.")
@pytest.mark.parametrize("marker_type", ALL_TYPES)
def test_completion_token_alignment_bad(parser: DecompParser, marker_type: MarkerType):
    """The marker has more indentation than the completion token.
    The parser gives a warning."""
    parser.read(dedent(f"""\
          // {marker_type.name}: TEST 0x1234
        {TOKENS[marker_type]}
        """))
    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == AlertCode.MARKER_NOT_ALIGNED


####
# 3. Vertical alignment. No blank line between the grouped markers.
# 4. Vertical alignment. No blank line between the marker and the completion token.
####


@pytest.mark.parametrize("marker_type", ALL_TYPES)
def test_blank_line_between_markers(parser: DecompParser, marker_type: MarkerType):
    """A blank line between two markers of the group is not permitted.
    The parser gives a warning."""
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234

        // {marker_type.name}: HELLO 0x5555
        {TOKENS[marker_type]}
        """))
    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == AlertCode.UNEXPECTED_BLANK_LINE


@pytest.mark.parametrize("marker_type", ALL_TYPES)
def test_blank_line_before_completion_token(
    parser: DecompParser, marker_type: MarkerType
):
    """A blank line between the marker and the completion token is not permitted.
    The parser gives a warning."""
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234

        {TOKENS[marker_type]}
        """))
    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == AlertCode.UNEXPECTED_BLANK_LINE


####
# 5. The marker types of one category must agree.
# The first marker of the group sets the pattern for the group.
# A STUB marker is the exception. It can combine with a FUNCTION marker.
# The completion token then sets the pattern for the group.
# A STUB marker cannot combine with a nameref type.
####

# fmt: off
AGREEING_TYPES = [
    (MarkerType.FUNCTION,  MarkerType.FUNCTION),
    (MarkerType.FUNCTION,  MarkerType.STUB),
    (MarkerType.STUB,      MarkerType.FUNCTION),
    (MarkerType.STUB,      MarkerType.STUB),
    (MarkerType.SYNTHETIC, MarkerType.SYNTHETIC),
    (MarkerType.TEMPLATE,  MarkerType.TEMPLATE),
]

DISAGREEING_TYPES = [
    (MarkerType.FUNCTION,  MarkerType.SYNTHETIC),
    (MarkerType.FUNCTION,  MarkerType.LIBRARY),
    (MarkerType.SYNTHETIC, MarkerType.FUNCTION),
    (MarkerType.TEMPLATE,  MarkerType.SYNTHETIC),
    (MarkerType.LIBRARY,   MarkerType.TEMPLATE),
    (MarkerType.SYNTHETIC, MarkerType.STUB),
    (MarkerType.STUB,      MarkerType.LIBRARY),
]
# fmt: on


@pytest.mark.parametrize("first, second", AGREEING_TYPES)
def test_marker_types_agree(
    parser: DecompParser, first: MarkerType, second: MarkerType
):
    """The two marker types of the group agree. The parser gives no alert.
    The parser keeps the two markers."""
    nameref = first in NAMEREF_TYPES
    parser.read(dedent(f"""\
        // {first.name}: TEST 0x1234
        // {second.name}: HELLO 0x5555
        {NAMEREF_TOKEN if nameref else FUNCTION_TOKEN}
        """))
    assert not parser.alerts
    assert symbol_tuples(parser) == [
        (first, "TEST", 0x1234),
        (second, "HELLO", 0x5555),
    ]
    assert all(s.is_nameref() is nameref for s in parser.iter_symbols())


@pytest.mark.xfail(reason="The parser gives an error here, not a warning.")
@pytest.mark.parametrize("first, second", DISAGREEING_TYPES)
def test_marker_types_disagree(
    parser: DecompParser, first: MarkerType, second: MarkerType
):
    """The two marker types of the group do not agree. The parser gives a warning.
    The parser keeps the two markers. The first marker sets the pattern for
    the group: a lookup by name or a lookup by line number."""
    nameref = first in NAMEREF_TYPES
    parser.read(dedent(f"""\
        // {first.name}: TEST 0x1234
        // {second.name}: HELLO 0x5555
        {TOKENS[first]}
        """))
    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == AlertCode.VARYING_MARKER_TYPES
    assert symbol_tuples(parser) == [
        (first, "TEST", 0x1234),
        (second, "HELLO", 0x5555),
    ]
    assert all(s.is_nameref() is nameref for s in parser.iter_symbols())


####
# 6. Markers of two different categories are not permitted.
####

# fmt: off
DIFFERENT_CATEGORIES = [
    (MarkerType.FUNCTION,  MarkerType.GLOBAL),
    (MarkerType.FUNCTION,  MarkerType.VTABLE),
    (MarkerType.GLOBAL,    MarkerType.FUNCTION),
    (MarkerType.VTABLE,    MarkerType.GLOBAL),
    (MarkerType.SYNTHETIC, MarkerType.VTABLE),
]
# fmt: on


@pytest.mark.xfail(reason="The parser drops the first marker too.")
@pytest.mark.parametrize("first, second", DIFFERENT_CATEGORIES)
def test_marker_categories_disagree(
    parser: DecompParser, first: MarkerType, second: MarkerType
):
    """The two markers of the group are in different categories.
    The parser gives an error and rejects the second marker.
    The parser keeps the first marker."""
    parser.read(dedent(f"""\
        // {first.name}: TEST 0x1234
        // {second.name}: HELLO 0x5555
        {TOKENS[first]}
        """))
    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == AlertCode.INCOMPATIBLE_MARKER

    # The first marker is the only symbol from this block.
    assert symbol_tuples(parser) == [
        (first, "TEST", 0x1234),
    ]


def test_variable_and_string_combine(parser: DecompParser):
    """A GLOBAL marker and a STRING marker refer to the same code line.
    This combination is the exception to the rule and stays permitted."""
    parser.read(dedent(f"""\
        // GLOBAL: TEST 0x1234
        // STRING: HELLO 0x5555
        {VARIABLE_TOKEN}
        """))
    assert not parser.alerts
    assert symbol_tuples(parser) == [
        (MarkerType.GLOBAL, "TEST", 0x1234),
        (MarkerType.STRING, "HELLO", 0x5555),
    ]


####
# 7. The parser removes the leading and trailing spaces from a nameref value.
####

NAMEREF_COMMENTS = [
    "// Test::Function",
    "//   Test::Function",
    "// Test::Function   ",
    "//   Test::Function   ",
    "//\tTest::Function\t",
]


@pytest.mark.parametrize("marker_type", NAMEREF_TYPES)
@pytest.mark.parametrize("comment", NAMEREF_COMMENTS)
def test_nameref_value_spaces(
    parser: DecompParser, marker_type: MarkerType, comment: str
):
    """The parser removes the leading and trailing spaces from the name."""
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234
        {comment}
        """))
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
    ]
    assert symbol_names(parser) == ["Test::Function"]


####
# 8. Extra slashes at the start of the marker are permitted.
# 9. Each line of the block must have the same number of slashes.
####

SLASHES = ["//", "///", "////"]


@pytest.mark.parametrize("slashes", SLASHES)
def test_extra_slashes(parser: DecompParser, slashes: str):
    """Extra slashes at the start of a marker are permitted.
    The parser gives no alert."""
    parser.read(dedent(f"""\
        {slashes} FUNCTION: TEST 0x1234
        {slashes} STUB: HELLO 0x5555
        {FUNCTION_TOKEN}
        """))
    assert not parser.alerts
    assert symbol_tuples(parser) == [
        (MarkerType.FUNCTION, "TEST", 0x1234),
        (MarkerType.STUB, "HELLO", 0x5555),
    ]


@pytest.mark.parametrize("slashes", SLASHES)
def test_extra_slashes_nameref(parser: DecompParser, slashes: str):
    """The marker and the nameref comment have the same number of slashes.
    The parser gives no alert."""
    parser.read(dedent(f"""\
        {slashes} SYNTHETIC: TEST 0x1234
        {slashes} Test::Function
        """))
    assert not parser.alerts
    assert symbol_tuples(parser) == [
        (MarkerType.SYNTHETIC, "TEST", 0x1234),
    ]
    assert symbol_names(parser) == ["Test::Function"]


# fmt: off
SLASH_DEPTH_MISMATCH = [
    ("//",   "///"),
    ("///",  "//"),
    ("///",  "////"),
]
# fmt: on


@pytest.mark.xfail(reason="The parser does not check the slash depth now.")
@pytest.mark.parametrize("first, second", SLASH_DEPTH_MISMATCH)
def test_slash_depth_mismatch_group(parser: DecompParser, first: str, second: str):
    """The two markers of the group do not have the same number of slashes.
    The parser gives a warning."""
    parser.read(dedent(f"""\
        {first} FUNCTION: TEST 0x1234
        {second} STUB: HELLO 0x5555
        {FUNCTION_TOKEN}
        """))
    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == AlertCode.VARYING_SLASH_DEPTH


@pytest.mark.xfail(reason="The parser does not check the slash depth now.")
@pytest.mark.parametrize("first, second", SLASH_DEPTH_MISMATCH)
def test_slash_depth_mismatch_nameref(parser: DecompParser, first: str, second: str):
    """The marker and the nameref comment do not have the same number of slashes.
    The parser gives a warning."""
    parser.read(dedent(f"""\
        {first} SYNTHETIC: TEST 0x1234
        {second} Test::Function
        """))
    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == AlertCode.VARYING_SLASH_DEPTH


####
# 10. Single line markers.
####


@pytest.mark.skip(reason="The rules for a single line marker are not decided.")
@pytest.mark.parametrize("indent", ["", "  ", "    "])
def test_single_line_marker(parser: DecompParser, indent: str):
    """The LINE marker is the only single line marker now.
    A single line marker has no completion token.
    These questions are open:
    1. Can a single line marker be a member of a marker group?
    2. Must a single line marker have the indentation of the next code line?
    3. Can a single line marker come after the code on the same line?
    """
    parser.read(dedent(f"""\
        // FUNCTION: TEST 0x1234
        void function_one()
        {{
        {indent}// LINE: TEST 0x1240
            function_two();
        }}
        """))
    assert not parser.alerts
