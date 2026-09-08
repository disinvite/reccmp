from itertools import pairwise
from textwrap import dedent
from typing import Iterable
import pytest
from reccmp.parser.tokenizer import (
    CodeToken,
    TokenType,
    tokenize_code_file,
    get_newlines_from_text,
    get_line_column_pos,
    get_namespaces_from_scopes,
    resolve_scopes,
)


def tokens_only(tokens: Iterable[CodeToken]) -> list[TokenType]:
    return [token for _, __, token in tokens]


def test_strings():
    """Make sure we correctly parse escaped characters."""
    assert list(tokenize_code_file('"test"')) == [(0, 6, TokenType.STRING)]
    assert list(tokenize_code_file('"\\""')) == [(0, 4, TokenType.STRING)]
    assert list(tokenize_code_file('"\\\\"')) == [(0, 4, TokenType.STRING)]
    assert list(tokenize_code_file('"\'"')) == [(0, 3, TokenType.STRING)]


def test_chars():
    """Make sure we correctly parse escaped characters.
    Note: we don't care if the char is more than 1 character."""
    assert list(tokenize_code_file("'x'")) == [(0, 3, TokenType.CHAR)]
    assert list(tokenize_code_file("'\\''")) == [(0, 4, TokenType.CHAR)]
    assert list(tokenize_code_file("'\\\\'")) == [(0, 4, TokenType.CHAR)]
    assert list(tokenize_code_file("'\"'")) == [(0, 3, TokenType.CHAR)]


@pytest.mark.xfail(reason="Edge case")
def test_raw_string():
    """Quotes and brackets inside a raw string literal do not end the token."""
    assert tokenize_code_file('R"(unmatched " and })"') == [(0, 22, TokenType.STRING)]


def test_eof():
    """Should emit unfinished tokens as CODE."""
    assert list(tokenize_code_file('"test')) == [(0, 5, TokenType.CODE)]
    assert list(tokenize_code_file("'x")) == [(0, 2, TokenType.CODE)]
    assert list(tokenize_code_file("/* test")) == [(0, 7, TokenType.CODE)]

    # This one can be finished
    assert list(tokenize_code_file("// test")) == [(0, 7, TokenType.LINE_COMMENT)]


def test_string_continuation():
    """Should end a STRING or CHAR token if we see an unescaped newline
    before the closing quote character."""
    assert list(tokenize_code_file('"xx\nyy"')) == [
        (0, 4, TokenType.STRING),
        (4, 7, TokenType.CODE),
    ]
    assert list(tokenize_code_file("'\nx'")) == [
        (0, 2, TokenType.CHAR),
        (2, 4, TokenType.CODE),
    ]
    assert list(tokenize_code_file('"xx\\\nyy"')) == [(0, 8, TokenType.STRING)]


@pytest.mark.xfail(reason="Edge case")
def test_line_comment_continuation():
    """Should allow line continuation for a line comment."""
    code = dedent("""\
        // First line\\
        Second line""")
    assert tokenize_code_file(code) == [
        (0, 26, TokenType.LINE_COMMENT),
    ]


def test_ppc_tokens_consume_other_types():
    """Should not emit curly brackets if they are part of a PPC statement."""
    assert list(tokenize_code_file("#define XYZ = (while(0) { };)")) == [
        (0, 29, TokenType.PPC_OTHER)
    ]


def test_digit_separator():
    """Should identify a digit separator and not emit a CHAR token."""
    assert tokens_only(tokenize_code_file("int x = 1'000'000")) == [
        TokenType.CODE,
        TokenType.EQUAL,
        TokenType.CODE,
    ]


def test_digit_separator_naive_skip():
    """Should not drop CODE tokens when a digit separator is detected."""
    assert tokenize_code_file("int x = 1'000; int y = 2'000;") == [
        (0, 6, TokenType.CODE),
        (6, 7, TokenType.EQUAL),
        (8, 13, TokenType.CODE),
        (13, 14, TokenType.SEMICOLON),
        (15, 21, TokenType.CODE),
        (21, 22, TokenType.EQUAL),
        (23, 28, TokenType.CODE),
        (28, 29, TokenType.SEMICOLON),
    ]


@pytest.mark.xfail(reason="Edge case")
def test_char_preceded_by_hex_letter():
    """Should identify that the `e` in `case` does not indicate a hex digit."""
    assert tokenize_code_file("case'}': break;") == [
        (0, 4, TokenType.CODE),
        (4, 7, TokenType.CHAR),
        (7, 14, TokenType.CODE),
        (14, 15, TokenType.SEMICOLON),
    ]


def test_hide_all_tokens_for_ppc():
    """Should include all tokens that are part of a PPC expression.
    The main concern is to hide curly brackets inside a #define line."""
    assert list(tokenize_code_file("#define TEST {")) == [
        (0, 14, TokenType.PPC_OTHER),
    ]


@pytest.mark.xfail(reason="Edge case")
def test_block_comment_after_directive():
    """Should consider block comments as line continuations for PPC tokens."""
    assert tokenize_code_file("#define A 1 /*\n*/ + 2") == [
        (0, 21, TokenType.PPC_OTHER),
    ]


def test_ppc_newline():
    """Tokens should have no gap, except for whitespace."""
    code = dedent("""\
        #ifndef ACT2ACTOR_H
        #define ACT2ACTOR_H

        #include "gogoanimactor.h"
        """)
    tokens = list(tokenize_code_file(code))
    for x, y in pairwise(tokens):
        x_stop = x[1]
        y_start = y[0]
        assert x_stop == y_start or (code[x_stop:y_start].strip() == "")


def test_struct_newline():
    """Tokens should have no gap, except for whitespace."""
    code = dedent("""\
        // SIZE 0x1a8
        class Act2Actor : public TestAnimActor {
        public:
            struct Location {
                MxFloat m_position[3];  // 0x00
                MxFloat m_direction[3]; // 0x0c
                const char* m_boundary; // 0x18
                MxBool m_cleared;       // 0x1c
            };
        """)
    tokens = list(tokenize_code_file(code))
    for x, y in pairwise(tokens):
        x_stop = x[1]
        y_start = y[0]
        assert x_stop == y_start or (code[x_stop:y_start].strip() == "")


def test_line_col_conversion():
    """Should accurately convert the absolute position into 1-based line and column numbers."""
    code = dedent("""\
        // Example file

        // Test
    """)
    newlines = get_newlines_from_text(code)

    assert get_line_column_pos(newlines, 0) == (1, 1)
    assert get_line_column_pos(newlines, 1) == (1, 2)
    assert get_line_column_pos(newlines, 15) == (1, 16)
    assert get_line_column_pos(newlines, 16) == (2, 1)
    assert get_line_column_pos(newlines, 17) == (3, 1)


def test_scope_detect_empty():
    """Should not detect any scopes in an empty file."""
    scopes, remain = resolve_scopes(tokenize_code_file(""))
    assert not scopes
    assert not remain


def test_scope_detect_single_pair():
    """Should detect a single scope."""
    scopes, remain = resolve_scopes(tokenize_code_file("{}"))
    assert scopes == {0: 1}
    assert not remain


def test_scope_detect_reverse_pair():
    """Should detect invalid input: curly brackets are in the wrong order.
    The discarded tokens are returned in the `remain` list."""
    scopes, remain = resolve_scopes(tokenize_code_file("}{"))
    assert not scopes
    assert remain == [(0, 1, TokenType.CURLY_CLOSE), (1, 2, TokenType.CURLY_OPEN)]


def test_scope_detect_nested():
    """Should detect nested scopes."""
    scopes, remain = resolve_scopes(tokenize_code_file("{{}}"))
    assert scopes == {0: 3, 1: 2}
    assert not remain


def test_scope_detect_siblings():
    """Should detect two scopes next to each other."""
    scopes, remain = resolve_scopes(tokenize_code_file("{}{}"))
    assert scopes == {0: 1, 2: 3}
    assert not remain


def test_scope_detect_nested_two_levels():
    """Should detect outer scope after pairing both inner scopes."""
    scopes, remain = resolve_scopes(tokenize_code_file("{{}{}}"))
    assert scopes == {0: 5, 1: 2, 3: 4}
    assert not remain


def test_scope_detect_unpaired_close():
    """Unpaired closing bracket returned in the `remain` list."""
    scopes, remain = resolve_scopes(tokenize_code_file("{}}"))
    assert scopes == {0: 1}
    assert remain == [(2, 3, TokenType.CURLY_CLOSE)]


def test_scope_detect_unpaired_open():
    """Should return unpaired opening brackets in the `remain` list."""
    scopes, remain = resolve_scopes(tokenize_code_file("{{}"))
    assert scopes == {1: 2}
    assert remain == [(0, 1, TokenType.CURLY_OPEN)]


def test_scope_detect_folding_with_invalid_ppc():
    """Should not crash if the input has invalid PPC statements."""
    code = "#endif"
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert not scopes


def test_scope_detect_inner_curly_open_outer_curly_close():
    """Simplified version a for loop that begins two different ways depending on compiler requirements.
    If we encounter a PPC block where both branches have an opening curly bracket that matches with
    a closing bracket outside the block, enable the first branch and pair up the scope.
    """
    code = dedent("""\
        {
        #ifdef COMPAT_MODE
        {
        #else
        {
        #endif
        }
        }
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    # Should use bracket from first branch of if/else
    assert scopes == {0: 40, 21: 38}


def test_scope_detect_unbalanced_ppc_branches():
    """In this example, the brackets are globally balanced,
    but the PPC block has two legs with different bracket sequences.
    We should not pair any brackets, even the outer two."""
    code = dedent("""\
        {
        #ifdef COMPAT_MODE
        {
        #else
        #endif
        }
        }
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert not scopes


def test_scope_detect_unbalanced_ppc_branches_no_inner_else():
    """In this example, the brackets are globally balanced,
    but the PPC block has two legs with different bracket sequences.
    We should not pair any brackets, even the outer two.
    Here the #else token is outside the impossible bracket
    pairing, so it is less obvious that it is wrong."""
    code = dedent("""\
        {
        #ifdef COMPAT_MODE
        #else
        {
        #endif
        }
        }
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert not scopes


def test_scope_detect_extern_c():
    """Should support unbalanced brackets in this configuration."""
    code = dedent("""\
        #ifdef TEST
        extern "C" {
        #endif
        
        #ifdef TEST
        }
        #endif
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert scopes == {23: 45}


def test_scope_detect_three_elif_branches():
    """When folding an N-way PPC branch with equal bracket sequences,
    use the brackets from the first branch to complete the scope."""
    code = dedent("""\
        {
        #if A
        {
        #elif B
        {
        #elif C
        {
        #endif
        }
        }
    """)
    scopes, remain = resolve_scopes(tokenize_code_file(code))
    assert scopes == {0: 39, 8: 37}
    assert not remain


def test_scope_detect_nested_ppc():
    """A #if block nested inside another #if block. Both brackets pair normally."""
    code = dedent("""\
        #if A
        {
        #if B
        {
        #endif
        }
        #endif
        }
    """)
    scopes, remain = resolve_scopes(tokenize_code_file(code))
    assert scopes == {6: 32, 14: 23}
    assert not remain


def test_scope_detect_same_direction_multi_bracket_legs():
    """PPC branches with multiple brackets can fold as long as the sequences are equal."""
    code = dedent("""\
        {{
        #if A
        {{
        #else
        {{
        #endif
        }}
        }}
    """)
    scopes, remain = resolve_scopes(tokenize_code_file(code))
    assert scopes == {0: 32, 1: 31, 9: 29, 10: 28}
    assert not remain


def test_scope_detect_both_branches_balanced():
    """Make sure that we can pair brackets inside of each leg of a PPC branch.
    All pairs are returned, even though the "correct" way would choose only one leg."""
    code = dedent("""\
        #if A
        {
        }
        #else
        {
        }
        #endif
    """)
    scopes, remain = resolve_scopes(tokenize_code_file(code))
    assert scopes == {6: 8, 16: 18}
    # TODO: Why return PPC tokens here?
    assert tokens_only(remain) == [
        TokenType.PPC_IF,
        TokenType.PPC_ELSE,
        TokenType.PPC_END,
    ]


def test_scope_detect_unequal_branch_counts():
    """Cannot resolve a single pair of brackets from this example.
    The brackets are unbalanced whether we ignore the PPC boundaries or not."""
    code = dedent("""\
        {
        #if A
        {
        {
        #else
        {
        #endif
        }
        }
        }
    """)
    scopes, _ = resolve_scopes(tokenize_code_file(code))
    assert not scopes


def test_scope_detect_mismatched_direction_multi_leg():
    """PPC branch legs do not have equal sequences. Do not pair any brackets.
    We also cannot pair by ignoring the PPC boundaries because the total is unbalanced.
    """
    code = dedent("""\
        {
        #if A
        {
        #elif B
        {
        #elif C
        }
        #endif
        }
    """)
    scopes, _ = resolve_scopes(tokenize_code_file(code))
    assert not scopes


def test_scope_detect_invalid_folding_1():
    """Cannot return any scopes."""
    code = dedent("""\
        {
        #ifdef TEST
        {
        #endif
        }
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert not scopes


@pytest.mark.xfail(reason="TODO: We do not delete tokens from partial PPC resolution.")
def test_scope_detect_ignore_if_0():
    """Same as `detect_invalid_folding_1`, but if we delete tokens from
    the `#if 0` leg then we could return the expected bracket pair."""
    code = dedent("""\
        {
        #ifdef 0
        {
        #endif
        }
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert scopes


def test_scope_detect_invalid_folding_2():
    """Do not return any scopes, despite the fact that we have global balance of brackets."""
    code = dedent("""\
        {
        #ifdef TEST
        {
        #else
        }
        #endif
        }
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert not scopes


def test_scope_detect_reject_impossible_naive_pairing_1():
    """Brackets are globally balanced, but we must reject the naive pairing
    because it is impossible: both legs of the PPC block would be active.
    Both legs have the same bracket sequence, so we can emit one pair,
    leaving one extra open bracket."""
    code = dedent("""\
        {
        {
        #if A
        }
        #else
        }
        #endif
    """)
    scopes, remain = resolve_scopes(tokenize_code_file(code))
    assert scopes == {2: 10}
    assert remain == [(0, 1, TokenType.CURLY_OPEN)]


def test_scope_detect_reject_impossible_naive_pairing_2():
    """Brackets are globally balanced, but we must reject the naive pairing
    because it is impossible: both legs of the PPC block would be active.
    Both legs have the same bracket sequence, so we can emit one pair,
    leaving one extra closing bracket."""
    code = dedent("""\
        #if A
        {
        #else
        {
        #endif
        }
        }
    """)
    scopes, remain = resolve_scopes(tokenize_code_file(code))
    assert scopes == {6: 23}
    assert remain == [(25, 26, TokenType.CURLY_CLOSE)]


@pytest.mark.xfail(reason="Returns nothing for this invalid input.")
def test_scope_detect_salvage_valid_pairing():
    """Should return partial bracket pairing for invalid input.
    In this case, it is the pair split by `#ifdef X`.
    If we isolate the invalid input, we can remove the `#ifdef Y` block and create a second pair.
    """
    code = dedent("""\
        {
        #ifdef X
        #endif
        }
        {
        #ifdef Y
        {
        #else
        }
        #endif
        }
    """)
    scopes, _ = resolve_scopes(tokenize_code_file(code))
    assert scopes == {0: 18}


def test_scopes_namespace():
    code = dedent("""\
        namespace Test {
        int g_test;
        }
    """)
    scopes, _ = resolve_scopes(tokenize_code_file(code))
    assert get_namespaces_from_scopes(code, scopes) == [(15, 29, "Test")]


def test_scopes_class_with_base():
    """Should correctly extract the namespace name from a class with a list of base classes."""
    code = dedent("""\
        class Test : public Other {
        int m_test;
        };
    """)
    scopes, _ = resolve_scopes(tokenize_code_file(code))
    assert get_namespaces_from_scopes(code, scopes) == [(26, 40, "Test")]


def test_scopes_forward_reference():
    """Should not declare a namespace for a class or struct without curly brackets."""
    code = dedent("""\
        class Test;
        struct Other;
    """)
    scopes, _ = resolve_scopes(tokenize_code_file(code))
    assert not get_namespaces_from_scopes(code, scopes)


def test_scopes_nested():
    """Should report the list of scopes in the order they begin in the file.
    (i.e. sorted by start position.)"""
    code = dedent("""\
        namespace Test {
        struct Inner {
        int m_test;
        };
        }
    """)
    scopes, _ = resolve_scopes(tokenize_code_file(code))
    assert get_namespaces_from_scopes(code, scopes) == [
        (15, 47, "Test"),
        (30, 44, "Inner"),
    ]


def test_scopes_unmatched_brackets():
    """Should not declare a scope for an unpaired curly bracket."""
    code = dedent("""\
        class Test {
    """)
    scopes, _ = resolve_scopes(tokenize_code_file(code))
    assert not get_namespaces_from_scopes(code, scopes)


def test_scopes_ignore_control_flow():
    """Should not define a namespace for scopes that are not a class, struct, or namespace."""
    code = dedent("""\
        if (test) {
        }
        for (;;) {
        }
    """)
    scopes, _ = resolve_scopes(tokenize_code_file(code))
    assert not get_namespaces_from_scopes(code, scopes)


@pytest.mark.xfail(reason="Namespace regex is too restrictive.")
def test_scopes_no_space_before_curly():
    """Should detect the scope name next to the curly bracket."""
    code = dedent("""\
        namespace Test{
        int g_test;
        }
    """)
    scopes, _ = resolve_scopes(tokenize_code_file(code))
    assert get_namespaces_from_scopes(code, scopes) == [(14, 28, "Test")]


@pytest.mark.xfail(reason="Namespace regex does not ignore commented tokens.")
def test_scopes_keyword_in_comment():
    """Should ignore a comment that resembles a class declaration."""
    code = dedent("""\
        // Helper for class Renderer
        void test()
        {
        int g_test;
        }
    """)
    scopes, _ = resolve_scopes(tokenize_code_file(code))
    assert not get_namespaces_from_scopes(code, scopes)


@pytest.mark.xfail(reason="Namespace regex is too restrictive.")
def test_scopes_name_after_declspec():
    """Should ignore prefixes like `__declspec` that are allowed in a class declaration."""
    code = dedent("""\
        class __declspec(dllexport) Test {
        int m_test;
        };
    """)
    scopes, _ = resolve_scopes(tokenize_code_file(code))
    assert get_namespaces_from_scopes(code, scopes) == [(33, 47, "Test")]
