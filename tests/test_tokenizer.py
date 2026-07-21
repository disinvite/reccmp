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
    scope_detect_churn,
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


def test_eof():
    """Unfinished tokens are emitted as CODE."""
    assert list(tokenize_code_file('"test')) == [(0, 5, TokenType.CODE)]
    assert list(tokenize_code_file("'x")) == [(0, 2, TokenType.CODE)]
    assert list(tokenize_code_file("/* test")) == [(0, 7, TokenType.CODE)]

    # This one can be finished
    assert list(tokenize_code_file("// test")) == [(0, 7, TokenType.LINE_COMMENT)]


def test_string_continuation():
    # Newline is part of broken string.
    # A second string token is not started.
    assert list(tokenize_code_file('"xx\nyy"')) == [
        (0, 4, TokenType.STRING),
        (4, 7, TokenType.CODE),
    ]
    assert list(tokenize_code_file("'\nx'")) == [
        (0, 2, TokenType.CHAR),
        (2, 4, TokenType.CODE),
    ]
    assert list(tokenize_code_file('"xx\\\nyy"')) == [(0, 8, TokenType.STRING)]


def test_ppc_tokens_consume_other_types():
    """Should not emit curly brackets if they are part of a PPC statement."""
    assert list(tokenize_code_file("#define XYZ = (while(0) { };)")) == [
        (0, 29, TokenType.PPC_OTHER)
    ]


def test_digit_separator():
    """Should not try to start a new CHAR token if the single quote is between two valid digits."""
    assert tokens_only(tokenize_code_file("int x = 1'000'000")) == [
        TokenType.CODE,
        TokenType.EQUAL,
        TokenType.CODE,
    ]


def test_digit_separator_naive_skip():
    """When disqualifying a CHAR token, do not skip delimiters it contains."""
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


def test_hide_all_tokens_for_ppc():
    """The main concern is to hide curly brackets inside a #define line."""
    assert list(tokenize_code_file("#define TEST {")) == [
        (0, 14, TokenType.PPC_OTHER),
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
        class Act2Actor : public LegoAnimActor {
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
    """Base case: no tokens to parse, no scopes returned."""
    scopes, remain = scope_detect_churn(tokenize_code_file(""))
    assert not scopes
    assert not remain


def test_scope_detect_single_pair():
    """Return a single scope."""
    scopes, remain = scope_detect_churn(tokenize_code_file("{}"))
    assert scopes == {0: 1}
    assert not remain


def test_scope_detect_reverse_pair():
    """Invalid input. Discarded tokens are returned in the `remain` list."""
    scopes, remain = scope_detect_churn(tokenize_code_file("}{"))
    assert not scopes
    assert remain == [(0, 1, TokenType.CURLY_CLOSE), (1, 2, TokenType.CURLY_OPEN)]


def test_scope_detect_nested():
    """Can returned layered scopes."""
    scopes, remain = scope_detect_churn(tokenize_code_file("{{}}"))
    assert scopes == {0: 3, 1: 2}
    assert not remain


def test_scope_detect_siblings():
    """Two adjacent pairs at the same level."""
    scopes, remain = scope_detect_churn(tokenize_code_file("{}{}"))
    assert scopes == {0: 1, 2: 3}
    assert not remain


def test_scope_detect_nested_two_levels():
    """Outer scope is paired on the second pass."""
    scopes, remain = scope_detect_churn(tokenize_code_file("{{}{}}"))
    assert scopes == {0: 5, 1: 2, 3: 4}
    assert not remain


def test_scope_detect_unpaired_close():
    """Unpaired closing bracket returned in the `remain` list."""
    scopes, remain = scope_detect_churn(tokenize_code_file("{}}"))
    assert scopes == {0: 1}
    assert remain == [(2, 3, TokenType.CURLY_CLOSE)]


def test_scope_detect_unpaired_open():
    """Unpaired opening brackets returned in the `remain` list."""
    scopes, remain = scope_detect_churn(tokenize_code_file("{{}"))
    assert scopes == {1: 2}
    assert remain == [(0, 1, TokenType.CURLY_OPEN)]


def test_scope_detect_folding_with_invalid_ppc():
    """Should not crash if the input has invalid PPC statements."""
    code = "#endif"
    tokens = tokenize_code_file(code)
    scopes, _ = scope_detect_churn(tokens)
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
    scopes, _ = scope_detect_churn(tokens)
    # Should use bracket from first branch of if/else
    assert scopes == {0: 40, 21: 38}


@pytest.mark.xfail(reason="TODO: Defeated by naive pairing with enable_ppc=False.")
def test_scope_detect_unbalanced_ppc_branches():
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
    scopes, _ = scope_detect_churn(tokens)
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
    scopes, _ = scope_detect_churn(tokens)
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
    scopes, remain = scope_detect_churn(tokenize_code_file(code))
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
    scopes, remain = scope_detect_churn(tokenize_code_file(code))
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
    scopes, remain = scope_detect_churn(tokenize_code_file(code))
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
    scopes, remain = scope_detect_churn(tokenize_code_file(code))
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
    scopes, _ = scope_detect_churn(tokenize_code_file(code))
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
    scopes, _ = scope_detect_churn(tokenize_code_file(code))
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
    scopes, _ = scope_detect_churn(tokens)
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
    scopes, _ = scope_detect_churn(tokens)
    assert scopes


@pytest.mark.xfail(reason="TODO: Defeated by naive pairing with enable_ppc=False.")
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
    scopes, _ = scope_detect_churn(tokens)
    assert not scopes
