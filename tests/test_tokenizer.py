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
    assert list(tokenize_code_file('"\\""')) == [(0, 4, TokenType.STRING)]
    assert list(tokenize_code_file('"\\\\"')) == [(0, 4, TokenType.STRING)]
    assert list(tokenize_code_file('"\'"')) == [(0, 3, TokenType.STRING)]


def test_chars():
    """Make sure we correctly parse escaped characters.
    Note: we don't care if the char is more than 1 character."""
    assert list(tokenize_code_file("'x'")) == [(0, 3, TokenType.CHAR)]
    assert list(tokenize_code_file("'\\''")) == [(0, 4, TokenType.CHAR)]
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


def test_digit_separator():
    """Should not try to start a new CHAR token if the single quote is between two valid digits."""
    assert tokens_only(tokenize_code_file("int x = 1'000'000")) == [
        TokenType.CODE,
        TokenType.EQUAL,
        TokenType.CODE,
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


def test_scope_detect_folding_with_invalid_ppc():
    code = "#endif"
    tokens = tokenize_code_file(code)
    scopes, _ = scope_detect_churn(tokens)
    assert not scopes
    # Should not crash


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


@pytest.mark.xfail(reason="TODO")
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
    assert scopes


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


@pytest.mark.xfail(reason="TODO: Undecided on behavior")
def test_scope_detect_invalid_folding_1():
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
