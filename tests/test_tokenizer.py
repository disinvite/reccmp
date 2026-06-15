from itertools import pairwise
from textwrap import dedent
from typing import Iterable
from reccmp.parser.tokenizer import tokenize_code_file


def tokens_only(tokens: Iterable[CodeToken]) -> list[str]:
    return [token for _, token in tokens]


def test_strings():
    """Make sure we correctly parse escaped characters."""
    assert list(tokenize_code_file('"test"')) == [(range(0, 6), "STRING")]
    assert list(tokenize_code_file('"\\""')) == [(range(0, 4), "STRING")]
    assert list(tokenize_code_file('"\\""')) == [(range(0, 4), "STRING")]
    assert list(tokenize_code_file('"\\\\"')) == [(range(0, 4), "STRING")]
    assert list(tokenize_code_file('"\'"')) == [(range(0, 3), "STRING")]


def test_chars():
    """Make sure we correctly parse escaped characters.
    Note: we don't care if the char is more than 1 character."""
    assert list(tokenize_code_file("'x'")) == [(range(0, 3), "CHAR")]
    assert list(tokenize_code_file("'\\''")) == [(range(0, 4), "CHAR")]
    assert list(tokenize_code_file("'\\''")) == [(range(0, 4), "CHAR")]
    assert list(tokenize_code_file("'\\'")) == [(range(0, 3), "CHAR")]
    assert list(tokenize_code_file("'\"'")) == [(range(0, 3), "CHAR")]


def test_eof():
    """Should return the last token even if there is no blank line.
    For paired delimiters like strings and block comments, just finish the token."""
    assert list(tokenize_code_file('"test')) == [(range(0, 5), "STRING")]
    assert list(tokenize_code_file("'x")) == [(range(0, 2), "CHAR")]
    assert list(tokenize_code_file("// test")) == [(range(0, 7), "LINE COMMENT")]
    assert list(tokenize_code_file("/* test")) == [(range(0, 7), "BLOCK COMMENT")]


def test_string_continuation():
    # Newline not part of broken string
    assert list(tokenize_code_file('"te\nst"')) == [
        (range(0, 3), "STRING"),
        (range(3, 6), "CODE"),
        (range(6, 7), "STRING"),
    ]
    assert list(tokenize_code_file('"te\\\nst"')) == [(range(0, 8), "STRING")]


def test_digit_separator():
    """Should not try to start a new CHAR token if the single quote is between two valid digits."""
    assert tokens_only(tokenize_code_file("int x = 1'000'000")) == ["CODE", "=", "CODE"]


def test_hide_some_tokens_for_ppc():
    """The main concern is to hide curly brackets inside a #define line."""
    assert list(tokenize_code_file("#define TEST {")) == [
        (range(0, 7), "#define"),
        (range(7, 14), "CODE"),
    ]


def test_define_string_visible():
    """String tokens inside of a #define statement must be emitted."""
    assert list(tokenize_code_file('#define TEST "Hello"')) == [
        (range(0, 7), "#define"),
        (range(7, 13), "CODE"),
        (range(13, 20), "STRING"),
    ]


def test_ppc_newline():
    """Tokens should have no gap"""
    code = dedent("""\
        #ifndef ACT2ACTOR_H
        #define ACT2ACTOR_H

        #include "gogoanimactor.h"
        """)
    tokens = list(tokenize_code_file(code))
    for (x_range, x_token), (y_range, y_token) in pairwise(tokens):
        assert x_range.stop == y_range.start, x_token
        assert x_token != "CODE" or y_token != "CODE", x_range


def test_struct_newline():
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
    for (x_range, x_token), (y_range, y_token) in pairwise(tokens):
        assert x_range.stop == y_range.start, x_token
        assert x_token != "CODE" or y_token != "CODE", x_range
