from textwrap import dedent
from typing import Iterable
import pytest
from reccmp.isledecomp.parser.tokenizer import tokenize, TokenType


def token_types(tokens: Iterable[tuple]) -> list[TokenType]:
    """Helper to unwrap token type"""
    return [token_type for (token_type, _, __) in tokens]


def token_values(tokens: Iterable[tuple]) -> list[str]:
    """Helper to unwrap token value"""
    return [value for (_, __, value) in tokens]


def test_string():
    assert token_types(tokenize('"test"')) == [TokenType.STRING]
    assert token_types(tokenize('"te\\"st"')) == [TokenType.STRING]
    assert token_types(tokenize('"te","st"')) == [
        TokenType.STRING,
        TokenType.OPERATOR,
        TokenType.STRING,
    ]

    assert token_types(tokenize('L"widechar"')) == [TokenType.STRING]


def test_busted_string():
    """Not legal to have a newline inside a C string without a line continuation mark.
    Clang gives you this when that happens. We may or may not want this for our tokens.
    """
    # assert len([*tokenize('"te\\\nst"')]) == 1

    assert token_values(tokenize('"te\nst"')) == [
        '"te',
        "\n",
        "st",
        '"',
    ]


def test_consts():
    assert token_types(tokenize("123")) == [TokenType.CONST]
    assert token_types(tokenize("1.0")) == [TokenType.CONST]
    assert token_types(tokenize("1.0f")) == [TokenType.CONST]
    assert token_types(tokenize(".01")) == [TokenType.CONST]
    assert token_types(tokenize("0x1234")) == [TokenType.CONST]
    assert token_types(tokenize("0o777")) == [TokenType.CONST]
    # Clang is very flexible here
    assert token_types(tokenize("1.0.5")) == [TokenType.CONST]
    # Cannot be an identifier if it starts with a number, so anything goes
    assert token_types(tokenize("0whatever")) == [TokenType.CONST]

    # Careful with dots at the start
    assert token_types(tokenize(".m_info")) != [TokenType.CONST]

    assert token_values(tokenize("thing0.m_info")) == ["thing0", ".", "m_info"]


@pytest.mark.xfail(reason="stretch goal")
def test_unicode_identifier():
    """Example from MSVC site using Japanese characters
    https://learn.microsoft.com/en-us/cpp/cpp/identifiers-cpp?view=msvc-170"""

    tokens = list(tokenize("テスト \\u30D1\\u30F3;"))
    assert token_types(tokens) == [
        TokenType.IDENTIFIER,
        TokenType.IDENTIFIER,  # Both escaped unicode chars
        TokenType.OPERATOR,
    ]


def test_block_comment_line_number():
    """Line number must be accurate for block comment that spans multiple lines"""
    code = dedent(
        """\
        /* this is a
        big
        comment */
        return;"""
    )

    tokens = list(tokenize(code))
    # Assert correct line and position
    assert [pos for (_, pos, ___) in tokens] == [(1, 0), (3, 27), (4, 28), (4, 34)]


def test_non_naive_operator_split():
    """Need to break on the full operator, not just a single character"""
    assert token_values(tokenize("a->m_test")) == ["a", "->", "m_test"]

    assert token_values(tokenize("x!=3")) == ["x", "!=", "3"]

    assert token_values(tokenize("x&&y")) == ["x", "&&", "y"]

    # Double colon as one token
    assert token_values(tokenize("MyClass::Test")) == ["MyClass", "::", "Test"]


def test_tilde():
    """~ is unary NOT, but is also used in destructor names"""
    assert token_values(tokenize("~a")) == ["~", "a"]
    assert token_values(tokenize("MyClass::~MyClass")) == [
        "MyClass",
        "::",
        "~",
        "MyClass",
    ]
