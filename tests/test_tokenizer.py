from textwrap import dedent
from typing import Iterable
import pytest
from reccmp.isledecomp.parser.tokenizer import tokenize, TokenType

pytestmark = pytest.mark.xfail(reason="WIP")


def token_types(tokens: Iterable[tuple]) -> list[TokenType]:
    """Helper to unwrap token type"""
    return [token_type for (token_type, _, __) in tokens]


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
    assert token_types(tokenize('"t\nest"')) == [
        TokenType.OPERATOR,  # "te
        TokenType.IDENTIFIER,  # st
        TokenType.OPERATOR,  # "
    ]


def test_consts():
    assert token_types(tokenize("123")) == [TokenType.CONST]
    assert token_types(tokenize("1.0")) == [TokenType.CONST]
    assert token_types(tokenize("1.0f")) == [TokenType.CONST]
    assert token_types(tokenize(".01")) == [TokenType.CONST]
    assert token_types(tokenize("0x1234")) == [TokenType.CONST]
    assert token_types(tokenize("0o777")) == [TokenType.CONST]


def test_unicode_identifier():
    """Example from MSVC site using Japanese characters
    https://learn.microsoft.com/en-us/cpp/cpp/identifiers-cpp?view=msvc-170"""

    tokens = list(tokenize("テスト \\u30D1\\u30F3;"))
    assert token_types(tokens) == [
        TokenType.IDENTIFIER,
        TokenType.IDENTIFIER,  # Both escaped unicode chars
        TokenType.OPERATOR,
    ]


def test_line_continuation():
    """Line continuation character (backslash) does not get its own token.
    Clang combines the lines (as the compiler would want) and newlines
    that follow start after that line number. We may or may not choose
    to emulate that behavior because it's not intuitive to fix syntax
    errors with your annotations."""
    code = "#define TestMacro(value)  \\\n  value"
    tokens = list(tokenize(code))

    # Assert continuation is not its own token
    assert [value for (_, __, value) in tokens] == [
        "#",
        "define",
        "TestMacro",
        "(",
        "value",
        ")",
        "value",
    ]

    # Assert all tokens on first line
    assert all(line_no == 1 for (_, (line_no, __), ___) in tokens)


def test_block_comment_line_number():
    """Line number must be accurate for block comment that spans multiple lines"""
    code = dedent(
        """/* this is a
        big
        comment */
        return;"""
    )

    tokens = list(tokenize(code))
    # Assert correct line and column
    assert [pos for (_, pos, ___) in tokens] == [(1, 1), (4, 1), (4, 7)]


def test_non_naive_operator_split():
    """Need to break on the full operator, not just a single character"""
    assert token_types(tokenize("a->m_test")) == [
        TokenType.IDENTIFIER,
        TokenType.OPERATOR,
        TokenType.IDENTIFIER,
    ]

    assert token_types(tokenize("x!=3")) == [
        TokenType.IDENTIFIER,
        TokenType.OPERATOR,
        TokenType.CONST,
    ]

    assert token_types(tokenize("x&&y")) == [
        TokenType.IDENTIFIER,
        TokenType.OPERATOR,
        TokenType.IDENTIFIER,
    ]
