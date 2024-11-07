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
        TokenType.IDENTIFIER,
        TokenType.OPERATOR,
    ]


def test_line_continuation():
    """Clang ignores the line continuation character (backslash)"""
    code = "#define TestMacro(value)  \\\n  value"
    assert [value for (_, __, value) in tokenize(code)] == [
        "#",
        "define",
        "TestMacro",
        "(",
        "value",
        ")",
        "value",
    ]


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
