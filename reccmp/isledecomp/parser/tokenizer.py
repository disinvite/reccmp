"""C/C++ tokenizer"""

import re
import enum
from typing import Iterator

__all__ = ["TokenType", "tokenize"]

r_omni = re.compile(
    "|".join(
        [
            r"(?P<ppc>#[a-z]+)",
            r"(?P<block>\/\*.*?\*\/)",
            r"(?P<comment>\/\/[^\n]*)",
            r"(?P<string>L?\"(?:[^\n\"\\]|\\[^\n])*\")",
            r"(?P<char>L?'(?:[^\n\'\\]|\\[^\n])')",
            r"(?P<literal>(?:\d|\.\d)[\.\w]*)",
            r"(?P<separator>\:{1,2}|->|[\(\)\[\]{}\?,;\.\#])",
            r"(?P<punctuation>>{1,2}=?|<{1,2}=?|&{2}|\|{2}|[!\+\-\*/%\^&\|\=]=?|~|\+{1,2}|-{1,2}|\.{3})",
            r"(?P<identifier>[^\s\d]\w*)",
            r"(?P<continuation>\\\n+)",
            r"(?P<newline>\n+)",
            r"(?P<unknown>\S)",
        ]
    ),
    flags=re.DOTALL,
)


class TokenType(enum.Enum):
    PREPROCESSOR = enum.auto()
    BLOCK_COMMENT = enum.auto()
    LINE_COMMENT = enum.auto()
    CHAR = enum.auto()
    STRING = enum.auto()
    IDENTIFIER = enum.auto()
    CONST = enum.auto()
    OPERATOR = enum.auto()
    CONTINUATION = enum.auto()
    NEWLINE = enum.auto()
    UNKNOWN = enum.auto()


_lastgroupmap = {
    "ppc": TokenType.PREPROCESSOR,
    "block": TokenType.BLOCK_COMMENT,
    "comment": TokenType.LINE_COMMENT,
    "string": TokenType.STRING,
    "char": TokenType.CHAR,
    "literal": TokenType.CONST,
    "separator": TokenType.OPERATOR,
    "punctuation": TokenType.OPERATOR,
    "identifier": TokenType.IDENTIFIER,
    "newline": TokenType.NEWLINE,
    "continuation": TokenType.CONTINUATION,
    "unknown": TokenType.UNKNOWN,
}


def tokenize(code: str) -> Iterator[tuple[TokenType, tuple[int, int], str]]:
    line_no = 1

    for match in r_omni.finditer(code):
        (start, end) = match.span()
        which = match.lastgroup
        value = code[start:end]
        yield (
            _lastgroupmap[which],
            (line_no, start),
            value,
        )

        if which in ("block", "string", "char", "newline", "continuation"):
            line_no += value.count("\n")
