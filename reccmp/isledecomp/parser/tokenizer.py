"""C/C++ tokenizer"""

import re
import enum
import string
from typing import Iterator

__all__ = ["TokenType", "tokenize"]

r_omni = re.compile(
    "|".join(
        [
            r"(?P<block>\/\*.*?\*\/)",
            r"(?P<comment>\/\/[^\n]*)",
            r"(?P<string>\"(?:[^\n\"\\]|\\[^\n])*\")",
            r"(?P<char>'(?:[^\n\'\\]|\\[^\n])')",
            r"(?P<newline>\n)",
            r"(?P<punctuation>::|>>=?|<<=?|->|\+{1,2}|-{1,2}|&{1,2}|\|{1,2}|[!\^\+\-\*\/%]=?|[\#\",:\.\(\)\[\]~;<>{}])",
            r"(?P<literal>\d[\.\w]*)",
            r"(?P<identifier>[^\s\d]\w*)",
        ]
    ),
    flags=re.DOTALL,
)


class TokenType(enum.Enum):
    COMMENT = enum.auto()
    CHAR = enum.auto()
    STRING = enum.auto()
    IDENTIFIER = enum.auto()
    CONST = enum.auto()
    OPERATOR = enum.auto()
    #
    STUFF = enum.auto()


def tokenize(code: str) -> Iterator[tuple[TokenType, tuple[int, int], str]]:
    lastgroupmap = {
        "block": TokenType.COMMENT,
        "comment": TokenType.COMMENT,
        "string": TokenType.STRING,
        "char": TokenType.CHAR,
        "literal": TokenType.CONST,
        "punctuation": TokenType.OPERATOR,
        "identifier": TokenType.IDENTIFIER,
    }

    last_newline = 0
    line_no = 1

    for match in r_omni.finditer(code):
        (start, end) = match.span()
        which = match.lastgroup
        if which == "newline":
            last_newline = start
            line_no += 1
        else:
            yield (
                lastgroupmap[which],
                (line_no, start - last_newline + 1),
                code[start:end],
            )

    return
