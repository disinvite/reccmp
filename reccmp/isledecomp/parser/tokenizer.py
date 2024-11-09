"""C/C++ tokenizer"""

import re
import enum
from typing import Iterator

__all__ = ["TokenType", "tokenize"]

r_omni = re.compile(
    "|".join(
        [
            r"(?P<ppc>#[a-z]+(?:\\\n|[^\n])*)",
            r"(?P<block>\/\*.*?\*\/)",
            r"(?P<comment>\/\/[^\n]*)",
            r"(?P<string>L?\"(?:[^\n\"\\]|\\[^\n])*\")",
            r"(?P<char>L?'(?:[^\n\'\\]|\\[^\n])')",
            r"(?P<separator>[\(\)\[\]{}\?,:\.\"\'\#])",
            r"(?P<punctuation>\:{2}|->|>{1,2}=?|<{1,2}=?|&{2}|\|{2}|[!\+\-\*/%\^&\|\=]=?|\+{1,2}|-{1,2}|\.{3})",
            r"(?P<literal>\d[\.\w]*)",
            r"(?P<identifier>[^\s\d]\w*)",
            r"(?P<newline>\n+)",
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
        "ppc": TokenType.STUFF,
        "block": TokenType.COMMENT,
        "comment": TokenType.COMMENT,
        "string": TokenType.STRING,
        "char": TokenType.CHAR,
        "literal": TokenType.CONST,
        "separator": TokenType.OPERATOR,
        "punctuation": TokenType.OPERATOR,
        "identifier": TokenType.IDENTIFIER,
    }

    line_no = 1

    for match in r_omni.finditer(code):
        (start, end) = match.span()
        which = match.lastgroup
        value = code[start:end]
        if which != "newline":
            yield (
                lastgroupmap[which],
                (line_no, start),
                value,
            )

        if which in ("ppc", "block", "newline"):
            line_no += value.count("\n")
