"""C/C++ tokenizer"""

import re
import enum
import string
from typing import Iterator

__all__ = ["TokenType", "tokenize"]

r_block_comment = re.compile(r"\/\*.*?\*\/", flags=re.DOTALL)
r_line_comment = re.compile(r"\/\/.*")
r_any_comment = re.compile(r"(?:\/\*.*?\*\/)|(?:\/\/[^\n]*)")
r_string = re.compile(r"\"(?:[^\"\\]|\\.)*\"")
r_char = re.compile(r"'(?:[^\'\\]|\\.)'")
r_whitespace = re.compile(r"[\s\n]+")
r_identifier = re.compile(r"[_a-zA-Z]\w*")
r_const = re.compile(r"\d[\.\w]*")

OPERATOR_SET = frozenset("()[]{}*,:=;+><|~!#-/&.?%^\\")
WHITESPACE = frozenset(" \t\r\n")


class TokenType(enum.Enum):
    COMMENT = enum.auto()
    CHAR = enum.auto()
    STRING = enum.auto()
    IDENTIFIER = enum.auto()
    CONST = enum.auto()
    OPERATOR = enum.auto()
    #
    STUFF = enum.auto()


Rejex = (
    ("/", r_any_comment, TokenType.COMMENT),
    (OPERATOR_SET, None, TokenType.OPERATOR),
    (string.ascii_letters + "_", r_identifier, TokenType.IDENTIFIER),
    ('"', r_string, TokenType.STRING),  # Match L"" strings
    ("'", r_char, TokenType.CHAR),
    (string.digits, r_const, TokenType.CONST),
)


def tokenize(code: str) -> Iterator[tuple[TokenType, tuple[int, int], str]]:
    curpos = 0

    end_of_code = len(code)
    while curpos < end_of_code:
        if code[curpos] in WHITESPACE:
            curpos += 1
            continue

        for start_char, compiled_re, token_type in Rejex:
            if code[curpos] not in start_char:
                continue

            if compiled_re is not None:
                match = compiled_re.match(code, curpos)
                if match is None:
                    continue

                end = match.end(0)
                value = code[curpos:end]
            else:
                value = code[curpos]
                end = curpos + 1

            yield (token_type, (curpos, end), value)
            curpos = end
            break
        else:
            # no match on regex
            curpos += 1
