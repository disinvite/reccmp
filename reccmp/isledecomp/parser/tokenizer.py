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
r_identifier = re.compile(r"[^\d]\w*")
r_const = re.compile(r"\d[\.\w]*")

OPERATOR_SET = frozenset("()[]{}*,:=;+><|~!#-/&.?%^")
WHITESPACE = frozenset(string.whitespace)
NEWLINES = frozenset("\r\n")


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
    (OPERATOR_SET, None, TokenType.OPERATOR),
    ('"', r_string, TokenType.STRING),  # Match L"" strings
    ("'", r_char, TokenType.CHAR),
    (string.digits, r_const, TokenType.CONST),
)


def tokenize(code: str) -> Iterator[tuple[TokenType, tuple[int, int], str]]:
    curpos = 0
    last_newline = 0
    line_no = 1

    end_of_code = len(code)
    while curpos < end_of_code:
        if code[curpos] in WHITESPACE:
            if code[curpos] in NEWLINES:
                last_newline = curpos + 1
                line_no += 1

            curpos += 1
            continue

        if code[curpos] == "/":
            if code[curpos + 1] == "/":
                end = code.index("\n", curpos + 1)
                yield (
                    TokenType.COMMENT,
                    (line_no, curpos - last_newline + 1),
                    code[curpos:end],
                )
                curpos = end
                continue

            if code[curpos + 1] == "*":
                end = (
                    code.index("*/", curpos + 1) + 2
                )  # Plus two to seek past this block.
                yield (
                    TokenType.COMMENT,
                    (line_no, curpos - last_newline + 1),
                    code[curpos:end],
                )
                # Adjust line number if this spans multiple lines.
                line_no += code[curpos:end].count("\n")
                curpos = end
                continue

        for start_char, compiled_re, token_type in Rejex:
            if code[curpos] not in start_char:
                continue

            if compiled_re is not None:
                match = compiled_re.match(code, curpos)
                if match is None:
                    continue

                end = match.end(0)
            else:
                end = curpos + 1

            yield (token_type, (line_no, curpos - last_newline + 1), code[curpos:end])
            curpos = end
            break
        else:
            # Identifiers matched by exclusion
            match = r_identifier.match(code, curpos)
            if match is None:
                curpos += 1  # skip
            else:
                end = match.end(0)
                yield (
                    TokenType.IDENTIFIER,
                    (line_no, curpos - last_newline + 1),
                    code[curpos:end],
                )
                curpos = end
