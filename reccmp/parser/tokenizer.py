import bisect
import re
import string
import enum
from typing import Iterator

# TODO: L-string L-char.
r_charsOfImport = re.compile(
    r"""
\\?\n|
\#\s*[a-z]+(?=\s)|
\\?[\\\"']|
[{}=;]|
//|
/\*|
\*/
""",
    flags=re.X,
)


class TokenType(enum.IntEnum):
    CURLY_OPEN = enum.auto()
    CURLY_CLOSE = enum.auto()
    PPC_IF = enum.auto()
    PPC_ELSE = enum.auto()
    PPC_END = enum.auto()
    PPC_OTHER = enum.auto()
    SEMICOLON = enum.auto()
    EQUAL = enum.auto()
    LINE_COMMENT = enum.auto()
    BLOCK_COMMENT = enum.auto()
    STRING = enum.auto()
    CHAR = enum.auto()
    CODE = enum.auto()


r_newSplitter = re.compile(
    r"""
//[^\n]*|
/\*.*\*/|
L?\"(?:[^\"\n\\]|\\.)*[\"\n]|
L?\'(?:[^'\n\\]|\\.)*['\n]|
\#\s*(\w+)(?:\\\n|[^\n])*|
[{}=;]
""",
    flags=re.X | re.DOTALL,
)


r_realClassStart = re.compile(r"(?:class|struct|namespace)\s+(\w+)\s*$")


CodeToken = tuple[int, int, TokenType]


def tokenize_code_file(text: str) -> Iterator[CodeToken]:
    # Start of code token between delimiters.
    start = 0

    for match in r_newSplitter.finditer(text):
        pos, stop = match.span()
        first = text[pos]

        if first == "{":
            token_type = TokenType.CURLY_OPEN
        elif first == "}":
            token_type = TokenType.CURLY_CLOSE
        elif first == "=":
            token_type = TokenType.EQUAL
        elif first == ";":
            token_type = TokenType.SEMICOLON
        elif first == '"':
            token_type = TokenType.STRING
        elif first == "'":
            if pos and text[pos - 1] in string.hexdigits:
                continue

            token_type = TokenType.CHAR
        elif first == "#":
            ppc_name = match.group(1).lower()
            if ppc_name.startswith("if"):
                token_type = TokenType.PPC_IF
            elif ppc_name.startswith("el"):
                token_type = TokenType.PPC_ELSE
            elif ppc_name == "endif":
                token_type = TokenType.PPC_END
            else:
                token_type = TokenType.PPC_OTHER

        else:
            second = text[pos + 1]
            if first == "L":
                token_type = TokenType.STRING if second == '"' else TokenType.CHAR
            else:
                token_type = (
                    TokenType.LINE_COMMENT if second == "/" else TokenType.BLOCK_COMMENT
                )

        if start < pos:
            yield (start, pos, TokenType.CODE)

        yield (pos, stop, token_type)
        start = stop

    if start < len(text):
        yield (start, len(text), TokenType.CODE)


def get_newlines_from_text(text: str) -> list[int]:
    return [0] + [m.start() for m in re.finditer(r"\n", text)]


def get_line_column_pos(newlines: list[int], offset: int) -> tuple[int, int]:
    # bisect etc
    i = bisect.bisect_left(newlines, offset)
    if i == 0:
        return (1, 1)

    pos = newlines[i - 1]
    return (i, offset - pos)


def find_next_token_type(
    tokens: list[CodeToken], start: int, types: set[TokenType]
) -> int | None:
    for i in range(start, len(tokens)):
        _, __, token = tokens[i]
        if token in types:
            return i

    return None


def get_token_groups(text: str, tokens: list[CodeToken]) -> Iterator[tuple[int, ...]]:
    """Groups of whitespace or line comments.
    Returned ranges are ids of tokens."""
    ids = []

    for i, (start, stop, token) in enumerate(tokens):
        if token == TokenType.LINE_COMMENT:
            ids.append(i)
            continue

        if token == TokenType.CODE and not text[start:stop].strip():
            continue

        if ids:
            yield tuple(ids)
            ids.clear()

    if ids:
        yield tuple(ids)


def get_scopes_from_tokens(
    text: str, tokens: list[CodeToken], enclosures: list[tuple[int, int]]
) -> list[tuple[tuple[int, int], str]]:
    names = []

    for scope_start, scope_stop in enclosures:
        if scope_start > 0:
            prev_start, prev_stop, prev_token = tokens[scope_start - 1]
            if prev_token == TokenType.CODE:
                excerpt = text[prev_start:prev_stop]
                match = r_realClassStart.search(excerpt)
                if match is not None:
                    scope_name = match.group(1)
                    names.append(((scope_start, scope_stop), scope_name))

    return names


def get_scope_name(scopes: list[tuple[range, str]], pos: int) -> str:
    stack = []

    for span, name in scopes:
        if pos in span:
            stack.append(name)

        if pos > span.stop:
            break

    return "::".join(stack)


def scope_tokens_only(tokens: list[CodeToken]) -> list[CodeToken]:
    return [
        (start, stop, token)
        for (start, stop, token) in tokens
        if token
        in {
            TokenType.CURLY_OPEN,
            TokenType.CURLY_CLOSE,
            TokenType.PPC_IF,
            TokenType.PPC_ELSE,
            TokenType.PPC_END,
        }
    ]


def reduce_scopes(
    tokens: list[CodeToken],
    *,
    enable_ppc: bool,
) -> tuple[list[tuple[int, int]], list[CodeToken]]:
    ranges = []
    done: set[int] = set()
    while True:
        stack: list[int] = []
        did_something = False
        for start, _, token in tokens:
            if start in done:
                continue

            if token == TokenType.CURLY_CLOSE:
                if stack:
                    last_start = stack.pop()
                    ranges.append((last_start, start))
                    done.add(start)
                    done.add(last_start)
                    did_something = True
            elif token == TokenType.CURLY_OPEN:
                stack.append(start)
            elif enable_ppc and token in {
                TokenType.PPC_IF,
                TokenType.PPC_ELSE,
                TokenType.PPC_END,
            }:
                stack.clear()

        if not did_something:
            break

    return (
        ranges,
        [(start, stop, token) for start, stop, token in tokens if start not in done],
    )


def reduced_tagger(remain: list[CodeToken]) -> set[int]:
    """Group leftover ppc and curly brackets into groups.
    If there is an uninterrupted group where all legs have the same curly offset
    use any subgroup and discard the rest.

    Sample debug output: mxdsobject.cpp
    REMAINING:
      179,     1,  i:  357   pos: 3497 : {       (0, 0)
      184,     1,  i:  365   pos: 3558 : #ifdef       (1, -1)
      186,    40,  i:  377   pos: 3630 : {       (1, 0)
      187,     1,  i:  379   pos: 3632 : #else       (1, -1)
      188,    49,  i:  389   pos: 3686 : {       (1, 1)
      189,     1,  i:  391   pos: 3688 : #endif       (1, -1)
      199,     2,  i:  428   pos: 4004 : }       (0, 0)
      206,     1,  i:  440   pos: 4073 : }       (0, 0)
    """
    interrupted = False
    global_mask = set()
    mask = set()
    legs: list[list[int]] = []

    for start, _, token in remain:
        mask.add(start)

        if token in (TokenType.CURLY_OPEN, TokenType.CURLY_CLOSE):
            if legs:
                legs[-1].append(start)

        elif token == TokenType.PPC_IF:
            interrupted = False
            mask = {start}
            legs = [[]]

        elif token == TokenType.PPC_ELSE:
            legs.append([])

        elif token == TokenType.PPC_END:
            # Do it before popping so we tag with the current group.
            if not interrupted and all(len(leg) == len(legs[0]) for leg in legs):
                keepers = set(legs[0])
                global_mask |= mask - keepers

            interrupted = True
            legs.clear()
            mask.clear()

    return global_mask


def scope_detect_churn(
    tokens: list[CodeToken],
) -> tuple[list[tuple[int, int]], list[CodeToken]]:
    remain = scope_tokens_only(tokens)

    out_ranges = []

    reduced_this_step = False
    for _ in range(10):
        # Trivial match of curly brackets that are next to each other.
        new_ranges, new_remain = reduce_scopes(remain, enable_ppc=True)
        if new_ranges:
            out_ranges.extend(new_ranges)
            remain = new_remain  # ?
            reduced_this_step = True

        # End early if there are no PPC tokens left.
        if not new_remain:
            break

        # Can we simply enable all PPC regions and match remaining brackets?
        new_ranges, new_remain = reduce_scopes(remain, enable_ppc=False)
        # If there is nothing left, this was successful.
        # Otherwise, do not update the lists with partial matches.
        if not new_remain:
            out_ranges.extend(new_ranges)
            remain = new_remain
            break

        mask = reduced_tagger(remain)
        if mask:
            remain = [
                (start, stop, token)
                for start, stop, token in remain
                if start not in mask
            ]
            reduced_this_step = True

        if not reduced_this_step:
            break

    return (sorted(out_ranges, key=lambda r: r[0]), remain)
