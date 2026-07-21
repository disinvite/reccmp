import bisect
import re
import string
import enum
from itertools import pairwise


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
    WHITESPACE = enum.auto()


r_newSplitter = re.compile(
    r"""
//[^\n]*|
/\*.*?\*/|
L?\"(?:[^\"\n\\]|\\.)*[\"\n]|
L?\'(?:[^'\n\\]|\\.)*['\n]|
\#\s*(\w+)(?:\\\n|[^\n])*|
[{}=;]
""",
    flags=re.X | re.DOTALL,
)

r_firstChar = re.compile(r"\S")


r_realClassStart = re.compile(r"(?:class|struct|namespace) (?P<name>\w+)[^{};=<>]+")


CodeToken = tuple[int, int, TokenType]


def tokenize_code_file(text: str) -> list[CodeToken]:
    tokens = []

    # Start of code token between delimiters.
    start = 0

    # Pull out the iterator to a variable so the
    # digit separator case can overwrite it.
    matches = r_newSplitter.finditer(text)

    while (match := next(matches, None)) is not None:
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
                # Reset the iterator to skip the single quote.
                # Do not skip delimiters inside this rejected CHAR token.
                matches = r_newSplitter.finditer(text, pos + 1)
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
            # Skip if this is entirely whitespace
            strip_match = r_firstChar.search(text, start, pos)
            if strip_match:
                tokens.append((strip_match.start(), pos, TokenType.CODE))

        tokens.append((pos, stop, token_type))
        start = stop

    if start < len(text):
        tokens.append((start, len(text), TokenType.CODE))

    return tokens


def get_newlines_from_text(text: str) -> list[int]:
    return [-1] + [m.start() for m in re.finditer(r"\n", text)]


def get_line_column_pos(newlines: list[int], offset: int) -> tuple[int, int]:
    """Calculate 1-based (line, column) position for the given absolute position.
    This is not needed for most tokens and would be expensive to do in the tokenizer.
    The `newlines` parameter is the precalculated result from get_newlines_from_text().
    """
    i = bisect.bisect_left(newlines, offset)
    if i == 0:
        return (1, 1)

    pos = newlines[i - 1]
    return (i, offset - pos)


def report_blank_lines(
    newlines: list[int], text: str, start: int, end: int
) -> list[int]:
    i = bisect.bisect_left(newlines, start)
    j = bisect.bisect_left(newlines, end)

    return [
        newlines[x] + 1  # First column of the blank line
        for x, y in pairwise(range(i, j))
        if not text[newlines[x] : newlines[y]].strip()
    ]


def get_scopes_from_tokens(
    text: str, enclosures: dict[int, int]
) -> list[tuple[int, int, str]]:
    """Using the known scope enclosures, find which ones are the start of a
    struct, class, or namespace. Return the name and range of positions where each
    named scope is active."""
    names = []

    for match in r_realClassStart.finditer(text):
        stop = match.end()
        if stop in enclosures:
            names.append((stop, enclosures[stop], match.group(1)))

    return names


def scope_tokens_only(tokens: list[CodeToken]) -> list[CodeToken]:
    return [
        x
        for x in tokens
        if x[2]
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
    """Pair up curly bracket tokens. Keep searching until we can't pair any more.
    Returns:
    [0]: List of new pairs found.
    [1]: Remaining tokens after paired tokens are removed.
    If enable_ppc is True, brackets can only be paired if they are both inside the same PPC branch.
    If it is false, we ignore PPC tokens entirely and assume all branches are enabled,
    even if this makes no sense. We do not examine or evaluate the PPC expressions at all.
    """
    ranges = []
    stack: list[CodeToken] = []
    output: list[CodeToken] = []
    for x in tokens:
        if x[2] == TokenType.CURLY_CLOSE:
            if stack:
                y = stack.pop()
                ranges.append((y[0], x[0]))
            else:
                output.append(x)
        elif x[2] == TokenType.CURLY_OPEN:
            stack.append(x)
        elif enable_ppc and x[2] in {
            TokenType.PPC_IF,
            TokenType.PPC_ELSE,
            TokenType.PPC_END,
        }:
            output.extend(stack)
            output.append(x)
            stack.clear()

    output.extend(stack)
    return (ranges, output)


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
    # Each leg records its curly brackets as (offset, token) so we can compare
    # branches by their bracket *sequence*, not just how many brackets they have.
    legs: list[list[tuple[int, TokenType]]] = [[]]

    for start, _, token in remain:
        # Build a list of all tokens that will be affected in this PPC block.
        mask.add(start)

        if token in (TokenType.CURLY_OPEN, TokenType.CURLY_CLOSE):
            legs[-1].append((start, token))

        elif token == TokenType.PPC_IF:
            # New block begins here. If one was already started,
            # it can no longer be condensed on this pass.
            interrupted = False
            mask = {start}
            legs = [[]]

        elif token == TokenType.PPC_ELSE:
            # New branch begins here
            legs.append([])

        elif token == TokenType.PPC_END:
            # `not interrupted`: branches are all at the same PPC level
            # `len(legs) > 1`: there is more than one option
            # signature match: every branch has the same bracket sequence
            # (same count AND same open/close direction). Folding one branch in
            # for another is only valid if they are structurally identical.
            # Rejects nonsense like `#if { #else } #endif`.
            signature = [token for _, token in legs[0]]
            if (
                not interrupted
                and len(legs) > 1
                and all([t for _, t in leg] == signature for leg in legs)
            ):
                # Retain only the curly brackets from the first branch.
                keepers = {start for start, _ in legs[0]}
                # All others in this block will be deleted.
                global_mask |= mask - keepers

            interrupted = True
            legs = [[]]
            mask.clear()

    return global_mask


def all_curly_paired(tokens: list[CodeToken]) -> bool:
    for x in tokens:
        if x[2] in {TokenType.CURLY_OPEN, TokenType.CURLY_CLOSE}:
            return False

    return True


def scope_detect_churn(
    tokens: list[CodeToken],
) -> tuple[dict[int, int], list[CodeToken]]:
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
        if all_curly_paired(new_remain):
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

    return (dict(out_ranges), remain)
