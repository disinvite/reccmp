import bisect
import re
import string
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


r_realClassStart = re.compile(r"(?:class|struct|namespace)\s+(\w+)\s*$")


CodeToken = tuple[range, str]


def tokenize_code_file(text: str) -> Iterator[CodeToken]:
    mode = "nothing"
    ppc_mode = False

    # Start of code token between delimiters.
    start = 0

    for match in r_charsOfImport.finditer(text):
        pos = match.start()
        stop = match.end()  # performant?
        token = match.group(0)

        # Suppress typical breaks if we are in a #define expression (except strings)
        if mode == "nothing" and token in {"{", "}", "=", ";"} and not ppc_mode:
            if start != pos:
                yield (range(start, pos), "CODE")
                start = pos

            yield (range(pos, stop), token)
            start = stop
            continue

        if token == '"':
            if mode == "string":
                mode = "nothing"
                yield (range(start, stop), "STRING")
                start = stop

            elif mode == "nothing":
                mode = "string"
                if start != pos:
                    yield (range(start, pos), "CODE")
                    start = pos

        elif token == "'":
            if mode == "char":
                mode = "nothing"
                yield (range(start, stop), "CHAR")
                start = stop

            elif mode == "nothing":
                # digit separator
                if pos > 0 and text[pos - 1] in string.hexdigits:
                    continue

                mode = "char"
                if start != pos:
                    yield (range(start, pos), "CODE")
                    start = pos

        elif token == "//" and mode == "nothing":
            mode = "line_comment"
            if start != pos:
                yield (range(start, pos), "CODE")
                start = pos

        elif token == "/*" and mode == "nothing":
            mode = "block_comment"
            if start != pos:
                yield (range(start, pos), "CODE")
                start = pos

        elif token == "*/" and mode == "block_comment":
            mode = "nothing"
            yield (range(start, stop), "BLOCK COMMENT")
            start = stop

        elif token in ("\\\n", "\n"):
            # TODO: comment disrupting continuation char
            if token == "\n":
                ppc_mode = False
                if mode == "string":
                    mode = "nothing"
                    # newline not part of string (?)
                    yield (range(start, pos), "STRING")
                    start = pos
                elif mode == "char":
                    mode = "nothing"
                    # newline not part of char (?)
                    yield (range(start, pos), "CHAR")
                    start = pos

            if mode == "line_comment":
                mode = "nothing"
                # Newline IS part of line comment
                yield (range(start, stop), "LINE COMMENT")
                start = stop

        elif token and token[0] == "#":
            if mode == "nothing":
                ppc_mode = True
                if start != pos:
                    yield (range(start, pos), "CODE")
                    start = pos

                yield (range(pos, stop), token)
                # This is not a paired delimiter.
                # The next token starts where this one ends.
                start = stop

    # Unfinished token
    last_range = range(start, len(text))
    if mode == "line_comment":
        yield (last_range, "LINE COMMENT")
    elif mode == "block_comment":
        yield (last_range, "BLOCK COMMENT")
    elif mode == "string":
        yield (last_range, "STRING")
    elif mode == "char":
        yield (last_range, "CHAR")
    elif start < len(text) - 1:
        yield (last_range, "CODE")


def get_newlines_from_text(text: str) -> list[int]:
    return [0] + [m.start() for m in re.finditer(r"\n", text)]


def get_line_column_pos(newlines: list[int], offset: int) -> tuple[int, int]:
    # bisect etc
    i = bisect.bisect_left(newlines, offset)
    if i == 0:
        return (1, 1)

    pos = newlines[i - 1]
    return (i, offset - pos)


def get_token_groups(text: str, tokens: list[CodeToken]) -> Iterator[tuple[int, ...]]:
    """Groups of whitespace or line comments.
    Returned ranges are ids of tokens."""
    ids = []

    for i, (span, token) in enumerate(tokens):
        if token == "LINE COMMENT":
            ids.append(i)
            continue

        if token == "CODE" and not text[span.start : span.stop].strip():
            continue

        if ids:
            yield tuple(ids)
            ids.clear()

    if ids:
        yield tuple(ids)


def get_scopes_from_tokens(
    text: str, tokens: list[CodeToken], enclosures: list[range]
) -> list[tuple[range, str]]:
    names = []

    for scope_span in enclosures:
        curly_idx = scope_span.start
        if curly_idx > 0:
            prev_span, prev_token = tokens[curly_idx - 1]
            if prev_token == "CODE":
                excerpt = text[prev_span.start : prev_span.stop]
                match = r_realClassStart.search(excerpt)
                if match is not None:
                    scope_name = match.group(1)
                    names.append((scope_span, scope_name))

    return names


def get_scope_name(scopes: list[tuple[range, str]], pos: int) -> str:
    stack = []

    for span, name in scopes:
        if pos in span:
            stack.append(name)

        if pos > span.stop:
            break

    return "::".join(stack)


IndexToken = tuple[int, str]


def scope_tokens_only(tokens: list[CodeToken]) -> list[IndexToken]:
    return [
        (i, token)
        for i, (_, token) in enumerate(tokens)
        if token != "CODE"
        and (
            token in ("{", "}")
            or (token.startswith("#") and ("if" in token or "el" in token))
        )
    ]


def reduce_scopes(tokens: list[IndexToken]) -> tuple[list[range], list[IndexToken]]:
    ranges = []
    done = set()
    while True:
        stack = []
        did_something = False
        for i, token in tokens:
            if i in done:
                continue

            # print(stack, token)
            if token in ("}", "#endif"):
                crop = []
                for last_i, last_token in stack[::-1]:
                    if token == "}":
                        if last_token == "{":
                            crop = [(last_i, last_token)]
                        break

                    if token == "#endif":
                        if last_token in ("{", "}"):
                            crop = []
                            break

                        crop.append((last_i, last_token))
                        if (
                            "if" in last_token
                            and "end" not in last_token
                            and "el" not in last_token
                        ):
                            break
                else:
                    crop = []

                if crop:
                    for _ in range(len(crop)):
                        stack.pop()

                    last_i, _ = crop[-1]
                    did_something = True
                    # hack to include else
                    done.update(range(last_i, i + 1))
                    if token == "}":
                        ranges.append(range(last_i, i + 1))
                else:
                    stack.append((i, token))

            else:
                stack.append((i, token))

        if not did_something:
            break

    return (ranges, [(i, token) for i, token in tokens if i not in done])


def reduced_tagger(remain: list[IndexToken]) -> set[int]:
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
    legs = []

    for i, token in remain:
        mask.add(i)

        if token in ("{", "}"):
            if legs:
                legs[-1].append(i)

        elif "if" in token and "el" not in token and "end" not in token:
            interrupted = False
            mask = {i}
            legs = [[]]

        elif "el" in token:
            legs.append([])

        elif "endif" in token:
            # Do it before popping so we tag with the current group.
            if not interrupted and all(len(leg) == len(legs[0]) for leg in legs):
                keepers = set(legs[0])
                global_mask |= mask - keepers

            interrupted = True
            legs.clear()
            mask.clear()

    return global_mask


def enable_all_and_reduce(
    tokens: list[IndexToken],
) -> tuple[list[range], list[IndexToken]]:
    remain = [(i, token) for i, token in tokens if token in ("{", "}")]
    return reduce_scopes(remain)


def scope_detect_churn(tokens: list[CodeToken]) -> tuple[list[range], list[IndexToken]]:
    remain = scope_tokens_only(tokens)

    out_ranges = []

    reduced_this_step = False
    for _ in range(10):
        # Trivial match of curly brackets that are next to each other.
        new_ranges, new_remain = reduce_scopes(remain)
        if new_ranges:
            out_ranges.extend(new_ranges)
            remain = new_remain  # ?
            reduced_this_step = True

        # End early if there are no PPC tokens left.
        if not new_remain:
            break

        # Can we simply enable all PPC regions and match remaining brackets?
        new_ranges, new_remain = enable_all_and_reduce(remain)
        # If there is nothing left, this was successful.
        # Otherwise, do not update the lists with partial matches.
        if not new_remain:
            out_ranges.extend(new_ranges)
            remain = new_remain
            break

        mask = reduced_tagger(remain)
        if mask:
            remain = [(i, token) for i, token in remain if i not in mask]
            reduced_this_step = True

        if not reduced_this_step:
            break

    return (sorted(out_ranges, key=lambda r: r.start), remain)
