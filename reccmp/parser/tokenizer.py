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

    start = 0
    end = 0

    for match in r_charsOfImport.finditer(text):
        pos = match.start()
        token = match.group(0)

        # Suppress typical breaks if we are in a #define expression (except strings)
        if mode == "nothing" and token in {"{", "}", "=", ";"} and not ppc_mode:
            if end != pos:
                yield (range(end, pos), "CODE")
            end = pos + 1  # ?
            yield (range(pos, pos + 1), token)
            continue

        # yield (range(start, end), mode) ?

        if token == '"':
            if mode == "string":
                mode = "nothing"
                end = pos + 1
                yield (range(start, end), "STRING")

            elif mode == "nothing":
                mode = "string"
                start = pos
                if end != pos:
                    yield (range(end, pos), "CODE")

        elif token == "'":
            if mode == "char":
                mode = "nothing"
                end = pos + 1
                yield (range(start, end), "CHAR")

            elif mode == "nothing":
                # digit separator
                if pos > 0 and text[pos - 1] in string.hexdigits:
                    continue

                mode = "char"
                start = pos
                if end != pos:
                    yield (range(end, pos), "CODE")

        elif token == "//" and mode == "nothing":
            mode = "line_comment"
            start = pos
            if end != pos:
                yield (range(end, pos), "CODE")

        elif token == "/*" and mode == "nothing":
            mode = "block_comment"
            start = pos
            if end != pos:
                yield (range(end, pos), "CODE")

        elif token == "*/" and mode == "block_comment":
            mode = "nothing"
            end = pos + 2
            yield (range(start, end), "BLOCK COMMENT")

        elif token in ("\\\n", "\n"):
            # TODO: comment disrupting continuation char
            if token == "\n":
                ppc_mode = False

            if mode == "line_comment":
                mode = "nothing"
                end = pos + 1
                yield (range(start, end), "LINE COMMENT")

        elif token and token[0] == "#":
            if mode == "nothing":
                ppc_mode = True
                start = pos
                if end != pos:
                    yield (range(end, pos), "CODE")

                end = pos + len(token)
                yield (range(start, end), token)


def get_newlines_from_text(text: str) -> list[int]:
    return [0] + [m.start() for m in re.finditer(r"\n", text)]


def get_line_column_pos(newlines: list[int], offset: int) -> tuple[int, int]:
    # bisect etc
    i = bisect.bisect_left(newlines, offset)
    if i == 0:
        return (1, 1)

    pos = newlines[i - 1]
    return (i, offset - pos)


def get_token_groups(text: str, tokens: list[CodeToken]) -> Iterator[range]:
    """Groups of whitespace or line comments.
    Returned ranges are spans of token list index."""
    start = None

    for i, (span, token) in enumerate(tokens):
        if token == "LINE COMMENT" or (token == "CODE" and not token.strip()):
            if start is None:
                start = i
        elif start is not None:
            yield range(start, i)
            start = None

    if start is not None:
        yield range(start, i)


r_indent_detector = re.compile(
    r"""
([\ \t]*) # Count spaces and tabs leading each line.
([^\n]*)  # Read the remainder of the line.
(?:\n|\Z) # Stop.
""",
    flags=re.X,
)


def get_curly_tab_stops(
    text: str, tokens: list[CodeToken]
) -> Iterator[tuple[int, str, int]]:
    newlines = get_newlines_from_text(text)

    tab_stops_per_line = {
        i: len(match.group(1))
        for i, match in enumerate(r_indent_detector.finditer(text), start=1)
    }

    for i, (span, token) in enumerate(tokens):
        if token in ("{", "}"):
            row, col = get_line_column_pos(newlines, span.start)
            # Token index, tab stops
            yield (i, token, tab_stops_per_line[row])


def get_enclosures(text: str, tokens: list[CodeToken]) -> list[range]:
    stack = []
    enclosures = []

    # TODO: redundant
    newlines = get_newlines_from_text(text)

    for index, token, tabstop in get_curly_tab_stops(text, tokens):
        # TODO: debug
        print(
            [
                (get_line_column_pos(newlines, tokens[x][0].start), level)
                for x, level in stack
            ]
        )
        if token == "{":

            if stack and tabstop < stack[-1][1]:
                stack.clear()

            stack.append((index, tabstop))
        elif token == "}" and stack:
            last_index, last_stop = stack[-1]
            if last_stop == tabstop:
                stack.pop()
                enclosures.append(range(last_index, index))

                # Remove duplicated brackets from ifdef.
                # while stack and stack[-1][1] == tabstop:
                #    stack.pop()

    if stack:
        enclosures.append(range(last_index, index))

    return sorted(enclosures, key=lambda r: r.start)


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
