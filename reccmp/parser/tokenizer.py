import bisect
import re
from typing import Iterator


# TODO: L-string L-char.
r_charsOfImport = re.compile(r"(?<!\\)[\"']|[{}=;]|//|/\*|\*/|\n")


r_realClassStart = re.compile(r"(?:class|struct|namespace)\s+(\w+)\s*$")


CodeToken = tuple[range, str]


def tokenize_code_file(text: str) -> Iterator[CodeToken]:
    mode = "nothing"

    start = 0
    end = 0

    for match in r_charsOfImport.finditer(text):
        pos = match.start()
        token = match.group(0)

        if mode == "nothing" and token in {"{", "}", "=", ";"}:
            if end != pos:
                yield (range(end, pos), "CODE")
            end = pos + 1 # ?
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

        elif token == "\n" and mode == "line_comment":
            mode = "nothing"
            end = pos + 1
            yield (range(start, end), "LINE COMMENT")


def get_newlines_from_text(text: str) -> list[int]:
    return [0] + [m.start() for m in re.finditer(r"\n", text)]


def get_line_column_pos(newlines: list[int], offset: int) -> tuple[int, int]:
    # bisect etc
    i = bisect.bisect_left(newlines, offset)
    pos = newlines[i]
    return (i + 1, pos - offset)


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


def get_scopes_from_tokens(text: str, tokens: list[CodeToken]) -> list[tuple[str, range]]:
    stack = []

    scopes = []

    def get_scope_name() -> str:
        return "::".join(s for (i, s) in stack if i == -1)

    # Prepend a sentinel so we can look back safely.
    padded = [(range(0, 0), ""), *tokens]
    for i in range(1, len(padded)):
        (span, token) = padded[i]

        if token == "{":
            prev_span, prev_token = padded[i - 1]
            if prev_token == "CODE":
                excerpt = text[prev_span.start : prev_span.stop]
                match = r_realClassStart.search(excerpt)
                if match is not None:
                    scope_name = match.group(1)
                    stack.append((-1, scope_name))

            stack.append((i - 1, "{"))

        elif token == "}":
            scope_end = i - 1
            if stack:
                (scope_start, _) = stack.pop()

            if stack and stack[-1][1] != "{":
                scopes.append((get_scope_name(), range(scope_start, scope_end)))
                stack.pop()
            else:
                scopes.append(("", range(scope_start, scope_end)))

    scopes.sort(key=lambda s: s[1].start)
    return scopes
