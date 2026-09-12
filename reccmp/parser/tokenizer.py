import bisect
import re
import string
import enum


class TokenType(enum.IntEnum):
    CURLY_OPEN = enum.auto()
    CURLY_CLOSE = enum.auto()
    PPC_IF = enum.auto()
    PPC_ELSE = enum.auto()
    PPC_ELIF = enum.auto()
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
[{}=;]|
//[^\n]*|
/\*.*?\*/|
L\"[^\"\n\\]*(?:\\.[^\"\n\\]*)*[\"\n]|
\"[^\"\n\\]*(?:\\.[^\"\n\\]*)*[\"\n]|
L\'[^'\n\\]*(?:\\.[^'\n\\]*)*['\n]|
\'[^'\n\\]*(?:\\.[^'\n\\]*)*['\n]|
\#\s*(\w+)(?:[^\n\\]+|\\\n|\\)*
""",
    flags=re.X | re.DOTALL,
)

r_firstChar = re.compile(r"\S")


# Keywords that begin a scope declaration. The name (if any) follows the keyword.
SCOPE_KEYWORDS = ("struct", "namespace", "class")

# The scope name is the last identifier before the end of the declaration
# or the start of a base class list.
r_scopeName = re.compile(r"(?P<name>\w+)\s*(?::(?!:).*)?$", flags=re.DOTALL)


CodeToken = tuple[int, int, TokenType]


def tokenize_code_file(text: str) -> list[CodeToken]:
    tokens = []

    # Start of code token between delimiters.
    start = 0

    # Pull out the iterator to a variable so the
    # digit separator case can overwrite it.
    matches = r_newSplitter.finditer(text)

    # The inner loop runs to exhaustion unless the digit separator case replaces
    # the iterator, which breaks out so the outer loop can pick up the new one.
    while True:
        for match in matches:
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
                    break

                token_type = TokenType.CHAR
            elif first == "#":
                ppc_name = match.group(1).lower()
                if ppc_name.startswith("if"):
                    token_type = TokenType.PPC_IF
                elif ppc_name.startswith("elif"):
                    token_type = TokenType.PPC_ELIF
                elif ppc_name == "else":
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
                        TokenType.LINE_COMMENT
                        if second == "/"
                        else TokenType.BLOCK_COMMENT
                    )

            if start < pos:
                # Skip if this is entirely whitespace
                strip_match = r_firstChar.search(text, start, pos)
                if strip_match:
                    tokens.append((strip_match.start(), pos, TokenType.CODE))

            tokens.append((pos, stop, token_type))
            start = stop
        else:
            # No more tokens
            break

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


DECLARATION_END_TOKENS = {
    TokenType.CURLY_OPEN,
    TokenType.CURLY_CLOSE,
    TokenType.SEMICOLON,
    TokenType.EQUAL,
}


def find_scope_keywords(text: str) -> list[tuple[int, int]]:
    """Positions of each `struct`, `namespace`, or `class` keyword in the text,
    sorted by start position. str.find is much faster than a regex alternation,
    which has to test every character of the file. There are few enough hits
    that we can reject the ones that are part of a longer word here."""
    hits = []

    for keyword in SCOPE_KEYWORDS:
        size = len(keyword)
        pos = text.find(keyword)
        while pos != -1:
            stop = pos + size
            # The chars on either side decide whether this is the keyword:
            # a space must separate it from the name, and it must not be the
            # tail of a longer word. (i.e. `subclass`)
            before = text[pos - 1 : pos]
            after = text[stop : stop + 1]
            if after.isspace() and not (before.isalnum() or before == "_"):
                hits.append((pos, stop))

            pos = text.find(keyword, stop)

    hits.sort()
    return hits


def get_namespaces_from_scopes(
    text: str,
    tokens: list[CodeToken],
    scopes: dict[int, int],
) -> list[tuple[int, int, str]]:
    """Using the known scope enclosures, find which ones are the start of a
    struct, class, or namespace. Return the name and range of positions where each
    named scope is active."""
    # Keyed on scope start: more than one keyword can point at the same scope.
    # (e.g. a template) The last one is the nearest to the start of the scope.
    names: dict[int, tuple[int, int, str]] = {}
    n_tokens = len(tokens)
    index = 0

    for start, keyword_stop in find_scope_keywords(text):
        # Find the token where the keyword begins. The tokens and the keywords both
        # move forward, so we never have to search from the start of the list.
        while index < n_tokens and tokens[index][1] <= start:
            index += 1

        if index == n_tokens:
            break

        if tokens[index][2] != TokenType.CODE:
            # The keyword is inside a comment, string, or preprocessor directive.
            continue

        # The declaration ends at the first curly bracket, semicolon, or equal sign.
        end = index
        while end < n_tokens and tokens[end][2] not in DECLARATION_END_TOKENS:
            end += 1

        if end == n_tokens:
            # Every keyword that follows ends here too.
            break

        # `scopes` is keyed on the position of a paired curly bracket, and no other
        # token can begin there. A forward reference (i.e. `class Test;`) and an
        # unpaired bracket both miss for the same reason: they are not a scope.
        scope_start = tokens[end][0]
        scope_stop = scopes.get(scope_start)
        if scope_stop is None:
            continue

        # Search for the name in the code token with the keyword so it cannot come
        # from a comment or macro that interrupts the declaration.
        match = r_scopeName.search(text, keyword_stop, tokens[index][1])
        if match is None:
            continue

        names[scope_start] = (scope_start, scope_stop, match.group(1))

    return list(names.values())


CURLY_TOKENS = {TokenType.CURLY_OPEN, TokenType.CURLY_CLOSE}

PPC_TOKENS = {
    TokenType.PPC_IF,
    TokenType.PPC_ELIF,
    TokenType.PPC_ELSE,
    TokenType.PPC_END,
}


SCOPE_TOKENS = CURLY_TOKENS | PPC_TOKENS


def scope_tokens_only(tokens: list[CodeToken]) -> list[CodeToken]:
    return [x for x in tokens if x[2] in SCOPE_TOKENS]


def pair_brackets(
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
        elif enable_ppc and x[2] in PPC_TOKENS:
            output.extend(stack)
            output.append(x)
            stack.clear()

    output.extend(stack)
    return (ranges, output)


def find_collapsible_ppc_branches(remain: list[CodeToken]) -> set[int]:
    """Find PPC blocks where every option (branch) introduces the same sequence of curly brackets.
    In other words, the net effect on bracket pairing is the same no matter how the preprocessor
    expressions are evaluated.

    If any blocks qualify, enable the curly brackets from the first branch (chosen arbitrarily)
    and return a list of tokens (by their start position) to remove from the list, including any
    `#if`, `#else`, or `#endif tokens that wrap the PPC blocks.

    A single pass can only mask out PPC blocks that are not interrupted by nesting.
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

        elif token in (TokenType.PPC_ELSE, TokenType.PPC_ELIF):
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
        if x[2] in CURLY_TOKENS:
            return False

    return True


def check_naive_folding(ranges: list[tuple[int, int]], tokens: list[CodeToken]) -> bool:
    """Check the new bracket pairs from pair_brackets(enable_ppc=False)
    and determine whether any of them are:
    1. Impossible: the brackets are in the same PPC block, divided by #else,
    so both of them could not be active at the same time.
    2. Conditional: one bracket is in inside a PPC block with an #else,
    the other is outside. Later processing will permit the case where ALL
    options in a PPC block have the same sequence of brackets, but they are
    rejected here.

    If any pairing has a problem, reject them all.

    We allow the case where one bracket is inside a PPC block WITHOUT
    an #else, and the other is outside the block. (`extern "C"` example)

    We also need to allow for PPC blocks with an #else where the #if and #endif
    are also part of the bracket sequence.
    (i.e. don't check only for an #else token)."""
    # Start by collecting each the boundaries of each PPC block and its legs.
    stack: list[tuple[int, list[int]]] = []
    blocks: list[list[int]] = []  # (if_pos, separators, endif_pos)
    for start, _, token in tokens:
        if token == TokenType.PPC_IF:
            stack.append((start, []))
        elif token in (TokenType.PPC_ELSE, TokenType.PPC_ELIF):
            if stack:
                stack[-1][1].append(start)
        elif token == TokenType.PPC_END:
            if stack:
                if_pos, separators = stack.pop()
                if separators:
                    blocks.append([if_pos, *separators, start])

    # Test each pairing against every PPC block with an #else/#elif.
    for open_pos, close_pos in ranges:
        # `boundaries` has the position of each #if/#else/.../#endif
        # component of the PPC block.
        for boundaries in blocks:
            # Check whether the entire PPC block is between the brackets.
            if not all(open_pos < b < close_pos for b in boundaries):
                return False

    return True


def resolve_scopes(
    tokens: list[CodeToken],
) -> tuple[dict[int, int], list[CodeToken]]:
    """Pair up curly brackets in the entire file to the best of our ability.
    Returns a map of (start -> stop) regions of the paired brackets.
    We may not be able to pair all brackets because of invalid syntax
    or preprocessor sequences that are not reducible.
    If this occurs, we also return a list of brackets and PPC tokens that we
    are unable to handle. The caller can decide how to alert the user."""
    remain = scope_tokens_only(tokens)

    out_ranges = []

    # 10 iterations chosen arbitrarily simply to avoid an unexpected infinite loop.
    for _ in range(10):
        reduced_this_step = False
        # Match any curly bracket pairs that are next to each other.
        new_ranges, new_remain = pair_brackets(remain, enable_ppc=True)
        if new_ranges:
            out_ranges.extend(new_ranges)
            remain = new_remain
            reduced_this_step = True

        # If all curly brackets have been matched, we are done.
        # There may still be PPC tokens in the list, but none can block a bracket match,
        # so they are not returned.
        if all_curly_paired(new_remain):
            remain = []
            break

        # Can we simply enable all PPC regions and match remaining brackets?
        new_ranges, new_remain = pair_brackets(remain, enable_ppc=False)
        # This is only allowed if:
        # 1. Doing this allows us to pair all remaining brackets.
        # 2. No pairing joins two regions separated by #else/#elif.
        # `new_remain` has had its PPC tokens removed, so use `remain`.
        if not new_remain and check_naive_folding(new_ranges, remain):
            out_ranges.extend(new_ranges)
            remain = new_remain
            break

        mask = find_collapsible_ppc_branches(remain)
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
