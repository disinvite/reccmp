# C++ Parser utility functions and data structures
import re
from ast import literal_eval

# The goal here is to just read whatever is on the next line, so some
# flexibility in the formatting seems OK
templateCommentRegex = re.compile(r"\s*//\s+(.*)")

# To remove any comment (//) or block comment (/*) and its leading spaces
# from the end of a code line
trailingCommentRegex = re.compile(r"(\s*(?://|/\*).*)$")

# Get char contents, ignore escape characters
singleQuoteRegex = re.compile(r"('(?:[^\'\\]|\\.)')")

# Match contents of block comment on one line
blockCommentRegex = re.compile(r"(/\*.*?\*/)")

# Match contents of single comment on one line
regularCommentRegex = re.compile(r"(//.*)")

# Get string contents, ignore escape characters that might interfere
doubleQuoteRegex = re.compile(r"(\"(?:[^\"\\]|\\.)*\")")

# Detect a line that would cause us to enter a new scope
scopeDetectRegex = re.compile(r"(?:class|struct|namespace) (?P<name>\w+).*(?:{)?")


def get_synthetic_name(line: str) -> str | None:
    """Synthetic names appear on a single line comment on the line after the marker.
    If that's not what we have, return None"""
    template_match = templateCommentRegex.match(line)

    if template_match is not None:
        return template_match.group(1)

    return None


def sanitize_code_line(line: str) -> str:
    """Helper for scope manager. Removes sections from a code line
    that would cause us to incorrectly detect curly brackets.
    This is a very naive implementation and fails entirely on multi-line
    strings or comments."""

    line = singleQuoteRegex.sub("''", line)
    line = doubleQuoteRegex.sub('""', line)
    line = blockCommentRegex.sub("", line)
    line = regularCommentRegex.sub("", line)

    return line.strip()


def remove_trailing_comment(line: str) -> str:
    return trailingCommentRegex.sub("", line)


def is_blank_or_comment(line: str) -> bool:
    """Helper to read ahead after the offset comment is matched.
    There could be blank lines or other comments before the
    function signature, and we want to skip those."""
    line_strip = line.strip()
    return (
        len(line_strip) == 0
        or line_strip.startswith("//")
        or line_strip.startswith("/*")
        or line_strip.endswith("*/")
    )


template_regex = re.compile(r"<(?P<type>[\w]+)\s*(?P<asterisks>\*+)?\s*>")


class_decl_regex = re.compile(
    r"\s*(?:\/\/)?\s*(?:class|struct) ((?:\w+(?:<.+>)?(?:::)?)+)"
)


def template_replace(match: re.Match) -> str:
    (type_name, asterisks) = match.groups()
    if asterisks is None:
        return f"<{type_name}>"

    return f"<{type_name} {asterisks}>"


def fix_template_type(class_name: str) -> str:
    """For template classes, we should reformat the class name so it matches
    the output from cvdump: one space between the template type and any asterisks
    if it is a pointer type."""
    if "<" not in class_name:
        return class_name

    return template_regex.sub(template_replace, class_name)


def get_class_name(line: str) -> str | None:
    """For VTABLE markers, extract the class name from the code line or comment
    where it appears."""

    match = class_decl_regex.match(line)
    if match is not None:
        return fix_template_type(match.group(1))

    return None


global_regex = re.compile(r"(?P<name>(?:\w+::)*\w+)(?:\)\(|\[.*|\s*=.*|;)")


def get_variable_name(line: str) -> str | None:
    """Grab the name of the variable annotated with the GLOBAL marker."""

    if (match := global_regex.search(line)) is not None:
        return match.group("name")

    return None


def get_string_contents(line: str) -> str | None:
    """Return the first C string seen on this line.
    We have to unescape the string, and a simple way to do that is to use
    python's ast.literal_eval. I'm sure there are many pitfalls to doing
    it this way, but hopefully the regex will ensure reasonably sane input."""

    try:
        if (match := doubleQuoteRegex.search(line)) is not None:
            return literal_eval(match.group(1))
    # pylint: disable=broad-exception-caught
    # No way to predict what kind of exception could occur.
    except Exception:
        pass

    return None
