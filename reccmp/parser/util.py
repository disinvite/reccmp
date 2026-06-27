# C++ Parser utility functions and data structures
import re
from ast import literal_eval
from typing import NamedTuple

# The goal here is to just read whatever is on the next line, so some
# flexibility in the formatting seems OK
templateCommentRegex = re.compile(r"\s*//\s+(.*)")


def get_synthetic_name(line: str) -> str | None:
    """Synthetic names appear on a single line comment on the line after the marker.
    If that's not what we have, return None"""
    template_match = templateCommentRegex.match(line)

    if template_match is not None:
        return template_match.group(1)

    return None


template_regex = re.compile(r"<(?P<type>[\w]+)\s*(?P<asterisks>\*+)?\s*>")


class_decl_regex = re.compile(
    r"\s*(?:\/\/)?\s*(?:class|struct) ((?:\w+(?:<.+>)?(?:::)?)+)"
)


def template_replace(match: re.Match) -> str:
    type_name, asterisks = match.groups()
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


# Previously we allowed `=` or `;` to end the variable name.
# These are now distinct tokens, so we stop at the end of the CODE token.
global_regex = re.compile(
    r"""
    (?P<name>(?:\w+::)*\w+)       # Any identifier with 0-N namespace qualifiers
    (?:                           # Suffix options:
        \(\w|                     # - Open paren: call constructor
        \)\(|                     # - Close paren, open paren: function pointer variable
        \[.*|                     # - Open bracket: array with or without size
        \s*=|
        \s*;|
        \s*$                      # - End of string
    )
""",
    flags=re.X,
)


def get_variable_name(line: str) -> str | None:
    """Grab the name of the variable annotated with the GLOBAL marker."""

    if (match := global_regex.search(line)) is not None:
        return match.group("name")

    return None


class ParserCodeString(NamedTuple):
    text: str
    is_widechar: bool


def get_string_contents(line: str) -> ParserCodeString | None:
    """Return the first C string seen on this line.
    We have to unescape the string, and a simple way to do that is to use
    python's ast.literal_eval. I'm sure there are many pitfalls to doing
    it this way, but hopefully the regex will ensure reasonably sane input."""

    # Remove line continuation marks. These are not newlines.
    line = line.replace("\\\n", "")

    try:
        is_widechar = line[0] == "L"
        if is_widechar:
            text = literal_eval(line[1:])
        else:
            text = literal_eval(line)

        return ParserCodeString(text=text, is_widechar=is_widechar)
    # pylint: disable=broad-exception-caught
    # No way to predict what kind of exception could occur.
    except Exception:
        pass

    return None
