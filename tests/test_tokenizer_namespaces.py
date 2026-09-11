"""Tests for extracting the namespace/struct/class name attached to a scope."""

from textwrap import dedent
import pytest
from reccmp.parser.tokenizer import (
    tokenize_code_file,
    get_namespaces_from_scopes,
    resolve_scopes,
)


@pytest.mark.parametrize("prefix", ["struct", "class", "namespace"])
def test_namespace_prefix(prefix: str):
    """Should extract the namespace from any of the three allowed prefixes."""
    code = dedent(f"""\
        {prefix} Test {{
        int g_test;
        }}
    """)

    # The exact position varies with the prefix used.
    start_pos = code.index("{")
    end_pos = code.index("}")

    scopes, _ = resolve_scopes(tokenize_code_file(code))
    assert get_namespaces_from_scopes(code, scopes) == [(start_pos, end_pos, "Test")]


def test_class_with_base():
    """Should correctly extract the namespace name from a class with a list of base classes."""
    code = dedent("""\
        class Test : public Other {
        int m_test;
        };
    """)
    scopes, _ = resolve_scopes(tokenize_code_file(code))
    assert get_namespaces_from_scopes(code, scopes) == [(26, 40, "Test")]


def test_forward_reference():
    """Should not declare a namespace for a class or struct without curly brackets."""
    code = dedent("""\
        class Test;
        struct Other;
    """)
    scopes, _ = resolve_scopes(tokenize_code_file(code))
    assert not get_namespaces_from_scopes(code, scopes)


def test_nested_scopes():
    """Should report the list of scopes in the order they begin in the file.
    (i.e. sorted by start position.)"""
    code = dedent("""\
        namespace Test {
        struct Inner {
        int m_test;
        };
        }
    """)
    scopes, _ = resolve_scopes(tokenize_code_file(code))
    assert get_namespaces_from_scopes(code, scopes) == [
        (15, 47, "Test"),
        (30, 44, "Inner"),
    ]


def test_unmatched_brackets():
    """Should not declare a scope for an unpaired curly bracket."""
    code = dedent("""\
        class Test {
    """)
    scopes, _ = resolve_scopes(tokenize_code_file(code))
    assert not get_namespaces_from_scopes(code, scopes)


def test_ignore_control_flow():
    """Should not define a namespace for scopes that are not a class, struct, or namespace."""
    code = dedent("""\
        if (test) {
        }
        for (;;) {
        }
    """)
    scopes, _ = resolve_scopes(tokenize_code_file(code))
    assert not get_namespaces_from_scopes(code, scopes)


@pytest.mark.xfail(reason="Namespace regex is too restrictive.")
def test_no_space_before_curly():
    """Should detect the scope name next to the curly bracket."""
    code = dedent("""\
        namespace Test{
        int g_test;
        }
    """)
    scopes, _ = resolve_scopes(tokenize_code_file(code))
    assert get_namespaces_from_scopes(code, scopes) == [(14, 28, "Test")]


@pytest.mark.xfail(reason="Namespace regex does not ignore commented tokens.")
def test_keyword_in_comment():
    """Should ignore a comment that resembles a class declaration."""
    code = dedent("""\
        // Helper for class Renderer
        void test()
        {
        int g_test;
        }
    """)
    scopes, _ = resolve_scopes(tokenize_code_file(code))
    assert not get_namespaces_from_scopes(code, scopes)


@pytest.mark.xfail(reason="Namespace regex is too restrictive.")
def test_class_name_after_declspec():
    """Should ignore prefixes like `__declspec` that are allowed in a class declaration."""
    code = dedent("""\
        class __declspec(dllexport) Test {
        int m_test;
        };
    """)
    scopes, _ = resolve_scopes(tokenize_code_file(code))
    assert get_namespaces_from_scopes(code, scopes) == [(33, 47, "Test")]
