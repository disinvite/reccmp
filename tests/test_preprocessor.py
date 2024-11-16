from textwrap import dedent
import pytest
from reccmp.isledecomp.parser.tokenizer import tokenize
from reccmp.isledecomp.parser.preprocessor import preprocessor, evaluate


def mock_tokens(text):
    """Split string on whitespace to mock tokenizer output. Expects to find text in tuple[2]"""
    return [(None, None, chunk) for chunk in text.split(" ")]


def test_eval_identity():
    assert evaluate(mock_tokens("0")) is False
    assert evaluate(mock_tokens("1")) is True


@pytest.mark.xfail(reason="todo")
def test_eval_macro():
    # undefined macro evaluates to 0
    assert evaluate("TEST") is False

    # defined but still zero
    assert evaluate("TEST", {"TEST", 0}) is False

    # defined as any non-zero
    assert evaluate("TEST", {"TEST", 1}) is True
    assert evaluate("TEST", {"TEST", "Anything"}) is True


def test_one():
    code = dedent(
        """\
        #ifndef XYZ
        return;
        #endif
    """
    )
    tokens = [*preprocessor(tokenize(code))]
    assert "return" in [value for (_, __, value) in tokens]

    code = dedent(
        """\
        #ifdef XYZ
        return;
        #endif
    """
    )
    tokens = [*preprocessor(tokenize(code))]
    assert "return" not in [value for (_, __, value) in tokens]


def test_define_inside_if():
    """Assert that this does not raise an exception
    The bug was that we did not leave COLLECT mode after the second #define."""
    code = dedent(
        """\
        #if defined(_M_IX86) || defined(__i386__)
        #define COMPARE_POINTER_TYPE MxS32
        #else
        #define COMPARE_POINTER_TYPE MxS32*
        #endif
    """
    )
    [*preprocessor(tokenize(code))]


def test_stopped_after_ifdef():
    code = dedent(
        """\
        #ifdef _DEBUG
        void Dump(void (*pTracer)(const char*, ...)) const;
        #endif
        hello
    """
    )
    tokens = list(preprocessor(tokenize(code)))
    assert "hello" in [t[2] for t in tokens]
