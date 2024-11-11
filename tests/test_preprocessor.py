from textwrap import dedent
from reccmp.isledecomp.parser.tokenizer import tokenize
from reccmp.isledecomp.parser.preprocessor import preprocessor, evaluate


def test_evaluate_basic():
    # identity
    assert evaluate("0") is False
    assert evaluate("1") is True

    # undefined macro evaluates to 0
    # assert evaluate("TEST") is False

    # defined but still zero
    # assert evaluate("TEST", {"TEST", 0}) is False

    # defined as any non-zero
    # assert evaluate("TEST", {"TEST", 1}) is True
    # assert evaluate("TEST", {"TEST", "Anything"}) is True


def test_one():
    code = dedent(
        """
        #ifndef XYZ
        return;
        #endif
    """
    )
    tokens = [*preprocessor(tokenize(code))]
    assert [value for (_, __, value) in tokens] == ["return", ";"]

    code = dedent(
        """
        #ifdef XYZ
        return;
        #endif
    """
    )
    tokens = [*preprocessor(tokenize(code))]
    assert len(tokens) == 0
