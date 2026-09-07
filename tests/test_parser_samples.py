from textwrap import dedent
import pytest
from reccmp.parser import DecompParser
from reccmp.parser.node import ParserSymbol


def code_blocks_are_sorted(blocks: list[ParserSymbol]) -> bool:
    """Helper to make this more idiomatic"""
    just_offsets = [block.offset for block in blocks]
    return just_offsets == sorted(just_offsets)


@pytest.fixture(name="parser")
def fixture_parser():
    return DecompParser()


# Tests are below #


def test_sanity(parser):
    """Read a very basic file"""
    parser.read(dedent("""\
        // FUNCTION: TEST 0x1234
        void function01()
        {
          // TODO
        }

        // FUNCTION: TEST 0x2345
        void function02()
        {
          // TODO
        }

        // FUNCTION: TEST 0x3456
        void function03()
        {
          // TODO
        }
    """))

    assert len(parser.functions) == 3
    assert code_blocks_are_sorted(parser.functions) is True
    # n.b. The parser returns line numbers as 1-based
    # Function begins on the first code line
    assert parser.functions[0].line_number == 2
    assert parser.functions[0].end_line == 5


def test_oneline(parser):
    """(Assuming clang-format permits this) This sample has a function
    on a single line. This will test the end-of-function detection"""
    parser.read(dedent("""\
        // FUNCTION: TEST 0x1234
        void short_function() { static char* msg = "oneliner"; }

        // FUNCTION: TEST 0x5555
        void function_after_one_liner()
        {
          // This function comes after the previous that is on a single line.
          // Do we report the offset for this one correctly?
        }
    """))

    assert len(parser.functions) == 2
    assert parser.functions[0].line_number == 2
    assert parser.functions[0].end_line == 2


def test_missing_offset(parser):
    """What if the function doesn't have an offset comment?"""
    parser.read(dedent("""\
        #include <stdio.h>

        int no_offset_comment()
        {
          static int dummy = 123;
          return -1;
        }

        // FUNCTION: TEST 0xdeadbeef
        void regular_ole_function()
        {
          printf("hi there");
        }
    """))

    # TODO: For now, the function without the offset will just be ignored.
    # Would be the same outcome if the comment was present but mangled and
    # we failed to match it. We should detect these cases in the future.
    assert len(parser.functions) == 1


def test_jumbled_case(parser):
    """The parser just reports what it sees. It is the responsibility of
    the downstream tools to do something about a jumbled file.
    Just verify that we are reading it correctly."""
    parser.read(dedent("""\
        // FUNCTION: TEST 0x1001
        void function_order01()
        {
            // TODO
        }

        // FUNCTION: TEST 0x1003
        void function_order03()
        {
            // TODO
        }

        // FUNCTION: TEST 0x1002
        void function_order02()
        {
            // TODO
        }
    """))

    assert len(parser.functions) == 3
    assert code_blocks_are_sorted(parser.functions) is False


def test_bad_file(parser):
    parser.read(dedent("""\
        // FUNCTION: TEST 0x1234
        void curly_with_spaces()
          {
          static char* msg = "hello";
          }

        // FUNCTION: TEST 0x5555
        void weird_closing_curly()
        {
          int x = 123; }

        // FUNCTION: HELLO 0x5656
        void bad_indenting() {
          if (0)
        {
          int y = 5;
        }}
    """))

    assert len(parser.functions) == 3


def test_indented(parser):
    """Offsets for functions inside of a class will probably be indented."""
    parser.read(dedent("""\
        // VTABLE: TEST 0x1001002
        class TestClass {
        public:
          TestClass();
          virtual ~TestClass() override;

          virtual MxResult Tickle() override; // vtable+08

          // FUNCTION: TEST 0x12345678
          inline const char* ClassName() const // vtable+0c
          {
            // 0xabcd1234
            return "TestClass";
          }

          // FUNCTION: TEST 0xdeadbeef
          inline MxBool IsA(const char* name) const override // vtable+10
          {
            return !strcmp(name, TestClass::ClassName());
          }

        private:
          int m_hello;
          int m_hiThere;
        };
    """))

    assert len(parser.functions) == 2
    assert parser.functions[0].offset == int("0x12345678", 16)
    assert parser.functions[0].line_number == 10
    assert parser.functions[0].end_line == 14

    assert parser.functions[1].offset == int("0xdeadbeef", 16)
    assert parser.functions[1].line_number == 17
    assert parser.functions[1].end_line == 20


def test_inline(parser):
    parser.read(dedent("""\
        // FUNCTION: TEST 0x10000001
        inline const char* OneLineWithComment() const { return "MxDSObject"; }; // hi there

        // FUNCTION: TEST 0x10000002
        inline const char* OneLine() const { return "MxDSObject"; };
    """))

    assert len(parser.functions) == 2
    for fun in parser.functions:
        assert fun.line_number is not None
        assert fun.line_number == fun.end_line


def test_multiple_offsets(parser):
    """If multiple offset marks appear before for a code block, take them
    all but ensure module name (case-insensitive) is distinct.
    Use first module occurrence in case of duplicates."""
    parser.read(dedent("""\
        // FUNCTION: TEST 0x1234
        // FUNCTION: HELLO 0x5555
        void different_modules()
        {
          // TODO
        }

        // FUNCTION: TEST 0x2345
        // FUNCTION: TEST 0x1234
        void same_module()
        {
          // TODO
        }

        // FUNCTION: TEST 0x2002
        // FUNCTION: test 0x1001
        void same_case_insensitive()
        {
          // TODO
        }
    """))

    assert len(parser.functions) == 4
    assert parser.functions[0].module == "TEST"
    assert parser.functions[0].line_number == 3

    assert parser.functions[1].module == "HELLO"
    assert parser.functions[1].line_number == 3

    # Duplicate modules are ignored
    assert parser.functions[2].line_number == 10
    assert parser.functions[2].offset == 0x2345

    assert parser.functions[3].module == "TEST"
    assert parser.functions[3].offset == 0x2002


def test_variables(parser):
    parser.read(dedent("""\
        // GLOBAL: TEST 0x1000
        const char *g_message = "test";

        // FUNCTION: TEST 0x1234
        void function01()
        {
          // GLOBAL: TEST 0x5555
          static int g_hello = 123;
        }
    """))

    assert len(parser.functions) == 1
    assert len(parser.variables) == 2
