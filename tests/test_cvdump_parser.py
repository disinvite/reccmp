"""Test Cvdump parser, reading global variables"""

from reccmp.cvdump.parser import (
    CvdumpParser,
    GdataEntry,
    ModuleEntry,
)
from reccmp.cvdump.cvinfo import CVInfoTypeEnum

GLOBALS_SAMPLE = """
S_PROCREF: 0x00000000: (   5, 000000D4) WinMain
S_LPROCREF: 0x00000000: (  21, 0000008C) write_char
S_GDATA32: [0003:00018F84], Type:      T_UINT4(0075), _winver
S_UDT:   T_32PRCHAR(0470), va_list
S_LDATA32: [0003:00018FCC], Type:       T_INT4(0074), fSystemSet
"""


def test_globals():
    """Ensure that CvdumpParser tracks symbols for global and link-local
    variables, while ignoring other symbol types found in the GLOBAL section"""
    parser = CvdumpParser()
    parser.read_section("GLOBALS", GLOBALS_SAMPLE)
    assert len(parser.globals) == 2

    assert parser.globals[0] == GdataEntry(
        section=0x0003,
        offset=0x00018F84,
        type=CVInfoTypeEnum.T_UINT4,
        name="_winver",
        is_global=True,
    )
    assert parser.globals[1] == GdataEntry(
        section=0x0003,
        offset=0x00018FCC,
        type=CVInfoTypeEnum.T_INT4,
        name="fSystemSet",
        is_global=False,
    )


MODULES_SAMPLE = r"""
0001 "GolDP.exp"
00F8 "C:\tools\MSVC600-8168\vc98\lib\LIBCMT.lib" "build\intel\mt_obj\trnsctrl.obj"
00F9 "" "* Linker *"
"""


def test_modules():
    """An empty library name is read as an empty string, and a module with
    no library name has lib=None."""
    parser = CvdumpParser()
    parser.read_section("MODULES", MODULES_SAMPLE)

    assert parser.modules == [
        ModuleEntry(id=0x0001, lib=None, obj="GolDP.exp"),
        ModuleEntry(
            id=0x00F8,
            lib=r"C:\tools\MSVC600-8168\vc98\lib\LIBCMT.lib",
            obj=r"build\intel\mt_obj\trnsctrl.obj",
        ),
        ModuleEntry(id=0x00F9, lib="", obj="* Linker *"),
    ]
