from pathlib import PureWindowsPath
from reccmp.formats.msvc_map import MsvcMap
from reccmp.types import EntityType

MSVC15_PUBLICS_SAMPLE = """\

  Address         Publics by Value

 0000:0000  Imp  GETSTOCKOBJECT       (GDI.87)
 0000:0000  Unr  ?DPtoLP@CDC@@RFCXPEUtagSIZE@@@Z
 0001:02E1       ?_afxWndFrameOrView@@3QFDF
 0001:02F0       ?_afxWndMDIFrame@@3QFDF

"""


def test_msvc15_publics():
    m = MsvcMap(MSVC15_PUBLICS_SAMPLE)

    # Ignore imports and "unr"?
    assert (0, 0) not in m.nodes
    assert m.nodes[(1, 0x2E1)].decorated_name == "?_afxWndFrameOrView@@3QFDF"
    assert m.nodes[(1, 0x2F0)].decorated_name == "?_afxWndMDIFrame@@3QFDF"


MSVC15_LINES_SAMPLE = """\

Line numbers for obj\\btnbar.obj(..\\src\\btnbar.cpp) segment COMDAT_SEG1

    25 0002:0093    26 0002:00b6     0 0002:00c1    29 0002:00c2
    30 0002:00d7    31 0002:00de    33 0002:00ea     0 0002:00f7

"""


def test_msvc15_lines():
    m = MsvcMap(MSVC15_LINES_SAMPLE)

    l = m.lines[0]
    assert l.path == PureWindowsPath("..\\src\\btnbar.cpp")
    assert ((2, 0x93), 25) in l.lines
    assert ((2, 0xC1), 0) in l.lines
    assert ((2, 0xF7), 0) in l.lines


MSVC50_PUBLICS_SAMPLE = """\

  Address         Publics by Value              Rva+Base   Lib:Object

 0001:00000000       ?InitLeadByte@@YAXXZ       10601000 f p0chrmap.obj
 0001:00000050       ?unInitLeadByte@@YAXXZ     10601050 f p0chrmap.obj
 0001:00000080       ?nextis@@YAHE@Z            10601080 f p0expr.obj
 0001:00000160       ?p0eval@@YAPAUs_tree0@@EPAU1@0@Z 10601160 f p0expr.obj
 0001:000007e0       ?do_constexpr@@YA_JXZ      106017e0 f p0expr.obj
 0001:00000870       ?constexpr@@YAPAUs_tree0@@XZ 10601870 f p0expr.obj
 0001:0005035a       _isalpha                   1065135a f MSVCRT:MSVCRT.dll
 0001:00050360       _isalnum                   10651360 f MSVCRT:MSVCRT.dll
 0001:00050366       _toupper                   10651366 f MSVCRT:MSVCRT.dll
 0001:00050370       __alloca_probe             10651370   MSVCRT:chkstk.obj
 0001:00050370       __chkstk                   10651370   MSVCRT:chkstk.obj
 0001:000503a0       _rewind                    106513a0 f MSVCRT:MSVCRT.dll
 0001:000503a6       _fflush                    106513a6 f MSVCRT:MSVCRT.dll

"""


def test_msvc50_publics():
    m = MsvcMap(MSVC50_PUBLICS_SAMPLE)

    assert m.nodes[(1, 0x5035A)].decorated_name == "_isalpha"
    assert m.nodes[(1, 0x5035A)].node_type == EntityType.FUNCTION
