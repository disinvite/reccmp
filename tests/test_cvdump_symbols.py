"""Test Cvdump SYMBOLS parser, reading function stack/params"""

from reccmp.isledecomp.cvdump.symbols import CvdumpSymbolsParser, StackOrRegisterSymbol

PROC_WITH_BLOC = """
(000638) S_GPROC32: [0001:000C6135], Cb: 00000361, Type:             0x10ED, RegistrationBook::ReadyWorld
         Parent: 00000000, End: 00000760, Next: 00000000
         Debug start: 0000000C, Debug end: 0000035C
         Flags: Frame Ptr Present
(00067C)  S_BPREL32: [FFFFFFD0], Type:             0x10EC, this
(000690)  S_BPREL32: [FFFFFFDC], Type:             0x10F5, checkmarkBuffer
(0006AC)  S_BPREL32: [FFFFFFE8], Type:             0x10F6, letterBuffer
(0006C8)  S_BPREL32: [FFFFFFF4], Type:      T_SHORT(0011), i
(0006D8)  S_BPREL32: [FFFFFFF8], Type:             0x10F8, players
(0006EC)  S_BPREL32: [FFFFFFFC], Type:             0x1044, gameState
(000704)  S_BLOCK32: [0001:000C624F], Cb: 000001DA,
          Parent: 00000638, End: 0000072C
(00071C)   S_BPREL32: [FFFFFFD8], Type:      T_SHORT(0011), j
(00072C)  S_END
(000730)  S_BLOCK32: [0001:000C6448], Cb: 00000032,
          Parent: 00000638, End: 0000075C
(000748)   S_BPREL32: [FFFFFFD4], Type:             0x10FA, infoman
(00075C)  S_END
(000760) S_END
"""


def test_sblock32():
    """S_END has double duty as marking the end of a function (S_GPROC32)
    and a scope block (S_BLOCK32). Make sure we can distinguish between
    the two and not end a function early."""
    parser = CvdumpSymbolsParser()
    parser.read_all(PROC_WITH_BLOC)

    # Make sure we can read the proc and all its stack references
    assert len(parser.symbols) == 1
    assert len(parser.symbols[0].stack_symbols) == 8


LDATA32_INSIDE_FUNCTION = """\
(004368) S_GPROC32: [0001:00050A28], Cb: 000000B5, Type:             0x1010, GetCDPathFromPathsTxtFile

(0043AC)  S_BPREL32: [00000008], Type:   T_32PRCHAR(0470), pPath_name
(0043C4)  S_LDATA32: [0003:0000B3C4], Type:       T_INT4(0074), got_it_already
(0043E4)  S_LDATA32: [0003:0003C488], Type:             0x100B, cd_pathname

(004400) S_END
"""


def test_ldata32_inside_function():
    """S_LDATA32 leaves inside of a function (S_GPROC32) are assumed to be
    static variables from that function."""
    parser = CvdumpSymbolsParser()
    parser.read_all(LDATA32_INSIDE_FUNCTION)

    assert len(parser.symbols) == 1
    assert len(parser.symbols[0].static_variables) == 2
    assert [v.name for v in parser.symbols[0].static_variables] == [
        "got_it_already",
        "cd_pathname",
    ]


def test_ldata32_outside_function():
    """Should ignore an S_LDATA32 leaf found outside a function.
    These appear to indicate const global variables and they should be
    repeated in the GLOBALS section."""
    parser = CvdumpSymbolsParser()
    parser.read_all(
        "(00045C) S_LDATA32: [0003:0000E298], Type:             0x1060, TestVariable"
    )

    # ignored... for now.
    # Should not crash with a failed assert. See GH issue #183.
    assert len(parser.symbols) == 0


FRAME_PTR_FUNCTION = """\
(0000AC) S_GPROC32: [0001:00081000], Cb: 00000095, Type:             0x1231, HistoryBook::HistoryBook
         Parent: 00000000, End: 00000128, Next: 00000000
         Debug start: 0000001D, Debug end: 00000074
         Flags: Frame Ptr Present

(0000EC)  S_LABEL32: [0001:0008108D], $L67067
(000100)  S_LABEL32: [0001:00081083], $L67066
(000114)  S_BPREL32: [FFFFFFF0], Type:             0x1230, this

(000128) S_END

(00012C) S_GPROC32: [0001:000810A0], Cb: 00000006, Type:             0x1234, HistoryBook::ClassName
         Parent: 00000000, End: 0000017C, Next: 00000000
         Debug start: 00000000, Debug end: 00000005

(00016C)  S_REGISTER: ecx, Type:             0x1233, this

(00017C) S_END
"""


def test_gproc32_frame_ptr():
    """Should detect 'Frame Ptr Present' in the Flags section of S_GPROC32."""
    parser = CvdumpSymbolsParser()
    parser.read_all(FRAME_PTR_FUNCTION)

    assert parser.symbols[0].frame_pointer_present is True
    assert parser.symbols[1].frame_pointer_present is False


def test_read_registers():
    parser = CvdumpSymbolsParser()
    # This example has both S_BPREL32 and S_REGISTER in different functions.
    parser.read_all(FRAME_PTR_FUNCTION)

    # Should convert locations to lower case
    assert parser.symbols[0].stack_symbols[0] == StackOrRegisterSymbol(
        symbol_type="S_BPREL32", location="[fffffff0]", data_type="0x1230", name="this"
    )
    assert parser.symbols[1].stack_symbols[0] == StackOrRegisterSymbol(
        symbol_type="S_REGISTER", location="ecx", data_type="0x1233", name="this"
    )
