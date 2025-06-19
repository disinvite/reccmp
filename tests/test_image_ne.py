from reccmp.isledecomp.formats import NEImage
from reccmp.isledecomp.formats.ne import NESegmentFlags, NETargetOSFlags


def test_vitals(skifree: NEImage):
    # Linker version 5.5
    assert (skifree.header.ne_ver, skifree.header.ne_rev) == (5, 5)
    assert skifree.header.ne_enttab == 0x526
    assert skifree.header.ne_cbenttab == 0x88
    assert skifree.header.ne_heap == 0x4000
    assert skifree.header.ne_stack == 0x4000
    assert skifree.header.ne_flags == NESegmentFlags.NEINST | NESegmentFlags.NEWINAPI
    assert skifree.header.ne_exetyp == NETargetOSFlags.NE_WINDOWS
    assert skifree.header.ne_flagsothers == 8  # according to ghidra


def test_reads(skifree: NEImage):
    assert (
        skifree.read(1, 0, 16)
        == b"\x1e\x58\x90\x45\x55\x8b\xec\x1e\x8e\xd8\x81\xec\x04\x01\x57\x56"
    )
    assert skifree.read_string(2, 0x17) == b"[out o' memory]\x00"

    # Read up to end of seg.
    # Skip relocation at 0x5a2a
    assert skifree.read_string(1, 0x5A2C) == b"\x8b\xd0\x2b\xc0\x8b\xe5\x5d\x4d\xcb\x90"
