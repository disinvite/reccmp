import pytest
from reccmp.isledecomp.formats import NEImage
from reccmp.isledecomp.formats.image import ImageImport
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

    assert skifree.imagebase == 0x10000000
    assert skifree.entry == 0x100051E1


def test_reads(skifree: NEImage):
    assert (
        skifree.read(0x10000000, 16)
        == b"\x1e\x58\x90\x45\x55\x8b\xec\x1e\x8e\xd8\x81\xec\x04\x01\x57\x56"
    )
    assert skifree.read_string(0x10080017) == b"[out o' memory]"

    # Read up to end of seg.
    # Skip relocation at 0x5a2a
    assert (
        skifree.read_string(0x10005A2C) == b"\x8b\xd0\x2b\xc0\x8b\xe5\x5d\x4d\xcb\x90"
    )


ADDR_CONVERSION_SAMPLES = (
    # Section starts
    ((1, 0), 0x10000000),
    ((2, 0), 0x10080000),
    # Section ends (virtual size - 1)
    ((1, 0x5A35), 0x10005A35),
    ((2, 0x0BC7), 0x10080BC7),
)


@pytest.mark.parametrize("relative, absolute", ADDR_CONVERSION_SAMPLES)
def test_addr_conversion_absolute(
    skifree: NEImage, relative: tuple[int, int], absolute: int
):
    """Testing conversion from seg:offset to absolute address."""
    assert skifree.get_abs_addr(*relative) == absolute


@pytest.mark.parametrize("relative, absolute", ADDR_CONVERSION_SAMPLES)
def test_addr_conversion_relative(
    skifree: NEImage, relative: tuple[int, int], absolute: int
):
    """Testing conversion from absolute address to seg:offset."""
    assert skifree.get_relative_addr(absolute) == relative


def test_reloc_patching_import_ordinal(skifree: NEImage):
    # Source chain of one: the reloc location is 0xffff.
    # Just assert that we changed it to something else.
    assert skifree.read(0x10000049, 5) != b"\x9a\xff\xff\x00\x00"

    # USER::LOADSTRING -> import_seg::000f8
    assert skifree.read(0x10000049, 3) == b"\x9a\xf8\x00"


def test_reloc_patching_internalref(skifree: NEImage):
    # Internalref reloc has all zeroes for the pointer.
    assert skifree.read(0x10003C92, 5) != b"\x9a\x00\x00\x00\x00"

    # Should replace with 0001:3c92.
    assert skifree.read(0x10003C92, 5) == b"\x9a\x6e\x52\x00\x10"

    # Separate relocs for seg and offset.
    assert skifree.read(0x10003E71, 2) == b"\x3c\x51"
    assert skifree.read(0x10003E76, 2) == b"\x00\x10"


IMPORT_REFS = (
    ImageImport(module="GDI", ordinal=34, addr=0x2000004C),
    ImageImport(module="KERNEL", ordinal=137, addr=0x20000040),
    ImageImport(module="USER", ordinal=420, addr=0x20000100),
)


@pytest.mark.parametrize("import_ref", IMPORT_REFS)
def test_imports(import_ref: tuple[ImageImport, ...], skifree: NEImage):
    assert import_ref in tuple(skifree.imports)
