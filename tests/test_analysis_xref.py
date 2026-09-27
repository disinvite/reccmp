import pytest
from reccmp.analysis.xref import (
    get_function_xrefs,
    create_xref_matches,
    XrefCollector,
    RefType,
)
from reccmp.compare.db import EntityDb
from reccmp.formats import PEImage
from reccmp.types import ImageId, EntityType
from .raw_image import RawImage

# MxCriticalSection::SetDoMutex.
# Short function that sets the g_mutex global variable at 0x10101e78.
SET_DO_MUTEX_ADDR = 0x100B6E00
G_MUTEX_ADDR = 0x10101E78


def test_get_function_xrefs_empty(binfile: PEImage):
    """The function's xrefs will be empty if entities it references are not known."""
    db = EntityDb()
    assert not get_function_xrefs(db, ImageId.ORIG, binfile, SET_DO_MUTEX_ADDR)


def test_get_function_xrefs_unmatched(binfile: PEImage):
    """The function's xrefs will be empty if entities it references are not *matched*."""
    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, G_MUTEX_ADDR, name="g_mutex", type=EntityType.DATA)

    assert not get_function_xrefs(db, ImageId.ORIG, binfile, SET_DO_MUTEX_ADDR)


def test_get_function_xrefs_matched(binfile: PEImage):
    """g_mutex variable is matched, and it should appear in the xrefs for SetDoMutex"""
    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, G_MUTEX_ADDR, name="g_mutex", type=EntityType.DATA)
        batch.match(G_MUTEX_ADDR, G_MUTEX_ADDR)

    assert get_function_xrefs(db, ImageId.ORIG, binfile, SET_DO_MUTEX_ADDR) == (
        (G_MUTEX_ADDR, RefType.WRITE),
    )


def test_get_function_xrefs_called_function():
    """Called functions appear as CALLs in the xrefs."""
    start_addr = 0x400000
    other_addr = 0x401000
    code = (
        b"\xe8\xfb\x0f\x00\x00"  # call 0x401000
        b"\xc3"  # ret
    )
    binfile = RawImage.from_memory(code, base_addr=start_addr)

    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, start_addr, size=len(code))
        batch.set(ImageId.ORIG, other_addr, name="test", type=EntityType.FUNCTION)
        batch.match(other_addr, other_addr)

    assert get_function_xrefs(db, ImageId.ORIG, binfile, start_addr) == (
        (other_addr, RefType.CALL),
    )


def test_get_function_xrefs_function_pointer():
    """Function entities that are not used in a call instruction appear as
    READ entries in the xrefs."""
    start_addr = 0x400000
    other_addr = 0x401000
    code = (
        b"\x68\x00\x10\x40\x00"  # push 0x401000
        b"\xc3"  # ret
    )
    binfile = RawImage.from_memory(code, base_addr=start_addr)

    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, start_addr, size=len(code))
        batch.set(ImageId.ORIG, other_addr, name="test", type=EntityType.FUNCTION)
        batch.match(other_addr, other_addr)

    assert get_function_xrefs(db, ImageId.ORIG, binfile, start_addr) == (
        (other_addr, RefType.READ),
    )


@pytest.mark.xfail(reason="Undecided on whether we need this")
def test_get_function_xrefs_indirect_call():
    """Indirect function calls should have their own xref category
    that is distinct from regular calls."""
    start_addr = 0x400000
    other_addr = 0x401000
    pointer = other_addr.to_bytes(4, "little")
    code = (
        b"\xff\x15\x00\x00\x40\x00"  # call dword ptr [0x400000]
        b"\xc3"  # ret
    )
    binfile = RawImage.from_memory(pointer + code, base_addr=start_addr)
    func_addr = start_addr + len(pointer)

    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, func_addr, size=len(code))
        batch.set(ImageId.ORIG, other_addr, name="test", type=EntityType.FUNCTION)
        batch.match(other_addr, other_addr)

    # TODO: Add the xrefs here if this feature is added.
    assert get_function_xrefs(db, ImageId.ORIG, binfile, func_addr)


def test_create_match_baseline():
    """No errors or exceptions for empty CRT arrays."""
    assert not create_xref_matches({}, {})


def test_create_match_single():
    """Should create match for unique xref."""
    write_xref = (1234, RefType.WRITE)
    x_xrefs = {100: (write_xref,)}
    y_xrefs = {200: (write_xref,)}
    assert create_xref_matches(x_xrefs, y_xrefs) == [(100, 200)]


def test_create_match_single_call():
    """Should create match for a unique function call."""
    call_xref = (1234, RefType.CALL)
    x_xrefs = {100: (call_xref,)}
    y_xrefs = {200: (call_xref,)}
    assert create_xref_matches(x_xrefs, y_xrefs) == [(100, 200)]


def test_create_match_call_is_not_a_read():
    """Should not match a function that calls the address with one that
    only reads it. e.g. passing the function pointer as an argument."""
    x_xrefs = {100: ((1234, RefType.READ),)}
    y_xrefs = {200: ((1234, RefType.CALL),)}
    assert not create_xref_matches(x_xrefs, y_xrefs)


@pytest.mark.parametrize("ref_type", RefType)
def test_create_match_non_unique_xref(ref_type: RefType):
    """Should not match functions if their xref is not unique."""
    xref = (1234, ref_type)
    x_xrefs = {100: (xref,), 200: (xref,)}
    y_xrefs = {200: (xref,), 300: (xref,)}
    assert not create_xref_matches(x_xrefs, y_xrefs)


def test_create_match_with_elimination():
    """Can create unique matches by eliminating already-matched functions."""
    write_xref = (1234, RefType.WRITE)
    read_xref = (5000, RefType.READ)
    # `write_xref` can be used to match uniquely on the first pass.
    # `read_xref` will provide a unique match after deleting the functions that contain `write_xref`.
    x_xrefs = {100: (read_xref,), 200: (write_xref, read_xref)}
    y_xrefs = {200: (read_xref,), 300: (write_xref, read_xref)}
    assert sorted(create_xref_matches(x_xrefs, y_xrefs)) == [
        (100, 200),
        (200, 300),
    ]


def test_create_match_group_shares_xref():
    """Two functions from the same array entry may use the same address.
    This is not the ambiguity that blocks a match between two different entries."""
    write_xref = (1234, RefType.WRITE)
    x_xrefs = {500: (write_xref, write_xref)}
    y_xrefs = {600: (write_xref, write_xref)}
    assert create_xref_matches(x_xrefs, y_xrefs) == [(500, 600)]


def test_create_match_no_match_within_one_array():
    write_xref = (1234, RefType.WRITE)
    read_xref = (5000, RefType.READ)
    x_xrefs = {
        100: (write_xref,),
        200: (read_xref,),
        300: (read_xref,),
    }
    y_xrefs = {400: (write_xref, read_xref)}
    assert create_xref_matches(x_xrefs, y_xrefs) == [(100, 400)]


def test_create_match_unique_pairs_removed_together():
    read_xref = (1000, RefType.READ)
    write_xref_a = (2000, RefType.WRITE)
    write_xref_b = (3000, RefType.WRITE)
    x_xrefs = {
        100: (read_xref, write_xref_a),
        300: (read_xref, write_xref_b),
    }
    y_xrefs = {
        200: (write_xref_a,),
        400: (read_xref,),
        500: (write_xref_b,),
    }
    assert sorted(create_xref_matches(x_xrefs, y_xrefs)) == [(100, 200), (300, 500)]


def test_create_match_ambiguous_partner():
    write_xref_a = (2000, RefType.WRITE)
    write_xref_b = (3000, RefType.WRITE)
    x_xrefs = {100: (write_xref_a, write_xref_b)}
    y_xrefs = {200: (write_xref_a,), 400: (write_xref_b,)}
    assert not create_xref_matches(x_xrefs, y_xrefs)


def test_create_match_ambiguous_partner_after_elimination():
    """An entry that was ambiguous in an earlier pass is still ambiguous
    when eliminating a matched entry gives it another partner."""
    xref_a = (1000, RefType.READ)
    xref_b = (2000, RefType.READ)
    xref_c = (3000, RefType.READ)
    xref_d = (4000, RefType.READ)
    # 100 and 200 both link to 1000 on the first pass. 400 matches 2000.
    # Removing 400 links 300 to 1000 through `xref_c`.
    x_xrefs = {
        100: (xref_a,),
        200: (xref_b,),
        300: (xref_c,),
        400: (xref_c, xref_d),
    }
    y_xrefs = {1000: (xref_a, xref_b, xref_c), 2000: (xref_d,)}
    assert create_xref_matches(x_xrefs, y_xrefs) == [(400, 2000)]


def test_create_match_two_unique_xrefs():
    """Should match functions that share more than one unique xref."""
    write_xref_a = (2000, RefType.WRITE)
    write_xref_b = (3000, RefType.WRITE)
    x_xrefs = {100: (write_xref_a, write_xref_b)}
    y_xrefs = {200: (write_xref_a, write_xref_b)}
    assert create_xref_matches(x_xrefs, y_xrefs) == [(100, 200)]


def test_collector_small_addrs_ignored():
    """Limit tested addresses to those large enough to be an EXE imagebase."""
    code = (
        b"\xc6\x05\x00\x00\x00\x00\x00"  # mov byte ptr [0x0], 0
        b"\xc6\x05\x00\x10\x00\x00\x00"  # mov byte ptr [0x1000], 0
        b"\xc6\x05\x00\x00\x40\x00\x00"  # mov byte ptr [0x400000], 0
        b"\xc6\x05\x00\x00\x00\x10\x00"  # mov byte ptr [0x10000000], 0
        b"\xc3"  # ret
    )

    collector = XrefCollector(lambda _: True)
    collector.analyze(code, 0)

    assert collector.seen_addrs == [
        (0x400000, RefType.WRITE),
        (0x10000000, RefType.WRITE),
    ]


def test_collector_repeated_addrs():
    """Collected addresses are presented in sequence and are not deduplicated.
    The caller can choose to reduce this to a set as needed."""
    code = (
        b"\xc6\x05\x00\x00\x40\x00\x00"  # mov byte ptr [0x400000], 0
        b"\xc6\x05\x00\x00\x40\x00\x00"  # mov byte ptr [0x400000], 0
        b"\x80\x3d\x00\x00\x40\x00\x00"  # cmp byte ptr [0x400000], 0x0
        b"\xc3"  # ret
    )

    collector = XrefCollector(lambda _: True)
    collector.analyze(code, 0)

    assert collector.seen_addrs == [
        (0x400000, RefType.WRITE),
        (0x400000, RefType.WRITE),
        (0x400000, RefType.READ),
    ]


def test_collector_classify_float_instructions_as_read_or_write():
    """Capstone does not present float instructions with their implicit FPU register.
    Make sure FSTP is identified as a write, and the others as reads."""
    code = (
        b"\xd9\x05\x00\x10\x40\x00"  # fld dword ptr [0x401000]
        b"\xd8\x35\x00\x20\x40\x00"  # fdiv dword ptr [0x402000]
        b"\xd9\x1d\x00\x30\x40\x00"  # fstp dword ptr [0x403000]
        b"\xc3"  # ret
    )

    collector = XrefCollector(lambda _: True)
    collector.analyze(code, 0)

    assert collector.seen_addrs == [
        (0x401000, RefType.READ),
        (0x402000, RefType.READ),
        (0x403000, RefType.WRITE),
    ]


def test_collector_not_all_dst_operands_are_writes():
    code = (
        b"\x80\x3d\x00\x00\x40\x00\x00"  # cmp byte ptr [0x400000], 0x0
        b"\xf6\x05\x00\x00\x41\x00\x08"  # test byte ptr [0x410000], 0x8
        b"\xc3"  # ret
    )

    collector = XrefCollector(lambda _: True)
    collector.analyze(code, 0)

    assert collector.seen_addrs == [
        (0x400000, RefType.READ),
        (0x410000, RefType.READ),
    ]


def test_collector_calls_and_jumps():
    """Jumps are ignored. Calls are collected as exec addresses."""
    code = (
        b"\xe8\xfb\x0f\x00\x00"  # call 0x401000
        b"\xe9\xf6\x1f\x00\x00"  # jmp 0x402000
        b"\xc3"  # ret
    )

    collector = XrefCollector(lambda _: True)
    # Must set start addr here because CALLs and JMPs are relative.
    collector.analyze(code, 0x400000)

    assert collector.seen_addrs == [
        (0x401000, RefType.CALL),
    ]
