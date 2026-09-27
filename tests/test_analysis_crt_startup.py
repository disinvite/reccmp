import struct
import pytest
from reccmp.analysis.crt_startup import (
    get_function_xrefs,
    find_crt_startup_labels,
    read_crt_functions,
    collect_crt_xrefs,
    CrtStartupArray,
    create_xref_matches,
    expand_entry_matches,
    XrefCollector,
    RefType,
    read_function_set,
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


XCA_XCZ_RANGE = range(0x100F0000, 0x100F0020)


def test_find_crt_startup_labels_empty():
    db = EntityDb()
    assert not find_crt_startup_labels(db, ImageId.ORIG)


def test_find_crt_startup_labels_cpp_init():
    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, XCA_XCZ_RANGE.start, name="___xc_a")
        batch.set(ImageId.ORIG, XCA_XCZ_RANGE.stop, name="___xc_z")

    labels = find_crt_startup_labels(db, ImageId.ORIG)
    assert labels["___xc_a"] == XCA_XCZ_RANGE.start
    assert labels["___xc_z"] == XCA_XCZ_RANGE.stop


# Maps function addr to thunk.
# The thunks are what appears in the ___xc_a array.
XCA_THUNK_MAPPING = (
    (0x10092360, 0x10092350),
    (0x10012DB0, 0x10012DA0),
    (0x100145A0, 0x10014590),
    (0x1001A6D0, 0x1001A6C0),
    (0x1002A4D0, 0x1002A4C0),
    (0x1003FA20, 0x1003FA10),
    (0x100537C0, 0x100537B0),
)


def test_xca_xrefs_empty(binfile: PEImage):
    db = EntityDb()

    # Baseline: no entities so all xrefs are empty
    array = read_crt_functions(binfile, XCA_XCZ_RANGE)
    collect_crt_xrefs(db, ImageId.ORIG, binfile, array)

    assert not array.xrefs


def test_xca_functions(binfile: PEImage):
    """Every entry in this array is a JMP thunk to a single function."""
    array = read_crt_functions(binfile, XCA_XCZ_RANGE)
    assert array.entries == [thunk for _, thunk in XCA_THUNK_MAPPING]
    assert array.function_set == {thunk: (addr,) for addr, thunk in XCA_THUNK_MAPPING}


def test_xca_xrefs_not_variable(binfile: PEImage):
    """We have the variable's entity in the database, but its type is not set.
    This means it cannot be part of the function's xrefs."""
    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 0x10102B28, name="g_spawnLocations")
        batch.match(0x10102B28, 0x10102B28)

    array = read_crt_functions(binfile, XCA_XCZ_RANGE)
    collect_crt_xrefs(db, ImageId.ORIG, binfile, array)
    assert 0x1001A6C0 not in array.xrefs


def test_xca_xrefs_matched_variable(binfile: PEImage):
    """Variable entity matched and with type set.
    We should now see it in the function's xrefs."""
    db = EntityDb()
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG, 0x10102B28, name="g_spawnLocations", type=EntityType.DATA
        )
        batch.match(0x10102B28, 0x10102B28)

    array = read_crt_functions(binfile, XCA_XCZ_RANGE)
    collect_crt_xrefs(db, ImageId.ORIG, binfile, array)
    assert array.xrefs[0x1001A6C0] == ((0x10102B28, RefType.READ),)


def test_xrefs_combine_function_set():
    """The xrefs of both functions behind a CALL+JMP thunk are stored together
    under the thunk's entry."""
    code = bytearray(0x30)
    code[0:10] = (
        b"\xe8\x0b\x00\x00\x00\xe9\x16\x00\x00\x00"  # call 0x400010, jmp 0x400020
    )
    code[0x10:0x18] = (
        b"\xc6\x05\x00\x00\x41\x00\x00"  # mov byte ptr [0x410000], 0
        b"\xc3"  # ret
    )
    code[0x20:0x28] = (
        b"\xc6\x05\x00\x00\x42\x00\x00"  # mov byte ptr [0x420000], 0
        b"\xc3"  # ret
    )
    binfile = RawImage.from_memory(bytes(code), base_addr=0x400000)

    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 0x400010, size=8)
        batch.set(ImageId.ORIG, 0x400020, size=8)
        for addr in (0x410000, 0x420000):
            batch.set(ImageId.ORIG, addr, name="test", type=EntityType.DATA)
            batch.match(addr, addr)

    array = CrtStartupArray(
        entries=[0x400000], function_set={0x400000: (0x400010, 0x400020)}
    )
    collect_crt_xrefs(db, ImageId.ORIG, binfile, array)
    assert array.xrefs == {
        0x400000: ((0x410000, RefType.WRITE), (0x420000, RefType.WRITE))
    }


def test_xca_xrefs_avoid_crash(binfile: PEImage):
    # Misaligned end address will cause struct.iter_unpack to raise struct.error.
    modified_range = range(XCA_XCZ_RANGE.start, XCA_XCZ_RANGE.stop - 1)

    try:
        read_crt_functions(binfile, modified_range)
    except struct.error:
        assert False, "Should not throw"


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


def test_expand_matches_thunk_one_sided():
    """Should not add thunk match unless it exists in both arrays."""
    x_array = CrtStartupArray(function_set={500: (100,)})
    y_array = CrtStartupArray()
    assert expand_entry_matches(x_array, y_array, [(500, 200)]) == [(100, 200)]


def test_expand_matches_thunk_two_sided():
    """Should match function and thunk."""
    x_array = CrtStartupArray(function_set={500: (100,)})
    y_array = CrtStartupArray(function_set={600: (200,)})
    assert expand_entry_matches(x_array, y_array, [(500, 600)]) == [
        (100, 200),
        (500, 600),
    ]


def test_expand_matches_group():
    """Should match every function behind the thunk when the thunk matches,
    and match the thunk once."""
    x_array = CrtStartupArray(function_set={500: (100, 101)})
    y_array = CrtStartupArray(function_set={600: (200, 201)})
    assert expand_entry_matches(x_array, y_array, [(500, 600)]) == [
        (100, 200),
        (101, 201),
        (500, 600),
    ]


def test_expand_matches_different_patterns():
    """If one thunk leads to two functions and the other to one,
    (i.e. if they both use thunks but with different patterns)
    match only the function that both patterns have in common."""
    x_array = CrtStartupArray(function_set={500: (100, 101)})
    y_array = CrtStartupArray(function_set={600: (200,)})
    assert expand_entry_matches(x_array, y_array, [(500, 600)]) == [
        (100, 200),
        (500, 600),
    ]


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


CRT_CALL_JMP_PATTERNS = (
    pytest.param(
        b"\xe8\x0b\x00\x00\x00\xe9\x16\x00\x00\x00", 0x20, id="call 0x10, jmp 0x20"
    ),
    pytest.param(
        b"\xe8\x0b\x00\x00\x00\xe9\x36\x00\x00\x00", 0x40, id="call 0x10, jmp 0x40"
    ),
)


@pytest.mark.parametrize("code, jmp_dest", CRT_CALL_JMP_PATTERNS)
def test_read_function_set_call_and_jmp(code: bytes, jmp_dest: int):
    """Follows the two-instruction thunk to the function at the next 16-byte boundary
    and to the jmp destination. The called function can be larger than 16 bytes,
    so the jmp displacement varies."""
    memory = bytearray(128)
    memory[0 : len(code)] = code
    memory[0x10] = 0xC3  # RET

    binfile = RawImage.from_memory(bytes(memory))
    assert read_function_set(binfile, 0) == (0x10, jmp_dest)
    assert not read_function_set(binfile, 0x10)


def test_read_function_set_call_next_function_and_jmp():
    """Follows the two-instruction thunk when the called function begins
    immediately after the thunk instead of at the next 16-byte boundary."""
    memory = bytearray(128)
    memory[0:10] = b"\xe8\x05\x00\x00\x00\xe9\x16\x00\x00\x00"  # call 0xa, jmp 0x20
    memory[0xA] = 0xC3  # RET

    binfile = RawImage.from_memory(bytes(memory))
    assert read_function_set(binfile, 0) == (0xA, 0x20)


def test_read_function_set_jmp_only():
    """Follows the single-instruction thunk to the function at the next 16-byte boundary."""
    memory = bytearray(128)
    memory[0:5] = b"\xe9\x0b\x00\x00\x00"  # jmp 0x10
    memory[0x10] = 0xC3  # RET

    binfile = RawImage.from_memory(bytes(memory))
    assert read_function_set(binfile, 0) == (0x10,)
    assert not read_function_set(binfile, 0x10)


def test_read_function_set_jmp_to_next_function():
    """Follows the single-instruction thunk when the function begins
    immediately after the thunk instead of at the next 16-byte boundary."""
    memory = bytearray(128)
    memory[0:5] = b"\xe9\x00\x00\x00\x00"  # jmp 0x5
    memory[0x5] = 0xC3  # RET

    binfile = RawImage.from_memory(bytes(memory))
    assert read_function_set(binfile, 0) == (0x5,)


CRT_NOT_THUNK_PATTERNS = (
    pytest.param(b"\xe8\x0b\x00\x00\x00\xc3", id="call without jmp (16-byte aligned)"),
    pytest.param(b"\xe8\x05\x00\x00\x00\xc3", id="call without jmp"),
    pytest.param(b"\xe8\x3b\x00\x00\x00\xc3", id="call too far away"),
    pytest.param(b"\xe9\x3b\x00\x00\x00", id="jmp too far away"),
    pytest.param(b"\xe9\xdb\xff\xff\xff", id="jmp backwards"),
)


@pytest.mark.parametrize("code", CRT_NOT_THUNK_PATTERNS)
def test_read_function_set_not_a_thunk(code: bytes):
    """The function may begin with a call or jmp. It is not a thunk unless the
    instructions match a thunk pattern exactly. Only the displacement of the
    second jmp is allowed to vary."""
    memory = bytearray(128)
    memory[0x40 : 0x40 + len(code)] = code

    binfile = RawImage.from_memory(bytes(memory))
    assert not read_function_set(binfile, 0x40)


def test_read_function_set_jmp_must_be_ahead():
    """If the CALL+JMP thunk pattern is used, expect the second function to
    follow the first. We are not certain where it will be, but (for now)
    we require the jump displacement to be positive (i.e. we jump ahead)"""
    code = b"\xe8\x0b\x00\x00\x00\xe9\xf6\xff\xff\xff"  # call 0x50, jmp 0x40
    memory = bytearray(128)
    memory[0x40 : 0x40 + len(code)] = code

    binfile = RawImage.from_memory(bytes(memory))
    assert not read_function_set(binfile, 0x40)
