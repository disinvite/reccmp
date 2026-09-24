import struct
import pytest
from reccmp.analysis.crt_startup import (
    get_function_fingerprint,
    find_crt_startup_labels,
    read_crt_functions,
    fingerprint_crt_functions,
    CrtStartupArray,
    FunctionSet,
    create_crt_matches,
    UsedAddressCollector,
    UsedHow,
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


def test_get_function_fingerprint_empty(binfile: PEImage):
    """The function fingerprint will be empty if entities it references are not known."""
    db = EntityDb()
    assert not get_function_fingerprint(db, ImageId.ORIG, binfile, SET_DO_MUTEX_ADDR)


def test_get_function_fingerprint_unmatched(binfile: PEImage):
    """The function fingerprint will be empty if entities it references are not *matched*."""
    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, G_MUTEX_ADDR, name="g_mutex", type=EntityType.DATA)

    assert not get_function_fingerprint(db, ImageId.ORIG, binfile, SET_DO_MUTEX_ADDR)


def test_get_function_fingerprint_matched(binfile: PEImage):
    """g_mutex variable is matched, and it should appear in the fingerprint for SetDoMutex"""
    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, G_MUTEX_ADDR, name="g_mutex", type=EntityType.DATA)
        batch.match(G_MUTEX_ADDR, G_MUTEX_ADDR)

    assert get_function_fingerprint(db, ImageId.ORIG, binfile, SET_DO_MUTEX_ADDR) == (
        (G_MUTEX_ADDR, UsedHow.WRITE),
    )


def test_get_function_fingerprint_called_function():
    """Called functions appear as CALLs in the fingerprint list."""
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

    assert get_function_fingerprint(db, ImageId.ORIG, binfile, start_addr) == (
        (other_addr, UsedHow.CALL),
    )


def test_get_function_fingerprint_function_pointer():
    """Function entities that are not used in a call instruction appear as
    READ entries in the fingerprint list."""
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

    assert get_function_fingerprint(db, ImageId.ORIG, binfile, start_addr) == (
        (other_addr, UsedHow.READ),
    )


@pytest.mark.xfail(reason="Undecided on whether we need this")
def test_get_function_fingerprint_indirect_call():
    """Indirect function calls should have their own fingerprint category
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

    # TODO: Add the fingerprints here if this feature is added.
    assert get_function_fingerprint(db, ImageId.ORIG, binfile, func_addr)


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


def test_xca_fingerprints_empty(binfile: PEImage):
    db = EntityDb()

    # Baseline: no entities so all fingerprints are empty
    array = read_crt_functions(binfile, XCA_XCZ_RANGE)
    fingerprint_crt_functions(db, ImageId.ORIG, binfile, array)

    assert set(array.fingerprints.keys()) == {addr for addr, _ in XCA_THUNK_MAPPING}
    assert all(not v for v in array.fingerprints.values())


def test_xca_functions(binfile: PEImage):
    """Every entry in this array is a JMP thunk to a single function."""
    array = read_crt_functions(binfile, XCA_XCZ_RANGE)
    assert array.functions == [
        FunctionSet((addr,), thunk=thunk) for addr, thunk in XCA_THUNK_MAPPING
    ]


def test_xca_fingerprints_not_variable(binfile: PEImage):
    """We have the variable's entity in the database, but its type is not set.
    This means it cannot be part of the function's fingerprint."""
    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 0x10102B28, name="g_spawnLocations")
        batch.match(0x10102B28, 0x10102B28)

    array = read_crt_functions(binfile, XCA_XCZ_RANGE)
    fingerprint_crt_functions(db, ImageId.ORIG, binfile, array)
    assert not array.fingerprints[0x1001A6D0]


def test_xca_fingerprints_matched_variable(binfile: PEImage):
    """Variable entity matched and with type set.
    We should now see it in the function's fingerprint list."""
    db = EntityDb()
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG, 0x10102B28, name="g_spawnLocations", type=EntityType.DATA
        )
        batch.match(0x10102B28, 0x10102B28)

    array = read_crt_functions(binfile, XCA_XCZ_RANGE)
    fingerprint_crt_functions(db, ImageId.ORIG, binfile, array)
    assert array.fingerprints[0x1001A6D0] == ((0x10102B28, UsedHow.READ),)


def test_xca_fingerprints_avoid_crash(binfile: PEImage):
    # Misaligned end address will cause struct.iter_unpack to raise struct.error.
    modified_range = range(XCA_XCZ_RANGE.start, XCA_XCZ_RANGE.stop - 1)

    try:
        read_crt_functions(binfile, modified_range)
    except struct.error:
        assert False, "Should not throw"


def test_create_match_baseline():
    """No errors or exceptions for empty CRT arrays."""
    x_array = CrtStartupArray()
    y_array = CrtStartupArray()
    assert not create_crt_matches(x_array, y_array)


def test_create_match_single():
    """Should create match for unique fingerprint."""
    write_sample = (1234, UsedHow.WRITE)
    x_array = CrtStartupArray(
        functions=[FunctionSet((100,))], fingerprints={100: (write_sample,)}
    )
    y_array = CrtStartupArray(
        functions=[FunctionSet((200,))], fingerprints={200: (write_sample,)}
    )
    assert create_crt_matches(x_array, y_array) == [(100, 200)]


def test_create_match_single_call():
    """Should create match for a unique function call."""
    call_sample = (1234, UsedHow.CALL)
    x_array = CrtStartupArray(
        functions=[FunctionSet((100,))], fingerprints={100: (call_sample,)}
    )
    y_array = CrtStartupArray(
        functions=[FunctionSet((200,))], fingerprints={200: (call_sample,)}
    )
    assert create_crt_matches(x_array, y_array) == [(100, 200)]


def test_create_match_call_is_not_a_read():
    """Should not match a function that calls the address with one that
    only reads it. e.g. passing the function pointer as an argument."""
    x_array = CrtStartupArray(
        functions=[FunctionSet((100,))],
        fingerprints={100: ((1234, UsedHow.READ),)},
    )
    y_array = CrtStartupArray(
        functions=[FunctionSet((200,))],
        fingerprints={200: ((1234, UsedHow.CALL),)},
    )
    assert not create_crt_matches(x_array, y_array)


def test_create_match_single_with_thunks_one_sided():
    """Should not add thunk match unless it exists in both arrays."""
    write_sample = (1234, UsedHow.WRITE)
    x_array = CrtStartupArray(
        functions=[FunctionSet((100,), thunk=500)],
        fingerprints={100: (write_sample,)},
    )
    y_array = CrtStartupArray(
        functions=[FunctionSet((200,))], fingerprints={200: (write_sample,)}
    )
    assert create_crt_matches(x_array, y_array) == [(100, 200)]


def test_create_match_single_with_thunks_two_sided():
    """Should match function and thunk."""
    write_sample = (1234, UsedHow.WRITE)
    x_array = CrtStartupArray(
        functions=[FunctionSet((100,), thunk=500)],
        fingerprints={100: (write_sample,)},
    )
    y_array = CrtStartupArray(
        functions=[FunctionSet((200,), thunk=600)],
        fingerprints={200: (write_sample,)},
    )
    assert create_crt_matches(x_array, y_array) == [(100, 200), (500, 600)]


def test_create_match_blank_fingerprint():
    """Should not match functions if their fingerprint has no addresses."""
    x_array = CrtStartupArray(functions=[FunctionSet((100,))])
    y_array = CrtStartupArray(functions=[FunctionSet((200,))])
    assert not create_crt_matches(x_array, y_array)


@pytest.mark.parametrize("used_how", UsedHow)
def test_create_match_non_unique_fingerprint(used_how: UsedHow):
    """Should not match functions if their fingerprint is not unique."""
    sample = (1234, used_how)
    x_array = CrtStartupArray(
        functions=[FunctionSet((100,)), FunctionSet((200,))],
        fingerprints={100: (sample,), 200: (sample,)},
    )
    y_array = CrtStartupArray(
        functions=[FunctionSet((200,)), FunctionSet((300,))],
        fingerprints={200: (sample,), 300: (sample,)},
    )
    assert not create_crt_matches(x_array, y_array)


def test_create_match_with_elimination():
    """Can create unique matches by eliminating already-matched functions."""
    write_sample = (1234, UsedHow.WRITE)
    read_sample = (5000, UsedHow.READ)
    # `write_sample` can be used to match uniquely on the first pass.
    # `read_sample` will provide a unique match after deleting the functions that contain `write_sample`.
    x_array = CrtStartupArray(
        functions=[FunctionSet((100,)), FunctionSet((200,))],
        fingerprints={100: (read_sample,), 200: (write_sample, read_sample)},
    )
    y_array = CrtStartupArray(
        functions=[FunctionSet((200,)), FunctionSet((300,))],
        fingerprints={200: (read_sample,), 300: (write_sample, read_sample)},
    )
    assert sorted(create_crt_matches(x_array, y_array)) == [
        (100, 200),
        (200, 300),
    ]


def test_create_match_group_by_first_function():
    """Should match the second function in the set when we match the first."""
    write_sample = (1234, UsedHow.WRITE)
    x_array = CrtStartupArray(
        functions=[FunctionSet((100, 101))], fingerprints={100: (write_sample,)}
    )
    y_array = CrtStartupArray(
        functions=[FunctionSet((200, 201))], fingerprints={200: (write_sample,)}
    )
    assert create_crt_matches(x_array, y_array) == [(100, 200), (101, 201)]


def test_create_match_group_by_second_function():
    """Should match the first function in the set when we match the second."""
    write_sample = (1234, UsedHow.WRITE)
    x_array = CrtStartupArray(
        functions=[FunctionSet((100, 101))], fingerprints={101: (write_sample,)}
    )
    y_array = CrtStartupArray(
        functions=[FunctionSet((200, 201))], fingerprints={201: (write_sample,)}
    )
    assert create_crt_matches(x_array, y_array) == [(100, 200), (101, 201)]


def test_create_match_group_shares_fingerprint():
    """Two functions from the same array entry may use the same address.
    This is not the ambiguity that blocks a match between two different entries."""
    write_sample = (1234, UsedHow.WRITE)
    x_array = CrtStartupArray(
        functions=[FunctionSet((100, 101))],
        fingerprints={100: (write_sample,), 101: (write_sample,)},
    )
    y_array = CrtStartupArray(
        functions=[FunctionSet((200, 201))],
        fingerprints={200: (write_sample,), 201: (write_sample,)},
    )
    assert create_crt_matches(x_array, y_array) == [(100, 200), (101, 201)]


def test_create_match_group_with_thunk():
    """Should match the thunk once, not once per function in the group."""
    write_sample = (1234, UsedHow.WRITE)
    x_array = CrtStartupArray(
        functions=[FunctionSet((100, 101), thunk=500)],
        fingerprints={100: (write_sample,)},
    )
    y_array = CrtStartupArray(
        functions=[FunctionSet((200, 201), thunk=600)],
        fingerprints={200: (write_sample,)},
    )
    assert create_crt_matches(x_array, y_array) == [(100, 200), (101, 201), (500, 600)]


def test_create_match_different_patterns():
    """If one function set has two functions and the other has one,
    (i.e. if they both use thunks but with different patterns)
    match only the function that both patterns have in common."""
    write_sample = (1234, UsedHow.WRITE)
    x_array = CrtStartupArray(
        functions=[FunctionSet((100, 101), thunk=500)],
        fingerprints={100: (write_sample,)},
    )
    y_array = CrtStartupArray(
        functions=[FunctionSet((200,), thunk=600)],
        fingerprints={200: (write_sample,)},
    )
    assert create_crt_matches(x_array, y_array) == [(100, 200), (500, 600)]


def test_create_match_group_with_elimination():
    """Can create a unique match for a function by eliminating the group
    that matched first on its second function."""
    write_sample = (1234, UsedHow.WRITE)
    read_sample = (5000, UsedHow.READ)
    # 100, 200, 300 and 400 all use `read_sample`, so none can match on the first pass.
    # `write_sample` is unique to 201 and 401. Matching them takes their groups with them.
    x_array = CrtStartupArray(
        functions=[FunctionSet((100,)), FunctionSet((200, 201))],
        fingerprints={100: (read_sample,), 200: (read_sample,), 201: (write_sample,)},
    )
    y_array = CrtStartupArray(
        functions=[FunctionSet((300,)), FunctionSet((400, 401))],
        fingerprints={300: (read_sample,), 400: (read_sample,), 401: (write_sample,)},
    )
    assert sorted(create_crt_matches(x_array, y_array)) == [
        (100, 300),
        (200, 400),
        (201, 401),
    ]


def test_create_match_no_match_within_one_array():
    write_sample = (1234, UsedHow.WRITE)
    read_sample = (5000, UsedHow.READ)
    x_array = CrtStartupArray(
        functions=[FunctionSet((100,)), FunctionSet((200,)), FunctionSet((300,))],
        fingerprints={100: (write_sample,), 200: (read_sample,), 300: (read_sample,)},
    )
    y_array = CrtStartupArray(
        functions=[FunctionSet((400,))],
        fingerprints={400: (write_sample, read_sample)},
    )
    assert create_crt_matches(x_array, y_array) == [(100, 400)]


def test_create_match_unique_pairs_removed_together():
    read_sample = (1000, UsedHow.READ)
    write_sample_a = (2000, UsedHow.WRITE)
    write_sample_b = (3000, UsedHow.WRITE)
    x_array = CrtStartupArray(
        functions=[FunctionSet((100,)), FunctionSet((300,))],
        fingerprints={
            100: (read_sample, write_sample_a),
            300: (read_sample, write_sample_b),
        },
    )
    y_array = CrtStartupArray(
        functions=[FunctionSet((200,)), FunctionSet((400,)), FunctionSet((500,))],
        fingerprints={
            200: (write_sample_a,),
            400: (read_sample,),
            500: (write_sample_b,),
        },
    )
    assert sorted(create_crt_matches(x_array, y_array)) == [(100, 200), (300, 500)]


def test_create_match_ambiguous_partner():
    write_sample_a = (2000, UsedHow.WRITE)
    write_sample_b = (3000, UsedHow.WRITE)
    x_array = CrtStartupArray(
        functions=[FunctionSet((100,))],
        fingerprints={100: (write_sample_a, write_sample_b)},
    )
    y_array = CrtStartupArray(
        functions=[FunctionSet((200,)), FunctionSet((400,))],
        fingerprints={200: (write_sample_a,), 400: (write_sample_b,)},
    )
    assert not create_crt_matches(x_array, y_array)


def test_collector_small_addrs_ignored():
    """Limit tested addresses to those large enough to be an EXE imagebase."""
    code = (
        b"\xc6\x05\x00\x00\x00\x00\x00"  # mov byte ptr [0x0], 0
        b"\xc6\x05\x00\x10\x00\x00\x00"  # mov byte ptr [0x1000], 0
        b"\xc6\x05\x00\x00\x40\x00\x00"  # mov byte ptr [0x400000], 0
        b"\xc6\x05\x00\x00\x00\x10\x00"  # mov byte ptr [0x10000000], 0
        b"\xc3"  # ret
    )

    collector = UsedAddressCollector(lambda _: True)
    collector.analyze(code, 0)

    assert collector.seen_addrs == [
        (0x400000, UsedHow.WRITE),
        (0x10000000, UsedHow.WRITE),
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

    collector = UsedAddressCollector(lambda _: True)
    collector.analyze(code, 0)

    assert collector.seen_addrs == [
        (0x400000, UsedHow.WRITE),
        (0x400000, UsedHow.WRITE),
        (0x400000, UsedHow.READ),
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

    collector = UsedAddressCollector(lambda _: True)
    collector.analyze(code, 0)

    assert collector.seen_addrs == [
        (0x401000, UsedHow.READ),
        (0x402000, UsedHow.READ),
        (0x403000, UsedHow.WRITE),
    ]


def test_collector_not_all_dst_operands_are_writes():
    code = (
        b"\x80\x3d\x00\x00\x40\x00\x00"  # cmp byte ptr [0x400000], 0x0
        b"\xf6\x05\x00\x00\x41\x00\x08"  # test byte ptr [0x410000], 0x8
        b"\xc3"  # ret
    )

    collector = UsedAddressCollector(lambda _: True)
    collector.analyze(code, 0)

    assert collector.seen_addrs == [
        (0x400000, UsedHow.READ),
        (0x410000, UsedHow.READ),
    ]


def test_collector_calls_and_jumps():
    """Jumps are ignored. Calls are collected as exec addresses."""
    code = (
        b"\xe8\xfb\x0f\x00\x00"  # call 0x401000
        b"\xe9\xf6\x1f\x00\x00"  # jmp 0x402000
        b"\xc3"  # ret
    )

    collector = UsedAddressCollector(lambda _: True)
    # Must set start addr here because CALLs and JMPs are relative.
    collector.analyze(code, 0x400000)

    assert collector.seen_addrs == [
        (0x401000, UsedHow.CALL),
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
    assert read_function_set(binfile, 0) == FunctionSet((0x10, jmp_dest), thunk=0)
    assert read_function_set(binfile, 0x10) == FunctionSet((0x10,))


def test_read_function_set_call_next_function_and_jmp():
    """Follows the two-instruction thunk when the called function begins
    immediately after the thunk instead of at the next 16-byte boundary."""
    memory = bytearray(128)
    memory[0:10] = b"\xe8\x05\x00\x00\x00\xe9\x16\x00\x00\x00"  # call 0xa, jmp 0x20
    memory[0xA] = 0xC3  # RET

    binfile = RawImage.from_memory(bytes(memory))
    assert read_function_set(binfile, 0) == FunctionSet((0xA, 0x20), thunk=0)


def test_read_function_set_jmp_only():
    """Follows the single-instruction thunk to the function at the next 16-byte boundary."""
    memory = bytearray(128)
    memory[0:5] = b"\xe9\x0b\x00\x00\x00"  # jmp 0x10
    memory[0x10] = 0xC3  # RET

    binfile = RawImage.from_memory(bytes(memory))
    assert read_function_set(binfile, 0) == FunctionSet((0x10,), thunk=0)
    assert read_function_set(binfile, 0x10) == FunctionSet((0x10,))


def test_read_function_set_jmp_to_next_function():
    """Follows the single-instruction thunk when the function begins
    immediately after the thunk instead of at the next 16-byte boundary."""
    memory = bytearray(128)
    memory[0:5] = b"\xe9\x00\x00\x00\x00"  # jmp 0x5
    memory[0x5] = 0xC3  # RET

    binfile = RawImage.from_memory(bytes(memory))
    assert read_function_set(binfile, 0) == FunctionSet((0x5,), thunk=0)


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
    assert read_function_set(binfile, 0x40) == FunctionSet((0x40,))


def test_read_function_set_jmp_must_be_ahead():
    """If the CALL+JMP thunk pattern is used, expect the second function to
    follow the first. We are not certain where it will be, but (for now)
    we require the jump displacement to be positive (i.e. we jump ahead)"""
    code = b"\xe8\x0b\x00\x00\x00\xe9\xf6\xff\xff\xff"  # call 0x50, jmp 0x40
    memory = bytearray(128)
    memory[0x40 : 0x40 + len(code)] = code

    binfile = RawImage.from_memory(bytes(memory))
    assert read_function_set(binfile, 0x40) == FunctionSet((0x40,))
