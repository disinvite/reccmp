import enum
import re
import struct
from dataclasses import dataclass, field
from functools import partial
from typing import Callable, Iterator
from typing_extensions import Buffer
from reccmp.compare.asm.const import JUMP_MNEMONICS
from reccmp.compare.asm.instgen import (
    InstructGen,
    SectionType,
)
from reccmp.formats import Image, PEImage
from reccmp.types import EntityType, ImageId
from reccmp.compare.db import EntityDb


class CrtStartupArrayType(enum.Enum):
    C_INIT = enum.auto()
    CPP_INIT = enum.auto()
    C_PRE_TERM = enum.auto()
    C_TERM = enum.auto()


_CRT_STARTUP_ARRAY_BOUNDARIES = {
    CrtStartupArrayType.C_INIT: ("___xi_a", "___xi_z"),
    CrtStartupArrayType.CPP_INIT: ("___xc_a", "___xc_z"),
    CrtStartupArrayType.C_PRE_TERM: ("___xp_a", "___xp_z"),
    CrtStartupArrayType.C_TERM: ("___xt_a", "___xt_z"),
}

_CRT_STARTUP_ARRAY_LABELS = [
    label for pair in _CRT_STARTUP_ARRAY_BOUNDARIES.values() for label in pair
]


_CRT_FUNCTION_NAMES = {
    CrtStartupArrayType.C_INIT: "$CRT_C_Initializer",
    CrtStartupArrayType.CPP_INIT: "$CRT_CPP_Initializer",
    CrtStartupArrayType.C_PRE_TERM: "$CRT_C_Pre-Terminator",
    CrtStartupArrayType.C_TERM: "$CRT_C_Terminator",
}


def get_crt_function_name(type_: CrtStartupArrayType) -> str:
    return _CRT_FUNCTION_NAMES[type_]


class UsedHow(enum.Enum):
    READ = enum.auto()
    WRITE = enum.auto()
    CALL = enum.auto()


UsedAddress = tuple[int, UsedHow]


@dataclass(frozen=True)
class FunctionSet:
    """The functions connected to a single entry in a CRT startup array.
    They match as a unit, so any one of them can match the others."""

    addrs: tuple[int, ...]
    """The functions we match by fingerprint, in the order we detected them.
    The thunk is excluded: it matches only after its group has matched."""

    thunk: int | None = None
    """The address that actually appeared in the array, if it is a thunk."""


@dataclass
class CrtStartupArray:
    """Result from analyzing functions in a CRT startup array.
    The functions within are called before main() is executed.
    For example: addresses of C++ initializer functions are between
    the labels ___xc_a and ___xc_z."""

    functions: list[FunctionSet] = field(default_factory=list)
    """One entry per address in the array, with any thunk unwrapped."""

    fingerprints: dict[int, tuple[UsedAddress, ...]] = field(default_factory=dict)
    """Maps function address -> (sorted) list of matched entities used in
    the function, normalized to orig address space. These fingerprints are
    used to match initializer functions in orig and recomp."""


ADDR_REGEX = re.compile(r"0x[0-9a-f]{6,8}")


class UsedAddressCollector:
    seen_addrs: list[UsedAddress]
    """List of addrs that would be replaced by a name or placeholder."""

    is_entity: Callable[[int], bool]
    """Test whether the address is a known entity in the database."""

    def __init__(self, is_entity: Callable[[int], bool]) -> None:
        self.is_entity = is_entity
        self.seen_addrs = []

    def _append_addrs(self, text: str, used_how: UsedHow):
        for hex_str in ADDR_REGEX.findall(text):
            addr = int(hex_str, 16)
            if self.is_entity(addr):
                self.seen_addrs.append((addr, used_how))

    def analyze(self, data: Buffer, start_addr: int):
        ig = InstructGen(bytes(data), start_addr, True)

        for section in ig.sections:
            if section.type == SectionType.CODE:
                for inst in section.contents:
                    inst_mnemonic, inst_op_str = inst[2:]
                    if inst_mnemonic == "ret":
                        break

                    if inst_mnemonic in JUMP_MNEMONICS:
                        continue

                    if inst_mnemonic in ("call",):
                        self._append_addrs(inst_op_str, UsedHow.CALL)
                        # self._append_addrs(inst_op_str, UsedHow.READ)
                    elif inst_mnemonic in ("mov", "fstp"):
                        dst_operand, _, src_operand = inst_op_str.partition(", ")
                        self._append_addrs(dst_operand, UsedHow.WRITE)
                        self._append_addrs(src_operand, UsedHow.READ)
                    else:
                        self._append_addrs(inst_op_str, UsedHow.READ)


def get_function_sample_size(db: EntityDb, image_id: ImageId, addr: int) -> int:
    """How many bytes should we read to sample the addresses used in the function?
    Use exact size if we have it, or any size estimate available."""
    ent = db.get(image_id, addr)
    if ent is not None:
        size = ent.size(image_id)
        if size is not None:
            return size

        max_size = db.get_max_size(image_id, addr)
        if max_size:
            return max_size

    # Arbitrary value with the intent of overshooting the function's actual size
    # and then correcting during disassembly.
    return 1000


def get_function_fingerprint(
    db: EntityDb, image_id: ImageId, binfile: Image, addr: int
) -> tuple[UsedAddress, ...]:
    """Create lists of addresses used by this function and the way they are used.
    Filter the addresses that point to a matched variable or function entity.
    These two lists of identifying characteristics about the function
    are the "fingerprint" we can use for matching."""
    size = get_function_sample_size(db, image_id, addr)
    raw = binfile.read(addr, size)

    collector = UsedAddressCollector(partial(db.exists, image_id))
    collector.analyze(raw, addr)

    normalized_addrs = []
    for sample_addr, used_how in collector.seen_addrs:
        ent = db.get(image_id, sample_addr)
        # Only matched entities are candidates for the fingerprint
        # because we have an address in both address spaces.
        if (
            ent
            and ent.matched
            and ent.get("type") in (EntityType.FUNCTION, EntityType.DATA)
        ):
            normalized_addr = ent.addr(ImageId.ORIG)
            assert isinstance(normalized_addr, int)
            normalized_addrs.append((normalized_addr, used_how))

    return tuple(normalized_addrs)


def read_crt_array(binfile: PEImage, span: range) -> Iterator[int]:
    """Read 4-byte (dword) pointers from the specified range.
    Excludes the first element, a zero."""
    try:
        for (addr,) in struct.iter_unpack("<I", binfile.read(span.start, len(span))):
            if addr != 0:
                yield addr
    except struct.error:
        # Don't crash on bad user input: the start or end addrs are incorrect
        pass


def find_crt_startup_labels(db: EntityDb, image_id: ImageId) -> dict[str, int]:
    found = {}

    for ent in db.all(image_id):
        name = ent.get("name")
        if name is not None and name in _CRT_STARTUP_ARRAY_LABELS:
            addr = ent.addr(image_id)
            assert isinstance(addr, int)
            found[name] = addr

            if len(found) == len(_CRT_STARTUP_ARRAY_LABELS):
                break

    return found


JMP_THUNKS = {b"\xe9\x00\x00\x00\x00", b"\xe9\x0b\x00\x00\x00"}
"""Observed thunk patterns for C++ init: jump to a single function, located
either directly after the thunk or at the next 16-byte boundary."""

CALL_JMP_THUNKS = {b"\xe8\x05\x00\x00\x00\xe9", b"\xe8\x0b\x00\x00\x00\xe9"}
"""Observed thunk patterns for C++ init: call the first function, then jump to
the second. The position of the second function depends on the size of the first,
so its displacement is not part of the pattern."""


def read_function_set(binfile: Image, addr: int) -> FunctionSet:
    """Read enough of the CRT startup function at `addr` to tell if it is a thunk.
    In MSVC binaries, we have observed C++ initializer functions acting as thunks for
    one or two other functions. If there are two (CALL + JMP pattern), the second
    function sets the destructor using atexit(). If a similar pattern appears in
    other kinds of startup functions, we will detect it here."""
    data = binfile.read(addr, 10)
    first, second = struct.unpack("<xixi", data)

    if data[:5] in JMP_THUNKS:
        return FunctionSet((addr + 5 + first,), thunk=addr)

    # The jmp to the second function is the only displacement that varies. It always goes forward.
    if data[:6] in CALL_JMP_THUNKS and second >= 0:
        return FunctionSet((addr + 5 + first, addr + 10 + second), thunk=addr)

    return FunctionSet((addr,))


def read_crt_functions(binfile: PEImage, span: range) -> CrtStartupArray:
    """Create the CRT array structure using the given range of addresses.
    For each function in the array that matches a known thunk pattern,
    "unwrap" the indirection so we can search the most likely place for
    the instruction that sets the variable."""
    # n.b. The first value in the array is zero. It was excluded by read_crt_array.
    return CrtStartupArray(
        [read_function_set(binfile, addr) for addr in read_crt_array(binfile, span)]
    )


def fingerprint_crt_functions(
    db: EntityDb, image_id: ImageId, binfile: PEImage, array: CrtStartupArray
):
    """Update the CRT array structure so that the detected functions have a characteristic
    set of addresses (the "fingerprint") read or written to by their instructions."""
    for group in array.functions:
        for addr in group.addrs:
            array.fingerprints[addr] = get_function_fingerprint(
                db, image_id, binfile, addr
            )


def iter_crt_array_ranges(
    db: EntityDb, image_id: ImageId
) -> Iterator[tuple[CrtStartupArrayType, range]]:
    """For each CRT array whose start and end labels are known, return the array type and address range."""
    labels = find_crt_startup_labels(db, image_id)
    for array_type, (label_start, label_end) in _CRT_STARTUP_ARRAY_BOUNDARIES.items():
        if label_start in labels and label_end in labels:
            array_range = range(labels[label_start], labels[label_end])
            yield (array_type, array_range)


def detect_crt_startup_arrays(
    db: EntityDb, image_id: ImageId, binfile: PEImage
) -> dict[CrtStartupArrayType, CrtStartupArray]:
    """Return a map of CRT startup array types to each list of functions."""
    return {
        array_type: read_crt_functions(binfile, array_range)
        for array_type, array_range in iter_crt_array_ranges(db, image_id)
    }


FunctionSetIndex = dict[UsedAddress, set[tuple[ImageId, FunctionSet]]]
"""FunctionSet must be hashable to use in the set."""


def _add_to_function_set_index(
    function_set_index: FunctionSetIndex, image_id: ImageId, array: CrtStartupArray
):
    """Add each sample from the array to the index, mapped to the function sets that use it.
    Sampled addresses are already normalized to the original binary address space."""
    for group in array.functions:
        # Samples from all functions in the set are combined here.
        for func_addr in group.addrs:
            for sample in array.fingerprints.get(func_addr, ()):
                function_set_index.setdefault(sample, set()).add((image_id, group))


def _find_unique_pair(
    function_set_index: FunctionSetIndex,
) -> tuple[FunctionSet, FunctionSet] | None:
    """Return the (orig, recomp) function sets that share a sample used exactly
    once in each array, or None if there are none. The samples are distinguished
    by how they are used: a READ is different from a WRITE to the same address."""
    for func_groups in function_set_index.values():
        if len(func_groups) == 2:
            [(img_x, group_x), (img_y, group_y)] = func_groups
            if img_x != img_y:
                # These are sets, so order is not guaranteed.
                if img_x == ImageId.ORIG:
                    return (group_x, group_y)
                return (group_y, group_x)
    return None


def create_crt_matches(
    orig_array: CrtStartupArray, recomp_array: CrtStartupArray
) -> list[tuple[int, int]]:
    """Return a list of matched pairs for functions from the CRT startup array.
    Matches are created using the combination of sampled addresses and how they
    are used (fingerprint). We can create a match if the sample is used only once
    in each array, eliminating matched functions from the pool until no new matches
    can be created.

    If the address in the CRT startup array points to a thunk, the samples for all
    thunked functions are pooled together. In the case of the C++ init functions,
    the only case where we have observed a thunk so far, the thunked functions serve
    different purposes, so it seems unlikely that pooling the samples could cause a
    mismatch."""

    function_set_index: FunctionSetIndex = {}
    _add_to_function_set_index(function_set_index, ImageId.ORIG, orig_array)
    _add_to_function_set_index(function_set_index, ImageId.RECOMP, recomp_array)

    matches: list[tuple[int, int]] = []
    thunks: list[tuple[int, int]] = []

    while (pair := _find_unique_pair(function_set_index)) is not None:
        orig_group, recomp_group = pair
        # Match the functions in the order we detected them.
        # zip stops at the shorter group.
        matches.extend(zip(orig_group.addrs, recomp_group.addrs))
        # Add the thunks last, after all functions are matched.
        if orig_group.thunk is not None and recomp_group.thunk is not None:
            thunks.append((orig_group.thunk, recomp_group.thunk))

        # Remove the matched sets so their samples can't match again.
        matched = {(ImageId.ORIG, orig_group), (ImageId.RECOMP, recomp_group)}
        for func_groups in function_set_index.values():
            func_groups -= matched

    matches.extend(thunks)
    return matches
