import enum
import re
import struct
from collections import Counter
from dataclasses import dataclass, field
from functools import partial
from typing import Callable, Iterator, Mapping
from typing_extensions import Buffer
from reccmp.compare.asm.const import JUMP_MNEMONICS
from reccmp.compare.asm.instgen import (
    InstructGen,
    SectionType,
)
from reccmp.formats import Image
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


class RefType(enum.Enum):
    READ = enum.auto()
    WRITE = enum.auto()
    CALL = enum.auto()


Xref = tuple[int, RefType]


FunctionXrefMap = Mapping[int, tuple[Xref, ...]]


@dataclass
class CrtStartupArray:
    """Result from analyzing functions in a CRT startup array.
    The functions within are called before main() is executed.
    For example: addresses of C++ initializer functions are between
    the labels ___xc_a and ___xc_z."""

    entries: list[int] = field(default_factory=list)
    """The addresses in the array."""

    function_set: dict[int, tuple[int, ...]] = field(default_factory=dict)
    """Maps entry -> the functions it calls or jumps to, for entries that are thunks."""

    xrefs: FunctionXrefMap = field(default_factory=dict)
    """Maps entry -> matched entities used by its function, normalized to
    orig address space. For a thunk, the xrefs of all thunked functions
    are combined. Entries with no xrefs are left out because they cannot be matched.
    These xrefs are used to match initializer functions in orig and recomp."""


ADDR_REGEX = re.compile(r"0x[0-9a-f]{6,8}")


class XrefCollector:
    seen_addrs: list[Xref]
    """List of addrs that would be replaced by a name or placeholder."""

    is_entity: Callable[[int], bool]
    """Test whether the address is a known entity in the database."""

    def __init__(self, is_entity: Callable[[int], bool]) -> None:
        self.is_entity = is_entity
        self.seen_addrs = []

    def _append_addrs(self, text: str, ref_type: RefType):
        for hex_str in ADDR_REGEX.findall(text):
            addr = int(hex_str, 16)
            if self.is_entity(addr):
                self.seen_addrs.append((addr, ref_type))

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
                        self._append_addrs(inst_op_str, RefType.CALL)
                        # self._append_addrs(inst_op_str, RefType.READ)
                    elif inst_mnemonic in ("mov", "fstp"):
                        dst_operand, _, src_operand = inst_op_str.partition(", ")
                        self._append_addrs(dst_operand, RefType.WRITE)
                        self._append_addrs(src_operand, RefType.READ)
                    else:
                        self._append_addrs(inst_op_str, RefType.READ)


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


def get_function_xrefs(
    db: EntityDb, image_id: ImageId, binfile: Image, addr: int
) -> tuple[Xref, ...]:
    """Create lists of addresses used by this function and the way they are used.
    Filter the addresses that point to a matched variable or function entity.
    These are the xrefs we use for matching."""
    size = get_function_sample_size(db, image_id, addr)
    raw = binfile.read(addr, size)

    collector = XrefCollector(partial(db.exists, image_id))
    collector.analyze(raw, addr)

    normalized_addrs = []
    for xref_addr, ref_type in collector.seen_addrs:
        ent = db.get(image_id, xref_addr)
        # Only matched entities can be xrefs
        # because we have an address in both address spaces.
        if (
            ent
            and ent.matched
            and ent.get("type") in (EntityType.FUNCTION, EntityType.DATA)
        ):
            normalized_addr = ent.addr(ImageId.ORIG)
            assert isinstance(normalized_addr, int)
            normalized_addrs.append((normalized_addr, ref_type))

    return tuple(normalized_addrs)


def read_crt_array(binfile: Image, span: range) -> Iterator[int]:
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


def read_function_set(binfile: Image, addr: int) -> tuple[int, ...]:
    """For the given address of a function in a CRT startup array, return the list of
    connected functions that follow specific patterns. For example, in the C++ initializer
    array, we have observed two thunk patterns that point to:
    1. JMP only:    Initializer function
    2. CALL + JMP:  Initializer function, atexit destructor setter function"""
    data = binfile.read(addr, 10)
    first_disp, second_disp = struct.unpack("<xixi", data)

    if data[:5] in JMP_THUNKS:
        return (addr + 5 + first_disp,)

    # In the CALL + JMP pattern, we cannot predict the JMP operand value because
    # the displacement depends on the size of the function in the CALL instruction.
    # However, the trend is that the three functions are in sequence, so allow
    # a forward jump only.
    if data[:6] in CALL_JMP_THUNKS and second_disp >= 0:
        return (addr + 5 + first_disp, addr + 10 + second_disp)

    return ()


def read_crt_functions(binfile: Image, span: range) -> CrtStartupArray:
    """Create the CRT array structure using the given range of addresses.
    For each function in the array that matches a known thunk pattern,
    "unwrap" the indirection so we can search the most likely place for
    the instruction that sets the variable."""
    array = CrtStartupArray()
    # n.b. The first value in the array is zero. It was excluded by read_crt_array.
    for addr in read_crt_array(binfile, span):
        array.entries.append(addr)
        thunked = read_function_set(binfile, addr)
        if thunked:
            array.function_set[addr] = thunked

    return array


def collect_crt_xrefs(
    db: EntityDb, image_id: ImageId, binfile: Image, array: CrtStartupArray
):
    """Update the CRT array structure with the xrefs of each detected function:
    the matched addresses its instructions read, write or call."""
    xrefs: dict[int, tuple[Xref, ...]] = {}
    for entry in array.entries:
        entry_xrefs = tuple(
            xref
            for addr in array.function_set.get(entry, (entry,))
            for xref in get_function_xrefs(db, image_id, binfile, addr)
        )
        if entry_xrefs:
            xrefs[entry] = entry_xrefs

    array.xrefs = xrefs


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
    db: EntityDb, image_id: ImageId, binfile: Image
) -> dict[CrtStartupArrayType, CrtStartupArray]:
    """Return a map of CRT startup array types to each list of functions."""
    return {
        array_type: read_crt_functions(binfile, array_range)
        for array_type, array_range in iter_crt_array_ranges(db, image_id)
    }


def _index_xrefs(
    entry_to_xref_map: FunctionXrefMap,
) -> dict[Xref, set[int]]:
    """Invert the input that maps each CRT array entry to xrefs collected from the function set.
    Return a mapping of xrefs that point to each array entry where the xref was seen.
    """
    index: dict[Xref, set[int]] = {}
    for entry, xrefs in entry_to_xref_map.items():
        for xref in xrefs:
            index.setdefault(xref, set()).add(entry)

    return index


def _find_unique_pairs(pairs: set[tuple[int, int]]) -> set[tuple[int, int]]:
    """Return (orig, recomp) pairs where orig and recomp are each used only once."""
    orig_count = Counter(orig for orig, _ in pairs)
    recomp_count = Counter(recomp for _, recomp in pairs)
    return {
        (orig, recomp)
        for orig, recomp in pairs
        if orig_count[orig] == 1 and recomp_count[recomp] == 1
    }


def expand_entry_matches(
    orig_array: CrtStartupArray,
    recomp_array: CrtStartupArray,
    pairs: list[tuple[int, int]],
) -> list[tuple[int, int]]:
    """Turn matched pairs of entries into matched pairs of functions.
    The thunks themselves are matched only if both entries are thunks."""
    matches: list[tuple[int, int]] = []
    for orig_entry, recomp_entry in pairs:
        orig_thunked = orig_array.function_set.get(orig_entry)
        recomp_thunked = recomp_array.function_set.get(recomp_entry)
        # zip stops at the shorter group.
        matches.extend(
            zip(orig_thunked or (orig_entry,), recomp_thunked or (recomp_entry,))
        )
        if orig_thunked and recomp_thunked:
            matches.append((orig_entry, recomp_entry))

    return matches


def create_crt_matches(
    orig_xrefs: FunctionXrefMap,
    recomp_xrefs: FunctionXrefMap,
) -> list[tuple[int, int]]:
    """Match entries from two CRT startup arrays using xrefs.

    In each pass, find "unique" xrefs that connect exactly one entry from each array.
    Add these connected pairs to a set. Extract pairs from the set where each entry
    appears only once: the entries can only connect to each other.
    These pairs become matches.
    Delete edges that connect a newly matched entry to its xrefs.
    Repeat until there are no new matches.
    """

    # The input maps contain edges from each entry to its xrefs.
    # Build the reverse edge list of xrefs to entries.
    orig_index = _index_xrefs(orig_xrefs)
    recomp_index = _index_xrefs(recomp_xrefs)

    # Candidate xrefs that can connect two entries.
    # To start, restrict to xrefs that appear in both arrays.
    # After each pass, this set will contain only xrefs that became unique
    # in at least one array after deleting edges to matched array entries.
    candidates = orig_index.keys() & recomp_index.keys()

    # Pairs of entries connected via a unique xref.
    # The set retains the "unresolvable" pairs where an entry points to more than
    # one unique xref. This prevents future matches using those entries.
    connections: set[tuple[int, int]] = set()

    # Output list.
    matches: list[tuple[int, int]] = []

    while True:
        for xref in candidates:
            # Use `get()` here because deleting edges may have dropped
            # the xref from one of the arrays.
            orig_entries = orig_index.get(xref, ())
            recomp_entries = recomp_index.get(xref, ())
            # If the xref is unique in both arrays:
            if len(orig_entries) == 1 and len(recomp_entries) == 1:
                (orig_entry,) = orig_entries
                (recomp_entry,) = recomp_entries
                connections.add((orig_entry, recomp_entry))

        # Pairings on unique xrefs where orig and recomp can only pair
        # to each other are upgraded to matches.
        new_matches = _find_unique_pairs(connections)
        if not new_matches:
            return matches

        matches.extend(new_matches)
        # Remove newly matched pairs from the set, so it now contains only
        # pairings where one or both entries have multiple options.
        connections -= new_matches

        # For each newly matched entry, delete the edges that connect the
        # entry to its xrefs. If this results in any xrefs that point to exactly
        # one orig or recomp entry, we will try to create pairs on the next pass.
        candidates = set()
        for orig_entry, recomp_entry in new_matches:
            for xrefs_by_entry, index, matched_entry in (
                (orig_xrefs, orig_index, orig_entry),
                (recomp_xrefs, recomp_index, recomp_entry),
            ):
                for xref in xrefs_by_entry[matched_entry]:
                    entries = index[xref]
                    entries.discard(matched_entry)
                    # If the xref is now used by only one entry in the array:
                    if len(entries) == 1:
                        candidates.add(xref)
