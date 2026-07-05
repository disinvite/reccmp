#!/usr/bin/env python3

import argparse
import enum
import itertools
import logging
import struct
import re
from typing import Iterable, Iterator
from iced_x86 import (
    Decoder,
    Instruction,
    OpKind,
    Mnemonic,
    Register,
    RegisterInfo,
)
from reccmp.compare import Compare
from reccmp.formats import Image
from reccmp.compare.asm.const import ICED_MNEMONIC_JUMPS, ICED_IMMEDIATE_OPKINDS
from reccmp.types import ConcreteBuffer, EntityType, ImageId
from reccmp.project.detect import (
    RecCmpProjectException,
    argparse_add_project_target_args,
    argparse_parse_project_target,
)

# Ignore all compare-db messages.
logging.getLogger("reccmp.compare").addHandler(logging.NullHandler())

logger = logging.getLogger()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="folded")
    argparse_add_project_target_args(parser)
    return parser.parse_args()


class WalkerItem(enum.Enum):
    START = enum.auto()
    INSTRUCTION = enum.auto()
    CALL = enum.auto()
    JUMP = enum.auto()
    JUMP_SWITCH = enum.auto()
    SWITCH_CASE = enum.auto()
    END = enum.auto()


class FunctionWalker:
    # pylint: disable=too-many-instance-attributes
    raw: bytes
    base_addr: int
    decoder: Decoder
    range: range
    seen: set[int]
    ip_queue: list[int]
    calls: list[int]
    last_addr: int

    def __init__(self, raw: bytes, base_addr: int):
        self.raw = raw
        self.base_addr = base_addr
        self.range = range(base_addr, base_addr + len(raw))
        self.last_addr = base_addr
        self.decoder = Decoder(32, self.raw, ip=self.base_addr)
        self.ip_queue = [base_addr]
        self.calls = []

    def _jump_table(self, cache: list[Instruction]):
        """We have hit a jump table. (Jump displacement instruction).
        Walk backwards through the previous instructions looking for:
        1. A data table, if present (1-byte indices into jump table)
        2. A JA instruction (branch if index register is beyond table size)
        3. A CMP instruction on the index register (establish table size)
        """
        jump_inst = cache[-1]
        jump_table_addr = jump_inst.memory_displacement
        jump_disp_reg = jump_inst.memory_index

        ja_found = False

        mov_register = Register.NONE

        table_size = 0
        data_table_addr = 0

        for inst in cache[::-1][1:]:
            if inst.mnemonic == Mnemonic.JA:
                ja_found = True

            if inst.mnemonic == Mnemonic.MOV and inst.op_count == 2:
                if inst.op0_kind == OpKind.REGISTER and inst.op1_kind == OpKind.MEMORY:
                    # meh
                    if (
                        RegisterInfo(inst.op0_register).number
                        == RegisterInfo(jump_disp_reg).number
                    ):
                        data_table_addr = inst.memory_displacement
                        jump_disp_reg = inst.memory_base

                elif (
                    inst.op0_kind == OpKind.REGISTER
                    and inst.op1_kind in ICED_IMMEDIATE_OPKINDS
                ):
                    if (
                        RegisterInfo(inst.op0_register).number
                        == RegisterInfo(mov_register).number
                    ):
                        table_size = inst.immediate(1) + 1
                        break

            if inst.mnemonic == Mnemonic.CMP and inst.op_count == 2:
                if inst.op0_register == jump_disp_reg:
                    if inst.op1_kind in ICED_IMMEDIATE_OPKINDS:
                        table_size = inst.immediate(1) + 1
                        break

                    if inst.op1_kind == OpKind.REGISTER:
                        mov_register = inst.op1_register

        if not ja_found:
            return

        if data_table_addr > 0 and table_size > 0:
            self.last_addr = max(self.last_addr, data_table_addr + table_size)
            data_table_raw = self.raw[data_table_addr - self.base_addr :][:table_size]
            table_size = max(list(data_table_raw))

        if table_size > 0:
            self.last_addr = max(self.last_addr, jump_table_addr + (table_size * 4))
            jump_table_raw = self.raw[jump_table_addr - self.base_addr :][
                : table_size * 4
            ]
            # jump_table_offset = jump_table_addr - self.base_addr
            for (dword,) in struct.iter_unpack("<I", jump_table_raw):
                self.ip_queue.append(dword)

    def _walk(self):
        cache = []
        inst = None  # meh

        for inst in self.decoder:
            # We have already seen this instruction.
            # The rest would be redundant.
            if inst.ip in self.seen:
                break

            self.seen.add(inst.ip)
            cache.append(inst)

            if inst.mnemonic in (Mnemonic.RET, Mnemonic.RETF):
                break

            if inst.op_count == 1:
                if (
                    inst.mnemonic == Mnemonic.CALL
                    and inst.op0_kind == OpKind.NEAR_BRANCH32
                ):
                    self.calls.append(inst.near_branch_target)

                elif inst.mnemonic == Mnemonic.JMP and inst.op0_kind == OpKind.MEMORY:
                    if inst.memory_displ_size == 4:
                        self._jump_table(cache)

                elif (
                    inst.mnemonic in ICED_MNEMONIC_JUMPS
                    and inst.op0_kind == OpKind.NEAR_BRANCH32
                ):
                    self.ip_queue.append(inst.near_branch_target)
                    # Stops on JMP. This may be the end of the function
                    # or the last instruction before an inline jump table.

            if inst.mnemonic == Mnemonic.JMP:
                break

        if inst:
            self.last_addr = max(self.last_addr, inst.ip + inst.len)

    def run(self):
        self.seen = set()

        while self.ip_queue:
            addr = self.ip_queue.pop(0)

            if addr not in self.range:
                continue

            self.decoder.ip = addr
            self.decoder.position = addr - self.base_addr

            self._walk()

        return range(self.base_addr, self.last_addr)


def find_padding_byte_boundaries(
    raw: ConcreteBuffer, base_addr: int
) -> Iterator[range]:
    """Find runs of padding chars that end on a 16-byte boundary.
    Using a conservative estimate of at least 5 consecutive padding bytes.
    The idea is that we want to exclude the (probably unlikely) occurrence
    of 4 consecutive bytes being used as an immediate value."""
    for match in re.finditer(rb"\x90{5,}|\xcc{5,}", raw):
        if match.end() % 16 == 0:
            yield range(base_addr + match.start(), base_addr + match.end())


def get_regions(image: Image) -> Iterator[range]:
    """Find regions that contain some number of functions that are separated by padding bytes."""
    for sect in image.get_code_regions():
        # Get the verified runs of padding bytes between functions.
        boundaries = list(find_padding_byte_boundaries(sect.data, sect.addr))

        # Turn these inside out to return the ranges of non-padding bytes.
        # These contain 1-to-N functions.
        yield range(sect.addr, boundaries[0].start)

        for range_a, range_b in itertools.pairwise(boundaries):
            yield range(range_a.stop, range_b.start)

        yield range(boundaries[-1].stop, sect.addr + sect.size)

        # TODO: needs to be done per-section
        break


def add_known_boundaries(ranges: Iterable[range], splits: list[int]) -> Iterator[range]:
    # Safety
    sorted_ranges = sorted(ranges, key=lambda r: r.start)
    sorted_splits = sorted(splits)

    # combined = []
    # combined.extend((0, r) for r in ranges)
    # combined.extend((1, s) for s in splits)

    while sorted_ranges:
        range_ = sorted_ranges.pop(0)

        # Burn any too early ones
        while sorted_splits and sorted_splits[0] < range_.start:
            sorted_splits.pop(0)

        collect = {range_.start}

        while sorted_splits and sorted_splits[0] in range_:
            collect.add(sorted_splits.pop(0))

        collect.add(range_.stop)

        for p_x, p_y in itertools.pairwise(sorted(collect)):
            yield range(p_x, p_y)


def region_contains_seh(raw: bytes) -> bool:
    """Looking for the characteristic `mov eax, fs:[0]` instruction."""
    return b"\x64\xa1\x00\x00\x00\x00" in raw


def region_contains_switch(raw: bytes) -> bool:
    """Matching a variety of destination registers."""
    return re.search(rb"\xff\x24.(.{4})", raw) is not None


def main():
    # pylint: disable=too-many-locals
    args = parse_args()
    try:
        target = argparse_parse_project_target(args=args)
    except RecCmpProjectException as e:
        logger.error(e.args[0])
        return 1

    compare = Compare.from_target(target)
    padded_regions = get_regions(compare.orig_bin)

    ##
    known_functions = []
    exclude_list = set()

    # pylint: disable=protected-access
    for ent in compare._db.all(ImageId.ORIG):
        addr = ent.addr(ImageId.ORIG)
        assert addr is not None

        name = ent.get("name")
        if name and (
            "__Unwind" in name or "__ehhandler" in name or "__ehfuncinfo" in name
        ):
            exclude_list.add(addr)

        elif ent.get("type") == EntityType.FUNCTION:
            known_functions.append(addr)

    ##

    regions: list[range] = list(add_known_boundaries(padded_regions, known_functions))

    for region in regions:
        raw = compare.orig_bin.read(region.start, len(region))
        has_seh = region_contains_seh(raw)
        has_switch = region_contains_switch(raw)

        flags = []
        if has_seh:
            flags.append("seh")
        if has_switch:
            flags.append("switch")

        start = region.start
        chunk = raw
        while chunk:
            found = FunctionWalker(chunk, start).run()
            # print(f"{found.start:08x} -> {found.stop:08x}")

            if found.start not in exclude_list:
                print(f"{found.start:08x},function,{found.stop - found.start}")

            end_offset = found.stop - region.start
            start = found.stop
            chunk = raw[end_offset:]

            # Remove any padding bytes
            match = re.match(rb"\x00+|\x90+|\xcc+", chunk)
            if match is not None:
                start += match.end()
                chunk = chunk[match.end() :]

            # print(f"{region.start:08x} -> {region.stop:08x} " + str(flags) if flags else "")

        # break

    return False


if __name__ == "__main__":
    raise SystemExit(main())
