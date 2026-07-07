#!/usr/bin/env python3

import argparse
import enum
import itertools
import logging
import struct
import re
from typing import Iterator
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
) -> list[tuple[int, int]]:
    """Find runs of padding chars that end on a 16-byte boundary.
    Using a conservative estimate of at least 5 consecutive padding bytes.
    The idea is that we want to exclude the (probably unlikely) occurrence
    of 4 consecutive bytes being used as an immediate value."""
    output = []

    for match in re.finditer(rb"\x90{5,}|\xcc{5,}", raw):
        start, end = match.span()
        if end % 16 == 0:
            output.append((base_addr + start, base_addr + end))

    return output


class BoundaryMark(enum.Enum):
    CONFIRMED_START = enum.auto()
    CONFIRMED_END = enum.auto()
    SEARCH_START = enum.auto()
    SEARCH_END = enum.auto()


def get_regions(image: Image) -> dict[int, BoundaryMark]:
    """Find regions that contain some number of functions that are separated by padding bytes."""
    output = {}

    for sect in image.get_code_regions():
        # Get the verified runs of padding bytes between functions.
        boundaries = find_padding_byte_boundaries(sect.data, sect.addr)

        # Turn these inside out to return the ranges of non-padding bytes.
        # These contain 1-to-N functions.

        first_padding_start, _ = boundaries[0]
        output[sect.addr] = BoundaryMark.SEARCH_START
        output[first_padding_start] = BoundaryMark.SEARCH_END

        for (_, x_pad_stop), (y_pad_start, _) in itertools.pairwise(boundaries):
            output[x_pad_stop] = BoundaryMark.SEARCH_START
            output[y_pad_start] = BoundaryMark.SEARCH_END

        _, last_padding_stop = boundaries[-1]
        output[last_padding_stop] = BoundaryMark.SEARCH_START
        output[sect.addr + sect.size] = BoundaryMark.SEARCH_END

        # TODO: needs to be done per-section.
        # Meaning: pass the ImageSection as the argument, not the entire Image.
        break

    return {}


def add_known_boundaries(
    padded_marks: dict[int, BoundaryMark], confirmed_marks: dict[int, BoundaryMark]
) -> Iterator[range]:
    # Overwrite padding marks with confirmed marks. We want only one mark per address.
    combined = {}
    combined.update(padded_marks)
    combined.update(confirmed_marks)

    marks = list(combined.items())
    marks.sort()

    last_addr = None
    last_mark = None
    for addr, mark in marks:
        if last_mark is None or last_addr is None:
            if mark in (BoundaryMark.SEARCH_START, BoundaryMark.CONFIRMED_START):
                last_addr = addr
                last_mark = mark
        elif last_mark == BoundaryMark.CONFIRMED_START:
            if mark == BoundaryMark.CONFIRMED_START:
                yield range(last_addr, addr)
                last_addr = addr
                last_mark = mark
            elif mark == BoundaryMark.CONFIRMED_END:
                yield range(last_addr, addr)
                last_addr = None
                last_mark = None
        else:
            yield range(last_addr, addr)
            if mark in (BoundaryMark.SEARCH_START, BoundaryMark.CONFIRMED_START):
                last_addr = addr
                last_mark = mark
            else:
                last_addr = None
                last_mark = None


def find_seh_starts(raw: ConcreteBuffer) -> list[int]:
    """Returns offset into buffer: presumably this is the entire segment."""
    r_mov_eax_fs_0 = re.compile(b"\x64\xa1\x00\x00\x00\x00")
    return [match.start() for match in r_mov_eax_fs_0.finditer(raw)]


def main():
    # pylint: disable=too-many-locals
    args = parse_args()
    try:
        target = argparse_parse_project_target(args=args)
    except RecCmpProjectException as e:
        logger.error(e.args[0])
        return 1

    compare = Compare.from_target(target)
    search_regions = get_regions(compare.orig_bin)

    ##
    known_functions: dict[int, BoundaryMark] = {}
    exclude_list = set()

    image_id = ImageId.ORIG
    # pylint: disable=protected-access
    for ent in compare._db.all(image_id):
        addr = ent.addr(image_id)
        assert addr is not None

        name = ent.get("name")
        if name and (
            "__Unwind" in name or "__ehhandler" in name or "__ehfuncinfo" in name
        ):
            exclude_list.add(addr)

        elif ent.get("type") == EntityType.FUNCTION:
            func_size = ent.size(image_id)
            if func_size:
                # size is at least 1 byte.
                known_functions[addr] = BoundaryMark.CONFIRMED_START
                known_functions[addr + func_size] = BoundaryMark.CONFIRMED_END
            else:
                known_functions[addr] = BoundaryMark.SEARCH_START

    ##

    regions = list(add_known_boundaries(search_regions, known_functions))

    for region in regions:
        raw = compare.orig_bin.read(region.start, len(region))

        start = region.start
        chunk = raw
        while chunk:
            found = FunctionWalker(chunk, start).run()
            # print(f"{found.start:08x} -> {found.stop:08x}")

            # No text output.
            # if found.start not in exclude_list:
            #     print(f"{found.start:08x},function,{found.stop - found.start}")

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
