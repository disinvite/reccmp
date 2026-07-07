#!/usr/bin/env python3

import argparse
import enum
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
from reccmp.compare.db import EntityDb
from reccmp.formats.image import Image, ImageRegion
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
    extent: range
    seen: set[int]
    ip_queue: list[int]
    calls: list[int]
    last_addr: int

    def __init__(self, raw: bytes, base_addr: int):
        self.raw = raw
        self.base_addr = base_addr
        self.extent = range(base_addr, base_addr + len(raw))
        self.last_addr = base_addr
        self.decoder = Decoder(32, self.raw, ip=self.base_addr)
        self.ip_queue = [base_addr]
        self.calls = []

    def _jump_table(self, cache: list[Instruction]) -> None:
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

    def _walk(self) -> None:
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

    def run(self) -> range:
        self.seen = set()

        while self.ip_queue:
            addr = self.ip_queue.pop(0)

            if addr not in self.extent:
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


def get_regions(sect: ImageRegion) -> dict[int, BoundaryMark]:
    """Find regions that contain some number of functions that are separated by padding bytes."""
    output = {
        sect.addr: BoundaryMark.SEARCH_START,
        sect.addr + sect.size: BoundaryMark.SEARCH_END,
    }

    # Get the verified runs of padding bytes between functions.
    boundaries = find_padding_byte_boundaries(sect.data, sect.addr)

    # Turn these inside out to return the ranges of non-padding bytes.
    # These contain 1-to-N functions.
    for code_end, code_start in boundaries:
        output[code_end] = BoundaryMark.SEARCH_END
        output[code_start] = BoundaryMark.SEARCH_START

    return output


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


def find_seh_starts(raw: ConcreteBuffer, base_addr: int = 0) -> list[int]:
    """Returns offset into buffer: presumably this is the entire segment."""
    r_mov_eax_fs_0 = re.compile(b"\x64\xa1\x00\x00\x00\x00")
    return [base_addr + match.start() for match in r_mov_eax_fs_0.finditer(raw)]


def get_function_starts(
    db: EntityDb, image_id: ImageId, range_: range
) -> dict[int, BoundaryMark]:
    known_functions = {}

    for ent in db.all_in_range(image_id, range_):
        addr = ent.addr(image_id)
        assert addr is not None

        # name = ent.get("name")
        # if name and (
        #    "__Unwind" in name or "__ehhandler" in name or "__ehfuncinfo" in name
        # ):
        #    exclude_list.add(addr)

        if ent.get("type") == EntityType.FUNCTION:
            func_size = ent.size(image_id)
            if func_size:
                # size is at least 1 byte.
                known_functions[addr] = BoundaryMark.CONFIRMED_START
                known_functions[addr + func_size] = BoundaryMark.CONFIRMED_END
            else:
                known_functions[addr] = BoundaryMark.SEARCH_START

    return known_functions


def run(db: EntityDb, image_id: ImageId, binfile: Image):
    for sect in binfile.get_code_regions():
        search_regions = get_regions(sect)

        # TODO: check against known recomp size. Flag discrepancies
        # seh_starts = find_seh_starts(sect.data, sect.addr)

        known_functions = get_function_starts(db, image_id, sect.range)

        regions = list(add_known_boundaries(search_regions, known_functions))

        for region in regions:
            raw = binfile.read(region.start, len(region))

            start = region.start
            chunk = raw
            while chunk:
                found = FunctionWalker(chunk, start).run()
                if found.start == found.stop:
                    break  # TODO: shouldn't happen

                # Intended for CSV output:
                # is_seh_function = found.start in seh_starts
                # discovered_size = found.stop - found.start
                # ent = db.get(image_id, found.start)
                # if ent is None or ent.size(image_id) != discovered_size:
                #     actual_size = "no ent" if ent is None else (ent.size(image_id) or "no size")
                #     print(f"{found.start:08x},function,{discovered_size:8}    {actual_size:10}   {'seh' if is_seh_function else '':5}")

                end_offset = found.stop - region.start
                start = found.stop
                chunk = raw[end_offset:]

                # Remove any padding bytes
                match = re.match(rb"\x00+|\x90+|\xcc+", chunk)
                if match is not None:
                    start += match.end()
                    chunk = chunk[match.end() :]


def main():
    args = parse_args()
    try:
        target = argparse_parse_project_target(args=args)
    except RecCmpProjectException as e:
        logger.error(e.args[0])
        return 1

    compare = Compare.from_target(target)

    # pylint: disable=protected-access
    run(compare._db, ImageId.ORIG, compare.orig_bin)

    return False


if __name__ == "__main__":
    raise SystemExit(main())
