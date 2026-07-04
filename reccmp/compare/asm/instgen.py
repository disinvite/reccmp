"""Pre-parser for x86 instructions. Will identify data/jump tables used with
switch statements and local jump/call destinations."""

import bisect
import struct
from enum import Enum, auto
from typing import Literal, NamedTuple
from iced_x86 import (
    Decoder,
    Formatter,
    FormatterSyntax,
    Instruction,
    MemorySizeOptions,
    OpKind,
    Mnemonic,
)
from .types import DisasmLiteInst

ICED_MNEMONIC_JUMPS = frozenset(
    [
        Mnemonic.JA,
        Mnemonic.JAE,
        Mnemonic.JB,
        Mnemonic.JBE,
        Mnemonic.JCXZ,
        Mnemonic.JE,
        Mnemonic.JECXZ,
        Mnemonic.JG,
        Mnemonic.JGE,
        Mnemonic.JL,
        Mnemonic.JLE,
        Mnemonic.JMP,
        Mnemonic.JMPE,
        Mnemonic.JNE,
        Mnemonic.JNO,
        Mnemonic.JNP,
        Mnemonic.JNS,
        Mnemonic.JO,
        Mnemonic.JP,
        Mnemonic.JRCXZ,
        Mnemonic.JS,
    ]
)

# _________________
formatter = Formatter(FormatterSyntax.INTEL)
formatter.hex_prefix = "0x"
formatter.hex_suffix = ""
formatter.uppercase_hex = False
formatter.show_branch_size = False
formatter.memory_size_options = MemorySizeOptions.ALWAYS
formatter.space_after_operand_separator = True
formatter.space_between_memory_add_operators = True
formatter.space_between_memory_mul_operators = False


class SectionType(Enum):
    CODE = auto()
    DATA_TAB = auto()
    ADDR_TAB = auto()


class CodeSection(NamedTuple):
    type: Literal[SectionType.CODE]
    contents: list[DisasmLiteInst]


TabSectionType = Literal[SectionType.DATA_TAB] | Literal[SectionType.ADDR_TAB]


class TabSection(NamedTuple):
    type: TabSectionType
    contents: list[tuple[int, int]]


FuncSection = CodeSection | TabSection


class InstructGen:
    # pylint: disable=too-many-instance-attributes
    def __init__(self, blob: bytes, start: int, is_32bit: bool = True) -> None:
        self.is_32bit = is_32bit
        self.decoder = Decoder(32 if is_32bit else 16, blob, ip=start)
        self.blob = blob
        self.start = start
        self.end = len(blob) + start
        self.section_end: int = self.end

        # Todo: Could be refactored later
        self.cur_addr: int = 0
        self.cur_section_type: SectionType = SectionType.CODE
        self.section_start = start

        self.sections: list[FuncSection] = []

        self.confirmed_addrs: dict[int, SectionType] = {}
        self.analysis()

    def _finish_code_section(self, contents: list[Instruction]):
        instructions = [
            DisasmLiteInst(
                inst.ip,
                inst.len,
                formatter.format_mnemonic(inst),
                formatter.format_all_operands(inst),
            )
            for inst in contents
        ]

        self.sections.append(CodeSection(SectionType.CODE, instructions))

    def _finish_tab_section(self, type_: TabSectionType, stuff: list[tuple[int, int]]):
        self.sections.append(TabSection(type_, stuff))

    def _insert_confirmed_addr(self, addr: int, type_: SectionType):
        # Ignore address outside the bounds of the function
        if not self.start <= addr < self.end:
            return

        self.confirmed_addrs[addr] = type_

        # This newly inserted address might signal the end of this section.
        # For example, a jump table at the end of the function means we should
        # stop reading instructions once we hit that address.
        # However, if there is a jump table in between code sections, we might
        # read a jump to an address back to the beginning of the function
        # (e.g. a loop that spans the entire function)
        # so ignore this address because we have already passed it.
        if type_ != self.cur_section_type and addr > self.cur_addr:
            self.section_end = min(self.section_end, addr)

    def _next_section(self, addr: int) -> SectionType | None:
        """We have reached the start of a new section. Tell what kind of
        data we are looking at (code or other) and how much we should read."""

        # Assume the start of every function is code.
        if addr == self.start:
            self.section_end = self.end
            return SectionType.CODE

        # The start of a new section must be an address that we've seen.
        new_type = self.confirmed_addrs.get(addr)
        if new_type is None:
            return None

        self.cur_section_type = new_type

        # The confirmed addrs dict is sorted by insertion order
        # i.e. the order in which we read the addresses
        # So we have to sort and then find the next item
        # to see where this section should end.

        # If we are in a CODE section, ignore contiguous CODE addresses.
        # These are not the start of a new section.
        # However: if we are not in CODE, any upcoming address is a new section.
        # Do this so we can detect contiguous non-CODE sections.
        confirmed = [
            conf_addr
            for (conf_addr, conf_type) in sorted(self.confirmed_addrs.items())
            if self.cur_section_type != SectionType.CODE
            or conf_type != self.cur_section_type
        ]

        index = bisect.bisect_right(confirmed, addr)
        if index < len(confirmed):
            self.section_end = confirmed[index]
        else:
            self.section_end = self.end

        return new_type

    def analysis(self):
        self.cur_addr = self.start

        while (sect_type := self._next_section(self.cur_addr)) is not None:
            self.section_start = self.cur_addr

            if sect_type == SectionType.CODE:
                self.decoder.ip = self.cur_addr
                self.decoder.position = self.cur_addr - self.start
                instructions = []

                for inst in self.decoder:
                    # section_end is updated as we read instructions.
                    # If we are into a jump/data table and would read
                    # a junk instruction, stop here.
                    if self.cur_addr >= self.section_end:
                        break

                    if inst.is_invalid or inst.mnemonic == Mnemonic.INT3:
                        # Bump so we don't get stuck forever
                        self.cur_addr += inst.len
                        break

                    instructions.append(inst)

                    # print(f"{inst.address:x} : {inst.mnemonic} {inst.op_str}")

                    if inst.mnemonic == Mnemonic.JMP and inst.op0_kind == OpKind.MEMORY:
                        if inst.memory_displ_size == 4:
                            self._insert_confirmed_addr(
                                inst.memory_displacement, SectionType.ADDR_TAB
                            )

                    elif (
                        inst.mnemonic in ICED_MNEMONIC_JUMPS
                        and inst.op0_kind == OpKind.NEAR_BRANCH32
                    ):
                        # Todo: log calls too (unwind section)
                        self._insert_confirmed_addr(
                            inst.near_branch_target, SectionType.CODE
                        )

                    elif (
                        inst.mnemonic in (Mnemonic.MOV, Mnemonic.MOVZX)
                        and inst.op_count > 1
                        and inst.op1_kind == OpKind.MEMORY
                    ):
                        # Todo: maintain pairing of data/jump tables
                        self._insert_confirmed_addr(
                            inst.memory_displacement, SectionType.DATA_TAB
                        )

                    # Do this instead of copying instruction address.
                    # If there is only one instruction, we would get stuck here.
                    self.cur_addr += inst.len
                else:
                    # Nudge the current addr so we will eventually move on to the
                    # next section.
                    # Todo: Maybe we could just call it quits here
                    self.cur_addr += 1

                # End of for loop on instructions.
                # We are at the end of the section or the entire function.
                # Cut out only the valid instructions for this section
                # and save it for later.

                # Todo: don't need to iter on every instruction here.
                # They are already in order.
                self._finish_code_section(instructions)

            elif sect_type == SectionType.ADDR_TAB:
                # Clamp to multiple of 4 (dwords)
                read_size = ((self.section_end - self.cur_addr) // 4) * 4
                offsets = range(self.section_start, self.section_start + read_size, 4)
                dwords = self.blob[
                    self.cur_addr - self.start : self.cur_addr - self.start + read_size
                ]
                addrs: list[int] = [addr for addr, in struct.iter_unpack("<L", dwords)]
                for addr in addrs:
                    # Todo: the fact that these are jump table destinations
                    # should factor into the label name.
                    self._insert_confirmed_addr(addr, SectionType.CODE)

                jump_table = list(zip(offsets, addrs))
                # for (t0,t1) in jump_table:
                #     print(f"{t0:x} : --> {t1:x}")

                self._finish_tab_section(SectionType.ADDR_TAB, jump_table)
                self.cur_addr = self.section_end

            else:
                # Todo: variable data size?
                read_size = self.section_end - self.cur_addr
                offsets = range(self.section_start, self.section_start + read_size)
                bytes_ = self.blob[
                    self.cur_addr - self.start : self.cur_addr - self.start + read_size
                ]
                data = [b for b, in struct.iter_unpack("<B", bytes_)]

                data_table = list(zip(offsets, data))
                # for (t0,t1) in data_table:
                #     print(f"{t0:x} : value {t1:02x}")

                self._finish_tab_section(SectionType.DATA_TAB, data_table)
                self.cur_addr = self.section_end
