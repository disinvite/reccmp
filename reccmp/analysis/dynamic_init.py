import struct
from dataclasses import dataclass
from typing import Iterator
from typing_extensions import Buffer
from reccmp.compare.asm.const import JUMP_MNEMONICS
from reccmp.compare.asm.instgen import (
    DisasmLiteInst,
    InstructGen,
    SectionType,
)
from reccmp.compare.asm.parse import ParseAsm
from reccmp.compare.functions import create_valid_addr_lookup
from reccmp.formats import PEImage
from reccmp.types import EntityType, ImageId
from reccmp.compare.db import EntityDb


@dataclass
class DynamicInitResult:
    """Result from analyzing functions between the labels ___xc_a and ___xc_z."""

    fingerprints: dict[int, tuple[int, ...]]
    """Maps function address -> (sorted) list of matched entities used in
    the function, normalized to orig address space. These fingerprints are
    used to match initializer functions in orig and recomp."""

    thunks: dict[int, int]
    """Maps thunked initializer function to the thunk address.
    The thunk is what actually appeared in the ___xc_a/z list."""


class InitFunctionAnalysis(ParseAsm):
    def analyze(self, data: Buffer, start_addr: int):
        ig = InstructGen(bytes(data), start_addr, self.is_32bit)

        instructions = (
            inst
            for section in ig.sections
            for inst in section.contents
            if section.type == SectionType.CODE
        )

        for inst in instructions:
            assert isinstance(inst, DisasmLiteInst)
            if "0x" in inst.op_str and (
                inst.mnemonic in JUMP_MNEMONICS or inst.size > 4 or not self.is_32bit
            ):
                self.sanitize(inst)

            if inst.mnemonic == "ret":
                break


def get_instruction_fingerprint(
    db: EntityDb, image_id: ImageId, binfile: PEImage, addr: int
) -> tuple[int, ...]:
    collected_addrs = []

    # pylint: disable=unused-argument
    # pylint: disable=useless-return
    def lookup(addr: int, exact: bool = False, indirect: bool = False) -> str | None:
        collected_addrs.append(addr)
        return None

    addr_test = create_valid_addr_lookup(db, ImageId.ORIG, binfile)
    zzz = InitFunctionAnalysis(addr_test, lookup, True)
    zzz.analyze(binfile.read(addr, 64), addr)

    normalized_addrs = []
    for ca in collected_addrs:
        ent = db.get(image_id, ca)
        if ent and ent.matched:
            normalized_addr = ent.addr(ImageId.ORIG)
            assert isinstance(normalized_addr, int)
            normalized_addrs.append(normalized_addr)

    return tuple(normalized_addrs)


def read_dwords_from_span(binfile: PEImage, span: range) -> Iterator[int]:
    for (addr,) in struct.iter_unpack("<I", binfile.read(span.start, len(span))):
        yield addr


def get_xca_range(db: EntityDb, image_id: ImageId) -> range | None:
    xca = None
    xcz = None
    # TODO: could exploit the fact that this is at the beginning of .data
    for ent in db.all(image_id):
        if ent.get("name") == "___xc_a":
            xca = ent.addr(image_id)
        if ent.get("name") == "___xc_z":
            xcz = ent.addr(image_id)

        if xca and xcz:
            return range(xca, xcz)

    return None


def unwrap_jump(binfile: PEImage, addr: int) -> tuple[bool, int]:
    """If there is a 5-byte JMP or CALL instruction at the given address,
    follow it by calculating the destination address.
    Returns either (True, jmp_destination) or (False, starting_addr)."""
    jmp = binfile.read(addr, 5)
    # Check for CALL (0xE8) or JMP (0xE9) opcodes.
    if jmp[0] in (0xE8, 0xE9):
        (offset,) = struct.unpack("<I", jmp[1:])
        # Add 5 because the offset is based on the address of
        # the *next* instruction after the JMP or CALL.
        return (True, addr + 5 + offset)

    return (False, addr)


def read_xca(
    db: EntityDb, image_id: ImageId, binfile: PEImage, span: range
) -> DynamicInitResult:
    funcs = tuple(read_dwords_from_span(binfile, span))

    fingerprints = {}
    thunks = {}

    for xc_addr in funcs:
        if xc_addr != 0:
            was_thunk, real_addr = unwrap_jump(binfile, xc_addr)
            fp = get_instruction_fingerprint(db, image_id, binfile, real_addr)
            if fp:
                fingerprints[real_addr] = fp
            if was_thunk:
                thunks[real_addr] = xc_addr

    return DynamicInitResult(fingerprints, thunks)


def get_it(
    db: EntityDb, image_id: ImageId, binfile: PEImage
) -> DynamicInitResult | None:
    xca_range = get_xca_range(db, image_id)
    if xca_range is None:
        return None

    return read_xca(db, image_id, binfile, xca_range)


def variable_init_functions(db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage):
    dyn_orig = get_it(db, ImageId.ORIG, orig_bin)
    dyn_recomp = get_it(db, ImageId.RECOMP, recomp_bin)

    if not dyn_orig or not dyn_recomp:
        return

    invert_orig = dict((fp, addr) for addr, fp in dyn_orig.fingerprints.items())
    invert_recomp = dict((fp, addr) for addr, fp in dyn_recomp.fingerprints.items())

    with db.batch() as batch:
        for fingerprint, orig_addr in invert_orig.items():
            batch.set(
                ImageId.ORIG,
                orig_addr,
                type=EntityType.FUNCTION,
                name="$DynamicInitializer",
            )

            if fingerprint in invert_recomp:
                recomp_addr = invert_recomp[fingerprint]
                batch.match(orig_addr, recomp_addr)

                if orig_addr in dyn_orig.thunks and recomp_addr in dyn_recomp.thunks:
                    orig_thunk = dyn_orig.thunks[orig_addr]
                    recomp_thunk = dyn_recomp.thunks[recomp_addr]
                    batch.set(
                        ImageId.ORIG,
                        orig_thunk,
                        type=EntityType.FUNCTION,
                        name="$DynamicInitializerThunk",
                    )
                    batch.match(orig_thunk, recomp_thunk)
