import struct
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
    db: EntityDb, binfile: PEImage, image_id: ImageId, addr: int
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


def get_xca(db: EntityDb, image_id: ImageId) -> tuple[int | None, int | None]:
    xca = None
    xcz = None
    # TODO: could exploit the fact that this is in .data
    for ent in db.all(image_id):
        if ent.get("name") == "___xc_a":
            xca = ent.addr(image_id)
        if ent.get("name") == "___xc_z":
            xcz = ent.addr(image_id)

        if xca and xcz:
            break

    return (xca, xcz)


def unwrap_jump(binfile: PEImage, addr: int) -> tuple[bool, int]:
    jmp = binfile.read(addr, 5)
    if jmp[0] in (0xE8, 0xE9):
        (offset,) = struct.unpack("<I", jmp[1:])
        return (True, addr + 5 + offset)

    return (False, addr)


def variable_init_functions(db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage):
    # Get ___xc_a in each image.
    # Match those.
    # Create functions for each.
    # Analyze functions and collect "fingerprint"
    # Match according to fingerprint (depending on previously matched functions/vars)

    xca_orig_raw = get_xca(db, ImageId.ORIG)
    xca_recomp_raw = get_xca(db, ImageId.RECOMP)
    if not all(xca_orig_raw) or not all(xca_recomp_raw):
        return

    # TODO: lol
    assert isinstance(xca_orig_raw[0], int)
    assert isinstance(xca_orig_raw[1], int)
    assert isinstance(xca_recomp_raw[0], int)
    assert isinstance(xca_recomp_raw[1], int)
    xca_orig = range(xca_orig_raw[0], xca_orig_raw[1])
    xca_recomp = range(xca_recomp_raw[0], xca_recomp_raw[1])

    def read_xc(binfile: PEImage, xca: range) -> Iterator[int]:
        for (addr,) in struct.iter_unpack("<I", binfile.read(xca.start, len(xca))):
            yield addr

    orig_funcs = tuple(read_xc(orig_bin, xca_orig))
    recomp_funcs = tuple(read_xc(recomp_bin, xca_recomp))

    orig_xyz = {}
    recomp_xyz = {}

    for xc_addr in orig_funcs:
        if xc_addr != 0:
            was_thunk, real_addr = unwrap_jump(orig_bin, xc_addr)
            x = get_instruction_fingerprint(db, orig_bin, ImageId.ORIG, real_addr)
            if x:
                orig_xyz[x] = (real_addr, xc_addr if was_thunk else None)

    for xc_addr in recomp_funcs:
        if xc_addr != 0:
            was_thunk, real_addr = unwrap_jump(recomp_bin, xc_addr)
            x = get_instruction_fingerprint(db, recomp_bin, ImageId.RECOMP, real_addr)
            if x:
                recomp_xyz[x] = (real_addr, xc_addr if was_thunk else None)

    with db.batch() as batch:
        for fingerprint, (orig_addr, orig_thunk) in orig_xyz.items():
            batch.set(
                ImageId.ORIG, orig_addr, type=EntityType.FUNCTION, name="Initialize"
            )
            if fingerprint in recomp_xyz:
                recomp_addr, recomp_thunk = recomp_xyz[fingerprint]
                batch.match(orig_addr, recomp_addr)
                if orig_thunk and recomp_thunk:
                    batch.set(
                        ImageId.ORIG,
                        orig_thunk,
                        type=EntityType.FUNCTION,
                        name="Initialize",
                    )
                    batch.match(orig_thunk, recomp_thunk)

    # breakpoint()
