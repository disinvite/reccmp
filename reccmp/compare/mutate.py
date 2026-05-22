"""Part of the core analysis/comparison logic of `reccmp`.
These functions create or update entities using the current information in the database.
"""

import logging
import struct
from functools import cache
from typing import Iterator
from typing_extensions import Buffer
from reccmp.compare.functions import create_valid_addr_lookup
from reccmp.compare.asm.const import JUMP_MNEMONICS
from reccmp.compare.asm.instgen import (
    DisasmLiteInst,
    InstructGen,
    SectionType,
)
from reccmp.compare.asm.parse import ParseAsm
from reccmp.cvdump.demangler import (
    get_function_arg_string,
)
from reccmp.cvdump import CvdumpTypesParser
from reccmp.cvdump.types import CvdumpTypeKey
from reccmp.formats import PEImage
from reccmp.types import EntityType, ImageId
from .db import EntityDb
from .queries import get_overloaded_functions, get_named_thunks

logger = logging.getLogger(__name__)


def match_array_elements(db: EntityDb, types: CvdumpTypesParser):
    """
    For each matched variable, check whether it is an array.
    If yes, adds a match for all its elements. If it is an array of structs, all fields in that struct are also matched.
    Note that there is no recursion, so an array of arrays would not be handled entirely.
    This step is necessary e.g. for `0x100f0a20` (LegoRacers.cpp).
    """
    seen_recomp = set()
    batch = db.batch()

    @cache
    def get_type_size(type_key: CvdumpTypeKey) -> int:
        type_ = types.get(type_key)
        assert type_.size is not None
        return type_.size

    # Helper function
    # pylint: disable=too-many-positional-arguments
    def _add_match_in_array(
        name: str,
        size: int,
        orig_addr: int,
        recomp_addr: int,
        max_orig: int,
        is_main_variable: bool,
    ):
        if recomp_addr in seen_recomp:
            return

        seen_recomp.add(recomp_addr)

        if is_main_variable:
            # Don't replace the type or size of the main variable entity.
            batch.set(ImageId.RECOMP, recomp_addr, name=name)
        else:
            batch.set(
                ImageId.RECOMP,
                recomp_addr,
                name=name,
                size=size,
                type=EntityType.OFFSET,
            )

        if orig_addr < max_orig:
            batch.match(orig_addr, recomp_addr)

    for match in db.get_matches_by_type(EntityType.DATA):
        # TODO: The type information we need is in multiple places. (See #106)
        type_key_raw = match.get("data_type")
        if type_key_raw is None:
            continue

        type_key = CvdumpTypeKey(type_key_raw)
        if type_key.is_scalar():
            # scalar type, so clearly not an array
            continue

        type_dict = types.keys.get(type_key)
        if type_dict is None:
            continue

        if type_dict.get("type") != "LF_ARRAY":
            continue

        array_type_key = type_dict.get("array_type")
        if array_type_key is None:
            continue

        data_type = types.get(type_key)

        # Check whether another orig variable appears before the end of the array in recomp.
        # If this happens we can still add all the recomp offsets, but do not attach the orig address
        # where it would extend into the next variable.
        upper_bound = match.orig_addr + match.any_size()
        if (
            next_orig := db.get_next_orig_addr(match.orig_addr)
        ) is not None and next_orig < upper_bound:
            logger.warning(
                "Array variable %s at 0x%x is larger in recomp",
                match.name,
                match.orig_addr,
            )
            upper_bound = next_orig

        array_element_type = types.get(array_type_key)

        assert data_type.members is not None

        for array_element in data_type.members:
            orig_element_base_addr = match.orig_addr + array_element.offset
            recomp_element_base_addr = match.recomp_addr + array_element.offset
            if array_element_type.members is None:
                # If array of scalars
                assert array_element_type.size is not None
                _add_match_in_array(
                    f"{match.name}{array_element.name}",
                    array_element_type.size,
                    orig_element_base_addr,
                    recomp_element_base_addr,
                    upper_bound,
                    array_element.offset == 0,
                )

            else:
                # Else: multidimensional array or array of structs
                for member in array_element_type.members:
                    _add_match_in_array(
                        f"{match.name}{array_element.name}.{member.name}",
                        get_type_size(member.type),
                        orig_element_base_addr + member.offset,
                        recomp_element_base_addr + member.offset,
                        upper_bound,
                        array_element.offset + member.offset == 0,
                    )

    batch.commit()


def name_thunks(db: EntityDb):
    """Add the 'Thunk of' prefix or 'vtordisp{x,y}' suffix to thunk or vtordisp entities.
    The current behavior is to use the computed_name (disambiguated) for an entity as the
    entity's "name" attribute."""

    with db.batch() as batch:
        for img, addr, name in get_named_thunks(db):
            batch.set(img, addr, name=name)


def unique_names_for_overloaded_functions(db: EntityDb):
    """Our asm sanitize will use the "friendly" name of a function.
    Overloaded functions will all have the same name. This function detects those
    cases and gives each one a unique name in the db."""
    with db.batch() as batch:
        for func in get_overloaded_functions(db):
            # Just number it to start, in case we don't have a symbol.
            new_name = f"{func.name}({func.nth})"

            if func.symbol is not None:
                dm_args = get_function_arg_string(func.symbol)
                if dm_args is not None:
                    new_name = f"{func.name}{dm_args}"

            if func.orig_addr is not None:
                batch.set(ImageId.ORIG, func.orig_addr, computed_name=new_name)
            elif func.recomp_addr is not None:
                batch.set(ImageId.RECOMP, func.recomp_addr, computed_name=new_name)


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
