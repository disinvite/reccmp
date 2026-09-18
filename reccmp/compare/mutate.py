"""Part of the core analysis/comparison logic of `reccmp`.
These functions create or update entities using the current information in the database.
"""

import logging
from reccmp.analysis.crt_startup import (
    detect_crt_startup_arrays,
    fingerprint_crt_functions,
    create_crt_matches,
)
from reccmp.cvdump.demangler import (
    get_function_arg_string,
)
from reccmp.cvdump.types import (
    CvdumpIntegrityError,
    CvdumpKeyError,
    CvdumpTypeKey,
    CvdumpTypesParser,
)
from reccmp.formats import Image, PEImage
from reccmp.types import EntityType, ImageId
from .db import EntityDb
from .functions import create_bin_lookup
from .queries import get_overloaded_functions, get_named_thunks

logger = logging.getLogger(__name__)


def set_max_size(db: EntityDb, image_id: ImageId):
    """In each section/segment of the image, for compared entities without a size value,
    calculate the distance between the entity and the solid entity that follows.
    Same calculation as db.get_max_size()."""
    assert image_id in (ImageId.ORIG, ImageId.RECOMP), "Invalid image id"

    # Any entity that takes up space can be used to measure against.
    solid_types = EntityType.solid_types()

    # We don't want to measure the size of const data entities like strings.
    # They already have an intrinsic size.
    measured_types = EntityType.variable_size_types()

    with db.batch() as batch:
        for range_ in db.sections(image_id):
            last_addr = None

            for ent in db.all_in_range(image_id, range_):
                this_type = ent.get("type")
                if this_type not in solid_types:
                    # Also excludes null type.
                    continue

                this_addr = ent.addr(image_id)
                assert this_addr is not None

                if last_addr is not None:
                    batch.set(image_id, last_addr, max_size=this_addr - last_addr)
                    last_addr = None

                # Only measure entities with no set size
                if last_addr is None and ent.size(image_id) is None:
                    if this_type in measured_types:
                        # Measure this entity next.
                        last_addr = this_addr

            # Measured against the end of the section/image.
            if last_addr is not None:
                batch.set(image_id, last_addr, max_size=range_.stop - last_addr)


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


def match_crt_startup(db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage):
    """Match CRT function entities established in create_crt_functions().
    For best performance, call after set_max_size() has provided a limit for
    CRT function size. Otherwise, the fingerprint sampler will read more
    bytes than necessary for each function."""
    crt_orig = detect_crt_startup_arrays(db, ImageId.ORIG, orig_bin)
    crt_recomp = detect_crt_startup_arrays(db, ImageId.RECOMP, recomp_bin)

    matches = []

    for array_type, orig_array in crt_orig.items():
        recomp_array = crt_recomp.get(array_type)
        if recomp_array is None:
            continue

        if orig_array.functions and recomp_array.functions:
            fingerprint_crt_functions(db, ImageId.ORIG, orig_bin, orig_array)
            fingerprint_crt_functions(db, ImageId.RECOMP, recomp_bin, recomp_array)
            matches.extend(create_crt_matches(orig_array, recomp_array))

    with db.batch() as batch:
        for orig_addr, recomp_addr in matches:
            batch.match(orig_addr, recomp_addr)


def match_pointers_recursive(
    db: EntityDb,
    types: CvdumpTypesParser,
    orig_bin: Image,
    recomp_bin: Image,
):
    """Match the pointer members of each variable entity with the 'recurse' option set.
    The pointers read from each binary become a new match, and we do the same for
    the entity created by that match until we run out of pointers to follow."""
    read_orig = create_bin_lookup(orig_bin)
    read_recomp = create_bin_lookup(recomp_bin)

    queue: list[tuple[int, int, CvdumpTypeKey]] = []
    completed: set[tuple[ImageId, int]] = set()
    matched_orig: set[int] = set()
    matched_recomp: set[int] = set()

    for ent in db.get_matches():
        matched_orig.add(ent.orig_addr)
        matched_recomp.add(ent.recomp_addr)

        if ent.get("type") != EntityType.DATA or not ent.get("recurse"):
            continue

        type_key = ent.get("data_type")
        if type_key is None:
            continue

        completed.update(
            ((ImageId.ORIG, ent.orig_addr), (ImageId.RECOMP, ent.recomp_addr))
        )
        queue.append((ent.orig_addr, ent.recomp_addr, CvdumpTypeKey(type_key)))

    with db.batch() as batch:
        while queue:
            orig_addr, recomp_addr, type_key = queue.pop()

            try:
                pointers = types.get_pointer_offsets(type_key)
            except (CvdumpKeyError, CvdumpIntegrityError):
                logger.error(
                    "Could not read pointers of type '0x%x' for match (0x%x, 0x%x)",
                    type_key,
                    orig_addr,
                    recomp_addr,
                )
                continue

            for offset, pointee in pointers:
                orig_ptr = read_orig(orig_addr + offset)
                recomp_ptr = read_recomp(recomp_addr + offset)

                # Ignore null pointers and addresses we could not read.
                if not orig_ptr or not recomp_ptr:
                    continue

                orig_key = (ImageId.ORIG, orig_ptr)
                recomp_key = (ImageId.RECOMP, recomp_ptr)

                if orig_key in completed or recomp_key in completed:
                    continue

                if (
                    orig_ptr in matched_orig or recomp_ptr in matched_recomp
                ) and not db.is_match(orig_ptr, recomp_ptr):
                    continue

                completed.update((orig_key, recomp_key))
                batch.match(orig_ptr, recomp_ptr)
                batch.set(ImageId.ORIG, orig_ptr, recurse=True)
                batch.set(ImageId.RECOMP, recomp_ptr, recurse=True)
                queue.append((orig_ptr, recomp_ptr, pointee))
