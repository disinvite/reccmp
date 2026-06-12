# pylint: disable=unused-import
from functools import partial
from typing import Callable, Iterator
from reccmp.formats import PEImage
from reccmp.types import ImageId
from .analyze import (
    create_imports,
    create_import_thunks,
    create_thunks,
    create_analysis_floats,
    create_analysis_strings,
    create_analysis_vtordisps,
    create_seh_entities,
    complete_partial_floats,
    complete_partial_strings,
    match_entry,
    match_exports,
)
from .dependency import (
    DependencyManager,
    ReccmpDepType,
    ReccmpMissingDependencyError,
    InternalManager,
)
from .ingest import (
    load_cvdump,
    load_cvdump_types,
    load_cvdump_lines,
    load_markers,
    load_data_sources,
)
from .match_msvc import (
    match_lines,
    match_symbols,
    match_functions,
    match_vtables,
    match_static_variables,
    match_variables,
    match_strings,
    match_ref,
    match_imports,
)
from .mutate import (
    match_array_elements,
    name_thunks,
    unique_names_for_overloaded_functions,
)
from .verify import (
    check_vtables,
)

VoidFunction = Callable[[], None]
ReccmpTask = tuple[str, VoidFunction]


def load_from_codeview_pdb(
    image_id: ImageId, deps: DependencyManager, internals: InternalManager
) -> Iterator[ReccmpTask]:
    try:
        pdb = deps.get_pdb(image_id)
        # Binfile required for segment:offset resolution
        binfile = deps.get_binary(image_id)
    except ReccmpMissingDependencyError:
        return

    if not isinstance(binfile, PEImage):
        return

    if image_id == ImageId.RECOMP:
        types_db = internals.get_types_db()
        yield ("Recomp types db", partial(load_cvdump_types, pdb, types_db))

    entity_db = internals.get_entity_db()
    yield ("PDB Parse", partial(load_cvdump, pdb, entity_db, binfile))

    if image_id == ImageId.RECOMP:
        lines_db = internals.get_lines_db()
        yield ("Recomp lines db", partial(load_cvdump_lines, pdb, lines_db, binfile))


def load_from_binfile(
    image_id: ImageId, deps: DependencyManager, internals: InternalManager
) -> Iterator[ReccmpTask]:
    try:
        binfile = deps.get_binary(image_id)
    except ReccmpMissingDependencyError:
        return

    if not isinstance(binfile, PEImage):
        return

    entity_db = internals.get_entity_db()
    yield ("Imports", partial(create_imports, entity_db, image_id, binfile))
    yield ("Import thunks", partial(create_import_thunks, entity_db, image_id, binfile))
    yield ("SEH entities", partial(create_seh_entities, entity_db, image_id, binfile))
    yield ("Incremental thunks", partial(create_thunks, entity_db, image_id, binfile))
    yield ("Vtordisp", partial(create_analysis_vtordisps, entity_db, image_id, binfile))


def load_binfile_const_data(
    image_id: ImageId, deps: DependencyManager, internals: InternalManager
) -> Iterator[ReccmpTask]:
    try:
        binfile = deps.get_binary(image_id)
        options = deps.get_options(ImageId.ORIG)
    except ReccmpMissingDependencyError:
        return

    if not isinstance(binfile, PEImage):
        return

    entity_db = internals.get_entity_db()
    bin_encoding = options.bin_encoding

    # Detect floats first to eliminate potential overlap with string data
    yield (
        "create_analysis_floats",
        partial(create_analysis_floats, entity_db, image_id, binfile),
    )
    yield (
        "create_analysis_strings",
        partial(create_analysis_strings, entity_db, image_id, binfile, bin_encoding),
    )
    yield (
        "complete_partial_floats",
        partial(complete_partial_floats, entity_db, image_id, binfile),
    )
    yield (
        "complete_partial_strings",
        partial(complete_partial_strings, entity_db, image_id, binfile, bin_encoding),
    )


def load_flat_files(
    deps: DependencyManager, internals: InternalManager
) -> Iterator[ReccmpTask]:
    try:
        data_sources = deps.get_csv_files(ImageId.ORIG)
    except ReccmpMissingDependencyError:
        return

    entity_db = internals.get_entity_db()
    yield ("Loading CSV", partial(load_data_sources, entity_db, data_sources))


def load_code_files(
    deps: DependencyManager, internals: InternalManager
) -> Iterator[ReccmpTask]:
    try:
        binfile = deps.get_binary(ImageId.ORIG)
        code_files = deps.get_code_files(ImageId.ORIG)
        options = deps.get_options(ImageId.ORIG)
    except ReccmpMissingDependencyError:
        return

    if not isinstance(binfile, PEImage):
        return

    entity_db = internals.get_entity_db()
    lines_db = internals.get_lines_db()
    target_id = internals.get_code_target()
    report = internals.get_report()

    yield (
        "Code annotations",
        partial(
            load_markers,
            code_files,
            lines_db,
            binfile,
            target_id,
            entity_db,
            options.bin_encoding,
            {},  # TODO: aliases
            report,
        ),
    )


def match_tasks(
    deps: DependencyManager, internals: InternalManager
) -> Iterator[ReccmpTask]:
    try:
        orig_bin = deps.get_binary(ImageId.ORIG)
        recomp_bin = deps.get_binary(ImageId.RECOMP)
    except ReccmpMissingDependencyError:
        return

    if not isinstance(orig_bin, PEImage) or not isinstance(recomp_bin, PEImage):
        return

    entity_db = internals.get_entity_db()
    lines_db = internals.get_lines_db()
    types_db = internals.get_types_db()
    report = internals.get_report()

    yield ("match_entry", partial(match_entry, entity_db, orig_bin, recomp_bin))
    yield ("match_symbols", partial(match_symbols, entity_db, report, truncate=True))
    yield (
        "match_functions",
        partial(match_functions, entity_db, report, truncate=True),
    )
    yield ("match_vtables", partial(match_vtables, entity_db, report))
    yield ("match_static_variables", partial(match_static_variables, entity_db, report))
    yield ("match_variables", partial(match_variables, entity_db, report))
    yield ("match_lines", partial(match_lines, entity_db, lines_db, report))
    yield ("match_array_elements", partial(match_array_elements, entity_db, types_db))


def build_task_list(
    deps: DependencyManager, internals: InternalManager
) -> Iterator[ReccmpTask]:
    for image_id in ImageId:
        yield from load_from_codeview_pdb(image_id, deps, internals)

    yield from load_code_files(deps, internals)
    yield from load_flat_files(deps, internals)

    yield from match_tasks(deps, internals)

    for image_id in ImageId:
        yield from load_from_binfile(image_id, deps, internals)
        yield from load_binfile_const_data(image_id, deps, internals)
