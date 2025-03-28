# This file can only be imported successfully when run from Ghidra using Ghidrathon.

# Disable spurious warnings in vscode / pylance
# pyright: reportMissingModuleSource=false

import logging

from ghidra.program.flatapi import FlatProgramAPI

from reccmp.isledecomp.compare.core import Compare
from reccmp.isledecomp.compare.db import ReccmpMatch

from .exceptions import Lego1Exception
from .type_importer import PdbTypeImporter
from .ghidra_helper import set_ghidra_label


logger = logging.getLogger(__name__)


def import_global_into_ghidra(
    api: FlatProgramAPI,
    compare: Compare,
    type_importer: PdbTypeImporter,
    glob: ReccmpMatch,
):
    node = next(
        (y for y in compare.cvdump_analysis.nodes if y.addr == glob.recomp_addr),
        None,
    )
    if node is None:
        # should never happen
        raise Lego1Exception(
            f"Failed to find node for {glob.name} at LEGO1 0x{glob.orig_addr:x}"
        )

    name = node.friendly_name or node.decorated_name
    assert name is not None, "node.decorated_name must not be None"

    logger.info("Handling global at %s: '%s'", hex(glob.orig_addr), name)
    if node.data_type is not None:
        data_type = type_importer.import_pdb_type_into_ghidra(node.data_type.key)
        address_ghidra = api.getAddressFactory().getAddress(hex(glob.orig_addr))

        existing_data = api.getDataAt(address_ghidra)
        if existing_data is not None:
            api.removeData(existing_data)

        data_end = glob.orig_addr + data_type.getLength()

        while True:
            # Clear conflicting data (usually auto-generated by Ghidra)
            next_data_entry = api.getDataAfter(address_ghidra)
            if next_data_entry is None:
                break
            next_data_address = int(next_data_entry.getAddress().getOffset())
            if next_data_address >= data_end:
                break
            logger.debug("Clearing conflicting data at %s", hex(next_data_address))
            api.removeData(next_data_entry)

        api.createData(address_ghidra, data_type)
    else:
        logger.debug("No datatype for variable '%s', adding label only", name)

    set_ghidra_label(api, glob.orig_addr, name)
