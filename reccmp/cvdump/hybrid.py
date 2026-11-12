from reccmp.formats.pdb import open_pdb
from .parser import CvdumpParser
from .pdb_parser import PdbParser
from .pdb_types import PdbTypesParser
from .runner import Cvdump, DumpOpt


class HybridCvdump(Cvdump):
    """Same interface as Cvdump, but every section is read from the PDB file
    by PdbParser and PdbTypesParser. cvdump.exe is not run."""

    def run(self) -> CvdumpParser:
        parser = CvdumpParser()

        with open(self._pdb, "rb") as f:
            pdb_data = f.read()

        pdb = PdbParser(pdb_data)

        if DumpOpt.LINES in self.options:
            parser.lines = pdb.lines

        if DumpOpt.SYMBOLS in self.options:
            parser.symbols_parser.symbols = pdb.symbols

        if DumpOpt.GLOBALS in self.options:
            parser.globals = pdb.globals

        if DumpOpt.PUBLICS in self.options:
            parser.publics = pdb.publics

        if DumpOpt.SECTION_CONTRIB in self.options:
            parser.sizerefs = pdb.sizerefs

        if DumpOpt.MODULES in self.options:
            parser.modules = pdb.modules

        if DumpOpt.TYPES in self.options:
            parser.types = PdbTypesParser(open_pdb(pdb_data))
            parser.is_16bit_type_pool = pdb.is_16bit_type_pool

        return parser
