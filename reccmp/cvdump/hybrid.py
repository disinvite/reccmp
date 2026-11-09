from reccmp.formats.pdb import MSFContainer, StreamIndex
from reccmp.formats.pdb.tpi import TPIHeader
from .parser import CvdumpParser
from .pdb_types import PdbTypesParser
from .runner import Cvdump, DumpOpt, cvdump_opt_map

# TPI version for MSVC 4.1. cvdump converts 16-bit types if the version is this or lower.
_TPI_IMPV41 = 19951122


class HybridCvdump(Cvdump):
    """Runs cvdump for every section except TYPES.
    The types are read from the PDB file by PdbTypesParser."""

    def cmd_line(self) -> list[str]:
        types_flag = cvdump_opt_map[DumpOpt.TYPES]
        return [arg for arg in super().cmd_line() if arg != types_flag]

    def run(self) -> CvdumpParser:
        parser = super().run()

        if DumpOpt.TYPES in self.options:
            with open(self._pdb, "rb") as f:
                msf = MSFContainer.from_bytes(f.read())

            data = msf.get_stream(StreamIndex.TPI)
            parser.types = PdbTypesParser(data)
            parser.is_16bit_type_pool = (
                TPIHeader.from_bytes(data).version <= _TPI_IMPV41
            )

        return parser
