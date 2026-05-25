import enum
from dataclasses import dataclass
from typing import Any, NamedTuple
from reccmp.compare.db import EntityDb
from reccmp.compare.event import ReccmpReportProtocol
from reccmp.compare.lines import LinesDb
from reccmp.types import ImageId
from reccmp.formats import (
    Image,
    TextFile,
)
from reccmp.cvdump import CvdumpAnalysis, CvdumpTypesParser

ReccmpDependencyValue = Any


class ReccmpMissingDependencyError(Exception):
    pass


class ReccmpProjectType(enum.Enum):
    MSVC_ANY = enum.auto()
    WATCOM_ANY = enum.auto()


class ReccmpDepType(enum.Enum):
    BINARY = enum.auto()
    PDB_FILE = enum.auto()
    MAP_FILE = enum.auto()
    CODE_FILE = enum.auto()
    CSV_FILE = enum.auto()
    OPTIONS = enum.auto()  #### ?


class ReccmpDepKey(NamedTuple):
    img: ImageId
    type: ReccmpDepType


class ReccmpOptions(NamedTuple):
    src_encoding: str
    bin_encoding: str


@dataclass
class InternalManager:
    target_id: str
    types_db: CvdumpTypesParser
    entity_db: EntityDb
    lines_db: LinesDb
    report: ReccmpReportProtocol

    def get_code_target(self) -> str:
        return self.target_id

    def get_types_db(self) -> CvdumpTypesParser:
        return self.types_db

    def get_entity_db(self) -> EntityDb:
        return self.entity_db

    def get_lines_db(self) -> LinesDb:
        return self.lines_db

    def get_report(self) -> ReccmpReportProtocol:
        return self.report


class DependencyManager:
    _deps: dict[ReccmpDepKey, ReccmpDependencyValue]

    def __init__(self):
        self._deps = {}

    def add_dependency(
        self, img: ImageId, type_: ReccmpDepType, value: ReccmpDependencyValue
    ):
        key = ReccmpDepKey(img, type_)
        self._deps.setdefault(key, []).append(value)

    def _find(self, img: ImageId, type_: ReccmpDepType) -> ReccmpDependencyValue:
        key = ReccmpDepKey(img, type_)
        for dep in self._deps.get(key, []):
            return dep

        raise ReccmpMissingDependencyError

    def get_binary(self, img: ImageId) -> Image:
        dep = self._find(img, ReccmpDepType.BINARY)
        assert isinstance(dep, Image)
        return dep

    def get_pdb(self, img: ImageId) -> CvdumpAnalysis:
        dep = self._find(img, ReccmpDepType.PDB_FILE)
        assert isinstance(dep, CvdumpAnalysis)
        return dep

    def get_code_files(self, img: ImageId) -> tuple[TextFile, ...]:
        dep = self._find(img, ReccmpDepType.CODE_FILE)
        assert isinstance(dep, tuple)
        return dep

    def get_csv_files(self, img: ImageId) -> tuple[TextFile, ...]:
        dep = self._find(img, ReccmpDepType.CSV_FILE)
        assert isinstance(dep, tuple)
        return dep

    def get_options(self, img: ImageId) -> ReccmpOptions:
        dep = self._find(img, ReccmpDepType.OPTIONS)
        assert isinstance(dep, ReccmpOptions)
        return dep
