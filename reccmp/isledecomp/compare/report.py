from datetime import datetime
from dataclasses import dataclass
from typing import Literal
from pydantic import BaseModel, Field, ValidationError
from .diff import CombinedDiffOutput


JSON_FORMAT_VERSION = 1


class ReccmpReportDeserializeError(Exception):
    """The given file is not a serialized reccmp report file"""


@dataclass
class ReccmpComparedEntity:
    orig_addr: str
    name: str
    accuracy: float
    recomp_addr: str | None = None
    is_effective: bool = False
    is_stub: bool = False
    diff: CombinedDiffOutput | None = None


class ReccmpStatusReport:
    # The filename of the original binary. This is here to avoid comparing reports derived from different files.
    # TODO: in the future, we may want to use the hash instead
    filename: str

    # Creation date of the file
    timestamp: datetime

    # Using orig addr as the key.
    entities: dict[str, ReccmpComparedEntity]

    def __init__(self, filename: str, timestamp: datetime | None = None) -> None:
        self.filename = filename
        if timestamp is not None:
            self.timestamp = timestamp
        else:
            self.timestamp = datetime.now().replace(microsecond=0)

        self.entities = {}


class JSONEntityVersion1(BaseModel):
    address: str
    name: str
    matching: float
    # Optional fields
    recomp: str | None = Field(default=None)
    stub: bool = Field(default=False)
    effective: bool = Field(default=False)
    diff: CombinedDiffOutput | None = Field(default=None)


class JSONReportVersion1(BaseModel):
    file: str
    format: Literal[1]
    timestamp: float
    data: list[JSONEntityVersion1]

    @classmethod
    def from_report(cls, report: ReccmpStatusReport) -> "JSONReportVersion1":
        entities = [
            JSONEntityVersion1(
                address=addr,  # prefer dict key over redundant value in entity
                name=e.name,
                matching=e.accuracy,
                recomp=e.recomp_addr,
                stub=e.is_stub,
                effective=e.is_effective,
                diff=e.diff,
            )
            for addr, e in report.entities.items()
        ]

        return cls(
            file=report.filename,
            format=1,
            timestamp=report.timestamp.timestamp(),
            data=entities,
        )


def _deserialize_reccmp_report_version_1(obj: JSONReportVersion1) -> ReccmpStatusReport:
    report = ReccmpStatusReport(
        filename=obj.file, timestamp=datetime.fromtimestamp(obj.timestamp)
    )

    for e in obj.data:
        report.entities[e.address] = ReccmpComparedEntity(
            orig_addr=e.address,
            name=e.name,
            accuracy=e.matching,
            recomp_addr=e.recomp,
            is_stub=e.stub,
            is_effective=e.effective,
        )

    return report


def deserialize_reccmp_report(json_obj: dict) -> ReccmpStatusReport:
    try:
        obj = JSONReportVersion1(**json_obj)
        return _deserialize_reccmp_report_version_1(obj)
    except ValidationError as ex:
        raise ReccmpReportDeserializeError from ex


def serialize_reccmp_report(
    report: ReccmpStatusReport, diff_included: bool = False
) -> dict:
    """Flatten the report into a dict to be written using json.dump"""
    now = datetime.now().replace(microsecond=0)
    report.timestamp = now
    obj = JSONReportVersion1.from_report(report)

    # Crude but necessary. HTML output needs diff, but it is excluded from the JSON report.
    if not diff_included:
        for x in obj.data:
            x.diff = None

    return obj.model_dump(exclude_defaults=True)
