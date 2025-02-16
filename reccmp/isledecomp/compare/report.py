from datetime import datetime
from dataclasses import dataclass
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
    filename: str | None

    # Creation date of the file
    timestamp: datetime | None

    # Using orig addr as the key.
    entities: dict[str, ReccmpComparedEntity]

    def __init__(self) -> None:
        self.filename = None
        self.timestamp = None
        self.entities = {}


def _deserialize_reccmp_report_version_1(json_obj: dict) -> ReccmpStatusReport:
    report = ReccmpStatusReport()
    report.filename = json_obj.get("file", None)

    if "timestamp" in json_obj:
        report.timestamp = datetime.fromtimestamp(json_obj["timestamp"])

    for obj in json_obj.get("data", []):
        if "address" not in obj or "name" not in obj or "matching" not in obj:
            # error?
            continue

        orig_addr = obj["address"]
        if orig_addr in report.entities:
            # error?
            continue

        report.entities[orig_addr] = ReccmpComparedEntity(
            orig_addr=obj["address"],
            name=obj["name"],
            accuracy=obj["matching"],
            recomp_addr=obj.get("recomp", ""),
            is_stub=obj.get("stub", False),
            is_effective=obj.get("effective", False),
        )

    return report


def deserialize_reccmp_report(json_obj: dict) -> ReccmpStatusReport:
    if "timestamp" not in json_obj:
        raise ReccmpReportDeserializeError

    format_version = json_obj.get("format", 1)
    if format_version == 1:
        return _deserialize_reccmp_report_version_1(json_obj)

    raise ReccmpReportDeserializeError


def _serialize_entity(
    addr: str, entity: ReccmpComparedEntity, diff_included: bool = False
) -> dict:
    """To save space in the JSON file, don't set bool fields when they are false"""
    obj = {
        "address": addr,  # prefer dict key over redundant value in entity
        "recomp": entity.recomp_addr or "",
        "name": entity.name,
        "matching": entity.accuracy,
    }

    if entity.is_effective:
        obj["effective"] = True

    if entity.diff is not None and diff_included:
        obj["diff"] = entity.diff

    if entity.is_stub:
        obj["stub"] = True

    return obj


def serialize_reccmp_report(
    report: ReccmpStatusReport, diff_included: bool = False
) -> dict:
    """Flatten the report into a dict to be written using json.dump"""
    now = datetime.now().replace(microsecond=0)
    obj = {
        "file": report.filename,
        "format": JSON_FORMAT_VERSION,
        "timestamp": now.timestamp(),
        "data": [
            _serialize_entity(addr, e, diff_included)
            for addr, e in report.entities.items()
        ],
    }

    return obj
