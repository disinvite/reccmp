#!/usr/bin/env python3

import argparse
import json
import logging
from pathlib import Path
from reccmp.isledecomp.utils import diff_json
from reccmp.isledecomp.compare.report import (
    ReccmpStatusReport,
    ReccmpComparedEntity,
    deserialize_reccmp_report,
)


logger = logging.getLogger(__name__)


class InvalidReccmpReportError(Exception):
    """The given file is not a serialized reccmp report file"""


def load_report_file(report_path: Path) -> ReccmpStatusReport:
    """Deserialize from JSON at the given filename and return the report."""

    with report_path.open("r", encoding="utf-8") as f:
        return deserialize_reccmp_report(json.load(f))


def get_candidate_list(
    paths: list[Path], start_file: Path | None = None
) -> list[ReccmpStatusReport]:
    """Deserialize all sample files and return the list of reports.
    Exclude the starter file if it was included here by mistake.
    Does not remove duplicates."""
    candidates = []

    for path in paths:
        if start_file is not None and path == start_file:
            logger.warning("Not sampling starting file %s", start_file)
            continue

        if path.is_file():
            try:
                obj = load_report_file(path)
                candidates.append(obj)
            except InvalidReccmpReportError:
                logger.warning("Skipping '%s' due to import error", path)

    return candidates


def get_accuracy(report: ReccmpStatusReport, addr: str) -> float:
    if addr in report.entities:
        return report.entities[addr].accuracy

    return 0.0


def combine_sample_files(
    starter: ReccmpStatusReport, samples: list[ReccmpStatusReport]
) -> ReccmpStatusReport:
    """Combines the sample reports into a single report for comparison.
    Uses the starter report because we defer to its value if we detect entropy."""

    output = ReccmpStatusReport()
    output.filename = starter.filename

    # Combine every orig addr used in any of the files.
    orig_addr_set = set(starter.entities.keys())
    for sample in samples:
        orig_addr_set = orig_addr_set | sample.entities.keys()

    all_orig_addrs = sorted(list(orig_addr_set))

    # TODO: use new names from recomp files?

    # Now we make a determination for each orig addr.
    for addr in all_orig_addrs:
        if addr not in starter.entities:
            # This is a new entity, which means this diff is not noise.
            # Use the entry from the first sample that has this addr.
            for sample in samples:
                if addr in sample.entities:
                    output.entities[addr] = sample.entities[addr]
                    break
            continue

        starter_entry = starter.entities[addr]

        # Match percentage for this entry from each sample.
        # Ignore effective match bool: this is the noise we want to eliminate.
        sample_accuracy = [get_accuracy(s, addr) for s in samples]

        samples_are_alike = all(v == sample_accuracy[0] for v in sample_accuracy)

        # If the accuracy is the same for all samples, use the new value.
        if samples_are_alike:
            new_entry = samples[0].entities[addr]

            # Hack: use starter value here so entropy section (e.g. 100% -> 100%*) is empty in the diff.
            # But don't log an effective match unless the new accuracy is 100%.
            is_effective = new_entry.accuracy == 1.0 and starter_entry.is_effective

            output.entities[addr] = ReccmpComparedEntity(
                orig_addr=addr,
                name=new_entry.name,
                accuracy=new_entry.accuracy,
                is_effective=is_effective,
                is_stub=new_entry.is_stub,
            )

        else:
            # Defer to starter value. No diff registered for this entry.
            output.entities[addr] = starter_entry

    return output


def main():
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Compare saved accuracy reports.",
    )
    parser.add_argument("--A", type=Path, metavar="<file>", help="Starting file.")
    parser.add_argument(
        "--B",
        type=Path,
        metavar="<files>",
        nargs="+",
        help="Target file(s).",
        required=True,
    )
    parser.add_argument(
        "--no-color", "-n", action="store_true", help="Do not color the output"
    )

    args = parser.parse_args()

    try:
        saved_data = load_report_file(args.A)
    except InvalidReccmpReportError:
        logger.error("Could not load starting file %s", args.A)
        return 1

    candidates = get_candidate_list(args.B, args.A)

    if len(candidates) == 0:
        logger.error("No files to sample!")
        return 1

    if len(candidates) == 1:
        # Standard diff
        diff_json(
            saved_data, candidates[0], show_both_addrs=False, is_plain=args.no_color
        )
        return 0

    # hack
    assert all(saved_data.filename == c.filename for c in candidates)

    new_data = combine_sample_files(saved_data, candidates)
    diff_json(saved_data, new_data, show_both_addrs=False, is_plain=args.no_color)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
