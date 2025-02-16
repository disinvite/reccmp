#!/usr/bin/env python3

import argparse
import json
import logging
from pathlib import Path
from reccmp.isledecomp.utils import diff_json


logger = logging.getLogger(__name__)


class InvalidReccmpReportError(Exception):
    """The given file is not a serialized reccmp report file"""


def load_report_file(report_path: Path) -> dict:
    """Deserialize from JSON at the given filename and return the report."""
    try:
        with report_path.open("r", encoding="utf-8") as f:
            obj = json.load(f)
    except json.decoder.JSONDecodeError as ex:
        raise InvalidReccmpReportError from ex

    # Rough estimate of whether this is a valid file
    if "timestamp" not in obj or "format" not in obj:
        raise InvalidReccmpReportError

    # Add this key so we can distinguish the files later.
    obj["report_filename"] = report_path.name
    return obj


def get_candidate_list(paths: list[Path], start_file: Path | None = None) -> list[dict]:
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


def use_orig_addr_as_key(data: list[dict]) -> dict:
    """Converts the list of dicts with key "address" into a dict keyed by the address."""
    # TODO: The file should already be in this format. (Version 2)
    # The database will ensure that there are no duplicate orig addrs.

    return {obj["address"]: obj for obj in data}


def get_matching(obj: dict | None) -> float:
    if obj is None:
        return 0.0

    return obj["matching"]


def combine_sample_files(starter: dict, samples: list[dict]) -> dict:
    """Combines the sample reports into a single report for comparison.
    Uses the starter report because we defer to its value if we detect entropy."""

    starter_invert = use_orig_addr_as_key(starter["data"])
    samples_invert = [use_orig_addr_as_key(sample["data"]) for sample in samples]

    # Combine every orig addr used in any of the files.
    orig_addr_set = set(starter_invert.keys())
    for sample in samples_invert:
        orig_addr_set = orig_addr_set | sample.keys()

    all_orig_addrs = sorted(list(orig_addr_set))

    # Data converted back to the serialized format to be passed into diff_json.
    data = []

    # TODO: use new names from recomp files?

    # Now we make a determination for each orig addr.
    for addr in all_orig_addrs:
        # TODO: If addr not in starter_invert --> new function

        starter_entry = starter_invert[addr]

        # Match percentage for this entry from each sample.
        # Ignore effective match bool: this is the noise we want to eliminate.
        sample_accuracy = [get_matching(s.get(addr)) for s in samples_invert]

        samples_are_alike = all(v == sample_accuracy[0] for v in sample_accuracy)

        # If the accuracy is the same for all samples, use the new value.
        if samples_are_alike:
            new_entry = samples_invert[0][addr]

            # Hack: use starter value here so entropy section (e.g. 100% -> 100%*) is empty in the diff.
            # But don't log an effective match unless the new accuracy is 100%.
            is_effective = new_entry["matching"] == 1.0 and starter_entry.get(
                "effective", False
            )

            output = {
                "address": addr,
                "name": new_entry["name"],
                "matching": new_entry["matching"],
                "effective": is_effective,
                "stub": new_entry.get("stub", False),
            }

            data.append(output)
            continue

        # Else: Defer to starter value. No diff registered for this entry.
        if addr in starter_invert:
            output = {
                "address": addr,
                # "recomp": starter_entry["recomp"],
                "name": starter_entry["name"],
                "matching": starter_entry["matching"],
                "effective": starter_entry.get("effective", False),
                "stub": starter_entry.get("stub", False),
            }

            data.append(output)

    return {"file": starter["file"], "format": starter["format"], "data": data}


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
    assert all(saved_data["file"] == c["file"] for c in candidates)
    assert all(saved_data["format"] == c["format"] for c in candidates)

    new_data = combine_sample_files(saved_data, candidates)
    diff_json(saved_data, new_data, show_both_addrs=False, is_plain=args.no_color)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
