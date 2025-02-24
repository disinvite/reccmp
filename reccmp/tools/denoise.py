#!/usr/bin/env python3

import argparse
import json
import logging
from pathlib import Path
from reccmp.isledecomp.utils import diff_json
from reccmp.isledecomp.compare.report import (
    ReccmpStatusReport,
    deserialize_reccmp_report,
    serialize_reccmp_report,
)


logger = logging.getLogger(__name__)


class InvalidReccmpReportError(Exception):
    """The given file is not a serialized reccmp report file"""


def write_report_file(output_file: Path, report: ReccmpStatusReport):
    """Convert the status report to JSON and write to a file."""
    json_obj = serialize_reccmp_report(report)

    with open(output_file, "w+", encoding="utf-8") as f:
        json.dump(json_obj, f)


def load_report_file(report_path: Path) -> ReccmpStatusReport:
    """Deserialize from JSON at the given filename and return the report."""

    with report_path.open("r", encoding="utf-8") as f:
        return deserialize_reccmp_report(json.load(f))


def deserialize_sample_files(paths: list[Path]) -> list[ReccmpStatusReport]:
    """Deserialize all sample files and return the list of reports.
    Does not remove duplicates."""
    samples = []

    for path in paths:
        if path.is_file():
            try:
                report = load_report_file(path)
                samples.append(report)
            except InvalidReccmpReportError:
                logger.warning("Skipping '%s' due to import error", path)

    return samples


def get_accuracy(report: ReccmpStatusReport, addr: str) -> float:
    if addr in report.entities:
        return report.entities[addr].accuracy

    return 0.0


def combine_sample_files(samples: list[ReccmpStatusReport]) -> ReccmpStatusReport:
    """Combines the sample reports into a single report for comparison."""
    assert len(samples) > 0

    output = ReccmpStatusReport(filename=samples[0].filename)

    # Combine every orig addr used in any of the files.
    orig_addr_set: set[str] = set()
    for sample in samples:
        orig_addr_set = orig_addr_set | sample.entities.keys()

    all_orig_addrs = sorted(list(orig_addr_set))

    for addr in all_orig_addrs:
        assert any(addr in sample.entities for sample in samples)

        # Find the first sample that used this addr to populate data for the new report.
        for sample in samples:
            if addr in sample.entities:
                # Set up our data
                output.entities[addr] = sample.entities[addr]
                break

        # Our aggregate accuracy score is the highest from any report.
        sample_accuracy = [get_accuracy(s, addr) for s in samples]
        agg_accuracy = max(sample_accuracy)

        output.entities[addr].accuracy = agg_accuracy
        output.entities[addr].recomp_addr = None  # ?
        output.entities[addr].is_effective_match = False  # ?

    return output


def main():
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Aggregate saved accuracy reports.",
    )
    parser.add_argument(
        "--diff", type=Path, metavar="<files>", nargs="+", help="Report files to diff."
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        metavar="<file>",
        help="Where to save the aggregate file.",
    )
    parser.add_argument(
        "--samples",
        type=Path,
        metavar="<files>",
        nargs="+",
        help="Report files to aggregate.",
    )
    parser.add_argument(
        "--no-color", "-n", action="store_true", help="Do not color the output"
    )

    args = parser.parse_args()

    agg_report: ReccmpStatusReport | None = None

    if args.samples is not None:
        samples = deserialize_sample_files(args.samples)

        if len(samples) < 2:
            logger.error("Not enough samples to aggregate!")
            return 1

        # hack
        assert all(samples[0].filename == s.filename for s in samples)
        agg_report = combine_sample_files(samples)

        if args.output is not None:
            write_report_file(args.output, agg_report)

    # If --diff has at least one file and we aggregated some samples this run, diff the first file and the aggregate.
    # If --diff has two or more files and we did not aggregate this run, diff the first two files in the list.
    if args.diff is not None:
        saved_data = load_report_file(args.diff[0])

        if agg_report is None:
            if len(args.diff) > 1:
                agg_report = load_report_file(args.diff[1])
            else:
                logger.error("Not enough files to diff!")
                return 1

        diff_json(saved_data, agg_report, show_both_addrs=False, is_plain=args.no_color)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
