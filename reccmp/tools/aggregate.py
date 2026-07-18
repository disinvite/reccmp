#!/usr/bin/env python3

import sys
import argparse
import logging
from typing import Sequence
from pathlib import Path
from reccmp.report.operations import (
    ReportToolArgs,
    report_tool,
    load_report_file,
)
from reccmp.compare.report import (
    ReccmpStatusReport,
    combine_reports,
    ReccmpReportDeserializeError,
    ReccmpReportSameSourceError,
)

logger = logging.getLogger(__name__)


def deserialize_sample_files(paths: list[Path]) -> list[ReccmpStatusReport]:
    """Deserialize all sample files and return the list of reports.
    Does not remove duplicates."""
    samples = []

    for path in paths:
        if path.is_file():
            try:
                report = load_report_file(path)
                samples.append(report)
            except ReccmpReportDeserializeError:
                logger.warning("Skipping '%s' due to import error", path)
        elif not path.exists():
            logger.warning("File not found: '%s'", path)

    return samples


class TwoOrMoreArgsAction(argparse.Action):
    """Support nargs=2+"""

    def __call__(
        self, parser, namespace, values: Sequence[str] | None, option_string=None
    ):
        assert isinstance(values, Sequence)
        if len(values) < 2:
            raise argparse.ArgumentError(self, "expected two or more arguments")

        setattr(namespace, self.dest, values)


class TwoOrFewerArgsAction(argparse.Action):
    """Support nargs=(1,2)"""

    def __call__(
        self, parser, namespace, values: Sequence[str] | None, option_string=None
    ):
        assert isinstance(values, Sequence)
        if len(values) not in (1, 2):
            raise argparse.ArgumentError(self, "expected one or two arguments")

        setattr(namespace, self.dest, values)


def parse_args(argv: list[str]) -> argparse.Namespace:
    if len(argv) > 1:
        prog = Path(argv[0]).stem
    else:
        prog = None  # defer to sys.argv

    parser = argparse.ArgumentParser(
        prog=prog,
        allow_abbrev=False,
        description="Aggregate saved accuracy reports.",
        fromfile_prefix_chars="@",
    )
    parser.add_argument(
        "--diff",
        type=Path,
        metavar="<files>",
        nargs="+",
        action=TwoOrFewerArgsAction,
        help="Report files to diff.",
    )
    parser.add_argument(
        "--html",
        type=Path,
        metavar="<file>",
        help="Location for HTML report based on aggregate.",
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
        action=TwoOrMoreArgsAction,
        help="Report files to aggregate.",
    )
    parser.add_argument(
        "--svg",
        "-S",
        type=Path,
        metavar="<file>",
        help="Generate SVG graphic of aggregate progress.",
    )
    parser.add_argument(
        "--svg-icon",
        metavar="icon",
        type=Path,
        help="Icon to use in SVG (PNG)",
    )
    parser.add_argument(
        "--total",
        "-T",
        type=int,
        metavar="<count>",
        help="Total number of expected functions (improves total accuracy statistic)",
    )
    parser.add_argument(
        "--no-color", "-n", action="store_true", help="Do not color the output"
    )

    args = parser.parse_args(argv[1:])

    if not (args.samples or args.diff):
        parser.error(
            "expected arguments for --samples or --diff. (No input files specified)"
        )

    if not (args.output or args.diff or args.html or args.svg):
        parser.error(
            "expected arguments for --output, --html, --svg, or --diff. (No output action specified)"
        )

    if args.svg and not args.samples:
        parser.error("--svg requires --samples to aggregate from")

    if args.diff and len(args.diff) == 1 and not args.samples:
        parser.error("--diff expects two report files")

    return args


def main():
    args = parse_args(sys.argv)

    input_report: ReccmpStatusReport | None = None
    input_diff: ReccmpStatusReport | None = None

    if args.samples is not None:
        samples = deserialize_sample_files(args.samples)

        if len(samples) < 2:
            logger.error("Not enough samples to aggregate!")
            return 1

        try:
            input_report = combine_reports(samples)
        except ReccmpReportSameSourceError:
            filename_list = sorted({s.filename for s in samples})
            logger.error(
                "Aggregate samples are not from the same source file!\nFilenames used: %s",
                filename_list,
            )
            return 1

    # If --diff has at least one file and we aggregated some samples this run, diff the first file and the aggregate.
    # If --diff has two files and we did not aggregate this run, diff the files in the list.
    if args.diff is not None:
        first_diff_report = load_report_file(args.diff[0])

        if input_report is None:
            if len(args.diff) > 1:
                input_report = first_diff_report
                input_diff = load_report_file(args.diff[1])
            else:
                logger.error("Not enough files to diff!")
                return 1
        elif len(args.diff) == 2:
            logger.warning(
                "Ignoring second --diff argument '%s'.\nDiff of '%s' and aggregate report follows.",
                args.diff[1],
                args.diff[0],
            )
        else:
            input_diff = first_diff_report

    if input_report is None:
        logger.error("Failed to generate aggregate!")
        return 1

    report_tool(
        ReportToolArgs(
            input_report=input_report,
            input_diff=input_diff,
            input_icon=args.svg_icon,
            input_total=args.total,
            output_svg=args.svg,
            output_json=args.output,
            output_html=args.html,
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
