from dataclasses import dataclass
from pathlib import Path
from reccmp.utils import (
    diff_json,
    gen_svg,
    write_html_report,
)
from reccmp.compare.report import (
    ReccmpStatusReport,
    report_progress_stats,
    serialize_reccmp_report,
    deserialize_reccmp_report,
)


def write_report_file(
    output_file: Path, report: ReccmpStatusReport, diff_included: bool = True
):
    """Convert the status report to JSON and write to a file."""
    json_str = serialize_reccmp_report(report, diff_included=diff_included)

    with open(output_file, "w+", encoding="utf-8") as f:
        f.write(json_str)


def load_report_file(report_path: Path) -> ReccmpStatusReport:
    """Deserialize from JSON at the given filename and return the report."""

    with report_path.open("r", encoding="utf-8") as f:
        return deserialize_reccmp_report(f.read())


@dataclass
class ReportToolArgs:
    # pylint: disable=too-many-instance-attributes
    input_report: ReccmpStatusReport
    input_diff: ReccmpStatusReport | None
    input_icon: Path | None
    input_total: int | None
    #
    output_svg: Path | None
    output_json: Path | None
    output_html: Path | None
    #
    diff_included: bool = True
    terminal_both_addrs: bool = False


def report_tool(args: ReportToolArgs):
    if args.output_json is not None:
        write_report_file(args.output_json, args.input_report, args.diff_included)

    if args.output_html is not None:
        # TODO: use diff_included param
        write_html_report(str(args.output_html), args.input_report, args.input_icon)

    if args.output_svg is not None:
        implemented_funcs, raw_accuracy = report_progress_stats(args.input_report)
        # TODO: if implemented_funcs == 0 ?

        total_funcs = max(implemented_funcs, args.input_total or 0)
        gen_svg(
            str(args.output_svg),
            args.input_report.filename,
            args.input_icon,
            implemented_funcs,
            total_funcs,
            raw_accuracy,
        )

    if args.input_diff is not None:
        diff_json(
            args.input_report, args.input_diff, show_both_addrs=args.terminal_both_addrs
        )
