#!/usr/bin/env python3

from datetime import datetime
from pathlib import Path
import argparse
import logging
import os
import time
from urllib.error import URLError

import colorama
from pydantic import TypeAdapter
import reccmp
from reccmp.utils import (
    gen_svg,
    diff_json,
    percent_string,
    print_match_verbose,
    safe_denominator,
    write_html_report,
)

from reccmp.compare import Compare
from reccmp.compare.db import ReccmpEntity
from reccmp.compare.report import (
    ReccmpStatusReport,
    ReccmpComparedEntity,
    deserialize_reccmp_report,
    serialize_reccmp_report,
    report_function_alignment,
    report_function_accuracy,
    format_address,
)
from reccmp.types import EntityType
from reccmp.project.logging import (
    argparse_add_logging_args,
    argparse_parse_logging,
)
from reccmp.project.detect import (
    RecCmpProject,
    RecCmpProjectException,
    argparse_add_project_target_args,
    argparse_parse_project_target,
    verify_target_paths,
)
from reccmp.remote import connect, http_get

logger = logging.getLogger()
colorama.just_fix_windows_console()


def gen_json(json_file: str, json_str: str):
    """Convert the status report to JSON and write to a file."""

    with open(json_file, "w", encoding="utf-8") as f:
        f.write(json_str)


def print_match_oneline(match: ReccmpComparedEntity, show_both_addrs: bool = False):
    percenttext = percent_string(match.effective_accuracy, match.is_effective_match)

    if show_both_addrs and match.recomp_addr is not None:
        addrs = (
            f"{format_address(match.orig_addr)} / {format_address(match.recomp_addr)}"
        )
    else:
        addrs = format_address(match.orig_addr)

    if match.is_stub:
        print(f"  {match.name} ({addrs}) is a stub.")
    else:
        print(f"  {match.name} ({addrs}) is {percenttext} similar to the original")


def parse_args() -> argparse.Namespace:
    def virtual_address(value) -> int:
        """Helper method for argparse, verbose parameter"""
        return int(value, 16)

    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Recompilation Compare: compare an original EXE with a recompiled EXE + PDB.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {reccmp.VERSION}"
    )
    argparse_add_project_target_args(parser)
    parser.add_argument(
        "--total",
        "-T",
        metavar="<count>",
        type=int,
        help="Total number of expected functions (improves total accuracy statistic)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        metavar="<offset>",
        type=virtual_address,
        help="Print assembly diff for specific function (original file's offset)",
    )
    parser.add_argument(
        "--json",
        metavar="<file>",
        help="Generate JSON file with match summary",
    )
    parser.add_argument(
        "--json-diet",
        action="store_true",
        help="Exclude diff from JSON report.",
    )
    parser.add_argument(
        "--diff",
        metavar="<file>",
        help="Diff against summary in JSON file",
    )
    parser.add_argument(
        "--dump",
        action="store_true",
        help="Write decompiled assembly to debug files.",
    )
    parser.add_argument(
        "--html",
        "-H",
        metavar="<file>",
        help="Generate searchable HTML summary of status and diffs",
    )
    parser.add_argument(
        "--no-color", "-n", action="store_true", help="Do not color the output"
    )
    parser.add_argument(
        "--svg", "-S", metavar="<file>", help="Generate SVG graphic of progress"
    )
    parser.add_argument(
        "--svg-icon", metavar="icon", type=Path, help="Icon to use in SVG (PNG)"
    )
    parser.add_argument(
        "--print-rec-addr",
        action="store_true",
        help="Print addresses of recompiled functions too",
    )
    parser.add_argument(
        "--silent",
        action="store_true",
        help="Don't display text summary of matches",
    )
    parser.add_argument(
        "--nolib",
        action="store_true",
        help="Exclude LIBRARY annotations from the analysis",
    )
    remote_group = parser.add_argument_group(title="Remote viewing")
    remote_group.add_argument(
        "--daemon",
        action="store_true",
        help="Get results from a reccmp-daemon for the target, starting it if needed",
    )
    remote_group.add_argument(
        "--port",
        type=int,
        metavar="<port>",
        help="Port for the daemon (default: the saved port, or one chosen by the daemon)",
    )
    remote_group.add_argument(
        "--restart",
        action="store_true",
        help="Stop the server if it is running, then start a new one",
    )
    argparse_add_logging_args(parser)

    args = parser.parse_args()
    argparse_parse_logging(args)

    if not args.daemon and (args.port is not None or args.restart):
        parser.error("--port and --restart require --daemon")

    if args.daemon and args.target is None:
        parser.error("--daemon requires --target")

    return args


def remote_main(args: argparse.Namespace) -> int:
    if args.verbose is None:
        logger.error("Only --verbose is supported with --daemon")
        return 1

    try:
        project = RecCmpProject.from_directory(Path.cwd())
        verify_target_paths(project.get(args.target))
    except RecCmpProjectException as e:
        logger.error("%s", e.args[0])
        return 1

    base_url = connect(project, args.target, port=args.port, restart=args.restart)
    if base_url is None:
        logger.error("Could not start reccmp-daemon")
        return 1

    print()

    for retry in range(10):
        try:
            status, body = http_get(f"{base_url}/addr/{args.verbose}")
        except (URLError, TimeoutError):
            status, body = (0, b"")

        if status == 200:
            match = TypeAdapter(ReccmpComparedEntity).validate_json(body)
            print_match_verbose(match, show_both_addrs=args.print_rec_addr)
            return 0

        if status == 404:
            logger.error("Failed to find a match at address 0x%x", args.verbose)
            return 1

        print(f"Server is not ready. Waiting a second. ({retry + 1})")
        time.sleep(1)

    logger.error("Max retries reached. Server may be stuck.")
    return 1


def dump_all_matched_functions(report: ReccmpStatusReport):
    logger.info("Creating assembly dump files.")
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    # Extract instructions from each compared entity in both address spaces.
    orig_items = [
        (entity.orig_addr, entity.name, entity.rdiff.orig_inst)
        for entity in report.entities.values()
        if entity.recomp_addr is not None and entity.rdiff is not None
    ]

    # mypy: recomp_addr can be None, but not for the matched entities we are reviewing.
    recomp_items = [
        (entity.recomp_addr, entity.name, entity.rdiff.recomp_inst)
        for entity in report.entities.values()
        if entity.recomp_addr is not None and entity.rdiff is not None
    ]

    # Sort by each binary's address order
    orig_items.sort(key=lambda v: v[0])
    recomp_items.sort(key=lambda v: v[0])

    orig_filename = f"reccmp-{timestamp}-orig.txt"
    recomp_filename = f"reccmp-{timestamp}-recomp.txt"

    for filename, vitals in (
        (orig_filename, orig_items),
        (recomp_filename, recomp_items),
    ):
        with open(filename, "w+", encoding="utf-8") as f:
            for _, name, instructions in vitals:
                f.write(f"; {name}\n")
                for addr, line in instructions:
                    if addr:
                        f.write(f"{addr:10}: {line}\n")
                    else:
                        f.write(f"        : {line}\n")


def main() -> int:
    args = parse_args()

    if args.daemon:
        return remote_main(args)

    try:
        target = argparse_parse_project_target(args)
    except RecCmpProjectException as e:
        logger.error("%s", e.args[0])
        return 1

    logging.basicConfig(level=args.loglevel, format="[%(levelname)s] %(message)s")

    compare = Compare.from_target(target)

    print()

    ### Compare one or none.

    if args.verbose is not None:
        match = compare.compare_address(args.verbose)
        if match is None:
            logger.error("Failed to find a match at address 0x%x", args.verbose)
            return 1

        print_match_verbose(match, show_both_addrs=args.print_rec_addr)
        return 0

    ### Compare everything.

    def entity_filter(entity: ReccmpEntity) -> bool:
        if (
            entity.entity_type == EntityType.FUNCTION
            and entity.name in target.report_config.ignore_functions
        ):
            return False

        if args.nolib and entity.get("library"):
            return False

        return True

    report = compare.to_report(
        filename=target.original_path.name, filter_fn=entity_filter
    )

    if args.dump:
        dump_all_matched_functions(report)

    # If we know how many functions are in the file (via analysis with Ghidra or other tools)
    # we can substitute an alternate value to use when calculating the percentages below.
    if args.total:
        # Use the alternate value if it exceeds the number of known functions
        report.function_count = max(report.function_count, int(args.total))

    # Count how many functions have the same virtual address in orig and recomp.
    functions_aligned_count = report_function_alignment(report)

    # Number of functions compared (i.e. excluding stubs)
    implemented_funcs, _, total_effective_accuracy = report_function_accuracy(report)

    # Print diff summary to terminal
    if not args.silent and args.diff is None:
        for entity in report.entities.values():
            if entity.is_matched():
                print_match_oneline(entity, show_both_addrs=args.print_rec_addr)

    # Compare with saved diff report.
    if args.diff is not None:
        try:
            with open(args.diff, "r", encoding="utf-8") as f:
                saved_data = deserialize_reccmp_report(f.read())

            saved_data.asmcmp_filtering(
                args.nolib, target.report_config.ignore_functions
            )

            diff_json(
                saved_data,
                report,
                show_both_addrs=args.print_rec_addr,
            )
        except FileNotFoundError:
            # In a CI workflow, the JSON file might not exist on the first run in a new branch.
            # Continue without a fatal error so users don't have to bother handling this situation.
            logger.error("Could not open JSON report file '%s' for diff", args.diff)

    ## Generate files and show summary.

    if args.json is not None:
        # If we're on a diet, hold the diff.
        diff_included = not bool(args.json_diet)
        gen_json(
            args.json, serialize_reccmp_report(report, diff_included=diff_included)
        )

    target_icon = args.svg_icon or target.report_config.icon

    if args.html is not None:
        write_html_report(args.html, report, target_icon)

    report.update_function_count()
    function_count = report.function_count

    implemented = implemented_funcs / safe_denominator(function_count) * 100

    effective_accuracy = (
        total_effective_accuracy / safe_denominator(implemented_funcs) * 100
    )
    progress = total_effective_accuracy / safe_denominator(function_count) * 100
    alignment_percentage = (
        functions_aligned_count / safe_denominator(function_count) * 100
    )

    print(
        f"\nImplemented:  {implemented:.2f}%  ({implemented_funcs} / {function_count})"
    )
    print(f"Accuracy:     {effective_accuracy:.2f}%")
    print(f"Progress:     {progress:.2f}%")

    if functions_aligned_count > 0:
        print(
            f"{functions_aligned_count} functions are aligned ({alignment_percentage:.2f}%)"
        )

    if args.svg is not None:
        gen_svg(
            args.svg,
            os.path.basename(target.original_path),
            target_icon,
            implemented_funcs,
            function_count,
            total_effective_accuracy,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
