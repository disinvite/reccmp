#!/usr/bin/env python3

import argparse
import logging
from pathlib import Path
import colorama
import reccmp
from reccmp.isledecomp.dir import walk_source_dir, is_file_c_like
from reccmp.isledecomp.parser import DecompLinter
from reccmp.isledecomp.parser.error import ParserAlert
from reccmp.project.logging import argparse_add_logging_args, argparse_parse_logging
from reccmp.project.detect import RecCmpProject, RecCmpProjectException

logger = logging.getLogger(__name__)

colorama.just_fix_windows_console()


def display_errors(alerts: list[ParserAlert], filename: Path):
    sorted_alerts = sorted(alerts, key=lambda a: a.line_number)

    print(colorama.Fore.LIGHTWHITE_EX, end="")
    # Remove any backrefs from the path
    print(filename.resolve())

    for alert in sorted_alerts:
        error_type = (
            f"{colorama.Fore.RED}error: "
            if alert.is_error()
            else f"{colorama.Fore.YELLOW}warning: "
        )
        components = [
            "  ",
            colorama.Fore.LIGHTWHITE_EX,
            f"{alert.line_number:4}",
            " : ",
            error_type,
            colorama.Fore.LIGHTWHITE_EX,
            alert.code.name.lower(),
            colorama.Fore.LIGHTBLACK_EX,
            f" ({alert.module})" if alert.module else "",
        ]
        print("".join(components), end="")

        if alert.line is not None:
            print(f"{colorama.Fore.WHITE}  {alert.line}", end="")

        print()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Syntax checking and linting for decomp annotation markers."
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {reccmp.VERSION}"
    )
    parser.add_argument("--target", metavar="<target-id>", help="ID of the target")
    parser.add_argument(
        "paths",
        metavar="<path>",
        nargs="*",
        type=Path,
        help="The file or directory to check.",
    )
    parser.add_argument(
        "--module",
        required=False,
        type=str,
        help="If present, run targeted checks for markers from the given module.",
    )
    parser.add_argument(
        "--warnfail",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Fail if syntax warnings are found.",
    )
    argparse_add_logging_args(parser)

    args = parser.parse_args()

    argparse_parse_logging(args)

    return args


def process_files(files: set[Path], module: str | None = None):
    warning_count = 0
    error_count = 0

    linter = DecompLinter()
    # Sort the set so the order is consistent.
    for filename in sorted(files):
        success = linter.check_file(filename, module)

        warnings = [a for a in linter.alerts if a.is_warning()]
        errors = [a for a in linter.alerts if a.is_error()]

        error_count += len(errors)
        warning_count += len(warnings)

        if not success:
            display_errors(linter.alerts, filename)
            print()

    return (warning_count, error_count)


def main():
    args = parse_args()

    # Targets may share a common file path.
    # Use set() so each file is only checked once.
    files_to_check: set[Path] = set()

    if not args.paths:
        # No path(s) specified. Try to find the project file.
        project = RecCmpProject.from_directory(directory=Path.cwd())
        if not project:
            logger.error("Cannot find reccmp project")
            return 1

        if args.target:
            try:
                target = project.get(args.target)
            except RecCmpProjectException as e:
                logger.error("%s", e.args[0])
                return 1

            files_to_check.update(walk_source_dir(target.source_root))
        else:
            # Read each target from the reccmp-project file
            # then get all filenames from each code directory.
            for partial_target in project.targets.values():
                if partial_target.source_root:
                    files_to_check.update(walk_source_dir(partial_target.source_root))
    else:
        for path in args.paths:
            if path.is_dir():
                files_to_check.update(walk_source_dir(path))
            elif path.is_file() and is_file_c_like(path):
                files_to_check.add(path)
            else:
                logger.error("Invalid path: %s", path)

    # If we are here and args.target is set, the target is valid for the project.
    module = args.target if args.target else args.module
    (warning_count, error_count) = process_files(files_to_check, module=module)

    print(colorama.Style.RESET_ALL, end="")

    if module is None:
        logger.warning("No module specified. We did not verify function address order.")

    return error_count > 0 or (warning_count > 0 and args.warnfail)


if __name__ == "__main__":
    raise SystemExit(main())
