#!/usr/bin/env python3

import os
import argparse
import logging
from typing import List
import colorama
import reccmp
from reccmp.isledecomp.bin import Bin as IsleBin
from reccmp.isledecomp.compare import Compare as IsleCompare
from reccmp.isledecomp.utils import print_combined_diff

# Ignore all compare-db messages.
logging.getLogger("isledecomp.compare").addHandler(logging.NullHandler())

colorama.just_fix_windows_console()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Comparing vtables.")
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {reccmp.VERSION}"
    )
    parser.add_argument(
        "original", metavar="original-binary", help="The original binary"
    )
    parser.add_argument(
        "recompiled", metavar="recompiled-binary", help="The recompiled binary"
    )
    parser.add_argument(
        "pdb", metavar="recompiled-pdb", help="The PDB of the recompiled binary"
    )
    parser.add_argument(
        "decomp_dir", metavar="decomp-dir", help="The decompiled source tree"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show more detailed information"
    )
    parser.add_argument(
        "--no-color", "-n", action="store_true", help="Do not color the output"
    )

    (args, _) = parser.parse_known_args()

    if not os.path.isfile(args.original):
        parser.error(f"Original binary {args.original} does not exist")

    if not os.path.isfile(args.recompiled):
        parser.error(f"Recompiled binary {args.recompiled} does not exist")

    if not os.path.isfile(args.pdb):
        parser.error(f"Symbols PDB {args.pdb} does not exist")

    if not os.path.isdir(args.decomp_dir):
        parser.error(f"Source directory {args.decomp_dir} does not exist")

    return args


def show_vtable_diff(udiff: List, _: bool = False, plain: bool = False):
    print_combined_diff(udiff, plain)


def print_summary(vtable_count: int, problem_count: int):
    if problem_count == 0:
        print(f"Vtables found: {vtable_count}.\n100% match.")
        return

    print(f"Vtables found: {vtable_count}.\nVtables not matching: {problem_count}.")


def main():
    args = parse_args()
    vtable_count = 0
    problem_count = 0

    with IsleBin(args.original) as orig_bin, IsleBin(args.recompiled) as recomp_bin:
        engine = IsleCompare(orig_bin, recomp_bin, args.pdb, args.decomp_dir)

        for tbl_match in engine.compare_vtables():
            vtable_count += 1
            if tbl_match.ratio < 1:
                problem_count += 1

                udiff = list(tbl_match.udiff)

                print(
                    tbl_match.name,
                    f": orig 0x{tbl_match.orig_addr:x}, recomp 0x{tbl_match.recomp_addr:x}",
                )
                show_vtable_diff(udiff, args.verbose, args.no_color)
                print()

        print_summary(vtable_count, problem_count)

        # Now compare adjuster thunk functions, if there are any.
        # These matches are generated by the compare engine.
        # They should always match 100%. If not, there is a problem
        # with the inheritance or an overriden function.
        for fun_match in engine.get_functions():
            if "`vtordisp" not in fun_match.name:
                continue

            diff = engine.compare_address(fun_match.orig_addr)
            if diff.ratio < 1.0:
                problem_count += 1
                print(
                    f"Problem with adjuster thunk {fun_match.name} (0x{fun_match.orig_addr:x} / 0x{fun_match.recomp_addr:x})"
                )

    return 1 if problem_count > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
