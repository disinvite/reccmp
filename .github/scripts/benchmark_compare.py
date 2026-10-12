import argparse
import logging
import sys
from pathlib import Path
from time import process_time_ns

from reccmp.compare import Compare
from reccmp.project.detect import (
    RecCmpProjectException,
    argparse_add_project_target_args,
    argparse_parse_project_target,
)

RUNS = 25

# Ignore all compare-db messages.
logging.getLogger("reccmp.compare").addHandler(logging.NullHandler())


def main() -> int:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Time Compare.from_target() and Compare.to_report() in nanoseconds.",
    )
    argparse_add_project_target_args(parser)
    parser.add_argument("--runs", type=int, default=RUNS)
    parser.add_argument("--output", type=Path, default=Path("times"))
    args = parser.parse_args()

    try:
        target = argparse_parse_project_target(args)
    except RecCmpProjectException as e:
        print(e.args[0], file=sys.stderr)
        return 1

    from_target = []
    to_report = []

    for _ in range(args.runs):
        start = process_time_ns()
        compare = Compare.from_target(target)
        loaded = process_time_ns()
        compare.to_report(filename=target.original_path.name)
        done = process_time_ns()
        from_target.append(loaded - start)
        to_report.append(done - loaded)

    for phase, times in (("from_target", from_target), ("to_report", to_report)):
        path = args.output.with_name(f"{args.output.name}-{phase}.txt")
        path.write_text("\n".join(str(t) for t in times) + "\n", encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
