import argparse
import statistics
from pathlib import Path

BIN_WIDTH = 100_000_000
WIDTH = 40


def read_times(paths: list[Path]) -> list[int]:
    times = []
    for path in paths:
        for line in path.read_text(encoding="utf-8").split():
            times.append(int(line))

    return times


def seconds(ns: float) -> str:
    return f"{ns / 1_000_000_000:.3f}s"


def split_outliers(times: list[int]) -> tuple[list[int], list[int]]:
    if len(times) < 4:
        return times, []

    q1, _, q3 = statistics.quantiles(times, n=4)
    iqr = q3 - q1
    low = q1 - 1.5 * iqr
    high = q3 + 1.5 * iqr

    keep = [t for t in times if low <= t <= high]
    drop = [t for t in times if t < low or t > high]
    return keep, drop


def histogram(times: list[int]) -> list[str]:
    low = min(times) // BIN_WIDTH * BIN_WIDTH
    bins = (max(times) - low) // BIN_WIDTH + 1

    counts = [0] * bins
    for t in times:
        counts[(t - low) // BIN_WIDTH] += 1

    tallest = max(counts)
    lines = []
    for i, count in enumerate(counts):
        bar_chars = "#" * round(count * WIDTH / tallest)
        lines.append(
            f"{seconds(low + i * BIN_WIDTH):>8} |{bar_chars:<{WIDTH}}| {count}"
        )

    return lines


def main():
    parser = argparse.ArgumentParser(description="Summarize benchmark sample times.")
    parser.add_argument("files", type=Path, nargs="+", help="Files of times in ns")
    args = parser.parse_args()

    times = read_times(args.files)
    if not times:
        parser.error("no samples")

    keep, drop = split_outliers(times)

    print(f"samples:  {len(times)}")
    print(f"outliers: {', '.join(seconds(t) for t in sorted(drop)) or 'none'}")
    print(f"average:  {seconds(statistics.fmean(keep))}")
    print(f"median:   {seconds(statistics.median(keep))}")
    print(f"minimum:  {seconds(min(keep))}")
    print(f"maximum:  {seconds(max(keep))}")
    print()
    for i, path in enumerate(args.files, 1):
        samples = read_times([path])
        print(
            f"{i:3d}: {len(samples)} samples, {seconds(min(samples))} - {seconds(max(samples))}"
        )
    print()
    print("\n".join(histogram(keep)))


if __name__ == "__main__":
    main()
