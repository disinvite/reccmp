import argparse
import math
import statistics
from pathlib import Path

BIN_WIDTH = 0.1
WIDTH = 40


def read_times(paths: list[Path]) -> list[float]:
    times = []
    for path in paths:
        for line in path.read_text(encoding="utf-8").split():
            times.append(int(line) / 1_000_000_000)

    return times


def split_outliers(times: list[float]) -> tuple[list[float], list[float]]:
    if len(times) < 4:
        return times, []

    q1, _, q3 = statistics.quantiles(times, n=4)
    iqr = q3 - q1
    low = q1 - 1.5 * iqr
    high = q3 + 1.5 * iqr

    keep = [t for t in times if low <= t <= high]
    drop = [t for t in times if t < low or t > high]
    return keep, drop


def histogram(times: list[float]) -> list[str]:
    low = math.floor(min(times) / BIN_WIDTH) * BIN_WIDTH
    bins = int((max(times) - low) / BIN_WIDTH) + 1

    counts = [0] * bins
    for t in times:
        counts[min(int((t - low) / BIN_WIDTH), bins - 1)] += 1

    tallest = max(counts)
    lines = []
    for i, count in enumerate(counts):
        bar_chars = "#" * round(count * WIDTH / tallest)
        lines.append(f"{low + i * BIN_WIDTH:7.3f}s |{bar_chars:<{WIDTH}}| {count}")

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
    print(f"outliers: {', '.join(f'{t:.3f}s' for t in sorted(drop)) or 'none'}")
    print(f"average:  {statistics.fmean(keep):.3f}s")
    print(f"median:   {statistics.median(keep):.3f}s")
    print(f"minimum:  {min(keep):.3f}s")
    print(f"maximum:  {max(keep):.3f}s")
    print()
    for i, path in enumerate(args.files, 1):
        samples = read_times([path])
        print(
            f"{i:3d}: {len(samples)} samples, {min(samples):.3f}s - {max(samples):.3f}s"
        )
    print()
    print("\n".join(histogram(keep)))


if __name__ == "__main__":
    main()
