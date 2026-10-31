"""
Single-threaded benchmark: analyses every file in a folder, one after
another, in one process, and prints the time, the failures and the peak
memory.

usage: python bench_androguard.py <apk-folder>
"""

import resource
import statistics
import sys
import time
from collections import Counter
from pathlib import Path

from androguard.core.apk import APK
from loguru import logger


def analyse(file: Path) -> None:
    """Extract the same fields as the apk-info comparison."""
    apk = APK(str(file))

    if not apk.get_package():
        raise ValueError("no package name")

    # v1, v2, v3 and v3.1 certificates, like apk-info's get_signatures();
    # androguard's get_signatures() only returns the raw v1 signature files
    _ = apk.get_certificates()
    _ = apk.get_min_sdk_version()
    _ = apk.get_main_activities()
    _ = apk.get_app_name()


def main(path: Path) -> None:
    # androguard uses loguru; drop its DEBUG output for a clean, fast run.
    logger.remove()
    logger.add(sys.stderr, level="WARNING")

    files = sorted(f for f in path.rglob("*") if f.is_file() and not f.name.startswith("."))

    times = []
    errors = Counter()
    started = time.perf_counter()
    for file in files:
        file_started = time.perf_counter()
        try:
            analyse(file)
        except Exception as e:  # noqa: BLE001 - a single bad file shouldn't abort the run
            print("failed", file, e, file=sys.stderr)
            errors[type(e).__name__] += 1
        times.append(time.perf_counter() - file_started)
    elapsed = time.perf_counter() - started

    # bytes on macOS, kilobytes on Linux
    maxrss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    maxrss_mb = maxrss / 2**20 if sys.platform == "darwin" else maxrss / 2**10

    failed = sum(errors.values())
    print(f"files={len(files)} ok={len(files) - failed} failed={failed} elapsed={elapsed:.2f}s")
    if times:
        print(
            f"per file: median={statistics.median(times) * 1000:.2f}ms "
            f"max={max(times) * 1000:.0f}ms peak_rss={maxrss_mb:.0f}MB"
        )
    for error, count in errors.most_common():
        print(f"  {count:6d} {error}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <apk-folder>")
        sys.exit(2)
    main(Path(sys.argv[1]))
