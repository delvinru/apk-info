import sys
import time
from pathlib import Path

from androguard.core.apk import APK
from loguru import logger


def analyse(file: Path) -> None:
    """Extract the same fields as the apk-info comparison."""
    apk = APK(str(file))

    if not apk.get_package():
        raise ValueError(f"{file}: no package name (not a valid APK?)")

    _ = apk.get_signatures()
    _ = apk.get_min_sdk_version()
    _ = apk.get_main_activities()
    _ = apk.get_app_name()


def main(path: Path) -> None:
    # androguard uses loguru; drop its DEBUG output for a clean, fast run.
    logger.remove()
    logger.add(sys.stderr, level="WARNING")

    files = [f for f in path.rglob("*") if f.is_file() and not f.name.startswith(".")]

    started = time.perf_counter()
    ok = 0
    failed = 0
    for file in files:
        try:
            analyse(file)
            ok += 1
        except Exception as e:  # noqa: BLE001 - a single bad file shouldn't abort the run
            print("failed", file, e, file=sys.stderr)
            failed += 1
    elapsed = time.perf_counter() - started

    print(f"files={len(files)} ok={ok} failed={failed} elapsed={elapsed:.3f}s")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <apk-folder>")
        sys.exit(2)
    main(Path(sys.argv[1]))
