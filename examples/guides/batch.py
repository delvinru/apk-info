"""Processing a folder of APKs in parallel, tolerating broken files.

Usage: python batch.py <folder>
"""

import json
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from apk_info import APK, APKError

EXTENSIONS = {".apk", ".xapk", ".apkm", ".apks"}


# --8<-- [start:batch]
def triage(path: Path) -> dict:
    try:
        apk = APK(path)
    except APKError as e:
        return {"file": str(path), "error": str(e)}

    return {
        "file": str(path),
        "package": apk.get_package_name(),
        "version": apk.get_version_name(),
        "min_sdk": apk.get_min_sdk_version(),
        "main_activity": apk.get_main_activity(),
        "permissions": sorted(apk.get_permissions()),
    }


if __name__ == "__main__":
    files = [p for p in Path(sys.argv[1]).rglob("*") if p.suffix.lower() in EXTENSIONS]

    # parsing holds the GIL, so threads would run one at a time; use processes
    with ProcessPoolExecutor() as pool:
        for result in pool.map(triage, files):
            print(json.dumps(result))
# --8<-- [end:batch]
