import sys
from pathlib import Path

from apk_info import APK


def main(path: Path) -> None:
    failed = 0

    for file in path.rglob("*"):
        if file.is_file() and not file.name.startswith("."):
            try:
                apk = APK(file)

                package_name = apk.get_package_name()
                assert package_name is not None

                _ = apk.get_signatures()
                _ = apk.get_min_sdk_version()
                _ = apk.get_main_activities()
                _ = apk.get_application_name()
            except Exception as e:
                print("failed", file, e)
                failed += 1

    print(f"{failed=}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <apk-folder>")
        exit()

    main(Path(sys.argv[1]))
