"""Reading files from an APK: listing, DEX, the app icon and tampered entries.

Usage: python files.py <path-to-apk> <output-dir>
"""

import sys
from pathlib import Path

from apk_info import APK

apk = APK(sys.argv[1])
out = Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)

# --8<-- [start:read]
# names come from the central directory, in archive order
names = apk.namelist()
print(f"{len(names)} entries")

data, compression = apk.read("AndroidManifest.xml")
print(f"{len(data)} bytes, {compression}")  # e.g. "deflated"
# --8<-- [end:read]

# --8<-- [start:dex]
for name in apk.namelist():
    if name.startswith("classes") and name.endswith(".dex"):
        data, _ = apk.read(name)
        (out / name).write_bytes(data)
        print(f"saved {name}: {len(data)} bytes")
# --8<-- [end:dex]

# --8<-- [start:icon]
icon = apk.get_application_icon()  # e.g. "res/mipmap-xxxhdpi-v4/ic_launcher.png"
if icon:
    data, _ = apk.read(icon)
    (out / Path(icon).name).write_bytes(data)
    # an .xml icon is an adaptive icon: binary XML that points to other drawables
    print(f"saved {icon}")
# --8<-- [end:icon]

# --8<-- [start:tampered]
for name in apk.namelist():
    _, compression = apk.read(name)
    if compression in ("stored_tampered", "deflated_tampered"):
        print(f"tampered header: {name} ({compression})")
# --8<-- [end:tampered]
