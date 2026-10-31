"""Prints basic information and signing certificates of an APK.

Usage: python quickstart.py <path-to-apk>
"""

import sys

if len(sys.argv) < 2:
    print(f"usage: {sys.argv[0]} <path-to-apk>")
    sys.exit(1)

path = sys.argv[1]

# --8<-- [start:basic]
from apk_info import APK

apk = APK(path)

print(f"Package:     {apk.get_package_name()}")
print(f"Version:     {apk.get_version_name()}")
print(f"Min SDK:     {apk.get_min_sdk_version()}")
print(f"Target SDK:  {apk.get_target_sdk_version()}")
print(f"Label:       {apk.get_application_label()}")
print(f"Main:        {apk.get_main_activity()}")
# --8<-- [end:basic]

# --8<-- [start:signatures]
from apk_info import Signature

for signature in apk.get_signatures():
    match signature:
        case Signature.V1() | Signature.V2() | Signature.V3() | Signature.V31() | Signature.V32():
            for cert in signature.certificates:
                print(f"{type(signature).__name__}: {cert.subject} ({cert.sha256_fingerprint})")
        case _:
            print(signature)
# --8<-- [end:signatures]
