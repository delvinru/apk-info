# apk-info

![PyPI - Version](https://img.shields.io/pypi/v/apk-info?style=flat)
![PyPI - License](https://img.shields.io/pypi/l/apk-info?style=flat)
![GitHub Repo stars](https://img.shields.io/github/stars/delvinru/apk-info?style=flat)

A full-featured `apk` parser.

## Features

- A malware-friendly zip extractor. Great [article](https://unit42.paloaltonetworks.com/apk-badpack-malware-tampered-headers/) about `BadPack` technique;
- A malware-friendly axml and arsc extractor;
- A full AXML (Android Binary XML) implementation;
- A full ARSC (Android Resource) implementation;
- Support for extracting information contained in the `APK Signature Block 42`:
  - [APK Signature scheme v1](https://source.android.com/docs/security/features/apksigning);
  - [APK Signature scheme v2](https://source.android.com/docs/security/features/apksigning/v2);
  - [APK Signature scheme v3](https://source.android.com/docs/security/features/apksigning/v3);
  - [APK Signature scheme v3.1](https://source.android.com/docs/security/features/apksigning/v3-1);
  - Stamp Block v1;
  - Stamp Block v2;
  - Apk Channel Block;
  - Google Play Frosting (there are plans, but there is critically little information about it);
- Correct extraction of the MainActivity based on how the Android OS [does it](https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/core/java/android/app/ApplicationPackageManager.java#310);
- Bindings for python 3.10+ with typings - no more `# type: ignore`;
- And of course just a fast parser - 🙃

## Usage

### Installation

```bash
uv pip install apk-info
```

### Get basic information about APK

```python
from apk_info import APK

apk = APK("./path-to-file.apk")
package_name = apk.get_package_name()
main_activities = apk.get_main_activities()
min_sdk = apk.get_min_sdk_version()

print(f"Package Name: {package_name}")
print(f"Minimal SDK: {min_sdk}")

if not main_activities:
    print("apk is not launchable!")
    exit()

print(f"Main Activity: {package_name}/{main_activities[0]}")
```

#### Get information about signatures

```python
import sys

from apk_info import APK, Signature

if len(sys.argv) < 2:
    print(f"usage: {sys.argv[0]} <apk>")
    sys.exit(1)

file = sys.argv[1]
apk = APK(file)

signatures = apk.get_signatures()
for signature in signatures:
    match signature:
        case Signature.V1() | Signature.V2() | Signature.V3() | Signature.V31():
            for cert in signature.certificates:
                print(f"{cert.subject=} {cert.valid_from=} {cert.valid_until=}")
        case Signature.ApkChannelBlock():
            print(f"got apk channel block: {signature.value}")
        case _:
            print(f"oh, cool, library added some new feature - {signature}")

```

For more information visit - [homepage](https://github.com/delvinru/apk-info).
