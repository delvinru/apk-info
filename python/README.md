<h1><img src="https://raw.githubusercontent.com/delvinru/apk-info/main/docs/assets/logo/wordmark-light.png" alt="apk-info" height="56"></h1>

![PyPI - Version](https://img.shields.io/pypi/v/apk-info?style=flat)
![PyPI - License](https://img.shields.io/pypi/l/apk-info?style=flat)
[![GitHub Repo stars](https://img.shields.io/github/stars/delvinru/apk-info?style=flat)](https://github.com/delvinru/apk-info)

Fast, malware-robust parser for Android apk/xapk/apkm/apks files.

Documentation: <https://delvinru.github.io/apk-info/>

## Features

- A malware-friendly zip reader that reads archives the way Android does, including the `BadPack` technique (great [article](https://unit42.paloaltonetworks.com/apk-badpack-malware-tampered-headers/) about it) and ZIP64;
- XAPK, APKM and APKS containers, opened through their base APK;
- A full AXML (Android Binary XML) and ARSC (Android Resource) implementation, robust against garbage chunks;
- Support for extracting information contained in the `APK Signing Block`:
  - [APK Signature scheme v1](https://source.android.com/docs/security/features/apksigning);
  - [APK Signature scheme v2](https://source.android.com/docs/security/features/apksigning/v2);
  - [APK Signature scheme v3](https://source.android.com/docs/security/features/apksigning/v3);
  - [APK Signature scheme v3.1](https://source.android.com/docs/security/features/apksigning/v3-1);
  - [APK Signature scheme v3.2](https://source.android.com/docs/security/features/apksigning/v3-2);
  - Stamp Block v1 & v2;
  - Channel blocks: [Walle](https://github.com/Meituan-Dianping/walle), [VasDolly v2](https://github.com/Tencent/VasDolly), [Packer NG v2](https://github.com/mcxiaoke/packer-ng-plugin), ByteDance;
  - Google Play Frosting (presence only, its structure isn't public);
- Correct extraction of the MainActivity based on how the Android OS [does it](https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/core/java/android/app/ApplicationPackageManager.java#310);
- Bindings for python 3.11+ with typings - no more `# type: ignore`; parsing releases the GIL, so threads run in parallel;
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
        case Signature.V1() | Signature.V2() | Signature.V3() | Signature.V31() | Signature.V32():
            for cert in signature.certificates:
                print(f"{cert.subject=} {cert.issuer=} {cert.valid_from=} {cert.valid_until=}")
        case Signature.ApkChannelBlock() | Signature.VasDollyV2() | Signature.ByteDance():
            print(f"got channel block: {signature.value}")
        case _:
            print(f"oh, cool, library added some new feature - {signature}")

# `xapk`/`apkm`/`apks` containers carry two separate signatures:
#   * get_signatures()           - the app identity, read from the inner base APK
#   * get_container_signatures() - the distributor's signature on the outer archive (empty for plain APKs)
container_sigs = apk.get_container_signatures()
```

For more information visit - [homepage](https://github.com/delvinru/apk-info).
