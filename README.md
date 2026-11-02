<h1>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo/wordmark-dark.svg">
    <img src="docs/assets/logo/wordmark-light.svg" alt="apk-info" height="56">
  </picture>
</h1>

[![crates.io](https://img.shields.io/crates/v/apk-info?style=flat)](https://crates.io/crates/apk-info)
[![rust downloads](https://img.shields.io/crates/d/apk-info?label=rust%20downloads)](https://crates.io/crates/apk-info)
[![docs.rs](https://img.shields.io/docsrs/apk-info?style=flat)](https://docs.rs/apk-info/latest/apk_info/)
[![pypi](https://img.shields.io/pypi/v/apk-info?style=flat)](https://pypi.org/project/apk-info/)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/apk-info?period=total&units=INTERNATIONAL_SYSTEM&left_color=GREY&right_color=BLUE&left_text=pypi+downloads)](https://pepy.tech/projects/apk-info)
[![license](https://img.shields.io/crates/l/apk-info)](./LICENSE)

Fast, malware-robust parser for Android apk/xapk/apkm/apks files.

Documentation: <https://delvinru.github.io/apk-info/>

```console
$ apk-info show apkstest.apk
apkstest.apk
  Package         io.github.delvinru.apkstest
  Label           APKS Test
  Version         1.0.7 (7)
  SDK             min 21 · target 35
  Main activity   io.github.delvinru.apkstest/.MainActivity
  ABIs            x86_64
```

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

## Getting started

### cli

#### Installation

With Homebrew:

```bash
brew install delvinru/tap/apk-info
```

Or with cargo:

```bash
cargo install apk-info-cli
```

#### Help

```bash
A command-line tool to inspect and extract APK files

Usage: apk-info [COMMAND]

Commands:
  show        Show basic information about the APK file
  extract     Unpack apk files as zip archive [alias: x]
  axml        Read and pretty-print binary AndroidManifest.xml
  repack      Repack a BadPack-damaged APK into a clean, well-formed zip archive
  completion  Generate shell completion
  help        Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### Python

#### Installation

```bash
uv pip install apk-info
```

#### Get basic information about APK

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

# For `xapk`/`apkm`/`apks` containers, `get_container_signatures()` returns the
# distributor's signature on the outer archive, separate from the app.
container_signatures = apk.get_container_signatures()
```

## Performance Analysis

One thread, cold page cache, the same metadata read by each tool from Python. Apple M3 Pro, macOS 26.6.1.

**Clean apps**: 5,714 APK and XAPK files from app stores, 429 GB.

|                  | Time    | Files/s | Peak memory | Failed |
| ---------------- | ------- | ------- | ----------- | ------ |
| apk-info 1.1.0   | 29.7 s  | 192     | 745 MB      | 0      |
| apk-info 1.0.13  | 71.4 s  | 80      | 770 MB      | 0      |
| androguard 4.1.4 | 926.3 s | 6       | 5.8 GB      | 784    |

**Malware**: 23,745 files from the [VirusShare Android collection](https://vx-underground.org/Samples/Virusshare%20Collection/Downloadable%20Releases), 106 GB.

|                  | Time    | Files/s | Peak memory | Failed |
| ---------------- | ------- | ------- | ----------- | ------ |
| apk-info 1.1.0   | 44.7 s  | 531     | 88 MB       | 692    |
| apk-info 1.0.13  | 76.0 s  | 312     | 87 MB       | 691    |
| androguard 4.1.4 | 362.6 s | 65      | 794 MB      | 737    |

Methodology, per-file timings and failure reasons: [Benchmarks](https://delvinru.github.io/apk-info/benchmarks/).

## FAQ

- Why not just use androguard?

Almost all of my projects are born from something that is inconvenient to use.
Androguard is a great tool in itself, but in my opinion it is simply not possible to maintain, and it is not suitable for production-ready code. It is also not suitable for analyzing a large number of files, because its logic isn't well optimized.

- I want to modify an APK. How do I do it with this library?

The library is read-only by design: I needed a good tool to extract information from an APK easily and quickly. There are many other good tools for modifying APKs.

- I repacked an APK. How do I sign it?

The `repack` command produces an unsigned APK. To re-sign it, I recommend [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer), a simple one-command tool that signs with v1/v2/v3 and zipaligns in a single pass:

```bash
java -jar uber-apk-signer.jar --apks ./malware.repacked.apk
```

## Credits

- [androguard](https://github.com/androguard/androguard)
- [apkInspector](https://github.com/erev0s/apkInspector)
