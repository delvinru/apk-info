# apk-info

[![Crates.io Version](https://img.shields.io/crates/v/apk-info?style=flat)](https://crates.io/crates/apk-info)
[![docs.rs](https://img.shields.io/docsrs/apk-info?style=flat)](https://docs.rs/apk-info/latest/apk_info/)
[![PyPI - Version](https://img.shields.io/pypi/v/apk-info?style=flat)](https://pypi.org/project/apk-info/)

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
  - Stamp Block v1 & v2;
  - Apk Channel Block;
  - [Packer NG v2](https://github.com/mcxiaoke/packer-ng-plugin/blob/ffbe05a2d27406f3aea574d083cded27f0742160/common/src/main/java/com/mcxiaoke/packer/common/PackerCommon.java#L20);
  - [Vasdolly v2](https://main.qcloudimg.com/raw/document/intl/product/pdf/tencent-cloud_1145_54493_en.pdf)
  - Google Play Frosting (there are plans, but there is critically little information about it);
- Correct extraction of the MainActivity based on how the Android OS [does it](https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/core/java/android/app/ApplicationPackageManager.java#310);
- Bindings for python 3.10+ with typings - no more `# type: ignore`;
- And of course just a fast parser - 🙃

## Getting started

### cli

#### Installation

```bash
cargo install apk-info-cli
```

#### Help

```bash
A command-line tool to inspect and extract APK files

Usage: apk-info [COMMAND]

Commands:
  show        Show basic information about apk file
  extract     Unpack apk files as zip archive [aliases: x]
  axml        Read and pretty-print binary AndroidManifest.xml
  repack      Unpack and repack a BadPack-damaged APK into a standard, well-formed zip archive
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
        case Signature.V1() | Signature.V2() | Signature.V3() | Signature.V31():
            for cert in signature.certificates:
                print(f"{cert.subject=} {cert.issuer=} {cert.valid_from=} {cert.valid_until=}")
        case Signature.ApkChannelBlock():
            print(f"got apk channel block: {signature.value}")
        case _:
            print(f"oh, cool, library added some new feature - {signature}")

# For `xapk`/`apkm` containers, `get_container_signatures()` returns the
# distributor's signature on the outer archive, separate from the app.
container_signatures = apk.get_container_signatures()
```

## Performance Analysis

Environment:

- OS: macOS Tahoe 26.6.1 arm64
- CPU: Apple M3 Pro (12) @ 4.06 GHz

The [script](examples/benchmark/bench.py):

1. Extract all available signatures from a file;
2. Extract the package name;
3. Extract the minimum sdk version;
4. Get a list of all Main Activities;
5. Get the application name;

apk-info library:

- Build - `release-lto`;
- Python bindings (honest comparison);

---

test case (clean collection):

- 152 apk files;
- Total size - 20GB;
- Logging mode - warning;

| #   | **apk-info**                                | **androguard**                                 |
| --- | ------------------------------------------- | ---------------------------------------------- |
| 1   | 0.98s user 4.32s system 80% cpu 6.584 total | 57.39s user 4.88s system 97% cpu 1:03.85 total |
| 2   | 0.96s user 4.23s system 79% cpu 6.486 total | 57.98s user 5.04s system 97% cpu 1:04.80 total |
| 3   | 0.95s user 4.15s system 79% cpu 6.422 total | 55.56s user 4.48s system 97% cpu 1:01.55 total |

---

test case (malware collection):

- 13374 apk files (from the [VirusShare Android APK collection](https://vx-underground.org/Samples/Virusshare%20Collection/Downloadable%20Releases));
- Total size - 68GB;
- Logging mode - warning;

> [!NOTE]
> The collection has 14026 downloaded samples. 652 of them are completely broken (not valid ZIP/APK archives) and rejected by both tools, so they are excluded from the benchmark — leaving 13374.

| #   | **apk-info**                                | **androguard**                                  |
| --- | ------------------------------------------- | ----------------------------------------------- |
| 1   | 5.15s user 12.53s system 66% cpu 26.990 total | 152.85s user 15.56s system 95% cpu 2:58.01 total |
| 2   | 5.41s user 13.08s system 69% cpu 27.010 total | 151.84s user 15.08s system 95% cpu 2:56.74 total |
| 3   | 5.25s user 12.76s system 68% cpu 26.610 total | 152.26s user 15.26s system 95% cpu 2:57.20 total |

---

On average, the speed gain is about x6.6 on this corpus.

## FAQ

- Why not just use androguard?

Almost all of my projects are born from something that is inconvenient to use.
Androguard is a great tool in itself, but it is simply not possible to maintain it (in my opinion) and it is not suitable for production-ready code. It is also not suitable for analyzing a large number of files due to the fact that all the logic is written in not very optimized way.

- I want to modify the apk, how do I do it using this library?

The library is designed for read-only mode only, because i need a good tool with which i can easily and quickly extract information from the apk. There are many other good tools out there.

- I repacked an apk, how do I sign it?

The `repack` command produces an unsigned apk. To re-sign it, we recommend [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer) — a simple one-command tool that signs with v1/v2/v3 and zipaligns in a single pass:

```bash
java -jar uber-apk-signer.jar --apks ./malware.repacked.apk
```

## Credits

- [androguard](https://github.com/androguard/androguard)
- [apkInspector](https://github.com/erev0s/apkInspector)
