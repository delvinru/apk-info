# apk-info

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

## Getting started

### cli

#### Installation

<!-- TODO: need actually check before release -->

```bash
cargo install apk-info
```

#### Help

```bash
A command-line tool to inspect and extract APK files

Usage: apk-info [COMMAND]

Commands:
  show     Show basic information about apk file
  extract  Unpack apk files as zip archive [aliases: x]
  axml     Read and pretty-print binary AndroidManifest.xml
  help     Print this message or the help of the given subcommand(s)

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
                print(f"{cert.subject=} {cert.valid_from=} {cert.valid_until=}")
        case Signature.ApkChannelBlock():
            print(f"got apk channel block: {signature.value}")
        case _:
            print(f"oh, cool, library added some new feature - {signature}")

```

## Performance Analysis

Environment:

- OS: macOS Tahoe 26.0.1 (25A362) arm64
- CPU: Apple M3 Pro (12) @ 4.06 GHz

The script:

1. Extract all available signatures from a file;
2. Extract the package name;
3. Extract the minimum sdk version;
4. Get a list of all Main Activities;
5. Get the application name;

apk-info library:

- Release build;
- Python bindings (honest comparison);

---

Test case:

- 152 apk files;
- Total size - 20GB;
- Logging mode - warning;

| #   | **apk-info**                                | **androguard**                                 |
| --- | ------------------------------------------- | ---------------------------------------------- |
| 1   | 1.22s user 4.26s system 81% cpu 6.760 total | 57.39s user 4.88s system 97% cpu 1:03.85 total |
| 2   | 1.21s user 4.22s system 81% cpu 6.657 total | 57.98s user 5.04s system 97% cpu 1:04.80 total |
| 3   | 1.22s user 4.25s system 81% cpu 6.688 total | 55.56s user 4.48s system 97% cpu 1:01.55 total |

---

Test case:

- 3010 apk files;
- Total size - 22GB;
- Logging mode - warning;

> [!IMPORTANT]
> There are a lot of malicious samples in this set that androguard simply cannot parse.

| #   | **apk-info**                                 | **androguard**                                  |
| --- | -------------------------------------------- | ----------------------------------------------- |
| 1   | 3.06s user 4.73s system 80% cpu 9.654 total  | 128.32s user 6.11s system 98% cpu 2:16.93 total |
| 2   | 3.27s user 5.25s system 84% cpu 10.126 total | 131.12s user 6.60s system 98% cpu 2:20.23 total |
| 3   | 3.10s user 4.75s system 81% cpu 9.674 total  | 130.82s user 6.51s system 98% cpu 2:19.88 total |

---

On average, the speed gain is about x10.

The main advantage is that `apk-info` can parse many more malicious files than `androguard`.

For example, a list of hashes:

- a045d8b62bbf4cdcfbd449a994958c1e051d06c0d888e0936838fff4be47aefc
- 3f972448cf4fdf8938b56c0627a2e274e3c9968b0212975eadda8e4de7ab782e
- d5fe92a103f643735d42e6070dc3fcc28f15e2cef488dae42ca235a061bc836a

> [!NOTE]
> There are many more such samples in everyday malware analysis.

## FAQ

- Why not just use androguard?

Almost all of my projects are born from something that is inconvenient to use.
Androguard is a great tool in itself, but it is simply not possible to maintain it (in my opinion) and it is not suitable for production-ready code. It is also not suitable for analyzing a large number of files due to the fact that all the logic is written in not very optimized way.

- I want to modify the apk, how do I do it using this library?

The library is designed for read-only mode only, because i need a good tool with which i can easily and quickly extract information from the apk. There are many other good tools out there.

## Credits

- [androguard](https://github.com/androguard/androguard)
- [apkInspector](https://github.com/erev0s/apkInspector)
