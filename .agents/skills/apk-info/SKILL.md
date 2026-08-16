---
name: apk-info
description: Parses and inspects Android APK/XAPK/APKM files, extracting package name, version, SDK levels, main activity, permissions, manifest components (activities, services, receivers, providers), signing certificates (v1/v2/v3/v3.1, source stamps, channel blocks), the decoded AndroidManifest.xml, and apktool-style resources. Ships as a CLI and a Python library; a faster, malware-robust alternative to androguard (handles BadPack and tampered zip headers). Use when analyzing or inspecting an APK/XAPK/APKM, when unzip/7z fail or drop the manifest on an APK (BadPack, unsupported compression, empty manifest), when a .zip is actually an APK, when decoding resources/manifest, or when extracting APK metadata/files programmatically. Read-only analysis - does not build, sign, modify, or decompile APKs.
license: Apache-2.0
metadata:
  author: delvinru
  version: 1.0.12
---

# apk-info

`apk-info` is a fast, malware-friendly, **read-only** APK parser. It extracts information from APK/XAPK/APKM files: package name, version, SDK requirements, main activity, permissions, signatures, manifest components, and individual files. It ships as a CLI (`apk-info`) and a Python library (`apk-info` on PyPI, ≥3.10, with full type stubs).

Its key strength is robustness against malformed/malicious inputs (BadPack technique, tampered zip headers, garbage AXML chunks) where standard parsers like androguard fail or are ~10× slower.

## References (read on demand)

`apk-info` is small — this file is just an overview. Read only the reference relevant to the current task; each is referenced one level deep and loaded only when needed.

- **`references/cli.md`** — Full CLI reference (`show`, `extract`, `axml`, `repack`, `completion`) with all flags and examples.
- **`references/python-api.md`** — Python API catalog grouped by task; use when writing Python that calls `apk_info`.
- **`references/recipes.md`** — Copy-paste recipes (extract icon, dump manifest, batch a folder, certificates, BadPack/unzip-vs-apk-info, decode resources).

## Installation

```bash
# CLI
cargo install apk-info-cli

# Python
uv pip install apk-info
# or: pip install apk-info
```

## Quick start — most common tasks

### CLI

```bash
# Basic info (package, version, SDK, main activity, ABIs)
apk-info show ./app.apk

# Include signature/certificate details
apk-info show --sigs ./app.apk

# Machine-readable output (one JSON object per APK) — pipe to jq
apk-info show --json ./app.apk | jq .package_name

# Works on a whole folder (recurses, skips dotfiles)
apk-info show --json ./malware-collection/ | jq -c .

# Pretty-print the AndroidManifest.xml
apk-info axml ./app.apk

# Extract all files from the APK
apk-info extract ./app.apk                 # → ./app.apk.unp/

# Extract only specific files (regex, repeatable)
apk-info extract ./app.apk -f 'classes\d+\.dex' -f 'AndroidManifest.xml'

# Decode resources apktool-style (manifest + res/values* + res/<type>-<cfg>)
# merges base + every config split for XAPK/APKM containers
apk-info extract ./app.apk -r
```

> **Why not just `unzip`?** Malware often tampers with zip headers (BadPack technique): the compression method field is set to a bogus value while the data is stored normally. `unzip` silently skips such entries (`unsupported compression method 55914`, exit 0) and `7z` creates empty 0-byte files — you lose `AndroidManifest.xml` without knowing it. `apk-info` detects the tampering, flags it as `StoredTampered`/`DeflatedTampered`, and extracts the data correctly. See `references/recipes.md` §9 and §16 for real-world examples.

### Python

```python
from apk_info import APK

apk = APK("./app.apk")

# Basics
print(apk.get_package_name())        # "com.example.app"
print(apk.get_version_name())        # "1.2.3"
print(apk.get_version_code())        # "2025101912"
print(apk.get_min_sdk_version())     # "26"
print(apk.get_target_sdk_version())  # 34 (int)

# Main (launchable) activity
activities = apk.get_main_activities()
if activities:
    print(f"{apk.get_package_name()}/{activities[0]}")

# Permissions
for perm in apk.get_permissions():
    print(perm)

# Signatures & certificates
for sig in apk.get_signatures():
    match sig:
        case type(sig).V1() | type(sig).V2() | type(sig).V3() | type(sig).V31():
            for cert in sig.certificates:
                print(cert.subject, cert.sha256_fingerprint)
```

## What apk-info can extract

| Data                                          | CLI           | Python method                                                                  |
| --------------------------------------------- | ------------- | ------------------------------------------------------------------------------ |
| Package name                                  | `show`        | `get_package_name()`                                                           |
| Version name / code                           | `show`        | `get_version_name()` / `get_version_code()`                                    |
| Min / target / max SDK                        | `show`        | `get_min_sdk_version()` / `get_target_sdk_version()` / `get_max_sdk_version()` |
| Main (launchable) activity                    | `show`        | `get_main_activity()` / `get_main_activities()`                                |
| Application label                             | `show`        | `get_application_label()`                                                      |
| Supported ABIs (native libs)                  | `show`        | `get_supported_abis()`                                                         |
| Signatures & certificates                     | `show --sigs` | `get_signatures()`                                                             |
| Permissions                                   | —             | `get_permissions()`                                                            |
| Declared permissions                          | —             | `get_declared_permissions()`                                                   |
| Features (device capabilities)                | —             | `get_features()`                                                               |
| Activities / Services / Receivers / Providers | —             | `get_activities()` / `get_services()` / `get_receivers()` / `get_providers()`  |
| Pretty-printed manifest                       | `axml`        | `get_xml_string()`                                                             |
| Raw file from APK                             | `extract`     | `read(filename)`                                                               |
| File listing                                  | `extract`     | `namelist()`                                                                   |
| Decoded resources (apktool-style)             | `extract -r`  | —                                                                              |
| Multidex check                                | —             | `is_multidex()`                                                                |
| Device-type checks (TV/watch/auto/chromebook) | —             | `is_leanback()` / `is_wearable()` / `is_automotive()` / `is_chromebook()`      |
| Any manifest attribute                        | —             | `get_attribute_value(tag, name)`                                               |
| Resolve `@string/...` references              | —             | `get_resource_value("@string/app_name")`                                       |

## Supported formats

- **APK** — standard Android packages.
- **XAPK** — APK containers with a `manifest.json` (the inner `<package_name>.apk` is parsed).
- **APKM** — APKM bundles (the inner `base.apk` is parsed).

Format is auto-detected — just point `APK(path)` or `apk-info show <path>` at any of them.

## Error handling

- **CLI**: parse errors are printed to stderr in red; the command continues to the next file when processing multiple paths.
- **Python**: `APK(path)` raises `FileNotFoundError` if the path doesn't exist, `TypeError` for bad argument types, and `apk_info.APKError` for parse failures. `get_signatures()` can raise `APKError` if certificates can't be parsed.

```python
from apk_info import APK, APKError

try:
    apk = APK("./maybe-malicious.apk")
except APKError as e:
    print(f"parse failed: {e}")
```
