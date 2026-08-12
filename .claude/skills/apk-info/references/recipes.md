# Recipes

Copy-paste solutions for common APK analysis tasks. Each recipe is self-contained.

## 1. Basic triage

Get the essential facts about an APK in one shot.

```python
from apk_info import APK

apk = APK("./app.apk")
print(f"Package:      {apk.get_package_name()}")
print(f"Version:      {apk.get_version_name()} ({apk.get_version_code()})")
print(f"Min SDK:      {apk.get_min_sdk_version()}")
print(f"Target SDK:   {apk.get_target_sdk_version()}")
print(f"Label:        {apk.get_application_label()}")
print(f"Debuggable:   {apk.get_application_debuggable()}")
print(f"Multidex:     {apk.is_multidex()}")
print(f"ABIs:         {apk.get_supported_abis()}")

activities = apk.get_main_activities()
print(f"Launchable:   {activities[0] if activities else '(none)'}")
```

CLI equivalent:
```bash
apk-info show --sigs ./app.apk
```

## 2. Extract and inspect certificates

Pull all signing certificates with their fingerprints — useful for tracking signing keys across a malware family.

```python
from apk_info import APK, Signature

apk = APK("./app.apk")
for sig in apk.get_signatures():
    match sig:
        case Signature.V1() | Signature.V2() | Signature.V3() | Signature.V31():
            print(f"--- {type(sig).__name__} ---")
            for cert in sig.certificates:
                print(f"  Subject:    {cert.subject}")
                print(f"  Issuer:     {cert.issuer}")
                print(f"  Valid:      {cert.valid_from} → {cert.valid_until}")
                print(f"  SHA256:     {cert.sha256_fingerprint}")
                print(f"  SHA1:       {cert.sha1_fingerprint}")
                print(f"  Serial:     {cert.serial_number}")
        case Signature.StampBlockV1() | Signature.StampBlockV2():
            print(f"--- {type(sig).__name__} ---")
            print(f"  Subject: {sig.certificate.subject}")
        case Signature.ApkChannelBlock():
            print(f"Channel block: {sig.value}")
        case Signature.PackerNextGenV2():
            print(f"Packer-NG: {sig.value.hex()}")
        case Signature.VasDollyV2():
            print(f"VasDolly: {sig.value}")
        case Signature.GooglePlayFrosting():
            print("Google Play Frosting present")
```

## 3. Dump the AndroidManifest.xml

```python
from apk_info import APK

apk = APK("./app.apk")
with open("AndroidManifest.xml", "w") as f:
    f.write(apk.get_xml_string())
```

CLI equivalent:
```bash
apk-info axml ./app.apk > AndroidManifest.xml
```

## 4. Extract the app icon

```python
from apk_info import APK

apk = APK("./app.apk")
icon_path = apk.get_application_icon()
if icon_path:
    data, _ = apk.read(icon_path)
    # The path may end in .png, .webp, or even .xml (adaptive icon)
    with open("icon" + "." + icon_path.rsplit(".", 1)[-1], "wb") as f:
        f.write(data)
else:
    print("no icon declared")
```

## 5. List all permissions

```python
from apk_info import APK

apk = APK("./app.apk")
print("Requested permissions (<uses-permission>):")
for perm in sorted(apk.get_permissions()):
    print(f"  {perm}")

print("\nSDK-23 permissions (<uses-permission-sdk-23>):")
for perm in sorted(apk.get_permissions_sdk23()):
    print(f"  {perm}")

print("\nDeclared permissions (<permission>):")
for perm in apk.get_declared_permissions():
    print(f"  {perm.name} [{perm.protection_level}]")
```

## 6. Find exported components (attack surface)

Exported activities/services/receivers/providers are reachable from other apps — a common attack surface.

```python
from apk_info import APK

apk = APK("./app.apk")

for activity in apk.get_activities():
    if activity.exported == "true":
        print(f"Exported activity: {activity.name}")

for svc in apk.get_services():
    if svc.exported == "true":
        print(f"Exported service: {svc.name}")

for recv in apk.get_receivers():
    if recv.exported == "true":
        print(f"Exported receiver: {recv.name}")

for prov in apk.get_providers():
    if prov.exported == "true":
        print(f"Exported provider: {prov.name} (authorities={prov.authorities})")
```

## 7. Batch-process a folder of APKs

Process every APK in a directory, collecting results into a list. Robust against parse failures (common with malware collections).

```python
import json
from pathlib import Path
from apk_info import APK, APKError

results = []
for path in Path("./apks/").rglob("*.apk"):
    try:
        apk = APK(path)
        results.append({
            "file": str(path),
            "package": apk.get_package_name(),
            "version": apk.get_version_name(),
            "min_sdk": apk.get_min_sdk_version(),
            "main_activity": apk.get_main_activity(),
            "permissions": sorted(apk.get_permissions()),
        })
    except APKError as e:
        results.append({"file": str(path), "error": str(e)})

with open("results.json", "w") as f:
    json.dump(results, f, indent=2)
```

CLI equivalent (faster, native):
```bash
apk-info show --json ./apks/ > results.jsonl
```

## 8. Extract specific files (DEX, native libs, etc.)

```python
from apk_info import APK

apk = APK("./app.apk")

# All DEX files
for name in apk.namelist():
    if name.startswith("classes") and name.endswith(".dex"):
        data, _ = apk.read(name)
        with open(name, "wb") as f:
            f.write(data)

# A specific file
data, compression = apk.read("assets/config.json")
print(f"compression: {compression}")
```

CLI equivalent:
```bash
apk-info extract ./app.apk -f 'classes\d+\.dex' -f 'assets/.*'
```

## 9. Detect BadPack / tampered compression

BadPack malware tampers with zip headers to break standard parsers. The most common trick: set the compression method field to a bogus value (e.g. `55914`) while the data is actually stored or deflated normally. Standard tools like `unzip` and `7z` refuse to extract such entries; apk-info detects the mismatch and decompresses correctly.

Check the compression type returned by `read()`:

```python
from apk_info import APK, FileCompressionType

apk = APK("./suspicious.apk")
for name in apk.namelist():
    _, compression = apk.read(name)
    if compression in (FileCompressionType.STORED_TAMPERED, FileCompressionType.DEFLATED_TAMPERED):
        print(f"TAMPERED: {name} ({compression})")
```

CLI: `apk-info extract -v` prints tampered compression types in bold red:

```
[*] extracted "AndroidManifest.xml" (StoredTampered)
```

### Real-world example: standard tools fail on BadPack

Below is a real BadPack malware sample (a multidex APK impersonating Facebook, signed with a fake "Facebook Corporation" certificate). The `AndroidManifest.xml` entry has its compression method set to `55914` — a nonexistent method. Here's how each tool handles it:

**`unzip`** — skips the manifest entirely, exits 0 (silent data loss):
```
$ unzip ./malware.apk -d ./out/
warning:  filename too long--truncating.        # garbage entries with overlong names
   skipping: AndroidManifest.xml  unsupported compression method 55914
$ echo $?
0
$ ls ./out/AndroidManifest.xml
ls: ./out/AndroidManifest.xml: No such file or directory
```

**`7z` / `7zz`** — creates the manifest as a 0-byte file, reports a headers error, exits 0:
```
$ 7zz x ./malware.apk -o./out/
ERROR: Headers Error : AndroidManifest.xml
ERROR: Cannot open output file : errno=63 : File name too long   # garbage entries
Sub items Errors: 9
$ ls -la ./out/AndroidManifest.xml
-rw-r--r--  0 bytes    AndroidManifest.xml          # empty!
```

**`apk-info`** — detects the tampered compression, extracts the manifest fully:
```
$ apk-info extract -v ./malware.apk -f AndroidManifest.xml
[*] extracted "AndroidManifest.xml" (StoredTampered)   # BadPack detected, data recovered

$ apk-info show ./malware.apk
Package Name: com.example.myapplication
Main Activity: com.example.myapplication/.MainActivity
Min SDK Version: 28
Target SDK Version: 33
Application Label: PENNY
```

The same analysis in Python:

```python
from apk_info import APK, Signature, FileCompressionType

apk = APK("./malware.apk")

# The manifest is extractable — apk-info handles BadPack
data, compression = apk.read("AndroidManifest.xml")
print(compression)  # FileCompressionType.STORED_TAMPERED
print(len(data))    # 6604 — full manifest recovered

# Quick triage
print(apk.get_package_name())          # "com.example.myapplication"
print(apk.get_application_label())     # "PENNY"
print(apk.is_multidex())               # True (9 DEX files)

# Dangerous permissions
for p in sorted(apk.get_permissions()):
    print(p)
# android.permission.DELETE_PACKAGES
# android.permission.INSTALL_PACKAGES
# android.permission.QUERY_ALL_PACKAGES
# android.permission.REQUEST_INSTALL_PACKAGES

# Fake signing certificate (impersonating Facebook)
for sig in apk.get_signatures():
    match sig:
        case Signature.V2() | Signature.V3():
            cert = sig.certificates[0]
            print(cert.subject)        # CN=Facebook Corporation,OU=Facebook,...
            print(cert.sha256_fingerprint)
```

**Why this matters:** when processing malware collections, silent extraction failures from `unzip`/`7z` mean you lose the `AndroidManifest.xml` — the most important file for triage — without knowing it. apk-info always recovers it.

## 10. Check if an APK is launchable

```python
from apk_info import APK

apk = APK("./app.apk")
if not apk.get_main_activities():
    print("not launchable (no MAIN+LAUNCHER/INFO intent filter)")
else:
    for activity in apk.get_main_activities():
        print(f"launchable: {apk.get_package_name()}/{activity}")
```

## 11. Identify device targets (TV, watch, auto, chromebook)

```python
from apk_info import APK

apk = APK("./app.apk")
targets = []
if apk.is_leanback():    targets.append("TV/Leanback")
if apk.is_wearable():    targets.append("Wear/Watch")
if apk.is_automotive():  targets.append("Automotive")
if apk.is_chromebook():  targets.append("Chromebook")
print("Targets:", targets or ["Phone/Tablet"])
```

## 12. Resolve a resource reference

Manifest attributes often reference resources (`@string/app_name`). These are auto-resolved by dedicated getters, but you can resolve any reference manually:

```python
from apk_info import APK

apk = APK("./app.apk")
print(apk.get_resource_value("@string/app_name"))        # "Cool App"
print(apk.get_resource_value("@drawable/ic_launcher"))   # "res/drawable-xhdpi/ic_launcher.png"
```

## 13. Read a custom manifest attribute

For attributes without a dedicated getter, use `get_attribute_value`:

```python
from apk_info import APK

apk = APK("./app.apk")
print(apk.get_attribute_value("application", "networkSecurityConfig"))
print(apk.get_attribute_value("application", "allowClearUserData"))
print(apk.get_attribute_value("manifest", "sharedUserId"))
```

## 14. Compare two APKs by signing certificate

```python
from apk_info import APK, Signature

def signing_keys(path):
    apk = APK(path)
    keys = set()
    for sig in apk.get_signatures():
        match sig:
            case Signature.V1() | Signature.V2() | Signature.V3() | Signature.V31():
                for cert in sig.certificates:
                    keys.add(cert.sha256_fingerprint)
    return keys

a = signing_keys("./app-v1.apk")
b = signing_keys("./app-v2.apk")
print("same signer:", a == b)
print("only in v1:", a - b)
print("only in v2:", b - a)
```

## 15. Process XAPK / APKM bundles

No special handling needed — `APK(path)` auto-detects the format and parses the inner APK.

```python
from apk_info import APK

apk = APK("./app.xapk")   # or .apkm
print(apk.get_package_name())
```

## 16. Why not just use unzip / 7z?

Standard archive tools fail silently on malware-tampered APKs. apk-info was built specifically for this. Common failure modes seen in real malware:

| Tool | Failure | Consequence |
|------|---------|-------------|
| `unzip` | `unsupported compression method 55914` → skips file | `AndroidManifest.xml` missing, exit 0 (no error signal) |
| `unzip` | `filename too long--truncating` | Garbage entries with overlong/non-ASCII names truncate silently |
| `7z` / `7zz` | `Headers Error` on manifest | `AndroidManifest.xml` created as **0 bytes** (empty), exit 0 |
| `7z` / `7zz` | `File name too long` (errno=63) | Garbage entries skipped, but exit 0 hides the partial extraction |
| `jar` / Python `zipfile` | `BadZipFile` or unsupported compression | Entire archive rejected — no data extracted at all |

The critical problem is **exit code 0** — scripts and pipelines that check `$?` will assume success and proceed with incomplete data.

### Safe extraction with apk-info

```bash
# Extract everything — tampered entries flagged, path-traversal names skipped,
# and over-long garbage paths saved under an md5 hash (data never lost, never aborts)
apk-info extract ./malware.apk

# Extract only what you need (regex filter)
apk-info extract ./malware.apk -f 'AndroidManifest.xml' -f 'classes\d+\.dex' -f 'resources.arsc'
```

```python
from apk_info import APK, FileCompressionType

apk = APK("./malware.apk")

# Read a file that unzip/7z couldn't extract
data, compression = apk.read("AndroidManifest.xml")
if compression in (FileCompressionType.STORED_TAMPERED, FileCompressionType.DEFLATED_TAMPERED):
    print(f"warning: {compression} — BadPack technique detected")
# data is always correctly decompressed regardless of compression type

# Iterate all entries — apk-info's namelist comes from the central directory
# and is not affected by tampered local headers
for name in apk.namelist():
    try:
        data, comp = apk.read(name)
    except Exception as e:
        print(f"skipped {name}: {e}")
```

### Quick comparison script

```python
import subprocess, sys
from apk_info import APK

path = sys.argv[1]

# What unzip extracts
r = subprocess.run(["unzip", "-l", path], capture_output=True, text=True)
unzip_listed = sum(1 for line in r.stdout.splitlines() if line.strip() and not line.startswith(("Archive", "  Length", "---")))

# What apk-info can read
apk = APK(path)
apk_count = sum(1 for _ in apk.namelist())

print(f"zip central directory entries: {apk_count}")
print(f"unzip listed entries:          {unzip_listed}")

# Check for BadPack
tampered = []
for name in apk.namelist():
    _, comp = apk.read(name)
    if "TAMPERED" in repr(comp):
        tampered.append(name)

if tampered:
    print(f"BadPack detected — {len(tampered)} tampered entries:")
    for name in tampered:
        print(f"  {name}")
```

## 17. Repack a BadPack APK so standard tools can open it

Instead of relying on apk-info for every read, you can rebuild the archive with correct headers once, then hand it to any standard tool (`unzip`, `7z`, `jar`, androguard, `aapt`, …). This is exactly what the CLI `repack` command does: decode every entry with the BadPack-aware reader and write it back into a clean, well-formed zip (Deflate-compressed, correct CRC32, sizes and offsets).

```bash
apk-info repack ./malware.apk                  # → ./malware.repacked.apk
apk-info repack ./malware.apk -o ./clean/      # → ./clean/malware.repacked.apk
apk-info repack ./malware-collection/          # repack a whole folder
```

**Before** — `unzip` drops the tampered manifest:
```
$ unzip -t ./malware.apk
    testing: AndroidManifest.xml     unknown compression method   # ← BadPack
```

**After** — the repacked archive validates and extracts cleanly:
```
$ apk-info repack ./malware.apk
[*] repacked "malware.apk" - fixed 1 tampered entry -> "malware.repacked.apk"

$ unzip -t ./malware.repacked.apk
No errors detected in compressed data of malware.repacked.apk.

$ unzip -p ./malware.repacked.apk AndroidManifest.xml   # now readable
$ apk-info show ./malware.repacked.apk                  # full info works
```

> **Note:** the rebuilt archive is **unsigned** — v1 signature files (`META-INF/`) and the APK Signature Block (v2/v3) are not reproduced. Use it for analysis, not for direct sideloading.
