# Python API reference

Complete catalog of the `apk_info` Python API (≥3.10, full type stubs included). Import with `from apk_info import APK`. All examples assume `apk = APK("./file.apk")`.

## Setup

```bash
uv pip install apk-info
# or: pip install apk-info
```

```python
from apk_info import APK, APKError, Signature, CertificateInfo, FileCompressionType
```

## Basic information

```python
apk.get_package_name()        # str | None — e.g. "com.example.app"
apk.get_version_name()        # str | None — e.g. "1.2.3"
apk.get_version_code()        # str | None — e.g. "2025101912" (string on purpose: malware may put junk here)
apk.get_min_sdk_version()     # str | None — e.g. "26"
apk.get_target_sdk_version()  # int — falls back to min_sdk, then 1
apk.get_max_sdk_version()     # str | None
apk.get_install_location()    # "auto" | "internalOnly" | "preferExternal" | None
apk.get_build_version_code()  # str | None — platformBuildVersionCode
apk.get_build_version_name()  # str | None
apk.get_compile_sdk_version() # str | None
apk.get_compile_sdk_version_codename()  # str | None
```

## Shared user ID

```python
apk.get_shared_user_id()                # str | None
apk.get_shared_user_label()             # str | None
apk.get_shared_user_max_sdk_version()   # str | None
```

## Main (launchable) activity

A main activity has an intent filter with action `MAIN` and category `LAUNCHER` or `INFO`. Resolution follows the Android OS algorithm.

```python
apk.get_main_activity()       # str | None — first launchable activity
apk.get_main_activities()     # list[str] — all launchable activities (order preserved)

# Example
activities = apk.get_main_activities()
if not activities:
    print("not launchable")
else:
    print(f"{apk.get_package_name()}/{activities[0]}")
```

## Application-level attributes

All return `str | None`. Values that are `@string/...` references are auto-resolved via `resources.arsc` when available.

```python
apk.get_application_label()           # app display name (resolved)
apk.get_application_name()            # Application subclass, e.g. "com.example.App"
apk.get_application_icon()            # path inside APK, e.g. "res/drawable/ic_launcher.png"
apk.get_application_logo()            # path inside APK
apk.get_application_debuggable()      # "true" | "false" | None
apk.get_application_allow_backup()    # "true" | "false" | None
apk.get_application_category()        # "game" | "social" | "news" | ... | None
apk.get_application_backup_agent()    # class name | None
apk.get_application_description()     # resolved string | None
apk.get_application_task_reparenting()  # "true" | "false" | None
```

## Permissions

```python
apk.get_permissions()          # set[str] — from <uses-permission>
apk.get_permissions_sdk23()    # set[str] — from <uses-permission-sdk-23>
apk.get_declared_permissions() # set[Permission] — <permission> elements defined by the app
```

`Permission` dataclass fields: `name`, `label`, `description`, `icon`, `permission_group`, `protection_level` (all `str | None`).

```python
for perm in apk.get_declared_permissions():
    print(f"{perm.name} — {perm.protection_level}")
```

## Features, libraries

```python
apk.get_features()           # set[str] — <uses-feature>, e.g. "android.hardware.camera"
apk.get_libraries()          # set[str] — <uses-library>
apk.get_native_libraries()   # set[str] — <uses-native-library>
```

## Device-type checks

```python
apk.is_automotive()  # bool — android.hardware.type.automotive
apk.is_leanback()    # bool — TV (android.hardware.type.television or android.software.leanback)
apk.is_wearable()    # bool — watch (android.hardware.type.watch)
apk.is_chromebook()  # bool — android.hardware.type.pc
```

## Manifest components

Each returns a list of frozen dataclasses with `str | None` fields. Activities, activity-aliases, and intent filters carry nested structures.

```python
apk.get_activities()        # list[Activity]
apk.get_activity_aliases()  # list[ActivityAlias]
apk.get_services()          # list[Service]
apk.get_receivers()         # list[Receiver]
apk.get_providers()         # list[Provider]
apk.get_attributions()      # set[Attribution]
```

**`Activity`** fields: `enabled`, `exported`, `icon`, `label`, `name`, `parent_activity_name`, `permission`, `process`, `intent_filters: list[IntentFilter]`.

**`ActivityAlias`** fields: `enabled`, `exported`, `icon`, `label`, `name`, `permission`, `target_activity`, `intent_filters: list[IntentFilter]`.

**`IntentFilter`** fields: `actions: list[str]`, `categories: list[str]`.

**`Service`** fields: `description`, `direct_boot_aware`, `enabled`, `exported`, `foreground_service_type`, `icon`, `isolated_process`, `label`, `name`, `permission`, `process`, `stop_with_task`.

**`Receiver`** fields: `direct_boot_aware`, `enabled`, `exported`, `icon`, `label`, `name`, `permission`, `process`.

**`Provider`** fields: `authorities`, `enabled`, `direct_boot_aware`, `exported`, `grant_uri_permissions`, `icon`, `init_order`, `label`, `multiprocess`, `name`, `permission`, `process`, `read_permission`, `syncable`, `write_permission`.

**`Attribution`** fields: `tag`, `label`.

```python
for activity in apk.get_activities():
    print(f"{activity.name} (exported={activity.exported})")
    for f in activity.intent_filters:
        print(f"  actions={f.actions} categories={f.categories}")
```

## Signatures & certificates

```python
apk.get_signatures()             # list[Signature] — raises APKError if certs can't be parsed
apk.get_container_signatures()   # list[Signature] — distributor's signature on a `xapk`/`apkm` container
```

`get_signatures()` returns the app signatures. For a plain APK that is the
file itself; for a `xapk`/`apkm` container it is the inner base APK, the
real app identity. `get_container_signatures()` is separate: it returns the
signature on the outer archive and is empty for plain APKs and for most
unsigned containers.

`Signature` is a union of frozen dataclass variants. Match with `match`/`case`:

```python
for sig in apk.get_signatures():
    match sig:
        case Signature.V1() | Signature.V2() | Signature.V3() | Signature.V31():
            # sig.certificates: list[CertificateInfo]
            for cert in sig.certificates:
                print(cert.subject, cert.sha256_fingerprint)
        case Signature.StampBlockV1() | Signature.StampBlockV2():
            # sig.certificate: CertificateInfo
            print("stamp:", sig.certificate.subject)
        case Signature.ApkChannelBlock():
            print("channel:", sig.value)
        case Signature.PackerNextGenV2():
            print("packer-ng:", sig.value.hex())
        case Signature.VasDollyV2():
            print("vasdolly:", sig.value)
        case Signature.GooglePlayFrosting():
            print("play frosting present")
```

**`CertificateInfo`** fields: `serial_number`, `subject`, `issuer`, `valid_from`, `valid_until`, `signature_type`, `md5_fingerprint`, `sha1_fingerprint`, `sha256_fingerprint` (all `str`).

## Reading files from the APK

```python
data, compression = apk.read("classes.dex")
# data: bytes
# compression: FileCompressionType — STORED | DEFLATED | STORED_TAMPERED | DEFLATED_TAMPERED

with open("out.bin", "wb") as f:
    f.write(data)
```

`STORED_TAMPERED` / `DEFLATED_TAMPERED` indicate the BadPack technique — the declared compression method didn't match reality, but the data was still correctly decompressed.

## File listing & multidex

```python
apk.namelist()      # list[str] — all entries in the zip central directory
apk.is_multidex()   # bool — True if more than one classes*.dex exists
```

## Native ABIs

```python
apk.get_supported_abis()  # list[str] — sorted, e.g. ["arm64-v8a", "armeabi-v7a", "x86_64"]
```

Derived from `lib/<abi>/*.so` paths in the archive.

## Pretty-printed manifest

```python
xml_string = apk.get_xml_string()  # str — human-readable AndroidManifest.xml
print(xml_string)
```

## Generic attribute access

For attributes without a dedicated getter:

```python
# First matching tag's attribute (resolves @refs via ARSC)
apk.get_attribute_value("application", "networkSecurityConfig")  # str | None

# All values for a tag+attribute across the manifest
apk.get_all_attribute_values("uses-permission", "name")  # list[str]

# Resolve a @string/... / @drawable/... reference manually
apk.get_resource_value("@string/app_name")  # str | None
apk.get_resource_value("@drawable/ic_launcher")  # str | None
```

## Error handling

```python
from apk_info import APK, APKError

try:
    apk = APK("./maybe-malicious.apk")
except FileNotFoundError:
    print("file missing")
except APKError as e:
    print(f"parse failed: {e}")

# get_signatures() can raise APKError on certificate parse failure
try:
    sigs = apk.get_signatures()
except APKError as e:
    print(f"sig error: {e}")
```

`APK(path)` raises:

- `FileNotFoundError` — path doesn't exist
- `TypeError` — argument isn't `str` or `PurePath`
- `APKError` — parse failure (malformed zip, manifest, or resources)

## Dataclass note

All returned objects are frozen dataclasses — fields are accessible as attributes (`cert.subject`) and they're hashable/immutable. Use `repr(obj)` for a readable one-line summary (every class implements `__repr__`).
