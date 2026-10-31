# FAQ

## Why not androguard?

androguard decompiles DEX files and builds call graphs, which apk-info doesn't do. For metadata across many APKs, androguard is 6–10× slower (see [Benchmarks](benchmarks.md)) and fails on tampered samples that Android installs. Use apk-info for the metadata, and hand the DEX files to androguard, jadx or another decompiler.

## Can apk-info modify or sign APKs?

No. apk-info only reads APKs. Use apktool to modify an APK and apksigner or [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer) to sign it.

The one command that writes an archive is `repack`. It produces a clean, **unsigned** copy of a damaged APK so other tools can open it. To install the copy, sign it:

```bash
java -jar uber-apk-signer.jar --apks malware.repacked.apk
```

## Does apk-info verify signatures?

No. It reports which certificates an APK is signed with, but doesn't check the signatures against the content. Use `apksigner verify --print-certs` for that.

## Does it decompile DEX files?

No. `read()` and `extract` give you the DEX files; use jadx, apktool or androguard to decompile them.

## Is it safe to run on malware?

apk-info only parses files and never executes code from them. Extraction skips path traversal entries and other hostile file names (see [Malformed and tampered APKs](guides/malformed-apks.md#extracting-hostile-archives-safely)). Analyze malware in an isolated environment anyway.

## Which Python versions are supported?

CPython 3.11 and newer, on Linux, macOS and Windows.

## Where do I report a bug?

On [GitHub](https://github.com/delvinru/apk-info/issues). If apk-info fails on an APK that Android installs, attach the sample or its hash.
