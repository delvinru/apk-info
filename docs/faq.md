# FAQ

## Why not androguard?

apk-info reads APKs the way Android does, and it is fast at it. On one thread it is 34× faster than androguard on clean apps and 8× on malware, with a fraction of its memory (see [Benchmarks](benchmarks.md)).

It also opens what androguard can't: XAPK, APKM and APKS containers, archives tampered with BadPack tricks, and manifests with unterminated strings that Android installs anyway. Across 23,745 malware samples, androguard failed on 45 that apk-info parsed, and apk-info failed on none that androguard parsed.

apk-info doesn't decompile code. To analyse it, take the DEX files out with `apk-info extract` and open them in a decompiler.

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
