# Processing many APKs

Malware collections contain truncated downloads, files that aren't APKs, and archives broken on purpose. Your batch job should keep going past all of them.

## CLI

`show --json` walks directories recursively and prints one JSON object per APK. It reports files that fail to parse on stderr and skips them, so stdout stays valid JSONL:

```bash
apk-info show --json ./samples/ > results.jsonl 2> errors.log
```

```bash
# package name per file
jq -r '[.path, .package_name] | @tsv' results.jsonl

# APKs that target an old SDK
jq -r 'select((.target_sdk_version | tonumber) < 29) | .path' results.jsonl
```

## Python

Catch `APKError` per file, and use processes to parse in parallel:

```python
--8<-- "examples/guides/batch.py:batch"
```

```json
{"file": "samples/junk.apk", "error": "got error while parsing apk archive: provided file is not a zip archive"}
{"file": "samples/org.adaway.apk", "package": "org.adaway", "version": "6.1.4", "min_sdk": "26", ...}
```

Parsing holds the GIL, so a thread pool won't speed things up; `ProcessPoolExecutor` will.

## Rust

`Apk` reads files independently, so threads parallelize well:

```rust
--8<-- "core/examples/batch.rs:batch"
```

## Tips

- Filter by extension (`.apk`, `.xapk`, `.apkm`, `.apks`), but don't rely on it: many malware samples have no extension. Files that aren't zip archives fail fast with `APKError`.
- `APK()` reads only the central directory, the manifest and `resources.arsc`. It reads DEX files and other entries on demand, so triage stays cheap for large APKs.
- `get_signatures()` parses the signing block when you call it.
