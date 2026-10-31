# Benchmarks

apk-info against [androguard](https://github.com/androguard/androguard), both used from Python.

## Setup

- macOS Tahoe 26.6.1, Apple M3 Pro (12 cores)
- apk-info built with the `release-lto` profile and called through its Python bindings, so both tools pay the same interpreter overhead
- logging at warning level

Each tool runs the same [script](https://github.com/delvinru/apk-info/blob/main/examples/benchmark/bench.py) over every file, sequentially:

1. extract all signatures;
2. read the package name;
3. read the minimum SDK version;
4. list the main activities;
5. read the application name.

## Clean apps

152 APKs, 20 GB in total.

| Run | apk-info | androguard |
|---|---|---|
| 1 | 6.58 s | 63.85 s |
| 2 | 6.49 s | 64.80 s |
| 3 | 6.42 s | 61.55 s |

apk-info is about **9.8× faster**.

## Malware

13,374 APKs, 68 GB in total, from the [VirusShare Android collection](https://vx-underground.org/Samples/Virusshare%20Collection/Downloadable%20Releases). The collection has 14,026 samples; both tools reject the 652 files that aren't valid zip or APK archives, so the benchmark leaves them out.

| Run | apk-info | androguard |
|---|---|---|
| 1 | 26.99 s | 178.01 s |
| 2 | 27.01 s | 176.74 s |
| 3 | 26.61 s | 177.20 s |

apk-info is about **6.6× faster**.

## Why it's faster

- Opening an APK reads only the central directory, the manifest and `resources.arsc`. DEX files and other entries are read on demand.
- apk-info reads the APK Signing Block from its fixed position before the central directory, without scanning the file.
- The zip, AXML and ARSC parsers are native Rust code; androguard's are pure Python.

## Run it yourself

```bash
uv pip install apk-info androguard loguru
python examples/benchmark/bench.py ./samples/
python examples/benchmark/bench_androguard.py ./samples/
```
