# Benchmarks

apk-info 1.1.0 against apk-info 1.0.13 and [androguard](https://github.com/androguard/androguard) 4.1.4, all used from Python.

!!! note "One thread"
    Every run is a single process that reads the files one at a time. apk-info doesn't use threads internally either, so the numbers show what one CPU core does. To process a collection faster, run several processes: the throughput grows with the number of cores.

## Collections

| | Clean | Malware |
|---|---|---|
| Source | app stores | [VirusShare Android](https://vx-underground.org/Samples/Virusshare%20Collection/Downloadable%20Releases), 2020–2022 |
| Files | 5,714: 4,930 APK, 784 XAPK | 23,745, no extension |
| Total size | 429 GB | 106 GB |
| File size, p10 / median / p90 / p99 / max | 7.1 / 49.5 / 180 / 365 / 2,356 MB | 0.3 / 1.8 / 13.8 / 29.7 / 33.5 MB |
| Zip entries, median / p90 / max | 1,206 / 3,563 / 36,612 | 68 / 794 / 9,156 |
| Damaged files | none | 692 that no tool opens, see [Failures](#failures) |

The clean apps are few and large, with big resource tables and many entries. The malware is many small files, plenty of them damaged on purpose.

## Method

| | |
|---|---|
| Machine | Apple M3 Pro (12 cores), 18 GB RAM, macOS Tahoe 26.6.1 |
| Python | 3.13 |
| apk-info 1.0.13 | wheel from PyPI |
| apk-info 1.1.0 | built with the `release-lto` profile, like the published wheels |
| androguard | 4.1.4, logging at error level |
| Cold run | page cache dropped before the run: every file comes from the disk, as in real use, where each file is read once |
| Warm run | the same run repeated right after, with the data in memory: the cost of the parsing alone |
| Repeats | 3 for malware, 2 for clean; the tables show the median |
| Files/s, per-file times | from the cold runs |
| Failed file | an exception, or no package name |
| Peak memory | resident set of the process over the whole run |

Work per file:

| | apk-info | androguard |
|---|---|---|
| Open | `APK(path)` | `APK(path)` |
| Package name | `get_package_name()` | `get_package()` |
| Signatures | `get_signatures()`: v1–v3.2, stamps, channels | `get_certificates()`: v1–v3.1 |
| Minimum SDK | `get_min_sdk_version()` | `get_min_sdk_version()` |
| Main activities | `get_main_activities()` | `get_main_activities()` |
| Label | `get_application_label()` | `get_app_name()` |

## Clean apps

| | Cold | Files/s | CPU | Peak memory | Failed | Warm |
|---|---|---|---|---|---|---|
| **apk-info 1.1.0** | **29.7 s** | **192** | **6.7 s** | **745 MB** | **0** | 22.5 s |
| apk-info 1.0.13 | 71.4 s | 80 | 18.2 s | 770 MB | 0 | 67.0 s |
| androguard 4.1.4 | 926.3 s | 6 | 543.2 s | 5.8 GB | 784 | 923.7 s |

androguard doesn't support XAPK: all its failures are the 784 XAPKs. Split by format:

| | APK, cold | XAPK, cold |
|---|---|---|
| **apk-info 1.1.0** | **25.3 s** | **4.2 s** |
| apk-info 1.0.13 | 31.0 s | 40.3 s |
| androguard 4.1.4 | 860.9 s | — |

Per APK, cold:

| | Median | p95 | p99 | Max |
|---|---|---|---|---|
| **apk-info 1.1.0** | **4.4 ms** | **9.7 ms** | **18.3 ms** | **0.23 s** |
| apk-info 1.0.13 | 5.2 ms | 11.9 ms | 25.1 ms | 0.31 s |
| androguard 4.1.4 | 123.0 ms | 419.8 ms | 836.9 ms | 14.6 s |

On APKs, apk-info 1.1.0 is **34× faster** than androguard.

## Malware

| | Cold | Files/s | CPU | Peak memory | Opened | Failed | Warm |
|---|---|---|---|---|---|---|---|
| **apk-info 1.1.0** | **44.7 s** | **531** | **7.6 s** | **88 MB** | **23,053** | **692** | 5.7 s |
| apk-info 1.0.13 | 76.0 s | 312 | 15.7 s | 87 MB | 23,054 | 691 | 36.8 s |
| androguard 4.1.4 | 362.6 s | 65 | 241.3 s | 794 MB | 23,008 | 737 | 345.3 s |

Per file, cold:

| | Median | p95 | p99 | Max |
|---|---|---|---|---|
| **apk-info 1.1.0** | **1.6 ms** | **3.6 ms** | **6.4 ms** | **0.01 s** |
| apk-info 1.0.13 | 1.7 ms | 5.2 ms | 42.2 ms | 0.25 s |
| androguard 4.1.4 | 7.0 ms | 48.2 ms | 98.3 ms | 0.37 s |

apk-info 1.1.0 is **8× faster** than androguard and 1.7× faster than 1.0.13. Most of its time here goes to reading the disk: 7.6 s of CPU in 44.7 s. With the files already in memory it's 60× faster than androguard.

1.0.13 reads a file without an end of central directory record in its last 64 KB from end to start, looking for one further back. 1.1.0 stops at 64 KB, like Android, which rejects such files as not zip.

### Failures

What each tool reports on the same samples:

| Samples | Files | apk-info 1.1.0 | androguard 4.1.4 |
|---|---|---|---|
| Truncated, or data appended after the archive: no EOCD in the last 64 KB | 670 | error: no EOCD | 611 no package name, 59 error: no EOCD |
| Zip without `AndroidManifest.xml` at the root | 10 | error: not an apk | no package name |
| App bundle (`.aab`) | 11 | error: app bundle | no package name |
| Truncated deflate stream | 1 | no package name | error |
| Unterminated UTF-16 strings in the manifest | 34 | **opened** | error |
| Other | 8 | **opened** | no package name |
| Truncated deflate stream, short structures | 3 | **opened** | error |

Android 9 and 14 both refuse to install the files without an EOCD in the last 64 KB (`INSTALL_PARSE_FAILED_NOT_APK`). No sample opens in androguard and fails in apk-info.

## Memory

| | Clean | Malware |
|---|---|---|
| **apk-info 1.1.0** | **745 MB** | **88 MB** |
| apk-info 1.0.13 | 770 MB | 87 MB |
| androguard 4.1.4 | 5.8 GB | 794 MB |

- apk-info keeps the manifest, the parsed resource table and the central directory of the open file; DEX files, native libraries and assets are never read.
- The resource table sets the peak: the largest `resources.arsc` among the clean apps, 168 MB, takes 650 MB once parsed.
- androguard grows to 2.7 GB halfway through the clean apps.

## Run it yourself

```bash
uv pip install apk-info androguard loguru
python examples/benchmark/bench.py ./samples/
python examples/benchmark/bench_androguard.py ./samples/
```

Both scripts run on one thread and print the time, the failures by error type and the peak memory.
