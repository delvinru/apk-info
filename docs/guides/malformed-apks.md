# Malformed and tampered APKs

Android's package installer accepts zip files that `unzip`, `7z` and most APK tools reject. Malware authors use this gap: an APK that installs and runs on a phone may fail to unpack on your analysis machine. The best-known variant is [BadPack](https://unit42.paloaltonetworks.com/apk-badpack-malware-tampered-headers/).

apk-info reads these files the way Android does.

## How BadPack works

A zip file describes every entry twice: in a local header right before its data, and in the central directory at the end of the file. Android takes the compression method and sizes from the central directory and ignores most of the local header. BadPack samples put garbage in the local headers, for example a compression method of `55914`, which doesn't exist.

The sample below is the test app from the repository (`apkstest.apk`, see the [Quickstart](../getting-started/quickstart.md)) with the local header of `AndroidManifest.xml` patched to method `55914`; the central directory is intact, so Android installs it as usual. Standard tools lose the manifest:

```console
$ unzip -o badpack.apk -d out/
  ...
out/AndroidManifest.xml:  unknown compression method
$ ls -l out/AndroidManifest.xml
-rw-r--r--  0  out/AndroidManifest.xml         # empty

$ 7zz x badpack.apk -oout/
ERROR: Headers Error : AndroidManifest.xml
$ ls -l out/AndroidManifest.xml
-rw-r--r--  0  out/AndroidManifest.xml         # empty
```

Without the manifest you get no package name, no permissions and no components, and your triage script gets no error to notice.

apk-info reads the file and flags the tampered header:

```console hl_lines="10 11 15"
$ apk-info show --anomalies badpack.apk
badpack.apk
  Package         io.github.delvinru.apkstest
  Label           APKS Test
  Version         1.0.7 (7)
  SDK             min 21 · target 35
  Main activity   io.github.delvinru.apkstest/.MainActivity
  ABIs            x86_64

Tampering         YES · 1 tampered
  ✗ compression_method_mismatch     AndroidManifest.xml: compression method 8 in the central directory, 55914 in the local header

$ apk-info extract -l badpack.apk -f AndroidManifest.xml
      size  method           csize  name
      6028  Deflate!          1738  AndroidManifest.xml
```

`--anomalies` names the technique, and in `extract -l` the `!`{ .hl } marks an entry whose local header disagrees with the central directory.

Other tricks seen in the wild that apk-info handles:

- an end-of-central-directory record that is fake, duplicated or hidden in the archive comment;
- central directory records past the declared entry count, used to shadow real entries;
- wrong sizes and offsets in local headers;
- entries named with path traversal (`../`), absurdly long names, or names that collide with directories;
- an entry name that isn't valid UTF-8, read with `�` so the entries after it stay visible;
- a compressed entry whose declared size disagrees with its data: the real data is returned and flagged as tampered;
- garbage chunks in `AndroidManifest.xml` and a `resources.arsc` broken on purpose.

Like Android, apk-info rejects a file with no end-of-central-directory record in its last 64 KB: a truncated archive, or one with data appended after it.

## Checking an APK for tampering

`anomalies()` lists the structural defects of an APK: the zip tricks above, a damaged `AndroidManifest.xml` or `resources.arsc`, an odd container layout. Each anomaly has a stable `code`, a `severity`, the `location` (an entry name, `base.apk!classes.dex` inside a container, or none for the archive itself) and a human-readable description. `is_tampered()` is true when any anomaly is rated `tampered`.

| Severity     | Meaning                                                                                     |
| ------------ | ------------------------------------------------------------------------------------------- |
| `tampered`   | a known technique against static analysis tools                                             |
| `suspicious` | no ordinary build tool produces it, but plain corruption, an exotic tool or a protector can |
| `info`       | a quirk that ordinary build tools produce too                                               |

None of the 5,714 store apps from the [Benchmarks](../benchmarks.md) has a `tampered` anomaly. See [Anomalies](../reference/anomalies.md) for how each severity is decided and the list of every anomaly.

=== "Python"

    ```python
    --8<-- "examples/guides/files.py:anomalies"
    ```

    ```text
    [tampered] AndroidManifest.xml: compression method 8 in the central directory, 55914 in the local header
    tampered: True
    ```

=== "Rust"

    ```rust
    --8<-- "core/examples/files.rs:anomalies"
    ```

    `ZipEntry::anomalies()` from the `apk-info-zip` crate checks a bare zip archive, and `AXML::anomalies()` / `ARSC::anomalies()` from `apk-info-axml` report what their parsers recovered from.

The check is not part of opening the APK: it reads the local header of every zip entry, one small read per entry. That's instant for a file in the page cache, but on a slow disk it costs a random read per entry.

## Detecting tampered entries

=== "Python"

    ```python
    --8<-- "examples/guides/files.py:tampered"
    ```

    ```text
    tampered header: AndroidManifest.xml (deflated_tampered)
    ```

    `read()` decompresses the data, so this reads every entry. That's fine for triage, but slow for large collections.

=== "Rust"

    ```rust
    --8<-- "core/examples/files.rs:tampered"
    ```

    `ZipEntry::entry_info()` from the `apk-info-zip` crate checks the headers without decompressing anything.

=== "CLI"

    ```bash
    apk-info extract -l app.apk | grep '!'
    ```

## Repairing an APK for other tools

If you need to run other tools on the sample, `repack` rewrites it as a clean zip archive with consistent headers, CRC32 checksums and offsets:

```console
$ apk-info repack badpack.apk
[*] repacked "badpack.apk" - fixed 1 tampered entry -> "badpack.repacked.apk"

$ unzip -t badpack.repacked.apk
...
No errors detected in compressed data of badpack.repacked.apk.
```

The repacked APK is unsigned: `repack` drops the v1 signature files and doesn't copy the APK Signing Block. Analyze the original's signatures with apk-info before repacking, and re-sign the copy (for example with [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer)) if you need to install it.

## Extracting hostile archives safely

`apk-info extract` is safe to run on untrusted samples:

- it skips entries that would escape the output directory (`../`, absolute paths) and prints a warning;
- it saves an entry whose name is too long for the filesystem under the MD5 of the name;
- it skips an entry that collides with an already extracted file or directory;
- it reports a broken sample in a batch and moves on to the next one.

apk-info only parses files. It never runs code from the APK.
