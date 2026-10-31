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

```console hl_lines="8"
$ apk-info show badpack.apk
Package Name: io.github.delvinru.apkstest
Main Activity: io.github.delvinru.apkstest/.MainActivity
...

$ apk-info extract -l badpack.apk -f AndroidManifest.xml
      size  method           csize  name
      6028  Deflate!          1738  AndroidManifest.xml
```

The `!`{ .hl } marks an entry whose local header disagrees with the central directory.

Other tricks seen in the wild that apk-info handles:

- an end-of-central-directory record that is fake, duplicated or hidden in the archive comment;
- central directory records past the declared entry count, used to shadow real entries;
- wrong sizes and offsets in local headers;
- entries named with path traversal (`../`), absurdly long names, or names that collide with directories;
- garbage chunks in `AndroidManifest.xml` and a `resources.arsc` broken on purpose.

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
