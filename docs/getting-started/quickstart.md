# Quickstart

This page does the same two things with each interface: print basic information about an APK, then list its signing certificates.
The examples use `apkstest.apk`, the small test app from the repository, but any `.apk`, `.xapk`, `.apkm` or `.apks` file works. To follow along:

```bash
unzip -p core/tests/fixtures/apks-universal.apks universal.apk > apkstest.apk
```

## Basic information

=== "CLI"

    ```console
    $ apk-info show apkstest.apk
    Package Name: io.github.delvinru.apkstest
    Main Activity: io.github.delvinru.apkstest/.MainActivity
    Min SDK Version: 21
    Max SDK Version: -
    Target SDK Version: 35
    Application Label: APKS Test
    Version Name: 1.0.7
    Version Code: 7
    ABIs: x86_64
    ```

    `show` accepts several files and directories at once and walks directories recursively.

=== "Python"

    ```python
    --8<-- "examples/quickstart.py:basic"
    ```

    Getters return `None` when the manifest doesn't set the value.

=== "Rust"

    ```rust
    --8<-- "core/examples/quickstart.rs:basic"
    ```

    Getters return `Option`, so a missing manifest attribute is `None` rather than an error.

The Python and Rust examples print:

```text
Package:     io.github.delvinru.apkstest
Version:     1.0.7
Min SDK:     21
Target SDK:  35
Label:       APKS Test
Main:        .MainActivity
```

The CLI prints the main activity as a `package/activity` component name, ready for `adb shell am start -n`. The library returns the activity name as written in the manifest, which may be relative (`.MainActivity`).

## Signatures

=== "CLI"

    ```console
    $ apk-info show --signatures apkstest.apk
    ...
    APK Signature block:
      Type: v1
      Serial Number: 1bdde6531ed48e6b
      Subject: CN=apk-info apks test
      Issuer: CN=apk-info apks test
      Valid from: 2026-10-31T18:17:58Z
      Valid until: 2126-10-07T18:17:58Z
      Signature type: sha384WithRSAEncryption
      MD5 fingerprint: 19c9134e6e59d32b357a88a77fca527d
      SHA1 fingerprint: 5a1a310e23b7a1e074be7772595c6c19d22f8b60
      SHA256 fingerprint: 71c1bcf09db2254f8eadf5f68637f84f5c34acc04fe9c672393c518af68bc6f2

      Type: v2
      ...
    ```

=== "Python"

    ```python
    --8<-- "examples/quickstart.py:signatures"
    ```

    Each scheme has its own class (`Signature.V1`, `Signature.V2`, …), so you can `match` on it.

    ```text
    V1: CN=apk-info apks test (71c1bcf09db2254f8eadf5f68637f84f5c34acc04fe9c672393c518af68bc6f2)
    V2: CN=apk-info apks test (71c1bcf09db2254f8eadf5f68637f84f5c34acc04fe9c672393c518af68bc6f2)
    V3: CN=apk-info apks test (71c1bcf09db2254f8eadf5f68637f84f5c34acc04fe9c672393c518af68bc6f2)
    ```

=== "Rust"

    ```rust
    --8<-- "core/examples/quickstart.rs:signatures"
    ```

    `Signature::name()` gives a short scheme name (`v1`, `v3.1`, `Stamp Block v2`, …).

    ```text
    v1: CN=apk-info apks test (71c1bcf09db2254f8eadf5f68637f84f5c34acc04fe9c672393c518af68bc6f2)
    v2: CN=apk-info apks test (71c1bcf09db2254f8eadf5f68637f84f5c34acc04fe9c672393c518af68bc6f2)
    v3: CN=apk-info apks test (71c1bcf09db2254f8eadf5f68637f84f5c34acc04fe9c672393c518af68bc6f2)
    ```

Build tools sign most APKs with several schemes and one key, so the same certificate shows up once per scheme.
For split containers, `get_signatures()` returns the base APK's signatures, and `get_container_signatures()` returns the signature of the outer archive, if it has one.

## JSON output

For scripts, `show --json` prints one JSON object per APK (JSONL):

```console
$ apk-info show --json apkstest.apk | jq '{package_name, version_name, min_sdk_version}'
{
  "package_name": "io.github.delvinru.apkstest",
  "version_name": "1.0.7",
  "min_sdk_version": "21"
}
```

## Run the examples

Both examples live in the repository, and CI runs them on every change:

=== "Python"

    ```bash
    python examples/quickstart.py apkstest.apk
    ```

=== "Rust"

    ```bash
    cargo run --example quickstart -- apkstest.apk
    ```

## Next steps

- [CLI reference](../reference/cli.md): extraction, manifest decoding, repacking BadPack samples.
- [Python API](../reference/python.md): permissions, components, resources and more.
