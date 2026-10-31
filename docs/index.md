---
hide:
  - navigation
  - toc
---

<div class="apk-hero" markdown>

<h1 class="apk-hero__title" aria-label="apk-info">
--8<-- "docs/assets/logo/wordmark.svg"
</h1>

<p class="apk-hero__lead"><strong>A fast, malware-friendly, read-only parser for Android APK files.</strong> Written in Rust, with a CLI and typed Python bindings.</p>

[Quickstart](getting-started/quickstart.md){ .md-button .md-button--primary }
[GitHub](https://github.com/delvinru/apk-info){ .md-button }

</div>

=== "Homebrew"

    ```bash
    brew install delvinru/tap/apk-info
    ```

=== "cargo"

    ```bash
    cargo install apk-info-cli
    ```

=== "Python"

    ```bash
    pip install apk-info
    ```

```console
$ apk-info show apkstest.apk
Package Name: io.github.delvinru.apkstest
Main Activity: io.github.delvinru.apkstest/.MainActivity
Min SDK Version: 21
Target SDK Version: 35
Application Label: APKS Test
Version Name: 1.0.7
ABIs: x86_64
```

## What it handles

<div class="apk-points" markdown>

**Tampered archives**
Reads APKs built with the [BadPack](guides/malformed-apks.md) technique: fake compression methods, mismatched headers, fake EOCD records. A broken resource table doesn't stop the manifest, DEX files or signatures from being read.

**Signatures**
v1 to v3.2 certificates, source stamps, Walle, VasDolly and Packer-NG channels, Google Play Frosting. See [Signatures](guides/signatures.md).

**Manifest and resources**
Full AXML and ARSC parsers, resource resolution, apktool-style decoding, and the main activity resolved the way Android does it.

**Split containers**
XAPK, APKM and APKS open through their base APK; resources of all splits decode into one tree. See [XAPK, APKM and APKS](guides/containers.md).

**Speed**
6.6× faster than androguard on 13,374 malware samples, 9.8× on clean apps. See [Benchmarks](benchmarks.md).

**Read-only**
Never modifies, signs or decompiles anything. `repack` writes a clean copy of a damaged archive so other tools can open it.

</div>

## Next

- [Quickstart](getting-started/quickstart.md): the same task with the CLI, Python and Rust.
- [Guides](guides/inspecting.md): manifest, components, signatures, files, containers, malformed APKs, batch processing.
- [CLI reference](reference/cli.md) and [Python API](reference/python.md). The Rust API is on [docs.rs](https://docs.rs/apk-info/latest/apk_info/).
