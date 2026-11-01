---
hide:
  - navigation
  - toc
---

<div class="apk-hero" markdown>

<h1 class="apk-hero__title" aria-label="apk-info">
--8<-- "docs/assets/logo/wordmark.svg"
</h1>

<p class="apk-hero__lead"><strong>Fast, malware-robust parser for Android apk/xapk/apkm/apks files.</strong> Written in Rust, with a CLI and typed Python bindings.</p>

[Quickstart](getting-started/quickstart.md){ .md-button .md-button--primary }
[GitHub](https://github.com/delvinru/apk-info){ .md-button }

</div>

=== "Homebrew"

    ```bash
    brew install delvinru/tap/apk-info
    ```

=== "Nix"

    ```bash
    nix profile install github:delvinru/apk-info
    ```

=== "cargo"

    ```bash
    cargo install apk-info-cli
    ```

=== "Python"

    ```bash
    pip install apk-info
    ```

Then point it at an APK:

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

## What it handles

<div class="apk-points" markdown>

**Tampered archives**
Reads APKs built with the [BadPack](guides/malformed-apks.md) technique: fake compression methods, mismatched headers, fake EOCD records. A broken resource table doesn't stop the manifest, DEX files or signatures from being read.

**Signatures**
v1 to v3.2 certificates, source stamps, Walle, VasDolly, Packer-NG and ByteDance channels, Google Play Frosting. See [Signatures](guides/signatures.md).

**Manifest and resources**
Full AXML and ARSC parsers, resource resolution, apktool-style decoding, and the main activity resolved the way Android does it.

**Split containers**
XAPK, APKM and APKS open through their base APK; resources of all splits decode into one tree. See [XAPK, APKM and APKS](guides/containers.md).

**Speed**
On one thread, 34× faster than androguard on clean apps and 8× on 23,745 malware samples, with a fraction of its memory. See [Benchmarks](benchmarks.md).

**Read-only**
Never modifies, signs or decompiles anything. `repack` writes a clean copy of a damaged archive so other tools can open it.

</div>

## Next

- [Quickstart](getting-started/quickstart.md): the same task with the CLI, Python and Rust.
- [Guides](guides/inspecting.md): manifest, components, signatures, files, containers, malformed APKs, batch processing.
- [CLI reference](reference/cli.md) and [Python API](reference/python.md). The Rust API is on [docs.rs](https://docs.rs/apk-info/latest/apk_info/).
