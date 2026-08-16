# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.12] - 2026-08-17

### Added

- apktool-style resource decode via `extract -r`: decodes the manifest, XML resources, and `resources.arsc` into `res/values*` and `res/<type>[-<cfg>]/` folders; merges resources of the base and every config split for `xapk`/`apkm` containers. ([f22340b](https://github.com/delvinru/apk-info/commit/f22340b))
- `get_container_signatures()` in the Rust and Python APIs — signature of the outer `xapk`/`apkm` container, separate from the app. ([f3d9c5d](https://github.com/delvinru/apk-info/commit/f3d9c5d))
- Container signature shown as its own block in `show --sigs` and `--json`. ([f3d9c5d](https://github.com/delvinru/apk-info/commit/f3d9c5d))
- New `repack` CLI command. ([90f0aeb](https://github.com/delvinru/apk-info/commit/90f0aeb))
- APKM format support for default extraction. ([759b39c](https://github.com/delvinru/apk-info/commit/759b39c))
- Show supported ABIs in the CLI; renamed to `get_supported_abis`. ([d5da648](https://github.com/delvinru/apk-info/commit/d5da648))
- Improved split APK parsing for `xapk`/`apkm` containers. ([280ced2](https://github.com/delvinru/apk-info/commit/280ced2))
- CLI ignores errors when reading files from an APK. ([6ddec0f](https://github.com/delvinru/apk-info/commit/6ddec0f))

### Changed

- `get_signatures()` returns the inner base APK signature for `xapk`/`apkm`, reflecting the real app identity. ([f3d9c5d](https://github.com/delvinru/apk-info/commit/f3d9c5d))
- ZIP signing verification moved from `openssl` to `x509_cert`. ([3563807](https://github.com/delvinru/apk-info/commit/3563807))

### Breaking Changes

- Python `APK.read()` reports compression mode as a string hint (`"stored"`, `"deflated"`, `"stored_tampered"`, `"deflated_tampered"`) instead of the `FileCompressionType` enum. ([476e511](https://github.com/delvinru/apk-info/commit/476e511))

### Performance

- `mimalloc` global allocator in the CLI and Python: ~2.6x lower peak memory, ~5% faster end-to-end Python parsing, ~22% less user CPU on large batches. ([f388c8e](https://github.com/delvinru/apk-info/commit/f388c8e))
- NUL-terminated UTF-16 package names decoded without an intermediate `Vec<u16>` allocation. ([f388c8e](https://github.com/delvinru/apk-info/commit/f388c8e))

### Fixed

- Parse prepended-data / polyglot and ZIP64-EOCD archives via robust central-directory offset resolution. ([13a2103](https://github.com/delvinru/apk-info/commit/13a2103))
- Read entries using the central directory (compression, sizes) for BadPack-safety, still flagging method mismatches as tampered. ([834f079](https://github.com/delvinru/apk-info/commit/834f079))
- Clamp an oversized EOCD `comment_length` instead of failing the whole parse. ([834f079](https://github.com/delvinru/apk-info/commit/834f079))
- Recover from a corrupted `local_header_offset` via lazy filename-verified scanning. ([834f079](https://github.com/delvinru/apk-info/commit/834f079))
- Deterministically resolve `@string/...` references on obfuscated ARSC (lowest-ID match). ([07f3bc4](https://github.com/delvinru/apk-info/commit/07f3bc4))
- More robust XML output on malicious input. ([770118e](https://github.com/delvinru/apk-info/commit/770118e))
- Fix AXML namespace-string typo. ([bd0e954](https://github.com/delvinru/apk-info/commit/bd0e954))
- Output serial number as hex. ([5b631e3](https://github.com/delvinru/apk-info/commit/5b631e3))

## [1.0.11] - 2026-02-25

### Added

- Intent filters support for activities; exported activity aliases ([87a02ec](https://github.com/delvinru/apk-info/commit/87a02ec)).
- More information in `show` command, including an option to output basic info as JSON ([4a32c50](https://github.com/delvinru/apk-info/commit/4a32c50)).
- Python bindings for the new API ([485d43c](https://github.com/delvinru/apk-info/commit/485d43c)).
- Information about SDK versions and native codes ([2199deb](https://github.com/delvinru/apk-info/commit/2199deb)).

### Fixed

- Intent filter could actually contain several items ([095882b](https://github.com/delvinru/apk-info/commit/095882b)).
- Python typing information ([efe16af](https://github.com/delvinru/apk-info/commit/efe16af)).

## [1.0.10] - 2026-02-19

### Fixed

- Decode system attributes before looking them up in the string pool ([714fe06](https://github.com/delvinru/apk-info/commit/714fe06)).
- Additional checks when extracting files ([67b471f](https://github.com/delvinru/apk-info/commit/67b471f)).
- Trim whitespace in the APK channel block ([0f95315](https://github.com/delvinru/apk-info/commit/0f95315)).

## [1.0.9] - 2025-12-07

### Added

- `issuer` field to `CertificateInfo` ([bfd690d](https://github.com/delvinru/apk-info/commit/bfd690d)).
- Handle `DynamicReference` type in AXML ([4753145](https://github.com/delvinru/apk-info/commit/4753145)).
- More reliable error handling during unpacking in the CLI ([faa5d02](https://github.com/delvinru/apk-info/commit/faa5d02)).
- More precise extraction using a file filter ([0091102](https://github.com/delvinru/apk-info/commit/0091102)).
- Detect a new type of signature block ([026f47c](https://github.com/delvinru/apk-info/commit/026f47c)).
- Show existence of the Google Play frosting block ([bad6327](https://github.com/delvinru/apk-info/commit/bad6327)).
- Compression type returned from the Python `read()` as an optional enum ([60ed2d0](https://github.com/delvinru/apk-info/commit/60ed2d0)).

### Fixed

- Bug with UTF-8 symbols in some malicious APKs ([03b4d14](https://github.com/delvinru/apk-info/commit/03b4d14)).

## [1.0.8] - 2025-11-14

### Added

- Better APK Signature Scheme v3-like signature parsing ([91c12c2](https://github.com/delvinru/apk-info/commit/91c12c2)).
- Parse the new signature block ([6b36a69](https://github.com/delvinru/apk-info/commit/6b36a69)).
- Handle another malicious technique in AXML ([e86b4be](https://github.com/delvinru/apk-info/commit/e86b4be)).
- `flake.nix` for installing the CLI binary ([4ebb30f](https://github.com/delvinru/apk-info/commit/4ebb30f)).

### Changed

- Use unsafe string conversion and a better hash map for zip files ([0f6be3c](https://github.com/delvinru/apk-info/commit/0f6be3c)).

### Fixed

- Better signature v2 parsing ([2c77734](https://github.com/delvinru/apk-info/commit/2c77734)).

## [1.0.7] - 2025-11-12

### Added

- Extract the `attribution` tag ([d2e69c4](https://github.com/delvinru/apk-info/commit/d2e69c4)).
- CLI autocompletion generation and pretty AXML output ([061a5b7](https://github.com/delvinru/apk-info/commit/061a5b7)).

## [1.0.6] - 2025-11-12

### Fixed

- Verify email on crates, update Python metadata ([7cc7d02](https://github.com/delvinru/apk-info/commit/7cc7d02)).

## [1.0.5] - 2025-11-12

- Release tooling fixes and dependency bumps; no user-facing changes.

## [1.0.4] - 2025-11-12

- Fix crate publishing; no user-facing changes.

## [1.0.3] - 2025-11-12

- Fix CI release setup; no user-facing changes.

## [1.0.2] - 2025-11-12

### Fixed

- Verify email on crates, update Python metadata ([7cc7d02](https://github.com/delvinru/apk-info/commit/7cc7d02)).

## [1.0.1] - 2025-11-12

- Fix Python release and CI; no user-facing changes.

## [1.0.0] - 2025-11-10

Initial release of `apk-info`, a full-featured APK parser.

### Added

- Custom ZIP parser with v1/v2/v3 signature extraction and `xapk` support.
- AXML parser for Android binary XML (`AndroidManifest.xml`), including a `resources.arsc` parser to resolve resource references.
- XML DOM logic in a dedicated crate.
- Core API for reading the manifest and its attributes (package name, version code/name, permissions, activities, services, receivers, providers, SDK versions, intent filters, etc.).
- CLI with `read`, `extract`, and `show` commands, plus pretty output.
- Python bindings.
- Fuzzing targets.

[1.0.12]: https://github.com/delvinru/apk-info/compare/v1.0.11...v1.0.12
[1.0.11]: https://github.com/delvinru/apk-info/compare/v1.0.10...v1.0.11
[1.0.10]: https://github.com/delvinru/apk-info/compare/v1.0.9...v1.0.10
[1.0.9]: https://github.com/delvinru/apk-info/compare/v1.0.8...v1.0.9
[1.0.8]: https://github.com/delvinru/apk-info/compare/v1.0.7...v1.0.8
[1.0.7]: https://github.com/delvinru/apk-info/compare/v1.0.6...v1.0.7
[1.0.6]: https://github.com/delvinru/apk-info/compare/v1.0.5...v1.0.6
[1.0.5]: https://github.com/delvinru/apk-info/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/delvinru/apk-info/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/delvinru/apk-info/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/delvinru/apk-info/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/delvinru/apk-info/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/delvinru/apk-info/releases/tag/v1.0.0
