# Signature test fixtures

Golden APK fixtures produced by the AOSP [`apksig`][apksig] project
(Apache License 2.0, Copyright (C) The Android Open Source Project).
Each file is a minimal CTS "tinyapp" signed by the apksig test suite to
exercise one parser path; see the test file comments for what each
fixture covers.

[apksig]: https://source.android.com/docs/security/features/apksigning

## Provenance

Copied verbatim from `src/test/resources/com/android/apksig/` of the
`platform/tools/apksig` repository (Android 17 development branch).
The upstream files and the signing-scheme documentation they exercise:

| Fixture                                                         | Scheme / path                        |
| --------------------------------------------------------------- | ------------------------------------ |
| `v1-only-with-rsa-2048.apk`                                     | v1 (JAR signing)                     |
| `v2-only-with-rsa-pkcs1-sha256-2048.apk`                        | v2                                   |
| `v2-only-10-signers.apk`                                        | v2, multiple signers                 |
| `v2-only-unknown-pair-in-apk-sig-block.apk`                     | v2 + unknown ID-value pair           |
| `v3-only-with-rsa-pkcs1-sha256-2048.apk`                        | v3                                   |
| `v31-tgt-33-no-v3-attr.apk`                                     | v3.1 (key rotation targeting SDK 33) |
| `v32-mldsa-rsa-2048_2-v3-rsa-2048-min-max-strip-attr-valid.apk` | v3.2 hybrid (ML-DSA + RSA)           |
| `stamp-1-v31-tgt-33-signer.apk`                                 | v2 source stamp + v2/v3/v3.1         |
| `golden-rsa-verity-out.apk`                                     | verity padding block                 |
| `v1-only-with-rsa-1024-cert-not-der.apk`                        | negative case: non-DER certificate   |

## Robustness fixtures (`broken-*` prefix)

Deliberately malformed archives, also from the upstream `apksig` test
suite. The contract under test: a damaged archive fails with a clean
`ZipError` (never a panic), and a damaged signature block degrades
gracefully. See `tests/signatures_broken.rs`.

| Fixture                                                          | Damage                                        |
| ---------------------------------------------------------------- | --------------------------------------------- |
| `broken-empty-unsigned.apk`                                      | not a ZIP archive                             |
| `broken-v2-only-empty.apk`                                       | not a ZIP archive                             |
| `broken-v3-only-empty.apk`                                       | not a ZIP archive                             |
| `broken-invalid_manifest.apk`                                    | EOCD record missing                           |
| `broken-v1-only-empty.apk`                                       | v1 signature over an empty APK body           |
| `broken-v1-only-max-sized-eocd-comment.apk`                      | 64 KiB ZIP comment (EOCD scan window edge)    |
| `broken-v2-only-max-sized-eocd-comment.apk`                      | 64 KiB ZIP comment (EOCD scan window edge)    |
| `broken-v2-only-garbage-between-cd-and-eocd.apk`                 | garbage between CD and EOCD (stale CD offset) |
| `broken-v2-only-truncated-cd.apk`                                | truncated central directory                   |
| `broken-v2-only-no-certs-in-sig.apk`                             | v2 signer with an empty certificate list      |
| `broken-v3-only-no-certs-in-sig.apk`                             | v3 signer with an empty certificate list      |
| `broken-v1v2v3-with-rsa-2048-lineage-3-signers-no-sig-block.apk` | APK Signing Block stripped                    |
| `broken-stamp-malformed-signature.apk`                           | stamp block truncated to one payload byte     |
| `broken-v2-only-apk-sig-block-size-mismatch.apk`                 | signing block leading/trailing sizes disagree |

Total size of both sets: about 400 KB — deliberately a curated set, one
file per parser path, not the full upstream verification-failure matrix.
