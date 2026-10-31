# Signatures and certificates

Android APKs carry their signatures in two places:

- **v1 (JAR signing):** `META-INF/*.SF` plus a PKCS#7 block in `META-INF/*.RSA`, `*.DSA` or `*.EC`.
- **The APK Signing Block:** a binary block right before the zip central directory. It holds the v2, v3, v3.1 and v3.2 signatures, plus other entries: source stamps, distribution channels, Google Play Frosting.

`get_signatures()` returns all of them as a list, one entry per scheme or block.

## All signatures

=== "Python"

    ```python
    --8<-- "examples/guides/signatures.py:all"
    ```

=== "Rust"

    ```rust
    --8<-- "core/examples/signatures.rs:all"
    ```

=== "CLI"

    ```bash
    apk-info show --signatures app.apk
    apk-info show --signatures --json app.apk
    ```

For Telegram from Google Play, the Python version prints:

```text
V1: CN=Nikolay Kudashov,OU=VK,O=VK,L=Saint-Petersburg
  ...
V2: CN=Nikolay Kudashov,OU=VK,O=VK,L=Saint-Petersburg
  ...
V3: CN=Nikolay Kudashov,OU=VK,O=VK,L=Saint-Petersburg
  ...
source stamp: CN=Android,OU=Android,O=Google Inc.,L=Mountain View,ST=California,C=US
Google Play Frosting block present
```

## What each entry means

| Entry | Python / Rust | Content |
|---|---|---|
| v1 | `Signature.V1` / `Signature::V1` | certificates from the PKCS#7 block |
| v2 | `V2` | certificates of every signer |
| v3 | `V3` | certificates; v3 adds key rotation |
| v3.1 | `V31` | certificates for Android 13+, when the key was rotated |
| v3.2 | `V32` | hybrid classical + post-quantum signature |
| source stamp | `StampBlockV1`, `StampBlockV2` | certificate of the store that distributed the APK (Google Play uses `CN=Android, O=Google Inc.`) |
| channel | `ApkChannelBlock` | [Walle](https://github.com/Meituan-Dianping/walle) channel string, often JSON |
| channel | `VasDollyV2` | [VasDolly](https://github.com/Tencent/VasDolly) channel string |
| channel | `PackerNextGenV2` | raw [Packer-NG](https://github.com/mcxiaoke/packer-ng-plugin) payload |
| Play Frosting | `GooglePlayFrosting` | presence of Google Play's metadata block only |

Each certificate has `subject`, `issuer`, `serial_number`, `valid_from`, `valid_until`, `signature_type`, and the `md5_fingerprint`, `sha1_fingerprint` and `sha256_fingerprint` of the DER encoding, as lowercase hex.

Build tools sign most apps with several schemes and one key, so you see the same certificate under v1, v2 and v3. Android 7 and later verify the newest scheme they support and ignore the older ones.

!!! warning "Certificates are not verified"

    apk-info reports which certificates an APK *claims* to be signed with. It doesn't check digests or signatures over the content. To verify that an APK is intact, use `apksigner verify`.

## Same signer?

Comparing certificate fingerprints is how you tell an update from a repackaged copy, or group samples of a malware family:

=== "Python"

    ```python
    --8<-- "examples/guides/signatures.py:compare"
    ```

=== "Rust"

    ```rust
    --8<-- "core/examples/signatures.rs:compare"
    ```

=== "CLI"

    ```bash
    apk-info show --json --signatures ./apks/ | jq -r --arg fp "<sha256>" '
      select([.signatures[] | objects | to_entries[].value
              | if type == "array" then .[] else . end
              | objects | .sha256_fingerprint] | index($fp))
      | .package_name'
    ```

With key rotation (v3 / v3.1), a legitimate update can carry a different certificate than an older version. apk-info doesn't expose the rotation lineage yet, so compare the v3.1 / v3 certificate for current versions and the v1 / v2 one for old versions.

## Split containers

For XAPK, APKM and APKS files, `get_signatures()` returns the base APK's signatures. The archive itself can also be signed: APKMirror, for example, signs APKM files with its own key. `get_container_signatures()` returns that signature separately, and `show --signatures` prints it as its own block.
