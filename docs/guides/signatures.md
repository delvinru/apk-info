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
| channel | `ByteDance` | ByteDance build config (Toutiao), usually JSON, returned as is |
| channel | `PackerNextGenV2` | raw [Packer-NG](https://github.com/mcxiaoke/packer-ng-plugin) payload |
| Play Frosting | `GooglePlayFrosting` | presence of Google Play's metadata block only |

Each certificate has `subject`, `issuer`, `serial_number`, `valid_from`, `valid_until`, `signature_type`, and the `md5_fingerprint`, `sha1_fingerprint` and `sha256_fingerprint` of the certificate as it is stored in the APK, as lowercase hex.

Build tools sign most apps with several schemes and one key, so you see the same certificate under v1, v2 and v3. Android 7 and later verify the newest scheme they support and ignore the older ones.

!!! warning "Certificates are not verified"

    apk-info reports which certificates an APK *claims* to be signed with. It doesn't check digests or signatures over the content. To verify that an APK is intact, use `apksigner verify`.

## Seen in the wild

What `apk-info show -s` prints for real apps. The certificates are cut down to their subject and SHA-256 fingerprint.

### Toutiao: key rotation, a Walle channel and a ByteDance config

Toutiao, ByteDance's news app, carries three things in one signing block. v1 and v2 are signed by the original 2011 key, v3 by a newer one: the key was rotated, and Android 9 and later trust the v3 signer. Next to the signatures, a Walle channel records the build (Git commit, branch, store channel), and a ByteDance block holds the app's build config.

Sample: Toutiao 13.9.0, sha256 `a1112a0c941f865847c2fab9138cf815735268fbfcd41d697412fb80992c7395`.

```console
$ apk-info show -s com.ss.android.article.news.apk
APK Signature block:
  Type: v1
  Subject: CN=Micro Cao,OU=ByteDance,O=ByteDance,L=Beijing,ST=Beijing,C=CN
  SHA256 fingerprint: d7811ec4166fea6cc720ba66699dc84b584ac9e6986613a76d4e43d8cbe32b27

  Type: v2
  Subject: CN=Micro Cao,OU=ByteDance,O=ByteDance,L=Beijing,ST=Beijing,C=CN
  SHA256 fingerprint: d7811ec4166fea6cc720ba66699dc84b584ac9e6986613a76d4e43d8cbe32b27

  Type: v3
  Subject: CN=Aweme Douyin,OU=ByteDance,O=ByteDance,L=Beijing,ST=Beijing,C=CN
  SHA256 fingerprint: 5182ae3b1b85337bb182cf24882449f84447ded18e296a747a9f6a0a2622512e

  Type: APK Channel block
  Channel: {"GIT_SHA": "ac4de1ddd3b", "build_timestamp": "2025-09-15_13-59-05", "GIT_BRANCH": "(HEAD detached at ac4de1ddd)", "meta_umeng_channel": "oppo_13_64", ...}

  Type: ByteDance
  Value: {"include_login_type": "", "branch_info": "x master", "close_weibo_sso": false, "close_short_cut_create": false, ...}
```

### Trip.com: a Walle channel per store

Apps distributed through many Chinese and third-party stores get one build per store, told apart by the Walle channel. Trip.com's build for the Samsung store:

Sample: Trip.com 8.58.0, sha256 `73f4abf490df542d4405d0a5f8703014bfd174e7bbd1ddb2aaf1ded8e7f85031`.

```console
$ apk-info show -s ctrip.english-8.58.0.apk
  Type: APK Channel block
  Channel: {"channel":"55555902","channelName":"samsung","version":"0","channelId":"55555902","channelCode":"samsung","extInfo":"{\"adjustToken\":\"7xfiwmopy3k0\"}"}
```

### AnyDesk: v3.1 rotation, a source stamp and Play Frosting

An app from Google Play: v2 and v3 are signed with the old key, v3.1 with the new one, which Android 13 and later verify. The source stamp is Google Play's certificate, and the Frosting block marks Play's own metadata.

Sample: AnyDesk 9.0.2, sha256 `7a1dd53e976cf053ac23c6b8b69e1f923a8802d1ff1751223ec82097a5ff0dfc`.

```console
$ apk-info show -s com.anydesk.anydeskandroid-9.0.2.xapk
  Type: v3
  Subject: CN=philandro Software GmbH,O=philandro Software GmbH,L=Stuttgart,ST=BW,C=DE
  SHA256 fingerprint: 74dc8452007ccdfefc366b65ad5361a255745d1f962a3565e6cf0f78762db316

  Type: v3.1
  Subject: CN=AnyDesk Software GmbH,O=AnyDesk Software GmbH,L=Stuttgart,ST=BW,C=DE
  SHA256 fingerprint: c4f5781df5c7f28e8167d7e69bede8aea687da8e8d0ba4bc5fb7b238cc0f8ff5

  Type: Stamp Block v2
  Subject: CN=Android,OU=Android,O=Google Inc.,L=Mountain View,ST=California,C=US
  SHA256 fingerprint: 3257d599a49d2c961a471ca9843f59d341a405884583fc087df4237b733bbd6d

  Type: Google Play Frosting
  Info: Metadata exist
```

### Malware: VasDolly and Packer-NG channels

Channel blocks show up in malware too, and tie samples to a distribution campaign. A trojan from the VirusShare collection, packaged with Tencent's VasDolly:

Sample: Trojan.AndroidOS.Guerrilla.y (`com.mockuai.mkselleros`), sha256 `815b175120768838e503cda4b731fcf328aad8c39b1fc19d0ddd8d8823d36dde`.

```console
$ apk-info show -s guerrilla.apk
  Type: v2-VasDolly
  Channel: tencent
```

A dropper with a Packer-NG channel. apk-info returns the payload as it is stored, as hex:

Sample: Trojan-Dropper.AndroidOS.Agent.san (`cn.xichan.mycoupon.ui`), sha256 `95cb273e5fce8d48f7921d2a2591c1b3f6d683be946a47bef9587c9ddfe4fc66`.

```console
$ apk-info show -s dropper.apk
  Type: Packer NG v2
  Value: 5061636b6572204e6720536967205632260000004348414e4e454ce288986d79636f75706f6e5f7979625f376432353035383030373632e2889926000000
```

Decoded, it is the magic `Packer Ng Sig V2`, a length, and `CHANNEL∘mycoupon_yyb_7d2505800762∙`: the key and the value of the channel are separated by `∘`, and `∙` ends the pair.

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
      select(any(.signatures[].certificates[]?; .sha256_fingerprint == $fp))
      | .package_name'
    ```

With key rotation (v3 / v3.1), a legitimate update can carry a different certificate than an older version. apk-info doesn't expose the rotation lineage yet, so compare the v3.1 / v3 certificate for current versions and the v1 / v2 one for old versions.

## Split containers

For XAPK, APKM and APKS files, `get_signatures()` returns the base APK's signatures. The archive itself can also be signed: APKMirror, for example, signs APKM files with its own key. `get_container_signatures()` returns that signature separately, and `show --signatures` prints it as its own block.
