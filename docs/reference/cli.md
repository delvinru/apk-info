# CLI reference

```text
Usage: apk-info [COMMAND]

Commands:
  show        Show basic information about the APK file
  extract     Unpack apk files as zip archive [alias: x]
  axml        Read and pretty-print binary AndroidManifest.xml
  repack      Repack a BadPack-damaged APK into a clean, well-formed zip archive
  completion  Generate shell completion
  help        Print this message or the help of the given subcommand(s)
```

Commands that take `<PATHS>...` accept files and directories. They walk directories recursively and skip entries whose names start with a dot.

## `show`

Prints the package name, main activity, SDK versions, application label, version and ABIs.

```bash
apk-info show [OPTIONS] <PATHS>...
```

| Option | Description |
|---|---|
| `-s`, `--signatures` | Also print the APK Signing Block contents: v1–v3.2 certificates, source stamps, channel blocks. For XAPK / APKM / APKS files, the outer archive's own signature (if any) is printed separately from the app's. |
| `-j`, `--json` | Print one JSON object per APK (JSONL) instead of colored text. |

```bash
apk-info show app.apk
apk-info show app.apk other.apk ./folder-of-apks/
apk-info show --signatures app.apk
apk-info show --json ./folder-of-apks/
```

`show` reports a file that fails to parse on stderr as `"<path>" - <error>` and moves on, so `show` is safe to run over large collections of broken samples, and stdout stays valid JSONL with `--json`. The exit code stays `0`.

### JSON output

```console
$ apk-info show --json --signatures apkstest.apk | jq
{
  "path": "apkstest.apk",
  "package_name": "io.github.delvinru.apkstest",
  "version_name": "1.0.7",
  "version_code": "7",
  "main_activity": "io.github.delvinru.apkstest/.MainActivity",
  "min_sdk_version": "21",
  "max_sdk_version": "-",
  "target_sdk_version": "35",
  "application_label": "APKS Test",
  "abis": ["x86_64"],
  "signatures": [
    {
      "v1": [
        {
          "serial_number": "1bdde6531ed48e6b",
          "subject": "CN=apk-info apks test",
          "issuer": "CN=apk-info apks test",
          "valid_from": "2026-10-31T18:17:58Z",
          "valid_until": "2126-10-07T18:17:58Z",
          "signature_type": "sha384WithRSAEncryption",
          "md5_fingerprint": "19c9134e6e59d32b357a88a77fca527d",
          "sha1_fingerprint": "5a1a310e23b7a1e074be7772595c6c19d22f8b60",
          "sha256_fingerprint": "71c1bcf09db2254f8eadf5f68637f84f5c34acc04fe9c672393c518af68bc6f2"
        }
      ]
    },
    { "v2": [ ... ] },
    { "v3": [ ... ] }
  ]
}
```

- `path` is the file the object describes, as passed on the command line or found in a directory.
- Missing values are printed as `"-"`.
- `signatures` is present only with `--signatures`. Each element is an object with a single key naming the block, except Google Play Frosting:
    - `v1`, `v2`, `v3`, `v31`, `v32`: a list of certificates;
    - `stamp_block_v1`, `stamp_block_v2`: a single certificate;
    - `apk_channel_block`, `vasdolly_v2`, `bytedance`: a string;
    - `packer_next_gen_v2`: a list of bytes;
    - Google Play Frosting is the plain string `"google_play_frosting"` (presence only).
- `container_signatures` has the same shape. It is present only with `--signatures`, and only when an XAPK / APKM / APKS archive is itself signed, which is rare.
- Fingerprints are lowercase hex without separators.

## `extract` (alias `x`)

Unpacks the APK. It decodes tampered (BadPack) entries, so it works on files where `unzip` and `7z` fail.

```bash
apk-info extract [OPTIONS] <PATHS>...
```

| Option | Description |
|---|---|
| `-o`, `--output <DIR>` | Base output directory. Each APK goes to `<DIR>/<filename>.unp/`. Default: `./<filename>.unp/`. |
| `-f`, `--files <REGEX>` | Extract only entries whose name matches the regular expression. Repeat to allow several patterns. |
| `-v`, `--verbose` | Print every extracted file. By default only notable entries are printed: the manifest, `resources.arsc`, native libraries and tampered entries. |
| `-r`, `--resources` | Decode resources apktool-style (see below). |
| `-l`, `--list` | List the archive instead of extracting it: size, compression method and compressed size per entry. Honors `-f`; ignores `-o`, `-v` and `-r`. Tampered entries are marked with `!`{ .hl }. |

```bash
# everything, to ./app.apk.unp/
apk-info extract app.apk

# to ./out/app.apk.unp/
apk-info extract app.apk -o out/

# only DEX files and the manifest
apk-info extract app.apk -f 'classes\d*\.dex' -f 'AndroidManifest.xml'

# only native libraries
apk-info extract app.apk -f 'lib/.*\.so'

# list contents without extracting
apk-info x -l app.apk
```

```console
$ apk-info x -l apkstest.apk
[*] listing 8 entries of "apkstest.apk"
      size  method           csize  name
      6028  Deflate           1738  AndroidManifest.xml
      1143  Deflate           1047  META-INF/BNDLTOOL.RSA
       616  Deflate            418  META-INF/BNDLTOOL.SF
       489  Deflate            332  META-INF/MANIFEST.MF
         9  Stored               9  lib/x86_64/libstub.so
        69  Stored              69  res/drawable-xxhdpi-v4/icon.png
       448  Deflate            184  res/xml/splits0.xml
      1060  Stored            1060  resources.arsc
```

### Decoding resources

With `-r`, the binary `AndroidManifest.xml` and XML resources become readable XML, and `resources.arsc` is expanded into `res/values*/` (strings, plurals, arrays, colors, styles, …) and `res/<type>[-<config>]/` folders, like apktool or jadx do.

- It writes only the resources registered in the resource table and skips obfuscated decoy files under `res/`.
- For XAPK / APKM / APKS files, it merges the resources of the base APK and every config split into one `res/` tree, so you get every locale and configuration variant in one place. The base `AndroidManifest.xml` goes to the output root.

```bash
apk-info extract app.apk -r
apk-info extract app.xapk -r -o out/
```

### Hostile archives

`extract` keeps going on malformed samples:

- It skips path traversal and placeholder entries (names starting with `..` or `/`, empty names, directory entries) and prints a warning.
- It saves an entry whose name is too long for the filesystem under the MD5 of the name.
- It skips entries that collide with an already extracted file or directory.
- It reports a broken sample as `[-] can't extract ...` and continues with the batch.
- It writes entries in central directory order, so the output is the same on every run.

## `axml`

Decodes a binary `AndroidManifest.xml` and prints it.

```bash
apk-info axml <PATH>
```

`<PATH>` is an APK / XAPK / APKM / APKS file, or a raw binary `AndroidManifest.xml`. On a terminal it highlights the syntax; in a pipe it prints plain XML.

```bash
apk-info axml app.apk > AndroidManifest.xml
apk-info axml app.apk | grep uses-permission
```

## `repack`

Rebuilds a BadPack-damaged APK as a clean zip archive, with correct compression headers, CRC32 checksums and offsets, so that `unzip`, `7z`, androguard and other tools can open it.

```bash
apk-info repack [OPTIONS] <PATHS>...
```

| Option | Description |
|---|---|
| `-o`, `--output <FILE>` | Output file. Only valid with a single input. Combined with `-d`, it must be a bare file name. |
| `-d`, `--output-dir <DIR>` | Output directory; each input becomes `<DIR>/<name>.repacked.apk`. |

Without options, `repack` writes `<name>.repacked.apk` next to the source.

```bash
apk-info repack malware.apk                         # ./malware.repacked.apk
apk-info repack malware.apk -d clean/               # clean/malware.repacked.apk
apk-info repack malware.apk -o fixed.apk            # ./fixed.apk
apk-info repack malware.apk -o fixed.apk -d clean/  # clean/fixed.apk
apk-info repack ./samples/ -d clean/                # every APK in a folder
```

The output is **unsigned**: `repack` drops the v1 files in `META-INF/` and the APK Signing Block. To install it, re-sign it, for example with [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer):

```bash
java -jar uber-apk-signer.jar --apks malware.repacked.apk
```

A typical workflow for a sample that standard tools can't open:

```bash
unzip -t malware.apk                                  # AndroidManifest.xml: unknown compression method
apk-info repack malware.apk                           # -> malware.repacked.apk
unzip -p malware.repacked.apk AndroidManifest.xml     # works now
```

## `completion`

```bash
apk-info completion <SHELL>
```

`<SHELL>` is `bash`, `elvish`, `fish`, `powershell` or `zsh`. See [Installation](../getting-started/installation.md#shell-completion).

## Exit codes

- `show` reports per-file errors and exits with `0`.
- `extract`, `axml` and `repack` exit with `1` on error.

## Recipes

```bash
# all package names in a folder
apk-info show --json ./apks/ | jq -r .package_name | sort -u

# APKs signed with a given certificate (SHA-256 fingerprint)
apk-info show --json --signatures ./apks/ | jq -r --arg fp "<sha256>" '
  select([.signatures[] | objects | to_entries[].value
          | if type == "array" then .[] else . end
          | objects | .sha256_fingerprint] | index($fp))
  | .package_name'

# one decoded manifest per APK
mkdir -p manifests
for apk in ./apks/*.apk; do
  apk-info axml "$apk" > "manifests/$(basename "$apk" .apk).xml"
done

# DEX files of every APK in a folder
apk-info extract ./apks/ -f 'classes\d*\.dex'
```
