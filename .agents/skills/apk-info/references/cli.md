# CLI reference

The `apk-info` CLI has five subcommands. Run `apk-info --help` or `apk-info <command> --help` for built-in help.

## Contents

- [show — basic APK info](#show--basic-apk-info)
- [extract (alias x) — unpack the APK](#extract-alias-x--unpack-the-apk)
- [axml — pretty-print AndroidManifest.xml](#axml--pretty-print-androidmanifestxml)
- [completion — generate shell completions](#completion--generate-shell-completions)
- [repack — unpack and rebuild a BadPack-damaged APK](#repack--unpack-and-rebuild-a-badpack-damaged-apk)
- [Exit codes & error behavior](#exit-codes--error-behavior)
- [Common pipelines](#common-pipelines)

## `show` — basic APK info

Prints package name, version, SDK versions, main activity, application label, and ABIs. Optionally includes signatures.

```bash
apk-info show <PATH> [<PATH> ...]
```

**Options:**

- `-s, --sigs` — also show APK signature block contents (v1/v2/v3/v3.1 certificates, stamp blocks, channel blocks, packers).
- `-j, --json` — output as JSONL (one JSON object per APK) instead of colored text. Suitable for piping to `jq` or other tools.
- Paths can be files or directories. Directories are walked recursively; dotfile entries are skipped.

**Examples:**

```bash
# Single file, human-readable
apk-info show ./app.apk

# Multiple files / directories
apk-info show ./app.apk ./other.apk ./folder-of-apks/

# Include signatures
apk-info show --sigs ./app.apk

# JSONL output for scripting
apk-info show --json ./app.apk
apk-info show --json ./malware-collection/ | jq -c '. | {package: .package_name, version: .version_name}'
```

**JSONL schema** (from `--json`):

```json
{
  "package_name": "com.example.app",
  "version_name": "1.2.3",
  "version_code": "2025101912",
  "main_activity": "com.example.app/.MainActivity",
  "min_sdk_version": "26",
  "max_sdk_version": "-",
  "target_sdk_version": "34",
  "application_label": "Example App",
  "abis": ["arm64-v8a", "armeabi-v7a"],
  "signatures": null
}
```

The `signatures` field is `null` unless `--sigs` is passed, in which case it contains an array of signature objects (filtered to exclude `Unknown`).

## `extract` (alias `x`) — unpack the APK

Extracts files from the APK's zip archive to disk.

```bash
apk-info extract <PATH> [<PATH> ...] [-o <OUTPUT_DIR>] [-f <REGEX> ...]
```

**Options:**

- `-o, --output <DIR>` — base output directory. Each APK is extracted to `<DIR>/<filename>.unp/`. If omitted, defaults to `./<filename>.unp/`.
- `-f, --files <REGEX>` — only extract files whose name matches the regex. Can be repeated to allow multiple patterns. Any match passes.
- `-v, --verbose` — print progress for every extracted file. By default only "interesting" files are shown: `AndroidManifest.xml`, `resources.arsc`, `.so` libraries, and tampered (BadPack) entries; all other files are printed only in verbose mode.
- `-r, --resources` — apktool-style resource decode (see below).

**Examples:**

```bash
# Extract everything to ./app.apk.unp/
apk-info extract ./app.apk

# Extract to a specific base dir → ./out/app.apk.unp/
apk-info extract ./app.apk -o ./out/

# Extract only DEX files and the manifest
apk-info extract ./app.apk -f 'classes\d+\.dex' -f 'AndroidManifest.xml'

# Extract native libraries only
apk-info extract ./app.apk -f 'lib/.*\.so'

# Decode resources apktool-style
apk-info extract ./app.apk -r
```

### `-r, --resources` — apktool-style resource decode

Decodes the package like `apktool`/`jadx`: the binary `AndroidManifest.xml` and
XML resources become readable XML, and `resources.arsc` is exploded into
`res/values*/...` (strings, plurals, arrays, colors, styles, ...) plus canonical
`res/<type>[-<config>]/` file-resource folders. The decoded entries live alongside
the raw extraction in `<out>/<file>.unp/` (the manifest, `resources.arsc` and
`res/*` entries are produced by the decode, not copied as raw files).

- **Arsc-driven, not zip-scan:** only resources registered in the resource table
  are emitted, so obfuscated flat decoy files under `res/` (e.g. Telegram's
  random `res/<xxx>.xml`) are skipped — matching apktool/jadx. See
  `recipes.md` §18.
- **Split containers (XAPK/APKM):** resources of the inner base *and* every
  `config.*`/`split_*` APK are merged into one `res/` tree, so all
  locale/configuration string variants are present in a single place; the base's
  `AndroidManifest.xml` stays at the output root (split manifests are not emitted).

```bash
# Decode a plain APK → ./app.apk.unp/res/values*/, .../res/<type>-<cfg>/, AndroidManifest.xml
apk-info extract ./app.apk -r

# Split container: merge base + config-split string variants
apk-info extract ./app.xapk -r -o ./out/
```

**Output highlighting:** `AndroidManifest.xml` and `resources.arsc` are highlighted in green/bold; `.so` files in magenta; other files are plain. The compression type is shown in parentheses — tampered types (`StoredTampered`/`DeflatedTampered`, indicating the BadPack technique) are shown in bold red. These interesting/tampered entries are shown by default; plain files are printed only with `--verbose`.

Path-traversal and placeholder entries (paths starting with `..` or `/`, empty names, directory entries ending in `/`) are skipped with a warning to avoid path traversal.

Malicious/broken paths are extracted safely: if a single component or the full output path is too long for the filesystem (`File name too long`, e.g. deeply nested garbage names used to break `unzip`/`7z`), apk-info prints a warning and saves the data under an **md5 hash** of the original name instead of the broken path, so nothing is lost and extraction never aborts.

## `axml` — pretty-print AndroidManifest.xml

Decodes the binary AndroidManifest.xml into human-readable XML and prints it.

```bash
apk-info axml <PATH>
```

The path can be either:

- An APK/XAPK/APKM file (the manifest is extracted and decoded from it).
- A raw binary `AndroidManifest.xml` file (parsed directly).

When stdout is a TTY, output is syntax-highlighted via `bat`. When piped, raw XML is printed (no ANSI codes), so you can redirect to a file:

```bash
apk-info axml ./app.apk > AndroidManifest.xml
apk-info axml ./app.apk | grep 'uses-permission'
```

## `completion` — generate shell completions

Generates completion scripts for the given shell.

```bash
apk-info completion <SHELL>
```

`<SHELL>` is one of: `bash`, `elvish`, `fish`, `powershell`, `zsh`.

**Examples:**

```bash
# Bash — add to ~/.bashrc or save to a completion directory
apk-info completion bash > /etc/bash_completion.d/apk-info

# Zsh
apk-info completion zsh > "${fpath[1]}/_apk-info"

# Fish
apk-info completion fish > ~/.config/fish/completions/apk-info.fish
```

## `repack` — unpack and rebuild a BadPack-damaged APK

Reads every entry using the same robust decoder as `extract` (which handles the `BadPack` technique) and writes the data back into a fresh, well-formed zip archive with correct compression headers, CRC32 checksums and offsets. This "repack" lets tools that choke on tampered headers — `unzip`, `7z`, androguard, etc. — open the APK normally.

```bash
apk-info repack <PATH> [<PATH> ...] [-o <OUTPUT_DIR>]
```

**Options:**

- `-o, --output <DIR>` — write results into `<DIR>/<name>.repacked.apk`. If omitted, the output is written next to the source file as `<name>.repacked.apk` (source stem + `.repacked.apk`).
- Paths can be files or directories. Directories are walked recursively; dotfile entries are skipped.

**Examples:**

```bash
apk-info repack ./malware.apk                      # → ./malware.repacked.apk
apk-info repack ./malware.apk -o ./clean/          # → ./clean/malware.repacked.apk
apk-info repack ./malware-collection/              # repack every APK in a folder
```

**Output highlighting:** the source path is green; when the archive contained tampered (`StoredTampered`/`DeflatedTampered`) entries, a `fixed N tampered entries` message is printed (bold).

> **Note:** the rebuilt archive is **NOT signed** — v1 signature files under `META-INF/` and the APK Signature Block (v2/v3/stamp/channel blocks) are not reproduced. Treat the output as an unsigned APK.

**Typical workflow** for a sample where `unzip`/`7z` fail or drop `AndroidManifest.xml`:

```bash
# before: unzip silently skips the manifest
unzip -t ./malware.apk          # ... AndroidManifest.xml: unknown compression method

# fix the headers via repack, then use any standard tool
apk-info repack ./malware.apk   # → ./malware.repacked.apk
unzip -p ./malware.repacked.apk AndroidManifest.xml   # now works
apk-info show ./malware.repacked.apk                  # package info readable
```

## Exit codes & error behavior

- On a per-file parse error, `show` prints the error in red and continues to the next file (exit 0 unless a fatal error occurs). This makes it safe to run over large collections of potentially-malformed files.
- `extract`, `axml` and `repack` propagate errors via `anyhow` and print them with `{:#}` formatting.
- `show` separates multiple APKs with a blank line in human-readable mode; JSONL mode emits one line per APK with no separator.

## Common pipelines

```bash
# Collect all package names from a folder
apk-info show --json ./apks/ | jq -r .package_name | sort -u

# Find APKs signed by a specific certificate (by SHA256 fingerprint)
apk-info show --json --sigs ./apks/ | jq -r 'select(.signatures[].certificates[].sha256_fingerprint == "ab:cd:...") | .package_name'

# Dump every manifest to its own file
for apk in ./apks/*.apk; do
  name=$(basename "$apk" .apk)
  apk-info axml "$apk" > "manifests/$name.xml"
done

# Extract just the DEX files from every APK in a folder
apk-info extract ./apks/ -f 'classes\d*\.dex'

# Quick triage: package, version, and main activity for a single file
apk-info show ./app.apk | grep -E 'Package|Main|Version'
```
