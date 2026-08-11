# CLI reference

The `apk-info` CLI has four subcommands. Run `apk-info --help` or `apk-info <command> --help` for built-in help.

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
```

**Output highlighting:** `AndroidManifest.xml` and `resources.arsc` are highlighted in green/bold; `.so` files in magenta; other files are plain. The compression type is shown in parentheses — tampered types (`StoredTampered`/`DeflatedTampered`, indicating the BadPack technique) are shown in bold red.

Bad filenames (paths starting with `..` or `/`, empty names, directory entries ending in `/`) are skipped with a warning to avoid path traversal.

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

## Exit codes & error behavior

- On a per-file parse error, `show` prints the error in red and continues to the next file (exit 0 unless a fatal error occurs). This makes it safe to run over large collections of potentially-malformed files.
- `extract` and `axml` propagate errors via `anyhow` and print them with `{:#}` formatting.
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
