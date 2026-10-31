# Installation

`apk-info` ships as three packages built from the same Rust core:

| Package | For | Install |
|---|---|---|
| `apk-info` CLI | the terminal | Homebrew or `cargo install apk-info-cli` |
| `apk-info` on PyPI | Python 3.11+ | `pip install apk-info` |
| `apk-info` crate | Rust | `cargo add apk-info` |

## CLI

=== "Homebrew"

    ```bash
    brew install delvinru/tap/apk-info
    ```

=== "cargo"

    ```bash
    cargo install apk-info-cli
    ```

    Requires Rust 1.95 or newer.

=== "Prebuilt binaries"

    Download an archive for your platform from [GitHub Releases](https://github.com/delvinru/apk-info/releases). Each release has builds for:

    - Linux (static musl): `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`
    - macOS: `x86_64-apple-darwin`, `aarch64-apple-darwin`
    - Windows: `x86_64-pc-windows-msvc`
    - Android (e.g. Termux or `adb shell`): `aarch64-linux-android`

Check that it works:

```bash
apk-info --version
```

### Shell completion

`apk-info completion <SHELL>` prints a completion script for `bash`, `elvish`, `fish`, `powershell` or `zsh`:

=== "zsh"

    ```bash
    apk-info completion zsh > "${fpath[1]}/_apk-info"
    ```

=== "bash"

    ```bash
    apk-info completion bash > ~/.local/share/bash-completion/completions/apk-info
    ```

=== "fish"

    ```bash
    apk-info completion fish > ~/.config/fish/completions/apk-info.fish
    ```

## Python

PyPI has wheels for Linux, macOS and Windows. You need CPython 3.11 or newer.

=== "uv"

    ```bash
    uv add apk-info
    ```

=== "pip"

    ```bash
    pip install apk-info
    ```

The package includes type stubs, so editors and type checkers see the full API.

```python
from apk_info import APK

apk = APK("app.apk")
print(apk.get_package_name())
```

## Rust

```bash
cargo add apk-info
```

The `apk-info` crate re-exports the lower-level crates. If you need only one part of the parser, depend on that crate:

| Crate | What it does |
|---|---|
| [`apk-info`](https://docs.rs/apk-info) | high-level `Apk` API: manifest, resources, signatures, containers |
| [`apk-info-zip`](https://docs.rs/apk-info-zip) | malware-tolerant zip reader and APK Signing Block parser |
| [`apk-info-axml`](https://docs.rs/apk-info-axml) | Android binary XML (AXML) and resource table (ARSC) parsers |
| [`apk-info-xml`](https://docs.rs/apk-info-xml) | XML element tree used by the AXML parser |
