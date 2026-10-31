# Inspecting an APK

Everything on this page reads the decoded `AndroidManifest.xml` and, where needed, the resource table.
The examples assume an opened APK:

=== "Python"

    ```python
    from apk_info import APK

    apk = APK("app.apk")
    ```

=== "Rust"

    ```rust
    use apk_info::Apk;

    let apk = Apk::new("app.apk")?;
    ```

## Triage

=== "Python"

    ```python
    --8<-- "examples/guides/triage.py:triage"
    ```

=== "Rust"

    ```rust
    --8<-- "core/examples/triage.rs:triage"
    ```

=== "CLI"

    ```bash
    apk-info show app.apk
    ```

Output of the Python version for `apkstest.apk` (Rust prints `Option`s with `{:?}`):

```text
Package:    io.github.delvinru.apkstest
Version:    1.0.7 (7)
SDK:        min 21, target 35
Label:      APKS Test
Debuggable: None
Backup:     None
Multidex:   False
ABIs:       ['x86_64']
```

Boolean manifest attributes come back as they are written: `"true"`, `"false"`, or `None` when the attribute is absent, so you can tell an explicit `android:debuggable="false"` from a missing one.

`get_supported_abis()` lists the ABIs found under `lib/`. For XAPK / APKM / APKS files it also includes the ABIs of `config.<abi>.apk` splits.

## Is it launchable?

An app is launchable when an activity (or activity alias) handles `MAIN` with the `LAUNCHER` or `INFO` category. `get_main_activities()` follows the same rules as Android's `ApplicationPackageManager`: activity aliases count, and activities with `android:enabled="false"` are skipped. `get_main_activity()` returns the first one.

=== "Python"

    ```python
    --8<-- "examples/guides/triage.py:launchable"
    ```

=== "Rust"

    ```rust
    --8<-- "core/examples/triage.rs:launchable"
    ```

```text
adb shell am start -n io.github.delvinru.apkstest/.MainActivity
```

You get activity names as written in the manifest, so they may be relative (`.MainActivity`). `am start -n` accepts both forms.

## Device targets

=== "Python"

    ```python
    --8<-- "examples/guides/triage.py:targets"
    ```

=== "Rust"

    ```rust
    --8<-- "core/examples/triage.rs:targets"
    ```

| Method | True when `<uses-feature>` declares |
|---|---|
| `is_leanback()` | `android.software.leanback` or `android.hardware.type.television` |
| `is_wearable()` | `android.hardware.type.watch` |
| `is_automotive()` | `android.hardware.type.automotive` |
| `is_chromebook()` | `android.hardware.type.pc` |

## Any manifest attribute

Getters exist for the common attributes. For everything else, `get_attribute_value(tag, name)` returns the attribute of the first matching tag, and `get_all_attribute_values(tag, name)` returns it for every matching tag. Pass attribute names without the `android:` prefix.

=== "Python"

    ```python
    --8<-- "examples/guides/triage.py:attributes"
    ```

=== "Rust"

    ```rust
    --8<-- "core/examples/triage.rs:attributes"
    ```

## Resource references

Many manifest values are references like `@string/app_name`. Getters such as `get_application_label()` resolve them through `resources.arsc`. For anything else, use `get_resource_value()`:

=== "Python"

    ```python
    --8<-- "examples/guides/triage.py:resources"
    ```

=== "Rust"

    ```rust
    --8<-- "core/examples/triage.rs:resources"
    ```

```text
APKS Test
res/drawable-xxhdpi-v4/icon.png
APKS Test
```

File resources resolve to their path inside the archive. Release builds often shorten these paths (for example `res/7j.png`), so don't expect `res/mipmap-*/ic_launcher.png` to exist.

If `resources.arsc` is missing or corrupted on purpose, parsing still succeeds: references stay unresolved, and you can still read the manifest, DEX files and signatures.

## The full manifest

=== "Python"

    ```python
    --8<-- "examples/guides/triage.py:manifest"
    ```

=== "Rust"

    ```rust
    --8<-- "core/examples/triage.rs:manifest"
    ```

=== "CLI"

    ```bash
    apk-info axml app.apk > AndroidManifest.xml
    ```

The output is the decoded XML with resource references resolved, the same as `apk-info axml` prints.
