# Files and resources

## Reading entries

`namelist()` lists the entries from the zip central directory, and `read()` returns an entry's decompressed bytes together with how it was stored.

=== "Python"

    ```python
    --8<-- "examples/guides/files.py:read"
    ```

    The compression hint is `"stored"`, `"deflated"`, `"stored_tampered"` or `"deflated_tampered"`.

=== "Rust"

    ```rust
    --8<-- "core/examples/files.rs:read"
    ```

    The compression is a `FileCompressionType`: `Stored`, `Deflated`, `StoredTampered` or `DeflatedTampered`.

=== "CLI"

    ```bash
    apk-info extract -l app.apk
    ```

For XAPK, APKM and APKS files, `namelist()` and `read()` work on the outer archive, so you can read `manifest.json` or an individual split. Pass `base=True` (Python) or use `get_base_zip()` (Rust) to read the app's own files. See [XAPK, APKM and APKS](containers.md#reading-files-of-the-base-apk).

A `_tampered`{ .hl } value means the entry's local header disagrees with the central directory, a sign of [BadPack](malformed-apks.md). apk-info still returns the correct data.

## DEX files and native libraries

=== "Python"

    ```python
    --8<-- "examples/guides/files.py:dex"
    ```

=== "Rust"

    ```rust
    --8<-- "core/examples/files.rs:dex"
    ```

=== "CLI"

    ```bash
    apk-info extract app.apk -f 'classes\d*\.dex'
    apk-info extract app.apk -f 'lib/.*\.so'
    ```

`is_multidex()` tells you whether there is more than one `classes*.dex`, and `get_native_libraries()` returns the libraries declared with `<uses-native-library>` in the manifest (not the `.so` files under `lib/`).

## The app icon

`get_application_icon()` resolves `android:icon` to a path inside the archive:

```python
--8<-- "examples/guides/files.py:icon"
```

On Android 8+ many apps use an adaptive icon: an `.xml` file in binary XML format that references a foreground and a background drawable. Use `apk-info extract -r` to get it as readable XML.

## Decoding resources

`apk-info extract -r` decodes resources the way apktool and jadx do:

```bash
apk-info extract apkstest.apk -r -o out/
```

```text
out/apkstest.apk.unp/
├── AndroidManifest.xml          # readable XML
├── META-INF/...
├── lib/x86_64/libstub.so
└── res/
    ├── drawable-xxhdpi/icon.png
    ├── values/strings.xml       # decoded from resources.arsc
    ├── values-ru/strings.xml
    └── xml/
```

```xml
<?xml version="1.0" encoding="utf-8"?>
<resources>
  <string name="app_name">APKS Test</string>
</resources>
```

- apk-info expands `resources.arsc` into `res/values*/` (strings, plurals, arrays, colors, styles, …) and writes file resources to their canonical `res/<type>[-<config>]/` folders.
- It writes only the resources registered in the resource table. Release builds shorten file names (`res/7j.png`), and some apps add decoy files under `res/`; the decoded tree uses the real names and skips the decoys.
- For XAPK, APKM and APKS files, it merges the resources of the base APK and every config split into one `res/` tree, so you get all languages and screen densities in one place.
- It copies DEX files, native libraries and assets as they are.

Locale folders use the legacy form (`values-es-r419`), like jadx; apktool writes `values-b+es+419`. Android accepts both.
