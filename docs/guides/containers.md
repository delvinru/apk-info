# XAPK, APKM and APKS

Google Play builds most apps from App Bundles and installs them as a set of APKs: a base APK plus configuration splits for the CPU architecture, screen density and language. Third-party stores and backup tools package such sets into a single archive:

| Format | Made by | Marker | Base APK |
|---|---|---|---|
| XAPK | APKPure, APKCombo | `manifest.json` | the `base` entry of `split_apks`, `<package_name>.apk`, or `base.apk` |
| APKM | APKMirror | `info.json` | `base.apk` |
| APKS | `bundletool build-apks` | `toc.pb` | `splits/base-master.apk`, `universal.apk`, `standalones/…` |
| APKS | SAI, App Manager | `meta.sai_v*.json`, `info.json` | `base.apk` |

## Opening a container

`APK(path)` detects the format and parses the base APK.

The candidates are tried in order until one parses: the base named in `manifest.json` (the `base` entry of `split_apks`, then `<package_name>.apk`), `base.apk`, then the base of a bundletool APKS. A broken `manifest.json` or a broken root `AndroidManifest.xml` only produces a warning when a base APK is found. Containers over 4 GB (ZIP64) are supported.

When none of these names is present and the archive has no `AndroidManifest.xml` of its own, apk-info guesses: the same names in another case or directory (`BASE.APK`, `app/base.apk`), then any APK at the root. A guess is accepted only if it is not a split, and a warning names it. An APK with a broken manifest is never treated as a container, so an APK it carries (for example a dropper's payload) is not reported as the app.

`apk-info extract -r` decodes the resources of the same base APK, plus its splits.

=== "Python"

    ```python
    from apk_info import APK

    apk = APK("org.telegram.messenger.xapk")
    print(apk.get_package_name())      # org.telegram.messenger
    print(apk.get_supported_abis())    # from config.<abi>.apk splits too
    ```

=== "Rust"

    ```rust
    use apk_info::Apk;

    let apk = Apk::new("org.telegram.messenger.xapk")?;
    println!("{:?}", apk.get_package_name());
    ```

=== "CLI"

    ```bash
    apk-info show org.telegram.messenger.xapk
    ```

What comes from where:

| Data | Source |
|---|---|
| manifest getters, components, permissions, resources | base APK |
| `get_signatures()`, `is_multidex()` | base APK |
| `get_supported_abis()` | base APK and the names of `config.<abi>.apk` splits |
| `get_container_signatures()` | the outer archive (APKMirror signs APKM files, most others are unsigned) |
| `namelist()`, `read()` | the outer archive; the base APK with `base=True` |

## Reading files of the base APK

By default `namelist()` and `read()` work on the outer archive, so they return `manifest.json`, `toc.pb` and the split APKs themselves, not `classes.dex`:

```python
apk = APK("app.apks")
apk.namelist()  # ['toc.pb', 'splits/base-master.apk', 'splits/base-ru.apk', ...]
```

=== "Python"

    Pass `base=True` to `namelist()` and `read()`:

    ```python
    from apk_info import APK

    apk = APK("org.telegram.messenger.xapk")
    dex = [n for n in apk.namelist(base=True) if n.endswith(".dex")]
    data, _ = apk.read("classes.dex", base=True)
    ```

    For a plain APK, `base=True` changes nothing, so the same code works for both.

=== "Rust"

    `get_base_zip()` returns the base APK of a container, or the APK itself:

    ```rust
    let apk = Apk::new("org.telegram.messenger.xapk")?;
    let base = apk.get_base_zip()?;
    let dex: Vec<&str> = base.namelist().filter(|n| n.ends_with(".dex")).collect();
    ```

=== "CLI"

    `extract` unpacks the outer archive. Extract the base APK, then extract it again:

    ```bash
    # -> ./org.telegram.messenger.xapk.unp/org.telegram.messenger.apk
    apk-info extract org.telegram.messenger.xapk -f 'org\.telegram\.messenger\.apk'
    # -> ./org.telegram.messenger.apk.unp/
    apk-info extract org.telegram.messenger.xapk.unp/org.telegram.messenger.apk
    ```

## Resources of all splits

Language strings and density-specific drawables live in the config splits, not in the base APK. `extract -r` merges them:

```bash
apk-info extract org.telegram.messenger.xapk -r -o out/
ls out/org.telegram.messenger.xapk.unp/res/ | grep values-
```

## Limitations

- A container nested in another archive (a ZIP holding an XAPK) is not opened.
- App Bundles (`.aab`) are rejected with an explicit error: build APKS from them with bundletool.
- Compressed (DEFLATED) entries over 4 GB can't be read or extracted; stored ones, which is how stores write APKs and OBB files, are fine.
- There is no API yet to list splits, their config qualifiers or their signatures, or the OBB files of an XAPK.
- Encrypted APKM files from before 2021 are rejected with a hint to decrypt them with [unapkm](https://github.com/souramoo/unapkm).
- For bundletool APKS files with standalone variants, `get_min_sdk_version()` reports the min SDK of `splits/base-master.apk`, which can be higher than the app's real minimum.
