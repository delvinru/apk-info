# XAPK, APKM and APKS

Google Play builds most apps from App Bundles and installs them as a set of APKs: a base APK plus configuration splits for the CPU architecture, screen density and language. Third-party stores and backup tools package such sets into a single archive:

| Format | Made by | Marker | Base APK |
|---|---|---|---|
| XAPK | APKPure, APKCombo | `manifest.json` | `<package_name>.apk` |
| APKM | APKMirror | `info.json` | `base.apk` |
| APKS | `bundletool build-apks` | `toc.pb` | `splits/base-master.apk`, `universal.apk`, `standalones/…` |
| APKS | SAI, App Manager | `meta.sai_v*.json`, `info.json` | `base.apk` |

## Opening a container

`APK(path)` detects the format and parses the base APK.

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

- apk-info looks for the XAPK base APK only as `<package_name>.apk`. It can't open archives that name it differently, for example `base.apk` next to a `manifest.json`.
- There is no API yet to list splits, their config qualifiers or their signatures, or the OBB files of an XAPK.
- apk-info doesn't support AAB files (`.aab`, the App Bundle itself) or encrypted APKM files from before 2021.
- For bundletool APKS files with standalone variants, `get_min_sdk_version()` reports the min SDK of `splits/base-master.apk`, which can be higher than the app's real minimum.
