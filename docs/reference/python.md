# Python API

```python
from apk_info import APK, APKError

try:
    apk = APK("app.apk")
except APKError as e:
    print(f"not an APK: {e}")
```

Everything goes through the `APK` class:

- The constructor accepts `str` or any `PurePath`, and raises `FileNotFoundError` for a missing file and `APKError` if the file can't be parsed.
- The constructor opens XAPK, APKM and APKS files through their base APK.
- Manifest getters return `str | None`. They return values as written in the manifest, so booleans are `"true"` / `"false"` and versions are strings.
- `get_target_sdk_version()` returns an `int`; it falls back to `min_sdk_version`, or `1` when neither is set.
- Collections are `set` when order doesn't matter (permissions, features) and `list` when it does (main activities).
- `get_signatures()` returns `Signature.*` dataclasses for use in `match` statements. See the [Quickstart](../getting-started/quickstart.md#signatures).

mkdocstrings generates the API below from the type stubs that ship with the package.

::: apk_info
