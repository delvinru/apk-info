# Permissions and components

## Permissions

An app can request permissions in two tags and define its own in a third:

| Tag | Method | Meaning |
|---|---|---|
| `<uses-permission>` | `get_permissions()` | requested on every Android version |
| `<uses-permission-sdk-23>` | `get_permissions_sdk23()` | requested only on Android 6.0+ |
| `<permission>` | `get_declared_permissions()` | defined by this app for others to request |

=== "Python"

    ```python
    --8<-- "examples/guides/components.py:permissions"
    ```

=== "Rust"

    ```rust
    --8<-- "core/examples/components.rs:permissions"
    ```

=== "CLI"

    ```bash
    apk-info axml app.apk | grep -E '<uses-permission|<permission'
    ```

```text
uses-permission         android.permission.FOREGROUND_SERVICE_DATA_SYNC
uses-permission         android.permission.INTERNET
uses-permission         android.permission.RECEIVE_BOOT_COMPLETED
uses-permission-sdk-23  android.permission.POST_NOTIFICATIONS
permission              io.github.delvinru.apkstest.READ [signature]
```

## Exported components

Other apps can start exported activities, services and receivers, and query exported providers. Start with them when you assess an app's attack surface.

=== "Python"

    ```python
    --8<-- "examples/guides/components.py:exported"
    ```

=== "Rust"

    ```rust
    --8<-- "core/examples/components.rs:exported"
    ```

```text
activity  .MainActivity  permission=None
receiver  .BootReceiver  permission=None
```

`exported` is the raw attribute value: `"true"`, `"false"` or `None`. When it's `None`, Android decides:

- **Activities, services, receivers.** Before Android 12 (target SDK 31), a component with an `<intent-filter>` is exported by default. Since target SDK 31, a component with an intent filter must set `android:exported`, or the app won't install.
- **Providers.** Exported by default only when `minSdkVersion` or `targetSdkVersion` is 16 or lower.


If a component requires a `permission` with the `signature` protection level, only apps signed with the same key can reach it.

## Intent filters

Activities, activity aliases, services and receivers carry their intent filters as lists of actions and categories:

```python
--8<-- "examples/guides/components.py:intent-filters"
```

```text
.MainActivity handles VIEW: ['android.intent.category.DEFAULT', 'android.intent.category.BROWSABLE']
```

## All component fields

`get_activities()`, `get_activity_aliases()`, `get_services()`, `get_receivers()` and `get_providers()` return objects with the raw manifest attributes: `name`, `exported`, `enabled`, `permission`, `process` and so on, plus type-specific ones such as `authorities` and `grant_uri_permissions` for providers or `foreground_service_type` for services.
See the [Python API](../reference/python.md) for the full list.
