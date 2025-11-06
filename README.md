# apk-info

A library for getting all the available information from an APK file.

## Features

- A malware-friendly zip extractor. Great [article](https://unit42.paloaltonetworks.com/apk-badpack-malware-tampered-headers/) about `BadPack` technique;
- A malware-friendly axml and arsc extractor;
- A full AXML (Android Binary XML) implementation;
- A full ARSC (Android Resource) implementation;
- Support for extracting information contained in the `APK Signature Block 42`:
    - v1;
    - v2;
    - v3;
    - v3.1;
    - Stamp Block v1;
    - Stamp Block v2;
    - Apk Channel Block;
    - Google Play Frosting (there are plans, but there is critically little information about it);
- Correct extraction of the MainActivity based on how the Android OS [does it](https://cs.android.com/android/platform/superproject/+/android-latest-release:frameworks/base/core/java/android/app/ApplicationPackageManager.java;l=310?q=getLaunchIntentForPackage);
- Bindings for python 3.10+ with typings - no more `# type: ignore`;
- And of course just a fast parser.

## Getting started

### Installation

```bash
uv pip install apk-info
```

### Get basic information about APK

```python
from apk_info import APK

apk = APK("./path-to-file.apk")
package_name = apk.get_package_name()
main_activities = apk.get_main_activities()
min_sdk = apk.get_min_sdk_version()

print(f"Package Name: {package_name}")
print(f"Minimal SDK: {min_sdk}")

if not main_activities:
    print("apk is not launchable!")
    exit()

print(f"Main Activity: {package_name}/{main_activities[0]}")
```

## FAQ

- Why not just use androguard?

Almost all of my projects are born from something that is inconvenient to use.
Androguard is a great tool in itself, but it is simply not possible to maintain it (in my opinion) and it is not suitable for production-ready code. It is also not suitable for analyzing a large number of files due to the fact that all the logic is written in not very optimized way.

- I want to modify the apk, how do I do it using this library?

The library is designed for read-only mode only, because i need a good tool with which i can easily and quickly extract information from the apk. There are many other good tools out there.

## Credits

- [androguard](https://github.com/androguard/androguard)
- [apkInspector](https://github.com/erev0s/apkInspector)
