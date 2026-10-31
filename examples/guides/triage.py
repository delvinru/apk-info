"""Inspecting an APK: triage, launchability, device targets and raw manifest values.

Usage: python triage.py <path-to-apk>
"""

import sys

from apk_info import APK

apk = APK(sys.argv[1])

# --8<-- [start:triage]
print(f"Package:    {apk.get_package_name()}")
print(f"Version:    {apk.get_version_name()} ({apk.get_version_code()})")
print(f"SDK:        min {apk.get_min_sdk_version()}, target {apk.get_target_sdk_version()}")
print(f"Label:      {apk.get_application_label()}")
print(f"Debuggable: {apk.get_application_debuggable()}")
print(f"Backup:     {apk.get_application_allow_backup()}")
print(f"Multidex:   {apk.is_multidex()}")
print(f"ABIs:       {apk.get_supported_abis()}")
# --8<-- [end:triage]

# --8<-- [start:launchable]
activities = apk.get_main_activities()
if not activities:
    print("not launchable: no MAIN + LAUNCHER activity")
for activity in activities:
    print(f"adb shell am start -n {apk.get_package_name()}/{activity}")
# --8<-- [end:launchable]

# --8<-- [start:targets]
targets = [
    name
    for name, matches in [
        ("TV", apk.is_leanback()),
        ("Wear OS", apk.is_wearable()),
        ("Android Automotive", apk.is_automotive()),
        ("ChromeOS", apk.is_chromebook()),
    ]
    if matches
]
print(f"Targets: {', '.join(targets) or 'phone / tablet'}")
print(f"Features: {sorted(apk.get_features())}")
# --8<-- [end:targets]

# --8<-- [start:attributes]
# any attribute of the first matching tag, by name without the "android:" prefix
print(apk.get_attribute_value("application", "networkSecurityConfig"))
print(apk.get_attribute_value("application", "usesCleartextTraffic"))

# every value of an attribute across all matching tags
print(apk.get_all_attribute_values("uses-permission", "name"))
# --8<-- [end:attributes]

# --8<-- [start:resources]
# getters resolve resource references for you...
print(apk.get_application_label())
print(apk.get_application_icon())

# ...and get_resource_value resolves any other reference
print(apk.get_resource_value("@string/app_name"))
# --8<-- [end:resources]

# --8<-- [start:manifest]
with open("AndroidManifest.xml", "w") as f:
    f.write(apk.get_xml_string())
# --8<-- [end:manifest]
