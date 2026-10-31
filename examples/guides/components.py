"""Permissions and manifest components.

Usage: python components.py <path-to-apk>
"""

import sys

from apk_info import APK

apk = APK(sys.argv[1])

# --8<-- [start:permissions]
for permission in sorted(apk.get_permissions()):
    print(f"uses-permission         {permission}")

for permission in apk.get_permissions_sdk23():
    print(f"uses-permission-sdk-23  {permission}")

# permissions the app defines for others to request
for permission in apk.get_declared_permissions():
    print(f"permission              {permission.name} [{permission.protection_level}]")
# --8<-- [end:permissions]

# --8<-- [start:exported]
target_sdk = apk.get_target_sdk_version()


def is_exported(component) -> bool:
    # before Android 12 (target SDK 31), a component with an intent filter
    # was exported unless it said otherwise
    if component.exported is None:
        return bool(component.intent_filters) and target_sdk < 31
    return component.exported == "true"


for kind, components in [
    ("activity", apk.get_activities()),
    ("service", apk.get_services()),
    ("receiver", apk.get_receivers()),
]:
    for component in components:
        if is_exported(component):
            print(f"{kind:9} {component.name}  permission={component.permission}")

for provider in apk.get_providers():
    if provider.exported == "true":
        print(f"provider  {provider.name}  authorities={provider.authorities}")
# --8<-- [end:exported]

# --8<-- [start:intent-filters]
for activity in apk.get_activities():
    for intent_filter in activity.intent_filters:
        if "android.intent.action.VIEW" in intent_filter.actions:
            print(f"{activity.name} handles VIEW: {intent_filter.categories}")
# --8<-- [end:intent-filters]
