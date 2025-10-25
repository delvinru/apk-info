import sys

from apk_info import APK

if len(sys.argv) < 2:
    print(f"usage: {sys.argv[0]} <apk>")
    sys.exit(1)

file = sys.argv[1]
apk = APK(file)
package_name = apk.get_package_name()
main_activities = apk.get_main_activities()
if not main_activities:
    print(f"{file} is not launchable!")
    sys.exit(1)

min_sdk = apk.get_min_sdk_version()
print(f"Main Activity: {package_name}/{main_activities[0]}")
print(f"Minimal SDK: {min_sdk}")
