#!/usr/bin/env bash
# Regenerates the `apks-*.apks` fixtures with bundletool.
#
# Requires aapt2, keytool, bundletool and an Android SDK platform, e.g.:
#   nix-shell -p bundletool --run ./build-apks-fixtures.sh
set -euo pipefail

out_dir=$(cd "$(dirname "$0")" && pwd)
android_jar=${ANDROID_JAR:-$HOME/Library/Android/sdk/platforms/android-35/android.jar}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

mkdir -p res/values res/values-ru res/drawable-xxhdpi

# $1 = extra manifest element, e.g. the instant-enabled <dist:module>
manifest() {
    cat <<EOF
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:dist="http://schemas.android.com/apk/distribution"
    package="io.github.delvinru.apkstest"
    android:versionCode="7"
    android:versionName="1.0.7">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="35" />
    $1
    <application android:label="@string/app_name" android:icon="@drawable/icon" android:hasCode="false">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
EOF
}
echo '<resources><string name="app_name">APKS Test</string></resources>' >res/values/strings.xml
echo '<resources><string name="app_name">Тест APKS</string></resources>' >res/values-ru/strings.xml

# 1x1 png
python3 -I -c '
import struct, sys, zlib
def chunk(t, d): return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
png += chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00")) + chunk(b"IEND", b"")
open(sys.argv[1], "wb").write(png)' res/drawable-xxhdpi/icon.png

aapt2 compile --dir res -o compiled.zip

# compressed native libs skip the 16 KiB page alignment of every abi split
echo '{"optimizations":{"uncompressNativeLibraries":{"enabled":false}}}' >BundleConfig.json

# $1 = output aab, $2 = extra manifest element
build_aab() {
    local module
    module=$(mktemp -d "$work/module.XXXX")
    manifest "$2" >"$module.xml"
    aapt2 link --proto-format -o "$module.apk" -I "$android_jar" --manifest "$module.xml" compiled.zip
    (
        cd "$module"
        unzip -q "$module.apk"
        mkdir manifest && mv AndroidManifest.xml manifest/
        # a native lib produces an abi split; one abi keeps the fixture small
        mkdir -p lib/x86_64 && printf '\x7fELF-stub' >lib/x86_64/libstub.so
        zip -qr "$module.zip" .
    )
    bundletool build-bundle --modules="$module.zip" --config=BundleConfig.json --output="$1"
}

build_aab app.aab ""
build_aab instant.aab '<dist:module dist:instant="true" />'

keytool -genkeypair -keystore ks.jks -storepass android -keypass android -alias apkstest \
    -keyalg RSA -keysize 2048 -validity 36500 -dname "CN=apk-info apks test" >/dev/null 2>&1
sign=(--ks=ks.jks --ks-pass=pass:android --ks-key-alias=apkstest)

bundletool build-apks --bundle=app.aab --output="$out_dir/apks-split.apks" --overwrite "${sign[@]}"
bundletool build-apks --bundle=app.aab --mode=universal --output="$out_dir/apks-universal.apks" --overwrite "${sign[@]}"

# system mode targets one device: system/system.apk plus language splits in splits/
echo '{"supportedAbis":["x86_64"],"supportedLocales":["en-US"],"screenDensity":480,"sdkVersion":35}' >device.json
bundletool build-apks --bundle=app.aab --mode=system --device-spec=device.json \
    --output="$out_dir/apks-system.apks" --overwrite "${sign[@]}"

bundletool build-apks --bundle=instant.aab --mode=instant --output="$out_dir/apks-instant.apks" --overwrite "${sign[@]}"
