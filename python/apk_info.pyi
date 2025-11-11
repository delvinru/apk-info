from dataclasses import dataclass
from pathlib import Path
from typing import Literal

__version__: str
"""
Gets the package version as defined in `Cargo.toml`
"""

class APKError(Exception):
    """
    Generic exception related to issues with `apk-info` library
    """

    ...

class APK:
    """
    APK class, the main entrypoint to use `apk-info` library.
    """

    def __init__(self, path: str | Path) -> None:
        """
        Create a new APK instance

        Parameters
        ----------
        path : str | Path
            Path to the APK file on disk

        Raises
        ------
        PyFileNotFoundError
            If file not exists
        PyValueError
            If got error while parsing zip entry
        PyTypeError
            If the argument is not str or Path
        """
        ...

    def read(self, filename: str) -> bytes:
        """
        Read raw data for the filename in the zip archive

        Parameters
        ----------
        filename: str
            The path to the file inside the APK archive

        Raises
        ------
        PyValueError
            If the passed name could not be converted to a rust string
        APKError
            If there are problems reading the file

        Examples
        --------

        ```python
        apk = APK("./file")
        with open("AndroidManifest.xml", "wb") as fd:
            fd.write(apk.read("AndroidManifest.xml))
        ```
        """
        ...

    def namelist(self) -> list[str]:
        """
        The list of files contained in the APK, obtained from the central directory (zip)

        Examples
        --------

        ```python
        apk = APK("./file")
        for file in apk.namelist():
            print(f"get file - {file}")
        ```
        """
        ...

    def is_multidex(self) -> bool:
        """
        Checks if the APK has multiple `classes.dex` files or not

        Examples
        --------

        ```python
        apk = APK("./file")
        print(apk.is_multidex()) # True
        ```
        """
        ...

    def get_xml_string(self) -> str:
        """
        Converts the internal xml representation of the `AndroidManifest.xml` to a human readable format

        Returns
        -------
        str
            pretty-printed AndroidManifest.xml
        """
        ...

    def get_resource_value(self, name: str) -> str | None:
        """
        An auxiliary method that allows you to get a value from a reference to a resource

        Parameters
        ----------
        name : str
            The reference to the resource in the `@string/app_name` format

        Examples
        --------

        >>> print(apk.get_resource_value("@string/app_name"))
        "Cool Application"

        >>> print(apk.get_resource_value("@drawable/ic_launcher"))
        "res/drawable-xhdpi/ic_launcher.png"

        Returns
        -------
        str | None
            If something was found, the value will be returned.
            It can be a string, a file path, etc., depending on the context in which this function is used.
        """

    def get_attribute_value(self, tag: str, name: str) -> str | None:
        """
        An auxiliary method that allows you to get the attribute value directly from `AndroidManifest.xml`.

        If the value is a link to a resource, it will be automatically resolved to the file name.

        Examples
        --------

        ```python
        apk = APK("./file")
        security_config = apk.get_attribute_value("application", "networkSecurityConfig")
        if security_config:
            with open("network_security_config.xml", "wb") as fd:
                fd.write(apk.read(security_config))
        ```

        Example of how to get additional information from the <application> tag:

        ```python
        apk = APK("./file")
        print(apk.get_attribute_value("application", "allowClearUserData"))
        ```
        """
        ...

    def get_all_attribute_values(self, tag: str, name: str) -> list[str]:
        """
        An auxiliary method that allows you to get the value from all attributes from `AndroidManifest.xml`.

        Examples
        --------

        ```python
        apk = APK("./file")
        print(apk.get_all_atribute_values("uses-permission", "name"))
        ```
        """
        ...

    def get_package_name(self) -> str | None:
        """
        Retrieves the package name declared in the `<manifest>` element.

        See: <a href="https://developer.android.com/guide/topics/manifest/manifest-element#package" target="_blank">https://developer.android.com/guide/topics/manifest/manifest-element#package</a>

        Returns
        -------
            str | None
                The package name (e.g., "com.example.app") if found, otherwise None
        """
        ...

    def get_shared_user_id(self) -> str | None:
        """
        Retrieves the `sharedUserId` attribute from the `<manifest>` element.

        See: <a href="https://developer.android.com/guide/topics/manifest/manifest-element#uid" target="_blank">https://developer.android.com/guide/topics/manifest/manifest-element#uid</a>

        Returns
        -------
        str | None
            The shared user ID if declared, otherwise None
        """
        ...

    def get_shared_user_label(self) -> str | None:
        """
        Retrieves the `sharedUserLabel` attribute from the `<manifest>` element.

        See: <a href="https://developer.android.com/guide/topics/manifest/manifest-element#uidlabel" target="_blank">https://developer.android.com/guide/topics/manifest/manifest-element#uidlabel</a>

        Returns
        -------
        str | None
            The shared user label if declared, otherwise None.
        """
        ...

    def get_shared_user_max_sdk_version(self) -> str | None:
        """
        Retrieves the `sharedUserMaxSdkVersion` attribute from the `<manifest>` element.

        See: <a href="https://developer.android.com/guide/topics/manifest/manifest-element#uidmaxsdk" target="_blank">https://developer.android.com/guide/topics/manifest/manifest-element#uidmaxsdk</a>

        Returns
        -------
        str | None
            The maximum SDK version for the shared user, if declared
        """
        ...

    def get_version_code(self) -> str | None:
        """
        Retrieves the application version code.

        See: <a href="https://developer.android.com/guide/topics/manifest/manifest-element#vcode" target="_blank">https://developer.android.com/guide/topics/manifest/manifest-element#vcode</a>

        Examples
        --------

        ```python
        apk = APK("./file")
        print(apk.get_version_code())
        "2025101912"
        ```

        Notes
        -----
        The automatic conversion to `int` was not done on purpose,
        because there is no certainty that malware will not try to insert random values there

        Returns
        -------
        str | None
            The version code as a string if present, otherwise None
        """
        ...

    def get_version_name(self) -> str | None:
        """
        Retrieves the human-readable application version name.

        See: <a href="https://developer.android.com/guide/topics/manifest/manifest-element#vname" target="_blank">https://developer.android.com/guide/topics/manifest/manifest-element#vname</a>

        Examples
        --------

        ```python
        apk = APK("./file")
        print(apk.get_version_name()) # "1.2.3"
        ```

        Returns
        -------
        str | None
            The version name as a string if present, otherwise None
        """
        ...

    def get_build_version_code(self) -> str | None:
        """
        Retrieves the `platformBuildVersionCode` from the `<manifest>` element.

        Returns
        -------
        str | None
            The version name as a string if present, otherwise None
        """
        ...

    def get_build_version_name(self) -> str | None:
        """
        Retrieves the `platformBuildVersionName` from the `<manifest>` element.

        Returns
        -------
        str | None
            The version name as a string if present, otherwise None
        """
        ...

    def get_install_location(self) -> Literal["auto", "internalOnly", "preferExternal"] | None:
        """
        Retrieves the preferred installation location declared in the manifest.

        See: <a href="https://developer.android.com/guide/topics/manifest/manifest-element#install" target="_blank">https://developer.android.com/guide/topics/manifest/manifest-element#install</a>

        Returns
        -------
        auto
            Let the system decie ideal install location
        internalOnly
            Explicitly request to be installed on internal phone storage only
        preferExternal
            Prefer to be installed on SD card
        None
            The installation location is not specified
        """
        ...

    def get_application_task_reparenting(self) -> Literal["true", "false"] | None:
        """
        Extracts the `android:allowTaskReparenting` attribute from `<application>`.

        See: <a href="https://developer.android.com/guide/topics/manifest/application-element#reparent" target="_blank">https://developer.android.com/guide/topics/manifest/application-element#reparent</a>

        Returns
        -------
        "true" | "false"
            If value is declared
        None
            If value is not declared
        """
        ...

    def get_application_allow_backup(self) -> Literal["true", "false"] | None:
        """
        Extracts the `android:allowBackup` attribute from `<application>`.

        See: <a href="https://developer.android.com/guide/topics/manifest/application-element#allowbackup" target="_blank">https://developer.android.com/guide/topics/manifest/application-element#allowbackup</a>

        Returns
        -------
        "true" | "false"
            If value is declared
        None
            If value is not declared
        """
        ...

    def get_application_category(
        self,
    ) -> Literal["accessibility", "audio", "game", "image", "maps", "news", "productivity", "social", "video"] | None:
        """
        Extracts the `android:appCategory` attribute from `<application>`.

        See: <a href="https://developer.android.com/guide/topics/manifest/application-element#appCategory" target="_blank">https://developer.android.com/guide/topics/manifest/application-element#appCategory</a>

        Returns
        -------
        accessibility
            Apps that are primarily accessibility apps, such as screen-readers
        audio
            Apps that primarily work with audio or music, such as music players
        game
            Apps that are primarily games
        image
            Apps that primarily work with images or photos, such as camera or gallery apps
        maps
            Apps that are primarily map apps, such as navigation apps
        news
            Apps that are primarily news apps, such as newspapers, magazines, or sports apps
        productivity
            Apps that are primarily productivity apps, such as cloud storage or workplace apps
        social
            Apps that are primarily social apps, such as messaging, communication, email, or social network apps
        video
            Apps that primarily work with video or movies, such as streaming video apps
        None
            Value not defined
        """
        ...

    def get_application_backup_agent(self) -> str | None:
        """
        Extracts the `android:backupAgent` attribute from `<application>`.

        See: <a href="https://developer.android.com/guide/topics/manifest/application-element#agent" target="_blank">https://developer.android.com/guide/topics/manifest/application-element#agent</a>

        Examples
        --------

        ```python
        print(apk.get_application_backup_agent())
        "com.android.launcher3.LauncherBackupAgent"
        ```

        Returns
        -------
        str | None
            The name of the backup agent class if declared, otherwise None.
        """
        ...

    def get_application_debuggable(self) -> Literal["true", "false"] | None:
        """
        Extracts the `android:debuggable` attribute from `<application>`.

        See: <a href="https://developer.android.com/guide/topics/manifest/application-element#debug" target="_blank">https://developer.android.com/guide/topics/manifest/application-element#debug</a>

        Returns
        -------
        str | None
            "true" or "false" if declared, otherwise None.
        """
        ...

    def get_application_description(self) -> str | None:
        """
        Extracts and resolve the `android:description` attribute from `<application>`.

        See: <a href="https://developer.android.com/guide/topics/manifest/application-element#desc" target="_blank">https://developer.android.com/guide/topics/manifest/application-element#desc</a>

        Notes
        -----
        The link to the resource will be automatically resolved and this value will be returned

        Returns
        -------
        str | None
            The description resource or literal value, if available.
        """
        ...

    def get_application_icon(self) -> str | None:
        """
        Extracts and resolves the `android:icon` attribute from `<application>`

        See: <a href="https://developer.android.com/guide/topics/manifest/application-element#icon" target="_blank">https://developer.android.com/guide/topics/manifest/application-element#icon</a>

        Notes
        ----
        There is no way to choose a resolution yet, it will be implemented in the future.

        Examples
        --------

        ```python
        apk = APK("./file")
        icon = apk.get_application_icon()
        if icon:
            # it's not always png, maybe webp or even xml.
            with open("icon.png", "wb") as fd:
                fd.write(apk.read(icon))
        ```

        Returns
        -------
        str | None
            The path to the icon file, if available.
        """
        ...

    def get_application_label(self) -> str | None:
        """
        Extracts and resolves the `android:label` attribute from `<application>`.

        See: <a href="https://developer.android.com/guide/topics/manifest/application-element#label" target="_blank">https://developer.android.com/guide/topics/manifest/application-element#label</a>

        Notes
        -----
        The link to the resource will be automatically resolved and this value will be returned

        Returns
        -------
        str | None
            The label resource or literal value, if available
        """
        ...

    def get_application_logo(self) -> str | None:
        """
        Extracts and resolves the `android:logo` attribute from `<application>`

        See: <a href="https://developer.android.com/guide/topics/manifest/application-element#logo" target="_blank">https://developer.android.com/guide/topics/manifest/application-element#logo</a>

        Examples
        --------

        ```python
        apk = APK("./file")
        logo = apk.get_application_logo()
        if logo:
            # it's not always png, maybe webp or even xml.
            with open("logo.png", "wb") as fd:
                fd.write(apk.read(logo))
        ```

        Returns
        -------
        str | None
            The path to the logo file, if available
        """
        ...

    def get_application_name(self) -> str | None:
        """
        Extracts the `android:name` attribute from `<application>`.

        See: <a href="https://developer.android.com/guide/topics/manifest/application-element#nm" target="_blank">https://developer.android.com/guide/topics/manifest/application-element#nm</a>

        Examples
        --------

        ```python
        print(apk.get_application_name())
        "com.whatsapp.AppShell"
        ```

        Returns
        -------
        str | None
            The fully qualified application class name, if defined.
        """
        ...

    def get_permissions(self) -> set[str]:
        """
        Retrieves all permissions names from `<uses-permission>`

        See: <a href="https://developer.android.com/guide/topics/manifest/uses-permission-element" target="_blank">https://developer.android.com/guide/topics/manifest/uses-permission-element</a>

        Returns
        -------
        set[str]
            A list of all permission names (e.g., "android.permission.INTERNET").
        """
        ...

    def get_permissions_sdk23(self) -> list[str]:
        """
        Retrieves all declared permissions for API level 23 and above from `<uses-permission-sdk-23>` elements

        See: <a href="https://developer.android.com/guide/topics/manifest/uses-permission-sdk-23-element" target="_blank">https://developer.android.com/guide/topics/manifest/uses-permission-sdk-23-element</a>

        Returns
        -------
        set[str]
            A list of permission names
        """
        ...

    def get_min_sdk_version(self) -> str | None:
        """
        Extracts the minimum supported SDK version (`minSdkVersion`) from the `<uses-sdk>` element

        See: <a href="https://developer.android.com/guide/topics/manifest/uses-sdk-element#min" target="_blank">https://developer.android.com/guide/topics/manifest/uses-sdk-element#min</a>

        Examples
        --------

        ```python
        print(apk.get_min_sdk_version())
        "26"
        ```

        Returns
        -------
        str | None
            The minimum SDK version as a string, or None if not specified.
        """
        ...

    def get_target_sdk_version(self) -> int:
        """
        Extracts the target SDK version (`targetSdkVersion`) from the `<uses-sdk>` element.

        See: <a href="https://developer.android.com/guide/topics/manifest/uses-sdk-element#target" target="_blank">https://developer.android.com/guide/topics/manifest/uses-sdk-element#target</a>

        Notes
        -----
        Determines the version based on the following algorithm:

        1. Check `targetSdkVersion`;
        2. If empty => check `minSdkVersion`;
        3. If empty => return 1;

        Returns
        -------
        int
            The target SDK version
        """
        ...

    def get_max_sdk_version(self) -> str | None:
        """
        Retrieves the maximum supported SDK version (`maxSdkVersion`) if declared.

        See: <a href="https://developer.android.com/guide/topics/manifest/uses-sdk-element#max" target="_blank">https://developer.android.com/guide/topics/manifest/uses-sdk-element#max</a>

        Returns
        -------
        str | None
            The maximum SDK version as a string, or None if not specified
        """
        ...

    def get_libraries(self) -> set[str]:
        """
        Retrieves all libraries declared by `<uses-library android:name="...">`.

        See: <a href="https://developer.android.com/guide/topics/manifest/uses-library-element" target="_blank">https://developer.android.com/guide/topics/manifest/uses-library-element</a>

        Returns
        -------
        set[str]
            A set of library names
        """
        ...

    def get_native_libraries(self) -> set[str]:
        """
        Retrieves all native libraries declared by `<uses-native-library android:name="...">`

        See: <a href="https://developer.android.com/guide/topics/manifest/uses-native-library-element" target="_blank">https://developer.android.com/guide/topics/manifest/uses-native-library-element</a>

        Returns
        -------
        set[str]
            A set of native library names
        """

    def get_features(self) -> set[str]:
        """
        Retrieves all hardware or software features declared by `<uses-feature android:name="...">`

        See: <a href="https://developer.android.com/guide/topics/manifest/uses-feature-element" target="_blank">https://developer.android.com/guide/topics/manifest/uses-feature-element</a>

        Returns
        -------
        set[str]
            A set of declared feature names
        """
        ...

    def is_automotive(self) -> bool:
        """
        Checks whether the app is designed to display its user interface on multiple screens inside the vehicle.

        See: <a href="https://developer.android.com/guide/topics/manifest/uses-feature-element#device-ui-hw-features" target="_blank">https://developer.android.com/guide/topics/manifest/uses-feature-element#device-ui-hw-features</a>
        """
        ...

    def is_leanback(self) -> bool:
        """
        Checks whether the app is designed to show its UI on a television.

        See: <a href="https://developer.android.com/guide/topics/manifest/uses-feature-element#device-ui-hw-features" target="_blank">https://developer.android.com/guide/topics/manifest/uses-feature-element#device-ui-hw-features</a>
        """
        ...

    def is_wearable(self) -> bool:
        """
        Checks whether the app is designed to show its UI on a watch.

        See: <a href="https://developer.android.com/guide/topics/manifest/uses-feature-element#device-ui-hw-features" target="_blank">https://developer.android.com/guide/topics/manifest/uses-feature-element#device-ui-hw-features</a>
        """
        ...

    def is_chromebook(self) -> bool:
        """
        Checks whether app is designed to show its UI on Chromebooks.

        See: <a href="https://developer.android.com/guide/topics/manifest/uses-feature-element#device-ui-hw-features" target="_blank">https://developer.android.com/guide/topics/manifest/uses-feature-element#device-ui-hw-features</a>
        """
        ...

    def get_declared_permissions(self) -> set[Permission]:
        """
        Retrieves all user defines permissions.

        See: <a href="https://developer.android.com/guide/topics/manifest/permission-element" target="_blank">https://developer.android.com/guide/topics/manifest/permission-element</a>

        Returns
        -------
        set[str]
            A set of permission names defined by the application
        """
        ...

    def get_main_activity(self) -> str | None:
        """
        Retrieves first main (launchable) activity defined in the manifest.

        A main activity is typically one that has an intent filter with actions `MAIN` and categories `LAUNCHER` or `INFO`.

        See: <a href="https://developer.android.com/guide/topics/manifest/activity-element" target="_blank">https://developer.android.com/guide/topics/manifest/activity-element</a>

        Resolve logic: <a href="https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/core/java/android/app/ApplicationPackageManager.java#310" target="_blank">https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/core/java/android/app/ApplicationPackageManager.java#310</a>

        Examples
        --------

        ```python
        print(apk.get_main_activity())
        "com.example.app.MainActivity"
        ```

        Returns
        -------
        str | None
            A main activity class name
        """
        ...

    def get_main_activities(self) -> list[str]:
        """
        Retrieves all main (launchable) activities defined in the manifest.

        A main activity is typically one that has an intent filter with actions `MAIN` and categories `LAUNCHER` or `INFO`.

        See: <a href="https://developer.android.com/guide/topics/manifest/activity-element" target="_blank">https://developer.android.com/guide/topics/manifest/activity-element</a>

        Resolve logic: <a href="https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/core/java/android/app/ApplicationPackageManager.java#310" target="_blank">https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/core/java/android/app/ApplicationPackageManager.java#310</a>

        Returns
        -------
        list[str]
            A list of main activity class names
        """
        ...

    def get_activities(self) -> list[Activity]:
        """
        Retrieves all `<activity>` components declared in the manifest.

        See: <a href="https://developer.android.com/guide/topics/manifest/activity-element" target="_blank">https://developer.android.com/guide/topics/manifest/activity-element</a>

        Returns
        -------
        list[Activity]
            A list of found activites
        """
        ...

    def get_services(self) -> list[Service]:
        """
        Retrieves all `<service>` components declared in the manifest.

        See: <a href="https://developer.android.com/guide/topics/manifest/service-element" target="_blank">https://developer.android.com/guide/topics/manifest/service-element</a>

        Returns
        -------
        list[Service]
            A list of found services
        """
        ...

    def get_receivers(self) -> list[Receiver]:
        """
        Retrieves all `<receiver>` components declared in the manifest.

        See: <a href="https://developer.android.com/guide/topics/manifest/receiver-element" target="_blank">https://developer.android.com/guide/topics/manifest/receiver-element</a>

        Returns
        -------
        list[Receiver]
            A list of broadcast receivers
        """
        ...

    def get_providers(self) -> list[Provider]:
        """
        Retrieves all `<provider>` components declared in the manifest.

        Returns
        -------
        list[Provider]
            A list of content providers
        """
        ...

    def get_signatures(self) -> list[SignatureType]:
        """
        Retrieves all APK signing signatures (v1, v2, v3, v3.1, etc).

        Combines results from multiple signature blocks within the APK file.

        Returns
        -------
        list[SignatureType]
            A list of certificate signatures
        """
        ...

@dataclass(frozen=True)
class CertificateInfo:
    serial_number: str
    """
    The serial number of the certificate in hexadecimal representation
    """

    subject: str
    """
    The subject of the certificate
    """

    valid_from: str
    """
    The date and time when the certificate becomes valid
    """

    valid_until: str
    """
    The date and time when the certificate expires
    """

    signature_type: str
    """
    The type of signature algorithm used
    """

    md5_fingerprint: str
    """
    MD5 fingerprint of the certificate
    """

    sha1_fingerprint: str
    """
    SHA1 fingerprint of the certificate
    """

    sha256_fingerprint: str
    """
    SHA256 fingerprint of the certificate
    """

@dataclass(frozen=True)
class Signature:
    @dataclass(frozen=True)
    class V1:
        """
        Default signature scheme based on JAR signing

        See: <a href="https://source.android.com/docs/security/features/apksigning/v2#v1-verification" target="_blank">https://source.android.com/docs/security/features/apksigning/v2#v1-verification</a>
        """

        certificates: list[CertificateInfo]

    @dataclass(frozen=True)
    class V2:
        """
        APK signature scheme v2

        See: <a href="https://source.android.com/docs/security/features/apksigning/v2" target="_blank">https://source.android.com/docs/security/features/apksigning/v2</a>
        """

        certificates: list[CertificateInfo]

    @dataclass(frozen=True)
    class V3:
        """
        APK signature scheme v3

        See: <a href="https://source.android.com/docs/security/features/apksigning/v3" target="_blank">https://source.android.com/docs/security/features/apksigning/v3</a>
        """

        certificates: list[CertificateInfo]

    @dataclass(frozen=True)
    class V31:
        """
        APK signature scheme v3.1

        See: <a href="https://source.android.com/docs/security/features/apksigning/v3-1" target="_blank">https://source.android.com/docs/security/features/apksigning/v3-1</a>
        """

        certificates: list[CertificateInfo]

    @dataclass(frozen=True)
    class ApkChannelBlock:
        """
        Some usefull information from apk channel block
        """

        value: str

    @dataclass(frozen=True)
    class StampBlockV1:
        """
        SourceStamp improves traceability of apps with respect to unauthorized distribution

        The stamp is part of the APK that is protected by the signing block

        See: <a href="https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/util/apk/SourceStampVerifier.java#75" target="_blank">https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/util/apk/SourceStampVerifier.java#75</a>
        """

        certificate: CertificateInfo

    @dataclass(frozen=True)
    class StampBlockV2:
        """SourceStamp improves traceability of apps with respect to unauthorized distribution

        The stamp is part of the APK that is protected by the signing block

        See: <a href="https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/util/apk/SourceStampVerifier.java#75" target="_blank">https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/util/apk/SourceStampVerifier.java#75</a>
        """

        certificate: CertificateInfo

type SignatureType = (
    Signature.V1
    | Signature.V2
    | Signature.V3
    | Signature.V31
    | Signature.ApkChannelBlock
    | Signature.StampBlockV1
    | Signature.StampBlockV2
)
"""
Represents all available signatures
"""

@dataclass(frozen=True)
class Activity:
    """
    Represents an Android activity defined in an app's manifest.

    More information:
    <a href="https://developer.android.com/guide/topics/manifest/activity-element" target="_blank">https://developer.android.com/guide/topics/manifest/activity-element</a>
    """

    enabled: str | None
    """
    Whether the activity can be instantiated by the system.

    See: https://developer.android.com/guide/topics/manifest/activity-element#enabled
    """

    exported: str | None
    """
    Whether the activity can be launched by components of other applications.

    See: https://developer.android.com/guide/topics/manifest/activity-element#exported
    """

    icon: str | None
    """
    An icon representing the activity.

    See: https://developer.android.com/guide/topics/manifest/activity-element#icon
    """

    label: str | None
    """
    A user-readable label for the activity.

    See: https://developer.android.com/guide/topics/manifest/activity-element#label
    """

    name: str | None
    """
    The name of the class that implements the activity, a subclass of `Activity`.

    See: https://developer.android.com/guide/topics/manifest/activity-element#nm
    """

    parent_activity_name: str | None
    """
    The class name of the logical parent of the activity.

    See: https://developer.android.com/guide/topics/manifest/activity-element#parent
    """

    permission: str | None
    """
    The name of a permission that clients must have to launch the activity or otherwise
    get it to respond to an intent.

    See: https://developer.android.com/guide/topics/manifest/activity-element#prmsn
    """

    process: str | None
    """
    The name of the process in which the activity runs.

    See: https://developer.android.com/guide/topics/manifest/activity-element#proc
    """

@dataclass(frozen=True)
class Permission:
    """
    Represents an Android permission defined in an app's manifest.

    More information:
    <a href="https://developer.android.com/guide/topics/manifest/permission-element" target="_blank">https://developer.android.com/guide/topics/manifest/permission-element</a>
    """

    description: str | None
    """
    A user-readable description of the permission that is longer and more informative than the label.

    See: https://developer.android.com/guide/topics/manifest/permission-element#desc
    """

    icon: str | None
    """
    A reference to a drawable resource for an icon that represents the permission.

    See: https://developer.android.com/guide/topics/manifest/permission-element#icon
    """

    label: str | None
    """
    A user-readable name for the permission.

    See: https://developer.android.com/guide/topics/manifest/permission-element#label
    """

    name: str | None
    """
    The name to be used in code to refer to the permission, such as in a <uses-permission> element
    or the permission attributes of application components.

    See: https://developer.android.com/guide/topics/manifest/permission-element#nm
    """

    permission_group: str | None
    """
    Assigns this permission to a group.

    See: https://developer.android.com/guide/topics/manifest/permission-element#pgroup
    """

    protection_level: str | None
    """
    Characterizes the potential risk implied in the permission and indicates the procedure for
    the system to follow when determining whether to grant the permission to an application
    requesting it.

    See: https://developer.android.com/guide/topics/manifest/permission-element#plevel
    """

@dataclass(frozen=True)
class Provider:
    """
    Represents an Android content provider defined in an app's manifest.

    More information:
    <a href="https://developer.android.com/guide/topics/manifest/provider-element" target="_blank">https://developer.android.com/guide/topics/manifest/provider-element</a>
    """

    authorities: str | None
    """
    A list of URI authorities identifying data offered by the content provider.

    See: https://developer.android.com/guide/topics/manifest/provider-element#auth
    """

    enabled: str | None
    """
    Whether the content provider can be instantiated by the system.

    See: https://developer.android.com/guide/topics/manifest/provider-element#enabled
    """

    direct_boot_aware: str | None
    """
    Whether the content provider is Direct Boot aware.

    See: https://developer.android.com/guide/topics/manifest/provider-element#directBootAware
    """

    exported: str | None
    """
    Whether the content provider is available for other applications to use.

    See: https://developer.android.com/guide/topics/manifest/provider-element#exported
    """

    grant_uri_permissions: str | None
    """
    Whether temporary URI permissions can be granted to access the provider’s data.

    See: https://developer.android.com/guide/topics/manifest/provider-element#granturi
    """

    icon: str | None
    """
    An icon representing the content provider.

    See: https://developer.android.com/guide/topics/manifest/provider-element#icon
    """

    init_order: str | None
    """
    The order in which the provider is instantiated relative to others in the same process.

    See: https://developer.android.com/guide/topics/manifest/provider-element#init
    """

    label: str | None
    """
    A user-readable label for the content provider.

    See: https://developer.android.com/guide/topics/manifest/provider-element#label
    """

    multiprocess: str | None
    """
    Whether multiple instances of the provider are created in multiprocess apps.

    See: https://developer.android.com/guide/topics/manifest/provider-element#multiprocess
    """

    name: str | None
    """
    The name of the class implementing the content provider.

    See: https://developer.android.com/guide/topics/manifest/provider-element#nm
    """

    permission: str | None
    """
    A permission required to read or write the provider’s data.

    See: https://developer.android.com/guide/topics/manifest/provider-element#prmsn
    """

    process: str | None
    """
    The name of the process where the provider runs.

    See: https://developer.android.com/guide/topics/manifest/provider-element#proc
    """

    read_permission: str | None
    """
    A permission that clients must have to read the provider’s data.

    See: https://developer.android.com/guide/topics/manifest/provider-element#read
    """

    syncable: str | None
    """
    Whether the provider’s data can be synchronized with a server.

    See: https://developer.android.com/guide/topics/manifest/provider-element#syncable
    """

    write_permission: str | None
    """
    A permission that clients must have to modify the provider’s data.

    See: https://developer.android.com/guide/topics/manifest/provider-element#write
    """

@dataclass(frozen=True)
class Service:
    """
    Represents an Android service defined in an app's manifest.

    More information:
    <a href="https://developer.android.com/guide/topics/manifest/service-element" target="_blank">https://developer.android.com/guide/topics/manifest/service-element</a>
    """

    description: str | None
    """
    A user-readable description of the service.

    See: https://developer.android.com/guide/topics/manifest/service-element#desc
    """

    direct_boot_aware: str | None
    """
    Indicates whether the service is aware of Direct Boot mode.

    See: https://developer.android.com/guide/topics/manifest/service-element#directBootAware
    """

    enabled: str | None
    """
    Specifies whether the service can be instantiated by the system.

    See: https://developer.android.com/guide/topics/manifest/service-element#enabled
    """

    exported: str | None
    """
    Defines whether the service can be used by other applications.

    See: https://developer.android.com/guide/topics/manifest/service-element#exported
    """

    foreground_service_type: str | None
    """
    Lists the types of foreground services this service can run as.

    See: https://developer.android.com/guide/topics/manifest/service-element#foregroundservicetype
    """

    icon: str | None
    """
    An icon representing the service.

    See: https://developer.android.com/guide/topics/manifest/service-element#icon
    """

    isolated_process: str | None
    """
    Indicates whether the service runs in an isolated process.

    See: https://developer.android.com/guide/topics/manifest/service-element#isolated
    """

    label: str | None
    """
    A user-readable name for the service.

    See: https://developer.android.com/guide/topics/manifest/service-element#label
    """

    name: str | None
    """
    The fully qualified name of the service class that implements the service.

    See: https://developer.android.com/guide/topics/manifest/service-element#nm
    """

    permission: str | None
    """
    The name of a permission that clients must hold to use this service.

    See: https://developer.android.com/guide/topics/manifest/service-element#prmsn
    """

    process: str | None
    """
    The name of the process where the service should run.

    See: https://developer.android.com/guide/topics/manifest/service-element#proc
    """

    stop_with_task: str | None
    """
    Indicates whether the service should be stopped when its task is removed.

    See: https://developer.android.com/guide/topics/manifest/service-element#stopWithTask
    """

@dataclass(frozen=True)
class Receiver:
    """
    Represents an Android broadcast receiver defined in an app's manifest.

    More information:
    <a href="https://developer.android.com/guide/topics/manifest/receiver-element" target="_blank">https://developer.android.com/guide/topics/manifest/receiver-element</a>
    """

    direct_boot_aware: str | None
    """
    Indicates whether the broadcast receiver is direct boot aware.

    See: https://developer.android.com/guide/topics/manifest/receiver-element#enabled
    """

    enabled: str | None
    """
    Whether the broadcast receiver can be instantiated by the system.

    See: developer.android.com/guide/topics/manifest/receiver-element#enabled
    """

    exported: str | None
    """
    Specifies whether the broadcast receiver is accessible to other applications.

    See: https://developer.android.com/guide/topics/manifest/receiver-element#exported
    """

    icon: str | None
    """
    An icon representing the broadcast receiver in the user interface.

    See: https://developer.android.com/guide/topics/manifest/receiver-element#icon
    """

    label: str | None
    """
    A user-readable label for the broadcast receiver.

    See: https://developer.android.com/guide/topics/manifest/receiver-element#label
    """

    name: str | None
    """
    The fully qualified name of the broadcast receiver class that implements the receiver.

    See: https://developer.android.com/guide/topics/manifest/receiver-element#nm
    """

    permission: str | None
    """
    The name of a permission that broadcasters must hold to send messages to this receiver.

    See: https://developer.android.com/guide/topics/manifest/receiver-element#prmsn
    """

    process: str | None
    """
    The name of the process in which the broadcast receiver should run.

    See: https://developer.android.com/guide/topics/manifest/receiver-element#proc
    """
