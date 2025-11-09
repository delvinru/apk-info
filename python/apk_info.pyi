from dataclasses import dataclass
from pathlib import Path
from typing import Literal

__version__: str
"""
Library version
"""

class APKError(Exception):
    """
    Generic exception related to issues with `apk-info` library
    """

    ...

class APK:
    """
    `APK` class, the main entrypoint to use `apk-info` library.

    **Example**

    ```python
    from apk_info import APK
    apk = APK("./path-to-file")
    ```
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

    def get_attribute_value(self, tag: str, name: str) -> str | None:
        """
        An auxiliary method that allows you to get the attribute value directly from AXML.

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
        """
        ...

    def get_all_attribute_values(self, tag: str, name: str) -> list[str]:
        """
        An auxiliary method that allows you to get the value from all attributes from AXML.

        Examples
        --------

        ```python
        apk = APK("./file")
        print(apk.get_all_atribute_values("uses-permission", "name")) # just use apk.get_permissions()
        ```
        """
        ...

    def get_package_name(self) -> str | None:
        """
        Retrieves the package name declared in the `<manifest>` element.

        .. manifest: https://developer.android.com/guide/topics/manifest/manifest-element#package

        Returns
        -------
            str | None
                The package name (e.g., "com.example.app") if found, otherwise None
        """
        ...

    def get_shared_user_id(self) -> str | None:
        """
        Retrieves the `sharedUserId` attribute from the `<manifest>` element.

        .. manifest: https://developer.android.com/guide/topics/manifest/manifest-element#uid

        Returns
        -------
            str | None
                The shared user ID if declared, otherwise None
        """
        ...

    def get_shared_user_label(self) -> str | None:
        """
        Retrieves the `sharedUserLabel` attribute from the `<manifest>` element.

        .. manifest: https://developer.android.com/guide/topics/manifest/manifest-element#uidlabel

        Returns
        -------
            str | None
                The shared user label if declared, otherwise None.
        """
        ...

    def get_shared_user_max_sdk_version(self) -> str | None:
        """
        Retrieves the `sharedUserMaxSdkVersion` attribute from the `<manifest>` element.

        .. manifest: https://developer.android.com/guide/topics/manifest/manifest-element#uidmaxsdk

        Returns
        -------
            str | None
                The maximum SDK version for the shared user, if declared
        """
        ...

    def get_version_code(self) -> str | None:
        """
        Retrieves the application version code.

        .. manifest: https://developer.android.com/guide/topics/manifest/manifest-element#vcode

        Examples
        --------

        ```python
        apk = APK("./file")
        print(apk.get_version_code()) # 2025101912
        ```

        Notes
        -----
            The automatic conversion to int was not done on purpose,
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

        .. manifest: https://developer.android.com/guide/topics/manifest/manifest-element#vname

        Examples
        --------

        ```python
        apk = APK("./file")
        print(apk.get_version_name()) # 1.2.3
        ```

        Returns
        -------
            str | None
                The version name as a string if present, otherwise None
        """
        ...

    def get_install_location(self) -> Literal["auto", "internalOnly", "preferExternal"] | None:
        """
        Retrieves the preferred installation location declared in the manifest.

        .. manifest: https://developer.android.com/guide/topics/manifest/manifest-element#install

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

    def get_application_task_reparenting(self) -> str | None:
        """
        Extracts the `android:allowTaskReparenting` attribute from `<application>`.

        Returns:
            str | None: "true" or "false" if declared, otherwise None.
        """
        ...

    def get_application_allow_backup(self) -> str | None:
        """
        Extracts the `android:allowBackup` attribute from `<application>`.

        Returns:
            str | None: "true" or "false" if declared, otherwise None.
        """
        ...

    def get_application_category(self) -> str | None:
        """
        Extracts the `android:appCategory` attribute from `<application>`.

        Possible values include:
            "accessibility", "audio", "game", "image", "maps",
            "news", "productivity", "social", or "video".

        Returns:
            str | None: The app category if defined, otherwise None.
        """
        ...

    def get_application_backup_agent(self) -> str | None:
        """
        Extracts the `android:backupAgent` attribute from `<application>`.

        Returns:
            str | None: The name of the backup agent class if declared, otherwise None.
        """
        ...

    def get_application_debuggable(self) -> str | None:
        """
        Extracts the `android:debuggable` attribute from `<application>`.

        Example:
            <application android:debuggable="true" />

        Returns:
            str | None: "true" or "false" if declared, otherwise None.
        """
        ...

    def get_application_description(self) -> str | None:
        """
        Extracts the `android:description` attribute from `<application>`.

        Note:
            This may refer to a string resource (e.g., "@string/app_desc").

        Returns:
            str | None: The description resource or literal value, if available.
        """
        ...

    def get_application_icon(self) -> str | None:
        """
        Extracts and resolve the `android:icon` attribute from `<application>`

        Returns:
            str | None: The path to the icon file, if available.
        """
        ...

    def get_application_label(self) -> str | None:
        """
        Extracts the `android:label` attribute from `<application>`.

        Note:
            This may refer to a string resource (e.g., "@string/app_name").

        Returns:
            str | None: The label resource or literal value, if available.
        """
        ...

    def get_application_name(self) -> str | None:
        """
        Extracts the `android:name` attribute from `<application>`.

        Returns:
            str | None: The fully qualified application class name, if defined.
        """
        ...

    def get_permissions(self) -> list[str]:
        """
        Retrieves all declared permissions from `<uses-permission>` elements.

        Returns:
            list[str]: A list of all permission names (e.g., "android.permission.INTERNET").
        """
        ...

    def get_permissions_sdk23(self) -> list[str]:
        """
        Retrieves all declared permissions for API level 23 and above
        from `<uses-permission-sdk-23>` elements.

        Returns:
            list[str]: A list of permission names if any are declared.
        """
        ...

    def get_min_sdk_version(self) -> str | None:
        """
        Extracts the minimum supported SDK version (`minSdkVersion`)
        from the `<uses-sdk>` element.

        Returns:
            str | None: The minimum SDK version as a string, or None if not specified.
        """
        ...

    def get_target_sdk_version(self) -> str | None:
        """
        Extracts the target SDK version (`targetSdkVersion`)
        from the `<uses-sdk>` element.

        Returns:
            str | None: The target SDK version as a string, or None if not specified.
        """
        ...

    def get_max_sdk_version(self) -> str | None:
        """
        Retrieves the maximum supported SDK version (`maxSdkVersion`) if declared.

        Returns:
            str | None: The maximum SDK version as a string, or None if not specified.
        """
        ...

    def get_libraries(self) -> list[str]:
        """
        Retrieves all libraries declared by `<uses-library android:name="...">`.

        Returns:
            list[str]: A list of library names.
        """
        ...

    def get_features(self) -> list[str]:
        """
        Retrieves all hardware or software features declared
        by `<uses-feature android:name="...">`.

        Returns:
            list[str]: A list of declared feature names.
        """
        ...

    def is_automotive(self) -> bool: ...
    def is_leanback(self) -> bool: ...
    def is_wearable(self) -> bool: ...
    def is_chromebook(self) -> bool: ...
    def get_declared_permissions(self) -> list[str]:
        """
        Retrieves all custom permissions defined by `<permission android:name="...">`.

        Returns:
            list[str]: A list of permission names defined by the application.
        """
        ...

    def get_main_activity(self) -> str | None:
        """
        Retrieves first main (launchable) activity defined in the manifest.

        A main activity is typically one that has an intent filter
        with actions `MAIN` and categories `LAUNCHER` or `INFO`.

        Returns:
            str | None: A main activity class name
        """
        ...

    def get_main_activities(self) -> list[str]:
        """
        Retrieves all main (launchable) activities defined in the manifest.

        A main activity is typically one that has an intent filter
        with actions `MAIN` and categories `LAUNCHER` or `INFO`.

        Returns:
            list[str]: A list of main activity class names.
        """
        ...

    def get_activities(self) -> list[str]:
        """
        Retrieves all `<activity>` components declared in the manifest.

        Returns:
            list[str]: A list of fully qualified activity class names.
        """
        ...

    def get_services(self) -> list[Service]:
        """
        Retrieves all `<service>` components declared in the manifest.

        Returns:
            list[str]: A list of service class names.
        """
        ...

    def get_receivers(self) -> list[Receiver]:
        """
        Retrieves all `<receiver>` components declared in the manifest.

        Returns:
            list[str]: A list of broadcast receiver class names.
        """
        ...

    def get_providers(self) -> list[str]:
        """
        Retrieves all `<provider>` components declared in the manifest.

        Returns:
            list[str]: A list of content provider class names.
        """
        ...

    def get_signatures(self) -> list[SignatureType]:
        """
        Retrieves all APK signing signatures (v1, v2, v3, and v3.1).

        Combines results from multiple signature blocks within the APK file.

        Returns:
            list[str]: A list of certificate signature strings.
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

        See: <https://source.android.com/docs/security/features/apksigning/v2#v1-verification>
        """

        certificates: list[CertificateInfo]

    @dataclass(frozen=True)
    class V2:
        """
        APK signature scheme v2

        See: <https://source.android.com/docs/security/features/apksigning/v2>
        """

        certificates: list[CertificateInfo]

    @dataclass(frozen=True)
    class V3:
        """
        APK signature scheme v3

        See: <https://source.android.com/docs/security/features/apksigning/v3>
        """

        certificates: list[CertificateInfo]

    @dataclass(frozen=True)
    class V31:
        """
        APK signature scheme v3.1

        See: <https://source.android.com/docs/security/features/apksigning/v3-1>
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

        See: <https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/util/apk/SourceStampVerifier.java#75>
        """

        certificate: CertificateInfo

    @dataclass(frozen=True)
    class StampBlockV2:
        """
        SourceStamp improves traceability of apps with respect to unauthorized distribution

        The stamp is part of the APK that is protected by the signing block

        See: <https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/util/apk/SourceStampVerifier.java#75>
        """

        certificate: CertificateInfo

SignatureType = (
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

from dataclasses import dataclass

@dataclass(frozen=True)
class Service:
    """
    Represents an Android service defined in an app's manifest.

    Each attribute corresponds to an attribute in the <service> element
    of the AndroidManifest.xml.
    """

    description: str | None
    """
    A user-readable description of the service.
    Corresponds to the `android:description` attribute.
    """

    direct_boot_aware: str | None
    """
    Indicates whether the service is aware of Direct Boot mode.
    Corresponds to the `android:directBootAware` attribute.
    """

    enabled: str | None
    """
    Specifies whether the service can be instantiated by the system.
    Corresponds to the `android:enabled` attribute.
    """

    exported: str | None
    """
    Defines whether the service can be used by other applications.
    Corresponds to the `android:exported` attribute.
    """

    foreground_service_type: str | None
    """
    Lists the types of foreground services this service can run as.
    Corresponds to the `android:foregroundServiceType` attribute.
    """

    isolated_process: str | None
    """
    Indicates whether the service runs in an isolated process.
    Corresponds to the `android:isolatedProcess` attribute.
    """

    name: str | None
    """
    The fully qualified name of the service class that implements the service.
    Corresponds to the `android:name` attribute.
    """

    permission: str | None
    """
    The name of a permission that clients must hold to use this service.
    Corresponds to the `android:permission` attribute.
    """

    process: str | None
    """
    The name of the process where the service should run.
    Corresponds to the `android:process` attribute.
    """

    stop_with_task: str | None
    """
    Indicates whether the service should be stopped when its task is removed.
    Corresponds to the `android:stopWithTask` attribute.
    """

@dataclass(frozen=True)
class Receiver:
    """
    Represents an Android broadcast receiver defined in an app's manifest.

    Each attribute corresponds to an attribute in the <receiver> element
    of the AndroidManifest.xml.
    """

    direct_boot_aware: str | None
    """
    Indicates whether the broadcast receiver is direct boot aware.
    Corresponds to the `android:directBootAware` attribute.
    """

    enabled: str | None
    """
    Whether the broadcast receiver can be instantiated by the system.
    Corresponds to the `android:enabled` attribute.
    """

    exported: str | None
    """
    Specifies whether the broadcast receiver is accessible to other applications.
    Corresponds to the `android:exported` attribute.
    """

    icon: str | None
    """
    An icon representing the broadcast receiver in the user interface.
    Corresponds to the `android:icon` attribute.
    """

    label: str | None
    """
    A user-readable label for the broadcast receiver.
    Corresponds to the `android:label` attribute.
    """

    name: str | None
    """
    The fully qualified name of the broadcast receiver class that implements the receiver.
    Corresponds to the `android:name` attribute.
    """

    permission: str | None
    """
    The name of a permission that broadcasters must hold to send messages to this receiver.
    Corresponds to the `android:permission` attribute.
    """

    process: str | None
    """
    The name of the process in which the broadcast receiver should run.
    Corresponds to the `android:process` attribute.
    """
