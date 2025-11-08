from dataclasses import dataclass
from pathlib import Path

__version__: str

class APK:
    def __init__(self, path: str | Path) -> None:
        """
        Create a new APK instance

        Args:
            path (str | Path): Path to the APK file on disk

        Raises:
            PyFileNotFoundError: If file not exists
            PyValueError: If got error while parsing zip entry
            PyTypeError: If the argument is not str or Path
        """
        ...

    def read(self, filename: str) -> bytes:
        """
        Read raw data for the filename in the zip archive
        """
        ...

    def get_files(self) -> list[str]:
        """
        List of the filenames included in the central directory
        """
        ...

    def get_package_name(self) -> str | None:
        """
        Retrieves the package name declared in the `<manifest>` element.

        Example:
            <manifest package="com.example.app" />

        Returns:
            str | None: The package name (e.g., "com.example.app") if found,
            otherwise None.
        """
        ...

    def get_shared_user_id(self) -> str | None:
        """
        Retrieves the `sharedUserId` attribute from the `<manifest>` element.

        Returns:
            str | None: The shared user ID if declared, otherwise None.
        """
        ...

    def get_shared_user_label(self) -> str | None:
        """
        Retrieves the `sharedUserLabel` attribute from the `<manifest>` element.

        Returns:
            str | None: The shared user label if declared, otherwise None.
        """
        ...

    def get_shared_user_max_sdk_version(self) -> str | None:
        """
        Retrieves the `sharedUserMaxSdkVersion` attribute from the `<manifest>` element.

        Returns:
            str | None: The maximum SDK version for the shared user, if declared.
        """
        ...

    def get_version_code(self) -> str | None:
        """
        Retrieves the application version code.

        Example:
            <manifest android:versionCode="42" />

        Returns:
            str | None: The version code as a string if present, otherwise None.
        """
        ...

    def get_version_name(self) -> str | None:
        """
        Retrieves the human-readable application version name.

        Example:
            <manifest android:versionName="1.2.3" />

        Returns:
            str | None: The version name as a string if present, otherwise None.
        """
        ...

    def get_install_location(self) -> str | None:
        """
        Retrieves the preferred installation location declared in the manifest.

        Possible values:
            "auto", "internalOnly", or "preferExternal".

        Returns:
            str | None: The installation location if specified, otherwise None.
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

    def get_declared_permissions(self) -> list[str]:
        """
        Retrieves all custom permissions defined by `<permission android:name="...">`.

        Returns:
            list[str]: A list of permission names defined by the application.
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
