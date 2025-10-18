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

        Returns:
            str | None: The package name (e.g., "com.example.app") if found,
            otherwise `None`.
        """
        ...

    def get_min_sdk_version(self) -> str | None:
        """
        Extracts the minimum supported SDK version (`minSdkVersion`)
        from the APK's manifest.

        Returns:
            str | None: The minimum SDK version as a string, or `None` if not specified.
        """
        ...

    def get_max_sdk_version(self) -> str | None:
        """
        Retrieves the maximum supported SDK version (`maxSdkVersion`) if declared.

        Returns:
            str | None: The maximum SDK version as a string, or `None` if not specified.
        """
        ...
