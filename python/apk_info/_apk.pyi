from pathlib import Path

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
