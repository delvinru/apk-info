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
