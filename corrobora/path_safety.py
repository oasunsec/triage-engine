"""Link checks compatible with the project's minimum Python version."""

from pathlib import Path
import stat


def is_link_or_reparse(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    # Path.is_junction() is unavailable on Python 3.10/3.11. Windows junctions,
    # symlinks, and other redirected paths expose the reparse attribute via lstat.
    return (stat.S_ISLNK(metadata.st_mode)
            or bool(getattr(metadata, "st_file_attributes", 0)
                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))


def reject_path_links(path: Path, message: str) -> None:
    absolute = path.absolute()
    if any(is_link_or_reparse(part) for part in (absolute, *absolute.parents)):
        raise ValueError(message)
