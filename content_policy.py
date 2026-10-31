from fnmatch import fnmatchcase
from pathlib import Path

from config import SENSITIVE_FILE_PATTERNS


def is_sensitive_file(file_path):
    filename = Path(file_path).name.lower()

    return any(
        fnmatchcase(filename, pattern)
        for pattern in SENSITIVE_FILE_PATTERNS
    )


def can_read_content(file_path):
    return not is_sensitive_file(file_path)
