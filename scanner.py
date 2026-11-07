import os
from pathlib import Path
from fnmatch import fnmatchcase

from config import DEFAULT_EXCLUDES, SNOWLINTIGNORE_FILENAME


def load_ignore_patterns(root):
    """
    Load exclusion patterns from the repository's .snowlintignore file.

    Blank lines and comments are ignored.
    """
    ignore_path = root / SNOWLINTIGNORE_FILENAME

    if not ignore_path.exists():
        return []

    if ignore_path.is_symlink():
        raise PermissionError(
            f"{SNOWLINTIGNORE_FILENAME} cannot be a symbolic link"
        )

    patterns = []

    for line_number, line in enumerate(
        ignore_path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        pattern = line.strip()

        if not pattern or pattern.startswith("#"):
            continue

        pattern = pattern.removeprefix("./").rstrip("/")

        if not pattern:
            continue

        pattern_path = Path(pattern)

        if pattern_path.is_absolute() or ".." in pattern_path.parts:
            raise ValueError(
                f"Invalid exclusion pattern at line {line_number}: {line}"
            )

        patterns.append(pattern)

    return patterns


def matches_pattern(relative_path, pattern):
    """
    Match a repository-relative path against one ignore pattern.

    Patterns without '/' match any individual path component.
    Patterns containing '/' match the relative path or one of
    its parent paths.
    """
    path = Path(relative_path)
    parts = path.parts

    if "/" not in pattern:
        return any(fnmatchcase(part, pattern) for part in parts)

    candidates = [
        Path(*parts[:index]).as_posix()
        for index in range(1, len(parts) + 1)
    ]

    return any(fnmatchcase(candidate, pattern) for candidate in candidates)


def get_exclusion_reason(
    relative_path,
    is_directory,
    ignore_names,
    ignore_patterns,
):
    """
    Return the reason for exclusion, or None if the path is included.
    """
    path = Path(relative_path)

    if is_directory and (
        path.name in ignore_names or path.name.endswith(".egg-info")
    ):
        return "directory_name_exclusion"

    for pattern in ignore_patterns:
        if matches_pattern(relative_path, pattern):
            return f"snowlintignore:{pattern}"

    return None


def scan_repository(
    directory_path,
    exclude_dirs=None,
    exclude_patterns=None,
):
    """
    Scan a repository and return included and excluded paths.

    Built-in directory exclusions cannot be overridden.
    Sensitive-file protection is handled separately by content_policy.py.
    """
    root = Path(directory_path).expanduser().resolve()

    if not root.exists():
        raise FileNotFoundError(f"Repository does not exist: {root}")

    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    ignore_names = set(DEFAULT_EXCLUDES)

    if exclude_dirs:
        ignore_names.update(exclude_dirs)

    ignore_patterns = load_ignore_patterns(root)

    if exclude_patterns:
        ignore_patterns.extend(exclude_patterns)

    included_files = []
    excluded_files = []
    excluded_directories = []

    for current_root, dirs, files in os.walk(root, followlinks=False):
        current_path = Path(current_root)

        remaining_dirs = []

        for directory in dirs:
            directory_path = current_path / directory
            relative_path = directory_path.relative_to(root).as_posix()

            reason = get_exclusion_reason(
                relative_path,
                is_directory=True,
                ignore_names=ignore_names,
                ignore_patterns=ignore_patterns,
            )

            if reason:
                excluded_directories.append({
                    "path": relative_path,
                    "reason": reason,
                })
            else:
                remaining_dirs.append(directory)

        # Prune excluded directories before os.walk enters them.
        dirs[:] = remaining_dirs

        for filename in files:
            file_path = current_path / filename
            relative_path = file_path.relative_to(root).as_posix()

            reason = get_exclusion_reason(
                relative_path,
                is_directory=False,
                ignore_names=ignore_names,
                ignore_patterns=ignore_patterns,
            )

            if reason:
                excluded_files.append({
                    "path": relative_path,
                    "reason": reason,
                })
            else:
                included_files.append(relative_path)

    included_files.sort()
    excluded_files.sort(key=lambda item: item["path"])
    excluded_directories.sort(key=lambda item: item["path"])

    return {
        "files": included_files,
        "excluded_files": excluded_files,
        "excluded_directories": excluded_directories,
        "summary": {
            "files_included": len(included_files),
            "files_excluded": len(excluded_files),
            "directories_excluded": len(excluded_directories),
            # Files inside pruned directories are intentionally not counted.
            "enumerated_files": len(included_files) + len(excluded_files),
        },
    }


def list_files(directory_path):
    """
    Backwards-compatible interface returning only included file paths.
    """
    return scan_repository(directory_path)["files"]


if __name__ == "__main__":
    result = scan_repository(".")

    print("Included files:")
    for file_path in result["files"]:
        print(file_path)

    print("\nExcluded files:")
    for item in result["excluded_files"]:
        print(f"{item['path']} — {item['reason']}")

    print("\nExcluded directories:")
    for item in result["excluded_directories"]:
        print(f"{item['path']} — {item['reason']}")

    print("\nSummary:")
    print(result["summary"])
