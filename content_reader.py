from pathlib import Path

from content_policy import can_read_content


DEFAULT_MAX_FILE_SIZE = 5_000_000  # 5 MB


def read_text_file(
    root_directory,
    relative_path,
    max_bytes=DEFAULT_MAX_FILE_SIZE,
):
    root = Path(root_directory).resolve()
    relative = Path(relative_path)

    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("Invalid repository-relative path")

    file_path = root / relative

    if file_path.is_symlink():
        raise PermissionError("Symbolic links are not supported")

    resolved_path = file_path.resolve()

    try:
        resolved_path.relative_to(root)
    except ValueError:
        raise PermissionError("File is outside the repository")

    if not resolved_path.is_file():
        raise FileNotFoundError(f"Not a regular file: {relative_path}")

    if not can_read_content(relative_path):
        return {
            "path": relative_path,
            "status": "protected",
            "content": None,
            "reason": "Blocked by sensitive-file policy",
        }

    if max_bytes < 0:
        raise ValueError("max_bytes cannot be negative")

    if resolved_path.stat().st_size > max_bytes:
        return {
            "path": relative_path,
            "status": "skipped",
            "content": None,
            "reason": "File exceeds maximum permitted size",
        }

    try:
        content = resolved_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return {
            "path": relative_path,
            "status": "skipped",
            "content": None,
            "reason": "Unsupported text encoding or binary file",
        }
    except OSError as error:
        return {
            "path": relative_path,
            "status": "error",
            "content": None,
            "reason": str(error),
        }

    return {
        "path": relative_path,
        "status": "read",
        "content": content,
        "reason": None,
    }
