"""Read repository text without following symbolic links or escaping the root."""
import errno
import os
import stat
from pathlib import Path

from content_policy import can_read_content

DEFAULT_MAX_FILE_SIZE = 5_000_000  # 5 MB


def _open_repository_file(root: Path, parts: tuple[str, ...]):
    """Walk with directory descriptors and O_NOFOLLOW to reduce path races."""
    if not hasattr(os, "O_NOFOLLOW"):
        raise NotImplementedError("Secure no-follow file access is unavailable on this platform")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    directory_flags = flags | getattr(os, "O_DIRECTORY", 0)
    current_fd = os.open(root, directory_flags)
    try:
        for component in parts[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return os.open(parts[-1], flags | getattr(os, "O_NONBLOCK", 0), dir_fd=current_fd)
    finally:
        os.close(current_fd)


def read_text_file(root_directory, relative_path, max_bytes=DEFAULT_MAX_FILE_SIZE):
    root = Path(root_directory).expanduser().resolve()
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts or "\\" in str(relative_path):
        raise ValueError("Invalid repository-relative path")
    if max_bytes < 0:
        raise ValueError("max_bytes cannot be negative")
    if not can_read_content(relative.as_posix()):
        return {"path": relative.as_posix(), "status": "protected", "content": None,
                "reason": "Blocked by sensitive-file policy"}

    fd = None
    try:
        fd = _open_repository_file(root, relative.parts)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise PermissionError("Not a regular file")
        if info.st_size > max_bytes:
            return {"path": relative.as_posix(), "status": "skipped", "content": None,
                    "reason": "File exceeds maximum permitted size"}
        chunks = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk: break
            chunks.append(chunk); remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            return {"path": relative.as_posix(), "status": "skipped", "content": None,
                    "reason": "File exceeds maximum permitted size"}
        try:
            content = data.decode("utf-8")
        except UnicodeDecodeError:
            return {"path": relative.as_posix(), "status": "skipped", "content": None,
                    "reason": "Unsupported text encoding or binary file"}
        return {"path": relative.as_posix(), "status": "read", "content": content, "reason": None}
    except FileNotFoundError:
        raise FileNotFoundError(f"Not a regular file: {relative_path}")
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise PermissionError("Symbolic links are not supported") from error
        return {"path": relative.as_posix(), "status": "error", "content": None, "reason": str(error)}
    finally:
        if fd is not None: os.close(fd)
