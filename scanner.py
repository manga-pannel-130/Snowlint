import os
from pathlib import Path
from config import DEFAULT_IGNORES


def list_files(directory_path):
    path = Path(directory_path)
    relative_paths = []

    for root, dirs, files in os.walk(path):
        dirs[:] = [
            directory for directory in dirs
            if directory not in DEFAULT_IGNORES
        ]

        for file in files:
            file_path = Path(root) / file
            relative_paths.append(
                file_path.relative_to(path).as_posix()
            )

    return relative_paths


if __name__ == "__main__":
    files = list_files(".")
    print(files)

