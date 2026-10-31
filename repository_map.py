from collections import Counter
from pathlib import Path

from scanner import list_files
from content_policy import can_read_content


LANGUAGE_EXTENSIONS = {
    ".py": "Python",
    ".pyw": "Python",
    ".pyi": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".mts": "TypeScript",
    ".cts": "TypeScript",
}

MANIFEST_NAMES = {
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "pipfile",
    "poetry.lock",
    "uv.lock",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
}

CONFIGURATION_NAMES = {
    ".gitignore",
    ".editorconfig",
    "tsconfig.json",
    "jsconfig.json",
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    "makefile",
}

CI_FILENAMES = {
    ".gitlab-ci.yml",
    "jenkinsfile",
    "azure-pipelines.yml",
    "bitbucket-pipelines.yml",
}


def classify_file(file_path):
    path = Path(file_path)
    filename = path.name.lower()
    extension = path.suffix.lower()

    if extension in LANGUAGE_EXTENSIONS:
        return "source"

    if filename in MANIFEST_NAMES:
        return "manifest"

    if filename.startswith("requirements") and filename.endswith(".txt"):
        return "manifest"

    if filename in CONFIGURATION_NAMES:
        return "configuration"

    if filename in CI_FILENAMES or file_path.startswith(".github/workflows/"):
        return "ci"

    return "other"


def build_inventory(directory_path):
    root = Path(directory_path).expanduser().resolve()

    if not root.exists():
        raise FileNotFoundError(f"Repository does not exist: {root}")

    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    discovered_paths = list_files(root)

    files = []
    extensions = Counter()
    languages = Counter()

    manifests = []
    configuration_files = []
    ci_files = []
    protected_files = []

    for relative_path in discovered_paths:
        path = Path(relative_path)
        extension = path.suffix.lower() or "[no extension]"
        category = classify_file(relative_path)
        readable = can_read_content(relative_path)

        file_record = {
            "path": relative_path,
            "extension": extension,
            "category": category,
            "content_readable": readable,
        }

        files.append(file_record)
        extensions[extension] += 1

        if extension in LANGUAGE_EXTENSIONS:
            languages[LANGUAGE_EXTENSIONS[extension]] += 1

        if category == "manifest":
            manifests.append(relative_path)

        elif category == "configuration":
            configuration_files.append(relative_path)

        elif category == "ci":
            ci_files.append(relative_path)

        if not readable:
            protected_files.append(relative_path)

    return {
        "summary": {
            "total_files": len(files),
            "readable_files": len(files) - len(protected_files),
            "protected_files": len(protected_files),
            "files_by_extension": dict(sorted(extensions.items())),
            "languages": dict(sorted(languages.items())),
        },
        "files": files,
        "manifests": manifests,
        "configuration_files": configuration_files,
        "ci_files": ci_files,
        "protected_files": protected_files,
    }
