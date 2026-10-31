from collections import Counter
from pathlib import Path

from scanner import scan_repository
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
    ".snowlintignore",
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

    # Check special filenames before extensions.
    # For example, setup.py is a manifest, not an ordinary source file.
    if filename in MANIFEST_NAMES:
        return "manifest"

    if filename.startswith("requirements") and filename.endswith(".txt"):
        return "manifest"

    if filename in CONFIGURATION_NAMES:
        return "configuration"

    if filename in CI_FILENAMES or file_path.startswith(".github/workflows/"):
        return "ci"

    if extension in LANGUAGE_EXTENSIONS:
        return "source"

    return "other"


def identify_language(file_path):
    extension = Path(file_path).suffix.lower()
    return LANGUAGE_EXTENSIONS.get(extension)


def identify_test_file(file_path):
    path = Path(file_path)
    filename = path.name.lower()

    test_directories = {
        "test",
        "tests",
        "__tests__",
    }

    if any(part.lower() in test_directories for part in path.parts[:-1]):
        return True

    test_suffixes = (
        ".test.js",
        ".test.jsx",
        ".test.ts",
        ".test.tsx",
        ".spec.js",
        ".spec.jsx",
        ".spec.ts",
        ".spec.tsx",
    )

    if filename.startswith("test_") or filename.endswith("_test.py"):
        return True

    return filename.endswith(test_suffixes)


def build_inventory(
    directory_path,
    exclude_dirs=None,
    exclude_patterns=None,
):
    root = Path(directory_path).expanduser().resolve()

    if not root.exists():
        raise FileNotFoundError(f"Repository does not exist: {root}")

    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    scan_result = scan_repository(
        root,
        exclude_dirs=exclude_dirs,
        exclude_patterns=exclude_patterns,
    )

    files = []

    extensions = Counter()
    languages = Counter()
    categories = Counter()

    manifests = []
    configuration_files = []
    ci_files = []
    protected_files = []

    content_status_counts = Counter()

    for relative_path in scan_result["files"]:
        path = Path(relative_path)
        absolute_path = root / path

        extension = path.suffix.lower() or "[no extension]"
        filename = path.name
        category = classify_file(relative_path)
        language = identify_language(relative_path)
        is_test = identify_test_file(relative_path)

        permitted = can_read_content(relative_path)
        is_symlink = absolute_path.is_symlink()

        # A symlink is not followed or inspected.
        if not permitted:
            content_status = "protected"
            content_reason = "Blocked by sensitive-file policy"
        elif is_symlink:
            content_status = "skipped"
            content_reason = "Symbolic links are not supported"
        else:
            content_status = "not_read"
            content_reason = None

        try:
            size_bytes = (
                None if is_symlink else absolute_path.stat().st_size
            )
            metadata_error = None
        except OSError as error:
            size_bytes = None
            metadata_error = str(error)

        file_record = {
            "path": relative_path,
            "name": filename,
            "extension": extension,
            "category": category,
            "language": language,
            "size_bytes": size_bytes,
            "is_test": is_test,
            "is_symlink": is_symlink,
            "content_permitted": permitted,
            "content_readable": permitted and not is_symlink,
            "content_status": content_status,
            "content_reason": content_reason,
            "metadata_error": metadata_error,
        }

        files.append(file_record)

        extensions[extension] += 1
        categories[category] += 1

        if language:
            languages[language] += 1

        content_status_counts[content_status] += 1

        if category == "manifest":
            manifests.append(relative_path)
        elif category == "configuration":
            configuration_files.append(relative_path)
        elif category == "ci":
            ci_files.append(relative_path)

        if not permitted:
            protected_files.append(relative_path)

    files.sort(key=lambda item: item["path"])

    included_count = len(files)
    excluded_count = scan_result["summary"]["files_excluded"]
    enumerated_count = scan_result["summary"]["enumerated_files"]

    read_count = content_status_counts["read"]
    skipped_count = content_status_counts["skipped"]
    error_count = content_status_counts["error"]
    protected_count = content_status_counts["protected"]
    not_read_count = content_status_counts["not_read"]

    content_read_coverage = (
        round((read_count / included_count) * 100, 2)
        if included_count
        else None
    )

    return {
        "summary": {
            # Backwards-compatible fields
            "total_files": included_count,
            "readable_files": included_count - protected_count,
            "protected_files": protected_count,

            # Expanded inventory counts
            "files_discovered": enumerated_count,
            "files_included": included_count,
            "files_excluded": excluded_count,
            "directories_excluded": (
                scan_result["summary"]["directories_excluded"]
            ),

            # Content inspection counts
            "files_read": read_count,
            "files_not_read": not_read_count,
            "files_skipped": skipped_count,
            "files_with_errors": error_count,

            # Metadata breakdowns
            "files_by_extension": dict(sorted(extensions.items())),
            # Metadata breakdowns
            "languages": dict(sorted(languages.items())),
            "files_by_language": dict(sorted(languages.items())),
            "files_by_category": dict(sorted(categories.items())),

            # None means no included files, not 0% analysis quality.
            "content_read_coverage_percent": content_read_coverage,
        },
        "coverage": {
            "files_discovered": enumerated_count,
            "files_included": included_count,
            "files_excluded": excluded_count,
            "directories_excluded": (
                scan_result["summary"]["directories_excluded"]
            ),
            "files_protected": protected_count,
            "files_read": read_count,
            "files_not_read": not_read_count,
            "files_skipped": skipped_count,
            "files_with_errors": error_count,
            "content_read_coverage_percent": content_read_coverage,
        },
        "files": files,
        "manifests": manifests,
        "configuration_files": configuration_files,
        "ci_files": ci_files,
        "protected_files": protected_files,
        "excluded_files": scan_result["excluded_files"],
        "excluded_directories": scan_result["excluded_directories"],
    }
