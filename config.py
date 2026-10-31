DEFAULT_EXCLUDES = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "coverage",
}

SNOWLINTIGNORE_FILENAME = ".snowlintignore"

SENSITIVE_FILE_PATTERNS = {
    ".env",
    ".env.*",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "credentials.json",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
}
