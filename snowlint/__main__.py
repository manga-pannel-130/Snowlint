"""Allow ``python -m snowlint`` to use the installed CLI."""

from snowlint.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
