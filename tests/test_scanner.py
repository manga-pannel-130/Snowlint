import tempfile
import unittest
from pathlib import Path

from scanner import list_files,scan_repository


class TestScanner(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def create_file(self, relative_path):
        file_path = self.root / relative_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text("test content")
        return file_path

    def test_discovers_nested_files(self):
        self.create_file("src/main.py")
        self.create_file("src/utils/helper.py")

        result = list_files(self.root)

        self.assertEqual(
            result,
            ["src/main.py", "src/utils/helper.py"]
        )

    def test_ignores_default_directories(self):
        self.create_file("src/main.py")
        self.create_file(".venv/lib/package.py")
        self.create_file("node_modules/library/index.js")
        self.create_file(".git/config")

        result = list_files(self.root)

        self.assertEqual(result, ["src/main.py"])

    def test_ignores_python_package_metadata_directories(self):
        self.create_file("snowlint.egg-info/PKG-INFO")
        self.create_file("src/main.py")

        result = list_files(self.root)

        self.assertEqual(result, ["src/main.py"])

    def test_keeps_useful_hidden_files(self):
        self.create_file(".gitignore")
        self.create_file(".github/workflows/ci.yml")
        self.create_file("src/main.py")

        result = list_files(self.root)

        self.assertEqual(
            result,
            [".github/workflows/ci.yml", ".gitignore", "src/main.py"]
        )

    def test_returns_sorted_paths(self):
        self.create_file("z.py")
        self.create_file("a.py")
        self.create_file("m.py")

        result = list_files(self.root)

        self.assertEqual(result, ["a.py", "m.py", "z.py"])

    def test_discovers_sensitive_file_paths(self):
        self.create_file(".env")
        self.create_file("src/main.py")

        result = list_files(self.root)

        self.assertEqual(result, [".env", "src/main.py"])

    def test_snowlintignore_excludes_matching_files(self):
        (self.root / ".snowlintignore").write_text(
            "*.log\ngenerated/\n",
            encoding="utf-8",
        )

        (self.root / "app.py").write_text("print('hello')")
        (self.root / "debug.log").write_text("log")
        (self.root / "generated").mkdir()
        (self.root / "generated" / "output.py").write_text("code")

        result = scan_repository(self.root)

        self.assertIn("app.py", result["files"])
        self.assertNotIn("debug.log", result["files"])
        self.assertNotIn("generated/output.py", result["files"])

        excluded_paths = {
            item["path"] for item in result["excluded_files"]
        }

        self.assertIn("debug.log", excluded_paths)

        excluded_dirs = {
            item["path"] for item in result["excluded_directories"]
        }

        self.assertIn("generated", excluded_dirs)


    def test_custom_directory_exclusion(self):
        (self.root / "vendor").mkdir()
        (self.root / "vendor" / "library.js").write_text("code")
        (self.root / "app.py").write_text("code")

        result = scan_repository(
            self.root,
            exclude_dirs={"vendor"},
        )

        self.assertIn("app.py", result["files"])
        self.assertNotIn("vendor/library.js", result["files"])


    def test_custom_file_pattern_exclusion(self):
        (self.root / "debug.log").write_text("log")
        (self.root / "app.py").write_text("code")

        result = scan_repository(
            self.root,
            exclude_patterns=["*.log"],
        )

        self.assertIn("app.py", result["files"])
        self.assertEqual(len(result["excluded_files"]), 1)


    def test_sensitive_files_are_not_hidden_by_default(self):
        (self.root / ".env").write_text("SECRET=value")

        result = scan_repository(self.root)

        # Discovery and content protection are separate responsibilities.
        self.assertIn(".env", result["files"])


    def test_ignore_file_rejects_parent_traversal(self):
        (self.root / ".snowlintignore").write_text(
            "../outside\n",
            encoding="utf-8",
        )

        with self.assertRaises(ValueError):
            scan_repository(self.root)

if __name__ == "__main__":
    unittest.main()
