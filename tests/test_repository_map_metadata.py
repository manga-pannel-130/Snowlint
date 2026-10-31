import tempfile
import unittest
from pathlib import Path

from repository_map import build_inventory, classify_file


class TestRepositoryMapMetadata(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_source_file_metadata(self):
        (self.root / "app.py").write_text(
            "print('hello')",
            encoding="utf-8",
        )

        result = build_inventory(self.root)
        record = result["files"][0]

        self.assertEqual(record["path"], "app.py")
        self.assertEqual(record["name"], "app.py")
        self.assertEqual(record["extension"], ".py")
        self.assertEqual(record["category"], "source")
        self.assertEqual(record["language"], "Python")
        self.assertEqual(record["size_bytes"], 14)
        self.assertFalse(record["is_test"])
        self.assertTrue(record["content_permitted"])
        self.assertEqual(record["content_status"], "not_read")

    def test_test_file_identification(self):
        test_dir = self.root / "tests"
        test_dir.mkdir()

        (test_dir / "test_scanner.py").write_text(
            "# test",
            encoding="utf-8",
        )

        result = build_inventory(self.root)
        record = result["files"][0]

        self.assertTrue(record["is_test"])

    def test_setup_py_is_classified_as_manifest(self):
        self.assertEqual(
            classify_file("setup.py"),
            "manifest",
        )

    def test_protected_file_metadata(self):
        (self.root / ".env").write_text(
            "SECRET=value",
            encoding="utf-8",
        )

        result = build_inventory(self.root)
        record = result["files"][0]

        self.assertFalse(record["content_permitted"])
        self.assertEqual(record["content_status"], "protected")
        self.assertIn(".env", result["protected_files"])
        self.assertEqual(result["coverage"]["files_protected"], 1)

    def test_exclusion_coverage(self):
        (self.root / ".snowlintignore").write_text(
            "*.log\nbuild/\n",
            encoding="utf-8",
        )

        (self.root / "app.py").write_text("code")
        (self.root / "debug.log").write_text("log")

        build_dir = self.root / "build"
        build_dir.mkdir()
        (build_dir / "output.js").write_text("code")

        result = build_inventory(self.root)
        coverage = result["coverage"]

        self.assertEqual(coverage["files_included"], 2)
        self.assertEqual(coverage["files_excluded"], 1)
        self.assertEqual(coverage["directories_excluded"], 1)
        self.assertEqual(coverage["files_discovered"], 3)

        self.assertIn(
            ".snowlintignore",
            result["configuration_files"],
        )

    def test_empty_repository_has_no_read_coverage_percentage(self):
        result = build_inventory(self.root)

        self.assertIsNone(
            result["coverage"]["content_read_coverage_percent"]
        )


if __name__ == "__main__":
    unittest.main()
