import tempfile
import unittest
from pathlib import Path

from repository_map import build_inventory


class TestRepositoryMap(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def create_file(self, relative_path):
        file_path = self.root / relative_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text("test content")

    def test_counts_languages(self):
        self.create_file("main.py")
        self.create_file("backend/api.py")
        self.create_file("frontend/app.tsx")
        self.create_file("frontend/utils.js")

        result = build_inventory(self.root)

        self.assertEqual(
            result["summary"]["languages"],
            {
                "JavaScript": 1,
                "Python": 2,
                "TypeScript": 1,
            },
        )

    def test_identifies_manifests(self):
        self.create_file("pyproject.toml")
        self.create_file("requirements.txt")
        self.create_file("package.json")

        result = build_inventory(self.root)

        self.assertEqual(
            result["manifests"],
            ["package.json", "pyproject.toml", "requirements.txt"],
        )

    def test_identifies_ci_files(self):
        self.create_file(".github/workflows/ci.yml")
        self.create_file(".gitlab-ci.yml")

        result = build_inventory(self.root)

        self.assertEqual(
            result["ci_files"],
            [".github/workflows/ci.yml", ".gitlab-ci.yml"],
        )

    def test_marks_sensitive_files_as_protected(self):
        self.create_file(".env")
        self.create_file("main.py")

        result = build_inventory(self.root)

        self.assertEqual(result["summary"]["total_files"], 2)
        self.assertEqual(result["summary"]["readable_files"], 1)
        self.assertEqual(result["summary"]["protected_files"], 1)
        self.assertEqual(result["protected_files"], [".env"])

    def test_rejects_nonexistent_directory(self):
        with self.assertRaises(FileNotFoundError):
            build_inventory(self.root / "does-not-exist")


if __name__ == "__main__":
    unittest.main()
