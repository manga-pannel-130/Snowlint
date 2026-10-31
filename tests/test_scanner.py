import tempfile
import unittest
from pathlib import Path

from scanner import list_files


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


if __name__ == "__main__":
    unittest.main()
