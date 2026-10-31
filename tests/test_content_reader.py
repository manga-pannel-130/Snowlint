import tempfile
import unittest
from pathlib import Path

from content_reader import read_text_file


class TestContentReader(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def create_file(self, name, content="test content"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)

        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")

        return path

    def test_reads_normal_file(self):
        self.create_file("main.py", "print('hello')")

        result = read_text_file(self.root, "main.py")

        self.assertEqual(result["status"], "read")
        self.assertEqual(result["content"], "print('hello')")

    def test_protects_sensitive_file(self):
        self.create_file(".env", "SECRET=123")

        result = read_text_file(self.root, ".env")

        self.assertEqual(result["status"], "protected")
        self.assertIsNone(result["content"])

    def test_rejects_path_traversal(self):
        with self.assertRaises(ValueError):
            read_text_file(self.root, "../secret.txt")

    def test_rejects_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            read_text_file(self.root, "missing.py")

    def test_skips_large_file(self):
        self.create_file("large.py", "x" * 100)

        result = read_text_file(self.root, "large.py", max_bytes=50)

        self.assertEqual(result["status"], "skipped")
        self.assertIsNone(result["content"])

    def test_skips_binary_file(self):
        self.create_file("model.bin", b"\x80\x81\x82\x83")

        result = read_text_file(self.root, "model.bin")

        self.assertEqual(result["status"], "skipped")
        self.assertIsNone(result["content"])

    def test_rejects_symbolic_links(self):
        target = self.create_file("target.py")
        link = self.root / "linked.py"
        link.symlink_to(target)

        with self.assertRaises(PermissionError):
            read_text_file(self.root, "linked.py")

    def test_rejects_negative_size_limit(self):
        self.create_file("main.py")

        with self.assertRaises(ValueError):
            read_text_file(self.root, "main.py", max_bytes=-1)


if __name__ == "__main__":
    unittest.main()
