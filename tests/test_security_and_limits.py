import json
import tempfile
import unittest
from pathlib import Path

from snowlint.core.engine import analyze_repository
from content_reader import read_text_file


class SecurityAndLimitsTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def create_file(self, name, content=""):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def test_rejects_backslash_path_traversal(self):
        self.create_file("safe.py", "print(1)")
        with self.assertRaises(ValueError):
            read_text_file(self.root, "..\\secret.py")

    def test_rejects_absolute_path_read(self):
        self.create_file("safe.py", "print(1)")
        with self.assertRaises(ValueError):
            read_text_file(self.root, "/etc/passwd")

    def test_corrupted_manifests_do_not_crash_analysis(self):
        self.create_file("package.json", "{ malformed json: true, ")
        self.create_file("pyproject.toml", "[[ invalid toml == 123 ]")
        self.create_file("app.py", "print('hello')\n")
        result = analyze_repository(self.root)
        self.assertEqual(result.coverage.files_read, 3)
        self.assertEqual(result.coverage.source_files_analyzed, 1)

    def test_syntax_error_in_source_is_recorded_as_limitation(self):
        self.create_file("broken.py", "def foo(:\n    syntax error here\n")
        result = analyze_repository(self.root)
        self.assertEqual(result.coverage.source_files_analyzed, 0)
        self.assertTrue(any("Python syntax error in broken.py" in lim for lim in result.coverage.limitations))

    def test_symlink_loop_handling(self):
        dir_a = self.root / "sub_a"
        dir_b = self.root / "sub_b"
        dir_a.mkdir(parents=True, exist_ok=True)
        dir_b.mkdir(parents=True, exist_ok=True)
        (dir_a / "test.py").write_text("print('a')", encoding="utf-8")
        loop_link = dir_b / "loop"
        loop_link.symlink_to(dir_a, target_is_directory=True)
        result = analyze_repository(self.root)
        # Should scan sub_a/test.py and ignore or skip the loop link safely
        self.assertGreaterEqual(result.coverage.files_discovered, 1)

    def test_unsupported_audit_scope_raises_value_error(self):
        with self.assertRaises(ValueError):
            analyze_repository(self.root, audit_scope="invalid_scope_name")


if __name__ == "__main__":
    unittest.main()
