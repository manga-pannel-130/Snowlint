import unittest

from content_policy import is_sensitive_file, can_read_content


class TestContentPolicy(unittest.TestCase):

    def test_blocks_environment_files(self):
        self.assertTrue(is_sensitive_file(".env"))
        self.assertTrue(is_sensitive_file(".env.local"))
        self.assertTrue(is_sensitive_file(".env.example"))

    def test_blocks_private_key_files(self):
        self.assertTrue(is_sensitive_file("id_rsa"))
        self.assertTrue(is_sensitive_file("id_ed25519"))
        self.assertTrue(is_sensitive_file("server.pem"))
        self.assertTrue(is_sensitive_file("private.key"))

    def test_blocks_secret_store_files(self):
        self.assertTrue(is_sensitive_file("credentials.json"))
        self.assertTrue(is_sensitive_file("secrets.yaml"))

    def test_allows_normal_source_files(self):
        self.assertFalse(is_sensitive_file("main.py"))
        self.assertFalse(is_sensitive_file("package.json"))
        self.assertFalse(is_sensitive_file("config.py"))

    def test_read_permission(self):
        self.assertFalse(can_read_content(".env"))
        self.assertTrue(can_read_content("main.py"))


if __name__ == "__main__":
    unittest.main()
