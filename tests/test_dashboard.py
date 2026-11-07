import threading
import os
import unittest
import urllib.error
import urllib.parse
import urllib.request

from snowlint.dashboard import create_server


@unittest.skipUnless(os.environ.get("SNOWLINT_TEST_HTTP") == "1", "Loopback integration tests require explicit opt-in")
class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.server = create_server(port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2)

    def test_local_onboarding_audit_and_json_result(self):
        page = urllib.request.urlopen(self.base + "/").read().decode()
        self.assertIn("What does the system do?", page)
        form = urllib.parse.urlencode({"repository": ".", "purpose": "Test", "audience": "Developers", "scope": "security"}).encode()
        request = urllib.request.Request(self.base + "/audit", data=form, headers={"Origin": self.base, "Content-Type": "application/x-www-form-urlencoded"})
        response = urllib.request.urlopen(request)
        self.assertEqual(response.status, 200)
        result = urllib.request.urlopen(self.base + "/api/audit").read().decode()
        self.assertIn('"system_purpose": "Test"', result)

    def test_rejects_cross_origin_audit_post(self):
        form = urllib.parse.urlencode({"repository": ".", "scope": "full"}).encode()
        request = urllib.request.Request(self.base + "/audit", data=form, headers={"Origin": "http://attacker.invalid", "Content-Type": "application/x-www-form-urlencoded"})
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request)
        self.assertEqual(error.exception.code, 403)
        error.exception.close()


if __name__ == "__main__":
    unittest.main()
