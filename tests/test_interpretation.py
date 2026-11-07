import tempfile
import unittest
from pathlib import Path

from snowlint.benchmark import run_benchmark
from snowlint.core.engine import analyze_repository
from snowlint.core.interpretation import interpret_with_provider


class InterpretationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "app.py").write_text("def run():\n    eval(source)\n", encoding="utf-8")
        self.result = analyze_repository(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_provider_requires_explicit_consent(self):
        called = []
        with self.assertRaises(PermissionError):
            interpret_with_provider(self.result, self.root, lambda packet: called.append(packet), explicit_consent=False)
        self.assertEqual(called, [])

    def test_only_exact_packet_evidence_is_accepted(self):
        def provider(packet):
            evidence = packet["observed_evidence"][0]
            return {"findings": [{"rule_id": "ARCH-CHECK", "title": "Review call path", "category": "architecture",
                "severity": "medium", "confidence": "low", "summary": "A bounded interpretation.",
                "recommendation": "Review the call path.", "evidence": [{"path": evidence["path"], "line_start": evidence["line"], "excerpt": evidence["text"]}]},
                {"rule_id": "FABRICATED", "title": "Fabricated", "category": "security", "severity": "high", "confidence": "medium",
                 "summary": "Not in evidence.", "recommendation": "Ignore.", "evidence": [{"path": "outside.py", "line_start": 1, "excerpt": "invented"}]}]}
        result = interpret_with_provider(self.result, self.root, provider, explicit_consent=True)
        added = [finding for finding in result.findings if finding.origin == "bounded_interpretation"]
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0].evidence[0].verification, "verified")

    def test_opt_in_packet_redacts_secrets_before_provider_call(self):
        (self.root / "app.py").write_text("API_TOKEN = 'secret-value-longer-than-twelve'\n", encoding="utf-8")
        result = analyze_repository(self.root)
        captured = []
        def provider(packet):
            captured.extend(packet["observed_evidence"])
            return {"findings": []}
        interpret_with_provider(result, self.root, provider, explicit_consent=True)
        self.assertTrue(captured)
        self.assertNotIn("secret-value-longer-than-twelve", str(captured))
        self.assertIn("<redacted>", str(captured))

    def test_synthetic_benchmark_is_reported_as_uncalibrated(self):
        report = run_benchmark()
        self.assertEqual(report["cases"], 10)
        self.assertGreaterEqual(report["precision"], .95)
        self.assertGreaterEqual(report["recall"], .95)
        self.assertFalse(report["calibrated"])


if __name__ == "__main__":
    unittest.main()
