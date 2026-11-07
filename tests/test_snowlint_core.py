import json
import tempfile
import unittest
from pathlib import Path

from snowlint.core.engine import analyze_repository
from snowlint.core.models import AuditResult, Evidence
from snowlint.diagrams import plantuml, write_diagrams


class CoreAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def put(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def test_ast_structure_routes_imports_and_security_evidence(self):
        self.put("app.py", "from service import run\n\nclass Api:\n    token: str\n    def get(self):\n        return eval(input())\n")
        self.put("service.py", "def run():\n    return 1\n")
        result = analyze_repository(self.root)
        self.assertEqual([f.rule_id for f in result.findings], ["PY-DYNAMIC-EVAL"])
        finding = result.findings[0]
        self.assertEqual(finding.evidence[0].path, "app.py")
        self.assertEqual(finding.evidence[0].line_start, 6)
        self.assertTrue(any(n.name == "Api" and "get" in n.methods and "token" in n.attributes for n in result.nodes))
        self.assertTrue(any(r.target == "file:service.py" for r in result.relationships))

    def test_multiline_typescript_import_arrow_routes_and_calls(self):
        self.put("web.ts", """import {
  createClient
} from './client';
function normalize(value: string) { return value.trim(); }
export const loadData = async (url: string) => {
  normalize(url);
  return fetch(
    url
  );
};
router.post(
  '/api/items', handler
);
eval(
  source
);
""")
        self.put("client.ts", "export const client = 1;\n")
        result = analyze_repository(self.root)
        self.assertTrue(any(n.name == "loadData" and n.kind == "function" for n in result.nodes))
        self.assertTrue(any(r.target == "file:client.ts" for r in result.relationships))
        self.assertTrue(any(r.kind == "calls_function" for r in result.relationships))
        self.assertTrue(any(route.name == "POST /api/items" for route in result.nodes))
        self.assertIn("JS-DYNAMIC-EVAL", [f.rule_id for f in result.findings])

    def test_python_ai_security_rules_and_workflow_evidence(self):
        self.put("api.py", """def run_model(prompt):
    output = client.generate(prompt)
    return eval(output)
""")
        self.put("ml.py", """import torch
model = torch.load('model.pt', weights_only=False)
""")
        result = analyze_repository(self.root)
        rule_ids = {f.rule_id for f in result.findings}
        self.assertIn("AI-OUTPUT-DYNAMIC-SINK", rule_ids)
        self.assertIn("ML-TORCH-UNSAFE-LOAD", rule_ids)
        self.assertTrue(any(w.name == "Model and retrieval integration sites" for w in result.workflows))

    def test_manifest_versions_are_canonical_data(self):
        self.put("package.json", json.dumps({"dependencies": {"react": "^18.2.0"}, "devDependencies": {"vite": "~5.0"}}))
        result = analyze_repository(self.root)
        deps = result.dependencies["package.json"]
        self.assertEqual({d["name"] for d in deps}, {"react", "vite"})
        self.assertTrue(all(d["constraint"] for d in deps))
        restored = AuditResult.from_dict(json.loads(result.to_json()))
        self.assertEqual(restored.dependencies, result.dependencies)

    def test_scope_filters_findings_and_broad_score_stays_unknown(self):
        self.put("app.py", "eval(value)\n")
        full = analyze_repository(self.root)
        security = analyze_repository(self.root, audit_scope="security")
        architecture = analyze_repository(self.root, audit_scope="architecture")
        self.assertEqual(len(full.findings), 1)
        self.assertEqual(len(security.findings), 1)
        self.assertEqual(architecture.findings, ())
        self.assertIsNone(full.scores["overall"])
        self.assertIsNone(architecture.scores["overall"])

    def test_sensitive_contents_are_not_read(self):
        self.put(".env", "TOKEN=should-never-be-read")
        self.put("app.py", "print('ok')")
        result = analyze_repository(self.root)
        self.assertEqual(result.coverage.files_protected, 1)
        self.assertFalse(any("should-never-be-read" in (e.excerpt or "") for f in result.findings for e in f.evidence))

    def test_python_parse_failure_does_not_count_as_analyzed(self):
        self.put("broken.py", "def broken(:\n    pass\n")
        result = analyze_repository(self.root)
        self.assertEqual(result.coverage.source_files_discovered, 1)
        self.assertEqual(result.coverage.source_files_analyzed, 0)
        self.assertIsNone(result.scores["overall"])
        self.assertTrue(any("syntax error" in note for note in result.coverage.limitations))

    def test_hard_coded_credential_finding_redacts_secret_value(self):
        self.put("app.py", "API_KEY = 'a-live-looking-value-123456'\n")
        result = analyze_repository(self.root)
        finding = next(f for f in result.findings if f.rule_id == "PY-HARDCODED-CREDENTIAL")
        self.assertIn("<redacted>", finding.evidence[0].excerpt)
        self.assertNotIn("a-live-looking-value-123456", result.to_json())

    def test_diagram_files_preserve_source_and_svg(self):
        self.put("app.py", "import json\n")
        result = analyze_repository(self.root)
        self.assertIn("module_json", plantuml(result, "component"))
        output = Path(self.temp.name) / "diagrams"
        written = write_diagrams(result, output)
        self.assertEqual(len(written), 8)
        self.assertIn("<svg", Path(written["component_svg"]).read_text(encoding="utf-8"))

    def test_evidence_paths_reject_windows_absolute_and_parent_paths(self):
        for value in ("../outside.py", "C:\\secrets.txt", "/etc/passwd"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                Evidence(value)


if __name__ == "__main__":
    unittest.main()
