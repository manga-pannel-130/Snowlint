import json
import tempfile
import unittest
from pathlib import Path

from snowlint.core.engine import analyze_repository


class RulesAndLanguageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def put(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    # Rule: PY-SQL-INJECTION-RISK
    def test_sql_injection_positive_fstring(self):
        self.put("db.py", "cursor.execute(f'SELECT * FROM users WHERE name = {user_input}')\n")
        result = analyze_repository(self.root)
        self.assertIn("PY-SQL-INJECTION-RISK", [f.rule_id for f in result.findings])

    def test_sql_injection_positive_modulo(self):
        self.put("db.py", "cursor.execute('SELECT * FROM users WHERE id = %s' % user_id)\n")
        result = analyze_repository(self.root)
        self.assertIn("PY-SQL-INJECTION-RISK", [f.rule_id for f in result.findings])

    def test_sql_injection_negative_parameterized(self):
        self.put("db.py", "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n")
        result = analyze_repository(self.root)
        self.assertNotIn("PY-SQL-INJECTION-RISK", [f.rule_id for f in result.findings])

    # Rule: ENG-DEBUG-FLAG-ENABLED
    def test_debug_mode_positive_assignment(self):
        self.put("settings.py", "DEBUG = True\n")
        result = analyze_repository(self.root)
        self.assertIn("ENG-DEBUG-FLAG-ENABLED", [f.rule_id for f in result.findings])

    def test_debug_mode_positive_app_run(self):
        self.put("server.py", "app.run(host='0.0.0.0', debug=True)\n")
        result = analyze_repository(self.root)
        self.assertIn("ENG-DEBUG-FLAG-ENABLED", [f.rule_id for f in result.findings])

    def test_debug_mode_negative(self):
        self.put("settings.py", "DEBUG = False\napp.run(debug=False)\n")
        result = analyze_repository(self.root)
        self.assertNotIn("ENG-DEBUG-FLAG-ENABLED", [f.rule_id for f in result.findings])

    # Rule: ENG-PERMISSIVE-CORS
    def test_permissive_cors_positive(self):
        self.put("main.py", "app.add_middleware(CORSMiddleware, allow_origins=['*'])\n")
        result = analyze_repository(self.root)
        self.assertIn("ENG-PERMISSIVE-CORS", [f.rule_id for f in result.findings])

    def test_permissive_cors_negative(self):
        self.put("main.py", "app.add_middleware(CORSMiddleware, allow_origins=['https://app.example.com'])\n")
        result = analyze_repository(self.root)
        self.assertNotIn("ENG-PERMISSIVE-CORS", [f.rule_id for f in result.findings])

    # Rule: ML-MISSING-RANDOM-SEED
    def test_ml_random_seed_positive(self):
        self.put("model.py", "model = RandomForestClassifier(n_estimators=100)\n")
        result = analyze_repository(self.root)
        self.assertIn("ML-MISSING-RANDOM-SEED", [f.rule_id for f in result.findings])

    def test_ml_random_seed_negative(self):
        self.put("model.py", "model = RandomForestClassifier(n_estimators=100, random_state=42)\n")
        result = analyze_repository(self.root)
        self.assertNotIn("ML-MISSING-RANDOM-SEED", [f.rule_id for f in result.findings])

    # Rule: AI-HARDCODED-PROMPT-INJECTION-RISK
    def test_prompt_injection_risk_positive(self):
        self.put("agent.py", "client.chat.completions.create(model='gpt-4', messages=[{'role': 'user', 'content': f'Translate: {user_text}'}])\n")
        result = analyze_repository(self.root)
        self.assertIn("AI-HARDCODED-PROMPT-INJECTION-RISK", [f.rule_id for f in result.findings])

    def test_prompt_injection_risk_negative(self):
        self.put("agent.py", "client.chat.completions.create(model='gpt-4', messages=[{'role': 'user', 'content': static_prompt}])\n")
        result = analyze_repository(self.root)
        self.assertNotIn("AI-HARDCODED-PROMPT-INJECTION-RISK", [f.rule_id for f in result.findings])

    # Rule: JS-INSECURE-HTTP-ENDPOINT
    def test_js_insecure_http_positive(self):
        self.put("client.ts", "fetch('http://external-api.com/v1/records');\n")
        result = analyze_repository(self.root)
        self.assertIn("JS-INSECURE-HTTP-ENDPOINT", [f.rule_id for f in result.findings])

    def test_js_insecure_http_negative_https_or_localhost(self):
        self.put("client.ts", "fetch('https://external-api.com/v1/records');\nfetch('http://localhost:8080/test');\n")
        result = analyze_repository(self.root)
        self.assertNotIn("JS-INSECURE-HTTP-ENDPOINT", [f.rule_id for f in result.findings])

    # Python cross-file symbol call and inheritance resolution
    def test_python_cross_file_call_and_inheritance(self):
        self.put("utils.py", "def compute_hash(val):\n    return hash(val)\n")
        self.put("app.py", """from utils import compute_hash

class BaseService:
    def execute(self):
        pass

class UserService(BaseService):
    def run(self, val):
        return compute_hash(val)
""")
        result = analyze_repository(self.root)
        rel_kinds = {(r.source, r.target, r.kind) for r in result.relationships}
        # Check inheritance
        self.assertTrue(any(r[2] == "inherits" and "BaseService" in r[1] for r in rel_kinds))
        # Check cross-file call
        self.assertTrue(any(r[2] == "calls_function" and "compute_hash" in r[1] for r in rel_kinds))

    # TypeScript interfaces, types, and heritage resolution
    def test_typescript_symbols_and_heritage(self):
        self.put("types.ts", """interface UserPayload {
    id: string;
    email: string;
}
type Status = string;
enum Role { Admin, Member }
class Animal {}
class Dog extends Animal implements UserPayload {}
""")
        result = analyze_repository(self.root)
        node_names = {n.name: n.kind for n in result.nodes}
        self.assertEqual(node_names.get("UserPayload"), "interface")
        self.assertEqual(node_names.get("Status"), "type")
        self.assertEqual(node_names.get("Role"), "enum")
        self.assertEqual(node_names.get("Dog"), "class")
        # Check inheritance & interface implementation
        rel_kinds = {(r.kind, r.target) for r in result.relationships}
        self.assertIn(("inherits", "symbol:Animal"), rel_kinds)
        self.assertIn(("implements", "symbol:UserPayload"), rel_kinds)

    # TypeScript cross-file function calls via destructured import
    def test_typescript_cross_file_destructured_calls(self):
        self.put("api.ts", "export function sendReport(data: any) { return true; }\n")
        self.put("index.ts", """import { sendReport } from './api';
function main() {
    sendReport({ ok: true });
}
""")
        result = analyze_repository(self.root)
        rel_kinds = {(r.kind, r.source, r.target) for r in result.relationships}
        self.assertTrue(any(r[0] == "calls_function" and "sendReport" in r[2] for r in rel_kinds))


if __name__ == "__main__":
    unittest.main()
