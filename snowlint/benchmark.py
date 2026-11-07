"""Small deterministic rule benchmark; intentionally not a product quality calibration set."""
from __future__ import annotations

import tempfile
from pathlib import Path

from snowlint.core.engine import analyze_repository


CASES = (
    ("python_eval", {"PY-DYNAMIC-EVAL"}, {"app.py": "result = eval(source)\n"}),
    ("python_safe_eval_text", set(), {"app.py": "# eval(source) is intentionally avoided\nprint('safe')\n"}),
    ("python_leakage_order", {"ML-PREPROCESSING-BEFORE-SPLIT"}, {"train.py": "x = scaler.fit_transform(data)\ntrain_test_split(x, y)\n"}),
    ("python_split_first", set(), {"train.py": "x_train, x_test = train_test_split(data)\nx = scaler.fit_transform(x_train)\n"}),
    ("python_model_output_sink", {"AI-OUTPUT-DYNAMIC-SINK", "PY-DYNAMIC-EVAL"}, {"ai.py": "output = client.generate(prompt)\neval(output)\n"}),
    ("python_model_output_display", set(), {"ai.py": "output = client.generate(prompt)\nprint(output)\n"}),
    ("javascript_eval", {"JS-DYNAMIC-EVAL"}, {"app.js": "function run(source) {\n  return eval(source);\n}\n"}),
    ("javascript_eval_comment", set(), {"app.js": "// eval(source) must never run\nconsole.log('ok')\n"}),
    ("typescript_secret", {"GEN-HARDCODED-CREDENTIAL"}, {"config.ts": "const API_TOKEN = 'literal-secret-value-123';\n"}),
    ("typescript_placeholder", set(), {"config.ts": "const API_TOKEN = 'your-token-here';\n"}),
)


def run_benchmark():
    """Evaluate exact rule identifiers on labeled synthetic fixtures."""
    tp = fp = fn = 0
    detail = []
    for name, expected, files in CASES:
        with tempfile.TemporaryDirectory(prefix="snowlint-bench-") as directory:
            root = Path(directory)
            for filename, content in files.items():
                path = root / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            observed = {finding.rule_id for finding in analyze_repository(root).findings}
        case_tp = len(expected & observed); case_fp = len(observed - expected); case_fn = len(expected - observed)
        tp += case_tp; fp += case_fp; fn += case_fn
        detail.append({"case": name, "expected": sorted(expected), "observed": sorted(observed),
                       "true_positive": case_tp, "false_positive": case_fp, "false_negative": case_fn})
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    return {"benchmark_version": "synthetic-v1", "cases": len(CASES), "true_positive": tp,
            "false_positive": fp, "false_negative": fn, "precision": precision, "recall": recall,
            "calibrated": False,
            "limitations": ["Synthetic fixtures exercise narrow patterns, not real-world prevalence or semantic correctness.",
                            "Do not use these metrics to calibrate quality scores or make release claims.",
                            "Calibration requires diverse labeled repositories, independent review, and language/framework-stratified evaluation."],
            "details": detail}
