"""Command line interface for local audit and artifact generation."""
import argparse
import json
import os
import sys
from pathlib import Path

from snowlint.core.engine import analyze_repository
from snowlint.core.models import AuditResult


def main(argv=None):
    parser = argparse.ArgumentParser(prog="snowlint", description="Local evidence-driven repository auditor")
    sub = parser.add_subparsers(dest="command", required=True)
    audit = sub.add_parser("audit", help="run a bounded static audit")
    audit.add_argument("repository", nargs="?", default=".")
    audit.add_argument("-o", "--output", default="snowlint-audit.json")
    audit.add_argument("--purpose")
    audit.add_argument("--audience")
    audit.add_argument("--scope", choices=["full", "performance", "security", "architecture", "testing", "ai_ml"])
    audit.add_argument("--llm-opt-in", action="store_true", help="explicitly allow sending a bounded, redacted evidence packet to the configured provider")
    audit.add_argument("--llm-endpoint", help="OpenAI-compatible chat completions URL; requires --llm-opt-in")
    audit.add_argument("--llm-model", help="provider model name; requires --llm-opt-in")
    audit.add_argument("--llm-api-key-env", default="SNOWLINT_LLM_API_KEY", help="environment variable containing optional provider key")
    diagrams = sub.add_parser("diagrams", help="write editable PlantUML source files")
    diagrams.add_argument("result"); diagrams.add_argument("-o", "--output-dir", default="snowlint-diagrams")
    report = sub.add_parser("report", help="write a DOCX report from an audit JSON")
    report.add_argument("result"); report.add_argument("-o", "--output", default="snowlint-report.docx")
    report.add_argument("--profile", choices=["technical", "academic"], default="technical")
    report.add_argument("--metadata-file", help="JSON metadata for academic identity fields")
    slides = sub.add_parser("slides", help="write an editable PPTX from audit JSON")
    slides.add_argument("result"); slides.add_argument("-o", "--output", default="snowlint-report.pptx")
    slides.add_argument("--theme", choices=["midnight", "paper", "violet"], default="midnight")
    slides.add_argument("--slide-count", type=int, default=8)
    slides.add_argument("--include", nargs="+", choices=["summary", "findings", "coverage", "architecture"], default=None)
    dashboard = sub.add_parser("dashboard", help="serve the local audit dashboard")
    dashboard.add_argument("result", nargs="?", help="existing canonical audit JSON; omit to run from dashboard")
    dashboard.add_argument("--host", default="127.0.0.1"); dashboard.add_argument("--port", type=int, default=8765)
    benchmark = sub.add_parser("benchmark", help="evaluate deterministic rules against labeled synthetic fixtures")
    benchmark.add_argument("-o", "--output", default="snowlint-benchmark.json")
    args = parser.parse_args(argv)
    if args.command == "benchmark":
        from snowlint.benchmark import run_benchmark
        payload = run_benchmark()
        Path(args.output).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote {args.output}: precision={payload['precision']} recall={payload['recall']} (synthetic, not calibrated)")
        return 0
    if args.command == "audit":
        purpose, audience, scope = args.purpose, args.audience, args.scope
        if sys.stdin.isatty() and (purpose is None or audience is None or scope is None):
            purpose = purpose if purpose is not None else input("What does this system do? ").strip()
            audience = audience if audience is not None else input("Who is it for, and what is its maturity? ").strip()
            scope = scope if scope is not None else input("Audit focus [full/security/architecture/testing/performance/ai_ml]: ").strip() or "full"
        result = analyze_repository(args.repository, system_purpose=purpose or "", intended_audience=audience or "", audit_scope=scope or "full")
        if args.llm_endpoint or args.llm_model:
            if not args.llm_opt_in:
                parser.error("--llm-endpoint/--llm-model require --llm-opt-in")
            if not args.llm_endpoint or not args.llm_model:
                parser.error("both --llm-endpoint and --llm-model are required for interpretation")
        if args.llm_opt_in:
            if not args.llm_endpoint or not args.llm_model:
                parser.error("--llm-opt-in requires --llm-endpoint and --llm-model")
            from snowlint.core.interpretation import interpret_with_provider, openai_compatible_provider
            provider = openai_compatible_provider(args.llm_endpoint, args.llm_model, os.environ.get(args.llm_api_key_env))
            result = interpret_with_provider(result, args.repository, provider, explicit_consent=True)
        Path(args.output).write_text(result.to_json()+"\n", encoding="utf-8")
        print(f"Wrote {args.output}: {len(result.findings)} findings; {result.coverage.files_read} files read")
        return 0
    result = None
    if args.command != "dashboard" or args.result:
        data = json.loads(Path(args.result).read_text(encoding="utf-8")); result = AuditResult.from_dict(data)
    if args.command == "diagrams":
        from snowlint.diagrams import write_diagrams
        print(json.dumps(write_diagrams(result, args.output_dir), indent=2))
    elif args.command == "report":
        from snowlint.exports import write_docx, write_pdf
        metadata = json.loads(Path(args.metadata_file).read_text(encoding="utf-8")) if args.metadata_file else None
        if Path(args.output).suffix.lower() == ".pdf": write_pdf(result, args.output, args.profile, metadata=metadata)
        else: write_docx(result, args.output, args.profile, metadata=metadata)
        print(f"Wrote {args.output}")
    elif args.command == "slides":
        from snowlint.exports import write_pptx
        write_pptx(result, args.output, theme=args.theme, slide_count=args.slide_count, include=args.include); print(f"Wrote {args.output}")
    elif args.command == "dashboard":
        from snowlint.dashboard import serve
        serve(result, args.host, args.port)
    return 0


if __name__ == "__main__": raise SystemExit(main())
