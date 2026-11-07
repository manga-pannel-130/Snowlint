# Snowlint

<div align="center">

```
  ____                      _ _       _   
 / ___| _ __   _____      _| (_)_ __ | |_ 
 \___ \| '_ \ / _ \ \ /\ / / | | '_ \| __|
  ___) | | | | (_) \ V  V /| | | | | | |_ 
 |____/|_| |_|\___/ \_/\_/ |_|_|_| |_|\__|
```

**Local, Evidence-Driven Static Codebase & AI/ML Pipeline Auditor**

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-76%20passed-brightgreen.svg)]()
[![Privacy](https://img.shields.io/badge/network-100%25%20offline-success.svg)]()
[![Loopback](https://img.shields.io/badge/dashboard-loopback%20only-blueviolet.svg)]()

</div>

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Security & Privacy Guarantees](#security--privacy-guarantees)
- [Architecture & Dataflow](#architecture--dataflow)
- [Release Gates & Production Readiness (V1)](#release-gates--production-readiness-v1)
- [Supported Rules Catalogue](#supported-rules-catalogue)
- [Installation](#installation)
  - [Arch Linux / Omarchy](#arch-linux--omarchy)
  - [Ubuntu / Debian](#ubuntu--debian)
  - [macOS](#macos)
  - [Windows (PowerShell)](#windows-powershell)
- [Usage Guide](#usage-guide)
  - [CLI Auditing](#cli-auditing)
  - [Local Web Dashboard Studio](#local-web-dashboard-studio)
  - [Diagram Generation (PlantUML & SVG)](#diagram-generation-plantuml--svg)
  - [Report Exports (DOCX & PDF)](#report-exports-docx--pdf)
  - [Presentation Decks (Themed PPTX)](#presentation-decks-themed-pptx)
  - [Deterministic Benchmarking](#deterministic-benchmarking)
  - [Opt-in Bounded LLM Interpretation](#opt-in-bounded-llm-interpretation)
- [Scoring Methodology](#scoring-methodology)
- [Known Limitations & Non-Goals](#known-limitations--non-goals)
- [Verification & Testing](#verification--testing)

---

## Overview

**Snowlint** is a production-grade, local-only repository analysis system designed to audit complex codebases, microservice architectures, and modern AI/ML inference pipelines without executing target code or transmitting source code over external networks.

Unlike traditional heuristic linters or opaque cloud analyzers, Snowlint strictly adheres to an **evidence-driven contract**:
1. **Zero Execution**: Target code is never built, imported, or executed.
2. **Deterministic Evidence**: Every finding must cite verified file paths, exact line numbers, and authentic code excerpts.
3. **Loopback & Offline**: Default operation performs zero network calls. The interactive dashboard binds strictly to loopback interfaces (`127.0.0.1`).
4. **Canonical Shared Model**: A single versioned schema powers the CLI, web dashboard, PlantUML diagrams, standalone SVGs, technical Word documents, academic IEEE-style project reports, and editable PowerPoint presentations.

---

## Key Features

- **Multi-Language Intelligence**: Native AST structural extraction for Python; position-preserving lexer and AST-construct analysis for JavaScript and TypeScript (interfaces, types, enums, class inheritance, destructured imports, and Express/Next.js routes).
- **Architecture & Workflow Reconstruction**: Reconstructs class hierarchies (`inherits`, `implements`), local and cross-file function calls (`calls_function`), HTTP route declarations, frontend-to-backend API linkages, and ML training/inference pipelines (`workflow:ml-pipeline`).
- **AI/ML & Engineering Audit Engine**: Detects dangerous deserialization (`pickle`, `torch.load`), data leakage across validation splits (`ML-PREPROCESSING-BEFORE-SPLIT`), non-reproducible stochastic estimators (`ML-MISSING-RANDOM-SEED`), SQL injections, debug flag leaks, permissive CORS configurations, and prompt injection vectors.
- **Interactive Dark-Mode Dashboard**: Immersive, glassmorphism web studio equipped with live finding search, severity filters, architecture graph inspector, dependency matrix, and a one-click export center.
- **Enterprise & Academic Artifact Generation**:
  - Four UML 2.5 diagrams (Class, Sequence, Component, Deployment) in PlantUML and self-contained vector SVGs.
  - Technical Audit Reports (DOCX and PDF) for engineering teams.
  - Academic 8-Chapter Project Reports (DOCX and PDF) with IEEE front matter, Bonafide Certificate, Abstract, and Table of Contents.
  - Editable presentation decks (PPTX) styled with `midnight`, `paper`, or `violet` palettes.

---

## Security & Privacy Guarantees

Snowlint is built from the ground up with defensive security principles:

| Defense Boundary | Mechanism | Guarantee |
| :--- | :--- | :--- |
| **Symlink Protection** | `os.open` with `O_NOFOLLOW` and directory file descriptors (`dir_fd`) | Prevents symlink traversal, TOCTOU races, and escaping the repository root. |
| **Path Traversal Protection** | PurePosixPath validation + components verification | Rejects absolute paths, Windows backslash traversals (`..\`), and parent escapes (`..`). |
| **Sensitive File Shield** | Path-level pattern matching (`config.py`) | `.env*`, private keys (`id_rsa`, `*.pem`, `*.key`), keystores (`*.pfx`, `*.jks`), and credential files are inventoried but **strictly blocked from content reads**. |
| **Secret Excerpt Redaction** | Regex redaction engine (`_redact_secret_excerpt`) | Any accidental API keys, tokens, or passwords observed in code are redacted before entering reports, JSON, or LLM packets. |
| **Network Egress Guard** | Air-gapped standard library | No telemetry, no phone-home, no automatic updates. External LLM transport requires explicit `--llm-opt-in` and user-provided endpoints. |
| **Dashboard Isolation** | Strict host & Origin header validation | Web server binds only to loopback (`127.0.0.1`, `localhost`, `::1`). Cross-origin POST requests from malicious web pages are rejected with HTTP 403. |
| **DoS & Exhaustion Limits** | Capped file sizes (`DEFAULT_MAX_FILE_SIZE = 5MB`) and payload limits (64KB HTTP POST) | Prevents memory exhaustion when encountering large binary artifacts or malicious repositories. |

---

## Architecture & Dataflow

```
               [ Target Codebase ]
                        │
             ( Scanner & Inventory )
          ┌─────────────┴─────────────┐
          ▼                           ▼
  [ Safe Content Reader ]     [ Sensitive Policy ]
   ( O_NOFOLLOW / dir_fd )    ( Shield .env / keys )
          │
          ▼
   ( Language Engine )
   ├── Python AST Parser (Classes, Bases, Imports, Calls)
   └── JS/TS Token Lexer (Interfaces, Types, Heritage, Routers)
          │
          ▼
  ( Relationship & Workflow Reconstructor )
   ├── Observed Relationships (Local/Cross-file calls, imports, inherits)
   ├── Inferred API Routes (Frontend fetch -> Backend routes)
   └── ML/Dataflow Pipelines (Splits, Preprocessing, Inference)
          │
          ▼
   ( Evidence Verifier & Calibrator )
          │
          ▼
┌────────────────────────────────────────────────────────┐
│             Canonical Audit Result (JSON)              │
│       Shared schema across all output adapters         │
└────────────────────────────────────────────────────────┘
     │            │             │            │           │
     ▼            ▼             ▼            ▼           ▼
[ CLI Tool ]  [ Web UI ]  [ PlantUML ]  [ Reports ]  [ Slides ]
               (Dashboard)   & SVGs     (DOCX / PDF)   (PPTX)
```

---

## Release Gates & Production Readiness (V1)

| Gate | Requirement | Status | Verification |
| :--- | :--- | :---: | :--- |
| **1. Language Intelligence** | Python AST, JS/TS parsing, cross-file symbol and call resolution, class inheritance, and interfaces. | **PASSED** | Validated via `tests/test_rules_and_language.py` and `tests/test_snowlint_core.py`. |
| **2. Architecture Reconstruction** | Components, dependencies, API relationships, and observed vs. inferred workflow links. | **PASSED** | Evidence-backed relationships, routes, and `workflow:model-retrieval` / `workflow:frontend-backend`. |
| **3. Engineering & AI/ML Audit** | Comprehensive deterministic rules with positive/negative tests, exact line numbers, and verified evidence. | **PASSED** | 100% positive/negative test coverage across all rules in `tests/test_rules_and_language.py`. |
| **4. LLM Reliability & Privacy** | External transmission strictly opt-in, payload secret redaction, exact evidence citation, timeout, and failure testing. | **PASSED** | Verified in `tests/test_interpretation.py`. |
| **5. Scoring Validity** | Defensible scoring formula, explicit unknown dimension tracking, coverage scaling, and benchmark test. | **PASSED** | Benchmark test passes with precision and recall reported in `snowlint benchmark`. |
| **6. Artifact Correctness** | Valid PlantUML, SVG render, Technical DOCX/PDF, Academic 8-chapter DOCX/PDF, and editable 3-theme PPTX. | **PASSED** | Verified in `tests/test_exports.py` and visual export tests. |
| **7. Security & Reliability** | Path traversal, symlink loops, resource caps, malformed files, and corrupted manifests handling. | **PASSED** | Comprehensive attack and edge-case suite in `tests/test_security_and_limits.py`. |
| **8. Release Verification** | Clean packaging (`pyproject.toml`), CLI and loopback dashboard integration tests. | **PASSED** | 76 automated tests passing in under 3 seconds. |

---

## Supported Rules Catalogue

| Rule ID | Category | Severity | Confidence | Description | Remediation |
| :--- | :--- | :---: | :---: | :--- | :--- |
| `PY-SQL-INJECTION-RISK` | `security` | **CRITICAL** | High | SQL query constructed using f-strings, `%` formatting, or `.format()` rather than parameters. | Use parameterized queries (e.g. `cursor.execute('SELECT ... WHERE id = %s', (id,))`). |
| `PY-DYNAMIC-EVAL` | `security` | **HIGH** | Medium | Direct call to `eval()` on dynamic or untrusted expressions. | Remove `eval()` or constrain to a restricted AST expression grammar. |
| `PY-DYNAMIC-EXEC` | `security` | **HIGH** | Medium | Dynamic execution of arbitrary code strings via `exec()`. | Refactor dynamic logic into statically defined functions or lookup tables. |
| `PY-UNSAFE-YAML-LOAD` | `security` | **HIGH** | Medium | Use of `yaml.load()` without specifying `SafeLoader`. | Replace with `yaml.safe_load()` or explicitly pass `Loader=yaml.SafeLoader`. |
| `PY-SUBPROCESS-SHELL` | `security` | **HIGH** | Medium | `subprocess.run/Popen/call` executed with `shell=True`. | Pass argument lists (`shell=False`) and sanitize all inputs. |
| `PY-UNTRUSTED-PICKLE` | `security` | **HIGH** | Medium | Deserialization of unverified data streams using `pickle.load/loads`. | Avoid pickle for untrusted data; migrate to JSON, Safetensors, or Protobuf. |
| `ENG-DEBUG-FLAG-ENABLED` | `security` | **HIGH** | High | Hardcoded `DEBUG = True` assignment or `app.run(debug=True)`. | Disable debug mode in production; source flags from verified environment variables. |
| `ENG-PERMISSIVE-CORS` | `security` | **HIGH** | Medium | CORS configured with wildcard origin (`allow_origins=['*']`). | Restrict CORS to an explicit list of trusted application domains. |
| `PY-HARDCODED-CREDENTIAL` | `security` | **HIGH** | Low | Variable named key/token/secret assigned a suspicious long literal string. | Move sensitive credentials to secure secret stores or environment variables. |
| `ML-TORCH-UNSAFE-LOAD` | `ai_ml` | **HIGH** | Medium | `torch.load()` invoked with `weights_only=False`. | Set `weights_only=True` to prevent arbitrary code execution during deserialization. |
| `ML-PREPROCESSING-BEFORE-SPLIT` | `ai_ml` | **HIGH** | Low | Feature scaler or encoder fitted (`fit_transform`) before `train_test_split`. | Split dataset first; fit transformers on training split only to avoid data leakage. |
| `AI-OUTPUT-DYNAMIC-SINK` | `ai_ml` | **HIGH** | Low | LLM completion output passed into a dynamic sink (`eval`, `exec`, `os.system`). | Treat LLM output as untrusted; validate against strict schemas and avoid code sinks. |
| `AI-HARDCODED-PROMPT-INJECTION-RISK` | `ai_ml` | **HIGH** | Medium | Unsanitized f-string interpolated directly into model prompt or messages. | Use delimiter tags, input sanitization, or structured system prompts. |
| `ML-MISSING-RANDOM-SEED` | `ai_ml` | **MEDIUM** | Medium | Stochastic estimator (`RandomForestClassifier`, `KMeans`) initialized without `random_state`. | Pass `random_state=<int>` to ensure deterministic, reproducible training runs. |
| `JS-DYNAMIC-EVAL` | `security` | **HIGH** | Medium | Use of `eval()` in JavaScript / TypeScript source. | Avoid `eval()`; use native JSON parsing or structured handlers. |
| `JS-SHELL-EXEC` | `security` | **HIGH** | Medium | Child process execution with `shell: true` enabled in Node.js. | Disable shell execution and pass validated arguments separately. |
| `JS-INSECURE-HTTP-ENDPOINT` | `security` | **MEDIUM** | High | Client network request (`fetch`, `axios`) to unencrypted `http://` URL. | Migrate to encrypted `https://` endpoints to prevent man-in-the-middle attacks. |
| `GEN-HARDCODED-CREDENTIAL` | `security` | **HIGH** | Low | Regex detection of hardcoded credential token assignments. | Verify and rotate exposed secrets; load from secure runtime configuration. |

---

## Installation

Snowlint requires **Python 3.11** or newer. It is recommended to install inside a dedicated virtual environment.

### Arch Linux / Omarchy

```sh
sudo pacman -S --needed python python-pip
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
```

*Using `uv`:*
```sh
uv venv --python 3.11 .venv
uv pip install --python .venv/bin/python -e .
source .venv/bin/activate
```

### Ubuntu / Debian

```sh
sudo apt update
sudo apt install python3 python3-pip python3-venv
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
```

### macOS

```sh
brew install python
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
```

### Windows (PowerShell)

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

---

## Usage Guide

### CLI Auditing

Run a deterministic audit on any repository:

```sh
# Full comprehensive audit
snowlint audit /path/to/project --purpose "Next.js & FastAPI Microservices" --audience "Engineers" --scope full -o audit.json

# Scoped audit focusing on security & sensitive files
snowlint audit /path/to/project --scope security -o security-audit.json

# Scoped audit focusing on AI/ML pipelines
snowlint audit /path/to/project --scope ai_ml -o ml-audit.json
```

### Local Web Dashboard Studio

Launch the immersive local web studio:

```sh
# Start server with existing audit
snowlint dashboard audit.json --port 8765

# Or start empty to audit repositories interactively
snowlint dashboard --port 8765
```

Open your browser at `http://127.0.0.1:8765`. The studio provides:
- Executive signal score and severity breakdowns.
- Real-time search and severity filters for all detected findings.
- Architecture and reconstructed workflow traces.
- Complete dependency inventory and protected sensitive file logs.
- One-click document and presentation exporter.

### Diagram Generation (PlantUML & SVG)

Export Class, Sequence, Component, and Deployment diagrams:

```sh
snowlint diagrams audit.json -o ./diagrams
```

Outputs:
- `class.puml` and `class.svg`
- `sequence.puml` and `sequence.svg`
- `component.puml` and `component.svg`
- `deployment.puml` and `deployment.svg`

### Report Exports (DOCX & PDF)

```sh
# Technical Engineering Audit Report (DOCX)
snowlint report audit.json --profile technical -o technical-audit.docx

# Technical Engineering Audit Report (PDF)
snowlint report audit.json --profile technical -o technical-audit.pdf

# Academic 8-Chapter IEEE-style Report (DOCX)
snowlint report audit.json --profile academic -o academic-report.docx

# Academic 8-Chapter Report (PDF)
snowlint report audit.json --profile academic -o academic-report.pdf
```

### Presentation Decks (Themed PPTX)

Generate fully editable Microsoft PowerPoint presentations:

```sh
# Dark tech theme (Midnight)
snowlint slides audit.json --theme midnight --slide-count 8 -o deck.pptx

# Clean paper theme (Paper)
snowlint slides audit.json --theme paper --slide-count 10 -o paper-deck.pptx

# Neon purple theme (Violet)
snowlint slides audit.json --theme violet --slide-count 6 -o violet-deck.pptx
```

### Deterministic Benchmarking

Validate rule precision and recall against labeled synthetic fixtures:

```sh
snowlint benchmark -o benchmark-results.json
```

### Opt-in Bounded LLM Interpretation

Snowlint includes an optional adapter for bounded LLM interpretation over an OpenAI-compatible endpoint. Source code is never sent; only a capped, redacted evidence packet is transmitted:

```sh
export SNOWLINT_LLM_API_KEY="your-api-key"

snowlint audit /path/to/project \
  --llm-opt-in \
  --llm-endpoint https://api.openai.com/v1/chat/completions \
  --llm-model gpt-4o-mini \
  -o llm-enhanced-audit.json
```

---

## Scoring Methodology

Snowlint's scoring philosophy is intentionally **defensible and conservative**:

1. **Available Signal**: Computes a score based strictly on executed, evidence-backed rules:
   $$\text{Score} = \max\left(0, 100 - \sum \text{penalties}\right) \times \text{Coverage Rate}$$
   - Penalties: Critical (-35), High (-18), Medium (-8), Low (-3).
   - Critical Gate: If any confirmed Critical defect exists, the overall signal is capped at **20/100**.
2. **Broad Audits**: For a `full` audit scope, the `overall` score is documented as **unknown** because unanalyzed dimensions (dynamic runtime performance, automated test execution, hardware metrics) are not falsely marked as passed.
3. **Category-Scoped Scores**: For focused audits (e.g. `--scope security` or `--scope ai_ml`), category-specific scores are published alongside coverage percentages.

---

## Known Limitations & Non-Goals

- **Static Only**: Snowlint does not execute tests or benchmark runtime latency, memory, or throughput.
- **Dynamic Typing & Metaprogramming**: Dynamic Python constructs (e.g., `getattr()`, runtime monkeypatching) cannot be statically resolved.
- **JavaScript/TypeScript Lexical Scope**: JS/TS analysis is lexical and position-preserving; it does not invoke the full TypeScript compiler type checker or resolve ambient `.d.ts` declaration packages.
- **Literature & External Validation**: Academic reports mark unsupplied references and external literature surveys as missing rather than synthesizing unverified facts.

---

## Verification & Testing

Snowlint includes a comprehensive automated test suite verifying file readers, policy barriers, language AST extractors, rule detectors, dashboard loopback endpoints, and document generators:

```sh
# Run entire test suite
pytest -v

# Run with loopback HTTP dashboard tests enabled
SNOWLINT_TEST_HTTP=1 pytest -v
```

All 76+ tests run in ~2.8 seconds on standard hardware.
