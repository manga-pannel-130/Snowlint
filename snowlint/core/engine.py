"""Deterministic, local static analysis. Target code is never executed."""
from __future__ import annotations

import ast
from dataclasses import replace
import hashlib
import json
import re
import tomllib
from pathlib import Path

from content_reader import read_text_file
from repository_map import build_inventory
from snowlint.core.models import (
    AuditResult,
    Confidence,
    Coverage,
    Evidence,
    Finding,
    Node,
    Relationship,
    Severity,
    Workflow,
    now_utc,
)

SOURCE_EXTENSIONS = {
    ".py",
    ".pyw",
    ".pyi",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".mts",
    ".cts",
}
SCOPE_RULES = {
    "full": None,
    "security": {"security"},
    "performance": {"performance"},
    "architecture": {"architecture"},
    "testing": {"testing"},
    "ai_ml": {"ai_ml"},
}


def _finding(
    rule,
    path,
    line,
    title,
    category,
    severity,
    summary,
    recommendation,
    excerpt="",
    confidence=Confidence.MEDIUM,
):
    line = max(1, line)
    evidence = (Evidence(path, line, line, excerpt.strip()[:240] or None),)
    identity = hashlib.sha256(f"{rule}:{path}:{line}".encode()).hexdigest()[:12]
    return Finding(
        identity,
        rule,
        title,
        category,
        "evidence_backed_risk",
        severity,
        confidence,
        summary,
        recommendation,
        evidence,
    )


def _redact_secret_excerpt(text):
    return re.sub(
        r"(?i)(api[_-]?key|secret|password|token)(\s*[:=]\s*)(['\"])[^'\"]+\3",
        lambda m: m.group(1) + m.group(2) + m.group(3) + "<redacted>" + m.group(3),
        text,
    )


def _call_name(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts)) if parts else ""


def _parse_requirement(value, source):
    value = value.split(";", 1)[0].strip()
    if not value or value.startswith(("#", "-", "git+", "http://", "https://")):
        return None
    match = re.match(r"^([A-Za-z0-9_.-]+)\s*((?:===|==|~=|!=|<=|>=|<|>).*?)?$", value)
    if match:
        constraint = (match.group(2) or "").strip() or None
        return {
            "name": match.group(1),
            "version": None,
            "constraint": constraint,
            "source": source,
        }
    return {"name": value, "version": None, "constraint": "unparsed", "source": source}


def _manifest_dependencies(path, content):
    filename = Path(path).name.lower()
    result = []
    if filename == "pyproject.toml":
        try:
            data = tomllib.loads(content)
            project = data.get("project", {})
            requirements = list(project.get("dependencies", []))
            for group in project.get("optional-dependencies", {}).values():
                requirements.extend(group)
            for item in requirements:
                dep = _parse_requirement(item, path)
                if dep:
                    result.append(dep)
            poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
            for name, constraint in poetry.items():
                if name.lower() != "python":
                    result.append(
                        {
                            "name": name,
                            "version": None,
                            "constraint": str(constraint),
                            "source": path,
                        }
                    )
        except (tomllib.TOMLDecodeError, TypeError, AttributeError):
            return []
    elif filename.startswith("requirements") and filename.endswith(".txt"):
        for line in content.splitlines():
            dep = _parse_requirement(line, path)
            if dep:
                result.append(dep)
    elif filename == "package.json":
        try:
            data = json.loads(content)
            for group in (
                "dependencies",
                "devDependencies",
                "peerDependencies",
                "optionalDependencies",
            ):
                for name, version in data.get(group, {}).items():
                    result.append(
                        {
                            "name": name,
                            "version": None,
                            "constraint": str(version),
                            "source": path,
                            "group": group,
                        }
                    )
        except (ValueError, TypeError, AttributeError):
            return []
    elif filename == "package-lock.json":
        try:
            data = json.loads(content)
            for lock_path, package in data.get("packages", {}).items():
                if not lock_path.startswith("node_modules/") or not isinstance(
                    package, dict
                ):
                    continue
                name = lock_path.split("node_modules/")[-1]
                if package.get("version"):
                    result.append(
                        {
                            "name": name,
                            "version": str(package["version"]),
                            "constraint": None,
                            "source": path,
                            "resolved": package.get("resolved"),
                        }
                    )
        except (ValueError, TypeError, AttributeError):
            return []
    elif filename == "poetry.lock":
        try:
            data = tomllib.loads(content)
            for package in data.get("package", []):
                result.append(
                    {
                        "name": package["name"],
                        "version": (
                            str(package.get("version"))
                            if package.get("version")
                            else None
                        ),
                        "constraint": None,
                        "source": path,
                    }
                )
        except (tomllib.TOMLDecodeError, TypeError, AttributeError):
            return []
    elif filename == "uv.lock":
        try:
            data = tomllib.loads(content)
            for package in data.get("package", []):
                result.append(
                    {
                        "name": package["name"],
                        "version": (
                            str(package.get("version"))
                            if package.get("version")
                            else None
                        ),
                        "constraint": None,
                        "source": path,
                    }
                )
        except (tomllib.TOMLDecodeError, TypeError, AttributeError):
            return []
    return result


def _resolve_local_module(name, current, source_paths):
    raw = name
    if name.startswith("."):
        dots = len(name) - len(name.lstrip("."))
        base = Path(current).parent
        for _ in range(max(0, dots - 1)):
            base = base.parent
        candidate = (base / name[dots:].lstrip("/").replace(".", "/")).as_posix()
    else:
        candidate = name.replace(".", "/")
    variants = [candidate + ext for ext in sorted(SOURCE_EXTENSIONS)]
    variants.extend(
        [
            candidate + "/__init__.py",
            candidate + "/index.js",
            candidate + "/index.ts",
            candidate + "/index.tsx",
        ]
    )
    for variant in variants:
        if variant in source_paths:
            return "file:" + variant
    return "module:" + raw


def _literal_route(decorator):
    if (
        isinstance(decorator, ast.Call)
        and decorator.args
        and isinstance(decorator.args[0], ast.Constant)
        and isinstance(decorator.args[0].value, str)
    ):
        return decorator.args[0].value
    return None


def _python_analysis(
    path, content, source_paths, nodes, relationships, findings, routes
):
    try:
        tree = ast.parse(content, filename=path)
    except SyntaxError as e:
        return (
            f"Python syntax error in {path}:{e.lineno or '?'} prevented structural"
            " analysis."
        )
    module_id = "file:" + path
    local_functions = {
        n.name: n.lineno
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    imported_symbols = {}  # symbol_name -> (target_module_id, original_name)
    class_by_node = {}

    for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
        methods = tuple(
            x.name
            for x in cls.body
            if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef))
        )
        attrs = tuple(
            sorted(
                {
                    t.id
                    for x in cls.body
                    if isinstance(x, (ast.Assign, ast.AnnAssign))
                    for t in (x.targets if isinstance(x, ast.Assign) else [x.target])
                    if isinstance(t, ast.Name)
                }
            )
        )
        class_id = f"class:{path}:{cls.lineno}:{cls.name}"
        nodes.append(
            Node(class_id, cls.name, "class", path, attrs, methods, cls.lineno)
        )
        class_by_node[id(cls)] = class_id

        # Class inheritance relationships
        for base in cls.bases:
            base_name = _call_name(base)
            if base_name:
                relationships.append(
                    Relationship(
                        class_id,
                        f"class:{base_name}",
                        "inherits",
                        "observed",
                        (Evidence(path, cls.lineno),),
                    )
                )

    for item in ast.walk(tree):
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            kind = "class" if isinstance(item, ast.ClassDef) else "function"
            if kind != "class":
                nodes.append(
                    Node(
                        f"{kind}:{path}:{item.lineno}:{item.name}",
                        item.name,
                        kind,
                        path,
                        line_start=item.lineno,
                    )
                )
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name in {
                "main",
                "app",
                "create_app",
                "handler",
            }:
                nodes.append(
                    Node(f"entrypoint:{path}:{item.lineno}", item.name, "entrypoint", path)
                )
            for decorator in item.decorator_list:
                decorator_name = (
                    _call_name(decorator.func)
                    if isinstance(decorator, ast.Call)
                    else _call_name(decorator)
                )
                if any(
                    word in decorator_name.lower()
                    for word in ("route", "get", "post", "put", "delete", "patch")
                ):
                    routes.append(
                        (path, item.lineno, _literal_route(decorator) or item.name)
                    )

        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for parent in ast.walk(tree):
                if isinstance(parent, ast.ClassDef) and item in parent.body:
                    relationships.append(
                        Relationship(
                            class_by_node[id(parent)],
                            f"function:{path}:{item.lineno}:{item.name}",
                            "contains_method",
                            "observed",
                            (Evidence(path, item.lineno),),
                        )
                    )
                    break

        if isinstance(item, ast.Import):
            for alias in item.names:
                target = _resolve_local_module(alias.name, path, source_paths)
                relationships.append(
                    Relationship(
                        module_id,
                        target,
                        "imports",
                        "observed",
                        (Evidence(path, item.lineno),),
                    )
                )
                imported_symbols[alias.asname or alias.name] = (target, alias.name)
        elif isinstance(item, ast.ImportFrom):
            imported = "." * item.level + (item.module or "")
            target = _resolve_local_module(imported, path, source_paths)
            relationships.append(
                Relationship(
                    module_id,
                    target,
                    "imports",
                    "observed",
                    (Evidence(path, item.lineno),),
                )
            )
            for alias in item.names:
                imported_symbols[alias.asname or alias.name] = (target, alias.name)

        # Assignments (Hardcoded credentials & debug flag checks)
        if isinstance(item, (ast.Assign, ast.AnnAssign)):
            targets = item.targets if isinstance(item, ast.Assign) else [item.target]
            value = item.value
            # Debug flag enabled check
            if any(isinstance(t, ast.Name) and t.id == "DEBUG" for t in targets):
                if isinstance(value, ast.Constant) and value.value is True:
                    findings.append(
                        _finding(
                            "ENG-DEBUG-FLAG-ENABLED",
                            path,
                            item.lineno,
                            "Debug mode explicitly enabled in application code",
                            "security",
                            Severity.HIGH,
                            "The DEBUG configuration flag is set to True, which may expose diagnostic tools or stack traces.",
                            "Disable debug mode in production configurations and source environment variables.",
                            content.splitlines()[item.lineno - 1],
                            Confidence.HIGH,
                        )
                    )
            # Credential assignment check
            if (
                isinstance(value, ast.Constant)
                and isinstance(value.value, str)
                and len(value.value) >= 12
            ):
                if any(
                    isinstance(t, ast.Name)
                    and re.search(r"(?:api.?key|secret|password|token)", t.id, re.I)
                    for t in targets
                ):
                    if not re.search(
                        r"(?:example|placeholder|dummy|changeme|your[_ -])",
                        value.value,
                        re.I,
                    ):
                        findings.append(
                            _finding(
                                "PY-HARDCODED-CREDENTIAL",
                                path,
                                item.lineno,
                                "Possible hard-coded credential",
                                "security",
                                Severity.HIGH,
                                "A credential-named variable is assigned a long string literal; static analysis cannot confirm whether it is active.",
                                "Verify this is not a live credential; move secrets into protected configuration and rotate exposed values.",
                                _redact_secret_excerpt(
                                    content.splitlines()[item.lineno - 1]
                                ),
                                Confidence.LOW,
                            )
                        )

        if not isinstance(item, ast.Call):
            continue

        name = _call_name(item.func)
        excerpt = ast.get_source_segment(content, item) or name
        func_key = name.split(".")[-1]

        # Function call resolution (local or imported cross-file)
        if func_key in local_functions:
            relationships.append(
                Relationship(
                    module_id,
                    f"function:{path}:{local_functions[func_key]}:{func_key}",
                    "calls_function",
                    "observed",
                    (Evidence(path, item.lineno),),
                )
            )
        elif func_key in imported_symbols:
            target_mod, orig_name = imported_symbols[func_key]
            relationships.append(
                Relationship(
                    module_id,
                    f"{target_mod}:{orig_name}",
                    "calls_function",
                    "observed",
                    (Evidence(path, item.lineno),),
                )
            )

        # Dynamic Eval / Exec
        if name in {"eval", "builtins.eval"}:
            findings.append(
                _finding(
                    "PY-DYNAMIC-EVAL",
                    path,
                    item.lineno,
                    "Dynamic expression evaluation",
                    "security",
                    Severity.HIGH,
                    "The code evaluates a computed expression; input trust cannot be established statically.",
                    "Avoid eval or validate against a restricted expression grammar.",
                    excerpt,
                )
            )
        elif name in {"exec", "builtins.exec"}:
            findings.append(
                _finding(
                    "PY-DYNAMIC-EXEC",
                    path,
                    item.lineno,
                    "Dynamic code execution",
                    "security",
                    Severity.HIGH,
                    "The code executes a computed code object or string.",
                    "Remove dynamic execution or constrain it to trusted, validated code.",
                    excerpt,
                )
            )

        # SQL Injection Risk Detection
        elif (
            name.endswith(("execute", "executemany", "raw"))
            and item.args
            and any(
                term in name.lower()
                for term in ("cursor", "db", "session", "conn", "execute", "raw")
            )
        ):
            first_arg = item.args[0]
            is_sql_injection = False
            if isinstance(first_arg, ast.JoinedStr):
                is_sql_injection = True
            elif isinstance(first_arg, ast.BinOp) and isinstance(
                first_arg.op, (ast.Mod, ast.Add)
            ):
                is_sql_injection = True
            elif (
                isinstance(first_arg, ast.Call)
                and isinstance(first_arg.func, ast.Attribute)
                and first_arg.func.attr == "format"
            ):
                is_sql_injection = True
            if is_sql_injection:
                findings.append(
                    _finding(
                        "PY-SQL-INJECTION-RISK",
                        path,
                        item.lineno,
                        "SQL query uses string formatting instead of parameterized query",
                        "security",
                        Severity.CRITICAL,
                        "A database query is constructed dynamically via string interpolation or concatenation rather than safe parameter placeholders.",
                        "Use parameterized query bindings (e.g. cursor.execute('SELECT ... WHERE id = %s', (user_id,))) to eliminate SQL injection risks.",
                        excerpt,
                        Confidence.HIGH,
                    )
                )

        # Unsafe YAML
        elif name.endswith("yaml.load"):
            safe_loader = any(
                k.arg == "Loader"
                and isinstance(k.value, ast.Name)
                and k.value.id == "SafeLoader"
                for k in item.keywords
            )
            if not safe_loader:
                findings.append(
                    _finding(
                        "PY-UNSAFE-YAML-LOAD",
                        path,
                        item.lineno,
                        "YAML loading requires safety review",
                        "security",
                        Severity.HIGH,
                        "yaml.load has no evident SafeLoader argument.",
                        "Use yaml.safe_load or pass SafeLoader when parsing untrusted YAML.",
                        excerpt,
                    )
                )

        # Subprocess Shell
        elif name.endswith(("subprocess.run", "subprocess.Popen", "subprocess.call")):
            if any(
                k.arg == "shell"
                and isinstance(k.value, ast.Constant)
                and k.value.value is True
                for k in item.keywords
            ):
                findings.append(
                    _finding(
                        "PY-SUBPROCESS-SHELL",
                        path,
                        item.lineno,
                        "Subprocess shell mode enabled",
                        "security",
                        Severity.HIGH,
                        "Shell interpretation is enabled; impact depends on whether arguments contain untrusted input.",
                        "Prefer argument arrays with shell=False and validate externally sourced values.",
                        excerpt,
                    )
                )

        # App Debug Run
        elif name.endswith(("app.run", "run")) and any(
            k.arg == "debug"
            and isinstance(k.value, ast.Constant)
            and k.value.value is True
            for k in item.keywords
        ):
            findings.append(
                _finding(
                    "ENG-DEBUG-FLAG-ENABLED",
                    path,
                    item.lineno,
                    "Application execution runs with debug=True",
                    "security",
                    Severity.HIGH,
                    "The web application starts with debug mode explicitly enabled.",
                    "Ensure debug mode is disabled in production environments.",
                    excerpt,
                    Confidence.HIGH,
                )
            )

        # Insecure CORS
        elif any(
            word in name.lower()
            for word in ("cors", "corsmiddleware", "add_middleware")
        ) or any(
            isinstance(arg, ast.Name) and "cors" in arg.id.lower()
            for arg in item.args
        ):
            for k in item.keywords:
                if k.arg in {"allow_origins", "origins"}:
                    if isinstance(k.value, ast.List) and any(
                        isinstance(elt, ast.Constant) and elt.value == "*"
                        for elt in k.value.elts
                    ):
                        findings.append(
                            _finding(
                                "ENG-PERMISSIVE-CORS",
                                path,
                                item.lineno,
                                "Permissive wildcard CORS policy configured",
                                "security",
                                Severity.HIGH,
                                "CORS middleware is initialized with allow_origins=['*'], allowing arbitrary origins to make credentialed requests.",
                                "Restrict allowed origins to an explicit list of trusted application domains.",
                                excerpt,
                                Confidence.MEDIUM,
                            )
                        )

        # Untrusted Pickle
        elif name.endswith(("pickle.load", "pickle.loads")):
            findings.append(
                _finding(
                    "PY-UNTRUSTED-PICKLE",
                    path,
                    item.lineno,
                    "Pickle deserialization requires trust review",
                    "security",
                    Severity.HIGH,
                    "Pickle deserialization can execute code when its input is untrusted.",
                    "Load pickle data only from trusted integrity-protected sources; prefer non-executable formats.",
                    excerpt,
                )
            )

        # Torch Artifact Loading
        elif name.endswith("torch.load"):
            unsafe = any(
                k.arg == "weights_only"
                and isinstance(k.value, ast.Constant)
                and k.value.value is False
                for k in item.keywords
            )
            findings.append(
                _finding(
                    "ML-TORCH-UNSAFE-LOAD" if unsafe else "ML-TORCH-LOAD",
                    path,
                    item.lineno,
                    (
                        "Unsafe model artifact loading option"
                        if unsafe
                        else "Model artifact loading requires trust review"
                    ),
                    "ai_ml",
                    Severity.HIGH if unsafe else Severity.MEDIUM,
                    (
                        "weights_only=False allows broader pickle deserialization and may"
                        " execute code in an untrusted artifact."
                        if unsafe
                        else "torch.load is present; safe options and artifact provenance"
                        " require review."
                    ),
                    (
                        "Keep weights_only enabled where supported and verify artifact"
                        " provenance and integrity."
                        if unsafe
                        else "Use weights_only=True where compatible and load artifacts only"
                        " from trusted sources."
                    ),
                    excerpt,
                    Confidence.MEDIUM if unsafe else Confidence.LOW,
                )
            )

        # ML Reproducibility: Missing Random State in Stochastic Estimators
        elif name.endswith(
            (
                "RandomForestClassifier",
                "RandomForestRegressor",
                "KMeans",
                "GradientBoostingClassifier",
                "ExtraTreesClassifier",
            )
        ):
            if not any(k.arg in {"random_state", "seed"} for k in item.keywords):
                findings.append(
                    _finding(
                        "ML-MISSING-RANDOM-SEED",
                        path,
                        item.lineno,
                        "Stochastic ML estimator initialized without random_state",
                        "ai_ml",
                        Severity.MEDIUM,
                        f"{name.split('.')[-1]} uses stochastic initialization without an explicit random_state parameter.",
                        "Pass an explicit random_state to ensure reproducible model training and evaluation.",
                        excerpt,
                        Confidence.MEDIUM,
                    )
                )

        # Prompt Injection Risk
        elif any(
            w in name.lower()
            for w in (
                "chatcompletion",
                "completions.create",
                "generate_content",
                "messages.create",
            )
        ):
            has_fstring_prompt = any(
                isinstance(sub, ast.JoinedStr)
                for arg in item.args
                for sub in ast.walk(arg)
            ) or any(
                isinstance(sub, ast.JoinedStr)
                for k in item.keywords
                for sub in ast.walk(k.value)
            )
            if has_fstring_prompt:
                findings.append(
                    _finding(
                        "AI-HARDCODED-PROMPT-INJECTION-RISK",
                        path,
                        item.lineno,
                        "Unsanitized interpolated prompt passed to model",
                        "ai_ml",
                        Severity.HIGH,
                        "An f-string expression is passed directly into a model generation call, risking prompt injection if variables contain untrusted input.",
                        "Use delimiter tags, strict message schemas, or guardrail validation on interpolated variables.",
                        excerpt,
                        Confidence.MEDIUM,
                    )
                )

        # Integrations & ML Operations
        if name.endswith(
            ("similarity_search", "similaritySearch", "query", "search")
        ) and any(w in name.lower() for w in ("vector", "similarity", "retriev")):
            relationships.append(
                Relationship(
                    module_id,
                    "integration:" + name,
                    "retrieves_context",
                    "observed",
                    (Evidence(path, item.lineno),),
                )
            )
        if name.endswith(
            (
                "create_tool_calling_agent",
                "initialize_agent",
                "AgentExecutor",
                "create_react_agent",
            )
        ):
            relationships.append(
                Relationship(
                    module_id,
                    "integration:" + name,
                    "creates_agent",
                    "observed",
                    (Evidence(path, item.lineno),),
                )
            )
        if any(
            word in name.lower()
            for word in (
                "openai",
                "anthropic",
                "chatcompletion",
                "invoke",
                "generate",
                "embed",
                "similarity_search",
                "vectorstore",
            )
        ):
            relationships.append(
                Relationship(
                    module_id,
                    "integration:" + name,
                    "calls_integration",
                    "observed",
                    (Evidence(path, item.lineno),),
                )
            )
        if any(
            word in name.lower()
            for word in ("fit_transform", "train_test_split", "predict", "evaluate")
        ):
            relationships.append(
                Relationship(
                    module_id,
                    "ml-step:" + name,
                    "calls_ml_operation",
                    "observed",
                    (Evidence(path, item.lineno),),
                )
            )

    # Risk review when a model output reaches a dynamic execution sink
    model_lines = [
        n.lineno
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and any(
            w in _call_name(n.func).lower()
            for w in ("chat.completion", "generate", "invoke")
        )
    ]
    dangerous_lines = [
        n.lineno
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and _call_name(n.func) in {"eval", "exec", "os.system"}
    ]
    if model_lines and dangerous_lines and max(model_lines) <= max(dangerous_lines):
        line = min(dangerous_lines)
        findings.append(
            _finding(
                "AI-OUTPUT-DYNAMIC-SINK",
                path,
                line,
                "AI output may reach dynamic execution",
                "ai_ml",
                Severity.HIGH,
                "A model-generation call and dynamic execution sink occur in the same module; static analysis cannot prove dataflow between them.",
                "Treat model output as untrusted input; validate against a strict schema and remove dynamic code execution.",
                content.splitlines()[line - 1],
                Confidence.LOW,
            )
        )

    # Preprocessing before split data leakage
    fit_lines = [
        n.lineno
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and _call_name(n.func).endswith(("fit_transform", ".fit"))
    ]
    split_lines = [
        n.lineno
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and _call_name(n.func).endswith("train_test_split")
    ]
    if fit_lines and split_lines and min(fit_lines) < min(split_lines):
        line = min(fit_lines)
        findings.append(
            _finding(
                "ML-PREPROCESSING-BEFORE-SPLIT",
                path,
                line,
                "Preprocessing may occur before data split",
                "ai_ml",
                Severity.HIGH,
                "A preprocessing fit call appears before train_test_split in this file, which can leak validation/test information if the same dataset is used.",
                "Split data first and fit learned transformations on training data only, then reuse them for validation, test, and inference.",
                content.splitlines()[line - 1],
                Confidence.LOW,
            )
        )

    return None


def _js_tokens(content):
    """Small position-preserving lexer for JS/TS constructs spanning lines."""
    tokens, i, line = [], 0, 1
    while i < len(content):
        c = content[i]
        if c.isspace():
            if c == "\n":
                line += 1
            i += 1
            continue
        if content.startswith("//", i):
            end = content.find("\n", i)
            i = len(content) if end < 0 else end
            continue
        if content.startswith("/*", i):
            end = content.find("*/", i + 2)
            segment = content[i:] if end < 0 else content[i : end + 2]
            line += segment.count("\n")
            i += len(segment)
            continue
        start, token_line = i, line
        if c in "'\"`":
            quote = c
            i += 1
            value = ""
            while i < len(content):
                if content[i] == "\\":
                    i += min(2, len(content) - i)
                    continue
                if content[i] == quote:
                    i += 1
                    break
                if content[i] == "\n":
                    line += 1
                value += content[i]
                i += 1
            tokens.append((value, token_line, "string"))
            continue
        if c.isalpha() or c in "_$":
            i += 1
            while i < len(content) and (content[i].isalnum() or content[i] in "_$"):
                i += 1
            tokens.append((content[start:i], token_line, "id"))
            continue
        if (
            content.startswith("=>", i)
            or content.startswith("?.", i)
            or content.startswith("===", i)
        ):
            value = next(x for x in ("===", "=>", "?.") if content.startswith(x, i))
            i += len(value)
        else:
            value = c
            i += 1
        tokens.append((value, token_line, "punc"))
    return tokens


def _js_analysis(
    path,
    content,
    source_paths,
    nodes,
    relationships,
    findings,
    routes,
    client_calls,
):
    """Extract common JS/TS structure across lines; unsupported syntax remains unknown."""
    tokens = _js_tokens(content)
    file_id = "file:" + path
    values = [t[0] for t in tokens]
    declared = {}
    imported_symbols = {}
    route_names = {"get", "post", "put", "delete", "patch", "all", "use"}

    # Imports and re-exports: import/export ... from 'x', side-effect import, require('x').
    for i, (value, line, kind) in enumerate(tokens):
        if value in {"import", "export"}:
            j = i + 1
            while (
                j < len(tokens)
                and tokens[j][0] not in {";", "import", "export"}
                and tokens[j][1] <= line + 15
            ):
                if tokens[j][2] == "string" and (j == i + 1 or "from" in values[i:j]):
                    specifier = tokens[j][0]
                    target = (
                        _resolve_local_module(specifier, path, source_paths)
                        if specifier.startswith(".")
                        else "module:" + specifier
                    )
                    relationships.append(
                        Relationship(
                            file_id,
                            target,
                            "imports",
                            "observed",
                            (Evidence(path, line),),
                        )
                    )
                    # Track destructured imported symbols
                    for k in range(i + 1, j):
                        if tokens[k][2] == "id" and tokens[k][0] not in {
                            "from",
                            "import",
                            "as",
                            "type",
                            "default",
                        }:
                            imported_symbols[tokens[k][0]] = target
                    break
                j += 1
        if (
            value == "require"
            and i + 2 < len(tokens)
            and tokens[i + 1][0] == "("
            and tokens[i + 2][2] == "string"
        ):
            specifier = tokens[i + 2][0]
            target = (
                _resolve_local_module(specifier, path, source_paths)
                if specifier.startswith(".")
                else "module:" + specifier
            )
            relationships.append(
                Relationship(
                    file_id,
                    target,
                    "imports",
                    "observed",
                    (Evidence(path, line),),
                )
            )

    # Named classes, interfaces, types, enums, function declarations, and arrow functions
    for i, (value, line, _) in enumerate(tokens):
        # Class declaration with extends / implements
        if value == "class" and i + 1 < len(tokens) and tokens[i + 1][2] == "id":
            name = tokens[i + 1][0]
            class_id = f"symbol:{path}:{line}:{name}"
            declared[name] = ("class", line)
            nodes.append(Node(class_id, name, "class", path, line_start=line))
            # Scan class heritage
            j = i + 2
            while j < min(i + 15, len(tokens)) and tokens[j][0] != "{":
                if (
                    tokens[j][0] == "extends"
                    and j + 1 < len(tokens)
                    and tokens[j + 1][2] == "id"
                ):
                    base_name = tokens[j + 1][0]
                    relationships.append(
                        Relationship(
                            class_id,
                            f"symbol:{base_name}",
                            "inherits",
                            "observed",
                            (Evidence(path, line),),
                        )
                    )
                if (
                    tokens[j][0] == "implements"
                    and j + 1 < len(tokens)
                    and tokens[j + 1][2] == "id"
                ):
                    iface_name = tokens[j + 1][0]
                    relationships.append(
                        Relationship(
                            class_id,
                            f"symbol:{iface_name}",
                            "implements",
                            "observed",
                            (Evidence(path, line),),
                        )
                    )
                j += 1
        # TypeScript interface
        elif value == "interface" and i + 1 < len(tokens) and tokens[i + 1][2] == "id":
            name = tokens[i + 1][0]
            declared[name] = ("interface", line)
            nodes.append(
                Node(
                    f"symbol:{path}:{line}:{name}",
                    name,
                    "interface",
                    path,
                    line_start=line,
                )
            )
        # TypeScript type alias
        elif (
            value == "type"
            and i + 2 < len(tokens)
            and tokens[i + 1][2] == "id"
            and tokens[i + 2][0] == "="
        ):
            name = tokens[i + 1][0]
            declared[name] = ("type", line)
            nodes.append(
                Node(f"symbol:{path}:{line}:{name}", name, "type", path, line_start=line)
            )
        # TypeScript enum
        elif value == "enum" and i + 1 < len(tokens) and tokens[i + 1][2] == "id":
            name = tokens[i + 1][0]
            declared[name] = ("enum", line)
            nodes.append(
                Node(f"symbol:{path}:{line}:{name}", name, "enum", path, line_start=line)
            )
        # Function declarations
        elif value == "function":
            j = i + 1
            if j < len(tokens) and tokens[j][0] == "*":
                j += 1
            if j < len(tokens) and tokens[j][2] == "id":
                name = tokens[j][0]
                declared[name] = ("function", line)
                nodes.append(
                    Node(
                        f"symbol:{path}:{line}:{name}",
                        name,
                        "function",
                        path,
                        line_start=line,
                    )
                )
        # Variable assigned arrow functions
        elif (
            value in {"const", "let", "var"}
            and i + 2 < len(tokens)
            and tokens[i + 1][2] == "id"
        ):
            name = tokens[i + 1][0]
            j = i + 2
            while j < len(tokens) and j < i + 100 and tokens[j][0] not in {";", "}"}:
                if tokens[j][0] == "=>":
                    declared[name] = ("function", line)
                    nodes.append(
                        Node(
                            f"symbol:{path}:{line}:{name}",
                            name,
                            "function",
                            path,
                            line_start=line,
                        )
                    )
                    break
                j += 1
        # Router declarations: router.get('/path', handler)
        if (
            value in route_names
            and i >= 2
            and values[i - 1] == "."
            and i + 2 < len(tokens)
            and tokens[i + 1][0] == "("
            and tokens[i + 2][2] == "string"
        ):
            routes.append((path, line, f"{value.upper()} {tokens[i+2][0]}"))

        # Frontend requests through fetch, axios, and common client.get/post calls.
        if (
            value in {"fetch", "get", "post", "put", "delete", "patch"}
            and i + 2 < len(tokens)
            and tokens[i + 1][0] == "("
        ):
            arg = next(
                (t for t in tokens[i + 2 : min(i + 8, len(tokens))] if t[2] == "string"),
                None,
            )
            if arg and (value == "fetch" or (i >= 2 and values[i - 1] == ".")):
                client_calls.append((path, line, arg[0]))
                # Check for insecure non-localhost HTTP endpoint
                if arg[0].startswith("http://") and not any(
                    h in arg[0] for h in ("localhost", "127.0.0.1", "::1")
                ):
                    source_line = (
                        content.splitlines()[line - 1]
                        if line <= len(content.splitlines())
                        else arg[0]
                    )
                    findings.append(
                        _finding(
                            "JS-INSECURE-HTTP-ENDPOINT",
                            path,
                            line,
                            "Insecure HTTP URL used in network request",
                            "security",
                            Severity.MEDIUM,
                            f"Network request URL '{arg[0][:60]}' uses unencrypted HTTP instead of HTTPS.",
                            "Use HTTPS endpoints to ensure transport encryption and integrity.",
                            source_line,
                            Confidence.HIGH,
                        )
                    )

    # Local & imported cross-file function calls
    for i, (value, line, kind) in enumerate(tokens[:-1]):
        if values[i + 1] == "(":
            if value in declared:
                relationships.append(
                    Relationship(
                        file_id,
                        f"symbol:{path}:{declared[value][1]}:{value}",
                        "calls_function",
                        "observed",
                        (Evidence(path, line),),
                    )
                )
            elif value in imported_symbols:
                target_mod = imported_symbols[value]
                relationships.append(
                    Relationship(
                        file_id,
                        f"{target_mod}:{value}",
                        "calls_function",
                        "observed",
                        (Evidence(path, line),),
                    )
                )

    # Security patterns from token sequences
    for i, (value, line, _) in enumerate(tokens):
        source_line = (
            content.splitlines()[line - 1]
            if line <= len(content.splitlines())
            else value
        )
        if value == "eval" and i + 1 < len(tokens) and values[i + 1] == "(":
            findings.append(
                _finding(
                    "JS-DYNAMIC-EVAL",
                    path,
                    line,
                    "Dynamic expression evaluation",
                    "security",
                    Severity.HIGH,
                    "The code evaluates a computed expression.",
                    "Avoid eval or validate against a restricted expression grammar.",
                    source_line,
                )
            )
        if (
            value in {"exec", "execSync"}
            and "shell" in values[i : min(i + 16, len(values))]
            and "true" in values[i : min(i + 16, len(values))]
        ):
            findings.append(
                _finding(
                    "JS-SHELL-EXEC",
                    path,
                    line,
                    "Shell execution enabled",
                    "security",
                    Severity.HIGH,
                    "A child-process call enables shell interpretation.",
                    "Avoid shell mode and pass validated arguments separately.",
                    source_line,
                )
            )
        # Insecure PRNG for IDs or Tokens
        if value == "random" and i >= 2 and values[i - 1] == "." and values[i - 2] == "Math":
            if any(term in source_line.lower() for term in ("id", "token", "key", "secret", "session", "uuid")):
                findings.append(
                    _finding(
                        "JS-INSECURE-RANDOM",
                        path,
                        line,
                        "Insecure pseudo-random number generator used for identifier generation",
                        "security",
                        Severity.MEDIUM,
                        "Math.random() is cryptographically predictable and prone to collisions when used for identifiers or security values.",
                        "Use crypto.randomUUID() or window.crypto.getRandomValues() for unpredictable, secure identifier generation.",
                        source_line,
                        Confidence.HIGH,
                    )
                )

        # Unencrypted LocalStorage for User Data
        if value in {"setItem", "getItem"} and i >= 2 and values[i - 1] == "." and values[i - 2] == "localStorage":
            if any(term in source_line.lower() for term in ("note", "user", "auth", "token", "secret", "record", "setting", "data")):
                findings.append(
                    _finding(
                        "JS-LOCAL-STORAGE-SENSITIVE",
                        path,
                        line,
                        "Client data persisted in unencrypted browser localStorage",
                        "security",
                        Severity.LOW,
                        "localStorage is accessible to any JavaScript running in the document origin, making stored client data vulnerable to XSS exfiltration.",
                        "Avoid storing sensitive user data in unencrypted localStorage; use IndexedDB with Web Cryptography encryption or secure HttpOnly cookies.",
                        source_line,
                        Confidence.MEDIUM,
                    )
                )

        # Client-Side AI Context Injection / Concatenation
        if (
            "context" in source_line.lower()
            and any(w in source_line.lower() for w in (".join(", "notes.", ".map("))
        ):
            findings.append(
                _finding(
                    "AI-CLIENT-CONTEXT-INJECTION",
                    path,
                    line,
                    "Client-side prompt context constructed via raw text concatenation",
                    "ai_ml",
                    Severity.HIGH,
                    "User note contents are concatenated directly into the AI context without boundary delimiters or sanitization, risking prompt injection and context poisoning.",
                    "Sanitize user inputs and wrap items in explicit boundary tags (e.g. <user_note>...</user_note>) before injecting into model context.",
                    source_line,
                    Confidence.MEDIUM,
                )
            )

        # Hardcoded Local / Unencrypted Service URL in string literals
        if kind == "string" and value.startswith("http://") and any(h in value for h in ("localhost", "127.0.0.1", "0.0.0.0", "11434")):
            findings.append(
                _finding(
                    "JS-HARDCODED-SERVICE-URL",
                    path,
                    line,
                    "Hardcoded unencrypted local service endpoint in client code",
                    "security",
                    Severity.LOW,
                    f"A hardcoded local service URL '{value[:50]}' was detected in client-side code.",
                    "Source service URLs from runtime environment variables (e.g. import.meta.env) to support secure production deployments.",
                    source_line,
                    Confidence.MEDIUM,
                )
            )

        # Direct HTML Injection Risk
        if value in {"dangerouslySetInnerHTML", "innerHTML", "document.write"}:
            findings.append(
                _finding(
                    "JS-DANGEROUS-HTML-INJECTION",
                    path,
                    line,
                    "Direct HTML injection without sanitization",
                    "security",
                    Severity.HIGH,
                    f"Usage of {value} can allow arbitrary HTML and script execution if data is untrusted.",
                    "Use standard text nodes or sanitize inputs using DOMPurify before inserting into the DOM.",
                    source_line,
                    Confidence.HIGH,
                )
            )

        credential = re.search(
            r"(?:api[_-]?key|secret|password|token)\s*[:=]\s*['\"]([^'\"]{12,})['\"]",
            source_line,
            re.I,
        )
        if credential and not re.search(
            r"(?:example|placeholder|dummy|changeme|your[_ -])",
            credential.group(1),
            re.I,
        ):
            findings.append(
                _finding(
                    "GEN-HARDCODED-CREDENTIAL",
                    path,
                    line,
                    "Possible hard-coded credential",
                    "security",
                    Severity.HIGH,
                    "A credential-like assignment has a long literal; it may be a placeholder or fixture.",
                    "Verify it is not a live credential; use protected configuration and rotate exposed secrets.",
                    _redact_secret_excerpt(source_line),
                    Confidence.LOW,
                )
            )
        if value in {
            "similaritySearch",
            "similarity_search",
            "vectorSearch",
            "embedDocuments",
            "createEmbedding",
        }:
            relationships.append(
                Relationship(
                    file_id,
                    "integration:" + value,
                    "calls_retrieval_or_embedding",
                    "observed",
                    (Evidence(path, line),),
                )
            )
        if value in {
            "chat",
            "invoke",
            "generate",
            "generateText",
            "streamText",
            "createAgent",
            "tool",
        } and (
            "openai" in path.lower()
            or "anthropic" in path.lower()
            or any(x in values for x in ("openai", "anthropic", "langchain"))
        ):
            relationships.append(
                Relationship(
                    file_id,
                    "integration:" + value,
                    "calls_model_or_agent",
                    "observed",
                    (Evidence(path, line),),
                )
            )


def _build_workflows(routes, client_calls=(), relationships=()):
    workflows = []
    if routes:
        evidence = tuple(
            Evidence(path, line, line, route) for path, line, route in routes[:40]
        )
        steps = tuple(
            f"Declared route {route} in {path}:{line}" for path, line, route in routes[:40]
        )
        workflows.append(
            Workflow(
                "workflow:http-routes",
                "Observed HTTP route declarations",
                steps,
                "observed",
                evidence,
                (
                    "Route declaration does not establish reachability or a complete"
                    " request-to-model workflow.",
                ),
            )
        )
    matched = [r for r in relationships if r.kind == "calls_api_route"]
    if matched:
        flow_evidence = tuple(ev for rel in matched[:30] for ev in rel.evidence)
        workflows.append(
            Workflow(
                "workflow:frontend-backend",
                "Frontend request to matching backend route",
                tuple(
                    f"{r.source} calls {r.target} (literal URL match inferred)"
                    for r in matched[:30]
                ),
                "inferred",
                flow_evidence,
                (
                    "Only literal URL matches are linked; runtime routing, auth,"
                    " response handling and downstream data/model flow are not"
                    " established.",
                ),
            )
        )
    elif client_calls:
        client_evidence = tuple(
            Evidence(path, line, line, url) for path, line, url in client_calls[:30]
        )
        workflows.append(
            Workflow(
                "workflow:frontend-http",
                "Observed frontend HTTP request sites",
                tuple(
                    f"Request site {url} in {path}:{line}"
                    for path, line, url in client_calls[:30]
                ),
                "observed",
                client_evidence,
                (
                    "Request destinations are observed; no matching backend route"
                    " was established.",
                ),
            )
        )
    model_edges = [
        r
        for r in relationships
        if r.kind
        in {
            "calls_ml_operation",
            "calls_model_or_agent",
            "calls_retrieval_or_embedding",
            "calls_integration",
            "retrieves_context",
            "creates_agent",
        }
    ]
    if model_edges:
        workflows.append(
            Workflow(
                "workflow:model-retrieval",
                "Model and retrieval integration sites",
                tuple(
                    f"{r.source} {r.kind.replace('_', ' ')} {r.target}"
                    for r in model_edges[:40]
                ),
                "observed",
                tuple(ev for rel in model_edges[:40] for ev in rel.evidence),
                (
                    "These are code-level call sites, not proof of successful"
                    " inference, retrieval quality, or end-to-end data flow.",
                ),
            )
        )
    return tuple(workflows)


def _verify_findings(findings, root):
    checked = []
    for finding in findings:
        good = True
        for ev in finding.evidence:
            try:
                read_result = read_text_file(root, ev.path)
                if read_result["status"] != "read":
                    good = False
                    break
                lines = read_result["content"].splitlines()
            except (OSError, UnicodeError, ValueError):
                good = False
                break
            if ev.line_start and (
                ev.line_start > len(lines)
                or (
                    ev.excerpt
                    and "<redacted>" not in ev.excerpt
                    and ev.excerpt not in lines[ev.line_start - 1]
                )
            ):
                good = False
                break
        if good:
            verified_evidence = tuple(
                replace(ev, verification="verified") for ev in finding.evidence
            )
            checked.append(replace(finding, evidence=verified_evidence))
    return checked


def _score(findings, coverage, scope):
    relevant = coverage.source_files_discovered
    rate = min(1.0, coverage.source_files_analyzed / relevant) if relevant else None
    caveats = [
        "Rule-signal indicator only; not a general software quality or production-readiness rating.",
        "Dimensions without implemented checks are unknown, not passed.",
    ]
    if rate is None or coverage.source_files_analyzed == 0:
        return {
            "overall": None,
            "available_signal": None,
            "coverage": rate,
            "status": "unknown",
            "dimensions": {},
            "unknown_dimensions": [
                "security",
                "architecture",
                "testing",
                "performance",
                "ai_ml",
            ],
            "critical_gate": False,
            "notes": caveats,
        }
    penalty = {"critical": 35, "high": 18, "medium": 8, "low": 3, "info": 0}
    score = round(max(0, 100 - sum(penalty[f.severity.value] for f in findings)) * rate, 1)
    gate = any(
        f.severity == Severity.CRITICAL and f.confidence == Confidence.HIGH
        for f in findings
    )
    if gate:
        score = min(score, 20)
    state = (
        "low_coverage"
        if rate < 0.4
        else "signal_only"
        if findings
        else "no_issues_detected_by_enabled_checks"
    )
    supported = {"security", "ai_ml"}
    selected = supported if scope == "full" else {scope} & supported
    dims = {
        category: {
            "value": score,
            "coverage": round(rate, 3),
            "status": state,
            "findings": sum(f.category == category for f in findings),
        }
        for category in sorted(selected)
    }
    unknown = sorted((supported | {"architecture", "testing", "performance"}) - selected)
    # Broad audits expose partial signal; only a category-scoped run can claim a scoped score.
    overall = score if scope != "full" and selected else None
    if scope == "full":
        caveats.append(
            "Overall score is unknown because architecture, testing, and performance"
            " benchmarks are not implemented."
        )
    return {
        "overall": overall,
        "available_signal": score,
        "coverage": round(rate, 3),
        "status": state if overall is not None else "partial_unknown",
        "dimensions": dims,
        "unknown_dimensions": unknown,
        "critical_gate": gate,
        "notes": caveats,
    }


def _unique(items, key):
    out, seen = [], set()
    for item in items:
        value = key(item)
        if value not in seen:
            seen.add(value)
            out.append(item)
    return out


def analyze_repository(
    root, *, system_purpose="", intended_audience="", audit_scope="full"
):
    root = Path(root).expanduser().resolve()
    if audit_scope not in SCOPE_RULES:
        raise ValueError(f"Unsupported audit scope: {audit_scope}")
    inventory = build_inventory(root)
    files = inventory["files"]
    source_paths = {
        r["path"]
        for r in files
        if Path(r["path"]).suffix.lower() in SOURCE_EXTENSIONS
    }
    nodes, relationships, findings, routes, client_calls, dependencies = (
        [],
        [],
        [],
        [],
        [],
        {},
    )
    limitations = [
        "Static analysis cannot establish runtime correctness, production behavior,"
        " model quality, fairness, or latency.",
        "JavaScript and TypeScript syntax support is lexical and incomplete.",
    ]
    counts = {
        "files_discovered": inventory["coverage"]["files_discovered"],
        "files_read": 0,
        "files_protected": inventory["coverage"]["files_protected"],
        "files_skipped": 0,
        "files_failed": 0,
        "files_excluded": inventory["coverage"]["files_excluded"],
        "source_files_discovered": sum(
            Path(r["path"]).suffix.lower() in SOURCE_EXTENSIONS for r in files
        ),
        "source_files_analyzed": 0,
    }
    for record in files:
        path = record["path"]
        if not record["content_permitted"] or record["is_symlink"]:
            counts["files_skipped"] += int(record["is_symlink"])
            continue
        try:
            read = read_text_file(root, path)
        except (OSError, ValueError) as error:
            counts["files_skipped"] += 1
            counts["files_failed"] += 1
            limitations.append(f"Content read failed for {path}: {error}.")
            continue
        if read["status"] != "read":
            counts["files_skipped"] += 1
            counts["files_failed"] += int(read["status"] == "error")
            continue
        counts["files_read"] += 1
        content = read["content"]
        suffix = Path(path).suffix.lower()
        if suffix in SOURCE_EXTENSIONS:
            nodes.append(Node("file:" + path, Path(path).name, "file", path))
        filename = Path(path).name.lower()
        if filename in {
            "dockerfile",
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
            "k8s.yaml",
            "kubernetes.yaml",
        }:
            config_id = "deployment-config:" + path
            nodes.append(Node(config_id, filename, "deployment_config", path))
            if filename != "dockerfile":
                for line_number, line in enumerate(content.splitlines(), 1):
                    service = re.match(r"^\s{2}([A-Za-z0-9_-]+):\s*(?:#.*)?$", line)
                    if service:
                        service_id = "deployment-service:" + service.group(1)
                        nodes.append(
                            Node(
                                service_id,
                                service.group(1),
                                "deployment_service",
                                path,
                                line_start=line_number,
                            )
                        )
                        relationships.append(
                            Relationship(
                                config_id,
                                service_id,
                                "declares_service",
                                "observed",
                                (Evidence(path, line_number),),
                            )
                        )
        found = _manifest_dependencies(path, content)
        if found:
            dependencies[path] = found
            nodes.extend(
                Node(
                    f"dependency:{d['name']}:{d.get('version') or ''}",
                    d["name"],
                    "dependency",
                    path,
                )
                for d in found
            )
        if suffix == ".py":
            issue = _python_analysis(
                path, content, source_paths, nodes, relationships, findings, routes
            )
            if issue:
                limitations.append(issue)
            else:
                counts["source_files_analyzed"] += 1
        elif suffix in SOURCE_EXTENSIONS:
            counts["source_files_analyzed"] += 1
            _js_analysis(
                path,
                content,
                source_paths,
                nodes,
                relationships,
                findings,
                routes,
                client_calls,
            )

    for path, line, route in routes:
        route_id = f"api-route:{path}:{line}"
        nodes.append(Node(route_id, route, "api_route", path, line_start=line))
        route_path = route.split(" ", 1)[-1]
        for client_path, client_line, url in client_calls:
            if path != client_path and route_path in url:
                relationships.append(
                    Relationship(
                        "file:" + client_path,
                        route_id,
                        "calls_api_route",
                        "inferred",
                        (
                            Evidence(client_path, client_line, client_line, url),
                            Evidence(path, line, line, route),
                        ),
                    )
                )

    selected = SCOPE_RULES[audit_scope]
    if selected is not None:
        findings = [f for f in findings if f.category in selected]
    findings = _verify_findings(findings, root)
    findings = _unique(
        findings,
        lambda f: (f.rule_id, tuple((e.path, e.line_start) for e in f.evidence)),
    )
    nodes = _unique(nodes, lambda n: n.id)
    relationships = _unique(
        relationships,
        lambda r: (
            r.source,
            r.target,
            r.kind,
            r.confidence,
            tuple((e.path, e.line_start) for e in r.evidence),
        ),
    )
    coverage = Coverage(**{**counts, "limitations": tuple(dict.fromkeys(limitations))})
    return AuditResult(
        str(root),
        now_utc(),
        {
            "system_purpose": system_purpose,
            "intended_audience": intended_audience,
            "audit_scope": audit_scope,
        },
        coverage,
        tuple(findings),
        tuple(nodes),
        tuple(relationships),
        _build_workflows(routes, client_calls, relationships),
        _score(findings, coverage, audit_scope),
        {k: tuple(v) for k, v in dependencies.items()},
    )
