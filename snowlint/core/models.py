"""Versioned canonical models shared by analysis and output adapters."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
from pathlib import PurePosixPath
from typing import Any

from snowlint import SCHEMA_VERSION


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingStatus(str, Enum):
    CONFIRMED_DEFECT = "confirmed_defect"
    EVIDENCE_BACKED_RISK = "evidence_backed_risk"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    VERIFIED_BEHAVIOR = "verified_behavior"


@dataclass(frozen=True)
class Evidence:
    path: str
    line_start: int | None = None
    line_end: int | None = None
    excerpt: str | None = None
    verification: str = "observed"

    def __post_init__(self):
        p = PurePosixPath(self.path)
        if p.is_absolute() or ".." in p.parts or not self.path or "\\" in self.path:
            raise ValueError("Evidence path must be repository-relative")
        if self.line_start is not None and self.line_start < 1:
            raise ValueError("line_start must be positive")
        if self.line_end is not None and self.line_end < (self.line_start or 1):
            raise ValueError("line_end must be >= line_start")


@dataclass(frozen=True)
class Finding:
    id: str
    rule_id: str
    title: str
    category: str
    status: str
    severity: Severity
    confidence: Confidence
    summary: str
    recommendation: str
    evidence: tuple[Evidence, ...] = ()
    origin: str = "deterministic"
    limitations: tuple[str, ...] = ()

    def __post_init__(self):
        if self.status not in {item.value for item in FindingStatus}:
            raise ValueError(f"Unsupported finding status: {self.status}")
        if not self.evidence and self.status != FindingStatus.INSUFFICIENT_EVIDENCE.value:
            raise ValueError("Substantive findings require evidence")


@dataclass(frozen=True)
class Node:
    id: str
    name: str
    kind: str
    path: str | None = None
    attributes: tuple[str, ...] = ()
    methods: tuple[str, ...] = ()
    line_start: int | None = None


@dataclass(frozen=True)
class Relationship:
    source: str
    target: str
    kind: str
    confidence: str = "observed"
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class Coverage:
    files_discovered: int = 0
    files_read: int = 0
    files_protected: int = 0
    files_skipped: int = 0
    files_failed: int = 0
    files_excluded: int = 0
    source_files_discovered: int = 0
    source_files_analyzed: int = 0
    limitations: tuple[str, ...] = ()

    def __post_init__(self):
        counts = (self.files_discovered, self.files_read, self.files_protected, self.files_skipped,
                  self.files_failed, self.files_excluded, self.source_files_discovered, self.source_files_analyzed)
        if any(value < 0 for value in counts): raise ValueError("Coverage counts cannot be negative")
        if self.source_files_analyzed > self.source_files_discovered: raise ValueError("Analyzed source count exceeds discovered source count")


@dataclass(frozen=True)
class AuditScore:
    value: float | None
    coverage: float | None
    status: str
    findings_count: int = 0
    critical_gate: bool = False
    notes: tuple[str, ...] = ()

    def __post_init__(self):
        if self.value is not None and not 0 <= self.value <= 100:
            raise ValueError("score value must be between 0 and 100")
        if self.coverage is not None and not 0 <= self.coverage <= 1:
            raise ValueError("score coverage must be between 0 and 1")


@dataclass(frozen=True)
class Workflow:
    id: str
    name: str
    steps: tuple[str, ...]
    confidence: str
    evidence: tuple[Evidence, ...] = ()
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuditResult:
    repository: str
    audited_at: str
    context: dict[str, str]
    coverage: Coverage
    findings: tuple[Finding, ...] = ()
    nodes: tuple[Node, ...] = ()
    relationships: tuple[Relationship, ...] = ()
    workflows: tuple[Workflow, ...] = ()
    scores: dict[str, Any] = field(default_factory=dict)
    dependencies: dict[str, tuple[dict[str, Any], ...]] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self):
        if self.schema_version not in {"1.0", "1.1"}:
            raise ValueError(f"Unsupported audit schema version: {self.schema_version}")
        timestamp = datetime.fromisoformat(self.audited_at.replace("Z", "+00:00"))
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("audited_at must include a timezone")

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(asdict(self))

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditResult":
        version = data.get("schema_version", "1.0")
        if version not in {"1.0", "1.1"}:
            raise ValueError(f"Unsupported audit schema version: {version}")
        findings = tuple(Finding(**{**f, "severity": Severity(f["severity"]),
                                    "confidence": Confidence(f["confidence"]),
                                    "evidence": tuple(Evidence(**e) for e in f.get("evidence", ())),
                                    "limitations": tuple(f.get("limitations", ()))}) for f in data.get("findings", ()))
        nodes = tuple(Node(**n) for n in data.get("nodes", ()))
        rels = tuple(Relationship(**{**r, "evidence": tuple(Evidence(**e) for e in r.get("evidence", ()))}) for r in data.get("relationships", ()))
        workflows = tuple(Workflow(**{**w, "steps": tuple(w.get("steps", ())),
                                      "evidence": tuple(Evidence(**e) for e in w.get("evidence", ())),
                                      "limitations": tuple(w.get("limitations", ()))}) for w in data.get("workflows", ()))
        return cls(**{**data, "coverage": Coverage(**data["coverage"]), "findings": findings,
                      "nodes": nodes, "relationships": rels, "workflows": workflows,
                      "dependencies": {k: tuple(v) for k, v in data.get("dependencies", {}).items()}})


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(v) for v in value]
    return value


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()
