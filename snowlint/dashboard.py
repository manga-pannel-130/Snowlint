"""Professional, immersive local-only dashboard served on loopback."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import html
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


def _render_onboarding_html():
    return """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Snowlint · Local Codebase Auditor</title>
<style>
:root {
  --bg: #090d16;
  --surface: #111827;
  --surface-hover: #162032;
  --surface-border: #1f293d;
  --accent: #00b4d8;
  --accent-glow: rgba(0, 180, 216, 0.25);
  --accent-purple: #8b5cf6;
  --text-main: #f1f5f9;
  --text-muted: #94a3b8;
  --border: #1e293b;
  --radius: 12px;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Inter", sans-serif;
  background: var(--bg);
  background-image: 
    radial-gradient(circle at 15% 15%, rgba(0, 180, 216, 0.08) 0%, transparent 40%),
    radial-gradient(circle at 85% 85%, rgba(139, 92, 246, 0.08) 0%, transparent 40%);
  color: var(--text-main);
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 2rem 1rem;
}
.container {
  width: 100%;
  max-width: 720px;
}
.header {
  text-align: center;
  margin-bottom: 2.2rem;
}
.logo-badge {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.4rem 0.9rem;
  background: rgba(0, 180, 216, 0.12);
  border: 1px solid rgba(0, 180, 216, 0.3);
  border-radius: 9999px;
  font-size: 0.85rem;
  font-weight: 600;
  color: var(--accent);
  margin-bottom: 1rem;
  letter-spacing: 0.03em;
}
.header h1 {
  font-size: 2.4rem;
  font-weight: 800;
  letter-spacing: -0.03em;
  background: linear-gradient(135deg, #ffffff 40%, #94a3b8 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  margin-bottom: 0.6rem;
}
.header p {
  color: var(--text-muted);
  font-size: 1.05rem;
  line-height: 1.5;
}
.card {
  background: var(--surface);
  border: 1px solid var(--surface-border);
  border-radius: var(--radius);
  padding: 2.2rem;
  box-shadow: 0 20px 40px -15px rgba(0, 0, 0, 0.6);
}
.form-group {
  margin-bottom: 1.4rem;
}
label {
  display: block;
  font-size: 0.88rem;
  font-weight: 600;
  color: var(--text-main);
  margin-bottom: 0.5rem;
}
label span.hint {
  font-weight: 400;
  color: var(--text-muted);
  font-size: 0.8rem;
  margin-left: 0.4rem;
}
input, textarea, select {
  width: 100%;
  background: #0c121e;
  border: 1px solid #1e293b;
  border-radius: 8px;
  padding: 0.8rem 1rem;
  font-size: 0.95rem;
  color: #fff;
  transition: all 0.2s;
  font-family: inherit;
}
input:focus, textarea:focus, select:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-glow);
}
textarea {
  min-height: 80px;
  resize: vertical;
}
.grid-2 {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
}
@media (max-width: 600px) {
  .grid-2 { grid-template-columns: 1fr; }
}
.btn-primary {
  width: 100%;
  background: linear-gradient(135deg, #00b4d8 0%, #0077b6 100%);
  color: #ffffff;
  border: none;
  border-radius: 8px;
  padding: 0.95rem 1.4rem;
  font-size: 1.05rem;
  font-weight: 700;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  box-shadow: 0 8px 20px -6px rgba(0, 180, 216, 0.5);
  margin-top: 1.8rem;
}
.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 12px 24px -6px rgba(0, 180, 216, 0.7);
}
.privacy-pill {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.6rem;
  margin-top: 1.5rem;
  color: var(--text-muted);
  font-size: 0.82rem;
}
.privacy-pill svg {
  color: #10b981;
}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="logo-badge">❄️ SNOWLINT V1 · LOCAL ENGINE</div>
    <h1>Evidence-Driven Audit</h1>
    <p>Local, bounded static analysis for repository architecture, security, and AI/ML pipelines.</p>
  </div>
  <div class="card">
    <form method="post" action="/audit">
      <div class="form-group">
        <label>Repository path <span class="hint">Absolute or relative to current directory</span></label>
        <input name="repository" required placeholder="/path/to/repository" autofocus>
      </div>
      <div class="form-group">
        <label>What does the system do? <span class="hint">System context & purpose</span></label>
        <textarea name="purpose" placeholder="e.g. Distributed asynchronous inference gateway for multi-modal models..."></textarea>
      </div>
      <div class="grid-2">
        <div class="form-group">
          <label>Audience and maturity</label>
          <input name="audience" placeholder="e.g. Enterprise Security, Production Ready">
        </div>
        <div class="form-group">
          <label>Audit focus scope</label>
          <select name="scope">
            <option value="full">Full Audit (All Checks)</option>
            <option value="security">Security & Credentials</option>
            <option value="ai_ml">AI/ML & Pipeline Risk</option>
            <option value="architecture">Architecture & Boundaries</option>
            <option value="testing">Testing Coverage</option>
            <option value="performance">Performance & Concurrency</option>
          </select>
        </div>
      </div>
      <button class="btn-primary" type="submit">
        <span>Run Local Audit</span>
        <svg width="18" height="18" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 5l7 7m0 0l-7 7m7-7H3"/></svg>
      </button>
    </form>
  </div>
  <div class="privacy-pill">
    <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
    <span>100% offline & local · No code execution · Sensitive files protected</span>
  </div>
</div>
</body>
</html>"""


def _render_evidence_blocks(evidence_items):
    out = []
    for ev in evidence_items:
        p = html.escape(ev.get("path", ""))
        line = html.escape(str(ev.get("line_start") or "1"))
        excerpt = html.escape(ev.get("excerpt") or "(no excerpt)")
        out.append(
            '<div class="evidence-box">'
            '<div class="evidence-loc">'
            '<svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor">'
            '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>'
            '</svg>'
            '<span>' + p + ':' + line + '</span>'
            '</div>'
            '<code>' + excerpt + '</code>'
            '</div>'
        )
    return "".join(out)


def _render_findings_html(findings_list):
    if not findings_list:
        return """
        <div class="empty-state">
          <div class="icon">✨</div>
          <h3>No Issues Detected</h3>
          <p>No defects or vulnerabilities were triggered by the currently enabled ruleset on analyzed files.</p>
        </div>"""
    cards = []
    for f in findings_list:
        sev = html.escape(f.get("severity", "info").lower())
        sev_upper = html.escape(f.get("severity", "info").upper())
        rule_id = html.escape(f.get("rule_id", ""))
        title = html.escape(f.get("title", ""))
        category = html.escape(f.get("category", ""))
        confidence = html.escape(str(f.get("confidence", "")))
        summary = html.escape(f.get("summary", ""))
        recommendation = html.escape(f.get("recommendation", ""))
        search_blob = html.escape(
            (f.get("title", "") + " " + f.get("rule_id", "") + " " + f.get("summary", "")).lower()
        )
        evidence_html = _render_evidence_blocks(f.get("evidence", []))
        sev_class = sev if sev in {"critical", "high", "medium", "low"} else "low"
        pill_class = sev[:4]

        card = (
            f'<div class="finding-card severity-{sev_class}" data-severity="{sev_class}" data-text="{search_blob}">'
            '<div class="finding-header">'
            '<div class="finding-title-group">'
            f'<span class="sev-pill {pill_class}">{sev_upper}</span>'
            f'<span class="rule-tag">{rule_id}</span>'
            f'<span class="finding-title">{title}</span>'
            '</div>'
            f'<span style="font-size: 0.8rem; color: var(--text-dim);">category: <b>{category}</b> · confidence: {confidence}</span>'
            '</div>'
            f'<p class="finding-summary">{summary}</p>'
            f'{evidence_html}'
            '<div class="remediation-box">'
            f'<strong>Remediation:</strong> {recommendation}'
            '</div>'
            '</div>'
        )
        cards.append(card)
    return "".join(cards)


def _render_workflows_html(workflows):
    if not workflows:
        return """
        <div class="empty-state">
          <div class="icon">🏛️</div>
          <h3>No Multi-Step Workflows Reconstructed</h3>
          <p>No multi-component route bindings or model pipelines could be established from static declarations.</p>
        </div>"""
    out = []
    for w in workflows:
        name = html.escape(w.get("name", ""))
        conf = html.escape(w.get("confidence", "observed"))
        conf_pill = "med" if conf == "inferred" else "low"
        steps_html = []
        for idx, step in enumerate(w.get("steps", [])):
            step_esc = html.escape(step)
            steps_html.append(
                f'<div class="workflow-step">'
                f'<span class="step-num">{idx + 1}</span>'
                f'<span style="color: #cbd5e1;">{step_esc}</span>'
                '</div>'
            )
        out.append(
            '<div class="workflow-card">'
            '<div class="workflow-header">'
            f'<div class="workflow-name">{name}</div>'
            f'<span class="sev-pill {conf_pill}">{conf.upper()}</span>'
            '</div>'
            '<div>' + "".join(steps_html) + '</div>'
            '</div>'
        )
    return "".join(out)


def _render_dependencies_html(dependencies):
    total = sum(len(v) for v in dependencies.values())
    if total == 0:
        return """
        <div class="empty-state" style="grid-column: 1 / -1;">
          <div class="icon">📦</div>
          <h3>No Manifest Dependencies Observed</h3>
          <p>No pyproject.toml, requirements.txt, or package.json dependencies were detected.</p>
        </div>"""
    out = []
    for src, deps in dependencies.items():
        src_esc = html.escape(src)
        for dep in deps:
            name_esc = html.escape(dep.get("name", ""))
            ver_esc = html.escape(dep.get("version") or dep.get("constraint") or "unconstrained")
            out.append(
                '<div style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 1.2rem;">'
                f'<div style="font-weight: 700; color: #fff; font-size: 1rem; margin-bottom: 0.3rem;">{name_esc}</div>'
                f'<div style="font-size: 0.82rem; color: var(--accent-cyan); font-family: monospace; margin-bottom: 0.4rem;">{ver_esc}</div>'
                f'<div style="font-size: 0.78rem; color: var(--text-dim);">Source: {src_esc}</div>'
                '</div>'
            )
    return "".join(out)


def _render_coverage_limitations_html(limitations, notes):
    out = []
    for lim in limitations:
        out.append(f'<li style="margin-bottom: 0.5rem;">{html.escape(lim)}</li>')
    for n in notes:
        out.append(f'<li style="margin-bottom: 0.5rem; color: #cbd5e1;">{html.escape(n)}</li>')
    return "".join(out)


def _render_dashboard_html(payload):
    findings_list = payload.get("findings", [])
    coverage = payload.get("coverage", {})
    scores = payload.get("scores", {})
    context = payload.get("context", {})
    nodes = payload.get("nodes", [])
    relationships = payload.get("relationships", [])
    workflows = payload.get("workflows", [])
    dependencies = payload.get("dependencies", {})
    repo = payload.get("repository", "")

    critical_count = sum(1 for f in findings_list if f.get("severity", "").lower() == "critical")
    high_count = sum(1 for f in findings_list if f.get("severity", "").lower() == "high")
    med_count = sum(1 for f in findings_list if f.get("severity", "").lower() == "medium")
    low_count = sum(1 for f in findings_list if f.get("severity", "").lower() in {"low", "info"})

    score_val = scores.get("available_signal")
    if score_val is not None:
        score_display = f"{score_val:.0f}"
        score_color = "#10b981" if score_val >= 80 else "#f59e0b" if score_val >= 50 else "#ef4444"
    else:
        score_display = "N/A"
        score_color = "#94a3b8"

    findings_html = _render_findings_html(findings_list)
    workflows_html = _render_workflows_html(workflows)
    dependencies_html = _render_dependencies_html(dependencies)
    limitations_html = _render_coverage_limitations_html(
        coverage.get("limitations", []), scores.get("notes", [])
    )

    repo_esc = html.escape(repo)
    repo_name_esc = html.escape(Path(repo).name or repo)
    purpose_esc = html.escape(context.get("system_purpose", ""))
    audience_esc = html.escape(context.get("intended_audience", ""))
    scope_val = context.get("audit_scope", "full")
    export_dir_default = html.escape(str(Path(repo).resolve() / "snowlint_exports"))

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Snowlint Audit · {repo_name_esc}</title>
<style>
:root {{
  --bg-app: #080c14;
  --bg-card: #0f1624;
  --bg-card-subtle: #141d2f;
  --border-subtle: #1b263b;
  --border-active: #2c3e5d;
  --accent-cyan: #00b4d8;
  --accent-cyan-glow: rgba(0, 180, 216, 0.2);
  --accent-violet: #8b5cf6;
  --sev-critical: #ef4444;
  --sev-high: #f97316;
  --sev-med: #eab308;
  --sev-low: #3b82f6;
  --sev-info: #64748b;
  --text-main: #f8fafc;
  --text-muted: #94a3b8;
  --text-dim: #64748b;
  --radius-sm: 6px;
  --radius-md: 10px;
  --radius-lg: 14px;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Inter", sans-serif;
  background: var(--bg-app);
  color: var(--text-main);
  line-height: 1.5;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}}
.navbar {{
  background: rgba(15, 22, 36, 0.85);
  backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--border-subtle);
  position: sticky;
  top: 0;
  z-index: 100;
  padding: 0.85rem 1.8rem;
  display: flex;
  align-items: center;
  justify-content: space-between;
}}
.nav-brand {{
  display: flex;
  align-items: center;
  gap: 0.8rem;
  font-weight: 700;
  font-size: 1.15rem;
}}
.nav-brand .logo-icon {{
  font-size: 1.3rem;
  filter: drop-shadow(0 0 8px rgba(0, 180, 216, 0.6));
}}
.nav-brand .title {{
  background: linear-gradient(135deg, #fff 30%, #94a3b8 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  letter-spacing: -0.02em;
}}
.nav-repo {{
  display: flex;
  align-items: center;
  gap: 0.5rem;
  background: var(--bg-card-subtle);
  border: 1px solid var(--border-subtle);
  padding: 0.35rem 0.8rem;
  border-radius: 9999px;
  font-size: 0.82rem;
  color: var(--text-muted);
  max-width: 480px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}}
.nav-repo strong {{
  color: var(--accent-cyan);
}}
.nav-actions {{
  display: flex;
  align-items: center;
  gap: 0.8rem;
}}
.btn-sm {{
  background: var(--bg-card-subtle);
  border: 1px solid var(--border-subtle);
  color: var(--text-main);
  padding: 0.45rem 0.85rem;
  border-radius: var(--radius-sm);
  font-size: 0.84rem;
  font-weight: 600;
  cursor: pointer;
  text-decoration: none;
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  transition: all 0.2s;
}}
.btn-sm:hover {{
  background: var(--border-active);
  color: #fff;
  border-color: var(--accent-cyan);
}}
.btn-primary-sm {{
  background: linear-gradient(135deg, #00b4d8 0%, #0077b6 100%);
  border: none;
  color: #fff;
  box-shadow: 0 4px 12px -2px rgba(0, 180, 216, 0.4);
}}
.btn-primary-sm:hover {{
  filter: brightness(1.1);
  transform: translateY(-1px);
}}
.layout {{
  max-width: 1400px;
  margin: 0 auto;
  padding: 1.8rem;
  width: 100%;
  flex: 1;
}}
.metrics-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 1.2rem;
  margin-bottom: 2rem;
}}
.metric-card {{
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  padding: 1.4rem;
  position: relative;
  overflow: hidden;
  transition: transform 0.2s, border-color 0.2s;
}}
.metric-card:hover {{
  border-color: var(--border-active);
  transform: translateY(-2px);
}}
.metric-card::before {{
  content: "";
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 2px;
  background: linear-gradient(90deg, transparent, var(--accent-cyan), transparent);
  opacity: 0.3;
}}
.metric-title {{
  font-size: 0.82rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--text-muted);
  font-weight: 600;
  margin-bottom: 0.6rem;
  display: flex;
  align-items: center;
  justify-content: space-between;
}}
.metric-value {{
  font-size: 2.2rem;
  font-weight: 800;
  letter-spacing: -0.03em;
  display: flex;
  align-items: baseline;
  gap: 0.4rem;
}}
.metric-sub {{
  margin-top: 0.4rem;
  font-size: 0.82rem;
  color: var(--text-dim);
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}}
.sev-pill {{
  font-size: 0.72rem;
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
  font-weight: 700;
  text-transform: uppercase;
}}
.sev-pill.crit {{ background: rgba(239, 68, 68, 0.18); color: var(--sev-critical); border: 1px solid rgba(239, 68, 68, 0.3); }}
.sev-pill.high {{ background: rgba(249, 115, 22, 0.18); color: var(--sev-high); border: 1px solid rgba(249, 115, 22, 0.3); }}
.sev-pill.med {{ background: rgba(234, 179, 8, 0.18); color: var(--sev-med); border: 1px solid rgba(234, 179, 8, 0.3); }}
.sev-pill.low {{ background: rgba(59, 130, 246, 0.18); color: var(--sev-low); border: 1px solid rgba(59, 130, 246, 0.3); }}
.tabs {{
  display: flex;
  align-items: center;
  gap: 0.6rem;
  border-bottom: 1px solid var(--border-subtle);
  margin-bottom: 1.8rem;
  overflow-x: auto;
}}
.tab-btn {{
  background: none;
  border: none;
  color: var(--text-muted);
  font-size: 0.92rem;
  font-weight: 600;
  padding: 0.75rem 1.1rem;
  border-bottom: 2px solid transparent;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  transition: all 0.2s;
  white-space: nowrap;
}}
.tab-btn:hover {{
  color: var(--text-main);
}}
.tab-btn.active {{
  color: var(--accent-cyan);
  border-bottom-color: var(--accent-cyan);
}}
.tab-badge {{
  background: var(--bg-card-subtle);
  border: 1px solid var(--border-subtle);
  padding: 0.1rem 0.45rem;
  border-radius: 9999px;
  font-size: 0.75rem;
}}
.filter-bar {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  margin-bottom: 1.4rem;
  flex-wrap: wrap;
}}
.search-input {{
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-sm);
  padding: 0.55rem 0.9rem;
  color: #fff;
  font-size: 0.88rem;
  min-width: 280px;
}}
.search-input:focus {{
  outline: none;
  border-color: var(--accent-cyan);
}}
.filter-select {{
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-sm);
  padding: 0.55rem 0.9rem;
  color: #fff;
  font-size: 0.88rem;
}}
.findings-container {{
  display: flex;
  flex-direction: column;
  gap: 1rem;
}}
.finding-card {{
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-left: 4px solid var(--sev-info);
  border-radius: var(--radius-md);
  padding: 1.4rem;
  transition: border-color 0.2s;
}}
.finding-card.severity-critical {{ border-left-color: var(--sev-critical); }}
.finding-card.severity-high {{ border-left-color: var(--sev-high); }}
.finding-card.severity-medium {{ border-left-color: var(--sev-med); }}
.finding-card.severity-low {{ border-left-color: var(--sev-low); }}
.finding-header {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.8rem;
  margin-bottom: 0.6rem;
  flex-wrap: wrap;
}}
.finding-title-group {{
  display: flex;
  align-items: center;
  gap: 0.6rem;
  flex-wrap: wrap;
}}
.finding-title {{
  font-size: 1.05rem;
  font-weight: 700;
  color: #fff;
}}
.rule-tag {{
  font-family: monospace;
  font-size: 0.78rem;
  background: var(--bg-card-subtle);
  border: 1px solid var(--border-subtle);
  color: var(--text-muted);
  padding: 0.2rem 0.5rem;
  border-radius: 4px;
}}
.finding-summary {{
  color: var(--text-muted);
  font-size: 0.92rem;
  margin-bottom: 1rem;
}}
.evidence-box {{
  background: #090e18;
  border: 1px solid #162032;
  border-radius: 6px;
  padding: 0.8rem 1rem;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.82rem;
  color: #cbd5e1;
  overflow-x: auto;
  margin-bottom: 0.8rem;
}}
.evidence-loc {{
  color: var(--accent-cyan);
  font-weight: 600;
  margin-bottom: 0.4rem;
  display: flex;
  align-items: center;
  gap: 0.4rem;
}}
.remediation-box {{
  background: rgba(0, 180, 216, 0.05);
  border: 1px solid rgba(0, 180, 216, 0.2);
  border-radius: 6px;
  padding: 0.75rem 1rem;
  font-size: 0.85rem;
  color: #e2e8f0;
}}
.remediation-box strong {{
  color: var(--accent-cyan);
  margin-right: 0.4rem;
}}
.empty-state {{
  text-align: center;
  padding: 4rem 2rem;
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
}}
.empty-state .icon {{
  font-size: 3rem;
  margin-bottom: 1rem;
}}
.empty-state h3 {{
  font-size: 1.3rem;
  font-weight: 700;
  margin-bottom: 0.5rem;
}}
.empty-state p {{
  color: var(--text-muted);
  font-size: 0.95rem;
  max-width: 500px;
  margin: 0 auto;
}}
.export-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 1.4rem;
  margin-top: 1.2rem;
}}
.export-card {{
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  padding: 1.6rem;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  transition: all 0.2s;
}}
.export-card:hover {{
  border-color: var(--accent-cyan);
  box-shadow: 0 10px 24px -10px var(--accent-cyan-glow);
}}
.export-card-header {{
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 0.8rem;
  margin-bottom: 0.8rem;
}}
.export-card-title {{
  font-size: 1.1rem;
  font-weight: 700;
  color: #fff;
}}
.export-card-desc {{
  font-size: 0.86rem;
  color: var(--text-muted);
  margin-bottom: 1.2rem;
}}
.export-badge {{
  font-size: 0.72rem;
  font-weight: 700;
  padding: 0.2rem 0.5rem;
  border-radius: 4px;
  text-transform: uppercase;
  background: var(--bg-card-subtle);
  border: 1px solid var(--border-subtle);
  color: var(--text-muted);
}}
.btn-export {{
  width: 100%;
  background: var(--bg-card-subtle);
  border: 1px solid var(--border-subtle);
  color: var(--text-main);
  padding: 0.75rem 1rem;
  border-radius: var(--radius-sm);
  font-weight: 600;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  transition: all 0.2s;
}}
.btn-export:hover {{
  background: var(--accent-cyan);
  border-color: var(--accent-cyan);
  color: #000;
  font-weight: 700;
}}
.export-settings-card {{
  background: var(--bg-card-subtle);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  padding: 1.4rem;
  margin-bottom: 1.8rem;
}}
.export-settings-grid {{
  display: grid;
  grid-template-columns: 2fr 1fr 1fr;
  gap: 1.2rem;
}}
@media (max-width: 800px) {{
  .export-settings-grid {{ grid-template-columns: 1fr; }}
}}
.checkbox-group {{
  display: flex;
  gap: 1.2rem;
  margin-top: 1rem;
  flex-wrap: wrap;
}}
.checkbox-label {{
  display: inline-flex;
  align-items: center;
  gap: 0.45rem;
  font-size: 0.86rem;
  color: var(--text-muted);
  cursor: pointer;
}}
.checkbox-label input {{
  width: auto;
  accent-color: var(--accent-cyan);
}}
.workflow-card {{
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  padding: 1.4rem;
  margin-bottom: 1.2rem;
}}
.workflow-header {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1rem;
}}
.workflow-name {{
  font-size: 1.05rem;
  font-weight: 700;
  color: var(--text-main);
}}
.workflow-step {{
  display: flex;
  align-items: flex-start;
  gap: 0.8rem;
  padding: 0.6rem 0;
  border-bottom: 1px solid rgba(255,255,255,0.05);
  font-size: 0.88rem;
}}
.step-num {{
  width: 22px;
  height: 22px;
  border-radius: 50%;
  background: var(--bg-card-subtle);
  border: 1px solid var(--border-subtle);
  color: var(--accent-cyan);
  font-size: 0.75rem;
  font-weight: 700;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}}
.modal-backdrop {{
  display: none;
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(0, 0, 0, 0.75);
  backdrop-filter: blur(8px);
  z-index: 200;
  align-items: center;
  justify-content: center;
  padding: 1rem;
}}
.modal-backdrop.open {{
  display: flex;
}}
.modal-content {{
  background: var(--bg-card);
  border: 1px solid var(--border-active);
  border-radius: var(--radius-lg);
  padding: 2.2rem;
  max-width: 600px;
  width: 100%;
  box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.8);
}}
</style>
</head>
<body>
<nav class="navbar">
  <div class="nav-brand">
    <span class="logo-icon">❄️</span>
    <span class="title">Snowlint Audit Studio</span>
  </div>
  <div class="nav-repo" title="{repo_esc}">
    <span>Repo:</span>
    <strong>{repo_esc}</strong>
  </div>
  <div class="nav-actions">
    <button class="btn-sm" onclick="openNewAuditModal()">
      <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>
      <span>New Audit</span>
    </button>
    <a class="btn-sm btn-primary-sm" href="/api/audit" download="snowlint-audit.json">
      <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
      <span>Download JSON</span>
    </a>
  </div>
</nav>

<main class="layout">
  <div class="metrics-grid">
    <div class="metric-card">
      <div class="metric-title">
        <span>Signal Score</span>
        <span style="color: {score_color}">●</span>
      </div>
      <div class="metric-value" style="color: {score_color}">
        {score_display}
        <span style="font-size: 1rem; color: var(--text-dim); font-weight: 500;">/100</span>
      </div>
      <div class="metric-sub">
        <span>Status: {html.escape(scores.get("status", "unknown"))}</span>
      </div>
    </div>

    <div class="metric-card">
      <div class="metric-title">
        <span>Detected Findings</span>
        <span>⚠️</span>
      </div>
      <div class="metric-value">
        {len(findings_list)}
      </div>
      <div class="metric-sub">
        <span class="sev-pill crit">{critical_count} crit</span>
        <span class="sev-pill high">{high_count} high</span>
        <span class="sev-pill med">{med_count} med</span>
        <span class="sev-pill low">{low_count} low</span>
      </div>
    </div>

    <div class="metric-card">
      <div class="metric-title">
        <span>Files Read & Coverage</span>
        <span>📁</span>
      </div>
      <div class="metric-value">
        {coverage.get("files_read", 0)}
        <span style="font-size: 1rem; color: var(--text-dim); font-weight: 500;">/ {coverage.get("files_discovered", 0)}</span>
      </div>
      <div class="metric-sub">
        <span>{coverage.get("source_files_analyzed", 0)}/{coverage.get("source_files_discovered", 0)} sources analyzed</span>
        <span>· {coverage.get("files_protected", 0)} protected</span>
      </div>
    </div>

    <div class="metric-card">
      <div class="metric-title">
        <span>Architecture & Flow</span>
        <span>⚡</span>
      </div>
      <div class="metric-value">
        {len(nodes)}
        <span style="font-size: 1rem; color: var(--text-dim); font-weight: 500;">nodes</span>
      </div>
      <div class="metric-sub">
        <span>{len(relationships)} relations</span>
        <span>· {len(workflows)} workflows</span>
      </div>
    </div>
  </div>

  <div class="tabs">
    <button class="tab-btn active" onclick="switchTab('findings', this)">
      <span>🔍 Findings</span>
      <span class="tab-badge">{len(findings_list)}</span>
    </button>
    <button class="tab-btn" onclick="switchTab('workflows', this)">
      <span>🏛️ Architecture & Workflows</span>
      <span class="tab-badge">{len(workflows)}</span>
    </button>
    <button class="tab-btn" onclick="switchTab('dependencies', this)">
      <span>📦 Dependencies</span>
      <span class="tab-badge">{sum(len(v) for v in dependencies.values())}</span>
    </button>
    <button class="tab-btn" onclick="switchTab('coverage', this)">
      <span>🛡️ Coverage & Boundaries</span>
    </button>
    <button class="tab-btn" onclick="switchTab('exports', this)">
      <span>🚀 Export Studio</span>
    </button>
  </div>

  <div id="tab-findings" class="tab-content">
    <div class="filter-bar">
      <input type="text" id="finding-search" class="search-input" placeholder="Search findings by rule, title, path or keyword..." oninput="filterFindings()">
      <select id="severity-filter" class="filter-select" onchange="filterFindings()">
        <option value="all">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low & Info</option>
      </select>
    </div>

    <div class="findings-container" id="findings-list">
      {findings_html}
    </div>
  </div>

  <div id="tab-workflows" class="tab-content" style="display: none;">
    <div style="margin-bottom: 1.5rem;">
      <h3 style="margin-bottom: 0.4rem;">Observed & Inferred Workflows</h3>
      <p style="color: var(--text-muted); font-size: 0.9rem;">Reconstructed API routes, frontend-to-backend call links, and model inference pipelines.</p>
    </div>
    {workflows_html}
  </div>

  <div id="tab-dependencies" class="tab-content" style="display: none;">
    <div style="margin-bottom: 1.5rem;">
      <h3 style="margin-bottom: 0.4rem;">Declared Dependencies</h3>
      <p style="color: var(--text-muted); font-size: 0.9rem;">Parsed package requirements and lockfile entries across manifest files.</p>
    </div>
    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 1rem;">
      {dependencies_html}
    </div>
  </div>

  <div id="tab-coverage" class="tab-content" style="display: none;">
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.4rem;">
      <div style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.6rem;">
        <h3 style="margin-bottom: 1rem; font-size: 1.1rem;">Scan Inventory Summary</h3>
        <table style="width: 100%; border-collapse: collapse; font-size: 0.9rem;">
          <tr style="border-bottom: 1px solid rgba(255,255,255,0.06);"><td style="padding: 0.6rem 0; color: var(--text-muted);">Files Discovered</td><td style="text-align: right; font-weight: 700;">{coverage.get("files_discovered", 0)}</td></tr>
          <tr style="border-bottom: 1px solid rgba(255,255,255,0.06);"><td style="padding: 0.6rem 0; color: var(--text-muted);">Files Read</td><td style="text-align: right; font-weight: 700; color: #10b981;">{coverage.get("files_read", 0)}</td></tr>
          <tr style="border-bottom: 1px solid rgba(255,255,255,0.06);"><td style="padding: 0.6rem 0; color: var(--text-muted);">Sensitive Files Protected</td><td style="text-align: right; font-weight: 700; color: var(--accent-cyan);">{coverage.get("files_protected", 0)}</td></tr>
          <tr style="border-bottom: 1px solid rgba(255,255,255,0.06);"><td style="padding: 0.6rem 0; color: var(--text-muted);">Files Skipped</td><td style="text-align: right; font-weight: 700;">{coverage.get("files_skipped", 0)}</td></tr>
          <tr style="border-bottom: 1px solid rgba(255,255,255,0.06);"><td style="padding: 0.6rem 0; color: var(--text-muted);">Files Excluded by Policy</td><td style="text-align: right; font-weight: 700;">{coverage.get("files_excluded", 0)}</td></tr>
          <tr style="border-bottom: 1px solid rgba(255,255,255,0.06);"><td style="padding: 0.6rem 0; color: var(--text-muted);">Source Files Discovered</td><td style="text-align: right; font-weight: 700;">{coverage.get("source_files_discovered", 0)}</td></tr>
          <tr><td style="padding: 0.6rem 0; color: var(--text-muted);">Source Files Analyzed</td><td style="text-align: right; font-weight: 700; color: var(--accent-cyan);">{coverage.get("source_files_analyzed", 0)}</td></tr>
        </table>
      </div>

      <div style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.6rem;">
        <h3 style="margin-bottom: 1rem; font-size: 1.1rem;">Analysis Boundaries & Caveats</h3>
        <ul style="list-style: disc; padding-left: 1.2rem; color: var(--text-muted); font-size: 0.88rem; line-height: 1.6;">
          {limitations_html}
        </ul>
      </div>
    </div>
  </div>

  <div id="tab-exports" class="tab-content" style="display: none;">
    <form method="post" action="/export">
      <div class="export-settings-card">
        <h3 style="margin-bottom: 0.8rem; font-size: 1.05rem;">Export Configuration</h3>
        <div class="export-settings-grid">
          <div>
            <label style="font-size: 0.82rem; font-weight: 600; display: block; margin-bottom: 0.4rem;">Output Destination Directory</label>
            <input name="directory" required value="{export_dir_default}" placeholder="/path/to/exports">
          </div>
          <div>
            <label style="font-size: 0.82rem; font-weight: 600; display: block; margin-bottom: 0.4rem;">Presentation Theme</label>
            <select name="theme">
              <option value="midnight">Midnight (Dark Tech)</option>
              <option value="paper">Paper (Minimal Clean)</option>
              <option value="violet">Violet (Deep Neon)</option>
            </select>
          </div>
          <div>
            <label style="font-size: 0.82rem; font-weight: 600; display: block; margin-bottom: 0.4rem;">Slide Count</label>
            <input type="number" name="slide_count" min="2" max="30" value="8">
          </div>
        </div>

        <div class="checkbox-group">
          <label class="checkbox-label"><input type="checkbox" name="include" value="summary" checked> Executive Summary</label>
          <label class="checkbox-label"><input type="checkbox" name="include" value="findings" checked> Findings & Risks</label>
          <label class="checkbox-label"><input type="checkbox" name="include" value="coverage" checked> Coverage Metrics</label>
          <label class="checkbox-label"><input type="checkbox" name="include" value="architecture" checked> Architecture & UML</label>
        </div>
      </div>

      <div class="export-grid">
        <div class="export-card">
          <div>
            <div class="export-card-header">
              <div class="export-card-title">PlantUML & SVGs</div>
              <span class="export-badge">UML 2.5</span>
            </div>
            <p class="export-card-desc">Class, sequence, component, and deployment diagrams with dependency-free SVG renders.</p>
          </div>
          <button class="btn-export" name="kind" value="diagrams">
            <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
            <span>Export Diagrams</span>
          </button>
        </div>

        <div class="export-card">
          <div>
            <div class="export-card-header">
              <div class="export-card-title">Technical DOCX</div>
              <span class="export-badge">Word Document</span>
            </div>
            <p class="export-card-desc">Comprehensive engineering audit report with prioritized findings, evidence tables, and recommendations.</p>
          </div>
          <button class="btn-export" name="kind" value="technical_docx">
            <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
            <span>Generate DOCX</span>
          </button>
        </div>

        <div class="export-card">
          <div>
            <div class="export-card-header">
              <div class="export-card-title">Technical PDF</div>
              <span class="export-badge">Printable PDF</span>
            </div>
            <p class="export-card-desc">Publication-ready PDF document formatted for stakeholder distribution and engineering signoff.</p>
          </div>
          <button class="btn-export" name="kind" value="technical_pdf">
            <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
            <span>Generate PDF</span>
          </button>
        </div>

        <div class="export-card">
          <div>
            <div class="export-card-header">
              <div class="export-card-title">Academic DOCX</div>
              <span class="export-badge">8-Chapter Format</span>
            </div>
            <p class="export-card-desc">Structured according to IEEE academic specifications: Bonafide Certificate, Abstract, and 8 standard chapters.</p>
          </div>
          <button class="btn-export" name="kind" value="academic_docx">
            <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
            <span>Academic DOCX</span>
          </button>
        </div>

        <div class="export-card">
          <div>
            <div class="export-card-header">
              <div class="export-card-title">Academic PDF</div>
              <span class="export-badge">Academic PDF</span>
            </div>
            <p class="export-card-desc">Formal 8-chapter project report PDF with title page, certification, and technology stack mappings.</p>
          </div>
          <button class="btn-export" name="kind" value="academic_pdf">
            <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
            <span>Academic PDF</span>
          </button>
        </div>

        <div class="export-card">
          <div>
            <div class="export-card-header">
              <div class="export-card-title">Presentation Slides</div>
              <span class="export-badge">PowerPoint PPTX</span>
            </div>
            <p class="export-card-desc">Editable presentation deck with chosen theme, architecture cards, and executive summary slides.</p>
          </div>
          <button class="btn-export" name="kind" value="pptx">
            <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
            <span>Generate Presentation</span>
          </button>
        </div>
      </div>
    </form>
  </div>
</main>

<div id="new-audit-modal" class="modal-backdrop">
  <div class="modal-content">
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.4rem;">
      <h2 style="font-size: 1.3rem; font-weight: 800;">Run New Audit</h2>
      <button onclick="closeNewAuditModal()" style="background:none; border:none; color:var(--text-muted); cursor:pointer; font-size:1.4rem;">&times;</button>
    </div>
    <form method="post" action="/audit">
      <div style="margin-bottom: 1.2rem;">
        <label style="font-size: 0.84rem; font-weight: 600; display:block; margin-bottom: 0.4rem;">Target repository path</label>
        <input name="repository" required value="{repo_esc}" placeholder="/path/to/project">
      </div>
      <div style="margin-bottom: 1.2rem;">
        <label style="font-size: 0.84rem; font-weight: 600; display:block; margin-bottom: 0.4rem;">What does the system do?</label>
        <textarea name="purpose" placeholder="Describe system architecture and context...">{purpose_esc}</textarea>
      </div>
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem;">
        <div>
          <label style="font-size: 0.84rem; font-weight: 600; display:block; margin-bottom: 0.4rem;">Audience</label>
          <input name="audience" value="{audience_esc}" placeholder="Developers, Auditors">
        </div>
        <div>
          <label style="font-size: 0.84rem; font-weight: 600; display:block; margin-bottom: 0.4rem;">Scope</label>
          <select name="scope">
            <option value="full" {'selected' if scope_val == 'full' else ''}>Full Audit</option>
            <option value="security" {'selected' if scope_val == 'security' else ''}>Security & Credentials</option>
            <option value="ai_ml" {'selected' if scope_val == 'ai_ml' else ''}>AI/ML Risk</option>
            <option value="architecture" {'selected' if scope_val == 'architecture' else ''}>Architecture</option>
          </select>
        </div>
      </div>
      <div style="display: flex; gap: 0.8rem; justify-content: flex-end;">
        <button type="button" onclick="closeNewAuditModal()" class="btn-sm" style="padding: 0.7rem 1.2rem;">Cancel</button>
        <button type="submit" class="btn-sm btn-primary-sm" style="padding: 0.7rem 1.4rem;">Execute Audit</button>
      </div>
    </form>
  </div>
</div>

<script>
function switchTab(name, btn) {{
  document.querySelectorAll('.tab-content').forEach(el => el.style.display = 'none');
  document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
  document.getElementById('tab-' + name).style.display = 'block';
  btn.classList.add('active');
}}
function filterFindings() {{
  const query = document.getElementById('finding-search').value.toLowerCase();
  const severity = document.getElementById('severity-filter').value;
  const cards = document.querySelectorAll('.finding-card');
  cards.forEach(card => {{
    const cardSev = card.getAttribute('data-severity');
    const cardText = card.getAttribute('data-text');
    const matchesSev = (severity === 'all') ||
      (severity === 'low' && (cardSev === 'low' || cardSev === 'info')) ||
      (cardSev === severity);
    const matchesQuery = !query || cardText.includes(query);
    if (matchesSev && matchesQuery) {{
      card.style.display = 'block';
    }} else {{
      card.style.display = 'none';
    }}
  }});
}}
function openNewAuditModal() {{
  document.getElementById('new-audit-modal').classList.add('open');
}}
function closeNewAuditModal() {{
  document.getElementById('new-audit-modal').classList.remove('open');
}}
</script>
</body>
</html>"""


def create_server(result=None, host="127.0.0.1", port=8765):
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Dashboard binds to loopback only")
    state = {"result": result}

    class Handler(BaseHTTPRequestHandler):
        def _allowed_origin(self):
            host_header = urlsplit("//" + self.headers.get("Host", "")).hostname or ""
            host_header = host_header.lower()
            if host_header not in {"127.0.0.1", "localhost", "::1"}:
                return False
            origin = self.headers.get("Origin")
            return not origin or origin in {
                f"http://{host}:{server.server_port}",
                f"http://localhost:{server.server_port}",
                f"http://127.0.0.1:{server.server_port}",
            }

        def do_GET(self):
            if self.path == "/api/audit":
                if state["result"] is None:
                    body = b'{"error":"No audit has been run"}'
                    self.send_response(404)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                payload = state["result"].to_dict()
                body = json.dumps(payload, indent=2).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
            elif self.path == "/":
                if state["result"] is None:
                    body = _render_onboarding_html().encode("utf-8")
                else:
                    body = _render_dashboard_html(state["result"].to_dict()).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
            else:
                body = b"Not found"
                self.send_response(404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if not self._allowed_origin():
                self.send_error(403, "Local origin required")
                return
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 65536:
                self.send_error(413, "Request too large")
                return
            form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            value = lambda key, default="": form.get(key, [default])[0]
            try:
                if self.path == "/audit":
                    from snowlint.core.engine import analyze_repository
                    result = analyze_repository(
                        value("repository"),
                        system_purpose=value("purpose"),
                        intended_audience=value("audience"),
                        audit_scope=value("scope", "full"),
                    )
                    state["result"] = result
                    self.send_response(303)
                    self.send_header("Location", "/")
                    self.end_headers()
                    return
                if self.path == "/export":
                    if state["result"] is None:
                        self.send_error(409, "Run an audit first")
                        return
                    from pathlib import Path
                    from snowlint.diagrams import write_diagrams
                    from snowlint.exports import write_docx, write_pdf, write_pptx
                    directory = Path(value("directory")).expanduser().resolve()
                    directory.mkdir(parents=True, exist_ok=True)
                    kind = value("kind")
                    if kind == "diagrams":
                        write_diagrams(state["result"], directory / "uml")
                    elif kind == "technical_docx":
                        write_docx(state["result"], directory / "technical-audit.docx")
                    elif kind == "technical_pdf":
                        write_pdf(state["result"], directory / "technical-audit.pdf")
                    elif kind == "academic_docx":
                        write_docx(state["result"], directory / "academic-report.docx", "academic")
                    elif kind == "academic_pdf":
                        write_pdf(state["result"], directory / "academic-report.pdf", "academic")
                    elif kind == "pptx":
                        write_pptx(
                            state["result"],
                            directory / "snowlint.pptx",
                            theme=value("theme", "midnight"),
                            slide_count=int(value("slide_count", "8")),
                            include=form.get("include") or None,
                        )
                    else:
                        self.send_error(400, "Unknown export kind")
                        return
                    self.send_response(303)
                    self.send_header("Location", "/")
                    self.end_headers()
                    return
                self.send_error(404)
            except (ValueError, OSError, RuntimeError) as error:
                body = html.escape(str(error)).encode("utf-8")
                self.send_response(400)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer((host, port), Handler)
    return server


def serve(result=None, host="127.0.0.1", port=8765):
    server = create_server(result, host, port)
    print(f"Snowlint dashboard: http://{host}:{server.server_port} (local only; Ctrl+C to stop)")
    try:
        server.serve_forever()
    finally:
        server.server_close()
