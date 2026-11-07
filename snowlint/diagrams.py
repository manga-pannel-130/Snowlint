"""PlantUML sources derived solely from the canonical AuditResult."""
from __future__ import annotations
import re
from xml.sax.saxutils import escape


def _safe(value):
    return re.sub(r"[^A-Za-z0-9_]", "_", value)


def _quoted(value):
    # Keep repository-controlled labels on one safe PlantUML statement.
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\r", " ").replace("\n", " ")


def plantuml(result, kind="component"):
    lines = ["@startuml", "hide empty members", "skinparam componentStyle rectangle"]
    nodes = list(result.nodes)
    rels = list(result.relationships)
    if kind == "class":
        for n in nodes:
            if n.kind == "class":
                lines.append(f'class "{_quoted(n.name)}" as {_safe(n.id)} {{')
                lines.extend(f"  {attribute}" for attribute in n.attributes)
                lines.extend(f"  {method}()" for method in n.methods)
                lines.append("}")
        for r in rels:
            if r.kind in {"contains_method", "inherits", "implements"}:
                lines.append(f"{_safe(r.source)} ..> {_safe(r.target)} : {r.kind}")
    elif kind == "sequence":
        interactions = [r for r in rels if r.kind in {"calls_integration", "calls_api_route", "calls_ml_operation"}]
        participants = {}
        for relation in interactions:
            participants[relation.source] = next((n.name for n in nodes if n.id == relation.source), relation.source)
            participants[relation.target] = next((n.name for n in nodes if n.id == relation.target), relation.target)
        if not interactions:
            lines.append('note "No inter-component call sequence could be established from observed static evidence."')
        else:
            for identifier, name in participants.items():
                lines.append(f'participant "{_quoted(name)}" as {_safe(identifier)}')
            for relation in interactions:
                lines.append(f"{_safe(relation.source)} -> {_safe(relation.target)} : {relation.kind}")
    elif kind == "deployment":
        configs = [n for n in nodes if n.kind in {"deployment_config", "deployment_service"}]
        if not configs:
            lines.append('note "Deployment environment and topology are unknown: no recognized deployment manifest was observed."')
        else:
            lines.append('node "Deployment configuration evidence" {')
            for n in configs:
                kind_name = "node" if n.kind == "deployment_service" else "artifact"
                lines.append(f'  {kind_name} "{_quoted(n.name)}" as {_safe(n.id)}')
            lines.append("}")
            for relation in rels:
                if relation.kind == "declares_service":
                    lines.append(f"{_safe(relation.source)} --> {_safe(relation.target)} : declares [observed]")
    else:
        for n in nodes:
            lines.append(f'component "{_quoted(n.name)}" as {_safe(n.id)}')
        for r in rels:
            marker = "-->" if r.confidence == "observed" else "..>"
            lines.append(f"{_safe(r.source)} {marker} {_safe(r.target)} : {r.kind} [{r.confidence}]")
    lines.append("@enduml")
    return "\n".join(lines) + "\n"


def write_diagrams(result, output_dir):
    from pathlib import Path
    target = Path(output_dir); target.mkdir(parents=True, exist_ok=True)
    outputs = {}
    for kind in ("class", "sequence", "component", "deployment"):
        path = target / f"{kind}.puml"
        path.write_text(plantuml(result, kind), encoding="utf-8")
        outputs[kind] = str(path)
        svg = target / f"{kind}.svg"
        svg.write_text(_render_svg(result, kind), encoding="utf-8")
        outputs[kind + "_svg"] = str(svg)
    return outputs


def _render_svg(result, kind):
    """Small dependency-free diagram renderer for portable SVG exports."""
    nodes = list(result.nodes)[:16]
    width, height = 1000, 180 + max(1, (len(nodes) + 3) // 4) * 120
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
             '<rect width="100%" height="100%" fill="#f8fafc"/>',
             '<defs><marker id="arrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto"><path d="M0,0 L0,6 L9,3 z" fill="#475569"/></marker></defs>',
             f'<text x="30" y="38" font-family="sans-serif" font-size="24" font-weight="bold">Snowlint {escape(kind.title())} Diagram</text>']
    positions = {}
    if kind == "sequence":
        interactions = [r for r in result.relationships if r.kind in {"calls_integration", "calls_api_route", "calls_ml_operation"}]
        names = list(dict.fromkeys([r.source for r in interactions] + [r.target for r in interactions]))
        names = names[:3]
        if not names: names = ["Unknown sequence"]
        for i, name in enumerate(names):
            x = 130 + i * (700 // max(1, len(names)-1)) if len(names) > 1 else 480
            parts += [f'<rect x="{x-75}" y="65" width="150" height="42" rx="5" fill="#dbeafe" stroke="#2563eb"/>',
                      f'<text x="{x}" y="92" text-anchor="middle" font-family="sans-serif">{escape(next((n.name for n in nodes if n.id == name), name)[:20])}</text>',
                      f'<path d="M{x} 107 V{height-25}" stroke="#64748b" stroke-dasharray="5 5"/>']
        if interactions and len(names) > 1:
            parts.append(f'<path d="M205 145 H405" stroke="#0f172a" marker-end="url(#arrow)"/><text x="305" y="137" text-anchor="middle" font-size="12">observed/inferred calls</text>')
        else:
            parts.append('<text x="500" y="160" text-anchor="middle" font-family="sans-serif">No call sequence established from static evidence</text>')
    elif kind == "deployment":
        configs = [n for n in nodes if n.kind in {"deployment_config", "deployment_service"}]
        if not configs:
            parts.append('<text x="500" y="150" text-anchor="middle" font-family="sans-serif">Deployment topology unknown</text>')
        else:
            for i, node in enumerate(configs[:8]):
                x, y = 80 + (i % 4) * 230, 80 + (i // 4) * 110
                parts += [f'<rect x="{x}" y="{y}" width="180" height="60" fill="#e0f2fe" stroke="#0369a1"/>',
                          f'<text x="{x+8}" y="{y+34}" font-family="sans-serif">{escape(node.name[:26])}</text>']
    else:
        for i, node in enumerate(nodes):
            x, y = 35 + (i % 4) * 245, 75 + (i // 4) * 120
            positions[node.id] = (x, y)
        for rel in result.relationships:
            if rel.source in positions and rel.target in positions:
                x1,y1=positions[rel.source]; x2,y2=positions[rel.target]
                dash = ' stroke-dasharray="5 4"' if rel.confidence != "observed" else ""
                parts.append(f'<path d="M{x1+190} {y1+35} L{x2} {y2+35}" stroke="#475569" marker-end="url(#arrow)"{dash}/>')
                parts.append(f'<text x="{(x1+x2+190)//2}" y="{(y1+y2)//2+30}" font-size="11" fill="#334155">{escape(rel.kind)}</text>')
        for node in nodes:
            x,y=positions[node.id]
            label = f"{node.kind}: {node.name}"[:34]
            parts += [f'<rect x="{x}" y="{y}" width="190" height="70" rx="5" fill="#e0f2fe" stroke="#0369a1"/>',
                      f'<text x="{x+10}" y="{y+38}" font-family="sans-serif" font-size="13">{escape(label)}</text>']
    parts += [f'<text x="25" y="{height-8}" font-size="11" fill="#475569">Relationships show observed repository evidence only; missing edges are unknown.</text>', '</svg>']
    return "\n".join(parts)
