"""Report and editable presentation exports over the canonical AuditResult."""
from pathlib import Path
from html import escape

THEMES = {
    "midnight": {"bg": "14213D", "panel": "213654", "accent": "00B4D8", "text": "FFFFFF", "muted": "C6D2E2"},
    "paper": {"bg": "F7F4EA", "panel": "E7E2D6", "accent": "315C4B", "text": "1D2622", "muted": "52625A"},
    "violet": {"bg": "211A35", "panel": "352A50", "accent": "B794F4", "text": "FFFFFF", "muted": "D6C8EB"},
}

ACADEMIC_CHAPTERS = (
    "1 INTRODUCTION", "2 LITERATURE SURVEY", "3 SYSTEM ARCHITECTURE",
    "4 SYSTEM REQUIREMENTS", "5 SYSTEM DESIGN AND IMPLEMENTATION",
    "6 RESULTS AND DISCUSSIONS", "7 CONCLUSION AND FUTURE WORK", "8 REFERENCES",
)


def _academic_sections(result):
    repo = Path(result.repository).name
    return [
        ("1 INTRODUCTION", [
            ("1.1 BACKGROUND OF THE PROJECT DOMAIN", [f"The audited repository is {repo}. The stated purpose is {result.context.get('system_purpose') or 'not provided'}."]),
            ("1.2 PROBLEM STATEMENT", ["An unfamiliar repository needs an evidence-backed account of its structure, dependencies, risks, and analysis limits."]),
            ("1.3 OBJECTIVES OF THE PROJECT", ["Inventory files and declared dependencies.", "Extract symbols and statically observed relationships.", "Report bounded findings with evidence and coverage."]),
            ("1.4 APPLICATIONS", ["Repository onboarding and engineering review."]),
        ]),
        ("2 LITERATURE SURVEY", [
            ("2.1 SUMMARY OF THE LITERATURE SURVEY", ["No verified literature sources were supplied. This report does not invent references or claims."]),
            ("2.2 FINDINGS FROM THE SURVEY", ["A literature synthesis requires supplied and reviewed sources."]),
        ]),
        ("3 SYSTEM ARCHITECTURE", [
            ("3.1 SYSTEM DIAGRAM", [f"The canonical model contains {len(result.nodes)} nodes and {len(result.relationships)} relationships. UML source and rendered diagrams are exported separately."]),
            ("3.2 EXPLANATION", ["Observed relationships come from source declarations. Inferred relationships are labelled; unknown behavior remains unknown."]),
        ]),
        ("4 SYSTEM REQUIREMENTS", [
            ("4.1 HARDWARE REQUIREMENTS", ["Hardware requirements were not measured by static analysis."]),
            ("4.2 SOFTWARE REQUIREMENTS", [f"Parsed dependency manifests: {len(result.dependencies)}. Declared versions do not prove installation succeeds."]),
            ("4.3 TECHNOLOGY STACK MAPPING", [f"Source extensions: {', '.join(sorted({Path(n.path).suffix for n in result.nodes if n.path and n.kind == 'file'})) or 'none'}"]),
        ]),
        ("5 SYSTEM DESIGN AND IMPLEMENTATION", [
            ("5.1 PROJECT MODULES", [f"Source paths: {', '.join(sorted({n.path for n in result.nodes if n.path and n.kind == 'file'})[:80]) or 'none'}"]),
            ("5.2 ALGORITHM", ["Snowlint performs bounded discovery, safe reads, static extraction, deterministic checks, evidence verification, and canonical serialization. It does not execute target code."]),
            ("5.3 TESTING AND EVALUATION METRICS", ["The target project's tests were not executed. Source analysis coverage is not behavioral test coverage."]),
        ]),
        ("6 RESULTS AND DISCUSSIONS", [
            ("6.1 AUDIT SUMMARY", [f"Findings: {len(result.findings)}. Files read: {result.coverage.files_read}. Source analyzed: {result.coverage.source_files_analyzed}/{result.coverage.source_files_discovered}."]),
            ("6.2 FINDINGS", [f"{f.severity.value.upper()} - {f.title}: {f.summary} Evidence: {', '.join(e.path + (':' + str(e.line_start) if e.line_start else '') for e in f.evidence)}. Recommendation: {f.recommendation}" for f in result.findings] or ["No findings from enabled checks. This is not proof that defects are absent."]),
            ("6.3 LIMITATIONS", list(result.coverage.limitations) or ["No additional limitations recorded."]),
        ]),
        ("7 CONCLUSION AND FUTURE WORK", [
            ("7.1 CONCLUSION", ["This report records static evidence and its limits; it does not certify runtime correctness or production readiness."]),
            ("7.2 FUTURE WORK", ["Validate rule precision on benchmark repositories, broaden syntax support, and improve workflow reconstruction."]),
        ]),
        ("8 REFERENCES", [("8.1 REFERENCES", ["No references were supplied. Add only sources verified by the project team."])]),
    ]


def _technical_sections(result):
    deps = [f"{d['name']} {d.get('version') or d.get('constraint') or '(version unspecified)'} - {source}"
            for source, records in result.dependencies.items() for d in records]
    findings = [f"{f.severity.value.upper()} | confidence {f.confidence.value} | {f.title}. {f.summary} Recommendation: {f.recommendation} Evidence: {', '.join(e.path + (':' + str(e.line_start) if e.line_start else '') for e in f.evidence)}"
                for f in result.findings]
    return [
        ("Executive summary", [f"{len(result.findings)} findings; {result.coverage.source_files_analyzed} source files analyzed.", f"Scope: {result.context.get('audit_scope', 'full')}. Assessment: {result.scores.get('status', 'unknown')}."]),
        ("Repository overview", [f"Root: {result.repository}", f"Files discovered {result.coverage.files_discovered}; read {result.coverage.files_read}; protected {result.coverage.files_protected}; skipped {result.coverage.files_skipped}."]),
        ("Architecture and workflows", [f"{len(result.nodes)} nodes and {len(result.relationships)} relationships.", *[f"{w.name}: {len(w.steps)} steps, {w.confidence} confidence." for w in result.workflows]] or ["No workflow was reconstructed from available evidence."]),
        ("Dependencies", deps or ["No dependency declarations were parsed."]),
        ("Prioritized findings", findings or ["No findings from enabled checks. Unimplemented dimensions remain unknown."]),
        ("Coverage and limitations", [f"Source analyzed {result.coverage.source_files_analyzed}/{result.coverage.source_files_discovered}.", *result.coverage.limitations, *result.scores.get("notes", [])]),
    ]


def write_docx(result, output, profile="technical", title=None, metadata=None):
    try:
        from docx import Document
        from docx.shared import Inches, Pt
        from docx.enum.text import WD_ALIGN_PARAGRAPH
    except ImportError as e:
        raise RuntimeError("Install Snowlint's document dependencies: pip install -e .") from e
    if profile not in {"technical", "academic"}: raise ValueError("profile must be technical or academic")
    metadata = metadata or {}
    doc = Document()
    section = doc.sections[0]
    section.page_width, section.page_height = Inches(8.27), Inches(11.69)
    section.top_margin = section.bottom_margin = Inches(.8)
    section.left_margin = section.right_margin = Inches(.9)
    normal = doc.styles["Normal"]
    normal.font.name = "Times New Roman" if profile == "academic" else "Aptos"
    normal.font.size = Pt(11)
    normal.paragraph_format.space_after = Pt(6)
    title_style = doc.styles["Title"]
    if title_style.element.pPr is not None:
        border = title_style.element.pPr.find("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}pBdr")
        if border is not None: title_style.element.pPr.remove(border)
    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    footer.add_run("Snowlint static audit  |  ")
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    field = OxmlElement("w:fldSimple"); field.set(qn("w:instr"), "PAGE")
    footer._p.append(field)
    doc.core_properties.title = title or ("Snowlint Technical Engineering Audit" if profile == "technical" else "Snowlint Project Report")
    doc.core_properties.subject = "Repository static audit"
    doc.core_properties.author = metadata.get("author", "Snowlint")
    if profile == "academic":
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.add_run((title or "SNOWLINT REPOSITORY AUDIT") + "\n").bold = True
        p.add_run("A PROJECT REPORT\n\nSubmitted by\n")
        p.add_run(metadata.get("authors", "Not provided") + "\n\n")
        p.add_run("in partial fulfillment for the award of\n" + metadata.get("degree", "Not provided") + "\n\n")
        p.add_run(metadata.get("institution", "Not provided") + "\n")
        p.add_run(metadata.get("department", "Not provided") + "\n")
        p.add_run(metadata.get("submission_date", result.audited_at[:10]))
        doc.add_page_break()
        doc.add_heading("BONAFIDE CERTIFICATE", 1)
        doc.add_paragraph("Project: " + metadata.get("project_title", title or "Snowlint Repository Audit"))
        doc.add_paragraph("Authors: " + metadata.get("authors", "Not provided"))
        doc.add_paragraph("Supervisor: " + metadata.get("supervisor", "Not provided"))
        doc.add_paragraph("Certificate approval, supervisor identity, and examination details require institutional verification.")
        doc.add_page_break()
        doc.add_heading("ACKNOWLEDGEMENT", 1)
        doc.add_paragraph(metadata.get("acknowledgement", "Not provided"))
        doc.add_page_break()
        doc.add_heading("ABSTRACT", 1)
        doc.add_paragraph(f"Static audit of {Path(result.repository).name}: {result.coverage.source_files_analyzed}/{result.coverage.source_files_discovered} source files analyzed and {len(result.findings)} findings. Static analysis does not prove runtime correctness or production readiness.")
        doc.add_page_break()
        doc.add_heading("TABLE OF CONTENTS", 1)
        toc = doc.add_paragraph()
        field = OxmlElement("w:fldSimple")
        field.set(qn("w:instr"), 'TOC \\o "1-2" \\h \\z \\u')
        toc_run = OxmlElement("w:r"); toc_text = OxmlElement("w:t"); toc_text.text = "Open in Word and update the table of contents field."
        toc_run.append(toc_text); field.append(toc_run); toc._p.append(field)
        doc.add_page_break()
        sections = _academic_sections(result)
    else:
        doc.add_heading(title or "Snowlint Technical Engineering Audit", 0)
        doc.add_paragraph(f"Repository: {result.repository}\nAudit time: {result.audited_at}\nPurpose: {result.context.get('system_purpose') or 'Not provided'}\nAudience: {result.context.get('intended_audience') or 'Not provided'}")
        doc.add_paragraph("This report is based on static repository evidence and is not a production-readiness certification.")
        sections = _technical_sections(result)
    for heading, subsections in sections:
        doc.add_heading(heading, 1)
        if profile == "academic":
            for subheading, paragraphs in subsections:
                doc.add_heading(subheading, 2)
                for paragraph in paragraphs: doc.add_paragraph(paragraph)
        else:
            for paragraph in subsections: doc.add_paragraph(paragraph, style="List Bullet")
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    doc.save(output)


def write_pdf(result, output, profile="technical", title=None, metadata=None):
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
    except ImportError as e:
        raise RuntimeError("Install Snowlint's document dependencies: pip install -e .") from e
    if profile not in {"technical", "academic"}: raise ValueError("profile must be technical or academic")
    metadata = metadata or {}
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SnowTitle", parent=styles["Title"], fontSize=23, leading=29, alignment=TA_CENTER, textColor=colors.HexColor("#14213D"), spaceAfter=18))
    styles.add(ParagraphStyle(name="SnowH1", parent=styles["Heading1"], fontSize=16, leading=20, textColor=colors.HexColor("#14213D"), spaceBefore=14, spaceAfter=7, keepWithNext=True))
    styles.add(ParagraphStyle(name="SnowH2", parent=styles["Heading2"], fontSize=12, leading=15, textColor=colors.HexColor("#315C4B"), spaceBefore=9, spaceAfter=4, keepWithNext=True))
    story = []
    if profile == "academic":
        story += [Spacer(1, 30*mm), Paragraph(escape(title or "SNOWLINT REPOSITORY AUDIT"), styles["SnowTitle"]), Paragraph("A PROJECT REPORT", styles["Heading2"]), Spacer(1, 15*mm),
                  Paragraph("Submitted by<br/>" + escape(metadata.get("authors", "Not provided")), styles["BodyText"]), Spacer(1, 12*mm),
                  Paragraph("Degree<br/>" + escape(metadata.get("degree", "Not provided")), styles["BodyText"]), Spacer(1, 12*mm),
                  Paragraph(escape(metadata.get("institution", "Not provided")) + "<br/>" + escape(metadata.get("department", "Not provided")), styles["BodyText"]),
                  Paragraph(escape(metadata.get("submission_date", result.audited_at[:10])), styles["BodyText"]), PageBreak()]
        front = [
            ("BONAFIDE CERTIFICATE", "Project, authors, and supervisor: " + metadata.get("project_title", title or "Snowlint Repository Audit") + " | " + metadata.get("authors", "Not provided") + " | " + metadata.get("supervisor", "Not provided") + ". Certificate details require institutional verification."),
            ("ACKNOWLEDGEMENT", metadata.get("acknowledgement", "Not provided")),
            ("ABSTRACT", f"Static audit of {Path(result.repository).name}: {result.coverage.source_files_analyzed}/{result.coverage.source_files_discovered} source files analyzed; {len(result.findings)} findings. Static analysis does not prove runtime correctness or production readiness."),
            ("TABLE OF CONTENTS", "<br/>".join(ACADEMIC_CHAPTERS)),
        ]
        for heading, text in front:
            story += [Paragraph(heading, styles["SnowH1"]), Paragraph(escape(text).replace("&lt;br/&gt;", "<br/>"), styles["BodyText"]), PageBreak()]
        sections = _academic_sections(result)
    else:
        story = [Paragraph(escape(title or "Snowlint Technical Engineering Audit"), styles["SnowTitle"]),
                 Paragraph("Repository: " + escape(result.repository) + "<br/>Audit time: " + escape(result.audited_at), styles["BodyText"]), Spacer(1, 7*mm)]
        sections = _technical_sections(result)
    for heading, subsections in sections:
        story.append(Paragraph(escape(heading), styles["SnowH1"]))
        if profile == "academic":
            for subheading, paragraphs in subsections:
                story.append(Paragraph(escape(subheading), styles["SnowH2"]))
                for text in paragraphs: story.append(Paragraph(escape(str(text)), styles["BodyText"]))
        else:
            for text in subsections: story.append(Paragraph(escape(str(text)), styles["BodyText"]))
    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#65758B"))
        canvas.drawString(18*mm, 12*mm, "Snowlint static audit - evidence and coverage limitations apply")
        canvas.drawRightString(A4[0]-18*mm, 12*mm, str(doc.page))
        canvas.restoreState()
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    SimpleDocTemplate(str(output), pagesize=A4, rightMargin=20*mm, leftMargin=20*mm, topMargin=18*mm, bottomMargin=22*mm, title=title or "Snowlint Audit").build(story, onFirstPage=footer, onLaterPages=footer)


def write_pptx(result, output, *, theme="midnight", slide_count=8, include=None):
    try: from pptx import Presentation
    except ImportError as e: raise RuntimeError("Install Snowlint's presentation dependencies: pip install -e .") from e
    if theme not in THEMES: raise ValueError(f"Unknown theme {theme}; choose from {', '.join(THEMES)}")
    if not 2 <= slide_count <= 30: raise ValueError("slide_count must be between 2 and 30")
    from pptx.dml.color import RGBColor
    from pptx.enum.shapes import MSO_SHAPE, MSO_CONNECTOR
    from pptx.util import Inches, Pt
    prs = Presentation()
    prs.slide_width, prs.slide_height = Inches(13.333), Inches(7.5)
    palette = THEMES[theme]
    options = set(include or ["summary", "findings", "coverage", "architecture"])
    def base(title):
        slide = prs.slides.add_slide(prs.slide_layouts[6])
        slide.background.fill.solid(); slide.background.fill.fore_color.rgb = RGBColor.from_string(palette["bg"])
        heading = slide.shapes.add_textbox(Inches(.65), Inches(.45), Inches(12), Inches(.65)).text_frame.paragraphs[0]
        heading.text = title; heading.font.size = Pt(32); heading.font.bold = True; heading.font.color.rgb = RGBColor.from_string(palette["accent"])
        return slide
    def text_slide(title, lines):
        slide = base(title)
        frame = slide.shapes.add_textbox(Inches(.85), Inches(1.35), Inches(11.6), Inches(5.5)).text_frame
        frame.word_wrap = True
        for i, line in enumerate(lines[:9]):
            p = frame.paragraphs[0] if i == 0 else frame.add_paragraph()
            p.text = str(line)[:500]; p.font.size = Pt(16 if len(lines) > 3 else 19); p.font.color.rgb = RGBColor.from_string(palette["text"]); p.space_after = Pt(12)
        return slide
    def box(slide, x, y, w, h, label):
        shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(x), Inches(y), Inches(w), Inches(h))
        shape.fill.solid(); shape.fill.fore_color.rgb = RGBColor.from_string(palette["panel"]); shape.line.color.rgb = RGBColor.from_string(palette["accent"])
        p = shape.text_frame.paragraphs[0]; p.text = label[:100]; p.font.size = Pt(10); p.font.color.rgb = RGBColor.from_string(palette["text"])
    def uml_slide():
        slide = base("UML views from repository evidence")
        panels = [("Class", .45, 1.35), ("Sequence", 6.8, 1.35), ("Component", .45, 4), ("Deployment", 6.8, 4)]
        for title, x, y in panels:
            p = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(5.8), Inches(.32)).text_frame.paragraphs[0]
            p.text = title; p.font.size = Pt(14); p.font.bold = True; p.font.color.rgb = RGBColor.from_string(palette["accent"])
            if title == "Class":
                items = [n for n in result.nodes if n.kind == "class"][:3]
                if not items: box(slide, x+.1, y+.55, 5.4, .75, "No classes observed")
                for j, n in enumerate(items): box(slide, x+.1+j*1.8, y+.55, 1.65, .95, n.name + "\n" + ", ".join((*n.attributes[:2], *n.methods[:2])))
            elif title == "Sequence":
                items = [r for r in result.relationships if r.kind in {"calls_integration", "calls_api_route", "calls_ml_operation"}][:3]
                if not items: box(slide, x+.1, y+.55, 5.4, .75, "No call sequence established; behavior remains unknown")
                for j, r in enumerate(items): box(slide, x+.1+j*1.8, y+.55, 1.65, .95, r.source.split(":")[-1] + " to " + r.target.split(":")[-1] + "\n" + r.kind + " (" + r.confidence + ")")
            elif title == "Component":
                edges = [r for r in result.relationships if r.kind in {"imports", "calls_api_route", "declares_service"}][:2]
                if not edges: box(slide, x+.1, y+.55, 5.4, .75, "No component dependency edge was extracted")
                for j, edge in enumerate(edges):
                    left_name = next((n.name for n in result.nodes if n.id == edge.source), edge.source.split(":")[-1])
                    right_name = next((n.name for n in result.nodes if n.id == edge.target), edge.target.split(":")[-1])
                    box(slide, x+.1, y+.55+j*.55, 2.0, .42, left_name)
                    slide.shapes.add_connector(MSO_CONNECTOR.STRAIGHT, Inches(x+2.15), Inches(y+.76+j*.55), Inches(x+3.15), Inches(y+.76+j*.55))
                    box(slide, x+3.2, y+.55+j*.55, 2.0, .42, right_name + " [" + edge.confidence + "]")
            else:
                items = [n for n in result.nodes if n.kind in {"deployment_config", "deployment_service"}][:3]
                if not items: box(slide, x+.1, y+.55, 5.4, .75, "Deployment topology unknown; no recognized manifest found")
                for j, n in enumerate(items): box(slide, x+.1+j*1.8, y+.55, 1.65, .8, n.name)
        note = slide.shapes.add_textbox(Inches(.65), Inches(7.05), Inches(12), Inches(.25)).text_frame.paragraphs[0]
        note.text = "Observed and inferred relationships are labelled; missing evidence is unknown."; note.font.size = Pt(9); note.font.color.rgb = RGBColor.from_string(palette["muted"])
    cover = text_slide("Snowlint Repository Audit", [Path(result.repository).name, f"{len(result.findings)} findings | {result.coverage.source_files_analyzed} source files analyzed", result.audited_at])
    cover_title = cover.shapes[0].text_frame.paragraphs[0]
    cover_title.font.size = Pt(42)
    if "architecture" in options: uml_slide()
    candidates = []
    if "summary" in options:
        candidates.append(("Audit summary", [f"Scope: {result.context.get('audit_scope', 'full')}", f"Assessment: {result.scores.get('status', 'unknown')}", "Overall quality score: unknown for this broad audit.", "Static audit; no production-readiness certification."]))
        extensions = {}
        for node in result.nodes:
            if node.kind == "file" and node.path:
                ext = Path(node.path).suffix or "[no extension]"; extensions[ext] = extensions.get(ext, 0) + 1
        candidates.append(("Repository inventory", [f"{ext}: {count} files" for ext, count in sorted(extensions.items())] or ["No source inventory"]))
        deps = [f"{d['name']} {d.get('version') or d.get('constraint') or '(version unspecified)'}" for records in result.dependencies.values() for d in records]
        candidates.append(("Declared dependencies", deps or ["No dependencies parsed from recognized manifests"]))
    if "architecture" in options:
        observed = [r for r in result.relationships if r.kind in {"imports", "calls_api_route", "calls_integration", "calls_ml_operation", "declares_service"}]
        edges = [f"{r.source.split(':')[-1]} -> {r.target.split(':')[-1]} ({r.kind}; {r.confidence})" for r in observed[:7]]
        candidates.append(("Architecture evidence", [f"{len(result.nodes)} nodes | {len(result.relationships)} relationships", *edges] or ["No workflow or dependency edges established from evidence."]))
    if "findings" in options:
        candidates.extend((f"{f.severity.value.upper()} | {f.title}", [f.summary, f"Confidence: {f.confidence.value}", f"Recommendation: {f.recommendation}", "Evidence: " + ", ".join(e.path + (":" + str(e.line_start) if e.line_start else "") for e in f.evidence)]) for f in result.findings)
    if "coverage" in options: candidates.append(("Coverage and limits", [f"Source analyzed: {result.coverage.source_files_analyzed}/{result.coverage.source_files_discovered}", *result.coverage.limitations[:4]]))
    if "coverage" in options:
        unknown = result.scores.get("unknown_dimensions", ["architecture", "testing", "performance", "AI/ML quality"])
        candidates.append(("Unknown dimensions", [f"Not assessed: {', '.join(unknown)}", "A missing finding means the enabled static checks did not report a pattern; it does not establish that the system is healthy."]))
    for title, body in candidates[:max(0, slide_count-len(prs.slides))]: text_slide(title, body)
    while len(prs.slides) < slide_count: text_slide("Review notes", ["Add verified context and review evidence before formal distribution."])
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    prs.save(output)
