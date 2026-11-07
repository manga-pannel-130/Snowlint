import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from snowlint.core.engine import analyze_repository
from snowlint.exports import write_docx, write_pdf, write_pptx

HAS_DOCS = all(importlib.util.find_spec(name) for name in ("docx", "pptx", "reportlab", "pypdf"))


@unittest.skipUnless(HAS_DOCS, "Optional export dependencies are not installed in this interpreter")
class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "app.py").write_text("class Api:\n    def get(self):\n        return 1\n", encoding="utf-8")
        self.result = analyze_repository(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_docx_profiles_are_distinct_and_have_expected_chapters(self):
        from docx import Document
        tech = self.root / "tech.docx"
        academic = self.root / "academic.docx"
        write_docx(self.result, tech)
        write_docx(self.result, academic, "academic", metadata={"authors": "Sample Author"})
        tech_text = "\n".join(p.text for p in Document(tech).paragraphs)
        academic_text = "\n".join(p.text for p in Document(academic).paragraphs)
        self.assertIn("Prioritized findings", tech_text)
        for chapter in ("BONAFIDE CERTIFICATE", "ABSTRACT", "1 INTRODUCTION", "8 REFERENCES"):
            self.assertIn(chapter, academic_text)
        self.assertIn("Sample Author", academic_text)

    def test_pdf_contains_text_and_pptx_respects_slide_count_and_theme(self):
        from pypdf import PdfReader
        from pptx import Presentation
        pdf = self.root / "report.pdf"
        deck = self.root / "report.pptx"
        write_pdf(self.result, pdf, "academic", metadata={"authors": "Sample Author"})
        write_pptx(self.result, deck, theme="paper", slide_count=4)
        self.assertGreater(len(PdfReader(pdf).pages), 3)
        text = "".join(p.extract_text() or "" for p in PdfReader(pdf).pages)
        self.assertIn("RESULTS AND DISCUSSIONS", text)
        presentation = Presentation(deck)
        self.assertEqual(len(presentation.slides), 4)
        self.assertIn("UML views", " ".join(shape.text for shape in presentation.slides[1].shapes if shape.has_text_frame))


if __name__ == "__main__":
    unittest.main()
