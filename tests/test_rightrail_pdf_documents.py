from __future__ import annotations

import hashlib
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

from pypdf import PdfWriter


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "extract_rightrail_pdf_documents.py"
SPEC = importlib.util.spec_from_file_location("rightrail_pdf_documents", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
pdf_documents = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = pdf_documents
SPEC.loader.exec_module(pdf_documents)


class RightRailPdfDocumentTests(unittest.TestCase):
    def test_expected_pdf_set_is_fixed(self) -> None:
        self.assertEqual(len(pdf_documents.PDF_SPECS), 4)
        self.assertEqual(
            pdf_documents.PDF_SPECS[
                "original/reference/RightRail_Architecture_and_Operating_Plan.pdf"
            ]["content_role"],
            "operating_plan_review_candidate",
        )

    def test_source_hash_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.bin"
            path.write_bytes(b"evidence")
            self.assertEqual(
                pdf_documents.sha256_file(path), hashlib.sha256(b"evidence").hexdigest()
            )

    def test_blank_pdf_has_no_text_layer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "blank.pdf"
            writer = PdfWriter()
            writer.add_blank_page(width=200, height=200)
            with path.open("wb") as handle:
                writer.write(handle)
            pages, _metadata = pdf_documents.extract_pdf(path)
            self.assertEqual(len(pages), 1)
            self.assertFalse(pages[0]["text_layer_present"])


if __name__ == "__main__":
    unittest.main()
