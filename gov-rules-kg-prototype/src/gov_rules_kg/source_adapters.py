from __future__ import annotations

import io
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .scaled_corpus import normalize_source_text


@dataclass(frozen=True)
class ExtractedSourceText:
    text: str
    parser_name: str
    parser_version: str
    text_layer_kind: str
    warnings: tuple[str, ...] = ()


def _decode_text(raw_bytes: bytes) -> str:
    for encoding in ("utf-8", "utf-8-sig", "windows-1252"):
        try:
            return raw_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw_bytes.decode("utf-8", errors="replace")


def _xml_or_html_text(raw_bytes: bytes, *, html: bool) -> str:
    try:
        from lxml import etree, html as lxml_html
    except ImportError as exc:  # pragma: no cover - dependency gate
        raise RuntimeError("lxml is required for XML and HTML source adapters") from exc
    parser: Any
    if html:
        root = lxml_html.fromstring(raw_bytes)
    else:
        parser = etree.XMLParser(resolve_entities=False, no_network=True, recover=False, huge_tree=True)
        root = etree.fromstring(raw_bytes, parser=parser)
    lines: list[str] = []
    block_tags = {
        "article",
        "caption",
        "chapter",
        "div",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "item",
        "li",
        "p",
        "part",
        "section",
        "subchapter",
        "td",
        "th",
        "title",
        "tr",
    }
    for element in root.iter():
        if not isinstance(element.tag, str):
            continue
        tag = element.tag.rsplit("}", 1)[-1].lower()
        if tag not in block_tags:
            continue
        descendant_block = any(
            isinstance(child.tag, str)
            and child is not element
            and child.tag.rsplit("}", 1)[-1].lower() in block_tags
            for child in element.iterdescendants()
        )
        if descendant_block and tag not in {"caption", "h1", "h2", "h3", "h4", "h5", "h6", "title"}:
            continue
        text = " ".join(part.strip() for part in element.itertext() if part.strip())
        if text and (not lines or lines[-1] != text):
            lines.append(text)
    return "\n".join(lines) if lines else " ".join(root.itertext())


def _pdf_text(raw_bytes: bytes) -> str:
    try:
        import fitz

        document = fitz.open(stream=raw_bytes, filetype="pdf")
        try:
            return "\n".join(page.get_text("text") for page in document)
        finally:
            document.close()
    except ImportError:
        try:
            from pypdf import PdfReader
        except ImportError as exc:  # pragma: no cover - dependency gate
            raise RuntimeError("PyMuPDF or pypdf is required for PDF source adapters") from exc
        reader = PdfReader(io.BytesIO(raw_bytes))
        return "\n".join(page.extract_text() or "" for page in reader.pages)


def extract_source_text(
    raw_bytes: bytes,
    *,
    mime_type: str,
    source_url: str,
    allow_ocr: bool = False,
) -> ExtractedSourceText:
    mime = mime_type.split(";", 1)[0].strip().lower()
    host = urlparse(source_url).netloc.lower()
    warnings: list[str] = []
    if mime in {"application/xml", "text/xml"} or source_url.lower().endswith(".xml"):
        text = _xml_or_html_text(raw_bytes, html=False)
        adapter = "ecfr_xml" if "ecfr.gov" in host else "govinfo_xml" if "govinfo.gov" in host else "xml"
    elif mime == "application/pdf" or source_url.lower().endswith(".pdf"):
        text = _pdf_text(raw_bytes)
        adapter = "agency_pdf"
    elif mime in {"text/html", "application/xhtml+xml"}:
        text = _xml_or_html_text(raw_bytes, html=True)
        adapter = "federal_register_html" if "federalregister.gov" in host else "agency_html"
    elif mime.startswith("text/") or mime in {"application/json", "application/octet-stream"}:
        text = _decode_text(raw_bytes)
        adapter = "govinfo_text" if "govinfo.gov" in host else "plain_text"
    else:
        raise ValueError(f"unsupported source MIME type: {mime}")
    normalized = normalize_source_text(text)
    if not normalized:
        if not allow_ocr:
            raise ValueError("source has no usable text layer; OCR review is required")
        raise ValueError("OCR execution is not bundled; ingest an OCR artifact marked as OCR evidence")
    if adapter == "agency_pdf" and len(normalized) < 200:
        warnings.append("pdf_text_layer_sparse_manual_ocr_review_required")
    return ExtractedSourceText(
        text=normalized,
        parser_name=adapter,
        parser_version="1",
        text_layer_kind="native",
        warnings=tuple(warnings),
    )
