from __future__ import annotations

import io
import re
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import urljoin, urlparse

from .scaled_corpus import canonical_url, normalize_source_text


@dataclass(frozen=True)
class ExtractedSourceBlock:
    text: str
    hierarchy_path: tuple[str, ...]
    heading: str | None
    block_kind: str
    source_locator: dict[str, Any]


@dataclass(frozen=True)
class ExtractedSourceText:
    text: str
    parser_name: str
    parser_version: str
    text_layer_kind: str
    warnings: tuple[str, ...] = ()
    blocks: tuple[ExtractedSourceBlock, ...] = ()


@dataclass(frozen=True)
class DiscoveredOfficialLink:
    canonical_url: str
    link_text: str
    source_locator: dict[str, Any]


_HTML_HEADINGS = {f"h{level}" for level in range(1, 7)}
_SKIPPED_HTML_TAGS = {
    "canvas",
    "footer",
    "form",
    "nav",
    "noscript",
    "script",
    "style",
    "svg",
    "template",
}
_XML_HEADING_TAGS = {"head", "hed", "heading", "subject", "title"}
_XML_CONTENT_TAGS = {
    "dd",
    "definition",
    "dt",
    "fp",
    "item",
    "li",
    "p",
    "paragraph",
    "text",
}
_HTML_CONTENT_TAGS = {"dd", "dt", "li", "p", "pre"}
SOURCE_DISCOVERY_PARSER_VERSION = "official-link-discovery-v1"


def _decode_text(raw_bytes: bytes) -> str:
    for encoding in ("utf-8", "utf-8-sig", "windows-1252"):
        try:
            return raw_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw_bytes.decode("utf-8", errors="replace")


def _tag(element: Any) -> str:
    return element.tag.rsplit("}", 1)[-1].lower() if isinstance(element.tag, str) else ""


def _element_text(element: Any) -> str:
    return normalize_source_text(
        " ".join(part.strip() for part in element.itertext() if part.strip())
    )


def _locator(element: Any, *, kind: str, sequence: int) -> dict[str, Any]:
    tree = element.getroottree()
    attributes = {
        str(key).lower(): str(value)
        for key, value in sorted(element.attrib.items())
        if str(key).lower() in {"id", "n", "name", "number", "value"}
    }
    return {
        "kind": kind,
        "node_path": tree.getpath(element),
        "sequence": sequence,
        "attributes": attributes,
    }


def _append_block(
    blocks: list[ExtractedSourceBlock],
    *,
    element: Any,
    text: str,
    path: Iterable[str],
    kind: str,
) -> None:
    normalized = normalize_source_text(text)
    if not normalized:
        return
    hierarchy = tuple(part for part in path if part)
    blocks.append(
        ExtractedSourceBlock(
            text=normalized,
            hierarchy_path=hierarchy,
            heading=hierarchy[-1] if hierarchy else None,
            block_kind=kind,
            source_locator=_locator(element, kind=kind, sequence=len(blocks)),
        )
    )


def _table_row_text(element: Any) -> str:
    cells = [
        _element_text(child)
        for child in element
        if _tag(child) in {"entry", "td", "th"}
    ]
    return " | ".join(cell for cell in cells if cell)


def _xml_blocks(root: Any) -> list[ExtractedSourceBlock]:
    blocks: list[ExtractedSourceBlock] = []

    def walk(element: Any, inherited_path: tuple[str, ...]) -> None:
        tag = _tag(element)
        direct_headings = [
            _element_text(child)
            for child in element
            if _tag(child) in _XML_HEADING_TAGS and _element_text(child)
        ]
        path = inherited_path
        for heading in direct_headings:
            if not path or path[-1] != heading:
                path = (*path, heading)

        if tag in _XML_HEADING_TAGS:
            return
        if tag in {"row", "tr"}:
            _append_block(
                blocks,
                element=element,
                text=_table_row_text(element),
                path=path,
                kind="table_row",
            )
            return
        if tag in _XML_CONTENT_TAGS:
            nested_blocks = any(
                _tag(child) in _XML_CONTENT_TAGS or _tag(child) in {"row", "tr"}
                for child in element
            )
            if nested_blocks:
                for child in element:
                    walk(child, path)
                return
            _append_block(
                blocks,
                element=element,
                text=_element_text(element),
                path=path,
                kind="list_item" if tag in {"dd", "dt", "item", "li"} else "paragraph",
            )
            return
        for child in element:
            walk(child, path)

    walk(root, ())
    return blocks


def _html_blocks(root: Any) -> list[ExtractedSourceBlock]:
    blocks: list[ExtractedSourceBlock] = []
    headings: list[str] = []
    for element in root.iter():
        tag = _tag(element)
        if not tag or any(_tag(ancestor) in _SKIPPED_HTML_TAGS for ancestor in element.iterancestors()):
            continue
        if tag in _SKIPPED_HTML_TAGS:
            continue
        if tag in _HTML_HEADINGS:
            heading = _element_text(element)
            if heading:
                level = int(tag[1])
                headings = headings[: level - 1]
                while len(headings) < level - 1:
                    headings.append(headings[-1] if headings else "Document")
                headings.append(heading)
            continue
        if tag == "tr":
            _append_block(
                blocks,
                element=element,
                text=_table_row_text(element),
                path=headings,
                kind="table_row",
            )
            continue
        if tag in _HTML_CONTENT_TAGS:
            _append_block(
                blocks,
                element=element,
                text=_element_text(element),
                path=headings,
                kind="list_item" if tag in {"dd", "dt", "li"} else "paragraph",
            )
    return blocks


def _xml_or_html_blocks(raw_bytes: bytes, *, html: bool) -> list[ExtractedSourceBlock]:
    try:
        from lxml import etree, html as lxml_html
    except ImportError as exc:  # pragma: no cover - dependency gate
        raise RuntimeError("lxml is required for XML and HTML source adapters") from exc
    if html:
        root = lxml_html.fromstring(raw_bytes)
        blocks = _html_blocks(root)
    else:
        parser = etree.XMLParser(
            resolve_entities=False,
            no_network=True,
            recover=False,
            huge_tree=True,
        )
        root = etree.fromstring(raw_bytes, parser=parser)
        blocks = _xml_blocks(root)
    if blocks:
        return blocks
    fallback = _element_text(root)
    if not fallback:
        return []
    return [
        ExtractedSourceBlock(
            text=fallback,
            hierarchy_path=(),
            heading=None,
            block_kind="document_text",
            source_locator=_locator(root, kind="document_text", sequence=0),
        )
    ]


def discover_official_links(
    raw_bytes: bytes,
    *,
    mime_type: str,
    source_url: str,
) -> tuple[DiscoveredOfficialLink, ...]:
    """Extract review candidates without promoting or fetching them."""

    mime = mime_type.split(";", 1)[0].strip().lower()
    if mime not in {"application/xml", "text/xml", "text/html", "application/xhtml+xml"}:
        return ()
    try:
        from lxml import etree, html as lxml_html
    except ImportError as exc:  # pragma: no cover - dependency gate
        raise RuntimeError("lxml is required for official source link discovery") from exc
    if mime in {"text/html", "application/xhtml+xml"}:
        root = lxml_html.fromstring(raw_bytes)
    else:
        parser = etree.XMLParser(
            resolve_entities=False,
            no_network=True,
            recover=False,
            huge_tree=True,
        )
        root = etree.fromstring(raw_bytes, parser=parser)

    base = canonical_url(source_url)
    blocked_extensions = {
        ".avi",
        ".css",
        ".csv",
        ".doc",
        ".docx",
        ".gif",
        ".ico",
        ".jpeg",
        ".jpg",
        ".js",
        ".mov",
        ".mp3",
        ".mp4",
        ".png",
        ".ppt",
        ".pptx",
        ".svg",
        ".webp",
        ".xls",
        ".xlsx",
        ".zip",
    }
    discovered: dict[str, DiscoveredOfficialLink] = {}
    for element in root.iter():
        href = element.get("href") if hasattr(element, "get") else None
        if not href:
            continue
        absolute = urljoin(base, str(href).strip())
        parsed = urlparse(absolute)
        host = parsed.netloc.lower().split(":", 1)[0]
        if parsed.scheme != "https" or not host.endswith(".gov"):
            continue
        if any(parsed.path.lower().endswith(extension) for extension in blocked_extensions):
            continue
        try:
            normalized_url = canonical_url(absolute)
        except ValueError:
            continue
        if normalized_url == base or normalized_url in discovered:
            continue
        discovered[normalized_url] = DiscoveredOfficialLink(
            canonical_url=normalized_url,
            link_text=_element_text(element)[:1000],
            source_locator=_locator(
                element, kind="official_source_link", sequence=len(discovered)
            ),
        )
    return tuple(discovered[url] for url in sorted(discovered))


def _pdf_blocks(raw_bytes: bytes) -> list[ExtractedSourceBlock]:
    pages: list[str]
    try:
        import fitz

        document = fitz.open(stream=raw_bytes, filetype="pdf")
        try:
            pages = [page.get_text("text") for page in document]
        finally:
            document.close()
    except ImportError:
        try:
            from pypdf import PdfReader
        except ImportError as exc:  # pragma: no cover - dependency gate
            raise RuntimeError("PyMuPDF or pypdf is required for PDF source adapters") from exc
        reader = PdfReader(io.BytesIO(raw_bytes))
        pages = [page.extract_text() or "" for page in reader.pages]

    blocks: list[ExtractedSourceBlock] = []
    for page_number, page in enumerate(pages, start=1):
        for paragraph_number, paragraph in enumerate(re.split(r"\n\s*\n", page)):
            text = normalize_source_text(paragraph)
            if not text:
                continue
            blocks.append(
                ExtractedSourceBlock(
                    text=text,
                    hierarchy_path=(f"Page {page_number}",),
                    heading=f"Page {page_number}",
                    block_kind="paragraph",
                    source_locator={
                        "kind": "pdf_page",
                        "page": page_number,
                        "paragraph": paragraph_number,
                        "sequence": len(blocks),
                    },
                )
            )
    return blocks


def _plain_text_blocks(raw_bytes: bytes) -> list[ExtractedSourceBlock]:
    normalized = normalize_source_text(_decode_text(raw_bytes))
    if not normalized:
        return []
    blocks: list[ExtractedSourceBlock] = []
    heading: str | None = None
    for sequence, paragraph in enumerate(normalized.split("\n")):
        text = paragraph.strip()
        if not text:
            continue
        looks_like_heading = bool(
            len(text) <= 160
            and (
                re.match(r"^(?:part|subpart|chapter|section|title)\s+[A-Z0-9]", text, re.I)
                or (text.isupper() and len(text.split()) <= 14)
            )
        )
        if looks_like_heading:
            heading = text
            continue
        path = (heading,) if heading else ()
        blocks.append(
            ExtractedSourceBlock(
                text=text,
                hierarchy_path=path,
                heading=heading,
                block_kind="paragraph",
                source_locator={
                    "kind": "text_line",
                    "line": sequence + 1,
                    "sequence": len(blocks),
                },
            )
        )
    return blocks


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
        blocks = _xml_or_html_blocks(raw_bytes, html=False)
        adapter = (
            "ecfr_xml"
            if "ecfr.gov" in host
            else "govinfo_xml"
            if "govinfo.gov" in host
            else "xml"
        )
    elif mime == "application/pdf" or source_url.lower().endswith(".pdf"):
        blocks = _pdf_blocks(raw_bytes)
        adapter = "agency_pdf"
    elif mime in {"text/html", "application/xhtml+xml"}:
        blocks = _xml_or_html_blocks(raw_bytes, html=True)
        adapter = (
            "federal_register_html"
            if "federalregister.gov" in host
            else "agency_html"
        )
    elif mime.startswith("text/") or mime in {"application/json", "application/octet-stream"}:
        blocks = _plain_text_blocks(raw_bytes)
        adapter = "govinfo_text" if "govinfo.gov" in host else "plain_text"
    else:
        raise ValueError(f"unsupported source MIME type: {mime}")

    normalized = normalize_source_text("\n".join(block.text for block in blocks))
    if not normalized:
        if not allow_ocr:
            raise ValueError("source has no usable text layer; OCR review is required")
        raise ValueError(
            "OCR execution is not bundled; ingest an OCR artifact marked as OCR evidence"
        )
    if adapter == "agency_pdf" and len(normalized) < 200:
        warnings.append("pdf_text_layer_sparse_manual_ocr_review_required")
    return ExtractedSourceText(
        text=normalized,
        parser_name=adapter,
        parser_version="2",
        text_layer_kind="native",
        warnings=tuple(warnings),
        blocks=tuple(blocks),
    )
