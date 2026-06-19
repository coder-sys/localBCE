from __future__ import annotations

import io
import re
import unicodedata
import warnings
from dataclasses import dataclass
from difflib import SequenceMatcher
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree

try:
    from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
except ImportError:  # pragma: no cover - default parser dependency gate
    BeautifulSoup = None  # type: ignore[assignment]
    XMLParsedAsHTMLWarning = Warning  # type: ignore[assignment]


CITATION_PATTERNS = [
    re.compile(r"\b\d+\s+CFR\s+part\s+\d+(?:\.\d+)?", re.IGNORECASE),
    re.compile(r"\b\d+\s+U\.?S\.?C\.?\s+(?:\u00a7|sec\.?|section)?\s*\d+[A-Za-z0-9\-]*", re.IGNORECASE),
    re.compile(r"\bWelfare and Institutions Code\s+(?:\u00a7|sec\.?|section)?\s*\d+[A-Za-z0-9\-]*", re.IGNORECASE),
    re.compile(r"\bTitle\s+22\b", re.IGNORECASE),
    re.compile(r"\bAPL\s*\d{2}-\d{3}\b", re.IGNORECASE),
    re.compile(r"\bBHIN\s*\d{2}-\d{3}\b", re.IGNORECASE),
    re.compile(r"\bACWDL\s*\d{2}-\d{2}\b", re.IGNORECASE),
]

TEXT_SECTION_PATTERN = re.compile(
    r"(?m)^(?P<section>(?:\u00a7\s*)?\d+(?:\.\d+)*[a-z]?(?:\.\d+)?)\s+"
    r"(?P<title>[A-Z][^\n]{3,180})$"
)

LEGAL_AUTHORITY_HINTS = {
    "shall",
    "must",
    "required",
    "requirement",
    "eligible",
    "eligibility",
    "benefit",
    "coverage",
    "payment",
    "provider",
    "agency",
    "state",
    "recipient",
    "enrollee",
    "applicant",
    "application",
    "determination",
    "exemption",
    "exception",
    "appeal",
    "notice",
    "compliance",
}

SECTION_SPOOF_MARKERS = {
    "javascript",
    "function(",
    "<script",
    "</div>",
    "click here",
    "browser update",
    "not a real section",
}

HTML_NOISE_TAGS = {
    "script",
    "style",
    "noscript",
    "template",
    "nav",
    "header",
    "footer",
    "form",
    "select",
    "option",
    "button",
    "svg",
    "iframe",
}

VOID_HTML_TAGS = {
    "area",
    "base",
    "br",
    "col",
    "embed",
    "hr",
    "img",
    "input",
    "link",
    "meta",
    "param",
    "source",
    "track",
    "wbr",
}

BROWSER_WARNING_PHRASES = [
    "please click here to continue",
    "browser update required",
    "your browser is not fully optimized",
    "weblinks are you looking for weblinks mobile",
    "hide page by default",
    "document.documentelement",
    "enable javascript",
]

HIDDEN_STYLE_MARKERS = [
    "display:none",
    "visibility:hidden",
    "opacity:0",
    "font-size:0",
    "clip:rect(",
    "left:-",
    "text-indent:-",
]

UNICODE_FORMAT_CONTROLS = {
    "\u200b", "\u200c", "\u200d", "\u200e", "\u200f",
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
    "\ufeff",
}


@dataclass
class RuleSection:
    section_id: str
    title: str
    text: str
    citations: list[str]
    source_kind: str


@dataclass
class ExtractedDocument:
    title: str
    text: str
    links: list[str]
    citations: list[str]
    extractor_notes: list[str]
    rule_sections: list[RuleSection]


def extract_text(url: str, content_type: str | None, body: bytes, parser_mode: str = "default") -> ExtractedDocument:
    lowered = (content_type or "").lower()
    if "pdf" in lowered or url.lower().endswith(".pdf"):
        return extract_pdf(body)
    if "text/plain" in lowered:
        return extract_plain_text(url, body)
    if parser_mode == "no-bs4":
        return extract_html_or_text_without_bs4(url, body)
    return extract_html_or_text(url, body)


def extract_plain_text(url: str, body: bytes) -> ExtractedDocument:
    text = clean_multiline_text(normalize_extracted_text(body.decode("utf-8", errors="replace")))
    title = first_nonempty_line(text) or url
    sections = extract_text_rule_sections(text)
    return ExtractedDocument(
        title=title,
        text=text,
        links=[],
        citations=extract_citations(text),
        extractor_notes=["plain_text", *document_quality_flags(title, text, len(sections))],
        rule_sections=sections,
    )


def extract_html_or_text(url: str, body: bytes) -> ExtractedDocument:
    if BeautifulSoup is None:
        return extract_html_or_text_without_bs4(url, body)
    raw = normalize_extracted_text(body.decode("utf-8", errors="replace"))
    parser = "xml" if raw.lstrip().startswith("<?xml") else "lxml"
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
        soup = BeautifulSoup(raw, parser)

    if parser != "xml":
        remove_html_noise(soup)

    title = soup.title.get_text(" ", strip=True) if soup.title else url
    links = [
        link
        for anchor in soup.find_all("a")
        for link in [safe_join_link(url, anchor.get("href"))]
        if link
    ]
    text = clean_multiline_text(soup.get_text("\n", strip=True) if soup.find() else raw)
    rule_sections = extract_xml_rule_sections(soup) if parser == "xml" else extract_text_rule_sections(text)
    quality_flags = document_quality_flags(title, text, len(rule_sections))
    notes = [f"{parser}_text", *quality_flags]

    return ExtractedDocument(
        title=title,
        text=text,
        links=links,
        citations=extract_citations(text),
        extractor_notes=notes,
        rule_sections=rule_sections,
    )


def extract_html_or_text_without_bs4(url: str, body: bytes) -> ExtractedDocument:
    raw = normalize_extracted_text(body.decode("utf-8", errors="replace"))
    stripped = raw.lstrip()
    if stripped.startswith("<?xml") or stripped.startswith("<XML") or stripped.startswith("<xml"):
        return extract_xml_without_bs4(url, raw)
    return extract_html_without_bs4(url, raw)


def extract_xml_without_bs4(url: str, raw: str) -> ExtractedDocument:
    try:
        root = ElementTree.fromstring(raw.encode("utf-8"))
    except ElementTree.ParseError:
        text = clean_multiline_text(strip_markup(raw))
        return ExtractedDocument(
            title=first_nonempty_line(text) or url,
            text=text,
            links=[],
            citations=extract_citations(text),
            extractor_notes=["stdlib_xml_parse_failed", *document_quality_flags(url, text, 0)],
            rule_sections=extract_text_rule_sections(text),
        )

    all_text = clean_multiline_text(" ".join(clean_text(part) for part in root.itertext() if clean_text(part)))
    sections = extract_xml_rule_sections_stdlib(root)
    title = first_xml_head(root) or first_nonempty_line(all_text) or url
    return ExtractedDocument(
        title=title,
        text=all_text,
        links=[],
        citations=extract_citations(all_text),
        extractor_notes=["stdlib_xml_text", *document_quality_flags(title, all_text, len(sections))],
        rule_sections=sections,
    )


def extract_html_without_bs4(url: str, raw: str) -> ExtractedDocument:
    parser = TextOnlyHTMLParser(url)
    parser.feed(raw)
    text = clean_multiline_text("\n".join(parser.text_parts))
    title = clean_text(parser.title) or first_nonempty_line(text) or url
    sections = extract_text_rule_sections(text)
    return ExtractedDocument(
        title=title,
        text=text,
        links=parser.links,
        citations=extract_citations(text),
        extractor_notes=["stdlib_html_text", *document_quality_flags(title, text, len(sections))],
        rule_sections=sections,
    )


def extract_pdf(body: bytes) -> ExtractedDocument:
    notes: list[str] = []
    pypdf_text = ""
    pymupdf_text = ""

    try:
        from pypdf import PdfReader

        reader = PdfReader(io.BytesIO(body))
        pypdf_text = "\n".join(page.extract_text() or "" for page in reader.pages)
        notes.append("pypdf_ok")
    except Exception as exc:
        notes.append(f"pypdf_failed:{exc}")

    try:
        import fitz

        doc = fitz.open(stream=body, filetype="pdf")
        pymupdf_text = "\n".join(page.get_text() for page in doc)
        notes.append("pymupdf_ok")
    except Exception as exc:
        notes.append(f"pymupdf_failed:{exc}")

    pypdf_text = normalize_extracted_text(pypdf_text)
    pymupdf_text = normalize_extracted_text(pymupdf_text)
    if pypdf_text and pymupdf_text:
        similarity = SequenceMatcher(None, clean_text(pypdf_text), clean_text(pymupdf_text)).ratio()
        length_ratio = min(len(pypdf_text), len(pymupdf_text)) / max(len(pypdf_text), len(pymupdf_text), 1)
        if similarity < 0.82 or length_ratio < 0.65:
            notes.append("low_quality_pdf_extractor_disagreement")
        else:
            notes.append("two_extractor_agreement")
    else:
        notes.append("single_pdf_extractor")
    text = pypdf_text if len(pypdf_text) <= len(pymupdf_text) or not pymupdf_text else pymupdf_text
    title = first_nonempty_line(text) or "PDF document"
    return ExtractedDocument(
        title=title,
        text=text,
        links=[],
        citations=extract_citations(text),
        extractor_notes=notes,
        rule_sections=extract_text_rule_sections(text),
    )


def extract_citations(text: str) -> list[str]:
    seen: set[str] = set()
    citations: list[str] = []
    for pattern in CITATION_PATTERNS:
        for match in pattern.finditer(text):
            citation = clean_text(match.group(0))
            key = citation.lower()
            if key not in seen:
                seen.add(key)
                citations.append(citation)
    return citations


def extract_xml_rule_sections(soup) -> list[RuleSection]:
    sections: list[RuleSection] = []
    for tag in soup.find_all(True):
        tag_type = (tag.get("TYPE") or tag.get("type") or "").upper()
        if tag_type not in {"SECTION", "APPENDIX"}:
            continue

        head = tag.find("HEAD") or tag.find("head")
        title = clean_text(head.get_text(" ", strip=True)) if head else ""
        text = clean_text(tag.get_text(" ", strip=True))
        if not text or len(text) < 80:
            continue

        section_id = tag.get("N") or tag.get("n") or title[:80] or f"section-{len(sections) + 1}"
        sections.append(
            RuleSection(
                section_id=clean_text(section_id),
                title=title or clean_text(text[:120]),
                text=text,
                citations=extract_citations(text),
                source_kind="xml_section",
            )
        )
    return sections


def extract_xml_rule_sections_stdlib(root: ElementTree.Element) -> list[RuleSection]:
    sections: list[RuleSection] = []
    for element in root.iter():
        tag_type = (element.attrib.get("TYPE") or element.attrib.get("type") or "").upper()
        if tag_type not in {"SECTION", "APPENDIX"}:
            continue
        head = first_child_by_local_name(element, "HEAD")
        title = clean_text(" ".join(head.itertext())) if head is not None else ""
        text = clean_text(" ".join(part for part in element.itertext() if part and part.strip()))
        if not text or len(text) < 80:
            continue
        section_id = element.attrib.get("N") or element.attrib.get("n") or title[:80] or f"section-{len(sections) + 1}"
        sections.append(
            RuleSection(
                section_id=clean_text(section_id),
                title=title or clean_text(text[:120]),
                text=text,
                citations=extract_citations(text),
                source_kind="xml_section_stdlib",
            )
        )
    return sections


def first_xml_head(root: ElementTree.Element) -> str | None:
    for element in root.iter():
        if local_name(element.tag).upper() == "HEAD":
            text = clean_text(" ".join(part for part in element.itertext() if part and part.strip()))
            if text:
                return text[:200]
    return None


def first_child_by_local_name(element: ElementTree.Element, wanted: str) -> ElementTree.Element | None:
    for child in list(element):
        if local_name(child.tag).upper() == wanted.upper():
            return child
    return None


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def extract_text_rule_sections(text: str) -> list[RuleSection]:
    matches = list(TEXT_SECTION_PATTERN.finditer(text))
    sections: list[RuleSection] = []
    for index, match in enumerate(matches):
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        section_text = clean_text(text[start:end])
        if len(section_text) < 120:
            continue

        section_id = clean_text(match.group("section"))
        title = clean_text(match.group("title"))
        if not is_plausible_text_rule_section(section_id, title, section_text):
            continue
        sections.append(
            RuleSection(
                section_id=section_id,
                title=title,
                text=section_text,
                citations=extract_citations(section_text),
                source_kind="text_section_guarded",
            )
        )
    return sections


def is_plausible_text_rule_section(section_id: str, title: str, section_text: str) -> bool:
    lowered = f"{section_id} {title} {section_text[:500]}".lower()
    if any(marker in lowered for marker in SECTION_SPOOF_MARKERS):
        return False
    if len(section_id.replace("\u00a7", "").strip()) > 40 or len(title) > 180:
        return False
    if len(re.findall(r"\d+", section_id)) > 5:
        return False
    if extract_citations(section_text):
        return True
    if "\u00a7" in section_id:
        return True
    tokens = set(re.findall(r"[a-z]+", lowered))
    return bool(tokens & LEGAL_AUTHORITY_HINTS)


def clean_text(text: str) -> str:
    return re.sub(r"\s+", " ", normalize_extracted_text(text)).strip()


def clean_multiline_text(text: str) -> str:
    lines: list[str] = []
    previous = ""
    for line in text.splitlines():
        stripped = clean_text(line)
        if not stripped:
            continue
        if stripped == previous:
            continue
        previous = stripped
        lines.append(stripped)
    return "\n".join(lines)


def remove_html_noise(soup: BeautifulSoup) -> None:
    for tag_name in HTML_NOISE_TAGS:
        for tag in soup.find_all(tag_name):
            tag.decompose()
    for element in soup.select("[aria-hidden='true'], [hidden]"):
        element.decompose()
    for element in soup.select("details:not([open]), input[type='hidden']"):
        element.decompose()
    for element in soup.find_all(True):
        style = normalize_style(element.get("style") or "")
        if any(marker in style for marker in HIDDEN_STYLE_MARKERS):
            element.decompose()


class TextOnlyHTMLParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.text_parts: list[str] = []
        self.links: list[str] = []
        self.title = ""
        self._skip_stack: list[str] = []
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_lower = tag.lower()
        attrs_dict = {key.lower(): value for key, value in attrs}
        hidden = (
            tag_lower in HTML_NOISE_TAGS
            or attrs_dict.get("hidden") is not None
            or str(attrs_dict.get("aria-hidden") or "").lower() == "true"
            or (tag_lower == "details" and attrs_dict.get("open") is None)
            or (tag_lower == "input" and str(attrs_dict.get("type") or "").lower() == "hidden")
            or any(marker in normalize_style(attrs_dict.get("style") or "") for marker in HIDDEN_STYLE_MARKERS)
        )
        if hidden and tag_lower not in VOID_HTML_TAGS:
            self._skip_stack.append(tag_lower)
        if tag_lower == "title":
            self._in_title = True
        if tag_lower == "a" and attrs_dict.get("href"):
            link = safe_join_link(self.base_url, attrs_dict["href"] or "")
            if link:
                self.links.append(link)

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()
        if tag_lower in self._skip_stack:
            while self._skip_stack:
                skipped = self._skip_stack.pop()
                if skipped == tag_lower:
                    break
        if tag_lower == "title":
            self._in_title = False

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        stack_len = len(self._skip_stack)
        self.handle_starttag(tag, attrs)
        if len(self._skip_stack) > stack_len:
            self._skip_stack.pop()

    def handle_data(self, data: str) -> None:
        cleaned = clean_text(data)
        if not cleaned or self._skip_stack:
            return
        if self._in_title:
            self.title = clean_text(f"{self.title} {cleaned}")
        else:
            self.text_parts.append(cleaned)


def strip_markup(raw: str) -> str:
    return re.sub(r"<[^>]+>", " ", raw)


def document_quality_flags(title: str, text: str, rule_section_count: int) -> list[str]:
    lowered = f"{title}\n{text}".lower()
    flags: list[str] = []
    if any(phrase in lowered for phrase in BROWSER_WARNING_PHRASES):
        flags.append("low_quality_browser_warning")
    if "<html" in lowered or "</div>" in lowered or "function(" in lowered:
        flags.append("low_quality_markup_or_script")
    if len(clean_text(text)) < 200 and rule_section_count == 0:
        flags.append("low_quality_too_short")
    return flags


def normalize_extracted_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in normalized if ch not in UNICODE_FORMAT_CONTROLS)


def normalize_style(style: str) -> str:
    return re.sub(r"\s+", "", style).lower()


def safe_join_link(base_url: str, href: str | None) -> str | None:
    if not href:
        return None
    joined = urljoin(base_url, href)
    parsed = urlparse(joined)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return joined


def is_low_quality_document(document: ExtractedDocument) -> bool:
    return any(note.startswith("low_quality_") for note in document.extractor_notes)


def first_nonempty_line(text: str) -> str | None:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:200]
    return None
