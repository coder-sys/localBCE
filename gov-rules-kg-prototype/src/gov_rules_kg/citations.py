from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass


FEDERAL_CFR_RE = re.compile(
    r"\b(?P<title>\d+)\s+CFR\s+(?:(?:part|pt\.?)\s+(?P<part>\d+)|(?:§|sec\.?|section)\s*(?P<section>\d+(?:\.\d+)*))(?P<subsection>(?:\([a-zA-Z0-9]+\))*)",
    re.IGNORECASE,
)
FEDERAL_USC_RE = re.compile(
    r"\b(?P<title>\d+)\s+U\.?S\.?C\.?\s+(?:(?:§|sec\.?|section)\s*)?(?P<section>\d+[A-Za-z0-9-]*)(?P<subsection>(?:\([a-zA-Z0-9]+\))*)",
    re.IGNORECASE,
)
CALIFORNIA_WIC_RE = re.compile(
    r"\b(?:California\s+)?(?:Welfare and Institutions Code|WIC)\s*(?:§|sec\.?|section)?\s*(?P<section>\d+[A-Za-z0-9.-]*)(?P<subsection>(?:\([a-zA-Z0-9]+\))*)",
    re.IGNORECASE,
)
CALIFORNIA_CCR_RE = re.compile(
    r"\b(?:California\s+Code\s+of\s+Regulations|CCR|Cal\.?\s+Code\s+Regs\.?)\s*(?:title\s*)?(?P<title>\d+)?\s*(?:§|sec\.?|section)?\s*(?P<section>\d+(?:\.\d+)*)(?P<subsection>(?:\([a-zA-Z0-9]+\))*)",
    re.IGNORECASE,
)
TEXAS_TAC_RE = re.compile(
    r"\b(?:Texas\s+Administrative\s+Code|TAC)\s*(?:title\s*)?(?P<title>\d+)\s*(?:§|sec\.?|section)?\s*(?P<section>\d+(?:\.\d+)*)(?P<subsection>(?:\([a-zA-Z0-9]+\))*)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Citation:
    citation_id: str
    jurisdiction: str
    state_code: str | None
    code: str
    title: str | None
    part: str | None
    section: str | None
    subsection: str
    paragraph_path: str | None
    normalized_citation: str
    source_text: str
    human_review_required: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def parse_citations(text: str, paragraph_path: str | None = None) -> list[Citation]:
    citations: list[Citation] = []
    for pattern, builder in [
        (FEDERAL_CFR_RE, build_cfr_citation),
        (FEDERAL_USC_RE, build_usc_citation),
        (CALIFORNIA_WIC_RE, build_ca_wic_citation),
        (CALIFORNIA_CCR_RE, build_ca_ccr_citation),
        (TEXAS_TAC_RE, build_tx_tac_citation),
    ]:
        for match in pattern.finditer(text):
            citations.append(builder(match, paragraph_path))
    return dedupe_citations(citations)


def build_cfr_citation(match: re.Match, paragraph_path: str | None) -> Citation:
    title = match.group("title")
    part = match.group("part")
    section = match.group("section")
    subsection = match.group("subsection") or ""
    if section and not part:
        part = section.split(".")[0]
    normalized = f"{title} CFR Part {part}" if part and not section else f"{title} CFR § {section}{subsection}"
    return make_citation("federal", None, "CFR", title, part, section, subsection, paragraph_path, normalized, match.group(0))


def build_usc_citation(match: re.Match, paragraph_path: str | None) -> Citation:
    title = match.group("title")
    section = match.group("section")
    subsection = match.group("subsection") or ""
    normalized = f"{title} USC § {section}{subsection}"
    return make_citation("federal", None, "USC", title, None, section, subsection, paragraph_path, normalized, match.group(0))


def build_ca_wic_citation(match: re.Match, paragraph_path: str | None) -> Citation:
    section = match.group("section")
    subsection = match.group("subsection") or ""
    normalized = f"California WIC § {section}{subsection}"
    return make_citation("state", "CA", "WIC", None, None, section, subsection, paragraph_path, normalized, match.group(0))


def build_ca_ccr_citation(match: re.Match, paragraph_path: str | None) -> Citation:
    title = match.group("title")
    section = match.group("section")
    subsection = match.group("subsection") or ""
    normalized = f"California CCR Title {title} § {section}{subsection}" if title else f"California CCR § {section}{subsection}"
    return make_citation("state", "CA", "CCR", title, None, section, subsection, paragraph_path, normalized, match.group(0))


def build_tx_tac_citation(match: re.Match, paragraph_path: str | None) -> Citation:
    title = match.group("title")
    section = match.group("section")
    subsection = match.group("subsection") or ""
    normalized = f"Texas TAC Title {title} § {section}{subsection}"
    return make_citation("state", "TX", "TAC", title, None, section, subsection, paragraph_path, normalized, match.group(0))


def make_citation(
    jurisdiction: str,
    state_code: str | None,
    code: str,
    title: str | None,
    part: str | None,
    section: str | None,
    subsection: str,
    paragraph_path: str | None,
    normalized: str,
    source_text: str,
) -> Citation:
    identity = "|".join(
        [
            jurisdiction,
            state_code or "",
            code,
            title or "",
            part or "",
            section or "",
            subsection,
            paragraph_path or "",
        ]
    )
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
    return Citation(
        citation_id=f"citation:{digest}",
        jurisdiction=jurisdiction,
        state_code=state_code,
        code=code,
        title=title,
        part=part,
        section=section,
        subsection=subsection,
        paragraph_path=paragraph_path,
        normalized_citation=normalized,
        source_text=source_text,
        human_review_required=not normalized,
    )


def dedupe_citations(citations: list[Citation]) -> list[Citation]:
    seen: set[str] = set()
    result: list[Citation] = []
    for citation in citations:
        if citation.citation_id in seen:
            continue
        seen.add(citation.citation_id)
        result.append(citation)
    return result


def citations_exactly_match(left: Citation, right: Citation) -> bool:
    return (
        left.jurisdiction == right.jurisdiction
        and left.state_code == right.state_code
        and left.code == right.code
        and left.title == right.title
        and left.part == right.part
        and left.section == right.section
        and left.subsection == right.subsection
        and left.paragraph_path == right.paragraph_path
    )

