from __future__ import annotations

from difflib import SequenceMatcher

from .citations import parse_citations, citations_exactly_match
from .store import Store, utc_now


def propose_merge_candidates(store: Store, limit: int = 25) -> list[dict]:
    rows = store.rows("entities")
    proposals: list[dict] = []
    for i, left in enumerate(rows):
        for right in rows[i + 1 :]:
            if left["entity_type"] != right["entity_type"]:
                continue
            if left["entity_type"] == "citation":
                continue
            title_score = SequenceMatcher(None, left["title"].lower(), right["title"].lower()).ratio()
            if title_score < 0.92:
                continue
            proposal = {
                "left_key": left["canonical_key"],
                "right_key": right["canonical_key"],
                "confidence": title_score,
                "evidence": {
                    "left_title": left["title"],
                    "right_title": right["title"],
                    "reason": "same entity_type and high title similarity; requires human review",
                },
                "created_at": utc_now(),
            }
            proposals.append(proposal)
            if len(proposals) >= limit:
                return proposals
    return proposals


def legal_citations_can_merge(left_title: str, right_title: str) -> bool:
    left = parse_citations(left_title)
    right = parse_citations(right_title)
    if not left or not right:
        return left_title.strip().lower() == right_title.strip().lower()
    return any(citations_exactly_match(left_citation, right_citation) for left_citation in left for right_citation in right)
