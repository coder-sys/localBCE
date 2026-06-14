from __future__ import annotations


KEYWORDS = {
    "Government": ["government", "agency", "department"],
    "Healthcare": ["medicaid", "medi-cal", "cms", "dhcs", "health", "medical"],
    "Eligibility": ["eligibility", "beneficiary", "enrollee", "aid code"],
    "Provider": ["provider", "network", "billing", "claim"],
    "Compliance": ["shall", "must", "required", "prohibited", "reporting"],
    "Authority": ["authority", "statute", "cfr", "usc", "wic", "title 22"],
}

RELEVANCE_TERMS = {
    "medicaid": 5,
    "medi-cal": 5,
    "medical assistance": 5,
    "cms": 4,
    "dhcs": 4,
    "health care": 4,
    "healthcare": 4,
    "public health": 3,
    "beneficiary": 3,
    "eligibility": 3,
    "provider": 3,
    "claim": 2,
    "billing": 2,
    "federal financial participation": 4,
    "managed care": 4,
    "state plan": 4,
    "welfare and institutions": 3,
    "title xix": 5,
    "42 cfr": 3,
    "42 u.s.c": 3,
}


def classify_text(text: str) -> dict:
    lowered = text.lower()
    labels: list[dict] = []
    for label, terms in KEYWORDS.items():
        hits = [term for term in terms if term in lowered]
        if hits:
            labels.append(
                {
                    "label": label,
                    "confidence": min(1.0, 0.35 + 0.15 * len(hits)),
                    "evidence": hits[:5],
                }
            )
    if not labels:
        labels.append({"label": "UNCLASSIFIED", "confidence": 0.0, "evidence": []})
    return {"labels": labels}


def relevance_score(text: str) -> dict:
    lowered = text.lower()
    hits: list[dict] = []
    score = 0
    for term, weight in RELEVANCE_TERMS.items():
        if term in lowered:
            score += weight
            hits.append({"term": term, "weight": weight})
    return {
        "score": score,
        "relevant": score >= 3,
        "evidence": hits[:10],
    }


def infer_entity_type(title: str, url: str, text: str) -> str:
    sample = f"{title} {url} {text[:1000]}".lower()
    if "cfr" in sample or "code of federal regulations" in sample:
        return "regulation"
    if "usc" in sample or "united states code" in sample or "wic" in sample:
        return "statute"
    if "apl" in sample or "bhin" in sample or "acwdl" in sample:
        return "guidance"
    if "medicaid" in sample or "medi-cal" in sample:
        return "program"
    if "shall" in sample or "must" in sample or "required" in sample:
        return "compliance_requirement"
    return "rule"
