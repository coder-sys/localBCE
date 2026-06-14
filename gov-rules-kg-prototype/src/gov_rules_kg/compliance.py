from __future__ import annotations

import re


OBLIGATION_PATTERNS = [
    re.compile(r"[^.]{0,120}\bshall\b[^.]{0,220}\.", re.IGNORECASE),
    re.compile(r"[^.]{0,120}\bmust\b[^.]{0,220}\.", re.IGNORECASE),
    re.compile(r"[^.]{0,120}\brequired to\b[^.]{0,220}\.", re.IGNORECASE),
    re.compile(r"[^.]{0,120}\bmay not\b[^.]{0,220}\.", re.IGNORECASE),
]


def extract_compliance_requirements(text: str) -> list[dict]:
    requirements: list[dict] = []
    seen: set[str] = set()
    for pattern in OBLIGATION_PATTERNS:
        for match in pattern.finditer(text):
            statement = " ".join(match.group(0).split())
            key = statement.lower()
            if key in seen:
                continue
            seen.add(key)
            requirements.append(
                {
                    "statement": statement,
                    "requirement_type": classify_requirement(statement),
                    "confidence": 0.55,
                }
            )
            if len(requirements) >= 25:
                return requirements
    return requirements


def classify_requirement(statement: str) -> str:
    lowered = statement.lower()
    if "report" in lowered:
        return "reporting"
    if "eligible" in lowered or "eligibility" in lowered:
        return "eligibility"
    if "document" in lowered or "record" in lowered:
        return "documentation"
    if "prohibit" in lowered or "may not" in lowered:
        return "restriction"
    return "obligation"
