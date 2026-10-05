"""Derived view: a check result as an ordered fix list in plain words.

Not a wire format and not an authority; the result's own checker still decides.
Text is static, one entry per closed code, and never echoes input values.
"""

from __future__ import annotations

from .codec import _load
from .contracts import RESULT_CONTRACT, FactName, InputError, RuleId

_BLOCKED = "Do not rely on this check. Ask your rule administrator for a current rule set."
REAL_USE_TEXT = "A person must check this claim. This tool cannot approve real claims."
_REVIEW = "Have a person review this claim. "
_SOURCE = "Have a person review the source record. "
TEXT = {
    "service_date": "Add the service date.",
    "service_category": "Add the service category.",
    "support_reference": "Add the supporting reference for this service.",
    "charge_cents": "Add the charge amount.",
    "source_binding": "Add the source record the facts came from.",
    "source_effective_at": "Add the date the source record takes effect.",
    "source_received_at": "Add the date and time the source record was received.",
    "BUNDLE_BLOCKED": _BLOCKED,
    "SERVICE_DATE_OUTSIDE_RULE_INTERVAL": _REVIEW + "The service date is outside the dates this rule covers.",
    "SERVICE_CATEGORY_REQUIRES_REVIEW": _REVIEW + "The service category needs review under this rule.",
    "CHARGE_OUTSIDE_SYNTHETIC_RANGE": _REVIEW + "The charge is outside the expected range.",
    "SOURCE_STATUS_REQUIRES_REVIEW": _SOURCE + "It is partial, in conflict, repeated or unknown.",
    "SOURCE_RECEIVED_BEFORE_EFFECTIVE_DATE": _SOURCE + "It was received before its own start date.",
    "SOURCE_RECEIVED_AFTER_EVALUATION_TIME": _SOURCE + "It is dated after the time of this check.",
    "SOURCE_STALE_FOR_SYNTHETIC_WINDOW": _SOURCE + "It is older than this rule allows.",
    "RULE_SEMANTIC_UNSUPPORTED": _REVIEW + "This tool does not support this version of the rule.",
}


def fix_list(result_bytes: bytes) -> tuple[tuple[str, str, str, str], ...]:
    """Return (ruleId, citation, fact, text) per fix; empty when nothing is needed.

    Claim-level lines (real use, blocked rule set) carry empty ruleId, citation and fact.
    Any unknown or malformed content raises InputError and returns nothing.
    """
    doc = _load(result_bytes, "RESULT_TOO_LARGE")
    try:
        if doc["contract"] != RESULT_CONTRACT:
            raise InputError("RESULT_SHAPE")
        if doc["runMode"] == "REAL_USE":
            return (("", "", "", REAL_USE_TEXT),)
        if doc["bundleIssues"]:
            return (("", "", "", TEXT["BUNDLE_BLOCKED"]),)
        fixes = []
        for rule in doc["rules"]:
            outcome = rule["outcome"]
            if outcome == "PASS":
                continue
            rule_id, citation = RuleId(rule["ruleId"]).value, rule["citation"]
            if type(citation) is not str or outcome not in ("MISSING", "HUMAN_CHECK"):
                raise InputError("RESULT_SHAPE")
            for code in rule["missingFacts"] if outcome == "MISSING" else rule["reasonCodes"]:
                fact = FactName(code).value if outcome == "MISSING" else ""
                fixes.append((rule_id, citation, fact, TEXT[code]))
        return tuple(fixes)
    except InputError:
        raise
    except (KeyError, TypeError, ValueError):
        raise InputError("RESULT_SHAPE") from None
