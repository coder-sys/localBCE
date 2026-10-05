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


_CODES = {  # reason codes each (bundle blocked, rule outcome) may carry; anything else is refused
    (False, "PASS"): frozenset(),
    (False, "MISSING"): frozenset({"REQUIRED_FACT_MISSING", "SUPPORT_REFERENCE_MISSING", "SOURCE_EFFECTIVE_TIME_MISSING", "SOURCE_RECEIVED_TIME_MISSING"}),
    (False, "HUMAN_CHECK"): frozenset(TEXT) - {f.value for f in FactName} - {"BUNDLE_BLOCKED"},
    (True, "HUMAN_CHECK"): frozenset({"BUNDLE_BLOCKED"}),
}


def fix_list(result_bytes: bytes) -> tuple[tuple[str, str, str, str], ...]:
    """Return (ruleId, citation, fact, text) per fix; empty exactly when the outcome is PASS.

    Claim-level lines (real use, blocked rule set) carry empty ruleId, citation and fact.
    Any unknown, inconsistent or malformed content raises InputError and returns nothing.
    """
    doc = _load(result_bytes, "RESULT_TOO_LARGE")
    try:
        if doc["contract"] != RESULT_CONTRACT or doc["outcome"] not in ("PASS", "MISSING", "HUMAN_CHECK") or doc["runMode"] not in ("SYNTHETIC_TEST", "REAL_USE"):
            raise InputError("RESULT_SHAPE")
        blocked = bool(doc["bundleIssues"])
        fixes = []
        for rule in doc["rules"]:
            outcome, codes, facts = rule["outcome"], rule["reasonCodes"], rule["missingFacts"]
            if type(codes) is not list or type(facts) is not list or not set(codes) <= _CODES[blocked, outcome]:
                raise InputError("RESULT_SHAPE")
            if bool(codes) != (outcome != "PASS") or bool(facts) != (outcome == "MISSING") or type(rule["citation"]) is not str:
                raise InputError("RESULT_SHAPE")
            rule_id, citation = RuleId(rule["ruleId"]).value, rule["citation"]
            for code in facts or codes:
                fixes.append((rule_id, citation, FactName(code).value if facts else "", TEXT[code]))
        if doc["runMode"] == "REAL_USE":
            fixes = [("", "", "", REAL_USE_TEXT)]
        elif blocked:
            fixes = [("", "", "", TEXT["BUNDLE_BLOCKED"])]
        if bool(fixes) != (doc["outcome"] != "PASS"):
            raise InputError("RESULT_SHAPE")
        return tuple(fixes)
    except InputError:
        raise
    except (KeyError, TypeError, ValueError):
        raise InputError("RESULT_SHAPE") from None
