from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .ratification import require_ratified_candidates


ROOT_BUILD_SCHEMA_VERSION = "gov_rules_kg_ratified_root_build_v1"


def _canonical_json(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def ratified_candidate_record(candidate: dict[str, Any]) -> dict[str, Any]:
    ratification = candidate.get("ratification")
    if not isinstance(ratification, dict):
        raise ValueError("ratified_candidate_missing_ratification")
    effective_from = str(candidate.get("effective_from") or ratification.get("effective_from") or "").strip()
    if not effective_from:
        raise ValueError("ratified_candidate_missing_effective_from")
    return {
        "rule_digest": ratification["rule_digest"],
        "executable_rule_id": candidate.get("executable_rule_id"),
        "source_candidate_id": candidate.get("source_candidate_id"),
        "effective_from": effective_from,
        "effective_until": candidate.get("effective_until") or ratification.get("effective_until"),
        "signature_scheme": ratification.get("signature_scheme"),
        "signature_threshold": ratification.get("signature_threshold"),
        "reviewers": ratification.get("reviewers", []),
    }


def build_ratified_rule_root(workdir: Path, candidates: list[dict[str, Any]]) -> dict[str, Any]:
    ratified = require_ratified_candidates(workdir, candidates)
    records = sorted(
        (ratified_candidate_record(candidate) for candidate in ratified),
        key=lambda item: (str(item.get("effective_from") or ""), str(item.get("rule_digest") or "")),
    )
    root_payload = {
        "schema_version": ROOT_BUILD_SCHEMA_VERSION,
        "records": records,
    }
    return {
        "schema_version": ROOT_BUILD_SCHEMA_VERSION,
        "ratified_rule_count": len(records),
        "ratified_rule_root": hashlib.sha256(_canonical_json(root_payload)).hexdigest(),
        "records": records,
    }
