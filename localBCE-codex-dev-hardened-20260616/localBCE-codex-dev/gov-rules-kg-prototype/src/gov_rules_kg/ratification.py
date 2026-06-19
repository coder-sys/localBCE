from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


RATIFICATION_PUBLIC_KEYS_ENV = "GOV_RULES_RATIFICATION_PUBLIC_KEYS_ED25519_B64"
RATIFICATION_PRIVATE_KEYS_ENV = "GOV_RULES_RATIFICATION_PRIVATE_KEYS_ED25519_B64"
RATIFICATION_THRESHOLD_ENV = "GOV_RULES_RATIFICATION_THRESHOLD"
RATIFICATION_MANIFEST_PATH = Path("reports/rule_ratifications.json")
RATIFIED_STATUSES = {"ratified", "approved"}
RETIRED_STATUSES = {"rescinded", "retracted", "superseded"}
DEFAULT_SIGNATURE_THRESHOLD = 2
SIGNED_FIELDS = (
    "executable_rule_id",
    "source_candidate_id",
    "vertical",
    "program",
    "rule_type",
    "jurisdiction_level",
    "jurisdiction_state",
    "authority_level",
    "condition_text",
    "outcome_text",
    "source_url",
    "citation_text",
    "confidence_score",
)


def _canonical_json(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_candidate_payload(candidate: dict[str, Any]) -> dict[str, Any]:
    return {field: candidate.get(field) for field in SIGNED_FIELDS}


def ratification_digest(candidate: dict[str, Any]) -> str:
    payload = json.dumps(canonical_candidate_payload(candidate), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def ratification_payload(rule_digest: str, reviewer: str, effective_from: str, effective_until: str | None = None) -> bytes:
    return _canonical_json(
        {
            "schema_version": "rule_ratification_v2",
            "rule_digest": rule_digest,
            "reviewer": reviewer,
            "effective_from": effective_from,
            "effective_until": effective_until,
        }
    )


def _b64decode_key(value: str, label: str) -> bytes:
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise RuntimeError(f"invalid ratification key encoding:{label}") from exc
    if len(raw) != 32:
        raise RuntimeError(f"invalid ratification key length:{label}")
    return raw


def _json_key_map(env_name: str) -> dict[str, str]:
    raw = os.environ.get(env_name, "").strip()
    if not raw:
        raise RuntimeError(f"missing ratification key registry: {env_name}")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid ratification key registry JSON: {env_name}") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError(f"ratification key registry must be an object: {env_name}")
    return {str(key): str(value) for key, value in parsed.items()}


def _public_keys() -> dict[str, Ed25519PublicKey]:
    keys: dict[str, Ed25519PublicKey] = {}
    for reviewer, value in _json_key_map(RATIFICATION_PUBLIC_KEYS_ENV).items():
        keys[reviewer] = Ed25519PublicKey.from_public_bytes(_b64decode_key(value, f"{RATIFICATION_PUBLIC_KEYS_ENV}:{reviewer}"))
    return keys


def ratification_signature(
    rule_digest: str,
    reviewer: str,
    effective_from: str,
    effective_until: str | None = None,
    *,
    private_key_b64: str | None = None,
) -> str:
    key_b64 = private_key_b64
    if key_b64 is None:
        private_keys = _json_key_map(RATIFICATION_PRIVATE_KEYS_ENV)
        key_b64 = private_keys.get(reviewer)
        if not key_b64:
            raise RuntimeError(f"missing ratification signing key for reviewer: {reviewer}")
    key = Ed25519PrivateKey.from_private_bytes(_b64decode_key(key_b64, f"{RATIFICATION_PRIVATE_KEYS_ENV}:{reviewer}"))
    signature = key.sign(ratification_payload(rule_digest, reviewer, effective_from, effective_until))
    return base64.b64encode(signature).decode("ascii")


def load_ratification_manifest(workdir: Path) -> list[dict[str, Any]]:
    path = workdir / RATIFICATION_MANIFEST_PATH
    if not path.exists():
        raise FileNotFoundError(f"rule ratification manifest not found: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        entries = payload.get("ratifications", [])
    else:
        entries = payload
    if not isinstance(entries, list):
        raise ValueError("rule ratification manifest must contain a list")
    return [entry for entry in entries if isinstance(entry, dict)]


def _entry_matches(entry: dict[str, Any], candidate: dict[str, Any]) -> bool:
    identifiers = {
        str(candidate.get("executable_rule_id") or ""),
        str(candidate.get("source_candidate_id") or ""),
        str(candidate.get("rule_id") or ""),
    }
    identifiers.discard("")
    entry_ids = {
        str(entry.get("executable_rule_id") or ""),
        str(entry.get("source_candidate_id") or ""),
        str(entry.get("rule_id") or ""),
    }
    entry_ids.discard("")
    return bool(identifiers.intersection(entry_ids))


def _ratification_error(candidate: dict[str, Any], reason: str) -> ValueError:
    candidate_id = candidate.get("executable_rule_id") or candidate.get("source_candidate_id") or "unknown"
    return ValueError(f"rule_ratification_invalid:{candidate_id}:{reason}")


def _signature_threshold(entry: dict[str, Any]) -> int:
    raw = entry.get("signature_threshold") or os.environ.get(RATIFICATION_THRESHOLD_ENV) or DEFAULT_SIGNATURE_THRESHOLD
    try:
        threshold = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("signature_threshold_invalid") from exc
    if threshold < 1:
        raise ValueError("signature_threshold_invalid")
    return threshold


def _signature_entries(entry: dict[str, Any]) -> list[dict[str, Any]]:
    signatures = entry.get("signatures")
    if isinstance(signatures, list):
        return [item for item in signatures if isinstance(item, dict)]
    if entry.get("signature") and entry.get("reviewer"):
        return [{"reviewer": entry.get("reviewer"), "signature": entry.get("signature")}]
    return []


def _valid_signature(
    signature_entry: dict[str, Any],
    *,
    rule_digest: str,
    effective_from: str,
    effective_until: str | None,
    public_keys: dict[str, Ed25519PublicKey],
) -> str | None:
    reviewer = str(signature_entry.get("reviewer") or "").strip()
    signature_b64 = str(signature_entry.get("signature") or "").strip()
    if not reviewer or not signature_b64:
        return None
    public_key = public_keys.get(reviewer)
    if public_key is None:
        return None
    try:
        signature = base64.b64decode(signature_b64.encode("ascii"), validate=True)
        public_key.verify(signature, ratification_payload(rule_digest, reviewer, effective_from, effective_until))
    except (InvalidSignature, ValueError):
        return None
    return reviewer


def verify_ratification(candidate: dict[str, Any], entries: list[dict[str, Any]]) -> dict[str, Any]:
    matching = [entry for entry in entries if _entry_matches(entry, candidate)]
    if not matching:
        raise _ratification_error(candidate, "missing")
    if len(matching) > 1:
        raise _ratification_error(candidate, "ambiguous")
    entry = matching[0]
    effective_from = str(entry.get("effective_from") or "").strip()
    effective_until_raw = entry.get("effective_until")
    effective_until = str(effective_until_raw).strip() if effective_until_raw else None
    status = str(entry.get("review_status") or "").strip().lower()
    superseded_by = str(entry.get("superseded_by") or "").strip()
    rescinded_at = str(entry.get("rescinded_at") or "").strip()
    if status in RETIRED_STATUSES or superseded_by or rescinded_at:
        raise _ratification_error(candidate, "retired_or_superseded")
    if status not in RATIFIED_STATUSES:
        raise _ratification_error(candidate, "not_ratified")
    if not effective_from:
        raise _ratification_error(candidate, "effective_from_missing")
    digest = ratification_digest(candidate)
    if str(entry.get("rule_digest") or "").strip() != digest:
        raise _ratification_error(candidate, "digest_mismatch")
    try:
        threshold = _signature_threshold(entry)
        public_keys = _public_keys()
    except (RuntimeError, ValueError) as exc:
        raise _ratification_error(candidate, str(exc)) from exc
    valid_reviewers: set[str] = set()
    signature_entries = _signature_entries(entry)
    for signature_entry in signature_entries:
        reviewer = _valid_signature(
            signature_entry,
            rule_digest=digest,
            effective_from=effective_from,
            effective_until=effective_until,
            public_keys=public_keys,
        )
        if reviewer:
            valid_reviewers.add(reviewer)
    if len(valid_reviewers) < threshold:
        raise _ratification_error(candidate, "signature_threshold_not_met")
    return {
        "review_status": status,
        "reviewers": sorted(valid_reviewers),
        "effective_from": effective_from,
        "effective_until": effective_until,
        "superseded_by": None,
        "rescinded_at": None,
        "rule_digest": digest,
        "signature_scheme": "ed25519",
        "signature_threshold": threshold,
        "signature_count": len(valid_reviewers),
    }


def require_ratified_candidates(workdir: Path, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not candidates:
        return []
    entries = load_ratification_manifest(workdir)
    ratified: list[dict[str, Any]] = []
    for candidate in candidates:
        ratification = verify_ratification(candidate, entries)
        ratified.append(
            {
                **candidate,
                "validation_status": "human_ratified_signed",
                "effective_from": ratification["effective_from"],
                "effective_until": ratification["effective_until"],
                "ratification": ratification,
                "notes": [
                    *candidate.get("notes", []),
                    "Export required signed human ratification.",
                ],
            }
        )
    return ratified
