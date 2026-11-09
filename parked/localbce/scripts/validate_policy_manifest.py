#!/usr/bin/env python3
"""Validate and canonically hash the governed STARK policy manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SCHEMA_VERSION = "localbce-stark-policy-manifest-v1"
HASH_ALGORITHM = "sha256_canonical_json_without_canonical_hash"
HEX32 = re.compile(r"^0x[0-9a-f]{64}$")
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
STATUSES = {"example_inactive", "pilot_approved", "retired"}


class ManifestError(ValueError):
    pass


def canonical_hash(manifest: dict[str, Any]) -> str:
    payload = dict(manifest)
    payload.pop("canonical_hash", None)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return "0x" + hashlib.sha256(encoded).hexdigest()


def require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ManifestError(f"{field} must be a non-empty string")
    return value


def parse_utc(value: Any, field: str) -> datetime:
    text = require_text(value, field)
    if not text.endswith("Z"):
        raise ManifestError(f"{field} must be UTC and end in Z")
    try:
        return datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise ManifestError(f"{field} is not a valid ISO-8601 timestamp") from exc


def require_https(value: Any, field: str) -> str:
    text = require_text(value, field)
    parsed = urlparse(text)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ManifestError(f"{field} must be an absolute https URL")
    return text


def validate(manifest: dict[str, Any]) -> None:
    required = {
        "schema_version", "manifest_id", "version", "status", "issuer",
        "effective_from", "effective_until", "maximum_evidence_age_seconds",
        "fee_schedule_root", "official_sources", "canonical_hash_algorithm",
        "canonical_hash", "authenticity_disclaimer",
    }
    unknown = set(manifest) - required
    missing = required - set(manifest)
    if missing or unknown:
        raise ManifestError(f"manifest fields mismatch; missing={sorted(missing)}, unknown={sorted(unknown)}")
    if manifest["schema_version"] != SCHEMA_VERSION:
        raise ManifestError(f"schema_version must be {SCHEMA_VERSION}")
    require_text(manifest["manifest_id"], "manifest_id")
    if not isinstance(manifest["version"], str) or not SEMVER.fullmatch(manifest["version"]):
        raise ManifestError("version must be semantic major.minor.patch")
    if manifest["status"] not in STATUSES:
        raise ManifestError(f"status must be one of {sorted(STATUSES)}")

    issuer = manifest["issuer"]
    if not isinstance(issuer, dict) or set(issuer) != {"issuer_id", "name", "authority_url"}:
        raise ManifestError("issuer must contain issuer_id, name, and authority_url only")
    require_text(issuer["issuer_id"], "issuer.issuer_id")
    require_text(issuer["name"], "issuer.name")
    require_https(issuer["authority_url"], "issuer.authority_url")

    effective_from = parse_utc(manifest["effective_from"], "effective_from")
    effective_until = parse_utc(manifest["effective_until"], "effective_until")
    if effective_until <= effective_from:
        raise ManifestError("effective_until must be after effective_from")
    if not isinstance(manifest["maximum_evidence_age_seconds"], int) or manifest["maximum_evidence_age_seconds"] <= 0:
        raise ManifestError("maximum_evidence_age_seconds must be a positive integer")
    if not isinstance(manifest["fee_schedule_root"], str) or not HEX32.fullmatch(manifest["fee_schedule_root"]):
        raise ManifestError("fee_schedule_root must be lowercase bytes32 hex")
    if int(manifest["fee_schedule_root"], 16) == 0:
        raise ManifestError("fee_schedule_root must be nonzero")

    sources = manifest["official_sources"]
    if not isinstance(sources, list) or not sources:
        raise ManifestError("official_sources must be a non-empty list")
    seen: set[str] = set()
    for index, source in enumerate(sources):
        expected = {"source_id", "issuer_id", "jurisdiction", "url", "official", "required"}
        if not isinstance(source, dict) or set(source) != expected:
            raise ManifestError(f"official_sources[{index}] has invalid fields")
        source_id = require_text(source["source_id"], f"official_sources[{index}].source_id")
        if source_id in seen:
            raise ManifestError(f"duplicate source_id: {source_id}")
        seen.add(source_id)
        require_text(source["issuer_id"], f"official_sources[{index}].issuer_id")
        require_text(source["jurisdiction"], f"official_sources[{index}].jurisdiction")
        require_https(source["url"], f"official_sources[{index}].url")
        if source["official"] is not True or not isinstance(source["required"], bool):
            raise ManifestError(f"official_sources[{index}] must be official and declare required")

    if manifest["canonical_hash_algorithm"] != HASH_ALGORITHM:
        raise ManifestError(f"canonical_hash_algorithm must be {HASH_ALGORITHM}")
    expected_hash = canonical_hash(manifest)
    if manifest["canonical_hash"] != expected_hash:
        raise ManifestError(f"canonical_hash mismatch: expected {expected_hash}")
    disclaimer = require_text(manifest["authenticity_disclaimer"], "authenticity_disclaimer").lower()
    if "not" not in disclaimer or "authentic" not in disclaimer or "legal" not in disclaimer:
        raise ManifestError("authenticity_disclaimer must state legal/source authenticity limitations")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--write-hash", action="store_true")
    args = parser.parse_args()
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise ManifestError("manifest must be a JSON object")
        if args.write_hash:
            manifest["canonical_hash"] = canonical_hash(manifest)
            args.manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        validate(manifest)
    except (OSError, json.JSONDecodeError, ManifestError) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"status": "ok", "manifest": str(args.manifest), "canonical_hash": manifest["canonical_hash"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
