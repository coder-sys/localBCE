from __future__ import annotations

import argparse
import hashlib
import json
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SCHEMA_VERSION = "localbce-state-medicaid-source-registry-v1"
PREFLIGHT_SCHEMA_VERSION = "localbce-state-medicaid-source-preflight-v1"
PILOT_SEQUENCE = ("NC", "GA", "CA")
RULE_FAMILIES = (
    "eligibility",
    "provider_enrollment",
    "duplicate_claim",
    "timely_filing",
)
SOURCE_TYPES = {"agency_guidance", "manual", "state_plan"}
APPROVED_HOST_STATES = {
    "medicaid.ncdhhs.gov": "NC",
    "medicaid.georgia.gov": "GA",
    "mmis.georgia.gov": "GA",
    "dch.georgia.gov": "GA",
    "dhcs.ca.gov": "CA",
    "mcweb.apps.prd.cammis.medi-cal.ca.gov": "CA",
}
EXPECTED_SOURCE_COUNT = 15
EXPECTED_STATE_COUNTS = {"NC": 5, "GA": 5, "CA": 5}


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_nonempty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a nonempty string")
    return value


def _normalized_host(url: str) -> str:
    return (urlparse(url).hostname or "").lower().removeprefix("www.")


def validate_state_medicaid_registry(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("registry must be a JSON object")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {SCHEMA_VERSION}")
    _require_nonempty_string(payload.get("registry_id"), "registry_id")
    if payload.get("program") != "medicaid":
        raise ValueError("program must be medicaid")
    if tuple(payload.get("pilot_sequence", [])) != PILOT_SEQUENCE:
        raise ValueError("pilot_sequence must be NC, GA, CA")
    if tuple(payload.get("rule_families", [])) != RULE_FAMILIES:
        raise ValueError("rule_families must match the Medicaid Core V1 boundary")
    if payload.get("official_sources_only") is not True:
        raise ValueError("official_sources_only must be true")
    if payload.get("extraction_status") != "discovery_only_not_captured":
        raise ValueError("extraction_status must remain discovery_only_not_captured")
    if payload.get("runtime_activation") is not False:
        raise ValueError("runtime_activation must be false")
    if payload.get("proof_binding") is not False:
        raise ValueError("proof_binding must be false")

    sources = payload.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("sources must be a nonempty list")
    if len(sources) != EXPECTED_SOURCE_COUNT:
        raise ValueError(f"sources must contain exactly {EXPECTED_SOURCE_COUNT} entries")

    source_ids: set[str] = set()
    source_urls: set[str] = set()
    coverage = {
        state: {family: 0 for family in RULE_FAMILIES}
        for state in PILOT_SEQUENCE
    }
    state_counts = {state: 0 for state in PILOT_SEQUENCE}

    for index, source in enumerate(sources):
        prefix = f"sources[{index}]"
        if not isinstance(source, dict):
            raise ValueError(f"{prefix} must be an object")
        source_id = _require_nonempty_string(source.get("source_id"), f"{prefix}.source_id")
        state_code = source.get("state_code")
        if state_code not in PILOT_SEQUENCE:
            raise ValueError(f"{prefix}.state_code must be NC, GA, or CA")
        if source_id in source_ids:
            raise ValueError(f"duplicate source_id: {source_id}")
        if not source_id.startswith(f"medicaid-us-{state_code.lower()}-"):
            raise ValueError(f"{prefix}.source_id does not match state_code")
        source_ids.add(source_id)

        if source.get("jurisdiction") != f"US-{state_code}":
            raise ValueError(f"{prefix}.jurisdiction must be US-{state_code}")
        _require_nonempty_string(source.get("authority"), f"{prefix}.authority")
        _require_nonempty_string(source.get("source_family"), f"{prefix}.source_family")
        if source.get("source_type") not in SOURCE_TYPES:
            raise ValueError(f"{prefix}.source_type is unsupported")

        source_url = _require_nonempty_string(source.get("source_url"), f"{prefix}.source_url")
        parsed = urlparse(source_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError(f"{prefix}.source_url must be an unauthenticated HTTPS URL")
        if "example" in source_url.lower() or "placeholder" in source_url.lower():
            raise ValueError(f"{prefix}.source_url must not be a placeholder")
        host = _normalized_host(source_url)
        if APPROVED_HOST_STATES.get(host) != state_code:
            raise ValueError(f"{prefix}.source_url host is not approved for {state_code}")
        if source_url in source_urls:
            raise ValueError(f"duplicate source_url: {source_url}")
        source_urls.add(source_url)

        families = source.get("rule_families")
        if not isinstance(families, list) or not families:
            raise ValueError(f"{prefix}.rule_families must be a nonempty list")
        if len(families) != len(set(families)):
            raise ValueError(f"{prefix}.rule_families must not contain duplicates")
        unsupported = sorted(set(families) - set(RULE_FAMILIES))
        if unsupported:
            raise ValueError(f"{prefix}.rule_families contains unsupported values: {unsupported}")

        if source.get("official") is not True:
            raise ValueError(f"{prefix}.official must be true")
        if source.get("snapshot_status") != "not_captured":
            raise ValueError(f"{prefix}.snapshot_status must be not_captured")
        if source.get("source_hash") is not None:
            raise ValueError(f"{prefix}.source_hash must be null until capture")
        if source.get("review_status") != "not_reviewed":
            raise ValueError(f"{prefix}.review_status must be not_reviewed")
        if source.get("legal_verification_status") != "not_verified":
            raise ValueError(f"{prefix}.legal_verification_status must be not_verified")
        if source.get("runtime_eligibility_status") != "ineligible_shadow_only":
            raise ValueError(
                f"{prefix}.runtime_eligibility_status must be ineligible_shadow_only"
            )

        state_counts[state_code] += 1
        for family in families:
            coverage[state_code][family] += 1

    for state_code, family_counts in coverage.items():
        missing = [family for family, count in family_counts.items() if count == 0]
        if missing:
            raise ValueError(f"{state_code} is missing rule-family coverage: {missing}")
    if state_counts != EXPECTED_STATE_COUNTS:
        raise ValueError("each Medicaid Core V1 state must contain exactly five sources")

    return {
        "status": "ok",
        "schema_version": SCHEMA_VERSION,
        "registry_id": payload["registry_id"],
        "program": "medicaid",
        "source_count": len(sources),
        "state_counts": state_counts,
        "rule_family_coverage": coverage,
        "runtime_activation": False,
        "proof_binding": False,
        "canonical_sha256": canonical_sha256(payload),
    }


def validate_state_medicaid_preflight(
    payload: Any,
    registry: dict[str, Any],
) -> dict[str, Any]:
    registry_summary = validate_state_medicaid_registry(registry)
    if not isinstance(payload, dict):
        raise ValueError("preflight report must be a JSON object")
    if payload.get("schema_version") != PREFLIGHT_SCHEMA_VERSION:
        raise ValueError(f"preflight schema_version must be {PREFLIGHT_SCHEMA_VERSION}")
    if payload.get("registry_id") != registry["registry_id"]:
        raise ValueError("preflight registry_id does not match the registry")
    if payload.get("registry_canonical_sha256") != registry_summary["canonical_sha256"]:
        raise ValueError("preflight registry hash does not match the registry")
    try:
        date.fromisoformat(str(payload.get("checked_at", "")))
    except ValueError as error:
        raise ValueError("preflight checked_at must be an ISO date") from error
    if payload.get("source_count") != EXPECTED_SOURCE_COUNT:
        raise ValueError("preflight source_count must be 15")
    if payload.get("http_200_count") != EXPECTED_SOURCE_COUNT:
        raise ValueError("preflight http_200_count must be 15")
    if payload.get("capture_ready_count") != 10:
        raise ValueError("preflight capture_ready_count must be 10")
    if payload.get("special_adapter_required_count") != 5:
        raise ValueError("preflight special_adapter_required_count must be 5")
    for field in (
        "source_bytes_captured",
        "legal_evidence_captured",
        "database_jobs_created",
        "runtime_activation",
        "proof_binding",
    ):
        if payload.get(field) is not False:
            raise ValueError(f"preflight {field} must be false")

    expected_sources = {source["source_id"]: source for source in registry["sources"]}
    report_sources = payload.get("sources")
    if not isinstance(report_sources, list) or len(report_sources) != EXPECTED_SOURCE_COUNT:
        raise ValueError("preflight sources must contain exactly 15 entries")
    seen: set[str] = set()
    status_counts = {"capture_ready": 0, "special_adapter_required": 0}
    adapter_required_ids: list[str] = []
    for index, source in enumerate(report_sources):
        prefix = f"preflight.sources[{index}]"
        if not isinstance(source, dict):
            raise ValueError(f"{prefix} must be an object")
        source_id = _require_nonempty_string(source.get("source_id"), f"{prefix}.source_id")
        if source_id in seen:
            raise ValueError(f"duplicate preflight source_id: {source_id}")
        seen.add(source_id)
        registry_source = expected_sources.get(source_id)
        if registry_source is None:
            raise ValueError(f"unknown preflight source_id: {source_id}")
        if source.get("http_status") != 200:
            raise ValueError(f"{prefix}.http_status must be 200")
        if not isinstance(source.get("response_bytes"), int) or source["response_bytes"] <= 0:
            raise ValueError(f"{prefix}.response_bytes must be positive")
        if not isinstance(source.get("redirect_count"), int) or source["redirect_count"] < 0:
            raise ValueError(f"{prefix}.redirect_count must be nonnegative")
        _require_nonempty_string(source.get("content_type"), f"{prefix}.content_type")
        parser_profile = _require_nonempty_string(
            source.get("parser_profile"), f"{prefix}.parser_profile"
        )
        status = source.get("preflight_status")
        if status not in status_counts:
            raise ValueError(f"{prefix}.preflight_status is unsupported")
        state_code = registry_source["state_code"]
        expected_status = (
            "special_adapter_required" if state_code == "CA" else "capture_ready"
        )
        if status != expected_status:
            raise ValueError(
                f"{prefix}.preflight_status must be {expected_status} for {state_code}"
            )
        if state_code == "CA" and not (
            parser_profile.startswith("incapsula_")
            or parser_profile.startswith("javascript_spa_")
        ):
            raise ValueError(f"{prefix} must retain the California adapter blocker")
        status_counts[status] += 1
        if status == "special_adapter_required":
            adapter_required_ids.append(source_id)

    if seen != set(expected_sources):
        raise ValueError("preflight source IDs do not exactly match the registry")
    if status_counts != {"capture_ready": 10, "special_adapter_required": 5}:
        raise ValueError("preflight status counts do not match Medicaid Core V1")
    return {
        "status": "ok",
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "registry_id": registry["registry_id"],
        "source_count": EXPECTED_SOURCE_COUNT,
        "status_counts": status_counts,
        "adapter_required_source_ids": sorted(adapter_required_ids),
        "legal_evidence_captured": False,
        "runtime_activation": False,
        "proof_binding": False,
        "canonical_sha256": canonical_sha256(payload),
    }


def build_postgres_supplemental_registry(
    registry: dict[str, Any],
    preflight: dict[str, Any],
) -> dict[str, Any]:
    registry_summary = validate_state_medicaid_registry(registry)
    preflight_summary = validate_state_medicaid_preflight(preflight, registry)
    preflight_by_id = {
        source["source_id"]: source for source in preflight["sources"]
    }
    sources: list[dict[str, Any]] = []
    for source in registry["sources"]:
        preflight_source = preflight_by_id[source["source_id"]]
        adapter_required = (
            preflight_source["preflight_status"] == "special_adapter_required"
        )
        sources.append(
            {
                "source_id": source["source_id"],
                "registry_version": registry["registry_id"],
                "canonical_url": source["source_url"],
                "program": "medicaid",
                "jurisdiction": {
                    "country": "US",
                    "level": "state",
                    "state": source["state_code"],
                },
                "issuer": source["authority"],
                "source_type": source["source_type"],
                "required": False,
                "official": True,
                "metadata": {
                    "source_family": source["source_family"],
                    "rule_families": source["rule_families"],
                    "snapshot_status": "not_captured",
                    "preflight_status": preflight_source["preflight_status"],
                    "parser_profile": preflight_source["parser_profile"],
                    "adapter_required": adapter_required,
                    "captured_legal_evidence": False,
                    "human_approved": False,
                    "review_status": "not_reviewed",
                    "legal_verification_status": "not_verified",
                    "runtime_eligibility_status": "ineligible_shadow_only",
                    "runtime_activation": False,
                    "proof_binding": False,
                },
            }
        )
    return {
        "schema_version": "localbce-supplemental-source-registry-v1",
        "registry_id": registry["registry_id"],
        "registry_manifest_sha256": registry_summary["canonical_sha256"],
        "preflight_manifest_sha256": preflight_summary["canonical_sha256"],
        "supplemental": True,
        "registry_activation": False,
        "runtime_activation": False,
        "proof_binding": False,
        "sources": sorted(sources, key=lambda item: item["source_id"]),
    }


def load_state_medicaid_registry(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ValueError(f"could not read registry: {error}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"registry is not valid JSON: {error}") from error
    return payload, validate_state_medicaid_registry(payload)


def load_state_medicaid_preflight(
    path: Path,
    registry: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ValueError(f"could not read preflight report: {error}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"preflight report is not valid JSON: {error}") from error
    return payload, validate_state_medicaid_preflight(payload, registry)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the Medicaid Core V1 state source registry"
    )
    parser.add_argument("registry", type=Path)
    parser.add_argument("--preflight", type=Path)
    args = parser.parse_args(argv)
    try:
        registry, summary = load_state_medicaid_registry(args.registry)
        if args.preflight is not None:
            _, preflight_summary = load_state_medicaid_preflight(
                args.preflight, registry
            )
            summary = {**summary, "preflight": preflight_summary}
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
