from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


MANIFEST_SCHEMA = "localbce-rules-baseline-manifest-v1"
EXPECTED_COUNTS = {
    "source_candidates": 226,
    "mapping_records": 221,
    "promotion_records": 221,
    "qa_pass_records": 191,
    "programs": 51,
    "missing_lineage": 5,
}
EXPECTED_ROLES = {"source_candidates", "mapping_qa", "promotion_reviews"}
EXPECTED_CANDIDATE_MODE = "claude_server_web_search_no_local_fetch_no_local_parse"
EXPECTED_CANDIDATE_STATUS = "claude_web_grounded_candidate"
EXPECTED_MAPPING_STATUS = "deterministic_mapping_candidate_not_legal_verified"
EXPECTED_PROMOTION_STATUS = "candidate_only_not_verified"
EXPECTED_REVIEW_STATUS = "promotion_ready"
SAFETY_BOOLEAN_FIELDS = {
    "runtime_activation",
    "proof_binding",
    "adjudication_effect",
    "runtime_eligible",
    "production_usable",
    "legally_verified",
    "human_approved",
}


class RulesBaselineError(ValueError):
    """Raised when the tracked rules baseline fails an integrity check."""


def _load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RulesBaselineError(f"missing {label}: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RulesBaselineError(f"invalid JSON in {label}: {exc.msg}") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except FileNotFoundError as exc:
        raise RulesBaselineError(f"missing baseline artifact: {path}") from exc
    return digest.hexdigest()


def _safe_artifact_path(workdir: Path, relative_path: Any) -> Path:
    if not isinstance(relative_path, str) or not relative_path.strip():
        raise RulesBaselineError("baseline artifact path must be a non-empty string")
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise RulesBaselineError(f"unsafe baseline artifact path: {relative_path}")
    resolved = (workdir / relative).resolve()
    try:
        resolved.relative_to(workdir.resolve())
    except ValueError as exc:
        raise RulesBaselineError(
            f"baseline artifact escapes the rules workdir: {relative_path}"
        ) from exc
    return resolved


def _require_list(value: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise RulesBaselineError(f"{label} must be a list of objects")
    return value


def _require_unique_ids(
    records: list[dict[str, Any]], field: str, label: str
) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for index, record in enumerate(records):
        value = record.get(field)
        if not isinstance(value, str) or not value.strip():
            raise RulesBaselineError(f"{label}[{index}].{field} must be non-empty")
        if value in indexed:
            raise RulesBaselineError(f"duplicate {label} {field}: {value}")
        indexed[value] = record
    return indexed


def _require_provenance(records: list[dict[str, Any]], label: str) -> None:
    for index, record in enumerate(records):
        source_url = record.get("source_url")
        citation = record.get("citation_text")
        if not isinstance(source_url, str) or not source_url.startswith("https://"):
            raise RulesBaselineError(f"{label}[{index}] must have an HTTPS source_url")
        if not isinstance(citation, str) or not citation.strip():
            raise RulesBaselineError(f"{label}[{index}] must have citation_text")


def _reject_safety_claims(value: Any, path: str = "root") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key in SAFETY_BOOLEAN_FIELDS and child is not False:
                raise RulesBaselineError(f"{child_path} must be false")
            _reject_safety_claims(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_safety_claims(child, f"{path}[{index}]")


def _validate_manifest(manifest: Any) -> list[dict[str, Any]]:
    if not isinstance(manifest, dict):
        raise RulesBaselineError("rules baseline manifest must be an object")
    if manifest.get("schema_version") != MANIFEST_SCHEMA:
        raise RulesBaselineError("rules baseline manifest has the wrong schema_version")
    for field in ("runtime_activation", "proof_binding", "adjudication_effect"):
        if manifest.get(field) is not False:
            raise RulesBaselineError(f"rules baseline manifest {field} must be false")
    if manifest.get("legal_verification_status") != "not_verified":
        raise RulesBaselineError("rules baseline must remain legally unverified")
    if manifest.get("expected_counts") != EXPECTED_COUNTS:
        raise RulesBaselineError("rules baseline expected_counts do not match the pinned baseline")

    artifacts = _require_list(manifest.get("artifacts"), "manifest.artifacts")
    roles = [artifact.get("role") for artifact in artifacts]
    if len(artifacts) != len(EXPECTED_ROLES) or set(roles) != EXPECTED_ROLES:
        raise RulesBaselineError("rules baseline manifest must define each required artifact once")
    if len(roles) != len(set(roles)):
        raise RulesBaselineError("rules baseline manifest contains a duplicate artifact role")
    return artifacts


def validate_rules_baseline(
    workdir: Path, manifest_path: Path | None = None
) -> dict[str, Any]:
    workdir = workdir.resolve()
    manifest_path = (
        manifest_path.resolve()
        if manifest_path is not None
        else workdir / "data" / "rules_baseline_manifest_v1.json"
    )
    manifest = _load_json(manifest_path, "rules baseline manifest")
    artifacts = _validate_manifest(manifest)

    payloads: dict[str, Any] = {}
    artifact_hashes: dict[str, str] = {}
    for artifact in artifacts:
        role = artifact["role"]
        expected_hash = artifact.get("sha256")
        if not isinstance(expected_hash, str) or len(expected_hash) != 64:
            raise RulesBaselineError(f"manifest artifact {role} has an invalid SHA-256")
        path = _safe_artifact_path(workdir, artifact.get("path"))
        actual_hash = _sha256(path)
        if actual_hash != expected_hash:
            raise RulesBaselineError(
                f"baseline artifact hash mismatch for {role}: "
                f"expected {expected_hash}, got {actual_hash}"
            )
        payloads[role] = _load_json(path, f"baseline artifact {role}")
        artifact_hashes[role] = actual_hash

    source_payload = payloads["source_candidates"]
    mapping_payload = payloads["mapping_qa"]
    promotion_payload = payloads["promotion_reviews"]
    if not isinstance(source_payload, dict) or not isinstance(mapping_payload, dict):
        raise RulesBaselineError("candidate and mapping baseline artifacts must be objects")

    source_records = _require_list(
        source_payload.get("candidate_rules"), "source candidate records"
    )
    mapping_records = _require_list(mapping_payload.get("candidates"), "mapping records")
    promotion_records = _require_list(promotion_payload, "promotion records")
    if source_payload.get("candidate_rule_count") != EXPECTED_COUNTS["source_candidates"]:
        raise RulesBaselineError("source artifact candidate_rule_count is not pinned to 226")
    if len(source_records) != EXPECTED_COUNTS["source_candidates"]:
        raise RulesBaselineError("source candidate record count does not match the baseline")
    if len(mapping_records) != EXPECTED_COUNTS["mapping_records"]:
        raise RulesBaselineError("mapping record count does not match the baseline")
    if len(promotion_records) != EXPECTED_COUNTS["promotion_records"]:
        raise RulesBaselineError("promotion record count does not match the baseline")

    source_by_id = _require_unique_ids(source_records, "candidate_id", "source candidates")
    mapping_by_id = _require_unique_ids(mapping_records, "source_candidate_id", "mappings")
    promotion_by_id = _require_unique_ids(
        promotion_records, "candidate_id", "promotion records"
    )
    if set(mapping_by_id) != set(promotion_by_id):
        raise RulesBaselineError("mapping and promotion candidate lineage sets differ")
    unknown_ids = set(mapping_by_id) - set(source_by_id)
    if unknown_ids:
        raise RulesBaselineError(
            f"mapping lineage references unknown candidates: {sorted(unknown_ids)}"
        )
    missing_lineage = sorted(set(source_by_id) - set(mapping_by_id))
    if len(missing_lineage) != EXPECTED_COUNTS["missing_lineage"]:
        raise RulesBaselineError("missing lineage count does not match the pinned baseline")

    _require_provenance(source_records, "source candidates")
    _require_provenance(mapping_records, "mappings")
    _require_provenance(promotion_records, "promotion records")
    for candidate_id, source in source_by_id.items():
        if source.get("mode") != EXPECTED_CANDIDATE_MODE:
            raise RulesBaselineError(f"unexpected extraction mode for {candidate_id}")
        if source.get("verification_status") != EXPECTED_CANDIDATE_STATUS:
            raise RulesBaselineError(f"unexpected candidate status for {candidate_id}")
    for candidate_id, mapping in mapping_by_id.items():
        if mapping.get("validation_status") != EXPECTED_MAPPING_STATUS:
            raise RulesBaselineError(f"mapping {candidate_id} claims an unexpected status")
        source = source_by_id[candidate_id]
        if mapping.get("program") != source.get("program"):
            raise RulesBaselineError(f"mapping program mismatch for {candidate_id}")
        if mapping.get("source_url") != source.get("source_url"):
            raise RulesBaselineError(f"mapping source URL mismatch for {candidate_id}")
        if mapping.get("citation_text") != source.get("citation_text"):
            raise RulesBaselineError(f"mapping citation mismatch for {candidate_id}")
    for candidate_id, promotion in promotion_by_id.items():
        if promotion.get("promotion_status") != EXPECTED_PROMOTION_STATUS:
            raise RulesBaselineError(f"promotion {candidate_id} claims an unexpected status")
        if promotion.get("review_status") != EXPECTED_REVIEW_STATUS:
            raise RulesBaselineError(f"promotion {candidate_id} has an unexpected review status")
        if promotion.get("verification_status") != EXPECTED_CANDIDATE_STATUS:
            raise RulesBaselineError(f"promotion {candidate_id} has an unexpected source status")
        source = source_by_id[candidate_id]
        if promotion.get("program") != source.get("program"):
            raise RulesBaselineError(f"promotion program mismatch for {candidate_id}")
        for field in ("source_url", "citation_text", "statement"):
            if promotion.get(field) != source.get(field):
                raise RulesBaselineError(
                    f"promotion {field} mismatch for {candidate_id}"
                )

    qa_pass_records = sum(
        record.get("qa_status") == "qa_pass" for record in mapping_records
    )
    if qa_pass_records != EXPECTED_COUNTS["qa_pass_records"]:
        raise RulesBaselineError("QA-pass count does not match the pinned baseline")
    program_values = [record.get("program") for record in source_records]
    if any(
        not isinstance(program, str) or not program.strip()
        for program in program_values
    ):
        raise RulesBaselineError("source candidates contain an invalid program")
    programs = sorted(set(program_values))
    if len(programs) != EXPECTED_COUNTS["programs"]:
        raise RulesBaselineError("program coverage does not match the pinned baseline")

    _reject_safety_claims(manifest)
    for role, payload in payloads.items():
        _reject_safety_claims(payload, role)

    return {
        "status": "ok",
        "schema_version": MANIFEST_SCHEMA,
        "manifest_sha256": _sha256(manifest_path),
        "artifact_sha256": artifact_hashes,
        "source_candidates": len(source_records),
        "mapping_records": len(mapping_records),
        "promotion_records": len(promotion_records),
        "qa_pass_records": qa_pass_records,
        "programs": len(programs),
        "missing_lineage": len(missing_lineage),
        "runtime_activation": False,
        "proof_binding": False,
        "adjudication_effect": False,
        "legal_verification_status": "not_verified",
    }
