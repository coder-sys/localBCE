from __future__ import annotations

import hashlib
import json
import re
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse, urlunparse

from .canonical_rules import canonical_sha256
from .canonical_rules import _parse_iso_date, _validate_condition, _validate_outcome
from .domain import GOVERNMENT_RULE_TAXONOMY, valid_program


SOURCE_REGISTRY_SCHEMA = "localbce-federal-source-registry-v1"
SOURCE_SNAPSHOT_SCHEMA = "localbce-source-snapshot-v1"
SECTION_SCHEMA = "localbce-source-section-v1"
INFERENCE_SCHEMA = "localbce-grounded-inference-v1"
QUALITY_SCHEMA = "localbce-rules-quality-report-v1"
RELEASE_SCHEMA = "localbce-rules-corpus-release-v1"
SHADOW_BUNDLE_SCHEMA = "localbce-grounded-shadow-bundle-v1"
CLAUDE_MODEL = "claude-sonnet-4-6"
EXTRACTION_PROMPT_VERSION = "grounded-atomic-extraction-v1"
CRITIQUE_PROMPT_VERSION = "grounded-atomic-critique-v1"
CORPUS_MILESTONES = (5_100, 51_000, 600_000)
QUALITY_THRESHOLDS = {
    "source_snapshot_coverage": 1.0,
    "citation_coverage": 1.0,
    "evidence_span_precision": 0.99,
    "typed_mapping_precision": 0.98,
    "program_classification_accuracy": 0.95,
    "minimum_program_accuracy": 0.90,
}


def all_programs() -> list[str]:
    taxonomy = GOVERNMENT_RULE_TAXONOMY["government_transaction_rules"]
    return [program for programs in taxonomy.values() for program in programs]


def program_quotas(target: int = 600_000) -> dict[str, int]:
    programs = all_programs()
    base, remainder = divmod(target, len(programs))
    return {
        program: base + (1 if index < remainder else 0)
        for index, program in enumerate(programs)
    }


def stable_id(prefix: str, *parts: Any) -> str:
    return f"{prefix}_{canonical_sha256(list(parts))[:32]}"


def canonical_url(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("official source URL must use https")
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    if path != "/":
        path = path.rstrip("/")
    return urlunparse(("https", parsed.netloc.lower(), path, "", parsed.query, ""))


def load_source_registry(workdir: Path, descriptor: Path | None = None) -> dict[str, Any]:
    manifest_dir = workdir / "data" / "source_manifests"
    descriptor_path = descriptor or manifest_dir / "federal_source_registry_v1.json"
    registry = json.loads(descriptor_path.read_text(encoding="utf-8"))
    errors: list[str] = []
    if registry.get("schema_version") != SOURCE_REGISTRY_SCHEMA:
        errors.append("unsupported federal source registry schema")
    pack_path = manifest_dir / str(registry.get("source_pack_path", ""))
    if not pack_path.is_file():
        raise ValueError("source pack does not exist")
    pack_bytes = pack_path.read_bytes()
    pack_hash = hashlib.sha256(pack_bytes).hexdigest()
    if pack_hash != registry.get("source_pack_sha256"):
        errors.append("source pack hash mismatch")
    pack = json.loads(pack_bytes)
    sources = pack.get("sources")
    if not isinstance(sources, list):
        raise ValueError("source pack sources must be a list")

    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            errors.append(f"sources[{index}] must be an object")
            continue
        try:
            url = canonical_url(str(source.get("url", "")))
        except ValueError as exc:
            errors.append(f"sources[{index}]: {exc}")
            continue
        program = valid_program(source.get("program"))
        if not program:
            errors.append(f"sources[{index}] has an unknown program")
            continue
        if source.get("official") is not True:
            errors.append(f"sources[{index}] must be official")
        key = (url, program)
        if key in seen:
            continue
        seen.add(key)
        normalized.append(
            {
                "source_id": stable_id("src", registry["registry_id"], url, program),
                "registry_version": registry["registry_id"],
                "canonical_url": url,
                "program": program,
                "jurisdiction": {"country": "US", "level": "federal", "state": None},
                "issuer": str(source.get("issuer") or urlparse(url).netloc).strip(),
                "source_type": str(source.get("source_type") or "unknown").strip(),
                "required": bool(source.get("required", False)),
                "official": True,
                "metadata": {
                    "name": source.get("name"),
                    "vertical": source.get("vertical"),
                    "reason": source.get("reason"),
                },
            }
        )
    if sorted({source["program"] for source in normalized}) != sorted(all_programs()):
        errors.append("source registry must cover exactly all 51 programs")
    if len(normalized) != registry.get("source_entrypoints"):
        errors.append("source registry entrypoint count mismatch")
    if errors:
        raise ValueError("; ".join(errors))
    return {
        **registry,
        "source_pack_sha256": pack_hash,
        "sources": sorted(normalized, key=lambda item: (item["program"], item["canonical_url"])),
        "program_quotas": program_quotas(int(registry["target_unique_grounded_candidates"])),
    }


def build_source_snapshot(
    source: dict[str, Any],
    raw_bytes: bytes,
    *,
    retrieved_at: str,
    mime_type: str,
    http_status: int = 200,
    effective_metadata: dict[str, Any] | None = None,
    text_layer_kind: str = "native",
) -> dict[str, Any]:
    if not raw_bytes:
        raise ValueError("source snapshot bytes cannot be empty")
    if text_layer_kind not in {"native", "ocr", "none"}:
        raise ValueError("unsupported text layer kind")
    parsed_time = datetime.fromisoformat(retrieved_at.replace("Z", "+00:00"))
    if parsed_time.tzinfo is None:
        raise ValueError("retrieved_at must include a timezone")
    snapshot_hash = hashlib.sha256(raw_bytes).hexdigest()
    return {
        "schema_version": SOURCE_SNAPSHOT_SCHEMA,
        "snapshot_hash": snapshot_hash,
        "source_id": source["source_id"],
        "canonical_url": canonical_url(source["canonical_url"]),
        "retrieved_at": parsed_time.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "http_status": int(http_status),
        "mime_type": mime_type.split(";", 1)[0].strip().lower(),
        "issuer": source["issuer"],
        "effective_metadata": effective_metadata or {},
        "compression": "zlib",
        "compressed_bytes": zlib.compress(raw_bytes, level=9),
        "uncompressed_size": len(raw_bytes),
        "text_layer_kind": text_layer_kind,
    }


def restore_snapshot_bytes(snapshot: dict[str, Any]) -> bytes:
    if snapshot.get("compression") != "zlib":
        raise ValueError("unsupported source snapshot compression")
    raw = zlib.decompress(snapshot["compressed_bytes"])
    if len(raw) != snapshot.get("uncompressed_size"):
        raise ValueError("source snapshot size mismatch")
    if hashlib.sha256(raw).hexdigest() != snapshot.get("snapshot_hash"):
        raise ValueError("source snapshot hash mismatch")
    return raw


def normalize_source_text(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\x00", "")
    lines = [re.sub(r"[\t ]+", " ", line).strip() for line in text.split("\n")]
    return "\n".join(line for line in lines if line).strip()


def segment_text(
    snapshot_hash: str,
    text: str,
    *,
    parser_name: str,
    parser_version: str = "1",
    ocr_used: bool = False,
    max_chars: int = 12_000,
) -> list[dict[str, Any]]:
    normalized = normalize_source_text(text)
    if not normalized:
        return []
    paragraphs = normalized.split("\n")
    chunks: list[str] = []
    current: list[str] = []
    current_size = 0
    for paragraph in paragraphs:
        extra = len(paragraph) + (1 if current else 0)
        if current and current_size + extra > max_chars:
            chunks.append("\n".join(current))
            current = []
            current_size = 0
        if len(paragraph) > max_chars:
            if current:
                chunks.append("\n".join(current))
                current = []
                current_size = 0
            chunks.extend(
                paragraph[start : start + max_chars]
                for start in range(0, len(paragraph), max_chars)
            )
            continue
        current.append(paragraph)
        current_size += extra
    if current:
        chunks.append("\n".join(current))

    sections: list[dict[str, Any]] = []
    search_from = 0
    for ordinal, chunk in enumerate(chunks):
        char_start = normalized.index(chunk, search_from)
        char_end = char_start + len(chunk)
        search_from = char_end
        text_hash = hashlib.sha256(chunk.encode("utf-8")).hexdigest()
        heading = chunk.split("\n", 1)[0][:240]
        sections.append(
            {
                "schema_version": SECTION_SCHEMA,
                "section_id": stable_id("sec", snapshot_hash, ordinal, text_hash),
                "snapshot_hash": snapshot_hash,
                "parent_section_id": None,
                "ordinal": ordinal,
                "hierarchy_path": [heading],
                "heading": heading,
                "normalized_text": chunk,
                "normalized_text_hash": text_hash,
                "source_char_start": char_start,
                "source_char_end": char_end,
                "parser_name": parser_name,
                "parser_version": parser_version,
                "ocr_used": ocr_used,
            }
        )
    return sections


def build_evidence_span(section: dict[str, Any], char_start: int, char_end: int) -> dict[str, Any]:
    text = section["normalized_text"]
    if char_start < 0 or char_end <= char_start or char_end > len(text):
        raise ValueError("evidence character offsets are out of range")
    quote = text[char_start:char_end]
    byte_start = len(text[:char_start].encode("utf-8"))
    byte_end = byte_start + len(quote.encode("utf-8"))
    return {
        "section_id": section["section_id"],
        "snapshot_hash": section["snapshot_hash"],
        "char_start": char_start,
        "char_end": char_end,
        "byte_start": byte_start,
        "byte_end": byte_end,
        "quote": quote,
        "evidence_hash": hashlib.sha256(quote.encode("utf-8")).hexdigest(),
    }


def validate_evidence_span(section: dict[str, Any], evidence: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if evidence.get("section_id") != section.get("section_id"):
        errors.append("evidence section_id mismatch")
    if evidence.get("snapshot_hash") != section.get("snapshot_hash"):
        errors.append("evidence snapshot_hash mismatch")
    try:
        expected = build_evidence_span(section, int(evidence.get("char_start")), int(evidence.get("char_end")))
    except (TypeError, ValueError) as exc:
        return errors + [str(exc)]
    for field in ("byte_start", "byte_end", "quote", "evidence_hash"):
        if evidence.get(field) != expected[field]:
            errors.append(f"evidence {field} mismatch")
    return errors


def inference_idempotency_key(
    section: dict[str, Any], prompt_version: str, model_version: str, schema_version: str
) -> str:
    return canonical_sha256(
        {
            "source_hash": section["snapshot_hash"],
            "section_hash": section["normalized_text_hash"],
            "prompt_version": prompt_version,
            "model_version": model_version,
            "schema_version": schema_version,
        }
    )


def build_inference_request(
    section: dict[str, Any],
    program: str,
    *,
    pass_number: int,
    proposed_candidates: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if pass_number not in {1, 2}:
        raise ValueError("inference pass must be 1 or 2")
    if not valid_program(program):
        raise ValueError("unknown program")
    prompt_version = EXTRACTION_PROMPT_VERSION if pass_number == 1 else CRITIQUE_PROMPT_VERSION
    request = {
        "schema_version": INFERENCE_SCHEMA,
        "pass": pass_number,
        "prompt_version": prompt_version,
        "model_version": CLAUDE_MODEL,
        "program": program,
        "section": {
            "section_id": section["section_id"],
            "snapshot_hash": section["snapshot_hash"],
            "heading": section.get("heading"),
            "text": section["normalized_text"],
        },
        "idempotency_key": inference_idempotency_key(section, prompt_version, CLAUDE_MODEL, INFERENCE_SCHEMA),
        "constraints": {
            "source_text_only": True,
            "exact_evidence_offsets_required": True,
            "atomic_candidates_only": True,
            "may_set_review_status": False,
            "may_set_legal_status": False,
            "may_set_runtime_eligibility": False,
            "may_set_proof_binding": False,
        },
    }
    if pass_number == 2:
        if not proposed_candidates:
            raise ValueError("critique pass requires proposed candidates")
        request["proposed_candidates"] = proposed_candidates
    elif proposed_candidates is not None:
        raise ValueError("extraction pass cannot include proposed candidates")
    return request


def validate_inference_candidates(
    section: dict[str, Any], response: dict[str, Any], *, expected_pass: int
) -> list[str]:
    errors: list[str] = []
    if response.get("schema_version") != INFERENCE_SCHEMA:
        errors.append("unsupported inference response schema")
    if response.get("pass") != expected_pass:
        errors.append("inference response pass mismatch")
    candidates = response.get("candidates")
    if not isinstance(candidates, list):
        return errors + ["inference candidates must be a list"]
    forbidden = {
        "review_status",
        "legal_verification_status",
        "runtime_eligibility_status",
        "runtime_activation",
        "proof_binding",
    }
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, dict):
            errors.append(f"candidates[{index}] must be an object")
            continue
        illegal = sorted(forbidden.intersection(candidate))
        if illegal:
            errors.append(f"candidates[{index}] sets forbidden status fields: {', '.join(illegal)}")
        if not valid_program(candidate.get("program")):
            errors.append(f"candidates[{index}] has an unknown program")
        if expected_pass == 2:
            if not re.fullmatch(r"cand_[0-9a-f]{32}", str(candidate.get("candidate_id", ""))):
                errors.append(f"candidates[{index}] has an invalid candidate_id")
            critique = candidate.get("critique")
            if not isinstance(critique, dict) or critique.get("result") not in {"accept", "repair", "reject"}:
                errors.append(f"candidates[{index}] critique result is invalid")
            elif not isinstance(critique.get("findings"), list):
                errors.append(f"candidates[{index}] critique findings must be a list")
        evidence = candidate.get("evidence")
        if not isinstance(evidence, dict):
            errors.append(f"candidates[{index}].evidence must be an object")
        else:
            errors.extend(
                f"candidates[{index}]: {error}"
                for error in validate_evidence_span(section, evidence)
            )
    return errors


def candidate_id(section: dict[str, Any], candidate: dict[str, Any]) -> str:
    evidence = candidate["evidence"]
    identity = {
        "snapshot_hash": section["snapshot_hash"],
        "section_id": section["section_id"],
        "evidence_hash": evidence["evidence_hash"],
        "program": candidate["program"],
        "rule_type": candidate.get("rule_type"),
        "conditions": candidate.get("conditions"),
        "outcome": candidate.get("outcome"),
        "effective_from": candidate.get("effective_from"),
        "effective_through": candidate.get("effective_through"),
    }
    return stable_id("cand", identity)


def build_typed_rule_draft(candidate: dict[str, Any]) -> dict[str, Any]:
    payload = candidate["candidate_payload"]
    evidence = {
        "snapshot_sha256": candidate["snapshot_hash"],
        "section_id": candidate["section_id"],
        "char_start": candidate["evidence_char_start"],
        "char_end": candidate["evidence_char_end"],
        "byte_start": candidate["evidence_byte_start"],
        "byte_end": candidate["evidence_byte_end"],
        "quote": candidate["evidence_quote"],
        "evidence_sha256": candidate["evidence_hash"],
    }
    return {
        "schema_version": "localbce-government-rule-v1",
        "rule_id": candidate["candidate_id"],
        "version": "1.0.0",
        "program": candidate["primary_program"],
        "jurisdiction": payload.get("jurisdiction")
        or {"country": "US", "level": "federal", "state": None},
        "authority": payload.get("authority"),
        "rule_type": payload.get("rule_type"),
        "conditions": payload.get("conditions"),
        "outcome": payload.get("outcome"),
        "effective_from": payload.get("effective_from"),
        "effective_through": payload.get("effective_through"),
        "exceptions": payload.get("exceptions", []),
        "source": {
            "url": candidate["canonical_url"],
            "citation_text": candidate["evidence_quote"],
            "snapshot_sha256": candidate["snapshot_hash"],
            "evidence": evidence,
        },
        "review_status": "unreviewed",
        "legal_verification_status": "not_verified",
        "runtime_eligibility_status": "shadow_only",
        "runtime_activation": False,
        "proof_binding": False,
    }


def validate_typed_rule_draft(rule: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if rule.get("schema_version") != "localbce-government-rule-v1":
        errors.append("unsupported rule schema")
    if not valid_program(rule.get("program")):
        errors.append("unknown program")
    jurisdiction = rule.get("jurisdiction")
    if not isinstance(jurisdiction, dict) or jurisdiction.get("country") != "US" or jurisdiction.get("level") != "federal":
        errors.append("scaled corpus candidate must have structured federal jurisdiction")
    authority = rule.get("authority")
    if not isinstance(authority, dict) or not str(authority.get("issuer", "")).strip() or not str(authority.get("citation", "")).strip():
        errors.append("structured authority issuer and citation are required")
    if not str(rule.get("rule_type", "")).endswith("_rule"):
        errors.append("typed rule_type is required")
    _validate_condition(rule.get("conditions"), "conditions", errors)
    _validate_outcome(rule.get("outcome"), "outcome", errors)
    effective_from = _parse_iso_date(rule.get("effective_from"), "effective_from", errors)
    effective_through = None
    if rule.get("effective_through") is not None:
        effective_through = _parse_iso_date(rule.get("effective_through"), "effective_through", errors)
    if effective_from and effective_through and effective_through < effective_from:
        errors.append("effective_through cannot precede effective_from")
    if not isinstance(rule.get("exceptions"), list):
        errors.append("exceptions must be a typed list")
    source = rule.get("source")
    if not isinstance(source, dict):
        errors.append("source provenance is required")
    else:
        try:
            canonical_url(str(source.get("url", "")))
        except ValueError as exc:
            errors.append(str(exc))
        if not str(source.get("citation_text", "")).strip():
            errors.append("source citation_text is required")
        evidence = source.get("evidence")
        if not isinstance(evidence, dict):
            errors.append("source evidence is required")
        else:
            quote = str(evidence.get("quote", ""))
            if hashlib.sha256(quote.encode("utf-8")).hexdigest() != evidence.get("evidence_sha256"):
                errors.append("source evidence hash mismatch")
            if evidence.get("snapshot_sha256") != source.get("snapshot_sha256"):
                errors.append("source snapshot hash mismatch")
    if rule.get("runtime_activation") is not False:
        errors.append("runtime activation is forbidden before R5")
    if rule.get("proof_binding") is not False:
        errors.append("proof binding is forbidden before R5")
    return errors


def draft_fingerprints(rule: dict[str, Any]) -> tuple[str, str, str, str]:
    canonical_hash = canonical_sha256(rule)
    scope = {
        "program": rule.get("program"),
        "jurisdiction": rule.get("jurisdiction"),
        "authority": rule.get("authority"),
        "rule_type": rule.get("rule_type"),
        "conditions": rule.get("conditions"),
    }
    scope_fingerprint = canonical_sha256(scope)
    semantic_fingerprint = canonical_sha256(
        {
            **scope,
            "effective_from": rule.get("effective_from"),
            "effective_through": rule.get("effective_through"),
        }
    )
    return canonical_hash, semantic_fingerprint, scope_fingerprint, canonical_sha256(rule.get("outcome"))


def effective_periods_overlap(left: dict[str, Any], right: dict[str, Any]) -> bool:
    left_start = datetime.strptime(left["effective_from"], "%Y-%m-%d").date()
    right_start = datetime.strptime(right["effective_from"], "%Y-%m-%d").date()
    left_end = (
        datetime.strptime(left["effective_through"], "%Y-%m-%d").date()
        if left.get("effective_through")
        else datetime.max.date()
    )
    right_end = (
        datetime.strptime(right["effective_through"], "%Y-%m-%d").date()
        if right.get("effective_through")
        else datetime.max.date()
    )
    return left_start <= right_end and right_start <= left_end


def quality_gate_report(
    *,
    candidate_count: int,
    sample_count: int,
    program_metrics: dict[str, dict[str, float]],
    source_snapshot_coverage: float,
    citation_coverage: float,
    evidence_span_precision: float,
    typed_mapping_precision: float,
    program_classification_accuracy: float,
    silently_merged_conflicts: int,
    deterministic_rerun_match: bool,
    mandatory_unsampled: int = 0,
    two_role_sample_count: int = 0,
) -> dict[str, Any]:
    expected_programs = set(all_programs())
    measured_programs = set(program_metrics)
    minimum_program_accuracy = min(
        (metrics.get("classification_accuracy", 0.0) for metrics in program_metrics.values()),
        default=0.0,
    )
    measurements = {
        "source_snapshot_coverage": source_snapshot_coverage,
        "citation_coverage": citation_coverage,
        "evidence_span_precision": evidence_span_precision,
        "typed_mapping_precision": typed_mapping_precision,
        "program_classification_accuracy": program_classification_accuracy,
        "minimum_program_accuracy": minimum_program_accuracy,
    }
    gates = {key: value >= QUALITY_THRESHOLDS[key] for key, value in measurements.items()}
    gates.update(
        {
            "minimum_release_sample": sample_count >= 1_020,
            "all_programs_sampled": measured_programs == expected_programs,
            "minimum_20_samples_per_program": measured_programs == expected_programs
            and all(int(metrics.get("sample_count", 0)) >= 20 for metrics in program_metrics.values()),
            "two_role_gold_set": two_role_sample_count >= 1_020,
            "all_mandatory_records_sampled": mandatory_unsampled == 0,
            "no_silently_merged_conflicts": silently_merged_conflicts == 0,
            "deterministic_rerun": deterministic_rerun_match,
        }
    )
    return {
        "schema_version": QUALITY_SCHEMA,
        "candidate_count": candidate_count,
        "sample_count": sample_count,
        "thresholds": QUALITY_THRESHOLDS,
        "measurements": measurements,
        "program_metrics": dict(sorted(program_metrics.items())),
        "silently_merged_conflicts": silently_merged_conflicts,
        "mandatory_unsampled": mandatory_unsampled,
        "two_role_sample_count": two_role_sample_count,
        "deterministic_rerun_match": deterministic_rerun_match,
        "gates": gates,
        "passed": all(gates.values()),
        "runtime_activation": False,
        "proof_binding": False,
    }


def build_release_manifest(
    *,
    release_id: str,
    target_count: int,
    candidates: Iterable[dict[str, Any]],
    source_manifest_hash: str,
    quality_report: dict[str, Any],
    blocker_counts: dict[str, int],
    reviewer_evidence: dict[str, Any],
) -> dict[str, Any]:
    if target_count not in CORPUS_MILESTONES:
        raise ValueError("unsupported corpus release target")
    ordered = sorted(candidates, key=lambda item: item["candidate_id"])
    ids = [item["candidate_id"] for item in ordered]
    if len(ids) != len(set(ids)):
        raise ValueError("corpus release contains duplicate candidate IDs")
    coverage = {program: 0 for program in all_programs()}
    for candidate in ordered:
        program = candidate.get("primary_program")
        if program not in coverage:
            raise ValueError("corpus release contains an unknown program")
        coverage[program] += 1
    quotas = program_quotas(target_count)
    payload = {
        "schema_version": RELEASE_SCHEMA,
        "release_id": release_id,
        "target_count": target_count,
        "candidate_count": len(ordered),
        "candidate_ids_sha256": canonical_sha256(ids),
        "source_manifest_hash": source_manifest_hash,
        "prompt_versions": [EXTRACTION_PROMPT_VERSION, CRITIQUE_PROMPT_VERSION],
        "model_versions": [CLAUDE_MODEL],
        "program_coverage": coverage,
        "program_quotas": quotas,
        "quota_met": coverage == quotas,
        "blocker_counts": dict(sorted(blocker_counts.items())),
        "quality": quality_report,
        "reviewer_evidence": reviewer_evidence,
        "runtime_activation": False,
        "proof_binding": False,
        "production_usable": False,
    }
    payload["gates_passed"] = bool(
        len(ordered) == target_count and payload["quota_met"] and quality_report.get("passed")
    )
    payload["canonical_release_hash"] = canonical_sha256(payload)
    return payload


def build_shadow_bundle(release: dict[str, Any], candidates: Iterable[dict[str, Any]]) -> dict[str, Any]:
    release_hash = release.get("canonical_release_hash")
    expected_hash = canonical_sha256(
        {key: value for key, value in release.items() if key != "canonical_release_hash"}
    )
    if release_hash != expected_hash:
        raise ValueError("corpus release hash mismatch")
    if release.get("runtime_activation") is not False or release.get("proof_binding") is not False:
        raise ValueError("only non-binding releases may be exported")
    if release.get("gates_passed") is not True:
        raise ValueError("shadow bundle export requires a fully gated corpus release")
    rules = sorted(candidates, key=lambda item: item["candidate_id"])
    bundle = {
        "schema_version": SHADOW_BUNDLE_SCHEMA,
        "release_id": release["release_id"],
        "release_hash": release_hash,
        "runtime_activation": False,
        "proof_binding": False,
        "adjudication_effect": False,
        "rules": rules,
    }
    bundle["rules_sha256"] = canonical_sha256(rules)
    return bundle
