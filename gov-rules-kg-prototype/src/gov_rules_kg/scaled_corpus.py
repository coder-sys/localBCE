from __future__ import annotations

import hashlib
import json
import re
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote, urlparse, urlunparse

from .canonical_rules import RULE_SCHEMA_VERSION, RULE_TYPES, canonical_sha256
from .canonical_rules import _parse_iso_date, _validate_condition, _validate_outcome
from .domain import GOVERNMENT_RULE_TAXONOMY, valid_program


SOURCE_REGISTRY_SCHEMA = "localbce-official-source-registry-v2"
SOURCE_REGISTRY_RELEASE_SCHEMA = "localbce-official-source-registry-release-v2"
SOURCE_SNAPSHOT_SCHEMA = "localbce-source-snapshot-v1"
OCR_ARTIFACT_SCHEMA = "localbce-source-ocr-artifact-v1"
SECTION_SCHEMA = "localbce-source-section-v1"
INFERENCE_SCHEMA = "localbce-grounded-inference-v1"
INFERENCE_RESPONSE_CONTRACT_VERSION = "grounded-inference-tool-contract-v13"
CANDIDATE_IDENTITY_VERSION = "grounded-candidate-identity-v2"
QUALITY_SCHEMA = "localbce-rules-quality-report-v1"
RELEASE_SCHEMA = "localbce-rules-corpus-release-v1"
SHADOW_BUNDLE_SCHEMA = "localbce-grounded-shadow-bundle-v1"
CLAUDE_MODEL = "claude-sonnet-4-6"
EXTRACTION_PROMPT_VERSION = "grounded-atomic-extraction-v6"
CRITIQUE_PROMPT_VERSION = "grounded-atomic-critique-v6"
RELEVANCE_CLASSIFIER_VERSION = "federal-rule-section-relevance-v2"
SOURCE_CANDIDATE_PREFLIGHT_VERSION = "source-candidate-preflight-v8"
SOURCE_CANDIDATE_PREFLIGHT_REPORT_SCHEMA = (
    "localbce-source-candidate-preflight-report-v1"
)
SOURCE_CANDIDATE_SCOPE_MODES = frozenset(
    {
        "curated_authority_hierarchy",
        "direct_candidate_evidence",
        "jurisdiction_directory_inheritance",
        "temporal_authority_inheritance",
    }
)
CORPUS_MILESTONES = (5_100, 51_000, 600_000)
MAX_CANDIDATES_PER_SECTION = 25
QUALITY_THRESHOLDS = {
    "source_snapshot_coverage": 1.0,
    "citation_coverage": 1.0,
    "evidence_span_precision": 0.99,
    "typed_mapping_precision": 0.98,
    "program_classification_accuracy": 0.95,
    "minimum_program_accuracy": 0.90,
}


def inference_contract_key(*, pass_number: int) -> str:
    if pass_number not in {1, 2}:
        raise ValueError("inference contract pass must be 1 or 2")
    return canonical_sha256(
        {
            "pass": pass_number,
            "prompt_version": (
                EXTRACTION_PROMPT_VERSION
                if pass_number == 1
                else CRITIQUE_PROMPT_VERSION
            ),
            "model_version": CLAUDE_MODEL,
            "schema_version": INFERENCE_SCHEMA,
            "response_contract_version": INFERENCE_RESPONSE_CONTRACT_VERSION,
            "candidate_identity_version": CANDIDATE_IDENTITY_VERSION,
        }
    )


EXTRACTION_CONTRACT_KEY = inference_contract_key(pass_number=1)
CRITIQUE_CONTRACT_KEY = inference_contract_key(pass_number=2)


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


def prioritize_inference_sections(
    sections: Iterable[dict[str, Any]],
    accepted_program_counts: dict[str, int],
    *,
    limit: int = 0,
) -> list[dict[str, Any]]:
    if limit < 0:
        raise ValueError("inference section limit cannot be negative")
    unknown_counts = sorted(
        program for program in accepted_program_counts if not valid_program(program)
    )
    if unknown_counts:
        raise ValueError("accepted candidate counts contain an unknown program")

    prioritized: list[dict[str, Any]] = []
    for section in sorted(sections, key=lambda item: str(item["section_id"])):
        programs = sorted(
            {str(value) for value in section.get("programs", []) if str(value)}
        )
        if not programs or any(not valid_program(program) for program in programs):
            raise ValueError("source section contains an unknown program")
        program = min(
            programs,
            key=lambda value: (int(accepted_program_counts.get(value, 0)), value),
        )
        prioritized.append(
            {
                **section,
                "program": program,
                "programs": programs,
                "program_candidate_count": int(
                    accepted_program_counts.get(program, 0)
                ),
            }
        )

    ordinals: dict[str, int] = {}
    for section in sorted(
        prioritized, key=lambda item: (item["program"], item["section_id"])
    ):
        program = str(section["program"])
        ordinals[program] = ordinals.get(program, 0) + 1
        section["program_ordinal"] = ordinals[program]
    prioritized.sort(
        key=lambda item: (
            item["program_candidate_count"],
            item["program_ordinal"],
            item["program"],
            item["section_id"],
        )
    )
    return prioritized[:limit] if limit > 0 else prioritized


def build_inference_launch_plan(
    *,
    target_count: int,
    registry: dict[str, Any],
    progress: dict[str, Any],
    preflight: dict[str, Any],
    metrics: dict[str, Any],
    credential_configured: bool,
    concurrency: int = 8,
) -> dict[str, Any]:
    if target_count not in CORPUS_MILESTONES:
        raise ValueError("unsupported inference launch target")
    if concurrency <= 0 or concurrency > 32:
        raise ValueError("inference launch concurrency must be between 1 and 32")
    programs = progress.get("programs", [])
    table_counts = metrics.get("table_counts", {})
    blockers: list[str] = []
    if not credential_configured:
        blockers.append("missing_anthropic_credential")
    if progress.get("program_count") != 51:
        blockers.append("source_registry_program_coverage_incomplete")
    if progress.get("programs_without_source_capture"):
        blockers.append("source_capture_incomplete")
    if progress.get("programs_without_active_sections"):
        blockers.append("source_section_coverage_incomplete")
    blocking_queue_failures = progress.get(
        "blocking_queue_failures", progress.get("queue_failures", {})
    )
    if any(int(value) > 0 for value in blocking_queue_failures.values()):
        blockers.append("failed_pipeline_jobs_require_explicit_retry")
    if int(preflight.get("unassessed_candidate_count", 0)) > 0:
        blockers.append("source_candidate_preflight_incomplete")
    if int(table_counts.get("source_sections", 0)) <= 0:
        blockers.append("no_captured_source_sections")

    wanings: list[str] = []
    if int(preflight.get("eligible_for_human_review_count", 0)) > 0:
        wanings.append("source_registry_human_review_backlog")
    if int(preflight.get("blocked_candidate_count", 0)) > 0:
        wanings.append("source_registry_preflight_blockers_present")
    if not progress.get("milestone_candidate_ready", False):
        wanings.append("candidate_milestone_not_yet_met")
    wanings.append("candidate_yield_per_section_is_not_guaranteed")

    payload = {
        "schema_version": "localbce-claude-inference-launch-plan-v1",
        "target_candidate_count": target_count,
        "program_count": progress.get("program_count"),
        "program_quotas": program_quotas(target_count),
        "registry_id": registry.get("registry_id"),
        "registry_manifest_sha256": registry.get("registry_manifest_sha256"),
        "base_source_entrypoints": len(registry.get("sources", [])),
        "captured_source_snapshots": int(table_counts.get("source_snapshots", 0)),
        "captured_source_sections": int(table_counts.get("source_sections", 0)),
        "active_section_contexts": sum(
            int(item.get("active_section_count", 0)) for item in programs
        ),
        "accepted_grounded_candidates": int(
            progress.get("accepted_grounded_candidates", 0)
        ),
        "deterministic_candidates": int(progress.get("deterministic_candidates", 0)),
        "source_candidate_preflight": {
            "version": preflight.get("preflight_version"),
            "assessed": int(preflight.get("assessed_candidate_count", 0)),
            "unassessed": int(preflight.get("unassessed_candidate_count", 0)),
            "eligible_for_human_review": int(
                preflight.get("eligible_for_human_review_count", 0)
            ),
            "blocked": int(preflight.get("blocked_candidate_count", 0)),
        },
        "model": CLAUDE_MODEL,
        "extraction_prompt_version": EXTRACTION_PROMPT_VERSION,
        "critique_prompt_version": CRITIQUE_PROMPT_VERSION,
        "response_contract_version": INFERENCE_RESPONSE_CONTRACT_VERSION,
        "concurrency": concurrency,
        "credential_configured": credential_configured,
        "blocking_queue_failures": {
            str(name): int(count)
            for name, count in sorted(blocking_queue_failures.items())
        },
        "launch_blockers": sorted(set(blockers)),
        "launch_wanings": sorted(set(wanings)),
        "launch_ready": not blockers,
        "milestone_candidate_ready": bool(
            progress.get("milestone_candidate_ready", False)
        ),
        "human_source_review_required": True,
        "automatic_source_approval": False,
        "runtime_activation": False,
        "proof_binding": False,
    }
    payload["launch_plan_hash"] = canonical_sha256(payload)
    return payload


def validate_inference_launch_plan(plan: dict[str, Any]) -> None:
    if plan.get("schema_version") != "localbce-claude-inference-launch-plan-v1":
        raise ValueError("unsupported inference launch plan schema")
    expected_hash = canonical_sha256(
        {
            key: value
            for key, value in plan.items()
            if key not in {"launch_plan_hash", "report", "validation_status"}
        }
    )
    if plan.get("launch_plan_hash") != expected_hash:
        raise ValueError("inference launch plan hash mismatch")
    if plan.get("model") != CLAUDE_MODEL:
        raise ValueError("inference launch plan model is not pinned")
    if plan.get("extraction_prompt_version") != EXTRACTION_PROMPT_VERSION:
        raise ValueError("inference extraction prompt version is not pinned")
    if plan.get("critique_prompt_version") != CRITIQUE_PROMPT_VERSION:
        raise ValueError("inference critique prompt version is not pinned")
    if plan.get("response_contract_version") != INFERENCE_RESPONSE_CONTRACT_VERSION:
        raise ValueError("inference response contract version is not pinned")
    if bool(plan.get("launch_blockers")) == bool(plan.get("launch_ready")):
        raise ValueError("inference launch readiness is inconsistent with blockers")
    if (
        plan.get("automatic_source_approval") is not False
        or plan.get("runtime_activation") is not False
        or plan.get("proof_binding") is not False
    ):
        raise ValueError("inference launch plan must remain review-only and non-binding")


def select_balanced_release_candidates(
    candidates: Iterable[dict[str, Any]], target_count: int
) -> dict[str, Any]:
    if target_count not in CORPUS_MILESTONES:
        raise ValueError("unsupported corpus release target")
    ordered = sorted(candidates, key=lambda item: item["candidate_id"])
    identifiers = [str(item.get("candidate_id", "")) for item in ordered]
    if not all(identifiers) or len(identifiers) != len(set(identifiers)):
        raise ValueError("corpus release contains duplicate or empty candidate IDs")
    quotas = program_quotas(target_count)
    by_program: dict[str, list[dict[str, Any]]] = {
        program: [] for program in all_programs()
    }
    for candidate in ordered:
        program = candidate.get("primary_program")
        if program not in by_program:
            raise ValueError("corpus release contains an unknown program")
        by_program[program].append(candidate)
    selected: list[dict[str, Any]] = []
    deficits: dict[str, int] = {}
    available_counts: dict[str, int] = {}
    excluded_above_quota = 0
    for program in all_programs():
        available = by_program[program]
        quota = quotas[program]
        available_counts[program] = len(available)
        selected.extend(available[:quota])
        deficits[program] = max(0, quota - len(available))
        excluded_above_quota += max(0, len(available) - quota)
    selected.sort(key=lambda item: item["candidate_id"])
    payload = {
        "target_count": target_count,
        "available_candidate_count": len(ordered),
        "selected_candidate_count": len(selected),
        "program_quotas": quotas,
        "available_program_counts": available_counts,
        "program_deficits": deficits,
        "total_deficit": sum(deficits.values()),
        "excluded_above_quota": excluded_above_quota,
        "selected_candidates": selected,
    }
    payload["selection_hash"] = canonical_sha256(
        [candidate["candidate_id"] for candidate in selected]
    )
    return payload


def stable_id(prefix: str, *parts: Any) -> str:
    return f"{prefix}_{canonical_sha256(list(parts))[:32]}"


def canonical_url(value: str) -> str:
    parsed = urlparse(value.strip())
    host = (parsed.hostname or "").lower()
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("official source URL has an invalid port") from exc
    if parsed.scheme != "https" or not host:
        raise ValueError("official source URL must use https")
    if parsed.username or parsed.password:
        raise ValueError("official source URL must not include user information")
    if port not in {None, 443}:
        raise ValueError("official source URL must use the default HTTPS port")
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    if path != "/":
        path = path.rstrip("/")
    return urlunparse(("https", host, path, "", parsed.query, ""))


_SOURCE_RULE_TERMS = {
    "appeal",
    "benefit",
    "claim",
    "compliance",
    "coverage",
    "cfr",
    "eligibility",
    "enforcement",
    "fee",
    "guidance",
    "handbook",
    "law",
    "manual",
    "payment",
    "policy",
    "provider",
    "regulation",
    "reimbursement",
    "requirement",
    "rule",
    "statute",
    "usc",
}
_SOURCE_NAVIGATION_TERMS = {
    "about",
    "accessibility",
    "calendar",
    "careers",
    "contact",
    "events",
    "facebook",
    "instagram",
    "linkedin",
    "news",
    "newsroom",
    "privacy",
    "search",
    "sitemap",
    "subscribe",
    "twitter",
    "youtube",
}
_SOURCE_SITE_POLICY_BOILERPLATE_TERMS = {
    "accessibility",
    "cookies",
    "disclosure",
    "privacy",
    "vulnerability",
}
_SOURCE_TEMPORAL_AUTHORITY_HOSTS = {
    "ecfr.gov",
    "federalregister.gov",
    "govinfo.gov",
    "gpo.gov",
    "public-inspection.federalregister.gov",
    "www.ecfr.gov",
    "www.federalregister.gov",
    "www.govinfo.gov",
    "www.gpo.gov",
}
_SOURCE_STATIC_SUFFIXES = {
    ".avi",
    ".bmp",
    ".css",
    ".csv",
    ".doc",
    ".docx",
    ".eot",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".json",
    ".map",
    ".mov",
    ".mp3",
    ".mp4",
    ".png",
    ".ppt",
    ".pptx",
    ".svg",
    ".ttf",
    ".wav",
    ".webp",
    ".woff",
    ".woff2",
    ".xls",
    ".xlsx",
    ".zip",
}
_SOURCE_DOCUMENT_SUFFIXES = {".htm", ".html", ".pdf", ".txt", ".xml"}
_SOURCE_HIERARCHICAL_AUTHORITY_HOSTS = {"ecfr.gov", "www.ecfr.gov", "www.govinfo.gov"}
_SOURCE_HIERARCHICAL_AUTHORITY_TYPES = {"regulation", "statute"}
_SOURCE_JURISDICTION_DIRECTORY_LABEL = re.compile(r"\([A-Z]{2,3}\)\s*$")

_SOURCE_PROGRAM_RELEVANCE_STOPWORDS = {
    "benefits",
    "federal",
    "program",
    "public",
    "services",
    "state",
}
_SOURCE_PROGRAM_RELEVANCE_ALIASES = {
    "aca_marketplace": {"aca"},
    "building_permits": {
        "building",
        "buildings",
        "construction",
        "housing",
        "permit",
        "permits",
        "planning",
        "zoning",
    },
    "driver_licenses": {
        "dmv",
        "dps",
        "driver",
        "drivers",
        "license",
        "licenses",
        "licensing",
        "motor",
        "vehicle",
        "vehicles",
    },
    "earned_income_tax_credit": {"eitc"},
}
_SOURCE_PROGRAM_REQUIRED_DIRECT_RELEVANCE_ALIASES = {
    "driver_licenses": {"dmv", "dps", "driver", "drivers", "license", "licenses"},
}


def _source_program_relevance_terms(program: str) -> set[str]:
    terms = set(re.findall(r"[a-z0-9]+", program.lower().replace("_", " ")))
    for token in tuple(terms):
        if token.endswith("ies") and len(token) > 3:
            terms.add(f"{token[:-3]}y")
        elif (
            token.endswith("s")
            and not token.endswith(("ss", "us", "is"))
            and len(token) > 3
        ):
            terms.add(token[:-1])
    terms.update(_SOURCE_PROGRAM_RELEVANCE_ALIASES.get(program, set()))
    return terms - _SOURCE_PROGRAM_RELEVANCE_STOPWORDS


def _has_curated_hierarchical_program_scope(
    *,
    candidate_url: str,
    parent_url: str,
    parent_source_type: str,
) -> bool:
    candidate = urlparse(candidate_url)
    parent = urlparse(parent_url)
    host = (candidate.hostname or "").lower()
    parent_host = (parent.hostname or "").lower()
    if (
        host != parent_host
        or host not in _SOURCE_HIERARCHICAL_AUTHORITY_HOSTS
        or parent_source_type not in _SOURCE_HIERARCHICAL_AUTHORITY_TYPES
    ):
        return False
    candidate_parts = tuple(part for part in candidate.path.split("/") if part)
    parent_parts = tuple(part for part in parent.path.split("/") if part)
    decoded_candidate_parts = tuple(unquote(part) for part in candidate_parts)
    if any(
        part in {".", ".."} or "/" in part or "\\" in part
        for part in decoded_candidate_parts
    ):
        return False
    return (
        bool(parent_parts)
        and len(candidate_parts) > len(parent_parts)
        and candidate_parts[: len(parent_parts)] == parent_parts
    )


def assess_source_candidate_preflight(candidate: dict[str, Any]) -> dict[str, Any]:
    """Deterministically triage a discovered URL before human source review."""

    candidate_url = canonical_url(str(candidate.get("candidate_url", "")))
    parsed = urlparse(candidate_url)
    host = (parsed.hostname or "").lower()
    if not host.endswith(".gov"):
        raise ValueError("source candidate preflight requires an official .gov URL")

    parent_url = canonical_url(str(candidate.get("parent_url", "")))
    parent_host = (urlparse(parent_url).hostname or "").lower()
    link_text = re.sub(r"\s+", " ", str(candidate.get("link_text", ""))).strip()
    path_tokens = set(re.findall(r"[a-z0-9]+", parsed.path.lower()))
    text_tokens = set(re.findall(r"[a-z0-9]+", link_text.lower()))
    all_tokens = path_tokens | text_tokens
    all_tokens.update(re.findall(r"[a-z0-9]+", f"{host} {parsed.query}".lower()))
    parent_parsed = urlparse(parent_url)
    parent_tokens = set(
        re.findall(
            r"[a-z0-9]+",
            f"{parent_host} {parent_parsed.path} {parent_parsed.query}".lower(),
        )
    )
    program = str(candidate.get("program", ""))
    program_terms = _source_program_relevance_terms(program)
    direct_program_relevance_terms = all_tokens & program_terms
    parent_program_relevance_terms = parent_tokens & program_terms
    same_parent_host = host == parent_host
    temporal_authority_candidate = host in _SOURCE_TEMPORAL_AUTHORITY_HOSTS
    jurisdiction_directory_link = bool(
        not same_parent_host
        and _SOURCE_JURISDICTION_DIRECTORY_LABEL.search(link_text)
    )
    inherited_parent_scope = bool(
        parent_program_relevance_terms
        and (jurisdiction_directory_link or temporal_authority_candidate)
    )
    strong_program_relevance_terms = direct_program_relevance_terms & (
        _SOURCE_PROGRAM_REQUIRED_DIRECT_RELEVANCE_ALIASES.get(program, set())
    )
    program_relevance_terms = sorted(
        direct_program_relevance_terms
        | (parent_program_relevance_terms if inherited_parent_scope else set())
    )
    parent_source_type = str(candidate.get("parent_source_type", "")).strip().lower()
    curated_hierarchical_program_scope = _has_curated_hierarchical_program_scope(
        candidate_url=candidate_url,
        parent_url=parent_url,
        parent_source_type=parent_source_type,
    )
    suffix = Path(parsed.path).suffix.lower()
    rule_terms = sorted(all_tokens & _SOURCE_RULE_TERMS)
    navigation_terms = sorted(all_tokens & _SOURCE_NAVIGATION_TERMS)
    site_policy_boilerplate_terms = sorted(
        all_tokens & _SOURCE_SITE_POLICY_BOILERPLATE_TERMS
    )
    locator_present = bool(candidate.get("source_locator"))

    blockers: list[str] = []
    if not link_text:
        blockers.append("missing_link_text")
    if suffix in _SOURCE_STATIC_SUFFIXES:
        blockers.append("non_rule_resource")
    if navigation_terms and not rule_terms:
        blockers.append("navigation_or_boilerplate")
    if site_policy_boilerplate_terms and not temporal_authority_candidate:
        blockers.append("site_policy_or_security_boilerplate")
    if not rule_terms and (
        suffix in _SOURCE_STATIC_SUFFIXES
        or (
            not program_relevance_terms
            and not curated_hierarchical_program_scope
            and suffix not in _SOURCE_DOCUMENT_SUFFIXES
        )
    ):
        blockers.append("weak_rule_relevance")
    program_specificity_satisfied = bool(
        program not in _SOURCE_PROGRAM_REQUIRED_DIRECT_RELEVANCE_ALIASES
        or strong_program_relevance_terms
        or inherited_parent_scope
        or curated_hierarchical_program_scope
    )
    if (
        not program_relevance_terms or not program_specificity_satisfied
    ) and not curated_hierarchical_program_scope:
        blockers.append("weak_program_relevance")
    if not locator_present:
        blockers.append("missing_source_locator")
    blockers = sorted(set(blockers))

    score = 20
    score += 10 if same_parent_host else 5
    score += 10 if suffix in _SOURCE_DOCUMENT_SUFFIXES else 0
    score += 10 if link_text else 0
    score += 5 if locator_present else 0
    score += 15 if temporal_authority_candidate else 0
    score += min(40, len(rule_terms) * 10)
    score += min(20, len(program_relevance_terms) * 10)
    score += 15 if curated_hierarchical_program_scope else 0
    score -= 20 * len(blockers)
    score = max(0, min(100, score))

    signals = {
        "document_suffix": suffix or None,
        "human_review_required": True,
        "link_text_present": bool(link_text),
        "locator_present": locator_present,
        "navigation_terms": navigation_terms,
        "official_host": True,
        "program_relevance_terms": program_relevance_terms,
        "direct_program_relevance_terms": sorted(direct_program_relevance_terms),
        "strong_program_relevance_terms": sorted(strong_program_relevance_terms),
        "inherited_parent_program_relevance_terms": (
            sorted(parent_program_relevance_terms) if inherited_parent_scope else []
        ),
        "program_specificity_satisfied": program_specificity_satisfied,
        "jurisdiction_directory_link": jurisdiction_directory_link,
        "curated_hierarchical_program_scope": curated_hierarchical_program_scope,
        "rule_relevance_terms": rule_terms,
        "same_parent_host": same_parent_host,
        "site_policy_boilerplate_terms": site_policy_boilerplate_terms,
        "source_priority": (
            "primary_temporal_authority" if temporal_authority_candidate else "general_official_source"
        ),
        "temporal_authority_candidate": temporal_authority_candidate,
    }
    payload = {
        "schema_version": SOURCE_CANDIDATE_PREFLIGHT_VERSION,
        "source_candidate_id": str(candidate.get("source_candidate_id", "")),
        "candidate_url": candidate_url,
        "parent_url": parent_url,
        "program": str(candidate.get("program", "")),
        "score": score,
        "blockers": blockers,
        "signals": signals,
        "eligible_for_human_review": not blockers,
        "registry_activation": False,
        "runtime_activation": False,
        "proof_binding": False,
    }
    payload["preflight_hash"] = canonical_sha256(payload)
    return payload


def assess_source_candidate_preflight_batch(
    candidates: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Canonicalize exact program/URL duplicates before human source review."""

    assessed: list[tuple[dict[str, Any], dict[str, Any]]] = []
    candidate_ids: set[str] = set()
    groups: dict[tuple[str, str], list[tuple[dict[str, Any], dict[str, Any]]]] = {}
    for candidate in candidates:
        candidate_id = str(candidate.get("source_candidate_id", ""))
        if not candidate_id or candidate_id in candidate_ids:
            raise ValueError("source preflight batch requires unique candidate IDs")
        candidate_ids.add(candidate_id)
        assessment = assess_source_candidate_preflight(candidate)
        item = (candidate, assessment)
        assessed.append(item)
        key = (
            str(candidate.get("program", "")),
            str(assessment["candidate_url"]),
        )
        groups.setdefault(key, []).append(item)

    results: list[dict[str, Any]] = []
    for group in groups.values():
        canonical_candidate, _ = min(
            group,
            key=lambda item: (
                bool(item[1]["blockers"]),
                -int(item[1]["score"]),
                -len(re.sub(r"\s+", " ", str(item[0].get("link_text", ""))).strip()),
                str(item[0]["source_candidate_id"]),
            ),
        )
        canonical_id = str(canonical_candidate["source_candidate_id"])
        duplicate_count = len(group)
        for candidate, assessment in group:
            payload = dict(assessment)
            signals = dict(payload["signals"])
            signals["canonical_source_candidate_id"] = canonical_id
            signals["duplicate_program_url_count"] = duplicate_count
            payload["signals"] = signals
            if str(candidate["source_candidate_id"]) != canonical_id:
                payload["blockers"] = sorted(
                    set(payload["blockers"]) | {"duplicate_source_candidate_url"}
                )
                payload["score"] = max(0, int(payload["score"]) - 20)
                payload["eligible_for_human_review"] = False
            payload.pop("preflight_hash", None)
            payload["preflight_hash"] = canonical_sha256(payload)
            results.append(payload)
    return sorted(results, key=lambda item: item["source_candidate_id"])


def validate_source_candidate_preflight_report(
    report: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    if not isinstance(report, dict):
        return ["source candidate preflight report must be an object"]
    if report.get("schema_version") != SOURCE_CANDIDATE_PREFLIGHT_REPORT_SCHEMA:
        errors.append("unsupported source candidate preflight report schema")
    if report.get("preflight_version") != SOURCE_CANDIDATE_PREFLIGHT_VERSION:
        errors.append("source candidate preflight version mismatch")
    if report.get("human_review_required") is not True:
        errors.append("source candidate preflight must require human review")
    if report.get("source_capacity_evidence_is_necessary_not_sufficient") is not True:
        errors.append("source capacity evidence trust boundary is missing")
    for field in (
        "automatic_registry_activation",
        "runtime_activation",
        "proof_binding",
    ):
        if report.get(field) is not False:
            errors.append(f"source candidate preflight {field} must be false")

    counts: dict[str, int] = {}
    for field in (
        "assessed_candidate_count",
        "unique_program_url_count",
        "duplicate_source_candidate_count",
        "duplicate_source_candidate_group_count",
        "unassessed_candidate_count",
        "eligible_for_human_review_count",
        "blocked_candidate_count",
        "capacity_blocker_review_candidate_count",
    ):
        value = report.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            errors.append(f"source candidate preflight {field} is invalid")
        else:
            counts[field] = value
    if all(
        field in counts
        for field in (
            "assessed_candidate_count",
            "eligible_for_human_review_count",
            "blocked_candidate_count",
        )
    ) and counts["assessed_candidate_count"] != (
        counts["eligible_for_human_review_count"]
        + counts["blocked_candidate_count"]
    ):
        errors.append("source candidate preflight assessed count mismatch")
    if all(
        field in counts
        for field in (
            "assessed_candidate_count",
            "unique_program_url_count",
            "duplicate_source_candidate_count",
        )
    ) and counts["assessed_candidate_count"] != (
        counts["unique_program_url_count"]
        + counts["duplicate_source_candidate_count"]
    ):
        errors.append("source candidate preflight unique URL count mismatch")
    if all(
        field in counts
        for field in (
            "duplicate_source_candidate_count",
            "duplicate_source_candidate_group_count",
        )
    ) and counts["duplicate_source_candidate_group_count"] > counts[
        "duplicate_source_candidate_count"
    ]:
        errors.append("source candidate duplicate group count mismatch")

    target = report.get("source_review_milestone_target")
    if (
        not isinstance(target, int)
        or isinstance(target, bool)
        or target not in CORPUS_MILESTONES
    ):
        errors.append("source candidate preflight milestone target is invalid")

    capacity_programs = report.get(
        "programs_without_program_context_quota_capacity"
    )
    if not isinstance(capacity_programs, list):
        errors.append("source candidate capacity blocker programs are invalid")
        capacity_programs = []
    elif any(
        not isinstance(program, str) or not valid_program(program)
        for program in capacity_programs
    ) or len(capacity_programs) != len(set(capacity_programs)):
        errors.append("source candidate capacity blocker programs are invalid")
        capacity_programs = []
    capacity_program_order = {
        program: index for index, program in enumerate(capacity_programs)
    }

    eligible_scope_counts = report.get("eligible_scope_mode_counts")
    if not isinstance(eligible_scope_counts, dict) or any(
        scope not in SOURCE_CANDIDATE_SCOPE_MODES
        or not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        for scope, value in eligible_scope_counts.items()
    ):
        errors.append("source candidate eligible scope mode counts are invalid")
        eligible_scope_counts = {}
    elif (
        "eligible_for_human_review_count" in counts
        and sum(eligible_scope_counts.values())
        != counts["eligible_for_human_review_count"]
    ):
        errors.append("source candidate eligible scope mode count mismatch")

    eligible_program_counts = report.get("eligible_program_counts")
    if not isinstance(eligible_program_counts, dict) or any(
        not isinstance(program, str)
        or not valid_program(program)
        or not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        for program, value in eligible_program_counts.items()
    ):
        errors.append("source candidate eligible program counts are invalid")
        eligible_program_counts = {}

    packet = report.get("capacity_blocker_review_candidates")
    packet_valid = isinstance(packet, list)
    if not packet_valid:
        errors.append("source candidate capacity blocker review packet is invalid")
        packet = []
    if (
        "capacity_blocker_review_candidate_count" in counts
        and len(packet) != counts["capacity_blocker_review_candidate_count"]
    ):
        errors.append("source candidate capacity blocker review count mismatch")
    packet_hash = str(
        report.get("capacity_blocker_review_candidates_sha256", "")
    )
    if not re.fullmatch(r"[0-9a-f]{64}", packet_hash):
        errors.append("source candidate capacity blocker review hash is invalid")
    elif packet_valid and packet_hash != canonical_sha256(packet):
        errors.append("source candidate capacity blocker review hash mismatch")

    seen_candidate_ids: set[str] = set()
    seen_program_urls: set[tuple[str, str]] = set()
    packet_program_counts: dict[str, int] = {}
    sortable_packet: list[dict[str, Any]] = []
    for index, candidate in enumerate(packet):
        prefix = f"capacity_blocker_review_candidates[{index}]"
        if not isinstance(candidate, dict):
            errors.append(f"{prefix} must be an object")
            continue
        candidate_id_value = candidate.get("source_candidate_id")
        candidate_id_text = str(candidate_id_value or "")
        candidate_id_valid = bool(
            re.fullmatch(r"source-candidate_[0-9a-f]{32}", candidate_id_text)
        )
        if not candidate_id_valid:
            errors.append(f"{prefix} source candidate ID is invalid")
        elif candidate_id_text in seen_candidate_ids:
            errors.append(f"{prefix} source candidate ID is duplicated")
        else:
            seen_candidate_ids.add(candidate_id_text)

        program = candidate.get("program")
        if not isinstance(program, str) or program not in capacity_program_order:
            errors.append(f"{prefix} program is not a capacity blocker")
        else:
            packet_program_counts[program] = packet_program_counts.get(program, 0) + 1

        candidate_url_value = candidate.get("candidate_url")
        candidate_url_text = str(candidate_url_value or "")
        try:
            normalized_url = canonical_url(candidate_url_text)
        except ValueError:
            errors.append(f"{prefix} candidate URL is invalid")
            normalized_url = ""
        if normalized_url:
            host = (urlparse(normalized_url).hostname or "").lower()
            if normalized_url != candidate_url_text or not host.endswith(".gov"):
                errors.append(f"{prefix} candidate URL must be canonical and official")
            program_url = (str(program or ""), normalized_url)
            if program_url in seen_program_urls:
                errors.append(f"{prefix} program URL is duplicated")
            else:
                seen_program_urls.add(program_url)

        if not str(candidate.get("link_text", "")).strip():
            errors.append(f"{prefix} link text is required")
        score = candidate.get("preflight_score")
        if (
            not isinstance(score, int)
            or isinstance(score, bool)
            or not 0 <= score <= 100
        ):
            errors.append(f"{prefix} preflight score is invalid")
        preflight_hash = str(candidate.get("preflight_hash", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", preflight_hash):
            errors.append(f"{prefix} preflight hash is invalid")
        if candidate.get("scope_mode") not in SOURCE_CANDIDATE_SCOPE_MODES:
            errors.append(f"{prefix} scope mode is invalid")
        if candidate.get("review_status") not in {
            "pending_review",
            "claimed_review",
        }:
            errors.append(f"{prefix} review status is invalid")
        if candidate.get("decision_required") != "approve_for_registry_or_reject":
            errors.append(f"{prefix} decision requirement is invalid")
        if candidate.get("approval_effect") != "inactive_registry_candidate_only":
            errors.append(f"{prefix} approval effect is invalid")
        for field in ("legal_verification", "runtime_activation", "proof_binding"):
            if candidate.get(field) is not False:
                errors.append(f"{prefix} {field} must be false")
        if (
            isinstance(program, str)
            and program in capacity_program_order
            and isinstance(score, int)
            and not isinstance(score, bool)
            and candidate_id_valid
        ):
            sortable_packet.append(candidate)

    if len(sortable_packet) == len(packet) and packet != sorted(
        sortable_packet,
        key=lambda item: (
            capacity_program_order[item["program"]],
            -item["preflight_score"],
            item["source_candidate_id"],
        ),
    ):
        errors.append("source candidate capacity blocker review order is unstable")
    if eligible_program_counts and capacity_programs:
        for program in capacity_programs:
            if packet_program_counts.get(program, 0) != eligible_program_counts.get(
                program, 0
            ):
                errors.append(
                    f"source candidate capacity blocker packet is incomplete for {program}"
                )
    return errors


def load_source_registry(workdir: Path, descriptor: Path | None = None) -> dict[str, Any]:
    manifest_dir = workdir / "data" / "source_manifests"
    descriptor_path = descriptor or manifest_dir / "official_source_registry_v2.json"
    descriptor_bytes = descriptor_path.read_bytes()
    descriptor_hash = hashlib.sha256(descriptor_bytes).hexdigest()
    registry = json.loads(descriptor_bytes)
    if registry.get("schema_version") == SOURCE_REGISTRY_RELEASE_SCHEMA:
        return _load_source_registry_release(registry)
    errors: list[str] = []
    if registry.get("schema_version") != SOURCE_REGISTRY_SCHEMA:
        errors.append("unsupported official source registry schema")
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
        if not (urlparse(url).hostname or "").lower().endswith(".gov"):
            errors.append(f"sources[{index}] must use an official .gov host")
            continue
        program = valid_program(source.get("program"))
        if not program:
            errors.append(f"sources[{index}] has an unknown program")
            continue
        if source.get("official") is not True:
            errors.append(f"sources[{index}] must be official")
        jurisdiction_level = str(source.get("jurisdiction_level", "")).strip()
        state_code = source.get("state_code")
        if jurisdiction_level not in {"federal", "state"}:
            errors.append(
                f"sources[{index}] jurisdiction_level must be federal or state"
            )
            continue
        if jurisdiction_level == "state":
            state_code = str(state_code or "").strip().upper()
            if not re.fullmatch(r"[A-Z]{2}", state_code):
                errors.append(
                    f"sources[{index}] state source requires a two-letter state_code"
                )
                continue
        elif state_code is not None:
            errors.append(f"sources[{index}] federal source must not set state_code")
            continue
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
                "jurisdiction": {
                    "country": "US",
                    "level": jurisdiction_level,
                    "state": state_code if jurisdiction_level == "state" else None,
                },
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
    ordered = sorted(
        normalized, key=lambda item: (item["program"], item["canonical_url"])
    )
    registry_manifest_hash = canonical_sha256(
        {
            "descriptor_sha256": descriptor_hash,
            "source_pack_sha256": pack_hash,
            "sources_sha256": canonical_sha256(ordered),
        }
    )
    return {
        **registry,
        "descriptor_sha256": descriptor_hash,
        "source_pack_sha256": pack_hash,
        "registry_manifest_sha256": registry_manifest_hash,
        "sources": ordered,
        "program_quotas": program_quotas(int(registry["target_unique_grounded_candidates"])),
    }


def _load_source_registry_release(registry: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    release_id = str(registry.get("release_id", "")).strip()
    if not release_id:
        errors.append("source registry release ID is required")
    if registry.get("registry_id") != release_id:
        errors.append("source registry release registry ID mismatch")
    expected_release_hash = canonical_sha256(
        {
            key: value
            for key, value in registry.items()
            if key != "canonical_release_hash"
        }
    )
    if registry.get("canonical_release_hash") != expected_release_hash:
        errors.append("source registry release hash mismatch")
    if (
        registry.get("registry_activation") is not False
        or registry.get("runtime_activation") is not False
        or registry.get("proof_binding") is not False
    ):
        errors.append("source registry release must remain inactive and proof-unbound")
    try:
        target = int(registry.get("target_unique_grounded_candidates"))
    except (TypeError, ValueError):
        target = 0
        errors.append("source registry release target is invalid")
    if target != 600_000:
        errors.append("source registry release target must remain 600000")

    sources = registry.get("sources")
    if not isinstance(sources, list):
        raise ValueError("source registry release sources must be a list")
    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            errors.append(f"sources[{index}] must be an object")
            continue
        try:
            url = canonical_url(str(source.get("canonical_url", "")))
        except ValueError as exc:
            errors.append(f"sources[{index}]: {exc}")
            continue
        if not (urlparse(url).hostname or "").lower().endswith(".gov"):
            errors.append(f"sources[{index}] must use an official .gov host")
            continue
        program = valid_program(source.get("program"))
        if not program:
            errors.append(f"sources[{index}] has an unknown program")
            continue
        key = (url, program)
        if key in seen:
            errors.append(f"sources[{index}] duplicates a program URL")
            continue
        seen.add(key)
        if source.get("official") is not True:
            errors.append(f"sources[{index}] must be official")
        if source.get("registry_version") != release_id:
            errors.append(f"sources[{index}] registry version mismatch")
        if source.get("source_id") != stable_id("src", release_id, url, program):
            errors.append(f"sources[{index}] source ID mismatch")
        normalized.append({**source, "canonical_url": url})

    ordered = sorted(
        normalized, key=lambda item: (item["program"], item["canonical_url"])
    )
    coverage = {program: 0 for program in all_programs()}
    for source in ordered:
        coverage[source["program"]] += 1
    if registry.get("source_count") != len(ordered):
        errors.append("source registry release count mismatch")
    if registry.get("program_source_counts") != coverage:
        errors.append("source registry release program coverage mismatch")
    if not all(coverage.values()):
        errors.append("source registry release must cover all 51 programs")
    if registry.get("canonical_sources_sha256") != canonical_sha256(ordered):
        errors.append("source registry release sources hash mismatch")
    quotas = program_quotas(target) if target else {}
    if registry.get("program_quotas") != quotas:
        errors.append("source registry release quotas mismatch")
    if errors:
        raise ValueError("; ".join(errors))
    return {
        **registry,
        "registry_id": release_id,
        "registry_manifest_sha256": expected_release_hash,
        "sources": ordered,
        "program_quotas": quotas,
    }


def build_source_registry_release(
    *,
    release_id: str,
    base_registry: dict[str, Any],
    approved_candidates: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    if not release_id.strip():
        raise ValueError("source registry release_id is required")
    sources: list[dict[str, Any]] = []
    for source in base_registry.get("sources", []):
        url = canonical_url(source["canonical_url"])
        program = source["program"]
        metadata = dict(source.get("metadata") or {})
        metadata["previous_source_id"] = source.get("source_id")
        sources.append(
            {
                **dict(source),
                "source_id": stable_id("src", release_id, url, program),
                "registry_version": release_id,
                "canonical_url": url,
                "metadata": metadata,
            }
        )
    seen = {
        (source["program"], canonical_url(source["canonical_url"]))
        for source in sources
    }
    additions: list[dict[str, Any]] = []
    for candidate in approved_candidates:
        if candidate.get("review_status") != "approved_for_registry":
            raise ValueError("source registry release contains an unapproved candidate")
        if candidate.get("decision") != "approve_for_registry":
            raise ValueError("source registry release requires an immutable approval decision")
        if candidate.get("reviewer_role") != "rules_admin":
            raise ValueError("source registry release requires a rules_admin decision")
        program = valid_program(candidate.get("program"))
        if not program:
            raise ValueError("source registry release candidate has an unknown program")
        url = canonical_url(str(candidate.get("candidate_url", "")))
        host = urlparse(url).netloc.lower().split(":", 1)[0]
        if not host.endswith(".gov"):
            raise ValueError("source registry release candidate must use an official .gov host")
        parent_snapshot_hash = str(candidate.get("parent_snapshot_hash", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", parent_snapshot_hash):
            raise ValueError("source registry release candidate requires parent snapshot lineage")
        if not str(candidate.get("source_candidate_id", "")).strip():
            raise ValueError("source registry release candidate ID is required")
        if not str(candidate.get("reviewer_id", "")).strip() or not str(
            candidate.get("rationale", "")
        ).strip():
            raise ValueError("source registry approval reviewer and rationale are required")
        key = (program, url)
        if key in seen:
            continue
        seen.add(key)
        additions.append(
            {
                "source_id": stable_id("src", release_id, url, program),
                "registry_version": release_id,
                "canonical_url": url,
                "program": program,
                "jurisdiction": {
                    "country": "US",
                    "level": "federal",
                    "state": None,
                },
                "issuer": host,
                "source_type": "reviewed_discovered_official",
                "required": False,
                "official": True,
                "metadata": {
                    "source_candidate_id": candidate["source_candidate_id"],
                    "parent_source_id": candidate.get("parent_source_id"),
                    "parent_snapshot_hash": parent_snapshot_hash,
                    "source_decision_id": candidate.get("source_decision_id"),
                    "reviewer_id": candidate["reviewer_id"],
                },
            }
        )
    combined = sorted(
        sources + additions,
        key=lambda item: (item["program"], item["canonical_url"]),
    )
    coverage = {program: 0 for program in all_programs()}
    for source in combined:
        if source["program"] not in coverage:
            raise ValueError("source registry release does not cover a known program")
        coverage[source["program"]] += 1
    payload = {
        "schema_version": SOURCE_REGISTRY_RELEASE_SCHEMA,
        "release_id": release_id,
        "registry_id": release_id,
        "base_registry_id": base_registry.get("registry_id"),
        "base_source_pack_sha256": base_registry.get("source_pack_sha256"),
        "base_source_count": len(sources),
        "approved_addition_count": len(additions),
        "source_count": len(combined),
        "program_source_counts": coverage,
        "target_unique_grounded_candidates": int(
            base_registry["target_unique_grounded_candidates"]
        ),
        "program_quotas": program_quotas(
            int(base_registry["target_unique_grounded_candidates"])
        ),
        "all_51_programs_covered": all(count > 0 for count in coverage.values()),
        "sources": combined,
        "canonical_sources_sha256": canonical_sha256(combined),
        "registry_activation": False,
        "runtime_activation": False,
        "proof_binding": False,
    }
    payload["canonical_release_hash"] = canonical_sha256(payload)
    return payload


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


def build_ocr_artifact(
    *,
    retrieval_id: str,
    snapshot_hash: str,
    artifact_bytes: bytes,
    engine_name: str,
    engine_version: str,
    operator_id: str,
    generated_at: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not retrieval_id.strip():
        raise ValueError("OCR retrieval_id is required")
    if not re.fullmatch(r"[0-9a-f]{64}", snapshot_hash):
        raise ValueError("OCR snapshot_hash must be a lowercase SHA-256 digest")
    if not artifact_bytes:
        raise ValueError("OCR artifact bytes cannot be empty")
    for field, value in (
        ("engine_name", engine_name),
        ("engine_version", engine_version),
        ("operator_id", operator_id),
    ):
        if not value.strip():
            raise ValueError(f"OCR {field} is required")
    try:
        decoded = artifact_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("OCR artifact must be UTF-8 text") from exc
    normalized_text = normalize_source_text(decoded)
    if not normalized_text:
        raise ValueError("OCR artifact has no usable text")
    try:
        parsed_time = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("OCR generated_at must be an ISO-8601 timestamp") from exc
    if parsed_time.tzinfo is None:
        raise ValueError("OCR generated_at must include a timezone")
    artifact_hash = hashlib.sha256(artifact_bytes).hexdigest()
    normalized_text_hash = hashlib.sha256(normalized_text.encode("utf-8")).hexdigest()
    return {
        "schema_version": OCR_ARTIFACT_SCHEMA,
        "ocr_artifact_id": stable_id(
            "ocr",
            retrieval_id,
            snapshot_hash,
            artifact_hash,
            engine_name.strip(),
            engine_version.strip(),
        ),
        "retrieval_id": retrieval_id,
        "snapshot_hash": snapshot_hash,
        "artifact_hash": artifact_hash,
        "compression": "zlib",
        "compressed_bytes": zlib.compress(artifact_bytes, level=9),
        "uncompressed_size": len(artifact_bytes),
        "normalized_text": normalized_text,
        "normalized_text_hash": normalized_text_hash,
        "engine_name": engine_name.strip(),
        "engine_version": engine_version.strip(),
        "operator_id": operator_id.strip(),
        "generated_at": parsed_time.astimezone(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        ),
        "metadata": metadata or {},
        "runtime_activation": False,
        "proof_binding": False,
    }


def restore_ocr_artifact_bytes(artifact: dict[str, Any]) -> bytes:
    if artifact.get("compression") != "zlib":
        raise ValueError("unsupported OCR artifact compression")
    try:
        raw = zlib.decompress(artifact["compressed_bytes"])
    except (KeyError, zlib.error) as exc:
        raise ValueError("OCR artifact decompression failed") from exc
    if len(raw) != artifact.get("uncompressed_size"):
        raise ValueError("OCR artifact size mismatch")
    if hashlib.sha256(raw).hexdigest() != artifact.get("artifact_hash"):
        raise ValueError("OCR artifact hash mismatch")
    return raw


def restore_snapshot_bytes(snapshot: dict[str, Any]) -> bytes:
    if snapshot.get("compression") != "zlib":
        raise ValueError("unsupported source snapshot compression")
    try:
        raw = zlib.decompress(snapshot["compressed_bytes"])
    except zlib.error as exc:
        raise ValueError("source snapshot decompression failed") from exc
    if len(raw) != snapshot.get("uncompressed_size"):
        raise ValueError("source snapshot size mismatch")
    if hashlib.sha256(raw).hexdigest() != snapshot.get("snapshot_hash"):
        raise ValueError("source snapshot hash mismatch")
    return raw


def normalize_source_text(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\x00", "")
    lines = [re.sub(r"[\t ]+", " ", line).strip() for line in text.split("\n")]
    return "\n".join(line for line in lines if line).strip()


def assess_section_relevance(section: dict[str, Any]) -> dict[str, Any]:
    """Classify captured text before it can consume paid inference.

    The classifier is deliberately recall-oriented. Definitions, exceptions,
    citations, tables, and numbered provisions remain eligible even when they
    do not contain a modal verb. Obvious navigation and site-policy boilerplate
    is rejected deterministically and remains auditable in PostgreSQL.
    """

    text = normalize_source_text(str(section.get("normalized_text", "")))
    heading = normalize_source_text(str(section.get("heading", "")))
    lowered = f"{heading}\n{text}".lower()
    reasons: list[str] = []
    score = 0

    pattens = (
        (
            "normative_language",
            r"\b(shall|must|may not|must not|required|prohibited|eligible|ineligible|entitled)\b",
            4,
        ),
        (
            "legal_citation",
            r"(?:\b\d+\s+(?:c\.?f\.?r\.?|u\.?s\.?c\.?)\b|\u00a7|\bsubpart\s+[a-z0-9]+\b)",
            3,
        ),
        (
            "deadline_or_threshold",
            r"(?:\bwithin\s+\d+\s+(?:calendar\s+|business\s+)?days?\b|[$%]\s*\d|\b\d+(?:\.\d+)?\s*percent\b)",
            2,
        ),
        (
            "definition_or_exception",
            r"\b(definitions?|means|except(?:ion)?|unless|provided that|notwithstanding)\b",
            2,
        ),
        (
            "administrative_result",
            r"\b(approve|deny|revoke|suspend|terminate|penalty|payment|benefit|appeal|hearing|notice)\b",
            2,
        ),
        (
            "numbered_legal_structure",
            r"(?m)^(?:\([a-z0-9ivx]+\)|[a-z0-9]+\.|section\s+\d+)",
            1,
        ),
    )
    for reason, patten, weight in pattens:
        if re.search(patten, lowered, flags=re.IGNORECASE | re.MULTILINE):
            reasons.append(reason)
            score += weight

    boilerplate_pattens = (
        r"\b(skip to main content|website policies|privacy policy|accessibility statement)\b",
        r"\b(sign up for email updates|follow us on|share this page)\b",
    )
    boilerplate = any(re.search(patten, lowered) for patten in boilerplate_pattens)
    if boilerplate:
        reasons.append("site_boilerplate")
        score -= 4

    resource_markers = len(
        re.findall(r"\((?:pdf|docx?|xlsx?)(?:[,)]|$)", lowered)
    )
    normative_markers = len(
        re.findall(
            r"\b(shall|must|may not|must not|required|prohibited|eligible|ineligible|entitled)\b",
            lowered,
        )
    )
    document_index = resource_markers >= 5 and normative_markers <= 1
    if document_index:
        reasons.append("document_resource_index")
        score -= 8

    relevant = bool(text) and score >= 2 and not document_index
    payload = {
        "classifier_version": RELEVANCE_CLASSIFIER_VERSION,
        "section_id": section.get("section_id"),
        "section_hash": section.get("normalized_text_hash"),
        "relevant": relevant,
        "score": score,
        "reasons": sorted(reasons),
    }
    payload["decision_hash"] = canonical_sha256(payload)
    return payload


def segment_text(
    snapshot_hash: str,
    text: str,
    *,
    parser_name: str,
    parser_version: str = "1",
    extraction_pipeline_version: str = "legacy-v1",
    ocr_used: bool = False,
    max_chars: int = 12_000,
    source_locator: dict[str, Any] | None = None,
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
                "section_id": stable_id(
                    "sec",
                    snapshot_hash,
                    extraction_pipeline_version,
                    parser_name,
                    parser_version,
                    ordinal,
                    text_hash,
                ),
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
                "extraction_pipeline_version": extraction_pipeline_version,
                "ocr_used": ocr_used,
            }
        )
        if source_locator is not None:
            sections[-1]["source_locator"] = {
                **source_locator,
                "artifact_char_start": char_start,
                "artifact_char_end": char_end,
                "sequence": ordinal,
            }
    return sections


def segment_structured_blocks(
    snapshot_hash: str,
    blocks: Iterable[dict[str, Any]],
    *,
    parser_name: str,
    parser_version: str = "2",
    extraction_pipeline_version: str = "legacy-v1",
    ocr_used: bool = False,
    max_chars: int = 12_000,
) -> list[dict[str, Any]]:
    """Segment adapter blocks without discarding legal hierarchy or locators."""

    prepared: list[dict[str, Any]] = []
    source_cursor = 0
    for block in blocks:
        text = normalize_source_text(str(block.get("text", "")))
        if not text:
            continue
        hierarchy = [
            normalize_source_text(str(part))
            for part in block.get("hierarchy_path", [])
            if normalize_source_text(str(part))
        ]
        heading = normalize_source_text(str(block.get("heading") or "")) or None
        locator = block.get("source_locator")
        if not isinstance(locator, dict):
            raise ValueError("structured source block requires a source_locator object")
        for offset in range(0, len(text), max_chars):
            fragment = text[offset : offset + max_chars]
            fragment_start = source_cursor + offset
            prepared.append(
                {
                    "text": fragment,
                    "hierarchy_path": hierarchy,
                    "heading": heading,
                    "block_kind": str(block.get("block_kind") or "paragraph"),
                    "source_locator": {
                        **locator,
                        "fragment_char_start": offset,
                        "fragment_char_end": offset + len(fragment),
                    },
                    "source_char_start": fragment_start,
                    "source_char_end": fragment_start + len(fragment),
                }
            )
        source_cursor += len(text) + 1

    grouped: list[dict[str, Any]] = []
    for block in prepared:
        if (
            grouped
            and grouped[-1]["hierarchy_path"] == block["hierarchy_path"]
            and len(grouped[-1]["text"]) + 1 + len(block["text"]) <= max_chars
        ):
            grouped[-1]["text"] += "\n" + block["text"]
            grouped[-1]["source_char_end"] = block["source_char_end"]
            grouped[-1]["source_locators"].append(block["source_locator"])
            grouped[-1]["block_kinds"].append(block["block_kind"])
            continue
        grouped.append(
            {
                "text": block["text"],
                "hierarchy_path": block["hierarchy_path"],
                "heading": block["heading"],
                "source_char_start": block["source_char_start"],
                "source_char_end": block["source_char_end"],
                "source_locators": [block["source_locator"]],
                "block_kinds": [block["block_kind"]],
            }
        )

    sections: list[dict[str, Any]] = []
    for ordinal, group in enumerate(grouped):
        text = group["text"]
        text_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        hierarchy = group["hierarchy_path"]
        heading = group["heading"] or (hierarchy[-1] if hierarchy else text[:240])
        sections.append(
            {
                "schema_version": SECTION_SCHEMA,
                "section_id": stable_id(
                    "sec",
                    snapshot_hash,
                    extraction_pipeline_version,
                    parser_name,
                    parser_version,
                    ordinal,
                    text_hash,
                    hierarchy,
                ),
                "snapshot_hash": snapshot_hash,
                "parent_section_id": None,
                "ordinal": ordinal,
                "hierarchy_path": hierarchy,
                "heading": heading,
                "normalized_text": text,
                "normalized_text_hash": text_hash,
                "source_char_start": group["source_char_start"],
                "source_char_end": group["source_char_end"],
                "parser_name": parser_name,
                "parser_version": parser_version,
                "extraction_pipeline_version": extraction_pipeline_version,
                "ocr_used": ocr_used,
                "source_locator": {
                    "block_kinds": sorted(set(group["block_kinds"])),
                    "blocks": group["source_locators"],
                },
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
    section: dict[str, Any],
    prompt_version: str,
    model_version: str,
    schema_version: str,
    response_contract_version: str,
) -> str:
    source_programs = sorted(
        {str(value) for value in section.get("programs", []) if str(value)}
    )
    return canonical_sha256(
        {
            "source_hash": section["snapshot_hash"],
            "section_hash": section["normalized_text_hash"],
            "source_programs": source_programs,
            "prompt_version": prompt_version,
            "model_version": model_version,
            "schema_version": schema_version,
            "response_contract_version": response_contract_version,
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
    source_programs = sorted(
        {str(value) for value in section.get("programs", [program])}
    )
    if not source_programs or any(not valid_program(value) for value in source_programs):
        raise ValueError("source section contains an unknown program")
    if program not in source_programs:
        raise ValueError("inference program is not linked to the source section")
    section_with_programs = {**section, "programs": source_programs}
    prompt_version = EXTRACTION_PROMPT_VERSION if pass_number == 1 else CRITIQUE_PROMPT_VERSION
    request = {
        "schema_version": INFERENCE_SCHEMA,
        "pass": pass_number,
        "prompt_version": prompt_version,
        "model_version": CLAUDE_MODEL,
        "response_contract_version": INFERENCE_RESPONSE_CONTRACT_VERSION,
        "program": program,
        "source_programs": source_programs,
        "section": {
            "section_id": section["section_id"],
            "snapshot_hash": section["snapshot_hash"],
            "heading": section.get("heading"),
            "hierarchy_path": section.get("hierarchy_path", []),
            "source_locator": section.get("source_locator", {}),
            "text": section["normalized_text"],
        },
        "idempotency_key": inference_idempotency_key(
            section_with_programs,
            prompt_version,
            CLAUDE_MODEL,
            INFERENCE_SCHEMA,
            INFERENCE_RESPONSE_CONTRACT_VERSION,
        ),
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
        received = (
            type(candidates).__name__
            if "candidates" in response
            else "missing"
        )
        return errors + [
            "inference candidates must be a list "
            f"(received {received}; response keys: "
            f"{', '.join(sorted(str(key) for key in response))})"
        ]
    if len(candidates) > 25:
        errors.append("inference response exceeds the 25-candidate limit")
    forbidden = {
        "review_status",
        "legal_verification_status",
        "runtime_eligibility_status",
        "runtime_activation",
        "proof_binding",
    }
    source_programs = {
        str(value) for value in section.get("programs", []) if str(value)
    }
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, dict):
            errors.append(f"candidates[{index}] must be an object")
            continue
        illegal = sorted(forbidden.intersection(candidate))
        if illegal:
            errors.append(f"candidates[{index}] sets forbidden status fields: {', '.join(illegal)}")
        if expected_pass == 1:
            if not valid_program(candidate.get("program")):
                errors.append(f"candidates[{index}] has an unknown program")
            elif source_programs and candidate.get("program") not in source_programs:
                errors.append(
                    f"candidates[{index}] program is not linked to the source section"
                )
            authority = candidate.get("authority")
            if (
                not isinstance(authority, dict)
                or not str(authority.get("issuer", "")).strip()
                or not str(authority.get("citation", "")).strip()
            ):
                errors.append(
                    f"candidates[{index}] authority issuer and citation are required"
                )
            if candidate.get("rule_type") not in RULE_TYPES:
                errors.append(f"candidates[{index}] rule_type is unsupported")
            _validate_condition(
                candidate.get("conditions"), f"candidates[{index}].conditions", errors
            )
            _validate_outcome(
                candidate.get("outcome"), f"candidates[{index}].outcome", errors
            )
            effective_from = None
            if candidate.get("effective_from") is not None:
                effective_from = _parse_iso_date(
                    candidate.get("effective_from"),
                    f"candidates[{index}].effective_from",
                    errors,
                )
            effective_through = None
            if candidate.get("effective_through") is not None:
                effective_through = _parse_iso_date(
                    candidate.get("effective_through"),
                    f"candidates[{index}].effective_through",
                    errors,
                )
            if (
                effective_from
                and effective_through
                and effective_through < effective_from
            ):
                errors.append(
                    f"candidates[{index}].effective_through cannot precede effective_from"
                )
            if not isinstance(candidate.get("exceptions"), list):
                errors.append(f"candidates[{index}].exceptions must be a list")
        if expected_pass == 2:
            if not re.fullmatch(r"cand_[0-9a-f]{32}", str(candidate.get("candidate_id", ""))):
                errors.append(f"candidates[{index}] has an invalid candidate_id")
            critique = candidate.get("critique")
            if not isinstance(critique, dict) or critique.get("result") not in {"accept", "repair", "reject"}:
                errors.append(f"candidates[{index}] critique result is invalid")
            elif not isinstance(critique.get("findings"), list):
                errors.append(f"candidates[{index}] critique findings must be a list")
            else:
                repaired = critique.get("repaired_candidate")
                if critique.get("result") == "repair":
                    if not isinstance(repaired, dict):
                        errors.append(
                            f"candidates[{index}] repair critique requires repaired_candidate"
                        )
                    else:
                        if "candidate_id" in repaired:
                            errors.append(
                                f"candidates[{index}] repaired_candidate cannot choose its candidate_id"
                            )
                        repaired_errors = validate_inference_candidates(
                            section,
                            {
                                "schema_version": INFERENCE_SCHEMA,
                                "pass": 1,
                                "candidates": [repaired],
                            },
                            expected_pass=1,
                        )
                        errors.extend(
                            f"candidates[{index}].repaired_candidate: {error}"
                            for error in repaired_errors
                        )
                        if (
                            not repaired_errors
                            and candidate_id(section, repaired)
                            == candidate.get("candidate_id")
                        ):
                            errors.append(
                                f"candidates[{index}] repair critique did not change candidate semantics"
                            )
                elif repaired is not None:
                    errors.append(
                        f"candidates[{index}] non-repair critique cannot include repaired_candidate"
                    )
        if expected_pass == 1:
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
        "jurisdiction": candidate.get("jurisdiction"),
        "authority": candidate.get("authority"),
        "rule_type": candidate.get("rule_type"),
        "conditions": candidate.get("conditions"),
        "outcome": candidate.get("outcome"),
        "effective_from": candidate.get("effective_from"),
        "effective_through": candidate.get("effective_through"),
        "exceptions": candidate.get("exceptions", []),
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
    left_start = (
        datetime.strptime(left["effective_from"], "%Y-%m-%d").date()
        if left.get("effective_from")
        else datetime.min.date()
    )
    right_start = (
        datetime.strptime(right["effective_from"], "%Y-%m-%d").date()
        if right.get("effective_from")
        else datetime.min.date()
    )
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
    open_conflicts: int = 0,
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
            "no_open_conflicts": open_conflicts == 0,
            "no_silently_merged_conflicts": silently_merged_conflicts == 0,
            "deterministic_rerun": deterministic_rerun_match,
        }
    )
    payload = {
        "schema_version": QUALITY_SCHEMA,
        "candidate_count": candidate_count,
        "sample_count": sample_count,
        "thresholds": QUALITY_THRESHOLDS,
        "measurements": measurements,
        "program_metrics": dict(sorted(program_metrics.items())),
        "open_conflicts": open_conflicts,
        "silently_merged_conflicts": silently_merged_conflicts,
        "mandatory_unsampled": mandatory_unsampled,
        "two_role_sample_count": two_role_sample_count,
        "deterministic_rerun_match": deterministic_rerun_match,
        "gates": gates,
        "passed": all(gates.values()),
        "runtime_activation": False,
        "proof_binding": False,
    }
    payload["canonical_quality_hash"] = canonical_sha256(payload)
    return payload


def build_release_manifest(
    *,
    release_id: str,
    target_count: int,
    candidates: Iterable[dict[str, Any]],
    source_registry_id: str,
    source_manifest_hash: str,
    quality_report: dict[str, Any],
    blocker_counts: dict[str, int],
    reviewer_evidence: dict[str, Any],
) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", release_id):
        raise ValueError("corpus release ID is invalid")
    if not str(source_registry_id).strip():
        raise ValueError("corpus release source registry ID is required")
    if not re.fullmatch(r"[0-9a-f]{64}", source_manifest_hash):
        raise ValueError("corpus release source manifest hash is invalid")
    selection = select_balanced_release_candidates(candidates, target_count)
    ordered = selection["selected_candidates"]
    ids = [item["candidate_id"] for item in ordered]
    snapshot_hashes = sorted({str(item.get("snapshot_hash", "")) for item in ordered})
    section_ids = [str(item.get("section_id", "")) for item in ordered]
    evidence_hashes = [str(item.get("evidence_hash", "")) for item in ordered]
    if ordered:
        if any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in snapshot_hashes):
            raise ValueError("corpus release candidate snapshot hash is invalid")
        if any(not value.strip() for value in section_ids):
            raise ValueError("corpus release candidate section ID is required")
        if any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in evidence_hashes):
            raise ValueError("corpus release candidate evidence hash is invalid")
    schema_versions = {
        "canonical_rule": RULE_SCHEMA_VERSION,
        "source_snapshot": SOURCE_SNAPSHOT_SCHEMA,
        "source_section": SECTION_SCHEMA,
        "grounded_inference": INFERENCE_SCHEMA,
        "quality_report": QUALITY_SCHEMA,
    }
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
        "available_candidate_count": selection["available_candidate_count"],
        "excluded_above_quota": selection["excluded_above_quota"],
        "program_deficits": selection["program_deficits"],
        "candidate_ids_sha256": canonical_sha256(ids),
        "source_registry_id": source_registry_id,
        "source_manifest_hash": source_manifest_hash,
        "source_snapshot_count": len(snapshot_hashes),
        "source_snapshot_hashes": snapshot_hashes,
        "source_snapshot_hashes_sha256": canonical_sha256(snapshot_hashes),
        "section_ids_sha256": canonical_sha256(section_ids),
        "evidence_hashes_sha256": canonical_sha256(evidence_hashes),
        "schema_versions": schema_versions,
        "prompt_versions": [EXTRACTION_PROMPT_VERSION, CRITIQUE_PROMPT_VERSION],
        "model_versions": [CLAUDE_MODEL],
        "inference_contract": {
            "response_contract_version": INFERENCE_RESPONSE_CONTRACT_VERSION,
            "extraction_contract_key": EXTRACTION_CONTRACT_KEY,
            "critique_contract_key": CRITIQUE_CONTRACT_KEY,
        },
        "program_coverage": coverage,
        "program_quotas": quotas,
        "quota_met": coverage == quotas,
        "blocker_counts": dict(sorted(blocker_counts.items())),
        "quality": quality_report,
        "quality_report_hash": canonical_sha256(quality_report),
        "reviewer_evidence": reviewer_evidence,
        "reviewer_evidence_hash": canonical_sha256(reviewer_evidence),
        "runtime_activation": False,
        "proof_binding": False,
        "production_usable": False,
    }
    payload["gates_passed"] = bool(
        len(ordered) == target_count and payload["quota_met"] and quality_report.get("passed")
    )
    payload["canonical_release_hash"] = canonical_sha256(payload)
    errors = validate_release_manifest(payload)
    if errors:
        raise ValueError("; ".join(errors))
    return payload


def validate_release_manifest(manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if manifest.get("schema_version") != RELEASE_SCHEMA:
        errors.append("unsupported corpus release schema")
    release_id = str(manifest.get("release_id", ""))
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", release_id):
        errors.append("corpus release ID is invalid")
    if not str(manifest.get("source_registry_id", "")).strip():
        errors.append("corpus release source registry ID is required")
    for field in (
        "candidate_ids_sha256",
        "source_manifest_hash",
        "source_snapshot_hashes_sha256",
        "section_ids_sha256",
        "evidence_hashes_sha256",
        "quality_report_hash",
        "reviewer_evidence_hash",
    ):
        if not re.fullmatch(r"[0-9a-f]{64}", str(manifest.get(field, ""))):
            errors.append(f"corpus release {field} is invalid")
    try:
        target_count = int(manifest.get("target_count"))
        candidate_count = int(manifest.get("candidate_count"))
        available_count = int(manifest.get("available_candidate_count"))
        excluded_count = int(manifest.get("excluded_above_quota"))
    except (TypeError, ValueError):
        target_count = candidate_count = available_count = excluded_count = -1
        errors.append("corpus release counts are invalid")
    if target_count not in CORPUS_MILESTONES:
        errors.append("corpus release target is unsupported")
    if min(candidate_count, available_count, excluded_count) < 0:
        errors.append("corpus release counts cannot be negative")
    if available_count < candidate_count:
        errors.append("corpus release available count is below candidate count")

    snapshot_hashes = manifest.get("source_snapshot_hashes")
    if not isinstance(snapshot_hashes, list) or snapshot_hashes != sorted(
        set(str(value) for value in snapshot_hashes)
    ) or any(not re.fullmatch(r"[0-9a-f]{64}", str(value)) for value in snapshot_hashes):
        errors.append("corpus release source snapshot hashes are invalid")
        snapshot_hashes = []
    try:
        snapshot_count = int(manifest.get("source_snapshot_count"))
    except (TypeError, ValueError):
        snapshot_count = -1
        errors.append("corpus release source snapshot count is invalid")
    if snapshot_count != len(snapshot_hashes):
        errors.append("corpus release source snapshot count mismatch")
    if manifest.get("source_snapshot_hashes_sha256") != canonical_sha256(snapshot_hashes):
        errors.append("corpus release source snapshot set hash mismatch")

    quotas = program_quotas(target_count) if target_count in CORPUS_MILESTONES else {}
    coverage = manifest.get("program_coverage")
    if not isinstance(coverage, dict) or set(coverage) != set(all_programs()):
        errors.append("corpus release program coverage is invalid")
        normalized_coverage: dict[str, int] = {}
    else:
        try:
            normalized_coverage = {
                program: int(coverage[program]) for program in all_programs()
            }
        except (TypeError, ValueError):
            normalized_coverage = {}
            errors.append("corpus release program coverage counts are invalid")
    if normalized_coverage and (
        min(normalized_coverage.values()) < 0
        or sum(normalized_coverage.values()) != candidate_count
    ):
        errors.append("corpus release program coverage count mismatch")
    if manifest.get("program_quotas") != quotas:
        errors.append("corpus release program quotas mismatch")
    expected_deficits = (
        {
            program: max(0, quotas[program] - normalized_coverage[program])
            for program in all_programs()
        }
        if quotas and normalized_coverage
        else {}
    )
    if manifest.get("program_deficits") != expected_deficits:
        errors.append("corpus release program deficits mismatch")
    quota_met = bool(quotas and normalized_coverage == quotas)
    if manifest.get("quota_met") is not quota_met:
        errors.append("corpus release quota gate mismatch")

    quality = manifest.get("quality")
    quality_passed = False
    if not isinstance(quality, dict):
        errors.append("corpus release quality report is required")
    else:
        if quality.get("schema_version") != QUALITY_SCHEMA:
            errors.append("corpus release quality schema mismatch")
        if quality.get("runtime_activation") is not False:
            errors.append("corpus release quality runtime activation must be false")
        if quality.get("proof_binding") is not False:
            errors.append("corpus release quality proof binding must be false")
        gates = quality.get("gates")
        if not isinstance(gates, dict) or not gates or any(
            not isinstance(value, bool) for value in gates.values()
        ):
            errors.append("corpus release quality gates are invalid")
        else:
            quality_passed = all(gates.values())
            if quality.get("passed") is not quality_passed:
                errors.append("corpus release quality verdict mismatch")
        expected_quality_hash = canonical_sha256(quality)
        if quality.get("canonical_quality_hash") != canonical_sha256(
            {key: value for key, value in quality.items() if key != "canonical_quality_hash"}
        ):
            errors.append("corpus release quality canonical hash mismatch")
        if manifest.get("quality_report_hash") != expected_quality_hash:
            errors.append("corpus release quality report hash mismatch")

    reviewer_evidence = manifest.get("reviewer_evidence")
    if not isinstance(reviewer_evidence, dict):
        errors.append("corpus release reviewer evidence is required")
    elif (
        reviewer_evidence.get("runtime_activation") is not False
        or reviewer_evidence.get("proof_binding") is not False
    ):
        errors.append("corpus release reviewer evidence must remain non-binding")
    elif manifest.get("reviewer_evidence_hash") != canonical_sha256(
        reviewer_evidence
    ):
        errors.append("corpus release reviewer evidence hash mismatch")
    blocker_counts = manifest.get("blocker_counts")
    if not isinstance(blocker_counts, dict) or any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in blocker_counts.values()
    ):
        errors.append("corpus release blocker counts are invalid")

    if manifest.get("prompt_versions") != [
        EXTRACTION_PROMPT_VERSION,
        CRITIQUE_PROMPT_VERSION,
    ]:
        errors.append("corpus release prompt versions mismatch")
    if manifest.get("model_versions") != [CLAUDE_MODEL]:
        errors.append("corpus release model version mismatch")
    if manifest.get("schema_versions") != {
        "canonical_rule": RULE_SCHEMA_VERSION,
        "source_snapshot": SOURCE_SNAPSHOT_SCHEMA,
        "source_section": SECTION_SCHEMA,
        "grounded_inference": INFERENCE_SCHEMA,
        "quality_report": QUALITY_SCHEMA,
    }:
        errors.append("corpus release schema versions mismatch")
    if manifest.get("inference_contract") != {
        "response_contract_version": INFERENCE_RESPONSE_CONTRACT_VERSION,
        "extraction_contract_key": EXTRACTION_CONTRACT_KEY,
        "critique_contract_key": CRITIQUE_CONTRACT_KEY,
    }:
        errors.append("corpus release inference contract mismatch")
    if manifest.get("runtime_activation") is not False:
        errors.append("corpus release runtime activation must be false")
    if manifest.get("proof_binding") is not False:
        errors.append("corpus release proof binding must be false")
    if manifest.get("production_usable") is not False:
        errors.append("corpus release production_usable must be false")
    expected_gates_passed = bool(
        candidate_count == target_count and quota_met and quality_passed
    )
    if manifest.get("gates_passed") is not expected_gates_passed:
        errors.append("corpus release aggregate gate mismatch")
    expected_hash = canonical_sha256(
        {
            key: value
            for key, value in manifest.items()
            if key != "canonical_release_hash"
        }
    )
    if manifest.get("canonical_release_hash") != expected_hash:
        errors.append("corpus release canonical hash mismatch")
    return errors


def build_shadow_bundle(release: dict[str, Any], candidates: Iterable[dict[str, Any]]) -> dict[str, Any]:
    errors = validate_release_manifest(release)
    if errors:
        raise ValueError("; ".join(errors))
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
