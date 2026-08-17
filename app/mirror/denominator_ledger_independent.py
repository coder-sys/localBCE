"""Independent verifier for the bounded synthetic Mirror Denominator Ledger.

This module owns the denominator contract, population commitments, outcome
conservation, and explicit narrowing semantics.  It does not own source
parsing, graph admission, governance mutation, or persistence.  Those remain
with the existing independent source/graph verifiers and ContinuityStore.

The current NC fixture returns one bounded provider-directory unit.  Its
source profile says completeness is UNKNOWN, so this artifact preserves a
returned population and its later narrowing without asserting a complete
real-world denominator or nonmembership.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re
from typing import Mapping, Sequence

from app.governance import provider_continuity_control_pack_v2_independent as governance
from app.mirror import nc_medicaid_fhir_independent as fhir
from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import provider_trust_graph_independent as graph
from app.mirror import source_evidence_custody_independent as custody


ARTIFACT_KIND = "MIRROR_DENOMINATOR_LEDGER_V1"
SCHEMA = "mirror-denominator-ledger-v1"
SCHEMA_VERSION = 1
STAGE_KIND = "DENOMINATOR_LEDGER"
STAGE_BASELINE = "BASELINE_POPULATION"
STAGE_NARROWED = "EXPLICIT_NARROWING"
STAGES = (STAGE_BASELINE, STAGE_NARROWED)
DOMAIN = "BL/MIRROR/DENOMINATOR-LEDGER/"
MAX_ARTIFACT_BYTES = 262_144
MAX_STRING_BYTES = 8_192
MAX_COUNT = 64
HEX128 = re.compile(r"^[0-9a-f]{128}$")

PROFILE_ID = "mirror.denominator.synthetic-provider-directory.v1"
PROFILE_VERSION = 1
SUBJECT = "DENOMINATOR_SYNTHETIC_SCOPE"
SCOPE = PROFILE_ID
RULE_PROFILE_ID = "mirror.denominator.synthetic-active-return.v1"
RULE_VERSION = 1

COVERAGE_COMPLETE_UNKNOWN = "COMPLETE_RETURNED_SET_UNKNOWN_DENOMINATOR"
COVERAGE_PARTIAL_UNKNOWN = "PARTIAL_SOURCE_UNKNOWN_DENOMINATOR"
COVERAGE_FAILED_UNKNOWN = "FAILED_SOURCE_UNKNOWN_DENOMINATOR"
COVERAGE_STALE_UNKNOWN = "STALE_SOURCE_UNKNOWN_DENOMINATOR"
COVERAGE_CONFLICTING_UNKNOWN = "CONFLICTING_SOURCE_UNKNOWN_DENOMINATOR"
COVERAGE_STATUSES = (
    COVERAGE_COMPLETE_UNKNOWN,
    COVERAGE_PARTIAL_UNKNOWN,
    COVERAGE_FAILED_UNKNOWN,
    COVERAGE_STALE_UNKNOWN,
    COVERAGE_CONFLICTING_UNKNOWN,
)

BUCKET_RETAINED = "RETAINED"
BUCKET_EXCLUDED = "EXCLUDED_GOVERNED_REASON"
BUCKET_INVALID = "INVALID_OR_UNKNOWN"
BUCKET_CONFLICTED = "SOURCE_CONFLICTED"
BUCKETS = (BUCKET_RETAINED, BUCKET_EXCLUDED, BUCKET_INVALID, BUCKET_CONFLICTED)
REASON_RETAINED = "RULE_MATCH"
REASON_EXCLUDED = "RULE_EXCLUDED_INACTIVE_OR_OUTSIDE_EFFECTIVE_INTERVAL"
REASON_INVALID = "SOURCE_INCOMPLETE_OR_UNKNOWN"
REASON_CONFLICTED = "SOURCE_CONFLICT"
REASONS = (REASON_RETAINED, REASON_EXCLUDED, REASON_INVALID, REASON_CONFLICTED)

SOURCE_QUALITY_KEYS = {"duplicates", "malformed_or_unknown", "source_gap", "source_conflict"}
OUTCOME_KEYS = {BUCKET_RETAINED, BUCKET_EXCLUDED, BUCKET_INVALID, BUCKET_CONFLICTED}
REASON_KEYS = set(REASONS)

AUTHORITY_FLAGS = {
    "automaticControlSetId": None,
    "automatic_enforcement_eligible": False,
    "clearance_authority": False,
    "payment_authority": False,
    "economic_mutation": False,
    "production_usable": False,
    "synthetic_only": True,
    "production_source_authentication": False,
    "proofSuiteId": None,
}
FIXED_FLAGS = {
    "observation_only": True,
    "read_only": True,
    "definition_is_policy_binding_only": True,
    "complete_population_proven": False,
    "business_truth_proven": False,
    "absence_inferred": False,
    "nonmembership_inferred": False,
    "source_completeness": "UNKNOWN",
    "allow_nonmembership": False,
    "production_usable": False,
    "synthetic_only": True,
    "activation": False,
    "clearance_authority": False,
    "payment_authority": False,
    "economic_mutation": False,
    "proofSuiteId": None,
}

PROFILE_MATERIAL = {
    "profile_id": PROFILE_ID,
    "version": PROFILE_VERSION,
    "source_profile_id": profile.SOURCE_PROFILE_ID,
    "source_profile_version": profile.SOURCE_PROFILE_VERSION,
    "source_profile_digest": profile.NC_MEDICAID_PROFILE.profile_digest,
    "graph_profile_id": profile.NC_MEDICAID_GRAPH_PROFILE.profile_id,
    "graph_profile_version": profile.NC_MEDICAID_GRAPH_PROFILE.version,
    "graph_profile_digest": profile.NC_MEDICAID_GRAPH_PROFILE.profile_digest,
    "scope": profile.NC_MEDICAID_GRAPH_PROFILE.scope,
    "effective_start": profile.NC_MEDICAID_GRAPH_PROFILE.effective_start,
    "effective_end": profile.NC_MEDICAID_GRAPH_PROFILE.effective_end,
    "authorized_source_roles": sorted(profile.NC_MEDICAID_GRAPH_PROFILE.source_roles),
    "population_unit": "ONE_PRACTITIONER_ROLE_LOCATION_COMPOSITE",
    "completeness_claim": "UNKNOWN",
    "allow_nonmembership": False,
    "synthetic_only": True,
    "production_usable": False,
    "activation": False,
}

RULE_MATERIAL = {
    "rule_profile_id": RULE_PROFILE_ID,
    "version": RULE_VERSION,
    "population_unit": "ONE_PRACTITIONER_ROLE_LOCATION_COMPOSITE",
    "retained_when": [
        "Practitioner.active=true",
        "PractitionerRole.active=true",
        "Location.status=active",
        "PractitionerRole.period covers the fixture observation date",
    ],
    "excluded_reason": REASON_EXCLUDED,
    "no_legal_liability": True,
    "no_payment_effect": True,
    "no_absence_inference": True,
}

CASE_KEYS = {
    "schema", "schema_version", "stage_kind", "profile_binding", "governance_binding",
    "subject", "scope", "source_binding", "population", "narrowing", "flags", "authority",
    "prior_artifact_id", "prior_stage_id", "artifact_id", "current_stage_id", "transition_id",
}
PROFILE_KEYS = set(PROFILE_MATERIAL) | {"profile_digest"}
RULE_KEYS = set(RULE_MATERIAL) | {"rule_digest"}
GOVERNANCE_KEYS = {
    "artifact_id", "stage_id", "transition_id", "profile_id", "profile_version", "profile_digest",
    "effective_start", "effective_end",
}
SOURCE_KEYS = {
    "artifact_id", "stage_id", "profile_id", "profile_version", "profile_digest",
    "source_profile_id", "source_profile_version", "source_profile_digest", "envelope_digest",
    "snapshot_id", "snapshot_root", "source_status", "failure_code", "freshness", "observation_time",
    "fetched_at", "page_complete", "source_completeness", "allow_nonmembership",
    "graph_artifact_id", "graph_stage_id", "graph_transition_id",
}
POPULATION_KEYS = {
    "population_root", "input_record_count", "coverage_status", "source_quality",
    "source_completeness", "allow_nonmembership",
}
NARROWING_KEYS = {
    "rule_binding", "parent_population_root", "child_population_root", "input_record_count",
    "outcome_counts", "reason_counts", "outcome_root", "chronology", "coverage_status",
    "source_completeness", "allow_nonmembership",
}
CHRONOLOGY_KEYS = {"prior_observation_time", "current_observation_time", "order"}

_HEX_FIELDS = {
    "artifact_id", "stage_id", "transition_id", "profile_digest", "source_profile_digest", "envelope_digest",
    "snapshot_id", "snapshot_root", "graph_artifact_id", "graph_stage_id", "graph_transition_id",
    "population_root", "parent_population_root", "child_population_root", "outcome_root", "comparison_root",
}
_CONFLICT_FAILURE_CODES = {"total-drift", "marker-drift"}
_MALFORMED_FAILURE_CODES = {"schema", "noncanonical", "forbidden-resource", "capability-mismatch", "profile-downgrade"}


class IndependentDenominatorError(ValueError):
    """Stable fail-closed error from the denominator verifier."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise IndependentDenominatorError("denominator:noncanonical") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IndependentDenominatorError("denominator:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, *, depth: int = 0, count: list[int] | None = None) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if count[0] > 16_384:
        raise IndependentDenominatorError("denominator:node-cap")
    if depth > 24:
        raise IndependentDenominatorError("denominator:depth-cap")
    if isinstance(value, float):
        raise IndependentDenominatorError("denominator:float")
    if isinstance(value, str):
        try:
            if len(value.encode("ascii")) > MAX_STRING_BYTES:
                raise IndependentDenominatorError("denominator:string-cap")
        except UnicodeEncodeError as exc:
            raise IndependentDenominatorError("denominator:ascii") from exc
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IndependentDenominatorError("denominator:key-type")
            _walk(key, depth=depth + 1, count=count)
            _walk(item, depth=depth + 1, count=count)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth=depth + 1, count=count)


def _parse(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentDenominatorError("denominator:byte-cap")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(IndependentDenominatorError("denominator:constant")),
        )
    except IndependentDenominatorError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentDenominatorError("denominator:parse") from exc
    if not isinstance(value, dict):
        raise IndependentDenominatorError("denominator:top-level")
    _walk(value)
    if _canonical(value) != raw:
        raise IndependentDenominatorError("denominator:not-canonical")
    return value


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _hex(value: object, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or HEX128.fullmatch(value) is None:
        raise IndependentDenominatorError(f"denominator:{label}")
    return value


def _text(value: object, label: str, *, maximum: int = MAX_STRING_BYTES) -> str:
    if not isinstance(value, str) or not value:
        raise IndependentDenominatorError(f"denominator:{label}")
    try:
        if len(value.encode("ascii")) > maximum:
            raise IndependentDenominatorError(f"denominator:{label}")
    except UnicodeEncodeError as exc:
        raise IndependentDenominatorError(f"denominator:{label}") from exc
    return value


def _expect(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise IndependentDenominatorError(f"denominator:{label}-keys")
    return value


def _count(value: object, label: str) -> int:
    if type(value) is not int or value < 0 or value > MAX_COUNT:
        raise IndependentDenominatorError(f"denominator:{label}")
    return value


def _profile_binding() -> dict[str, object]:
    return {**PROFILE_MATERIAL, "profile_digest": _digest("profile", PROFILE_MATERIAL)}


def _rule_binding() -> dict[str, object]:
    return {**RULE_MATERIAL, "rule_digest": _digest("rule", RULE_MATERIAL)}


def _empty_counts(keys: Sequence[str]) -> dict[str, int]:
    return {key: 0 for key in keys}


def _source_quality(source_value: Mapping[str, object], fhir_result: Mapping[str, object]) -> dict[str, int]:
    status = source_value["source_status"]
    failure = source_value["failure_code"]
    resources = fhir_result["resources"]
    quality = _empty_counts(("duplicates", "malformed_or_unknown", "source_gap", "source_conflict"))
    if status != "COMPLETE":
        quality["source_gap"] = 1
    if failure in _CONFLICT_FAILURE_CODES:
        quality["source_conflict"] = 1
    expected_counts = dict(profile.RESOURCE_CARDINALITY)
    counts = fhir_result.get("resource_counts")
    exact_shape = isinstance(counts, dict) and counts == expected_counts and len(resources) == sum(expected_counts.values())
    if resources and (status != "COMPLETE" or not exact_shape):
        quality["malformed_or_unknown"] = 1
    if failure in _MALFORMED_FAILURE_CODES:
        quality["malformed_or_unknown"] = 1
    return quality


def _coverage_status(source_value: Mapping[str, object], quality: Mapping[str, int]) -> str:
    if quality["source_conflict"]:
        return COVERAGE_CONFLICTING_UNKNOWN
    status = source_value["source_status"]
    return {
        "COMPLETE": COVERAGE_COMPLETE_UNKNOWN,
        "PARTIAL": COVERAGE_PARTIAL_UNKNOWN,
        "FAILED": COVERAGE_FAILED_UNKNOWN,
        "STALE": COVERAGE_STALE_UNKNOWN,
    }[status]


def _resources_from_source(source_value: Mapping[str, object]) -> bytes:
    envelope = _expect(source_value["envelope"], {"encoding", "byte_length", "bytes_hex"}, "source-envelope")
    if envelope["encoding"] != "canonical-json-ascii-hex" or type(envelope["byte_length"]) is not int or type(envelope["bytes_hex"]) is not str:
        raise IndependentDenominatorError("denominator:source-envelope")
    try:
        raw = bytes.fromhex(envelope["bytes_hex"])
    except ValueError as exc:
        raise IndependentDenominatorError("denominator:source-envelope") from exc
    if len(raw) != envelope["byte_length"]:
        raise IndependentDenominatorError("denominator:source-envelope")
    return raw


def _record_units(resources: Sequence[Mapping[str, object]]) -> list[list[dict[str, object]]]:
    if not resources:
        return []
    ordered = sorted((deepcopy(dict(item)) for item in resources), key=lambda item: (str(item.get("resourceType")), str(item.get("id"))))
    return [ordered]


def _record_leaf(resources: Sequence[Mapping[str, object]]) -> str:
    ordered = sorted((dict(item) for item in resources), key=lambda item: (str(item.get("resourceType")), str(item.get("id"))))
    return _digest("record-leaf", {"profile_id": PROFILE_ID, "resources": ordered})


def _population_root(leaves: Sequence[str]) -> str:
    return _digest("population-root", {"leaves": sorted(leaves), "record_count": len(leaves)})


def _empty_population_root() -> str:
    return _population_root(())


def _period_matches(role: Mapping[str, object]) -> bool:
    period = role.get("period")
    if not isinstance(period, dict) or not isinstance(period.get("start"), str) or not isinstance(period.get("end"), str):
        return False
    observation_date = profile.NC_MEDICAID_PROFILE.fetched_at[:10]
    return str(period["start"]) <= observation_date < str(period["end"])


def _rule_decision(resources: Sequence[Mapping[str, object]]) -> tuple[str, str]:
    by_type = {str(item.get("resourceType")): item for item in resources}
    practitioner = by_type.get("Practitioner")
    role = by_type.get("PractitionerRole")
    location = by_type.get("Location")
    if (
        not isinstance(practitioner, dict)
        or not isinstance(role, dict)
        or not isinstance(location, dict)
        or practitioner.get("active") is not True
        or role.get("active") is not True
        or location.get("status") != "active"
        or not _period_matches(role)
    ):
        return BUCKET_EXCLUDED, REASON_EXCLUDED
    return BUCKET_RETAINED, REASON_RETAINED


def _outcomes(source_value: Mapping[str, object], fhir_result: Mapping[str, object]) -> tuple[list[dict[str, str]], dict[str, int], dict[str, int]]:
    resources = fhir_result["resources"]
    units = _record_units(resources)
    quality = _source_quality(source_value, fhir_result)
    outcomes: list[dict[str, str]] = []
    for unit in units:
        leaf = _record_leaf(unit)
        if quality["source_conflict"]:
            bucket, reason = BUCKET_CONFLICTED, REASON_CONFLICTED
        elif source_value["source_status"] != "COMPLETE" or quality["malformed_or_unknown"]:
            bucket, reason = BUCKET_INVALID, REASON_INVALID
        else:
            bucket, reason = _rule_decision(unit)
        outcomes.append({"leaf": leaf, "bucket": bucket, "reason": reason})
    outcome_counts = _empty_counts(BUCKETS)
    reason_counts = _empty_counts(REASONS)
    for item in outcomes:
        outcome_counts[item["bucket"]] += 1
        reason_counts[item["reason"]] += 1
    return outcomes, outcome_counts, reason_counts


def _source_and_fhir(
    source_raw: bytes,
    graph_raw: bytes | None,
    governance_raw: bytes,
    registry: Mapping[str, object],
) -> tuple[dict[str, object], dict[str, object], dict[str, object] | None, dict[str, object] | None, dict[str, object], dict[str, object]]:
    try:
        source_value = custody._parse(source_raw)
        source_preview = custody.verify_artifact(
            source_raw,
            graph_raw=graph_raw,
            graph_profile_registry=registry,
            allow_unresolved_graph=True,
        )
        linked_id = source_preview.get("linked_graph_artifact_id")
        if (linked_id is not None) != (graph_raw is not None):
            raise IndependentDenominatorError("denominator:graph-link")
        graph_value: dict[str, object] | None = None
        graph_result: dict[str, object] | None = None
        if graph_raw is not None:
            graph_value = graph._parse(graph_raw)
            graph_result = graph.verify_bytes_v2(graph_raw, registry)
            if graph_result.get("report_id") != linked_id or graph_result.get("profile_id") != profile.NC_MEDICAID_GRAPH_PROFILE.profile_id:
                raise IndependentDenominatorError("denominator:graph-binding")
        envelope_raw = _resources_from_source(source_value)
        fhir_result = fhir.verify_bytes(envelope_raw, profile=profile.NC_MEDICAID_PROFILE)
        if fhir_result["snapshot_id"] != source_value["snapshot_id"] or fhir_result["snapshot_root"] != source_value["snapshot_root"]:
            raise IndependentDenominatorError("denominator:snapshot-binding")
        gov_value = governance._parse(governance_raw)
        gov_result = governance.verify_bytes(governance_raw, registry)
        if gov_result.get("current_stage_kind") != governance.STAGE_APPROVED:
            raise IndependentDenominatorError("denominator:governance-not-approved")
        gov_profile = _expect(gov_value["profile"], governance.PROFILE_KEYS, "governance-profile")
        if (
            gov_profile.get("profile_id") != profile.NC_MEDICAID_GRAPH_PROFILE.profile_id
            or gov_profile.get("version") != profile.NC_MEDICAID_GRAPH_PROFILE.version
            or gov_profile.get("profile_digest") != profile.NC_MEDICAID_GRAPH_PROFILE.profile_digest
            or gov_value.get("subject") != {"provider_graph_subject": profile.NC_MEDICAID_GRAPH_PROFILE.subject, "scope": profile.NC_MEDICAID_GRAPH_PROFILE.scope}
        ):
            raise IndependentDenominatorError("denominator:governance-profile")
        observation_time = source_value["observation_time"]
        if not gov_result["effective_start"] <= observation_time <= gov_result["effective_end"]:
            raise IndependentDenominatorError("denominator:governance-interval")
    except IndependentDenominatorError:
        raise
    except Exception as exc:
        raise IndependentDenominatorError("denominator:upstream-reject") from exc
    return source_value, source_preview, graph_value, graph_result, fhir_result, gov_result


def _governance_binding(governance_value: Mapping[str, object], governance_result: Mapping[str, object]) -> dict[str, object]:
    return {
        "artifact_id": _hex(governance_result["artifact_id"], "governance-artifact"),
        "stage_id": _hex(governance_result["current_stage_id"], "governance-stage"),
        "transition_id": _hex(governance_value["chain_root"], "governance-transition"),
        "profile_id": _text(governance_result["profile_id"], "governance-profile-id"),
        "profile_version": governance_result["profile_version"],
        "profile_digest": _hex(governance_result["profile_digest"], "governance-profile-digest"),
        "effective_start": governance_result["effective_start"],
        "effective_end": governance_result["effective_end"],
    }


def _source_binding(
    source_value: Mapping[str, object],
    source_preview: Mapping[str, object],
    graph_value: Mapping[str, object] | None,
    fhir_result: Mapping[str, object],
) -> dict[str, object]:
    graph_binding = {
        "graph_artifact_id": None,
        "graph_stage_id": None,
        "graph_transition_id": None,
    }
    if graph_value is not None:
        snapshot = _expect(graph_value["observation_snapshot"], {"snapshot_id", "snapshot_root", "observation_time"}, "graph-snapshot")
        transition = _expect(graph_value["transition"], graph.TRANSITION_KEYS, "graph-transition")
        report = _expect(graph_value["report"], graph.REPORT_KEYS, "graph-report")
        graph_binding = {
            "graph_artifact_id": _hex(report["report_id"], "graph-artifact"),
            "graph_stage_id": _hex(snapshot["snapshot_id"], "graph-stage"),
            "graph_transition_id": _hex(transition["transition_id"], "graph-transition"),
        }
    return {
        "artifact_id": _hex(source_preview["artifact_id"], "source-artifact"),
        "stage_id": _hex(source_preview["current_stage_id"], "source-stage"),
        "profile_id": profile.NC_MEDICAID_GRAPH_PROFILE.profile_id,
        "profile_version": profile.NC_MEDICAID_GRAPH_PROFILE.version,
        "profile_digest": _hex(profile.NC_MEDICAID_GRAPH_PROFILE.profile_digest, "graph-profile-digest"),
        "source_profile_id": _text(source_value["profile_binding"]["source_profile_id"], "source-profile-id"),
        "source_profile_version": source_value["profile_binding"]["source_profile_version"],
        "source_profile_digest": _hex(profile.NC_MEDICAID_PROFILE.profile_digest, "source-profile-digest"),
        "envelope_digest": _hex(source_preview["envelope_digest"], "envelope-digest"),
        "snapshot_id": _hex(source_value["snapshot_id"], "snapshot-id"),
        "snapshot_root": _hex(source_value["snapshot_root"], "snapshot-root"),
        "source_status": _text(source_value["source_status"], "source-status"),
        "failure_code": source_value["failure_code"],
        "freshness": _text(source_value["freshness"], "freshness"),
        "observation_time": source_value["observation_time"],
        "fetched_at": _text(source_value["fetched_at"], "fetched-at"),
        "page_complete": source_value["page_complete"],
        "source_completeness": "UNKNOWN",
        "allow_nonmembership": False,
        **graph_binding,
    }


def _population(source_value: Mapping[str, object], fhir_result: Mapping[str, object]) -> dict[str, object]:
    resources = fhir_result["resources"]
    leaves = [_record_leaf(unit) for unit in _record_units(resources)]
    quality = _source_quality(source_value, fhir_result)
    return {
        "population_root": _population_root(leaves),
        "input_record_count": len(leaves),
        "coverage_status": _coverage_status(source_value, quality),
        "source_quality": quality,
        "source_completeness": "UNKNOWN",
        "allow_nonmembership": False,
    }


def _empty_narrowing() -> None:
    return None


def _narrowing(
    source_value: Mapping[str, object],
    source_preview: Mapping[str, object],
    fhir_result: Mapping[str, object],
    prior_population: Mapping[str, object],
) -> dict[str, object]:
    outcomes, outcome_counts, reason_counts = _outcomes(source_value, fhir_result)
    retained = [item["leaf"] for item in outcomes if item["bucket"] == BUCKET_RETAINED]
    outcome_root = _digest("outcome-root", {"parent_population_root": prior_population["population_root"], "outcomes": sorted(outcomes, key=lambda item: item["leaf"])})
    return {
        "rule_binding": _rule_binding(),
        "parent_population_root": prior_population["population_root"],
        "child_population_root": _population_root(retained),
        "input_record_count": len(outcomes),
        "outcome_counts": outcome_counts,
        "reason_counts": reason_counts,
        "outcome_root": outcome_root,
        "chronology": {
            "prior_observation_time": source_value["observation_time"],
            "current_observation_time": source_value["observation_time"],
            "order": "EQUAL_SOURCE_SNAPSHOT",
        },
        "coverage_status": prior_population["coverage_status"],
        "source_completeness": "UNKNOWN",
        "allow_nonmembership": False,
    }


def _base_body(
    source_value: Mapping[str, object],
    source_preview: Mapping[str, object],
    graph_value: Mapping[str, object] | None,
    fhir_result: Mapping[str, object],
    governance_value: Mapping[str, object],
    governance_result: Mapping[str, object],
) -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "stage_kind": STAGE_BASELINE,
        "profile_binding": _profile_binding(),
        "governance_binding": _governance_binding(governance_value, governance_result),
        "subject": SUBJECT,
        "scope": SCOPE,
        "source_binding": _source_binding(source_value, source_preview, graph_value, fhir_result),
        "population": _population(source_value, fhir_result),
        "narrowing": _empty_narrowing(),
        "flags": dict(FIXED_FLAGS),
        "authority": dict(AUTHORITY_FLAGS),
        "prior_artifact_id": None,
        "prior_stage_id": None,
    }


def _identity_values(value: Mapping[str, object]) -> tuple[str, str, str]:
    body = deepcopy(dict(value))
    for key in ("artifact_id", "current_stage_id", "transition_id"):
        body.pop(key, None)
    artifact_id = _digest("artifact-id", body)
    stage_id = _digest(
        "stage-id",
        {
            "artifact_id": artifact_id,
            "stage_kind": value["stage_kind"],
            "prior_artifact_id": value["prior_artifact_id"],
            "prior_stage_id": value["prior_stage_id"],
            "population_root": value["population"]["population_root"],
            "outcome_root": value["narrowing"]["outcome_root"] if isinstance(value["narrowing"], dict) else None,
        },
    )
    transition_id = _digest(
        "transition-id",
        {
            "artifact_id": artifact_id,
            "current_stage_id": stage_id,
            "stage_kind": value["stage_kind"],
            "prior_artifact_id": value["prior_artifact_id"],
            "prior_stage_id": value["prior_stage_id"],
        },
    )
    return artifact_id, stage_id, transition_id


def _validate_counts(value: object, keys: set[str], label: str) -> dict[str, int]:
    counts = _expect(value, keys, label)
    result = {key: _count(counts[key], f"{label}-{key}") for key in sorted(keys)}
    return result


def _validate_shape(value: Mapping[str, object]) -> None:
    if set(value) != CASE_KEYS or value.get("schema") != SCHEMA or value.get("schema_version") != SCHEMA_VERSION:
        raise IndependentDenominatorError("denominator:schema")
    profile_binding = _expect(value.get("profile_binding"), PROFILE_KEYS, "profile")
    if profile_binding != _profile_binding():
        raise IndependentDenominatorError("denominator:profile-binding")
    governance_binding = _expect(value.get("governance_binding"), GOVERNANCE_KEYS, "governance")
    for key in ("artifact_id", "stage_id", "transition_id", "profile_digest"):
        _hex(governance_binding[key], f"governance-{key}")
    _text(governance_binding["profile_id"], "governance-profile-id")
    for key in ("profile_version", "effective_start", "effective_end"):
        if type(governance_binding[key]) is not int:
            raise IndependentDenominatorError(f"denominator:governance-{key}")
    if value.get("subject") != SUBJECT or value.get("scope") != SCOPE:
        raise IndependentDenominatorError("denominator:scope")
    source = _expect(value.get("source_binding"), SOURCE_KEYS, "source")
    for key in ("artifact_id", "stage_id", "profile_digest", "source_profile_digest", "envelope_digest", "snapshot_id", "snapshot_root"):
        _hex(source[key], f"source-{key}")
    for key in ("graph_artifact_id", "graph_stage_id", "graph_transition_id"):
        _hex(source[key], f"source-{key}", nullable=True)
    for key in ("profile_id", "source_profile_id", "source_status", "freshness", "fetched_at"):
        _text(source[key], f"source-{key}")
    for key in ("profile_version", "source_profile_version", "observation_time"):
        if type(source[key]) is not int:
            raise IndependentDenominatorError(f"denominator:source-{key}")
    if type(source["page_complete"]) is not bool or source["source_completeness"] != "UNKNOWN" or source["allow_nonmembership"] is not False:
        raise IndependentDenominatorError("denominator:source-claims")
    if source["failure_code"] is not None and not isinstance(source["failure_code"], str):
        raise IndependentDenominatorError("denominator:source-failure")
    population = _expect(value.get("population"), POPULATION_KEYS, "population")
    _hex(population["population_root"], "population-root")
    _count(population["input_record_count"], "population-record-count")
    if population["coverage_status"] not in COVERAGE_STATUSES:
        raise IndependentDenominatorError("denominator:coverage-status")
    _validate_counts(population["source_quality"], SOURCE_QUALITY_KEYS, "source-quality")
    if population["source_completeness"] != "UNKNOWN" or population["allow_nonmembership"] is not False:
        raise IndependentDenominatorError("denominator:population-claims")
    narrowing = value["narrowing"]
    if narrowing is not None:
        item = _expect(narrowing, NARROWING_KEYS, "narrowing")
        rule = _expect(item["rule_binding"], RULE_KEYS, "rule")
        if rule != _rule_binding():
            raise IndependentDenominatorError("denominator:rule-binding")
        for key in ("parent_population_root", "child_population_root", "outcome_root"):
            _hex(item[key], f"narrowing-{key}")
        _count(item["input_record_count"], "narrowing-record-count")
        _validate_counts(item["outcome_counts"], OUTCOME_KEYS, "outcome-counts")
        _validate_counts(item["reason_counts"], REASON_KEYS, "reason-counts")
        chronology = _expect(item["chronology"], CHRONOLOGY_KEYS, "chronology")
        for key in ("prior_observation_time", "current_observation_time"):
            if type(chronology[key]) is not int:
                raise IndependentDenominatorError(f"denominator:chronology-{key}")
        if chronology["order"] != "EQUAL_SOURCE_SNAPSHOT":
            raise IndependentDenominatorError("denominator:chronology-order")
        if item["coverage_status"] not in COVERAGE_STATUSES or item["source_completeness"] != "UNKNOWN" or item["allow_nonmembership"] is not False:
            raise IndependentDenominatorError("denominator:narrowing-claims")
        if item["input_record_count"] != sum(item["outcome_counts"].values()) or item["input_record_count"] != sum(item["reason_counts"].values()):
            raise IndependentDenominatorError("denominator:conservation")
        if item["parent_population_root"] != population["population_root"]:
            raise IndependentDenominatorError("denominator:parent-root")
    if value["flags"] != FIXED_FLAGS or value["authority"] != AUTHORITY_FLAGS:
        raise IndependentDenominatorError("denominator:authority-flags")
    if value["stage_kind"] not in STAGES:
        raise IndependentDenominatorError("denominator:stage")
    if value["stage_kind"] == STAGE_BASELINE and (value["prior_artifact_id"] is not None or value["prior_stage_id"] is not None or narrowing is not None):
        raise IndependentDenominatorError("denominator:baseline-state")
    if value["stage_kind"] == STAGE_NARROWED and (value["prior_artifact_id"] is None or value["prior_stage_id"] is None or narrowing is None):
        raise IndependentDenominatorError("denominator:narrowed-state")
    for key in ("prior_artifact_id", "prior_stage_id"):
        _hex(value[key], f"denominator-{key}", nullable=True)
    _hex(value["artifact_id"], "artifact-id")
    _hex(value["current_stage_id"], "stage-id")
    _hex(value["transition_id"], "transition-id")


def _verify_upstream(
    source_raw: bytes,
    graph_raw: bytes | None,
    governance_raw: bytes,
    registry: Mapping[str, object],
) -> tuple[dict[str, object], dict[str, object], dict[str, object] | None, dict[str, object], dict[str, object]]:
    source_value, source_preview, graph_value, graph_result, fhir_result, governance_result = _source_and_fhir(source_raw, graph_raw, governance_raw, registry)
    return source_value, source_preview, graph_value, fhir_result, governance_result


def _expected_body(
    stage: str,
    *,
    source_raw: bytes,
    graph_raw: bytes | None,
    governance_raw: bytes,
    registry: Mapping[str, object],
    prior_denominator_raw: bytes | None,
) -> dict[str, object]:
    source_value, source_preview, graph_value, fhir_result, governance_result = _verify_upstream(source_raw, graph_raw, governance_raw, registry)
    governance_value = governance._parse(governance_raw)
    body = _base_body(source_value, source_preview, graph_value, fhir_result, governance_value, governance_result)
    if stage == STAGE_BASELINE:
        if prior_denominator_raw is not None:
            raise IndependentDenominatorError("denominator:baseline-prior")
        return body
    if stage != STAGE_NARROWED or prior_denominator_raw is None:
        raise IndependentDenominatorError("denominator:narrowing-prior")
    prior = _parse(prior_denominator_raw)
    _validate_shape(prior)
    if prior["stage_kind"] != STAGE_BASELINE:
        raise IndependentDenominatorError("denominator:prior-stage")
    if prior["source_binding"] != body["source_binding"] or prior["governance_binding"] != body["governance_binding"] or prior["population"] != body["population"]:
        raise IndependentDenominatorError("denominator:prior-binding")
    body["prior_artifact_id"] = prior["artifact_id"]
    body["prior_stage_id"] = prior["current_stage_id"]
    body["stage_kind"] = STAGE_NARROWED
    body["narrowing"] = _narrowing(source_value, source_preview, fhir_result, prior["population"])
    return body


def build_artifact(
    stage: str,
    *,
    source_raw: bytes,
    graph_raw: bytes | None,
    governance_raw: bytes,
    registry: Mapping[str, object],
    prior_denominator_raw: bytes | None = None,
) -> bytes:
    """Build a candidate from store-selected upstream bytes."""

    if stage not in STAGES:
        raise IndependentDenominatorError("denominator:stage")
    body = _expected_body(
        stage,
        source_raw=source_raw,
        graph_raw=graph_raw,
        governance_raw=governance_raw,
        registry=registry,
        prior_denominator_raw=prior_denominator_raw,
    )
    artifact_id, stage_id, transition_id = _identity_values(body)
    value = {**body, "artifact_id": artifact_id, "current_stage_id": stage_id, "transition_id": transition_id}
    _validate_shape(value)
    raw = _canonical(value)
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentDenominatorError("denominator:artifact-byte-cap")
    return raw


def verify_artifact(
    raw: bytes,
    *,
    source_raw: bytes,
    graph_raw: bytes | None,
    governance_raw: bytes,
    registry: Mapping[str, object],
    prior_denominator_raw: bytes | None = None,
) -> dict[str, object]:
    """Reconstruct one baseline or narrowing transition independently."""

    value = _parse(raw)
    _validate_shape(value)
    expected = _expected_body(
        value["stage_kind"],
        source_raw=source_raw,
        graph_raw=graph_raw,
        governance_raw=governance_raw,
        registry=registry,
        prior_denominator_raw=prior_denominator_raw,
    )
    body = dict(value)
    for key in ("artifact_id", "current_stage_id", "transition_id"):
        body.pop(key, None)
    if body != expected:
        raise IndependentDenominatorError("denominator:semantic-binding")
    artifact_id, stage_id, transition_id = _identity_values(value)
    if (value["artifact_id"], value["current_stage_id"], value["transition_id"]) != (artifact_id, stage_id, transition_id):
        raise IndependentDenominatorError("denominator:identity")
    return {
        "kind": ARTIFACT_KIND,
        "schema": SCHEMA,
        "artifact_id": value["artifact_id"],
        "payload": raw,
        "payload_hash": _digest("payload", raw.hex()),
        "subject": SUBJECT,
        "scope": SCOPE,
        "report_id": value["artifact_id"],
        "current_stage_id": value["current_stage_id"],
        "transition_id": value["transition_id"],
        "stage_kind": STAGE_KIND,
        "prior_artifact_id": value["prior_artifact_id"],
        "prior_stage_id": value["prior_stage_id"],
        "authority_json": _canonical(AUTHORITY_FLAGS).decode("ascii"),
        "profile_id": PROFILE_ID,
        "profile_version": PROFILE_VERSION,
        "denominator_stage": value["stage_kind"],
        "source_artifact_id": value["source_binding"]["artifact_id"],
        "population_root": value["population"]["population_root"],
        "child_population_root": value["narrowing"]["child_population_root"] if isinstance(value["narrowing"], dict) else None,
        "input_record_count": value["population"]["input_record_count"],
        "outcome_counts": value["narrowing"]["outcome_counts"] if isinstance(value["narrowing"], dict) else None,
    }


__all__ = [
    "ARTIFACT_KIND", "AUTHORITY_FLAGS", "BUCKET_CONFLICTED", "BUCKET_EXCLUDED", "BUCKET_INVALID", "BUCKET_RETAINED",
    "BUCKETS", "CASE_KEYS", "COVERAGE_COMPLETE_UNKNOWN", "COVERAGE_CONFLICTING_UNKNOWN", "COVERAGE_FAILED_UNKNOWN",
    "COVERAGE_PARTIAL_UNKNOWN", "COVERAGE_STALE_UNKNOWN", "FIXED_FLAGS", "IndependentDenominatorError", "MAX_ARTIFACT_BYTES",
    "PROFILE_ID", "PROFILE_VERSION", "RULE_PROFILE_ID", "RULE_VERSION", "SCHEMA", "SCHEMA_VERSION", "SCOPE", "STAGE_BASELINE",
    "STAGE_KIND", "STAGE_NARROWED", "STAGES", "SUBJECT", "build_artifact", "verify_artifact", "_canonical", "_digest", "_parse",
    "_identity_values",
]
