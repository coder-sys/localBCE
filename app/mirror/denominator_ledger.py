"""Producer-side composition for the bounded synthetic Denominator Ledger.

The producer owns composition and deterministic fixture decisions only.  It
does not accept caller-supplied population counts, membership outcomes,
completeness, or authority flags.  The wire bytes are independently rebuilt by
``denominator_ledger_independent`` before ContinuityStore commits them.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
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
DOMAIN = "BL/MIRROR/DENOMINATOR-LEDGER/"
PROFILE_ID = "mirror.denominator.synthetic-provider-directory.v1"
PROFILE_VERSION = 1
SUBJECT = "DENOMINATOR_SYNTHETIC_SCOPE"
SCOPE = PROFILE_ID
RULE_PROFILE_ID = "mirror.denominator.synthetic-active-return.v1"
RULE_VERSION = 1
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
SOURCE_QUALITY_KEYS = ("duplicates", "malformed_or_unknown", "source_gap", "source_conflict")
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


class DenominatorProducerError(ValueError):
    pass


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise DenominatorProducerError("denominator:noncanonical") from exc


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _profile_binding() -> dict[str, object]:
    material = {
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
    return {**material, "profile_digest": _digest("profile", material)}


def _rule_binding() -> dict[str, object]:
    material = {
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
    return {**material, "rule_digest": _digest("rule", material)}


def _hex(value: object, label: str, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or len(value) != 128 or any(char not in "0123456789abcdef" for char in value):
        raise DenominatorProducerError(f"denominator:{label}")
    return value


def _source_envelope(value: Mapping[str, object]) -> bytes:
    envelope = value.get("envelope")
    if not isinstance(envelope, dict) or set(envelope) != {"encoding", "byte_length", "bytes_hex"}:
        raise DenominatorProducerError("denominator:source-envelope")
    try:
        raw = bytes.fromhex(str(envelope["bytes_hex"]))
    except (TypeError, ValueError) as exc:
        raise DenominatorProducerError("denominator:source-envelope") from exc
    if envelope["encoding"] != "canonical-json-ascii-hex" or type(envelope["byte_length"]) is not int or len(raw) != envelope["byte_length"]:
        raise DenominatorProducerError("denominator:source-envelope")
    return raw


def _upstream(
    source_raw: bytes,
    graph_raw: bytes | None,
    governance_raw: bytes,
    registry: Mapping[str, object],
) -> tuple[dict[str, object], dict[str, object], dict[str, object] | None, dict[str, object], dict[str, object], dict[str, object]]:
    try:
        source_value = custody._parse(source_raw)
        source_preview = custody.verify_artifact(source_raw, graph_raw=graph_raw, graph_profile_registry=registry, allow_unresolved_graph=True)
        graph_value = graph._parse(graph_raw) if graph_raw is not None else None
        fhir_result = fhir.verify_bytes(_source_envelope(source_value), profile=profile.NC_MEDICAID_PROFILE)
        gov_value = governance._parse(governance_raw)
        gov_result = governance.verify_bytes(governance_raw, registry)
    except Exception as exc:
        raise DenominatorProducerError("denominator:upstream-reject") from exc
    if gov_result.get("current_stage_kind") != governance.STAGE_APPROVED:
        raise DenominatorProducerError("denominator:governance-not-approved")
    if not gov_result["effective_start"] <= source_value["observation_time"] <= gov_result["effective_end"]:
        raise DenominatorProducerError("denominator:governance-interval")
    return source_value, source_preview, graph_value, fhir_result, gov_value, gov_result


def _governance_binding(value: Mapping[str, object], result: Mapping[str, object]) -> dict[str, object]:
    return {
        "artifact_id": _hex(result["artifact_id"], "governance-artifact"),
        "stage_id": _hex(result["current_stage_id"], "governance-stage"),
        "transition_id": _hex(value["chain_root"], "governance-transition"),
        "profile_id": result["profile_id"],
        "profile_version": result["profile_version"],
        "profile_digest": _hex(result["profile_digest"], "governance-profile-digest"),
        "effective_start": result["effective_start"],
        "effective_end": result["effective_end"],
    }


def _source_binding(value: Mapping[str, object], preview: Mapping[str, object], graph_value: Mapping[str, object] | None) -> dict[str, object]:
    graph_binding = {"graph_artifact_id": None, "graph_stage_id": None, "graph_transition_id": None}
    if graph_value is not None:
        graph_binding = {
            "graph_artifact_id": _hex(graph_value["report"]["report_id"], "graph-artifact"),
            "graph_stage_id": _hex(graph_value["observation_snapshot"]["snapshot_id"], "graph-stage"),
            "graph_transition_id": _hex(graph_value["transition"]["transition_id"], "graph-transition"),
        }
    return {
        "artifact_id": _hex(preview["artifact_id"], "source-artifact"),
        "stage_id": _hex(preview["current_stage_id"], "source-stage"),
        "profile_id": profile.NC_MEDICAID_GRAPH_PROFILE.profile_id,
        "profile_version": profile.NC_MEDICAID_GRAPH_PROFILE.version,
        "profile_digest": _hex(profile.NC_MEDICAID_GRAPH_PROFILE.profile_digest, "graph-profile-digest"),
        "source_profile_id": value["profile_binding"]["source_profile_id"],
        "source_profile_version": value["profile_binding"]["source_profile_version"],
        "source_profile_digest": _hex(profile.NC_MEDICAID_PROFILE.profile_digest, "source-profile-digest"),
        "envelope_digest": _hex(preview["envelope_digest"], "envelope-digest"),
        "snapshot_id": _hex(value["snapshot_id"], "snapshot-id"),
        "snapshot_root": _hex(value["snapshot_root"], "snapshot-root"),
        "source_status": value["source_status"],
        "failure_code": value["failure_code"],
        "freshness": value["freshness"],
        "observation_time": value["observation_time"],
        "fetched_at": value["fetched_at"],
        "page_complete": value["page_complete"],
        "source_completeness": "UNKNOWN",
        "allow_nonmembership": False,
        **graph_binding,
    }


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


def _quality(source_value: Mapping[str, object], result: Mapping[str, object]) -> dict[str, int]:
    status = source_value["source_status"]
    failure = source_value["failure_code"]
    resources = result["resources"]
    quality = {key: 0 for key in SOURCE_QUALITY_KEYS}
    if status != "COMPLETE":
        quality["source_gap"] = 1
    if failure in {"total-drift", "marker-drift"}:
        quality["source_conflict"] = 1
    expected = dict(profile.RESOURCE_CARDINALITY)
    counts = result.get("resource_counts")
    exact_shape = isinstance(counts, dict) and counts == expected and len(resources) == sum(expected.values())
    if resources and (status != "COMPLETE" or not exact_shape):
        quality["malformed_or_unknown"] = 1
    if failure in {"schema", "noncanonical", "forbidden-resource", "capability-mismatch", "profile-downgrade"}:
        quality["malformed_or_unknown"] = 1
    return quality


def _coverage(status: str, quality: Mapping[str, int]) -> str:
    if quality["source_conflict"]:
        return "CONFLICTING_SOURCE_UNKNOWN_DENOMINATOR"
    return {
        "COMPLETE": "COMPLETE_RETURNED_SET_UNKNOWN_DENOMINATOR",
        "PARTIAL": "PARTIAL_SOURCE_UNKNOWN_DENOMINATOR",
        "FAILED": "FAILED_SOURCE_UNKNOWN_DENOMINATOR",
        "STALE": "STALE_SOURCE_UNKNOWN_DENOMINATOR",
    }[status]


def _population(source_value: Mapping[str, object], fhir_result: Mapping[str, object]) -> dict[str, object]:
    leaves = [_record_leaf(unit) for unit in _record_units(fhir_result["resources"])]
    quality = _quality(source_value, fhir_result)
    return {
        "population_root": _population_root(leaves),
        "input_record_count": len(leaves),
        "coverage_status": _coverage(source_value["source_status"], quality),
        "source_quality": quality,
        "source_completeness": "UNKNOWN",
        "allow_nonmembership": False,
    }


def _period_matches(role: Mapping[str, object]) -> bool:
    period = role.get("period")
    if not isinstance(period, dict) or not isinstance(period.get("start"), str) or not isinstance(period.get("end"), str):
        return False
    date = profile.NC_MEDICAID_PROFILE.fetched_at[:10]
    return str(period["start"]) <= date < str(period["end"])


def _decision(resources: Sequence[Mapping[str, object]]) -> tuple[str, str]:
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
    quality = _quality(source_value, fhir_result)
    outcomes: list[dict[str, str]] = []
    for unit in _record_units(fhir_result["resources"]):
        leaf = _record_leaf(unit)
        if quality["source_conflict"]:
            bucket, reason = BUCKET_CONFLICTED, REASON_CONFLICTED
        elif source_value["source_status"] != "COMPLETE" or quality["malformed_or_unknown"]:
            bucket, reason = BUCKET_INVALID, REASON_INVALID
        else:
            bucket, reason = _decision(unit)
        outcomes.append({"leaf": leaf, "bucket": bucket, "reason": reason})
    outcome_counts = {key: 0 for key in BUCKETS}
    reason_counts = {key: 0 for key in REASONS}
    for item in outcomes:
        outcome_counts[item["bucket"]] += 1
        reason_counts[item["reason"]] += 1
    return outcomes, outcome_counts, reason_counts


def _base(source_value: Mapping[str, object], source_preview: Mapping[str, object], graph_value: Mapping[str, object] | None, fhir_result: Mapping[str, object], gov_value: Mapping[str, object], gov_result: Mapping[str, object]) -> dict[str, object]:
    population = _population(source_value, fhir_result)
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "stage_kind": STAGE_BASELINE,
        "profile_binding": _profile_binding(),
        "governance_binding": _governance_binding(gov_value, gov_result),
        "subject": SUBJECT,
        "scope": SCOPE,
        "source_binding": _source_binding(source_value, source_preview, graph_value),
        "population": population,
        "narrowing": None,
        "flags": dict(FIXED_FLAGS),
        "authority": dict(AUTHORITY_FLAGS),
        "prior_artifact_id": None,
        "prior_stage_id": None,
    }


def _identity(value: Mapping[str, object]) -> tuple[str, str, str]:
    body = deepcopy(dict(value))
    for key in ("artifact_id", "current_stage_id", "transition_id"):
        body.pop(key, None)
    artifact_id = _digest("artifact-id", body)
    stage_id = _digest("stage-id", {"artifact_id": artifact_id, "stage_kind": value["stage_kind"], "prior_artifact_id": value["prior_artifact_id"], "prior_stage_id": value["prior_stage_id"], "population_root": value["population"]["population_root"], "outcome_root": value["narrowing"]["outcome_root"] if isinstance(value["narrowing"], dict) else None})
    transition_id = _digest("transition-id", {"artifact_id": artifact_id, "current_stage_id": stage_id, "stage_kind": value["stage_kind"], "prior_artifact_id": value["prior_artifact_id"], "prior_stage_id": value["prior_stage_id"]})
    return artifact_id, stage_id, transition_id


def build_artifact(stage: str, *, source_raw: bytes, graph_raw: bytes | None, governance_raw: bytes, registry: Mapping[str, object], prior_denominator_raw: bytes | None = None) -> bytes:
    if stage not in {STAGE_BASELINE, STAGE_NARROWED}:
        raise DenominatorProducerError("denominator:stage")
    source_value, source_preview, graph_value, fhir_result, gov_value, gov_result = _upstream(source_raw, graph_raw, governance_raw, registry)
    body = _base(source_value, source_preview, graph_value, fhir_result, gov_value, gov_result)
    if stage == STAGE_NARROWED:
        if prior_denominator_raw is None:
            raise DenominatorProducerError("denominator:prior")
        try:
            prior = json.loads(prior_denominator_raw.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DenominatorProducerError("denominator:prior") from exc
        if not isinstance(prior, dict) or prior.get("stage_kind") != STAGE_BASELINE:
            raise DenominatorProducerError("denominator:prior-stage")
        if prior.get("source_binding") != body["source_binding"] or prior.get("governance_binding") != body["governance_binding"] or prior.get("population") != body["population"]:
            raise DenominatorProducerError("denominator:prior-binding")
        outcomes, outcome_counts, reason_counts = _outcomes(source_value, fhir_result)
        retained = [item["leaf"] for item in outcomes if item["bucket"] == BUCKET_RETAINED]
        body["prior_artifact_id"] = prior["artifact_id"]
        body["prior_stage_id"] = prior["current_stage_id"]
        body["stage_kind"] = STAGE_NARROWED
        body["narrowing"] = {
            "rule_binding": _rule_binding(),
            "parent_population_root": prior["population"]["population_root"],
            "child_population_root": _population_root(retained),
            "input_record_count": len(outcomes),
            "outcome_counts": outcome_counts,
            "reason_counts": reason_counts,
            "outcome_root": _digest("outcome-root", {"parent_population_root": prior["population"]["population_root"], "outcomes": sorted(outcomes, key=lambda item: item["leaf"])}),
            "chronology": {"prior_observation_time": source_value["observation_time"], "current_observation_time": source_value["observation_time"], "order": "EQUAL_SOURCE_SNAPSHOT"},
            "coverage_status": prior["population"]["coverage_status"],
            "source_completeness": "UNKNOWN",
            "allow_nonmembership": False,
        }
    artifact_id, stage_id, transition_id = _identity(body)
    raw = _canonical({**body, "artifact_id": artifact_id, "current_stage_id": stage_id, "transition_id": transition_id})
    if len(raw) > 262_144:
        raise DenominatorProducerError("denominator:artifact-byte-cap")
    return raw


class DenominatorLedgerService:
    """Narrow caller-facing facade; selectors are not authority inputs."""

    def __init__(self, continuity_store: object, *, graph_profile_registry: Mapping[str, object] | None = None) -> None:
        self.store = continuity_store
        self.graph_profile_registry = dict(graph_profile_registry or getattr(continuity_store, "graph_profile_registry", {}))

    def create_baseline(self, source_artifact_id: str):
        return self.store.admit_denominator(STAGE_BASELINE, source_artifact_id=source_artifact_id, graph_profile_registry=self.graph_profile_registry)

    def narrow(self, denominator_artifact_id: str):
        return self.store.admit_denominator(STAGE_NARROWED, denominator_artifact_id=denominator_artifact_id, graph_profile_registry=self.graph_profile_registry)


__all__ = ["ARTIFACT_KIND", "DenominatorLedgerService", "DenominatorProducerError", "STAGE_BASELINE", "STAGE_NARROWED", "build_artifact"]
