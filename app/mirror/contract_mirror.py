"""Producer/composition root for the synthetic Contract Mirror V1 seam.

The caller supplies only selectors for stored evidence.  ContinuityStore
loads the bytes and the independent verifier remains the authority for the
obligation, denominator binding, observed result, and case linkage.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import time
from typing import Mapping

from app.mirror import contract_mirror_independent as independent
from app.mirror import denominator_ledger_independent as denominator
from app.mirror import discrepancy_case_independent as case
from app.mirror import source_reconciliation_independent as reconciliation
from app.governance import provider_continuity_control_pack_v2_independent as governance


class ContractMirrorError(ValueError):
    """Stable composition-layer failure."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ContractMirrorError("contract:noncanonical") from exc


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((independent.DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _governance_binding(raw: bytes, registry: Mapping[str, object], profile: Mapping[str, object], subject: Mapping[str, object]) -> dict[str, object]:
    try:
        value = governance._parse(raw)
        result = governance.verify_bytes(raw, registry)
        if value.get("schema") != governance.SCHEMA or result.get("current_stage_kind") != governance.STAGE_APPROVED:
            raise ContractMirrorError("contract:governance-not-approved")
        descriptor = value["profile"]
        if not isinstance(descriptor, dict) or any(descriptor.get(key) != profile[key] for key in ("profile_id", "version", "profile_digest")):
            raise ContractMirrorError("contract:governance-profile")
        if value.get("subject") != {"provider_graph_subject": subject["subject"], "scope": subject["scope"]}:
            raise ContractMirrorError("contract:governance-subject")
    except ContractMirrorError:
        raise
    except Exception as exc:
        raise ContractMirrorError("contract:governance-reject") from exc
    return {
        "artifact_id": result["artifact_id"],
        "stage_id": result["current_stage_id"],
        "transition_id": value["chain_root"],
        "profile_id": result["profile_id"],
        "profile_version": result["profile_version"],
        "profile_digest": result["profile_digest"],
        "effective_start": result["effective_start"],
        "effective_end": result["effective_end"],
    }


def _denominator_binding(value: Mapping[str, object], result: Mapping[str, object]) -> dict[str, object]:
    population = value["population"]
    narrowing = value.get("narrowing")
    if not isinstance(population, dict):
        raise ContractMirrorError("contract:denominator-population")
    narrowing_value = narrowing if isinstance(narrowing, dict) else None
    return {
        "artifact_id": result["artifact_id"],
        "stage_id": result["current_stage_id"],
        "transition_id": result["transition_id"],
        "stage_kind": value["stage_kind"],
        "profile_id": result["profile_id"],
        "profile_version": result["profile_version"],
        "population_root": population["population_root"],
        "child_population_root": narrowing_value["child_population_root"] if narrowing_value is not None else None,
        "input_record_count": population["input_record_count"],
        "outcome_counts": dict(narrowing_value["outcome_counts"]) if narrowing_value is not None else None,
        "outcome_root": narrowing_value["outcome_root"] if narrowing_value is not None else None,
        "coverage_status": population["coverage_status"],
        "source_completeness": "UNKNOWN",
        "allow_nonmembership": False,
    }


def _observation(raw: bytes) -> dict[str, object]:
    value = reconciliation._parse(raw)
    result = value["result"]
    chronology = value["chronology"]
    content = value["source_content"]
    if not all(isinstance(item, dict) for item in (result, chronology, content, value.get("linkage_transition"))):
        raise ContractMirrorError("contract:observation-shape")
    return {
        "reconciliation_artifact_id": value["artifact_id"],
        "reconciliation_stage_id": value["current_stage_id"],
        "reconciliation_transition_id": value["transition_id"],
        "source_observation_status": result["source_observation_status"],
        "linkage_status": value["linkage_transition"]["status"],
        "normalized_content_root": content["current_root"],
        "comparison_content_root": content["comparison_root"],
        "chronology_order": chronology["order"],
        "chronology_prior_marker": chronology["prior_marker"],
        "chronology_current_marker": chronology["current_marker"],
        "source_completeness": "UNKNOWN",
        "allow_nonmembership": False,
    }


def _obligation(governance_binding: Mapping[str, object], subject: Mapping[str, object], boundary: str) -> dict[str, object]:
    return {
        "obligation_id": independent.OBLIGATION_ID,
        "version": independent.OBLIGATION_VERSION,
        "responsible_boundary": boundary,
        "responsibility_profile_id": independent.RESPONSIBILITY_PROFILE_ID,
        "subject": subject["subject"],
        "scope": subject["scope"],
        "effective_start": governance_binding["effective_start"],
        "effective_end": governance_binding["effective_end"],
        "population_definition_id": denominator.PROFILE_ID,
        "population_definition_version": denominator.PROFILE_VERSION,
        "denominator_contract_id": denominator.SCHEMA,
        "denominator_profile_id": denominator.PROFILE_ID,
        "denominator_profile_version": denominator.PROFILE_VERSION,
        "required_observation": {
            "profile_id": reconciliation.RECONCILIATION_CONTRACT_ID,
            "version": reconciliation.RECONCILIATION_CONTRACT_VERSION,
            "expected_result": "RETURNED_PROVIDER_DIRECTORY_OBSERVATION",
            "dimensions": ["source_observation_status", "normalized_content_root", "chronology_order"],
        },
        "permitted_exception": {
            "class_id": independent.EXCEPTION_CLASS_ID,
            "governed_by_control_pack": True,
            "max_duration_seconds": 86_400,
            "may_change_obligation": False,
            "may_authorize_payment": False,
            "synthetic_only": True,
        },
        "remediation_rule": {
            "profile_id": independent.REMEDIATION_PROFILE_ID,
            "retest_profile_id": independent.RETEST_PROFILE_ID,
            "assertion_is_truth": False,
            "full_parity_required_for_resolution": True,
        },
        "governance_artifact_id": governance_binding["artifact_id"],
    }


def _evaluation(denom: Mapping[str, object], observation: Mapping[str, object]) -> dict[str, object]:
    source_status = observation["source_observation_status"]
    if str(denom["coverage_status"]).endswith("UNKNOWN_DENOMINATOR"):
        status, basis = independent.RESULT_INDETERMINATE, "DENOMINATOR_COMPLETENESS_UNKNOWN"
    elif source_status in {reconciliation.STATUS_SOURCE_FAILURE, reconciliation.STATUS_STALE_OR_GAPPED}:
        status, basis = independent.RESULT_UNAVAILABLE, "SOURCE_OBSERVATION_UNAVAILABLE_OR_STALE"
    elif source_status in {reconciliation.STATUS_CONFLICTING, reconciliation.STATUS_NOT_OBSERVED_INCOMPLETE}:
        status, basis = independent.RESULT_INDETERMINATE, "INCOMPLETE_OR_CONFLICTING_OBSERVATION"
    elif source_status == reconciliation.STATUS_OBSERVED_CHANGED:
        status, basis = independent.RESULT_VARIANCE, "CHANGED_VERIFIED_SOURCE_CONTENT"
    else:
        status, basis = independent.RESULT_CONFORMING, "OBSERVED_RETURNED_CONTENT"
    return {
        "status": status,
        "basis": basis,
        "expected_result": "RETURNED_PROVIDER_DIRECTORY_OBSERVATION",
        "observed_result": source_status,
        "dimensions": ["denominator_population", "source_observation_status", "normalized_content_root", "chronology_order"],
        "conformance_claim": False,
        "variance_claim": False,
        "absence_inferred": False,
        "nonmembership_inferred": False,
        "business_truth_proven": False,
    }


def _body(
    stage: str,
    *,
    denominator_raw: bytes,
    case_raw: bytes,
    governance_raw: bytes,
    registry: Mapping[str, object],
    prior_contract_raw: bytes | None,
) -> dict[str, object]:
    denom_value = denominator._parse(denominator_raw)
    denom_result = denominator.verify_artifact(
        denominator_raw,
        source_raw=registry["_contract_source_raw"],
        graph_raw=registry.get("_contract_graph_raw"),
        governance_raw=governance_raw,
        registry=registry,
        prior_denominator_raw=registry.get("_contract_prior_denominator_raw"),
    )
    case_value = case._parse(case_raw)
    upstream = case_value["upstream"]
    graph = upstream["graph"]
    subject = {"subject": case_value["subject"], "scope": case_value["scope"]}
    profile = {"profile_id": graph["profile_id"], "version": graph["profile_version"], "profile_digest": graph["profile_digest"]}
    gov = _governance_binding(governance_raw, registry, profile, subject)
    if denom_value["governance_binding"]["artifact_id"] != gov["artifact_id"]:
        raise ContractMirrorError("contract:denominator-governance")
    if stage == independent.STAGE_RETESTED:
        if prior_contract_raw is None:
            raise ContractMirrorError("contract:prior-required")
        prior = json.loads(prior_contract_raw.decode("ascii"))
        if prior.get("stage_kind") != independent.STAGE_EVALUATED or case_value["lifecycle_state"] not in {case.STAGE_PARITY, case.STAGE_PERSISTS}:
            raise ContractMirrorError("contract:retest-stage")
        observed_raw = registry.get("_contract_retest_reconciliation_raw")
        if not isinstance(observed_raw, bytes):
            raise ContractMirrorError("contract:retest-observation")
    else:
        if stage != independent.STAGE_EVALUATED or prior_contract_raw is not None:
            raise ContractMirrorError("contract:stage-input")
        observed_raw = registry["_contract_reconciliation_raw"]
    observation = _observation(observed_raw)
    if stage == independent.STAGE_EVALUATED and observation["reconciliation_artifact_id"] != upstream["reconciliation"]["artifact_id"]:
        raise ContractMirrorError("contract:case-observation")
    if stage == independent.STAGE_EVALUATED and denom_value["source_binding"]["artifact_id"] != upstream["reconciliation"]["current_custody_artifact_id"]:
        raise ContractMirrorError("contract:denominator-source")
    responsibility = case._responsibility(upstream["finding"]["kind"], observation["source_observation_status"])
    body = {
        "schema": independent.SCHEMA,
        "schema_version": independent.SCHEMA_VERSION,
        "contract_binding": independent._contract_binding(),
        "profile_binding": independent._profile_binding(),
        "governance_binding": gov,
        "obligation": _obligation(gov, subject, responsibility["boundary"]),
        "denominator": _denominator_binding(denom_value, denom_result),
        "observation": observation,
        "case_link": {
            "case_id": case_value["case_id"],
            "artifact_id": case_value["artifact_id"],
            "stage_id": case_value["current_stage_id"],
            "transition_id": case_value["transition_id"],
            "finding_id": upstream["finding"]["finding_id"],
            "lifecycle_state": case_value["lifecycle_state"],
        },
        "evaluation": _evaluation(_denominator_binding(denom_value, denom_result), observation),
        "exception_reference": {
            "status": "NOT_APPLIED",
            "class_id": independent.EXCEPTION_CLASS_ID,
            "governance_artifact_id": gov["artifact_id"],
            "effective_start": None,
            "effective_end": None,
            "changes_obligation": False,
            "payment_authority": False,
            "synthetic_only": True,
        },
        "stage_kind": stage,
        "prior_artifact_id": prior_contract_raw and json.loads(prior_contract_raw.decode("ascii"))["artifact_id"],
        "prior_stage_id": prior_contract_raw and json.loads(prior_contract_raw.decode("ascii"))["current_stage_id"],
        "flags": dict(independent.FIXED_FLAGS),
        "authority": dict(independent.AUTHORITY_FLAGS),
    }
    return body


def build_artifact(
    stage: str,
    *,
    denominator_raw: bytes,
    denominator_context: Mapping[str, object],
    case_raw: bytes,
    case_context: Mapping[str, object],
    registry: Mapping[str, object],
    prior_contract_raw: bytes | None = None,
) -> bytes:
    """Build from store-selected bytes; context is never caller authority."""

    if stage not in independent.STAGES:
        raise ContractMirrorError("contract:stage")
    # The producer keeps its own material construction but receives its bytes
    # through a private context copy so the public registry cannot select them.
    producer_registry = dict(registry)
    producer_registry.update(
        {
            "_contract_source_raw": denominator_context["source_raw"],
            "_contract_graph_raw": denominator_context.get("graph_raw"),
            "_contract_prior_denominator_raw": denominator_context.get("prior_denominator_raw"),
            "_contract_reconciliation_raw": case_context["reconciliation_raw"],
            "_contract_retest_reconciliation_raw": case_context.get("retest_reconciliation_raw"),
        }
    )
    body = _body(
        stage,
        denominator_raw=denominator_raw,
        case_raw=case_raw,
        governance_raw=denominator_context["governance_raw"],
        registry=producer_registry,
        prior_contract_raw=prior_contract_raw,
    )
    artifact_id, stage_id, transition_id = independent._identity_values(body)
    raw = _canonical({**body, "artifact_id": artifact_id, "current_stage_id": stage_id, "transition_id": transition_id})
    if len(raw) > independent.MAX_ARTIFACT_BYTES:
        raise ContractMirrorError("contract:artifact-byte-cap")
    return raw


class ContractMirrorService:
    """Configured facade whose methods accept selectors only."""

    def __init__(self, continuity_store: object, *, graph_profile_registry: Mapping[str, object] | None = None) -> None:
        from app.mirror import continuity_store as store

        if not isinstance(continuity_store, store.ContinuityStore):
            raise ContractMirrorError("composition:store")
        registry = dict(graph_profile_registry or continuity_store.graph_profile_registry)
        if registry != dict(continuity_store.graph_profile_registry):
            raise ContractMirrorError("composition:registry")
        self.store = continuity_store
        self.graph_profile_registry = registry

    def evaluate(self, denominator_artifact_id: str, reconciliation_artifact_id: str, finding_id: str):
        for value, label in ((denominator_artifact_id, "denominator"), (reconciliation_artifact_id, "reconciliation"), (finding_id, "finding")):
            if not isinstance(value, str) or not value:
                raise ContractMirrorError(f"contract:{label}-selector")
        return self._admit(
            independent.STAGE_EVALUATED,
            denominator_artifact_id=denominator_artifact_id,
            reconciliation_artifact_id=reconciliation_artifact_id,
            finding_id=finding_id,
            graph_profile_registry=self.graph_profile_registry,
        )

    def retest(self, contract_artifact_id: str):
        if not isinstance(contract_artifact_id, str) or not contract_artifact_id:
            raise ContractMirrorError("contract:artifact-selector")
        return self._admit(
            independent.STAGE_RETESTED,
            contract_artifact_id=contract_artifact_id,
            graph_profile_registry=self.graph_profile_registry,
        )

    def _admit(self, stage: str, **selectors: str):
        from app.mirror import continuity_store as store

        for attempt in range(3):
            try:
                return self.store.admit_contract(stage, **selectors)
            except store.StoreBusyError:
                if attempt == 2:
                    raise
                time.sleep(0.05 * (attempt + 1))
        raise ContractMirrorError("contract:busy-retry-exhausted")


__all__ = ["ContractMirrorError", "ContractMirrorService", "build_artifact"]
