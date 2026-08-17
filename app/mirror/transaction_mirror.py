"""Composition root for the synthetic Transaction Mirror V1 seam.

The public service accepts only stored-artifact selectors and names of fixed
synthetic fixtures.  It never accepts phase statuses, processor results,
official amounts, report outcomes, divergence flags, or authority booleans.
ContinuityStore selects the actual upstream bytes and performs the atomic
observation-plus-trace admission.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import time
from typing import Mapping

from app.mirror import contract_mirror_independent as contract
from app.mirror import source_evidence_custody_independent as custody
from app.mirror import transaction_mirror_independent as independent


class TransactionMirrorError(ValueError):
    """Stable composition-layer failure."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise TransactionMirrorError("transaction:noncanonical") from exc


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((independent.DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _payload_hash(raw: bytes) -> str:
    return _digest("stored-payload", raw.hex())


def _trace_id(source_raw: bytes, contract_raw: bytes) -> str:
    source_value = custody._parse(source_raw)
    contract_value = contract._parse(contract_raw)
    return _digest(
        "trace-id",
        {
            "profile_id": independent.PROFILE_ID,
            "profile_version": independent.PROFILE_VERSION,
            "source_artifact_id": source_value["artifact_id"],
            "source_stage_id": source_value["current_stage_id"],
            "source_payload_hash": _payload_hash(source_raw),
            "contract_artifact_id": contract_value["artifact_id"],
            "contract_stage_id": contract_value["current_stage_id"],
            "contract_payload_hash": _payload_hash(contract_raw),
        },
    )


def _fixture_evidence(fixture_id: str) -> dict[str, object]:
    if fixture_id not in independent.FIXTURES:
        raise TransactionMirrorError("transaction:fixture")
    processor = {
        "status": independent.STATUS_OBSERVED,
        "reason": "PROCESSOR_BOUNDARY_RESULT_OBSERVED",
        "boundary_id": "SYNTH_PROCESSOR_BOUNDARY_V1",
        "observed_at": 7_010,
        "result_code": "PROCESSOR_ACCEPTED",
        "amount_minor": 12_500,
        "currency": "USD",
    }
    official = {
        "status": independent.STATUS_OBSERVED,
        "reason": "OFFICIAL_STATE_BOUNDARY_RESULT_OBSERVED",
        "boundary_id": "SYNTH_OFFICIAL_STATE_PAYMENT_BOUNDARY_V1",
        "observed_at": 7_020,
        "result_code": "OFFICIAL_OUTCOME_RECORDED",
        "amount_minor": 12_500,
        "currency": "USD",
    }
    report = {
        "status": independent.STATUS_OBSERVED,
        "reason": "OFFICIAL_REPORT_OBSERVED",
        "boundary_id": "SYNTH_OFFICIAL_REPORTING_BOUNDARY_V1",
        "observed_at": 7_030,
        "result_code": "REPORT_MATCHED",
        "amount_minor": 12_500,
        "currency": "USD",
    }
    correction = None
    appeal = None
    if fixture_id == independent.FIXTURE_GAPPED:
        official = {**official, "status": independent.STATUS_GAPPED, "reason": "OFFICIAL_OUTCOME_EVIDENCE_GAPPED", "observed_at": None, "result_code": None, "amount_minor": None, "currency": None}
        report = {**report, "status": independent.STATUS_GAPPED, "reason": "REPORT_DEPENDS_ON_GAPPED_OFFICIAL_OUTCOME", "observed_at": None, "result_code": None, "amount_minor": None, "currency": None}
    elif fixture_id == independent.FIXTURE_MISMATCHED:
        official = {**official, "reason": "OFFICIAL_OUTCOME_DIFFERS_FROM_PROCESSOR", "result_code": "OFFICIAL_OUTCOME_REJECTED", "amount_minor": 0}
        report = {**report, "reason": "REPORT_RECORDS_OFFICIAL_REJECTION", "result_code": "REPORT_REJECTED", "amount_minor": 0}
    elif fixture_id == independent.FIXTURE_CORRECTION:
        correction = {
            "status": independent.STATUS_OBSERVED,
            "reason": "CORRECTION_BOUNDARY_OBSERVED",
            "boundary_id": "SYNTH_OFFICIAL_CORRECTION_BOUNDARY_V1",
            "observed_at": 7_040,
            "result_code": "CORRECTION_APPENDED",
            "amount_minor": 12_500,
            "currency": "USD",
        }
    elif fixture_id == independent.FIXTURE_APPEAL:
        appeal = {
            "status": independent.STATUS_OBSERVED,
            "reason": "APPEAL_BOUNDARY_OBSERVED",
            "boundary_id": "SYNTH_OFFICIAL_APPEAL_BOUNDARY_V1",
            "observed_at": 7_040,
            "result_code": "APPEAL_OPENED",
            "amount_minor": None,
            "currency": None,
        }
    return {"processor": processor, "official": official, "report": report, "correction": correction, "appeal": appeal}


def _observation_stage(fixture_id: str) -> str:
    if fixture_id == independent.FIXTURE_CORRECTION:
        return independent.OBSERVATION_STAGES[1]
    if fixture_id == independent.FIXTURE_APPEAL:
        return independent.OBSERVATION_STAGES[2]
    return independent.OBSERVATION_STAGES[0]


def _trace_stage(fixture_id: str) -> str:
    if fixture_id == independent.FIXTURE_CORRECTION:
        return independent.TRACE_STAGES[1]
    if fixture_id == independent.FIXTURE_APPEAL:
        return independent.TRACE_STAGES[2]
    return independent.TRACE_STAGES[0]


def _source_binding(source_raw: bytes, source_value: Mapping[str, object]) -> dict[str, object]:
    return {
        "artifact_id": source_value["artifact_id"],
        "stage_id": source_value["current_stage_id"],
        "transition_id": source_value["transition_id"],
        "payload_hash": _payload_hash(source_raw),
        "source_profile_id": source_value["profile_binding"]["source_profile_id"],
        "source_profile_version": source_value["profile_binding"]["source_profile_version"],
        "source_status": source_value["source_status"],
        "observation_time": source_value["observation_time"],
        "source_completeness": source_value["source_completeness"],
        "allow_nonmembership": source_value["allow_nonmembership"],
    }


def _contract_binding(contract_raw: bytes, contract_value: Mapping[str, object]) -> dict[str, object]:
    obligation = contract_value["obligation"]
    denominator = contract_value["denominator"]
    governance_value = contract_value["governance_binding"]
    return {
        "artifact_id": contract_value["artifact_id"],
        "stage_id": contract_value["current_stage_id"],
        "transition_id": contract_value["transition_id"],
        "payload_hash": _payload_hash(contract_raw),
        "contract_profile_id": contract_value["profile_binding"]["profile_id"],
        "contract_profile_version": contract_value["profile_binding"]["version"],
        "contract_digest": contract_value["contract_binding"]["contract_digest"],
        "obligation_id": obligation["obligation_id"],
        "obligation_version": obligation["version"],
        "denominator_artifact_id": denominator["artifact_id"],
        "denominator_stage_id": denominator["stage_id"],
        "denominator_population_root": denominator["population_root"],
        "governance_artifact_id": governance_value["artifact_id"],
        "governance_stage_id": governance_value["stage_id"],
        "effective_start": obligation["effective_start"],
        "effective_end": obligation["effective_end"],
    }


def _identity_values(value: Mapping[str, object]) -> tuple[str, str, str]:
    body = deepcopy(dict(value))
    body.pop("artifact_id", None)
    body.pop("current_stage_id", None)
    body.pop("transition_id", None)
    artifact_id = _digest("artifact-id", body)
    stage_id = _digest(
        "stage-id",
        {
            "artifact_id": artifact_id,
            "stage_kind": value["stage_kind"],
            "prior_artifact_id": value["prior_artifact_id"],
            "prior_stage_id": value["prior_stage_id"],
            "trace_id": value["trace_id"],
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


def build_observation_artifact(
    fixture_id: str,
    *,
    source_raw: bytes,
    contract_raw: bytes,
    prior_observation_raw: bytes | None = None,
) -> bytes:
    if fixture_id not in independent.FIXTURES:
        raise TransactionMirrorError("transaction:fixture")
    source_value = custody._parse(source_raw)
    contract_value = contract._parse(contract_raw)
    trace_id = _trace_id(source_raw, contract_raw)
    prior_artifact_id = None
    prior_stage_id = None
    if prior_observation_raw is not None:
        prior_value = independent._parse(prior_observation_raw)
        prior_artifact_id = prior_value["artifact_id"]
        prior_stage_id = prior_value["current_stage_id"]
        if prior_value.get("trace_id") != trace_id:
            raise TransactionMirrorError("transaction:observation-prior")
    body = {
        "schema": independent.OBSERVATION_SCHEMA,
        "schema_version": independent.SCHEMA_VERSION,
        "profile_binding": independent._profile_binding(),
        "trace_id": trace_id,
        "fixture_id": fixture_id,
        "source_binding": _source_binding(source_raw, source_value),
        "contract_binding": _contract_binding(contract_raw, contract_value),
        "evidence": _fixture_evidence(fixture_id),
        "stage_kind": _observation_stage(fixture_id),
        "prior_artifact_id": prior_artifact_id,
        "prior_stage_id": prior_stage_id,
        "flags": dict(independent.FIXED_FLAGS),
        "authority": dict(independent.AUTHORITY_FLAGS),
    }
    artifact_id, stage_id, transition_id = _identity_values(body)
    raw = _canonical({**body, "artifact_id": artifact_id, "current_stage_id": stage_id, "transition_id": transition_id})
    if len(raw) > independent.MAX_ARTIFACT_BYTES:
        raise TransactionMirrorError("transaction:observation-byte-cap")
    return raw


def _phase(name: str, status: str, reason: str, observed_at: int | None, artifact_id: str, stage_id: str, role: str) -> dict[str, object]:
    return {"name": name, "status": status, "reason": reason, "observed_at": observed_at, "evidence": {"artifact_id": artifact_id, "stage_id": stage_id, "role": role}}


def _outcome_signature(value: Mapping[str, object]) -> tuple[object, object, object]:
    """Compare boundary outcome dimensions, not role-specific result labels."""

    return value["status"], value["amount_minor"], value["currency"]


def _expected_trace_material(source_value: Mapping[str, object], contract_value: Mapping[str, object], observation_value: Mapping[str, object]) -> tuple[list[dict[str, object]], dict[str, object], dict[str, object]]:
    source_status = source_value["source_status"]
    input_status = independent.STATUS_OBSERVED if source_status == "COMPLETE" else independent.STATUS_GAPPED
    input_reason = "SOURCE_CUSTODY_ADMITTED" if input_status == independent.STATUS_OBSERVED else "SOURCE_CUSTODY_COVERAGE_GAPPED"
    input_time = source_value["observation_time"] if input_status == independent.STATUS_OBSERVED else None
    observation_id = observation_value["artifact_id"]
    observation_stage = observation_value["current_stage_id"]
    phases = [
        _phase(independent.PHASE_INPUT, input_status, input_reason, input_time, source_value["artifact_id"], source_value["current_stage_id"], "SOURCE_CUSTODY"),
        _phase(independent.PHASE_RULE, independent.STATUS_OBSERVED, "GOVERNED_CONTRACT_BOUND", 7_001, contract_value["artifact_id"], contract_value["current_stage_id"], "CONTRACT_MIRROR"),
    ]
    evidence = observation_value["evidence"]
    phases.extend([
        _phase(independent.PHASE_PROCESSOR, evidence["processor"]["status"], evidence["processor"]["reason"], evidence["processor"]["observed_at"], observation_id, observation_stage, "PROCESSOR"),
        _phase(independent.PHASE_OFFICIAL, evidence["official"]["status"], evidence["official"]["reason"], evidence["official"]["observed_at"], observation_id, observation_stage, "OFFICIAL"),
        _phase(independent.PHASE_REPORT, evidence["report"]["status"], evidence["report"]["reason"], evidence["report"]["observed_at"], observation_id, observation_stage, "REPORT"),
    ])
    if evidence["correction"] is not None:
        phases.append(_phase(independent.PHASE_CORRECTION, evidence["correction"]["status"], evidence["correction"]["reason"], evidence["correction"]["observed_at"], observation_id, observation_stage, "CORRECTION"))
    if evidence["appeal"] is not None:
        phases.append(_phase(independent.PHASE_APPEAL, evidence["appeal"]["status"], evidence["appeal"]["reason"], evidence["appeal"]["observed_at"], observation_id, observation_stage, "APPEAL"))
    chronology = {
        "source_observation_time": source_value["observation_time"],
        "effective_start": contract_value["obligation"]["effective_start"],
        "effective_end": contract_value["obligation"]["effective_end"],
        "observed_times": [item["observed_at"] for item in phases if item["observed_at"] is not None],
    }
    processor = evidence["processor"]
    official = evidence["official"]
    report = evidence["report"]
    if official["status"] != independent.STATUS_OBSERVED or report["status"] != independent.STATUS_OBSERVED:
        divergence = {"status": independent.DIVERGENCE_UNKNOWN, "reason": "OFFICIAL_OR_REPORT_EVIDENCE_MISSING", "dimensions": ["processor_vs_official", "official_vs_report"]}
    else:
        dimensions = []
        if _outcome_signature(processor) != _outcome_signature(official):
            dimensions.append("processor_vs_official")
        if _outcome_signature(official) != _outcome_signature(report):
            dimensions.append("official_vs_report")
        divergence = {
            "status": independent.DIVERGENCE_OBSERVED if dimensions else independent.DIVERGENCE_NONE,
            "reason": "BOUNDARY_RESULTS_DIFFER" if dimensions else "BOUNDARY_RESULTS_MATCHED",
            "dimensions": dimensions,
        }
    return phases, chronology, divergence


def build_trace_artifact(
    *,
    source_raw: bytes,
    contract_raw: bytes,
    observation_raw: bytes,
    prior_trace_raw: bytes | None = None,
) -> bytes:
    source_value = custody._parse(source_raw)
    contract_value = contract._parse(contract_raw)
    observation_value = independent._parse(observation_raw)
    trace_id = _trace_id(source_raw, contract_raw)
    if observation_value.get("trace_id") != trace_id:
        raise TransactionMirrorError("transaction:trace-observation")
    prior_artifact_id = None
    prior_stage_id = None
    if prior_trace_raw is not None:
        prior_value = independent._parse(prior_trace_raw)
        prior_artifact_id = prior_value["artifact_id"]
        prior_stage_id = prior_value["current_stage_id"]
        if prior_value.get("trace_id") != trace_id:
            raise TransactionMirrorError("transaction:trace-prior")
    phases, chronology, divergence = _expected_trace_material(source_value, contract_value, observation_value)
    case_link = None
    if divergence["status"] == independent.DIVERGENCE_OBSERVED:
        case_link = dict(contract_value["case_link"])
    body = {
        "schema": independent.TRACE_SCHEMA,
        "schema_version": independent.SCHEMA_VERSION,
        "profile_binding": independent._profile_binding(),
        "trace_id": trace_id,
        "contract_binding": _contract_binding(contract_raw, contract_value),
        "input_binding": _source_binding(source_raw, source_value),
        "observation_binding": {
            "artifact_id": observation_value["artifact_id"],
            "stage_id": observation_value["current_stage_id"],
            "transition_id": observation_value["transition_id"],
            "payload_hash": _payload_hash(observation_raw),
            "fixture_id": observation_value["fixture_id"],
        },
        "phases": phases,
        "chronology": chronology,
        "divergence": divergence,
        "case_link": case_link,
        "stage_kind": _trace_stage(observation_value["fixture_id"]),
        "prior_artifact_id": prior_artifact_id,
        "prior_stage_id": prior_stage_id,
        "flags": dict(independent.FIXED_FLAGS),
        "authority": dict(independent.AUTHORITY_FLAGS),
    }
    artifact_id, stage_id, transition_id = _identity_values(body)
    raw = _canonical({**body, "artifact_id": artifact_id, "current_stage_id": stage_id, "transition_id": transition_id})
    if len(raw) > independent.MAX_ARTIFACT_BYTES:
        raise TransactionMirrorError("transaction:trace-byte-cap")
    return raw


class TransactionMirrorService:
    """Configured facade accepting selectors and fixed synthetic fixture names."""

    def __init__(self, continuity_store: object, *, graph_profile_registry: Mapping[str, object] | None = None) -> None:
        from app.mirror import continuity_store as store

        if not isinstance(continuity_store, store.ContinuityStore):
            raise TransactionMirrorError("composition:store")
        registry = dict(graph_profile_registry or continuity_store.graph_profile_registry)
        if registry != dict(continuity_store.graph_profile_registry):
            raise TransactionMirrorError("composition:registry")
        self.store = continuity_store
        self.graph_profile_registry = registry

    def trace(self, contract_artifact_id: str, *, fixture_id: str = independent.FIXTURE_FULL):
        if not isinstance(contract_artifact_id, str) or not contract_artifact_id:
            raise TransactionMirrorError("transaction:contract-selector")
        if fixture_id not in independent.FIXTURES[:3]:
            raise TransactionMirrorError("transaction:initial-fixture")
        return self._admit("TRACE_INITIAL", contract_artifact_id=contract_artifact_id, fixture_id=fixture_id, graph_profile_registry=self.graph_profile_registry)

    def correct(self, trace_artifact_id: str):
        if not isinstance(trace_artifact_id, str) or not trace_artifact_id:
            raise TransactionMirrorError("transaction:trace-selector")
        return self._admit("TRACE_CORRECTION", trace_artifact_id=trace_artifact_id, fixture_id=independent.FIXTURE_CORRECTION, graph_profile_registry=self.graph_profile_registry)

    def appeal(self, trace_artifact_id: str):
        if not isinstance(trace_artifact_id, str) or not trace_artifact_id:
            raise TransactionMirrorError("transaction:trace-selector")
        return self._admit("TRACE_APPEAL", trace_artifact_id=trace_artifact_id, fixture_id=independent.FIXTURE_APPEAL, graph_profile_registry=self.graph_profile_registry)

    def _admit(self, action: str, **selectors: str):
        from app.mirror import continuity_store as store

        for attempt in range(3):
            try:
                return self.store.admit_transaction(action, **selectors)
            except store.StoreBusyError:
                if attempt == 2:
                    raise
                time.sleep(0.05 * (attempt + 1))
        raise TransactionMirrorError("transaction:busy-retry-exhausted")


__all__ = [
    "TransactionMirrorError", "TransactionMirrorService", "build_observation_artifact", "build_trace_artifact",
]
