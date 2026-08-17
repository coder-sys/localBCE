"""Independent verifier for the synthetic Transaction Mirror V1 seam.

This module owns only the transaction trace grammar and its phase/divergence
binding.  Source custody, Contract Mirror, governance, and discrepancy-case
meaning remain in their existing independent owners.  Boundary observations
are fixed synthetic fixtures; a caller cannot provide a processor result,
official outcome, amount, currency, or phase status.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re
from typing import Mapping

from app.mirror import contract_mirror_independent as contract
from app.mirror import source_evidence_custody_independent as custody


OBSERVATION_ARTIFACT_KIND = "MIRROR_TRANSACTION_OBSERVATION_V1"
TRACE_ARTIFACT_KIND = "MIRROR_TRANSACTION_TRACE_V1"
OBSERVATION_SCHEMA = "mirror-transaction-observation-v1"
TRACE_SCHEMA = "mirror-transaction-trace-v1"
SCHEMA_VERSION = 1
OBSERVATION_STAGE_KIND = "TRANSACTION_BOUNDARY_OBSERVATION"
TRACE_STAGE_KIND = "TRANSACTION_TRACE"
DOMAIN = "BL/MIRROR/TRANSACTION/"
MAX_ARTIFACT_BYTES = 262_144
MAX_STRING_BYTES = 8_192
HEX128 = re.compile(r"^[0-9a-f]{128}$")

PROFILE_ID = "mirror.transaction.synthetic-processor-official-trace.v1"
PROFILE_VERSION = 1

PHASE_INPUT = "INPUT_OBSERVED"
PHASE_RULE = "GOVERNING_RULE_BOUND"
PHASE_PROCESSOR = "PROCESSOR_RESULT_OBSERVED"
PHASE_OFFICIAL = "OFFICIAL_OUTCOME_OBSERVED"
PHASE_REPORT = "REPORT_OBSERVED"
PHASE_CORRECTION = "CORRECTION"
PHASE_APPEAL = "APPEAL"
BASE_PHASES = (PHASE_INPUT, PHASE_RULE, PHASE_PROCESSOR, PHASE_OFFICIAL, PHASE_REPORT)
OPTIONAL_PHASES = (PHASE_CORRECTION, PHASE_APPEAL)

STATUS_OBSERVED = "OBSERVED"
STATUS_UNKNOWN = "UNKNOWN"
STATUS_GAPPED = "GAPPED"
STATUS_CONFLICTED = "CONFLICTED"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"
PHASE_STATUSES = (STATUS_OBSERVED, STATUS_UNKNOWN, STATUS_GAPPED, STATUS_CONFLICTED, STATUS_NOT_APPLICABLE)

DIVERGENCE_NONE = "NONE_OBSERVED"
DIVERGENCE_OBSERVED = "DIVERGENCE_OBSERVED"
DIVERGENCE_UNKNOWN = "DIVERGENCE_UNKNOWN"
DIVERGENCE_STATUSES = (DIVERGENCE_NONE, DIVERGENCE_OBSERVED, DIVERGENCE_UNKNOWN)

FIXTURE_FULL = "SYNTHETIC_FULL_TRACE_V1"
FIXTURE_GAPPED = "SYNTHETIC_GAPPED_OFFICIAL_TRACE_V1"
FIXTURE_MISMATCHED = "SYNTHETIC_MISMATCHED_OFFICIAL_TRACE_V1"
FIXTURE_CORRECTION = "SYNTHETIC_CORRECTION_TRACE_V1"
FIXTURE_APPEAL = "SYNTHETIC_APPEAL_TRACE_V1"
FIXTURES = (FIXTURE_FULL, FIXTURE_GAPPED, FIXTURE_MISMATCHED, FIXTURE_CORRECTION, FIXTURE_APPEAL)

OBSERVATION_STAGES = ("OBSERVATION_CAPTURED", "OBSERVATION_CORRECTED", "OBSERVATION_APPEALED")
TRACE_STAGES = ("TRACE_OBSERVED", "TRACE_CORRECTED", "TRACE_APPEALED")

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
    "read_only": True,
    "observation_only": True,
    "processor_authority": False,
    "official_outcome_authority": False,
    "payment_movement": False,
    "reporting_authority": False,
    "business_truth_proven": False,
    "legal_determination": False,
    "production_usable": False,
    "synthetic_only": True,
    "activation": False,
    "clearance_authority": False,
    "payment_authority": False,
    "economic_mutation": False,
    "proofSuiteId": None,
}

OBSERVATION_KEYS = {
    "schema", "schema_version", "profile_binding", "trace_id", "fixture_id",
    "source_binding", "contract_binding", "evidence", "stage_kind",
    "prior_artifact_id", "prior_stage_id", "flags", "authority",
    "artifact_id", "current_stage_id", "transition_id",
}
TRACE_KEYS = {
    "schema", "schema_version", "profile_binding", "trace_id", "contract_binding",
    "input_binding", "observation_binding", "phases", "chronology", "divergence",
    "case_link", "stage_kind", "prior_artifact_id", "prior_stage_id", "flags",
    "authority", "artifact_id", "current_stage_id", "transition_id",
}
PROFILE_KEYS = {"profile_id", "version", "profile_digest"}
SOURCE_BINDING_KEYS = {"artifact_id", "stage_id", "transition_id", "payload_hash", "source_profile_id", "source_profile_version", "source_status", "observation_time", "source_completeness", "allow_nonmembership"}
CONTRACT_BINDING_KEYS = {
    "artifact_id", "stage_id", "transition_id", "payload_hash", "contract_profile_id",
    "contract_profile_version", "contract_digest", "obligation_id", "obligation_version",
    "denominator_artifact_id", "denominator_stage_id", "denominator_population_root",
    "governance_artifact_id", "governance_stage_id", "effective_start", "effective_end",
}
EVIDENCE_KEYS = {"processor", "official", "report", "correction", "appeal"}
EVIDENCE_ITEM_KEYS = {"status", "reason", "boundary_id", "observed_at", "result_code", "amount_minor", "currency"}
PHASE_KEYS = {"name", "status", "reason", "observed_at", "evidence"}
PHASE_EVIDENCE_KEYS = {"artifact_id", "stage_id", "role"}
CHRONOLOGY_KEYS = {"source_observation_time", "effective_start", "effective_end", "observed_times"}
DIVERGENCE_KEYS = {"status", "reason", "dimensions"}
CASE_LINK_KEYS = {"case_id", "artifact_id", "stage_id", "transition_id", "finding_id", "lifecycle_state"}

_HEX_FIELDS = {
    "artifact_id", "current_stage_id", "transition_id", "prior_artifact_id", "prior_stage_id",
    "trace_id", "profile_digest", "payload_hash", "stage_id", "transition_id",
    "contract_artifact_id", "contract_stage_id", "contract_transition_id", "source_artifact_id",
}


class IndependentTransactionMirrorError(ValueError):
    """Stable fail-closed rejection from the independent transaction verifier."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise IndependentTransactionMirrorError("transaction:noncanonical") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IndependentTransactionMirrorError("transaction:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, *, depth: int = 0, count: list[int] | None = None) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if count[0] > 16_384:
        raise IndependentTransactionMirrorError("transaction:node-cap")
    if depth > 24:
        raise IndependentTransactionMirrorError("transaction:depth-cap")
    if isinstance(value, float):
        raise IndependentTransactionMirrorError("transaction:float")
    if isinstance(value, str):
        try:
            if len(value.encode("ascii")) > MAX_STRING_BYTES:
                raise IndependentTransactionMirrorError("transaction:string-cap")
        except UnicodeEncodeError as exc:
            raise IndependentTransactionMirrorError("transaction:ascii") from exc
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IndependentTransactionMirrorError("transaction:key-type")
            _walk(key, depth=depth + 1, count=count)
            _walk(item, depth=depth + 1, count=count)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth=depth + 1, count=count)


def _parse(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentTransactionMirrorError("transaction:byte-cap")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(IndependentTransactionMirrorError("transaction:constant")),
        )
    except IndependentTransactionMirrorError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentTransactionMirrorError("transaction:parse") from exc
    if not isinstance(value, dict):
        raise IndependentTransactionMirrorError("transaction:top-level")
    _walk(value)
    if _canonical(value) != raw:
        raise IndependentTransactionMirrorError("transaction:not-canonical")
    return value


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _payload_hash(raw: bytes) -> str:
    return _digest("stored-payload", raw.hex())


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise IndependentTransactionMirrorError(f"transaction:{label}")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise IndependentTransactionMirrorError(f"transaction:{label}") from exc
    return value


def _hex(value: object, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or HEX128.fullmatch(value) is None:
        raise IndependentTransactionMirrorError(f"transaction:{label}")
    return value


def _expect(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise IndependentTransactionMirrorError(f"transaction:{label}-keys")
    return value


def _int(value: object, label: str, *, minimum: int = 0, maximum: int = 90_000) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise IndependentTransactionMirrorError(f"transaction:{label}")
    return value


def _profile_binding() -> dict[str, object]:
    material = {
        "profile_id": PROFILE_ID,
        "version": PROFILE_VERSION,
        "base_phases": list(BASE_PHASES),
        "optional_phases": list(OPTIONAL_PHASES),
        "phase_statuses": list(PHASE_STATUSES),
        "divergence_statuses": list(DIVERGENCE_STATUSES),
        "fixture_ids": list(FIXTURES),
        "amount_semantics": "OBSERVATION_ONLY_BOUNDARY_VALUE",
        "payment_semantics": "NO_PAYMENT_MUTATION",
    }
    return {**material, "profile_digest": _digest("profile", material)}


def _fixture_evidence(fixture_id: str) -> dict[str, object]:
    if fixture_id not in FIXTURES:
        raise IndependentTransactionMirrorError("transaction:fixture")
    processor = {
        "status": STATUS_OBSERVED,
        "reason": "PROCESSOR_BOUNDARY_RESULT_OBSERVED",
        "boundary_id": "SYNTH_PROCESSOR_BOUNDARY_V1",
        "observed_at": 7_010,
        "result_code": "PROCESSOR_ACCEPTED",
        "amount_minor": 12_500,
        "currency": "USD",
    }
    official = {
        "status": STATUS_OBSERVED,
        "reason": "OFFICIAL_STATE_BOUNDARY_RESULT_OBSERVED",
        "boundary_id": "SYNTH_OFFICIAL_STATE_PAYMENT_BOUNDARY_V1",
        "observed_at": 7_020,
        "result_code": "OFFICIAL_OUTCOME_RECORDED",
        "amount_minor": 12_500,
        "currency": "USD",
    }
    report = {
        "status": STATUS_OBSERVED,
        "reason": "OFFICIAL_REPORT_OBSERVED",
        "boundary_id": "SYNTH_OFFICIAL_REPORTING_BOUNDARY_V1",
        "observed_at": 7_030,
        "result_code": "REPORT_MATCHED",
        "amount_minor": 12_500,
        "currency": "USD",
    }
    correction = None
    appeal = None
    if fixture_id == FIXTURE_GAPPED:
        official = {**official, "status": STATUS_GAPPED, "reason": "OFFICIAL_OUTCOME_EVIDENCE_GAPPED", "observed_at": None, "result_code": None, "amount_minor": None, "currency": None}
        report = {**report, "status": STATUS_GAPPED, "reason": "REPORT_DEPENDS_ON_GAPPED_OFFICIAL_OUTCOME", "observed_at": None, "result_code": None, "amount_minor": None, "currency": None}
    elif fixture_id == FIXTURE_MISMATCHED:
        official = {**official, "reason": "OFFICIAL_OUTCOME_DIFFERS_FROM_PROCESSOR", "result_code": "OFFICIAL_OUTCOME_REJECTED", "amount_minor": 0}
        report = {**report, "reason": "REPORT_RECORDS_OFFICIAL_REJECTION", "result_code": "REPORT_REJECTED", "amount_minor": 0}
    elif fixture_id == FIXTURE_CORRECTION:
        correction = {
            "status": STATUS_OBSERVED,
            "reason": "CORRECTION_BOUNDARY_OBSERVED",
            "boundary_id": "SYNTH_OFFICIAL_CORRECTION_BOUNDARY_V1",
            "observed_at": 7_040,
            "result_code": "CORRECTION_APPENDED",
            "amount_minor": 12_500,
            "currency": "USD",
        }
    elif fixture_id == FIXTURE_APPEAL:
        appeal = {
            "status": STATUS_OBSERVED,
            "reason": "APPEAL_BOUNDARY_OBSERVED",
            "boundary_id": "SYNTH_OFFICIAL_APPEAL_BOUNDARY_V1",
            "observed_at": 7_040,
            "result_code": "APPEAL_OPENED",
            "amount_minor": None,
            "currency": None,
        }
    return {"processor": processor, "official": official, "report": report, "correction": correction, "appeal": appeal}


def _expected_observation_stage(fixture_id: str) -> str:
    if fixture_id == FIXTURE_CORRECTION:
        return OBSERVATION_STAGES[1]
    if fixture_id == FIXTURE_APPEAL:
        return OBSERVATION_STAGES[2]
    return OBSERVATION_STAGES[0]


def _expected_trace_stage(fixture_id: str) -> str:
    if fixture_id == FIXTURE_CORRECTION:
        return TRACE_STAGES[1]
    if fixture_id == FIXTURE_APPEAL:
        return TRACE_STAGES[2]
    return TRACE_STAGES[0]


def trace_id_for(*, source_raw: bytes, contract_raw: bytes) -> str:
    source_value = custody._parse(source_raw)
    contract_value = contract._parse(contract_raw)
    material = {
        "profile_id": PROFILE_ID,
        "profile_version": PROFILE_VERSION,
        "source_artifact_id": source_value["artifact_id"],
        "source_stage_id": source_value["current_stage_id"],
        "source_payload_hash": _payload_hash(source_raw),
        "contract_artifact_id": contract_value["artifact_id"],
        "contract_stage_id": contract_value["current_stage_id"],
        "contract_payload_hash": _payload_hash(contract_raw),
    }
    return _digest("trace-id", material)


def _verify_upstream(
    *,
    source_raw: bytes,
    contract_raw: bytes,
    contract_context: Mapping[str, object],
    registry: Mapping[str, object],
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    try:
        source_value = custody._parse(source_raw)
        source_graph_raw = contract_context.get("denominator_context", {}).get("graph_raw")
        source_result = custody.verify_artifact(source_raw, graph_raw=source_graph_raw, graph_profile_registry=registry)
        contract_value = contract._parse(contract_raw)
        contract_result = contract.verify_artifact(
            contract_raw,
            denominator_raw=contract_context["denominator_raw"],
            denominator_context=contract_context["denominator_context"],
            case_raw=contract_context["case_raw"],
            case_context=contract_context["case_context"],
            registry=registry,
            prior_contract_raw=contract_context.get("prior_contract_raw"),
        )
    except IndependentTransactionMirrorError:
        raise
    except Exception as exc:
        raise IndependentTransactionMirrorError("transaction:upstream-reject") from exc
    denominator_value = contract._parse(contract_context["denominator_raw"])
    if denominator_value["source_binding"]["artifact_id"] != source_value["artifact_id"]:
        raise IndependentTransactionMirrorError("transaction:source-binding")
    if contract_result["denominator_artifact_id"] != denominator_value["artifact_id"]:
        raise IndependentTransactionMirrorError("transaction:contract-denominator")
    return source_value, contract_value, contract_result


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


def _validate_profile(value: Mapping[str, object]) -> None:
    if value != _profile_binding():
        raise IndependentTransactionMirrorError("transaction:profile-binding")


def _validate_evidence_item(value: object, label: str) -> dict[str, object]:
    item = _expect(value, EVIDENCE_ITEM_KEYS, label)
    if item["status"] not in PHASE_STATUSES:
        raise IndependentTransactionMirrorError(f"transaction:{label}-status")
    _text(item["reason"], f"{label}-reason")
    _text(item["boundary_id"], f"{label}-boundary")
    observed_at = item["observed_at"]
    if observed_at is not None:
        _int(observed_at, f"{label}-time")
    for key in ("result_code", "currency"):
        if item[key] is not None:
            _text(item[key], f"{label}-{key}")
    if item["amount_minor"] is not None:
        _int(item["amount_minor"], f"{label}-amount")
    if item["status"] in {STATUS_OBSERVED, STATUS_CONFLICTED} and item["observed_at"] is None:
        raise IndependentTransactionMirrorError(f"transaction:{label}-observed-time")
    if item["status"] != STATUS_OBSERVED and item["result_code"] is not None:
        raise IndependentTransactionMirrorError(f"transaction:{label}-nonobserved-result")
    return item


def _validate_binding(value: Mapping[str, object], keys: set[str], label: str) -> None:
    item = _expect(value, keys, label)
    hex_keys = {
        "artifact_id", "stage_id", "transition_id", "payload_hash", "denominator_population_root",
        "governance_artifact_id", "governance_stage_id",
    }
    for key in hex_keys:
        if key in item:
            _hex(item[key], f"{label}-{key}")
    for key in ("source_profile_id", "contract_profile_id", "contract_digest", "obligation_id", "source_status", "source_completeness"):
        if key in item:
            _text(item[key], f"{label}-{key}")
    for key in ("source_profile_version", "contract_profile_version", "obligation_version", "effective_start", "effective_end", "observation_time"):
        if key in item:
            _int(item[key], f"{label}-{key}", minimum=1)


def _validate_observation_shape(value: Mapping[str, object]) -> None:
    if set(value) != OBSERVATION_KEYS or value.get("schema") != OBSERVATION_SCHEMA or value.get("schema_version") != SCHEMA_VERSION:
        raise IndependentTransactionMirrorError("transaction:observation-schema")
    _validate_profile(_expect(value["profile_binding"], set(_profile_binding()), "observation-profile"))
    _hex(value["trace_id"], "observation-trace-id")
    _text(value["fixture_id"], "observation-fixture")
    if value["fixture_id"] not in FIXTURES:
        raise IndependentTransactionMirrorError("transaction:observation-fixture")
    _validate_binding(value["source_binding"], SOURCE_BINDING_KEYS, "observation-source")
    _validate_binding(value["contract_binding"], CONTRACT_BINDING_KEYS, "observation-contract")
    evidence = _expect(value["evidence"], EVIDENCE_KEYS, "observation-evidence")
    for key in EVIDENCE_KEYS:
        if evidence[key] is not None:
            _validate_evidence_item(evidence[key], f"observation-{key}")
    expected = _fixture_evidence(value["fixture_id"])
    if evidence != expected:
        raise IndependentTransactionMirrorError("transaction:observation-fixture-binding")
    if value["stage_kind"] not in OBSERVATION_STAGES:
        raise IndependentTransactionMirrorError("transaction:observation-stage")
    if value["stage_kind"] != _expected_observation_stage(value["fixture_id"]):
        raise IndependentTransactionMirrorError("transaction:observation-stage-binding")
    _hex(value["artifact_id"], "observation-artifact-id")
    _hex(value["current_stage_id"], "observation-stage-id")
    _hex(value["transition_id"], "observation-transition-id")
    _hex(value["prior_artifact_id"], "observation-prior-artifact", nullable=True)
    _hex(value["prior_stage_id"], "observation-prior-stage", nullable=True)
    if (value["prior_artifact_id"] is None) != (value["prior_stage_id"] is None):
        raise IndependentTransactionMirrorError("transaction:observation-prior-pair")
    if value["fixture_id"] in {FIXTURE_FULL, FIXTURE_GAPPED, FIXTURE_MISMATCHED} and value["prior_artifact_id"] is not None:
        raise IndependentTransactionMirrorError("transaction:observation-initial-prior")
    if value["fixture_id"] in {FIXTURE_CORRECTION, FIXTURE_APPEAL} and value["prior_artifact_id"] is None:
        raise IndependentTransactionMirrorError("transaction:observation-transition-prior")
    if value["flags"] != FIXED_FLAGS or value["authority"] != AUTHORITY_FLAGS:
        raise IndependentTransactionMirrorError("transaction:observation-authority")


def _phase(name: str, status: str, reason: str, observed_at: int | None, artifact_id: str, stage_id: str, role: str) -> dict[str, object]:
    return {
        "name": name,
        "status": status,
        "reason": reason,
        "observed_at": observed_at,
        "evidence": {"artifact_id": artifact_id, "stage_id": stage_id, "role": role},
    }


def _outcome_signature(value: Mapping[str, object]) -> tuple[object, object, object]:
    """Compare boundary outcome dimensions, not role-specific result labels."""

    return value["status"], value["amount_minor"], value["currency"]


def _expected_phases(
    *,
    source_value: Mapping[str, object],
    contract_value: Mapping[str, object],
    observation_value: Mapping[str, object],
) -> tuple[list[dict[str, object]], dict[str, object], dict[str, object]]:
    source_status = source_value["source_status"]
    input_status = STATUS_OBSERVED if source_status == "COMPLETE" else STATUS_GAPPED
    input_reason = "SOURCE_CUSTODY_ADMITTED" if input_status == STATUS_OBSERVED else "SOURCE_CUSTODY_COVERAGE_GAPPED"
    input_time = source_value["observation_time"] if input_status == STATUS_OBSERVED else None
    observation_id = observation_value["artifact_id"]
    observation_stage = observation_value["current_stage_id"]
    phases = [
        _phase(PHASE_INPUT, input_status, input_reason, input_time, source_value["artifact_id"], source_value["current_stage_id"], "SOURCE_CUSTODY"),
        _phase(PHASE_RULE, STATUS_OBSERVED, "GOVERNED_CONTRACT_BOUND", 7_001, contract_value["artifact_id"], contract_value["current_stage_id"], "CONTRACT_MIRROR"),
    ]
    evidence = observation_value["evidence"]
    phases.extend([
        _phase(PHASE_PROCESSOR, evidence["processor"]["status"], evidence["processor"]["reason"], evidence["processor"]["observed_at"], observation_id, observation_stage, "PROCESSOR"),
        _phase(PHASE_OFFICIAL, evidence["official"]["status"], evidence["official"]["reason"], evidence["official"]["observed_at"], observation_id, observation_stage, "OFFICIAL"),
        _phase(PHASE_REPORT, evidence["report"]["status"], evidence["report"]["reason"], evidence["report"]["observed_at"], observation_id, observation_stage, "REPORT"),
    ])
    if evidence["correction"] is not None:
        phases.append(_phase(PHASE_CORRECTION, evidence["correction"]["status"], evidence["correction"]["reason"], evidence["correction"]["observed_at"], observation_id, observation_stage, "CORRECTION"))
    if evidence["appeal"] is not None:
        phases.append(_phase(PHASE_APPEAL, evidence["appeal"]["status"], evidence["appeal"]["reason"], evidence["appeal"]["observed_at"], observation_id, observation_stage, "APPEAL"))
    effective_start = contract_value["obligation"]["effective_start"]
    effective_end = contract_value["obligation"]["effective_end"]
    observed_times = [item["observed_at"] for item in phases if item["observed_at"] is not None]
    chronology = {
        "source_observation_time": source_value["observation_time"],
        "effective_start": effective_start,
        "effective_end": effective_end,
        "observed_times": observed_times,
    }
    official = evidence["official"]
    processor = evidence["processor"]
    report = evidence["report"]
    if official["status"] != STATUS_OBSERVED or report["status"] != STATUS_OBSERVED:
        divergence = {"status": DIVERGENCE_UNKNOWN, "reason": "OFFICIAL_OR_REPORT_EVIDENCE_MISSING", "dimensions": ["processor_vs_official", "official_vs_report"]}
    else:
        dimensions = []
        if _outcome_signature(processor) != _outcome_signature(official):
            dimensions.append("processor_vs_official")
        if _outcome_signature(official) != _outcome_signature(report):
            dimensions.append("official_vs_report")
        divergence = {
            "status": DIVERGENCE_OBSERVED if dimensions else DIVERGENCE_NONE,
            "reason": "BOUNDARY_RESULTS_DIFFER" if dimensions else "BOUNDARY_RESULTS_MATCHED",
            "dimensions": dimensions,
        }
    return phases, chronology, divergence


def _validate_phases(value: object, *, source_value: Mapping[str, object], contract_value: Mapping[str, object], observation_value: Mapping[str, object]) -> tuple[list[dict[str, object]], dict[str, object], dict[str, object]]:
    if not isinstance(value, list) or len(value) not in (len(BASE_PHASES), len(BASE_PHASES) + 1):
        raise IndependentTransactionMirrorError("transaction:phases")
    for item in value:
        phase = _expect(item, PHASE_KEYS, "transaction-phase")
        if phase["name"] not in BASE_PHASES + OPTIONAL_PHASES or phase["status"] not in PHASE_STATUSES:
            raise IndependentTransactionMirrorError("transaction:phase-value")
        _text(phase["reason"], "transaction-phase-reason")
        if phase["observed_at"] is not None:
            _int(phase["observed_at"], "transaction-phase-time")
        evidence = _expect(phase["evidence"], PHASE_EVIDENCE_KEYS, "transaction-phase-evidence")
        _hex(evidence["artifact_id"], "transaction-phase-artifact")
        _hex(evidence["stage_id"], "transaction-phase-stage")
        _text(evidence["role"], "transaction-phase-role")
    expected = _expected_phases(source_value=source_value, contract_value=contract_value, observation_value=observation_value)
    if value != expected[0]:
        raise IndependentTransactionMirrorError("transaction:phase-binding")
    return expected


def _validate_observation_upstream(
    raw: bytes,
    *,
    source_raw: bytes,
    contract_raw: bytes,
    contract_context: Mapping[str, object],
    registry: Mapping[str, object],
    prior_observation_raw: bytes | None,
) -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]:
    value = _parse(raw)
    _validate_observation_shape(value)
    source_value, contract_value, contract_result = _verify_upstream(source_raw=source_raw, contract_raw=contract_raw, contract_context=contract_context, registry=registry)
    expected_trace_id = trace_id_for(source_raw=source_raw, contract_raw=contract_raw)
    if value["trace_id"] != expected_trace_id:
        raise IndependentTransactionMirrorError("transaction:trace-id")
    source_binding = _source_binding(source_raw, source_value)
    contract_binding = _contract_binding(contract_raw, contract_value)
    if value["source_binding"] != source_binding or value["contract_binding"] != contract_binding:
        raise IndependentTransactionMirrorError("transaction:observation-upstream-binding")
    if value["fixture_id"] in {FIXTURE_CORRECTION, FIXTURE_APPEAL}:
        if prior_observation_raw is None:
            raise IndependentTransactionMirrorError("transaction:observation-prior-missing")
        prior = _parse(prior_observation_raw)
        _validate_observation_shape(prior)
        if prior["trace_id"] != value["trace_id"] or prior["fixture_id"] not in {FIXTURE_FULL, FIXTURE_MISMATCHED, FIXTURE_CORRECTION}:
            raise IndependentTransactionMirrorError("transaction:observation-prior-binding")
        prior_identity = _identity_values(prior)
        if (prior["artifact_id"], prior["current_stage_id"], prior["transition_id"]) != prior_identity:
            raise IndependentTransactionMirrorError("transaction:observation-prior-identity")
        if value["fixture_id"] == FIXTURE_CORRECTION and prior["fixture_id"] != FIXTURE_FULL:
            raise IndependentTransactionMirrorError("transaction:correction-prior")
        if value["fixture_id"] == FIXTURE_APPEAL and prior["fixture_id"] not in {FIXTURE_FULL, FIXTURE_CORRECTION}:
            raise IndependentTransactionMirrorError("transaction:appeal-prior")
        if prior["current_stage_id"] != value["prior_stage_id"] or prior["artifact_id"] != value["prior_artifact_id"]:
            raise IndependentTransactionMirrorError("transaction:observation-prior-identity")
    elif prior_observation_raw is not None:
        raise IndependentTransactionMirrorError("transaction:observation-unexpected-prior")
    return value, source_value, contract_value, contract_result


def verify_observation_artifact(
    raw: bytes,
    *,
    source_raw: bytes,
    contract_raw: bytes,
    contract_context: Mapping[str, object],
    registry: Mapping[str, object],
    prior_observation_raw: bytes | None = None,
) -> dict[str, object]:
    value, source_value, contract_value, contract_result = _validate_observation_upstream(
        raw,
        source_raw=source_raw,
        contract_raw=contract_raw,
        contract_context=contract_context,
        registry=registry,
        prior_observation_raw=prior_observation_raw,
    )
    artifact_id, stage_id, transition_id = _identity_values(value)
    if (value["artifact_id"], value["current_stage_id"], value["transition_id"]) != (artifact_id, stage_id, transition_id):
        raise IndependentTransactionMirrorError("transaction:observation-identity")
    return {
        "kind": OBSERVATION_ARTIFACT_KIND,
        "schema": OBSERVATION_SCHEMA,
        "artifact_id": value["artifact_id"],
        "payload": raw,
        "payload_hash": _payload_hash(raw),
        "subject": value["trace_id"],
        "scope": PROFILE_ID,
        "report_id": value["trace_id"],
        "current_stage_id": value["current_stage_id"],
        "transition_id": value["transition_id"],
        "stage_kind": OBSERVATION_STAGE_KIND,
        "prior_artifact_id": value["prior_artifact_id"],
        "prior_stage_id": value["prior_stage_id"],
        "authority_json": _canonical(AUTHORITY_FLAGS).decode("ascii"),
        "profile_id": PROFILE_ID,
        "profile_version": PROFILE_VERSION,
        "fixture_id": value["fixture_id"],
        "trace_id": value["trace_id"],
        "source_artifact_id": source_value["artifact_id"],
        "contract_artifact_id": contract_result["artifact_id"],
    }


def _validate_trace_shape(value: Mapping[str, object]) -> None:
    if set(value) != TRACE_KEYS or value.get("schema") != TRACE_SCHEMA or value.get("schema_version") != SCHEMA_VERSION:
        raise IndependentTransactionMirrorError("transaction:trace-schema")
    _validate_profile(_expect(value["profile_binding"], set(_profile_binding()), "trace-profile"))
    _hex(value["trace_id"], "trace-id")
    _validate_binding(value["contract_binding"], CONTRACT_BINDING_KEYS, "trace-contract")
    _validate_binding(value["input_binding"], SOURCE_BINDING_KEYS, "trace-input")
    observation = _expect(value["observation_binding"], {"artifact_id", "stage_id", "transition_id", "payload_hash", "fixture_id"}, "trace-observation")
    for key in ("artifact_id", "stage_id", "transition_id", "payload_hash"):
        _hex(observation[key], f"trace-observation-{key}")
    _text(observation["fixture_id"], "trace-observation-fixture")
    chronology = _expect(value["chronology"], CHRONOLOGY_KEYS, "trace-chronology")
    for key in ("source_observation_time", "effective_start", "effective_end"):
        _int(chronology[key], f"trace-chronology-{key}", minimum=1)
    if not isinstance(chronology["observed_times"], list) or any(type(item) is not int for item in chronology["observed_times"]):
        raise IndependentTransactionMirrorError("transaction:chronology-times")
    divergence = _expect(value["divergence"], DIVERGENCE_KEYS, "trace-divergence")
    if divergence["status"] not in DIVERGENCE_STATUSES or not isinstance(divergence["dimensions"], list) or any(item not in {"processor_vs_official", "official_vs_report"} for item in divergence["dimensions"]) or len(set(divergence["dimensions"])) != len(divergence["dimensions"]):
        raise IndependentTransactionMirrorError("transaction:divergence")
    _text(divergence["reason"], "transaction:divergence-reason")
    case_link = value["case_link"]
    if case_link is not None:
        case_value = _expect(case_link, CASE_LINK_KEYS, "trace-case")
        for key in ("case_id", "artifact_id", "stage_id", "transition_id", "finding_id"):
            _hex(case_value[key], f"trace-case-{key}")
        _text(case_value["lifecycle_state"], "trace-case-state")
    if value["stage_kind"] not in TRACE_STAGES:
        raise IndependentTransactionMirrorError("transaction:trace-stage")
    _hex(value["artifact_id"], "trace-artifact-id")
    _hex(value["current_stage_id"], "trace-stage-id")
    _hex(value["transition_id"], "trace-transition-id")
    _hex(value["prior_artifact_id"], "trace-prior-artifact", nullable=True)
    _hex(value["prior_stage_id"], "trace-prior-stage", nullable=True)
    if (value["prior_artifact_id"] is None) != (value["prior_stage_id"] is None):
        raise IndependentTransactionMirrorError("transaction:trace-prior-pair")
    if value["flags"] != FIXED_FLAGS or value["authority"] != AUTHORITY_FLAGS:
        raise IndependentTransactionMirrorError("transaction:trace-authority")


def _expected_case_link(contract_value: Mapping[str, object], divergence: Mapping[str, object]) -> dict[str, object] | None:
    if divergence["status"] != DIVERGENCE_OBSERVED:
        return None
    case_link = contract_value.get("case_link")
    if not isinstance(case_link, dict) or set(case_link) != contract.CASE_LINK_KEYS:
        raise IndependentTransactionMirrorError("transaction:case-link")
    return dict(case_link)


def _validate_trace_upstream(
    raw: bytes,
    *,
    source_raw: bytes,
    contract_raw: bytes,
    contract_context: Mapping[str, object],
    observation_raw: bytes,
    registry: Mapping[str, object],
    prior_trace_raw: bytes | None,
    prior_observation_raw: bytes | None,
) -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object], dict[str, object]]:
    value = _parse(raw)
    _validate_trace_shape(value)
    observation_value, source_value, contract_value, contract_result = _validate_observation_upstream(
        observation_raw,
        source_raw=source_raw,
        contract_raw=contract_raw,
        contract_context=contract_context,
        registry=registry,
        prior_observation_raw=prior_observation_raw,
    )
    expected_trace_id = trace_id_for(source_raw=source_raw, contract_raw=contract_raw)
    if value["trace_id"] != expected_trace_id or observation_value["trace_id"] != expected_trace_id:
        raise IndependentTransactionMirrorError("transaction:trace-id")
    if value["observation_binding"] != {
        "artifact_id": observation_value["artifact_id"],
        "stage_id": observation_value["current_stage_id"],
        "transition_id": observation_value["transition_id"],
        "payload_hash": _payload_hash(observation_raw),
        "fixture_id": observation_value["fixture_id"],
    }:
        raise IndependentTransactionMirrorError("transaction:observation-binding")
    if value["contract_binding"] != _contract_binding(contract_raw, contract_value) or value["input_binding"] != _source_binding(source_raw, source_value):
        raise IndependentTransactionMirrorError("transaction:trace-upstream-binding")
    phases, chronology, divergence = _validate_phases(
        value["phases"], source_value=source_value, contract_value=contract_value, observation_value=observation_value
    )
    if value["chronology"] != chronology or value["divergence"] != divergence:
        raise IndependentTransactionMirrorError("transaction:derived-binding")
    if chronology["observed_times"] != sorted(chronology["observed_times"]) or len(set(chronology["observed_times"])) != len(chronology["observed_times"]):
        raise IndependentTransactionMirrorError("transaction:chronology-order")
    if chronology["source_observation_time"] < chronology["effective_start"] or chronology["source_observation_time"] >= chronology["effective_end"]:
        raise IndependentTransactionMirrorError("transaction:source-chronology-interval")
    if any(item < chronology["effective_start"] or item >= chronology["effective_end"] for item in chronology["observed_times"]):
        raise IndependentTransactionMirrorError("transaction:chronology-interval")
    expected_case = _expected_case_link(contract_value, divergence)
    if value["case_link"] != expected_case:
        raise IndependentTransactionMirrorError("transaction:case-binding")
    if value["stage_kind"] != _expected_trace_stage(observation_value["fixture_id"]):
        raise IndependentTransactionMirrorError("transaction:trace-stage-binding")
    if observation_value["fixture_id"] in {FIXTURE_CORRECTION, FIXTURE_APPEAL}:
        if prior_trace_raw is None:
            raise IndependentTransactionMirrorError("transaction:trace-prior-missing")
        prior = _parse(prior_trace_raw)
        _validate_trace_shape(prior)
        if prior["trace_id"] != value["trace_id"] or prior["current_stage_id"] != value["prior_stage_id"] or prior["artifact_id"] != value["prior_artifact_id"]:
            raise IndependentTransactionMirrorError("transaction:trace-prior-binding")
        prior_identity = _identity_values(prior)
        if (prior["artifact_id"], prior["current_stage_id"], prior["transition_id"]) != prior_identity:
            raise IndependentTransactionMirrorError("transaction:trace-prior-identity")
        if prior_observation_raw is None:
            raise IndependentTransactionMirrorError("transaction:trace-prior-observation-missing")
        prior_observation = _parse(prior_observation_raw)
        _validate_observation_shape(prior_observation)
        if prior["observation_binding"] != {
            "artifact_id": prior_observation["artifact_id"],
            "stage_id": prior_observation["current_stage_id"],
            "transition_id": prior_observation["transition_id"],
            "payload_hash": _payload_hash(prior_observation_raw),
            "fixture_id": prior_observation["fixture_id"],
        } or prior["stage_kind"] != _expected_trace_stage(prior_observation["fixture_id"]):
            raise IndependentTransactionMirrorError("transaction:trace-prior-observation-binding")
        if observation_value["fixture_id"] == FIXTURE_CORRECTION and prior["stage_kind"] != TRACE_STAGES[0]:
            raise IndependentTransactionMirrorError("transaction:correction-trace-prior")
        if observation_value["fixture_id"] == FIXTURE_APPEAL and prior["stage_kind"] not in {TRACE_STAGES[0], TRACE_STAGES[1]}:
            raise IndependentTransactionMirrorError("transaction:appeal-trace-prior")
    elif prior_trace_raw is not None:
        raise IndependentTransactionMirrorError("transaction:trace-unexpected-prior")
    return value, source_value, contract_value, contract_result, observation_value


def verify_trace_artifact(
    raw: bytes,
    *,
    source_raw: bytes,
    contract_raw: bytes,
    contract_context: Mapping[str, object],
    observation_raw: bytes,
    registry: Mapping[str, object],
    prior_trace_raw: bytes | None = None,
    prior_observation_raw: bytes | None = None,
) -> dict[str, object]:
    value, source_value, contract_value, contract_result, observation_value = _validate_trace_upstream(
        raw,
        source_raw=source_raw,
        contract_raw=contract_raw,
        contract_context=contract_context,
        observation_raw=observation_raw,
        registry=registry,
        prior_trace_raw=prior_trace_raw,
        prior_observation_raw=prior_observation_raw,
    )
    artifact_id, stage_id, transition_id = _identity_values(value)
    if (value["artifact_id"], value["current_stage_id"], value["transition_id"]) != (artifact_id, stage_id, transition_id):
        raise IndependentTransactionMirrorError("transaction:trace-identity")
    return {
        "kind": TRACE_ARTIFACT_KIND,
        "schema": TRACE_SCHEMA,
        "artifact_id": value["artifact_id"],
        "payload": raw,
        "payload_hash": _payload_hash(raw),
        "subject": value["trace_id"],
        "scope": PROFILE_ID,
        "report_id": value["trace_id"],
        "current_stage_id": value["current_stage_id"],
        "transition_id": value["transition_id"],
        "stage_kind": TRACE_STAGE_KIND,
        "prior_artifact_id": value["prior_artifact_id"],
        "prior_stage_id": value["prior_stage_id"],
        "authority_json": _canonical(AUTHORITY_FLAGS).decode("ascii"),
        "profile_id": PROFILE_ID,
        "profile_version": PROFILE_VERSION,
        "trace_stage": value["stage_kind"],
        "trace_id": value["trace_id"],
        "observation_artifact_id": observation_value["artifact_id"],
        "contract_artifact_id": contract_result["artifact_id"],
        "divergence_status": value["divergence"]["status"],
        "case_artifact_id": value["case_link"]["artifact_id"] if value["case_link"] is not None else None,
    }


__all__ = [
    "AUTHORITY_FLAGS", "BASE_PHASES", "DIVERGENCE_NONE", "DIVERGENCE_OBSERVED", "DIVERGENCE_UNKNOWN",
    "FIXTURE_APPEAL", "FIXTURE_CORRECTION", "FIXTURE_FULL", "FIXTURE_GAPPED", "FIXTURE_MISMATCHED", "FIXTURES",
    "FIXED_FLAGS", "IndependentTransactionMirrorError", "MAX_ARTIFACT_BYTES", "OBSERVATION_ARTIFACT_KIND",
    "OBSERVATION_SCHEMA", "OBSERVATION_STAGE_KIND", "PROFILE_ID", "PROFILE_VERSION", "PHASE_APPEAL",
    "PHASE_CORRECTION", "PHASE_INPUT", "PHASE_OFFICIAL", "PHASE_PROCESSOR", "PHASE_REPORT", "PHASE_RULE",
    "PHASE_STATUSES", "SCHEMA_VERSION", "TRACE_ARTIFACT_KIND", "TRACE_SCHEMA", "TRACE_STAGE_KIND",
    "TRACE_STAGES", "_canonical", "_digest", "_identity_values", "_parse", "_payload_hash", "_profile_binding",
    "trace_id_for", "verify_observation_artifact", "verify_trace_artifact",
]
