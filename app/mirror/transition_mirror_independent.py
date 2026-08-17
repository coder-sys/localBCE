"""Independent verifier for the fixed synthetic Transition Mirror V1 profile.

This module is intentionally downstream of the existing independent Transaction,
Contract, Denominator, and Money verifiers.  It owns only the lane-comparison
grammar and reconstructs that comparison from the exact stored upstream bytes.
It is not a cutover, rollback, payment, or business-equivalence authority.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re
from typing import Mapping

from app.mirror import contract_mirror_independent as contract
from app.mirror import denominator_ledger_independent as denominator
from app.mirror import money_mirror_independent as money
from app.mirror import transaction_mirror_independent as transaction


DOMAIN = "BL/MIRROR/TRANSITION-V1/"
ARTIFACT_KIND = "MIRROR_TRANSITION_COMPARISON_V1"
SCHEMA = "mirror-transition-comparison-v1"
SCHEMA_VERSION = 1
PROFILE_ID = "mirror.transition.synthetic-incumbent-challenger.v1"
PROFILE_VERSION = 1
SCOPE = PROFILE_ID
CURRENCY = "USD"
UNIT = "MINOR_UNITS"
LANE_REFERENCE = "INCUMBENT"
LANE_CHALLENGER = "CHALLENGER"
LANE_ORDER = (LANE_REFERENCE, LANE_CHALLENGER)
DIMENSION_INTERFACE = "INTERFACE_SCHEMA_ROLE_CAPABILITY"
DIMENSION_TRANSACTION = "TRANSACTION_LIFECYCLE"
DIMENSION_CONTRACT = "CONTRACT_OBLIGATION"
DIMENSION_DENOMINATOR = "DENOMINATOR_COVERAGE"
DIMENSION_MONEY = "MONEY_OBSERVATION"
DIMENSION_ERROR = "ERROR_PARTIAL_UNKNOWN_BEHAVIOR"
DIMENSIONS = (
    DIMENSION_INTERFACE,
    DIMENSION_TRANSACTION,
    DIMENSION_CONTRACT,
    DIMENSION_DENOMINATOR,
    DIMENSION_MONEY,
    DIMENSION_ERROR,
)
RESULT_MATCHED = "MATCHED"
RESULT_DIVERGENT = "DIVERGENT"
RESULT_PARTIAL = "PARTIAL"
RESULT_UNKNOWN = "UNKNOWN"
RESULT_CONFLICTED = "CONFLICTED"
RESULT_STATUSES = (RESULT_MATCHED, RESULT_DIVERGENT, RESULT_PARTIAL, RESULT_UNKNOWN, RESULT_CONFLICTED)
STAGE_COMPARED = "TRANSITION_COMPARED"
STAGE_RETESTED = "TRANSITION_RETESTED"
FIXTURE_MATCHED = "SYNTH_TRANSITION_MATCHED_V1"
FIXTURE_INTERFACE_DIVERGENT = "SYNTH_TRANSITION_INTERFACE_DIVERGENT_V1"
FIXTURE_TRANSACTION_DIVERGENT = "SYNTH_TRANSITION_TRANSACTION_DIVERGENT_V1"
FIXTURE_CONTRACT_DIVERGENT = "SYNTH_TRANSITION_CONTRACT_DIVERGENT_V1"
FIXTURE_DENOMINATOR_PARTIAL = "SYNTH_TRANSITION_DENOMINATOR_PARTIAL_V1"
FIXTURE_MONEY_DIVERGENT = "SYNTH_TRANSITION_MONEY_DIVERGENT_V1"
FIXTURE_ERROR_UNKNOWN = "SYNTH_TRANSITION_ERROR_UNKNOWN_V1"
FIXTURE_CONFLICTED = "SYNTH_TRANSITION_CONFLICTED_V1"
FIXTURES = (
    FIXTURE_MATCHED,
    FIXTURE_INTERFACE_DIVERGENT,
    FIXTURE_TRANSACTION_DIVERGENT,
    FIXTURE_CONTRACT_DIVERGENT,
    FIXTURE_DENOMINATOR_PARTIAL,
    FIXTURE_MONEY_DIVERGENT,
    FIXTURE_ERROR_UNKNOWN,
    FIXTURE_CONFLICTED,
)
INITIAL_FIXTURES = frozenset(FIXTURES)
RETEST_FIXTURES = frozenset(FIXTURES)
MAX_ARTIFACT_BYTES = 524_288
MAX_DEPTH = 24
MAX_NODES = 2_048
MAX_STRING_BYTES = 512
HEX128 = re.compile(r"^[0-9a-f]{128}$")

AUTHORITY_FLAGS = {
    "automaticControlSetId": None,
    "automatic_enforcement_eligible": False,
    "clearance_authority": False,
    "economic_mutation": False,
    "payment_authority": False,
    "production_usable": False,
    "synthetic_only": True,
    "production_source_authentication": False,
    "proofSuiteId": None,
}
FIXED_FLAGS = {
    "activation": False,
    "business_equivalence_proven": False,
    "business_truth_proven": False,
    "clearance_authority": False,
    "cutover_authority": False,
    "economic_mutation": False,
    "observation_only": True,
    "payment_authority": False,
    "production_usable": False,
    "proofSuiteId": None,
    "read_only": True,
    "rollback_authority": False,
    "synthetic_only": True,
    "winner_selected": False,
}
INTERFACE_MATERIAL = {
    "schema_id": "mirror.transition.synthetic-lane-contract.v1",
    "schema_version": 1,
    "role_order": ["INPUT", "RULE", "TRANSACTION", "CONTRACT", "DENOMINATOR", "MONEY", "ERROR"],
    "capabilities": ["READ_ONLY_OBSERVATION", "CANONICAL_EXPORT", "REPLAY_EVIDENCE", "ROLLBACK_READINESS_EVIDENCE"],
}


class IndependentTransitionMirrorError(ValueError):
    """Raised when a transition artifact or its stored upstream is invalid."""


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _payload_hash(raw: bytes) -> str:
    return _digest("stored-payload", raw.hex())


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IndependentTransitionMirrorError("transition:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, *, depth: int = 0, count: list[int] | None = None) -> None:
    count = count if count is not None else [0]
    count[0] += 1
    if count[0] > MAX_NODES or depth > MAX_DEPTH:
        raise IndependentTransitionMirrorError("transition:resource-cap")
    if isinstance(value, str):
        try:
            if len(value.encode("utf-8")) > MAX_STRING_BYTES:
                raise IndependentTransitionMirrorError("transition:string-cap")
        except UnicodeEncodeError as exc:
            raise IndependentTransitionMirrorError("transition:utf8") from exc
    elif isinstance(value, float):
        raise IndependentTransitionMirrorError("transition:number")
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth=depth + 1, count=count)
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IndependentTransitionMirrorError("transition:key")
            _walk(item, depth=depth + 1, count=count)
    elif not isinstance(value, (str, int, bool)) and value is not None:
        raise IndependentTransitionMirrorError("transition:type")


def _reject_constant(value: str) -> object:
    raise IndependentTransitionMirrorError("transition:constant")


def _parse(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentTransitionMirrorError("transition:byte-cap")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentTransitionMirrorError("transition:json") from exc
    if not isinstance(value, dict):
        raise IndependentTransitionMirrorError("transition:top-level")
    _walk(value)
    if _canonical(value) != raw:
        raise IndependentTransitionMirrorError("transition:noncanonical")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise IndependentTransitionMirrorError(f"transition:{label}")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise IndependentTransitionMirrorError(f"transition:{label}") from exc
    return value


def _hex(value: object, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or HEX128.fullmatch(value) is None:
        raise IndependentTransitionMirrorError(f"transition:{label}")
    return value


def _expect(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise IndependentTransitionMirrorError(f"transition:{label}-keys")
    return value


def _profile_material() -> dict[str, object]:
    return {
        "profile_id": PROFILE_ID,
        "version": PROFILE_VERSION,
        "lane_order": list(LANE_ORDER),
        "dimensions": list(DIMENSIONS),
        "currency": CURRENCY,
        "unit": UNIT,
        "input_contract": "SAME_GOVERNED_INPUTS_AND_CONTROLS_ON_BOTH_LANES",
        "semantics": "READ_ONLY_COMPARISON_NO_WINNER_NO_CUTOVER",
        "fixture_ids": list(FIXTURES),
    }


def _profile_binding() -> dict[str, object]:
    material = _profile_material()
    return {**material, "profile_digest": _digest("profile", material)}


def _copy_keys(value: Mapping[str, object], keys: tuple[str, ...], label: str) -> dict[str, object]:
    try:
        return {key: value[key] for key in keys}
    except (KeyError, TypeError) as exc:
        raise IndependentTransitionMirrorError(f"transition:{label}") from exc


def _upstream(
    money_raw: bytes,
    money_context: Mapping[str, object],
    registry: Mapping[str, object] | None,
) -> dict[str, object]:
    if not isinstance(money_context, Mapping):
        raise IndependentTransitionMirrorError("transition:money-context")
    transaction_raw = money_context.get("transaction_raw")
    transaction_context = money_context.get("transaction_context")
    if type(transaction_raw) is not bytes or not isinstance(transaction_context, Mapping):
        raise IndependentTransitionMirrorError("transition:transaction-context")
    try:
        money_value = money._parse(money_raw)
        transaction_value = transaction._parse(transaction_raw)
        contract_raw = transaction_context["contract_raw"]
        contract_context = transaction_context["contract_context"]
        source_raw = transaction_context["source_raw"]
        observation_raw = transaction_context["observation_raw"]
        if not all(type(item) is bytes for item in (contract_raw, source_raw, observation_raw)):
            raise IndependentTransitionMirrorError("transition:upstream-bytes")
        if not isinstance(contract_context, Mapping):
            raise IndependentTransitionMirrorError("transition:contract-context")
        money_result = money.verify_artifact(
            money_raw,
            transaction_raw=transaction_raw,
            transaction_context=transaction_context,
            prior_money_raw=money_context.get("prior_money_raw"),
            registry=registry or {},
        )
        transaction_result = transaction.verify_trace_artifact(
            transaction_raw,
            source_raw=source_raw,
            contract_raw=contract_raw,
            contract_context=contract_context,
            observation_raw=observation_raw,
            registry=registry or {},
            prior_trace_raw=transaction_context.get("prior_trace_raw"),
            prior_observation_raw=transaction_context.get("prior_observation_raw"),
        )
        contract_value = contract._parse(contract_raw)
        denominator_raw = contract_context["denominator_raw"]
        governance_raw = contract_context["denominator_context"]["governance_raw"]
        if type(denominator_raw) is not bytes:
            raise IndependentTransitionMirrorError("transition:denominator-bytes")
        if type(governance_raw) is not bytes:
            raise IndependentTransitionMirrorError("transition:governance-bytes")
        denominator_value = denominator._parse(denominator_raw)
    except IndependentTransitionMirrorError:
        raise
    except Exception as exc:
        raise IndependentTransitionMirrorError("transition:upstream-reject") from exc
    return {
        "money_raw": money_raw,
        "money_value": money_value,
        "money_result": money_result,
        "transaction_raw": transaction_raw,
        "transaction_value": transaction_value,
        "transaction_result": transaction_result,
        "contract_raw": contract_raw,
        "contract_value": contract_value,
        "denominator_raw": denominator_raw,
        "denominator_value": denominator_value,
        "governance_raw": governance_raw,
    }


def _shared_binding(upstream: Mapping[str, object]) -> dict[str, object]:
    money_value = upstream["money_value"]
    transaction_value = upstream["transaction_value"]
    contract_value = upstream["contract_value"]
    denominator_value = upstream["denominator_value"]
    if not all(isinstance(item, Mapping) for item in (money_value, transaction_value, contract_value, denominator_value)):
        raise IndependentTransitionMirrorError("transition:upstream-shape")
    transaction_binding = money_value["transaction_binding"]
    contract_binding = transaction_binding["contract_binding"]
    governance_binding = contract_value["governance_binding"]
    terms = money_value["terms"]
    chronology = money_value["chronology"]
    input_binding = transaction_value["input_binding"]
    governance = _copy_keys(governance_binding, ("artifact_id", "stage_id", "transition_id", "profile_id", "profile_version", "profile_digest", "effective_start", "effective_end"), "governance-binding")
    governance["payload_hash"] = _payload_hash(upstream["governance_raw"])
    body = {
        "governance": governance,
        "contract": {
            **_copy_keys(contract_binding, ("artifact_id", "contract_digest", "contract_profile_id", "contract_profile_version", "denominator_artifact_id", "denominator_population_root", "denominator_stage_id", "effective_start", "effective_end", "governance_artifact_id", "governance_stage_id", "obligation_id", "obligation_version"), "contract-binding"),
            "stage_id": contract_value["current_stage_id"],
            "transition_id": contract_value["transition_id"],
            "payload_hash": _payload_hash(upstream["contract_raw"]),
        },
        "denominator": _copy_keys(denominator_value["population"], ("population_root", "coverage_status", "input_record_count", "source_completeness", "allow_nonmembership"), "denominator-population"),
        "transaction": {
            "artifact_id": transaction_value["artifact_id"],
            "stage_id": transaction_value["current_stage_id"],
            "transition_id": transaction_value["transition_id"],
            "payload_hash": _payload_hash(upstream["transaction_raw"]),
            "trace_id": transaction_value["trace_id"],
            "source_profile_id": input_binding["source_profile_id"],
            "source_profile_version": input_binding["source_profile_version"],
            "source_status": input_binding["source_status"],
            "source_completeness": input_binding["source_completeness"],
        },
        "money": {
            "artifact_id": money_value["artifact_id"],
            "stage_id": money_value["current_stage_id"],
            "transition_id": money_value["transition_id"],
            "payload_hash": _payload_hash(upstream["money_raw"]),
            "money_trace_id": money_value["money_trace_id"],
            "currency": terms["currency"],
            "overall_status": money_value["comparisons"]["overall"]["status"],
            "event_status": money_value["comparisons"]["event_chain_conservation"]["status"],
            "report_status": money_value["comparisons"]["official_net_vs_report"]["status"],
        },
        "time_window": {
            "effective_start": contract_binding["effective_start"],
            "effective_end": contract_binding["effective_end"],
            "observation_time": transaction_value["chronology"]["source_observation_time"],
            "money_event_times": chronology["event_times"],
            "money_effective_times": chronology["effective_times"],
        },
        "currency": terms["currency"],
        "unit": UNIT,
    }
    body["input_root"] = _digest("input-root", body)
    return body


def _status_from_upstream(upstream: Mapping[str, object]) -> dict[str, str]:
    transaction_value = upstream["transaction_value"]
    contract_value = upstream["contract_value"]
    denominator_value = upstream["denominator_value"]
    money_value = upstream["money_value"]
    phase_statuses = [item["status"] for item in transaction_value["phases"]]
    if "CONFLICTED" in phase_statuses:
        transaction_status = RESULT_CONFLICTED
    elif "GAPPED" in phase_statuses:
        transaction_status = RESULT_PARTIAL
    elif "UNKNOWN" in phase_statuses:
        transaction_status = RESULT_UNKNOWN
    elif transaction_value["divergence"]["status"] == "DIVERGENCE_OBSERVED":
        transaction_status = RESULT_DIVERGENT
    else:
        transaction_status = RESULT_MATCHED
    contract_status = RESULT_MATCHED if contract_value["evaluation"]["status"] == "OBSERVED_CONFORMING" else RESULT_PARTIAL
    denominator_status = RESULT_MATCHED
    if denominator_value["population"]["source_completeness"] != "COMPLETE" or "UNKNOWN" in denominator_value["population"]["coverage_status"]:
        denominator_status = RESULT_PARTIAL
    money_status = money_value["comparisons"]["overall"]["status"]
    error_status = RESULT_MATCHED
    if "CONFLICTED" in phase_statuses:
        error_status = RESULT_CONFLICTED
    elif "GAPPED" in phase_statuses:
        error_status = RESULT_PARTIAL
    elif "UNKNOWN" in phase_statuses:
        error_status = RESULT_UNKNOWN
    return {
        DIMENSION_INTERFACE: RESULT_MATCHED,
        DIMENSION_TRANSACTION: transaction_status,
        DIMENSION_CONTRACT: contract_status,
        DIMENSION_DENOMINATOR: denominator_status,
        DIMENSION_MONEY: money_status,
        DIMENSION_ERROR: error_status,
    }


def _fixture_override(fixture_id: str) -> tuple[str, str] | None:
    return {
        FIXTURE_INTERFACE_DIVERGENT: (DIMENSION_INTERFACE, RESULT_DIVERGENT),
        FIXTURE_TRANSACTION_DIVERGENT: (DIMENSION_TRANSACTION, RESULT_DIVERGENT),
        FIXTURE_CONTRACT_DIVERGENT: (DIMENSION_CONTRACT, RESULT_DIVERGENT),
        FIXTURE_DENOMINATOR_PARTIAL: (DIMENSION_DENOMINATOR, RESULT_PARTIAL),
        FIXTURE_MONEY_DIVERGENT: (DIMENSION_MONEY, RESULT_DIVERGENT),
        FIXTURE_ERROR_UNKNOWN: (DIMENSION_ERROR, RESULT_UNKNOWN),
        FIXTURE_CONFLICTED: (DIMENSION_ERROR, RESULT_CONFLICTED),
    }.get(fixture_id)


def _reason(status: str, *, same: bool) -> str:
    if status == RESULT_MATCHED:
        return "LANE_BOUNDARIES_MATCHED" if same else "LANE_BOUNDARIES_MATCHED_BY_PROFILE"
    if status == RESULT_DIVERGENT:
        return "LANE_OBSERVATIONS_DIVERGE"
    if status == RESULT_PARTIAL:
        return "LANE_EVIDENCE_PARTIAL"
    if status == RESULT_UNKNOWN:
        return "LANE_EVIDENCE_UNKNOWN"
    return "LANE_EVIDENCE_CONFLICTED"


def _compare_status(left: str, right: str) -> str:
    if RESULT_CONFLICTED in (left, right):
        return RESULT_CONFLICTED
    if RESULT_DIVERGENT in (left, right):
        return RESULT_DIVERGENT
    if RESULT_PARTIAL in (left, right):
        return RESULT_PARTIAL
    if RESULT_UNKNOWN in (left, right):
        return RESULT_UNKNOWN
    return RESULT_MATCHED


def _expected_lane_statuses(upstream: Mapping[str, object], fixture_id: str) -> tuple[dict[str, str], dict[str, str]]:
    base = _status_from_upstream(upstream)
    incumbent = dict(base)
    challenger = dict(base)
    override = _fixture_override(fixture_id)
    if override is not None:
        dimension, status = override
        challenger[dimension] = status
    return incumbent, challenger


def _evidence_for(dimension: str, upstream: Mapping[str, object]) -> dict[str, object]:
    if dimension == DIMENSION_INTERFACE:
        return deepcopy(INTERFACE_MATERIAL)
    if dimension == DIMENSION_TRANSACTION:
        value = upstream["transaction_value"]
        return {"artifact_id": value["artifact_id"], "stage_id": value["current_stage_id"], "transition_id": value["transition_id"], "role": "TRANSACTION_TRACE"}
    if dimension == DIMENSION_CONTRACT:
        value = upstream["contract_value"]
        return {"artifact_id": value["artifact_id"], "stage_id": value["current_stage_id"], "transition_id": value["transition_id"], "role": "CONTRACT_MIRROR"}
    if dimension == DIMENSION_DENOMINATOR:
        value = upstream["denominator_value"]
        return {"artifact_id": value["artifact_id"], "stage_id": value["current_stage_id"], "transition_id": value["transition_id"], "role": "DENOMINATOR_LEDGER"}
    value = upstream["money_value"]
    return {"artifact_id": value["artifact_id"], "stage_id": value["current_stage_id"], "transition_id": value["transition_id"], "role": "MONEY_MIRROR"}


def _lanes(upstream: Mapping[str, object], fixture_id: str) -> list[dict[str, object]]:
    incumbent, challenger = _expected_lane_statuses(upstream, fixture_id)
    result: list[dict[str, object]] = []
    for lane_id, statuses in ((LANE_REFERENCE, incumbent), (LANE_CHALLENGER, challenger)):
        result.append(
            {
                "lane_id": lane_id,
                "interface": {"status": statuses[DIMENSION_INTERFACE], "reason": _reason(statuses[DIMENSION_INTERFACE], same=lane_id == LANE_REFERENCE), "evidence": _evidence_for(DIMENSION_INTERFACE, upstream)},
                "transaction": {"status": statuses[DIMENSION_TRANSACTION], "reason": _reason(statuses[DIMENSION_TRANSACTION], same=True), "evidence": _evidence_for(DIMENSION_TRANSACTION, upstream)},
                "contract": {"status": statuses[DIMENSION_CONTRACT], "reason": _reason(statuses[DIMENSION_CONTRACT], same=True), "evidence": _evidence_for(DIMENSION_CONTRACT, upstream)},
                "denominator": {"status": statuses[DIMENSION_DENOMINATOR], "reason": _reason(statuses[DIMENSION_DENOMINATOR], same=True), "evidence": _evidence_for(DIMENSION_DENOMINATOR, upstream)},
                "money": {"status": statuses[DIMENSION_MONEY], "reason": _reason(statuses[DIMENSION_MONEY], same=True), "evidence": _evidence_for(DIMENSION_MONEY, upstream)},
                "error": {"status": statuses[DIMENSION_ERROR], "reason": _reason(statuses[DIMENSION_ERROR], same=True), "evidence": {"boundary": "TRANSITION_MIRROR"}},
            }
        )
    return result


def _comparison(lanes: list[Mapping[str, object]]) -> dict[str, object]:
    dimensions: list[dict[str, object]] = []
    for name, key in zip(DIMENSIONS, ("interface", "transaction", "contract", "denominator", "money", "error")):
        left = lanes[0][key]
        right = lanes[1][key]
        status = _compare_status(left["status"], right["status"])
        dimensions.append({"dimension": name, "incumbent_status": left["status"], "challenger_status": right["status"], "status": status, "reason": _reason(status, same=left["status"] == right["status"])})
    statuses = [item["status"] for item in dimensions]
    overall = RESULT_CONFLICTED if RESULT_CONFLICTED in statuses else RESULT_DIVERGENT if RESULT_DIVERGENT in statuses else RESULT_PARTIAL if RESULT_PARTIAL in statuses else RESULT_UNKNOWN if RESULT_UNKNOWN in statuses else RESULT_MATCHED
    return {
        "dimensions": dimensions,
        "overall": {
            "status": overall,
            "reason": _reason(overall, same=True),
            "winner": None,
            "cutover": "NOT_AUTHORIZED",
            "business_equivalence": False,
            "operational_readiness": "NOT_CLAIMED",
        },
    }


def _case_link(upstream: Mapping[str, object], comparison: Mapping[str, object]) -> dict[str, object] | None:
    if comparison["overall"]["status"] not in {RESULT_DIVERGENT, RESULT_CONFLICTED}:
        return None
    value = upstream["contract_value"].get("case_link")
    return deepcopy(value) if isinstance(value, dict) else None


def _expected_body(upstream: Mapping[str, object], fixture_id: str, prior_value: Mapping[str, object] | None) -> dict[str, object]:
    shared = _shared_binding(upstream)
    lanes = _lanes(upstream, fixture_id)
    comparison = _comparison(lanes)
    case_link = _case_link(upstream, comparison)
    subject = _digest("transition-subject", {"profile_id": PROFILE_ID, "money_trace_id": upstream["money_value"]["money_trace_id"], "input_root": shared["input_root"]})
    prior_id = prior_value["artifact_id"] if prior_value is not None else None
    prior_stage = prior_value["current_stage_id"] if prior_value is not None else None
    body: dict[str, object] = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "profile_binding": _profile_binding(),
        "fixture_id": fixture_id,
        "subject": subject,
        "scope": SCOPE,
        "shared_binding": shared,
        "lanes": lanes,
        "comparison": comparison,
        "parity_history": {
            "status": comparison["overall"]["status"],
            "history_mode": "APPEND_ONLY_OBSERVATION",
            "predecessor_artifact_id": prior_id,
        },
        "responsibility": {
            "status": "OBSERVATION_ONLY",
            "boundary": "UNKNOWN" if comparison["overall"]["status"] != RESULT_MATCHED else "SHARED_OBSERVATION_SCOPE",
            "reason": "DIFFERENCE_REQUIRES_BOUNDARY_REVIEW" if comparison["overall"]["status"] != RESULT_MATCHED else "NO_OPERATIONAL_DIFFERENCE_CLAIMED",
            "blame_claim": False,
            "liability_claim": False,
        },
        "discrepancy": {
            "status": "UNRESOLVED_OBSERVED_DIFFERENCE" if comparison["overall"]["status"] in {RESULT_DIVERGENT, RESULT_CONFLICTED} else "EVIDENCE_PARTIAL" if comparison["overall"]["status"] in {RESULT_PARTIAL, RESULT_UNKNOWN} else "NONE_OBSERVED",
            "reason": "LANE_DIFFERENCE_REQUIRES_EXISTING_CASE_LIFECYCLE" if case_link is not None else "NO_CASE_CREATED_BY_TRANSITION",
            "case_link": case_link,
        },
        "remediation": {
            "status": "NOT_STARTED",
            "owner_boundary": "UNKNOWN",
            "evidence_mode": "NO_REMEDIATION_ASSERTION",
            "case_link": case_link,
        },
        "retest": {
            "status": "EXECUTED" if prior_value is not None else "NOT_REQUESTED",
            "identity": _digest("retest", {"prior_artifact_id": prior_id, "fixture_id": fixture_id, "input_root": shared["input_root"]}) if prior_value is not None else None,
            "prior_artifact_id": prior_id,
            "result_status": comparison["overall"]["status"] if prior_value is not None else None,
        },
        "rollback_evidence": {
            "status": "CHAIN_REPLAYABLE_OBSERVATION",
            "scope": "TRANSITION_ARTIFACT_CHAIN",
            "history_preserved": True,
            "predecessor_bound": prior_value is not None,
            "cutover_authorized": False,
            "rollback_authorized": False,
        },
        "stage_kind": STAGE_RETESTED if prior_value is not None else STAGE_COMPARED,
        "prior_artifact_id": prior_id,
        "prior_stage_id": prior_stage,
        "flags": deepcopy(FIXED_FLAGS),
        "authority": deepcopy(AUTHORITY_FLAGS),
    }
    artifact_id, stage_id, transition_id = _identity_values(body)
    return {**body, "artifact_id": artifact_id, "current_stage_id": stage_id, "transition_id": transition_id}


def _identity_values(value: Mapping[str, object]) -> tuple[str, str, str]:
    body = deepcopy(dict(value))
    body.pop("artifact_id", None)
    body.pop("current_stage_id", None)
    body.pop("transition_id", None)
    artifact_id = _digest("artifact-id", body)
    stage_id = _digest("stage-id", {"artifact_id": artifact_id, "stage_kind": value["stage_kind"], "prior_artifact_id": value["prior_artifact_id"], "prior_stage_id": value["prior_stage_id"]})
    transition_id = _digest("transition-id", {"artifact_id": artifact_id, "current_stage_id": stage_id, "stage_kind": value["stage_kind"], "prior_artifact_id": value["prior_artifact_id"], "prior_stage_id": value["prior_stage_id"]})
    return artifact_id, stage_id, transition_id


def _validate_shape(value: Mapping[str, object]) -> None:
    keys = {"schema", "schema_version", "profile_binding", "fixture_id", "subject", "scope", "shared_binding", "lanes", "comparison", "parity_history", "responsibility", "discrepancy", "remediation", "retest", "rollback_evidence", "stage_kind", "prior_artifact_id", "prior_stage_id", "flags", "authority", "artifact_id", "current_stage_id", "transition_id"}
    if set(value) != keys or value["schema"] != SCHEMA or value["schema_version"] != SCHEMA_VERSION:
        raise IndependentTransitionMirrorError("transition:schema")
    if value["profile_binding"] != _profile_binding():
        raise IndependentTransitionMirrorError("transition:profile-binding")
    if value["fixture_id"] not in FIXTURES:
        raise IndependentTransitionMirrorError("transition:fixture")
    for key in ("subject", "artifact_id", "current_stage_id", "transition_id"):
        _hex(value[key], key)
    if value["scope"] != SCOPE or value["stage_kind"] not in (STAGE_COMPARED, STAGE_RETESTED):
        raise IndependentTransitionMirrorError("transition:scope-stage")
    prior_id = _hex(value["prior_artifact_id"], "prior-artifact", nullable=True)
    prior_stage = _hex(value["prior_stage_id"], "prior-stage", nullable=True)
    if (prior_id is None) != (prior_stage is None):
        raise IndependentTransitionMirrorError("transition:prior-pair")
    if value["flags"] != FIXED_FLAGS or value["authority"] != AUTHORITY_FLAGS:
        raise IndependentTransitionMirrorError("transition:authority")
    lanes = value["lanes"]
    if not isinstance(lanes, list) or len(lanes) != 2 or [item.get("lane_id") for item in lanes if isinstance(item, dict)] != list(LANE_ORDER):
        raise IndependentTransitionMirrorError("transition:lanes")


def _validate_lanes(value: object) -> None:
    if not isinstance(value, list) or len(value) != 2:
        raise IndependentTransitionMirrorError("transition:lane-count")
    for lane in value:
        if not isinstance(lane, dict) or set(lane) != {"lane_id", "interface", "transaction", "contract", "denominator", "money", "error"}:
            raise IndependentTransitionMirrorError("transition:lane-shape")
        for key in ("interface", "transaction", "contract", "denominator", "money", "error"):
            observation = lane[key]
            if not isinstance(observation, dict) or set(observation) != {"status", "reason", "evidence"} or observation["status"] not in RESULT_STATUSES:
                raise IndependentTransitionMirrorError("transition:lane-observation")
            _text(observation["reason"], "lane-reason")
            if not isinstance(observation["evidence"], dict):
                raise IndependentTransitionMirrorError("transition:lane-evidence")


def _validate_value(value: Mapping[str, object], upstream: Mapping[str, object], prior_value: Mapping[str, object] | None) -> None:
    _validate_shape(value)
    _validate_lanes(value["lanes"])
    expected = _expected_body(upstream, value["fixture_id"], prior_value)
    for key in ("subject", "scope", "shared_binding", "lanes", "comparison", "parity_history", "responsibility", "discrepancy", "remediation", "retest", "rollback_evidence", "stage_kind", "prior_artifact_id", "prior_stage_id", "flags", "authority"):
        if value[key] != expected[key]:
            raise IndependentTransitionMirrorError(f"transition:{key}-binding")
    identity = _identity_values(value)
    if (value["artifact_id"], value["current_stage_id"], value["transition_id"]) != identity:
        raise IndependentTransitionMirrorError("transition:identity")


def verify_artifact(
    raw: bytes,
    *,
    money_raw: bytes,
    money_context: Mapping[str, object],
    prior_transition_raw: bytes | None = None,
    registry: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Verify Transition bytes from exact state-selected upstream evidence."""

    value = _parse(raw)
    upstream = _upstream(money_raw, money_context, registry)
    prior_value: Mapping[str, object] | None = None
    if prior_transition_raw is not None:
        prior_value = _parse(prior_transition_raw)
        _validate_value(prior_value, upstream, None)
        if prior_value["stage_kind"] != STAGE_COMPARED:
            raise IndependentTransitionMirrorError("transition:prior-stage")
    if value["stage_kind"] == STAGE_COMPARED and prior_transition_raw is not None:
        raise IndependentTransitionMirrorError("transition:initial-prior")
    if value["stage_kind"] == STAGE_RETESTED and prior_transition_raw is None:
        raise IndependentTransitionMirrorError("transition:retest-prior")
    _validate_value(value, upstream, prior_value)
    return {
        "kind": ARTIFACT_KIND,
        "schema": SCHEMA,
        "artifact_id": value["artifact_id"],
        "payload": raw,
        "payload_hash": _payload_hash(raw),
        "subject": value["subject"],
        "scope": value["scope"],
        "report_id": value["artifact_id"],
        "current_stage_id": value["current_stage_id"],
        "transition_id": value["transition_id"],
        "stage_kind": value["stage_kind"],
        "prior_artifact_id": value["prior_artifact_id"],
        "prior_stage_id": value["prior_stage_id"],
        "authority_json": _canonical(AUTHORITY_FLAGS).decode("ascii"),
        "profile_id": PROFILE_ID,
        "profile_version": PROFILE_VERSION,
        "transition_status": value["comparison"]["overall"]["status"],
        "transition_money_artifact_id": value["shared_binding"]["money"]["artifact_id"],
        "transition_contract_artifact_id": value["shared_binding"]["contract"]["artifact_id"],
        "transition_case_artifact_id": value["discrepancy"]["case_link"]["artifact_id"] if value["discrepancy"]["case_link"] is not None else None,
    }


__all__ = [
    "ARTIFACT_KIND", "AUTHORITY_FLAGS", "CURRENCY", "DIMENSIONS", "FIXED_FLAGS", "FIXTURE_CONFLICTED", "FIXTURE_CONTRACT_DIVERGENT", "FIXTURE_DENOMINATOR_PARTIAL", "FIXTURE_ERROR_UNKNOWN", "FIXTURE_INTERFACE_DIVERGENT", "FIXTURE_MATCHED", "FIXTURE_MONEY_DIVERGENT", "FIXTURE_TRANSACTION_DIVERGENT", "FIXTURES", "INITIAL_FIXTURES", "IndependentTransitionMirrorError", "MAX_ARTIFACT_BYTES", "PROFILE_ID", "PROFILE_VERSION", "RESULT_CONFLICTED", "RESULT_DIVERGENT", "RESULT_MATCHED", "RESULT_PARTIAL", "RESULT_UNKNOWN", "RETEST_FIXTURES", "SCHEMA", "SCHEMA_VERSION", "SCOPE", "STAGE_COMPARED", "STAGE_RETESTED", "UNIT", "_canonical", "_digest", "_identity_values", "_parse", "_payload_hash", "_profile_binding", "verify_artifact",
]
