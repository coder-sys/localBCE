"""Producer-side fixed synthetic Transition Mirror V1 seam.

Callers can select a stored Money observation and a named synthetic fixture only.
The ContinuityStore supplies the upstream bytes and performs independent
verification before durable admission.
"""

from __future__ import annotations

from copy import deepcopy
import time
from typing import Mapping

from app.mirror import contract_mirror_independent as contract
from app.mirror import denominator_ledger_independent as denominator
from app.mirror import money_mirror_independent as money
from app.mirror import transaction_mirror_independent as transaction
from app.mirror import transition_mirror_independent as independent


class TransitionMirrorError(ValueError):
    """Raised for selector or producer-side construction failures."""


def _upstream(money_raw: bytes, money_context: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(money_context, Mapping):
        raise TransitionMirrorError("transition:money-context")
    transaction_raw = money_context.get("transaction_raw")
    transaction_context = money_context.get("transaction_context")
    if type(transaction_raw) is not bytes or not isinstance(transaction_context, Mapping):
        raise TransitionMirrorError("transition:transaction-context")
    try:
        money_value = money._parse(money_raw)
        transaction_value = transaction._parse(transaction_raw)
        contract_raw = transaction_context["contract_raw"]
        contract_context = transaction_context["contract_context"]
        if not all(type(item) is bytes for item in (contract_raw, transaction_context["source_raw"], transaction_context["observation_raw"])):
            raise TransitionMirrorError("transition:upstream-bytes")
        contract_value = contract._parse(contract_raw)
        denominator_raw = contract_context["denominator_raw"]
        governance_raw = contract_context["denominator_context"]["governance_raw"]
        denominator_value = denominator._parse(denominator_raw)
    except TransitionMirrorError:
        raise
    except Exception as exc:
        raise TransitionMirrorError("transition:upstream-shape") from exc
    return {
        "money_raw": money_raw,
        "money_value": money_value,
        "transaction_raw": transaction_raw,
        "transaction_value": transaction_value,
        "contract_raw": contract_raw,
        "contract_value": contract_value,
        "denominator_raw": denominator_raw,
        "denominator_value": denominator_value,
        "governance_raw": governance_raw,
    }


def _copy_keys(value: Mapping[str, object], keys: tuple[str, ...], label: str) -> dict[str, object]:
    try:
        return {key: value[key] for key in keys}
    except (KeyError, TypeError) as exc:
        raise TransitionMirrorError(f"transition:{label}") from exc


def _shared_binding(upstream: Mapping[str, object]) -> dict[str, object]:
    money_value = upstream["money_value"]
    transaction_value = upstream["transaction_value"]
    contract_value = upstream["contract_value"]
    denominator_value = upstream["denominator_value"]
    transaction_binding = money_value["transaction_binding"]
    contract_binding = transaction_binding["contract_binding"]
    governance_binding = contract_value["governance_binding"]
    terms = money_value["terms"]
    chronology = money_value["chronology"]
    input_binding = transaction_value["input_binding"]
    governance = _copy_keys(governance_binding, ("artifact_id", "stage_id", "transition_id", "profile_id", "profile_version", "profile_digest", "effective_start", "effective_end"), "governance-binding")
    governance["payload_hash"] = independent._payload_hash(upstream["governance_raw"])
    body: dict[str, object] = {
        "governance": governance,
        "contract": {
            **_copy_keys(contract_binding, ("artifact_id", "contract_digest", "contract_profile_id", "contract_profile_version", "denominator_artifact_id", "denominator_population_root", "denominator_stage_id", "effective_start", "effective_end", "governance_artifact_id", "governance_stage_id", "obligation_id", "obligation_version"), "contract-binding"),
            "stage_id": contract_value["current_stage_id"],
            "transition_id": contract_value["transition_id"],
            "payload_hash": independent._payload_hash(upstream["contract_raw"]),
        },
        "denominator": _copy_keys(denominator_value["population"], ("population_root", "coverage_status", "input_record_count", "source_completeness", "allow_nonmembership"), "denominator-population"),
        "transaction": {
            "artifact_id": transaction_value["artifact_id"],
            "stage_id": transaction_value["current_stage_id"],
            "transition_id": transaction_value["transition_id"],
            "payload_hash": independent._payload_hash(upstream["transaction_raw"]),
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
            "payload_hash": independent._payload_hash(upstream["money_raw"]),
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
        "unit": independent.UNIT,
    }
    body["input_root"] = independent._digest("input-root", body)
    return body


def _base_statuses(upstream: Mapping[str, object]) -> dict[str, str]:
    transaction_value = upstream["transaction_value"]
    contract_value = upstream["contract_value"]
    denominator_value = upstream["denominator_value"]
    money_value = upstream["money_value"]
    phase_statuses = [item["status"] for item in transaction_value["phases"]]
    if "CONFLICTED" in phase_statuses:
        transaction_status = independent.RESULT_CONFLICTED
    elif "GAPPED" in phase_statuses:
        transaction_status = independent.RESULT_PARTIAL
    elif "UNKNOWN" in phase_statuses:
        transaction_status = independent.RESULT_UNKNOWN
    elif transaction_value["divergence"]["status"] == "DIVERGENCE_OBSERVED":
        transaction_status = independent.RESULT_DIVERGENT
    else:
        transaction_status = independent.RESULT_MATCHED
    contract_status = independent.RESULT_MATCHED if contract_value["evaluation"]["status"] == "OBSERVED_CONFORMING" else independent.RESULT_PARTIAL
    denominator_status = independent.RESULT_MATCHED
    if denominator_value["population"]["source_completeness"] != "COMPLETE" or "UNKNOWN" in denominator_value["population"]["coverage_status"]:
        denominator_status = independent.RESULT_PARTIAL
    money_status = money_value["comparisons"]["overall"]["status"]
    error_status = independent.RESULT_MATCHED
    if "CONFLICTED" in phase_statuses:
        error_status = independent.RESULT_CONFLICTED
    elif "GAPPED" in phase_statuses:
        error_status = independent.RESULT_PARTIAL
    elif "UNKNOWN" in phase_statuses:
        error_status = independent.RESULT_UNKNOWN
    return {
        independent.DIMENSION_INTERFACE: independent.RESULT_MATCHED,
        independent.DIMENSION_TRANSACTION: transaction_status,
        independent.DIMENSION_CONTRACT: contract_status,
        independent.DIMENSION_DENOMINATOR: denominator_status,
        independent.DIMENSION_MONEY: money_status,
        independent.DIMENSION_ERROR: error_status,
    }


def _override(fixture_id: str) -> tuple[str, str] | None:
    return {
        independent.FIXTURE_INTERFACE_DIVERGENT: (independent.DIMENSION_INTERFACE, independent.RESULT_DIVERGENT),
        independent.FIXTURE_TRANSACTION_DIVERGENT: (independent.DIMENSION_TRANSACTION, independent.RESULT_DIVERGENT),
        independent.FIXTURE_CONTRACT_DIVERGENT: (independent.DIMENSION_CONTRACT, independent.RESULT_DIVERGENT),
        independent.FIXTURE_DENOMINATOR_PARTIAL: (independent.DIMENSION_DENOMINATOR, independent.RESULT_PARTIAL),
        independent.FIXTURE_MONEY_DIVERGENT: (independent.DIMENSION_MONEY, independent.RESULT_DIVERGENT),
        independent.FIXTURE_ERROR_UNKNOWN: (independent.DIMENSION_ERROR, independent.RESULT_UNKNOWN),
        independent.FIXTURE_CONFLICTED: (independent.DIMENSION_ERROR, independent.RESULT_CONFLICTED),
    }.get(fixture_id)


def _reason(status: str, same: bool) -> str:
    if status == independent.RESULT_MATCHED:
        return "LANE_BOUNDARIES_MATCHED" if same else "LANE_BOUNDARIES_MATCHED_BY_PROFILE"
    if status == independent.RESULT_DIVERGENT:
        return "LANE_OBSERVATIONS_DIVERGE"
    if status == independent.RESULT_PARTIAL:
        return "LANE_EVIDENCE_PARTIAL"
    if status == independent.RESULT_UNKNOWN:
        return "LANE_EVIDENCE_UNKNOWN"
    return "LANE_EVIDENCE_CONFLICTED"


def _evidence(dimension: str, upstream: Mapping[str, object]) -> dict[str, object]:
    if dimension == independent.DIMENSION_INTERFACE:
        return deepcopy(independent.INTERFACE_MATERIAL)
    source = {
        independent.DIMENSION_TRANSACTION: (upstream["transaction_value"], "TRANSACTION_TRACE"),
        independent.DIMENSION_CONTRACT: (upstream["contract_value"], "CONTRACT_MIRROR"),
        independent.DIMENSION_DENOMINATOR: (upstream["denominator_value"], "DENOMINATOR_LEDGER"),
        independent.DIMENSION_MONEY: (upstream["money_value"], "MONEY_MIRROR"),
    }[dimension]
    value, role = source
    return {"artifact_id": value["artifact_id"], "stage_id": value["current_stage_id"], "transition_id": value["transition_id"], "role": role}


def _build_lanes(upstream: Mapping[str, object], fixture_id: str) -> list[dict[str, object]]:
    incumbent = _base_statuses(upstream)
    challenger = dict(incumbent)
    override = _override(fixture_id)
    if override is not None:
        challenger[override[0]] = override[1]
    output: list[dict[str, object]] = []
    for lane_id, statuses in ((independent.LANE_REFERENCE, incumbent), (independent.LANE_CHALLENGER, challenger)):
        output.append(
            {
                "lane_id": lane_id,
                "interface": {"status": statuses[independent.DIMENSION_INTERFACE], "reason": _reason(statuses[independent.DIMENSION_INTERFACE], lane_id == independent.LANE_REFERENCE), "evidence": _evidence(independent.DIMENSION_INTERFACE, upstream)},
                "transaction": {"status": statuses[independent.DIMENSION_TRANSACTION], "reason": _reason(statuses[independent.DIMENSION_TRANSACTION], True), "evidence": _evidence(independent.DIMENSION_TRANSACTION, upstream)},
                "contract": {"status": statuses[independent.DIMENSION_CONTRACT], "reason": _reason(statuses[independent.DIMENSION_CONTRACT], True), "evidence": _evidence(independent.DIMENSION_CONTRACT, upstream)},
                "denominator": {"status": statuses[independent.DIMENSION_DENOMINATOR], "reason": _reason(statuses[independent.DIMENSION_DENOMINATOR], True), "evidence": _evidence(independent.DIMENSION_DENOMINATOR, upstream)},
                "money": {"status": statuses[independent.DIMENSION_MONEY], "reason": _reason(statuses[independent.DIMENSION_MONEY], True), "evidence": _evidence(independent.DIMENSION_MONEY, upstream)},
                "error": {"status": statuses[independent.DIMENSION_ERROR], "reason": _reason(statuses[independent.DIMENSION_ERROR], True), "evidence": {"boundary": "TRANSITION_MIRROR"}},
            }
        )
    return output


def _compare(lanes: list[Mapping[str, object]]) -> dict[str, object]:
    def pair_status(left: str, right: str) -> str:
        if independent.RESULT_CONFLICTED in (left, right):
            return independent.RESULT_CONFLICTED
        if independent.RESULT_DIVERGENT in (left, right):
            return independent.RESULT_DIVERGENT
        if independent.RESULT_PARTIAL in (left, right):
            return independent.RESULT_PARTIAL
        if independent.RESULT_UNKNOWN in (left, right):
            return independent.RESULT_UNKNOWN
        return independent.RESULT_MATCHED

    dimensions: list[dict[str, object]] = []
    for name, key in zip(independent.DIMENSIONS, ("interface", "transaction", "contract", "denominator", "money", "error")):
        left = lanes[0][key]
        right = lanes[1][key]
        status = pair_status(left["status"], right["status"])
        dimensions.append({"dimension": name, "incumbent_status": left["status"], "challenger_status": right["status"], "status": status, "reason": _reason(status, left["status"] == right["status"])})
    statuses = [item["status"] for item in dimensions]
    overall = independent.RESULT_CONFLICTED if independent.RESULT_CONFLICTED in statuses else independent.RESULT_DIVERGENT if independent.RESULT_DIVERGENT in statuses else independent.RESULT_PARTIAL if independent.RESULT_PARTIAL in statuses else independent.RESULT_UNKNOWN if independent.RESULT_UNKNOWN in statuses else independent.RESULT_MATCHED
    return {
        "dimensions": dimensions,
        "overall": {"status": overall, "reason": _reason(overall, True), "winner": None, "cutover": "NOT_AUTHORIZED", "business_equivalence": False, "operational_readiness": "NOT_CLAIMED"},
    }


def build_artifact(
    fixture_id: str,
    *,
    money_raw: bytes,
    money_context: Mapping[str, object],
    prior_transition_raw: bytes | None = None,
) -> bytes:
    """Build one selector-driven candidate; the store supplies the selectors' bytes."""

    if fixture_id not in independent.FIXTURES:
        raise TransitionMirrorError("transition:fixture")
    upstream = _upstream(money_raw, money_context)
    prior_value = independent._parse(prior_transition_raw) if prior_transition_raw is not None else None
    shared = _shared_binding(upstream)
    lanes = _build_lanes(upstream, fixture_id)
    comparison = _compare(lanes)
    case_link = deepcopy(upstream["contract_value"].get("case_link")) if comparison["overall"]["status"] in {independent.RESULT_DIVERGENT, independent.RESULT_CONFLICTED} and isinstance(upstream["contract_value"].get("case_link"), dict) else None
    subject = independent._digest("transition-subject", {"profile_id": independent.PROFILE_ID, "money_trace_id": upstream["money_value"]["money_trace_id"], "input_root": shared["input_root"]})
    prior_id = prior_value["artifact_id"] if prior_value is not None else None
    prior_stage = prior_value["current_stage_id"] if prior_value is not None else None
    body: dict[str, object] = {
        "schema": independent.SCHEMA,
        "schema_version": independent.SCHEMA_VERSION,
        "profile_binding": independent._profile_binding(),
        "fixture_id": fixture_id,
        "subject": subject,
        "scope": independent.SCOPE,
        "shared_binding": shared,
        "lanes": lanes,
        "comparison": comparison,
        "parity_history": {"status": comparison["overall"]["status"], "history_mode": "APPEND_ONLY_OBSERVATION", "predecessor_artifact_id": prior_id},
        "responsibility": {
            "status": "OBSERVATION_ONLY",
            "boundary": "UNKNOWN" if comparison["overall"]["status"] != independent.RESULT_MATCHED else "SHARED_OBSERVATION_SCOPE",
            "reason": "DIFFERENCE_REQUIRES_BOUNDARY_REVIEW" if comparison["overall"]["status"] != independent.RESULT_MATCHED else "NO_OPERATIONAL_DIFFERENCE_CLAIMED",
            "blame_claim": False,
            "liability_claim": False,
        },
        "discrepancy": {
            "status": "UNRESOLVED_OBSERVED_DIFFERENCE" if comparison["overall"]["status"] in {independent.RESULT_DIVERGENT, independent.RESULT_CONFLICTED} else "EVIDENCE_PARTIAL" if comparison["overall"]["status"] in {independent.RESULT_PARTIAL, independent.RESULT_UNKNOWN} else "NONE_OBSERVED",
            "reason": "LANE_DIFFERENCE_REQUIRES_EXISTING_CASE_LIFECYCLE" if case_link is not None else "NO_CASE_CREATED_BY_TRANSITION",
            "case_link": case_link,
        },
        "remediation": {"status": "NOT_STARTED", "owner_boundary": "UNKNOWN", "evidence_mode": "NO_REMEDIATION_ASSERTION", "case_link": case_link},
        "retest": {
            "status": "EXECUTED" if prior_value is not None else "NOT_REQUESTED",
            "identity": independent._digest("retest", {"prior_artifact_id": prior_id, "fixture_id": fixture_id, "input_root": shared["input_root"]}) if prior_value is not None else None,
            "prior_artifact_id": prior_id,
            "result_status": comparison["overall"]["status"] if prior_value is not None else None,
        },
        "rollback_evidence": {"status": "CHAIN_REPLAYABLE_OBSERVATION", "scope": "TRANSITION_ARTIFACT_CHAIN", "history_preserved": True, "predecessor_bound": prior_value is not None, "cutover_authorized": False, "rollback_authorized": False},
        "stage_kind": independent.STAGE_RETESTED if prior_value is not None else independent.STAGE_COMPARED,
        "prior_artifact_id": prior_id,
        "prior_stage_id": prior_stage,
        "flags": deepcopy(independent.FIXED_FLAGS),
        "authority": deepcopy(independent.AUTHORITY_FLAGS),
    }
    artifact_id, stage_id, transition_id = independent._identity_values(body)
    return independent._canonical({**body, "artifact_id": artifact_id, "current_stage_id": stage_id, "transition_id": transition_id})


class TransitionMirrorService:
    """Selector-only facade for the state-owned Transition admission seam."""

    def __init__(self, continuity_store: object, *, graph_profile_registry: Mapping[str, object] | None = None) -> None:
        from app.mirror import continuity_store as store

        if not isinstance(continuity_store, store.ContinuityStore):
            raise TransitionMirrorError("composition:store")
        registry = dict(graph_profile_registry or continuity_store.graph_profile_registry)
        if registry != dict(continuity_store.graph_profile_registry):
            raise TransitionMirrorError("composition:registry")
        self._store = continuity_store
        self._registry = registry

    def compare(self, money_artifact_id: str, *, fixture_id: str = independent.FIXTURE_MATCHED):
        return self._admit("TRANSITION_INITIAL", money_artifact_id=money_artifact_id, fixture_id=fixture_id)

    def retest(self, transition_artifact_id: str, *, fixture_id: str = independent.FIXTURE_MATCHED):
        return self._admit("TRANSITION_RETEST", transition_artifact_id=transition_artifact_id, fixture_id=fixture_id)

    def _admit(self, action: str, **selectors: str):
        from app.mirror import continuity_store as store

        for attempt in range(3):
            try:
                return self._store.admit_transition(action, graph_profile_registry=self._registry, **selectors)
            except store.StoreBusyError:
                if attempt == 2:
                    raise
                time.sleep(0.05 * (attempt + 1))
        raise TransitionMirrorError("transition:busy-retry-exhausted")


__all__ = ["TransitionMirrorError", "TransitionMirrorService", "build_artifact"]
