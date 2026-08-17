"""Composition root for the synthetic Money Mirror V1 seam.

Only selectors and named synthetic fixtures cross this facade.  The store
selects the Transaction Trace, Contract, governance, and prior money bytes in
one transaction; no caller supplies an amount, role, currency, total, or
authority flag.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import time
from typing import Mapping

from app.mirror import money_mirror_independent as independent
from app.mirror import transaction_mirror_independent as transaction


class MoneyMirrorError(ValueError):
    """Stable composition-layer failure."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise MoneyMirrorError("money:noncanonical") from exc


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((independent.DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _payload_hash(raw: bytes) -> str:
    return _digest("stored-payload", raw.hex())


def _role(
    role: str,
    status: str,
    boundary_id: str,
    event_time: int | None,
    effective_time: int | None,
    currency: str | None,
    amount_minor: int | None,
    amount_sign: str | None = None,
    predecessor_role: str | None = None,
    correction_of: str | None = None,
) -> dict[str, object]:
    body = {
        "role": role,
        "status": status,
        "boundary_id": boundary_id,
        "event_time": event_time,
        "effective_time": effective_time,
        "currency": currency,
        "amount_minor": amount_minor,
        "amount_sign": amount_sign,
        "predecessor_role": predecessor_role,
        "correction_of": correction_of,
    }
    return {**body, "provenance_root": _digest("role-root", body)}


def _na(role: str, boundary_id: str) -> dict[str, object]:
    return _role(role, independent.STATUS_NOT_APPLICABLE, boundary_id, None, None, None, None)


def _roles_for_fixture(fixture_id: str) -> list[dict[str, object]]:
    """Create only fixed local fixture bytes; this is not source or ledger authority."""

    if fixture_id == independent.FIXTURE_MULTI_CURRENCY:
        return [
            _role(independent.ROLE_ADJUDICATED, independent.STATUS_OBSERVED, "SYNTH_OFFICIAL_ADJUDICATION_BOUNDARY_V1", 7_100, 7_100, independent.CURRENCY, 12_500),
            _role(independent.ROLE_POSTED, independent.STATUS_OBSERVED, "SYNTH_OFFICIAL_PAYMENT_RAIL_BOUNDARY_V1", 7_110, 7_110, independent.CURRENCY, 12_500),
            _na(independent.ROLE_VOID, "SYNTH_OFFICIAL_REVERSAL_BOUNDARY_V1"),
            _na(independent.ROLE_ADJUSTMENT, "SYNTH_OFFICIAL_ADJUSTMENT_BOUNDARY_V1"),
            _role(independent.ROLE_REPORT, independent.STATUS_OBSERVED, "SYNTH_OFFICIAL_REPORTING_BOUNDARY_V1", 7_120, 7_120, "EUR", 12_500),
        ]
    if fixture_id == independent.FIXTURE_GAPPED:
        return [
            _role(independent.ROLE_ADJUDICATED, independent.STATUS_OBSERVED, "SYNTH_OFFICIAL_ADJUDICATION_BOUNDARY_V1", 7_100, 7_100, independent.CURRENCY, 12_500),
            _role(independent.ROLE_POSTED, independent.STATUS_GAPPED, "SYNTH_OFFICIAL_PAYMENT_RAIL_BOUNDARY_V1", None, None, None, None),
            _na(independent.ROLE_VOID, "SYNTH_OFFICIAL_REVERSAL_BOUNDARY_V1"),
            _na(independent.ROLE_ADJUSTMENT, "SYNTH_OFFICIAL_ADJUSTMENT_BOUNDARY_V1"),
            _role(independent.ROLE_REPORT, independent.STATUS_GAPPED, "SYNTH_OFFICIAL_REPORTING_BOUNDARY_V1", None, None, None, None),
        ]
    posted = 0 if fixture_id == independent.FIXTURE_MISMATCHED else 12_500
    report = 0 if fixture_id in {independent.FIXTURE_MISMATCHED, independent.FIXTURE_VOID} else 12_500
    if fixture_id in {independent.FIXTURE_ADJUSTMENT, independent.FIXTURE_CORRECTION}:
        report = 13_000
    elif fixture_id == independent.FIXTURE_REPORT_MISMATCH:
        report = 12_000
    adjustment = _na(independent.ROLE_ADJUSTMENT, "SYNTH_OFFICIAL_ADJUSTMENT_BOUNDARY_V1")
    if fixture_id in {independent.FIXTURE_ADJUSTMENT, independent.FIXTURE_REPORT_MISMATCH, independent.FIXTURE_CORRECTION}:
        adjustment = _role(independent.ROLE_ADJUSTMENT, independent.STATUS_OBSERVED, "SYNTH_OFFICIAL_ADJUSTMENT_BOUNDARY_V1", 7_115, 7_115, independent.CURRENCY, 500, "POSITIVE", independent.ROLE_POSTED)
    void = _na(independent.ROLE_VOID, "SYNTH_OFFICIAL_REVERSAL_BOUNDARY_V1")
    if fixture_id == independent.FIXTURE_VOID:
        void = _role(independent.ROLE_VOID, independent.STATUS_OBSERVED, "SYNTH_OFFICIAL_REVERSAL_BOUNDARY_V1", 7_115, 7_115, independent.CURRENCY, 12_500, None, independent.ROLE_POSTED)
    report_role = _role(independent.ROLE_REPORT, independent.STATUS_OBSERVED, "SYNTH_OFFICIAL_REPORTING_BOUNDARY_V1", 7_120, 7_120, independent.CURRENCY, report)
    if fixture_id == independent.FIXTURE_CORRECTION:
        report_role["correction_of"] = independent.ROLE_REPORT
        body = dict(report_role)
        body.pop("provenance_root")
        report_role["provenance_root"] = _digest("role-root", body)
    return [
        _role(independent.ROLE_ADJUDICATED, independent.STATUS_OBSERVED, "SYNTH_OFFICIAL_ADJUDICATION_BOUNDARY_V1", 7_100, 7_100, independent.CURRENCY, 12_500),
        _role(independent.ROLE_POSTED, independent.STATUS_OBSERVED, "SYNTH_OFFICIAL_PAYMENT_RAIL_BOUNDARY_V1", 7_110, 7_110, independent.CURRENCY, posted),
        void,
        adjustment,
        report_role,
    ]


def _terms(roles: list[Mapping[str, object]]) -> dict[str, object]:
    posted, void, adjustment, report = roles[1], roles[2], roles[3], roles[4]
    if any(item["status"] not in {independent.STATUS_OBSERVED, independent.STATUS_NOT_APPLICABLE} for item in roles) or posted["status"] != independent.STATUS_OBSERVED:
        return {"currency": independent.CURRENCY, "gross_official_posted_minor": None, "signed_adjustments_minor": None, "voided_amount_minor": None, "net_official_observed_minor": None, "report_amount_minor": None}
    signed = 0 if adjustment["status"] == independent.STATUS_NOT_APPLICABLE else int(adjustment["amount_minor"]) * (1 if adjustment["amount_sign"] == "POSITIVE" else -1)
    voided = 0 if void["status"] == independent.STATUS_NOT_APPLICABLE else int(void["amount_minor"])
    net = int(posted["amount_minor"]) + signed - voided
    if net < 0 or abs(net) > independent.MINOR_LIMIT:
        raise MoneyMirrorError("money:conservation-overflow")
    return {"currency": independent.CURRENCY, "gross_official_posted_minor": posted["amount_minor"], "signed_adjustments_minor": signed, "voided_amount_minor": voided, "net_official_observed_minor": net, "report_amount_minor": report["amount_minor"] if report["status"] == independent.STATUS_OBSERVED else None}


def _comparison(status: str, reason: str) -> dict[str, object]:
    return {"status": status, "reason": reason}


def _comparisons(roles: list[Mapping[str, object]], observation_value: Mapping[str, object]) -> dict[str, object]:
    evidence = observation_value["evidence"]
    processor, official = evidence["processor"], evidence["official"]
    if processor["status"] != transaction.STATUS_OBSERVED or official["status"] != transaction.STATUS_OBSERVED:
        processor_result = _comparison(independent.RESULT_UNKNOWN, "PROCESSOR_OR_OFFICIAL_EVIDENCE_MISSING")
    elif (processor["amount_minor"], processor["currency"]) != (official["amount_minor"], official["currency"]):
        processor_result = _comparison(independent.RESULT_DIVERGENT, "PROCESSOR_VS_OFFICIAL_DIFFER")
    else:
        processor_result = _comparison(independent.RESULT_MATCHED, "PROCESSOR_VS_OFFICIAL_MATCHED")
    terms = _terms(roles)
    event_result = _comparison(independent.RESULT_UNKNOWN, "OFFICIAL_EVENT_CHAIN_INCOMPLETE") if terms["net_official_observed_minor"] is None else _comparison(independent.RESULT_MATCHED, "OFFICIAL_EVENT_CHAIN_CONSERVES")
    report = roles[4]
    if terms["net_official_observed_minor"] is None or report["status"] != independent.STATUS_OBSERVED:
        report_result = _comparison(independent.RESULT_UNKNOWN, "OFFICIAL_REPORT_EVIDENCE_MISSING")
    elif terms["net_official_observed_minor"] == terms["report_amount_minor"] and report["currency"] == independent.CURRENCY:
        report_result = _comparison(independent.RESULT_MATCHED, "OFFICIAL_NET_EQUALS_REPORT")
    else:
        report_result = _comparison(independent.RESULT_DIVERGENT, "OFFICIAL_NET_DIFFERS_FROM_REPORT")
    statuses = (processor_result["status"], event_result["status"], report_result["status"])
    if independent.RESULT_CONFLICTED in statuses:
        overall = _comparison(independent.RESULT_CONFLICTED, "MONEY_EVIDENCE_CONFLICTED")
    elif independent.RESULT_DIVERGENT in statuses:
        overall = _comparison(independent.RESULT_DIVERGENT, "MONEY_BOUNDARIES_DIVERGE")
    elif independent.RESULT_UNKNOWN in statuses:
        overall = _comparison(independent.RESULT_PARTIAL, "MONEY_EVIDENCE_PARTIAL")
    else:
        overall = _comparison(independent.RESULT_MATCHED, "MONEY_BOUNDARIES_MATCHED")
    return {"processor_vs_official": processor_result, "event_chain_conservation": event_result, "official_net_vs_report": report_result, "overall": overall}


def _coverage(roles: list[Mapping[str, object]]) -> dict[str, object]:
    if any(item["status"] in {independent.STATUS_CONFLICTED, independent.STATUS_GAPPED} for item in roles):
        return {"status": independent.COVERAGE_PARTIAL, "reason": "OFFICIAL_MONEY_EVIDENCE_PARTIAL"}
    if any(item["status"] == independent.STATUS_UNKNOWN for item in roles):
        return {"status": independent.COVERAGE_UNKNOWN, "reason": "OFFICIAL_MONEY_EVIDENCE_UNKNOWN"}
    return {"status": independent.COVERAGE_COMPLETE, "reason": "ALL_FIXED_MONEY_ROLES_ACCOUNTED"}


def _chronology(roles: list[Mapping[str, object]], transaction_value: Mapping[str, object], contract_value: Mapping[str, object]) -> dict[str, object]:
    event_times = [item["event_time"] for item in roles if item["event_time"] is not None]
    effective_times = [item["effective_time"] for item in roles if item["effective_time"] is not None]
    return {
        "transaction_observation_time": transaction_value["input_binding"]["observation_time"],
        "effective_start": contract_value["obligation"]["effective_start"],
        "effective_end": contract_value["obligation"]["effective_end"],
        "event_times": event_times,
        "effective_times": effective_times,
    }


def _transaction_binding(transaction_raw: bytes, transaction_value: Mapping[str, object], contract_value: Mapping[str, object]) -> dict[str, object]:
    return {
        "trace_artifact_id": transaction_value["artifact_id"],
        "trace_stage_id": transaction_value["current_stage_id"],
        "trace_transition_id": transaction_value["transition_id"],
        "trace_payload_hash": _payload_hash(transaction_raw),
        "trace_id": transaction_value["trace_id"],
        "contract_binding": transaction._contract_binding(transaction_raw, contract_value),
    }


def _identity_values(value: Mapping[str, object]) -> tuple[str, str, str]:
    body = deepcopy(dict(value))
    body.pop("artifact_id", None)
    body.pop("current_stage_id", None)
    body.pop("transition_id", None)
    artifact_id = _digest("artifact-id", body)
    stage_id = _digest("stage-id", {"artifact_id": artifact_id, "stage_kind": value["stage_kind"], "prior_artifact_id": value["prior_artifact_id"], "prior_stage_id": value["prior_stage_id"], "money_trace_id": value["money_trace_id"]})
    transition_id = _digest("transition-id", {"artifact_id": artifact_id, "current_stage_id": stage_id, "stage_kind": value["stage_kind"], "prior_artifact_id": value["prior_artifact_id"], "prior_stage_id": value["prior_stage_id"]})
    return artifact_id, stage_id, transition_id


def build_artifact(
    fixture_id: str,
    *,
    transaction_raw: bytes,
    transaction_context: Mapping[str, object],
    prior_money_raw: bytes | None = None,
) -> bytes:
    if fixture_id not in independent.FIXTURES:
        raise MoneyMirrorError("money:fixture")
    transaction_value = transaction._parse(transaction_raw)
    if transaction_value.get("schema") != transaction.TRACE_SCHEMA:
        raise MoneyMirrorError("money:trace-kind")
    contract_value = transaction._parse(transaction_context["contract_raw"])
    observation_value = transaction._parse(transaction_context["observation_raw"])
    roles = _roles_for_fixture(fixture_id)
    prior_artifact_id = None
    prior_stage_id = None
    if prior_money_raw is not None:
        prior_value = independent._parse(prior_money_raw)
        prior_artifact_id = prior_value["artifact_id"]
        prior_stage_id = prior_value["current_stage_id"]
        if prior_value["money_trace_id"] != independent.money_trace_id_for(transaction_raw):
            raise MoneyMirrorError("money:prior-trace")
    terms = _terms(roles)
    comparisons = _comparisons(roles, observation_value)
    body = {
        "schema": independent.SCHEMA,
        "schema_version": independent.SCHEMA_VERSION,
        "profile_binding": independent._profile_binding(),
        "money_trace_id": independent.money_trace_id_for(transaction_raw),
        "transaction_binding": _transaction_binding(transaction_raw, transaction_value, contract_value),
        "fixture_id": fixture_id,
        "roles": roles,
        "terms": terms,
        "comparisons": comparisons,
        "evidence_coverage": _coverage(roles),
        "chronology": _chronology(roles, transaction_value, contract_value),
        "case_link": dict(contract_value["case_link"]) if comparisons["overall"]["status"] == independent.RESULT_DIVERGENT else None,
        "stage_kind": independent._stage_for_fixture(fixture_id),
        "prior_artifact_id": prior_artifact_id,
        "prior_stage_id": prior_stage_id,
        "flags": dict(independent.FIXED_FLAGS),
        "authority": dict(independent.AUTHORITY_FLAGS),
    }
    artifact_id, stage_id, transition_id = _identity_values(body)
    raw = _canonical({**body, "artifact_id": artifact_id, "current_stage_id": stage_id, "transition_id": transition_id})
    if len(raw) > independent.MAX_ARTIFACT_BYTES:
        raise MoneyMirrorError("money:byte-cap")
    return raw


class MoneyMirrorService:
    """Configured facade for selector-only synthetic money observations."""

    def __init__(self, continuity_store: object, *, graph_profile_registry: Mapping[str, object] | None = None) -> None:
        from app.mirror import continuity_store as store

        if not isinstance(continuity_store, store.ContinuityStore):
            raise MoneyMirrorError("composition:store")
        registry = dict(graph_profile_registry or continuity_store.graph_profile_registry)
        if registry != dict(continuity_store.graph_profile_registry):
            raise MoneyMirrorError("composition:registry")
        self.store = continuity_store
        self.graph_profile_registry = registry

    def observe(self, trace_artifact_id: str, *, fixture_id: str = independent.FIXTURE_MATCHED):
        if not isinstance(trace_artifact_id, str) or not trace_artifact_id:
            raise MoneyMirrorError("money:trace-selector")
        if fixture_id not in independent.INITIAL_FIXTURES:
            raise MoneyMirrorError("money:initial-fixture")
        return self._admit("MONEY_INITIAL", trace_artifact_id=trace_artifact_id, fixture_id=fixture_id, graph_profile_registry=self.graph_profile_registry)

    def void(self, money_artifact_id: str):
        return self._transition("MONEY_VOID", money_artifact_id, independent.FIXTURE_VOID)

    def adjust(self, money_artifact_id: str):
        return self._transition("MONEY_ADJUSTMENT", money_artifact_id, independent.FIXTURE_ADJUSTMENT)

    def report_mismatch(self, money_artifact_id: str):
        return self._transition("MONEY_REPORT_MISMATCH", money_artifact_id, independent.FIXTURE_REPORT_MISMATCH)

    def correct(self, money_artifact_id: str):
        return self._transition("MONEY_CORRECTION", money_artifact_id, independent.FIXTURE_CORRECTION)

    def _transition(self, action: str, money_artifact_id: str, fixture_id: str):
        if not isinstance(money_artifact_id, str) or not money_artifact_id:
            raise MoneyMirrorError("money:artifact-selector")
        return self._admit(action, money_artifact_id=money_artifact_id, fixture_id=fixture_id, graph_profile_registry=self.graph_profile_registry)

    def _admit(self, action: str, **selectors: str):
        from app.mirror import continuity_store as store

        for attempt in range(3):
            try:
                return self.store.admit_money(action, **selectors)
            except store.StoreBusyError:
                if attempt == 2:
                    raise
                time.sleep(0.05 * (attempt + 1))
        raise MoneyMirrorError("money:busy-retry-exhausted")


__all__ = ["MoneyMirrorError", "MoneyMirrorService", "build_artifact"]
