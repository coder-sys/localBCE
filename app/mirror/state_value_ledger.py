"""Selector-only composition root for the synthetic State Value Ledger V1.

The facade accepts only store-selected upstream artifact IDs.  It never accepts
amounts, categories, calculation rules, owners, eligibility, authority flags,
or caller-provided summaries.  The ContinuityStore supplies the exact bytes
inside its write transaction before this module proposes canonical bytes.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from typing import Mapping

from app.mirror import state_value_ledger_independent as independent
from app.mirror import money_mirror_independent as money


class StateValueLedgerError(ValueError):
    """Stable composition-layer failure."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise StateValueLedgerError("state-value:noncanonical") from exc


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((independent.DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _payload_hash(raw: bytes) -> str:
    return independent._payload_hash(raw)


def _ref(value: Mapping[str, object], raw: bytes, *, extra: Mapping[str, object] | None = None, transition_id: str | None = None) -> dict[str, object]:
    profile_binding = value.get("profile_binding") if isinstance(value.get("profile_binding"), Mapping) else {}
    result: dict[str, object] = {
        "artifact_id": value["artifact_id"],
        "stage_id": value["current_stage_id"],
        "transition_id": value.get("transition_id") if transition_id is None else transition_id,
        "payload_hash": _payload_hash(raw),
        "profile_id": value.get("profile_id") or profile_binding.get("profile_id"),
        "profile_version": value.get("profile_version") or profile_binding.get("version"),
    }
    if extra:
        result.update(extra)
    return result


def _governance_ref(raw: bytes, value: Mapping[str, object]) -> dict[str, object]:
    profile = value["profile"]
    return {
        "artifact_id": value["artifact_id"],
        "stage_id": value["current_stage_id"],
        "transition_id": value["chain_root"],
        "payload_hash": _payload_hash(raw),
        "profile_id": profile["profile_id"],
        "profile_version": profile["version"],
    }


def _upstream(
    money_raw: bytes,
    money_context: Mapping[str, object],
    *,
    transition_raw: bytes | None,
) -> dict[str, object]:
    try:
        money_value = money._parse(money_raw)
        transaction_raw = money_context["transaction_raw"]
        transaction_context = money_context["transaction_context"]
        transaction_value = json.loads(transaction_raw.decode("ascii"))
        contract_raw = transaction_context["contract_raw"]
        contract_value = json.loads(contract_raw.decode("ascii"))
        contract_context = transaction_context["contract_context"]
        denominator_raw = contract_context["denominator_raw"]
        denominator_value = json.loads(denominator_raw.decode("ascii"))
        denominator_context = contract_context["denominator_context"]
        governance_raw = denominator_context["governance_raw"]
        governance_value = json.loads(governance_raw.decode("ascii"))
        transition_value = json.loads(transition_raw.decode("ascii")) if transition_raw is not None else None
        upstream = {
            "money": _ref(money_value, money_raw, extra={"money_trace_id": money_value["money_trace_id"]}),
            "transaction": _ref(transaction_value, transaction_raw, extra={"trace_id": transaction_value["trace_id"]}),
            "contract": _ref(contract_value, contract_raw),
            "denominator": _ref(denominator_value, denominator_raw, extra={"population_root": denominator_value["population"]["population_root"]}),
            "governance": _governance_ref(governance_raw, governance_value),
            "transition": _ref(transition_value, transition_raw) if transition_value is not None and transition_raw is not None else None,
        }
        return {
            "money_raw": money_raw,
            "money_value": money_value,
            "transaction_raw": transaction_raw,
            "transaction_value": transaction_value,
            "transaction_context": transaction_context,
            "contract_raw": contract_raw,
            "contract_value": contract_value,
            "contract_context": contract_context,
            "denominator_raw": denominator_raw,
            "denominator_value": denominator_value,
            "governance_raw": governance_raw,
            "governance_value": governance_value,
            "transition_raw": transition_raw,
            "transition_value": transition_value,
            "upstream": upstream,
        }
    except Exception as exc:
        raise StateValueLedgerError("state-value:upstream-context") from exc


def _sign(value: int | None) -> str:
    if value is None:
        return "UNKNOWN"
    if value > 0:
        return "POSITIVE"
    if value < 0:
        return "NEGATIVE"
    return "ZERO"


def _entry(upstream: Mapping[str, object], *, review_state: str, retest_state: str) -> dict[str, object]:
    money_value = upstream["money_value"]
    transaction_value = upstream["transaction_value"]
    contract_value = upstream["contract_value"]
    terms = money_value["terms"]
    baseline_role = money_value["roles"][0]
    baseline_amount = baseline_role["amount_minor"] if baseline_role["status"] == money.STATUS_OBSERVED else None
    intervention_amount = terms["net_official_observed_minor"]
    delta = intervention_amount - baseline_amount if type(intervention_amount) is int and type(baseline_amount) is int else None
    overall = money_value["comparisons"]["overall"]["status"]
    coverage = money_value["evidence_coverage"]["status"]
    if money_value["stage_kind"] == money.STAGE_VOIDED or (type(terms["voided_amount_minor"]) is int and terms["voided_amount_minor"] > 0):
        eligibility, category, reason, strength = independent.STATUS_REVERSED, independent.CATEGORY_REVERSED, independent.REASON_REVERSAL, "OBSERVED_OFFICIAL_REVERSAL"
    elif overall == money.RESULT_CONFLICTED:
        eligibility, category, reason, strength = independent.STATUS_DISPUTED, independent.CATEGORY_DISPUTED, independent.REASON_CONFLICTED, "DISPUTED_OFFICIAL_BOUNDARIES"
    elif overall == money.RESULT_DIVERGENT:
        eligibility, category, reason, strength = independent.STATUS_DISPUTED, independent.CATEGORY_DISPUTED, independent.REASON_DIVERGENT, "DISPUTED_OFFICIAL_BOUNDARIES"
    elif coverage != money.COVERAGE_COMPLETE or delta is None:
        eligibility, category, reason, strength = independent.STATUS_UNKNOWN, independent.CATEGORY_UNKNOWN, independent.REASON_INCOMPLETE, "UNKNOWN_OFFICIAL_COVERAGE"
    elif delta == 0:
        eligibility, category, reason, strength = independent.STATUS_EXCLUDED, independent.CATEGORY_EXCLUDED, independent.REASON_ZERO, "OBSERVED_OFFICIAL_ARITHMETIC"
    elif delta < 0:
        eligibility, category, reason, strength = independent.STATUS_COUNTED, independent.CATEGORY_COUNTED, independent.REASON_NEGATIVE_ARITHMETIC, "OBSERVED_NEGATIVE_ARITHMETIC"
    else:
        eligibility, category, reason, strength = independent.STATUS_COUNTED, independent.CATEGORY_COUNTED, independent.REASON_ARITHMETIC, "OBSERVED_OFFICIAL_ARITHMETIC"
    uncertainty = sorted(["DENOMINATOR_COMPLETENESS_UNKNOWN", "NONMEMBERSHIP_DISABLED", "NO_CAUSAL_INFERENCE"])
    if delta is None:
        uncertainty.append("OFFICIAL_NET_UNKNOWN")
    if eligibility == independent.STATUS_DISPUTED:
        uncertainty.append("OFFICIAL_BOUNDARIES_DIVERGE")
    if eligibility == independent.STATUS_REVERSED:
        uncertainty.append("REVERSAL_OBSERVED")
    uncertainty = sorted(uncertainty)
    obligation = contract_value["obligation"]
    period_start, period_end = obligation["effective_start"], obligation["effective_end"]
    baseline = {
        "identity": "OFFICIAL_ADJUDICATED_REFERENCE",
        "period_start": period_start,
        "period_end": period_end,
        "currency": independent.CURRENCY,
        "amount_minor": baseline_amount,
        "source_role": money.ROLE_ADJUDICATED,
    }
    intervention = {
        "identity": "OFFICIAL_NET_OBSERVED",
        "period_start": period_start,
        "period_end": period_end,
        "currency": independent.CURRENCY,
        "amount_minor": intervention_amount,
        "source_role": "OFFICIAL_NET_OBSERVED",
    }
    calculation = {
        "formula_id": independent.MATERIAL_PROFILE["formula_id"],
        "formula_version": independent.MATERIAL_PROFILE["formula_version"],
        "unit": independent.UNIT,
        "delta_minor": delta,
        "sign": _sign(delta),
        "causal_claim": False,
        "assumptions": ["OFFICIAL_BOUNDARY_OBSERVATION_ONLY", "NO_CURRENCY_CONVERSION", "NO_CAUSAL_INFERENCE"],
    }
    reversal = {
        "status": "REVERSED" if eligibility == independent.STATUS_REVERSED else "NOT_REVERSED",
        "source_role": money.ROLE_VOID if eligibility == independent.STATUS_REVERSED else None,
        "amount_minor": terms["voided_amount_minor"] if eligibility == independent.STATUS_REVERSED else None,
        "predecessor_money_artifact_id": money_value["prior_artifact_id"] if eligibility == independent.STATUS_REVERSED else None,
    }
    without_id = {
        "economic_event_key": independent.economic_event_key_for(transaction_value),
        "category": category,
        "eligibility_status": eligibility,
        "reason_code": reason,
        "evidence_strength": strength,
        "uncertainty": uncertainty,
        "owner_boundary": obligation["responsible_boundary"],
        "owner_basis": "CONTRACT_OBLIGATION_RESPONSIBLE_BOUNDARY",
        "review_state": review_state,
        "retest_state": retest_state,
        "reversal": reversal,
        "baseline": baseline,
        "intervention": intervention,
        "calculation": calculation,
        "upstream": upstream["upstream"],
        "flags": {
            "causal_claim": False,
            "payment_authority": False,
            "clearance_authority": False,
            "production_usable": False,
            "state_approval": False,
            "automatic_decision_authority": False,
        },
    }
    return {"value_claim_id": _digest("value-claim-id", without_id), **without_id}


def _aggregate(entries: list[Mapping[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {"entry_count": len(entries), "currency": independent.CURRENCY, "unit": independent.UNIT}
    for status, label in (
        (independent.STATUS_COUNTED, "counted"),
        (independent.STATUS_EXCLUDED, "excluded"),
        (independent.STATUS_DISPUTED, "disputed"),
        (independent.STATUS_UNKNOWN, "unknown"),
        (independent.STATUS_REVERSED, "reversed"),
    ):
        selected = [item["calculation"]["delta_minor"] for item in entries if item["eligibility_status"] == status]
        result[f"{label}_entries"] = len(selected)
        result[f"{label}_minor"] = None if any(item is None for item in selected) else sum(selected)
    return result


def _lineage() -> dict[str, object]:
    return {
        "upstream_dependencies": ["MONEY", "CONTRACT", "DENOMINATOR", "TRANSACTION", "GOVERNANCE"],
        "counting_once_rule": "ONE_CURRENT_ENTRY_PER_TRANSACTION_TRACE",
        "limitations": ["NO_CAUSAL_INFERENCE", "NO_NONMEMBERSHIP", "NO_PAYMENT_AUTHORITY", "DENOMINATOR_COMPLETENESS_UNKNOWN"],
    }


def _chronology(upstream: Mapping[str, object]) -> dict[str, object]:
    money_value = upstream["money_value"]
    transaction_value = upstream["transaction_value"]
    obligation = upstream["contract_value"]["obligation"]
    times = [item["event_time"] for item in money_value["roles"] if item["event_time"] is not None]
    return {
        "observation_time": transaction_value["input_binding"]["observation_time"],
        "effective_start": obligation["effective_start"],
        "effective_end": obligation["effective_end"],
        "current_money_event_time": max(times) if times else None,
        "status": "BOUNDED_SOURCE_AND_CONTRACT_INTERVAL",
    }


def _recalculation(mode: str, input_money_artifact_id: str, prior_artifact_id: str | None, replaced_claim_id: str | None, new_claim_id: str) -> dict[str, object]:
    material = {
        "mode": mode,
        "input_money_artifact_id": input_money_artifact_id,
        "prior_artifact_id": prior_artifact_id,
        "replaced_value_claim_id": replaced_claim_id,
        "new_value_claim_id": new_claim_id,
    }
    return {**material, "identity": _digest("recalculation", material)}


def build_artifact(
    money_raw: bytes,
    *,
    money_context: Mapping[str, object],
    prior_value_raw: bytes | None = None,
    transition_raw: bytes | None = None,
) -> bytes:
    """Propose canonical bytes from exact store-selected upstream bytes."""

    current_upstream = _upstream(money_raw, money_context, transition_raw=transition_raw)
    prior_value = independent._parse(prior_value_raw) if prior_value_raw is not None else None
    current_entry = _entry(current_upstream, review_state="UNREVIEWED" if prior_value is None else "RECALCULATED", retest_state="NOT_RETESTED" if prior_value is None else "RECALCULATED")
    if prior_value is None:
        entries = [current_entry]
        mode, replaced_claim = "INITIAL", None
        stage_kind = independent.STAGE_OBSERVED
        prior_artifact_id = prior_stage_id = None
    else:
        prior_entries = list(prior_value["entries"])
        prior_by_key = {item["economic_event_key"]: item for item in prior_entries}
        key = current_entry["economic_event_key"]
        prior_entry = prior_by_key.get(key)
        if prior_entry is None:
            mode, replaced_claim = "APPEND_NEW", None
        elif current_entry["upstream"]["money"]["artifact_id"] == prior_entry["upstream"]["money"]["artifact_id"]:
            mode, replaced_claim = "RECALCULATE_EXISTING", None
        elif current_upstream["money_value"].get("prior_artifact_id") == prior_entry["upstream"]["money"]["artifact_id"]:
            mode, replaced_claim = "REPLACE_EXISTING", prior_entry["value_claim_id"]
        else:
            raise StateValueLedgerError("state-value:economic-event-reuse")
        prior_by_key[key] = current_entry
        entries = sorted(prior_by_key.values(), key=lambda item: str(item["economic_event_key"]))
        stage_kind = independent.STAGE_RECALCULATED
        prior_artifact_id = prior_value["artifact_id"]
        prior_stage_id = prior_value["current_stage_id"]
    recalculation = _recalculation(mode, current_entry["upstream"]["money"]["artifact_id"], prior_artifact_id, replaced_claim, current_entry["value_claim_id"])
    body = {
        "schema": independent.SCHEMA,
        "schema_version": independent.SCHEMA_VERSION,
        "profile_binding": independent._profile_binding(),
        "subject": independent.SUBJECT,
        "scope": independent.SCOPE,
        "stage_kind": stage_kind,
        "prior_artifact_id": prior_artifact_id,
        "prior_stage_id": prior_stage_id,
        "upstream_mode": "STORE_SELECTED_EXACT_BYTES",
        "entries": entries,
        "aggregate": _aggregate(entries),
        "lineage": _lineage(),
        "chronology": _chronology(current_upstream),
        "recalculation": recalculation,
        "flags": dict(independent.FIXED_FLAGS),
        "authority": dict(independent.AUTHORITY_FLAGS),
    }
    artifact_id, stage_id, transition_id = independent._identity_values(body)
    raw = _canonical({**body, "artifact_id": artifact_id, "current_stage_id": stage_id, "transition_id": transition_id})
    if len(raw) > independent.MAX_ARTIFACT_BYTES:
        raise StateValueLedgerError("state-value:byte-cap")
    return raw


class StateValueLedgerService:
    """Configured selector-only facade for the synthetic value ledger."""

    def __init__(self, continuity_store: object, *, graph_profile_registry: Mapping[str, object] | None = None) -> None:
        from app.mirror import continuity_store as store

        if not isinstance(continuity_store, store.ContinuityStore):
            raise StateValueLedgerError("composition:store")
        registry = dict(graph_profile_registry or continuity_store.graph_profile_registry)
        if registry != dict(continuity_store.graph_profile_registry):
            raise StateValueLedgerError("composition:registry")
        self.store = continuity_store
        self.graph_profile_registry = registry

    def observe(self, money_artifact_id: str, *, transition_artifact_id: str | None = None):
        if not isinstance(money_artifact_id, str) or not money_artifact_id:
            raise StateValueLedgerError("state-value:money-selector")
        if transition_artifact_id is not None and (not isinstance(transition_artifact_id, str) or not transition_artifact_id):
            raise StateValueLedgerError("state-value:transition-selector")
        return self._admit("STATE_VALUE_INITIAL", money_artifact_id=money_artifact_id, transition_artifact_id=transition_artifact_id)

    def recalculate(self, value_artifact_id: str, money_artifact_id: str, *, transition_artifact_id: str | None = None):
        if not isinstance(value_artifact_id, str) or not value_artifact_id or not isinstance(money_artifact_id, str) or not money_artifact_id:
            raise StateValueLedgerError("state-value:recalculation-selectors")
        if transition_artifact_id is not None and (not isinstance(transition_artifact_id, str) or not transition_artifact_id):
            raise StateValueLedgerError("state-value:transition-selector")
        return self._admit(
            "STATE_VALUE_RECALCULATE",
            money_artifact_id=money_artifact_id,
            value_artifact_id=value_artifact_id,
            transition_artifact_id=transition_artifact_id,
        )

    def _admit(self, action: str, **selectors: str | None):
        from app.mirror import continuity_store as store

        return store.run_with_busy_recovery(
            lambda: self.store.admit_state_value(action, graph_profile_registry=self.graph_profile_registry, **selectors)
        )


__all__ = ["StateValueLedgerError", "StateValueLedgerService", "build_artifact"]
