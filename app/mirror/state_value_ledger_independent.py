"""Independent verifier for the fixed synthetic State Value Ledger V1 seam.

The artifact is a bounded observation of independently stored Mirror evidence,
not an accounting balance, savings claim, causal result, payment instruction,
or state-approved counting authority.  This module owns the wire grammar,
counting-once rule, and reconstruction of every derived value from exact
upstream bytes.  It deliberately does not import the producer facade.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re
from typing import Mapping

from app.governance import provider_continuity_control_pack_v2_independent as governance
from app.mirror import contract_mirror_independent as contract
from app.mirror import denominator_ledger_independent as denominator
from app.mirror import money_mirror_independent as money
from app.mirror import transaction_mirror_independent as transaction
from app.mirror import transition_mirror_independent as transition


ARTIFACT_KIND = "MIRROR_STATE_VALUE_LEDGER_V1"
SCHEMA = "mirror-state-value-ledger-v1"
SCHEMA_VERSION = 1
DOMAIN = "BL/MIRROR/STATE-VALUE/"
MAX_ARTIFACT_BYTES = 262_144
MAX_STRING_BYTES = 8_192
MAX_NODES = 16_384
MAX_DEPTH = 24
MINOR_LIMIT = money.MINOR_LIMIT
HEX128 = re.compile(r"^[0-9a-f]{128}$")

PROFILE_ID = "mirror.state-value.synthetic-counting-once.v1"
PROFILE_VERSION = 1
SUBJECT = "SYNTH_STATE_VALUE_LEDGER_SCOPE_V1"
SCOPE = PROFILE_ID
CURRENCY = money.CURRENCY
UNIT = "MINOR_UNITS"

STAGE_OBSERVED = "VALUE_OBSERVED"
STAGE_RECALCULATED = "VALUE_RECALCULATED"
STAGES = (STAGE_OBSERVED, STAGE_RECALCULATED)

STATUS_COUNTED = "COUNTED_OBSERVED"
STATUS_EXCLUDED = "EXCLUDED"
STATUS_DISPUTED = "DISPUTED"
STATUS_UNKNOWN = "UNKNOWN"
STATUS_REVERSED = "REVERSED"
STATUSES = (STATUS_COUNTED, STATUS_EXCLUDED, STATUS_DISPUTED, STATUS_UNKNOWN, STATUS_REVERSED)

CATEGORY_COUNTED = "OBSERVED_RECONCILIATION_DELTA"
CATEGORY_EXCLUDED = "EXCLUDED_NONVALUE"
CATEGORY_DISPUTED = "DISPUTED_BOUNDARY_VARIANCE"
CATEGORY_UNKNOWN = "UNKNOWN_UNQUALIFIED"
CATEGORY_REVERSED = "OBSERVED_REVERSAL"
CATEGORIES = (CATEGORY_COUNTED, CATEGORY_EXCLUDED, CATEGORY_DISPUTED, CATEGORY_UNKNOWN, CATEGORY_REVERSED)

REASON_ARITHMETIC = "OBSERVED_ARITHMETIC_DELTA_ONLY"
REASON_NEGATIVE_ARITHMETIC = "OBSERVED_NEGATIVE_ARITHMETIC_DELTA"
REASON_ZERO = "ZERO_DELTA_NOT_A_VALUE_CLAIM"
REASON_DIVERGENT = "MONEY_BOUNDARIES_DIVERGE"
REASON_CONFLICTED = "MONEY_EVIDENCE_CONFLICTED"
REASON_INCOMPLETE = "MONEY_EVIDENCE_PARTIAL"
REASON_REVERSAL = "MONEY_REVERSAL_OBSERVED"
REASONS = {
    REASON_ARITHMETIC,
    REASON_NEGATIVE_ARITHMETIC,
    REASON_ZERO,
    REASON_DIVERGENT,
    REASON_CONFLICTED,
    REASON_INCOMPLETE,
    REASON_REVERSAL,
}

EVIDENCE_STRENGTHS = {
    "OBSERVED_OFFICIAL_ARITHMETIC",
    "OBSERVED_NEGATIVE_ARITHMETIC",
    "DISPUTED_OFFICIAL_BOUNDARIES",
    "UNKNOWN_OFFICIAL_COVERAGE",
    "OBSERVED_OFFICIAL_REVERSAL",
}
OWNER_BOUNDARIES = {"UNKNOWN", "SHARED", "STATE_SOURCE", "PLAN_OR_PROVIDER", "RIGHTRAIL_PROCESSING"}
REVIEW_STATES = {"UNREVIEWED", "RECALCULATED"}
RETEST_STATES = {"NOT_RETESTED", "RECALCULATED"}
RECALCULATION_MODES = {"INITIAL", "APPEND_NEW", "RECALCULATE_EXISTING", "REPLACE_EXISTING"}
SIGN_VALUES = {"POSITIVE", "NEGATIVE", "ZERO", "UNKNOWN"}

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
    "state_approval": False,
    "causal_proof": False,
    "cutover_authority": False,
    "automatic_decision_authority": False,
}
FIXED_FLAGS = {
    "read_only": True,
    "observation_only": True,
    "payment_movement": False,
    "settlement_authority": False,
    "clearance_authority": False,
    "payment_authority": False,
    "economic_mutation": False,
    "state_approval": False,
    "causal_inference": False,
    "causal_proof": False,
    "business_truth_proven": False,
    "production_usable": False,
    "synthetic_only": True,
    "activation": False,
    "automatic_decision_authority": False,
    "cutover_authority": False,
    "proofSuiteId": None,
}

MATERIAL_PROFILE = {
    "profile_id": PROFILE_ID,
    "version": PROFILE_VERSION,
    "subject": SUBJECT,
    "scope": SCOPE,
    "currency": CURRENCY,
    "unit": UNIT,
    "categories": list(CATEGORIES),
    "eligibility_statuses": list(STATUSES),
    "formula_id": "OBSERVED_OFFICIAL_NET_MINUS_ADJUDICATED_REFERENCE_V1",
    "formula_version": 1,
    "counting_key": "ONE_CURRENT_ENTRY_PER_TRANSACTION_TRACE",
    "upstream_roles": ["MONEY", "CONTRACT", "DENOMINATOR", "TRANSACTION", "GOVERNANCE"],
    "optional_upstream_roles": ["TRANSITION"],
    "semantics": "OBSERVED_INTEGER_ARITHMETIC_ONLY_NO_CAUSAL_SAVINGS_OR_PAYMENT_AUTHORITY",
    "denominator_semantics": "LINEAGE_BOUND_COMPLETENESS_UNKNOWN_DOES_NOT_PROVE_ABSENCE",
}

TOP_KEYS = {
    "schema", "schema_version", "profile_binding", "subject", "scope", "stage_kind",
    "prior_artifact_id", "prior_stage_id", "upstream_mode", "entries", "aggregate",
    "lineage", "chronology", "recalculation", "flags", "authority", "artifact_id",
    "current_stage_id", "transition_id",
}
PROFILE_KEYS = set(MATERIAL_PROFILE) | {"profile_digest"}
LINEAGE_KEYS = {"upstream_dependencies", "counting_once_rule", "limitations"}
CHRONOLOGY_KEYS = {"observation_time", "effective_start", "effective_end", "current_money_event_time", "status"}
RECALC_KEYS = {"mode", "input_money_artifact_id", "prior_artifact_id", "replaced_value_claim_id", "new_value_claim_id", "identity"}
AGGREGATE_KEYS = {
    "entry_count", "counted_entries", "excluded_entries", "disputed_entries", "unknown_entries", "reversed_entries",
    "counted_minor", "excluded_minor", "disputed_minor", "unknown_minor", "reversed_minor", "currency", "unit",
}
ENTRY_KEYS = {
    "value_claim_id", "economic_event_key", "category", "eligibility_status", "reason_code", "evidence_strength",
    "uncertainty", "owner_boundary", "owner_basis", "review_state", "retest_state", "reversal", "baseline",
    "intervention", "calculation", "upstream", "flags",
}
PERIOD_VALUE_KEYS = {"identity", "period_start", "period_end", "currency", "amount_minor", "source_role"}
CALCULATION_KEYS = {"formula_id", "formula_version", "unit", "delta_minor", "sign", "causal_claim", "assumptions"}
REVERSAL_KEYS = {"status", "source_role", "amount_minor", "predecessor_money_artifact_id"}
ENTRY_FLAGS = {"causal_claim", "payment_authority", "clearance_authority", "production_usable", "state_approval", "automatic_decision_authority"}
REF_KEYS = {"artifact_id", "stage_id", "transition_id", "payload_hash", "profile_id", "profile_version"}
MONEY_REF_KEYS = REF_KEYS | {"money_trace_id"}
TRANSACTION_REF_KEYS = REF_KEYS | {"trace_id"}
DENOMINATOR_REF_KEYS = REF_KEYS | {"population_root"}


class IndependentStateValueLedgerError(ValueError):
    """Stable fail-closed rejection from the State Value verifier."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise IndependentStateValueLedgerError("state-value:noncanonical") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, item in pairs:
        if key in result:
            raise IndependentStateValueLedgerError("state-value:duplicate-key")
        result[key] = item
    return result


def _walk(value: object, *, depth: int = 0, count: list[int] | None = None) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if count[0] > MAX_NODES:
        raise IndependentStateValueLedgerError("state-value:node-cap")
    if depth > MAX_DEPTH:
        raise IndependentStateValueLedgerError("state-value:depth-cap")
    if isinstance(value, float):
        raise IndependentStateValueLedgerError("state-value:float")
    if isinstance(value, str):
        try:
            if len(value.encode("ascii")) > MAX_STRING_BYTES:
                raise IndependentStateValueLedgerError("state-value:string-cap")
        except UnicodeEncodeError as exc:
            raise IndependentStateValueLedgerError("state-value:ascii") from exc
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IndependentStateValueLedgerError("state-value:key-type")
            _walk(key, depth=depth + 1, count=count)
            _walk(item, depth=depth + 1, count=count)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth=depth + 1, count=count)


def _parse(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentStateValueLedgerError("state-value:byte-cap")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(IndependentStateValueLedgerError("state-value:constant")),
        )
    except IndependentStateValueLedgerError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentStateValueLedgerError("state-value:parse") from exc
    if not isinstance(value, dict):
        raise IndependentStateValueLedgerError("state-value:top-level")
    _walk(value)
    if _canonical(value) != raw:
        raise IndependentStateValueLedgerError("state-value:not-canonical")
    return value


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _payload_hash(raw: bytes) -> str:
    return _digest("upstream-payload", raw.hex())


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise IndependentStateValueLedgerError(f"state-value:{label}")
    try:
        if len(value.encode("ascii")) > MAX_STRING_BYTES:
            raise IndependentStateValueLedgerError(f"state-value:{label}")
    except UnicodeEncodeError as exc:
        raise IndependentStateValueLedgerError(f"state-value:{label}") from exc
    return value


def _hex(value: object, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or HEX128.fullmatch(value) is None:
        raise IndependentStateValueLedgerError(f"state-value:{label}")
    return value


def _expect(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise IndependentStateValueLedgerError(f"state-value:{label}-keys")
    return value


def _minor(value: object, label: str, *, nullable: bool = False) -> int | None:
    if nullable and value is None:
        return None
    if type(value) is not int or abs(value) > MINOR_LIMIT:
        raise IndependentStateValueLedgerError(f"state-value:{label}")
    return value


def _time(value: object, label: str, *, nullable: bool = False) -> int | None:
    if nullable and value is None:
        return None
    if type(value) is not int or value < 1 or value > 90_000:
        raise IndependentStateValueLedgerError(f"state-value:{label}")
    return value


def _profile_binding() -> dict[str, object]:
    return {**deepcopy(MATERIAL_PROFILE), "profile_digest": _digest("profile", MATERIAL_PROFILE)}


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
            "recalculation": value["recalculation"],
        },
    )
    transition_id = _digest(
        "transition-id",
        {"artifact_id": artifact_id, "current_stage_id": stage_id, "stage_kind": value["stage_kind"], "recalculation": value["recalculation"]},
    )
    return artifact_id, stage_id, transition_id


def economic_event_key_for(transaction_value: Mapping[str, object]) -> str:
    trace_id = transaction_value.get("trace_id")
    if not isinstance(trace_id, str) or not trace_id:
        raise IndependentStateValueLedgerError("state-value:economic-event-trace")
    return _digest("economic-event-key", {"profile_id": PROFILE_ID, "scope": SCOPE, "transaction_trace_id": trace_id})


def _ref(result: Mapping[str, object], raw: bytes, *, extra: Mapping[str, object] | None = None, transition_id: str | None = None) -> dict[str, object]:
    value = {
        "artifact_id": result["artifact_id"],
        "stage_id": result["current_stage_id"],
        "transition_id": result.get("transition_id") if transition_id is None else transition_id,
        "payload_hash": _payload_hash(raw),
        "profile_id": result.get("profile_id"),
        "profile_version": result.get("profile_version"),
    }
    if extra:
        value.update(extra)
    return value


def _governance_ref(governance_raw: bytes, governance_value: Mapping[str, object], governance_result: Mapping[str, object]) -> dict[str, object]:
    return {
        "artifact_id": governance_result["artifact_id"],
        "stage_id": governance_result["current_stage_id"],
        "transition_id": governance_value["chain_root"],
        "payload_hash": _payload_hash(governance_raw),
        "profile_id": governance_result["profile_id"],
        "profile_version": governance_result["profile_version"],
    }


def _verify_upstream(
    money_raw: bytes,
    money_context: Mapping[str, object],
    *,
    transition_raw: bytes | None,
    transition_context: Mapping[str, object] | None,
    registry: Mapping[str, object],
) -> dict[str, object]:
    try:
        money_value = money._parse(money_raw)
        transaction_raw = money_context["transaction_raw"]
        transaction_context = money_context["transaction_context"]
        if type(transaction_raw) is not bytes or not isinstance(transaction_context, Mapping):
            raise IndependentStateValueLedgerError("state-value:money-context")
        money_result = money.verify_artifact(
            money_raw,
            transaction_raw=transaction_raw,
            transaction_context=transaction_context,
            prior_money_raw=money_context.get("prior_money_raw"),
            registry=registry,
        )
        transaction_value = transaction._parse(transaction_raw)
        transaction_result = transaction.verify_trace_artifact(
            transaction_raw,
            source_raw=transaction_context["source_raw"],
            contract_raw=transaction_context["contract_raw"],
            contract_context=transaction_context["contract_context"],
            observation_raw=transaction_context["observation_raw"],
            registry=registry,
            prior_trace_raw=transaction_context.get("prior_trace_raw"),
            prior_observation_raw=transaction_context.get("prior_observation_raw"),
        )
        contract_raw = transaction_context["contract_raw"]
        contract_context = transaction_context["contract_context"]
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
        denominator_raw = contract_context["denominator_raw"]
        denominator_context = contract_context["denominator_context"]
        denominator_value = denominator._parse(denominator_raw)
        denominator_result = denominator.verify_artifact(
            denominator_raw,
            source_raw=denominator_context["source_raw"],
            graph_raw=denominator_context.get("graph_raw"),
            governance_raw=denominator_context["governance_raw"],
            registry=registry,
            prior_denominator_raw=denominator_context.get("prior_denominator_raw"),
        )
        governance_raw = denominator_context["governance_raw"]
        governance_value = governance._parse(governance_raw)
        governance_result = governance.verify_bytes(governance_raw, registry)
        transition_value = None
        transition_result = None
        if transition_raw is not None:
            if not isinstance(transition_context, Mapping):
                raise IndependentStateValueLedgerError("state-value:transition-context")
            transition_value = transition._parse(transition_raw)
            transition_result = transition.verify_artifact(
                transition_raw,
                money_raw=transition_context["money_raw"],
                money_context=transition_context["money_context"],
                prior_transition_raw=transition_context.get("prior_transition_raw"),
                registry=registry,
            )
            if transition_result.get("transition_money_artifact_id") != money_result["artifact_id"]:
                raise IndependentStateValueLedgerError("state-value:transition-money-binding")
        if money_result["artifact_id"] != money_value["artifact_id"] or transaction_result["artifact_id"] != transaction_value["artifact_id"]:
            raise IndependentStateValueLedgerError("state-value:upstream-identity")
        upstream = {
            "money": _ref(money_result, money_raw, extra={"money_trace_id": money_result["money_trace_id"]}),
            "transaction": _ref(transaction_result, transaction_raw, extra={"trace_id": transaction_value["trace_id"]}),
            "contract": _ref(contract_result, contract_raw),
            "denominator": _ref(denominator_result, denominator_raw, extra={"population_root": denominator_result["population_root"]}),
            "governance": _governance_ref(governance_raw, governance_value, governance_result),
            "transition": _ref(transition_result, transition_raw) if transition_result is not None and transition_raw is not None else None,
        }
        return {
            "money_raw": money_raw,
            "money_value": money_value,
            "money_result": money_result,
            "transaction_raw": transaction_raw,
            "transaction_value": transaction_value,
            "transaction_result": transaction_result,
            "transaction_context": transaction_context,
            "contract_raw": contract_raw,
            "contract_value": contract_value,
            "contract_result": contract_result,
            "contract_context": contract_context,
            "denominator_raw": denominator_raw,
            "denominator_value": denominator_value,
            "denominator_result": denominator_result,
            "governance_raw": governance_raw,
            "governance_value": governance_value,
            "governance_result": governance_result,
            "transition_raw": transition_raw,
            "transition_value": transition_value,
            "transition_result": transition_result,
            "upstream": upstream,
        }
    except IndependentStateValueLedgerError:
        raise
    except Exception as exc:
        raise IndependentStateValueLedgerError("state-value:upstream-reject") from exc


def _sign(value: int | None) -> str:
    if value is None:
        return "UNKNOWN"
    if value > 0:
        return "POSITIVE"
    if value < 0:
        return "NEGATIVE"
    return "ZERO"


def _expected_entry(upstream: Mapping[str, object], *, review_state: str, retest_state: str) -> dict[str, object]:
    money_value = upstream["money_value"]
    money_result = upstream["money_result"]
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
        eligibility, category, reason, strength = STATUS_REVERSED, CATEGORY_REVERSED, REASON_REVERSAL, "OBSERVED_OFFICIAL_REVERSAL"
    elif overall == money.RESULT_CONFLICTED:
        eligibility, category, reason, strength = STATUS_DISPUTED, CATEGORY_DISPUTED, REASON_CONFLICTED, "DISPUTED_OFFICIAL_BOUNDARIES"
    elif overall == money.RESULT_DIVERGENT:
        eligibility, category, reason, strength = STATUS_DISPUTED, CATEGORY_DISPUTED, REASON_DIVERGENT, "DISPUTED_OFFICIAL_BOUNDARIES"
    elif coverage != money.COVERAGE_COMPLETE or delta is None:
        eligibility, category, reason, strength = STATUS_UNKNOWN, CATEGORY_UNKNOWN, REASON_INCOMPLETE, "UNKNOWN_OFFICIAL_COVERAGE"
    elif delta == 0:
        eligibility, category, reason, strength = STATUS_EXCLUDED, CATEGORY_EXCLUDED, REASON_ZERO, "OBSERVED_OFFICIAL_ARITHMETIC"
    elif delta < 0:
        eligibility, category, reason, strength = STATUS_COUNTED, CATEGORY_COUNTED, REASON_NEGATIVE_ARITHMETIC, "OBSERVED_NEGATIVE_ARITHMETIC"
    else:
        eligibility, category, reason, strength = STATUS_COUNTED, CATEGORY_COUNTED, REASON_ARITHMETIC, "OBSERVED_OFFICIAL_ARITHMETIC"
    uncertainty = sorted(["DENOMINATOR_COMPLETENESS_UNKNOWN", "NONMEMBERSHIP_DISABLED", "NO_CAUSAL_INFERENCE"])
    if delta is None:
        uncertainty.append("OFFICIAL_NET_UNKNOWN")
    if eligibility == STATUS_DISPUTED:
        uncertainty.append("OFFICIAL_BOUNDARIES_DIVERGE")
    if eligibility == STATUS_REVERSED:
        uncertainty.append("REVERSAL_OBSERVED")
    uncertainty = sorted(uncertainty)
    obligation = contract_value["obligation"]
    owner = obligation["responsible_boundary"]
    if owner not in OWNER_BOUNDARIES:
        raise IndependentStateValueLedgerError("state-value:owner-boundary")
    period_start = obligation["effective_start"]
    period_end = obligation["effective_end"]
    baseline = {
        "identity": "OFFICIAL_ADJUDICATED_REFERENCE",
        "period_start": period_start,
        "period_end": period_end,
        "currency": CURRENCY,
        "amount_minor": baseline_amount,
        "source_role": money.ROLE_ADJUDICATED,
    }
    intervention = {
        "identity": "OFFICIAL_NET_OBSERVED",
        "period_start": period_start,
        "period_end": period_end,
        "currency": CURRENCY,
        "amount_minor": intervention_amount,
        "source_role": "OFFICIAL_NET_OBSERVED",
    }
    calculation = {
        "formula_id": MATERIAL_PROFILE["formula_id"],
        "formula_version": MATERIAL_PROFILE["formula_version"],
        "unit": UNIT,
        "delta_minor": delta,
        "sign": _sign(delta),
        "causal_claim": False,
        "assumptions": ["OFFICIAL_BOUNDARY_OBSERVATION_ONLY", "NO_CURRENCY_CONVERSION", "NO_CAUSAL_INFERENCE"],
    }
    reversal = {
        "status": "REVERSED" if eligibility == STATUS_REVERSED else "NOT_REVERSED",
        "source_role": money.ROLE_VOID if eligibility == STATUS_REVERSED else None,
        "amount_minor": terms["voided_amount_minor"] if eligibility == STATUS_REVERSED else None,
        "predecessor_money_artifact_id": money_value["prior_artifact_id"] if eligibility == STATUS_REVERSED else None,
    }
    economic_key = economic_event_key_for(transaction_value)
    entry_without_id = {
        "economic_event_key": economic_key,
        "category": category,
        "eligibility_status": eligibility,
        "reason_code": reason,
        "evidence_strength": strength,
        "uncertainty": uncertainty,
        "owner_boundary": owner,
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
    claim_id = _digest("value-claim-id", entry_without_id)
    return {"value_claim_id": claim_id, **entry_without_id}


def _aggregate(entries: list[Mapping[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {"entry_count": len(entries), "currency": CURRENCY, "unit": UNIT}
    for status, label in (
        (STATUS_COUNTED, "counted"),
        (STATUS_EXCLUDED, "excluded"),
        (STATUS_DISPUTED, "disputed"),
        (STATUS_UNKNOWN, "unknown"),
        (STATUS_REVERSED, "reversed"),
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


def _validate_ref(value: object, keys: set[str], label: str) -> None:
    item = _expect(value, keys, label)
    for key in ("artifact_id", "stage_id", "transition_id", "payload_hash"):
        _hex(item[key], f"{label}-{key}")
    _text(item["profile_id"], f"{label}-profile")
    if type(item["profile_version"]) is not int or item["profile_version"] < 1:
        raise IndependentStateValueLedgerError(f"state-value:{label}-version")


def _validate_entry_shape(value: object, index: int) -> dict[str, object]:
    item = _expect(value, ENTRY_KEYS, f"entry-{index}")
    _hex(item["value_claim_id"], f"entry-{index}-claim")
    _hex(item["economic_event_key"], f"entry-{index}-economic-key")
    if item["category"] not in CATEGORIES or item["eligibility_status"] not in STATUSES or item["reason_code"] not in REASONS or item["evidence_strength"] not in EVIDENCE_STRENGTHS:
        raise IndependentStateValueLedgerError(f"state-value:entry-{index}-classification")
    uncertainty = item["uncertainty"]
    if not isinstance(uncertainty, list) or not uncertainty or any(not isinstance(code, str) for code in uncertainty) or uncertainty != sorted(set(uncertainty)):
        raise IndependentStateValueLedgerError(f"state-value:entry-{index}-uncertainty")
    if item["owner_boundary"] not in OWNER_BOUNDARIES or item["owner_basis"] != "CONTRACT_OBLIGATION_RESPONSIBLE_BOUNDARY":
        raise IndependentStateValueLedgerError(f"state-value:entry-{index}-owner")
    if item["review_state"] not in REVIEW_STATES or item["retest_state"] not in RETEST_STATES:
        raise IndependentStateValueLedgerError(f"state-value:entry-{index}-review")
    for label in ("baseline", "intervention"):
        field = _expect(item[label], PERIOD_VALUE_KEYS, f"entry-{index}-{label}")
        _text(field["identity"], f"entry-{index}-{label}-identity")
        _time(field["period_start"], f"entry-{index}-{label}-start")
        _time(field["period_end"], f"entry-{index}-{label}-end")
        if field["period_start"] >= field["period_end"] or field["currency"] != CURRENCY or field["source_role"] == "":
            raise IndependentStateValueLedgerError(f"state-value:entry-{index}-{label}-binding")
        _minor(field["amount_minor"], f"entry-{index}-{label}-amount", nullable=True)
    calculation = _expect(item["calculation"], CALCULATION_KEYS, f"entry-{index}-calculation")
    if calculation["formula_id"] != MATERIAL_PROFILE["formula_id"] or calculation["formula_version"] != MATERIAL_PROFILE["formula_version"] or calculation["unit"] != UNIT or calculation["causal_claim"] is not False:
        raise IndependentStateValueLedgerError(f"state-value:entry-{index}-formula")
    _minor(calculation["delta_minor"], f"entry-{index}-delta", nullable=True)
    if calculation["sign"] not in SIGN_VALUES or calculation["assumptions"] != ["OFFICIAL_BOUNDARY_OBSERVATION_ONLY", "NO_CURRENCY_CONVERSION", "NO_CAUSAL_INFERENCE"]:
        raise IndependentStateValueLedgerError(f"state-value:entry-{index}-calculation-binding")
    reversal = _expect(item["reversal"], REVERSAL_KEYS, f"entry-{index}-reversal")
    if reversal["status"] not in {"REVERSED", "NOT_REVERSED"}:
        raise IndependentStateValueLedgerError(f"state-value:entry-{index}-reversal-status")
    if reversal["source_role"] not in {None, money.ROLE_VOID}:
        raise IndependentStateValueLedgerError(f"state-value:entry-{index}-reversal-role")
    _minor(reversal["amount_minor"], f"entry-{index}-reversal-amount", nullable=True)
    _hex(reversal["predecessor_money_artifact_id"], f"entry-{index}-reversal-prior", nullable=True)
    upstream = _expect(item["upstream"], {"money", "transaction", "contract", "denominator", "governance", "transition"}, f"entry-{index}-upstream")
    _validate_ref(upstream["money"], MONEY_REF_KEYS, f"entry-{index}-money")
    _validate_ref(upstream["transaction"], TRANSACTION_REF_KEYS, f"entry-{index}-transaction")
    _validate_ref(upstream["contract"], REF_KEYS, f"entry-{index}-contract")
    _validate_ref(upstream["denominator"], DENOMINATOR_REF_KEYS, f"entry-{index}-denominator")
    _validate_ref(upstream["governance"], REF_KEYS, f"entry-{index}-governance")
    if upstream["transition"] is not None:
        _validate_ref(upstream["transition"], REF_KEYS, f"entry-{index}-transition")
    if item["flags"] != {
        "causal_claim": False,
        "payment_authority": False,
        "clearance_authority": False,
        "production_usable": False,
        "state_approval": False,
        "automatic_decision_authority": False,
    }:
        raise IndependentStateValueLedgerError(f"state-value:entry-{index}-flags")
    return item


def _validate_shape(value: Mapping[str, object]) -> None:
    if set(value) != TOP_KEYS or value.get("schema") != SCHEMA or value.get("schema_version") != SCHEMA_VERSION:
        raise IndependentStateValueLedgerError("state-value:schema")
    if value["profile_binding"] != _profile_binding() or value["subject"] != SUBJECT or value["scope"] != SCOPE:
        raise IndependentStateValueLedgerError("state-value:profile-binding")
    if value["stage_kind"] not in STAGES:
        raise IndependentStateValueLedgerError("state-value:stage")
    _hex(value["artifact_id"], "artifact-id")
    _hex(value["current_stage_id"], "stage-id")
    _hex(value["transition_id"], "transition-id")
    _hex(value["prior_artifact_id"], "prior-artifact", nullable=True)
    _hex(value["prior_stage_id"], "prior-stage", nullable=True)
    if (value["prior_artifact_id"] is None) != (value["prior_stage_id"] is None):
        raise IndependentStateValueLedgerError("state-value:prior-pair")
    if value["upstream_mode"] != "STORE_SELECTED_EXACT_BYTES":
        raise IndependentStateValueLedgerError("state-value:upstream-mode")
    entries = value["entries"]
    if not isinstance(entries, list) or not entries or len(entries) > 16:
        raise IndependentStateValueLedgerError("state-value:entries")
    for index, item in enumerate(entries):
        _validate_entry_shape(item, index)
    aggregate = _expect(value["aggregate"], AGGREGATE_KEYS, "aggregate")
    if aggregate["currency"] != CURRENCY or aggregate["unit"] != UNIT:
        raise IndependentStateValueLedgerError("state-value:aggregate-units")
    for key in ("entry_count", "counted_entries", "excluded_entries", "disputed_entries", "unknown_entries", "reversed_entries"):
        if type(aggregate[key]) is not int or aggregate[key] < 0 or aggregate[key] > 16:
            raise IndependentStateValueLedgerError(f"state-value:aggregate-{key}")
    for key in ("counted_minor", "excluded_minor", "disputed_minor", "unknown_minor", "reversed_minor"):
        _minor(aggregate[key], f"aggregate-{key}", nullable=True)
    lineage = _expect(value["lineage"], LINEAGE_KEYS, "lineage")
    if lineage != _lineage():
        raise IndependentStateValueLedgerError("state-value:lineage")
    chronology = _expect(value["chronology"], CHRONOLOGY_KEYS, "chronology")
    _time(chronology["observation_time"], "chronology-observation")
    _time(chronology["effective_start"], "chronology-start")
    _time(chronology["effective_end"], "chronology-end")
    _time(chronology["current_money_event_time"], "chronology-money-event", nullable=True)
    if chronology["effective_start"] >= chronology["effective_end"] or chronology["status"] != "BOUNDED_SOURCE_AND_CONTRACT_INTERVAL":
        raise IndependentStateValueLedgerError("state-value:chronology")
    recalculation = _expect(value["recalculation"], RECALC_KEYS, "recalculation")
    if recalculation["mode"] not in RECALCULATION_MODES:
        raise IndependentStateValueLedgerError("state-value:recalculation-mode")
    _hex(recalculation["input_money_artifact_id"], "recalculation-input")
    _hex(recalculation["replaced_value_claim_id"], "recalculation-replaced", nullable=True)
    _hex(recalculation["new_value_claim_id"], "recalculation-new")
    _hex(recalculation["identity"], "recalculation-identity")
    if value["flags"] != FIXED_FLAGS or value["authority"] != AUTHORITY_FLAGS:
        raise IndependentStateValueLedgerError("state-value:authority")


def _validate_entries_against_upstream(
    entries: list[Mapping[str, object]],
    contexts: Mapping[str, Mapping[str, object]],
    *,
    registry: Mapping[str, object],
) -> list[dict[str, object]]:
    expected_entries: list[dict[str, object]] = []
    seen_keys: set[str] = set()
    seen_claims: set[str] = set()
    for index, item in enumerate(entries):
        money_id = item["upstream"]["money"]["artifact_id"]
        context = contexts.get(money_id)
        if not isinstance(context, Mapping) or type(context.get("money_raw")) is not bytes or not isinstance(context.get("money_context"), Mapping):
            raise IndependentStateValueLedgerError("state-value:money-context-missing")
        transition_ref = item["upstream"]["transition"]
        transition_raw = None
        transition_context = None
        if transition_ref is not None:
            transition_contexts = context.get("transition_contexts")
            if not isinstance(transition_contexts, Mapping):
                raise IndependentStateValueLedgerError("state-value:transition-context-missing")
            transition_data = transition_contexts.get(transition_ref["artifact_id"])
            if not isinstance(transition_data, Mapping) or type(transition_data.get("transition_raw")) is not bytes:
                raise IndependentStateValueLedgerError("state-value:transition-bytes-missing")
            transition_raw = transition_data["transition_raw"]
            transition_context = transition_data.get("transition_context")
        upstream = _verify_upstream(
            context["money_raw"],
            context["money_context"],
            transition_raw=transition_raw,
            transition_context=transition_context,
            registry=registry,
        )
        expected = _expected_entry(upstream, review_state=item["review_state"], retest_state=item["retest_state"])
        if dict(item) != expected:
            raise IndependentStateValueLedgerError(f"state-value:entry-{index}-semantic-binding")
        if expected["economic_event_key"] in seen_keys or expected["value_claim_id"] in seen_claims:
            raise IndependentStateValueLedgerError("state-value:counting-key-duplicate")
        seen_keys.add(expected["economic_event_key"])
        seen_claims.add(expected["value_claim_id"])
        expected_entries.append(expected)
    if expected_entries != sorted(expected_entries, key=lambda item: str(item["economic_event_key"])):
        raise IndependentStateValueLedgerError("state-value:entry-order")
    return expected_entries


def _validate_semantics(
    value: Mapping[str, object],
    *,
    money_contexts: Mapping[str, Mapping[str, object]],
    prior_value: Mapping[str, object] | None,
    transition_contexts: Mapping[str, Mapping[str, object]] | None,
    registry: Mapping[str, object],
) -> None:
    contexts = dict(money_contexts)
    for money_id, context in list(contexts.items()):
        if not isinstance(context, Mapping):
            raise IndependentStateValueLedgerError("state-value:context-shape")
        if transition_contexts is not None:
            contexts[money_id] = {**context, "transition_contexts": transition_contexts}
    if prior_value is None:
        if value["stage_kind"] != STAGE_OBSERVED or value["prior_artifact_id"] is not None or value["recalculation"]["mode"] != "INITIAL" or len(value["entries"]) != 1:
            raise IndependentStateValueLedgerError("state-value:initial-binding")
        expected_entries = _validate_entries_against_upstream(value["entries"], contexts, registry=registry)
        current = expected_entries[0]
        expected_recalc = _recalculation("INITIAL", current["upstream"]["money"]["artifact_id"], None, None, current["value_claim_id"])
    else:
        _validate_shape(prior_value)
        if value["stage_kind"] != STAGE_RECALCULATED or value["prior_artifact_id"] != prior_value["artifact_id"] or value["prior_stage_id"] != prior_value["current_stage_id"]:
            raise IndependentStateValueLedgerError("state-value:prior-binding")
        prior_contexts = contexts
        _validate_entries_against_upstream(prior_value["entries"], prior_contexts, registry=registry)
        if prior_value["aggregate"] != _aggregate(prior_value["entries"]):
            raise IndependentStateValueLedgerError("state-value:prior-aggregate")
        current_money_id = value["recalculation"]["input_money_artifact_id"]
        current_context = contexts.get(current_money_id)
        if not isinstance(current_context, Mapping):
            raise IndependentStateValueLedgerError("state-value:recalculation-context")
        transition_ref = None
        if value["entries"]:
            for entry in value["entries"]:
                if entry["upstream"]["money"]["artifact_id"] == current_money_id:
                    transition_ref = entry["upstream"]["transition"]
                    break
        transition_raw = None
        transition_context = None
        if transition_ref is not None:
            data = (transition_contexts or {}).get(transition_ref["artifact_id"])
            if not isinstance(data, Mapping):
                raise IndependentStateValueLedgerError("state-value:recalculation-transition")
            transition_raw, transition_context = data.get("transition_raw"), data.get("transition_context")
        current_upstream = _verify_upstream(
            current_context["money_raw"],
            current_context["money_context"],
            transition_raw=transition_raw,
            transition_context=transition_context,
            registry=registry,
        )
        current_key = economic_event_key_for(current_upstream["transaction_value"])
        prior_by_key = {item["economic_event_key"]: item for item in prior_value["entries"]}
        prior_entry = prior_by_key.get(current_key)
        if prior_entry is None:
            mode, replaced_claim = "APPEND_NEW", None
        elif current_money_id == prior_entry["upstream"]["money"]["artifact_id"]:
            mode, replaced_claim = "RECALCULATE_EXISTING", None
        elif current_upstream["money_value"].get("prior_artifact_id") == prior_entry["upstream"]["money"]["artifact_id"]:
            mode, replaced_claim = "REPLACE_EXISTING", prior_entry["value_claim_id"]
        else:
            raise IndependentStateValueLedgerError("state-value:economic-event-reuse")
        current_entry = _expected_entry(current_upstream, review_state="RECALCULATED", retest_state="RECALCULATED")
        expected_entries_dict = dict(prior_by_key)
        expected_entries_dict[current_key] = current_entry
        expected_entries = sorted(expected_entries_dict.values(), key=lambda item: str(item["economic_event_key"]))
        if list(value["entries"]) != expected_entries:
            raise IndependentStateValueLedgerError("state-value:recalculation-entries")
        expected_recalc = _recalculation(mode, current_money_id, prior_value["artifact_id"], replaced_claim, current_entry["value_claim_id"])
    if value["aggregate"] != _aggregate(expected_entries):
        raise IndependentStateValueLedgerError("state-value:aggregate-binding")
    if value["lineage"] != _lineage() or value["chronology"] != _chronology(_verify_upstream(
        contexts[value["recalculation"]["input_money_artifact_id"]]["money_raw"],
        contexts[value["recalculation"]["input_money_artifact_id"]]["money_context"],
        transition_raw=None,
        transition_context=None,
        registry=registry,
    )):
        raise IndependentStateValueLedgerError("state-value:binding")
    if value["recalculation"] != expected_recalc:
        raise IndependentStateValueLedgerError("state-value:recalculation-binding")
    artifact_id, stage_id, transition_id = _identity_values(value)
    if (value["artifact_id"], value["current_stage_id"], value["transition_id"]) != (artifact_id, stage_id, transition_id):
        raise IndependentStateValueLedgerError("state-value:identity")


def verify_artifact(
    raw: bytes,
    *,
    money_contexts: Mapping[str, Mapping[str, object]],
    prior_value_raw: bytes | None = None,
    transition_contexts: Mapping[str, Mapping[str, object]] | None = None,
    registry: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Reconstruct all value facts from state-selected upstream bytes."""

    value = _parse(raw)
    _validate_shape(value)
    prior_value = _parse(prior_value_raw) if prior_value_raw is not None else None
    _validate_semantics(
        value,
        money_contexts=money_contexts,
        prior_value=prior_value,
        transition_contexts=transition_contexts,
        registry=dict(registry or {}),
    )
    aggregate = value["aggregate"]
    return {
        "kind": ARTIFACT_KIND,
        "schema": SCHEMA,
        "artifact_id": value["artifact_id"],
        "payload": raw,
        "payload_hash": _payload_hash(raw),
        "subject": SUBJECT,
        "scope": SCOPE,
        "report_id": value["artifact_id"],
        "current_stage_id": value["current_stage_id"],
        "transition_id": value["transition_id"],
        "stage_kind": value["stage_kind"],
        "prior_artifact_id": value["prior_artifact_id"],
        "prior_stage_id": value["prior_stage_id"],
        "authority_json": _canonical(AUTHORITY_FLAGS).decode("ascii"),
        "profile_id": PROFILE_ID,
        "profile_version": PROFILE_VERSION,
        "counted_minor": aggregate["counted_minor"],
        "unknown_minor": aggregate["unknown_minor"],
        "disputed_minor": aggregate["disputed_minor"],
        "reversed_minor": aggregate["reversed_minor"],
    }


__all__ = [
    "ARTIFACT_KIND", "AUTHORITY_FLAGS", "CATEGORIES", "CATEGORY_COUNTED", "CATEGORY_DISPUTED", "CATEGORY_EXCLUDED",
    "CATEGORY_REVERSED", "CATEGORY_UNKNOWN", "FIXED_FLAGS", "IndependentStateValueLedgerError", "MAX_ARTIFACT_BYTES",
    "MINOR_LIMIT", "PROFILE_ID", "PROFILE_VERSION", "SCHEMA", "SCHEMA_VERSION", "SCOPE", "STAGE_OBSERVED",
    "STAGE_RECALCULATED", "STAGES", "STATUS_COUNTED", "STATUS_DISPUTED", "STATUS_EXCLUDED", "STATUS_REVERSED",
    "STATUS_UNKNOWN", "SUBJECT", "_canonical", "_digest", "_identity_values", "_parse", "_payload_hash",
    "_profile_binding", "economic_event_key_for", "verify_artifact",
]
