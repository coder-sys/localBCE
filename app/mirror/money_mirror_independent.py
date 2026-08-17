"""Independent verifier for the synthetic Money Mirror V1 artifact.

Money Mirror observes bounded official-boundary evidence.  It is deliberately
not a ledger, settlement engine, payment authority, or State Value calculation.
The verifier owns the fixed synthetic role grammar, integer conservation rule,
and comparison statuses; the producer may only propose canonical bytes.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re
from typing import Mapping

from app.mirror import contract_mirror_independent as contract
from app.mirror import transaction_mirror_independent as transaction


ARTIFACT_KIND = "MIRROR_MONEY_OBSERVATION_V1"
SCHEMA = "mirror-money-observation-v1"
SCHEMA_VERSION = 1
DOMAIN = "BL/MIRROR/MONEY/"
MAX_ARTIFACT_BYTES = 262_144
MAX_STRING_BYTES = 8_192
MINOR_LIMIT = 1_000_000_000_000
HEX128 = re.compile(r"^[0-9a-f]{128}$")

PROFILE_ID = "mirror.money.synthetic-official-observation.v1"
PROFILE_VERSION = 1
CURRENCY = "USD"

ROLE_ADJUDICATED = "ADJUDICATED_REFERENCE"
ROLE_POSTED = "OFFICIAL_POSTED"
ROLE_VOID = "VOID_REVERSAL"
ROLE_ADJUSTMENT = "ADJUSTMENT"
ROLE_REPORT = "OFFICIAL_REPORT"
ROLE_ORDER = (ROLE_ADJUDICATED, ROLE_POSTED, ROLE_VOID, ROLE_ADJUSTMENT, ROLE_REPORT)

STATUS_OBSERVED = "OBSERVED"
STATUS_UNKNOWN = "UNKNOWN"
STATUS_GAPPED = "GAPPED"
STATUS_CONFLICTED = "CONFLICTED"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"
ROLE_STATUSES = (STATUS_OBSERVED, STATUS_UNKNOWN, STATUS_GAPPED, STATUS_CONFLICTED, STATUS_NOT_APPLICABLE)

COVERAGE_COMPLETE = "COMPLETE"
COVERAGE_PARTIAL = "PARTIAL"
COVERAGE_UNKNOWN = "UNKNOWN"

RESULT_MATCHED = "MATCHED"
RESULT_DIVERGENT = "DIVERGENT"
RESULT_PARTIAL = "PARTIAL"
RESULT_UNKNOWN = "UNKNOWN"
RESULT_CONFLICTED = "CONFLICTED"
RESULT_STATUSES = (RESULT_MATCHED, RESULT_DIVERGENT, RESULT_PARTIAL, RESULT_UNKNOWN, RESULT_CONFLICTED)

STAGE_OBSERVED = "MONEY_OBSERVED"
STAGE_VOIDED = "MONEY_VOIDED"
STAGE_ADJUSTED = "MONEY_ADJUSTED"
STAGE_REPORT_MISMATCHED = "MONEY_REPORT_MISMATCHED"
STAGE_CORRECTED = "MONEY_CORRECTED"
STAGES = (STAGE_OBSERVED, STAGE_VOIDED, STAGE_ADJUSTED, STAGE_REPORT_MISMATCHED, STAGE_CORRECTED)

FIXTURE_MATCHED = "SYNTH_MONEY_MATCHED_V1"
FIXTURE_GAPPED = "SYNTH_MONEY_GAPPED_OFFICIAL_V1"
FIXTURE_MISMATCHED = "SYNTH_MONEY_PROCESSOR_OFFICIAL_MISMATCH_V1"
FIXTURE_VOID = "SYNTH_MONEY_VOID_REVERSAL_V1"
FIXTURE_ADJUSTMENT = "SYNTH_MONEY_SIGNED_ADJUSTMENT_V1"
FIXTURE_REPORT_MISMATCH = "SYNTH_MONEY_REPORT_MISMATCH_V1"
FIXTURE_CORRECTION = "SYNTH_MONEY_REPORT_CORRECTION_V1"
FIXTURE_MULTI_CURRENCY = "SYNTH_MONEY_MULTI_CURRENCY_REJECTED_V1"
FIXTURES = (
    FIXTURE_MATCHED,
    FIXTURE_GAPPED,
    FIXTURE_MISMATCHED,
    FIXTURE_VOID,
    FIXTURE_ADJUSTMENT,
    FIXTURE_REPORT_MISMATCH,
    FIXTURE_CORRECTION,
    FIXTURE_MULTI_CURRENCY,
)
INITIAL_FIXTURES = (FIXTURE_MATCHED, FIXTURE_GAPPED, FIXTURE_MISMATCHED)

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
    "official_boundary_authority": False,
    "payment_movement": False,
    "settlement_authority": False,
    "account_balance": False,
    "state_value_claim": False,
    "accounting_claim": False,
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

MONEY_KEYS = {
    "schema", "schema_version", "profile_binding", "money_trace_id", "transaction_binding", "fixture_id",
    "roles", "terms", "comparisons", "evidence_coverage", "chronology", "case_link", "stage_kind",
    "prior_artifact_id", "prior_stage_id", "flags", "authority", "artifact_id", "current_stage_id", "transition_id",
}
PROFILE_KEYS = {"profile_id", "version", "profile_digest"}
TRANSACTION_BINDING_KEYS = {
    "trace_artifact_id", "trace_stage_id", "trace_transition_id", "trace_payload_hash", "trace_id", "contract_binding",
}
ROLE_KEYS = {
    "role", "status", "boundary_id", "provenance_root", "event_time", "effective_time", "currency", "amount_minor",
    "amount_sign", "predecessor_role", "correction_of",
}
TERMS_KEYS = {"currency", "gross_official_posted_minor", "signed_adjustments_minor", "voided_amount_minor", "net_official_observed_minor", "report_amount_minor"}
COMPARISON_KEYS = {"processor_vs_official", "event_chain_conservation", "official_net_vs_report", "overall"}
COMPARISON_ITEM_KEYS = {"status", "reason"}
COVERAGE_KEYS = {"status", "reason"}
CHRONOLOGY_KEYS = {"transaction_observation_time", "effective_start", "effective_end", "event_times", "effective_times"}
CASE_LINK_KEYS = {"case_id", "artifact_id", "stage_id", "transition_id", "finding_id", "lifecycle_state"}


class IndependentMoneyMirrorError(ValueError):
    """Stable fail-closed rejection from the Money Mirror verifier."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise IndependentMoneyMirrorError("money:noncanonical") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IndependentMoneyMirrorError("money:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, *, depth: int = 0, count: list[int] | None = None) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if count[0] > 16_384:
        raise IndependentMoneyMirrorError("money:node-cap")
    if depth > 24:
        raise IndependentMoneyMirrorError("money:depth-cap")
    if isinstance(value, float):
        raise IndependentMoneyMirrorError("money:float")
    if isinstance(value, str):
        try:
            if len(value.encode("ascii")) > MAX_STRING_BYTES:
                raise IndependentMoneyMirrorError("money:string-cap")
        except UnicodeEncodeError as exc:
            raise IndependentMoneyMirrorError("money:ascii") from exc
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IndependentMoneyMirrorError("money:key-type")
            _walk(key, depth=depth + 1, count=count)
            _walk(item, depth=depth + 1, count=count)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth=depth + 1, count=count)


def _parse(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentMoneyMirrorError("money:byte-cap")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(IndependentMoneyMirrorError("money:constant")),
        )
    except IndependentMoneyMirrorError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentMoneyMirrorError("money:parse") from exc
    if not isinstance(value, dict):
        raise IndependentMoneyMirrorError("money:top-level")
    _walk(value)
    if _canonical(value) != raw:
        raise IndependentMoneyMirrorError("money:not-canonical")
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
        raise IndependentMoneyMirrorError(f"money:{label}")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise IndependentMoneyMirrorError(f"money:{label}") from exc
    return value


def _hex(value: object, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or HEX128.fullmatch(value) is None:
        raise IndependentMoneyMirrorError(f"money:{label}")
    return value


def _expect(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise IndependentMoneyMirrorError(f"money:{label}-keys")
    return value


def _bounded_minor(value: object, label: str, *, nullable: bool = False, nonnegative: bool = True) -> int | None:
    if nullable and value is None:
        return None
    if type(value) is not int or abs(value) > MINOR_LIMIT or (nonnegative and value < 0):
        raise IndependentMoneyMirrorError(f"money:{label}")
    return value


def _bounded_time(value: object, label: str, *, nullable: bool = False) -> int | None:
    if nullable and value is None:
        return None
    if type(value) is not int or value < 1 or value > 90_000:
        raise IndependentMoneyMirrorError(f"money:{label}")
    return value


def _profile_binding() -> dict[str, object]:
    material = {
        "profile_id": PROFILE_ID,
        "version": PROFILE_VERSION,
        "currency": CURRENCY,
        "role_order": list(ROLE_ORDER),
        "role_statuses": list(ROLE_STATUSES),
        "result_statuses": list(RESULT_STATUSES),
        "fixture_ids": list(FIXTURES),
        "equation": "gross_official_posted_minor+signed_adjustments_minor-voided_amount_minor=net_official_observed_minor",
        "semantics": "READ_ONLY_OFFICIAL_BOUNDARY_OBSERVATION_NO_SETTLEMENT",
    }
    return {**material, "profile_digest": _digest("profile", material)}


def money_trace_id_for(transaction_raw: bytes) -> str:
    value = transaction._parse(transaction_raw)
    if value.get("schema") != transaction.TRACE_SCHEMA:
        raise IndependentMoneyMirrorError("money:trace-kind")
    return _digest("money-trace-id", {"profile_id": PROFILE_ID, "profile_version": PROFILE_VERSION, "trace_id": value["trace_id"], "trace_artifact_id": value["artifact_id"], "trace_payload_hash": _payload_hash(transaction_raw)})


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
    return _role(role, STATUS_NOT_APPLICABLE, boundary_id, None, None, None, None)


def _expected_roles(fixture_id: str) -> list[dict[str, object]]:
    if fixture_id == FIXTURE_MULTI_CURRENCY:
        return [
            _role(ROLE_ADJUDICATED, STATUS_OBSERVED, "SYNTH_OFFICIAL_ADJUDICATION_BOUNDARY_V1", 7_100, 7_100, CURRENCY, 12_500),
            _role(ROLE_POSTED, STATUS_OBSERVED, "SYNTH_OFFICIAL_PAYMENT_RAIL_BOUNDARY_V1", 7_110, 7_110, CURRENCY, 12_500),
            _na(ROLE_VOID, "SYNTH_OFFICIAL_REVERSAL_BOUNDARY_V1"),
            _na(ROLE_ADJUSTMENT, "SYNTH_OFFICIAL_ADJUSTMENT_BOUNDARY_V1"),
            _role(ROLE_REPORT, STATUS_OBSERVED, "SYNTH_OFFICIAL_REPORTING_BOUNDARY_V1", 7_120, 7_120, "EUR", 12_500),
        ]
    if fixture_id == FIXTURE_GAPPED:
        return [
            _role(ROLE_ADJUDICATED, STATUS_OBSERVED, "SYNTH_OFFICIAL_ADJUDICATION_BOUNDARY_V1", 7_100, 7_100, CURRENCY, 12_500),
            _role(ROLE_POSTED, STATUS_GAPPED, "SYNTH_OFFICIAL_PAYMENT_RAIL_BOUNDARY_V1", None, None, None, None),
            _na(ROLE_VOID, "SYNTH_OFFICIAL_REVERSAL_BOUNDARY_V1"),
            _na(ROLE_ADJUSTMENT, "SYNTH_OFFICIAL_ADJUSTMENT_BOUNDARY_V1"),
            _role(ROLE_REPORT, STATUS_GAPPED, "SYNTH_OFFICIAL_REPORTING_BOUNDARY_V1", None, None, None, None),
        ]
    if fixture_id == FIXTURE_MISMATCHED:
        posted = 0
        report = 0
    elif fixture_id in {FIXTURE_ADJUSTMENT, FIXTURE_REPORT_MISMATCH, FIXTURE_CORRECTION}:
        posted = 12_500
        report = 13_000 if fixture_id in {FIXTURE_ADJUSTMENT, FIXTURE_CORRECTION} else 12_000
    else:
        posted = 12_500
        report = 12_500
    adjustment = _na(ROLE_ADJUSTMENT, "SYNTH_OFFICIAL_ADJUSTMENT_BOUNDARY_V1")
    if fixture_id in {FIXTURE_ADJUSTMENT, FIXTURE_REPORT_MISMATCH, FIXTURE_CORRECTION}:
        adjustment = _role(ROLE_ADJUSTMENT, STATUS_OBSERVED, "SYNTH_OFFICIAL_ADJUSTMENT_BOUNDARY_V1", 7_115, 7_115, CURRENCY, 500, "POSITIVE", ROLE_POSTED)
    void = _na(ROLE_VOID, "SYNTH_OFFICIAL_REVERSAL_BOUNDARY_V1")
    if fixture_id == FIXTURE_VOID:
        report = 0
        void = _role(ROLE_VOID, STATUS_OBSERVED, "SYNTH_OFFICIAL_REVERSAL_BOUNDARY_V1", 7_115, 7_115, CURRENCY, 12_500, None, ROLE_POSTED)
    report_role = _role(ROLE_REPORT, STATUS_OBSERVED, "SYNTH_OFFICIAL_REPORTING_BOUNDARY_V1", 7_120, 7_120, CURRENCY, report)
    if fixture_id == FIXTURE_CORRECTION:
        report_role["correction_of"] = ROLE_REPORT
        body = dict(report_role)
        body.pop("provenance_root")
        report_role["provenance_root"] = _digest("role-root", body)
    return [
        _role(ROLE_ADJUDICATED, STATUS_OBSERVED, "SYNTH_OFFICIAL_ADJUDICATION_BOUNDARY_V1", 7_100, 7_100, CURRENCY, 12_500),
        _role(ROLE_POSTED, STATUS_OBSERVED, "SYNTH_OFFICIAL_PAYMENT_RAIL_BOUNDARY_V1", 7_110, 7_110, CURRENCY, posted),
        void,
        adjustment,
        report_role,
    ]


def _derive_terms(roles: list[Mapping[str, object]]) -> dict[str, object]:
    posted, void, adjustment, report = roles[1], roles[2], roles[3], roles[4]
    complete = all(item["status"] in {STATUS_OBSERVED, STATUS_NOT_APPLICABLE} for item in roles)
    if not complete or posted["status"] != STATUS_OBSERVED:
        return {"currency": CURRENCY, "gross_official_posted_minor": None, "signed_adjustments_minor": None, "voided_amount_minor": None, "net_official_observed_minor": None, "report_amount_minor": None}
    gross = int(posted["amount_minor"])
    signed = 0
    if adjustment["status"] == STATUS_OBSERVED:
        signed = int(adjustment["amount_minor"]) * (1 if adjustment["amount_sign"] == "POSITIVE" else -1)
    elif adjustment["status"] != STATUS_NOT_APPLICABLE:
        return {"currency": CURRENCY, "gross_official_posted_minor": None, "signed_adjustments_minor": None, "voided_amount_minor": None, "net_official_observed_minor": None, "report_amount_minor": None}
    voided = int(void["amount_minor"]) if void["status"] == STATUS_OBSERVED else 0
    if void["status"] not in {STATUS_OBSERVED, STATUS_NOT_APPLICABLE}:
        return {"currency": CURRENCY, "gross_official_posted_minor": None, "signed_adjustments_minor": None, "voided_amount_minor": None, "net_official_observed_minor": None, "report_amount_minor": None}
    net = gross + signed - voided
    if abs(net) > MINOR_LIMIT or net < 0:
        raise IndependentMoneyMirrorError("money:conservation-overflow")
    report_amount = int(report["amount_minor"]) if report["status"] == STATUS_OBSERVED else None
    return {"currency": CURRENCY, "gross_official_posted_minor": gross, "signed_adjustments_minor": signed, "voided_amount_minor": voided, "net_official_observed_minor": net, "report_amount_minor": report_amount}


def _comparison(status: str, reason: str) -> dict[str, object]:
    return {"status": status, "reason": reason}


def _derive_comparisons(roles: list[Mapping[str, object]], observation_value: Mapping[str, object]) -> dict[str, object]:
    evidence = observation_value["evidence"]
    processor = evidence["processor"]
    official = evidence["official"]
    if processor["status"] != transaction.STATUS_OBSERVED or official["status"] != transaction.STATUS_OBSERVED:
        processor_result = _comparison(RESULT_UNKNOWN, "PROCESSOR_OR_OFFICIAL_EVIDENCE_MISSING")
    elif (processor["amount_minor"], processor["currency"]) != (official["amount_minor"], official["currency"]):
        processor_result = _comparison(RESULT_DIVERGENT, "PROCESSOR_VS_OFFICIAL_DIFFER")
    else:
        processor_result = _comparison(RESULT_MATCHED, "PROCESSOR_VS_OFFICIAL_MATCHED")
    terms = _derive_terms(roles)
    if terms["net_official_observed_minor"] is None:
        event_result = _comparison(RESULT_UNKNOWN, "OFFICIAL_EVENT_CHAIN_INCOMPLETE")
    else:
        event_result = _comparison(RESULT_MATCHED, "OFFICIAL_EVENT_CHAIN_CONSERVES")
    report = roles[4]
    if terms["net_official_observed_minor"] is None or report["status"] != STATUS_OBSERVED:
        report_result = _comparison(RESULT_UNKNOWN, "OFFICIAL_REPORT_EVIDENCE_MISSING")
    elif terms["net_official_observed_minor"] == terms["report_amount_minor"] and report["currency"] == CURRENCY:
        report_result = _comparison(RESULT_MATCHED, "OFFICIAL_NET_EQUALS_REPORT")
    else:
        report_result = _comparison(RESULT_DIVERGENT, "OFFICIAL_NET_DIFFERS_FROM_REPORT")
    statuses = (processor_result["status"], event_result["status"], report_result["status"])
    if RESULT_CONFLICTED in statuses:
        overall = _comparison(RESULT_CONFLICTED, "MONEY_EVIDENCE_CONFLICTED")
    elif RESULT_DIVERGENT in statuses:
        overall = _comparison(RESULT_DIVERGENT, "MONEY_BOUNDARIES_DIVERGE")
    elif RESULT_UNKNOWN in statuses:
        overall = _comparison(RESULT_PARTIAL, "MONEY_EVIDENCE_PARTIAL")
    else:
        overall = _comparison(RESULT_MATCHED, "MONEY_BOUNDARIES_MATCHED")
    return {"processor_vs_official": processor_result, "event_chain_conservation": event_result, "official_net_vs_report": report_result, "overall": overall}


def _derive_coverage(roles: list[Mapping[str, object]]) -> dict[str, object]:
    if any(item["status"] in {STATUS_CONFLICTED, STATUS_GAPPED} for item in roles):
        return {"status": COVERAGE_PARTIAL, "reason": "OFFICIAL_MONEY_EVIDENCE_PARTIAL"}
    if any(item["status"] == STATUS_UNKNOWN for item in roles):
        return {"status": COVERAGE_UNKNOWN, "reason": "OFFICIAL_MONEY_EVIDENCE_UNKNOWN"}
    return {"status": COVERAGE_COMPLETE, "reason": "ALL_FIXED_MONEY_ROLES_ACCOUNTED"}


def _derive_chronology(roles: list[Mapping[str, object]], transaction_value: Mapping[str, object], contract_value: Mapping[str, object]) -> dict[str, object]:
    times = [item["event_time"] for item in roles if item["event_time"] is not None]
    effective = [item["effective_time"] for item in roles if item["effective_time"] is not None]
    chronology = {
        "transaction_observation_time": transaction_value["input_binding"]["observation_time"],
        "effective_start": contract_value["obligation"]["effective_start"],
        "effective_end": contract_value["obligation"]["effective_end"],
        "event_times": times,
        "effective_times": effective,
    }
    if times != sorted(times) or len(times) != len(set(times)) or effective != sorted(effective) or len(effective) != len(set(effective)):
        raise IndependentMoneyMirrorError("money:chronology-order")
    start, end = chronology["effective_start"], chronology["effective_end"]
    if any(item < start or item >= end for item in [chronology["transaction_observation_time"], *times, *effective]):
        raise IndependentMoneyMirrorError("money:chronology-interval")
    return chronology


def _identity_values(value: Mapping[str, object]) -> tuple[str, str, str]:
    body = deepcopy(dict(value))
    body.pop("artifact_id", None)
    body.pop("current_stage_id", None)
    body.pop("transition_id", None)
    artifact_id = _digest("artifact-id", body)
    stage_id = _digest("stage-id", {"artifact_id": artifact_id, "stage_kind": value["stage_kind"], "prior_artifact_id": value["prior_artifact_id"], "prior_stage_id": value["prior_stage_id"], "money_trace_id": value["money_trace_id"]})
    transition_id = _digest("transition-id", {"artifact_id": artifact_id, "current_stage_id": stage_id, "stage_kind": value["stage_kind"], "prior_artifact_id": value["prior_artifact_id"], "prior_stage_id": value["prior_stage_id"]})
    return artifact_id, stage_id, transition_id


def _validate_profile(value: Mapping[str, object]) -> None:
    if value != _profile_binding():
        raise IndependentMoneyMirrorError("money:profile-binding")


def _validate_transaction_binding(value: Mapping[str, object], transaction_value: Mapping[str, object], contract_value: Mapping[str, object], transaction_raw: bytes) -> None:
    expected = {
        "trace_artifact_id": transaction_value["artifact_id"],
        "trace_stage_id": transaction_value["current_stage_id"],
        "trace_transition_id": transaction_value["transition_id"],
        "trace_payload_hash": _payload_hash(transaction_raw),
        "trace_id": transaction_value["trace_id"],
        "contract_binding": transaction._contract_binding(bytes(transaction_raw), contract_value),
    }
    if dict(value) != expected:
        raise IndependentMoneyMirrorError("money:transaction-binding")


def _validate_role(value: object, expected: Mapping[str, object], index: int) -> dict[str, object]:
    item = _expect(value, ROLE_KEYS, f"money-role-{index}")
    if item != expected:
        raise IndependentMoneyMirrorError(f"money:role-{index}-binding")
    _text(item["role"], f"role-{index}-name")
    if item["status"] not in ROLE_STATUSES:
        raise IndependentMoneyMirrorError(f"money:role-{index}-status")
    _text(item["boundary_id"], f"role-{index}-boundary")
    _hex(item["provenance_root"], f"role-{index}-root")
    _bounded_time(item["event_time"], f"role-{index}-event", nullable=True)
    _bounded_time(item["effective_time"], f"role-{index}-effective", nullable=True)
    if item["currency"] is not None:
        _text(item["currency"], f"role-{index}-currency")
    _bounded_minor(item["amount_minor"], f"role-{index}-amount", nullable=True)
    if item["amount_sign"] not in {None, "POSITIVE", "NEGATIVE"}:
        raise IndependentMoneyMirrorError(f"money:role-{index}-sign")
    if item["amount_minor"] == 0 and item["amount_sign"] == "NEGATIVE":
        raise IndependentMoneyMirrorError("money:negative-zero")
    for key in ("predecessor_role", "correction_of"):
        if item[key] is not None:
            _text(item[key], f"role-{index}-{key}")
    return item


def _validate_shape(value: Mapping[str, object]) -> None:
    if set(value) != MONEY_KEYS or value.get("schema") != SCHEMA or value.get("schema_version") != SCHEMA_VERSION:
        raise IndependentMoneyMirrorError("money:schema")
    _validate_profile(_expect(value["profile_binding"], PROFILE_KEYS | {"currency", "role_order", "role_statuses", "result_statuses", "fixture_ids", "equation", "semantics"}, "money-profile"))
    _hex(value["money_trace_id"], "trace-id")
    _text(value["fixture_id"], "fixture")
    if value["fixture_id"] not in FIXTURES:
        raise IndependentMoneyMirrorError("money:fixture")
    _hex(value["artifact_id"], "artifact-id")
    _hex(value["current_stage_id"], "stage-id")
    _hex(value["transition_id"], "transition-id")
    _hex(value["prior_artifact_id"], "prior-artifact", nullable=True)
    _hex(value["prior_stage_id"], "prior-stage", nullable=True)
    if (value["prior_artifact_id"] is None) != (value["prior_stage_id"] is None):
        raise IndependentMoneyMirrorError("money:prior-pair")
    if value["stage_kind"] not in STAGES:
        raise IndependentMoneyMirrorError("money:stage")
    roles = value["roles"]
    if not isinstance(roles, list) or len(roles) != len(ROLE_ORDER):
        raise IndependentMoneyMirrorError("money:roles")
    for item in roles:
        if not isinstance(item, dict):
            raise IndependentMoneyMirrorError("money:role-shape")
    terms = _expect(value["terms"], TERMS_KEYS, "money-terms")
    _text(terms["currency"], "terms-currency")
    for key in TERMS_KEYS - {"currency"}:
        _bounded_minor(terms[key], f"terms-{key}", nullable=True, nonnegative=(key != "signed_adjustments_minor"))
    comparisons = _expect(value["comparisons"], COMPARISON_KEYS, "money-comparisons")
    for key in COMPARISON_KEYS:
        item = _expect(comparisons[key], COMPARISON_ITEM_KEYS, f"money-comparison-{key}")
        if item["status"] not in RESULT_STATUSES:
            raise IndependentMoneyMirrorError(f"money-comparison-{key}-status")
        _text(item["reason"], f"money-comparison-{key}-reason")
    coverage = _expect(value["evidence_coverage"], COVERAGE_KEYS, "money-coverage")
    if coverage["status"] not in {COVERAGE_COMPLETE, COVERAGE_PARTIAL, COVERAGE_UNKNOWN}:
        raise IndependentMoneyMirrorError("money:coverage-status")
    _text(coverage["reason"], "money-coverage-reason")
    chronology = _expect(value["chronology"], CHRONOLOGY_KEYS, "money-chronology")
    _bounded_time(chronology["transaction_observation_time"], "money-chronology-transaction")
    for key in ("effective_start", "effective_end"):
        _bounded_time(chronology[key], f"money-chronology-{key}")
    for key in ("event_times", "effective_times"):
        if not isinstance(chronology[key], list) or any(type(item) is not int for item in chronology[key]):
            raise IndependentMoneyMirrorError("money:chronology-times")
    if value["case_link"] is not None:
        case = _expect(value["case_link"], CASE_LINK_KEYS, "money-case")
        for key in ("case_id", "artifact_id", "stage_id", "transition_id", "finding_id"):
            _hex(case[key], f"money-case-{key}")
        _text(case["lifecycle_state"], "money-case-state")
    if value["flags"] != FIXED_FLAGS or value["authority"] != AUTHORITY_FLAGS:
        raise IndependentMoneyMirrorError("money:authority")


def _stage_for_fixture(fixture_id: str) -> str:
    return {
        FIXTURE_MATCHED: STAGE_OBSERVED,
        FIXTURE_GAPPED: STAGE_OBSERVED,
        FIXTURE_MISMATCHED: STAGE_OBSERVED,
        FIXTURE_VOID: STAGE_VOIDED,
        FIXTURE_ADJUSTMENT: STAGE_ADJUSTED,
        FIXTURE_REPORT_MISMATCH: STAGE_REPORT_MISMATCHED,
        FIXTURE_CORRECTION: STAGE_CORRECTED,
    }.get(fixture_id, STAGE_OBSERVED)


def _expected_case_link(contract_value: Mapping[str, object], comparisons: Mapping[str, object]) -> dict[str, object] | None:
    if comparisons["overall"]["status"] != RESULT_DIVERGENT:
        return None
    case_link = contract_value.get("case_link")
    if not isinstance(case_link, dict) or set(case_link) != CASE_LINK_KEYS:
        raise IndependentMoneyMirrorError("money:case-link")
    return dict(case_link)


def _validate_value(value: Mapping[str, object], *, transaction_value: Mapping[str, object], contract_value: Mapping[str, object], observation_value: Mapping[str, object], transaction_raw: bytes, prior_value: Mapping[str, object] | None, allow_existing_prior: bool = False) -> None:
    _validate_shape(value)
    if value["fixture_id"] == FIXTURE_MULTI_CURRENCY:
        raise IndependentMoneyMirrorError("money:currency-mismatch")
    expected_roles = _expected_roles(value["fixture_id"])
    roles = [_validate_role(item, expected_roles[index], index) for index, item in enumerate(value["roles"])]
    if [item["role"] for item in roles] != list(ROLE_ORDER) or len({item["role"] for item in roles}) != len(ROLE_ORDER):
        raise IndependentMoneyMirrorError("money:role-order")
    expected_terms = _derive_terms(roles)
    expected_comparisons = _derive_comparisons(roles, observation_value)
    expected_coverage = _derive_coverage(roles)
    expected_chronology = _derive_chronology(roles, transaction_value, contract_value)
    if value["terms"] != expected_terms:
        raise IndependentMoneyMirrorError("money:terms-binding")
    if value["comparisons"] != expected_comparisons:
        raise IndependentMoneyMirrorError("money:comparison-binding")
    if value["evidence_coverage"] != expected_coverage:
        raise IndependentMoneyMirrorError("money:coverage-binding")
    if value["chronology"] != expected_chronology:
        raise IndependentMoneyMirrorError("money:chronology-binding")
    if value["stage_kind"] != _stage_for_fixture(value["fixture_id"]):
        raise IndependentMoneyMirrorError("money:stage-binding")
    if value["prior_artifact_id"] is None and value["fixture_id"] not in INITIAL_FIXTURES:
        raise IndependentMoneyMirrorError("money:prior-required")
    if value["prior_artifact_id"] is not None and value["fixture_id"] in INITIAL_FIXTURES:
        raise IndependentMoneyMirrorError("money:initial-prior")
    if prior_value is not None:
        if prior_value["money_trace_id"] != value["money_trace_id"]:
            raise IndependentMoneyMirrorError("money:prior-trace")
        if (value["prior_artifact_id"], value["prior_stage_id"]) != (prior_value["artifact_id"], prior_value["current_stage_id"]):
            raise IndependentMoneyMirrorError("money:prior-binding")
        allowed = {
            FIXTURE_VOID: {FIXTURE_MATCHED},
            FIXTURE_ADJUSTMENT: {FIXTURE_MATCHED},
            FIXTURE_REPORT_MISMATCH: {FIXTURE_MATCHED, FIXTURE_ADJUSTMENT},
            FIXTURE_CORRECTION: {FIXTURE_REPORT_MISMATCH},
        }.get(value["fixture_id"], set())
        if prior_value["fixture_id"] not in allowed:
            raise IndependentMoneyMirrorError("money:prior-stage")
    elif value["prior_artifact_id"] is not None and not allow_existing_prior:
        raise IndependentMoneyMirrorError("money:prior-missing")
    expected_case = _expected_case_link(contract_value, expected_comparisons)
    if value["case_link"] != expected_case:
        raise IndependentMoneyMirrorError("money:case-binding")
    artifact_id, stage_id, transition_id = _identity_values(value)
    if (value["artifact_id"], value["current_stage_id"], value["transition_id"]) != (artifact_id, stage_id, transition_id):
        raise IndependentMoneyMirrorError("money:identity")


def _transaction_binding(transaction_raw: bytes, transaction_value: Mapping[str, object], contract_value: Mapping[str, object]) -> dict[str, object]:
    return {
        "trace_artifact_id": transaction_value["artifact_id"],
        "trace_stage_id": transaction_value["current_stage_id"],
        "trace_transition_id": transaction_value["transition_id"],
        "trace_payload_hash": _payload_hash(transaction_raw),
        "trace_id": transaction_value["trace_id"],
        "contract_binding": transaction._contract_binding(bytes(transaction_raw), contract_value),
    }


def verify_artifact(
    raw: bytes,
    *,
    transaction_raw: bytes,
    transaction_context: Mapping[str, object],
    prior_money_raw: bytes | None = None,
    registry: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Reconstruct the stored Transaction Trace and independently verify money bytes."""

    value = _parse(raw)
    _validate_shape(value)
    if not isinstance(transaction_context, Mapping):
        raise IndependentMoneyMirrorError("money:transaction-context")
    try:
        transaction_value = transaction._parse(transaction_raw)
        if transaction_value.get("schema") != transaction.TRACE_SCHEMA:
            raise IndependentMoneyMirrorError("money:trace-kind")
        transaction_result = transaction.verify_trace_artifact(
            transaction_raw,
            source_raw=transaction_context["source_raw"],
            contract_raw=transaction_context["contract_raw"],
            contract_context=transaction_context["contract_context"],
            observation_raw=transaction_context["observation_raw"],
            registry=registry or {},
            prior_trace_raw=transaction_context.get("prior_trace_raw"),
            prior_observation_raw=transaction_context.get("prior_observation_raw"),
        )
        contract_object = transaction._parse(transaction_context["contract_raw"])
        observation_value = transaction._parse(transaction_context["observation_raw"])
    except IndependentMoneyMirrorError:
        raise
    except Exception as exc:
        raise IndependentMoneyMirrorError("money:transaction-reject") from exc
    expected_trace_id = money_trace_id_for(transaction_raw)
    if value["money_trace_id"] != expected_trace_id:
        raise IndependentMoneyMirrorError("money:trace-id")
    _validate_transaction_binding(value["transaction_binding"], transaction_value, contract_object, transaction_raw)
    if transaction_result["artifact_id"] != transaction_value["artifact_id"]:
        raise IndependentMoneyMirrorError("money:trace-receipt")
    prior_value = None
    if prior_money_raw is not None:
        prior_value = _parse(prior_money_raw)
        _validate_value(
            prior_value,
            transaction_value=transaction_value,
            contract_value=contract_object,
            observation_value=observation_value,
            transaction_raw=transaction_raw,
            prior_value=None,
            allow_existing_prior=True,
        )
    _validate_value(
        value,
        transaction_value=transaction_value,
        contract_value=contract_object,
        observation_value=observation_value,
        transaction_raw=transaction_raw,
        prior_value=prior_value,
    )
    return {
        "kind": ARTIFACT_KIND,
        "schema": SCHEMA,
        "artifact_id": value["artifact_id"],
        "payload": raw,
        "payload_hash": _payload_hash(raw),
        "subject": value["money_trace_id"],
        "scope": PROFILE_ID,
        "report_id": value["money_trace_id"],
        "current_stage_id": value["current_stage_id"],
        "transition_id": value["transition_id"],
        "stage_kind": value["stage_kind"],
        "prior_artifact_id": value["prior_artifact_id"],
        "prior_stage_id": value["prior_stage_id"],
        "authority_json": _canonical(AUTHORITY_FLAGS).decode("ascii"),
        "profile_id": PROFILE_ID,
        "profile_version": PROFILE_VERSION,
        "money_trace_id": value["money_trace_id"],
        "transaction_trace_artifact_id": transaction_value["artifact_id"],
        "transaction_contract_artifact_id": contract_object["artifact_id"],
        "result_status": value["comparisons"]["overall"]["status"],
        "event_status": value["comparisons"]["event_chain_conservation"]["status"],
        "report_status": value["comparisons"]["official_net_vs_report"]["status"],
        "case_artifact_id": value["case_link"]["artifact_id"] if value["case_link"] is not None else None,
    }


__all__ = [
    "ARTIFACT_KIND", "AUTHORITY_FLAGS", "CURRENCY", "FIXED_FLAGS", "FIXTURE_ADJUSTMENT", "FIXTURE_CORRECTION",
    "FIXTURE_GAPPED", "FIXTURE_MATCHED", "FIXTURE_MISMATCHED", "FIXTURE_MULTI_CURRENCY", "FIXTURE_REPORT_MISMATCH",
    "FIXTURE_VOID", "INITIAL_FIXTURES", "IndependentMoneyMirrorError", "MAX_ARTIFACT_BYTES", "MINOR_LIMIT",
    "PROFILE_ID", "PROFILE_VERSION", "RESULT_CONFLICTED", "RESULT_DIVERGENT", "RESULT_MATCHED", "RESULT_PARTIAL",
    "RESULT_UNKNOWN", "SCHEMA", "SCHEMA_VERSION", "STAGE_ADJUSTED", "STAGE_CORRECTED", "STAGE_OBSERVED",
    "STAGE_REPORT_MISMATCHED", "STAGE_VOIDED", "STATUS_CONFLICTED", "STATUS_GAPPED", "STATUS_NOT_APPLICABLE",
    "STATUS_OBSERVED", "STATUS_UNKNOWN", "_canonical", "_digest", "_identity_values", "_parse", "_payload_hash",
    "_profile_binding", "money_trace_id_for", "verify_artifact",
]
