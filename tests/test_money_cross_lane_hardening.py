from __future__ import annotations

import copy
import json
import subprocess
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

import pytest

from app.batch.accumulators import BenefitAccumulator, preview_benefit_claim
from app.batch.batch_orchestrator import (
    BatchConfig,
    _enforce_payment_reconciliation,
    _validate_batch_config,
)
from app.batch.stark_binding import (
    AggregationWitness,
    BatchSlot,
    build_multi_line_service_line_witness,
    claim_output_for_multi_line_witness,
    validate_multi_line_claim_witness,
    verify_aggregation,
)
from app.generator_835 import _x12_amount
from app.ingestion import parse_837
from app.models import ServiceLine
from app.money import MAX_AMOUNT_CENTS, canonical_source_money_cents
from app.operator_portal import _claim_charge_cents_from_edi
from app.rules_engine_adapter import adjudicate as adapter_adjudicate
from app.rules_engine_fallback import adjudicate as python_adjudicate
from app.shared_context import build_shared_context
from tests.test_rules_engine_coverage import base_context, ensure_rust_binary, rust_adjudicate


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module", autouse=True)
def _fresh_rust_rules_engine() -> None:
    ensure_rust_binary()


def _valid_context():
    ctx = copy.deepcopy(base_context())
    ctx.provider.npi = "1999999984"
    return ctx


def _proof_output(ctx):
    return claim_output_for_multi_line_witness(
        build_multi_line_service_line_witness(ctx, config=BatchConfig())
    )


def test_source_money_boundary_accepts_only_canonical_ascii_strings() -> None:
    assert canonical_source_money_cents("0") == 0
    assert canonical_source_money_cents("0.29") == 29
    assert canonical_source_money_cents("42949672.95") == MAX_AMOUNT_CENTS
    for invalid in (0, 0.0, True, Decimal("0"), b"0"):
        with pytest.raises(ValueError, match="money_source_must_be_ascii_string"):
            canonical_source_money_cents(invalid)


def test_one_cent_claim_total_mismatch_is_rejected_exactly_at_ingestion() -> None:
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    edi = payload["edi"].replace("*125.00***11:B:1", "*0.03***11:B:1")
    edi = edi.replace("SV1*HC:99213*125.00", "SV1*HC:99213*0.02")
    parsed = parse_837(edi)
    assert parsed.accepted
    with pytest.raises(ValueError, match="claim_total_mismatch"):
        build_shared_context(parsed, payload["flags"], strict_oracle=False)


@pytest.mark.parametrize("field", ["charge_amount", "units"])
def test_zero_charge_or_units_has_same_private_g8a_denial_in_all_live_semantic_lanes(field: str) -> None:
    ctx = _valid_context()
    setattr(ctx.service_lines[0], field, "0.00")
    if field == "charge_amount":
        ctx.total_charge = "0.00"

    python_result = python_adjudicate(ctx)
    rust_result = rust_adjudicate(ctx)
    proof_output = _proof_output(ctx)

    assert not python_result.approved
    assert python_result.denial_reason == "invalid_charge"
    assert rust_result["approved"] is False
    assert rust_result["denial_reason"] == "invalid_charge"
    assert proof_output["decision"] == 0
    assert proof_output["failure_code"] == 10
    assert proof_output["payment_cents"] == 0


def test_one_zero_line_in_positive_multiline_claim_is_g8a_denial_not_approval() -> None:
    ctx = _valid_context()
    ctx.service_lines = [
        replace(ctx.service_lines[0], line_id="1", charge_amount="0.00"),
        replace(ctx.service_lines[0], line_id="2", charge_amount="125.00"),
    ]
    ctx.total_charge = "125.00"

    assert python_adjudicate(ctx).denial_reason == "invalid_charge"
    assert rust_adjudicate(ctx)["denial_reason"] == "invalid_charge"
    output = _proof_output(ctx)
    assert (output["decision"], output["failure_code"], output["payment_cents"]) == (0, 10, 0)


@pytest.mark.parametrize("value", ["12500", 12500.0, 12500.9, True, Decimal("12500")])
def test_proof_money_fields_reject_alternate_python_types_without_coercion(value: object) -> None:
    bundle = build_multi_line_service_line_witness(_valid_context(), config=BatchConfig())
    forged_line = replace(bundle.service_lines[0], line_charge_cents=value)
    forged = replace(bundle, service_lines=(forged_line, *bundle.service_lines[1:]))
    with pytest.raises(ValueError, match="amount_cents_out_of_range"):
        validate_multi_line_claim_witness(forged)


@pytest.mark.parametrize("value", [True, 12500.0, 12500.9, Decimal("12500")])
def test_rules_adapter_rejects_noninteger_fee_values_before_engine_selection(
    value: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BL_FORCE_PYTHON_RULES_ENGINE", "1")
    with pytest.raises(ValueError, match="policy_row_allowed_cents_not_integer"):
        adapter_adjudicate(_valid_context(), fee_schedule_cents={"99213": value})


def test_rules_adapter_rejects_nontext_fee_codes_before_engine_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BL_FORCE_PYTHON_RULES_ENGINE", "1")
    with pytest.raises(ValueError, match="policy_row_procedure_code_not_string"):
        adapter_adjudicate(_valid_context(), fee_schedule_cents={99213: 12_500})


def test_per_claim_u32_boundary_and_wider_k256_aggregate_are_both_enforced() -> None:
    maximum_slots = [
        BatchSlot(f"synthetic-{index}", index + 1, True, MAX_AMOUNT_CENTS, MAX_AMOUNT_CENTS)
        for index in range(256)
    ]
    maximum = AggregationWitness(maximum_slots, 256, 0, 0, 0, 0)
    assert verify_aggregation(maximum)
    assert sum(slot.payment_amount_cents for slot in maximum_slots) == 256 * MAX_AMOUNT_CENTS

    for invalid in (-1, 1 << 32, True, 1.5):
        slot = BatchSlot("synthetic", 1, True, invalid, invalid)
        with pytest.raises(ValueError, match="amount_cents_out_of_range"):
            verify_aggregation(AggregationWitness([slot], 1, 0, 0, 0, 0))


def test_payment_config_accumulator_and_provider_aggregate_are_integer_only() -> None:
    for invalid in (0.5, True):
        with pytest.raises(ValueError):
            _validate_batch_config(BatchConfig(deductible_cents=invalid))
        with pytest.raises(ValueError):
            _validate_batch_config(BatchConfig(annual_benefit_cap_cents=invalid))
        with pytest.raises(ValueError):
            BenefitAccumulator("MEMBER", 2026, 1000, paid_to_date_cents=invalid)

    accumulator = BenefitAccumulator("MEMBER", 2026, 1000)
    for invalid in (0.5, True, -1, 1 << 32):
        with pytest.raises(ValueError):
            preview_benefit_claim(accumulator, allowed_cents=invalid)

    expected = 256 * MAX_AMOUNT_CENTS
    assert _enforce_payment_reconciliation("provider", [MAX_AMOUNT_CENTS] * 256, expected) == expected
    for invalid in (1.5, True, -1, 1 << 32):
        with pytest.raises(ValueError):
            _enforce_payment_reconciliation("provider", [invalid], invalid)


def test_inconsistent_large_direct_context_cannot_emit_out_of_range_payment() -> None:
    ctx = _valid_context()
    half = "21474836.48"
    ctx.service_lines = [
        replace(ctx.service_lines[0], line_id="1", charge_amount=half),
        replace(ctx.service_lines[0], line_id="2", charge_amount=half),
    ]
    ctx.total_charge = "42949672.95"
    with pytest.raises(ValueError, match="claim_total_out_of_range"):
        python_adjudicate(ctx)
    with pytest.raises(subprocess.CalledProcessError):
        rust_adjudicate(ctx)


def test_audit_and_835_money_views_never_prefix_parse_or_round() -> None:
    assert _claim_charge_cents_from_edi("CLM*X*0.29~") == 29
    assert _claim_charge_cents_from_edi("CLM*X*42949672.95~") == MAX_AMOUNT_CENTS
    for malformed in ("1.005", "1e2", "01", "42949672.96"):
        assert _claim_charge_cents_from_edi(f"CLM*X*{malformed}~") == 0
        with pytest.raises(ValueError, match="malformed_835_amount"):
            _x12_amount(malformed, "synthetic")
    assert _x12_amount("0.29", "synthetic") == "0.29"
