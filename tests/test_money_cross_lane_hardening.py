from __future__ import annotations

import copy
import json
import subprocess
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

import pytest

from app.generator_835 import _x12_amount
from app.ingestion import parse_837
from app.models import ServiceLine
from app.money import MAX_AMOUNT_CENTS, canonical_source_money_cents
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


@pytest.mark.parametrize("value", [True, 12500.0, 12500.9])
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


def test_835_money_view_never_prefix_parse_or_round() -> None:
    for malformed in ("1.005", "1e2", "01", "42949672.96"):
        with pytest.raises(ValueError, match="malformed_835_amount"):
            _x12_amount(malformed, "synthetic")
    assert _x12_amount("0.29", "synthetic") == "0.29"
