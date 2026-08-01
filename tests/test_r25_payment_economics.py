from __future__ import annotations

from dataclasses import replace

import pytest

from experiments.fixed_shape_claim_air.payment import (
    BatchEconomics,
    SlotEconomics,
    derive_batch_economics,
    derive_slot_economics,
)
from experiments.fixed_shape_claim_air.profile import PROFILES, get_profile
from experiments.fixed_shape_claim_air.semantics import SlotKind, StructuralError
from tests.test_r25_fixed_shape_trace import _cover, _real


def test_approval_uses_plan_payable_and_conserves_exact_cents() -> None:
    economics = derive_slot_economics(_real(0))
    assert (
        economics.gross_allowed_cents,
        economics.patient_responsibility_cents,
        economics.plan_payable_cents,
        economics.payer_reserve_debit_cents,
        economics.provider_payable_credit_cents,
    ) == (100, 20, 80, 80, 80)
    assert economics.plan_payable_cents != economics.gross_allowed_cents


def test_denial_and_cover_have_zero_economics() -> None:
    for slot in (_real(0, denied=True), _cover(0)):
        economics = derive_slot_economics(slot)
        assert economics.decision == 0
        assert (
            economics.gross_allowed_cents,
            economics.patient_responsibility_cents,
            economics.plan_payable_cents,
            economics.payer_reserve_debit_cents,
            economics.provider_payable_credit_cents,
        ) == (0, 0, 0, 0, 0)


@pytest.mark.parametrize("profile_id", tuple(PROFILES))
def test_all_profiles_emit_exact_k_economic_records(profile_id: str) -> None:
    profile = get_profile(profile_id)
    batch = derive_batch_economics(
        profile,
        tuple(_cover(index) for index in range(profile.claim_slots)),
    )
    assert len(batch.slots) == profile.claim_slots
    assert batch.total_plan_payable_cents == 0
    assert batch.total_debits_cents == batch.total_credits_cents == 0


@pytest.mark.parametrize("profile_id", tuple(PROFILES))
def test_checked_wide_batch_totals_do_not_narrow_to_u32(profile_id: str) -> None:
    profile = get_profile(profile_id)
    slots = tuple(_real(index) for index in range(profile.claim_slots))
    batch = derive_batch_economics(profile, slots)
    assert batch.total_plan_payable_cents == profile.claim_slots * 80
    assert batch.total_debits_cents == batch.total_credits_cents


@pytest.mark.parametrize(
    ("changes", "error"),
    [
        ({"plan_payable_cents": 81}, "plan_payable_relation_mismatch"),
        ({"payer_reserve_debit_cents": 79}, "slot_conservation_mismatch"),
        ({"provider_payable_credit_cents": 79}, "slot_conservation_mismatch"),
        ({"plan_payable_cents": True}, "out_of_range"),
        ({"plan_payable_cents": -1}, "out_of_range"),
        ({"plan_payable_cents": 1 << 32}, "out_of_range"),
    ],
)
def test_forged_or_noncanonical_slot_economics_fail(
    changes: dict[str, object], error: str
) -> None:
    valid = derive_slot_economics(_real(0))
    with pytest.raises(StructuralError, match=error):
        replace(valid, **changes)


def test_nonapproval_cannot_carry_hidden_economics() -> None:
    with pytest.raises(StructuralError, match="nonapproval_economics_must_be_zero"):
        SlotEconomics(0, SlotKind.COVER, 0, 0, 0, 1, 1, 1)


def test_forged_batch_totals_fail_closed() -> None:
    profile = get_profile("K128_CALIBRATION")
    valid = derive_batch_economics(
        profile,
        tuple(_cover(index) for index in range(profile.claim_slots)),
    )
    assert isinstance(valid, BatchEconomics)
    with pytest.raises(StructuralError, match="batch_plan_payable_total_mismatch"):
        replace(valid, total_plan_payable_cents=1)
