from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512
import os
from unittest import mock

import pytest

from experiments.fixed_shape_claim_air.authenticated_payment_reference import (
    AuthenticatedPaymentState,
    build_authenticated_payment_transition,
    verify_authenticated_payment_transition,
)
from experiments.fixed_shape_claim_air.payment import SlotEconomics
from experiments.fixed_shape_claim_air.profile import get_profile
from experiments.fixed_shape_claim_air.semantics import SlotKind, StructuralError


FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}


def _operation(
    index: int,
    *,
    approval: bool = False,
    denial: bool = False,
) -> SlotEconomics:
    if approval and denial:
        raise AssertionError("synthetic operation cannot be both approved and denied")
    return SlotEconomics(
        slot_index=index,
        slot_kind=SlotKind.REAL if approval or denial else SlotKind.COVER,
        decision=1 if approval else 0,
        gross_allowed_cents=100 if approval else 0,
        patient_responsibility_cents=20 if approval else 0,
        plan_payable_cents=80 if approval else 0,
        payer_reserve_debit_cents=80 if approval else 0,
        provider_payable_credit_cents=80 if approval else 0,
    )


def _before(*, reserve: int = 1_000) -> AuthenticatedPaymentState:
    return AuthenticatedPaymentState(
        epoch=7,
        sequence=11,
        next_slot_index=0,
        payer_reserve_cents=reserve,
        provider_obligation_cents=30,
        total_paid_cents=40,
        patient_responsibility_cents=5,
        operation_log_root_sha3_512=sha3_512(b"SYNTHETIC-WAVE1A-LOG").digest(),
    )


def test_every_approval_denial_and_cover_slot_advances_authenticated_state() -> None:
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        profile = get_profile("K128_CALIBRATION")
        operations = tuple(
            _operation(index, approval=index == 0, denial=index == 1)
            for index in range(profile.claim_slots)
        )
        transition = build_authenticated_payment_transition(
            profile, operations, _before()
        )
        assert verify_authenticated_payment_transition(profile, transition)
        assert len(transition.transitions) == profile.claim_slots
        assert len(
            {value.root_after_sha3_512 for value in transition.transitions}
        ) == profile.claim_slots
        assert transition.total_plan_payable_cents == 80
        final = transition.transitions[-1].state_after
        assert final.sequence == 12
        assert final.next_slot_index == 0
        assert final.payer_reserve_cents == 920
        assert final.provider_obligation_cents == 110
        assert final.total_paid_cents == 120
        assert final.patient_responsibility_cents == 25


def test_payment_transition_rejects_underflow_chain_and_operation_mutation() -> None:
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        profile = get_profile("K128_CALIBRATION")
        operations = tuple(
            _operation(index, approval=index == 0)
            for index in range(profile.claim_slots)
        )
        with pytest.raises(StructuralError, match="reserve_underflow"):
            build_authenticated_payment_transition(
                profile, operations, _before(reserve=79)
            )
        transition = build_authenticated_payment_transition(
            profile, operations, _before()
        )
        with pytest.raises(StructuralError, match="root_after_mismatch"):
            replace(
                transition.transitions[0],
                root_after_sha3_512=bytes(64),
            )


def test_authenticated_payment_reference_is_disabled_in_production() -> None:
    with mock.patch.dict(os.environ, {**FLAGS, "BL_ENV": "production"}, clear=False):
        with pytest.raises(RuntimeError, match="synthetic_pq_tree_reference_forbidden"):
            _before()
