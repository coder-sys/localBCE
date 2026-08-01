from __future__ import annotations

from dataclasses import fields, replace
from hashlib import sha3_512
import os
from unittest import mock

import pytest

from experiments.fixed_shape_claim_air.payment import derive_batch_economics
from experiments.fixed_shape_claim_air.payment_state import (
    PAYMENT_STATE_ENCODED_LENGTH,
    REFERENCE_STATUS,
    PaymentStateRootPairReference,
    StrongPaymentStateV1Reference,
    append_reference_operation_log,
    build_reference_payment_root_pair,
    decode_reference_payment_state,
    encode_reference_payment_state,
    reference_payment_state_root,
)
from experiments.fixed_shape_claim_air.profile import get_profile
from experiments.fixed_shape_claim_air.semantics import StructuralError
from tests.test_r25_fixed_shape_trace import _cover, _real


FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_R25_PAYMENT_STATE_REFERENCE": "1",
}
ROOT_KAT = (
    "8233833c87c842269cbd59c927eecd573cb39eb2165df286be8b858d7986a540"
    "295214e22bc64d5300c7dbc2b74d986bb227aa807f8afc69487cc0079261ea85"
)


@pytest.fixture(autouse=True)
def _synthetic_guard():
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        yield


def _state(sequence: int = 0, *, roots: tuple[bytes, ...] | None = None) -> StrongPaymentStateV1Reference:
    selected = roots or tuple(bytes([index]) * 64 for index in range(1, 6))
    return StrongPaymentStateV1Reference(
        version=1,
        epoch=7,
        sequence=sequence,
        asset_registry_root_512=selected[0],
        benefit_accumulator_root_512=selected[1],
        obligation_root_512=selected[2],
        private_asset_ledger_root_512=selected[3],
        operation_log_root_512=selected[4],
    )


def test_exact_encoding_round_trip_and_root_kat() -> None:
    state = _state()
    encoded = encode_reference_payment_state(state)
    assert len(encoded) == PAYMENT_STATE_ENCODED_LENGTH == 350
    assert decode_reference_payment_state(encoded) == state
    assert reference_payment_state_root(state).hex() == ROOT_KAT
    assert sha3_512(encoded).hexdigest() == (
        "3bfa997feffff0bdff94fd71aec767a732a308e917803081c31f00e3a7a684157"
        "18a6aa02343481f56fb418aca0446b823d0ab5fc17e69544e0120d27e67daff"
    )


@pytest.mark.parametrize(
    "field_name",
    [
        "epoch",
        "sequence",
        "asset_registry_root_512",
        "benefit_accumulator_root_512",
        "obligation_root_512",
        "private_asset_ledger_root_512",
        "operation_log_root_512",
    ],
)
def test_each_state_field_is_root_bound(field_name: str) -> None:
    baseline = _state()
    value = getattr(baseline, field_name)
    changed = value + 1 if type(value) is int else bytes([0xAA]) * 64
    mutated = replace(baseline, **{field_name: changed})
    assert reference_payment_state_root(mutated) != reference_payment_state_root(baseline)


@pytest.mark.parametrize("bad", [bytes(64), bytes(31), bytes(63), bytes(65), bytearray(64)])
def test_roots_reject_zero_wrong_length_and_wrong_type(bad: object) -> None:
    with pytest.raises(StructuralError, match="payment_state_asset_registry_root"):
        replace(_state(), asset_registry_root_512=bad)


def test_all_cover_batch_still_appends_every_operation_and_changes_composite_root() -> None:
    profile = get_profile("K128_CALIBRATION")
    economics = derive_batch_economics(
        profile,
        tuple(_cover(index) for index in range(profile.claim_slots)),
    )
    before = _state()
    log_after = append_reference_operation_log(
        before.operation_log_root_512,
        economics.slots,
        expected_count=profile.claim_slots,
    )
    after = replace(before, sequence=1, operation_log_root_512=log_after)
    pair = build_reference_payment_root_pair(before, after)
    assert isinstance(pair, PaymentStateRootPairReference)
    assert pair.root_before_512 != pair.root_after_512
    assert tuple(field.name for field in fields(pair)) == (
        "root_before_512",
        "root_after_512",
    )


def test_mixed_batch_operation_order_and_count_fail_closed() -> None:
    profile = get_profile("K128_CALIBRATION")
    slots = [_real(0)]
    slots.extend(_cover(index) for index in range(1, profile.claim_slots))
    economics = derive_batch_economics(profile, slots)
    with pytest.raises(StructuralError, match="operation_count_mismatch"):
        append_reference_operation_log(
            _state().operation_log_root_512,
            economics.slots[:-1],
            expected_count=profile.claim_slots,
        )
    reordered = list(economics.slots)
    reordered[0], reordered[1] = reordered[1], reordered[0]
    with pytest.raises(StructuralError, match="operation_count_mismatch"):
        append_reference_operation_log(
            _state().operation_log_root_512,
            reordered,
            expected_count=profile.claim_slots,
        )


def test_sequence_epoch_and_unchanged_operation_log_are_rejected() -> None:
    before = _state()
    for after, error in (
        (replace(before, sequence=2, operation_log_root_512=bytes([9]) * 64), "sequence_transition"),
        (replace(before, epoch=8, sequence=1, operation_log_root_512=bytes([9]) * 64), "epoch_mismatch"),
        (replace(before, sequence=1), "operation_log_unchanged"),
    ):
        with pytest.raises(StructuralError, match=error):
            build_reference_payment_root_pair(before, after)


def test_three_factor_guard_and_reference_status_fail_closed() -> None:
    assert _state().reference_status == REFERENCE_STATUS
    for missing in FLAGS:
        incomplete = {key: value for key, value in FLAGS.items() if key != missing}
        with mock.patch.dict(os.environ, incomplete, clear=True):
            with pytest.raises(RuntimeError, match="synthetic_r25_payment_state_forbidden"):
                _state()
