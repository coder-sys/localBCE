from __future__ import annotations

from dataclasses import replace
import os
from unittest import mock

import pytest

from experiments.fixed_shape_claim_air.payment import derive_batch_economics
from experiments.fixed_shape_claim_air.payment_state import (
    PAYMENT_STATE_ENCODED_LENGTH,
    append_reference_operation_log,
    build_reference_payment_root_pair,
    decode_reference_payment_state,
    encode_reference_payment_state,
    reference_payment_state_root,
)
from experiments.fixed_shape_claim_air.profile import get_profile
from experiments.fixed_shape_claim_air.semantics import StructuralError
from tests.test_r25_fixed_shape_trace import _cover, _real
from tests.test_r25_payment_state_reference import FLAGS, _state


@pytest.fixture(autouse=True)
def _synthetic_guard():
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        yield


def test_encoding_truncation_trailing_magic_and_declared_length_fail_closed() -> None:
    encoded = encode_reference_payment_state(_state())
    for malformed, error in (
        (encoded[:-1], "encoding_length_mismatch"),
        (encoded + b"\x00", "encoding_length_mismatch"),
        (b"XXXXXXXX" + encoded[8:], "magic_mismatch"),
        (encoded[:8] + (PAYMENT_STATE_ENCODED_LENGTH - 1).to_bytes(4, "big") + encoded[12:], "declared_length_mismatch"),
    ):
        with pytest.raises(StructuralError, match=error):
            decode_reference_payment_state(malformed)


def test_operation_omission_reorder_and_forged_composite_root_fail() -> None:
    profile = get_profile("K128_CALIBRATION")
    economics = derive_batch_economics(
        profile,
        tuple(_cover(index) for index in range(profile.claim_slots)),
    )
    before = _state()
    with pytest.raises(StructuralError, match="operation_count_mismatch"):
        append_reference_operation_log(
            before.operation_log_root_512,
            economics.slots[:-1],
            expected_count=profile.claim_slots,
        )
    reordered = tuple(reversed(economics.slots))
    with pytest.raises(StructuralError, match="operation_order_invalid"):
        append_reference_operation_log(
            before.operation_log_root_512,
            reordered,
            expected_count=profile.claim_slots,
        )
    with pytest.raises(StructuralError, match="composite_root_unchanged"):
        build_reference_payment_root_pair(
            before,
            replace(before, sequence=1, operation_log_root_512=bytes([9]) * 64),
        ).__class__(
            reference_payment_state_root(before),
            reference_payment_state_root(before),
        )


def test_reference_root_bytes_do_not_contain_private_ascii_canaries() -> None:
    canaries = (b"SYNTH-MEMBER", b"F840", b"PLAN-PAYABLE", b"80")
    encoded = encode_reference_payment_state(_state())
    root = reference_payment_state_root(_state())
    for canary in canaries:
        assert canary not in encoded
        assert canary not in root
