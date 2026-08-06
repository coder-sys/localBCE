from __future__ import annotations

from copy import deepcopy
from unittest import mock

import pytest

from app import privacy_v2


def _batch_bundle(*, allowed: int = 12500, payment: int = 12500) -> dict:
    return {
        "witness": {"synthetic_private_claim": "LOCAL_ONLY"},
        "expected_output": {
            "batch_root_before": 11,
            "batch_root_after": 12,
            "claim_source_root": 13,
            "oracle_facts_root": 14,
            "policy_root": 15,
            "ruleset_root": 16,
            "batch_commitment": 17,
            "total_allowed_cents": allowed,
            "total_payment_cents": payment,
        },
    }


def _bundle() -> dict:
    with mock.patch.object(
        privacy_v2, "flatten_batch_claim_input_witness", return_value=[2001, 2002]
    ):
        return privacy_v2.build_privacy_v2_bundle(
            _batch_bundle(),
            settlement_domain=1001,
            batch_nonce=1002,
            private_data_commitment=1003,
            privacy_salt=1004,
            value_salt=1005,
        )


def _verify(candidate: dict) -> bool:
    with mock.patch.object(
        privacy_v2, "flatten_batch_claim_input_witness", return_value=[2001, 2002]
    ):
        return privacy_v2.verify_privacy_v2_bundle(
            _batch_bundle(),
            candidate,
            settlement_domain=1001,
            batch_nonce=1002,
            private_data_commitment=1003,
            privacy_salt=1004,
            value_salt=1005,
        )


def test_private_witness_splice_is_rejected() -> None:
    candidate = _bundle()
    candidate["witness"]["private_data_commitment"] = 9999
    with pytest.raises(ValueError, match="private_witness"):
        _verify(candidate)


def test_serialized_argument_reorder_is_rejected() -> None:
    candidate = _bundle()
    candidate["serialized_arguments"] = list(reversed(candidate["serialized_arguments"]))
    with pytest.raises(ValueError, match="serialized_arguments"):
        _verify(candidate)


def test_public_output_rebinding_is_rejected() -> None:
    candidate = _bundle()
    candidate["expected_output"]["settlement_commitment"] ^= 1
    with pytest.raises(ValueError, match="expected_output"):
        _verify(candidate)


def test_public_output_extra_private_field_is_rejected() -> None:
    candidate = _bundle()
    candidate["expected_output"] = {
        **candidate["expected_output"],
        "total_payment_cents": 12500,
    }
    with pytest.raises(ValueError, match="public_output_schema"):
        privacy_v2.privacy_v2_public_receipt(candidate["expected_output"])


def test_coercible_security_input_is_rejected() -> None:
    with mock.patch.object(
        privacy_v2, "flatten_batch_claim_input_witness", return_value=[]
    ):
        with pytest.raises(ValueError, match="not_exact_integer"):
            privacy_v2.build_privacy_v2_bundle(
                _batch_bundle(),
                settlement_domain="1001",
                batch_nonce=1002,
                private_data_commitment=1003,
                privacy_salt=1004,
                value_salt=1005,
            )
