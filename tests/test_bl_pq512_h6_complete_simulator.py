from __future__ import annotations

import pytest

from experiments.bl_pq512_crypto_foundation.h6_complete_simulator import (
    MALFORMED_CASES,
    H6SimulatorError,
    run_complete_simulator_suite,
    simulate_valid,
)
from experiments.bl_pq512_crypto_foundation.h6_receipt_grammar import (
    H6ReceiptGrammarError,
    encode_receipt,
    encode_sidecar,
    parse_receipt,
    parse_sidecar,
)


def _fields(count: int) -> tuple[bytes, ...]:
    return tuple(bytes([index + 1]) * 64 for index in range(count))


def test_complete_simulator_covers_all_lifecycle_branches() -> None:
    result = run_complete_simulator_suite()
    assert result["valid_record_count"] == 6
    assert result["malformed_case_count"] == len(MALFORMED_CASES) == 5
    for key in (
        "semantic_air_simulated",
        "state_simulated",
        "gkr_simulated",
        "pcs_simulated",
        "public_coin_simulated",
        "malformed_input_rejected",
        "abort_rejected",
        "retry_fresh_randomness",
        "crash_recovery_zero_retained_artifacts",
        "repeated_proof_shape_fixed",
    ):
        assert result[key] is True
    assert result["proofSuiteId"] is None
    assert result["activationAllowed"] is False
    assert result["native_hiding"]["active_certificate_verified"] is True
    assert result["native_hiding"]["active_coverage_gaps"] == ()
    assert result["native_hiding"]["active_historical_circle_gaps"]


def test_retry_keeps_attempt_identity_and_changes_proof() -> None:
    first = simulate_valid(
        128,
        "APPROVAL",
        logical_attempt=b"attempt",
        proof_randomness=b"randomness-a",
    )
    retry = simulate_valid(
        128,
        "APPROVAL",
        logical_attempt=b"attempt",
        proof_randomness=b"randomness-b",
    )
    assert first.attempt_id_512 == retry.attempt_id_512
    assert first.receipt_digest_512 != retry.receipt_digest_512
    assert first.observable_shape == retry.observable_shape


def test_sidecar_and_receipt_are_fixed_width_and_strict() -> None:
    sidecar = encode_sidecar(_fields(11))
    receipt = encode_receipt(_fields(7))
    assert len(parse_sidecar(sidecar)) == 11
    assert len(parse_receipt(receipt)) == 7
    with pytest.raises(H6ReceiptGrammarError, match="trailing|length"):
        parse_receipt(receipt + b"x")


def test_simulator_rejects_invalid_outcome_before_private_processing() -> None:
    with pytest.raises(H6SimulatorError, match="input_invalid"):
        simulate_valid(
            128,
            "UNKNOWN",
            logical_attempt=b"attempt",
            proof_randomness=b"randomness",
        )
