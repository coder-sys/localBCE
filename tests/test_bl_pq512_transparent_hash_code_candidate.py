from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512
import inspect

import pytest

from experiments.bl_pq512_crypto_foundation.transparent_hash_code_candidate import (
    BACKEND_ID,
    COMMITMENT_BYTES,
    MASK_BYTES,
    bind_authenticated_public_coin,
    commit,
    open_commitment,
    security_ledger,
    security_review,
    simulate_commitment,
    verify_opening,
)


def _value(label: bytes, length: int) -> bytes:
    return (sha3_512(label).digest() * ((length + 63) // 64))[:length]


def test_commitment_is_coin_independent_and_verifies() -> None:
    statement = _value(b"transparent-statement", 64)
    attempt = _value(b"transparent-attempt", 64)
    mask = _value(b"transparent-mask", MASK_BYTES)
    commitment = commit(statement, attempt, mask)
    opening = open_commitment(commitment, statement, mask)
    verify_opening(commitment, opening)
    assert len(commitment.commitment) == COMMITMENT_BYTES
    assert "public_coin" not in inspect.signature(commit).parameters
    first_transcript = bind_authenticated_public_coin(
        commitment, _value(b"transparent-coin-1", 64)
    )
    second_transcript = bind_authenticated_public_coin(
        commitment, _value(b"transparent-coin-2", 64)
    )
    assert first_transcript != second_transcript
    assert commitment == commit(statement, attempt, mask)


def test_security_ledger_has_256_bit_margin_after_multi_target_loss() -> None:
    ledger = security_ledger()
    assert ledger.output_bits == 1_024
    assert ledger.quantum_collision_bits == 341
    assert ledger.effective_binding_bits == 309
    assert ledger.effective_hiding_bits == 480
    assert ledger.meets_floor
    with pytest.raises(ValueError, match="ledger_mutation"):
        replace(ledger, quantum_collision_bits=256)
    review = security_review()
    assert review.commitment_before_coin
    assert review.no_fiat_shamir_or_qrom_credit
    assert review.h4_composition_complete is False
    assert review.review_digest_512
    with pytest.raises(ValueError, match="review_mutation"):
        replace(review, commitment_before_coin=False)


def test_opening_and_simulator_mutations_fail_closed() -> None:
    statement = _value(b"transparent-statement-attack", 64)
    attempt = _value(b"transparent-attempt-attack", 64)
    mask = _value(b"transparent-mask-attack", MASK_BYTES)
    commitment = commit(statement, attempt, mask)
    opening = open_commitment(commitment, statement, mask)
    with pytest.raises(ValueError, match="opening_mismatch"):
        verify_opening(
            commitment,
            replace(opening, statement=_value(b"wrong-statement", 64)),
        )
    with pytest.raises(ValueError, match="opening_mismatch"):
        verify_opening(
            replace(commitment, commitment=bytes([commitment.commitment[0] ^ 1]) + commitment.commitment[1:]),
            opening,
        )
    simulated = simulate_commitment(_value(b"simulator", 64))
    assert simulated.attempt_id != commitment.attempt_id
    assert simulated.commitment != commitment.commitment
    assert BACKEND_ID == "TRANSPARENT_SHAKE256_1024"
