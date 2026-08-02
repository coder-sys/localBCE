from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512

import pytest

from experiments.bl_pq512_crypto_foundation.state_plane import (
    HashPadCommitment,
    StateEntry,
    StatePlaneError,
    StateSnapshot,
    build_hash_pad_commitment,
    build_state_transition,
    independently_verify_state_transition,
)
from tests.test_bl_pq512_state_plane import _operations, _projection


def _proof():
    before = StateSnapshot.empty("K128_CALIBRATION", capacity=8, epoch=7)
    return build_state_transition(
        before,
        _operations(before),
        _projection(),
        sha3_512(b"authenticated-public-coin").digest(),
        sha3_512(b"private-mask").digest(),
    )


def test_state_root_and_sequence_mutations_fail_closed() -> None:
    proof = _proof()
    forged_after = replace(proof.after, sequence=2)
    with pytest.raises(StatePlaneError, match="sequence|manifest|verifier|transition"):
        replace(proof, after=forged_after)
    with pytest.raises(StatePlaneError, match="state_plane_transition_operation_count_invalid"):
        independently_verify_state_transition(replace(proof, operations=proof.operations[:-1]))


def test_commitment_tag_and_opening_mutations_fail_closed() -> None:
    proof = _proof()
    forged_commitment = replace(
        proof.commitment,
        tag_512=sha3_512(b"forged-tag").digest(),
        commitment_digest_512=b"",
    )
    with pytest.raises(StatePlaneError, match="opening|commitment|transition"):
        replace(proof, commitment=forged_commitment)

    artifact, opening = build_hash_pad_commitment(
        proof.statement_digest_512,
        proof.opening.mask_512,
        proof.public_coin_digest_512,
    )
    assert isinstance(artifact, HashPadCommitment)
    with pytest.raises(StatePlaneError, match="opening_rejected"):
        from experiments.bl_pq512_crypto_foundation.state_plane import verify_hash_pad_opening

        verify_hash_pad_opening(artifact, replace(opening, mask_512=b"M" * 64))


def test_empty_slot_cannot_carry_private_bytes() -> None:
    with pytest.raises(StatePlaneError, match="empty_entry_contains_private_bytes"):
        StateEntry(0, False, b"K" * 64, b"V" * 64)
