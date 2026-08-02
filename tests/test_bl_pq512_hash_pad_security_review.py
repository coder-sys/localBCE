from __future__ import annotations

from experiments.bl_pq512_crypto_foundation.hash_pad_security_review import (
    DECISION,
    hash_pad_security_review,
    verify_hash_pad_reference_kat,
)


def test_hash_pad_review_is_digest_bound_and_rejects_admission() -> None:
    review = hash_pad_security_review()
    assert review.decision == DECISION == "REJECTED_GATE_2E_ADMISSION"
    assert review.admitted is False
    assert review.review_digest_512 != bytes(64)
    assert "full_256_bit_quantum_binding_theorem_missing" in review.rejection_reasons
    assert "h4_state_air_composition_missing" in review.rejection_reasons
    assert review.as_public_dict()["admitted"] is False


def test_hash_pad_review_kat_replays_without_public_opening_material() -> None:
    commitment, opening = verify_hash_pad_reference_kat()
    public = commitment.as_public_dict()
    assert opening.statement_digest_512 != bytes(64)
    assert "statement_digest_512" not in public
    assert "mask_512" not in public
    assert public["commitment_digest_sha3_512_hex"] == commitment.commitment_digest_512.hex()
