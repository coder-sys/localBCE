from __future__ import annotations

from hashlib import sha3_512

from app.batch.pq_nullifier_derivation import derive_attempt_nullifiers_v1, derive_cover_nullifiers_v2
from experiments.fixed_shape_claim_air.a12_nullifier_executable_air import (
    AttemptNullifierAirRequest,
    CoverNullifierAirRequest,
    build_a12_nullifier_executable_air,
)
from experiments.fixed_shape_claim_air.executable_air import evaluate_program, evaluate_serialized
from experiments.fixed_shape_claim_air.stark252_projection_air import compatibility_felt_from_sha3_512
from tests.test_a12_nullifier_derivation import _authority, _cover_context_v2, _identity


def test_a12_strong_air_binds_attempt_cover_and_pepper_commitment() -> None:
    authority = _authority()
    nonce = sha3_512(b"BL-A12-COVER-NONCE").digest()
    instance = build_a12_nullifier_executable_air(
        (
            AttemptNullifierAirRequest("attempt", _identity()),
            CoverNullifierAirRequest("cover", _cover_context_v2(), nonce),
        ),
        authority,
    )
    assert instance.strong_nullifiers == (
        derive_attempt_nullifiers_v1(_identity(), authority).strong_sha3_512,
        derive_cover_nullifiers_v2(_cover_context_v2(), nonce).strong_sha3_512,
    )
    assert instance.compatibility_aliases == tuple(
        compatibility_felt_from_sha3_512(value) for value in instance.strong_nullifiers
    )
    direct = evaluate_program(instance.program, instance.traces)
    serialized = evaluate_serialized(instance.program.canonical_bytes(), instance.traces)
    assert direct == serialized
    assert direct.maximum_degree == 2


def test_a12_program_hides_kind_and_identifier_lengths() -> None:
    authority = _authority()
    attempt = build_a12_nullifier_executable_air(
        (AttemptNullifierAirRequest("slot", _identity()),), authority
    )
    cover = build_a12_nullifier_executable_air(
        (
            CoverNullifierAirRequest(
                "slot", _cover_context_v2(), sha3_512(b"BL-A12-COVER-NONCE").digest()
            ),
        ),
        authority,
    )
    assert attempt.program.commitment() == cover.program.commitment()
