from __future__ import annotations

from dataclasses import replace
from functools import lru_cache
from hashlib import sha3_512

import pytest

from experiments.bl_pq512_crypto_foundation.claim_truth_pq_authority import (
    ClaimTruthAuthorityRegistryV1,
    ClaimTruthRootsV1,
    sign_claim_truth_roots,
)
from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    MlDsa87PqcryptoAdapter,
    SphincsShake256fSimplePqcryptoAdapter,
)
from experiments.fixed_shape_claim_air.claim_truth_authority_executable_air import (
    build_claim_truth_authority_executable_air,
)
from experiments.fixed_shape_claim_air.executable_air import (
    evaluate_program,
    evaluate_serialized,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError


@lru_cache(maxsize=1)
def _authority():
    roots = ClaimTruthRootsV1(
        *(sha3_512(f"claim-truth-root-{index}".encode()).digest() for index in range(6))
    )
    ml = MlDsa87PqcryptoAdapter()
    slh = SphincsShake256fSimplePqcryptoAdapter()
    ml_public, ml_secret = ml.generate_keypair()
    slh_public, slh_secret = slh.generate_keypair()
    registry = ClaimTruthAuthorityRegistryV1(
        "K128_CALIBRATION",
        "BL-SYNTH-GOV-INTAKE-V1",
        7,
        sha3_512(b"authority-snapshot-7").digest(),
        ml_public,
        slh_public,
    )
    envelope = sign_claim_truth_roots(
        registry,
        roots,
        ml_adapter=ml,
        ml_secret_key=ml_secret,
        slh_adapter=slh,
        slh_secret_key=slh_secret,
    )
    return registry, envelope, ml, slh


def test_dual_pq_authority_digest_and_all_roots_are_air_bound() -> None:
    registry, envelope, ml, slh = _authority()
    instance = build_claim_truth_authority_executable_air(
        registry, envelope, ml_adapter=ml, slh_adapter=slh
    )

    direct = evaluate_program(
        instance.program, instance.traces, instance.public_input_bytes
    )
    serialized = evaluate_serialized(
        instance.program.canonical_bytes(),
        instance.traces,
        instance.public_input_bytes,
    )
    assert direct == serialized
    assert instance.pq_authority_verified is True
    assert instance.authority_message_hash_constrained is True
    assert instance.traces["sha3_digest_batch"].rows == 1
    assert direct.maximum_degree == 2


def test_invalid_second_pq_signature_never_reaches_air() -> None:
    registry, envelope, ml, slh = _authority()
    bad = replace(
        envelope,
        slh_dsa_shake_256f_signature=bytes(
            (envelope.slh_dsa_shake_256f_signature[0] ^ 1,)
        )
        + envelope.slh_dsa_shake_256f_signature[1:],
    )
    with pytest.raises(
        StructuralError, match="claim_truth_authority_dual_pq_verification_failed"
    ):
        build_claim_truth_authority_executable_air(
            registry, bad, ml_adapter=ml, slh_adapter=slh
        )
