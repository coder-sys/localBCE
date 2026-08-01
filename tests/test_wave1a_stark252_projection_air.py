from __future__ import annotations

from hashlib import sha3_512

from experiments.fixed_shape_claim_air.executable_air import evaluate_program, evaluate_serialized
from experiments.fixed_shape_claim_air.stark252_projection_air import (
    PROJECTION_MODULUS,
    STARK252_PRIME,
    Stark252ProjectionRequest,
    build_stark252_projection_air,
    compatibility_felt_from_sha3_512,
)


def test_sha3_512_projection_is_exact_canonical_and_independently_evaluated() -> None:
    digests = (bytes(64), sha3_512(b"Blind Ledger projection KAT").digest(), bytes([255]) * 64)
    instance = build_stark252_projection_air(
        tuple(Stark252ProjectionRequest(f"projection-{index}", digest) for index, digest in enumerate(digests))
    )
    assert instance.aliases == tuple(
        int.from_bytes(digest, "big") % PROJECTION_MODULUS + 1 for digest in digests
    )
    assert instance.aliases == tuple(compatibility_felt_from_sha3_512(digest) for digest in digests)
    assert all(0 < value < STARK252_PRIME for value in instance.aliases)
    direct = evaluate_program(instance.program, instance.traces)
    serialized = evaluate_serialized(instance.program.canonical_bytes(), instance.traces)
    assert direct == serialized
    assert direct.maximum_degree == 2


def test_projection_program_is_witness_independent() -> None:
    left = build_stark252_projection_air((Stark252ProjectionRequest("p", bytes(64)),))
    right = build_stark252_projection_air(
        (Stark252ProjectionRequest("p", sha3_512(b"different witness").digest()),)
    )
    assert left.program.commitment() == right.program.commitment()
