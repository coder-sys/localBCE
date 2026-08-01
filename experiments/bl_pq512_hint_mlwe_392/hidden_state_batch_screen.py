"""Bounded throughput screen for the unqualified hidden-state workload model.

K128 and K512 are architecture-model inputs, not qualified measurements.
K1024 and K2048 are conservative ceilings of the unique affine model through
those two inputs. This module does not change any release or security target.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction

from experiments.bl_pq512_hint_mlwe_392.relation_cost_screen import (
    K128_MODEL,
    K512_MODEL,
)


PACK_BITS = 8
GATES_PER_PACKED_PERMUTATION = 460_800


@dataclass(frozen=True, slots=True)
class BatchProjection:
    claims: int
    sha3_permutations: int
    permutations_per_claim: Fraction
    packed_shards: int
    packed_gates: int
    phase_one_seconds: float | None
    evidence_class: str


def _ceil_fraction(value: Fraction) -> int:
    return -(-value.numerator // value.denominator)


def affine_model() -> tuple[Fraction, Fraction]:
    """Return `(fixed, per_claim)` through the K128 and K512 inputs."""

    claim_delta = 512 - 128
    permutation_delta = (
        K512_MODEL.sha3_permutations - K128_MODEL.sha3_permutations
    )
    per_claim = Fraction(permutation_delta, claim_delta)
    fixed = Fraction(K128_MODEL.sha3_permutations) - 128 * per_claim
    return fixed, per_claim


def project_batch(
    claims: int, gates_per_second: float | None = None
) -> BatchProjection:
    if type(claims) is not int or claims <= 0:
        raise ValueError("claims_must_be_positive")
    if gates_per_second is not None and gates_per_second <= 0:
        raise ValueError("gates_per_second_must_be_positive")

    fixed, per_claim = affine_model()
    exact = fixed + claims * per_claim
    permutations = _ceil_fraction(exact)
    shards = (permutations + PACK_BITS - 1) // PACK_BITS
    gates = shards * GATES_PER_PACKED_PERMUTATION
    if claims == 128:
        evidence = "ARCHITECTURE_MODEL_INPUT_UNQUALIFIED_K128"
    elif claims == 512:
        evidence = "ARCHITECTURE_MODEL_INPUT_UNQUALIFIED_K512"
    else:
        evidence = "TWO_POINT_AFFINE_PROJECTION_UNQUALIFIED"
    return BatchProjection(
        claims=claims,
        sha3_permutations=permutations,
        permutations_per_claim=Fraction(permutations, claims),
        packed_shards=shards,
        packed_gates=gates,
        phase_one_seconds=(
            None if gates_per_second is None else gates / gates_per_second
        ),
        evidence_class=evidence,
    )


def main() -> None:
    for claims in (128, 512, 1_024, 2_048):
        result = project_batch(claims)
        print(
            {
                "claims": result.claims,
                "sha3_permutations": result.sha3_permutations,
                "permutations_per_claim": float(
                    result.permutations_per_claim
                ),
                "packed_shards": result.packed_shards,
                "packed_gates": result.packed_gates,
                "evidence_class": result.evidence_class,
            }
        )


if __name__ == "__main__":
    main()
