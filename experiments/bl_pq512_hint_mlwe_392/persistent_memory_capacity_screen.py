"""Resource screen for the sparse persistent-memory AIP candidate.

The primary construction represents initial and final sparse state by
``(m, a)`` and ``(m', a')`` in ``F^C``.  Its published concrete model is
approximately ``7*C + 51*A`` verifier constraints.  Blind Ledger has four
frozen ordered-map lanes, each with capacity 2^24.  This module applies those
literal quantities before any backend substitution or implementation work.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction

from experiments.bl_pq512_crypto_foundation.claim_batch_access_manifest import (
    build_c0_claim_batch_access_manifest,
)
from experiments.bl_pq512_crypto_foundation.field16_reference import M31_MODULUS
from experiments.fixed_shape_claim_air.ordered_map_reference import (
    ORDERED_MAP_SHARD_CAPACITY,
)
from experiments.fixed_shape_claim_air.profile import PROFILES


PRIMARY_SOURCE = "https://eprint.iacr.org/2024/979"
STATE_LANES = 4
FP16_ENCODED_BYTES = 64
STATE_VECTORS = 4  # initial/final addresses and initial/final values
LAPTOP_RAM_BYTES = 5_000_000_000


@dataclass(frozen=True, slots=True)
class PersistentMemoryCapacityScreen:
    profile_id: str
    accesses: int
    per_lane_capacity: int
    total_capacity: int
    published_constraint_estimate: int
    raw_state_vector_bytes: int
    soundness_bits_floor: int
    verdict: str
    blockers: tuple[str, ...]


def _bits_floor(probability: Fraction) -> int:
    numerator = probability.numerator
    denominator = probability.denominator
    result = denominator.bit_length() - numerator.bit_length()
    if numerator << result > denominator:
        result -= 1
    return result


def screen_sparse_persistent_memory(
    profile_id: str,
) -> PersistentMemoryCapacityScreen:
    try:
        profile = PROFILES[profile_id]
    except KeyError as exc:
        raise ValueError("persistent_memory_profile_unknown") from exc
    manifest = build_c0_claim_batch_access_manifest(profile)
    capacity = STATE_LANES * ORDERED_MAP_SHARD_CAPACITY
    constraints = 7 * capacity + 51 * manifest.ordered_map_operations
    raw_bytes = STATE_VECTORS * capacity * FP16_ENCODED_BYTES
    soundness_error = Fraction(
        capacity + manifest.ordered_map_operations - 1,
        M31_MODULUS**16,
    )
    blockers = []
    if raw_bytes >= LAPTOP_RAM_BYTES:
        blockers.append("raw_committed_state_vectors_exceed_3gb_ram")
    blockers.extend(
        (
            "published_compiler_uses_forbidden_pedersen_and_groth_backend",
            "native_hiding_backend_not_supplied",
            "blind_ledger_atomic_composition_not_supplied",
        )
    )
    return PersistentMemoryCapacityScreen(
        profile_id=profile_id,
        accesses=manifest.ordered_map_operations,
        per_lane_capacity=ORDERED_MAP_SHARD_CAPACITY,
        total_capacity=capacity,
        published_constraint_estimate=constraints,
        raw_state_vector_bytes=raw_bytes,
        soundness_bits_floor=_bits_floor(soundness_error),
        verdict="REJECTED_C1_REFERENCE_LAPTOP",
        blockers=tuple(blockers),
    )


def main() -> None:
    for profile_id in ("K128_CALIBRATION", "K512_CALIBRATION"):
        print(screen_sparse_persistent_memory(profile_id))


if __name__ == "__main__":
    main()
