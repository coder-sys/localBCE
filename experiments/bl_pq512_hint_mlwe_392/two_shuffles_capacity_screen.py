"""Resource screen for the Two-Shuffles RAM relation on frozen state.

The paper's exact scalar-RAM cost is ``4*T + 2*n`` input gates.  Blind
Ledger values are 512 bits and require at least two Fp16 elements, so the
same derivation becomes ``2*T + (T+n)*(2+1) = 5*T + 3*n``.  Unlike the
paper's headline regime, Blind Ledger has far fewer accesses than cells.

This module also maps that exact gate count onto the already measured
2^22-coefficient PCS control.  The concurrency bound is deliberately
optimistic: it charges only the 2 GiB committed codeword per shard against
the current 5,000,000,000-byte RAM ceiling and ignores every other resident
allocation.
"""

from __future__ import annotations

from dataclasses import dataclass

from experiments.bl_pq512_crypto_foundation.claim_batch_access_manifest import (
    build_c0_claim_batch_access_manifest,
)
from experiments.fixed_shape_claim_air.ordered_map_reference import (
    ORDERED_MAP_SHARD_CAPACITY,
)
from experiments.fixed_shape_claim_air.profile import PROFILES


PRIMARY_SOURCE = "https://www.usenix.org/system/files/usenixsecurity24-yang-yibin.pdf"
STATE_LANES = 4
VALUE_FP16_ELEMENTS = 2
PCS_COEFFICIENT_CAPACITY = 1 << 22
PCS_CODEWORD_BYTES = 1 << 31
LAPTOP_RAM_BYTES = 5_000_000_000
MEASURED_PCS_PROVE_SECONDS = 19.0984184


@dataclass(frozen=True, slots=True)
class TwoShufflesCapacityScreen:
    profile_id: str
    state_cells: int
    accesses: int
    accesses_per_cell: float
    input_gates: int
    minimum_pcs_shards: int
    optimistic_concurrent_shards: int
    optimistic_pcs_waves: int
    optimistic_pcs_prove_seconds: float
    latency_limit_seconds: int
    verdict: str
    blockers: tuple[str, ...]


def _ceil_div(numerator: int, denominator: int) -> int:
    return (numerator + denominator - 1) // denominator


def screen_two_shuffles(profile_id: str) -> TwoShufflesCapacityScreen:
    try:
        profile = PROFILES[profile_id]
    except KeyError as exc:
        raise ValueError("two_shuffles_profile_unknown") from exc

    manifest = build_c0_claim_batch_access_manifest(profile)
    cells = STATE_LANES * ORDERED_MAP_SHARD_CAPACITY
    accesses = manifest.ordered_map_operations
    # Set membership contributes 2T. RAM access/teardown contributes
    # (T+n)*(ell+1), with ell=2 for a 512-bit value in Fp16.
    input_gates = 2 * accesses + (accesses + cells) * (
        VALUE_FP16_ELEMENTS + 1
    )
    shards = _ceil_div(input_gates, PCS_COEFFICIENT_CAPACITY)
    concurrent = LAPTOP_RAM_BYTES // PCS_CODEWORD_BYTES
    waves = _ceil_div(shards, concurrent)
    optimistic_seconds = waves * MEASURED_PCS_PROVE_SECONDS
    latency_limit = 60 if profile_id == "K128_CALIBRATION" else 180

    blockers = [
        "published_constant_per_access_regime_requires_accesses_much_greater_than_cells",
        "full_state_setup_and_teardown_are_mandatory",
        "published_implementation_uses_unselected_vole_backend",
        "atomic_sha3_512_state_binding_not_supplied",
    ]
    if optimistic_seconds >= latency_limit:
        blockers.append("optimistic_current_pcs_floor_exceeds_latency_gate")

    return TwoShufflesCapacityScreen(
        profile_id=profile_id,
        state_cells=cells,
        accesses=accesses,
        accesses_per_cell=accesses / cells,
        input_gates=input_gates,
        minimum_pcs_shards=shards,
        optimistic_concurrent_shards=concurrent,
        optimistic_pcs_waves=waves,
        optimistic_pcs_prove_seconds=optimistic_seconds,
        latency_limit_seconds=latency_limit,
        verdict="REJECTED_C4_CURRENT_PCS_REFERENCE_LAPTOP",
        blockers=tuple(blockers),
    )


def main() -> None:
    for profile_id in ("K128_CALIBRATION", "K512_CALIBRATION"):
        print(screen_two_shuffles(profile_id))


if __name__ == "__main__":
    main()
