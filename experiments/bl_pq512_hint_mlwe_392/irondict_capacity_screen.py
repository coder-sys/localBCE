"""Current-backend screen for an IRONDICT-derived state relation.

IRONDICT's generic relation is relevant, but its efficient sparse update path
depends on a homomorphic PCS.  The only active Blind Ledger implementation
candidate is the transparent SHA3-512/Fp16 code-based PCS, which is not
homomorphic.  Updating even one capacity-sized state polynomial therefore
requires recommitting all 2^26 cells.

The timing floor below is optimistic: it maps those cells to the measured
2^22-coefficient PCS control, permits as much parallelism as 2 GiB codewords
alone fit under the current 5,000,000,000-byte ceiling, and omits zerocheck,
hiding, grammar, semantic GKR, verification, and all other resident memory.
"""

from __future__ import annotations

from dataclasses import dataclass

from experiments.fixed_shape_claim_air.ordered_map_reference import (
    ORDERED_MAP_SHARD_CAPACITY,
)


PRIMARY_SOURCE = (
    "https://www.usenix.org/system/files/conference/usenixsecurity26/"
    "sec26_prepub_hafezi.pdf"
)
STATE_LANES = 4
STATE_CELLS = STATE_LANES * ORDERED_MAP_SHARD_CAPACITY
PCS_COEFFICIENT_CAPACITY = 1 << 22
PCS_CODEWORD_BYTES = 1 << 31
LAPTOP_RAM_BYTES = 5_000_000_000
MEASURED_PCS_PROVE_SECONDS = 19.0984184
MEASURED_GKR_SECONDS = {
    "K128_CALIBRATION": 44.9440978,
    "K512_CALIBRATION": 124.8322177,
}
LATENCY_LIMIT_SECONDS = {
    "K128_CALIBRATION": 60,
    "K512_CALIBRATION": 180,
}


@dataclass(frozen=True, slots=True)
class IrondictCapacityScreen:
    profile_id: str
    state_cells: int
    minimum_full_recommitment_shards: int
    optimistic_concurrent_shards: int
    optimistic_pcs_waves: int
    optimistic_pcs_seconds: float
    measured_gkr_seconds: float
    optimistic_combined_seconds: float
    latency_limit_seconds: int
    verdict: str
    blockers: tuple[str, ...]


def _ceil_div(numerator: int, denominator: int) -> int:
    return (numerator + denominator - 1) // denominator


def screen_irondict_current_pcs(profile_id: str) -> IrondictCapacityScreen:
    try:
        gkr_seconds = MEASURED_GKR_SECONDS[profile_id]
        latency_limit = LATENCY_LIMIT_SECONDS[profile_id]
    except KeyError as exc:
        raise ValueError("irondict_profile_unknown") from exc

    shards = _ceil_div(STATE_CELLS, PCS_COEFFICIENT_CAPACITY)
    concurrent = LAPTOP_RAM_BYTES // PCS_CODEWORD_BYTES
    waves = _ceil_div(shards, concurrent)
    pcs_seconds = waves * MEASURED_PCS_PROVE_SECONDS
    combined = gkr_seconds + pcs_seconds

    return IrondictCapacityScreen(
        profile_id=profile_id,
        state_cells=STATE_CELLS,
        minimum_full_recommitment_shards=shards,
        optimistic_concurrent_shards=concurrent,
        optimistic_pcs_waves=waves,
        optimistic_pcs_seconds=pcs_seconds,
        measured_gkr_seconds=gkr_seconds,
        optimistic_combined_seconds=combined,
        latency_limit_seconds=latency_limit,
        verdict="REJECTED_C2_CURRENT_TRANSPARENT_PCS_LATENCY",
        blockers=(
            "active_transparent_pcs_is_not_homomorphic",
            "full_capacity_polynomial_recommitment_required",
            "optimistic_gkr_plus_pcs_floor_exceeds_latency_gate",
            "released_kzh_backend_uses_forbidden_pairings_and_structured_setup",
            "released_fiat_shamir_transcript_is_forbidden",
            "blind_ledger_atomic_semantic_composition_not_supplied",
        ),
    )


def main() -> None:
    for profile_id in ("K128_CALIBRATION", "K512_CALIBRATION"):
        print(screen_irondict_current_pcs(profile_id))


if __name__ == "__main__":
    main()
