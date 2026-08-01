"""Fail-closed Hint-MLWE capacity screen for authenticated state accesses.

This is a strict lower bound, not a compiled relation size.  Every sealed
ordered-map operation must bind its complete 512-bit key and complete 512-bit
value before and after the operation.  Paths, leaf-link fields, indices,
ordering auxiliaries, range witnesses, claim fields, hiding randomness, and
the semantic AIR are deliberately excluded.  A candidate that cannot hold
this smaller payload cannot implement the sealed state transition.
"""

from __future__ import annotations

from dataclasses import dataclass

from experiments.bl_pq512_crypto_foundation.claim_batch_access_manifest import (
    build_c0_claim_batch_access_manifest,
)
from experiments.bl_pq512_hint_mlwe_392.candidate_geometry import (
    D256_BOX4_Q68_K29,
)
from experiments.bl_pq512_hint_mlwe_392.message_rank_options import OPTIONS
from experiments.fixed_shape_claim_air.profile import PROFILES


BITS_PER_STATE_WORD = 512
STATE_WORDS_PER_OPERATION_LOWER_BOUND = 3
# Use the largest modulus among the screened options.  This is deliberately
# optimistic for Hint-MLWE: a radix-2^b chunk is injective when 2^b < q.
MAXIMUM_SCREENED_PAYLOAD_BITS_PER_COEFFICIENT = max(
    (option.modulus - 1).bit_length() - 1 for option in OPTIONS
)
HINT_COEFFICIENTS_PER_STATE_WORD = (
    BITS_PER_STATE_WORD + MAXIMUM_SCREENED_PAYLOAD_BITS_PER_COEFFICIENT - 1
) // MAXIMUM_SCREENED_PAYLOAD_BITS_PER_COEFFICIENT


@dataclass(frozen=True, slots=True)
class StateAccessCapacityScreen:
    profile_id: str
    ordered_map_operations: int
    state_words_per_operation_lower_bound: int
    payload_bits_per_hint_coefficient: int
    hint_coefficients_per_state_word: int
    coefficient_lower_bound: int
    message_rank_lower_bound: int
    largest_screened_message_rank: int
    largest_screened_capacity: int
    capacity_shortfall_coefficients: int
    verdict: str
    omitted_payload: tuple[str, ...]


def _ceil_div(numerator: int, denominator: int) -> int:
    if numerator < 0 or denominator <= 0:
        raise ValueError("ceil_div_domain_error")
    return (numerator + denominator - 1) // denominator


def screen_state_access_capacity(profile_id: str) -> StateAccessCapacityScreen:
    try:
        profile = PROFILES[profile_id]
    except KeyError as exc:
        raise ValueError("state_access_profile_unknown") from exc
    manifest = build_c0_claim_batch_access_manifest(profile)
    coefficient_lower_bound = (
        manifest.ordered_map_operations
        * STATE_WORDS_PER_OPERATION_LOWER_BOUND
        * HINT_COEFFICIENTS_PER_STATE_WORD
    )
    largest_rank = max(option.message_rank for option in OPTIONS)
    largest_capacity = largest_rank * D256_BOX4_Q68_K29.degree
    shortfall = max(0, coefficient_lower_bound - largest_capacity)
    return StateAccessCapacityScreen(
        profile_id=profile_id,
        ordered_map_operations=manifest.ordered_map_operations,
        state_words_per_operation_lower_bound=(
            STATE_WORDS_PER_OPERATION_LOWER_BOUND
        ),
        payload_bits_per_hint_coefficient=(
            MAXIMUM_SCREENED_PAYLOAD_BITS_PER_COEFFICIENT
        ),
        hint_coefficients_per_state_word=HINT_COEFFICIENTS_PER_STATE_WORD,
        coefficient_lower_bound=coefficient_lower_bound,
        message_rank_lower_bound=_ceil_div(
            coefficient_lower_bound, D256_BOX4_Q68_K29.degree
        ),
        largest_screened_message_rank=largest_rank,
        largest_screened_capacity=largest_capacity,
        capacity_shortfall_coefficients=shortfall,
        verdict=(
            "REJECTED_SCREENED_COMPACT_HINT_OPTIONS"
            if shortfall
            else "LOWER_BOUND_FITS_RELATION_STILL_UNCOMPILED"
        ),
        omitted_payload=(
            "target_and_allocated_leaf_link_fields",
            "membership_and_absence_paths",
            "indices_modes_and_cursors",
            "ordering_uniqueness_and_range_auxiliaries",
            "claim_semantics_and_payment_arithmetic",
            "commitment_bridge_and_hiding_randomness",
        ),
    )


def main() -> None:
    for profile_id in ("K128_CALIBRATION", "K512_CALIBRATION"):
        print(screen_state_access_capacity(profile_id))


if __name__ == "__main__":
    main()
