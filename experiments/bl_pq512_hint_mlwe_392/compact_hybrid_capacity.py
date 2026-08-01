"""Capacity gate for the compact non-SHA3 Hint-MLWE hybrid lane.

The six per-slot scalars are the exact non-index, non-nullifier fields in
MasterSlotRecordV2. This module does not assume that authority certification
removes range, transition, or auxiliary witnesses.
"""

from __future__ import annotations

from dataclasses import dataclass

from experiments.bl_pq512_hint_mlwe_392.candidate_geometry import (
    D256_BOX4_Q68_K29,
)


PRIVATE_MASTER_SCALARS_PER_SLOT = (
    "decision",
    "failure_code",
    "allowed_cents",
    "payment_cents",
    "raw_gate_bits",
    "effective_gate_bits",
)
CURRENT_MESSAGE_CAPACITY_COEFFICIENTS = (
    D256_BOX4_Q68_K29.message_rank * D256_BOX4_Q68_K29.degree
)


@dataclass(frozen=True, slots=True)
class CompactCapacityScreen:
    profile_id: str
    claim_slots: int
    private_scalars_per_slot: int
    base_private_coefficients: int
    base_message_rank: int
    remaining_coefficients: int
    maximum_per_slot_scalars_with_one_fixed_coefficient: int
    verdict: str
    blockers: tuple[str, ...]


def _ceil_div(numerator: int, denominator: int) -> int:
    return (numerator + denominator - 1) // denominator


def screen_workspace_master_record(
    profile_id: str, claim_slots: int
) -> CompactCapacityScreen:
    if type(claim_slots) is not int or claim_slots <= 0:
        raise ValueError("claim_slots_must_be_positive")
    per_slot = len(PRIVATE_MASTER_SCALARS_PER_SLOT)
    base = claim_slots * per_slot
    remaining = CURRENT_MESSAGE_CAPACITY_COEFFICIENTS - base
    blockers = (
        (
            "no_coefficient_room_for_hidden_state_or_auxiliaries",
            "exact_compact_relation_manifest_missing",
            "semantic_equivalence_delegation_boundary_unproved",
        )
        if remaining <= 0
        else (
            "exact_compact_relation_manifest_missing",
            "semantic_equivalence_delegation_boundary_unproved",
        )
    )
    verdict = (
        "REJECTED_CURRENT_M1"
        if remaining <= 0
        else "CAPACITY_HEADROOM_ONLY_NOT_ADMITTED"
    )
    return CompactCapacityScreen(
        profile_id=profile_id,
        claim_slots=claim_slots,
        private_scalars_per_slot=per_slot,
        base_private_coefficients=base,
        base_message_rank=_ceil_div(
            base, D256_BOX4_Q68_K29.degree
        ),
        remaining_coefficients=remaining,
        maximum_per_slot_scalars_with_one_fixed_coefficient=(
            (CURRENT_MESSAGE_CAPACITY_COEFFICIENTS - 1) // claim_slots
        ),
        verdict=verdict,
        blockers=blockers,
    )


def main() -> None:
    for profile_id, claim_slots in (
        ("K128_CALIBRATION", 128),
        ("K512_CALIBRATION", 512),
    ):
        print(screen_workspace_master_record(profile_id, claim_slots))


if __name__ == "__main__":
    main()
