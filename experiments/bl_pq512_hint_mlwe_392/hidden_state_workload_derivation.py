"""Derive honest Keccak workload bounds for hidden-state architecture screens.

The previously used 782/894 permutation pair is not derived from the sealed
Wave 1 schedule.  This module separates three materially different changes:

* replacing only authenticated replay/payment state;
* additionally authenticating governed private input columns directly while
  retaining the sealed deterministic A12 nullifier derivation; and
* replacing A12 with public random nullifiers, which is a semantic change and
  therefore receives no admissible workload credit.

The committed-state wrapper and its SHA3-512 public identifier are not yet
specified, so even the admissible lower bound is not an exact final workload.
"""

from __future__ import annotations

from dataclasses import dataclass

from experiments.fixed_shape_claim_air.profile import PROFILES
from experiments.fixed_shape_claim_air.wave1a_global_sha3_capacity_schedule import (
    build_wave1a_global_sha3_capacity_schedule,
)


HARD_CODED_MODEL = {
    "K128_CALIBRATION": 782,
    "K512_CALIBRATION": 894,
}


@dataclass(frozen=True, slots=True)
class HiddenStateWorkloadDerivation:
    profile_id: str
    sealed_permutations: int
    state_permutations_removed: int
    state_only_replacement_permutations: int
    claim_truth_permutations_removed: int
    deterministic_nullifier_permutations_retained: int
    salt_use_permutations_retained: int
    master_permutations_retained: int
    admissible_lower_bound_permutations: int
    hard_coded_model_permutations: int
    hard_coded_model_delta_from_admissible_lower_bound: int
    random_nullifier_model_admissible: bool
    exact_final_workload_known: bool
    unresolved_additions: tuple[str, ...]


def derive_hidden_state_workload(
    profile_id: str,
) -> HiddenStateWorkloadDerivation:
    try:
        profile = PROFILES[profile_id]
    except KeyError as exc:
        raise ValueError("hidden_state_profile_unknown") from exc
    schedule = build_wave1a_global_sha3_capacity_schedule(profile)
    by_component = {
        component: sum(
            run.permutations
            for run in schedule.runs
            if run.component == component
        )
        for component in {
            "claim_truth",
            "a12_nullifier",
            "salt_use",
            "replay_map",
            "payment",
            "master",
        }
    }
    state = by_component["replay_map"] + by_component["payment"]
    admissible = (
        by_component["a12_nullifier"]
        + by_component["salt_use"]
        + by_component["master"]
    )
    model = HARD_CODED_MODEL[profile_id]
    return HiddenStateWorkloadDerivation(
        profile_id=profile_id,
        sealed_permutations=schedule.total_permutations,
        state_permutations_removed=state,
        state_only_replacement_permutations=(
            schedule.total_permutations - state
        ),
        claim_truth_permutations_removed=by_component["claim_truth"],
        deterministic_nullifier_permutations_retained=(
            by_component["a12_nullifier"]
        ),
        salt_use_permutations_retained=by_component["salt_use"],
        master_permutations_retained=by_component["master"],
        admissible_lower_bound_permutations=admissible,
        hard_coded_model_permutations=model,
        hard_coded_model_delta_from_admissible_lower_bound=model - admissible,
        random_nullifier_model_admissible=False,
        exact_final_workload_known=False,
        unresolved_additions=(
            "committed_state_before_after_sha3_512_identifier_schedule",
            "state_commitment_to_semantic_air_bridge",
            "authority_signed_private_column_commitment_binding",
            "atomic_state_transition_transcript_binding",
        ),
    )


def main() -> None:
    for profile_id in ("K128_CALIBRATION", "K512_CALIBRATION"):
        print(derive_hidden_state_workload(profile_id))


if __name__ == "__main__":
    main()
