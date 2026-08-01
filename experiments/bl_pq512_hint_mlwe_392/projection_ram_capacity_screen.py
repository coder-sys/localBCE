"""Concrete-admission screen for the touched-projection RAM candidate.

The primary projection-code theorem has two branches:

* near-linear encoding size and ``O~(k^2)`` projection time; or
* ``O~(k^(1+alpha))`` projection time with ``O(n^c_alpha)`` encoding size.

Here ``k`` counts binary database coordinates.  A fixed-shape Blind Ledger
batch permits every governed state operation to touch a distinct 512-bit
value, so qualification has to cover at least that adversarial schedule.
The source does not publish concrete constants or a reference implementation
from which laptop RAM, scratch, or time can be derived.  This screen therefore
does not turn asymptotic notation into a fake benchmark: it records the exact
Blind Ledger input scale and refuses to admit C3 until concrete parameters
exist.
"""

from __future__ import annotations

from dataclasses import dataclass

from experiments.bl_pq512_crypto_foundation.claim_batch_access_manifest import (
    build_c0_claim_batch_access_manifest,
)
from experiments.fixed_shape_claim_air.profile import PROFILES


PRIMARY_SOURCE = (
    "https://escholarship.org/content/qt9405r7n6/"
    "qt9405r7n6_noSplash_0eef9d1e41a4330580e002ff86d1089a.pdf"
)
STATE_VALUE_BITS = 512


@dataclass(frozen=True, slots=True)
class ProjectionRamCapacityScreen:
    profile_id: str
    state_operations: int
    qualification_touched_bits: int
    quadratic_projection_scale: int
    concrete_time_known: bool
    concrete_ram_known: bool
    concrete_scratch_known: bool
    verdict: str
    blockers: tuple[str, ...]


def screen_projection_ram(profile_id: str) -> ProjectionRamCapacityScreen:
    try:
        profile = PROFILES[profile_id]
    except KeyError as exc:
        raise ValueError("projection_ram_profile_unknown") from exc

    manifest = build_c0_claim_batch_access_manifest(profile)
    operations = manifest.ordered_map_operations
    touched_bits = operations * STATE_VALUE_BITS

    return ProjectionRamCapacityScreen(
        profile_id=profile_id,
        state_operations=operations,
        qualification_touched_bits=touched_bits,
        quadratic_projection_scale=touched_bits * touched_bits,
        concrete_time_known=False,
        concrete_ram_known=False,
        concrete_scratch_known=False,
        verdict="NOT_ADMITTED_C3_NO_CONCRETE_LAPTOP_PARAMETERS",
        blockers=(
            "quadratic_branch_has_only_asymptotic_projection_time",
            "subquadratic_branch_has_superlinear_global_encoding",
            "no_concrete_reference_parameters_or_implementation",
            "native_blind_ledger_hiding_and_atomic_composition_not_supplied",
        ),
    )


def main() -> None:
    for profile_id in ("K128_CALIBRATION", "K512_CALIBRATION"):
        print(screen_projection_ram(profile_id))


if __name__ == "__main__":
    main()
