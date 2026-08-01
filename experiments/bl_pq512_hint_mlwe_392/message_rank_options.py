"""Measured limiting-attack options above the current m1=12 boundary."""

from __future__ import annotations

from dataclasses import dataclass, replace

from experiments.bl_pq512_hint_mlwe_392.candidate_geometry import (
    D256_BOX4_Q68_K29,
    GeometryResult,
    derive_geometry,
)


@dataclass(frozen=True, slots=True)
class MessageRankOption:
    message_rank: int
    base: int
    modulus: int
    sage_prime_attempts: int
    proof_bytes: int
    matrix_coefficients: int
    simulatability_usvp_bits: str
    knowledge_sis_bits: str
    estimator_input_sha3_512: str


@dataclass(frozen=True, slots=True)
class MessageRankOptionScreen:
    option: MessageRankOption
    geometry: GeometryResult
    coefficient_capacity: int
    status: str
    unresolved: tuple[str, ...]


OPTIONS = (
    MessageRankOption(
        13,
        19_753_217_274,
        390_189_592_673_851_991_077,
        5,
        163_986,
        760_320,
        "405.98",
        "431.155",
        "41de51e6f0eceadd7f2a42bc693ab5481bb62b9838796189f258c220c705"
        "f7eac7ceb701cd30013dedeaf33b5f7b7b819d04d60e330c94e43c4a032f2aaf8f19",
    ),
    MessageRankOption(
        16,
        21_919_567_806,
        480_467_452_801_831_653_637,
        22,
        173_696,
        811_008,
        "403.595",
        "428.77",
        "02e38d3f13adb5b19ed0020aaa044f3609b70d9f64564b5074636f5dfce616"
        "b19ebad4a2dc8d38f1fd44ab3f3707260e83f6afb8b91787194b402f4afb1693fb",
    ),
    MessageRankOption(
        24,
        26_858_388_586,
        721_373_037_436_575_079_397,
        17,
        200_707,
        946_176,
        "399.09",
        "424.0",
        "f0a44859125811b49b366266fade69e8f38f84c540e880e8fc37e569d954a53"
        "bcef12e59cd1b669697e7626836252be96ac90cb9d2d440d8053527edf1d2e96b",
    ),
    MessageRankOption(
        32,
        31_023_618_734,
        962_464_919_352_595_762_757,
        6,
        228_647,
        1_081_344,
        "395.91",
        "420.82",
        "e68b2e6b2125ae96915cd42cca5f225016236ede40418e9a7f50245a3f516a6"
        "f5767b9365ab1e68574aa98d20630a4595514a8fff004815335eb1827537f45da",
    ),
)


def screen_option(option: MessageRankOption) -> MessageRankOptionScreen:
    if option.base % 1_249 or option.base % 4 != 2:
        raise ValueError("option_base_congruence_invalid")
    if option.modulus != option.base * option.base + 1:
        raise ValueError("option_modulus_not_base_squared_plus_one")
    geometry = derive_geometry(
        replace(
            D256_BOX4_Q68_K29,
            message_rank=option.message_rank,
            base=option.base,
            modulus=option.modulus,
        )
    )
    if (
        geometry.proof_bytes_ceiling != option.proof_bytes
        or geometry.matrix_coefficients != option.matrix_coefficients
    ):
        raise ValueError("option_geometry_mismatch")
    if (
        not geometry.knowledge_below_modulus
        or not geometry.binding_below_modulus
        or not geometry.compression_divides_modulus_minus_one
        or not geometry.compression_inequality_holds
    ):
        raise ValueError("option_geometry_gate_failed")
    if min(
        float(option.simulatability_usvp_bits),
        float(option.knowledge_sis_bits),
    ) < 392:
        raise ValueError("option_limiting_attack_below_392")
    return MessageRankOptionScreen(
        option=option,
        geometry=geometry,
        coefficient_capacity=option.message_rank
        * D256_BOX4_Q68_K29.degree,
        status="LIMITING_ATTACKS_PASS_FULL_ATTACKS_PENDING",
        unresolved=(
            "complete_default_attack_set",
            "bkw_estimator_model_gap",
            "exact_compact_relation_manifest",
            "authenticated_public_coin_backend",
            "full_prover_and_verifier_measurement",
        ),
    )


def main() -> None:
    for option in OPTIONS:
        print(screen_option(option))


if __name__ == "__main__":
    main()
