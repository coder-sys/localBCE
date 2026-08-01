"""Fail-closed cost screen for mapping Blind Ledger SHA3 into Hint-MLWE.

The circuit counts are copied from the executable generated-circuit report in
``experiments/bl_pq512_crypto_core/src/keccak_circuit.rs``. The 782/894
permutation workloads remain unqualified architecture-model inputs.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from experiments.bl_pq512_hint_mlwe_392.candidate_geometry import (
    D256_BOX4_Q68_K29,
    GeometryResult,
    derive_geometry,
)


STATE_BITS = 1_600
ROUNDS = 24
STATE_SNAPSHOTS_PER_PERMUTATION = ROUNDS + 1
CIRCUIT_DEPTH = 216
MAXIMUM_RAW_WIDTH = 3_200
MAXIMUM_PADDED_WIDTH = 4_096
XOR_GATES_PER_PERMUTATION = 192_000
AND_GATES_PER_PERMUTATION = 38_400
RELAY_GATES_PER_PERMUTATION = 230_400
PADDED_WIRES_PER_PERMUTATION = 589_824
LAPTOP_RAM_BYTES = 5_000_000_000
LAPTOP_SCRATCH_BYTES = 5_000_000_000


@dataclass(frozen=True, slots=True)
class Workload:
    profile_id: str
    sha3_permutations: int


@dataclass(frozen=True, slots=True)
class DirectHintMlweScreen:
    workload: Workload
    quadratic_relations: int
    linear_relations: int
    state_snapshot_bits: int
    state_only_message_rank_lower_bound: int
    generated_witness_coefficients: int
    generated_message_rank: int
    state_only_geometry: GeometryResult
    generated_geometry: GeometryResult
    generated_matrix_bytes_current_upstream: int
    verdict: str
    blockers: tuple[str, ...]


K128_MODEL = Workload("K128_HIDDEN_STATE_MODEL_UNQUALIFIED", 782)
K512_MODEL = Workload("K512_HIDDEN_STATE_MODEL_UNQUALIFIED", 894)


def _ceil_div(numerator: int, denominator: int) -> int:
    if numerator < 0 or denominator <= 0:
        raise ValueError("ceil_div_domain_error")
    return (numerator + denominator - 1) // denominator


def screen_direct_hint_mlwe(workload: Workload) -> DirectHintMlweScreen:
    if (
        type(workload.sha3_permutations) is not int
        or workload.sha3_permutations <= 0
    ):
        raise ValueError("sha3_permutations_must_be_positive")

    degree = D256_BOX4_Q68_K29.degree
    state_bits = (
        workload.sha3_permutations
        * STATE_SNAPSHOTS_PER_PERMUTATION
        * STATE_BITS
    )
    state_m1 = _ceil_div(state_bits, degree)
    generated_coefficients = (
        workload.sha3_permutations * PADDED_WIRES_PER_PERMUTATION
    )
    generated_m1 = _ceil_div(generated_coefficients, degree)
    state_geometry = derive_geometry(
        replace(D256_BOX4_Q68_K29, message_rank=state_m1)
    )
    generated_geometry = derive_geometry(
        replace(D256_BOX4_Q68_K29, message_rank=generated_m1)
    )
    matrix_bytes = (
        generated_geometry.matrix_coefficients
        * generated_geometry.modulus_limbs_64
        * 8
    )

    blockers: list[str] = []
    if not state_geometry.knowledge_below_modulus:
        blockers.append("state_only_knowledge_bound_not_below_modulus")
    if not generated_geometry.knowledge_below_modulus:
        blockers.append("generated_relation_knowledge_bound_not_below_modulus")
    if matrix_bytes >= LAPTOP_RAM_BYTES:
        blockers.append("current_upstream_dense_matrix_exceeds_3gb_ram")
    if generated_geometry.proof_bytes_ceiling >= LAPTOP_SCRATCH_BYTES:
        blockers.append("proof_alone_exceeds_5gb_scratch")

    return DirectHintMlweScreen(
        workload=workload,
        quadratic_relations=workload.sha3_permutations
        * (XOR_GATES_PER_PERMUTATION + AND_GATES_PER_PERMUTATION),
        linear_relations=workload.sha3_permutations
        * RELAY_GATES_PER_PERMUTATION,
        state_snapshot_bits=state_bits,
        state_only_message_rank_lower_bound=state_m1,
        generated_witness_coefficients=generated_coefficients,
        generated_message_rank=generated_m1,
        state_only_geometry=state_geometry,
        generated_geometry=generated_geometry,
        generated_matrix_bytes_current_upstream=matrix_bytes,
        verdict="DIRECT_HINT_MLWE_REJECTED",
        blockers=tuple(blockers),
    )


def maximum_current_candidate_message_rank() -> int:
    """Return the last m1 for which the current knowledge bound is below q."""

    message_rank = 1
    while derive_geometry(
        replace(D256_BOX4_Q68_K29, message_rank=message_rank)
    ).knowledge_below_modulus:
        message_rank += 1
    return message_rank - 1


def main() -> None:
    for workload in (K128_MODEL, K512_MODEL):
        result = screen_direct_hint_mlwe(workload)
        print(
            {
                "profile_id": workload.profile_id,
                "verdict": result.verdict,
                "sha3_permutations": workload.sha3_permutations,
                "quadratic_relations": result.quadratic_relations,
                "linear_relations": result.linear_relations,
                "state_only_m1_lower_bound": (
                    result.state_only_message_rank_lower_bound
                ),
                "generated_m1": result.generated_message_rank,
                "proof_bytes": result.generated_geometry.proof_bytes_ceiling,
                "matrix_bytes_current_upstream": (
                    result.generated_matrix_bytes_current_upstream
                ),
                "blockers": result.blockers,
            }
        )


if __name__ == "__main__":
    main()
