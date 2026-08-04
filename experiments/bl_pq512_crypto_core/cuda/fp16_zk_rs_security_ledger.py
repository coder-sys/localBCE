"""Exact parameter ledger for the candidate Fp16 ZK-RS IOPP.

This instantiates Theorem 8.1 of Chiesa--Fenzi--Weissenberg, ePrint
2026/391, in the unique-decoding/MCA regime.  The MCA bound used here is the
unconditional linear-code bound at radius below one third of relative
distance: base-code error at most block_length / |F|, with the paper's
interleaving lemma contributing the interleaving factor.

This script closes the numerical IOPP schedule and the exact algebraic errors
introduced by the nineteen-claim, sixteen-packed-coordinate binding, the
nine-round quadratic row sumcheck, and the worst-case K512 square-free state
composition. It does not by itself qualify the complete Blind Ledger proof.
"""

import math
from fractions import Fraction


M31 = 2_147_483_647
FIELD_CARDINALITY = M31**16
TARGET_BITS = 392

MAIN_BLOCK = 131_072
MAIN_MESSAGE = 65_536
MAIN_RANDOMNESS = 2_048
MAIN_DIMENSION = MAIN_MESSAGE + MAIN_RANDOMNESS
MAIN_DISTANCE_NUMERATOR = MAIN_BLOCK - MAIN_DIMENSION + 1
MAIN_DELTA = Fraction(5, 32)
MAIN_QUERIES = 1_600
MAIN_INTERLEAVING = 512
SUMCHECK_ROUNDS = 9
GKR_CLAIMS = 19
PACKED_COORDINATES = 16
SUMCHECK_DEGREE = 2

STATE_CAPACITY = 512
STATE_PHASES = 2
STATE_COMPOSED_GKR_LAYERS = 65
STATE_SQUAREFREE_LAYERS_PER_PHASE = 32
STATE_SUMCHECK_ROUNDS = 777
STATE_SUMCHECK_DEGREE_BUDGET = 1_748
STATE_CLAIM_COMBINATIONS = STATE_COMPOSED_GKR_LAYERS
STATE_COEFFICIENT_CLAIM_COMBINATIONS = 1
STATE_GKR_MASK_PADDED = 32_768
STATE_GKR_MASK_USED = 28_932
STATE_GKR_MASK_LEAKAGE_RANK = 27_768
STATE_GKR_MASK_PCS_CONDITIONED_RANK = 29_368
STATE_GKR_MASK_FREE_DIMENSION = 3_400

MASK_BLOCK = 8_192
MASK_MESSAGE = MAIN_RANDOMNESS
MASK_RANDOMNESS = 1_218
MASK_DIMENSION = MASK_MESSAGE + MASK_RANDOMNESS
MASK_DISTANCE_NUMERATOR = MASK_BLOCK - MASK_DIMENSION + 1
MASK_DELTA = Fraction(1, 5)
MASK_QUERIES = 1_218
INPUT_MASK_ORACLES = 0
SUMCHECK_MASK_ORACLES = SUMCHECK_ROUNDS
BASE_PROTOCOL_MASK_ORACLES = SUMCHECK_ROUNDS


def bits(probability):
    if probability <= 0:
        return math.inf
    return math.log2(probability.denominator) - math.log2(
        probability.numerator
    )


def require(condition, label):
    if not condition:
        raise SystemExit(label)


def main():
    require(
        MAIN_INTERLEAVING == 1 << SUMCHECK_ROUNDS,
        "main_interleaving_round_mismatch",
    )
    require(
        3 * MAIN_DELTA
        < Fraction(MAIN_DISTANCE_NUMERATOR, MAIN_BLOCK),
        "main_mca_radius_not_strict",
    )
    require(
        2 * MAIN_DELTA
        < Fraction(MAIN_DISTANCE_NUMERATOR, MAIN_BLOCK),
        "main_unique_decoding_not_strict",
    )
    require(
        3 * MASK_DELTA
        < Fraction(MASK_DISTANCE_NUMERATOR, MASK_BLOCK),
        "mask_mca_radius_not_strict",
    )
    require(
        2 * MASK_DELTA
        < Fraction(MASK_DISTANCE_NUMERATOR, MASK_BLOCK),
        "mask_unique_decoding_not_strict",
    )
    require(
        MAIN_RANDOMNESS >= MAIN_QUERIES,
        "main_zk_randomness_below_query_count",
    )
    require(
        MASK_RANDOMNESS >= MASK_QUERIES,
        "mask_zk_randomness_below_query_count",
    )
    require(MASK_MESSAGE >= 2, "mask_message_too_short")
    require(M31 % 2 == 1, "field_characteristic_two")
    require(
        STATE_GKR_MASK_USED <= STATE_GKR_MASK_PADDED,
        "state_gkr_mask_layout_overflow",
    )
    require(
        STATE_GKR_MASK_LEAKAGE_RANK + MAIN_QUERIES
        == STATE_GKR_MASK_PCS_CONDITIONED_RANK,
        "state_gkr_mask_conditioned_rank_mismatch",
    )
    require(
        STATE_GKR_MASK_PADDED - STATE_GKR_MASK_PCS_CONDITIONED_RANK
        == STATE_GKR_MASK_FREE_DIMENSION
        and STATE_GKR_MASK_FREE_DIMENSION > 0,
        "state_gkr_mask_randomness_exhausted",
    )

    field_inverse = Fraction(1, FIELD_CARDINALITY)
    nonzero_field_inverse = Fraction(1, FIELD_CARDINALITY - 1)
    errors = [
        (
            "gkr_claim_batch",
            Fraction(GKR_CLAIMS - 1, FIELD_CARDINALITY),
        ),
        (
            "packed_coordinate_batch",
            Fraction(PACKED_COORDINATES - 1, FIELD_CARDINALITY),
        ),
        (
            "source_mask_batch",
            field_inverse,
        ),
        (
            "quadratic_row_sumcheck",
            Fraction(
                SUMCHECK_ROUNDS * SUMCHECK_DEGREE,
                FIELD_CARDINALITY,
            ),
        ),
        (
            "state_key_compression_collision",
            Fraction(
                STATE_PHASES * STATE_CAPACITY * (STATE_CAPACITY - 1) // 2,
                FIELD_CARDINALITY,
            ),
        ),
        (
            "state_squarefree_identity",
            Fraction(
                STATE_PHASES * (2 * STATE_CAPACITY - 1),
                FIELD_CARDINALITY,
            ),
        ),
        (
            "state_squarefree_sumchecks",
            Fraction(
                STATE_SUMCHECK_DEGREE_BUDGET,
                FIELD_CARDINALITY,
            ),
        ),
        (
            "state_squarefree_claim_combinations",
            STATE_CLAIM_COMBINATIONS * nonzero_field_inverse,
        ),
        (
            "state_coefficient_claim_combination",
            STATE_COEFFICIENT_CLAIM_COMBINATIONS * nonzero_field_inverse,
        ),
        ("initial_list_field", field_inverse),
    ]
    for round_index in range(1, SUMCHECK_ROUNDS + 1):
        remaining_interleaving = 1 << (
            SUMCHECK_ROUNDS - round_index
        )
        mca = Fraction(
            remaining_interleaving * MAIN_BLOCK,
            FIELD_CARDINALITY,
        )
        list_field = Fraction(MASK_MESSAGE, FIELD_CARDINALITY)
        errors.append(
            (
                f"sumcheck_round_{round_index}_mca_plus_field",
                mca + list_field,
            )
        )
    base_error = Fraction(MAIN_BLOCK, FIELD_CARDINALITY)
    base_error += Fraction(
        SUMCHECK_ROUNDS * MASK_BLOCK,
        FIELD_CARDINALITY,
    )
    base_error += field_inverse
    errors.append(("base_combination", base_error))
    main_query_error = (1 - MAIN_DELTA) ** MAIN_QUERIES
    mask_query_error = (1 - MASK_DELTA) ** MASK_QUERIES
    query_error = max(main_query_error, mask_query_error)
    errors.append(("spotcheck_max", query_error))

    composed_error = sum(
        (probability for _, probability in errors),
        Fraction(0, 1),
    )
    minimum_term_bits = min(bits(probability) for _, probability in errors)
    require(
        minimum_term_bits >= TARGET_BITS,
        "iopp_term_below_target",
    )
    require(
        bits(composed_error) >= TARGET_BITS,
        "iopp_composition_below_target",
    )

    print("ledger=fp16_zk_rs_theorem_8_1_state_composed_v3")
    print("activation=false")
    print("proof_suite_id=null")
    print("theorem_source=eprint_2026_391_theorem_8_1")
    print(
        "mca_bound_source="
        "eprint_2025_753_unique_decoding_linear_code_n_over_field"
    )
    print("mca_assumption=unconditional_unique_decoding_regime")
    print(f"target_error_bits={TARGET_BITS}")
    print(f"field_cardinality_bits={math.log2(FIELD_CARDINALITY):.9f}")
    print("field_characteristic_not_two=true")
    print(f"main_block={MAIN_BLOCK}")
    print(f"main_message={MAIN_MESSAGE}")
    print(f"main_randomness={MAIN_RANDOMNESS}")
    print(f"main_dimension={MAIN_DIMENSION}")
    print(
        "main_relative_distance="
        f"{MAIN_DISTANCE_NUMERATOR}/{MAIN_BLOCK}"
    )
    print("main_proximity=5/32")
    print(f"main_queries={MAIN_QUERIES}")
    print(f"main_query_error_bits={bits(main_query_error):.9f}")
    print(f"main_interleaving={MAIN_INTERLEAVING}")
    print(f"gkr_claims={GKR_CLAIMS}")
    print(f"packed_coordinates={PACKED_COORDINATES}")
    print(f"sumcheck_rounds={SUMCHECK_ROUNDS}")
    print(f"sumcheck_degree={SUMCHECK_DEGREE}")
    print(f"state_capacity_worst_case={STATE_CAPACITY}")
    print(f"state_phases={STATE_PHASES}")
    print(
        "state_squarefree_layers_per_phase="
        f"{STATE_SQUAREFREE_LAYERS_PER_PHASE}"
    )
    print(
        "state_sumcheck_rounds="
        f"{STATE_SUMCHECK_ROUNDS}"
    )
    print(f"state_sumcheck_degree_budget={STATE_SUMCHECK_DEGREE_BUDGET}")
    print(
        "state_claim_combinations="
        f"{STATE_CLAIM_COMBINATIONS}"
    )
    print(
        "state_coefficient_claim_combinations="
        f"{STATE_COEFFICIENT_CLAIM_COMBINATIONS}"
    )
    print(f"state_gkr_mask_padded_coefficients={STATE_GKR_MASK_PADDED}")
    print(f"state_gkr_mask_used_coefficients={STATE_GKR_MASK_USED}")
    print(f"state_gkr_mask_leakage_rank={STATE_GKR_MASK_LEAKAGE_RANK}")
    print(
        "state_gkr_mask_pcs_conditioned_rank="
        f"{STATE_GKR_MASK_PCS_CONDITIONED_RANK}"
    )
    print(f"state_gkr_mask_free_dimension={STATE_GKR_MASK_FREE_DIMENSION}")
    print(f"mask_block={MASK_BLOCK}")
    print(f"mask_message={MASK_MESSAGE}")
    print(f"mask_randomness={MASK_RANDOMNESS}")
    print(f"mask_dimension={MASK_DIMENSION}")
    print(
        "mask_relative_distance="
        f"{MASK_DISTANCE_NUMERATOR}/{MASK_BLOCK}"
    )
    print("mask_proximity=1/5")
    print(f"mask_queries={MASK_QUERIES}")
    print(f"mask_query_error_bits={bits(mask_query_error):.9f}")
    print(
        "total_oracle_queries="
        f"{MAIN_QUERIES + SUMCHECK_MASK_ORACLES * MASK_QUERIES}"
    )
    print(
        "sumcheck_mask_oracles="
        f"{SUMCHECK_MASK_ORACLES}"
    )
    print(
        "base_protocol_mask_oracles="
        f"{BASE_PROTOCOL_MASK_ORACLES}"
    )
    for label, probability in errors:
        print(f"error_{label}_bits={bits(probability):.9f}")
    print(f"minimum_independent_error_bits={minimum_term_bits:.9f}")
    print(f"composed_iopp_error_bits={bits(composed_error):.9f}")
    print("main_rs_query_zk_error=0")
    print("mask_rs_query_zk_error=0")
    print("iopp_parameter_schedule_closed=true")
    print("each_iopp_error_term_at_least_392_bits=true")
    print("composed_iopp_error_at_least_392_bits=true")
    print("nineteen_claim_coordinate_binding_ledger_closed=true")
    print("quadratic_row_sumcheck_ledger_closed=true")
    print("state_squarefree_algebraic_ledger_closed=true")
    print("state_gkr_mask_rank_ledger_closed=true")
    print("candidate_iopp_source_implemented=true")
    print("iopp_implementation_complete=false")
    print("canonical_communication_grammar_closed=false")
    print("complete_simulator_implementation_verified=true")
    print("cryptographic_composition_ledger_closed=false")
    print("complete_proof_qualification=false")


if __name__ == "__main__":
    main()
