"""Nonactivating semantic-to-H4 padded-bus bridge reference.

This module freezes the *virtual* row map and the degree-three-or-less
relations needed to bind the existing Wave 1A SHA3 interface tables to the
existing H4 Keccak input/output boundary.  It deliberately does not allocate a
second copy of either production trace.  The selected prover still needs a
masked sparse-functional reduction from these virtual relations to the two
existing PCS commitments; the obligations are recorded in the canonical
program below.  Version 3 adds two small independent semantic-side carrier
polynomials and two H4-side mask polynomials under one typed aggregate
Construction object.  It never materializes another trace-sized bus oracle.

The executable helpers are synthetic KAT machinery.  They contain private
messages and H4 states only in memory and never serialize them as a public
proof output.  The small quotient evaluator is an M31 special-case algebraic
check.  The production bridge quotient is instead an exact 4,789-coefficient
Fp16 vector authenticated directly in parent round 901 before OODS sampling;
it does not require a separate FRI.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha3_512
import json
from math import log2
from typing import Final, Iterable, Sequence

from experiments.bl_pq512_crypto_foundation.field16_reference import M31_MODULUS
from experiments.bl_pq512_crypto_foundation.sha3_512_air_reference import (
    KECCAK_ROUNDS,
    RATE_BYTES,
    STATE_BYTES,
    _build_round,
)

from .application_sha3_executable_air import Sha3Call
from .profile import CalibrationProfile
from .semantics import StructuralError
from .wave1a_global_sha3_capacity_schedule import (
    PROFILE_TAGS,
    build_wave1a_global_sha3_capacity_schedule,
)


PROGRAM_ID: Final[str] = "BL-WAVE1A-SEMANTIC-H4-BRIDGE-RELATION-v3"
PROGRAM_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE1A/SEMANTIC-H4-BRIDGE-PROGRAM/v3\x00"
STATUS: Final[str] = "WAVE1A_SEMANTIC_H4_BRIDGE_REFERENCE_NONACTIVATING"
BASE_PROGRAM_ID: Final[str] = "BL-WAVE1A-GLOBAL-EXECUTABLE-AIR-v1"

DIGEST_BYTES: Final[int] = 64
STATE_BITS: Final[int] = STATE_BYTES * 8
RATE_BITS: Final[int] = RATE_BYTES * 8
CAPACITY_BITS: Final[int] = STATE_BITS - RATE_BITS
MAXIMUM_CONSTRAINT_DEGREE: Final[int] = 3
SEMANTIC_MASK_COEFFICIENT_COUNT: Final[int] = 4_789
SEMANTIC_MASK_PADDED_COUNT: Final[int] = 8_192
QUOTIENT_IDENTITY_COUNT: Final[int] = 2
SYNTHETIC_MAXIMUM_GROUP_ROWS: Final[int] = 1 << 16
H4_BRIDGE_MASK_COEFFICIENT_COUNT: Final[int] = 4_789
H4_BRIDGE_MASK_PADDED_COUNT: Final[int] = 8_192
H4_BRIDGE_CONSTRUCTION_ROOT_OWNERSHIP: Final[str] = (
    "ONE_TYPED_AGGREGATE_OBJECT_WITH_ORDERED_C_MESSAGE_C_DIGEST_N_MESSAGE_N_DIGEST_LANES"
)
H4_BRIDGE_MASK_LANE_COUNT: Final[int] = 4
H4_BRIDGE_MASK_LANES_PER_GROUP: Final[int] = 2
H4_BRIDGE_MASK_DOMAIN_SEPARATED_EVALUATIONS_PER_GROUP: Final[int] = 4
H4_BRIDGE_MASK_DOMAIN_SEPARATED_EVALUATIONS: Final[int] = (
    H4_BRIDGE_MASK_LANE_COUNT * 2
)
H4_BRIDGE_MASK_AUXILIARY_SPOTCHECK_OPENINGS: Final[int] = 1_218
H4_BRIDGE_MASK_CONDITIONAL_OBSERVATION_RANK_PER_GROUP: Final[int] = (
    H4_BRIDGE_MASK_LANES_PER_GROUP
    * H4_BRIDGE_MASK_AUXILIARY_SPOTCHECK_OPENINGS
    + 2
)
H4_BRIDGE_MASK_CONDITIONAL_OBSERVATION_RANK: Final[int] = (
    len(("message", "digest"))
    * H4_BRIDGE_MASK_CONDITIONAL_OBSERVATION_RANK_PER_GROUP
)
H4_BRIDGE_MASK_CONDITIONAL_RESIDUAL_FREEDOM_PER_GROUP: Final[int] = (
    H4_BRIDGE_MASK_COEFFICIENT_COUNT
    - H4_BRIDGE_MASK_CONDITIONAL_OBSERVATION_RANK_PER_GROUP
)
H4_BRIDGE_MASK_CONDITIONAL_RESIDUAL_FREEDOM: Final[int] = (
    len(("message", "digest"))
    * H4_BRIDGE_MASK_CONDITIONAL_RESIDUAL_FREEDOM_PER_GROUP
)
H4_BRIDGE_MASK_RESIDUAL_BITS_PER_GROUP: Final[float] = round(
    H4_BRIDGE_MASK_CONDITIONAL_RESIDUAL_FREEDOM_PER_GROUP
    * 16
    * log2(M31_MODULUS),
    4,
)
H4_BRIDGE_MASK_RESIDUAL_BITS_FLOOR_PER_GROUP: Final[int] = (
    H4_BRIDGE_MASK_CONDITIONAL_RESIDUAL_FREEDOM_PER_GROUP * 16 * 30
)
H4_BRIDGE_MASK_PUBLIC_ANSWER_FORM: Final[str] = "A_lane=B_lane+mu*R_lane"
H4_BRIDGE_SERIALIZED_FUNCTIONAL_INVENTORY: Final[tuple[str, ...]] = (
    "groups:message,digest",
    "semantic_native_mask_coefficients_M31_per_group:4789",
    "semantic_selected_observation_rank_M31_per_group:4789",
    "semantic_C_coefficients_Fp16_per_group:4789",
    "H4_N_coefficients_Fp16_per_group:4789",
    "C_and_N_independent_R_coefficients_Fp16_per_group:2x4789",
    "Q_coefficients_Fp16_per_group:4789",
    "A_C_and_A_N_coefficients_Fp16_per_group:2x4789",
    "paired_base_pad_direct_query_openings_Fp16_per_lane:1218",
    "C_and_N_oods_evaluations_Fp16_per_group:4_rank_at_most_2_after_Q",
)
H4_BRIDGE_MASK_DOMAIN_MAPS: Final[tuple[str, str]] = (
    "message_lanes=(C_message,N_message)",
    "digest_lanes=(C_digest,N_digest)",
)
SEMANTIC_BRIDGE_CARRIER_COEFFICIENT_COUNT: Final[int] = 4_789
QUOTIENT_COMPONENT_COUNT: Final[int] = 1
QUOTIENT_COMPONENT_ORDER: Final[tuple[str, ...]] = ("coefficients[0:4789]",)
QUOTIENT_COEFFICIENT_BASIS: Final[str] = (
    "Circle-FFT tensor basis in bit-reversed coefficient order "
    "[y,x,pi(x),pi^2(x),...] with pi(x)=2*x^2-1; append 3403 exact Fp16 zeros "
    "to length 8192 before evaluate_extension_coefficients_at_point"
)
QUOTIENT_ROOT_DOMAIN: Final[str] = (
    "BL/PQ512/WAVE1A/SEMANTIC-H4-BRIDGE/DIRECT-Q-COEFFICIENTS/v1"
)
FP16_CANONICAL_BYTES: Final[int] = 64
PARENT_MAX_PROVER_MESSAGE_BYTES: Final[int] = 1 << 20
PARENT_KIND901_FIXED_BYTES: Final[int] = 212
PARENT_KIND901_GROUP_FRAME_BYTES: Final[int] = 8
PARENT_KIND901_DIRECT_Q_BYTES: Final[int] = (
    2
    * (
        PARENT_KIND901_GROUP_FRAME_BYTES
        + H4_BRIDGE_MASK_COEFFICIENT_COUNT * FP16_CANONICAL_BYTES
    )
)
PARENT_KIND901_MESSAGE_BYTES: Final[int] = (
    PARENT_KIND901_FIXED_BYTES + PARENT_KIND901_DIRECT_Q_BYTES
)
BRIDGE_PUBLIC_ANSWER_COEFFICIENT_BYTES: Final[int] = (
    H4_BRIDGE_MASK_LANE_COUNT
    * H4_BRIDGE_MASK_COEFFICIENT_COUNT
    * FP16_CANONICAL_BYTES
)
BRIDGE_CONSTRUCTION_BASE_LANE_ORDER: Final[tuple[str, ...]] = (
    "C_message",
    "C_digest",
    "N_message",
    "N_digest",
)
BRIDGE_CONSTRUCTION_PAD_LANE_ORDER: Final[tuple[str, ...]] = (
    "R_C_message",
    "R_C_digest",
    "R_N_message",
    "R_N_digest",
)
BRIDGE_CONSTRUCTION_ANSWER_LANE_ORDER: Final[tuple[str, ...]] = (
    "A_C_message",
    "A_C_digest",
    "A_N_message",
    "A_N_digest",
)
SELECTED_CIRCLE_QUERY_COUNT: Final[int] = 945
SELECTED_CIRCLE_THETA_NUMERATOR: Final[int] = 4_294_967_295
SELECTED_CIRCLE_THETA_DENOMINATOR: Final[int] = 17_179_869_184
SELECTED_CIRCLE_QUERY_SOUNDNESS_BITS: Final[float] = 392.2104367
SEMANTIC_SELECTED_OBSERVATION_RANK_M31_PER_GROUP: Final[int] = (
    2 * 2 * (16 + SELECTED_CIRCLE_QUERY_COUNT) + SELECTED_CIRCLE_QUERY_COUNT
)
BRIDGE_BATCHING_SOUNDNESS_BITS: Final[dict[int, float]] = {
    1: 467.7937,
    3: 465.9390,
}
CANONICAL_BUS_SCALAR_LAYOUT: Final[tuple[str, ...]] = (
    "message[j]=value[j]+256*live[j] in M31",
    "digest[64*i+t]=digest_byte[i,t] in M31",
    "tower_pack[q]=Fp16::from_coefficients(bus[16*q:16*q+16])",
    "H4_lane_l(C)=sum_{i=0}^{15}Fp16_coordinate_i(C)*l^i in M31",
    "global_permutation_p=(shard=floor(p/131072),within=p%131072,group=floor(within/16),lane=within%16)",
    "H4_source_address(w,g)=(word=floor(g/32),position=(g%32)*2048+w)",
)

NATIVE_GROUPS: Final[tuple[str, str]] = ("message", "digest")
SELECTOR_MAPS: Final[tuple[str, ...]] = (
    "A_0=1",
    "A_b=live[72*b-1] for b>0",
    "L_b=A_b*(1-A_(b+1)); A_block_count=0",
    "D_0=1-live[0]",
    "D_j=(1-live[j])*live[j-1] for j>0 within one call",
)
TRANSCRIPT_ORDER: Final[tuple[str, ...]] = (
    "base_program_and_profile_fixed",
    "existing_semantic_masked_main_root_fixed_without_any_raw_S_opening",
    "h4_source_and_typed_aggregate_C_N_base_and_independent_R_pad_roots_fixed",
    "constraint_family_batching_challenges",
    "typed_aggregate_A_root_and_two_exact_4789_coefficient_Q_vectors_fixed",
    "fp8_excluding_circle_oods_point",
    "complete_post_z_primitive_response_oracle_and_claim_vector_fixed",
    "completion_challenge",
    "challenge_selected_openings_authenticated_to_response_root",
)
SEMANTIC_PUBLIC_COIN_SPLIT: Final[tuple[str, ...]] = (
    "semantic_child_round0_main_root_completes_and_samples_logup_beta_gamma",
    "semantic_child_round1_interaction_root_completes_and_samples_semantic_composition_alpha",
    "semantic_composition_root_is_computed_but_native_child_oods_round_is_not_accepted",
    "parent_kind900_binds_semantic_session_schedule_partial_root_main_interaction_composition_roots",
    "parent_kind901_samples_the_only_z_and_injects_exact_xy_into_semantic_DEEP",
    "semantic_continuation_initial_root=H(parent_session,parent_round901_root,semantic_session,semantic_schedule,semantic_partial_root,composition_root,z)",
    "semantic_continuation_runs_oods_claim_fri_mask_batch_and_adaptive_fri_fold_rounds_from_that_root",
    "parent_kind902_binds_semantic_continuation_final_root_and_semantic_component_package_commitment",
)
SELECTED_WORKER_OBLIGATIONS: Final[tuple[str, ...]] = (
    "verify_h4_packed_input_booleanity_sumcheck_before_bridge_equality",
    "prove_predecessor_and_block_boundary_gather_maps_from_semantic_main_root",
    "prove_circle_lagrange_sparse_functional_from_h4_source_root",
    (
        "reserve_independent_8192_padded_C_message_C_digest_N_message_N_digest_"
        "base_lanes_and_four_independent_R_pad_lanes_before_bridge_alpha"
    ),
    "authenticate_existing_semantic_S_hat_and_small_Construction_C_at_z_and_conjugate",
    "forbid_every_raw_or_unmasked_semantic_S_opening",
    "compute_S_aug_equals_S_hat_plus_Z_H_times_C_inside_the_verifier",
    "verify_public_bridge_mask_answers_have_form_A_lane_equals_B_lane_plus_mu_times_R_lane",
    "parse_exact_canonical_4789_coefficient_Q_message_and_Q_digest_vectors_before_z",
    "authenticate_the_fixed_primitive_vector_contract_from_semantic_main_and_h4_source_roots",
    "open_z_and_fp8_conjugate_without_a_raw_bus_functional",
    "bind_h4_global_padding_lanes_to_zero_input_and_keccak_f_zero_output",
    "extend_selected_transcript_package_and_verifier_before_activation",
)
MASK_RANK_STATUS: Final[str] = (
    "QUALIFIED_2351_FP16_RESIDUAL_PER_GROUP_ONLY_FOR_THE_EXACT_SERIALIZED_INVENTORY"
)
H4_INPUT_BOOLEANITY_PREREQUISITE: Final[str] = (
    "H4_PACKED_SOURCE_16_COORDINATE_M31_DEGREE_2_INPUT_BOOLEANITY_SUMCHECK"
)


@dataclass(frozen=True, slots=True)
class BridgeMaskRankQualification:
    """Joint semantic-carrier/H4-lane rank for the exact serialized inventory."""

    direct_base_openings: int
    bridge_evaluations_per_group: int
    observation_rank_per_group: int
    observation_rank: int
    residual_freedom_per_group: int
    residual_freedom: int
    residual_bits_per_group: float
    residual_bits_floor_per_group: int


def qualify_bridge_mask_rank(
    *,
    serialized_field_inventory: Sequence[str],
) -> BridgeMaskRankQualification:
    """Qualify only the exact verifier-parsed C/N/R/A/Q field inventory."""

    if tuple(serialized_field_inventory) != H4_BRIDGE_SERIALIZED_FUNCTIONAL_INVENTORY:
        raise StructuralError("semantic_bus_bridge_mask_rank_unqualified")
    return BridgeMaskRankQualification(
        direct_base_openings=H4_BRIDGE_MASK_AUXILIARY_SPOTCHECK_OPENINGS,
        bridge_evaluations_per_group=(
            H4_BRIDGE_MASK_DOMAIN_SEPARATED_EVALUATIONS_PER_GROUP
        ),
        observation_rank_per_group=(
            H4_BRIDGE_MASK_CONDITIONAL_OBSERVATION_RANK_PER_GROUP
        ),
        observation_rank=H4_BRIDGE_MASK_CONDITIONAL_OBSERVATION_RANK,
        residual_freedom_per_group=(
            H4_BRIDGE_MASK_CONDITIONAL_RESIDUAL_FREEDOM_PER_GROUP
        ),
        residual_freedom=H4_BRIDGE_MASK_CONDITIONAL_RESIDUAL_FREEDOM,
        residual_bits_per_group=H4_BRIDGE_MASK_RESIDUAL_BITS_PER_GROUP,
        residual_bits_floor_per_group=H4_BRIDGE_MASK_RESIDUAL_BITS_FLOOR_PER_GROUP,
    )


def _next_power_of_two(value: int) -> int:
    if type(value) is not int or value <= 0:
        raise StructuralError("semantic_bus_bridge_positive_count_required")
    return 1 << (value - 1).bit_length()


def _field(value: int) -> int:
    if type(value) is not int:
        raise StructuralError("semantic_bus_bridge_field_value_invalid")
    return value % M31_MODULUS


@dataclass(frozen=True, slots=True)
class SemanticBusBridgeLayout:
    """Verifier-fixed production geometry; no witness rows are materialized."""

    profile_id: str
    governed_profile_code: int
    call_count: int
    total_capacity_bytes: int
    total_permutations: int
    padded_permutations: int
    coprocessor_shards: int
    message_logical_rows: int
    message_trace_rows: int
    digest_logical_rows: int
    digest_trace_rows: int
    message_evaluation_log_size: int
    digest_evaluation_log_size: int
    semantic_trace_padding_rows: int
    digest_trace_padding_rows: int
    h4_global_padding_permutations: int
    capacity_schedule_commitment_512: bytes
    hash_bus_descriptor_commitment_512: bytes

    def __post_init__(self) -> None:
        scalar_fields = (
            self.call_count,
            self.total_capacity_bytes,
            self.total_permutations,
            self.padded_permutations,
            self.coprocessor_shards,
            self.message_logical_rows,
            self.message_trace_rows,
            self.digest_logical_rows,
            self.digest_trace_rows,
            self.message_evaluation_log_size,
            self.digest_evaluation_log_size,
        )
        if (
            type(self.profile_id) is not str
            or not self.profile_id
            or self.governed_profile_code not in {1, 3}
            or PROFILE_TAGS.get(self.profile_id) != self.governed_profile_code
            or any(type(value) is not int or value <= 0 for value in scalar_fields)
            or type(self.semantic_trace_padding_rows) is not int
            or self.semantic_trace_padding_rows < 0
            or type(self.digest_trace_padding_rows) is not int
            or self.digest_trace_padding_rows < 0
            or type(self.h4_global_padding_permutations) is not int
            or self.h4_global_padding_permutations < 0
            or type(self.capacity_schedule_commitment_512) is not bytes
            or len(self.capacity_schedule_commitment_512) != 64
            or type(self.hash_bus_descriptor_commitment_512) is not bytes
            or len(self.hash_bus_descriptor_commitment_512) != 64
        ):
            raise StructuralError("semantic_bus_bridge_layout_invalid")
        if (
            self.message_logical_rows != self.total_permutations * RATE_BYTES
            or self.digest_logical_rows != self.call_count * DIGEST_BYTES
            or self.message_trace_rows != _next_power_of_two(self.message_logical_rows)
            or self.digest_trace_rows != _next_power_of_two(self.digest_logical_rows)
            or self.semantic_trace_padding_rows
            != self.message_trace_rows - self.message_logical_rows
            or self.digest_trace_padding_rows
            != self.digest_trace_rows - self.digest_logical_rows
            or self.h4_global_padding_permutations
            != self.padded_permutations - self.total_permutations
        ):
            raise StructuralError("semantic_bus_bridge_layout_arithmetic_invalid")

    def canonical(self) -> dict[str, object]:
        return {
            "profileId": self.profile_id,
            "governedProfileCode": self.governed_profile_code,
            "governedOriginalCallRange": [0, self.call_count],
            "callCount": self.call_count,
            "totalCapacityBytes": self.total_capacity_bytes,
            "totalPermutations": self.total_permutations,
            "paddedPermutations": self.padded_permutations,
            "coprocessorShards": self.coprocessor_shards,
            "messageLogicalRows": self.message_logical_rows,
            "messageTraceRows": self.message_trace_rows,
            "digestLogicalRows": self.digest_logical_rows,
            "digestTraceRows": self.digest_trace_rows,
            "messageEvaluationLogSize": self.message_evaluation_log_size,
            "digestEvaluationLogSize": self.digest_evaluation_log_size,
            "semanticTracePaddingRows": self.semantic_trace_padding_rows,
            "digestTracePaddingRows": self.digest_trace_padding_rows,
            "h4GlobalPaddingPermutations": self.h4_global_padding_permutations,
            "capacityScheduleCommitment512": self.capacity_schedule_commitment_512.hex(),
            "hashBusDescriptorCommitment512": self.hash_bus_descriptor_commitment_512.hex(),
        }


@dataclass(frozen=True, slots=True)
class BridgeConstraintFamily:
    name: str
    group: str
    maximum_degree: int
    scalar_equations: int
    virtual_row_map: str

    def __post_init__(self) -> None:
        if (
            type(self.name) is not str
            or not self.name
            or self.group not in NATIVE_GROUPS
            or type(self.maximum_degree) is not int
            or not 1 <= self.maximum_degree <= MAXIMUM_CONSTRAINT_DEGREE
            or type(self.scalar_equations) is not int
            or self.scalar_equations <= 0
            or type(self.virtual_row_map) is not str
            or not self.virtual_row_map
        ):
            raise StructuralError("semantic_bus_bridge_constraint_family_invalid")

    def canonical(self) -> dict[str, object]:
        return {
            "name": self.name,
            "group": self.group,
            "maximumDegree": self.maximum_degree,
            "scalarEquations": self.scalar_equations,
            "virtualRowMap": self.virtual_row_map,
        }


@dataclass(frozen=True, slots=True)
class BridgePrimitiveVector:
    """One verifier-fixed vector needed to evaluate the odd-characteristic AIR."""

    name: str
    group: str
    authentication: str
    value_definition: str
    algebraic_uses: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            not self.name
            or self.group not in NATIVE_GROUPS
            or self.authentication
            not in {
                "SEMANTIC_CIRCLE_PCS_TRANSLATED_OPENING",
                "H4_SOURCE_BASIS_CONVERSION_RESPONSE",
                "POST_Z_PRODUCT_RESPONSE",
                "VERIFIER_FIXED_SELECTOR",
            }
            or not self.value_definition
            or not self.algebraic_uses
        ):
            raise StructuralError("semantic_bus_bridge_primitive_vector_invalid")

    def canonical(self) -> dict[str, object]:
        return {
            "name": self.name,
            "group": self.group,
            "authentication": self.authentication,
            "valueDefinition": self.value_definition,
            "algebraicUses": list(self.algebraic_uses),
        }


PRIMITIVE_VECTOR_CONTRACT: Final[tuple[BridgePrimitiveVector, ...]] = (
    BridgePrimitiveVector(
        "semantic_message_live_value_and_predecessor",
        "message",
        "SEMANTIC_CIRCLE_PCS_TRANSLATED_OPENING",
        "(live[j],value[j],live[j-1]) with call-start predecessor fixed to zero",
        ("block_active", "actual_last", "delimiter", "rate_expected_byte"),
    ),
    BridgePrimitiveVector(
        "h4_rate_input_bits",
        "message",
        "H4_SOURCE_BASIS_CONVERSION_RESPONSE",
        "I_b[j]=Lane_l(input_source(shard,group,8*(j%72)+b)), b=0..7",
        ("absorbed_byte", "rate_xor_product"),
    ),
    BridgePrimitiveVector(
        "h4_rate_predecessor_output_bits",
        "message",
        "H4_SOURCE_BASIS_CONVERSION_RESPONSE",
        "P_b[j]=0 at call block zero, else Lane_l(output_source(global_permutation-1,8*(j%72)+b))",
        ("absorbed_byte", "rate_xor_product", "cross_shard_predecessor"),
    ),
    BridgePrimitiveVector(
        "h4_rate_input_times_predecessor_bits",
        "message",
        "POST_Z_PRODUCT_RESPONSE",
        "XP_b[j]=I_b[j]*P_b[j], b=0..7",
        ("I_xor_P=I+P-2*XP",),
    ),
    BridgePrimitiveVector(
        "h4_all_input_bits_alpha_batch",
        "message",
        "H4_SOURCE_BASIS_CONVERSION_RESPONSE",
        "sum_w alpha^(inactive_offset+w)*I_w at every block-start row",
        ("(1-block_active)*input",),
    ),
    BridgePrimitiveVector(
        "h4_capacity_input_and_predecessor_alpha_batches",
        "message",
        "H4_SOURCE_BASIS_CONVERSION_RESPONSE",
        "separate alpha-weighted input and predecessor-output sums for wires 576..1599",
        ("block_active*(input-predecessor)",),
    ),
    BridgePrimitiveVector(
        "semantic_digest_bytes_and_actual_last_gather",
        "digest",
        "SEMANTIC_CIRCLE_PCS_TRANSLATED_OPENING",
        "digest G[i,t] and actual_last E[i,k] gathered from authenticated live rows",
        ("digest_last_output",),
    ),
    BridgePrimitiveVector(
        "h4_digest_output_bits",
        "digest",
        "H4_SOURCE_BASIS_CONVERSION_RESPONSE",
        "O_b[i,k,t]=Lane_l(output_source(permutation(i,k),8*t+b)), b=0..7",
        ("digest_selected_output_product",),
    ),
    BridgePrimitiveVector(
        "semantic_actual_last_times_h4_digest_output",
        "digest",
        "POST_Z_PRODUCT_RESPONSE",
        "EO_b[i,k,t]=E[i,k]*O_b[i,k,t]",
        ("G[i,t]-sum_k sum_b 2^b*EO_b[i,k,t]",),
    ),
)


@dataclass(frozen=True, slots=True)
class BridgeQuotientIdentity:
    group: str
    witness_domain_rows: int
    trace_log_size: int
    coefficient_count: int
    padded_coefficient_count: int
    component_count: int
    component_order: tuple[str, ...]
    typed_root_domain: str
    equation: str

    def __post_init__(self) -> None:
        if (
            self.group not in NATIVE_GROUPS
            or type(self.witness_domain_rows) is not int
            or self.witness_domain_rows <= 0
            or self.witness_domain_rows & (self.witness_domain_rows - 1) != 0
            or self.trace_log_size != self.witness_domain_rows.bit_length() - 1
            or self.coefficient_count != H4_BRIDGE_MASK_COEFFICIENT_COUNT
            or self.padded_coefficient_count != H4_BRIDGE_MASK_PADDED_COUNT
            or self.component_count != QUOTIENT_COMPONENT_COUNT
            or self.component_order != QUOTIENT_COMPONENT_ORDER
            or self.typed_root_domain != QUOTIENT_ROOT_DOMAIN
            or type(self.equation) is not str
            or not self.equation
        ):
            raise StructuralError("semantic_bus_bridge_quotient_identity_invalid")

    def canonical(self) -> dict[str, object]:
        return {
            "group": self.group,
            "witnessDomainRows": self.witness_domain_rows,
            "traceLogSize": self.trace_log_size,
            "coefficientCount": self.coefficient_count,
            "degreeBoundExclusive": self.coefficient_count,
            "paddedCoefficientCount": self.padded_coefficient_count,
            "componentCount": self.component_count,
            "componentOrder": list(self.component_order),
            "coefficientBasis": QUOTIENT_COEFFICIENT_BASIS,
            "typedRootDomain": self.typed_root_domain,
            "encoding": "exact 4789 canonical 64-byte Fp16 tensor-basis coefficients in kind901",
            "authority": "verifier_parsed_authenticated_kind901_bytes_not_a_supplied_root_or_opening",
            "equation": self.equation,
        }


@dataclass(frozen=True, slots=True)
class SemanticBusBridgeProgram:
    layout: SemanticBusBridgeLayout
    constraint_families: tuple[BridgeConstraintFamily, ...]
    quotient_identities: tuple[BridgeQuotientIdentity, ...]
    status: str = STATUS
    proof_suite_id: None = None
    activation_allowed: bool = False
    h4_bridge_mask_coefficient_count: int = H4_BRIDGE_MASK_COEFFICIENT_COUNT

    def __post_init__(self) -> None:
        if (
            not isinstance(self.layout, SemanticBusBridgeLayout)
            or len(self.constraint_families) != 6
            or tuple(identity.group for identity in self.quotient_identities)
            != NATIVE_GROUPS
            or self.status != STATUS
            or self.proof_suite_id is not None
            or self.activation_allowed
            or self.h4_bridge_mask_coefficient_count != H4_BRIDGE_MASK_COEFFICIENT_COUNT
        ):
            raise StructuralError("semantic_bus_bridge_program_invalid")
        if max(family.maximum_degree for family in self.constraint_families) != 3:
            raise StructuralError("semantic_bus_bridge_degree_ledger_invalid")

    def canonical_object(self) -> dict[str, object]:
        return {
            "programId": PROGRAM_ID,
            "baseProgramId": BASE_PROGRAM_ID,
            "field": "Fp16(M31^16) with canonical M31 base embedding",
            "status": self.status,
            "proofSuiteId": self.proof_suite_id,
            "activationAllowed": self.activation_allowed,
            "publicBusOutput": None,
            "rawBusOracleMaterialized": False,
            "actualPcsAuthenticationAvailable": True,
            "pcsAuthority": (
                "native BindingRootV2 Circle-coefficient openings with verifier-derived "
                "AIR column ordinals, strict pre-z root inventory, and H4 source-mask PCS"
            ),
            "pythonReferenceMintsAcceptanceReceipt": False,
            "nativeGroups": list(NATIVE_GROUPS),
            "canonicalBusScalarLayout": list(CANONICAL_BUS_SCALAR_LAYOUT),
            "selectorMaps": list(SELECTOR_MAPS),
            "layout": self.layout.canonical(),
            "constraintFamilies": [value.canonical() for value in self.constraint_families],
            "equationCount": sum(value.scalar_equations for value in self.constraint_families),
            "bridgeBatchingSoundnessBits": BRIDGE_BATCHING_SOUNDNESS_BITS[
                self.layout.governed_profile_code
            ],
            "selectedCircleQueryTerm": {
                "thetaNumerator": SELECTED_CIRCLE_THETA_NUMERATOR,
                "thetaDenominator": SELECTED_CIRCLE_THETA_DENOMINATOR,
                "queryCount": SELECTED_CIRCLE_QUERY_COUNT,
                "soundnessBits": SELECTED_CIRCLE_QUERY_SOUNDNESS_BITS,
            },
            "quotientIdentities": [value.canonical() for value in self.quotient_identities],
            "parentKind901MessageBytes": PARENT_KIND901_MESSAGE_BYTES,
            "parentKind901MaximumBytes": PARENT_MAX_PROVER_MESSAGE_BYTES,
            "parentKind901HeadroomBytes": (
                PARENT_MAX_PROVER_MESSAGE_BYTES - PARENT_KIND901_MESSAGE_BYTES
            ),
            "bridgePublicAnswerCoefficientBytes": (
                BRIDGE_PUBLIC_ANSWER_COEFFICIENT_BYTES
            ),
            "bridgePublicAnswerLocation": (
                "root_bound_component_package_not_parent_kind901"
            ),
            "bridgeConstructionBaseLaneOrder": list(
                BRIDGE_CONSTRUCTION_BASE_LANE_ORDER
            ),
            "bridgeConstructionPadLaneOrder": list(
                BRIDGE_CONSTRUCTION_PAD_LANE_ORDER
            ),
            "bridgeConstructionAnswerLaneOrder": list(
                BRIDGE_CONSTRUCTION_ANSWER_LANE_ORDER
            ),
            "semanticMaskCoefficientCount": SEMANTIC_MASK_COEFFICIENT_COUNT,
            "semanticMaskPaddedCount": SEMANTIC_MASK_PADDED_COUNT,
            "semanticSelectedObservationRankM31PerGroup": (
                SEMANTIC_SELECTED_OBSERVATION_RANK_M31_PER_GROUP
            ),
            "semanticBridgeCarrierPolynomial": "C_g",
            "semanticBridgeCarrierField": "Fp16",
            "semanticBridgeCarrierCoefficientCount": (
                SEMANTIC_BRIDGE_CARRIER_COEFFICIENT_COUNT
            ),
            "semanticBridgeCarrierConstructionLanes": ["C_message", "C_digest"],
            "authenticatedExistingSemanticMaskedSOpeningAllowed": True,
            "rawOrUnmaskedSemanticSOpeningAllowed": False,
            "semanticAugmentedOpeningEquation": "S_aug_g=S_hat_g+Z_H_g*C_g",
            "h4BridgeMaskCoefficientCount": self.h4_bridge_mask_coefficient_count,
            "h4BridgeMaskDegreeBoundExclusive": self.h4_bridge_mask_coefficient_count,
            "h4BridgeMaskPaddedCount": H4_BRIDGE_MASK_PADDED_COUNT,
            "h4BridgeConstructionRootOwnership": H4_BRIDGE_CONSTRUCTION_ROOT_OWNERSHIP,
            "h4BridgeMaskPolynomial": (
                "ordered C_message,C_digest,N_message,N_digest base lanes"
            ),
            "h4BridgeIndependentResponsePad": "one independent R per base lane",
            "h4BridgeMaskedFunctional": "H_hat_g=H_g+Z_H_g*N_g",
            "h4BridgeMaskDomainMaps": list(H4_BRIDGE_MASK_DOMAIN_MAPS),
            "h4BridgeMaskDomainSeparatedEvaluations": H4_BRIDGE_MASK_DOMAIN_SEPARATED_EVALUATIONS,
            "h4BridgeMaskAuxiliarySpotcheckOpenings": H4_BRIDGE_MASK_AUXILIARY_SPOTCHECK_OPENINGS,
            "bridgeConstructionDirectBaseOpeningsPerLane": (
                H4_BRIDGE_MASK_AUXILIARY_SPOTCHECK_OPENINGS
            ),
            "h4BridgeMaskObservationRankPerGroup": (
                H4_BRIDGE_MASK_CONDITIONAL_OBSERVATION_RANK_PER_GROUP
            ),
            "h4BridgeMaskConditionalObservationRank": H4_BRIDGE_MASK_CONDITIONAL_OBSERVATION_RANK,
            "h4BridgeMaskConditionalResidualFreedomPerGroup": (
                H4_BRIDGE_MASK_CONDITIONAL_RESIDUAL_FREEDOM_PER_GROUP
            ),
            "h4BridgeMaskConditionalResidualFreedom": H4_BRIDGE_MASK_CONDITIONAL_RESIDUAL_FREEDOM,
            "h4BridgeMaskResidualBitsPerGroup": H4_BRIDGE_MASK_RESIDUAL_BITS_PER_GROUP,
            "h4BridgeMaskResidualBitsFloorPerGroup": (
                H4_BRIDGE_MASK_RESIDUAL_BITS_FLOOR_PER_GROUP
            ),
            "h4BridgeMaskPublicAnswerForm": H4_BRIDGE_MASK_PUBLIC_ANSWER_FORM,
            "bridgeMaskStandaloneZeroBaseAllowed": False,
            "h4BridgeMaskJointRankEquation": (
                "per_group_worst_case_M_sem_known:unknown(C,N,R_C,R_N)=4*4789;"
                "Q=4789;A_C,A_N=2*4789;direct=2*1218;"
                "C,N_z_conjugate_rank<=2;residual=2351_Fp16"
            ),
            "bridgeMaskRankAuthority": "H4_SERIALIZED_FIELD_INVENTORY",
            "bridgeMaskUnknownExtraFunctionalEffect": "FAIL_CLOSED_UNQUALIFIED",
            "bridgeMaskRankStatus": MASK_RANK_STATUS,
            "primitiveVectorContract": [value.canonical() for value in PRIMITIVE_VECTOR_CONTRACT],
            "prerequisites": [H4_INPUT_BOOLEANITY_PREREQUISITE],
            "transcriptOrder": list(TRANSCRIPT_ORDER),
            "semanticPublicCoinSplit": list(SEMANTIC_PUBLIC_COIN_SPLIT),
            "selectedWorkerObligations": list(SELECTED_WORKER_OBLIGATIONS),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.canonical_object(), sort_keys=True, separators=(",", ":")
        ).encode("ascii")

    @property
    def commitment_512(self) -> bytes:
        return sha3_512(PROGRAM_DOMAIN + self.canonical_bytes).digest()


def _selected_evaluation_log_size(trace_rows: int) -> int:
    masked_coefficients = _next_power_of_two(
        trace_rows + SEMANTIC_MASK_PADDED_COUNT
    )
    # One composition-mask slack bit and rate-1/2 selected FRI blowup.
    return masked_coefficients.bit_length() - 1 + 2


def build_semantic_bus_bridge_layout(
    profile: CalibrationProfile,
) -> SemanticBusBridgeLayout:
    if not isinstance(profile, CalibrationProfile):
        raise StructuralError("semantic_bus_bridge_profile_invalid")
    schedule = build_wave1a_global_sha3_capacity_schedule(profile)
    total_capacity_bytes = sum(run.capacity * run.count for run in schedule.runs)
    message_logical_rows = schedule.total_permutations * RATE_BYTES
    digest_logical_rows = schedule.total_calls * DIGEST_BYTES
    message_trace_rows = _next_power_of_two(message_logical_rows)
    digest_trace_rows = _next_power_of_two(digest_logical_rows)
    return SemanticBusBridgeLayout(
        profile_id=profile.profile_id,
        governed_profile_code=PROFILE_TAGS[profile.profile_id],
        call_count=schedule.total_calls,
        total_capacity_bytes=total_capacity_bytes,
        total_permutations=schedule.total_permutations,
        padded_permutations=schedule.padded_permutations,
        coprocessor_shards=schedule.coprocessor_shards,
        message_logical_rows=message_logical_rows,
        message_trace_rows=message_trace_rows,
        digest_logical_rows=digest_logical_rows,
        digest_trace_rows=digest_trace_rows,
        message_evaluation_log_size=_selected_evaluation_log_size(
            message_trace_rows
        ),
        digest_evaluation_log_size=_selected_evaluation_log_size(
            digest_trace_rows
        ),
        semantic_trace_padding_rows=message_trace_rows - message_logical_rows,
        digest_trace_padding_rows=digest_trace_rows - digest_logical_rows,
        h4_global_padding_permutations=(
            schedule.padded_permutations - schedule.total_permutations
        ),
        capacity_schedule_commitment_512=schedule.commitment_512,
        hash_bus_descriptor_commitment_512=schedule.descriptor_commitment_512,
    )


def build_semantic_bus_bridge_program(
    profile: CalibrationProfile,
) -> SemanticBusBridgeProgram:
    layout = build_semantic_bus_bridge_layout(profile)
    families = (
        BridgeConstraintFamily(
            "rate_absorb_byte",
            "message",
            3,
            layout.message_logical_rows,
            "one equation at each canonical call/block/rate-byte row",
        ),
        BridgeConstraintFamily(
            "inactive_input_zero_bit",
            "message",
            2,
            layout.total_permutations * STATE_BITS,
            "1600 bit equations batched at each canonical block-start row",
        ),
        BridgeConstraintFamily(
            "active_capacity_carry_bit",
            "message",
            2,
            layout.total_permutations * CAPACITY_BITS,
            "1024 capacity-bit equations batched at each canonical block-start row",
        ),
        BridgeConstraintFamily(
            "delimiter_cardinality",
            "message",
            2,
            layout.call_count,
            "one equation at each verifier-fixed call-start row",
        ),
        BridgeConstraintFamily(
            "actual_last_cardinality",
            "message",
            2,
            layout.call_count,
            "one equation at each verifier-fixed call-start row",
        ),
        BridgeConstraintFamily(
            "digest_last_output_byte",
            "digest",
            3,
            layout.digest_logical_rows,
            "one equation at each canonical call/digest-byte row",
        ),
    )
    quotients = (
        BridgeQuotientIdentity(
            "message",
            layout.message_trace_rows,
            layout.message_trace_rows.bit_length() - 1,
            H4_BRIDGE_MASK_COEFFICIENT_COUNT,
            H4_BRIDGE_MASK_PADDED_COUNT,
            QUOTIENT_COMPONENT_COUNT,
            QUOTIENT_COMPONENT_ORDER,
            QUOTIENT_ROOT_DOMAIN,
            "S_aug_message(z)-H_hat_message(z)=Z_H_message(z)*Q_message(z)",
        ),
        BridgeQuotientIdentity(
            "digest",
            layout.digest_trace_rows,
            layout.digest_trace_rows.bit_length() - 1,
            H4_BRIDGE_MASK_COEFFICIENT_COUNT,
            H4_BRIDGE_MASK_PADDED_COUNT,
            QUOTIENT_COMPONENT_COUNT,
            QUOTIENT_COMPONENT_ORDER,
            QUOTIENT_ROOT_DOMAIN,
            "S_aug_digest(z)-H_hat_digest(z)=Z_H_digest(z)*Q_digest(z)",
        ),
    )
    return SemanticBusBridgeProgram(layout, families, quotients)


@dataclass(frozen=True, slots=True)
class PaddedRowSelectors:
    block_active: tuple[int, ...]
    actual_last: tuple[int, ...]
    delimiter: tuple[int, ...]


def derive_padded_row_selectors(
    live: Sequence[int], capacity: int
) -> PaddedRowSelectors:
    materialized = tuple(live)
    if (
        type(capacity) is not int
        or capacity < 0
        or len(materialized) != (capacity // RATE_BYTES + 1) * RATE_BYTES
        or any(type(value) is not int or value not in {0, 1} for value in materialized)
    ):
        raise StructuralError("semantic_bus_bridge_selector_input_invalid")
    if any(left < right for left, right in zip(materialized, materialized[1:])):
        raise StructuralError("semantic_bus_bridge_live_prefix_invalid")
    block_count = len(materialized) // RATE_BYTES
    active = tuple(
        1 if block == 0 else materialized[block * RATE_BYTES - 1]
        for block in range(block_count)
    )
    actual_last = tuple(
        value * (1 - (active[block + 1] if block + 1 < block_count else 0))
        for block, value in enumerate(active)
    )
    delimiter = tuple(
        (1 - value) * (1 if position == 0 else materialized[position - 1])
        for position, value in enumerate(materialized)
    )
    if sum(actual_last) != 1 or sum(delimiter) != 1:
        raise StructuralError("semantic_bus_bridge_selector_cardinality_invalid")
    return PaddedRowSelectors(active, actual_last, delimiter)


@dataclass(frozen=True, slots=True)
class SemanticCallTrace:
    call_index: int
    capacity: int
    live: tuple[int, ...]
    value: tuple[int, ...]
    digest: bytes

    def __post_init__(self) -> None:
        rows = (
            (self.capacity // RATE_BYTES + 1) * RATE_BYTES
            if type(self.capacity) is int and self.capacity >= 0
            else -1
        )
        if (
            type(self.call_index) is not int
            or self.call_index < 0
            or rows <= 0
            or type(self.live) is not tuple
            or type(self.value) is not tuple
            or len(self.live) != rows
            or len(self.value) != rows
            or any(
                type(item) is not int or not 0 <= item < M31_MODULUS
                for item in self.live
            )
            or any(type(item) is not int or not 0 <= item <= 0xFF for item in self.value)
            or type(self.digest) is not bytes
            or len(self.digest) != DIGEST_BYTES
        ):
            raise StructuralError("semantic_bus_bridge_semantic_call_invalid")


@dataclass(frozen=True, slots=True)
class H4PermutationBoundary:
    call_index: int
    block_index: int
    input_state: bytes
    output_state: bytes

    def __post_init__(self) -> None:
        if (
            type(self.call_index) is not int
            or self.call_index < 0
            or type(self.block_index) is not int
            or self.block_index < 0
            or type(self.input_state) is not bytes
            or len(self.input_state) != STATE_BYTES
            or type(self.output_state) is not bytes
            or len(self.output_state) != STATE_BYTES
        ):
            raise StructuralError("semantic_bus_bridge_h4_boundary_invalid")


@dataclass(frozen=True, slots=True)
class H4CallTrace:
    call_index: int
    capacity: int
    boundaries: tuple[H4PermutationBoundary, ...]

    def __post_init__(self) -> None:
        if (
            type(self.call_index) is not int
            or self.call_index < 0
            or type(self.capacity) is not int
            or self.capacity < 0
            or type(self.boundaries) is not tuple
            or not self.boundaries
        ):
            raise StructuralError("semantic_bus_bridge_h4_call_invalid")


@dataclass(frozen=True, slots=True)
class SyntheticSemanticH4Bridge:
    profile_id: str
    semantic_calls: tuple[SemanticCallTrace, ...]
    h4_calls: tuple[H4CallTrace, ...]
    status: str = STATUS
    proof_suite_id: None = None
    activation_allowed: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.profile_id) is not str
            or not self.profile_id
            or type(self.semantic_calls) is not tuple
            or not self.semantic_calls
            or type(self.h4_calls) is not tuple
            or not self.h4_calls
            or self.status != STATUS
            or self.proof_suite_id is not None
            or self.activation_allowed
        ):
            raise StructuralError("semantic_bus_bridge_instance_invalid")


def canonical_sha3_512_padded_blocks(message: bytes) -> tuple[bytes, ...]:
    if type(message) is not bytes:
        raise StructuralError("semantic_bus_bridge_message_invalid")
    padded = bytearray(message)
    padded.append(0x06)
    padded.extend(b"\x00" * ((-len(padded)) % RATE_BYTES))
    padded[-1] ^= 0x80
    return tuple(
        bytes(padded[offset : offset + RATE_BYTES])
        for offset in range(0, len(padded), RATE_BYTES)
    )


def _keccak_f_bytes(state: bytes) -> bytes:
    if type(state) is not bytes or len(state) != STATE_BYTES:
        raise StructuralError("semantic_bus_bridge_keccak_state_invalid")
    current = tuple(state)
    for round_index in range(KECCAK_ROUNDS):
        current = _build_round(current, round_index).output_bytes
    return bytes(current)


@lru_cache(maxsize=1)
def _keccak_f_zero() -> bytes:
    return _keccak_f_bytes(bytes(STATE_BYTES))


def build_synthetic_semantic_h4_bridge(
    profile_id: str, calls: Sequence[Sha3Call]
) -> SyntheticSemanticH4Bridge:
    materialized = tuple(calls)
    if (
        type(profile_id) is not str
        or not profile_id
        or not materialized
        or any(not isinstance(call, Sha3Call) for call in materialized)
    ):
        raise StructuralError("semantic_bus_bridge_build_input_invalid")
    semantic_calls: list[SemanticCallTrace] = []
    h4_calls: list[H4CallTrace] = []
    for call_index, call in enumerate(materialized):
        row_count = (call.capacity // RATE_BYTES + 1) * RATE_BYTES
        live = tuple(int(index < len(call.message)) for index in range(row_count))
        value = tuple(
            call.message[index] if index < len(call.message) else 0
            for index in range(row_count)
        )
        digest = sha3_512(call.message).digest()
        semantic_calls.append(
            SemanticCallTrace(call_index, call.capacity, live, value, digest)
        )

        padded_blocks = canonical_sha3_512_padded_blocks(call.message)
        carried = bytes(STATE_BYTES)
        boundaries: list[H4PermutationBoundary] = []
        for block_index in range(call.capacity // RATE_BYTES + 1):
            if block_index < len(padded_blocks):
                absorbed = bytearray(carried)
                for index, byte in enumerate(padded_blocks[block_index]):
                    absorbed[index] ^= byte
                input_state = bytes(absorbed)
                output_state = _keccak_f_bytes(input_state)
                carried = output_state
            else:
                input_state = bytes(STATE_BYTES)
                output_state = _keccak_f_zero()
            boundaries.append(
                H4PermutationBoundary(
                    call_index, block_index, input_state, output_state
                )
            )
        if carried[:DIGEST_BYTES] != digest:
            raise AssertionError("semantic_bus_bridge_synthetic_digest_mismatch")
        h4_calls.append(
            H4CallTrace(call_index, call.capacity, tuple(boundaries))
        )
    return SyntheticSemanticH4Bridge(
        profile_id, tuple(semantic_calls), tuple(h4_calls)
    )


@dataclass(frozen=True, slots=True)
class BridgeResidual:
    group: str
    row: int
    family: str
    subindex: int
    degree: int
    value: int

    def __post_init__(self) -> None:
        if (
            self.group not in NATIVE_GROUPS
            or type(self.row) is not int
            or self.row < 0
            or type(self.family) is not str
            or not self.family
            or type(self.subindex) is not int
            or self.subindex < 0
            or type(self.degree) is not int
            or not 1 <= self.degree <= MAXIMUM_CONSTRAINT_DEGREE
            or type(self.value) is not int
            or not 0 <= self.value < M31_MODULUS
        ):
            raise StructuralError("semantic_bus_bridge_residual_invalid")


def _bit(value: int, index: int) -> int:
    return (value >> index) & 1


def _validate_semantic_assumptions(call: SemanticCallTrace) -> None:
    if any(value not in {0, 1} for value in call.live):
        raise StructuralError("semantic_bus_bridge_semantic_live_boolean")
    if any(left < right for left, right in zip(call.live, call.live[1:])):
        raise StructuralError("semantic_bus_bridge_semantic_live_prefix")
    if any((1 - live) * value for live, value in zip(call.live, call.value, strict=True)):
        raise StructuralError("semantic_bus_bridge_semantic_inactive_value")


def _validate_bridge_shape(
    instance: SyntheticSemanticH4Bridge,
    expected_profile_id: str,
    expected_capacities: Sequence[int],
) -> tuple[int, ...]:
    capacities = tuple(expected_capacities)
    if type(expected_profile_id) is not str or not expected_profile_id:
        raise StructuralError("semantic_bus_bridge_expected_profile_invalid")
    if instance.profile_id != expected_profile_id:
        raise StructuralError("semantic_bus_bridge_profile_mismatch")
    if (
        not capacities
        or any(type(value) is not int or value < 0 for value in capacities)
        or len(instance.semantic_calls) != len(capacities)
        or len(instance.h4_calls) != len(capacities)
    ):
        raise StructuralError("semantic_bus_bridge_call_count_mismatch")
    for call_index, (semantic, h4, capacity) in enumerate(
        zip(instance.semantic_calls, instance.h4_calls, capacities, strict=True)
    ):
        if semantic.call_index != call_index or h4.call_index != call_index:
            raise StructuralError("semantic_bus_bridge_call_order_mismatch")
        if semantic.capacity != capacity or h4.capacity != capacity:
            raise StructuralError("semantic_bus_bridge_capacity_mismatch")
        expected_blocks = capacity // RATE_BYTES + 1
        if len(h4.boundaries) != expected_blocks:
            raise StructuralError("semantic_bus_bridge_block_count_mismatch")
        for block_index, boundary in enumerate(h4.boundaries):
            if (
                boundary.call_index != call_index
                or boundary.block_index != block_index
            ):
                raise StructuralError("semantic_bus_bridge_block_order_mismatch")
        _validate_semantic_assumptions(semantic)
    return capacities


def evaluate_bridge_residuals(
    instance: SyntheticSemanticH4Bridge,
    *,
    expected_profile_id: str,
    expected_capacities: Sequence[int],
) -> tuple[BridgeResidual, ...]:
    """Evaluate the exact virtual message/digest relations without a copy table."""

    _validate_bridge_shape(instance, expected_profile_id, expected_capacities)
    residuals: list[BridgeResidual] = []
    message_offset = 0
    digest_offset = 0
    for semantic, h4 in zip(instance.semantic_calls, instance.h4_calls, strict=True):
        selectors = derive_padded_row_selectors(semantic.live, semantic.capacity)
        residuals.append(
            BridgeResidual(
                "message",
                message_offset,
                "delimiter_cardinality",
                0,
                2,
                _field(sum(selectors.delimiter) - 1),
            )
        )
        residuals.append(
            BridgeResidual(
                "message",
                message_offset,
                "actual_last_cardinality",
                0,
                2,
                _field(sum(selectors.actual_last) - 1),
            )
        )
        for block_index, boundary in enumerate(h4.boundaries):
            active = selectors.block_active[block_index]
            actual_last = selectors.actual_last[block_index]
            prior = (
                bytes(STATE_BYTES)
                if block_index == 0
                else h4.boundaries[block_index - 1].output_state
            )
            block_row = message_offset + block_index * RATE_BYTES
            for byte_index in range(RATE_BYTES):
                global_position = block_index * RATE_BYTES + byte_index
                absorbed_byte = sum(
                    (1 << bit_index)
                    * (
                        _bit(boundary.input_state[byte_index], bit_index)
                        + _bit(prior[byte_index], bit_index)
                        - 2
                        * _bit(boundary.input_state[byte_index], bit_index)
                        * _bit(prior[byte_index], bit_index)
                    )
                    for bit_index in range(8)
                )
                expected_byte = (
                    semantic.value[global_position]
                    + 6 * selectors.delimiter[global_position]
                    + 128 * actual_last * int(byte_index == RATE_BYTES - 1)
                )
                residuals.append(
                    BridgeResidual(
                        "message",
                        block_row + byte_index,
                        "rate_absorb_byte",
                        0,
                        3,
                        _field(active * (absorbed_byte - expected_byte)),
                    )
                )
            for state_bit in range(STATE_BITS):
                byte_index, bit_index = divmod(state_bit, 8)
                input_bit = _bit(boundary.input_state[byte_index], bit_index)
                residuals.append(
                    BridgeResidual(
                        "message",
                        block_row,
                        "inactive_input_zero_bit",
                        state_bit,
                        2,
                        _field((1 - active) * input_bit),
                    )
                )
            for capacity_bit in range(CAPACITY_BITS):
                state_bit = RATE_BITS + capacity_bit
                byte_index, bit_index = divmod(state_bit, 8)
                input_bit = _bit(boundary.input_state[byte_index], bit_index)
                prior_bit = _bit(prior[byte_index], bit_index)
                residuals.append(
                    BridgeResidual(
                        "message",
                        block_row,
                        "active_capacity_carry_bit",
                        capacity_bit,
                        2,
                        _field(active * (input_bit - prior_bit)),
                    )
                )
        for digest_index, digest_byte in enumerate(semantic.digest):
            selected = sum(
                selectors.actual_last[block_index]
                * boundary.output_state[digest_index]
                for block_index, boundary in enumerate(h4.boundaries)
            )
            residuals.append(
                BridgeResidual(
                    "digest",
                    digest_offset + digest_index,
                    "digest_last_output_byte",
                    0,
                    3,
                    _field(digest_byte - selected),
                )
            )
        message_offset += len(semantic.live)
        digest_offset += DIGEST_BYTES
    return tuple(residuals)


@dataclass(frozen=True, slots=True)
class BridgeEvaluationReport:
    call_count: int
    permutation_count: int
    message_rows: int
    digest_rows: int
    message_scalar_equations: int
    digest_scalar_equations: int
    maximum_degree: int
    h4_keccak_boundaries_verified: int
    direct_h4_byte_states_checked: bool
    primitive_vector_pcs_authenticated: bool = False
    status: str = STATUS
    proof_suite_id: None = None
    activation_allowed: bool = False


def evaluate_synthetic_semantic_h4_bridge(
    instance: SyntheticSemanticH4Bridge,
    *,
    expected_profile_id: str,
    expected_capacities: Sequence[int],
) -> BridgeEvaluationReport:
    """Evaluate in-memory KAT bytes; this never returns a proof receipt."""

    residuals = evaluate_bridge_residuals(
        instance,
        expected_profile_id=expected_profile_id,
        expected_capacities=expected_capacities,
    )
    for residual in residuals:
        if residual.value:
            raise StructuralError(
                f"semantic_bus_bridge_identity_failed:{residual.family}:"
                f"{residual.row}:{residual.subindex}"
            )
    verified = 0
    for call in instance.h4_calls:
        for boundary in call.boundaries:
            if _keccak_f_bytes(boundary.input_state) != boundary.output_state:
                raise StructuralError("semantic_bus_bridge_h4_gkr_relation_failed")
            verified += 1
    message = tuple(value for value in residuals if value.group == "message")
    digest = tuple(value for value in residuals if value.group == "digest")
    return BridgeEvaluationReport(
        call_count=len(instance.semantic_calls),
        permutation_count=sum(len(call.boundaries) for call in instance.h4_calls),
        message_rows=sum(len(call.live) for call in instance.semantic_calls),
        digest_rows=len(instance.semantic_calls) * DIGEST_BYTES,
        message_scalar_equations=len(message),
        digest_scalar_equations=len(digest),
        maximum_degree=max(value.degree for value in residuals),
        h4_keccak_boundaries_verified=verified,
        direct_h4_byte_states_checked=True,
        primitive_vector_pcs_authenticated=False,
    )


_FAMILY_ORDER: Final[dict[str, int]] = {
    "rate_absorb_byte": 0,
    "inactive_input_zero_bit": 1,
    "active_capacity_carry_bit": 2,
    "delimiter_cardinality": 3,
    "actual_last_cardinality": 4,
    "digest_last_output_byte": 5,
}


def batch_synthetic_bridge_residuals(
    residuals: Iterable[BridgeResidual], family_challenge: int
) -> dict[str, tuple[int, ...]]:
    """Batch a small KAT inventory; production layouts are intentionally refused."""

    rho = _field(family_challenge)
    if rho == 0:
        raise StructuralError("semantic_bus_bridge_batch_challenge_zero")
    materialized = tuple(residuals)
    maximum_rows = {
        group: max(
            (value.row + 1 for value in materialized if value.group == group),
            default=0,
        )
        for group in NATIVE_GROUPS
    }
    if any(
        rows <= 0 or rows > SYNTHETIC_MAXIMUM_GROUP_ROWS
        for rows in maximum_rows.values()
    ):
        raise StructuralError("semantic_bus_bridge_synthetic_row_bound")
    result = {
        group: [0] * maximum_rows[group]
        for group in NATIVE_GROUPS
    }
    ordered = sorted(
        materialized,
        key=lambda value: (
            NATIVE_GROUPS.index(value.group),
            value.row,
            _FAMILY_ORDER[value.family],
            value.subindex,
        ),
    )
    power = 1
    for residual in ordered:
        result[residual.group][residual.row] = _field(
            result[residual.group][residual.row] + power * residual.value
        )
        power = _field(power * rho)
    return {group: tuple(values) for group, values in result.items()}


def _polynomial_evaluate(coefficients: Sequence[int], point: int) -> int:
    result = 0
    for coefficient in reversed(tuple(coefficients)):
        result = _field(result * point + coefficient)
    return result


def _lagrange_and_zeroifier(values: Sequence[int], point: int) -> tuple[int, int]:
    """Evaluate over H={0,...,n-1}; synthetic M31 KAT only."""

    materialized = tuple(_field(value) for value in values)
    if not materialized or len(materialized) >= M31_MODULUS:
        raise StructuralError("semantic_bus_bridge_synthetic_domain_invalid")
    z = _field(point)
    if z < len(materialized):
        raise StructuralError("semantic_bus_bridge_synthetic_point_in_domain")
    zeroifier = 1
    for domain_value in range(len(materialized)):
        zeroifier = _field(zeroifier * (z - domain_value))
    factorial = [1]
    for value in range(1, len(materialized) + 1):
        factorial.append(_field(factorial[-1] * value))
    evaluation = 0
    last = len(materialized) - 1
    for index, value in enumerate(materialized):
        if value == 0:
            continue
        denominator = _field(
            factorial[index]
            * factorial[last - index]
            * (-1 if (last - index) & 1 else 1)
        )
        weight = _field(
            zeroifier
            * pow(_field(z - index), M31_MODULUS - 2, M31_MODULUS)
            * pow(denominator, M31_MODULUS - 2, M31_MODULUS)
        )
        evaluation = _field(evaluation + value * weight)
    return evaluation, zeroifier


@dataclass(frozen=True, slots=True)
class SyntheticQuotientChallenges:
    family_challenge: int
    message_point: int
    digest_point: int


@dataclass(frozen=True, slots=True)
class SyntheticQuotientMasks:
    message_coefficients: tuple[int, ...]
    digest_coefficients: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class SyntheticQuotientClaims:
    message_quotient_evaluation: int
    digest_quotient_evaluation: int


def honest_synthetic_quotient_claims(
    masks: SyntheticQuotientMasks,
    challenges: SyntheticQuotientChallenges,
) -> SyntheticQuotientClaims:
    if (
        not masks.message_coefficients
        or not masks.digest_coefficients
        or any(
            type(value) is not int or not 0 <= value < M31_MODULUS
            for value in (*masks.message_coefficients, *masks.digest_coefficients)
        )
    ):
        raise StructuralError("semantic_bus_bridge_synthetic_mask_invalid")
    return SyntheticQuotientClaims(
        _polynomial_evaluate(masks.message_coefficients, challenges.message_point),
        _polynomial_evaluate(masks.digest_coefficients, challenges.digest_point),
    )


def verify_synthetic_quotient_identities(
    instance: SyntheticSemanticH4Bridge,
    *,
    expected_profile_id: str,
    expected_capacities: Sequence[int],
    challenges: SyntheticQuotientChallenges,
    masks: SyntheticQuotientMasks,
    claims: SyntheticQuotientClaims,
) -> None:
    """Check both masked divisibility equations in the small M31 KAT domain."""

    residuals = evaluate_bridge_residuals(
        instance,
        expected_profile_id=expected_profile_id,
        expected_capacities=expected_capacities,
    )
    rows = batch_synthetic_bridge_residuals(
        residuals, challenges.family_challenge
    )
    for group, point, coefficients, quotient in (
        (
            "message",
            challenges.message_point,
            masks.message_coefficients,
            claims.message_quotient_evaluation,
        ),
        (
            "digest",
            challenges.digest_point,
            masks.digest_coefficients,
            claims.digest_quotient_evaluation,
        ),
    ):
        padded = (*rows[group],) + (0,) * (
            _next_power_of_two(len(rows[group])) - len(rows[group])
        )
        constraint_evaluation, zeroifier = _lagrange_and_zeroifier(padded, point)
        mask_evaluation = _polynomial_evaluate(coefficients, point)
        masked_numerator = _field(
            constraint_evaluation + zeroifier * mask_evaluation
        )
        if masked_numerator != _field(zeroifier * quotient):
            raise StructuralError(
                f"semantic_bus_bridge_quotient_identity_failed:{group}"
            )


__all__ = [
    "BASE_PROGRAM_ID",
    "BRIDGE_CONSTRUCTION_ANSWER_LANE_ORDER",
    "BRIDGE_CONSTRUCTION_BASE_LANE_ORDER",
    "BRIDGE_CONSTRUCTION_PAD_LANE_ORDER",
    "BRIDGE_PUBLIC_ANSWER_COEFFICIENT_BYTES",
    "CANONICAL_BUS_SCALAR_LAYOUT",
    "H4_BRIDGE_MASK_AUXILIARY_SPOTCHECK_OPENINGS",
    "H4_BRIDGE_MASK_COEFFICIENT_COUNT",
    "H4_BRIDGE_MASK_CONDITIONAL_OBSERVATION_RANK",
    "H4_BRIDGE_MASK_CONDITIONAL_OBSERVATION_RANK_PER_GROUP",
    "H4_BRIDGE_MASK_CONDITIONAL_RESIDUAL_FREEDOM",
    "H4_BRIDGE_MASK_CONDITIONAL_RESIDUAL_FREEDOM_PER_GROUP",
    "H4_BRIDGE_MASK_DOMAIN_SEPARATED_EVALUATIONS",
    "H4_BRIDGE_MASK_PADDED_COUNT",
    "H4_BRIDGE_MASK_PUBLIC_ANSWER_FORM",
    "H4_BRIDGE_MASK_RESIDUAL_BITS_FLOOR_PER_GROUP",
    "H4_BRIDGE_MASK_RESIDUAL_BITS_PER_GROUP",
    "H4_BRIDGE_SERIALIZED_FUNCTIONAL_INVENTORY",
    "BridgeMaskRankQualification",
    "BridgeConstraintFamily",
    "BridgeEvaluationReport",
    "BridgePrimitiveVector",
    "BridgeQuotientIdentity",
    "BridgeResidual",
    "CAPACITY_BITS",
    "DIGEST_BYTES",
    "H4CallTrace",
    "H4_INPUT_BOOLEANITY_PREREQUISITE",
    "H4PermutationBoundary",
    "MASK_RANK_STATUS",
    "MAXIMUM_CONSTRAINT_DEGREE",
    "NATIVE_GROUPS",
    "PROGRAM_ID",
    "PaddedRowSelectors",
    "PRIMITIVE_VECTOR_CONTRACT",
    "PARENT_KIND901_MESSAGE_BYTES",
    "PARENT_MAX_PROVER_MESSAGE_BYTES",
    "QUOTIENT_COMPONENT_COUNT",
    "QUOTIENT_COMPONENT_ORDER",
    "QUOTIENT_ROOT_DOMAIN",
    "SELECTED_WORKER_OBLIGATIONS",
    "SEMANTIC_PUBLIC_COIN_SPLIT",
    "SEMANTIC_BRIDGE_CARRIER_COEFFICIENT_COUNT",
    "SEMANTIC_SELECTED_OBSERVATION_RANK_M31_PER_GROUP",
    "STATUS",
    "SemanticBusBridgeLayout",
    "SemanticBusBridgeProgram",
    "SemanticCallTrace",
    "SyntheticQuotientChallenges",
    "SyntheticQuotientClaims",
    "SyntheticQuotientMasks",
    "SyntheticSemanticH4Bridge",
    "batch_synthetic_bridge_residuals",
    "build_semantic_bus_bridge_layout",
    "build_semantic_bus_bridge_program",
    "build_synthetic_semantic_h4_bridge",
    "canonical_sha3_512_padded_blocks",
    "derive_padded_row_selectors",
    "evaluate_synthetic_semantic_h4_bridge",
    "evaluate_bridge_residuals",
    "honest_synthetic_quotient_claims",
    "qualify_bridge_mask_rank",
    "verify_synthetic_quotient_identities",
]
