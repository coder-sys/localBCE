//! Frozen schedule and zero-knowledge mask layout for the selected
//! seven-layer, B=16 relay-free Keccak GKR.
//!
//! This module contains dimensions only. It does not generate challenges and
//! deliberately contains no Fiat--Shamir transform.

use alloc::{vec, vec::Vec};

use crate::{
    chained_public_coin::{
        ChainedChallenge, ChainedPublicCoinBundle, ChainedPublicCoinError, ChainedRoundDescriptor,
        verify_chained_public_coin_bundle,
    },
    gkr_packed_binary_bridge_fp16::PACKED_BINARY_MESSAGE_COEFFICIENTS,
    gkr_zk_mask::{CompleteGkrZkMaskCommitmentLayout, GkrZkMaskError},
};

pub const KECCAK_ROUNDS: u32 = 24;
pub const GKR_LAYERS_PER_KECCAK_ROUND: u32 = 7;
pub const GKR_LAYERS: u32 = KECCAK_ROUNDS * GKR_LAYERS_PER_KECCAK_ROUND;
pub const GKR_BRIDGE_ROUNDS_PER_LAYER: u32 = 1;
pub const GKR_GROUP_ROUNDS_PER_LAYER: u32 = 13;
pub const GKR_TERMINAL_ROUNDS_PER_LAYER: u32 = 1;
pub const GKR_OUTPUT_QUERY_ROUNDS: u32 = 1;
pub const WIRE_ROUNDS_BY_LAYER: [u32; 7] = [22, 20, 20, 18, 20, 22, 22];
pub const LEFT_WIRE_ROUNDS_BY_LAYER: [u32; 7] = [11, 10, 9, 9, 11, 11, 11];
pub const RIGHT_WIRE_ROUNDS_BY_LAYER: [u32; 7] = [11, 10, 11, 9, 9, 11, 11];
pub const GKR_WIRE_ROUNDS_PER_KECCAK_ROUND: u32 = 144;
pub const GKR_CLAIM_MIX_ROUNDS: u32 = 95;
pub const GKR_TRANSCRIPT_ROUNDS: u32 = GKR_OUTPUT_QUERY_ROUNDS
    + GKR_LAYERS
        * (GKR_BRIDGE_ROUNDS_PER_LAYER
            + GKR_GROUP_ROUNDS_PER_LAYER
            + GKR_TERMINAL_ROUNDS_PER_LAYER)
    + KECCAK_ROUNDS * GKR_WIRE_ROUNDS_PER_KECCAK_ROUND
    + GKR_CLAIM_MIX_ROUNDS;
pub const GKR_MASK_BATCH_ROUNDS: u32 = 1;
pub const GKR_ROUNDS: u32 = GKR_TRANSCRIPT_ROUNDS + GKR_MASK_BATCH_ROUNDS;

/// The state-relation bridge consumes one output-query response and
/// twenty-four authenticated public-coin sumcheck responses. The production
/// state-composed schedule then proves square-freeness of both fixed-capacity
/// snapshots before the downstream PCS coordinate/source/mask, row, base, and
/// query rounds.
pub const STATE_RELATION_ROUNDS: u32 = 26;
pub const STATE_SQUAREFREE_K128_ROUNDS: u32 = 614;
pub const STATE_SQUAREFREE_K512_ROUNDS: u32 = 882;
pub const H4_BOOLEANITY_VARIABLES: u32 = 29;
pub const H4_BOOLEANITY_PRELUDE_ROUNDS: u32 = 1;
pub const H4_BOOLEANITY_GROUP_ROUNDS: u32 = H4_BOOLEANITY_VARIABLES;
pub const H4_BOOLEANITY_LEFT_ROUNDS: u32 = 1;
pub const H4_BOOLEANITY_RIGHT_ROUNDS: u32 = 1;
pub const H4_BOOLEANITY_TERMINAL_ROUNDS: u32 = 1;
pub const H4_BOOLEANITY_SUMCHECK_ROUNDS: u32 = H4_BOOLEANITY_GROUP_ROUNDS
    + H4_BOOLEANITY_LEFT_ROUNDS
    + H4_BOOLEANITY_RIGHT_ROUNDS
    + H4_BOOLEANITY_TERMINAL_ROUNDS;
pub const H4_BOOLEANITY_ROUNDS: u32 = H4_BOOLEANITY_PRELUDE_ROUNDS + H4_BOOLEANITY_SUMCHECK_ROUNDS;
pub const H4_PADDING_VARIABLES: u32 = 29;
pub const H4_PADDING_PRELUDE_ROUNDS: u32 = 1;
pub const H4_PADDING_SUMCHECK_ROUNDS: u32 = H4_PADDING_VARIABLES;
pub const H4_PADDING_TERMINAL_ROUNDS: u32 = 1;
pub const H4_PADDING_ROUNDS: u32 =
    H4_PADDING_PRELUDE_ROUNDS + H4_PADDING_SUMCHECK_ROUNDS + H4_PADDING_TERMINAL_ROUNDS;
pub const PCS_DOWNSTREAM_ROUNDS: u32 = 13;
pub const STATE_MASK_BATCH_ROUNDS: u32 = 1;
/// Historical partial state-relation bridge. This is not the complete
/// state-composed production schedule.
pub const STATE_RELATION_COMBINED_ROUNDS: u32 = GKR_ROUNDS
    + STATE_RELATION_ROUNDS
    + H4_BOOLEANITY_ROUNDS
    + H4_PADDING_ROUNDS
    + STATE_MASK_BATCH_ROUNDS
    + PCS_DOWNSTREAM_ROUNDS;
pub const STATE_COMPOSED_K128_ROUNDS: u32 =
    STATE_RELATION_COMBINED_ROUNDS + STATE_SQUAREFREE_K128_ROUNDS;
pub const STATE_COMPOSED_K512_ROUNDS: u32 =
    STATE_RELATION_COMBINED_ROUNDS + STATE_SQUAREFREE_K512_ROUNDS;
/// Kept as the partial bridge identity for the standalone schedule-control
/// binary. New production callers must use the profile-specific constants.
pub const COMBINED_ROUNDS: u32 = STATE_RELATION_COMBINED_ROUNDS;

pub const GKR_MASK_USED_COEFFICIENTS: usize = 23_544;
pub const GKR_MASK_PADDED_COEFFICIENTS: usize = 32_768;
pub const STATE_COMPOSED_K128_MASK_USED_COEFFICIENTS: usize = 28_013;
pub const STATE_COMPOSED_K512_MASK_USED_COEFFICIENTS: usize = 29_201;
pub const GKR_MASK_TENSOR_INNER_MESSAGE_VALUES: usize = 512;
pub const GKR_MASK_TENSOR_INNER_CODE_VALUES: usize = 8_192;
pub const GKR_MASK_TENSOR_OUTER_MESSAGE_VALUES: usize = 64;
pub const GKR_MASK_TENSOR_OUTER_CODE_VALUES: usize = 128;
pub const GKR_MASK_TENSOR_LEAVES: usize =
    GKR_MASK_TENSOR_INNER_CODE_VALUES * GKR_MASK_TENSOR_OUTER_CODE_VALUES;
pub const GKR_MASK_TENSOR_LEAF_BYTES: usize = 64;
pub const GKR_MASK_TENSOR_PCS_OPENINGS: usize = 1_218;
pub const GKR_MASK_HIDDEN_TENSOR_COUNT: usize = 2;
pub const GKR_MASK_JOINT_COEFFICIENT_DIMENSION: usize =
    GKR_MASK_HIDDEN_TENSOR_COUNT * GKR_MASK_PADDED_COEFFICIENTS;
pub const GKR_MASK_PUBLIC_ANSWER_EQUATION_RANK: usize = GKR_MASK_PADDED_COEFFICIENTS;
pub const GKR_MASK_BASE_TARGET_RANK: usize = 1;
/// `M31 > 2^30`, so one unconstrained Fp16 dimension carries more than 480
/// bits.  The ledger uses the strict integer lower bound rather than a rounded
/// decimal logarithm.
pub const GKR_MASK_FP16_ENTROPY_BITS_LOWER_BOUND: usize = 16 * 30;
pub const H4_MASK_RESIDUAL_SECURITY_BITS: usize = 256;

pub const H4_STATE_RELATION_OUTPUT_KIND: u16 = 120;
pub const H4_STATE_RELATION_GROUP_KIND: u16 = 121;
pub const H4_STATE_RELATION_WIRE_KIND: u16 = 122;
pub const H4_STATE_RELATION_TERMINAL_KIND: u16 = 123;
pub const H4_STATE_SQUAREFREE_BETA_KIND: u16 = 130;
pub const H4_STATE_SQUAREFREE_POINT_KIND: u16 = 131;
pub const H4_STATE_SQUAREFREE_GROUP_KIND: u16 = 138;
pub const H4_STATE_SQUAREFREE_LEFT_KIND: u16 = 139;
pub const H4_STATE_SQUAREFREE_RIGHT_KIND: u16 = 140;
pub const H4_STATE_SQUAREFREE_TERMINAL_KIND: u16 = 141;
pub const H4_STATE_SQUAREFREE_MIX_KIND: u16 = 142;
pub const H4_STATE_COMPOSED_MASK_BATCH_KIND: u16 = 143;
pub const H4_BOOLEANITY_PRELUDE_KIND: u16 = 144;
pub const H4_BOOLEANITY_SUMCHECK_KIND: u16 = 145;
pub const H4_BOOLEANITY_TERMINAL_KIND: u16 = 146;
pub const H4_PADDING_PRELUDE_KIND: u16 = 147;
pub const H4_PADDING_SUMCHECK_KIND: u16 = 148;
pub const H4_PADDING_TERMINAL_KIND: u16 = 149;
pub const H4_PCS_CLAIM_BATCH_KIND: u16 = 799;
pub const H4_PCS_INITIAL_KIND: u16 = 800;
pub const H4_PCS_ROW_KIND: u16 = 801;
pub const H4_PCS_BASE_KIND: u16 = 802;
pub const H4_PCS_ANSWER_KIND: u16 = 803;

/// Closed observation-rank inventory for the corrected kind-67 GKR mask.
///
/// `state_composed_*_rank` counts every already-serialized GKR, state, and
/// square-free mask view from [`CompleteGkrZkMaskCommitmentLayout`].  Kind 67
/// itself and the independent hidden Construction-8.2 base tensor each add
/// one scalar evaluation at every authenticated auxiliary query.  The public
/// answer tensor contributes 32,768 coefficient equations linking the two
/// hidden tensors, but no 64-state opening vector crosses the proof boundary.
/// The rank below is deliberately joint over both hidden tensors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GkrMaskTensorObservationRankCertificate {
    pub coefficient_dimension: usize,
    pub joint_coefficient_dimension: usize,
    pub used_coefficients: usize,
    pub bridge_view_rank: usize,
    pub sumcheck_view_rank: usize,
    pub layer_view_rank: usize,
    pub aggregate_opening_rank: usize,
    pub state_composed_transcript_rank: usize,
    pub tensor_pcs_opening_scalars: usize,
    pub base_tensor_pcs_opening_scalars: usize,
    pub public_answer_equation_rank: usize,
    pub base_target_rank: usize,
    pub complete_observation_rank: usize,
    pub residual_dimension: usize,
    pub residual_entropy_bits_lower_bound: usize,
    pub tensor_leaves: usize,
    pub tensor_leaf_bytes: usize,
    pub conservative_relative_distance_numerator: usize,
    pub conservative_relative_distance_denominator: usize,
}

/// Failure while replaying the one authenticated, profile-specific H4 chain.
///
/// This error is deliberately owned by the library rather than the process
/// adapter.  A caller cannot replace exact descriptor matching with a host
/// assertion after the public-coin signatures have verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum H4AuthenticatedScheduleError {
    Geometry,
    Descriptor { ordinal: usize },
    PublicCoin(ChainedPublicCoinError),
}

impl From<ChainedPublicCoinError> for H4AuthenticatedScheduleError {
    fn from(value: ChainedPublicCoinError) -> Self {
        Self::PublicCoin(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectedGkrRoundKind {
    OutputQuery,
    ClaimMix,
    PackedBridge,
    SharedGroup,
    Wire,
    Terminal,
    MaskBatch,
}

fn layer_requires_claim_mix(proof_round: usize, layer: usize) -> bool {
    matches!(layer, 0 | 2 | 4) || (layer == 6 && proof_round != 0)
}

/// Number of authenticated field elements released by one selected GKR
/// transcript round.
///
/// The output-query response supplies one packed-shard query, twenty-four
/// output-point coordinates, and the bridge/sumcheck mask scalars for the
/// first layer. A claim-mix response supplies its batching scalar plus the two
/// mask scalars for the layer it immediately precedes. When the next layer has
/// no claim-mix round, the preceding terminal response carries its terminal
/// challenge plus those two next-layer mask scalars. No extra transcript round
/// is introduced for masking.
pub fn selected_gkr_round_output_count(round: u32) -> Option<u16> {
    let kind = selected_gkr_round_kind(round)?;
    if kind == SelectedGkrRoundKind::OutputQuery {
        return Some(27);
    }
    if kind == SelectedGkrRoundKind::ClaimMix {
        return Some(3);
    }
    if kind != SelectedGkrRoundKind::Terminal {
        return Some(1);
    }

    let next = round.checked_add(1)?;
    match selected_gkr_round_kind(next) {
        Some(SelectedGkrRoundKind::PackedBridge) => Some(3),
        _ => Some(1),
    }
}

/// Return the exact round kind in backward proof order.
pub fn selected_gkr_round_kind(round: u32) -> Option<SelectedGkrRoundKind> {
    if round >= GKR_ROUNDS {
        return None;
    }
    if round == GKR_TRANSCRIPT_ROUNDS {
        return Some(SelectedGkrRoundKind::MaskBatch);
    }
    if round == 0 {
        return Some(SelectedGkrRoundKind::OutputQuery);
    }
    let mut remaining = round - 1;
    for proof_round in 0..KECCAK_ROUNDS as usize {
        for proof_layer in 0..GKR_LAYERS_PER_KECCAK_ROUND as usize {
            let layer = GKR_LAYERS_PER_KECCAK_ROUND as usize - 1 - proof_layer;
            if layer_requires_claim_mix(proof_round, layer) {
                if remaining == 0 {
                    return Some(SelectedGkrRoundKind::ClaimMix);
                }
                remaining -= 1;
            }
            if remaining == 0 {
                return Some(SelectedGkrRoundKind::PackedBridge);
            }
            remaining -= 1;
            if remaining < GKR_GROUP_ROUNDS_PER_LAYER {
                return Some(SelectedGkrRoundKind::SharedGroup);
            }
            remaining -= GKR_GROUP_ROUNDS_PER_LAYER;
            let wire_rounds = WIRE_ROUNDS_BY_LAYER[layer];
            if remaining < wire_rounds {
                return Some(SelectedGkrRoundKind::Wire);
            }
            remaining -= wire_rounds;
            if remaining == 0 {
                return Some(SelectedGkrRoundKind::Terminal);
            }
            remaining -= 1;
        }
    }
    None
}

pub(crate) fn h4_gkr_descriptor_kind(kind: SelectedGkrRoundKind) -> u16 {
    match kind {
        SelectedGkrRoundKind::OutputQuery => 100,
        SelectedGkrRoundKind::PackedBridge => 110,
        SelectedGkrRoundKind::SharedGroup => 111,
        SelectedGkrRoundKind::Wire => 112,
        SelectedGkrRoundKind::Terminal => 113,
        SelectedGkrRoundKind::ClaimMix => 114,
        SelectedGkrRoundKind::MaskBatch => 115,
    }
}

fn push_h4_descriptor(
    descriptors: &mut Vec<ChainedRoundDescriptor>,
    kind: u16,
    output_count: u16,
) -> Result<(), GkrZkMaskError> {
    let ordinal = u32::try_from(descriptors.len()).map_err(|_| GkrZkMaskError::Overflow)?;
    descriptors.push(ChainedRoundDescriptor {
        kind,
        ordinal,
        output_count,
    });
    Ok(())
}

fn push_h4_squarefree_layer_descriptors(
    descriptors: &mut Vec<ChainedRoundDescriptor>,
    group_variables: usize,
    left_variables: usize,
    right_variables: usize,
) -> Result<(), GkrZkMaskError> {
    for _ in 0..group_variables {
        push_h4_descriptor(descriptors, H4_STATE_SQUAREFREE_GROUP_KIND, 1)?;
    }
    for _ in 0..left_variables {
        push_h4_descriptor(descriptors, H4_STATE_SQUAREFREE_LEFT_KIND, 1)?;
    }
    for _ in 0..right_variables {
        push_h4_descriptor(descriptors, H4_STATE_SQUAREFREE_RIGHT_KIND, 1)?;
    }
    push_h4_descriptor(descriptors, H4_STATE_SQUAREFREE_TERMINAL_KIND, 1)?;
    // The proof API requests two nonzero claim-mixing coefficients together.
    // The authenticated chain deliberately publishes the same terminal pair
    // in two ordered message-first rounds so neither coefficient is released
    // before its own signed round evidence.
    push_h4_descriptor(descriptors, H4_STATE_SQUAREFREE_MIX_KIND, 1)?;
    push_h4_descriptor(descriptors, H4_STATE_SQUAREFREE_MIX_KIND, 1)?;
    Ok(())
}

/// Exact library-owned descriptor schedule for one synchronized H4 aggregate.
///
/// This is the authoritative descriptor replay consumed by both the portable
/// package verifier and the process adapter. It contains one logical chain for
/// all shards; K512 does not multiply the number of rounds or challenges.
pub fn selected_state_composed_round_descriptors(
    capacity: usize,
) -> Result<Vec<ChainedRoundDescriptor>, GkrZkMaskError> {
    let (state_variables, squarefree_rounds, total_rounds) = match capacity {
        128 => (
            7_usize,
            STATE_SQUAREFREE_K128_ROUNDS,
            STATE_COMPOSED_K128_ROUNDS,
        ),
        512 => (
            9_usize,
            STATE_SQUAREFREE_K512_ROUNDS,
            STATE_COMPOSED_K512_ROUNDS,
        ),
        _ => return Err(GkrZkMaskError::Shape),
    };
    let mut descriptors = Vec::with_capacity(total_rounds as usize);

    for ordinal in 0..GKR_ROUNDS {
        let kind = selected_gkr_round_kind(ordinal).ok_or(GkrZkMaskError::Shape)?;
        let output_count = selected_gkr_round_output_count(ordinal).ok_or(GkrZkMaskError::Shape)?;
        push_h4_descriptor(&mut descriptors, h4_gkr_descriptor_kind(kind), output_count)?;
    }

    push_h4_descriptor(&mut descriptors, H4_STATE_RELATION_OUTPUT_KIND, 19)?;
    for _ in 0..12 {
        push_h4_descriptor(&mut descriptors, H4_STATE_RELATION_GROUP_KIND, 1)?;
    }
    for _ in 0..12 {
        push_h4_descriptor(&mut descriptors, H4_STATE_RELATION_WIRE_KIND, 1)?;
    }
    push_h4_descriptor(&mut descriptors, H4_STATE_RELATION_TERMINAL_KIND, 1)?;

    let layers_per_phase = 3 + 2 * state_variables + 1 + state_variables + 1;
    let squarefree_layer_count = 2 * layers_per_phase;
    push_h4_descriptor(&mut descriptors, H4_STATE_SQUAREFREE_BETA_KIND, 1)?;
    push_h4_descriptor(
        &mut descriptors,
        H4_STATE_SQUAREFREE_POINT_KIND,
        u16::try_from(1 + squarefree_layer_count).map_err(|_| GkrZkMaskError::Overflow)?,
    )?;
    let squarefree_start = descriptors.len();
    for _phase in 0..2 {
        for _ in 0..3 {
            push_h4_squarefree_layer_descriptors(&mut descriptors, 0, 1, 1)?;
        }
        for source_variables in 2..=state_variables + 1 {
            for _ in 0..2 {
                push_h4_squarefree_layer_descriptors(
                    &mut descriptors,
                    0,
                    source_variables,
                    source_variables,
                )?;
            }
        }
        push_h4_squarefree_layer_descriptors(&mut descriptors, 0, 2, 2)?;
        for source_variables in (1..=state_variables).chain(core::iter::once(state_variables)) {
            push_h4_squarefree_layer_descriptors(
                &mut descriptors,
                1,
                source_variables,
                source_variables,
            )?;
        }
    }
    let observed_squarefree_rounds = descriptors
        .len()
        .checked_sub(squarefree_start)
        .and_then(|rounds| rounds.checked_add(2))
        .ok_or(GkrZkMaskError::Overflow)?;
    if observed_squarefree_rounds != squarefree_rounds as usize {
        return Err(GkrZkMaskError::Shape);
    }

    // The source and corrected kind-67 tensor roots are repeated in the
    // message-first prelude before the equality point and Construction-1 rho
    // are released. Four component-address bits, sixteen coefficient-address
    // bits, and nine boundary/word-address bits make one exact 29-variable
    // hash-only table. The verifier-fixed multiplication circuit adds one
    // left-wire, one right-wire, and one terminal w round after the group
    // reduction. The two single-variable source rounds are degree five so the
    // complete Construction-2 nonlinear correction is retained.
    push_h4_descriptor(
        &mut descriptors,
        H4_BOOLEANITY_PRELUDE_KIND,
        u16::try_from(1 + H4_BOOLEANITY_VARIABLES).map_err(|_| GkrZkMaskError::Overflow)?,
    )?;
    for _ in 0..H4_BOOLEANITY_GROUP_ROUNDS {
        push_h4_descriptor(&mut descriptors, H4_BOOLEANITY_SUMCHECK_KIND, 1)?;
    }
    push_h4_descriptor(&mut descriptors, H4_BOOLEANITY_SUMCHECK_KIND, 1)?;
    push_h4_descriptor(&mut descriptors, H4_BOOLEANITY_SUMCHECK_KIND, 1)?;
    push_h4_descriptor(&mut descriptors, H4_BOOLEANITY_TERMINAL_KIND, 1)?;

    // Global padding is a separate linear masked identity over the same
    // committed source. Its selector excludes the documented boundary-one
    // state lane and is pinned by the portable grammar, never supplied by the
    // prover. The final message publishes only the masked source terminal.
    push_h4_descriptor(
        &mut descriptors,
        H4_PADDING_PRELUDE_KIND,
        u16::try_from(1 + H4_PADDING_VARIABLES).map_err(|_| GkrZkMaskError::Overflow)?,
    )?;
    for _ in 0..H4_PADDING_SUMCHECK_ROUNDS {
        push_h4_descriptor(&mut descriptors, H4_PADDING_SUMCHECK_KIND, 1)?;
    }
    push_h4_descriptor(&mut descriptors, H4_PADDING_TERMINAL_KIND, 1)?;

    push_h4_descriptor(&mut descriptors, H4_STATE_COMPOSED_MASK_BATCH_KIND, 1)?;
    push_h4_descriptor(&mut descriptors, H4_PCS_CLAIM_BATCH_KIND, 6)?;
    push_h4_descriptor(&mut descriptors, H4_PCS_INITIAL_KIND, 1)?;
    for _ in 0..9 {
        push_h4_descriptor(&mut descriptors, H4_PCS_ROW_KIND, 1)?;
    }
    push_h4_descriptor(&mut descriptors, H4_PCS_BASE_KIND, 1)?;
    push_h4_descriptor(&mut descriptors, H4_PCS_ANSWER_KIND, 1)?;

    if descriptors.len() != total_rounds as usize {
        return Err(GkrZkMaskError::Shape);
    }
    Ok(descriptors)
}

/// Authenticate and replay the exact one-chain H4 schedule for `capacity`.
///
/// K512 still has one logical transcript: its four shard messages are carried
/// by each round's aggregate frame and receive the same returned challenge.
/// This function verifies the dual-PQ public coin and independently pins every
/// descriptor kind, ordinal, and output count.  Message-frame semantics remain
/// the responsibility of the portable H4 package verifier.
pub fn verify_selected_state_composed_public_coin_bundle(
    bundle: &ChainedPublicCoinBundle,
    capacity: usize,
) -> Result<Vec<ChainedChallenge>, H4AuthenticatedScheduleError> {
    let expected = selected_state_composed_round_descriptors(capacity)
        .map_err(|_| H4AuthenticatedScheduleError::Geometry)?;
    if bundle.rounds.len() != expected.len() {
        return Err(H4AuthenticatedScheduleError::Geometry);
    }
    let challenges = verify_chained_public_coin_bundle(bundle)?;
    if challenges.len() != expected.len() {
        return Err(H4AuthenticatedScheduleError::Geometry);
    }
    for (ordinal, (round, descriptor)) in bundle.rounds.iter().zip(expected).enumerate() {
        if round.descriptor != descriptor {
            return Err(H4AuthenticatedScheduleError::Descriptor { ordinal });
        }
    }
    Ok(challenges)
}

/// Variable degrees for the Libra Construction-1 sumcheck mask in exact
/// backward proof order. Each layer binds thirteen shared-group variables
/// with cubic messages. Each source wire axis is quadratic except for its last
/// variable, whose Construction-2 terminal correction is cubic. The final
/// terminal-extension variable is quadratic.
pub fn selected_sumcheck_mask_variable_degrees() -> Vec<Vec<usize>> {
    let mut layers = Vec::with_capacity(GKR_LAYERS as usize);
    for _round in (0..KECCAK_ROUNDS as usize).rev() {
        for layer in (0..GKR_LAYERS_PER_KECCAK_ROUND as usize).rev() {
            let mut degrees = vec![3; GKR_GROUP_ROUNDS_PER_LAYER as usize];
            let left_start = degrees.len();
            degrees.extend(core::iter::repeat_n(
                2,
                LEFT_WIRE_ROUNDS_BY_LAYER[layer] as usize,
            ));
            *degrees
                .last_mut()
                .expect("every selected left source has variables") = 3;
            let right_start = degrees.len();
            degrees.extend(core::iter::repeat_n(
                2,
                RIGHT_WIRE_ROUNDS_BY_LAYER[layer] as usize,
            ));
            *degrees
                .last_mut()
                .expect("every selected right source has variables") = 3;
            debug_assert_eq!(
                degrees.len() - left_start,
                WIRE_ROUNDS_BY_LAYER[layer] as usize
            );
            debug_assert!(right_start > left_start);
            degrees.push(2);
            layers.push(degrees);
        }
    }
    layers
}

pub fn selected_gkr_mask_layout() -> Result<CompleteGkrZkMaskCommitmentLayout, GkrZkMaskError> {
    CompleteGkrZkMaskCommitmentLayout::new(
        &selected_sumcheck_mask_variable_degrees(),
        PACKED_BINARY_MESSAGE_COEFFICIENTS,
    )
}

/// Append the state-relation, dual-product-tree, and coefficient-evaluation
/// masks to the selected Keccak layout. The existing 168 layer ordinals stay
/// unchanged, so all masks remain in the one H4-committed auxiliary
/// polynomial. State layers do not publish packed-binary bridges; retaining
/// the fixed bridge-width slots keeps one simple, auditable layout and still
/// fits the already committed 2^15 coefficient capacity.
pub fn selected_state_composed_mask_variable_degrees(
    capacity: usize,
) -> Result<Vec<Vec<usize>>, GkrZkMaskError> {
    let state_variables = match capacity {
        128 => 7,
        512 => 9,
        _ => return Err(GkrZkMaskError::Shape),
    };
    let mut layers = selected_sumcheck_mask_variable_degrees();

    // One 2^12-group relation layer over two 64-wire source axes, followed by
    // the Construction-2 terminal-extension variable.
    let mut relation = vec![3; 12];
    for _ in 0..2 {
        relation.extend(core::iter::repeat_n(2, 5));
        relation.push(3);
    }
    relation.push(2);
    layers.push(relation);

    // Each phase starts at public zero and reduces through a three-layer
    // A*P+B*P'-1 tail. All three layers have two-element source axes.
    for _phase in 0..2 {
        for _ in 0..3 {
            // With no preceding group/wire coordinate, Construction 2's
            // first-coordinate layer mask makes each source round quintic.
            layers.push(vec![5, 5, 2]);
        }

        // The dual product tree has two layers at every height. Both source
        // axes have `source_variables` variables and each final source round
        // is cubic because it carries the terminal masking correction.
        for source_variables in 2..=state_variables + 1 {
            for _layer in 0..2 {
                let mut degrees = vec![2; 2 * source_variables];
                degrees[source_variables - 1] = 3;
                degrees[2 * source_variables - 1] = 3;
                degrees.push(2);
                layers.push(degrees);
            }
        }

        // One proof-native adapter maps grouped `[A,0,B,0]` to the
        // two-element `[A,B]` identity input without a host-trusted reshape.
        layers.push(vec![2, 3, 2, 3, 2]);

        // A and B share a one-variable group axis. One multiplication layer
        // and the complete binary sum tree reduce their coefficient tables to
        // the two values consumed by the identity tail without publishing
        // either value.
        let coefficient_source_variables =
            (1..=state_variables).chain(core::iter::once(state_variables));
        for source_variables in coefficient_source_variables {
            let mut degrees = vec![3];
            degrees.extend(core::iter::repeat_n(2, 2 * source_variables));
            let terminal_degree = if source_variables == 1 { 5 } else { 3 };
            degrees[source_variables] = terminal_degree;
            degrees[2 * source_variables] = terminal_degree;
            degrees.push(2);
            layers.push(degrees);
        }
    }

    // One verifier-fixed relay-free multiplication layer proves
    // `[b,0] * [b-1,0] = 0`. Equality-weighted group rounds are cubic. The
    // generic Construction-2 terminal correction has exact degree five on
    // each one-variable source axis, followed by the ordinary degree-two w
    // round. This is the already-tested nonlinear masked GKR protocol, not a
    // bespoke b(r)(b(r)-1) shortcut.
    let mut booleanity = vec![3; H4_BOOLEANITY_VARIABLES as usize];
    booleanity.extend([5, 5, 2]);
    layers.push(booleanity);

    // The padding relation is linear in the committed source and multiplied
    // only by the verifier-fixed equality polynomial. Its 29 round messages
    // are therefore exactly quadratic; a separate layer mask hides the one
    // terminal later coupled through Construction 8.2.
    layers.push(vec![2; H4_PADDING_VARIABLES as usize]);
    Ok(layers)
}

/// Verifier-derived ordinal of the domain-separated Booleanity mask layer in
/// the one corrected kind-67 tensor.  It is never accepted from proof bytes.
pub fn selected_booleanity_mask_layer(capacity: usize) -> Result<usize, GkrZkMaskError> {
    selected_state_composed_mask_variable_degrees(capacity)?
        .len()
        .checked_sub(2)
        .ok_or(GkrZkMaskError::Empty)
}

/// Verifier-derived ordinal of the domain-separated global-padding mask layer
/// in the same corrected kind-67 tensor. It is never accepted from proof bytes.
pub fn selected_padding_mask_layer(capacity: usize) -> Result<usize, GkrZkMaskError> {
    selected_state_composed_mask_variable_degrees(capacity)?
        .len()
        .checked_sub(1)
        .ok_or(GkrZkMaskError::Empty)
}

pub fn selected_state_composed_mask_layout(
    capacity: usize,
) -> Result<CompleteGkrZkMaskCommitmentLayout, GkrZkMaskError> {
    CompleteGkrZkMaskCommitmentLayout::new(
        &selected_state_composed_mask_variable_degrees(capacity)?,
        PACKED_BINARY_MESSAGE_COEFFICIENTS,
    )
}

pub fn gkr_mask_tensor_observation_rank_certificate(
    capacity: usize,
) -> Result<GkrMaskTensorObservationRankCertificate, GkrZkMaskError> {
    let layout = selected_state_composed_mask_layout(capacity)?;
    let budget = layout.leakage_budget()?;
    let complete_observation_rank = budget
        .total_rank
        .checked_add(GKR_MASK_PUBLIC_ANSWER_EQUATION_RANK)
        .and_then(|rank| rank.checked_add(GKR_MASK_TENSOR_PCS_OPENINGS))
        .and_then(|rank| rank.checked_add(GKR_MASK_TENSOR_PCS_OPENINGS))
        .and_then(|rank| rank.checked_add(GKR_MASK_BASE_TARGET_RANK))
        .ok_or(GkrZkMaskError::Overflow)?;
    let residual_dimension = GKR_MASK_JOINT_COEFFICIENT_DIMENSION
        .checked_sub(complete_observation_rank)
        .filter(|residual| *residual > 0)
        .ok_or(GkrZkMaskError::Shape)?;
    let residual_entropy_bits_lower_bound = residual_dimension
        .checked_mul(GKR_MASK_FP16_ENTROPY_BITS_LOWER_BOUND)
        .filter(|bits| *bits >= H4_MASK_RESIDUAL_SECURITY_BITS)
        .ok_or(GkrZkMaskError::Shape)?;
    Ok(GkrMaskTensorObservationRankCertificate {
        coefficient_dimension: layout.padded_coefficients,
        joint_coefficient_dimension: GKR_MASK_JOINT_COEFFICIENT_DIMENSION,
        used_coefficients: layout.used_coefficients,
        bridge_view_rank: budget.bridge_view_rank,
        sumcheck_view_rank: budget.sumcheck_view_rank,
        layer_view_rank: budget.layer_view_rank,
        aggregate_opening_rank: budget.aggregate_opening_rank,
        state_composed_transcript_rank: budget.total_rank,
        tensor_pcs_opening_scalars: GKR_MASK_TENSOR_PCS_OPENINGS,
        base_tensor_pcs_opening_scalars: GKR_MASK_TENSOR_PCS_OPENINGS,
        public_answer_equation_rank: GKR_MASK_PUBLIC_ANSWER_EQUATION_RANK,
        base_target_rank: GKR_MASK_BASE_TARGET_RANK,
        complete_observation_rank,
        residual_dimension,
        residual_entropy_bits_lower_bound,
        tensor_leaves: GKR_MASK_TENSOR_LEAVES,
        tensor_leaf_bytes: GKR_MASK_TENSOR_LEAF_BYTES,
        // (1 - 512/8192) * (1 - 64/128) = 15/32.  The exact RS
        // minimum distance is slightly larger; this conservative value is the
        // one used by the query-failure ledger.
        conservative_relative_distance_numerator: 15,
        conservative_relative_distance_denominator: 32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_schedule_counts_are_exact() {
        assert_eq!(WIRE_ROUNDS_BY_LAYER.iter().sum::<u32>(), 144);
        assert_eq!(
            LEFT_WIRE_ROUNDS_BY_LAYER
                .iter()
                .zip(RIGHT_WIRE_ROUNDS_BY_LAYER)
                .map(|(left, right)| *left + right)
                .collect::<Vec<_>>(),
            WIRE_ROUNDS_BY_LAYER
        );
        assert_eq!(GKR_LAYERS, 168);
        assert_eq!(GKR_CLAIM_MIX_ROUNDS, 95);
        assert_eq!(GKR_TRANSCRIPT_ROUNDS, 6_072);
        assert_eq!(GKR_MASK_BATCH_ROUNDS, 1);
        assert_eq!(GKR_ROUNDS, 6_073);
        assert_eq!(STATE_RELATION_ROUNDS, 26);
        assert_eq!(STATE_SQUAREFREE_K128_ROUNDS, 614);
        assert_eq!(STATE_SQUAREFREE_K512_ROUNDS, 882);
        assert_eq!(PCS_DOWNSTREAM_ROUNDS, 13);
        assert_eq!(STATE_MASK_BATCH_ROUNDS, 1);
        assert_eq!(H4_BOOLEANITY_ROUNDS, 33);
        assert_eq!(H4_PADDING_ROUNDS, 31);
        assert_eq!(STATE_RELATION_COMBINED_ROUNDS, 6_177);
        assert_eq!(STATE_COMPOSED_K128_ROUNDS, 6_791);
        assert_eq!(STATE_COMPOSED_K512_ROUNDS, 7_059);

        let kinds = (0..GKR_ROUNDS)
            .map(|round| selected_gkr_round_kind(round).unwrap())
            .collect::<Vec<_>>();
        for (kind, expected) in [
            (SelectedGkrRoundKind::OutputQuery, 1),
            (SelectedGkrRoundKind::ClaimMix, 95),
            (SelectedGkrRoundKind::PackedBridge, 168),
            (SelectedGkrRoundKind::SharedGroup, 2_184),
            (SelectedGkrRoundKind::Wire, 3_456),
            (SelectedGkrRoundKind::Terminal, 168),
            (SelectedGkrRoundKind::MaskBatch, 1),
        ] {
            assert_eq!(
                kinds.iter().filter(|candidate| **candidate == kind).count(),
                expected
            );
        }

        assert_eq!(selected_gkr_round_output_count(0), Some(27));
        for round in 1..GKR_ROUNDS {
            let kind = selected_gkr_round_kind(round).unwrap();
            let output_count = selected_gkr_round_output_count(round).unwrap();
            assert_eq!(
                output_count,
                match kind {
                    SelectedGkrRoundKind::ClaimMix => 3,
                    SelectedGkrRoundKind::Terminal
                        if selected_gkr_round_kind(round + 1)
                            == Some(SelectedGkrRoundKind::PackedBridge) =>
                    {
                        3
                    }
                    _ => 1,
                },
                "round={round} kind={kind:?}"
            );
        }
    }

    #[test]
    fn state_composed_descriptor_schedule_is_exact_and_global() {
        for (capacity, expected_rounds, point_outputs) in [
            (128, STATE_COMPOSED_K128_ROUNDS, 53),
            (512, STATE_COMPOSED_K512_ROUNDS, 65),
        ] {
            let descriptors = selected_state_composed_round_descriptors(capacity).unwrap();
            assert_eq!(descriptors.len(), expected_rounds as usize);
            assert!(
                descriptors
                    .iter()
                    .enumerate()
                    .all(|(ordinal, descriptor)| descriptor.ordinal as usize == ordinal)
            );
            assert_eq!(descriptors[0].kind, 100);
            assert_eq!(
                descriptors[GKR_ROUNDS as usize].kind,
                H4_STATE_RELATION_OUTPUT_KIND
            );
            assert_eq!(
                descriptors[GKR_ROUNDS as usize + STATE_RELATION_ROUNDS as usize].kind,
                H4_STATE_SQUAREFREE_BETA_KIND
            );
            assert_eq!(
                descriptors[GKR_ROUNDS as usize + STATE_RELATION_ROUNDS as usize + 1],
                ChainedRoundDescriptor {
                    kind: H4_STATE_SQUAREFREE_POINT_KIND,
                    ordinal: GKR_ROUNDS + STATE_RELATION_ROUNDS + 1,
                    output_count: point_outputs,
                }
            );
            let squarefree_rounds = match capacity {
                128 => STATE_SQUAREFREE_K128_ROUNDS,
                512 => STATE_SQUAREFREE_K512_ROUNDS,
                _ => unreachable!(),
            };
            let booleanity_start =
                (GKR_ROUNDS + STATE_RELATION_ROUNDS + squarefree_rounds) as usize;
            assert_eq!(
                descriptors[booleanity_start],
                ChainedRoundDescriptor {
                    kind: H4_BOOLEANITY_PRELUDE_KIND,
                    ordinal: booleanity_start as u32,
                    output_count: 30,
                }
            );
            assert!(
                descriptors[booleanity_start + 1..booleanity_start + 32]
                    .iter()
                    .all(|descriptor| descriptor.kind == H4_BOOLEANITY_SUMCHECK_KIND
                        && descriptor.output_count == 1)
            );
            assert_eq!(
                descriptors[booleanity_start + 32].kind,
                H4_BOOLEANITY_TERMINAL_KIND
            );
            assert_eq!(
                descriptors[booleanity_start + 33],
                ChainedRoundDescriptor {
                    kind: H4_PADDING_PRELUDE_KIND,
                    ordinal: (booleanity_start + 33) as u32,
                    output_count: 30,
                }
            );
            assert!(
                descriptors[booleanity_start + 34..booleanity_start + 63]
                    .iter()
                    .all(|descriptor| descriptor.kind == H4_PADDING_SUMCHECK_KIND
                        && descriptor.output_count == 1)
            );
            assert_eq!(
                descriptors[booleanity_start + 63].kind,
                H4_PADDING_TERMINAL_KIND
            );
            assert_eq!(
                descriptors[booleanity_start + 64].kind,
                H4_STATE_COMPOSED_MASK_BATCH_KIND
            );
            assert_eq!(
                descriptors[descriptors.len() - 13..]
                    .iter()
                    .map(|descriptor| descriptor.kind)
                    .collect::<Vec<_>>(),
                [H4_PCS_CLAIM_BATCH_KIND, H4_PCS_INITIAL_KIND]
                    .into_iter()
                    .chain(core::iter::repeat_n(H4_PCS_ROW_KIND, 9))
                    .chain([H4_PCS_BASE_KIND, H4_PCS_ANSWER_KIND])
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn selected_mask_layout_fits_the_frozen_auxiliary_polynomial() {
        let degrees = selected_sumcheck_mask_variable_degrees();
        assert_eq!(degrees.len(), GKR_LAYERS as usize);
        assert_eq!(degrees.iter().map(Vec::len).sum::<usize>(), 5_808);
        assert_eq!(
            degrees
                .iter()
                .flatten()
                .filter(|degree| **degree == 3)
                .count(),
            2_520
        );
        assert_eq!(
            degrees
                .iter()
                .flatten()
                .filter(|degree| **degree == 2)
                .count(),
            3_288
        );

        let layout = selected_gkr_mask_layout().unwrap();
        assert_eq!(layout.layers.len(), GKR_LAYERS as usize);
        assert_eq!(layout.used_coefficients, GKR_MASK_USED_COEFFICIENTS);
        assert_eq!(layout.padded_coefficients, GKR_MASK_PADDED_COEFFICIENTS);
        assert!(layout.used_coefficients <= layout.padded_coefficients);
    }

    #[test]
    fn selected_mask_leakage_rank_is_bounded_by_committed_randomness() {
        let layout = selected_gkr_mask_layout().unwrap();
        let budget = layout.leakage_budget().unwrap();
        assert_eq!(budget.bridge_view_rank, 7_728);
        assert_eq!(budget.sumcheck_view_rank, 14_304);
        assert_eq!(budget.layer_view_rank, 672);
        assert_eq!(budget.aggregate_opening_rank, 1);
        assert_eq!(budget.total_rank, 22_705);
        assert!(budget.total_rank < layout.padded_coefficients);
    }

    #[test]
    fn state_composed_masks_fit_the_existing_auxiliary_polynomial() {
        for (capacity, layer_count, used, total_rank) in [
            (128, 223, STATE_COMPOSED_K128_MASK_USED_COEFFICIENTS, 26_899),
            (512, 235, STATE_COMPOSED_K512_MASK_USED_COEFFICIENTS, 28_027),
        ] {
            let degrees = selected_state_composed_mask_variable_degrees(capacity).unwrap();
            let layout = selected_state_composed_mask_layout(capacity).unwrap();
            let budget = layout.leakage_budget().unwrap();
            assert_eq!(degrees.len(), layer_count);
            assert_eq!(layout.layers.len(), layer_count);
            assert_eq!(layout.used_coefficients, used);
            assert_eq!(layout.padded_coefficients, GKR_MASK_PADDED_COEFFICIENTS);
            assert_eq!(budget.total_rank, total_rank);
            assert_eq!(
                selected_booleanity_mask_layer(capacity).unwrap(),
                layer_count - 2
            );
            assert_eq!(
                selected_padding_mask_layer(capacity).unwrap(),
                layer_count - 1
            );
            assert_eq!(degrees[layer_count - 2][..29], [3; 29]);
            assert_eq!(degrees[layer_count - 2][29..], [5, 5, 2]);
            assert_eq!(degrees[layer_count - 1], [2; 29]);
            assert!(budget.total_rank < layout.padded_coefficients);
        }
    }

    #[test]
    fn coupled_construction_8_2_tensors_have_a_positive_joint_rank_margin() {
        for (capacity, transcript_rank, complete_rank, residual) in
            [(128, 26_899, 62_104, 3_432), (512, 28_027, 63_232, 2_304)]
        {
            let certificate = gkr_mask_tensor_observation_rank_certificate(capacity).unwrap();
            assert_eq!(certificate.coefficient_dimension, 32_768);
            assert_eq!(certificate.joint_coefficient_dimension, 65_536);
            assert_eq!(certificate.state_composed_transcript_rank, transcript_rank);
            assert_eq!(certificate.tensor_pcs_opening_scalars, 1_218);
            assert_eq!(certificate.base_tensor_pcs_opening_scalars, 1_218);
            assert_eq!(certificate.public_answer_equation_rank, 32_768);
            assert_eq!(certificate.base_target_rank, 1);
            assert_eq!(certificate.complete_observation_rank, complete_rank);
            assert_eq!(certificate.residual_dimension, residual);
            assert_eq!(
                certificate.residual_entropy_bits_lower_bound,
                residual * GKR_MASK_FP16_ENTROPY_BITS_LOWER_BOUND
            );
            assert!(
                certificate.residual_entropy_bits_lower_bound >= H4_MASK_RESIDUAL_SECURITY_BITS
            );
            assert_eq!(certificate.tensor_leaves, 1 << 20);
            assert_eq!(certificate.tensor_leaf_bytes, 64);
            assert_eq!(
                (
                    certificate.conservative_relative_distance_numerator,
                    certificate.conservative_relative_distance_denominator,
                ),
                (15, 32)
            );
            assert!(
                certificate.complete_observation_rank < certificate.joint_coefficient_dimension
            );
        }
    }

    #[test]
    fn retired_sixty_four_codeword_layout_is_fully_recoverable() {
        let old_slice_dimension = 512_usize;
        let old_slice_count = 64_usize;
        let distinct_openings = GKR_MASK_TENSOR_PCS_OPENINGS;
        let old_pcs_rank = old_slice_count * distinct_openings.min(old_slice_dimension);
        assert_eq!(old_pcs_rank, GKR_MASK_PADDED_COEFFICIENTS);

        let tensor_root_opening_rank = GKR_MASK_TENSOR_PCS_OPENINGS;
        assert_eq!(
            GKR_MASK_PADDED_COEFFICIENTS - tensor_root_opening_rank,
            31_550
        );
        assert_eq!(
            gkr_mask_tensor_observation_rank_certificate(512)
                .unwrap()
                .residual_dimension,
            2_304
        );
    }
}
