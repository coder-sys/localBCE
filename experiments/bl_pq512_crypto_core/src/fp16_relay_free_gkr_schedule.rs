//! Frozen schedule and zero-knowledge mask layout for the selected
//! seven-layer, B=16 relay-free Keccak GKR.
//!
//! This module contains dimensions only. It does not generate challenges and
//! deliberately contains no Fiat--Shamir transform.

use alloc::{vec, vec::Vec};

use crate::{
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

/// The combined schedule reuses the last GKR challenge for the H4 claim
/// batching. The state relation then consumes one output-query response and
/// twenty-four authenticated public-coin sumcheck responses before the
/// downstream PCS coordinate/source/mask, row, base, and query rounds.
pub const STATE_RELATION_ROUNDS: u32 = 25;
pub const PCS_DOWNSTREAM_ROUNDS: u32 = 13;
pub const COMBINED_ROUNDS: u32 = GKR_ROUNDS + STATE_RELATION_ROUNDS + PCS_DOWNSTREAM_ROUNDS;

pub const GKR_MASK_USED_COEFFICIENTS: usize = 23_544;
pub const GKR_MASK_PADDED_COEFFICIENTS: usize = 32_768;

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
        assert_eq!(STATE_RELATION_ROUNDS, 25);
        assert_eq!(PCS_DOWNSTREAM_ROUNDS, 13);
        assert_eq!(COMBINED_ROUNDS, 6_111);

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
}
