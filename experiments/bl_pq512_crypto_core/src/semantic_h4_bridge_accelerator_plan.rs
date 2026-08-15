//! Small bounded-memory plan for the semantic/H4 bridge accelerator.

use alloc::vec::Vec;

use crate::semantic_h4_bridge_gkr::{
    BRIDGE_BLOCK_GROUP_LOG, BRIDGE_DIGEST_GROUP_LOG, SemanticH4BridgeCircuit,
    SemanticH4BridgeProfile, semantic_h4_bridge_topologies,
};

pub const BRIDGE_ACCELERATOR_CHUNK_BUDGET_BYTES: u64 = 512 * 1_024 * 1_024;
pub const BRIDGE_ACCELERATOR_NON_CHUNK_RESERVE_BYTES: u64 = 512 * 1_024 * 1_024;
pub const BRIDGE_ACCELERATOR_RETAINED_STATE_CEILING_BYTES: u64 = 3 * 1_024 * 1_024 * 1_024;
pub const BRIDGE_ACCELERATOR_DEVICE_CEILING_BYTES: u64 = 8_192 * 1_024 * 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemanticH4BridgeAcceleratorLayerPlan {
    pub circuit: SemanticH4BridgeCircuit,
    pub layer: usize,
    pub group_log: u8,
    /// Upper bound; the worker may retain and progressively fold an
    /// authenticated-source accumulator once it fits the separate ceiling.
    pub streaming_rounds: u8,
    /// Largest power-of-two group chunk admitted by the working-set model.
    pub chunk_groups: u32,
    pub chunk_working_set_bytes: u64,
    /// Maximum retained progressive-fold state admitted by the worker.
    pub transition_table_bytes: u64,
}

fn chunk_bytes(left_width: usize, right_width: usize, groups: u64) -> Option<u64> {
    let widths = u64::try_from(left_width.checked_add(right_width)?).ok()?;
    // Base-M31 current/next rows plus Fp16-weighted left/right rows. The
    // message reduction partials are covered by the fixed non-chunk reserve.
    widths.checked_mul(groups)?.checked_mul(4 + 64)
}

pub fn semantic_h4_bridge_accelerator_plan(
    profile: SemanticH4BridgeProfile,
) -> Option<Vec<SemanticH4BridgeAcceleratorLayerPlan>> {
    let topologies = semantic_h4_bridge_topologies();
    let mut result = Vec::new();
    for (circuit, group_log, layers) in [
        (
            SemanticH4BridgeCircuit::Rate,
            profile.rate_group_log(),
            topologies.rate,
        ),
        (
            SemanticH4BridgeCircuit::Inactive,
            BRIDGE_BLOCK_GROUP_LOG,
            topologies.inactive,
        ),
        (
            SemanticH4BridgeCircuit::Capacity,
            BRIDGE_BLOCK_GROUP_LOG,
            topologies.capacity,
        ),
        (
            SemanticH4BridgeCircuit::Digest,
            BRIDGE_DIGEST_GROUP_LOG,
            topologies.digest,
        ),
    ] {
        for (layer_index, layer) in layers.iter().enumerate() {
            let mut chunk_groups = 1_u64;
            while chunk_groups < (1_u64 << group_log) {
                let next = chunk_groups.checked_mul(2)?;
                if chunk_bytes(layer.left_width, layer.right_width, next)?
                    > BRIDGE_ACCELERATOR_CHUNK_BUDGET_BYTES
                {
                    break;
                }
                chunk_groups = next;
            }
            let bytes = chunk_bytes(layer.left_width, layer.right_width, chunk_groups)?;
            result.push(SemanticH4BridgeAcceleratorLayerPlan {
                circuit,
                layer: layer_index,
                group_log,
                streaming_rounds: group_log,
                chunk_groups: u32::try_from(chunk_groups).ok()?,
                chunk_working_set_bytes: bytes,
                transition_table_bytes: BRIDGE_ACCELERATOR_RETAINED_STATE_CEILING_BYTES,
            });
        }
    }
    Some(result)
}

pub fn semantic_h4_bridge_required_free_device_bytes(
    profile: SemanticH4BridgeProfile,
) -> Option<u64> {
    semantic_h4_bridge_accelerator_plan(profile)?
        .into_iter()
        .map(|plan| plan.chunk_working_set_bytes)
        .max()?
        .checked_add(BRIDGE_ACCELERATOR_NON_CHUNK_RESERVE_BYTES)?
        .checked_add(BRIDGE_ACCELERATOR_RETAINED_STATE_CEILING_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_layer_is_fully_streamed_and_bounded() {
        for profile in [SemanticH4BridgeProfile::K128, SemanticH4BridgeProfile::K512] {
            let plans = semantic_h4_bridge_accelerator_plan(profile).unwrap();
            assert_eq!(plans.len(), 24);
            for plan in plans {
                assert_eq!(plan.streaming_rounds, plan.group_log);
                assert!(plan.chunk_groups.is_power_of_two());
                assert!(plan.chunk_working_set_bytes <= BRIDGE_ACCELERATOR_CHUNK_BUDGET_BYTES);
                assert_eq!(
                    plan.transition_table_bytes,
                    BRIDGE_ACCELERATOR_RETAINED_STATE_CEILING_BYTES
                );
            }
            assert!(
                semantic_h4_bridge_required_free_device_bytes(profile).unwrap()
                    <= BRIDGE_ACCELERATOR_DEVICE_CEILING_BYTES
            );
        }
    }
}
