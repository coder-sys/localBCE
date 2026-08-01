//! Independent bit-sliced execution check for compact B16 Keccak boundaries.

use alloc::{vec, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use crate::{
    hash_bus::GROUP_COUNT,
    hash_bus_b16_boundary::HashBusB16Shard,
    hash_bus_source::KECCAK_STATE_BITS,
    keccak_gkr_dag::{
        KeccakDagGateKind, KeccakDagLayer, KeccakDagSource, build_keccak_gkr_dag_round,
    },
};

const PADDED_STATE_BITS: usize = 2_048;
const KECCAK_ROUNDS: usize = 24;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashBusB16TraceError {
    Shape,
    Plan,
    Mismatch { group: usize, wire: usize },
}

fn gate_value(kind: KeccakDagGateKind, left: u16, right: u16) -> u16 {
    match kind {
        KeccakDagGateKind::Xor | KeccakDagGateKind::XorConstant(false) => left ^ right,
        KeccakDagGateKind::NotLeftAndRight => !left & right,
        KeccakDagGateKind::XorConstant(true) => !(left ^ right),
        KeccakDagGateKind::Zero => 0,
    }
}

fn source<'a>(
    source: KeccakDagSource,
    round_input: &'a [u16],
    boundaries: &'a [Vec<u16>],
) -> &'a [u16] {
    match source {
        KeccakDagSource::RoundInput => round_input,
        KeccakDagSource::Layer(index) => &boundaries[index],
    }
}

fn evaluate_group(
    plans: &[[KeccakDagLayer; 7]],
    shard: &HashBusB16Shard,
    group: usize,
    boundaries: &mut [Vec<u16>],
    round_input: &mut [u16],
) -> Result<(), HashBusB16TraceError> {
    let group_count = usize::try_from(GROUP_COUNT).map_err(|_| HashBusB16TraceError::Shape)?;
    for (wire, destination) in round_input[..KECCAK_STATE_BITS].iter_mut().enumerate() {
        *destination = shard.input[wire * group_count + group];
    }
    round_input[KECCAK_STATE_BITS..].fill(0);
    for layers in plans {
        for (layer_index, layer) in layers.iter().enumerate() {
            let (prior, current_and_later) = boundaries.split_at_mut(layer_index);
            let left = source(layer.left_source, round_input, prior);
            let right = source(layer.right_source, round_input, prior);
            let output = &mut current_and_later[0];
            output.resize(layer.padded_width, 0);
            for (destination, gate) in output.iter_mut().zip(&layer.gates) {
                *destination = gate_value(gate.kind, left[gate.left], right[gate.right]);
            }
        }
        round_input[..KECCAK_STATE_BITS].copy_from_slice(&boundaries[6][..KECCAK_STATE_BITS]);
        round_input[KECCAK_STATE_BITS..].fill(0);
    }
    for (wire, actual) in round_input[..KECCAK_STATE_BITS].iter().copied().enumerate() {
        if actual != shard.output[wire * group_count + group] {
            return Err(HashBusB16TraceError::Mismatch { group, wire });
        }
    }
    Ok(())
}

pub fn verify_hash_bus_b16_shard(
    shard: &HashBusB16Shard,
    worker_count: usize,
) -> Result<(), HashBusB16TraceError> {
    let group_count = usize::try_from(GROUP_COUNT).map_err(|_| HashBusB16TraceError::Shape)?;
    let values = KECCAK_STATE_BITS
        .checked_mul(group_count)
        .ok_or(HashBusB16TraceError::Shape)?;
    if shard.input.len() != values
        || shard.output.len() != values
        || worker_count == 0
        || worker_count > 16
    {
        return Err(HashBusB16TraceError::Shape);
    }
    let plans = (0..KECCAK_ROUNDS)
        .map(|round| build_keccak_gkr_dag_round(round).map_err(|_| HashBusB16TraceError::Plan))
        .collect::<Result<Vec<_>, _>>()?;
    let first_failure = AtomicUsize::new(group_count);
    thread::scope(|scope| {
        for worker in 0..worker_count {
            let plans = &plans;
            let first_failure = &first_failure;
            scope.spawn(move || {
                let mut boundaries = (0..7).map(|_| Vec::new()).collect::<Vec<_>>();
                let mut round_input = vec![0_u16; PADDED_STATE_BITS];
                for group in (worker..group_count).step_by(worker_count) {
                    if group >= first_failure.load(Ordering::Relaxed) {
                        continue;
                    }
                    if evaluate_group(plans, shard, group, &mut boundaries, &mut round_input)
                        .is_err()
                    {
                        first_failure.fetch_min(group, Ordering::Relaxed);
                    }
                }
            });
        }
    });
    let group = first_failure.load(Ordering::Relaxed);
    if group == group_count {
        return Ok(());
    }
    let mut boundaries = (0..7).map(|_| Vec::new()).collect::<Vec<_>>();
    let mut round_input = vec![0_u16; PADDED_STATE_BITS];
    evaluate_group(&plans, shard, group, &mut boundaries, &mut round_input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_sliced_gate_formulas_match_every_boolean_lane() {
        for left in [0_u16, 0xa53c, u16::MAX] {
            for right in [0_u16, 0xc369, u16::MAX] {
                for kind in [
                    KeccakDagGateKind::Xor,
                    KeccakDagGateKind::NotLeftAndRight,
                    KeccakDagGateKind::XorConstant(false),
                    KeccakDagGateKind::XorConstant(true),
                    KeccakDagGateKind::Zero,
                ] {
                    let actual = gate_value(kind, left, right);
                    for lane in 0..16 {
                        let left = (left >> lane) & 1;
                        let right = (right >> lane) & 1;
                        let expected = match kind {
                            KeccakDagGateKind::Xor | KeccakDagGateKind::XorConstant(false) => {
                                left ^ right
                            }
                            KeccakDagGateKind::NotLeftAndRight => (1 - left) & right,
                            KeccakDagGateKind::XorConstant(true) => 1 ^ left ^ right,
                            KeccakDagGateKind::Zero => 0,
                        };
                        assert_eq!((actual >> lane) & 1, expected);
                    }
                }
            }
        }
    }
}
