//! Deterministic row-streaming witness generator for the direct Boolean SHA3 AIR.

use core::fmt;

use alloc::vec::Vec;

use crate::field::M31;
use crate::sha3_air::{KECCAK_ROUNDS, RATE_BYTES, Sha3TraceError, keccak_f1600_round};

pub const BOOLEAN_STATE_BITS: usize = 1_600;
pub const BOOLEAN_PARITY_BITS: usize = 320;
pub const BOOLEAN_ROUND_PRIVATE_COLUMNS: usize = 1_924;
pub const BOOLEAN_ABSORB_PRIVATE_COLUMNS: usize = 2_330;
pub const BOOLEAN_DIGEST_PRIVATE_COLUMNS: usize = 576;
pub const BOOLEAN_ROWS_PER_PERMUTATION: usize = 25;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BooleanSha3Call<'a> {
    pub message: &'a [u8],
    pub capacity: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BooleanSha3TraceReport {
    pub calls: usize,
    pub permutations: usize,
    pub round_rows: usize,
    pub absorb_rows: usize,
    pub digest_rows: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BooleanSha3TraceError {
    Calls,
    Capacity,
    Overflow,
    Sha3(Sha3TraceError),
}

impl From<Sha3TraceError> for BooleanSha3TraceError {
    fn from(value: Sha3TraceError) -> Self {
        Self::Sha3(value)
    }
}

impl fmt::Display for BooleanSha3TraceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Boolean SHA3 trace error: {self:?}")
    }
}

impl core::error::Error for BooleanSha3TraceError {}

fn padded_block_count(length: usize) -> Result<usize, BooleanSha3TraceError> {
    length
        .checked_add(1)
        .ok_or(BooleanSha3TraceError::Overflow)
        .map(|value| value.div_ceil(RATE_BYTES as usize))
}

fn bytes_to_lanes(state: &[u8; 200]) -> [u64; 25] {
    let mut lanes = [0_u64; 25];
    for (lane, bytes) in lanes.iter_mut().zip(state.chunks_exact(8)) {
        *lane = u64::from_le_bytes(bytes.try_into().expect("exact lane width"));
    }
    lanes
}

fn lanes_to_bytes(lanes: &[u64; 25]) -> [u8; 200] {
    let mut state = [0_u8; 200];
    for (bytes, lane) in state.chunks_exact_mut(8).zip(lanes) {
        bytes.copy_from_slice(&lane.to_le_bytes());
    }
    state
}

fn m31(value: u32) -> M31 {
    M31::from_canonical(value).expect("Boolean SHA3 witness values are canonical M31")
}

fn append_state_bits(row: &mut Vec<M31>, state: &[u8; 200]) {
    row.extend(
        (0..BOOLEAN_STATE_BITS).map(|index| m31(u32::from((state[index / 8] >> (index % 8)) & 1))),
    );
}

fn append_parities(row: &mut Vec<M31>, state: &[u8; 200]) {
    for x in 0..5 {
        for z in 0..64 {
            let parity = (0..5).fold(0_u8, |value, y| {
                let index = 64 * (x + 5 * y) + z;
                value ^ ((state[index / 8] >> (index % 8)) & 1)
            });
            row.push(m31(u32::from(parity)));
        }
    }
}

fn padded_block(message: &[u8], block_index: usize, actual_blocks: usize) -> [u8; 72] {
    let mut block = [0_u8; 72];
    let start = block_index * 72;
    for (index, value) in block.iter_mut().enumerate() {
        let position = start + index;
        if position < message.len() {
            *value = message[position];
        } else if position == message.len() {
            *value = 0x06;
        }
    }
    if block_index + 1 == actual_blocks {
        block[71] ^= 0x80;
    }
    block
}

pub fn for_each_boolean_sha3_trace_row(
    calls: &[BooleanSha3Call<'_>],
    mut round_row: impl FnMut(&[M31]),
    mut absorb_row: impl FnMut(&[M31]),
    mut digest_row: impl FnMut(&[M31]),
) -> Result<BooleanSha3TraceReport, BooleanSha3TraceError> {
    if calls.is_empty() {
        return Err(BooleanSha3TraceError::Calls);
    }
    let mut permutations = 0_usize;
    for call in calls {
        if call.message.len() > call.capacity {
            return Err(BooleanSha3TraceError::Capacity);
        }
        permutations = permutations
            .checked_add(padded_block_count(call.capacity)?)
            .ok_or(BooleanSha3TraceError::Overflow)?;
    }

    for call in calls {
        let capacity_blocks = padded_block_count(call.capacity)?;
        let actual_blocks = padded_block_count(call.message.len())?;
        let mut chained_state = [0_u8; 200];
        let mut digest = [0_u8; 64];
        for block_index in 0..capacity_blocks {
            let active = block_index < actual_blocks;
            let actual_last = block_index + 1 == actual_blocks;
            let prior = if active { chained_state } else { [0_u8; 200] };
            let block = if active {
                padded_block(call.message, block_index, actual_blocks)
            } else {
                [0_u8; 72]
            };
            let mut absorbed = prior;
            for (destination, value) in absorbed.iter_mut().zip(block) {
                *destination ^= value;
            }

            let mut absorb_values = Vec::with_capacity(BOOLEAN_ABSORB_PRIVATE_COLUMNS);
            append_state_bits(&mut absorb_values, &prior);
            absorb_values.extend(block.map(|value| m31(u32::from(value))));
            for value in block {
                absorb_values.extend((0..8).map(|bit| m31(u32::from((value >> bit) & 1))));
            }
            let live_count = call.message.len().saturating_sub(block_index * 72).min(72);
            absorb_values.extend((0..72).map(|index| m31(u32::from(index < live_count))));
            let capacity_remaining = call.capacity.saturating_sub(block_index * 72).min(72);
            let slack = capacity_remaining - live_count;
            absorb_values.extend((0..7).map(|bit| m31(((slack >> bit) & 1) as u32)));
            absorb_values.push(m31(u32::from(active)));
            absorb_values.push(m31(u32::from(actual_last)));
            absorb_values.push(m31(u32::from(active && block_index > 0)));
            debug_assert_eq!(absorb_values.len(), BOOLEAN_ABSORB_PRIVATE_COLUMNS);
            absorb_row(&absorb_values);

            let mut lanes = bytes_to_lanes(&absorbed);
            for round_index in 0..KECCAK_ROUNDS as usize {
                let state = lanes_to_bytes(&lanes);
                let mut values = Vec::with_capacity(BOOLEAN_ROUND_PRIVATE_COLUMNS);
                append_state_bits(&mut values, &state);
                append_parities(&mut values, &state);
                values.push(m31(u32::from(active)));
                values.push(m31(u32::from(actual_last)));
                values.push(M31::ZERO);
                values.push(M31::ZERO);
                debug_assert_eq!(values.len(), BOOLEAN_ROUND_PRIVATE_COLUMNS);
                round_row(&values);
                keccak_f1600_round(&mut lanes, round_index)?;
            }
            let output = lanes_to_bytes(&lanes);
            let mut values = Vec::with_capacity(BOOLEAN_ROUND_PRIVATE_COLUMNS);
            append_state_bits(&mut values, &output);
            append_parities(&mut values, &output);
            values.push(m31(u32::from(active)));
            values.push(m31(u32::from(actual_last)));
            values.push(m31(u32::from(active && !actual_last)));
            values.push(m31(u32::from(actual_last)));
            debug_assert_eq!(values.len(), BOOLEAN_ROUND_PRIVATE_COLUMNS);
            round_row(&values);

            if active {
                chained_state = output;
                if actual_last {
                    digest.copy_from_slice(&output[..64]);
                }
            }
        }
        let mut values = Vec::with_capacity(BOOLEAN_DIGEST_PRIVATE_COLUMNS);
        values.extend(digest.map(|value| m31(u32::from(value))));
        for value in digest {
            values.extend((0..8).map(|bit| m31(u32::from((value >> bit) & 1))));
        }
        debug_assert_eq!(values.len(), BOOLEAN_DIGEST_PRIVATE_COLUMNS);
        digest_row(&values);
    }
    Ok(BooleanSha3TraceReport {
        calls: calls.len(),
        permutations,
        round_rows: permutations
            .checked_mul(BOOLEAN_ROWS_PER_PERMUTATION)
            .ok_or(BooleanSha3TraceError::Overflow)?,
        absorb_rows: permutations,
        digest_rows: calls.len(),
    })
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::sha3_air::sha3_512_reference;

    #[test]
    fn boundary_lengths_stream_exact_digests_and_geometry() {
        let messages = [vec![], vec![1], vec![2; 71], vec![3; 72], vec![4; 73]];
        let calls = messages
            .iter()
            .map(|message| BooleanSha3Call {
                message,
                capacity: 73,
            })
            .collect::<Vec<_>>();
        let mut digest_rows = Vec::new();
        let report = for_each_boolean_sha3_trace_row(
            &calls,
            |_| {},
            |_| {},
            |row| digest_rows.push(row.to_vec()),
        )
        .unwrap();
        assert_eq!(report.permutations, 10);
        assert_eq!(report.round_rows, 250);
        for (message, row) in messages.iter().zip(digest_rows) {
            let expected = sha3_512_reference(message);
            assert_eq!(
                row[..64]
                    .iter()
                    .map(|value| value.as_u32())
                    .collect::<Vec<_>>(),
                expected.iter().copied().map(u32::from).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn over_capacity_and_empty_call_set_fail_closed() {
        assert_eq!(
            for_each_boolean_sha3_trace_row(&[], |_| {}, |_| {}, |_| {}),
            Err(BooleanSha3TraceError::Calls)
        );
        assert_eq!(
            for_each_boolean_sha3_trace_row(
                &[BooleanSha3Call {
                    message: b"AB",
                    capacity: 1,
                }],
                |_| {},
                |_| {},
                |_| {},
            ),
            Err(BooleanSha3TraceError::Capacity)
        );
    }
}
