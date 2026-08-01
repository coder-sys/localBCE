//! Byte-oriented low-degree SHA3-512 AIR shape and permutation KAT.
//!
//! This independently mirrors the Python reference's fixed shape and executes
//! Keccak-f[1600] without calling the `sha3` digest implementation. It is not
//! an interaction trace, prover integration, or activation claim.

use alloc::vec::Vec;

use sha3::{Digest, Sha3_512};

/// Exact shape-commitment domain.
pub const SHA3_BYTE_AIR_DOMAIN: &[u8] = b"BL/PQ512/WAVE1B/SHA3-512-BYTE-AIR/v1";
/// Keccak state size in bytes.
pub const STATE_BYTES: u16 = 200;
/// SHA3-512 sponge rate in bytes.
pub const RATE_BYTES: u16 = 72;
/// SHA3-512 sponge capacity in bytes.
pub const CAPACITY_BYTES: u16 = 128;
/// Keccak-f[1600] round count.
pub const KECCAK_ROUNDS: u16 = 24;
/// Base columns in the Keccak round core.
pub const CORE_ROUND_BASE_COLUMNS: u32 = 1_632;
/// Private block-byte columns carried by the sponge trace.
pub const SPONGE_BLOCK_COLUMNS: u32 = 72;
/// Full sponge trace width.
pub const TRACE_BASE_COLUMNS: u32 = CORE_ROUND_BASE_COLUMNS + SPONGE_BLOCK_COLUMNS;
/// Fixed-table lookup messages in the Keccak round core.
pub const CORE_ROUND_LOOKUP_MESSAGES: u32 = 1_024;
/// Additional absorb-XOR lookups on the first round of each block.
pub const ABSORB_XOR_LOOKUPS: u32 = 72;
/// Maximum lookup messages on a trace row.
pub const FIRST_ROUND_LOOKUP_MESSAGES: u32 = CORE_ROUND_LOOKUP_MESSAGES + ABSORB_XOR_LOOKUPS;
/// XOR8 lookups per round.
pub const ROUND_XOR_LOOKUPS: u32 = 608;
/// AND_NOT8 lookups per round.
pub const ROUND_AND_NOT_LOOKUPS: u32 = 200;
/// SPLIT8 lookups per round.
pub const ROUND_SPLIT_LOOKUPS: u32 = 216;
/// Direct maximum constraint degree.
pub const DIRECT_MAXIMUM_DEGREE: u16 = 2;
/// Conservative lookup-composed maximum degree.
pub const COMPOSED_MAXIMUM_DEGREE: u16 = 3;
/// Cross-language commitment domain for complete fixed-capacity trace rows.
pub const SHA3_TRACE_ROWS_DOMAIN: &[u8] = b"BL/PQ512/WAVE1A/SHA3-512-TRACE-ROWS/v1";

pub(crate) const ROTATION_OFFSETS: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];
pub(crate) const ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Compute the exact cross-language shape commitment.
pub fn shape_commitment() -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(SHA3_BYTE_AIR_DOMAIN);
    hash.update(STATE_BYTES.to_be_bytes());
    hash.update(RATE_BYTES.to_be_bytes());
    hash.update(CAPACITY_BYTES.to_be_bytes());
    hash.update(KECCAK_ROUNDS.to_be_bytes());
    hash.update(CORE_ROUND_BASE_COLUMNS.to_be_bytes());
    hash.update(SPONGE_BLOCK_COLUMNS.to_be_bytes());
    hash.update(TRACE_BASE_COLUMNS.to_be_bytes());
    hash.update(CORE_ROUND_LOOKUP_MESSAGES.to_be_bytes());
    hash.update(ABSORB_XOR_LOOKUPS.to_be_bytes());
    hash.update(FIRST_ROUND_LOOKUP_MESSAGES.to_be_bytes());
    hash.update(ROUND_XOR_LOOKUPS.to_be_bytes());
    hash.update(ROUND_AND_NOT_LOOKUPS.to_be_bytes());
    hash.update(ROUND_SPLIT_LOOKUPS.to_be_bytes());
    hash.update(DIRECT_MAXIMUM_DEGREE.to_be_bytes());
    hash.update(COMPOSED_MAXIMUM_DEGREE.to_be_bytes());
    hash.update([0_u8, 0_u8]);
    for constant in ROUND_CONSTANTS {
        hash.update(constant.to_be_bytes());
    }
    for row in ROTATION_OFFSETS {
        hash.update(row.map(|value| value as u8));
    }
    hash.finalize().into()
}

/// Apply Keccak-f[1600] to 25 little-endian lanes.
fn keccak_f1600_round_constant(state: &mut [u64; 25], round_constant: u64) {
    let mut parity = [0_u64; 5];
    for x in 0..5 {
        parity[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    let mut delta = [0_u64; 5];
    for x in 0..5 {
        delta[x] = parity[(x + 4) % 5] ^ parity[(x + 1) % 5].rotate_left(1);
    }
    for x in 0..5 {
        for y in 0..5 {
            state[x + 5 * y] ^= delta[x];
        }
    }

    let mut rotated = [0_u64; 25];
    for x in 0..5 {
        for y in 0..5 {
            rotated[y + 5 * ((2 * x + 3 * y) % 5)] =
                state[x + 5 * y].rotate_left(ROTATION_OFFSETS[x][y]);
        }
    }
    for x in 0..5 {
        for y in 0..5 {
            state[x + 5 * y] = rotated[x + 5 * y]
                ^ ((!rotated[(x + 1) % 5 + 5 * y]) & rotated[(x + 2) % 5 + 5 * y]);
        }
    }
    state[0] ^= round_constant;
}

pub fn keccak_f1600(state: &mut [u64; 25]) {
    for round_constant in ROUND_CONSTANTS {
        keccak_f1600_round_constant(state, round_constant);
    }
}

/// Apply exactly one indexed Keccak-f[1600] round.
pub fn keccak_f1600_round(state: &mut [u64; 25], round_index: usize) -> Result<(), Sha3TraceError> {
    let round_constant = *ROUND_CONSTANTS
        .get(round_index)
        .ok_or(Sha3TraceError::RoundIndexInvalid)?;
    keccak_f1600_round_constant(state, round_constant);
    Ok(())
}

/// Execute the frozen SHA3-512 sponge reference.
pub fn sha3_512_reference(message: &[u8]) -> [u8; 64] {
    let block_count = (message.len() + 1).div_ceil(RATE_BYTES as usize);
    let mut padded = Vec::with_capacity(block_count * RATE_BYTES as usize);
    padded.extend_from_slice(message);
    padded.push(0x06);
    padded.resize(block_count * RATE_BYTES as usize, 0);
    let last = padded.last_mut().expect("SHA3 padding always has one byte");
    *last ^= 0x80;

    let mut state = [0_u64; 25];
    for block in padded.chunks_exact(RATE_BYTES as usize) {
        for (index, byte) in block.iter().enumerate() {
            state[index / 8] ^= u64::from(*byte) << (8 * (index % 8));
        }
        keccak_f1600(&mut state);
    }

    let mut digest = [0_u8; 64];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = (state[index / 8] >> (8 * (index % 8))) as u8;
    }
    digest
}

/// Stream only fixed-capacity permutation boundaries for the GKR lane.
///
/// Inactive capacity blocks execute the same all-zero Keccak permutation as
/// the full AIR trace. The sink therefore receives exactly
/// `capacity / RATE_BYTES + 1` input/output pairs without round witnesses.
pub fn for_each_sha3_512_permutation_boundary<F>(
    message: &[u8],
    capacity: usize,
    mut sink: F,
) -> Result<[u8; 64], Sha3TraceError>
where
    F: FnMut(usize, bool, bool, &[u64; 25], &[u64; 25]),
{
    if message.len() > capacity {
        return Err(Sha3TraceError::MessageExceedsCapacity);
    }
    let active_blocks = (message.len() + RATE_BYTES as usize) / RATE_BYTES as usize;
    let block_capacity = capacity / RATE_BYTES as usize + 1;
    let mut carried_state = [0_u64; 25];
    let mut digest_state = [0_u64; 25];

    for block_index in 0..block_capacity {
        let active = block_index < active_blocks;
        let actual_last = block_index + 1 == active_blocks;
        let mut input = if active { carried_state } else { [0_u64; 25] };
        if active {
            let start = block_index * RATE_BYTES as usize;
            let stop = core::cmp::min(start + RATE_BYTES as usize, message.len());
            for (position, byte) in message[start..stop].iter().copied().enumerate() {
                input[position / 8] ^= u64::from(byte) << (8 * (position % 8));
            }
            if message.len() >= start && message.len() < start + RATE_BYTES as usize {
                let position = message.len() - start;
                input[position / 8] ^= 0x06_u64 << (8 * (position % 8));
                let last = RATE_BYTES as usize - 1;
                input[last / 8] ^= 0x80_u64 << (8 * (last % 8));
            }
        }
        let mut output = input;
        keccak_f1600(&mut output);
        sink(block_index, active, actual_last, &input, &output);
        if active {
            carried_state = output;
            if actual_last {
                digest_state = output;
            }
        }
    }

    let mut digest = [0_u8; 64];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = (digest_state[index / 8] >> (8 * (index % 8))) as u8;
    }
    Ok(digest)
}

/// One complete byte-oriented Keccak round witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeccakRoundWitness {
    /// Input state after any block absorption.
    pub state_bytes: [u8; 200],
    /// Four chained XOR outputs for each of 40 theta parity bytes.
    pub theta_parity_steps: [u8; 160],
    /// Five theta-D lanes.
    pub theta_d: [u8; 40],
    /// State after theta.
    pub theta_state: [u8; 200],
    /// Low/high outputs for all 216 non-byte-aligned rotations.
    pub rotation_splits: [[u8; 2]; 216],
    /// Chi AND-NOT outputs.
    pub chi_and_not: [u8; 200],
    /// Chi XOR outputs before iota.
    pub chi_raw: [u8; 200],
    /// Round output after iota.
    pub output_bytes: [u8; 200],
}

/// Fixed-capacity trace construction error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Sha3TraceError {
    /// The message is longer than the declared capacity.
    MessageExceedsCapacity,
    /// A round index is outside `0..24`.
    RoundIndexInvalid,
    /// The frozen 216-row split inventory did not reconcile.
    SplitInventoryMismatch,
}

fn lane_offset(x: usize, y: usize) -> usize {
    8 * (x + 5 * y)
}

fn lane(state: &[u8; 200], x: usize, y: usize) -> [u8; 8] {
    let offset = lane_offset(x, y);
    let mut result = [0_u8; 8];
    result.copy_from_slice(&state[offset..offset + 8]);
    result
}

fn store_lane(state: &mut [u8; 200], x: usize, y: usize, value: [u8; 8]) {
    let offset = lane_offset(x, y);
    state[offset..offset + 8].copy_from_slice(&value);
}

fn rotate_lane_bytes(
    source: [u8; 8],
    rotation: u32,
    splits: &mut [[u8; 2]; 216],
    split_cursor: &mut usize,
) -> [u8; 8] {
    let byte_shift = (rotation / 8) as usize;
    let bit_shift = (rotation % 8) as usize;
    let mut rotated = [0_u8; 8];
    if bit_shift == 0 {
        for (destination, output) in rotated.iter_mut().enumerate() {
            *output = source[(destination + 8 - byte_shift) % 8];
        }
        return rotated;
    }

    let start = *split_cursor;
    let low_width = 8 - bit_shift;
    let low_mask = ((1_u16 << low_width) - 1) as u8;
    for value in source {
        splits[*split_cursor] = [value & low_mask, value >> low_width];
        *split_cursor += 1;
    }
    for (destination, output) in rotated.iter_mut().enumerate() {
        let source_index = (destination + 8 - byte_shift) % 8;
        let previous_index = (source_index + 7) % 8;
        *output =
            (splits[start + source_index][0] << bit_shift) + splits[start + previous_index][1];
    }
    rotated
}

/// Construct every frozen witness column for one Keccak round.
pub fn build_round_witness(
    state_bytes: [u8; 200],
    round_index: usize,
) -> Result<KeccakRoundWitness, Sha3TraceError> {
    if round_index >= KECCAK_ROUNDS as usize {
        return Err(Sha3TraceError::RoundIndexInvalid);
    }

    let mut parity_steps = [0_u8; 160];
    let mut c_lanes = [[0_u8; 8]; 5];
    let mut parity_cursor = 0;
    for (x, c_lane) in c_lanes.iter_mut().enumerate() {
        for byte_index in 0..8 {
            let mut accumulator = state_bytes[lane_offset(x, 0) + byte_index];
            for y in 1..5 {
                accumulator ^= state_bytes[lane_offset(x, y) + byte_index];
                parity_steps[parity_cursor] = accumulator;
                parity_cursor += 1;
            }
            c_lane[byte_index] = accumulator;
        }
    }

    let mut rotation_splits = [[0_u8; 2]; 216];
    let mut split_cursor = 0;
    let mut rotated_c = [[0_u8; 8]; 5];
    for x in 0..5 {
        rotated_c[x] = rotate_lane_bytes(c_lanes[x], 1, &mut rotation_splits, &mut split_cursor);
    }

    let mut d_lanes = [[0_u8; 8]; 5];
    for x in 0..5 {
        for byte_index in 0..8 {
            d_lanes[x][byte_index] =
                c_lanes[(x + 4) % 5][byte_index] ^ rotated_c[(x + 1) % 5][byte_index];
        }
    }
    let mut theta_d = [0_u8; 40];
    for x in 0..5 {
        theta_d[x * 8..(x + 1) * 8].copy_from_slice(&d_lanes[x]);
    }

    let mut theta_state = [0_u8; 200];
    for (x, d_lane) in d_lanes.iter().enumerate() {
        for y in 0..5 {
            let mut output = lane(&state_bytes, x, y);
            for byte_index in 0..8 {
                output[byte_index] ^= d_lane[byte_index];
            }
            store_lane(&mut theta_state, x, y, output);
        }
    }

    let mut b_state = [0_u8; 200];
    for (x, rotations) in ROTATION_OFFSETS.iter().enumerate() {
        for (y, rotation) in rotations.iter().enumerate() {
            let rotated = rotate_lane_bytes(
                lane(&theta_state, x, y),
                *rotation,
                &mut rotation_splits,
                &mut split_cursor,
            );
            store_lane(&mut b_state, y, (2 * x + 3 * y) % 5, rotated);
        }
    }
    if split_cursor != ROUND_SPLIT_LOOKUPS as usize {
        return Err(Sha3TraceError::SplitInventoryMismatch);
    }

    let mut chi_and_not = [0_u8; 200];
    let mut chi_raw = [0_u8; 200];
    for x in 0..5 {
        for y in 0..5 {
            let current = lane(&b_state, x, y);
            let next = lane(&b_state, (x + 1) % 5, y);
            let next_next = lane(&b_state, (x + 2) % 5, y);
            let mut and_lane = [0_u8; 8];
            let mut raw_lane = [0_u8; 8];
            for byte_index in 0..8 {
                and_lane[byte_index] = (!next[byte_index]) & next_next[byte_index];
                raw_lane[byte_index] = current[byte_index] ^ and_lane[byte_index];
            }
            store_lane(&mut chi_and_not, x, y, and_lane);
            store_lane(&mut chi_raw, x, y, raw_lane);
        }
    }

    let mut output_bytes = chi_raw;
    let constant = ROUND_CONSTANTS[round_index].to_le_bytes();
    for byte_index in 0..8 {
        output_bytes[byte_index] ^= constant[byte_index];
    }
    Ok(KeccakRoundWitness {
        state_bytes,
        theta_parity_steps: parity_steps,
        theta_d,
        theta_state,
        rotation_splits,
        chi_and_not,
        chi_raw,
        output_bytes,
    })
}

/// Stream every fixed-capacity SHA3 trace row without retaining the full trace.
pub fn for_each_sha3_512_trace_row<F>(
    message: &[u8],
    capacity: usize,
    mut sink: F,
) -> Result<[u8; 64], Sha3TraceError>
where
    F: FnMut(usize, usize, bool, bool, &[u8; 72], &KeccakRoundWitness),
{
    if message.len() > capacity {
        return Err(Sha3TraceError::MessageExceedsCapacity);
    }
    let active_blocks = (message.len() + RATE_BYTES as usize) / RATE_BYTES as usize;
    let block_capacity = capacity / RATE_BYTES as usize + 1;
    let mut carried_state = [0_u8; 200];
    let mut digest_state = [0_u8; 200];

    for block_index in 0..block_capacity {
        let active = block_index < active_blocks;
        let actual_last = block_index + 1 == active_blocks;
        let mut block = [0_u8; 72];
        let mut state = if active { carried_state } else { [0_u8; 200] };
        if active {
            let start = block_index * RATE_BYTES as usize;
            let stop = core::cmp::min(start + RATE_BYTES as usize, message.len());
            if start < stop {
                block[..stop - start].copy_from_slice(&message[start..stop]);
            }
            if message.len() >= start && message.len() < start + RATE_BYTES as usize {
                block[message.len() - start] ^= 0x06;
                block[RATE_BYTES as usize - 1] ^= 0x80;
            }
            for byte_index in 0..RATE_BYTES as usize {
                state[byte_index] ^= block[byte_index];
            }
        }
        for round_index in 0..KECCAK_ROUNDS as usize {
            let witness = build_round_witness(state, round_index)?;
            sink(
                block_index,
                round_index,
                active,
                actual_last,
                &block,
                &witness,
            );
            state = witness.output_bytes;
        }
        if active {
            carried_state = state;
            if actual_last {
                digest_state = state;
            }
        }
    }

    let mut digest = [0_u8; 64];
    digest.copy_from_slice(&digest_state[..64]);
    Ok(digest)
}

/// Commit every streamed trace cell in a canonical cross-language order.
pub fn sha3_512_trace_commitment(
    message: &[u8],
    capacity: usize,
) -> Result<[u8; 64], Sha3TraceError> {
    let mut hash = Sha3_512::new();
    hash.update(SHA3_TRACE_ROWS_DOMAIN);
    hash.update((capacity as u64).to_be_bytes());
    hash.update((message.len() as u64).to_be_bytes());
    hash.update((((capacity / RATE_BYTES as usize) + 1) as u64).to_be_bytes());
    let digest = for_each_sha3_512_trace_row(
        message,
        capacity,
        |block_index, round_index, active, actual_last, block, witness| {
            hash.update((block_index as u32).to_be_bytes());
            hash.update([round_index as u8, u8::from(active), u8::from(actual_last)]);
            if round_index == 0 {
                hash.update(block);
            } else {
                hash.update([0_u8; 72]);
            }
            hash.update(witness.state_bytes);
            hash.update(witness.theta_parity_steps);
            hash.update(witness.theta_d);
            hash.update(witness.theta_state);
            for split in witness.rotation_splits {
                hash.update(split);
            }
            hash.update(witness.chi_and_not);
            hash.update(witness.chi_raw);
            hash.update(witness.output_bytes);
        },
    )?;
    hash.update(digest);
    Ok(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_shape_commitment_matches() {
        assert_eq!(
            shape_commitment(),
            hex64(
                "824d0d5adb44dc5a7f61960f7ad61ccb5a34aff177a51616afd0de6b49bbb4ad\
                 ea54e216cb0d0ea5bbe59f4818468e6bc3deafec21bdeddb4db797d899784e1c"
            )
        );
    }

    #[test]
    fn fips_202_empty_and_abc_kats_match() {
        assert_eq!(
            sha3_512_reference(b""),
            hex64(
                "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6\
                 15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
            )
        );
        assert_eq!(
            sha3_512_reference(b"abc"),
            hex64(
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
                 10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
            )
        );
    }

    #[test]
    fn padding_boundaries_match_the_sha3_crate() {
        for length in [0_usize, 1, 71, 72, 73, 143, 144, 1024] {
            let message: Vec<u8> = (0..length).map(|index| index as u8).collect();
            let expected: [u8; 64] = Sha3_512::digest(&message).into();
            assert_eq!(sha3_512_reference(&message), expected);
        }
    }

    #[test]
    fn streamed_fixed_capacity_trace_matches_digest_and_shape() {
        for (message, capacity) in [
            (b"".as_slice(), 71_usize),
            (b"abc".as_slice(), 71_usize),
            (b"Blind Ledger fixed trace".as_slice(), 143_usize),
        ] {
            let mut rows = 0_usize;
            let digest =
                for_each_sha3_512_trace_row(message, capacity, |_, _, _, _, _, witness| {
                    rows += 1;
                    assert_eq!(witness.rotation_splits.len(), 216);
                })
                .unwrap();
            assert_eq!(digest, sha3_512_reference(message));
            assert_eq!(rows, (capacity / RATE_BYTES as usize + 1) * 24);
        }
    }

    #[test]
    fn gkr_boundaries_match_the_full_fixed_capacity_trace() {
        let multi_block = b"exact-rate-block".repeat(6);
        for (message, capacity) in [
            (&b""[..], 0),
            (&b"abc"[..], 71),
            (multi_block.as_slice(), 144),
        ] {
            let mut compact = Vec::new();
            let compact_digest = for_each_sha3_512_permutation_boundary(
                message,
                capacity,
                |_, active, last, input, output| {
                    compact.push((active, last, *input, *output));
                },
            )
            .unwrap();
            let mut full = Vec::new();
            let full_digest = for_each_sha3_512_trace_row(
                message,
                capacity,
                |block, round, active, last, _, witness| {
                    if round == 0 {
                        full.push((active, last, witness.state_bytes));
                    }
                    if round == KECCAK_ROUNDS as usize - 1 {
                        assert_eq!(block + 1, full.len());
                        let compact_output = compact[block].3;
                        for (index, byte) in witness.output_bytes.iter().copied().enumerate() {
                            assert_eq!(
                                byte,
                                (compact_output[index / 8] >> (8 * (index % 8))) as u8
                            );
                        }
                    }
                },
            )
            .unwrap();
            assert_eq!(compact_digest, full_digest);
            assert_eq!(compact_digest, sha3_512_reference(message));
            assert_eq!(compact.len(), full.len());
            for ((compact_active, compact_last, input, _), (active, last, bytes)) in
                compact.iter().zip(full)
            {
                assert_eq!((*compact_active, *compact_last), (active, last));
                for (index, byte) in bytes.iter().copied().enumerate() {
                    assert_eq!(byte, (input[index / 8] >> (8 * (index % 8))) as u8);
                }
            }
        }
    }

    #[test]
    fn streamed_trace_rejects_message_over_capacity() {
        assert_eq!(
            for_each_sha3_512_trace_row(b"too long", 7, |_, _, _, _, _, _| {}),
            Err(Sha3TraceError::MessageExceedsCapacity)
        );
    }

    #[test]
    fn streamed_trace_commitment_matches_python() {
        assert_eq!(
            sha3_512_trace_commitment(b"abc", 71).unwrap(),
            hex64(
                "227da2c01e98a51402e53ceef7feb77015e2ba714b7fb465400a6af69b601ff4\
                 f2f1a4c0a7de504063bb38ce99e7d1b05ae43f44e66afe410909c699921114d8"
            )
        );
    }

    fn hex64(value: &str) -> [u8; 64] {
        let compact = value.replace([' ', '\n', '\r'], "");
        assert_eq!(compact.len(), 128);
        let mut decoded = [0_u8; 64];
        for (index, byte) in decoded.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16).unwrap();
        }
        decoded
    }
}
