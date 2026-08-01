//! Data-parallel bit-sliced Keccak-f[1600] witness kernel.
//!
//! This module is the bounded H1 execution substrate. It stores one bit-plane
//! across many independent permutations per machine word, emits round
//! boundaries through a callback, and never constructs a per-gate graph.

use core::fmt;

use alloc::vec;

use crate::sha3_air::{KECCAK_ROUNDS, ROTATION_OFFSETS, ROUND_CONSTANTS};

const STATE_BITS: usize = 1_600;
const THETA_BITS: usize = 320;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BitSlicedKeccakReport {
    pub instances: usize,
    pub machine_words_per_plane: usize,
    pub round_count: usize,
    pub working_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BitSlicedKeccakError {
    Empty,
    Shape,
    Round,
    Overflow,
}

impl fmt::Display for BitSlicedKeccakError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "bit-sliced Keccak error: {self:?}")
    }
}

impl core::error::Error for BitSlicedKeccakError {}

fn plane(x: usize, y: usize, z: usize, words: usize) -> usize {
    (64 * (x + 5 * y) + z) * words
}

fn theta_plane(x: usize, z: usize, words: usize) -> usize {
    (64 * x + z) * words
}

fn active_word_mask(word: usize, words: usize, instances: usize) -> u64 {
    if word + 1 < words || instances.is_multiple_of(64) {
        u64::MAX
    } else {
        (1_u64 << (instances % 64)) - 1
    }
}

/// Execute every permutation in lockstep and expose each completed round.
///
/// The callback receives the zero-based round index and the complete
/// bit-sliced state. Its slice is valid only for the duration of the call.
pub fn execute_bit_sliced_keccak_f1600(
    states: &mut [[u64; 25]],
    mut round_boundary: impl FnMut(usize, &[u64]),
) -> Result<BitSlicedKeccakReport, BitSlicedKeccakError> {
    if states.is_empty() {
        return Err(BitSlicedKeccakError::Empty);
    }
    let instances = states.len();
    let words = instances.div_ceil(64);
    let state_words = STATE_BITS
        .checked_mul(words)
        .ok_or(BitSlicedKeccakError::Overflow)?;
    let theta_words = THETA_BITS
        .checked_mul(words)
        .ok_or(BitSlicedKeccakError::Overflow)?;
    let mut state = vec![0_u64; state_words];
    let mut permuted = vec![0_u64; state_words];
    let mut theta = vec![0_u64; theta_words];

    for (instance, lanes) in states.iter().enumerate() {
        let word = instance / 64;
        let bit = instance % 64;
        for (lane, value) in lanes.iter().copied().enumerate() {
            for z in 0..64 {
                state[(64 * lane + z) * words + word] |= ((value >> z) & 1) << bit;
            }
        }
    }

    for (round, round_constant) in ROUND_CONSTANTS.iter().copied().enumerate() {
        for x in 0..5 {
            for z in 0..64 {
                for word in 0..words {
                    theta[theta_plane(x, z, words) + word] = (0..5).fold(0_u64, |value, y| {
                        value ^ state[plane(x, y, z, words) + word]
                    });
                }
            }
        }
        for x in 0..5 {
            for y in 0..5 {
                for z in 0..64 {
                    for word in 0..words {
                        let delta = theta[theta_plane((x + 4) % 5, z, words) + word]
                            ^ theta[theta_plane((x + 1) % 5, (z + 63) % 64, words) + word];
                        state[plane(x, y, z, words) + word] ^= delta;
                    }
                }
            }
        }
        permuted.fill(0);
        for (x, rotations) in ROTATION_OFFSETS.iter().enumerate() {
            for (y, rotation) in rotations.iter().copied().enumerate() {
                let destination_x = y;
                let destination_y = (2 * x + 3 * y) % 5;
                let rotation = rotation as usize;
                for z in 0..64 {
                    let destination_z = (z + rotation) % 64;
                    let source = plane(x, y, z, words);
                    let destination = plane(destination_x, destination_y, destination_z, words);
                    permuted[destination..destination + words]
                        .copy_from_slice(&state[source..source + words]);
                }
            }
        }
        for x in 0..5 {
            for y in 0..5 {
                for z in 0..64 {
                    for word in 0..words {
                        state[plane(x, y, z, words) + word] = permuted
                            [plane(x, y, z, words) + word]
                            ^ ((!permuted[plane((x + 1) % 5, y, z, words) + word])
                                & permuted[plane((x + 2) % 5, y, z, words) + word]);
                    }
                }
            }
        }
        for z in 0..64 {
            if (round_constant >> z) & 1 == 1 {
                for word in 0..words {
                    state[plane(0, 0, z, words) + word] ^= active_word_mask(word, words, instances);
                }
            }
        }
        round_boundary(round, &state);
    }

    for (instance, lanes) in states.iter_mut().enumerate() {
        let word = instance / 64;
        let bit = instance % 64;
        for (lane, value) in lanes.iter_mut().enumerate() {
            *value = (0..64).fold(0_u64, |value, z| {
                value | (((state[(64 * lane + z) * words + word] >> bit) & 1) << z)
            });
        }
    }
    let working_words = state_words
        .checked_mul(2)
        .and_then(|value| value.checked_add(theta_words))
        .ok_or(BitSlicedKeccakError::Overflow)?;
    Ok(BitSlicedKeccakReport {
        instances,
        machine_words_per_plane: words,
        round_count: usize::from(KECCAK_ROUNDS),
        working_bytes: working_words
            .checked_mul(core::mem::size_of::<u64>())
            .ok_or(BitSlicedKeccakError::Overflow)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha3_air::keccak_f1600_round;
    use alloc::vec::Vec;

    fn states(count: usize) -> Vec<[u64; 25]> {
        (0..count)
            .map(|instance| {
                core::array::from_fn(|lane| {
                    (instance as u64 + 1)
                        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                        .rotate_left(lane as u32)
                        ^ lane as u64
                })
            })
            .collect()
    }

    #[test]
    fn every_round_matches_the_scalar_permutation_across_word_boundaries() {
        for count in [1, 2, 63, 64, 65, 129] {
            let mut observed = states(count);
            let mut expected = observed.clone();
            let report = execute_bit_sliced_keccak_f1600(&mut observed, |round, _| {
                for state in &mut expected {
                    keccak_f1600_round(state, round).unwrap();
                }
            })
            .unwrap();
            assert_eq!(observed, expected);
            assert_eq!(report.instances, count);
            assert_eq!(report.machine_words_per_plane, count.div_ceil(64));
            assert_eq!(report.round_count, 24);
            assert_eq!(
                report.working_bytes,
                (2 * STATE_BITS + THETA_BITS) * count.div_ceil(64) * 8
            );
        }
    }

    #[test]
    fn empty_batch_fails_closed() {
        assert_eq!(
            execute_bit_sliced_keccak_f1600(&mut [], |_, _| {}),
            Err(BitSlicedKeccakError::Empty)
        );
    }
}
