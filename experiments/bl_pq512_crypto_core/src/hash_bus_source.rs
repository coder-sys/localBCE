//! Streaming SHA3 bus to selected B=16 GKR boundary conversion.

use crate::{
    fp16_relay_free_gkr_source::KECCAK_F_ZERO,
    hash_bus::{HashBusDescriptor, PACKED_SHARDS, PERMUTATIONS_PER_COPROCESSOR_SHARD},
    sha3_air::{Sha3TraceError, for_each_sha3_512_permutation_boundary},
};

pub const KECCAK_STATE_BITS: usize = 1_600;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HashBusMessage<'a> {
    pub message: &'a [u8],
    pub capacity: u64,
    pub digest: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashBusSourceError {
    Schedule,
    Capacity,
    Digest,
    Overflow,
    Sha3(Sha3TraceError),
}

impl From<Sha3TraceError> for HashBusSourceError {
    fn from(value: Sha3TraceError) -> Self {
        Self::Sha3(value)
    }
}

fn pack_state(destination: &mut [u16; KECCAK_STATE_BITS], packed_lane: usize, state: &[u64; 25]) {
    for (lane, value) in state.iter().copied().enumerate() {
        for bit in 0..64 {
            destination[64 * lane + bit] |= (((value >> bit) & 1) as u16) << packed_lane;
        }
    }
}

fn push_boundary<F>(
    permutation: &mut u64,
    input_patterns: &mut [u16; KECCAK_STATE_BITS],
    output_patterns: &mut [u16; KECCAK_STATE_BITS],
    input: &[u64; 25],
    output: &[u64; 25],
    sink: &mut F,
) -> Result<(), HashBusSourceError>
where
    F: FnMut(
        u16,
        u16,
        &[u16; KECCAK_STATE_BITS],
        &[u16; KECCAK_STATE_BITS],
    ) -> Result<(), HashBusSourceError>,
{
    let within_shard = *permutation % PERMUTATIONS_PER_COPROCESSOR_SHARD;
    let packed_lane = usize::try_from(within_shard % u64::from(PACKED_SHARDS))
        .map_err(|_| HashBusSourceError::Overflow)?;
    if packed_lane == 0 {
        input_patterns.fill(0);
        output_patterns.fill(0);
    }
    pack_state(input_patterns, packed_lane, input);
    pack_state(output_patterns, packed_lane, output);
    *permutation = permutation
        .checked_add(1)
        .ok_or(HashBusSourceError::Overflow)?;
    if packed_lane + 1 == usize::from(PACKED_SHARDS) {
        let completed = *permutation - 1;
        let coprocessor_shard = u16::try_from(completed / PERMUTATIONS_PER_COPROCESSOR_SHARD)
            .map_err(|_| HashBusSourceError::Overflow)?;
        let group = u16::try_from(
            (completed % PERMUTATIONS_PER_COPROCESSOR_SHARD) / u64::from(PACKED_SHARDS),
        )
        .map_err(|_| HashBusSourceError::Overflow)?;
        sink(coprocessor_shard, group, input_patterns, output_patterns)?;
    }
    Ok(())
}

/// Stream every live and authenticated dummy B=16 boundary group.
///
/// The callback receives `(coprocessor_shard, group, input_patterns,
/// output_patterns)`. Each pattern is one 16-bit packed wire. The omitted 448
/// padded circuit wires are fixed zero by the selected circuit definition.
pub fn for_each_hash_bus_b16_group<'a, I, F>(
    descriptor: &HashBusDescriptor,
    messages: I,
    mut sink: F,
) -> Result<(), HashBusSourceError>
where
    I: IntoIterator<Item = HashBusMessage<'a>>,
    F: FnMut(
        u16,
        u16,
        &[u16; KECCAK_STATE_BITS],
        &[u16; KECCAK_STATE_BITS],
    ) -> Result<(), HashBusSourceError>,
{
    let mut messages = messages.into_iter();
    let mut permutation = 0_u64;
    let mut input_patterns = [0_u16; KECCAK_STATE_BITS];
    let mut output_patterns = [0_u16; KECCAK_STATE_BITS];

    for run in &descriptor.runs {
        for _ in 0..run.count {
            let item = messages.next().ok_or(HashBusSourceError::Schedule)?;
            if item.capacity != run.capacity {
                return Err(HashBusSourceError::Capacity);
            }
            let mut push_error = None;
            let digest = for_each_sha3_512_permutation_boundary(
                item.message,
                usize::try_from(item.capacity).map_err(|_| HashBusSourceError::Overflow)?,
                |_, _, _, input, output| {
                    if push_error.is_none() {
                        push_error = push_boundary(
                            &mut permutation,
                            &mut input_patterns,
                            &mut output_patterns,
                            input,
                            output,
                            &mut sink,
                        )
                        .err();
                    }
                },
            )?;
            if let Some(error) = push_error {
                return Err(error);
            }
            if digest != item.digest {
                return Err(HashBusSourceError::Digest);
            }
        }
    }
    if messages.next().is_some() || permutation != descriptor.total_permutations {
        return Err(HashBusSourceError::Schedule);
    }

    let zero_input = [0_u64; 25];
    while permutation < descriptor.padded_permutations {
        push_boundary(
            &mut permutation,
            &mut input_patterns,
            &mut output_patterns,
            &zero_input,
            &KECCAK_F_ZERO,
            &mut sink,
        )?;
    }
    if permutation != descriptor.padded_permutations {
        return Err(HashBusSourceError::Schedule);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hash_bus::{build_hash_bus_descriptor, build_hash_bus_descriptor_with_state},
        wave1a_global_schedule::Profile,
    };
    use sha3::{Digest, Sha3_512};
    use std::vec;

    #[test]
    fn k128_and_k512_stream_exact_selected_groups_without_boundary_storage() {
        let empty_digest: [u8; 64] = Sha3_512::digest([]).into();
        for (profile, expected_shards, expected_groups) in [
            (Profile::K128Calibration, 1_u16, 8_192_u64),
            (Profile::K512Calibration, 4_u16, 32_768_u64),
        ] {
            let descriptor = build_hash_bus_descriptor(profile).unwrap();
            let messages = descriptor.runs.iter().flat_map(|run| {
                core::iter::repeat_n(
                    HashBusMessage {
                        message: &[],
                        capacity: run.capacity,
                        digest: empty_digest,
                    },
                    run.count as usize,
                )
            });
            let mut groups = 0_u64;
            let mut final_location = None;
            let mut final_input = [0_u16; KECCAK_STATE_BITS];
            let mut final_output = [0_u16; KECCAK_STATE_BITS];
            for_each_hash_bus_b16_group(&descriptor, messages, |shard, group, input, output| {
                groups += 1;
                final_location = Some((shard, group));
                final_input = *input;
                final_output = *output;
                Ok(())
            })
            .unwrap();
            assert_eq!(descriptor.coprocessor_shards, expected_shards);
            assert_eq!(groups, expected_groups);
            assert_eq!(
                final_location,
                Some((expected_shards - 1, (8_192 - 1) as u16))
            );
            assert_eq!(final_input, [0_u16; KECCAK_STATE_BITS]);
            for (wire, pattern) in final_output.iter().copied().enumerate() {
                let expected = (KECCAK_F_ZERO[wire / 64] >> (wire % 64)) & 1;
                assert_eq!(pattern, if expected == 0 { 0 } else { u16::MAX });
            }
        }
    }

    #[test]
    fn digest_and_sink_failures_propagate_without_panics() {
        let descriptor = build_hash_bus_descriptor(Profile::K128Calibration).unwrap();
        let first_capacity = descriptor.runs[0].capacity;
        assert_eq!(
            for_each_hash_bus_b16_group(
                &descriptor,
                [HashBusMessage {
                    message: &[],
                    capacity: first_capacity,
                    digest: [0_u8; 64],
                }],
                |_, _, _, _| Ok(()),
            ),
            Err(HashBusSourceError::Digest)
        );

        let empty_digest: [u8; 64] = Sha3_512::digest([]).into();
        let messages = descriptor.runs.iter().flat_map(|run| {
            core::iter::repeat_n(
                HashBusMessage {
                    message: &[],
                    capacity: run.capacity,
                    digest: empty_digest,
                },
                run.count as usize,
            )
        });
        assert_eq!(
            for_each_hash_bus_b16_group(&descriptor, messages, |_, _, _, _| {
                Err(HashBusSourceError::Overflow)
            }),
            Err(HashBusSourceError::Overflow)
        );
    }

    #[test]
    fn state_composed_stream_has_only_authenticated_dummy_groups_after_total() {
        let descriptor = build_hash_bus_descriptor_with_state(Profile::K128Calibration).unwrap();
        let empty_digest: [u8; 64] = Sha3_512::digest([]).into();
        let final_capacity = descriptor.runs.last().unwrap().capacity as usize;
        let final_message = vec![0x5a_u8; final_capacity];
        let final_digest: [u8; 64] = Sha3_512::digest(&final_message).into();
        let final_call = descriptor.total_calls - 1;
        let messages = descriptor
            .runs
            .iter()
            .flat_map(|run| core::iter::repeat_n(run.capacity, run.count as usize))
            .enumerate()
            .map(|(index, capacity)| HashBusMessage {
                message: if index as u64 == final_call {
                    &final_message
                } else {
                    &[]
                },
                capacity,
                digest: if index as u64 == final_call {
                    final_digest
                } else {
                    empty_digest
                },
            });
        let first_dummy_group = descriptor
            .total_permutations
            .div_ceil(u64::from(PACKED_SHARDS));
        for_each_hash_bus_b16_group(&descriptor, messages, |_, group, input, output| {
            if u64::from(group) >= first_dummy_group {
                assert_eq!(input, &[0_u16; KECCAK_STATE_BITS]);
                for (wire, pattern) in output.iter().copied().enumerate() {
                    let bit = (KECCAK_F_ZERO[wire / 64] >> (wire % 64)) & 1;
                    assert_eq!(pattern, if bit == 0 { 0 } else { u16::MAX });
                }
            }
            Ok(())
        })
        .unwrap();
    }
}
