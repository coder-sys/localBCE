//! Verifier-derived fixed-shape SHA3-512 bus geometry.

use core::fmt;

use alloc::vec::Vec;
use sha3::{Digest, Sha3_512};

use crate::ordered_map_schedule::{OrderedMapScheduleError, build_ordered_map_batch_schedule};
use crate::sha3_air::RATE_BYTES;
use crate::wave1a_global_schedule::Profile;

pub const CAPACITY_SCHEDULE_DOMAIN: &[u8] = b"BL/PQ512/WAVE1A/GLOBAL-SHA3-CAPACITY-SCHEDULE/v1\0";
pub const HASH_BUS_DESCRIPTOR_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/HASH-BUS-DESCRIPTOR/v2\0";
pub const HASH_BUS_DESCRIPTOR_VERSION: u16 = 2;
pub const KECCAK_STATE_BITS: u16 = 1_600;
pub const KECCAK_ROUNDS: u16 = 24;
pub const PACKED_SHARDS: u16 = 16;
pub const GROUP_COUNT: u64 = 8_192;
pub const PERMUTATIONS_PER_COPROCESSOR_SHARD: u64 = GROUP_COUNT * PACKED_SHARDS as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HashBusCapacityRun {
    pub component: &'static str,
    pub label: &'static str,
    pub capacity: u64,
    pub count: u64,
}

impl HashBusCapacityRun {
    pub fn permutations(self) -> Result<u64, HashBusError> {
        self.capacity
            .checked_div(u64::from(RATE_BYTES))
            .and_then(|blocks| blocks.checked_add(1))
            .and_then(|blocks| blocks.checked_mul(self.count))
            .ok_or(HashBusError::Overflow)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HashBusDescriptor {
    pub profile: Profile,
    pub runs: Vec<HashBusCapacityRun>,
    pub total_calls: u64,
    pub total_permutations: u64,
    pub coprocessor_shards: u16,
    pub padded_permutations: u64,
    pub capacity_schedule_commitment: [u8; 64],
    pub descriptor_commitment: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HashBusPermutationSlot {
    pub call_index: u64,
    pub run_index: u16,
    pub block_index: u16,
    pub blocks_in_call: u16,
    pub capacity: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashBusError {
    Overflow,
    Encoding,
    OrderedMap(OrderedMapScheduleError),
}

impl From<OrderedMapScheduleError> for HashBusError {
    fn from(value: OrderedMapScheduleError) -> Self {
        Self::OrderedMap(value)
    }
}

impl fmt::Display for HashBusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "hash bus error: {self:?}")
    }
}

impl core::error::Error for HashBusError {}

fn push(
    runs: &mut Vec<HashBusCapacityRun>,
    component: &'static str,
    label: &'static str,
    capacity: u64,
    count: u64,
) -> Result<(), HashBusError> {
    if component.is_empty() || label.is_empty() || count == 0 {
        return Err(HashBusError::Encoding);
    }
    runs.push(HashBusCapacityRun {
        component,
        label,
        capacity,
        count,
    });
    Ok(())
}

fn push_map_runs(
    runs: &mut Vec<HashBusCapacityRun>,
    component: &'static str,
    prefix: &'static str,
    operations: u64,
) -> Result<(), HashBusError> {
    let schedule = build_ordered_map_batch_schedule(operations, 24)?;
    let labels = match prefix {
        "replay" => ("replay_leaf", "replay_node", "replay_header"),
        "benefit" => ("benefit_leaf", "benefit_node", "benefit_header"),
        "obligation" => ("obligation_leaf", "obligation_node", "obligation_header"),
        "ledger" => ("ledger_leaf", "ledger_node", "ledger_header"),
        _ => return Err(HashBusError::Encoding),
    };
    push(runs, component, labels.0, 212, schedule.leaf_hash_rows)?;
    push(runs, component, labels.1, 141, schedule.node_hash_rows)?;
    push(runs, component, labels.2, 84, schedule.header_hash_rows)
}

fn profile_id(profile: Profile) -> &'static str {
    match profile {
        Profile::K128Calibration => "K128_CALIBRATION",
        Profile::K256DesignPoint => "K256_DESIGN_POINT",
        Profile::K512Calibration => "K512_CALIBRATION",
    }
}

pub fn build_hash_bus_descriptor(profile: Profile) -> Result<HashBusDescriptor, HashBusError> {
    let k = profile.claim_slots();
    let mut runs = Vec::with_capacity(31);
    push(&mut runs, "claim_truth", "source_leaf", 5_648, k)?;
    push(&mut runs, "claim_truth", "source_node", 140, k - 1)?;
    push(&mut runs, "claim_truth", "source_root", 76, 1)?;
    push(&mut runs, "claim_truth", "oracle_leaf", 2_133, k)?;
    push(&mut runs, "claim_truth", "oracle_root", 11 + 64 * k, 1)?;
    push(&mut runs, "claim_truth", "policy_leaf", 914, k)?;
    push(&mut runs, "claim_truth", "policy_root", 11 + 64 * k, 1)?;
    push(&mut runs, "claim_truth", "ruleset", 1_097, 1)?;
    push(&mut runs, "claim_truth", "authority", 538, 1)?;
    push(&mut runs, "a12_nullifier", "nullifier", 254, k)?;
    push(&mut runs, "a12_nullifier", "pepper", 76, 1)?;
    push(&mut runs, "salt_use", "salt_use", 78, 1)?;
    push_map_runs(&mut runs, "replay_map", "replay", k + 1)?;
    push_map_runs(&mut runs, "payment", "benefit", k)?;
    push_map_runs(&mut runs, "payment", "obligation", k)?;
    push_map_runs(&mut runs, "payment", "ledger", 2 * k)?;
    push(&mut runs, "payment", "key", 169, 4 * k)?;
    push(&mut runs, "payment", "operation", 816, k)?;
    push(&mut runs, "payment", "operation_log", 167, k)?;
    push(&mut runs, "master", "governance", 607, 1)?;
    push(&mut runs, "master", "batch", 926 + 81 * k, 1)?;
    push(&mut runs, "master", "value", 654, 1)?;
    push(&mut runs, "master", "settlement", 984, 1)?;

    let total_calls = runs.iter().try_fold(0_u64, |total, run| {
        total.checked_add(run.count).ok_or(HashBusError::Overflow)
    })?;
    let total_permutations = runs.iter().try_fold(0_u64, |total, run| {
        total
            .checked_add(run.permutations()?)
            .ok_or(HashBusError::Overflow)
    })?;
    let mut capacity_hash = Sha3_512::new();
    capacity_hash.update(CAPACITY_SCHEDULE_DOMAIN);
    let profile_id = profile_id(profile).as_bytes();
    capacity_hash.update([u8::try_from(profile_id.len()).map_err(|_| HashBusError::Encoding)?]);
    capacity_hash.update(profile_id);
    capacity_hash.update(
        u16::try_from(runs.len())
            .map_err(|_| HashBusError::Encoding)?
            .to_be_bytes(),
    );
    for run in &runs {
        for value in [run.component.as_bytes(), run.label.as_bytes()] {
            capacity_hash.update([u8::try_from(value.len()).map_err(|_| HashBusError::Encoding)?]);
            capacity_hash.update(value);
        }
        capacity_hash.update(run.capacity.to_be_bytes());
        capacity_hash.update(run.count.to_be_bytes());
    }
    capacity_hash.update(total_calls.to_be_bytes());
    capacity_hash.update(total_permutations.to_be_bytes());
    let capacity_schedule_commitment = capacity_hash.finalize().into();
    let coprocessor_shards_u64 = total_permutations.div_ceil(PERMUTATIONS_PER_COPROCESSOR_SHARD);
    let coprocessor_shards =
        u16::try_from(coprocessor_shards_u64).map_err(|_| HashBusError::Overflow)?;
    let padded_permutations = coprocessor_shards_u64
        .checked_mul(PERMUTATIONS_PER_COPROCESSOR_SHARD)
        .ok_or(HashBusError::Overflow)?;

    let mut descriptor_hash = Sha3_512::new();
    descriptor_hash.update(HASH_BUS_DESCRIPTOR_DOMAIN);
    descriptor_hash.update(HASH_BUS_DESCRIPTOR_VERSION.to_be_bytes());
    descriptor_hash.update([profile as u8]);
    descriptor_hash.update(total_calls.to_be_bytes());
    descriptor_hash.update(total_permutations.to_be_bytes());
    descriptor_hash.update(capacity_schedule_commitment);
    descriptor_hash.update(KECCAK_STATE_BITS.to_be_bytes());
    descriptor_hash.update(KECCAK_ROUNDS.to_be_bytes());
    descriptor_hash.update(PACKED_SHARDS.to_be_bytes());
    descriptor_hash.update(GROUP_COUNT.to_be_bytes());
    descriptor_hash.update(PERMUTATIONS_PER_COPROCESSOR_SHARD.to_be_bytes());
    descriptor_hash.update(coprocessor_shards.to_be_bytes());
    descriptor_hash.update(padded_permutations.to_be_bytes());
    let descriptor_commitment = descriptor_hash.finalize().into();
    Ok(HashBusDescriptor {
        profile,
        runs,
        total_calls,
        total_permutations,
        coprocessor_shards,
        padded_permutations,
        capacity_schedule_commitment,
        descriptor_commitment,
    })
}

/// Resolve one fixed coprocessor lane to its unique call and sponge block.
///
/// Returns `None` only for the descriptor-authenticated dummy tail after the
/// final live permutation and before `padded_permutations`.
pub fn hash_bus_permutation_slot(
    descriptor: &HashBusDescriptor,
    permutation_index: u64,
) -> Result<Option<HashBusPermutationSlot>, HashBusError> {
    if permutation_index >= descriptor.padded_permutations {
        return Err(HashBusError::Encoding);
    }
    if permutation_index >= descriptor.total_permutations {
        return Ok(None);
    }
    let mut remaining = permutation_index;
    let mut call_offset = 0_u64;
    for (run_index, run) in descriptor.runs.iter().copied().enumerate() {
        let blocks_in_call = run
            .capacity
            .checked_div(u64::from(RATE_BYTES))
            .and_then(|blocks| blocks.checked_add(1))
            .ok_or(HashBusError::Overflow)?;
        let run_permutations = blocks_in_call
            .checked_mul(run.count)
            .ok_or(HashBusError::Overflow)?;
        if remaining < run_permutations {
            let call_in_run = remaining / blocks_in_call;
            return Ok(Some(HashBusPermutationSlot {
                call_index: call_offset
                    .checked_add(call_in_run)
                    .ok_or(HashBusError::Overflow)?,
                run_index: u16::try_from(run_index).map_err(|_| HashBusError::Overflow)?,
                block_index: u16::try_from(remaining % blocks_in_call)
                    .map_err(|_| HashBusError::Overflow)?,
                blocks_in_call: u16::try_from(blocks_in_call)
                    .map_err(|_| HashBusError::Overflow)?,
                capacity: run.capacity,
            }));
        }
        remaining -= run_permutations;
        call_offset = call_offset
            .checked_add(run.count)
            .ok_or(HashBusError::Overflow)?;
    }
    Err(HashBusError::Encoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex(value: &str) -> [u8; 64] {
        let mut result = [0_u8; 64];
        for (destination, pair) in result.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
            let nibble = |value| match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                _ => panic!("invalid hex"),
            };
            *destination = (nibble(pair[0]) << 4) | nibble(pair[1]);
        }
        result
    }

    #[test]
    fn k128_and_k512_geometry_matches_the_independent_python_schedule() {
        for (profile, calls, permutations, shards, padded, capacity, expected_descriptor) in [
            (
                Profile::K128Calibration,
                46_858,
                113_730,
                1,
                131_072,
                "2422aa275787b8dd44e4ca8be711a44721e77f9e0a48834afea7be26ada9144ed9899e6031948b7ae28e7b73ed4d578e6bacb01ddc3d9bb58a59a6fb76d492ff",
                "d7b979425eee9ac48804c27f0d90e1e67083a9f85c038f4b735067c57d23b6d859841f4f97470168d6f48079fa788e4b8e2b0abe63ac51819975cd64996e80dd",
            ),
            (
                Profile::K512Calibration,
                165_762,
                411_406,
                4,
                524_288,
                "2f9f836cd9af695b5760e1680453f68bcbe16d3ed0eb8e2c25177b16387c81c6417d86e1dc530afc0f77d6b7192709aac385fb418eacaf2f752ce434cdd59328",
                "c8328a2c76c3c2c4fbedbc723a2250dcf6ee0b9f198f15241113860a628788cead865b1372b4877101f56023e47deb5f372fa6d54e0ccd5352c25332e325eb91",
            ),
        ] {
            let descriptor = build_hash_bus_descriptor(profile).unwrap();
            assert_eq!(descriptor.runs.len(), 31);
            assert_eq!(descriptor.total_calls, calls);
            assert_eq!(descriptor.total_permutations, permutations);
            assert_eq!(descriptor.coprocessor_shards, shards);
            assert_eq!(descriptor.padded_permutations, padded);
            assert_eq!(
                descriptor.capacity_schedule_commitment,
                decode_hex(capacity)
            );
            assert_eq!(
                descriptor.descriptor_commitment,
                decode_hex(expected_descriptor)
            );
        }
    }

    #[test]
    fn permutation_slots_cover_every_live_block_and_only_the_dummy_tail() {
        for profile in [Profile::K128Calibration, Profile::K512Calibration] {
            let descriptor = build_hash_bus_descriptor(profile).unwrap();
            let first = hash_bus_permutation_slot(&descriptor, 0).unwrap().unwrap();
            assert_eq!(first.call_index, 0);
            assert_eq!(first.run_index, 0);
            assert_eq!(first.block_index, 0);
            assert_eq!(first.blocks_in_call, 79);
            assert_eq!(first.capacity, 5_648);

            let last = hash_bus_permutation_slot(&descriptor, descriptor.total_permutations - 1)
                .unwrap()
                .unwrap();
            assert_eq!(last.call_index, descriptor.total_calls - 1);
            assert_eq!(last.run_index, 30);
            assert_eq!(last.block_index + 1, last.blocks_in_call);
            assert_eq!(last.capacity, 984);

            assert_eq!(
                hash_bus_permutation_slot(&descriptor, descriptor.total_permutations),
                Ok(None)
            );
            assert_eq!(
                hash_bus_permutation_slot(&descriptor, descriptor.padded_permutations),
                Err(HashBusError::Encoding)
            );
        }
    }
}
