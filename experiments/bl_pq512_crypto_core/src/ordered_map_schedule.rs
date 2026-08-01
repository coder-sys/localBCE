//! Exact fixed-shape ordered-map schedule shared with the Python AIR.
//!
//! This module freezes dimensions and their domain-separated commitment.  It
//! does not claim that the complete ordered-map AIR or proof backend is present
//! in Rust yet.

use alloc::vec::Vec;

use sha3::{Digest, Sha3_512};

use crate::sha3_air::{
    KECCAK_ROUNDS, RATE_BYTES, Sha3TraceError, for_each_sha3_512_trace_row, sha3_512_reference,
};

/// Cross-language schedule commitment domain.
pub const ORDERED_MAP_BATCH_SCHEDULE_DOMAIN: &[u8] =
    b"BL/PQ512/WAVE1A/ORDERED-MAP-BATCH-SCHEDULE/v1\0";
/// Cross-language fixed hash-call commitment domain.
pub const ORDERED_MAP_HASH_SCHEDULE_DOMAIN: &[u8] =
    b"BL/PQ512/WAVE1A/ORDERED-MAP-HASH-SCHEDULE/v1\0";
/// Logical ordered-map depth.
pub const ORDERED_MAP_DEPTH: u8 = 64;

/// One map lane's fixed privacy schedule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderedMapBatchSchedule {
    pub operation_rows: u64,
    pub shard_index_bits: u8,
    pub position_rows: u64,
    pub memory_rows: u64,
    pub proof_node_rows: u64,
    pub node_hash_rows: u64,
    pub leaf_hash_rows: u64,
    pub header_hash_rows: u64,
    pub sha3_call_rows: u64,
    pub sha3_permutations: u64,
}

/// Fail-closed schedule construction error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderedMapScheduleError {
    OperationRowsInvalid,
    ShardIndexBitsInvalid,
    DimensionOverflow,
    LanesRequired,
    LaneCountOverflow,
}

/// Typed MAP4 hash-port family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OrderedMapHashFamily {
    Leaf = 1,
    Node = 2,
    Header = 3,
}

/// One owned fixed hash-port row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderedMapHashCall {
    pub family: OrderedMapHashFamily,
    pub live: bool,
    pub message: Vec<u8>,
    pub digest: [u8; 64],
}

/// Exact streaming evaluation report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderedMapHashScheduleReport {
    pub calls: u64,
    pub permutations: u64,
    pub keccak_round_rows: u64,
    pub commitment: [u8; 64],
}

/// Fail-closed hash schedule error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderedMapHashScheduleError {
    CallsRequired,
    CallCountMismatch,
    FamilyMismatch,
    LivePrefixInvalid,
    HeaderMustBeLive,
    MessageLengthMismatch,
    DummyMessageMismatch,
    DigestMismatch,
    CountOverflow,
    Trace(Sha3TraceError),
}

fn u64_dimension(value: u128) -> Result<u64, OrderedMapScheduleError> {
    value
        .try_into()
        .map_err(|_| OrderedMapScheduleError::DimensionOverflow)
}

/// Build the exact Python-parity privacy envelope.
pub fn build_ordered_map_batch_schedule(
    operation_rows: u64,
    shard_index_bits: u8,
) -> Result<OrderedMapBatchSchedule, OrderedMapScheduleError> {
    if operation_rows == 0 {
        return Err(OrderedMapScheduleError::OperationRowsInvalid);
    }
    if !(1..=ORDERED_MAP_DEPTH).contains(&shard_index_bits) {
        return Err(OrderedMapScheduleError::ShardIndexBitsInvalid);
    }

    let operations = u128::from(operation_rows);
    let positions = operations
        .checked_mul(2)
        .ok_or(OrderedMapScheduleError::DimensionOverflow)?;
    let upper_levels = u128::from(ORDERED_MAP_DEPTH - shard_index_bits);
    let mut proof_nodes = upper_levels;
    let mut parents_per_root = upper_levels;
    for height in 0..shard_index_bits {
        let proof_width = 1_u128 << u32::from(shard_index_bits - height);
        proof_nodes = proof_nodes
            .checked_add(core::cmp::min(positions, proof_width))
            .ok_or(OrderedMapScheduleError::DimensionOverflow)?;
        let parent_width = 1_u128 << u32::from(shard_index_bits - height - 1);
        parents_per_root = parents_per_root
            .checked_add(core::cmp::min(positions, parent_width))
            .ok_or(OrderedMapScheduleError::DimensionOverflow)?;
    }
    let node_hashes = parents_per_root
        .checked_mul(2)
        .ok_or(OrderedMapScheduleError::DimensionOverflow)?;
    let leaf_hashes = positions
        .checked_mul(2)
        .ok_or(OrderedMapScheduleError::DimensionOverflow)?;
    let header_hashes = 2_u128;
    let sha3_calls = node_hashes
        .checked_add(leaf_hashes)
        .and_then(|value| value.checked_add(header_hashes))
        .ok_or(OrderedMapScheduleError::DimensionOverflow)?;
    let permutations = node_hashes
        .checked_mul(2)
        .and_then(|value| value.checked_add(leaf_hashes * 3))
        .and_then(|value| value.checked_add(header_hashes * 2))
        .ok_or(OrderedMapScheduleError::DimensionOverflow)?;

    Ok(OrderedMapBatchSchedule {
        operation_rows,
        shard_index_bits,
        position_rows: u64_dimension(positions)?,
        memory_rows: u64_dimension(positions)?,
        proof_node_rows: u64_dimension(proof_nodes)?,
        node_hash_rows: u64_dimension(node_hashes)?,
        leaf_hash_rows: u64_dimension(leaf_hashes)?,
        header_hash_rows: u64_dimension(header_hashes)?,
        sha3_call_rows: u64_dimension(sha3_calls)?,
        sha3_permutations: u64_dimension(permutations)?,
    })
}

/// Commit an ordered list of `(map_domain, schedule)` pairs.
pub fn ordered_map_batch_schedule_commitment(
    lanes: &[(u8, OrderedMapBatchSchedule)],
) -> Result<[u8; 64], OrderedMapScheduleError> {
    if lanes.is_empty() {
        return Err(OrderedMapScheduleError::LanesRequired);
    }
    let lane_count: u32 = lanes
        .len()
        .try_into()
        .map_err(|_| OrderedMapScheduleError::LaneCountOverflow)?;
    let mut hash = Sha3_512::new();
    hash.update(ORDERED_MAP_BATCH_SCHEDULE_DOMAIN);
    hash.update(lane_count.to_be_bytes());
    for (map_domain, schedule) in lanes {
        hash.update([*map_domain]);
        for value in [
            schedule.operation_rows,
            u64::from(schedule.shard_index_bits),
            schedule.position_rows,
            schedule.memory_rows,
            schedule.proof_node_rows,
            schedule.node_hash_rows,
            schedule.leaf_hash_rows,
            schedule.header_hash_rows,
            schedule.sha3_call_rows,
            schedule.sha3_permutations,
        ] {
            hash.update(value.to_be_bytes());
        }
    }
    Ok(hash.finalize().into())
}

fn dummy_leaf_message(map_domain: u8) -> Vec<u8> {
    let mut message = Vec::with_capacity(212);
    message.extend_from_slice(b"BL/PQ/MAP4\0");
    message.push(map_domain);
    message.extend_from_slice(&[0_u8; 128]);
    message.extend_from_slice(&[0xff_u8; 64]);
    message.extend_from_slice(&1_u64.to_be_bytes());
    message
}

fn dummy_node_message(map_domain: u8) -> Vec<u8> {
    let mut message = Vec::with_capacity(141);
    message.extend_from_slice(b"BL/PQ/MAP4\x01");
    message.push(map_domain);
    message.push(0);
    message.extend_from_slice(&[0_u8; 128]);
    message
}

/// Stream and validate every fixed map hash row, including padding rows.
pub fn evaluate_ordered_map_hash_schedule(
    schedule: OrderedMapBatchSchedule,
    map_domain: u8,
    calls: &[OrderedMapHashCall],
) -> Result<OrderedMapHashScheduleReport, OrderedMapHashScheduleError> {
    if calls.is_empty() {
        return Err(OrderedMapHashScheduleError::CallsRequired);
    }
    if u64::try_from(calls.len()).ok() != Some(schedule.sha3_call_rows) {
        return Err(OrderedMapHashScheduleError::CallCountMismatch);
    }
    let leaf_stop: usize = schedule
        .leaf_hash_rows
        .try_into()
        .map_err(|_| OrderedMapHashScheduleError::CountOverflow)?;
    let node_stop: usize = (schedule.leaf_hash_rows + schedule.node_hash_rows)
        .try_into()
        .map_err(|_| OrderedMapHashScheduleError::CountOverflow)?;
    let dummy_leaf = dummy_leaf_message(map_domain);
    let dummy_node = dummy_node_message(map_domain);
    let mut leaf_padding_seen = false;
    let mut node_padding_seen = false;
    let mut permutations = 0_u64;
    let mut round_rows = 0_u64;
    let call_count: u32 = calls
        .len()
        .try_into()
        .map_err(|_| OrderedMapHashScheduleError::CountOverflow)?;
    let mut commitment = Sha3_512::new();
    commitment.update(ORDERED_MAP_HASH_SCHEDULE_DOMAIN);
    commitment.update(call_count.to_be_bytes());

    for (ordinal, call) in calls.iter().enumerate() {
        let (expected_family, expected_length) = if ordinal < leaf_stop {
            (OrderedMapHashFamily::Leaf, 212_usize)
        } else if ordinal < node_stop {
            (OrderedMapHashFamily::Node, 141_usize)
        } else {
            (OrderedMapHashFamily::Header, 84_usize)
        };
        if call.family != expected_family {
            return Err(OrderedMapHashScheduleError::FamilyMismatch);
        }
        if call.message.len() != expected_length {
            return Err(OrderedMapHashScheduleError::MessageLengthMismatch);
        }
        match call.family {
            OrderedMapHashFamily::Leaf => {
                if !call.live {
                    leaf_padding_seen = true;
                    if call.message != dummy_leaf {
                        return Err(OrderedMapHashScheduleError::DummyMessageMismatch);
                    }
                } else if leaf_padding_seen {
                    return Err(OrderedMapHashScheduleError::LivePrefixInvalid);
                }
            }
            OrderedMapHashFamily::Node => {
                if !call.live {
                    node_padding_seen = true;
                    if call.message != dummy_node {
                        return Err(OrderedMapHashScheduleError::DummyMessageMismatch);
                    }
                } else if node_padding_seen {
                    return Err(OrderedMapHashScheduleError::LivePrefixInvalid);
                }
            }
            OrderedMapHashFamily::Header => {
                if !call.live {
                    return Err(OrderedMapHashScheduleError::HeaderMustBeLive);
                }
            }
        }
        if sha3_512_reference(&call.message) != call.digest {
            return Err(OrderedMapHashScheduleError::DigestMismatch);
        }
        let streamed_digest =
            for_each_sha3_512_trace_row(&call.message, call.message.len(), |_, _, _, _, _, _| {
                round_rows += 1
            })
            .map_err(OrderedMapHashScheduleError::Trace)?;
        if streamed_digest != call.digest {
            return Err(OrderedMapHashScheduleError::DigestMismatch);
        }
        permutations += (call.message.len() / usize::from(RATE_BYTES) + 1) as u64;

        commitment.update((ordinal as u64).to_be_bytes());
        commitment.update([call.family as u8, u8::from(call.live)]);
        commitment.update((call.message.len() as u16).to_be_bytes());
        commitment.update(&call.message);
        commitment.update(call.digest);
    }
    if permutations != schedule.sha3_permutations
        || round_rows != permutations * u64::from(KECCAK_ROUNDS)
    {
        return Err(OrderedMapHashScheduleError::CountOverflow);
    }
    Ok(OrderedMapHashScheduleReport {
        calls: u64::from(call_count),
        permutations,
        keccak_round_rows: round_rows,
        commitment: commitment.finalize().into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_message(map_domain: u8, cursor: u64, inner_root: [u8; 64]) -> Vec<u8> {
        let mut message = Vec::with_capacity(84);
        message.extend_from_slice(b"BL/PQ/MAP4\x02");
        message.push(map_domain);
        message.extend_from_slice(&cursor.to_be_bytes());
        message.extend_from_slice(&inner_root);
        message
    }

    fn synthetic_hash_calls(
        schedule: OrderedMapBatchSchedule,
        map_domain: u8,
    ) -> Vec<OrderedMapHashCall> {
        let mut calls = Vec::new();
        let leaf = dummy_leaf_message(map_domain);
        let leaf_digest = sha3_512_reference(&leaf);
        for _ in 0..schedule.leaf_hash_rows {
            calls.push(OrderedMapHashCall {
                family: OrderedMapHashFamily::Leaf,
                live: false,
                message: leaf.clone(),
                digest: leaf_digest,
            });
        }
        let node = dummy_node_message(map_domain);
        let node_digest = sha3_512_reference(&node);
        for _ in 0..schedule.node_hash_rows {
            calls.push(OrderedMapHashCall {
                family: OrderedMapHashFamily::Node,
                live: false,
                message: node.clone(),
                digest: node_digest,
            });
        }
        for (cursor, label) in [(2_u64, b"BEFORE".as_slice()), (3, b"AFTER".as_slice())] {
            let message = header_message(map_domain, cursor, sha3_512_reference(label));
            let digest = sha3_512_reference(&message);
            calls.push(OrderedMapHashCall {
                family: OrderedMapHashFamily::Header,
                live: true,
                message,
                digest,
            });
        }
        calls
    }

    #[test]
    fn k128_economic_schedule_matches_python_exactly() {
        let benefit = build_ordered_map_batch_schedule(128, 24).unwrap();
        let obligation = build_ordered_map_batch_schedule(128, 24).unwrap();
        let ledger = build_ordered_map_batch_schedule(256, 24).unwrap();
        assert_eq!(
            benefit,
            OrderedMapBatchSchedule {
                operation_rows: 128,
                shard_index_bits: 24,
                position_rows: 256,
                memory_rows: 256,
                proof_node_rows: 4_646,
                node_hash_rows: 8_782,
                leaf_hash_rows: 512,
                header_hash_rows: 2,
                sha3_call_rows: 9_296,
                sha3_permutations: 19_104,
            }
        );
        assert_eq!(
            ledger,
            OrderedMapBatchSchedule {
                operation_rows: 256,
                shard_index_bits: 24,
                position_rows: 512,
                memory_rows: 512,
                proof_node_rows: 8_742,
                node_hash_rows: 16_462,
                leaf_hash_rows: 1_024,
                header_hash_rows: 2,
                sha3_call_rows: 17_488,
                sha3_permutations: 36_000,
            }
        );
        assert_eq!(
            benefit.sha3_call_rows + obligation.sha3_call_rows + ledger.sha3_call_rows,
            36_080
        );
        assert_eq!(
            benefit.sha3_permutations + obligation.sha3_permutations + ledger.sha3_permutations,
            74_208
        );
    }

    #[test]
    fn python_schedule_commitment_matches_and_relabeling_changes_it() {
        let benefit = build_ordered_map_batch_schedule(128, 24).unwrap();
        let obligation = build_ordered_map_batch_schedule(128, 24).unwrap();
        let ledger = build_ordered_map_batch_schedule(256, 24).unwrap();
        let lanes = [(0x11, benefit), (0x12, obligation), (0x13, ledger)];
        assert_eq!(
            ordered_map_batch_schedule_commitment(&lanes).unwrap(),
            hex64(
                "1c390b67823fc6b71233d87d4082d48082b6f9ed3ff2f7c4d5e079f5b6bff947\
                 646b41c9714e263f29a1e3722a9cab8fa158091f00f77b1c7304a21182588683"
            )
        );
        let relabeled = [(0x12, benefit), (0x11, obligation), (0x13, ledger)];
        assert_ne!(
            ordered_map_batch_schedule_commitment(&lanes).unwrap(),
            ordered_map_batch_schedule_commitment(&relabeled).unwrap()
        );
    }

    #[test]
    fn fixed_hash_schedule_streams_every_row_and_matches_python() {
        let schedule = build_ordered_map_batch_schedule(1, 2).unwrap();
        let report = evaluate_ordered_map_hash_schedule(
            schedule,
            b'G',
            &synthetic_hash_calls(schedule, b'G'),
        )
        .unwrap();
        assert_eq!(report.calls, 136);
        assert_eq!(report.permutations, 276);
        assert_eq!(report.keccak_round_rows, 6_624);
        assert_eq!(
            report.commitment,
            hex64(
                "a45ec62a23518d528dda98e20da49e513c2d7ac82e6ceb58637985a066190a56\
                 3e776676816d21e784c88ad1084a560c565cd00bef82b83c0c4a91d37052fee0"
            )
        );
    }

    #[test]
    fn fixed_hash_schedule_tampering_fails_closed() {
        let schedule = build_ordered_map_batch_schedule(1, 2).unwrap();
        let baseline = synthetic_hash_calls(schedule, b'G');

        let mut digest = baseline.clone();
        digest[0].digest[0] ^= 1;
        assert_eq!(
            evaluate_ordered_map_hash_schedule(schedule, b'G', &digest),
            Err(OrderedMapHashScheduleError::DigestMismatch)
        );

        let mut dummy = baseline.clone();
        dummy[0].message[12] ^= 1;
        dummy[0].digest = sha3_512_reference(&dummy[0].message);
        assert_eq!(
            evaluate_ordered_map_hash_schedule(schedule, b'G', &dummy),
            Err(OrderedMapHashScheduleError::DummyMessageMismatch)
        );

        let mut header = baseline;
        let last = header.len() - 1;
        header[last].live = false;
        assert_eq!(
            evaluate_ordered_map_hash_schedule(schedule, b'G', &header),
            Err(OrderedMapHashScheduleError::HeaderMustBeLive)
        );
    }

    #[test]
    fn invalid_schedule_requests_fail_closed() {
        assert_eq!(
            build_ordered_map_batch_schedule(0, 24),
            Err(OrderedMapScheduleError::OperationRowsInvalid)
        );
        assert_eq!(
            build_ordered_map_batch_schedule(1, 0),
            Err(OrderedMapScheduleError::ShardIndexBitsInvalid)
        );
        assert_eq!(
            ordered_map_batch_schedule_commitment(&[]),
            Err(OrderedMapScheduleError::LanesRequired)
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
