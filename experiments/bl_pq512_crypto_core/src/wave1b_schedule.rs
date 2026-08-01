//! Frozen cross-language metadata for the historical R33 K512/beta=1 interface schedule.
//!
//! The schedule groups all 16 Wave 1A tables after the conservative native-
//! hiding row extension. It binds gaps, varying widths, global batching-power
//! offsets, one independent mask per attached domain, and all 16 fold rounds.
//! It contains no evaluations, is forbidden as final theorem input, and
//! selects no proof suite.

use alloc::vec::Vec;
use sha3::{Digest, Sha3_512};

pub const FRI_DOMAIN_SCHEDULE_DOMAIN: &[u8] = b"BL/PQ512/WAVE1B/FRI-DOMAIN-SCHEDULE/v1";
pub const K512_BETA1_LOG_BLOWUP: u16 = 1;
pub const K512_BETA1_TRACE_COLUMNS: u32 = 2_279;
pub const K512_BETA1_MASK_COLUMNS: u16 = 6;
pub const K512_BETA1_ACTIVATION_ALLOWED: bool = false;
pub const K512_BETA1_PROOF_SUITE_ID: Option<[u8; 64]> = None;
pub const K512_BETA1_SCHEDULE_SHA3_512: [u8; 64] = [
    0xb1, 0x47, 0xa1, 0x29, 0xa8, 0x99, 0xe3, 0x3a, 0x4e, 0xd7, 0x09, 0x7a, 0xc7, 0x06, 0xc3, 0x67,
    0xf9, 0x71, 0xaa, 0xbe, 0x8b, 0x6c, 0xb1, 0x88, 0x17, 0x36, 0x95, 0x90, 0x32, 0x53, 0x0c, 0x30,
    0xb4, 0xcc, 0xd1, 0x0c, 0xaf, 0xf6, 0x3b, 0x29, 0x4f, 0x7f, 0xf9, 0x97, 0x7e, 0x21, 0xdb, 0x59,
    0x95, 0x15, 0xa2, 0x8c, 0x08, 0xd5, 0x6b, 0xe2, 0xe7, 0x3b, 0x84, 0x71, 0x4c, 0x7e, 0x13, 0x73,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FriInterfaceDomainGroup {
    pub trace_log_size: u16,
    pub evaluation_log_size: u16,
    pub table_names: &'static [&'static str],
    pub trace_column_count: u32,
    pub global_power_offset: u32,
    pub mask_column_count: u16,
}

pub const K512_BETA1_GROUPS: [FriInterfaceDomainGroup; 6] = [
    FriInterfaceDomainGroup {
        trace_log_size: 19,
        evaluation_log_size: 20,
        table_names: &["oracle_tree", "policy_and_ruleset_tree"],
        trace_column_count: 188,
        global_power_offset: 0,
        mask_column_count: 1,
    },
    FriInterfaceDomainGroup {
        trace_log_size: 17,
        evaluation_log_size: 18,
        table_names: &["strong_replay_transition", "private_asset_ledger_map"],
        trace_column_count: 372,
        global_power_offset: 188,
        mask_column_count: 1,
    },
    FriInterfaceDomainGroup {
        trace_log_size: 16,
        evaluation_log_size: 17,
        table_names: &["benefit_accumulator_map", "provider_obligation_map"],
        trace_column_count: 272,
        global_power_offset: 560,
        mask_column_count: 1,
    },
    FriInterfaceDomainGroup {
        trace_log_size: 15,
        evaluation_log_size: 16,
        table_names: &[
            "service_lines",
            "authorizations",
            "legacy_replay_transition",
        ],
        trace_column_count: 312,
        global_power_offset: 832,
        mask_column_count: 1,
    },
    FriInterfaceDomainGroup {
        trace_log_size: 13,
        evaluation_log_size: 14,
        table_names: &[
            "canonical_witness",
            "claim_gate_and_money",
            "diagnoses",
            "oracle_facts",
            "claim_source_tree",
            "payment_operation_log",
        ],
        trace_column_count: 1_047,
        global_power_offset: 1_144,
        mask_column_count: 1,
    },
    FriInterfaceDomainGroup {
        trace_log_size: 4,
        evaluation_log_size: 5,
        table_names: &["ordered_public_statement"],
        trace_column_count: 88,
        global_power_offset: 2_191,
        mask_column_count: 1,
    },
];

pub const K512_BETA1_FOLD_LOG_SIZES: [u16; 16] =
    [20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5];

pub fn k512_beta1_canonical_bytes() -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(FRI_DOMAIN_SCHEDULE_DOMAIN);
    encoded.extend_from_slice(&K512_BETA1_LOG_BLOWUP.to_be_bytes());
    encoded.extend_from_slice(&(K512_BETA1_GROUPS.len() as u16).to_be_bytes());
    encoded.extend_from_slice(&(K512_BETA1_FOLD_LOG_SIZES.len() as u16).to_be_bytes());
    for log_size in K512_BETA1_FOLD_LOG_SIZES {
        encoded.extend_from_slice(&log_size.to_be_bytes());
    }
    for group in K512_BETA1_GROUPS {
        encoded.extend_from_slice(&group.trace_log_size.to_be_bytes());
        encoded.extend_from_slice(&group.evaluation_log_size.to_be_bytes());
        encoded.extend_from_slice(&group.trace_column_count.to_be_bytes());
        encoded.extend_from_slice(&group.global_power_offset.to_be_bytes());
        encoded.extend_from_slice(&group.mask_column_count.to_be_bytes());
        encoded.extend_from_slice(&(group.table_names.len() as u16).to_be_bytes());
        for name in group.table_names {
            let name = name.as_bytes();
            encoded.extend_from_slice(&(name.len() as u16).to_be_bytes());
            encoded.extend_from_slice(name);
        }
    }
    encoded
}

pub fn k512_beta1_schedule_sha3_512() -> [u8; 64] {
    Sha3_512::digest(k512_beta1_canonical_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn k512_beta1_schedule_is_gap_complete_globally_offset_and_nonactivating() {
        assert_eq!(K512_BETA1_GROUPS.len(), 6);
        assert_eq!(K512_BETA1_FOLD_LOG_SIZES.len(), 16);
        assert_eq!(K512_BETA1_FOLD_LOG_SIZES[0], 20);
        assert_eq!(K512_BETA1_FOLD_LOG_SIZES[15], 5);
        assert!(
            K512_BETA1_FOLD_LOG_SIZES
                .windows(2)
                .all(|pair| pair[0] == pair[1] + 1)
        );
        assert!(
            K512_BETA1_GROUPS
                .windows(2)
                .all(|pair| pair[0].evaluation_log_size > pair[1].evaluation_log_size)
        );

        let mut expected_offset = 0_u32;
        let mut table_count = 0_usize;
        let mut mask_count = 0_u16;
        for group in K512_BETA1_GROUPS {
            assert_eq!(
                group.evaluation_log_size,
                group.trace_log_size + K512_BETA1_LOG_BLOWUP
            );
            assert_eq!(group.global_power_offset, expected_offset);
            assert_eq!(group.mask_column_count, 1);
            expected_offset += group.trace_column_count;
            table_count += group.table_names.len();
            mask_count += group.mask_column_count;
        }
        assert_eq!(expected_offset, K512_BETA1_TRACE_COLUMNS);
        assert_eq!(table_count, 16);
        assert_eq!(mask_count, K512_BETA1_MASK_COLUMNS);
        const {
            assert!(!K512_BETA1_ACTIVATION_ALLOWED);
            assert!(K512_BETA1_PROOF_SUITE_ID.is_none());
        }
    }

    #[test]
    fn python_schedule_commitment_matches() {
        assert_eq!(k512_beta1_schedule_sha3_512(), K512_BETA1_SCHEDULE_SHA3_512);
    }
}
