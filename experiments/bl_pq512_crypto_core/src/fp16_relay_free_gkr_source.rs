//! Canonical B=16 source-table encoding for the relay-free Keccak GKR.
//!
//! Sixteen Boolean shard values are interpolated at the public M31 nodes
//! `0..15`. The sixteen monomial coefficients are stored in the frozen Fp16
//! tower basis. The low eleven Boolean address bits select the padded Keccak
//! wire, the next five select the low group bits, and the high eight select
//! one of the 256 RS messages.

use crate::{
    field::Fp16,
    gkr_packed_bridge_fp16::{LagrangeBasis, PACKED_INSTANCES, lagrange_basis},
};

pub const PADDED_WIRES: usize = 2_048;
pub const GROUP_COUNT: usize = 8_192;
pub const GROUPS_PER_RS_WORD: usize = 32;
pub const RS_WORDS_PER_BOUNDARY: usize = 256;
pub const RS_MESSAGE_VALUES: usize = 65_536;
pub const SOURCE_VALUES_PER_BOUNDARY: usize = RS_WORDS_PER_BOUNDARY * RS_MESSAGE_VALUES;
pub const KECCAK_F_ZERO: [u64; 25] = [
    0xf125_8f79_40e1_dde7,
    0x84d5_ccf9_33c0_478a,
    0xd598_261e_a65a_a9ee,
    0xbd15_4730_6f80_494d,
    0x8b28_4e05_6253_d057,
    0xff97_a42d_7f8e_6fd4,
    0x90fe_e5a0_a446_47c4,
    0x8c5b_da0c_d619_2e76,
    0xad30_a6f7_1b19_059c,
    0x3093_5ab7_d08f_fc64,
    0xeb5a_a93f_2317_d635,
    0xa9a6_e626_0d71_2103,
    0x81a5_7c16_dbcf_555f,
    0x43b8_31cd_0347_c826,
    0x01f2_2f1a_11a5_569f,
    0x05e5_635a_21d9_ae61,
    0x64be_fef2_8cc9_70f2,
    0x6136_7095_7bc4_6611,
    0xb87c_5a55_4fd0_0ecb,
    0x8c3e_e88a_1ccf_32c8,
    0x940c_7922_ae3a_2614,
    0x1841_f924_a2c5_09e4,
    0x16f5_3526_e704_65c2,
    0x75f6_44e9_7f30_a13b,
    0xeaf1_ff7b_5cec_a249,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayFreeGkrSourceError {
    Wire,
    Group,
    Word,
    Position,
}

/// Return `(word, coefficient_position)` for one wire/group source value.
pub fn source_address(
    wire: usize,
    group: usize,
) -> Result<(usize, usize), RelayFreeGkrSourceError> {
    if wire >= PADDED_WIRES {
        return Err(RelayFreeGkrSourceError::Wire);
    }
    if group >= GROUP_COUNT {
        return Err(RelayFreeGkrSourceError::Group);
    }
    let word = group / GROUPS_PER_RS_WORD;
    let position = (group % GROUPS_PER_RS_WORD) * PADDED_WIRES + wire;
    Ok((word, position))
}

pub fn source_wire_group(
    word: usize,
    position: usize,
) -> Result<(usize, usize), RelayFreeGkrSourceError> {
    if word >= RS_WORDS_PER_BOUNDARY {
        return Err(RelayFreeGkrSourceError::Word);
    }
    if position >= RS_MESSAGE_VALUES {
        return Err(RelayFreeGkrSourceError::Position);
    }
    let wire = position % PADDED_WIRES;
    let group = word * GROUPS_PER_RS_WORD + position / PADDED_WIRES;
    Ok((wire, group))
}

/// Encode the sixteen Boolean shard evaluations as one committed Fp16 source
/// coefficient.
pub fn encode_b16_pattern(pattern: u16) -> Fp16 {
    let basis = lagrange_basis();
    encode_b16_pattern_with_basis(pattern, &basis)
}

pub fn encode_b16_pattern_with_basis(pattern: u16, basis: &LagrangeBasis) -> Fp16 {
    let mut coefficients = [0_u32; PACKED_INSTANCES];
    for (shard, basis_row) in basis.iter().enumerate() {
        if (pattern >> shard) & 1 == 0 {
            continue;
        }
        for (coefficient, value) in basis_row.iter().copied().enumerate() {
            let value_coordinates = value.coefficients();
            debug_assert!(value_coordinates[1..].iter().all(|entry| *entry == 0));
            let sum = u64::from(coefficients[coefficient]) + u64::from(value_coordinates[0]);
            coefficients[coefficient] = (sum % 2_147_483_647) as u32;
        }
    }
    Fp16::from_coefficients(coefficients).expect("interpolation coefficients are canonical M31")
}

pub fn encode_b16_shards(shards: [bool; PACKED_INSTANCES]) -> Fp16 {
    let pattern = shards
        .into_iter()
        .enumerate()
        .fold(0_u16, |value, (shard, bit)| {
            value | (u16::from(bit) << shard)
        });
    encode_b16_pattern(pattern)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha3_air::keccak_f1600;

    const M31_MODULUS: u64 = 2_147_483_647;

    fn evaluate_encoded_pattern(encoded: Fp16, node: u32) -> u32 {
        encoded
            .coefficients()
            .into_iter()
            .rev()
            .fold(0_u64, |value, coefficient| {
                (value * u64::from(node) + u64::from(coefficient)) % M31_MODULUS
            }) as u32
    }

    #[test]
    fn source_address_is_a_bijection_with_the_pcs_layout() {
        for group in 0..GROUP_COUNT {
            for wire in [0, 1, 63, 64, 1_599, 1_600, PADDED_WIRES - 1] {
                let (word, position) = source_address(wire, group).unwrap();
                assert_eq!(source_wire_group(word, position), Ok((wire, group)));
                assert_eq!(
                    (word << 16) | position,
                    (group >> 5) << 16 | (group & 31) << 11 | wire
                );
            }
        }
        assert_eq!(
            source_address(PADDED_WIRES, 0),
            Err(RelayFreeGkrSourceError::Wire)
        );
        assert_eq!(
            source_address(0, GROUP_COUNT),
            Err(RelayFreeGkrSourceError::Group)
        );
    }

    #[test]
    fn every_b16_pattern_round_trips_at_all_public_nodes() {
        let basis = lagrange_basis();
        for pattern in 0_u16..=u16::MAX {
            let encoded = encode_b16_pattern_with_basis(pattern, &basis);
            for shard in 0..PACKED_INSTANCES {
                assert_eq!(
                    evaluate_encoded_pattern(encoded, shard as u32),
                    u32::from((pattern >> shard) & 1),
                    "pattern={pattern} shard={shard}"
                );
            }
        }
    }

    #[test]
    fn shard_array_and_pattern_encodings_agree() {
        for pattern in [0, 1, 0x8000, 0xa53c, 0xffff] {
            let shards = core::array::from_fn(|shard| (pattern >> shard) & 1 == 1);
            assert_eq!(encode_b16_shards(shards), encode_b16_pattern(pattern));
        }
    }

    #[test]
    fn frozen_zero_trace_output_matches_independent_keccak() {
        let mut state = [0_u64; 25];
        keccak_f1600(&mut state);
        assert_eq!(state, KECCAK_F_ZERO);
    }
}
