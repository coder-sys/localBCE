//! Generated, graph-free layered Boolean circuit for Keccak-f[1600].
//!
//! Every layer contains only adjacent-layer two-input XOR/AND gates. Values
//! needed by a later layer are explicit XOR-with-zero relay gates, so the
//! reported width is a circuit fact rather than the 1,600-bit state baseline.

use core::fmt;

use sha3::{Digest, Sha3_512};

use crate::sha3_air::{KECCAK_ROUNDS, ROTATION_OFFSETS, ROUND_CONSTANTS};

const DESCRIPTOR_DOMAIN: &[u8] = b"BL/PQ512/KECCAK-LAYERED-BOOLEAN-CIRCUIT/v1";
const STATE_BITS: usize = 1_600;
const CHI_GATES: usize = 1_600;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum KeccakLayerKind {
    ThetaPairs = 0,
    ThetaPairParity = 1,
    ThetaColumnParity = 2,
    ThetaDelta = 3,
    ThetaState = 4,
    ChiAnd = 5,
    ChiMask = 6,
    ChiOutput = 7,
    Iota = 8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeccakLayerDescriptor {
    pub kind: KeccakLayerKind,
    pub xor_gates: usize,
    pub and_gates: usize,
    pub relay_gates: usize,
    pub raw_width: usize,
    pub padded_width: usize,
}

const fn padded_width(width: usize) -> usize {
    width.next_power_of_two()
}

const fn layer(
    kind: KeccakLayerKind,
    xor_gates: usize,
    and_gates: usize,
    relay_gates: usize,
) -> KeccakLayerDescriptor {
    let raw_width = xor_gates + and_gates + relay_gates;
    KeccakLayerDescriptor {
        kind,
        xor_gates,
        and_gates,
        relay_gates,
        raw_width,
        padded_width: padded_width(raw_width),
    }
}

/// Exact forward layer schedule for one Keccak round.
///
/// Rho and pi are wiring permutations and therefore add no gate layer.
pub const ROUND_LAYERS: [KeccakLayerDescriptor; 9] = [
    layer(KeccakLayerKind::ThetaPairs, 640, 0, STATE_BITS),
    layer(KeccakLayerKind::ThetaPairParity, 320, 0, STATE_BITS),
    layer(KeccakLayerKind::ThetaColumnParity, 320, 0, STATE_BITS),
    layer(KeccakLayerKind::ThetaDelta, 320, 0, STATE_BITS),
    layer(KeccakLayerKind::ThetaState, STATE_BITS, 0, 0),
    layer(KeccakLayerKind::ChiAnd, 0, CHI_GATES, STATE_BITS),
    layer(KeccakLayerKind::ChiMask, CHI_GATES, 0, STATE_BITS),
    layer(KeccakLayerKind::ChiOutput, CHI_GATES, 0, 0),
    layer(KeccakLayerKind::Iota, STATE_BITS, 0, 0),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeccakCircuitReport {
    pub rounds: usize,
    pub depth: usize,
    pub maximum_raw_width: usize,
    pub maximum_padded_width: usize,
    pub xor_gates_per_permutation: usize,
    pub and_gates_per_permutation: usize,
    pub relay_gates_per_permutation: usize,
    pub padded_wires_per_permutation: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeccakCircuitError {
    Round,
    Overflow,
}

impl fmt::Display for KeccakCircuitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Keccak circuit error: {self:?}")
    }
}

impl core::error::Error for KeccakCircuitError {}

pub fn circuit_report() -> KeccakCircuitReport {
    let xor_per_round = ROUND_LAYERS
        .iter()
        .map(|layer| layer.xor_gates)
        .sum::<usize>();
    let and_per_round = ROUND_LAYERS
        .iter()
        .map(|layer| layer.and_gates)
        .sum::<usize>();
    let relay_per_round = ROUND_LAYERS
        .iter()
        .map(|layer| layer.relay_gates)
        .sum::<usize>();
    let padded_per_round = ROUND_LAYERS
        .iter()
        .map(|layer| layer.padded_width)
        .sum::<usize>();
    let rounds = usize::from(KECCAK_ROUNDS);
    KeccakCircuitReport {
        rounds,
        depth: rounds * ROUND_LAYERS.len(),
        maximum_raw_width: ROUND_LAYERS
            .iter()
            .map(|layer| layer.raw_width)
            .max()
            .unwrap_or(0),
        maximum_padded_width: ROUND_LAYERS
            .iter()
            .map(|layer| layer.padded_width)
            .max()
            .unwrap_or(0),
        xor_gates_per_permutation: rounds * xor_per_round,
        and_gates_per_permutation: rounds * and_per_round,
        relay_gates_per_permutation: rounds * relay_per_round,
        padded_wires_per_permutation: rounds * padded_per_round,
    }
}

/// Commitment to every generated layer dimension and gate count.
pub fn circuit_descriptor_commitment() -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(DESCRIPTOR_DOMAIN);
    hash.update(STATE_BITS.to_be_bytes());
    hash.update(KECCAK_ROUNDS.to_be_bytes());
    hash.update(ROUND_LAYERS.len().to_be_bytes());
    for descriptor in ROUND_LAYERS {
        hash.update([descriptor.kind as u8]);
        hash.update(descriptor.xor_gates.to_be_bytes());
        hash.update(descriptor.and_gates.to_be_bytes());
        hash.update(descriptor.relay_gates.to_be_bytes());
        hash.update(descriptor.raw_width.to_be_bytes());
        hash.update(descriptor.padded_width.to_be_bytes());
    }
    hash.finalize().into()
}

/// Execute the generated nine-layer round on 64 parallel bit positions.
pub fn execute_layered_keccak_round(
    state: &mut [u64; 25],
    round: usize,
) -> Result<(), KeccakCircuitError> {
    let round_constant = *ROUND_CONSTANTS
        .get(round)
        .ok_or(KeccakCircuitError::Round)?;

    let mut pairs = [[0_u64; 2]; 5];
    for x in 0..5 {
        pairs[x][0] = state[x] ^ state[x + 5];
        pairs[x][1] = state[x + 10] ^ state[x + 15];
    }
    let pair_parity = core::array::from_fn::<_, 5, _>(|x| pairs[x][0] ^ pairs[x][1]);
    let column_parity = core::array::from_fn::<_, 5, _>(|x| pair_parity[x] ^ state[x + 20]);
    let delta = core::array::from_fn::<_, 5, _>(|x| {
        column_parity[(x + 4) % 5] ^ column_parity[(x + 1) % 5].rotate_left(1)
    });
    let theta_state = core::array::from_fn::<_, 25, _>(|lane| state[lane] ^ delta[lane % 5]);

    let mut permuted = [0_u64; 25];
    for x in 0..5 {
        for y in 0..5 {
            permuted[y + 5 * ((2 * x + 3 * y) % 5)] =
                theta_state[x + 5 * y].rotate_left(ROTATION_OFFSETS[x][y]);
        }
    }
    let chi_and = core::array::from_fn::<_, 25, _>(|lane| {
        let x = lane % 5;
        let y = lane / 5;
        permuted[(x + 1) % 5 + 5 * y] & permuted[(x + 2) % 5 + 5 * y]
    });
    let chi_mask = core::array::from_fn::<_, 25, _>(|lane| {
        let x = lane % 5;
        let y = lane / 5;
        permuted[(x + 2) % 5 + 5 * y] ^ chi_and[lane]
    });
    let mut output = core::array::from_fn::<_, 25, _>(|lane| permuted[lane] ^ chi_mask[lane]);
    output[0] ^= round_constant;
    *state = output;
    Ok(())
}

pub fn checked_profile_wire_count(permutations: usize) -> Result<usize, KeccakCircuitError> {
    circuit_report()
        .padded_wires_per_permutation
        .checked_mul(permutations)
        .ok_or(KeccakCircuitError::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha3_air::keccak_f1600_round;

    #[test]
    fn descriptor_dimensions_are_exact_and_internally_consistent() {
        let report = circuit_report();
        assert_eq!(report.depth, 216);
        assert_eq!(report.maximum_raw_width, 3_200);
        assert_eq!(report.maximum_padded_width, 4_096);
        assert_eq!(report.xor_gates_per_permutation, 192_000);
        assert_eq!(report.and_gates_per_permutation, 38_400);
        assert_eq!(report.relay_gates_per_permutation, 230_400);
        assert_eq!(report.padded_wires_per_permutation, 589_824);
        for layer in ROUND_LAYERS {
            assert_eq!(
                layer.raw_width,
                layer.xor_gates + layer.and_gates + layer.relay_gates
            );
            assert!(layer.padded_width.is_power_of_two());
            assert!(layer.padded_width >= layer.raw_width);
        }
    }

    #[test]
    fn generated_layers_match_the_independent_scalar_rounds() {
        let mut generated =
            core::array::from_fn(|lane| (lane as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let mut expected = generated;
        for round in 0..usize::from(KECCAK_ROUNDS) {
            execute_layered_keccak_round(&mut generated, round).unwrap();
            keccak_f1600_round(&mut expected, round).unwrap();
            assert_eq!(generated, expected, "round {round}");
        }
    }

    #[test]
    fn invalid_round_fails_closed_and_profile_counts_are_checked() {
        assert_eq!(
            execute_layered_keccak_round(&mut [0_u64; 25], 24),
            Err(KeccakCircuitError::Round)
        );
        assert_eq!(
            checked_profile_wire_count(usize::MAX),
            Err(KeccakCircuitError::Overflow)
        );
    }
}
