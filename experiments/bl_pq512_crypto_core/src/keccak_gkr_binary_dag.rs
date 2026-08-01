//! Two-layer binary-native Keccak round DAG experiment.
//!
//! Characteristic two lets the five-input column parity and theta correction
//! stay linear. Rho and pi are public wire permutations, so the first layer
//! writes the permuted theta state directly. The second layer evaluates
//! `a + c + b*c + iota`, which is exactly `a XOR ((!b) AND c) XOR iota` on
//! Boolean inputs. This module is nonactivating and leaves the selected
//! M31/Fp16 proof path unchanged.

use alloc::{vec, vec::Vec};

use crate::{
    gf128::Gf128Triple,
    keccak_circuit::KeccakCircuitError,
    sha3_air::{ROTATION_OFFSETS, ROUND_CONSTANTS},
};

pub const BINARY_DAG_STATE_BITS: usize = 1_600;
pub const BINARY_DAG_PADDED_BITS: usize = 2_048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BinaryThetaGate {
    pub sources: [usize; 11],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BinaryChiGate {
    pub a: usize,
    pub b: usize,
    pub c: usize,
    pub constant: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryKeccakDagRound {
    pub theta: Vec<BinaryThetaGate>,
    pub chi_iota: Vec<BinaryChiGate>,
}

fn bit(x: usize, y: usize, z: usize) -> usize {
    64 * (x + 5 * y) + z
}

fn rho_pi_inverse() -> Result<Vec<usize>, KeccakCircuitError> {
    let mut inverse = vec![usize::MAX; BINARY_DAG_STATE_BITS];
    for (x, rotations) in ROTATION_OFFSETS.iter().enumerate() {
        for (y, rotation) in rotations.iter().copied().enumerate() {
            let destination_x = y;
            let destination_y = (2 * x + 3 * y) % 5;
            for z in 0..64 {
                let destination_z = (z + rotation as usize) % 64;
                inverse[bit(destination_x, destination_y, destination_z)] = bit(x, y, z);
            }
        }
    }
    if inverse.contains(&usize::MAX) {
        return Err(KeccakCircuitError::Overflow);
    }
    Ok(inverse)
}

pub fn build_binary_keccak_dag_round(
    round: usize,
) -> Result<BinaryKeccakDagRound, KeccakCircuitError> {
    let round_constant = *ROUND_CONSTANTS
        .get(round)
        .ok_or(KeccakCircuitError::Round)?;
    let inverse = rho_pi_inverse()?;

    let mut theta = Vec::with_capacity(BINARY_DAG_PADDED_BITS);
    for &source in inverse.iter().take(BINARY_DAG_STATE_BITS) {
        let lane = source / 64;
        let x = lane % 5;
        let y = lane / 5;
        let z = source % 64;
        let mut sources = [0_usize; 11];
        sources[0] = bit(x, y, z);
        for source_y in 0..5 {
            sources[1 + source_y] = bit((x + 4) % 5, source_y, z);
            sources[6 + source_y] = bit((x + 1) % 5, source_y, (z + 63) % 64);
        }
        theta.push(BinaryThetaGate { sources });
    }
    theta.resize(
        BINARY_DAG_PADDED_BITS,
        BinaryThetaGate {
            sources: [0_usize; 11],
        },
    );

    let mut chi_iota = Vec::with_capacity(BINARY_DAG_PADDED_BITS);
    for y in 0..5 {
        for x in 0..5 {
            for z in 0..64 {
                chi_iota.push(BinaryChiGate {
                    a: bit(x, y, z),
                    b: bit((x + 1) % 5, y, z),
                    c: bit((x + 2) % 5, y, z),
                    constant: x == 0 && y == 0 && ((round_constant >> z) & 1) == 1,
                });
            }
        }
    }
    chi_iota.resize(
        BINARY_DAG_PADDED_BITS,
        BinaryChiGate {
            a: 0,
            b: 0,
            c: 0,
            constant: false,
        },
    );

    Ok(BinaryKeccakDagRound { theta, chi_iota })
}

pub fn evaluate_binary_keccak_dag_round(
    dag: &BinaryKeccakDagRound,
    input: &[bool],
) -> Result<[Vec<bool>; 2], KeccakCircuitError> {
    if input.len() != BINARY_DAG_PADDED_BITS
        || dag.theta.len() != BINARY_DAG_PADDED_BITS
        || dag.chi_iota.len() != BINARY_DAG_PADDED_BITS
    {
        return Err(KeccakCircuitError::Overflow);
    }

    let mut theta = vec![false; BINARY_DAG_PADDED_BITS];
    for (output, gate) in dag.theta[..BINARY_DAG_STATE_BITS].iter().enumerate() {
        theta[output] = gate
            .sources
            .iter()
            .copied()
            .fold(false, |value, source| value ^ input[source]);
    }

    let mut chi = vec![false; BINARY_DAG_PADDED_BITS];
    for (output, gate) in dag.chi_iota[..BINARY_DAG_STATE_BITS].iter().enumerate() {
        chi[output] = theta[gate.a] ^ ((!theta[gate.b]) & theta[gate.c]) ^ gate.constant;
    }
    Ok([theta, chi])
}

pub fn evaluate_binary_chi_polynomial(
    a: Gf128Triple,
    b: Gf128Triple,
    c: Gf128Triple,
    constant: bool,
) -> Gf128Triple {
    let mut value = a + c + b * c;
    if constant {
        value += Gf128Triple::ONE;
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{gf128::Gf128, keccak_circuit::execute_layered_keccak_round};

    fn bits_from_state(state: &[u64; 25]) -> Vec<bool> {
        let mut bits = vec![false; BINARY_DAG_PADDED_BITS];
        for (lane, value) in state.iter().copied().enumerate() {
            for z in 0..64 {
                bits[64 * lane + z] = ((value >> z) & 1) == 1;
            }
        }
        bits
    }

    fn state_from_bits(bits: &[bool]) -> [u64; 25] {
        core::array::from_fn(|lane| {
            (0..64).fold(0_u64, |value, z| {
                value | (u64::from(bits[64 * lane + z]) << z)
            })
        })
    }

    fn embedded(value: bool) -> Gf128Triple {
        if value {
            Gf128Triple::ONE
        } else {
            Gf128Triple::ZERO
        }
    }

    #[test]
    fn binary_dag_geometry_has_two_boundaries_and_no_relays() {
        let dag = build_binary_keccak_dag_round(0).unwrap();
        assert_eq!(dag.theta.len(), BINARY_DAG_PADDED_BITS);
        assert_eq!(dag.chi_iota.len(), BINARY_DAG_PADDED_BITS);
        assert_eq!(2 * BINARY_DAG_STATE_BITS, 3_200);
        assert_eq!(2 * BINARY_DAG_PADDED_BITS, 4_096);
        assert!(dag.theta[..BINARY_DAG_STATE_BITS].iter().all(|gate| {
            gate.sources
                .iter()
                .all(|source| *source < BINARY_DAG_STATE_BITS)
        }));
        assert!(dag.chi_iota[..BINARY_DAG_STATE_BITS].iter().all(|gate| {
            gate.a < BINARY_DAG_STATE_BITS
                && gate.b < BINARY_DAG_STATE_BITS
                && gate.c < BINARY_DAG_STATE_BITS
        }));
    }

    #[test]
    fn binary_dag_round_matches_independent_keccak_for_10000_cases() {
        for case in 0_u64..10_000 {
            let round = (case as usize * 7) % 24;
            let mut expected = core::array::from_fn(|lane| {
                case.wrapping_add(1)
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    .rotate_left((lane as u32 * 11 + case as u32) & 63)
            });
            let input = bits_from_state(&expected);
            execute_layered_keccak_round(&mut expected, round).unwrap();
            let dag = build_binary_keccak_dag_round(round).unwrap();
            let boundaries = evaluate_binary_keccak_dag_round(&dag, &input).unwrap();
            assert_eq!(
                state_from_bits(boundaries.last().unwrap()),
                expected,
                "case={case} round={round}"
            );
        }
    }

    #[test]
    fn chi_polynomial_is_exact_on_the_boolean_cube() {
        for pattern in 0_u128..16 {
            let a = (pattern & 1) != 0;
            let b = (pattern & 2) != 0;
            let c = (pattern & 4) != 0;
            let constant = (pattern & 8) != 0;
            let actual =
                evaluate_binary_chi_polynomial(embedded(a), embedded(b), embedded(c), constant);
            let expected = embedded(a ^ ((!b) & c) ^ constant);
            assert_eq!(actual, expected);
        }

        let a = Gf128Triple([
            Gf128::from_u128(0x1234),
            Gf128::from_u128(0x5678),
            Gf128::from_u128(0x9abc),
        ]);
        let b = Gf128Triple([
            Gf128::from_u128(0xdef0),
            Gf128::from_u128(0x1357),
            Gf128::from_u128(0x2468),
        ]);
        let c = Gf128Triple([
            Gf128::from_u128(0xaaaa),
            Gf128::from_u128(0xbbbb),
            Gf128::from_u128(0xcccc),
        ]);
        assert_eq!(
            evaluate_binary_chi_polynomial(a, b, c, false),
            a + c + b * c
        );
    }
}
