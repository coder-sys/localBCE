//! Multi-factor sumcheck for products of publicly shifted multilinear tables.
//!
//! A factor with XOR shift `s` represents `f(x xor s)` on the Boolean
//! hypercube. The shift is public wiring, and all factors are bound together
//! in one low-bit-first sumcheck round. Challenges are supplied externally;
//! this module contains no Fiat--Shamir transform.

use alloc::{vec, vec::Vec};
use core::fmt;

use crate::field::Fp16;

pub const MAX_MULTI_FACTORS: usize = 11;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShiftedMultilinearFactor {
    pub evaluations: Vec<Fp16>,
    pub xor_shift: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultiFactorSumcheckProof {
    pub rounds: Vec<Vec<Fp16>>,
    pub terminal_factors: Vec<Fp16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MultiFactorSumcheckError {
    Empty,
    Shape,
    FactorCount,
    Shift,
    ChallengeCount,
    Sequence,
    Claim,
    Terminal,
}

impl fmt::Display for MultiFactorSumcheckError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "multi-factor sumcheck error: {self:?}")
    }
}

impl core::error::Error for MultiFactorSumcheckError {}

fn validate_factors(
    factors: &[ShiftedMultilinearFactor],
) -> Result<(usize, usize), MultiFactorSumcheckError> {
    if factors.is_empty() {
        return Err(MultiFactorSumcheckError::Empty);
    }
    if factors.len() > MAX_MULTI_FACTORS {
        return Err(MultiFactorSumcheckError::FactorCount);
    }
    let length = factors[0].evaluations.len();
    if length < 2 || !length.is_power_of_two() {
        return Err(MultiFactorSumcheckError::Shape);
    }
    for factor in factors {
        if factor.evaluations.len() != length {
            return Err(MultiFactorSumcheckError::Shape);
        }
        if factor.xor_shift >= length {
            return Err(MultiFactorSumcheckError::Shift);
        }
    }
    Ok((length, length.ilog2() as usize))
}

fn polynomial_evaluation(coefficients: &[Fp16], point: Fp16) -> Fp16 {
    coefficients
        .iter()
        .copied()
        .rev()
        .fold(Fp16::ZERO, |value, coefficient| value * point + coefficient)
}

fn product(values: impl IntoIterator<Item = Fp16>) -> Fp16 {
    values
        .into_iter()
        .fold(Fp16::ONE, |value, factor| value * factor)
}

pub fn naive_shifted_product_sum(
    factors: &[ShiftedMultilinearFactor],
) -> Result<Fp16, MultiFactorSumcheckError> {
    let (length, _) = validate_factors(factors)?;
    Ok((0..length).fold(Fp16::ZERO, |sum, index| {
        sum + product(
            factors
                .iter()
                .map(|factor| factor.evaluations[index ^ factor.xor_shift]),
        )
    }))
}

fn fold_table(values: &mut Vec<Fp16>, challenge: Fp16) {
    for index in 0..values.len() / 2 {
        let zero = values[2 * index];
        values[index] = zero + challenge * (values[2 * index + 1] - zero);
    }
    values.truncate(values.len() / 2);
}

fn round_coefficients(tables: &[Vec<Fp16>]) -> Result<Vec<Fp16>, MultiFactorSumcheckError> {
    if tables.is_empty()
        || tables[0].len() < 2
        || !tables[0].len().is_power_of_two()
        || tables.iter().any(|table| table.len() != tables[0].len())
    {
        return Err(MultiFactorSumcheckError::Shape);
    }
    let mut coefficients = vec![Fp16::ZERO; tables.len() + 1];
    for pair in 0..tables[0].len() / 2 {
        let mut local = vec![Fp16::ONE];
        for table in tables {
            let zero = table[2 * pair];
            let delta = table[2 * pair + 1] - zero;
            let mut next = vec![Fp16::ZERO; local.len() + 1];
            for (degree, coefficient) in local.iter().copied().enumerate() {
                next[degree] = next[degree] + coefficient * zero;
                next[degree + 1] = next[degree + 1] + coefficient * delta;
            }
            local = next;
        }
        for (destination, coefficient) in coefficients.iter_mut().zip(local) {
            *destination = *destination + coefficient;
        }
    }
    Ok(coefficients)
}

pub struct MultiFactorSumcheckState {
    current_claim: Fp16,
    factor_count: usize,
    round_count: usize,
    accepted_challenges: usize,
    pending: Option<Vec<Fp16>>,
    rounds: Vec<Vec<Fp16>>,
}

impl MultiFactorSumcheckState {
    pub fn new(
        initial_claim: Fp16,
        factor_count: usize,
        round_count: usize,
    ) -> Result<Self, MultiFactorSumcheckError> {
        if factor_count == 0 || factor_count > MAX_MULTI_FACTORS || round_count == 0 {
            return Err(MultiFactorSumcheckError::Shape);
        }
        Ok(Self {
            current_claim: initial_claim,
            factor_count,
            round_count,
            accepted_challenges: 0,
            pending: None,
            rounds: Vec::with_capacity(round_count),
        })
    }

    pub fn publish_round(&mut self, coefficients: &[Fp16]) -> Result<(), MultiFactorSumcheckError> {
        if self.pending.is_some() || self.accepted_challenges >= self.round_count {
            return Err(MultiFactorSumcheckError::Sequence);
        }
        if coefficients.len() != self.factor_count + 1 {
            return Err(MultiFactorSumcheckError::Shape);
        }
        if polynomial_evaluation(coefficients, Fp16::ZERO)
            + polynomial_evaluation(coefficients, Fp16::ONE)
            != self.current_claim
        {
            return Err(MultiFactorSumcheckError::Claim);
        }
        self.pending = Some(coefficients.to_vec());
        Ok(())
    }

    pub fn accept_authenticated_challenge(
        &mut self,
        challenge: Fp16,
    ) -> Result<(), MultiFactorSumcheckError> {
        let coefficients = self
            .pending
            .take()
            .ok_or(MultiFactorSumcheckError::Sequence)?;
        self.current_claim = polynomial_evaluation(&coefficients, challenge);
        self.rounds.push(coefficients);
        self.accepted_challenges += 1;
        Ok(())
    }

    pub fn finish(
        self,
        terminal_factors: &[Fp16],
    ) -> Result<MultiFactorSumcheckProof, MultiFactorSumcheckError> {
        if self.pending.is_some() || self.accepted_challenges != self.round_count {
            return Err(MultiFactorSumcheckError::Sequence);
        }
        if terminal_factors.len() != self.factor_count
            || product(terminal_factors.iter().copied()) != self.current_claim
        {
            return Err(MultiFactorSumcheckError::Terminal);
        }
        Ok(MultiFactorSumcheckProof {
            rounds: self.rounds,
            terminal_factors: terminal_factors.to_vec(),
        })
    }
}

pub fn prove_multi_factor_sumcheck_control(
    factors: &[ShiftedMultilinearFactor],
    challenges: &[Fp16],
) -> Result<MultiFactorSumcheckProof, MultiFactorSumcheckError> {
    let (length, variables) = validate_factors(factors)?;
    if challenges.len() != variables {
        return Err(MultiFactorSumcheckError::ChallengeCount);
    }
    let initial_claim = naive_shifted_product_sum(factors)?;
    let mut state = MultiFactorSumcheckState::new(initial_claim, factors.len(), variables)?;
    let mut tables = factors
        .iter()
        .map(|factor| {
            (0..length)
                .map(|index| factor.evaluations[index ^ factor.xor_shift])
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    for challenge in challenges.iter().copied() {
        let coefficients = round_coefficients(&tables)?;
        state.publish_round(&coefficients)?;
        state.accept_authenticated_challenge(challenge)?;
        for table in &mut tables {
            fold_table(table, challenge);
        }
    }
    let terminal_factors = tables.iter().map(|table| table[0]).collect::<Vec<_>>();
    state.finish(&terminal_factors)
}

pub fn verify_multi_factor_sumcheck(
    initial_claim: Fp16,
    factor_count: usize,
    challenges: &[Fp16],
    proof: &MultiFactorSumcheckProof,
) -> Result<(), MultiFactorSumcheckError> {
    if proof.rounds.len() != challenges.len() {
        return Err(MultiFactorSumcheckError::ChallengeCount);
    }
    let mut state = MultiFactorSumcheckState::new(initial_claim, factor_count, challenges.len())?;
    for (message, challenge) in proof.rounds.iter().zip(challenges.iter().copied()) {
        state.publish_round(message)?;
        state.accept_authenticated_challenge(challenge)?;
    }
    state.finish(&proof.terminal_factors)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{M31, M31_MODULUS};

    fn random_fp16(state: &mut u64) -> Fp16 {
        let mut coefficients = [0_u32; 16];
        for coefficient in &mut coefficients {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *coefficient = (*state as u32) % M31_MODULUS;
        }
        Fp16::from_coefficients(coefficients).unwrap()
    }

    fn evaluate_multilinear(values: &[Fp16], point: &[Fp16]) -> Fp16 {
        let mut folded = values.to_vec();
        for coordinate in point.iter().copied() {
            fold_table(&mut folded, coordinate);
        }
        folded[0]
    }

    fn naive_partial_round_evaluation(
        factors: &[ShiftedMultilinearFactor],
        prefix: &[Fp16],
        round_point: Fp16,
    ) -> Fp16 {
        let variables = factors[0].evaluations.len().ilog2() as usize;
        let remaining = variables - prefix.len() - 1;
        (0..1_usize << remaining).fold(Fp16::ZERO, |sum, suffix| {
            let mut point = prefix.to_vec();
            point.push(round_point);
            for bit in 0..remaining {
                point.push(Fp16::from_m31(if (suffix >> bit) & 1 == 0 {
                    M31::ZERO
                } else {
                    M31::ONE
                }));
            }
            sum + product(factors.iter().map(|factor| {
                let shifted = point
                    .iter()
                    .copied()
                    .enumerate()
                    .map(|(bit, coordinate)| {
                        if (factor.xor_shift >> bit) & 1 == 0 {
                            coordinate
                        } else {
                            Fp16::ONE - coordinate
                        }
                    })
                    .collect::<Vec<_>>();
                evaluate_multilinear(&factor.evaluations, &shifted)
            }))
        })
    }

    fn interpolate_integer_nodes(evaluations: &[Fp16]) -> Vec<Fp16> {
        let mut result = vec![Fp16::ZERO; evaluations.len()];
        for (node, evaluation) in evaluations.iter().copied().enumerate() {
            let mut basis = vec![Fp16::ONE];
            let mut denominator = Fp16::ONE;
            let node_value = Fp16::from_m31(M31::from_canonical(node as u32).unwrap());
            for other in 0..evaluations.len() {
                if other == node {
                    continue;
                }
                let other_value = Fp16::from_m31(M31::from_canonical(other as u32).unwrap());
                let mut next = vec![Fp16::ZERO; basis.len() + 1];
                for (degree, coefficient) in basis.iter().copied().enumerate() {
                    next[degree] = next[degree] - coefficient * other_value;
                    next[degree + 1] = next[degree + 1] + coefficient;
                }
                basis = next;
                denominator = denominator * (node_value - other_value);
            }
            let scale = evaluation * denominator.inverse().unwrap();
            for (destination, coefficient) in result.iter_mut().zip(basis) {
                *destination = *destination + scale * coefficient;
            }
        }
        result
    }

    #[test]
    fn random_shifted_mle_rounds_match_naive_reference_exactly() {
        let mut state = 0x8f5d_0b27_1a6c_e319_u64;
        for factor_count in [1, 3, 11] {
            for _case in 0..4 {
                let variables = 5;
                let length = 1 << variables;
                let factors = (0..factor_count)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        ShiftedMultilinearFactor {
                            evaluations: (0..length).map(|_| random_fp16(&mut state)).collect(),
                            xor_shift: (state as usize) & (length - 1),
                        }
                    })
                    .collect::<Vec<_>>();
                let challenges = (0..variables)
                    .map(|_| random_fp16(&mut state))
                    .collect::<Vec<_>>();
                let initial_claim = naive_shifted_product_sum(&factors).unwrap();
                let proof = prove_multi_factor_sumcheck_control(&factors, &challenges).unwrap();
                verify_multi_factor_sumcheck(initial_claim, factor_count, &challenges, &proof)
                    .unwrap();

                let mut prefix = Vec::new();
                for (round, coefficients) in proof.rounds.iter().enumerate() {
                    let evaluations = (0..=factor_count)
                        .map(|node| {
                            naive_partial_round_evaluation(
                                &factors,
                                &prefix,
                                Fp16::from_m31(M31::from_canonical(node as u32).unwrap()),
                            )
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(*coefficients, interpolate_integer_nodes(&evaluations));
                    prefix.push(challenges[round]);
                }
                for (factor, terminal) in factors.iter().zip(&proof.terminal_factors) {
                    let shifted = challenges
                        .iter()
                        .copied()
                        .enumerate()
                        .map(|(bit, coordinate)| {
                            if (factor.xor_shift >> bit) & 1 == 0 {
                                coordinate
                            } else {
                                Fp16::ONE - coordinate
                            }
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(
                        *terminal,
                        evaluate_multilinear(&factor.evaluations, &shifted)
                    );
                }
            }
        }
    }

    #[test]
    fn malformed_shapes_and_transcript_order_fail_closed() {
        assert_eq!(
            prove_multi_factor_sumcheck_control(&[], &[]),
            Err(MultiFactorSumcheckError::Empty)
        );
        let factor = ShiftedMultilinearFactor {
            evaluations: vec![Fp16::ONE; 4],
            xor_shift: 4,
        };
        assert_eq!(
            prove_multi_factor_sumcheck_control(&[factor], &[Fp16::ONE; 2]),
            Err(MultiFactorSumcheckError::Shift)
        );
        let mut state = MultiFactorSumcheckState::new(Fp16::ONE, 3, 2).unwrap();
        assert_eq!(
            state.accept_authenticated_challenge(Fp16::ONE),
            Err(MultiFactorSumcheckError::Sequence)
        );
        assert_eq!(
            state.publish_round(&[Fp16::ZERO; 3]),
            Err(MultiFactorSumcheckError::Shape)
        );
    }
}
