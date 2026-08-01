//! Degree-two batch sumcheck for multilinear products with different sizes.
//!
//! This is the algebra used by zkDeepFold to reduce evaluations of the hidden
//! polynomial and its auxiliary random polynomial to one shared random point.
//! A shorter polynomial is interpreted as a function of the suffix variables,
//! exactly as in Appendix D of DeepFold. Challenges remain external,
//! authenticated public-coin inputs; there is no Fiat--Shamir path here.

use alloc::{vec, vec::Vec};
use core::fmt;

use crate::field::Fp16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchProductClaim {
    pub left_evaluations: Vec<Fp16>,
    pub right_evaluations: Vec<Fp16>,
    pub claimed_sum: Fp16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchProductSumcheckProof {
    pub rounds: Vec<[Fp16; 3]>,
    pub terminal_left: Vec<Fp16>,
    pub terminal_right: Vec<Fp16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchProductSumcheckError {
    Empty,
    Shape,
    Claim,
    ChallengeCount,
    Sequence,
    Incomplete,
    Terminal,
}

impl fmt::Display for BatchProductSumcheckError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "BL-PQ512 multilinear batch sumcheck error: {self:?}"
        )
    }
}

impl core::error::Error for BatchProductSumcheckError {}

fn evaluate_quadratic(coefficients: [Fp16; 3], point: Fp16) -> Fp16 {
    coefficients[0] + point * (coefficients[1] + point * coefficients[2])
}

pub(crate) fn sum_product(left: &[Fp16], right: &[Fp16]) -> Fp16 {
    left.iter()
        .copied()
        .zip(right.iter().copied())
        .fold(Fp16::ZERO, |sum, (a, b)| sum + a * b)
}

fn power(base: Fp16, exponent: usize) -> Fp16 {
    (0..exponent).fold(Fp16::ONE, |value, _| value * base)
}

fn variable_count(length: usize) -> Result<usize, BatchProductSumcheckError> {
    if length == 0 || !length.is_power_of_two() {
        return Err(BatchProductSumcheckError::Shape);
    }
    Ok(length.ilog2() as usize)
}

fn validate_claims(
    claims: &[BatchProductClaim],
) -> Result<(usize, Vec<usize>), BatchProductSumcheckError> {
    if claims.is_empty() {
        return Err(BatchProductSumcheckError::Empty);
    }
    let mut variable_counts = Vec::with_capacity(claims.len());
    for claim in claims {
        if claim.left_evaluations.len() != claim.right_evaluations.len() {
            return Err(BatchProductSumcheckError::Shape);
        }
        let variables = variable_count(claim.left_evaluations.len())?;
        if sum_product(&claim.left_evaluations, &claim.right_evaluations) != claim.claimed_sum {
            return Err(BatchProductSumcheckError::Claim);
        }
        variable_counts.push(variables);
    }
    let maximum = variable_counts
        .iter()
        .copied()
        .max()
        .ok_or(BatchProductSumcheckError::Empty)?;
    if maximum == 0 {
        return Err(BatchProductSumcheckError::Shape);
    }
    Ok((maximum, variable_counts))
}

/// Boolean-hypercube evaluations of the multilinear equality polynomial.
pub fn equality_evaluations(point: &[Fp16]) -> Result<Vec<Fp16>, BatchProductSumcheckError> {
    if point.is_empty() || point.len() >= usize::BITS as usize {
        return Err(BatchProductSumcheckError::Shape);
    }
    let mut evaluations = vec![Fp16::ONE];
    for challenge in point {
        let one_minus = Fp16::ONE - *challenge;
        let previous = evaluations.len();
        evaluations.resize(2 * previous, Fp16::ZERO);
        for index in (0..previous).rev() {
            let value = evaluations[index];
            evaluations[index] = value * one_minus;
            evaluations[previous + index] = value * *challenge;
        }
    }
    Ok(evaluations)
}

/// Form the product-sum claim `sum_b f(b) eq(b, point) = f(point)`.
pub fn multilinear_evaluation_product_claim(
    evaluations: &[Fp16],
    point: &[Fp16],
    claimed_value: Fp16,
) -> Result<BatchProductClaim, BatchProductSumcheckError> {
    if evaluations.len() != 1_usize << point.len() {
        return Err(BatchProductSumcheckError::Shape);
    }
    let claim = BatchProductClaim {
        left_evaluations: evaluations.to_vec(),
        right_evaluations: equality_evaluations(point)?,
        claimed_sum: claimed_value,
    };
    if sum_product(&claim.left_evaluations, &claim.right_evaluations) != claimed_value {
        return Err(BatchProductSumcheckError::Claim);
    }
    Ok(claim)
}

fn initial_claim(
    claimed_sums: &[Fp16],
    variable_counts: &[usize],
    maximum_variables: usize,
    mixing_challenge: Fp16,
) -> Result<Fp16, BatchProductSumcheckError> {
    if claimed_sums.is_empty() || claimed_sums.len() != variable_counts.len() {
        return Err(BatchProductSumcheckError::Shape);
    }
    let two = Fp16::ONE + Fp16::ONE;
    let mut weight = Fp16::ONE;
    let mut combined = Fp16::ZERO;
    for (claim, variables) in claimed_sums
        .iter()
        .copied()
        .zip(variable_counts.iter().copied())
    {
        if variables > maximum_variables {
            return Err(BatchProductSumcheckError::Shape);
        }
        combined = combined + weight * power(two, maximum_variables - variables) * claim;
        weight = weight * mixing_challenge;
    }
    Ok(combined)
}

/// Sequential verifier boundary for an authenticated-public-coin transcript.
///
/// The mixing challenge must be sampled only after all input claims are fixed.
/// Each round message must then be published before its corresponding
/// authenticated challenge is accepted.
pub struct BatchProductSumcheckState {
    current_claim: Fp16,
    variable_counts: Vec<usize>,
    mixing_challenge: Fp16,
    maximum_variables: usize,
    accepted_challenges: usize,
    pending: Option<[Fp16; 3]>,
    rounds: Vec<[Fp16; 3]>,
}

impl BatchProductSumcheckState {
    pub fn new(
        claimed_sums: &[Fp16],
        variable_counts: &[usize],
        maximum_variables: usize,
        mixing_challenge: Fp16,
    ) -> Result<Self, BatchProductSumcheckError> {
        if maximum_variables == 0
            || variable_counts
                .iter()
                .any(|variables| *variables > maximum_variables)
        {
            return Err(BatchProductSumcheckError::Shape);
        }
        Ok(Self {
            current_claim: initial_claim(
                claimed_sums,
                variable_counts,
                maximum_variables,
                mixing_challenge,
            )?,
            variable_counts: variable_counts.to_vec(),
            mixing_challenge,
            maximum_variables,
            accepted_challenges: 0,
            pending: None,
            rounds: Vec::with_capacity(maximum_variables),
        })
    }

    pub fn publish_round(
        &mut self,
        coefficients: [Fp16; 3],
    ) -> Result<(), BatchProductSumcheckError> {
        if self.pending.is_some() || self.accepted_challenges >= self.maximum_variables {
            return Err(BatchProductSumcheckError::Sequence);
        }
        if coefficients[0] + coefficients[0] + coefficients[1] + coefficients[2]
            != self.current_claim
        {
            return Err(BatchProductSumcheckError::Claim);
        }
        self.pending = Some(coefficients);
        Ok(())
    }

    pub fn accept_authenticated_challenge(
        &mut self,
        challenge: Fp16,
    ) -> Result<(), BatchProductSumcheckError> {
        let coefficients = self
            .pending
            .take()
            .ok_or(BatchProductSumcheckError::Sequence)?;
        self.current_claim = evaluate_quadratic(coefficients, challenge);
        self.rounds.push(coefficients);
        self.accepted_challenges += 1;
        Ok(())
    }

    pub fn finish(
        self,
        terminal_left: &[Fp16],
        terminal_right: &[Fp16],
    ) -> Result<BatchProductSumcheckProof, BatchProductSumcheckError> {
        if self.pending.is_some() || self.accepted_challenges != self.maximum_variables {
            return Err(BatchProductSumcheckError::Incomplete);
        }
        if terminal_left.len() != self.variable_counts.len()
            || terminal_right.len() != self.variable_counts.len()
        {
            return Err(BatchProductSumcheckError::Terminal);
        }
        let mut weight = Fp16::ONE;
        let mut terminal_claim = Fp16::ZERO;
        for (left, right) in terminal_left
            .iter()
            .copied()
            .zip(terminal_right.iter().copied())
        {
            terminal_claim = terminal_claim + weight * left * right;
            weight = weight * self.mixing_challenge;
        }
        if terminal_claim != self.current_claim {
            return Err(BatchProductSumcheckError::Terminal);
        }
        Ok(BatchProductSumcheckProof {
            rounds: self.rounds,
            terminal_left: terminal_left.to_vec(),
            terminal_right: terminal_right.to_vec(),
        })
    }
}

pub(crate) fn fold_table(values: &mut Vec<Fp16>, challenge: Fp16) {
    for index in 0..values.len() / 2 {
        let left = values[2 * index];
        let right = values[2 * index + 1];
        values[index] = left + challenge * (right - left);
    }
    values.truncate(values.len() / 2);
}

pub(crate) fn product_round_coefficients(
    left: &[Fp16],
    right: &[Fp16],
) -> Result<[Fp16; 3], BatchProductSumcheckError> {
    if left.len() != right.len() || left.len() < 2 || !left.len().is_power_of_two() {
        return Err(BatchProductSumcheckError::Shape);
    }
    let mut coefficients = [Fp16::ZERO; 3];
    for pair in 0..left.len() / 2 {
        let left_zero = left[2 * pair];
        let left_delta = left[2 * pair + 1] - left_zero;
        let right_zero = right[2 * pair];
        let right_delta = right[2 * pair + 1] - right_zero;
        coefficients[0] = coefficients[0] + left_zero * right_zero;
        coefficients[1] = coefficients[1] + left_zero * right_delta + left_delta * right_zero;
        coefficients[2] = coefficients[2] + left_delta * right_delta;
    }
    Ok(coefficients)
}

#[cfg(feature = "parallel")]
pub(crate) fn product_round_coefficients_parallel(
    left: &[Fp16],
    right: &[Fp16],
    workers: usize,
) -> Result<[Fp16; 3], BatchProductSumcheckError> {
    if workers == 0 {
        return Err(BatchProductSumcheckError::Shape);
    }
    let pair_count = left.len() / 2;
    if workers == 1 || pair_count < 1 << 14 {
        return product_round_coefficients(left, right);
    }
    let worker_count = workers.min(pair_count);
    let chunk_pairs = pair_count.div_ceil(worker_count);
    let partials = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(worker_count);
        for worker in 0..worker_count {
            let start_pair = worker * chunk_pairs;
            let end_pair = (start_pair + chunk_pairs).min(pair_count);
            if start_pair == end_pair {
                continue;
            }
            handles.push(scope.spawn(move || {
                product_round_coefficients(
                    &left[2 * start_pair..2 * end_pair],
                    &right[2 * start_pair..2 * end_pair],
                )
            }));
        }
        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .map_err(|_| BatchProductSumcheckError::Shape)?
            })
            .collect::<Result<Vec<_>, _>>()
    })?;
    Ok(partials
        .into_iter()
        .fold([Fp16::ZERO; 3], |mut combined, partial| {
            for index in 0..3 {
                combined[index] = combined[index] + partial[index];
            }
            combined
        }))
}

#[cfg(feature = "parallel")]
pub(crate) fn sum_product_parallel(
    left: &[Fp16],
    right: &[Fp16],
    workers: usize,
) -> Result<Fp16, BatchProductSumcheckError> {
    if left.len() != right.len() || left.is_empty() || workers == 0 {
        return Err(BatchProductSumcheckError::Shape);
    }
    if workers == 1 || left.len() < 1 << 15 {
        return Ok(sum_product(left, right));
    }
    let worker_count = workers.min(left.len());
    let chunk = left.len().div_ceil(worker_count);
    let partials = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(worker_count);
        for worker in 0..worker_count {
            let start = worker * chunk;
            let end = (start + chunk).min(left.len());
            if start == end {
                continue;
            }
            handles.push(scope.spawn(move || sum_product(&left[start..end], &right[start..end])));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().map_err(|_| BatchProductSumcheckError::Shape))
            .collect::<Result<Vec<_>, _>>()
    })?;
    Ok(partials
        .into_iter()
        .fold(Fp16::ZERO, |sum, partial| sum + partial))
}

#[cfg(feature = "parallel")]
pub(crate) fn fold_table_parallel(
    values: &mut Vec<Fp16>,
    challenge: Fp16,
    workers: usize,
) -> Result<(), BatchProductSumcheckError> {
    if values.len() < 2 || !values.len().is_power_of_two() || workers == 0 {
        return Err(BatchProductSumcheckError::Shape);
    }
    let output_len = values.len() / 2;
    if workers == 1 || output_len < 1 << 14 {
        fold_table(values, challenge);
        return Ok(());
    }
    let worker_count = workers.min(output_len);
    let chunk = output_len.div_ceil(worker_count);
    let source = values.as_slice();
    let parts = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(worker_count);
        for worker in 0..worker_count {
            let start = worker * chunk;
            let end = (start + chunk).min(output_len);
            if start == end {
                continue;
            }
            handles.push(scope.spawn(move || {
                (start..end)
                    .map(|index| {
                        let left = source[2 * index];
                        let right = source[2 * index + 1];
                        left + challenge * (right - left)
                    })
                    .collect::<Vec<_>>()
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().map_err(|_| BatchProductSumcheckError::Shape))
            .collect::<Result<Vec<_>, _>>()
    })?;
    let mut folded = Vec::with_capacity(output_len);
    for part in parts {
        folded.extend(part);
    }
    *values = folded;
    Ok(())
}

#[cfg(feature = "parallel")]
pub(crate) fn equality_evaluations_parallel(
    point: &[Fp16],
    workers: usize,
) -> Result<Vec<Fp16>, BatchProductSumcheckError> {
    if point.is_empty() || point.len() >= usize::BITS as usize || workers == 0 {
        return Err(BatchProductSumcheckError::Shape);
    }
    let mut evaluations = vec![Fp16::ONE];
    for challenge in point {
        let one_minus = Fp16::ONE - *challenge;
        let previous = evaluations.len();
        evaluations.resize(2 * previous, Fp16::ZERO);
        let (low, high) = evaluations.split_at_mut(previous);
        if workers == 1 || previous < 1 << 15 {
            for index in 0..previous {
                let value = low[index];
                low[index] = value * one_minus;
                high[index] = value * *challenge;
            }
            continue;
        }
        let chunk = previous.div_ceil(workers.min(previous));
        std::thread::scope(|scope| {
            for (low_chunk, high_chunk) in low.chunks_mut(chunk).zip(high.chunks_mut(chunk)) {
                scope.spawn(move || {
                    for (low_value, high_value) in low_chunk.iter_mut().zip(high_chunk) {
                        let value = *low_value;
                        *low_value = value * one_minus;
                        *high_value = value * *challenge;
                    }
                });
            }
        });
    }
    Ok(evaluations)
}

/// Deterministic algebra control using a completed challenge vector.
///
/// Production callers must expose the same round messages through
/// [`BatchProductSumcheckState`] and obtain each challenge only afterwards.
pub fn prove_batch_product_sumcheck_control(
    claims: &[BatchProductClaim],
    mixing_challenge: Fp16,
    challenges: &[Fp16],
) -> Result<BatchProductSumcheckProof, BatchProductSumcheckError> {
    let (maximum_variables, variable_counts) = validate_claims(claims)?;
    if challenges.len() != maximum_variables {
        return Err(BatchProductSumcheckError::ChallengeCount);
    }
    let claimed_sums = claims
        .iter()
        .map(|claim| claim.claimed_sum)
        .collect::<Vec<_>>();
    let mut state = BatchProductSumcheckState::new(
        &claimed_sums,
        &variable_counts,
        maximum_variables,
        mixing_challenge,
    )?;
    let mut working = claims
        .iter()
        .map(|claim| {
            (
                claim.left_evaluations.clone(),
                claim.right_evaluations.clone(),
            )
        })
        .collect::<Vec<_>>();
    let inverse_two = (Fp16::ONE + Fp16::ONE)
        .inverse()
        .map_err(|_| BatchProductSumcheckError::Shape)?;

    for (round, challenge) in challenges.iter().copied().enumerate() {
        let mut coefficients = [Fp16::ZERO; 3];
        let mut weight = Fp16::ONE;
        for (claim_index, variables) in variable_counts.iter().copied().enumerate() {
            let inactive_prefix = maximum_variables - variables;
            if round < inactive_prefix {
                let remaining_inactive = inactive_prefix - round;
                coefficients[0] = coefficients[0]
                    + weight
                        * power(Fp16::ONE + Fp16::ONE, remaining_inactive)
                        * claims[claim_index].claimed_sum
                        * inverse_two;
            } else {
                let (left, right) = &working[claim_index];
                for pair in 0..left.len() / 2 {
                    let left_zero = left[2 * pair];
                    let left_delta = left[2 * pair + 1] - left_zero;
                    let right_zero = right[2 * pair];
                    let right_delta = right[2 * pair + 1] - right_zero;
                    coefficients[0] = coefficients[0] + weight * left_zero * right_zero;
                    coefficients[1] = coefficients[1]
                        + weight * (left_zero * right_delta + left_delta * right_zero);
                    coefficients[2] = coefficients[2] + weight * left_delta * right_delta;
                }
            }
            weight = weight * mixing_challenge;
        }
        state.publish_round(coefficients)?;
        state.accept_authenticated_challenge(challenge)?;
        for (claim_index, variables) in variable_counts.iter().copied().enumerate() {
            if round >= maximum_variables - variables {
                fold_table(&mut working[claim_index].0, challenge);
                fold_table(&mut working[claim_index].1, challenge);
            }
        }
    }

    let terminal_left = working.iter().map(|claim| claim.0[0]).collect::<Vec<_>>();
    let terminal_right = working.iter().map(|claim| claim.1[0]).collect::<Vec<_>>();
    state.finish(&terminal_left, &terminal_right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::M31;
    use crate::multilinear_pcs::evaluate_multilinear;

    fn fp(value: u32) -> Fp16 {
        Fp16::from_m31(M31::from_canonical(value).unwrap())
    }

    fn claim(left: Vec<Fp16>, right: Vec<Fp16>) -> BatchProductClaim {
        let claimed_sum = sum_product(&left, &right);
        BatchProductClaim {
            left_evaluations: left,
            right_evaluations: right,
            claimed_sum,
        }
    }

    #[test]
    fn different_size_batch_sumcheck_roundtrips_sequentially() {
        let claims = [
            claim((1..=8).map(fp).collect(), (11..=18).map(fp).collect()),
            claim((21..=24).map(fp).collect(), (31..=34).map(fp).collect()),
        ];
        let challenges = [fp(41), fp(43), fp(47)];
        let mixing = fp(53);
        let proof = prove_batch_product_sumcheck_control(&claims, mixing, &challenges).unwrap();

        let variable_counts = [3, 2];
        let claimed_sums = claims.map(|claim| claim.claimed_sum);
        let mut verifier =
            BatchProductSumcheckState::new(&claimed_sums, &variable_counts, 3, mixing).unwrap();
        for (message, challenge) in proof.rounds.iter().copied().zip(challenges.iter().copied()) {
            verifier.publish_round(message).unwrap();
            verifier.accept_authenticated_challenge(challenge).unwrap();
        }
        verifier
            .finish(&proof.terminal_left, &proof.terminal_right)
            .unwrap();
    }

    #[test]
    fn verifier_rejects_order_claim_and_terminal_mutations() {
        let claims = [
            claim(vec![fp(2), fp(3), fp(5), fp(7)], vec![fp(11); 4]),
            claim(vec![fp(13), fp(17)], vec![fp(19), fp(23)]),
        ];
        let challenges = [fp(29), fp(31)];
        let mixing = fp(37);
        let proof = prove_batch_product_sumcheck_control(&claims, mixing, &challenges).unwrap();
        let claimed_sums = claims.map(|claim| claim.claimed_sum);

        let mut ordering =
            BatchProductSumcheckState::new(&claimed_sums, &[2, 1], 2, mixing).unwrap();
        assert_eq!(
            ordering.accept_authenticated_challenge(challenges[0]),
            Err(BatchProductSumcheckError::Sequence)
        );

        let mut bad_round = proof.rounds[0];
        bad_round[0] = bad_round[0] + Fp16::ONE;
        assert_eq!(
            ordering.publish_round(bad_round),
            Err(BatchProductSumcheckError::Claim)
        );

        let mut verifier =
            BatchProductSumcheckState::new(&claimed_sums, &[2, 1], 2, mixing).unwrap();
        for (message, challenge) in proof.rounds.iter().copied().zip(challenges.iter().copied()) {
            verifier.publish_round(message).unwrap();
            verifier.accept_authenticated_challenge(challenge).unwrap();
        }
        let mut terminal_left = proof.terminal_left.clone();
        terminal_left[0] = terminal_left[0] + Fp16::ONE;
        assert_eq!(
            verifier.finish(&terminal_left, &proof.terminal_right),
            Err(BatchProductSumcheckError::Terminal)
        );
    }

    #[test]
    fn equality_product_claim_matches_multilinear_evaluation() {
        let evaluations = (1..=8).map(fp).collect::<Vec<_>>();
        let point = [fp(11), fp(13), fp(17)];
        let value = evaluate_multilinear(&evaluations, &point).unwrap();
        let claim = multilinear_evaluation_product_claim(&evaluations, &point, value).unwrap();
        assert_eq!(
            sum_product(&claim.left_evaluations, &claim.right_evaluations),
            value
        );
        assert_eq!(
            multilinear_evaluation_product_claim(&evaluations, &point, value + Fp16::ONE),
            Err(BatchProductSumcheckError::Claim)
        );
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn parallel_primitives_match_scalar_above_parallel_thresholds() {
        let point = (0..16).map(|index| fp(101 + 2 * index)).collect::<Vec<_>>();
        let equality = equality_evaluations(&point).unwrap();
        let left = (0..1 << 16)
            .map(|index| fp(1 + (index as u32 * 17) % 65_521))
            .collect::<Vec<_>>();
        let right = (0..1 << 16)
            .map(|index| fp(3 + (index as u32 * 29) % 65_519))
            .collect::<Vec<_>>();
        let coefficients = product_round_coefficients(&left, &right).unwrap();
        let product = sum_product(&left, &right);
        let challenge = fp(211);
        let mut folded = left.clone();
        fold_table(&mut folded, challenge);

        for workers in [1, 2, 4] {
            assert_eq!(
                equality_evaluations_parallel(&point, workers).unwrap(),
                equality
            );
            assert_eq!(
                product_round_coefficients_parallel(&left, &right, workers).unwrap(),
                coefficients
            );
            assert_eq!(
                sum_product_parallel(&left, &right, workers).unwrap(),
                product
            );
            let mut parallel_folded = left.clone();
            fold_table_parallel(&mut parallel_folded, challenge, workers).unwrap();
            assert_eq!(parallel_folded, folded);
        }
    }
}
