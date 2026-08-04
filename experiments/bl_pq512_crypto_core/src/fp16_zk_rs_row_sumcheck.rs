//! Compact quadratic sumcheck for the 512-way row-batched PCS boundary.
//!
//! The committed source has 512 packed rows, each with 65,536 small-field
//! component coefficients.  Materializing those rows or their relation forms
//! would exceed the engineering memory target.  Instead, the producer supplies
//! the sixteen component-polynomial evaluations of each relevant row at each
//! fixed GKR low point. This module converts them into the exact fixed claim
//! count times sixteen Frobenius-conjugate source/relation states.
//!
//! Both sides of every state are folded independently.  Their product therefore
//! produces the exact degree-two sumcheck message and preserves the cross terms
//! required at a non-Boolean verifier challenge.  Folding pre-multiplied row
//! inner products would lose those cross terms and is forbidden.

use alloc::{vec, vec::Vec};
use core::fmt;

use crate::{
    field::{Fp16, M31_MODULUS},
    fp16_zk_rs_gkr_binding::{
        BOUNDARY_COUNT, COEFFICIENT_VARIABLES, DIRECT_CLAIM_START, Fp16ZkRsGkrBinding,
        GKR_CLAIM_COUNT, WORD_VARIABLES, WORDS_PER_BOUNDARY, coordinate_linearized_coefficients,
    },
    gkr_packed_bridge_fp16::PACKED_INSTANCES,
};

const GLOBAL_WORDS: usize = BOUNDARY_COUNT * WORDS_PER_BOUNDARY;
const LINEARIZED_STATES: usize = GKR_CLAIM_COUNT * PACKED_INSTANCES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fp16ZkRsRowSumcheckError {
    ClaimRowCount,
    WordRowCount,
    InitialTargetMismatch,
    WorkerPanic,
    RoundComplete,
    RoundIncomplete,
}

impl fmt::Display for Fp16ZkRsRowSumcheckError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Fp16 ZK-RS row sumcheck error: {self:?}")
    }
}

impl core::error::Error for Fp16ZkRsRowSumcheckError {}

fn fp16_basis() -> [Fp16; PACKED_INSTANCES] {
    core::array::from_fn(|coordinate| {
        let mut coefficients = [0_u32; PACKED_INSTANCES];
        coefficients[coordinate] = 1;
        Fp16::from_coefficients(coefficients).expect("basis coordinate is canonical")
    })
}

fn equality_weight(index: usize, point: &[Fp16]) -> Fp16 {
    point
        .iter()
        .copied()
        .enumerate()
        .fold(Fp16::ONE, |weight, (variable, challenge)| {
            if (index >> variable) & 1 == 1 {
                weight * challenge
            } else {
                weight * (Fp16::ONE - challenge)
            }
        })
}

#[cfg(feature = "parallel")]
fn claim_powers(challenge: Fp16) -> [Fp16; GKR_CLAIM_COUNT] {
    let mut power = Fp16::ONE;
    core::array::from_fn(|_| {
        let current = power;
        power = power * challenge;
        current
    })
}

#[cfg(feature = "parallel")]
fn row_states(
    binding: &Fp16ZkRsGkrBinding,
    component_rows: &[Vec<[Fp16; PACKED_INSTANCES]>],
    basis: &[Fp16; PACKED_INSTANCES],
    coordinate_map: &[Fp16; PACKED_INSTANCES],
    powers: &[Fp16; GKR_CLAIM_COUNT],
    claim_ordinal: usize,
    global_word: usize,
) -> ([Fp16; PACKED_INSTANCES], [Fp16; PACKED_INSTANCES]) {
    let claim = &binding.claims[claim_ordinal];
    let boundary = usize::from(claim.boundary);
    let source_boundary = global_word / WORDS_PER_BOUNDARY;
    let word = global_word % WORDS_PER_BOUNDARY;
    if claim_ordinal >= DIRECT_CLAIM_START {
        let direct_relation = if source_boundary == boundary {
            equality_weight(word, &claim.claim.point[COEFFICIENT_VARIABLES..])
        } else {
            Fp16::ZERO
        };
        let mut source = [Fp16::ZERO; PACKED_INSTANCES];
        let mut relation = [Fp16::ZERO; PACKED_INSTANCES];
        source[0] = component_rows[claim_ordinal][global_word][0];
        relation[0] = powers[claim_ordinal] * direct_relation;
        return (source, relation);
    }
    let mut conjugated_components = component_rows[claim_ordinal][global_word];
    let mut conjugated_high = if source_boundary == boundary {
        equality_weight(word, &claim.claim.point[COEFFICIENT_VARIABLES..])
    } else {
        Fp16::ZERO
    };
    let mut source = [Fp16::ZERO; PACKED_INSTANCES];
    let mut relation = [Fp16::ZERO; PACKED_INSTANCES];
    for conjugate in 0..PACKED_INSTANCES {
        source[conjugate] = basis
            .iter()
            .copied()
            .zip(conjugated_components)
            .fold(Fp16::ZERO, |sum, (basis_element, component)| {
                sum + basis_element * component
            });
        relation[conjugate] = powers[claim_ordinal] * coordinate_map[conjugate] * conjugated_high;
        for component in &mut conjugated_components {
            *component = component.pow_u32(M31_MODULUS);
        }
        conjugated_high = conjugated_high.pow_u32(M31_MODULUS);
    }
    (source, relation)
}

/// Exact compact prover state for the nine interleaving variables.
///
/// The two vectors together occupy about 5.25 MB at production geometry.
/// Source row evaluations passed to [`new`](Self::new) occupy about 2.62 MB.
#[derive(Clone, Debug)]
pub struct Fp16ZkRsRowSumcheck {
    source: Vec<Fp16>,
    relation: Vec<Fp16>,
    active_words: usize,
    round: usize,
}

impl Fp16ZkRsRowSumcheck {
    /// Build and validate the compact state.
    ///
    /// `component_rows[claim][word][component]` is the evaluation of one
    /// committed row's M31 component polynomial at that claim's low
    /// sixteen-coordinate point.  Every claim supplies all 512 source rows.
    /// Its relation remains supported only on the claim's declared boundary;
    /// retaining the opposite-boundary source rows preserves the cross terms
    /// created by the ninth non-Boolean fold.
    pub fn new(
        binding: &Fp16ZkRsGkrBinding,
        component_rows: &[Vec<[Fp16; PACKED_INSTANCES]>],
    ) -> Result<Self, Fp16ZkRsRowSumcheckError> {
        if component_rows.len() != GKR_CLAIM_COUNT {
            return Err(Fp16ZkRsRowSumcheckError::ClaimRowCount);
        }
        if component_rows.iter().any(|rows| rows.len() != GLOBAL_WORDS) {
            return Err(Fp16ZkRsRowSumcheckError::WordRowCount);
        }

        let basis = fp16_basis();
        let coordinate_map = coordinate_linearized_coefficients(binding.coordinate_challenge);
        let mut source = vec![Fp16::ZERO; LINEARIZED_STATES * GLOBAL_WORDS];
        let mut relation = vec![Fp16::ZERO; LINEARIZED_STATES * GLOBAL_WORDS];
        let mut claim_power = Fp16::ONE;

        for (claim_ordinal, (claim, rows)) in binding.claims.iter().zip(component_rows).enumerate()
        {
            let boundary = usize::from(claim.boundary);
            let high_point = &claim.claim.point[COEFFICIENT_VARIABLES..];
            for (global_word, components) in rows.iter().enumerate() {
                if claim_ordinal >= DIRECT_CLAIM_START {
                    let source_boundary = global_word / WORDS_PER_BOUNDARY;
                    let word = global_word % WORDS_PER_BOUNDARY;
                    let state = claim_ordinal * PACKED_INSTANCES;
                    let offset = state * GLOBAL_WORDS + global_word;
                    source[offset] = components[0];
                    relation[offset] = if source_boundary == boundary {
                        claim_power * equality_weight(word, high_point)
                    } else {
                        Fp16::ZERO
                    };
                    continue;
                }
                let mut conjugated_components = *components;
                let source_boundary = global_word / WORDS_PER_BOUNDARY;
                let word = global_word % WORDS_PER_BOUNDARY;
                let mut conjugated_high = if source_boundary == boundary {
                    equality_weight(word, high_point)
                } else {
                    Fp16::ZERO
                };
                for (conjugate, map_coefficient) in coordinate_map.iter().copied().enumerate() {
                    let packed = basis
                        .iter()
                        .copied()
                        .zip(conjugated_components)
                        .fold(Fp16::ZERO, |sum, (basis_element, component)| {
                            sum + basis_element * component
                        });
                    let state = claim_ordinal * PACKED_INSTANCES + conjugate;
                    let offset = state * GLOBAL_WORDS + global_word;
                    source[offset] = packed;
                    relation[offset] = claim_power * map_coefficient * conjugated_high;
                    for component in &mut conjugated_components {
                        *component = component.pow_u32(M31_MODULUS);
                    }
                    conjugated_high = conjugated_high.pow_u32(M31_MODULUS);
                }
            }
            claim_power = claim_power * binding.claim_challenge;
        }

        let result = Self {
            source,
            relation,
            active_words: GLOBAL_WORDS,
            round: 0,
        };
        if result.initial_target() != binding.expected_target {
            return Err(Fp16ZkRsRowSumcheckError::InitialTargetMismatch);
        }
        Ok(result)
    }

    /// Construct the same state with a bounded caller-selected worker count.
    ///
    /// Claim/row pairs are independent, allowing a 16-thread laptop to use
    /// every logical processor while retaining the same compact input.
    #[cfg(feature = "parallel")]
    pub fn new_parallel(
        binding: &Fp16ZkRsGkrBinding,
        component_rows: &[Vec<[Fp16; PACKED_INSTANCES]>],
        workers: usize,
    ) -> Result<Self, Fp16ZkRsRowSumcheckError> {
        if component_rows.len() != GKR_CLAIM_COUNT {
            return Err(Fp16ZkRsRowSumcheckError::ClaimRowCount);
        }
        if component_rows.iter().any(|rows| rows.len() != GLOBAL_WORDS) {
            return Err(Fp16ZkRsRowSumcheckError::WordRowCount);
        }
        let basis = fp16_basis();
        let coordinate_map = coordinate_linearized_coefficients(binding.coordinate_challenge);
        let powers = claim_powers(binding.claim_challenge);
        let task_count = GKR_CLAIM_COUNT * GLOBAL_WORDS;
        let worker_count = workers.clamp(1, task_count);
        let tasks_per_worker = task_count.div_ceil(worker_count);
        let batches = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(worker_count);
            for worker in 0..worker_count {
                let start = worker * tasks_per_worker;
                let end = (start + tasks_per_worker).min(task_count);
                if start == end {
                    continue;
                }
                handles.push(scope.spawn(move || {
                    (start..end)
                        .map(|task| {
                            let claim_ordinal = task / GLOBAL_WORDS;
                            let global_word = task % GLOBAL_WORDS;
                            (
                                claim_ordinal,
                                global_word,
                                row_states(
                                    binding,
                                    component_rows,
                                    &basis,
                                    &coordinate_map,
                                    &powers,
                                    claim_ordinal,
                                    global_word,
                                ),
                            )
                        })
                        .collect::<Vec<_>>()
                }));
            }
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .map_err(|_| Fp16ZkRsRowSumcheckError::WorkerPanic)
                })
                .collect::<Result<Vec<_>, _>>()
        })?;
        let mut source = vec![Fp16::ZERO; LINEARIZED_STATES * GLOBAL_WORDS];
        let mut relation = vec![Fp16::ZERO; LINEARIZED_STATES * GLOBAL_WORDS];
        for batch in batches {
            for (claim_ordinal, global_word, (row_source, row_relation)) in batch {
                for conjugate in 0..PACKED_INSTANCES {
                    let state = claim_ordinal * PACKED_INSTANCES + conjugate;
                    let offset = state * GLOBAL_WORDS + global_word;
                    source[offset] = row_source[conjugate];
                    relation[offset] = row_relation[conjugate];
                }
            }
        }
        let result = Self {
            source,
            relation,
            active_words: GLOBAL_WORDS,
            round: 0,
        };
        if result.initial_target() != binding.expected_target {
            return Err(Fp16ZkRsRowSumcheckError::InitialTargetMismatch);
        }
        Ok(result)
    }

    /// Current degree-two source message in coefficient form.
    pub fn round_coefficients(&self) -> Result<[Fp16; 3], Fp16ZkRsRowSumcheckError> {
        if self.round > WORD_VARIABLES {
            return Err(Fp16ZkRsRowSumcheckError::RoundComplete);
        }
        Ok(self.round_coefficients_for_states(0, LINEARIZED_STATES))
    }

    fn round_coefficients_for_states(&self, start: usize, end: usize) -> [Fp16; 3] {
        let mut coefficients = [Fp16::ZERO; 3];
        for state in start..end {
            let offset = state * GLOBAL_WORDS;
            let source = &self.source[offset..offset + self.active_words];
            let relation = &self.relation[offset..offset + self.active_words];
            for (source_pair, relation_pair) in source.chunks_exact(2).zip(relation.chunks_exact(2))
            {
                let source_delta = source_pair[1] - source_pair[0];
                let relation_delta = relation_pair[1] - relation_pair[0];
                coefficients[0] = coefficients[0] + source_pair[0] * relation_pair[0];
                coefficients[1] = coefficients[1]
                    + source_pair[0] * relation_delta
                    + source_delta * relation_pair[0];
                coefficients[2] = coefficients[2] + source_delta * relation_delta;
            }
        }
        coefficients
    }

    /// Compute the canonical quadratic message across a bounded worker set.
    #[cfg(feature = "parallel")]
    pub fn round_coefficients_parallel(
        &self,
        workers: usize,
    ) -> Result<[Fp16; 3], Fp16ZkRsRowSumcheckError> {
        if self.round > WORD_VARIABLES {
            return Err(Fp16ZkRsRowSumcheckError::RoundComplete);
        }
        let worker_count = workers.clamp(1, LINEARIZED_STATES);
        let states_per_worker = LINEARIZED_STATES.div_ceil(worker_count);
        let partials = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(worker_count);
            for worker in 0..worker_count {
                let start = worker * states_per_worker;
                let end = (start + states_per_worker).min(LINEARIZED_STATES);
                if start != end {
                    handles
                        .push(scope.spawn(move || self.round_coefficients_for_states(start, end)));
                }
            }
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .map_err(|_| Fp16ZkRsRowSumcheckError::WorkerPanic)
                })
                .collect::<Result<Vec<_>, _>>()
        })?;
        Ok(partials
            .into_iter()
            .fold([Fp16::ZERO; 3], |mut sum, partial| {
                for index in 0..3 {
                    sum[index] = sum[index] + partial[index];
                }
                sum
            }))
    }

    /// Fold both source and relation states at one authenticated challenge.
    pub fn fold(&mut self, challenge: Fp16) -> Result<(), Fp16ZkRsRowSumcheckError> {
        if self.round > WORD_VARIABLES {
            return Err(Fp16ZkRsRowSumcheckError::RoundComplete);
        }
        let next_words = self.active_words / 2;
        for state in 0..LINEARIZED_STATES {
            let offset = state * GLOBAL_WORDS;
            for destination in 0..next_words {
                let left = self.source[offset + 2 * destination];
                let right = self.source[offset + 2 * destination + 1];
                self.source[offset + destination] = left + (right - left) * challenge;
                let left = self.relation[offset + 2 * destination];
                let right = self.relation[offset + 2 * destination + 1];
                self.relation[offset + destination] = left + (right - left) * challenge;
            }
        }
        self.active_words = next_words;
        self.round += 1;
        Ok(())
    }

    /// Fold disjoint state ranges across a bounded worker set.
    #[cfg(feature = "parallel")]
    pub fn fold_parallel(
        &mut self,
        challenge: Fp16,
        workers: usize,
    ) -> Result<(), Fp16ZkRsRowSumcheckError> {
        if self.round > WORD_VARIABLES {
            return Err(Fp16ZkRsRowSumcheckError::RoundComplete);
        }
        let next_words = self.active_words / 2;
        let worker_count = workers.clamp(1, LINEARIZED_STATES);
        let states_per_worker = LINEARIZED_STATES.div_ceil(worker_count);
        let values_per_worker = states_per_worker * GLOBAL_WORDS;
        std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(worker_count);
            for (source, relation) in self
                .source
                .chunks_mut(values_per_worker)
                .zip(self.relation.chunks_mut(values_per_worker))
            {
                let active_words = self.active_words;
                handles.push(scope.spawn(move || {
                    let state_count = source.len() / GLOBAL_WORDS;
                    for state in 0..state_count {
                        let offset = state * GLOBAL_WORDS;
                        for destination in 0..next_words {
                            let left = source[offset + 2 * destination];
                            let right = source[offset + 2 * destination + 1];
                            source[offset + destination] = left + (right - left) * challenge;
                            let left = relation[offset + 2 * destination];
                            let right = relation[offset + 2 * destination + 1];
                            relation[offset + destination] = left + (right - left) * challenge;
                        }
                        debug_assert!(next_words < active_words);
                    }
                }));
            }
            for handle in handles {
                handle
                    .join()
                    .map_err(|_| Fp16ZkRsRowSumcheckError::WorkerPanic)?;
            }
            Ok::<(), Fp16ZkRsRowSumcheckError>(())
        })?;
        self.active_words = next_words;
        self.round += 1;
        Ok(())
    }

    /// Initial row relation, before any interleaving variable is folded.
    pub fn initial_target(&self) -> Fp16 {
        let mut target = Fp16::ZERO;
        for state in 0..LINEARIZED_STATES {
            let offset = state * GLOBAL_WORDS;
            for word in 0..self.active_words {
                target = target + self.source[offset + word] * self.relation[offset + word];
            }
        }
        target
    }

    /// Final Construction 7.2 target after all nine folds.
    pub fn terminal_target(&self) -> Result<Fp16, Fp16ZkRsRowSumcheckError> {
        if self.round != WORD_VARIABLES + 1 {
            return Err(Fp16ZkRsRowSumcheckError::RoundIncomplete);
        }
        Ok((0..LINEARIZED_STATES).fold(Fp16::ZERO, |target, state| {
            let offset = state * GLOBAL_WORDS;
            target + self.source[offset] * self.relation[offset]
        }))
    }

    pub fn round(&self) -> usize {
        self.round
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        field::M31,
        fp16_zk_rs_gkr_binding::{
            BOUNDARY_VARIABLES, PackedComponentClaim, bind_gkr_boundary_claims,
            verify_main_answer_target,
        },
        gkr_packed_bridge_fp16::{lagrange_basis, lagrange_evaluations},
        gkr_sumcheck::LayerOutputClaim,
    };

    const SPARSE_COEFFICIENTS: usize = 4;

    fn fp(value: u32) -> Fp16 {
        Fp16::from_m31(M31::from_canonical(value).unwrap())
    }

    fn field(seed: u32) -> Fp16 {
        let coefficients =
            core::array::from_fn(|coordinate| (seed + 97 * coordinate as u32) % M31_MODULUS);
        Fp16::from_coefficients(coefficients).unwrap()
    }

    fn source(boundary: usize, word: usize, position: usize) -> Fp16 {
        field(1_003 + 101 * boundary as u32 + 17 * word as u32 + 271 * position as u32)
    }

    fn component_rows(point: &[Fp16]) -> Vec<[Fp16; PACKED_INSTANCES]> {
        (0..GLOBAL_WORDS)
            .map(|global_word| {
                let boundary = global_word / WORDS_PER_BOUNDARY;
                let word = global_word % WORDS_PER_BOUNDARY;
                let mut result = [Fp16::ZERO; PACKED_INSTANCES];
                for position in 0..SPARSE_COEFFICIENTS {
                    let weight = equality_weight(position, point);
                    for (destination, coordinate) in result
                        .iter_mut()
                        .zip(source(boundary, word, position).coefficients())
                    {
                        *destination = *destination
                            + weight.mul_by_m31(M31::from_canonical(coordinate).unwrap());
                    }
                }
                result
            })
            .collect()
    }

    fn direct_rows(point: &[Fp16]) -> Vec<[Fp16; PACKED_INSTANCES]> {
        (0..GLOBAL_WORDS)
            .map(|global_word| {
                let boundary = global_word / WORDS_PER_BOUNDARY;
                let word = global_word % WORDS_PER_BOUNDARY;
                let value = (0..SPARSE_COEFFICIENTS).fold(Fp16::ZERO, |sum, position| {
                    sum + equality_weight(position, point) * source(boundary, word, position)
                });
                [value; PACKED_INSTANCES]
            })
            .collect()
    }

    fn fixture() -> (Fp16ZkRsGkrBinding, Vec<Vec<[Fp16; PACKED_INSTANCES]>>) {
        let basis = lagrange_basis();
        let mut claims = Vec::new();
        let mut rows = Vec::new();
        for claim_ordinal in 0..GKR_CLAIM_COUNT {
            let boundary = usize::from(claim_ordinal != 0);
            let point = (0..BOUNDARY_VARIABLES)
                .map(|coordinate| field(7_001 + 313 * claim_ordinal as u32 + coordinate as u32))
                .collect::<Vec<_>>();
            let claim_rows = if claim_ordinal >= DIRECT_CLAIM_START {
                direct_rows(&point[..COEFFICIENT_VARIABLES])
            } else {
                component_rows(&point[..COEFFICIENT_VARIABLES])
            };
            let high_point = &point[COEFFICIENT_VARIABLES..];
            let component_evaluations = if claim_ordinal >= DIRECT_CLAIM_START {
                let value = (0..WORDS_PER_BOUNDARY).fold(Fp16::ZERO, |sum, word| {
                    let global_word = boundary * WORDS_PER_BOUNDARY + word;
                    sum + equality_weight(word, high_point) * claim_rows[global_word][0]
                });
                [value; PACKED_INSTANCES]
            } else {
                core::array::from_fn(|component| {
                    (0..WORDS_PER_BOUNDARY).fold(Fp16::ZERO, |sum, word| {
                        let global_word = boundary * WORDS_PER_BOUNDARY + word;
                        sum + equality_weight(word, high_point) * claim_rows[global_word][component]
                    })
                })
            };
            let shard_query = fp(19 + claim_ordinal as u32);
            let value = if claim_ordinal >= DIRECT_CLAIM_START {
                component_evaluations[0]
            } else {
                component_evaluations
                    .iter()
                    .copied()
                    .zip(lagrange_evaluations(&basis, shard_query))
                    .fold(Fp16::ZERO, |sum, (evaluation, weight)| {
                        sum + evaluation * weight
                    })
            };
            claims.push(PackedComponentClaim {
                boundary: boundary as u8,
                claim: LayerOutputClaim {
                    point,
                    value,
                    coefficient: if claim_ordinal == 0 {
                        Fp16::ONE
                    } else {
                        fp(43 + claim_ordinal as u32)
                    },
                },
                shard_query,
                component_evaluations,
            });
            rows.push(claim_rows);
        }
        (
            bind_gkr_boundary_claims(&claims, field(80_003), field(90_001)).unwrap(),
            rows,
        )
    }

    fn polynomial_eval(coefficients: [Fp16; 3], point: Fp16) -> Fp16 {
        coefficients[0] + coefficients[1] * point + coefficients[2] * point.square()
    }

    #[test]
    fn compact_quadratic_chain_matches_independent_answer_target() {
        let (binding, rows) = fixture();
        let mut prover = Fp16ZkRsRowSumcheck::new(&binding, &rows).unwrap();
        #[cfg(feature = "parallel")]
        let mut parallel = Fp16ZkRsRowSumcheck::new_parallel(&binding, &rows, 16).unwrap();
        let mut expected = binding.expected_target;
        let mut challenges = Vec::new();
        for round in 0..=WORD_VARIABLES {
            let message = prover.round_coefficients().unwrap();
            #[cfg(feature = "parallel")]
            assert_eq!(parallel.round_coefficients_parallel(16).unwrap(), message);
            assert_eq!(message[0] + polynomial_eval(message, Fp16::ONE), expected);
            let challenge = field(100_003 + 1_009 * round as u32);
            expected = polynomial_eval(message, challenge);
            prover.fold(challenge).unwrap();
            #[cfg(feature = "parallel")]
            parallel.fold_parallel(challenge, 16).unwrap();
            challenges.push(challenge);
        }
        let target = prover.terminal_target().unwrap();
        #[cfg(feature = "parallel")]
        assert_eq!(parallel.terminal_target().unwrap(), target);
        assert_eq!(target, expected);

        let mut answer = vec![Fp16::ZERO; 1 << COEFFICIENT_VARIABLES];
        for boundary in 0..BOUNDARY_COUNT {
            for word in 0..WORDS_PER_BOUNDARY {
                let global_word = boundary * WORDS_PER_BOUNDARY + word;
                let weight = equality_weight(global_word, &challenges);
                for (position, destination) in
                    answer.iter_mut().take(SPARSE_COEFFICIENTS).enumerate()
                {
                    *destination = *destination + weight * source(boundary, word, position);
                }
            }
        }
        verify_main_answer_target(&binding, &challenges, &answer, target).unwrap();
    }

    #[test]
    fn inconsistent_source_rows_fail_closed() {
        let (binding, mut rows) = fixture();
        rows[3][WORDS_PER_BOUNDARY + 29][7] = rows[3][WORDS_PER_BOUNDARY + 29][7] + Fp16::ONE;
        assert_eq!(
            Fp16ZkRsRowSumcheck::new(&binding, &rows).unwrap_err(),
            Fp16ZkRsRowSumcheckError::InitialTargetMismatch
        );
    }
}
