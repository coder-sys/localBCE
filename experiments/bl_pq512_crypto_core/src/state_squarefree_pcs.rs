//! Exact PCS composition for the linear state-uniqueness proof.
//!
//! The four private Bezout tables occupy one fixed Construction 8.2 auxiliary
//! message: four 512-element blocks followed by the existing 1,218 random
//! padding coefficients.  K128 uses the prefix of each block and leaves the
//! remainder zero.  This gives one post-`beta`, pre-`r` commitment without
//! changing the selected auxiliary code geometry.
//!
//! The four virtual square-free leaves reduce to twelve openings of the
//! existing H4 state source.  This module constructs and independently checks
//! both exact opening boundaries; transcript orchestration and Merkle/RS
//! commitment I/O remain with the production H4 coordinator.

use alloc::{vec, vec::Vec};
use core::fmt;

use crate::{
    field::Fp16,
    multilinear_pcs::{MultilinearOpeningClaim, evaluate_multilinear},
    state_relation_gkr::{
        STATE_RELATION_GROUP_COUNT, STATE_RELATION_GROUP_VARIABLES, STATE_RELATION_SOURCE_WIDTH,
        STATE_RELATION_WIRE_VARIABLES, h4_state_point,
    },
    state_squarefree_gkr::{
        STATE_SQUAREFREE_MAX_CAPACITY, StateSquarefreeGkrProof, StateSquarefreeWitness,
        state_squarefree_state_reductions, verify_state_squarefree_gkr,
    },
};

pub const STATE_SQUAREFREE_COEFFICIENT_TABLES: usize = 4;
pub const STATE_SQUAREFREE_COEFFICIENT_BLOCK: usize = STATE_SQUAREFREE_MAX_CAPACITY;
pub const STATE_SQUAREFREE_AUXILIARY_MESSAGE_VALUES: usize = 2_048;
pub const STATE_SQUAREFREE_AUXILIARY_RANDOM_VALUES: usize = 1_218;
pub const STATE_SQUAREFREE_AUXILIARY_DIMENSION: usize =
    STATE_SQUAREFREE_AUXILIARY_MESSAGE_VALUES + STATE_SQUAREFREE_AUXILIARY_RANDOM_VALUES;
pub const STATE_SQUAREFREE_COEFFICIENT_VARIABLES: usize = 11;
pub const STATE_SQUAREFREE_H4_CLAIMS: usize = 12;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateSquarefreeCoefficientComposition {
    /// Four coefficient claims lifted into the fixed 2^11 message geometry.
    pub claims: [MultilinearOpeningClaim; STATE_SQUAREFREE_COEFFICIENT_TABLES],
    /// Authenticated nonzero coefficients sampled after all four claims.
    pub mixing_coefficients: [Fp16; STATE_SQUAREFREE_COEFFICIENT_TABLES],
    /// The exact linear functional applied to the 2,048 message coefficients.
    pub functional: Vec<Fp16>,
    pub target: Fp16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateSquarefreeH4InputClaim {
    pub boundary: u8,
    pub point: Vec<Fp16>,
    pub value: Fp16,
    pub shard_query: Fp16,
    pub phase: u8,
    pub reduction: u8,
    pub state_wire: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateSquarefreePcsError {
    Shape,
    ZeroMixingCoefficient,
    Opening,
    Reduction,
}

impl fmt::Display for StateSquarefreePcsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "state square-free PCS error: {self:?}")
    }
}

impl core::error::Error for StateSquarefreePcsError {}

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

fn coefficient_tables(witness: &StateSquarefreeWitness) -> [&[Fp16]; 4] {
    [
        &witness.phases[0].bezout_a,
        &witness.phases[0].bezout_b,
        &witness.phases[1].bezout_a,
        &witness.phases[1].bezout_b,
    ]
}

/// Pack the private coefficient tables and fresh Construction 8.2 random
/// padding into one fixed auxiliary coefficient vector.
pub fn build_state_squarefree_auxiliary_source(
    witness: &StateSquarefreeWitness,
    random_padding: &[Fp16],
) -> Result<Vec<Fp16>, StateSquarefreePcsError> {
    if witness.layout.capacity > STATE_SQUAREFREE_COEFFICIENT_BLOCK
        || random_padding.len() != STATE_SQUAREFREE_AUXILIARY_RANDOM_VALUES
        || coefficient_tables(witness)
            .iter()
            .any(|table| table.len() != witness.layout.capacity)
    {
        return Err(StateSquarefreePcsError::Shape);
    }
    let mut source = vec![Fp16::ZERO; STATE_SQUAREFREE_AUXILIARY_DIMENSION];
    for (table, coefficients) in coefficient_tables(witness).into_iter().enumerate() {
        let start = table * STATE_SQUAREFREE_COEFFICIENT_BLOCK;
        source[start..start + coefficients.len()].copy_from_slice(coefficients);
    }
    source[STATE_SQUAREFREE_AUXILIARY_MESSAGE_VALUES..].copy_from_slice(random_padding);
    Ok(source)
}

fn lift_coefficient_point(
    point: &[Fp16],
    capacity: usize,
    table: usize,
) -> Result<Vec<Fp16>, StateSquarefreePcsError> {
    if capacity > STATE_SQUAREFREE_COEFFICIENT_BLOCK
        || !capacity.is_power_of_two()
        || point.len() != capacity.ilog2() as usize
        || table >= STATE_SQUAREFREE_COEFFICIENT_TABLES
    {
        return Err(StateSquarefreePcsError::Shape);
    }
    let mut lifted = point.to_vec();
    lifted.resize(
        STATE_SQUAREFREE_COEFFICIENT_BLOCK.ilog2() as usize,
        Fp16::ZERO,
    );
    for bit in 0..2 {
        lifted.push(if (table >> bit) & 1 == 1 {
            Fp16::ONE
        } else {
            Fp16::ZERO
        });
    }
    if lifted.len() != STATE_SQUAREFREE_COEFFICIENT_VARIABLES {
        return Err(StateSquarefreePcsError::Shape);
    }
    Ok(lifted)
}

/// Construct the one auxiliary linear form that opens all four private
/// coefficient tables.  The caller must obtain `mixing_coefficients` from the
/// authenticated public coin after every claim point and value is fixed.
pub fn compose_state_squarefree_coefficient_claims(
    proof: &StateSquarefreeGkrProof,
    auxiliary_source: &[Fp16],
    mixing_coefficients: [Fp16; STATE_SQUAREFREE_COEFFICIENT_TABLES],
) -> Result<StateSquarefreeCoefficientComposition, StateSquarefreePcsError> {
    if auxiliary_source.len() != STATE_SQUAREFREE_AUXILIARY_DIMENSION
        || mixing_coefficients
            .iter()
            .any(|coefficient| coefficient.is_zero())
    {
        return Err(
            if mixing_coefficients
                .iter()
                .any(|coefficient| coefficient.is_zero())
            {
                StateSquarefreePcsError::ZeroMixingCoefficient
            } else {
                StateSquarefreePcsError::Shape
            },
        );
    }
    let verified =
        verify_state_squarefree_gkr(proof).map_err(|_| StateSquarefreePcsError::Shape)?;
    let short_claims = [
        &verified.coefficient_claims[0][0],
        &verified.coefficient_claims[0][1],
        &verified.coefficient_claims[1][0],
        &verified.coefficient_claims[1][1],
    ];
    let mut claims = Vec::with_capacity(STATE_SQUAREFREE_COEFFICIENT_TABLES);
    let mut functional = vec![Fp16::ZERO; STATE_SQUAREFREE_AUXILIARY_MESSAGE_VALUES];
    let mut target = Fp16::ZERO;
    for (table, (claim, mixing)) in short_claims
        .into_iter()
        .zip(mixing_coefficients)
        .enumerate()
    {
        let lifted = MultilinearOpeningClaim {
            point: lift_coefficient_point(&claim.point, proof.layout.capacity, table)?,
            value: claim.value,
        };
        let actual = evaluate_multilinear(
            &auxiliary_source[..STATE_SQUAREFREE_AUXILIARY_MESSAGE_VALUES],
            &lifted.point,
        )
        .map_err(|_| StateSquarefreePcsError::Shape)?;
        if actual != lifted.value {
            return Err(StateSquarefreePcsError::Opening);
        }
        for (index, weight) in functional.iter_mut().enumerate() {
            *weight = *weight + mixing * equality_weight(index, &lifted.point);
        }
        target = target + mixing * lifted.value;
        claims.push(lifted);
    }
    let actual_target = auxiliary_source[..STATE_SQUAREFREE_AUXILIARY_MESSAGE_VALUES]
        .iter()
        .copied()
        .zip(&functional)
        .fold(Fp16::ZERO, |sum, (value, weight)| sum + value * *weight);
    if actual_target != target {
        return Err(StateSquarefreePcsError::Opening);
    }
    Ok(StateSquarefreeCoefficientComposition {
        claims: claims
            .try_into()
            .map_err(|_| StateSquarefreePcsError::Shape)?,
        mixing_coefficients,
        functional,
        target,
    })
}

fn state_column_opening(
    source: &[Fp16],
    wire: usize,
    point: &[Fp16],
) -> Result<Fp16, StateSquarefreePcsError> {
    if source.len() != STATE_RELATION_GROUP_COUNT * STATE_RELATION_SOURCE_WIDTH
        || wire >= STATE_RELATION_SOURCE_WIDTH
        || point.len() != STATE_RELATION_GROUP_VARIABLES
    {
        return Err(StateSquarefreePcsError::Shape);
    }
    let column = (0..STATE_RELATION_GROUP_COUNT)
        .map(|group| source[group * STATE_RELATION_SOURCE_WIDTH + wire])
        .collect::<Vec<_>>();
    evaluate_multilinear(&column, point).map_err(|_| StateSquarefreePcsError::Shape)
}

fn local_state_point(wire: usize, row_point: &[Fp16]) -> Vec<Fp16> {
    let mut point = Vec::with_capacity(STATE_RELATION_WIRE_VARIABLES + row_point.len());
    for bit in 0..STATE_RELATION_WIRE_VARIABLES {
        point.push(if (wire >> bit) & 1 == 1 {
            Fp16::ONE
        } else {
            Fp16::ZERO
        });
    }
    point.extend_from_slice(row_point);
    point
}

/// Lift the four virtual-leaf reductions to twelve exact openings of the
/// already committed H4 state source and independently check each affine
/// reduction before returning it to row batching.
pub fn state_squarefree_h4_input_claims(
    source: &[Fp16],
    proof: &StateSquarefreeGkrProof,
    shard_query: Fp16,
) -> Result<[StateSquarefreeH4InputClaim; STATE_SQUAREFREE_H4_CLAIMS], StateSquarefreePcsError> {
    if shard_query.is_zero() {
        return Err(StateSquarefreePcsError::Shape);
    }
    let reductions =
        state_squarefree_state_reductions(proof).map_err(|_| StateSquarefreePcsError::Shape)?;
    let mut claims = Vec::with_capacity(STATE_SQUAREFREE_H4_CLAIMS);
    for (phase, phase_reductions) in reductions.iter().enumerate() {
        for (reduction_index, reduction) in phase_reductions.iter().enumerate() {
            let mut openings = [Fp16::ZERO; 3];
            for (opening_index, wire) in reduction.state_wires.into_iter().enumerate() {
                let value = state_column_opening(source, wire, &reduction.row_point)?;
                openings[opening_index] = value;
                let point = h4_state_point(&local_state_point(wire, &reduction.row_point))
                    .map_err(|_| StateSquarefreePcsError::Shape)?;
                claims.push(StateSquarefreeH4InputClaim {
                    boundary: 1,
                    point,
                    value,
                    shard_query,
                    phase: phase as u8,
                    reduction: reduction_index as u8,
                    state_wire: wire as u8,
                });
            }
            let reduced = reduction.affine_coefficients[0]
                + reduction.affine_coefficients[1] * openings[0]
                + reduction.affine_coefficients[2] * openings[1]
                + reduction.affine_coefficients[3] * openings[2];
            if reduced != reduction.expected_value {
                return Err(StateSquarefreePcsError::Reduction);
            }
        }
    }
    claims
        .try_into()
        .map_err(|_| StateSquarefreePcsError::Shape)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        field::M31,
        state_relation_gkr::{StateRelationEntry, StateRelationRow, build_state_relation_source},
        state_squarefree_gkr::{
            StateSquarefreeLayout, build_state_squarefree_witness,
            prove_state_squarefree_gkr_control, state_squarefree_control_challenges,
        },
    };

    fn fp(value: u32) -> Fp16 {
        Fp16::from_m31(M31::from_canonical(value).unwrap())
    }

    fn rows(capacity: usize) -> Vec<StateRelationRow> {
        (0..capacity)
            .map(|index| {
                let mut key = [0_u8; 64];
                key[56..].copy_from_slice(&(index as u64 + 1).to_be_bytes());
                let entry = StateRelationEntry {
                    index: index as u32,
                    present: index < capacity - 1,
                    key: if index < capacity - 1 { key } else { [0; 64] },
                    value: if index < capacity - 1 {
                        [(index % 200) as u8 + 7; 64]
                    } else {
                        [0; 64]
                    },
                };
                StateRelationRow {
                    operation_before: entry,
                    operation_after: entry,
                    snapshot_before: entry,
                    snapshot_after: entry,
                }
            })
            .collect()
    }

    fn fixture(
        capacity: usize,
    ) -> (
        Vec<StateRelationRow>,
        StateSquarefreeWitness,
        StateSquarefreeGkrProof,
    ) {
        let rows = rows(capacity);
        let layout = StateSquarefreeLayout::new(capacity).unwrap();
        let witness = build_state_squarefree_witness(&rows, layout, fp(17)).unwrap();
        let proof = prove_state_squarefree_gkr_control(
            &rows,
            &witness,
            fp(29),
            state_squarefree_control_challenges(layout).unwrap(),
        )
        .unwrap();
        (rows, witness, proof)
    }

    #[test]
    fn coefficient_tables_use_one_fixed_hidden_auxiliary_word() {
        for capacity in [128, 512] {
            let (_, witness, proof) = fixture(capacity);
            let padding = vec![fp(41); STATE_SQUAREFREE_AUXILIARY_RANDOM_VALUES];
            let source = build_state_squarefree_auxiliary_source(&witness, &padding).unwrap();
            assert_eq!(source.len(), STATE_SQUAREFREE_AUXILIARY_DIMENSION);
            if capacity == 128 {
                assert!(
                    source[128..STATE_SQUAREFREE_COEFFICIENT_BLOCK]
                        .iter()
                        .all(|value| value.is_zero())
                );
            }
            assert_eq!(
                &source[STATE_SQUAREFREE_AUXILIARY_MESSAGE_VALUES..],
                padding.as_slice()
            );
            let composition = compose_state_squarefree_coefficient_claims(
                &proof,
                &source,
                [fp(43), fp(47), fp(53), fp(59)],
            )
            .unwrap();
            assert_eq!(composition.claims.len(), 4);
            assert_eq!(composition.functional.len(), 2_048);
        }
    }

    #[test]
    fn coefficient_mutation_and_zero_mixing_reject() {
        let (_, witness, proof) = fixture(128);
        let mut source = build_state_squarefree_auxiliary_source(
            &witness,
            &vec![fp(61); STATE_SQUAREFREE_AUXILIARY_RANDOM_VALUES],
        )
        .unwrap();
        source[3] = source[3] + Fp16::ONE;
        assert_eq!(
            compose_state_squarefree_coefficient_claims(
                &proof,
                &source,
                [fp(2), fp(3), fp(5), fp(7)],
            ),
            Err(StateSquarefreePcsError::Opening)
        );
        let source = build_state_squarefree_auxiliary_source(
            &witness,
            &vec![fp(61); STATE_SQUAREFREE_AUXILIARY_RANDOM_VALUES],
        )
        .unwrap();
        assert_eq!(
            compose_state_squarefree_coefficient_claims(
                &proof,
                &source,
                [fp(2), Fp16::ZERO, fp(5), fp(7)],
            ),
            Err(StateSquarefreePcsError::ZeroMixingCoefficient)
        );
    }

    #[test]
    fn twelve_state_openings_lift_to_the_existing_h4_source() {
        let (rows, _, proof) = fixture(128);
        let source = build_state_relation_source(&rows).unwrap();
        let claims = state_squarefree_h4_input_claims(&source, &proof, fp(71)).unwrap();
        assert_eq!(claims.len(), STATE_SQUAREFREE_H4_CLAIMS);
        assert!(
            claims
                .iter()
                .all(|claim| claim.boundary == 1 && claim.point.len() == 24)
        );
        let mut mutated = source;
        mutated[1] = mutated[1] + Fp16::ONE;
        assert_eq!(
            state_squarefree_h4_input_claims(&mutated, &proof, fp(71)),
            Err(StateSquarefreePcsError::Reduction)
        );
    }
}
