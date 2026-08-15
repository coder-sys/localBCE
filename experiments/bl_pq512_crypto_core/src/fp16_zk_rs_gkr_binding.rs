//! Small-field row batching for the B=16 GKR/Construction 8.2 boundary.
//!
//! The committed boundary coefficient at one Boolean address is
//! `P(x) = sum_i beta_i * P_i(x)`, where every `P_i(x)` is in M31 and the
//! `beta_i` are the frozen Fp16 basis.  A GKR claim is not a plain opening of
//! `P`: it is `sum_i L_i(b) * P_i(r)` for the packed-shard query `b`.
//!
//! Following the row-batched FRI-Binius identity, the prover publishes all
//! sixteen component evaluations before the authenticated batching challenges.
//! The verifier checks the GKR value and reduces their coordinate equations to
//! one Fp16-linear relation on the already committed packed coefficients.  No
//! unpacked boundary, relation table, or host-supplied PCS form is trusted.

use alloc::{vec, vec::Vec};
use core::fmt;

use crate::{
    field::{Fp16, M31, M31_MODULUS},
    gkr_packed_bridge_fp16::{PACKED_INSTANCES, lagrange_basis, lagrange_evaluations},
    gkr_sumcheck::LayerOutputClaim,
};

pub const BOUNDARY_VARIABLES: usize = 24;
pub const COEFFICIENT_VARIABLES: usize = 16;
pub const WORD_VARIABLES: usize = BOUNDARY_VARIABLES - COEFFICIENT_VARIABLES;
pub const WORDS_PER_BOUNDARY: usize = 1 << WORD_VARIABLES;
pub const BOUNDARY_COUNT: usize = 2;
pub const INTERLEAVED_WORDS: usize = BOUNDARY_COUNT * WORDS_PER_BOUNDARY;
pub const OUTPUT_CLAIM_COUNT: usize = 1;
pub const HASH_INPUT_CLAIM_COUNT: usize = 4;
pub const STATE_RELATION_INPUT_CLAIM_COUNT: usize = 2;
pub const STATE_SQUAREFREE_INPUT_CLAIM_COUNT: usize = 12;
pub const INPUT_CLAIM_COUNT: usize =
    HASH_INPUT_CLAIM_COUNT + STATE_RELATION_INPUT_CLAIM_COUNT + STATE_SQUAREFREE_INPUT_CLAIM_COUNT;
pub const GKR_CLAIM_COUNT: usize = OUTPUT_CLAIM_COUNT + INPUT_CLAIM_COUNT;
/// Claims before this ordinal are packed M31 component polynomials. State
/// claims at and after this ordinal are direct Fp16 multilinear polynomials.
pub const PACKED_CLAIM_COUNT: usize = OUTPUT_CLAIM_COUNT + HASH_INPUT_CLAIM_COUNT;
pub const DIRECT_CLAIM_START: usize = PACKED_CLAIM_COUNT;
const LOW_MESSAGE_WIRES: usize = 1 << 11;
const HASH_MESSAGE_WIRES: usize = 1_600;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fp16ZkRsGkrBindingError {
    ClaimCount,
    BoundaryOrder,
    PointDimension,
    OutputCoefficient,
    ZeroInputCoefficient,
    ZeroClaimChallenge,
    ZeroCoordinateChallenge,
    GkrValueMismatch,
    WordValueCount,
    WordChallengeCount,
    AnswerCoefficientCount,
    TargetMismatch,
    AnswerTargetMismatch,
}

impl fmt::Display for Fp16ZkRsGkrBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Fp16 ZK-RS GKR binding error: {self:?}")
    }
}

impl core::error::Error for Fp16ZkRsGkrBindingError {}

/// One GKR boundary claim and the small-field evaluations it asserts.
///
/// Canonical order is one output claim on boundary zero followed by four
/// relay-free RoundInput claims, two state-relation claims, and twelve
/// square-free state-source claims on boundary one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackedComponentClaim {
    pub boundary: u8,
    pub claim: LayerOutputClaim,
    pub shard_query: Fp16,
    pub component_evaluations: [Fp16; PACKED_INSTANCES],
}

/// Compact verifier state for the row-batched packed-coefficient relation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fp16ZkRsGkrBinding {
    pub claims: Vec<PackedComponentClaim>,
    pub claim_challenge: Fp16,
    pub coordinate_challenge: Fp16,
    pub expected_target: Fp16,
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

fn is_hash_message_position(position: usize) -> bool {
    position & (LOW_MESSAGE_WIRES - 1) < HASH_MESSAGE_WIRES
}

fn coordinate_batch(value: Fp16, challenge: Fp16) -> Fp16 {
    let mut power = Fp16::ONE;
    value
        .coefficients()
        .into_iter()
        .fold(Fp16::ZERO, |sum, coordinate| {
            let result = sum
                + power.mul_by_m31(
                    M31::from_canonical(coordinate).expect("Fp16 coordinates are canonical"),
                );
            power = power * challenge;
            result
        })
}

fn packed_component_coordinates(evaluations: &[Fp16; PACKED_INSTANCES], coordinate: usize) -> Fp16 {
    let coefficients =
        core::array::from_fn(|component| evaluations[component].coefficients()[coordinate]);
    Fp16::from_coefficients(coefficients).expect("evaluations have canonical coordinates")
}

fn validate_claims(claims: &[PackedComponentClaim]) -> Result<(), Fp16ZkRsGkrBindingError> {
    if claims.len() != GKR_CLAIM_COUNT {
        return Err(Fp16ZkRsGkrBindingError::ClaimCount);
    }
    if claims[0].boundary != 0 || claims[1..].iter().any(|claim| claim.boundary != 1) {
        return Err(Fp16ZkRsGkrBindingError::BoundaryOrder);
    }
    if claims
        .iter()
        .any(|claim| claim.claim.point.len() != BOUNDARY_VARIABLES)
    {
        return Err(Fp16ZkRsGkrBindingError::PointDimension);
    }
    if claims[0].claim.coefficient != Fp16::ONE {
        return Err(Fp16ZkRsGkrBindingError::OutputCoefficient);
    }
    if claims[1..]
        .iter()
        .any(|claim| claim.claim.coefficient.is_zero())
    {
        return Err(Fp16ZkRsGkrBindingError::ZeroInputCoefficient);
    }

    let basis = lagrange_basis();
    for (claim_ordinal, claim) in claims.iter().enumerate() {
        if claim_ordinal >= DIRECT_CLAIM_START {
            if claim
                .component_evaluations
                .iter()
                .any(|evaluation| *evaluation != claim.claim.value)
            {
                return Err(Fp16ZkRsGkrBindingError::GkrValueMismatch);
            }
            continue;
        }
        let shard_weights = lagrange_evaluations(&basis, claim.shard_query);
        let expected = claim
            .component_evaluations
            .iter()
            .copied()
            .zip(shard_weights)
            .fold(Fp16::ZERO, |sum, (evaluation, weight)| {
                sum + evaluation * weight
            });
        if expected != claim.claim.value {
            return Err(Fp16ZkRsGkrBindingError::GkrValueMismatch);
        }
    }
    Ok(())
}

/// Bind the canonical nineteen GKR claims to one packed-coefficient relation.
///
/// Both batching challenges are authenticated verifier coins sampled only
/// after all component evaluations are fixed.  Zero is rejected so no
/// canonical claim or coordinate can be silently dropped.
pub fn bind_gkr_boundary_claims(
    claims: &[PackedComponentClaim],
    claim_challenge: Fp16,
    coordinate_challenge: Fp16,
) -> Result<Fp16ZkRsGkrBinding, Fp16ZkRsGkrBindingError> {
    validate_claims(claims)?;
    if claim_challenge.is_zero() {
        return Err(Fp16ZkRsGkrBindingError::ZeroClaimChallenge);
    }
    if coordinate_challenge.is_zero() {
        return Err(Fp16ZkRsGkrBindingError::ZeroCoordinateChallenge);
    }

    let mut claim_power = Fp16::ONE;
    let mut expected_target = Fp16::ZERO;
    for (claim_ordinal, claim) in claims.iter().enumerate() {
        if claim_ordinal >= DIRECT_CLAIM_START {
            expected_target = expected_target + claim_power * claim.claim.value;
        } else {
            let mut coordinate_power = Fp16::ONE;
            for coordinate in 0..PACKED_INSTANCES {
                expected_target = expected_target
                    + claim_power
                        * coordinate_power
                        * packed_component_coordinates(&claim.component_evaluations, coordinate);
                coordinate_power = coordinate_power * coordinate_challenge;
            }
        }
        claim_power = claim_power * claim_challenge;
    }

    Ok(Fp16ZkRsGkrBinding {
        claims: claims.to_vec(),
        claim_challenge,
        coordinate_challenge,
        expected_target,
    })
}

/// Evaluate the verifier-derived relation coefficient at one packed address.
///
/// Boolean index bit zero corresponds to GKR point coordinate zero.  The low
/// sixteen bits are the RS-message coefficient position and the high eight
/// bits are the word within one boundary.
pub fn relation_weight(
    binding: &Fp16ZkRsGkrBinding,
    boundary: usize,
    index: usize,
) -> Result<Fp16, Fp16ZkRsGkrBindingError> {
    if boundary >= BOUNDARY_COUNT || index >= 1 << BOUNDARY_VARIABLES {
        return Err(Fp16ZkRsGkrBindingError::BoundaryOrder);
    }
    let mut claim_power = Fp16::ONE;
    let mut result = Fp16::ZERO;
    for (claim_ordinal, claim) in binding.claims.iter().enumerate() {
        if usize::from(claim.boundary) == boundary {
            let relation = if claim_ordinal >= DIRECT_CLAIM_START {
                equality_weight(index, &claim.claim.point)
            } else {
                let position = index & ((1 << COEFFICIENT_VARIABLES) - 1);
                if is_hash_message_position(position) {
                    coordinate_batch(
                        equality_weight(index, &claim.claim.point),
                        binding.coordinate_challenge,
                    )
                } else {
                    Fp16::ZERO
                }
            };
            result = result + claim_power * relation;
        }
        claim_power = claim_power * binding.claim_challenge;
    }
    Ok(result)
}

/// Verify 512 relation-word sums against the component-claim target.
///
/// Each word value is already the inner product of one 65,536-coefficient
/// packed message with its verifier-derived relation row.  Construction 8.2
/// must prove those source inner products; treating them as ordinary
/// multilinear point evaluations is forbidden.
pub fn verify_gkr_relation_word_values(
    binding: &Fp16ZkRsGkrBinding,
    word_values: &[Fp16],
) -> Result<(), Fp16ZkRsGkrBindingError> {
    if word_values.len() != INTERLEAVED_WORDS {
        return Err(Fp16ZkRsGkrBindingError::WordValueCount);
    }
    let target = word_values
        .iter()
        .copied()
        .fold(Fp16::ZERO, |sum, value| sum + value);
    if target != binding.expected_target {
        return Err(Fp16ZkRsGkrBindingError::TargetMismatch);
    }
    Ok(())
}

fn fp16_basis() -> [Fp16; PACKED_INSTANCES] {
    core::array::from_fn(|coordinate| {
        let mut coefficients = [0_u32; PACKED_INSTANCES];
        coefficients[coordinate] = 1;
        Fp16::from_coefficients(coefficients).expect("frozen basis vector is canonical")
    })
}

fn frobenius_powers(value: Fp16) -> [Fp16; PACKED_INSTANCES] {
    let mut powers = [Fp16::ZERO; PACKED_INSTANCES];
    powers[0] = value;
    for power in 1..PACKED_INSTANCES {
        powers[power] = powers[power - 1].pow_u32(M31_MODULUS);
    }
    powers
}

pub(crate) fn linearized_coefficients(
    images: [Fp16; PACKED_INSTANCES],
) -> [Fp16; PACKED_INSTANCES] {
    let basis = fp16_basis();
    let mut matrix: [[Fp16; PACKED_INSTANCES + 1]; PACKED_INSTANCES] =
        core::array::from_fn(|row| {
            let powers = frobenius_powers(basis[row]);
            core::array::from_fn(|column| {
                if column == PACKED_INSTANCES {
                    images[row]
                } else {
                    powers[column]
                }
            })
        });
    for column in 0..PACKED_INSTANCES {
        let pivot = (column..PACKED_INSTANCES)
            .find(|row| !matrix[*row][column].is_zero())
            .expect("the frozen Moore matrix is nonsingular");
        matrix.swap(column, pivot);
        let inverse = matrix[column][column]
            .inverse()
            .expect("the pivot is nonzero");
        for value in &mut matrix[column][column..] {
            *value = *value * inverse;
        }
        let pivot_row = matrix[column];
        for (row, values) in matrix.iter_mut().enumerate() {
            if row == column {
                continue;
            }
            let scale = values[column];
            for entry in column..=PACKED_INSTANCES {
                values[entry] = values[entry] - scale * pivot_row[entry];
            }
        }
    }
    core::array::from_fn(|row| matrix[row][PACKED_INSTANCES])
}

/// Return the unique sixteen-term linearized-polynomial representation of
/// coordinate batching at `challenge`.
///
/// Accelerator coordinators may upload these verifier-derived coefficients,
/// but the independent answer verifier remains authoritative for the final
/// relation target.
pub fn coordinate_linearized_coefficients(challenge: Fp16) -> [Fp16; PACKED_INSTANCES] {
    let images = fp16_basis().map(|basis| coordinate_batch(basis, challenge));
    linearized_coefficients(images)
}

fn word_fold_weight(word: usize, challenges: &[Fp16]) -> Fp16 {
    equality_weight(word, challenges)
}

fn claim_linearized_coefficients(
    binding: &Fp16ZkRsGkrBinding,
    claim_ordinal: usize,
    word_challenges: &[Fp16],
) -> [Fp16; PACKED_INSTANCES] {
    let claim = &binding.claims[claim_ordinal];
    let boundary_weight = if claim.boundary == 0 {
        Fp16::ONE - word_challenges[WORD_VARIABLES]
    } else {
        word_challenges[WORD_VARIABLES]
    };
    let claim_power = claim_power(binding, claim_ordinal);
    let scale = claim_power * boundary_weight;
    let high_point = &claim.claim.point[COEFFICIENT_VARIABLES..];
    let images = fp16_basis().map(|basis| {
        (0..WORDS_PER_BOUNDARY).fold(Fp16::ZERO, |sum, word| {
            let fold = word_fold_weight(word, &word_challenges[..WORD_VARIABLES]);
            let high = equality_weight(word, high_point);
            sum + fold * coordinate_batch(basis * high, binding.coordinate_challenge)
        }) * scale
    });
    linearized_coefficients(images)
}

fn claim_power(binding: &Fp16ZkRsGkrBinding, claim_ordinal: usize) -> Fp16 {
    (0..claim_ordinal).fold(Fp16::ONE, |power, _| power * binding.claim_challenge)
}

fn equality_table(point: &[Fp16]) -> Vec<Fp16> {
    let mut table = vec![Fp16::ONE];
    for challenge in point {
        let previous = table.len();
        table.resize(2 * previous, Fp16::ZERO);
        for index in (0..previous).rev() {
            let value = table[index];
            table[index] = value * (Fp16::ONE - *challenge);
            table[previous + index] = value * *challenge;
        }
    }
    table
}

/// Derive the final 65,536-entry Construction 7.2 linear form after the nine
/// interleaving-sumcheck challenges.
///
/// The coordinate projection is an M31-linear map on Fp16.  It is converted
/// to its unique 16-term linearized polynomial, so the verifier builds only
/// sixteen ordinary equality tables per GKR claim rather than a 512 by
/// 65,536 relation table.
pub fn folded_relation_table(
    binding: &Fp16ZkRsGkrBinding,
    word_challenges: &[Fp16],
) -> Result<Vec<Fp16>, Fp16ZkRsGkrBindingError> {
    if word_challenges.len() != WORD_VARIABLES + 1 {
        return Err(Fp16ZkRsGkrBindingError::WordChallengeCount);
    }
    let mut relation = vec![Fp16::ZERO; 1 << COEFFICIENT_VARIABLES];
    for (claim_ordinal, claim) in binding.claims.iter().enumerate() {
        if claim_ordinal >= DIRECT_CLAIM_START {
            let boundary_weight = if claim.boundary == 0 {
                Fp16::ONE - word_challenges[WORD_VARIABLES]
            } else {
                word_challenges[WORD_VARIABLES]
            };
            let claim_scale = claim_power(binding, claim_ordinal) * boundary_weight;
            let low_table = equality_table(&claim.claim.point[..COEFFICIENT_VARIABLES]);
            let high_scale = (0..WORDS_PER_BOUNDARY).fold(Fp16::ZERO, |sum, word| {
                sum + word_fold_weight(word, &word_challenges[..WORD_VARIABLES])
                    * equality_weight(word, &claim.claim.point[COEFFICIENT_VARIABLES..])
            });
            let coefficient = claim_scale * high_scale;
            for (destination, equality) in relation.iter_mut().zip(low_table) {
                *destination = *destination + coefficient * equality;
            }
            continue;
        }
        let coefficients = claim_linearized_coefficients(binding, claim_ordinal, word_challenges);
        let mut conjugated_point = claim.claim.point[..COEFFICIENT_VARIABLES].to_vec();
        for coefficient in coefficients {
            let mut table = equality_table(&conjugated_point);
            for (position, equality) in table.iter_mut().enumerate() {
                if !is_hash_message_position(position) {
                    *equality = Fp16::ZERO;
                }
            }
            for (destination, equality) in relation.iter_mut().zip(table) {
                *destination = *destination + coefficient * equality;
            }
            for coordinate in &mut conjugated_point {
                *coordinate = coordinate.pow_u32(M31_MODULUS);
            }
        }
    }
    Ok(relation)
}

fn component_polynomial_evaluations(
    answer_coefficients: &[Fp16],
    point: &[Fp16],
    hash_only: bool,
) -> [Fp16; PACKED_INSTANCES] {
    let equality = equality_table(point);
    let mut evaluations = [Fp16::ZERO; PACKED_INSTANCES];
    for (position, (coefficient, weight)) in answer_coefficients
        .iter()
        .copied()
        .zip(equality)
        .enumerate()
    {
        if hash_only && !is_hash_message_position(position) {
            continue;
        }
        for (evaluation, coordinate) in evaluations.iter_mut().zip(coefficient.coefficients()) {
            *evaluation = *evaluation
                + weight.mul_by_m31(
                    M31::from_canonical(coordinate).expect("Fp16 coordinate is canonical"),
                );
        }
    }
    evaluations
}

/// Compute one claim's contribution to the final Construction 7.2 target.
///
/// This is the production verifier route.  It evaluates the sixteen M31
/// component polynomials once at the claim point, then obtains all Frobenius
/// conjugate evaluations algebraically.  It avoids constructing the slower
/// 65,536-entry row-relation table.
pub fn claim_main_answer_target(
    binding: &Fp16ZkRsGkrBinding,
    claim_ordinal: usize,
    word_challenges: &[Fp16],
    answer_coefficients: &[Fp16],
) -> Result<Fp16, Fp16ZkRsGkrBindingError> {
    if word_challenges.len() != WORD_VARIABLES + 1 {
        return Err(Fp16ZkRsGkrBindingError::WordChallengeCount);
    }
    if answer_coefficients.len() < 1 << COEFFICIENT_VARIABLES {
        return Err(Fp16ZkRsGkrBindingError::AnswerCoefficientCount);
    }
    let claim = binding
        .claims
        .get(claim_ordinal)
        .ok_or(Fp16ZkRsGkrBindingError::ClaimCount)?;
    if claim_ordinal >= DIRECT_CLAIM_START {
        let boundary_weight = if claim.boundary == 0 {
            Fp16::ONE - word_challenges[WORD_VARIABLES]
        } else {
            word_challenges[WORD_VARIABLES]
        };
        let high_scale = (0..WORDS_PER_BOUNDARY).fold(Fp16::ZERO, |sum, word| {
            sum + word_fold_weight(word, &word_challenges[..WORD_VARIABLES])
                * equality_weight(word, &claim.claim.point[COEFFICIENT_VARIABLES..])
        });
        let scale = claim_power(binding, claim_ordinal) * boundary_weight * high_scale;
        let low_table = equality_table(&claim.claim.point[..COEFFICIENT_VARIABLES]);
        return Ok(answer_coefficients[..1 << COEFFICIENT_VARIABLES]
            .iter()
            .copied()
            .zip(low_table)
            .fold(Fp16::ZERO, |sum, (coefficient, equality)| {
                sum + coefficient * equality * scale
            }));
    }
    let coefficients = claim_linearized_coefficients(binding, claim_ordinal, word_challenges);
    let mut components = component_polynomial_evaluations(
        &answer_coefficients[..1 << COEFFICIENT_VARIABLES],
        &claim.claim.point[..COEFFICIENT_VARIABLES],
        true,
    );
    let basis = fp16_basis();
    let mut target = Fp16::ZERO;
    for coefficient in coefficients {
        let packed_conjugate = basis
            .iter()
            .copied()
            .zip(components)
            .fold(Fp16::ZERO, |sum, (basis_element, component)| {
                sum + basis_element * component
            });
        target = target + coefficient * packed_conjugate;
        for component in &mut components {
            *component = component.pow_u32(M31_MODULUS);
        }
    }
    Ok(target)
}

/// Independently enforce Construction 7.2's main answer target.
///
/// The answer carries 65,536 message coefficients followed by random-padding
/// coefficients.  Random padding is authenticated by the code but is not part
/// of this public linear relation.
pub fn verify_main_answer_target(
    binding: &Fp16ZkRsGkrBinding,
    word_challenges: &[Fp16],
    answer_coefficients: &[Fp16],
    expected_target: Fp16,
) -> Result<(), Fp16ZkRsGkrBindingError> {
    if answer_coefficients.len() < 1 << COEFFICIENT_VARIABLES {
        return Err(Fp16ZkRsGkrBindingError::AnswerCoefficientCount);
    }
    let mut actual = Fp16::ZERO;
    for claim_ordinal in 0..binding.claims.len() {
        actual = actual
            + claim_main_answer_target(
                binding,
                claim_ordinal,
                word_challenges,
                answer_coefficients,
            )?;
    }
    if actual != expected_target {
        return Err(Fp16ZkRsGkrBindingError::AnswerTargetMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPARSE_PER_BOUNDARY: usize = 4;
    type SparseBoundaryFixture =
        [[(usize, [M31; PACKED_INSTANCES]); SPARSE_PER_BOUNDARY]; BOUNDARY_COUNT];

    fn fp(value: u32) -> Fp16 {
        Fp16::from_m31(M31::from_canonical(value).unwrap())
    }

    fn field(seed: u32) -> Fp16 {
        let coefficients =
            core::array::from_fn(|coordinate| (seed + 97 * coordinate as u32) % 2_147_483_647);
        Fp16::from_coefficients(coefficients).unwrap()
    }

    fn sparse_source(boundary: usize) -> [(usize, [M31; PACKED_INSTANCES]); SPARSE_PER_BOUNDARY] {
        core::array::from_fn(|entry| {
            let word = (17 + 71 * boundary + 43 * entry) % WORDS_PER_BOUNDARY;
            let wire = (101 + 137 * boundary + 997 * entry) % HASH_MESSAGE_WIRES;
            let group = (17 + 71 * boundary + 43 * entry) % 32;
            let position = (group << 11) | wire;
            let components = core::array::from_fn(|component| {
                M31::from_canonical(
                    (11 + 10_007 * boundary as u32 + 1_009 * entry as u32 + 131 * component as u32)
                        % 2_147_483_647,
                )
                .unwrap()
            });
            ((word << COEFFICIENT_VARIABLES) | position, components)
        })
    }

    fn component_claim(
        ordinal: usize,
        boundary: usize,
        source: &[(usize, [M31; PACKED_INSTANCES]); SPARSE_PER_BOUNDARY],
        direct: bool,
    ) -> PackedComponentClaim {
        let point = (0..BOUNDARY_VARIABLES)
            .map(|coordinate| field(31 + 401 * ordinal as u32 + 17 * coordinate as u32))
            .collect::<Vec<_>>();
        let component_evaluations = if direct {
            let value = source.iter().fold(Fp16::ZERO, |sum, (index, values)| {
                let packed = Fp16::from_coefficients(values.map(M31::as_u32)).unwrap();
                sum + equality_weight(*index, &point) * packed
            });
            [value; PACKED_INSTANCES]
        } else {
            core::array::from_fn(|component| {
                source.iter().fold(Fp16::ZERO, |sum, (index, values)| {
                    sum + equality_weight(*index, &point).mul_by_m31(values[component])
                })
            })
        };
        let shard_query = field(7_001 + 211 * ordinal as u32);
        let value = if direct {
            component_evaluations[0]
        } else {
            let shard_weights = lagrange_evaluations(&lagrange_basis(), shard_query);
            component_evaluations
                .iter()
                .copied()
                .zip(shard_weights)
                .fold(Fp16::ZERO, |sum, (evaluation, weight)| {
                    sum + evaluation * weight
                })
        };
        PackedComponentClaim {
            boundary: boundary as u8,
            claim: LayerOutputClaim {
                point,
                value,
                coefficient: if ordinal == 0 {
                    Fp16::ONE
                } else {
                    field(9_001 + ordinal as u32)
                },
            },
            shard_query,
            component_evaluations,
        }
    }

    fn fixture() -> (Vec<PackedComponentClaim>, SparseBoundaryFixture) {
        let sources = [sparse_source(0), sparse_source(1)];
        let mut claims = Vec::with_capacity(GKR_CLAIM_COUNT);
        claims.push(component_claim(0, 0, &sources[0], false));
        for ordinal in 1..GKR_CLAIM_COUNT {
            claims.push(component_claim(
                ordinal,
                1,
                &sources[1],
                ordinal >= DIRECT_CLAIM_START,
            ));
        }
        (claims, sources)
    }

    #[test]
    fn row_batched_identity_matches_sparse_packed_source() {
        let (claims, sources) = fixture();
        let binding = bind_gkr_boundary_claims(&claims, field(19_001), field(23_001)).unwrap();
        let mut word_values = vec![Fp16::ZERO; INTERLEAVED_WORDS];
        for (boundary, source) in sources.iter().enumerate() {
            for (index, components) in source {
                let packed = Fp16::from_coefficients(components.map(M31::as_u32)).unwrap();
                let word = index >> COEFFICIENT_VARIABLES;
                word_values[boundary * WORDS_PER_BOUNDARY + word] = word_values
                    [boundary * WORDS_PER_BOUNDARY + word]
                    + packed * relation_weight(&binding, boundary, *index).unwrap();
            }
        }
        verify_gkr_relation_word_values(&binding, &word_values).unwrap();

        word_values[311] = word_values[311] + Fp16::ONE;
        assert_eq!(
            verify_gkr_relation_word_values(&binding, &word_values),
            Err(Fp16ZkRsGkrBindingError::TargetMismatch)
        );
    }

    fn slow_folded_relation_weight(
        binding: &Fp16ZkRsGkrBinding,
        position: usize,
        word_challenges: &[Fp16],
    ) -> Fp16 {
        (0..BOUNDARY_COUNT).fold(Fp16::ZERO, |boundary_sum, boundary| {
            let boundary_factor = if boundary == 0 {
                Fp16::ONE - word_challenges[WORD_VARIABLES]
            } else {
                word_challenges[WORD_VARIABLES]
            };
            boundary_sum
                + boundary_factor
                    * (0..WORDS_PER_BOUNDARY).fold(Fp16::ZERO, |word_sum, word| {
                        let index = (word << COEFFICIENT_VARIABLES) | position;
                        word_sum
                            + word_fold_weight(word, &word_challenges[..WORD_VARIABLES])
                                * relation_weight(binding, boundary, index).unwrap()
                    })
        })
    }

    #[test]
    fn linearized_final_form_matches_direct_512_word_fold_and_answer_target() {
        let (claims, sources) = fixture();
        let binding = bind_gkr_boundary_claims(&claims, field(37_001), field(41_001)).unwrap();
        let challenges = (0..WORD_VARIABLES + 1)
            .map(|index| field(43_001 + 307 * index as u32))
            .collect::<Vec<_>>();
        let relation = folded_relation_table(&binding, &challenges).unwrap();
        for position in [0, 1, 101, 65_535] {
            assert_eq!(
                relation[position],
                slow_folded_relation_weight(&binding, position, &challenges)
            );
        }

        let mut folded_source = vec![Fp16::ZERO; 1 << COEFFICIENT_VARIABLES];
        for (boundary, source) in sources.iter().enumerate() {
            let boundary_factor = if boundary == 0 {
                Fp16::ONE - challenges[WORD_VARIABLES]
            } else {
                challenges[WORD_VARIABLES]
            };
            for (index, components) in source {
                let word = index >> COEFFICIENT_VARIABLES;
                let position = index & ((1 << COEFFICIENT_VARIABLES) - 1);
                let packed = Fp16::from_coefficients(components.map(M31::as_u32)).unwrap();
                folded_source[position] = folded_source[position]
                    + boundary_factor
                        * word_fold_weight(word, &challenges[..WORD_VARIABLES])
                        * packed;
            }
        }
        let expected = folded_source
            .iter()
            .copied()
            .zip(&relation)
            .fold(Fp16::ZERO, |sum, (value, weight)| sum + value * *weight);
        let fast_target = (0..GKR_CLAIM_COUNT).fold(Fp16::ZERO, |sum, claim_ordinal| {
            sum + claim_main_answer_target(&binding, claim_ordinal, &challenges, &folded_source)
                .unwrap()
        });
        assert_eq!(fast_target, expected);
        verify_main_answer_target(&binding, &challenges, &folded_source, expected).unwrap();
        folded_source[101] = folded_source[101] + Fp16::ONE;
        assert_eq!(
            verify_main_answer_target(&binding, &challenges, &folded_source, expected),
            Err(Fp16ZkRsGkrBindingError::AnswerTargetMismatch)
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn production_shape_fast_answer_target_is_bounded() {
        let (claims, _) = fixture();
        let binding = bind_gkr_boundary_claims(&claims, field(47_001), field(53_001)).unwrap();
        let challenges = (0..WORD_VARIABLES + 1)
            .map(|index| field(59_001 + 419 * index as u32))
            .collect::<Vec<_>>();
        let answer = (0..1 << COEFFICIENT_VARIABLES)
            .map(|position| field(61_001 + 23 * position as u32))
            .collect::<Vec<_>>();
        let expected = (0..GKR_CLAIM_COUNT).fold(Fp16::ZERO, |sum, claim_ordinal| {
            sum + claim_main_answer_target(&binding, claim_ordinal, &challenges, &answer).unwrap()
        });
        let started = std::time::Instant::now();
        verify_main_answer_target(&binding, &challenges, &answer, expected).unwrap();
        std::println!(
            "fast_answer_target_seconds={:.6}",
            started.elapsed().as_secs_f64()
        );
    }

    #[test]
    fn malformed_order_value_and_challenges_fail_closed() {
        let (claims, _) = fixture();
        let rho = field(29_001);
        let lambda = field(31_001);

        assert_eq!(
            bind_gkr_boundary_claims(&claims[..4], rho, lambda),
            Err(Fp16ZkRsGkrBindingError::ClaimCount)
        );
        let mut wrong_boundary = claims.clone();
        wrong_boundary[3].boundary = 0;
        assert_eq!(
            bind_gkr_boundary_claims(&wrong_boundary, rho, lambda),
            Err(Fp16ZkRsGkrBindingError::BoundaryOrder)
        );
        let mut malformed = claims.clone();
        malformed[0].claim.point.pop();
        assert_eq!(
            bind_gkr_boundary_claims(&malformed, rho, lambda),
            Err(Fp16ZkRsGkrBindingError::PointDimension)
        );
        let mut output_coefficient = claims.clone();
        output_coefficient[0].claim.coefficient = fp(2);
        assert_eq!(
            bind_gkr_boundary_claims(&output_coefficient, rho, lambda),
            Err(Fp16ZkRsGkrBindingError::OutputCoefficient)
        );
        let mut input_coefficient = claims.clone();
        input_coefficient[2].claim.coefficient = Fp16::ZERO;
        assert_eq!(
            bind_gkr_boundary_claims(&input_coefficient, rho, lambda),
            Err(Fp16ZkRsGkrBindingError::ZeroInputCoefficient)
        );
        let mut changed_component = claims.clone();
        changed_component[4].component_evaluations[7] =
            changed_component[4].component_evaluations[7] + Fp16::ONE;
        assert_eq!(
            bind_gkr_boundary_claims(&changed_component, rho, lambda),
            Err(Fp16ZkRsGkrBindingError::GkrValueMismatch)
        );
        assert_eq!(
            bind_gkr_boundary_claims(&claims, Fp16::ZERO, lambda),
            Err(Fp16ZkRsGkrBindingError::ZeroClaimChallenge)
        );
        assert_eq!(
            bind_gkr_boundary_claims(&claims, rho, Fp16::ZERO),
            Err(Fp16ZkRsGkrBindingError::ZeroCoordinateChallenge)
        );
        let binding = bind_gkr_boundary_claims(&claims, rho, lambda).unwrap();
        assert_eq!(
            folded_relation_table(&binding, &[Fp16::ONE; WORD_VARIABLES]),
            Err(Fp16ZkRsGkrBindingError::WordChallengeCount)
        );
        assert_eq!(
            verify_main_answer_target(
                &binding,
                &[Fp16::ONE; WORD_VARIABLES + 1],
                &[Fp16::ZERO; 3],
                Fp16::ZERO
            ),
            Err(Fp16ZkRsGkrBindingError::AnswerCoefficientCount)
        );
    }
}
