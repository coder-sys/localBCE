//! Direct Circle evaluation-map certificates for native-hiding review.
//!
//! This module mirrors the Python CRT certificate inputs and independently
//! derives degree-16 minimal polynomials.  It covers direct trace-oracle
//! evaluations only; it is not the quotient-closure proof or full simulator.

use alloc::vec;
use alloc::vec::Vec;

use sha3::{Digest, Sha3_512};

use crate::circle_fri::{BaseCirclePoint, CircleFriError, bit_reverse_index, canonic_circle_point};
use crate::field::{EXTENSION_DEGREE, FieldError, Fp16, M31};

/// Exact direct evaluation-map certificate domain.
pub const EVALUATION_MAP_DOMAIN: &[u8] = b"BL/PQ512/WAVE1B/CIRCLE-EVALUATION-MAP/v1";

/// Strict direct evaluation-map construction failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CircleHidingError {
    /// A lower-level field operation failed.
    Field(FieldError),
    /// A lower-level Circle-domain operation failed.
    Circle(CircleFriError),
    /// The extension input was in Fp8 and did not have degree 16.
    ExtensionNotDegreeSixteen,
    /// A Frobenius orbit repeated before all 16 conjugates were visited.
    FrobeniusOrbitTooShort,
    /// A computed minimal-polynomial coefficient was not in M31.
    MinimalPolynomialNotOverBaseField,
    /// Two extension inputs belonged to the same Frobenius orbit.
    ExtensionFrobeniusOrbitDuplicate,
    /// No extension parameter or no query position was supplied.
    EmptyInput,
    /// The requested degree freedom was below the conservative direct rank.
    DegreeFreedomTooSmall,
    /// A query position did not fit the selected evaluation domain.
    QueryPositionOutOfRange,
    /// A stereographic denominator was zero.
    StereographicInfinity,
    /// A base-field translation unexpectedly lost degree 16.
    TranslationLostDegreeSixteen,
    /// An input count exceeded its canonical integer encoding.
    CountOverflow,
}

impl From<FieldError> for CircleHidingError {
    fn from(value: FieldError) -> Self {
        Self::Field(value)
    }
}

impl From<CircleFriError> for CircleHidingError {
    fn from(value: CircleFriError) -> Self {
        Self::Circle(value)
    }
}

/// Derive the exact monic M31 minimal polynomial of a degree-16 value.
pub fn minimal_polynomial_fp16(value: Fp16) -> Result<[u32; 17], CircleHidingError> {
    if value.is_in_fp8_subfield() {
        return Err(CircleHidingError::ExtensionNotDegreeSixteen);
    }
    let mut orbit = [Fp16::ZERO; EXTENSION_DEGREE];
    for power in 0..EXTENSION_DEGREE {
        let conjugate = value.frobenius(power as u8)?;
        if orbit[..power].contains(&conjugate) {
            return Err(CircleHidingError::FrobeniusOrbitTooShort);
        }
        orbit[power] = conjugate;
    }

    let mut polynomial = vec![Fp16::ONE];
    for root in orbit {
        let mut next = vec![Fp16::ZERO; polynomial.len() + 1];
        for (index, coefficient) in polynomial.into_iter().enumerate() {
            next[index] = next[index].sub(coefficient.mul(root));
            next[index + 1] = next[index + 1].add(coefficient);
        }
        polynomial = next;
    }

    let mut result = [0_u32; 17];
    for (index, coefficient) in polynomial.into_iter().enumerate() {
        let coordinates = coefficient.coefficients();
        if coordinates[1..].iter().any(|coordinate| *coordinate != 0) {
            return Err(CircleHidingError::MinimalPolynomialNotOverBaseField);
        }
        result[index] = coordinates[0];
    }
    if result[16] != 1 {
        return Err(CircleHidingError::MinimalPolynomialNotOverBaseField);
    }
    Ok(result)
}

/// Translate one degree-16 stereographic parameter by a base Circle point.
pub fn translate_circle_parameter(
    parameter: Fp16,
    step: BaseCirclePoint,
) -> Result<Fp16, CircleHidingError> {
    if parameter.is_in_fp8_subfield() {
        return Err(CircleHidingError::ExtensionNotDegreeSixteen);
    }
    let step_denominator = M31::ONE.add(step.x);
    if step_denominator.is_zero() {
        return Err(CircleHidingError::StereographicInfinity);
    }
    let step_parameter = step.y.mul(step_denominator.inverse()?);
    let embedded_step = Fp16::from_m31(step_parameter);
    let denominator = Fp16::ONE.sub(parameter.mul(embedded_step));
    if denominator.is_zero() {
        return Err(CircleHidingError::StereographicInfinity);
    }
    let translated = parameter.add(embedded_step).mul(denominator.inverse()?);
    if translated.is_in_fp8_subfield() {
        return Err(CircleHidingError::TranslationLostDegreeSixteen);
    }
    Ok(translated)
}

fn base_query_parameter(
    evaluation_log_size: u8,
    query_position: u64,
) -> Result<u32, CircleHidingError> {
    let domain_size = 1_u64
        .checked_shl(u32::from(evaluation_log_size))
        .ok_or(CircleHidingError::QueryPositionOutOfRange)?;
    if query_position >= domain_size || query_position > usize::MAX as u64 {
        return Err(CircleHidingError::QueryPositionOutOfRange);
    }
    let natural_index = bit_reverse_index(query_position as usize, evaluation_log_size)?;
    let point = canonic_circle_point(evaluation_log_size, natural_index)?;
    let denominator = M31::ONE.add(point.x);
    if denominator.is_zero() {
        return Err(CircleHidingError::StereographicInfinity);
    }
    Ok(point.y.mul(denominator.inverse()?).as_u32())
}

/// Compute the canonical direct evaluation-map certificate SHA3-512 digest.
pub fn direct_evaluation_certificate_commitment(
    extension_parameters: &[Fp16],
    evaluation_log_size: u8,
    query_positions: &[u64],
    degree_freedom: u64,
) -> Result<[u8; 64], CircleHidingError> {
    if extension_parameters.is_empty() || query_positions.is_empty() {
        return Err(CircleHidingError::EmptyInput);
    }
    let extension_count =
        u16::try_from(extension_parameters.len()).map_err(|_| CircleHidingError::CountOverflow)?;
    let query_count =
        u32::try_from(query_positions.len()).map_err(|_| CircleHidingError::CountOverflow)?;
    let minimals = extension_parameters
        .iter()
        .copied()
        .map(minimal_polynomial_fp16)
        .collect::<Result<Vec<_>, _>>()?;
    for (index, minimal) in minimals.iter().enumerate() {
        if minimals[..index].contains(minimal) {
            return Err(CircleHidingError::ExtensionFrobeniusOrbitDuplicate);
        }
    }
    let parameters = query_positions
        .iter()
        .copied()
        .map(|position| base_query_parameter(evaluation_log_size, position))
        .collect::<Result<Vec<_>, _>>()?;
    let mut unique_parameters = Vec::new();
    for parameter in parameters.iter().copied() {
        if !unique_parameters.contains(&parameter) {
            unique_parameters.push(parameter);
        }
    }
    let conservative_rank = u64::from(EXTENSION_DEGREE as u32)
        .checked_mul(u64::from(extension_count))
        .and_then(|rank| rank.checked_add(u64::from(query_count)))
        .ok_or(CircleHidingError::CountOverflow)?;
    if degree_freedom < conservative_rank {
        return Err(CircleHidingError::DegreeFreedomTooSmall);
    }
    let rank = u64::from(EXTENSION_DEGREE as u32) * u64::from(extension_count)
        + unique_parameters.len() as u64;
    let circle_basis_degree = degree_freedom / 2;
    let free_dimension = degree_freedom - rank;

    let mut hash = Sha3_512::new();
    hash.update(EVALUATION_MAP_DOMAIN);
    hash.update(extension_count.to_be_bytes());
    for (parameter, minimal) in extension_parameters.iter().zip(&minimals) {
        hash.update(parameter.encode());
        hash.update(17_u16.to_be_bytes());
        for coefficient in minimal {
            hash.update(coefficient.to_be_bytes());
        }
    }
    hash.update(u16::from(evaluation_log_size).to_be_bytes());
    hash.update(query_count.to_be_bytes());
    hash.update(degree_freedom.to_be_bytes());
    hash.update(circle_basis_degree.to_be_bytes());
    hash.update(rank.to_be_bytes());
    hash.update(free_dimension.to_be_bytes());
    for (position, parameter) in query_positions.iter().zip(parameters) {
        hash.update(position.to_be_bytes());
        hash.update(parameter.to_be_bytes());
    }
    Ok(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circle_fri::circle_domain_step;
    use crate::oods::{OODS_DEFAULT_MAX_ATTEMPTS, sample_oods_parameter};

    #[test]
    fn python_k512_direct_evaluation_certificate_matches() {
        let mut seed = [0_u8; 64];
        let mut session = [0_u8; 64];
        for (index, byte) in seed.iter_mut().enumerate() {
            *byte = index as u8;
        }
        for (index, byte) in session.iter_mut().enumerate() {
            *byte = (index + 64) as u8;
        }
        let sampled = sample_oods_parameter(&seed, &session, 3, OODS_DEFAULT_MAX_ATTEMPTS).unwrap();
        let translated = translate_circle_parameter(
            sampled.parameter.element(),
            circle_domain_step(20).unwrap(),
        )
        .unwrap();
        let positions = (0_u64..926).map(|index| index * 2).collect::<Vec<_>>();
        let digest = direct_evaluation_certificate_commitment(
            &[sampled.parameter.element(), translated],
            21,
            &positions,
            4_694,
        )
        .unwrap();
        assert_eq!(
            digest,
            hex64(
                "79148ba5b5ee6655478cd478cf3dd159bb8d458d1b6dad0245ee2db0ba223d4c7\
                 66e0764f9909d05cba9efd0ea98329f53a70618553bf53ea1cd3ead86b6fb04"
            )
        );
    }

    #[test]
    fn fixed_subfield_duplicate_orbit_and_short_rank_fail_closed() {
        assert_eq!(
            minimal_polynomial_fp16(Fp16::ONE),
            Err(CircleHidingError::ExtensionNotDegreeSixteen)
        );
        let value =
            Fp16::from_coefficients([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
                .unwrap();
        assert_eq!(
            direct_evaluation_certificate_commitment(&[value, value], 8, &[0, 2], 40),
            Err(CircleHidingError::ExtensionFrobeniusOrbitDuplicate)
        );
        assert_eq!(
            direct_evaluation_certificate_commitment(&[value], 8, &[0, 2], 17),
            Err(CircleHidingError::DegreeFreedomTooSmall)
        );
        assert_ne!(
            base_query_parameter(8, 0).unwrap(),
            base_query_parameter(8, 1).unwrap()
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

    #[test]
    fn field_modulus_is_the_expected_mersenne_prime() {
        assert_eq!(crate::field::M31_MODULUS, (1_u32 << 31) - 1);
    }
}
