//! Nonactivating zero-knowledge ring-switch masking algebra.
//!
//! The Diamond--Posen ring-switch compiler sends a `2^k`-entry partial
//! evaluation before sampling the row-batching point. Sending that vector
//! directly is not zero knowledge. This module provides the exact linear
//! masking step: sample a uniform vector from the kernel of the public
//! equality functional and add it to the partial evaluation. A selected
//! protocol must separately commit to the mask and prove its evaluation at
//! the later row-batching point with a qualified hiding PCS.
//!
//! Randomness is supplied by the caller. This module does not select entropy,
//! a PCS, transcript domains, or a proof profile.

use alloc::{vec, vec::Vec};
use core::fmt;

use crate::gf128::Gf128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ZkRingSwitchError {
    EmptyVector,
    LengthMismatch { expected: usize, actual: usize },
    LengthNotPowerOfTwo { length: usize },
    PointLengthMismatch { expected: usize, actual: usize },
    ZeroFunctional,
}

impl fmt::Display for ZkRingSwitchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyVector => formatter.write_str("ring-switch vector must be nonempty"),
            Self::LengthMismatch { expected, actual } => {
                write!(formatter, "expected {expected} values, got {actual}")
            }
            Self::LengthNotPowerOfTwo { length } => {
                write!(
                    formatter,
                    "ring-switch vector length {length} is not a power of two"
                )
            }
            Self::PointLengthMismatch { expected, actual } => {
                write!(
                    formatter,
                    "ring-switch point requires {expected} coordinates, got {actual}"
                )
            }
            Self::ZeroFunctional => {
                formatter.write_str("ring-switch equality functional is identically zero")
            }
        }
    }
}

impl core::error::Error for ZkRingSwitchError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConditionedRingSwitchMask {
    values: Vec<Gf128>,
    pivot: usize,
}

impl ConditionedRingSwitchMask {
    pub fn values(&self) -> &[Gf128] {
        &self.values
    }

    pub const fn pivot(&self) -> usize {
        self.pivot
    }
}

/// Expands the Boolean-hypercube equality polynomial at `point`.
pub fn multilinear_equality(point: &[Gf128]) -> Result<Vec<Gf128>, ZkRingSwitchError> {
    let length = 1_usize
        .checked_shl(u32::try_from(point.len()).map_err(|_| {
            ZkRingSwitchError::LengthNotPowerOfTwo {
                length: point.len(),
            }
        })?)
        .ok_or(ZkRingSwitchError::LengthNotPowerOfTwo {
            length: point.len(),
        })?;
    let mut values = vec![Gf128::ZERO; length];
    values[0] = Gf128::ONE;
    let mut populated = 1;
    for &coordinate in point {
        let complement = Gf128::ONE + coordinate;
        for index in (0..populated).rev() {
            let value = values[index];
            values[2 * index] = value * complement;
            values[2 * index + 1] = value * coordinate;
        }
        populated *= 2;
    }
    Ok(values)
}

/// Evaluates a multilinear table at one point.
pub fn evaluate_multilinear(table: &[Gf128], point: &[Gf128]) -> Result<Gf128, ZkRingSwitchError> {
    validate_table_point(table, point)?;
    let mut folded = table.to_vec();
    let mut active = folded.len();
    for &coordinate in point {
        let complement = Gf128::ONE + coordinate;
        for index in 0..active / 2 {
            folded[index] = folded[2 * index] * complement + folded[2 * index + 1] * coordinate;
        }
        active /= 2;
    }
    Ok(folded[0])
}

/// Constructs a mask in the kernel of `functional`.
///
/// `free_values` must contain exactly one fewer element than `functional`.
/// For a nonzero functional, the result is a bijective parameterization of
/// its codimension-one kernel, so uniform independent inputs yield a uniform
/// kernel mask.
pub fn condition_zero_inner_product(
    functional: &[Gf128],
    free_values: &[Gf128],
) -> Result<ConditionedRingSwitchMask, ZkRingSwitchError> {
    if functional.is_empty() {
        return Err(ZkRingSwitchError::EmptyVector);
    }
    let expected = functional.len() - 1;
    if free_values.len() != expected {
        return Err(ZkRingSwitchError::LengthMismatch {
            expected,
            actual: free_values.len(),
        });
    }
    let pivot = functional
        .iter()
        .position(|&coefficient| coefficient != Gf128::ZERO)
        .ok_or(ZkRingSwitchError::ZeroFunctional)?;
    let inverse = functional[pivot]
        .inverse()
        .ok_or(ZkRingSwitchError::ZeroFunctional)?;
    let mut values = vec![Gf128::ZERO; functional.len()];
    let mut free_index = 0;
    let mut residual = Gf128::ZERO;
    for (index, &coefficient) in functional.iter().enumerate() {
        if index == pivot {
            continue;
        }
        values[index] = free_values[free_index];
        residual += coefficient * values[index];
        free_index += 1;
    }
    values[pivot] = residual * inverse;
    debug_assert_eq!(inner_product(functional, &values), Gf128::ZERO);
    Ok(ConditionedRingSwitchMask { values, pivot })
}

pub fn inner_product(left: &[Gf128], right: &[Gf128]) -> Gf128 {
    debug_assert_eq!(left.len(), right.len());
    left.iter()
        .zip(right)
        .fold(Gf128::ZERO, |sum, (&left, &right)| sum + left * right)
}

fn validate_table_point(table: &[Gf128], point: &[Gf128]) -> Result<(), ZkRingSwitchError> {
    if table.is_empty() {
        return Err(ZkRingSwitchError::EmptyVector);
    }
    if !table.len().is_power_of_two() {
        return Err(ZkRingSwitchError::LengthNotPowerOfTwo {
            length: table.len(),
        });
    }
    let expected = table.len().ilog2() as usize;
    if point.len() != expected {
        return Err(ZkRingSwitchError::PointLengthMismatch {
            expected,
            actual: point.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deterministic_values(count: usize, seed: u128) -> Vec<Gf128> {
        (0..count)
            .map(|index| {
                Gf128::from_u128(
                    seed.wrapping_add(index as u128 + 1)
                        .wrapping_mul(0x9e37_79b9_7f4a_7c15_d6e8_feb8_6659_fd93),
                )
            })
            .collect()
    }

    #[test]
    fn conditioned_mask_hides_partial_vector_without_changing_claim() {
        let low_point = deterministic_values(7, 0x7269_6e67);
        let functional = multilinear_equality(&low_point).unwrap();
        let partial = deterministic_values(128, 0x0070_6172_7469_616c);
        let free_values = deterministic_values(127, 0x6d61_736b);
        let mask = condition_zero_inner_product(&functional, &free_values).unwrap();
        let masked = partial
            .iter()
            .zip(mask.values())
            .map(|(&partial, &mask)| partial + mask)
            .collect::<Vec<_>>();

        assert_eq!(inner_product(&functional, mask.values()), Gf128::ZERO);
        assert_eq!(
            inner_product(&functional, &masked),
            inner_product(&functional, &partial)
        );

        let row_batch_point = deterministic_values(7, 0x0072_6f77_2d62_6174_6368);
        assert_eq!(
            evaluate_multilinear(&masked, &row_batch_point).unwrap(),
            evaluate_multilinear(&partial, &row_batch_point).unwrap()
                + evaluate_multilinear(mask.values(), &row_batch_point).unwrap()
        );
    }

    #[test]
    fn every_free_coordinate_changes_the_kernel_mask() {
        let functional =
            multilinear_equality(&deterministic_values(7, 0x6675_6e63_7469_6f6e)).unwrap();
        let zero = vec![Gf128::ZERO; 127];
        let baseline = condition_zero_inner_product(&functional, &zero).unwrap();
        assert_eq!(baseline.values(), &[Gf128::ZERO; 128]);
        for free_index in 0..127 {
            let mut free = zero.clone();
            free[free_index] = Gf128::ONE;
            let candidate = condition_zero_inner_product(&functional, &free).unwrap();
            assert_ne!(candidate.values(), baseline.values());
            assert_eq!(inner_product(&functional, candidate.values()), Gf128::ZERO);
        }
    }

    #[test]
    fn malformed_shapes_and_tampering_fail_the_algebraic_checks() {
        assert_eq!(
            condition_zero_inner_product(&[], &[]),
            Err(ZkRingSwitchError::EmptyVector)
        );
        assert_eq!(
            evaluate_multilinear(&[Gf128::ZERO; 3], &[Gf128::ZERO]),
            Err(ZkRingSwitchError::LengthNotPowerOfTwo { length: 3 })
        );

        let point = deterministic_values(7, 0x7461_6d70_6572);
        let functional = multilinear_equality(&point).unwrap();
        let free = deterministic_values(127, 0x6d61_736b);
        let mut mask = condition_zero_inner_product(&functional, &free)
            .unwrap()
            .values;
        mask[37] += Gf128::ONE;
        assert_ne!(inner_product(&functional, &mask), Gf128::ZERO);
    }
}
