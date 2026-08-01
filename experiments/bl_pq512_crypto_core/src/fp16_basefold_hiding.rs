//! Nonactivating algebra for arbitrary-field BaseFold witness hiding.
//!
//! A sensitive polynomial is randomized as `f + (X^|H| - 1) r`, preserving
//! its values on the fundamental subgroup `H`. The Reed--Solomon evaluation
//! domain is a disjoint multiplicative coset. A second, fully random companion
//! polynomial protects the subsequently folded virtual oracle.

use alloc::{vec, vec::Vec};

use crate::{
    field::Fp16,
    multilinear_pcs::{MultilinearPcsError, derive_two_adic_root},
};

pub fn mask_with_subgroup_vanishing(
    witness: &[Fp16],
    randomizer: &[Fp16],
) -> Result<Vec<Fp16>, MultilinearPcsError> {
    if witness.is_empty() || !witness.len().is_power_of_two() || randomizer.is_empty() {
        return Err(MultilinearPcsError::FriLayerShape);
    }
    let mut masked = vec![Fp16::ZERO; witness.len() + randomizer.len()];
    masked[..witness.len()].copy_from_slice(witness);
    for (degree, coefficient) in randomizer.iter().copied().enumerate() {
        masked[degree] = masked[degree] - coefficient;
        masked[witness.len() + degree] = masked[witness.len() + degree] + coefficient;
    }
    Ok(masked)
}

pub fn evaluate_univariate(coefficients: &[Fp16], point: Fp16) -> Fp16 {
    coefficients
        .iter()
        .copied()
        .rev()
        .fold(Fp16::ZERO, |value, coefficient| value * point + coefficient)
}

pub fn frozen_coset_shift() -> Fp16 {
    let mut coordinates = [0_u32; 16];
    coordinates[8] = 1;
    Fp16::from_coefficients(coordinates).expect("frozen tower generator is canonical")
}

pub fn coset_points(log_size: u8) -> Result<Vec<Fp16>, MultilinearPcsError> {
    let count = 1_usize << log_size;
    let root = derive_two_adic_root(log_size)?;
    let shift = frozen_coset_shift();
    let mut point = shift;
    let mut points = Vec::with_capacity(count);
    for _ in 0..count {
        points.push(point);
        point = point * root;
    }
    Ok(points)
}

pub fn coset_is_disjoint_from_two_adic_subgroup(log_size: u8) -> Result<bool, MultilinearPcsError> {
    let mut power = frozen_coset_shift();
    for _ in 0..log_size {
        power = power.square();
    }
    Ok(power != Fp16::ONE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{M31, M31_MODULUS};

    fn fp(value: u32) -> Fp16 {
        Fp16::from_m31(M31::from_canonical(value).unwrap())
    }

    fn deterministic_field(seed: u64) -> Fp16 {
        let mut state = seed;
        let coordinates = core::array::from_fn(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state as u32) % M31_MODULUS
        });
        Fp16::from_coefficients(coordinates).unwrap()
    }

    fn matrix_rank(mut matrix: Vec<Vec<Fp16>>) -> usize {
        let rows = matrix.len();
        let columns = matrix[0].len();
        let mut rank = 0;
        for column in 0..columns {
            let Some(pivot) = (rank..rows).find(|row| !matrix[*row][column].is_zero()) else {
                continue;
            };
            matrix.swap(rank, pivot);
            let inverse = matrix[rank][column].inverse().unwrap();
            for value in &mut matrix[rank][column..] {
                *value = *value * inverse;
            }
            let pivot_row = matrix[rank].clone();
            for (row, values) in matrix.iter_mut().enumerate() {
                if row == rank {
                    continue;
                }
                let scale = values[column];
                for index in column..columns {
                    values[index] = values[index] - scale * pivot_row[index];
                }
            }
            rank += 1;
        }
        rank
    }

    #[test]
    fn vanishing_mask_preserves_fundamental_domain_and_hides_coset_queries() {
        const LOG_H: u8 = 3;
        const QUERY_VIEWS: usize = 4;
        let witness = (0..1 << LOG_H)
            .map(|index| deterministic_field(101 + index as u64))
            .collect::<Vec<_>>();
        let randomizer = (0..QUERY_VIEWS)
            .map(|index| deterministic_field(701 + index as u64))
            .collect::<Vec<_>>();
        let masked = mask_with_subgroup_vanishing(&witness, &randomizer).unwrap();

        let root = derive_two_adic_root(LOG_H).unwrap();
        let mut point = Fp16::ONE;
        for _ in 0..1 << LOG_H {
            assert_eq!(
                evaluate_univariate(&masked, point),
                evaluate_univariate(&witness, point)
            );
            point = point * root;
        }

        assert!(coset_is_disjoint_from_two_adic_subgroup(LOG_H + 1).unwrap());
        let coset = coset_points(LOG_H + 1).unwrap();
        let h_size = 1_usize << LOG_H;
        let matrix = coset[..QUERY_VIEWS]
            .iter()
            .copied()
            .map(|query| {
                let vanishing = query.pow_u32(h_size as u32) - Fp16::ONE;
                let mut power = Fp16::ONE;
                (0..QUERY_VIEWS)
                    .map(|_| {
                        let value = vanishing * power;
                        power = power * query;
                        value
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert_eq!(matrix_rank(matrix), QUERY_VIEWS);
    }

    #[test]
    fn full_random_companion_changes_the_folded_virtual_oracle() {
        let sensitive = (0..16)
            .map(|index| deterministic_field(1_001 + index))
            .collect::<Vec<_>>();
        let companion = (0..16)
            .map(|index| deterministic_field(2_001 + index))
            .collect::<Vec<_>>();
        let alpha = fp(17);
        let virtual_oracle = sensitive
            .iter()
            .zip(&companion)
            .map(|(left, right)| *left + alpha * *right)
            .collect::<Vec<_>>();
        let mut changed = companion;
        changed[7] = changed[7] + Fp16::ONE;
        let changed_virtual = sensitive
            .iter()
            .zip(&changed)
            .map(|(left, right)| *left + alpha * *right)
            .collect::<Vec<_>>();
        assert_ne!(virtual_oracle, changed_virtual);
    }
}
