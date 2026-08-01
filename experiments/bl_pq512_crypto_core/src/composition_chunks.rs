//! Degree-preserving quotient chunks on the committed trace domain.
//!
//! A high-degree AIR must not force every trace column onto the much larger
//! composition work domain.  The prover interpolates the quotient once on that
//! work domain, splits its Circle-basis coefficients into equal low-degree
//! chunks, and evaluates every chunk on the ordinary committed domain.  The
//! verifier joins chunk openings with the exact higher Circle-basis factors.

use alloc::vec::Vec;

use crate::circle_fft::{CircleFftError, evaluate_extension_circle_coefficients};
use crate::circle_fri::{CircleFriError, bit_reverse_index, canonic_circle_point};
use crate::field::Fp16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompositionChunkError {
    CircleFft(CircleFftError),
    CircleFri(CircleFriError),
    Shape,
}

impl From<CircleFftError> for CompositionChunkError {
    fn from(value: CircleFftError) -> Self {
        Self::CircleFft(value)
    }
}

impl From<CircleFriError> for CompositionChunkError {
    fn from(value: CircleFriError) -> Self {
        Self::CircleFri(value)
    }
}

fn checked_log_size(length: usize) -> Result<u8, CompositionChunkError> {
    if length < 4 || !length.is_power_of_two() {
        return Err(CompositionChunkError::Shape);
    }
    Ok(length.ilog2() as u8)
}

/// Split full quotient coefficients and evaluate every chunk on the smaller
/// committed domain. No coefficient is dropped or aliased.
pub fn evaluate_composition_chunks(
    coefficients: &[Fp16],
    component_coefficient_log_size: u8,
    committed_evaluation_log_size: u8,
) -> Result<Vec<Vec<Fp16>>, CompositionChunkError> {
    let full_log_size = checked_log_size(coefficients.len())?;
    if component_coefficient_log_size < 2
        || component_coefficient_log_size > full_log_size
        || committed_evaluation_log_size < component_coefficient_log_size
    {
        return Err(CompositionChunkError::Shape);
    }
    let chunk_len = 1_usize << component_coefficient_log_size;
    coefficients
        .chunks_exact(chunk_len)
        .map(|chunk| {
            evaluate_extension_circle_coefficients(chunk, committed_evaluation_log_size)
                .map_err(CompositionChunkError::from)
        })
        .collect()
}

fn fold_values(values: &[Fp16], mappings: &[Fp16]) -> Result<Fp16, CompositionChunkError> {
    if values.len() == 1 {
        return mappings
            .is_empty()
            .then_some(values[0])
            .ok_or(CompositionChunkError::Shape);
    }
    if mappings.is_empty() || !values.len().is_power_of_two() {
        return Err(CompositionChunkError::Shape);
    }
    let half = values.len() / 2;
    let left = fold_values(&values[..half], &mappings[1..])?;
    let right = fold_values(&values[half..], &mappings[1..])?;
    Ok(left.add(right.mul(mappings[0])))
}

/// Higher-basis mappings omitted from one low-degree chunk evaluation.
pub fn composition_chunk_mappings(
    full_coefficient_log_size: u8,
    committed_log_size: u8,
    committed_evaluation_log_size: u8,
    fft_index: usize,
) -> Result<Vec<Fp16>, CompositionChunkError> {
    if committed_log_size < 2
        || committed_log_size > full_coefficient_log_size
        || committed_evaluation_log_size < committed_log_size
    {
        return Err(CompositionChunkError::Shape);
    }
    let natural = bit_reverse_index(fft_index, committed_evaluation_log_size)?;
    let point = canonic_circle_point(committed_evaluation_log_size, natural)?;
    let mut mappings = Vec::with_capacity(usize::from(full_coefficient_log_size));
    mappings.push(Fp16::from_m31(point.y));
    if full_coefficient_log_size > 1 {
        let mut x = point.x;
        for _ in 1..full_coefficient_log_size {
            mappings.push(Fp16::from_m31(x));
            x = x.square().double().sub(crate::field::M31::ONE);
        }
    }
    mappings.reverse();
    mappings.truncate(usize::from(full_coefficient_log_size - committed_log_size));
    Ok(mappings)
}

/// Join one row of chunk evaluations into the original quotient evaluation.
pub fn join_composition_chunks_at(
    component_values: &[Fp16],
    full_coefficient_log_size: u8,
    committed_log_size: u8,
    committed_evaluation_log_size: u8,
    fft_index: usize,
) -> Result<Fp16, CompositionChunkError> {
    let expected = 1_usize << (full_coefficient_log_size - committed_log_size);
    if component_values.len() != expected {
        return Err(CompositionChunkError::Shape);
    }
    let mappings = composition_chunk_mappings(
        full_coefficient_log_size,
        committed_log_size,
        committed_evaluation_log_size,
        fft_index,
    )?;
    fold_values(component_values, &mappings)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::circle_fft::evaluate_extension_coefficients_at_point;
    use crate::circle_fri::{bit_reverse_index, canonic_circle_point};
    use crate::field::{Fp16, M31};
    use crate::oods::CirclePoint;

    #[test]
    fn chunks_reconstruct_nonzero_high_coefficients_on_smaller_domain() {
        let coefficients = (0..256)
            .map(|index| Fp16::from_m31(M31::from_canonical((index * 17 + 9) as u32).unwrap()))
            .collect::<Vec<_>>();
        let committed_log = 5;
        let evaluation_log = 6;
        let chunks =
            evaluate_composition_chunks(&coefficients, committed_log, evaluation_log).unwrap();
        assert_eq!(chunks.len(), 8);
        assert!(chunks[1..].iter().flatten().any(|value| !value.is_zero()));

        for fft_index in 0..1_usize << evaluation_log {
            let row = chunks
                .iter()
                .map(|chunk| chunk[fft_index])
                .collect::<Vec<_>>();
            let joined =
                join_composition_chunks_at(&row, 8, committed_log, evaluation_log, fft_index)
                    .unwrap();
            let natural = bit_reverse_index(fft_index, evaluation_log).unwrap();
            let point = canonic_circle_point(evaluation_log, natural).unwrap();
            let expected = evaluate_extension_coefficients_at_point(
                &coefficients,
                CirclePoint {
                    x: Fp16::from_m31(point.x),
                    y: Fp16::from_m31(point.y),
                },
            )
            .unwrap();
            assert_eq!(joined, expected);
        }
    }

    #[test]
    fn malformed_chunk_shapes_fail_closed() {
        assert_eq!(
            evaluate_composition_chunks(&vec![Fp16::ZERO; 8], 4, 5),
            Err(CompositionChunkError::Shape)
        );
        assert_eq!(
            join_composition_chunks_at(&[Fp16::ZERO; 3], 8, 5, 6, 0),
            Err(CompositionChunkError::Shape)
        );
    }
}
