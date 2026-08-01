//! Canonical pairwise masking for degree-preserving composition chunks.

use alloc::vec::Vec;
use sha3::{Digest, Sha3_512};

use crate::air_composition::AirCompositionOracle;
use crate::circle_fft::{CircleFftError, evaluate_extension_circle_coefficients};
use crate::circle_fri::{CircleFriError, bit_reverse_index, canonic_circle_point};
use crate::field::Fp16;
use crate::trace_mask::{TraceMaskError, sample_extension_trace_mask_coefficients};

pub const COMPOSITION_MASK_ID_DOMAIN: &[u8] = b"BL/PQ512/WAVE1B/COMPOSITION-QUOTIENT-MASK-ID/v2\0";
/// Pairwise masking multiplies a low-degree randomizer by the first omitted
/// Circle-basis factor, so one extra degree bit is mandatory before FRI blowup.
pub const COMPOSITION_MASK_DEGREE_SLACK_LOG: u8 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompositionMaskError {
    CircleFft(CircleFftError),
    CircleFri(CircleFriError),
    TraceMask(TraceMaskError),
    Shape,
    CountOverflow,
    Reconstruction,
}

impl From<CircleFftError> for CompositionMaskError {
    fn from(value: CircleFftError) -> Self {
        Self::CircleFft(value)
    }
}
impl From<CircleFriError> for CompositionMaskError {
    fn from(value: CircleFriError) -> Self {
        Self::CircleFri(value)
    }
}
impl From<TraceMaskError> for CompositionMaskError {
    fn from(value: TraceMaskError) -> Self {
        Self::TraceMask(value)
    }
}

pub(crate) fn mask_id(
    program_commitment: &[u8; 64],
    table_index: usize,
    pair_index: usize,
) -> Result<[u8; 64], CompositionMaskError> {
    let mut hash = Sha3_512::new();
    hash.update(COMPOSITION_MASK_ID_DOMAIN);
    hash.update(program_commitment);
    hash.update(
        u32::try_from(table_index)
            .map_err(|_| CompositionMaskError::CountOverflow)?
            .to_be_bytes(),
    );
    hash.update(
        u32::try_from(pair_index)
            .map_err(|_| CompositionMaskError::CountOverflow)?
            .to_be_bytes(),
    );
    Ok(hash.finalize().into())
}

/// Basis factor joining the equal left/right Circle coefficient halves.
pub fn canonical_split_factor(
    evaluation_log_size: u8,
    fft_index: usize,
) -> Result<Fp16, CompositionMaskError> {
    let natural = bit_reverse_index(fft_index, evaluation_log_size)?;
    let mut point = canonic_circle_point(evaluation_log_size, natural)?;
    for _ in 0..evaluation_log_size - 1 {
        point = point.double();
    }
    Ok(Fp16::from_m31(point.x))
}

/// Independently mask adjacent quotient chunks while preserving their exact
/// higher-basis join at every committed point.
pub fn mask_composition_components(
    composition: &mut AirCompositionOracle,
    secret_mask_seed: &[u8],
    session_id: &[u8],
    quotient_mask_coefficient_count: usize,
) -> Result<(), CompositionMaskError> {
    if quotient_mask_coefficient_count == 0 {
        return Err(CompositionMaskError::Shape);
    }
    for (table_index, table) in composition.tables.iter_mut().enumerate() {
        if table.composition_components_masked
            || table.composition.len() != 1_usize << table.evaluation_log_size
        {
            return Err(CompositionMaskError::Shape);
        }
        let components = table
            .composition_components
            .as_mut()
            .ok_or(CompositionMaskError::Shape)?;
        if components.len() < 2
            || !components.len().is_power_of_two()
            || components
                .iter()
                .any(|values| values.len() != table.composition.len())
            || quotient_mask_coefficient_count > 1_usize << table.component_coefficient_log_size
        {
            return Err(CompositionMaskError::Shape);
        }
        for pair_index in 0..components.len() / 2 {
            let sampled = sample_extension_trace_mask_coefficients(
                secret_mask_seed,
                session_id,
                &mask_id(
                    &composition.program_binary_commitment,
                    table_index,
                    pair_index,
                )?,
                quotient_mask_coefficient_count,
            )?;
            let mut mask_coefficients = sampled;
            mask_coefficients.resize(mask_coefficients.len().next_power_of_two(), Fp16::ZERO);
            let mask = evaluate_extension_circle_coefficients(
                &mask_coefficients,
                table.evaluation_log_size,
            )?;
            let (left_slice, right_slice) = components.split_at_mut(2 * pair_index + 1);
            let left = &mut left_slice[2 * pair_index];
            let right = &mut right_slice[0];
            for fft_index in 0..table.composition.len() {
                let mappings = crate::composition_chunks::composition_chunk_mappings(
                    table.composition_work_log_size,
                    table.component_coefficient_log_size,
                    table.evaluation_log_size,
                    fft_index,
                )
                .map_err(|_| CompositionMaskError::Shape)?;
                let factor = *mappings.last().ok_or(CompositionMaskError::Shape)?;
                let joined = left[fft_index].add(factor.mul(right[fft_index]));
                left[fft_index] = left[fft_index].add(factor.mul(mask[fft_index]));
                right[fft_index] = right[fft_index].sub(mask[fft_index]);
                if left[fft_index].add(factor.mul(right[fft_index])) != joined {
                    return Err(CompositionMaskError::Reconstruction);
                }
            }
        }
        let mut row = Vec::with_capacity(components.len());
        for fft_index in 0..table.composition.len() {
            row.clear();
            row.extend(components.iter().map(|component| component[fft_index]));
            let joined = crate::composition_chunks::join_composition_chunks_at(
                &row,
                table.composition_work_log_size,
                table.component_coefficient_log_size,
                table.evaluation_log_size,
                fft_index,
            )
            .map_err(|_| CompositionMaskError::Shape)?;
            if joined != table.composition[fft_index] {
                return Err(CompositionMaskError::Reconstruction);
            }
        }
        table.composition_components_masked = true;
    }
    Ok(())
}
