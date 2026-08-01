//! Scalar Circle FFT/IFFT and low-degree extension over the frozen M31 domain.
//!
//! The coefficient basis is the Circle-FFT tensor basis in bit-reversed order:
//! `y, x, pi(x), pi^2(x), ...`, where `pi(x)=2*x^2-1`.  Evaluations are also
//! returned in bit-reversed order.  This is the auditable scalar path; an
//! optimized path must remain exactly equivalent to it.

use alloc::vec;
use alloc::vec::Vec;

use crate::circle_fri::{BaseCirclePoint, M31_CIRCLE_LOG_ORDER, MAX_CIRCLE_DOMAIN_LOG_SIZE};
use crate::field::{FieldError, Fp16, M31};

/// Minimum Circle-FFT domain supported by the complete transform.
pub const MIN_CIRCLE_FFT_LOG_SIZE: u8 = 1;

/// Strict Circle-FFT construction failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CircleFftError {
    LogSizeInvalid { log_size: u8 },
    LengthInvalid { length: usize },
    TargetLogSizeTooSmall { source: u8, target: u8 },
    Field(FieldError),
}

impl From<FieldError> for CircleFftError {
    fn from(value: FieldError) -> Self {
        Self::Field(value)
    }
}

fn checked_log_size(length: usize) -> Result<u8, CircleFftError> {
    if length < 2 || !length.is_power_of_two() {
        return Err(CircleFftError::LengthInvalid { length });
    }
    let log_size = length.ilog2() as u8;
    if !(MIN_CIRCLE_FFT_LOG_SIZE..=MAX_CIRCLE_DOMAIN_LOG_SIZE).contains(&log_size) {
        return Err(CircleFftError::LogSizeInvalid { log_size });
    }
    Ok(log_size)
}

/// Convert rows produced in one-step canonical coset order into the natural
/// order expected by the Circle FFT domain.
///
/// Execution traces use the full coset sequence because `next` must mean the
/// next logical row. A Circle domain stores its second half in reverse. An
/// explicit boundary permutation is therefore mandatory.
pub fn coset_order_to_circle_domain_order<T: Clone>(
    values: &[T],
) -> Result<Vec<T>, CircleFftError> {
    checked_log_size(values.len())?;
    let half = values.len() / 2;
    let mut result = Vec::with_capacity(values.len());
    for index in 0..half {
        result.push(values[index << 1].clone());
    }
    for index in 0..half {
        result.push(values[values.len() - 1 - (index << 1)].clone());
    }
    Ok(result)
}

fn reverse_low_bits(index: usize, log_size: u8) -> usize {
    index.reverse_bits() >> (usize::BITS - u32::from(log_size))
}

/// In-place exact bit-reversal permutation.
pub fn bit_reverse_permute<T>(values: &mut [T]) -> Result<(), CircleFftError> {
    if values.len() == 1 {
        return Ok(());
    }
    let log_size = checked_log_size(values.len())?;
    for index in 0..values.len() {
        let reversed = reverse_low_bits(index, log_size);
        if reversed > index {
            values.swap(index, reversed);
        }
    }
    Ok(())
}

fn half_coset_parameters(log_size: u8) -> (usize, usize, u8) {
    let initial_index = 1_usize << (M31_CIRCLE_LOG_ORDER - (log_size + 1));
    let step_index = 1_usize << (M31_CIRCLE_LOG_ORDER - (log_size - 1));
    (initial_index, step_index, log_size - 1)
}

fn slow_precompute_twiddles(log_size: u8) -> Result<Vec<M31>, CircleFftError> {
    if !(3..=MAX_CIRCLE_DOMAIN_LOG_SIZE).contains(&log_size) {
        return Err(CircleFftError::LogSizeInvalid { log_size });
    }
    let (mut initial_index, mut step_index, mut coset_log_size) = half_coset_parameters(log_size);
    let mut twiddles = Vec::with_capacity(1_usize << (log_size - 1));
    while coset_log_size != 0 {
        let count = 1_usize << (coset_log_size - 1);
        let start = twiddles.len();
        for offset in 0..count {
            let point = BaseCirclePoint::generator()
                .multiply(initial_index.wrapping_add(offset.wrapping_mul(step_index)));
            twiddles.push(point.x);
        }
        bit_reverse_permute(&mut twiddles[start..])?;
        initial_index = initial_index.wrapping_mul(2);
        step_index = step_index.wrapping_mul(2);
        coset_log_size -= 1;
    }
    twiddles.push(M31::ONE);
    Ok(twiddles)
}

pub(crate) fn line_twiddle_layers(
    log_size: u8,
    inverse: bool,
) -> Result<Vec<Vec<M31>>, CircleFftError> {
    let mut buffer = slow_precompute_twiddles(log_size)?;
    if inverse {
        for value in &mut buffer {
            *value = value.inverse()?;
        }
    }
    let layer_count = usize::from(log_size - 1);
    let mut layers = Vec::with_capacity(layer_count);
    for exponent in 0..layer_count {
        let length = 1_usize << exponent;
        let end = buffer.len() - length;
        let start = end - length;
        layers.push(buffer[start..end].to_vec());
    }
    layers.reverse();
    Ok(layers)
}

pub(crate) fn circle_twiddles(first_line_layer: &[M31]) -> Result<Vec<M31>, CircleFftError> {
    if first_line_layer.len() < 2 || !first_line_layer.len().is_multiple_of(2) {
        return Err(CircleFftError::LengthInvalid {
            length: first_line_layer.len(),
        });
    }
    let mut result = Vec::with_capacity(first_line_layer.len() * 2);
    for pair in first_line_layer.chunks_exact(2) {
        let x = pair[0];
        let y = pair[1];
        result.extend_from_slice(&[y, y.neg(), x.neg(), x]);
    }
    Ok(result)
}

fn butterfly(left: &mut M31, right: &mut M31, twiddle: M31) {
    let product = right.mul(twiddle);
    let original_left = *left;
    *left = original_left.add(product);
    *right = original_left.sub(product);
}

fn inverse_butterfly(left: &mut M31, right: &mut M31, inverse_twiddle: M31) {
    let original_left = *left;
    let original_right = *right;
    *left = original_left.add(original_right);
    *right = original_left.sub(original_right).mul(inverse_twiddle);
}

fn extension_butterfly(left: &mut Fp16, right: &mut Fp16, twiddle: M31) {
    let product = right.mul(Fp16::from_m31(twiddle));
    let original_left = *left;
    *left = original_left.add(product);
    *right = original_left.sub(product);
}

fn extension_inverse_butterfly(left: &mut Fp16, right: &mut Fp16, inverse_twiddle: M31) {
    let original_left = *left;
    let original_right = *right;
    *left = original_left.add(original_right);
    *right = original_left
        .sub(original_right)
        .mul(Fp16::from_m31(inverse_twiddle));
}

fn layer_loop(values: &mut [M31], layer: usize, block: usize, twiddle: M31, inverse: bool) {
    for offset in 0..(1_usize << layer) {
        let left_index = (block << (layer + 1)) + offset;
        let right_index = left_index + (1_usize << layer);
        let (left_slice, right_slice) = values.split_at_mut(right_index);
        let left = &mut left_slice[left_index];
        let right = &mut right_slice[0];
        if inverse {
            inverse_butterfly(left, right, twiddle);
        } else {
            butterfly(left, right, twiddle);
        }
    }
}

fn extension_layer_loop(
    values: &mut [Fp16],
    layer: usize,
    block: usize,
    twiddle: M31,
    inverse: bool,
) {
    for offset in 0..(1_usize << layer) {
        let left_index = (block << (layer + 1)) + offset;
        let right_index = left_index + (1_usize << layer);
        let (left_slice, right_slice) = values.split_at_mut(right_index);
        let left = &mut left_slice[left_index];
        let right = &mut right_slice[0];
        if inverse {
            extension_inverse_butterfly(left, right, twiddle);
        } else {
            extension_butterfly(left, right, twiddle);
        }
    }
}

/// Evaluate bit-reversed Circle-FFT coefficients on the canonical domain.
pub fn evaluate_circle_coefficients(
    coefficients: &[M31],
    domain_log_size: u8,
) -> Result<Vec<M31>, CircleFftError> {
    let coefficient_log_size = checked_log_size(coefficients.len())?;
    if domain_log_size < coefficient_log_size {
        return Err(CircleFftError::TargetLogSizeTooSmall {
            source: coefficient_log_size,
            target: domain_log_size,
        });
    }
    if !(MIN_CIRCLE_FFT_LOG_SIZE..=MAX_CIRCLE_DOMAIN_LOG_SIZE).contains(&domain_log_size) {
        return Err(CircleFftError::LogSizeInvalid {
            log_size: domain_log_size,
        });
    }
    let mut values = vec![M31::ZERO; 1_usize << domain_log_size];
    values[..coefficients.len()].copy_from_slice(coefficients);
    if domain_log_size == 1 {
        let (_, _, _) = half_coset_parameters(domain_log_size);
        let initial = BaseCirclePoint::generator().multiply(1_usize << (M31_CIRCLE_LOG_ORDER - 2));
        let (mut left, mut right) = (values[0], values[1]);
        butterfly(&mut left, &mut right, initial.y);
        values[0] = left;
        values[1] = right;
        return Ok(values);
    }
    if domain_log_size == 2 {
        let (initial_index, _, _) = half_coset_parameters(domain_log_size);
        let initial = BaseCirclePoint::generator().multiply(initial_index);
        let (mut value0, mut value1, mut value2, mut value3) =
            (values[0], values[1], values[2], values[3]);
        butterfly(&mut value0, &mut value2, initial.x);
        butterfly(&mut value1, &mut value3, initial.x);
        butterfly(&mut value0, &mut value1, initial.y);
        butterfly(&mut value2, &mut value3, initial.y.neg());
        values.copy_from_slice(&[value0, value1, value2, value3]);
        return Ok(values);
    }

    let line_layers = line_twiddle_layers(domain_log_size, false)?;
    let circle_layer = circle_twiddles(&line_layers[0])?;
    for (layer, twiddles) in line_layers.iter().enumerate().rev() {
        for (block, twiddle) in twiddles.iter().copied().enumerate() {
            layer_loop(&mut values, layer + 1, block, twiddle, false);
        }
    }
    for (block, twiddle) in circle_layer.into_iter().enumerate() {
        layer_loop(&mut values, 0, block, twiddle, false);
    }
    Ok(values)
}

/// Interpolate bit-reversed canonical-domain evaluations into FFT coefficients.
pub fn interpolate_circle_evaluations(evaluations: &[M31]) -> Result<Vec<M31>, CircleFftError> {
    let log_size = checked_log_size(evaluations.len())?;
    let mut values = evaluations.to_vec();
    if log_size == 1 {
        let initial = BaseCirclePoint::generator().multiply(1_usize << (M31_CIRCLE_LOG_ORDER - 2));
        let inverse_y = initial.y.inverse()?;
        let (mut left, mut right) = (values[0], values[1]);
        inverse_butterfly(&mut left, &mut right, inverse_y);
        let inverse_size = M31::from_canonical(2)?.inverse()?;
        values[0] = left.mul(inverse_size);
        values[1] = right.mul(inverse_size);
        return Ok(values);
    }
    if log_size == 2 {
        let (initial_index, _, _) = half_coset_parameters(log_size);
        let initial = BaseCirclePoint::generator().multiply(initial_index);
        let inverse_x = initial.x.inverse()?;
        let inverse_y = initial.y.inverse()?;
        let (mut value0, mut value1, mut value2, mut value3) =
            (values[0], values[1], values[2], values[3]);
        inverse_butterfly(&mut value0, &mut value1, inverse_y);
        inverse_butterfly(&mut value2, &mut value3, inverse_y.neg());
        inverse_butterfly(&mut value0, &mut value2, inverse_x);
        inverse_butterfly(&mut value1, &mut value3, inverse_x);
        let inverse_size = M31::from_canonical(4)?.inverse()?;
        values.copy_from_slice(&[
            value0.mul(inverse_size),
            value1.mul(inverse_size),
            value2.mul(inverse_size),
            value3.mul(inverse_size),
        ]);
        return Ok(values);
    }

    let line_layers = line_twiddle_layers(log_size, true)?;
    let circle_layer = circle_twiddles(&line_layers[0])?;
    for (block, twiddle) in circle_layer.into_iter().enumerate() {
        layer_loop(&mut values, 0, block, twiddle, true);
    }
    for (layer, twiddles) in line_layers.iter().enumerate() {
        for (block, twiddle) in twiddles.iter().copied().enumerate() {
            layer_loop(&mut values, layer + 1, block, twiddle, true);
        }
    }
    let domain_size = u32::try_from(values.len()).map_err(|_| CircleFftError::LengthInvalid {
        length: values.len(),
    })?;
    let inverse_size = M31::from_canonical(domain_size)?.inverse()?;
    for value in &mut values {
        *value = value.mul(inverse_size);
    }
    Ok(values)
}

/// Interpolate natural-order trace rows and evaluate their low-degree extension.
pub fn low_degree_extend(
    natural_trace: &[M31],
    log_blowup: u8,
) -> Result<Vec<M31>, CircleFftError> {
    let trace_log_size = checked_log_size(natural_trace.len())?;
    let target_log_size = trace_log_size
        .checked_add(log_blowup)
        .ok_or(CircleFftError::LogSizeInvalid { log_size: u8::MAX })?;
    if target_log_size > MAX_CIRCLE_DOMAIN_LOG_SIZE {
        return Err(CircleFftError::LogSizeInvalid {
            log_size: target_log_size,
        });
    }
    let mut bit_reversed = natural_trace.to_vec();
    bit_reverse_permute(&mut bit_reversed)?;
    let coefficients = interpolate_circle_evaluations(&bit_reversed)?;
    evaluate_circle_coefficients(&coefficients, target_log_size)
}

/// Low-degree extend values whose input rows are in canonical coset order.
pub fn low_degree_extend_coset_order(
    coset_order_trace: &[M31],
    log_blowup: u8,
) -> Result<Vec<M31>, CircleFftError> {
    let circle_order = coset_order_to_circle_domain_order(coset_order_trace)?;
    low_degree_extend(&circle_order, log_blowup)
}

/// Evaluate bit-reversed Fp16 Circle-FFT coefficients on the canonical domain.
pub fn evaluate_extension_circle_coefficients(
    coefficients: &[Fp16],
    domain_log_size: u8,
) -> Result<Vec<Fp16>, CircleFftError> {
    let coefficient_log_size = checked_log_size(coefficients.len())?;
    if domain_log_size < coefficient_log_size {
        return Err(CircleFftError::TargetLogSizeTooSmall {
            source: coefficient_log_size,
            target: domain_log_size,
        });
    }
    if !(MIN_CIRCLE_FFT_LOG_SIZE..=MAX_CIRCLE_DOMAIN_LOG_SIZE).contains(&domain_log_size) {
        return Err(CircleFftError::LogSizeInvalid {
            log_size: domain_log_size,
        });
    }
    let mut values = vec![Fp16::ZERO; 1_usize << domain_log_size];
    values[..coefficients.len()].copy_from_slice(coefficients);
    if domain_log_size == 1 {
        let initial = BaseCirclePoint::generator().multiply(1_usize << (M31_CIRCLE_LOG_ORDER - 2));
        let (mut left, mut right) = (values[0], values[1]);
        extension_butterfly(&mut left, &mut right, initial.y);
        values[0] = left;
        values[1] = right;
        return Ok(values);
    }
    if domain_log_size == 2 {
        let (initial_index, _, _) = half_coset_parameters(domain_log_size);
        let initial = BaseCirclePoint::generator().multiply(initial_index);
        let (mut value0, mut value1, mut value2, mut value3) =
            (values[0], values[1], values[2], values[3]);
        extension_butterfly(&mut value0, &mut value2, initial.x);
        extension_butterfly(&mut value1, &mut value3, initial.x);
        extension_butterfly(&mut value0, &mut value1, initial.y);
        extension_butterfly(&mut value2, &mut value3, initial.y.neg());
        values.copy_from_slice(&[value0, value1, value2, value3]);
        return Ok(values);
    }
    let line_layers = line_twiddle_layers(domain_log_size, false)?;
    let circle_layer = circle_twiddles(&line_layers[0])?;
    for (layer, twiddles) in line_layers.iter().enumerate().rev() {
        for (block, twiddle) in twiddles.iter().copied().enumerate() {
            extension_layer_loop(&mut values, layer + 1, block, twiddle, false);
        }
    }
    for (block, twiddle) in circle_layer.into_iter().enumerate() {
        extension_layer_loop(&mut values, 0, block, twiddle, false);
    }
    Ok(values)
}

/// Interpolate bit-reversed Fp16 canonical-domain evaluations.
pub fn interpolate_extension_circle_evaluations(
    evaluations: &[Fp16],
) -> Result<Vec<Fp16>, CircleFftError> {
    let log_size = checked_log_size(evaluations.len())?;
    let mut values = evaluations.to_vec();
    if log_size == 1 {
        let initial = BaseCirclePoint::generator().multiply(1_usize << (M31_CIRCLE_LOG_ORDER - 2));
        let inverse_y = initial.y.inverse()?;
        let (mut left, mut right) = (values[0], values[1]);
        extension_inverse_butterfly(&mut left, &mut right, inverse_y);
        let inverse_size = M31::from_canonical(2)?.inverse()?;
        values[0] = left.mul(Fp16::from_m31(inverse_size));
        values[1] = right.mul(Fp16::from_m31(inverse_size));
        return Ok(values);
    }
    if log_size == 2 {
        let (initial_index, _, _) = half_coset_parameters(log_size);
        let initial = BaseCirclePoint::generator().multiply(initial_index);
        let inverse_x = initial.x.inverse()?;
        let inverse_y = initial.y.inverse()?;
        let (mut value0, mut value1, mut value2, mut value3) =
            (values[0], values[1], values[2], values[3]);
        extension_inverse_butterfly(&mut value0, &mut value1, inverse_y);
        extension_inverse_butterfly(&mut value2, &mut value3, inverse_y.neg());
        extension_inverse_butterfly(&mut value0, &mut value2, inverse_x);
        extension_inverse_butterfly(&mut value1, &mut value3, inverse_x);
        let inverse_size = Fp16::from_m31(M31::from_canonical(4)?.inverse()?);
        values.copy_from_slice(&[
            value0.mul(inverse_size),
            value1.mul(inverse_size),
            value2.mul(inverse_size),
            value3.mul(inverse_size),
        ]);
        return Ok(values);
    }
    let line_layers = line_twiddle_layers(log_size, true)?;
    let circle_layer = circle_twiddles(&line_layers[0])?;
    for (block, twiddle) in circle_layer.into_iter().enumerate() {
        extension_layer_loop(&mut values, 0, block, twiddle, true);
    }
    for (layer, twiddles) in line_layers.iter().enumerate() {
        for (block, twiddle) in twiddles.iter().copied().enumerate() {
            extension_layer_loop(&mut values, layer + 1, block, twiddle, true);
        }
    }
    let domain_size = u32::try_from(values.len()).map_err(|_| CircleFftError::LengthInvalid {
        length: values.len(),
    })?;
    let inverse_size = Fp16::from_m31(M31::from_canonical(domain_size)?.inverse()?);
    for value in &mut values {
        *value = value.mul(inverse_size);
    }
    Ok(values)
}

/// Interpolate equal-sized Fp16 columns while reusing one inverse-twiddle plan.
pub fn interpolate_extension_circle_evaluation_columns(
    evaluations: &[Vec<Fp16>],
) -> Result<Vec<Vec<Fp16>>, CircleFftError> {
    let first = evaluations
        .first()
        .ok_or(CircleFftError::LengthInvalid { length: 0 })?;
    let log_size = checked_log_size(first.len())?;
    if evaluations.iter().any(|column| column.len() != first.len()) {
        return Err(CircleFftError::LengthInvalid { length: 0 });
    }
    if log_size <= 2 {
        return evaluations
            .iter()
            .map(|column| interpolate_extension_circle_evaluations(column))
            .collect();
    }
    let line_layers = line_twiddle_layers(log_size, true)?;
    let circle_layer = circle_twiddles(&line_layers[0])?;
    let domain_size = u32::try_from(first.len()).map_err(|_| CircleFftError::LengthInvalid {
        length: first.len(),
    })?;
    let inverse_size = Fp16::from_m31(M31::from_canonical(domain_size)?.inverse()?);
    #[cfg(feature = "parallel")]
    if evaluations.len() > 1 && first.len() >= 1 << 12 {
        let workers = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
            .min(evaluations.len());
        if workers > 1 {
            let chunk_size = evaluations.len().div_ceil(workers);
            let pieces = std::thread::scope(|scope| {
                let handles = evaluations
                    .chunks(chunk_size)
                    .map(|chunk| {
                        scope.spawn(|| {
                            chunk
                                .iter()
                                .map(|column| {
                                    apply_extension_inverse_plan(
                                        column,
                                        &line_layers,
                                        &circle_layer,
                                        inverse_size,
                                    )
                                })
                                .collect::<Vec<_>>()
                        })
                    })
                    .collect::<Vec<_>>();
                handles
                    .into_iter()
                    .map(|handle| {
                        handle
                            .join()
                            .map_err(|_| CircleFftError::LengthInvalid { length: 0 })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })?;
            return Ok(pieces.into_iter().flatten().collect());
        }
    }
    evaluations
        .iter()
        .map(|column| {
            Ok(apply_extension_inverse_plan(
                column,
                &line_layers,
                &circle_layer,
                inverse_size,
            ))
        })
        .collect()
}

fn apply_extension_inverse_plan(
    column: &[Fp16],
    line_layers: &[Vec<M31>],
    circle_layer: &[M31],
    inverse_size: Fp16,
) -> Vec<Fp16> {
    let mut values = column.to_vec();
    for (block, twiddle) in circle_layer.iter().copied().enumerate() {
        extension_layer_loop(&mut values, 0, block, twiddle, true);
    }
    for (layer, twiddles) in line_layers.iter().enumerate() {
        for (block, twiddle) in twiddles.iter().copied().enumerate() {
            extension_layer_loop(&mut values, layer + 1, block, twiddle, true);
        }
    }
    for value in &mut values {
        *value = value.mul(inverse_size);
    }
    values
}

fn fold_coefficients(values: &[M31], mappings: &[M31]) -> M31 {
    if values.len() == 1 {
        return values[0];
    }
    let half = values.len() / 2;
    let left = fold_coefficients(&values[..half], &mappings[1..]);
    let right = fold_coefficients(&values[half..], &mappings[1..]);
    left.add(right.mul(mappings[0]))
}

fn fold_extension_coefficients(values: &[Fp16], mappings: &[Fp16]) -> Fp16 {
    if values.len() == 1 {
        return values[0];
    }
    let half = values.len() / 2;
    let left = fold_extension_coefficients(&values[..half], &mappings[1..]);
    let right = fold_extension_coefficients(&values[half..], &mappings[1..]);
    left.add(right.mul(mappings[0]))
}

/// Independently evaluate FFT-basis coefficients at one base-field circle point.
pub fn evaluate_coefficients_at_point(
    coefficients: &[M31],
    point: BaseCirclePoint,
) -> Result<M31, CircleFftError> {
    let log_size = checked_log_size(coefficients.len())?;
    let mut mappings = Vec::with_capacity(usize::from(log_size));
    mappings.push(point.y);
    if log_size > 1 {
        let mut x = point.x;
        for _ in 1..log_size {
            mappings.push(x);
            x = x.square().double().sub(M31::ONE);
        }
    }
    mappings.reverse();
    Ok(fold_coefficients(coefficients, &mappings))
}

/// Independently evaluate Fp16 FFT-basis coefficients at one Fp16 circle point.
pub fn evaluate_extension_coefficients_at_point(
    coefficients: &[Fp16],
    point: crate::oods::CirclePoint,
) -> Result<Fp16, CircleFftError> {
    let log_size = checked_log_size(coefficients.len())?;
    if point.x.square().add(point.y.square()) != Fp16::ONE {
        return Err(CircleFftError::LengthInvalid { length: 0 });
    }
    let mut mappings = Vec::with_capacity(usize::from(log_size));
    mappings.push(point.y);
    if log_size > 1 {
        let mut x = point.x;
        for _ in 1..log_size {
            mappings.push(x);
            let squared = x.square();
            x = squared.add(squared).sub(Fp16::ONE);
        }
    }
    mappings.reverse();
    Ok(fold_extension_coefficients(coefficients, &mappings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circle_fri::canonic_circle_point;

    fn values(log_size: u8) -> Vec<M31> {
        (0..1_u32 << log_size)
            .map(|value| M31::from_canonical(value * value + 17 * value + 3).unwrap())
            .collect()
    }

    fn extension_values(log_size: u8) -> Vec<Fp16> {
        values(log_size)
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                let mut coefficients = [0_u32; 16];
                coefficients[0] = value.as_u32();
                coefficients[8] = (index as u32 + 1) % crate::field::M31_MODULUS;
                Fp16::from_coefficients(coefficients).unwrap()
            })
            .collect()
    }

    #[test]
    fn scalar_circle_fft_round_trips_all_small_domains() {
        for log_size in 1..=10 {
            let coefficients = values(log_size);
            let evaluations = evaluate_circle_coefficients(&coefficients, log_size).unwrap();
            assert_eq!(
                interpolate_circle_evaluations(&evaluations).unwrap(),
                coefficients
            );
        }
    }

    #[test]
    fn fft_evaluations_match_independent_basis_folding() {
        for log_size in 1..=8 {
            let coefficients = values(log_size);
            let evaluations = evaluate_circle_coefficients(&coefficients, log_size).unwrap();
            for natural_index in 0..1_usize << log_size {
                let point = if log_size == 1 {
                    let initial = BaseCirclePoint::generator()
                        .multiply(1_usize << (M31_CIRCLE_LOG_ORDER - 2));
                    if natural_index == 0 {
                        initial
                    } else {
                        initial.conjugate()
                    }
                } else {
                    canonic_circle_point(log_size, natural_index).unwrap()
                };
                let expected = evaluate_coefficients_at_point(&coefficients, point).unwrap();
                let stored_index = reverse_low_bits(natural_index, log_size);
                assert_eq!(evaluations[stored_index], expected);
            }
        }
    }

    #[test]
    fn low_degree_extension_preserves_the_same_polynomial() {
        let natural_trace = values(5);
        let mut bit_reversed = natural_trace.clone();
        bit_reverse_permute(&mut bit_reversed).unwrap();
        let coefficients = interpolate_circle_evaluations(&bit_reversed).unwrap();
        let extended = low_degree_extend(&natural_trace, 3).unwrap();
        for natural_index in [0_usize, 1, 37, 127, 255] {
            let point = canonic_circle_point(8, natural_index).unwrap();
            let expected = evaluate_coefficients_at_point(&coefficients, point).unwrap();
            assert_eq!(extended[reverse_low_bits(natural_index, 8)], expected);
        }
    }

    #[test]
    fn extension_circle_fft_round_trips_and_matches_direct_basis() {
        for log_size in 1..=8 {
            let coefficients = extension_values(log_size);
            let evaluations =
                evaluate_extension_circle_coefficients(&coefficients, log_size).unwrap();
            assert_eq!(
                interpolate_extension_circle_evaluations(&evaluations).unwrap(),
                coefficients
            );
            let second = evaluations
                .iter()
                .map(|value| value.add(Fp16::ONE))
                .collect::<Vec<_>>();
            assert_eq!(
                interpolate_extension_circle_evaluation_columns(&[
                    evaluations.clone(),
                    second.clone(),
                ])
                .unwrap(),
                vec![
                    interpolate_extension_circle_evaluations(&evaluations).unwrap(),
                    interpolate_extension_circle_evaluations(&second).unwrap(),
                ]
            );
            for natural_index in 0..1_usize << log_size {
                let base = if log_size == 1 {
                    let initial = BaseCirclePoint::generator()
                        .multiply(1_usize << (M31_CIRCLE_LOG_ORDER - 2));
                    if natural_index == 0 {
                        initial
                    } else {
                        initial.conjugate()
                    }
                } else {
                    canonic_circle_point(log_size, natural_index).unwrap()
                };
                let point = crate::oods::CirclePoint {
                    x: Fp16::from_m31(base.x),
                    y: Fp16::from_m31(base.y),
                };
                let expected =
                    evaluate_extension_coefficients_at_point(&coefficients, point).unwrap();
                assert_eq!(
                    evaluations[reverse_low_bits(natural_index, log_size)],
                    expected
                );
            }
        }
    }
}
