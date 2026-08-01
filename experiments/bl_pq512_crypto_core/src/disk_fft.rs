//! Bounded-memory, byte-exact file-backed Fp16 Circle FFT evaluation.

use core::fmt;

use alloc::{string::String, vec, vec::Vec};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::circle_fft::{
    CircleFftError, bit_reverse_permute, circle_twiddles, coset_order_to_circle_domain_order,
    interpolate_extension_circle_evaluations, line_twiddle_layers,
};
use crate::circle_fri::MAX_CIRCLE_DOMAIN_LOG_SIZE;
use crate::field::{FP16_ENCODED_LENGTH, Fp16, M31};
use crate::trace_mask::{TraceMaskError, canonical_coset_zeroifier_evaluations};

const FILE_FFT_MEMORY_CAP_VALUES: usize = 1 << 14;
const BASE_ENCODED_LENGTH: usize = 4;

#[derive(Debug)]
pub enum DiskFftError {
    Circle(CircleFftError),
    Decode(crate::field::DecodeError),
    Field(crate::field::FieldError),
    Io(std::io::ErrorKind),
    Shape,
    Overflow,
    TraceMask(TraceMaskError),
}

impl From<CircleFftError> for DiskFftError {
    fn from(value: CircleFftError) -> Self {
        Self::Circle(value)
    }
}
impl From<crate::field::DecodeError> for DiskFftError {
    fn from(value: crate::field::DecodeError) -> Self {
        Self::Decode(value)
    }
}
impl From<crate::field::FieldError> for DiskFftError {
    fn from(value: crate::field::FieldError) -> Self {
        Self::Field(value)
    }
}
impl From<std::io::Error> for DiskFftError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.kind())
    }
}
impl From<TraceMaskError> for DiskFftError {
    fn from(value: TraceMaskError) -> Self {
        Self::TraceMask(value)
    }
}

impl fmt::Display for DiskFftError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "BL-PQ512 disk FFT error: {self:?}")
    }
}

impl core::error::Error for DiskFftError {}

pub fn evaluate_extension_circle_coefficients_to_file(
    coefficients: &[Fp16],
    domain_log_size: u8,
    output_path: &Path,
) -> Result<(), DiskFftError> {
    if coefficients.len() < 2
        || !coefficients.len().is_power_of_two()
        || domain_log_size < coefficients.len().ilog2() as u8
        || !(3..=MAX_CIRCLE_DOMAIN_LOG_SIZE).contains(&domain_log_size)
        || !output_path.is_absolute()
    {
        return Err(DiskFftError::Shape);
    }
    let domain_size = 1_usize
        .checked_shl(u32::from(domain_log_size))
        .ok_or(DiskFftError::Overflow)?;
    initialize_evaluation_file(coefficients, domain_size, output_path)?;
    let line_layers = line_twiddle_layers(domain_log_size, false)?;
    let circle_layer = circle_twiddles(&line_layers[0])?;
    for (layer, twiddles) in line_layers.iter().enumerate().rev() {
        apply_extension_layer(output_path, domain_size, layer + 1, twiddles)?;
    }
    apply_extension_layer(output_path, domain_size, 0, &circle_layer)?;
    Ok(())
}

/// Interpolate a complete canonical-domain Fp16 evaluation file in place.
///
/// The resulting file contains bit-reversed Circle coefficients and is byte
/// identical to `interpolate_extension_circle_evaluations`.  Every transform
/// layer uses bounded buffers; the full evaluation vector is never resident.
pub fn interpolate_extension_circle_file_in_place(
    path: &Path,
    domain_log_size: u8,
) -> Result<(), DiskFftError> {
    validate_complete_file(path, domain_log_size)?;
    if domain_log_size < 3 {
        return Err(DiskFftError::Shape);
    }
    let domain_size = 1_usize
        .checked_shl(u32::from(domain_log_size))
        .ok_or(DiskFftError::Overflow)?;
    let line_layers = line_twiddle_layers(domain_log_size, true)?;
    let circle_layer = circle_twiddles(&line_layers[0])?;
    apply_extension_inverse_layer(path, domain_size, 0, &circle_layer)?;
    for (layer, twiddles) in line_layers.iter().enumerate() {
        apply_extension_inverse_layer(path, domain_size, layer + 1, twiddles)?;
    }
    let domain_u32 = u32::try_from(domain_size).map_err(|_| DiskFftError::Overflow)?;
    let inverse_size = Fp16::from_m31(M31::from_canonical(domain_u32)?.inverse()?);
    scale_extension_file(path, domain_size, inverse_size)
}

/// Evaluate a complete, zero-padded Fp16 coefficient file in place.
pub fn evaluate_extension_circle_coefficient_file_in_place(
    path: &Path,
    domain_log_size: u8,
) -> Result<(), DiskFftError> {
    validate_complete_file(path, domain_log_size)?;
    if domain_log_size < 3 {
        return Err(DiskFftError::Shape);
    }
    let domain_size = 1_usize
        .checked_shl(u32::from(domain_log_size))
        .ok_or(DiskFftError::Overflow)?;
    let line_layers = line_twiddle_layers(domain_log_size, false)?;
    let circle_layer = circle_twiddles(&line_layers[0])?;
    for (layer, twiddles) in line_layers.iter().enumerate().rev() {
        apply_extension_layer(path, domain_size, layer + 1, twiddles)?;
    }
    apply_extension_layer(path, domain_size, 0, &circle_layer)
}

/// Interpolate a complete canonical-domain M31 evaluation file in place.
pub fn interpolate_base_circle_file_in_place(
    path: &Path,
    domain_log_size: u8,
) -> Result<(), DiskFftError> {
    validate_complete_base_file(path, domain_log_size)?;
    if domain_log_size < 3 {
        return Err(DiskFftError::Shape);
    }
    let domain_size = 1_usize
        .checked_shl(u32::from(domain_log_size))
        .ok_or(DiskFftError::Overflow)?;
    let line_layers = line_twiddle_layers(domain_log_size, true)?;
    let circle_layer = circle_twiddles(&line_layers[0])?;
    apply_base_inverse_layer(path, domain_size, 0, &circle_layer)?;
    for (layer, twiddles) in line_layers.iter().enumerate() {
        apply_base_inverse_layer(path, domain_size, layer + 1, twiddles)?;
    }
    let domain_u32 = u32::try_from(domain_size).map_err(|_| DiskFftError::Overflow)?;
    scale_base_file(
        path,
        domain_size,
        M31::from_canonical(domain_u32)?.inverse()?,
    )
}

/// Evaluate a complete, zero-padded M31 coefficient file in place.
pub fn evaluate_base_circle_coefficient_file_in_place(
    path: &Path,
    domain_log_size: u8,
) -> Result<(), DiskFftError> {
    validate_complete_base_file(path, domain_log_size)?;
    if domain_log_size < 3 {
        return Err(DiskFftError::Shape);
    }
    let domain_size = 1_usize
        .checked_shl(u32::from(domain_log_size))
        .ok_or(DiskFftError::Overflow)?;
    let line_layers = line_twiddle_layers(domain_log_size, false)?;
    let circle_layer = circle_twiddles(&line_layers[0])?;
    for (layer, twiddles) in line_layers.iter().enumerate().rev() {
        apply_base_layer(path, domain_size, layer + 1, twiddles)?;
    }
    apply_base_layer(path, domain_size, 0, &circle_layer)
}

/// Re-evaluate one committed base-field polynomial on a larger work domain
/// without holding either domain in memory.
pub fn extend_base_circle_evaluation_file(
    source_path: &Path,
    source_log_size: u8,
    target_log_size: u8,
    output_path: &Path,
) -> Result<(), DiskFftError> {
    validate_complete_base_file(source_path, source_log_size)?;
    if target_log_size <= source_log_size
        || target_log_size > MAX_CIRCLE_DOMAIN_LOG_SIZE
        || !output_path.is_absolute()
        || output_path.exists()
    {
        return Err(DiskFftError::Shape);
    }
    fs::copy(source_path, output_path)?;
    let result = (|| {
        interpolate_base_circle_file_in_place(output_path, source_log_size)?;
        let target_bytes = (1_u64 << target_log_size)
            .checked_mul(BASE_ENCODED_LENGTH as u64)
            .ok_or(DiskFftError::Overflow)?;
        OpenOptions::new()
            .write(true)
            .open(output_path)?
            .set_len(target_bytes)?;
        evaluate_base_circle_coefficient_file_in_place(output_path, target_log_size)
    })();
    if result.is_err() {
        let _ = fs::remove_file(output_path);
    }
    result
}

/// Re-evaluate one committed extension-field polynomial on a larger work
/// domain with bounded memory.
pub fn extend_extension_circle_evaluation_file(
    source_path: &Path,
    source_log_size: u8,
    target_log_size: u8,
    output_path: &Path,
) -> Result<(), DiskFftError> {
    validate_complete_file(source_path, source_log_size)?;
    if target_log_size <= source_log_size
        || target_log_size > MAX_CIRCLE_DOMAIN_LOG_SIZE
        || !output_path.is_absolute()
        || output_path.exists()
    {
        return Err(DiskFftError::Shape);
    }
    fs::copy(source_path, output_path)?;
    let result = (|| {
        interpolate_extension_circle_file_in_place(output_path, source_log_size)?;
        let target_bytes = (1_u64 << target_log_size)
            .checked_mul(FP16_ENCODED_LENGTH as u64)
            .ok_or(DiskFftError::Overflow)?;
        OpenOptions::new()
            .write(true)
            .open(output_path)?
            .set_len(target_bytes)?;
        evaluate_extension_circle_coefficient_file_in_place(output_path, target_log_size)
    })();
    if result.is_err() {
        let _ = fs::remove_file(output_path);
    }
    result
}

/// Evaluate a complete coefficient file at one extension-field circle point.
/// The file is used as destructive scratch and its first word becomes the
/// result. This is the bounded-memory equivalent of
/// `evaluate_extension_coefficients_at_point`.
pub fn evaluate_extension_coefficient_file_at_point_in_place(
    path: &Path,
    domain_log_size: u8,
    point: crate::oods::CirclePoint,
) -> Result<Fp16, DiskFftError> {
    validate_complete_file(path, domain_log_size)?;
    if point.x.square().add(point.y.square()) != Fp16::ONE {
        return Err(DiskFftError::Shape);
    }
    let mut mappings = Vec::with_capacity(usize::from(domain_log_size));
    mappings.push(point.y);
    if domain_log_size > 1 {
        let mut x = point.x;
        for _ in 1..domain_log_size {
            mappings.push(x);
            let squared = x.square();
            x = squared.add(squared).sub(Fp16::ONE);
        }
    }
    mappings.reverse();
    let mut active = 1_usize << domain_log_size;
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    for mapping in mappings {
        let half = active / 2;
        for start in (0..half).step_by(FILE_FFT_MEMORY_CAP_VALUES) {
            let count = FILE_FFT_MEMORY_CAP_VALUES.min(half - start);
            let mut left = read_values_at(&mut file, start, count)?;
            let right = read_values_at(&mut file, half + start, count)?;
            for (left, right) in left.iter_mut().zip(right) {
                *left = left.add(right.mul(mapping));
            }
            write_values_at(&mut file, start, &left)?;
        }
        active = half;
    }
    file.sync_data()?;
    Ok(read_values_at(&mut file, 0, 1)?[0])
}

fn validate_complete_file(path: &Path, domain_log_size: u8) -> Result<(), DiskFftError> {
    if !path.is_absolute() || !(3..=MAX_CIRCLE_DOMAIN_LOG_SIZE).contains(&domain_log_size) {
        return Err(DiskFftError::Shape);
    }
    let values = 1_u64
        .checked_shl(u32::from(domain_log_size))
        .ok_or(DiskFftError::Overflow)?;
    let bytes = values
        .checked_mul(FP16_ENCODED_LENGTH as u64)
        .ok_or(DiskFftError::Overflow)?;
    if fs::metadata(path)?.len() != bytes {
        return Err(DiskFftError::Shape);
    }
    Ok(())
}

fn validate_complete_base_file(path: &Path, domain_log_size: u8) -> Result<(), DiskFftError> {
    if !path.is_absolute() || !(3..=MAX_CIRCLE_DOMAIN_LOG_SIZE).contains(&domain_log_size) {
        return Err(DiskFftError::Shape);
    }
    let values = 1_u64
        .checked_shl(u32::from(domain_log_size))
        .ok_or(DiskFftError::Overflow)?;
    let bytes = values
        .checked_mul(BASE_ENCODED_LENGTH as u64)
        .ok_or(DiskFftError::Overflow)?;
    if fs::metadata(path)?.len() != bytes {
        return Err(DiskFftError::Shape);
    }
    Ok(())
}

pub fn mask_extension_trace_column_to_file(
    natural_trace: &[Fp16],
    randomizer_coefficients: &[Fp16],
    target_log_size: u8,
    work_directory: &Path,
    operation_nonce: &[u8; 32],
    output_path: &Path,
) -> Result<(), DiskFftError> {
    if natural_trace.len() < 2
        || !natural_trace.len().is_power_of_two()
        || randomizer_coefficients.is_empty()
        || !work_directory.is_absolute()
        || !work_directory.is_dir()
        || output_path.parent() != Some(work_directory)
    {
        return Err(DiskFftError::Shape);
    }
    let trace_log_size = natural_trace.len().ilog2() as u8;
    let randomizer_size = randomizer_coefficients.len().next_power_of_two();
    let minimum = natural_trace
        .len()
        .checked_add(randomizer_size)
        .ok_or(DiskFftError::Overflow)?
        .next_power_of_two()
        .ilog2() as u8;
    if target_log_size < minimum || target_log_size > MAX_CIRCLE_DOMAIN_LOG_SIZE {
        return Err(DiskFftError::Shape);
    }
    let (trace_path, random_path) = temporary_evaluation_paths(work_directory, operation_nonce);
    let result = (|| {
        let mut bit_reversed = coset_order_to_circle_domain_order(natural_trace)?;
        bit_reverse_permute(&mut bit_reversed)?;
        let mut trace_coefficients = interpolate_extension_circle_evaluations(&bit_reversed)?;
        bit_reversed.fill(Fp16::ZERO);
        evaluate_extension_circle_coefficients_to_file(
            &trace_coefficients,
            target_log_size,
            &trace_path,
        )?;
        trace_coefficients.fill(Fp16::ZERO);

        let mut randomizer = randomizer_coefficients.to_vec();
        randomizer.resize(randomizer_size, Fp16::ZERO);
        evaluate_extension_circle_coefficients_to_file(&randomizer, target_log_size, &random_path)?;
        randomizer.fill(Fp16::ZERO);

        let zeroifiers = canonical_coset_zeroifier_evaluations(trace_log_size, target_log_size)?;
        combine_mask_files(&trace_path, &random_path, &zeroifiers, output_path)
    })();
    let _ = fs::remove_file(&trace_path);
    let _ = fs::remove_file(&random_path);
    if result.is_err() {
        let _ = fs::remove_file(output_path);
    }
    result
}

fn combine_mask_files(
    trace_path: &Path,
    random_path: &Path,
    zeroifiers: &[M31],
    output_path: &Path,
) -> Result<(), DiskFftError> {
    let mut trace = BufReader::new(File::open(trace_path)?);
    let mut random = BufReader::new(File::open(random_path)?);
    let mut output = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_path)?,
    );
    let block_values = 1 << 12;
    for start in (0..zeroifiers.len()).step_by(block_values) {
        let count = block_values.min(zeroifiers.len() - start);
        let mut trace_encoded = vec![0_u8; count * FP16_ENCODED_LENGTH];
        let mut random_encoded = vec![0_u8; count * FP16_ENCODED_LENGTH];
        trace.read_exact(&mut trace_encoded)?;
        random.read_exact(&mut random_encoded)?;
        for index in 0..count {
            let offset = index * FP16_ENCODED_LENGTH;
            let trace_value = Fp16::decode(&trace_encoded[offset..offset + FP16_ENCODED_LENGTH])?;
            let random_value = Fp16::decode(&random_encoded[offset..offset + FP16_ENCODED_LENGTH])?;
            let masked =
                trace_value.add(Fp16::from_m31(zeroifiers[start + index]).mul(random_value));
            output.write_all(&masked.encode())?;
        }
    }
    output.flush()?;
    output.get_ref().sync_data()?;
    Ok(())
}

fn temporary_evaluation_paths(directory: &Path, nonce: &[u8; 32]) -> (PathBuf, PathBuf) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut suffix = String::new();
    for byte in nonce {
        suffix.push(DIGITS[usize::from(byte >> 4)] as char);
        suffix.push(DIGITS[usize::from(byte & 15)] as char);
    }
    (
        directory.join(alloc::format!("fft-trace-{suffix}.tmp")),
        directory.join(alloc::format!("fft-mask-{suffix}.tmp")),
    )
}

fn initialize_evaluation_file(
    coefficients: &[Fp16],
    domain_size: usize,
    output_path: &Path,
) -> Result<(), DiskFftError> {
    let mut output = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_path)?,
    );
    for coefficient in coefficients {
        output.write_all(&coefficient.encode())?;
    }
    let mut remaining = domain_size - coefficients.len();
    let zeros = vec![0_u8; (1 << 14) * FP16_ENCODED_LENGTH];
    while remaining != 0 {
        let count = remaining.min(1 << 14);
        output.write_all(&zeros[..count * FP16_ENCODED_LENGTH])?;
        remaining -= count;
    }
    output.flush()?;
    output.get_ref().sync_data()?;
    Ok(())
}

fn apply_base_layer(
    path: &Path,
    domain_size: usize,
    layer: usize,
    twiddles: &[M31],
) -> Result<(), DiskFftError> {
    apply_base_layer_common(path, domain_size, layer, twiddles, false)
}

fn apply_base_inverse_layer(
    path: &Path,
    domain_size: usize,
    layer: usize,
    twiddles: &[M31],
) -> Result<(), DiskFftError> {
    apply_base_layer_common(path, domain_size, layer, twiddles, true)
}

fn apply_base_layer_common(
    path: &Path,
    domain_size: usize,
    layer: usize,
    twiddles: &[M31],
    inverse: bool,
) -> Result<(), DiskFftError> {
    let half = 1_usize
        .checked_shl(u32::try_from(layer).map_err(|_| DiskFftError::Overflow)?)
        .ok_or(DiskFftError::Overflow)?;
    let block_values = half.checked_mul(2).ok_or(DiskFftError::Overflow)?;
    let block_count = domain_size / block_values;
    if block_values * block_count != domain_size || twiddles.len() != block_count {
        return Err(DiskFftError::Shape);
    }
    #[cfg(feature = "parallel")]
    {
        let thread_count = std::thread::available_parallelism()
            .map_or(1, core::num::NonZeroUsize::get)
            .min(block_count);
        if thread_count > 1 {
            let blocks_per_thread = block_count.div_ceil(thread_count);
            let results = std::thread::scope(|scope| {
                let mut handles = Vec::new();
                for start in (0..block_count).step_by(blocks_per_thread) {
                    let stop = (start + blocks_per_thread).min(block_count);
                    handles.push(scope.spawn(move || {
                        apply_base_layer_range(path, layer, &twiddles[start..stop], start, inverse)
                    }));
                }
                handles
                    .into_iter()
                    .map(|handle| handle.join().map_err(|_| DiskFftError::Shape)?)
                    .collect::<Result<Vec<_>, DiskFftError>>()
            });
            results?;
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)?
                .sync_data()?;
            return Ok(());
        }
    }
    apply_base_layer_range(path, layer, twiddles, 0, inverse)?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?
        .sync_data()?;
    Ok(())
}

fn apply_base_layer_range(
    path: &Path,
    layer: usize,
    twiddles: &[M31],
    first_global_block: usize,
    inverse: bool,
) -> Result<(), DiskFftError> {
    let half = 1_usize
        .checked_shl(u32::try_from(layer).map_err(|_| DiskFftError::Overflow)?)
        .ok_or(DiskFftError::Overflow)?;
    let block_values = half.checked_mul(2).ok_or(DiskFftError::Overflow)?;
    let block_count = twiddles.len();
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    if block_values <= FILE_FFT_MEMORY_CAP_VALUES {
        let blocks_per_group = (FILE_FFT_MEMORY_CAP_VALUES / block_values).max(1);
        let mut first_block = 0usize;
        while first_block < block_count {
            let group_blocks = blocks_per_group.min(block_count - first_block);
            let value_count = group_blocks * block_values;
            let value_offset = (first_global_block + first_block) * block_values;
            let mut values = read_base_values_at(&mut file, value_offset, value_count)?;
            for local_block in 0..group_blocks {
                let start = local_block * block_values;
                let twiddle = twiddles[first_block + local_block];
                for offset in 0..half {
                    base_butterfly_pair(
                        &mut values,
                        start + offset,
                        start + half + offset,
                        twiddle,
                        inverse,
                    );
                }
            }
            write_base_values_at(&mut file, value_offset, &values)?;
            first_block += group_blocks;
        }
    } else {
        let chunk_values = FILE_FFT_MEMORY_CAP_VALUES / 2;
        for (block, twiddle) in twiddles.iter().copied().enumerate() {
            let block_start = (first_global_block + block) * block_values;
            for offset in (0..half).step_by(chunk_values) {
                let count = chunk_values.min(half - offset);
                let mut left = read_base_values_at(&mut file, block_start + offset, count)?;
                let mut right = read_base_values_at(&mut file, block_start + half + offset, count)?;
                for index in 0..count {
                    let original_left = left[index];
                    let original_right = right[index];
                    if inverse {
                        left[index] = original_left.add(original_right);
                        right[index] = original_left.sub(original_right).mul(twiddle);
                    } else {
                        let product = original_right.mul(twiddle);
                        left[index] = original_left.add(product);
                        right[index] = original_left.sub(product);
                    }
                }
                write_base_values_at(&mut file, block_start + offset, &left)?;
                write_base_values_at(&mut file, block_start + half + offset, &right)?;
            }
        }
    }
    Ok(())
}

fn base_butterfly_pair(values: &mut [M31], left: usize, right: usize, twiddle: M31, inverse: bool) {
    let original_left = values[left];
    let original_right = values[right];
    if inverse {
        values[left] = original_left.add(original_right);
        values[right] = original_left.sub(original_right).mul(twiddle);
    } else {
        let product = original_right.mul(twiddle);
        values[left] = original_left.add(product);
        values[right] = original_left.sub(product);
    }
}

fn scale_base_file(path: &Path, values: usize, factor: M31) -> Result<(), DiskFftError> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    for start in (0..values).step_by(FILE_FFT_MEMORY_CAP_VALUES) {
        let count = FILE_FFT_MEMORY_CAP_VALUES.min(values - start);
        let mut block = read_base_values_at(&mut file, start, count)?;
        for value in &mut block {
            *value = value.mul(factor);
        }
        write_base_values_at(&mut file, start, &block)?;
    }
    file.sync_data()?;
    Ok(())
}

fn read_base_values_at(
    file: &mut File,
    value_offset: usize,
    value_count: usize,
) -> Result<Vec<M31>, DiskFftError> {
    let byte_offset = u64::try_from(value_offset)
        .ok()
        .and_then(|value| value.checked_mul(BASE_ENCODED_LENGTH as u64))
        .ok_or(DiskFftError::Overflow)?;
    let byte_count = value_count
        .checked_mul(BASE_ENCODED_LENGTH)
        .ok_or(DiskFftError::Overflow)?;
    let mut encoded = vec![0_u8; byte_count];
    file.seek(SeekFrom::Start(byte_offset))?;
    file.read_exact(&mut encoded)?;
    encoded
        .chunks_exact(BASE_ENCODED_LENGTH)
        .map(|word| {
            let value = u32::from_be_bytes(word.try_into().map_err(|_| DiskFftError::Shape)?);
            if value >= crate::field::M31_MODULUS {
                return Err(DiskFftError::Shape);
            }
            M31::from_canonical(value).map_err(DiskFftError::from)
        })
        .collect()
}

fn write_base_values_at(
    file: &mut File,
    value_offset: usize,
    values: &[M31],
) -> Result<(), DiskFftError> {
    let byte_offset = u64::try_from(value_offset)
        .ok()
        .and_then(|value| value.checked_mul(BASE_ENCODED_LENGTH as u64))
        .ok_or(DiskFftError::Overflow)?;
    file.seek(SeekFrom::Start(byte_offset))?;
    let mut encoded = Vec::with_capacity(values.len() * BASE_ENCODED_LENGTH);
    for value in values {
        encoded.extend_from_slice(&value.as_u32().to_be_bytes());
    }
    file.write_all(&encoded)?;
    Ok(())
}

fn apply_extension_layer(
    path: &Path,
    domain_size: usize,
    layer: usize,
    twiddles: &[M31],
) -> Result<(), DiskFftError> {
    let half = 1_usize
        .checked_shl(u32::try_from(layer).map_err(|_| DiskFftError::Overflow)?)
        .ok_or(DiskFftError::Overflow)?;
    let block_values = half.checked_mul(2).ok_or(DiskFftError::Overflow)?;
    let block_count = domain_size / block_values;
    if block_values * block_count != domain_size || twiddles.len() != block_count {
        return Err(DiskFftError::Shape);
    }
    #[cfg(feature = "parallel")]
    {
        let thread_count = std::thread::available_parallelism()
            .map_or(1, core::num::NonZeroUsize::get)
            .min(block_count);
        if thread_count > 1 {
            let blocks_per_thread = block_count.div_ceil(thread_count);
            let results = std::thread::scope(|scope| {
                let mut handles = Vec::new();
                for start in (0..block_count).step_by(blocks_per_thread) {
                    let stop = (start + blocks_per_thread).min(block_count);
                    handles.push(scope.spawn(move || {
                        apply_extension_layer_range(path, layer, &twiddles[start..stop], start)
                    }));
                }
                handles
                    .into_iter()
                    .map(|handle| handle.join().map_err(|_| DiskFftError::Shape)?)
                    .collect::<Result<Vec<_>, DiskFftError>>()
            });
            results?;
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)?
                .sync_data()?;
            return Ok(());
        }
    }
    apply_extension_layer_range(path, layer, twiddles, 0)?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?
        .sync_data()?;
    Ok(())
}

fn apply_extension_inverse_layer(
    path: &Path,
    domain_size: usize,
    layer: usize,
    twiddles: &[M31],
) -> Result<(), DiskFftError> {
    let half = 1_usize
        .checked_shl(u32::try_from(layer).map_err(|_| DiskFftError::Overflow)?)
        .ok_or(DiskFftError::Overflow)?;
    let block_values = half.checked_mul(2).ok_or(DiskFftError::Overflow)?;
    let block_count = domain_size / block_values;
    if block_values * block_count != domain_size || twiddles.len() != block_count {
        return Err(DiskFftError::Shape);
    }
    #[cfg(feature = "parallel")]
    {
        let thread_count = std::thread::available_parallelism()
            .map_or(1, core::num::NonZeroUsize::get)
            .min(block_count);
        if thread_count > 1 {
            let blocks_per_thread = block_count.div_ceil(thread_count);
            let results = std::thread::scope(|scope| {
                let mut handles = Vec::new();
                for start in (0..block_count).step_by(blocks_per_thread) {
                    let stop = (start + blocks_per_thread).min(block_count);
                    handles.push(scope.spawn(move || {
                        apply_extension_inverse_layer_range(
                            path,
                            layer,
                            &twiddles[start..stop],
                            start,
                        )
                    }));
                }
                handles
                    .into_iter()
                    .map(|handle| handle.join().map_err(|_| DiskFftError::Shape)?)
                    .collect::<Result<Vec<_>, DiskFftError>>()
            });
            results?;
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)?
                .sync_data()?;
            return Ok(());
        }
    }
    apply_extension_inverse_layer_range(path, layer, twiddles, 0)?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?
        .sync_data()?;
    Ok(())
}

fn apply_extension_layer_range(
    path: &Path,
    layer: usize,
    twiddles: &[M31],
    first_global_block: usize,
) -> Result<(), DiskFftError> {
    let half = 1_usize
        .checked_shl(u32::try_from(layer).map_err(|_| DiskFftError::Overflow)?)
        .ok_or(DiskFftError::Overflow)?;
    let block_values = half.checked_mul(2).ok_or(DiskFftError::Overflow)?;
    let block_count = twiddles.len();
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    if block_values <= FILE_FFT_MEMORY_CAP_VALUES {
        let blocks_per_group = (FILE_FFT_MEMORY_CAP_VALUES / block_values).max(1);
        let mut first_block = 0usize;
        while first_block < block_count {
            let group_blocks = blocks_per_group.min(block_count - first_block);
            let value_count = group_blocks * block_values;
            let value_offset = (first_global_block + first_block) * block_values;
            let mut values = read_values_at(&mut file, value_offset, value_count)?;
            for local_block in 0..group_blocks {
                let start = local_block * block_values;
                let twiddle = twiddles[first_block + local_block];
                for offset in 0..half {
                    let left = start + offset;
                    let right = left + half;
                    extension_butterfly_pair(&mut values, left, right, twiddle);
                }
            }
            write_values_at(&mut file, value_offset, &values)?;
            first_block += group_blocks;
        }
    } else {
        let chunk_values = FILE_FFT_MEMORY_CAP_VALUES / 2;
        for (block, twiddle) in twiddles.iter().copied().enumerate() {
            let block_start = (first_global_block + block) * block_values;
            for offset in (0..half).step_by(chunk_values) {
                let count = chunk_values.min(half - offset);
                let mut left = read_values_at(&mut file, block_start + offset, count)?;
                let mut right = read_values_at(&mut file, block_start + half + offset, count)?;
                for index in 0..count {
                    let product = right[index].mul(Fp16::from_m31(twiddle));
                    let original_left = left[index];
                    left[index] = original_left.add(product);
                    right[index] = original_left.sub(product);
                }
                write_values_at(&mut file, block_start + offset, &left)?;
                write_values_at(&mut file, block_start + half + offset, &right)?;
            }
        }
    }
    Ok(())
}

fn apply_extension_inverse_layer_range(
    path: &Path,
    layer: usize,
    twiddles: &[M31],
    first_global_block: usize,
) -> Result<(), DiskFftError> {
    let half = 1_usize
        .checked_shl(u32::try_from(layer).map_err(|_| DiskFftError::Overflow)?)
        .ok_or(DiskFftError::Overflow)?;
    let block_values = half.checked_mul(2).ok_or(DiskFftError::Overflow)?;
    let block_count = twiddles.len();
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    if block_values <= FILE_FFT_MEMORY_CAP_VALUES {
        let blocks_per_group = (FILE_FFT_MEMORY_CAP_VALUES / block_values).max(1);
        let mut first_block = 0usize;
        while first_block < block_count {
            let group_blocks = blocks_per_group.min(block_count - first_block);
            let value_count = group_blocks * block_values;
            let value_offset = (first_global_block + first_block) * block_values;
            let mut values = read_values_at(&mut file, value_offset, value_count)?;
            for local_block in 0..group_blocks {
                let start = local_block * block_values;
                let twiddle = twiddles[first_block + local_block];
                for offset in 0..half {
                    let left = start + offset;
                    let right = left + half;
                    extension_inverse_butterfly_pair(&mut values, left, right, twiddle);
                }
            }
            write_values_at(&mut file, value_offset, &values)?;
            first_block += group_blocks;
        }
    } else {
        let chunk_values = FILE_FFT_MEMORY_CAP_VALUES / 2;
        for (block, twiddle) in twiddles.iter().copied().enumerate() {
            let block_start = (first_global_block + block) * block_values;
            for offset in (0..half).step_by(chunk_values) {
                let count = chunk_values.min(half - offset);
                let mut left = read_values_at(&mut file, block_start + offset, count)?;
                let mut right = read_values_at(&mut file, block_start + half + offset, count)?;
                for index in 0..count {
                    let original_left = left[index];
                    let original_right = right[index];
                    left[index] = original_left.add(original_right);
                    right[index] = original_left
                        .sub(original_right)
                        .mul(Fp16::from_m31(twiddle));
                }
                write_values_at(&mut file, block_start + offset, &left)?;
                write_values_at(&mut file, block_start + half + offset, &right)?;
            }
        }
    }
    Ok(())
}

fn extension_butterfly_pair(values: &mut [Fp16], left: usize, right: usize, twiddle: M31) {
    let product = values[right].mul(Fp16::from_m31(twiddle));
    let original_left = values[left];
    values[left] = original_left.add(product);
    values[right] = original_left.sub(product);
}

fn extension_inverse_butterfly_pair(
    values: &mut [Fp16],
    left: usize,
    right: usize,
    inverse_twiddle: M31,
) {
    let original_left = values[left];
    let original_right = values[right];
    values[left] = original_left.add(original_right);
    values[right] = original_left
        .sub(original_right)
        .mul(Fp16::from_m31(inverse_twiddle));
}

fn scale_extension_file(path: &Path, values: usize, factor: Fp16) -> Result<(), DiskFftError> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    for start in (0..values).step_by(FILE_FFT_MEMORY_CAP_VALUES) {
        let count = FILE_FFT_MEMORY_CAP_VALUES.min(values - start);
        let mut block = read_values_at(&mut file, start, count)?;
        for value in &mut block {
            *value = value.mul(factor);
        }
        write_values_at(&mut file, start, &block)?;
    }
    file.sync_data()?;
    Ok(())
}

fn read_values_at(
    file: &mut File,
    value_offset: usize,
    value_count: usize,
) -> Result<Vec<Fp16>, DiskFftError> {
    let byte_offset = u64::try_from(value_offset)
        .ok()
        .and_then(|value| value.checked_mul(FP16_ENCODED_LENGTH as u64))
        .ok_or(DiskFftError::Overflow)?;
    let byte_count = value_count
        .checked_mul(FP16_ENCODED_LENGTH)
        .ok_or(DiskFftError::Overflow)?;
    let mut encoded = vec![0_u8; byte_count];
    file.seek(SeekFrom::Start(byte_offset))?;
    file.read_exact(&mut encoded)?;
    encoded
        .chunks_exact(FP16_ENCODED_LENGTH)
        .map(Fp16::decode)
        .collect::<Result<Vec<_>, _>>()
        .map_err(DiskFftError::from)
}

fn write_values_at(
    file: &mut File,
    value_offset: usize,
    values: &[Fp16],
) -> Result<(), DiskFftError> {
    let byte_offset = u64::try_from(value_offset)
        .ok()
        .and_then(|value| value.checked_mul(FP16_ENCODED_LENGTH as u64))
        .ok_or(DiskFftError::Overflow)?;
    file.seek(SeekFrom::Start(byte_offset))?;
    let mut encoded = Vec::with_capacity(values.len() * FP16_ENCODED_LENGTH);
    for value in values {
        encoded.extend_from_slice(&value.encode());
    }
    file.write_all(&encoded)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::*;
    use crate::circle_fft::evaluate_extension_circle_coefficients;
    use crate::trace_mask::{
        canonical_coset_zeroifier_evaluations, mask_extension_trace_column_with_zeroifiers,
    };

    #[test]
    fn file_backed_base_fft_round_trip_and_extension_match_memory() {
        let parent = std::env::temp_dir();
        let source = parent.join(format!("blpq-disk-base-source-{}.m31", std::process::id()));
        let output = parent.join(format!("blpq-disk-base-output-{}.m31", std::process::id()));
        let coefficients = (0..32)
            .map(|index| M31::from_canonical(index * 41 + 3).unwrap())
            .collect::<Vec<_>>();
        let evaluations =
            crate::circle_fft::evaluate_circle_coefficients(&coefficients, 6).unwrap();
        let mut source_file = BufWriter::new(File::create(&source).unwrap());
        for value in &evaluations {
            source_file
                .write_all(&value.as_u32().to_be_bytes())
                .unwrap();
        }
        source_file.flush().unwrap();
        drop(source_file);

        extend_base_circle_evaluation_file(&source, 6, 8, &output).unwrap();
        let expected = crate::circle_fft::evaluate_circle_coefficients(&coefficients, 8).unwrap();
        let mut output_file = File::open(&output).unwrap();
        let observed = read_base_values_at(&mut output_file, 0, 1 << 8).unwrap();
        assert_eq!(observed, expected);

        interpolate_base_circle_file_in_place(&source, 6).unwrap();
        let mut coefficient_file = File::open(&source).unwrap();
        let observed_coefficients = read_base_values_at(&mut coefficient_file, 0, 1 << 6).unwrap();
        assert_eq!(&observed_coefficients[..coefficients.len()], &coefficients);
        assert!(
            observed_coefficients[coefficients.len()..]
                .iter()
                .all(|value| value.is_zero())
        );
        evaluate_base_circle_coefficient_file_in_place(&source, 6).unwrap();
        let mut round_trip_file = File::open(&source).unwrap();
        let round_trip = read_base_values_at(&mut round_trip_file, 0, 1 << 6).unwrap();
        assert_eq!(round_trip, evaluations);
        fs::remove_file(source).unwrap();
        fs::remove_file(output).unwrap();
    }

    #[test]
    fn file_backed_extension_domain_expansion_matches_memory() {
        let parent = std::env::temp_dir();
        let source = parent.join(format!(
            "blpq-disk-extension-source-{}.fp16",
            std::process::id()
        ));
        let output = parent.join(format!(
            "blpq-disk-extension-output-{}.fp16",
            std::process::id()
        ));
        let coefficients = (0..32)
            .map(|index| {
                let mut values = [0_u32; 16];
                values[0] = index * 53 + 17;
                values[5] = index * 7 + 1;
                Fp16::from_coefficients(values).unwrap()
            })
            .collect::<Vec<_>>();
        let source_values = evaluate_extension_circle_coefficients(&coefficients, 6).unwrap();
        let mut source_file = BufWriter::new(File::create(&source).unwrap());
        for value in &source_values {
            source_file.write_all(&value.encode()).unwrap();
        }
        source_file.flush().unwrap();
        drop(source_file);

        extend_extension_circle_evaluation_file(&source, 6, 8, &output).unwrap();
        let expected = evaluate_extension_circle_coefficients(&coefficients, 8).unwrap();
        let mut output_file = File::open(&output).unwrap();
        let observed = read_values_at(&mut output_file, 0, 1 << 8).unwrap();
        assert_eq!(observed, expected);
        fs::remove_file(source).unwrap();
        fs::remove_file(output).unwrap();
    }

    #[test]
    fn file_backed_extension_fft_matches_memory_at_every_row() {
        let parent = std::env::temp_dir();
        let path = parent.join(format!("blpq-disk-fft-test-{}.fp16", std::process::id()));
        let coefficients = (0..16)
            .map(|index| Fp16::from_m31(M31::from_canonical(index + 1).unwrap()))
            .collect::<Vec<_>>();
        let expected = evaluate_extension_circle_coefficients(&coefficients, 8).unwrap();
        evaluate_extension_circle_coefficients_to_file(&coefficients, 8, &path).unwrap();
        let mut file = File::open(&path).unwrap();
        let observed = read_values_at(&mut file, 0, 1 << 8).unwrap();
        assert_eq!(observed, expected);
        drop(file);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn file_backed_extension_mask_matches_memory_at_every_row() {
        let directory =
            std::env::temp_dir().join(format!("blpq-disk-mask-test-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let output = directory.join("masked.fp16");
        let natural = (0..16)
            .map(|index| Fp16::from_m31(M31::from_canonical(index + 3).unwrap()))
            .collect::<Vec<_>>();
        let randomizer = (0..5)
            .map(|index| Fp16::from_m31(M31::from_canonical(index + 71).unwrap()))
            .collect::<Vec<_>>();
        let zeroifiers = canonical_coset_zeroifier_evaluations(4, 8).unwrap();
        let expected =
            mask_extension_trace_column_with_zeroifiers(&natural, &randomizer, 8, &zeroifiers)
                .unwrap();
        mask_extension_trace_column_to_file(
            &natural,
            &randomizer,
            8,
            &directory,
            &[0x91; 32],
            &output,
        )
        .unwrap();
        let mut file = File::open(&output).unwrap();
        let observed = read_values_at(&mut file, 0, 1 << 8).unwrap();
        assert_eq!(observed, expected);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        drop(file);
        fs::remove_file(output).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn file_backed_inverse_and_forward_are_exact_at_every_row() {
        let path = std::env::temp_dir().join(format!(
            "blpq-disk-inverse-fft-test-{}.fp16",
            std::process::id()
        ));
        let evaluations = (0..256)
            .map(|index| Fp16::from_m31(M31::from_canonical(index * 7 + 3).unwrap()))
            .collect::<Vec<_>>();
        let expected_coefficients = interpolate_extension_circle_evaluations(&evaluations).unwrap();
        let mut encoded = Vec::with_capacity(evaluations.len() * FP16_ENCODED_LENGTH);
        for value in &evaluations {
            encoded.extend_from_slice(&value.encode());
        }
        fs::write(&path, encoded).unwrap();
        interpolate_extension_circle_file_in_place(&path, 8).unwrap();
        let mut file = File::open(&path).unwrap();
        let observed = read_values_at(&mut file, 0, 256).unwrap();
        assert_eq!(observed, expected_coefficients);
        drop(file);
        evaluate_extension_circle_coefficient_file_in_place(&path, 8).unwrap();
        let mut file = File::open(&path).unwrap();
        let roundtrip = read_values_at(&mut file, 0, 256).unwrap();
        assert_eq!(roundtrip, evaluations);
        drop(file);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn file_backed_point_evaluation_matches_recursive_memory_evaluation() {
        let path = std::env::temp_dir().join(format!(
            "blpq-disk-point-evaluation-test-{}.fp16",
            std::process::id()
        ));
        let coefficients = (0..256)
            .map(|index| Fp16::from_m31(M31::from_canonical(index * 11 + 5).unwrap()))
            .collect::<Vec<_>>();
        let parameter = crate::oods::OodsParameter::try_from_element(
            Fp16::from_coefficients([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
        )
        .unwrap();
        let point = crate::oods::stereographic_circle_point(parameter).unwrap();
        let expected =
            crate::circle_fft::evaluate_extension_coefficients_at_point(&coefficients, point)
                .unwrap();
        let mut encoded = Vec::new();
        for coefficient in &coefficients {
            encoded.extend_from_slice(&coefficient.encode());
        }
        fs::write(&path, encoded).unwrap();
        let observed =
            evaluate_extension_coefficient_file_at_point_in_place(&path, 8, point).unwrap();
        assert_eq!(observed, expected);
        fs::remove_file(path).unwrap();
    }
}
