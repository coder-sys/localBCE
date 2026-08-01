//! Run-owned, bounded-memory product-sumcheck table folding.
//!
//! This module is an experimental theorem-neutral storage control. It changes
//! neither the degree-two sumcheck equation nor challenge ordering. Each call
//! reads one current left/right table exactly once, emits the same round
//! coefficients as the dense control, folds both tables in place, and truncates
//! the run-owned files to the next round. Callers must treat either file as
//! disposable after any error because a failed call may have written a prefix.

use alloc::{vec, vec::Vec};
use core::fmt;
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
};

use crate::field::{FP16_ENCODED_LENGTH, Fp16};

/// Failure while validating or folding a run-owned table pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileBackedSumcheckError {
    Shape,
    Io,
    NonCanonical,
    Worker,
}

impl fmt::Display for FileBackedSumcheckError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shape => formatter.write_str("invalid file-backed sumcheck shape"),
            Self::Io => formatter.write_str("file-backed sumcheck I/O failure"),
            Self::NonCanonical => formatter.write_str("noncanonical Fp16 table value"),
            Self::Worker => formatter.write_str("file-backed sumcheck worker failure"),
        }
    }
}

impl core::error::Error for FileBackedSumcheckError {}

/// Exact result of one degree-two round and its authenticated fold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileBackedProductRound {
    pub coefficients: [Fp16; 3],
    pub next_value_count: usize,
}

fn checked_file_length(value_count: usize) -> Result<u64, FileBackedSumcheckError> {
    u64::try_from(value_count)
        .ok()
        .and_then(|count| count.checked_mul(FP16_ENCODED_LENGTH as u64))
        .ok_or(FileBackedSumcheckError::Shape)
}

fn validate_table(path: &Path, value_count: usize) -> Result<(), FileBackedSumcheckError> {
    let expected = checked_file_length(value_count)?;
    let actual = File::open(path)
        .and_then(|file| file.metadata())
        .map_err(|_| FileBackedSumcheckError::Io)?
        .len();
    if actual != expected {
        return Err(FileBackedSumcheckError::Shape);
    }
    Ok(())
}

fn decode_value(encoded: &[u8]) -> Result<Fp16, FileBackedSumcheckError> {
    Fp16::decode(encoded).map_err(|_| FileBackedSumcheckError::NonCanonical)
}

struct FoldPart {
    ordinal: usize,
    coefficients: [Fp16; 3],
    left: Vec<u8>,
    right: Vec<u8>,
}

fn fold_part(
    ordinal: usize,
    left: &[u8],
    right: &[u8],
    challenge: Fp16,
) -> Result<FoldPart, FileBackedSumcheckError> {
    if left.len() != right.len()
        || !left.len().is_multiple_of(2 * FP16_ENCODED_LENGTH)
        || left.is_empty()
    {
        return Err(FileBackedSumcheckError::Shape);
    }
    let pair_count = left.len() / (2 * FP16_ENCODED_LENGTH);
    let mut left_folded = Vec::with_capacity(pair_count * FP16_ENCODED_LENGTH);
    let mut right_folded = Vec::with_capacity(pair_count * FP16_ENCODED_LENGTH);
    let mut coefficients = [Fp16::ZERO; 3];
    for pair in 0..pair_count {
        let start = pair * 2 * FP16_ENCODED_LENGTH;
        let middle = start + FP16_ENCODED_LENGTH;
        let end = middle + FP16_ENCODED_LENGTH;
        let left_zero = decode_value(&left[start..middle])?;
        let left_one = decode_value(&left[middle..end])?;
        let right_zero = decode_value(&right[start..middle])?;
        let right_one = decode_value(&right[middle..end])?;
        let left_delta = left_one - left_zero;
        let right_delta = right_one - right_zero;
        coefficients[0] = coefficients[0] + left_zero * right_zero;
        coefficients[1] = coefficients[1] + left_zero * right_delta + left_delta * right_zero;
        coefficients[2] = coefficients[2] + left_delta * right_delta;
        left_folded.extend_from_slice(&(left_zero + challenge * left_delta).encode());
        right_folded.extend_from_slice(&(right_zero + challenge * right_delta).encode());
    }
    Ok(FoldPart {
        ordinal,
        coefficients,
        left: left_folded,
        right: right_folded,
    })
}

/// Publish one exact product-sumcheck round and fold both run-owned tables.
///
/// `slab_value_count` is a public resource parameter. It must be an even
/// power of two. Work is split deterministically into contiguous pair ranges,
/// and partial field sums are combined in increasing range order.
pub fn product_round_and_fold_files(
    left_path: &Path,
    right_path: &Path,
    value_count: usize,
    challenge: Fp16,
    slab_value_count: usize,
    workers: usize,
) -> Result<FileBackedProductRound, FileBackedSumcheckError> {
    if value_count < 2
        || !value_count.is_power_of_two()
        || slab_value_count < 2
        || !slab_value_count.is_power_of_two()
        || workers == 0
    {
        return Err(FileBackedSumcheckError::Shape);
    }
    validate_table(left_path, value_count)?;
    validate_table(right_path, value_count)?;

    let slab_values = slab_value_count.min(value_count);
    let slab_bytes = slab_values
        .checked_mul(FP16_ENCODED_LENGTH)
        .ok_or(FileBackedSumcheckError::Shape)?;
    let mut left_reader = BufReader::with_capacity(
        slab_bytes,
        File::open(left_path).map_err(|_| FileBackedSumcheckError::Io)?,
    );
    let mut right_reader = BufReader::with_capacity(
        slab_bytes,
        File::open(right_path).map_err(|_| FileBackedSumcheckError::Io)?,
    );
    let mut left_writer = BufWriter::with_capacity(
        slab_bytes / 2,
        OpenOptions::new()
            .write(true)
            .open(left_path)
            .map_err(|_| FileBackedSumcheckError::Io)?,
    );
    let mut right_writer = BufWriter::with_capacity(
        slab_bytes / 2,
        OpenOptions::new()
            .write(true)
            .open(right_path)
            .map_err(|_| FileBackedSumcheckError::Io)?,
    );

    let mut remaining = value_count;
    let mut combined = [Fp16::ZERO; 3];
    let mut left_encoded = vec![0_u8; slab_bytes];
    let mut right_encoded = vec![0_u8; slab_bytes];
    while remaining != 0 {
        let current_values = slab_values.min(remaining);
        let current_bytes = current_values * FP16_ENCODED_LENGTH;
        left_reader
            .read_exact(&mut left_encoded[..current_bytes])
            .and_then(|_| right_reader.read_exact(&mut right_encoded[..current_bytes]))
            .map_err(|_| FileBackedSumcheckError::Io)?;
        let pair_count = current_values / 2;
        let worker_count = workers.min(pair_count);
        let chunk_pairs = pair_count.div_ceil(worker_count);
        let parts = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(worker_count);
            for ordinal in 0..worker_count {
                let start_pair = ordinal * chunk_pairs;
                let end_pair = (start_pair + chunk_pairs).min(pair_count);
                if start_pair == end_pair {
                    continue;
                }
                let start = start_pair * 2 * FP16_ENCODED_LENGTH;
                let end = end_pair * 2 * FP16_ENCODED_LENGTH;
                let left = &left_encoded[start..end];
                let right = &right_encoded[start..end];
                handles.push(scope.spawn(move || fold_part(ordinal, left, right, challenge)));
            }
            handles
                .into_iter()
                .map(|handle| handle.join().map_err(|_| FileBackedSumcheckError::Worker)?)
                .collect::<Result<Vec<_>, _>>()
        })?;
        for (expected, part) in parts.into_iter().enumerate() {
            if part.ordinal != expected {
                return Err(FileBackedSumcheckError::Worker);
            }
            for (destination, value) in combined.iter_mut().zip(part.coefficients) {
                *destination = *destination + value;
            }
            left_writer
                .write_all(&part.left)
                .and_then(|_| right_writer.write_all(&part.right))
                .map_err(|_| FileBackedSumcheckError::Io)?;
        }
        remaining -= current_values;
    }
    left_writer
        .flush()
        .and_then(|_| right_writer.flush())
        .map_err(|_| FileBackedSumcheckError::Io)?;
    drop(left_writer);
    drop(right_writer);
    let next_value_count = value_count / 2;
    let next_length = checked_file_length(next_value_count)?;
    OpenOptions::new()
        .write(true)
        .open(left_path)
        .and_then(|file| file.set_len(next_length))
        .and_then(|_| {
            OpenOptions::new()
                .write(true)
                .open(right_path)
                .and_then(|file| file.set_len(next_length))
        })
        .map_err(|_| FileBackedSumcheckError::Io)?;
    Ok(FileBackedProductRound {
        coefficients: combined,
        next_value_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use std::{
        fs::{self, File},
        io::Write,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::{
        M31,
        multilinear_batch_sumcheck::{fold_table, product_round_coefficients},
    };

    fn fp(value: u32) -> Fp16 {
        Fp16::from_m31(M31::from_canonical(value).unwrap())
    }

    fn temporary_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "bl-pq512-file-sumcheck-{}-{label}-{nonce}.bin",
            std::process::id()
        ))
    }

    fn write_table(path: &Path, values: &[Fp16]) {
        let mut file = File::create(path).unwrap();
        for value in values {
            file.write_all(&value.encode()).unwrap();
        }
        file.flush().unwrap();
    }

    #[test]
    fn file_rounds_match_dense_control_exactly() {
        let left_path = temporary_path("left");
        let right_path = temporary_path("right");
        let mut dense_left = (0..1_u32 << 12)
            .map(|index| fp((17 * index + 3) % 65_521))
            .collect::<Vec<_>>();
        let mut dense_right = (0..1_u32 << 12)
            .map(|index| fp((29 * index + 11) % 65_519))
            .collect::<Vec<_>>();
        write_table(&left_path, &dense_left);
        write_table(&right_path, &dense_right);
        let mut value_count = dense_left.len();
        for round in 0..12_u32 {
            let challenge = fp(101 + round);
            let expected = product_round_coefficients(&dense_left, &dense_right).unwrap();
            let actual = product_round_and_fold_files(
                &left_path,
                &right_path,
                value_count,
                challenge,
                1 << 8,
                4,
            )
            .unwrap();
            assert_eq!(actual.coefficients, expected);
            fold_table(&mut dense_left, challenge);
            fold_table(&mut dense_right, challenge);
            value_count /= 2;
            assert_eq!(actual.next_value_count, value_count);
        }
        assert_eq!(dense_left.len(), 1);
        assert_eq!(dense_right.len(), 1);
        assert_eq!(fs::metadata(&left_path).unwrap().len(), 64);
        assert_eq!(fs::metadata(&right_path).unwrap().len(), 64);
        fs::remove_file(left_path).unwrap();
        fs::remove_file(right_path).unwrap();
    }

    #[test]
    fn rejects_truncated_and_noncanonical_tables() {
        let left_path = temporary_path("bad-left");
        let right_path = temporary_path("bad-right");
        write_table(&left_path, &[fp(1), fp(2), fp(3), fp(4)]);
        write_table(&right_path, &[fp(5), fp(6), fp(7), fp(8)]);
        File::options()
            .write(true)
            .open(&right_path)
            .unwrap()
            .set_len(3 * 64)
            .unwrap();
        assert_eq!(
            product_round_and_fold_files(&left_path, &right_path, 4, fp(9), 4, 2),
            Err(FileBackedSumcheckError::Shape)
        );
        write_table(&right_path, &[fp(5), fp(6), fp(7), fp(8)]);
        let mut forged = File::options().write(true).open(&left_path).unwrap();
        forged.write_all(&u32::MAX.to_be_bytes()).unwrap();
        forged.flush().unwrap();
        assert_eq!(
            product_round_and_fold_files(&left_path, &right_path, 4, fp(9), 4, 2),
            Err(FileBackedSumcheckError::NonCanonical)
        );
        fs::remove_file(left_path).unwrap();
        fs::remove_file(right_path).unwrap();
    }

    #[test]
    fn rejects_non_power_of_two_resource_shapes() {
        let path = temporary_path("shape");
        assert_eq!(
            product_round_and_fold_files(&path, &path, 4, fp(1), 3, 1),
            Err(FileBackedSumcheckError::Shape)
        );
    }
}
