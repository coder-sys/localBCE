//! Bounded external permutation for nonlocal AIR next-row Fp16 access.

use core::cmp::Ordering;
use core::fmt;

use alloc::collections::BinaryHeap;
use alloc::{format, string::String, vec::Vec};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use crate::air_composition::{AirCompositionError, inverse_shifted_fft_index};
use crate::field::{FP16_ENCODED_LENGTH, Fp16, M31, M31_MODULUS};

const SORT_MEMORY_BYTES: usize = 32 << 20;
const RECORD_BYTES: usize = 8 + FP16_ENCODED_LENGTH;
const BASE_RECORD_BYTES: usize = 8 + 4;

#[derive(Debug)]
pub enum DiskPermutationError {
    Air(AirCompositionError),
    Decode(crate::field::DecodeError),
    Field(crate::field::FieldError),
    Io(std::io::ErrorKind),
    Shape,
    Overflow,
}

impl From<AirCompositionError> for DiskPermutationError {
    fn from(value: AirCompositionError) -> Self {
        Self::Air(value)
    }
}
impl From<crate::field::DecodeError> for DiskPermutationError {
    fn from(value: crate::field::DecodeError) -> Self {
        Self::Decode(value)
    }
}
impl From<crate::field::FieldError> for DiskPermutationError {
    fn from(value: crate::field::FieldError) -> Self {
        Self::Field(value)
    }
}
impl From<std::io::Error> for DiskPermutationError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.kind())
    }
}

impl fmt::Display for DiskPermutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "BL-PQ512 disk permutation error: {self:?}")
    }
}

impl core::error::Error for DiskPermutationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Record {
    target: usize,
    value: Fp16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HeapRecord {
    target: usize,
    run: usize,
    value: Fp16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BaseRecord {
    target: usize,
    value: M31,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BaseHeapRecord {
    target: usize,
    run: usize,
    value: M31,
}

impl Ord for BaseHeapRecord {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .target
            .cmp(&self.target)
            .then_with(|| other.run.cmp(&self.run))
    }
}

impl PartialOrd for BaseHeapRecord {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HeapRecord {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .target
            .cmp(&self.target)
            .then_with(|| other.run.cmp(&self.run))
    }
}

impl PartialOrd for HeapRecord {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub fn build_shifted_fp16_file(
    source_path: &Path,
    output_path: &Path,
    evaluation_log_size: u8,
    trace_log_size: u8,
    work_directory: &Path,
    operation_nonce: &[u8; 32],
) -> Result<(), DiskPermutationError> {
    if !source_path.is_absolute()
        || !source_path.is_file()
        || !output_path.is_absolute()
        || output_path.parent() != Some(work_directory)
        || !work_directory.is_absolute()
        || !work_directory.is_dir()
    {
        return Err(DiskPermutationError::Shape);
    }
    let rows = 1_usize
        .checked_shl(u32::from(evaluation_log_size))
        .ok_or(DiskPermutationError::Overflow)?;
    let expected_bytes = u64::try_from(rows)
        .ok()
        .and_then(|value| value.checked_mul(FP16_ENCODED_LENGTH as u64))
        .ok_or(DiskPermutationError::Overflow)?;
    if fs::metadata(source_path)?.len() != expected_bytes {
        return Err(DiskPermutationError::Shape);
    }
    let suffix = nonce_suffix(operation_nonce);
    let result = build_runs_and_merge(
        source_path,
        output_path,
        evaluation_log_size,
        trace_log_size,
        work_directory,
        &suffix,
        rows,
    );
    if result.is_err() {
        let _ = fs::remove_file(output_path);
    }
    for run in run_paths(work_directory, &suffix) {
        let _ = fs::remove_file(run);
    }
    result
}

/// Build the exact next-row permutation for one M31 evaluation column with
/// bounded memory and external merge runs.
pub fn build_shifted_m31_file(
    source_path: &Path,
    output_path: &Path,
    evaluation_log_size: u8,
    trace_log_size: u8,
    work_directory: &Path,
    operation_nonce: &[u8; 32],
) -> Result<(), DiskPermutationError> {
    if !source_path.is_absolute()
        || !source_path.is_file()
        || !output_path.is_absolute()
        || output_path.parent() != Some(work_directory)
        || !work_directory.is_absolute()
        || !work_directory.is_dir()
    {
        return Err(DiskPermutationError::Shape);
    }
    let rows = 1_usize
        .checked_shl(u32::from(evaluation_log_size))
        .ok_or(DiskPermutationError::Overflow)?;
    let expected_bytes = u64::try_from(rows)
        .ok()
        .and_then(|value| value.checked_mul(4))
        .ok_or(DiskPermutationError::Overflow)?;
    if fs::metadata(source_path)?.len() != expected_bytes {
        return Err(DiskPermutationError::Shape);
    }
    let suffix = nonce_suffix(operation_nonce);
    let result = build_base_runs_and_merge(
        source_path,
        output_path,
        evaluation_log_size,
        trace_log_size,
        work_directory,
        &suffix,
        rows,
    );
    if result.is_err() {
        let _ = fs::remove_file(output_path);
    }
    for run in base_run_paths(work_directory, &suffix) {
        let _ = fs::remove_file(run);
    }
    result
}

fn build_runs_and_merge(
    source_path: &Path,
    output_path: &Path,
    evaluation_log_size: u8,
    trace_log_size: u8,
    work_directory: &Path,
    suffix: &str,
    rows: usize,
) -> Result<(), DiskPermutationError> {
    let records_per_run = (SORT_MEMORY_BYTES / RECORD_BYTES).max(1);
    let mut source = BufReader::new(File::open(source_path)?);
    let mut paths = Vec::new();
    let mut source_index = 0usize;
    while source_index < rows {
        let count = records_per_run.min(rows - source_index);
        let mut records = Vec::with_capacity(count);
        for offset in 0..count {
            let mut encoded = [0_u8; FP16_ENCODED_LENGTH];
            source.read_exact(&mut encoded)?;
            let index = source_index + offset;
            records.push(Record {
                target: inverse_shifted_fft_index(index, evaluation_log_size, trace_log_size)?,
                value: Fp16::decode(&encoded)?,
            });
        }
        records.sort_unstable_by_key(|record| record.target);
        let path = work_directory.join(format!("shift-{suffix}-{:08}.run", paths.len()));
        let mut run = BufWriter::new(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?,
        );
        for record in records {
            write_record(&mut run, record)?;
        }
        run.flush()?;
        run.get_ref().sync_data()?;
        paths.push(path);
        source_index += count;
    }
    merge_runs(&paths, output_path, rows)
}

fn merge_runs(
    paths: &[PathBuf],
    output_path: &Path,
    rows: usize,
) -> Result<(), DiskPermutationError> {
    let mut readers = paths
        .iter()
        .map(File::open)
        .map(|result| result.map(BufReader::new))
        .collect::<Result<Vec<_>, _>>()?;
    let mut heap = BinaryHeap::new();
    for (run, reader) in readers.iter_mut().enumerate() {
        if let Some(record) = read_record(reader)? {
            heap.push(HeapRecord {
                target: record.target,
                run,
                value: record.value,
            });
        }
    }
    let mut output = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_path)?,
    );
    for expected_target in 0..rows {
        let observed = heap.pop().ok_or(DiskPermutationError::Shape)?;
        if observed.target != expected_target {
            return Err(DiskPermutationError::Shape);
        }
        output.write_all(&observed.value.encode())?;
        if let Some(next) = read_record(&mut readers[observed.run])? {
            heap.push(HeapRecord {
                target: next.target,
                run: observed.run,
                value: next.value,
            });
        }
    }
    if !heap.is_empty() {
        return Err(DiskPermutationError::Shape);
    }
    output.flush()?;
    output.get_ref().sync_data()?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_base_runs_and_merge(
    source_path: &Path,
    output_path: &Path,
    evaluation_log_size: u8,
    trace_log_size: u8,
    work_directory: &Path,
    suffix: &str,
    rows: usize,
) -> Result<(), DiskPermutationError> {
    let records_per_run = (SORT_MEMORY_BYTES / BASE_RECORD_BYTES).max(1);
    let mut source = BufReader::new(File::open(source_path)?);
    let mut paths = Vec::new();
    let mut source_index = 0usize;
    while source_index < rows {
        let count = records_per_run.min(rows - source_index);
        let mut records = Vec::with_capacity(count);
        for offset in 0..count {
            let mut encoded = [0_u8; 4];
            source.read_exact(&mut encoded)?;
            let raw = u32::from_be_bytes(encoded);
            if raw >= M31_MODULUS {
                return Err(DiskPermutationError::Shape);
            }
            let index = source_index + offset;
            records.push(BaseRecord {
                target: inverse_shifted_fft_index(index, evaluation_log_size, trace_log_size)?,
                value: M31::from_canonical(raw)?,
            });
        }
        records.sort_unstable_by_key(|record| record.target);
        let path = work_directory.join(format!("shift-base-{suffix}-{:08}.run", paths.len()));
        let mut run = BufWriter::new(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?,
        );
        for record in records {
            write_base_record(&mut run, record)?;
        }
        run.flush()?;
        run.get_ref().sync_data()?;
        paths.push(path);
        source_index += count;
    }
    merge_base_runs(&paths, output_path, rows)
}

fn merge_base_runs(
    paths: &[PathBuf],
    output_path: &Path,
    rows: usize,
) -> Result<(), DiskPermutationError> {
    let mut readers = paths
        .iter()
        .map(File::open)
        .map(|result| result.map(BufReader::new))
        .collect::<Result<Vec<_>, _>>()?;
    let mut heap = BinaryHeap::new();
    for (run, reader) in readers.iter_mut().enumerate() {
        if let Some(record) = read_base_record(reader)? {
            heap.push(BaseHeapRecord {
                target: record.target,
                run,
                value: record.value,
            });
        }
    }
    let mut output = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_path)?,
    );
    for expected_target in 0..rows {
        let observed = heap.pop().ok_or(DiskPermutationError::Shape)?;
        if observed.target != expected_target {
            return Err(DiskPermutationError::Shape);
        }
        output.write_all(&observed.value.as_u32().to_be_bytes())?;
        if let Some(next) = read_base_record(&mut readers[observed.run])? {
            heap.push(BaseHeapRecord {
                target: next.target,
                run: observed.run,
                value: next.value,
            });
        }
    }
    if !heap.is_empty() {
        return Err(DiskPermutationError::Shape);
    }
    output.flush()?;
    output.get_ref().sync_data()?;
    Ok(())
}

fn write_base_record(
    output: &mut impl Write,
    record: BaseRecord,
) -> Result<(), DiskPermutationError> {
    output.write_all(
        &u64::try_from(record.target)
            .map_err(|_| DiskPermutationError::Overflow)?
            .to_be_bytes(),
    )?;
    output.write_all(&record.value.as_u32().to_be_bytes())?;
    Ok(())
}

fn read_base_record(input: &mut impl Read) -> Result<Option<BaseRecord>, DiskPermutationError> {
    let mut target = [0_u8; 8];
    let mut read = 0usize;
    while read < target.len() {
        let count = input.read(&mut target[read..])?;
        if count == 0 {
            if read == 0 {
                return Ok(None);
            }
            return Err(DiskPermutationError::Shape);
        }
        read += count;
    }
    let mut encoded = [0_u8; 4];
    input.read_exact(&mut encoded)?;
    let raw = u32::from_be_bytes(encoded);
    if raw >= M31_MODULUS {
        return Err(DiskPermutationError::Shape);
    }
    Ok(Some(BaseRecord {
        target: usize::try_from(u64::from_be_bytes(target))
            .map_err(|_| DiskPermutationError::Overflow)?,
        value: M31::from_canonical(raw)?,
    }))
}

fn write_record(output: &mut impl Write, record: Record) -> Result<(), DiskPermutationError> {
    output.write_all(
        &u64::try_from(record.target)
            .map_err(|_| DiskPermutationError::Overflow)?
            .to_be_bytes(),
    )?;
    output.write_all(&record.value.encode())?;
    Ok(())
}

fn read_record(input: &mut impl Read) -> Result<Option<Record>, DiskPermutationError> {
    let mut target = [0_u8; 8];
    let mut read = 0usize;
    while read < target.len() {
        let count = input.read(&mut target[read..])?;
        if count == 0 {
            if read == 0 {
                return Ok(None);
            }
            return Err(DiskPermutationError::Shape);
        }
        read += count;
    }
    let mut value = [0_u8; FP16_ENCODED_LENGTH];
    input.read_exact(&mut value)?;
    Ok(Some(Record {
        target: usize::try_from(u64::from_be_bytes(target))
            .map_err(|_| DiskPermutationError::Overflow)?,
        value: Fp16::decode(&value)?,
    }))
}

fn nonce_suffix(nonce: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut suffix = String::new();
    for byte in nonce {
        suffix.push(DIGITS[usize::from(byte >> 4)] as char);
        suffix.push(DIGITS[usize::from(byte & 15)] as char);
    }
    suffix
}

fn run_paths(directory: &Path, suffix: &str) -> Vec<PathBuf> {
    match fs::read_dir(directory) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with(&format!("shift-{suffix}-")) && name.ends_with(".run")
                    })
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn base_run_paths(directory: &Path, suffix: &str) -> Vec<PathBuf> {
    match fs::read_dir(directory) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with(&format!("shift-base-{suffix}-")) && name.ends_with(".run")
                    })
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air_composition::shifted_fft_index;
    use crate::field::M31;

    #[test]
    fn external_shift_matches_exact_index_permutation_and_cleans_runs() {
        let directory =
            std::env::temp_dir().join(format!("blpq-disk-shift-test-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let source = directory.join("source.fp16");
        let output = directory.join("shifted.fp16");
        let values = (0..256)
            .map(|index| Fp16::from_m31(M31::from_canonical(index + 1).unwrap()))
            .collect::<Vec<_>>();
        let mut encoded = Vec::new();
        for value in &values {
            encoded.extend_from_slice(&value.encode());
        }
        fs::write(&source, encoded).unwrap();
        build_shifted_fp16_file(&source, &output, 8, 4, &directory, &[0xa7; 32]).unwrap();
        let observed = fs::read(&output)
            .unwrap()
            .chunks_exact(FP16_ENCODED_LENGTH)
            .map(|word| Fp16::decode(word).unwrap())
            .collect::<Vec<_>>();
        let expected = (0..256)
            .map(|index| values[shifted_fft_index(index, 8, 4).unwrap()])
            .collect::<Vec<_>>();
        assert_eq!(observed, expected);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 2);
        fs::remove_file(source).unwrap();
        fs::remove_file(output).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn external_base_shift_matches_exact_index_permutation_and_cleans_runs() {
        let directory =
            std::env::temp_dir().join(format!("blpq-disk-base-shift-test-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let source = directory.join("source.m31");
        let output = directory.join("shifted.m31");
        let values = (0..256)
            .map(|index| M31::from_canonical(index + 11).unwrap())
            .collect::<Vec<_>>();
        let mut encoded = Vec::new();
        for value in &values {
            encoded.extend_from_slice(&value.as_u32().to_be_bytes());
        }
        fs::write(&source, encoded).unwrap();
        build_shifted_m31_file(&source, &output, 8, 4, &directory, &[0xb3; 32]).unwrap();
        let observed = fs::read(&output)
            .unwrap()
            .chunks_exact(4)
            .map(|word| M31::from_canonical(u32::from_be_bytes(word.try_into().unwrap())).unwrap())
            .collect::<Vec<_>>();
        let expected = (0..256)
            .map(|index| values[shifted_fft_index(index, 8, 4).unwrap()])
            .collect::<Vec<_>>();
        assert_eq!(observed, expected);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 2);
        fs::remove_file(source).unwrap();
        fs::remove_file(output).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
