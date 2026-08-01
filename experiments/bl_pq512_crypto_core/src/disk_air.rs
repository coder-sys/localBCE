//! Bounded-memory construction of the committed masked main AIR oracle.

use core::fmt;

use alloc::collections::BTreeMap;
use alloc::{format, string::String, vec, vec::Vec};
use sha3::{Digest, Sha3_512};
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use crate::air_composition::{AirCompositionError, oracle_id};
use crate::air_ir::{AIR_PROGRAM_DOMAIN, AirIrError, parse_air_program};
use crate::cross_domain::{DiskCrossDomainError, DiskCrossDomainTree, DiskDomainEvaluationBatch};
use crate::oracle_commitment::{
    OracleCommitmentError, OracleTableGeometry, derive_oracle_commitment_layouts,
};
use crate::streaming_store::{StreamingScratchExecution, StreamingStoreError};
use crate::trace_mask::{
    TraceMaskError, canonical_coset_zeroifier_evaluations, mask_trace_column_with_zeroifiers,
    sample_trace_mask_coefficients,
};

const DISK_AIR_MARKER: &[u8; 8] = b"BLPQDAR1";
const TRANSPOSE_MEMORY_CAP_BYTES: usize = 32 << 20;
const TRANSPOSE_MAX_BLOCK_ROWS: usize = 8192;

#[derive(Debug)]
pub enum DiskAirError {
    Air(AirIrError),
    Composition(AirCompositionError),
    CrossDomain(DiskCrossDomainError),
    Oracle(OracleCommitmentError),
    Store(StreamingStoreError),
    TraceMask(TraceMaskError),
    Io(std::io::ErrorKind),
    ProgramMismatch,
    Parent,
    Ownership,
    Shape,
    Overflow,
}

impl From<AirIrError> for DiskAirError {
    fn from(value: AirIrError) -> Self {
        Self::Air(value)
    }
}
impl From<AirCompositionError> for DiskAirError {
    fn from(value: AirCompositionError) -> Self {
        Self::Composition(value)
    }
}
impl From<DiskCrossDomainError> for DiskAirError {
    fn from(value: DiskCrossDomainError) -> Self {
        Self::CrossDomain(value)
    }
}
impl From<OracleCommitmentError> for DiskAirError {
    fn from(value: OracleCommitmentError) -> Self {
        Self::Oracle(value)
    }
}
impl From<StreamingStoreError> for DiskAirError {
    fn from(value: StreamingStoreError) -> Self {
        Self::Store(value)
    }
}
impl From<TraceMaskError> for DiskAirError {
    fn from(value: TraceMaskError) -> Self {
        Self::TraceMask(value)
    }
}
impl From<std::io::Error> for DiskAirError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.kind())
    }
}

impl fmt::Display for DiskAirError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "BL-PQ512 disk AIR error: {self:?}")
    }
}

impl core::error::Error for DiskAirError {}

#[derive(Clone, Debug)]
pub struct DiskTableMainTraceOracle {
    pub table_index: usize,
    pub logical_rows: usize,
    pub trace_rows: usize,
    pub trace_log_size: u8,
    pub evaluation_log_size: u8,
    pub composition_work_log_size: u8,
    pub component_coefficient_log_size: u8,
    pub composition_component_count: usize,
    pub committed_column_indices: Vec<usize>,
    pub column_files: Vec<PathBuf>,
}

struct OwnedAirDirectory {
    path: PathBuf,
    program_commitment: [u8; 64],
}

impl Drop for OwnedAirDirectory {
    fn drop(&mut self) {
        let _ = cleanup_owned_air_directory(&self.path, &self.program_commitment);
    }
}

pub struct DiskAirMainTraceOracle {
    pub source_program_commitment: [u8; 64],
    pub program_binary_commitment: [u8; 64],
    pub tables: Vec<DiskTableMainTraceOracle>,
    pub tree: DiskCrossDomainTree,
    owned_directory: OwnedAirDirectory,
}

type DiskMainBuild = (Vec<DiskTableMainTraceOracle>, BTreeMap<u8, Vec<PathBuf>>);

impl DiskAirMainTraceOracle {
    #[must_use]
    pub fn scratch_path(&self) -> &Path {
        &self.owned_directory.path
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_disk_air_main_trace_oracle(
    program_encoded: &[u8],
    execution: &StreamingScratchExecution,
    secret_mask_seed: &[u8],
    session_id: &[u8],
    mask_coefficient_count: usize,
    log_blowup: u8,
    scratch_parent: &Path,
    build_nonce: &[u8; 32],
) -> Result<DiskAirMainTraceOracle, DiskAirError> {
    if !scratch_parent.is_absolute()
        || !scratch_parent.is_dir()
        || mask_coefficient_count == 0
        || log_blowup == 0
    {
        return Err(DiskAirError::Parent);
    }
    let program = parse_air_program(program_encoded)?;
    let mut program_hash = Sha3_512::new();
    program_hash.update(AIR_PROGRAM_DOMAIN);
    program_hash.update(program_encoded);
    let program_binary_commitment: [u8; 64] = program_hash.finalize().into();
    if execution.manifest().program_binary_commitment != program_binary_commitment
        || execution.manifest().tables.len() != program.tables.len()
    {
        return Err(DiskAirError::ProgramMismatch);
    }
    let layouts =
        derive_oracle_commitment_layouts(program_encoded, mask_coefficient_count, log_blowup)?;
    let directory = scratch_parent.join(air_directory_name(build_nonce));
    create_owned_air_directory(&directory, &program_binary_commitment)?;
    let owned_directory = OwnedAirDirectory {
        path: directory.clone(),
        program_commitment: program_binary_commitment,
    };
    let (tables, grouped_files) = build_owned_main(
        &program,
        execution,
        secret_mask_seed,
        session_id,
        mask_coefficient_count,
        &layouts.tables,
        &directory,
    )?;
    let mut batches = Vec::with_capacity(layouts.main_trace.specs().len());
    for spec in layouts.main_trace.specs() {
        let files = grouped_files
            .get(&spec.log_size)
            .ok_or(DiskAirError::Shape)?;
        if files.len() != spec.column_count as usize {
            return Err(DiskAirError::Shape);
        }
        batches.push(DiskDomainEvaluationBatch::new_from_columns(
            *spec,
            files.clone(),
        )?);
    }
    let mut tree_hash = Sha3_512::new();
    tree_hash.update(b"BL/PQ512/WAVE1B/DISK-MAIN-TREE-NONCE/v1\0");
    tree_hash.update(build_nonce);
    let tree_nonce: [u8; 64] = tree_hash.finalize().into();
    let mut short_tree_nonce = [0_u8; 32];
    short_tree_nonce.copy_from_slice(&tree_nonce[..32]);
    let tree = DiskCrossDomainTree::build(
        layouts.main_trace,
        batches,
        scratch_parent,
        &short_tree_nonce,
    )?;
    Ok(DiskAirMainTraceOracle {
        source_program_commitment: program.source_program_commitment,
        program_binary_commitment,
        tables,
        tree,
        owned_directory,
    })
}

fn build_owned_main(
    program: &crate::air_ir::ParsedProgram,
    execution: &StreamingScratchExecution,
    secret_mask_seed: &[u8],
    session_id: &[u8],
    mask_coefficient_count: usize,
    geometries: &[OracleTableGeometry],
    directory: &Path,
) -> Result<DiskMainBuild, DiskAirError> {
    let mut tables = Vec::with_capacity(program.tables.len());
    let mut grouped_files = BTreeMap::<u8, Vec<PathBuf>>::new();
    for (table_index, (table, geometry)) in program.tables.iter().zip(geometries).enumerate() {
        if geometry.table_index != table_index {
            return Err(DiskAirError::Shape);
        }
        let manifest_table = &execution.manifest().tables[table_index];
        let expected_indices = manifest_table
            .columns
            .iter()
            .map(|column| column.column_index)
            .collect::<Vec<_>>();
        if expected_indices.len() != geometry.main_column_count {
            return Err(DiskAirError::Shape);
        }
        let zeroifiers = canonical_coset_zeroifier_evaluations(
            geometry.trace_log_size,
            geometry.evaluation_log_size,
        )?;
        let mut column_files = Vec::with_capacity(expected_indices.len());
        for column_index in &expected_indices {
            let mut natural =
                execution.read_column_range(table_index, *column_index, 0, table.rows)?;
            if natural.len() != table.rows {
                return Err(DiskAirError::Shape);
            }
            natural.resize(geometry.trace_rows, crate::field::M31::ZERO);
            let coefficients = sample_trace_mask_coefficients(
                secret_mask_seed,
                session_id,
                &oracle_id(
                    &program.source_program_commitment,
                    table_index,
                    *column_index,
                )?,
                mask_coefficient_count,
            )?;
            let evaluations = mask_trace_column_with_zeroifiers(
                &natural,
                &coefficients,
                geometry.evaluation_log_size,
                &zeroifiers,
            )?;
            let path = directory.join(format!("main-t{table_index:08x}-c{column_index:08x}.m31"));
            write_m31_column(&path, &evaluations)?;
            grouped_files
                .entry(geometry.evaluation_log_size)
                .or_default()
                .push(path.clone());
            column_files.push(path);
        }
        tables.push(DiskTableMainTraceOracle {
            table_index,
            logical_rows: table.rows,
            trace_rows: geometry.trace_rows,
            trace_log_size: geometry.trace_log_size,
            evaluation_log_size: geometry.evaluation_log_size,
            composition_work_log_size: geometry.composition_work_log_size,
            component_coefficient_log_size: geometry.component_coefficient_log_size,
            composition_component_count: geometry.composition_component_count,
            committed_column_indices: expected_indices,
            column_files,
        });
    }
    Ok((tables, grouped_files))
}

fn write_m31_column(path: &Path, values: &[crate::field::M31]) -> Result<(), DiskAirError> {
    let mut output = BufWriter::new(OpenOptions::new().write(true).create_new(true).open(path)?);
    for value in values {
        output.write_all(&value.as_u32().to_be_bytes())?;
    }
    output.flush()?;
    output.get_ref().sync_data()?;
    Ok(())
}

pub fn transpose_column_files(
    column_files: &[PathBuf],
    rows: usize,
    scalar_bytes: usize,
    output_path: &Path,
) -> Result<(), DiskAirError> {
    if column_files.is_empty() || rows == 0 || !matches!(scalar_bytes, 4 | 64) {
        return Err(DiskAirError::Shape);
    }
    let column_bytes = rows
        .checked_mul(scalar_bytes)
        .ok_or(DiskAirError::Overflow)?;
    for path in column_files {
        if !path.is_absolute() || fs::metadata(path)?.len() != column_bytes as u64 {
            return Err(DiskAirError::Shape);
        }
    }
    let bytes_per_block_row = column_files
        .len()
        .checked_mul(scalar_bytes)
        .ok_or(DiskAirError::Overflow)?;
    let block_rows =
        (TRANSPOSE_MEMORY_CAP_BYTES / bytes_per_block_row).clamp(1, TRANSPOSE_MAX_BLOCK_ROWS);
    let mut readers = column_files
        .iter()
        .map(File::open)
        .collect::<Result<Vec<_>, _>>()?;
    let mut output = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_path)?,
    );
    for row_start in (0..rows).step_by(block_rows) {
        let count = block_rows.min(rows - row_start);
        let block_bytes = count
            .checked_mul(scalar_bytes)
            .ok_or(DiskAirError::Overflow)?;
        let mut blocks = Vec::with_capacity(readers.len());
        for reader in &mut readers {
            let mut block = vec![0_u8; block_bytes];
            reader.read_exact(&mut block)?;
            blocks.push(block);
        }
        for row in 0..count {
            let start = row * scalar_bytes;
            let stop = start + scalar_bytes;
            for block in &blocks {
                output.write_all(&block[start..stop])?;
            }
        }
    }
    output.flush()?;
    output.get_ref().sync_data()?;
    Ok(())
}

fn air_directory_name(nonce: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::from("blpq-disk-air-");
    for byte in nonce {
        name.push(DIGITS[usize::from(byte >> 4)] as char);
        name.push(DIGITS[usize::from(byte & 15)] as char);
    }
    name
}

fn create_owned_air_directory(
    directory: &Path,
    program_commitment: &[u8; 64],
) -> Result<(), DiskAirError> {
    fs::create_dir(directory)?;
    let marker_path = directory.join("OWNER");
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker_path)
        .and_then(|mut marker| {
            marker.write_all(DISK_AIR_MARKER)?;
            marker.write_all(program_commitment)?;
            marker.sync_data()
        });
    if let Err(error) = result {
        let _ = fs::remove_file(marker_path);
        let _ = fs::remove_dir(directory);
        return Err(error.into());
    }
    Ok(())
}

fn cleanup_owned_air_directory(
    directory: &Path,
    expected_program: &[u8; 64],
) -> Result<(), DiskAirError> {
    let mut marker = [0_u8; 72];
    File::open(directory.join("OWNER"))?.read_exact(&mut marker)?;
    if &marker[..8] != DISK_AIR_MARKER || &marker[8..] != expected_program {
        return Err(DiskAirError::Ownership);
    }
    fs::remove_dir_all(directory)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_transpose_is_exact_for_base_and_extension_words() {
        let parent = std::env::temp_dir().join(format!(
            "blpq-disk-air-transpose-test-{}",
            std::process::id()
        ));
        fs::create_dir(&parent).unwrap();
        for scalar_bytes in [4_usize, 64] {
            let columns = (0..3)
                .map(|column| {
                    let path = parent.join(format!("{scalar_bytes}-{column}.column"));
                    let mut encoded = Vec::new();
                    for row in 0..5 {
                        encoded
                            .extend(vec![u8::try_from(column * 16 + row).unwrap(); scalar_bytes]);
                    }
                    fs::write(&path, encoded).unwrap();
                    path
                })
                .collect::<Vec<_>>();
            let output = parent.join(format!("{scalar_bytes}.rows"));
            transpose_column_files(&columns, 5, scalar_bytes, &output).unwrap();
            let observed = fs::read(&output).unwrap();
            let mut expected = Vec::new();
            for row in 0..5 {
                for column in 0..3 {
                    expected.extend(vec![u8::try_from(column * 16 + row).unwrap(); scalar_bytes]);
                }
            }
            assert_eq!(observed, expected);
            for column in columns {
                fs::remove_file(column).unwrap();
            }
            fs::remove_file(output).unwrap();
        }
        fs::remove_dir(parent).unwrap();
    }
}
