//! Bounded-memory masking and commitment of trace-domain LogUp columns.

use core::fmt;

use alloc::collections::BTreeMap;
use alloc::{format, string::String, vec, vec::Vec};
use sha3::{Digest, Sha3_512};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::air_ir::{AirIrError, parse_air_program};
use crate::air_logup::{AirLogupError, AirLogupOracle, compress_side, interaction_id};
use crate::cross_domain::{DiskCrossDomainError, DiskCrossDomainTree, DiskDomainEvaluationBatch};
use crate::disk_air::DiskAirError;
use crate::disk_fft::{DiskFftError, mask_extension_trace_column_to_file};
use crate::oracle_commitment::{OracleCommitmentError, derive_oracle_commitment_layouts};
use crate::streaming_store::{StreamingScratchExecution, StreamingStoreError};
use crate::trace_mask::{TraceMaskError, sample_extension_trace_mask_coefficients};

const DISK_LOGUP_MARKER: &[u8; 8] = b"BLPQDLU1";

#[derive(Debug)]
pub enum DiskLogupError {
    Air(AirIrError),
    AirLogup(AirLogupError),
    CrossDomain(DiskCrossDomainError),
    DiskAir(DiskAirError),
    DiskFft(DiskFftError),
    Oracle(OracleCommitmentError),
    TraceMask(TraceMaskError),
    Store(StreamingStoreError),
    Io(std::io::ErrorKind),
    Parent,
    Ownership,
    Shape,
    Overflow,
}

impl From<AirIrError> for DiskLogupError {
    fn from(value: AirIrError) -> Self {
        Self::Air(value)
    }
}

impl From<AirLogupError> for DiskLogupError {
    fn from(value: AirLogupError) -> Self {
        Self::AirLogup(value)
    }
}
impl From<DiskCrossDomainError> for DiskLogupError {
    fn from(value: DiskCrossDomainError) -> Self {
        Self::CrossDomain(value)
    }
}
impl From<DiskAirError> for DiskLogupError {
    fn from(value: DiskAirError) -> Self {
        Self::DiskAir(value)
    }
}
impl From<DiskFftError> for DiskLogupError {
    fn from(value: DiskFftError) -> Self {
        Self::DiskFft(value)
    }
}
impl From<OracleCommitmentError> for DiskLogupError {
    fn from(value: OracleCommitmentError) -> Self {
        Self::Oracle(value)
    }
}
impl From<TraceMaskError> for DiskLogupError {
    fn from(value: TraceMaskError) -> Self {
        Self::TraceMask(value)
    }
}
impl From<StreamingStoreError> for DiskLogupError {
    fn from(value: StreamingStoreError) -> Self {
        Self::Store(value)
    }
}
impl From<std::io::Error> for DiskLogupError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.kind())
    }
}

impl fmt::Display for DiskLogupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "BL-PQ512 disk LogUp error: {self:?}")
    }
}

impl core::error::Error for DiskLogupError {}

#[derive(Clone, Debug)]
pub struct DiskLogupTableInteraction {
    pub lookup_index: usize,
    pub table_index: usize,
    pub evaluation_log_size: u8,
    pub side_signs: Vec<i8>,
    pub masked_column_files: Vec<PathBuf>,
    pub final_sum: crate::field::Fp16,
}

struct OwnedLogupDirectory {
    path: PathBuf,
    program_commitment: [u8; 64],
}

impl Drop for OwnedLogupDirectory {
    fn drop(&mut self) {
        let _ = cleanup_owned_directory(&self.path, &self.program_commitment);
    }
}

pub struct DiskAirLogupOracle {
    pub interactions: Vec<DiskLogupTableInteraction>,
    pub lookup_count: u32,
    pub side_count: u64,
    pub denominator_count: u64,
    pub tree: DiskCrossDomainTree,
    owned_directory: OwnedLogupDirectory,
}

impl DiskAirLogupOracle {
    #[must_use]
    pub fn scratch_path(&self) -> &Path {
        &self.owned_directory.path
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_disk_air_logup_oracle(
    program_encoded: &[u8],
    unmasked: &AirLogupOracle,
    source_program_commitment: &[u8; 64],
    secret_mask_seed: &[u8],
    session_id: &[u8],
    mask_coefficient_count: usize,
    log_blowup: u8,
    scratch_parent: &Path,
    build_nonce: &[u8; 32],
) -> Result<DiskAirLogupOracle, DiskLogupError> {
    if !scratch_parent.is_absolute() || !scratch_parent.is_dir() {
        return Err(DiskLogupError::Parent);
    }
    if unmasked.interactions.iter().any(|interaction| {
        !interaction.masked_inverse_evaluations.is_empty()
            || !interaction.masked_accumulator_evaluations.is_empty()
    }) {
        return Err(DiskLogupError::Shape);
    }
    if parse_air_program(program_encoded)?.source_program_commitment != *source_program_commitment {
        return Err(DiskLogupError::Shape);
    }
    let layouts =
        derive_oracle_commitment_layouts(program_encoded, mask_coefficient_count, log_blowup)?;
    let layout = layouts.interaction_trace.ok_or(DiskLogupError::Shape)?;
    let directory = scratch_parent.join(logup_directory_name(build_nonce));
    create_owned_directory(&directory, &layouts.program_binary_commitment)?;
    let owned_directory = OwnedLogupDirectory {
        path: directory.clone(),
        program_commitment: layouts.program_binary_commitment,
    };
    let mut interactions = Vec::with_capacity(unmasked.interactions.len());
    let mut grouped = BTreeMap::<u8, Vec<PathBuf>>::new();
    for interaction in &unmasked.interactions {
        let lookup_index = interaction.lookup_index as usize;
        let table_index = interaction.table_index as usize;
        let mut files = Vec::with_capacity(interaction.inverse_columns.len() + 1);
        for (column_index, natural) in interaction
            .inverse_columns
            .iter()
            .chain(core::iter::once(&interaction.accumulator_column))
            .enumerate()
        {
            let randomizer = sample_extension_trace_mask_coefficients(
                secret_mask_seed,
                session_id,
                &interaction_id(
                    source_program_commitment,
                    lookup_index,
                    table_index,
                    column_index,
                )?,
                mask_coefficient_count,
            )?;
            let output = directory.join(format!(
                "interaction-l{lookup_index:08x}-t{table_index:08x}-c{column_index:08x}.fp16"
            ));
            let operation_nonce =
                derived_operation_nonce(build_nonce, lookup_index, table_index, column_index)?;
            mask_extension_trace_column_to_file(
                natural,
                &randomizer,
                interaction.evaluation_log_size,
                &directory,
                &operation_nonce,
                &output,
            )?;
            grouped
                .entry(interaction.evaluation_log_size)
                .or_default()
                .push(output.clone());
            files.push(output);
        }
        interactions.push(DiskLogupTableInteraction {
            lookup_index,
            table_index,
            evaluation_log_size: interaction.evaluation_log_size,
            side_signs: interaction.side_signs.clone(),
            masked_column_files: files,
            final_sum: interaction.final_sum,
        });
    }
    let mut batches = Vec::with_capacity(layout.specs().len());
    for spec in layout.specs() {
        let files = grouped.get(&spec.log_size).ok_or(DiskLogupError::Shape)?;
        if files.len() != spec.column_count as usize {
            return Err(DiskLogupError::Shape);
        }
        batches.push(DiskDomainEvaluationBatch::new_from_columns(
            *spec,
            files.clone(),
        )?);
    }
    let tree_nonce = derived_tree_nonce(build_nonce);
    let tree = DiskCrossDomainTree::build(layout, batches, scratch_parent, &tree_nonce)?;
    Ok(DiskAirLogupOracle {
        interactions,
        lookup_count: unmasked.lookup_count,
        side_count: unmasked.side_count,
        denominator_count: unmasked.denominator_count,
        tree,
        owned_directory,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_disk_air_logup_oracle_from_streaming(
    program_encoded: &[u8],
    execution: &StreamingScratchExecution,
    beta: crate::field::Fp16,
    gamma: crate::field::Fp16,
    secret_mask_seed: &[u8],
    session_id: &[u8],
    mask_coefficient_count: usize,
    log_blowup: u8,
    table_evaluation_log_sizes: &[u8],
    scratch_parent: &Path,
    build_nonce: &[u8; 32],
) -> Result<DiskAirLogupOracle, DiskLogupError> {
    if beta.is_zero()
        || gamma.is_zero()
        || mask_coefficient_count == 0
        || !scratch_parent.is_absolute()
        || !scratch_parent.is_dir()
    {
        return Err(DiskLogupError::Parent);
    }
    let program = parse_air_program(program_encoded)?;
    let layouts =
        derive_oracle_commitment_layouts(program_encoded, mask_coefficient_count, log_blowup)?;
    if execution.manifest().program_binary_commitment != layouts.program_binary_commitment
        || execution.manifest().tables.len() != program.tables.len()
        || table_evaluation_log_sizes.len() != program.tables.len()
    {
        return Err(DiskLogupError::Shape);
    }
    let layout = layouts.interaction_trace.ok_or(DiskLogupError::Shape)?;
    let directory = scratch_parent.join(logup_directory_name(build_nonce));
    create_owned_directory(&directory, &layouts.program_binary_commitment)?;
    let owned_directory = OwnedLogupDirectory {
        path: directory.clone(),
        program_commitment: layouts.program_binary_commitment,
    };
    let mut interactions = Vec::new();
    let mut global_sums = vec![crate::field::Fp16::ZERO; program.lookups.len()];
    let mut side_count = 0_u64;
    let mut denominator_count = 0_u64;
    for (table_index, table) in program.tables.iter().enumerate() {
        let mut columns = Vec::with_capacity(table.columns.len());
        for column_index in 0..table.columns.len() {
            if let Some((_, fixed)) = table
                .fixed_columns
                .iter()
                .find(|(index, _)| *index == column_index)
            {
                columns.push(fixed.materialize());
            } else {
                columns.push(execution.read_column_range(
                    table_index,
                    column_index,
                    0,
                    table.rows,
                )?);
            }
        }
        for (lookup_index, lookup) in program.lookups.iter().enumerate() {
            let sides = lookup
                .sources
                .iter()
                .filter(|side| side.table == table_index)
                .map(|side| (1_i8, side))
                .chain(
                    lookup
                        .destinations
                        .iter()
                        .filter(|side| side.table == table_index)
                        .map(|side| (-1_i8, side)),
                )
                .collect::<Vec<_>>();
            if sides.is_empty() {
                continue;
            }
            side_count = side_count
                .checked_add(u64::try_from(sides.len()).map_err(|_| DiskLogupError::Shape)?)
                .ok_or(DiskLogupError::Shape)?;
            let trace_rows = table
                .rows
                .next_power_of_two()
                .max(mask_coefficient_count.next_power_of_two());
            let mask_size = mask_coefficient_count.next_power_of_two();
            let minimum_log = (trace_rows
                .checked_add(mask_size)
                .ok_or(DiskLogupError::Shape)?
                .next_power_of_two()
                .ilog2() as u8)
                .checked_add(log_blowup)
                .ok_or(DiskLogupError::Shape)?;
            let evaluation_log_size = table_evaluation_log_sizes[table_index];
            if evaluation_log_size < minimum_log {
                return Err(DiskLogupError::Shape);
            }
            let mut inverse_columns = vec![vec![crate::field::Fp16::ZERO; trace_rows]; sides.len()];
            let mut contribution = vec![crate::field::Fp16::ZERO; trace_rows];
            for (side_index, (sign, side)) in sides.iter().enumerate() {
                for row in side.row_start..side.row_stop {
                    let (selector, weight, denominator) =
                        compress_side(side, &columns, row, beta, gamma)?;
                    if selector.is_zero() {
                        continue;
                    }
                    if denominator.is_zero() {
                        return Err(DiskLogupError::AirLogup(
                            AirLogupError::ExceptionalDenominator,
                        ));
                    }
                    let inverse = denominator.inverse().map_err(AirLogupError::Field)?;
                    inverse_columns[side_index][row] = inverse;
                    denominator_count = denominator_count
                        .checked_add(1)
                        .ok_or(DiskLogupError::Shape)?;
                    let weighted = inverse.mul(crate::field::Fp16::from_m31(weight));
                    contribution[row] = if *sign > 0 {
                        contribution[row].add(weighted)
                    } else {
                        contribution[row].sub(weighted)
                    };
                }
            }
            let mut accumulator = vec![crate::field::Fp16::ZERO; trace_rows];
            for row in 1..trace_rows {
                accumulator[row] = accumulator[row - 1].add(contribution[row - 1]);
            }
            let final_sum = accumulator[table.rows - 1].add(contribution[table.rows - 1]);
            global_sums[lookup_index] = global_sums[lookup_index].add(final_sum);
            let mut files = Vec::with_capacity(inverse_columns.len() + 1);
            for (column_index, natural) in inverse_columns
                .iter()
                .chain(core::iter::once(&accumulator))
                .enumerate()
            {
                let randomizer = sample_extension_trace_mask_coefficients(
                    secret_mask_seed,
                    session_id,
                    &interaction_id(
                        &program.source_program_commitment,
                        lookup_index,
                        table_index,
                        column_index,
                    )?,
                    mask_coefficient_count,
                )?;
                let output = directory.join(format!(
                    "interaction-l{lookup_index:08x}-t{table_index:08x}-c{column_index:08x}.fp16"
                ));
                let operation_nonce =
                    derived_operation_nonce(build_nonce, lookup_index, table_index, column_index)?;
                mask_extension_trace_column_to_file(
                    natural,
                    &randomizer,
                    evaluation_log_size,
                    &directory,
                    &operation_nonce,
                    &output,
                )?;
                files.push(output);
            }
            interactions.push(DiskLogupTableInteraction {
                lookup_index,
                table_index,
                evaluation_log_size,
                side_signs: sides.iter().map(|(sign, _)| *sign).collect(),
                masked_column_files: files,
                final_sum,
            });
        }
    }
    for (lookup_index, sum) in global_sums.into_iter().enumerate() {
        if !sum.is_zero() {
            return Err(DiskLogupError::AirLogup(AirLogupError::GlobalSumNonzero {
                lookup_index: u32::try_from(lookup_index).map_err(|_| DiskLogupError::Shape)?,
            }));
        }
    }
    interactions.sort_by_key(|interaction| (interaction.lookup_index, interaction.table_index));
    let mut grouped = BTreeMap::<u8, Vec<PathBuf>>::new();
    for interaction in &interactions {
        grouped
            .entry(interaction.evaluation_log_size)
            .or_default()
            .extend(interaction.masked_column_files.iter().cloned());
    }
    let mut batches = Vec::with_capacity(layout.specs().len());
    for spec in layout.specs() {
        let files = grouped.get(&spec.log_size).ok_or(DiskLogupError::Shape)?;
        if files.len() != spec.column_count as usize {
            return Err(DiskLogupError::Shape);
        }
        batches.push(DiskDomainEvaluationBatch::new_from_columns(
            *spec,
            files.clone(),
        )?);
    }
    let tree = DiskCrossDomainTree::build(
        layout,
        batches,
        scratch_parent,
        &derived_tree_nonce(build_nonce),
    )?;
    Ok(DiskAirLogupOracle {
        interactions,
        lookup_count: u32::try_from(program.lookups.len()).map_err(|_| DiskLogupError::Shape)?,
        side_count,
        denominator_count,
        tree,
        owned_directory,
    })
}

fn derived_operation_nonce(
    build_nonce: &[u8; 32],
    lookup_index: usize,
    table_index: usize,
    column_index: usize,
) -> Result<[u8; 32], DiskLogupError> {
    let mut hash = Sha3_512::new();
    hash.update(b"BL/PQ512/WAVE1B/DISK-LOGUP-COLUMN-NONCE/v1\0");
    hash.update(build_nonce);
    hash.update(
        u64::try_from(lookup_index)
            .map_err(|_| DiskLogupError::Overflow)?
            .to_be_bytes(),
    );
    hash.update(
        u64::try_from(table_index)
            .map_err(|_| DiskLogupError::Overflow)?
            .to_be_bytes(),
    );
    hash.update(
        u64::try_from(column_index)
            .map_err(|_| DiskLogupError::Overflow)?
            .to_be_bytes(),
    );
    let digest: [u8; 64] = hash.finalize().into();
    let mut nonce = [0_u8; 32];
    nonce.copy_from_slice(&digest[..32]);
    Ok(nonce)
}

fn derived_tree_nonce(build_nonce: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha3_512::new();
    hash.update(b"BL/PQ512/WAVE1B/DISK-LOGUP-TREE-NONCE/v1\0");
    hash.update(build_nonce);
    let digest: [u8; 64] = hash.finalize().into();
    let mut nonce = [0_u8; 32];
    nonce.copy_from_slice(&digest[..32]);
    nonce
}

fn logup_directory_name(nonce: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::from("blpq-disk-logup-");
    for byte in nonce {
        name.push(DIGITS[usize::from(byte >> 4)] as char);
        name.push(DIGITS[usize::from(byte & 15)] as char);
    }
    name
}

fn create_owned_directory(
    directory: &Path,
    program_commitment: &[u8; 64],
) -> Result<(), DiskLogupError> {
    fs::create_dir(directory)?;
    let marker_path = directory.join("OWNER");
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker_path)
        .and_then(|mut marker| {
            marker.write_all(DISK_LOGUP_MARKER)?;
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

fn cleanup_owned_directory(
    directory: &Path,
    expected_program: &[u8; 64],
) -> Result<(), DiskLogupError> {
    let mut marker = [0_u8; 72];
    File::open(directory.join("OWNER"))?.read_exact(&mut marker)?;
    if &marker[..8] != DISK_LOGUP_MARKER || &marker[8..] != expected_program {
        return Err(DiskLogupError::Ownership);
    }
    fs::remove_dir_all(directory)?;
    Ok(())
}
