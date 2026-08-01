//! Bounded-memory construction and commitment of the joined AIR quotient.

use core::fmt;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::{format, string::String, vec, vec::Vec};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::air_composition::{AirCompositionError, alpha_power, selector_evaluations};
use crate::air_ir::{AirIrError, Identity, ParsedProgram, parse_air_program};
use crate::composition_mask::{CompositionMaskError, mask_id};
use crate::cross_domain::{DiskCrossDomainError, DiskCrossDomainTree, DiskDomainEvaluationBatch};
use crate::disk_air::{DiskAirError, DiskAirMainTraceOracle};
use crate::disk_fft::{
    DiskFftError, evaluate_extension_circle_coefficient_file_in_place,
    evaluate_extension_circle_coefficients_to_file, extend_base_circle_evaluation_file,
    extend_extension_circle_evaluation_file, interpolate_extension_circle_file_in_place,
};
use crate::disk_logup::{DiskAirLogupOracle, DiskLogupError};
use crate::disk_permutation::{
    DiskPermutationError, build_shifted_fp16_file, build_shifted_m31_file,
};
use crate::field::{FP16_ENCODED_LENGTH, Fp16, M31, M31_MODULUS};
use crate::oracle_commitment::{OracleCommitmentError, derive_oracle_commitment_layouts};
use crate::streaming_store::{StreamingScratchExecution, StreamingStoreError};
use crate::trace_mask::{
    TraceMaskError, canonical_coset_zeroifier_evaluations, sample_extension_trace_mask_coefficients,
};

const DISK_COMPOSITION_MARKER: &[u8; 8] = b"BLPQDCP1";
const WORK_COLUMN_SCRATCH_CAP_BYTES: u64 = 32 << 30;
const UPDATE_BLOCK_ROWS: usize = 1 << 12;

type IdentityBatch = (
    core::ops::Range<usize>,
    BTreeSet<usize>,
    BTreeSet<usize>,
    BTreeSet<(usize, usize)>,
);

struct LogupTermContext<'a> {
    program: &'a ParsedProgram,
    main: &'a DiskAirMainTraceOracle,
    logup: &'a DiskAirLogupOracle,
    beta: Fp16,
    gamma: Fp16,
    alpha: Fp16,
    numerators: &'a [PathBuf],
    directory: &'a Path,
    build_nonce: &'a [u8; 32],
}

#[derive(Debug)]
pub enum DiskCompositionError {
    Air(AirIrError),
    Circle(crate::circle_fft::CircleFftError),
    Composition(AirCompositionError),
    CompositionMask(CompositionMaskError),
    CrossDomain(DiskCrossDomainError),
    DiskAir(DiskAirError),
    DiskFft(DiskFftError),
    DiskLogup(DiskLogupError),
    DiskPermutation(DiskPermutationError),
    Oracle(OracleCommitmentError),
    Store(StreamingStoreError),
    TraceMask(TraceMaskError),
    Decode(crate::field::DecodeError),
    Field(crate::field::FieldError),
    Io(std::io::ErrorKind),
    Parent,
    Ownership,
    ProgramMismatch,
    Shape,
    Overflow,
    Reconstruction,
}

macro_rules! convert_error {
    ($source:ty, $variant:ident) => {
        impl From<$source> for DiskCompositionError {
            fn from(value: $source) -> Self {
                Self::$variant(value)
            }
        }
    };
}

convert_error!(AirIrError, Air);
convert_error!(crate::circle_fft::CircleFftError, Circle);
convert_error!(AirCompositionError, Composition);
convert_error!(CompositionMaskError, CompositionMask);
convert_error!(DiskCrossDomainError, CrossDomain);
convert_error!(DiskAirError, DiskAir);
convert_error!(DiskFftError, DiskFft);
convert_error!(DiskLogupError, DiskLogup);
convert_error!(DiskPermutationError, DiskPermutation);
convert_error!(OracleCommitmentError, Oracle);
convert_error!(StreamingStoreError, Store);
convert_error!(TraceMaskError, TraceMask);
convert_error!(crate::field::DecodeError, Decode);
convert_error!(crate::field::FieldError, Field);

impl From<std::io::Error> for DiskCompositionError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.kind())
    }
}

impl fmt::Display for DiskCompositionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "BL-PQ512 disk composition error: {self:?}")
    }
}

impl core::error::Error for DiskCompositionError {}

#[derive(Clone, Debug)]
pub struct DiskTableCompositionOracle {
    pub table_index: usize,
    pub logical_rows: usize,
    pub trace_rows: usize,
    pub trace_log_size: u8,
    pub evaluation_log_size: u8,
    pub composition_work_log_size: u8,
    pub component_coefficient_log_size: u8,
    pub component_files: Vec<PathBuf>,
    pub composition_coefficient_count: usize,
}

struct OwnedCompositionDirectory {
    path: PathBuf,
    program_commitment: [u8; 64],
}

impl Drop for OwnedCompositionDirectory {
    fn drop(&mut self) {
        let _ = cleanup_owned_directory(&self.path, &self.program_commitment);
    }
}

pub struct DiskAirCompositionOracle {
    pub source_program_commitment: [u8; 64],
    pub program_binary_commitment: [u8; 64],
    pub tables: Vec<DiskTableCompositionOracle>,
    pub identity_term_count: u64,
    pub fixed_term_count: u64,
    pub public_term_count: u64,
    pub logup_term_count: u64,
    pub tree: DiskCrossDomainTree,
    owned_directory: OwnedCompositionDirectory,
}

impl DiskAirCompositionOracle {
    #[must_use]
    pub fn scratch_path(&self) -> &Path {
        &self.owned_directory.path
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_disk_air_composition_oracle(
    program_encoded: &[u8],
    execution: &StreamingScratchExecution,
    main: &DiskAirMainTraceOracle,
    logup: &DiskAirLogupOracle,
    beta: Fp16,
    gamma: Fp16,
    composition_alpha: Fp16,
    secret_mask_seed: &[u8],
    session_id: &[u8],
    trace_mask_coefficient_count: usize,
    quotient_mask_coefficient_count: usize,
    log_blowup: u8,
    scratch_parent: &Path,
    build_nonce: &[u8; 32],
) -> Result<DiskAirCompositionOracle, DiskCompositionError> {
    if beta.is_zero()
        || gamma.is_zero()
        || composition_alpha.is_zero()
        || trace_mask_coefficient_count == 0
        || quotient_mask_coefficient_count == 0
        || !scratch_parent.is_absolute()
        || !scratch_parent.is_dir()
    {
        return Err(DiskCompositionError::Parent);
    }
    let program = parse_air_program(program_encoded)?;
    let layouts = derive_oracle_commitment_layouts(
        program_encoded,
        trace_mask_coefficient_count,
        log_blowup,
    )?;
    validate_inputs(
        &program,
        execution,
        main,
        logup,
        &layouts.program_binary_commitment,
    )?;
    let directory = scratch_parent.join(directory_name(build_nonce));
    create_owned_directory(&directory, &layouts.program_binary_commitment)?;
    let owned_directory = OwnedCompositionDirectory {
        path: directory.clone(),
        program_commitment: layouts.program_binary_commitment,
    };

    let ordinary_terms = count_ordinary_terms(&program)?;
    let mut next_global_coefficient = Fp16::ONE;
    let mut table_numerators = Vec::with_capacity(program.tables.len());
    for (table_index, table) in program.tables.iter().enumerate() {
        let main_table = &main.tables[table_index];
        let numerator = directory.join(format!("numerator-t{table_index:08x}.fp16"));
        initialize_zero_fp16_file(&numerator, 1_usize << main_table.composition_work_log_size)?;
        add_identity_terms(
            table,
            main_table,
            &numerator,
            composition_alpha,
            &mut next_global_coefficient,
            &directory,
            build_nonce,
            table_index,
        )?;
        // Fixed columns are verifier-reconstructed. Their old equality term is
        // identically zero, but it remains in the frozen alpha schedule.
        for _ in &table.fixed_columns {
            next_global_coefficient = next_global_coefficient.mul(composition_alpha);
        }
        add_public_terms(
            &program,
            execution,
            table_index,
            main_table,
            &numerator,
            composition_alpha,
            &mut next_global_coefficient,
            &directory,
        )?;
        table_numerators.push(numerator);
    }

    let expected_after_ordinary = alpha_power(composition_alpha, ordinary_terms);
    if next_global_coefficient != expected_after_ordinary {
        return Err(DiskCompositionError::Shape);
    }
    let logup_term_count = add_logup_terms(
        &LogupTermContext {
            program: &program,
            main,
            logup,
            beta,
            gamma,
            alpha: composition_alpha,
            numerators: &table_numerators,
            directory: &directory,
            build_nonce,
        },
        &mut next_global_coefficient,
    )?;

    let mut tables = Vec::with_capacity(program.tables.len());
    let mut grouped = BTreeMap::<u8, Vec<PathBuf>>::new();
    for (table_index, numerator) in table_numerators.iter().enumerate() {
        let main_table = &main.tables[table_index];
        divide_by_vanishing(
            numerator,
            main_table.trace_log_size,
            main_table.composition_work_log_size,
        )?;
        let (components, coefficient_count) = split_and_mask_quotient(
            numerator,
            table_index,
            &layouts.program_binary_commitment,
            main_table.evaluation_log_size,
            main_table.composition_work_log_size,
            main_table.component_coefficient_log_size,
            main_table.composition_component_count,
            secret_mask_seed,
            session_id,
            quotient_mask_coefficient_count,
            &directory,
        )?;
        let _ = fs::remove_file(numerator);
        grouped
            .entry(main_table.evaluation_log_size)
            .or_default()
            .extend(components.iter().cloned());
        tables.push(DiskTableCompositionOracle {
            table_index,
            logical_rows: main_table.logical_rows,
            trace_rows: main_table.trace_rows,
            trace_log_size: main_table.trace_log_size,
            evaluation_log_size: main_table.evaluation_log_size,
            composition_work_log_size: main_table.composition_work_log_size,
            component_coefficient_log_size: main_table.component_coefficient_log_size,
            component_files: components,
            composition_coefficient_count: coefficient_count,
        });
    }
    let mut batches = Vec::with_capacity(layouts.composition.specs().len());
    for spec in layouts.composition.specs() {
        let files = grouped
            .get(&spec.log_size)
            .ok_or(DiskCompositionError::Shape)?;
        if files.len() != spec.column_count as usize {
            return Err(DiskCompositionError::Shape);
        }
        batches.push(DiskDomainEvaluationBatch::new_from_columns(
            *spec,
            files.clone(),
        )?);
    }
    let tree = DiskCrossDomainTree::build(
        layouts.composition,
        batches,
        scratch_parent,
        &derive_nonce(build_nonce, b"tree", 0, 0)?,
    )?;
    Ok(DiskAirCompositionOracle {
        source_program_commitment: program.source_program_commitment,
        program_binary_commitment: layouts.program_binary_commitment,
        tables,
        identity_term_count: program
            .tables
            .iter()
            .try_fold(0_u64, |count, table| {
                count.checked_add(table.identities.len() as u64)
            })
            .ok_or(DiskCompositionError::Overflow)?,
        fixed_term_count: program
            .tables
            .iter()
            .try_fold(0_u64, |count, table| {
                count.checked_add(table.fixed_columns.len() as u64)
            })
            .ok_or(DiskCompositionError::Overflow)?,
        public_term_count: u64::try_from(program.public_inputs.len())
            .map_err(|_| DiskCompositionError::Overflow)?,
        logup_term_count,
        tree,
        owned_directory,
    })
}

fn validate_inputs(
    program: &ParsedProgram,
    execution: &StreamingScratchExecution,
    main: &DiskAirMainTraceOracle,
    logup: &DiskAirLogupOracle,
    program_binary_commitment: &[u8; 64],
) -> Result<(), DiskCompositionError> {
    if execution.manifest().program_binary_commitment != *program_binary_commitment
        || main.program_binary_commitment != *program_binary_commitment
        || main.source_program_commitment != program.source_program_commitment
        || main.tables.len() != program.tables.len()
        || logup.lookup_count as usize != program.lookups.len()
        || execution.manifest().public_inputs.len() != program.public_inputs.len()
    {
        return Err(DiskCompositionError::ProgramMismatch);
    }
    for (table_index, (table, disk)) in program.tables.iter().zip(&main.tables).enumerate() {
        if disk.table_index != table_index
            || disk.logical_rows != table.rows
            || disk.column_files.len() != disk.committed_column_indices.len()
        {
            return Err(DiskCompositionError::Shape);
        }
    }
    Ok(())
}

fn count_ordinary_terms(program: &ParsedProgram) -> Result<u64, DiskCompositionError> {
    let identities = program.tables.iter().try_fold(0_u64, |count, table| {
        count.checked_add(table.identities.len() as u64)
    });
    let fixed = program.tables.iter().try_fold(0_u64, |count, table| {
        count.checked_add(table.fixed_columns.len() as u64)
    });
    identities
        .and_then(|value| fixed.and_then(|fixed| value.checked_add(fixed)))
        .and_then(|value| value.checked_add(program.public_inputs.len() as u64))
        .ok_or(DiskCompositionError::Overflow)
}

fn identity_batches(
    identities: &[Identity],
    evaluation_count: usize,
) -> Result<Vec<IdentityBatch>, DiskCompositionError> {
    let bytes_per_column = u64::try_from(evaluation_count)
        .ok()
        .and_then(|rows| rows.checked_mul(4))
        .ok_or(DiskCompositionError::Overflow)?;
    if bytes_per_column > WORK_COLUMN_SCRATCH_CAP_BYTES {
        return Err(DiskCompositionError::Shape);
    }
    let max_files = usize::try_from(WORK_COLUMN_SCRATCH_CAP_BYTES / bytes_per_column)
        .map_err(|_| DiskCompositionError::Overflow)?
        .max(1);
    let mut batches = Vec::new();
    let mut start = 0usize;
    while start < identities.len() {
        let mut current_columns = BTreeSet::new();
        let mut next_columns = BTreeSet::new();
        let mut selector_ranges = BTreeSet::new();
        let mut stop = start;
        while stop < identities.len() {
            let identity = &identities[stop];
            let mut candidate_current = current_columns.clone();
            let mut candidate_next = next_columns.clone();
            identity
                .expression
                .collect_columns_by_shift(&mut candidate_current, &mut candidate_next);
            let mut candidate_ranges = selector_ranges.clone();
            candidate_ranges.insert((identity.row_start, identity.row_stop));
            let file_count = candidate_current
                .len()
                .checked_add(candidate_next.len())
                .and_then(|count| count.checked_add(candidate_ranges.len()))
                .ok_or(DiskCompositionError::Overflow)?;
            if file_count > max_files && stop != start {
                break;
            }
            if file_count > max_files {
                return Err(DiskCompositionError::Shape);
            }
            current_columns = candidate_current;
            next_columns = candidate_next;
            selector_ranges = candidate_ranges;
            stop += 1;
        }
        batches.push((start..stop, current_columns, next_columns, selector_ranges));
        start = stop;
    }
    Ok(batches)
}

#[allow(clippy::too_many_arguments)]
fn add_identity_terms(
    table: &crate::air_ir::Table,
    main: &crate::disk_air::DiskTableMainTraceOracle,
    numerator_path: &Path,
    alpha: Fp16,
    next_coefficient: &mut Fp16,
    directory: &Path,
    build_nonce: &[u8; 32],
    table_index: usize,
) -> Result<(), DiskCompositionError> {
    let evaluations = 1_usize << main.composition_work_log_size;
    let batches = identity_batches(&table.identities, evaluations)?;
    let coefficients = table
        .identities
        .iter()
        .map(|_| {
            let coefficient = *next_coefficient;
            *next_coefficient = next_coefficient.mul(alpha);
            coefficient
        })
        .collect::<Vec<_>>();
    for (batch_index, (range, current_columns, next_columns, selector_ranges)) in
        batches.into_iter().enumerate()
    {
        let mut owned_paths = Vec::new();
        let current_files = materialize_work_columns(
            table,
            main,
            &current_columns,
            directory,
            table_index,
            batch_index,
            "current",
            &mut owned_paths,
        )?;
        let next_sources = materialize_work_columns(
            table,
            main,
            &next_columns,
            directory,
            table_index,
            batch_index,
            "next-source",
            &mut owned_paths,
        )?;
        let mut next_files = BTreeMap::new();
        for (column, source) in next_sources {
            let path = directory.join(format!(
                "work-next-t{table_index:08x}-b{batch_index:08x}-c{column:08x}.m31"
            ));
            build_shifted_m31_file(
                &source,
                &path,
                main.composition_work_log_size,
                main.trace_log_size,
                directory,
                &derive_nonce(build_nonce, b"work-next", batch_index, column)?,
            )?;
            owned_paths.push(path.clone());
            next_files.insert(column, path);
        }
        let selector_files = materialize_selector_files(
            main,
            &selector_ranges,
            directory,
            table_index,
            batch_index,
            &mut owned_paths,
        )?;
        update_numerator_from_work_files(
            numerator_path,
            evaluations,
            table,
            &table.identities,
            range,
            &coefficients,
            &current_files,
            &next_files,
            &selector_files,
        )?;
        for path in owned_paths {
            let _ = fs::remove_file(path);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn materialize_work_columns(
    table: &crate::air_ir::Table,
    main: &crate::disk_air::DiskTableMainTraceOracle,
    requested: &BTreeSet<usize>,
    directory: &Path,
    table_index: usize,
    batch_index: usize,
    label: &str,
    owned_paths: &mut Vec<PathBuf>,
) -> Result<BTreeMap<usize, PathBuf>, DiskCompositionError> {
    let mut result = BTreeMap::new();
    for column in requested {
        if *column >= table.columns.len() {
            return Err(DiskCompositionError::Shape);
        }
        let source = if table.fixed_columns.iter().any(|(fixed, _)| fixed == column) {
            let mut singleton = BTreeSet::new();
            singleton.insert(*column);
            let values = load_columns(table, main, &singleton)?
                .remove(column)
                .ok_or(DiskCompositionError::Shape)?;
            let path = directory.join(format!(
                "work-{label}-base-t{table_index:08x}-b{batch_index:08x}-c{column:08x}.m31"
            ));
            write_m31_file(&path, &values)?;
            owned_paths.push(path.clone());
            path
        } else {
            let position = main
                .committed_column_indices
                .iter()
                .position(|candidate| candidate == column)
                .ok_or(DiskCompositionError::Shape)?;
            main.column_files[position].clone()
        };
        if main.composition_work_log_size == main.evaluation_log_size {
            result.insert(*column, source);
        } else if main.composition_work_log_size > main.evaluation_log_size {
            let path = directory.join(format!(
                "work-{label}-t{table_index:08x}-b{batch_index:08x}-c{column:08x}.m31"
            ));
            extend_base_circle_evaluation_file(
                &source,
                main.evaluation_log_size,
                main.composition_work_log_size,
                &path,
            )?;
            owned_paths.push(path.clone());
            result.insert(*column, path);
        } else {
            return Err(DiskCompositionError::Shape);
        }
    }
    Ok(result)
}

fn materialize_selector_files(
    main: &crate::disk_air::DiskTableMainTraceOracle,
    ranges: &BTreeSet<(usize, usize)>,
    directory: &Path,
    table_index: usize,
    batch_index: usize,
    owned_paths: &mut Vec<PathBuf>,
) -> Result<BTreeMap<(usize, usize), PathBuf>, DiskCompositionError> {
    let mut result = BTreeMap::new();
    for (range_index, (row_start, row_stop)) in ranges.iter().copied().enumerate() {
        let values = selector_evaluations(
            main.trace_rows,
            row_start,
            row_stop,
            main.evaluation_log_size,
        )?;
        let source = directory.join(format!(
            "selector-base-t{table_index:08x}-b{batch_index:08x}-r{range_index:08x}.m31"
        ));
        write_m31_file(&source, &values)?;
        owned_paths.push(source.clone());
        let path = if main.composition_work_log_size == main.evaluation_log_size {
            source
        } else if main.composition_work_log_size > main.evaluation_log_size {
            let work = directory.join(format!(
                "selector-work-t{table_index:08x}-b{batch_index:08x}-r{range_index:08x}.m31"
            ));
            extend_base_circle_evaluation_file(
                &source,
                main.evaluation_log_size,
                main.composition_work_log_size,
                &work,
            )?;
            owned_paths.push(work.clone());
            work
        } else {
            return Err(DiskCompositionError::Shape);
        };
        result.insert((row_start, row_stop), path);
    }
    Ok(result)
}

fn write_m31_file(path: &Path, values: &[M31]) -> Result<(), DiskCompositionError> {
    let mut output = BufWriter::new(OpenOptions::new().write(true).create_new(true).open(path)?);
    for value in values {
        output.write_all(&value.as_u32().to_be_bytes())?;
    }
    output.flush()?;
    output.get_ref().sync_data()?;
    Ok(())
}

fn read_m31_block(input: &mut impl Read, count: usize) -> Result<Vec<M31>, DiskCompositionError> {
    let mut encoded = vec![0_u8; count * 4];
    input.read_exact(&mut encoded)?;
    encoded
        .chunks_exact(4)
        .map(|word| {
            let raw = u32::from_be_bytes(word.try_into().map_err(|_| DiskCompositionError::Shape)?);
            if raw >= M31_MODULUS {
                return Err(DiskCompositionError::Shape);
            }
            M31::from_canonical(raw).map_err(DiskCompositionError::Field)
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn update_numerator_from_work_files(
    numerator_path: &Path,
    rows: usize,
    table: &crate::air_ir::Table,
    identities: &[Identity],
    range: core::ops::Range<usize>,
    coefficients: &[Fp16],
    current_files: &BTreeMap<usize, PathBuf>,
    next_files: &BTreeMap<usize, PathBuf>,
    selector_files: &BTreeMap<(usize, usize), PathBuf>,
) -> Result<(), DiskCompositionError> {
    let mut current_readers = current_files
        .iter()
        .map(|(column, path)| Ok((*column, BufReader::new(File::open(path)?))))
        .collect::<Result<Vec<_>, std::io::Error>>()?;
    let mut next_readers = next_files
        .iter()
        .map(|(column, path)| Ok((*column, BufReader::new(File::open(path)?))))
        .collect::<Result<Vec<_>, std::io::Error>>()?;
    let mut selector_readers = selector_files
        .iter()
        .map(|(key, path)| Ok((*key, BufReader::new(File::open(path)?))))
        .collect::<Result<Vec<_>, std::io::Error>>()?;
    let mut numerator = OpenOptions::new()
        .read(true)
        .write(true)
        .open(numerator_path)?;
    let mut current = vec![Fp16::ZERO; table.columns.len()];
    let mut next = vec![Fp16::ZERO; table.columns.len()];
    for start in (0..rows).step_by(UPDATE_BLOCK_ROWS) {
        let count = UPDATE_BLOCK_ROWS.min(rows - start);
        let current_blocks = current_readers
            .iter_mut()
            .map(|(column, reader)| Ok((*column, read_m31_block(reader, count)?)))
            .collect::<Result<BTreeMap<_, _>, DiskCompositionError>>()?;
        let next_blocks = next_readers
            .iter_mut()
            .map(|(column, reader)| Ok((*column, read_m31_block(reader, count)?)))
            .collect::<Result<BTreeMap<_, _>, DiskCompositionError>>()?;
        let selector_blocks = selector_readers
            .iter_mut()
            .map(|(key, reader)| Ok((*key, read_m31_block(reader, count)?)))
            .collect::<Result<BTreeMap<_, _>, DiskCompositionError>>()?;
        let byte_count = count * FP16_ENCODED_LENGTH;
        let mut encoded = vec![0_u8; byte_count];
        numerator.read_exact(&mut encoded)?;
        for offset in 0..count {
            for (column, values) in &current_blocks {
                current[*column] = Fp16::from_m31(values[offset]);
            }
            for (column, values) in &next_blocks {
                next[*column] = Fp16::from_m31(values[offset]);
            }
            let mut term = Fp16::ZERO;
            for identity_index in range.clone() {
                let identity = &identities[identity_index];
                let selector = selector_blocks
                    .get(&(identity.row_start, identity.row_stop))
                    .ok_or(DiskCompositionError::Shape)?[offset];
                term = term.add(
                    coefficients[identity_index].mul(
                        Fp16::from_m31(selector)
                            .mul(identity.expression.evaluate_extension(&current, &next)?),
                    ),
                );
            }
            let byte = offset * FP16_ENCODED_LENGTH;
            let value = Fp16::decode(&encoded[byte..byte + FP16_ENCODED_LENGTH])?.add(term);
            encoded[byte..byte + FP16_ENCODED_LENGTH].copy_from_slice(&value.encode());
        }
        numerator.seek(SeekFrom::Current(
            -i64::try_from(byte_count).map_err(|_| DiskCompositionError::Overflow)?,
        ))?;
        numerator.write_all(&encoded)?;
    }
    numerator.sync_data()?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn add_public_terms(
    program: &ParsedProgram,
    execution: &StreamingScratchExecution,
    table_index: usize,
    main: &crate::disk_air::DiskTableMainTraceOracle,
    numerator_path: &Path,
    alpha: Fp16,
    next_coefficient: &mut Fp16,
    directory: &Path,
) -> Result<(), DiskCompositionError> {
    let table = &program.tables[table_index];
    for (input_index, binding) in program.public_inputs.iter().enumerate() {
        if binding.table != table_index {
            continue;
        }
        let coefficient = *next_coefficient;
        *next_coefficient = next_coefficient.mul(alpha);
        let mut requested = BTreeSet::new();
        requested.insert(binding.column);
        let mut owned_paths = Vec::new();
        let columns = materialize_work_columns(
            table,
            main,
            &requested,
            directory,
            table_index,
            input_index,
            "public",
            &mut owned_paths,
        )?;
        let mut ranges = BTreeSet::new();
        ranges.insert((binding.row, binding.row + 1));
        let selectors = materialize_selector_files(
            main,
            &ranges,
            directory,
            table_index,
            input_index,
            &mut owned_paths,
        )?;
        let supplied = execution.manifest().public_inputs[input_index];
        update_public_term_from_work_files(
            numerator_path,
            1_usize << main.composition_work_log_size,
            columns
                .get(&binding.column)
                .ok_or(DiskCompositionError::Shape)?,
            selectors
                .get(&(binding.row, binding.row + 1))
                .ok_or(DiskCompositionError::Shape)?,
            coefficient,
            supplied,
        )?;
        for path in owned_paths {
            let _ = fs::remove_file(path);
        }
    }
    Ok(())
}

fn update_public_term_from_work_files(
    numerator_path: &Path,
    rows: usize,
    values_path: &Path,
    selector_path: &Path,
    coefficient: Fp16,
    supplied: M31,
) -> Result<(), DiskCompositionError> {
    let mut values = BufReader::new(File::open(values_path)?);
    let mut selectors = BufReader::new(File::open(selector_path)?);
    let mut numerator = OpenOptions::new()
        .read(true)
        .write(true)
        .open(numerator_path)?;
    for start in (0..rows).step_by(UPDATE_BLOCK_ROWS) {
        let count = UPDATE_BLOCK_ROWS.min(rows - start);
        let value_block = read_m31_block(&mut values, count)?;
        let selector_block = read_m31_block(&mut selectors, count)?;
        let byte_count = count * FP16_ENCODED_LENGTH;
        let mut encoded = vec![0_u8; byte_count];
        numerator.read_exact(&mut encoded)?;
        for offset in 0..count {
            let term = coefficient.mul(
                Fp16::from_m31(selector_block[offset])
                    .mul(Fp16::from_m31(value_block[offset]).sub(Fp16::from_m31(supplied))),
            );
            let byte = offset * FP16_ENCODED_LENGTH;
            let value = Fp16::decode(&encoded[byte..byte + FP16_ENCODED_LENGTH])?.add(term);
            encoded[byte..byte + FP16_ENCODED_LENGTH].copy_from_slice(&value.encode());
        }
        numerator.seek(SeekFrom::Current(
            -i64::try_from(byte_count).map_err(|_| DiskCompositionError::Overflow)?,
        ))?;
        numerator.write_all(&encoded)?;
    }
    numerator.sync_data()?;
    Ok(())
}

fn add_logup_terms(
    context: &LogupTermContext<'_>,
    next_coefficient: &mut Fp16,
) -> Result<u64, DiskCompositionError> {
    let mut added = 0_u64;
    for interaction in &context.logup.interactions {
        let table = &context.program.tables[interaction.table_index];
        let main_table = &context.main.tables[interaction.table_index];
        let lookup = &context.program.lookups[interaction.lookup_index];
        let sides = lookup
            .sources
            .iter()
            .filter(|side| side.table == interaction.table_index)
            .map(|side| (1_i8, side))
            .chain(
                lookup
                    .destinations
                    .iter()
                    .filter(|side| side.table == interaction.table_index)
                    .map(|side| (-1_i8, side)),
            )
            .collect::<Vec<_>>();
        if sides.len() + 1 != interaction.masked_column_files.len()
            || interaction.side_signs != sides.iter().map(|(sign, _)| *sign).collect::<Vec<_>>()
            || interaction.evaluation_log_size != main_table.evaluation_log_size
        {
            return Err(DiskCompositionError::Shape);
        }
        let evaluations = 1_usize << main_table.composition_work_log_size;
        let contribution_path = context.directory.join(format!(
            "contribution-l{:08x}-t{:08x}.fp16",
            interaction.lookup_index, interaction.table_index
        ));
        initialize_zero_fp16_file(&contribution_path, evaluations)?;
        for (side_index, (sign, side)) in sides.iter().enumerate() {
            let coefficient = *next_coefficient;
            *next_coefficient = next_coefficient.mul(context.alpha);
            added = added.checked_add(1).ok_or(DiskCompositionError::Overflow)?;
            let mut referenced = BTreeSet::new();
            side.selector.collect_columns(&mut referenced);
            side.weight.collect_columns(&mut referenced);
            for expression in &side.values {
                expression.collect_columns(&mut referenced);
            }
            let mut shifted = BTreeSet::new();
            let mut current_only = BTreeSet::new();
            side.selector
                .collect_columns_by_shift(&mut current_only, &mut shifted);
            side.weight
                .collect_columns_by_shift(&mut current_only, &mut shifted);
            for expression in &side.values {
                expression.collect_columns_by_shift(&mut current_only, &mut shifted);
            }
            if !shifted.is_empty() || current_only != referenced {
                return Err(DiskCompositionError::Shape);
            }
            let mut owned_paths = Vec::new();
            let columns = materialize_work_columns(
                table,
                main_table,
                &referenced,
                context.directory,
                interaction.table_index,
                side_index,
                "logup",
                &mut owned_paths,
            )?;
            let mut ranges = BTreeSet::new();
            ranges.insert((side.row_start, side.row_stop));
            let selectors = materialize_selector_files(
                main_table,
                &ranges,
                context.directory,
                interaction.table_index,
                side_index,
                &mut owned_paths,
            )?;
            let inverse_source = &interaction.masked_column_files[side_index];
            let (inverse_path, inverse_owned) = materialize_extension_work_file(
                inverse_source,
                main_table,
                context.directory,
                &format!(
                    "inverse-l{:08x}-t{:08x}-s{side_index:08x}.fp16",
                    interaction.lookup_index, interaction.table_index
                ),
            )?;
            if inverse_owned {
                owned_paths.push(inverse_path.clone());
            }
            update_logup_side_from_work_files(
                &context.numerators[interaction.table_index],
                &contribution_path,
                &inverse_path,
                evaluations,
                table,
                side,
                &columns,
                selectors
                    .get(&(side.row_start, side.row_stop))
                    .ok_or(DiskCompositionError::Shape)?,
                context.beta,
                context.gamma,
                coefficient,
                *sign,
            )?;
            for path in owned_paths {
                let _ = fs::remove_file(path);
            }
        }
        let transition_coefficient = *next_coefficient;
        *next_coefficient = next_coefficient.mul(context.alpha);
        let first_coefficient = *next_coefficient;
        *next_coefficient = next_coefficient.mul(context.alpha);
        let last_coefficient = *next_coefficient;
        *next_coefficient = next_coefficient.mul(context.alpha);
        added = added.checked_add(3).ok_or(DiskCompositionError::Overflow)?;
        let accumulator_source = interaction
            .masked_column_files
            .last()
            .ok_or(DiskCompositionError::Shape)?;
        let (accumulator_path, accumulator_owned) = materialize_extension_work_file(
            accumulator_source,
            main_table,
            context.directory,
            &format!(
                "accumulator-l{:08x}-t{:08x}.fp16",
                interaction.lookup_index, interaction.table_index
            ),
        )?;
        let shifted_path = context.directory.join(format!(
            "shifted-l{:08x}-t{:08x}.fp16",
            interaction.lookup_index, interaction.table_index
        ));
        build_shifted_fp16_file(
            &accumulator_path,
            &shifted_path,
            main_table.composition_work_log_size,
            main_table.trace_log_size,
            context.directory,
            &derive_nonce(
                context.build_nonce,
                b"shift",
                interaction.lookup_index,
                interaction.table_index,
            )?,
        )?;
        let mut selector_ranges = BTreeSet::new();
        selector_ranges.insert((0, main_table.trace_rows - 1));
        selector_ranges.insert((0, 1));
        selector_ranges.insert((main_table.trace_rows - 1, main_table.trace_rows));
        let mut selector_owned = Vec::new();
        let selector_files = materialize_selector_files(
            main_table,
            &selector_ranges,
            context.directory,
            interaction.table_index,
            usize::MAX - interaction.lookup_index,
            &mut selector_owned,
        )?;
        update_logup_accumulator_from_work_files(
            &context.numerators[interaction.table_index],
            &accumulator_path,
            &shifted_path,
            &contribution_path,
            selector_files
                .get(&(0, main_table.trace_rows - 1))
                .ok_or(DiskCompositionError::Shape)?,
            selector_files
                .get(&(0, 1))
                .ok_or(DiskCompositionError::Shape)?,
            selector_files
                .get(&(main_table.trace_rows - 1, main_table.trace_rows))
                .ok_or(DiskCompositionError::Shape)?,
            evaluations,
            transition_coefficient,
            first_coefficient,
            last_coefficient,
            interaction.final_sum,
        )?;
        for path in selector_owned {
            let _ = fs::remove_file(path);
        }
        if accumulator_owned {
            let _ = fs::remove_file(accumulator_path);
        }
        let _ = fs::remove_file(shifted_path);
        let _ = fs::remove_file(contribution_path);
    }
    Ok(added)
}

fn materialize_extension_work_file(
    source: &Path,
    main: &crate::disk_air::DiskTableMainTraceOracle,
    directory: &Path,
    name: &str,
) -> Result<(PathBuf, bool), DiskCompositionError> {
    if main.composition_work_log_size == main.evaluation_log_size {
        return Ok((source.to_path_buf(), false));
    }
    if main.composition_work_log_size < main.evaluation_log_size {
        return Err(DiskCompositionError::Shape);
    }
    let path = directory.join(name);
    extend_extension_circle_evaluation_file(
        source,
        main.evaluation_log_size,
        main.composition_work_log_size,
        &path,
    )?;
    Ok((path, true))
}

fn read_fp16_block(input: &mut impl Read, count: usize) -> Result<Vec<Fp16>, DiskCompositionError> {
    let mut encoded = vec![0_u8; count * FP16_ENCODED_LENGTH];
    input.read_exact(&mut encoded)?;
    encoded
        .chunks_exact(FP16_ENCODED_LENGTH)
        .map(Fp16::decode)
        .collect::<Result<Vec<_>, _>>()
        .map_err(DiskCompositionError::Decode)
}

#[allow(clippy::too_many_arguments)]
fn update_logup_side_from_work_files(
    numerator_path: &Path,
    contribution_path: &Path,
    inverse_path: &Path,
    rows: usize,
    table: &crate::air_ir::Table,
    side: &crate::air_ir::LookupSide,
    column_files: &BTreeMap<usize, PathBuf>,
    range_selector_path: &Path,
    beta: Fp16,
    gamma: Fp16,
    coefficient: Fp16,
    sign: i8,
) -> Result<(), DiskCompositionError> {
    let mut column_readers = column_files
        .iter()
        .map(|(column, path)| Ok((*column, BufReader::new(File::open(path)?))))
        .collect::<Result<Vec<_>, std::io::Error>>()?;
    let mut range_reader = BufReader::new(File::open(range_selector_path)?);
    let mut inverse_reader = BufReader::new(File::open(inverse_path)?);
    let mut numerator = OpenOptions::new()
        .read(true)
        .write(true)
        .open(numerator_path)?;
    let mut contribution = OpenOptions::new()
        .read(true)
        .write(true)
        .open(contribution_path)?;
    let mut current = vec![Fp16::ZERO; table.columns.len()];
    for start in (0..rows).step_by(UPDATE_BLOCK_ROWS) {
        let count = UPDATE_BLOCK_ROWS.min(rows - start);
        let column_blocks = column_readers
            .iter_mut()
            .map(|(column, reader)| Ok((*column, read_m31_block(reader, count)?)))
            .collect::<Result<BTreeMap<_, _>, DiskCompositionError>>()?;
        let range_block = read_m31_block(&mut range_reader, count)?;
        let inverse_block = read_fp16_block(&mut inverse_reader, count)?;
        let byte_count = count * FP16_ENCODED_LENGTH;
        let mut numerator_encoded = vec![0_u8; byte_count];
        let mut contribution_encoded = vec![0_u8; byte_count];
        numerator.read_exact(&mut numerator_encoded)?;
        contribution.read_exact(&mut contribution_encoded)?;
        for offset in 0..count {
            for (column, values) in &column_blocks {
                current[*column] = Fp16::from_m31(values[offset]);
            }
            let selector = side.selector.evaluate_extension(&current, &current)?;
            let mut denominator = gamma;
            let mut power = beta;
            for expression in &side.values {
                denominator =
                    denominator.add(power.mul(expression.evaluate_extension(&current, &current)?));
                power = power.mul(beta);
            }
            let range_value = Fp16::from_m31(range_block[offset]);
            let inverse = inverse_block[offset];
            let inverse_term =
                coefficient.mul(range_value.mul(denominator.mul(inverse).sub(selector)));
            let weight = side.weight.evaluate_extension(&current, &current)?;
            let contribution_term = range_value.mul(weight).mul(inverse);
            let contribution_term = if sign > 0 {
                contribution_term
            } else {
                contribution_term.neg()
            };
            let byte = offset * FP16_ENCODED_LENGTH;
            let numerator_value =
                Fp16::decode(&numerator_encoded[byte..byte + FP16_ENCODED_LENGTH])?
                    .add(inverse_term);
            numerator_encoded[byte..byte + FP16_ENCODED_LENGTH]
                .copy_from_slice(&numerator_value.encode());
            let contribution_value =
                Fp16::decode(&contribution_encoded[byte..byte + FP16_ENCODED_LENGTH])?
                    .add(contribution_term);
            contribution_encoded[byte..byte + FP16_ENCODED_LENGTH]
                .copy_from_slice(&contribution_value.encode());
        }
        let rewind = -i64::try_from(byte_count).map_err(|_| DiskCompositionError::Overflow)?;
        numerator.seek(SeekFrom::Current(rewind))?;
        contribution.seek(SeekFrom::Current(rewind))?;
        numerator.write_all(&numerator_encoded)?;
        contribution.write_all(&contribution_encoded)?;
    }
    numerator.sync_data()?;
    contribution.sync_data()?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn update_logup_accumulator_from_work_files(
    numerator_path: &Path,
    accumulator_path: &Path,
    shifted_path: &Path,
    contribution_path: &Path,
    transition_selector_path: &Path,
    first_selector_path: &Path,
    last_selector_path: &Path,
    rows: usize,
    transition_coefficient: Fp16,
    first_coefficient: Fp16,
    last_coefficient: Fp16,
    final_sum: Fp16,
) -> Result<(), DiskCompositionError> {
    let mut numerator = OpenOptions::new()
        .read(true)
        .write(true)
        .open(numerator_path)?;
    let mut accumulator = BufReader::new(File::open(accumulator_path)?);
    let mut shifted = BufReader::new(File::open(shifted_path)?);
    let mut contribution = BufReader::new(File::open(contribution_path)?);
    let mut transition_selector = BufReader::new(File::open(transition_selector_path)?);
    let mut first_selector = BufReader::new(File::open(first_selector_path)?);
    let mut last_selector = BufReader::new(File::open(last_selector_path)?);
    for start in (0..rows).step_by(UPDATE_BLOCK_ROWS) {
        let count = UPDATE_BLOCK_ROWS.min(rows - start);
        let accumulator_block = read_fp16_block(&mut accumulator, count)?;
        let shifted_block = read_fp16_block(&mut shifted, count)?;
        let contribution_block = read_fp16_block(&mut contribution, count)?;
        let transition_block = read_m31_block(&mut transition_selector, count)?;
        let first_block = read_m31_block(&mut first_selector, count)?;
        let last_block = read_m31_block(&mut last_selector, count)?;
        let byte_count = count * FP16_ENCODED_LENGTH;
        let mut encoded = vec![0_u8; byte_count];
        numerator.read_exact(&mut encoded)?;
        for offset in 0..count {
            let accumulator_value = accumulator_block[offset];
            let transition = Fp16::from_m31(transition_block[offset]).mul(
                shifted_block[offset]
                    .sub(accumulator_value)
                    .sub(contribution_block[offset]),
            );
            let first = Fp16::from_m31(first_block[offset]).mul(accumulator_value);
            let last = Fp16::from_m31(last_block[offset]).mul(accumulator_value.sub(final_sum));
            let term = transition_coefficient
                .mul(transition)
                .add(first_coefficient.mul(first))
                .add(last_coefficient.mul(last));
            let byte = offset * FP16_ENCODED_LENGTH;
            let value = Fp16::decode(&encoded[byte..byte + FP16_ENCODED_LENGTH])?.add(term);
            encoded[byte..byte + FP16_ENCODED_LENGTH].copy_from_slice(&value.encode());
        }
        numerator.seek(SeekFrom::Current(
            -i64::try_from(byte_count).map_err(|_| DiskCompositionError::Overflow)?,
        ))?;
        numerator.write_all(&encoded)?;
    }
    numerator.sync_data()?;
    Ok(())
}

fn load_columns(
    table: &crate::air_ir::Table,
    main: &crate::disk_air::DiskTableMainTraceOracle,
    requested: &BTreeSet<usize>,
) -> Result<BTreeMap<usize, Vec<M31>>, DiskCompositionError> {
    let evaluations = 1_usize << main.evaluation_log_size;
    let mut result = BTreeMap::new();
    for column in requested {
        if *column >= table.columns.len() {
            return Err(DiskCompositionError::Shape);
        }
        if let Some((_, natural)) = table
            .fixed_columns
            .iter()
            .find(|(fixed, _)| fixed == column)
        {
            let mut padded = natural.materialize();
            padded.resize(main.trace_rows, M31::ZERO);
            result.insert(
                *column,
                crate::circle_fft::low_degree_extend_coset_order(
                    &padded,
                    main.evaluation_log_size - main.trace_log_size,
                )?,
            );
        } else {
            let position = main
                .committed_column_indices
                .iter()
                .position(|candidate| candidate == column)
                .ok_or(DiskCompositionError::Shape)?;
            result.insert(
                *column,
                read_m31_file(&main.column_files[position], evaluations)?,
            );
        }
    }
    Ok(result)
}

fn read_m31_file(path: &Path, count: usize) -> Result<Vec<M31>, DiskCompositionError> {
    let expected = u64::try_from(count)
        .ok()
        .and_then(|value| value.checked_mul(4))
        .ok_or(DiskCompositionError::Overflow)?;
    if fs::metadata(path)?.len() != expected {
        return Err(DiskCompositionError::Shape);
    }
    let mut reader = BufReader::new(File::open(path)?);
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let mut encoded = [0_u8; 4];
        reader.read_exact(&mut encoded)?;
        let value = u32::from_be_bytes(encoded);
        if value >= M31_MODULUS {
            return Err(DiskCompositionError::Shape);
        }
        values.push(M31::from_canonical(value)?);
    }
    Ok(values)
}

fn validate_fp16_file(path: &Path, rows: usize) -> Result<(), DiskCompositionError> {
    let bytes = u64::try_from(rows)
        .ok()
        .and_then(|value| value.checked_mul(FP16_ENCODED_LENGTH as u64))
        .ok_or(DiskCompositionError::Overflow)?;
    if !path.is_absolute() || fs::metadata(path)?.len() != bytes {
        return Err(DiskCompositionError::Shape);
    }
    Ok(())
}

fn divide_by_vanishing(
    path: &Path,
    trace_log_size: u8,
    evaluation_log_size: u8,
) -> Result<(), DiskCompositionError> {
    let zeroifiers = canonical_coset_zeroifier_evaluations(trace_log_size, evaluation_log_size)?;
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    for block in zeroifiers.chunks(UPDATE_BLOCK_ROWS) {
        let mut encoded = vec![0_u8; block.len() * FP16_ENCODED_LENGTH];
        file.read_exact(&mut encoded)?;
        for (offset, denominator) in block.iter().enumerate() {
            if denominator.is_zero() {
                return Err(DiskCompositionError::Shape);
            }
            let byte = offset * FP16_ENCODED_LENGTH;
            let value = Fp16::decode(&encoded[byte..byte + FP16_ENCODED_LENGTH])?
                .mul(Fp16::from_m31(denominator.inverse()?));
            encoded[byte..byte + FP16_ENCODED_LENGTH].copy_from_slice(&value.encode());
        }
        file.seek(SeekFrom::Current(
            -i64::try_from(encoded.len()).map_err(|_| DiskCompositionError::Overflow)?,
        ))?;
        file.write_all(&encoded)?;
    }
    file.sync_data()?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn split_and_mask_quotient(
    quotient_path: &Path,
    table_index: usize,
    program_commitment: &[u8; 64],
    committed_evaluation_log_size: u8,
    composition_work_log_size: u8,
    component_coefficient_log_size: u8,
    component_count: usize,
    secret_mask_seed: &[u8],
    session_id: &[u8],
    mask_coefficient_count: usize,
    directory: &Path,
) -> Result<(Vec<PathBuf>, usize), DiskCompositionError> {
    if component_count < 2
        || !component_count.is_power_of_two()
        || committed_evaluation_log_size < component_coefficient_log_size
        || composition_work_log_size < component_coefficient_log_size
        || component_count
            != 1_usize << (composition_work_log_size - component_coefficient_log_size)
    {
        return Err(DiskCompositionError::Shape);
    }
    let work_rows = 1_usize << composition_work_log_size;
    let committed_rows = 1_usize << committed_evaluation_log_size;
    let coefficient_path = directory.join(format!("coefficients-t{table_index:08x}.fp16"));
    fs::copy(quotient_path, &coefficient_path)?;
    validate_fp16_file(&coefficient_path, work_rows)?;
    interpolate_extension_circle_file_in_place(&coefficient_path, composition_work_log_size)?;
    let coefficient_count = last_nonzero_fp16(&coefficient_path, work_rows)?;
    let chunk_rows = 1_usize << component_coefficient_log_size;
    let mut components = split_coefficient_chunks(
        &coefficient_path,
        table_index,
        component_count,
        chunk_rows,
        committed_rows,
        directory,
    )?;
    let _ = fs::remove_file(coefficient_path);
    for component in &components {
        evaluate_extension_circle_coefficient_file_in_place(
            component,
            committed_evaluation_log_size,
        )?;
    }
    if mask_coefficient_count > chunk_rows {
        return Err(DiskCompositionError::Shape);
    }
    for pair_index in 0..component_count / 2 {
        let mut mask_coefficients = sample_extension_trace_mask_coefficients(
            secret_mask_seed,
            session_id,
            &mask_id(program_commitment, table_index, pair_index)?,
            mask_coefficient_count,
        )?;
        mask_coefficients.resize(mask_coefficients.len().next_power_of_two(), Fp16::ZERO);
        let mask_path = directory.join(format!(
            "quotient-mask-t{table_index:08x}-p{pair_index:08x}.fp16"
        ));
        evaluate_extension_circle_coefficients_to_file(
            &mask_coefficients,
            committed_evaluation_log_size,
            &mask_path,
        )?;
        mask_component_pair(
            &components[2 * pair_index],
            &components[2 * pair_index + 1],
            &mask_path,
            composition_work_log_size,
            component_coefficient_log_size,
            committed_evaluation_log_size,
        )?;
        let _ = fs::remove_file(mask_path);
    }
    Ok((core::mem::take(&mut components), coefficient_count))
}

fn split_coefficient_chunks(
    source: &Path,
    table_index: usize,
    component_count: usize,
    chunk_rows: usize,
    committed_rows: usize,
    directory: &Path,
) -> Result<Vec<PathBuf>, DiskCompositionError> {
    if component_count == 0
        || chunk_rows == 0
        || committed_rows < chunk_rows
        || component_count
            .checked_mul(chunk_rows)
            .ok_or(DiskCompositionError::Overflow)?
            != fs::metadata(source)?.len() as usize / FP16_ENCODED_LENGTH
    {
        return Err(DiskCompositionError::Shape);
    }
    let mut source = BufReader::new(File::open(source)?);
    let mut paths = Vec::with_capacity(component_count);
    for component_index in 0..component_count {
        let path = directory.join(format!(
            "composition-t{table_index:08x}-c{component_index:08x}.fp16"
        ));
        let mut output = BufWriter::new(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?,
        );
        for start in (0..chunk_rows).step_by(UPDATE_BLOCK_ROWS) {
            let count = UPDATE_BLOCK_ROWS.min(chunk_rows - start);
            let mut block = vec![0_u8; count * FP16_ENCODED_LENGTH];
            source.read_exact(&mut block)?;
            output.write_all(&block)?;
        }
        output.flush()?;
        output.get_ref().set_len(
            u64::try_from(committed_rows)
                .ok()
                .and_then(|rows| rows.checked_mul(FP16_ENCODED_LENGTH as u64))
                .ok_or(DiskCompositionError::Overflow)?,
        )?;
        output.get_ref().sync_data()?;
        paths.push(path);
    }
    Ok(paths)
}

#[allow(clippy::too_many_arguments)]
fn mask_component_pair(
    left_path: &Path,
    right_path: &Path,
    mask_path: &Path,
    composition_work_log_size: u8,
    component_coefficient_log_size: u8,
    committed_evaluation_log_size: u8,
) -> Result<(), DiskCompositionError> {
    let rows = 1_usize << committed_evaluation_log_size;
    validate_fp16_file(left_path, rows)?;
    validate_fp16_file(right_path, rows)?;
    validate_fp16_file(mask_path, rows)?;
    let mut left = OpenOptions::new().read(true).write(true).open(left_path)?;
    let mut right = OpenOptions::new().read(true).write(true).open(right_path)?;
    let mut mask = BufReader::new(File::open(mask_path)?);
    for row in 0..rows {
        let left_value = read_one_fp16(&mut left)?;
        let right_value = read_one_fp16(&mut right)?;
        let mask_value = read_one_fp16(&mut mask)?;
        let mappings = crate::composition_chunks::composition_chunk_mappings(
            composition_work_log_size,
            component_coefficient_log_size,
            committed_evaluation_log_size,
            row,
        )
        .map_err(|_| DiskCompositionError::Shape)?;
        let factor = *mappings.last().ok_or(DiskCompositionError::Shape)?;
        let joined = left_value.add(factor.mul(right_value));
        let masked_left = left_value.add(factor.mul(mask_value));
        let masked_right = right_value.sub(mask_value);
        if masked_left.add(factor.mul(masked_right)) != joined {
            return Err(DiskCompositionError::Reconstruction);
        }
        let rewind = -(FP16_ENCODED_LENGTH as i64);
        left.seek(SeekFrom::Current(rewind))?;
        right.seek(SeekFrom::Current(rewind))?;
        left.write_all(&masked_left.encode())?;
        right.write_all(&masked_right.encode())?;
    }
    left.sync_data()?;
    right.sync_data()?;
    Ok(())
}

fn read_one_fp16(input: &mut impl Read) -> Result<Fp16, DiskCompositionError> {
    let mut encoded = [0_u8; FP16_ENCODED_LENGTH];
    input.read_exact(&mut encoded)?;
    Ok(Fp16::decode(&encoded)?)
}

fn last_nonzero_fp16(path: &Path, rows: usize) -> Result<usize, DiskCompositionError> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut last = 0usize;
    for row in 0..rows {
        if !read_one_fp16(&mut reader)?.is_zero() {
            last = row + 1;
        }
    }
    Ok(last)
}

fn initialize_zero_fp16_file(path: &Path, rows: usize) -> Result<(), DiskCompositionError> {
    let bytes = u64::try_from(rows)
        .ok()
        .and_then(|value| value.checked_mul(FP16_ENCODED_LENGTH as u64))
        .ok_or(DiskCompositionError::Overflow)?;
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.set_len(bytes)?;
    file.sync_data()?;
    Ok(())
}

fn derive_nonce(
    build_nonce: &[u8; 32],
    label: &[u8],
    left: usize,
    right: usize,
) -> Result<[u8; 32], DiskCompositionError> {
    use sha3::{Digest, Sha3_512};
    let mut hash = Sha3_512::new();
    hash.update(b"BL/PQ512/WAVE1B/DISK-COMPOSITION-NONCE/v1\0");
    hash.update(build_nonce);
    hash.update(label);
    hash.update(
        u64::try_from(left)
            .map_err(|_| DiskCompositionError::Overflow)?
            .to_be_bytes(),
    );
    hash.update(
        u64::try_from(right)
            .map_err(|_| DiskCompositionError::Overflow)?
            .to_be_bytes(),
    );
    let digest: [u8; 64] = hash.finalize().into();
    let mut nonce = [0_u8; 32];
    nonce.copy_from_slice(&digest[..32]);
    Ok(nonce)
}

fn directory_name(nonce: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::from("blpq-disk-composition-");
    for byte in nonce {
        name.push(DIGITS[usize::from(byte >> 4)] as char);
        name.push(DIGITS[usize::from(byte & 15)] as char);
    }
    name
}

fn create_owned_directory(
    directory: &Path,
    program_commitment: &[u8; 64],
) -> Result<(), DiskCompositionError> {
    fs::create_dir(directory)?;
    let marker_path = directory.join("OWNER");
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker_path)
        .and_then(|mut marker| {
            marker.write_all(DISK_COMPOSITION_MARKER)?;
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
) -> Result<(), DiskCompositionError> {
    let mut marker = [0_u8; 72];
    File::open(directory.join("OWNER"))?.read_exact(&mut marker)?;
    if &marker[..8] != DISK_COMPOSITION_MARKER || &marker[8..] != expected_program {
        return Err(DiskCompositionError::Ownership);
    }
    fs::remove_dir_all(directory)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circle_fft::{
        evaluate_extension_circle_coefficients, evaluate_extension_coefficients_at_point,
    };
    use crate::circle_fri::{bit_reverse_index, canonic_circle_point};
    use crate::field::M31;
    use crate::oods::CirclePoint;

    #[test]
    fn disk_dynamic_chunks_mask_and_reconstruct_every_committed_row() {
        let directory =
            std::env::temp_dir().join(format!("blpq-disk-dynamic-chunks-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let quotient_path = directory.join("quotient.fp16");
        let coefficients = (0..256)
            .map(|index| Fp16::from_m31(M31::from_canonical((index * 29 + 7) as u32).unwrap()))
            .collect::<Vec<_>>();
        let quotient = evaluate_extension_circle_coefficients(&coefficients, 8).unwrap();
        let mut output = BufWriter::new(File::create(&quotient_path).unwrap());
        for value in &quotient {
            output.write_all(&value.encode()).unwrap();
        }
        output.flush().unwrap();
        drop(output);

        let (paths, coefficient_count) = split_and_mask_quotient(
            &quotient_path,
            0,
            &[9_u8; 64],
            6,
            8,
            5,
            8,
            &[3_u8; 64],
            &[4_u8; 64],
            4,
            &directory,
        )
        .unwrap();
        assert_eq!(coefficient_count, coefficients.len());
        assert_eq!(paths.len(), 8);
        let components = paths
            .iter()
            .map(|path| {
                let mut reader = BufReader::new(File::open(path).unwrap());
                (0..64)
                    .map(|_| read_one_fp16(&mut reader).unwrap())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        for fft_index in 0..64 {
            let row = components
                .iter()
                .map(|component| component[fft_index])
                .collect::<Vec<_>>();
            let joined =
                crate::composition_chunks::join_composition_chunks_at(&row, 8, 5, 6, fft_index)
                    .unwrap();
            let natural = bit_reverse_index(fft_index, 6).unwrap();
            let point = canonic_circle_point(6, natural).unwrap();
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
        for path in paths {
            fs::remove_file(path).unwrap();
        }
        fs::remove_file(quotient_path).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
