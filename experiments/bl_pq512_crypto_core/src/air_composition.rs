//! Identity, fixed-column, and public-input composition over masked AIR traces.
//!
//! This is the algebraic bridge from the verifier-visible Wave 1A program IR
//! to the Circle proof engine.  Lookup arguments remain a separate LogUp
//! interaction module and are never silently counted as identity constraints.

use alloc::collections::{BTreeMap, btree_map::Entry};
use alloc::vec;
use alloc::vec::Vec;
use sha3::{Digest, Sha3_512};

use crate::air_ir::{
    AirIrError, Identity, ParsedProgram, evaluate_air_execution, parse_air_program, parse_execution,
};
use crate::air_logup::{AirLogupError, AirLogupOracle, LogupTableInteraction, interaction_id};
use crate::circle_fft::{
    CircleFftError, evaluate_circle_coefficients, evaluate_extension_circle_coefficients,
    interpolate_circle_evaluations, interpolate_extension_circle_evaluations,
    low_degree_extend_coset_order,
};
use crate::circle_fri::{CircleFriError, bit_reverse_index, canonic_circle_point};
use crate::field::{FieldError, Fp16, M31};
use crate::trace_mask::{
    TraceMaskError, canonical_coset_vanishing, canonical_coset_zeroifier_evaluations,
    mask_trace_column_with_zeroifiers, sample_trace_mask_coefficients,
};

pub const AIR_COMPOSITION_ORACLE_DOMAIN: &[u8] = b"BL/PQ512/WAVE1B/AIR-COMPOSITION-ORACLE/v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TableMainTraceOracle {
    pub table_index: u32,
    pub logical_rows: usize,
    pub trace_rows: usize,
    pub trace_log_size: u8,
    pub evaluation_log_size: u8,
    pub composition_work_log_size: u8,
    pub component_coefficient_log_size: u8,
    pub committed_column_indices: Vec<usize>,
    pub trace_columns: Vec<Vec<M31>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AirMainTraceOracle {
    pub source_program_commitment: [u8; 64],
    pub program_binary_commitment: [u8; 64],
    pub tables: Vec<TableMainTraceOracle>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TableCompositionOracle {
    pub table_index: u32,
    pub logical_rows: usize,
    pub trace_rows: usize,
    pub trace_log_size: u8,
    pub evaluation_log_size: u8,
    pub composition_work_log_size: u8,
    pub component_coefficient_log_size: u8,
    pub committed_column_indices: Vec<usize>,
    pub trace_columns: Vec<Vec<M31>>,
    pub composition_work: Option<Vec<Fp16>>,
    pub composition: Vec<Fp16>,
    pub composition_components: Option<Vec<Vec<Fp16>>>,
    pub composition_components_masked: bool,
    pub composition_coefficient_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AirCompositionOracle {
    pub source_program_commitment: [u8; 64],
    pub program_binary_commitment: [u8; 64],
    pub tables: Vec<TableCompositionOracle>,
    pub identity_term_count: u64,
    pub fixed_term_count: u64,
    pub public_term_count: u64,
    pub lookup_count_pending_logup: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AirCompositionError {
    Air(AirIrError),
    CircleFft(CircleFftError),
    CircleFri(CircleFriError),
    TraceMask(TraceMaskError),
    CompositionChunk(crate::composition_chunks::CompositionChunkError),
    Logup(AirLogupError),
    Field(FieldError),
    ProgramExecutionMismatch,
    Parameter,
    CountOverflow,
    ExceptionalDenominator,
}

impl From<AirIrError> for AirCompositionError {
    fn from(value: AirIrError) -> Self {
        Self::Air(value)
    }
}
impl From<CircleFftError> for AirCompositionError {
    fn from(value: CircleFftError) -> Self {
        Self::CircleFft(value)
    }
}
impl From<CircleFriError> for AirCompositionError {
    fn from(value: CircleFriError) -> Self {
        Self::CircleFri(value)
    }
}
impl From<TraceMaskError> for AirCompositionError {
    fn from(value: TraceMaskError) -> Self {
        Self::TraceMask(value)
    }
}
impl From<crate::composition_chunks::CompositionChunkError> for AirCompositionError {
    fn from(value: crate::composition_chunks::CompositionChunkError) -> Self {
        Self::CompositionChunk(value)
    }
}
impl From<AirLogupError> for AirCompositionError {
    fn from(value: AirLogupError) -> Self {
        Self::Logup(value)
    }
}
impl From<FieldError> for AirCompositionError {
    fn from(value: FieldError) -> Self {
        Self::Field(value)
    }
}

fn programs_match(program: &ParsedProgram, execution: &crate::air_ir::ParsedExecution) -> bool {
    program.source_program_commitment == execution.source_program_commitment
        && program.program_id == execution._program_id
        && program.tables == execution.tables
        && program.lookups == execution.lookups
        && program.public_inputs == execution.public_inputs
}

fn truncate_zero_m31_tail(
    mut coefficients: Vec<M31>,
    target_log_size: u8,
) -> Result<Vec<M31>, AirCompositionError> {
    let target_count = 1_usize << target_log_size;
    if coefficients.len() > target_count {
        if coefficients[target_count..]
            .iter()
            .any(|coefficient| !coefficient.is_zero())
        {
            return Err(AirCompositionError::Parameter);
        }
        coefficients.truncate(target_count);
    }
    Ok(coefficients)
}

fn truncate_zero_fp16_tail(
    mut coefficients: Vec<Fp16>,
    target_log_size: u8,
) -> Result<Vec<Fp16>, AirCompositionError> {
    let target_count = 1_usize << target_log_size;
    if coefficients.len() > target_count {
        if coefficients[target_count..]
            .iter()
            .any(|coefficient| !coefficient.is_zero())
        {
            return Err(AirCompositionError::Parameter);
        }
        coefficients.truncate(target_count);
    }
    Ok(coefficients)
}

pub(crate) fn shifted_fft_index(
    fft_index: usize,
    evaluation_log_size: u8,
    trace_log_size: u8,
) -> Result<usize, AirCompositionError> {
    if evaluation_log_size <= trace_log_size {
        return Err(AirCompositionError::Parameter);
    }
    let natural = bit_reverse_index(fft_index, evaluation_log_size)?;
    let half = 1_usize << (evaluation_log_size - 1);
    let offset = 1_usize << (evaluation_log_size - trace_log_size - 1);
    let shifted_natural = if natural < half {
        (natural + offset) % half
    } else {
        half + ((natural - half + half - offset) % half)
    };
    Ok(bit_reverse_index(shifted_natural, evaluation_log_size)?)
}

#[cfg(feature = "std")]
pub(crate) fn inverse_shifted_fft_index(
    fft_index: usize,
    evaluation_log_size: u8,
    trace_log_size: u8,
) -> Result<usize, AirCompositionError> {
    if evaluation_log_size <= trace_log_size {
        return Err(AirCompositionError::Parameter);
    }
    let natural = bit_reverse_index(fft_index, evaluation_log_size)?;
    let half = 1_usize << (evaluation_log_size - 1);
    let offset = 1_usize << (evaluation_log_size - trace_log_size - 1);
    let shifted_natural = if natural < half {
        (natural + half - offset) % half
    } else {
        half + ((natural - half + offset) % half)
    };
    Ok(bit_reverse_index(shifted_natural, evaluation_log_size)?)
}

pub(crate) fn selector_evaluations(
    trace_rows: usize,
    row_start: usize,
    row_stop: usize,
    evaluation_log_size: u8,
) -> Result<Vec<M31>, AirCompositionError> {
    let mut values = vec![M31::ZERO; trace_rows];
    if row_start >= row_stop || row_stop > trace_rows {
        return Err(AirCompositionError::Parameter);
    }
    values[row_start..row_stop].fill(M31::ONE);
    Ok(low_degree_extend_coset_order(
        &values,
        evaluation_log_size - trace_rows.ilog2() as u8,
    )?)
}

pub(crate) fn oracle_id(
    source_program_commitment: &[u8; 64],
    table_index: usize,
    column_index: usize,
) -> Result<[u8; 64], AirCompositionError> {
    let table = u32::try_from(table_index).map_err(|_| AirCompositionError::CountOverflow)?;
    let column = u32::try_from(column_index).map_err(|_| AirCompositionError::CountOverflow)?;
    let mut hash = Sha3_512::new();
    hash.update(AIR_COMPOSITION_ORACLE_DOMAIN);
    hash.update(source_program_commitment);
    hash.update(table.to_be_bytes());
    hash.update(column.to_be_bytes());
    Ok(hash.finalize().into())
}

fn add_term(accumulator: &mut Fp16, coefficient: &mut Fp16, alpha: Fp16, value: Fp16) {
    *accumulator = accumulator.add(coefficient.mul(value));
    *coefficient = coefficient.mul(alpha);
}

fn identity_value(
    identity: &Identity,
    selector: M31,
    current: &[Fp16],
    next: &[Fp16],
) -> Result<Fp16, AirCompositionError> {
    Ok(Fp16::from_m31(selector).mul(identity.expression.evaluate_extension(current, next)?))
}

/// Mask and LDE the main trace before any interaction or composition challenge.
pub fn build_air_main_trace_oracle(
    program_encoded: &[u8],
    execution_encoded: &[u8],
    secret_mask_seed: &[u8],
    session_id: &[u8],
    mask_coefficient_count: usize,
    log_blowup: u8,
) -> Result<AirMainTraceOracle, AirCompositionError> {
    if mask_coefficient_count == 0 || log_blowup == 0 {
        return Err(AirCompositionError::Parameter);
    }
    evaluate_air_execution(execution_encoded)?;
    let program = parse_air_program(program_encoded)?;
    let execution = parse_execution(execution_encoded)?;
    if !programs_match(&program, &execution) {
        return Err(AirCompositionError::ProgramExecutionMismatch);
    }
    let mut program_hash = Sha3_512::new();
    program_hash.update(crate::air_ir::AIR_PROGRAM_DOMAIN);
    program_hash.update(program_encoded);
    let program_binary_commitment = program_hash.finalize().into();
    let mut tables = Vec::with_capacity(program.tables.len());

    for (table_index, (table, raw_trace)) in
        program.tables.iter().zip(&execution.traces).enumerate()
    {
        // The conservative native-hiding theorem requires the trace domain H
        // to contain at least one point for every mask coefficient.  Derive H
        // from both the logical witness and the hiding freedom; otherwise a
        // small table can produce a syntactically valid proof that does not
        // meet the selected simulator bound.
        let trace_rows = table
            .rows
            .next_power_of_two()
            .max(mask_coefficient_count.next_power_of_two());
        let trace_log_size = trace_rows.ilog2() as u8;
        let mask_size = mask_coefficient_count.next_power_of_two();
        let masked_degree_bound = trace_rows
            .checked_add(mask_size)
            .ok_or(AirCompositionError::CountOverflow)?
            .next_power_of_two();
        let component_coefficient_log_size = masked_degree_bound.ilog2() as u8;
        let maximum_identity_degree = table
            .identities
            .iter()
            .map(|identity| identity.expression.degree())
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .max()
            .unwrap_or(1) as usize;
        let composition_degree_bound = masked_degree_bound
            .checked_mul(maximum_identity_degree.max(1) + 1)
            .ok_or(AirCompositionError::CountOverflow)?
            .next_power_of_two();
        let composition_work_log_size = composition_degree_bound.ilog2() as u8;
        let evaluation_log_size = component_coefficient_log_size
            .checked_add(crate::composition_mask::COMPOSITION_MASK_DEGREE_SLACK_LOG)
            .ok_or(AirCompositionError::Parameter)?
            .checked_add(log_blowup)
            .ok_or(AirCompositionError::Parameter)?;
        if evaluation_log_size <= trace_log_size {
            return Err(AirCompositionError::Parameter);
        }

        let mut is_fixed = vec![false; table.columns.len()];
        for (index, _) in &table.fixed_columns {
            is_fixed[*index] = true;
        }
        let committed_column_indices = is_fixed
            .iter()
            .enumerate()
            .filter_map(|(index, fixed)| (!fixed).then_some(index))
            .collect::<Vec<_>>();
        let zeroifiers =
            canonical_coset_zeroifier_evaluations(trace_log_size, evaluation_log_size)?;
        let mut trace_columns = Vec::with_capacity(raw_trace.len());
        for (column_index, raw_column) in raw_trace.iter().enumerate() {
            let mut natural = raw_column.clone();
            natural.resize(trace_rows, M31::ZERO);
            if is_fixed[column_index] {
                trace_columns.push(low_degree_extend_coset_order(
                    &natural,
                    evaluation_log_size - trace_log_size,
                )?);
            } else {
                let coefficients = sample_trace_mask_coefficients(
                    secret_mask_seed,
                    session_id,
                    &oracle_id(
                        &program.source_program_commitment,
                        table_index,
                        column_index,
                    )?,
                    mask_coefficient_count,
                )?;
                trace_columns.push(mask_trace_column_with_zeroifiers(
                    &natural,
                    &coefficients,
                    evaluation_log_size,
                    &zeroifiers,
                )?);
            }
        }

        tables.push(TableMainTraceOracle {
            table_index: u32::try_from(table_index)
                .map_err(|_| AirCompositionError::CountOverflow)?,
            logical_rows: table.rows,
            trace_rows,
            trace_log_size,
            evaluation_log_size,
            composition_work_log_size,
            component_coefficient_log_size,
            committed_column_indices,
            trace_columns,
        });
    }
    Ok(AirMainTraceOracle {
        source_program_commitment: program.source_program_commitment,
        program_binary_commitment,
        tables,
    })
}

/// Apply the later composition challenge to an already committed main trace.
pub fn build_air_composition_from_main(
    program_encoded: &[u8],
    execution_encoded: &[u8],
    composition_alpha: Fp16,
    main: AirMainTraceOracle,
) -> Result<AirCompositionOracle, AirCompositionError> {
    if composition_alpha.is_zero() {
        return Err(AirCompositionError::Parameter);
    }
    evaluate_air_execution(execution_encoded)?;
    let program = parse_air_program(program_encoded)?;
    let execution = parse_execution(execution_encoded)?;
    if !programs_match(&program, &execution)
        || main.source_program_commitment != program.source_program_commitment
        || main.tables.len() != program.tables.len()
    {
        return Err(AirCompositionError::ProgramExecutionMismatch);
    }
    let mut program_hash = Sha3_512::new();
    program_hash.update(crate::air_ir::AIR_PROGRAM_DOMAIN);
    program_hash.update(program_encoded);
    let program_binary_commitment: [u8; 64] = program_hash.finalize().into();
    if main.program_binary_commitment != program_binary_commitment {
        return Err(AirCompositionError::ProgramExecutionMismatch);
    }
    let mut tables = Vec::with_capacity(program.tables.len());
    let mut identity_term_count = 0_u64;
    let mut fixed_term_count = 0_u64;
    let mut public_term_count = 0_u64;
    let mut global_coefficient = Fp16::ONE;

    for (table_index, (table, main_table)) in program.tables.iter().zip(main.tables).enumerate() {
        if main_table.table_index as usize != table_index
            || main_table.logical_rows != table.rows
            || main_table.trace_columns.len() != table.columns.len()
        {
            return Err(AirCompositionError::ProgramExecutionMismatch);
        }
        let expected_committed = (0..table.columns.len())
            .filter(|column| !table.fixed_columns.iter().any(|(fixed, _)| fixed == column))
            .collect::<Vec<_>>();
        if main_table.committed_column_indices != expected_committed {
            return Err(AirCompositionError::ProgramExecutionMismatch);
        }
        let trace_rows = main_table.trace_rows;
        let trace_log_size = main_table.trace_log_size;
        let evaluation_log_size = main_table.evaluation_log_size;
        let composition_work_log_size = main_table.composition_work_log_size;
        let component_coefficient_log_size = main_table.component_coefficient_log_size;
        let committed_column_indices = main_table.committed_column_indices;
        let trace_columns = main_table.trace_columns;
        let work_trace_columns = trace_columns
            .iter()
            .map(|column| {
                let coefficients = truncate_zero_m31_tail(
                    interpolate_circle_evaluations(column)?,
                    composition_work_log_size,
                )?;
                evaluate_circle_coefficients(&coefficients, composition_work_log_size)
                    .map_err(AirCompositionError::from)
            })
            .collect::<Result<Vec<_>, AirCompositionError>>()?;
        let mut selector_cache = BTreeMap::<(usize, usize), Vec<M31>>::new();
        for (row_start, row_stop) in table
            .identities
            .iter()
            .map(|identity| (identity.row_start, identity.row_stop))
            .chain(core::iter::once((0, table.rows)))
            .chain(
                program
                    .public_inputs
                    .iter()
                    .filter(|binding| binding.table == table_index)
                    .map(|binding| (binding.row, binding.row + 1)),
            )
        {
            if let Entry::Vacant(entry) = selector_cache.entry((row_start, row_stop)) {
                entry.insert(selector_evaluations(
                    trace_rows,
                    row_start,
                    row_stop,
                    composition_work_log_size,
                )?);
            }
        }
        let fixed_expected = table
            .fixed_columns
            .iter()
            .map(|(column, values)| {
                let mut padded = values.materialize();
                padded.resize(trace_rows, M31::ZERO);
                Ok((
                    *column,
                    low_degree_extend_coset_order(
                        &padded,
                        composition_work_log_size - trace_log_size,
                    )?,
                ))
            })
            .collect::<Result<Vec<_>, AirCompositionError>>()?;
        let public_bindings = program
            .public_inputs
            .iter()
            .enumerate()
            .filter(|(_, binding)| binding.table == table_index)
            .map(|(input_index, binding)| {
                Ok((
                    binding.column,
                    execution.supplied_public_inputs[input_index],
                    binding.row,
                ))
            })
            .collect::<Result<Vec<_>, AirCompositionError>>()?;

        let evaluation_count = 1_usize << composition_work_log_size;
        let mut composition = Vec::with_capacity(evaluation_count);
        let mut current = Vec::with_capacity(work_trace_columns.len());
        let mut next = Vec::with_capacity(work_trace_columns.len());
        for fft_index in 0..evaluation_count {
            let shifted = shifted_fft_index(fft_index, composition_work_log_size, trace_log_size)?;
            current.clear();
            current.extend(
                work_trace_columns
                    .iter()
                    .map(|column| Fp16::from_m31(column[fft_index])),
            );
            next.clear();
            next.extend(
                work_trace_columns
                    .iter()
                    .map(|column| Fp16::from_m31(column[shifted])),
            );
            let mut accumulator = Fp16::ZERO;
            let mut coefficient = global_coefficient;
            for identity in &table.identities {
                let selector = selector_cache
                    .get(&(identity.row_start, identity.row_stop))
                    .ok_or(AirCompositionError::Parameter)?;
                add_term(
                    &mut accumulator,
                    &mut coefficient,
                    composition_alpha,
                    identity_value(identity, selector[fft_index], &current, &next)?,
                );
            }
            let live_selector = selector_cache
                .get(&(0, table.rows))
                .ok_or(AirCompositionError::Parameter)?;
            for (column, expected) in &fixed_expected {
                let difference = current[*column].sub(Fp16::from_m31(expected[fft_index]));
                add_term(
                    &mut accumulator,
                    &mut coefficient,
                    composition_alpha,
                    Fp16::from_m31(live_selector[fft_index]).mul(difference),
                );
            }
            for (column, supplied, row) in &public_bindings {
                let selector = selector_cache
                    .get(&(*row, *row + 1))
                    .ok_or(AirCompositionError::Parameter)?;
                let difference = current[*column].sub(Fp16::from_m31(*supplied));
                add_term(
                    &mut accumulator,
                    &mut coefficient,
                    composition_alpha,
                    Fp16::from_m31(selector[fft_index]).mul(difference),
                );
            }
            let natural_index = bit_reverse_index(fft_index, composition_work_log_size)?;
            let point = canonic_circle_point(composition_work_log_size, natural_index)?;
            let denominator = canonical_coset_vanishing(point, trace_log_size)?;
            if denominator.is_zero() {
                return Err(AirCompositionError::ExceptionalDenominator);
            }
            composition.push(accumulator.mul(Fp16::from_m31(denominator.inverse()?)));
        }
        let term_count = table.identities.len() + fixed_expected.len() + public_bindings.len();
        for _ in 0..term_count {
            global_coefficient = global_coefficient.mul(composition_alpha);
        }
        identity_term_count = identity_term_count
            .checked_add(table.identities.len() as u64)
            .ok_or(AirCompositionError::CountOverflow)?;
        fixed_term_count = fixed_term_count
            .checked_add(fixed_expected.len() as u64)
            .ok_or(AirCompositionError::CountOverflow)?;
        public_term_count = public_term_count
            .checked_add(public_bindings.len() as u64)
            .ok_or(AirCompositionError::CountOverflow)?;

        let coefficients = interpolate_extension_circle_evaluations(&composition)?;
        let composition_coefficient_count = coefficients
            .iter()
            .rposition(|value| !value.is_zero())
            .map_or(0, |index| index + 1);
        let composition_components = crate::composition_chunks::evaluate_composition_chunks(
            &coefficients,
            component_coefficient_log_size,
            evaluation_log_size,
        )?;
        let committed_evaluations = 1_usize << evaluation_log_size;
        let mut committed_composition = Vec::with_capacity(committed_evaluations);
        let mut component_row = Vec::with_capacity(composition_components.len());
        for fft_index in 0..committed_evaluations {
            component_row.clear();
            component_row.extend(
                composition_components
                    .iter()
                    .map(|component| component[fft_index]),
            );
            committed_composition.push(crate::composition_chunks::join_composition_chunks_at(
                &component_row,
                composition_work_log_size,
                component_coefficient_log_size,
                evaluation_log_size,
                fft_index,
            )?);
        }
        tables.push(TableCompositionOracle {
            table_index: main_table.table_index,
            logical_rows: table.rows,
            trace_rows,
            trace_log_size,
            evaluation_log_size,
            composition_work_log_size,
            component_coefficient_log_size,
            committed_column_indices,
            trace_columns,
            composition_work: Some(composition),
            composition: committed_composition,
            composition_components: Some(composition_components),
            composition_components_masked: false,
            composition_coefficient_count,
        });
    }
    Ok(AirCompositionOracle {
        source_program_commitment: program.source_program_commitment,
        program_binary_commitment,
        tables,
        identity_term_count,
        fixed_term_count,
        public_term_count,
        lookup_count_pending_logup: u32::try_from(program.lookups.len())
            .map_err(|_| AirCompositionError::CountOverflow)?,
    })
}

/// Compatibility constructor for tests and non-interactive local tooling.
pub fn build_air_composition_oracle(
    program_encoded: &[u8],
    execution_encoded: &[u8],
    composition_alpha: Fp16,
    secret_mask_seed: &[u8],
    session_id: &[u8],
    mask_coefficient_count: usize,
    log_blowup: u8,
) -> Result<AirCompositionOracle, AirCompositionError> {
    let main = build_air_main_trace_oracle(
        program_encoded,
        execution_encoded,
        secret_mask_seed,
        session_id,
        mask_coefficient_count,
        log_blowup,
    )?;
    build_air_composition_from_main(program_encoded, execution_encoded, composition_alpha, main)
}

pub(crate) fn alpha_power(alpha: Fp16, exponent: u64) -> Fp16 {
    let mut result = Fp16::ONE;
    for _ in 0..exponent {
        result = result.mul(alpha);
    }
    result
}

fn remask_interaction_at_log(
    source_program_commitment: &[u8; 64],
    interaction: &mut LogupTableInteraction,
    evaluation_log_size: u8,
    secret_mask_seed: &[u8],
    session_id: &[u8],
    mask_coefficient_count: usize,
) -> Result<(), AirCompositionError> {
    let lookup_index = interaction.lookup_index as usize;
    let table_index = interaction.table_index as usize;
    interaction.evaluation_log_size = evaluation_log_size;
    let zeroifiers = crate::trace_mask::canonical_coset_zeroifier_evaluations(
        interaction.trace_rows.ilog2() as u8,
        evaluation_log_size,
    )?;
    interaction.masked_inverse_evaluations.clear();
    for (column_index, column) in interaction.inverse_columns.iter().enumerate() {
        let randomizer = crate::trace_mask::sample_extension_trace_mask_coefficients(
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
        interaction.masked_inverse_evaluations.push(
            crate::trace_mask::mask_extension_trace_column_with_zeroifiers(
                column,
                &randomizer,
                evaluation_log_size,
                &zeroifiers,
            )?,
        );
    }
    let accumulator_randomizer = crate::trace_mask::sample_extension_trace_mask_coefficients(
        secret_mask_seed,
        session_id,
        &interaction_id(
            source_program_commitment,
            lookup_index,
            table_index,
            interaction.inverse_columns.len(),
        )?,
        mask_coefficient_count,
    )?;
    interaction.masked_accumulator_evaluations =
        crate::trace_mask::mask_extension_trace_column_with_zeroifiers(
            &interaction.accumulator_column,
            &accumulator_randomizer,
            evaluation_log_size,
            &zeroifiers,
        )?;
    Ok(())
}

/// Re-expand LogUp columns to the main table's final evaluation domain before
/// the interaction root is committed and before alpha is sampled.
pub fn prepare_logup_for_composition(
    program_encoded: &[u8],
    main: &AirMainTraceOracle,
    logup: &mut AirLogupOracle,
    secret_mask_seed: &[u8],
    session_id: &[u8],
    mask_coefficient_count: usize,
) -> Result<(), AirCompositionError> {
    if mask_coefficient_count == 0 {
        return Err(AirCompositionError::Parameter);
    }
    let program = parse_air_program(program_encoded)?;
    if main.source_program_commitment != program.source_program_commitment
        || main.tables.len() != program.tables.len()
        || logup.lookup_count as usize != program.lookups.len()
    {
        return Err(AirCompositionError::ProgramExecutionMismatch);
    }
    for interaction in &mut logup.interactions {
        let table = main
            .tables
            .get(interaction.table_index as usize)
            .ok_or(AirCompositionError::Parameter)?;
        if table.trace_rows != interaction.trace_rows
            || table.logical_rows != interaction.logical_rows
        {
            return Err(AirCompositionError::Parameter);
        }
        if interaction.evaluation_log_size != table.evaluation_log_size {
            remask_interaction_at_log(
                &program.source_program_commitment,
                interaction,
                table.evaluation_log_size,
                secret_mask_seed,
                session_id,
                mask_coefficient_count,
            )?;
        }
    }
    Ok(())
}

/// Merge LogUp inverse, recurrence, and endpoint identities into the same
/// quotient oracle used for ordinary AIR identities.
#[allow(clippy::too_many_arguments)]
pub fn add_logup_to_composition(
    program_encoded: &[u8],
    execution_encoded: &[u8],
    composition: &mut AirCompositionOracle,
    logup: &mut AirLogupOracle,
    beta: Fp16,
    gamma: Fp16,
    composition_alpha: Fp16,
    secret_mask_seed: &[u8],
    session_id: &[u8],
    mask_coefficient_count: usize,
) -> Result<u64, AirCompositionError> {
    if beta.is_zero()
        || gamma.is_zero()
        || composition_alpha.is_zero()
        || mask_coefficient_count == 0
    {
        return Err(AirCompositionError::Parameter);
    }
    let program = parse_air_program(program_encoded)?;
    let execution = parse_execution(execution_encoded)?;
    if !programs_match(&program, &execution)
        || composition.source_program_commitment != program.source_program_commitment
        || logup.lookup_count as usize != program.lookups.len()
    {
        return Err(AirCompositionError::ProgramExecutionMismatch);
    }
    let existing_terms = composition
        .identity_term_count
        .checked_add(composition.fixed_term_count)
        .and_then(|value| value.checked_add(composition.public_term_count))
        .ok_or(AirCompositionError::CountOverflow)?;
    let mut coefficient = alpha_power(composition_alpha, existing_terms);
    let mut added_terms = 0_u64;

    for interaction in &mut logup.interactions {
        let lookup_index = interaction.lookup_index as usize;
        let table_index = interaction.table_index as usize;
        let lookup = program
            .lookups
            .get(lookup_index)
            .ok_or(AirCompositionError::Parameter)?;
        let table_oracle = composition
            .tables
            .get_mut(table_index)
            .ok_or(AirCompositionError::Parameter)?;
        if table_oracle.trace_rows != interaction.trace_rows
            || table_oracle.logical_rows != interaction.logical_rows
        {
            return Err(AirCompositionError::Parameter);
        }
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
        if sides.len() != interaction.inverse_columns.len()
            || interaction.side_signs != sides.iter().map(|(sign, _)| *sign).collect::<Vec<_>>()
        {
            return Err(AirCompositionError::Parameter);
        }

        let evaluation_log_size = table_oracle.evaluation_log_size;
        let evaluation_count = 1_usize << evaluation_log_size;
        let work_log_size = table_oracle.composition_work_log_size;
        let work_count = 1_usize << work_log_size;
        let trace_log_size = table_oracle.trace_log_size;
        let already_prepared = interaction.evaluation_log_size == evaluation_log_size
            && interaction
                .masked_inverse_evaluations
                .iter()
                .all(|column| column.len() == evaluation_count)
            && interaction.masked_accumulator_evaluations.len() == evaluation_count;
        if !already_prepared {
            remask_interaction_at_log(
                &program.source_program_commitment,
                interaction,
                evaluation_log_size,
                secret_mask_seed,
                session_id,
                mask_coefficient_count,
            )?;
        }

        let work_trace_columns = table_oracle
            .trace_columns
            .iter()
            .map(|column| {
                let coefficients =
                    truncate_zero_m31_tail(interpolate_circle_evaluations(column)?, work_log_size)?;
                evaluate_circle_coefficients(&coefficients, work_log_size)
                    .map_err(AirCompositionError::from)
            })
            .collect::<Result<Vec<_>, AirCompositionError>>()?;
        let work_inverse_columns = interaction
            .masked_inverse_evaluations
            .iter()
            .map(|column| {
                let coefficients = truncate_zero_fp16_tail(
                    interpolate_extension_circle_evaluations(column)?,
                    work_log_size,
                )?;
                evaluate_extension_circle_coefficients(&coefficients, work_log_size)
                    .map_err(AirCompositionError::from)
            })
            .collect::<Result<Vec<_>, AirCompositionError>>()?;
        let accumulator_coefficients = truncate_zero_fp16_tail(
            interpolate_extension_circle_evaluations(&interaction.masked_accumulator_evaluations)?,
            work_log_size,
        )?;
        let work_accumulator =
            evaluate_extension_circle_coefficients(&accumulator_coefficients, work_log_size)?;

        let mut selector_cache = BTreeMap::<(usize, usize), Vec<M31>>::new();
        for range in sides
            .iter()
            .map(|(_, side)| (side.row_start, side.row_stop))
            .chain([
                (0, interaction.trace_rows - 1),
                (0, 1),
                (interaction.trace_rows - 1, interaction.trace_rows),
            ])
        {
            if let Entry::Vacant(entry) = selector_cache.entry(range) {
                entry.insert(selector_evaluations(
                    interaction.trace_rows,
                    range.0,
                    range.1,
                    work_log_size,
                )?);
            }
        }
        let side_coefficients = (0..sides.len())
            .map(|_| {
                let current = coefficient;
                coefficient = coefficient.mul(composition_alpha);
                current
            })
            .collect::<Vec<_>>();
        let transition_coefficient = coefficient;
        coefficient = coefficient.mul(composition_alpha);
        let first_coefficient = coefficient;
        coefficient = coefficient.mul(composition_alpha);
        let last_coefficient = coefficient;
        coefficient = coefficient.mul(composition_alpha);
        added_terms = added_terms
            .checked_add(sides.len() as u64 + 3)
            .ok_or(AirCompositionError::CountOverflow)?;

        let mut current = Vec::with_capacity(work_trace_columns.len());
        let composition_work = table_oracle
            .composition_work
            .as_mut()
            .ok_or(AirCompositionError::Parameter)?;
        if composition_work.len() != work_count {
            return Err(AirCompositionError::Parameter);
        }
        for fft_index in 0..work_count {
            let shifted = shifted_fft_index(fft_index, work_log_size, trace_log_size)?;
            current.clear();
            current.extend(
                work_trace_columns
                    .iter()
                    .map(|column| Fp16::from_m31(column[fft_index])),
            );
            let mut numerator = Fp16::ZERO;
            let mut contribution = Fp16::ZERO;
            for (side_index, (sign, side)) in sides.iter().enumerate() {
                let selector = side.selector.evaluate_extension(&current, &current)?;
                let range = selector_cache
                    .get(&(side.row_start, side.row_stop))
                    .ok_or(AirCompositionError::Parameter)?;
                let range_value = Fp16::from_m31(range[fft_index]);
                let weight = side.weight.evaluate_extension(&current, &current)?;
                let mut denominator = gamma;
                let mut power = beta;
                for value in &side.values {
                    denominator =
                        denominator.add(power.mul(value.evaluate_extension(&current, &current)?));
                    power = power.mul(beta);
                }
                let inverse = work_inverse_columns[side_index][fft_index];
                let inverse_constraint = range_value.mul(denominator.mul(inverse).sub(selector));
                numerator = numerator.add(side_coefficients[side_index].mul(inverse_constraint));
                let signed = range_value.mul(weight).mul(inverse);
                contribution = if *sign > 0 {
                    contribution.add(signed)
                } else {
                    contribution.sub(signed)
                };
            }
            let accumulator = work_accumulator[fft_index];
            let next_accumulator = work_accumulator[shifted];
            let transition_selector = selector_cache
                .get(&(0, interaction.trace_rows - 1))
                .ok_or(AirCompositionError::Parameter)?;
            let first_selector = selector_cache
                .get(&(0, 1))
                .ok_or(AirCompositionError::Parameter)?;
            let last_selector = selector_cache
                .get(&(interaction.trace_rows - 1, interaction.trace_rows))
                .ok_or(AirCompositionError::Parameter)?;
            let transition = Fp16::from_m31(transition_selector[fft_index])
                .mul(next_accumulator.sub(accumulator).sub(contribution));
            numerator = numerator.add(transition_coefficient.mul(transition));
            numerator = numerator.add(
                first_coefficient.mul(Fp16::from_m31(first_selector[fft_index]).mul(accumulator)),
            );
            numerator = numerator.add(
                last_coefficient.mul(
                    Fp16::from_m31(last_selector[fft_index])
                        .mul(accumulator.sub(interaction.final_sum)),
                ),
            );
            let natural_index = bit_reverse_index(fft_index, work_log_size)?;
            let point = canonic_circle_point(work_log_size, natural_index)?;
            let denominator = canonical_coset_vanishing(point, trace_log_size)?;
            if denominator.is_zero() {
                return Err(AirCompositionError::ExceptionalDenominator);
            }
            composition_work[fft_index] = composition_work[fft_index]
                .add(numerator.mul(Fp16::from_m31(denominator.inverse()?)));
        }
    }
    for table_oracle in &mut composition.tables {
        let composition_work = table_oracle
            .composition_work
            .as_ref()
            .ok_or(AirCompositionError::Parameter)?;
        let coefficients = interpolate_extension_circle_evaluations(composition_work)?;
        table_oracle.composition_coefficient_count = coefficients
            .iter()
            .rposition(|value| !value.is_zero())
            .map_or(0, |index| index + 1);
        let components = crate::composition_chunks::evaluate_composition_chunks(
            &coefficients,
            table_oracle.component_coefficient_log_size,
            table_oracle.evaluation_log_size,
        )?;
        let committed_count = 1_usize << table_oracle.evaluation_log_size;
        let mut row = Vec::with_capacity(components.len());
        table_oracle.composition.clear();
        table_oracle.composition.reserve(committed_count);
        for fft_index in 0..committed_count {
            row.clear();
            row.extend(components.iter().map(|component| component[fft_index]));
            table_oracle
                .composition
                .push(crate::composition_chunks::join_composition_chunks_at(
                    &row,
                    table_oracle.composition_work_log_size,
                    table_oracle.component_coefficient_log_size,
                    table_oracle.evaluation_log_size,
                    fft_index,
                )?);
        }
        table_oracle.composition_components = Some(components);
        table_oracle.composition_components_masked = false;
    }
    composition.lookup_count_pending_logup = 0;
    Ok(added_terms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circle_fri::{BaseCirclePoint, M31_CIRCLE_LOG_ORDER};

    #[test]
    fn smaller_work_domain_requires_an_exact_zero_coefficient_tail() {
        let mut base = vec![M31::ZERO; 64];
        base[3] = M31::ONE;
        assert_eq!(truncate_zero_m31_tail(base.clone(), 5).unwrap().len(), 32);
        base[32] = M31::ONE;
        assert!(matches!(
            truncate_zero_m31_tail(base, 5),
            Err(AirCompositionError::Parameter)
        ));

        let mut extension = vec![Fp16::ZERO; 64];
        extension[3] = Fp16::ONE;
        assert_eq!(
            truncate_zero_fp16_tail(extension.clone(), 5).unwrap().len(),
            32
        );
        extension[32] = Fp16::ONE;
        assert!(matches!(
            truncate_zero_fp16_tail(extension, 5),
            Err(AirCompositionError::Parameter)
        ));
    }

    #[test]
    fn shifted_fft_index_is_exact_trace_step_translation() {
        for trace_log in 2..=6 {
            for evaluation_log in trace_log + 1..=9 {
                let step = BaseCirclePoint::generator()
                    .multiply(1_usize << (M31_CIRCLE_LOG_ORDER - trace_log));
                for fft_index in 0..1_usize << evaluation_log {
                    let natural = bit_reverse_index(fft_index, evaluation_log).unwrap();
                    let point = canonic_circle_point(evaluation_log, natural).unwrap();
                    let shifted = shifted_fft_index(fft_index, evaluation_log, trace_log).unwrap();
                    let shifted_natural = bit_reverse_index(shifted, evaluation_log).unwrap();
                    assert_eq!(
                        point.add(step),
                        canonic_circle_point(evaluation_log, shifted_natural).unwrap()
                    );
                }
            }
        }
    }
}
