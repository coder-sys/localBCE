//! Degree-16 LogUp interaction traces for executable AIR lookup arguments.
//!
//! Tuple coordinates are compressed with public `beta`, shifted by public
//! `gamma`, and inverted only on selected rows.  Each table gets one prefix
//! accumulator per lookup; the prover must obtain an exact zero global sum.
//! Interaction columns are then natively masked before commitment.

use alloc::vec;
use alloc::vec::Vec;
use sha3::{Digest, Sha3_512};

use crate::air_ir::{
    AirIrError, LookupSide, evaluate_air_execution, parse_air_program, parse_execution,
};
use crate::field::{FieldError, Fp16, M31};
use crate::trace_mask::{
    TraceMaskError, canonical_coset_zeroifier_evaluations,
    mask_extension_trace_column_with_zeroifiers, sample_extension_trace_mask_coefficients,
};

pub const LOGUP_ORACLE_DOMAIN: &[u8] = b"BL/PQ512/WAVE1B/LOGUP-INTERACTION-ORACLE/v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogupTableInteraction {
    pub lookup_index: u32,
    pub table_index: u32,
    pub logical_rows: usize,
    pub trace_rows: usize,
    pub evaluation_log_size: u8,
    pub side_signs: Vec<i8>,
    pub inverse_columns: Vec<Vec<Fp16>>,
    pub accumulator_column: Vec<Fp16>,
    pub masked_inverse_evaluations: Vec<Vec<Fp16>>,
    pub masked_accumulator_evaluations: Vec<Fp16>,
    pub final_sum: Fp16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AirLogupOracle {
    pub interactions: Vec<LogupTableInteraction>,
    pub lookup_count: u32,
    pub side_count: u64,
    pub denominator_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AirLogupError {
    Air(AirIrError),
    TraceMask(TraceMaskError),
    Field(FieldError),
    ProgramExecutionMismatch,
    Parameter,
    SelectorNotBoolean,
    ExceptionalDenominator,
    GlobalSumNonzero { lookup_index: u32 },
    CountOverflow,
}

impl From<AirIrError> for AirLogupError {
    fn from(value: AirIrError) -> Self {
        Self::Air(value)
    }
}
impl From<TraceMaskError> for AirLogupError {
    fn from(value: TraceMaskError) -> Self {
        Self::TraceMask(value)
    }
}
impl From<FieldError> for AirLogupError {
    fn from(value: FieldError) -> Self {
        Self::Field(value)
    }
}

pub(crate) fn compress_side(
    side: &LookupSide,
    columns: &[Vec<M31>],
    row: usize,
    beta: Fp16,
    gamma: Fp16,
) -> Result<(M31, M31, Fp16), AirLogupError> {
    let selector = side.selector.evaluate(columns, row)?;
    if selector.as_u32() > 1 {
        return Err(AirLogupError::SelectorNotBoolean);
    }
    let weight = side.weight.evaluate(columns, row)?;
    let mut compressed = gamma;
    let mut power = beta;
    for expression in &side.values {
        compressed = compressed.add(power.mul(Fp16::from_m31(expression.evaluate(columns, row)?)));
        power = power.mul(beta);
    }
    Ok((selector, weight, compressed))
}

pub(crate) fn interaction_id(
    source_program_commitment: &[u8; 64],
    lookup_index: usize,
    table_index: usize,
    column_index: usize,
) -> Result<[u8; 64], AirLogupError> {
    let lookup = u32::try_from(lookup_index).map_err(|_| AirLogupError::CountOverflow)?;
    let table = u32::try_from(table_index).map_err(|_| AirLogupError::CountOverflow)?;
    let column = u32::try_from(column_index).map_err(|_| AirLogupError::CountOverflow)?;
    let mut hash = Sha3_512::new();
    hash.update(LOGUP_ORACLE_DOMAIN);
    hash.update(source_program_commitment);
    hash.update(lookup.to_be_bytes());
    hash.update(table.to_be_bytes());
    hash.update(column.to_be_bytes());
    Ok(hash.finalize().into())
}

/// Build and mask every lookup interaction trace.
#[allow(clippy::too_many_arguments)]
pub fn build_air_logup_oracle(
    program_encoded: &[u8],
    execution_encoded: &[u8],
    beta: Fp16,
    gamma: Fp16,
    secret_mask_seed: &[u8],
    session_id: &[u8],
    mask_coefficient_count: usize,
    evaluation_log_expansion: u8,
) -> Result<AirLogupOracle, AirLogupError> {
    build_air_logup_oracle_internal(
        program_encoded,
        execution_encoded,
        beta,
        gamma,
        secret_mask_seed,
        session_id,
        mask_coefficient_count,
        evaluation_log_expansion,
        None,
        true,
    )
}

/// Build interaction traces directly on already-selected main-trace domains.
/// This avoids constructing and discarding a smaller masked LDE before the
/// interaction commitment, while enforcing the same minimum hiding domain.
#[allow(clippy::too_many_arguments)]
pub fn build_air_logup_oracle_at_evaluation_logs(
    program_encoded: &[u8],
    execution_encoded: &[u8],
    beta: Fp16,
    gamma: Fp16,
    secret_mask_seed: &[u8],
    session_id: &[u8],
    mask_coefficient_count: usize,
    evaluation_log_expansion: u8,
    table_evaluation_log_sizes: &[u8],
) -> Result<AirLogupOracle, AirLogupError> {
    build_air_logup_oracle_internal(
        program_encoded,
        execution_encoded,
        beta,
        gamma,
        secret_mask_seed,
        session_id,
        mask_coefficient_count,
        evaluation_log_expansion,
        Some(table_evaluation_log_sizes),
        true,
    )
}

/// Build exact trace-domain LogUp columns without materializing their possibly
/// multi-gigabyte masked evaluation domains. The disk prover expands and masks
/// these columns with the same oracle identifiers and parameters.
#[allow(clippy::too_many_arguments)]
pub fn build_air_logup_unmasked_at_evaluation_logs(
    program_encoded: &[u8],
    execution_encoded: &[u8],
    beta: Fp16,
    gamma: Fp16,
    secret_mask_seed: &[u8],
    session_id: &[u8],
    mask_coefficient_count: usize,
    evaluation_log_expansion: u8,
    table_evaluation_log_sizes: &[u8],
) -> Result<AirLogupOracle, AirLogupError> {
    build_air_logup_oracle_internal(
        program_encoded,
        execution_encoded,
        beta,
        gamma,
        secret_mask_seed,
        session_id,
        mask_coefficient_count,
        evaluation_log_expansion,
        Some(table_evaluation_log_sizes),
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_air_logup_oracle_internal(
    program_encoded: &[u8],
    execution_encoded: &[u8],
    beta: Fp16,
    gamma: Fp16,
    secret_mask_seed: &[u8],
    session_id: &[u8],
    mask_coefficient_count: usize,
    evaluation_log_expansion: u8,
    table_evaluation_log_sizes: Option<&[u8]>,
    materialize_evaluations: bool,
) -> Result<AirLogupOracle, AirLogupError> {
    if beta.is_zero()
        || gamma.is_zero()
        || mask_coefficient_count == 0
        || evaluation_log_expansion < 1
    {
        return Err(AirLogupError::Parameter);
    }
    evaluate_air_execution(execution_encoded)?;
    let program = parse_air_program(program_encoded)?;
    let execution = parse_execution(execution_encoded)?;
    if program.source_program_commitment != execution.source_program_commitment
        || program.program_id != execution._program_id
        || program.tables != execution.tables
        || program.lookups != execution.lookups
        || program.public_inputs != execution.public_inputs
    {
        return Err(AirLogupError::ProgramExecutionMismatch);
    }
    if table_evaluation_log_sizes.is_some_and(|logs| logs.len() != program.tables.len()) {
        return Err(AirLogupError::Parameter);
    }

    let mut interactions = Vec::new();
    let mut side_count = 0_u64;
    let mut denominator_count = 0_u64;
    for (lookup_index, lookup) in program.lookups.iter().enumerate() {
        let mut global_sum = Fp16::ZERO;
        for table_index in 0..program.tables.len() {
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
                .checked_add(sides.len() as u64)
                .ok_or(AirLogupError::CountOverflow)?;
            let logical_rows = program.tables[table_index].rows;
            // Keep the interaction trace on the same theorem-qualified H as
            // the main trace.  This also keeps prover and verifier geometry
            // derivation identical for small logical tables.
            let trace_rows = logical_rows
                .next_power_of_two()
                .max(mask_coefficient_count.next_power_of_two());
            let mask_size = mask_coefficient_count.next_power_of_two();
            let masked_bound = trace_rows
                .checked_add(mask_size)
                .ok_or(AirLogupError::CountOverflow)?
                .next_power_of_two();
            let minimum_evaluation_log_size = (masked_bound.ilog2() as u8)
                .checked_add(evaluation_log_expansion)
                .ok_or(AirLogupError::Parameter)?;
            let evaluation_log_size = table_evaluation_log_sizes
                .map(|logs| logs[table_index])
                .unwrap_or(minimum_evaluation_log_size);
            if evaluation_log_size < minimum_evaluation_log_size {
                return Err(AirLogupError::Parameter);
            }
            let columns = &execution.traces[table_index];
            let mut inverse_columns = vec![vec![Fp16::ZERO; trace_rows]; sides.len()];
            let mut contribution = vec![Fp16::ZERO; trace_rows];
            for (side_index, (sign, side)) in sides.iter().enumerate() {
                for row in side.row_start..side.row_stop {
                    let (selector, weight, denominator) =
                        compress_side(side, columns, row, beta, gamma)?;
                    if selector.is_zero() {
                        continue;
                    }
                    if denominator.is_zero() {
                        return Err(AirLogupError::ExceptionalDenominator);
                    }
                    let inverse = denominator.inverse()?;
                    inverse_columns[side_index][row] = inverse;
                    denominator_count = denominator_count
                        .checked_add(1)
                        .ok_or(AirLogupError::CountOverflow)?;
                    let weighted = inverse.mul(Fp16::from_m31(weight));
                    contribution[row] = if *sign > 0 {
                        contribution[row].add(weighted)
                    } else {
                        contribution[row].sub(weighted)
                    };
                }
            }
            let mut accumulator = vec![Fp16::ZERO; trace_rows];
            for row in 1..trace_rows {
                accumulator[row] = accumulator[row - 1].add(contribution[row - 1]);
            }
            let final_sum = accumulator[logical_rows - 1].add(contribution[logical_rows - 1]);
            global_sum = global_sum.add(final_sum);

            let (masked_inverse_evaluations, masked_accumulator_evaluations) =
                if materialize_evaluations {
                    let mut masked_inverse_evaluations = Vec::with_capacity(inverse_columns.len());
                    let zeroifiers = canonical_coset_zeroifier_evaluations(
                        trace_rows.ilog2() as u8,
                        evaluation_log_size,
                    )?;
                    for (column_index, column) in inverse_columns.iter().enumerate() {
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
                        masked_inverse_evaluations.push(
                            mask_extension_trace_column_with_zeroifiers(
                                column,
                                &randomizer,
                                evaluation_log_size,
                                &zeroifiers,
                            )?,
                        );
                    }
                    let accumulator_randomizer = sample_extension_trace_mask_coefficients(
                        secret_mask_seed,
                        session_id,
                        &interaction_id(
                            &program.source_program_commitment,
                            lookup_index,
                            table_index,
                            sides.len(),
                        )?,
                        mask_coefficient_count,
                    )?;
                    let masked_accumulator_evaluations =
                        mask_extension_trace_column_with_zeroifiers(
                            &accumulator,
                            &accumulator_randomizer,
                            evaluation_log_size,
                            &zeroifiers,
                        )?;
                    (masked_inverse_evaluations, masked_accumulator_evaluations)
                } else {
                    (Vec::new(), Vec::new())
                };
            interactions.push(LogupTableInteraction {
                lookup_index: u32::try_from(lookup_index)
                    .map_err(|_| AirLogupError::CountOverflow)?,
                table_index: u32::try_from(table_index)
                    .map_err(|_| AirLogupError::CountOverflow)?,
                logical_rows,
                trace_rows,
                evaluation_log_size,
                side_signs: sides.iter().map(|(sign, _)| *sign).collect(),
                inverse_columns,
                accumulator_column: accumulator,
                masked_inverse_evaluations,
                masked_accumulator_evaluations,
                final_sum,
            });
        }
        if !global_sum.is_zero() {
            return Err(AirLogupError::GlobalSumNonzero {
                lookup_index: u32::try_from(lookup_index)
                    .map_err(|_| AirLogupError::CountOverflow)?,
            });
        }
    }
    Ok(AirLogupOracle {
        interactions,
        lookup_count: u32::try_from(program.lookups.len())
            .map_err(|_| AirLogupError::CountOverflow)?,
        side_count,
        denominator_count,
    })
}
