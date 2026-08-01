//! Verifier-derived memory preflight for monolithic versus streamed proving.

use core::fmt;

use alloc::collections::BTreeSet;

use crate::air_ir::{AirIrError, parse_air_program};
use crate::cross_domain::{DISK_TREE_RETAINED_LEVEL_BUDGET_BYTES, EvaluationField};
use crate::oracle_commitment::{OracleCommitmentError, derive_oracle_commitment_layouts};
use crate::proof_parameters::{LOG_BLOWUP, QUERY_COUNT, TRACE_MASK_COEFFICIENT_COUNT};

pub const MONOLITHIC_PROVER_MEMORY_CAP_BYTES: u128 = 1_u128 << 30;
pub const STREAMING_SCRATCH_RESERVE_BYTES: u128 = 4_u128 << 30;
/// These estimates are derived layout models, never measured telemetry.
pub const RESOURCE_PREFLIGHT_EVIDENCE_CLASS: &str = "DERIVED_MODEL";
/// The model describes the generic AIR/oracle layout, not the generated backend.
pub const RESOURCE_PREFLIGHT_MODEL_ID: &str = "GENERIC_AIR_ORACLE_LAYOUT_V1";
const COMPOSITION_WORK_COLUMN_FILES_BYTES: u128 = 64_u128 << 30;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProverResourceEstimate {
    pub main_evaluation_bytes: u128,
    pub interaction_evaluation_bytes: u128,
    pub composition_evaluation_bytes: u128,
    pub deep_evaluation_bytes: u128,
    pub fri_mask_bytes: u128,
    pub folded_layer_bytes: u128,
    pub monolithic_live_bytes_lower_bound: u128,
    pub maximum_domain_rows: u128,
    pub requires_streaming: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamingScratchEstimate {
    pub raw_witness_bytes: u128,
    pub persistent_oracle_bytes: u128,
    pub peak_temporary_bytes: u128,
    pub filesystem_overhead_bytes: u128,
    pub reserve_bytes: u128,
    pub required_available_bytes: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourcePreflightError {
    Air(AirIrError),
    Oracle(OracleCommitmentError),
    Overflow,
    FieldMismatch,
}

impl From<AirIrError> for ResourcePreflightError {
    fn from(value: AirIrError) -> Self {
        Self::Air(value)
    }
}

impl From<OracleCommitmentError> for ResourcePreflightError {
    fn from(value: OracleCommitmentError) -> Self {
        Self::Oracle(value)
    }
}

impl fmt::Display for ResourcePreflightError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "BL-PQ512 resource preflight error: {self:?}")
    }
}

impl core::error::Error for ResourcePreflightError {}

fn add(left: u128, right: u128) -> Result<u128, ResourcePreflightError> {
    left.checked_add(right)
        .ok_or(ResourcePreflightError::Overflow)
}

fn mul(left: u128, right: u128) -> Result<u128, ResourcePreflightError> {
    left.checked_mul(right)
        .ok_or(ResourcePreflightError::Overflow)
}

fn layout_bytes(
    layout: &crate::cross_domain::CrossDomainLayout,
    expected_field: EvaluationField,
) -> Result<u128, ResourcePreflightError> {
    layout.specs().iter().try_fold(0_u128, |total, spec| {
        if spec.field != expected_field {
            return Err(ResourcePreflightError::FieldMismatch);
        }
        let scalar_bytes = match expected_field {
            EvaluationField::M31 => 4_u128,
            EvaluationField::Fp16 => 64_u128,
        };
        add(
            total,
            mul(
                mul(1_u128 << spec.log_size, u128::from(spec.column_count))?,
                scalar_bytes,
            )?,
        )
    })
}

fn tree_bytes(maximum_log_size: u8) -> Result<u128, ResourcePreflightError> {
    let next_log = u32::from(maximum_log_size)
        .checked_add(1)
        .ok_or(ResourcePreflightError::Overflow)?;
    let nodes = 1_u128
        .checked_shl(next_log)
        .and_then(|value| value.checked_sub(1))
        .ok_or(ResourcePreflightError::Overflow)?;
    mul(nodes, 64)
}

fn retained_tree_bytes(maximum_log_size: u8) -> Result<u128, ResourcePreflightError> {
    Ok(tree_bytes(maximum_log_size)?.min(u128::from(DISK_TREE_RETAINED_LEVEL_BUDGET_BYTES)))
}

fn recomputed_tree_bytes(maximum_log_size: u8) -> Result<u128, ResourcePreflightError> {
    let bytes = tree_bytes(maximum_log_size)?;
    Ok(
        if bytes > u128::from(DISK_TREE_RETAINED_LEVEL_BUDGET_BYTES) {
            mul(
                add(QUERY_COUNT as u128, 1)?,
                mul(u128::from(maximum_log_size), 64)?,
            )?
        } else {
            0
        },
    )
}

/// Conservative peak scratch-space requirement for the disk-backed prover.
///
/// `raw_witness_bytes` is derived from the authenticated streaming manifest.
/// The estimate includes canonical columns, deterministically retained Merkle
/// levels, the largest bounded query frontier, DEEP/FRI work files, 25%
/// filesystem headroom, and a fixed free-space reserve.
pub fn estimate_selected_streaming_scratch(
    program_encoded: &[u8],
    raw_witness_bytes: u128,
) -> Result<StreamingScratchEstimate, ResourcePreflightError> {
    let layouts = derive_oracle_commitment_layouts(
        program_encoded,
        TRACE_MASK_COEFFICIENT_COUNT,
        LOG_BLOWUP,
    )?;
    let program = parse_air_program(program_encoded)?;
    let main = layout_bytes(&layouts.main_trace, EvaluationField::M31)?;
    let interaction = layouts
        .interaction_trace
        .as_ref()
        .map(|layout| layout_bytes(layout, EvaluationField::Fp16))
        .transpose()?
        .unwrap_or(0);
    let composition = layout_bytes(&layouts.composition, EvaluationField::Fp16)?;

    let main_tree = retained_tree_bytes(layouts.main_trace.maximum_log_size())?;
    let interaction_tree = layouts
        .interaction_trace
        .as_ref()
        .map(|layout| retained_tree_bytes(layout.maximum_log_size()))
        .transpose()?
        .unwrap_or(0);
    let composition_tree = retained_tree_bytes(layouts.composition.maximum_log_size())?;
    let persistent_oracle_bytes = [
        raw_witness_bytes,
        main,
        main_tree,
        interaction,
        interaction_tree,
        composition,
        composition_tree,
    ]
    .into_iter()
    .try_fold(0_u128, add)?;

    let mut domain_logs = BTreeSet::new();
    domain_logs.extend(layouts.main_trace.specs().iter().map(|spec| spec.log_size));
    domain_logs.extend(layouts.composition.specs().iter().map(|spec| spec.log_size));
    if let Some(layout) = &layouts.interaction_trace {
        domain_logs.extend(layout.specs().iter().map(|spec| spec.log_size));
    }
    let mask_domain_bytes = domain_logs
        .into_iter()
        .try_fold(0_u128, |total, log| add(total, mul(1_u128 << log, 64)?))?;
    let maximum_log = layouts
        .main_trace
        .maximum_log_size()
        .max(layouts.composition.maximum_log_size())
        .max(
            layouts
                .interaction_trace
                .as_ref()
                .map(|layout| layout.maximum_log_size())
                .unwrap_or(0),
        );
    let maximum_rows = 1_u128 << maximum_log;
    // Two retained mask/batch files per domain plus the mask tree, fold values,
    // fold Merkle levels, and one largest-domain inverse/work file.
    let fri_temporary = add(mul(mask_domain_bytes, 2)?, mul(maximum_rows, 384)?)?;
    let maximum_work_log = layouts
        .tables
        .iter()
        .map(|table| table.composition_work_log_size)
        .max()
        .ok_or(ResourcePreflightError::Overflow)?;
    let maximum_work_rows = 1_u128 << maximum_work_log;
    let work_extension_file = mul(maximum_work_rows, 64)?;
    let mut streamed_column_peak = 0_u128;
    for (table, geometry) in program.tables.iter().zip(&layouts.tables) {
        let work_base_file = mul(1_u128 << geometry.composition_work_log_size, 4)?;
        let selector_range_count = table
            .identities
            .iter()
            .map(|identity| (identity.row_start, identity.row_stop))
            .collect::<BTreeSet<_>>()
            .len() as u128;
        // Current columns, next-source columns, and shifted next columns are
        // the only simultaneous base-field work-file families.
        let potential_files = add(mul(table.columns.len() as u128, 3)?, selector_range_count)?;
        let capped_work_files =
            mul(potential_files, work_base_file)?.min(COMPOSITION_WORK_COLUMN_FILES_BYTES);
        let fixed_committed_files = mul(
            mul(
                table.fixed_columns.len() as u128,
                1_u128 << geometry.evaluation_log_size,
            )?,
            4,
        )?;
        streamed_column_peak =
            streamed_column_peak.max(add(capped_work_files, fixed_committed_files)?);
    }
    // Identity batches cap current/selector work files at 32 GiB; next-row
    // columns can simultaneously require another shifted copy. The quotient
    // split can instead retain both a work-domain numerator and coefficient
    // copy. Account for the larger path exactly rather than the old two-half
    // approximation.
    let streamed_identity_temporary = add(streamed_column_peak, work_extension_file)?;
    let split_temporary = mul(work_extension_file, 2)?;
    let composition_temporary = streamed_identity_temporary.max(split_temporary);
    let deep_temporary = mul(maximum_rows, 192)?;
    let tree_recompute_temporary = [
        recomputed_tree_bytes(layouts.main_trace.maximum_log_size())?,
        layouts
            .interaction_trace
            .as_ref()
            .map(|layout| recomputed_tree_bytes(layout.maximum_log_size()))
            .transpose()?
            .unwrap_or(0),
        recomputed_tree_bytes(layouts.composition.maximum_log_size())?,
    ]
    .into_iter()
    .max()
    .unwrap_or(0);
    let peak_temporary_bytes = fri_temporary
        .max(composition_temporary)
        .max(deep_temporary)
        .max(tree_recompute_temporary);
    let accounted = add(persistent_oracle_bytes, peak_temporary_bytes)?;
    let filesystem_overhead_bytes = accounted / 4;
    let required_available_bytes = add(
        add(accounted, filesystem_overhead_bytes)?,
        STREAMING_SCRATCH_RESERVE_BYTES,
    )?;
    Ok(StreamingScratchEstimate {
        raw_witness_bytes,
        persistent_oracle_bytes,
        peak_temporary_bytes,
        filesystem_overhead_bytes,
        reserve_bytes: STREAMING_SCRATCH_RESERVE_BYTES,
        required_available_bytes,
    })
}

/// Derive a conservative live-memory lower bound solely from program IR.
pub fn estimate_selected_prover_resources(
    program_encoded: &[u8],
) -> Result<ProverResourceEstimate, ResourcePreflightError> {
    let layouts = derive_oracle_commitment_layouts(
        program_encoded,
        TRACE_MASK_COEFFICIENT_COUNT,
        LOG_BLOWUP,
    )?;
    let main_evaluation_bytes = layout_bytes(&layouts.main_trace, EvaluationField::M31)?;
    let interaction_evaluation_bytes = layouts
        .interaction_trace
        .as_ref()
        .map(|layout| layout_bytes(layout, EvaluationField::Fp16))
        .transpose()?
        .unwrap_or(0);
    let composition_evaluation_bytes = layout_bytes(&layouts.composition, EvaluationField::Fp16)?;

    let main_as_extension = mul(main_evaluation_bytes, 16)?;
    let original_extension_bytes = add(
        add(main_as_extension, interaction_evaluation_bytes)?,
        composition_evaluation_bytes,
    )?;
    let deep_evaluation_bytes = mul(original_extension_bytes, 2)?;
    let fri_mask_bytes = layouts
        .main_trace
        .specs()
        .iter()
        .try_fold(0_u128, |total, spec| {
            add(total, mul(1_u128 << spec.log_size, 64)?)
        })?;
    let maximum_log = layouts
        .main_trace
        .maximum_log_size()
        .max(layouts.composition.maximum_log_size())
        .max(
            layouts
                .interaction_trace
                .as_ref()
                .map(|layout| layout.maximum_log_size())
                .unwrap_or(0),
        );
    let maximum_domain_rows = 1_u128 << maximum_log;
    let folded_layer_bytes = mul(maximum_domain_rows, 128)?;
    let monolithic_live_bytes_lower_bound = [
        main_evaluation_bytes,
        interaction_evaluation_bytes,
        composition_evaluation_bytes,
        deep_evaluation_bytes,
        fri_mask_bytes,
        folded_layer_bytes,
    ]
    .into_iter()
    .try_fold(0_u128, add)?;
    Ok(ProverResourceEstimate {
        main_evaluation_bytes,
        interaction_evaluation_bytes,
        composition_evaluation_bytes,
        deep_evaluation_bytes,
        fri_mask_bytes,
        folded_layer_bytes,
        monolithic_live_bytes_lower_bound,
        maximum_domain_rows,
        requires_streaming: monolithic_live_bytes_lower_bound > MONOLITHIC_PROVER_MEMORY_CAP_BYTES,
    })
}
