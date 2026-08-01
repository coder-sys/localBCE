//! Selected non-activating BL-PQ512 proof parameters.
//!
//! These constants are the deployment-shaped prototype parameters, not the
//! older R33 worksheet values.  Geometry is always re-derived from the
//! verifier-visible executable AIR.  Activation remains a separate audited
//! governance decision.

use core::fmt;

use alloc::vec::Vec;
use sha3::{Digest, Sha3_512};

use crate::air_ir::{AirIrError, parse_air_program};
use crate::oracle_commitment::{OracleCommitmentError, derive_oracle_commitment_layouts};

pub const SELECTED_PARAMETER_DOMAIN: &[u8] = b"BL/PQ512/WAVE1B/SELECTED-PROOF-PARAMETERS/v1\0";
pub const PROOF_SUITE_DOMAIN: &[u8] = b"BL/PQ512/PROOF-SUITE-ID/v1\0";
pub const PUBLIC_COIN_MAGIC: &[u8; 8] = b"BLPQPC01";
pub const PUBLIC_COIN_VERSION: u16 = 1;
pub const SELECTED_SCHEDULE_DOMAIN: u16 = 787;
pub const QUERY_DOMAIN: u16 = 784;
pub const PARAMETER_VERSION: u16 = 1;
pub const CHALLENGE_EXTENSION_DEGREE: u16 = 16;
pub const LOG_BLOWUP: u8 = 1;
pub const PER_TERM_SOUNDNESS_BITS: u16 = 256;
pub const QUERY_COUNT: usize = 945;
pub const OODS_QUERY_COUNT: usize = 1;
pub const REDUCED_AIR_DEGREE: usize = 2;
pub const TRACE_MASK_COEFFICIENT_COUNT: usize = 4_789;
pub const QUOTIENT_MASK_COEFFICIENT_COUNT: usize = 946;
pub const MINIMUM_TRACE_ROWS: usize = 8_192;
pub const UNIQUE_DECODING_SLACK_BITS: u16 = 32;
pub const THETA_NUMERATOR: u64 = 4_294_967_295;
pub const THETA_DENOMINATOR: u64 = 17_179_869_184;
pub const ACTIVATION_ALLOWED: bool = false;

// p = 2^31 - 1, so p^16 > 2^480. Reserving the current 256-bit floor permits
// numerators below 2^224 without relying on floating point or a bigint crate.
const CONSERVATIVE_NUMERATOR_BITS: u32 = 224;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedProofGeometry {
    pub program_binary_commitment: [u8; 64],
    pub maximum_evaluation_log_size: u8,
    pub query_domain_size: usize,
    pub fold_round_count: usize,
    pub original_fri_column_count: usize,
    pub degree_corrected_fri_column_count: usize,
    pub logup_numerator_bound: u128,
    pub composition_numerator_bound: u128,
    pub deep_numerator_bound: u128,
    pub fri_batch_numerator_bound: u128,
    pub fri_fold_numerator_bound: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProofParameterError {
    Air(AirIrError),
    Oracle(OracleCommitmentError),
    CountOverflow,
    DomainTooLarge,
    AlgebraicBudget,
    ZeroCommitment,
}

impl From<AirIrError> for ProofParameterError {
    fn from(value: AirIrError) -> Self {
        Self::Air(value)
    }
}

impl From<OracleCommitmentError> for ProofParameterError {
    fn from(value: OracleCommitmentError) -> Self {
        Self::Oracle(value)
    }
}

impl fmt::Display for ProofParameterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "BL-PQ512 selected proof parameter error: {self:?}"
        )
    }
}

impl core::error::Error for ProofParameterError {}

fn checked_add(left: u128, right: u128) -> Result<u128, ProofParameterError> {
    left.checked_add(right)
        .ok_or(ProofParameterError::CountOverflow)
}

fn checked_mul(left: u128, right: u128) -> Result<u128, ProofParameterError> {
    left.checked_mul(right)
        .ok_or(ProofParameterError::CountOverflow)
}

fn meets_algebraic_budget(numerator: u128) -> bool {
    numerator > 0 && 128 - numerator.leading_zeros() < CONSERVATIVE_NUMERATOR_BITS
}

pub fn selected_parameter_bytes() -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(SELECTED_PARAMETER_DOMAIN);
    encoded.extend_from_slice(&PARAMETER_VERSION.to_be_bytes());
    encoded.extend_from_slice(&((1_u64 << 31) - 1).to_be_bytes());
    encoded.extend_from_slice(&CHALLENGE_EXTENSION_DEGREE.to_be_bytes());
    encoded.push(LOG_BLOWUP);
    encoded.extend_from_slice(&PER_TERM_SOUNDNESS_BITS.to_be_bytes());
    encoded.extend_from_slice(&(QUERY_COUNT as u32).to_be_bytes());
    encoded.extend_from_slice(&(OODS_QUERY_COUNT as u16).to_be_bytes());
    encoded.extend_from_slice(&(REDUCED_AIR_DEGREE as u16).to_be_bytes());
    encoded.extend_from_slice(&(TRACE_MASK_COEFFICIENT_COUNT as u32).to_be_bytes());
    encoded.extend_from_slice(&(QUOTIENT_MASK_COEFFICIENT_COUNT as u32).to_be_bytes());
    encoded.extend_from_slice(&(MINIMUM_TRACE_ROWS as u32).to_be_bytes());
    encoded.extend_from_slice(&UNIQUE_DECODING_SLACK_BITS.to_be_bytes());
    encoded.extend_from_slice(&THETA_NUMERATOR.to_be_bytes());
    encoded.extend_from_slice(&THETA_DENOMINATOR.to_be_bytes());
    encoded.push(u8::from(ACTIVATION_ALLOWED));
    encoded
}

pub fn selected_parameter_commitment() -> [u8; 64] {
    Sha3_512::digest(selected_parameter_bytes()).into()
}

fn transcript_digest(domain: u16, parts: &[&[u8]]) -> Result<[u8; 64], ProofParameterError> {
    let mut hash = Sha3_512::new();
    hash.update(PUBLIC_COIN_MAGIC);
    hash.update(PUBLIC_COIN_VERSION.to_be_bytes());
    hash.update(domain.to_be_bytes());
    for part in parts {
        let length = u32::try_from(part.len()).map_err(|_| ProofParameterError::CountOverflow)?;
        hash.update(length.to_be_bytes());
        hash.update(part);
    }
    Ok(hash.finalize().into())
}

fn descriptor(kind: u16, ordinal: u16, output_kind: u16, output_count: u16) -> [u8; 8] {
    let mut encoded = [0_u8; 8];
    encoded[..2].copy_from_slice(&kind.to_be_bytes());
    encoded[2..4].copy_from_slice(&ordinal.to_be_bytes());
    encoded[4..6].copy_from_slice(&output_kind.to_be_bytes());
    encoded[6..].copy_from_slice(&output_count.to_be_bytes());
    encoded
}

pub fn selected_schedule_commitment(
    program_binary_commitment: &[u8; 64],
    geometry: SelectedProofGeometry,
) -> Result<[u8; 64], ProofParameterError> {
    if !program_binary_commitment.iter().any(|byte| *byte != 0)
        || geometry.fold_round_count == 0
        || geometry.fold_round_count > 29
    {
        return Err(ProofParameterError::ZeroCommitment);
    }
    let parameter = selected_parameter_commitment();
    let query_domain = (geometry.query_domain_size as u64).to_be_bytes();
    let query_count = (QUERY_COUNT as u32).to_be_bytes();
    let replacement = [1_u8];
    let attempts = 1_u16.to_be_bytes();
    let fold_count = (geometry.fold_round_count as u16).to_be_bytes();
    let mut descriptors = Vec::with_capacity(geometry.fold_round_count + 5);
    descriptors.push(descriptor(1, 0, 1, 2));
    descriptors.push(descriptor(2, 0, 1, 1));
    descriptors.push(descriptor(3, 0, 1, 1));
    descriptors.push(descriptor(4, 0, 1, 1));
    for ordinal in 0..geometry.fold_round_count {
        descriptors.push(descriptor(5, ordinal as u16, 1, 1));
    }
    descriptors.push(descriptor(6, 0, 2, 1));
    let mut parts = Vec::<&[u8]>::with_capacity(descriptors.len() + 8);
    parts.extend_from_slice(&[
        &parameter,
        program_binary_commitment,
        &query_domain,
        &query_count,
        &replacement,
        &attempts,
        &fold_count,
    ]);
    parts.extend(descriptors.iter().map(|value| value.as_slice()));
    transcript_digest(SELECTED_SCHEDULE_DOMAIN, &parts)
}

pub fn selected_query_positions(
    session_id: &[u8; 64],
    query_seed: &[u8; 64],
    domain_size: usize,
) -> Result<Vec<usize>, ProofParameterError> {
    if !session_id.iter().any(|byte| *byte != 0)
        || !(2..=1_usize << 30).contains(&domain_size)
        || !domain_size.is_power_of_two()
    {
        return Err(ProofParameterError::DomainTooLarge);
    }
    let mut positions = Vec::with_capacity(QUERY_COUNT);
    for draw in 0..QUERY_COUNT {
        let draw_bytes = (draw as u32).to_be_bytes();
        let attempt = 0_u16.to_be_bytes();
        let digest = transcript_digest(
            QUERY_DOMAIN,
            &[session_id, query_seed, &draw_bytes, &attempt],
        )?;
        let mut low = [0_u8; core::mem::size_of::<usize>()];
        let start = digest.len() - low.len();
        low.copy_from_slice(&digest[start..]);
        positions.push(usize::from_be_bytes(low) & (domain_size - 1));
    }
    Ok(positions)
}

/// Derive and enforce the selected theorem geometry from program-only IR.
pub fn selected_proof_geometry(
    program_encoded: &[u8],
) -> Result<SelectedProofGeometry, ProofParameterError> {
    let program = parse_air_program(program_encoded)?;
    let layouts = derive_oracle_commitment_layouts(
        program_encoded,
        TRACE_MASK_COEFFICIENT_COUNT,
        LOG_BLOWUP,
    )?;
    if layouts
        .tables
        .iter()
        .any(|table| table.trace_rows < MINIMUM_TRACE_ROWS)
    {
        return Err(ProofParameterError::AlgebraicBudget);
    }
    let maximum_log = layouts
        .tables
        .iter()
        .map(|table| table.evaluation_log_size)
        .max()
        .ok_or(ProofParameterError::CountOverflow)?;
    if !(2..=30).contains(&maximum_log) {
        return Err(ProofParameterError::DomainTooLarge);
    }
    let query_domain_size = 1_usize
        .checked_shl(u32::from(maximum_log))
        .ok_or(ProofParameterError::DomainTooLarge)?;
    let main_columns = layouts
        .main_trace
        .specs()
        .iter()
        .try_fold(0_usize, |sum, spec| {
            sum.checked_add(spec.column_count as usize)
                .ok_or(ProofParameterError::CountOverflow)
        })?;
    let interaction_columns = layouts
        .interaction_trace
        .as_ref()
        .map(|layout| {
            layout.specs().iter().try_fold(0_usize, |sum, spec| {
                sum.checked_add(spec.column_count as usize)
                    .ok_or(ProofParameterError::CountOverflow)
            })
        })
        .transpose()?
        .unwrap_or(0);
    let composition_columns =
        layouts
            .composition
            .specs()
            .iter()
            .try_fold(0_usize, |sum, spec| {
                sum.checked_add(spec.column_count as usize)
                    .ok_or(ProofParameterError::CountOverflow)
            })?;
    let original_columns = main_columns
        .checked_add(interaction_columns)
        .and_then(|value| value.checked_add(composition_columns))
        .ok_or(ProofParameterError::CountOverflow)?;
    let corrected_columns = original_columns
        .checked_mul(2)
        .ok_or(ProofParameterError::CountOverflow)?;

    let total_trace_columns = program.tables.iter().try_fold(0_u128, |sum, table| {
        checked_add(sum, table.columns.len() as u128)
    })?;
    let maximum_lookup_width = program
        .lookups
        .iter()
        .flat_map(|lookup| lookup.sources.iter().chain(&lookup.destinations))
        .map(|side| side.values.len() as u128)
        .max()
        .unwrap_or(1);
    let logup_rows = program
        .lookups
        .iter()
        .try_fold(0_u128, |lookup_sum, lookup| {
            lookup
                .sources
                .iter()
                .chain(&lookup.destinations)
                .try_fold(lookup_sum, |sum, side| {
                    checked_add(
                        sum,
                        checked_mul(
                            (side.values.len() as u128) + 2,
                            (side.row_stop - side.row_start) as u128,
                        )?,
                    )
                })
        })?;
    let logup_numerator = checked_add(
        checked_mul(maximum_lookup_width, total_trace_columns)?,
        logup_rows,
    )?;
    let composition_numerator = checked_add(
        2,
        program
            .tables
            .iter()
            .enumerate()
            .try_fold(0_u128, |maximum, (table_index, table)| {
                let touching_sides = program
                    .lookups
                    .iter()
                    .flat_map(|lookup| lookup.sources.iter().chain(&lookup.destinations))
                    .filter(|side| side.table == table_index)
                    .count() as u128;
                Ok::<u128, ProofParameterError>(
                    maximum.max(table.columns.len() as u128 + touching_sides),
                )
            })?,
    )?;
    let maximum_degree = program
        .tables
        .iter()
        .flat_map(|table| &table.identities)
        .map(|identity| identity.expression.degree())
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .unwrap_or(1) as u128;
    let maximum_trace_rows = layouts
        .tables
        .iter()
        .map(|table| table.trace_rows as u128)
        .max()
        .ok_or(ProofParameterError::CountOverflow)?;
    let deep_numerator = checked_add(1, checked_mul(maximum_degree, maximum_trace_rows)?)?;
    let fri_batch_numerator = checked_mul(
        corrected_columns.saturating_sub(1) as u128,
        query_domain_size as u128,
    )?;
    let fold_domain_sum =
        (2..=maximum_log).try_fold(0_u128, |sum, log| checked_add(sum, 1_u128 << log))?;
    let fri_fold_numerator = checked_mul(3, fold_domain_sum)?;
    if [
        logup_numerator,
        composition_numerator,
        deep_numerator,
        fri_batch_numerator,
        fri_fold_numerator,
    ]
    .into_iter()
    .any(|numerator| !meets_algebraic_budget(numerator))
    {
        return Err(ProofParameterError::AlgebraicBudget);
    }

    Ok(SelectedProofGeometry {
        program_binary_commitment: layouts.program_binary_commitment,
        maximum_evaluation_log_size: maximum_log,
        query_domain_size,
        fold_round_count: usize::from(maximum_log - 1),
        original_fri_column_count: original_columns,
        degree_corrected_fri_column_count: corrected_columns,
        logup_numerator_bound: logup_numerator,
        composition_numerator_bound: composition_numerator,
        deep_numerator_bound: deep_numerator,
        fri_batch_numerator_bound: fri_batch_numerator,
        fri_fold_numerator_bound: fri_fold_numerator,
    })
}

pub fn proof_suite_id(
    program_binary_commitment: &[u8; 64],
    public_coin_schedule_commitment: &[u8; 64],
) -> Result<[u8; 64], ProofParameterError> {
    if !program_binary_commitment.iter().any(|byte| *byte != 0)
        || !public_coin_schedule_commitment
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(ProofParameterError::ZeroCommitment);
    }
    let mut hash = Sha3_512::new();
    hash.update(PROOF_SUITE_DOMAIN);
    hash.update(selected_parameter_commitment());
    hash.update(program_binary_commitment);
    hash.update(public_coin_schedule_commitment);
    Ok(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_hiding_counts_and_parameter_commitment_are_stable() {
        assert_eq!(
            TRACE_MASK_COEFFICIENT_COUNT,
            2 * REDUCED_AIR_DEGREE
                * (CHALLENGE_EXTENSION_DEGREE as usize * OODS_QUERY_COUNT + QUERY_COUNT)
                + QUERY_COUNT
        );
        assert_eq!(
            QUOTIENT_MASK_COEFFICIENT_COUNT,
            OODS_QUERY_COUNT + QUERY_COUNT
        );
        assert!(MINIMUM_TRACE_ROWS.is_power_of_two());
        const { assert!(MINIMUM_TRACE_ROWS >= TRACE_MASK_COEFFICIENT_COUNT) };
        assert_eq!(selected_parameter_bytes().len(), 99);
        assert_ne!(selected_parameter_commitment(), [0_u8; 64]);
    }

    #[test]
    fn suite_id_binds_program_and_schedule_and_rejects_zero() {
        let first = proof_suite_id(&[1_u8; 64], &[2_u8; 64]).unwrap();
        assert_ne!(first, proof_suite_id(&[3_u8; 64], &[2_u8; 64]).unwrap());
        assert_ne!(first, proof_suite_id(&[1_u8; 64], &[4_u8; 64]).unwrap());
        assert_eq!(
            proof_suite_id(&[0_u8; 64], &[2_u8; 64]),
            Err(ProofParameterError::ZeroCommitment)
        );
    }
}
