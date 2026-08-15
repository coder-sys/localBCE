//! Authenticated Fp8-conjugate-pair DEEP quotient oracle construction.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use sha3::{Digest, Sha3_512};

use crate::air_composition::AirCompositionOracle;
use crate::air_logup::AirLogupOracle;
use crate::binding_root_v2::{BindingDigestV2, BindingRoleV2, BindingRootV2};
use crate::circle_fft::{
    CircleFftError, evaluate_extension_coefficients_at_point,
    interpolate_extension_circle_evaluation_columns,
};
use crate::circle_fri::{
    CircleFriError, DegreeCorrectionPlan, FriDomainBatch, bit_reverse_index, canonic_circle_point,
    conjugate_pair_zeroifier, degree_corrected_row_with_plan,
};
use crate::cross_domain::{
    CommitmentStage, CrossDomainError, CrossDomainLayout, DomainSpec, EvaluationField,
};
use crate::field::{Fp16, batch_inverse_fp16};
use crate::oods::CirclePoint;

pub const DEEP_QUOTIENT_COMMITMENT_DOMAIN: &[u8] = b"BL/PQ512/WAVE1B/DEEP-QUOTIENT-COMMITMENT/v1\0";
pub const DEEP_CLAIMS_DOMAIN: &[u8] = b"BL/PQ512/WAVE1B/DEEP-CLAIMS/v1\0";
pub const DEEP_CLAIMS_BINDING_V2_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/DEEP-CLAIMS/BINDING-ROOT-V2/v2\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainOodsClaims {
    pub log_size: u8,
    pub values: Vec<Fp16>,
    pub conjugate_values: Vec<Fp16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeepQuotientOracles {
    pub query: CirclePoint,
    pub claims: Vec<DomainOodsClaims>,
    pub batches: Vec<FriDomainBatch>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeepQuotientError {
    CircleFft(CircleFftError),
    CircleFri(CircleFriError),
    CrossDomain(CrossDomainError),
    QueryNotOnCircle,
    QueryInFixedSubfield,
    Shape,
    CountOverflow,
}

impl From<CircleFftError> for DeepQuotientError {
    fn from(value: CircleFftError) -> Self {
        Self::CircleFft(value)
    }
}
impl From<CircleFriError> for DeepQuotientError {
    fn from(value: CircleFriError) -> Self {
        Self::CircleFri(value)
    }
}
impl From<CrossDomainError> for DeepQuotientError {
    fn from(value: CrossDomainError) -> Self {
        Self::CrossDomain(value)
    }
}

fn grouped_columns(
    composition: &AirCompositionOracle,
    logup: &AirLogupOracle,
) -> BTreeMap<u8, Vec<Vec<Fp16>>> {
    let mut groups = BTreeMap::<u8, Vec<Vec<Fp16>>>::new();
    for table in &composition.tables {
        let columns = groups.entry(table.evaluation_log_size).or_default();
        columns.extend(table.committed_column_indices.iter().map(|index| {
            table.trace_columns[*index]
                .iter()
                .copied()
                .map(Fp16::from_m31)
                .collect::<Vec<_>>()
        }));
    }
    for interaction in &logup.interactions {
        let columns = groups.entry(interaction.evaluation_log_size).or_default();
        columns.extend(interaction.masked_inverse_evaluations.clone());
        columns.push(interaction.masked_accumulator_evaluations.clone());
    }
    for table in &composition.tables {
        if let Some(components) = &table.composition_components {
            groups
                .entry(table.evaluation_log_size)
                .or_default()
                .extend(components.iter().cloned());
        }
    }
    groups
}

fn claims_at(
    columns: &[Vec<Fp16>],
    query: CirclePoint,
) -> Result<(Vec<Fp16>, Vec<Fp16>), DeepQuotientError> {
    let conjugate = CirclePoint {
        x: query.x.conjugate(),
        y: query.y.conjugate(),
    };
    let mut values = Vec::with_capacity(columns.len());
    let mut conjugate_values = Vec::with_capacity(columns.len());
    let coefficient_columns = interpolate_extension_circle_evaluation_columns(columns)?;
    for coefficients in &coefficient_columns {
        values.push(evaluate_extension_coefficients_at_point(
            coefficients,
            query,
        )?);
        conjugate_values.push(evaluate_extension_coefficients_at_point(
            coefficients,
            conjugate,
        )?);
    }
    Ok((values, conjugate_values))
}

fn degree_corrected_batch_rows(
    domain_points: &[crate::circle_fri::BaseCirclePoint],
    zeroifier_inverses: &[Fp16],
    columns: &[Vec<Fp16>],
    correction_plan: &DegreeCorrectionPlan,
) -> Result<Vec<Vec<Fp16>>, DeepQuotientError> {
    if domain_points.len() != zeroifier_inverses.len() {
        return Err(DeepQuotientError::Shape);
    }
    let build_range = |start: usize, stop: usize| {
        (start..stop)
            .map(|fft_index| {
                let originals = columns
                    .iter()
                    .map(|column| column[fft_index])
                    .collect::<Vec<_>>();
                Ok(degree_corrected_row_with_plan(
                    domain_points[fft_index],
                    &originals,
                    zeroifier_inverses[fft_index],
                    correction_plan,
                )?
                .fri_batch_values())
            })
            .collect::<Result<Vec<_>, DeepQuotientError>>()
    };
    #[cfg(feature = "parallel")]
    if domain_points.len() >= 1 << 12 {
        let workers = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
            .min(domain_points.len());
        if workers > 1 {
            let chunk_size = domain_points.len().div_ceil(workers);
            let pieces = std::thread::scope(|scope| {
                let handles = (0..domain_points.len())
                    .step_by(chunk_size)
                    .map(|start| {
                        let stop = (start + chunk_size).min(domain_points.len());
                        let build_range = &build_range;
                        scope.spawn(move || build_range(start, stop))
                    })
                    .collect::<Vec<_>>();
                handles
                    .into_iter()
                    .map(|handle| handle.join().map_err(|_| DeepQuotientError::Shape)?)
                    .collect::<Result<Vec<_>, _>>()
            })?;
            return Ok(pieces.into_iter().flatten().collect());
        }
    }
    build_range(0, domain_points.len())
}

fn commitment_id(
    program_binary_commitment: &[u8; 64],
    claims: &[DomainOodsClaims],
) -> Result<[u8; 64], DeepQuotientError> {
    let mut hash = Sha3_512::new();
    hash.update(DEEP_QUOTIENT_COMMITMENT_DOMAIN);
    hash.update(program_binary_commitment);
    hash.update(
        u32::try_from(claims.len())
            .map_err(|_| DeepQuotientError::CountOverflow)?
            .to_be_bytes(),
    );
    for claim in claims {
        hash.update([claim.log_size]);
        hash.update(
            u32::try_from(claim.values.len())
                .map_err(|_| DeepQuotientError::CountOverflow)?
                .to_be_bytes(),
        );
        for value in claim.values.iter().chain(&claim.conjugate_values) {
            hash.update(value.encode());
        }
    }
    Ok(hash.finalize().into())
}

/// Bind OODS claims to the exact public oracle roots without committing a
/// duplicate original-plus-derived-quotient evaluation tree.
pub fn deep_claims_commitment(
    program_binary_commitment: &[u8; 64],
    query: CirclePoint,
    claims: &[DomainOodsClaims],
    main_root: &[u8; 64],
    interaction_root: Option<&[u8; 64]>,
    composition_root: &[u8; 64],
) -> Result<[u8; 64], DeepQuotientError> {
    if claims.is_empty()
        || claims
            .windows(2)
            .any(|pair| pair[0].log_size >= pair[1].log_size)
        || claims.iter().any(|claim| {
            claim.values.is_empty() || claim.values.len() != claim.conjugate_values.len()
        })
    {
        return Err(DeepQuotientError::Shape);
    }
    let mut hash = Sha3_512::new();
    hash.update(DEEP_CLAIMS_DOMAIN);
    hash.update(program_binary_commitment);
    hash.update(main_root);
    hash.update([u8::from(interaction_root.is_some())]);
    if let Some(root) = interaction_root {
        hash.update(root);
    }
    hash.update(composition_root);
    hash.update(query.x.encode());
    hash.update(query.y.encode());
    hash.update(
        u32::try_from(claims.len())
            .map_err(|_| DeepQuotientError::CountOverflow)?
            .to_be_bytes(),
    );
    for claim in claims {
        hash.update([claim.log_size]);
        hash.update(
            u32::try_from(claim.values.len())
                .map_err(|_| DeepQuotientError::CountOverflow)?
                .to_be_bytes(),
        );
        for value in claim.values.iter().chain(&claim.conjugate_values) {
            hash.update(value.encode());
        }
    }
    Ok(hash.finalize().into())
}

/// Bind OODS claims to native 128-byte BindingRootV2 oracle roots.
///
/// This parallel selected-v3 commitment never accepts or wraps a legacy
/// 64-byte Merkle/oracle root.
pub fn deep_claims_commitment_binding_v2(
    program_binary_commitment: &[u8; 64],
    query: CirclePoint,
    claims: &[DomainOodsClaims],
    main_root: &BindingRootV2,
    interaction_root: Option<&BindingRootV2>,
    composition_root: &BindingRootV2,
) -> Result<BindingDigestV2, DeepQuotientError> {
    if claims.is_empty()
        || claims
            .windows(2)
            .any(|pair| pair[0].log_size >= pair[1].log_size)
        || claims.iter().any(|claim| {
            claim.values.is_empty() || claim.values.len() != claim.conjugate_values.len()
        })
    {
        return Err(DeepQuotientError::Shape);
    }
    let mut payload = Vec::new();
    payload.extend_from_slice(DEEP_CLAIMS_BINDING_V2_DOMAIN);
    payload.extend_from_slice(program_binary_commitment);
    payload.extend_from_slice(main_root.as_bytes());
    payload.push(u8::from(interaction_root.is_some()));
    if let Some(root) = interaction_root {
        payload.extend_from_slice(root.as_bytes());
    }
    payload.extend_from_slice(composition_root.as_bytes());
    payload.extend_from_slice(&query.x.encode());
    payload.extend_from_slice(&query.y.encode());
    payload.extend_from_slice(
        &u32::try_from(claims.len())
            .map_err(|_| DeepQuotientError::CountOverflow)?
            .to_be_bytes(),
    );
    for claim in claims {
        payload.push(claim.log_size);
        payload.extend_from_slice(
            &u32::try_from(claim.values.len())
                .map_err(|_| DeepQuotientError::CountOverflow)?
                .to_be_bytes(),
        );
        for value in claim.values.iter().chain(&claim.conjugate_values) {
            payload.extend_from_slice(&value.encode());
        }
    }
    BindingDigestV2::hash(BindingRoleV2::Payload, &payload)
        .map_err(|_| DeepQuotientError::CountOverflow)
}

/// Derive the verifier-authoritative DEEP layout only from the public program
/// commitment and the two-point claims fixed before FRI batching.
pub fn deep_quotient_layout(
    program_binary_commitment: &[u8; 64],
    claims: &[DomainOodsClaims],
) -> Result<CrossDomainLayout, DeepQuotientError> {
    if claims.is_empty()
        || claims
            .windows(2)
            .any(|pair| pair[0].log_size >= pair[1].log_size)
        || claims.iter().any(|claim| {
            claim.values.is_empty() || claim.values.len() != claim.conjugate_values.len()
        })
    {
        return Err(DeepQuotientError::Shape);
    }
    let specs = claims
        .iter()
        .map(|claim| {
            let columns = claim
                .values
                .len()
                .checked_mul(2)
                .ok_or(DeepQuotientError::CountOverflow)?;
            DomainSpec::new(
                claim.log_size,
                EvaluationField::Fp16,
                u32::try_from(columns).map_err(|_| DeepQuotientError::CountOverflow)?,
            )
            .map_err(DeepQuotientError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CrossDomainLayout::new(
        CommitmentStage::DeepQuotient,
        commitment_id(program_binary_commitment, claims)?,
        specs,
    )?)
}

/// Derive OODS claims and original-plus-derived-quotient FRI rows.
///
/// These rows are intentionally not committed a second time. Their originals
/// are authenticated by the native oracle roots and their quotient halves are
/// deterministically recomputed by the verifier.
pub fn build_deep_quotient_oracles(
    composition: &AirCompositionOracle,
    logup: &AirLogupOracle,
    query: CirclePoint,
) -> Result<DeepQuotientOracles, DeepQuotientError> {
    if query.x.square().add(query.y.square()) != Fp16::ONE {
        return Err(DeepQuotientError::QueryNotOnCircle);
    }
    if query.x.is_in_fp8_subfield() && query.y.is_in_fp8_subfield() {
        return Err(DeepQuotientError::QueryInFixedSubfield);
    }
    if composition.lookup_count_pending_logup != 0 {
        return Err(DeepQuotientError::Shape);
    }
    if composition
        .tables
        .iter()
        .any(|table| table.composition_components.is_none())
    {
        return Err(DeepQuotientError::Shape);
    }
    let groups = grouped_columns(composition, logup);
    if groups.is_empty() || groups.values().any(Vec::is_empty) {
        return Err(DeepQuotientError::Shape);
    }
    let mut claims = Vec::with_capacity(groups.len());
    let mut ascending_batches = Vec::with_capacity(groups.len());
    for (log_size, columns) in &groups {
        let rows = 1_usize << *log_size;
        if columns.iter().any(|column| column.len() != rows) {
            return Err(DeepQuotientError::Shape);
        }
        let (values, conjugate_values) = claims_at(columns, query)?;
        let domain_points = (0..rows)
            .map(|fft_index| {
                let natural_index = bit_reverse_index(fft_index, *log_size)?;
                canonic_circle_point(*log_size, natural_index).map_err(DeepQuotientError::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let zeroifiers = domain_points
            .iter()
            .copied()
            .map(|point| conjugate_pair_zeroifier(point, query))
            .collect::<Result<Vec<_>, _>>()?;
        let zeroifier_inverses =
            batch_inverse_fp16(&zeroifiers).map_err(|_| DeepQuotientError::Shape)?;
        let correction_plan = DegreeCorrectionPlan::new(query, &values, &conjugate_values)?;
        let batch_rows = degree_corrected_batch_rows(
            &domain_points,
            &zeroifier_inverses,
            columns,
            &correction_plan,
        )?;
        claims.push(DomainOodsClaims {
            log_size: *log_size,
            values,
            conjugate_values,
        });
        ascending_batches.push(FriDomainBatch::new(*log_size, batch_rows)?);
    }
    ascending_batches.reverse();
    Ok(DeepQuotientOracles {
        query,
        claims,
        batches: ascending_batches,
    })
}
