//! Typed SHA3-512 commitments for complete main, interaction, and composition oracles.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use sha3::{Digest, Sha3_512};

use crate::air_composition::{AirCompositionOracle, AirMainTraceOracle};
use crate::air_ir::{AIR_PROGRAM_DOMAIN, AirIrError, parse_air_program};
use crate::air_logup::AirLogupOracle;
use crate::binding_root_v2::{BindingDigestV2, BindingRoleV2, BindingRootV2, BindingRootV2Error};
use crate::cross_domain::{
    BindingCrossDomainTreeV2, CommitmentStage, CrossDomainError, CrossDomainLayout,
    CrossDomainTree, DomainEvaluationBatch, DomainSpec, EvaluationField,
};
use crate::field::{Fp16, M31};

pub const ORACLE_COMMITMENT_ID_DOMAIN: &[u8] = b"BL/PQ512/WAVE1B/ORACLE-COMMITMENT-ID/v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedAirOracles {
    pub main_trace: CrossDomainTree,
    pub interaction_trace: Option<CrossDomainTree>,
    pub composition: CrossDomainTree,
}

/// Parallel native BindingRootV2 commitments for the selected-v3 path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingCommittedAirOraclesV2 {
    pub main_trace: BindingCrossDomainTreeV2,
    pub interaction_trace: Option<BindingCrossDomainTreeV2>,
    pub composition: BindingCrossDomainTreeV2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleCommitmentLayouts {
    pub program_binary_commitment: [u8; 64],
    pub main_trace: CrossDomainLayout,
    pub interaction_trace: Option<CrossDomainLayout>,
    pub composition: CrossDomainLayout,
    pub tables: Vec<OracleTableGeometry>,
    pub interactions: Vec<OracleInteractionGeometry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OracleTableGeometry {
    pub table_index: usize,
    pub trace_rows: usize,
    pub trace_log_size: u8,
    pub evaluation_log_size: u8,
    pub composition_work_log_size: u8,
    pub component_coefficient_log_size: u8,
    pub composition_component_count: usize,
    pub main_column_offset: usize,
    pub main_column_count: usize,
    pub composition_column_offset: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OracleInteractionGeometry {
    pub lookup_index: usize,
    pub table_index: usize,
    pub evaluation_log_size: u8,
    pub interaction_column_offset: usize,
    pub side_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommittedAirRoots {
    pub main_trace: crate::cross_domain::CrossDomainRoot,
    pub interaction_trace: Option<crate::cross_domain::CrossDomainRoot>,
    pub composition: crate::cross_domain::CrossDomainRoot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindingCommittedAirRootsV2 {
    pub main_trace: BindingRootV2,
    pub interaction_trace: Option<BindingRootV2>,
    pub composition: BindingRootV2,
}

impl CommittedAirOracles {
    pub const fn roots(&self) -> CommittedAirRoots {
        CommittedAirRoots {
            main_trace: self.main_trace.root(),
            interaction_trace: match &self.interaction_trace {
                Some(tree) => Some(tree.root()),
                None => None,
            },
            composition: self.composition.root(),
        }
    }

    /// Recommit the exact oracle row packets with native BindingRootV2 trees.
    /// Legacy roots are neither copied nor hashed into these commitments.
    pub fn binding_v2(
        &self,
        program_encoded: &[u8],
        mask_coefficient_count: usize,
        log_blowup: u8,
    ) -> Result<BindingCommittedAirOraclesV2, OracleCommitmentError> {
        let legacy =
            derive_oracle_commitment_layouts(program_encoded, mask_coefficient_count, log_blowup)?;
        let native = derive_binding_oracle_commitment_layouts_v2(
            program_encoded,
            mask_coefficient_count,
            log_blowup,
        )?;
        if self.main_trace.layout() != &legacy.main_trace
            || self.interaction_trace.as_ref().map(CrossDomainTree::layout)
                != legacy.interaction_trace.as_ref()
            || self.composition.layout() != &legacy.composition
        {
            return Err(OracleCommitmentError::Shape);
        }
        Ok(BindingCommittedAirOraclesV2 {
            main_trace: self.main_trace.binding_v2_tree(native.main_trace.clone())?,
            interaction_trace: match (&self.interaction_trace, native.interaction_trace) {
                (Some(source), Some(layout)) => Some(source.binding_v2_tree(layout)?),
                (None, None) => None,
                _ => return Err(OracleCommitmentError::Shape),
            },
            composition: self.composition.binding_v2_tree(native.composition)?,
        })
    }
}

impl BindingCommittedAirOraclesV2 {
    pub const fn roots(&self) -> BindingCommittedAirRootsV2 {
        BindingCommittedAirRootsV2 {
            main_trace: self.main_trace.root(),
            interaction_trace: match &self.interaction_trace {
                Some(tree) => Some(tree.root()),
                None => None,
            },
            composition: self.composition.root(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OracleCommitmentError {
    Air(AirIrError),
    Binding(BindingRootV2Error),
    CrossDomain(CrossDomainError),
    Shape,
    CountOverflow,
}

impl From<BindingRootV2Error> for OracleCommitmentError {
    fn from(value: BindingRootV2Error) -> Self {
        Self::Binding(value)
    }
}

impl From<AirIrError> for OracleCommitmentError {
    fn from(value: AirIrError) -> Self {
        Self::Air(value)
    }
}

impl From<CrossDomainError> for OracleCommitmentError {
    fn from(value: CrossDomainError) -> Self {
        Self::CrossDomain(value)
    }
}

fn commitment_id(
    program_commitment: &[u8; 64],
    stage: CommitmentStage,
    groups: &[(u8, usize)],
) -> Result<[u8; 64], OracleCommitmentError> {
    let mut hash = Sha3_512::new();
    hash.update(ORACLE_COMMITMENT_ID_DOMAIN);
    hash.update(program_commitment);
    hash.update((stage as u16).to_be_bytes());
    hash.update(
        u32::try_from(groups.len())
            .map_err(|_| OracleCommitmentError::CountOverflow)?
            .to_be_bytes(),
    );
    for (log_size, columns) in groups {
        hash.update([*log_size]);
        hash.update(
            u32::try_from(*columns)
                .map_err(|_| OracleCommitmentError::CountOverflow)?
                .to_be_bytes(),
        );
    }
    Ok(hash.finalize().into())
}

fn layout_from_counts(
    program_commitment: &[u8; 64],
    stage: CommitmentStage,
    counts: &BTreeMap<u8, usize>,
    field: EvaluationField,
) -> Result<Option<CrossDomainLayout>, OracleCommitmentError> {
    if counts.is_empty() {
        return Ok(None);
    }
    let groups = counts
        .iter()
        .map(|(log, count)| (*log, *count))
        .collect::<Vec<_>>();
    let specs = groups
        .iter()
        .map(|(log, count)| {
            DomainSpec::new(
                *log,
                field,
                u32::try_from(*count).map_err(|_| OracleCommitmentError::CountOverflow)?,
            )
            .map_err(OracleCommitmentError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(CrossDomainLayout::new(
        stage,
        commitment_id(program_commitment, stage, &groups)?,
        specs,
    )?))
}

const ORACLE_COMMITMENT_BINDING_V2_DOMAIN: &[u8] =
    b"BL/PQ512/WAVE2/ORACLE-COMMITMENT-BINDING-V2/v1\0";

fn binding_layout_from_legacy(
    program_encoded: &[u8],
    legacy: &CrossDomainLayout,
) -> Result<CrossDomainLayout, OracleCommitmentError> {
    if legacy.binding_commitment_id().is_some() {
        return Err(OracleCommitmentError::Shape);
    }
    let mut frame = Vec::with_capacity(
        ORACLE_COMMITMENT_BINDING_V2_DOMAIN.len()
            + 8
            + program_encoded.len()
            + 2
            + 4
            + legacy.specs().len() * 8,
    );
    frame.extend_from_slice(ORACLE_COMMITMENT_BINDING_V2_DOMAIN);
    frame.extend_from_slice(
        &u64::try_from(program_encoded.len())
            .map_err(|_| OracleCommitmentError::CountOverflow)?
            .to_be_bytes(),
    );
    frame.extend_from_slice(program_encoded);
    frame.extend_from_slice(&(legacy.stage() as u16).to_be_bytes());
    frame.extend_from_slice(
        &u32::try_from(legacy.specs().len())
            .map_err(|_| OracleCommitmentError::CountOverflow)?
            .to_be_bytes(),
    );
    for spec in legacy.specs() {
        frame.push(spec.log_size);
        frame.push(spec.field as u8);
        frame.extend_from_slice(&0_u16.to_be_bytes());
        frame.extend_from_slice(&spec.column_count.to_be_bytes());
    }
    let descriptor = BindingDigestV2::hash(BindingRoleV2::Payload, &frame)?;
    Ok(CrossDomainLayout::new_binding_v2(
        legacy.stage(),
        descriptor,
        legacy.specs().to_vec(),
    )?)
}

/// Derive the verifier-authoritative native-v2 oracle layouts directly from
/// the exact AIR program bytes. The 128-byte descriptors bind the program,
/// stage, ordered domains, fields, and column counts; no legacy root or
/// 64-byte layout digest is promoted into native proof authority.
pub fn derive_binding_oracle_commitment_layouts_v2(
    program_encoded: &[u8],
    mask_coefficient_count: usize,
    log_blowup: u8,
) -> Result<OracleCommitmentLayouts, OracleCommitmentError> {
    let legacy =
        derive_oracle_commitment_layouts(program_encoded, mask_coefficient_count, log_blowup)?;
    Ok(OracleCommitmentLayouts {
        program_binary_commitment: legacy.program_binary_commitment,
        main_trace: binding_layout_from_legacy(program_encoded, &legacy.main_trace)?,
        interaction_trace: legacy
            .interaction_trace
            .as_ref()
            .map(|layout| binding_layout_from_legacy(program_encoded, layout))
            .transpose()?,
        composition: binding_layout_from_legacy(program_encoded, &legacy.composition)?,
        tables: legacy.tables,
        interactions: legacy.interactions,
    })
}

/// Derive all verifier-authoritative oracle layouts from program-only IR and
/// explicit hiding/domain parameters. No witness shape is trusted.
pub fn derive_oracle_commitment_layouts(
    program_encoded: &[u8],
    mask_coefficient_count: usize,
    log_blowup: u8,
) -> Result<OracleCommitmentLayouts, OracleCommitmentError> {
    if mask_coefficient_count == 0 || log_blowup == 0 {
        return Err(OracleCommitmentError::Shape);
    }
    let program = parse_air_program(program_encoded)?;
    let mut hash = Sha3_512::new();
    hash.update(AIR_PROGRAM_DOMAIN);
    hash.update(program_encoded);
    let program_binary_commitment = hash.finalize().into();
    let mask_size = mask_coefficient_count.next_power_of_two();
    let mut main = BTreeMap::<u8, usize>::new();
    let mut composition = BTreeMap::<u8, usize>::new();
    let mut table_evaluation_logs = Vec::with_capacity(program.tables.len());
    let mut main_offsets = BTreeMap::<u8, usize>::new();
    let mut composition_offsets = BTreeMap::<u8, usize>::new();
    let mut table_geometries = Vec::with_capacity(program.tables.len());
    for (table_index, table) in program.tables.iter().enumerate() {
        let trace_rows = table
            .rows
            .next_power_of_two()
            .max(mask_coefficient_count.next_power_of_two());
        let masked_bound = trace_rows
            .checked_add(mask_size)
            .ok_or(OracleCommitmentError::CountOverflow)?
            .next_power_of_two();
        let maximum_identity_degree = table
            .identities
            .iter()
            .map(|identity| identity.expression.degree())
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .max()
            .unwrap_or(1) as usize;
        let composition_bound = masked_bound
            .checked_mul(maximum_identity_degree.max(1) + 1)
            .ok_or(OracleCommitmentError::CountOverflow)?
            .next_power_of_two();
        let component_coefficient_log_size = masked_bound.ilog2() as u8;
        let evaluation_log_size = component_coefficient_log_size
            .checked_add(crate::composition_mask::COMPOSITION_MASK_DEGREE_SLACK_LOG)
            .ok_or(OracleCommitmentError::CountOverflow)?
            .checked_add(log_blowup)
            .ok_or(OracleCommitmentError::CountOverflow)?;
        let composition_work_log_size = composition_bound.ilog2() as u8;
        let has_lookup_side = program.lookups.iter().any(|lookup| {
            lookup
                .sources
                .iter()
                .chain(&lookup.destinations)
                .any(|side| side.table == table_index)
        });
        // Keep LogUp's inverse/accumulator work files on a domain no smaller
        // than the committed interaction/evaluation domain. Do not inflate
        // tables that have no lookup side.
        let composition_work_log_size = if has_lookup_side {
            composition_work_log_size.max(evaluation_log_size)
        } else {
            composition_work_log_size
        };
        let composition_component_count = 1_usize
            .checked_shl(u32::from(
                composition_work_log_size - component_coefficient_log_size,
            ))
            .ok_or(OracleCommitmentError::CountOverflow)?;
        table_evaluation_logs.push(evaluation_log_size);
        let main_column_offset = *main_offsets.entry(evaluation_log_size).or_default();
        let composition_column_offset =
            *composition_offsets.entry(evaluation_log_size).or_default();
        let main_column_count = table
            .columns
            .len()
            .checked_sub(table.fixed_columns.len())
            .ok_or(OracleCommitmentError::Shape)?;
        table_geometries.push(OracleTableGeometry {
            table_index,
            trace_rows,
            trace_log_size: trace_rows.ilog2() as u8,
            evaluation_log_size,
            composition_work_log_size,
            component_coefficient_log_size,
            composition_component_count,
            main_column_offset,
            main_column_count,
            composition_column_offset,
        });
        *main_offsets
            .get_mut(&evaluation_log_size)
            .expect("inserted") += main_column_count;
        *composition_offsets
            .get_mut(&evaluation_log_size)
            .expect("inserted") += composition_component_count;
        if main_column_count != 0 {
            *main.entry(evaluation_log_size).or_default() += main_column_count;
        }
        *composition.entry(evaluation_log_size).or_default() += composition_component_count;
    }
    let mut interaction = BTreeMap::<u8, usize>::new();
    let mut interaction_offsets = BTreeMap::<u8, usize>::new();
    let mut interaction_geometries = Vec::new();
    for (lookup_index, lookup) in program.lookups.iter().enumerate() {
        for (table_index, evaluation_log_size) in table_evaluation_logs.iter().copied().enumerate()
        {
            let side_count = lookup
                .sources
                .iter()
                .chain(&lookup.destinations)
                .filter(|side| side.table == table_index)
                .count();
            if side_count == 0 {
                continue;
            }
            let interaction_column_offset =
                *interaction_offsets.entry(evaluation_log_size).or_default();
            interaction_geometries.push(OracleInteractionGeometry {
                lookup_index,
                table_index,
                evaluation_log_size,
                interaction_column_offset,
                side_count,
            });
            *interaction_offsets
                .get_mut(&evaluation_log_size)
                .expect("inserted") += side_count + 1;
            *interaction.entry(evaluation_log_size).or_default() += side_count + 1;
        }
    }
    Ok(OracleCommitmentLayouts {
        program_binary_commitment,
        main_trace: layout_from_counts(
            &program_binary_commitment,
            CommitmentStage::MainTrace,
            &main,
            EvaluationField::M31,
        )?
        .ok_or(OracleCommitmentError::Shape)?,
        interaction_trace: layout_from_counts(
            &program_binary_commitment,
            CommitmentStage::InteractionTrace,
            &interaction,
            EvaluationField::Fp16,
        )?,
        composition: layout_from_counts(
            &program_binary_commitment,
            CommitmentStage::Composition,
            &composition,
            EvaluationField::Fp16,
        )?
        .ok_or(OracleCommitmentError::Shape)?,
        tables: table_geometries,
        interactions: interaction_geometries,
    })
}

fn m31_tree(
    program_commitment: &[u8; 64],
    stage: CommitmentStage,
    columns: BTreeMap<u8, Vec<Vec<M31>>>,
) -> Result<CrossDomainTree, OracleCommitmentError> {
    let groups = columns
        .iter()
        .map(|(log, values)| (*log, values.len()))
        .collect::<Vec<_>>();
    if groups.is_empty() {
        return Err(OracleCommitmentError::Shape);
    }
    let specs = groups
        .iter()
        .map(|(log, count)| {
            DomainSpec::new(
                *log,
                EvaluationField::M31,
                u32::try_from(*count).map_err(|_| OracleCommitmentError::CountOverflow)?,
            )
            .map_err(OracleCommitmentError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let layout = CrossDomainLayout::new(
        stage,
        commitment_id(program_commitment, stage, &groups)?,
        specs.clone(),
    )?;
    let batches = specs
        .into_iter()
        .zip(columns)
        .map(|(spec, (_, values))| {
            let rows = 1_usize << spec.log_size;
            if values.is_empty() || values.iter().any(|column| column.len() != rows) {
                return Err(OracleCommitmentError::Shape);
            }
            DomainEvaluationBatch::new(
                spec,
                (0..rows)
                    .map(|row| {
                        values
                            .iter()
                            .flat_map(|column| column[row].as_u32().to_be_bytes())
                            .collect::<Vec<_>>()
                    })
                    .collect(),
            )
            .map_err(OracleCommitmentError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CrossDomainTree::build(layout, batches)?)
}

fn fp16_tree(
    program_commitment: &[u8; 64],
    stage: CommitmentStage,
    columns: BTreeMap<u8, Vec<Vec<Fp16>>>,
) -> Result<Option<CrossDomainTree>, OracleCommitmentError> {
    let groups = columns
        .iter()
        .map(|(log, values)| (*log, values.len()))
        .collect::<Vec<_>>();
    if groups.is_empty() {
        return Ok(None);
    }
    let specs = groups
        .iter()
        .map(|(log, count)| {
            DomainSpec::new(
                *log,
                EvaluationField::Fp16,
                u32::try_from(*count).map_err(|_| OracleCommitmentError::CountOverflow)?,
            )
            .map_err(OracleCommitmentError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let layout = CrossDomainLayout::new(
        stage,
        commitment_id(program_commitment, stage, &groups)?,
        specs.clone(),
    )?;
    let batches = specs
        .into_iter()
        .zip(columns)
        .map(|(spec, (_, values))| {
            let rows = 1_usize << spec.log_size;
            if values.is_empty() || values.iter().any(|column| column.len() != rows) {
                return Err(OracleCommitmentError::Shape);
            }
            DomainEvaluationBatch::new(
                spec,
                (0..rows)
                    .map(|row| {
                        values
                            .iter()
                            .flat_map(|column| column[row].encode())
                            .collect::<Vec<_>>()
                    })
                    .collect(),
            )
            .map_err(OracleCommitmentError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(CrossDomainTree::build(layout, batches)?))
}

/// Commit the main trace at the first interactive suspension boundary.
pub fn commit_main_trace_oracle(
    main: &AirMainTraceOracle,
) -> Result<CrossDomainTree, OracleCommitmentError> {
    let mut columns = BTreeMap::<u8, Vec<Vec<M31>>>::new();
    for table in &main.tables {
        if table.committed_column_indices.is_empty() {
            continue;
        }
        let columns = columns.entry(table.evaluation_log_size).or_default();
        for index in &table.committed_column_indices {
            columns.push(
                table
                    .trace_columns
                    .get(*index)
                    .ok_or(OracleCommitmentError::Shape)?
                    .clone(),
            );
        }
    }
    m31_tree(
        &main.program_binary_commitment,
        CommitmentStage::MainTrace,
        columns,
    )
}

/// Commit LogUp interaction columns after beta/gamma and before alpha.
pub fn commit_interaction_trace_oracle(
    program_binary_commitment: &[u8; 64],
    logup: &AirLogupOracle,
) -> Result<Option<CrossDomainTree>, OracleCommitmentError> {
    let mut interaction = BTreeMap::<u8, Vec<Vec<Fp16>>>::new();
    for table in &logup.interactions {
        let columns = interaction.entry(table.evaluation_log_size).or_default();
        columns.extend(table.masked_inverse_evaluations.clone());
        columns.push(table.masked_accumulator_evaluations.clone());
    }
    fp16_tree(
        program_binary_commitment,
        CommitmentStage::InteractionTrace,
        interaction,
    )
}

/// Commit composition while reusing both earlier interactive commitments.
pub fn commit_air_oracles_with_precommitments(
    main_trace: CrossDomainTree,
    interaction_trace: Option<CrossDomainTree>,
    composition: &AirCompositionOracle,
    logup: &AirLogupOracle,
) -> Result<CommittedAirOracles, OracleCommitmentError> {
    if composition.lookup_count_pending_logup != 0 {
        return Err(OracleCommitmentError::Shape);
    }
    let mut expected_main_counts = BTreeMap::<u8, usize>::new();
    let mut expected_interaction_counts = BTreeMap::<u8, usize>::new();
    let mut quotient = BTreeMap::<u8, Vec<Vec<Fp16>>>::new();
    for table in &composition.tables {
        if !table.composition_components_masked {
            return Err(OracleCommitmentError::Shape);
        }
        if !table.committed_column_indices.is_empty() {
            *expected_main_counts
                .entry(table.evaluation_log_size)
                .or_default() += table.committed_column_indices.len();
        }
        let components = table
            .composition_components
            .as_ref()
            .ok_or(OracleCommitmentError::Shape)?;
        quotient
            .entry(table.evaluation_log_size)
            .or_default()
            .extend(components.iter().cloned());
    }
    for table in &logup.interactions {
        *expected_interaction_counts
            .entry(table.evaluation_log_size)
            .or_default() += table.masked_inverse_evaluations.len() + 1;
    }
    let expected_main_layout = layout_from_counts(
        &composition.program_binary_commitment,
        CommitmentStage::MainTrace,
        &expected_main_counts,
        EvaluationField::M31,
    )?
    .ok_or(OracleCommitmentError::Shape)?;
    let expected_interaction_layout = layout_from_counts(
        &composition.program_binary_commitment,
        CommitmentStage::InteractionTrace,
        &expected_interaction_counts,
        EvaluationField::Fp16,
    )?;
    if main_trace.layout() != &expected_main_layout
        || interaction_trace.as_ref().map(CrossDomainTree::layout)
            != expected_interaction_layout.as_ref()
    {
        return Err(OracleCommitmentError::Shape);
    }
    let composition_tree = fp16_tree(
        &composition.program_binary_commitment,
        CommitmentStage::Composition,
        quotient,
    )?
    .ok_or(OracleCommitmentError::Shape)?;
    Ok(CommittedAirOracles {
        main_trace,
        interaction_trace,
        composition: composition_tree,
    })
}

/// Commit later oracles while reusing the already-built main commitment tree.
pub fn commit_air_oracles_with_main(
    main_trace: CrossDomainTree,
    composition: &AirCompositionOracle,
    logup: &AirLogupOracle,
) -> Result<CommittedAirOracles, OracleCommitmentError> {
    let interaction_trace =
        commit_interaction_trace_oracle(&composition.program_binary_commitment, logup)?;
    commit_air_oracles_with_precommitments(main_trace, interaction_trace, composition, logup)
}

/// Compatibility constructor that commits all stages in one local call.
pub fn commit_air_oracles(
    composition: &AirCompositionOracle,
    logup: &AirLogupOracle,
) -> Result<CommittedAirOracles, OracleCommitmentError> {
    let mut main = BTreeMap::<u8, Vec<Vec<M31>>>::new();
    for table in &composition.tables {
        if table.committed_column_indices.is_empty() {
            continue;
        }
        let columns = main.entry(table.evaluation_log_size).or_default();
        for index in &table.committed_column_indices {
            columns.push(
                table
                    .trace_columns
                    .get(*index)
                    .ok_or(OracleCommitmentError::Shape)?
                    .clone(),
            );
        }
    }
    let main_trace = m31_tree(
        &composition.program_binary_commitment,
        CommitmentStage::MainTrace,
        main,
    )?;
    commit_air_oracles_with_main(main_trace, composition, logup)
}
