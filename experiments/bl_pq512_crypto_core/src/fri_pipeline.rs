//! Multi-domain masked FRI pipeline for the committed DEEP quotient batches.

use alloc::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use alloc::vec;
use alloc::vec::Vec;
use sha3::{Digest, Sha3_512};

use crate::air_composition::{
    AirCompositionOracle, alpha_power, selector_evaluations, shifted_fft_index,
};
use crate::air_ir::{FixedColumn, ParsedProgram, Table, parse_air_program};
use crate::air_logup::AirLogupOracle;
use crate::binding_root_v2::{BindingDigestV2, BindingRoleV2, BindingRootV2};
use crate::circle_fft::{
    CircleFftError, evaluate_extension_circle_coefficients,
    interpolate_extension_circle_evaluations, low_degree_extend_coset_order,
};
use crate::circle_fri::{
    CircleFriError, FriCascade, FriDomainBatch, batch_row, bit_reverse_index, canonic_circle_point,
    degree_corrected_row, fold_circle_into_line, fold_circle_pair, fold_line, fold_line_pair,
};
use crate::cross_domain::{
    BindingCrossDomainMultiProofV2, BindingCrossDomainTreeV2, CommitmentStage, CrossDomainError,
    CrossDomainLayout, CrossDomainProof, CrossDomainRoot, CrossDomainTree, DomainOpening,
    DomainSpec, EvaluationField, inverse_transpose_circle_fft_index, project_circle_fft_index,
    transpose_circle_fft_index,
};
use crate::deep_quotient::{
    DeepQuotientOracles, DomainOodsClaims, deep_claims_commitment,
    deep_claims_commitment_binding_v2,
};
use crate::field::{DecodeError, Fp16, M31, M31_MODULUS};
use crate::fri_layer_multiproof::{
    FriLayerMultiproofError, FriPipelineBindingMultiproofsV2, FriPipelineCanonicalMultiproofs,
    binding_fri_layer_root_v2, build_fri_layer_binding_multiproofs_v2,
    verify_fri_layer_binding_multiproofs_v2, verify_fri_pipeline_layer_multiproofs,
};
use crate::merkle::{MerkleError, MerkleProof, MerkleTree, RootHash};
use crate::oods::CirclePoint;
use crate::oracle_commitment::{
    BindingCommittedAirOraclesV2, BindingCommittedAirRootsV2, CommittedAirOracles,
    CommittedAirRoots, OracleTableGeometry, derive_binding_oracle_commitment_layouts_v2,
    derive_oracle_commitment_layouts,
};
use crate::proof_format::FriPipelineProofV2;
use crate::trace_mask::{
    TraceMaskError, canonical_coset_vanishing, sample_extension_trace_mask_coefficients,
};

pub const FRI_MASK_ID_DOMAIN: &[u8] = b"BL/PQ512/WAVE1B/FRI-BATCH-MASK-ID/v1\0";
pub const FRI_LAYER_LEAF_DOMAIN: &[u8] = b"BL/PQ512/WAVE1B/FRI-LAYER-LEAF/v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriPipeline {
    pub claims_commitment: [u8; 64],
    pub degree_bounds: Vec<usize>,
    pub masks: Vec<FriDomainBatch>,
    pub mask_tree: CrossDomainTree,
    pub cascade: FriCascade,
    pub layer_roots: Vec<RootHash>,
    pub final_constant: Fp16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriMaskOracle {
    pub claims_commitment: [u8; 64],
    pub degree_bounds: Vec<usize>,
    pub masks: Vec<FriDomainBatch>,
    pub mask_tree: CrossDomainTree,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InteractiveFriBuilder {
    claims_commitment: [u8; 64],
    degree_bounds: Vec<usize>,
    masks: Vec<FriDomainBatch>,
    mask_tree: CrossDomainTree,
    domain_log_sizes: Vec<u8>,
    batch_column_counts: Vec<usize>,
    batch_power_offsets: Vec<usize>,
    batch_masks: Vec<Vec<Fp16>>,
    batched_domains: Vec<Vec<Fp16>>,
    fold_log_sizes: Vec<u8>,
    folded_layers: Vec<Vec<Fp16>>,
    layer_roots: Vec<RootHash>,
    fold_coefficients: Vec<Fp16>,
    batch_coefficient: Fp16,
}

/// One authenticated pair in a committed folded FRI layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriPipelineLayerOpening {
    pub log_size: u8,
    pub left: Fp16,
    pub right: Fp16,
    pub left_proof: MerkleProof,
    pub right_proof: MerkleProof,
}

/// Every opening required to check one public-coin query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriPipelineQueryProof {
    pub initial_index: usize,
    pub mask_left: CrossDomainProof,
    pub mask_right: CrossDomainProof,
    pub main_left: CrossDomainProof,
    pub main_right: CrossDomainProof,
    pub interaction_left: Option<CrossDomainProof>,
    pub interaction_right: Option<CrossDomainProof>,
    pub composition_left: CrossDomainProof,
    pub composition_right: CrossDomainProof,
    /// Deduplicated authenticated logical-next main rows required by AIR.
    pub next_main: Vec<CrossDomainProof>,
    /// Deduplicated authenticated logical-next interaction rows required by LogUp.
    pub next_interaction: Vec<CrossDomainProof>,
    pub layers: Vec<FriPipelineLayerOpening>,
}

/// Multi-domain FRI openings. Roots and challenges remain authoritative
/// external public-coin inputs and are intentionally not trusted from here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriPipelineProof {
    /// Per-interaction table sums, fixed before composition challenge use.
    pub logup_final_sums: Vec<Fp16>,
    pub queries: Vec<FriPipelineQueryProof>,
}

/// Canonical native BindingRootV2 proof. Query coordinates are derived from
/// the strict public coin and all repeated openings are globally deduplicated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriPipelineProofV3 {
    pub logup_final_sums: Vec<Fp16>,
    pub query_indices: Vec<usize>,
    pub mask: BindingCrossDomainMultiProofV2,
    pub main: BindingCrossDomainMultiProofV2,
    pub interaction: Option<BindingCrossDomainMultiProofV2>,
    pub composition: BindingCrossDomainMultiProofV2,
    pub fri_layers: FriPipelineBindingMultiproofsV2,
}

/// Native v3 commitments derived from one already-built legacy prover state.
///
/// The legacy prover keeps its row packets in `CrossDomainTree` values while
/// the accepting v3 verifier requires independent `BindingRootV2` trees.  This
/// adapter recommits those exact packets and derives the folded-layer roots in
/// the same order consumed by `verify_fri_pipeline_v3`.  It is intentionally a
/// construction helper only: it does not mint a verifier receipt or claim that
/// the legacy proof has been accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeFriPipelineV3Construction {
    pub proof: FriPipelineProofV3,
    pub oracle_roots: BindingCommittedAirRootsV2,
    pub mask_root: BindingRootV2,
    pub layer_roots: Vec<BindingRootV2>,
}

/// Opaque result of the complete native-128 AIR/DEEP/FRI verifier.  Bridge
/// adapters consume authenticated OODS claim cells through this receipt;
/// they never accept a root/value pair supplied independently by the host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedFriPipelineV3 {
    receipt_binding: BindingDigestV2,
    public_inputs_binding: BindingDigestV2,
    program_binding: BindingDigestV2,
    oracle_roots: BindingCommittedAirRootsV2,
    query_point: CirclePoint,
    claims: Vec<DomainOodsClaims>,
}

impl VerifiedFriPipelineV3 {
    pub const fn receipt_binding(&self) -> BindingDigestV2 {
        self.receipt_binding
    }
    pub const fn public_inputs_binding(&self) -> BindingDigestV2 {
        self.public_inputs_binding
    }
    pub const fn program_binding(&self) -> BindingDigestV2 {
        self.program_binding
    }

    pub const fn oracle_roots(&self) -> &BindingCommittedAirRootsV2 {
        &self.oracle_roots
    }

    pub const fn query_point(&self) -> CirclePoint {
        self.query_point
    }

    pub fn claims(&self) -> &[DomainOodsClaims] {
        &self.claims
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FriPipelineError {
    CircleFft(CircleFftError),
    CircleFri(CircleFriError),
    CrossDomain(CrossDomainError),
    Merkle(MerkleError),
    TraceMask(TraceMaskError),
    Shape,
    DegreeBound {
        log_size: u8,
        column: usize,
        used: usize,
        domain_size: usize,
    },
    FinalNotConstant,
    CountOverflow,
    Decode(DecodeError),
    LayerMultiproof(FriLayerMultiproofError),
    Authentication,
    FoldMismatch,
    Query,
}

impl From<CircleFftError> for FriPipelineError {
    fn from(value: CircleFftError) -> Self {
        Self::CircleFft(value)
    }
}
impl From<CircleFriError> for FriPipelineError {
    fn from(value: CircleFriError) -> Self {
        Self::CircleFri(value)
    }
}
impl From<CrossDomainError> for FriPipelineError {
    fn from(value: CrossDomainError) -> Self {
        Self::CrossDomain(value)
    }
}
impl From<MerkleError> for FriPipelineError {
    fn from(value: MerkleError) -> Self {
        Self::Merkle(value)
    }
}
impl From<TraceMaskError> for FriPipelineError {
    fn from(value: TraceMaskError) -> Self {
        Self::TraceMask(value)
    }
}
impl From<DecodeError> for FriPipelineError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}
impl From<FriLayerMultiproofError> for FriPipelineError {
    fn from(value: FriLayerMultiproofError) -> Self {
        Self::LayerMultiproof(value)
    }
}

fn exact_degree_bound(batch: &FriDomainBatch) -> Result<usize, FriPipelineError> {
    let columns = batch.column_count();
    let mut maximum = 0_usize;
    let mut maximum_column = 0_usize;
    for column in 0..columns {
        let evaluations = batch.rows.iter().map(|row| row[column]).collect::<Vec<_>>();
        let coefficients = interpolate_extension_circle_evaluations(&evaluations)?;
        let used = coefficients
            .iter()
            .rposition(|value| !value.is_zero())
            .map_or(0, |index| index + 1);
        if used > maximum {
            maximum = used;
            maximum_column = column;
        }
    }
    let bound = maximum.max(2).next_power_of_two();
    if bound >= batch.rows.len() {
        return Err(FriPipelineError::DegreeBound {
            log_size: batch.log_size,
            column: maximum_column,
            used: maximum,
            domain_size: batch.rows.len(),
        });
    }
    Ok(bound)
}

pub(crate) fn mask_id(deep_root: &[u8; 64], log_size: u8) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(FRI_MASK_ID_DOMAIN);
    hash.update(deep_root);
    hash.update([log_size]);
    hash.finalize().into()
}

/// Derive the verifier-authoritative independent-mask commitment layout.
pub fn fri_mask_layout(
    claims_commitment: &[u8; 64],
    claims: &[DomainOodsClaims],
) -> Result<CrossDomainLayout, FriPipelineError> {
    if claims.is_empty() {
        return Err(FriPipelineError::Shape);
    }
    let specs = claims
        .iter()
        .map(|claim| DomainSpec::new(claim.log_size, EvaluationField::Fp16, 1))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CrossDomainLayout::new(
        CommitmentStage::FriBatchMask,
        mask_id(claims_commitment, 0),
        specs,
    )?)
}

/// Native-v2 mask layout. The complete 128-byte DEEP-claims binding is the
/// descriptor authority; no 64-byte digest is derived or wrapped.
pub fn fri_mask_layout_binding_v2(
    claims_commitment: &BindingDigestV2,
    claims: &[DomainOodsClaims],
) -> Result<CrossDomainLayout, FriPipelineError> {
    if claims.is_empty() {
        return Err(FriPipelineError::Shape);
    }
    let specs = claims
        .iter()
        .map(|claim| DomainSpec::new(claim.log_size, EvaluationField::Fp16, 1))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CrossDomainLayout::new_binding_v2(
        CommitmentStage::FriBatchMask,
        *claims_commitment,
        specs,
    )?)
}

fn layer_tree(log_size: u8, values: &[Fp16]) -> Result<MerkleTree, FriPipelineError> {
    if values.len() != 1_usize << (log_size - 1) {
        return Err(FriPipelineError::Shape);
    }
    let payloads = values
        .iter()
        .map(|value| {
            let mut payload = Vec::with_capacity(FRI_LAYER_LEAF_DOMAIN.len() + 1 + 64);
            payload.extend_from_slice(FRI_LAYER_LEAF_DOMAIN);
            payload.push(log_size);
            payload.extend_from_slice(&value.encode());
            payload
        })
        .collect::<Vec<_>>();
    let leaves = payloads.iter().map(Vec::as_slice).collect::<Vec<_>>();
    Ok(MerkleTree::from_leaf_payloads(&leaves)?)
}

pub(crate) fn layer_payload(log_size: u8, value: Fp16) -> Vec<u8> {
    let mut payload = Vec::with_capacity(FRI_LAYER_LEAF_DOMAIN.len() + 1 + 64);
    payload.extend_from_slice(FRI_LAYER_LEAF_DOMAIN);
    payload.push(log_size);
    payload.extend_from_slice(&value.encode());
    payload
}

fn decode_fp16_row(opening: &DomainOpening) -> Result<Vec<Fp16>, FriPipelineError> {
    if opening.spec.field != EvaluationField::Fp16
        || opening.payload.len() != opening.spec.column_count as usize * 64
    {
        return Err(FriPipelineError::Shape);
    }
    opening
        .payload
        .chunks_exact(64)
        .map(Fp16::decode)
        .collect::<Result<Vec<_>, _>>()
        .map_err(FriPipelineError::from)
}

fn decode_m31_row(opening: &DomainOpening) -> Result<Vec<Fp16>, FriPipelineError> {
    if opening.spec.field != EvaluationField::M31
        || opening.payload.len() != opening.spec.column_count as usize * 4
    {
        return Err(FriPipelineError::Shape);
    }
    opening
        .payload
        .chunks_exact(4)
        .map(|word| {
            let value = u32::from_be_bytes(word.try_into().map_err(|_| FriPipelineError::Shape)?);
            if value >= M31_MODULUS {
                return Err(FriPipelineError::Shape);
            }
            Ok(Fp16::from_m31(
                M31::from_canonical(value).map_err(|_| FriPipelineError::Shape)?,
            ))
        })
        .collect()
}

fn opening_at(proof: &CrossDomainProof, log_size: u8) -> Result<&DomainOpening, FriPipelineError> {
    proof
        .openings()
        .iter()
        .find(|opening| opening.spec.log_size == log_size)
        .ok_or(FriPipelineError::Shape)
}

fn maybe_opening_at(proof: &CrossDomainProof, log_size: u8) -> Option<&DomainOpening> {
    proof
        .openings()
        .iter()
        .find(|opening| opening.spec.log_size == log_size)
}

fn projected_index(mut index: usize, from_log: u8, to_log: u8) -> Result<usize, FriPipelineError> {
    if to_log > from_log {
        return Err(FriPipelineError::Shape);
    }
    for log_size in (to_log + 1..=from_log).rev() {
        index = project_circle_fft_index(index, log_size)?;
    }
    Ok(index)
}

fn lifted_index(index: usize, from_log: u8, to_log: u8) -> Result<usize, FriPipelineError> {
    if to_log < from_log {
        return Err(FriPipelineError::Shape);
    }
    let transposed = transpose_circle_fft_index(index, from_log)?;
    let lifted = transposed
        .checked_shl(u32::from(to_log - from_log))
        .ok_or(FriPipelineError::CountOverflow)?;
    Ok(inverse_transpose_circle_fft_index(lifted, to_log)?)
}

fn tree_pair(
    tree: &CrossDomainTree,
    left_index: usize,
    right_index: usize,
    source_log: u8,
) -> Result<(CrossDomainProof, CrossDomainProof), FriPipelineError> {
    let target_log = tree.layout().maximum_log_size();
    Ok((
        tree.proof(projected_index(left_index, source_log, target_log)?)?,
        tree.proof(projected_index(right_index, source_log, target_log)?)?,
    ))
}

fn verify_layer_opening(
    opening: &FriPipelineLayerOpening,
    expected_log_size: u8,
    expected_root: &RootHash,
    expected_pair_start: usize,
) -> Result<bool, FriPipelineError> {
    let leaf_count = 1_usize << (expected_log_size - 1);
    if opening.log_size != expected_log_size
        || opening.left_proof.leaf_index() != expected_pair_start
        || opening.right_proof.leaf_index() != expected_pair_start + 1
        || opening.left_proof.leaf_count() != leaf_count
        || opening.right_proof.leaf_count() != leaf_count
    {
        return Err(FriPipelineError::Shape);
    }
    Ok(opening.left_proof.verify(
        &layer_payload(expected_log_size, opening.left),
        expected_root,
    )? && opening.right_proof.verify(
        &layer_payload(expected_log_size, opening.right),
        expected_root,
    )?)
}

#[derive(Default)]
struct AirVerificationCache {
    selectors: BTreeMap<(usize, usize, usize, u8), Vec<M31>>,
    fixed_columns: BTreeMap<(usize, usize, usize, u8), Vec<M31>>,
}

fn selector_at(
    cache: &mut AirVerificationCache,
    trace_rows: usize,
    row_start: usize,
    row_stop: usize,
    evaluation_log_size: u8,
    fft_index: usize,
) -> Result<M31, FriPipelineError> {
    let key = (trace_rows, row_start, row_stop, evaluation_log_size);
    if let Entry::Vacant(entry) = cache.selectors.entry(key) {
        let evaluations =
            selector_evaluations(trace_rows, row_start, row_stop, evaluation_log_size)
                .map_err(|_| FriPipelineError::Shape)?;
        entry.insert(evaluations);
    }
    cache
        .selectors
        .get(&key)
        .ok_or(FriPipelineError::Shape)?
        .get(fft_index)
        .copied()
        .ok_or(FriPipelineError::Query)
}

#[allow(clippy::too_many_arguments)]
fn fixed_column_at(
    cache: &mut AirVerificationCache,
    table_index: usize,
    column_index: usize,
    values: &FixedColumn,
    trace_rows: usize,
    trace_log_size: u8,
    evaluation_log_size: u8,
    fft_index: usize,
) -> Result<M31, FriPipelineError> {
    let key = (table_index, column_index, trace_rows, evaluation_log_size);
    if let Entry::Vacant(entry) = cache.fixed_columns.entry(key) {
        let mut padded = values.materialize();
        padded.resize(trace_rows, M31::ZERO);
        let evaluations =
            low_degree_extend_coset_order(&padded, evaluation_log_size - trace_log_size)?;
        entry.insert(evaluations);
    }
    cache
        .fixed_columns
        .get(&key)
        .ok_or(FriPipelineError::Shape)?
        .get(fft_index)
        .copied()
        .ok_or(FriPipelineError::Query)
}

fn reconstruct_table_row(
    cache: &mut AirVerificationCache,
    table_index: usize,
    table: &Table,
    geometry: &OracleTableGeometry,
    committed: &[Fp16],
    fft_index: usize,
) -> Result<Vec<Fp16>, FriPipelineError> {
    if committed.len() != geometry.main_column_count {
        return Err(FriPipelineError::Shape);
    }
    let fixed = table
        .fixed_columns
        .iter()
        .map(|(index, values)| (*index, values))
        .collect::<BTreeMap<_, _>>();
    let mut committed_index = 0usize;
    let mut row = Vec::with_capacity(table.columns.len());
    for column_index in 0..table.columns.len() {
        if let Some(values) = fixed.get(&column_index) {
            row.push(Fp16::from_m31(fixed_column_at(
                cache,
                table_index,
                column_index,
                values,
                geometry.trace_rows,
                geometry.trace_log_size,
                geometry.evaluation_log_size,
                fft_index,
            )?));
        } else {
            row.push(
                *committed
                    .get(committed_index)
                    .ok_or(FriPipelineError::Shape)?,
            );
            committed_index += 1;
        }
    }
    if committed_index != committed.len() {
        return Err(FriPipelineError::Shape);
    }
    Ok(row)
}

fn add_composition_term(numerator: &mut Fp16, coefficient: &mut Fp16, alpha: Fp16, value: Fp16) {
    *numerator = numerator.add(coefficient.mul(value));
    *coefficient = coefficient.mul(alpha);
}

fn proof_at_index(
    proofs: &[CrossDomainProof],
    query_fft_index: usize,
) -> Result<&CrossDomainProof, FriPipelineError> {
    proofs
        .iter()
        .find(|proof| proof.query_fft_index() == query_fft_index)
        .ok_or(FriPipelineError::Query)
}

fn authenticated_original_row(
    query: &FriPipelineQueryProof,
    left: bool,
    log_size: u8,
) -> Result<(usize, Vec<Fp16>), FriPipelineError> {
    let main = if left {
        &query.main_left
    } else {
        &query.main_right
    };
    let interaction = if left {
        query.interaction_left.as_ref()
    } else {
        query.interaction_right.as_ref()
    };
    let composition = if left {
        &query.composition_left
    } else {
        &query.composition_right
    };
    let mut index = None;
    let mut values = Vec::new();
    if let Some(opening) = maybe_opening_at(main, log_size) {
        index = Some(opening.fft_index);
        values.extend(decode_m31_row(opening)?);
    }
    if let Some(opening) = interaction.and_then(|proof| maybe_opening_at(proof, log_size)) {
        if index.is_some_and(|expected| expected != opening.fft_index) {
            return Err(FriPipelineError::Query);
        }
        index = Some(opening.fft_index);
        values.extend(decode_fp16_row(opening)?);
    }
    if let Some(opening) = maybe_opening_at(composition, log_size) {
        if index.is_some_and(|expected| expected != opening.fft_index) {
            return Err(FriPipelineError::Query);
        }
        index = Some(opening.fft_index);
        values.extend(decode_fp16_row(opening)?);
    }
    if values.is_empty() {
        return Err(FriPipelineError::Shape);
    }
    Ok((index.ok_or(FriPipelineError::Shape)?, values))
}

#[allow(clippy::too_many_arguments)]
fn verify_air_composition_query(
    query: &FriPipelineQueryProof,
    program: &ParsedProgram,
    layouts: &crate::oracle_commitment::OracleCommitmentLayouts,
    legacy_roots: Option<&CommittedAirRoots>,
    supplied_public_inputs: &[M31],
    composition_alpha: Fp16,
    logup_beta: Fp16,
    logup_gamma: Fp16,
    logup_final_sums: &[Fp16],
    largest_log: u8,
    cache: &mut AirVerificationCache,
) -> Result<bool, FriPipelineError> {
    if composition_alpha.is_zero()
        || logup_beta.is_zero()
        || logup_gamma.is_zero()
        || supplied_public_inputs.len() != program.public_inputs.len()
        || logup_final_sums.len() != layouts.interactions.len()
    {
        return Err(FriPipelineError::Shape);
    }
    let current_main_proof = if query.initial_index & 1 == 0 {
        &query.main_left
    } else {
        &query.main_right
    };
    let current_composition_proof = if query.initial_index & 1 == 0 {
        &query.composition_left
    } else {
        &query.composition_right
    };
    let current_interaction_proof = if query.initial_index & 1 == 0 {
        query.interaction_left.as_ref()
    } else {
        query.interaction_right.as_ref()
    };

    let mut expected_next_main = BTreeSet::new();
    for geometry in &layouts.tables {
        if geometry.main_column_count == 0 {
            continue;
        }
        let current = opening_at(current_main_proof, geometry.evaluation_log_size)?.fft_index;
        let shifted = shifted_fft_index(
            current,
            geometry.evaluation_log_size,
            geometry.trace_log_size,
        )
        .map_err(|_| FriPipelineError::Shape)?;
        expected_next_main.insert(lifted_index(
            shifted,
            geometry.evaluation_log_size,
            layouts.main_trace.maximum_log_size(),
        )?);
    }
    let supplied_next_main = query
        .next_main
        .iter()
        .map(CrossDomainProof::query_fft_index)
        .collect::<BTreeSet<_>>();
    if supplied_next_main != expected_next_main || supplied_next_main.len() != query.next_main.len()
    {
        return Err(FriPipelineError::Query);
    }
    if let Some(roots) = legacy_roots {
        for proof in &query.next_main {
            if !proof.verify(&layouts.main_trace, &roots.main_trace)? {
                return Ok(false);
            }
        }
    }

    let mut expected_next_interaction = BTreeSet::new();
    if let Some(layout) = &layouts.interaction_trace {
        for geometry in &layouts.interactions {
            let current = current_interaction_proof
                .and_then(|proof| maybe_opening_at(proof, geometry.evaluation_log_size))
                .ok_or(FriPipelineError::Shape)?
                .fft_index;
            let trace_log_size = layouts.tables[geometry.table_index].trace_log_size;
            let shifted = shifted_fft_index(current, geometry.evaluation_log_size, trace_log_size)
                .map_err(|_| FriPipelineError::Shape)?;
            expected_next_interaction.insert(lifted_index(
                shifted,
                geometry.evaluation_log_size,
                layout.maximum_log_size(),
            )?);
        }
    }
    let supplied_next_interaction = query
        .next_interaction
        .iter()
        .map(CrossDomainProof::query_fft_index)
        .collect::<BTreeSet<_>>();
    if supplied_next_interaction != expected_next_interaction
        || supplied_next_interaction.len() != query.next_interaction.len()
    {
        return Err(FriPipelineError::Query);
    }
    if let Some(roots) = legacy_roots {
        if let (Some(layout), Some(root)) = (&layouts.interaction_trace, &roots.interaction_trace) {
            for proof in &query.next_interaction {
                if !proof.verify(layout, root)? {
                    return Ok(false);
                }
            }
        }
    }

    let mut table_current = Vec::with_capacity(program.tables.len());
    let mut table_next = Vec::with_capacity(program.tables.len());
    let mut table_composition = Vec::with_capacity(program.tables.len());
    let mut table_current_indices = Vec::with_capacity(program.tables.len());
    for geometry in &layouts.tables {
        let table = &program.tables[geometry.table_index];
        let composition_opening =
            opening_at(current_composition_proof, geometry.evaluation_log_size)?;
        let current_opening = if geometry.main_column_count == 0 {
            None
        } else {
            Some(opening_at(
                current_main_proof,
                geometry.evaluation_log_size,
            )?)
        };
        let current_fft_index = current_opening
            .map(|opening| opening.fft_index)
            .unwrap_or(composition_opening.fft_index);
        if current_opening.is_some_and(|opening| opening.fft_index != composition_opening.fft_index)
        {
            return Err(FriPipelineError::Query);
        }
        let current_group = current_opening
            .map(decode_m31_row)
            .transpose()?
            .unwrap_or_default();
        let column_stop = geometry
            .main_column_offset
            .checked_add(geometry.main_column_count)
            .ok_or(FriPipelineError::CountOverflow)?;
        let current_committed = if geometry.main_column_count == 0 {
            &[][..]
        } else {
            current_group
                .get(geometry.main_column_offset..column_stop)
                .ok_or(FriPipelineError::Shape)?
        };
        let current = reconstruct_table_row(
            cache,
            geometry.table_index,
            table,
            geometry,
            current_committed,
            current_fft_index,
        )?;
        let shifted = shifted_fft_index(
            current_fft_index,
            geometry.evaluation_log_size,
            geometry.trace_log_size,
        )
        .map_err(|_| FriPipelineError::Shape)?;
        let next_group = if geometry.main_column_count == 0 {
            Vec::new()
        } else {
            let next_max_index = lifted_index(
                shifted,
                geometry.evaluation_log_size,
                layouts.main_trace.maximum_log_size(),
            )?;
            let next_opening = opening_at(
                proof_at_index(&query.next_main, next_max_index)?,
                geometry.evaluation_log_size,
            )?;
            if next_opening.fft_index != shifted {
                return Err(FriPipelineError::Query);
            }
            decode_m31_row(next_opening)?
        };
        let next_committed = if geometry.main_column_count == 0 {
            &[][..]
        } else {
            next_group
                .get(geometry.main_column_offset..column_stop)
                .ok_or(FriPipelineError::Shape)?
        };
        let next = reconstruct_table_row(
            cache,
            geometry.table_index,
            table,
            geometry,
            next_committed,
            shifted,
        )?;
        let composition_group = decode_fp16_row(composition_opening)?;
        let composition_stop = geometry
            .composition_column_offset
            .checked_add(geometry.composition_component_count)
            .ok_or(FriPipelineError::Shape)?;
        let component_values = composition_group
            .get(geometry.composition_column_offset..composition_stop)
            .ok_or(FriPipelineError::Shape)?;
        let composition_value = crate::composition_chunks::join_composition_chunks_at(
            component_values,
            geometry.composition_work_log_size,
            geometry.component_coefficient_log_size,
            geometry.evaluation_log_size,
            current_fft_index,
        )
        .map_err(|_| FriPipelineError::Shape)?;
        table_current.push(current);
        table_next.push(next);
        table_composition.push(composition_value);
        table_current_indices.push(current_fft_index);
    }

    let mut numerators = vec![Fp16::ZERO; program.tables.len()];
    let mut coefficient = Fp16::ONE;
    for geometry in &layouts.tables {
        let table_index = geometry.table_index;
        let table = &program.tables[table_index];
        let current_index = table_current_indices[table_index];
        for identity in &table.identities {
            let selector = selector_at(
                cache,
                geometry.trace_rows,
                identity.row_start,
                identity.row_stop,
                geometry.evaluation_log_size,
                current_index,
            )?;
            let value = Fp16::from_m31(selector).mul(
                identity
                    .expression
                    .evaluate_extension(&table_current[table_index], &table_next[table_index])
                    .map_err(|_| FriPipelineError::Shape)?,
            );
            add_composition_term(
                &mut numerators[table_index],
                &mut coefficient,
                composition_alpha,
                value,
            );
        }
        let live = selector_at(
            cache,
            geometry.trace_rows,
            0,
            table.rows,
            geometry.evaluation_log_size,
            current_index,
        )?;
        for (column, values) in &table.fixed_columns {
            let expected = fixed_column_at(
                cache,
                table_index,
                *column,
                values,
                geometry.trace_rows,
                geometry.trace_log_size,
                geometry.evaluation_log_size,
                current_index,
            )?;
            let value = Fp16::from_m31(live)
                .mul(table_current[table_index][*column].sub(Fp16::from_m31(expected)));
            add_composition_term(
                &mut numerators[table_index],
                &mut coefficient,
                composition_alpha,
                value,
            );
        }
        for (input_index, binding) in program.public_inputs.iter().enumerate() {
            if binding.table != table_index {
                continue;
            }
            let selector = selector_at(
                cache,
                geometry.trace_rows,
                binding.row,
                binding.row + 1,
                geometry.evaluation_log_size,
                current_index,
            )?;
            let difference = table_current[table_index][binding.column]
                .sub(Fp16::from_m31(supplied_public_inputs[input_index]));
            add_composition_term(
                &mut numerators[table_index],
                &mut coefficient,
                composition_alpha,
                Fp16::from_m31(selector).mul(difference),
            );
        }
    }

    let existing_terms = program
        .tables
        .iter()
        .map(|table| table.identities.len() + table.fixed_columns.len())
        .sum::<usize>()
        .checked_add(program.public_inputs.len())
        .ok_or(FriPipelineError::CountOverflow)?;
    if coefficient != alpha_power(composition_alpha, existing_terms as u64) {
        return Err(FriPipelineError::Shape);
    }
    let mut lookup_sums = vec![Fp16::ZERO; program.lookups.len()];
    for (interaction_index, geometry) in layouts.interactions.iter().enumerate() {
        let lookup = &program.lookups[geometry.lookup_index];
        let sides = lookup
            .sources
            .iter()
            .filter(|side| side.table == geometry.table_index)
            .map(|side| (1_i8, side))
            .chain(
                lookup
                    .destinations
                    .iter()
                    .filter(|side| side.table == geometry.table_index)
                    .map(|side| (-1_i8, side)),
            )
            .collect::<Vec<_>>();
        if sides.len() != geometry.side_count {
            return Err(FriPipelineError::Shape);
        }
        let current_proof = current_interaction_proof.ok_or(FriPipelineError::Shape)?;
        let current_opening = opening_at(current_proof, geometry.evaluation_log_size)?;
        let current_group = decode_fp16_row(current_opening)?;
        let stop = geometry
            .interaction_column_offset
            .checked_add(geometry.side_count + 1)
            .ok_or(FriPipelineError::CountOverflow)?;
        let interaction_values = current_group
            .get(geometry.interaction_column_offset..stop)
            .ok_or(FriPipelineError::Shape)?;
        let trace_geometry = layouts.tables[geometry.table_index];
        let shifted = shifted_fft_index(
            current_opening.fft_index,
            geometry.evaluation_log_size,
            trace_geometry.trace_log_size,
        )
        .map_err(|_| FriPipelineError::Shape)?;
        let interaction_layout = layouts
            .interaction_trace
            .as_ref()
            .ok_or(FriPipelineError::Shape)?;
        let next_max_index = lifted_index(
            shifted,
            geometry.evaluation_log_size,
            interaction_layout.maximum_log_size(),
        )?;
        let next_group = decode_fp16_row(opening_at(
            proof_at_index(&query.next_interaction, next_max_index)?,
            geometry.evaluation_log_size,
        )?)?;
        let next_accumulator = *next_group
            .get(geometry.interaction_column_offset + geometry.side_count)
            .ok_or(FriPipelineError::Shape)?;
        let mut contribution = Fp16::ZERO;
        for (side_index, (sign, side)) in sides.iter().enumerate() {
            let range = selector_at(
                cache,
                trace_geometry.trace_rows,
                side.row_start,
                side.row_stop,
                geometry.evaluation_log_size,
                current_opening.fft_index,
            )?;
            let current = &table_current[geometry.table_index];
            let selector = side
                .selector
                .evaluate_extension(current, current)
                .map_err(|_| FriPipelineError::Shape)?;
            let weight = side
                .weight
                .evaluate_extension(current, current)
                .map_err(|_| FriPipelineError::Shape)?;
            let mut denominator = logup_gamma;
            let mut power = logup_beta;
            for value in &side.values {
                denominator = denominator.add(
                    power.mul(
                        value
                            .evaluate_extension(current, current)
                            .map_err(|_| FriPipelineError::Shape)?,
                    ),
                );
                power = power.mul(logup_beta);
            }
            let inverse = interaction_values[side_index];
            let inverse_constraint =
                Fp16::from_m31(range).mul(denominator.mul(inverse).sub(selector));
            add_composition_term(
                &mut numerators[geometry.table_index],
                &mut coefficient,
                composition_alpha,
                inverse_constraint,
            );
            let signed = Fp16::from_m31(range).mul(weight).mul(inverse);
            contribution = if *sign > 0 {
                contribution.add(signed)
            } else {
                contribution.sub(signed)
            };
        }
        let accumulator = interaction_values[geometry.side_count];
        let transition_selector = selector_at(
            cache,
            trace_geometry.trace_rows,
            0,
            trace_geometry.trace_rows - 1,
            geometry.evaluation_log_size,
            current_opening.fft_index,
        )?;
        let transition = Fp16::from_m31(transition_selector)
            .mul(next_accumulator.sub(accumulator).sub(contribution));
        add_composition_term(
            &mut numerators[geometry.table_index],
            &mut coefficient,
            composition_alpha,
            transition,
        );
        let first_selector = selector_at(
            cache,
            trace_geometry.trace_rows,
            0,
            1,
            geometry.evaluation_log_size,
            current_opening.fft_index,
        )?;
        add_composition_term(
            &mut numerators[geometry.table_index],
            &mut coefficient,
            composition_alpha,
            Fp16::from_m31(first_selector).mul(accumulator),
        );
        let last_selector = selector_at(
            cache,
            trace_geometry.trace_rows,
            trace_geometry.trace_rows - 1,
            trace_geometry.trace_rows,
            geometry.evaluation_log_size,
            current_opening.fft_index,
        )?;
        add_composition_term(
            &mut numerators[geometry.table_index],
            &mut coefficient,
            composition_alpha,
            Fp16::from_m31(last_selector).mul(accumulator.sub(logup_final_sums[interaction_index])),
        );
        lookup_sums[geometry.lookup_index] =
            lookup_sums[geometry.lookup_index].add(logup_final_sums[interaction_index]);
    }
    if lookup_sums.iter().any(|sum| !sum.is_zero()) {
        return Ok(false);
    }

    for geometry in &layouts.tables {
        let opening = opening_at(current_main_proof, geometry.evaluation_log_size)?;
        let natural_index = bit_reverse_index(opening.fft_index, geometry.evaluation_log_size)?;
        let point = canonic_circle_point(geometry.evaluation_log_size, natural_index)?;
        let zeroifier = canonical_coset_vanishing(point, geometry.trace_log_size)
            .map_err(|_| FriPipelineError::Shape)?;
        if table_composition[geometry.table_index].mul(Fp16::from_m31(zeroifier))
            != numerators[geometry.table_index]
        {
            return Ok(false);
        }
    }
    let _ = largest_log;
    Ok(true)
}

/// Materialize only the authenticated paths needed for public queries.
pub fn prove_fri_pipeline(
    deep: &DeepQuotientOracles,
    pipeline: &FriPipeline,
    oracles: &CommittedAirOracles,
    composition: &AirCompositionOracle,
    logup: &AirLogupOracle,
    query_indices: &[usize],
) -> Result<FriPipelineProof, FriPipelineError> {
    if query_indices.is_empty()
        || pipeline.cascade.folded_layers.len() != pipeline.layer_roots.len()
        || pipeline.cascade.folded_layers.len() != pipeline.cascade.fold_log_sizes.len()
    {
        return Err(FriPipelineError::Query);
    }
    let largest_log = deep
        .batches
        .first()
        .ok_or(FriPipelineError::Shape)?
        .log_size;
    let maximum_size = 1_usize << largest_log;
    if query_indices.iter().any(|index| *index >= maximum_size) {
        return Err(FriPipelineError::Query);
    }
    let trees = pipeline
        .cascade
        .fold_log_sizes
        .iter()
        .copied()
        .zip(&pipeline.cascade.folded_layers)
        .map(|(log_size, values)| layer_tree(log_size, values))
        .collect::<Result<Vec<_>, _>>()?;
    if trees
        .iter()
        .map(MerkleTree::root)
        .ne(pipeline.layer_roots.iter().copied())
    {
        return Err(FriPipelineError::Authentication);
    }
    let mut queries = Vec::with_capacity(query_indices.len());
    for initial_index in query_indices.iter().copied() {
        let pair_start = initial_index & !1;
        let (main_left, main_right) =
            tree_pair(&oracles.main_trace, pair_start, pair_start + 1, largest_log)?;
        let (composition_left, composition_right) = tree_pair(
            &oracles.composition,
            pair_start,
            pair_start + 1,
            largest_log,
        )?;
        let (interaction_left, interaction_right) = if let Some(tree) = &oracles.interaction_trace {
            let (left, right) = tree_pair(tree, pair_start, pair_start + 1, largest_log)?;
            (Some(left), Some(right))
        } else {
            (None, None)
        };
        let mut next_main_indices = BTreeSet::new();
        let main_max_log = oracles.main_trace.layout().maximum_log_size();
        for table in &composition.tables {
            let current = projected_index(initial_index, largest_log, table.evaluation_log_size)?;
            let shifted =
                shifted_fft_index(current, table.evaluation_log_size, table.trace_log_size)
                    .map_err(|_| FriPipelineError::Shape)?;
            next_main_indices.insert(lifted_index(
                shifted,
                table.evaluation_log_size,
                main_max_log,
            )?);
        }
        let next_main = next_main_indices
            .into_iter()
            .map(|index| {
                oracles
                    .main_trace
                    .proof(index)
                    .map_err(FriPipelineError::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut next_interaction_indices = BTreeSet::new();
        if let Some(tree) = &oracles.interaction_trace {
            let interaction_max_log = tree.layout().maximum_log_size();
            for interaction in &logup.interactions {
                let trace_log_size = interaction.trace_rows.ilog2() as u8;
                let current =
                    projected_index(initial_index, largest_log, interaction.evaluation_log_size)?;
                let shifted =
                    shifted_fft_index(current, interaction.evaluation_log_size, trace_log_size)
                        .map_err(|_| FriPipelineError::Shape)?;
                next_interaction_indices.insert(lifted_index(
                    shifted,
                    interaction.evaluation_log_size,
                    interaction_max_log,
                )?);
            }
        }
        let next_interaction = if let Some(tree) = &oracles.interaction_trace {
            next_interaction_indices
                .into_iter()
                .map(|index| tree.proof(index).map_err(FriPipelineError::from))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        };
        let mut layer_index = initial_index >> 1;
        let mut layers = Vec::with_capacity(trees.len());
        for ((log_size, values), tree) in pipeline
            .cascade
            .fold_log_sizes
            .iter()
            .copied()
            .zip(&pipeline.cascade.folded_layers)
            .zip(&trees)
        {
            let current_pair = layer_index & !1;
            layers.push(FriPipelineLayerOpening {
                log_size,
                left: values[current_pair],
                right: values[current_pair + 1],
                left_proof: tree.proof(current_pair)?,
                right_proof: tree.proof(current_pair + 1)?,
            });
            layer_index >>= 1;
        }
        queries.push(FriPipelineQueryProof {
            initial_index,
            mask_left: pipeline.mask_tree.proof(pair_start)?,
            mask_right: pipeline.mask_tree.proof(pair_start + 1)?,
            main_left,
            main_right,
            interaction_left,
            interaction_right,
            composition_left,
            composition_right,
            next_main,
            next_interaction,
            layers,
        });
    }
    Ok(FriPipelineProof {
        logup_final_sums: logup
            .interactions
            .iter()
            .map(|interaction| interaction.final_sum)
            .collect(),
        queries,
    })
}

/// Verify the complete multi-domain batching and fold cascade against roots
/// fixed at the appropriate interactive suspension boundaries.
#[allow(clippy::too_many_arguments)]
pub fn verify_fri_pipeline(
    proof: &FriPipelineProof,
    program_encoded: &[u8],
    mask_coefficient_count: usize,
    log_blowup: u8,
    supplied_public_inputs: &[M31],
    composition_alpha: Fp16,
    logup_beta: Fp16,
    logup_gamma: Fp16,
    oracle_roots: &CommittedAirRoots,
    mask_root: &CrossDomainRoot,
    query_point: CirclePoint,
    claims: &[DomainOodsClaims],
    batch_coefficient: Fp16,
    fold_coefficients: &[Fp16],
    layer_roots: &[RootHash],
    final_constant: Fp16,
    expected_query_indices: &[usize],
) -> Result<bool, FriPipelineError> {
    verify_fri_pipeline_openings(
        &proof.logup_final_sums,
        &proof.queries,
        None,
        None,
        program_encoded,
        mask_coefficient_count,
        log_blowup,
        supplied_public_inputs,
        composition_alpha,
        logup_beta,
        logup_gamma,
        PipelineAuthentication::Legacy {
            oracle_roots,
            mask_root,
            layer_roots,
        },
        query_point,
        claims,
        batch_coefficient,
        fold_coefficients,
        final_constant,
        expected_query_indices,
    )
}

/// Verify the v2 grammar, authenticating each global FRI layer multiproof once
/// before replaying the ordered public-coin queries (including duplicates).
#[allow(clippy::too_many_arguments)]
pub fn verify_fri_pipeline_v2(
    proof: &FriPipelineProofV2,
    program_encoded: &[u8],
    mask_coefficient_count: usize,
    log_blowup: u8,
    supplied_public_inputs: &[M31],
    composition_alpha: Fp16,
    logup_beta: Fp16,
    logup_gamma: Fp16,
    oracle_roots: &CommittedAirRoots,
    mask_root: &CrossDomainRoot,
    query_point: CirclePoint,
    claims: &[DomainOodsClaims],
    batch_coefficient: Fp16,
    fold_coefficients: &[Fp16],
    layer_roots: &[RootHash],
    final_constant: Fp16,
    expected_query_indices: &[usize],
) -> Result<bool, FriPipelineError> {
    if proof.queries.iter().any(|query| !query.layers.is_empty()) {
        return Err(FriPipelineError::Shape);
    }
    if !verify_fri_pipeline_layer_multiproofs(
        &proof.fri_layer_multiproofs,
        expected_query_indices,
        layer_roots,
    )? {
        return Ok(false);
    }
    verify_fri_pipeline_openings(
        &proof.logup_final_sums,
        &proof.queries,
        Some(&proof.fri_layer_multiproofs),
        None,
        program_encoded,
        mask_coefficient_count,
        log_blowup,
        supplied_public_inputs,
        composition_alpha,
        logup_beta,
        logup_gamma,
        PipelineAuthentication::Legacy {
            oracle_roots,
            mask_root,
            layer_roots,
        },
        query_point,
        claims,
        batch_coefficient,
        fold_coefficients,
        final_constant,
        expected_query_indices,
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BindingSelectedIndicesV3 {
    mask: Vec<usize>,
    main: Vec<usize>,
    interaction: Vec<usize>,
    composition: Vec<usize>,
}

/// Verifier-derived layouts and canonical opening coordinates for one native
/// BindingRootV2 AIR/FRI statement. None of these coordinates or layouts is
/// accepted from the encoded proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriPipelineProofV3Geometry {
    pub mask_layout: CrossDomainLayout,
    pub main_layout: CrossDomainLayout,
    pub interaction_layout: Option<CrossDomainLayout>,
    pub composition_layout: CrossDomainLayout,
    pub mask_indices: Vec<usize>,
    pub main_indices: Vec<usize>,
    pub interaction_indices: Vec<usize>,
    pub composition_indices: Vec<usize>,
    pub fri_layer_log_sizes: Vec<u8>,
}

fn binding_selected_indices_v3(
    layouts: &crate::oracle_commitment::OracleCommitmentLayouts,
    largest_log: u8,
    query_indices: &[usize],
) -> Result<BindingSelectedIndicesV3, FriPipelineError> {
    if query_indices.is_empty()
        || query_indices
            .iter()
            .any(|index| *index >= 1_usize << largest_log)
    {
        return Err(FriPipelineError::Query);
    }
    let mut mask = BTreeSet::new();
    let mut main = BTreeSet::new();
    let mut interaction = BTreeSet::new();
    let mut composition = BTreeSet::new();
    for initial_index in query_indices.iter().copied() {
        let pair_start = initial_index & !1;
        mask.extend([pair_start, pair_start + 1]);
        for index in [pair_start, pair_start + 1] {
            main.insert(projected_index(
                index,
                largest_log,
                layouts.main_trace.maximum_log_size(),
            )?);
            composition.insert(projected_index(
                index,
                largest_log,
                layouts.composition.maximum_log_size(),
            )?);
            if let Some(layout) = &layouts.interaction_trace {
                interaction.insert(projected_index(
                    index,
                    largest_log,
                    layout.maximum_log_size(),
                )?);
            }
        }
        for geometry in &layouts.tables {
            if geometry.main_column_count == 0 {
                continue;
            }
            let current =
                projected_index(initial_index, largest_log, geometry.evaluation_log_size)?;
            let shifted = shifted_fft_index(
                current,
                geometry.evaluation_log_size,
                geometry.trace_log_size,
            )
            .map_err(|_| FriPipelineError::Shape)?;
            main.insert(lifted_index(
                shifted,
                geometry.evaluation_log_size,
                layouts.main_trace.maximum_log_size(),
            )?);
        }
        if let Some(layout) = &layouts.interaction_trace {
            for geometry in &layouts.interactions {
                let current =
                    projected_index(initial_index, largest_log, geometry.evaluation_log_size)?;
                let trace_log_size = layouts.tables[geometry.table_index].trace_log_size;
                let shifted =
                    shifted_fft_index(current, geometry.evaluation_log_size, trace_log_size)
                        .map_err(|_| FriPipelineError::Shape)?;
                interaction.insert(lifted_index(
                    shifted,
                    geometry.evaluation_log_size,
                    layout.maximum_log_size(),
                )?);
            }
        }
    }
    Ok(BindingSelectedIndicesV3 {
        mask: mask.into_iter().collect(),
        main: main.into_iter().collect(),
        interaction: interaction.into_iter().collect(),
        composition: composition.into_iter().collect(),
    })
}

/// Derive native proof geometry from the exact AIR program, OODS statement,
/// 128-byte oracle roots, and ordered public-coin query list.
#[allow(clippy::too_many_arguments)]
pub fn derive_fri_pipeline_proof_v3_geometry(
    program_encoded: &[u8],
    mask_coefficient_count: usize,
    log_blowup: u8,
    query_point: CirclePoint,
    claims: &[DomainOodsClaims],
    oracle_roots: &BindingCommittedAirRootsV2,
    expected_query_indices: &[usize],
) -> Result<FriPipelineProofV3Geometry, FriPipelineError> {
    let layouts = derive_binding_oracle_commitment_layouts_v2(
        program_encoded,
        mask_coefficient_count,
        log_blowup,
    )
    .map_err(|_| FriPipelineError::Shape)?;
    if layouts.interaction_trace.is_some() != oracle_roots.interaction_trace.is_some() {
        return Err(FriPipelineError::Shape);
    }
    let claims_commitment = deep_claims_commitment_binding_v2(
        &layouts.program_binary_commitment,
        query_point,
        claims,
        &oracle_roots.main_trace,
        oracle_roots.interaction_trace.as_ref(),
        &oracle_roots.composition,
    )
    .map_err(|_| FriPipelineError::Shape)?;
    let mask_layout = fri_mask_layout_binding_v2(&claims_commitment, claims)?;
    let selected = binding_selected_indices_v3(
        &layouts,
        mask_layout.maximum_log_size(),
        expected_query_indices,
    )?;
    let fri_layer_log_sizes = (2..=mask_layout.maximum_log_size()).rev().collect();
    Ok(FriPipelineProofV3Geometry {
        mask_layout,
        main_layout: layouts.main_trace,
        interaction_layout: layouts.interaction_trace,
        composition_layout: layouts.composition,
        mask_indices: selected.mask,
        main_indices: selected.main,
        interaction_indices: selected.interaction,
        composition_indices: selected.composition,
        fri_layer_log_sizes,
    })
}

fn selected_indices_match_v3(
    proof: &BindingCrossDomainMultiProofV2,
    expected: &[usize],
) -> Result<bool, FriPipelineError> {
    let expected = expected
        .iter()
        .copied()
        .map(|index| u64::try_from(index).map_err(|_| FriPipelineError::CountOverflow))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(proof.proof().selected_indices() == expected)
}

fn binding_query_views_v3(
    proof: &FriPipelineProofV3,
    layouts: &crate::oracle_commitment::OracleCommitmentLayouts,
    largest_log: u8,
) -> Result<Vec<FriPipelineQueryProof>, FriPipelineError> {
    proof
        .query_indices
        .iter()
        .copied()
        .map(|initial_index| {
            let pair_start = initial_index & !1;
            let main_left_index = projected_index(
                pair_start,
                largest_log,
                layouts.main_trace.maximum_log_size(),
            )?;
            let main_right_index = projected_index(
                pair_start + 1,
                largest_log,
                layouts.main_trace.maximum_log_size(),
            )?;
            let composition_left_index = projected_index(
                pair_start,
                largest_log,
                layouts.composition.maximum_log_size(),
            )?;
            let composition_right_index = projected_index(
                pair_start + 1,
                largest_log,
                layouts.composition.maximum_log_size(),
            )?;
            let (interaction_left, interaction_right) = if let (Some(layout), Some(interaction)) =
                (&layouts.interaction_trace, &proof.interaction)
            {
                (
                    Some(
                        interaction
                            .row(projected_index(
                                pair_start,
                                largest_log,
                                layout.maximum_log_size(),
                            )?)?
                            .arithmetic_view(),
                    ),
                    Some(
                        interaction
                            .row(projected_index(
                                pair_start + 1,
                                largest_log,
                                layout.maximum_log_size(),
                            )?)?
                            .arithmetic_view(),
                    ),
                )
            } else if layouts.interaction_trace.is_none() && proof.interaction.is_none() {
                (None, None)
            } else {
                return Err(FriPipelineError::Shape);
            };
            let mut next_main_indices = BTreeSet::new();
            for geometry in &layouts.tables {
                if geometry.main_column_count == 0 {
                    continue;
                }
                let current =
                    projected_index(initial_index, largest_log, geometry.evaluation_log_size)?;
                let shifted = shifted_fft_index(
                    current,
                    geometry.evaluation_log_size,
                    geometry.trace_log_size,
                )
                .map_err(|_| FriPipelineError::Shape)?;
                next_main_indices.insert(lifted_index(
                    shifted,
                    geometry.evaluation_log_size,
                    layouts.main_trace.maximum_log_size(),
                )?);
            }
            let next_main = next_main_indices
                .into_iter()
                .map(|index| Ok(proof.main.row(index)?.arithmetic_view()))
                .collect::<Result<Vec<_>, FriPipelineError>>()?;
            let mut next_interaction_indices = BTreeSet::new();
            if let Some(layout) = &layouts.interaction_trace {
                for geometry in &layouts.interactions {
                    let current =
                        projected_index(initial_index, largest_log, geometry.evaluation_log_size)?;
                    let shifted = shifted_fft_index(
                        current,
                        geometry.evaluation_log_size,
                        layouts.tables[geometry.table_index].trace_log_size,
                    )
                    .map_err(|_| FriPipelineError::Shape)?;
                    next_interaction_indices.insert(lifted_index(
                        shifted,
                        geometry.evaluation_log_size,
                        layout.maximum_log_size(),
                    )?);
                }
            }
            let next_interaction = match &proof.interaction {
                Some(interaction) => next_interaction_indices
                    .into_iter()
                    .map(|index| Ok(interaction.row(index)?.arithmetic_view()))
                    .collect::<Result<Vec<_>, FriPipelineError>>()?,
                None if next_interaction_indices.is_empty() => Vec::new(),
                None => return Err(FriPipelineError::Shape),
            };
            Ok(FriPipelineQueryProof {
                initial_index,
                mask_left: proof.mask.row(pair_start)?.arithmetic_view(),
                mask_right: proof.mask.row(pair_start + 1)?.arithmetic_view(),
                main_left: proof.main.row(main_left_index)?.arithmetic_view(),
                main_right: proof.main.row(main_right_index)?.arithmetic_view(),
                interaction_left,
                interaction_right,
                composition_left: proof
                    .composition
                    .row(composition_left_index)?
                    .arithmetic_view(),
                composition_right: proof
                    .composition
                    .row(composition_right_index)?
                    .arithmetic_view(),
                next_main,
                next_interaction,
                layers: Vec::new(),
            })
        })
        .collect()
}

/// Build the canonical selected-v3 proof entirely from native BindingRootV2
/// trees. Legacy paths are not copied into the returned object.
#[allow(clippy::too_many_arguments)]
pub fn prove_fri_pipeline_v3(
    program_encoded: &[u8],
    mask_coefficient_count: usize,
    log_blowup: u8,
    deep: &DeepQuotientOracles,
    pipeline: &FriPipeline,
    binding_mask_tree: &BindingCrossDomainTreeV2,
    binding_oracles: &BindingCommittedAirOraclesV2,
    logup: &AirLogupOracle,
    binding_layer_roots: &[BindingRootV2],
    query_indices: &[usize],
) -> Result<FriPipelineProofV3, FriPipelineError> {
    let oracle_layouts = derive_binding_oracle_commitment_layouts_v2(
        program_encoded,
        mask_coefficient_count,
        log_blowup,
    )
    .map_err(|_| FriPipelineError::Shape)?;
    let roots = binding_oracles.roots();
    let claims_commitment = deep_claims_commitment_binding_v2(
        &oracle_layouts.program_binary_commitment,
        deep.query,
        &deep.claims,
        &roots.main_trace,
        roots.interaction_trace.as_ref(),
        &roots.composition,
    )
    .map_err(|_| FriPipelineError::Shape)?;
    let mask_layout = fri_mask_layout_binding_v2(&claims_commitment, &deep.claims)?;
    if binding_oracles.main_trace.layout() != &oracle_layouts.main_trace
        || binding_oracles
            .interaction_trace
            .as_ref()
            .map(BindingCrossDomainTreeV2::layout)
            != oracle_layouts.interaction_trace.as_ref()
        || binding_oracles.composition.layout() != &oracle_layouts.composition
        || binding_mask_tree.layout() != &mask_layout
        || pipeline.cascade.fold_log_sizes.len() != binding_layer_roots.len()
        || pipeline.cascade.folded_layers.len() != binding_layer_roots.len()
    {
        return Err(FriPipelineError::Shape);
    }
    let largest_log = mask_layout.maximum_log_size();
    let selected = binding_selected_indices_v3(&oracle_layouts, largest_log, query_indices)?;
    let mask = binding_mask_tree.proof(&selected.mask)?;
    let main = binding_oracles.main_trace.proof(&selected.main)?;
    let interaction = match &binding_oracles.interaction_trace {
        Some(tree) => Some(tree.proof(&selected.interaction)?),
        None if selected.interaction.is_empty() => None,
        None => return Err(FriPipelineError::Shape),
    };
    let composition = binding_oracles.composition.proof(&selected.composition)?;
    let fri_layers = build_fri_layer_binding_multiproofs_v2(
        &pipeline.cascade.fold_log_sizes,
        &pipeline.cascade.folded_layers,
        binding_layer_roots,
        query_indices,
    )?;
    Ok(FriPipelineProofV3 {
        logup_final_sums: logup
            .interactions
            .iter()
            .map(|interaction| interaction.final_sum)
            .collect(),
        query_indices: query_indices.to_vec(),
        mask,
        main,
        interaction,
        composition,
        fri_layers,
    })
}

/// Build the native BindingRootV2 proof seam from the exact in-memory legacy
/// prover state.  No legacy root or authentication path is copied into the
/// returned proof.  Callers must still pass the returned proof and all
/// returned commitments through `verify_fri_pipeline_v3_receipt` before they
/// can enter any accepting composition.
#[allow(clippy::too_many_arguments)]
pub fn prove_fri_pipeline_v3_from_legacy(
    program_encoded: &[u8],
    mask_coefficient_count: usize,
    log_blowup: u8,
    deep: &DeepQuotientOracles,
    pipeline: &FriPipeline,
    oracles: &CommittedAirOracles,
    logup: &AirLogupOracle,
    query_indices: &[usize],
) -> Result<NativeFriPipelineV3Construction, FriPipelineError> {
    let binding_oracles = oracles
        .binding_v2(program_encoded, mask_coefficient_count, log_blowup)
        .map_err(|_| FriPipelineError::Shape)?;
    let oracle_roots = binding_oracles.roots();
    let native_layouts = derive_binding_oracle_commitment_layouts_v2(
        program_encoded,
        mask_coefficient_count,
        log_blowup,
    )
    .map_err(|_| FriPipelineError::Shape)?;
    let claims_commitment = deep_claims_commitment_binding_v2(
        &native_layouts.program_binary_commitment,
        deep.query,
        &deep.claims,
        &oracle_roots.main_trace,
        oracle_roots.interaction_trace.as_ref(),
        &oracle_roots.composition,
    )
    .map_err(|_| FriPipelineError::Shape)?;
    let binding_mask_layout = fri_mask_layout_binding_v2(&claims_commitment, &deep.claims)?;
    let binding_mask_tree = pipeline.mask_tree.binding_v2_tree(binding_mask_layout)?;
    let binding_layer_roots = pipeline
        .cascade
        .fold_log_sizes
        .iter()
        .copied()
        .zip(&pipeline.cascade.folded_layers)
        .map(|(log_size, values)| binding_fri_layer_root_v2(log_size, values))
        .collect::<Result<Vec<_>, _>>()?;
    let proof = prove_fri_pipeline_v3(
        program_encoded,
        mask_coefficient_count,
        log_blowup,
        deep,
        pipeline,
        &binding_mask_tree,
        &binding_oracles,
        logup,
        &binding_layer_roots,
        query_indices,
    )?;
    Ok(NativeFriPipelineV3Construction {
        proof,
        oracle_roots: binding_oracles.roots(),
        mask_root: binding_mask_tree.root(),
        layer_roots: binding_layer_roots,
    })
}

/// Verify a generic AIR/FRI instance whose complete PCS surface uses native
/// BindingRootV2 commitments. The exact program bytes and ordered public
/// inputs are verifier-owned inputs to this function; no selected-program
/// identity or caller assertion is accepted from the proof.
#[allow(clippy::too_many_arguments)]
pub fn verify_fri_pipeline_v3(
    proof: &FriPipelineProofV3,
    program_encoded: &[u8],
    mask_coefficient_count: usize,
    log_blowup: u8,
    supplied_public_inputs: &[M31],
    composition_alpha: Fp16,
    logup_beta: Fp16,
    logup_gamma: Fp16,
    oracle_roots: &BindingCommittedAirRootsV2,
    mask_root: &BindingRootV2,
    query_point: CirclePoint,
    claims: &[DomainOodsClaims],
    batch_coefficient: Fp16,
    fold_coefficients: &[Fp16],
    layer_roots: &[BindingRootV2],
    final_constant: Fp16,
    expected_query_indices: &[usize],
) -> Result<bool, FriPipelineError> {
    let oracle_layouts = derive_binding_oracle_commitment_layouts_v2(
        program_encoded,
        mask_coefficient_count,
        log_blowup,
    )
    .map_err(|_| FriPipelineError::Shape)?;
    let claims_commitment = deep_claims_commitment_binding_v2(
        &oracle_layouts.program_binary_commitment,
        query_point,
        claims,
        &oracle_roots.main_trace,
        oracle_roots.interaction_trace.as_ref(),
        &oracle_roots.composition,
    )
    .map_err(|_| FriPipelineError::Shape)?;
    let mask_layout = fri_mask_layout_binding_v2(&claims_commitment, claims)?;
    if proof.query_indices != expected_query_indices
        || proof.fri_layers.query_indices != expected_query_indices
        || oracle_layouts.interaction_trace.is_some() != oracle_roots.interaction_trace.is_some()
        || oracle_layouts.interaction_trace.is_some() != proof.interaction.is_some()
    {
        return Err(FriPipelineError::Shape);
    }

    let selected = binding_selected_indices_v3(
        &oracle_layouts,
        mask_layout.maximum_log_size(),
        expected_query_indices,
    )?;
    if !selected_indices_match_v3(&proof.mask, &selected.mask)?
        || !selected_indices_match_v3(&proof.main, &selected.main)?
        || !selected_indices_match_v3(&proof.composition, &selected.composition)?
    {
        return Err(FriPipelineError::Query);
    }
    match (
        &oracle_layouts.interaction_trace,
        &oracle_roots.interaction_trace,
        &proof.interaction,
    ) {
        (Some(_), Some(_), Some(interaction)) => {
            if !selected_indices_match_v3(interaction, &selected.interaction)? {
                return Err(FriPipelineError::Query);
            }
        }
        (None, None, None) if selected.interaction.is_empty() => {}
        _ => return Err(FriPipelineError::Shape),
    }

    proof.mask.verify(&mask_layout, mask_root)?;
    proof
        .main
        .verify(&oracle_layouts.main_trace, &oracle_roots.main_trace)?;
    if let (Some(layout), Some(root), Some(interaction)) = (
        &oracle_layouts.interaction_trace,
        &oracle_roots.interaction_trace,
        &proof.interaction,
    ) {
        interaction.verify(layout, root)?;
    }
    proof
        .composition
        .verify(&oracle_layouts.composition, &oracle_roots.composition)?;
    verify_fri_layer_binding_multiproofs_v2(
        &proof.fri_layers,
        expected_query_indices,
        layer_roots,
    )?;

    let queries = binding_query_views_v3(proof, &oracle_layouts, mask_layout.maximum_log_size())?;
    verify_fri_pipeline_openings(
        &proof.logup_final_sums,
        &queries,
        None,
        Some(&proof.fri_layers),
        program_encoded,
        mask_coefficient_count,
        log_blowup,
        supplied_public_inputs,
        composition_alpha,
        logup_beta,
        logup_gamma,
        PipelineAuthentication::BindingV2 {
            oracle_roots,
            layer_roots,
        },
        query_point,
        claims,
        batch_coefficient,
        fold_coefficients,
        final_constant,
        expected_query_indices,
    )
}

/// Verify and retain exactly the authenticated data needed by downstream
/// proof-native bridge adapters.
#[allow(clippy::too_many_arguments)]
pub fn verify_fri_pipeline_v3_receipt(
    proof: &FriPipelineProofV3,
    program_encoded: &[u8],
    mask_coefficient_count: usize,
    log_blowup: u8,
    supplied_public_inputs: &[M31],
    composition_alpha: Fp16,
    logup_beta: Fp16,
    logup_gamma: Fp16,
    oracle_roots: &BindingCommittedAirRootsV2,
    mask_root: &BindingRootV2,
    query_point: CirclePoint,
    claims: &[DomainOodsClaims],
    batch_coefficient: Fp16,
    fold_coefficients: &[Fp16],
    layer_roots: &[BindingRootV2],
    final_constant: Fp16,
    expected_query_indices: &[usize],
) -> Result<VerifiedFriPipelineV3, FriPipelineError> {
    if !verify_fri_pipeline_v3(
        proof,
        program_encoded,
        mask_coefficient_count,
        log_blowup,
        supplied_public_inputs,
        composition_alpha,
        logup_beta,
        logup_gamma,
        oracle_roots,
        mask_root,
        query_point,
        claims,
        batch_coefficient,
        fold_coefficients,
        layer_roots,
        final_constant,
        expected_query_indices,
    )? {
        return Err(FriPipelineError::Shape);
    }
    let mut program_frame = b"BL/PQ512/WAVE2/VERIFIED-FRI-V3-PROGRAM/v1\0".to_vec();
    program_frame.extend_from_slice(
        &u64::try_from(program_encoded.len())
            .map_err(|_| FriPipelineError::CountOverflow)?
            .to_be_bytes(),
    );
    program_frame.extend_from_slice(program_encoded);
    let program_binding = BindingDigestV2::hash(BindingRoleV2::Payload, &program_frame)
        .map_err(|_| FriPipelineError::Shape)?;
    let mut public_input_frame = b"BL/PQ512/WAVE2/SEMANTIC-V3-PUBLIC-INPUTS/v1\0".to_vec();
    public_input_frame.extend_from_slice(
        &u32::try_from(supplied_public_inputs.len())
            .map_err(|_| FriPipelineError::CountOverflow)?
            .to_be_bytes(),
    );
    for value in supplied_public_inputs {
        public_input_frame.extend_from_slice(&value.as_u32().to_be_bytes());
    }
    let public_inputs_binding = BindingDigestV2::hash(BindingRoleV2::Payload, &public_input_frame)
        .map_err(|_| FriPipelineError::Shape)?;
    let mut receipt_frame = b"BL/PQ512/WAVE2/VERIFIED-FRI-V3/v1\0".to_vec();
    receipt_frame.extend_from_slice(program_binding.as_bytes());
    receipt_frame.extend_from_slice(public_inputs_binding.as_bytes());
    receipt_frame.extend_from_slice(oracle_roots.main_trace.as_bytes());
    match oracle_roots.interaction_trace {
        Some(root) => receipt_frame.extend_from_slice(root.as_bytes()),
        None => receipt_frame.extend_from_slice(&[0_u8; 128]),
    }
    receipt_frame.extend_from_slice(oracle_roots.composition.as_bytes());
    receipt_frame.extend_from_slice(&query_point.x.encode());
    receipt_frame.extend_from_slice(&query_point.y.encode());
    receipt_frame.extend_from_slice(
        &u32::try_from(claims.len())
            .map_err(|_| FriPipelineError::CountOverflow)?
            .to_be_bytes(),
    );
    for claim in claims {
        receipt_frame.push(claim.log_size);
        receipt_frame.extend_from_slice(
            &u32::try_from(claim.values.len())
                .map_err(|_| FriPipelineError::CountOverflow)?
                .to_be_bytes(),
        );
        for value in &claim.values {
            receipt_frame.extend_from_slice(&value.encode());
        }
        receipt_frame.extend_from_slice(
            &u32::try_from(claim.conjugate_values.len())
                .map_err(|_| FriPipelineError::CountOverflow)?
                .to_be_bytes(),
        );
        for value in &claim.conjugate_values {
            receipt_frame.extend_from_slice(&value.encode());
        }
    }
    let receipt_binding = BindingDigestV2::hash(BindingRoleV2::Payload, &receipt_frame)
        .map_err(|_| FriPipelineError::Shape)?;
    Ok(VerifiedFriPipelineV3 {
        receipt_binding,
        public_inputs_binding,
        program_binding,
        oracle_roots: oracle_roots.clone(),
        query_point,
        claims: claims.to_vec(),
    })
}

#[derive(Clone, Copy)]
enum PipelineAuthentication<'a> {
    Legacy {
        oracle_roots: &'a CommittedAirRoots,
        mask_root: &'a CrossDomainRoot,
        layer_roots: &'a [RootHash],
    },
    BindingV2 {
        oracle_roots: &'a BindingCommittedAirRootsV2,
        layer_roots: &'a [BindingRootV2],
    },
}

impl PipelineAuthentication<'_> {
    fn layer_count(self) -> usize {
        match self {
            Self::Legacy { layer_roots, .. } => layer_roots.len(),
            Self::BindingV2 { layer_roots, .. } => layer_roots.len(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_fri_pipeline_openings(
    logup_final_sums: &[Fp16],
    queries: &[FriPipelineQueryProof],
    fri_layer_multiproofs: Option<&FriPipelineCanonicalMultiproofs>,
    binding_fri_layer_multiproofs: Option<&FriPipelineBindingMultiproofsV2>,
    program_encoded: &[u8],
    mask_coefficient_count: usize,
    log_blowup: u8,
    supplied_public_inputs: &[M31],
    composition_alpha: Fp16,
    logup_beta: Fp16,
    logup_gamma: Fp16,
    authentication: PipelineAuthentication<'_>,
    query_point: CirclePoint,
    claims: &[DomainOodsClaims],
    batch_coefficient: Fp16,
    fold_coefficients: &[Fp16],
    final_constant: Fp16,
    expected_query_indices: &[usize],
) -> Result<bool, FriPipelineError> {
    let program = parse_air_program(program_encoded).map_err(|_| FriPipelineError::Shape)?;
    let oracle_layouts = match authentication {
        PipelineAuthentication::Legacy { .. } => {
            derive_oracle_commitment_layouts(program_encoded, mask_coefficient_count, log_blowup)
        }
        PipelineAuthentication::BindingV2 { .. } => derive_binding_oracle_commitment_layouts_v2(
            program_encoded,
            mask_coefficient_count,
            log_blowup,
        ),
    }
    .map_err(|_| FriPipelineError::Shape)?;
    let mask_layout = match authentication {
        PipelineAuthentication::Legacy { oracle_roots, .. } => {
            let main_root_bytes = oracle_roots.main_trace.into_bytes();
            let interaction_root_bytes =
                oracle_roots.interaction_trace.map(|root| root.into_bytes());
            let composition_root_bytes = oracle_roots.composition.into_bytes();
            let claims_commitment = deep_claims_commitment(
                &oracle_layouts.program_binary_commitment,
                query_point,
                claims,
                &main_root_bytes,
                interaction_root_bytes.as_ref(),
                &composition_root_bytes,
            )
            .map_err(|_| FriPipelineError::Shape)?;
            fri_mask_layout(&claims_commitment, claims)?
        }
        PipelineAuthentication::BindingV2 { oracle_roots, .. } => {
            let claims_commitment = deep_claims_commitment_binding_v2(
                &oracle_layouts.program_binary_commitment,
                query_point,
                claims,
                &oracle_roots.main_trace,
                oracle_roots.interaction_trace.as_ref(),
                &oracle_roots.composition,
            )
            .map_err(|_| FriPipelineError::Shape)?;
            fri_mask_layout_binding_v2(&claims_commitment, claims)?
        }
    };
    let interaction_root_present = match authentication {
        PipelineAuthentication::Legacy { oracle_roots, .. } => {
            oracle_roots.interaction_trace.is_some()
        }
        PipelineAuthentication::BindingV2 { oracle_roots, .. } => {
            oracle_roots.interaction_trace.is_some()
        }
    };
    if oracle_layouts.interaction_trace.is_some() != interaction_root_present {
        return Err(FriPipelineError::Shape);
    }
    if queries.len() != expected_query_indices.len()
        || queries.is_empty()
        || batch_coefficient.is_zero()
        || fold_coefficients.len() != authentication.layer_count()
        || fold_coefficients.is_empty()
        || (fri_layer_multiproofs.is_some() && binding_fri_layer_multiproofs.is_some())
    {
        return Err(FriPipelineError::Shape);
    }
    let largest_log = mask_layout.maximum_log_size();
    if fold_coefficients.len() != usize::from(largest_log - 1) {
        return Err(FriPipelineError::Shape);
    }
    let fold_logs = (2..=largest_log).rev().collect::<Vec<_>>();
    if fold_logs.len() != fold_coefficients.len() {
        return Err(FriPipelineError::Shape);
    }
    let mut descending_specs = claims
        .iter()
        .map(|claim| {
            DomainSpec::new(
                claim.log_size,
                EvaluationField::Fp16,
                u32::try_from(claim.values.len() * 2)
                    .map_err(|_| FriPipelineError::CountOverflow)?,
            )
            .map_err(FriPipelineError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    descending_specs.reverse();
    if descending_specs
        .iter()
        .any(|spec| spec.field != EvaluationField::Fp16)
        || mask_layout.specs().len() != descending_specs.len()
        || mask_layout
            .specs()
            .iter()
            .zip(descending_specs.iter().rev())
            .any(|(mask, deep)| {
                mask.log_size != deep.log_size
                    || mask.field != EvaluationField::Fp16
                    || mask.column_count != 1
            })
    {
        return Err(FriPipelineError::Shape);
    }
    let mut next_offset = 0_usize;
    let offsets = descending_specs
        .iter()
        .map(|spec| {
            let current = next_offset;
            next_offset = next_offset
                .checked_add(spec.column_count as usize)
                .ok_or(FriPipelineError::CountOverflow)?;
            Ok(current)
        })
        .collect::<Result<Vec<_>, FriPipelineError>>()?;

    let mut air_cache = AirVerificationCache::default();
    for (query, expected_index) in queries.iter().zip(expected_query_indices) {
        if query.initial_index != *expected_index
            || query.initial_index >= 1_usize << largest_log
            || if fri_layer_multiproofs.is_some() || binding_fri_layer_multiproofs.is_some() {
                !query.layers.is_empty()
            } else {
                query.layers.len() != fold_logs.len()
            }
        {
            return Err(FriPipelineError::Query);
        }
        let pair_start = query.initial_index & !1;
        let main_left_index = projected_index(
            pair_start,
            largest_log,
            oracle_layouts.main_trace.maximum_log_size(),
        )?;
        let main_right_index = projected_index(
            pair_start + 1,
            largest_log,
            oracle_layouts.main_trace.maximum_log_size(),
        )?;
        for (candidate, expected) in [
            (&query.main_left, main_left_index),
            (&query.main_right, main_right_index),
        ] {
            let authenticated = match authentication {
                PipelineAuthentication::Legacy { oracle_roots, .. } => {
                    candidate.verify(&oracle_layouts.main_trace, &oracle_roots.main_trace)?
                }
                PipelineAuthentication::BindingV2 { .. } => true,
            };
            if candidate.query_fft_index() != expected || !authenticated {
                return Err(FriPipelineError::Authentication);
            }
        }
        let composition_left_index = projected_index(
            pair_start,
            largest_log,
            oracle_layouts.composition.maximum_log_size(),
        )?;
        let composition_right_index = projected_index(
            pair_start + 1,
            largest_log,
            oracle_layouts.composition.maximum_log_size(),
        )?;
        for (candidate, expected) in [
            (&query.composition_left, composition_left_index),
            (&query.composition_right, composition_right_index),
        ] {
            let authenticated = match authentication {
                PipelineAuthentication::Legacy { oracle_roots, .. } => {
                    candidate.verify(&oracle_layouts.composition, &oracle_roots.composition)?
                }
                PipelineAuthentication::BindingV2 { .. } => true,
            };
            if candidate.query_fft_index() != expected || !authenticated {
                return Err(FriPipelineError::Authentication);
            }
        }
        match (
            &oracle_layouts.interaction_trace,
            &query.interaction_left,
            &query.interaction_right,
        ) {
            (Some(layout), Some(left), Some(right)) => {
                let expected_left =
                    projected_index(pair_start, largest_log, layout.maximum_log_size())?;
                let expected_right =
                    projected_index(pair_start + 1, largest_log, layout.maximum_log_size())?;
                let authenticated = match authentication {
                    PipelineAuthentication::Legacy { oracle_roots, .. } => {
                        let root = oracle_roots
                            .interaction_trace
                            .as_ref()
                            .ok_or(FriPipelineError::Shape)?;
                        left.verify(layout, root)? && right.verify(layout, root)?
                    }
                    PipelineAuthentication::BindingV2 { .. } => true,
                };
                if left.query_fft_index() != expected_left
                    || right.query_fft_index() != expected_right
                    || !authenticated
                {
                    return Err(FriPipelineError::Authentication);
                }
            }
            (None, None, None) => {}
            _ => return Err(FriPipelineError::Shape),
        }
        if !verify_air_composition_query(
            query,
            &program,
            &oracle_layouts,
            match authentication {
                PipelineAuthentication::Legacy { oracle_roots, .. } => Some(oracle_roots),
                PipelineAuthentication::BindingV2 { .. } => None,
            },
            supplied_public_inputs,
            composition_alpha,
            logup_beta,
            logup_gamma,
            logup_final_sums,
            largest_log,
            &mut air_cache,
        )? {
            return Ok(false);
        }
        for (candidate, expected) in [
            (&query.mask_left, pair_start),
            (&query.mask_right, pair_start + 1),
        ] {
            let authenticated = match authentication {
                PipelineAuthentication::Legacy { mask_root, .. } => {
                    candidate.verify(&mask_layout, mask_root)?
                }
                PipelineAuthentication::BindingV2 { .. } => true,
            };
            if candidate.query_fft_index() != expected || !authenticated {
                return Ok(false);
            }
        }

        let mut output_index = query.initial_index >> 1;
        let mut prior_pair: Option<[Fp16; 2]> = None;
        for (round, log_size) in fold_logs.iter().copied().enumerate() {
            let layer_pair_start = output_index & !1;
            let layer_pair = if let Some(multiproofs) = binding_fri_layer_multiproofs {
                let layer = multiproofs
                    .layers
                    .get(round)
                    .ok_or(FriPipelineError::Shape)?;
                if layer.log_size != log_size {
                    return Err(FriPipelineError::Shape);
                }
                multiproofs.opened_pair(round, layer_pair_start)?
            } else if let Some(multiproofs) = fri_layer_multiproofs {
                let layer = multiproofs
                    .layers
                    .get(round)
                    .ok_or(FriPipelineError::Shape)?;
                if layer.log_size != log_size {
                    return Err(FriPipelineError::Shape);
                }
                multiproofs.opened_pair(round, layer_pair_start)?
            } else {
                let layer = &query.layers[round];
                let root = match authentication {
                    PipelineAuthentication::Legacy { layer_roots, .. } => {
                        layer_roots.get(round).ok_or(FriPipelineError::Shape)?
                    }
                    PipelineAuthentication::BindingV2 { .. } => {
                        return Err(FriPipelineError::Shape);
                    }
                };
                if !verify_layer_opening(layer, log_size, root, layer_pair_start)? {
                    return Ok(false);
                }
                [layer.left, layer.right]
            };
            let folded_prior = prior_pair
                .map(|pair| fold_line_pair(&pair, output_index, log_size, fold_coefficients[round]))
                .transpose()?;
            let attached = descending_specs
                .iter()
                .zip(&offsets)
                .find(|(spec, _)| spec.log_size == log_size);
            let computed = if let Some((spec, offset)) = attached {
                let mask_left = opening_at(&query.mask_left, log_size)?;
                let mask_right = opening_at(&query.mask_right, log_size)?;
                let input_pair_start = output_index << 1;
                let (left_index, left_originals) =
                    authenticated_original_row(query, true, log_size)?;
                let (right_index, right_originals) =
                    authenticated_original_row(query, false, log_size)?;
                if left_index != input_pair_start
                    || right_index != input_pair_start + 1
                    || mask_left.fft_index != input_pair_start
                    || mask_right.fft_index != input_pair_start + 1
                {
                    return Err(FriPipelineError::Query);
                }
                let claim = claims
                    .iter()
                    .find(|claim| claim.log_size == log_size)
                    .ok_or(FriPipelineError::Shape)?;
                if left_originals.len() != claim.values.len()
                    || right_originals.len() != claim.values.len()
                {
                    return Err(FriPipelineError::Shape);
                }
                let left_point =
                    canonic_circle_point(log_size, bit_reverse_index(left_index, log_size)?)?;
                let right_point =
                    canonic_circle_point(log_size, bit_reverse_index(right_index, log_size)?)?;
                let left_row = degree_corrected_row(
                    left_point,
                    query_point,
                    &left_originals,
                    &claim.values,
                    &claim.conjugate_values,
                )?
                .fri_batch_values();
                let right_row = degree_corrected_row(
                    right_point,
                    query_point,
                    &right_originals,
                    &claim.values,
                    &claim.conjugate_values,
                )?
                .fri_batch_values();
                let left_mask = decode_fp16_row(mask_left)?;
                let right_mask = decode_fp16_row(mask_right)?;
                let left = batch_row(&left_row, left_mask[0], batch_coefficient, *offset);
                let right = batch_row(&right_row, right_mask[0], batch_coefficient, *offset);
                if left_row.len() != spec.column_count as usize {
                    return Err(FriPipelineError::Shape);
                }
                let folded_batch = fold_circle_pair(
                    &[left, right],
                    input_pair_start >> 1,
                    log_size,
                    fold_coefficients[round],
                )?;
                if let Some(prior) = folded_prior {
                    fold_coefficients[round]
                        .square()
                        .mul(prior)
                        .add(folded_batch)
                } else {
                    folded_batch
                }
            } else {
                folded_prior.ok_or(FriPipelineError::Shape)?
            };
            let observed = layer_pair[output_index & 1];
            if computed != observed {
                return Ok(false);
            }
            prior_pair = Some(layer_pair);
            output_index >>= 1;
        }
        if fri_layer_multiproofs.is_none()
            && binding_fri_layer_multiproofs.is_none()
            && query
                .layers
                .last()
                .ok_or(FriPipelineError::Shape)?
                .left_proof
                .leaf_count()
                != 2
        {
            return Ok(false);
        }
        let terminal = prior_pair.ok_or(FriPipelineError::Shape)?;
        if terminal[0] != final_constant || terminal[1] != final_constant {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Build and commit the independent FRI masks before the batching challenge.
pub fn build_fri_mask_oracle(
    deep: &DeepQuotientOracles,
    claims_commitment: [u8; 64],
    secret_mask_seed: &[u8],
    session_id: &[u8],
) -> Result<FriMaskOracle, FriPipelineError> {
    if deep.batches.is_empty() || !claims_commitment.iter().any(|byte| *byte != 0) {
        return Err(FriPipelineError::Shape);
    }
    let mut degree_bounds = Vec::with_capacity(deep.batches.len());
    let mut masks = Vec::with_capacity(deep.batches.len());
    for batch in &deep.batches {
        let degree_bound = exact_degree_bound(batch)?;
        degree_bounds.push(degree_bound);
        let coefficients = sample_extension_trace_mask_coefficients(
            secret_mask_seed,
            session_id,
            &mask_id(&claims_commitment, batch.log_size),
            degree_bound,
        )?;
        let evaluations = evaluate_extension_circle_coefficients(&coefficients, batch.log_size)?;
        masks.push(FriDomainBatch::new(
            batch.log_size,
            evaluations.into_iter().map(|value| vec![value]).collect(),
        )?);
    }
    let mask_tree =
        CrossDomainTree::build_fri_batch_mask_tree(mask_id(&claims_commitment, 0), &masks)?;
    Ok(FriMaskOracle {
        claims_commitment,
        degree_bounds,
        masks,
        mask_tree,
    })
}

/// Apply the later batching challenge without consuming any fold challenge.
pub fn start_interactive_fri(
    deep: &DeepQuotientOracles,
    mask: FriMaskOracle,
    batch_coefficient: Fp16,
) -> Result<InteractiveFriBuilder, FriPipelineError> {
    if deep.batches.is_empty()
        || batch_coefficient.is_zero()
        || mask.masks.len() != deep.batches.len()
    {
        return Err(FriPipelineError::Shape);
    }
    let domain_log_sizes = deep
        .batches
        .iter()
        .map(|batch| batch.log_size)
        .collect::<Vec<_>>();
    if domain_log_sizes.windows(2).any(|pair| pair[0] <= pair[1]) {
        return Err(FriPipelineError::Shape);
    }
    let largest_log = domain_log_sizes[0];
    let fold_log_sizes = (2..=largest_log).rev().collect::<Vec<_>>();
    let batch_column_counts = deep
        .batches
        .iter()
        .map(FriDomainBatch::column_count)
        .collect::<Vec<_>>();
    let mut next_offset = 0_usize;
    let batch_power_offsets = batch_column_counts
        .iter()
        .map(|count| {
            let current = next_offset;
            next_offset = next_offset
                .checked_add(*count)
                .ok_or(FriPipelineError::CountOverflow)?;
            Ok(current)
        })
        .collect::<Result<Vec<_>, FriPipelineError>>()?;
    let mut batch_masks = Vec::with_capacity(deep.batches.len());
    let mut batched_domains = Vec::with_capacity(deep.batches.len());
    for ((batch, mask_batch), power_offset) in deep
        .batches
        .iter()
        .zip(&mask.masks)
        .zip(&batch_power_offsets)
    {
        if batch.log_size != mask_batch.log_size || mask_batch.column_count() != 1 {
            return Err(FriPipelineError::Shape);
        }
        let mask_values = mask_batch.rows.iter().map(|row| row[0]).collect::<Vec<_>>();
        let batched = batch
            .rows
            .iter()
            .zip(&mask_values)
            .map(|(row, mask_value)| batch_row(row, *mask_value, batch_coefficient, *power_offset))
            .collect::<Vec<_>>();
        batch_masks.push(mask_values);
        batched_domains.push(batched);
    }
    Ok(InteractiveFriBuilder {
        claims_commitment: mask.claims_commitment,
        degree_bounds: mask.degree_bounds,
        masks: mask.masks,
        mask_tree: mask.mask_tree,
        domain_log_sizes,
        batch_column_counts,
        batch_power_offsets,
        batch_masks,
        batched_domains,
        fold_log_sizes,
        folded_layers: Vec::new(),
        layer_roots: Vec::new(),
        fold_coefficients: Vec::new(),
        batch_coefficient,
    })
}

impl InteractiveFriBuilder {
    pub fn fold_round_count(&self) -> usize {
        self.fold_log_sizes.len()
    }

    pub fn completed_fold_count(&self) -> usize {
        self.folded_layers.len()
    }

    /// Consume exactly one fresh challenge and return the newly committed root.
    pub fn fold_next(&mut self, coefficient: Fp16) -> Result<RootHash, FriPipelineError> {
        if coefficient.is_zero() || self.folded_layers.len() >= self.fold_log_sizes.len() {
            return Err(FriPipelineError::Shape);
        }
        let round = self.folded_layers.len();
        let log_size = self.fold_log_sizes[round];
        let folded_previous = self
            .folded_layers
            .last()
            .map(|values| fold_line(values, coefficient))
            .transpose()?;
        let batch_index = self
            .domain_log_sizes
            .iter()
            .position(|value| *value == log_size);
        let current = if let Some(index) = batch_index {
            let folded_batch = fold_circle_into_line(&self.batched_domains[index], coefficient)?;
            if let Some(previous) = folded_previous {
                if previous.len() != folded_batch.len() {
                    return Err(FriPipelineError::Shape);
                }
                let squared = coefficient.square();
                previous
                    .into_iter()
                    .zip(folded_batch)
                    .map(|(prior, added)| squared.mul(prior).add(added))
                    .collect::<Vec<_>>()
            } else {
                folded_batch
            }
        } else {
            folded_previous.ok_or(FriPipelineError::Shape)?
        };
        let root = layer_tree(log_size, &current)?.root();
        self.fold_coefficients.push(coefficient);
        self.folded_layers.push(current);
        self.layer_roots.push(root);
        Ok(root)
    }

    pub fn finish(self) -> Result<FriPipeline, FriPipelineError> {
        if self.folded_layers.len() != self.fold_log_sizes.len() {
            return Err(FriPipelineError::Shape);
        }
        let final_layer = self.folded_layers.last().ok_or(FriPipelineError::Shape)?;
        let final_constant = *final_layer.first().ok_or(FriPipelineError::Shape)?;
        if final_layer.iter().any(|value| *value != final_constant) {
            return Err(FriPipelineError::FinalNotConstant);
        }
        let cascade = FriCascade {
            domain_log_sizes: self.domain_log_sizes,
            fold_log_sizes: self.fold_log_sizes,
            batch_column_counts: self.batch_column_counts,
            batch_power_offsets: self.batch_power_offsets,
            batch_masks: self.batch_masks,
            batched_domains: self.batched_domains,
            folded_layers: self.folded_layers,
            batch_coefficient: self.batch_coefficient,
            fold_coefficients: self.fold_coefficients,
        };
        Ok(FriPipeline {
            claims_commitment: self.claims_commitment,
            degree_bounds: self.degree_bounds,
            masks: self.masks,
            mask_tree: self.mask_tree,
            cascade,
            layer_roots: self.layer_roots,
            final_constant,
        })
    }
}

/// Compatibility constructor that exercises the staged implementation.
pub fn build_fri_pipeline(
    deep: &DeepQuotientOracles,
    claims_commitment: [u8; 64],
    batch_coefficient: Fp16,
    fold_coefficients: &[Fp16],
    secret_mask_seed: &[u8],
    session_id: &[u8],
) -> Result<FriPipeline, FriPipelineError> {
    let masks = build_fri_mask_oracle(deep, claims_commitment, secret_mask_seed, session_id)?;
    let mut builder = start_interactive_fri(deep, masks, batch_coefficient)?;
    if fold_coefficients.len() != builder.fold_round_count() {
        return Err(FriPipelineError::Shape);
    }
    for coefficient in fold_coefficients {
        builder.fold_next(*coefficient)?;
    }
    builder.finish()
}
