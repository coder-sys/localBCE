//! Bounded-memory multi-domain FRI masking, batching, folding, and layers.

use core::fmt;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::{format, string::String, vec, vec::Vec};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::circle_fri::{
    CircleFriError, bit_reverse_index, canonic_circle_point, conjugate_pair_zeroifier,
    fold_circle_pair, fold_line_pair,
};
use crate::cross_domain::{
    CrossDomainProof, DiskCrossDomainError, DiskCrossDomainTree, DiskDomainEvaluationBatch,
    inverse_transpose_circle_fft_index, project_circle_fft_index, transpose_circle_fft_index,
};
use crate::deep_quotient::DomainOodsClaims;
use crate::disk_air::DiskAirMainTraceOracle;
use crate::disk_composition::DiskAirCompositionOracle;
use crate::disk_deep::{
    DiskDeepDomainPlan, DiskDeepError, DiskDeepQuotientPlan, DiskOriginalColumn,
};
use crate::disk_fft::{DiskFftError, evaluate_extension_circle_coefficient_file_in_place};
use crate::disk_logup::DiskAirLogupOracle;
use crate::field::{
    EXTENSION_DEGREE, FP16_ENCODED_LENGTH, FieldError, Fp16, M31, M31_MODULUS, batch_inverse_fp16,
};
use crate::fri_pipeline::{
    FriPipelineError, FriPipelineLayerOpening, FriPipelineProof, FriPipelineQueryProof,
    fri_mask_layout, layer_payload, mask_id,
};
use crate::merkle::{
    ChildHash, LeafHash, MerkleError, MerkleProof, NodeHash, RootHash, hash_leaf, hash_node,
    hash_root,
};
use crate::trace_mask::{
    TRACE_MASK_FP16_DOMAIN_CODE, TRACE_MASK_MAGIC, TRACE_MASK_MAX_ATTEMPTS, TRACE_MASK_VERSION,
    TraceMaskError,
};

const FRI_BLOCK_ROWS: usize = 1 << 12;

#[derive(Debug)]
pub enum DiskFriError {
    CircleFri(CircleFriError),
    CrossDomain(DiskCrossDomainError),
    Deep(DiskDeepError),
    DiskFft(DiskFftError),
    Field(FieldError),
    Fri(FriPipelineError),
    Merkle(MerkleError),
    TraceMask(TraceMaskError),
    Decode(crate::field::DecodeError),
    Io(std::io::ErrorKind),
    Parent,
    Ownership,
    Shape,
    Overflow,
    FinalNotConstant,
}

macro_rules! convert_error {
    ($source:ty, $variant:ident) => {
        impl From<$source> for DiskFriError {
            fn from(value: $source) -> Self {
                Self::$variant(value)
            }
        }
    };
}

convert_error!(CircleFriError, CircleFri);
convert_error!(DiskCrossDomainError, CrossDomain);
convert_error!(DiskDeepError, Deep);
convert_error!(DiskFftError, DiskFft);
convert_error!(FieldError, Field);
convert_error!(FriPipelineError, Fri);
convert_error!(MerkleError, Merkle);
convert_error!(TraceMaskError, TraceMask);
convert_error!(crate::field::DecodeError, Decode);

impl From<std::io::Error> for DiskFriError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.kind())
    }
}

impl fmt::Display for DiskFriError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "BL-PQ512 disk FRI error: {self:?}")
    }
}

impl core::error::Error for DiskFriError {}

const DISK_FRI_MARKER: &[u8; 8] = b"BLPQDFR1";

struct OwnedFriDirectory {
    path: PathBuf,
    claims_commitment: [u8; 64],
}

impl Drop for OwnedFriDirectory {
    fn drop(&mut self) {
        let _ = cleanup_owned_directory(&self.path, &self.claims_commitment);
    }
}

pub struct DiskFriMaskOracle {
    pub claims_commitment: [u8; 64],
    pub degree_bounds: Vec<usize>,
    /// Descending, matching `DiskDeepQuotientPlan::domains`.
    pub mask_files: Vec<PathBuf>,
    pub tree: DiskCrossDomainTree,
    owned_directory: OwnedFriDirectory,
}

impl DiskFriMaskOracle {
    #[must_use]
    pub fn scratch_path(&self) -> &Path {
        &self.owned_directory.path
    }
}

pub struct DiskFriLayerTree {
    pub log_size: u8,
    pub values_path: PathBuf,
    level_paths: Vec<PathBuf>,
    pub root: RootHash,
}

impl DiskFriLayerTree {
    pub fn proof(&self, leaf_index: usize) -> Result<MerkleProof, DiskFriError> {
        let leaf_count = 1_usize << (self.log_size - 1);
        if leaf_index >= leaf_count || self.level_paths.is_empty() {
            return Err(DiskFriError::Shape);
        }
        let mut index = leaf_index;
        let mut siblings = Vec::with_capacity(self.level_paths.len() - 1);
        for path in &self.level_paths[..self.level_paths.len() - 1] {
            siblings.push(read_hash_at(path, index ^ 1)?);
            index >>= 1;
        }
        Ok(MerkleProof::from_parts(leaf_index, leaf_count, siblings)?)
    }

    pub fn value(&self, index: usize) -> Result<Fp16, DiskFriError> {
        let count = 1_usize << (self.log_size - 1);
        if index >= count {
            return Err(DiskFriError::Shape);
        }
        read_fp16_at(&self.values_path, index)
    }
}

pub struct DiskInteractiveFriBuilder {
    plan: DiskDeepQuotientPlan,
    pub mask: DiskFriMaskOracle,
    domain_files: Vec<PathBuf>,
    batch_power_offsets: Vec<usize>,
    fold_log_sizes: Vec<u8>,
    fold_coefficients: Vec<Fp16>,
    layers: Vec<DiskFriLayerTree>,
    batch_coefficient: Fp16,
}

pub struct DiskFriPipeline {
    pub plan: DiskDeepQuotientPlan,
    pub mask: DiskFriMaskOracle,
    pub batch_power_offsets: Vec<usize>,
    pub fold_log_sizes: Vec<u8>,
    pub fold_coefficients: Vec<Fp16>,
    pub layers: Vec<DiskFriLayerTree>,
    pub batch_coefficient: Fp16,
    pub final_constant: Fp16,
}

pub fn build_disk_fri_mask_oracle(
    plan: &DiskDeepQuotientPlan,
    claims_commitment: [u8; 64],
    secret_mask_seed: &[u8],
    session_id: &[u8],
    scratch_parent: &Path,
    build_nonce: &[u8; 32],
) -> Result<DiskFriMaskOracle, DiskFriError> {
    if plan.domains.is_empty()
        || !claims_commitment.iter().any(|byte| *byte != 0)
        || !scratch_parent.is_absolute()
        || !scratch_parent.is_dir()
    {
        return Err(DiskFriError::Parent);
    }
    let layout = fri_mask_layout(&claims_commitment, &plan.claims)?;
    let directory = scratch_parent.join(directory_name(build_nonce));
    create_owned_directory(&directory, &claims_commitment)?;
    let owned_directory = OwnedFriDirectory {
        path: directory.clone(),
        claims_commitment,
    };
    let mut files_by_log = Vec::with_capacity(plan.domains.len());
    let mut degree_bounds = Vec::with_capacity(plan.domains.len());
    for domain in &plan.domains {
        let path = directory.join(format!("mask-log-{:02}.fp16", domain.log_size));
        write_mask_coefficient_file(
            &path,
            1_usize << domain.log_size,
            domain.degree_bound,
            secret_mask_seed,
            session_id,
            &mask_id(&claims_commitment, domain.log_size),
        )?;
        evaluate_extension_circle_coefficient_file_in_place(&path, domain.log_size)?;
        files_by_log.push((domain.log_size, path));
        degree_bounds.push(domain.degree_bound);
    }
    let mut batches = Vec::with_capacity(layout.specs().len());
    for spec in layout.specs() {
        let path = files_by_log
            .iter()
            .find(|(log_size, _)| *log_size == spec.log_size)
            .map(|(_, path)| path.clone())
            .ok_or(DiskFriError::Shape)?;
        batches.push(DiskDomainEvaluationBatch::new(*spec, path)?);
    }
    let tree = DiskCrossDomainTree::build(
        layout,
        batches,
        scratch_parent,
        &derive_nonce(build_nonce, b"mask-tree", 0)?,
    )?;
    Ok(DiskFriMaskOracle {
        claims_commitment,
        degree_bounds,
        mask_files: files_by_log.into_iter().map(|(_, path)| path).collect(),
        tree,
        owned_directory,
    })
}

pub fn start_disk_interactive_fri(
    plan: DiskDeepQuotientPlan,
    mask: DiskFriMaskOracle,
    batch_coefficient: Fp16,
) -> Result<DiskInteractiveFriBuilder, DiskFriError> {
    if plan.domains.is_empty()
        || batch_coefficient.is_zero()
        || plan.domains.len() != mask.mask_files.len()
        || plan
            .domains
            .iter()
            .zip(&mask.degree_bounds)
            .any(|(domain, bound)| domain.degree_bound != *bound)
    {
        return Err(DiskFriError::Shape);
    }
    let largest_log = plan.domains[0].log_size;
    if plan
        .domains
        .windows(2)
        .any(|pair| pair[0].log_size <= pair[1].log_size)
    {
        return Err(DiskFriError::Shape);
    }
    let counts = plan
        .domains
        .iter()
        .map(|domain| {
            domain
                .columns
                .len()
                .checked_mul(2)
                .ok_or(DiskFriError::Overflow)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut next_offset = 0usize;
    let batch_power_offsets = counts
        .iter()
        .map(|count| {
            let current = next_offset;
            next_offset = next_offset
                .checked_add(*count)
                .ok_or(DiskFriError::Overflow)?;
            Ok(current)
        })
        .collect::<Result<Vec<_>, DiskFriError>>()?;
    let mut domain_files = Vec::with_capacity(plan.domains.len());
    for (((domain, mask_path), power_offset), domain_index) in plan
        .domains
        .iter()
        .zip(&mask.mask_files)
        .zip(&batch_power_offsets)
        .zip(0_usize..)
    {
        let output = mask
            .scratch_path()
            .join(format!("batched-log-{:02}.fp16", domain.log_size));
        fs::copy(mask_path, &output)?;
        build_batched_domain(
            domain,
            &plan.claims,
            plan.query,
            batch_coefficient,
            *power_offset,
            &output,
            mask.scratch_path(),
            domain_index,
        )?;
        domain_files.push(output);
    }
    Ok(DiskInteractiveFriBuilder {
        plan,
        mask,
        domain_files,
        batch_power_offsets,
        fold_log_sizes: (2..=largest_log).rev().collect(),
        fold_coefficients: Vec::new(),
        layers: Vec::new(),
        batch_coefficient,
    })
}

impl DiskInteractiveFriBuilder {
    pub fn fold_round_count(&self) -> usize {
        self.fold_log_sizes.len()
    }

    pub fn fold_next(&mut self, coefficient: Fp16) -> Result<RootHash, DiskFriError> {
        if coefficient.is_zero() || self.layers.len() >= self.fold_log_sizes.len() {
            return Err(DiskFriError::Shape);
        }
        let round = self.layers.len();
        let log_size = self.fold_log_sizes[round];
        let attached = self
            .plan
            .domains
            .iter()
            .position(|domain| domain.log_size == log_size)
            .map(|index| self.domain_files[index].as_path());
        let prior = self.layers.last().map(|layer| layer.values_path.as_path());
        if attached.is_none() && prior.is_none() {
            return Err(DiskFriError::Shape);
        }
        let output = self
            .mask
            .scratch_path()
            .join(format!("fold-round-{round:02}-log-{log_size:02}.fp16"));
        fold_layer_files(attached, prior, log_size, coefficient, &output)?;
        let tree = build_layer_tree(log_size, output, self.mask.scratch_path(), round)?;
        let root = tree.root;
        self.fold_coefficients.push(coefficient);
        self.layers.push(tree);
        Ok(root)
    }

    pub fn finish(self) -> Result<DiskFriPipeline, DiskFriError> {
        if self.layers.len() != self.fold_log_sizes.len() {
            return Err(DiskFriError::Shape);
        }
        let final_layer = self.layers.last().ok_or(DiskFriError::Shape)?;
        let left = final_layer.value(0)?;
        let right = final_layer.value(1)?;
        if left != right {
            return Err(DiskFriError::FinalNotConstant);
        }
        Ok(DiskFriPipeline {
            plan: self.plan,
            mask: self.mask,
            batch_power_offsets: self.batch_power_offsets,
            fold_log_sizes: self.fold_log_sizes,
            fold_coefficients: self.fold_coefficients,
            layers: self.layers,
            batch_coefficient: self.batch_coefficient,
            final_constant: left,
        })
    }
}

pub fn prove_disk_fri_pipeline(
    pipeline: &DiskFriPipeline,
    main: &DiskAirMainTraceOracle,
    logup: &DiskAirLogupOracle,
    composition: &DiskAirCompositionOracle,
    query_indices: &[usize],
) -> Result<FriPipelineProof, DiskFriError> {
    if query_indices.is_empty()
        || pipeline.layers.len() != pipeline.fold_log_sizes.len()
        || main.program_binary_commitment != composition.program_binary_commitment
    {
        return Err(DiskFriError::Shape);
    }
    let largest_log = pipeline
        .plan
        .domains
        .first()
        .ok_or(DiskFriError::Shape)?
        .log_size;
    let maximum_size = 1_usize << largest_log;
    if query_indices.iter().any(|index| *index >= maximum_size) {
        return Err(DiskFriError::Shape);
    }
    let mut main_indices = BTreeSet::new();
    let mut composition_indices = BTreeSet::new();
    let mut interaction_indices = BTreeSet::new();
    let mut mask_indices = BTreeSet::new();
    let main_max_log = main.tree.layout().maximum_log_size();
    let interaction_max_log = logup.tree.layout().maximum_log_size();
    for initial_index in query_indices.iter().copied() {
        let pair_start = initial_index & !1;
        for index in [pair_start, pair_start + 1] {
            main_indices.insert(projected_index(index, largest_log, main_max_log)?);
            composition_indices.insert(projected_index(
                index,
                largest_log,
                composition.tree.layout().maximum_log_size(),
            )?);
            interaction_indices.insert(projected_index(index, largest_log, interaction_max_log)?);
            mask_indices.insert(projected_index(
                index,
                largest_log,
                pipeline.mask.tree.layout().maximum_log_size(),
            )?);
        }
        for table in &main.tables {
            let current = projected_index(initial_index, largest_log, table.evaluation_log_size)?;
            let shifted = crate::air_composition::shifted_fft_index(
                current,
                table.evaluation_log_size,
                table.trace_log_size,
            )
            .map_err(|_| DiskFriError::Shape)?;
            main_indices.insert(lifted_index(
                shifted,
                table.evaluation_log_size,
                main_max_log,
            )?);
        }
        for interaction in &logup.interactions {
            let current =
                projected_index(initial_index, largest_log, interaction.evaluation_log_size)?;
            let trace_log_size = main
                .tables
                .get(interaction.table_index)
                .ok_or(DiskFriError::Shape)?
                .trace_log_size;
            let shifted = crate::air_composition::shifted_fft_index(
                current,
                interaction.evaluation_log_size,
                trace_log_size,
            )
            .map_err(|_| DiskFriError::Shape)?;
            interaction_indices.insert(lifted_index(
                shifted,
                interaction.evaluation_log_size,
                interaction_max_log,
            )?);
        }
    }
    let main_proofs = disk_proof_map(&main.tree, &main_indices)?;
    let composition_proofs = disk_proof_map(&composition.tree, &composition_indices)?;
    let interaction_proofs = disk_proof_map(&logup.tree, &interaction_indices)?;
    let mask_proofs = disk_proof_map(&pipeline.mask.tree, &mask_indices)?;
    let mut queries = Vec::with_capacity(query_indices.len());
    for initial_index in query_indices.iter().copied() {
        let pair_start = initial_index & !1;
        let (main_left, main_right) = disk_proof_pair(
            &main_proofs,
            pair_start,
            pair_start + 1,
            largest_log,
            main_max_log,
        )?;
        let (composition_left, composition_right) = disk_proof_pair(
            &composition_proofs,
            pair_start,
            pair_start + 1,
            largest_log,
            composition.tree.layout().maximum_log_size(),
        )?;
        let (interaction_left, interaction_right) = disk_proof_pair(
            &interaction_proofs,
            pair_start,
            pair_start + 1,
            largest_log,
            interaction_max_log,
        )?;
        let (mask_left, mask_right) = disk_proof_pair(
            &mask_proofs,
            pair_start,
            pair_start + 1,
            largest_log,
            pipeline.mask.tree.layout().maximum_log_size(),
        )?;
        let mut next_main_indices = BTreeSet::new();
        for table in &main.tables {
            let current = projected_index(initial_index, largest_log, table.evaluation_log_size)?;
            let shifted = crate::air_composition::shifted_fft_index(
                current,
                table.evaluation_log_size,
                table.trace_log_size,
            )
            .map_err(|_| DiskFriError::Shape)?;
            next_main_indices.insert(lifted_index(
                shifted,
                table.evaluation_log_size,
                main_max_log,
            )?);
        }
        let next_main = next_main_indices
            .into_iter()
            .map(|index| disk_proof(&main_proofs, index))
            .collect::<Result<Vec<_>, _>>()?;
        let mut next_interaction_indices = BTreeSet::new();
        for interaction in &logup.interactions {
            let current =
                projected_index(initial_index, largest_log, interaction.evaluation_log_size)?;
            let trace_log_size = main
                .tables
                .get(interaction.table_index)
                .ok_or(DiskFriError::Shape)?
                .trace_log_size;
            let shifted = crate::air_composition::shifted_fft_index(
                current,
                interaction.evaluation_log_size,
                trace_log_size,
            )
            .map_err(|_| DiskFriError::Shape)?;
            next_interaction_indices.insert(lifted_index(
                shifted,
                interaction.evaluation_log_size,
                interaction_max_log,
            )?);
        }
        let next_interaction = next_interaction_indices
            .into_iter()
            .map(|index| disk_proof(&interaction_proofs, index))
            .collect::<Result<Vec<_>, _>>()?;
        let mut output_index = initial_index >> 1;
        let mut layer_openings = Vec::with_capacity(pipeline.layers.len());
        for layer in &pipeline.layers {
            let layer_pair_start = output_index & !1;
            layer_openings.push(FriPipelineLayerOpening {
                log_size: layer.log_size,
                left: layer.value(layer_pair_start)?,
                right: layer.value(layer_pair_start + 1)?,
                left_proof: layer.proof(layer_pair_start)?,
                right_proof: layer.proof(layer_pair_start + 1)?,
            });
            output_index >>= 1;
        }
        queries.push(FriPipelineQueryProof {
            initial_index,
            mask_left,
            mask_right,
            main_left,
            main_right,
            interaction_left: Some(interaction_left),
            interaction_right: Some(interaction_right),
            composition_left,
            composition_right,
            next_main,
            next_interaction,
            layers: layer_openings,
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

fn projected_index(mut index: usize, from_log: u8, to_log: u8) -> Result<usize, DiskFriError> {
    if to_log > from_log {
        return Err(DiskFriError::Shape);
    }
    for log_size in (to_log + 1..=from_log).rev() {
        index = project_circle_fft_index(index, log_size).map_err(|_| DiskFriError::Shape)?;
    }
    Ok(index)
}

fn lifted_index(index: usize, from_log: u8, to_log: u8) -> Result<usize, DiskFriError> {
    if to_log < from_log {
        return Err(DiskFriError::Shape);
    }
    let transposed =
        transpose_circle_fft_index(index, from_log).map_err(|_| DiskFriError::Shape)?;
    let lifted = transposed
        .checked_shl(u32::from(to_log - from_log))
        .ok_or(DiskFriError::Overflow)?;
    inverse_transpose_circle_fft_index(lifted, to_log).map_err(|_| DiskFriError::Shape)
}

fn disk_proof_map(
    tree: &DiskCrossDomainTree,
    indices: &BTreeSet<usize>,
) -> Result<BTreeMap<usize, CrossDomainProof>, DiskFriError> {
    let ordered = indices.iter().copied().collect::<Vec<_>>();
    let proofs = tree.proofs(&ordered)?;
    if proofs.len() != ordered.len() {
        return Err(DiskFriError::Shape);
    }
    Ok(ordered.into_iter().zip(proofs).collect())
}

fn disk_proof(
    proofs: &BTreeMap<usize, CrossDomainProof>,
    index: usize,
) -> Result<CrossDomainProof, DiskFriError> {
    proofs.get(&index).cloned().ok_or(DiskFriError::Shape)
}

fn disk_proof_pair(
    proofs: &BTreeMap<usize, CrossDomainProof>,
    left_index: usize,
    right_index: usize,
    source_log: u8,
    target_log: u8,
) -> Result<(CrossDomainProof, CrossDomainProof), DiskFriError> {
    Ok((
        disk_proof(proofs, projected_index(left_index, source_log, target_log)?)?,
        disk_proof(
            proofs,
            projected_index(right_index, source_log, target_log)?,
        )?,
    ))
}

#[allow(clippy::too_many_arguments)]
fn build_batched_domain(
    domain: &DiskDeepDomainPlan,
    claims: &[DomainOodsClaims],
    query: crate::oods::CirclePoint,
    alpha: Fp16,
    power_offset: usize,
    output: &Path,
    directory: &Path,
    domain_index: usize,
) -> Result<(), DiskFriError> {
    let claim = claims
        .iter()
        .find(|claim| claim.log_size == domain.log_size)
        .ok_or(DiskFriError::Shape)?;
    if claim.values.len() != domain.columns.len()
        || claim.conjugate_values.len() != domain.columns.len()
    {
        return Err(DiskFriError::Shape);
    }
    let rows = 1_usize << domain.log_size;
    let inverse_path = directory.join(format!(
        "deep-inverses-d{domain_index:08x}-log-{:02}.fp16",
        domain.log_size
    ));
    write_zeroifier_inverses(&inverse_path, domain.log_size, query)?;
    let mut original_power = power_after(alpha, power_offset + 1);
    let mut quotient_power = original_power.mul(power_after(alpha, domain.columns.len()));
    for (column_index, source) in domain.columns.iter().enumerate() {
        update_batched_column(
            output,
            source,
            &inverse_path,
            domain.log_size,
            query,
            claim.values[column_index],
            claim.conjugate_values[column_index],
            original_power,
            quotient_power,
        )?;
        original_power = original_power.mul(alpha);
        quotient_power = quotient_power.mul(alpha);
    }
    fs::remove_file(inverse_path)?;
    validate_fp16_file(output, rows)
}

fn power_after(value: Fp16, exponent: usize) -> Fp16 {
    let mut result = Fp16::ONE;
    let mut base = value;
    let mut remaining = exponent;
    while remaining != 0 {
        if remaining & 1 == 1 {
            result = result.mul(base);
        }
        base = base.square();
        remaining >>= 1;
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn update_batched_column(
    output: &Path,
    source: &DiskOriginalColumn,
    inverse_path: &Path,
    log_size: u8,
    query: crate::oods::CirclePoint,
    claim: Fp16,
    conjugate_claim: Fp16,
    original_power: Fp16,
    quotient_power: Fp16,
) -> Result<(), DiskFriError> {
    let rows = 1_usize << log_size;
    validate_fp16_file(output, rows)?;
    let conjugate = crate::oods::CirclePoint {
        x: query.x.conjugate(),
        y: query.y.conjugate(),
    };
    let (use_y, query_coordinate, conjugate_coordinate) = if query.y != conjugate.y {
        (true, query.y, conjugate.y)
    } else if query.x != conjugate.x {
        (false, query.x, conjugate.x)
    } else {
        return Err(DiskFriError::Shape);
    };
    let scale = conjugate_coordinate.sub(query_coordinate);
    let slope = conjugate_claim.sub(claim);
    let intercept = claim.mul(scale).sub(slope.mul(query_coordinate));
    let mut destination = OpenOptions::new().read(true).write(true).open(output)?;
    let mut source = OriginalReader::new(source)?;
    let mut inverses = BufReader::new(File::open(inverse_path)?);
    for start in (0..rows).step_by(FRI_BLOCK_ROWS) {
        let count = FRI_BLOCK_ROWS.min(rows - start);
        let mut encoded = vec![0_u8; count * FP16_ENCODED_LENGTH];
        destination.read_exact(&mut encoded)?;
        for offset in 0..count {
            let row = start + offset;
            let original = source.read()?;
            let inverse = read_one_fp16(&mut inverses)?;
            let point = canonic_circle_point(log_size, bit_reverse_index(row, log_size)?)?;
            let coordinate = Fp16::from_m31(if use_y { point.y } else { point.x });
            let quotient = scale
                .mul(original)
                .sub(slope.mul(coordinate).add(intercept))
                .mul(inverse);
            let byte = offset * FP16_ENCODED_LENGTH;
            let value = Fp16::decode(&encoded[byte..byte + FP16_ENCODED_LENGTH])?
                .add(original_power.mul(original))
                .add(quotient_power.mul(quotient));
            encoded[byte..byte + FP16_ENCODED_LENGTH].copy_from_slice(&value.encode());
        }
        destination.seek(SeekFrom::Current(
            -i64::try_from(encoded.len()).map_err(|_| DiskFriError::Overflow)?,
        ))?;
        destination.write_all(&encoded)?;
    }
    destination.sync_data()?;
    Ok(())
}

fn write_zeroifier_inverses(
    output: &Path,
    log_size: u8,
    query: crate::oods::CirclePoint,
) -> Result<(), DiskFriError> {
    let rows = 1_usize << log_size;
    let mut output = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)?,
    );
    for start in (0..rows).step_by(FRI_BLOCK_ROWS) {
        let count = FRI_BLOCK_ROWS.min(rows - start);
        let zeroifiers = (start..start + count)
            .map(|row| {
                let point = canonic_circle_point(log_size, bit_reverse_index(row, log_size)?)?;
                conjugate_pair_zeroifier(point, query)
            })
            .collect::<Result<Vec<_>, CircleFriError>>()?;
        let inverses = batch_inverse_fp16(&zeroifiers).map_err(|_| DiskFriError::Shape)?;
        for inverse in inverses {
            output.write_all(&inverse.encode())?;
        }
    }
    output.flush()?;
    output.get_ref().sync_data()?;
    Ok(())
}

fn fold_layer_files(
    attached: Option<&Path>,
    prior: Option<&Path>,
    log_size: u8,
    coefficient: Fp16,
    output: &Path,
) -> Result<(), DiskFriError> {
    let input_rows = 1_usize << log_size;
    if let Some(path) = attached {
        validate_fp16_file(path, input_rows)?;
    }
    if let Some(path) = prior {
        validate_fp16_file(path, input_rows)?;
    }
    let mut attached = attached.map(File::open).transpose()?.map(BufReader::new);
    let mut prior = prior.map(File::open).transpose()?.map(BufReader::new);
    let mut output = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)?,
    );
    for pair_index in 0..input_rows / 2 {
        let folded_batch = attached
            .as_mut()
            .map(|reader| {
                let pair = [read_one_fp16(reader)?, read_one_fp16(reader)?];
                fold_circle_pair(&pair, pair_index, log_size, coefficient)
                    .map_err(DiskFriError::from)
            })
            .transpose()?;
        let folded_prior = prior
            .as_mut()
            .map(|reader| {
                let pair = [read_one_fp16(reader)?, read_one_fp16(reader)?];
                fold_line_pair(&pair, pair_index, log_size, coefficient).map_err(DiskFriError::from)
            })
            .transpose()?;
        let value = match (folded_prior, folded_batch) {
            (Some(prior), Some(batch)) => coefficient.square().mul(prior).add(batch),
            (None, Some(batch)) => batch,
            (Some(prior), None) => prior,
            (None, None) => return Err(DiskFriError::Shape),
        };
        output.write_all(&value.encode())?;
    }
    output.flush()?;
    output.get_ref().sync_data()?;
    Ok(())
}

fn build_layer_tree(
    log_size: u8,
    values_path: PathBuf,
    directory: &Path,
    round: usize,
) -> Result<DiskFriLayerTree, DiskFriError> {
    let leaf_count = 1_usize << (log_size - 1);
    validate_fp16_file(&values_path, leaf_count)?;
    let leaves_path = directory.join(format!("layer-{round:02}-level-00.hash"));
    let mut values = BufReader::new(File::open(&values_path)?);
    let mut leaves = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&leaves_path)?,
    );
    for _ in 0..leaf_count {
        let value = read_one_fp16(&mut values)?;
        leaves.write_all(hash_leaf(&layer_payload(log_size, value))?.as_bytes())?;
    }
    leaves.flush()?;
    leaves.get_ref().sync_data()?;
    let mut level_paths = vec![leaves_path];
    let mut count = leaf_count;
    while count > 1 {
        let input_path = level_paths.last().ok_or(DiskFriError::Shape)?;
        let output_path = directory.join(format!(
            "layer-{round:02}-level-{:02}.hash",
            level_paths.len()
        ));
        let mut input = BufReader::new(File::open(input_path)?);
        let mut output = BufWriter::new(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output_path)?,
        );
        for _ in 0..count / 2 {
            let left = read_one_hash(&mut input)?;
            let right = read_one_hash(&mut input)?;
            let parent = if count == leaf_count {
                hash_node(
                    ChildHash::Leaf(LeafHash::from_bytes(left)),
                    ChildHash::Leaf(LeafHash::from_bytes(right)),
                )
            } else {
                hash_node(
                    ChildHash::Node(NodeHash::from_bytes(left)),
                    ChildHash::Node(NodeHash::from_bytes(right)),
                )
            };
            output.write_all(parent.as_bytes())?;
        }
        output.flush()?;
        output.get_ref().sync_data()?;
        level_paths.push(output_path);
        count /= 2;
    }
    let top = read_hash_at(level_paths.last().ok_or(DiskFriError::Shape)?, 0)?;
    let root = if leaf_count == 1 {
        hash_root(1, ChildHash::Leaf(LeafHash::from_bytes(top)))?
    } else {
        hash_root(
            u64::try_from(leaf_count).map_err(|_| DiskFriError::Overflow)?,
            ChildHash::Node(NodeHash::from_bytes(top)),
        )?
    };
    Ok(DiskFriLayerTree {
        log_size,
        values_path,
        level_paths,
        root,
    })
}

fn write_mask_coefficient_file(
    output: &Path,
    rows: usize,
    count: usize,
    secret_seed: &[u8],
    session_id: &[u8],
    oracle_id: &[u8],
) -> Result<(), DiskFriError> {
    if secret_seed.len() != 64
        || session_id.len() != 64
        || oracle_id.len() != 64
        || count == 0
        || count > rows
    {
        return Err(DiskFriError::Shape);
    }
    let count_u32 = u32::try_from(count).map_err(|_| DiskFriError::Overflow)?;
    let acceptance_limit = u64::from(M31_MODULUS) * 2;
    let mut xof = Shake256::default();
    xof.update(TRACE_MASK_MAGIC);
    xof.update(&TRACE_MASK_VERSION.to_be_bytes());
    xof.update(&TRACE_MASK_FP16_DOMAIN_CODE.to_be_bytes());
    xof.update(session_id);
    xof.update(oracle_id);
    xof.update(secret_seed);
    xof.update(&count_u32.to_be_bytes());
    let mut reader = xof.finalize_xof();
    let mut output = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)?,
    );
    for coefficient in 0..count_u32 {
        let mut coordinates = [0_u32; EXTENSION_DEGREE];
        for coordinate in &mut coordinates {
            let mut accepted = None;
            for _ in 0..TRACE_MASK_MAX_ATTEMPTS {
                let mut word = [0_u8; 4];
                reader.read(&mut word);
                let candidate = u64::from(u32::from_be_bytes(word));
                if candidate < acceptance_limit {
                    accepted = Some((candidate % u64::from(M31_MODULUS)) as u32);
                    break;
                }
            }
            *coordinate = accepted.ok_or(TraceMaskError::AttemptCapExhausted { coefficient })?;
        }
        output.write_all(&Fp16::from_coefficients(coordinates)?.encode())?;
    }
    let zeros = vec![0_u8; FRI_BLOCK_ROWS * FP16_ENCODED_LENGTH];
    let mut remaining = rows - count;
    while remaining != 0 {
        let block = FRI_BLOCK_ROWS.min(remaining);
        output.write_all(&zeros[..block * FP16_ENCODED_LENGTH])?;
        remaining -= block;
    }
    output.flush()?;
    output.get_ref().sync_data()?;
    Ok(())
}

enum OriginalReader {
    M31(BufReader<File>),
    Fp16(BufReader<File>),
}

impl OriginalReader {
    fn new(source: &DiskOriginalColumn) -> Result<Self, DiskFriError> {
        Ok(match source {
            DiskOriginalColumn::M31(path) => Self::M31(BufReader::new(File::open(path)?)),
            DiskOriginalColumn::Fp16(path) => Self::Fp16(BufReader::new(File::open(path)?)),
        })
    }

    fn read(&mut self) -> Result<Fp16, DiskFriError> {
        match self {
            Self::M31(reader) => {
                let mut encoded = [0_u8; 4];
                reader.read_exact(&mut encoded)?;
                let value = u32::from_be_bytes(encoded);
                if value >= M31_MODULUS {
                    return Err(DiskFriError::Shape);
                }
                Ok(Fp16::from_m31(M31::from_canonical(value)?))
            }
            Self::Fp16(reader) => read_one_fp16(reader),
        }
    }
}

fn read_one_fp16(input: &mut impl Read) -> Result<Fp16, DiskFriError> {
    let mut encoded = [0_u8; FP16_ENCODED_LENGTH];
    input.read_exact(&mut encoded)?;
    Ok(Fp16::decode(&encoded)?)
}

fn read_fp16_at(path: &Path, index: usize) -> Result<Fp16, DiskFriError> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(
        u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_mul(FP16_ENCODED_LENGTH as u64))
            .ok_or(DiskFriError::Overflow)?,
    ))?;
    read_one_fp16(&mut file)
}

fn read_one_hash(input: &mut impl Read) -> Result<[u8; 64], DiskFriError> {
    let mut hash = [0_u8; 64];
    input.read_exact(&mut hash)?;
    Ok(hash)
}

fn read_hash_at(path: &Path, index: usize) -> Result<[u8; 64], DiskFriError> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(
        u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_mul(64))
            .ok_or(DiskFriError::Overflow)?,
    ))?;
    read_one_hash(&mut file)
}

fn validate_fp16_file(path: &Path, rows: usize) -> Result<(), DiskFriError> {
    let expected = u64::try_from(rows)
        .ok()
        .and_then(|value| value.checked_mul(FP16_ENCODED_LENGTH as u64))
        .ok_or(DiskFriError::Overflow)?;
    if !path.is_absolute() || fs::metadata(path)?.len() != expected {
        return Err(DiskFriError::Shape);
    }
    Ok(())
}

fn derive_nonce(
    build_nonce: &[u8; 32],
    label: &[u8],
    index: usize,
) -> Result<[u8; 32], DiskFriError> {
    use sha3::{Digest, Sha3_512};
    let mut hash = Sha3_512::new();
    Digest::update(&mut hash, b"BL/PQ512/WAVE1B/DISK-FRI-NONCE/v1\0");
    Digest::update(&mut hash, build_nonce);
    Digest::update(&mut hash, label);
    Digest::update(
        &mut hash,
        u64::try_from(index)
            .map_err(|_| DiskFriError::Overflow)?
            .to_be_bytes(),
    );
    let digest: [u8; 64] = hash.finalize().into();
    let mut nonce = [0_u8; 32];
    nonce.copy_from_slice(&digest[..32]);
    Ok(nonce)
}

fn directory_name(nonce: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::from("blpq-disk-fri-");
    for byte in nonce {
        name.push(DIGITS[usize::from(byte >> 4)] as char);
        name.push(DIGITS[usize::from(byte & 15)] as char);
    }
    name
}

fn create_owned_directory(
    directory: &Path,
    claims_commitment: &[u8; 64],
) -> Result<(), DiskFriError> {
    fs::create_dir(directory)?;
    let marker_path = directory.join("OWNER");
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker_path)
        .and_then(|mut marker| {
            marker.write_all(DISK_FRI_MARKER)?;
            marker.write_all(claims_commitment)?;
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
    expected_claims: &[u8; 64],
) -> Result<(), DiskFriError> {
    let mut marker = [0_u8; 72];
    File::open(directory.join("OWNER"))?.read_exact(&mut marker)?;
    if &marker[..8] != DISK_FRI_MARKER || &marker[8..] != expected_claims {
        return Err(DiskFriError::Ownership);
    }
    fs::remove_dir_all(directory)?;
    Ok(())
}
