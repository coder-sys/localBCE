//! Projection-consistent SHA3-512 cross-circle-domain commitments.
//!
//! Circle-FFT bit-reverse indices are transposed before ordinary binary-tree
//! reduction. Dropping the low transposed bit is therefore exactly one circle
//! squaring projection. Values from every registered smaller domain are
//! inserted at their corresponding tree level, so one path authenticates the
//! complete multi-domain query.

use core::fmt;

use alloc::vec;
use alloc::vec::Vec;
use sha3::{Digest, Sha3_512};

use crate::binding_root_v2::{
    BINDING_V2_BYTES, BindingDigestV2, BindingMerkleLeafV2, BindingMerkleMultiProofV2,
    BindingMerkleNodeV2, BindingMerkleTreeV2, BindingRootV2, BindingRootV2Error,
    canonical_binding_frontier_positions_v2,
};
use crate::circle_fri::FriDomainBatch;
use crate::field::{Fp16, M31_MODULUS};

#[cfg(feature = "std")]
use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
};
#[cfg(feature = "std")]
use std::fs::{self, File, OpenOptions};
#[cfg(feature = "std")]
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
#[cfg(feature = "std")]
use std::path::{Path, PathBuf};

/// `BL/PQ512/v1/PCS/CROSS-DOMAIN/EVALUATION`.
pub const CROSS_DOMAIN_EVALUATION_DOMAIN: u16 = 516;
/// `BL/PQ512/v1/PCS/CROSS-DOMAIN/CHILDREN`.
pub const CROSS_DOMAIN_CHILDREN_DOMAIN: u16 = 517;
/// `BL/PQ512/v1/PCS/CROSS-DOMAIN/INSERT`.
pub const CROSS_DOMAIN_INSERT_DOMAIN: u16 = 518;
/// `BL/PQ512/v1/PCS/CROSS-DOMAIN/ROOT`.
pub const CROSS_DOMAIN_ROOT_DOMAIN: u16 = 519;
/// `BL/PQ512/v1/PCS/CROSS-DOMAIN/LAYOUT`.
pub const CROSS_DOMAIN_LAYOUT_DOMAIN: u16 = 520;

const CROSS_DOMAIN_MAGIC: &[u8; 8] = b"BLPQXDM1";
const CROSS_DOMAIN_VERSION: u16 = 1;
const DIGEST_LENGTH: usize = 64;
const MAX_DOMAIN_LOG_SIZE: u8 = 30;
pub const BINDING_CROSS_DOMAIN_ROW_V2_MAGIC: &[u8; 8] = b"BLB2XD01";
pub const BINDING_CROSS_DOMAIN_ROW_V2_VERSION: u16 = 2;
const BINDING_LAYOUT_ID_PINNED_SHA3_512: u8 = 1;
const BINDING_LAYOUT_ID_NATIVE_V2: u8 = 2;
/// At most this many bytes of cross-domain Merkle levels are retained per
/// oracle. Larger public geometries deterministically recompute levels after
/// challenges instead of exceeding the bounded-scratch design.
pub const DISK_TREE_RETAINED_LEVEL_BUDGET_BYTES: u64 = 256_u64 << 20;

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiskTreeLevelPolicy {
    Retain,
    Recompute,
}

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiskTreeLevelPlan {
    pub policy: DiskTreeLevelPolicy,
    pub level_bytes: u64,
}

#[cfg(feature = "std")]
pub fn plan_disk_tree_levels(
    maximum_log_size: u8,
    retained_level_budget_bytes: u64,
) -> Result<DiskTreeLevelPlan, DiskCrossDomainError> {
    let node_count = 1_u64
        .checked_shl(u32::from(maximum_log_size) + 1)
        .and_then(|count| count.checked_sub(1))
        .ok_or(DiskCrossDomainError::Overflow)?;
    let level_bytes = node_count
        .checked_mul(DIGEST_LENGTH as u64)
        .ok_or(DiskCrossDomainError::Overflow)?;
    Ok(DiskTreeLevelPlan {
        policy: if level_bytes <= retained_level_budget_bytes {
            DiskTreeLevelPolicy::Retain
        } else {
            DiskTreeLevelPolicy::Recompute
        },
        level_bytes,
    })
}

/// The proof round whose oracle values are committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum CommitmentStage {
    /// Public/preprocessed columns.
    Preprocessed = 1,
    /// Main trace columns, including their native hiding masks.
    MainTrace = 2,
    /// Lookup/interaction columns, including their native hiding masks.
    InteractionTrace = 3,
    /// Composition and quotient-segment columns.
    Composition = 4,
    /// Degree-corrected DEEP quotient batch.
    DeepQuotient = 5,
    /// One committed Circle-FRI layer.
    FriLayer = 6,
    /// Independent committed FRI batch mask.
    FriBatchMask = 7,
}

/// Canonical scalar encoding used by one domain batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum EvaluationField {
    /// Four-byte canonical M31 scalars.
    M31 = 1,
    /// Sixty-four-byte canonical frozen-basis Fp16 scalars.
    Fp16 = 2,
}

impl EvaluationField {
    const fn encoded_width(self) -> usize {
        match self {
            Self::M31 => 4,
            Self::Fp16 => 64,
        }
    }
}

/// One immutable domain entry in a commitment layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DomainSpec {
    /// Base-two logarithm of the canonical circle-coset size.
    pub log_size: u8,
    /// Canonical field encoding of every column value.
    pub field: EvaluationField,
    /// Exact number of columns inserted at this level.
    pub column_count: u32,
}

impl DomainSpec {
    /// Strictly constructs one domain specification.
    pub const fn new(
        log_size: u8,
        field: EvaluationField,
        column_count: u32,
    ) -> Result<Self, CrossDomainError> {
        if log_size == 0 || log_size > MAX_DOMAIN_LOG_SIZE {
            return Err(CrossDomainError::DomainLogSizeInvalid { log_size });
        }
        if column_count == 0 {
            return Err(CrossDomainError::ZeroColumns);
        }
        Ok(Self {
            log_size,
            field,
            column_count,
        })
    }

    fn payload_length(self) -> Result<usize, CrossDomainError> {
        usize::try_from(self.column_count)
            .ok()
            .and_then(|count| count.checked_mul(self.field.encoded_width()))
            .ok_or(CrossDomainError::LengthOverflow)
    }
}

/// Typed full-width layout identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LayoutHash([u8; DIGEST_LENGTH]);

impl LayoutHash {
    /// Returns the exact SHA3-512 layout identity.
    pub const fn into_bytes(self) -> [u8; DIGEST_LENGTH] {
        self.0
    }
}

/// Typed full-width cross-domain commitment root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrossDomainRoot([u8; DIGEST_LENGTH]);

impl CrossDomainRoot {
    /// Constructs a parsed root from an exact digest.
    pub const fn from_bytes(bytes: [u8; DIGEST_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the exact SHA3-512 root.
    pub const fn into_bytes(self) -> [u8; DIGEST_LENGTH] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CrossDomainHash([u8; DIGEST_LENGTH]);

/// Immutable expected domain set for one commitment round.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossDomainLayout {
    stage: CommitmentStage,
    commitment_id: [u8; DIGEST_LENGTH],
    binding_commitment_id: Option<BindingDigestV2>,
    specs: Vec<DomainSpec>,
    identity: LayoutHash,
}

impl CrossDomainLayout {
    /// Constructs a layout only from strictly increasing, unique domain sizes.
    pub fn new(
        stage: CommitmentStage,
        commitment_id: [u8; DIGEST_LENGTH],
        specs: Vec<DomainSpec>,
    ) -> Result<Self, CrossDomainError> {
        if !commitment_id.iter().any(|byte| *byte != 0) {
            return Err(CrossDomainError::ZeroCommitmentId);
        }
        if specs.is_empty() {
            return Err(CrossDomainError::NoDomains);
        }
        let mut previous = 0;
        for (index, spec) in specs.iter().enumerate() {
            DomainSpec::new(spec.log_size, spec.field, spec.column_count)?;
            if index != 0 && spec.log_size <= previous {
                return Err(CrossDomainError::DomainsNotStrictlyIncreasing);
            }
            previous = spec.log_size;
        }
        let identity = LayoutHash(hash_layout(stage, &commitment_id, &specs));
        Ok(Self {
            stage,
            commitment_id,
            binding_commitment_id: None,
            specs,
            identity,
        })
    }

    /// Constructs a native-v2 layout whose acceptance-critical descriptor is
    /// the complete 128-byte BindingDigestV2. The 64-byte compatibility slot
    /// is deliberately zero and is never serialized by the native row codec.
    pub fn new_binding_v2(
        stage: CommitmentStage,
        commitment_id: BindingDigestV2,
        specs: Vec<DomainSpec>,
    ) -> Result<Self, CrossDomainError> {
        if commitment_id.as_bytes()[..64].iter().all(|byte| *byte == 0)
            || commitment_id.as_bytes()[64..].iter().all(|byte| *byte == 0)
        {
            return Err(CrossDomainError::ZeroCommitmentId);
        }
        if specs.is_empty() {
            return Err(CrossDomainError::NoDomains);
        }
        let mut previous = 0;
        for (index, spec) in specs.iter().enumerate() {
            DomainSpec::new(spec.log_size, spec.field, spec.column_count)?;
            if index != 0 && spec.log_size <= previous {
                return Err(CrossDomainError::DomainsNotStrictlyIncreasing);
            }
            previous = spec.log_size;
        }
        // Native-v2 rows carry the complete 128-byte commitment descriptor
        // directly.  The legacy 64-byte layout identity is deliberately not
        // an acceptance authority for this layout.
        let identity = LayoutHash([0_u8; DIGEST_LENGTH]);
        Ok(Self {
            stage,
            commitment_id: [0_u8; DIGEST_LENGTH],
            binding_commitment_id: Some(commitment_id),
            specs,
            identity,
        })
    }

    /// Returns the exact round kind.
    pub const fn stage(&self) -> CommitmentStage {
        self.stage
    }

    /// Returns the bound nonzero commitment descriptor identity.
    pub const fn commitment_id(&self) -> &[u8; DIGEST_LENGTH] {
        &self.commitment_id
    }

    /// Returns the native acceptance-critical descriptor when this layout was
    /// derived from a BindingDigestV2 rather than a verifier-pinned SHA3-512 ID.
    pub const fn binding_commitment_id(&self) -> Option<&BindingDigestV2> {
        self.binding_commitment_id.as_ref()
    }

    /// Returns the ordered domain specifications.
    pub fn specs(&self) -> &[DomainSpec] {
        &self.specs
    }

    /// Returns the full-width layout identity.
    pub const fn identity(&self) -> LayoutHash {
        self.identity
    }

    /// Returns the largest registered domain logarithm.
    pub fn maximum_log_size(&self) -> u8 {
        self.specs[self.specs.len() - 1].log_size
    }

    fn spec_at(&self, log_size: u8) -> Option<DomainSpec> {
        self.specs
            .iter()
            .copied()
            .find(|spec| spec.log_size == log_size)
    }
}

/// All row payloads for one domain, in circle-FFT bit-reverse order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainEvaluationBatch {
    spec: DomainSpec,
    rows: Vec<Vec<u8>>,
}

impl DomainEvaluationBatch {
    /// Validates shape and every canonical scalar before accepting a batch.
    pub fn new(spec: DomainSpec, rows: Vec<Vec<u8>>) -> Result<Self, CrossDomainError> {
        DomainSpec::new(spec.log_size, spec.field, spec.column_count)?;
        let expected_rows = 1_usize
            .checked_shl(u32::from(spec.log_size))
            .ok_or(CrossDomainError::LengthOverflow)?;
        if rows.len() != expected_rows {
            return Err(CrossDomainError::RowCountMismatch {
                log_size: spec.log_size,
                expected: expected_rows,
                actual: rows.len(),
            });
        }
        let expected_length = spec.payload_length()?;
        for (row_index, row) in rows.iter().enumerate() {
            if row.len() != expected_length {
                return Err(CrossDomainError::RowLengthMismatch {
                    log_size: spec.log_size,
                    row_index,
                    expected: expected_length,
                    actual: row.len(),
                });
            }
            validate_row(spec, row, row_index)?;
        }
        Ok(Self { spec, rows })
    }

    /// Returns the exact registered domain specification.
    pub const fn spec(&self) -> DomainSpec {
        self.spec
    }
}

/// One domain row opened along a projected query path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainOpening {
    /// Exact domain specification.
    pub spec: DomainSpec,
    /// Row index in circle-FFT bit-reverse order.
    pub fft_index: usize,
    /// Canonical concatenated row values.
    pub payload: Vec<u8>,
}

/// One shared cross-domain authentication path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossDomainProof {
    query_fft_index: usize,
    siblings: Vec<[u8; DIGEST_LENGTH]>,
    openings: Vec<DomainOpening>,
}

impl CrossDomainProof {
    /// Strictly construct a parsed proof. Layout-specific shape and payload
    /// checks are repeated by [`Self::verify`].
    pub fn from_parts(
        query_fft_index: usize,
        siblings: Vec<[u8; DIGEST_LENGTH]>,
        openings: Vec<DomainOpening>,
    ) -> Result<Self, CrossDomainError> {
        if siblings.is_empty() || siblings.len() > usize::from(MAX_DOMAIN_LOG_SIZE) {
            return Err(CrossDomainError::SiblingCountMismatch {
                expected: usize::from(MAX_DOMAIN_LOG_SIZE),
                actual: siblings.len(),
            });
        }
        let maximum_size = 1_usize
            .checked_shl(siblings.len() as u32)
            .ok_or(CrossDomainError::LengthOverflow)?;
        if query_fft_index >= maximum_size {
            return Err(CrossDomainError::QueryIndexOutOfBounds {
                index: query_fft_index,
                domain_size: maximum_size,
            });
        }
        if openings.is_empty()
            || openings
                .windows(2)
                .any(|pair| pair[0].spec.log_size >= pair[1].spec.log_size)
        {
            return Err(CrossDomainError::DomainsNotStrictlyIncreasing);
        }
        for opening in &openings {
            DomainSpec::new(
                opening.spec.log_size,
                opening.spec.field,
                opening.spec.column_count,
            )?;
            if opening.fft_index >= 1_usize << opening.spec.log_size {
                return Err(CrossDomainError::OpeningIndexMismatch {
                    log_size: opening.spec.log_size,
                    expected: 0,
                    actual: opening.fft_index,
                });
            }
            if opening.payload.len() != opening.spec.payload_length()? {
                return Err(CrossDomainError::RowLengthMismatch {
                    log_size: opening.spec.log_size,
                    row_index: opening.fft_index,
                    expected: opening.spec.payload_length()?,
                    actual: opening.payload.len(),
                });
            }
            validate_row(opening.spec, &opening.payload, opening.fft_index)?;
        }
        Ok(Self {
            query_fft_index,
            siblings,
            openings,
        })
    }

    /// Returns the largest-domain query index in circle-FFT bit-reverse order.
    pub const fn query_fft_index(&self) -> usize {
        self.query_fft_index
    }

    /// Returns bottom-up sibling hashes.
    pub fn siblings(&self) -> &[[u8; DIGEST_LENGTH]] {
        &self.siblings
    }

    /// Returns openings in strictly increasing domain-size order.
    pub fn openings(&self) -> &[DomainOpening] {
        &self.openings
    }

    /// Recomputes the exact typed cross-domain root.
    pub fn verify(
        &self,
        layout: &CrossDomainLayout,
        expected_root: &CrossDomainRoot,
    ) -> Result<bool, CrossDomainError> {
        let maximum_log = layout.maximum_log_size();
        let maximum_size = 1_usize
            .checked_shl(u32::from(maximum_log))
            .ok_or(CrossDomainError::LengthOverflow)?;
        if self.query_fft_index >= maximum_size {
            return Err(CrossDomainError::QueryIndexOutOfBounds {
                index: self.query_fft_index,
                domain_size: maximum_size,
            });
        }
        if self.siblings.len() != usize::from(maximum_log) {
            return Err(CrossDomainError::SiblingCountMismatch {
                expected: usize::from(maximum_log),
                actual: self.siblings.len(),
            });
        }
        if self.openings.len() != layout.specs.len() {
            return Err(CrossDomainError::OpeningCountMismatch {
                expected: layout.specs.len(),
                actual: self.openings.len(),
            });
        }

        let maximum_transposed = transpose_circle_fft_index(self.query_fft_index, maximum_log)?;
        for (opening, spec) in self.openings.iter().zip(layout.specs.iter()) {
            if opening.spec != *spec {
                return Err(CrossDomainError::OpeningSpecMismatch {
                    log_size: spec.log_size,
                });
            }
            let level_index = maximum_transposed >> (maximum_log - spec.log_size);
            let expected_fft_index =
                inverse_transpose_circle_fft_index(level_index, spec.log_size)?;
            if opening.fft_index != expected_fft_index {
                return Err(CrossDomainError::OpeningIndexMismatch {
                    log_size: spec.log_size,
                    expected: expected_fft_index,
                    actual: opening.fft_index,
                });
            }
            if opening.payload.len() != spec.payload_length()? {
                return Err(CrossDomainError::RowLengthMismatch {
                    log_size: spec.log_size,
                    row_index: opening.fft_index,
                    expected: spec.payload_length()?,
                    actual: opening.payload.len(),
                });
            }
            validate_row(*spec, &opening.payload, opening.fft_index)?;
        }

        let mut current_index = maximum_transposed;
        let maximum_opening = self.opening_at(maximum_log)?;
        let mut current = hash_insert(
            maximum_log,
            current_index,
            empty_cross_domain_hash(),
            hash_evaluation(layout, maximum_opening),
        );

        for (sibling_offset, parent_log) in (0..maximum_log).rev().enumerate() {
            let sibling = CrossDomainHash(self.siblings[sibling_offset]);
            current = if current_index & 1 == 0 {
                hash_children(current, sibling)
            } else {
                hash_children(sibling, current)
            };
            current_index >>= 1;
            if layout.spec_at(parent_log).is_some() {
                let opening = self.opening_at(parent_log)?;
                current = hash_insert(
                    parent_log,
                    current_index,
                    current,
                    hash_evaluation(layout, opening),
                );
            }
        }
        Ok(hash_root(layout, current) == *expected_root)
    }

    fn opening_at(&self, log_size: u8) -> Result<&DomainOpening, CrossDomainError> {
        self.openings
            .iter()
            .find(|opening| opening.spec.log_size == log_size)
            .ok_or(CrossDomainError::MissingOpening { log_size })
    }
}

/// A materialized cross-domain tree used by the prover.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossDomainTree {
    layout: CrossDomainLayout,
    batches: Vec<DomainEvaluationBatch>,
    levels: Vec<Vec<CrossDomainHash>>,
    root: CrossDomainRoot,
}

impl CrossDomainTree {
    /// Commit one independent Fp16 mask column on every FRI input domain.
    ///
    /// The resulting root must be fixed as the prover message before the
    /// public-coin batching coefficient is sampled.
    pub fn build_fri_batch_mask_tree(
        commitment_id: [u8; DIGEST_LENGTH],
        batch_masks: &[FriDomainBatch],
    ) -> Result<Self, CrossDomainError> {
        if batch_masks.is_empty() {
            return Err(CrossDomainError::NoFriBatchMasks);
        }
        let mut ordered = batch_masks.to_vec();
        ordered.sort_by_key(|batch| batch.log_size);
        if ordered.iter().any(|batch| batch.column_count() != 1) {
            return Err(CrossDomainError::FriBatchMaskColumnCountMismatch);
        }
        if ordered
            .windows(2)
            .any(|pair| pair[0].log_size == pair[1].log_size)
        {
            return Err(CrossDomainError::FriBatchMaskDomainDuplicate);
        }
        let specs = ordered
            .iter()
            .map(|batch| DomainSpec::new(batch.log_size, EvaluationField::Fp16, 1))
            .collect::<Result<Vec<_>, _>>()?;
        let layout =
            CrossDomainLayout::new(CommitmentStage::FriBatchMask, commitment_id, specs.clone())?;
        let batches = specs
            .into_iter()
            .zip(ordered)
            .map(|(spec, batch)| {
                DomainEvaluationBatch::new(
                    spec,
                    batch
                        .rows
                        .into_iter()
                        .map(|row| row[0].encode().to_vec())
                        .collect(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::build(layout, batches)
    }

    /// Builds the exact projection-consistent tree for every registered domain.
    pub fn build(
        layout: CrossDomainLayout,
        batches: Vec<DomainEvaluationBatch>,
    ) -> Result<Self, CrossDomainError> {
        if batches.len() != layout.specs.len() {
            return Err(CrossDomainError::BatchCountMismatch {
                expected: layout.specs.len(),
                actual: batches.len(),
            });
        }
        for (batch, spec) in batches.iter().zip(layout.specs.iter()) {
            if batch.spec != *spec {
                return Err(CrossDomainError::BatchSpecMismatch {
                    log_size: spec.log_size,
                });
            }
        }

        let maximum_log = layout.maximum_log_size();
        let mut levels = vec![Vec::new(); usize::from(maximum_log) + 1];
        for log_size in (0..=maximum_log).rev() {
            let count = 1_usize
                .checked_shl(u32::from(log_size))
                .ok_or(CrossDomainError::LengthOverflow)?;
            let mut nodes = if log_size == maximum_log {
                vec![empty_cross_domain_hash(); count]
            } else {
                levels[usize::from(log_size + 1)]
                    .chunks_exact(2)
                    .map(|pair| hash_children(pair[0], pair[1]))
                    .collect::<Vec<_>>()
            };

            if let Some(batch) = batches.iter().find(|batch| batch.spec.log_size == log_size) {
                for fft_index in 0..count {
                    let transposed_index = transpose_circle_fft_index(fft_index, log_size)?;
                    let opening = DomainOpening {
                        spec: batch.spec,
                        fft_index,
                        payload: batch.rows[fft_index].clone(),
                    };
                    nodes[transposed_index] = hash_insert(
                        log_size,
                        transposed_index,
                        nodes[transposed_index],
                        hash_evaluation(&layout, &opening),
                    );
                }
            }
            levels[usize::from(log_size)] = nodes;
        }
        let root = hash_root(&layout, levels[0][0]);
        Ok(Self {
            layout,
            batches,
            levels,
            root,
        })
    }

    /// Returns the exact full-width root.
    pub const fn root(&self) -> CrossDomainRoot {
        self.root
    }

    /// Returns the immutable layout.
    pub const fn layout(&self) -> &CrossDomainLayout {
        &self.layout
    }

    /// Opens every registered domain on one projected query path.
    pub fn proof(&self, query_fft_index: usize) -> Result<CrossDomainProof, CrossDomainError> {
        let maximum_log = self.layout.maximum_log_size();
        let maximum_size = 1_usize
            .checked_shl(u32::from(maximum_log))
            .ok_or(CrossDomainError::LengthOverflow)?;
        if query_fft_index >= maximum_size {
            return Err(CrossDomainError::QueryIndexOutOfBounds {
                index: query_fft_index,
                domain_size: maximum_size,
            });
        }
        let maximum_transposed = transpose_circle_fft_index(query_fft_index, maximum_log)?;
        let mut current_index = maximum_transposed;
        let mut siblings = Vec::with_capacity(usize::from(maximum_log));
        for level in (1..=maximum_log).rev() {
            siblings.push(self.levels[usize::from(level)][current_index ^ 1].0);
            current_index >>= 1;
        }

        let mut openings = Vec::with_capacity(self.batches.len());
        for batch in &self.batches {
            let level_index = maximum_transposed >> (maximum_log - batch.spec.log_size);
            let fft_index = inverse_transpose_circle_fft_index(level_index, batch.spec.log_size)?;
            openings.push(DomainOpening {
                spec: batch.spec,
                fft_index,
                payload: batch.rows[fft_index].clone(),
            });
        }
        Ok(CrossDomainProof {
            query_fft_index,
            siblings,
            openings,
        })
    }

    /// Recommit the exact multi-domain rows as native BindingRootV2 leaves.
    ///
    /// This is a parallel v3 construction. It never hashes or embeds the
    /// legacy cross-domain root or any legacy authentication-path digest.
    pub fn binding_v2_tree(
        &self,
        binding_layout: CrossDomainLayout,
    ) -> Result<BindingCrossDomainTreeV2, CrossDomainError> {
        if binding_layout.binding_commitment_id().is_none()
            || binding_layout.stage() != self.layout.stage()
            || binding_layout.specs() != self.layout.specs()
        {
            return Err(CrossDomainError::BindingRowEncoding);
        }
        BindingCrossDomainTreeV2::build(binding_layout, self.batches.clone())
    }
}

/// One complete projected multi-domain row authenticated by BindingRootV2.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingCrossDomainRowV2 {
    query_fft_index: usize,
    openings: Vec<DomainOpening>,
}

impl BindingCrossDomainRowV2 {
    pub const fn query_fft_index(&self) -> usize {
        self.query_fft_index
    }

    pub fn openings(&self) -> &[DomainOpening] {
        &self.openings
    }

    /// Encode the canonical leaf payload. The complete expected layout is
    /// carried directly; no 64-byte layout/root digest is wrapped as authority.
    pub fn encode_payload(&self, layout: &CrossDomainLayout) -> Result<Vec<u8>, CrossDomainError> {
        validate_binding_row_v2(layout, self)?;
        let expected_length = binding_cross_domain_row_v2_payload_len(layout)?;
        let mut output = Vec::with_capacity(expected_length);
        output.extend_from_slice(BINDING_CROSS_DOMAIN_ROW_V2_MAGIC);
        output.extend_from_slice(&BINDING_CROSS_DOMAIN_ROW_V2_VERSION.to_be_bytes());
        output.extend_from_slice(&0_u16.to_be_bytes());
        output.extend_from_slice(&(layout.stage as u16).to_be_bytes());
        output.extend_from_slice(
            &u16::try_from(layout.specs.len())
                .map_err(|_| CrossDomainError::LengthOverflow)?
                .to_be_bytes(),
        );
        output.extend_from_slice(
            layout
                .binding_commitment_id
                .as_ref()
                .ok_or(CrossDomainError::BindingRowEncoding)?
                .as_bytes(),
        );
        output.extend_from_slice(
            &u64::try_from(self.query_fft_index)
                .map_err(|_| CrossDomainError::LengthOverflow)?
                .to_be_bytes(),
        );
        for opening in &self.openings {
            output.push(opening.spec.log_size);
            output.push(opening.spec.field as u8);
            output.extend_from_slice(&0_u16.to_be_bytes());
            output.extend_from_slice(&opening.spec.column_count.to_be_bytes());
            output.extend_from_slice(
                &u64::try_from(opening.fft_index)
                    .map_err(|_| CrossDomainError::LengthOverflow)?
                    .to_be_bytes(),
            );
            output.extend_from_slice(
                &u32::try_from(opening.payload.len())
                    .map_err(|_| CrossDomainError::LengthOverflow)?
                    .to_be_bytes(),
            );
            output.extend_from_slice(&opening.payload);
        }
        if output.len() != expected_length {
            return Err(CrossDomainError::LengthOverflow);
        }
        Ok(output)
    }

    /// Parse one exact row payload against verifier-owned layout and index.
    /// All lengths are derived and checked before any row vector is allocated.
    pub fn decode_payload(
        encoded: &[u8],
        layout: &CrossDomainLayout,
        expected_query_fft_index: usize,
    ) -> Result<Self, CrossDomainError> {
        if encoded.len() != binding_cross_domain_row_v2_payload_len(layout)? {
            return Err(CrossDomainError::BindingRowEncoding);
        }
        let mut offset = 0_usize;
        let mut take = |length: usize| -> Result<&[u8], CrossDomainError> {
            let end = offset
                .checked_add(length)
                .ok_or(CrossDomainError::LengthOverflow)?;
            let value = encoded
                .get(offset..end)
                .ok_or(CrossDomainError::BindingRowEncoding)?;
            offset = end;
            Ok(value)
        };
        if take(8)? != BINDING_CROSS_DOMAIN_ROW_V2_MAGIC
            || u16::from_be_bytes(
                take(2)?
                    .try_into()
                    .map_err(|_| CrossDomainError::BindingRowEncoding)?,
            ) != BINDING_CROSS_DOMAIN_ROW_V2_VERSION
            || take(2)? != [0_u8; 2]
            || u16::from_be_bytes(
                take(2)?
                    .try_into()
                    .map_err(|_| CrossDomainError::BindingRowEncoding)?,
            ) != layout.stage as u16
            || usize::from(u16::from_be_bytes(
                take(2)?
                    .try_into()
                    .map_err(|_| CrossDomainError::BindingRowEncoding)?,
            )) != layout.specs.len()
            || take(BINDING_V2_BYTES)?
                != layout
                    .binding_commitment_id
                    .as_ref()
                    .ok_or(CrossDomainError::BindingRowEncoding)?
                    .as_bytes()
        {
            return Err(CrossDomainError::BindingRowEncoding);
        }
        let query_fft_index = usize::try_from(u64::from_be_bytes(
            take(8)?
                .try_into()
                .map_err(|_| CrossDomainError::BindingRowEncoding)?,
        ))
        .map_err(|_| CrossDomainError::BindingRowEncoding)?;
        if query_fft_index != expected_query_fft_index {
            return Err(CrossDomainError::OpeningIndexMismatch {
                log_size: layout.maximum_log_size(),
                expected: expected_query_fft_index,
                actual: query_fft_index,
            });
        }
        let maximum_log = layout.maximum_log_size();
        let maximum_transposed = transpose_circle_fft_index(query_fft_index, maximum_log)?;
        let mut openings = Vec::with_capacity(layout.specs.len());
        for spec in &layout.specs {
            let log_size = take(1)?[0];
            let field = take(1)?[0];
            if take(2)? != [0_u8; 2]
                || log_size != spec.log_size
                || field != spec.field as u8
                || u32::from_be_bytes(
                    take(4)?
                        .try_into()
                        .map_err(|_| CrossDomainError::BindingRowEncoding)?,
                ) != spec.column_count
            {
                return Err(CrossDomainError::BindingRowEncoding);
            }
            let fft_index = usize::try_from(u64::from_be_bytes(
                take(8)?
                    .try_into()
                    .map_err(|_| CrossDomainError::BindingRowEncoding)?,
            ))
            .map_err(|_| CrossDomainError::BindingRowEncoding)?;
            let expected_index = inverse_transpose_circle_fft_index(
                maximum_transposed >> (maximum_log - spec.log_size),
                spec.log_size,
            )?;
            if fft_index != expected_index {
                return Err(CrossDomainError::OpeningIndexMismatch {
                    log_size: spec.log_size,
                    expected: expected_index,
                    actual: fft_index,
                });
            }
            let payload_length = usize::try_from(u32::from_be_bytes(
                take(4)?
                    .try_into()
                    .map_err(|_| CrossDomainError::BindingRowEncoding)?,
            ))
            .map_err(|_| CrossDomainError::BindingRowEncoding)?;
            if payload_length != spec.payload_length()? {
                return Err(CrossDomainError::BindingRowEncoding);
            }
            let payload = take(payload_length)?.to_vec();
            validate_row(*spec, &payload, fft_index)?;
            openings.push(DomainOpening {
                spec: *spec,
                fft_index,
                payload,
            });
        }
        if offset != encoded.len() {
            return Err(CrossDomainError::BindingRowEncoding);
        }
        let row = Self {
            query_fft_index,
            openings,
        };
        validate_binding_row_v2(layout, &row)?;
        Ok(row)
    }

    /// Internal value-only adapter for the existing AIR arithmetic. It carries
    /// no legacy siblings, so accidental legacy authentication fails closed.
    pub(crate) fn arithmetic_view(&self) -> CrossDomainProof {
        CrossDomainProof {
            query_fft_index: self.query_fft_index,
            siblings: Vec::new(),
            openings: self.openings.clone(),
        }
    }
}

pub fn binding_cross_domain_row_v2_payload_len(
    layout: &CrossDomainLayout,
) -> Result<usize, CrossDomainError> {
    let mut length = 8_usize + 2 + 2 + 2 + 2 + BINDING_V2_BYTES + 8;
    for spec in &layout.specs {
        length = length
            .checked_add(1 + 1 + 2 + 4 + 8 + 4)
            .and_then(|value| value.checked_add(spec.payload_length().ok()?))
            .ok_or(CrossDomainError::LengthOverflow)?;
    }
    Ok(length)
}

fn validate_binding_row_v2(
    layout: &CrossDomainLayout,
    row: &BindingCrossDomainRowV2,
) -> Result<(), CrossDomainError> {
    let maximum_log = layout.maximum_log_size();
    let maximum_size = 1_usize
        .checked_shl(u32::from(maximum_log))
        .ok_or(CrossDomainError::LengthOverflow)?;
    if row.query_fft_index >= maximum_size {
        return Err(CrossDomainError::QueryIndexOutOfBounds {
            index: row.query_fft_index,
            domain_size: maximum_size,
        });
    }
    if row.openings.len() != layout.specs.len() {
        return Err(CrossDomainError::OpeningCountMismatch {
            expected: layout.specs.len(),
            actual: row.openings.len(),
        });
    }
    let maximum_transposed = transpose_circle_fft_index(row.query_fft_index, maximum_log)?;
    for (opening, spec) in row.openings.iter().zip(&layout.specs) {
        if opening.spec != *spec {
            return Err(CrossDomainError::OpeningSpecMismatch {
                log_size: spec.log_size,
            });
        }
        let expected_index = inverse_transpose_circle_fft_index(
            maximum_transposed >> (maximum_log - spec.log_size),
            spec.log_size,
        )?;
        if opening.fft_index != expected_index {
            return Err(CrossDomainError::OpeningIndexMismatch {
                log_size: spec.log_size,
                expected: expected_index,
                actual: opening.fft_index,
            });
        }
        if opening.payload.len() != spec.payload_length()? {
            return Err(CrossDomainError::RowLengthMismatch {
                log_size: spec.log_size,
                row_index: opening.fft_index,
                expected: spec.payload_length()?,
                actual: opening.payload.len(),
            });
        }
        validate_row(*spec, &opening.payload, opening.fft_index)?;
    }
    Ok(())
}

/// Canonical native-v2 multiproof and its exact opened row packets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingCrossDomainMultiProofV2 {
    rows: Vec<BindingCrossDomainRowV2>,
    proof: BindingMerkleMultiProofV2,
}

impl BindingCrossDomainMultiProofV2 {
    pub fn from_parts(
        layout: &CrossDomainLayout,
        rows: Vec<BindingCrossDomainRowV2>,
        proof: BindingMerkleMultiProofV2,
    ) -> Result<Self, CrossDomainError> {
        if rows.len() != proof.selected_indices().len()
            || rows
                .iter()
                .zip(proof.selected_indices())
                .any(|(row, index)| u64::try_from(row.query_fft_index).ok() != Some(*index))
        {
            return Err(CrossDomainError::BindingRowEncoding);
        }
        let expected_leaf_count = 1_u64
            .checked_shl(u32::from(layout.maximum_log_size()))
            .ok_or(CrossDomainError::LengthOverflow)?;
        if proof.leaf_count() != expected_leaf_count {
            return Err(CrossDomainError::BindingRowEncoding);
        }
        for row in &rows {
            validate_binding_row_v2(layout, row)?;
        }
        Ok(Self { rows, proof })
    }

    pub fn rows(&self) -> &[BindingCrossDomainRowV2] {
        &self.rows
    }

    pub const fn proof(&self) -> &BindingMerkleMultiProofV2 {
        &self.proof
    }

    pub fn row(
        &self,
        query_fft_index: usize,
    ) -> Result<&BindingCrossDomainRowV2, CrossDomainError> {
        self.rows
            .binary_search_by_key(&query_fft_index, |row| row.query_fft_index)
            .ok()
            .and_then(|position| self.rows.get(position))
            .ok_or(CrossDomainError::QueryIndexOutOfBounds {
                index: query_fft_index,
                domain_size: usize::try_from(self.proof.leaf_count()).unwrap_or(usize::MAX),
            })
    }

    pub fn verify(
        &self,
        layout: &CrossDomainLayout,
        expected_root: &BindingRootV2,
    ) -> Result<(), CrossDomainError> {
        let payloads = self
            .rows
            .iter()
            .map(|row| row.encode_payload(layout))
            .collect::<Result<Vec<_>, _>>()?;
        self.proof.verify_payloads(&payloads, expected_root)?;
        Ok(())
    }
}

/// Materialized prover tree for the native BindingRootV2 cross-domain format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingCrossDomainTreeV2 {
    layout: CrossDomainLayout,
    batches: Vec<DomainEvaluationBatch>,
    tree: BindingMerkleTreeV2,
}

impl BindingCrossDomainTreeV2 {
    pub fn build(
        layout: CrossDomainLayout,
        batches: Vec<DomainEvaluationBatch>,
    ) -> Result<Self, CrossDomainError> {
        if batches.len() != layout.specs.len() {
            return Err(CrossDomainError::BatchCountMismatch {
                expected: layout.specs.len(),
                actual: batches.len(),
            });
        }
        for (batch, spec) in batches.iter().zip(&layout.specs) {
            if batch.spec != *spec {
                return Err(CrossDomainError::BatchSpecMismatch {
                    log_size: spec.log_size,
                });
            }
        }
        let leaf_count = 1_usize
            .checked_shl(u32::from(layout.maximum_log_size()))
            .ok_or(CrossDomainError::LengthOverflow)?;
        let payloads = (0..leaf_count)
            .map(|query_fft_index| {
                binding_row_v2_from_batches(&layout, &batches, query_fft_index)?
                    .encode_payload(&layout)
            })
            .collect::<Result<Vec<_>, CrossDomainError>>()?;
        let tree = BindingMerkleTreeV2::from_payloads(&payloads)?;
        Ok(Self {
            layout,
            batches,
            tree,
        })
    }

    pub const fn layout(&self) -> &CrossDomainLayout {
        &self.layout
    }

    pub const fn root(&self) -> BindingRootV2 {
        self.tree.root()
    }

    pub fn proof(
        &self,
        selected_query_fft_indices: &[usize],
    ) -> Result<BindingCrossDomainMultiProofV2, CrossDomainError> {
        let selected = selected_query_fft_indices
            .iter()
            .copied()
            .map(|index| u64::try_from(index).map_err(|_| CrossDomainError::LengthOverflow))
            .collect::<Result<Vec<_>, _>>()?;
        let proof = self.tree.prove(&selected)?;
        let rows = selected_query_fft_indices
            .iter()
            .copied()
            .map(|index| binding_row_v2_from_batches(&self.layout, &self.batches, index))
            .collect::<Result<Vec<_>, _>>()?;
        BindingCrossDomainMultiProofV2::from_parts(&self.layout, rows, proof)
    }
}

fn binding_row_v2_from_batches(
    layout: &CrossDomainLayout,
    batches: &[DomainEvaluationBatch],
    query_fft_index: usize,
) -> Result<BindingCrossDomainRowV2, CrossDomainError> {
    let maximum_log = layout.maximum_log_size();
    let maximum_size = 1_usize
        .checked_shl(u32::from(maximum_log))
        .ok_or(CrossDomainError::LengthOverflow)?;
    if query_fft_index >= maximum_size {
        return Err(CrossDomainError::QueryIndexOutOfBounds {
            index: query_fft_index,
            domain_size: maximum_size,
        });
    }
    let maximum_transposed = transpose_circle_fft_index(query_fft_index, maximum_log)?;
    let openings = batches
        .iter()
        .map(|batch| {
            let level_index = maximum_transposed >> (maximum_log - batch.spec.log_size);
            let fft_index = inverse_transpose_circle_fft_index(level_index, batch.spec.log_size)?;
            Ok(DomainOpening {
                spec: batch.spec,
                fft_index,
                payload: batch.rows[fft_index].clone(),
            })
        })
        .collect::<Result<Vec<_>, CrossDomainError>>()?;
    let row = BindingCrossDomainRowV2 {
        query_fft_index,
        openings,
    };
    validate_binding_row_v2(layout, &row)?;
    Ok(row)
}

#[cfg(feature = "std")]
#[derive(Debug)]
pub enum DiskCrossDomainError {
    CrossDomain(CrossDomainError),
    Io(std::io::ErrorKind),
    Parent,
    Ownership,
    Shape,
    Overflow,
}

#[cfg(feature = "std")]
impl From<CrossDomainError> for DiskCrossDomainError {
    fn from(value: CrossDomainError) -> Self {
        Self::CrossDomain(value)
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for DiskCrossDomainError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.kind())
    }
}

#[cfg(feature = "std")]
impl fmt::Display for DiskCrossDomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "BL-PQ512 disk cross-domain error: {self:?}")
    }
}

#[cfg(feature = "std")]
impl core::error::Error for DiskCrossDomainError {}

#[cfg(feature = "std")]
#[derive(Debug)]
pub struct DiskDomainEvaluationBatch {
    spec: DomainSpec,
    row_file: Option<PathBuf>,
    column_files: Option<Vec<PathBuf>>,
    column_readers: Option<std::sync::Mutex<Vec<File>>>,
}

#[cfg(feature = "std")]
impl DiskDomainEvaluationBatch {
    pub fn new(spec: DomainSpec, row_file: PathBuf) -> Result<Self, DiskCrossDomainError> {
        DomainSpec::new(spec.log_size, spec.field, spec.column_count)?;
        if !row_file.is_absolute() || !row_file.is_file() {
            return Err(DiskCrossDomainError::Shape);
        }
        let payload_length = spec.payload_length()?;
        let expected = u64::try_from(1_usize << spec.log_size)
            .ok()
            .and_then(|rows| {
                u64::try_from(payload_length)
                    .ok()
                    .and_then(|length| rows.checked_mul(length))
            })
            .ok_or(DiskCrossDomainError::Overflow)?;
        if fs::metadata(&row_file)?.len() != expected {
            return Err(DiskCrossDomainError::Shape);
        }
        Ok(Self {
            spec,
            row_file: Some(row_file),
            column_files: None,
            column_readers: None,
        })
    }

    /// Use a transient row-major file for tree construction, then retain only
    /// the canonical column files used by downstream prover stages.
    pub fn new_with_columns(
        spec: DomainSpec,
        row_file: PathBuf,
        column_files: Vec<PathBuf>,
    ) -> Result<Self, DiskCrossDomainError> {
        let mut batch = Self::new(spec, row_file)?;
        let scalar_bytes = match spec.field {
            EvaluationField::M31 => 4_u64,
            EvaluationField::Fp16 => 64_u64,
        };
        let expected_column_bytes = u64::try_from(1_usize << spec.log_size)
            .ok()
            .and_then(|rows| rows.checked_mul(scalar_bytes))
            .ok_or(DiskCrossDomainError::Overflow)?;
        if column_files.len() != spec.column_count as usize
            || column_files.iter().any(|path| {
                !path.is_absolute()
                    || fs::metadata(path)
                        .map(|metadata| metadata.len() != expected_column_bytes)
                        .unwrap_or(true)
            })
        {
            return Err(DiskCrossDomainError::Shape);
        }
        let readers = column_files
            .iter()
            .map(File::open)
            .collect::<Result<Vec<_>, _>>()?;
        batch.column_files = Some(column_files);
        batch.column_readers = Some(std::sync::Mutex::new(readers));
        Ok(batch)
    }

    /// Commit and open directly from the canonical column layout without
    /// constructing a duplicate row-major file.
    pub fn new_from_columns(
        spec: DomainSpec,
        column_files: Vec<PathBuf>,
    ) -> Result<Self, DiskCrossDomainError> {
        DomainSpec::new(spec.log_size, spec.field, spec.column_count)?;
        let scalar_bytes = match spec.field {
            EvaluationField::M31 => 4_u64,
            EvaluationField::Fp16 => 64_u64,
        };
        let expected_column_bytes = u64::try_from(1_usize << spec.log_size)
            .ok()
            .and_then(|rows| rows.checked_mul(scalar_bytes))
            .ok_or(DiskCrossDomainError::Overflow)?;
        if column_files.len() != spec.column_count as usize
            || column_files.iter().any(|path| {
                !path.is_absolute()
                    || fs::metadata(path)
                        .map(|metadata| metadata.len() != expected_column_bytes)
                        .unwrap_or(true)
            })
        {
            return Err(DiskCrossDomainError::Shape);
        }
        let readers = column_files
            .iter()
            .map(File::open)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            spec,
            row_file: None,
            column_files: Some(column_files),
            column_readers: Some(std::sync::Mutex::new(readers)),
        })
    }

    pub const fn spec(&self) -> DomainSpec {
        self.spec
    }
}

#[cfg(feature = "std")]
pub struct DiskCrossDomainTree {
    layout: CrossDomainLayout,
    batches: Vec<DiskDomainEvaluationBatch>,
    directory: PathBuf,
    level_paths: Vec<PathBuf>,
    root: CrossDomainRoot,
    level_plan: DiskTreeLevelPlan,
}

#[cfg(feature = "std")]
impl DiskCrossDomainTree {
    pub fn build(
        layout: CrossDomainLayout,
        batches: Vec<DiskDomainEvaluationBatch>,
        scratch_parent: &Path,
        tree_nonce: &[u8; 32],
    ) -> Result<Self, DiskCrossDomainError> {
        Self::build_with_level_budget(
            layout,
            batches,
            scratch_parent,
            tree_nonce,
            DISK_TREE_RETAINED_LEVEL_BUDGET_BYTES,
        )
    }

    pub fn build_with_level_budget(
        layout: CrossDomainLayout,
        batches: Vec<DiskDomainEvaluationBatch>,
        scratch_parent: &Path,
        tree_nonce: &[u8; 32],
        retained_level_budget_bytes: u64,
    ) -> Result<Self, DiskCrossDomainError> {
        if !scratch_parent.is_absolute()
            || !scratch_parent.is_dir()
            || batches.len() != layout.specs.len()
        {
            return Err(DiskCrossDomainError::Parent);
        }
        for (batch, spec) in batches.iter().zip(&layout.specs) {
            if batch.spec != *spec {
                return Err(DiskCrossDomainError::Shape);
            }
        }
        let directory = scratch_parent.join(disk_tree_directory_name(tree_nonce));
        fs::create_dir(&directory)?;
        let marker_path = directory.join("OWNER");
        let marker_result = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker_path)
            .and_then(|mut marker| {
                marker.write_all(b"BLPQCDT1")?;
                marker.write_all(&layout.identity().into_bytes())?;
                marker.sync_data()
            });
        if let Err(error) = marker_result {
            let _ = fs::remove_file(&marker_path);
            let _ = fs::remove_dir(&directory);
            return Err(error.into());
        }
        let result = Self::build_owned(
            layout,
            batches,
            directory.clone(),
            retained_level_budget_bytes,
        );
        if result.is_err() {
            let _ = cleanup_disk_tree(&directory, None);
        }
        result
    }

    fn build_owned(
        layout: CrossDomainLayout,
        batches: Vec<DiskDomainEvaluationBatch>,
        directory: PathBuf,
        retained_level_budget_bytes: u64,
    ) -> Result<Self, DiskCrossDomainError> {
        let level_plan =
            plan_disk_tree_levels(layout.maximum_log_size(), retained_level_budget_bytes)?;
        let level_paths = disk_tree_level_paths(layout.maximum_log_size(), &directory);
        let top = if level_plan.policy == DiskTreeLevelPolicy::Retain {
            write_disk_tree_levels(&layout, &batches, &directory)?;
            read_hash_at(&level_paths[0], 0)?
        } else {
            recompute_disk_tree_frontier(&layout, &batches, &BTreeSet::new())?.0
        };
        let root = hash_root(&layout, top);
        for batch in &batches {
            if batch.column_files.is_some()
                && let Some(row_file) = &batch.row_file
            {
                fs::remove_file(row_file)?;
            }
        }
        Ok(Self {
            layout,
            batches,
            directory,
            level_paths,
            root,
            level_plan,
        })
    }

    pub const fn root(&self) -> CrossDomainRoot {
        self.root
    }

    pub const fn layout(&self) -> &CrossDomainLayout {
        &self.layout
    }

    pub const fn level_plan(&self) -> DiskTreeLevelPlan {
        self.level_plan
    }

    pub fn proof(&self, query_fft_index: usize) -> Result<CrossDomainProof, DiskCrossDomainError> {
        self.proofs(&[query_fft_index])?
            .pop()
            .ok_or(DiskCrossDomainError::Shape)
    }

    /// Open several queries while reusing one handle per retained Merkle level
    /// and row-major batch. Input order and duplicates are preserved.
    pub fn proofs(
        &self,
        query_fft_indices: &[usize],
    ) -> Result<Vec<CrossDomainProof>, DiskCrossDomainError> {
        let maximum_log = self.layout.maximum_log_size();
        let maximum_size = 1_usize
            .checked_shl(u32::from(maximum_log))
            .ok_or(DiskCrossDomainError::Overflow)?;
        if let Some(query_fft_index) = query_fft_indices
            .iter()
            .copied()
            .find(|query| *query >= maximum_size)
        {
            return Err(CrossDomainError::QueryIndexOutOfBounds {
                index: query_fft_index,
                domain_size: maximum_size,
            }
            .into());
        }
        if self.level_plan.policy == DiskTreeLevelPolicy::Retain {
            return self.proofs_from_level_paths(query_fft_indices, &self.level_paths);
        }
        let mut targets = BTreeSet::new();
        for query_fft_index in query_fft_indices.iter().copied() {
            let mut current_index = transpose_circle_fft_index(query_fft_index, maximum_log)?;
            for level in (1..=maximum_log).rev() {
                targets.insert((level, current_index ^ 1));
                current_index >>= 1;
            }
        }
        let (top, frontier) = recompute_disk_tree_frontier(&self.layout, &self.batches, &targets)?;
        if hash_root(&self.layout, top) != self.root {
            return Err(DiskCrossDomainError::Shape);
        }
        self.proofs_from_frontier(query_fft_indices, &frontier)
    }

    fn proofs_from_frontier(
        &self,
        query_fft_indices: &[usize],
        frontier: &BTreeMap<(u8, usize), CrossDomainHash>,
    ) -> Result<Vec<CrossDomainProof>, DiskCrossDomainError> {
        let maximum_log = self.layout.maximum_log_size();
        let mut proofs = self.proofs_with_sibling_source(query_fft_indices, |level, index| {
            frontier
                .get(&(level, index))
                .copied()
                .ok_or(DiskCrossDomainError::Shape)
        })?;
        if proofs
            .iter()
            .any(|proof| proof.siblings.len() != usize::from(maximum_log))
        {
            return Err(DiskCrossDomainError::Shape);
        }
        Ok(core::mem::take(&mut proofs))
    }

    fn proofs_from_level_paths(
        &self,
        query_fft_indices: &[usize],
        level_paths: &[PathBuf],
    ) -> Result<Vec<CrossDomainProof>, DiskCrossDomainError> {
        let mut level_readers = level_paths
            .iter()
            .map(File::open)
            .collect::<Result<Vec<_>, _>>()?;
        self.proofs_with_sibling_source(query_fft_indices, |level, index| {
            read_hash_at_reader(&mut level_readers[usize::from(level)], index)
        })
    }

    fn proofs_with_sibling_source<F>(
        &self,
        query_fft_indices: &[usize],
        mut sibling: F,
    ) -> Result<Vec<CrossDomainProof>, DiskCrossDomainError>
    where
        F: FnMut(u8, usize) -> Result<CrossDomainHash, DiskCrossDomainError>,
    {
        let maximum_log = self.layout.maximum_log_size();
        let mut row_readers = self
            .batches
            .iter()
            .map(|batch| {
                if batch.column_readers.is_some() {
                    Ok(None)
                } else {
                    batch
                        .row_file
                        .as_ref()
                        .ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "missing disk cross-domain row source",
                            )
                        })
                        .and_then(File::open)
                        .map(Some)
                }
            })
            .collect::<Result<Vec<_>, std::io::Error>>()?;
        let mut proofs = Vec::with_capacity(query_fft_indices.len());
        for query_fft_index in query_fft_indices.iter().copied() {
            let maximum_transposed = transpose_circle_fft_index(query_fft_index, maximum_log)?;
            let mut current_index = maximum_transposed;
            let mut siblings = Vec::with_capacity(usize::from(maximum_log));
            for level in (1..=maximum_log).rev() {
                siblings.push(sibling(level, current_index ^ 1)?.0);
                current_index >>= 1;
            }
            let mut openings = Vec::with_capacity(self.batches.len());
            for (batch_index, batch) in self.batches.iter().enumerate() {
                let level_index = maximum_transposed >> (maximum_log - batch.spec.log_size);
                let fft_index =
                    inverse_transpose_circle_fft_index(level_index, batch.spec.log_size)?;
                let payload = if let Some(column_readers) = &batch.column_readers {
                    let scalar_bytes = match batch.spec.field {
                        EvaluationField::M31 => 4_usize,
                        EvaluationField::Fp16 => 64_usize,
                    };
                    let offset = u64::try_from(fft_index)
                        .ok()
                        .and_then(|index| {
                            u64::try_from(scalar_bytes)
                                .ok()
                                .and_then(|length| index.checked_mul(length))
                        })
                        .ok_or(DiskCrossDomainError::Overflow)?;
                    let mut payload = Vec::with_capacity(batch.spec.payload_length()?);
                    let mut scalar = vec![0_u8; scalar_bytes];
                    let mut columns = column_readers
                        .lock()
                        .map_err(|_| DiskCrossDomainError::Shape)?;
                    for column in columns.iter_mut() {
                        column.seek(SeekFrom::Start(offset))?;
                        column.read_exact(&mut scalar)?;
                        payload.extend_from_slice(&scalar);
                    }
                    payload
                } else {
                    let payload_length = batch.spec.payload_length()?;
                    let offset = u64::try_from(fft_index)
                        .ok()
                        .and_then(|index| {
                            u64::try_from(payload_length)
                                .ok()
                                .and_then(|length| index.checked_mul(length))
                        })
                        .ok_or(DiskCrossDomainError::Overflow)?;
                    let mut payload = vec![0_u8; payload_length];
                    let rows = row_readers[batch_index]
                        .as_mut()
                        .ok_or(DiskCrossDomainError::Shape)?;
                    rows.seek(SeekFrom::Start(offset))?;
                    rows.read_exact(&mut payload)?;
                    payload
                };
                validate_row(batch.spec, &payload, fft_index)?;
                openings.push(DomainOpening {
                    spec: batch.spec,
                    fft_index,
                    payload,
                });
            }
            proofs.push(CrossDomainProof {
                query_fft_index,
                siblings,
                openings,
            });
        }
        Ok(proofs)
    }
}

#[cfg(feature = "std")]
struct DiskBatchSequentialReader {
    spec: DomainSpec,
    row: Option<File>,
    columns: Option<Vec<BufReader<File>>>,
    next_node_index: usize,
}

#[cfg(feature = "std")]
impl DiskBatchSequentialReader {
    fn new(batch: &DiskDomainEvaluationBatch) -> Result<Self, DiskCrossDomainError> {
        let row = batch
            .row_file
            .as_ref()
            .filter(|path| path.is_file())
            .map(File::open)
            .transpose()?;
        let columns = if row.is_none() {
            Some(
                batch
                    .column_files
                    .as_ref()
                    .ok_or(DiskCrossDomainError::Shape)?
                    .iter()
                    .map(|path| File::open(path).map(BufReader::new))
                    .collect::<Result<Vec<_>, _>>()?,
            )
        } else {
            None
        };
        Ok(Self {
            spec: batch.spec,
            row,
            columns,
            next_node_index: 0,
        })
    }

    fn read_payload(
        &mut self,
        node_index: usize,
    ) -> Result<(usize, Vec<u8>), DiskCrossDomainError> {
        let count = 1_usize
            .checked_shl(u32::from(self.spec.log_size))
            .ok_or(DiskCrossDomainError::Overflow)?;
        if node_index != self.next_node_index || node_index >= count {
            return Err(DiskCrossDomainError::Shape);
        }
        let fft_index = inverse_transpose_circle_fft_index(node_index, self.spec.log_size)?;
        let payload = if let Some(row) = self.row.as_mut() {
            let payload_length = self.spec.payload_length()?;
            let offset = u64::try_from(fft_index)
                .ok()
                .and_then(|index| {
                    u64::try_from(payload_length)
                        .ok()
                        .and_then(|length| index.checked_mul(length))
                })
                .ok_or(DiskCrossDomainError::Overflow)?;
            let mut payload = vec![0_u8; payload_length];
            row.seek(SeekFrom::Start(offset))?;
            row.read_exact(&mut payload)?;
            payload
        } else {
            let scalar_bytes = self.spec.field.encoded_width();
            let half = count >> 1;
            let columns = self.columns.as_mut().ok_or(DiskCrossDomainError::Shape)?;
            if node_index == half {
                for column in columns.iter_mut() {
                    column.seek(SeekFrom::Start(0))?;
                }
            }
            let scalar_offset = if node_index < half { 0 } else { scalar_bytes };
            let mut pair = vec![0_u8; scalar_bytes * 2];
            let mut payload = Vec::with_capacity(self.spec.payload_length()?);
            for column in columns.iter_mut() {
                column.read_exact(&mut pair)?;
                payload.extend_from_slice(&pair[scalar_offset..scalar_offset + scalar_bytes]);
            }
            payload
        };
        validate_row(self.spec, &payload, fft_index)?;
        self.next_node_index += 1;
        Ok((fft_index, payload))
    }
}

/// Native BindingRootV2 commitment over one disk-backed cross-domain source.
///
/// Only the canonical source files and the final 128-byte root are retained.
/// Tree construction uses one half-leaf transient file because circle-index
/// transposition emits all even native leaves before all odd native leaves.
/// Authentication frontiers are recomputed after the public queries exist,
/// keeping both host memory and persistent scratch bounded independently of
/// the domain size.
#[cfg(feature = "std")]
pub struct DiskBindingCrossDomainTreeV2<'a> {
    source: &'a DiskCrossDomainTree,
    layout: CrossDomainLayout,
    root: BindingRootV2,
}

#[cfg(feature = "std")]
impl DiskCrossDomainTree {
    pub fn binding_v2_tree(
        &self,
        binding_layout: CrossDomainLayout,
    ) -> Result<DiskBindingCrossDomainTreeV2<'_>, DiskCrossDomainError> {
        if binding_layout.binding_commitment_id().is_none()
            || binding_layout.stage() != self.layout.stage()
            || binding_layout.specs() != self.layout.specs()
        {
            return Err(DiskCrossDomainError::Shape);
        }
        let (top, frontier, rows) =
            recompute_disk_binding_v2(self, &binding_layout, &BTreeSet::new(), &BTreeSet::new())?;
        if !frontier.is_empty() || !rows.is_empty() {
            return Err(DiskCrossDomainError::Shape);
        }
        let leaf_count = 1_u64
            .checked_shl(u32::from(binding_layout.maximum_log_size()))
            .ok_or(DiskCrossDomainError::Overflow)?;
        let root = BindingRootV2::from_top(leaf_count, top).map_err(CrossDomainError::from)?;
        Ok(DiskBindingCrossDomainTreeV2 {
            source: self,
            layout: binding_layout,
            root,
        })
    }
}

#[cfg(feature = "std")]
impl DiskBindingCrossDomainTreeV2<'_> {
    pub const fn layout(&self) -> &CrossDomainLayout {
        &self.layout
    }

    pub const fn root(&self) -> BindingRootV2 {
        self.root
    }

    pub fn proof(
        &self,
        selected_query_fft_indices: &[usize],
    ) -> Result<BindingCrossDomainMultiProofV2, DiskCrossDomainError> {
        let selected_indices = selected_query_fft_indices
            .iter()
            .copied()
            .map(|index| u64::try_from(index).map_err(|_| DiskCrossDomainError::Overflow))
            .collect::<Result<Vec<_>, _>>()?;
        let leaf_count = 1_u64
            .checked_shl(u32::from(self.layout.maximum_log_size()))
            .ok_or(DiskCrossDomainError::Overflow)?;
        let positions = canonical_binding_frontier_positions_v2(leaf_count, &selected_indices)
            .map_err(CrossDomainError::from)?;
        let targets = positions
            .iter()
            .map(|position| (position.level, position.index))
            .collect::<BTreeSet<_>>();
        let selected = selected_query_fft_indices
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if selected.len() != selected_query_fft_indices.len() {
            return Err(DiskCrossDomainError::Shape);
        }
        let (top, frontier, mut rows) =
            recompute_disk_binding_v2(self.source, &self.layout, &targets, &selected)?;
        let recomputed_root =
            BindingRootV2::from_top(leaf_count, top).map_err(CrossDomainError::from)?;
        if recomputed_root != self.root || frontier.len() != positions.len() {
            return Err(DiskCrossDomainError::Shape);
        }
        let frontier_digests = positions
            .iter()
            .map(|position| {
                frontier
                    .get(&(position.level, position.index))
                    .copied()
                    .ok_or(DiskCrossDomainError::Shape)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let proof = BindingMerkleMultiProofV2::from_canonical_frontier(
            leaf_count,
            selected_indices,
            frontier_digests,
        )
        .map_err(CrossDomainError::from)?;
        let ordered_rows = selected_query_fft_indices
            .iter()
            .map(|index| rows.remove(index).ok_or(DiskCrossDomainError::Shape))
            .collect::<Result<Vec<_>, _>>()?;
        if !rows.is_empty() {
            return Err(DiskCrossDomainError::Shape);
        }
        BindingCrossDomainMultiProofV2::from_parts(&self.layout, ordered_rows, proof)
            .map_err(DiskCrossDomainError::from)
    }
}

#[cfg(feature = "std")]
struct DiskBindingBatchReader {
    reader: DiskBatchSequentialReader,
    current_node_index: Option<usize>,
    current_fft_index: usize,
    current_payload: Vec<u8>,
}

#[cfg(feature = "std")]
impl DiskBindingBatchReader {
    fn new(batch: &DiskDomainEvaluationBatch) -> Result<Self, DiskCrossDomainError> {
        Ok(Self {
            reader: DiskBatchSequentialReader::new(batch)?,
            current_node_index: None,
            current_fft_index: 0,
            current_payload: Vec::new(),
        })
    }

    fn opening(
        &mut self,
        maximum_transposed_index: usize,
        maximum_log_size: u8,
    ) -> Result<DomainOpening, DiskCrossDomainError> {
        let node_index = maximum_transposed_index >> (maximum_log_size - self.reader.spec.log_size);
        if self.current_node_index != Some(node_index) {
            let (fft_index, payload) = self.reader.read_payload(node_index)?;
            self.current_node_index = Some(node_index);
            self.current_fft_index = fft_index;
            self.current_payload = payload;
        }
        Ok(DomainOpening {
            spec: self.reader.spec,
            fft_index: self.current_fft_index,
            payload: self.current_payload.clone(),
        })
    }
}

#[cfg(feature = "std")]
fn next_disk_binding_row(
    layout: &CrossDomainLayout,
    readers: &mut [DiskBindingBatchReader],
    maximum_transposed_index: usize,
) -> Result<BindingCrossDomainRowV2, DiskCrossDomainError> {
    let query_fft_index =
        inverse_transpose_circle_fft_index(maximum_transposed_index, layout.maximum_log_size())?;
    let openings = readers
        .iter_mut()
        .map(|reader| reader.opening(maximum_transposed_index, layout.maximum_log_size()))
        .collect::<Result<Vec<_>, _>>()?;
    let row = BindingCrossDomainRowV2 {
        query_fft_index,
        openings,
    };
    validate_binding_row_v2(layout, &row)?;
    Ok(row)
}

#[cfg(feature = "std")]
fn retain_binding_target(
    targets: &BTreeSet<(u32, u64)>,
    retained: &mut BTreeMap<(u32, u64), BindingDigestV2>,
    level: u32,
    index: u64,
    digest: BindingDigestV2,
) -> Result<(), DiskCrossDomainError> {
    if targets.contains(&(level, index)) && retained.insert((level, index), digest).is_some() {
        return Err(DiskCrossDomainError::Shape);
    }
    Ok(())
}

#[cfg(feature = "std")]
type RecomputedDiskBindingV2 = (
    BindingDigestV2,
    BTreeMap<(u32, u64), BindingDigestV2>,
    BTreeMap<usize, BindingCrossDomainRowV2>,
);

#[cfg(feature = "std")]
fn recompute_disk_binding_v2(
    source: &DiskCrossDomainTree,
    layout: &CrossDomainLayout,
    targets: &BTreeSet<(u32, u64)>,
    selected_queries: &BTreeSet<usize>,
) -> Result<RecomputedDiskBindingV2, DiskCrossDomainError> {
    let maximum_log = layout.maximum_log_size();
    let leaf_count = 1_usize
        .checked_shl(u32::from(maximum_log))
        .ok_or(DiskCrossDomainError::Overflow)?;
    let half = leaf_count >> 1;
    let even_path = source.directory.join("binding-v2-even-leaves.tmp");
    let even_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&even_path)?;
    let result = (|| {
        let mut readers = source
            .batches
            .iter()
            .map(DiskBindingBatchReader::new)
            .collect::<Result<Vec<_>, _>>()?;
        let mut retained = BTreeMap::new();
        let mut selected_rows = BTreeMap::new();
        let mut even = BufWriter::new(even_file);
        for maximum_transposed_index in 0..half {
            let row = next_disk_binding_row(layout, &mut readers, maximum_transposed_index)?;
            let query_index = row.query_fft_index;
            if query_index != maximum_transposed_index << 1 {
                return Err(DiskCrossDomainError::Shape);
            }
            let payload = row.encode_payload(layout)?;
            let digest = BindingMerkleLeafV2::hash(
                u64::try_from(query_index).map_err(|_| DiskCrossDomainError::Overflow)?,
                &payload,
            )
            .map_err(CrossDomainError::from)?
            .digest();
            retain_binding_target(
                targets,
                &mut retained,
                0,
                u64::try_from(query_index).map_err(|_| DiskCrossDomainError::Overflow)?,
                digest,
            )?;
            if selected_queries.contains(&query_index)
                && selected_rows.insert(query_index, row).is_some()
            {
                return Err(DiskCrossDomainError::Shape);
            }
            even.write_all(digest.as_bytes())?;
        }
        even.flush()?;
        drop(even);

        let mut even = BufReader::new(File::open(&even_path)?);
        let mut stack = vec![None; usize::from(maximum_log) + 1];
        for pair_index in 0..half {
            let maximum_transposed_index = half + pair_index;
            let row = next_disk_binding_row(layout, &mut readers, maximum_transposed_index)?;
            let query_index = row.query_fft_index;
            if query_index != (pair_index << 1) + 1 {
                return Err(DiskCrossDomainError::Shape);
            }
            let payload = row.encode_payload(layout)?;
            let odd = BindingMerkleLeafV2::hash(
                u64::try_from(query_index).map_err(|_| DiskCrossDomainError::Overflow)?,
                &payload,
            )
            .map_err(CrossDomainError::from)?
            .digest();
            retain_binding_target(
                targets,
                &mut retained,
                0,
                u64::try_from(query_index).map_err(|_| DiskCrossDomainError::Overflow)?,
                odd,
            )?;
            if selected_queries.contains(&query_index)
                && selected_rows.insert(query_index, row).is_some()
            {
                return Err(DiskCrossDomainError::Shape);
            }

            let mut even_encoded = [0_u8; BINDING_V2_BYTES];
            even.read_exact(&mut even_encoded)?;
            let left = BindingDigestV2::decode(&even_encoded).map_err(CrossDomainError::from)?;
            let mut level = 1_u32;
            let mut node_index =
                u64::try_from(pair_index).map_err(|_| DiskCrossDomainError::Overflow)?;
            let mut current = BindingMerkleNodeV2::hash(level, node_index, left, odd)
                .map_err(CrossDomainError::from)?
                .digest();
            retain_binding_target(targets, &mut retained, level, node_index, current)?;
            while node_index & 1 == 1 {
                let left = stack
                    [usize::try_from(level).map_err(|_| DiskCrossDomainError::Overflow)?]
                .take()
                .ok_or(DiskCrossDomainError::Shape)?;
                node_index >>= 1;
                level = level.checked_add(1).ok_or(DiskCrossDomainError::Overflow)?;
                current = BindingMerkleNodeV2::hash(level, node_index, left, current)
                    .map_err(CrossDomainError::from)?
                    .digest();
                retain_binding_target(targets, &mut retained, level, node_index, current)?;
            }
            let slot = stack
                .get_mut(usize::try_from(level).map_err(|_| DiskCrossDomainError::Overflow)?)
                .ok_or(DiskCrossDomainError::Shape)?;
            if slot.replace(current).is_some() {
                return Err(DiskCrossDomainError::Shape);
            }
        }
        let mut trailing = [0_u8; 1];
        if even.read(&mut trailing)? != 0
            || readers.iter().any(|reader| {
                reader.reader.next_node_index != 1_usize << reader.reader.spec.log_size
            })
            || stack[..usize::from(maximum_log)]
                .iter()
                .any(Option::is_some)
            || retained.len() != targets.len()
            || selected_rows.len() != selected_queries.len()
        {
            return Err(DiskCrossDomainError::Shape);
        }
        let top = stack[usize::from(maximum_log)]
            .take()
            .ok_or(DiskCrossDomainError::Shape)?;
        Ok((top, retained, selected_rows))
    })();
    match fs::remove_file(&even_path) {
        Ok(()) => result,
        Err(cleanup_error) if result.is_ok() => Err(cleanup_error.into()),
        Err(_) => result,
    }
}

#[cfg(feature = "std")]
type DiskTreeFrontier = BTreeMap<(u8, usize), CrossDomainHash>;

#[cfg(feature = "std")]
type RecomputedDiskTree = (CrossDomainHash, DiskTreeFrontier);

#[cfg(feature = "std")]
fn recompute_disk_tree_frontier(
    layout: &CrossDomainLayout,
    batches: &[DiskDomainEvaluationBatch],
    targets: &BTreeSet<(u8, usize)>,
) -> Result<RecomputedDiskTree, DiskCrossDomainError> {
    let maximum_log = layout.maximum_log_size();
    let leaf_count = 1_usize
        .checked_shl(u32::from(maximum_log))
        .ok_or(DiskCrossDomainError::Overflow)?;
    let mut readers = batches
        .iter()
        .map(DiskBatchSequentialReader::new)
        .collect::<Result<Vec<_>, _>>()?;
    let mut stack = vec![None; usize::from(maximum_log) + 1];
    let mut frontier = BTreeMap::new();

    for leaf_index in 0..leaf_count {
        let mut log_size = maximum_log;
        let mut node_index = leaf_index;
        let mut current = empty_cross_domain_hash();
        if let Some(reader) = readers
            .iter_mut()
            .find(|reader| reader.spec.log_size == log_size)
        {
            let (fft_index, payload) = reader.read_payload(node_index)?;
            current = hash_insert(
                log_size,
                node_index,
                current,
                hash_evaluation(
                    layout,
                    &DomainOpening {
                        spec: reader.spec,
                        fft_index,
                        payload,
                    },
                ),
            );
        }
        if targets.contains(&(log_size, node_index))
            && frontier.insert((log_size, node_index), current).is_some()
        {
            return Err(DiskCrossDomainError::Shape);
        }
        while node_index & 1 == 1 {
            let left = stack[usize::from(log_size)]
                .take()
                .ok_or(DiskCrossDomainError::Shape)?;
            current = hash_children(left, current);
            node_index >>= 1;
            log_size = log_size.checked_sub(1).ok_or(DiskCrossDomainError::Shape)?;
            if let Some(reader) = readers
                .iter_mut()
                .find(|reader| reader.spec.log_size == log_size)
            {
                let (fft_index, payload) = reader.read_payload(node_index)?;
                current = hash_insert(
                    log_size,
                    node_index,
                    current,
                    hash_evaluation(
                        layout,
                        &DomainOpening {
                            spec: reader.spec,
                            fft_index,
                            payload,
                        },
                    ),
                );
            }
            if targets.contains(&(log_size, node_index))
                && frontier.insert((log_size, node_index), current).is_some()
            {
                return Err(DiskCrossDomainError::Shape);
            }
        }
        if stack[usize::from(log_size)].replace(current).is_some() {
            return Err(DiskCrossDomainError::Shape);
        }
    }
    if readers
        .iter()
        .any(|reader| reader.next_node_index != 1_usize << reader.spec.log_size)
        || stack[1..].iter().any(Option::is_some)
    {
        return Err(DiskCrossDomainError::Shape);
    }
    let top = stack[0].ok_or(DiskCrossDomainError::Shape)?;
    if frontier.len() != targets.len() {
        return Err(DiskCrossDomainError::Shape);
    }
    Ok((top, frontier))
}

#[cfg(feature = "std")]
fn disk_tree_level_paths(maximum_log: u8, directory: &Path) -> Vec<PathBuf> {
    (0..=maximum_log)
        .map(|log_size| directory.join(format!("level-{log_size:02}.sha3-512")))
        .collect()
}

#[cfg(feature = "std")]
fn write_disk_tree_levels(
    layout: &CrossDomainLayout,
    batches: &[DiskDomainEvaluationBatch],
    directory: &Path,
) -> Result<Vec<PathBuf>, DiskCrossDomainError> {
    let maximum_log = layout.maximum_log_size();
    let level_paths = disk_tree_level_paths(maximum_log, directory);
    let result = (|| {
        for log_size in (0..=maximum_log).rev() {
            let count = 1_usize
                .checked_shl(u32::from(log_size))
                .ok_or(DiskCrossDomainError::Overflow)?;
            let mut output = BufWriter::new(
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&level_paths[usize::from(log_size)])?,
            );
            let mut child = if log_size == maximum_log {
                None
            } else {
                Some(BufReader::new(File::open(
                    &level_paths[usize::from(log_size + 1)],
                )?))
            };
            let batch = batches.iter().find(|batch| batch.spec.log_size == log_size);
            let mut rows = batch
                .and_then(|batch| batch.row_file.as_ref())
                .filter(|row_file| row_file.is_file())
                .map(File::open)
                .transpose()?;
            let mut columns = if rows.is_none() {
                batch
                    .and_then(|batch| batch.column_files.as_ref())
                    .map(|paths| {
                        paths
                            .iter()
                            .map(|path| File::open(path).map(BufReader::new))
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .transpose()?
            } else {
                None
            };
            let mut row_payload = match batch {
                Some(batch) => vec![0_u8; batch.spec.payload_length()?],
                None => Vec::new(),
            };
            for node_index in 0..count {
                let mut node = if let Some(reader) = child.as_mut() {
                    let left = read_cross_domain_hash(reader)?;
                    let right = read_cross_domain_hash(reader)?;
                    hash_children(left, right)
                } else {
                    empty_cross_domain_hash()
                };
                if let Some(batch) = batch {
                    let fft_index = inverse_transpose_circle_fft_index(node_index, log_size)?;
                    let payload = if let Some(row_file) = rows.as_mut() {
                        let offset = u64::try_from(fft_index)
                            .ok()
                            .and_then(|index| {
                                u64::try_from(row_payload.len())
                                    .ok()
                                    .and_then(|length| index.checked_mul(length))
                            })
                            .ok_or(DiskCrossDomainError::Overflow)?;
                        row_file.seek(SeekFrom::Start(offset))?;
                        row_file.read_exact(&mut row_payload)?;
                        row_payload.clone()
                    } else if let Some(column_readers) = columns.as_mut() {
                        let scalar_bytes = batch.spec.field.encoded_width();
                        let half = count >> 1;
                        if node_index == half {
                            for column in column_readers.iter_mut() {
                                column.seek(SeekFrom::Start(0))?;
                            }
                        }
                        let scalar_offset = if node_index < half { 0 } else { scalar_bytes };
                        let mut pair = vec![0_u8; scalar_bytes * 2];
                        let mut payload = Vec::with_capacity(batch.spec.payload_length()?);
                        for column in column_readers.iter_mut() {
                            column.read_exact(&mut pair)?;
                            payload.extend_from_slice(
                                &pair[scalar_offset..scalar_offset + scalar_bytes],
                            );
                        }
                        payload
                    } else {
                        return Err(DiskCrossDomainError::Shape);
                    };
                    validate_row(batch.spec, &payload, fft_index)?;
                    node = hash_insert(
                        log_size,
                        node_index,
                        node,
                        hash_evaluation(
                            layout,
                            &DomainOpening {
                                spec: batch.spec,
                                fft_index,
                                payload,
                            },
                        ),
                    );
                }
                output.write_all(&node.0)?;
            }
            output.flush()?;
            output.get_ref().sync_data()?;
        }
        Ok(level_paths.clone())
    })();
    if result.is_err() {
        let _ = remove_disk_tree_levels(&level_paths);
    }
    result
}

#[cfg(feature = "std")]
fn remove_disk_tree_levels(level_paths: &[PathBuf]) -> Result<(), DiskCrossDomainError> {
    for path in level_paths {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(feature = "std")]
impl Drop for DiskCrossDomainTree {
    fn drop(&mut self) {
        let _ = cleanup_disk_tree(&self.directory, Some(&self.layout.identity().into_bytes()));
    }
}

#[cfg(feature = "std")]
fn disk_tree_directory_name(nonce: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::from("blpq-cross-domain-");
    for byte in nonce {
        name.push(DIGITS[usize::from(byte >> 4)] as char);
        name.push(DIGITS[usize::from(byte & 15)] as char);
    }
    name
}

#[cfg(feature = "std")]
fn read_cross_domain_hash(reader: &mut impl Read) -> Result<CrossDomainHash, std::io::Error> {
    let mut encoded = [0_u8; DIGEST_LENGTH];
    reader.read_exact(&mut encoded)?;
    Ok(CrossDomainHash(encoded))
}

#[cfg(feature = "std")]
fn read_hash_at(path: &Path, index: usize) -> Result<CrossDomainHash, DiskCrossDomainError> {
    read_hash_at_reader(&mut File::open(path)?, index)
}

#[cfg(feature = "std")]
fn read_hash_at_reader(
    file: &mut File,
    index: usize,
) -> Result<CrossDomainHash, DiskCrossDomainError> {
    let offset = u64::try_from(index)
        .ok()
        .and_then(|value| value.checked_mul(DIGEST_LENGTH as u64))
        .ok_or(DiskCrossDomainError::Overflow)?;
    file.seek(SeekFrom::Start(offset))?;
    Ok(read_cross_domain_hash(file)?)
}

#[cfg(feature = "std")]
fn cleanup_disk_tree(
    directory: &Path,
    expected_layout: Option<&[u8; 64]>,
) -> Result<(), DiskCrossDomainError> {
    let marker_path = directory.join("OWNER");
    let mut marker = [0_u8; 72];
    File::open(&marker_path)?.read_exact(&mut marker)?;
    if &marker[..8] != b"BLPQCDT1"
        || expected_layout.is_some_and(|expected| &marker[8..] != expected)
    {
        return Err(DiskCrossDomainError::Ownership);
    }
    fs::remove_dir_all(directory)?;
    Ok(())
}

/// Moves the least-significant circle-FFT bit to the most-significant place.
pub fn transpose_circle_fft_index(index: usize, log_size: u8) -> Result<usize, CrossDomainError> {
    validate_index(index, log_size)?;
    Ok((index >> 1) | ((index & 1) << (log_size - 1)))
}

/// Inverts [`transpose_circle_fft_index`].
pub fn inverse_transpose_circle_fft_index(
    index: usize,
    log_size: u8,
) -> Result<usize, CrossDomainError> {
    validate_index(index, log_size)?;
    let high = (index >> (log_size - 1)) & 1;
    let lower_mask = (1_usize << (log_size - 1)) - 1;
    Ok(((index & lower_mask) << 1) | high)
}

/// Applies one circle-squaring projection to a bit-reverse FFT index.
pub fn project_circle_fft_index(index: usize, log_size: u8) -> Result<usize, CrossDomainError> {
    if log_size < 2 {
        return Err(CrossDomainError::ProjectionDomainTooSmall { log_size });
    }
    let transposed = transpose_circle_fft_index(index, log_size)?;
    inverse_transpose_circle_fft_index(transposed >> 1, log_size - 1)
}

/// Strict cross-domain construction or proof-validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CrossDomainError {
    /// The native BindingRootV2 substrate rejected a tree or proof.
    Binding(BindingRootV2Error),
    /// A native cross-domain row packet was not byte-exact for its layout.
    BindingRowEncoding,
    /// A domain log size is outside `1..=30`.
    DomainLogSizeInvalid { log_size: u8 },
    /// A projection requires a domain of size at least four.
    ProjectionDomainTooSmall { log_size: u8 },
    /// A domain declared no columns.
    ZeroColumns,
    /// The layout commitment descriptor identity was zero.
    ZeroCommitmentId,
    /// The layout contained no domains.
    NoDomains,
    /// No independent FRI batch-mask domains were supplied.
    NoFriBatchMasks,
    /// A FRI batch mask had other than one column.
    FriBatchMaskColumnCountMismatch,
    /// Two FRI batch masks used the same circle domain.
    FriBatchMaskDomainDuplicate,
    /// Domain entries were duplicated or out of order.
    DomainsNotStrictlyIncreasing,
    /// A platform length calculation overflowed.
    LengthOverflow,
    /// A row count did not equal the declared power-of-two domain size.
    RowCountMismatch {
        log_size: u8,
        expected: usize,
        actual: usize,
    },
    /// A row byte length did not match its exact field/column shape.
    RowLengthMismatch {
        log_size: u8,
        row_index: usize,
        expected: usize,
        actual: usize,
    },
    /// One four-byte M31 scalar was not canonical.
    NonCanonicalM31 {
        row_index: usize,
        column_index: usize,
        value: u32,
    },
    /// One 64-byte Fp16 scalar was not canonical.
    NonCanonicalFp16 {
        row_index: usize,
        column_index: usize,
    },
    /// A supplied index was outside its declared domain.
    IndexOutOfBounds { index: usize, domain_size: usize },
    /// The prover supplied the wrong number of domain batches.
    BatchCountMismatch { expected: usize, actual: usize },
    /// One batch did not match its layout entry.
    BatchSpecMismatch { log_size: u8 },
    /// A proof query was outside the largest domain.
    QueryIndexOutOfBounds { index: usize, domain_size: usize },
    /// The authentication path length was not the largest domain log size.
    SiblingCountMismatch { expected: usize, actual: usize },
    /// The proof supplied the wrong number of domain openings.
    OpeningCountMismatch { expected: usize, actual: usize },
    /// An opening did not match the expected layout entry.
    OpeningSpecMismatch { log_size: u8 },
    /// An opening did not follow the projection-consistent query path.
    OpeningIndexMismatch {
        log_size: u8,
        expected: usize,
        actual: usize,
    },
    /// An expected domain opening was absent.
    MissingOpening { log_size: u8 },
}

impl From<BindingRootV2Error> for CrossDomainError {
    fn from(value: BindingRootV2Error) -> Self {
        Self::Binding(value)
    }
}

impl fmt::Display for CrossDomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "cross-domain PCS error: {self:?}")
    }
}

impl core::error::Error for CrossDomainError {}

fn validate_index(index: usize, log_size: u8) -> Result<(), CrossDomainError> {
    if log_size == 0 || log_size > MAX_DOMAIN_LOG_SIZE {
        return Err(CrossDomainError::DomainLogSizeInvalid { log_size });
    }
    let domain_size = 1_usize
        .checked_shl(u32::from(log_size))
        .ok_or(CrossDomainError::LengthOverflow)?;
    if index >= domain_size {
        return Err(CrossDomainError::IndexOutOfBounds { index, domain_size });
    }
    Ok(())
}

fn validate_row(spec: DomainSpec, row: &[u8], row_index: usize) -> Result<(), CrossDomainError> {
    match spec.field {
        EvaluationField::M31 => {
            for (column_index, chunk) in row.chunks_exact(4).enumerate() {
                let value = u32::from_be_bytes(chunk.try_into().expect("four-byte chunk"));
                if value >= M31_MODULUS {
                    return Err(CrossDomainError::NonCanonicalM31 {
                        row_index,
                        column_index,
                        value,
                    });
                }
            }
        }
        EvaluationField::Fp16 => {
            for (column_index, chunk) in row.chunks_exact(64).enumerate() {
                if Fp16::decode(chunk).is_err() {
                    return Err(CrossDomainError::NonCanonicalFp16 {
                        row_index,
                        column_index,
                    });
                }
            }
        }
    }
    Ok(())
}

fn hash_layout(
    stage: CommitmentStage,
    commitment_id: &[u8; DIGEST_LENGTH],
    specs: &[DomainSpec],
) -> [u8; DIGEST_LENGTH] {
    let mut hash = begin_hash(CROSS_DOMAIN_LAYOUT_DOMAIN);
    hash.update((stage as u16).to_be_bytes());
    hash.update(commitment_id);
    hash.update((specs.len() as u32).to_be_bytes());
    for spec in specs {
        hash.update([spec.log_size]);
        hash.update((spec.field as u16).to_be_bytes());
        hash.update(spec.column_count.to_be_bytes());
    }
    hash.finalize().into()
}

fn hash_evaluation(layout: &CrossDomainLayout, opening: &DomainOpening) -> [u8; DIGEST_LENGTH] {
    let mut hash = begin_hash(CROSS_DOMAIN_EVALUATION_DOMAIN);
    hash.update(layout.identity.0);
    hash.update([opening.spec.log_size]);
    hash.update((opening.spec.field as u16).to_be_bytes());
    hash.update(opening.spec.column_count.to_be_bytes());
    hash.update((opening.fft_index as u64).to_be_bytes());
    hash.update((opening.payload.len() as u64).to_be_bytes());
    hash.update(&opening.payload);
    hash.finalize().into()
}

fn empty_cross_domain_hash() -> CrossDomainHash {
    CrossDomainHash(begin_hash(CROSS_DOMAIN_CHILDREN_DOMAIN).finalize().into())
}

fn hash_children(left: CrossDomainHash, right: CrossDomainHash) -> CrossDomainHash {
    let mut hash = begin_hash(CROSS_DOMAIN_CHILDREN_DOMAIN);
    hash.update(left.0);
    hash.update(right.0);
    CrossDomainHash(hash.finalize().into())
}

fn hash_insert(
    log_size: u8,
    transposed_index: usize,
    children: CrossDomainHash,
    evaluation: [u8; DIGEST_LENGTH],
) -> CrossDomainHash {
    let mut hash = begin_hash(CROSS_DOMAIN_INSERT_DOMAIN);
    hash.update([log_size]);
    hash.update((transposed_index as u64).to_be_bytes());
    hash.update(children.0);
    hash.update(evaluation);
    CrossDomainHash(hash.finalize().into())
}

fn hash_root(layout: &CrossDomainLayout, top: CrossDomainHash) -> CrossDomainRoot {
    let mut hash = begin_hash(CROSS_DOMAIN_ROOT_DOMAIN);
    hash.update(layout.identity.0);
    hash.update([layout.maximum_log_size()]);
    hash.update(top.0);
    CrossDomainRoot(hash.finalize().into())
}

fn begin_hash(domain: u16) -> Sha3_512 {
    let mut hash = Sha3_512::new();
    hash.update(CROSS_DOMAIN_MAGIC);
    hash.update(CROSS_DOMAIN_VERSION.to_be_bytes());
    hash.update(domain.to_be_bytes());
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding_root_v2::{BindingRoleV2, BindingRootV2Error};

    fn fp16(value: u32) -> Fp16 {
        Fp16::from_coefficients([value, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap()
    }

    #[test]
    fn native_v2_rows_bind_the_complete_128_byte_descriptor() {
        let spec = DomainSpec::new(2, EvaluationField::M31, 1).unwrap();
        let descriptor = BindingDigestV2::hash(BindingRoleV2::Payload, b"native-layout").unwrap();
        let layout =
            CrossDomainLayout::new_binding_v2(CommitmentStage::MainTrace, descriptor, vec![spec])
                .unwrap();
        let batch = DomainEvaluationBatch::new(spec, m31_rows(2, 1, 7)).unwrap();
        let tree = BindingCrossDomainTreeV2::build(layout.clone(), vec![batch]).unwrap();
        let proof = tree.proof(&[1]).unwrap();
        proof.verify(&layout, &tree.root()).unwrap();

        let changed_descriptor =
            BindingDigestV2::hash(BindingRoleV2::Payload, b"changed-layout").unwrap();
        let changed_layout = CrossDomainLayout::new_binding_v2(
            CommitmentStage::MainTrace,
            changed_descriptor,
            vec![spec],
        )
        .unwrap();
        assert!(matches!(
            proof.verify(&changed_layout, &tree.root()),
            Err(CrossDomainError::Binding(BindingRootV2Error::RootMismatch))
        ));
        assert_eq!(
            binding_cross_domain_row_v2_payload_len(&layout).unwrap(),
            176
        );
    }

    fn m31_rows(log_size: u8, columns: u32, offset: u32) -> Vec<Vec<u8>> {
        (0..1_usize << log_size)
            .map(|row| {
                (0..columns)
                    .flat_map(|column| {
                        (offset + u32::try_from(row).unwrap() * 17 + column).to_be_bytes()
                    })
                    .collect()
            })
            .collect()
    }

    #[cfg(feature = "std")]
    fn write_m31_columns(
        parent: &Path,
        prefix: &str,
        rows: &[Vec<u8>],
        columns: usize,
    ) -> Vec<PathBuf> {
        (0..columns)
            .map(|column| {
                let path = parent.join(format!("{prefix}-{column}.m31"));
                let bytes = rows
                    .iter()
                    .flat_map(|row| row[column * 4..column * 4 + 4].iter().copied())
                    .collect::<Vec<_>>();
                fs::write(&path, bytes).unwrap();
                path
            })
            .collect()
    }

    fn fixture() -> CrossDomainTree {
        let small = DomainSpec::new(2, EvaluationField::M31, 2).unwrap();
        let large = DomainSpec::new(4, EvaluationField::M31, 1).unwrap();
        let layout =
            CrossDomainLayout::new(CommitmentStage::MainTrace, [0x5a; 64], vec![small, large])
                .unwrap();
        CrossDomainTree::build(
            layout,
            vec![
                DomainEvaluationBatch::new(small, m31_rows(2, 2, 100)).unwrap(),
                DomainEvaluationBatch::new(large, m31_rows(4, 1, 200)).unwrap(),
            ],
        )
        .unwrap()
    }

    #[test]
    fn transposition_is_bijective_and_projection_consistent() {
        for log_size in 2..=12 {
            for index in 0..1_usize << log_size {
                let transposed = transpose_circle_fft_index(index, log_size).unwrap();
                assert_eq!(
                    inverse_transpose_circle_fft_index(transposed, log_size).unwrap(),
                    index
                );
                let projected = project_circle_fft_index(index, log_size).unwrap();
                assert_eq!(
                    transpose_circle_fft_index(projected, log_size - 1).unwrap(),
                    transposed >> 1
                );
            }
        }
    }

    #[test]
    fn every_query_uses_one_shared_path_and_verifies() {
        let tree = fixture();
        assert_eq!(
            tree.layout().identity().into_bytes(),
            decode_hex(
                "02ce24cd2bac1d5585735c48379a65d3df5fa9353f627f34b82ef0a659b374b0c0ea42baacaf4a818e6a70bc75073f89b49d6f1af4e979cd9c1b43e1ff870a10"
            )
        );
        assert_eq!(
            tree.root().into_bytes(),
            decode_hex(
                "051b8ab28853ab0b09f7fc2ac0815df7c2dd9236ffdf10f84b2ace3dc0f691ada2aa81b277039e7d4b5ff5009961281b31fecebd115942a58c282178dbd7c2f0"
            )
        );
        for query in 0..16 {
            let proof = tree.proof(query).unwrap();
            assert_eq!(proof.siblings().len(), 4);
            assert_eq!(proof.openings().len(), 2);
            assert!(proof.verify(tree.layout(), &tree.root()).unwrap());
            assert_eq!(proof.openings()[1].fft_index, query);
            assert_eq!(
                proof.openings()[0].fft_index,
                project_circle_fft_index(project_circle_fft_index(query, 4).unwrap(), 3).unwrap()
            );
        }
        let proof = tree.proof(11).unwrap();
        assert_eq!(proof.openings()[0].fft_index, 3);
        let expected_siblings = [
            "e58d0664b6cbd12ff3a8cdbe470063f20469372a1fb86744d9c0780ba64f9856c2311e3ee0a9176f167dc02fe7c6d5f82609b7ddf5ffdc2c682bfd1b7e1b62c6",
            "fd78e3b6e66d134e46469ee9cb6e2677afa8bee7fd6ab3ec121a81e28ac1bf7553f1322f2c21bf7cec6a8bc9e7480160e5e0e89a535ce7dbe258ee7671fab24a",
            "d1dcff84a94644be1a7a103a6921db1d84f1ffedae3177faaea03503e9825ce1f6ecfafa0712b1b090ed1f05e4e2741c87545891e68e26fecc3d1dbd38df1df6",
            "89d265785cd6599c6d7d69c14aa3c7fec379775a85c805331351fee4b61e036c80667162f26b860876dd7bd515b7930b7562712eb982b6c47155a746260a8df6",
        ];
        assert_eq!(
            proof.siblings(),
            expected_siblings.map(decode_hex).as_slice()
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn disk_tree_is_byte_exact_and_cleans_only_owned_levels() {
        let memory = fixture();
        let parent = std::env::temp_dir().join(format!(
            "blpq-disk-cross-domain-test-{}",
            std::process::id()
        ));
        fs::create_dir(&parent).unwrap();
        let small_path = parent.join("small.rows");
        let large_path = parent.join("large.rows");
        fs::write(&small_path, m31_rows(2, 2, 100).concat()).unwrap();
        fs::write(&large_path, m31_rows(4, 1, 200).concat()).unwrap();
        let specs = memory.layout().specs();
        let disk = DiskCrossDomainTree::build(
            memory.layout().clone(),
            vec![
                DiskDomainEvaluationBatch::new(specs[0], small_path.clone()).unwrap(),
                DiskDomainEvaluationBatch::new(specs[1], large_path.clone()).unwrap(),
            ],
            &parent,
            &[0x83; 32],
        )
        .unwrap();
        assert_eq!(disk.root(), memory.root());
        for query in 0..16 {
            let observed = disk.proof(query).unwrap();
            assert_eq!(observed, memory.proof(query).unwrap());
            assert!(observed.verify(disk.layout(), &disk.root()).unwrap());
        }
        drop(disk);
        assert!(small_path.is_file());
        assert!(large_path.is_file());
        fs::remove_file(small_path).unwrap();
        fs::remove_file(large_path).unwrap();
        fs::remove_dir(parent).unwrap();
    }

    #[cfg(feature = "std")]
    #[test]
    fn disk_tree_discards_transient_rows_and_opens_from_canonical_columns() {
        let memory = fixture();
        let parent = std::env::temp_dir().join(format!(
            "blpq-disk-cross-domain-columns-test-{}",
            std::process::id()
        ));
        fs::create_dir(&parent).unwrap();
        let small_rows = m31_rows(2, 2, 100);
        let large_rows = m31_rows(4, 1, 200);
        let small_path = parent.join("small.rows");
        let large_path = parent.join("large.rows");
        fs::write(&small_path, small_rows.concat()).unwrap();
        fs::write(&large_path, large_rows.concat()).unwrap();
        let small_columns = write_m31_columns(&parent, "small", &small_rows, 2);
        let large_columns = write_m31_columns(&parent, "large", &large_rows, 1);
        let specs = memory.layout().specs();
        let disk = DiskCrossDomainTree::build(
            memory.layout().clone(),
            vec![
                DiskDomainEvaluationBatch::new_with_columns(
                    specs[0],
                    small_path.clone(),
                    small_columns.clone(),
                )
                .unwrap(),
                DiskDomainEvaluationBatch::new_with_columns(
                    specs[1],
                    large_path.clone(),
                    large_columns.clone(),
                )
                .unwrap(),
            ],
            &parent,
            &[0x84; 32],
        )
        .unwrap();
        assert!(!small_path.exists());
        assert!(!large_path.exists());
        assert_eq!(disk.root(), memory.root());
        for query in 0..16 {
            assert_eq!(disk.proof(query).unwrap(), memory.proof(query).unwrap());
        }
        drop(disk);
        for path in small_columns.into_iter().chain(large_columns) {
            fs::remove_file(path).unwrap();
        }
        fs::remove_dir(parent).unwrap();
    }

    #[cfg(feature = "std")]
    #[test]
    fn disk_binding_v2_root_and_multiproof_match_native_memory_tree() {
        let legacy = fixture();
        let parent =
            std::env::temp_dir().join(format!("blpq-disk-binding-v2-test-{}", std::process::id()));
        fs::create_dir(&parent).unwrap();
        let small_rows = m31_rows(2, 2, 100);
        let large_rows = m31_rows(4, 1, 200);
        let small_columns = write_m31_columns(&parent, "small", &small_rows, 2);
        let large_columns = write_m31_columns(&parent, "large", &large_rows, 1);
        let specs = legacy.layout().specs();
        let disk = DiskCrossDomainTree::build_with_level_budget(
            legacy.layout().clone(),
            vec![
                DiskDomainEvaluationBatch::new_from_columns(specs[0], small_columns.clone())
                    .unwrap(),
                DiskDomainEvaluationBatch::new_from_columns(specs[1], large_columns.clone())
                    .unwrap(),
            ],
            &parent,
            &[0x86; 32],
            0,
        )
        .unwrap();
        let descriptor =
            BindingDigestV2::hash(BindingRoleV2::Payload, b"disk-native-layout").unwrap();
        let native_layout = CrossDomainLayout::new_binding_v2(
            CommitmentStage::MainTrace,
            descriptor,
            specs.to_vec(),
        )
        .unwrap();
        let memory = BindingCrossDomainTreeV2::build(
            native_layout.clone(),
            vec![
                DomainEvaluationBatch::new(specs[0], small_rows).unwrap(),
                DomainEvaluationBatch::new(specs[1], large_rows).unwrap(),
            ],
        )
        .unwrap();
        let native_disk = disk.binding_v2_tree(native_layout.clone()).unwrap();
        assert_eq!(native_disk.root(), memory.root());
        assert!(!disk.directory.join("binding-v2-even-leaves.tmp").exists());
        let selected = [0, 3, 7, 8, 15];
        let observed = native_disk.proof(&selected).unwrap();
        assert_eq!(observed, memory.proof(&selected).unwrap());
        observed
            .verify(&native_layout, &native_disk.root())
            .unwrap();
        assert!(!disk.directory.join("binding-v2-even-leaves.tmp").exists());
        drop(native_disk);
        drop(disk);
        for path in small_columns.into_iter().chain(large_columns) {
            fs::remove_file(path).unwrap();
        }
        fs::remove_dir(parent).unwrap();
    }

    #[cfg(feature = "std")]
    #[test]
    fn disk_tree_recompute_plan_is_root_and_opening_exact() {
        let memory = fixture();
        let parent = std::env::temp_dir().join(format!(
            "blpq-disk-cross-domain-recompute-test-{}",
            std::process::id()
        ));
        fs::create_dir(&parent).unwrap();
        let small_rows = m31_rows(2, 2, 100);
        let large_rows = m31_rows(4, 1, 200);
        let small_columns = write_m31_columns(&parent, "small", &small_rows, 2);
        let large_columns = write_m31_columns(&parent, "large", &large_rows, 1);
        let specs = memory.layout().specs();
        let disk = DiskCrossDomainTree::build_with_level_budget(
            memory.layout().clone(),
            vec![
                DiskDomainEvaluationBatch::new_from_columns(specs[0], small_columns.clone())
                    .unwrap(),
                DiskDomainEvaluationBatch::new_from_columns(specs[1], large_columns.clone())
                    .unwrap(),
            ],
            &parent,
            &[0x85; 32],
            0,
        )
        .unwrap();
        assert_eq!(disk.level_plan().policy, DiskTreeLevelPolicy::Recompute);
        assert_eq!(disk.level_plan().level_bytes, 31 * 64);
        assert!(disk.level_paths.iter().all(|path| !path.exists()));
        assert_eq!(disk.root(), memory.root());
        let queries = [11, 0, 11, 15];
        let proofs = disk.proofs(&queries).unwrap();
        assert_eq!(proofs.len(), queries.len());
        for (proof, query) in proofs.iter().zip(queries) {
            assert_eq!(proof, &memory.proof(query).unwrap());
            assert!(proof.verify(disk.layout(), &disk.root()).unwrap());
        }
        assert!(disk.level_paths.iter().all(|path| !path.exists()));
        drop(disk);
        for path in small_columns.into_iter().chain(large_columns) {
            fs::remove_file(path).unwrap();
        }
        fs::remove_dir(parent).unwrap();
    }

    #[test]
    fn payload_sibling_index_and_layout_tampering_fail_closed() {
        let tree = fixture();
        let proof = tree.proof(11).unwrap();

        let mut forged = proof.clone();
        forged.openings[0].payload[0] ^= 1;
        assert!(!forged.verify(tree.layout(), &tree.root()).unwrap());

        let mut forged = proof.clone();
        forged.siblings[1][0] ^= 1;
        assert!(!forged.verify(tree.layout(), &tree.root()).unwrap());

        let mut forged = proof.clone();
        forged.openings[0].fft_index ^= 1;
        assert!(matches!(
            forged.verify(tree.layout(), &tree.root()),
            Err(CrossDomainError::OpeningIndexMismatch { .. })
        ));

        let altered_layout = CrossDomainLayout::new(
            CommitmentStage::InteractionTrace,
            [0x5a; 64],
            tree.layout.specs.clone(),
        )
        .unwrap();
        assert!(!proof.verify(&altered_layout, &tree.root()).unwrap());
    }

    #[test]
    fn malformed_shapes_and_noncanonical_scalars_are_rejected() {
        let spec = DomainSpec::new(2, EvaluationField::M31, 1).unwrap();
        assert!(matches!(
            DomainEvaluationBatch::new(spec, vec![vec![0; 4]; 3]),
            Err(CrossDomainError::RowCountMismatch { .. })
        ));
        assert!(matches!(
            DomainEvaluationBatch::new(spec, vec![vec![0; 3]; 4]),
            Err(CrossDomainError::RowLengthMismatch { .. })
        ));
        let bad = M31_MODULUS.to_be_bytes().to_vec();
        assert!(matches!(
            DomainEvaluationBatch::new(spec, vec![bad; 4]),
            Err(CrossDomainError::NonCanonicalM31 { .. })
        ));
        assert!(matches!(
            CrossDomainLayout::new(CommitmentStage::MainTrace, [1; 64], vec![spec, spec]),
            Err(CrossDomainError::DomainsNotStrictlyIncreasing)
        ));
    }

    #[test]
    fn fri_batch_masks_have_a_typed_shared_commitment() {
        let large =
            FriDomainBatch::new(4, (0..16).map(|row| vec![fp16(19 + row)]).collect()).unwrap();
        let small =
            FriDomainBatch::new(3, (0..8).map(|row| vec![fp16(23 + row)]).collect()).unwrap();
        let tree = CrossDomainTree::build_fri_batch_mask_tree([0x6b; 64], &[large, small]).unwrap();
        assert_eq!(tree.layout().stage(), CommitmentStage::FriBatchMask);
        assert_eq!(
            tree.root().into_bytes(),
            decode_hex(
                "81c47e0626132b05d1f9095e9f56fa90b37356fd7d8ad4846d644bfe4a3ec82594e4d3b139fc9490981ca6507e7967bb6688a8bd333fd06fd67ebef76bdaa38e"
            )
        );
        for query in 0..16 {
            let proof = tree.proof(query).unwrap();
            assert!(proof.verify(tree.layout(), &tree.root()).unwrap());
        }
    }

    #[test]
    fn malformed_fri_batch_mask_sets_fail_closed() {
        assert_eq!(
            CrossDomainTree::build_fri_batch_mask_tree([1; 64], &[]),
            Err(CrossDomainError::NoFriBatchMasks)
        );
        let valid = FriDomainBatch::new(3, vec![vec![fp16(1)]; 8]).unwrap();
        let wide = FriDomainBatch::new(3, vec![vec![fp16(1), fp16(2)]; 8]).unwrap();
        assert_eq!(
            CrossDomainTree::build_fri_batch_mask_tree([1; 64], &[wide]),
            Err(CrossDomainError::FriBatchMaskColumnCountMismatch)
        );
        assert_eq!(
            CrossDomainTree::build_fri_batch_mask_tree([1; 64], &[valid.clone(), valid]),
            Err(CrossDomainError::FriBatchMaskDomainDuplicate)
        );
    }

    fn decode_hex(value: &str) -> [u8; 64] {
        assert_eq!(value.len(), 128);
        let bytes = value.as_bytes();
        let mut decoded = [0_u8; 64];
        for (index, output) in decoded.iter_mut().enumerate() {
            *output = (nibble(bytes[index * 2]) << 4) | nibble(bytes[index * 2 + 1]);
        }
        decoded
    }

    const fn nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid test hex"),
        }
    }
}
