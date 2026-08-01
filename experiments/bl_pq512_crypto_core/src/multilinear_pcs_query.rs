//! Canonical fixed-shape query openings for the selected multilinear PCS.
//!
//! Value and leaf positions are verifier-derived from the ordered public-coin
//! queries. Proof bytes carry neither tree coordinates nor alternate layouts.

#[cfg(feature = "parallel")]
use crate::mlpcs_gpu_worker::{MlpcsGpuWorker, MlpcsGpuWorkerError};
#[cfg(feature = "parallel")]
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use sha3::{Digest, Sha3_512};
#[cfg(feature = "parallel")]
use std::{
    ffi::OsString,
    fs::File,
    io::{BufReader, Read},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

use crate::field::{FP16_ENCODED_LENGTH, Fp16};
use crate::merkle::RootHash;
#[cfg(feature = "parallel")]
use crate::merkle::{ChildHash, LeafHash, NodeHash, hash_leaf, hash_node, hash_root};
#[cfg(feature = "parallel")]
use crate::merkle_multiproof::build_bounded_canonical_multiproof_from_leaf_hashes_parallel;
use crate::merkle_multiproof::{
    CanonicalMerkleMultiProof, CanonicalMerkleMultiProofError, CanonicalMerkleOpening,
    build_recomputed_canonical_multiproof, canonical_frontier_positions,
};
use crate::multilinear_pcs::{
    MLPCS_AUXILIARY_INJECTION_FOLD, MLPCS_AUXILIARY_LDE_LOG_SIZE, MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE,
    MLPCS_LDE_LOG_SIZE, MLPCS_UNIQUE_QUERY_COUNT, derive_two_adic_root,
    verify_multiplicative_batch_fold,
};

pub const MLPCS_VALUES_PER_LEAF: usize = 16;
pub const MLPCS_LEAF_PAYLOAD_BYTES: usize = MLPCS_VALUES_PER_LEAF * FP16_ENCODED_LENGTH;
pub const MLPCS_FOLD_ROUNDS: usize = MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE as usize;
pub const MLPCS_FOLD_QUERY_MAGIC: &[u8; 8] = b"BLPQMFQ1";
pub const MLPCS_FOLD_QUERY_VERSION: u16 = 1;
pub const MLPCS_BATCHED_FOLD_QUERY_MAGIC: &[u8; 8] = b"BLPQBFQ1";
pub const MLPCS_BATCHED_FOLD_QUERY_VERSION: u16 = 1;
const MLPCS_QUERY_DERIVATION_DOMAIN: &[u8] = b"BL/PQ512/MLPCS-QUERY-POSITION/v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultilinearPcsLeafOpening {
    pub leaf_index: usize,
    pub values: [Fp16; MLPCS_VALUES_PER_LEAF],
}

impl MultilinearPcsLeafOpening {
    pub fn payload(&self) -> [u8; MLPCS_LEAF_PAYLOAD_BYTES] {
        let mut payload = [0_u8; MLPCS_LEAF_PAYLOAD_BYTES];
        for (index, value) in self.values.iter().copied().enumerate() {
            let start = index * FP16_ENCODED_LENGTH;
            payload[start..start + FP16_ENCODED_LENGTH].copy_from_slice(&value.encode());
        }
        payload
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultilinearPcsLayerOpening {
    pub leaves: Vec<MultilinearPcsLeafOpening>,
    pub multiproof: CanonicalMerkleMultiProof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultilinearPcsFoldQueryProof {
    /// Main roots for the `2^25` through `2^4` committed layers.
    pub main_layer_roots: Vec<RootHash>,
    pub auxiliary_root: RootHash,
    pub main_layer_openings: Vec<MultilinearPcsLayerOpening>,
    pub auxiliary_opening: MultilinearPcsLayerOpening,
    /// Uncommitted terminal `2^3` layer, required to be constant.
    pub final_values: Vec<Fp16>,
}

/// Two separately committed hidden-state boundaries sharing one FRI fold.
///
/// The input and output roots are fixed before `main_mixing_challenge` is
/// released. Their authenticated initial values are then mixed, and the
/// remaining 21 committed layers use the existing fold/query proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchedMultilinearPcsFoldQueryProof {
    pub input_root: RootHash,
    pub output_root: RootHash,
    pub input_initial_opening: MultilinearPcsLayerOpening,
    pub output_initial_opening: MultilinearPcsLayerOpening,
    /// Shared committed layers for sizes `2^24` through `2^4`.
    pub shared: MultilinearPcsFoldQueryProof,
}

pub struct SelectedFoldQueryExpectations<'a> {
    pub main_root: RootHash,
    pub auxiliary_root: RootHash,
    pub fold_challenges: &'a [Fp16],
    pub auxiliary_mixing_challenge: Fp16,
    pub main_terminal: Fp16,
    pub auxiliary_terminal: Fp16,
    pub queries: &'a [usize],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MultilinearPcsQueryError {
    Shape,
    QueryCount { expected: usize, actual: usize },
    QueryOutOfBounds,
    LeafOrder,
    PayloadLength { expected: usize, actual: usize },
    MissingValue,
    Authentication,
    RootCount,
    LayerCount,
    FoldMismatch,
    FinalLayer,
    Sequence,
    EncodingLength,
    Truncated,
    NonZeroPadding,
    TrailingBytes,
    Magic,
    Version,
    Merkle(CanonicalMerkleMultiProofError),
}

struct Reader<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(encoded: &'a [u8]) -> Self {
        Self { encoded, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], MultilinearPcsQueryError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(MultilinearPcsQueryError::Truncated)?;
        let value = self
            .encoded
            .get(self.offset..end)
            .ok_or(MultilinearPcsQueryError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn root(&mut self) -> Result<RootHash, MultilinearPcsQueryError> {
        let bytes: [u8; 64] = self
            .take(64)?
            .try_into()
            .map_err(|_| MultilinearPcsQueryError::Truncated)?;
        if !bytes.iter().any(|byte| *byte != 0) {
            return Err(MultilinearPcsQueryError::Authentication);
        }
        Ok(RootHash::from_bytes(bytes))
    }

    fn zero_padding(&mut self, length: usize) -> Result<(), MultilinearPcsQueryError> {
        if self.take(length)?.iter().any(|byte| *byte != 0) {
            return Err(MultilinearPcsQueryError::NonZeroPadding);
        }
        Ok(())
    }
}

impl From<CanonicalMerkleMultiProofError> for MultilinearPcsQueryError {
    fn from(value: CanonicalMerkleMultiProofError) -> Self {
        Self::Merkle(value)
    }
}

impl fmt::Display for MultilinearPcsQueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "BL-PQ512 multilinear PCS query error: {self:?}")
    }
}

impl core::error::Error for MultilinearPcsQueryError {}

fn validate_value_count(value_count: usize) -> Result<usize, MultilinearPcsQueryError> {
    if value_count < MLPCS_VALUES_PER_LEAF
        || !value_count.is_power_of_two()
        || !value_count.is_multiple_of(MLPCS_VALUES_PER_LEAF)
    {
        return Err(MultilinearPcsQueryError::Shape);
    }
    Ok(value_count / MLPCS_VALUES_PER_LEAF)
}

fn selected_leaf_indices(
    value_count: usize,
    expected_value_indices: &[usize],
) -> Result<Vec<usize>, MultilinearPcsQueryError> {
    validate_value_count(value_count)?;
    if expected_value_indices.is_empty() {
        return Err(MultilinearPcsQueryError::Shape);
    }
    if expected_value_indices
        .iter()
        .any(|index| *index >= value_count)
    {
        return Err(MultilinearPcsQueryError::QueryOutOfBounds);
    }
    let mut leaves = expected_value_indices
        .iter()
        .map(|index| index / MLPCS_VALUES_PER_LEAF)
        .collect::<Vec<_>>();
    leaves.sort_unstable();
    leaves.dedup();
    Ok(leaves)
}

fn decode_leaf(
    leaf_index: usize,
    payload: &[u8],
) -> Result<MultilinearPcsLeafOpening, MultilinearPcsQueryError> {
    if payload.len() != MLPCS_LEAF_PAYLOAD_BYTES {
        return Err(MultilinearPcsQueryError::PayloadLength {
            expected: MLPCS_LEAF_PAYLOAD_BYTES,
            actual: payload.len(),
        });
    }
    let mut values = [Fp16::ZERO; MLPCS_VALUES_PER_LEAF];
    for (value, encoded) in values
        .iter_mut()
        .zip(payload.chunks_exact(FP16_ENCODED_LENGTH))
    {
        *value = Fp16::decode(encoded).map_err(|_| MultilinearPcsQueryError::Shape)?;
    }
    Ok(MultilinearPcsLeafOpening { leaf_index, values })
}

/// Build one layer proof in a single leaf-order pass with bounded retained state.
pub fn build_recomputed_layer_opening<I, P>(
    value_count: usize,
    payloads: I,
    expected_value_indices: &[usize],
) -> Result<(RootHash, MultilinearPcsLayerOpening), MultilinearPcsQueryError>
where
    I: IntoIterator<Item = P>,
    P: AsRef<[u8]>,
{
    let leaf_count = validate_value_count(value_count)?;
    let selected = selected_leaf_indices(value_count, expected_value_indices)?;
    let mut captured = Vec::with_capacity(selected.len());
    let mut invalid_payload = None;
    let inspected = payloads
        .into_iter()
        .enumerate()
        .map(|(leaf_index, payload)| {
            let encoded = payload.as_ref();
            if encoded.len() != MLPCS_LEAF_PAYLOAD_BYTES && invalid_payload.is_none() {
                invalid_payload = Some(encoded.len());
            }
            if selected.binary_search(&leaf_index).is_ok() {
                captured.push((leaf_index, encoded.to_vec()));
            }
            payload
        });
    let (root, multiproof) =
        build_recomputed_canonical_multiproof(leaf_count, inspected, &selected)?;
    if let Some(actual) = invalid_payload {
        return Err(MultilinearPcsQueryError::PayloadLength {
            expected: MLPCS_LEAF_PAYLOAD_BYTES,
            actual,
        });
    }
    if captured.len() != selected.len()
        || captured
            .iter()
            .map(|(index, _)| *index)
            .ne(selected.iter().copied())
    {
        return Err(MultilinearPcsQueryError::LeafOrder);
    }
    let leaves = captured
        .into_iter()
        .map(|(index, payload)| decode_leaf(index, &payload))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((root, MultilinearPcsLayerOpening { leaves, multiproof }))
}

/// Independently authenticate exactly the verifier-derived value positions.
pub fn verify_layer_opening(
    opening: &MultilinearPcsLayerOpening,
    expected_root: &RootHash,
    value_count: usize,
    expected_value_indices: &[usize],
) -> Result<(), MultilinearPcsQueryError> {
    let leaf_count = validate_value_count(value_count)?;
    let selected = selected_leaf_indices(value_count, expected_value_indices)?;
    if opening.leaves.len() != selected.len()
        || opening
            .leaves
            .iter()
            .map(|leaf| leaf.leaf_index)
            .ne(selected.iter().copied())
    {
        return Err(MultilinearPcsQueryError::LeafOrder);
    }
    let canonical = opening
        .leaves
        .iter()
        .map(|leaf| CanonicalMerkleOpening {
            index: leaf.leaf_index,
            payload: leaf.payload().to_vec(),
        })
        .collect::<Vec<_>>();
    if !opening
        .multiproof
        .verify(leaf_count, &canonical, expected_root)?
    {
        return Err(MultilinearPcsQueryError::Authentication);
    }
    Ok(())
}

/// Retrieve one authenticated value after [`verify_layer_opening`] succeeds.
pub fn opened_value(
    opening: &MultilinearPcsLayerOpening,
    value_index: usize,
) -> Result<Fp16, MultilinearPcsQueryError> {
    let leaf_index = value_index / MLPCS_VALUES_PER_LEAF;
    let leaf = opening
        .leaves
        .binary_search_by_key(&leaf_index, |leaf| leaf.leaf_index)
        .ok()
        .and_then(|position| opening.leaves.get(position))
        .ok_or(MultilinearPcsQueryError::MissingValue)?;
    Ok(leaf.values[value_index % MLPCS_VALUES_PER_LEAF])
}

fn validate_selected_queries(initial_queries: &[usize]) -> Result<(), MultilinearPcsQueryError> {
    if initial_queries.len() != MLPCS_UNIQUE_QUERY_COUNT {
        return Err(MultilinearPcsQueryError::QueryCount {
            expected: MLPCS_UNIQUE_QUERY_COUNT,
            actual: initial_queries.len(),
        });
    }
    let domain_size = 1_usize << MLPCS_LDE_LOG_SIZE;
    if initial_queries.iter().any(|query| *query >= domain_size) {
        return Err(MultilinearPcsQueryError::QueryOutOfBounds);
    }
    Ok(())
}

/// Deterministically expand a post-commitment authenticated coin into the
/// theorem-selected query multiset. Sampling with replacement is intentional.
pub fn derive_selected_query_positions(
    session_id: &[u8; 64],
    query_coin: Fp16,
) -> Result<Vec<usize>, MultilinearPcsQueryError> {
    if !session_id.iter().any(|byte| *byte != 0) {
        return Err(MultilinearPcsQueryError::Shape);
    }
    let domain_size = 1_usize << MLPCS_LDE_LOG_SIZE;
    let coin = query_coin.encode();
    Ok((0..MLPCS_UNIQUE_QUERY_COUNT)
        .map(|draw| {
            let digest = Sha3_512::digest(
                [
                    MLPCS_QUERY_DERIVATION_DOMAIN,
                    session_id,
                    coin.as_slice(),
                    &u32::try_from(draw)
                        .expect("selected query count fits u32")
                        .to_be_bytes(),
                ]
                .concat(),
            );
            let mut low = [0_u8; core::mem::size_of::<usize>()];
            let low_length = low.len();
            low.copy_from_slice(&digest[digest.len() - low_length..]);
            usize::from_be_bytes(low) & (domain_size - 1)
        })
        .collect())
}

fn layer_value_indices(
    initial_queries: &[usize],
    initial_log_size: u8,
    fold_rounds: usize,
) -> Result<Vec<Vec<usize>>, MultilinearPcsQueryError> {
    if fold_rounds == 0
        || fold_rounds >= usize::from(initial_log_size)
        || initial_log_size >= usize::BITS as u8
    {
        return Err(MultilinearPcsQueryError::Shape);
    }
    let domain_size = 1_usize << initial_log_size;
    if initial_queries.is_empty() || initial_queries.iter().any(|query| *query >= domain_size) {
        return Err(MultilinearPcsQueryError::QueryOutOfBounds);
    }
    let mut queries = initial_queries.to_vec();
    let mut layers = Vec::with_capacity(fold_rounds);
    let mut value_count = domain_size;
    for _ in 0..fold_rounds {
        let half = value_count / 2;
        let mut indices = Vec::with_capacity(2 * queries.len());
        for query in &mut queries {
            let base = *query % half;
            indices.push(base);
            indices.push(base + half);
            *query = base;
        }
        indices.sort_unstable();
        indices.dedup();
        layers.push(indices);
        value_count = half;
    }
    Ok(layers)
}

/// Exact pair positions opened in each of the 22 committed main layers.
pub fn selected_main_layer_value_indices(
    initial_queries: &[usize],
) -> Result<Vec<Vec<usize>>, MultilinearPcsQueryError> {
    validate_selected_queries(initial_queries)?;
    layer_value_indices(initial_queries, MLPCS_LDE_LOG_SIZE, MLPCS_FOLD_ROUNDS)
}

/// Auxiliary-codeword positions opened at the unique size-matching injection.
pub fn selected_auxiliary_value_indices(
    initial_queries: &[usize],
) -> Result<Vec<usize>, MultilinearPcsQueryError> {
    validate_selected_queries(initial_queries)?;
    let mut positions = initial_queries.to_vec();
    let mut value_count = 1_usize << MLPCS_LDE_LOG_SIZE;
    for _ in 0..MLPCS_AUXILIARY_INJECTION_FOLD {
        value_count /= 2;
        for position in &mut positions {
            *position %= value_count;
        }
    }
    if value_count != 1_usize << MLPCS_AUXILIARY_LDE_LOG_SIZE {
        return Err(MultilinearPcsQueryError::Shape);
    }
    positions.sort_unstable();
    positions.dedup();
    Ok(positions)
}

#[allow(dead_code)]
fn leaf_payloads(
    values: &[Fp16],
) -> impl ExactSizeIterator<Item = [u8; MLPCS_LEAF_PAYLOAD_BYTES]> + '_ {
    values.chunks_exact(MLPCS_VALUES_PER_LEAF).map(|leaf| {
        let mut payload = [0_u8; MLPCS_LEAF_PAYLOAD_BYTES];
        for (index, value) in leaf.iter().copied().enumerate() {
            let start = index * FP16_ENCODED_LENGTH;
            payload[start..start + FP16_ENCODED_LENGTH].copy_from_slice(&value.encode());
        }
        payload
    })
}

fn commit_layer_root_streaming(values: &[Fp16]) -> Result<RootHash, MultilinearPcsQueryError> {
    validate_value_count(values.len())?;
    #[cfg(feature = "parallel")]
    {
        let leaf_count = values.len() / MLPCS_VALUES_PER_LEAF;
        let workers = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
            .min(leaf_count);
        let mut current = vec![[0_u8; 64]; leaf_count];
        let chunk = leaf_count.div_ceil(workers);
        std::thread::scope(|scope| {
            for (chunk_ordinal, hashes) in current.chunks_mut(chunk).enumerate() {
                let first_leaf = chunk_ordinal * chunk;
                let chunk_values = &values[first_leaf * MLPCS_VALUES_PER_LEAF
                    ..(first_leaf + hashes.len()) * MLPCS_VALUES_PER_LEAF];
                scope.spawn(move || {
                    for (digest, leaf) in hashes
                        .iter_mut()
                        .zip(chunk_values.chunks_exact(MLPCS_VALUES_PER_LEAF))
                    {
                        let mut payload = [0_u8; MLPCS_LEAF_PAYLOAD_BYTES];
                        for (index, value) in leaf.iter().copied().enumerate() {
                            let start = index * FP16_ENCODED_LENGTH;
                            payload[start..start + FP16_ENCODED_LENGTH]
                                .copy_from_slice(&value.encode());
                        }
                        *digest = hash_leaf(&payload)
                            .expect("fixed selected PCS leaf payload is bounded")
                            .into_bytes();
                    }
                });
            }
        });
        let mut level = 0_usize;
        while current.len() > 1 {
            let parent_count = current.len() / 2;
            let mut parents = vec![[0_u8; 64]; parent_count];
            let parent_chunk = parent_count.div_ceil(workers.min(parent_count));
            std::thread::scope(|scope| {
                for (chunk_ordinal, output) in parents.chunks_mut(parent_chunk).enumerate() {
                    let first_parent = chunk_ordinal * parent_chunk;
                    let children = &current[2 * first_parent..2 * (first_parent + output.len())];
                    scope.spawn(move || {
                        for (parent, pair) in output.iter_mut().zip(children.chunks_exact(2)) {
                            *parent = if level == 0 {
                                hash_node(
                                    ChildHash::Leaf(LeafHash::from_bytes(pair[0])),
                                    ChildHash::Leaf(LeafHash::from_bytes(pair[1])),
                                )
                            } else {
                                hash_node(
                                    ChildHash::Node(NodeHash::from_bytes(pair[0])),
                                    ChildHash::Node(NodeHash::from_bytes(pair[1])),
                                )
                            }
                            .into_bytes();
                        }
                    });
                }
            });
            current = parents;
            level += 1;
        }
        let top = if leaf_count == 1 {
            ChildHash::Leaf(LeafHash::from_bytes(current[0]))
        } else {
            ChildHash::Node(NodeHash::from_bytes(current[0]))
        };
        hash_root(
            u64::try_from(leaf_count).map_err(|_| MultilinearPcsQueryError::Shape)?,
            top,
        )
        .map_err(|_| MultilinearPcsQueryError::Shape)
    }
    #[cfg(not(feature = "parallel"))]
    {
        let (root, _) = build_recomputed_layer_opening(values.len(), leaf_payloads(values), &[0])?;
        Ok(root)
    }
}

#[cfg(feature = "parallel")]
const FILE_LEAF_SLAB: usize = 1 << 14;

#[cfg(feature = "parallel")]
fn validate_codeword_file(path: &Path, value_count: usize) -> Result<(), MultilinearPcsQueryError> {
    validate_value_count(value_count)?;
    let expected = u64::try_from(value_count)
        .ok()
        .and_then(|count| count.checked_mul(FP16_ENCODED_LENGTH as u64))
        .ok_or(MultilinearPcsQueryError::Shape)?;
    if File::open(path)
        .and_then(|file| file.metadata())
        .map_err(|_| MultilinearPcsQueryError::Shape)?
        .len()
        != expected
    {
        return Err(MultilinearPcsQueryError::Shape);
    }
    Ok(())
}

#[cfg(feature = "parallel")]
fn build_file_layer_opening(
    path: &Path,
    value_count: usize,
    expected_value_indices: &[usize],
) -> Result<(RootHash, MultilinearPcsLayerOpening), MultilinearPcsQueryError> {
    validate_codeword_file(path, value_count)?;
    let mut reader = BufReader::with_capacity(
        16 << 20,
        File::open(path).map_err(|_| MultilinearPcsQueryError::Shape)?,
    );
    build_stream_layer_opening(&mut reader, value_count, expected_value_indices)
}

#[cfg(feature = "parallel")]
pub(crate) fn build_stream_layer_opening(
    reader: &mut dyn Read,
    value_count: usize,
    expected_value_indices: &[usize],
) -> Result<(RootHash, MultilinearPcsLayerOpening), MultilinearPcsQueryError> {
    let leaf_count = validate_value_count(value_count)?;
    let mut invalid = false;
    let payloads = (0..leaf_count).map(|_| {
        let mut payload = vec![0_u8; MLPCS_LEAF_PAYLOAD_BYTES];
        if reader.read_exact(&mut payload).is_err()
            || payload
                .chunks_exact(FP16_ENCODED_LENGTH)
                .any(|encoded| Fp16::decode(encoded).is_err())
        {
            invalid = true;
        }
        payload
    });
    let result = build_recomputed_layer_opening(value_count, payloads, expected_value_indices);
    if invalid {
        return Err(MultilinearPcsQueryError::Shape);
    }
    result
}

#[cfg(feature = "parallel")]
fn mix_file_codewords(
    input_path: &Path,
    output_path: &Path,
    value_count: usize,
    mixing: Fp16,
) -> Result<Vec<Fp16>, MultilinearPcsQueryError> {
    validate_codeword_file(input_path, value_count)?;
    validate_codeword_file(output_path, value_count)?;
    let workers = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1);
    let mut input = BufReader::with_capacity(
        16 << 20,
        File::open(input_path).map_err(|_| MultilinearPcsQueryError::Shape)?,
    );
    let mut output = BufReader::with_capacity(
        16 << 20,
        File::open(output_path).map_err(|_| MultilinearPcsQueryError::Shape)?,
    );
    let mut mixed = vec![Fp16::ZERO; value_count];
    let values_per_slab = FILE_LEAF_SLAB * MLPCS_VALUES_PER_LEAF;
    let invalid = AtomicBool::new(false);
    let mut first = 0_usize;
    while first < value_count {
        let slab_values = values_per_slab.min(value_count - first);
        let mut input_bytes = vec![0_u8; slab_values * FP16_ENCODED_LENGTH];
        let mut output_bytes = vec![0_u8; slab_values * FP16_ENCODED_LENGTH];
        input
            .read_exact(&mut input_bytes)
            .and_then(|_| output.read_exact(&mut output_bytes))
            .map_err(|_| MultilinearPcsQueryError::Shape)?;
        let destinations = &mut mixed[first..first + slab_values];
        let chunk = slab_values.div_ceil(workers.min(slab_values));
        std::thread::scope(|scope| {
            for (chunk_ordinal, destination) in destinations.chunks_mut(chunk).enumerate() {
                let start = chunk_ordinal * chunk * FP16_ENCODED_LENGTH;
                let bytes = destination.len() * FP16_ENCODED_LENGTH;
                let input_chunk = &input_bytes[start..start + bytes];
                let output_chunk = &output_bytes[start..start + bytes];
                let invalid = &invalid;
                scope.spawn(move || {
                    for ((destination, input), output) in destination
                        .iter_mut()
                        .zip(input_chunk.chunks_exact(FP16_ENCODED_LENGTH))
                        .zip(output_chunk.chunks_exact(FP16_ENCODED_LENGTH))
                    {
                        match (Fp16::decode(input), Fp16::decode(output)) {
                            (Ok(input), Ok(output)) => *destination = input + mixing * output,
                            _ => invalid.store(true, Ordering::Relaxed),
                        }
                    }
                });
            }
        });
        first += slab_values;
    }
    if invalid.load(Ordering::Relaxed) {
        return Err(MultilinearPcsQueryError::Shape);
    }
    Ok(mixed)
}

/// Initial commitments fixed before the two-boundary main-mixing challenge.
enum DualBoundaryCodewordStorage {
    Memory {
        input: Vec<Fp16>,
        output: Vec<Fp16>,
    },
    #[cfg(feature = "parallel")]
    Files {
        input: PathBuf,
        output: PathBuf,
    },
}

pub struct PreparedDualBoundaryFoldCommitments {
    codewords: DualBoundaryCodewordStorage,
    auxiliary_codeword: Vec<Fp16>,
    #[cfg(feature = "parallel")]
    gpu: Option<GpuFoldConfiguration>,
    input_root: RootHash,
    output_root: RootHash,
    auxiliary_root: RootHash,
}

#[cfg(feature = "parallel")]
struct GpuFoldConfiguration {
    python: PathBuf,
    worker: PathBuf,
    runtime: OsString,
}

impl PreparedDualBoundaryFoldCommitments {
    pub fn prepare(
        input_codeword: Vec<Fp16>,
        output_codeword: Vec<Fp16>,
        auxiliary_codeword: Vec<Fp16>,
    ) -> Result<Self, MultilinearPcsQueryError> {
        if input_codeword.len() != 1_usize << MLPCS_LDE_LOG_SIZE
            || output_codeword.len() != input_codeword.len()
            || auxiliary_codeword.len() != 1_usize << MLPCS_AUXILIARY_LDE_LOG_SIZE
        {
            return Err(MultilinearPcsQueryError::Shape);
        }
        let input_root = commit_layer_root_streaming(&input_codeword)?;
        let output_root = commit_layer_root_streaming(&output_codeword)?;
        let auxiliary_root = commit_layer_root_streaming(&auxiliary_codeword)?;
        Ok(Self {
            codewords: DualBoundaryCodewordStorage::Memory {
                input: input_codeword,
                output: output_codeword,
            },
            auxiliary_codeword,
            #[cfg(feature = "parallel")]
            gpu: None,
            input_root,
            output_root,
            auxiliary_root,
        })
    }

    #[cfg(feature = "parallel")]
    pub fn prepare_files(
        input_codeword: PathBuf,
        output_codeword: PathBuf,
        auxiliary_codeword: Vec<Fp16>,
    ) -> Result<Self, MultilinearPcsQueryError> {
        if auxiliary_codeword.len() != 1_usize << MLPCS_AUXILIARY_LDE_LOG_SIZE {
            return Err(MultilinearPcsQueryError::Shape);
        }
        let value_count = 1_usize << MLPCS_LDE_LOG_SIZE;
        let input_root = build_file_layer_opening(&input_codeword, value_count, &[0])?.0;
        let output_root = build_file_layer_opening(&output_codeword, value_count, &[0])?.0;
        let auxiliary_root = commit_layer_root_streaming(&auxiliary_codeword)?;
        Ok(Self {
            codewords: DualBoundaryCodewordStorage::Files {
                input: input_codeword,
                output: output_codeword,
            },
            auxiliary_codeword,
            gpu: None,
            input_root,
            output_root,
            auxiliary_root,
        })
    }

    #[cfg(feature = "parallel")]
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_files_gpu(
        input_codeword: PathBuf,
        output_codeword: PathBuf,
        auxiliary_codeword: Vec<Fp16>,
        python: PathBuf,
        worker: PathBuf,
        runtime: OsString,
    ) -> Result<Self, MultilinearPcsQueryError> {
        let mut prepared =
            Self::prepare_files(input_codeword, output_codeword, auxiliary_codeword)?;
        prepared.gpu = Some(GpuFoldConfiguration {
            python,
            worker,
            runtime,
        });
        Ok(prepared)
    }

    pub const fn roots(&self) -> [RootHash; 3] {
        [self.input_root, self.output_root, self.auxiliary_root]
    }

    pub fn start(
        self,
        main_mixing_challenge: Fp16,
        auxiliary_mixing_challenge: Fp16,
    ) -> Result<DualBoundaryFoldCommitmentProver, MultilinearPcsQueryError> {
        #[cfg(feature = "parallel")]
        let gpu_layer = if let Some(gpu) = &self.gpu {
            let (input, output) = match &self.codewords {
                DualBoundaryCodewordStorage::Files { input, output } => (input, output),
                DualBoundaryCodewordStorage::Memory { .. } => {
                    return Err(MultilinearPcsQueryError::Shape);
                }
            };
            Some(FoldLayerStorage::Gpu(
                MlpcsGpuWorker::spawn(
                    &gpu.python,
                    &gpu.worker,
                    &gpu.runtime,
                    input,
                    output,
                    main_mixing_challenge,
                    auxiliary_mixing_challenge,
                    &self.auxiliary_codeword,
                )
                .map_err(|_| MultilinearPcsQueryError::Shape)?,
            ))
        } else {
            None
        };
        #[cfg(not(feature = "parallel"))]
        let gpu_layer: Option<FoldLayerStorage> = None;

        let mixed_layer = if let Some(layer) = gpu_layer {
            layer
        } else {
            FoldLayerStorage::Memory(match &self.codewords {
                DualBoundaryCodewordStorage::Memory { input, output } => {
                    let mut mixed = input.clone();
                    #[cfg(feature = "parallel")]
                    {
                        let workers = std::thread::available_parallelism()
                            .map(usize::from)
                            .unwrap_or(1);
                        let chunk = mixed.len().div_ceil(workers.min(mixed.len()));
                        std::thread::scope(|scope| {
                            for (input, output) in mixed.chunks_mut(chunk).zip(output.chunks(chunk))
                            {
                                scope.spawn(move || {
                                    for (input, output) in
                                        input.iter_mut().zip(output.iter().copied())
                                    {
                                        *input = *input + main_mixing_challenge * output;
                                    }
                                });
                            }
                        });
                    }
                    #[cfg(not(feature = "parallel"))]
                    for (input, output) in mixed.iter_mut().zip(output.iter().copied()) {
                        *input = *input + main_mixing_challenge * output;
                    }
                    mixed
                }
                #[cfg(feature = "parallel")]
                DualBoundaryCodewordStorage::Files { input, output } => mix_file_codewords(
                    input,
                    output,
                    1_usize << MLPCS_LDE_LOG_SIZE,
                    main_mixing_challenge,
                )?,
            })
        };
        Ok(DualBoundaryFoldCommitmentProver {
            codewords: self.codewords,
            auxiliary_codeword: self.auxiliary_codeword,
            input_root: self.input_root,
            output_root: self.output_root,
            auxiliary_root: self.auxiliary_root,
            main_mixing_challenge,
            auxiliary_mixing_challenge,
            mixed_layer,
            #[cfg(feature = "parallel")]
            final_values: Vec::new(),
            fold_challenges: Vec::with_capacity(MLPCS_FOLD_ROUNDS),
            shared_roots: Vec::with_capacity(MLPCS_FOLD_ROUNDS - 1),
            pending_round: false,
        })
    }
}

enum FoldLayerStorage {
    Memory(Vec<Fp16>),
    #[cfg(feature = "parallel")]
    Gpu(MlpcsGpuWorker),
}

/// Publish-before-challenge commitment pass for the shared two-boundary FRI.
///
/// Round zero is already bound by the separately published input/output
/// roots. Every later round publishes the current mixed-layer root before its
/// challenge. Query positions are deliberately absent from this state.
pub struct DualBoundaryFoldCommitmentProver {
    codewords: DualBoundaryCodewordStorage,
    auxiliary_codeword: Vec<Fp16>,
    input_root: RootHash,
    output_root: RootHash,
    auxiliary_root: RootHash,
    main_mixing_challenge: Fp16,
    auxiliary_mixing_challenge: Fp16,
    mixed_layer: FoldLayerStorage,
    #[cfg(feature = "parallel")]
    final_values: Vec<Fp16>,
    fold_challenges: Vec<Fp16>,
    shared_roots: Vec<RootHash>,
    pending_round: bool,
}

impl DualBoundaryFoldCommitmentProver {
    pub fn round_ordinal(&self) -> usize {
        self.fold_challenges.len()
    }

    pub fn publish_round_root(&mut self) -> Result<Option<RootHash>, MultilinearPcsQueryError> {
        let round = self.round_ordinal();
        if self.pending_round || round >= MLPCS_FOLD_ROUNDS {
            return Err(MultilinearPcsQueryError::Sequence);
        }
        let root = if round == 0 {
            None
        } else {
            let root = match &mut self.mixed_layer {
                FoldLayerStorage::Memory(values) => commit_layer_root_streaming(values)?,
                #[cfg(feature = "parallel")]
                FoldLayerStorage::Gpu(worker) => worker
                    .stream_layer(|reader, value_count| {
                        build_stream_layer_opening(reader, value_count, &[0])
                            .map(|(root, _)| root)
                            .map_err(|_| MlpcsGpuWorkerError::Protocol)
                    })
                    .map_err(|_| MultilinearPcsQueryError::Authentication)?,
            };
            self.shared_roots.push(root);
            Some(root)
        };
        self.pending_round = true;
        Ok(root)
    }

    pub fn accept_authenticated_challenge(
        &mut self,
        challenge: Fp16,
    ) -> Result<(), MultilinearPcsQueryError> {
        if !self.pending_round {
            return Err(MultilinearPcsQueryError::Sequence);
        }
        let round = self.round_ordinal();
        let layer_log_size = MLPCS_LDE_LOG_SIZE
            .checked_sub(u8::try_from(round).map_err(|_| MultilinearPcsQueryError::Shape)?)
            .ok_or(MultilinearPcsQueryError::Shape)?;
        let domain_root =
            derive_two_adic_root(layer_log_size).map_err(|_| MultilinearPcsQueryError::Shape)?;
        let auxiliary = (round + 1 == usize::from(MLPCS_AUXILIARY_INJECTION_FOLD)).then_some((
            self.auxiliary_codeword.as_slice(),
            self.auxiliary_mixing_challenge,
        ));
        #[cfg(feature = "parallel")]
        match &mut self.mixed_layer {
            FoldLayerStorage::Memory(values) => {
                let workers = std::thread::available_parallelism()
                    .map(usize::from)
                    .unwrap_or(1);
                crate::multilinear_pcs::fold_multiplicative_batch_layer_in_place_parallel(
                    values,
                    domain_root,
                    challenge,
                    auxiliary,
                    workers,
                )
                .map_err(|_| MultilinearPcsQueryError::Shape)?;
            }
            FoldLayerStorage::Gpu(worker) => worker
                .fold(challenge)
                .map_err(|_| MultilinearPcsQueryError::Authentication)?,
        }
        #[cfg(not(feature = "parallel"))]
        {
            let FoldLayerStorage::Memory(values) = &self.mixed_layer;
            self.mixed_layer = FoldLayerStorage::Memory(
                crate::multilinear_pcs::fold_multiplicative_batch_layer(
                    values,
                    domain_root,
                    challenge,
                    auxiliary,
                )
                .map_err(|_| MultilinearPcsQueryError::Shape)?,
            );
        }
        self.fold_challenges.push(challenge);
        if self.fold_challenges.len() == MLPCS_FOLD_ROUNDS {
            #[cfg(feature = "parallel")]
            if let FoldLayerStorage::Gpu(worker) = &mut self.mixed_layer {
                self.final_values = worker
                    .stream_layer(|reader, value_count| {
                        read_stream_values(reader, value_count)
                            .map_err(|_| MlpcsGpuWorkerError::Protocol)
                    })
                    .map_err(|_| MultilinearPcsQueryError::Authentication)?;
            }
        }
        self.pending_round = false;
        Ok(())
    }

    pub fn final_values(&self) -> Result<&[Fp16], MultilinearPcsQueryError> {
        if self.pending_round || self.fold_challenges.len() != MLPCS_FOLD_ROUNDS {
            return Err(MultilinearPcsQueryError::Sequence);
        }
        match &self.mixed_layer {
            FoldLayerStorage::Memory(values) => Ok(values),
            #[cfg(feature = "parallel")]
            FoldLayerStorage::Gpu(_) => Ok(&self.final_values),
        }
    }

    /// Build openings only after the authenticated query positions exist.
    ///
    /// Every root and final value is recomputed and required to equal the
    /// earlier publish-before-challenge commitment pass.
    pub fn finish_with_queries(
        self,
        initial_queries: &[usize],
    ) -> Result<BatchedMultilinearPcsFoldQueryProof, MultilinearPcsQueryError> {
        if self.pending_round || self.fold_challenges.len() != MLPCS_FOLD_ROUNDS {
            return Err(MultilinearPcsQueryError::Sequence);
        }
        let expected_final_values = match &self.mixed_layer {
            FoldLayerStorage::Memory(values) => values.clone(),
            #[cfg(feature = "parallel")]
            FoldLayerStorage::Gpu(_) => self.final_values.clone(),
        };
        let proof = match self.codewords {
            DualBoundaryCodewordStorage::Memory { input, output } => {
                build_selected_batched_fold_query_proof(
                    input,
                    output,
                    self.auxiliary_codeword,
                    self.main_mixing_challenge,
                    &self.fold_challenges,
                    self.auxiliary_mixing_challenge,
                    initial_queries,
                )?
            }
            #[cfg(feature = "parallel")]
            DualBoundaryCodewordStorage::Files { input, output } => match self.mixed_layer {
                FoldLayerStorage::Gpu(worker) => build_selected_batched_fold_query_proof_gpu(
                    worker,
                    &input,
                    &output,
                    self.auxiliary_codeword,
                    self.main_mixing_challenge,
                    &self.fold_challenges,
                    initial_queries,
                )?,
                FoldLayerStorage::Memory(_) => build_selected_batched_fold_query_proof_files(
                    &input,
                    &output,
                    self.auxiliary_codeword,
                    self.main_mixing_challenge,
                    &self.fold_challenges,
                    self.auxiliary_mixing_challenge,
                    initial_queries,
                )?,
            },
        };
        if proof.input_root != self.input_root
            || proof.output_root != self.output_root
            || proof.shared.auxiliary_root != self.auxiliary_root
            || proof.shared.main_layer_roots != self.shared_roots
            || proof.shared.final_values != expected_final_values
        {
            return Err(MultilinearPcsQueryError::Authentication);
        }
        Ok(proof)
    }
}

#[cfg(feature = "parallel")]
fn build_parallel_layer_opening(
    values: &[Fp16],
    expected_value_indices: &[usize],
    workers: usize,
) -> Result<(RootHash, MultilinearPcsLayerOpening), MultilinearPcsQueryError> {
    let leaf_count = validate_value_count(values.len())?;
    if workers == 0 {
        return Err(MultilinearPcsQueryError::Shape);
    }
    let selected = selected_leaf_indices(values.len(), expected_value_indices)?;
    let mut leaf_hashes = vec![[0_u8; 64]; leaf_count];
    let chunk = leaf_count.div_ceil(workers.min(leaf_count));
    std::thread::scope(|scope| {
        for (hash_chunk, value_chunk) in leaf_hashes
            .chunks_mut(chunk)
            .zip(values.chunks(chunk * MLPCS_VALUES_PER_LEAF))
        {
            scope.spawn(move || {
                for (digest, leaf) in hash_chunk
                    .iter_mut()
                    .zip(value_chunk.chunks_exact(MLPCS_VALUES_PER_LEAF))
                {
                    let mut payload = [0_u8; MLPCS_LEAF_PAYLOAD_BYTES];
                    for (index, value) in leaf.iter().copied().enumerate() {
                        let start = index * FP16_ENCODED_LENGTH;
                        payload[start..start + FP16_ENCODED_LENGTH]
                            .copy_from_slice(&value.encode());
                    }
                    *digest = hash_leaf(&payload)
                        .expect("fixed selected PCS leaf payload is bounded")
                        .into_bytes();
                }
            });
        }
    });
    let (root, multiproof) = build_bounded_canonical_multiproof_from_leaf_hashes_parallel(
        leaf_hashes,
        &selected,
        workers,
    )?;
    if values.len() / MLPCS_VALUES_PER_LEAF != leaf_count {
        return Err(MultilinearPcsQueryError::Shape);
    }
    let leaves = selected
        .iter()
        .copied()
        .map(|leaf_index| MultilinearPcsLeafOpening {
            leaf_index,
            values: values
                [leaf_index * MLPCS_VALUES_PER_LEAF..(leaf_index + 1) * MLPCS_VALUES_PER_LEAF]
                .try_into()
                .expect("validated fixed-size leaf"),
        })
        .collect();
    Ok((root, MultilinearPcsLayerOpening { leaves, multiproof }))
}

#[allow(clippy::too_many_arguments)]
fn build_fold_query_proof_geometry(
    mut main_layer: Vec<Fp16>,
    auxiliary_layer: Vec<Fp16>,
    fold_challenges: &[Fp16],
    auxiliary_mixing_challenge: Fp16,
    initial_queries: &[usize],
    initial_log_size: u8,
    auxiliary_log_size: u8,
    auxiliary_injection_fold: usize,
) -> Result<MultilinearPcsFoldQueryProof, MultilinearPcsQueryError> {
    let fold_rounds = fold_challenges.len();
    if fold_rounds == 0
        || auxiliary_injection_fold == 0
        || auxiliary_injection_fold > fold_rounds
        || initial_log_size >= usize::BITS as u8
        || auxiliary_log_size >= usize::BITS as u8
        || initial_log_size
            .checked_sub(auxiliary_log_size)
            .map(usize::from)
            != Some(auxiliary_injection_fold)
        || main_layer.len() != 1_usize << initial_log_size
        || auxiliary_layer.len() != 1_usize << auxiliary_log_size
    {
        return Err(MultilinearPcsQueryError::Shape);
    }
    let layer_indices = layer_value_indices(initial_queries, initial_log_size, fold_rounds)?;
    let mut auxiliary_indices = initial_queries.to_vec();
    let mut auxiliary_value_count = 1_usize << initial_log_size;
    for _ in 0..auxiliary_injection_fold {
        auxiliary_value_count /= 2;
        for index in &mut auxiliary_indices {
            *index %= auxiliary_value_count;
        }
    }
    auxiliary_indices.sort_unstable();
    auxiliary_indices.dedup();
    #[cfg(feature = "parallel")]
    let workers = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1);
    #[cfg(feature = "parallel")]
    let (auxiliary_root, auxiliary_opening) =
        build_parallel_layer_opening(&auxiliary_layer, &auxiliary_indices, workers)?;
    #[cfg(not(feature = "parallel"))]
    let (auxiliary_root, auxiliary_opening) = build_recomputed_layer_opening(
        auxiliary_layer.len(),
        leaf_payloads(&auxiliary_layer),
        &auxiliary_indices,
    )?;

    let mut main_layer_roots = Vec::with_capacity(fold_rounds);
    let mut main_layer_openings = Vec::with_capacity(fold_rounds);
    let mut layer_log_size = initial_log_size;
    for (round, challenge) in fold_challenges.iter().copied().enumerate() {
        #[cfg(feature = "parallel")]
        let (root, opening) =
            build_parallel_layer_opening(&main_layer, &layer_indices[round], workers)?;
        #[cfg(not(feature = "parallel"))]
        let (root, opening) = build_recomputed_layer_opening(
            main_layer.len(),
            leaf_payloads(&main_layer),
            &layer_indices[round],
        )?;
        main_layer_roots.push(root);
        main_layer_openings.push(opening);
        let domain_root =
            derive_two_adic_root(layer_log_size).map_err(|_| MultilinearPcsQueryError::Shape)?;
        let auxiliary = (round + 1 == auxiliary_injection_fold)
            .then_some((auxiliary_layer.as_slice(), auxiliary_mixing_challenge));
        #[cfg(feature = "parallel")]
        {
            crate::multilinear_pcs::fold_multiplicative_batch_layer_in_place_parallel(
                &mut main_layer,
                domain_root,
                challenge,
                auxiliary,
                workers,
            )
            .map_err(|_| MultilinearPcsQueryError::Shape)?;
        }
        #[cfg(not(feature = "parallel"))]
        {
            main_layer = crate::multilinear_pcs::fold_multiplicative_batch_layer(
                &main_layer,
                domain_root,
                challenge,
                auxiliary,
            )
            .map_err(|_| MultilinearPcsQueryError::Shape)?;
        }
        layer_log_size = layer_log_size
            .checked_sub(1)
            .ok_or(MultilinearPcsQueryError::Shape)?;
    }

    Ok(MultilinearPcsFoldQueryProof {
        main_layer_roots,
        auxiliary_root,
        main_layer_openings,
        auxiliary_opening,
        final_values: main_layer,
    })
}

/// Construct the exact selected 22-layer query proof from committed codewords.
///
/// Challenges and query positions must come from the authenticated outer
/// public-coin protocol. The verifier remains authoritative over every root,
/// position, fold, and final value.
pub fn build_selected_fold_query_proof(
    main_codeword: Vec<Fp16>,
    auxiliary_codeword: Vec<Fp16>,
    fold_challenges: &[Fp16],
    auxiliary_mixing_challenge: Fp16,
    initial_queries: &[usize],
) -> Result<MultilinearPcsFoldQueryProof, MultilinearPcsQueryError> {
    validate_selected_queries(initial_queries)?;
    if fold_challenges.len() != MLPCS_FOLD_ROUNDS {
        return Err(MultilinearPcsQueryError::Shape);
    }
    build_fold_query_proof_geometry(
        main_codeword,
        auxiliary_codeword,
        fold_challenges,
        auxiliary_mixing_challenge,
        initial_queries,
        MLPCS_LDE_LOG_SIZE,
        MLPCS_AUXILIARY_LDE_LOG_SIZE,
        usize::from(MLPCS_AUXILIARY_INJECTION_FOLD),
    )
}

/// Construct a two-boundary query proof with one shared 22-round FRI path.
///
/// This is the minimal batching extension needed by the semantic state bus:
/// only the initial `2^25` commitments/openings are duplicated.
#[allow(clippy::too_many_arguments)]
pub fn build_selected_batched_fold_query_proof(
    mut input_codeword: Vec<Fp16>,
    output_codeword: Vec<Fp16>,
    auxiliary_codeword: Vec<Fp16>,
    main_mixing_challenge: Fp16,
    fold_challenges: &[Fp16],
    auxiliary_mixing_challenge: Fp16,
    initial_queries: &[usize],
) -> Result<BatchedMultilinearPcsFoldQueryProof, MultilinearPcsQueryError> {
    validate_selected_queries(initial_queries)?;
    if fold_challenges.len() != MLPCS_FOLD_ROUNDS
        || input_codeword.len() != 1_usize << MLPCS_LDE_LOG_SIZE
        || output_codeword.len() != input_codeword.len()
    {
        return Err(MultilinearPcsQueryError::Shape);
    }
    let initial_indices =
        layer_value_indices(initial_queries, MLPCS_LDE_LOG_SIZE, MLPCS_FOLD_ROUNDS)?
            .into_iter()
            .next()
            .ok_or(MultilinearPcsQueryError::Shape)?;
    #[cfg(feature = "parallel")]
    let workers = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1);
    #[cfg(feature = "parallel")]
    let (input_root, input_initial_opening) =
        build_parallel_layer_opening(&input_codeword, &initial_indices, workers)?;
    #[cfg(not(feature = "parallel"))]
    let (input_root, input_initial_opening) = build_recomputed_layer_opening(
        input_codeword.len(),
        leaf_payloads(&input_codeword),
        &initial_indices,
    )?;
    #[cfg(feature = "parallel")]
    let (output_root, output_initial_opening) =
        build_parallel_layer_opening(&output_codeword, &initial_indices, workers)?;
    #[cfg(not(feature = "parallel"))]
    let (output_root, output_initial_opening) = build_recomputed_layer_opening(
        output_codeword.len(),
        leaf_payloads(&output_codeword),
        &initial_indices,
    )?;

    #[cfg(feature = "parallel")]
    {
        let chunk = input_codeword
            .len()
            .div_ceil(workers.min(input_codeword.len()));
        std::thread::scope(|scope| {
            for (input, output) in input_codeword
                .chunks_mut(chunk)
                .zip(output_codeword.chunks(chunk))
            {
                scope.spawn(move || {
                    for (input, output) in input.iter_mut().zip(output.iter().copied()) {
                        *input = *input + main_mixing_challenge * output;
                    }
                });
            }
        });
    }
    #[cfg(not(feature = "parallel"))]
    for (input, output) in input_codeword.iter_mut().zip(output_codeword) {
        *input = *input + main_mixing_challenge * output;
    }
    let initial_root =
        derive_two_adic_root(MLPCS_LDE_LOG_SIZE).map_err(|_| MultilinearPcsQueryError::Shape)?;
    #[cfg(feature = "parallel")]
    let mixed_after_first = {
        crate::multilinear_pcs::fold_multiplicative_batch_layer_in_place_parallel(
            &mut input_codeword,
            initial_root,
            fold_challenges[0],
            None,
            workers,
        )
        .map_err(|_| MultilinearPcsQueryError::Shape)?;
        input_codeword
    };
    #[cfg(not(feature = "parallel"))]
    let mixed_after_first = crate::multilinear_pcs::fold_multiplicative_batch_layer(
        &input_codeword,
        initial_root,
        fold_challenges[0],
        None,
    )
    .map_err(|_| MultilinearPcsQueryError::Shape)?;
    let reduced_queries = initial_queries
        .iter()
        .map(|query| query % (1_usize << (MLPCS_LDE_LOG_SIZE - 1)))
        .collect::<Vec<_>>();
    let shared = build_fold_query_proof_geometry(
        mixed_after_first,
        auxiliary_codeword,
        &fold_challenges[1..],
        auxiliary_mixing_challenge,
        &reduced_queries,
        MLPCS_LDE_LOG_SIZE - 1,
        MLPCS_AUXILIARY_LDE_LOG_SIZE,
        usize::from(MLPCS_AUXILIARY_INJECTION_FOLD) - 1,
    )?;
    Ok(BatchedMultilinearPcsFoldQueryProof {
        input_root,
        output_root,
        input_initial_opening,
        output_initial_opening,
        shared,
    })
}

#[cfg(feature = "parallel")]
#[allow(clippy::too_many_arguments)]
fn build_selected_batched_fold_query_proof_files(
    input_codeword: &Path,
    output_codeword: &Path,
    auxiliary_codeword: Vec<Fp16>,
    main_mixing_challenge: Fp16,
    fold_challenges: &[Fp16],
    auxiliary_mixing_challenge: Fp16,
    initial_queries: &[usize],
) -> Result<BatchedMultilinearPcsFoldQueryProof, MultilinearPcsQueryError> {
    validate_selected_queries(initial_queries)?;
    if fold_challenges.len() != MLPCS_FOLD_ROUNDS {
        return Err(MultilinearPcsQueryError::Shape);
    }
    let value_count = 1_usize << MLPCS_LDE_LOG_SIZE;
    let initial_indices =
        layer_value_indices(initial_queries, MLPCS_LDE_LOG_SIZE, MLPCS_FOLD_ROUNDS)?
            .into_iter()
            .next()
            .ok_or(MultilinearPcsQueryError::Shape)?;
    let (input_root, input_initial_opening) =
        build_file_layer_opening(input_codeword, value_count, &initial_indices)?;
    let (output_root, output_initial_opening) =
        build_file_layer_opening(output_codeword, value_count, &initial_indices)?;
    let mut mixed = mix_file_codewords(
        input_codeword,
        output_codeword,
        value_count,
        main_mixing_challenge,
    )?;
    let workers = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1);
    let initial_root =
        derive_two_adic_root(MLPCS_LDE_LOG_SIZE).map_err(|_| MultilinearPcsQueryError::Shape)?;
    crate::multilinear_pcs::fold_multiplicative_batch_layer_in_place_parallel(
        &mut mixed,
        initial_root,
        fold_challenges[0],
        None,
        workers,
    )
    .map_err(|_| MultilinearPcsQueryError::Shape)?;
    let reduced_queries = initial_queries
        .iter()
        .map(|query| query % (1_usize << (MLPCS_LDE_LOG_SIZE - 1)))
        .collect::<Vec<_>>();
    let shared = build_fold_query_proof_geometry(
        mixed,
        auxiliary_codeword,
        &fold_challenges[1..],
        auxiliary_mixing_challenge,
        &reduced_queries,
        MLPCS_LDE_LOG_SIZE - 1,
        MLPCS_AUXILIARY_LDE_LOG_SIZE,
        usize::from(MLPCS_AUXILIARY_INJECTION_FOLD) - 1,
    )?;
    Ok(BatchedMultilinearPcsFoldQueryProof {
        input_root,
        output_root,
        input_initial_opening,
        output_initial_opening,
        shared,
    })
}

#[cfg(feature = "parallel")]
fn read_stream_values(
    reader: &mut dyn Read,
    value_count: usize,
) -> Result<Vec<Fp16>, MultilinearPcsQueryError> {
    validate_value_count(value_count)?;
    let mut values = Vec::with_capacity(value_count);
    let mut encoded = [0_u8; FP16_ENCODED_LENGTH];
    for _ in 0..value_count {
        reader
            .read_exact(&mut encoded)
            .map_err(|_| MultilinearPcsQueryError::Shape)?;
        values.push(Fp16::decode(&encoded).map_err(|_| MultilinearPcsQueryError::Shape)?);
    }
    Ok(values)
}

#[cfg(feature = "parallel")]
#[allow(clippy::too_many_arguments)]
fn build_selected_batched_fold_query_proof_gpu(
    mut worker: MlpcsGpuWorker,
    input_codeword: &Path,
    output_codeword: &Path,
    auxiliary_codeword: Vec<Fp16>,
    main_mixing_challenge: Fp16,
    fold_challenges: &[Fp16],
    initial_queries: &[usize],
) -> Result<BatchedMultilinearPcsFoldQueryProof, MultilinearPcsQueryError> {
    validate_selected_queries(initial_queries)?;
    if fold_challenges.len() != MLPCS_FOLD_ROUNDS {
        return Err(MultilinearPcsQueryError::Shape);
    }
    let value_count = 1_usize << MLPCS_LDE_LOG_SIZE;
    let initial_indices =
        layer_value_indices(initial_queries, MLPCS_LDE_LOG_SIZE, MLPCS_FOLD_ROUNDS)?
            .into_iter()
            .next()
            .ok_or(MultilinearPcsQueryError::Shape)?;
    let (input_root, input_initial_opening) =
        build_file_layer_opening(input_codeword, value_count, &initial_indices)?;
    let (output_root, output_initial_opening) =
        build_file_layer_opening(output_codeword, value_count, &initial_indices)?;
    let reduced_queries = initial_queries
        .iter()
        .map(|query| query % (1_usize << (MLPCS_LDE_LOG_SIZE - 1)))
        .collect::<Vec<_>>();
    let shared_layer_indices = layer_value_indices(
        &reduced_queries,
        MLPCS_LDE_LOG_SIZE - 1,
        MLPCS_FOLD_ROUNDS - 1,
    )?;
    let mut auxiliary_indices = reduced_queries.clone();
    let mut auxiliary_value_count = 1_usize << (MLPCS_LDE_LOG_SIZE - 1);
    for _ in 0..usize::from(MLPCS_AUXILIARY_INJECTION_FOLD) - 1 {
        auxiliary_value_count /= 2;
        for index in &mut auxiliary_indices {
            *index %= auxiliary_value_count;
        }
    }
    auxiliary_indices.sort_unstable();
    auxiliary_indices.dedup();
    let workers = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1);
    let (auxiliary_root, auxiliary_opening) =
        build_parallel_layer_opening(&auxiliary_codeword, &auxiliary_indices, workers)?;

    worker
        .reset(main_mixing_challenge)
        .map_err(|_| MultilinearPcsQueryError::Authentication)?;
    worker
        .fold(fold_challenges[0])
        .map_err(|_| MultilinearPcsQueryError::Authentication)?;
    let mut main_layer_roots = Vec::with_capacity(MLPCS_FOLD_ROUNDS - 1);
    let mut main_layer_openings = Vec::with_capacity(MLPCS_FOLD_ROUNDS - 1);
    for round in 0..MLPCS_FOLD_ROUNDS - 1 {
        let (root, opening) = worker
            .stream_layer(|reader, streamed_count| {
                build_stream_layer_opening(reader, streamed_count, &shared_layer_indices[round])
                    .map_err(|_| MlpcsGpuWorkerError::Protocol)
            })
            .map_err(|_| MultilinearPcsQueryError::Authentication)?;
        main_layer_roots.push(root);
        main_layer_openings.push(opening);
        worker
            .fold(fold_challenges[round + 1])
            .map_err(|_| MultilinearPcsQueryError::Authentication)?;
    }
    let final_values = worker
        .stream_layer(|reader, streamed_count| {
            read_stream_values(reader, streamed_count).map_err(|_| MlpcsGpuWorkerError::Protocol)
        })
        .map_err(|_| MultilinearPcsQueryError::Authentication)?;
    worker
        .finish()
        .map_err(|_| MultilinearPcsQueryError::Authentication)?;
    Ok(BatchedMultilinearPcsFoldQueryProof {
        input_root,
        output_root,
        input_initial_opening,
        output_initial_opening,
        shared: MultilinearPcsFoldQueryProof {
            main_layer_roots,
            auxiliary_root,
            main_layer_openings,
            auxiliary_opening,
            final_values,
        },
    })
}

fn pow_usize(mut base: Fp16, mut exponent: usize) -> Fp16 {
    let mut value = Fp16::ONE;
    while exponent != 0 {
        if exponent & 1 == 1 {
            value = value * base;
        }
        base = base.square();
        exponent >>= 1;
    }
    value
}

#[allow(clippy::too_many_arguments)]
fn verify_fold_query_proof_geometry(
    proof: &MultilinearPcsFoldQueryProof,
    expected_main_root: RootHash,
    expected_auxiliary_root: RootHash,
    fold_challenges: &[Fp16],
    auxiliary_mixing_challenge: Fp16,
    expected_main_terminal: Fp16,
    expected_auxiliary_terminal: Fp16,
    initial_queries: &[usize],
    initial_log_size: u8,
    auxiliary_log_size: u8,
    auxiliary_injection_fold: usize,
) -> Result<(), MultilinearPcsQueryError> {
    let fold_rounds = fold_challenges.len();
    if fold_rounds == 0
        || auxiliary_injection_fold == 0
        || auxiliary_injection_fold > fold_rounds
        || initial_log_size
            .checked_sub(auxiliary_log_size)
            .map(usize::from)
            != Some(auxiliary_injection_fold)
    {
        return Err(MultilinearPcsQueryError::Shape);
    }
    if proof.main_layer_roots.len() != fold_rounds {
        return Err(MultilinearPcsQueryError::RootCount);
    }
    if proof.main_layer_openings.len() != fold_rounds {
        return Err(MultilinearPcsQueryError::LayerCount);
    }
    if proof.main_layer_roots[0] != expected_main_root
        || proof.auxiliary_root != expected_auxiliary_root
    {
        return Err(MultilinearPcsQueryError::Authentication);
    }
    let terminal_count = 1_usize << (usize::from(initial_log_size) - fold_rounds);
    if proof.final_values.len() != terminal_count
        || proof.final_values.is_empty()
        || proof
            .final_values
            .iter()
            .any(|value| *value != proof.final_values[0])
        || proof.final_values[0]
            != expected_main_terminal + auxiliary_mixing_challenge * expected_auxiliary_terminal
    {
        return Err(MultilinearPcsQueryError::FinalLayer);
    }

    let layer_indices = layer_value_indices(initial_queries, initial_log_size, fold_rounds)?;
    let mut value_count = 1_usize << initial_log_size;
    for (round, indices) in layer_indices.iter().take(fold_rounds).enumerate() {
        verify_layer_opening(
            &proof.main_layer_openings[round],
            &proof.main_layer_roots[round],
            value_count,
            indices,
        )?;
        value_count /= 2;
    }
    let mut auxiliary_indices = initial_queries.to_vec();
    let mut auxiliary_value_count = 1_usize << initial_log_size;
    for _ in 0..auxiliary_injection_fold {
        auxiliary_value_count /= 2;
        for index in &mut auxiliary_indices {
            *index %= auxiliary_value_count;
        }
    }
    auxiliary_indices.sort_unstable();
    auxiliary_indices.dedup();
    if auxiliary_value_count != 1_usize << auxiliary_log_size {
        return Err(MultilinearPcsQueryError::Shape);
    }
    verify_layer_opening(
        &proof.auxiliary_opening,
        &proof.auxiliary_root,
        auxiliary_value_count,
        &auxiliary_indices,
    )?;

    let initial_root =
        derive_two_adic_root(initial_log_size).map_err(|_| MultilinearPcsQueryError::Shape)?;
    for initial_query in initial_queries.iter().copied() {
        let mut query = initial_query;
        let mut layer_size = 1_usize << initial_log_size;
        let mut round_root = initial_root;
        for (round, fold_challenge) in fold_challenges.iter().copied().enumerate() {
            let half = layer_size / 2;
            let base = query % half;
            let at_x = opened_value(&proof.main_layer_openings[round], base)?;
            let at_negative_x = opened_value(&proof.main_layer_openings[round], base + half)?;
            let expected = if round + 1 == fold_rounds {
                proof.final_values[base]
            } else {
                opened_value(&proof.main_layer_openings[round + 1], base)?
            };
            let auxiliary = if round + 1 == auxiliary_injection_fold {
                Some((
                    opened_value(&proof.auxiliary_opening, base)?,
                    auxiliary_mixing_challenge,
                ))
            } else {
                None
            };
            let inverse_x = pow_usize(
                round_root
                    .inverse()
                    .map_err(|_| MultilinearPcsQueryError::Shape)?,
                base,
            );
            if !verify_multiplicative_batch_fold(
                at_x,
                at_negative_x,
                inverse_x,
                fold_challenge,
                auxiliary,
                expected,
            )
            .map_err(|_| MultilinearPcsQueryError::Shape)?
            {
                return Err(MultilinearPcsQueryError::FoldMismatch);
            }
            query = base;
            layer_size = half;
            round_root = round_root.square();
        }
    }
    Ok(())
}

/// Independently verify the complete selected low-degree/query segment.
///
/// This does not verify the preceding binding-line messages and therefore is
/// intentionally not exposed as a complete PCS verifier.
pub fn verify_selected_fold_query_proof(
    proof: &MultilinearPcsFoldQueryProof,
    expected: SelectedFoldQueryExpectations<'_>,
) -> Result<(), MultilinearPcsQueryError> {
    let SelectedFoldQueryExpectations {
        main_root: expected_main_root,
        auxiliary_root: expected_auxiliary_root,
        fold_challenges,
        auxiliary_mixing_challenge,
        main_terminal: expected_main_terminal,
        auxiliary_terminal: expected_auxiliary_terminal,
        queries: initial_queries,
    } = expected;
    validate_selected_queries(initial_queries)?;
    if fold_challenges.len() != MLPCS_FOLD_ROUNDS {
        return Err(MultilinearPcsQueryError::Shape);
    }
    verify_fold_query_proof_geometry(
        proof,
        expected_main_root,
        expected_auxiliary_root,
        fold_challenges,
        auxiliary_mixing_challenge,
        expected_main_terminal,
        expected_auxiliary_terminal,
        initial_queries,
        MLPCS_LDE_LOG_SIZE,
        MLPCS_AUXILIARY_LDE_LOG_SIZE,
        usize::from(MLPCS_AUXILIARY_INJECTION_FOLD),
    )
}

/// Independently verify the two initial roots and their one shared FRI path.
#[allow(clippy::too_many_arguments)]
pub fn verify_selected_batched_fold_query_proof(
    proof: &BatchedMultilinearPcsFoldQueryProof,
    expected_input_root: RootHash,
    expected_output_root: RootHash,
    main_mixing_challenge: Fp16,
    fold_challenges: &[Fp16],
    auxiliary_mixing_challenge: Fp16,
    expected_input_terminal: Fp16,
    expected_output_terminal: Fp16,
    expected_auxiliary_terminal: Fp16,
    initial_queries: &[usize],
) -> Result<(), MultilinearPcsQueryError> {
    validate_selected_queries(initial_queries)?;
    if fold_challenges.len() != MLPCS_FOLD_ROUNDS
        || proof.input_root != expected_input_root
        || proof.output_root != expected_output_root
    {
        return Err(MultilinearPcsQueryError::Authentication);
    }
    let layer_indices =
        layer_value_indices(initial_queries, MLPCS_LDE_LOG_SIZE, MLPCS_FOLD_ROUNDS)?;
    verify_layer_opening(
        &proof.input_initial_opening,
        &expected_input_root,
        1_usize << MLPCS_LDE_LOG_SIZE,
        &layer_indices[0],
    )?;
    verify_layer_opening(
        &proof.output_initial_opening,
        &expected_output_root,
        1_usize << MLPCS_LDE_LOG_SIZE,
        &layer_indices[0],
    )?;
    let reduced_queries = initial_queries
        .iter()
        .map(|query| query % (1_usize << (MLPCS_LDE_LOG_SIZE - 1)))
        .collect::<Vec<_>>();
    let expected_shared_root = *proof
        .shared
        .main_layer_roots
        .first()
        .ok_or(MultilinearPcsQueryError::RootCount)?;
    verify_fold_query_proof_geometry(
        &proof.shared,
        expected_shared_root,
        proof.shared.auxiliary_root,
        &fold_challenges[1..],
        auxiliary_mixing_challenge,
        expected_input_terminal + main_mixing_challenge * expected_output_terminal,
        expected_auxiliary_terminal,
        &reduced_queries,
        MLPCS_LDE_LOG_SIZE - 1,
        MLPCS_AUXILIARY_LDE_LOG_SIZE,
        usize::from(MLPCS_AUXILIARY_INJECTION_FOLD) - 1,
    )?;

    let domain_root =
        derive_two_adic_root(MLPCS_LDE_LOG_SIZE).map_err(|_| MultilinearPcsQueryError::Shape)?;
    let inverse_root = domain_root
        .inverse()
        .map_err(|_| MultilinearPcsQueryError::Shape)?;
    let half = 1_usize << (MLPCS_LDE_LOG_SIZE - 1);
    for query in initial_queries {
        let base = *query % half;
        let input_at_x = opened_value(&proof.input_initial_opening, base)?;
        let input_at_negative_x = opened_value(&proof.input_initial_opening, base + half)?;
        let output_at_x = opened_value(&proof.output_initial_opening, base)?;
        let output_at_negative_x = opened_value(&proof.output_initial_opening, base + half)?;
        let expected = opened_value(&proof.shared.main_layer_openings[0], base)?;
        if !verify_multiplicative_batch_fold(
            input_at_x + main_mixing_challenge * output_at_x,
            input_at_negative_x + main_mixing_challenge * output_at_negative_x,
            pow_usize(inverse_root, base),
            fold_challenges[0],
            None,
            expected,
        )
        .map_err(|_| MultilinearPcsQueryError::Shape)?
        {
            return Err(MultilinearPcsQueryError::FoldMismatch);
        }
    }
    Ok(())
}

fn maximally_spread_frontier_slots(leaf_count: usize, opened_leaves: usize) -> usize {
    let mut active = opened_leaves;
    let mut total = 0_usize;
    for level in 0..leaf_count.ilog2() as usize {
        let parent_capacity = leaf_count >> (level + 1);
        if active <= parent_capacity {
            total += active;
        } else {
            total += 2 * parent_capacity - active;
            active = parent_capacity;
        }
    }
    total
}

fn maximum_frontier_slots(leaf_count: usize, maximum_opened_leaves: usize) -> usize {
    (1..=maximum_opened_leaves.min(leaf_count))
        .map(|opened| maximally_spread_frontier_slots(leaf_count, opened))
        .max()
        .unwrap_or(0)
}

fn maximum_main_leaf_slots(value_count: usize) -> usize {
    (2 * MLPCS_UNIQUE_QUERY_COUNT).min(value_count / MLPCS_VALUES_PER_LEAF)
}

fn maximum_auxiliary_leaf_slots() -> usize {
    MLPCS_UNIQUE_QUERY_COUNT.min((1_usize << MLPCS_AUXILIARY_LDE_LOG_SIZE) / MLPCS_VALUES_PER_LEAF)
}

/// Exact fixed byte length of every selected fold-query proof.
pub fn selected_fold_query_proof_encoded_len() -> usize {
    let mut length = 8 + 2 + 1;
    length += (MLPCS_FOLD_ROUNDS + 1) * 64;
    let mut value_count = 1_usize << MLPCS_LDE_LOG_SIZE;
    for _ in 0..MLPCS_FOLD_ROUNDS {
        let leaf_count = value_count / MLPCS_VALUES_PER_LEAF;
        let leaf_slots = maximum_main_leaf_slots(value_count);
        length += leaf_slots * MLPCS_LEAF_PAYLOAD_BYTES;
        length += maximum_frontier_slots(leaf_count, leaf_slots) * 64;
        value_count /= 2;
    }
    let auxiliary_leaf_count = (1_usize << MLPCS_AUXILIARY_LDE_LOG_SIZE) / MLPCS_VALUES_PER_LEAF;
    let auxiliary_leaf_slots = maximum_auxiliary_leaf_slots();
    length += auxiliary_leaf_slots * MLPCS_LEAF_PAYLOAD_BYTES;
    length += maximum_frontier_slots(auxiliary_leaf_count, auxiliary_leaf_slots) * 64;
    length + (1_usize << (MLPCS_LDE_LOG_SIZE as usize - MLPCS_FOLD_ROUNDS)) * 64
}

/// Exact fixed byte length of the two-boundary shared fold/query proof.
pub fn selected_batched_fold_query_proof_encoded_len() -> usize {
    let value_count = 1_usize << MLPCS_LDE_LOG_SIZE;
    let leaf_count = value_count / MLPCS_VALUES_PER_LEAF;
    let leaf_slots = maximum_main_leaf_slots(value_count);
    let one_initial_opening =
        leaf_slots * MLPCS_LEAF_PAYLOAD_BYTES + maximum_frontier_slots(leaf_count, leaf_slots) * 64;
    selected_fold_query_proof_encoded_len() + 64 + one_initial_opening
}

fn encode_fixed_layer(
    encoded: &mut Vec<u8>,
    opening: &MultilinearPcsLayerOpening,
    value_count: usize,
    expected_value_indices: &[usize],
    maximum_leaf_slots: usize,
) -> Result<(), MultilinearPcsQueryError> {
    let leaf_count = validate_value_count(value_count)?;
    let selected = selected_leaf_indices(value_count, expected_value_indices)?;
    if selected.len() > maximum_leaf_slots
        || opening.multiproof.leaf_count() != leaf_count
        || opening.leaves.len() != selected.len()
        || opening
            .leaves
            .iter()
            .map(|leaf| leaf.leaf_index)
            .ne(selected.iter().copied())
    {
        return Err(MultilinearPcsQueryError::Shape);
    }
    let actual_frontier = canonical_frontier_positions(leaf_count, &selected)?.len();
    let maximum_frontier = maximum_frontier_slots(leaf_count, maximum_leaf_slots);
    if actual_frontier > maximum_frontier
        || opening.multiproof.frontier_digests().len() != actual_frontier
    {
        return Err(MultilinearPcsQueryError::Shape);
    }
    for leaf in &opening.leaves {
        encoded.extend_from_slice(&leaf.payload());
    }
    encoded.resize(
        encoded.len() + (maximum_leaf_slots - selected.len()) * MLPCS_LEAF_PAYLOAD_BYTES,
        0,
    );
    encoded.extend_from_slice(&opening.multiproof.frontier_bytes());
    encoded.resize(encoded.len() + (maximum_frontier - actual_frontier) * 64, 0);
    Ok(())
}

fn decode_fixed_layer(
    reader: &mut Reader<'_>,
    value_count: usize,
    expected_value_indices: &[usize],
    maximum_leaf_slots: usize,
) -> Result<MultilinearPcsLayerOpening, MultilinearPcsQueryError> {
    let leaf_count = validate_value_count(value_count)?;
    let selected = selected_leaf_indices(value_count, expected_value_indices)?;
    if selected.len() > maximum_leaf_slots {
        return Err(MultilinearPcsQueryError::Shape);
    }
    let leaves = selected
        .iter()
        .copied()
        .map(|leaf_index| decode_leaf(leaf_index, reader.take(MLPCS_LEAF_PAYLOAD_BYTES)?))
        .collect::<Result<Vec<_>, _>>()?;
    reader.zero_padding((maximum_leaf_slots - selected.len()) * MLPCS_LEAF_PAYLOAD_BYTES)?;
    let actual_frontier = canonical_frontier_positions(leaf_count, &selected)?.len();
    let maximum_frontier = maximum_frontier_slots(leaf_count, maximum_leaf_slots);
    if actual_frontier > maximum_frontier {
        return Err(MultilinearPcsQueryError::Shape);
    }
    let multiproof = CanonicalMerkleMultiProof::from_frontier_bytes(
        leaf_count,
        &selected,
        reader.take(actual_frontier * 64)?,
    )?;
    reader.zero_padding((maximum_frontier - actual_frontier) * 64)?;
    Ok(MultilinearPcsLayerOpening { leaves, multiproof })
}

/// Canonical fixed-length bytes for the selected fold/query proof segment.
pub fn encode_selected_fold_query_proof(
    proof: &MultilinearPcsFoldQueryProof,
    initial_queries: &[usize],
) -> Result<Vec<u8>, MultilinearPcsQueryError> {
    validate_selected_queries(initial_queries)?;
    if proof.main_layer_roots.len() != MLPCS_FOLD_ROUNDS
        || proof.main_layer_openings.len() != MLPCS_FOLD_ROUNDS
        || proof.final_values.len() != 8
        || proof
            .main_layer_roots
            .iter()
            .chain(core::iter::once(&proof.auxiliary_root))
            .any(|root| !root.as_bytes().iter().any(|byte| *byte != 0))
    {
        return Err(MultilinearPcsQueryError::Shape);
    }
    let layer_indices = selected_main_layer_value_indices(initial_queries)?;
    let auxiliary_indices = selected_auxiliary_value_indices(initial_queries)?;
    let mut encoded = Vec::with_capacity(selected_fold_query_proof_encoded_len());
    encoded.extend_from_slice(MLPCS_FOLD_QUERY_MAGIC);
    encoded.extend_from_slice(&MLPCS_FOLD_QUERY_VERSION.to_be_bytes());
    encoded.push(0);
    for root in &proof.main_layer_roots {
        encoded.extend_from_slice(root.as_bytes());
    }
    encoded.extend_from_slice(proof.auxiliary_root.as_bytes());
    let mut value_count = 1_usize << MLPCS_LDE_LOG_SIZE;
    for (round, opening) in proof.main_layer_openings.iter().enumerate() {
        encode_fixed_layer(
            &mut encoded,
            opening,
            value_count,
            &layer_indices[round],
            maximum_main_leaf_slots(value_count),
        )?;
        value_count /= 2;
    }
    encode_fixed_layer(
        &mut encoded,
        &proof.auxiliary_opening,
        1_usize << MLPCS_AUXILIARY_LDE_LOG_SIZE,
        &auxiliary_indices,
        maximum_auxiliary_leaf_slots(),
    )?;
    for value in &proof.final_values {
        encoded.extend_from_slice(&value.encode());
    }
    if encoded.len() != selected_fold_query_proof_encoded_len() {
        return Err(MultilinearPcsQueryError::EncodingLength);
    }
    Ok(encoded)
}

/// Strict parser whose geometry and node positions come only from public coin.
pub fn decode_selected_fold_query_proof(
    encoded: &[u8],
    initial_queries: &[usize],
) -> Result<MultilinearPcsFoldQueryProof, MultilinearPcsQueryError> {
    validate_selected_queries(initial_queries)?;
    if encoded.len() != selected_fold_query_proof_encoded_len() {
        return Err(MultilinearPcsQueryError::EncodingLength);
    }
    let layer_indices = selected_main_layer_value_indices(initial_queries)?;
    let auxiliary_indices = selected_auxiliary_value_indices(initial_queries)?;
    let mut reader = Reader::new(encoded);
    if reader.take(8)? != MLPCS_FOLD_QUERY_MAGIC {
        return Err(MultilinearPcsQueryError::Magic);
    }
    if u16::from_be_bytes(
        reader
            .take(2)?
            .try_into()
            .map_err(|_| MultilinearPcsQueryError::Truncated)?,
    ) != MLPCS_FOLD_QUERY_VERSION
    {
        return Err(MultilinearPcsQueryError::Version);
    }
    reader.zero_padding(1)?;
    let main_layer_roots = (0..MLPCS_FOLD_ROUNDS)
        .map(|_| reader.root())
        .collect::<Result<Vec<_>, _>>()?;
    let auxiliary_root = reader.root()?;
    let mut value_count = 1_usize << MLPCS_LDE_LOG_SIZE;
    let mut main_layer_openings = Vec::with_capacity(MLPCS_FOLD_ROUNDS);
    for indices in &layer_indices {
        main_layer_openings.push(decode_fixed_layer(
            &mut reader,
            value_count,
            indices,
            maximum_main_leaf_slots(value_count),
        )?);
        value_count /= 2;
    }
    let auxiliary_opening = decode_fixed_layer(
        &mut reader,
        1_usize << MLPCS_AUXILIARY_LDE_LOG_SIZE,
        &auxiliary_indices,
        maximum_auxiliary_leaf_slots(),
    )?;
    let final_values = (0..8)
        .map(|_| {
            Fp16::decode(reader.take(FP16_ENCODED_LENGTH)?)
                .map_err(|_| MultilinearPcsQueryError::Shape)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if reader.offset != encoded.len() {
        return Err(MultilinearPcsQueryError::TrailingBytes);
    }
    Ok(MultilinearPcsFoldQueryProof {
        main_layer_roots,
        auxiliary_root,
        main_layer_openings,
        auxiliary_opening,
        final_values,
    })
}

/// Canonical fixed-length bytes for the two-boundary shared fold/query proof.
pub fn encode_selected_batched_fold_query_proof(
    proof: &BatchedMultilinearPcsFoldQueryProof,
    initial_queries: &[usize],
) -> Result<Vec<u8>, MultilinearPcsQueryError> {
    validate_selected_queries(initial_queries)?;
    if proof.shared.main_layer_roots.len() != MLPCS_FOLD_ROUNDS - 1
        || proof.shared.main_layer_openings.len() != MLPCS_FOLD_ROUNDS - 1
        || proof.shared.final_values.len() != 8
        || [&proof.input_root, &proof.output_root]
            .into_iter()
            .chain(proof.shared.main_layer_roots.iter())
            .chain(core::iter::once(&proof.shared.auxiliary_root))
            .any(|root| !root.as_bytes().iter().any(|byte| *byte != 0))
    {
        return Err(MultilinearPcsQueryError::Shape);
    }
    let layer_indices =
        layer_value_indices(initial_queries, MLPCS_LDE_LOG_SIZE, MLPCS_FOLD_ROUNDS)?;
    let reduced_queries = initial_queries
        .iter()
        .map(|query| query % (1_usize << (MLPCS_LDE_LOG_SIZE - 1)))
        .collect::<Vec<_>>();
    let auxiliary_indices = {
        let mut positions = reduced_queries.clone();
        let mut value_count = 1_usize << (MLPCS_LDE_LOG_SIZE - 1);
        for _ in 0..usize::from(MLPCS_AUXILIARY_INJECTION_FOLD) - 1 {
            value_count /= 2;
            for position in &mut positions {
                *position %= value_count;
            }
        }
        positions.sort_unstable();
        positions.dedup();
        positions
    };
    let mut encoded = Vec::with_capacity(selected_batched_fold_query_proof_encoded_len());
    encoded.extend_from_slice(MLPCS_BATCHED_FOLD_QUERY_MAGIC);
    encoded.extend_from_slice(&MLPCS_BATCHED_FOLD_QUERY_VERSION.to_be_bytes());
    encoded.push(0);
    encoded.extend_from_slice(proof.input_root.as_bytes());
    encoded.extend_from_slice(proof.output_root.as_bytes());
    for root in &proof.shared.main_layer_roots {
        encoded.extend_from_slice(root.as_bytes());
    }
    encoded.extend_from_slice(proof.shared.auxiliary_root.as_bytes());
    let initial_value_count = 1_usize << MLPCS_LDE_LOG_SIZE;
    for opening in [&proof.input_initial_opening, &proof.output_initial_opening] {
        encode_fixed_layer(
            &mut encoded,
            opening,
            initial_value_count,
            &layer_indices[0],
            maximum_main_leaf_slots(initial_value_count),
        )?;
    }
    let mut value_count = initial_value_count / 2;
    for (opening, indices) in proof
        .shared
        .main_layer_openings
        .iter()
        .zip(layer_indices.iter().skip(1))
    {
        encode_fixed_layer(
            &mut encoded,
            opening,
            value_count,
            indices,
            maximum_main_leaf_slots(value_count),
        )?;
        value_count /= 2;
    }
    encode_fixed_layer(
        &mut encoded,
        &proof.shared.auxiliary_opening,
        1_usize << MLPCS_AUXILIARY_LDE_LOG_SIZE,
        &auxiliary_indices,
        maximum_auxiliary_leaf_slots(),
    )?;
    for value in &proof.shared.final_values {
        encoded.extend_from_slice(&value.encode());
    }
    if encoded.len() != selected_batched_fold_query_proof_encoded_len() {
        return Err(MultilinearPcsQueryError::EncodingLength);
    }
    Ok(encoded)
}

/// Strict two-boundary parser; all positions still come from public coin.
pub fn decode_selected_batched_fold_query_proof(
    encoded: &[u8],
    initial_queries: &[usize],
) -> Result<BatchedMultilinearPcsFoldQueryProof, MultilinearPcsQueryError> {
    validate_selected_queries(initial_queries)?;
    if encoded.len() != selected_batched_fold_query_proof_encoded_len() {
        return Err(MultilinearPcsQueryError::EncodingLength);
    }
    let layer_indices =
        layer_value_indices(initial_queries, MLPCS_LDE_LOG_SIZE, MLPCS_FOLD_ROUNDS)?;
    let reduced_queries = initial_queries
        .iter()
        .map(|query| query % (1_usize << (MLPCS_LDE_LOG_SIZE - 1)))
        .collect::<Vec<_>>();
    let auxiliary_indices = {
        let mut positions = reduced_queries;
        let mut value_count = 1_usize << (MLPCS_LDE_LOG_SIZE - 1);
        for _ in 0..usize::from(MLPCS_AUXILIARY_INJECTION_FOLD) - 1 {
            value_count /= 2;
            for position in &mut positions {
                *position %= value_count;
            }
        }
        positions.sort_unstable();
        positions.dedup();
        positions
    };
    let mut reader = Reader::new(encoded);
    if reader.take(8)? != MLPCS_BATCHED_FOLD_QUERY_MAGIC {
        return Err(MultilinearPcsQueryError::Magic);
    }
    if u16::from_be_bytes(
        reader
            .take(2)?
            .try_into()
            .map_err(|_| MultilinearPcsQueryError::Truncated)?,
    ) != MLPCS_BATCHED_FOLD_QUERY_VERSION
    {
        return Err(MultilinearPcsQueryError::Version);
    }
    reader.zero_padding(1)?;
    let input_root = reader.root()?;
    let output_root = reader.root()?;
    let main_layer_roots = (0..MLPCS_FOLD_ROUNDS - 1)
        .map(|_| reader.root())
        .collect::<Result<Vec<_>, _>>()?;
    let auxiliary_root = reader.root()?;
    let initial_value_count = 1_usize << MLPCS_LDE_LOG_SIZE;
    let input_initial_opening = decode_fixed_layer(
        &mut reader,
        initial_value_count,
        &layer_indices[0],
        maximum_main_leaf_slots(initial_value_count),
    )?;
    let output_initial_opening = decode_fixed_layer(
        &mut reader,
        initial_value_count,
        &layer_indices[0],
        maximum_main_leaf_slots(initial_value_count),
    )?;
    let mut value_count = initial_value_count / 2;
    let mut main_layer_openings = Vec::with_capacity(MLPCS_FOLD_ROUNDS - 1);
    for indices in layer_indices.iter().skip(1) {
        main_layer_openings.push(decode_fixed_layer(
            &mut reader,
            value_count,
            indices,
            maximum_main_leaf_slots(value_count),
        )?);
        value_count /= 2;
    }
    let auxiliary_opening = decode_fixed_layer(
        &mut reader,
        1_usize << MLPCS_AUXILIARY_LDE_LOG_SIZE,
        &auxiliary_indices,
        maximum_auxiliary_leaf_slots(),
    )?;
    let final_values = (0..8)
        .map(|_| {
            Fp16::decode(reader.take(FP16_ENCODED_LENGTH)?)
                .map_err(|_| MultilinearPcsQueryError::Shape)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if reader.offset != encoded.len() {
        return Err(MultilinearPcsQueryError::TrailingBytes);
    }
    Ok(BatchedMultilinearPcsFoldQueryProof {
        input_root,
        output_root,
        input_initial_opening,
        output_initial_opening,
        shared: MultilinearPcsFoldQueryProof {
            main_layer_roots,
            auxiliary_root,
            main_layer_openings,
            auxiliary_opening,
            final_values,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::M31;
    use crate::multilinear_pcs::{
        evaluate_multilinear_coefficients, evaluate_univariate_lde,
        fold_multiplicative_batch_layer, fold_multiplicative_fri_layer,
    };
    #[cfg(feature = "parallel")]
    use alloc::format;
    use alloc::vec;

    fn fp(value: u32) -> Fp16 {
        Fp16::from_m31(M31::from_canonical(value).unwrap())
    }

    fn leaf_payload(first: u32) -> [u8; MLPCS_LEAF_PAYLOAD_BYTES] {
        let opening = MultilinearPcsLeafOpening {
            leaf_index: 0,
            values: core::array::from_fn(|index| fp(first + index as u32)),
        };
        opening.payload()
    }

    #[test]
    fn post_commitment_query_expansion_is_fixed_and_bounded() {
        let session = [9_u8; 64];
        let first = derive_selected_query_positions(&session, fp(41)).unwrap();
        let replay = derive_selected_query_positions(&session, fp(41)).unwrap();
        let changed = derive_selected_query_positions(&session, fp(43)).unwrap();
        assert_eq!(first, replay);
        assert_ne!(first, changed);
        assert_eq!(first.len(), MLPCS_UNIQUE_QUERY_COUNT);
        assert!(
            first
                .iter()
                .all(|position| *position < 1_usize << MLPCS_LDE_LOG_SIZE)
        );
        assert_eq!(
            derive_selected_query_positions(&[0_u8; 64], fp(41)),
            Err(MultilinearPcsQueryError::Shape)
        );
    }

    #[test]
    fn bounded_parallel_commitment_root_matches_recomputed_tree() {
        for value_count in [16, 64] {
            let values = (0..value_count)
                .map(|value| fp(value + 1))
                .collect::<Vec<_>>();
            let parallel = commit_layer_root_streaming(&values).unwrap();
            let (recomputed, _) =
                build_recomputed_layer_opening(values.len(), leaf_payloads(&values), &[0]).unwrap();
            assert_eq!(parallel, recomputed);
        }
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn file_backed_opening_and_mix_match_memory_and_reject_noncanonical_values() {
        let values = (0..64).map(|value| fp(value + 1)).collect::<Vec<_>>();
        let outputs = (0..64).map(|value| fp(value + 101)).collect::<Vec<_>>();
        let encode = |items: &[Fp16]| {
            items
                .iter()
                .flat_map(|value| value.encode())
                .collect::<Vec<_>>()
        };
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir();
        let input_path = directory.join(format!("bl-mlpcs-input-{}-{nonce}", std::process::id()));
        let output_path = directory.join(format!("bl-mlpcs-output-{}-{nonce}", std::process::id()));
        std::fs::write(&input_path, encode(&values)).unwrap();
        std::fs::write(&output_path, encode(&outputs)).unwrap();
        let indices = [1_usize, 18, 63];
        let memory = build_parallel_layer_opening(&values, &indices, 4).unwrap();
        let file = build_file_layer_opening(&input_path, values.len(), &indices).unwrap();
        assert_eq!(file, memory);
        let mixing = fp(211);
        let mixed = mix_file_codewords(&input_path, &output_path, values.len(), mixing).unwrap();
        assert_eq!(
            mixed,
            values
                .iter()
                .copied()
                .zip(outputs.iter().copied())
                .map(|(input, output)| input + mixing * output)
                .collect::<Vec<_>>()
        );
        let mut malformed = encode(&values);
        malformed[..4].copy_from_slice(&crate::field::M31_MODULUS.to_le_bytes());
        std::fs::write(&input_path, malformed).unwrap();
        assert_eq!(
            build_file_layer_opening(&input_path, values.len(), &indices),
            Err(MultilinearPcsQueryError::Shape)
        );
        std::fs::remove_file(input_path).unwrap();
        std::fs::remove_file(output_path).unwrap();
    }

    fn synthetic_opening(
        value_count: usize,
        value_indices: &[usize],
    ) -> MultilinearPcsLayerOpening {
        let leaf_count = value_count / MLPCS_VALUES_PER_LEAF;
        let selected = selected_leaf_indices(value_count, value_indices).unwrap();
        let frontier_count = canonical_frontier_positions(leaf_count, &selected)
            .unwrap()
            .len();
        MultilinearPcsLayerOpening {
            leaves: selected
                .iter()
                .copied()
                .map(|leaf_index| MultilinearPcsLeafOpening {
                    leaf_index,
                    values: [Fp16::ZERO; MLPCS_VALUES_PER_LEAF],
                })
                .collect(),
            multiproof: CanonicalMerkleMultiProof::from_parts(
                leaf_count,
                &selected,
                vec![[7_u8; 64]; frontier_count],
            )
            .unwrap(),
        }
    }

    #[test]
    fn canonical_layer_opening_authenticates_only_derived_leaves() {
        let payloads = [
            leaf_payload(1),
            leaf_payload(101),
            leaf_payload(201),
            leaf_payload(301),
        ];
        let expected_indices = [1, 2, 18, 18, 63];
        let (root, opening) =
            build_recomputed_layer_opening(64, payloads, &expected_indices).unwrap();
        verify_layer_opening(&opening, &root, 64, &expected_indices).unwrap();
        assert_eq!(opening.leaves.len(), 3);
        assert_eq!(opened_value(&opening, 18).unwrap(), fp(103));

        let mut changed = opening.clone();
        changed.leaves[1].values[2] = changed.leaves[1].values[2] + Fp16::ONE;
        assert_eq!(
            verify_layer_opening(&changed, &root, 64, &expected_indices),
            Err(MultilinearPcsQueryError::Authentication)
        );
        assert_eq!(
            verify_layer_opening(&opening, &root, 64, &[1, 18]),
            Err(MultilinearPcsQueryError::LeafOrder)
        );
    }

    #[test]
    fn selected_query_geometry_preserves_multiplicity_before_deduplication() {
        let queries = (0..MLPCS_UNIQUE_QUERY_COUNT)
            .map(|index| (index * 65_537) % (1_usize << MLPCS_LDE_LOG_SIZE))
            .collect::<Vec<_>>();
        let layers = selected_main_layer_value_indices(&queries).unwrap();
        assert_eq!(layers.len(), 22);
        assert!(layers.iter().all(|indices| !indices.is_empty()));
        assert!(layers[21].iter().all(|index| *index < 16));
        let auxiliary = selected_auxiliary_value_indices(&queries).unwrap();
        assert!(
            auxiliary
                .iter()
                .all(|index| *index < 1_usize << MLPCS_AUXILIARY_LDE_LOG_SIZE)
        );
        assert_eq!(
            selected_main_layer_value_indices(&queries[..472]),
            Err(MultilinearPcsQueryError::QueryCount {
                expected: 473,
                actual: 472
            })
        );
    }

    #[test]
    fn independent_fold_query_verifier_rejects_mutated_openings() {
        let main_coefficients = [fp(2), fp(3), fp(5), fp(7)];
        let auxiliary_coefficients = [fp(11), fp(13)];
        let challenges = [fp(17), fp(19)];
        let mixing = fp(23);
        let main0 = evaluate_univariate_lde(&main_coefficients, 4).unwrap();
        let auxiliary = evaluate_univariate_lde(&auxiliary_coefficients, 4).unwrap();
        let main_terminal =
            evaluate_multilinear_coefficients(&main_coefficients, &challenges).unwrap();
        let auxiliary_terminal =
            evaluate_multilinear_coefficients(&auxiliary_coefficients, &challenges[1..]).unwrap();
        let root0 = derive_two_adic_root(6).unwrap();
        let main1 = fold_multiplicative_batch_layer(
            &main0,
            root0,
            challenges[0],
            Some((&auxiliary, mixing)),
        )
        .unwrap();
        let final_values =
            fold_multiplicative_fri_layer(&main1, root0.square(), challenges[1]).unwrap();
        assert!(final_values.iter().all(|value| *value == final_values[0]));

        let queries = [1, 35, 1];
        let proof = build_fold_query_proof_geometry(
            main0,
            auxiliary,
            &challenges,
            mixing,
            &queries,
            6,
            5,
            1,
        )
        .unwrap();
        assert_eq!(proof.main_layer_roots.len(), 2);
        assert_eq!(proof.final_values, final_values);
        let main_root0 = proof.main_layer_roots[0];
        let auxiliary_root = proof.auxiliary_root;
        verify_fold_query_proof_geometry(
            &proof,
            main_root0,
            auxiliary_root,
            &challenges,
            mixing,
            main_terminal,
            auxiliary_terminal,
            &queries,
            6,
            5,
            1,
        )
        .unwrap();

        let mut changed = proof.clone();
        changed.main_layer_openings[1].leaves[0].values[0] =
            changed.main_layer_openings[1].leaves[0].values[0] + Fp16::ONE;
        assert!(matches!(
            verify_fold_query_proof_geometry(
                &changed,
                main_root0,
                auxiliary_root,
                &challenges,
                mixing,
                main_terminal,
                auxiliary_terminal,
                &queries,
                6,
                5,
                1,
            ),
            Err(MultilinearPcsQueryError::Authentication)
                | Err(MultilinearPcsQueryError::FoldMismatch)
        ));
    }

    #[test]
    fn selected_fixed_length_codec_roundtrips_and_rejects_padding_mutation() {
        let queries = vec![1_usize; MLPCS_UNIQUE_QUERY_COUNT];
        let indices = selected_main_layer_value_indices(&queries).unwrap();
        let auxiliary_indices = selected_auxiliary_value_indices(&queries).unwrap();
        let mut value_count = 1_usize << MLPCS_LDE_LOG_SIZE;
        let main_layer_openings = indices
            .iter()
            .map(|layer| {
                let opening = synthetic_opening(value_count, layer);
                value_count /= 2;
                opening
            })
            .collect::<Vec<_>>();
        let proof = MultilinearPcsFoldQueryProof {
            main_layer_roots: (1..=MLPCS_FOLD_ROUNDS)
                .map(|ordinal| RootHash::from_bytes([ordinal as u8; 64]))
                .collect(),
            auxiliary_root: RootHash::from_bytes([99; 64]),
            main_layer_openings,
            auxiliary_opening: synthetic_opening(
                1_usize << MLPCS_AUXILIARY_LDE_LOG_SIZE,
                &auxiliary_indices,
            ),
            final_values: vec![Fp16::ZERO; 8],
        };
        let encoded = encode_selected_fold_query_proof(&proof, &queries).unwrap();
        assert_eq!(encoded.len(), selected_fold_query_proof_encoded_len());
        assert_eq!(
            decode_selected_fold_query_proof(&encoded, &queries).unwrap(),
            proof
        );
        assert_eq!(
            decode_selected_fold_query_proof(&encoded[..encoded.len() - 1], &queries),
            Err(MultilinearPcsQueryError::EncodingLength)
        );

        let header_and_roots = 8 + 2 + 1 + (MLPCS_FOLD_ROUNDS + 1) * 64;
        let actual_first_layer_leaves = proof.main_layer_openings[0].leaves.len();
        assert!(actual_first_layer_leaves < maximum_main_leaf_slots(1 << MLPCS_LDE_LOG_SIZE));
        let mut changed = encoded;
        changed[header_and_roots + actual_first_layer_leaves * MLPCS_LEAF_PAYLOAD_BYTES] = 1;
        assert_eq!(
            decode_selected_fold_query_proof(&changed, &queries),
            Err(MultilinearPcsQueryError::NonZeroPadding)
        );
    }

    #[test]
    fn fixed_frontier_envelope_matches_exhaustive_small_trees() {
        for leaf_count in [2_usize, 4, 8, 16] {
            let mut exact_maximum = vec![0_usize; leaf_count + 1];
            for mask in 1_usize..1_usize << leaf_count {
                let selected = (0..leaf_count)
                    .filter(|index| (mask >> index) & 1 == 1)
                    .collect::<Vec<_>>();
                let frontier = canonical_frontier_positions(leaf_count, &selected)
                    .unwrap()
                    .len();
                exact_maximum[selected.len()] = exact_maximum[selected.len()].max(frontier);
            }
            let mut observed = 0_usize;
            for (maximum_opened, exact) in exact_maximum.iter().copied().enumerate().skip(1) {
                observed = observed.max(exact);
                assert_eq!(maximum_frontier_slots(leaf_count, maximum_opened), observed);
            }
        }
    }
}
