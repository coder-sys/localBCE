//! Canonical global multiproofs for ordinary Merkle-backed FRI layers.
//!
//! This is the v2 FRI-opening adapter, not a replacement proof grammar yet.
//! It preserves the full ordered public-coin query list (including repeated
//! queries) while deriving each layer's unique leaf set and Merkle frontier.
//! No caller supplies Merkle coordinates.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::binding_root_v2::{
    BindingMerkleMultiProofV2, BindingMerkleTreeV2, BindingRootV2, BindingRootV2Error,
};
use crate::field::Fp16;
use crate::fri_pipeline::{FriPipeline, layer_payload};
use crate::merkle::RootHash;
use crate::merkle_multiproof::{
    CanonicalMerkleMultiProof, CanonicalMerkleMultiProofError, CanonicalMerkleNodePosition,
    CanonicalMerkleOpening, build_recomputed_canonical_multiproof, canonical_frontier_positions,
};

pub const MAX_FRI_MULTIPROOF_QUERIES: usize = 1_024;
pub const FRI_LAYER_MULTIPROOF_MAGIC: &[u8; 8] = b"BLPQFM01";
pub const FRI_LAYER_MULTIPROOF_VERSION: u16 = 1;
const MAX_FRI_LAYER_MULTIPROOF_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriLayerCanonicalMultiproof {
    pub log_size: u8,
    pub selected_indices: Vec<usize>,
    pub opened_values: Vec<Fp16>,
    pub proof: CanonicalMerkleMultiProof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriPipelineCanonicalMultiproofs {
    /// Ordered public-coin query list; duplicates are intentional and retained.
    pub query_indices: Vec<usize>,
    pub layers: Vec<FriLayerCanonicalMultiproof>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FriLayerMultiproofError {
    Binding(BindingRootV2Error),
    Merkle(CanonicalMerkleMultiProofError),
    Shape,
    Query,
    Authentication,
    Encoding,
}

impl From<BindingRootV2Error> for FriLayerMultiproofError {
    fn from(value: BindingRootV2Error) -> Self {
        Self::Binding(value)
    }
}

impl FriPipelineCanonicalMultiproofs {
    /// Return the canonically authenticated pair for one fold round.
    ///
    /// The lookup is by verifier-derived coordinates; no prover-supplied
    /// ordering or per-query Merkle path is consulted.
    pub fn opened_pair(
        &self,
        round: usize,
        pair_start: usize,
    ) -> Result<[Fp16; 2], FriLayerMultiproofError> {
        if pair_start & 1 != 0 {
            return Err(FriLayerMultiproofError::Query);
        }
        let layer = self
            .layers
            .get(round)
            .ok_or(FriLayerMultiproofError::Shape)?;
        let right_index = pair_start
            .checked_add(1)
            .ok_or(FriLayerMultiproofError::Query)?;
        let left_position = layer
            .selected_indices
            .binary_search(&pair_start)
            .map_err(|_| FriLayerMultiproofError::Query)?;
        let right_position = layer
            .selected_indices
            .binary_search(&right_index)
            .map_err(|_| FriLayerMultiproofError::Query)?;
        Ok([
            *layer
                .opened_values
                .get(left_position)
                .ok_or(FriLayerMultiproofError::Shape)?,
            *layer
                .opened_values
                .get(right_position)
                .ok_or(FriLayerMultiproofError::Shape)?,
        ])
    }

    /// Encode only values and the canonical frontier. Query indices and layer
    /// geometry remain verifier-authoritative inputs and are not prover bytes.
    pub fn encoded(&self) -> Result<Vec<u8>, FriLayerMultiproofError> {
        if self.layers.is_empty() || self.layers.len() > 29 {
            return Err(FriLayerMultiproofError::Shape);
        }
        let mut output = Vec::new();
        output.extend_from_slice(FRI_LAYER_MULTIPROOF_MAGIC);
        output.extend_from_slice(&FRI_LAYER_MULTIPROOF_VERSION.to_be_bytes());
        push_u32(&mut output, self.layers.len())?;
        for (round, layer) in self.layers.iter().enumerate() {
            let leaf_count = checked_layer_leaf_count(layer.log_size)?;
            let expected_indices =
                selected_indices_for_layer(&self.query_indices, round, leaf_count)?;
            if layer.selected_indices != expected_indices
                || layer.opened_values.len() != expected_indices.len()
                || layer.proof.leaf_count() != leaf_count
            {
                return Err(FriLayerMultiproofError::Shape);
            }
            let expected_frontier =
                canonical_frontier_positions(leaf_count, &expected_indices)?.len();
            if layer.proof.frontier_digests().len() != expected_frontier {
                return Err(FriLayerMultiproofError::Shape);
            }
            output.push(layer.log_size);
            push_u32(&mut output, layer.opened_values.len())?;
            for value in &layer.opened_values {
                output.extend_from_slice(&value.encode());
            }
            let frontier = layer.proof.frontier_bytes();
            push_u32(&mut output, frontier.len())?;
            output.extend_from_slice(&frontier);
            if output.len() > MAX_FRI_LAYER_MULTIPROOF_BYTES {
                return Err(FriLayerMultiproofError::Encoding);
            }
        }
        Ok(output)
    }

    /// Decode with verifier-supplied query and layer geometry. Coordinates and
    /// opening counts are reconstructed, not trusted from the wire.
    pub fn decode(
        encoded: &[u8],
        expected_query_indices: &[usize],
        expected_layer_log_sizes: &[u8],
    ) -> Result<Self, FriLayerMultiproofError> {
        if expected_query_indices.is_empty()
            || expected_query_indices.len() > MAX_FRI_MULTIPROOF_QUERIES
            || expected_layer_log_sizes.is_empty()
            || expected_layer_log_sizes.len() > 29
        {
            return Err(FriLayerMultiproofError::Query);
        }
        let mut reader = Reader::new(encoded)?;
        if reader.take(8)? != FRI_LAYER_MULTIPROOF_MAGIC
            || reader.u16()? != FRI_LAYER_MULTIPROOF_VERSION
        {
            return Err(FriLayerMultiproofError::Encoding);
        }
        if reader.u32()? != expected_layer_log_sizes.len() {
            return Err(FriLayerMultiproofError::Shape);
        }
        let mut layers = Vec::with_capacity(expected_layer_log_sizes.len());
        for (round, expected_log_size) in expected_layer_log_sizes.iter().copied().enumerate() {
            if reader.take(1)?[0] != expected_log_size {
                return Err(FriLayerMultiproofError::Shape);
            }
            let leaf_count = checked_layer_leaf_count(expected_log_size)?;
            let selected_indices =
                selected_indices_for_layer(expected_query_indices, round, leaf_count)?;
            if reader.u32()? != selected_indices.len() {
                return Err(FriLayerMultiproofError::Shape);
            }
            let opened_values = (0..selected_indices.len())
                .map(|_| {
                    Fp16::decode(reader.take(64)?).map_err(|_| FriLayerMultiproofError::Encoding)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let frontier_length = reader.u32()?;
            let expected_frontier =
                canonical_frontier_positions(leaf_count, &selected_indices)?.len();
            if frontier_length != expected_frontier * 64 {
                return Err(FriLayerMultiproofError::Shape);
            }
            let frontier = reader.take(frontier_length)?;
            let proof = CanonicalMerkleMultiProof::from_frontier_bytes(
                leaf_count,
                &selected_indices,
                frontier,
            )?;
            layers.push(FriLayerCanonicalMultiproof {
                log_size: expected_log_size,
                selected_indices,
                opened_values,
                proof,
            });
        }
        reader.finish()?;
        Ok(Self {
            query_indices: expected_query_indices.to_vec(),
            layers,
        })
    }
}

impl From<CanonicalMerkleMultiProofError> for FriLayerMultiproofError {
    fn from(value: CanonicalMerkleMultiProofError) -> Self {
        Self::Merkle(value)
    }
}

fn push_u32(output: &mut Vec<u8>, value: usize) -> Result<(), FriLayerMultiproofError> {
    output.extend_from_slice(
        &u32::try_from(value)
            .map_err(|_| FriLayerMultiproofError::Encoding)?
            .to_be_bytes(),
    );
    Ok(())
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Result<Self, FriLayerMultiproofError> {
        if input.len() > MAX_FRI_LAYER_MULTIPROOF_BYTES {
            return Err(FriLayerMultiproofError::Encoding);
        }
        Ok(Self { input, offset: 0 })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], FriLayerMultiproofError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(FriLayerMultiproofError::Encoding)?;
        if end > self.input.len() {
            return Err(FriLayerMultiproofError::Encoding);
        }
        let value = &self.input[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, FriLayerMultiproofError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| FriLayerMultiproofError::Encoding)?,
        ))
    }

    fn u32(&mut self) -> Result<usize, FriLayerMultiproofError> {
        usize::try_from(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| FriLayerMultiproofError::Encoding)?,
        ))
        .map_err(|_| FriLayerMultiproofError::Encoding)
    }

    fn finish(self) -> Result<(), FriLayerMultiproofError> {
        if self.offset != self.input.len() {
            return Err(FriLayerMultiproofError::Encoding);
        }
        Ok(())
    }
}

fn checked_layer_leaf_count(log_size: u8) -> Result<usize, FriLayerMultiproofError> {
    if log_size == 0 || log_size > 30 {
        return Err(FriLayerMultiproofError::Shape);
    }
    1_usize
        .checked_shl(u32::from(log_size - 1))
        .ok_or(FriLayerMultiproofError::Shape)
}

pub(crate) fn selected_indices_for_layer(
    query_indices: &[usize],
    round: usize,
    leaf_count: usize,
) -> Result<Vec<usize>, FriLayerMultiproofError> {
    if query_indices.is_empty() || query_indices.len() > MAX_FRI_MULTIPROOF_QUERIES {
        return Err(FriLayerMultiproofError::Query);
    }
    let shift = u32::try_from(round.checked_add(1).ok_or(FriLayerMultiproofError::Query)?)
        .map_err(|_| FriLayerMultiproofError::Query)?;
    let mut selected = BTreeSet::new();
    for query in query_indices {
        let layer_index = query
            .checked_shr(shift)
            .ok_or(FriLayerMultiproofError::Query)?;
        let pair_start = layer_index & !1;
        let pair_end = pair_start
            .checked_add(1)
            .ok_or(FriLayerMultiproofError::Query)?;
        if pair_end >= leaf_count {
            return Err(FriLayerMultiproofError::Query);
        }
        selected.insert(pair_start);
        selected.insert(pair_end);
    }
    Ok(selected.into_iter().collect())
}

/// Compact already-materialized v1 FRI layer openings without trusting any
/// prover-supplied coordinates. This is the migration bridge used to compare
/// v1 and v2 bytes before changing the authoritative proof grammar.
pub fn compact_fri_layer_openings(
    query_layers: &[&[crate::fri_pipeline::FriPipelineLayerOpening]],
    expected_query_indices: &[usize],
) -> Result<FriPipelineCanonicalMultiproofs, FriLayerMultiproofError> {
    if query_layers.len() != expected_query_indices.len()
        || expected_query_indices.is_empty()
        || expected_query_indices.len() > MAX_FRI_MULTIPROOF_QUERIES
    {
        return Err(FriLayerMultiproofError::Query);
    }
    let layer_count = query_layers
        .first()
        .ok_or(FriLayerMultiproofError::Shape)?
        .len();
    if layer_count == 0
        || query_layers
            .iter()
            .any(|layers| layers.len() != layer_count)
    {
        return Err(FriLayerMultiproofError::Shape);
    }
    let mut compacted = Vec::with_capacity(layer_count);
    for round in 0..layer_count {
        let log_size = query_layers[0][round].log_size;
        let leaf_count = checked_layer_leaf_count(log_size)?;
        let selected_indices =
            selected_indices_for_layer(expected_query_indices, round, leaf_count)?;
        let mut values = BTreeMap::new();
        let mut frontier = BTreeMap::new();
        for (query_index, layers) in expected_query_indices.iter().zip(query_layers) {
            let layer = &layers[round];
            if layer.log_size != log_size {
                return Err(FriLayerMultiproofError::Shape);
            }
            for (index, value, path) in [
                (layer.left_proof.leaf_index(), layer.left, &layer.left_proof),
                (
                    layer.right_proof.leaf_index(),
                    layer.right,
                    &layer.right_proof,
                ),
            ] {
                let expected_pair = (*query_index >> (round + 1)) & !1;
                if index != expected_pair && index != expected_pair + 1 {
                    return Err(FriLayerMultiproofError::Query);
                }
                if let Some(existing) = values.insert(index, value)
                    && existing != value
                {
                    return Err(FriLayerMultiproofError::Authentication);
                }
                let mut node_index = index;
                for (level, digest) in path.siblings().iter().copied().enumerate() {
                    frontier.insert(
                        CanonicalMerkleNodePosition {
                            level: u8::try_from(level)
                                .map_err(|_| FriLayerMultiproofError::Shape)?,
                            index: node_index ^ 1,
                        },
                        digest,
                    );
                    node_index >>= 1;
                }
            }
        }
        if values.keys().copied().collect::<Vec<_>>() != selected_indices {
            return Err(FriLayerMultiproofError::Query);
        }
        let frontier_positions = canonical_frontier_positions(leaf_count, &selected_indices)?;
        let frontier_digests = frontier_positions
            .iter()
            .map(|position| {
                frontier
                    .get(position)
                    .copied()
                    .ok_or(FriLayerMultiproofError::Authentication)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let opened_values = selected_indices
            .iter()
            .map(|index| values[index])
            .collect::<Vec<_>>();
        let proof =
            CanonicalMerkleMultiProof::from_parts(leaf_count, &selected_indices, frontier_digests)?;
        compacted.push(FriLayerCanonicalMultiproof {
            log_size,
            selected_indices,
            opened_values,
            proof,
        });
    }
    Ok(FriPipelineCanonicalMultiproofs {
        query_indices: expected_query_indices.to_vec(),
        layers: compacted,
    })
}

/// Build one recomputed canonical multiproof per FRI layer from prover values.
pub fn build_fri_layer_multiproofs(
    fold_log_sizes: &[u8],
    folded_layers: &[Vec<Fp16>],
    layer_roots: &[RootHash],
    query_indices: &[usize],
) -> Result<FriPipelineCanonicalMultiproofs, FriLayerMultiproofError> {
    if fold_log_sizes.len() != folded_layers.len() || layer_roots.len() != folded_layers.len() {
        return Err(FriLayerMultiproofError::Shape);
    }
    let mut layers = Vec::with_capacity(folded_layers.len());
    for (round, ((log_size, values), expected_root)) in fold_log_sizes
        .iter()
        .copied()
        .zip(folded_layers)
        .zip(layer_roots)
        .enumerate()
    {
        let leaf_count = values.len();
        if log_size == 0 || leaf_count != 1_usize << (log_size - 1) {
            return Err(FriLayerMultiproofError::Shape);
        }
        let selected_indices = selected_indices_for_layer(query_indices, round, leaf_count)?;
        let (observed_root, proof) = build_recomputed_canonical_multiproof(
            leaf_count,
            values
                .iter()
                .copied()
                .map(|value| layer_payload(log_size, value)),
            &selected_indices,
        )?;
        if &observed_root != expected_root {
            return Err(FriLayerMultiproofError::Authentication);
        }
        let opened_values = selected_indices
            .iter()
            .map(|index| values[*index])
            .collect();
        layers.push(FriLayerCanonicalMultiproof {
            log_size,
            selected_indices,
            opened_values,
            proof,
        });
    }
    Ok(FriPipelineCanonicalMultiproofs {
        query_indices: query_indices.to_vec(),
        layers,
    })
}

/// Convenience wrapper over the prover's committed FRI cascade.
pub fn build_fri_pipeline_layer_multiproofs(
    pipeline: &FriPipeline,
    query_indices: &[usize],
) -> Result<FriPipelineCanonicalMultiproofs, FriLayerMultiproofError> {
    build_fri_layer_multiproofs(
        &pipeline.cascade.fold_log_sizes,
        &pipeline.cascade.folded_layers,
        &pipeline.layer_roots,
        query_indices,
    )
}

/// Verify that the global layer openings are exactly those induced by queries.
pub fn verify_fri_pipeline_layer_multiproofs(
    proof: &FriPipelineCanonicalMultiproofs,
    expected_query_indices: &[usize],
    expected_layer_roots: &[RootHash],
) -> Result<bool, FriLayerMultiproofError> {
    if proof.query_indices != expected_query_indices
        || proof.layers.len() != expected_layer_roots.len()
    {
        return Err(FriLayerMultiproofError::Shape);
    }
    for (round, (layer, root)) in proof.layers.iter().zip(expected_layer_roots).enumerate() {
        let leaf_count = 1_usize
            .checked_shl(u32::from(layer.log_size.saturating_sub(1)))
            .ok_or(FriLayerMultiproofError::Shape)?;
        if layer.log_size == 0 || layer.opened_values.len() != layer.selected_indices.len() {
            return Err(FriLayerMultiproofError::Shape);
        }
        let expected_indices =
            selected_indices_for_layer(expected_query_indices, round, leaf_count)?;
        if layer.selected_indices != expected_indices {
            return Err(FriLayerMultiproofError::Query);
        }
        let openings = layer
            .selected_indices
            .iter()
            .copied()
            .zip(layer.opened_values.iter().copied())
            .map(|(index, value)| CanonicalMerkleOpening {
                index,
                payload: layer_payload(layer.log_size, value),
            })
            .collect::<Vec<_>>();
        if !layer.proof.verify(leaf_count, &openings, root)? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub const FRI_LAYER_BINDING_MULTIPROOF_V2_MAGIC: &[u8; 8] = b"BLB2FM02";
pub const FRI_LAYER_BINDING_MULTIPROOF_V2_VERSION: u16 = 2;

/// One native BindingRootV2 FRI-layer opening set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriLayerBindingMultiproofV2 {
    pub log_size: u8,
    pub selected_indices: Vec<usize>,
    pub opened_values: Vec<Fp16>,
    pub proof: BindingMerkleMultiProofV2,
}

/// Native BindingRootV2 FRI openings for every fold layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriPipelineBindingMultiproofsV2 {
    pub query_indices: Vec<usize>,
    pub layers: Vec<FriLayerBindingMultiproofV2>,
}

impl FriPipelineBindingMultiproofsV2 {
    pub fn opened_pair(
        &self,
        round: usize,
        pair_start: usize,
    ) -> Result<[Fp16; 2], FriLayerMultiproofError> {
        if pair_start & 1 != 0 {
            return Err(FriLayerMultiproofError::Query);
        }
        let layer = self
            .layers
            .get(round)
            .ok_or(FriLayerMultiproofError::Shape)?;
        let right = pair_start
            .checked_add(1)
            .ok_or(FriLayerMultiproofError::Query)?;
        let left_position = layer
            .selected_indices
            .binary_search(&pair_start)
            .map_err(|_| FriLayerMultiproofError::Query)?;
        let right_position = layer
            .selected_indices
            .binary_search(&right)
            .map_err(|_| FriLayerMultiproofError::Query)?;
        Ok([
            *layer
                .opened_values
                .get(left_position)
                .ok_or(FriLayerMultiproofError::Shape)?,
            *layer
                .opened_values
                .get(right_position)
                .ok_or(FriLayerMultiproofError::Shape)?,
        ])
    }

    pub fn encode(&self) -> Result<Vec<u8>, FriLayerMultiproofError> {
        if self.layers.is_empty() || self.layers.len() > 29 {
            return Err(FriLayerMultiproofError::Shape);
        }
        let mut output = Vec::new();
        output.extend_from_slice(FRI_LAYER_BINDING_MULTIPROOF_V2_MAGIC);
        output.extend_from_slice(&FRI_LAYER_BINDING_MULTIPROOF_V2_VERSION.to_be_bytes());
        output.extend_from_slice(
            &u16::try_from(self.layers.len())
                .map_err(|_| FriLayerMultiproofError::Encoding)?
                .to_be_bytes(),
        );
        for (round, layer) in self.layers.iter().enumerate() {
            let leaf_count = checked_layer_leaf_count(layer.log_size)?;
            let expected_indices =
                selected_indices_for_layer(&self.query_indices, round, leaf_count)?;
            if layer.selected_indices != expected_indices
                || layer.opened_values.len() != expected_indices.len()
                || layer.proof.leaf_count()
                    != u64::try_from(leaf_count).map_err(|_| FriLayerMultiproofError::Shape)?
                || layer.proof.selected_indices()
                    != expected_indices
                        .iter()
                        .copied()
                        .map(|index| {
                            u64::try_from(index).map_err(|_| FriLayerMultiproofError::Shape)
                        })
                        .collect::<Result<Vec<_>, _>>()?
            {
                return Err(FriLayerMultiproofError::Shape);
            }
            let proof = layer.proof.encode()?;
            output.push(layer.log_size);
            output.extend_from_slice(&[0_u8; 3]);
            output.extend_from_slice(
                &u32::try_from(proof.len())
                    .map_err(|_| FriLayerMultiproofError::Encoding)?
                    .to_be_bytes(),
            );
            output.extend_from_slice(&proof);
            for value in &layer.opened_values {
                output.extend_from_slice(&value.encode());
            }
            if output.len() > MAX_FRI_LAYER_MULTIPROOF_BYTES {
                return Err(FriLayerMultiproofError::Encoding);
            }
        }
        Ok(output)
    }

    /// Decode using only verifier-derived query coordinates and fold geometry.
    /// The exact proof length and BindingRootV2 caps are checked before values
    /// or frontier vectors are allocated.
    pub fn decode(
        encoded: &[u8],
        expected_query_indices: &[usize],
        expected_layer_log_sizes: &[u8],
    ) -> Result<Self, FriLayerMultiproofError> {
        if expected_query_indices.is_empty()
            || expected_query_indices.len() > MAX_FRI_MULTIPROOF_QUERIES
            || expected_layer_log_sizes.is_empty()
            || expected_layer_log_sizes.len() > 29
            || encoded.len() > MAX_FRI_LAYER_MULTIPROOF_BYTES
        {
            return Err(FriLayerMultiproofError::Shape);
        }
        let mut reader = Reader::new(encoded)?;
        if reader.take(8)? != FRI_LAYER_BINDING_MULTIPROOF_V2_MAGIC
            || reader.u16()? != FRI_LAYER_BINDING_MULTIPROOF_V2_VERSION
            || usize::from(reader.u16()?) != expected_layer_log_sizes.len()
        {
            return Err(FriLayerMultiproofError::Encoding);
        }
        let mut layers = Vec::with_capacity(expected_layer_log_sizes.len());
        for (round, expected_log_size) in expected_layer_log_sizes.iter().copied().enumerate() {
            if reader.take(1)?[0] != expected_log_size || reader.take(3)? != [0_u8; 3] {
                return Err(FriLayerMultiproofError::Shape);
            }
            let leaf_count = checked_layer_leaf_count(expected_log_size)?;
            let selected_indices =
                selected_indices_for_layer(expected_query_indices, round, leaf_count)?;
            let proof_length = reader.u32()?;
            let minimum = crate::binding_root_v2::BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES;
            if proof_length < minimum
                || proof_length > crate::binding_root_v2::MAX_BINDING_MERKLE_MULTIPROOF_V2_BYTES
            {
                return Err(FriLayerMultiproofError::Encoding);
            }
            let proof = BindingMerkleMultiProofV2::decode(reader.take(proof_length)?)?;
            let expected_u64 = selected_indices
                .iter()
                .copied()
                .map(|index| u64::try_from(index).map_err(|_| FriLayerMultiproofError::Shape))
                .collect::<Result<Vec<_>, _>>()?;
            if proof.leaf_count()
                != u64::try_from(leaf_count).map_err(|_| FriLayerMultiproofError::Shape)?
                || proof.selected_indices() != expected_u64
            {
                return Err(FriLayerMultiproofError::Query);
            }
            let value_bytes = selected_indices
                .len()
                .checked_mul(64)
                .ok_or(FriLayerMultiproofError::Encoding)?;
            let encoded_values = reader.take(value_bytes)?;
            let opened_values = encoded_values
                .chunks_exact(64)
                .map(|value| Fp16::decode(value).map_err(|_| FriLayerMultiproofError::Encoding))
                .collect::<Result<Vec<_>, _>>()?;
            layers.push(FriLayerBindingMultiproofV2 {
                log_size: expected_log_size,
                selected_indices,
                opened_values,
                proof,
            });
        }
        reader.finish()?;
        Ok(Self {
            query_indices: expected_query_indices.to_vec(),
            layers,
        })
    }
}

pub fn binding_fri_layer_tree_v2(
    log_size: u8,
    values: &[Fp16],
) -> Result<BindingMerkleTreeV2, FriLayerMultiproofError> {
    if values.len() != checked_layer_leaf_count(log_size)? {
        return Err(FriLayerMultiproofError::Shape);
    }
    let payloads = values
        .iter()
        .copied()
        .map(|value| layer_payload(log_size, value))
        .collect::<Vec<_>>();
    Ok(BindingMerkleTreeV2::from_payloads(&payloads)?)
}

pub fn binding_fri_layer_root_v2(
    log_size: u8,
    values: &[Fp16],
) -> Result<BindingRootV2, FriLayerMultiproofError> {
    Ok(binding_fri_layer_tree_v2(log_size, values)?.root())
}

pub fn build_fri_layer_binding_multiproofs_v2(
    fold_log_sizes: &[u8],
    folded_layers: &[Vec<Fp16>],
    expected_roots: &[BindingRootV2],
    query_indices: &[usize],
) -> Result<FriPipelineBindingMultiproofsV2, FriLayerMultiproofError> {
    if fold_log_sizes.len() != folded_layers.len()
        || expected_roots.len() != folded_layers.len()
        || folded_layers.is_empty()
    {
        return Err(FriLayerMultiproofError::Shape);
    }
    let mut layers = Vec::with_capacity(folded_layers.len());
    for (round, ((log_size, values), expected_root)) in fold_log_sizes
        .iter()
        .copied()
        .zip(folded_layers)
        .zip(expected_roots)
        .enumerate()
    {
        let tree = binding_fri_layer_tree_v2(log_size, values)?;
        if tree.root() != *expected_root {
            return Err(FriLayerMultiproofError::Authentication);
        }
        let leaf_count = values.len();
        let selected_indices = selected_indices_for_layer(query_indices, round, leaf_count)?;
        let selected_u64 = selected_indices
            .iter()
            .copied()
            .map(|index| u64::try_from(index).map_err(|_| FriLayerMultiproofError::Shape))
            .collect::<Result<Vec<_>, _>>()?;
        let proof = tree.prove(&selected_u64)?;
        let opened_values = selected_indices
            .iter()
            .map(|index| values[*index])
            .collect();
        layers.push(FriLayerBindingMultiproofV2 {
            log_size,
            selected_indices,
            opened_values,
            proof,
        });
    }
    Ok(FriPipelineBindingMultiproofsV2 {
        query_indices: query_indices.to_vec(),
        layers,
    })
}

pub fn verify_fri_layer_binding_multiproofs_v2(
    proof: &FriPipelineBindingMultiproofsV2,
    expected_query_indices: &[usize],
    expected_roots: &[BindingRootV2],
) -> Result<(), FriLayerMultiproofError> {
    if proof.query_indices != expected_query_indices || proof.layers.len() != expected_roots.len() {
        return Err(FriLayerMultiproofError::Shape);
    }
    for (round, (layer, root)) in proof.layers.iter().zip(expected_roots).enumerate() {
        let leaf_count = checked_layer_leaf_count(layer.log_size)?;
        let expected_indices =
            selected_indices_for_layer(expected_query_indices, round, leaf_count)?;
        if layer.selected_indices != expected_indices
            || layer.opened_values.len() != expected_indices.len()
        {
            return Err(FriLayerMultiproofError::Query);
        }
        let payloads = layer
            .opened_values
            .iter()
            .copied()
            .map(|value| layer_payload(layer.log_size, value))
            .collect::<Vec<_>>();
        layer.proof.verify_payloads(&payloads, root)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::M31;
    use crate::merkle::MerkleTree;
    use alloc::vec;

    fn values(count: usize, offset: u32) -> Vec<Fp16> {
        (0..count)
            .map(|index| Fp16::from_m31(M31::from_canonical(offset + index as u32).unwrap()))
            .collect()
    }

    fn roots(log_sizes: &[u8], layers: &[Vec<Fp16>]) -> Vec<RootHash> {
        log_sizes
            .iter()
            .copied()
            .zip(layers)
            .map(|(log_size, layer)| {
                let payloads = layer
                    .iter()
                    .copied()
                    .map(|value| layer_payload(log_size, value))
                    .collect::<Vec<_>>();
                MerkleTree::from_leaf_payloads(
                    &payloads.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                )
                .unwrap()
                .root()
            })
            .collect()
    }

    #[test]
    fn duplicate_queries_are_preserved_but_layer_leaves_are_deduplicated() {
        let logs = vec![5, 4, 3];
        let layers = vec![values(16, 10), values(8, 30), values(4, 50)];
        let roots = roots(&logs, &layers);
        let queries = vec![1, 1, 6, 17];
        let proof = build_fri_layer_multiproofs(&logs, &layers, &roots, &queries).unwrap();
        assert_eq!(proof.query_indices, queries);
        assert_eq!(proof.layers[0].selected_indices, vec![0, 1, 2, 3, 8, 9]);
        assert!(verify_fri_pipeline_layer_multiproofs(&proof, &queries, &roots).unwrap());
        let encoded = proof.encoded().unwrap();
        let decoded = FriPipelineCanonicalMultiproofs::decode(&encoded, &queries, &logs).unwrap();
        assert_eq!(decoded, proof);
        assert!(matches!(
            FriPipelineCanonicalMultiproofs::decode(
                &(encoded.clone().into_iter().chain([0]).collect::<Vec<_>>()),
                &queries,
                &logs,
            ),
            Err(FriLayerMultiproofError::Encoding)
        ));
        let mut forged = encoded.clone();
        forged[14] ^= 1;
        assert!(FriPipelineCanonicalMultiproofs::decode(&forged, &queries, &logs).is_err());
    }

    #[test]
    fn verifier_rejects_query_or_opening_substitution() {
        let logs = vec![5, 4, 3];
        let layers = vec![values(16, 10), values(8, 30), values(4, 50)];
        let roots = roots(&logs, &layers);
        let queries = vec![1, 1, 6, 17];
        let proof = build_fri_layer_multiproofs(&logs, &layers, &roots, &queries).unwrap();

        assert_eq!(
            verify_fri_pipeline_layer_multiproofs(&proof, &[1, 6, 17], &roots),
            Err(FriLayerMultiproofError::Shape)
        );
        let mut forged_value = proof.clone();
        forged_value.layers[0].opened_values[0] = Fp16::from_m31(M31::from_canonical(999).unwrap());
        assert!(!verify_fri_pipeline_layer_multiproofs(&forged_value, &queries, &roots).unwrap());
        let mut forged_index = proof.clone();
        forged_index.layers[0].selected_indices[0] = 1;
        assert_eq!(
            verify_fri_pipeline_layer_multiproofs(&forged_index, &queries, &roots),
            Err(FriLayerMultiproofError::Query)
        );
    }

    #[test]
    fn v1_layer_openings_compact_to_the_same_global_frontier() {
        let logs = vec![5, 4, 3];
        let layers = vec![values(16, 10), values(8, 30), values(4, 50)];
        let roots = roots(&logs, &layers);
        let queries = vec![1, 1, 6, 17];
        let query_layers = queries
            .iter()
            .map(|query| {
                logs.iter()
                    .copied()
                    .zip(&layers)
                    .enumerate()
                    .map(|(round, (log_size, values))| {
                        let payloads = values
                            .iter()
                            .copied()
                            .map(|value| layer_payload(log_size, value))
                            .collect::<Vec<_>>();
                        let tree = MerkleTree::from_leaf_payloads(
                            &payloads.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                        )
                        .unwrap();
                        let layer_index = query >> (round + 1);
                        let layer_pair = layer_index & !1;
                        crate::fri_pipeline::FriPipelineLayerOpening {
                            log_size,
                            left: values[layer_pair],
                            right: values[layer_pair + 1],
                            left_proof: tree.proof(layer_pair).unwrap(),
                            right_proof: tree.proof(layer_pair + 1).unwrap(),
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let query_layer_refs = query_layers.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let compact = compact_fri_layer_openings(&query_layer_refs, &queries).unwrap();
        assert!(verify_fri_pipeline_layer_multiproofs(&compact, &queries, &roots).unwrap());
    }
}
