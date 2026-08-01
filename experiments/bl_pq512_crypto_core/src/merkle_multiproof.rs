//! Canonical theorem-neutral multiproofs for ordinary PCS Merkle trees.
//!
//! This module is deliberately limited to the domain-513/514/515 binary tree
//! implemented by [`crate::merkle`].  Cross-domain commitments insert domain
//! rows at multiple heights and MUST NOT use this reconstruction algorithm.
//! Node coordinates are derived from the verifier-authoritative leaf count and
//! strictly sorted opened indices; they are never accepted from proof bytes.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use crate::merkle::{
    ChildHash, LeafHash, MerkleError, MerkleTree, NodeHash, RootHash, hash_leaf, hash_node,
    hash_root,
};

/// The selected proof geometry admits evaluation logs no larger than 30, so
/// a committed folded FRI layer has at most `2^(30-1)` leaves.
pub const MAX_FRI_LAYER_LEAF_COUNT: usize = 1 << 29;
/// At most two leaves are opened for each of the bounded 1,024 public queries.
pub const MAX_FRI_LAYER_OPENED_LEAVES: usize = 2_048;
/// Conservative allocation bound for a 2,048-leaf frontier at depth 29.
pub const MAX_FRI_LAYER_FRONTIER_DIGESTS: usize =
    MAX_FRI_LAYER_OPENED_LEAVES * MAX_FRI_LAYER_LEAF_COUNT.trailing_zeros() as usize;

/// A verifier-derived binary-tree node coordinate.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CanonicalMerkleNodePosition {
    /// Zero is the leaf level; increasing values move toward the root.
    pub level: u8,
    /// Left-to-right node index at `level`.
    pub index: usize,
}

/// One selected leaf payload.  The index list must be strictly increasing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalMerkleOpening {
    pub index: usize,
    pub payload: Vec<u8>,
}

/// A canonical ordinary-Merkle multiproof.
///
/// Frontier positions are intentionally absent: the verifier derives their
/// exact bottom-up/left-to-right order from the expected opened indices.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalMerkleMultiProof {
    leaf_count: usize,
    frontier_digests: Vec<[u8; 64]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalMerkleMultiProofError {
    Merkle(MerkleError),
    LeafCount,
    OpeningCount,
    IndexOrder,
    IndexOutOfBounds,
    FrontierCount { expected: usize, actual: usize },
    FrontierEncoding,
    PayloadCount { expected: usize, actual: usize },
    NodeConflict,
    Reconstruction,
}

impl From<MerkleError> for CanonicalMerkleMultiProofError {
    fn from(value: MerkleError) -> Self {
        Self::Merkle(value)
    }
}

fn validate_leaf_count(leaf_count: usize) -> Result<usize, CanonicalMerkleMultiProofError> {
    if leaf_count == 0 || !leaf_count.is_power_of_two() || leaf_count > MAX_FRI_LAYER_LEAF_COUNT {
        return Err(CanonicalMerkleMultiProofError::LeafCount);
    }
    Ok(leaf_count.trailing_zeros() as usize)
}

fn validate_indices(
    leaf_count: usize,
    selected_indices: &[usize],
) -> Result<usize, CanonicalMerkleMultiProofError> {
    let depth = validate_leaf_count(leaf_count)?;
    if selected_indices.is_empty()
        || selected_indices.len() > MAX_FRI_LAYER_OPENED_LEAVES
        || selected_indices.len() > leaf_count
    {
        return Err(CanonicalMerkleMultiProofError::OpeningCount);
    }
    if selected_indices.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(CanonicalMerkleMultiProofError::IndexOrder);
    }
    if selected_indices.iter().any(|index| *index >= leaf_count) {
        return Err(CanonicalMerkleMultiProofError::IndexOutOfBounds);
    }
    Ok(depth)
}

/// Derive the one canonical proof-node order for a selected leaf set.
pub fn canonical_frontier_positions(
    leaf_count: usize,
    selected_indices: &[usize],
) -> Result<Vec<CanonicalMerkleNodePosition>, CanonicalMerkleMultiProofError> {
    let depth = validate_indices(leaf_count, selected_indices)?;
    let mut active = selected_indices.to_vec();
    let mut frontier = Vec::new();
    for level in 0..depth {
        for index in active.iter().copied() {
            let sibling = index ^ 1;
            if active.binary_search(&sibling).is_err() {
                frontier.push(CanonicalMerkleNodePosition {
                    level: u8::try_from(level)
                        .map_err(|_| CanonicalMerkleMultiProofError::LeafCount)?,
                    index: sibling,
                });
            }
        }
        let mut parents = Vec::with_capacity(active.len());
        for index in active {
            let parent = index >> 1;
            if parents.last().copied() != Some(parent) {
                parents.push(parent);
            }
        }
        active = parents;
    }
    if active.as_slice() != [0] || frontier.len() > MAX_FRI_LAYER_FRONTIER_DIGESTS {
        return Err(CanonicalMerkleMultiProofError::Reconstruction);
    }
    Ok(frontier)
}

impl CanonicalMerkleMultiProof {
    /// Strictly construct a proof for the verifier-derived selected indices.
    pub fn from_parts(
        leaf_count: usize,
        selected_indices: &[usize],
        frontier_digests: Vec<[u8; 64]>,
    ) -> Result<Self, CanonicalMerkleMultiProofError> {
        let expected = canonical_frontier_positions(leaf_count, selected_indices)?.len();
        if frontier_digests.len() != expected {
            return Err(CanonicalMerkleMultiProofError::FrontierCount {
                expected,
                actual: frontier_digests.len(),
            });
        }
        Ok(Self {
            leaf_count,
            frontier_digests,
        })
    }

    pub const fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    pub fn frontier_digests(&self) -> &[[u8; 64]] {
        &self.frontier_digests
    }

    /// Canonical context-free frontier payload.  Tree size and positions are
    /// verifier inputs and therefore intentionally absent from these bytes.
    pub fn frontier_bytes(&self) -> Vec<u8> {
        self.frontier_digests
            .iter()
            .flat_map(|digest| digest.iter().copied())
            .collect()
    }

    /// Parse an exact frontier payload with no attacker-supplied coordinates.
    pub fn from_frontier_bytes(
        leaf_count: usize,
        selected_indices: &[usize],
        encoded: &[u8],
    ) -> Result<Self, CanonicalMerkleMultiProofError> {
        if !encoded.len().is_multiple_of(64) {
            return Err(CanonicalMerkleMultiProofError::FrontierEncoding);
        }
        let digests = encoded
            .chunks_exact(64)
            .map(|chunk| {
                chunk
                    .try_into()
                    .map_err(|_| CanonicalMerkleMultiProofError::FrontierEncoding)
            })
            .collect::<Result<Vec<[u8; 64]>, _>>()?;
        Self::from_parts(leaf_count, selected_indices, digests)
    }

    /// Independently reconstruct the domain-515 root from canonical openings.
    pub fn verify(
        &self,
        expected_leaf_count: usize,
        openings: &[CanonicalMerkleOpening],
        expected_root: &RootHash,
    ) -> Result<bool, CanonicalMerkleMultiProofError> {
        let indices = openings
            .iter()
            .map(|opening| opening.index)
            .collect::<Vec<_>>();
        let leaf_hashes = openings
            .iter()
            .map(|opening| {
                hash_leaf(&opening.payload)
                    .map(LeafHash::into_bytes)
                    .map_err(CanonicalMerkleMultiProofError::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.verify_leaf_hashes(expected_leaf_count, &indices, &leaf_hashes, expected_root)
    }

    /// Independently reconstruct the domain-515 root from already
    /// authenticated leaf digests.
    ///
    /// This entry point is for protocols whose verifier-authoritative leaf
    /// grammar uses a typed domain other than the ordinary domain-513 payload
    /// framing. The caller must recompute every supplied digest from the exact
    /// protocol leaf bytes and metadata before invoking this method.
    pub fn verify_leaf_hashes(
        &self,
        expected_leaf_count: usize,
        selected_indices: &[usize],
        leaf_hashes: &[[u8; 64]],
        expected_root: &RootHash,
    ) -> Result<bool, CanonicalMerkleMultiProofError> {
        if self.leaf_count != expected_leaf_count {
            return Err(CanonicalMerkleMultiProofError::LeafCount);
        }
        let depth = validate_indices(expected_leaf_count, selected_indices)?;
        if leaf_hashes.len() != selected_indices.len() {
            return Err(CanonicalMerkleMultiProofError::PayloadCount {
                expected: selected_indices.len(),
                actual: leaf_hashes.len(),
            });
        }
        let frontier_positions =
            canonical_frontier_positions(expected_leaf_count, selected_indices)?;
        if self.frontier_digests.len() != frontier_positions.len() {
            return Err(CanonicalMerkleMultiProofError::FrontierCount {
                expected: frontier_positions.len(),
                actual: self.frontier_digests.len(),
            });
        }

        let mut active = BTreeMap::new();
        for (&index, &leaf_hash) in selected_indices.iter().zip(leaf_hashes) {
            if active.insert(index, leaf_hash).is_some() {
                return Err(CanonicalMerkleMultiProofError::NodeConflict);
            }
        }
        let mut frontier_offset = 0_usize;
        for level in 0..depth {
            let level_u8 =
                u8::try_from(level).map_err(|_| CanonicalMerkleMultiProofError::LeafCount)?;
            while frontier_offset < frontier_positions.len()
                && frontier_positions[frontier_offset].level == level_u8
            {
                let position = frontier_positions[frontier_offset];
                if active
                    .insert(position.index, self.frontier_digests[frontier_offset])
                    .is_some()
                {
                    return Err(CanonicalMerkleMultiProofError::NodeConflict);
                }
                frontier_offset += 1;
            }
            if active.len() % 2 != 0 {
                return Err(CanonicalMerkleMultiProofError::Reconstruction);
            }
            let nodes = active.into_iter().collect::<Vec<_>>();
            let mut parents = BTreeMap::new();
            for pair in nodes.chunks_exact(2) {
                let (left_index, left) = pair[0];
                let (right_index, right) = pair[1];
                if left_index & 1 != 0 || right_index != left_index + 1 {
                    return Err(CanonicalMerkleMultiProofError::Reconstruction);
                }
                let parent = if level == 0 {
                    hash_node(
                        ChildHash::Leaf(LeafHash::from_bytes(left)),
                        ChildHash::Leaf(LeafHash::from_bytes(right)),
                    )
                    .into_bytes()
                } else {
                    hash_node(
                        ChildHash::Node(NodeHash::from_bytes(left)),
                        ChildHash::Node(NodeHash::from_bytes(right)),
                    )
                    .into_bytes()
                };
                if parents.insert(left_index >> 1, parent).is_some() {
                    return Err(CanonicalMerkleMultiProofError::NodeConflict);
                }
            }
            active = parents;
        }
        if frontier_offset != frontier_positions.len()
            || active.len() != 1
            || !active.contains_key(&0)
        {
            return Err(CanonicalMerkleMultiProofError::Reconstruction);
        }
        let top = active[&0];
        let root = if expected_leaf_count == 1 {
            hash_root(1, ChildHash::Leaf(LeafHash::from_bytes(top)))?
        } else {
            hash_root(
                u64::try_from(expected_leaf_count)
                    .map_err(|_| CanonicalMerkleMultiProofError::LeafCount)?,
                ChildHash::Node(NodeHash::from_bytes(top)),
            )?
        };
        Ok(root == *expected_root)
    }
}

/// Build a canonical proof from the existing fully retained Merkle tree.
pub fn build_retained_canonical_multiproof(
    payloads: &[&[u8]],
    selected_indices: &[usize],
) -> Result<(RootHash, CanonicalMerkleMultiProof), CanonicalMerkleMultiProofError> {
    let leaf_count = payloads.len();
    let tree = MerkleTree::from_leaf_payloads(payloads)?;
    build_canonical_multiproof_from_tree(&tree, leaf_count, selected_indices)
}

/// Build the byte-identical retained proof with bounded native workers.
#[cfg(feature = "parallel")]
pub fn build_retained_canonical_multiproof_parallel(
    payloads: &[&[u8]],
    selected_indices: &[usize],
    workers: usize,
) -> Result<(RootHash, CanonicalMerkleMultiProof), CanonicalMerkleMultiProofError> {
    let leaf_count = payloads.len();
    let tree = MerkleTree::from_leaf_payloads_parallel(payloads, workers)?;
    build_canonical_multiproof_from_tree(&tree, leaf_count, selected_indices)
}

/// Build the canonical proof from already authenticated leaf hashes while
/// retaining only the current and next Merkle levels.
#[cfg(feature = "parallel")]
pub fn build_bounded_canonical_multiproof_from_leaf_hashes_parallel(
    mut current: Vec<[u8; 64]>,
    selected_indices: &[usize],
    workers: usize,
) -> Result<(RootHash, CanonicalMerkleMultiProof), CanonicalMerkleMultiProofError> {
    let leaf_count = current.len();
    let depth = validate_indices(leaf_count, selected_indices)?;
    if workers == 0 {
        return Err(CanonicalMerkleMultiProofError::LeafCount);
    }
    let positions = canonical_frontier_positions(leaf_count, selected_indices)?;
    let mut frontier = vec![[0_u8; 64]; positions.len()];
    let mut filled = vec![false; positions.len()];
    for level in 0..depth {
        for (slot, position) in positions.iter().copied().enumerate() {
            if usize::from(position.level) == level {
                frontier[slot] = *current
                    .get(position.index)
                    .ok_or(CanonicalMerkleMultiProofError::Reconstruction)?;
                filled[slot] = true;
            }
        }
        let parent_count = current.len() / 2;
        let mut parents = vec![[0_u8; 64]; parent_count];
        let chunk = parent_count.div_ceil(workers.min(parent_count));
        std::thread::scope(|scope| {
            for (chunk_ordinal, output) in parents.chunks_mut(chunk).enumerate() {
                let first_parent = chunk_ordinal * chunk;
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
    }
    if current.len() != 1 || filled.iter().any(|value| !*value) {
        return Err(CanonicalMerkleMultiProofError::Reconstruction);
    }
    let top = if leaf_count == 1 {
        ChildHash::Leaf(LeafHash::from_bytes(current[0]))
    } else {
        ChildHash::Node(NodeHash::from_bytes(current[0]))
    };
    let root = hash_root(
        u64::try_from(leaf_count).map_err(|_| CanonicalMerkleMultiProofError::LeafCount)?,
        top,
    )?;
    Ok((
        root,
        CanonicalMerkleMultiProof {
            leaf_count,
            frontier_digests: frontier,
        },
    ))
}

fn build_canonical_multiproof_from_tree(
    tree: &MerkleTree,
    leaf_count: usize,
    selected_indices: &[usize],
) -> Result<(RootHash, CanonicalMerkleMultiProof), CanonicalMerkleMultiProofError> {
    let frontier_positions = canonical_frontier_positions(leaf_count, selected_indices)?;
    let mut available = BTreeMap::new();
    for selected in selected_indices.iter().copied() {
        let path = tree.proof(selected)?;
        let mut node_index = selected;
        for (level, digest) in path.siblings().iter().copied().enumerate() {
            let position = CanonicalMerkleNodePosition {
                level: u8::try_from(level)
                    .map_err(|_| CanonicalMerkleMultiProofError::LeafCount)?,
                index: node_index ^ 1,
            };
            if let Some(existing) = available.insert(position, digest)
                && existing != digest
            {
                return Err(CanonicalMerkleMultiProofError::NodeConflict);
            }
            node_index >>= 1;
        }
    }
    let frontier = frontier_positions
        .iter()
        .map(|position| {
            available
                .get(position)
                .copied()
                .ok_or(CanonicalMerkleMultiProofError::Reconstruction)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((
        tree.root(),
        CanonicalMerkleMultiProof::from_parts(leaf_count, selected_indices, frontier)?,
    ))
}

fn record_frontier_node(
    targets: &BTreeMap<CanonicalMerkleNodePosition, usize>,
    frontier: &mut [[u8; 64]],
    filled: &mut [bool],
    level: usize,
    index: usize,
    digest: [u8; 64],
) -> Result<(), CanonicalMerkleMultiProofError> {
    let position = CanonicalMerkleNodePosition {
        level: u8::try_from(level).map_err(|_| CanonicalMerkleMultiProofError::LeafCount)?,
        index,
    };
    if let Some(slot) = targets.get(&position).copied() {
        if filled[slot] {
            return Err(CanonicalMerkleMultiProofError::NodeConflict);
        }
        frontier[slot] = digest;
        filled[slot] = true;
    }
    Ok(())
}

/// Recompute the same canonical proof in one leaf-order pass with only a
/// logarithmic hash stack plus the exact proof frontier retained in memory.
pub fn build_recomputed_canonical_multiproof<I, P>(
    leaf_count: usize,
    payloads: I,
    selected_indices: &[usize],
) -> Result<(RootHash, CanonicalMerkleMultiProof), CanonicalMerkleMultiProofError>
where
    I: IntoIterator<Item = P>,
    P: AsRef<[u8]>,
{
    let depth = validate_indices(leaf_count, selected_indices)?;
    let positions = canonical_frontier_positions(leaf_count, selected_indices)?;
    let targets = positions
        .iter()
        .copied()
        .enumerate()
        .map(|(slot, position)| (position, slot))
        .collect::<BTreeMap<_, _>>();
    if targets.len() != positions.len() {
        return Err(CanonicalMerkleMultiProofError::NodeConflict);
    }
    let mut frontier = vec![[0_u8; 64]; positions.len()];
    let mut filled = vec![false; positions.len()];
    let mut stack = vec![None; depth + 1];
    let mut observed = 0_usize;

    for (leaf_index, payload) in payloads.into_iter().enumerate() {
        if leaf_index >= leaf_count {
            return Err(CanonicalMerkleMultiProofError::PayloadCount {
                expected: leaf_count,
                actual: leaf_index + 1,
            });
        }
        observed += 1;
        let mut current = hash_leaf(payload.as_ref())?.into_bytes();
        let mut node_index = leaf_index;
        let mut level = 0_usize;
        record_frontier_node(
            &targets,
            &mut frontier,
            &mut filled,
            level,
            node_index,
            current,
        )?;
        loop {
            if node_index & 1 == 0 {
                if stack[level].replace(current).is_some() {
                    return Err(CanonicalMerkleMultiProofError::NodeConflict);
                }
                break;
            }
            let left = stack[level]
                .take()
                .ok_or(CanonicalMerkleMultiProofError::Reconstruction)?;
            current = if level == 0 {
                hash_node(
                    ChildHash::Leaf(LeafHash::from_bytes(left)),
                    ChildHash::Leaf(LeafHash::from_bytes(current)),
                )
                .into_bytes()
            } else {
                hash_node(
                    ChildHash::Node(NodeHash::from_bytes(left)),
                    ChildHash::Node(NodeHash::from_bytes(current)),
                )
                .into_bytes()
            };
            node_index >>= 1;
            level += 1;
            record_frontier_node(
                &targets,
                &mut frontier,
                &mut filled,
                level,
                node_index,
                current,
            )?;
        }
    }
    if observed != leaf_count {
        return Err(CanonicalMerkleMultiProofError::PayloadCount {
            expected: leaf_count,
            actual: observed,
        });
    }
    if stack[..depth].iter().any(Option::is_some)
        || stack[depth].is_none()
        || filled.iter().any(|value| !*value)
    {
        return Err(CanonicalMerkleMultiProofError::Reconstruction);
    }
    let top = stack[depth].ok_or(CanonicalMerkleMultiProofError::Reconstruction)?;
    let root = if leaf_count == 1 {
        hash_root(1, ChildHash::Leaf(LeafHash::from_bytes(top)))?
    } else {
        hash_root(
            u64::try_from(leaf_count).map_err(|_| CanonicalMerkleMultiProofError::LeafCount)?,
            ChildHash::Node(NodeHash::from_bytes(top)),
        )?
    };
    Ok((
        root,
        CanonicalMerkleMultiProof::from_parts(leaf_count, selected_indices, frontier)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    fn payloads(count: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|index| alloc::format!("fri-kat-leaf-{index:02}").into_bytes())
            .collect()
    }

    fn openings(payloads: &[Vec<u8>], indices: &[usize]) -> Vec<CanonicalMerkleOpening> {
        indices
            .iter()
            .copied()
            .map(|index| CanonicalMerkleOpening {
                index,
                payload: payloads[index].clone(),
            })
            .collect()
    }

    #[test]
    fn retained_and_recomputed_proofs_are_byte_identical() {
        let payloads = payloads(32);
        let references = payloads.iter().map(Vec::as_slice).collect::<Vec<_>>();
        for indices in [
            vec![0, 1],
            vec![1, 6, 17, 30],
            vec![0, 1, 2, 3, 28, 29, 30, 31],
            (0..32).collect::<Vec<_>>(),
        ] {
            let (retained_root, retained) =
                build_retained_canonical_multiproof(&references, &indices).unwrap();
            let (recomputed_root, recomputed) = build_recomputed_canonical_multiproof(
                payloads.len(),
                payloads.iter().map(Vec::as_slice),
                &indices,
            )
            .unwrap();
            assert_eq!(retained_root, recomputed_root);
            assert_eq!(retained, recomputed);
            assert_eq!(retained.frontier_bytes(), recomputed.frontier_bytes());
            #[cfg(feature = "parallel")]
            {
                let leaf_hashes = payloads
                    .iter()
                    .map(|payload| hash_leaf(payload).unwrap().into_bytes())
                    .collect::<Vec<_>>();
                let (bounded_root, bounded) =
                    build_bounded_canonical_multiproof_from_leaf_hashes_parallel(
                        leaf_hashes,
                        &indices,
                        4,
                    )
                    .unwrap();
                assert_eq!(bounded_root, retained_root);
                assert_eq!(bounded, retained);
            }
            assert!(
                retained
                    .verify(
                        payloads.len(),
                        &openings(&payloads, &indices),
                        &retained_root
                    )
                    .unwrap()
            );
            let leaf_hashes = indices
                .iter()
                .map(|&index| hash_leaf(&payloads[index]).unwrap().into_bytes())
                .collect::<Vec<_>>();
            assert!(
                retained
                    .verify_leaf_hashes(payloads.len(), &indices, &leaf_hashes, &retained_root,)
                    .unwrap()
            );
            let mut mutated = leaf_hashes;
            mutated[0][0] ^= 1;
            assert!(
                !retained
                    .verify_leaf_hashes(payloads.len(), &indices, &mutated, &retained_root,)
                    .unwrap()
            );
        }
    }

    #[test]
    fn exact_frontier_order_is_bottom_up_then_left_to_right() {
        assert_eq!(
            canonical_frontier_positions(8, &[1, 2, 6]).unwrap(),
            vec![
                CanonicalMerkleNodePosition { level: 0, index: 0 },
                CanonicalMerkleNodePosition { level: 0, index: 3 },
                CanonicalMerkleNodePosition { level: 0, index: 7 },
                CanonicalMerkleNodePosition { level: 1, index: 2 },
            ]
        );
    }

    #[test]
    fn strict_bounds_and_canonical_indices_fail_closed() {
        assert_eq!(
            canonical_frontier_positions(0, &[0]),
            Err(CanonicalMerkleMultiProofError::LeafCount)
        );
        assert_eq!(
            canonical_frontier_positions(3, &[0]),
            Err(CanonicalMerkleMultiProofError::LeafCount)
        );
        assert_eq!(
            canonical_frontier_positions(MAX_FRI_LAYER_LEAF_COUNT + 1, &[0]),
            Err(CanonicalMerkleMultiProofError::LeafCount)
        );
        assert_eq!(
            canonical_frontier_positions(8, &[]),
            Err(CanonicalMerkleMultiProofError::OpeningCount)
        );
        assert_eq!(
            canonical_frontier_positions(8, &[1, 1]),
            Err(CanonicalMerkleMultiProofError::IndexOrder)
        );
        assert_eq!(
            canonical_frontier_positions(8, &[2, 1]),
            Err(CanonicalMerkleMultiProofError::IndexOrder)
        );
        assert_eq!(
            canonical_frontier_positions(8, &[8]),
            Err(CanonicalMerkleMultiProofError::IndexOutOfBounds)
        );
    }

    #[test]
    fn every_payload_and_frontier_mutation_is_rejected() {
        let payloads = payloads(8);
        let references = payloads.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let indices = [1, 2, 6];
        let (root, proof) = build_retained_canonical_multiproof(&references, &indices).unwrap();
        let mut opened = openings(&payloads, &indices);
        opened[1].payload[0] ^= 1;
        assert!(!proof.verify(8, &opened, &root).unwrap());

        let encoded = proof.frontier_bytes();
        assert_eq!(
            CanonicalMerkleMultiProof::from_frontier_bytes(
                8,
                &indices,
                &encoded[..encoded.len() - 1]
            ),
            Err(CanonicalMerkleMultiProofError::FrontierEncoding)
        );
        assert!(matches!(
            CanonicalMerkleMultiProof::from_frontier_bytes(
                8,
                &indices,
                &encoded[..encoded.len() - 64]
            ),
            Err(CanonicalMerkleMultiProofError::FrontierCount { .. })
        ));
        let mut extra = encoded.clone();
        extra.extend_from_slice(&[0_u8; 64]);
        assert!(matches!(
            CanonicalMerkleMultiProof::from_frontier_bytes(8, &indices, &extra),
            Err(CanonicalMerkleMultiProofError::FrontierCount { .. })
        ));
        let mut mutated = encoded.clone();
        mutated[0] ^= 1;
        let forged = CanonicalMerkleMultiProof::from_frontier_bytes(8, &indices, &mutated).unwrap();
        assert!(
            !forged
                .verify(8, &openings(&payloads, &indices), &root)
                .unwrap()
        );
        let mut swapped = encoded.clone();
        let mut first_digest = [0_u8; 64];
        let mut second_digest = [0_u8; 64];
        first_digest.copy_from_slice(&swapped[..64]);
        second_digest.copy_from_slice(&swapped[64..128]);
        swapped[..64].copy_from_slice(&second_digest);
        swapped[64..128].copy_from_slice(&first_digest);
        let forged = CanonicalMerkleMultiProof::from_frontier_bytes(8, &indices, &swapped).unwrap();
        assert!(
            !forged
                .verify(8, &openings(&payloads, &indices), &root)
                .unwrap()
        );
    }

    #[test]
    fn recomputation_rejects_short_and_long_sources() {
        let payloads = payloads(8);
        assert_eq!(
            build_recomputed_canonical_multiproof(
                8,
                payloads[..7].iter().map(Vec::as_slice),
                &[1, 2]
            ),
            Err(CanonicalMerkleMultiProofError::PayloadCount {
                expected: 8,
                actual: 7
            })
        );
        let mut long = payloads.clone();
        long.push(b"extra".to_vec());
        assert_eq!(
            build_recomputed_canonical_multiproof(8, long.iter().map(Vec::as_slice), &[1, 2]),
            Err(CanonicalMerkleMultiProofError::PayloadCount {
                expected: 8,
                actual: 9
            })
        );
    }

    #[test]
    fn cross_language_kat_is_stable() {
        let payloads = payloads(8);
        let references = payloads.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let (root, proof) = build_retained_canonical_multiproof(&references, &[1, 2, 6]).unwrap();
        assert_eq!(
            hex(root.as_bytes()),
            "8de11168450abee94788b12818af72f52a072960b59cb2896dc147b4681549790e30cd251b0ddded925c8d40582bb48cacc22668e368dcf0548bc74880f32d57"
        );
        assert_eq!(
            hex(&proof.frontier_bytes()),
            concat!(
                "be8a2e9c2089a30c93ae0571d771aa4d0876b13a407c9110a01a573bb15292d1",
                "122bbedf48595bab0f0693955e3d43f79d01d7d628cad1d280e179788473fc57",
                "3bc86473c6fbe0f3431a8ef5b2c8629aa6151fc757bbdd4272caa745618d9888",
                "ff5285adfbfd7527d59629f690b2201c49576be4ae945af5a93b29d5281c083c",
                "7cff721464d9023af7b07de7847ca2b02f7eef9c1ec64e814baa4964a67a8172",
                "6a912602235aea2f9587045aa5ba292428f501c9b9a06d7c747bb7879e18274a",
                "be86be8d8677314e90a4746d6cd5efe637519c6c44d7832cf2144baddcc396d6",
                "b8b9b2953f473afe0f2f3381c4e1103c069d12fbc7530df284171f3c8331d5a2"
            )
        );
    }

    fn hex(bytes: &[u8]) -> alloc::string::String {
        bytes
            .iter()
            .map(|byte| alloc::format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join("")
            .to_string()
    }
}
