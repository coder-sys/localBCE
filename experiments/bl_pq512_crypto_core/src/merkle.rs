//! Typed, full-width SHA3-512 PCS Merkle substrate.
//!
//! This module freezes domain-separated hash framing and strict tree/proof
//! behavior. It does not select a Circle-FRI leaf layout.

use core::fmt;

#[cfg(feature = "parallel")]
use alloc::vec;
use alloc::{collections::BTreeMap, vec::Vec};
use sha3::{Digest, Sha3_512};

/// `BL/PQ512/v1/PCS/MERKLE/EMPTY`.
pub const PCS_MERKLE_EMPTY_DOMAIN: u16 = 512;
/// `BL/PQ512/v1/PCS/MERKLE/LEAF`.
pub const PCS_MERKLE_LEAF_DOMAIN: u16 = 513;
/// `BL/PQ512/v1/PCS/MERKLE/NODE`.
pub const PCS_MERKLE_NODE_DOMAIN: u16 = 514;
/// `BL/PQ512/v1/PCS/MERKLE/ROOT`.
pub const PCS_MERKLE_ROOT_DOMAIN: u16 = 515;

const PCS_MAGIC: &[u8; 8] = b"BLPQPCS1";
const PCS_VERSION: u16 = 1;
const DIGEST_LENGTH: usize = 64;

macro_rules! typed_digest {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name([u8; DIGEST_LENGTH]);

        impl $name {
            /// Constructs the typed value from an exact full-width digest.
            pub const fn from_bytes(bytes: [u8; DIGEST_LENGTH]) -> Self {
                Self(bytes)
            }

            /// Borrows the exact full-width digest.
            pub const fn as_bytes(&self) -> &[u8; DIGEST_LENGTH] {
                &self.0
            }

            /// Returns the exact full-width digest.
            pub const fn into_bytes(self) -> [u8; DIGEST_LENGTH] {
                self.0
            }
        }
    };
}

typed_digest!(EmptyHash, "A domain-512 empty digest.");
typed_digest!(LeafHash, "A domain-513 leaf digest.");
typed_digest!(NodeHash, "A domain-514 internal-node digest.");
typed_digest!(RootHash, "A domain-515 tree-root digest.");

/// A typed child accepted by node and root hashing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildHash {
    /// A leaf-level child.
    Leaf(LeafHash),
    /// An internal-node child.
    Node(NodeHash),
    /// An explicitly empty child for a future pinned PCS layout.
    Empty(EmptyHash),
}

impl ChildHash {
    const fn bytes(self) -> [u8; DIGEST_LENGTH] {
        match self {
            Self::Leaf(value) => value.into_bytes(),
            Self::Node(value) => value.into_bytes(),
            Self::Empty(value) => value.into_bytes(),
        }
    }
}

/// Strict Merkle construction or proof-validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MerkleError {
    /// Tree construction received no leaves.
    EmptyTree,
    /// The leaf count was not a power of two.
    LeafCountNotPowerOfTwo { count: usize },
    /// A platform length could not fit the frozen u64 framing.
    LengthOverflow,
    /// A proof index was outside the tree.
    IndexOutOfBounds { index: usize, leaf_count: usize },
    /// The proof did not contain exactly one sibling per tree level.
    SiblingCountMismatch { expected: usize, actual: usize },
    /// A parallel construction requested no workers.
    ZeroWorkerCount,
    /// A parallel construction requires a power-of-two worker count.
    WorkerCountNotPowerOfTwo { count: usize },
    /// A parallel construction requested more workers than leaves.
    WorkerCountExceedsLeaves { workers: usize, leaves: usize },
    /// A requested frontier node is not present in the selected tree.
    FrontierTargetOutOfBounds {
        level: usize,
        index: usize,
        leaf_count: usize,
    },
    /// A requested frontier node was listed more than once.
    DuplicateFrontierTarget { level: usize, index: usize },
    /// The stateless traversal did not produce every requested frontier node.
    MissingFrontierTarget,
}

impl fmt::Display for MerkleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTree => formatter.write_str("PCS Merkle tree must be nonempty"),
            Self::LeafCountNotPowerOfTwo { count } => {
                write!(formatter, "leaf count {count} is not a power of two")
            }
            Self::LengthOverflow => formatter.write_str("length exceeds frozen u64 framing"),
            Self::IndexOutOfBounds { index, leaf_count } => write!(
                formatter,
                "leaf index {index} is outside tree with {leaf_count} leaves"
            ),
            Self::SiblingCountMismatch { expected, actual } => write!(
                formatter,
                "proof requires {expected} siblings, got {actual}"
            ),
            Self::ZeroWorkerCount => {
                formatter.write_str("parallel Merkle workers must be positive")
            }
            Self::WorkerCountNotPowerOfTwo { count } => {
                write!(
                    formatter,
                    "parallel Merkle worker count {count} is not a power of two"
                )
            }
            Self::WorkerCountExceedsLeaves { workers, leaves } => write!(
                formatter,
                "parallel Merkle worker count {workers} exceeds leaf count {leaves}"
            ),
            Self::FrontierTargetOutOfBounds {
                level,
                index,
                leaf_count,
            } => write!(
                formatter,
                "Merkle frontier target ({level}, {index}) is outside tree with {leaf_count} leaves"
            ),
            Self::DuplicateFrontierTarget { level, index } => {
                write!(
                    formatter,
                    "duplicate Merkle frontier target ({level}, {index})"
                )
            }
            Self::MissingFrontierTarget => {
                formatter.write_str("stateless Merkle traversal missed a requested frontier node")
            }
        }
    }
}

impl core::error::Error for MerkleError {}

/// Hashes the exact domain-512 empty preimage.
pub fn hash_empty() -> EmptyHash {
    EmptyHash(hash_parts(PCS_MERKLE_EMPTY_DOMAIN, &[]))
}

/// Hashes one length-framed leaf under domain 513.
pub fn hash_leaf(payload: &[u8]) -> Result<LeafHash, MerkleError> {
    let length = u64::try_from(payload.len()).map_err(|_| MerkleError::LengthOverflow)?;
    Ok(LeafHash(hash_parts(
        PCS_MERKLE_LEAF_DOMAIN,
        &[&length.to_be_bytes(), payload],
    )))
}

/// Hashes exactly two full-width typed children under domain 514.
pub fn hash_node(left: ChildHash, right: ChildHash) -> NodeHash {
    NodeHash(hash_node_bytes(&left.bytes(), &right.bytes()))
}

/// Wraps a power-of-two tree top and leaf count under domain 515.
pub fn hash_root(leaf_count: u64, top: ChildHash) -> Result<RootHash, MerkleError> {
    let count = usize::try_from(leaf_count).map_err(|_| MerkleError::LengthOverflow)?;
    validate_leaf_count(count)?;
    Ok(RootHash(hash_root_bytes(leaf_count, &top.bytes())))
}

/// One strict binary Merkle proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleProof {
    leaf_index: usize,
    leaf_count: usize,
    siblings: Vec<[u8; DIGEST_LENGTH]>,
}

impl MerkleProof {
    /// Returns the proven leaf index.
    pub const fn leaf_index(&self) -> usize {
        self.leaf_index
    }

    /// Returns the committed leaf count.
    pub const fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Returns bottom-up full-width siblings.
    pub fn siblings(&self) -> &[[u8; DIGEST_LENGTH]] {
        &self.siblings
    }

    /// Strictly constructs a parsed proof from exact full-width fields.
    pub fn from_parts(
        leaf_index: usize,
        leaf_count: usize,
        siblings: Vec<[u8; DIGEST_LENGTH]>,
    ) -> Result<Self, MerkleError> {
        validate_leaf_count(leaf_count)?;
        if leaf_index >= leaf_count {
            return Err(MerkleError::IndexOutOfBounds {
                index: leaf_index,
                leaf_count,
            });
        }
        let expected = tree_depth(leaf_count);
        if siblings.len() != expected {
            return Err(MerkleError::SiblingCountMismatch {
                expected,
                actual: siblings.len(),
            });
        }
        Ok(Self {
            leaf_index,
            leaf_count,
            siblings,
        })
    }

    /// Recomputes and compares the exact domain-515 root.
    pub fn verify(&self, payload: &[u8], expected_root: &RootHash) -> Result<bool, MerkleError> {
        validate_leaf_count(self.leaf_count)?;
        if self.leaf_index >= self.leaf_count {
            return Err(MerkleError::IndexOutOfBounds {
                index: self.leaf_index,
                leaf_count: self.leaf_count,
            });
        }
        let expected_siblings = tree_depth(self.leaf_count);
        if self.siblings.len() != expected_siblings {
            return Err(MerkleError::SiblingCountMismatch {
                expected: expected_siblings,
                actual: self.siblings.len(),
            });
        }

        let mut current = hash_leaf(payload)?.into_bytes();
        let mut index = self.leaf_index;
        for sibling in &self.siblings {
            current = if index & 1 == 0 {
                hash_node_bytes(&current, sibling)
            } else {
                hash_node_bytes(sibling, &current)
            };
            index >>= 1;
        }
        let leaf_count = u64::try_from(self.leaf_count).map_err(|_| MerkleError::LengthOverflow)?;
        Ok(hash_root_bytes(leaf_count, &current) == expected_root.into_bytes())
    }
}

/// A strict, nonempty, power-of-two binary PCS Merkle tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleTree {
    levels: Vec<Vec<[u8; DIGEST_LENGTH]>>,
    root: RootHash,
}

/// A root plus only the requested tree nodes, produced without retaining full Merkle levels.
///
/// Coordinates are `(level, index)`, where level zero is the leaf-digest level and increasing
/// levels move toward the root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatelessMerkleResult {
    root: RootHash,
    frontier: BTreeMap<(usize, usize), [u8; DIGEST_LENGTH]>,
}

impl StatelessMerkleResult {
    /// Returns the exact domain-515 tree root.
    pub const fn root(&self) -> RootHash {
        self.root
    }

    /// Returns the requested node digest at `(level, index)`, if present.
    pub fn frontier_node(&self, level: usize, index: usize) -> Option<&[u8; DIGEST_LENGTH]> {
        self.frontier.get(&(level, index))
    }

    /// Returns the number of distinct retained frontier nodes.
    pub fn frontier_len(&self) -> usize {
        self.frontier.len()
    }
}

/// Builds a root and selected query frontier with bounded memory and native worker threads.
///
/// Unlike [`MerkleTree::from_leaf_payloads_parallel`], this retains only one logarithmic hash
/// stack per worker plus the explicitly requested frontier. `payload_at` is evaluated exactly once
/// per leaf, in committed order within each deterministic contiguous worker range.
#[cfg(feature = "parallel")]
pub fn stateless_root_and_frontier_parallel<T, F>(
    leaf_count: usize,
    targets: &[(usize, usize)],
    workers: usize,
    payload_at: F,
) -> Result<StatelessMerkleResult, MerkleError>
where
    T: AsRef<[u8]> + Send,
    F: Fn(usize) -> T + Sync,
{
    validate_leaf_count(leaf_count)?;
    if workers == 0 {
        return Err(MerkleError::ZeroWorkerCount);
    }
    if !workers.is_power_of_two() {
        return Err(MerkleError::WorkerCountNotPowerOfTwo { count: workers });
    }
    if workers > leaf_count {
        return Err(MerkleError::WorkerCountExceedsLeaves {
            workers,
            leaves: leaf_count,
        });
    }
    let targets = validate_frontier_targets(leaf_count, targets)?;
    let chunk_len = leaf_count / workers;
    let chunk_log = tree_depth(chunk_len);
    let mut chunk_results = (0..workers).map(|_| None).collect::<Vec<_>>();

    std::thread::scope(|scope| {
        for (chunk_index, slot) in chunk_results.iter_mut().enumerate() {
            let targets = &targets;
            let payload_at = &payload_at;
            scope.spawn(move || {
                let start = chunk_index * chunk_len;
                *slot = Some(build_stateless_range(start, chunk_len, targets, payload_at));
            });
        }
    });

    let mut frontier = BTreeMap::new();
    let mut top_stack = vec![None; workers.ilog2() as usize + 1];
    for (chunk_index, result) in chunk_results.into_iter().enumerate() {
        let (mut current, local_frontier) =
            result.expect("scoped worker always writes its result")?;
        for (coordinate, digest) in local_frontier {
            if frontier.insert(coordinate, digest).is_some() {
                return Err(MerkleError::DuplicateFrontierTarget {
                    level: coordinate.0,
                    index: coordinate.1,
                });
            }
        }

        let mut level = chunk_log;
        let mut node_index = chunk_index;
        while node_index & 1 == 1 {
            let left = top_stack[level - chunk_log]
                .take()
                .ok_or(MerkleError::MissingFrontierTarget)?;
            current = hash_node_bytes(&left, &current);
            node_index >>= 1;
            level += 1;
            retain_frontier_node(&targets, &mut frontier, level, node_index, current)?;
        }
        if top_stack[level - chunk_log].replace(current).is_some() {
            return Err(MerkleError::MissingFrontierTarget);
        }
    }

    if top_stack[..top_stack.len() - 1].iter().any(Option::is_some) {
        return Err(MerkleError::MissingFrontierTarget);
    }
    let top = top_stack
        .last()
        .and_then(|entry| *entry)
        .ok_or(MerkleError::MissingFrontierTarget)?;
    if frontier.len() != targets.len() {
        return Err(MerkleError::MissingFrontierTarget);
    }
    let leaf_count_u64 = u64::try_from(leaf_count).map_err(|_| MerkleError::LengthOverflow)?;
    Ok(StatelessMerkleResult {
        root: RootHash(hash_root_bytes(leaf_count_u64, &top)),
        frontier,
    })
}

#[cfg(feature = "parallel")]
#[allow(clippy::type_complexity)]
fn build_stateless_range<T, F>(
    start: usize,
    count: usize,
    targets: &alloc::collections::BTreeSet<(usize, usize)>,
    payload_at: &F,
) -> Result<
    (
        [u8; DIGEST_LENGTH],
        BTreeMap<(usize, usize), [u8; DIGEST_LENGTH]>,
    ),
    MerkleError,
>
where
    T: AsRef<[u8]>,
    F: Fn(usize) -> T + Sync,
{
    let depth = tree_depth(count);
    let mut stack = vec![None; depth + 1];
    let mut frontier = BTreeMap::new();
    for local_leaf_index in 0..count {
        let leaf_index = start + local_leaf_index;
        let payload = payload_at(leaf_index);
        let mut current = hash_leaf(payload.as_ref())?.into_bytes();
        let mut level = 0;
        let mut local_node_index = local_leaf_index;
        let mut global_node_index = leaf_index;
        retain_frontier_node(targets, &mut frontier, level, global_node_index, current)?;
        while local_node_index & 1 == 1 {
            let left = stack[level]
                .take()
                .ok_or(MerkleError::MissingFrontierTarget)?;
            current = hash_node_bytes(&left, &current);
            local_node_index >>= 1;
            global_node_index >>= 1;
            level += 1;
            retain_frontier_node(targets, &mut frontier, level, global_node_index, current)?;
        }
        if stack[level].replace(current).is_some() {
            return Err(MerkleError::MissingFrontierTarget);
        }
    }
    if stack[..depth].iter().any(Option::is_some) {
        return Err(MerkleError::MissingFrontierTarget);
    }
    let top = stack[depth].ok_or(MerkleError::MissingFrontierTarget)?;
    Ok((top, frontier))
}

#[cfg(feature = "parallel")]
fn retain_frontier_node(
    targets: &alloc::collections::BTreeSet<(usize, usize)>,
    frontier: &mut BTreeMap<(usize, usize), [u8; DIGEST_LENGTH]>,
    level: usize,
    index: usize,
    digest: [u8; DIGEST_LENGTH],
) -> Result<(), MerkleError> {
    if targets.contains(&(level, index)) && frontier.insert((level, index), digest).is_some() {
        return Err(MerkleError::DuplicateFrontierTarget { level, index });
    }
    Ok(())
}

#[cfg(feature = "parallel")]
fn validate_frontier_targets(
    leaf_count: usize,
    targets: &[(usize, usize)],
) -> Result<alloc::collections::BTreeSet<(usize, usize)>, MerkleError> {
    use alloc::collections::BTreeSet;

    let depth = tree_depth(leaf_count);
    let mut unique = BTreeSet::new();
    for &(level, index) in targets {
        let width = leaf_count
            .checked_shr(u32::try_from(level).unwrap_or(u32::MAX))
            .unwrap_or(0);
        if level > depth || index >= width {
            return Err(MerkleError::FrontierTargetOutOfBounds {
                level,
                index,
                leaf_count,
            });
        }
        if !unique.insert((level, index)) {
            return Err(MerkleError::DuplicateFrontierTarget { level, index });
        }
    }
    Ok(unique)
}

impl MerkleTree {
    /// Builds a strict tree from leaf payloads in committed order.
    pub fn from_leaf_payloads(payloads: &[&[u8]]) -> Result<Self, MerkleError> {
        validate_leaf_count(payloads.len())?;
        let mut levels = Vec::with_capacity(tree_depth(payloads.len()) + 1);
        let mut current = payloads
            .iter()
            .map(|payload| hash_leaf(payload).map(LeafHash::into_bytes))
            .collect::<Result<Vec<_>, _>>()?;
        levels.push(current.clone());

        while current.len() > 1 {
            let next = current
                .chunks_exact(2)
                .map(|pair| hash_node_bytes(&pair[0], &pair[1]))
                .collect::<Vec<_>>();
            levels.push(next.clone());
            current = next;
        }

        let leaf_count = u64::try_from(payloads.len()).map_err(|_| MerkleError::LengthOverflow)?;
        let root = RootHash(hash_root_bytes(leaf_count, &current[0]));
        Ok(Self { levels, root })
    }

    /// Builds the byte-identical tree with bounded native worker threads.
    #[cfg(feature = "parallel")]
    pub fn from_leaf_payloads_parallel(
        payloads: &[&[u8]],
        workers: usize,
    ) -> Result<Self, MerkleError> {
        validate_leaf_count(payloads.len())?;
        if workers == 0 {
            return Err(MerkleError::ZeroWorkerCount);
        }
        for payload in payloads {
            u64::try_from(payload.len()).map_err(|_| MerkleError::LengthOverflow)?;
        }
        let mut levels = Vec::with_capacity(tree_depth(payloads.len()) + 1);
        let mut current = vec![[0_u8; DIGEST_LENGTH]; payloads.len()];
        let chunk_size = payloads.len().div_ceil(workers);
        std::thread::scope(|scope| {
            for (output, input) in current
                .chunks_mut(chunk_size)
                .zip(payloads.chunks(chunk_size))
            {
                scope.spawn(move || {
                    for (destination, payload) in output.iter_mut().zip(input) {
                        *destination = hash_leaf(payload)
                            .expect("payload lengths were prevalidated")
                            .into_bytes();
                    }
                });
            }
        });
        levels.push(current.clone());

        while current.len() > 1 {
            let mut next = vec![[0_u8; DIGEST_LENGTH]; current.len() / 2];
            let chunk_size = next.len().div_ceil(workers);
            std::thread::scope(|scope| {
                for (output, input) in next
                    .chunks_mut(chunk_size)
                    .zip(current.chunks(2 * chunk_size))
                {
                    scope.spawn(move || {
                        for (destination, pair) in output.iter_mut().zip(input.chunks_exact(2)) {
                            *destination = hash_node_bytes(&pair[0], &pair[1]);
                        }
                    });
                }
            });
            levels.push(next.clone());
            current = next;
        }

        let leaf_count = u64::try_from(payloads.len()).map_err(|_| MerkleError::LengthOverflow)?;
        let root = RootHash(hash_root_bytes(leaf_count, &current[0]));
        Ok(Self { levels, root })
    }

    /// Returns the exact domain-515 tree root.
    pub const fn root(&self) -> RootHash {
        self.root
    }

    /// Returns the number of committed leaves.
    pub fn leaf_count(&self) -> usize {
        self.levels[0].len()
    }

    /// Derives one bottom-up full-width membership proof.
    pub fn proof(&self, leaf_index: usize) -> Result<MerkleProof, MerkleError> {
        let leaf_count = self.leaf_count();
        if leaf_index >= leaf_count {
            return Err(MerkleError::IndexOutOfBounds {
                index: leaf_index,
                leaf_count,
            });
        }
        let mut siblings = Vec::with_capacity(tree_depth(leaf_count));
        let mut index = leaf_index;
        for level in &self.levels[..self.levels.len() - 1] {
            siblings.push(level[index ^ 1]);
            index >>= 1;
        }
        MerkleProof::from_parts(leaf_index, leaf_count, siblings)
    }
}

fn hash_parts(domain: u16, parts: &[&[u8]]) -> [u8; DIGEST_LENGTH] {
    let mut hash = Sha3_512::new();
    hash.update(PCS_MAGIC);
    hash.update(PCS_VERSION.to_be_bytes());
    hash.update(domain.to_be_bytes());
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

fn hash_node_bytes(left: &[u8; DIGEST_LENGTH], right: &[u8; DIGEST_LENGTH]) -> [u8; DIGEST_LENGTH] {
    hash_parts(PCS_MERKLE_NODE_DOMAIN, &[left, right])
}

fn hash_root_bytes(leaf_count: u64, top: &[u8; DIGEST_LENGTH]) -> [u8; DIGEST_LENGTH] {
    hash_parts(PCS_MERKLE_ROOT_DOMAIN, &[&leaf_count.to_be_bytes(), top])
}

fn validate_leaf_count(count: usize) -> Result<(), MerkleError> {
    if count == 0 {
        return Err(MerkleError::EmptyTree);
    }
    if !count.is_power_of_two() {
        return Err(MerkleError::LeafCountNotPowerOfTwo { count });
    }
    Ok(())
}

fn tree_depth(leaf_count: usize) -> usize {
    leaf_count.trailing_zeros() as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn independent_hash_kats_match_exact_framing() {
        assert_eq!(
            hash_empty().into_bytes(),
            decode_hex(
                "d8c47d03e2c41b6d457999c1b6499b6f8bba0f99711ce4af2aaad6e195943a0104bf7bce2fbf3f3454477b5a8cc577279f4f24c2c28609de4f09b05cfe935a56"
            )
        );
        let leaves = [&b"\x00"[..], &b"\x01"[..], &b"\x02"[..], &b"\x03"[..]];
        let leaf_zero = hash_leaf(leaves[0]).unwrap();
        assert_eq!(
            leaf_zero.into_bytes(),
            decode_hex(
                "d3a191e9db0947ac45b54dedd196d899e078b950925559c2cf9e61b3f15d9d2f8f378c57d080f293a334ca032b6272e451ec7b769888186fdaa27942729fb342"
            )
        );
        let node = hash_node(
            ChildHash::Leaf(leaf_zero),
            ChildHash::Leaf(hash_leaf(leaves[1]).unwrap()),
        );
        assert_eq!(
            node.into_bytes(),
            decode_hex(
                "e1d8c226e7da7497f1ebf98486cbff248527ace9147383187f8472206212dab533e4f1144eeab512eff9f0160e82f35c31f8ecb7b415716c2553688328dc1f6a"
            )
        );
        let tree = MerkleTree::from_leaf_payloads(&leaves).unwrap();
        assert_eq!(
            tree.root().into_bytes(),
            decode_hex(
                "fa4ed4a51a6d8ac4e2163cb580d5f752f56a4e622846bb5b8c4989cb2691e8865515fb5c5be0dca01161f058b15adf84e1a5de098e4b3ff5d1b6280ed97783ef"
            )
        );
    }

    #[test]
    fn every_power_of_two_membership_proof_verifies() {
        let storage = (0_u16..128)
            .map(|index| index.to_be_bytes().to_vec())
            .collect::<Vec<_>>();
        let leaves = storage.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let tree = MerkleTree::from_leaf_payloads(&leaves).unwrap();
        for (index, payload) in leaves.iter().enumerate() {
            let proof = tree.proof(index).unwrap();
            assert!(proof.verify(payload, &tree.root()).unwrap());
            assert_eq!(proof.siblings().len(), 7);
        }
    }

    #[test]
    fn singleton_tree_has_empty_proof_but_domain_wrapped_root() {
        let tree = MerkleTree::from_leaf_payloads(&[b"only leaf"]).unwrap();
        let proof = tree.proof(0).unwrap();
        assert!(proof.siblings().is_empty());
        assert!(proof.verify(b"only leaf", &tree.root()).unwrap());
        assert_ne!(
            tree.root().into_bytes(),
            hash_leaf(b"only leaf").unwrap().into_bytes()
        );
    }

    #[test]
    fn malformed_tree_shapes_and_proofs_fail_closed() {
        assert_eq!(
            MerkleTree::from_leaf_payloads(&[]),
            Err(MerkleError::EmptyTree)
        );
        assert_eq!(
            MerkleTree::from_leaf_payloads(&[b"a", b"b", b"c"]),
            Err(MerkleError::LeafCountNotPowerOfTwo { count: 3 })
        );

        let leaves = [&b"a"[..], &b"b"[..], &b"c"[..], &b"d"[..]];
        let tree = MerkleTree::from_leaf_payloads(&leaves).unwrap();
        assert_eq!(
            tree.proof(4),
            Err(MerkleError::IndexOutOfBounds {
                index: 4,
                leaf_count: 4
            })
        );
        assert_eq!(
            MerkleProof::from_parts(0, 4, vec![[0_u8; 64]]),
            Err(MerkleError::SiblingCountMismatch {
                expected: 2,
                actual: 1
            })
        );
        assert_eq!(
            MerkleProof::from_parts(4, 4, vec![[0_u8; 64]; 2]),
            Err(MerkleError::IndexOutOfBounds {
                index: 4,
                leaf_count: 4
            })
        );
    }

    #[test]
    fn payload_sibling_orientation_and_root_tampering_are_rejected() {
        let leaves = [&b"a"[..], &b"b"[..], &b"c"[..], &b"d"[..]];
        let tree = MerkleTree::from_leaf_payloads(&leaves).unwrap();
        let proof = tree.proof(2).unwrap();
        assert!(!proof.verify(b"forged", &tree.root()).unwrap());

        let mut siblings = proof.siblings().to_vec();
        siblings[0][0] ^= 1;
        let forged_proof = MerkleProof::from_parts(2, 4, siblings).unwrap();
        assert!(!forged_proof.verify(leaves[2], &tree.root()).unwrap());

        let mut root = tree.root().into_bytes();
        root[63] ^= 1;
        assert!(
            !proof
                .verify(leaves[2], &RootHash::from_bytes(root))
                .unwrap()
        );
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn parallel_tree_is_byte_exact_at_one_and_four_workers() {
        let storage = (0_u16..128)
            .map(|index| index.to_be_bytes().to_vec())
            .collect::<Vec<_>>();
        let leaves = storage.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let serial = MerkleTree::from_leaf_payloads(&leaves).unwrap();
        for workers in [1, 4] {
            assert_eq!(
                MerkleTree::from_leaf_payloads_parallel(&leaves, workers).unwrap(),
                serial
            );
        }
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn stateless_parallel_root_and_query_frontier_match_retained_tree() {
        let storage = (0_u16..256)
            .map(|index| index.to_be_bytes().to_vec())
            .collect::<Vec<_>>();
        let leaves = storage.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let retained = MerkleTree::from_leaf_payloads_parallel(&leaves, 4).unwrap();
        let queries = [0_usize, 1, 37, 128, 255];
        let depth = tree_depth(leaves.len());
        let mut targets = alloc::collections::BTreeSet::new();
        for query in queries {
            for level in 0..depth {
                targets.insert((level, (query >> level) ^ 1));
            }
        }
        let targets = targets.into_iter().collect::<Vec<_>>();
        let stateless =
            stateless_root_and_frontier_parallel::<&[u8], _>(leaves.len(), &targets, 4, |index| {
                leaves[index]
            })
            .unwrap();
        assert_eq!(stateless.root(), retained.root());
        assert_eq!(stateless.frontier_len(), targets.len());

        for query in queries {
            let siblings = (0..depth)
                .map(|level| {
                    *stateless
                        .frontier_node(level, (query >> level) ^ 1)
                        .unwrap()
                })
                .collect::<Vec<_>>();
            let proof = MerkleProof::from_parts(query, leaves.len(), siblings).unwrap();
            assert!(proof.verify(leaves[query], &stateless.root()).unwrap());
            assert_eq!(proof, retained.proof(query).unwrap());
        }
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn stateless_frontier_rejects_invalid_geometry() {
        let payload_at = |index: usize| index.to_be_bytes();
        assert_eq!(
            stateless_root_and_frontier_parallel(8, &[], 3, payload_at),
            Err(MerkleError::WorkerCountNotPowerOfTwo { count: 3 })
        );
        assert_eq!(
            stateless_root_and_frontier_parallel(8, &[(0, 8)], 2, payload_at),
            Err(MerkleError::FrontierTargetOutOfBounds {
                level: 0,
                index: 8,
                leaf_count: 8
            })
        );
        assert_eq!(
            stateless_root_and_frontier_parallel(8, &[(1, 1), (1, 1)], 2, payload_at),
            Err(MerkleError::DuplicateFrontierTarget { level: 1, index: 1 })
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
