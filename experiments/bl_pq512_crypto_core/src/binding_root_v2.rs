//! Candidate 128-byte dual-domain SHA3-512 binding and Merkle substrate.
//!
//! Every digest is `LEFT || RIGHT`, where both 64-byte lanes hash the same
//! canonical `magic || version || role || payload_len || payload` frame under
//! independent frozen domains. The Merkle construction uses these digests for
//! leaves, internal nodes, frontier entries, and roots; it never wraps a
//! legacy 64-byte tree.
//!
//! This is a nonactivating candidate under a joint ideal-sponge and independent
//! domain assumption. It is not a Z10 qualification, production selection, or
//! proof-suite activation.

use alloc::{collections::BTreeMap, vec::Vec};

use sha3::{Digest, Sha3_512};

#[cfg(feature = "std")]
use std::io::Read;

pub const BINDING_V2_BYTES: usize = 128;
pub const BINDING_V2_LANE_BYTES: usize = 64;
pub const BINDING_V2_MAGIC: &[u8; 8] = b"BLBIND02";
pub const BINDING_V2_VERSION: u16 = 2;
pub const BINDING_V2_LEFT_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/BINDING/LEFT/v2\0";
pub const BINDING_V2_RIGHT_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/BINDING/RIGHT/v2\0";

pub const BINDING_MERKLE_MULTIPROOF_V2_MAGIC: &[u8; 8] = b"BLB2MP02";
pub const BINDING_MERKLE_MULTIPROOF_V2_VERSION: u16 = 2;
pub const BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES: usize = 28;
pub const MAX_BINDING_MERKLE_LEAVES_V2: u64 = 1_u64 << 32;
pub const MAX_BINDING_MERKLE_OPENINGS_V2: usize = 4_096;
pub const MAX_BINDING_MERKLE_FRONTIER_V2: usize = 131_072;
pub const MAX_BINDING_MERKLE_MULTIPROOF_V2_BYTES: usize = BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES
    + MAX_BINDING_MERKLE_OPENINGS_V2 * 8
    + MAX_BINDING_MERKLE_FRONTIER_V2 * BINDING_V2_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum BindingRoleV2 {
    Payload = 0x0001,
    MerkleLeaf = 0x0101,
    MerkleNode = 0x0102,
    MerkleRoot = 0x0103,
}

impl BindingRoleV2 {
    pub const fn code(self) -> u16 {
        self as u16
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingRootV2Error {
    ArithmeticOverflow,
    DigestLength,
    EmptyTree,
    InvalidNodeLevel,
    NonPowerOfTwo,
    TooManyLeaves,
    TooManyOpenings,
    TooManyFrontierDigests,
    IndicesNotStrictlyIncreasing,
    IndexOutOfRange,
    PayloadCount,
    FrontierLength,
    RootMismatch,
    ProofLength,
    ProofMagic,
    ProofVersion,
    ProofFlags,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct BindingDigestV2([u8; BINDING_V2_BYTES]);

impl BindingDigestV2 {
    pub fn hash(role: BindingRoleV2, payload: &[u8]) -> Result<Self, BindingRootV2Error> {
        let payload_len =
            u64::try_from(payload.len()).map_err(|_| BindingRootV2Error::ArithmeticOverflow)?;
        let left = hash_lane(BINDING_V2_LEFT_DOMAIN, role, payload_len, payload);
        let right = hash_lane(BINDING_V2_RIGHT_DOMAIN, role, payload_len, payload);
        let mut bytes = [0_u8; BINDING_V2_BYTES];
        bytes[..BINDING_V2_LANE_BYTES].copy_from_slice(&left);
        bytes[BINDING_V2_LANE_BYTES..].copy_from_slice(&right);
        Ok(Self(bytes))
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, BindingRootV2Error> {
        let bytes: [u8; BINDING_V2_BYTES] = encoded
            .try_into()
            .map_err(|_| BindingRootV2Error::DigestLength)?;
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; BINDING_V2_BYTES] {
        &self.0
    }

    pub const fn to_bytes(self) -> [u8; BINDING_V2_BYTES] {
        self.0
    }

    /// Hash an exact, bounded payload stream using the byte-identical v2
    /// dual-lane frame used by [`Self::hash`].
    ///
    /// The reader must represent exactly `payload_len` bytes. A caller hashing
    /// one section of a larger stream must first bound it (for example with
    /// [`std::io::Read::take`]); otherwise the first byte of the following
    /// section is correctly rejected as trailing payload. This function never
    /// allocates in proportion to `payload_len`.
    #[cfg(feature = "std")]
    pub fn hash_reader_exact<R: Read>(
        role: BindingRoleV2,
        payload_len: u64,
        reader: &mut R,
    ) -> Result<Self, BindingRootV2StreamError> {
        let mut left = framed_lane_hasher(BINDING_V2_LEFT_DOMAIN, role, payload_len);
        let mut right = framed_lane_hasher(BINDING_V2_RIGHT_DOMAIN, role, payload_len);
        let mut remaining = payload_len;
        let mut consumed = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        while remaining != 0 {
            let requested = usize::try_from(remaining.min(buffer.len() as u64))
                .expect("the requested chunk is bounded by the fixed buffer");
            let read = loop {
                match reader.read(&mut buffer[..requested]) {
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    result => break result?,
                }
            };
            if read == 0 {
                return Err(BindingRootV2StreamError::ShortPayload {
                    declared: payload_len,
                    actual: consumed,
                });
            }
            left.update(&buffer[..read]);
            right.update(&buffer[..read]);
            let read =
                u64::try_from(read).map_err(|_| BindingRootV2StreamError::ArithmeticOverflow)?;
            consumed = consumed
                .checked_add(read)
                .ok_or(BindingRootV2StreamError::ArithmeticOverflow)?;
            remaining -= read;
        }

        let mut trailing = [0_u8; 1];
        let trailing_read = loop {
            match reader.read(&mut trailing) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                result => break result?,
            }
        };
        if trailing_read != 0 {
            return Err(BindingRootV2StreamError::TrailingPayload);
        }

        let mut bytes = [0_u8; BINDING_V2_BYTES];
        bytes[..BINDING_V2_LANE_BYTES].copy_from_slice(&left.finalize());
        bytes[BINDING_V2_LANE_BYTES..].copy_from_slice(&right.finalize());
        Ok(Self(bytes))
    }
}

/// Exact-length streaming failures for [`BindingDigestV2::hash_reader_exact`].
#[cfg(feature = "std")]
#[derive(Debug)]
pub enum BindingRootV2StreamError {
    ArithmeticOverflow,
    ShortPayload { declared: u64, actual: u64 },
    TrailingPayload,
    Io(std::io::Error),
}

#[cfg(feature = "std")]
impl core::fmt::Display for BindingRootV2StreamError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ArithmeticOverflow => formatter.write_str("stream payload arithmetic overflow"),
            Self::ShortPayload { declared, actual } => write!(
                formatter,
                "stream payload ended after {actual} bytes; declared {declared}"
            ),
            Self::TrailingPayload => formatter.write_str("stream payload has trailing bytes"),
            Self::Io(error) => write!(formatter, "stream payload I/O failed: {error}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BindingRootV2StreamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for BindingRootV2StreamError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct BindingMerkleLeafV2(BindingDigestV2);

impl BindingMerkleLeafV2 {
    pub fn hash(index: u64, payload: &[u8]) -> Result<Self, BindingRootV2Error> {
        let mut frame = Vec::with_capacity(
            8_usize
                .checked_add(payload.len())
                .ok_or(BindingRootV2Error::ArithmeticOverflow)?,
        );
        frame.extend_from_slice(&index.to_be_bytes());
        frame.extend_from_slice(payload);
        Ok(Self(BindingDigestV2::hash(
            BindingRoleV2::MerkleLeaf,
            &frame,
        )?))
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, BindingRootV2Error> {
        Ok(Self(BindingDigestV2::decode(encoded)?))
    }

    pub const fn digest(self) -> BindingDigestV2 {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; BINDING_V2_BYTES] {
        self.0.as_bytes()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct BindingMerkleNodeV2(BindingDigestV2);

impl BindingMerkleNodeV2 {
    pub fn hash(
        level: u32,
        index: u64,
        left: BindingDigestV2,
        right: BindingDigestV2,
    ) -> Result<Self, BindingRootV2Error> {
        if level == 0 {
            return Err(BindingRootV2Error::InvalidNodeLevel);
        }
        let mut frame = Vec::with_capacity(4 + 8 + 2 * BINDING_V2_BYTES);
        frame.extend_from_slice(&level.to_be_bytes());
        frame.extend_from_slice(&index.to_be_bytes());
        frame.extend_from_slice(left.as_bytes());
        frame.extend_from_slice(right.as_bytes());
        Ok(Self(BindingDigestV2::hash(
            BindingRoleV2::MerkleNode,
            &frame,
        )?))
    }

    pub const fn digest(self) -> BindingDigestV2 {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; BINDING_V2_BYTES] {
        self.0.as_bytes()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct BindingRootV2(BindingDigestV2);

impl BindingRootV2 {
    // Deliberately private: callers cannot bless an externally supplied or
    // legacy-tree digest as a v2 root. Trees and verified multiproofs are the
    // only root-construction paths in this module.
    pub(crate) fn from_top(
        leaf_count: u64,
        top: BindingDigestV2,
    ) -> Result<Self, BindingRootV2Error> {
        validate_leaf_count(leaf_count)?;
        let height = leaf_count.trailing_zeros();
        let mut frame = Vec::with_capacity(8 + 4 + BINDING_V2_BYTES);
        frame.extend_from_slice(&leaf_count.to_be_bytes());
        frame.extend_from_slice(&height.to_be_bytes());
        frame.extend_from_slice(top.as_bytes());
        Ok(Self(BindingDigestV2::hash(
            BindingRoleV2::MerkleRoot,
            &frame,
        )?))
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, BindingRootV2Error> {
        Ok(Self(BindingDigestV2::decode(encoded)?))
    }

    pub const fn digest(self) -> BindingDigestV2 {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; BINDING_V2_BYTES] {
        self.0.as_bytes()
    }

    pub const fn to_bytes(self) -> [u8; BINDING_V2_BYTES] {
        self.0.to_bytes()
    }
}

fn hash_lane(
    domain: &[u8],
    role: BindingRoleV2,
    payload_len: u64,
    payload: &[u8],
) -> [u8; BINDING_V2_LANE_BYTES] {
    let mut hash = framed_lane_hasher(domain, role, payload_len);
    hash.update(payload);
    hash.finalize().into()
}

fn framed_lane_hasher(domain: &[u8], role: BindingRoleV2, payload_len: u64) -> Sha3_512 {
    let mut hash = Sha3_512::new();
    hash.update(domain);
    hash.update(BINDING_V2_MAGIC);
    hash.update(BINDING_V2_VERSION.to_be_bytes());
    hash.update(role.code().to_be_bytes());
    hash.update(payload_len.to_be_bytes());
    hash
}

fn validate_leaf_count(leaf_count: u64) -> Result<(), BindingRootV2Error> {
    if leaf_count == 0 {
        return Err(BindingRootV2Error::EmptyTree);
    }
    if !leaf_count.is_power_of_two() {
        return Err(BindingRootV2Error::NonPowerOfTwo);
    }
    if leaf_count > MAX_BINDING_MERKLE_LEAVES_V2 {
        return Err(BindingRootV2Error::TooManyLeaves);
    }
    Ok(())
}

fn validate_indices(leaf_count: u64, indices: &[u64]) -> Result<(), BindingRootV2Error> {
    if indices.is_empty() || indices.len() > MAX_BINDING_MERKLE_OPENINGS_V2 {
        return Err(BindingRootV2Error::TooManyOpenings);
    }
    let mut previous = None;
    for &index in indices {
        if index >= leaf_count {
            return Err(BindingRootV2Error::IndexOutOfRange);
        }
        if previous.is_some_and(|prior| prior >= index) {
            return Err(BindingRootV2Error::IndicesNotStrictlyIncreasing);
        }
        previous = Some(index);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindingMerklePositionV2 {
    pub level: u32,
    pub index: u64,
}

/// Return the unique canonical frontier in bottom-up, then left-to-right order.
pub fn canonical_binding_frontier_positions_v2(
    leaf_count: u64,
    selected_indices: &[u64],
) -> Result<Vec<BindingMerklePositionV2>, BindingRootV2Error> {
    validate_leaf_count(leaf_count)?;
    validate_indices(leaf_count, selected_indices)?;
    let height = leaf_count.trailing_zeros();
    let mut active = selected_indices.to_vec();
    let mut frontier = Vec::new();
    for level in 0..height {
        let level_start = frontier.len();
        for &index in &active {
            let sibling = index ^ 1;
            if active.binary_search(&sibling).is_err() {
                frontier.push(BindingMerklePositionV2 {
                    level,
                    index: sibling,
                });
                if frontier.len() > MAX_BINDING_MERKLE_FRONTIER_V2 {
                    return Err(BindingRootV2Error::TooManyFrontierDigests);
                }
            }
        }
        frontier[level_start..].sort_by_key(|item| item.index);
        let mut parents = Vec::with_capacity(active.len());
        for index in active {
            let parent = index >> 1;
            if parents.last().copied() != Some(parent) {
                parents.push(parent);
            }
        }
        active = parents;
    }
    if active.as_slice() != [0] {
        return Err(BindingRootV2Error::NonPowerOfTwo);
    }
    Ok(frontier)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingMerkleMultiProofV2 {
    leaf_count: u64,
    selected_indices: Vec<u64>,
    frontier_digests: Vec<BindingDigestV2>,
}

impl BindingMerkleMultiProofV2 {
    fn from_parts(
        leaf_count: u64,
        selected_indices: Vec<u64>,
        frontier_digests: Vec<BindingDigestV2>,
    ) -> Result<Self, BindingRootV2Error> {
        let expected =
            canonical_binding_frontier_positions_v2(leaf_count, &selected_indices)?.len();
        if frontier_digests.len() != expected {
            return Err(BindingRootV2Error::FrontierLength);
        }
        Ok(Self {
            leaf_count,
            selected_indices,
            frontier_digests,
        })
    }

    /// Construct a proof from the canonical frontier computed by a bounded
    /// producer. The same strict index and frontier-shape checks used by the
    /// wire decoder are applied here; callers cannot supply an arbitrary
    /// subset or ordering of Merkle nodes.
    pub fn from_canonical_frontier(
        leaf_count: u64,
        selected_indices: Vec<u64>,
        frontier_digests: Vec<BindingDigestV2>,
    ) -> Result<Self, BindingRootV2Error> {
        Self::from_parts(leaf_count, selected_indices, frontier_digests)
    }

    pub const fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    pub fn selected_indices(&self) -> &[u64] {
        &self.selected_indices
    }

    pub fn frontier_digests(&self) -> &[BindingDigestV2] {
        &self.frontier_digests
    }

    pub fn encode(&self) -> Result<Vec<u8>, BindingRootV2Error> {
        let selected_count = u32::try_from(self.selected_indices.len())
            .map_err(|_| BindingRootV2Error::ArithmeticOverflow)?;
        let frontier_count = u32::try_from(self.frontier_digests.len())
            .map_err(|_| BindingRootV2Error::ArithmeticOverflow)?;
        let encoded_len =
            encoded_proof_len(self.selected_indices.len(), self.frontier_digests.len())?;
        let mut encoded = Vec::with_capacity(encoded_len);
        encoded.extend_from_slice(BINDING_MERKLE_MULTIPROOF_V2_MAGIC);
        encoded.extend_from_slice(&BINDING_MERKLE_MULTIPROOF_V2_VERSION.to_be_bytes());
        encoded.extend_from_slice(&0_u16.to_be_bytes());
        encoded.extend_from_slice(&self.leaf_count.to_be_bytes());
        encoded.extend_from_slice(&selected_count.to_be_bytes());
        encoded.extend_from_slice(&frontier_count.to_be_bytes());
        for index in &self.selected_indices {
            encoded.extend_from_slice(&index.to_be_bytes());
        }
        for digest in &self.frontier_digests {
            encoded.extend_from_slice(digest.as_bytes());
        }
        if encoded.len() != encoded_len {
            return Err(BindingRootV2Error::ProofLength);
        }
        Ok(encoded)
    }

    /// Parse an exact bounded proof. Counts and total length are validated
    /// before either attacker-sized vector is allocated.
    pub fn decode(encoded: &[u8]) -> Result<Self, BindingRootV2Error> {
        if encoded.len() < BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES
            || encoded.len() > MAX_BINDING_MERKLE_MULTIPROOF_V2_BYTES
        {
            return Err(BindingRootV2Error::ProofLength);
        }
        if encoded.get(..8) != Some(BINDING_MERKLE_MULTIPROOF_V2_MAGIC) {
            return Err(BindingRootV2Error::ProofMagic);
        }
        if u16::from_be_bytes(
            encoded[8..10]
                .try_into()
                .map_err(|_| BindingRootV2Error::ProofLength)?,
        ) != BINDING_MERKLE_MULTIPROOF_V2_VERSION
        {
            return Err(BindingRootV2Error::ProofVersion);
        }
        if encoded[10..12] != [0_u8; 2] {
            return Err(BindingRootV2Error::ProofFlags);
        }
        let leaf_count = u64::from_be_bytes(
            encoded[12..20]
                .try_into()
                .map_err(|_| BindingRootV2Error::ProofLength)?,
        );
        validate_leaf_count(leaf_count)?;
        let selected_count = usize::try_from(u32::from_be_bytes(
            encoded[20..24]
                .try_into()
                .map_err(|_| BindingRootV2Error::ProofLength)?,
        ))
        .map_err(|_| BindingRootV2Error::ArithmeticOverflow)?;
        let frontier_count = usize::try_from(u32::from_be_bytes(
            encoded[24..28]
                .try_into()
                .map_err(|_| BindingRootV2Error::ProofLength)?,
        ))
        .map_err(|_| BindingRootV2Error::ArithmeticOverflow)?;
        if selected_count == 0 || selected_count > MAX_BINDING_MERKLE_OPENINGS_V2 {
            return Err(BindingRootV2Error::TooManyOpenings);
        }
        if frontier_count > MAX_BINDING_MERKLE_FRONTIER_V2 {
            return Err(BindingRootV2Error::TooManyFrontierDigests);
        }
        let expected_len = encoded_proof_len(selected_count, frontier_count)?;
        if encoded.len() != expected_len {
            return Err(BindingRootV2Error::ProofLength);
        }

        let mut offset = BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES;
        let mut selected_indices = Vec::with_capacity(selected_count);
        for _ in 0..selected_count {
            selected_indices.push(u64::from_be_bytes(
                encoded[offset..offset + 8]
                    .try_into()
                    .map_err(|_| BindingRootV2Error::ProofLength)?,
            ));
            offset += 8;
        }
        let expected_frontier =
            canonical_binding_frontier_positions_v2(leaf_count, &selected_indices)?.len();
        if frontier_count != expected_frontier {
            return Err(BindingRootV2Error::FrontierLength);
        }
        let mut frontier_digests = Vec::with_capacity(frontier_count);
        for _ in 0..frontier_count {
            frontier_digests.push(BindingDigestV2::decode(
                &encoded[offset..offset + BINDING_V2_BYTES],
            )?);
            offset += BINDING_V2_BYTES;
        }
        if offset != encoded.len() {
            return Err(BindingRootV2Error::ProofLength);
        }
        Self::from_parts(leaf_count, selected_indices, frontier_digests)
    }

    pub fn verify_payloads<P: AsRef<[u8]>>(
        &self,
        payloads: &[P],
        expected_root: &BindingRootV2,
    ) -> Result<(), BindingRootV2Error> {
        if payloads.len() != self.selected_indices.len() {
            return Err(BindingRootV2Error::PayloadCount);
        }
        let leaves = self
            .selected_indices
            .iter()
            .copied()
            .zip(payloads)
            .map(|(index, payload)| BindingMerkleLeafV2::hash(index, payload.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        self.verify_leaf_hashes(&leaves, expected_root)
    }

    pub fn verify_leaf_hashes(
        &self,
        leaf_hashes: &[BindingMerkleLeafV2],
        expected_root: &BindingRootV2,
    ) -> Result<(), BindingRootV2Error> {
        if leaf_hashes.len() != self.selected_indices.len() {
            return Err(BindingRootV2Error::PayloadCount);
        }
        let frontier_positions =
            canonical_binding_frontier_positions_v2(self.leaf_count, &self.selected_indices)?;
        if frontier_positions.len() != self.frontier_digests.len() {
            return Err(BindingRootV2Error::FrontierLength);
        }
        let mut active = BTreeMap::new();
        for (&index, leaf) in self.selected_indices.iter().zip(leaf_hashes) {
            if active.insert(index, leaf.digest()).is_some() {
                return Err(BindingRootV2Error::IndicesNotStrictlyIncreasing);
            }
        }
        let height = self.leaf_count.trailing_zeros();
        let mut frontier_offset = 0_usize;
        for level in 0..height {
            while frontier_offset < frontier_positions.len()
                && frontier_positions[frontier_offset].level == level
            {
                let position = frontier_positions[frontier_offset];
                if active
                    .insert(position.index, self.frontier_digests[frontier_offset])
                    .is_some()
                {
                    return Err(BindingRootV2Error::FrontierLength);
                }
                frontier_offset += 1;
            }
            let entries = active.into_iter().collect::<Vec<_>>();
            if entries.is_empty() || !entries.len().is_multiple_of(2) {
                return Err(BindingRootV2Error::FrontierLength);
            }
            let mut parents = BTreeMap::new();
            for pair in entries.chunks_exact(2) {
                let (left_index, left) = pair[0];
                let (right_index, right) = pair[1];
                if left_index & 1 != 0 || right_index != left_index + 1 {
                    return Err(BindingRootV2Error::FrontierLength);
                }
                let parent_index = left_index >> 1;
                let node = BindingMerkleNodeV2::hash(level + 1, parent_index, left, right)?;
                if parents.insert(parent_index, node.digest()).is_some() {
                    return Err(BindingRootV2Error::FrontierLength);
                }
            }
            active = parents;
        }
        if frontier_offset != frontier_positions.len() || active.len() != 1 {
            return Err(BindingRootV2Error::FrontierLength);
        }
        let top = active
            .remove(&0)
            .ok_or(BindingRootV2Error::FrontierLength)?;
        let actual_root = BindingRootV2::from_top(self.leaf_count, top)?;
        if actual_root != *expected_root {
            return Err(BindingRootV2Error::RootMismatch);
        }
        Ok(())
    }
}

fn encoded_proof_len(
    selected_count: usize,
    frontier_count: usize,
) -> Result<usize, BindingRootV2Error> {
    BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES
        .checked_add(
            selected_count
                .checked_mul(8)
                .ok_or(BindingRootV2Error::ArithmeticOverflow)?,
        )
        .and_then(|length| {
            frontier_count
                .checked_mul(BINDING_V2_BYTES)
                .and_then(|frontier_bytes| length.checked_add(frontier_bytes))
        })
        .ok_or(BindingRootV2Error::ArithmeticOverflow)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingMerkleTreeV2 {
    levels: Vec<Vec<BindingDigestV2>>,
    root: BindingRootV2,
}

impl BindingMerkleTreeV2 {
    pub fn from_payloads<P: AsRef<[u8]>>(payloads: &[P]) -> Result<Self, BindingRootV2Error> {
        let leaf_digests = payloads
            .iter()
            .enumerate()
            .map(|(index, payload)| {
                Ok(BindingMerkleLeafV2::hash(
                    u64::try_from(index).map_err(|_| BindingRootV2Error::ArithmeticOverflow)?,
                    payload.as_ref(),
                )?
                .digest())
            })
            .collect::<Result<Vec<_>, BindingRootV2Error>>()?;
        Self::from_leaf_digests(leaf_digests)
    }

    /// Build a v2 tree from already-authenticated leaf digests.
    ///
    /// The streaming H4 producer uses this boundary after hashing one
    /// bounded leaf payload at a time. It deliberately accepts only native
    /// `BindingDigestV2` values, so callers cannot promote a legacy 64-byte
    /// Merkle node or root into the v2 tree.
    pub fn from_leaf_digests(
        leaf_digests: Vec<BindingDigestV2>,
    ) -> Result<Self, BindingRootV2Error> {
        let leaf_count =
            u64::try_from(leaf_digests.len()).map_err(|_| BindingRootV2Error::TooManyLeaves)?;
        validate_leaf_count(leaf_count)?;
        let mut current = leaf_digests;
        let mut levels = Vec::with_capacity(leaf_count.trailing_zeros() as usize + 1);
        levels.push(current.clone());
        let mut level = 1_u32;
        while current.len() > 1 {
            let mut parents = Vec::with_capacity(current.len() / 2);
            for (parent_index, pair) in current.chunks_exact(2).enumerate() {
                parents.push(
                    BindingMerkleNodeV2::hash(
                        level,
                        u64::try_from(parent_index)
                            .map_err(|_| BindingRootV2Error::ArithmeticOverflow)?,
                        pair[0],
                        pair[1],
                    )?
                    .digest(),
                );
            }
            levels.push(parents.clone());
            current = parents;
            level += 1;
        }
        let top = current[0];
        let root = BindingRootV2::from_top(leaf_count, top)?;
        Ok(Self { levels, root })
    }

    pub const fn root(&self) -> BindingRootV2 {
        self.root
    }

    pub fn leaf_count(&self) -> u64 {
        self.levels[0].len() as u64
    }

    pub fn prove(
        &self,
        selected_indices: &[u64],
    ) -> Result<BindingMerkleMultiProofV2, BindingRootV2Error> {
        let leaf_count = self.leaf_count();
        let positions = canonical_binding_frontier_positions_v2(leaf_count, selected_indices)?;
        let frontier_digests = positions
            .iter()
            .map(|position| {
                let level = usize::try_from(position.level)
                    .map_err(|_| BindingRootV2Error::ArithmeticOverflow)?;
                let index = usize::try_from(position.index)
                    .map_err(|_| BindingRootV2Error::ArithmeticOverflow)?;
                self.levels
                    .get(level)
                    .and_then(|nodes| nodes.get(index))
                    .copied()
                    .ok_or(BindingRootV2Error::FrontierLength)
            })
            .collect::<Result<Vec<_>, _>>()?;
        BindingMerkleMultiProofV2::from_parts(
            leaf_count,
            selected_indices.to_vec(),
            frontier_digests,
        )
    }
}
