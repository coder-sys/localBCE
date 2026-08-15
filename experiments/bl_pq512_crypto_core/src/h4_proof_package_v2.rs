//! H4 package-v2 framing, strict public-coin replay, and native 128-byte Merkle seam.
//!
//! Version 2 never treats a 64-byte SHA3-512 value as a Merkle root. Segment
//! leaves, internal nodes, frontier nodes, and roots are the native typed
//! objects from [`crate::binding_root_v2`]. The module currently parses only
//! the pre-allocation boundary, the synchronized global public-coin chain, and
//! one complete segment proof. It deliberately cannot construct an accepting
//! H4 receipt until every shard's GKR, state, square-free, Booleanity, padding,
//! Construction-8.2, and rank equation is replayed from these authenticated
//! bytes.

use alloc::{vec, vec::Vec};
use sha3::{Digest, Sha3_512};

use crate::{
    binding_root_v2::{
        BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES, BINDING_MERKLE_MULTIPROOF_V2_MAGIC,
        BINDING_MERKLE_MULTIPROOF_V2_VERSION, BINDING_V2_BYTES, BindingDigestV2,
        BindingMerkleLeafV2, BindingMerkleMultiProofV2, BindingMerkleNodeV2, BindingRoleV2,
        BindingRootV2, BindingRootV2Error, canonical_binding_frontier_positions_v2,
    },
    chained_public_coin::ChainedRoundDescriptor,
    field::Fp16,
    fp16_relay_free_gkr_schedule::{
        GKR_ROUNDS, H4_BOOLEANITY_PRELUDE_KIND, H4_BOOLEANITY_SUMCHECK_KIND,
        H4_BOOLEANITY_TERMINAL_KIND, H4_BOOLEANITY_VARIABLES, H4_PADDING_PRELUDE_KIND,
        H4_PADDING_SUMCHECK_KIND, H4_PADDING_TERMINAL_KIND, H4_PADDING_VARIABLES,
        H4_PCS_ANSWER_KIND, H4_PCS_BASE_KIND, H4_PCS_CLAIM_BATCH_KIND, H4_PCS_INITIAL_KIND,
        H4_PCS_ROW_KIND, H4_STATE_COMPOSED_MASK_BATCH_KIND, H4_STATE_RELATION_GROUP_KIND,
        H4_STATE_RELATION_OUTPUT_KIND, H4_STATE_RELATION_TERMINAL_KIND,
        H4_STATE_RELATION_WIRE_KIND, H4_STATE_SQUAREFREE_BETA_KIND, H4_STATE_SQUAREFREE_GROUP_KIND,
        H4_STATE_SQUAREFREE_LEFT_KIND, H4_STATE_SQUAREFREE_MIX_KIND,
        H4_STATE_SQUAREFREE_POINT_KIND, H4_STATE_SQUAREFREE_RIGHT_KIND,
        H4_STATE_SQUAREFREE_TERMINAL_KIND, STATE_COMPOSED_K128_ROUNDS, STATE_COMPOSED_K512_ROUNDS,
        STATE_RELATION_ROUNDS, gkr_mask_tensor_observation_rank_certificate,
        h4_gkr_descriptor_kind, selected_gkr_round_kind, selected_state_composed_round_descriptors,
    },
    fp16_relay_free_gkr_uniform::UniformRelayFreeGkrRound,
    fp16_zk_rs_gkr_binding::GKR_CLAIM_COUNT,
    h4_proof_package_v1::{H4AuthenticatedRound, encode_codeword, exact_queries, tensor_queries},
    state_squarefree_gkr::state_squarefree_authenticated_rounds,
    strict_pq_public_coin_v2::{
        STRICT_PQ_H4_MAX_BUNDLE_BYTES_V2, StrictPqFp16PolicyV2, StrictPqGovernedVerifierKeyV2,
        StrictPqH4ProfileV2, StrictPqPublicCoinBundleV2, StrictPqPublicCoinV2Error,
        StrictPqRootUseRegistryV2, StrictPqRoundDescriptorV2, replay_strict_pq_fp16_public_coin_v2,
    },
};

#[cfg(feature = "std")]
use crate::binding_root_v2::BindingRootV2StreamError;
#[cfg(feature = "std")]
use std::io::{Read, Seek, SeekFrom, Write};

pub const H4_PROOF_PACKAGE_V2_MAGIC: &[u8; 8] = b"BLH4PK02";
pub const H4_PROOF_PACKAGE_V2_VERSION: u16 = 2;
pub const H4_PROOF_PACKAGE_V2_BYTES: usize = 192 << 20;
pub const H4_PROOF_PACKAGE_V2_HEADER_BYTES: usize = 768;
pub const H4_AGGREGATE_PACKAGE_V2_MAGIC: &[u8; 8] = b"BLH4AG02";
pub const H4_AGGREGATE_PACKAGE_V2_VERSION: u16 = 2;
pub const H4_AGGREGATE_PACKAGE_V2_HEADER_BYTES: usize = 768;
pub const H4_GLOBAL_ROUND_FRAME_V2_MAGIC: &[u8; 8] = b"BLH4GR02";
pub const H4_GLOBAL_ROUND_FRAME_V2_VERSION: u16 = 2;
pub const H4_GLOBAL_ROUND_FRAME_V2_HEADER_BYTES: usize = 16;
pub const H4_GLOBAL_ROUND_FRAME_V2_SHARD_HEADER_BYTES: usize = 5;
pub const H4_GLOBAL_RAW_FRAME_LENGTH_BYTES: usize = 4;
pub const H4_GLOBAL_FRAME_V2_MAX_BYTES: usize = 1 << 20;
pub const H4_GLOBAL_RAW_FRAMES_V2_MAX_BYTES: usize = 16 << 20;
pub const H4_GLOBAL_MAX_SHARD_MESSAGE_BYTES: usize = 1 << 20;
pub const H4_KIND801_MAX_SHARD_MESSAGE_BYTES: usize = 131_088;
pub const H4_BRIDGE_RESPONSE_QUERY_DOMAIN_V2: &[u8] =
    b"BL/PQ512/WAVE2/H4/BRIDGE-SOURCE-RESPONSE/QUERIES/v2\0";

pub const H4_PUBLIC_VIEW_V2_MAGIC: &[u8; 8] = b"BLH4PV02";
pub const H4_PUBLIC_VIEW_V2_VERSION: u16 = 2;
pub const H4_PUBLIC_VIEW_V2_HEADER_BYTES: usize = 32;
pub const H4_PUBLIC_VIEW_V2_ROOT_COUNT: usize = 5;
pub const H4_PUBLIC_VIEW_V2_ROOT_INVENTORY_BYTES: usize =
    H4_PUBLIC_VIEW_V2_ROOT_COUNT * BINDING_V2_BYTES;
pub const H4_PACKED_CLAIMS_BYTES: usize = 52_364;
pub const H4_GKR_RELATION_TERMINAL_BYTES: usize = 4_096;
pub const H4_PUBLIC_VIEW_V2_FIXED_BYTES: usize = H4_PUBLIC_VIEW_V2_HEADER_BYTES
    + H4_PUBLIC_VIEW_V2_ROOT_INVENTORY_BYTES
    + H4_PACKED_CLAIMS_BYTES
    + H4_GKR_RELATION_TERMINAL_BYTES;

pub const H4_RS_MULTIPROOF_V2_MAGIC: &[u8; 8] = b"BLZKRSV4";
pub const H4_RS_MULTIPROOF_V2_PREFIX_BYTES: usize = 8 + 4 + 64;
pub const H4_RS_SEGMENT_V2_HEADER_BYTES: usize = 5 * 8 + 2 * 4 + BINDING_V2_BYTES;
pub const H4_RS_SEGMENT_LEAF_FRAME_MAGIC: &[u8; 8] = b"BLH4SL02";
pub const H4_RS_SEGMENT_LEAF_FRAME_BYTES: usize = 8 + 2 + 2 + 4 * 8;

pub const H4_MAIN_CODE_VALUES: usize = 1 << 17;
pub const H4_MAIN_OPENINGS: usize = 1_600;
pub const H4_AUXILIARY_CODE_VALUES: usize = 1 << 13;
pub const H4_AUXILIARY_OPENINGS: usize = 1_218;
pub const H4_GKR_TENSOR_LEAVES: usize = 1 << 20;
pub const H4_MAIN_MAX_FRONTIER_NODES: usize = 10_048;
pub const H4_SOURCE_WORDS: usize = 512;
pub const H4_SOURCE_LEAF_BYTES: usize = H4_SOURCE_WORDS * 64;
pub const H4_SOURCE_TENSOR_KIND: u64 = 32;
/// Post-Z reuses the already committed Construction main-base polynomial.
/// A second 512-copy base tensor would contain no additional entropy or
/// authority and would add four gigabytes of redundant hashing at K128.
pub const H4_BRIDGE_BASE_LEAF_BYTES: usize = 64;
pub const H4_BRIDGE_BASE_KIND: u64 = 65;
pub const H4_AUXILIARY_MAX_FRONTIER_NODES: usize = 3_266;
pub const H4_TENSOR_MAX_FRONTIER_NODES: usize = 11_792;

pub const H4_ANSWER_MAIN_COEFFICIENT_BYTES: usize = 67_584 * 64;
pub const H4_ANSWER_ORDINARY_AUXILIARY_COEFFICIENT_BYTES: usize = 10 * 3_266 * 64;
pub const H4_ANSWER_GKR_TENSOR_COEFFICIENT_BYTES: usize = 64 * 512 * 64;
pub const H4_ANSWER_COEFFICIENT_BYTES: usize = H4_ANSWER_MAIN_COEFFICIENT_BYTES
    + H4_ANSWER_ORDINARY_AUXILIARY_COEFFICIENT_BYTES
    + H4_ANSWER_GKR_TENSOR_COEFFICIENT_BYTES;
pub const H4_BLSQCL03_BYTES: usize = 8 + BINDING_V2_BYTES + 2 + 2 + BINDING_V2_BYTES;
pub const H4_BLSQAB03_BYTES: usize = 8 + H4_BLSQCL03_BYTES + 2 * (8 + 12 * 64) + 2 * 64;
pub const H4_SOURCE_SEGMENT_SET_V2_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/H4/SOURCE-SEGMENT-SET/v2\0";
pub const H4_NATIVE_ROOT_STATEMENT_ID_V2_DOMAIN: &[u8] =
    b"BL/PQ512/WAVE2/H4/NATIVE-ROOT-STATEMENT-ID/v2\0";
pub const H4_NATIVE_DIGEST_STATEMENT_ID_V2_DOMAIN: &[u8] =
    b"BL/PQ512/WAVE2/H4/NATIVE-DIGEST-STATEMENT-ID/v2\0";
pub const H4_SQUAREFREE_CLAIMS_DIGEST_V2_DOMAIN: &[u8] =
    b"BL/PQ512/WAVE2/H4/SQUAREFREE-CLAIMS/v2\0";
const PCS_SUMCHECK_BASE_KIND: u64 = 64;
const PCS_MAIN_BASE_KIND: u64 = 65;
const GKR_TENSOR_BASE_KIND: u64 = 66;
const GKR_TENSOR_MASK_KIND: u64 = 67;
const PCS_SQUAREFREE_KIND: u64 = 68;
const GKR_TENSOR_ANSWER_KIND: u64 = 69;
const WORD_SUMCHECK_ROUNDS: usize = 9;
const NON_GKR_AUXILIARY_WORDS: usize = 10;
pub const H4_DURABLE_MAX_ATTEMPTS_PER_STATEMENT: u16 = 4;
const NULL_PROOF_SUITE_ID: [u8; 64] = [0_u8; 64];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum H4ProofProfileV2 {
    K128 = 1,
    K512 = 3,
}

impl H4ProofProfileV2 {
    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn governed_label(self) -> &'static str {
        match self {
            Self::K128 => "K128_CALIBRATION",
            Self::K512 => "K512_CALIBRATION",
        }
    }

    pub const fn shard_count(self) -> u8 {
        match self {
            Self::K128 => 1,
            Self::K512 => 4,
        }
    }

    pub const fn transcript_rounds(self) -> u32 {
        match self {
            Self::K128 => STATE_COMPOSED_K128_ROUNDS,
            Self::K512 => STATE_COMPOSED_K512_ROUNDS,
        }
    }

    pub const fn state_capacity(self) -> usize {
        match self {
            Self::K128 => 128,
            Self::K512 => 512,
        }
    }

    pub const fn strict_public_coin_profile(self) -> StrictPqH4ProfileV2 {
        match self {
            Self::K128 => StrictPqH4ProfileV2::K128,
            Self::K512 => StrictPqH4ProfileV2::K512,
        }
    }

    pub const fn initial_segment_count(self) -> usize {
        match self {
            Self::K128 => 16,
            Self::K512 => 32,
        }
    }

    pub const fn initial_leaf_bytes(self) -> usize {
        match self {
            Self::K128 => 2_048,
            Self::K512 => 1_024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum H4ProofPackageV2Error {
    ArithmeticOverflow,
    Length,
    Magic,
    Version,
    Flags,
    Profile,
    Geometry,
    SectionLength,
    ProofSuite,
    ZeroIdentifier,
    LegacyRootWidth,
    Schedule,
    GlobalFrame,
    Multiproof,
    RootMismatch,
    NonCanonicalField,
    Algebra,
    Rank,
    Binding(BindingRootV2Error),
}

#[derive(Debug)]
pub enum H4GlobalTranscriptV2Error {
    Package(H4ProofPackageV2Error),
    PublicCoin(StrictPqPublicCoinV2Error),
}

impl From<H4ProofPackageV2Error> for H4GlobalTranscriptV2Error {
    fn from(value: H4ProofPackageV2Error) -> Self {
        Self::Package(value)
    }
}

impl From<StrictPqPublicCoinV2Error> for H4GlobalTranscriptV2Error {
    fn from(value: StrictPqPublicCoinV2Error) -> Self {
        Self::PublicCoin(value)
    }
}

#[cfg(feature = "std")]
#[derive(Debug)]
pub enum H4AggregateStreamV2Error {
    Package(H4ProofPackageV2Error),
    Transcript(H4GlobalTranscriptV2Error),
    Binding(BindingRootV2StreamError),
    Io(std::io::Error),
}

#[cfg(feature = "std")]
impl From<H4ProofPackageV2Error> for H4AggregateStreamV2Error {
    fn from(value: H4ProofPackageV2Error) -> Self {
        Self::Package(value)
    }
}

#[cfg(feature = "std")]
impl From<H4GlobalTranscriptV2Error> for H4AggregateStreamV2Error {
    fn from(value: H4GlobalTranscriptV2Error) -> Self {
        Self::Transcript(value)
    }
}

#[cfg(feature = "std")]
impl From<BindingRootV2StreamError> for H4AggregateStreamV2Error {
    fn from(value: BindingRootV2StreamError) -> Self {
        Self::Binding(value)
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for H4AggregateStreamV2Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<BindingRootV2Error> for H4ProofPackageV2Error {
    fn from(value: BindingRootV2Error) -> Self {
        Self::Binding(value)
    }
}

fn nonzero(value: &[u8]) -> bool {
    value.iter().any(|byte| *byte != 0)
}

fn both_binding_lanes_nonzero(value: &[u8; BINDING_V2_BYTES]) -> bool {
    nonzero(&value[..BINDING_V2_BYTES / 2]) && nonzero(&value[BINDING_V2_BYTES / 2..])
}

/// Compact transcript identifier for a native-128 root. This identifier is
/// never used as Merkle authority: the full root remains header/public-view
/// pinned and every opening is verified against it. Its sole purpose is to
/// reuse the already-reviewed 64-byte algebra message slots without wrapping
/// or truncating the BindingRootV2 tree.
pub fn h4_native_root_statement_id_v2(role: u16, root: BindingRootV2) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(H4_NATIVE_ROOT_STATEMENT_ID_V2_DOMAIN);
    hash.update(role.to_be_bytes());
    hash.update(root.as_bytes());
    hash.finalize().into()
}

pub fn h4_native_digest_statement_id_v2(role: u16, digest: BindingDigestV2) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(H4_NATIVE_DIGEST_STATEMENT_ID_V2_DOMAIN);
    hash.update(role.to_be_bytes());
    hash.update(digest.as_bytes());
    hash.finalize().into()
}

fn array_at<const N: usize>(
    encoded: &[u8],
    offset: usize,
) -> Result<[u8; N], H4ProofPackageV2Error> {
    encoded
        .get(offset..offset + N)
        .ok_or(H4ProofPackageV2Error::Length)?
        .try_into()
        .map_err(|_| H4ProofPackageV2Error::Length)
}

fn u16_at(encoded: &[u8], offset: usize) -> Result<u16, H4ProofPackageV2Error> {
    Ok(u16::from_be_bytes(array_at(encoded, offset)?))
}

fn u32_at(encoded: &[u8], offset: usize) -> Result<u32, H4ProofPackageV2Error> {
    Ok(u32::from_be_bytes(array_at(encoded, offset)?))
}

fn u64_at(encoded: &[u8], offset: usize) -> Result<u64, H4ProofPackageV2Error> {
    Ok(u64::from_be_bytes(array_at(encoded, offset)?))
}

fn profile_from_code(code: u8) -> Result<H4ProofProfileV2, H4ProofPackageV2Error> {
    match code {
        1 => Ok(H4ProofProfileV2::K128),
        3 => Ok(H4ProofProfileV2::K512),
        _ => Err(H4ProofPackageV2Error::Profile),
    }
}

/// Frozen strict-PQ challenge policy for one exact H4-v2 descriptor kind.
///
/// The strict sampler applies one policy to every output in a descriptor. A
/// multi-output round therefore uses the strongest policy required by any of
/// its outputs. In particular, output-query/prelude coordinates are sampled
/// nonzero because the same descriptor also releases a nonzero mask scalar.
/// Booleanity and padding sumcheck coordinates additionally exclude one, as
/// required by their verifier-owned masked source reductions.
pub fn h4_strict_pq_policy_v2(
    descriptor: StrictPqRoundDescriptorV2,
) -> Result<StrictPqFp16PolicyV2, H4ProofPackageV2Error> {
    match descriptor.kind() {
        100
        | 113
        | 114
        | 115
        | H4_STATE_RELATION_OUTPUT_KIND
        | H4_STATE_SQUAREFREE_BETA_KIND
        | H4_STATE_SQUAREFREE_POINT_KIND
        | H4_STATE_SQUAREFREE_MIX_KIND
        | H4_STATE_COMPOSED_MASK_BATCH_KIND
        | H4_BOOLEANITY_PRELUDE_KIND
        | H4_PADDING_PRELUDE_KIND
        | H4_PADDING_TERMINAL_KIND
        | H4_PCS_CLAIM_BATCH_KIND
        | H4_PCS_INITIAL_KIND
        | H4_PCS_BASE_KIND => Ok(StrictPqFp16PolicyV2::Nonzero),
        H4_BOOLEANITY_SUMCHECK_KIND | H4_BOOLEANITY_TERMINAL_KIND | H4_PADDING_SUMCHECK_KIND => {
            Ok(StrictPqFp16PolicyV2::NonzeroNonone)
        }
        110
        | 111
        | 112
        | H4_STATE_RELATION_GROUP_KIND
        | H4_STATE_RELATION_WIRE_KIND
        | H4_STATE_RELATION_TERMINAL_KIND
        | H4_STATE_SQUAREFREE_GROUP_KIND
        | H4_STATE_SQUAREFREE_LEFT_KIND
        | H4_STATE_SQUAREFREE_RIGHT_KIND
        | H4_STATE_SQUAREFREE_TERMINAL_KIND
        | H4_PCS_ROW_KIND
        | H4_PCS_ANSWER_KIND => Ok(StrictPqFp16PolicyV2::Uniform),
        _ => Err(H4ProofPackageV2Error::Schedule),
    }
}

/// Exact global ordinal/descriptor schedule and its verifier-owned policies.
pub fn h4_strict_pq_schedule_v2(
    profile: H4ProofProfileV2,
) -> Result<(Vec<StrictPqRoundDescriptorV2>, Vec<StrictPqFp16PolicyV2>), H4ProofPackageV2Error> {
    let legacy_descriptors = selected_state_composed_round_descriptors(profile.state_capacity())
        .map_err(|_| H4ProofPackageV2Error::Schedule)?;
    if legacy_descriptors.len() != profile.transcript_rounds() as usize {
        return Err(H4ProofPackageV2Error::Schedule);
    }
    let mut descriptors = Vec::with_capacity(legacy_descriptors.len());
    let mut policies = Vec::with_capacity(legacy_descriptors.len());
    for expected_ordinal in 0..profile.transcript_rounds() {
        let legacy = legacy_descriptors
            .get(expected_ordinal as usize)
            .ok_or(H4ProofPackageV2Error::Schedule)?;
        if legacy.ordinal != expected_ordinal {
            return Err(H4ProofPackageV2Error::Schedule);
        }
        let descriptor =
            StrictPqRoundDescriptorV2::new(legacy.kind, legacy.ordinal, legacy.output_count)
                .map_err(|_| H4ProofPackageV2Error::Schedule)?;
        policies.push(h4_strict_pq_policy_v2(descriptor)?);
        descriptors.push(descriptor);
    }
    Ok((descriptors, policies))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedH4GlobalRoundFrameV2<'a> {
    shard_messages: Vec<&'a [u8]>,
    shard_ranges: Vec<core::ops::Range<usize>>,
}

impl<'a> ParsedH4GlobalRoundFrameV2<'a> {
    pub fn shard_messages(&self) -> &[&'a [u8]] {
        &self.shard_messages
    }

    pub fn shard_ranges(&self) -> &[core::ops::Range<usize>] {
        &self.shard_ranges
    }
}

/// Encode the only authenticated prover message for one synchronized H4-v2
/// round. K512 still receives one descriptor/challenge vector, not four child
/// transcript chains.
pub fn encode_h4_global_round_frame_v2(
    profile: H4ProofProfileV2,
    descriptor: StrictPqRoundDescriptorV2,
    shard_messages: &[&[u8]],
) -> Result<Vec<u8>, H4ProofPackageV2Error> {
    if shard_messages.len() != usize::from(profile.shard_count()) {
        return Err(H4ProofPackageV2Error::GlobalFrame);
    }
    let governed_maximum = if descriptor.kind() == H4_PCS_ROW_KIND {
        H4_KIND801_MAX_SHARD_MESSAGE_BYTES
    } else {
        H4_GLOBAL_MAX_SHARD_MESSAGE_BYTES
    };
    let payload_bytes = shard_messages.iter().try_fold(0_usize, |total, message| {
        if message.is_empty() || message.len() > governed_maximum {
            return Err(H4ProofPackageV2Error::GlobalFrame);
        }
        total
            .checked_add(H4_GLOBAL_ROUND_FRAME_V2_SHARD_HEADER_BYTES)
            .and_then(|value| value.checked_add(message.len()))
            .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)
    })?;
    let frame_bytes = H4_GLOBAL_ROUND_FRAME_V2_HEADER_BYTES
        .checked_add(payload_bytes)
        .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
    if frame_bytes > H4_GLOBAL_FRAME_V2_MAX_BYTES {
        return Err(H4ProofPackageV2Error::GlobalFrame);
    }
    let mut encoded = Vec::with_capacity(frame_bytes);
    encoded.extend_from_slice(H4_GLOBAL_ROUND_FRAME_V2_MAGIC);
    encoded.extend_from_slice(&[profile.code(), profile.shard_count()]);
    encoded.extend_from_slice(&descriptor.kind().to_be_bytes());
    encoded.extend_from_slice(&descriptor.ordinal().to_be_bytes());
    for (shard_index, message) in shard_messages.iter().enumerate() {
        encoded.push(
            u8::try_from(shard_index).map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?,
        );
        encoded.extend_from_slice(
            &u32::try_from(message.len())
                .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?
                .to_be_bytes(),
        );
        encoded.extend_from_slice(message);
    }
    if encoded.len() != frame_bytes {
        return Err(H4ProofPackageV2Error::Length);
    }
    Ok(encoded)
}

/// Parse one synchronized H4-v2 frame without allocating from untrusted
/// lengths. Shard ordinals must occur exactly once in canonical order.
pub fn parse_h4_global_round_frame_v2<'a>(
    encoded: &'a [u8],
    expected_profile: H4ProofProfileV2,
    expected_descriptor: StrictPqRoundDescriptorV2,
) -> Result<ParsedH4GlobalRoundFrameV2<'a>, H4ProofPackageV2Error> {
    if encoded.len() < H4_GLOBAL_ROUND_FRAME_V2_HEADER_BYTES
        || encoded.len() > H4_GLOBAL_FRAME_V2_MAX_BYTES
        || encoded.get(..8) != Some(H4_GLOBAL_ROUND_FRAME_V2_MAGIC)
        || encoded[8] != expected_profile.code()
        || encoded[9] != expected_profile.shard_count()
        || u16_at(encoded, 10)? != expected_descriptor.kind()
        || u32_at(encoded, 12)? != expected_descriptor.ordinal()
    {
        return Err(H4ProofPackageV2Error::GlobalFrame);
    }
    let governed_maximum = if expected_descriptor.kind() == H4_PCS_ROW_KIND {
        H4_KIND801_MAX_SHARD_MESSAGE_BYTES
    } else {
        H4_GLOBAL_MAX_SHARD_MESSAGE_BYTES
    };
    let mut offset = H4_GLOBAL_ROUND_FRAME_V2_HEADER_BYTES;
    let mut shard_messages = Vec::with_capacity(usize::from(expected_profile.shard_count()));
    let mut shard_ranges = Vec::with_capacity(usize::from(expected_profile.shard_count()));
    for expected_shard in 0..expected_profile.shard_count() {
        let shard = *encoded
            .get(offset)
            .ok_or(H4ProofPackageV2Error::GlobalFrame)?;
        offset = offset
            .checked_add(1)
            .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
        let message_len = usize::try_from(u32_at(encoded, offset)?)
            .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
        offset = offset
            .checked_add(4)
            .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
        let end = offset
            .checked_add(message_len)
            .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
        if shard != expected_shard || message_len == 0 || message_len > governed_maximum {
            return Err(H4ProofPackageV2Error::GlobalFrame);
        }
        shard_messages.push(
            encoded
                .get(offset..end)
                .ok_or(H4ProofPackageV2Error::GlobalFrame)?,
        );
        shard_ranges.push(offset..end);
        offset = end;
    }
    if offset != encoded.len() {
        return Err(H4ProofPackageV2Error::GlobalFrame);
    }
    Ok(ParsedH4GlobalRoundFrameV2 {
        shard_messages,
        shard_ranges,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H4AuthenticatedRoundChallengesV2 {
    descriptor: StrictPqRoundDescriptorV2,
    policy: StrictPqFp16PolicyV2,
    outputs: Vec<Fp16>,
    transcript_root: [u8; BINDING_V2_BYTES],
}

impl H4AuthenticatedRoundChallengesV2 {
    pub const fn descriptor(&self) -> StrictPqRoundDescriptorV2 {
        self.descriptor
    }

    pub const fn policy(&self) -> StrictPqFp16PolicyV2 {
        self.policy
    }

    pub fn outputs(&self) -> &[Fp16] {
        &self.outputs
    }

    pub const fn transcript_root(&self) -> &[u8; BINDING_V2_BYTES] {
        &self.transcript_root
    }
}

/// Opaque transcript-only boundary. This is deliberately not `VerifiedH4`:
/// it authenticates the global messages/challenges but proves none of the
/// shard algebra or Construction-8.2 equations by itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedH4GlobalTranscriptV2Boundary {
    profile: H4ProofProfileV2,
    rounds: Vec<H4AuthenticatedRoundChallengesV2>,
    final_transcript_root: [u8; BINDING_V2_BYTES],
}

impl VerifiedH4GlobalTranscriptV2Boundary {
    pub const fn profile(&self) -> H4ProofProfileV2 {
        self.profile
    }

    pub fn rounds(&self) -> &[H4AuthenticatedRoundChallengesV2] {
        &self.rounds
    }

    pub const fn final_transcript_root(&self) -> &[u8; BINDING_V2_BYTES] {
        &self.final_transcript_root
    }
}

/// Verify the exact strict-PQ bundle and concatenated length-prefixed global
/// frame section. The section grammar is `u32be frame_len || frame` repeated
/// once for every verifier-derived global ordinal, with no trailing byte.
pub fn verify_h4_global_transcript_v2(
    profile: H4ProofProfileV2,
    governed_key: &StrictPqGovernedVerifierKeyV2,
    strict_bundle: &[u8],
    raw_frames: &[u8],
    root_use_registry: &mut StrictPqRootUseRegistryV2,
) -> Result<VerifiedH4GlobalTranscriptV2Boundary, H4GlobalTranscriptV2Error> {
    if strict_bundle.is_empty()
        || strict_bundle.len() > STRICT_PQ_H4_MAX_BUNDLE_BYTES_V2
        || raw_frames.is_empty()
        || raw_frames.len() > H4_GLOBAL_RAW_FRAMES_V2_MAX_BYTES
        || governed_key.round_count() != profile.transcript_rounds()
    {
        return Err(H4ProofPackageV2Error::Geometry.into());
    }
    let (descriptors, policies) = h4_strict_pq_schedule_v2(profile)?;
    let bundle = StrictPqPublicCoinBundleV2::decode(strict_bundle)?;
    if bundle.rounds().len() != descriptors.len()
        || bundle
            .rounds()
            .iter()
            .zip(&descriptors)
            .any(|(round, expected)| round.descriptor() != *expected)
    {
        return Err(H4ProofPackageV2Error::Schedule.into());
    }

    let mut offset = 0_usize;
    let mut encoded_frames = Vec::with_capacity(descriptors.len());
    for descriptor in &descriptors {
        let frame_len = usize::try_from(u32_at(raw_frames, offset)?)
            .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
        offset = offset
            .checked_add(H4_GLOBAL_RAW_FRAME_LENGTH_BYTES)
            .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
        let end = offset
            .checked_add(frame_len)
            .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
        let frame = raw_frames
            .get(offset..end)
            .ok_or(H4ProofPackageV2Error::GlobalFrame)?;
        parse_h4_global_round_frame_v2(frame, profile, *descriptor)?;
        encoded_frames.push(frame);
        offset = end;
    }
    if offset != raw_frames.len() {
        return Err(H4ProofPackageV2Error::GlobalFrame.into());
    }

    let strict_outputs = replay_strict_pq_fp16_public_coin_v2(
        governed_key,
        &bundle,
        profile.strict_public_coin_profile(),
        &policies,
        &encoded_frames,
        root_use_registry,
    )?;
    if strict_outputs.len() != descriptors.len() {
        return Err(H4ProofPackageV2Error::Schedule.into());
    }
    let rounds = strict_outputs
        .into_iter()
        .zip(policies)
        .map(|(output, policy)| H4AuthenticatedRoundChallengesV2 {
            descriptor: output.challenges().descriptor(),
            policy,
            outputs: output
                .challenges()
                .samples()
                .iter()
                .copied()
                .map(|sample| sample.element())
                .collect(),
            transcript_root: *output.transcript_root(),
        })
        .collect::<Vec<_>>();
    Ok(VerifiedH4GlobalTranscriptV2Boundary {
        profile,
        rounds,
        final_transcript_root: *bundle.final_transcript_root(),
    })
}

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct H4GlobalRoundFrameLocationV2 {
    descriptor: StrictPqRoundDescriptorV2,
    frame_offset: u64,
    frame_bytes: u32,
    shard_message_offsets: [u64; 4],
    shard_message_bytes: [u32; 4],
}

#[cfg(feature = "std")]
impl H4GlobalRoundFrameLocationV2 {
    pub const fn descriptor(&self) -> StrictPqRoundDescriptorV2 {
        self.descriptor
    }

    pub const fn frame_offset(&self) -> u64 {
        self.frame_offset
    }

    pub const fn frame_bytes(&self) -> u32 {
        self.frame_bytes
    }

    pub fn shard_message(&self, shard_index: u8) -> Result<(u64, u32), H4ProofPackageV2Error> {
        let index = usize::from(shard_index);
        let bytes = *self
            .shard_message_bytes
            .get(index)
            .ok_or(H4ProofPackageV2Error::GlobalFrame)?;
        let offset = *self
            .shard_message_offsets
            .get(index)
            .ok_or(H4ProofPackageV2Error::GlobalFrame)?;
        if bytes == 0 {
            return Err(H4ProofPackageV2Error::GlobalFrame);
        }
        Ok((offset, bytes))
    }
}

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedH4ShardEnvelopeV2Boundary {
    body_offset: u64,
    header: ParsedH4ShardHeaderV2,
}

#[cfg(feature = "std")]
impl VerifiedH4ShardEnvelopeV2Boundary {
    pub const fn body_offset(&self) -> u64 {
        self.body_offset
    }

    pub const fn header(&self) -> ParsedH4ShardHeaderV2 {
        self.header
    }
}

/// Streaming envelope/transcript boundary for an H4-v2 component embedded in
/// a larger Read+Seek container. This validates the independently governed
/// header, strict global chain, every shard header, and all fixed-body zero
/// padding while keeping peak allocation bounded by the 16 MiB raw-frame
/// section plus the 3.4 MiB strict bundle. It still is not `VerifiedH4`.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedH4AggregateEnvelopeV2Boundary {
    aggregate_binding: BindingDigestV2,
    header: ParsedH4AggregateHeaderV2,
    transcript: VerifiedH4GlobalTranscriptV2Boundary,
    frame_locations: Vec<H4GlobalRoundFrameLocationV2>,
    shards: Vec<VerifiedH4ShardEnvelopeV2Boundary>,
}

#[cfg(feature = "std")]
impl VerifiedH4AggregateEnvelopeV2Boundary {
    pub const fn aggregate_binding(&self) -> BindingDigestV2 {
        self.aggregate_binding
    }

    pub const fn header(&self) -> ParsedH4AggregateHeaderV2 {
        self.header
    }

    pub const fn transcript(&self) -> &VerifiedH4GlobalTranscriptV2Boundary {
        &self.transcript
    }

    pub fn frame_locations(&self) -> &[H4GlobalRoundFrameLocationV2] {
        &self.frame_locations
    }

    pub fn shards(&self) -> &[VerifiedH4ShardEnvelopeV2Boundary] {
        &self.shards
    }
}

#[cfg(feature = "std")]
fn h4_global_frame_locations_v2(
    raw_frames: &[u8],
    raw_frames_offset: u64,
    profile: H4ProofProfileV2,
    descriptors: &[StrictPqRoundDescriptorV2],
) -> Result<Vec<H4GlobalRoundFrameLocationV2>, H4ProofPackageV2Error> {
    let mut offset = 0_usize;
    let mut locations = Vec::with_capacity(descriptors.len());
    for descriptor in descriptors {
        let frame_bytes = u32_at(raw_frames, offset)?;
        let frame_len =
            usize::try_from(frame_bytes).map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
        offset = offset
            .checked_add(H4_GLOBAL_RAW_FRAME_LENGTH_BYTES)
            .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
        let frame_start = offset;
        let frame_end = frame_start
            .checked_add(frame_len)
            .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
        let frame = raw_frames
            .get(frame_start..frame_end)
            .ok_or(H4ProofPackageV2Error::GlobalFrame)?;
        let parsed = parse_h4_global_round_frame_v2(frame, profile, *descriptor)?;
        let absolute_frame = raw_frames_offset
            .checked_add(
                u64::try_from(frame_start)
                    .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?,
            )
            .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
        let mut shard_message_offsets = [0_u64; 4];
        let mut shard_message_bytes = [0_u32; 4];
        for (shard_index, range) in parsed.shard_ranges().iter().enumerate() {
            shard_message_offsets[shard_index] = absolute_frame
                .checked_add(
                    u64::try_from(range.start)
                        .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?,
                )
                .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
            shard_message_bytes[shard_index] = u32::try_from(range.end - range.start)
                .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
        }
        locations.push(H4GlobalRoundFrameLocationV2 {
            descriptor: *descriptor,
            frame_offset: absolute_frame,
            frame_bytes,
            shard_message_offsets,
            shard_message_bytes,
        });
        offset = frame_end;
    }
    if offset != raw_frames.len() {
        return Err(H4ProofPackageV2Error::GlobalFrame);
    }
    Ok(locations)
}

#[cfg(feature = "std")]
fn scan_exact_zeroes<R: Read>(reader: &mut R, length: u64) -> Result<(), H4AggregateStreamV2Error> {
    let mut remaining = length;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        let chunk = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
        reader.read_exact(&mut buffer[..chunk])?;
        if buffer[..chunk].iter().any(|byte| *byte != 0) {
            return Err(H4ProofPackageV2Error::SectionLength.into());
        }
        remaining -= u64::try_from(chunk).map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
    }
    Ok(())
}

#[cfg(feature = "std")]
/// Checks the bounded H4 component against a governed verification key and then
/// replays its single strict public-coin chain.
///
/// `key.expected_aggregate_binding()` must be copied from the independently
/// authenticated outer component descriptor. It is not a prover-supplied
/// assertion. The exact component binding is checked before strict replay can
/// reserve any contributor root in `root_use_registry`.
pub fn verify_h4_aggregate_package_v2_streaming_boundary<R: Read + Seek>(
    reader: &mut R,
    component_offset: u64,
    component_bytes: u64,
    key: &H4AggregatePackageV2VerificationKey,
    root_use_registry: &mut StrictPqRootUseRegistryV2,
) -> Result<VerifiedH4AggregateEnvelopeV2Boundary, H4AggregateStreamV2Error> {
    let component_end = component_offset
        .checked_add(component_bytes)
        .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
    let stream_end = reader.seek(SeekFrom::End(0))?;
    if component_bytes == 0 || component_end > stream_end {
        return Err(H4ProofPackageV2Error::Length.into());
    }
    reader.seek(SeekFrom::Start(component_offset))?;

    let mut header_bytes = [0_u8; H4_AGGREGATE_PACKAGE_V2_HEADER_BYTES];
    reader.read_exact(&mut header_bytes)?;
    let header = verify_h4_aggregate_header_v2(&header_bytes, key)?;
    if u64::try_from(header.aggregate_bytes)
        .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?
        != component_bytes
    {
        return Err(H4ProofPackageV2Error::SectionLength.into());
    }

    // This pass deliberately precedes strict public-coin replay. A component
    // whose outer-authenticated binding does not match must not consume a
    // one-use Lamport root and thereby turn a malformed package into a retry
    // denial of service.
    reader.seek(SeekFrom::Start(component_offset))?;
    let mut bounded = reader.take(component_bytes);
    let aggregate_binding =
        BindingDigestV2::hash_reader_exact(BindingRoleV2::Payload, component_bytes, &mut bounded)?;
    if aggregate_binding != key.expected_aggregate_binding() {
        return Err(H4ProofPackageV2Error::RootMismatch.into());
    }
    reader.seek(SeekFrom::Start(
        component_offset
            .checked_add(H4_AGGREGATE_PACKAGE_V2_HEADER_BYTES as u64)
            .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?,
    ))?;

    let mut strict_bundle = Vec::with_capacity(header.strict_bundle_bytes);
    strict_bundle.resize(header.strict_bundle_bytes, 0);
    reader.read_exact(&mut strict_bundle)?;
    let raw_frames_offset = component_offset
        .checked_add(H4_AGGREGATE_PACKAGE_V2_HEADER_BYTES as u64)
        .and_then(|value| value.checked_add(header.strict_bundle_bytes as u64))
        .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
    let mut raw_frames = Vec::with_capacity(header.raw_frames_bytes);
    raw_frames.resize(header.raw_frames_bytes, 0);
    reader.read_exact(&mut raw_frames)?;

    let transcript = verify_h4_global_transcript_v2(
        header.profile,
        key.strict_public_coin_key(),
        &strict_bundle,
        &raw_frames,
        root_use_registry,
    )?;
    let (descriptors, _) = h4_strict_pq_schedule_v2(header.profile)?;
    let frame_locations =
        h4_global_frame_locations_v2(&raw_frames, raw_frames_offset, header.profile, &descriptors)?;
    drop(raw_frames);
    drop(strict_bundle);

    let shard_bodies_offset = raw_frames_offset
        .checked_add(header.raw_frames_bytes as u64)
        .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
    let mut shards = Vec::with_capacity(usize::from(header.profile.shard_count()));
    for expected_shard in 0..header.profile.shard_count() {
        let body_offset = shard_bodies_offset
            .checked_add(
                u64::from(expected_shard)
                    .checked_mul(H4_PROOF_PACKAGE_V2_BYTES as u64)
                    .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?,
            )
            .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
        reader.seek(SeekFrom::Start(body_offset))?;
        let mut shard_header_bytes = [0_u8; H4_PROOF_PACKAGE_V2_HEADER_BYTES];
        reader.read_exact(&mut shard_header_bytes)?;
        let shard = parse_h4_shard_header_v2(&shard_header_bytes)?;
        if shard.profile != header.profile
            || shard.shard_index != expected_shard
            || shard.attempt != header.attempt
            || shard.profile_identity != header.profile_identity
            || shard.program_commitment != header.program_commitment
            || shard.schedule_commitment != header.schedule_commitment
            || shard.session_id != header.session_id
        {
            return Err(H4ProofPackageV2Error::Schedule.into());
        }
        let padding_offset = body_offset
            .checked_add(
                u64::try_from(shard.compact_core_bytes)
                    .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?,
            )
            .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
        let body_end = body_offset
            .checked_add(H4_PROOF_PACKAGE_V2_BYTES as u64)
            .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
        reader.seek(SeekFrom::Start(padding_offset))?;
        scan_exact_zeroes(reader, body_end - padding_offset)?;
        shards.push(VerifiedH4ShardEnvelopeV2Boundary {
            body_offset,
            header: shard,
        });
    }
    if shard_bodies_offset
        .checked_add(
            u64::from(header.profile.shard_count())
                .checked_mul(H4_PROOF_PACKAGE_V2_BYTES as u64)
                .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?,
        )
        .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?
        != component_end
    {
        return Err(H4ProofPackageV2Error::SectionLength.into());
    }

    Ok(VerifiedH4AggregateEnvelopeV2Boundary {
        aggregate_binding,
        header,
        transcript,
        frame_locations,
        shards,
    })
}

pub const fn max_canonical_frontier_nodes(
    leaf_count: usize,
    opening_count: usize,
) -> Option<usize> {
    if leaf_count == 0
        || !leaf_count.is_power_of_two()
        || opening_count == 0
        || opening_count > leaf_count
    {
        return None;
    }
    let mut nodes = leaf_count;
    let mut active = opening_count;
    let mut frontier = 0_usize;
    while nodes > 1 {
        nodes /= 2;
        let next = if active < nodes { active } else { nodes };
        frontier += 2 * next - active;
        active = next;
    }
    if active == 1 { Some(frontier) } else { None }
}

const fn segment_max_bytes(openings: usize, leaf_bytes: usize, frontier: usize) -> usize {
    H4_RS_SEGMENT_V2_HEADER_BYTES
        + openings * 4
        + openings * leaf_bytes
        + frontier * BINDING_V2_BYTES
}

pub const fn h4_rs_multiproof_v2_max_bytes(_profile: H4ProofProfileV2) -> usize {
    H4_RS_MULTIPROOF_V2_PREFIX_BYTES
        + segment_max_bytes(
            H4_MAIN_OPENINGS,
            H4_SOURCE_LEAF_BYTES,
            H4_MAIN_MAX_FRONTIER_NODES,
        )
        + segment_max_bytes(
            H4_AUXILIARY_OPENINGS,
            19 * 64,
            H4_AUXILIARY_MAX_FRONTIER_NODES,
        )
        + segment_max_bytes(H4_AUXILIARY_OPENINGS, 64, H4_TENSOR_MAX_FRONTIER_NODES)
        + segment_max_bytes(H4_MAIN_OPENINGS, 64, H4_MAIN_MAX_FRONTIER_NODES)
        + segment_max_bytes(H4_AUXILIARY_OPENINGS, 64, H4_TENSOR_MAX_FRONTIER_NODES)
        + segment_max_bytes(H4_AUXILIARY_OPENINGS, 64, H4_AUXILIARY_MAX_FRONTIER_NODES)
}

pub const fn h4_public_view_v2_max_bytes(profile: H4ProofProfileV2) -> usize {
    H4_PUBLIC_VIEW_V2_FIXED_BYTES
        + h4_rs_multiproof_v2_max_bytes(profile)
        + segment_max_bytes(
            H4_MAIN_OPENINGS,
            H4_SOURCE_LEAF_BYTES,
            H4_MAIN_MAX_FRONTIER_NODES,
        )
        + segment_max_bytes(
            H4_MAIN_OPENINGS,
            H4_BRIDGE_BASE_LEAF_BYTES,
            H4_MAIN_MAX_FRONTIER_NODES,
        )
        + crate::h4_bridge_source_response_v2::H4_BRIDGE_SOURCE_RESPONSE_V2_BYTES
}

pub const fn h4_shard_compact_core_v2_max_bytes(profile: H4ProofProfileV2) -> usize {
    H4_PROOF_PACKAGE_V2_HEADER_BYTES
        + h4_public_view_v2_max_bytes(profile)
        + H4_ANSWER_COEFFICIENT_BYTES
        + H4_BLSQAB03_BYTES
}

pub const fn h4_aggregate_package_v2_max_bytes(profile: H4ProofProfileV2) -> usize {
    H4_AGGREGATE_PACKAGE_V2_HEADER_BYTES
        + STRICT_PQ_H4_MAX_BUNDLE_BYTES_V2
        + H4_GLOBAL_RAW_FRAMES_V2_MAX_BYTES
        + profile.shard_count() as usize * H4_PROOF_PACKAGE_V2_BYTES
}

/// Governed inputs that must exist independently of an untrusted H4-v2
/// package. The expected aggregate binding is an outer/container commitment,
/// never a value learned from the package being checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H4AggregatePackageV2VerificationKey {
    profile: H4ProofProfileV2,
    attempt: u16,
    profile_identity: [u8; 64],
    program_commitment: [u8; 64],
    statement_binding: BindingDigestV2,
    gkr_statement_bindings: [BindingDigestV2; 4],
    state_relation_source_binding: BindingDigestV2,
    expected_aggregate_binding: BindingDigestV2,
    strict_public_coin_key: StrictPqGovernedVerifierKeyV2,
}

impl H4AggregatePackageV2VerificationKey {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile: H4ProofProfileV2,
        attempt: u16,
        profile_identity: [u8; 64],
        program_commitment: [u8; 64],
        statement_binding: BindingDigestV2,
        gkr_statement_bindings: [BindingDigestV2; 4],
        state_relation_source_binding: BindingDigestV2,
        expected_aggregate_binding: BindingDigestV2,
        strict_public_coin_key: StrictPqGovernedVerifierKeyV2,
    ) -> Result<Self, H4ProofPackageV2Error> {
        if attempt >= H4_DURABLE_MAX_ATTEMPTS_PER_STATEMENT
            || u16::from(strict_public_coin_key.attempt()) != attempt
            || strict_public_coin_key.round_count() != profile.transcript_rounds()
            || !nonzero(&profile_identity)
            || !nonzero(&program_commitment)
            || !nonzero(strict_public_coin_key.session_id())
            || !nonzero(strict_public_coin_key.schedule_commitment())
        {
            return Err(H4ProofPackageV2Error::Geometry);
        }
        for binding in [
            statement_binding,
            state_relation_source_binding,
            expected_aggregate_binding,
        ] {
            if !both_binding_lanes_nonzero(binding.as_bytes()) {
                return Err(H4ProofPackageV2Error::LegacyRootWidth);
            }
        }
        for (index, binding) in gkr_statement_bindings.iter().enumerate() {
            let live = index < usize::from(profile.shard_count());
            if live != both_binding_lanes_nonzero(binding.as_bytes()) {
                return Err(H4ProofPackageV2Error::LegacyRootWidth);
            }
        }
        Ok(Self {
            profile,
            attempt,
            profile_identity,
            program_commitment,
            statement_binding,
            gkr_statement_bindings,
            state_relation_source_binding,
            expected_aggregate_binding,
            strict_public_coin_key,
        })
    }

    pub const fn profile(&self) -> H4ProofProfileV2 {
        self.profile
    }

    pub const fn attempt(&self) -> u16 {
        self.attempt
    }

    pub const fn expected_aggregate_binding(&self) -> BindingDigestV2 {
        self.expected_aggregate_binding
    }

    pub const fn profile_identity(&self) -> &[u8; 64] {
        &self.profile_identity
    }

    pub const fn program_commitment(&self) -> &[u8; 64] {
        &self.program_commitment
    }

    pub const fn statement_binding(&self) -> BindingDigestV2 {
        self.statement_binding
    }

    pub const fn state_relation_source_binding(&self) -> BindingDigestV2 {
        self.state_relation_source_binding
    }

    pub const fn strict_public_coin_key(&self) -> &StrictPqGovernedVerifierKeyV2 {
        &self.strict_public_coin_key
    }

    pub const fn gkr_statement_bindings(&self) -> &[BindingDigestV2; 4] {
        &self.gkr_statement_bindings
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedH4AggregateHeaderV2 {
    pub profile: H4ProofProfileV2,
    pub attempt: u16,
    pub strict_bundle_bytes: usize,
    pub raw_frames_bytes: usize,
    pub aggregate_bytes: usize,
    pub profile_identity: [u8; 64],
    pub program_commitment: [u8; 64],
    pub schedule_commitment: [u8; 64],
    pub session_id: [u8; 64],
    pub governed_key_binding: BindingDigestV2,
    pub statement_binding: BindingDigestV2,
    pub state_relation_source_binding: BindingDigestV2,
}

pub fn parse_h4_aggregate_header_v2(
    encoded: &[u8],
) -> Result<ParsedH4AggregateHeaderV2, H4ProofPackageV2Error> {
    if encoded.len() != H4_AGGREGATE_PACKAGE_V2_HEADER_BYTES {
        return Err(H4ProofPackageV2Error::Length);
    }
    if encoded.get(..8) != Some(H4_AGGREGATE_PACKAGE_V2_MAGIC) {
        return Err(H4ProofPackageV2Error::Magic);
    }
    if u16_at(encoded, 8)? != H4_AGGREGATE_PACKAGE_V2_VERSION {
        return Err(H4ProofPackageV2Error::Version);
    }
    let profile = profile_from_code(encoded[10])?;
    let shard_count = encoded[11];
    let attempt = u16_at(encoded, 12)?;
    if shard_count != profile.shard_count()
        || attempt >= H4_DURABLE_MAX_ATTEMPTS_PER_STATEMENT
        || u16_at(encoded, 14)? != 0
    {
        return Err(H4ProofPackageV2Error::Flags);
    }
    let strict_bundle_bytes = usize::try_from(u64_at(encoded, 16)?)
        .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
    let raw_frames_bytes = usize::try_from(u64_at(encoded, 24)?)
        .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
    let shard_body_bytes = usize::try_from(u64_at(encoded, 32)?)
        .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
    let aggregate_bytes = usize::try_from(u64_at(encoded, 40)?)
        .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
    if u32_at(encoded, 48)? != profile.transcript_rounds()
        || u16_at(encoded, 52)? != H4_GLOBAL_ROUND_FRAME_V2_VERSION
        || encoded[54..64] != [0_u8; 10]
        || strict_bundle_bytes == 0
        || strict_bundle_bytes > STRICT_PQ_H4_MAX_BUNDLE_BYTES_V2
        || raw_frames_bytes == 0
        || raw_frames_bytes > H4_GLOBAL_RAW_FRAMES_V2_MAX_BYTES
        || shard_body_bytes != H4_PROOF_PACKAGE_V2_BYTES
    {
        return Err(H4ProofPackageV2Error::Geometry);
    }
    let expected_aggregate_bytes = H4_AGGREGATE_PACKAGE_V2_HEADER_BYTES
        .checked_add(strict_bundle_bytes)
        .and_then(|value| value.checked_add(raw_frames_bytes))
        .and_then(|value| {
            usize::from(shard_count)
                .checked_mul(shard_body_bytes)
                .and_then(|shards| value.checked_add(shards))
        })
        .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
    if aggregate_bytes != expected_aggregate_bytes
        || aggregate_bytes > h4_aggregate_package_v2_max_bytes(profile)
    {
        return Err(H4ProofPackageV2Error::SectionLength);
    }
    if encoded[64..128] != NULL_PROOF_SUITE_ID {
        return Err(H4ProofPackageV2Error::ProofSuite);
    }
    let profile_identity = array_at(encoded, 128)?;
    let program_commitment = array_at(encoded, 192)?;
    let schedule_commitment = array_at(encoded, 256)?;
    let session_id = array_at(encoded, 320)?;
    let governed_key_binding = BindingDigestV2::decode(&encoded[384..512])?;
    let statement_binding = BindingDigestV2::decode(&encoded[512..640])?;
    let state_relation_source_binding = BindingDigestV2::decode(&encoded[640..768])?;
    if [
        profile_identity.as_slice(),
        program_commitment.as_slice(),
        schedule_commitment.as_slice(),
        session_id.as_slice(),
        governed_key_binding.as_bytes().as_slice(),
        statement_binding.as_bytes().as_slice(),
        state_relation_source_binding.as_bytes().as_slice(),
    ]
    .into_iter()
    .any(|value| !nonzero(value))
    {
        return Err(H4ProofPackageV2Error::ZeroIdentifier);
    }
    if !both_binding_lanes_nonzero(governed_key_binding.as_bytes())
        || !both_binding_lanes_nonzero(statement_binding.as_bytes())
        || !both_binding_lanes_nonzero(state_relation_source_binding.as_bytes())
    {
        return Err(H4ProofPackageV2Error::LegacyRootWidth);
    }
    Ok(ParsedH4AggregateHeaderV2 {
        profile,
        attempt,
        strict_bundle_bytes,
        raw_frames_bytes,
        aggregate_bytes,
        profile_identity,
        program_commitment,
        schedule_commitment,
        session_id,
        governed_key_binding,
        statement_binding,
        state_relation_source_binding,
    })
}

/// Inputs for the bounded H4-v2 aggregate writer.
///
/// This assembles already-produced global transcript frames and fixed shard
/// artifacts. It does not verify the proof or create an accepting receipt;
/// the native streaming verifier remains the authority for those operations.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct H4AggregatePackageV2WriteInput<'a> {
    pub profile: H4ProofProfileV2,
    pub attempt: u16,
    pub profile_identity: [u8; 64],
    pub program_commitment: [u8; 64],
    pub schedule_commitment: [u8; 64],
    pub session_id: [u8; 64],
    pub governed_key_binding: BindingDigestV2,
    pub statement_binding: BindingDigestV2,
    pub state_relation_source_binding: BindingDigestV2,
    pub strict_bundle: &'a [u8],
    pub raw_frames: &'a [u8],
    pub shard_bodies: &'a [&'a [u8]],
}

#[cfg(feature = "std")]
fn validate_h4_aggregate_write_input(
    input: &H4AggregatePackageV2WriteInput<'_>,
) -> Result<usize, H4AggregateStreamV2Error> {
    if input.attempt >= H4_DURABLE_MAX_ATTEMPTS_PER_STATEMENT
        || !nonzero(&input.profile_identity)
        || !nonzero(&input.program_commitment)
        || !nonzero(&input.schedule_commitment)
        || !nonzero(&input.session_id)
        || !both_binding_lanes_nonzero(input.governed_key_binding.as_bytes())
        || !both_binding_lanes_nonzero(input.statement_binding.as_bytes())
        || !both_binding_lanes_nonzero(input.state_relation_source_binding.as_bytes())
    {
        return Err(H4ProofPackageV2Error::Geometry.into());
    }
    if input.shard_bodies.len() != usize::from(input.profile.shard_count())
        || input.strict_bundle.is_empty()
        || input.strict_bundle.len() > STRICT_PQ_H4_MAX_BUNDLE_BYTES_V2
        || input.raw_frames.is_empty()
        || input.raw_frames.len() > H4_GLOBAL_RAW_FRAMES_V2_MAX_BYTES
    {
        return Err(H4ProofPackageV2Error::SectionLength.into());
    }

    let bundle = StrictPqPublicCoinBundleV2::decode(input.strict_bundle)
        .map_err(|error| H4AggregateStreamV2Error::Transcript(error.into()))?;
    if bundle.attempt() != u8::try_from(input.attempt).unwrap_or(u8::MAX)
        || bundle.session_id() != &input.session_id
        || bundle.schedule_commitment() != &input.schedule_commitment
    {
        return Err(H4ProofPackageV2Error::Schedule.into());
    }
    let (descriptors, _) = h4_strict_pq_schedule_v2(input.profile)?;
    if bundle.rounds().len() != descriptors.len()
        || bundle
            .rounds()
            .iter()
            .zip(&descriptors)
            .any(|(round, expected)| round.descriptor() != *expected)
    {
        return Err(H4ProofPackageV2Error::Schedule.into());
    }

    let mut offset = 0_usize;
    for descriptor in &descriptors {
        let frame_len = usize::try_from(u32_at(input.raw_frames, offset)?)
            .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
        offset = offset
            .checked_add(H4_GLOBAL_RAW_FRAME_LENGTH_BYTES)
            .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
        let end = offset
            .checked_add(frame_len)
            .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
        let frame = input
            .raw_frames
            .get(offset..end)
            .ok_or(H4ProofPackageV2Error::GlobalFrame)?;
        parse_h4_global_round_frame_v2(frame, input.profile, *descriptor)?;
        offset = end;
    }
    if offset != input.raw_frames.len() {
        return Err(H4ProofPackageV2Error::GlobalFrame.into());
    }

    for (shard_index, body) in input.shard_bodies.iter().enumerate() {
        if body.len() != H4_PROOF_PACKAGE_V2_BYTES {
            return Err(H4ProofPackageV2Error::SectionLength.into());
        }
        let header = parse_h4_shard_header_v2(
            body.get(..H4_PROOF_PACKAGE_V2_HEADER_BYTES)
                .ok_or(H4ProofPackageV2Error::Length)?,
        )?;
        if header.profile != input.profile
            || header.shard_index != u8::try_from(shard_index).unwrap_or(u8::MAX)
            || header.attempt != input.attempt
            || header.profile_identity != input.profile_identity
            || header.program_commitment != input.program_commitment
            || header.schedule_commitment != input.schedule_commitment
            || header.session_id != input.session_id
        {
            return Err(H4ProofPackageV2Error::Schedule.into());
        }
    }

    let aggregate_bytes = H4_AGGREGATE_PACKAGE_V2_HEADER_BYTES
        .checked_add(input.strict_bundle.len())
        .and_then(|value| value.checked_add(input.raw_frames.len()))
        .and_then(|value| {
            input
                .shard_bodies
                .len()
                .checked_mul(H4_PROOF_PACKAGE_V2_BYTES)
                .and_then(|shards| value.checked_add(shards))
        })
        .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
    if aggregate_bytes > h4_aggregate_package_v2_max_bytes(input.profile) {
        return Err(H4ProofPackageV2Error::SectionLength.into());
    }
    Ok(aggregate_bytes)
}

#[cfg(feature = "std")]
fn encode_h4_aggregate_header_v2(
    input: &H4AggregatePackageV2WriteInput<'_>,
    aggregate_bytes: usize,
) -> Result<[u8; H4_AGGREGATE_PACKAGE_V2_HEADER_BYTES], H4ProofPackageV2Error> {
    let mut header = [0_u8; H4_AGGREGATE_PACKAGE_V2_HEADER_BYTES];
    header[..8].copy_from_slice(H4_AGGREGATE_PACKAGE_V2_MAGIC);
    header[8..10].copy_from_slice(&H4_AGGREGATE_PACKAGE_V2_VERSION.to_be_bytes());
    header[10] = input.profile.code();
    header[11] = input.profile.shard_count();
    header[12..14].copy_from_slice(&input.attempt.to_be_bytes());
    header[16..24].copy_from_slice(
        &u64::try_from(input.strict_bundle.len())
            .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?
            .to_be_bytes(),
    );
    header[24..32].copy_from_slice(
        &u64::try_from(input.raw_frames.len())
            .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?
            .to_be_bytes(),
    );
    header[32..40].copy_from_slice(&(H4_PROOF_PACKAGE_V2_BYTES as u64).to_be_bytes());
    header[40..48].copy_from_slice(
        &u64::try_from(aggregate_bytes)
            .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?
            .to_be_bytes(),
    );
    header[48..52].copy_from_slice(&input.profile.transcript_rounds().to_be_bytes());
    header[52..54].copy_from_slice(&H4_GLOBAL_ROUND_FRAME_V2_VERSION.to_be_bytes());
    header[128..192].copy_from_slice(&input.profile_identity);
    header[192..256].copy_from_slice(&input.program_commitment);
    header[256..320].copy_from_slice(&input.schedule_commitment);
    header[320..384].copy_from_slice(&input.session_id);
    header[384..512].copy_from_slice(input.governed_key_binding.as_bytes());
    header[512..640].copy_from_slice(input.statement_binding.as_bytes());
    header[640..768].copy_from_slice(input.state_relation_source_binding.as_bytes());
    Ok(header)
}

/// Stream one H4-v2 aggregate artifact without materializing the fixed shard
/// bodies a second time. The output is still unqualified until the native
/// verifier replays the complete package.
#[cfg(feature = "std")]
pub fn write_h4_aggregate_package_v2<W: Write>(
    writer: &mut W,
    input: &H4AggregatePackageV2WriteInput<'_>,
) -> Result<usize, H4AggregateStreamV2Error> {
    let aggregate_bytes = validate_h4_aggregate_write_input(input)?;
    let header = encode_h4_aggregate_header_v2(input, aggregate_bytes)?;
    writer.write_all(&header)?;
    writer.write_all(input.strict_bundle)?;
    writer.write_all(input.raw_frames)?;
    for body in input.shard_bodies {
        writer.write_all(body)?;
    }
    Ok(aggregate_bytes)
}

pub fn verify_h4_aggregate_header_v2(
    encoded: &[u8],
    key: &H4AggregatePackageV2VerificationKey,
) -> Result<ParsedH4AggregateHeaderV2, H4ProofPackageV2Error> {
    let header = parse_h4_aggregate_header_v2(encoded)?;
    let governed_key_binding = key
        .strict_public_coin_key
        .binding()
        .map_err(|_| H4ProofPackageV2Error::Schedule)?;
    if header.profile != key.profile
        || header.attempt != key.attempt
        || header.profile_identity != key.profile_identity
        || header.program_commitment != key.program_commitment
        || header.schedule_commitment != *key.strict_public_coin_key.schedule_commitment()
        || header.session_id != *key.strict_public_coin_key.session_id()
        || header.governed_key_binding != governed_key_binding
        || header.statement_binding != key.statement_binding
        || header.state_relation_source_binding != key.state_relation_source_binding
    {
        return Err(H4ProofPackageV2Error::Schedule);
    }
    Ok(header)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedH4ShardHeaderV2 {
    pub profile: H4ProofProfileV2,
    pub shard_index: u8,
    pub attempt: u16,
    pub compact_core_bytes: usize,
    pub public_view_bytes: usize,
    pub profile_identity: [u8; 64],
    pub program_commitment: [u8; 64],
    pub schedule_commitment: [u8; 64],
    pub session_id: [u8; 64],
    pub source_tensor_root: BindingRootV2,
    pub gkr_mask_tensor_root: BindingRootV2,
    pub bridge_base_tensor_root: BindingRootV2,
}

pub fn parse_h4_shard_header_v2(
    encoded: &[u8],
) -> Result<ParsedH4ShardHeaderV2, H4ProofPackageV2Error> {
    if encoded.len() != H4_PROOF_PACKAGE_V2_HEADER_BYTES {
        return Err(H4ProofPackageV2Error::Length);
    }
    if encoded.get(..8) != Some(H4_PROOF_PACKAGE_V2_MAGIC) {
        return Err(H4ProofPackageV2Error::Magic);
    }
    if u16_at(encoded, 8)? != H4_PROOF_PACKAGE_V2_VERSION {
        return Err(H4ProofPackageV2Error::Version);
    }
    let profile = profile_from_code(encoded[10])?;
    let shard_index = encoded[11];
    if shard_index >= profile.shard_count()
        || encoded[12] != profile.shard_count()
        || encoded[13] != 0
        || encoded[14..16] != [0_u8; 2]
        || encoded[54..64] != [0_u8; 10]
    {
        return Err(H4ProofPackageV2Error::Geometry);
    }
    let compact_core_bytes = usize::try_from(u64_at(encoded, 16)?)
        .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
    let embedded_public_coin_bytes = usize::try_from(u64_at(encoded, 24)?)
        .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
    let public_view_bytes = usize::try_from(u64_at(encoded, 32)?)
        .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
    let answer_bytes = usize::try_from(u64_at(encoded, 40)?)
        .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
    let binding_bytes = usize::try_from(u32_at(encoded, 48)?)
        .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
    let attempt = u16_at(encoded, 52)?;
    let expected_core = H4_PROOF_PACKAGE_V2_HEADER_BYTES
        .checked_add(public_view_bytes)
        .and_then(|value| value.checked_add(answer_bytes))
        .and_then(|value| value.checked_add(binding_bytes))
        .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
    if embedded_public_coin_bytes != 0
        || attempt >= H4_DURABLE_MAX_ATTEMPTS_PER_STATEMENT
        || public_view_bytes < H4_PUBLIC_VIEW_V2_FIXED_BYTES + H4_RS_MULTIPROOF_V2_PREFIX_BYTES
        || public_view_bytes > h4_public_view_v2_max_bytes(profile)
        || answer_bytes != H4_ANSWER_COEFFICIENT_BYTES
        || binding_bytes != H4_BLSQAB03_BYTES
        || compact_core_bytes != expected_core
        || compact_core_bytes > h4_shard_compact_core_v2_max_bytes(profile)
        || compact_core_bytes >= H4_PROOF_PACKAGE_V2_BYTES
    {
        return Err(H4ProofPackageV2Error::SectionLength);
    }
    if encoded[64..128] != NULL_PROOF_SUITE_ID {
        return Err(H4ProofPackageV2Error::ProofSuite);
    }
    let profile_identity = array_at(encoded, 128)?;
    let program_commitment = array_at(encoded, 192)?;
    let schedule_commitment = array_at(encoded, 256)?;
    let session_id = array_at(encoded, 320)?;
    if [
        profile_identity.as_slice(),
        program_commitment.as_slice(),
        schedule_commitment.as_slice(),
        session_id.as_slice(),
    ]
    .into_iter()
    .any(|value| !nonzero(value))
    {
        return Err(H4ProofPackageV2Error::ZeroIdentifier);
    }
    let source_tensor_root = BindingRootV2::decode(&encoded[384..512])?;
    let gkr_mask_tensor_root = BindingRootV2::decode(&encoded[512..640])?;
    let bridge_base_tensor_root = BindingRootV2::decode(&encoded[640..768])?;
    if !both_binding_lanes_nonzero(source_tensor_root.as_bytes())
        || !both_binding_lanes_nonzero(gkr_mask_tensor_root.as_bytes())
        || !both_binding_lanes_nonzero(bridge_base_tensor_root.as_bytes())
    {
        return Err(H4ProofPackageV2Error::LegacyRootWidth);
    }
    Ok(ParsedH4ShardHeaderV2 {
        profile,
        shard_index,
        attempt,
        compact_core_bytes,
        public_view_bytes,
        profile_identity,
        program_commitment,
        schedule_commitment,
        session_id,
        source_tensor_root,
        gkr_mask_tensor_root,
        bridge_base_tensor_root,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct H4NativeRootInventoryV2 {
    pub sumcheck_base_root: BindingRootV2,
    pub main_base_root: BindingRootV2,
    pub gkr_base_tensor_root: BindingRootV2,
    pub squarefree_root: BindingRootV2,
    pub answer_tensor_root: BindingRootV2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ParsedH4PublicViewV2<'a> {
    pub roots: H4NativeRootInventoryV2,
    pub packed_claims: &'a [u8],
    pub relation_terminals: &'a [u8],
    pub pcs_multiproofs: &'a [u8],
}

pub(crate) fn parse_h4_public_view_v2(
    encoded: &[u8],
) -> Result<ParsedH4PublicViewV2<'_>, H4ProofPackageV2Error> {
    if encoded.len() < H4_PUBLIC_VIEW_V2_FIXED_BYTES + H4_RS_MULTIPROOF_V2_PREFIX_BYTES
        || encoded.get(..8) != Some(H4_PUBLIC_VIEW_V2_MAGIC)
        || u16_at(encoded, 8)? != H4_PUBLIC_VIEW_V2_VERSION
        || u16_at(encoded, 10)? != 0
        || usize::from(u16_at(encoded, 12)?) != GKR_CLAIM_COUNT
        || usize::from(u16_at(encoded, 14)?) != H4_GKR_RELATION_TERMINAL_BYTES / 64
        || usize::try_from(u32_at(encoded, 16)?)
            .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?
            != H4_PACKED_CLAIMS_BYTES
        || usize::try_from(u32_at(encoded, 20)?)
            .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?
            != H4_GKR_RELATION_TERMINAL_BYTES
    {
        return Err(H4ProofPackageV2Error::Geometry);
    }
    let pcs_bytes = usize::try_from(u64_at(encoded, 24)?)
        .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
    let roots_start = H4_PUBLIC_VIEW_V2_HEADER_BYTES;
    let claims_start = roots_start + H4_PUBLIC_VIEW_V2_ROOT_INVENTORY_BYTES;
    let terminals_start = claims_start + H4_PACKED_CLAIMS_BYTES;
    let pcs_start = terminals_start + H4_GKR_RELATION_TERMINAL_BYTES;
    if pcs_bytes < H4_RS_MULTIPROOF_V2_PREFIX_BYTES
        || pcs_start.checked_add(pcs_bytes) != Some(encoded.len())
    {
        return Err(H4ProofPackageV2Error::SectionLength);
    }
    let roots = H4NativeRootInventoryV2 {
        sumcheck_base_root: BindingRootV2::decode(&encoded[roots_start..roots_start + 128])?,
        main_base_root: BindingRootV2::decode(&encoded[roots_start + 128..roots_start + 256])?,
        gkr_base_tensor_root: BindingRootV2::decode(
            &encoded[roots_start + 256..roots_start + 384],
        )?,
        squarefree_root: BindingRootV2::decode(&encoded[roots_start + 384..roots_start + 512])?,
        answer_tensor_root: BindingRootV2::decode(&encoded[roots_start + 512..claims_start])?,
    };
    if [
        roots.sumcheck_base_root,
        roots.main_base_root,
        roots.gkr_base_tensor_root,
        roots.squarefree_root,
        roots.answer_tensor_root,
    ]
    .iter()
    .any(|root| !both_binding_lanes_nonzero(root.as_bytes()))
    {
        return Err(H4ProofPackageV2Error::LegacyRootWidth);
    }
    Ok(ParsedH4PublicViewV2 {
        roots,
        packed_claims: &encoded[claims_start..terminals_start],
        relation_terminals: &encoded[terminals_start..pcs_start],
        pcs_multiproofs: &encoded[pcs_start..],
    })
}

/// Validate the full native-128 square-free claim record and produce the
/// byte-compatible algebra view used by the reviewed H4 verifier.  The
/// 64-byte values in the compatibility view are statement identifiers only;
/// authority remains the full BindingRootV2/BindingDigestV2 checked here.
fn squarefree_binding_v1_compatibility_v2(
    encoded: &[u8],
    expected_squarefree_root: BindingRootV2,
    expected_capacity: u16,
) -> Result<Vec<u8>, H4ProofPackageV2Error> {
    if encoded.len() != H4_BLSQAB03_BYTES
        || encoded.get(..8) != Some(b"BLSQAB03")
        || encoded.get(8..16) != Some(b"BLSQCL03")
    {
        return Err(H4ProofPackageV2Error::Algebra);
    }
    let root = BindingRootV2::decode(&encoded[16..16 + BINDING_V2_BYTES])?;
    let scalar_offset = 16 + BINDING_V2_BYTES;
    let capacity = u16_at(encoded, scalar_offset)?;
    let count = u16_at(encoded, scalar_offset + 2)?;
    let digest_offset = scalar_offset + 4;
    let claims_digest = BindingDigestV2::decode(
        encoded
            .get(digest_offset..digest_offset + BINDING_V2_BYTES)
            .ok_or(H4ProofPackageV2Error::Length)?,
    )?;
    let payload_offset = 8 + H4_BLSQCL03_BYTES;
    if root != expected_squarefree_root || capacity != expected_capacity || count != 2 {
        return Err(H4ProofPackageV2Error::RootMismatch);
    }
    let mut preimage = Vec::with_capacity(
        H4_SQUAREFREE_CLAIMS_DIGEST_V2_DOMAIN.len() + BINDING_V2_BYTES + 4 + 2 * (8 + 12 * 64),
    );
    preimage.extend_from_slice(H4_SQUAREFREE_CLAIMS_DIGEST_V2_DOMAIN);
    preimage.extend_from_slice(root.as_bytes());
    preimage.extend_from_slice(&capacity.to_be_bytes());
    preimage.extend_from_slice(&count.to_be_bytes());
    let phase_end = payload_offset
        .checked_add(2 * (8 + 12 * 64))
        .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
    let phase_bytes = encoded
        .get(payload_offset..phase_end)
        .ok_or(H4ProofPackageV2Error::Length)?;
    for phase in phase_bytes.chunks_exact(8 + 12 * 64) {
        if u16::from_be_bytes(
            phase[..2]
                .try_into()
                .map_err(|_| H4ProofPackageV2Error::Length)?,
        ) != 11
            || phase[2..8] != [0_u8; 6]
        {
            return Err(H4ProofPackageV2Error::Algebra);
        }
        for value in phase[8..].chunks_exact(64) {
            let value: &[u8; 64] = value
                .try_into()
                .map_err(|_| H4ProofPackageV2Error::Length)?;
            Fp16::decode(value).map_err(|_| H4ProofPackageV2Error::NonCanonicalField)?;
        }
    }
    preimage.extend_from_slice(phase_bytes);
    if BindingDigestV2::hash(BindingRoleV2::Payload, &preimage)? != claims_digest {
        return Err(H4ProofPackageV2Error::RootMismatch);
    }
    for value in encoded[phase_end..].chunks_exact(64) {
        let value: &[u8; 64] = value
            .try_into()
            .map_err(|_| H4ProofPackageV2Error::Length)?;
        let decoded = Fp16::decode(value).map_err(|_| H4ProofPackageV2Error::NonCanonicalField)?;
        if decoded.is_zero() {
            return Err(H4ProofPackageV2Error::Algebra);
        }
    }

    let root_id = h4_native_root_statement_id_v2(PCS_SQUAREFREE_KIND as u16, root);
    let digest_id = h4_native_digest_statement_id_v2(PCS_SQUAREFREE_KIND as u16, claims_digest);
    let mut claim_v1 = Vec::with_capacity(crate::h4_proof_package_v1::H4_BLSQCL02_BYTES);
    claim_v1.extend_from_slice(b"BLSQCL02");
    claim_v1.extend_from_slice(&root_id);
    claim_v1.extend_from_slice(&capacity.to_be_bytes());
    claim_v1.extend_from_slice(&count.to_be_bytes());
    claim_v1.extend_from_slice(&digest_id);
    let mut answer_v1 = Vec::with_capacity(crate::h4_proof_package_v1::H4_BLSQAB02_BYTES);
    answer_v1.extend_from_slice(b"BLSQAB02");
    answer_v1.extend_from_slice(&claim_v1);
    answer_v1.extend_from_slice(phase_bytes);
    answer_v1.extend_from_slice(
        encoded
            .get(phase_end..)
            .ok_or(H4ProofPackageV2Error::Length)?,
    );
    if answer_v1.len() != crate::h4_proof_package_v1::H4_BLSQAB02_BYTES {
        return Err(H4ProofPackageV2Error::Length);
    }
    Ok(answer_v1)
}

fn h4_v1_compatibility_body_v2(
    header: ParsedH4ShardHeaderV2,
    public_view: ParsedH4PublicViewV2<'_>,
    answer_coefficients: &[u8],
    squarefree_binding_v1: &[u8],
) -> Result<Vec<u8>, H4ProofPackageV2Error> {
    if answer_coefficients.len() != H4_ANSWER_COEFFICIENT_BYTES
        || squarefree_binding_v1.len() != crate::h4_proof_package_v1::H4_BLSQAB02_BYTES
    {
        return Err(H4ProofPackageV2Error::Length);
    }
    let fake_pcs = vec![0_u8; crate::h4_proof_package_v1::H4_RS_MULTIPROOF_PREFIX_BYTES];
    let public_view_bytes = crate::h4_proof_package_v1::H4_PUBLIC_VIEW_V1_HEADER_BYTES
        .checked_add(public_view.packed_claims.len())
        .and_then(|value| value.checked_add(public_view.relation_terminals.len()))
        .and_then(|value| value.checked_add(fake_pcs.len()))
        .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
    let compact_core_bytes = crate::h4_proof_package_v1::H4_PROOF_PACKAGE_V1_HEADER_BYTES
        .checked_add(public_view_bytes)
        .and_then(|value| value.checked_add(answer_coefficients.len()))
        .and_then(|value| value.checked_add(squarefree_binding_v1.len()))
        .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
    let mut encoded = vec![0_u8; compact_core_bytes];
    encoded[..8].copy_from_slice(crate::h4_proof_package_v1::H4_PROOF_PACKAGE_V1_MAGIC);
    encoded[8..10]
        .copy_from_slice(&crate::h4_proof_package_v1::H4_PROOF_PACKAGE_V1_VERSION.to_be_bytes());
    encoded[10] = header.profile.code();
    encoded[11] = header.shard_index;
    encoded[12] = header.profile.shard_count();
    encoded[16..24].copy_from_slice(&(compact_core_bytes as u64).to_be_bytes());
    encoded[32..40].copy_from_slice(&(public_view_bytes as u64).to_be_bytes());
    encoded[40..48].copy_from_slice(&(answer_coefficients.len() as u64).to_be_bytes());
    encoded[48..52].copy_from_slice(&(squarefree_binding_v1.len() as u32).to_be_bytes());
    encoded[52..54].copy_from_slice(&header.attempt.to_be_bytes());
    encoded[64..128].copy_from_slice(&NULL_PROOF_SUITE_ID);
    encoded[128..192].copy_from_slice(&header.profile_identity);
    encoded[192..256].copy_from_slice(&header.program_commitment);
    encoded[256..320].copy_from_slice(&header.schedule_commitment);
    encoded[320..384].copy_from_slice(&header.session_id);
    encoded[384..448].copy_from_slice(&h4_native_root_statement_id_v2(
        H4_SOURCE_TENSOR_KIND as u16,
        header.source_tensor_root,
    ));
    encoded[448..512].copy_from_slice(&h4_native_root_statement_id_v2(
        GKR_TENSOR_MASK_KIND as u16,
        header.gkr_mask_tensor_root,
    ));
    let mut offset = crate::h4_proof_package_v1::H4_PROOF_PACKAGE_V1_HEADER_BYTES;
    encoded[offset..offset + 8]
        .copy_from_slice(crate::h4_proof_package_v1::H4_PUBLIC_VIEW_V1_MAGIC);
    encoded[offset + 8..offset + 10]
        .copy_from_slice(&crate::h4_proof_package_v1::H4_PUBLIC_VIEW_V1_VERSION.to_be_bytes());
    encoded[offset + 12..offset + 14].copy_from_slice(&(GKR_CLAIM_COUNT as u16).to_be_bytes());
    encoded[offset + 14..offset + 16]
        .copy_from_slice(&(H4_GKR_RELATION_TERMINAL_BYTES as u16 / 64).to_be_bytes());
    encoded[offset + 16..offset + 20]
        .copy_from_slice(&(public_view.packed_claims.len() as u32).to_be_bytes());
    encoded[offset + 20..offset + 24]
        .copy_from_slice(&(public_view.relation_terminals.len() as u32).to_be_bytes());
    encoded[offset + 24..offset + 32].copy_from_slice(&(fake_pcs.len() as u64).to_be_bytes());
    offset += crate::h4_proof_package_v1::H4_PUBLIC_VIEW_V1_HEADER_BYTES;
    encoded[offset..offset + public_view.packed_claims.len()]
        .copy_from_slice(public_view.packed_claims);
    offset += public_view.packed_claims.len();
    encoded[offset..offset + public_view.relation_terminals.len()]
        .copy_from_slice(public_view.relation_terminals);
    offset += public_view.relation_terminals.len();
    encoded[offset..offset + fake_pcs.len()].copy_from_slice(&fake_pcs);
    offset += fake_pcs.len();
    encoded[offset..offset + answer_coefficients.len()].copy_from_slice(answer_coefficients);
    offset += answer_coefficients.len();
    encoded[offset..].copy_from_slice(squarefree_binding_v1);
    Ok(encoded)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct H4RsSegmentDescriptorV2 {
    pub boundary: u64,
    pub kind: u64,
    pub data_bytes: u64,
    pub leaf_count: u64,
    pub leaf_bytes: u64,
}

pub fn h4_rs_segment_leaf_payload_v2(
    descriptor: H4RsSegmentDescriptorV2,
    payload: &[u8],
) -> Result<Vec<u8>, H4ProofPackageV2Error> {
    if u64::try_from(payload.len()).map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?
        != descriptor.leaf_bytes
    {
        return Err(H4ProofPackageV2Error::Geometry);
    }
    let mut framed = Vec::with_capacity(
        H4_RS_SEGMENT_LEAF_FRAME_BYTES
            .checked_add(payload.len())
            .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?,
    );
    framed.extend_from_slice(H4_RS_SEGMENT_LEAF_FRAME_MAGIC);
    framed.extend_from_slice(&H4_PROOF_PACKAGE_V2_VERSION.to_be_bytes());
    framed.extend_from_slice(&0_u16.to_be_bytes());
    framed.extend_from_slice(&descriptor.boundary.to_be_bytes());
    framed.extend_from_slice(&descriptor.kind.to_be_bytes());
    framed.extend_from_slice(&descriptor.data_bytes.to_be_bytes());
    framed.extend_from_slice(&descriptor.leaf_bytes.to_be_bytes());
    framed.extend_from_slice(payload);
    if framed.len() != H4_RS_SEGMENT_LEAF_FRAME_BYTES + payload.len() {
        return Err(H4ProofPackageV2Error::Length);
    }
    Ok(framed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedH4RsSegmentV2<'a> {
    pub descriptor: H4RsSegmentDescriptorV2,
    pub root: BindingRootV2,
    pub opened_payloads: &'a [u8],
    pub frontier_count: usize,
}

pub fn verify_h4_rs_segment_v2<'a>(
    encoded: &'a [u8],
    expected_descriptor: H4RsSegmentDescriptorV2,
    expected_indices: &[u32],
    expected_root: BindingRootV2,
) -> Result<ParsedH4RsSegmentV2<'a>, H4ProofPackageV2Error> {
    if encoded.len() < H4_RS_SEGMENT_V2_HEADER_BYTES {
        return Err(H4ProofPackageV2Error::Length);
    }
    let descriptor = H4RsSegmentDescriptorV2 {
        boundary: u64_at(encoded, 0)?,
        kind: u64_at(encoded, 8)?,
        data_bytes: u64_at(encoded, 16)?,
        leaf_count: u64_at(encoded, 24)?,
        leaf_bytes: u64_at(encoded, 32)?,
    };
    let opening_count = usize::try_from(u32_at(encoded, 40)?)
        .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
    let frontier_count = usize::try_from(u32_at(encoded, 44)?)
        .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
    let root = BindingRootV2::decode(&encoded[48..H4_RS_SEGMENT_V2_HEADER_BYTES])?;
    if descriptor != expected_descriptor {
        return Err(H4ProofPackageV2Error::Geometry);
    }
    if root != expected_root {
        return Err(H4ProofPackageV2Error::RootMismatch);
    }
    if opening_count != expected_indices.len()
        || opening_count == 0
        || opening_count > H4_MAIN_OPENINGS
        || descriptor.leaf_count == 0
        || !descriptor.leaf_count.is_power_of_two()
        || descriptor.leaf_count > u64::from(u32::MAX)
        || descriptor.leaf_bytes == 0
        || !descriptor.leaf_bytes.is_multiple_of(64)
        || descriptor.data_bytes
            != descriptor
                .leaf_count
                .checked_mul(descriptor.leaf_bytes)
                .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?
    {
        return Err(H4ProofPackageV2Error::Geometry);
    }
    let indices_start = H4_RS_SEGMENT_V2_HEADER_BYTES;
    let indices_end = indices_start
        .checked_add(
            opening_count
                .checked_mul(4)
                .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?,
        )
        .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
    let leaf_bytes = usize::try_from(descriptor.leaf_bytes)
        .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
    let payload_end = indices_end
        .checked_add(
            opening_count
                .checked_mul(leaf_bytes)
                .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?,
        )
        .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
    let expected_end = payload_end
        .checked_add(
            frontier_count
                .checked_mul(BINDING_V2_BYTES)
                .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?,
        )
        .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
    if encoded.len() != expected_end {
        return Err(H4ProofPackageV2Error::Length);
    }

    let mut indices = Vec::with_capacity(opening_count);
    for ordinal in 0..opening_count {
        let offset = indices_start + ordinal * 4;
        let index = u32_at(encoded, offset)?;
        if expected_indices.get(ordinal) != Some(&index) {
            return Err(H4ProofPackageV2Error::Multiproof);
        }
        indices.push(u64::from(index));
    }
    if indices.windows(2).any(|pair| pair[0] >= pair[1])
        || indices
            .last()
            .is_none_or(|index| *index >= descriptor.leaf_count)
    {
        return Err(H4ProofPackageV2Error::Multiproof);
    }
    let expected_frontier =
        canonical_binding_frontier_positions_v2(descriptor.leaf_count, &indices)?.len();
    if frontier_count != expected_frontier {
        return Err(H4ProofPackageV2Error::Multiproof);
    }

    let opened_payloads = &encoded[indices_end..payload_end];
    for value in opened_payloads.chunks_exact(64) {
        let encoded: &[u8; 64] = value
            .try_into()
            .map_err(|_| H4ProofPackageV2Error::NonCanonicalField)?;
        Fp16::decode(encoded).map_err(|_| H4ProofPackageV2Error::NonCanonicalField)?;
    }

    let frontier = &encoded[payload_end..expected_end];
    let mut canonical_proof = Vec::with_capacity(
        BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES
            + opening_count * 8
            + frontier_count * BINDING_V2_BYTES,
    );
    canonical_proof.extend_from_slice(BINDING_MERKLE_MULTIPROOF_V2_MAGIC);
    canonical_proof.extend_from_slice(&BINDING_MERKLE_MULTIPROOF_V2_VERSION.to_be_bytes());
    canonical_proof.extend_from_slice(&0_u16.to_be_bytes());
    canonical_proof.extend_from_slice(&descriptor.leaf_count.to_be_bytes());
    canonical_proof.extend_from_slice(
        &u32::try_from(opening_count)
            .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?
            .to_be_bytes(),
    );
    canonical_proof.extend_from_slice(
        &u32::try_from(frontier_count)
            .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?
            .to_be_bytes(),
    );
    for index in &indices {
        canonical_proof.extend_from_slice(&index.to_be_bytes());
    }
    canonical_proof.extend_from_slice(frontier);
    let proof = BindingMerkleMultiProofV2::decode(&canonical_proof)?;

    let mut leaves = Vec::with_capacity(opening_count);
    for (&index, payload) in indices.iter().zip(opened_payloads.chunks_exact(leaf_bytes)) {
        let framed = h4_rs_segment_leaf_payload_v2(descriptor, payload)?;
        leaves.push(BindingMerkleLeafV2::hash(index, &framed)?);
    }
    proof
        .verify_leaf_hashes(&leaves, &root)
        .map_err(|error| match error {
            BindingRootV2Error::RootMismatch => H4ProofPackageV2Error::RootMismatch,
            other => H4ProofPackageV2Error::Binding(other),
        })?;
    Ok(ParsedH4RsSegmentV2 {
        descriptor,
        root,
        opened_payloads,
        frontier_count,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedH4NativeOpeningsV2 {
    pub source_main_openings: Vec<Fp16>,
    pub sumcheck_source_openings: Vec<Fp16>,
    pub ordinary_base_openings: Vec<Fp16>,
    pub main_base_openings: Vec<Fp16>,
    pub squarefree_source_openings: Vec<Fp16>,
    pub base_tensor_openings: Vec<Fp16>,
    pub mask_tensor_openings: Vec<Fp16>,
}

/// Opaque authority for one Construction-owned, masked H4 source functional.
///
/// This is intentionally distinct from the bridge-mask PCS opening.  Only the
/// H4-v2 verifier may construct it after checking the native source/base/answer
/// code relation and the verifier-derived sparse functional.  The bridge may
/// consume the value, point, and bindings, but cannot manufacture a matching
/// scalar from a bridge-mask opening.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedH4BridgeSourceTerminalV2 {
    source_segment_set_binding: BindingDigestV2,
    answer_binding: BindingDigestV2,
    point: Vec<Fp16>,
    masked_value: Fp16,
}

/// Source-derived Construction authority used by the post-z bridge.  The
/// public answer coefficients mask the H4 source.  Checking
/// `combination * masked_terminal == F(answer)` binds the GKR source mask to
/// the already-authenticated Construction base without opening either the raw
/// H4 functional or the base-mask functional.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedH4ConstructionV2 {
    source_segment_set_binding: BindingDigestV2,
    answer_binding: BindingDigestV2,
    combination: Fp16,
    answer_coefficients: Vec<Fp16>,
}

impl VerifiedH4ConstructionV2 {
    pub(crate) const fn source_segment_set_binding(&self) -> BindingDigestV2 {
        self.source_segment_set_binding
    }

    pub(crate) const fn answer_binding(&self) -> BindingDigestV2 {
        self.answer_binding
    }

    pub(crate) const fn combination(&self) -> Fp16 {
        self.combination
    }

    pub(crate) fn answer_coefficients(&self) -> &[Fp16] {
        &self.answer_coefficients
    }
}

#[cfg(feature = "std")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct VerifiedH4PreAlphaShardV2 {
    algebra_binding: BindingDigestV2,
    source_root: BindingRootV2,
    bridge_base_root: BindingRootV2,
    construction: VerifiedH4ConstructionV2,
}

fn h4_answer_binding_v2(
    source_segment_set_binding: BindingDigestV2,
    combination: Fp16,
    coefficients: &[Fp16],
) -> Result<BindingDigestV2, H4ProofPackageV2Error> {
    let mut encoded = b"BL/PQ512/WAVE2/H4/CONSTRUCTION-ANSWER/v2\0".to_vec();
    encoded.extend_from_slice(source_segment_set_binding.as_bytes());
    encoded.extend_from_slice(&combination.encode());
    encoded.extend_from_slice(
        &u32::try_from(coefficients.len())
            .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?
            .to_be_bytes(),
    );
    for coefficient in coefficients {
        encoded.extend_from_slice(&coefficient.encode());
    }
    Ok(BindingDigestV2::hash(BindingRoleV2::Payload, &encoded)?)
}

fn verify_h4_construction_spotchecks_v2(
    answer_coefficients: &[Fp16],
    main_queries: &[usize],
    auxiliary_queries: &[usize],
    openings: &VerifiedH4NativeOpeningsV2,
    combination: Fp16,
) -> Result<(), H4ProofPackageV2Error> {
    let main_values = H4_ANSWER_MAIN_COEFFICIENT_BYTES / 64;
    let ordinary_values = H4_ANSWER_ORDINARY_AUXILIARY_COEFFICIENT_BYTES / 64;
    if combination.is_zero()
        || answer_coefficients.len() < main_values + ordinary_values
        || main_queries.len() != H4_MAIN_OPENINGS
        || auxiliary_queries.len() != H4_AUXILIARY_OPENINGS
    {
        return Err(H4ProofPackageV2Error::Geometry);
    }
    let main_answer = encode_codeword(
        &answer_coefficients[..main_values],
        H4_MAIN_CODE_VALUES.ilog2(),
    )
    .map_err(|_| H4ProofPackageV2Error::Geometry)?;
    for (ordinal, query) in main_queries.iter().copied().enumerate() {
        if main_answer.get(query).is_none_or(|answer| {
            *answer
                != openings.main_base_openings[ordinal]
                    + combination * openings.source_main_openings[ordinal]
        }) {
            return Err(H4ProofPackageV2Error::RootMismatch);
        }
    }
    let ordinary = &answer_coefficients[main_values..main_values + ordinary_values];
    let word_values = ordinary_values / NON_GKR_AUXILIARY_WORDS;
    for (word, coefficients) in ordinary.chunks_exact(word_values).enumerate() {
        let answer = encode_codeword(coefficients, H4_AUXILIARY_CODE_VALUES.ilog2())
            .map_err(|_| H4ProofPackageV2Error::Geometry)?;
        for (ordinal, query) in auxiliary_queries.iter().copied().enumerate() {
            let source = if word < WORD_SUMCHECK_ROUNDS {
                openings.sumcheck_source_openings[ordinal * WORD_SUMCHECK_ROUNDS + word]
            } else if word == NON_GKR_AUXILIARY_WORDS - 1 {
                openings.squarefree_source_openings[ordinal]
            } else {
                return Err(H4ProofPackageV2Error::Geometry);
            };
            let base = openings.ordinary_base_openings[ordinal * NON_GKR_AUXILIARY_WORDS + word];
            if answer
                .get(query)
                .is_none_or(|value| *value != base + combination * source)
            {
                return Err(H4ProofPackageV2Error::RootMismatch);
            }
        }
    }
    Ok(())
}

fn verify_h4_construction_v2(
    source_segment_set_binding: BindingDigestV2,
    answer_coefficients: Vec<Fp16>,
    main_queries: &[usize],
    auxiliary_queries: &[usize],
    openings: &VerifiedH4NativeOpeningsV2,
    combination: Fp16,
) -> Result<VerifiedH4ConstructionV2, H4ProofPackageV2Error> {
    if answer_coefficients.len() != H4_ANSWER_COEFFICIENT_BYTES / 64 || combination.is_zero() {
        return Err(H4ProofPackageV2Error::Geometry);
    }
    verify_h4_construction_spotchecks_v2(
        &answer_coefficients,
        main_queries,
        auxiliary_queries,
        openings,
        combination,
    )?;
    let answer_binding = h4_answer_binding_v2(
        source_segment_set_binding,
        combination,
        &answer_coefficients,
    )?;
    Ok(VerifiedH4ConstructionV2 {
        source_segment_set_binding,
        answer_binding,
        combination,
        answer_coefficients,
    })
}

impl VerifiedH4BridgeSourceTerminalV2 {
    pub(crate) const fn source_segment_set_binding(&self) -> BindingDigestV2 {
        self.source_segment_set_binding
    }

    pub(crate) const fn answer_binding(&self) -> BindingDigestV2 {
        self.answer_binding
    }

    pub(crate) fn point(&self) -> &[Fp16] {
        &self.point
    }

    pub(crate) const fn masked_value(&self) -> Fp16 {
        self.masked_value
    }

    #[cfg(test)]
    pub(crate) fn synthetic_for_test(
        source_segment_set_binding: BindingDigestV2,
        answer_binding: BindingDigestV2,
        point: Vec<Fp16>,
        masked_value: Fp16,
    ) -> Self {
        Self {
            source_segment_set_binding,
            answer_binding,
            point,
            masked_value,
        }
    }
}

/// Mint masked H4 source terminals without opening the raw source or its
/// Construction base mask.  The verifier-derived coefficient functional is
/// evaluated only on the public answer coefficients.
pub(crate) fn verify_h4_bridge_source_terminals_v2(
    construction: &VerifiedH4ConstructionV2,
    points: &[Vec<Fp16>],
    coefficient_weights: &[Vec<Fp16>],
    claimed_masked_values: &[Fp16],
) -> Result<Vec<VerifiedH4BridgeSourceTerminalV2>, H4ProofPackageV2Error> {
    let functional_values =
        H4_ANSWER_MAIN_COEFFICIENT_BYTES / 64 + H4_ANSWER_ORDINARY_AUXILIARY_COEFFICIENT_BYTES / 64;
    if points.is_empty()
        || points.len() != coefficient_weights.len()
        || points.len() != claimed_masked_values.len()
        || points.iter().any(Vec::is_empty)
        || coefficient_weights
            .iter()
            .any(|weights| weights.len() != functional_values)
        || construction.combination().is_zero()
    {
        return Err(H4ProofPackageV2Error::Geometry);
    }
    let answer = &construction.answer_coefficients()[..functional_values];
    let mut terminals = Vec::with_capacity(points.len());
    for ((point, weights), claimed) in points
        .iter()
        .zip(coefficient_weights)
        .zip(claimed_masked_values)
    {
        let answer_opening = inner_product_v2(answer, weights)?;
        if answer_opening != construction.combination() * *claimed {
            return Err(H4ProofPackageV2Error::RootMismatch);
        }
        terminals.push(VerifiedH4BridgeSourceTerminalV2 {
            source_segment_set_binding: construction.source_segment_set_binding(),
            answer_binding: construction.answer_binding(),
            point: point.clone(),
            masked_value: *claimed,
        });
    }
    Ok(terminals)
}

fn decode_opening_values_v2(encoded: &[u8]) -> Result<Vec<Fp16>, H4ProofPackageV2Error> {
    if !encoded.len().is_multiple_of(64) {
        return Err(H4ProofPackageV2Error::NonCanonicalField);
    }
    encoded
        .chunks_exact(64)
        .map(|value| Fp16::decode(value).map_err(|_| H4ProofPackageV2Error::NonCanonicalField))
        .collect()
}

fn inner_product_v2(left: &[Fp16], right: &[Fp16]) -> Result<Fp16, H4ProofPackageV2Error> {
    if left.len() != right.len() {
        return Err(H4ProofPackageV2Error::Geometry);
    }
    Ok(left
        .iter()
        .zip(right)
        .fold(Fp16::ZERO, |sum, (left, right)| sum + *left * *right))
}

/// Recompute the public A-tensor's native BindingRootV2 and the exact query
/// openings used by the hidden B/N relation.  A is public, so this streaming
/// root construction introduces no new proof oracle and never relies on a
/// legacy 64-byte Merkle root.
fn answer_tensor_root_and_openings_v2(
    coefficients: &[Fp16],
    tensor_query_indices: &[usize],
) -> Result<(BindingRootV2, Vec<Fp16>), H4ProofPackageV2Error> {
    const OUTER_MESSAGE_VALUES: usize = 64;
    const INNER_MESSAGE_VALUES: usize = 512;
    const INNER_CODE_VALUES: usize = 1 << 13;
    const OUTER_CODE_VALUES: usize = 1 << 7;
    if coefficients.len() != OUTER_MESSAGE_VALUES * INNER_MESSAGE_VALUES
        || tensor_query_indices.len() != H4_AUXILIARY_OPENINGS
        || tensor_query_indices
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || tensor_query_indices
            .last()
            .is_none_or(|index| *index >= H4_GKR_TENSOR_LEAVES)
    {
        return Err(H4ProofPackageV2Error::Geometry);
    }
    let inner_codewords = coefficients
        .chunks_exact(INNER_MESSAGE_VALUES)
        .map(|word| encode_codeword(word, INNER_CODE_VALUES.ilog2()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| H4ProofPackageV2Error::Geometry)?;
    let descriptor = H4RsSegmentDescriptorV2 {
        boundary: 2,
        kind: GKR_TENSOR_ANSWER_KIND,
        data_bytes: (H4_GKR_TENSOR_LEAVES * 64) as u64,
        leaf_count: H4_GKR_TENSOR_LEAVES as u64,
        leaf_bytes: 64,
    };
    let mut frontier: Vec<Option<BindingDigestV2>> =
        vec![None; H4_GKR_TENSOR_LEAVES.ilog2() as usize + 1];
    let mut openings = Vec::with_capacity(tensor_query_indices.len());
    let mut query_ordinal = 0usize;
    let mut outer_coefficients = vec![Fp16::ZERO; OUTER_MESSAGE_VALUES];
    for inner in 0..INNER_CODE_VALUES {
        for (coefficient, codeword) in outer_coefficients.iter_mut().zip(&inner_codewords) {
            *coefficient = codeword[inner];
        }
        let outer_codeword = encode_codeword(&outer_coefficients, OUTER_CODE_VALUES.ilog2())
            .map_err(|_| H4ProofPackageV2Error::Geometry)?;
        for (outer, value) in outer_codeword.into_iter().enumerate() {
            let leaf = inner * OUTER_CODE_VALUES + outer;
            if tensor_query_indices.get(query_ordinal) == Some(&leaf) {
                openings.push(value);
                query_ordinal += 1;
            }
            let payload = h4_rs_segment_leaf_payload_v2(descriptor, &value.encode())?;
            let mut node = BindingMerkleLeafV2::hash(leaf as u64, &payload)?.digest();
            let mut level = 0usize;
            loop {
                if let Some(left) = frontier[level].take() {
                    node = BindingMerkleNodeV2::hash(
                        (level + 1) as u32,
                        (leaf >> (level + 1)) as u64,
                        left,
                        node,
                    )?
                    .digest();
                    level += 1;
                } else {
                    frontier[level] = Some(node);
                    break;
                }
            }
        }
    }
    let root_level = H4_GKR_TENSOR_LEAVES.ilog2() as usize;
    if query_ordinal != tensor_query_indices.len()
        || openings.len() != tensor_query_indices.len()
        || frontier[..root_level].iter().any(Option::is_some)
    {
        return Err(H4ProofPackageV2Error::Geometry);
    }
    let top = frontier[root_level]
        .take()
        .ok_or(H4ProofPackageV2Error::Geometry)?;
    Ok((
        BindingRootV2::from_top(H4_GKR_TENSOR_LEAVES as u64, top)?,
        openings,
    ))
}

/// Recompute the native answer-tensor root from the exact serialized answer
/// coefficients retained by the H4 producer. The answer tensor is public
/// proof material, but its root is still a v2 Merkle root and cannot be
/// imported from the legacy 64-byte commitment.
pub fn answer_tensor_root_v2(
    encoded_answer_coefficients: &[u8],
) -> Result<BindingRootV2, H4ProofPackageV2Error> {
    if encoded_answer_coefficients.len() != H4_ANSWER_COEFFICIENT_BYTES {
        return Err(H4ProofPackageV2Error::Geometry);
    }
    let coefficients = decode_opening_values_v2(encoded_answer_coefficients)?;
    let query_indices = (0..H4_AUXILIARY_OPENINGS).collect::<Vec<_>>();
    answer_tensor_root_and_openings_v2(
        &coefficients[coefficients
            .len()
            .checked_sub(H4_ANSWER_GKR_TENSOR_COEFFICIENT_BYTES / 64)
            .ok_or(H4ProofPackageV2Error::Geometry)?..],
        &query_indices,
    )
    .map(|(root, _)| root)
}

fn native_algebra_backend_v2(
    openings: VerifiedH4NativeOpeningsV2,
    answer_tensor_statement_id: [u8; 64],
    answer_tensor_openings: Vec<Fp16>,
) -> crate::h4_proof_package_v1::NativeH4AlgebraBackend {
    crate::h4_proof_package_v1::NativeH4AlgebraBackend {
        openings: crate::h4_proof_package_v1::VerifiedH4TensorMultiproofs {
            source_main_openings: openings.source_main_openings,
            sumcheck_source_openings: openings.sumcheck_source_openings,
            ordinary_base_openings: openings.ordinary_base_openings,
            main_base_openings: openings.main_base_openings,
            squarefree_source_openings: openings.squarefree_source_openings,
            base_openings: openings.base_tensor_openings,
            mask_openings: openings.mask_tensor_openings,
        },
        answer_tensor_statement_id,
        answer_tensor_openings,
    }
}

fn boolean_equality_weight_v2(index: usize, point: &[Fp16]) -> Fp16 {
    point
        .iter()
        .copied()
        .enumerate()
        .fold(Fp16::ONE, |weight, (variable, challenge)| {
            if (index >> variable) & 1 == 1 {
                weight * challenge
            } else {
                weight * (Fp16::ONE - challenge)
            }
        })
}

#[cfg(test)]
mod post_z_word_fold_tests {
    use alloc::{vec, vec::Vec};

    use super::{H4_SOURCE_WORDS, boolean_equality_weight_v2};
    use crate::field::Fp16;

    fn fp(value: u32) -> Fp16 {
        Fp16::from_coefficients([value, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap()
    }

    #[test]
    fn bridge_leaf_fold_uses_only_the_nine_word_coordinates() {
        let mut point = vec![Fp16::ZERO; H4_SOURCE_WORDS.ilog2() as usize];
        point[0] = Fp16::ONE;
        point[2] = Fp16::ONE;
        let selected = 0b101;
        let values = (0..H4_SOURCE_WORDS)
            .map(|index| fp(index as u32 + 3))
            .collect::<Vec<_>>();
        let folded = values
            .iter()
            .enumerate()
            .fold(Fp16::ZERO, |sum, (index, value)| {
                sum + *value * boolean_equality_weight_v2(index, &point)
            });
        assert_eq!(folded, values[selected]);
    }
}

/// Authenticate completion-selected openings of the same v2 source tensor
/// and its independent bridge base tensor. Both trees use one 512-word leaf
/// per RS position, so the verifier folds exactly the same row functional in
/// each tree without duplicating 16/32 independently rooted source slices.
pub(crate) fn verify_h4_bridge_response_openings_v2(
    source_segment: &[u8],
    base_segment: &[u8],
    expected_source_root: BindingRootV2,
    expected_base_root: BindingRootV2,
    positions: &[usize],
    projection_challenges: &[Fp16],
    answer_binding: BindingDigestV2,
) -> Result<
    crate::h4_bridge_source_response_v2::VerifiedH4BridgeResponseCodeOpeningsV2,
    H4ProofPackageV2Error,
> {
    if positions.len() != H4_MAIN_OPENINGS
        || projection_challenges.len() != 9
        || projection_challenges
            .iter()
            .any(|challenge| challenge.is_zero() || *challenge == Fp16::ONE)
    {
        return Err(H4ProofPackageV2Error::Geometry);
    }
    let indices = positions
        .iter()
        .copied()
        .map(|position| {
            u32::try_from(position).map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let source_descriptor = H4RsSegmentDescriptorV2 {
        boundary: 3,
        kind: H4_SOURCE_TENSOR_KIND,
        data_bytes: (H4_MAIN_CODE_VALUES * H4_SOURCE_LEAF_BYTES) as u64,
        leaf_count: H4_MAIN_CODE_VALUES as u64,
        leaf_bytes: H4_SOURCE_LEAF_BYTES as u64,
    };
    let base_descriptor = H4RsSegmentDescriptorV2 {
        boundary: 2,
        kind: H4_BRIDGE_BASE_KIND,
        data_bytes: (H4_MAIN_CODE_VALUES * H4_BRIDGE_BASE_LEAF_BYTES) as u64,
        leaf_count: H4_MAIN_CODE_VALUES as u64,
        leaf_bytes: H4_BRIDGE_BASE_LEAF_BYTES as u64,
    };
    let source = verify_h4_rs_segment_v2(
        source_segment,
        source_descriptor,
        &indices,
        expected_source_root,
    )?;
    let base =
        verify_h4_rs_segment_v2(base_segment, base_descriptor, &indices, expected_base_root)?;
    // The response table has nine word coordinates plus one boundary
    // selector.  Each committed leaf contains only the 512 word axis; the
    // boundary challenge is applied by the response functional, not folded
    // into a non-existent tenth leaf coordinate.
    let weights = (0..H4_SOURCE_WORDS)
        .map(|word| boolean_equality_weight_v2(word, projection_challenges))
        .collect::<Vec<_>>();
    let folded_source = source
        .opened_payloads
        .chunks_exact(H4_SOURCE_LEAF_BYTES)
        .map(|payload| inner_product_v2(&decode_opening_values_v2(payload)?, &weights))
        .collect::<Result<Vec<_>, _>>()?;
    let folded_base = base
        .opened_payloads
        .chunks_exact(H4_BRIDGE_BASE_LEAF_BYTES)
        .map(|payload| {
            decode_opening_values_v2(payload)?
                .into_iter()
                .next()
                .ok_or(H4ProofPackageV2Error::Geometry)
        })
        .collect::<Result<Vec<_>, _>>()?;
    crate::h4_bridge_source_response_v2::VerifiedH4BridgeResponseCodeOpeningsV2::from_native_multiproofs(
        expected_source_root,
        expected_base_root,
        answer_binding,
        positions.to_vec(),
        folded_source,
        folded_base,
    )
    .map_err(|_| H4ProofPackageV2Error::RootMismatch)
}

/// Complete the source-root side of the post-z bridge without accepting any
/// caller-supplied sparse coefficient vector. The claim vector/circuit tags
/// come from the verified bridge GKR, and both Construction code openings are
/// authenticated against roots pinned in the H4 shard header.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_h4_bridge_source_response_against_native_roots_v2(
    profile: H4ProofProfileV2,
    shard_index: u8,
    verified_gkr: &crate::semantic_h4_bridge_gkr::VerifiedMaskedSemanticH4BridgeGkr,
    semantic_batch: &crate::semantic_h4_bridge_gkr::VerifiedSemanticBridgeSourceBatchV3,
    response: &crate::h4_bridge_source_response_v2::H4BridgeSourceResponseV2,
    claim_challenge: Fp16,
    row_challenges: &[Fp16],
    projection_challenges: &[Fp16],
    construction_mix: Fp16,
    authenticated_shard_target: Fp16,
    source_segment: &[u8],
    base_segment: &[u8],
    expected_source_root: BindingRootV2,
    expected_base_root: BindingRootV2,
    positions: &[usize],
) -> Result<
    crate::h4_bridge_source_response_v2::VerifiedH4BridgeSourceResponseV2,
    H4ProofPackageV2Error,
> {
    if semantic_batch.claim_vector_binding()
        != crate::semantic_h4_bridge_gkr::semantic_h4_bridge_claim_vector_commitment(verified_gkr)
            .map_err(|_| H4ProofPackageV2Error::Geometry)?
        || semantic_batch.claim_challenge() != claim_challenge
    {
        return Err(H4ProofPackageV2Error::RootMismatch);
    }
    let relation = crate::h4_bridge_source_response_v2::VerifiedH4BridgeRelationV2::from_verified_gkr_shard_target(
            profile,
            shard_index,
            verified_gkr,
            claim_challenge,
            authenticated_shard_target,
        )
        .map_err(|_| H4ProofPackageV2Error::Geometry)?;
    let openings = verify_h4_bridge_response_openings_v2(
        source_segment,
        base_segment,
        expected_source_root,
        expected_base_root,
        positions,
        projection_challenges,
        response.answer_binding,
    )?;
    crate::h4_bridge_source_response_v2::verify_h4_bridge_source_response_v2(
        response,
        &relation,
        row_challenges,
        construction_mix,
        &openings,
    )
    .map_err(|error| match error {
        crate::h4_bridge_source_response_v2::H4BridgeSourceResponseV2Error::Code
        | crate::h4_bridge_source_response_v2::H4BridgeSourceResponseV2Error::Binding => {
            H4ProofPackageV2Error::RootMismatch
        }
        _ => H4ProofPackageV2Error::Geometry,
    })
}

/// Produce one post-Z response from the same opaque semantic/H4 inputs that
/// the accepting path later verifies.  The source and base coefficient arrays
/// are producer inputs only; their roots and completion-selected openings must
/// still be authenticated by [`verify_h4_bridge_source_response_against_native_roots_v2`].
/// The challenge callback is called after each polynomial is complete, which
/// lets a strict public-coin coordinator absorb the exact round message before
/// releasing its challenge.
#[allow(clippy::too_many_arguments)]
pub(crate) fn produce_h4_bridge_source_response_from_verified_inputs(
    profile: H4ProofProfileV2,
    shard_index: u8,
    verified_gkr: &crate::semantic_h4_bridge_gkr::VerifiedMaskedSemanticH4BridgeGkr,
    semantic_batch: &crate::semantic_h4_bridge_gkr::VerifiedSemanticBridgeSourceBatchV3,
    source_coefficients: &[crate::field::Fp16],
    base_coefficients: &[crate::field::Fp16],
    construction_mix: crate::field::Fp16,
    row_challenge_provider: impl FnMut(
        usize,
        &[crate::field::Fp16;
             crate::h4_bridge_source_response_v2::H4_BRIDGE_SOURCE_RESPONSE_MESSAGE_VALUES],
    ) -> Result<
        crate::field::Fp16,
        crate::h4_bridge_source_response_v2::H4BridgeSourceResponseV2Error,
    >,
) -> Result<
    crate::h4_bridge_source_response_v2::H4BridgeSourceResponseV2,
    crate::h4_bridge_source_response_v2::H4BridgeSourceResponseV2Error,
> {
    crate::h4_bridge_source_response_v2::produce_h4_bridge_source_response_from_verified_gkr(
        profile,
        shard_index,
        verified_gkr,
        semantic_batch,
        source_coefficients,
        base_coefficients,
        construction_mix,
        row_challenge_provider,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_h4_native_multiproof_stream_v2(
    encoded: &[u8],
    _profile: H4ProofProfileV2,
    query_seed: [u8; 64],
    fold_weights: &[Fp16],
    expected_source_tensor_root: BindingRootV2,
    expected_sumcheck_root: BindingRootV2,
    expected_mask_tensor_root: BindingRootV2,
    expected_main_base_root: BindingRootV2,
    expected_base_tensor_root: BindingRootV2,
    expected_squarefree_root: BindingRootV2,
) -> Result<VerifiedH4NativeOpeningsV2, H4ProofPackageV2Error> {
    if fold_weights.len() != 512
        || encoded.len() < H4_RS_MULTIPROOF_V2_PREFIX_BYTES
        || encoded.get(..8) != Some(H4_RS_MULTIPROOF_V2_MAGIC)
        || encoded.get(12..76) != Some(query_seed.as_slice())
    {
        return Err(H4ProofPackageV2Error::Multiproof);
    }
    let segment_count = usize::try_from(u32_at(encoded, 8)?)
        .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
    const SOURCE_SEGMENTS: usize = 1;
    if segment_count != SOURCE_SEGMENTS + 5 {
        return Err(H4ProofPackageV2Error::Geometry);
    }

    let main_queries = exact_queries(
        &query_seed,
        b"main_queries",
        H4_MAIN_CODE_VALUES,
        H4_MAIN_OPENINGS,
    )
    .map_err(|_| H4ProofPackageV2Error::Multiproof)?;
    let auxiliary_queries = exact_queries(
        &query_seed,
        b"aux_queries",
        H4_AUXILIARY_CODE_VALUES,
        H4_AUXILIARY_OPENINGS,
    )
    .map_err(|_| H4ProofPackageV2Error::Multiproof)?;
    let tensor_queries = tensor_queries(&query_seed, &auxiliary_queries)
        .map_err(|_| H4ProofPackageV2Error::Multiproof)?;

    let mut offset = H4_RS_MULTIPROOF_V2_PREFIX_BYTES;
    let mut source_main_openings = vec![Fp16::ZERO; H4_MAIN_OPENINGS];
    let mut sumcheck_source_openings = None;
    let mut ordinary_base_openings = None;
    let mut main_base_openings = None;
    let mut squarefree_source_openings = None;
    let mut base_tensor_openings = None;
    let mut mask_tensor_openings = None;

    for ordinal in 0..segment_count {
        let header_end = offset
            .checked_add(H4_RS_SEGMENT_V2_HEADER_BYTES)
            .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
        let header = encoded
            .get(offset..header_end)
            .ok_or(H4ProofPackageV2Error::Length)?;
        let descriptor = H4RsSegmentDescriptorV2 {
            boundary: u64_at(header, 0)?,
            kind: u64_at(header, 8)?,
            data_bytes: u64_at(header, 16)?,
            leaf_count: u64_at(header, 24)?,
            leaf_bytes: u64_at(header, 32)?,
        };
        let opening_count = usize::try_from(u32_at(header, 40)?)
            .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
        let frontier_count = usize::try_from(u32_at(header, 44)?)
            .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
        let segment_bytes = H4_RS_SEGMENT_V2_HEADER_BYTES
            .checked_add(
                opening_count
                    .checked_mul(4)
                    .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?,
            )
            .and_then(|value| {
                usize::try_from(descriptor.leaf_bytes)
                    .ok()
                    .and_then(|leaf_bytes| opening_count.checked_mul(leaf_bytes))
                    .and_then(|payload| value.checked_add(payload))
            })
            .and_then(|value| {
                frontier_count
                    .checked_mul(BINDING_V2_BYTES)
                    .and_then(|frontier| value.checked_add(frontier))
            })
            .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
        let end = offset
            .checked_add(segment_bytes)
            .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
        let segment = encoded
            .get(offset..end)
            .ok_or(H4ProofPackageV2Error::Length)?;

        let (expected_descriptor, expected_indices, expected_root) = if ordinal < SOURCE_SEGMENTS {
            (
                H4RsSegmentDescriptorV2 {
                    boundary: 3,
                    kind: H4_SOURCE_TENSOR_KIND,
                    data_bytes: u64::try_from(H4_MAIN_CODE_VALUES * H4_SOURCE_LEAF_BYTES)
                        .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?,
                    leaf_count: H4_MAIN_CODE_VALUES as u64,
                    leaf_bytes: H4_SOURCE_LEAF_BYTES as u64,
                },
                &main_queries,
                expected_source_tensor_root,
            )
        } else {
            match ordinal - SOURCE_SEGMENTS {
                0 => (
                    H4RsSegmentDescriptorV2 {
                        boundary: 2,
                        kind: PCS_SUMCHECK_BASE_KIND,
                        data_bytes: (H4_AUXILIARY_CODE_VALUES * 19 * 64) as u64,
                        leaf_count: H4_AUXILIARY_CODE_VALUES as u64,
                        leaf_bytes: (19 * 64) as u64,
                    },
                    &auxiliary_queries,
                    expected_sumcheck_root,
                ),
                1 => (
                    H4RsSegmentDescriptorV2 {
                        boundary: 2,
                        kind: GKR_TENSOR_MASK_KIND,
                        data_bytes: (H4_GKR_TENSOR_LEAVES * 64) as u64,
                        leaf_count: H4_GKR_TENSOR_LEAVES as u64,
                        leaf_bytes: 64,
                    },
                    &tensor_queries,
                    expected_mask_tensor_root,
                ),
                2 => (
                    H4RsSegmentDescriptorV2 {
                        boundary: 2,
                        kind: PCS_MAIN_BASE_KIND,
                        data_bytes: (H4_MAIN_CODE_VALUES * 64) as u64,
                        leaf_count: H4_MAIN_CODE_VALUES as u64,
                        leaf_bytes: 64,
                    },
                    &main_queries,
                    expected_main_base_root,
                ),
                3 => (
                    H4RsSegmentDescriptorV2 {
                        boundary: 2,
                        kind: GKR_TENSOR_BASE_KIND,
                        data_bytes: (H4_GKR_TENSOR_LEAVES * 64) as u64,
                        leaf_count: H4_GKR_TENSOR_LEAVES as u64,
                        leaf_bytes: 64,
                    },
                    &tensor_queries,
                    expected_base_tensor_root,
                ),
                4 => (
                    H4RsSegmentDescriptorV2 {
                        boundary: 2,
                        kind: PCS_SQUAREFREE_KIND,
                        data_bytes: (H4_AUXILIARY_CODE_VALUES * 64) as u64,
                        leaf_count: H4_AUXILIARY_CODE_VALUES as u64,
                        leaf_bytes: 64,
                    },
                    &auxiliary_queries,
                    expected_squarefree_root,
                ),
                _ => return Err(H4ProofPackageV2Error::Geometry),
            }
        };
        let expected_indices_u32 = expected_indices
            .iter()
            .copied()
            .map(|index| {
                u32::try_from(index).map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let parsed = verify_h4_rs_segment_v2(
            segment,
            expected_descriptor,
            &expected_indices_u32,
            expected_root,
        )?;
        if ordinal < SOURCE_SEGMENTS {
            for (target, payload) in source_main_openings
                .iter_mut()
                .zip(parsed.opened_payloads.chunks_exact(H4_SOURCE_LEAF_BYTES))
            {
                *target = inner_product_v2(&decode_opening_values_v2(payload)?, fold_weights)?;
            }
        } else {
            let values = decode_opening_values_v2(parsed.opened_payloads)?;
            match expected_descriptor.kind {
                PCS_SUMCHECK_BASE_KIND => {
                    let mut source =
                        Vec::with_capacity(H4_AUXILIARY_OPENINGS * WORD_SUMCHECK_ROUNDS);
                    let mut base =
                        Vec::with_capacity(H4_AUXILIARY_OPENINGS * NON_GKR_AUXILIARY_WORDS);
                    for row in values.chunks_exact(WORD_SUMCHECK_ROUNDS + NON_GKR_AUXILIARY_WORDS) {
                        source.extend_from_slice(&row[..WORD_SUMCHECK_ROUNDS]);
                        base.extend_from_slice(&row[WORD_SUMCHECK_ROUNDS..]);
                    }
                    sumcheck_source_openings = Some(source);
                    ordinary_base_openings = Some(base);
                }
                GKR_TENSOR_MASK_KIND => mask_tensor_openings = Some(values),
                PCS_MAIN_BASE_KIND => main_base_openings = Some(values),
                GKR_TENSOR_BASE_KIND => base_tensor_openings = Some(values),
                PCS_SQUAREFREE_KIND => squarefree_source_openings = Some(values),
                _ => return Err(H4ProofPackageV2Error::Geometry),
            }
        }
        offset = end;
    }
    if offset != encoded.len() {
        return Err(H4ProofPackageV2Error::RootMismatch);
    }
    let verified = VerifiedH4NativeOpeningsV2 {
        source_main_openings,
        sumcheck_source_openings: sumcheck_source_openings
            .ok_or(H4ProofPackageV2Error::Multiproof)?,
        ordinary_base_openings: ordinary_base_openings.ok_or(H4ProofPackageV2Error::Multiproof)?,
        main_base_openings: main_base_openings.ok_or(H4ProofPackageV2Error::Multiproof)?,
        squarefree_source_openings: squarefree_source_openings
            .ok_or(H4ProofPackageV2Error::Multiproof)?,
        base_tensor_openings: base_tensor_openings.ok_or(H4ProofPackageV2Error::Multiproof)?,
        mask_tensor_openings: mask_tensor_openings.ok_or(H4ProofPackageV2Error::Multiproof)?,
    };
    if verified.source_main_openings.len() != H4_MAIN_OPENINGS
        || verified.sumcheck_source_openings.len() != H4_AUXILIARY_OPENINGS * WORD_SUMCHECK_ROUNDS
        || verified.ordinary_base_openings.len() != H4_AUXILIARY_OPENINGS * NON_GKR_AUXILIARY_WORDS
        || verified.main_base_openings.len() != H4_MAIN_OPENINGS
        || verified.squarefree_source_openings.len() != H4_AUXILIARY_OPENINGS
        || verified.base_tensor_openings.len() != H4_AUXILIARY_OPENINGS
        || verified.mask_tensor_openings.len() != H4_AUXILIARY_OPENINGS
    {
        return Err(H4ProofPackageV2Error::Geometry);
    }
    Ok(verified)
}

fn h4_primary_multiproof_length_v2(encoded: &[u8]) -> Result<usize, H4ProofPackageV2Error> {
    if encoded.len() < H4_RS_MULTIPROOF_V2_PREFIX_BYTES
        || encoded.get(..8) != Some(H4_RS_MULTIPROOF_V2_MAGIC)
    {
        return Err(H4ProofPackageV2Error::Multiproof);
    }
    let segment_count = usize::try_from(u32_at(encoded, 8)?)
        .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
    if segment_count != 6 {
        return Err(H4ProofPackageV2Error::Geometry);
    }
    let mut offset = H4_RS_MULTIPROOF_V2_PREFIX_BYTES;
    for _ in 0..segment_count {
        let header_end = offset
            .checked_add(H4_RS_SEGMENT_V2_HEADER_BYTES)
            .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
        let header = encoded
            .get(offset..header_end)
            .ok_or(H4ProofPackageV2Error::Length)?;
        let opening_count = usize::try_from(u32_at(header, 40)?)
            .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
        let frontier_count = usize::try_from(u32_at(header, 44)?)
            .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
        let leaf_bytes = usize::try_from(u64_at(header, 32)?)
            .map_err(|_| H4ProofPackageV2Error::ArithmeticOverflow)?;
        offset = header_end
            .checked_add(
                opening_count
                    .checked_mul(4 + leaf_bytes)
                    .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?,
            )
            .and_then(|value| {
                frontier_count
                    .checked_mul(BINDING_V2_BYTES)
                    .and_then(|frontier| value.checked_add(frontier))
            })
            .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
        if offset > encoded.len() {
            return Err(H4ProofPackageV2Error::Length);
        }
    }
    Ok(offset)
}

/// Opaque pre-alpha receipt. It is not H4 acceptance by itself; acceptance is
/// reached only through `complete_h4_v2` after strict post-z bridge replay,
/// shard-summed source equality, and source-augmented mask PCS verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedH4PreAlphaV2 {
    profile: H4ProofProfileV2,
    aggregate_binding: BindingDigestV2,
    final_transcript_root: [u8; BINDING_V2_BYTES],
    shard_algebra_bindings: Vec<BindingDigestV2>,
    source_roots: Vec<BindingRootV2>,
    bridge_base_roots: Vec<BindingRootV2>,
    constructions: Vec<VerifiedH4ConstructionV2>,
}

impl VerifiedH4PreAlphaV2 {
    pub const fn profile(&self) -> H4ProofProfileV2 {
        self.profile
    }

    pub const fn aggregate_binding(&self) -> BindingDigestV2 {
        self.aggregate_binding
    }

    pub const fn final_transcript_root(&self) -> &[u8; BINDING_V2_BYTES] {
        &self.final_transcript_root
    }

    pub fn shard_algebra_bindings(&self) -> &[BindingDigestV2] {
        &self.shard_algebra_bindings
    }

    pub fn source_roots(&self) -> &[BindingRootV2] {
        &self.source_roots
    }

    pub fn bridge_base_roots(&self) -> &[BindingRootV2] {
        &self.bridge_base_roots
    }

    pub fn construction_count(&self) -> usize {
        self.constructions.len()
    }
}

#[cfg(feature = "std")]
fn read_h4_shard_rounds_v2<R: Read + Seek>(
    reader: &mut R,
    boundary: &VerifiedH4AggregateEnvelopeV2Boundary,
    shard_index: u8,
) -> Result<Vec<H4AuthenticatedRound>, H4AggregateStreamV2Error> {
    let mut result = Vec::with_capacity(boundary.frame_locations().len());
    for (location, authenticated) in boundary
        .frame_locations()
        .iter()
        .zip(boundary.transcript().rounds())
    {
        if location.descriptor() != authenticated.descriptor() {
            return Err(H4ProofPackageV2Error::Schedule.into());
        }
        let (offset, bytes) = location.shard_message(shard_index)?;
        let mut message = vec![0_u8; bytes as usize];
        reader.seek(SeekFrom::Start(offset))?;
        reader.read_exact(&mut message)?;
        result.push(H4AuthenticatedRound {
            descriptor: ChainedRoundDescriptor {
                kind: authenticated.descriptor().kind(),
                ordinal: authenticated.descriptor().ordinal(),
                output_count: authenticated.descriptor().output_count(),
            },
            message,
            outputs: authenticated.outputs().to_vec(),
        });
    }
    Ok(result)
}

fn unique_round_kind_v2(
    rounds: &[H4AuthenticatedRound],
    kind: u16,
) -> Result<usize, H4ProofPackageV2Error> {
    let matches = rounds
        .iter()
        .enumerate()
        .filter(|(_, round)| round.descriptor.kind == kind)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(H4ProofPackageV2Error::Schedule);
    }
    Ok(matches[0])
}

#[cfg(feature = "std")]
fn verify_h4_shard_pre_alpha_v2<R: Read + Seek>(
    reader: &mut R,
    boundary: &VerifiedH4AggregateEnvelopeV2Boundary,
    key: &H4AggregatePackageV2VerificationKey,
    shard: VerifiedH4ShardEnvelopeV2Boundary,
) -> Result<VerifiedH4PreAlphaShardV2, H4AggregateStreamV2Error> {
    let header = shard.header();
    reader.seek(SeekFrom::Start(
        shard
            .body_offset()
            .checked_add(H4_PROOF_PACKAGE_V2_HEADER_BYTES as u64)
            .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?,
    ))?;
    let mut public_view_bytes = vec![0_u8; header.public_view_bytes];
    reader.read_exact(&mut public_view_bytes)?;
    let public_view = parse_h4_public_view_v2(&public_view_bytes)?;
    let primary_length = h4_primary_multiproof_length_v2(public_view.pcs_multiproofs)?;

    let rounds = read_h4_shard_rounds_v2(reader, boundary, header.shard_index)?;
    let claim_index = unique_round_kind_v2(&rounds, H4_PCS_CLAIM_BATCH_KIND)?;
    let initial_index = unique_round_kind_v2(&rounds, H4_PCS_INITIAL_KIND)?;
    let base_index = unique_round_kind_v2(&rounds, H4_PCS_BASE_KIND)?;
    let answer_index = unique_round_kind_v2(&rounds, H4_PCS_ANSWER_KIND)?;
    let row_indices = rounds
        .iter()
        .enumerate()
        .filter(|(_, round)| round.descriptor.kind == H4_PCS_ROW_KIND)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if row_indices.len() != WORD_SUMCHECK_ROUNDS
        || rounds[claim_index].outputs.len() != 6
        || rounds[initial_index].outputs.len() != 1
        || rounds[base_index].outputs.len() != 1
        || rounds[answer_index].outputs.len() != 1
        || row_indices
            .iter()
            .any(|index| rounds[*index].outputs.len() != 1)
    {
        return Err(H4ProofPackageV2Error::Schedule.into());
    }
    let claim_challenge = rounds[claim_index].outputs[0];
    let coordinate_challenge = rounds[claim_index].outputs[1];
    let mixing = [
        rounds[claim_index].outputs[2],
        rounds[claim_index].outputs[3],
    ];
    let epsilon = rounds[initial_index].outputs[0];
    let row_challenges = row_indices
        .iter()
        .map(|index| rounds[*index].outputs[0])
        .collect::<Vec<_>>();
    let combination = rounds[base_index].outputs[0];
    let query_seed = rounds[answer_index].outputs[0];
    let query_seed_bytes = query_seed.encode();
    let main_queries = exact_queries(
        &query_seed_bytes,
        b"main_queries",
        H4_MAIN_CODE_VALUES,
        H4_MAIN_OPENINGS,
    )
    .map_err(|_| H4ProofPackageV2Error::Multiproof)?;
    let auxiliary_queries = exact_queries(
        &query_seed_bytes,
        b"aux_queries",
        H4_AUXILIARY_CODE_VALUES,
        H4_AUXILIARY_OPENINGS,
    )
    .map_err(|_| H4ProofPackageV2Error::Multiproof)?;
    let tensor_query_indices = tensor_queries(&query_seed_bytes, &auxiliary_queries)
        .map_err(|_| H4ProofPackageV2Error::Multiproof)?;
    let fold_weights = crate::h4_proof_package_v1::multilinear_weights(&row_challenges)
        .map_err(|_| H4ProofPackageV2Error::Algebra)?;
    let openings = verify_h4_native_multiproof_stream_v2(
        &public_view.pcs_multiproofs[..primary_length],
        header.profile,
        query_seed_bytes,
        &fold_weights,
        header.source_tensor_root,
        public_view.roots.sumcheck_base_root,
        header.gkr_mask_tensor_root,
        public_view.roots.main_base_root,
        public_view.roots.gkr_base_tensor_root,
        public_view.roots.squarefree_root,
    )?;

    let answer_offset = shard
        .body_offset()
        .checked_add(H4_PROOF_PACKAGE_V2_HEADER_BYTES as u64)
        .and_then(|value| value.checked_add(header.public_view_bytes as u64))
        .ok_or(H4ProofPackageV2Error::ArithmeticOverflow)?;
    reader.seek(SeekFrom::Start(answer_offset))?;
    let mut answer_coefficients = vec![0_u8; H4_ANSWER_COEFFICIENT_BYTES];
    reader.read_exact(&mut answer_coefficients)?;
    let mut squarefree_binding_v2 = vec![0_u8; H4_BLSQAB03_BYTES];
    reader.read_exact(&mut squarefree_binding_v2)?;
    let squarefree_binding_v1 = squarefree_binding_v1_compatibility_v2(
        &squarefree_binding_v2,
        public_view.roots.squarefree_root,
        u16::try_from(header.profile.state_capacity())
            .map_err(|_| H4ProofPackageV2Error::Geometry)?,
    )?;
    let claim_v1 = &squarefree_binding_v1[8..8 + crate::h4_proof_package_v1::H4_BLSQCL02_BYTES];
    if rounds[claim_index].message.len() != 392 + claim_v1.len()
        || rounds[claim_index].message.get(392..) != Some(claim_v1)
    {
        return Err(H4ProofPackageV2Error::Algebra.into());
    }
    let decoded_answer = decode_opening_values_v2(&answer_coefficients)?;
    let tensor_start = decoded_answer
        .len()
        .checked_sub(H4_ANSWER_GKR_TENSOR_COEFFICIENT_BYTES / 64)
        .ok_or(H4ProofPackageV2Error::Geometry)?;
    let (answer_tensor_root, answer_tensor_openings) =
        answer_tensor_root_and_openings_v2(&decoded_answer[tensor_start..], &tensor_query_indices)?;
    if answer_tensor_root != public_view.roots.answer_tensor_root {
        return Err(H4ProofPackageV2Error::RootMismatch.into());
    }
    let answer_tensor_statement_id =
        h4_native_root_statement_id_v2(GKR_TENSOR_ANSWER_KIND as u16, answer_tensor_root);
    let native_backend = native_algebra_backend_v2(
        openings.clone(),
        answer_tensor_statement_id,
        answer_tensor_openings,
    );
    let compatibility = h4_v1_compatibility_body_v2(
        header,
        public_view,
        &answer_coefficients,
        &squarefree_binding_v1,
    )?;

    let gkr_rounds = rounds[..GKR_ROUNDS as usize]
        .iter()
        .enumerate()
        .map(|(ordinal, round)| {
            let kind =
                selected_gkr_round_kind(ordinal as u32).ok_or(H4ProofPackageV2Error::Schedule)?;
            if h4_gkr_descriptor_kind(kind) != round.descriptor.kind {
                return Err(H4ProofPackageV2Error::Schedule);
            }
            Ok(UniformRelayFreeGkrRound {
                kind,
                message: round.message.clone(),
                outputs: round.outputs.clone(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let state_start = GKR_ROUNDS as usize;
    let state_end = state_start + STATE_RELATION_ROUNDS as usize;
    let squarefree_end = state_end
        + state_squarefree_authenticated_rounds(header.profile.state_capacity() as usize)
            .ok_or(H4ProofPackageV2Error::Algebra)? as usize;
    let booleanity_end = squarefree_end + 4 + H4_BOOLEANITY_VARIABLES as usize;
    let padding_end = booleanity_end + 2 + H4_PADDING_VARIABLES as usize;
    if padding_end >= rounds.len() {
        return Err(H4ProofPackageV2Error::Schedule.into());
    }
    let profile_v1 = match header.profile {
        H4ProofProfileV2::K128 => crate::h4_proof_package_v1::H4ProofProfile::K128,
        H4ProofProfileV2::K512 => crate::h4_proof_package_v1::H4ProofProfile::K512,
    };
    let gkr_binding = h4_native_digest_statement_id_v2(
        0x100 + u16::from(header.shard_index),
        key.gkr_statement_bindings[usize::from(header.shard_index)],
    );
    let state_source_id =
        h4_native_digest_statement_id_v2(0x200, key.state_relation_source_binding);
    let statement_id = h4_native_digest_statement_id_v2(0x201, key.statement_binding);
    let algebra = crate::h4_proof_package_v1::verify_h4_shard_package_v1_boundary(
        &compatibility,
        profile_v1,
        header.shard_index,
        header.attempt,
        header.profile_identity,
        header.program_commitment,
        header.schedule_commitment,
        header.session_id,
        statement_id,
        &rounds[claim_index].message,
        &rounds[initial_index].message,
        &row_indices
            .iter()
            .map(|index| rounds[*index].message.as_slice())
            .collect::<Vec<_>>(),
        &rounds[base_index].message,
        &rounds[answer_index].message,
        claim_challenge,
        coordinate_challenge,
        mixing,
        epsilon,
        &row_challenges,
        combination,
        query_seed,
        h4_native_digest_statement_id_v2(
            0x202,
            BindingDigestV2::decode(boundary.transcript().final_transcript_root())
                .map_err(H4ProofPackageV2Error::Binding)?,
        ),
        gkr_binding,
        gkr_rounds,
        state_source_id,
        rounds[state_start..state_end].to_vec(),
        rounds[state_end..squarefree_end].to_vec(),
        rounds[squarefree_end..booleanity_end].to_vec(),
        rounds[booleanity_end..padding_end].to_vec(),
        rounds[padding_end].clone(),
        Some(native_backend),
    )
    .map_err(|_| H4ProofPackageV2Error::Algebra)?;
    let mut source_segment_set = b"BL/PQ512/WAVE2/H4/SOURCE-SEGMENT-SET/v2\0".to_vec();
    source_segment_set.push(header.profile.code());
    source_segment_set.push(header.shard_index);
    source_segment_set.extend_from_slice(header.source_tensor_root.as_bytes());
    source_segment_set.extend_from_slice(public_view.roots.main_base_root.as_bytes());
    source_segment_set.extend_from_slice(public_view.roots.gkr_base_tensor_root.as_bytes());
    source_segment_set.extend_from_slice(public_view.roots.squarefree_root.as_bytes());
    let source_segment_set_binding =
        BindingDigestV2::hash(BindingRoleV2::Payload, &source_segment_set)
            .map_err(H4ProofPackageV2Error::Binding)?;
    let construction = verify_h4_construction_v2(
        source_segment_set_binding,
        decoded_answer,
        &main_queries,
        &auxiliary_queries,
        &openings,
        combination,
    )?;
    let mut receipt = Vec::new();
    receipt.extend_from_slice(b"BL/PQ512/WAVE2/H4/SHARD-ALGEBRA/v2\0");
    receipt.extend_from_slice(&[header.profile.code(), header.shard_index]);
    receipt.extend_from_slice(header.source_tensor_root.as_bytes());
    receipt.extend_from_slice(public_view.roots.sumcheck_base_root.as_bytes());
    receipt.extend_from_slice(header.gkr_mask_tensor_root.as_bytes());
    receipt.extend_from_slice(public_view.roots.main_base_root.as_bytes());
    receipt.extend_from_slice(public_view.roots.gkr_base_tensor_root.as_bytes());
    receipt.extend_from_slice(public_view.roots.squarefree_root.as_bytes());
    receipt.extend_from_slice(public_view.roots.answer_tensor_root.as_bytes());
    receipt.extend_from_slice(&algebra.answer_functional.encode());
    receipt.extend_from_slice(&algebra.source_functional.encode());
    receipt.extend_from_slice(&algebra.booleanity.transcript_commitment());
    receipt.extend_from_slice(&algebra.padding.transcript_commitment());
    receipt.extend_from_slice(&(algebra.complete_mask_constraint_count as u32).to_be_bytes());
    Ok(VerifiedH4PreAlphaShardV2 {
        algebra_binding: BindingDigestV2::hash(BindingRoleV2::Payload, &receipt)
            .map_err(H4ProofPackageV2Error::Binding)?,
        source_root: header.source_tensor_root,
        bridge_base_root: header.bridge_base_tensor_root,
        construction,
    })
}

/// Complete pre-parent H4-v2 verification.  Root-use state is transactional:
/// a malformed algebra/PCS shard cannot consume a strict one-time key.
#[cfg(feature = "std")]
pub fn verify_h4_pre_alpha_v2<R: Read + Seek>(
    reader: &mut R,
    component_offset: u64,
    component_bytes: u64,
    key: &H4AggregatePackageV2VerificationKey,
    root_use_registry: &mut StrictPqRootUseRegistryV2,
) -> Result<VerifiedH4PreAlphaV2, H4AggregateStreamV2Error> {
    let mask_rank = gkr_mask_tensor_observation_rank_certificate(key.profile.state_capacity())
        .map_err(|_| H4ProofPackageV2Error::Rank)?;
    let enumerated_rank = mask_rank
        .state_composed_transcript_rank
        .checked_add(mask_rank.public_answer_equation_rank)
        .and_then(|rank| rank.checked_add(mask_rank.tensor_pcs_opening_scalars))
        .and_then(|rank| rank.checked_add(mask_rank.base_tensor_pcs_opening_scalars))
        .and_then(|rank| rank.checked_add(mask_rank.base_target_rank))
        .ok_or(H4ProofPackageV2Error::Rank)?;
    if enumerated_rank != mask_rank.complete_observation_rank
        || mask_rank.complete_observation_rank >= mask_rank.joint_coefficient_dimension
        || mask_rank.tensor_pcs_opening_scalars != H4_AUXILIARY_OPENINGS
        || mask_rank.base_tensor_pcs_opening_scalars != H4_AUXILIARY_OPENINGS
        || mask_rank.public_answer_equation_rank != H4_ANSWER_GKR_TENSOR_COEFFICIENT_BYTES / 64
        || mask_rank.base_target_rank != 1
        || mask_rank.residual_dimension
            != mask_rank.joint_coefficient_dimension - mask_rank.complete_observation_rank
        || mask_rank.residual_entropy_bits_lower_bound != mask_rank.residual_dimension * 16 * 30
        || mask_rank.residual_entropy_bits_lower_bound < 256
        || mask_rank.tensor_leaves != H4_GKR_TENSOR_LEAVES
        || mask_rank.tensor_leaf_bytes != 64
    {
        return Err(H4ProofPackageV2Error::Rank.into());
    }
    let mut pending_registry = root_use_registry.clone();
    let boundary = verify_h4_aggregate_package_v2_streaming_boundary(
        reader,
        component_offset,
        component_bytes,
        key,
        &mut pending_registry,
    )?;
    let mut shard_algebra_bindings = Vec::with_capacity(boundary.shards().len());
    let mut source_roots = Vec::with_capacity(boundary.shards().len());
    let mut bridge_base_roots = Vec::with_capacity(boundary.shards().len());
    let mut constructions = Vec::with_capacity(boundary.shards().len());
    for shard in boundary.shards().iter().copied() {
        let verified = verify_h4_shard_pre_alpha_v2(reader, &boundary, key, shard)?;
        shard_algebra_bindings.push(verified.algebra_binding);
        source_roots.push(verified.source_root);
        bridge_base_roots.push(verified.bridge_base_root);
        constructions.push(verified.construction);
    }
    *root_use_registry = pending_registry;
    Ok(VerifiedH4PreAlphaV2 {
        profile: boundary.header().profile,
        aggregate_binding: boundary.aggregate_binding(),
        final_transcript_root: *boundary.transcript().final_transcript_root(),
        shard_algebra_bindings,
        source_roots,
        bridge_base_roots,
        constructions,
    })
}

/// One shard's post-parent-z response.  Challenge outputs must come from the
/// strict-PQ replay API; source/base bytes are authenticated against roots
/// already fixed in the matching pre-alpha receipt.
pub struct H4PostZShardV2<'a> {
    pub response: &'a crate::h4_bridge_source_response_v2::H4BridgeSourceResponseV2,
    pub strict: &'a crate::h4_bridge_source_response_v2::VerifiedStrictH4BridgeSourceResponseV2,
    pub source_segment: &'a [u8],
    pub base_segment: &'a [u8],
}

/// Source-augmented bridge-mask PCS proof. The source binding is intentionally
/// absent: `complete_h4_v2` derives it from the verified shard responses and
/// supplies it directly to the mask verifier, avoiding a caller-authenticated
/// receipt cycle.
pub struct H4SourceMaskProofV2<'a> {
    pub batch_challenge: Fp16,
    pub inner_product_proof: &'a crate::semantic_h4_bridge_gkr::PublicBridgeInnerProductProof,
    pub inner_product_challenges: &'a [Fp16],
    pub pcs_proof: &'a crate::binding_multilinear_pcs_v2::BindingMultilinearPcsProofV2,
    pub expected_mask_root: BindingRootV2,
    pub expected_context: BindingDigestV2,
    pub completion_coin: BindingDigestV2,
}

impl<'a> From<&'a crate::semantic_h4_bridge_gkr::ProducedSemanticH4BridgeSourceMaskV3>
    for H4SourceMaskProofV2<'a>
{
    fn from(
        produced: &'a crate::semantic_h4_bridge_gkr::ProducedSemanticH4BridgeSourceMaskV3,
    ) -> Self {
        Self {
            batch_challenge: produced.batch_challenge,
            inner_product_proof: &produced.inner_product_proof,
            inner_product_challenges: &produced.inner_product_challenges,
            pcs_proof: &produced.pcs_proof,
            expected_mask_root: produced.expected_mask_root,
            expected_context: produced.expected_context,
            completion_coin: produced.completion_coin,
        }
    }
}

/// Opaque authority that every post-Z H4 source/base response has been
/// authenticated against the roots fixed before alpha, agrees with the
/// strict bridge transcript, and satisfies the shard-summed semantic/H4
/// source identity.
///
/// This receipt deliberately owns the pre-alpha authority.  It therefore
/// cannot be paired with a different H4 package after a producer uses its
/// verifier-derived source constraints to construct the final mask PCS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedH4PostZSourcesV2 {
    pre_alpha: VerifiedH4PreAlphaV2,
    verified_gkr: crate::semantic_h4_bridge_gkr::VerifiedMaskedSemanticH4BridgeGkr,
    semantic_batch: crate::semantic_h4_bridge_gkr::VerifiedSemanticBridgeSourceBatchV3,
    source_binding: crate::semantic_h4_bridge_gkr::VerifiedSemanticH4BridgeSourceBinding,
    post_z_context: BindingDigestV2,
    strict_gkr_final_transcript_root: [u8; BINDING_V2_BYTES],
    strict_response_final_transcript_roots: Vec<[u8; BINDING_V2_BYTES]>,
    verified_responses: Vec<crate::h4_bridge_source_response_v2::VerifiedH4BridgeSourceResponseV2>,
    post_z_response_oracle_root: BindingDigestV2,
}

impl VerifiedH4PostZSourcesV2 {
    pub const fn profile(&self) -> H4ProofProfileV2 {
        self.pre_alpha.profile
    }

    pub const fn pre_alpha_binding(&self) -> BindingDigestV2 {
        self.pre_alpha.aggregate_binding
    }

    pub const fn source_binding(&self) -> BindingDigestV2 {
        self.source_binding.source_batch_binding()
    }

    pub const fn post_z_context(&self) -> BindingDigestV2 {
        self.post_z_context
    }

    pub const fn post_z_response_oracle_root(&self) -> BindingDigestV2 {
        self.post_z_response_oracle_root
    }

    pub const fn claim_vector_commitment(&self) -> BindingDigestV2 {
        self.semantic_batch.claim_vector_binding()
    }

    /// Produce the exact source-augmented mask proof for this authenticated
    /// post-Z receipt.  The context and source equations are verifier-owned;
    /// the caller supplies only the private mask coefficients and public-coin
    /// challenges needed by the native PCS producer.
    pub fn produce_source_mask_proof(
        &self,
        mask_coefficients: &[Fp16],
        batch_challenge: Fp16,
        inner_product_challenges: &[Fp16],
        completion_coin: BindingDigestV2,
    ) -> Result<
        crate::semantic_h4_bridge_gkr::ProducedSemanticH4BridgeSourceMaskV3,
        H4ProofPackageV2Error,
    > {
        let profile = match self.pre_alpha.profile {
            H4ProofProfileV2::K128 => crate::semantic_h4_bridge_gkr::SemanticH4BridgeProfile::K128,
            H4ProofProfileV2::K512 => crate::semantic_h4_bridge_gkr::SemanticH4BridgeProfile::K512,
        };
        crate::semantic_h4_bridge_gkr::produce_semantic_h4_bridge_source_mask_batch_with_pcs(
            profile,
            &self.verified_gkr,
            &self.source_binding,
            mask_coefficients,
            batch_challenge,
            inner_product_challenges,
            self.post_z_context,
            completion_coin,
        )
        .map_err(|_| H4ProofPackageV2Error::Algebra)
    }
}

/// Opaque complete H4-v2 acceptance receipt.  Construction is possible only
/// after the native pre-alpha algebra, every shard-local post-z source
/// reduction, the global shard-sum identity, and the source-augmented mask PCS
/// have all verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedH4V2 {
    profile: H4ProofProfileV2,
    pre_alpha_binding: BindingDigestV2,
    receipt_binding: BindingDigestV2,
    source_binding: BindingDigestV2,
    semantic_fri_binding: BindingDigestV2,
    semantic_coefficient_root_inventory_binding: BindingDigestV2,
    post_z_context: BindingDigestV2,
    post_z_response_oracle_root: BindingDigestV2,
    post_z_claim_vector_commitment: BindingDigestV2,
    constructions: Vec<VerifiedH4ConstructionV2>,
}

impl VerifiedH4V2 {
    pub const fn profile(&self) -> H4ProofProfileV2 {
        self.profile
    }

    pub const fn pre_alpha_binding(&self) -> BindingDigestV2 {
        self.pre_alpha_binding
    }

    pub const fn receipt_binding(&self) -> BindingDigestV2 {
        self.receipt_binding
    }

    pub const fn source_binding(&self) -> BindingDigestV2 {
        self.source_binding
    }

    pub const fn semantic_fri_binding(&self) -> BindingDigestV2 {
        self.semantic_fri_binding
    }

    pub const fn semantic_coefficient_root_inventory_binding(&self) -> BindingDigestV2 {
        self.semantic_coefficient_root_inventory_binding
    }

    pub const fn post_z_context(&self) -> BindingDigestV2 {
        self.post_z_context
    }

    /// Root of the ordered, verifier-derived H4 source-response receipts.
    /// This is not a caller-provided oracle root.
    pub const fn post_z_response_oracle_root(&self) -> BindingDigestV2 {
        self.post_z_response_oracle_root
    }

    /// Claim-vector identity fixed by the verified semantic/H4 bridge batch.
    pub const fn post_z_claim_vector_commitment(&self) -> BindingDigestV2 {
        self.post_z_claim_vector_commitment
    }

    pub fn construction_count(&self) -> usize {
        self.constructions.len()
    }
}

/// A verifier request for one H4 Construction opening. The request describes
/// the verifier-derived functional weights; the claimed value is checked
/// against the authenticated answer coefficients before an opening is minted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H4BridgeOpeningRequest {
    pub shard_index: usize,
    pub point: Vec<Fp16>,
    pub coefficient_weights: Vec<Fp16>,
    pub claimed_masked_value: Fp16,
}

/// Opaque H4 opening accepted by the current post-Z bridge. It carries only
/// values derived from a verified native answer polynomial and its source
/// binding; callers cannot construct it from a root/value pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedH4BridgeOpening {
    source_segment_set_binding: BindingDigestV2,
    answer_binding: BindingDigestV2,
    point: Vec<Fp16>,
    masked_value: Fp16,
}

impl VerifiedH4BridgeOpening {
    pub const fn source_segment_set_binding(&self) -> BindingDigestV2 {
        self.source_segment_set_binding
    }

    pub const fn answer_binding(&self) -> BindingDigestV2 {
        self.answer_binding
    }

    pub fn point(&self) -> &[Fp16] {
        &self.point
    }

    pub const fn masked_value(&self) -> Fp16 {
        self.masked_value
    }
}

impl VerifiedH4V2 {
    /// Verify and mint H4 bridge openings from the exact Construction answer
    /// polynomial retained by pre-alpha verification. A mismatched weight,
    /// point, shard, or claimed value fails before any opening is returned.
    pub fn verify_bridge_openings(
        &self,
        requests: &[H4BridgeOpeningRequest],
    ) -> Result<Vec<VerifiedH4BridgeOpening>, H4ProofPackageV2Error> {
        if requests.is_empty()
            || requests.iter().any(|request| {
                request.shard_index >= self.constructions.len()
                    || request.point.is_empty()
                    || request.coefficient_weights.is_empty()
            })
        {
            return Err(H4ProofPackageV2Error::Geometry);
        }
        let mut result = Vec::with_capacity(requests.len());
        for request in requests {
            let construction = &self.constructions[request.shard_index];
            let terminals = verify_h4_bridge_source_terminals_v2(
                construction,
                core::slice::from_ref(&request.point),
                core::slice::from_ref(&request.coefficient_weights),
                core::slice::from_ref(&request.claimed_masked_value),
            )?;
            let terminal = terminals
                .into_iter()
                .next()
                .ok_or(H4ProofPackageV2Error::Geometry)?;
            result.push(VerifiedH4BridgeOpening {
                source_segment_set_binding: terminal.source_segment_set_binding(),
                answer_binding: terminal.answer_binding(),
                point: terminal.point().to_vec(),
                masked_value: terminal.masked_value(),
            });
        }
        Ok(result)
    }
}

/// Authenticate every post-Z source response and derive the exact
/// source-augmented bridge-mask relation before the mask proof is produced.
/// In K512 the four physical shard targets are checked additively; the legacy
/// bug where every shard could claim the same global target is structurally
/// impossible here.
pub fn verify_h4_post_z_sources_v2(
    pre_alpha: VerifiedH4PreAlphaV2,
    strict_gkr: &crate::semantic_h4_bridge_gkr::VerifiedStrictSemanticH4BridgeGkr,
    semantic_batch: &crate::semantic_h4_bridge_gkr::VerifiedSemanticBridgeSourceBatchV3,
    expected_post_z_context: BindingDigestV2,
    shards: &[H4PostZShardV2<'_>],
) -> Result<VerifiedH4PostZSourcesV2, H4ProofPackageV2Error> {
    let verified_gkr = strict_gkr.verified_gkr();
    let expected_semantic_profile = match pre_alpha.profile {
        H4ProofProfileV2::K128 => crate::semantic_h4_bridge_gkr::SemanticH4BridgeProfile::K128,
        H4ProofProfileV2::K512 => crate::semantic_h4_bridge_gkr::SemanticH4BridgeProfile::K512,
    };
    if strict_gkr.context() != expected_post_z_context
        || verified_gkr.profile != expected_semantic_profile
        || shards.len() != usize::from(pre_alpha.profile.shard_count())
        || shards.len() != pre_alpha.source_roots.len()
        || shards.len() != pre_alpha.bridge_base_roots.len()
    {
        return Err(H4ProofPackageV2Error::Geometry);
    }
    let mut verified_responses = Vec::with_capacity(shards.len());
    let mut strict_response_final_transcript_roots = Vec::with_capacity(shards.len());
    for (shard_index, shard) in shards.iter().enumerate() {
        let challenges = shard.strict.challenges();
        if shard.strict.context() != expected_post_z_context
            || shard.strict.claim_vector_binding() != semantic_batch.claim_vector_binding()
            || challenges.claim_challenge != semantic_batch.claim_challenge()
        {
            return Err(H4ProofPackageV2Error::Schedule);
        }
        let first = shard
            .response
            .row_sumcheck_rounds
            .first()
            .ok_or(H4ProofPackageV2Error::Algebra)?;
        let shard_target = first[0] + first[0] + first[1] + first[2];
        let query_seed = challenges.response_seal_challenge.encode();
        let positions = exact_queries(
            &query_seed,
            H4_BRIDGE_RESPONSE_QUERY_DOMAIN_V2,
            H4_MAIN_CODE_VALUES,
            H4_MAIN_OPENINGS,
        )
        .map_err(|_| H4ProofPackageV2Error::Multiproof)?;
        let verified = verify_h4_bridge_source_response_against_native_roots_v2(
            pre_alpha.profile,
            u8::try_from(shard_index).map_err(|_| H4ProofPackageV2Error::Geometry)?,
            verified_gkr,
            semantic_batch,
            shard.response,
            challenges.claim_challenge,
            &challenges.row_challenges,
            &challenges.projection_challenges,
            challenges.coordinate_challenge,
            shard_target,
            shard.source_segment,
            shard.base_segment,
            pre_alpha.source_roots[shard_index],
            pre_alpha.bridge_base_roots[shard_index],
            &positions,
        )?;
        verified_responses.push(verified);
        strict_response_final_transcript_roots.push(*shard.strict.final_transcript_root());
    }
    let source_binding =
        crate::semantic_h4_bridge_gkr::bind_semantic_h4_bridge_batched_sources_v3_aggregate(
            verified_gkr,
            semantic_batch,
            &verified_responses,
        )
        .map_err(|_| H4ProofPackageV2Error::Algebra)?;
    let mut response_oracle = b"BL/PQ512/WAVE2/H4/POST-Z-RESPONSE-ORACLE/v2\0".to_vec();
    response_oracle.push(pre_alpha.profile.code());
    response_oracle.extend_from_slice(semantic_batch.claim_vector_binding().as_bytes());
    for response in &verified_responses {
        response_oracle.extend_from_slice(response.source_root().as_bytes());
        response_oracle.extend_from_slice(response.base_root().as_bytes());
        response_oracle.extend_from_slice(response.answer_binding().as_bytes());
        response_oracle.extend_from_slice(&response.masked_target().encode());
    }
    let post_z_response_oracle_root =
        BindingDigestV2::hash(BindingRoleV2::Payload, &response_oracle)?;
    Ok(VerifiedH4PostZSourcesV2 {
        pre_alpha,
        verified_gkr: verified_gkr.clone(),
        semantic_batch: semantic_batch.clone(),
        source_binding,
        post_z_context: expected_post_z_context,
        strict_gkr_final_transcript_root: *strict_gkr.final_transcript_root(),
        strict_response_final_transcript_roots,
        verified_responses,
        post_z_response_oracle_root,
    })
}

/// Complete H4 from the opaque post-Z authority and a mask proof produced for
/// its verifier-derived source constraints. No package, response, scalar, or
/// context can be substituted between source authentication and completion.
pub fn complete_h4_v2_from_verified_post_z(
    post_z: VerifiedH4PostZSourcesV2,
    source_mask_proof: H4SourceMaskProofV2<'_>,
) -> Result<VerifiedH4V2, H4ProofPackageV2Error> {
    if source_mask_proof.expected_context != post_z.post_z_context {
        return Err(H4ProofPackageV2Error::Schedule);
    }
    let expected_semantic_profile = match post_z.pre_alpha.profile {
        H4ProofProfileV2::K128 => crate::semantic_h4_bridge_gkr::SemanticH4BridgeProfile::K128,
        H4ProofProfileV2::K512 => crate::semantic_h4_bridge_gkr::SemanticH4BridgeProfile::K512,
    };
    let (source_mask_batch, _) =
        crate::semantic_h4_bridge_gkr::verify_semantic_h4_bridge_source_mask_batch_with_pcs(
            expected_semantic_profile,
            &post_z.verified_gkr,
            &post_z.source_binding,
            source_mask_proof.batch_challenge,
            source_mask_proof.inner_product_proof,
            source_mask_proof.inner_product_challenges,
            source_mask_proof.pcs_proof,
            source_mask_proof.expected_mask_root,
            source_mask_proof.expected_context,
            source_mask_proof.completion_coin,
        )
        .map_err(|_| H4ProofPackageV2Error::Algebra)?;
    let pre_alpha = post_z.pre_alpha;
    let semantic_batch = post_z.semantic_batch;
    let source_binding = post_z.source_binding;
    let verified_responses = post_z.verified_responses;
    let expected_post_z_context = post_z.post_z_context;
    let mut receipt = b"BL/PQ512/WAVE2/VERIFIED-H4/v2\0".to_vec();
    receipt.push(pre_alpha.profile.code());
    receipt.extend_from_slice(pre_alpha.aggregate_binding.as_bytes());
    receipt.extend_from_slice(&pre_alpha.final_transcript_root);
    receipt.extend_from_slice(source_binding.source_batch_binding().as_bytes());
    receipt.extend_from_slice(semantic_batch.semantic_fri_binding().as_bytes());
    receipt.extend_from_slice(
        semantic_batch
            .coefficient_root_inventory_binding()
            .as_bytes(),
    );
    receipt.extend_from_slice(source_mask_batch.mask_root.as_bytes());
    receipt.extend_from_slice(expected_post_z_context.as_bytes());
    receipt.extend_from_slice(&post_z.strict_gkr_final_transcript_root);
    receipt.extend_from_slice(&source_mask_batch.challenge.encode());
    receipt.extend_from_slice(&source_mask_batch.opening.encode());
    receipt.extend_from_slice(&(verified_responses.len() as u32).to_be_bytes());
    for (response, strict_root) in verified_responses
        .iter()
        .zip(&post_z.strict_response_final_transcript_roots)
    {
        receipt.extend_from_slice(response.source_root().as_bytes());
        receipt.extend_from_slice(response.base_root().as_bytes());
        receipt.extend_from_slice(response.answer_binding().as_bytes());
        receipt.extend_from_slice(&response.masked_target().encode());
        receipt.extend_from_slice(strict_root);
    }
    Ok(VerifiedH4V2 {
        profile: pre_alpha.profile,
        pre_alpha_binding: pre_alpha.aggregate_binding,
        receipt_binding: BindingDigestV2::hash(BindingRoleV2::Payload, &receipt)?,
        source_binding: source_binding.source_batch_binding(),
        semantic_fri_binding: semantic_batch.semantic_fri_binding(),
        semantic_coefficient_root_inventory_binding: semantic_batch
            .coefficient_root_inventory_binding(),
        post_z_context: expected_post_z_context,
        post_z_response_oracle_root: post_z.post_z_response_oracle_root,
        post_z_claim_vector_commitment: semantic_batch.claim_vector_binding(),
        constructions: pre_alpha.constructions,
    })
}

/// One-call compatibility boundary for accepting verifiers that already have
/// a serialized source-mask proof. Producers should use
/// [`verify_h4_post_z_sources_v2`] followed by
/// [`VerifiedH4PostZSourcesV2::produce_source_mask_proof`] and
/// [`complete_h4_v2_from_verified_post_z`].
pub fn complete_h4_v2(
    pre_alpha: VerifiedH4PreAlphaV2,
    strict_gkr: &crate::semantic_h4_bridge_gkr::VerifiedStrictSemanticH4BridgeGkr,
    semantic_batch: &crate::semantic_h4_bridge_gkr::VerifiedSemanticBridgeSourceBatchV3,
    source_mask_proof: H4SourceMaskProofV2<'_>,
    expected_post_z_context: BindingDigestV2,
    shards: &[H4PostZShardV2<'_>],
) -> Result<VerifiedH4V2, H4ProofPackageV2Error> {
    let post_z = verify_h4_post_z_sources_v2(
        pre_alpha,
        strict_gkr,
        semantic_batch,
        expected_post_z_context,
        shards,
    )?;
    complete_h4_v2_from_verified_post_z(post_z, source_mask_proof)
}

pub const H4_PROOF_PACKAGE_V2_ACCEPTING: bool = true;

#[cfg(test)]
mod algebra_tests {
    use super::*;
    use crate::{field::M31, h4_proof_package_v1::encode_codeword};

    fn fp(value: u32) -> Fp16 {
        Fp16::from_m31(M31::from_canonical(value).unwrap())
    }

    fn squarefree_binding_v2_fixture(capacity: u16) -> (BindingRootV2, Vec<u8>) {
        let top = BindingDigestV2::hash(BindingRoleV2::MerkleNode, b"squarefree-root").unwrap();
        let root = BindingRootV2::from_top(1, top).unwrap();
        let mut phases = Vec::new();
        for phase in 0..2_u32 {
            phases.extend_from_slice(&11_u16.to_be_bytes());
            phases.extend_from_slice(&[0_u8; 6]);
            for value in 0..12_u32 {
                phases.extend_from_slice(&fp(phase * 17 + value + 1).encode());
            }
        }
        let mut digest_preimage = Vec::new();
        digest_preimage.extend_from_slice(H4_SQUAREFREE_CLAIMS_DIGEST_V2_DOMAIN);
        digest_preimage.extend_from_slice(root.as_bytes());
        digest_preimage.extend_from_slice(&capacity.to_be_bytes());
        digest_preimage.extend_from_slice(&2_u16.to_be_bytes());
        digest_preimage.extend_from_slice(&phases);
        let claims_digest =
            BindingDigestV2::hash(BindingRoleV2::Payload, &digest_preimage).unwrap();
        let mut encoded = Vec::new();
        encoded.extend_from_slice(b"BLSQAB03");
        encoded.extend_from_slice(b"BLSQCL03");
        encoded.extend_from_slice(root.as_bytes());
        encoded.extend_from_slice(&capacity.to_be_bytes());
        encoded.extend_from_slice(&2_u16.to_be_bytes());
        encoded.extend_from_slice(claims_digest.as_bytes());
        encoded.extend_from_slice(&phases);
        encoded.extend_from_slice(&fp(101).encode());
        encoded.extend_from_slice(&fp(103).encode());
        assert_eq!(encoded.len(), H4_BLSQAB03_BYTES);
        (root, encoded)
    }

    #[test]
    fn squarefree_binding_v2_authenticates_full_root_digest_and_payload() {
        let capacity = 512;
        let (root, encoded) = squarefree_binding_v2_fixture(capacity);
        let compatibility =
            squarefree_binding_v1_compatibility_v2(&encoded, root, capacity).unwrap();
        assert_eq!(
            compatibility.len(),
            crate::h4_proof_package_v1::H4_BLSQAB02_BYTES
        );
        assert_eq!(&compatibility[..8], b"BLSQAB02");
        assert_eq!(&compatibility[8..16], b"BLSQCL02");

        for offset in [16, 16 + BINDING_V2_BYTES + 4, 8 + H4_BLSQCL03_BYTES + 10] {
            let mut mutated = encoded.clone();
            mutated[offset] ^= 1;
            assert!(squarefree_binding_v1_compatibility_v2(&mutated, root, capacity).is_err());
        }
        let mut zero_mix = encoded;
        zero_mix[H4_BLSQAB03_BYTES - 64..].fill(0);
        assert_eq!(
            squarefree_binding_v1_compatibility_v2(&zero_mix, root, capacity),
            Err(H4ProofPackageV2Error::Algebra)
        );
    }

    #[test]
    fn construction_spotchecks_bind_answer_to_source_and_base() {
        let combination = fp(103);
        let main_count = H4_ANSWER_MAIN_COEFFICIENT_BYTES / 64;
        let ordinary_word_count =
            (H4_ANSWER_ORDINARY_AUXILIARY_COEFFICIENT_BYTES / 64) / NON_GKR_AUXILIARY_WORDS;
        let source_main = (0..main_count)
            .map(|index| fp((index as u32 * 11 + 3) % 65_521))
            .collect::<Vec<_>>();
        let base_main = (0..main_count)
            .map(|index| fp((index as u32 * 13 + 5) % 65_521))
            .collect::<Vec<_>>();
        let answer_main = base_main
            .iter()
            .zip(&source_main)
            .map(|(base, source)| *base + combination * *source)
            .collect::<Vec<_>>();
        let source_ordinary = (0..NON_GKR_AUXILIARY_WORDS)
            .map(|word| {
                (0..ordinary_word_count)
                    .map(|index| fp((word as u32 * 71 + index as u32 * 17 + 7) % 65_521))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let base_ordinary = (0..NON_GKR_AUXILIARY_WORDS)
            .map(|word| {
                (0..ordinary_word_count)
                    .map(|index| fp((word as u32 * 73 + index as u32 * 19 + 9) % 65_521))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let answer_ordinary = base_ordinary
            .iter()
            .zip(&source_ordinary)
            .map(|(base, source)| {
                base.iter()
                    .zip(source)
                    .map(|(base, source)| *base + combination * *source)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let main_queries = (0..H4_MAIN_OPENINGS)
            .map(|index| (index * 79 + 17) % H4_MAIN_CODE_VALUES)
            .collect::<Vec<_>>();
        let auxiliary_queries = (0..H4_AUXILIARY_OPENINGS)
            .map(|index| (index * 41 + 19) % H4_AUXILIARY_CODE_VALUES)
            .collect::<Vec<_>>();
        let source_main_code = encode_codeword(&source_main, H4_MAIN_CODE_VALUES.ilog2()).unwrap();
        let base_main_code = encode_codeword(&base_main, H4_MAIN_CODE_VALUES.ilog2()).unwrap();
        let source_ordinary_code = source_ordinary
            .iter()
            .map(|word| encode_codeword(word, H4_AUXILIARY_CODE_VALUES.ilog2()).unwrap())
            .collect::<Vec<_>>();
        let base_ordinary_code = base_ordinary
            .iter()
            .map(|word| encode_codeword(word, H4_AUXILIARY_CODE_VALUES.ilog2()).unwrap())
            .collect::<Vec<_>>();
        let openings = VerifiedH4NativeOpeningsV2 {
            source_main_openings: main_queries
                .iter()
                .map(|index| source_main_code[*index])
                .collect(),
            sumcheck_source_openings: (0..H4_AUXILIARY_OPENINGS)
                .flat_map(|ordinal| {
                    let query = auxiliary_queries[ordinal];
                    source_ordinary_code[..WORD_SUMCHECK_ROUNDS]
                        .iter()
                        .map(move |codeword| codeword[query])
                })
                .collect(),
            ordinary_base_openings: (0..H4_AUXILIARY_OPENINGS)
                .flat_map(|ordinal| {
                    let query = auxiliary_queries[ordinal];
                    base_ordinary_code
                        .iter()
                        .map(move |codeword| codeword[query])
                })
                .collect(),
            main_base_openings: main_queries
                .iter()
                .map(|index| base_main_code[*index])
                .collect(),
            squarefree_source_openings: auxiliary_queries
                .iter()
                .map(|index| source_ordinary_code[NON_GKR_AUXILIARY_WORDS - 1][*index])
                .collect(),
            base_tensor_openings: vec![Fp16::ZERO; H4_AUXILIARY_OPENINGS],
            mask_tensor_openings: vec![Fp16::ZERO; H4_AUXILIARY_OPENINGS],
        };
        let mut answer = answer_main;
        for word in answer_ordinary {
            answer.extend_from_slice(&word);
        }
        verify_h4_construction_spotchecks_v2(
            &answer,
            &main_queries,
            &auxiliary_queries,
            &openings,
            combination,
        )
        .unwrap();
        let functional_values = answer.len();
        let source_binding = BindingDigestV2::hash(BindingRoleV2::Payload, b"source-set").unwrap();
        let mut complete_answer = answer.clone();
        complete_answer.resize(H4_ANSWER_COEFFICIENT_BYTES / 64, Fp16::ZERO);
        let answer_binding =
            h4_answer_binding_v2(source_binding, combination, &complete_answer).unwrap();
        let construction = VerifiedH4ConstructionV2 {
            source_segment_set_binding: source_binding,
            answer_binding,
            combination,
            answer_coefficients: complete_answer,
        };
        let weights = (0..functional_values)
            .map(|index| fp((index as u32 * 29 + 11) % 65_521))
            .collect::<Vec<_>>();
        let claimed = inner_product_v2(&answer, &weights).unwrap() * combination.inverse().unwrap();
        let terminals = verify_h4_bridge_source_terminals_v2(
            &construction,
            &[vec![fp(3), fp(5)]],
            &[weights],
            &[claimed],
        )
        .unwrap();
        assert_eq!(terminals[0].masked_value(), claimed);
        assert_eq!(terminals[0].answer_binding(), answer_binding);
        assert_eq!(
            verify_h4_bridge_source_terminals_v2(
                &construction,
                &[vec![fp(3), fp(5)]],
                &[vec![Fp16::ZERO; functional_values]],
                &[claimed],
            ),
            Err(H4ProofPackageV2Error::RootMismatch)
        );
        answer[0] = answer[0] + Fp16::ONE;
        assert_eq!(
            verify_h4_construction_spotchecks_v2(
                &answer,
                &main_queries,
                &auxiliary_queries,
                &openings,
                combination,
            ),
            Err(H4ProofPackageV2Error::RootMismatch)
        );
    }
}
