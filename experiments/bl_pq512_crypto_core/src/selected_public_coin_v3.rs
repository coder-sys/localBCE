//! Versioned two-segment semantic public coin for the nonactivating v3 bridge.
//!
//! Global semantic rounds 0 and 1 are authenticated before the composite
//! parent. The parent then authenticates the composition root, bridge mask
//! inventory and the sole OODS point. Semantic replay resumes at global round
//! 2 from a parent-derived anchor. There is deliberately no semantic kind-3
//! round and no child-local OODS sampler.
//!
//! All hashes in this module are 64-byte SHA3-512 transcript/audit authorities
//! used for second-preimage binding. They are not Merkle/oracle commitments and
//! do not repair the pending Z10 128-byte collision-binding migration.
//! Serialized 64-byte main/interaction/FRI roots and the contributor registry
//! commitment remain nonactivating collision-binding placeholders.

use alloc::{vec, vec::Vec};
use core::fmt;

use ml_dsa::{
    EncodedVerifyingKey as MlDsaEncodedVerifyingKey, MlDsa87, Signature as MlDsaSignature,
    VerifyingKey as MlDsaVerifyingKey, signature::Verifier as _,
};
use sha3::{Digest, Sha3_512};
use slh_dsa::{Shake256f, Signature as SlhDsaSignature, VerifyingKey as SlhDsaVerifyingKey};

use crate::circle_fft::evaluate_extension_coefficients_at_point;
use crate::composite_parent_public_coin::{
    BridgeQuotientGroup, COMPOSITE_PARENT_FINAL_KIND, COMPOSITE_PARENT_PRE_ALPHA_KIND,
    COMPOSITE_PARENT_QUOTIENT_KIND, VerifiedCompositeParentPrefix,
};
use crate::field::{DecodeError, Fp16};
use crate::master_commitments::Profile;
use crate::oods::{CirclePoint, OodsParameter, stereographic_circle_point};
use crate::proof_parameters::{ProofParameterError, selected_query_positions};
use crate::sampler::{DEFAULT_MAX_ATTEMPTS, sample_uniform_fp16};
use crate::strict_pq_public_coin_v2::{
    StrictPqFp16PolicyV2, StrictPqGovernedVerifierKeyV2, StrictPqH4ProfileV2,
    StrictPqPublicCoinBundleV2, StrictPqPublicCoinV2Error, StrictPqRootUseRegistryV2,
    StrictPqRoundDescriptorV2, replay_strict_pq_fp16_public_coin_v2,
};

pub const SEMANTIC_V3_PREFIX_MAGIC: &[u8; 8] = b"BLV3SP01";
pub const SEMANTIC_V3_CONTINUATION_MAGIC: &[u8; 8] = b"BLV3SC01";
pub const SEMANTIC_V3_TRANSCRIPT_VERSION: u16 = 1;
pub const SEMANTIC_V3_TOPOLOGY_TAG: &[u8] = b"TWO-SEGMENT-R0-R1-PARENT-R2-PLUS/v1";
pub const SEMANTIC_V3_PARENT_ANCHOR_SEAM_TAG: &[u8] =
    b"PARENT-KIND900-KIND901-AUTHENTICATED-ANCHOR-SEAM/v1";
pub const SEMANTIC_V3_FIELD16_OUTPUT_KIND: u16 = 1;
pub const SEMANTIC_V3_QUERY_SEED_OUTPUT_KIND: u16 = 2;
pub const SEMANTIC_V3_QUERY_COUNT: u16 = 945;
pub const SEMANTIC_V3_Q_COEFFICIENT_COUNT: usize = 4_789;
pub const SEMANTIC_V3_Q_PADDED_COUNT: usize = 8_192;

pub const SEMANTIC_V3_SCHEDULE_DOMAIN: &[u8] = b"BL/PQ512/SELECTED/SEMANTIC-V3/SCHEDULE/v1\0";
pub const SEMANTIC_V3_CONTRIBUTOR_SET_DOMAIN: &[u8] =
    b"BL/PQ512/SELECTED/SEMANTIC-V3/CONTRIBUTOR-SET/v1\0";
pub const SEMANTIC_V3_PREFIX_INIT_DOMAIN: &[u8] = b"BL/PQ512/SELECTED/SEMANTIC-V3/PREFIX-INIT/v1\0";
pub const SEMANTIC_V3_COMMITMENT_HASH_DOMAIN: &[u8] =
    b"BL/PQ512/SELECTED/SEMANTIC-V3/ROUND-COMMITMENT/v1\0";
pub const SEMANTIC_V3_COMMITMENT_SIGNATURE_DOMAIN: &[u8] =
    b"BL/PQ512/SELECTED/SEMANTIC-V3/COMMITMENT-SIGNATURE/v1\0";
pub const SEMANTIC_V3_REVEAL_SIGNATURE_DOMAIN: &[u8] =
    b"BL/PQ512/SELECTED/SEMANTIC-V3/REVEAL-SIGNATURE/v1\0";
pub const SEMANTIC_V3_ROUND_SEED_DOMAIN: &[u8] = b"BL/PQ512/SELECTED/SEMANTIC-V3/ROUND-SEED/v1\0";
pub const SEMANTIC_V3_AUDIT_ROOT_DOMAIN: &[u8] = b"BL/PQ512/SELECTED/SEMANTIC-V3/AUDIT-ROOT/v1\0";
pub const SEMANTIC_V3_PREFIX_RECEIPT_DOMAIN: &[u8] =
    b"BL/PQ512/SELECTED/SEMANTIC-V3/PREFIX-RECEIPT/v1\0";
pub const SEMANTIC_V3_CONTINUATION_ANCHOR_DOMAIN: &[u8] =
    b"BL/PQ512/SELECTED/SEMANTIC-V3/PARENT-ANCHOR/v1\0";
pub const SEMANTIC_V3_PARENT_ANCHOR_FRAME_COMMITMENT_DOMAIN: &[u8] =
    b"BL/PQ512/SELECTED/SEMANTIC-V3/PRODUCER-ANCHOR-FRAME/v1\0";
pub const SEMANTIC_V3_STRICT_SCHEDULE_DOMAIN: &[u8] =
    b"BL/PQ512/SELECTED/SEMANTIC-V3/STRICT-PQ-SCHEDULE/v2\0";
pub const SEMANTIC_V3_STRICT_MESSAGE_BINDING_DOMAIN: &[u8] =
    b"BL/PQ512/SELECTED/SEMANTIC-V3/STRICT-MESSAGE-BINDING/v1\0";
pub const SEMANTIC_V3_NATIVE_COMMITMENT_MESSAGE_DOMAIN: &[u8] =
    b"BL/PQ512/SELECTED/SEMANTIC-V3/NATIVE-COMMITMENT-MESSAGE/v1\0";
pub const SEMANTIC_V3_NATIVE_BATCH_DERIVATION_MESSAGE_DOMAIN: &[u8] =
    b"BL/PQ512/SELECTED/SEMANTIC-V3/NATIVE-BATCH-DERIVATION-MESSAGE/v1\0";

const SEMANTIC_V3_NATIVE_MAIN_ROLE: u16 = 1;
const SEMANTIC_V3_NATIVE_INTERACTION_ROLE: u16 = 2;
const SEMANTIC_V3_NATIVE_COMPOSITION_ROLE: u16 = 3;
const SEMANTIC_V3_NATIVE_CLAIMS_ROLE: u16 = 4;
const SEMANTIC_V3_NATIVE_MASK_ROLE: u16 = 5;
const SEMANTIC_V3_NATIVE_FRI_LAYER_ROLE: u16 = 6;

fn native_commitment_message(
    role: u16,
    ordinal: u32,
    digest: &crate::binding_root_v2::BindingDigestV2,
) -> [u8; 64] {
    let role = role.to_be_bytes();
    let ordinal = ordinal.to_be_bytes();
    hash(
        SEMANTIC_V3_NATIVE_COMMITMENT_MESSAGE_DOMAIN,
        &[&role, &ordinal, digest.as_bytes()],
    )
}

/// Fixed 64-byte transcript message that commits to the complete native
/// 128-byte main root. It is a public-coin message binding, never a Merkle
/// root or a substitute verification authority.
pub fn semantic_v3_native_main_root_message(
    root: &crate::binding_root_v2::BindingRootV2,
) -> [u8; 64] {
    native_commitment_message(SEMANTIC_V3_NATIVE_MAIN_ROLE, 0, &root.digest())
}

pub fn semantic_v3_native_interaction_root_message(
    root: &crate::binding_root_v2::BindingRootV2,
) -> [u8; 64] {
    native_commitment_message(SEMANTIC_V3_NATIVE_INTERACTION_ROLE, 0, &root.digest())
}

pub fn semantic_v3_native_composition_root_message(
    root: &crate::binding_root_v2::BindingRootV2,
) -> [u8; 64] {
    native_commitment_message(SEMANTIC_V3_NATIVE_COMPOSITION_ROLE, 0, &root.digest())
}

/// First continuation message: independent transcript bindings for the full
/// native DEEP-claims digest and native mask root.
pub fn semantic_v3_native_batch_message(
    claims: &crate::binding_root_v2::BindingDigestV2,
    mask_root: &crate::binding_root_v2::BindingRootV2,
) -> [u8; 128] {
    let claims = native_commitment_message(SEMANTIC_V3_NATIVE_CLAIMS_ROLE, 0, claims);
    let mask = native_commitment_message(SEMANTIC_V3_NATIVE_MASK_ROLE, 0, &mask_root.digest());
    let mut message = [0_u8; 128];
    message[..64].copy_from_slice(&claims);
    message[64..].copy_from_slice(&mask);
    message
}

pub fn semantic_v3_native_fri_layer_message(
    ordinal: usize,
    root: &crate::binding_root_v2::BindingRootV2,
) -> Result<[u8; 64], SemanticV3PublicCoinError> {
    Ok(native_commitment_message(
        SEMANTIC_V3_NATIVE_FRI_LAYER_ROLE,
        u32::try_from(ordinal).map_err(|_| SemanticV3PublicCoinError::Shape)?,
        &root.digest(),
    ))
}

/// Transcript message sampled before the first FRI fold. It binds the full
/// native oracle/claims/mask commitment set and the already-sampled batch
/// coefficient, so no legacy batch-derivation digest can authorize v3.
#[allow(clippy::too_many_arguments)]
pub fn semantic_v3_native_batch_derivation_message(
    main_root: &crate::binding_root_v2::BindingRootV2,
    interaction_root: &crate::binding_root_v2::BindingRootV2,
    composition_root: &crate::binding_root_v2::BindingRootV2,
    claims: &crate::binding_root_v2::BindingDigestV2,
    mask_root: &crate::binding_root_v2::BindingRootV2,
    batch_coefficient: Fp16,
) -> [u8; 64] {
    let coefficient = batch_coefficient.encode();
    hash(
        SEMANTIC_V3_NATIVE_BATCH_DERIVATION_MESSAGE_DOMAIN,
        &[
            main_root.as_bytes(),
            interaction_root.as_bytes(),
            composition_root.as_bytes(),
            claims.as_bytes(),
            mask_root.as_bytes(),
            &coefficient,
        ],
    )
}
pub const SEMANTIC_V3_PARENT_ANCHOR_COMMAND: &str = "V3_PARENT_ANCHOR";
pub const SEMANTIC_V3_PARENT_ANCHOR_FIELD_COUNT: usize = 14;
pub const SEMANTIC_V3_PARENT_ANCHOR_BINARY_MAGIC: &[u8; 8] = b"BLV3PAF1";
pub const SEMANTIC_V3_PARENT_ANCHOR_BINARY_VERSION: u16 = 1;
pub const SEMANTIC_V3_PARENT_ANCHOR_BINARY_BYTES: usize =
    8 + 2 + 2 + SEMANTIC_V3_PARENT_ANCHOR_FIELD_COUNT * 64;
pub const SEMANTIC_V3_CONTEXT_MAGIC: &[u8; 8] = b"BLV3CX01";
pub const SEMANTIC_V3_CONTEXT_VERSION: u16 = 1;
pub const SEMANTIC_V3_CONTEXT_BYTES: usize = 8 + 2 + 2 + 1 + 7 + 5 * 64 + 2 + 1 + 1 + 4;

const MAX_ARTIFACT_BYTES: usize = 16 << 20;
const MAX_CONTRIBUTORS: usize = 16;
const MAX_SIGNATURE_BYTES: usize = 64 << 10;
const ML_DSA_PUBLIC_KEY_BYTES: usize = 2_592;
const ML_DSA_SIGNATURE_BYTES: usize = 4_627;
const SLH_DSA_PUBLIC_KEY_BYTES: usize = 64;
const SLH_DSA_SIGNATURE_BYTES: usize = 49_856;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
enum SignatureSuite {
    MlDsa87 = 1,
    SlhDsaShake256f = 2,
}

impl SignatureSuite {
    fn decode(value: u16) -> Result<Self, SemanticV3PublicCoinError> {
        match value {
            1 => Ok(Self::MlDsa87),
            2 => Ok(Self::SlhDsaShake256f),
            _ => Err(SemanticV3PublicCoinError::Suite),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Contributor {
    contributor_id: [u8; 64],
    key_id: [u8; 64],
    suite: SignatureSuite,
    public_key: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Envelope {
    contributor_id: [u8; 64],
    payload: [u8; 64],
    signature: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Round {
    descriptor: [u8; 8],
    prover_message: Vec<u8>,
    commitments: Vec<Envelope>,
    reveals: Vec<Envelope>,
    resulting_root: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemanticV3Geometry {
    pub fold_round_count: u16,
    pub query_domain_log_size: u8,
    pub log_blowup: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemanticV3GovernedContext {
    pub profile: Profile,
    pub semantic_program_commitment: [u8; 64],
    pub parameter_commitment: [u8; 64],
    pub statement_commitment: [u8; 64],
    pub composite_parent_schedule_commitment: [u8; 64],
    pub contributor_set_commitment: [u8; 64],
    pub geometry: SemanticV3Geometry,
}

impl SemanticV3GovernedContext {
    /// Encode the complete verifier-owned semantic context.  This is a
    /// transport record only: decoding it does not mint a receipt, and the
    /// strict schedule is still recomputed by the native verifier.
    pub fn encode(&self) -> Result<Vec<u8>, SemanticV3PublicCoinError> {
        if !matches!(
            self.profile,
            Profile::K128Calibration | Profile::K512Calibration
        ) || self.geometry.fold_round_count == 0
            || self.geometry.query_domain_log_size == 0
            || self.geometry.query_domain_log_size > 30
            || self.geometry.log_blowup == 0
            || [
                self.semantic_program_commitment,
                self.parameter_commitment,
                self.statement_commitment,
                self.composite_parent_schedule_commitment,
                self.contributor_set_commitment,
            ]
            .iter()
            .any(|value| !nonzero(value))
        {
            return Err(SemanticV3PublicCoinError::Context);
        }
        let mut encoded = Vec::with_capacity(SEMANTIC_V3_CONTEXT_BYTES);
        encoded.extend_from_slice(SEMANTIC_V3_CONTEXT_MAGIC);
        encoded.extend_from_slice(&SEMANTIC_V3_CONTEXT_VERSION.to_be_bytes());
        encoded.extend_from_slice(&0_u16.to_be_bytes());
        encoded.push(self.profile as u8);
        encoded.extend_from_slice(&[0_u8; 7]);
        for value in [
            self.semantic_program_commitment,
            self.parameter_commitment,
            self.statement_commitment,
            self.composite_parent_schedule_commitment,
            self.contributor_set_commitment,
        ] {
            encoded.extend_from_slice(&value);
        }
        encoded.extend_from_slice(&self.geometry.fold_round_count.to_be_bytes());
        encoded.push(self.geometry.query_domain_log_size);
        encoded.push(self.geometry.log_blowup);
        encoded.extend_from_slice(&[0_u8; 4]);
        debug_assert_eq!(encoded.len(), SEMANTIC_V3_CONTEXT_BYTES);
        Ok(encoded)
    }

    /// Decode a bounded semantic context without treating any serialized
    /// field as an accepting result.  Native verification recomputes all
    /// schedule and component bindings after this transport step.
    pub fn decode(encoded: &[u8]) -> Result<Self, SemanticV3PublicCoinError> {
        if encoded.len() != SEMANTIC_V3_CONTEXT_BYTES
            || encoded.get(..8) != Some(SEMANTIC_V3_CONTEXT_MAGIC)
            || encoded.get(8..10) != Some(&SEMANTIC_V3_CONTEXT_VERSION.to_be_bytes())
            || encoded.get(10..12) != Some(&[0_u8; 2])
            || encoded
                .get(13..20)
                .is_none_or(|value| value.iter().any(|byte| *byte != 0))
        {
            return Err(SemanticV3PublicCoinError::EncodingLength);
        }
        let profile = match encoded[12] {
            1 => Profile::K128Calibration,
            3 => Profile::K512Calibration,
            _ => return Err(SemanticV3PublicCoinError::Profile),
        };
        let mut fields = [[0_u8; 64]; 5];
        for (index, field) in fields.iter_mut().enumerate() {
            let start = 20 + index * 64;
            field.copy_from_slice(
                encoded
                    .get(start..start + 64)
                    .ok_or(SemanticV3PublicCoinError::Truncated)?,
            );
        }
        let fold_round_count = u16::from_be_bytes(
            encoded[340..342]
                .try_into()
                .map_err(|_| SemanticV3PublicCoinError::Truncated)?,
        );
        let geometry = SemanticV3Geometry {
            fold_round_count,
            query_domain_log_size: encoded[342],
            log_blowup: encoded[343],
        };
        if encoded[344..348].iter().any(|byte| *byte != 0)
            || geometry.fold_round_count == 0
            || geometry.query_domain_log_size == 0
            || geometry.query_domain_log_size > 30
            || geometry.log_blowup == 0
            || fields.iter().any(|value| !nonzero(value))
        {
            return Err(SemanticV3PublicCoinError::Context);
        }
        Ok(Self {
            profile,
            semantic_program_commitment: fields[0],
            parameter_commitment: fields[1],
            statement_commitment: fields[2],
            composite_parent_schedule_commitment: fields[3],
            contributor_set_commitment: fields[4],
            geometry,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemanticV3DirectQuotientEvaluations {
    pub message_at_z: Fp16,
    pub message_at_conjugate: Fp16,
    pub digest_at_z: Fp16,
    pub digest_at_conjugate: Fp16,
}

/// Opaque authority produced only by `verify_semantic_v3_prefix`.
#[derive(Clone, Debug)]
pub struct VerifiedSemanticV3Prefix {
    semantic_session_id: [u8; 64],
    semantic_schedule_commitment: [u8; 64],
    contributor_set_commitment: [u8; 64],
    round_1_transcript_root: [u8; 64],
    main_trace_root: [u8; 64],
    interaction_trace_root: [u8; 64],
    logup_beta: Fp16,
    logup_gamma: Fp16,
    composition_alpha: Fp16,
    profile: Profile,
    semantic_program_commitment: [u8; 64],
    parameter_commitment: [u8; 64],
    statement_commitment: [u8; 64],
    receipt_commitment: [u8; 64],
    contributors: Vec<Contributor>,
}

/// Opaque matched context produced only by the composite-parent verifier.
#[derive(Clone, Debug)]
struct VerifiedSemanticContinuationAnchorInputs {
    parent_session_id: [u8; 64],
    parent_round_901_transcript_root: [u8; 64],
    semantic_session_id: [u8; 64],
    semantic_schedule_commitment: [u8; 64],
    contributor_set_commitment: [u8; 64],
    round_1_transcript_root: [u8; 64],
    composition_root: [u8; 64],
    z: CirclePoint,
    bridge_program_commitment: [u8; 64],
    answer_aggregate_root: [u8; 64],
    message_direct_q_commitment: [u8; 64],
    digest_direct_q_commitment: [u8; 64],
    direct_q_evaluations: SemanticV3DirectQuotientEvaluations,
    continuation_initial_root: [u8; 64],
    contributors: Vec<Contributor>,
}

/// Caller-shaped producer guidance for the v3 worker.
///
/// This frame is not verifier authority.  The verifier independently derives
/// `VerifiedSemanticContinuationAnchorInputs` from the signed parent and then
/// byte-compares this complete frame before replaying the continuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemanticV3ParentAnchorFrame {
    parent_session_id: [u8; 64],
    parent_round_901_transcript_root: [u8; 64],
    semantic_session_id: [u8; 64],
    semantic_schedule_commitment: [u8; 64],
    contributor_set_commitment: [u8; 64],
    semantic_round_1_transcript_root: [u8; 64],
    composition_root: [u8; 64],
    z: CirclePoint,
    bridge_program_commitment: [u8; 64],
    answer_aggregate_root: [u8; 64],
    message_direct_q_commitment: [u8; 64],
    digest_direct_q_commitment: [u8; 64],
    continuation_initial_root: [u8; 64],
}

#[derive(Clone, Debug)]
pub struct VerifiedSemanticV3Continuation {
    final_transcript_root: [u8; 64],
    fri_batch_coefficient: Fp16,
    fri_fold_coefficients: Vec<Fp16>,
    query_seed: [u8; 64],
    direct_q_evaluations: SemanticV3DirectQuotientEvaluations,
}

impl VerifiedSemanticV3Continuation {
    pub const fn final_transcript_root(&self) -> &[u8; 64] {
        &self.final_transcript_root
    }

    pub const fn fri_batch_coefficient(&self) -> Fp16 {
        self.fri_batch_coefficient
    }

    pub fn fri_fold_coefficients(&self) -> &[Fp16] {
        &self.fri_fold_coefficients
    }

    pub const fn query_seed(&self) -> &[u8; 64] {
        &self.query_seed
    }

    pub const fn direct_q_evaluations(&self) -> SemanticV3DirectQuotientEvaluations {
        self.direct_q_evaluations
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SemanticV3PublicCoinError {
    EncodingLength,
    Truncated,
    Trailing,
    Magic,
    Version,
    Reserved,
    Shape,
    Profile,
    Suite,
    Contributor,
    PublicKeyLength,
    SignatureLength,
    SignatureEncoding,
    SignatureInvalid,
    Descriptor,
    Message,
    Commitment,
    Challenge,
    Root,
    Context,
    ParentAnchorEncoding,
    ParentAnchorCircle,
    ParentAnchorMismatch,
    Field(DecodeError),
    QuotientEvaluation,
    StrictPq(StrictPqPublicCoinV2Error),
    Parameters(ProofParameterError),
}

impl From<DecodeError> for SemanticV3PublicCoinError {
    fn from(value: DecodeError) -> Self {
        Self::Field(value)
    }
}

impl From<StrictPqPublicCoinV2Error> for SemanticV3PublicCoinError {
    fn from(value: StrictPqPublicCoinV2Error) -> Self {
        Self::StrictPq(value)
    }
}

impl From<ProofParameterError> for SemanticV3PublicCoinError {
    fn from(value: ProofParameterError) -> Self {
        Self::Parameters(value)
    }
}

impl fmt::Display for SemanticV3PublicCoinError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "BL-PQ512 semantic-v3 public coin error: {self:?}"
        )
    }
}

impl core::error::Error for SemanticV3PublicCoinError {}

fn nonzero(value: &[u8; 64]) -> bool {
    value.iter().any(|byte| *byte != 0)
}

fn hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut digest = Sha3_512::new();
    digest.update(domain);
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    digest.finalize().into()
}

fn lower_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn decode_lower_hex_digest(encoded: &str) -> Result<[u8; 64], SemanticV3PublicCoinError> {
    if encoded.len() != 128 || !encoded.is_ascii() {
        return Err(SemanticV3PublicCoinError::ParentAnchorEncoding);
    }
    let mut output = [0_u8; 64];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let high =
            lower_hex_nibble(pair[0]).ok_or(SemanticV3PublicCoinError::ParentAnchorEncoding)?;
        let low =
            lower_hex_nibble(pair[1]).ok_or(SemanticV3PublicCoinError::ParentAnchorEncoding)?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
fn semantic_v3_continuation_initial_root(
    parent_session_id: &[u8; 64],
    parent_round_901_transcript_root: &[u8; 64],
    semantic_session_id: &[u8; 64],
    semantic_schedule_commitment: &[u8; 64],
    contributor_set_commitment: &[u8; 64],
    semantic_round_1_transcript_root: &[u8; 64],
    composition_root: &[u8; 64],
    z: CirclePoint,
    bridge_program_commitment: &[u8; 64],
    answer_aggregate_root: &[u8; 64],
    message_direct_q_commitment: &[u8; 64],
    digest_direct_q_commitment: &[u8; 64],
) -> [u8; 64] {
    let version = 3_u16.to_be_bytes();
    hash(
        SEMANTIC_V3_CONTINUATION_ANCHOR_DOMAIN,
        &[
            &version,
            parent_session_id,
            parent_round_901_transcript_root,
            semantic_session_id,
            semantic_schedule_commitment,
            contributor_set_commitment,
            semantic_round_1_transcript_root,
            composition_root,
            &z.x.encode(),
            &z.y.encode(),
            bridge_program_commitment,
            answer_aggregate_root,
            message_direct_q_commitment,
            digest_direct_q_commitment,
        ],
    )
}

impl SemanticV3ParentAnchorFrame {
    fn from_fields(
        fields: [[u8; 64]; SEMANTIC_V3_PARENT_ANCHOR_FIELD_COUNT],
    ) -> Result<Self, SemanticV3PublicCoinError> {
        let z = CirclePoint {
            x: Fp16::decode(&fields[7])?,
            y: Fp16::decode(&fields[8])?,
        };
        if z.x.square() + z.y.square() != Fp16::ONE {
            return Err(SemanticV3PublicCoinError::ParentAnchorCircle);
        }
        if fields[..7]
            .iter()
            .chain(fields[9..].iter())
            .any(|value| !nonzero(value))
        {
            return Err(SemanticV3PublicCoinError::Context);
        }
        let frame = Self {
            parent_session_id: fields[0],
            parent_round_901_transcript_root: fields[1],
            semantic_session_id: fields[2],
            semantic_schedule_commitment: fields[3],
            contributor_set_commitment: fields[4],
            semantic_round_1_transcript_root: fields[5],
            composition_root: fields[6],
            z,
            bridge_program_commitment: fields[9],
            answer_aggregate_root: fields[10],
            message_direct_q_commitment: fields[11],
            digest_direct_q_commitment: fields[12],
            continuation_initial_root: fields[13],
        };
        if frame.continuation_initial_root
            != semantic_v3_continuation_initial_root(
                &frame.parent_session_id,
                &frame.parent_round_901_transcript_root,
                &frame.semantic_session_id,
                &frame.semantic_schedule_commitment,
                &frame.contributor_set_commitment,
                &frame.semantic_round_1_transcript_root,
                &frame.composition_root,
                frame.z,
                &frame.bridge_program_commitment,
                &frame.answer_aggregate_root,
                &frame.message_direct_q_commitment,
                &frame.digest_direct_q_commitment,
            )
        {
            return Err(SemanticV3PublicCoinError::ParentAnchorMismatch);
        }
        Ok(frame)
    }

    /// Decode exactly fourteen lowercase 128-hex-character fields following
    /// `V3_PARENT_ANCHOR`.
    pub fn decode_command_tokens(tokens: &[&str]) -> Result<Self, SemanticV3PublicCoinError> {
        if tokens.len() != SEMANTIC_V3_PARENT_ANCHOR_FIELD_COUNT {
            return Err(SemanticV3PublicCoinError::ParentAnchorEncoding);
        }
        let fields = tokens
            .iter()
            .map(|value| decode_lower_hex_digest(value))
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_fields(
            fields
                .try_into()
                .map_err(|_| SemanticV3PublicCoinError::ParentAnchorEncoding)?,
        )
    }

    /// Encode the complete anchor frame, including the derived continuation
    /// root. This is producer transport only; decoding rechecks the circle,
    /// nonzero context, and derived-root equation before any continuation is
    /// replayed.
    pub fn encode(&self) -> Vec<u8> {
        let fields = self.encoded_fields();
        let mut encoded = Vec::with_capacity(SEMANTIC_V3_PARENT_ANCHOR_BINARY_BYTES);
        encoded.extend_from_slice(SEMANTIC_V3_PARENT_ANCHOR_BINARY_MAGIC);
        encoded.extend_from_slice(&SEMANTIC_V3_PARENT_ANCHOR_BINARY_VERSION.to_be_bytes());
        encoded.extend_from_slice(&[0_u8; 2]);
        for field in fields {
            encoded.extend_from_slice(&field);
        }
        encoded
    }

    /// Decode the canonical binary anchor frame and re-run all anchor
    /// consistency checks. No opaque continuation receipt is created here.
    pub fn decode(encoded: &[u8]) -> Result<Self, SemanticV3PublicCoinError> {
        if encoded.len() != SEMANTIC_V3_PARENT_ANCHOR_BINARY_BYTES
            || encoded.get(..8) != Some(SEMANTIC_V3_PARENT_ANCHOR_BINARY_MAGIC)
            || encoded.get(8..10) != Some(&SEMANTIC_V3_PARENT_ANCHOR_BINARY_VERSION.to_be_bytes())
            || encoded.get(10..12) != Some(&[0_u8; 2])
        {
            return Err(SemanticV3PublicCoinError::ParentAnchorEncoding);
        }
        let mut fields = [[0_u8; 64]; SEMANTIC_V3_PARENT_ANCHOR_FIELD_COUNT];
        for (index, field) in fields.iter_mut().enumerate() {
            let start = 12 + index * 64;
            field.copy_from_slice(
                encoded
                    .get(start..start + 64)
                    .ok_or(SemanticV3PublicCoinError::ParentAnchorEncoding)?,
            );
        }
        Self::from_fields(fields)
    }

    pub fn oods_point(&self) -> CirclePoint {
        self.z
    }

    pub fn encoded_fields(&self) -> [[u8; 64]; SEMANTIC_V3_PARENT_ANCHOR_FIELD_COUNT] {
        [
            self.parent_session_id,
            self.parent_round_901_transcript_root,
            self.semantic_session_id,
            self.semantic_schedule_commitment,
            self.contributor_set_commitment,
            self.semantic_round_1_transcript_root,
            self.composition_root,
            self.z.x.encode(),
            self.z.y.encode(),
            self.bridge_program_commitment,
            self.answer_aggregate_root,
            self.message_direct_q_commitment,
            self.digest_direct_q_commitment,
            self.continuation_initial_root,
        ]
    }

    pub fn commitment(&self) -> [u8; 64] {
        let fields = self.encoded_fields();
        let mut parts = Vec::with_capacity(fields.len() + 1);
        parts.push(SEMANTIC_V3_PARENT_ANCHOR_COMMAND.as_bytes());
        parts.extend(fields.iter().map(|value| value.as_slice()));
        hash(SEMANTIC_V3_PARENT_ANCHOR_FRAME_COMMITMENT_DOMAIN, &parts)
    }
}

fn descriptor(kind: u16, ordinal: u16, output_kind: u16, output_count: u16) -> [u8; 8] {
    let mut result = [0_u8; 8];
    result[..2].copy_from_slice(&kind.to_be_bytes());
    result[2..4].copy_from_slice(&ordinal.to_be_bytes());
    result[4..6].copy_from_slice(&output_kind.to_be_bytes());
    result[6..].copy_from_slice(&output_count.to_be_bytes());
    result
}

pub(crate) fn semantic_v3_descriptors(geometry: SemanticV3Geometry) -> Vec<[u8; 8]> {
    let mut result = Vec::with_capacity(usize::from(geometry.fold_round_count) + 5);
    result.push(descriptor(1, 0, SEMANTIC_V3_FIELD16_OUTPUT_KIND, 2));
    result.push(descriptor(2, 0, SEMANTIC_V3_FIELD16_OUTPUT_KIND, 1));
    result.push(descriptor(4, 0, SEMANTIC_V3_FIELD16_OUTPUT_KIND, 1));
    for ordinal in 0..geometry.fold_round_count {
        result.push(descriptor(5, ordinal, SEMANTIC_V3_FIELD16_OUTPUT_KIND, 1));
    }
    result.push(descriptor(6, 0, SEMANTIC_V3_QUERY_SEED_OUTPUT_KIND, 1));
    result
}

/// Strict-PQ global schedule for the native-128 selected path. The legacy
/// kind-local descriptor above is retained only for non-authoritative v1
/// provenance; acceptance uses these global u32 ordinals exclusively.
pub fn semantic_v3_strict_descriptors(
    geometry: SemanticV3Geometry,
) -> Result<Vec<StrictPqRoundDescriptorV2>, SemanticV3PublicCoinError> {
    if geometry.fold_round_count == 0
        || geometry.query_domain_log_size == 0
        || geometry.query_domain_log_size > 30
    {
        return Err(SemanticV3PublicCoinError::Context);
    }
    let mut kinds_and_counts = Vec::with_capacity(usize::from(geometry.fold_round_count) + 7);
    kinds_and_counts.extend([
        (1_u16, 2_u16),
        (2, 1),
        (COMPOSITE_PARENT_PRE_ALPHA_KIND, 1),
        (COMPOSITE_PARENT_QUOTIENT_KIND, 1),
        (4, 1),
    ]);
    kinds_and_counts.extend((0..geometry.fold_round_count).map(|_| (5_u16, 1_u16)));
    kinds_and_counts.push((6, 1));
    kinds_and_counts.push((COMPOSITE_PARENT_FINAL_KIND, 1));
    kinds_and_counts
        .into_iter()
        .enumerate()
        .map(|(ordinal, (kind, output_count))| {
            Ok(StrictPqRoundDescriptorV2::new(
                kind,
                u32::try_from(ordinal).map_err(|_| SemanticV3PublicCoinError::Shape)?,
                output_count,
            )?)
        })
        .collect()
}

/// Exact selected-v3 kind-to-policy mapping. FRI folds and the query seed are
/// uniform; every challenge consumed by a denominator or required nonzero by
/// the AIR/parent verifier is sampled nonzero; kind 901 alone samples OODS.
pub fn semantic_v3_strict_policies(
    geometry: SemanticV3Geometry,
) -> Result<Vec<StrictPqFp16PolicyV2>, SemanticV3PublicCoinError> {
    let descriptors = semantic_v3_strict_descriptors(geometry)?;
    descriptors
        .iter()
        .map(|descriptor| match descriptor.kind() {
            1 | 2 | COMPOSITE_PARENT_PRE_ALPHA_KIND | COMPOSITE_PARENT_FINAL_KIND | 4 => {
                Ok(StrictPqFp16PolicyV2::Nonzero)
            }
            COMPOSITE_PARENT_QUOTIENT_KIND => Ok(StrictPqFp16PolicyV2::OodsOutsideFp8),
            5 | 6 => Ok(StrictPqFp16PolicyV2::Uniform),
            _ => Err(SemanticV3PublicCoinError::Descriptor),
        })
        .collect()
}

fn strict_profile(profile: Profile) -> Result<StrictPqH4ProfileV2, SemanticV3PublicCoinError> {
    match profile {
        Profile::K128Calibration => Ok(StrictPqH4ProfileV2::K128),
        Profile::K512Calibration => Ok(StrictPqH4ProfileV2::K512),
        _ => Err(SemanticV3PublicCoinError::Profile),
    }
}

/// Schedule identity for the strict native path. It binds the full global
/// descriptor/policy sequence and the exact governed semantic/parent context.
pub fn semantic_v3_strict_schedule_commitment(
    context: &SemanticV3GovernedContext,
) -> Result<[u8; 64], SemanticV3PublicCoinError> {
    let descriptors = semantic_v3_strict_descriptors(context.geometry)?;
    let policies = semantic_v3_strict_policies(context.geometry)?;
    if [
        context.semantic_program_commitment,
        context.parameter_commitment,
        context.statement_commitment,
        context.composite_parent_schedule_commitment,
        context.contributor_set_commitment,
    ]
    .iter()
    .any(|value| !nonzero(value))
    {
        return Err(SemanticV3PublicCoinError::Context);
    }
    let version = 2_u16.to_be_bytes();
    let profile = [strict_profile(context.profile)?.code()];
    let geometry = [
        context.geometry.query_domain_log_size,
        context.geometry.log_blowup,
    ];
    let folds = context.geometry.fold_round_count.to_be_bytes();
    let queries = SEMANTIC_V3_QUERY_COUNT.to_be_bytes();
    let mut descriptor_bytes = Vec::with_capacity(descriptors.len() * 8);
    for descriptor in &descriptors {
        descriptor_bytes.extend_from_slice(&descriptor.encode());
    }
    let policy_bytes = policies
        .iter()
        .map(|policy| policy.code())
        .collect::<Vec<_>>();
    Ok(hash(
        SEMANTIC_V3_STRICT_SCHEDULE_DOMAIN,
        &[
            &version,
            SEMANTIC_V3_TOPOLOGY_TAG,
            &profile,
            &context.semantic_program_commitment,
            &context.parameter_commitment,
            &context.statement_commitment,
            &context.composite_parent_schedule_commitment,
            &context.contributor_set_commitment,
            &geometry,
            &folds,
            &queries,
            &descriptor_bytes,
            &policy_bytes,
        ],
    ))
}

/// Opaque challenge authority returned only after strict-PQ replay.
#[derive(Clone, Debug)]
pub struct VerifiedStrictSemanticV3PublicCoin {
    profile: Profile,
    pre_final_transcript_root: [u8; 128],
    final_transcript_root: [u8; 128],
    logup_beta: Fp16,
    logup_gamma: Fp16,
    composition_alpha: Fp16,
    bridge_alpha: Fp16,
    oods_point: CirclePoint,
    completion_challenge: Fp16,
    fri_batch_coefficient: Fp16,
    fri_fold_coefficients: Vec<Fp16>,
    query_seed: [u8; 64],
    query_positions: Vec<usize>,
    round_message_bindings: Vec<crate::binding_root_v2::BindingDigestV2>,
}

impl VerifiedStrictSemanticV3PublicCoin {
    pub const fn profile(&self) -> Profile {
        self.profile
    }
    pub const fn final_transcript_root(&self) -> &[u8; 128] {
        &self.final_transcript_root
    }

    /// Strict transcript checkpoint after the query round and before parent
    /// round 902. Post-Z work binds this checkpoint so the 902 message can be
    /// derived from completed component receipts without a transcript
    /// self-reference. The final root remains the aggregate receipt identity.
    pub const fn pre_final_transcript_root(&self) -> &[u8; 128] {
        &self.pre_final_transcript_root
    }

    pub const fn logup_challenges(&self) -> (Fp16, Fp16) {
        (self.logup_beta, self.logup_gamma)
    }

    pub const fn composition_alpha(&self) -> Fp16 {
        self.composition_alpha
    }

    pub const fn bridge_alpha(&self) -> Fp16 {
        self.bridge_alpha
    }

    pub const fn oods_point(&self) -> CirclePoint {
        self.oods_point
    }

    pub const fn completion_challenge(&self) -> Fp16 {
        self.completion_challenge
    }

    pub const fn fri_batch_coefficient(&self) -> Fp16 {
        self.fri_batch_coefficient
    }

    pub fn fri_fold_coefficients(&self) -> &[Fp16] {
        &self.fri_fold_coefficients
    }

    pub const fn query_seed(&self) -> &[u8; 64] {
        &self.query_seed
    }

    pub fn query_positions(&self) -> &[usize] {
        &self.query_positions
    }

    pub fn round_message_binding(
        &self,
        ordinal: usize,
    ) -> Option<crate::binding_root_v2::BindingDigestV2> {
        self.round_message_bindings.get(ordinal).copied()
    }
}

pub(crate) fn strict_message_binding(
    ordinal: usize,
    message: &[u8],
) -> Result<crate::binding_root_v2::BindingDigestV2, SemanticV3PublicCoinError> {
    let mut encoded = SEMANTIC_V3_STRICT_MESSAGE_BINDING_DOMAIN.to_vec();
    encoded.extend_from_slice(
        &u32::try_from(ordinal)
            .map_err(|_| SemanticV3PublicCoinError::Shape)?
            .to_be_bytes(),
    );
    encoded.extend_from_slice(
        &u64::try_from(message.len())
            .map_err(|_| SemanticV3PublicCoinError::Shape)?
            .to_be_bytes(),
    );
    encoded.extend_from_slice(message);
    crate::binding_root_v2::BindingDigestV2::hash(
        crate::binding_root_v2::BindingRoleV2::Payload,
        &encoded,
    )
    .map_err(|_| SemanticV3PublicCoinError::Challenge)
}

fn strict_output_elements(
    output: &crate::strict_pq_public_coin_v2::StrictPqFp16RoundOutputV2,
    expected: usize,
) -> Result<Vec<Fp16>, SemanticV3PublicCoinError> {
    let samples = output.challenges().samples();
    if samples.len() != expected {
        return Err(SemanticV3PublicCoinError::Challenge);
    }
    Ok(samples.iter().map(|sample| sample.element()).collect())
}

/// Replay the sole authoritative selected-v3 public coin. The raw prover
/// messages are supplied by the package verifier after it reconstructs every
/// prefix, parent, and continuation message from typed package fields.
pub fn verify_strict_semantic_v3_public_coin<M: AsRef<[u8]>>(
    encoded_bundle: &[u8],
    governed_key: &StrictPqGovernedVerifierKeyV2,
    raw_prover_messages: &[M],
    context: &SemanticV3GovernedContext,
    registry: &mut StrictPqRootUseRegistryV2,
) -> Result<VerifiedStrictSemanticV3PublicCoin, SemanticV3PublicCoinError> {
    let descriptors = semantic_v3_strict_descriptors(context.geometry)?;
    let policies = semantic_v3_strict_policies(context.geometry)?;
    let expected_schedule = semantic_v3_strict_schedule_commitment(context)?;
    if governed_key.schedule_commitment() != &expected_schedule
        || usize::try_from(governed_key.round_count()).ok() != Some(descriptors.len())
        || raw_prover_messages.len() != descriptors.len()
    {
        return Err(SemanticV3PublicCoinError::Context);
    }
    let bundle = StrictPqPublicCoinBundleV2::decode(encoded_bundle)?;
    if bundle.rounds().len() != descriptors.len()
        || bundle
            .rounds()
            .iter()
            .zip(&descriptors)
            .any(|(round, expected)| round.descriptor() != *expected)
    {
        return Err(SemanticV3PublicCoinError::Descriptor);
    }
    let outputs = replay_strict_pq_fp16_public_coin_v2(
        governed_key,
        &bundle,
        strict_profile(context.profile)?,
        &policies,
        raw_prover_messages,
        registry,
    )?;
    if outputs.len() != descriptors.len() {
        return Err(SemanticV3PublicCoinError::Shape);
    }
    let prefix_0 = strict_output_elements(&outputs[0], 2)?;
    let prefix_1 = strict_output_elements(&outputs[1], 1)?;
    let parent_900 = strict_output_elements(&outputs[2], 1)?;
    let parent_901 = strict_output_elements(&outputs[3], 1)?;
    let continuation_batch = strict_output_elements(&outputs[4], 1)?;
    let fold_start = 5_usize;
    let fold_end = fold_start
        .checked_add(usize::from(context.geometry.fold_round_count))
        .ok_or(SemanticV3PublicCoinError::Shape)?;
    let fri_fold_coefficients = outputs
        .get(fold_start..fold_end)
        .ok_or(SemanticV3PublicCoinError::Shape)?
        .iter()
        .map(|output| strict_output_elements(output, 1).map(|elements| elements[0]))
        .collect::<Result<Vec<_>, _>>()?;
    let query_output = outputs
        .get(fold_end)
        .ok_or(SemanticV3PublicCoinError::Shape)?;
    let query = strict_output_elements(query_output, 1)?;
    let parent_902 = strict_output_elements(
        outputs
            .get(fold_end + 1)
            .ok_or(SemanticV3PublicCoinError::Shape)?,
        1,
    )?;
    if fold_end + 2 != outputs.len() {
        return Err(SemanticV3PublicCoinError::Shape);
    }
    let query_seed = query[0].encode();
    let domain_size = 1_usize
        .checked_shl(u32::from(context.geometry.query_domain_log_size))
        .ok_or(SemanticV3PublicCoinError::Shape)?;
    let query_positions =
        selected_query_positions(governed_key.session_id(), &query_seed, domain_size)?;
    let round_message_bindings = raw_prover_messages
        .iter()
        .enumerate()
        .map(|(ordinal, message)| strict_message_binding(ordinal, message.as_ref()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(VerifiedStrictSemanticV3PublicCoin {
        profile: context.profile,
        pre_final_transcript_root: *query_output.transcript_root(),
        final_transcript_root: *bundle.final_transcript_root(),
        logup_beta: prefix_0[0],
        logup_gamma: prefix_0[1],
        composition_alpha: prefix_1[0],
        bridge_alpha: parent_900[0],
        oods_point: stereographic_circle_point(
            OodsParameter::try_from_element(parent_901[0])
                .map_err(|_| SemanticV3PublicCoinError::Challenge)?,
        )
        .map_err(|_| SemanticV3PublicCoinError::Challenge)?,
        completion_challenge: parent_902[0],
        fri_batch_coefficient: continuation_batch[0],
        fri_fold_coefficients,
        query_seed,
        query_positions,
        round_message_bindings,
    })
}

pub(crate) fn semantic_v3_schedule_commitment(
    context: &SemanticV3GovernedContext,
) -> Result<[u8; 64], SemanticV3PublicCoinError> {
    if !matches!(
        context.profile,
        Profile::K128Calibration | Profile::K512Calibration
    ) || context.geometry.fold_round_count == 0
        || context.geometry.query_domain_log_size == 0
        || [
            context.semantic_program_commitment,
            context.parameter_commitment,
            context.statement_commitment,
            context.composite_parent_schedule_commitment,
            context.contributor_set_commitment,
        ]
        .iter()
        .any(|value| !nonzero(value))
    {
        return Err(SemanticV3PublicCoinError::Context);
    }
    let version = 3_u16.to_be_bytes();
    let profile = [context.profile as u8];
    let geometry = [
        context.geometry.query_domain_log_size,
        context.geometry.log_blowup,
    ];
    let folds = context.geometry.fold_round_count.to_be_bytes();
    let queries = SEMANTIC_V3_QUERY_COUNT.to_be_bytes();
    let descriptors = semantic_v3_descriptors(context.geometry);
    let mut parts = vec![
        version.as_slice(),
        SEMANTIC_V3_TOPOLOGY_TAG,
        profile.as_slice(),
        context.semantic_program_commitment.as_slice(),
        context.parameter_commitment.as_slice(),
        context.statement_commitment.as_slice(),
        context.composite_parent_schedule_commitment.as_slice(),
        geometry.as_slice(),
        folds.as_slice(),
        queries.as_slice(),
    ];
    parts.push(descriptors[0].as_slice());
    parts.push(descriptors[1].as_slice());
    parts.push(SEMANTIC_V3_PARENT_ANCHOR_SEAM_TAG);
    parts.extend(descriptors[2..].iter().map(|value| value.as_slice()));
    Ok(hash(SEMANTIC_V3_SCHEDULE_DOMAIN, &parts))
}

struct Reader<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(encoded: &'a [u8]) -> Result<Self, SemanticV3PublicCoinError> {
        if encoded.len() < 10 || encoded.len() > MAX_ARTIFACT_BYTES {
            return Err(SemanticV3PublicCoinError::EncodingLength);
        }
        Ok(Self { encoded, offset: 0 })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], SemanticV3PublicCoinError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(SemanticV3PublicCoinError::Truncated)?;
        let value = self
            .encoded
            .get(self.offset..end)
            .ok_or(SemanticV3PublicCoinError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, SemanticV3PublicCoinError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, SemanticV3PublicCoinError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| SemanticV3PublicCoinError::Truncated)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, SemanticV3PublicCoinError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| SemanticV3PublicCoinError::Truncated)?,
        ))
    }

    fn digest(&mut self) -> Result<[u8; 64], SemanticV3PublicCoinError> {
        self.take(64)?
            .try_into()
            .map_err(|_| SemanticV3PublicCoinError::Truncated)
    }

    fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, SemanticV3PublicCoinError> {
        let length = usize::try_from(self.u32()?).map_err(|_| SemanticV3PublicCoinError::Shape)?;
        if length > maximum {
            return Err(SemanticV3PublicCoinError::Shape);
        }
        Ok(self.take(length)?.to_vec())
    }
}

fn decode_contributors(
    reader: &mut Reader<'_>,
) -> Result<Vec<Contributor>, SemanticV3PublicCoinError> {
    let count = usize::from(reader.u16()?);
    if !(2..=MAX_CONTRIBUTORS).contains(&count) {
        return Err(SemanticV3PublicCoinError::Contributor);
    }
    let mut contributors = Vec::with_capacity(count);
    for _ in 0..count {
        let contributor_id = reader.digest()?;
        let key_id = reader.digest()?;
        let suite = SignatureSuite::decode(reader.u16()?)?;
        let public_key = reader.bytes(MAX_SIGNATURE_BYTES)?;
        let expected_length = match suite {
            SignatureSuite::MlDsa87 => ML_DSA_PUBLIC_KEY_BYTES,
            SignatureSuite::SlhDsaShake256f => SLH_DSA_PUBLIC_KEY_BYTES,
        };
        if public_key.len() != expected_length || !nonzero(&contributor_id) || !nonzero(&key_id) {
            return Err(SemanticV3PublicCoinError::PublicKeyLength);
        }
        contributors.push(Contributor {
            contributor_id,
            key_id,
            suite,
            public_key,
        });
    }
    if contributors.windows(2).any(|pair| {
        pair[0].contributor_id >= pair[1].contributor_id || pair[0].key_id == pair[1].key_id
    }) || !contributors
        .iter()
        .any(|value| value.suite == SignatureSuite::MlDsa87)
        || !contributors
            .iter()
            .any(|value| value.suite == SignatureSuite::SlhDsaShake256f)
    {
        return Err(SemanticV3PublicCoinError::Contributor);
    }
    Ok(contributors)
}

fn contributor_set_commitment(contributors: &[Contributor]) -> [u8; 64] {
    let mut encodings = Vec::with_capacity(contributors.len());
    for contributor in contributors {
        let suite = (contributor.suite as u16).to_be_bytes();
        encodings.push(hash(
            SEMANTIC_V3_CONTRIBUTOR_SET_DOMAIN,
            &[
                &contributor.contributor_id,
                &contributor.key_id,
                &suite,
                &contributor.public_key,
            ],
        ));
    }
    let references = encodings
        .iter()
        .map(|value| value.as_slice())
        .collect::<Vec<_>>();
    hash(SEMANTIC_V3_CONTRIBUTOR_SET_DOMAIN, &references)
}

fn decode_envelope(reader: &mut Reader<'_>) -> Result<Envelope, SemanticV3PublicCoinError> {
    Ok(Envelope {
        contributor_id: reader.digest()?,
        payload: reader.digest()?,
        signature: reader.bytes(MAX_SIGNATURE_BYTES)?,
    })
}

fn decode_round(
    reader: &mut Reader<'_>,
    contributor_count: usize,
) -> Result<Round, SemanticV3PublicCoinError> {
    let descriptor = reader
        .take(8)?
        .try_into()
        .map_err(|_| SemanticV3PublicCoinError::Truncated)?;
    let prover_message = reader.bytes(256)?;
    if usize::from(reader.u16()?) != contributor_count {
        return Err(SemanticV3PublicCoinError::Shape);
    }
    let commitments = (0..contributor_count)
        .map(|_| decode_envelope(reader))
        .collect::<Result<Vec<_>, _>>()?;
    if usize::from(reader.u16()?) != contributor_count {
        return Err(SemanticV3PublicCoinError::Shape);
    }
    let reveals = (0..contributor_count)
        .map(|_| decode_envelope(reader))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Round {
        descriptor,
        prover_message,
        commitments,
        reveals,
        resulting_root: reader.digest()?,
    })
}

fn verify_signature(
    contributor: &Contributor,
    message: &[u8],
    signature: &[u8],
) -> Result<(), SemanticV3PublicCoinError> {
    match contributor.suite {
        SignatureSuite::MlDsa87 => {
            if signature.len() != ML_DSA_SIGNATURE_BYTES {
                return Err(SemanticV3PublicCoinError::SignatureLength);
            }
            let encoded =
                MlDsaEncodedVerifyingKey::<MlDsa87>::try_from(contributor.public_key.as_slice())
                    .map_err(|_| SemanticV3PublicCoinError::SignatureEncoding)?;
            let key = MlDsaVerifyingKey::<MlDsa87>::decode(&encoded);
            let signature = MlDsaSignature::<MlDsa87>::try_from(signature)
                .map_err(|_| SemanticV3PublicCoinError::SignatureEncoding)?;
            key.verify(message, &signature)
                .map_err(|_| SemanticV3PublicCoinError::SignatureInvalid)
        }
        SignatureSuite::SlhDsaShake256f => {
            if signature.len() != SLH_DSA_SIGNATURE_BYTES {
                return Err(SemanticV3PublicCoinError::SignatureLength);
            }
            let key = SlhDsaVerifyingKey::<Shake256f>::try_from(contributor.public_key.as_slice())
                .map_err(|_| SemanticV3PublicCoinError::SignatureEncoding)?;
            let signature = SlhDsaSignature::<Shake256f>::try_from(signature)
                .map_err(|_| SemanticV3PublicCoinError::SignatureEncoding)?;
            key.verify(message, &signature)
                .map_err(|_| SemanticV3PublicCoinError::SignatureInvalid)
        }
    }
}

fn round_signature_message(
    domain: &[u8],
    session: &[u8; 64],
    global_round: u32,
    descriptor: &[u8; 8],
    prior_root: &[u8; 64],
    prover_message: &[u8],
    contributor: &Contributor,
    payload: &[u8; 64],
) -> [u8; 64] {
    let round = global_round.to_be_bytes();
    let message_digest: [u8; 64] = Sha3_512::digest(prover_message).into();
    hash(
        domain,
        &[
            session,
            &round,
            descriptor,
            prior_root,
            &message_digest,
            &contributor.contributor_id,
            &contributor.key_id,
            payload,
        ],
    )
}

fn expected_commitment(
    session: &[u8; 64],
    global_round: u32,
    descriptor: &[u8; 8],
    prior_root: &[u8; 64],
    prover_message: &[u8],
    contributor_id: &[u8; 64],
    reveal: &[u8; 64],
) -> [u8; 64] {
    let round = global_round.to_be_bytes();
    let message_digest: [u8; 64] = Sha3_512::digest(prover_message).into();
    hash(
        SEMANTIC_V3_COMMITMENT_HASH_DOMAIN,
        &[
            session,
            &round,
            descriptor,
            prior_root,
            &message_digest,
            contributor_id,
            reveal,
        ],
    )
}

fn round_seed(
    session: &[u8; 64],
    global_round: u32,
    descriptor: &[u8; 8],
    prior_root: &[u8; 64],
    prover_message: &[u8],
    commitments: &[Envelope],
    reveals: &[Envelope],
) -> [u8; 64] {
    let round = global_round.to_be_bytes();
    let mut parts = vec![
        session.as_slice(),
        round.as_slice(),
        descriptor.as_slice(),
        prior_root.as_slice(),
        prover_message,
    ];
    for (commitment, reveal) in commitments.iter().zip(reveals) {
        parts.push(commitment.contributor_id.as_slice());
        parts.push(commitment.payload.as_slice());
        parts.push(reveal.payload.as_slice());
    }
    hash(SEMANTIC_V3_ROUND_SEED_DOMAIN, &parts)
}

fn audit_root(
    session: &[u8; 64],
    global_round: u32,
    descriptor: &[u8; 8],
    prior_root: &[u8; 64],
    prover_message: &[u8],
    seed: &[u8; 64],
    commitments: &[Envelope],
    reveals: &[Envelope],
    fields: &[Fp16],
) -> [u8; 64] {
    let round = global_round.to_be_bytes();
    let field_encodings = fields
        .iter()
        .map(|value| value.encode())
        .collect::<Vec<_>>();
    let mut parts = vec![
        session.as_slice(),
        round.as_slice(),
        descriptor.as_slice(),
        prior_root.as_slice(),
        prover_message,
        seed.as_slice(),
    ];
    for (commitment, reveal) in commitments.iter().zip(reveals) {
        parts.push(commitment.payload.as_slice());
        parts.push(commitment.signature.as_slice());
        parts.push(reveal.payload.as_slice());
        parts.push(reveal.signature.as_slice());
    }
    parts.extend(field_encodings.iter().map(|value| value.as_slice()));
    hash(SEMANTIC_V3_AUDIT_ROOT_DOMAIN, &parts)
}

fn verify_round(
    round: &Round,
    expected_descriptor: [u8; 8],
    expected_message_bytes: usize,
    session: &[u8; 64],
    global_round: u32,
    prior_root: &[u8; 64],
    contributors: &[Contributor],
    draw_count: usize,
) -> Result<([u8; 64], [u8; 64], Vec<Fp16>), SemanticV3PublicCoinError> {
    if round.descriptor != expected_descriptor
        || round.prover_message.len() != expected_message_bytes
        || round
            .prover_message
            .chunks_exact(64)
            .any(|value| !value.iter().any(|byte| *byte != 0))
        || round.commitments.len() != contributors.len()
        || round.reveals.len() != contributors.len()
    {
        return Err(SemanticV3PublicCoinError::Message);
    }
    for (index, contributor) in contributors.iter().enumerate() {
        let commitment = &round.commitments[index];
        let reveal = &round.reveals[index];
        if commitment.contributor_id != contributor.contributor_id
            || reveal.contributor_id != contributor.contributor_id
            || commitment.payload
                != expected_commitment(
                    session,
                    global_round,
                    &round.descriptor,
                    prior_root,
                    &round.prover_message,
                    &contributor.contributor_id,
                    &reveal.payload,
                )
        {
            return Err(SemanticV3PublicCoinError::Commitment);
        }
        let commitment_message = round_signature_message(
            SEMANTIC_V3_COMMITMENT_SIGNATURE_DOMAIN,
            session,
            global_round,
            &round.descriptor,
            prior_root,
            &round.prover_message,
            contributor,
            &commitment.payload,
        );
        verify_signature(contributor, &commitment_message, &commitment.signature)?;
        let reveal_message = round_signature_message(
            SEMANTIC_V3_REVEAL_SIGNATURE_DOMAIN,
            session,
            global_round,
            &round.descriptor,
            prior_root,
            &round.prover_message,
            contributor,
            &reveal.payload,
        );
        verify_signature(contributor, &reveal_message, &reveal.signature)?;
    }
    let seed = round_seed(
        session,
        global_round,
        &round.descriptor,
        prior_root,
        &round.prover_message,
        &round.commitments,
        &round.reveals,
    );
    let fields = (0..draw_count)
        .map(|draw| {
            sample_uniform_fp16(
                &seed,
                session,
                global_round,
                draw as u32,
                DEFAULT_MAX_ATTEMPTS,
            )
            .map(|sample| sample.element)
            .map_err(|_| SemanticV3PublicCoinError::Challenge)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let root = audit_root(
        session,
        global_round,
        &round.descriptor,
        prior_root,
        &round.prover_message,
        &seed,
        &round.commitments,
        &round.reveals,
        &fields,
    );
    if root != round.resulting_root {
        return Err(SemanticV3PublicCoinError::Root);
    }
    Ok((root, seed, fields))
}

/// Verify exactly global semantic rounds 0 and 1.
pub fn verify_semantic_v3_prefix(
    encoded: &[u8],
    expected: &SemanticV3GovernedContext,
) -> Result<VerifiedSemanticV3Prefix, SemanticV3PublicCoinError> {
    let mut reader = Reader::new(encoded)?;
    if reader.take(8)? != SEMANTIC_V3_PREFIX_MAGIC {
        return Err(SemanticV3PublicCoinError::Magic);
    }
    if reader.u16()? != SEMANTIC_V3_TRANSCRIPT_VERSION {
        return Err(SemanticV3PublicCoinError::Version);
    }
    if reader.u16()? != 0 {
        return Err(SemanticV3PublicCoinError::Reserved);
    }
    let semantic_session_id = reader.digest()?;
    let semantic_schedule_commitment = reader.digest()?;
    let semantic_program_commitment = reader.digest()?;
    let parameter_commitment = reader.digest()?;
    let statement_commitment = reader.digest()?;
    let profile = match reader.u8()? {
        1 => Profile::K128Calibration,
        3 => Profile::K512Calibration,
        _ => return Err(SemanticV3PublicCoinError::Profile),
    };
    if reader.take(7)?.iter().any(|value| *value != 0) {
        return Err(SemanticV3PublicCoinError::Reserved);
    }
    let contributors = decode_contributors(&mut reader)?;
    let contributor_set_commitment = contributor_set_commitment(&contributors);
    if profile != expected.profile
        || semantic_program_commitment != expected.semantic_program_commitment
        || parameter_commitment != expected.parameter_commitment
        || statement_commitment != expected.statement_commitment
        || contributor_set_commitment != expected.contributor_set_commitment
        || semantic_schedule_commitment != semantic_v3_schedule_commitment(expected)?
        || !nonzero(&semantic_session_id)
    {
        return Err(SemanticV3PublicCoinError::Context);
    }
    if reader.u16()? != 2 {
        return Err(SemanticV3PublicCoinError::Shape);
    }
    let round_0 = decode_round(&mut reader, contributors.len())?;
    let round_1 = decode_round(&mut reader, contributors.len())?;
    let claimed_final_root = reader.digest()?;
    if reader.offset != encoded.len() {
        return Err(SemanticV3PublicCoinError::Trailing);
    }
    let profile_byte = [profile as u8];
    let init_root = hash(
        SEMANTIC_V3_PREFIX_INIT_DOMAIN,
        &[
            &semantic_session_id,
            &semantic_schedule_commitment,
            &contributor_set_commitment,
            &semantic_program_commitment,
            &parameter_commitment,
            &statement_commitment,
            &profile_byte,
        ],
    );
    let descriptors = semantic_v3_descriptors(expected.geometry);
    let (round_0_root, _, round_0_fields) = verify_round(
        &round_0,
        descriptors[0],
        64,
        &semantic_session_id,
        0,
        &init_root,
        &contributors,
        2,
    )?;
    let (round_1_root, _, round_1_fields) = verify_round(
        &round_1,
        descriptors[1],
        64,
        &semantic_session_id,
        1,
        &round_0_root,
        &contributors,
        1,
    )?;
    if claimed_final_root != round_1_root {
        return Err(SemanticV3PublicCoinError::Root);
    }
    let main_trace_root: [u8; 64] = round_0.prover_message[..64]
        .try_into()
        .map_err(|_| SemanticV3PublicCoinError::Message)?;
    let interaction_trace_root: [u8; 64] = round_1.prover_message[..64]
        .try_into()
        .map_err(|_| SemanticV3PublicCoinError::Message)?;
    let encoded_digest: [u8; 64] = Sha3_512::digest(encoded).into();
    let receipt_commitment = hash(
        SEMANTIC_V3_PREFIX_RECEIPT_DOMAIN,
        &[
            &encoded_digest,
            &semantic_session_id,
            &semantic_schedule_commitment,
            &contributor_set_commitment,
            &round_1_root,
            &main_trace_root,
            &interaction_trace_root,
            &round_0_fields[0].encode(),
            &round_0_fields[1].encode(),
            &round_1_fields[0].encode(),
        ],
    );
    Ok(VerifiedSemanticV3Prefix {
        semantic_session_id,
        semantic_schedule_commitment,
        contributor_set_commitment,
        round_1_transcript_root: round_1_root,
        main_trace_root,
        interaction_trace_root,
        logup_beta: round_0_fields[0],
        logup_gamma: round_0_fields[1],
        composition_alpha: round_1_fields[0],
        profile,
        semantic_program_commitment,
        parameter_commitment,
        statement_commitment,
        receipt_commitment,
        contributors,
    })
}

impl VerifiedSemanticV3Prefix {
    pub fn semantic_session_id(&self) -> [u8; 64] {
        self.semantic_session_id
    }

    pub fn semantic_schedule_commitment(&self) -> [u8; 64] {
        self.semantic_schedule_commitment
    }

    pub fn contributor_set_commitment(&self) -> [u8; 64] {
        self.contributor_set_commitment
    }

    pub fn round_1_transcript_root(&self) -> [u8; 64] {
        self.round_1_transcript_root
    }

    pub fn main_trace_root(&self) -> [u8; 64] {
        self.main_trace_root
    }

    pub fn interaction_trace_root(&self) -> [u8; 64] {
        self.interaction_trace_root
    }

    pub fn receipt_commitment(&self) -> [u8; 64] {
        self.receipt_commitment
    }

    pub fn profile(&self) -> Profile {
        self.profile
    }

    pub fn semantic_program_commitment(&self) -> [u8; 64] {
        self.semantic_program_commitment
    }

    pub fn parameter_commitment(&self) -> [u8; 64] {
        self.parameter_commitment
    }

    pub fn statement_commitment(&self) -> [u8; 64] {
        self.statement_commitment
    }

    pub fn composition_alpha(&self) -> Fp16 {
        self.composition_alpha
    }

    pub fn logup_challenges(&self) -> (Fp16, Fp16) {
        (self.logup_beta, self.logup_gamma)
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn synthetic_verified_semantic_v3_prefix_for_parent_test(
    profile: Profile,
    semantic_session_id: [u8; 64],
    semantic_schedule_commitment: [u8; 64],
    contributor_set_commitment: [u8; 64],
    round_1_transcript_root: [u8; 64],
    main_trace_root: [u8; 64],
    interaction_trace_root: [u8; 64],
    semantic_program_commitment: [u8; 64],
    parameter_commitment: [u8; 64],
    statement_commitment: [u8; 64],
    receipt_commitment: [u8; 64],
) -> VerifiedSemanticV3Prefix {
    VerifiedSemanticV3Prefix {
        semantic_session_id,
        semantic_schedule_commitment,
        contributor_set_commitment,
        round_1_transcript_root,
        main_trace_root,
        interaction_trace_root,
        logup_beta: Fp16::ONE,
        logup_gamma: Fp16::ONE,
        composition_alpha: Fp16::ONE,
        profile,
        semantic_program_commitment,
        parameter_commitment,
        statement_commitment,
        receipt_commitment,
        contributors: Vec::new(),
    }
}

#[cfg(test)]
pub(crate) fn synthetic_verified_strict_semantic_v3_for_parent_test(
    profile: Profile,
    completion_challenge: Fp16,
) -> VerifiedStrictSemanticV3PublicCoin {
    VerifiedStrictSemanticV3PublicCoin {
        profile,
        pre_final_transcript_root: [1; 128],
        final_transcript_root: [2; 128],
        logup_beta: Fp16::ONE,
        logup_gamma: Fp16::ONE,
        composition_alpha: Fp16::ONE,
        bridge_alpha: Fp16::ONE,
        oods_point: CirclePoint {
            x: Fp16::ONE,
            y: Fp16::ONE,
        },
        completion_challenge,
        fri_batch_coefficient: Fp16::ONE,
        fri_fold_coefficients: vec![Fp16::ONE],
        query_seed: [3; 64],
        query_positions: vec![0],
        round_message_bindings: vec![],
    }
}

fn evaluate_direct_q(
    coefficients: &[Fp16],
    z: CirclePoint,
) -> Result<(Fp16, Fp16), SemanticV3PublicCoinError> {
    if coefficients.len() != SEMANTIC_V3_Q_COEFFICIENT_COUNT {
        return Err(SemanticV3PublicCoinError::Shape);
    }
    let mut padded = vec![Fp16::ZERO; SEMANTIC_V3_Q_PADDED_COUNT];
    padded[..coefficients.len()].copy_from_slice(coefficients);
    let conjugate = CirclePoint {
        x: z.x.conjugate(),
        y: z.y.conjugate(),
    };
    Ok((
        evaluate_extension_coefficients_at_point(&padded, z)
            .map_err(|_| SemanticV3PublicCoinError::QuotientEvaluation)?,
        evaluate_extension_coefficients_at_point(&padded, conjugate)
            .map_err(|_| SemanticV3PublicCoinError::QuotientEvaluation)?,
    ))
}

#[allow(clippy::too_many_arguments)]
fn continuation_anchor_from_verified_parts(
    prefix: &VerifiedSemanticV3Prefix,
    parent_session_id: [u8; 64],
    parent_round_901_transcript_root: [u8; 64],
    composition_root: [u8; 64],
    z: CirclePoint,
    bridge_program_commitment: [u8; 64],
    answer_aggregate_root: [u8; 64],
    message_direct_q_commitment: [u8; 64],
    digest_direct_q_commitment: [u8; 64],
    message_q_coefficients: &[Fp16],
    digest_q_coefficients: &[Fp16],
) -> Result<VerifiedSemanticContinuationAnchorInputs, SemanticV3PublicCoinError> {
    if [
        parent_session_id,
        parent_round_901_transcript_root,
        composition_root,
        bridge_program_commitment,
        answer_aggregate_root,
        message_direct_q_commitment,
        digest_direct_q_commitment,
    ]
    .iter()
    .any(|value| !nonzero(value))
    {
        return Err(SemanticV3PublicCoinError::Context);
    }
    let (message_at_z, message_at_conjugate) = evaluate_direct_q(message_q_coefficients, z)?;
    let (digest_at_z, digest_at_conjugate) = evaluate_direct_q(digest_q_coefficients, z)?;
    let direct_q_evaluations = SemanticV3DirectQuotientEvaluations {
        message_at_z,
        message_at_conjugate,
        digest_at_z,
        digest_at_conjugate,
    };
    let continuation_initial_root = semantic_v3_continuation_initial_root(
        &parent_session_id,
        &parent_round_901_transcript_root,
        &prefix.semantic_session_id,
        &prefix.semantic_schedule_commitment,
        &prefix.contributor_set_commitment,
        &prefix.round_1_transcript_root,
        &composition_root,
        z,
        &bridge_program_commitment,
        &answer_aggregate_root,
        &message_direct_q_commitment,
        &digest_direct_q_commitment,
    );
    Ok(VerifiedSemanticContinuationAnchorInputs {
        parent_session_id,
        parent_round_901_transcript_root,
        semantic_session_id: prefix.semantic_session_id,
        semantic_schedule_commitment: prefix.semantic_schedule_commitment,
        contributor_set_commitment: prefix.contributor_set_commitment,
        round_1_transcript_root: prefix.round_1_transcript_root,
        composition_root,
        z,
        bridge_program_commitment,
        answer_aggregate_root,
        message_direct_q_commitment,
        digest_direct_q_commitment,
        direct_q_evaluations,
        continuation_initial_root,
        contributors: prefix.contributors.clone(),
    })
}

/// Derive the continuation anchor only from an opaque, already-matched parent
/// prefix. No digest or coefficient argument is accepted from the caller.
fn verified_semantic_continuation_anchor_inputs(
    parent: &VerifiedCompositeParentPrefix,
) -> Result<VerifiedSemanticContinuationAnchorInputs, SemanticV3PublicCoinError> {
    let commitments = parent.direct_quotient_commitments();
    continuation_anchor_from_verified_parts(
        parent.semantic_prefix(),
        parent.session_id(),
        parent.round_901_transcript_root(),
        parent.semantic_composition_root(),
        parent.oods_point(),
        parent.bridge_program_commitment(),
        parent.bridge_mask_answer_aggregate_root(),
        commitments.message,
        commitments.digest,
        parent.direct_quotient_coefficients(BridgeQuotientGroup::Message),
        parent.direct_quotient_coefficients(BridgeQuotientGroup::Digest),
    )
}

fn verified_semantic_continuation_anchor_inputs_with_strict(
    parent: &VerifiedCompositeParentPrefix,
    strict: &VerifiedStrictSemanticV3PublicCoin,
) -> Result<VerifiedSemanticContinuationAnchorInputs, SemanticV3PublicCoinError> {
    if parent.profile() != strict.profile() {
        return Err(SemanticV3PublicCoinError::Context);
    }
    let commitments = parent.direct_quotient_commitments();
    continuation_anchor_from_verified_parts(
        parent.semantic_prefix(),
        parent.session_id(),
        parent.round_901_transcript_root(),
        parent.semantic_composition_root(),
        strict.oods_point(),
        parent.bridge_program_commitment(),
        parent.bridge_mask_answer_aggregate_root(),
        commitments.message,
        commitments.digest,
        parent.direct_quotient_coefficients(BridgeQuotientGroup::Message),
        parent.direct_quotient_coefficients(BridgeQuotientGroup::Digest),
    )
}

impl VerifiedSemanticContinuationAnchorInputs {
    pub(crate) fn continuation_initial_root(&self) -> [u8; 64] {
        self.continuation_initial_root
    }

    pub(crate) fn direct_q_evaluations(&self) -> SemanticV3DirectQuotientEvaluations {
        self.direct_q_evaluations
    }
}

fn match_parent_anchor_frame(
    serialized: &SemanticV3ParentAnchorFrame,
    verified: &VerifiedSemanticContinuationAnchorInputs,
) -> Result<(), SemanticV3PublicCoinError> {
    if serialized.parent_session_id != verified.parent_session_id
        || serialized.parent_round_901_transcript_root != verified.parent_round_901_transcript_root
        || serialized.semantic_session_id != verified.semantic_session_id
        || serialized.semantic_schedule_commitment != verified.semantic_schedule_commitment
        || serialized.contributor_set_commitment != verified.contributor_set_commitment
        || serialized.semantic_round_1_transcript_root != verified.round_1_transcript_root
        || serialized.composition_root != verified.composition_root
        || serialized.z != verified.z
        || serialized.bridge_program_commitment != verified.bridge_program_commitment
        || serialized.answer_aggregate_root != verified.answer_aggregate_root
        || serialized.message_direct_q_commitment != verified.message_direct_q_commitment
        || serialized.digest_direct_q_commitment != verified.digest_direct_q_commitment
        || serialized.continuation_initial_root != verified.continuation_initial_root
    {
        return Err(SemanticV3PublicCoinError::ParentAnchorMismatch);
    }
    Ok(())
}

/// Replay global semantic rounds 2+ from the authenticated parent anchor.
fn verify_semantic_v3_continuation(
    encoded: &[u8],
    anchor: &VerifiedSemanticContinuationAnchorInputs,
    geometry: SemanticV3Geometry,
) -> Result<VerifiedSemanticV3Continuation, SemanticV3PublicCoinError> {
    let mut reader = Reader::new(encoded)?;
    if reader.take(8)? != SEMANTIC_V3_CONTINUATION_MAGIC {
        return Err(SemanticV3PublicCoinError::Magic);
    }
    if reader.u16()? != SEMANTIC_V3_TRANSCRIPT_VERSION || reader.u16()? != 0 {
        return Err(SemanticV3PublicCoinError::Version);
    }
    if reader.digest()? != anchor.semantic_session_id
        || reader.digest()? != anchor.semantic_schedule_commitment
        || reader.digest()? != anchor.contributor_set_commitment
        || reader.digest()? != anchor.continuation_initial_root
    {
        return Err(SemanticV3PublicCoinError::Context);
    }
    let expected_count = usize::from(geometry.fold_round_count) + 2;
    if usize::from(reader.u16()?) != expected_count {
        return Err(SemanticV3PublicCoinError::Shape);
    }
    let rounds = (0..expected_count)
        .map(|_| decode_round(&mut reader, anchor.contributors.len()))
        .collect::<Result<Vec<_>, _>>()?;
    let claimed_final_root = reader.digest()?;
    if reader.offset != encoded.len() {
        return Err(SemanticV3PublicCoinError::Trailing);
    }
    let descriptors = semantic_v3_descriptors(geometry);
    let mut prior_root = anchor.continuation_initial_root;
    let mut fri_batch_coefficient = None;
    let mut fri_fold_coefficients = Vec::with_capacity(usize::from(geometry.fold_round_count));
    let mut query_seed = None;
    for (offset, round) in rounds.iter().enumerate() {
        let global_round = (offset + 2) as u32;
        let is_first = offset == 0;
        let is_final = offset + 1 == rounds.len();
        let message_bytes = if is_first { 128 } else { 64 };
        let draws = usize::from(!is_final);
        let (root, seed, fields) = verify_round(
            round,
            descriptors[offset + 2],
            message_bytes,
            &anchor.semantic_session_id,
            global_round,
            &prior_root,
            &anchor.contributors,
            draws,
        )?;
        if is_final {
            query_seed = Some(seed);
        } else if is_first {
            fri_batch_coefficient = Some(fields[0]);
        } else {
            fri_fold_coefficients.push(fields[0]);
        }
        prior_root = root;
    }
    if prior_root != claimed_final_root
        || fri_fold_coefficients.len() != usize::from(geometry.fold_round_count)
    {
        return Err(SemanticV3PublicCoinError::Root);
    }
    Ok(VerifiedSemanticV3Continuation {
        final_transcript_root: prior_root,
        fri_batch_coefficient: fri_batch_coefficient.ok_or(SemanticV3PublicCoinError::Challenge)?,
        fri_fold_coefficients,
        query_seed: query_seed.ok_or(SemanticV3PublicCoinError::Challenge)?,
        direct_q_evaluations: anchor.direct_q_evaluations,
    })
}

/// Verifier-side v3 replay.  The echoed producer commitment is deliberately
/// absent: authority comes from the independently verified parent prefix.
pub fn verify_semantic_v3_parent_frame_and_continuation(
    serialized_parent_anchor: &SemanticV3ParentAnchorFrame,
    parent: &VerifiedCompositeParentPrefix,
    encoded_continuation: &[u8],
    geometry: SemanticV3Geometry,
) -> Result<VerifiedSemanticV3Continuation, SemanticV3PublicCoinError> {
    let verified_anchor = verified_semantic_continuation_anchor_inputs(parent)?;
    match_parent_anchor_frame(serialized_parent_anchor, &verified_anchor)?;
    verify_semantic_v3_continuation(encoded_continuation, &verified_anchor, geometry)
}

/// Accepting continuation replay. The parent chain authenticates the 900/901
/// message order and quotient inventory; the strict-PQ global coin owns the
/// proof challenge, including the sole OODS point. This prevents two
/// independently sampled transcript points from entering one proof.
pub fn verify_semantic_v3_parent_frame_and_continuation_with_strict(
    serialized_parent_anchor: &SemanticV3ParentAnchorFrame,
    parent: &VerifiedCompositeParentPrefix,
    strict: &VerifiedStrictSemanticV3PublicCoin,
    encoded_continuation: &[u8],
    geometry: SemanticV3Geometry,
) -> Result<VerifiedSemanticV3Continuation, SemanticV3PublicCoinError> {
    let verified_anchor = verified_semantic_continuation_anchor_inputs_with_strict(parent, strict)?;
    match_parent_anchor_frame(serialized_parent_anchor, &verified_anchor)?;
    verify_semantic_v3_continuation(encoded_continuation, &verified_anchor, geometry)
}

/// Reconstruct the strict-PQ prover-message sequence from the three
/// authenticated transcript segments. The returned bytes are still raw
/// transport; `verify_strict_semantic_v3_public_coin` replays the bundle and
/// binds each message to its global ordinal before producing an opaque
/// receipt.
pub fn semantic_v3_strict_prover_messages(
    encoded_prefix: &[u8],
    encoded_parent_bundle: &[u8],
    encoded_continuation: &[u8],
) -> Result<Vec<Vec<u8>>, SemanticV3PublicCoinError> {
    let mut prefix_reader = Reader::new(encoded_prefix)?;
    if prefix_reader.take(8)? != SEMANTIC_V3_PREFIX_MAGIC
        || prefix_reader.u16()? != SEMANTIC_V3_TRANSCRIPT_VERSION
        || prefix_reader.u16()? != 0
    {
        return Err(SemanticV3PublicCoinError::ParentAnchorEncoding);
    }
    let _session_id = prefix_reader.digest()?;
    let _schedule_commitment = prefix_reader.digest()?;
    let _semantic_program_commitment = prefix_reader.digest()?;
    let _parameter_commitment = prefix_reader.digest()?;
    let _statement_commitment = prefix_reader.digest()?;
    let _profile = prefix_reader.u8()?;
    if prefix_reader.take(7)?.iter().any(|byte| *byte != 0) {
        return Err(SemanticV3PublicCoinError::ParentAnchorEncoding);
    }
    let contributors = decode_contributors(&mut prefix_reader)?;
    if prefix_reader.u16()? != 2 {
        return Err(SemanticV3PublicCoinError::Shape);
    }
    let prefix_rounds = (0..2)
        .map(|_| decode_round(&mut prefix_reader, contributors.len()))
        .collect::<Result<Vec<_>, _>>()?;
    let _claimed_prefix_root = prefix_reader.digest()?;
    if prefix_reader.offset != encoded_prefix.len() {
        return Err(SemanticV3PublicCoinError::Trailing);
    }

    let parent =
        crate::chained_public_coin::decode_chained_public_coin_bundle(encoded_parent_bundle)
            .map_err(|_| SemanticV3PublicCoinError::ParentAnchorEncoding)?;
    if parent.rounds.len() != 3
        || parent
            .rounds
            .iter()
            .any(|round| round.prover_message.is_empty())
    {
        return Err(SemanticV3PublicCoinError::Shape);
    }

    let mut continuation_reader = Reader::new(encoded_continuation)?;
    if continuation_reader.take(8)? != SEMANTIC_V3_CONTINUATION_MAGIC
        || continuation_reader.u16()? != SEMANTIC_V3_TRANSCRIPT_VERSION
        || continuation_reader.u16()? != 0
    {
        return Err(SemanticV3PublicCoinError::ParentAnchorEncoding);
    }
    let _continuation_session = continuation_reader.digest()?;
    let _continuation_schedule = continuation_reader.digest()?;
    let _continuation_contributors = continuation_reader.digest()?;
    let _continuation_initial_root = continuation_reader.digest()?;
    let continuation_count = usize::from(continuation_reader.u16()?);
    if continuation_count < 2 {
        return Err(SemanticV3PublicCoinError::Shape);
    }
    let continuation_rounds = (0..continuation_count)
        .map(|_| decode_round(&mut continuation_reader, contributors.len()))
        .collect::<Result<Vec<_>, _>>()?;
    let _claimed_continuation_root = continuation_reader.digest()?;
    if continuation_reader.offset != encoded_continuation.len() {
        return Err(SemanticV3PublicCoinError::Trailing);
    }

    let mut messages = Vec::with_capacity(5 + continuation_rounds.len());
    messages.extend(prefix_rounds.into_iter().map(|round| round.prover_message));
    messages.extend(
        parent.rounds[..2]
            .iter()
            .map(|round| round.prover_message.clone()),
    );
    messages.extend(
        continuation_rounds
            .into_iter()
            .map(|round| round.prover_message),
    );
    messages.push(parent.rounds[2].prover_message.clone());
    Ok(messages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, string::String};
    use ml_dsa::{
        Keypair as _, MlDsa87, Seed, SignatureEncoding as _, Signer as _,
        SigningKey as MlDsaSigningKey,
    };
    use slh_dsa::{Shake256f, SigningKey as SlhDsaSigningKey};

    enum TestSigner {
        Ml(MlDsaSigningKey<MlDsa87>),
        Slh(SlhDsaSigningKey<Shake256f>),
    }

    impl TestSigner {
        fn sign(&self, message: &[u8]) -> Vec<u8> {
            match self {
                Self::Ml(key) => key.sign(message).to_bytes().to_vec(),
                Self::Slh(key) => key
                    .try_sign(message)
                    .expect("valid fixed SLH-DSA message")
                    .to_bytes()
                    .to_vec(),
            }
        }
    }

    fn digest(value: u8) -> [u8; 64] {
        [value; 64]
    }

    fn contributor_fixture() -> (Vec<Contributor>, Vec<TestSigner>) {
        let ml = MlDsaSigningKey::<MlDsa87>::from_seed(&Seed::from([17_u8; 32]));
        let slh = SlhDsaSigningKey::<Shake256f>::slh_keygen_internal(
            &[19_u8; 32],
            &[23_u8; 32],
            &[29_u8; 32],
        );
        (
            vec![
                Contributor {
                    contributor_id: digest(1),
                    key_id: digest(11),
                    suite: SignatureSuite::MlDsa87,
                    public_key: ml.verifying_key().encode().to_vec(),
                },
                Contributor {
                    contributor_id: digest(2),
                    key_id: digest(12),
                    suite: SignatureSuite::SlhDsaShake256f,
                    public_key: slh.verifying_key().to_bytes().to_vec(),
                },
            ],
            vec![TestSigner::Ml(ml), TestSigner::Slh(slh)],
        )
    }

    fn signed_round(
        session: &[u8; 64],
        global_round: u32,
        descriptor: [u8; 8],
        prior_root: &[u8; 64],
        prover_message: Vec<u8>,
        contributors: &[Contributor],
        signers: &[TestSigner],
        draw_count: usize,
    ) -> (Round, Vec<Fp16>) {
        let reveals = contributors
            .iter()
            .enumerate()
            .map(|(index, contributor)| Envelope {
                contributor_id: contributor.contributor_id,
                payload: hash(
                    b"BL/PQ512/SELECTED/SEMANTIC-V3/TEST-REVEAL/v1\0",
                    &[&global_round.to_be_bytes(), &[index as u8]],
                ),
                signature: Vec::new(),
            })
            .collect::<Vec<_>>();
        let mut commitments = contributors
            .iter()
            .zip(&reveals)
            .map(|(contributor, reveal)| Envelope {
                contributor_id: contributor.contributor_id,
                payload: expected_commitment(
                    session,
                    global_round,
                    &descriptor,
                    prior_root,
                    &prover_message,
                    &contributor.contributor_id,
                    &reveal.payload,
                ),
                signature: Vec::new(),
            })
            .collect::<Vec<_>>();
        let mut reveals = reveals;
        for index in 0..contributors.len() {
            let commitment_message = round_signature_message(
                SEMANTIC_V3_COMMITMENT_SIGNATURE_DOMAIN,
                session,
                global_round,
                &descriptor,
                prior_root,
                &prover_message,
                &contributors[index],
                &commitments[index].payload,
            );
            commitments[index].signature = signers[index].sign(&commitment_message);
            let reveal_message = round_signature_message(
                SEMANTIC_V3_REVEAL_SIGNATURE_DOMAIN,
                session,
                global_round,
                &descriptor,
                prior_root,
                &prover_message,
                &contributors[index],
                &reveals[index].payload,
            );
            reveals[index].signature = signers[index].sign(&reveal_message);
        }
        let seed = round_seed(
            session,
            global_round,
            &descriptor,
            prior_root,
            &prover_message,
            &commitments,
            &reveals,
        );
        let fields = (0..draw_count)
            .map(|draw| {
                sample_uniform_fp16(
                    &seed,
                    session,
                    global_round,
                    draw as u32,
                    DEFAULT_MAX_ATTEMPTS,
                )
                .unwrap()
                .element
            })
            .collect::<Vec<_>>();
        let resulting_root = audit_root(
            session,
            global_round,
            &descriptor,
            prior_root,
            &prover_message,
            &seed,
            &commitments,
            &reveals,
            &fields,
        );
        (
            Round {
                descriptor,
                prover_message,
                commitments,
                reveals,
                resulting_root,
            },
            fields,
        )
    }

    fn push_bytes(output: &mut Vec<u8>, value: &[u8]) {
        output.extend_from_slice(&(value.len() as u32).to_be_bytes());
        output.extend_from_slice(value);
    }

    fn encode_contributors(output: &mut Vec<u8>, contributors: &[Contributor]) {
        output.extend_from_slice(&(contributors.len() as u16).to_be_bytes());
        for contributor in contributors {
            output.extend_from_slice(&contributor.contributor_id);
            output.extend_from_slice(&contributor.key_id);
            output.extend_from_slice(&(contributor.suite as u16).to_be_bytes());
            push_bytes(output, &contributor.public_key);
        }
    }

    fn encode_envelope(output: &mut Vec<u8>, envelope: &Envelope) {
        output.extend_from_slice(&envelope.contributor_id);
        output.extend_from_slice(&envelope.payload);
        push_bytes(output, &envelope.signature);
    }

    fn encode_round(output: &mut Vec<u8>, round: &Round) {
        output.extend_from_slice(&round.descriptor);
        push_bytes(output, &round.prover_message);
        output.extend_from_slice(&(round.commitments.len() as u16).to_be_bytes());
        for commitment in &round.commitments {
            encode_envelope(output, commitment);
        }
        output.extend_from_slice(&(round.reveals.len() as u16).to_be_bytes());
        for reveal in &round.reveals {
            encode_envelope(output, reveal);
        }
        output.extend_from_slice(&round.resulting_root);
    }

    fn governed_context(contributors: &[Contributor]) -> SemanticV3GovernedContext {
        SemanticV3GovernedContext {
            profile: Profile::K128Calibration,
            semantic_program_commitment: digest(31),
            parameter_commitment: digest(32),
            statement_commitment: digest(33),
            composite_parent_schedule_commitment: digest(34),
            contributor_set_commitment: contributor_set_commitment(contributors),
            geometry: SemanticV3Geometry {
                fold_round_count: 3,
                query_domain_log_size: 26,
                log_blowup: 2,
            },
        }
    }

    #[test]
    fn governed_context_transport_matches_python_kat() {
        let context = SemanticV3GovernedContext {
            profile: Profile::K512Calibration,
            semantic_program_commitment: [1; 64],
            parameter_commitment: [2; 64],
            statement_commitment: [3; 64],
            composite_parent_schedule_commitment: [4; 64],
            contributor_set_commitment: [5; 64],
            geometry: SemanticV3Geometry {
                fold_round_count: 0x1234,
                query_domain_log_size: 26,
                log_blowup: 2,
            },
        };
        let encoded = context.encode().unwrap();
        assert_eq!(encoded.len(), SEMANTIC_V3_CONTEXT_BYTES);
        assert_eq!(
            SemanticV3GovernedContext::decode(&encoded).unwrap(),
            context
        );
        assert_eq!(
            Sha3_512::digest(&encoded).as_slice(),
            &[
                0x75, 0x95, 0x67, 0xca, 0xb1, 0x8f, 0xd0, 0xd4, 0x2a, 0xa4, 0x8a, 0x63, 0x29, 0x9c,
                0x75, 0xbf, 0x5f, 0xee, 0x60, 0xeb, 0x9f, 0x85, 0xe6, 0x84, 0xc4, 0xe8, 0x1c, 0x88,
                0x32, 0x4f, 0xd1, 0x1f, 0x41, 0x34, 0x27, 0xcf, 0x8c, 0x52, 0x64, 0xae, 0x4c, 0xda,
                0xf8, 0xda, 0x12, 0xa1, 0x69, 0x19, 0x88, 0x08, 0x5b, 0x7e, 0x1a, 0x49, 0xd1, 0xd8,
                0x42, 0x54, 0x91, 0xab, 0xa3, 0x80, 0x73, 0xde,
            ]
        );
    }

    fn encoded_prefix() -> (
        Vec<u8>,
        SemanticV3GovernedContext,
        Vec<Contributor>,
        Vec<TestSigner>,
    ) {
        let (contributors, signers) = contributor_fixture();
        let context = governed_context(&contributors);
        let session = digest(30);
        let schedule = semantic_v3_schedule_commitment(&context).unwrap();
        let profile = [context.profile as u8];
        let init = hash(
            SEMANTIC_V3_PREFIX_INIT_DOMAIN,
            &[
                &session,
                &schedule,
                &context.contributor_set_commitment,
                &context.semantic_program_commitment,
                &context.parameter_commitment,
                &context.statement_commitment,
                &profile,
            ],
        );
        let descriptors = semantic_v3_descriptors(context.geometry);
        let (round_0, _) = signed_round(
            &session,
            0,
            descriptors[0],
            &init,
            digest(40).to_vec(),
            &contributors,
            &signers,
            2,
        );
        let (round_1, _) = signed_round(
            &session,
            1,
            descriptors[1],
            &round_0.resulting_root,
            digest(41).to_vec(),
            &contributors,
            &signers,
            1,
        );
        let mut output = Vec::new();
        output.extend_from_slice(SEMANTIC_V3_PREFIX_MAGIC);
        output.extend_from_slice(&SEMANTIC_V3_TRANSCRIPT_VERSION.to_be_bytes());
        output.extend_from_slice(&0_u16.to_be_bytes());
        output.extend_from_slice(&session);
        output.extend_from_slice(&schedule);
        output.extend_from_slice(&context.semantic_program_commitment);
        output.extend_from_slice(&context.parameter_commitment);
        output.extend_from_slice(&context.statement_commitment);
        output.push(context.profile as u8);
        output.extend_from_slice(&[0_u8; 7]);
        encode_contributors(&mut output, &contributors);
        output.extend_from_slice(&2_u16.to_be_bytes());
        encode_round(&mut output, &round_0);
        encode_round(&mut output, &round_1);
        output.extend_from_slice(&round_1.resulting_root);
        (output, context, contributors, signers)
    }

    fn encoded_continuation(
        anchor: &VerifiedSemanticContinuationAnchorInputs,
        geometry: SemanticV3Geometry,
        contributors: &[Contributor],
        signers: &[TestSigner],
    ) -> Vec<u8> {
        let descriptors = semantic_v3_descriptors(geometry);
        let mut prior_root = anchor.continuation_initial_root;
        let round_count = usize::from(geometry.fold_round_count) + 2;
        let mut rounds = Vec::with_capacity(round_count);
        for offset in 0..round_count {
            let is_first = offset == 0;
            let is_final = offset + 1 == round_count;
            let prover_message = if is_first {
                [digest(80).as_slice(), digest(81).as_slice()].concat()
            } else {
                digest(82 + offset as u8).to_vec()
            };
            let (round, _) = signed_round(
                &anchor.semantic_session_id,
                (offset + 2) as u32,
                descriptors[offset + 2],
                &prior_root,
                prover_message,
                contributors,
                signers,
                usize::from(!is_final),
            );
            prior_root = round.resulting_root;
            rounds.push(round);
        }
        let mut output = Vec::new();
        output.extend_from_slice(SEMANTIC_V3_CONTINUATION_MAGIC);
        output.extend_from_slice(&SEMANTIC_V3_TRANSCRIPT_VERSION.to_be_bytes());
        output.extend_from_slice(&0_u16.to_be_bytes());
        output.extend_from_slice(&anchor.semantic_session_id);
        output.extend_from_slice(&anchor.semantic_schedule_commitment);
        output.extend_from_slice(&anchor.contributor_set_commitment);
        output.extend_from_slice(&anchor.continuation_initial_root);
        output.extend_from_slice(&(round_count as u16).to_be_bytes());
        for round in &rounds {
            encode_round(&mut output, round);
        }
        output.extend_from_slice(&prior_root);
        output
    }

    #[test]
    fn exact_v3_descriptor_sequence_has_no_kind_three() {
        let geometry = SemanticV3Geometry {
            fold_round_count: 3,
            query_domain_log_size: 26,
            log_blowup: 2,
        };
        let descriptors = semantic_v3_descriptors(geometry);
        assert_eq!(
            descriptors,
            vec![
                descriptor(1, 0, 1, 2),
                descriptor(2, 0, 1, 1),
                descriptor(4, 0, 1, 1),
                descriptor(5, 0, 1, 1),
                descriptor(5, 1, 1, 1),
                descriptor(5, 2, 1, 1),
                descriptor(6, 0, 2, 1),
            ]
        );
        assert!(
            descriptors
                .iter()
                .all(|value| value[..2] != 3_u16.to_be_bytes())
        );
    }

    #[test]
    fn parent_anchor_command_is_strict_and_matches_python_kat() {
        let mut tokens = (1_u8..=7)
            .map(|value| format!("{value:02x}").repeat(64))
            .collect::<Vec<_>>();
        tokens.push("00".repeat(64));
        tokens.push({
            let mut one = [0_u8; 64];
            one[3] = 1;
            one.iter()
                .map(|value| format!("{value:02x}"))
                .collect::<String>()
        });
        tokens.extend((10_u8..=13).map(|value| format!("{value:02x}").repeat(64)));
        tokens.push(
            "2ffa158f08d8bdf6dedf610f2f362f62f794bf3a4643a2f901a68c30fd4eecac\
             0a84b3c958708279b5fa02f61d079e917e43d823ae2c86cb89c40e4a2392f881"
                .replace(' ', ""),
        );
        let token_refs = tokens.iter().map(String::as_str).collect::<Vec<_>>();
        let frame = SemanticV3ParentAnchorFrame::decode_command_tokens(&token_refs).unwrap();
        assert_eq!(
            SemanticV3ParentAnchorFrame::decode(&frame.encode()).unwrap(),
            frame
        );
        assert_eq!(frame.oods_point().x, Fp16::ZERO);
        assert_eq!(frame.oods_point().y, Fp16::ONE);
        assert_eq!(
            frame.commitment(),
            decode_lower_hex_digest(
                "99b6b9259ec33c33c60731b10fc33bf36fd6102e44df3ba45e368887b8648325\
                 c0b251dc2760e15c239f24ec268d406477a2cf3ddc39b0b7dd19dbb4fb646473"
                    .replace(' ', "")
                    .as_str()
            )
            .unwrap()
        );

        assert_eq!(
            SemanticV3ParentAnchorFrame::decode_command_tokens(&token_refs[..13]),
            Err(SemanticV3PublicCoinError::ParentAnchorEncoding)
        );
        let mut uppercase = tokens.clone();
        uppercase[13] = uppercase[13].to_ascii_uppercase();
        let uppercase_refs = uppercase.iter().map(String::as_str).collect::<Vec<_>>();
        assert_eq!(
            SemanticV3ParentAnchorFrame::decode_command_tokens(&uppercase_refs),
            Err(SemanticV3PublicCoinError::ParentAnchorEncoding)
        );
        let mut legacy64 = tokens.clone();
        legacy64[0].truncate(64);
        let legacy64_refs = legacy64.iter().map(String::as_str).collect::<Vec<_>>();
        assert_eq!(
            SemanticV3ParentAnchorFrame::decode_command_tokens(&legacy64_refs),
            Err(SemanticV3PublicCoinError::ParentAnchorEncoding)
        );
        let mut off_circle = tokens.clone();
        off_circle[8] = "00".repeat(64);
        let off_circle_refs = off_circle.iter().map(String::as_str).collect::<Vec<_>>();
        assert_eq!(
            SemanticV3ParentAnchorFrame::decode_command_tokens(&off_circle_refs),
            Err(SemanticV3PublicCoinError::ParentAnchorCircle)
        );
        let mut changed_root = tokens;
        changed_root[13].replace_range(..1, "0");
        let changed_root_refs = changed_root.iter().map(String::as_str).collect::<Vec<_>>();
        assert_eq!(
            SemanticV3ParentAnchorFrame::decode_command_tokens(&changed_root_refs),
            Err(SemanticV3PublicCoinError::ParentAnchorMismatch)
        );
    }

    #[test]
    fn signed_prefix_roundtrip_and_context_mutations_fail() {
        let (encoded, context, _, _) = encoded_prefix();
        let verified = verify_semantic_v3_prefix(&encoded, &context).unwrap();
        assert_eq!(verified.semantic_session_id(), digest(30));
        assert_eq!(verified.main_trace_root(), digest(40));
        assert_eq!(verified.interaction_trace_root(), digest(41));

        let mut changed_context = context;
        changed_context.statement_commitment = digest(99);
        assert!(matches!(
            verify_semantic_v3_prefix(&encoded, &changed_context),
            Err(SemanticV3PublicCoinError::Context)
        ));
        let mut changed = encoded;
        changed[0] ^= 1;
        assert_eq!(
            verify_semantic_v3_prefix(&changed, &context).unwrap_err(),
            SemanticV3PublicCoinError::Magic
        );
    }

    #[test]
    fn anchor_binds_parent_context_and_q_evaluations_but_cannot_accept() {
        let (encoded, context, contributors, signers) = encoded_prefix();
        let prefix = verify_semantic_v3_prefix(&encoded, &context).unwrap();
        let sampled = crate::oods::sample_oods_parameter(
            &digest(70),
            &digest(71),
            1,
            crate::oods::OODS_DEFAULT_MAX_ATTEMPTS,
        )
        .unwrap();
        let z = crate::oods::stereographic_circle_point(sampled.parameter).unwrap();
        let message = vec![Fp16::ONE; SEMANTIC_V3_Q_COEFFICIENT_COUNT];
        let digest_q = vec![Fp16::ZERO; SEMANTIC_V3_Q_COEFFICIENT_COUNT];
        let anchor = continuation_anchor_from_verified_parts(
            &prefix,
            digest(50),
            digest(51),
            digest(52),
            z,
            digest(53),
            digest(54),
            digest(55),
            digest(56),
            &message,
            &digest_q,
        )
        .unwrap();
        let frame = SemanticV3ParentAnchorFrame {
            parent_session_id: anchor.parent_session_id,
            parent_round_901_transcript_root: anchor.parent_round_901_transcript_root,
            semantic_session_id: anchor.semantic_session_id,
            semantic_schedule_commitment: anchor.semantic_schedule_commitment,
            contributor_set_commitment: anchor.contributor_set_commitment,
            semantic_round_1_transcript_root: anchor.round_1_transcript_root,
            composition_root: anchor.composition_root,
            z: anchor.z,
            bridge_program_commitment: anchor.bridge_program_commitment,
            answer_aggregate_root: anchor.answer_aggregate_root,
            message_direct_q_commitment: anchor.message_direct_q_commitment,
            digest_direct_q_commitment: anchor.digest_direct_q_commitment,
            continuation_initial_root: anchor.continuation_initial_root,
        };
        match_parent_anchor_frame(&frame, &anchor).unwrap();
        let mut mismatched_frame = frame;
        mismatched_frame.answer_aggregate_root = digest(99);
        assert_eq!(
            match_parent_anchor_frame(&mismatched_frame, &anchor),
            Err(SemanticV3PublicCoinError::ParentAnchorMismatch)
        );
        let changed = continuation_anchor_from_verified_parts(
            &prefix,
            digest(50),
            digest(57),
            digest(52),
            z,
            digest(53),
            digest(54),
            digest(55),
            digest(56),
            &message,
            &digest_q,
        )
        .unwrap();
        assert_ne!(
            anchor.continuation_initial_root(),
            changed.continuation_initial_root()
        );
        assert_eq!(anchor.direct_q_evaluations().digest_at_z, Fp16::ZERO);
        let encoded_continuation =
            encoded_continuation(&anchor, context.geometry, &contributors, &signers);
        let verified =
            verify_semantic_v3_continuation(&encoded_continuation, &anchor, context.geometry)
                .unwrap();
        assert_eq!(verified.fri_fold_coefficients.len(), 3);
        let mut replayed = encoded_continuation;
        let anchor_root_offset = 12 + 3 * 64;
        replayed[anchor_root_offset] ^= 1;
        assert_eq!(
            verify_semantic_v3_continuation(&replayed, &anchor, context.geometry).unwrap_err(),
            SemanticV3PublicCoinError::Context
        );
    }
}
