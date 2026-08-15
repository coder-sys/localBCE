//! Composite-owned parent public coin for the version-3 proof.
//!
//! The semantic and H4 children commit independently before this three-round
//! chain begins. Round 900 fixes both child root inventories plus the one H4
//! bridge-mask base/pad aggregates before the nonzero bridge batching coefficient.
//! The aggregates cover four ordered Construction lanes: semantic carriers for
//! message/digest followed by H4 masks for message/digest. Round 901 fixes the
//! four answer lanes and serializes both exact degree-bounded quotient coefficient
//! vectors before one canonical OODS point is derived from that round's
//! authenticated seed. Round 902 fixes the post-OODS responses, component
//! packages, and receipt commitments; its completion challenge may check those
//! responses before `VerifiedCompositeParentPrefix::complete` can succeed. No
//! child is allowed to rechallenge the bridge coefficient, OODS, or completion
//! challenge.
//!
//! The 64-byte transcript roots are second-preimage authorities. Every
//! serialized 64-byte Merkle/oracle root remains nonactivating until the Z10
//! dual-domain 128-byte collision-binding migration is complete.

#[cfg(test)]
use alloc::vec;
use alloc::vec::Vec;

use sha3::{Digest, Sha3_512};

use crate::binding_root_v2::BindingDigestV2;
use crate::chained_public_coin::{
    ChainedChallenge, ChainedPublicCoinError, ChainedRoundDescriptor,
    decode_chained_public_coin_bundle, encode_chained_public_coin_bundle,
    verify_chained_public_coin_bundle,
};
#[cfg(feature = "std")]
use crate::chained_public_coin_client::{
    ChainedPublicCoinClientError, ChainedPublicCoinCoordinator,
};
use crate::field::Fp16;
use crate::fri_pipeline::VerifiedFriPipelineV3;
use crate::h4_proof_package_v2::VerifiedH4V2;
use crate::master_commitments::Profile;
use crate::oods::{
    CirclePoint, OODS_DEFAULT_MAX_ATTEMPTS, OodsError, sample_oods_parameter,
    stereographic_circle_point,
};
use crate::selected_public_coin_v3::{
    VerifiedSemanticV3Continuation, VerifiedSemanticV3Prefix, VerifiedStrictSemanticV3PublicCoin,
};
use crate::semantic_h4_bridge::VerifiedBridgeDivisibility;
use crate::semantic_h4_bridge_gkr::{
    DecisiveCompositionV3Error, VerifiedDecisiveCompositionV3,
    complete_verified_decisive_composition_v3,
};
use crate::typed_state_proof_package::VerifiedTypedStateV3;

#[cfg(feature = "std")]
use std::path::Path;

pub const COMPOSITE_PARENT_PRE_ALPHA_KIND: u16 = 900;
pub const COMPOSITE_PARENT_QUOTIENT_KIND: u16 = 901;
pub const COMPOSITE_PARENT_FINAL_KIND: u16 = 902;
pub const COMPOSITE_PARENT_ROUND_COUNT: usize = 3;
pub const COMPOSITE_PARENT_MAX_ATTEMPTS: u16 = 4;

const PRE_ALPHA_MAGIC: &[u8; 8] = b"BLV3PA03";
const QUOTIENT_MAGIC: &[u8; 8] = b"BLV3QR03";
const FINAL_MAGIC: &[u8; 8] = b"BLV3FR03";
const MESSAGE_VERSION: u16 = 3;
const MESSAGE_FLAGS: u16 = 0;
const SCHEDULE_DOMAIN: &[u8] = b"BL/PQ512/V3/COMPOSITE-PARENT-SCHEDULE/v3\0";
const DIRECT_QUOTIENT_DOMAIN: &[u8] =
    b"BL/PQ512/V3/SEMANTIC-H4-BRIDGE/DIRECT-QUOTIENT-COEFFICIENTS/v1\0";
const POST_Z_H4_RECEIPT_DOMAIN: &[u8] = b"BL/PQ512/V3/COMPOSITE-PARENT/POST-Z-H4-RECEIPT/v1\0";
// Circle-FFT tensor basis in bit-reversed coefficient order
// `y,x,pi(x),pi^2(x),...`, pi(x)=2*x^2-1. The consumer appends zero
// coefficients to length 8192 before `evaluate_extension_coefficients_at_point`.
const QUOTIENT_BASIS_CODE: u8 = 1;
const BRIDGE_QUOTIENT_COEFFICIENT_COUNT: usize = 4_789;
const FP16_BYTES: usize = 64;

const PRE_ALPHA_DIGESTS: usize = 20;
const PRE_ALPHA_BYTES: usize = 8 + 2 + 2 + 1 + 7 + 64 + 2 + 6 + 64 + PRE_ALPHA_DIGESTS * 64;
const QUOTIENT_FIXED_DIGESTS: usize = 3;
const QUOTIENT_GROUP_FRAME_BYTES: usize = 8;
const QUOTIENT_BYTES: usize = 8
    + 2
    + 2
    + 1
    + 7
    + QUOTIENT_FIXED_DIGESTS * 64
    + 2 * (QUOTIENT_GROUP_FRAME_BYTES + BRIDGE_QUOTIENT_COEFFICIENT_COUNT * FP16_BYTES);
const FINAL_DIGESTS: usize = 13;
const FINAL_BYTES: usize = 8 + 2 + 2 + FINAL_DIGESTS * 64;

pub const COMPOSITE_PARENT_PRE_ALPHA_BYTES: usize = PRE_ALPHA_BYTES;
pub const COMPOSITE_PARENT_QUOTIENT_BYTES: usize = QUOTIENT_BYTES;
pub const COMPOSITE_PARENT_FINAL_BYTES: usize = FINAL_BYTES;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositeParentPreAlphaMessage {
    pub profile: Profile,
    pub composite_session_id: [u8; 64],
    pub attempt: u16,
    pub schedule_commitment: [u8; 64],
    pub parent_program_commitment: [u8; 64],
    pub candidate_descriptor_commitment: [u8; 64],
    pub statement_commitment: [u8; 64],
    pub semantic_program_commitment: [u8; 64],
    pub semantic_session_id: [u8; 64],
    pub semantic_schedule_commitment: [u8; 64],
    pub semantic_contributor_set_commitment: [u8; 64],
    pub semantic_prefix_receipt_commitment: [u8; 64],
    pub semantic_round_1_transcript_root: [u8; 64],
    pub semantic_main_root: [u8; 64],
    pub semantic_interaction_root: [u8; 64],
    pub semantic_composition_root: [u8; 64],
    pub h4_child_final_root: [u8; 64],
    pub h4_ordered_shard_root_receipt: [u8; 64],
    pub h4_source_root: [u8; 64],
    pub h4_b_tensor_root: [u8; 64],
    pub h4_n_tensor_root: [u8; 64],
    pub h4_a_tensor_root: [u8; 64],
    pub bridge_mask_base_aggregate_root: [u8; 64],
    pub bridge_mask_pad_aggregate_root: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Untrusted 901 message/template material. Encoding validates its fixed
/// shape and profile/program identity; it is not a parent receipt.
pub struct CompositeParentQuotientMessage {
    pub profile: Profile,
    pub prior_transcript_root: [u8; 64],
    pub bridge_program_commitment: [u8; 64],
    pub bridge_mask_answer_aggregate_root: [u8; 64],
    pub message_quotient_coefficients: Vec<Fp16>,
    pub digest_quotient_coefficients: Vec<Fp16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BridgeQuotientGroup {
    Message = 0,
    Digest = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectBridgeQuotientCommitments {
    pub message: [u8; 64],
    pub digest: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Untrusted 902 message/template material. Encoding validates its fixed
/// shape and nonzero commitments; component binding still occurs only during
/// parent verification.
pub struct CompositeParentFinalMessage {
    pub prior_transcript_root: [u8; 64],
    pub post_z_primitive_response_oracle_root: [u8; 64],
    pub post_z_primitive_claim_vector_commitment: [u8; 64],
    pub semantic_continuation_final_root: [u8; 64],
    pub semantic_component_package_commitment: [u8; 64],
    pub h4_component_package_commitment: [u8; 64],
    pub typed_component_package_commitment: [u8; 64],
    pub typed_verified_receipt_commitment: [u8; 64],
    pub h4_booleanity_receipt_commitment: [u8; 64],
    pub h4_global_padding_receipt_commitment: [u8; 64],
    pub bridge_privacy_ledger_commitment: [u8; 64],
    pub semantic_exposure_ledger_commitment: [u8; 64],
    pub h4_exposure_ledger_commitment: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompositeParentPublicCoinError {
    Chained(ChainedPublicCoinError),
    #[cfg(feature = "std")]
    Client(ChainedPublicCoinClientError),
    Oods(OodsError),
    Length,
    Magic,
    Version,
    Flags,
    Profile,
    Reserved,
    ZeroCommitment,
    Attempt,
    Schedule,
    Descriptor,
    Message,
    PriorTranscriptRoot,
    NonCanonicalField,
    ZeroChallenge,
    SemanticPrefix,
    ComponentBinding,
    Decisive(DecisiveCompositionV3Error),
}

impl From<ChainedPublicCoinError> for CompositeParentPublicCoinError {
    fn from(value: ChainedPublicCoinError) -> Self {
        Self::Chained(value)
    }
}

impl From<DecisiveCompositionV3Error> for CompositeParentPublicCoinError {
    fn from(value: DecisiveCompositionV3Error) -> Self {
        Self::Decisive(value)
    }
}

#[cfg(feature = "std")]
impl From<ChainedPublicCoinClientError> for CompositeParentPublicCoinError {
    fn from(value: ChainedPublicCoinClientError) -> Self {
        Self::Client(value)
    }
}

impl From<OodsError> for CompositeParentPublicCoinError {
    fn from(value: OodsError) -> Self {
        Self::Oods(value)
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedCompositeParentPrefix {
    profile: Profile,
    session_id: [u8; 64],
    attempt: u16,
    bridge_alpha: Fp16,
    oods_point: CirclePoint,
    round_900_transcript_root: [u8; 64],
    round_901_transcript_root: [u8; 64],
    final_transcript_root: [u8; 64],
    completion_challenge: Fp16,
    bridge_mask_answer_aggregate_root: [u8; 64],
    direct_quotient_commitments: DirectBridgeQuotientCommitments,
    message_quotient_coefficients: Vec<Fp16>,
    digest_quotient_coefficients: Vec<Fp16>,
    semantic_prefix: VerifiedSemanticV3Prefix,
    semantic_composition_root: [u8; 64],
    bridge_program_commitment: [u8; 64],
    final_message: CompositeParentFinalMessage,
}

/// A replayed 900/901/902 chain with its descriptor order and nonzero
/// challenge shape checked. This is deliberately weaker than
/// `VerifiedCompositeParentPrefix`: it does not bind the messages to a
/// verified semantic prefix, H4 receipt, typed-state receipt, or post-Z
/// divisibility receipt, and therefore cannot complete the parent or accept
/// the outer composition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedCompositeParentTranscriptReplay {
    round_900_transcript_root: [u8; 64],
    round_901_transcript_root: [u8; 64],
    final_transcript_root: [u8; 64],
}

impl VerifiedCompositeParentTranscriptReplay {
    pub const fn round_900_transcript_root(&self) -> &[u8; 64] {
        &self.round_900_transcript_root
    }

    pub const fn round_901_transcript_root(&self) -> &[u8; 64] {
        &self.round_901_transcript_root
    }

    pub const fn final_transcript_root(&self) -> &[u8; 64] {
        &self.final_transcript_root
    }
}

/// Opaque output of the future pure post-z primitive/source PCS verifier.
///
/// There is deliberately no constructor in the current reference.  The parent
/// prefix therefore cannot be completed merely from caller digests or flags.
#[derive(Clone, Debug)]
pub(crate) struct VerifiedPostZBridgeOpenings {
    response_oracle_root: [u8; 64],
    claim_vector_commitment: [u8; 64],
    completion_challenge: Fp16,
    divisibility_receipt_commitment: [u8; 64],
}

#[derive(Clone, Debug)]
pub struct VerifiedCompositeParent {
    profile: Profile,
    session_id: [u8; 64],
    attempt: u16,
    bridge_alpha: Fp16,
    oods_point: CirclePoint,
    round_900_transcript_root: [u8; 64],
    round_901_transcript_root: [u8; 64],
    final_transcript_root: [u8; 64],
    completion_challenge: Fp16,
    bridge_divisibility_receipt_commitment: [u8; 64],
}

impl VerifiedCompositeParent {
    pub const fn profile(&self) -> Profile {
        self.profile
    }

    pub const fn session_id(&self) -> &[u8; 64] {
        &self.session_id
    }

    pub const fn attempt(&self) -> u16 {
        self.attempt
    }

    pub const fn bridge_alpha(&self) -> Fp16 {
        self.bridge_alpha
    }

    pub const fn oods_point(&self) -> CirclePoint {
        self.oods_point
    }

    pub const fn round_900_transcript_root(&self) -> &[u8; 64] {
        &self.round_900_transcript_root
    }

    pub const fn round_901_transcript_root(&self) -> &[u8; 64] {
        &self.round_901_transcript_root
    }

    pub const fn final_transcript_root(&self) -> &[u8; 64] {
        &self.final_transcript_root
    }

    pub const fn completion_challenge(&self) -> Fp16 {
        self.completion_challenge
    }

    pub const fn bridge_divisibility_receipt_commitment(&self) -> &[u8; 64] {
        &self.bridge_divisibility_receipt_commitment
    }
}

/// Cross-component bindings checked from opaque native verifier receipts.
///
/// This is intentionally not `VerifiedCompositeParent`: the pure OODS
/// semantic/H4 divisibility equations are a separate authority product and
/// must still be supplied before the parent can claim complete acceptance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCompositeParentComponentBindings {
    profile: Profile,
    final_transcript_root: [u8; 64],
    binding_commitment: [u8; 64],
    decisive_receipt_binding: BindingDigestV2,
}

impl VerifiedCompositeParentComponentBindings {
    pub const fn profile(&self) -> Profile {
        self.profile
    }

    pub const fn final_transcript_root(&self) -> &[u8; 64] {
        &self.final_transcript_root
    }

    pub const fn binding_commitment(&self) -> &[u8; 64] {
        &self.binding_commitment
    }

    pub const fn decisive_receipt_binding(&self) -> BindingDigestV2 {
        self.decisive_receipt_binding
    }
}

fn nonzero(value: &[u8; 64]) -> bool {
    value.iter().any(|byte| *byte != 0)
}

fn profile_from_u8(value: u8) -> Result<Profile, CompositeParentPublicCoinError> {
    match value {
        1 => Ok(Profile::K128Calibration),
        3 => Ok(Profile::K512Calibration),
        _ => Err(CompositeParentPublicCoinError::Profile),
    }
}

fn expected_bridge_program(profile: Profile) -> Result<[u8; 64], CompositeParentPublicCoinError> {
    let hex = match profile {
        Profile::K128Calibration => b"2b6c174d9ce183e1f6e5e2bc51e4c411f55ba5997aa2f87b81ca062c8473e33be60406d97d2dbd17958bf8fdbe89ab92b44cdb8acf48a09ca879310a635cd29f" as &[u8],
        Profile::K512Calibration => b"b1962cd2423238664861bc6f2551c0da9b362febcfc9b48e5ac8b2dda613973d7ec080dd3ad4e5ffcc9978d3bd8b395a9677c9b7be0fefdfb9fdeed4b4d1c966" as &[u8],
        Profile::K256DesignPoint => return Err(CompositeParentPublicCoinError::Profile),
    };
    let mut result = [0_u8; 64];
    for (index, byte) in result.iter_mut().enumerate() {
        let hi = hex_nibble(hex[2 * index])?;
        let lo = hex_nibble(hex[2 * index + 1])?;
        *byte = (hi << 4) | lo;
    }
    Ok(result)
}

fn hex_nibble(value: u8) -> Result<u8, CompositeParentPublicCoinError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(CompositeParentPublicCoinError::Message),
    }
}

fn direct_quotient_commitment(
    profile: Profile,
    group: BridgeQuotientGroup,
    bridge_program_commitment: &[u8; 64],
    base_root: &[u8; 64],
    pad_root: &[u8; 64],
    answer_root: &[u8; 64],
    coefficients: &[Fp16],
) -> Result<[u8; 64], CompositeParentPublicCoinError> {
    if coefficients.len() != BRIDGE_QUOTIENT_COEFFICIENT_COUNT {
        return Err(CompositeParentPublicCoinError::Length);
    }
    let mut hash = Sha3_512::new();
    hash.update(DIRECT_QUOTIENT_DOMAIN);
    hash.update([profile as u8, group as u8, QUOTIENT_BASIS_CODE]);
    hash.update((BRIDGE_QUOTIENT_COEFFICIENT_COUNT as u16).to_be_bytes());
    hash.update(bridge_program_commitment);
    hash.update(base_root);
    hash.update(pad_root);
    hash.update(answer_root);
    for coefficient in coefficients {
        hash.update(coefficient.encode());
    }
    Ok(hash.finalize().into())
}

fn descriptor(kind: u16) -> ChainedRoundDescriptor {
    ChainedRoundDescriptor {
        kind,
        ordinal: 0,
        output_count: 1,
    }
}

pub fn composite_parent_schedule_commitment(
    profile: Profile,
    parent_program_commitment: &[u8; 64],
) -> Result<[u8; 64], CompositeParentPublicCoinError> {
    if !matches!(profile, Profile::K128Calibration | Profile::K512Calibration)
        || !nonzero(parent_program_commitment)
    {
        return Err(CompositeParentPublicCoinError::Profile);
    }
    let mut hash = Sha3_512::new();
    hash.update(SCHEDULE_DOMAIN);
    hash.update([profile as u8]);
    hash.update(parent_program_commitment);
    for item in [
        descriptor(COMPOSITE_PARENT_PRE_ALPHA_KIND),
        descriptor(COMPOSITE_PARENT_QUOTIENT_KIND),
        descriptor(COMPOSITE_PARENT_FINAL_KIND),
    ] {
        hash.update(item.encode());
    }
    Ok(hash.finalize().into())
}

/// Live producer state after parent round 900 has fixed both child root
/// inventories and sampled the bridge batching coefficient.  The public-coin
/// process remains owned by this value; consuming it is the only way to enter
/// round 901.
#[cfg(feature = "std")]
pub struct CompositeParentAfterRound900 {
    coordinator: ChainedPublicCoinCoordinator,
    pre_alpha: CompositeParentPreAlphaMessage,
    bridge_alpha: Fp16,
    round_900_transcript_root: [u8; 64],
}

#[cfg(feature = "std")]
impl CompositeParentAfterRound900 {
    pub const fn bridge_alpha(&self) -> Fp16 {
        self.bridge_alpha
    }

    pub const fn round_900_transcript_root(&self) -> &[u8; 64] {
        &self.round_900_transcript_root
    }

    pub const fn profile(&self) -> Profile {
        self.pre_alpha.profile
    }

    /// Return the exact round-900 prover message already accepted by the
    /// parent coordinator. The global strict coin must absorb these identical
    /// bytes before quotient production uses its bridge challenge.
    pub fn round_900_message(&self) -> Result<Vec<u8>, CompositeParentPublicCoinError> {
        self.pre_alpha.encode()
    }

    /// Bind the exact degree-bounded quotient coefficient vectors and derive
    /// the canonical OODS point from round 901.  This consumes the round-900
    /// state so the quotient message cannot be replaced after OODS material
    /// begins production.
    pub fn absorb_quotient(
        mut self,
        quotient_template_encoded: &[u8],
    ) -> Result<CompositeParentAfterRound901, CompositeParentPublicCoinError> {
        let mut quotient =
            CompositeParentQuotientMessage::decode_template(quotient_template_encoded)?;
        if quotient.profile != self.pre_alpha.profile
            || quotient.bridge_program_commitment
                != expected_bridge_program(self.pre_alpha.profile)?
        {
            return Err(CompositeParentPublicCoinError::Message);
        }
        quotient.prior_transcript_root = self.coordinator.transcript_root();
        let quotient_bytes = quotient.encode()?;
        let challenge = self
            .coordinator
            .challenge_with_evidence(descriptor(COMPOSITE_PARENT_QUOTIENT_KIND), &quotient_bytes)?;
        if challenge.field_elements.len() != 1 || challenge.field_elements[0].is_zero() {
            return Err(CompositeParentPublicCoinError::Descriptor);
        }
        let round_901_transcript_root = self.coordinator.transcript_root();
        let sampled = sample_oods_parameter(
            &challenge.seed,
            &self.pre_alpha.composite_session_id,
            1,
            OODS_DEFAULT_MAX_ATTEMPTS,
        )?;
        let oods_point = stereographic_circle_point(sampled.parameter)?;
        let direct_quotient_commitments = DirectBridgeQuotientCommitments {
            message: direct_quotient_commitment(
                self.pre_alpha.profile,
                BridgeQuotientGroup::Message,
                &quotient.bridge_program_commitment,
                &self.pre_alpha.bridge_mask_base_aggregate_root,
                &self.pre_alpha.bridge_mask_pad_aggregate_root,
                &quotient.bridge_mask_answer_aggregate_root,
                &quotient.message_quotient_coefficients,
            )?,
            digest: direct_quotient_commitment(
                self.pre_alpha.profile,
                BridgeQuotientGroup::Digest,
                &quotient.bridge_program_commitment,
                &self.pre_alpha.bridge_mask_base_aggregate_root,
                &self.pre_alpha.bridge_mask_pad_aggregate_root,
                &quotient.bridge_mask_answer_aggregate_root,
                &quotient.digest_quotient_coefficients,
            )?,
        };
        Ok(CompositeParentAfterRound901 {
            coordinator: self.coordinator,
            pre_alpha: self.pre_alpha,
            bridge_alpha: self.bridge_alpha,
            round_900_transcript_root: self.round_900_transcript_root,
            round_901_transcript_root,
            oods_point,
            quotient,
            direct_quotient_commitments,
        })
    }
}

/// Live producer state after the OODS point is fixed and before final parent
/// completion.  Semantic continuation, H4 post-Z, and typed-state verification
/// may run while this state owns the same public-coin process.
#[cfg(feature = "std")]
pub struct CompositeParentAfterRound901 {
    coordinator: ChainedPublicCoinCoordinator,
    pre_alpha: CompositeParentPreAlphaMessage,
    bridge_alpha: Fp16,
    round_900_transcript_root: [u8; 64],
    round_901_transcript_root: [u8; 64],
    oods_point: CirclePoint,
    quotient: CompositeParentQuotientMessage,
    direct_quotient_commitments: DirectBridgeQuotientCommitments,
}

#[cfg(feature = "std")]
impl CompositeParentAfterRound901 {
    pub const fn profile(&self) -> Profile {
        self.pre_alpha.profile
    }

    pub const fn bridge_alpha(&self) -> Fp16 {
        self.bridge_alpha
    }

    pub const fn oods_point(&self) -> CirclePoint {
        self.oods_point
    }

    pub const fn round_900_transcript_root(&self) -> &[u8; 64] {
        &self.round_900_transcript_root
    }

    pub const fn round_901_transcript_root(&self) -> &[u8; 64] {
        &self.round_901_transcript_root
    }

    pub const fn parent_session_id(&self) -> &[u8; 64] {
        &self.pre_alpha.composite_session_id
    }

    pub const fn semantic_composition_root(&self) -> &[u8; 64] {
        &self.pre_alpha.semantic_composition_root
    }

    pub const fn bridge_program_commitment(&self) -> &[u8; 64] {
        &self.quotient.bridge_program_commitment
    }

    pub const fn bridge_mask_answer_aggregate_root(&self) -> &[u8; 64] {
        &self.quotient.bridge_mask_answer_aggregate_root
    }

    pub const fn direct_quotient_commitments(&self) -> &DirectBridgeQuotientCommitments {
        &self.direct_quotient_commitments
    }

    pub fn direct_quotient_coefficients(&self, group: BridgeQuotientGroup) -> &[Fp16] {
        match group {
            BridgeQuotientGroup::Message => &self.quotient.message_quotient_coefficients,
            BridgeQuotientGroup::Digest => &self.quotient.digest_quotient_coefficients,
        }
    }

    /// Return the exact round-901 prover message already accepted by the
    /// parent coordinator. Its predecessor root is coordinator-owned and has
    /// already been filled into the retained quotient message.
    pub fn round_901_message(&self) -> Result<Vec<u8>, CompositeParentPublicCoinError> {
        self.quotient.encode()
    }

    /// Fill the final parent predecessor root without consuming the live
    /// parent transaction. This lets the global strict coin absorb the exact
    /// round-902 bytes before the legacy parent audit chain commits them.
    pub fn prepare_final_message(
        &self,
        final_template_encoded: &[u8],
    ) -> Result<Vec<u8>, CompositeParentPublicCoinError> {
        let mut final_message =
            CompositeParentFinalMessage::decode_template(final_template_encoded)?;
        final_message.prior_transcript_root = self.coordinator.transcript_root();
        final_message.encode()
    }

    /// Bind the post-OODS component receipts in round 902 and return a fully
    /// replay-checked three-round parent bundle.  The final template's prior
    /// root must be zero; this producer fills it from its live round-901 state.
    pub fn finish(
        self,
        final_template_encoded: &[u8],
    ) -> Result<Vec<u8>, CompositeParentPublicCoinError> {
        let final_bytes = self.prepare_final_message(final_template_encoded)?;
        self.finish_encoded(&final_bytes)
    }

    /// Consume an exact final message previously returned by
    /// [`Self::prepare_final_message`]. Any byte substitution, including a
    /// stale predecessor root, fails before the parent coordinator advances.
    pub fn finish_encoded(
        mut self,
        final_bytes: &[u8],
    ) -> Result<Vec<u8>, CompositeParentPublicCoinError> {
        let final_message = CompositeParentFinalMessage::decode(final_bytes)?;
        if final_message.prior_transcript_root != self.coordinator.transcript_root() {
            return Err(CompositeParentPublicCoinError::Message);
        }
        let outputs = self
            .coordinator
            .challenge(descriptor(COMPOSITE_PARENT_FINAL_KIND), final_bytes)?;
        if outputs.len() != 1 || outputs[0].is_zero() {
            return Err(CompositeParentPublicCoinError::Descriptor);
        }
        let bundle = self.coordinator.finish_bundle()?;
        let encoded = encode_chained_public_coin_bundle(&bundle)?;
        let decoded = decode_chained_public_coin_bundle(&encoded)?;
        let replayed = verify_chained_public_coin_bundle(&decoded)?;
        if replayed.len() != COMPOSITE_PARENT_ROUND_COUNT
            || replayed.iter().any(|challenge| {
                challenge.field_elements.len() != 1 || challenge.field_elements[0].is_zero()
            })
        {
            return Err(CompositeParentPublicCoinError::Descriptor);
        }
        Ok(encoded)
    }
}

/// Start the staged parent producer and authenticate round 900.  This is the
/// executable sequencing seam required by real proof production: callers can
/// now run post-OODS component producers between rounds 901 and 902 without
/// restarting or predicting the parent public coin.
#[cfg(feature = "std")]
pub fn begin_composite_parent_production(
    service_program: &Path,
    pre_alpha_encoded: &[u8],
) -> Result<CompositeParentAfterRound900, CompositeParentPublicCoinError> {
    let pre_alpha = CompositeParentPreAlphaMessage::decode(pre_alpha_encoded)?;
    let expected_schedule = composite_parent_schedule_commitment(
        pre_alpha.profile,
        &pre_alpha.parent_program_commitment,
    )?;
    if pre_alpha.schedule_commitment != expected_schedule {
        return Err(CompositeParentPublicCoinError::Schedule);
    }
    let mut coordinator = ChainedPublicCoinCoordinator::spawn(
        service_program,
        pre_alpha.composite_session_id,
        pre_alpha.attempt,
        expected_schedule,
        COMPOSITE_PARENT_ROUND_COUNT as u32,
    )?;
    let pre_alpha_bytes = pre_alpha.encode()?;
    let outputs = coordinator.challenge(
        descriptor(COMPOSITE_PARENT_PRE_ALPHA_KIND),
        &pre_alpha_bytes,
    )?;
    if outputs.len() != 1 || outputs[0].is_zero() {
        return Err(CompositeParentPublicCoinError::Descriptor);
    }
    Ok(CompositeParentAfterRound900 {
        round_900_transcript_root: coordinator.transcript_root(),
        coordinator,
        pre_alpha,
        bridge_alpha: outputs[0],
    })
}

/// Produce the authenticated parent 900/901/902 chain from exact message
/// templates and the local dual-PQ public-coin services.
///
/// The quotient and final templates must carry an all-zero
/// `prior_transcript_root`. Those two fields are owned by this coordinator and
/// are filled only from the native transcript root after the preceding round
/// has been accepted. The returned bytes are a verified chained-public-coin
/// bundle, but they are not a complete parent acceptance receipt: the pure
/// post-z bridge/source verifier must still produce
/// `VerifiedPostZBridgeOpenings` before the parent can complete.
#[cfg(feature = "std")]
pub fn produce_composite_parent_bundle(
    service_program: &Path,
    pre_alpha_encoded: &[u8],
    quotient_template_encoded: &[u8],
    final_template_encoded: &[u8],
) -> Result<Vec<u8>, CompositeParentPublicCoinError> {
    begin_composite_parent_production(service_program, pre_alpha_encoded)?
        .absorb_quotient(quotient_template_encoded)?
        .finish(final_template_encoded)
}

fn push_digest(output: &mut Vec<u8>, value: &[u8; 64]) {
    output.extend_from_slice(value);
}

impl CompositeParentPreAlphaMessage {
    pub fn encode(&self) -> Result<Vec<u8>, CompositeParentPublicCoinError> {
        if !matches!(
            self.profile,
            Profile::K128Calibration | Profile::K512Calibration
        ) || self.attempt >= COMPOSITE_PARENT_MAX_ATTEMPTS
        {
            return Err(CompositeParentPublicCoinError::Attempt);
        }
        let digests = self.digests();
        if digests.iter().any(|value| !nonzero(value)) {
            return Err(CompositeParentPublicCoinError::ZeroCommitment);
        }
        let mut output = Vec::with_capacity(PRE_ALPHA_BYTES);
        output.extend_from_slice(PRE_ALPHA_MAGIC);
        output.extend_from_slice(&MESSAGE_VERSION.to_be_bytes());
        output.extend_from_slice(&MESSAGE_FLAGS.to_be_bytes());
        output.push(self.profile as u8);
        output.extend_from_slice(&[0_u8; 7]);
        push_digest(&mut output, &self.composite_session_id);
        output.extend_from_slice(&self.attempt.to_be_bytes());
        output.extend_from_slice(&[0_u8; 6]);
        push_digest(&mut output, &self.schedule_commitment);
        for value in digests {
            push_digest(&mut output, value);
        }
        if output.len() != PRE_ALPHA_BYTES {
            return Err(CompositeParentPublicCoinError::Length);
        }
        Ok(output)
    }

    fn digests(&self) -> [&[u8; 64]; PRE_ALPHA_DIGESTS] {
        [
            &self.parent_program_commitment,
            &self.candidate_descriptor_commitment,
            &self.statement_commitment,
            &self.semantic_program_commitment,
            &self.semantic_session_id,
            &self.semantic_schedule_commitment,
            &self.semantic_contributor_set_commitment,
            &self.semantic_prefix_receipt_commitment,
            &self.semantic_round_1_transcript_root,
            &self.semantic_main_root,
            &self.semantic_interaction_root,
            &self.semantic_composition_root,
            &self.h4_child_final_root,
            &self.h4_ordered_shard_root_receipt,
            &self.h4_source_root,
            &self.h4_b_tensor_root,
            &self.h4_n_tensor_root,
            &self.h4_a_tensor_root,
            &self.bridge_mask_base_aggregate_root,
            &self.bridge_mask_pad_aggregate_root,
        ]
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, CompositeParentPublicCoinError> {
        if encoded.len() != PRE_ALPHA_BYTES {
            return Err(CompositeParentPublicCoinError::Length);
        }
        let mut reader = Reader::new(encoded);
        reader.header(PRE_ALPHA_MAGIC)?;
        let profile = profile_from_u8(reader.u8()?)?;
        reader.zeros(7)?;
        let composite_session_id = reader.digest()?;
        let attempt = reader.u16()?;
        reader.zeros(6)?;
        let schedule_commitment = reader.digest()?;
        let values = reader.digests::<PRE_ALPHA_DIGESTS>()?;
        let result = Self {
            profile,
            composite_session_id,
            attempt,
            schedule_commitment,
            parent_program_commitment: values[0],
            candidate_descriptor_commitment: values[1],
            statement_commitment: values[2],
            semantic_program_commitment: values[3],
            semantic_session_id: values[4],
            semantic_schedule_commitment: values[5],
            semantic_contributor_set_commitment: values[6],
            semantic_prefix_receipt_commitment: values[7],
            semantic_round_1_transcript_root: values[8],
            semantic_main_root: values[9],
            semantic_interaction_root: values[10],
            semantic_composition_root: values[11],
            h4_child_final_root: values[12],
            h4_ordered_shard_root_receipt: values[13],
            h4_source_root: values[14],
            h4_b_tensor_root: values[15],
            h4_n_tensor_root: values[16],
            h4_a_tensor_root: values[17],
            bridge_mask_base_aggregate_root: values[18],
            bridge_mask_pad_aggregate_root: values[19],
        };
        result.encode()?;
        Ok(result)
    }
}

impl CompositeParentQuotientMessage {
    pub fn encode(&self) -> Result<Vec<u8>, CompositeParentPublicCoinError> {
        let values = [
            &self.prior_transcript_root,
            &self.bridge_program_commitment,
            &self.bridge_mask_answer_aggregate_root,
        ];
        if !matches!(
            self.profile,
            Profile::K128Calibration | Profile::K512Calibration
        ) || self.bridge_program_commitment != expected_bridge_program(self.profile)?
        {
            return Err(CompositeParentPublicCoinError::Profile);
        }
        if values.iter().any(|value| !nonzero(value)) {
            return Err(CompositeParentPublicCoinError::ZeroCommitment);
        }
        if self.message_quotient_coefficients.len() != BRIDGE_QUOTIENT_COEFFICIENT_COUNT
            || self.digest_quotient_coefficients.len() != BRIDGE_QUOTIENT_COEFFICIENT_COUNT
        {
            return Err(CompositeParentPublicCoinError::Length);
        }
        let mut output = Vec::with_capacity(QUOTIENT_BYTES);
        output.extend_from_slice(QUOTIENT_MAGIC);
        output.extend_from_slice(&MESSAGE_VERSION.to_be_bytes());
        output.extend_from_slice(&MESSAGE_FLAGS.to_be_bytes());
        output.push(self.profile as u8);
        output.extend_from_slice(&[0_u8; 7]);
        for value in values {
            push_digest(&mut output, value);
        }
        self.push_group(
            &mut output,
            BridgeQuotientGroup::Message,
            &self.message_quotient_coefficients,
        );
        self.push_group(
            &mut output,
            BridgeQuotientGroup::Digest,
            &self.digest_quotient_coefficients,
        );
        if output.len() != QUOTIENT_BYTES {
            return Err(CompositeParentPublicCoinError::Length);
        }
        Ok(output)
    }

    fn push_group(&self, output: &mut Vec<u8>, group: BridgeQuotientGroup, coefficients: &[Fp16]) {
        output.push(group as u8);
        output.push(QUOTIENT_BASIS_CODE);
        output.extend_from_slice(&(BRIDGE_QUOTIENT_COEFFICIENT_COUNT as u16).to_be_bytes());
        output.extend_from_slice(&[0_u8; 4]);
        for coefficient in coefficients {
            output.extend_from_slice(&coefficient.encode());
        }
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, CompositeParentPublicCoinError> {
        let result = Self::decode_unchecked(encoded)?;
        result.encode()?;
        Ok(result)
    }

    /// Decode a producer template whose transcript predecessor is intentionally
    /// left empty.  Only the producer may replace that field, and the rest of
    /// the canonical message is still validated before any public-coin round
    /// is started.
    pub fn decode_template(encoded: &[u8]) -> Result<Self, CompositeParentPublicCoinError> {
        let result = Self::decode_unchecked(encoded)?;
        if nonzero(&result.prior_transcript_root) {
            return Err(CompositeParentPublicCoinError::Message);
        }
        let mut checked = result.clone();
        checked.prior_transcript_root = [1_u8; 64];
        checked.encode()?;
        Ok(result)
    }

    fn decode_unchecked(encoded: &[u8]) -> Result<Self, CompositeParentPublicCoinError> {
        if encoded.len() != QUOTIENT_BYTES {
            return Err(CompositeParentPublicCoinError::Length);
        }
        let mut reader = Reader::new(encoded);
        reader.header(QUOTIENT_MAGIC)?;
        let profile = profile_from_u8(reader.u8()?)?;
        reader.zeros(7)?;
        let values = reader.digests::<QUOTIENT_FIXED_DIGESTS>()?;
        let message_quotient_coefficients = reader.quotient_group(BridgeQuotientGroup::Message)?;
        let digest_quotient_coefficients = reader.quotient_group(BridgeQuotientGroup::Digest)?;
        if reader.offset != encoded.len() {
            return Err(CompositeParentPublicCoinError::Length);
        }
        let result = Self {
            profile,
            prior_transcript_root: values[0],
            bridge_program_commitment: values[1],
            bridge_mask_answer_aggregate_root: values[2],
            message_quotient_coefficients,
            digest_quotient_coefficients,
        };
        Ok(result)
    }
}

impl CompositeParentFinalMessage {
    pub fn encode(&self) -> Result<Vec<u8>, CompositeParentPublicCoinError> {
        let values = self.digests();
        if values.iter().any(|value| !nonzero(value)) {
            return Err(CompositeParentPublicCoinError::ZeroCommitment);
        }
        let mut output = Vec::with_capacity(FINAL_BYTES);
        output.extend_from_slice(FINAL_MAGIC);
        output.extend_from_slice(&MESSAGE_VERSION.to_be_bytes());
        output.extend_from_slice(&MESSAGE_FLAGS.to_be_bytes());
        for value in values {
            push_digest(&mut output, value);
        }
        Ok(output)
    }

    fn digests(&self) -> [&[u8; 64]; FINAL_DIGESTS] {
        [
            &self.prior_transcript_root,
            &self.post_z_primitive_response_oracle_root,
            &self.post_z_primitive_claim_vector_commitment,
            &self.semantic_continuation_final_root,
            &self.semantic_component_package_commitment,
            &self.h4_component_package_commitment,
            &self.typed_component_package_commitment,
            &self.typed_verified_receipt_commitment,
            &self.h4_booleanity_receipt_commitment,
            &self.h4_global_padding_receipt_commitment,
            &self.bridge_privacy_ledger_commitment,
            &self.semantic_exposure_ledger_commitment,
            &self.h4_exposure_ledger_commitment,
        ]
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, CompositeParentPublicCoinError> {
        let result = Self::decode_unchecked(encoded)?;
        result.encode()?;
        Ok(result)
    }

    /// Decode a producer template whose predecessor root will be filled from
    /// the authenticated round-901 transcript root.
    pub fn decode_template(encoded: &[u8]) -> Result<Self, CompositeParentPublicCoinError> {
        let result = Self::decode_unchecked(encoded)?;
        if nonzero(&result.prior_transcript_root) {
            return Err(CompositeParentPublicCoinError::Message);
        }
        let mut checked = result.clone();
        checked.prior_transcript_root = [1_u8; 64];
        checked.encode()?;
        Ok(result)
    }

    fn decode_unchecked(encoded: &[u8]) -> Result<Self, CompositeParentPublicCoinError> {
        if encoded.len() != FINAL_BYTES {
            return Err(CompositeParentPublicCoinError::Length);
        }
        let mut reader = Reader::new(encoded);
        reader.header(FINAL_MAGIC)?;
        let values = reader.digests::<FINAL_DIGESTS>()?;
        let result = Self {
            prior_transcript_root: values[0],
            post_z_primitive_response_oracle_root: values[1],
            post_z_primitive_claim_vector_commitment: values[2],
            semantic_continuation_final_root: values[3],
            semantic_component_package_commitment: values[4],
            h4_component_package_commitment: values[5],
            typed_component_package_commitment: values[6],
            typed_verified_receipt_commitment: values[7],
            h4_booleanity_receipt_commitment: values[8],
            h4_global_padding_receipt_commitment: values[9],
            bridge_privacy_ledger_commitment: values[10],
            semantic_exposure_ledger_commitment: values[11],
            h4_exposure_ledger_commitment: values[12],
        };
        Ok(result)
    }
}

pub fn verify_composite_parent_prefix(
    encoded_bundle: &[u8],
    expected_pre_alpha: &CompositeParentPreAlphaMessage,
    semantic_prefix: &VerifiedSemanticV3Prefix,
) -> Result<VerifiedCompositeParentPrefix, CompositeParentPublicCoinError> {
    let bundle = decode_chained_public_coin_bundle(encoded_bundle)?;
    if bundle.attempt >= COMPOSITE_PARENT_MAX_ATTEMPTS {
        return Err(CompositeParentPublicCoinError::Attempt);
    }
    let expected_schedule = composite_parent_schedule_commitment(
        expected_pre_alpha.profile,
        &expected_pre_alpha.parent_program_commitment,
    )?;
    if bundle.session_id != expected_pre_alpha.composite_session_id
        || bundle.attempt != expected_pre_alpha.attempt
        || bundle.schedule_commitment != expected_schedule
        || expected_pre_alpha.schedule_commitment != expected_schedule
    {
        return Err(CompositeParentPublicCoinError::Schedule);
    }
    let expected_descriptors = [
        descriptor(COMPOSITE_PARENT_PRE_ALPHA_KIND),
        descriptor(COMPOSITE_PARENT_QUOTIENT_KIND),
        descriptor(COMPOSITE_PARENT_FINAL_KIND),
    ];
    if bundle.rounds.len() != COMPOSITE_PARENT_ROUND_COUNT
        || bundle
            .rounds
            .iter()
            .zip(expected_descriptors)
            .any(|(round, expected)| round.descriptor != expected)
    {
        return Err(CompositeParentPublicCoinError::Descriptor);
    }
    let challenges = verify_chained_public_coin_bundle(&bundle)?;
    if challenges.len() != COMPOSITE_PARENT_ROUND_COUNT {
        return Err(CompositeParentPublicCoinError::Descriptor);
    }
    let parsed_pre_alpha =
        CompositeParentPreAlphaMessage::decode(&bundle.rounds[0].prover_message)?;
    if parsed_pre_alpha != *expected_pre_alpha {
        return Err(CompositeParentPublicCoinError::Message);
    }
    if parsed_pre_alpha.profile != semantic_prefix.profile()
        || parsed_pre_alpha.semantic_program_commitment
            != semantic_prefix.semantic_program_commitment()
        || parsed_pre_alpha.statement_commitment != semantic_prefix.statement_commitment()
        || parsed_pre_alpha.semantic_session_id != semantic_prefix.semantic_session_id()
        || parsed_pre_alpha.semantic_schedule_commitment
            != semantic_prefix.semantic_schedule_commitment()
        || parsed_pre_alpha.semantic_contributor_set_commitment
            != semantic_prefix.contributor_set_commitment()
        || parsed_pre_alpha.semantic_prefix_receipt_commitment
            != semantic_prefix.receipt_commitment()
        || parsed_pre_alpha.semantic_round_1_transcript_root
            != semantic_prefix.round_1_transcript_root()
        || parsed_pre_alpha.semantic_main_root != semantic_prefix.main_trace_root()
        || parsed_pre_alpha.semantic_interaction_root != semantic_prefix.interaction_trace_root()
    {
        return Err(CompositeParentPublicCoinError::SemanticPrefix);
    }
    let parsed_quotient = CompositeParentQuotientMessage::decode(&bundle.rounds[1].prover_message)?;
    if parsed_quotient.profile != expected_pre_alpha.profile
        || parsed_quotient.bridge_program_commitment
            != expected_bridge_program(expected_pre_alpha.profile)?
    {
        return Err(CompositeParentPublicCoinError::Message);
    }
    if parsed_quotient.prior_transcript_root != challenges[0].transcript_root {
        return Err(CompositeParentPublicCoinError::PriorTranscriptRoot);
    }
    let final_message = CompositeParentFinalMessage::decode(&bundle.rounds[2].prover_message)?;
    if final_message.prior_transcript_root != challenges[1].transcript_root {
        return Err(CompositeParentPublicCoinError::PriorTranscriptRoot);
    }
    let sampled = sample_oods_parameter(
        &challenges[1].seed,
        &bundle.session_id,
        1,
        OODS_DEFAULT_MAX_ATTEMPTS,
    )?;
    let oods_point = stereographic_circle_point(sampled.parameter)?;
    let direct_quotient_commitments = DirectBridgeQuotientCommitments {
        message: direct_quotient_commitment(
            expected_pre_alpha.profile,
            BridgeQuotientGroup::Message,
            &parsed_quotient.bridge_program_commitment,
            &expected_pre_alpha.bridge_mask_base_aggregate_root,
            &expected_pre_alpha.bridge_mask_pad_aggregate_root,
            &parsed_quotient.bridge_mask_answer_aggregate_root,
            &parsed_quotient.message_quotient_coefficients,
        )?,
        digest: direct_quotient_commitment(
            expected_pre_alpha.profile,
            BridgeQuotientGroup::Digest,
            &parsed_quotient.bridge_program_commitment,
            &expected_pre_alpha.bridge_mask_base_aggregate_root,
            &expected_pre_alpha.bridge_mask_pad_aggregate_root,
            &parsed_quotient.bridge_mask_answer_aggregate_root,
            &parsed_quotient.digest_quotient_coefficients,
        )?,
    };
    Ok(VerifiedCompositeParentPrefix {
        profile: expected_pre_alpha.profile,
        session_id: bundle.session_id,
        attempt: bundle.attempt,
        bridge_alpha: one_field(&challenges[0])?,
        oods_point,
        round_900_transcript_root: challenges[0].transcript_root,
        round_901_transcript_root: challenges[1].transcript_root,
        final_transcript_root: challenges[2].transcript_root,
        completion_challenge: one_field(&challenges[2])?,
        bridge_mask_answer_aggregate_root: parsed_quotient.bridge_mask_answer_aggregate_root,
        direct_quotient_commitments,
        message_quotient_coefficients: parsed_quotient.message_quotient_coefficients,
        digest_quotient_coefficients: parsed_quotient.digest_quotient_coefficients,
        semantic_prefix: semantic_prefix.clone(),
        semantic_composition_root: parsed_pre_alpha.semantic_composition_root,
        bridge_program_commitment: parsed_quotient.bridge_program_commitment,
        final_message,
    })
}

fn profile_code(profile: Profile) -> Result<u8, CompositeParentPublicCoinError> {
    match profile {
        Profile::K128Calibration => Ok(1),
        Profile::K512Calibration => Ok(3),
        Profile::K256DesignPoint => Err(CompositeParentPublicCoinError::Profile),
    }
}

fn legacy_binding_commitment(
    domain: &[u8],
    profile: Profile,
    pieces: &[&[u8]],
) -> Result<[u8; 64], CompositeParentPublicCoinError> {
    let mut hash = Sha3_512::new();
    hash.update(domain);
    hash.update([profile_code(profile)?]);
    for piece in pieces {
        hash.update(piece);
    }
    Ok(hash.finalize().into())
}

/// Derive the exact round-902 parent message from opaque verifier receipts.
/// The prior transcript root remains zero because the staged parent producer
/// owns and fills it from its live round-901 state. No component package
/// commitment is accepted from a caller.
#[allow(clippy::too_many_arguments)]
pub fn derive_composite_parent_final_message(
    profile: Profile,
    strict: &VerifiedStrictSemanticV3PublicCoin,
    semantic: &VerifiedFriPipelineV3,
    continuation: &VerifiedSemanticV3Continuation,
    h4: &VerifiedH4V2,
    typed: &VerifiedTypedStateV3,
    decisive: &VerifiedDecisiveCompositionV3,
) -> Result<CompositeParentFinalMessage, CompositeParentPublicCoinError> {
    if strict.profile() != profile
        || typed.governed_profile_code() != profile_code(profile)?
        || decisive.profile() != profile
        || h4.profile().code() != profile_code(profile)?
    {
        return Err(CompositeParentPublicCoinError::ComponentBinding);
    }
    derive_composite_parent_final_template_from_pre_final(
        profile,
        strict.pre_final_transcript_root(),
        strict.oods_point(),
        semantic,
        continuation,
        h4,
        typed,
    )
}

/// Derive the round-902 template from receipts available after post-Z and the
/// strict transcript checkpoint immediately before round 902.
///
/// This is a producer transport helper, not an accepting authority. The
/// verifier calls [`derive_composite_parent_final_message`] after replaying
/// the complete strict transcript and byte-compares the resulting message.
/// Using the pre-final checkpoint is essential: including the final root in
/// the message that creates that root would make honest production
/// self-referential and impossible.
#[allow(clippy::too_many_arguments)]
pub fn derive_composite_parent_final_template_from_pre_final(
    profile: Profile,
    strict_pre_final_transcript_root: &[u8; 128],
    strict_oods_point: CirclePoint,
    semantic: &VerifiedFriPipelineV3,
    continuation: &VerifiedSemanticV3Continuation,
    h4: &VerifiedH4V2,
    typed: &VerifiedTypedStateV3,
) -> Result<CompositeParentFinalMessage, CompositeParentPublicCoinError> {
    if typed.governed_profile_code() != profile_code(profile)?
        || h4.profile().code() != profile_code(profile)?
        || semantic.query_point() != strict_oods_point
        || !strict_pre_final_transcript_root
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(CompositeParentPublicCoinError::ComponentBinding);
    }
    let zero_interaction = [0_u8; 128];
    let interaction = semantic
        .oracle_roots()
        .interaction_trace
        .as_ref()
        .map_or(zero_interaction.as_slice(), |root| {
            root.as_bytes().as_slice()
        });
    Ok(CompositeParentFinalMessage {
        prior_transcript_root: [0_u8; 64],
        post_z_primitive_response_oracle_root: legacy_binding_commitment(
            POST_Z_H4_RECEIPT_DOMAIN,
            profile,
            &[h4.post_z_response_oracle_root().as_bytes()],
        )?,
        post_z_primitive_claim_vector_commitment: legacy_binding_commitment(
            b"BL/PQ512/V3/COMPOSITE-PARENT/POST-Z-CLAIM-VECTOR/v1\0",
            profile,
            &[h4.post_z_claim_vector_commitment().as_bytes()],
        )?,
        semantic_continuation_final_root: *continuation.final_transcript_root(),
        semantic_component_package_commitment: legacy_binding_commitment(
            b"BL/PQ512/V3/COMPOSITE-PARENT/SEMANTIC-PACKAGE/v2\0",
            profile,
            &[
                strict_pre_final_transcript_root,
                semantic.program_binding().as_bytes(),
                semantic.public_inputs_binding().as_bytes(),
                semantic.oracle_roots().main_trace.as_bytes(),
                interaction,
                semantic.oracle_roots().composition.as_bytes(),
                continuation.final_transcript_root(),
            ],
        )?,
        h4_component_package_commitment: legacy_binding_commitment(
            b"BL/PQ512/V3/COMPOSITE-PARENT/H4-PACKAGE/v1\0",
            profile,
            &[
                h4.pre_alpha_binding().as_bytes(),
                h4.receipt_binding().as_bytes(),
                h4.source_binding().as_bytes(),
                h4.semantic_fri_binding().as_bytes(),
                h4.semantic_coefficient_root_inventory_binding().as_bytes(),
                h4.post_z_context().as_bytes(),
                h4.post_z_response_oracle_root().as_bytes(),
                h4.post_z_claim_vector_commitment().as_bytes(),
            ],
        )?,
        typed_component_package_commitment: legacy_binding_commitment(
            b"BL/PQ512/V3/COMPOSITE-PARENT/TYPED-PACKAGE/v1\0",
            profile,
            &[
                typed.public_inputs_binding().as_bytes(),
                typed.receipt_binding().as_bytes(),
            ],
        )?,
        typed_verified_receipt_commitment: legacy_binding_commitment(
            b"BL/PQ512/V3/COMPOSITE-PARENT/TYPED-RECEIPT/v1\0",
            profile,
            &[typed.receipt_binding().as_bytes()],
        )?,
        h4_booleanity_receipt_commitment: legacy_binding_commitment(
            b"BL/PQ512/V3/COMPOSITE-PARENT/H4-BOOLEANITY-LINEAGE/v1\0",
            profile,
            &[h4.receipt_binding().as_bytes()],
        )?,
        h4_global_padding_receipt_commitment: legacy_binding_commitment(
            b"BL/PQ512/V3/COMPOSITE-PARENT/H4-PADDING-LINEAGE/v1\0",
            profile,
            &[h4.receipt_binding().as_bytes()],
        )?,
        bridge_privacy_ledger_commitment: legacy_binding_commitment(
            b"BL/PQ512/V3/COMPOSITE-PARENT/BRIDGE-PRIVACY-LEDGER/v2\0",
            profile,
            &[
                strict_pre_final_transcript_root,
                semantic.receipt_binding().as_bytes(),
                h4.source_binding().as_bytes(),
                h4.receipt_binding().as_bytes(),
                typed.receipt_binding().as_bytes(),
            ],
        )?,
        semantic_exposure_ledger_commitment: legacy_binding_commitment(
            b"BL/PQ512/V3/COMPOSITE-PARENT/SEMANTIC-EXPOSURE-LEDGER/v2\0",
            profile,
            &[
                strict_pre_final_transcript_root,
                semantic.receipt_binding().as_bytes(),
                continuation.final_transcript_root(),
            ],
        )?,
        h4_exposure_ledger_commitment: legacy_binding_commitment(
            b"BL/PQ512/V3/COMPOSITE-PARENT/H4-EXPOSURE-LEDGER/v1\0",
            profile,
            &[
                h4.source_binding().as_bytes(),
                h4.post_z_response_oracle_root().as_bytes(),
                h4.post_z_claim_vector_commitment().as_bytes(),
                h4.receipt_binding().as_bytes(),
            ],
        )?,
    })
}

/// Replay only the serialized parent public-coin chain. The three message
/// bodies remain untrusted until `verify_composite_parent_prefix` binds them
/// to the independently verified semantic prefix and governed parent
/// context. This helper exists so an outer parser can retain a real replay
/// result without confusing it with parent completion.
pub fn verify_composite_parent_transcript(
    encoded_bundle: &[u8],
) -> Result<VerifiedCompositeParentTranscriptReplay, CompositeParentPublicCoinError> {
    let bundle = decode_chained_public_coin_bundle(encoded_bundle)?;
    if bundle.attempt >= COMPOSITE_PARENT_MAX_ATTEMPTS
        || bundle.rounds.len() != COMPOSITE_PARENT_ROUND_COUNT
    {
        return Err(CompositeParentPublicCoinError::Descriptor);
    }
    let expected_kinds = [
        COMPOSITE_PARENT_PRE_ALPHA_KIND,
        COMPOSITE_PARENT_QUOTIENT_KIND,
        COMPOSITE_PARENT_FINAL_KIND,
    ];
    if bundle.rounds.iter().enumerate().any(|(index, round)| {
        round.descriptor.kind != expected_kinds[index]
            || round.descriptor.ordinal != 0
            || round.descriptor.output_count != 1
    }) {
        return Err(CompositeParentPublicCoinError::Descriptor);
    }
    let challenges = verify_chained_public_coin_bundle(&bundle)?;
    if challenges.len() != COMPOSITE_PARENT_ROUND_COUNT
        || challenges.iter().any(|challenge| {
            challenge.field_elements.len() != 1 || challenge.field_elements[0].is_zero()
        })
    {
        return Err(CompositeParentPublicCoinError::ZeroChallenge);
    }
    Ok(VerifiedCompositeParentTranscriptReplay {
        round_900_transcript_root: challenges[0].transcript_root,
        round_901_transcript_root: challenges[1].transcript_root,
        final_transcript_root: challenges[2].transcript_root,
    })
}

/// Check every parent final-message component that is derivable from current
/// opaque native receipts. The returned receipt is bound to the decisive
/// composition result and can be consumed by the parent completion method.
pub fn verify_parent_component_bindings(
    prefix: &VerifiedCompositeParentPrefix,
    strict: &VerifiedStrictSemanticV3PublicCoin,
    semantic: &VerifiedFriPipelineV3,
    continuation: &VerifiedSemanticV3Continuation,
    h4: &VerifiedH4V2,
    typed: &VerifiedTypedStateV3,
    decisive: &VerifiedDecisiveCompositionV3,
) -> Result<VerifiedCompositeParentComponentBindings, CompositeParentPublicCoinError> {
    let profile = prefix.profile;
    let derived = derive_composite_parent_final_message(
        profile,
        strict,
        semantic,
        continuation,
        h4,
        typed,
        decisive,
    )?;
    let expected = [
        derived.post_z_primitive_response_oracle_root,
        derived.post_z_primitive_claim_vector_commitment,
        derived.semantic_continuation_final_root,
        derived.semantic_component_package_commitment,
        derived.h4_component_package_commitment,
        derived.typed_component_package_commitment,
        derived.typed_verified_receipt_commitment,
        derived.h4_booleanity_receipt_commitment,
        derived.h4_global_padding_receipt_commitment,
        derived.bridge_privacy_ledger_commitment,
        derived.semantic_exposure_ledger_commitment,
        derived.h4_exposure_ledger_commitment,
    ];
    let observed = [
        prefix.final_message.post_z_primitive_response_oracle_root,
        prefix
            .final_message
            .post_z_primitive_claim_vector_commitment,
        prefix.final_message.semantic_continuation_final_root,
        prefix.final_message.semantic_component_package_commitment,
        prefix.final_message.h4_component_package_commitment,
        prefix.final_message.typed_component_package_commitment,
        prefix.final_message.typed_verified_receipt_commitment,
        prefix.final_message.h4_booleanity_receipt_commitment,
        prefix.final_message.h4_global_padding_receipt_commitment,
        prefix.final_message.bridge_privacy_ledger_commitment,
        prefix.final_message.semantic_exposure_ledger_commitment,
        prefix.final_message.h4_exposure_ledger_commitment,
    ];
    if observed != expected {
        return Err(CompositeParentPublicCoinError::ComponentBinding);
    }
    let mut commitment = Sha3_512::new();
    commitment.update(b"BL/PQ512/V3/COMPOSITE-PARENT/VERIFIED-COMPONENT-BINDINGS/v1\0");
    commitment.update([profile_code(profile)?]);
    commitment.update(&prefix.final_transcript_root);
    for field in &expected {
        commitment.update(field);
    }
    commitment.update(decisive.receipt_binding().as_bytes());
    Ok(VerifiedCompositeParentComponentBindings {
        profile,
        final_transcript_root: prefix.final_transcript_root,
        binding_commitment: commitment.finalize().into(),
        decisive_receipt_binding: decisive.receipt_binding(),
    })
}

/// Complete the current parent authority seam from the exact opaque native
/// receipts. This is the coordinator entry point for parent completion; it
/// does not accept caller-supplied roots, flags, or post-z scalar pairs.
#[allow(clippy::too_many_arguments)]
pub fn complete_verified_composite_parent(
    prefix: VerifiedCompositeParentPrefix,
    strict: &VerifiedStrictSemanticV3PublicCoin,
    semantic: &VerifiedFriPipelineV3,
    continuation: &VerifiedSemanticV3Continuation,
    h4: &VerifiedH4V2,
    typed: &VerifiedTypedStateV3,
    decisive: &VerifiedDecisiveCompositionV3,
) -> Result<VerifiedCompositeParent, CompositeParentPublicCoinError> {
    let bindings = verify_parent_component_bindings(
        &prefix,
        strict,
        semantic,
        continuation,
        h4,
        typed,
        decisive,
    )?;
    prefix.complete_after_decisive_composition(bindings, decisive, strict)
}

/// Complete the parent from the proof-native Circle divisibility receipt.
///
/// This is the post-Z authority path. The receipt is constructed only by the
/// authenticated semantic/H4 bridge verifier, and carries the response-oracle
/// root, claim-vector commitment, completion challenge, and divisibility
/// commitment that the parent message fixes. No caller-supplied digest or
/// success flag can enter this path.
#[allow(clippy::too_many_arguments)]
pub fn complete_verified_composite_parent_after_bridge_divisibility(
    prefix: VerifiedCompositeParentPrefix,
    strict: &VerifiedStrictSemanticV3PublicCoin,
    semantic: &VerifiedFriPipelineV3,
    continuation: &VerifiedSemanticV3Continuation,
    h4: &VerifiedH4V2,
    typed: &VerifiedTypedStateV3,
    decisive: &VerifiedDecisiveCompositionV3,
    divisibility: &VerifiedBridgeDivisibility,
) -> Result<VerifiedCompositeParent, CompositeParentPublicCoinError> {
    let bindings = verify_parent_component_bindings(
        &prefix,
        strict,
        semantic,
        continuation,
        h4,
        typed,
        decisive,
    )?;
    prefix.complete_after_verified_bridge_divisibility(bindings, divisibility, strict)
}

/// Producer-facing name for the proof-native parent completion boundary.
///
/// The implementation intentionally remains one path: it consumes only the
/// opaque decisive and bridge-divisibility receipts and therefore cannot be
/// used to serialize caller-selected post-Z roots or a success flag.
#[allow(clippy::too_many_arguments)]
pub fn produce_verified_composite_parent_after_bridge_divisibility(
    prefix: VerifiedCompositeParentPrefix,
    strict: &VerifiedStrictSemanticV3PublicCoin,
    semantic: &VerifiedFriPipelineV3,
    continuation: &VerifiedSemanticV3Continuation,
    h4: &VerifiedH4V2,
    typed: &VerifiedTypedStateV3,
    decisive: &VerifiedDecisiveCompositionV3,
    divisibility: &VerifiedBridgeDivisibility,
) -> Result<VerifiedCompositeParent, CompositeParentPublicCoinError> {
    complete_verified_composite_parent_after_bridge_divisibility(
        prefix,
        strict,
        semantic,
        continuation,
        h4,
        typed,
        decisive,
        divisibility,
    )
}

/// The in-memory v3 coordinator authority. It consumes the four independently
/// verified component receipts, completes the decisive composition, and then
/// completes the already-authenticated 900/901/902 parent prefix from that
/// receipt. No serialized envelope, caller digest, or activation flag is
/// accepted as a substitute for a native receipt.
#[derive(Clone, Debug)]
pub struct VerifiedV3CompositeReceipt {
    pub profile: Profile,
    strict_final_transcript_root: [u8; 128],
    semantic_receipt_binding: BindingDigestV2,
    h4_receipt_binding: BindingDigestV2,
    typed_receipt_binding: BindingDigestV2,
    pub decisive_receipt_binding: BindingDigestV2,
    pub parent: VerifiedCompositeParent,
}

impl VerifiedV3CompositeReceipt {
    pub const fn decisive_receipt_binding(&self) -> BindingDigestV2 {
        self.decisive_receipt_binding
    }

    pub const fn parent(&self) -> &VerifiedCompositeParent {
        &self.parent
    }

    pub const fn strict_final_transcript_root(&self) -> &[u8; 128] {
        &self.strict_final_transcript_root
    }

    pub const fn semantic_receipt_binding(&self) -> BindingDigestV2 {
        self.semantic_receipt_binding
    }

    pub const fn h4_receipt_binding(&self) -> BindingDigestV2 {
        self.h4_receipt_binding
    }

    pub const fn typed_receipt_binding(&self) -> BindingDigestV2 {
        self.typed_receipt_binding
    }
}

/// Complete the library-level v3 coordinator from native verifier products.
/// This is deliberately separate from the outer serialized-envelope verifier:
/// the latter must still read and verify each on-disk component before it can
/// call this function.
#[allow(clippy::too_many_arguments)]
pub fn complete_verified_v3_composite(
    strict: VerifiedStrictSemanticV3PublicCoin,
    semantic: VerifiedFriPipelineV3,
    continuation: &VerifiedSemanticV3Continuation,
    h4: VerifiedH4V2,
    typed: VerifiedTypedStateV3,
    prefix: VerifiedCompositeParentPrefix,
) -> Result<VerifiedV3CompositeReceipt, CompositeParentPublicCoinError> {
    let decisive = complete_verified_decisive_composition_v3(
        strict.clone(),
        semantic.clone(),
        h4.clone(),
        typed.clone(),
    )?;
    let parent = complete_verified_composite_parent(
        prefix,
        &strict,
        &semantic,
        continuation,
        &h4,
        &typed,
        &decisive,
    )?;
    if parent.profile != decisive.profile() {
        return Err(CompositeParentPublicCoinError::ComponentBinding);
    }
    Ok(VerifiedV3CompositeReceipt {
        profile: parent.profile,
        strict_final_transcript_root: *strict.final_transcript_root(),
        semantic_receipt_binding: semantic.receipt_binding(),
        h4_receipt_binding: h4.receipt_binding(),
        typed_receipt_binding: typed.receipt_binding(),
        decisive_receipt_binding: decisive.receipt_binding(),
        parent,
    })
}

/// Complete the native v3 composition through the proof-native post-Z bridge
/// divisibility receipt. The ordinary library coordinator above remains the
/// decisive-composition boundary; this stricter variant is the one an outer
/// verifier must use once it has replayed the serialized bridge evidence.
#[allow(clippy::too_many_arguments)]
pub fn complete_verified_v3_composite_after_bridge_divisibility(
    strict: VerifiedStrictSemanticV3PublicCoin,
    semantic: VerifiedFriPipelineV3,
    continuation: &VerifiedSemanticV3Continuation,
    h4: VerifiedH4V2,
    typed: VerifiedTypedStateV3,
    prefix: VerifiedCompositeParentPrefix,
    divisibility: &VerifiedBridgeDivisibility,
) -> Result<VerifiedV3CompositeReceipt, CompositeParentPublicCoinError> {
    let decisive = complete_verified_decisive_composition_v3(
        strict.clone(),
        semantic.clone(),
        h4.clone(),
        typed.clone(),
    )?;
    let parent = complete_verified_composite_parent_after_bridge_divisibility(
        prefix,
        &strict,
        &semantic,
        continuation,
        &h4,
        &typed,
        &decisive,
        divisibility,
    )?;
    if parent.profile != decisive.profile() {
        return Err(CompositeParentPublicCoinError::ComponentBinding);
    }
    Ok(VerifiedV3CompositeReceipt {
        profile: parent.profile,
        strict_final_transcript_root: *strict.final_transcript_root(),
        semantic_receipt_binding: semantic.receipt_binding(),
        h4_receipt_binding: h4.receipt_binding(),
        typed_receipt_binding: typed.receipt_binding(),
        decisive_receipt_binding: decisive.receipt_binding(),
        parent,
    })
}

impl VerifiedCompositeParentPrefix {
    pub const fn profile(&self) -> Profile {
        self.profile
    }

    pub fn bridge_alpha(&self) -> Fp16 {
        self.bridge_alpha
    }

    pub fn oods_point(&self) -> CirclePoint {
        self.oods_point
    }

    pub fn round_901_transcript_root(&self) -> [u8; 64] {
        self.round_901_transcript_root
    }

    pub fn completion_challenge(&self) -> Fp16 {
        self.completion_challenge
    }

    pub fn bridge_mask_answer_aggregate_root(&self) -> [u8; 64] {
        self.bridge_mask_answer_aggregate_root
    }

    pub fn direct_quotient_commitments(&self) -> &DirectBridgeQuotientCommitments {
        &self.direct_quotient_commitments
    }

    pub fn direct_quotient_coefficients(&self, group: BridgeQuotientGroup) -> &[Fp16] {
        match group {
            BridgeQuotientGroup::Message => &self.message_quotient_coefficients,
            BridgeQuotientGroup::Digest => &self.digest_quotient_coefficients,
        }
    }

    pub fn semantic_prefix(&self) -> &VerifiedSemanticV3Prefix {
        &self.semantic_prefix
    }

    pub fn session_id(&self) -> [u8; 64] {
        self.session_id
    }

    pub fn semantic_composition_root(&self) -> [u8; 64] {
        self.semantic_composition_root
    }

    pub fn bridge_program_commitment(&self) -> [u8; 64] {
        self.bridge_program_commitment
    }

    pub fn post_z_response_commitments(&self) -> ([u8; 64], [u8; 64]) {
        (
            self.final_message.post_z_primitive_response_oracle_root,
            self.final_message.post_z_primitive_claim_vector_commitment,
        )
    }

    /// Finish the parent only from the native decisive-composition receipt and
    /// the component-binding receipt minted against this exact prefix. The
    /// caller cannot supply a digest, boolean, or legacy post-z claim pair.
    pub fn complete_after_decisive_composition(
        self,
        bindings: VerifiedCompositeParentComponentBindings,
        decisive: &crate::semantic_h4_bridge_gkr::VerifiedDecisiveCompositionV3,
        strict: &VerifiedStrictSemanticV3PublicCoin,
    ) -> Result<VerifiedCompositeParent, CompositeParentPublicCoinError> {
        if bindings.profile != self.profile
            || bindings.final_transcript_root != self.final_transcript_root
            || bindings.decisive_receipt_binding != decisive.receipt_binding()
            || decisive.profile() != self.profile
            || strict.profile() != self.profile
            || !decisive
                .receipt_binding()
                .as_bytes()
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(CompositeParentPublicCoinError::ComponentBinding);
        }
        Ok(VerifiedCompositeParent {
            profile: self.profile,
            session_id: self.session_id,
            attempt: self.attempt,
            bridge_alpha: strict.bridge_alpha(),
            oods_point: strict.oods_point(),
            round_900_transcript_root: self.round_900_transcript_root,
            round_901_transcript_root: self.round_901_transcript_root,
            final_transcript_root: self.final_transcript_root,
            completion_challenge: strict.completion_challenge(),
            bridge_divisibility_receipt_commitment: legacy_binding_commitment(
                b"BL/PQ512/V3/COMPOSITE-PARENT/DECISIVE-RECEIPT/v1\0",
                self.profile,
                &[decisive.receipt_binding().as_bytes()],
            )?,
        })
    }

    pub(crate) fn complete_after_verified_bridge_divisibility(
        self,
        bindings: VerifiedCompositeParentComponentBindings,
        verified: &VerifiedBridgeDivisibility,
        strict: &VerifiedStrictSemanticV3PublicCoin,
    ) -> Result<VerifiedCompositeParent, CompositeParentPublicCoinError> {
        if bindings.profile != self.profile
            || bindings.final_transcript_root != self.final_transcript_root
            || verified.profile() != self.profile
            || strict.profile() != self.profile
            || verified.post_z_response_oracle_root()
                != &self.final_message.post_z_primitive_response_oracle_root
            || verified.post_z_claim_vector_commitment()
                != &self.final_message.post_z_primitive_claim_vector_commitment
            || verified.completion_challenge() != strict.completion_challenge()
            || !nonzero(verified.commitment())
        {
            return Err(CompositeParentPublicCoinError::Message);
        }
        self.complete_after_post_z_verification(
            VerifiedPostZBridgeOpenings {
                response_oracle_root: *verified.post_z_response_oracle_root(),
                claim_vector_commitment: *verified.post_z_claim_vector_commitment(),
                completion_challenge: verified.completion_challenge(),
                divisibility_receipt_commitment: *verified.commitment(),
            },
            strict,
        )
    }

    pub(crate) fn complete_after_post_z_verification(
        self,
        verified: VerifiedPostZBridgeOpenings,
        strict: &VerifiedStrictSemanticV3PublicCoin,
    ) -> Result<VerifiedCompositeParent, CompositeParentPublicCoinError> {
        if verified.response_oracle_root != self.final_message.post_z_primitive_response_oracle_root
            || verified.claim_vector_commitment
                != self.final_message.post_z_primitive_claim_vector_commitment
            || strict.profile() != self.profile
            || verified.completion_challenge != strict.completion_challenge()
            || !nonzero(&verified.divisibility_receipt_commitment)
        {
            return Err(CompositeParentPublicCoinError::Message);
        }
        Ok(VerifiedCompositeParent {
            profile: self.profile,
            session_id: self.session_id,
            attempt: self.attempt,
            bridge_alpha: strict.bridge_alpha(),
            oods_point: strict.oods_point(),
            round_900_transcript_root: self.round_900_transcript_root,
            round_901_transcript_root: self.round_901_transcript_root,
            final_transcript_root: self.final_transcript_root,
            completion_challenge: strict.completion_challenge(),
            bridge_divisibility_receipt_commitment: verified.divisibility_receipt_commitment,
        })
    }
}

fn one_field(challenge: &ChainedChallenge) -> Result<Fp16, CompositeParentPublicCoinError> {
    if challenge.field_elements.len() != 1 {
        return Err(CompositeParentPublicCoinError::Descriptor);
    }
    let value = challenge.field_elements[0];
    if value.is_zero() {
        return Err(CompositeParentPublicCoinError::ZeroChallenge);
    }
    Ok(value)
}

struct Reader<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(encoded: &'a [u8]) -> Self {
        Self { encoded, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CompositeParentPublicCoinError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CompositeParentPublicCoinError::Length)?;
        let value = self
            .encoded
            .get(self.offset..end)
            .ok_or(CompositeParentPublicCoinError::Length)?;
        self.offset = end;
        Ok(value)
    }

    fn header(&mut self, magic: &[u8; 8]) -> Result<(), CompositeParentPublicCoinError> {
        if self.take(8)? != magic {
            return Err(CompositeParentPublicCoinError::Magic);
        }
        if self.u16()? != MESSAGE_VERSION {
            return Err(CompositeParentPublicCoinError::Version);
        }
        if self.u16()? != MESSAGE_FLAGS {
            return Err(CompositeParentPublicCoinError::Flags);
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, CompositeParentPublicCoinError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, CompositeParentPublicCoinError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| CompositeParentPublicCoinError::Length)?,
        ))
    }

    fn zeros(&mut self, length: usize) -> Result<(), CompositeParentPublicCoinError> {
        if self.take(length)?.iter().any(|byte| *byte != 0) {
            return Err(CompositeParentPublicCoinError::Reserved);
        }
        Ok(())
    }

    fn digest(&mut self) -> Result<[u8; 64], CompositeParentPublicCoinError> {
        self.take(64)?
            .try_into()
            .map_err(|_| CompositeParentPublicCoinError::Length)
    }

    fn digests<const N: usize>(&mut self) -> Result<[[u8; 64]; N], CompositeParentPublicCoinError> {
        let mut values = [[0_u8; 64]; N];
        for value in &mut values {
            *value = self.digest()?;
        }
        Ok(values)
    }

    fn quotient_group(
        &mut self,
        expected_group: BridgeQuotientGroup,
    ) -> Result<Vec<Fp16>, CompositeParentPublicCoinError> {
        if self.u8()? != expected_group as u8 || self.u8()? != QUOTIENT_BASIS_CODE {
            return Err(CompositeParentPublicCoinError::Message);
        }
        if self.u16()? as usize != BRIDGE_QUOTIENT_COEFFICIENT_COUNT {
            return Err(CompositeParentPublicCoinError::Length);
        }
        self.zeros(4)?;
        let mut coefficients = Vec::with_capacity(BRIDGE_QUOTIENT_COEFFICIENT_COUNT);
        for _ in 0..BRIDGE_QUOTIENT_COEFFICIENT_COUNT {
            coefficients.push(
                Fp16::decode(self.take(FP16_BYTES)?)
                    .map_err(|_| CompositeParentPublicCoinError::NonCanonicalField)?,
            );
        }
        Ok(coefficients)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding_root_v2::BindingRoleV2;
    use crate::chained_public_coin::{
        ChainedContributor, ChainedPublicCoin, ChainedPublicCoinBundle, ChainedRoundEvidence,
        PqSignatureSuite, chain_head_signature_message, chain_step,
        encode_chained_public_coin_bundle,
    };
    use ml_dsa::{
        Keypair as _, MlDsa87, Seed, SignatureEncoding as _, Signer as _,
        SigningKey as MlDsaSigningKey,
    };
    use slh_dsa::{Shake256f, SigningKey as SlhDsaSigningKey};

    fn digest(value: u8) -> [u8; 64] {
        [value; 64]
    }

    fn signed_contributors(
        session_id: &[u8; 64],
        attempt: u16,
        schedule: &[u8; 64],
        round_count: u32,
    ) -> (Vec<ChainedContributor>, Vec<Vec<[u8; 64]>>) {
        let ids = [
            Sha3_512::digest(b"composite-parent-ml-contributor").into(),
            Sha3_512::digest(b"composite-parent-slh-contributor").into(),
        ];
        let key_ids = [
            Sha3_512::digest(b"composite-parent-ml-key").into(),
            Sha3_512::digest(b"composite-parent-slh-key").into(),
        ];
        let mut chains = Vec::new();
        for (index, contributor_id) in ids.iter().enumerate() {
            let mut values = vec![[0_u8; 64]; round_count as usize + 1];
            values[round_count as usize] =
                Sha3_512::digest([b"composite-parent-tail".as_slice(), &[index as u8]].concat())
                    .into();
            for round in (0..round_count).rev() {
                values[round as usize] = chain_step(
                    session_id,
                    attempt,
                    schedule,
                    contributor_id,
                    round,
                    &values[round as usize + 1],
                );
            }
            chains.push(values);
        }

        let ml_signing = MlDsaSigningKey::<MlDsa87>::from_seed(&Seed::from([37_u8; 32]));
        let slh_signing = SlhDsaSigningKey::<Shake256f>::slh_keygen_internal(
            &[41_u8; 32],
            &[43_u8; 32],
            &[47_u8; 32],
        );
        let mut contributors = vec![
            ChainedContributor {
                contributor_id: ids[0],
                key_id: key_ids[0],
                suite: PqSignatureSuite::MlDsa87,
                public_key: ml_signing.verifying_key().encode().to_vec(),
                chain_head: chains[0][0],
                head_signature: Vec::new(),
            },
            ChainedContributor {
                contributor_id: ids[1],
                key_id: key_ids[1],
                suite: PqSignatureSuite::SlhDsaShake256f,
                public_key: slh_signing.verifying_key().to_bytes().to_vec(),
                chain_head: chains[1][0],
                head_signature: Vec::new(),
            },
        ];
        let ml_message = chain_head_signature_message(
            session_id,
            attempt,
            schedule,
            round_count,
            &contributors[0],
        );
        contributors[0].head_signature = ml_signing.sign(&ml_message).to_bytes().to_vec();
        let slh_message = chain_head_signature_message(
            session_id,
            attempt,
            schedule,
            round_count,
            &contributors[1],
        );
        contributors[1].head_signature = slh_signing
            .try_sign(&slh_message)
            .expect("valid fixed SLH-DSA message")
            .to_bytes()
            .to_vec();

        let mut paired = contributors.into_iter().zip(chains).collect::<Vec<_>>();
        paired.sort_by_key(|item| item.0.contributor_id);
        paired.into_iter().unzip()
    }

    fn pre_alpha() -> CompositeParentPreAlphaMessage {
        let parent_program_commitment = digest(3);
        let schedule_commitment = composite_parent_schedule_commitment(
            Profile::K128Calibration,
            &parent_program_commitment,
        )
        .unwrap();
        CompositeParentPreAlphaMessage {
            profile: Profile::K128Calibration,
            composite_session_id: digest(1),
            attempt: 2,
            schedule_commitment,
            parent_program_commitment,
            candidate_descriptor_commitment: digest(4),
            statement_commitment: digest(5),
            semantic_program_commitment: digest(6),
            semantic_session_id: digest(44),
            semantic_schedule_commitment: digest(45),
            semantic_contributor_set_commitment: digest(46),
            semantic_prefix_receipt_commitment: digest(47),
            semantic_round_1_transcript_root: digest(7),
            semantic_main_root: digest(8),
            semantic_interaction_root: digest(9),
            semantic_composition_root: digest(10),
            h4_child_final_root: digest(13),
            h4_ordered_shard_root_receipt: digest(14),
            h4_source_root: digest(15),
            h4_b_tensor_root: digest(16),
            h4_n_tensor_root: digest(17),
            h4_a_tensor_root: digest(18),
            bridge_mask_base_aggregate_root: digest(19),
            bridge_mask_pad_aggregate_root: digest(20),
        }
    }

    fn semantic_prefix() -> VerifiedSemanticV3Prefix {
        crate::selected_public_coin_v3::synthetic_verified_semantic_v3_prefix_for_parent_test(
            Profile::K128Calibration,
            digest(44),
            digest(45),
            digest(46),
            digest(7),
            digest(8),
            digest(9),
            digest(6),
            digest(48),
            digest(5),
            digest(47),
        )
    }

    fn quotient() -> CompositeParentQuotientMessage {
        CompositeParentQuotientMessage {
            profile: Profile::K128Calibration,
            prior_transcript_root: digest(21),
            bridge_program_commitment: expected_bridge_program(Profile::K128Calibration).unwrap(),
            bridge_mask_answer_aggregate_root: digest(23),
            message_quotient_coefficients: vec![Fp16::ONE; BRIDGE_QUOTIENT_COEFFICIENT_COUNT],
            digest_quotient_coefficients: vec![Fp16::ZERO; BRIDGE_QUOTIENT_COEFFICIENT_COUNT],
        }
    }

    fn final_message() -> CompositeParentFinalMessage {
        CompositeParentFinalMessage {
            prior_transcript_root: digest(31),
            post_z_primitive_response_oracle_root: digest(32),
            post_z_primitive_claim_vector_commitment: digest(33),
            semantic_continuation_final_root: digest(34),
            semantic_component_package_commitment: digest(35),
            h4_component_package_commitment: digest(36),
            typed_component_package_commitment: digest(37),
            typed_verified_receipt_commitment: digest(38),
            h4_booleanity_receipt_commitment: digest(39),
            h4_global_padding_receipt_commitment: digest(40),
            bridge_privacy_ledger_commitment: digest(41),
            semantic_exposure_ledger_commitment: digest(42),
            h4_exposure_ledger_commitment: digest(43),
        }
    }

    #[test]
    fn exact_parent_message_grammars_roundtrip() {
        let pre = pre_alpha();
        let encoded = pre.encode().unwrap();
        assert_eq!(encoded.len(), PRE_ALPHA_BYTES);
        assert_eq!(
            CompositeParentPreAlphaMessage::decode(&encoded).unwrap(),
            pre
        );

        let quotient = quotient();
        let encoded = quotient.encode().unwrap();
        assert_eq!(encoded.len(), QUOTIENT_BYTES);
        assert_eq!(
            CompositeParentQuotientMessage::decode(&encoded).unwrap(),
            quotient
        );

        let final_message = final_message();
        let encoded = final_message.encode().unwrap();
        assert_eq!(encoded.len(), FINAL_BYTES);
        assert!(!encoded.windows(64).any(|window| window == digest(45)));
        assert_eq!(
            CompositeParentFinalMessage::decode(&encoded).unwrap(),
            final_message
        );
    }

    #[test]
    fn profile_attempt_reserved_and_zero_mutations_reject() {
        let encoded = pre_alpha().encode().unwrap();
        let mut changed = encoded.clone();
        changed[12] = 2;
        assert_eq!(
            CompositeParentPreAlphaMessage::decode(&changed),
            Err(CompositeParentPublicCoinError::Profile)
        );
        let mut changed = encoded.clone();
        changed[13] = 1;
        assert_eq!(
            CompositeParentPreAlphaMessage::decode(&changed),
            Err(CompositeParentPublicCoinError::Reserved)
        );
        let mut changed = encoded;
        changed[12 + 1 + 7 + 64] = 0;
        changed[12 + 1 + 7 + 64 + 1] = 4;
        assert_eq!(
            CompositeParentPreAlphaMessage::decode(&changed),
            Err(CompositeParentPublicCoinError::Attempt)
        );

        let mut changed = quotient().encode().unwrap();
        changed[20..84].fill(0);
        assert_eq!(
            CompositeParentQuotientMessage::decode(&changed),
            Err(CompositeParentPublicCoinError::ZeroCommitment)
        );

        let mut changed = quotient().encode().unwrap();
        let first_coefficient = 12 + 8 + 3 * 64 + QUOTIENT_GROUP_FRAME_BYTES;
        changed[first_coefficient..first_coefficient + 4]
            .copy_from_slice(&0x7fff_ffff_u32.to_be_bytes());
        assert_eq!(
            CompositeParentQuotientMessage::decode(&changed),
            Err(CompositeParentPublicCoinError::NonCanonicalField)
        );
    }

    #[test]
    fn schedule_is_profile_and_program_bound() {
        let program = digest(50);
        assert_ne!(
            composite_parent_schedule_commitment(Profile::K128Calibration, &program).unwrap(),
            composite_parent_schedule_commitment(Profile::K512Calibration, &program).unwrap()
        );
        assert_ne!(
            composite_parent_schedule_commitment(Profile::K128Calibration, &program).unwrap(),
            composite_parent_schedule_commitment(Profile::K128Calibration, &digest(51)).unwrap()
        );
    }

    #[test]
    fn direct_quotient_is_structurally_bounded_and_context_bound() {
        assert_eq!(QUOTIENT_BYTES, 613_220);
        let pre = pre_alpha();
        let quotient = quotient();
        let original = direct_quotient_commitment(
            quotient.profile,
            BridgeQuotientGroup::Message,
            &quotient.bridge_program_commitment,
            &pre.bridge_mask_base_aggregate_root,
            &pre.bridge_mask_pad_aggregate_root,
            &quotient.bridge_mask_answer_aggregate_root,
            &quotient.message_quotient_coefficients,
        )
        .unwrap();
        let mut changed = quotient.message_quotient_coefficients.clone();
        changed[BRIDGE_QUOTIENT_COEFFICIENT_COUNT - 1] = Fp16::ZERO;
        let mutated = direct_quotient_commitment(
            quotient.profile,
            BridgeQuotientGroup::Message,
            &quotient.bridge_program_commitment,
            &pre.bridge_mask_base_aggregate_root,
            &pre.bridge_mask_pad_aggregate_root,
            &quotient.bridge_mask_answer_aggregate_root,
            &changed,
        )
        .unwrap();
        assert_ne!(original, mutated);
        let digest_group = direct_quotient_commitment(
            quotient.profile,
            BridgeQuotientGroup::Digest,
            &quotient.bridge_program_commitment,
            &pre.bridge_mask_base_aggregate_root,
            &pre.bridge_mask_pad_aggregate_root,
            &quotient.bridge_mask_answer_aggregate_root,
            &quotient.message_quotient_coefficients,
        )
        .unwrap();
        assert_ne!(original, digest_group);
    }

    #[test]
    fn zero_parent_challenges_fail_closed_without_local_resampling() {
        let zero = ChainedChallenge {
            seed: digest(90),
            field_elements: vec![Fp16::ZERO],
            transcript_root: digest(91),
        };
        assert_eq!(
            one_field(&zero),
            Err(CompositeParentPublicCoinError::ZeroChallenge)
        );
    }

    #[test]
    fn exact_dual_pq_parent_chain_verifies_and_message_substitution_fails() {
        let pre = pre_alpha();
        let (contributors, chains) = signed_contributors(
            &pre.composite_session_id,
            pre.attempt,
            &pre.schedule_commitment,
            COMPOSITE_PARENT_ROUND_COUNT as u32,
        );
        let mut coin = ChainedPublicCoin::new(
            pre.composite_session_id,
            pre.attempt,
            pre.schedule_commitment,
            COMPOSITE_PARENT_ROUND_COUNT as u32,
            contributors.clone(),
        )
        .unwrap();
        let mut rounds = Vec::new();

        let pre_message = pre.encode().unwrap();
        let reveals = chains.iter().map(|chain| chain[1]).collect::<Vec<_>>();
        let challenge_900 = coin
            .accept_round(
                descriptor(COMPOSITE_PARENT_PRE_ALPHA_KIND),
                &pre_message,
                &reveals,
            )
            .unwrap();
        rounds.push(ChainedRoundEvidence {
            descriptor: descriptor(COMPOSITE_PARENT_PRE_ALPHA_KIND),
            prover_message: pre_message,
            reveals,
        });

        let mut quotient_expected = quotient();
        quotient_expected.prior_transcript_root = challenge_900.transcript_root;
        let quotient_message = quotient_expected.encode().unwrap();
        let reveals = chains.iter().map(|chain| chain[2]).collect::<Vec<_>>();
        let challenge_901 = coin
            .accept_round(
                descriptor(COMPOSITE_PARENT_QUOTIENT_KIND),
                &quotient_message,
                &reveals,
            )
            .unwrap();
        rounds.push(ChainedRoundEvidence {
            descriptor: descriptor(COMPOSITE_PARENT_QUOTIENT_KIND),
            prover_message: quotient_message,
            reveals,
        });

        let mut final_expected = final_message();
        final_expected.prior_transcript_root = challenge_901.transcript_root;
        let final_encoded = final_expected.encode().unwrap();
        let reveals = chains.iter().map(|chain| chain[3]).collect::<Vec<_>>();
        coin.accept_round(
            descriptor(COMPOSITE_PARENT_FINAL_KIND),
            &final_encoded,
            &reveals,
        )
        .unwrap();
        rounds.push(ChainedRoundEvidence {
            descriptor: descriptor(COMPOSITE_PARENT_FINAL_KIND),
            prover_message: final_encoded,
            reveals,
        });

        let bundle = ChainedPublicCoinBundle {
            session_id: pre.composite_session_id,
            attempt: pre.attempt,
            schedule_commitment: pre.schedule_commitment,
            contributors,
            rounds,
            claimed_final_transcript_root: coin.transcript_root(),
        };
        let encoded = encode_chained_public_coin_bundle(&bundle).unwrap();
        let replay = verify_composite_parent_transcript(&encoded).unwrap();
        assert_eq!(
            replay.round_900_transcript_root(),
            &challenge_900.transcript_root
        );
        assert_eq!(
            replay.round_901_transcript_root(),
            &challenge_901.transcript_root
        );
        assert_eq!(replay.final_transcript_root(), &coin.transcript_root());
        let semantic_prefix = semantic_prefix();
        let prefix = verify_composite_parent_prefix(&encoded, &pre, &semantic_prefix).unwrap();
        assert_eq!(
            prefix.round_901_transcript_root(),
            challenge_901.transcript_root
        );
        assert_eq!(
            prefix.post_z_response_commitments(),
            (digest(32), digest(33))
        );
        assert!(!prefix.completion_challenge().is_zero());
        assert_eq!(
            prefix.bridge_mask_answer_aggregate_root(),
            quotient_expected.bridge_mask_answer_aggregate_root
        );
        assert_eq!(
            prefix.direct_quotient_coefficients(BridgeQuotientGroup::Message),
            quotient_expected.message_quotient_coefficients
        );
        assert_ne!(
            prefix.direct_quotient_commitments().message,
            prefix.direct_quotient_commitments().digest
        );
        let fake_receipt = VerifiedPostZBridgeOpenings {
            response_oracle_root: digest(99),
            claim_vector_commitment: digest(33),
            completion_challenge: prefix.completion_challenge(),
            divisibility_receipt_commitment: digest(45),
        };
        let strict =
            crate::selected_public_coin_v3::synthetic_verified_strict_semantic_v3_for_parent_test(
                Profile::K128Calibration,
                prefix.completion_challenge(),
            );
        assert!(matches!(
            prefix.complete_after_post_z_verification(fake_receipt, &strict),
            Err(CompositeParentPublicCoinError::Message)
        ));

        let mut substituted = bundle.clone();
        substituted.rounds[0].prover_message[PRE_ALPHA_BYTES - 1] ^= 1;
        let encoded = encode_chained_public_coin_bundle(&substituted).unwrap();
        assert!(matches!(
            verify_composite_parent_prefix(&encoded, &pre, &semantic_prefix),
            Err(CompositeParentPublicCoinError::Chained(
                ChainedPublicCoinError::FinalTranscriptRoot
            ))
        ));

        let mut q_substituted = bundle.clone();
        q_substituted.rounds[1].prover_message[QUOTIENT_BYTES - 1] ^= 1;
        let encoded = encode_chained_public_coin_bundle(&q_substituted).unwrap();
        assert!(matches!(
            verify_composite_parent_prefix(&encoded, &pre, &semantic_prefix),
            Err(CompositeParentPublicCoinError::Chained(
                ChainedPublicCoinError::FinalTranscriptRoot
            ))
        ));

        let mismatched_prefix =
            crate::selected_public_coin_v3::synthetic_verified_semantic_v3_prefix_for_parent_test(
                Profile::K128Calibration,
                digest(98),
                digest(45),
                digest(46),
                digest(7),
                digest(8),
                digest(9),
                digest(6),
                digest(48),
                digest(5),
                digest(47),
            );
        let encoded = encode_chained_public_coin_bundle(&bundle).unwrap();
        assert!(matches!(
            verify_composite_parent_prefix(&encoded, &pre, &mismatched_prefix),
            Err(CompositeParentPublicCoinError::SemanticPrefix)
        ));

        for (schedule, contributors) in [(digest(97), digest(46)), (digest(45), digest(96))] {
            let mismatched_prefix = crate::selected_public_coin_v3::synthetic_verified_semantic_v3_prefix_for_parent_test(
                Profile::K128Calibration,
                digest(44),
                schedule,
                contributors,
                digest(7),
                digest(8),
                digest(9),
                digest(6),
                digest(48),
                digest(5),
                digest(47),
            );
            assert!(matches!(
                verify_composite_parent_prefix(&encoded, &pre, &mismatched_prefix),
                Err(CompositeParentPublicCoinError::SemanticPrefix)
            ));
        }
    }

    #[test]
    fn composite_receipt_evidence_roundtrips_and_rejects_mutations() {
        fn binding(value: u8) -> BindingDigestV2 {
            BindingDigestV2::hash(BindingRoleV2::Payload, &[value]).unwrap()
        }

        let receipt = VerifiedV3CompositeReceipt {
            profile: Profile::K128Calibration,
            strict_final_transcript_root: [1_u8; 128],
            semantic_receipt_binding: binding(2),
            h4_receipt_binding: binding(3),
            typed_receipt_binding: binding(4),
            decisive_receipt_binding: binding(5),
            parent: VerifiedCompositeParent {
                profile: Profile::K128Calibration,
                session_id: [6_u8; 64],
                attempt: 1,
                bridge_alpha: Fp16::ONE,
                oods_point: CirclePoint {
                    x: Fp16::ONE,
                    y: Fp16::ONE,
                },
                round_900_transcript_root: [7_u8; 64],
                round_901_transcript_root: [8_u8; 64],
                final_transcript_root: [9_u8; 64],
                completion_challenge: Fp16::ONE,
                bridge_divisibility_receipt_commitment: [10_u8; 64],
            },
        };

        let encoded =
            crate::composite_receipt_v3::encode_verified_v3_composite_receipt(&receipt).unwrap();
        assert_eq!(
            encoded.len(),
            crate::composite_receipt_v3::V3_COMPOSITE_RECEIPT_V4_BYTES
        );
        let decoded =
            crate::composite_receipt_v3::decode_v3_composite_receipt_evidence(&encoded).unwrap();
        assert_eq!(decoded.profile_code, 1);
        assert_eq!(decoded.attempt, 1);
        assert_eq!(decoded.strict_final_transcript_root, [1_u8; 128]);
        assert_eq!(decoded.parent_session_id, [6_u8; 64]);
        assert_eq!(decoded.parent_round_900_transcript_root, [7_u8; 64]);
        assert_eq!(decoded.parent_round_901_transcript_root, [8_u8; 64]);
        assert_eq!(decoded.parent_final_transcript_root, [9_u8; 64]);
        assert_eq!(decoded.parent_divisibility_receipt_commitment, [10_u8; 64]);
        assert_eq!(decoded.semantic_receipt_binding, binding(2));
        assert_eq!(decoded.h4_receipt_binding, binding(3));
        assert_eq!(decoded.typed_receipt_binding, binding(4));
        assert_eq!(decoded.decisive_receipt_binding, binding(5));

        let mut changed = encoded.clone();
        changed[0] ^= 1;
        assert_eq!(
            crate::composite_receipt_v3::decode_v3_composite_receipt_evidence(&changed),
            Err(crate::composite_receipt_v3::V3CompositeReceiptV4Error::Magic)
        );

        let mut changed = encoded.clone();
        changed[10] = 1;
        assert_eq!(
            crate::composite_receipt_v3::decode_v3_composite_receipt_evidence(&changed),
            Err(crate::composite_receipt_v3::V3CompositeReceiptV4Error::Flags)
        );

        let mut changed = encoded;
        changed[20..148].fill(0);
        assert_eq!(
            crate::composite_receipt_v3::decode_v3_composite_receipt_evidence(&changed),
            Err(crate::composite_receipt_v3::V3CompositeReceiptV4Error::Identity)
        );
    }
}
