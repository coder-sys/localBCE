//! Transactional current-H4 post-Z completion boundary.
//!
//! `h4_proof_package_v2` owns the acceptance equations. This module owns the
//! smallest reusable boundary around them: decode each serialized `BLH4SR02`
//! response, replay its governed strict-PQ transcript, bind its source/base
//! segments, and call the native completion function only after every shard
//! has produced an opaque verifier receipt.
//!
//! This is deliberately not a witness-to-proof generator. It is a complete
//! post-alpha H4 completion authority for already-produced current-v2 proof
//! material. It never mints a receipt from caller roots, scalar pairs, or
//! status flags, and root-use registry changes commit only after the entire
//! completion succeeds.

use alloc::vec::Vec;

use crate::binding_root_v2::BindingDigestV2;
use crate::field::Fp16;
use crate::h4_bridge_source_response_v2::{
    H4BridgeSourceResponseV2Error, VerifiedStrictH4BridgeSourceResponseV2,
    decode_h4_bridge_source_response_v2, verify_strict_h4_bridge_source_response_v2,
};
use crate::h4_proof_package_v2::{
    H4PostZShardV2, H4ProofPackageV2Error, H4SourceMaskProofV2, VerifiedH4PostZSourcesV2,
    VerifiedH4PreAlphaV2, VerifiedH4V2, complete_h4_v2_from_verified_post_z,
    verify_h4_post_z_sources_v2,
};
use crate::semantic_h4_bridge_gkr::{
    ProducedSemanticH4BridgeSourceMaskV3, VerifiedSemanticBridgeSourceBatchV3,
    VerifiedStrictSemanticH4BridgeGkr,
};
use crate::strict_pq_public_coin_v2::{StrictPqGovernedVerifierKeyV2, StrictPqRootUseRegistryV2};

/// One serialized response and its authenticated native-RS opening segments.
/// The claim-vector binding and context are intentionally not fields: both are
/// derived from the already-verified semantic/H4 inputs supplied to the
/// completion call.
pub struct H4PostZResponseInput<'a> {
    pub encoded_strict_bundle: &'a [u8],
    pub encoded_response: &'a [u8],
    pub first_ordinal: u32,
    pub source_segment: &'a [u8],
    pub base_segment: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum H4V2CompletionError {
    Response(H4BridgeSourceResponseV2Error),
    Proof(H4ProofPackageV2Error),
    RegistryChanged,
}

const H4_SOURCE_MASK_COIN_DOMAIN_V3: &[u8] =
    b"BL/PQ512/WAVE2/H4/SOURCE-MASK-COIN/v3\0";

/// Fiat-Shamir coins fixed by the authenticated post-Z receipt.  The mask
/// vector is committed by the earlier bridge GKR, so this is the first
/// non-circular boundary that can bind the added source constraints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H4SourceMaskCoinsV3 {
    pub batch_challenge: Fp16,
    pub inner_product_challenges: Vec<Fp16>,
    pub completion_coin: BindingDigestV2,
}

pub fn derive_h4_source_mask_coins_v3(
    post_z: &PreparedH4V2PostZ,
) -> Result<H4SourceMaskCoinsV3, H4V2CompletionError> {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(H4_SOURCE_MASK_COIN_DOMAIN_V3);
    transcript.push(post_z.post_z.profile().code());
    transcript.extend_from_slice(post_z.post_z.pre_alpha_binding().as_bytes());
    transcript.extend_from_slice(post_z.post_z.source_binding().as_bytes());
    transcript.extend_from_slice(post_z.post_z.post_z_context().as_bytes());
    transcript.extend_from_slice(post_z.post_z.post_z_response_oracle_root().as_bytes());
    transcript.extend_from_slice(post_z.post_z.claim_vector_commitment().as_bytes());
    let seed = BindingDigestV2::hash(
        crate::binding_root_v2::BindingRoleV2::Payload,
        &transcript,
    )
    .map_err(|_| H4V2CompletionError::Proof(H4ProofPackageV2Error::Algebra))?;
    let profile = match post_z.post_z.profile() {
        crate::h4_proof_package_v2::H4ProofProfileV2::K128 => {
            crate::semantic_h4_bridge_gkr::SemanticH4BridgeProfile::K128
        }
        crate::h4_proof_package_v2::H4ProofProfileV2::K512 => {
            crate::semantic_h4_bridge_gkr::SemanticH4BridgeProfile::K512
        }
    };
    let challenge_count = crate::semantic_h4_bridge_gkr::semantic_h4_bridge_mask_layout(profile)
        .map_err(|_| H4V2CompletionError::Proof(H4ProofPackageV2Error::Algebra))?
        .padded_coefficients
        .ilog2() as usize;
    let mut fields = Vec::with_capacity(challenge_count + 1);
    let mut draw = 0_u32;
    while fields.len() <= challenge_count {
        let sampled = crate::sampler::sample_uniform_fp16(
            &seed.as_bytes()[..64],
            &seed.as_bytes()[64..],
            0,
            draw,
            crate::sampler::DEFAULT_MAX_ATTEMPTS,
        )
        .map_err(|_| H4V2CompletionError::Proof(H4ProofPackageV2Error::Algebra))?;
        draw = draw
            .checked_add(1)
            .ok_or(H4V2CompletionError::Proof(H4ProofPackageV2Error::Algebra))?;
        if fields.is_empty() && sampled.element.is_zero() {
            continue;
        }
        fields.push(sampled.element);
    }
    let completion_coin = BindingDigestV2::hash(
        crate::binding_root_v2::BindingRoleV2::Payload,
        &[transcript.as_slice(), seed.as_bytes(), b"completion"].concat(),
    )
    .map_err(|_| H4V2CompletionError::Proof(H4ProofPackageV2Error::Algebra))?;
    Ok(H4SourceMaskCoinsV3 {
        batch_challenge: fields[0],
        inner_product_challenges: fields[1..].to_vec(),
        completion_coin,
    })
}

impl From<H4BridgeSourceResponseV2Error> for H4V2CompletionError {
    fn from(value: H4BridgeSourceResponseV2Error) -> Self {
        Self::Response(value)
    }
}

impl From<H4ProofPackageV2Error> for H4V2CompletionError {
    fn from(value: H4ProofPackageV2Error) -> Self {
        Self::Proof(value)
    }
}

/// Transactional two-phase H4 completion state.  Post-Z source authentication
/// has succeeded, but strict-PQ root reservations are not committed to the
/// caller registry until the source-mask proof also verifies.
pub struct PreparedH4V2PostZ {
    post_z: VerifiedH4PostZSourcesV2,
    starting_registry: StrictPqRootUseRegistryV2,
    pending_registry: StrictPqRootUseRegistryV2,
}

impl PreparedH4V2PostZ {
    pub const fn post_z(&self) -> &VerifiedH4PostZSourcesV2 {
        &self.post_z
    }

    pub fn produce_source_mask_proof(
        &self,
        mask_coefficients: &[crate::field::Fp16],
        batch_challenge: crate::field::Fp16,
        inner_product_challenges: &[crate::field::Fp16],
        completion_coin: BindingDigestV2,
    ) -> Result<ProducedSemanticH4BridgeSourceMaskV3, H4V2CompletionError> {
        self.post_z
            .produce_source_mask_proof(
                mask_coefficients,
                batch_challenge,
                inner_product_challenges,
                completion_coin,
            )
            .map_err(H4V2CompletionError::Proof)
    }

    pub fn complete_and_commit(
        self,
        source_mask_proof: H4SourceMaskProofV2<'_>,
        root_use_registry: &mut StrictPqRootUseRegistryV2,
    ) -> Result<VerifiedH4V2, H4V2CompletionError> {
        if *root_use_registry != self.starting_registry {
            return Err(H4V2CompletionError::RegistryChanged);
        }
        let completed = complete_h4_v2_from_verified_post_z(self.post_z, source_mask_proof)?;
        *root_use_registry = self.pending_registry;
        Ok(completed)
    }
}

/// Replay and complete the current H4-v2 post-Z boundary transactionally.
///
/// The caller must supply a governed H4 strict key, but cannot supply the
/// claim vector, response challenge, source binding, or response oracle root:
/// those are derived from `semantic_batch`, the strict transcript, and the
/// authenticated RS segments. A failed shard or failed final completion
/// leaves `root_use_registry` byte-for-byte unchanged.
#[allow(clippy::too_many_arguments)]
pub fn complete_h4_v2_from_serialized_post_z(
    pre_alpha: VerifiedH4PreAlphaV2,
    strict_gkr: &VerifiedStrictSemanticH4BridgeGkr,
    semantic_batch: &VerifiedSemanticBridgeSourceBatchV3,
    source_mask_proof: H4SourceMaskProofV2<'_>,
    expected_post_z_context: BindingDigestV2,
    governed_key: &StrictPqGovernedVerifierKeyV2,
    inputs: &[H4PostZResponseInput<'_>],
    root_use_registry: &mut StrictPqRootUseRegistryV2,
) -> Result<VerifiedH4V2, H4V2CompletionError> {
    let governed_keys = inputs.iter().map(|_| governed_key).collect::<Vec<_>>();
    complete_h4_v2_from_serialized_post_z_with_keys(
        pre_alpha,
        strict_gkr,
        semantic_batch,
        source_mask_proof,
        expected_post_z_context,
        &governed_keys,
        inputs,
        root_use_registry,
    )
}

/// Replay and complete post-Z responses when each shard has its own governed
/// strict-PQ key.  A key is a one-time root-use reservation, so reusing one
/// key across K512's four shards would violate the registry's lifetime
/// invariant.  The key slice is therefore part of the explicit shard
/// contract, and its order is bound to `inputs`.
#[allow(clippy::too_many_arguments)]
pub fn complete_h4_v2_from_serialized_post_z_with_keys(
    pre_alpha: VerifiedH4PreAlphaV2,
    strict_gkr: &VerifiedStrictSemanticH4BridgeGkr,
    semantic_batch: &VerifiedSemanticBridgeSourceBatchV3,
    source_mask_proof: H4SourceMaskProofV2<'_>,
    expected_post_z_context: BindingDigestV2,
    governed_keys: &[&StrictPqGovernedVerifierKeyV2],
    inputs: &[H4PostZResponseInput<'_>],
    root_use_registry: &mut StrictPqRootUseRegistryV2,
) -> Result<VerifiedH4V2, H4V2CompletionError> {
    let prepared = prepare_h4_v2_from_serialized_post_z_with_keys(
        pre_alpha,
        strict_gkr,
        semantic_batch,
        expected_post_z_context,
        governed_keys,
        inputs,
        root_use_registry,
    )?;
    prepared.complete_and_commit(source_mask_proof, root_use_registry)
}

/// Replay all serialized post-Z shards and retain the verifier-derived source
/// constraints so a real producer can construct the final mask PCS without a
/// caller-authenticated scalar or a receipt cycle.
#[allow(clippy::too_many_arguments)]
pub fn prepare_h4_v2_from_serialized_post_z_with_keys(
    pre_alpha: VerifiedH4PreAlphaV2,
    strict_gkr: &VerifiedStrictSemanticH4BridgeGkr,
    semantic_batch: &VerifiedSemanticBridgeSourceBatchV3,
    expected_post_z_context: BindingDigestV2,
    governed_keys: &[&StrictPqGovernedVerifierKeyV2],
    inputs: &[H4PostZResponseInput<'_>],
    root_use_registry: &StrictPqRootUseRegistryV2,
) -> Result<PreparedH4V2PostZ, H4V2CompletionError> {
    if inputs.len() != usize::from(pre_alpha.profile().shard_count()) {
        return Err(H4V2CompletionError::Proof(H4ProofPackageV2Error::Geometry));
    }
    if governed_keys.len() != inputs.len() {
        return Err(H4V2CompletionError::Proof(H4ProofPackageV2Error::Geometry));
    }

    // Every strict replay is staged against a private registry. This keeps a
    // later malformed response from consuming the roots of earlier responses.
    let starting_registry = root_use_registry.clone();
    let mut pending_registry = starting_registry.clone();
    let mut responses = Vec::with_capacity(inputs.len());
    let mut strict_responses: Vec<VerifiedStrictH4BridgeSourceResponseV2> =
        Vec::with_capacity(inputs.len());
    for (input, governed_key) in inputs.iter().zip(governed_keys) {
        let response = decode_h4_bridge_source_response_v2(input.encoded_response)?;
        let strict = verify_strict_h4_bridge_source_response_v2(
            input.encoded_strict_bundle,
            governed_key,
            pre_alpha.profile(),
            &response,
            expected_post_z_context,
            semantic_batch.claim_vector_binding(),
            input.first_ordinal,
            &mut pending_registry,
        )?;
        responses.push(response);
        strict_responses.push(strict);
    }

    let shards = responses
        .iter()
        .zip(&strict_responses)
        .zip(inputs)
        .map(|((response, strict), input)| H4PostZShardV2 {
            response,
            strict,
            source_segment: input.source_segment,
            base_segment: input.base_segment,
        })
        .collect::<Vec<_>>();
    let post_z = verify_h4_post_z_sources_v2(
        pre_alpha,
        strict_gkr,
        semantic_batch,
        expected_post_z_context,
        &shards,
    )?;
    Ok(PreparedH4V2PostZ {
        post_z,
        starting_registry,
        pending_registry,
    })
}

/// Producer-facing name for the same authenticated completion boundary.
///
/// This is intentionally a thin alias, not a second implementation: the
/// verifier-owned replay and transactional registry semantics above remain
/// the only authority.  The function produces a complete H4 receipt only
/// from a verified pre-alpha package, strict bridge-GKR receipt, verified
/// semantic source batch, and serialized post-Z openings; it does not create
/// witness material or promote an unqualified artifact.
#[allow(clippy::too_many_arguments)]
pub fn produce_h4_v2_from_serialized_post_z(
    pre_alpha: VerifiedH4PreAlphaV2,
    strict_gkr: &VerifiedStrictSemanticH4BridgeGkr,
    semantic_batch: &VerifiedSemanticBridgeSourceBatchV3,
    source_mask_proof: H4SourceMaskProofV2<'_>,
    expected_post_z_context: BindingDigestV2,
    governed_key: &StrictPqGovernedVerifierKeyV2,
    inputs: &[H4PostZResponseInput<'_>],
    root_use_registry: &mut StrictPqRootUseRegistryV2,
) -> Result<VerifiedH4V2, H4V2CompletionError> {
    complete_h4_v2_from_serialized_post_z(
        pre_alpha,
        strict_gkr,
        semantic_batch,
        source_mask_proof,
        expected_post_z_context,
        governed_key,
        inputs,
        root_use_registry,
    )
}

/// Compile-time capability marker for the boundary above. It does not claim
/// that a witness-to-`BLH4PK02` producer exists.
pub const H4_V2_POST_Z_COMPLETION_AVAILABLE: bool = true;
/// The post-Z producer boundary is available; witness-to-pre-alpha production
/// remains a separate, profile-specific input contract.
pub const H4_V2_POST_Z_PRODUCER_AVAILABLE: bool = true;
