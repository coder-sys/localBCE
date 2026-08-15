//! Production-shaped producer for the semantic/H4 bridge GKR.
//!
//! This module owns the smallest missing proving boundary that can be made
//! complete from repository-owned inputs: it turns authenticated source
//! vectors and a governed strict-PQ key into a bridge-GKR proof and its strict
//! transcript bundle.  It does not manufacture the key, choose challenges,
//! create semantic Circle openings, or claim complete H4 acceptance.  The
//! caller must supply all of those upstream identities and the accepting
//! verifier still has to replay this output through the full post-Z path.

use alloc::vec::Vec;

use zeroize::Zeroize;

use crate::binding_root_v2::BINDING_V2_BYTES;
use crate::field::Fp16;
use crate::semantic_h4_bridge_gkr::{
    NonuniformSemanticH4BridgeOracle, PublicMaskedSemanticH4BridgeGkrProof,
    SemanticH4BridgeGkrError, SemanticH4BridgeProfile, encode_public_masked_semantic_h4_bridge_gkr,
    produce_public_masked_nonuniform_semantic_h4_bridge_gkr,
    produce_public_masked_semantic_h4_bridge_gkr, semantic_h4_bridge_strict_schedule_commitment,
    verify_strict_semantic_h4_bridge_gkr,
};
use crate::strict_pq_public_coin_v2::{
    STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2, STRICT_PQ_LAMPORT_SECRET_BYTES_V2, StrictPqFp16PolicyV2,
    StrictPqGovernedVerifierKeyV2, StrictPqH4ProfileV2, StrictPqLamportSecretKeyV2,
    StrictPqPublicCoinV2Error, StrictPqRootUseRegistryV2, StrictPqRoundDescriptorV2,
    StrictPqTranscriptBuilderV2, build_chain_from_supplied_tail_v2, sign_chain_head_v2,
};

/// Errors from the supplied-material bridge producer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticH4BridgeProducerError {
    Input,
    Secret(StrictPqPublicCoinV2Error),
    Chain(StrictPqPublicCoinV2Error),
    Transcript(StrictPqPublicCoinV2Error),
    Proof(SemanticH4BridgeGkrError),
    Encoding(SemanticH4BridgeGkrError),
    ScheduleMismatch,
    Replay(SemanticH4BridgeGkrError),
}

impl From<StrictPqPublicCoinV2Error> for SemanticH4BridgeProducerError {
    fn from(value: StrictPqPublicCoinV2Error) -> Self {
        Self::Transcript(value)
    }
}

/// Complete output of the bridge-GKR producer.  The bytes are transport
/// artifacts; no field here is an accepting receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProducedSemanticH4BridgeGkr {
    pub proof: PublicMaskedSemanticH4BridgeGkrProof,
    pub encoded_proof: Vec<u8>,
    pub encoded_strict_bundle: Vec<u8>,
    pub governed_key: Vec<u8>,
    pub final_transcript_root: [u8; BINDING_V2_BYTES],
    pub first_ordinal: u32,
}

fn strict_profile(profile: SemanticH4BridgeProfile) -> StrictPqH4ProfileV2 {
    match profile {
        SemanticH4BridgeProfile::K128 => StrictPqH4ProfileV2::K128,
        SemanticH4BridgeProfile::K512 => StrictPqH4ProfileV2::K512,
    }
}

fn decode_secret_material(
    encoded: &[u8],
) -> Result<Vec<[u8; STRICT_PQ_LAMPORT_SECRET_BYTES_V2]>, SemanticH4BridgeProducerError> {
    let expected = STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2
        .checked_mul(STRICT_PQ_LAMPORT_SECRET_BYTES_V2)
        .ok_or(SemanticH4BridgeProducerError::Input)?;
    if encoded.len() != expected {
        return Err(SemanticH4BridgeProducerError::Input);
    }
    encoded
        .chunks_exact(STRICT_PQ_LAMPORT_SECRET_BYTES_V2)
        .map(|chunk| {
            chunk
                .try_into()
                .map_err(|_| SemanticH4BridgeProducerError::Input)
        })
        .collect()
}

/// A strict-PQ producer whose private material is supplied by the caller.
/// This prevents a proof worker from silently generating an ungoverned key or
/// falling back to process entropy at the authority boundary.
pub(crate) struct SuppliedStrictFp16Producer {
    profile: StrictPqH4ProfileV2,
    governed_key: StrictPqGovernedVerifierKeyV2,
    chains: Vec<crate::strict_pq_public_coin_v2::StrictPqChainV2>,
    builder: StrictPqTranscriptBuilderV2,
    next_ordinal: u32,
}

impl SuppliedStrictFp16Producer {
    pub(crate) fn new(
        profile: StrictPqH4ProfileV2,
        governed_key: StrictPqGovernedVerifierKeyV2,
        secret_material: [&[u8]; 2],
        tails: [&[u8]; 2],
    ) -> Result<Self, SemanticH4BridgeProducerError> {
        if tails.iter().any(|tail| tail.len() != BINDING_V2_BYTES)
            || governed_key.round_count() == 0
        {
            return Err(SemanticH4BridgeProducerError::Input);
        }
        let mut chains = Vec::with_capacity(2);
        let mut anchors = Vec::with_capacity(2);
        for index in 0..2 {
            let mut secrets = decode_secret_material(secret_material[index])?;
            let contributor = governed_key
                .contributors()
                .get(index)
                .ok_or(SemanticH4BridgeProducerError::Input)?;
            let context = contributor.context().clone();
            let (secret_key, public_key) =
                match StrictPqLamportSecretKeyV2::keygen_from_supplied_secrets(
                    context,
                    core::mem::take(&mut secrets),
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        secrets.zeroize();
                        return Err(SemanticH4BridgeProducerError::Secret(error));
                    }
                };
            if public_key.context() != contributor.context()
                || public_key.root() != contributor.root()
            {
                return Err(SemanticH4BridgeProducerError::Input);
            }
            let tail = <[u8; BINDING_V2_BYTES]>::try_from(tails[index])
                .map_err(|_| SemanticH4BridgeProducerError::Input)?;
            let chain = build_chain_from_supplied_tail_v2(
                &public_key,
                governed_key.session_id(),
                governed_key.schedule_commitment(),
                governed_key.round_count(),
                tail,
            )
            .map_err(SemanticH4BridgeProducerError::Chain)?;
            let anchor = sign_chain_head_v2(secret_key, &governed_key, *chain.head())
                .map_err(SemanticH4BridgeProducerError::Secret)?;
            chains.push(chain);
            anchors.push(anchor);
        }
        let mut registry = StrictPqRootUseRegistryV2::new();
        let builder = StrictPqTranscriptBuilderV2::start(&governed_key, anchors, &mut registry)
            .map_err(SemanticH4BridgeProducerError::Transcript)?;
        Ok(Self {
            profile,
            governed_key,
            chains,
            builder,
            next_ordinal: 0,
        })
    }

    pub(crate) fn challenge(
        &mut self,
        descriptor: StrictPqRoundDescriptorV2,
        policy: StrictPqFp16PolicyV2,
        message: &[u8],
    ) -> Result<Vec<Fp16>, SemanticH4BridgeGkrError> {
        if descriptor.ordinal() != self.next_ordinal {
            return Err(SemanticH4BridgeGkrError::Transcript);
        }
        let reveals = self
            .chains
            .iter()
            .map(|chain| {
                chain
                    .reveals()
                    .get(self.next_ordinal as usize)
                    .copied()
                    .ok_or(SemanticH4BridgeGkrError::Transcript)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let output = self
            .builder
            .absorb_fp16_round(self.profile, policy, descriptor, message, reveals)
            .map_err(|_| SemanticH4BridgeGkrError::Transcript)?;
        self.next_ordinal = self
            .next_ordinal
            .checked_add(1)
            .ok_or(SemanticH4BridgeGkrError::Transcript)?;
        Ok(output
            .challenges()
            .samples()
            .iter()
            .map(|sample| sample.element())
            .collect())
    }

    pub(crate) fn finish(
        self,
    ) -> Result<(Vec<u8>, Vec<u8>, [u8; BINDING_V2_BYTES]), SemanticH4BridgeProducerError> {
        if self.next_ordinal != self.governed_key.round_count() {
            return Err(SemanticH4BridgeProducerError::Transcript(
                StrictPqPublicCoinV2Error::RoundCount,
            ));
        }
        let governed_key = self.governed_key.encode();
        let bundle = self
            .builder
            .finish()
            .map_err(SemanticH4BridgeProducerError::Transcript)?;
        let root = *bundle.final_transcript_root();
        let encoded_bundle = bundle
            .encode()
            .map_err(SemanticH4BridgeProducerError::Transcript)?;
        Ok((governed_key, encoded_bundle, root))
    }
}

/// Produce and immediately replay-check a semantic-H4 bridge-GKR proof.
///
/// `first_ordinal` is currently required to be zero because the strict-PQ
/// transcript builder owns the local ordinal domain.  The separate file field
/// remains explicit so a future offset-capable transcript can change the
/// contract without silently changing this producer.
#[allow(clippy::too_many_arguments)]
pub fn produce_semantic_h4_bridge_gkr(
    profile: SemanticH4BridgeProfile,
    context_commitment: crate::binding_root_v2::BindingDigestV2,
    first_ordinal: u32,
    source_values: [Vec<Fp16>; 4],
    mask_coefficients: &[Fp16],
    governed_key_bytes: &[u8],
    contributor_secret_material: [&[u8]; 2],
    contributor_tails: [&[u8]; 2],
) -> Result<ProducedSemanticH4BridgeGkr, SemanticH4BridgeProducerError> {
    if first_ordinal != 0 {
        return Err(SemanticH4BridgeProducerError::Input);
    }
    let governed_key = StrictPqGovernedVerifierKeyV2::decode(governed_key_bytes)
        .map_err(SemanticH4BridgeProducerError::Transcript)?;
    let mut coin = SuppliedStrictFp16Producer::new(
        strict_profile(profile),
        governed_key,
        contributor_secret_material,
        contributor_tails,
    )?;
    let (proof, _) = produce_public_masked_semantic_h4_bridge_gkr(
        profile,
        context_commitment,
        first_ordinal,
        source_values,
        mask_coefficients,
        |descriptor, policy, message| coin.challenge(descriptor, policy, message),
    )
    .map_err(SemanticH4BridgeProducerError::Proof)?;
    let (encoded_key, encoded_bundle, final_transcript_root) = coin.finish()?;
    let expected_schedule =
        semantic_h4_bridge_strict_schedule_commitment(&proof, context_commitment, first_ordinal)
            .map_err(SemanticH4BridgeProducerError::Encoding)?;
    let governed_key = StrictPqGovernedVerifierKeyV2::decode(&encoded_key)
        .map_err(SemanticH4BridgeProducerError::Transcript)?;
    if governed_key.schedule_commitment() != &expected_schedule {
        return Err(SemanticH4BridgeProducerError::ScheduleMismatch);
    }
    let mut registry = StrictPqRootUseRegistryV2::new();
    verify_strict_semantic_h4_bridge_gkr(
        &encoded_bundle,
        &governed_key,
        &proof,
        context_commitment,
        first_ordinal,
        &mut registry,
    )
    .map_err(SemanticH4BridgeProducerError::Replay)?;
    let encoded_proof = encode_public_masked_semantic_h4_bridge_gkr(&proof)
        .map_err(SemanticH4BridgeProducerError::Encoding)?;
    Ok(ProducedSemanticH4BridgeGkr {
        proof,
        encoded_proof,
        encoded_strict_bundle: encoded_bundle,
        governed_key: encoded_key,
        final_transcript_root,
        first_ordinal,
    })
}

/// Real varying-trace counterpart to [`produce_semantic_h4_bridge_gkr`].
/// The supplied oracle cannot choose public-coin challenges and the produced
/// bytes are replayed through the same verifier before this function returns.
#[allow(clippy::too_many_arguments)]
pub fn produce_nonuniform_semantic_h4_bridge_gkr(
    profile: SemanticH4BridgeProfile,
    context_commitment: crate::binding_root_v2::BindingDigestV2,
    first_ordinal: u32,
    oracle: &mut dyn NonuniformSemanticH4BridgeOracle,
    mask_coefficients: &[Fp16],
    governed_key_bytes: &[u8],
    contributor_secret_material: [&[u8]; 2],
    contributor_tails: [&[u8]; 2],
) -> Result<ProducedSemanticH4BridgeGkr, SemanticH4BridgeProducerError> {
    if first_ordinal != 0 {
        return Err(SemanticH4BridgeProducerError::Input);
    }
    let governed_key = StrictPqGovernedVerifierKeyV2::decode(governed_key_bytes)
        .map_err(SemanticH4BridgeProducerError::Transcript)?;
    let mut coin = SuppliedStrictFp16Producer::new(
        strict_profile(profile),
        governed_key,
        contributor_secret_material,
        contributor_tails,
    )?;
    let (proof, _) = produce_public_masked_nonuniform_semantic_h4_bridge_gkr(
        profile,
        context_commitment,
        first_ordinal,
        oracle,
        mask_coefficients,
        |descriptor, policy, message| coin.challenge(descriptor, policy, message),
    )
    .map_err(SemanticH4BridgeProducerError::Proof)?;
    let (encoded_key, encoded_bundle, final_transcript_root) = coin.finish()?;
    let expected_schedule =
        semantic_h4_bridge_strict_schedule_commitment(&proof, context_commitment, first_ordinal)
            .map_err(SemanticH4BridgeProducerError::Encoding)?;
    let governed_key = StrictPqGovernedVerifierKeyV2::decode(&encoded_key)
        .map_err(SemanticH4BridgeProducerError::Transcript)?;
    if governed_key.schedule_commitment() != &expected_schedule {
        return Err(SemanticH4BridgeProducerError::ScheduleMismatch);
    }
    let mut registry = StrictPqRootUseRegistryV2::new();
    verify_strict_semantic_h4_bridge_gkr(
        &encoded_bundle,
        &governed_key,
        &proof,
        context_commitment,
        first_ordinal,
        &mut registry,
    )
    .map_err(SemanticH4BridgeProducerError::Replay)?;
    let encoded_proof = encode_public_masked_semantic_h4_bridge_gkr(&proof)
        .map_err(SemanticH4BridgeProducerError::Encoding)?;
    Ok(ProducedSemanticH4BridgeGkr {
        proof,
        encoded_proof,
        encoded_strict_bundle: encoded_bundle,
        governed_key: encoded_key,
        final_transcript_root,
        first_ordinal,
    })
}

/// This producer is only the bridge-GKR sub-seam. It must not be used as a
/// complete H4 or major-run capability marker.
pub const SEMANTIC_H4_BRIDGE_GKR_PRODUCER_AVAILABLE: bool = true;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonzero_first_ordinal_is_rejected_before_key_material() {
        let result = produce_semantic_h4_bridge_gkr(
            SemanticH4BridgeProfile::K128,
            crate::binding_root_v2::BindingDigestV2::hash(
                crate::binding_root_v2::BindingRoleV2::Payload,
                b"context",
            )
            .unwrap(),
            1,
            [Vec::new(), Vec::new(), Vec::new(), Vec::new()],
            &[],
            &[],
            [&[], &[]],
            [&[], &[]],
        );
        assert_eq!(result, Err(SemanticH4BridgeProducerError::Input));
    }
}
