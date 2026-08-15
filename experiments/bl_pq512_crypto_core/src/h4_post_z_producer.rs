//! Producer for one authenticated current-v2 post-Z response.
//!
//! This is the smallest real post-Z acquisition seam: it consumes verified
//! semantic/H4 bridge inputs and the actual source/base coefficient vectors,
//! derives every response challenge from a caller-supplied governed strict-PQ
//! transaction, and immediately replays the serialized result. It does not
//! create a pre-alpha H4 package, semantic Circle proofs, mask PCS openings,
//! bridge divisibility claims, or a major-run acceptance receipt.

use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::binding_root_v2::{BINDING_V2_BYTES, BindingDigestV2, BindingRoleV2};
use crate::chained_public_coin::ChainedRoundDescriptor;
use crate::field::Fp16;
use crate::h4_bridge_source_response_v2::{
    H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS, H4_BRIDGE_SOURCE_RESPONSE_MESSAGE_VALUES,
    H4_BRIDGE_SOURCE_RESPONSE_PRELUDE_OUTPUTS, H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS,
    H4BridgeSourceResponseStrictRoundV2, H4BridgeSourceResponseV2, H4BridgeSourceResponseV2Error,
    encode_h4_bridge_source_response_v2, h4_bridge_source_response_strict_answer_round_v2,
    h4_bridge_source_response_strict_prelude_round_v2,
    h4_bridge_source_response_strict_row_round_v2,
    h4_bridge_source_response_strict_schedule_commitment_v2,
    produce_h4_bridge_source_response_from_verified_gkr,
    verify_strict_h4_bridge_source_response_v2,
};
use crate::h4_proof_package_v2::H4ProofProfileV2;
use crate::semantic_h4_bridge_gkr::{
    VerifiedMaskedSemanticH4BridgeGkr, VerifiedSemanticBridgeSourceBatchV3,
    semantic_h4_bridge_claim_vector_commitment,
};
use crate::semantic_h4_bridge_producer::{
    SemanticH4BridgeProducerError, SuppliedStrictFp16Producer,
};
use crate::strict_h4_interactive_coin::StrictH4InteractiveCoin;
use crate::strict_pq_public_coin_v2::{
    StrictPqGovernedVerifierKeyV2, StrictPqH4ProfileV2, StrictPqRootUseRegistryV2,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum H4PostZProducerError {
    Input,
    Binding,
    ScheduleMismatch,
    ChallengeMismatch,
    Response(H4BridgeSourceResponseV2Error),
    Strict(SemanticH4BridgeProducerError),
    FreshStrict,
}

fn chained_descriptor(
    descriptor: crate::strict_pq_public_coin_v2::StrictPqRoundDescriptorV2,
) -> ChainedRoundDescriptor {
    ChainedRoundDescriptor {
        kind: descriptor.kind(),
        ordinal: descriptor.ordinal(),
        output_count: descriptor.output_count(),
    }
}

impl From<H4BridgeSourceResponseV2Error> for H4PostZProducerError {
    fn from(value: H4BridgeSourceResponseV2Error) -> Self {
        Self::Response(value)
    }
}

/// One response plus its authenticated strict-PQ transport artifacts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProducedH4PostZResponse {
    pub response: H4BridgeSourceResponseV2,
    pub encoded_response: Vec<u8>,
    pub encoded_strict_bundle: Vec<u8>,
    pub governed_key: Vec<u8>,
    pub strict: crate::h4_bridge_source_response_v2::VerifiedStrictH4BridgeSourceResponseV2,
    pub final_transcript_root: [u8; BINDING_V2_BYTES],
    pub first_ordinal: u32,
}

fn strict_profile(profile: H4ProofProfileV2) -> StrictPqH4ProfileV2 {
    match profile {
        H4ProofProfileV2::K128 => StrictPqH4ProfileV2::K128,
        H4ProofProfileV2::K512 => StrictPqH4ProfileV2::K512,
    }
}

fn placeholder_response() -> Result<H4BridgeSourceResponseV2, H4PostZProducerError> {
    let answer_binding = BindingDigestV2::hash(
        BindingRoleV2::Payload,
        b"BL/PQ512/WAVE2/H4/POST-Z-PRODUCER/SCHEDULE-SHAPE/v1\0",
    )
    .map_err(|_| H4PostZProducerError::Binding)?;
    Ok(H4BridgeSourceResponseV2 {
        row_sumcheck_rounds: vec![
            [Fp16::ZERO; H4_BRIDGE_SOURCE_RESPONSE_MESSAGE_VALUES];
            H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS
        ],
        answer_coefficients: vec![Fp16::ZERO; H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS],
        answer_binding,
    })
}

fn strict_round_error(error: SemanticH4BridgeProducerError) -> H4PostZProducerError {
    H4PostZProducerError::Strict(error)
}

/// Produce and replay one shard-local post-Z response.
///
/// The strict key and private contributor material are inputs to the
/// transaction, not generated here. The key's schedule commitment must match
/// the canonical response schedule; this prevents a producer from silently
/// substituting a different transcript. `first_ordinal` is currently zero
/// because the native strict-PQ builder owns the local ordinal domain.
#[allow(clippy::too_many_arguments)]
pub fn produce_h4_post_z_response_from_verified_inputs(
    profile: H4ProofProfileV2,
    shard_index: u8,
    verified_gkr: &VerifiedMaskedSemanticH4BridgeGkr,
    semantic_batch: &VerifiedSemanticBridgeSourceBatchV3,
    source_coefficients: &[Fp16],
    base_coefficients: &[Fp16],
    _construction_mix: Fp16,
    context: BindingDigestV2,
    first_ordinal: u32,
    governed_key_bytes: &[u8],
    contributor_secret_material: [&[u8]; 2],
    contributor_tails: [&[u8]; 2],
) -> Result<ProducedH4PostZResponse, H4PostZProducerError> {
    if first_ordinal != 0
        || shard_index >= profile.shard_count()
        || source_coefficients.len() != H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS
        || base_coefficients.len() != H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS
    {
        return Err(H4PostZProducerError::Input);
    }
    let claim_vector_binding = semantic_batch.claim_vector_binding();
    let shape = placeholder_response()?;
    let expected_schedule = h4_bridge_source_response_strict_schedule_commitment_v2(
        &shape,
        context,
        claim_vector_binding,
        first_ordinal,
    )?;
    let governed_key = StrictPqGovernedVerifierKeyV2::decode(governed_key_bytes)
        .map_err(|error| strict_round_error(SemanticH4BridgeProducerError::Transcript(error)))?;
    if governed_key.schedule_commitment() != &expected_schedule
        || governed_key.round_count()
            != u32::try_from(H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS + 2)
                .map_err(|_| H4PostZProducerError::Input)?
    {
        return Err(H4PostZProducerError::ScheduleMismatch);
    }
    let key_for_verify = governed_key.clone();
    let mut coin = SuppliedStrictFp16Producer::new(
        strict_profile(profile),
        governed_key,
        contributor_secret_material,
        contributor_tails,
    )
    .map_err(strict_round_error)?;

    let prelude = h4_bridge_source_response_strict_prelude_round_v2(
        context,
        claim_vector_binding,
        first_ordinal,
    )?;
    let prelude_output = coin
        .challenge(prelude.descriptor, prelude.policy, &prelude.message)
        .map_err(|error| strict_round_error(SemanticH4BridgeProducerError::Proof(error)))?;
    if prelude_output.len() != H4_BRIDGE_SOURCE_RESPONSE_PRELUDE_OUTPUTS
        || prelude_output[0] != semantic_batch.claim_challenge()
    {
        return Err(H4PostZProducerError::ChallengeMismatch);
    }
    let construction_mix = prelude_output[1];

    let strict_failure = RefCell::new(None);
    let response_result = produce_h4_bridge_source_response_from_verified_gkr(
        profile,
        shard_index,
        verified_gkr,
        semantic_batch,
        source_coefficients,
        base_coefficients,
        construction_mix,
        |row_index, polynomial| {
            let round: H4BridgeSourceResponseStrictRoundV2 =
                h4_bridge_source_response_strict_row_round_v2(
                    context,
                    first_ordinal,
                    row_index,
                    polynomial,
                )
                .map_err(|_| H4BridgeSourceResponseV2Error::Encoding)?;
            let output = match coin.challenge(round.descriptor, round.policy, &round.message) {
                Ok(output) => output,
                Err(error) => {
                    strict_failure.replace(Some(error));
                    return Err(H4BridgeSourceResponseV2Error::Transcript);
                }
            };
            if output.len() != 1 {
                return Err(H4BridgeSourceResponseV2Error::Transcript);
            }
            Ok(output[0])
        },
    );
    if let Some(error) = strict_failure.into_inner() {
        return Err(strict_round_error(SemanticH4BridgeProducerError::Proof(
            error,
        )));
    }
    let response = response_result?;
    let answer: H4BridgeSourceResponseStrictRoundV2 =
        h4_bridge_source_response_strict_answer_round_v2(&response, context, first_ordinal)?;
    let answer_output = coin
        .challenge(answer.descriptor, answer.policy, &answer.message)
        .map_err(|error| strict_round_error(SemanticH4BridgeProducerError::Proof(error)))?;
    if answer_output.len() != 1 {
        return Err(H4PostZProducerError::ChallengeMismatch);
    }

    let (encoded_key, encoded_bundle, final_transcript_root) =
        coin.finish().map_err(strict_round_error)?;
    let actual_schedule = h4_bridge_source_response_strict_schedule_commitment_v2(
        &response,
        context,
        claim_vector_binding,
        first_ordinal,
    )?;
    if actual_schedule != expected_schedule {
        return Err(H4PostZProducerError::ScheduleMismatch);
    }
    let encoded_response = encode_h4_bridge_source_response_v2(&response)?;
    let verified_key = StrictPqGovernedVerifierKeyV2::decode(&encoded_key)
        .map_err(|error| strict_round_error(SemanticH4BridgeProducerError::Transcript(error)))?;
    if verified_key != key_for_verify {
        return Err(H4PostZProducerError::ScheduleMismatch);
    }
    let mut registry = StrictPqRootUseRegistryV2::new();
    let strict = verify_strict_h4_bridge_source_response_v2(
        &encoded_bundle,
        &verified_key,
        profile,
        &response,
        context,
        claim_vector_binding,
        first_ordinal,
        &mut registry,
    )?;
    if strict.final_transcript_root() != &final_transcript_root {
        return Err(H4PostZProducerError::ChallengeMismatch);
    }
    Ok(ProducedH4PostZResponse {
        response,
        encoded_response,
        encoded_strict_bundle: encoded_bundle,
        governed_key: encoded_key,
        strict,
        final_transcript_root,
        first_ordinal,
    })
}

/// Produce one post-Z response from a live committed-tensor projection.
///
/// The prelude first fixes the semantic batching challenge, construction mix,
/// and all nine tensor-projection coordinates.  Only then may the callbacks
/// authenticate the semantic batch and fold the already-committed source/base
/// tensors.  The ordinary response sumcheck runs afterward, so no witness
/// value depends on one of its own adaptive row challenges.
#[allow(clippy::too_many_arguments)]
pub fn produce_h4_post_z_response_from_projection_oracle(
    profile: H4ProofProfileV2,
    shard_index: u8,
    verified_gkr: &VerifiedMaskedSemanticH4BridgeGkr,
    context: BindingDigestV2,
    first_ordinal: u32,
    governed_key_bytes: &[u8],
    contributor_secret_material: [&[u8]; 2],
    contributor_tails: [&[u8]; 2],
    semantic_batch_provider: impl FnOnce(
        Fp16,
    ) -> Result<
        VerifiedSemanticBridgeSourceBatchV3,
        H4PostZProducerError,
    >,
    coefficient_oracle: impl FnOnce(
        &[Fp16],
        Fp16,
    ) -> Result<(Vec<Fp16>, Vec<Fp16>), H4PostZProducerError>,
) -> Result<ProducedH4PostZResponse, H4PostZProducerError> {
    if first_ordinal != 0 || shard_index >= profile.shard_count() {
        return Err(H4PostZProducerError::Input);
    }
    let claim_vector_binding = semantic_h4_bridge_claim_vector_commitment(verified_gkr)
        .map_err(|_| H4PostZProducerError::Binding)?;
    let shape = placeholder_response()?;
    let expected_schedule = h4_bridge_source_response_strict_schedule_commitment_v2(
        &shape,
        context,
        claim_vector_binding,
        first_ordinal,
    )?;
    let governed_key = StrictPqGovernedVerifierKeyV2::decode(governed_key_bytes)
        .map_err(|error| strict_round_error(SemanticH4BridgeProducerError::Transcript(error)))?;
    if governed_key.schedule_commitment() != &expected_schedule
        || governed_key.round_count()
            != u32::try_from(H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS + 2)
                .map_err(|_| H4PostZProducerError::Input)?
    {
        return Err(H4PostZProducerError::ScheduleMismatch);
    }
    let key_for_verify = governed_key.clone();
    let mut coin = SuppliedStrictFp16Producer::new(
        strict_profile(profile),
        governed_key,
        contributor_secret_material,
        contributor_tails,
    )
    .map_err(strict_round_error)?;
    let prelude = h4_bridge_source_response_strict_prelude_round_v2(
        context,
        claim_vector_binding,
        first_ordinal,
    )?;
    let prelude_output = coin
        .challenge(prelude.descriptor, prelude.policy, &prelude.message)
        .map_err(|error| strict_round_error(SemanticH4BridgeProducerError::Proof(error)))?;
    if prelude_output.len() != H4_BRIDGE_SOURCE_RESPONSE_PRELUDE_OUTPUTS {
        return Err(H4PostZProducerError::ChallengeMismatch);
    }
    let semantic_batch = semantic_batch_provider(prelude_output[0])?;
    if semantic_batch.claim_vector_binding() != claim_vector_binding
        || semantic_batch.claim_challenge() != prelude_output[0]
    {
        return Err(H4PostZProducerError::ChallengeMismatch);
    }
    let construction_mix = prelude_output[1];
    let (source_coefficients, base_coefficients) =
        coefficient_oracle(&prelude_output[2..], construction_mix)?;
    if source_coefficients.len() != H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS
        || base_coefficients.len() != H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS
    {
        return Err(H4PostZProducerError::Input);
    }

    let strict_failure = RefCell::new(None);
    let response_result = produce_h4_bridge_source_response_from_verified_gkr(
        profile,
        shard_index,
        verified_gkr,
        &semantic_batch,
        &source_coefficients,
        &base_coefficients,
        construction_mix,
        |row_index, polynomial| {
            let round = h4_bridge_source_response_strict_row_round_v2(
                context,
                first_ordinal,
                row_index,
                polynomial,
            )
            .map_err(|_| H4BridgeSourceResponseV2Error::Encoding)?;
            let output = match coin.challenge(round.descriptor, round.policy, &round.message) {
                Ok(output) => output,
                Err(error) => {
                    strict_failure.replace(Some(error));
                    return Err(H4BridgeSourceResponseV2Error::Transcript);
                }
            };
            if output.len() != 1 {
                return Err(H4BridgeSourceResponseV2Error::Transcript);
            }
            Ok(output[0])
        },
    );
    if let Some(error) = strict_failure.into_inner() {
        return Err(strict_round_error(SemanticH4BridgeProducerError::Proof(
            error,
        )));
    }
    let response = response_result?;
    let answer =
        h4_bridge_source_response_strict_answer_round_v2(&response, context, first_ordinal)?;
    let answer_output = coin
        .challenge(answer.descriptor, answer.policy, &answer.message)
        .map_err(|error| strict_round_error(SemanticH4BridgeProducerError::Proof(error)))?;
    if answer_output.len() != 1 {
        return Err(H4PostZProducerError::ChallengeMismatch);
    }
    let (encoded_key, encoded_bundle, final_transcript_root) =
        coin.finish().map_err(strict_round_error)?;
    let actual_schedule = h4_bridge_source_response_strict_schedule_commitment_v2(
        &response,
        context,
        claim_vector_binding,
        first_ordinal,
    )?;
    if actual_schedule != expected_schedule {
        return Err(H4PostZProducerError::ScheduleMismatch);
    }
    let encoded_response = encode_h4_bridge_source_response_v2(&response)?;
    let verified_key = StrictPqGovernedVerifierKeyV2::decode(&encoded_key)
        .map_err(|error| strict_round_error(SemanticH4BridgeProducerError::Transcript(error)))?;
    if verified_key != key_for_verify {
        return Err(H4PostZProducerError::ScheduleMismatch);
    }
    let mut registry = StrictPqRootUseRegistryV2::new();
    let strict = verify_strict_h4_bridge_source_response_v2(
        &encoded_bundle,
        &verified_key,
        profile,
        &response,
        context,
        claim_vector_binding,
        first_ordinal,
        &mut registry,
    )?;
    if strict.final_transcript_root() != &final_transcript_root {
        return Err(H4PostZProducerError::ChallengeMismatch);
    }
    Ok(ProducedH4PostZResponse {
        response,
        encoded_response,
        encoded_strict_bundle: encoded_bundle,
        governed_key: encoded_key,
        strict,
        final_transcript_root,
        first_ordinal,
    })
}

/// Fresh-key variant for a run-local calibration authority.  It derives the
/// canonical schedule before key generation, keeps private Lamport material
/// in-process, and immediately replays the completed transcript.
#[allow(clippy::too_many_arguments)]
pub fn produce_h4_post_z_response_from_fresh_projection_oracle(
    profile: H4ProofProfileV2,
    shard_index: u8,
    attempt: u16,
    session_id: [u8; 64],
    verified_gkr: &VerifiedMaskedSemanticH4BridgeGkr,
    context: BindingDigestV2,
    semantic_batch_provider: impl FnOnce(
        Fp16,
    ) -> Result<
        VerifiedSemanticBridgeSourceBatchV3,
        H4PostZProducerError,
    >,
    coefficient_oracle: impl FnOnce(
        &[Fp16],
        Fp16,
    ) -> Result<(Vec<Fp16>, Vec<Fp16>), H4PostZProducerError>,
) -> Result<ProducedH4PostZResponse, H4PostZProducerError> {
    let first_ordinal = 0;
    if shard_index >= profile.shard_count() || attempt >= 4 {
        return Err(H4PostZProducerError::Input);
    }
    let claim_vector_binding = semantic_h4_bridge_claim_vector_commitment(verified_gkr)
        .map_err(|_| H4PostZProducerError::Binding)?;
    let shape = placeholder_response()?;
    let schedule = h4_bridge_source_response_strict_schedule_commitment_v2(
        &shape,
        context,
        claim_vector_binding,
        first_ordinal,
    )?;
    let round_count = u32::try_from(H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS + 2)
        .map_err(|_| H4PostZProducerError::Input)?;
    let mut coin = StrictH4InteractiveCoin::new_for_schedule(
        profile,
        session_id,
        attempt,
        schedule,
        round_count,
    )
    .map_err(|_| H4PostZProducerError::FreshStrict)?;
    let prelude = h4_bridge_source_response_strict_prelude_round_v2(
        context,
        claim_vector_binding,
        first_ordinal,
    )?;
    let prelude_output = coin
        .challenge_with_policy(
            chained_descriptor(prelude.descriptor),
            prelude.policy,
            &prelude.message,
        )
        .map_err(|_| H4PostZProducerError::FreshStrict)?;
    if prelude_output.len() != H4_BRIDGE_SOURCE_RESPONSE_PRELUDE_OUTPUTS {
        return Err(H4PostZProducerError::ChallengeMismatch);
    }
    let semantic_batch = semantic_batch_provider(prelude_output[0])?;
    if semantic_batch.claim_vector_binding() != claim_vector_binding
        || semantic_batch.claim_challenge() != prelude_output[0]
    {
        return Err(H4PostZProducerError::ChallengeMismatch);
    }
    let construction_mix = prelude_output[1];
    let (source_coefficients, base_coefficients) =
        coefficient_oracle(&prelude_output[2..], construction_mix)?;
    if source_coefficients.len() != H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS
        || base_coefficients.len() != H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS
    {
        return Err(H4PostZProducerError::Input);
    }
    let strict_failure = RefCell::new(false);
    let response = produce_h4_bridge_source_response_from_verified_gkr(
        profile,
        shard_index,
        verified_gkr,
        &semantic_batch,
        &source_coefficients,
        &base_coefficients,
        construction_mix,
        |row_index, polynomial| {
            let round = h4_bridge_source_response_strict_row_round_v2(
                context,
                first_ordinal,
                row_index,
                polynomial,
            )?;
            let output = coin
                .challenge_with_policy(
                    chained_descriptor(round.descriptor),
                    round.policy,
                    &round.message,
                )
                .map_err(|_| {
                    strict_failure.replace(true);
                    H4BridgeSourceResponseV2Error::Transcript
                })?;
            output
                .first()
                .copied()
                .filter(|_| output.len() == 1)
                .ok_or(H4BridgeSourceResponseV2Error::Transcript)
        },
    )?;
    if strict_failure.into_inner() {
        return Err(H4PostZProducerError::FreshStrict);
    }
    let answer =
        h4_bridge_source_response_strict_answer_round_v2(&response, context, first_ordinal)?;
    if coin
        .challenge_with_policy(
            chained_descriptor(answer.descriptor),
            answer.policy,
            &answer.message,
        )
        .map_err(|_| H4PostZProducerError::FreshStrict)?
        .len()
        != 1
    {
        return Err(H4PostZProducerError::ChallengeMismatch);
    }
    let finished = coin
        .finish()
        .map_err(|_| H4PostZProducerError::FreshStrict)?;
    let governed_key = StrictPqGovernedVerifierKeyV2::decode(&finished.governed_key)
        .map_err(|_| H4PostZProducerError::FreshStrict)?;
    let encoded_response = encode_h4_bridge_source_response_v2(&response)?;
    let mut registry = StrictPqRootUseRegistryV2::new();
    let strict = verify_strict_h4_bridge_source_response_v2(
        &finished.encoded_bundle,
        &governed_key,
        profile,
        &response,
        context,
        claim_vector_binding,
        first_ordinal,
        &mut registry,
    )?;
    if strict.final_transcript_root() != &finished.final_transcript_root {
        return Err(H4PostZProducerError::ChallengeMismatch);
    }
    Ok(ProducedH4PostZResponse {
        response,
        encoded_response,
        encoded_strict_bundle: finished.encoded_bundle,
        governed_key: finished.governed_key,
        strict,
        final_transcript_root: finished.final_transcript_root,
        first_ordinal,
    })
}

/// This is a post-Z response sub-producer, not complete H4 or major-run
/// production.
pub const H4_POST_Z_RESPONSE_PRODUCER_AVAILABLE: bool = true;
