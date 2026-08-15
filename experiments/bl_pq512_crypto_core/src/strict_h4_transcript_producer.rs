//! Current H4-v2 strict-public-coin producer boundary.
//!
//! This module produces only the authenticated `BLSPQPC2` transcript bundle.
//! It does not produce an H4 shard, a post-Z response, or an accepting
//! aggregate.  Keeping those authorities separate prevents a transcript-only
//! artifact from being mistaken for proof production.

use alloc::vec::Vec;

use crate::binding_root_v2::BINDING_V2_BYTES;
use crate::h4_proof_package_v2::{
    H4_GLOBAL_RAW_FRAMES_V2_MAX_BYTES, H4ProofPackageV2Error, H4ProofProfileV2,
    h4_strict_pq_schedule_v2, parse_h4_global_round_frame_v2, verify_h4_global_transcript_v2,
};
use crate::strict_pq_public_coin_v2::{
    STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2, STRICT_PQ_LAMPORT_SECRET_BYTES_V2,
    StrictPqGovernedVerifierKeyV2, StrictPqH4ProfileV2, StrictPqLamportSecretKeyV2,
    StrictPqPublicCoinV2Error, StrictPqRootUseRegistryV2, StrictPqTranscriptBuilderV2,
    build_chain_from_supplied_tail_v2, sign_chain_head_v2,
};
use zeroize::Zeroize;

pub const STRICT_H4_TRANSCRIPT_SECRET_BYTES_V2: usize =
    STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2 * STRICT_PQ_LAMPORT_SECRET_BYTES_V2;
pub const STRICT_H4_TRANSCRIPT_TAIL_BYTES_V2: usize = BINDING_V2_BYTES;

#[derive(Debug)]
pub enum StrictH4TranscriptProducerError {
    InputShape,
    FrameLength,
    Frame(H4ProofPackageV2Error),
    Schedule(H4ProofPackageV2Error),
    GovernedKey(StrictPqPublicCoinV2Error),
    Secret(StrictPqPublicCoinV2Error),
    Chain(StrictPqPublicCoinV2Error),
    Transcript(StrictPqPublicCoinV2Error),
    TranscriptReplay(crate::h4_proof_package_v2::H4GlobalTranscriptV2Error),
    Bundle(StrictPqPublicCoinV2Error),
}

pub struct StrictH4TranscriptProducerInput<'a> {
    pub profile: H4ProofProfileV2,
    pub governed_key: &'a [u8],
    pub contributor_secret_material: [&'a [u8]; 2],
    pub contributor_tails: [&'a [u8]; 2],
    /// Canonical `u32be frame_length || BLH4GR02 frame` records in schedule order.
    pub raw_frames: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProducedStrictH4TranscriptV2 {
    pub encoded_bundle: Vec<u8>,
    pub final_transcript_root: [u8; BINDING_V2_BYTES],
    pub round_count: usize,
}

fn strict_profile(profile: H4ProofProfileV2) -> StrictPqH4ProfileV2 {
    match profile {
        H4ProofProfileV2::K128 => StrictPqH4ProfileV2::K128,
        H4ProofProfileV2::K512 => StrictPqH4ProfileV2::K512,
    }
}

fn decode_secret_material(
    encoded: &[u8],
) -> Result<Vec<[u8; STRICT_PQ_LAMPORT_SECRET_BYTES_V2]>, StrictH4TranscriptProducerError> {
    if encoded.len() != STRICT_H4_TRANSCRIPT_SECRET_BYTES_V2 {
        return Err(StrictH4TranscriptProducerError::InputShape);
    }
    let mut result = Vec::with_capacity(STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2);
    for chunk in encoded.chunks_exact(STRICT_PQ_LAMPORT_SECRET_BYTES_V2) {
        let secret = <[u8; STRICT_PQ_LAMPORT_SECRET_BYTES_V2]>::try_from(chunk)
            .map_err(|_| StrictH4TranscriptProducerError::InputShape)?;
        result.push(secret);
    }
    if result.len() != STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2 {
        result.zeroize();
        return Err(StrictH4TranscriptProducerError::InputShape);
    }
    Ok(result)
}

fn decode_tail(encoded: &[u8]) -> Result<[u8; BINDING_V2_BYTES], StrictH4TranscriptProducerError> {
    encoded
        .try_into()
        .map_err(|_| StrictH4TranscriptProducerError::InputShape)
}

fn decode_frames(
    profile: H4ProofProfileV2,
    raw_frames: &[u8],
) -> Result<Vec<Vec<u8>>, StrictH4TranscriptProducerError> {
    if raw_frames.is_empty() || raw_frames.len() > H4_GLOBAL_RAW_FRAMES_V2_MAX_BYTES {
        return Err(StrictH4TranscriptProducerError::InputShape);
    }
    let (descriptors, _) =
        h4_strict_pq_schedule_v2(profile).map_err(StrictH4TranscriptProducerError::Schedule)?;
    let mut offset = 0_usize;
    let mut frames = Vec::with_capacity(descriptors.len());
    for descriptor in descriptors {
        let length_end = offset
            .checked_add(4)
            .ok_or(StrictH4TranscriptProducerError::FrameLength)?;
        let length_bytes = raw_frames
            .get(offset..length_end)
            .ok_or(StrictH4TranscriptProducerError::FrameLength)?;
        let frame_length = usize::try_from(u32::from_be_bytes(
            length_bytes
                .try_into()
                .map_err(|_| StrictH4TranscriptProducerError::FrameLength)?,
        ))
        .map_err(|_| StrictH4TranscriptProducerError::FrameLength)?;
        offset = length_end;
        let frame_end = offset
            .checked_add(frame_length)
            .ok_or(StrictH4TranscriptProducerError::FrameLength)?;
        let frame = raw_frames
            .get(offset..frame_end)
            .ok_or(StrictH4TranscriptProducerError::FrameLength)?;
        parse_h4_global_round_frame_v2(frame, profile, descriptor)
            .map_err(StrictH4TranscriptProducerError::Frame)?;
        frames.push(frame.to_vec());
        offset = frame_end;
    }
    if offset != raw_frames.len() {
        return Err(StrictH4TranscriptProducerError::FrameLength);
    }
    Ok(frames)
}

/// Produce and immediately replay-check one current H4-v2 strict transcript.
///
/// The caller supplies all private key material and chain tails; this function
/// never creates custody material or falls back to OS entropy.  A returned
/// bundle is still transcript evidence only and cannot enter the decisive
/// composition without the separate H4 shard and post-Z authorities.
pub fn produce_strict_h4_transcript(
    input: StrictH4TranscriptProducerInput<'_>,
) -> Result<ProducedStrictH4TranscriptV2, StrictH4TranscriptProducerError> {
    if input.governed_key.len() == 0
        || input.contributor_secret_material.len() != 2
        || input.contributor_tails.len() != 2
    {
        return Err(StrictH4TranscriptProducerError::InputShape);
    }
    let governed_key = StrictPqGovernedVerifierKeyV2::decode(input.governed_key)
        .map_err(StrictH4TranscriptProducerError::GovernedKey)?;
    if governed_key.round_count() != input.profile.transcript_rounds() {
        return Err(StrictH4TranscriptProducerError::InputShape);
    }
    let frames = decode_frames(input.profile, input.raw_frames)?;
    if frames.len() != usize::try_from(governed_key.round_count()).unwrap_or(0) {
        return Err(StrictH4TranscriptProducerError::InputShape);
    }

    let mut chains = Vec::with_capacity(2);
    let mut anchors = Vec::with_capacity(2);
    for index in 0..2 {
        let mut secrets = decode_secret_material(input.contributor_secret_material[index])?;
        let context = governed_key
            .contributors()
            .get(index)
            .ok_or(StrictH4TranscriptProducerError::InputShape)?
            .context()
            .clone();
        let (secret_key, public_key) =
            match StrictPqLamportSecretKeyV2::keygen_from_supplied_secrets(
                context,
                core::mem::take(&mut secrets),
            ) {
                Ok(value) => value,
                Err(error) => {
                    secrets.zeroize();
                    return Err(StrictH4TranscriptProducerError::Secret(error));
                }
            };
        let governed_public_key = governed_key
            .contributors()
            .get(index)
            .ok_or(StrictH4TranscriptProducerError::InputShape)?;
        if public_key.context() != governed_public_key.context()
            || public_key.root() != governed_public_key.root()
        {
            return Err(StrictH4TranscriptProducerError::InputShape);
        }
        let tail = decode_tail(input.contributor_tails[index])?;
        let chain = build_chain_from_supplied_tail_v2(
            &public_key,
            governed_key.session_id(),
            governed_key.schedule_commitment(),
            governed_key.round_count(),
            tail,
        )
        .map_err(StrictH4TranscriptProducerError::Chain)?;
        let anchor = sign_chain_head_v2(secret_key, &governed_key, *chain.head())
            .map_err(StrictH4TranscriptProducerError::Secret)?;
        chains.push(chain);
        anchors.push(anchor);
    }

    let mut registry = StrictPqRootUseRegistryV2::new();
    let mut builder = StrictPqTranscriptBuilderV2::start(&governed_key, anchors, &mut registry)
        .map_err(StrictH4TranscriptProducerError::Transcript)?;
    let profile = strict_profile(input.profile);
    let (descriptors, policies) = h4_strict_pq_schedule_v2(input.profile)
        .map_err(StrictH4TranscriptProducerError::Schedule)?;
    for (ordinal, ((descriptor, policy), frame)) in descriptors
        .into_iter()
        .zip(policies)
        .zip(&frames)
        .enumerate()
    {
        let reveals = chains
            .iter()
            .map(|chain| {
                chain
                    .reveals()
                    .get(ordinal)
                    .copied()
                    .ok_or(StrictH4TranscriptProducerError::InputShape)
            })
            .collect::<Result<Vec<_>, _>>()?;
        builder
            .absorb_fp16_round(profile, policy, descriptor, frame, reveals)
            .map_err(StrictH4TranscriptProducerError::Transcript)?;
    }
    let bundle = builder
        .finish()
        .map_err(StrictH4TranscriptProducerError::Bundle)?;
    let encoded_bundle = bundle
        .encode()
        .map_err(StrictH4TranscriptProducerError::Bundle)?;
    let mut replay_registry = StrictPqRootUseRegistryV2::new();
    verify_h4_global_transcript_v2(
        input.profile,
        &governed_key,
        &encoded_bundle,
        input.raw_frames,
        &mut replay_registry,
    )
    .map_err(StrictH4TranscriptProducerError::TranscriptReplay)?;
    Ok(ProducedStrictH4TranscriptV2 {
        final_transcript_root: *bundle.final_transcript_root(),
        round_count: frames.len(),
        encoded_bundle,
    })
}
