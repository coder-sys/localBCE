//! Native pre-verification for the typed-state component inside a v3 envelope.
//!
//! The outer envelope parser owns framing and component hashes. This module
//! owns the next narrow boundary: it reads the typed-state body at the
//! authenticated offset and invokes the typed-state verifier with the
//! program commitment and profile code from the trusted layout. It never
//! turns the result into an accepting v3 receipt; semantic, H4, and parent
//! receipts remain separate authorities.

use alloc::vec::Vec;
use std::io::{Read, Seek, SeekFrom};

use crate::chained_public_coin::MAX_CHAIN_BUNDLE_BYTES;
use crate::composite_parent_public_coin::{
    VerifiedCompositeParentTranscriptReplay, verify_composite_parent_transcript,
};
use crate::h4_proof_package_v2::{
    H4AggregatePackageV2VerificationKey, H4AggregateStreamV2Error, VerifiedH4PreAlphaV2,
    verify_h4_pre_alpha_v2,
};
use crate::strict_pq_public_coin_v2::StrictPqRootUseRegistryV2;
use crate::typed_state_proof_package::{
    TYPED_STATE_PROOF_PACKAGE_BYTES, TypedStateProofPackageError, TypedStateProofVerificationKey,
    VerifiedTypedStateV3, verify_typed_state_component_v3,
};
use crate::v3_composite_envelope::{
    V3ComponentKind, V3EnvelopeError, V3ParsedEnvelope, V3ProfileLayout,
};

#[derive(Debug)]
pub enum V3TypedComponentPreflightError {
    Envelope(V3EnvelopeError),
    Io(std::io::ErrorKind),
    TypedState(TypedStateProofPackageError),
}

impl From<V3EnvelopeError> for V3TypedComponentPreflightError {
    fn from(value: V3EnvelopeError) -> Self {
        Self::Envelope(value)
    }
}

impl From<TypedStateProofPackageError> for V3TypedComponentPreflightError {
    fn from(value: TypedStateProofPackageError) -> Self {
        Self::TypedState(value)
    }
}

#[derive(Debug)]
pub enum V3H4ComponentPreflightError {
    Envelope(V3EnvelopeError),
    Io(std::io::ErrorKind),
    H4(H4AggregateStreamV2Error),
}

impl From<V3EnvelopeError> for V3H4ComponentPreflightError {
    fn from(value: V3EnvelopeError) -> Self {
        Self::Envelope(value)
    }
}

impl From<H4AggregateStreamV2Error> for V3H4ComponentPreflightError {
    fn from(value: H4AggregateStreamV2Error) -> Self {
        Self::H4(value)
    }
}

#[derive(Debug)]
pub enum V3TranscriptComponentPreflightError {
    Envelope(V3EnvelopeError),
    Io(std::io::ErrorKind),
    Parent(crate::composite_parent_public_coin::CompositeParentPublicCoinError),
}

impl From<V3EnvelopeError> for V3TranscriptComponentPreflightError {
    fn from(value: V3EnvelopeError) -> Self {
        Self::Envelope(value)
    }
}

impl From<crate::composite_parent_public_coin::CompositeParentPublicCoinError>
    for V3TranscriptComponentPreflightError
{
    fn from(value: crate::composite_parent_public_coin::CompositeParentPublicCoinError) -> Self {
        Self::Parent(value)
    }
}

fn profile_label(profile_code: u8) -> Result<&'static [u8], V3TypedComponentPreflightError> {
    match profile_code {
        1 => Ok(b"K128_CALIBRATION"),
        3 => Ok(b"K512_CALIBRATION"),
        _ => Err(V3EnvelopeError::Profile.into()),
    }
}

fn typed_component_index(
    layout: &V3ProfileLayout,
) -> Result<usize, V3TypedComponentPreflightError> {
    layout
        .components
        .iter()
        .position(|component| component.kind == V3ComponentKind::TypedState)
        .ok_or_else(|| V3EnvelopeError::ComponentOrder.into())
}

fn h4_component_index(layout: &V3ProfileLayout) -> Result<usize, V3H4ComponentPreflightError> {
    layout
        .components
        .iter()
        .position(|component| component.kind == V3ComponentKind::H4)
        .ok_or_else(|| V3EnvelopeError::ComponentOrder.into())
}

fn transcript_component_index(
    layout: &V3ProfileLayout,
) -> Result<usize, V3TranscriptComponentPreflightError> {
    layout
        .components
        .iter()
        .position(|component| component.kind == V3ComponentKind::CompositeTranscript)
        .ok_or_else(|| V3EnvelopeError::ComponentOrder.into())
}

fn read_zeroes<R: Read>(
    reader: &mut R,
    mut remaining: u64,
) -> Result<(), V3TranscriptComponentPreflightError> {
    let mut buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        let take = usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| {
            V3TranscriptComponentPreflightError::Io(std::io::ErrorKind::InvalidData)
        })?;
        reader
            .read_exact(&mut buffer[..take])
            .map_err(|error| V3TranscriptComponentPreflightError::Io(error.kind()))?;
        if buffer[..take].iter().any(|byte| *byte != 0) {
            return Err(V3EnvelopeError::TranscriptPadding.into());
        }
        remaining -= take as u64;
    }
    Ok(())
}

/// Replay the authenticated `BLV3TR01` component without treating it as a
/// completed parent. The envelope parser already checked the component hash
/// and zero padding; this boundary additionally decodes and replays the
/// bounded chained public-coin bundle.
pub fn verify_composite_transcript_component<R: Read + Seek>(
    reader: &mut R,
    layout: &V3ProfileLayout,
    parsed: &V3ParsedEnvelope,
) -> Result<VerifiedCompositeParentTranscriptReplay, V3TranscriptComponentPreflightError> {
    layout.validate()?;
    if parsed.profile_code != layout.profile_code
        || parsed.layout_commitment != layout.layout_commitment
    {
        return Err(V3EnvelopeError::Layout.into());
    }
    let index = transcript_component_index(layout)?;
    let descriptor = parsed
        .descriptors
        .get(index)
        .ok_or_else(|| V3EnvelopeError::ComponentOrder)?;
    if descriptor.kind != V3ComponentKind::CompositeTranscript
        || descriptor.grammar != crate::v3_composite_envelope::V3_TRANSCRIPT_GRAMMAR
        || descriptor.length < crate::v3_composite_envelope::V3_TRANSCRIPT_PREFIX_BYTES + 1
    {
        return Err(V3EnvelopeError::Transcript.into());
    }
    let offset = *parsed
        .component_offsets
        .get(index)
        .ok_or_else(|| V3EnvelopeError::ComponentOrder)?;
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|error| V3TranscriptComponentPreflightError::Io(error.kind()))?;
    let mut prefix = [0_u8; crate::v3_composite_envelope::V3_TRANSCRIPT_PREFIX_BYTES as usize];
    reader
        .read_exact(&mut prefix)
        .map_err(|error| V3TranscriptComponentPreflightError::Io(error.kind()))?;
    if prefix[..8] != crate::v3_composite_envelope::V3_TRANSCRIPT_MAGIC[..]
        || u16::from_be_bytes(prefix[8..10].try_into().map_err(|_| {
            V3TranscriptComponentPreflightError::Io(std::io::ErrorKind::InvalidData)
        })?) != descriptor.grammar
        || u16::from_be_bytes(prefix[10..12].try_into().map_err(|_| {
            V3TranscriptComponentPreflightError::Io(std::io::ErrorKind::InvalidData)
        })?) != crate::v3_composite_envelope::V3_TRANSCRIPT_FLAGS
    {
        return Err(V3EnvelopeError::Transcript.into());
    }
    let payload_length =
        u64::from_be_bytes(prefix[12..20].try_into().map_err(|_| {
            V3TranscriptComponentPreflightError::Io(std::io::ErrorKind::InvalidData)
        })?);
    let maximum_payload = descriptor
        .length
        .checked_sub(crate::v3_composite_envelope::V3_TRANSCRIPT_PREFIX_BYTES)
        .ok_or(V3EnvelopeError::Transcript)?;
    if payload_length == 0
        || payload_length > maximum_payload
        || payload_length > MAX_CHAIN_BUNDLE_BYTES as u64
    {
        return Err(V3EnvelopeError::Transcript.into());
    }
    let payload_size = usize::try_from(payload_length)
        .map_err(|_| V3TranscriptComponentPreflightError::Io(std::io::ErrorKind::OutOfMemory))?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(payload_size)
        .map_err(|_| V3TranscriptComponentPreflightError::Io(std::io::ErrorKind::OutOfMemory))?;
    payload.resize(payload_size, 0);
    reader
        .read_exact(&mut payload)
        .map_err(|error| V3TranscriptComponentPreflightError::Io(error.kind()))?;
    read_zeroes(reader, maximum_payload - payload_length)?;
    Ok(verify_composite_parent_transcript(&payload)?)
}

/// Verify the typed-state component at the offset authenticated by the v3
/// envelope parser. The file is read exactly once for this component and the
/// native verifier receives no caller-selected profile or program key.
pub fn verify_typed_state_component_from_v3_envelope<R: Read + Seek>(
    reader: &mut R,
    layout: &V3ProfileLayout,
    parsed: &V3ParsedEnvelope,
) -> Result<VerifiedTypedStateV3, V3TypedComponentPreflightError> {
    layout.validate()?;
    if parsed.profile_code != layout.profile_code
        || parsed.layout_commitment != layout.layout_commitment
    {
        return Err(V3EnvelopeError::Layout.into());
    }
    let index = typed_component_index(layout)?;
    let descriptor = parsed
        .descriptors
        .get(index)
        .ok_or_else(|| V3EnvelopeError::ComponentOrder)?;
    let expected_length = u64::try_from(TYPED_STATE_PROOF_PACKAGE_BYTES)
        .map_err(|_| V3EnvelopeError::ComponentLength)?;
    if descriptor.kind != V3ComponentKind::TypedState || descriptor.length != expected_length {
        return Err(V3EnvelopeError::ComponentLength.into());
    }
    let offset = *parsed
        .component_offsets
        .get(index)
        .ok_or_else(|| V3EnvelopeError::ComponentOrder)?;
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|error| V3TypedComponentPreflightError::Io(error.kind()))?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(TYPED_STATE_PROOF_PACKAGE_BYTES)
        .map_err(|_| V3TypedComponentPreflightError::Io(std::io::ErrorKind::OutOfMemory))?;
    encoded.resize(TYPED_STATE_PROOF_PACKAGE_BYTES, 0);
    reader
        .read_exact(&mut encoded)
        .map_err(|error| V3TypedComponentPreflightError::Io(error.kind()))?;

    let expected_program_commitment = layout.components[index].expected_program_commitment;
    let expected_profile_label = profile_label(layout.profile_code)?;
    verify_typed_state_component_v3(
        &encoded,
        TypedStateProofVerificationKey {
            expected_profile_label,
            expected_program_commitment,
        },
        layout.profile_code,
        &layout.profile_id,
        &parsed.public_fields,
        &parsed.sidecar,
    )
    .map_err(Into::into)
}

/// Verify the H4 component at the offset authenticated by the v3 envelope.
/// The caller supplies only the independently governed H4 verification key;
/// the package bytes remain untrusted until the native pre-alpha verifier has
/// replayed the strict transcript, global frames, ordered shard packages, and
/// native algebra boundaries.  This function intentionally stops at the
/// pre-alpha receipt because post-Z source responses and the source-augmented
/// mask PCS are separate authority products.
pub fn verify_h4_component_from_v3_envelope<R: Read + Seek>(
    reader: &mut R,
    layout: &V3ProfileLayout,
    parsed: &V3ParsedEnvelope,
    key: &H4AggregatePackageV2VerificationKey,
    root_use_registry: &mut StrictPqRootUseRegistryV2,
) -> Result<VerifiedH4PreAlphaV2, V3H4ComponentPreflightError> {
    layout.validate()?;
    if parsed.profile_code != layout.profile_code
        || parsed.layout_commitment != layout.layout_commitment
        || key.profile().code() != layout.profile_code
    {
        return Err(V3EnvelopeError::Layout.into());
    }
    let index = h4_component_index(layout)?;
    let descriptor = parsed
        .descriptors
        .get(index)
        .ok_or_else(|| V3EnvelopeError::ComponentOrder)?;
    if descriptor.kind != V3ComponentKind::H4 || descriptor.length == 0 {
        return Err(V3EnvelopeError::ComponentLength.into());
    }
    let offset = *parsed
        .component_offsets
        .get(index)
        .ok_or_else(|| V3EnvelopeError::ComponentOrder)?;
    verify_h4_pre_alpha_v2(reader, offset, descriptor.length, key, root_use_registry)
        .map_err(Into::into)
}
