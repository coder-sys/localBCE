//! Fixed-shape version-3 composite-envelope grammar.
//!
//! This module parses and commits the outer grammar only.  Aggregate
//! verification has no success type until the semantic, portable H4, and
//! composite-transcript verifier endpoints exist.

use alloc::{vec, vec::Vec};
use std::convert::Infallible;
use std::io::{ErrorKind, Read, Seek, SeekFrom};

use sha3::{Digest, Sha3_512};

use crate::v3_authority_run::{
    V3AuthorityReceipts, V3AuthorityRunError, V3AuthorityRunResult, complete_v3_authority_run,
};

pub const V3_MAGIC: &[u8; 8] = b"BLPQENV3";
pub const V3_VERSION: u16 = 3;
pub const V3_FLAGS: u16 = 0;
pub const V3_HEADER_BYTES: usize = 1_652;
pub const V3_PUBLIC_FIELD_COUNT: usize = 12;
pub const V3_PUBLIC_FIELD_BYTES: usize = 32;
pub const V3_SIDECAR_BYTES: usize = 744;
pub const V3_DESCRIPTOR_COUNT: usize = 4;
pub const V3_DESCRIPTOR_BYTES: usize = 76;
/// Streaming parser ceiling. K512 carries four fixed 192 MiB H4 shard bodies
/// plus one shared transcript and the semantic/typed components, so the old
/// 512 MiB ceiling could not represent the governed full profile.
pub const V3_ABSOLUTE_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;

pub const V3_LAYOUT_MAGIC: &[u8; 8] = b"BLV3LY01";
pub const V3_LAYOUT_VERSION: u16 = 2;
pub const V3_LAYOUT_FLAGS: u16 = 0;
pub const V3_LAYOUT_BYTES: usize = 820;
pub const V3_LAYOUT_COMMITMENT_DOMAIN: &[u8] = b"BL/PQ512/V3/LAYOUT/v2\0";
pub const V3_ENVELOPE_COMMITMENT_DOMAIN: &[u8] = b"BL/PQ512/V3/COMPOSITE-ENVELOPE/v1\0";

pub const K128_PROFILE_CODE: u8 = 1;
pub const K512_PROFILE_CODE: u8 = 3;
pub const K128_PROFILE_LABEL: &[u8] = b"K128_CALIBRATION";
pub const K512_PROFILE_LABEL: &[u8] = b"K512_CALIBRATION";

pub fn governed_profile_label(profile_code: u8) -> Result<&'static [u8], V3EnvelopeError> {
    match profile_code {
        K128_PROFILE_CODE => Ok(K128_PROFILE_LABEL),
        K512_PROFILE_CODE => Ok(K512_PROFILE_LABEL),
        _ => Err(V3EnvelopeError::Profile),
    }
}

pub const V3_TRANSCRIPT_MAGIC: &[u8; 8] = b"BLV3TR01";
pub const V3_TRANSCRIPT_GRAMMAR: u16 = 1;
pub const V3_TRANSCRIPT_FLAGS: u16 = 0;
pub const V3_TRANSCRIPT_PREFIX_BYTES: u64 = 20;

pub const V3_STATUS: &str = "V3_GRAMMAR_PARSED_AGGREGATE_UNQUALIFIED";
pub const V3_ACCEPTING_STATUS: &str = "V3_NATIVE_AGGREGATE_ACCEPTED_NONACTIVATING";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum V3ComponentKind {
    Semantic = 1,
    H4 = 2,
    TypedState = 3,
    CompositeTranscript = 4,
}

impl V3ComponentKind {
    pub const ORDER: [Self; V3_DESCRIPTOR_COUNT] = [
        Self::Semantic,
        Self::H4,
        Self::TypedState,
        Self::CompositeTranscript,
    ];

    fn decode(value: u16) -> Result<Self, V3EnvelopeError> {
        match value {
            1 => Ok(Self::Semantic),
            2 => Ok(Self::H4),
            3 => Ok(Self::TypedState),
            4 => Ok(Self::CompositeTranscript),
            _ => Err(V3EnvelopeError::ComponentOrder),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V3ComponentLayout {
    pub kind: V3ComponentKind,
    pub grammar: u16,
    pub exact_length: u64,
    pub maximum_length: u64,
    pub expected_program_commitment: [u8; 64],
    pub expected_schedule_commitment: [u8; 64],
}

impl V3ComponentLayout {
    fn validate(&self) -> Result<(), V3EnvelopeError> {
        if self.grammar == 0
            || self.exact_length == 0
            || self.exact_length > self.maximum_length
            || self.maximum_length > V3_ABSOLUTE_MAX_BYTES
            || !nonzero(&self.expected_program_commitment)
            || !nonzero(&self.expected_schedule_commitment)
        {
            return Err(V3EnvelopeError::Layout);
        }
        if self.kind == V3ComponentKind::CompositeTranscript
            && (self.grammar != V3_TRANSCRIPT_GRAMMAR
                || self.exact_length < V3_TRANSCRIPT_PREFIX_BYTES + 1)
        {
            return Err(V3EnvelopeError::Layout);
        }
        Ok(())
    }

    fn append_canonical(&self, encoded: &mut Vec<u8>) {
        encoded.extend_from_slice(&(self.kind as u16).to_be_bytes());
        encoded.extend_from_slice(&self.grammar.to_be_bytes());
        encoded.extend_from_slice(&self.exact_length.to_be_bytes());
        encoded.extend_from_slice(&self.maximum_length.to_be_bytes());
        encoded.extend_from_slice(&self.expected_program_commitment);
        encoded.extend_from_slice(&self.expected_schedule_commitment);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V3ProfileLayout {
    pub profile_id: [u8; 64],
    pub profile_code: u8,
    pub candidate_descriptor_identity: [u8; 64],
    pub total_length: u64,
    pub maximum_total_length: u64,
    pub components: [V3ComponentLayout; V3_DESCRIPTOR_COUNT],
    pub layout_commitment: [u8; 64],
}

impl V3ProfileLayout {
    pub fn new(
        profile_id: [u8; 64],
        profile_code: u8,
        candidate_descriptor_identity: [u8; 64],
        maximum_total_length: u64,
        components: [V3ComponentLayout; V3_DESCRIPTOR_COUNT],
    ) -> Result<Self, V3EnvelopeError> {
        let component_total = components.iter().try_fold(0_u64, |total, component| {
            total
                .checked_add(component.exact_length)
                .ok_or(V3EnvelopeError::Length)
        })?;
        let total_length = u64::try_from(V3_HEADER_BYTES)
            .map_err(|_| V3EnvelopeError::Length)?
            .checked_add(component_total)
            .ok_or(V3EnvelopeError::Length)?;
        let mut layout = Self {
            profile_id,
            profile_code,
            candidate_descriptor_identity,
            total_length,
            maximum_total_length,
            components,
            layout_commitment: [0_u8; 64],
        };
        layout.layout_commitment = derive_layout_commitment(&layout);
        layout.validate()?;
        Ok(layout)
    }

    pub fn validate(&self) -> Result<(), V3EnvelopeError> {
        governed_profile_label(self.profile_code)?;
        if !nonzero(&self.profile_id)
            || !nonzero(&self.candidate_descriptor_identity)
            || !nonzero(&self.layout_commitment)
            || self.maximum_total_length > V3_ABSOLUTE_MAX_BYTES
            || self.total_length > self.maximum_total_length
        {
            return Err(V3EnvelopeError::Layout);
        }
        let mut expected_total =
            u64::try_from(V3_HEADER_BYTES).map_err(|_| V3EnvelopeError::Length)?;
        for (expected_kind, component) in V3ComponentKind::ORDER.iter().zip(&self.components) {
            if component.kind != *expected_kind {
                return Err(V3EnvelopeError::Layout);
            }
            component.validate()?;
            if component.maximum_length > self.maximum_total_length {
                return Err(V3EnvelopeError::Layout);
            }
            expected_total = expected_total
                .checked_add(component.exact_length)
                .ok_or(V3EnvelopeError::Length)?;
        }
        if self.total_length != expected_total
            || self.layout_commitment != derive_layout_commitment(self)
        {
            return Err(V3EnvelopeError::Layout);
        }
        Ok(())
    }

    fn commitment_preimage(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(V3_LAYOUT_BYTES - 64);
        encoded.extend_from_slice(V3_LAYOUT_MAGIC);
        encoded.extend_from_slice(&V3_LAYOUT_VERSION.to_be_bytes());
        encoded.extend_from_slice(&V3_LAYOUT_FLAGS.to_be_bytes());
        encoded.extend_from_slice(&self.profile_id);
        encoded.push(self.profile_code);
        encoded.extend_from_slice(&[0_u8; 7]);
        encoded.extend_from_slice(&self.candidate_descriptor_identity);
        encoded.extend_from_slice(&self.total_length.to_be_bytes());
        encoded.extend_from_slice(&self.maximum_total_length.to_be_bytes());
        for component in &self.components {
            component.append_canonical(&mut encoded);
        }
        encoded
    }

    pub fn encode(&self) -> Result<Vec<u8>, V3EnvelopeError> {
        self.validate()?;
        let mut encoded = self.commitment_preimage();
        encoded.extend_from_slice(&self.layout_commitment);
        if encoded.len() != V3_LAYOUT_BYTES {
            return Err(V3EnvelopeError::Layout);
        }
        Ok(encoded)
    }

    pub fn decode_trusted(encoded: &[u8]) -> Result<Self, V3EnvelopeError> {
        if encoded.len() != V3_LAYOUT_BYTES {
            return Err(V3EnvelopeError::Length);
        }
        let mut reader = SliceReader::new(encoded);
        if reader.take(8)? != V3_LAYOUT_MAGIC {
            return Err(V3EnvelopeError::Magic);
        }
        if reader.u16()? != V3_LAYOUT_VERSION {
            return Err(V3EnvelopeError::Version);
        }
        if reader.u16()? != V3_LAYOUT_FLAGS {
            return Err(V3EnvelopeError::Flags);
        }
        let profile_id = reader.digest()?;
        let profile_code = reader.take(1)?[0];
        if reader.take(7)?.iter().any(|byte| *byte != 0) {
            return Err(V3EnvelopeError::Flags);
        }
        let candidate_descriptor_identity = reader.digest()?;
        let total_length = reader.u64()?;
        let maximum_total_length = reader.u64()?;
        let mut components = Vec::with_capacity(V3_DESCRIPTOR_COUNT);
        for _ in 0..V3_DESCRIPTOR_COUNT {
            components.push(V3ComponentLayout {
                kind: V3ComponentKind::decode(reader.u16()?)?,
                grammar: reader.u16()?,
                exact_length: reader.u64()?,
                maximum_length: reader.u64()?,
                expected_program_commitment: reader.digest()?,
                expected_schedule_commitment: reader.digest()?,
            });
        }
        let layout_commitment = reader.digest()?;
        if reader.offset != encoded.len() {
            return Err(V3EnvelopeError::Trailing);
        }
        let layout = Self {
            profile_id,
            profile_code,
            candidate_descriptor_identity,
            total_length,
            maximum_total_length,
            components: components.try_into().map_err(|_| V3EnvelopeError::Layout)?,
            layout_commitment,
        };
        layout.validate()?;
        Ok(layout)
    }
}

pub fn derive_layout_commitment(layout: &V3ProfileLayout) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(V3_LAYOUT_COMMITMENT_DOMAIN);
    hash.update(layout.commitment_preimage());
    hash.finalize().into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V3ComponentDescriptor {
    pub kind: V3ComponentKind,
    pub grammar: u16,
    pub length: u64,
    pub sha3_512: [u8; 64],
}

impl V3ComponentDescriptor {
    fn append(&self, encoded: &mut Vec<u8>) {
        encoded.extend_from_slice(&(self.kind as u16).to_be_bytes());
        encoded.extend_from_slice(&self.grammar.to_be_bytes());
        encoded.extend_from_slice(&self.length.to_be_bytes());
        encoded.extend_from_slice(&self.sha3_512);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V3ParsedEnvelope {
    pub profile_id: [u8; 64],
    pub profile_code: u8,
    pub candidate_descriptor_identity: [u8; 64],
    pub layout_commitment: [u8; 64],
    pub public_fields: [[u8; V3_PUBLIC_FIELD_BYTES]; V3_PUBLIC_FIELD_COUNT],
    pub sidecar: [u8; V3_SIDECAR_BYTES],
    pub descriptors: [V3ComponentDescriptor; V3_DESCRIPTOR_COUNT],
    /// Absolute byte offsets of the fixed component bodies in the envelope.
    /// These offsets are derived from the authenticated header and are only
    /// routing metadata; component authority still comes from each native
    /// component verifier.
    pub component_offsets: [u64; V3_DESCRIPTOR_COUNT],
    pub envelope_commitment: [u8; 64],
    pub status: &'static str,
    pub production_usable: bool,
    pub activation_allowed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum V3EnvelopeError {
    Io(ErrorKind),
    Length,
    Magic,
    Version,
    Flags,
    HeaderLength,
    TotalLength,
    Profile,
    CandidateDescriptor,
    Layout,
    Sidecar,
    ComponentOrder,
    ComponentGrammar,
    ComponentLength,
    ComponentDigest,
    Transcript,
    TranscriptPadding,
    Trailing,
    AggregateVerificationUnavailable,
    NativeAuthority,
}

impl From<std::io::Error> for V3EnvelopeError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.kind())
    }
}

struct SliceReader<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> SliceReader<'a> {
    fn new(encoded: &'a [u8]) -> Self {
        Self { encoded, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], V3EnvelopeError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(V3EnvelopeError::Length)?;
        let value = self
            .encoded
            .get(self.offset..end)
            .ok_or(V3EnvelopeError::Length)?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, V3EnvelopeError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| V3EnvelopeError::Length)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, V3EnvelopeError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| V3EnvelopeError::Length)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, V3EnvelopeError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| V3EnvelopeError::Length)?,
        ))
    }

    fn digest(&mut self) -> Result<[u8; 64], V3EnvelopeError> {
        self.take(64)?
            .try_into()
            .map_err(|_| V3EnvelopeError::Length)
    }
}

fn nonzero(value: &[u8]) -> bool {
    value.iter().any(|byte| *byte != 0)
}

fn validate_sidecar(sidecar: &[u8], profile_id: &[u8; 64]) -> Result<(), V3EnvelopeError> {
    if sidecar.len() != V3_SIDECAR_BYTES
        || sidecar.get(..8) != Some(b"BLPQSC01")
        || sidecar.get(8..10) != Some(&1_u16.to_be_bytes())
        || sidecar.get(10..12) != Some(&0_u16.to_be_bytes())
        || sidecar.get(12..16) != Some(&(V3_SIDECAR_BYTES as u32).to_be_bytes())
        || sidecar.get(16..80) != Some(profile_id)
        || sidecar[80..144].iter().any(|byte| *byte != 0)
    {
        return Err(V3EnvelopeError::Sidecar);
    }
    for start in [16, 144, 208, 272, 360, 424, 488, 552, 616, 680] {
        if !nonzero(&sidecar[start..start + 64]) {
            return Err(V3EnvelopeError::Sidecar);
        }
    }
    let epoch = u64::from_be_bytes(
        sidecar[336..344]
            .try_into()
            .map_err(|_| V3EnvelopeError::Sidecar)?,
    );
    let sequence_before = u64::from_be_bytes(
        sidecar[344..352]
            .try_into()
            .map_err(|_| V3EnvelopeError::Sidecar)?,
    );
    let sequence_after = u64::from_be_bytes(
        sidecar[352..360]
            .try_into()
            .map_err(|_| V3EnvelopeError::Sidecar)?,
    );
    if epoch == 0
        || sequence_before == u64::MAX
        || sequence_after != sequence_before + 1
        || sidecar[360..424] == sidecar[424..488]
        || sidecar[552..616] == sidecar[616..680]
    {
        return Err(V3EnvelopeError::Sidecar);
    }
    Ok(())
}

fn parse_header(
    encoded: &[u8],
    layout: &V3ProfileLayout,
) -> Result<
    (
        [[u8; V3_PUBLIC_FIELD_BYTES]; V3_PUBLIC_FIELD_COUNT],
        [u8; V3_SIDECAR_BYTES],
        [V3ComponentDescriptor; V3_DESCRIPTOR_COUNT],
    ),
    V3EnvelopeError,
> {
    if encoded.len() != V3_HEADER_BYTES {
        return Err(V3EnvelopeError::HeaderLength);
    }
    let mut reader = SliceReader::new(encoded);
    if reader.take(8)? != V3_MAGIC {
        return Err(V3EnvelopeError::Magic);
    }
    if reader.u16()? != V3_VERSION {
        return Err(V3EnvelopeError::Version);
    }
    if reader.u16()? != V3_FLAGS {
        return Err(V3EnvelopeError::Flags);
    }
    if reader.u32()? != V3_HEADER_BYTES as u32 {
        return Err(V3EnvelopeError::HeaderLength);
    }
    if reader.u64()? != layout.total_length {
        return Err(V3EnvelopeError::TotalLength);
    }
    if reader.digest()? != layout.profile_id {
        return Err(V3EnvelopeError::Profile);
    }
    if reader.digest()? != layout.candidate_descriptor_identity {
        return Err(V3EnvelopeError::CandidateDescriptor);
    }
    if reader.digest()? != layout.layout_commitment {
        return Err(V3EnvelopeError::Layout);
    }
    let mut public_fields = [[0_u8; V3_PUBLIC_FIELD_BYTES]; V3_PUBLIC_FIELD_COUNT];
    for field in &mut public_fields {
        field.copy_from_slice(reader.take(V3_PUBLIC_FIELD_BYTES)?);
    }
    let mut sidecar = [0_u8; V3_SIDECAR_BYTES];
    sidecar.copy_from_slice(reader.take(V3_SIDECAR_BYTES)?);
    validate_sidecar(&sidecar, &layout.profile_id)?;
    if usize::from(reader.u16()?) != V3_DESCRIPTOR_COUNT || reader.u16()? != 0 {
        return Err(V3EnvelopeError::ComponentOrder);
    }
    let mut descriptors = Vec::with_capacity(V3_DESCRIPTOR_COUNT);
    for expected in &layout.components {
        let kind = V3ComponentKind::decode(reader.u16()?)?;
        let grammar = reader.u16()?;
        let length = reader.u64()?;
        let sha3_512 = reader.digest()?;
        if kind != expected.kind {
            return Err(V3EnvelopeError::ComponentOrder);
        }
        if grammar != expected.grammar {
            return Err(V3EnvelopeError::ComponentGrammar);
        }
        if length != expected.exact_length {
            return Err(V3EnvelopeError::ComponentLength);
        }
        if !nonzero(&sha3_512) {
            return Err(V3EnvelopeError::ComponentDigest);
        }
        descriptors.push(V3ComponentDescriptor {
            kind,
            grammar,
            length,
            sha3_512,
        });
    }
    if reader.offset != V3_HEADER_BYTES {
        return Err(V3EnvelopeError::Trailing);
    }
    Ok((
        public_fields,
        sidecar,
        descriptors
            .try_into()
            .map_err(|_| V3EnvelopeError::ComponentOrder)?,
    ))
}

fn read_and_hash<R: Read>(
    reader: &mut R,
    mut length: u64,
    component_hash: &mut Sha3_512,
    envelope_hash: &mut Sha3_512,
    reject_nonzero: bool,
) -> Result<(), V3EnvelopeError> {
    let mut buffer = [0_u8; 64 * 1024];
    while length != 0 {
        let take = usize::try_from(length.min(buffer.len() as u64))
            .map_err(|_| V3EnvelopeError::Length)?;
        reader.read_exact(&mut buffer[..take])?;
        if reject_nonzero && buffer[..take].iter().any(|byte| *byte != 0) {
            return Err(V3EnvelopeError::TranscriptPadding);
        }
        component_hash.update(&buffer[..take]);
        envelope_hash.update(&buffer[..take]);
        length -= take as u64;
    }
    Ok(())
}

fn read_component<R: Read>(
    reader: &mut R,
    descriptor: &V3ComponentDescriptor,
    envelope_hash: &mut Sha3_512,
) -> Result<[u8; 64], V3EnvelopeError> {
    let mut component_hash = Sha3_512::new();
    if descriptor.kind == V3ComponentKind::CompositeTranscript {
        let mut prefix = [0_u8; V3_TRANSCRIPT_PREFIX_BYTES as usize];
        reader.read_exact(&mut prefix)?;
        component_hash.update(prefix);
        envelope_hash.update(prefix);
        if prefix[..8] != V3_TRANSCRIPT_MAGIC[..]
            || u16::from_be_bytes(
                prefix[8..10]
                    .try_into()
                    .map_err(|_| V3EnvelopeError::Transcript)?,
            ) != descriptor.grammar
            || u16::from_be_bytes(
                prefix[10..12]
                    .try_into()
                    .map_err(|_| V3EnvelopeError::Transcript)?,
            ) != V3_TRANSCRIPT_FLAGS
        {
            return Err(V3EnvelopeError::Transcript);
        }
        let payload_length = u64::from_be_bytes(
            prefix[12..20]
                .try_into()
                .map_err(|_| V3EnvelopeError::Transcript)?,
        );
        let maximum_payload = descriptor
            .length
            .checked_sub(V3_TRANSCRIPT_PREFIX_BYTES)
            .ok_or(V3EnvelopeError::Transcript)?;
        if payload_length == 0 || payload_length > maximum_payload {
            return Err(V3EnvelopeError::Transcript);
        }
        read_and_hash(
            reader,
            payload_length,
            &mut component_hash,
            envelope_hash,
            false,
        )?;
        read_and_hash(
            reader,
            maximum_payload - payload_length,
            &mut component_hash,
            envelope_hash,
            true,
        )?;
    } else {
        read_and_hash(
            reader,
            descriptor.length,
            &mut component_hash,
            envelope_hash,
            false,
        )?;
    }
    Ok(component_hash.finalize().into())
}

pub fn parse_v3_envelope<R: Read + Seek>(
    reader: &mut R,
    layout: &V3ProfileLayout,
) -> Result<V3ParsedEnvelope, V3EnvelopeError> {
    layout.validate()?;
    let observed_length = reader.seek(SeekFrom::End(0))?;
    if observed_length != layout.total_length {
        return Err(V3EnvelopeError::TotalLength);
    }
    reader.seek(SeekFrom::Start(0))?;
    let mut header = vec![0_u8; V3_HEADER_BYTES];
    reader.read_exact(&mut header)?;
    let (public_fields, sidecar, descriptors) = parse_header(&header, layout)?;

    let mut envelope_hash = Sha3_512::new();
    envelope_hash.update(V3_ENVELOPE_COMMITMENT_DOMAIN);
    envelope_hash.update(layout.total_length.to_be_bytes());
    envelope_hash.update(&header);
    let mut component_offsets = [0_u64; V3_DESCRIPTOR_COUNT];
    for (index, descriptor) in descriptors.iter().enumerate() {
        component_offsets[index] = reader.stream_position()?;
        if read_component(reader, descriptor, &mut envelope_hash)? != descriptor.sha3_512 {
            return Err(V3EnvelopeError::ComponentDigest);
        }
    }
    let mut trailing = [0_u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(V3EnvelopeError::Trailing);
    }
    Ok(V3ParsedEnvelope {
        profile_id: layout.profile_id,
        profile_code: layout.profile_code,
        candidate_descriptor_identity: layout.candidate_descriptor_identity,
        layout_commitment: layout.layout_commitment,
        public_fields,
        sidecar,
        descriptors,
        component_offsets,
        envelope_commitment: envelope_hash.finalize().into(),
        status: V3_STATUS,
        production_usable: false,
        activation_allowed: false,
    })
}

pub fn verify_v3_composite<R: Read + Seek>(
    reader: &mut R,
    layout: &V3ProfileLayout,
) -> Result<Infallible, V3EnvelopeError> {
    let _parsed = parse_v3_envelope(reader, layout)?;
    Err(V3EnvelopeError::AggregateVerificationUnavailable)
}

/// Complete the accepting outer boundary after every component receipt has
/// been minted by a native verifier over this exact parsed envelope.
///
/// Serialized roots, receipt evidence, and lifecycle flags cannot enter the
/// composition here. The file-backed runner is responsible for obtaining the
/// opaque receipts by replaying the envelope components first; this function
/// is the final native-only acceptance seam and remains nonactivating.
pub fn verify_v3_composite_with_native_receipts<R: Read + Seek>(
    reader: &mut R,
    layout: &V3ProfileLayout,
    receipts: V3AuthorityReceipts,
) -> Result<(V3ParsedEnvelope, V3AuthorityRunResult), V3EnvelopeError> {
    let parsed = parse_v3_envelope(reader, layout)?;
    let result = complete_v3_authority_run(receipts).map_err(|error| match error {
        V3AuthorityRunError::Coordinator(_) | V3AuthorityRunError::Receipt(_) => {
            V3EnvelopeError::NativeAuthority
        }
    })?;
    let expected_profile = match parsed.profile_code {
        K128_PROFILE_CODE => crate::master_commitments::Profile::K128Calibration,
        K512_PROFILE_CODE => crate::master_commitments::Profile::K512Calibration,
        _ => return Err(V3EnvelopeError::Profile),
    };
    if result.receipt.profile != expected_profile
        || result.proof_suite_id.is_some()
        || result.production_usable
        || result.activation_allowed
    {
        return Err(V3EnvelopeError::NativeAuthority);
    }
    Ok((parsed, result))
}

pub fn build_composite_transcript_slot(
    payload: &[u8],
    fixed_length: u64,
) -> Result<Vec<u8>, V3EnvelopeError> {
    let payload_length = u64::try_from(payload.len()).map_err(|_| V3EnvelopeError::Length)?;
    if payload.is_empty()
        || fixed_length
            < V3_TRANSCRIPT_PREFIX_BYTES
                .checked_add(payload_length)
                .ok_or(V3EnvelopeError::Length)?
    {
        return Err(V3EnvelopeError::Transcript);
    }
    let capacity = usize::try_from(fixed_length).map_err(|_| V3EnvelopeError::Length)?;
    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(V3_TRANSCRIPT_MAGIC);
    encoded.extend_from_slice(&V3_TRANSCRIPT_GRAMMAR.to_be_bytes());
    encoded.extend_from_slice(&V3_TRANSCRIPT_FLAGS.to_be_bytes());
    encoded.extend_from_slice(&payload_length.to_be_bytes());
    encoded.extend_from_slice(payload);
    encoded.resize(capacity, 0);
    Ok(encoded)
}

pub fn encode_v3_envelope(
    layout: &V3ProfileLayout,
    public_fields: &[[u8; V3_PUBLIC_FIELD_BYTES]; V3_PUBLIC_FIELD_COUNT],
    sidecar: &[u8; V3_SIDECAR_BYTES],
    components: &[Vec<u8>; V3_DESCRIPTOR_COUNT],
) -> Result<Vec<u8>, V3EnvelopeError> {
    layout.validate()?;
    validate_sidecar(sidecar, &layout.profile_id)?;
    let mut descriptors = Vec::with_capacity(V3_DESCRIPTOR_COUNT);
    for (expected, component) in layout.components.iter().zip(components) {
        if u64::try_from(component.len()).map_err(|_| V3EnvelopeError::Length)?
            != expected.exact_length
        {
            return Err(V3EnvelopeError::ComponentLength);
        }
        if expected.kind == V3ComponentKind::CompositeTranscript {
            let mut cursor = std::io::Cursor::new(component);
            let mut sink = Sha3_512::new();
            let descriptor = V3ComponentDescriptor {
                kind: expected.kind,
                grammar: expected.grammar,
                length: expected.exact_length,
                sha3_512: Sha3_512::digest(component).into(),
            };
            let _ = read_component(&mut cursor, &descriptor, &mut sink)?;
        }
        descriptors.push(V3ComponentDescriptor {
            kind: expected.kind,
            grammar: expected.grammar,
            length: expected.exact_length,
            sha3_512: Sha3_512::digest(component).into(),
        });
    }
    let mut encoded = Vec::with_capacity(
        usize::try_from(layout.total_length).map_err(|_| V3EnvelopeError::Length)?,
    );
    encoded.extend_from_slice(V3_MAGIC);
    encoded.extend_from_slice(&V3_VERSION.to_be_bytes());
    encoded.extend_from_slice(&V3_FLAGS.to_be_bytes());
    encoded.extend_from_slice(&(V3_HEADER_BYTES as u32).to_be_bytes());
    encoded.extend_from_slice(&layout.total_length.to_be_bytes());
    encoded.extend_from_slice(&layout.profile_id);
    encoded.extend_from_slice(&layout.candidate_descriptor_identity);
    encoded.extend_from_slice(&layout.layout_commitment);
    for field in public_fields {
        encoded.extend_from_slice(field);
    }
    encoded.extend_from_slice(sidecar);
    encoded.extend_from_slice(&(V3_DESCRIPTOR_COUNT as u16).to_be_bytes());
    encoded.extend_from_slice(&0_u16.to_be_bytes());
    for descriptor in &descriptors {
        descriptor.append(&mut encoded);
    }
    if encoded.len() != V3_HEADER_BYTES {
        return Err(V3EnvelopeError::HeaderLength);
    }
    for component in components {
        encoded.extend_from_slice(component);
    }
    if u64::try_from(encoded.len()).map_err(|_| V3EnvelopeError::Length)? != layout.total_length {
        return Err(V3EnvelopeError::TotalLength);
    }
    Ok(encoded)
}
