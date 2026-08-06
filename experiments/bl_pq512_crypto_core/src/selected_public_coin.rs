//! Rust-authoritative replay for the selected dual-PQ interactive transcript.
//!
//! The Python coordinator is allowed to construct the transcript, but it is
//! not an authority for a release candidate.  This module parses the complete
//! private transcript artifact, verifies every ML-DSA/SLH-DSA commitment and
//! reveal signature, recomputes every seed/challenge/root, and binds the
//! result to the exact selected proof bundle and outer statement.

use alloc::{vec, vec::Vec};
use core::fmt;

use ml_dsa::{
    EncodedVerifyingKey as MlDsaEncodedVerifyingKey, MlDsa87, Signature as MlDsaSignature,
    VerifyingKey as MlDsaVerifyingKey, signature::Verifier as _,
};
use sha3::{Digest, Sha3_512};
use slh_dsa::{Shake256f, Signature as SlhDsaSignature, VerifyingKey as SlhDsaVerifyingKey};

use crate::field::{DecodeError, Fp16};
use crate::oods::{
    OODS_DEFAULT_MAX_ATTEMPTS, OODS_SAMPLE_DOMAIN_CODE, SampledOodsParameter,
    sample_oods_parameter, stereographic_circle_point,
};
use crate::proof_parameters::selected_proof_geometry;
use crate::sampler::{DEFAULT_MAX_ATTEMPTS, SampledFp16, sample_uniform_fp16};
use crate::selected_challenge::SelectedChallengeBundle;

pub const SELECTED_TRANSCRIPT_MAGIC: &[u8; 8] = b"BLPQTR01";
pub const SELECTED_TRANSCRIPT_VERSION: u16 = 1;
pub const SELECTED_TRANSCRIPT_COMMITMENT_DOMAIN: &[u8] =
    b"BL/PQ512/PRODUCTION-CANDIDATE/TRANSCRIPT/v1\0";
pub const MAX_SELECTED_TRANSCRIPT_BYTES: usize = 16 << 20;
const TRANSCRIPT_MAGIC: &[u8; 8] = b"BLPQPC01";
const TRANSCRIPT_VERSION: u16 = 1;
const INIT_DOMAIN: u16 = 768;
const COMMITMENT_DOMAIN: u16 = 773;
const REVEAL_DOMAIN: u16 = 774;
const SEED_DOMAIN: u16 = 775;
const AUDIT_DOMAIN: u16 = 777;
const SCHEDULE_DOMAIN: u16 = 778;
const QUERY_COUNT: usize = 945;
const PUBLIC_OUTPUT_BYTES: usize = 384;
const SIDECAR_BYTES: usize = 744;
const PROVER_MESSAGE_BYTES: usize = 144;
const MAX_CONTRIBUTORS: usize = 16;
const MAX_PROVER_MESSAGE_BYTES: usize = 64 << 20;
const MAX_SIGNATURE_BYTES: usize = 64 << 10;
const ML_DSA_87_PUBLIC_KEY_BYTES: usize = 2_592;
const ML_DSA_87_SIGNATURE_BYTES: usize = 4_627;
const SLH_DSA_SHAKE_256F_PUBLIC_KEY_BYTES: usize = 64;
const SLH_DSA_SHAKE_256F_SIGNATURE_BYTES: usize = 49_856;
const ML_DSA_SUITE: &[u8] = b"FIPS204-ML-DSA-87";
const SLH_DSA_SUITE: &[u8] = b"FIPS205-SLH-DSA-SHAKE-256F";
const OODS_ROUND: usize = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SignatureSuite {
    MlDsa87,
    SlhDsaShake256f,
}

impl SignatureSuite {
    fn decode(code: u16) -> Result<Self, SelectedTranscriptError> {
        match code {
            1 => Ok(Self::MlDsa87),
            2 => Ok(Self::SlhDsaShake256f),
            _ => Err(SelectedTranscriptError::Suite),
        }
    }

    fn encoded(self) -> &'static [u8] {
        match self {
            Self::MlDsa87 => ML_DSA_SUITE,
            Self::SlhDsaShake256f => SLH_DSA_SUITE,
        }
    }
}

#[derive(Clone, Debug)]
struct Contributor {
    contributor_id: [u8; 64],
    key_id: [u8; 64],
    suite: SignatureSuite,
    public_key: Vec<u8>,
}

#[derive(Clone, Debug)]
struct SignedEnvelope {
    contributor_id: [u8; 64],
    payload: [u8; 64],
    signature: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Round {
    descriptor: [u8; 8],
    prover_message: Vec<u8>,
    commitments: Vec<SignedEnvelope>,
    reveals: Vec<SignedEnvelope>,
    resulting_root: [u8; 64],
}

#[derive(Clone, Debug)]
struct Transcript {
    session_id: [u8; 64],
    public_outputs: Vec<u8>,
    sidecar: Vec<u8>,
    proof_suite_id: [u8; 64],
    schedule_commitment: [u8; 64],
    contributors: Vec<Contributor>,
    rounds: Vec<Round>,
    final_transcript_root: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectedTranscriptError {
    EncodingLength,
    Truncated,
    Trailing,
    Magic,
    Version,
    Length,
    Shape,
    Identity,
    StatementMismatch,
    Suite,
    Contributor,
    PublicKeyLength,
    SignatureLength,
    SignatureEncoding,
    SignatureInvalid,
    SignatureInvalidAt {
        round: usize,
        contributor: usize,
        kind: u8,
    },
    Descriptor,
    ProverMessage,
    Commitment,
    Challenge,
    Root,
    Bundle,
    Field(DecodeError),
}

impl From<DecodeError> for SelectedTranscriptError {
    fn from(value: DecodeError) -> Self {
        Self::Field(value)
    }
}

impl fmt::Display for SelectedTranscriptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "BL-PQ512 selected transcript error: {self:?}")
    }
}

impl core::error::Error for SelectedTranscriptError {}

struct Reader<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(encoded: &'a [u8]) -> Result<Self, SelectedTranscriptError> {
        if encoded.len() < 10 || encoded.len() > MAX_SELECTED_TRANSCRIPT_BYTES {
            return Err(SelectedTranscriptError::EncodingLength);
        }
        Ok(Self { encoded, offset: 0 })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], SelectedTranscriptError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(SelectedTranscriptError::Length)?;
        let value = self
            .encoded
            .get(self.offset..end)
            .ok_or(SelectedTranscriptError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, SelectedTranscriptError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| SelectedTranscriptError::Truncated)?,
        ))
    }

    fn u32(&mut self) -> Result<usize, SelectedTranscriptError> {
        usize::try_from(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| SelectedTranscriptError::Truncated)?,
        ))
        .map_err(|_| SelectedTranscriptError::Length)
    }

    fn digest(&mut self) -> Result<[u8; 64], SelectedTranscriptError> {
        let value: [u8; 64] = self
            .take(64)?
            .try_into()
            .map_err(|_| SelectedTranscriptError::Truncated)?;
        if !value.iter().any(|byte| *byte != 0) {
            return Err(SelectedTranscriptError::Identity);
        }
        Ok(value)
    }

    fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, SelectedTranscriptError> {
        let length = self.u32()?;
        if length == 0 || length > maximum {
            return Err(SelectedTranscriptError::Length);
        }
        Ok(self.take(length)?.to_vec())
    }
}

fn nonzero(value: &[u8]) -> bool {
    value.iter().any(|byte| *byte != 0)
}

fn framed_bytes(domain: u16, parts: &[&[u8]]) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(TRANSCRIPT_MAGIC);
    encoded.extend_from_slice(&TRANSCRIPT_VERSION.to_be_bytes());
    encoded.extend_from_slice(&domain.to_be_bytes());
    for part in parts {
        encoded.extend_from_slice(
            &u32::try_from(part.len())
                .expect("bounded selected transcript part")
                .to_be_bytes(),
        );
        encoded.extend_from_slice(part);
    }
    encoded
}

fn digest(domain: u16, parts: &[&[u8]]) -> [u8; 64] {
    Sha3_512::digest(framed_bytes(domain, parts)).into()
}

fn digest_owned(domain: u16, parts: &[Vec<u8>]) -> [u8; 64] {
    let references = parts.iter().map(Vec::as_slice).collect::<Vec<_>>();
    digest(domain, &references)
}

fn transcript_commitment(encoded: &[u8]) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(SELECTED_TRANSCRIPT_COMMITMENT_DOMAIN);
    hash.update(encoded);
    hash.finalize().into()
}

fn decode_envelope(reader: &mut Reader<'_>) -> Result<SignedEnvelope, SelectedTranscriptError> {
    let contributor_id = reader.digest()?;
    let payload: [u8; 64] = reader
        .take(64)?
        .try_into()
        .map_err(|_| SelectedTranscriptError::Truncated)?;
    let signature = reader.bytes(MAX_SIGNATURE_BYTES)?;
    Ok(SignedEnvelope {
        contributor_id,
        payload,
        signature,
    })
}

fn decode_selected_transcript(encoded: &[u8]) -> Result<Transcript, SelectedTranscriptError> {
    let mut reader = Reader::new(encoded)?;
    if reader.take(8)? != SELECTED_TRANSCRIPT_MAGIC.as_slice() {
        return Err(SelectedTranscriptError::Magic);
    }
    if reader.u16()? != SELECTED_TRANSCRIPT_VERSION {
        return Err(SelectedTranscriptError::Version);
    }
    let session_id = reader.digest()?;
    let public_outputs = reader.take(PUBLIC_OUTPUT_BYTES)?.to_vec();
    let sidecar = reader.take(SIDECAR_BYTES)?.to_vec();
    let proof_suite_id = reader.digest()?;
    let schedule_commitment = reader.digest()?;
    let contributor_count = usize::from(reader.u16()?);
    if !(2..=MAX_CONTRIBUTORS).contains(&contributor_count) {
        return Err(SelectedTranscriptError::Contributor);
    }
    let mut contributors = Vec::with_capacity(contributor_count);
    for _ in 0..contributor_count {
        let contributor_id = reader.digest()?;
        let key_id = reader.digest()?;
        let suite = SignatureSuite::decode(reader.u16()?)?;
        let public_key = reader.bytes(MAX_SIGNATURE_BYTES)?;
        let expected = match suite {
            SignatureSuite::MlDsa87 => ML_DSA_87_PUBLIC_KEY_BYTES,
            SignatureSuite::SlhDsaShake256f => SLH_DSA_SHAKE_256F_PUBLIC_KEY_BYTES,
        };
        if public_key.len() != expected {
            return Err(SelectedTranscriptError::PublicKeyLength);
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
    }) {
        return Err(SelectedTranscriptError::Contributor);
    }
    if !contributors
        .iter()
        .any(|item| item.suite == SignatureSuite::MlDsa87)
        || !contributors
            .iter()
            .any(|item| item.suite == SignatureSuite::SlhDsaShake256f)
    {
        return Err(SelectedTranscriptError::Contributor);
    }
    let round_count = reader.u32()?;
    if round_count == 0 || round_count > 64 {
        return Err(SelectedTranscriptError::Shape);
    }
    let mut rounds = Vec::with_capacity(round_count);
    for _ in 0..round_count {
        let descriptor = reader
            .take(8)?
            .try_into()
            .map_err(|_| SelectedTranscriptError::Truncated)?;
        let prover_message = reader.bytes(MAX_PROVER_MESSAGE_BYTES)?;
        let commitment_count = usize::from(reader.u16()?);
        if commitment_count != contributor_count {
            return Err(SelectedTranscriptError::Shape);
        }
        let commitments = (0..commitment_count)
            .map(|_| decode_envelope(&mut reader))
            .collect::<Result<Vec<_>, _>>()?;
        let reveal_count = usize::from(reader.u16()?);
        if reveal_count != contributor_count {
            return Err(SelectedTranscriptError::Shape);
        }
        let reveals = (0..reveal_count)
            .map(|_| decode_envelope(&mut reader))
            .collect::<Result<Vec<_>, _>>()?;
        let resulting_root = reader.digest()?;
        rounds.push(Round {
            descriptor,
            prover_message,
            commitments,
            reveals,
            resulting_root,
        });
    }
    let final_transcript_root = reader.digest()?;
    if reader.offset != encoded.len() {
        return Err(SelectedTranscriptError::Trailing);
    }
    Ok(Transcript {
        session_id,
        public_outputs,
        sidecar,
        proof_suite_id,
        schedule_commitment,
        contributors,
        rounds,
        final_transcript_root,
    })
}

fn verify_signature(
    suite: SignatureSuite,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), SelectedTranscriptError> {
    match suite {
        SignatureSuite::MlDsa87 => {
            if public_key.len() != ML_DSA_87_PUBLIC_KEY_BYTES
                || signature.len() != ML_DSA_87_SIGNATURE_BYTES
            {
                return Err(SelectedTranscriptError::SignatureLength);
            }
            let encoded_key = MlDsaEncodedVerifyingKey::<MlDsa87>::try_from(public_key)
                .map_err(|_| SelectedTranscriptError::SignatureEncoding)?;
            let key = MlDsaVerifyingKey::<MlDsa87>::decode(&encoded_key);
            let signature = MlDsaSignature::<MlDsa87>::try_from(signature)
                .map_err(|_| SelectedTranscriptError::SignatureEncoding)?;
            key.verify(message, &signature)
                .map_err(|_| SelectedTranscriptError::SignatureInvalid)
        }
        SignatureSuite::SlhDsaShake256f => {
            if public_key.len() != SLH_DSA_SHAKE_256F_PUBLIC_KEY_BYTES
                || signature.len() != SLH_DSA_SHAKE_256F_SIGNATURE_BYTES
            {
                return Err(SelectedTranscriptError::SignatureLength);
            }
            let key = SlhDsaVerifyingKey::<Shake256f>::try_from(public_key)
                .map_err(|_| SelectedTranscriptError::SignatureEncoding)?;
            let signature = SlhDsaSignature::<Shake256f>::try_from(signature)
                .map_err(|_| SelectedTranscriptError::SignatureEncoding)?;
            key.verify(message, &signature)
                .map_err(|_| SelectedTranscriptError::SignatureInvalid)
        }
    }
}

fn expected_descriptor(round: usize, fold_round_count: usize) -> [u8; 8] {
    let (kind, ordinal, output_kind, output_count) = match round {
        0 => (1, 0, 1, 2),
        1 => (2, 0, 1, 1),
        2 => (3, 0, 1, 1),
        3 => (4, 0, 1, 1),
        value if value < 4 + fold_round_count => (5, value - 4, 1, 1),
        _ => (6, 0, 2, 1),
    };
    let mut encoded = [0_u8; 8];
    encoded[..2].copy_from_slice(&(kind as u16).to_be_bytes());
    encoded[2..4].copy_from_slice(&(ordinal as u16).to_be_bytes());
    encoded[4..6].copy_from_slice(&(output_kind as u16).to_be_bytes());
    encoded[6..].copy_from_slice(&(output_count as u16).to_be_bytes());
    encoded
}

fn expected_message_kind(round: usize, fold_round_count: usize) -> (u16, u16) {
    match round {
        0 => (1, 0),
        1 => (2, 0),
        2 => (3, 0),
        3 => (4, 0),
        value if value < 4 + fold_round_count => {
            if value == 4 {
                (5, 0)
            } else {
                (6, (value - 4 - 1) as u16)
            }
        }
        _ => (6, (fold_round_count - 1) as u16),
    }
}

fn validate_prover_message(
    message: &[u8],
    round: usize,
    fold_round_count: usize,
) -> Result<(), SelectedTranscriptError> {
    if message.len() != PROVER_MESSAGE_BYTES
        || message[..8] != *b"BLPQPM01"
        || message[8..10] != 1_u16.to_be_bytes()
        || message[14..16] != [0_u8; 2]
    {
        return Err(SelectedTranscriptError::ProverMessage);
    }
    let (kind, ordinal) = expected_message_kind(round, fold_round_count);
    if u16::from_be_bytes(message[10..12].try_into().expect("message kind width")) != kind
        || u16::from_be_bytes(message[12..14].try_into().expect("message ordinal width")) != ordinal
        || !nonzero(&message[16..80])
        || (round == 3 && !nonzero(&message[80..144]))
        || (round != 3 && nonzero(&message[80..144]))
    {
        return Err(SelectedTranscriptError::ProverMessage);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn signature_message(
    domain: u16,
    session_id: &[u8; 64],
    round: usize,
    descriptor: &[u8; 8],
    prior_root: &[u8; 64],
    prover_message: &[u8],
    contributor: &Contributor,
    payload: &[u8; 64],
) -> Vec<u8> {
    let round_bytes = (round as u32).to_be_bytes();
    let message_digest: [u8; 64] = Sha3_512::digest(prover_message).into();
    framed_bytes(
        domain,
        &[
            session_id,
            &round_bytes,
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
    session_id: &[u8; 64],
    round: usize,
    descriptor: &[u8; 8],
    prior_root: &[u8; 64],
    prover_message: &[u8],
    contributor_id: &[u8; 64],
    reveal: &[u8; 64],
) -> [u8; 64] {
    let round_bytes = (round as u32).to_be_bytes();
    let message_digest: [u8; 64] = Sha3_512::digest(prover_message).into();
    digest(
        COMMITMENT_DOMAIN,
        &[
            session_id,
            &round_bytes,
            descriptor,
            prior_root,
            &message_digest,
            contributor_id,
            reveal,
        ],
    )
}

fn round_seed(
    session_id: &[u8; 64],
    round: usize,
    descriptor: &[u8; 8],
    prior_root: &[u8; 64],
    prover_message: &[u8],
    commitments: &[SignedEnvelope],
    reveals: &[SignedEnvelope],
) -> [u8; 64] {
    let round_bytes = (round as u32).to_be_bytes();
    let mut parts = vec![
        session_id.to_vec(),
        round_bytes.to_vec(),
        descriptor.to_vec(),
        prior_root.to_vec(),
        prover_message.to_vec(),
    ];
    for (commitment, reveal) in commitments.iter().zip(reveals) {
        parts.push(commitment.contributor_id.to_vec());
        parts.push(commitment.payload.to_vec());
        parts.push(reveal.payload.to_vec());
    }
    digest_owned(SEED_DOMAIN, &parts)
}

#[allow(clippy::too_many_arguments)]
fn audit_root(
    session_id: &[u8; 64],
    round: usize,
    descriptor: &[u8; 8],
    prior_root: &[u8; 64],
    prover_message: &[u8],
    seed: &[u8; 64],
    commitments: &[SignedEnvelope],
    reveals: &[SignedEnvelope],
    sampled_oods: Option<SampledOodsParameter>,
    field_elements: &[Fp16],
) -> [u8; 64] {
    let round_bytes = (round as u32).to_be_bytes();
    let mut parts = vec![
        session_id.to_vec(),
        round_bytes.to_vec(),
        descriptor.to_vec(),
        prior_root.to_vec(),
        prover_message.to_vec(),
        seed.to_vec(),
    ];
    for (commitment, reveal) in commitments.iter().zip(reveals) {
        parts.push(commitment.contributor_id.to_vec());
        parts.push(commitment.payload.to_vec());
        parts.push(commitment.signature.clone());
        parts.push(reveal.payload.to_vec());
        parts.push(reveal.signature.clone());
    }
    if let Some(sampled) = sampled_oods {
        parts.push(OODS_SAMPLE_DOMAIN_CODE.to_be_bytes().to_vec());
        parts.push(OODS_DEFAULT_MAX_ATTEMPTS.to_be_bytes().to_vec());
        parts.push(sampled.accepted_attempt.to_be_bytes().to_vec());
        parts.push(sampled.digest.to_vec());
    }
    parts.extend(field_elements.iter().map(|value| value.encode().to_vec()));
    digest_owned(AUDIT_DOMAIN, &parts)
}

fn check_field_challenge(
    round: usize,
    fields: &[SampledFp16],
    bundle: &SelectedChallengeBundle,
) -> bool {
    match round {
        0 => {
            fields.len() == 2
                && fields[0].element == bundle.logup_beta
                && fields[1].element == bundle.logup_gamma
        }
        1 => fields.len() == 1 && fields[0].element == bundle.composition_alpha,
        3 => fields.len() == 1 && fields[0].element == bundle.fri_batch_coefficient,
        value => {
            let ordinal = value - 4;
            fields.len() == 1
                && bundle
                    .fri_fold_coefficients
                    .get(ordinal)
                    .is_some_and(|expected| *expected == fields[0].element)
        }
    }
}

/// Verify the complete selected transcript against the exact outer statement
/// and decoded challenge bundle.  The returned digest is the private artifact
/// identity used by the release-candidate receipt.
pub fn verify_selected_public_coin_transcript(
    encoded: &[u8],
    public_outputs: &[u8],
    sidecar: &[u8],
    bundle: &SelectedChallengeBundle,
    program: &[u8],
) -> Result<[u8; 64], SelectedTranscriptError> {
    let transcript = decode_selected_transcript(encoded)?;
    if transcript.public_outputs != public_outputs
        || transcript.sidecar != sidecar
        || transcript.proof_suite_id != bundle.proof_suite_id
        || transcript.schedule_commitment != bundle.schedule_commitment
        || transcript.session_id != bundle.session_id
        || public_outputs.len() != PUBLIC_OUTPUT_BYTES
        || sidecar.len() != SIDECAR_BYTES
    {
        return Err(SelectedTranscriptError::StatementMismatch);
    }
    let geometry = selected_proof_geometry(program).map_err(|_| SelectedTranscriptError::Bundle)?;
    let expected_rounds = geometry.fold_round_count + 5;
    if transcript.rounds.len() != expected_rounds {
        return Err(SelectedTranscriptError::Shape);
    }
    let contributor_encodings = transcript
        .contributors
        .iter()
        .map(|contributor| {
            framed_bytes(
                SCHEDULE_DOMAIN,
                &[
                    &contributor.contributor_id,
                    &contributor.key_id,
                    contributor.suite.encoded(),
                    &contributor.public_key,
                ],
            )
        })
        .collect::<Vec<_>>();
    let contributor_references = contributor_encodings
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let contributor_digest = digest(SCHEDULE_DOMAIN, &contributor_references);
    let init_root = digest(
        INIT_DOMAIN,
        &[
            &transcript.session_id,
            &transcript.public_outputs,
            &transcript.sidecar,
            &transcript.proof_suite_id,
            &transcript.schedule_commitment,
            &contributor_digest,
        ],
    );
    let mut prior_root = init_root;
    for (round_index, round) in transcript.rounds.iter().enumerate() {
        if round.descriptor != expected_descriptor(round_index, geometry.fold_round_count) {
            return Err(SelectedTranscriptError::Descriptor);
        }
        validate_prover_message(
            &round.prover_message,
            round_index,
            geometry.fold_round_count,
        )?;
        if round.commitments.len() != transcript.contributors.len()
            || round.reveals.len() != transcript.contributors.len()
        {
            return Err(SelectedTranscriptError::Shape);
        }
        for (index, contributor) in transcript.contributors.iter().enumerate() {
            let commitment = &round.commitments[index];
            let reveal = &round.reveals[index];
            if commitment.contributor_id != contributor.contributor_id
                || reveal.contributor_id != contributor.contributor_id
            {
                return Err(SelectedTranscriptError::Contributor);
            }
            let commitment_message = signature_message(
                COMMITMENT_DOMAIN,
                &transcript.session_id,
                round_index,
                &round.descriptor,
                &prior_root,
                &round.prover_message,
                contributor,
                &commitment.payload,
            );
            verify_signature(
                contributor.suite,
                &contributor.public_key,
                &commitment_message,
                &commitment.signature,
            )
            .map_err(|error| match error {
                SelectedTranscriptError::SignatureInvalid => {
                    SelectedTranscriptError::SignatureInvalidAt {
                        round: round_index,
                        contributor: index,
                        kind: 1,
                    }
                }
                other => other,
            })?;
            let reveal_message = signature_message(
                REVEAL_DOMAIN,
                &transcript.session_id,
                round_index,
                &round.descriptor,
                &prior_root,
                &round.prover_message,
                contributor,
                &reveal.payload,
            );
            verify_signature(
                contributor.suite,
                &contributor.public_key,
                &reveal_message,
                &reveal.signature,
            )
            .map_err(|error| match error {
                SelectedTranscriptError::SignatureInvalid => {
                    SelectedTranscriptError::SignatureInvalidAt {
                        round: round_index,
                        contributor: index,
                        kind: 2,
                    }
                }
                other => other,
            })?;
            if commitment.payload
                != expected_commitment(
                    &transcript.session_id,
                    round_index,
                    &round.descriptor,
                    &prior_root,
                    &round.prover_message,
                    &contributor.contributor_id,
                    &reveal.payload,
                )
            {
                return Err(SelectedTranscriptError::Commitment);
            }
        }
        let seed = round_seed(
            &transcript.session_id,
            round_index,
            &round.descriptor,
            &prior_root,
            &round.prover_message,
            &round.commitments,
            &round.reveals,
        );
        let mut sampled_oods = None;
        let mut field_elements = Vec::new();
        if round_index == OODS_ROUND {
            let sampled = sample_oods_parameter(
                &seed,
                &transcript.session_id,
                round_index as u32,
                OODS_DEFAULT_MAX_ATTEMPTS,
            )
            .map_err(|_| SelectedTranscriptError::Challenge)?;
            let point = stereographic_circle_point(sampled.parameter)
                .map_err(|_| SelectedTranscriptError::Challenge)?;
            if point != bundle.oods_point {
                return Err(SelectedTranscriptError::Challenge);
            }
            field_elements.push(sampled.parameter.element());
            sampled_oods = Some(sampled);
        } else if round_index < expected_rounds - 1 {
            let draw_count = if round_index == 0 { 2 } else { 1 };
            let samples = (0..draw_count)
                .map(|draw| {
                    sample_uniform_fp16(
                        &seed,
                        &transcript.session_id,
                        round_index as u32,
                        draw as u32,
                        DEFAULT_MAX_ATTEMPTS,
                    )
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| SelectedTranscriptError::Challenge)?;
            if !check_field_challenge(round_index, &samples, bundle) {
                return Err(SelectedTranscriptError::Challenge);
            }
            field_elements.extend(samples.iter().map(|sample| sample.element));
        } else if seed != bundle.query_seed {
            return Err(SelectedTranscriptError::Challenge);
        }
        let resulting_root = audit_root(
            &transcript.session_id,
            round_index,
            &round.descriptor,
            &prior_root,
            &round.prover_message,
            &seed,
            &round.commitments,
            &round.reveals,
            sampled_oods,
            &field_elements,
        );
        if resulting_root != round.resulting_root {
            return Err(SelectedTranscriptError::Root);
        }
        prior_root = resulting_root;
    }
    if prior_root != transcript.final_transcript_root
        || prior_root != bundle.final_transcript_root
        || bundle.query_positions.len() != QUERY_COUNT
    {
        return Err(SelectedTranscriptError::Root);
    }
    Ok(transcript_commitment(encoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_commitment_is_domain_separated() {
        let encoded = b"synthetic-private-transcript";
        let plain: [u8; 64] = Sha3_512::digest(encoded).into();
        assert_ne!(transcript_commitment(encoded), plain);
    }
}
