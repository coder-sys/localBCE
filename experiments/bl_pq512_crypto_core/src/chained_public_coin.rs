//! Amortized authenticated public coin for long interactive proofs.
//!
//! Each contributor authenticates one reverse SHA3-512 chain head with an
//! approved category-5 PQ signature.  A round reveal is accepted only after
//! the prover message is fixed and only when it is the unique preimage of the
//! contributor's current chain state.  Missing, duplicated, out-of-order, or
//! malformed evidence fails closed.

use core::fmt;

use alloc::{vec, vec::Vec};
use ml_dsa::{
    EncodedVerifyingKey as MlDsaEncodedVerifyingKey, MlDsa87, Signature as MlDsaSignature,
    VerifyingKey as MlDsaVerifyingKey, signature::Verifier as _,
};
use sha3::{Digest, Sha3_512};
use slh_dsa::{Shake256f, Signature as SlhDsaSignature, VerifyingKey as SlhDsaVerifyingKey};

use crate::field::Fp16;
use crate::sampler::{DEFAULT_MAX_ATTEMPTS, SampleError, sample_uniform_fp16};

pub const CHAIN_MAGIC: &[u8; 8] = b"BLPQHCH1";
pub const CHAIN_VERSION: u16 = 1;
pub const CHAIN_BUNDLE_MAGIC: &[u8; 8] = b"BLPQHCB1";
pub const CHAIN_BUNDLE_VERSION: u16 = 1;
pub const MAX_CHAIN_BUNDLE_BYTES: usize = 16 << 20;
pub const ML_DSA_87_PUBLIC_KEY_BYTES: usize = 2_592;
pub const ML_DSA_87_SIGNATURE_BYTES: usize = 4_627;
pub const SLH_DSA_SHAKE_256F_PUBLIC_KEY_BYTES: usize = 64;
pub const SLH_DSA_SHAKE_256F_SIGNATURE_BYTES: usize = 49_856;
pub const MAX_CHAIN_ROUNDS: u32 = 65_535;
pub const MAX_PROVER_MESSAGE_BYTES: usize = 1 << 20;

const HEAD_AUTH_DOMAIN: u16 = 1;
const CHAIN_STEP_DOMAIN: u16 = 2;
const SESSION_INIT_DOMAIN: u16 = 3;
const ROUND_SEED_DOMAIN: u16 = 4;
const ROUND_AUDIT_DOMAIN: u16 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum PqSignatureSuite {
    MlDsa87 = 1,
    SlhDsaShake256f = 2,
}

impl PqSignatureSuite {
    fn encode(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainedContributor {
    pub contributor_id: [u8; 64],
    pub key_id: [u8; 64],
    pub suite: PqSignatureSuite,
    pub public_key: Vec<u8>,
    pub chain_head: [u8; 64],
    pub head_signature: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainedRoundDescriptor {
    pub kind: u16,
    pub ordinal: u32,
    pub output_count: u16,
}

impl ChainedRoundDescriptor {
    pub const fn encode(self) -> [u8; 8] {
        let kind = self.kind.to_be_bytes();
        let ordinal = self.ordinal.to_be_bytes();
        let count = self.output_count.to_be_bytes();
        [
            kind[0], kind[1], ordinal[0], ordinal[1], ordinal[2], ordinal[3], count[0], count[1],
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainedChallenge {
    pub seed: [u8; 64],
    pub field_elements: Vec<Fp16>,
    pub transcript_root: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainedRoundEvidence {
    pub descriptor: ChainedRoundDescriptor,
    pub prover_message: Vec<u8>,
    pub reveals: Vec<[u8; 64]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainedPublicCoinBundle {
    pub session_id: [u8; 64],
    pub attempt: u16,
    pub schedule_commitment: [u8; 64],
    pub contributors: Vec<ChainedContributor>,
    pub rounds: Vec<ChainedRoundEvidence>,
    pub claimed_final_transcript_root: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChainedPublicCoinError {
    EncodingLength,
    Truncated,
    TrailingBytes,
    Magic,
    Version,
    NonCanonicalSuite,
    LengthOverflow,
    ZeroIdentifier,
    AttemptOutOfRange,
    RoundCount,
    ContributorCount,
    ContributorOrder,
    SuiteDiversity,
    PublicKeyLength,
    SignatureLength,
    SignatureEncoding,
    SignatureInvalid(PqSignatureSuite),
    Complete,
    Descriptor,
    ProverMessageLength,
    RevealCount,
    ChainRevealInvalid { contributor: usize, round: u32 },
    Sample(SampleError),
    FinalTranscriptRoot,
}

impl From<SampleError> for ChainedPublicCoinError {
    fn from(value: SampleError) -> Self {
        Self::Sample(value)
    }
}

impl fmt::Display for ChainedPublicCoinError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "BL-PQ512 chained public coin error: {self:?}")
    }
}

impl core::error::Error for ChainedPublicCoinError {}

struct Reader<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(encoded: &'a [u8]) -> Result<Self, ChainedPublicCoinError> {
        if encoded.len() < 10 || encoded.len() > MAX_CHAIN_BUNDLE_BYTES {
            return Err(ChainedPublicCoinError::EncodingLength);
        }
        Ok(Self { encoded, offset: 0 })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ChainedPublicCoinError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ChainedPublicCoinError::LengthOverflow)?;
        let value = self
            .encoded
            .get(self.offset..end)
            .ok_or(ChainedPublicCoinError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, ChainedPublicCoinError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| ChainedPublicCoinError::Truncated)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, ChainedPublicCoinError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| ChainedPublicCoinError::Truncated)?,
        ))
    }

    fn digest(&mut self) -> Result<[u8; 64], ChainedPublicCoinError> {
        self.take(64)?
            .try_into()
            .map_err(|_| ChainedPublicCoinError::Truncated)
    }
}

pub fn decode_chained_public_coin_bundle(
    encoded: &[u8],
) -> Result<ChainedPublicCoinBundle, ChainedPublicCoinError> {
    let mut reader = Reader::new(encoded)?;
    if reader.take(8)? != CHAIN_BUNDLE_MAGIC {
        return Err(ChainedPublicCoinError::Magic);
    }
    if reader.u16()? != CHAIN_BUNDLE_VERSION {
        return Err(ChainedPublicCoinError::Version);
    }
    let session_id = reader.digest()?;
    let attempt = reader.u16()?;
    let schedule_commitment = reader.digest()?;
    let round_count = reader.u32()?;
    if round_count == 0 || round_count > MAX_CHAIN_ROUNDS {
        return Err(ChainedPublicCoinError::RoundCount);
    }
    let contributor_count = usize::from(reader.u16()?);
    if !(2..=16).contains(&contributor_count) {
        return Err(ChainedPublicCoinError::ContributorCount);
    }
    let mut contributors = Vec::with_capacity(contributor_count);
    for _ in 0..contributor_count {
        let contributor_id = reader.digest()?;
        let key_id = reader.digest()?;
        let suite = match reader.u16()? {
            1 => PqSignatureSuite::MlDsa87,
            2 => PqSignatureSuite::SlhDsaShake256f,
            _ => return Err(ChainedPublicCoinError::NonCanonicalSuite),
        };
        let public_key_length =
            usize::try_from(reader.u32()?).map_err(|_| ChainedPublicCoinError::LengthOverflow)?;
        let signature_length =
            usize::try_from(reader.u32()?).map_err(|_| ChainedPublicCoinError::LengthOverflow)?;
        let chain_head = reader.digest()?;
        let public_key = reader.take(public_key_length)?.to_vec();
        let head_signature = reader.take(signature_length)?.to_vec();
        contributors.push(ChainedContributor {
            contributor_id,
            key_id,
            suite,
            public_key,
            chain_head,
            head_signature,
        });
    }
    let mut rounds = Vec::with_capacity(
        usize::try_from(round_count).map_err(|_| ChainedPublicCoinError::LengthOverflow)?,
    );
    for _ in 0..round_count {
        let descriptor = ChainedRoundDescriptor {
            kind: reader.u16()?,
            ordinal: reader.u32()?,
            output_count: reader.u16()?,
        };
        let message_length =
            usize::try_from(reader.u32()?).map_err(|_| ChainedPublicCoinError::LengthOverflow)?;
        if message_length == 0 || message_length > MAX_PROVER_MESSAGE_BYTES {
            return Err(ChainedPublicCoinError::ProverMessageLength);
        }
        let prover_message = reader.take(message_length)?.to_vec();
        let reveals = (0..contributor_count)
            .map(|_| reader.digest())
            .collect::<Result<Vec<_>, _>>()?;
        rounds.push(ChainedRoundEvidence {
            descriptor,
            prover_message,
            reveals,
        });
    }
    let claimed_final_transcript_root = reader.digest()?;
    if reader.offset != encoded.len() {
        return Err(ChainedPublicCoinError::TrailingBytes);
    }
    Ok(ChainedPublicCoinBundle {
        session_id,
        attempt,
        schedule_commitment,
        contributors,
        rounds,
        claimed_final_transcript_root,
    })
}

pub fn encode_chained_public_coin_bundle(
    bundle: &ChainedPublicCoinBundle,
) -> Result<Vec<u8>, ChainedPublicCoinError> {
    let round_count =
        u32::try_from(bundle.rounds.len()).map_err(|_| ChainedPublicCoinError::RoundCount)?;
    if round_count == 0
        || round_count > MAX_CHAIN_ROUNDS
        || !(2..=16).contains(&bundle.contributors.len())
    {
        return Err(ChainedPublicCoinError::RoundCount);
    }
    let mut encoded = Vec::new();
    encoded.extend_from_slice(CHAIN_BUNDLE_MAGIC);
    encoded.extend_from_slice(&CHAIN_BUNDLE_VERSION.to_be_bytes());
    encoded.extend_from_slice(&bundle.session_id);
    encoded.extend_from_slice(&bundle.attempt.to_be_bytes());
    encoded.extend_from_slice(&bundle.schedule_commitment);
    encoded.extend_from_slice(&round_count.to_be_bytes());
    encoded.extend_from_slice(
        &u16::try_from(bundle.contributors.len())
            .map_err(|_| ChainedPublicCoinError::ContributorCount)?
            .to_be_bytes(),
    );
    for contributor in &bundle.contributors {
        encoded.extend_from_slice(&contributor.contributor_id);
        encoded.extend_from_slice(&contributor.key_id);
        encoded.extend_from_slice(&contributor.suite.encode());
        encoded.extend_from_slice(
            &u32::try_from(contributor.public_key.len())
                .map_err(|_| ChainedPublicCoinError::LengthOverflow)?
                .to_be_bytes(),
        );
        encoded.extend_from_slice(
            &u32::try_from(contributor.head_signature.len())
                .map_err(|_| ChainedPublicCoinError::LengthOverflow)?
                .to_be_bytes(),
        );
        encoded.extend_from_slice(&contributor.chain_head);
        encoded.extend_from_slice(&contributor.public_key);
        encoded.extend_from_slice(&contributor.head_signature);
    }
    for round in &bundle.rounds {
        if round.reveals.len() != bundle.contributors.len()
            || round.prover_message.is_empty()
            || round.prover_message.len() > MAX_PROVER_MESSAGE_BYTES
        {
            return Err(ChainedPublicCoinError::RevealCount);
        }
        encoded.extend_from_slice(&round.descriptor.encode());
        encoded.extend_from_slice(
            &u32::try_from(round.prover_message.len())
                .map_err(|_| ChainedPublicCoinError::LengthOverflow)?
                .to_be_bytes(),
        );
        encoded.extend_from_slice(&round.prover_message);
        for reveal in &round.reveals {
            encoded.extend_from_slice(reveal);
        }
    }
    encoded.extend_from_slice(&bundle.claimed_final_transcript_root);
    if encoded.len() > MAX_CHAIN_BUNDLE_BYTES {
        return Err(ChainedPublicCoinError::EncodingLength);
    }
    Ok(encoded)
}

pub fn verify_chained_public_coin_bundle(
    bundle: &ChainedPublicCoinBundle,
) -> Result<Vec<ChainedChallenge>, ChainedPublicCoinError> {
    let round_count =
        u32::try_from(bundle.rounds.len()).map_err(|_| ChainedPublicCoinError::RoundCount)?;
    let mut session = ChainedPublicCoin::new(
        bundle.session_id,
        bundle.attempt,
        bundle.schedule_commitment,
        round_count,
        bundle.contributors.clone(),
    )?;
    let mut challenges = Vec::with_capacity(bundle.rounds.len());
    for evidence in &bundle.rounds {
        challenges.push(session.accept_round(
            evidence.descriptor,
            &evidence.prover_message,
            &evidence.reveals,
        )?);
    }
    if !session.complete() || session.transcript_root() != bundle.claimed_final_transcript_root {
        return Err(ChainedPublicCoinError::FinalTranscriptRoot);
    }
    Ok(challenges)
}

fn framed_hash(domain: u16, parts: &[&[u8]]) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(CHAIN_MAGIC);
    hash.update(CHAIN_VERSION.to_be_bytes());
    hash.update(domain.to_be_bytes());
    for part in parts {
        hash.update(
            u32::try_from(part.len())
                .expect("bounded public-coin part")
                .to_be_bytes(),
        );
        hash.update(part);
    }
    hash.finalize().into()
}

pub fn chain_step(
    session_id: &[u8; 64],
    attempt: u16,
    schedule_commitment: &[u8; 64],
    contributor_id: &[u8; 64],
    round: u32,
    next: &[u8; 64],
) -> [u8; 64] {
    framed_hash(
        CHAIN_STEP_DOMAIN,
        &[
            session_id,
            &attempt.to_be_bytes(),
            schedule_commitment,
            contributor_id,
            &round.to_be_bytes(),
            next,
        ],
    )
}

pub fn chain_head_signature_message(
    session_id: &[u8; 64],
    attempt: u16,
    schedule_commitment: &[u8; 64],
    round_count: u32,
    contributor: &ChainedContributor,
) -> [u8; 64] {
    framed_hash(
        HEAD_AUTH_DOMAIN,
        &[
            session_id,
            &attempt.to_be_bytes(),
            schedule_commitment,
            &round_count.to_be_bytes(),
            &contributor.contributor_id,
            &contributor.key_id,
            &contributor.suite.encode(),
            &contributor.chain_head,
        ],
    )
}

pub fn verify_chain_head_signature(
    session_id: &[u8; 64],
    attempt: u16,
    schedule_commitment: &[u8; 64],
    round_count: u32,
    contributor: &ChainedContributor,
) -> Result<(), ChainedPublicCoinError> {
    let message = chain_head_signature_message(
        session_id,
        attempt,
        schedule_commitment,
        round_count,
        contributor,
    );
    match contributor.suite {
        PqSignatureSuite::MlDsa87 => {
            if contributor.public_key.len() != ML_DSA_87_PUBLIC_KEY_BYTES {
                return Err(ChainedPublicCoinError::PublicKeyLength);
            }
            if contributor.head_signature.len() != ML_DSA_87_SIGNATURE_BYTES {
                return Err(ChainedPublicCoinError::SignatureLength);
            }
            let encoded_key =
                MlDsaEncodedVerifyingKey::<MlDsa87>::try_from(contributor.public_key.as_slice())
                    .map_err(|_| ChainedPublicCoinError::SignatureEncoding)?;
            let key = MlDsaVerifyingKey::<MlDsa87>::decode(&encoded_key);
            let signature =
                MlDsaSignature::<MlDsa87>::try_from(contributor.head_signature.as_slice())
                    .map_err(|_| ChainedPublicCoinError::SignatureEncoding)?;
            key.verify(&message, &signature)
                .map_err(|_| ChainedPublicCoinError::SignatureInvalid(contributor.suite))
        }
        PqSignatureSuite::SlhDsaShake256f => {
            if contributor.public_key.len() != SLH_DSA_SHAKE_256F_PUBLIC_KEY_BYTES {
                return Err(ChainedPublicCoinError::PublicKeyLength);
            }
            if contributor.head_signature.len() != SLH_DSA_SHAKE_256F_SIGNATURE_BYTES {
                return Err(ChainedPublicCoinError::SignatureLength);
            }
            let key = SlhDsaVerifyingKey::<Shake256f>::try_from(contributor.public_key.as_slice())
                .map_err(|_| ChainedPublicCoinError::SignatureEncoding)?;
            let signature =
                SlhDsaSignature::<Shake256f>::try_from(contributor.head_signature.as_slice())
                    .map_err(|_| ChainedPublicCoinError::SignatureEncoding)?;
            key.verify(&message, &signature)
                .map_err(|_| ChainedPublicCoinError::SignatureInvalid(contributor.suite))
        }
    }
}

pub struct ChainedPublicCoin {
    session_id: [u8; 64],
    attempt: u16,
    schedule_commitment: [u8; 64],
    round_count: u32,
    round: u32,
    contributors: Vec<ChainedContributor>,
    chain_states: Vec<[u8; 64]>,
    transcript_root: [u8; 64],
}

impl ChainedPublicCoin {
    pub fn new(
        session_id: [u8; 64],
        attempt: u16,
        schedule_commitment: [u8; 64],
        round_count: u32,
        contributors: Vec<ChainedContributor>,
    ) -> Result<Self, ChainedPublicCoinError> {
        if !session_id.iter().any(|byte| *byte != 0)
            || !schedule_commitment.iter().any(|byte| *byte != 0)
        {
            return Err(ChainedPublicCoinError::ZeroIdentifier);
        }
        if attempt >= 16 {
            return Err(ChainedPublicCoinError::AttemptOutOfRange);
        }
        if round_count == 0 || round_count > MAX_CHAIN_ROUNDS {
            return Err(ChainedPublicCoinError::RoundCount);
        }
        if contributors.len() < 2 {
            return Err(ChainedPublicCoinError::ContributorCount);
        }
        if contributors.windows(2).any(|pair| {
            pair[0].contributor_id >= pair[1].contributor_id || pair[0].key_id == pair[1].key_id
        }) {
            return Err(ChainedPublicCoinError::ContributorOrder);
        }
        let has_ml = contributors
            .iter()
            .any(|item| item.suite == PqSignatureSuite::MlDsa87);
        let has_slh = contributors
            .iter()
            .any(|item| item.suite == PqSignatureSuite::SlhDsaShake256f);
        if !has_ml || !has_slh {
            return Err(ChainedPublicCoinError::SuiteDiversity);
        }
        for contributor in &contributors {
            if !contributor.contributor_id.iter().any(|byte| *byte != 0)
                || !contributor.key_id.iter().any(|byte| *byte != 0)
                || !contributor.chain_head.iter().any(|byte| *byte != 0)
            {
                return Err(ChainedPublicCoinError::ZeroIdentifier);
            }
            verify_chain_head_signature(
                &session_id,
                attempt,
                &schedule_commitment,
                round_count,
                contributor,
            )?;
        }
        let attempt_encoded = attempt.to_be_bytes();
        let round_count_encoded = round_count.to_be_bytes();
        let suite_encodings = contributors
            .iter()
            .map(|contributor| contributor.suite.encode())
            .collect::<Vec<_>>();
        let mut init_parts: Vec<&[u8]> = vec![
            &session_id,
            &attempt_encoded,
            &schedule_commitment,
            &round_count_encoded,
        ];
        for (contributor, suite_encoded) in contributors.iter().zip(&suite_encodings) {
            init_parts.extend([
                contributor.contributor_id.as_slice(),
                contributor.key_id.as_slice(),
                suite_encoded.as_slice(),
                contributor.public_key.as_slice(),
                contributor.chain_head.as_slice(),
                contributor.head_signature.as_slice(),
            ]);
        }
        let transcript_root = framed_hash(SESSION_INIT_DOMAIN, &init_parts);
        let chain_states = contributors.iter().map(|item| item.chain_head).collect();
        Ok(Self {
            session_id,
            attempt,
            schedule_commitment,
            round_count,
            round: 0,
            contributors,
            chain_states,
            transcript_root,
        })
    }

    pub const fn round(&self) -> u32 {
        self.round
    }

    pub const fn transcript_root(&self) -> [u8; 64] {
        self.transcript_root
    }

    pub const fn complete(&self) -> bool {
        self.round == self.round_count
    }

    pub fn accept_round(
        &mut self,
        descriptor: ChainedRoundDescriptor,
        prover_message: &[u8],
        reveals: &[[u8; 64]],
    ) -> Result<ChainedChallenge, ChainedPublicCoinError> {
        if self.complete() {
            return Err(ChainedPublicCoinError::Complete);
        }
        if descriptor.output_count == 0 {
            return Err(ChainedPublicCoinError::Descriptor);
        }
        if prover_message.is_empty() || prover_message.len() > MAX_PROVER_MESSAGE_BYTES {
            return Err(ChainedPublicCoinError::ProverMessageLength);
        }
        if reveals.len() != self.contributors.len() {
            return Err(ChainedPublicCoinError::RevealCount);
        }
        for (index, ((contributor, current), reveal)) in self
            .contributors
            .iter()
            .zip(&self.chain_states)
            .zip(reveals)
            .enumerate()
        {
            if chain_step(
                &self.session_id,
                self.attempt,
                &self.schedule_commitment,
                &contributor.contributor_id,
                self.round,
                reveal,
            ) != *current
            {
                return Err(ChainedPublicCoinError::ChainRevealInvalid {
                    contributor: index,
                    round: self.round,
                });
            }
        }
        let descriptor_encoded = descriptor.encode();
        let attempt_encoded = self.attempt.to_be_bytes();
        let round_encoded = self.round.to_be_bytes();
        let mut seed_parts: Vec<&[u8]> = vec![
            &self.session_id,
            &attempt_encoded,
            &self.schedule_commitment,
            &round_encoded,
            &descriptor_encoded,
            &self.transcript_root,
            prover_message,
        ];
        for (contributor, reveal) in self.contributors.iter().zip(reveals) {
            seed_parts.extend([contributor.contributor_id.as_slice(), reveal.as_slice()]);
        }
        let seed = framed_hash(ROUND_SEED_DOMAIN, &seed_parts);
        let mut field_elements = Vec::with_capacity(usize::from(descriptor.output_count));
        for draw in 0..u32::from(descriptor.output_count) {
            field_elements.push(
                sample_uniform_fp16(
                    &seed,
                    &self.session_id,
                    self.round,
                    draw,
                    DEFAULT_MAX_ATTEMPTS,
                )?
                .element,
            );
        }
        let transcript_root = framed_hash(
            ROUND_AUDIT_DOMAIN,
            &[
                &self.transcript_root,
                &descriptor_encoded,
                prover_message,
                &seed,
                &field_elements
                    .iter()
                    .flat_map(|value| value.encode())
                    .collect::<Vec<_>>(),
            ],
        );
        self.chain_states.copy_from_slice(reveals);
        self.transcript_root = transcript_root;
        self.round += 1;
        Ok(ChainedChallenge {
            seed,
            field_elements,
            transcript_root,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::{
        Keypair as _, Seed, SignatureEncoding as _, Signer as _, SigningKey as MlDsaSigningKey,
    };
    use slh_dsa::SigningKey as SlhDsaSigningKey;

    fn signed_contributors(
        session_id: &[u8; 64],
        schedule: &[u8; 64],
        round_count: u32,
    ) -> (Vec<ChainedContributor>, Vec<Vec<[u8; 64]>>) {
        let ids = [
            Sha3_512::digest(b"chain-test-ml-contributor").into(),
            Sha3_512::digest(b"chain-test-slh-contributor").into(),
        ];
        let key_ids = [
            Sha3_512::digest(b"chain-test-ml-key").into(),
            Sha3_512::digest(b"chain-test-slh-key").into(),
        ];
        let mut chains = Vec::new();
        for (index, contributor_id) in ids.iter().enumerate() {
            let mut values = vec![[0_u8; 64]; round_count as usize + 1];
            values[round_count as usize] =
                Sha3_512::digest([b"chain-test-tail".as_slice(), &[index as u8]].concat()).into();
            for round in (0..round_count).rev() {
                values[round as usize] = chain_step(
                    session_id,
                    0,
                    schedule,
                    contributor_id,
                    round,
                    &values[round as usize + 1],
                );
            }
            chains.push(values);
        }

        let ml_signing = MlDsaSigningKey::<MlDsa87>::from_seed(&Seed::from([7_u8; 32]));
        let slh_signing = SlhDsaSigningKey::<Shake256f>::slh_keygen_internal(
            &[11_u8; 32],
            &[13_u8; 32],
            &[17_u8; 32],
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
        let ml_message =
            chain_head_signature_message(session_id, 0, schedule, round_count, &contributors[0]);
        contributors[0].head_signature = ml_signing.sign(&ml_message).to_bytes().to_vec();
        let slh_message =
            chain_head_signature_message(session_id, 0, schedule, round_count, &contributors[1]);
        contributors[1].head_signature = slh_signing
            .try_sign(&slh_message)
            .expect("valid fixed SLH-DSA message")
            .to_bytes()
            .to_vec();

        let mut paired = contributors.into_iter().zip(chains).collect::<Vec<_>>();
        paired.sort_by_key(|item| item.0.contributor_id);
        paired.into_iter().unzip()
    }

    #[test]
    fn native_dual_pq_heads_and_reverse_chains_verify_and_tampering_fails() {
        let session_id: [u8; 64] = Sha3_512::digest(b"chain-test-session").into();
        let schedule: [u8; 64] = Sha3_512::digest(b"chain-test-schedule").into();
        let (contributors, chains) = signed_contributors(&session_id, &schedule, 3);
        let mut coin =
            ChainedPublicCoin::new(session_id, 0, schedule, 3, contributors.clone()).unwrap();
        let mut evidence = Vec::new();
        for round in 0..3 {
            let reveals = chains
                .iter()
                .map(|chain| chain[round + 1])
                .collect::<Vec<_>>();
            let descriptor = ChainedRoundDescriptor {
                kind: 100,
                ordinal: round as u32,
                output_count: 1,
            };
            let prover_message = [round as u8 + 1];
            let challenge = coin
                .accept_round(descriptor, &prover_message, &reveals)
                .unwrap();
            assert_eq!(challenge.field_elements.len(), 1);
            evidence.push(ChainedRoundEvidence {
                descriptor,
                prover_message: prover_message.to_vec(),
                reveals,
            });
        }
        assert!(coin.complete());
        let bundle = ChainedPublicCoinBundle {
            session_id,
            attempt: 0,
            schedule_commitment: schedule,
            contributors: contributors.clone(),
            rounds: evidence,
            claimed_final_transcript_root: coin.transcript_root(),
        };
        let encoded = encode_chained_public_coin_bundle(&bundle).unwrap();
        let decoded = decode_chained_public_coin_bundle(&encoded).unwrap();
        assert_eq!(decoded, bundle);
        assert_eq!(
            verify_chained_public_coin_bundle(&decoded).unwrap().len(),
            3
        );
        let mut forged_bundle = decoded;
        forged_bundle.claimed_final_transcript_root[0] ^= 1;
        assert_eq!(
            verify_chained_public_coin_bundle(&forged_bundle),
            Err(ChainedPublicCoinError::FinalTranscriptRoot)
        );

        let mut forged = contributors;
        forged[0].head_signature[0] ^= 1;
        assert!(matches!(
            ChainedPublicCoin::new(session_id, 0, schedule, 3, forged),
            Err(ChainedPublicCoinError::SignatureInvalid(_))
                | Err(ChainedPublicCoinError::SignatureEncoding)
        ));
    }
}
