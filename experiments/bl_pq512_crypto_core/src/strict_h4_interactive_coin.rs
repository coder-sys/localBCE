//! Interactive current H4-v2 strict public-coin boundary.
//!
//! The CUDA/field producer asks for one challenge only after it has emitted
//! the authenticated prover message for that round.  This adapter owns the
//! two ephemeral Lamport contributors, keeps their unrevealed chain state
//! private, and records the exact messages needed to replay the resulting
//! `BLSPQPC2` bundle.  It is a proof-run component, not custody selection or
//! production activation.

use alloc::{vec, vec::Vec};
use sha3::{Digest, Sha3_512};
use zeroize::Zeroize;

use crate::chained_public_coin::ChainedRoundDescriptor;
use crate::field::Fp16;
use crate::h4_proof_package_v2::{H4ProofPackageV2Error, H4ProofProfileV2, h4_strict_pq_policy_v2};
use crate::strict_pq_public_coin_v2::{
    STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2, STRICT_PQ_LAMPORT_SECRET_BYTES_V2, StrictPqChainV2,
    StrictPqGovernedVerifierKeyV2, StrictPqH4ProfileV2, StrictPqKeyContextV2,
    StrictPqLamportPublicKeyV2, StrictPqLamportSecretKeyV2, StrictPqPublicCoinV2Error,
    StrictPqRootUseRegistryV2, StrictPqRoundDescriptorV2, StrictPqTranscriptBuilderV2,
    build_chain_from_supplied_tail_v2, sign_chain_head_v2,
};

#[derive(Debug)]
pub enum StrictH4InteractiveCoinError {
    Input,
    Entropy,
    PublicCoin(StrictPqPublicCoinV2Error),
    Schedule(H4ProofPackageV2Error),
}

impl From<StrictPqPublicCoinV2Error> for StrictH4InteractiveCoinError {
    fn from(value: StrictPqPublicCoinV2Error) -> Self {
        Self::PublicCoin(value)
    }
}

impl From<H4ProofPackageV2Error> for StrictH4InteractiveCoinError {
    fn from(value: H4ProofPackageV2Error) -> Self {
        Self::Schedule(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinishedStrictH4InteractiveCoin {
    pub governed_key: Vec<u8>,
    pub encoded_bundle: Vec<u8>,
    pub final_transcript_root: [u8; 128],
    pub raw_messages: Vec<Vec<u8>>,
}

struct ContributorMaterial {
    public_key: StrictPqLamportPublicKeyV2,
    secret_key: StrictPqLamportSecretKeyV2,
    tail: [u8; 128],
}

pub struct StrictH4InteractiveCoin {
    profile: H4ProofProfileV2,
    governed_key: StrictPqGovernedVerifierKeyV2,
    builder: StrictPqTranscriptBuilderV2,
    chains: Vec<StrictPqChainV2>,
    raw_messages: Vec<Vec<u8>>,
    next_ordinal: u32,
}

fn id(domain: &[u8], session_id: &[u8; 64], schedule_commitment: &[u8; 64], index: u8) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(domain);
    hash.update(session_id);
    hash.update(schedule_commitment);
    hash.update([index]);
    hash.finalize().into()
}

fn random_secret_material()
-> Result<Vec<[u8; STRICT_PQ_LAMPORT_SECRET_BYTES_V2]>, StrictH4InteractiveCoinError> {
    let total = STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2
        .checked_mul(STRICT_PQ_LAMPORT_SECRET_BYTES_V2)
        .ok_or(StrictH4InteractiveCoinError::Input)?;
    let mut bytes = vec![0_u8; total];
    if getrandom::fill(&mut bytes).is_err() {
        bytes.zeroize();
        return Err(StrictH4InteractiveCoinError::Entropy);
    }
    let result = bytes
        .chunks_exact(STRICT_PQ_LAMPORT_SECRET_BYTES_V2)
        .map(|chunk| {
            chunk
                .try_into()
                .map_err(|_| StrictH4InteractiveCoinError::Input)
        })
        .collect::<Result<Vec<[u8; STRICT_PQ_LAMPORT_SECRET_BYTES_V2]>, _>>();
    bytes.zeroize();
    result
}

fn random_tail() -> Result<[u8; 128], StrictH4InteractiveCoinError> {
    let mut tail = [0_u8; 128];
    if getrandom::fill(&mut tail).is_err() || tail.iter().all(|byte| *byte == 0) {
        tail.zeroize();
        return Err(StrictH4InteractiveCoinError::Entropy);
    }
    Ok(tail)
}

fn strict_profile(profile: H4ProofProfileV2) -> StrictPqH4ProfileV2 {
    match profile {
        H4ProofProfileV2::K128 => StrictPqH4ProfileV2::K128,
        H4ProofProfileV2::K512 => StrictPqH4ProfileV2::K512,
    }
}

impl StrictH4InteractiveCoin {
    pub fn new(
        profile: H4ProofProfileV2,
        session_id: [u8; 64],
        attempt: u16,
        schedule_commitment: [u8; 64],
        round_count: u32,
    ) -> Result<Self, StrictH4InteractiveCoinError> {
        if round_count != profile.transcript_rounds() {
            return Err(StrictH4InteractiveCoinError::Input);
        }
        Self::new_for_schedule(
            profile,
            session_id,
            attempt,
            schedule_commitment,
            round_count,
        )
    }

    pub fn new_for_schedule(
        profile: H4ProofProfileV2,
        session_id: [u8; 64],
        attempt: u16,
        schedule_commitment: [u8; 64],
        round_count: u32,
    ) -> Result<Self, StrictH4InteractiveCoinError> {
        if !session_id.iter().any(|byte| *byte != 0)
            || !schedule_commitment.iter().any(|byte| *byte != 0)
            || attempt >= 4
            || round_count == 0
        {
            return Err(StrictH4InteractiveCoinError::Input);
        }
        let candidate_protocol_id = id(
            b"BL/PQ512/WAVE2/STRICT-H4/CANDIDATE/v2\0",
            &session_id,
            &schedule_commitment,
            0,
        );
        let schema_id = id(
            b"BL/PQ512/WAVE2/STRICT-H4/SCHEMA/v2\0",
            &session_id,
            &schedule_commitment,
            0,
        );
        let statement_id = id(
            b"BL/PQ512/WAVE2/STRICT-H4/STATEMENT/v2\0",
            &session_id,
            &schedule_commitment,
            0,
        );
        let mut materials = Vec::with_capacity(2);
        for index in 0..2_u8 {
            let contributor_id = id(
                b"BL/PQ512/WAVE2/STRICT-H4/CONTRIBUTOR/v2\0",
                &session_id,
                &schedule_commitment,
                index,
            );
            let key_id = id(
                b"BL/PQ512/WAVE2/STRICT-H4/KEY/v2\0",
                &session_id,
                &schedule_commitment,
                index,
            );
            let context = StrictPqKeyContextV2::new(
                candidate_protocol_id,
                schema_id,
                1,
                1,
                statement_id,
                contributor_id,
                key_id,
                u8::try_from(attempt).map_err(|_| StrictH4InteractiveCoinError::Input)?,
            )?;
            let (secret_key, public_key) =
                StrictPqLamportSecretKeyV2::keygen_from_supplied_secrets(
                    context,
                    random_secret_material()?,
                )?;
            materials.push(ContributorMaterial {
                public_key,
                secret_key,
                tail: random_tail()?,
            });
        }
        materials.sort_by(|left, right| {
            left.public_key
                .context()
                .contributor_id()
                .cmp(right.public_key.context().contributor_id())
        });
        if materials.windows(2).any(|pair| {
            pair[0].public_key.context().contributor_id()
                >= pair[1].public_key.context().contributor_id()
        }) {
            return Err(StrictH4InteractiveCoinError::Input);
        }
        let governed_key = StrictPqGovernedVerifierKeyV2::new(
            session_id,
            schedule_commitment,
            round_count,
            materials
                .iter()
                .map(|material| material.public_key.clone())
                .collect(),
        )?;
        let mut chains = Vec::with_capacity(materials.len());
        let mut anchors = Vec::with_capacity(materials.len());
        for material in materials {
            let chain = build_chain_from_supplied_tail_v2(
                &material.public_key,
                &session_id,
                &schedule_commitment,
                round_count,
                material.tail,
            )?;
            let anchor = sign_chain_head_v2(material.secret_key, &governed_key, *chain.head())?;
            chains.push(chain);
            anchors.push(anchor);
        }
        let mut registry = StrictPqRootUseRegistryV2::new();
        let builder = StrictPqTranscriptBuilderV2::start(&governed_key, anchors, &mut registry)?;
        Ok(Self {
            profile,
            governed_key,
            builder,
            chains,
            raw_messages: Vec::with_capacity(round_count as usize),
            next_ordinal: 0,
        })
    }

    pub fn challenge(
        &mut self,
        descriptor: ChainedRoundDescriptor,
        message: &[u8],
    ) -> Result<Vec<Fp16>, StrictH4InteractiveCoinError> {
        let expected = StrictPqRoundDescriptorV2::new(
            descriptor.kind,
            descriptor.ordinal,
            descriptor.output_count,
        )?;
        if descriptor.ordinal != self.next_ordinal || message.is_empty() {
            return Err(StrictH4InteractiveCoinError::Input);
        }
        let policy = h4_strict_pq_policy_v2(expected)?;
        self.challenge_with_policy(descriptor, policy, message)
    }

    pub fn challenge_with_policy(
        &mut self,
        descriptor: ChainedRoundDescriptor,
        policy: crate::strict_pq_public_coin_v2::StrictPqFp16PolicyV2,
        message: &[u8],
    ) -> Result<Vec<Fp16>, StrictH4InteractiveCoinError> {
        let expected = StrictPqRoundDescriptorV2::new(
            descriptor.kind,
            descriptor.ordinal,
            descriptor.output_count,
        )?;
        if descriptor.ordinal != self.next_ordinal || message.is_empty() {
            return Err(StrictH4InteractiveCoinError::Input);
        }
        let reveals = self
            .chains
            .iter()
            .map(|chain| {
                chain
                    .reveals()
                    .get(self.next_ordinal as usize)
                    .copied()
                    .ok_or(StrictH4InteractiveCoinError::Input)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let output = self.builder.absorb_fp16_round(
            strict_profile(self.profile),
            policy,
            expected,
            message,
            reveals,
        )?;
        self.raw_messages.push(message.to_vec());
        self.next_ordinal = self
            .next_ordinal
            .checked_add(1)
            .ok_or(StrictH4InteractiveCoinError::Input)?;
        Ok(output
            .challenges()
            .samples()
            .iter()
            .map(|sample| sample.element())
            .collect())
    }

    pub fn finish(self) -> Result<FinishedStrictH4InteractiveCoin, StrictH4InteractiveCoinError> {
        if self.next_ordinal != self.governed_key.round_count() {
            return Err(StrictH4InteractiveCoinError::Input);
        }
        let bundle = self.builder.finish()?;
        let final_transcript_root = *bundle.final_transcript_root();
        let governed_key = self.governed_key.encode();
        let encoded_bundle = bundle.encode()?;
        Ok(FinishedStrictH4InteractiveCoin {
            governed_key,
            encoded_bundle,
            final_transcript_root,
            raw_messages: self.raw_messages,
        })
    }
}
