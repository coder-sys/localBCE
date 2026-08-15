//! Interactive producer for the authoritative selected-v3 strict public coin.
//!
//! The state machine owns two ephemeral calibration contributors, absorbs the
//! exact semantic/parent message schedule one message at a time, and returns
//! challenges only after each message is fixed.  `finish` immediately replays
//! the serialized bundle against the governed context before exposing any
//! artifact bytes.  The keys are run-scoped, nonactivating calibration keys;
//! private material is consumed and zeroized by the Lamport signer.

use alloc::{vec, vec::Vec};

use sha3::{Digest, Sha3_512};
use zeroize::Zeroize;

use crate::binding_root_v2::BINDING_V2_BYTES;
use crate::chained_public_coin::MAX_PROVER_MESSAGE_BYTES;
use crate::field::Fp16;
use crate::selected_public_coin_v3::{
    SemanticV3GovernedContext, SemanticV3PublicCoinError, semantic_v3_strict_descriptors,
    semantic_v3_strict_policies, semantic_v3_strict_schedule_commitment,
    verify_strict_semantic_v3_public_coin,
};
use crate::strict_pq_public_coin_v2::{
    STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2, STRICT_PQ_LAMPORT_SECRET_BYTES_V2, StrictPqChainV2,
    StrictPqGovernedVerifierKeyV2, StrictPqH4ProfileV2, StrictPqKeyContextV2,
    StrictPqLamportPublicKeyV2, StrictPqLamportSecretKeyV2, StrictPqPublicCoinV2Error,
    StrictPqRootUseRegistryV2, StrictPqRoundDescriptorV2, StrictPqTranscriptBuilderV2,
    build_chain_from_supplied_tail_v2, sign_chain_head_v2,
};

#[derive(Debug)]
pub enum SemanticV3StrictCoinProducerError {
    Input,
    Entropy,
    PublicCoin(StrictPqPublicCoinV2Error),
    Semantic(SemanticV3PublicCoinError),
}

impl From<StrictPqPublicCoinV2Error> for SemanticV3StrictCoinProducerError {
    fn from(value: StrictPqPublicCoinV2Error) -> Self {
        Self::PublicCoin(value)
    }
}

impl From<SemanticV3PublicCoinError> for SemanticV3StrictCoinProducerError {
    fn from(value: SemanticV3PublicCoinError) -> Self {
        Self::Semantic(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticV3StrictRoundOutput {
    pub ordinal: u32,
    pub descriptor: StrictPqRoundDescriptorV2,
    pub field_elements: Vec<Fp16>,
    pub transcript_root: [u8; BINDING_V2_BYTES],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinishedSemanticV3StrictCoin {
    pub governed_key: Vec<u8>,
    pub encoded_bundle: Vec<u8>,
    pub pre_final_transcript_root: [u8; BINDING_V2_BYTES],
    pub final_transcript_root: [u8; BINDING_V2_BYTES],
    pub raw_messages: Vec<Vec<u8>>,
}

struct ContributorMaterial {
    public_key: StrictPqLamportPublicKeyV2,
    secret_key: StrictPqLamportSecretKeyV2,
    tail: [u8; BINDING_V2_BYTES],
}

pub struct SemanticV3StrictCoin {
    context: SemanticV3GovernedContext,
    profile: StrictPqH4ProfileV2,
    governed_key: StrictPqGovernedVerifierKeyV2,
    descriptors: Vec<StrictPqRoundDescriptorV2>,
    policies: Vec<crate::strict_pq_public_coin_v2::StrictPqFp16PolicyV2>,
    builder: StrictPqTranscriptBuilderV2,
    chains: Vec<StrictPqChainV2>,
    raw_messages: Vec<Vec<u8>>,
    pre_final_transcript_root: Option<[u8; BINDING_V2_BYTES]>,
}

fn strict_profile(
    profile: crate::master_commitments::Profile,
) -> Result<StrictPqH4ProfileV2, SemanticV3StrictCoinProducerError> {
    match profile {
        crate::master_commitments::Profile::K128Calibration => Ok(StrictPqH4ProfileV2::K128),
        crate::master_commitments::Profile::K512Calibration => Ok(StrictPqH4ProfileV2::K512),
        crate::master_commitments::Profile::K256DesignPoint => {
            Err(SemanticV3StrictCoinProducerError::Input)
        }
    }
}

fn identifier(
    domain: &[u8],
    context: &SemanticV3GovernedContext,
    session: &[u8; 64],
    lane: u8,
) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(domain);
    hash.update([context.profile as u8, lane]);
    hash.update(session);
    hash.update(context.semantic_program_commitment);
    hash.update(context.parameter_commitment);
    hash.update(context.statement_commitment);
    hash.update(context.composite_parent_schedule_commitment);
    hash.update(context.contributor_set_commitment);
    hash.finalize().into()
}

fn random_secret_material()
-> Result<Vec<[u8; STRICT_PQ_LAMPORT_SECRET_BYTES_V2]>, SemanticV3StrictCoinProducerError> {
    let total = STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2
        .checked_mul(STRICT_PQ_LAMPORT_SECRET_BYTES_V2)
        .ok_or(SemanticV3StrictCoinProducerError::Input)?;
    let mut bytes = vec![0_u8; total];
    if getrandom::fill(&mut bytes).is_err() {
        bytes.zeroize();
        return Err(SemanticV3StrictCoinProducerError::Entropy);
    }
    let result = bytes
        .chunks_exact(STRICT_PQ_LAMPORT_SECRET_BYTES_V2)
        .map(|chunk| {
            chunk
                .try_into()
                .map_err(|_| SemanticV3StrictCoinProducerError::Input)
        })
        .collect::<Result<Vec<_>, _>>();
    bytes.zeroize();
    result
}

fn random_tail() -> Result<[u8; BINDING_V2_BYTES], SemanticV3StrictCoinProducerError> {
    let mut tail = [0_u8; BINDING_V2_BYTES];
    if getrandom::fill(&mut tail).is_err() || tail.iter().all(|byte| *byte == 0) {
        tail.zeroize();
        return Err(SemanticV3StrictCoinProducerError::Entropy);
    }
    Ok(tail)
}

impl SemanticV3StrictCoin {
    pub fn new(
        context: SemanticV3GovernedContext,
        session_id: [u8; 64],
        attempt: u8,
    ) -> Result<Self, SemanticV3StrictCoinProducerError> {
        if session_id.iter().all(|byte| *byte == 0) || attempt >= 4 {
            return Err(SemanticV3StrictCoinProducerError::Input);
        }
        let profile = strict_profile(context.profile)?;
        let descriptors = semantic_v3_strict_descriptors(context.geometry)?;
        let policies = semantic_v3_strict_policies(context.geometry)?;
        let schedule = semantic_v3_strict_schedule_commitment(&context)?;
        let round_count = u32::try_from(descriptors.len())
            .map_err(|_| SemanticV3StrictCoinProducerError::Input)?;
        let candidate = identifier(
            b"BL/PQ512/SELECTED/SEMANTIC-V3/STRICT-CANDIDATE/v1\0",
            &context,
            &session_id,
            0,
        );
        let schema = identifier(
            b"BL/PQ512/SELECTED/SEMANTIC-V3/STRICT-SCHEMA/v1\0",
            &context,
            &session_id,
            0,
        );
        let statement = identifier(
            b"BL/PQ512/SELECTED/SEMANTIC-V3/STRICT-STATEMENT/v1\0",
            &context,
            &session_id,
            0,
        );
        let mut materials = Vec::with_capacity(2);
        for lane in 0..2_u8 {
            let contributor = identifier(
                b"BL/PQ512/SELECTED/SEMANTIC-V3/STRICT-CONTRIBUTOR/v1\0",
                &context,
                &session_id,
                lane,
            );
            let key = identifier(
                b"BL/PQ512/SELECTED/SEMANTIC-V3/STRICT-KEY/v1\0",
                &context,
                &session_id,
                lane,
            );
            let key_context = StrictPqKeyContextV2::new(
                candidate,
                schema,
                1,
                1,
                statement,
                contributor,
                key,
                attempt,
            )?;
            let (secret_key, public_key) =
                StrictPqLamportSecretKeyV2::keygen_from_supplied_secrets(
                    key_context,
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
        let governed_key = StrictPqGovernedVerifierKeyV2::new(
            session_id,
            schedule,
            round_count,
            materials
                .iter()
                .map(|material| material.public_key.clone())
                .collect(),
        )?;
        let mut chains = Vec::with_capacity(2);
        let mut anchors = Vec::with_capacity(2);
        for material in materials {
            let chain = build_chain_from_supplied_tail_v2(
                &material.public_key,
                &session_id,
                &schedule,
                round_count,
                material.tail,
            )?;
            anchors.push(sign_chain_head_v2(
                material.secret_key,
                &governed_key,
                *chain.head(),
            )?);
            chains.push(chain);
        }
        let mut registry = StrictPqRootUseRegistryV2::new();
        let builder = StrictPqTranscriptBuilderV2::start(&governed_key, anchors, &mut registry)?;
        Ok(Self {
            context,
            profile,
            governed_key,
            descriptors,
            policies,
            builder,
            chains,
            raw_messages: Vec::with_capacity(round_count as usize),
            pre_final_transcript_root: None,
        })
    }

    pub fn next_descriptor(&self) -> Option<StrictPqRoundDescriptorV2> {
        self.descriptors.get(self.raw_messages.len()).copied()
    }

    pub fn absorb_message(
        &mut self,
        message: &[u8],
    ) -> Result<SemanticV3StrictRoundOutput, SemanticV3StrictCoinProducerError> {
        let ordinal = self.raw_messages.len();
        // Parent round 901 carries the complete quotient/coefficient frame and
        // is intentionally much larger than the small semantic root messages.
        // Keep this producer aligned with the governed strict-coin transport
        // limit instead of imposing a second, incompatible 256-byte ceiling.
        if message.is_empty() || message.len() > MAX_PROVER_MESSAGE_BYTES {
            return Err(SemanticV3StrictCoinProducerError::Input);
        }
        let descriptor = *self
            .descriptors
            .get(ordinal)
            .ok_or(SemanticV3StrictCoinProducerError::Input)?;
        let policy = *self
            .policies
            .get(ordinal)
            .ok_or(SemanticV3StrictCoinProducerError::Input)?;
        let reveals = self
            .chains
            .iter()
            .map(|chain| {
                chain
                    .reveals()
                    .get(ordinal)
                    .copied()
                    .ok_or(SemanticV3StrictCoinProducerError::Input)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let output =
            self.builder
                .absorb_fp16_round(self.profile, policy, descriptor, message, reveals)?;
        self.raw_messages.push(message.to_vec());
        if ordinal + 2 == self.descriptors.len() {
            self.pre_final_transcript_root = Some(*output.transcript_root());
        }
        Ok(SemanticV3StrictRoundOutput {
            ordinal: u32::try_from(ordinal)
                .map_err(|_| SemanticV3StrictCoinProducerError::Input)?,
            descriptor,
            field_elements: output
                .challenges()
                .samples()
                .iter()
                .map(|sample| sample.element())
                .collect(),
            transcript_root: *output.transcript_root(),
        })
    }

    pub fn finish(self) -> Result<FinishedSemanticV3StrictCoin, SemanticV3StrictCoinProducerError> {
        if self.raw_messages.len() != self.descriptors.len() {
            return Err(SemanticV3StrictCoinProducerError::Input);
        }
        let pre_final_transcript_root = self
            .pre_final_transcript_root
            .ok_or(SemanticV3StrictCoinProducerError::Input)?;
        let bundle = self.builder.finish()?;
        let final_transcript_root = *bundle.final_transcript_root();
        let governed_key = self.governed_key.encode();
        let encoded_bundle = bundle.encode()?;
        let mut registry = StrictPqRootUseRegistryV2::new();
        let replay = verify_strict_semantic_v3_public_coin(
            &encoded_bundle,
            &self.governed_key,
            &self.raw_messages,
            &self.context,
            &mut registry,
        )?;
        if replay.pre_final_transcript_root() != &pre_final_transcript_root
            || replay.final_transcript_root() != &final_transcript_root
        {
            return Err(SemanticV3StrictCoinProducerError::Input);
        }
        Ok(FinishedSemanticV3StrictCoin {
            governed_key,
            encoded_bundle,
            pre_final_transcript_root,
            final_transcript_root,
            raw_messages: self.raw_messages,
        })
    }
}

pub const SEMANTIC_V3_STRICT_COIN_PRODUCER_AVAILABLE: bool = true;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chained_public_coin::MAX_PROVER_MESSAGE_BYTES;
    use crate::master_commitments::Profile;
    use crate::selected_public_coin_v3::SemanticV3Geometry;

    #[test]
    fn interactive_strict_coin_replays_before_exposing_artifacts() {
        let context = SemanticV3GovernedContext {
            profile: Profile::K128Calibration,
            semantic_program_commitment: [1; 64],
            parameter_commitment: [2; 64],
            statement_commitment: [3; 64],
            composite_parent_schedule_commitment: [4; 64],
            contributor_set_commitment: [5; 64],
            geometry: SemanticV3Geometry {
                fold_round_count: 1,
                query_domain_log_size: 4,
                log_blowup: 2,
            },
        };
        let descriptors = semantic_v3_strict_descriptors(context.geometry).unwrap();
        let mut coin = SemanticV3StrictCoin::new(context, [9; 64], 0).unwrap();
        let mut roots = Vec::new();
        for ordinal in 0..descriptors.len() {
            let output = coin.absorb_message(&[ordinal as u8 + 1]).unwrap();
            assert_eq!(output.ordinal as usize, ordinal);
            assert_eq!(output.descriptor, descriptors[ordinal]);
            assert!(!output.field_elements.is_empty());
            roots.push(output.transcript_root);
        }
        let finished = coin.finish().unwrap();
        assert_eq!(finished.pre_final_transcript_root, roots[roots.len() - 2]);
        assert_eq!(finished.final_transcript_root, roots[roots.len() - 1]);
        assert!(!finished.governed_key.is_empty());
        assert!(!finished.encoded_bundle.is_empty());
    }

    #[test]
    fn strict_coin_accepts_a_real_sized_parent_frame_and_rejects_oversize() {
        let context = SemanticV3GovernedContext {
            profile: Profile::K128Calibration,
            semantic_program_commitment: [1; 64],
            parameter_commitment: [2; 64],
            statement_commitment: [3; 64],
            composite_parent_schedule_commitment: [4; 64],
            contributor_set_commitment: [5; 64],
            geometry: SemanticV3Geometry {
                fold_round_count: 1,
                query_domain_log_size: 4,
                log_blowup: 2,
            },
        };
        // Round 901 is roughly 600 KiB for the governed K128 geometry.
        let mut coin = SemanticV3StrictCoin::new(context.clone(), [10; 64], 0).unwrap();
        let output = coin.absorb_message(&vec![0x91; 640 * 1024]).unwrap();
        assert_eq!(output.ordinal, 0);

        let mut oversize = SemanticV3StrictCoin::new(context, [11; 64], 0).unwrap();
        assert!(matches!(
            oversize.absorb_message(&vec![0_u8; MAX_PROVER_MESSAGE_BYTES + 1]),
            Err(SemanticV3StrictCoinProducerError::Input)
        ));
    }
}
