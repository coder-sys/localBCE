//! TEST-ONLY deterministic authenticated public coin for benchmark calibration.
//!
//! This module is compiled only with `bench_fixture_coin`. Its hash namespace,
//! signing keys, and reveal chains are distinct from the production chained
//! public coin. Evidence produced here is NON-QUALIFYING.

use bl_pq512_crypto_core::{
    Fp16,
    chained_public_coin::{
        ChainedChallenge, ChainedContributor, ChainedPublicCoinBundle, ChainedRoundDescriptor,
        ChainedRoundEvidence, MAX_CHAIN_ROUNDS, MAX_PROVER_MESSAGE_BYTES,
        ML_DSA_87_PUBLIC_KEY_BYTES, ML_DSA_87_SIGNATURE_BYTES, PqSignatureSuite,
        SLH_DSA_SHAKE_256F_PUBLIC_KEY_BYTES, SLH_DSA_SHAKE_256F_SIGNATURE_BYTES,
    },
    sampler::{DEFAULT_MAX_ATTEMPTS, sample_uniform_fp16},
};
use ml_dsa::{
    EncodedVerifyingKey as MlDsaEncodedVerifyingKey, Keypair as _, MlDsa87, Seed,
    Signature as MlDsaSignature, SignatureEncoding as _, Signer as _,
    SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey, signature::Verifier as _,
};
use sha3::{Digest, Sha3_512};
use slh_dsa::{
    Shake256f, Signature as SlhDsaSignature, SigningKey as SlhDsaSigningKey,
    VerifyingKey as SlhDsaVerifyingKey,
};

const FIXTURE_MAGIC: &[u8] = b"BL/TEST-ONLY/BENCH-FIXTURE-COIN/v1\0";
const HEAD_AUTH_DOMAIN: &[u8] = b"FIXTURE-HEAD-AUTH\0";
const CHAIN_STEP_DOMAIN: &[u8] = b"FIXTURE-CHAIN-STEP\0";
const SESSION_INIT_DOMAIN: &[u8] = b"FIXTURE-SESSION-INIT\0";
const ROUND_SEED_DOMAIN: &[u8] = b"FIXTURE-ROUND-SEED\0";
const ROUND_AUDIT_DOMAIN: &[u8] = b"FIXTURE-ROUND-AUDIT\0";
const ID_DOMAIN: &[u8] = b"FIXTURE-ID\0";
const TAIL_DOMAIN: &[u8] = b"FIXTURE-TAIL\0";

fn fixture_hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(FIXTURE_MAGIC);
    hash.update(
        u32::try_from(domain.len())
            .expect("bounded fixture domain")
            .to_be_bytes(),
    );
    hash.update(domain);
    for part in parts {
        hash.update(
            u32::try_from(part.len())
                .expect("bounded fixture hash part")
                .to_be_bytes(),
        );
        hash.update(part);
    }
    hash.finalize().into()
}

fn fixture_id(label: &[u8], session_id: &[u8; 64], suite: PqSignatureSuite) -> [u8; 64] {
    fixture_hash(
        ID_DOMAIN,
        &[label, session_id, &(suite as u16).to_be_bytes()],
    )
}

fn fixture_chain_step(
    session_id: &[u8; 64],
    attempt: u16,
    schedule_commitment: &[u8; 64],
    contributor_id: &[u8; 64],
    round: u32,
    next: &[u8; 64],
) -> [u8; 64] {
    fixture_hash(
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

fn fixture_head_message(
    session_id: &[u8; 64],
    attempt: u16,
    schedule_commitment: &[u8; 64],
    round_count: u32,
    contributor: &ChainedContributor,
) -> [u8; 64] {
    fixture_hash(
        HEAD_AUTH_DOMAIN,
        &[
            session_id,
            &attempt.to_be_bytes(),
            schedule_commitment,
            &round_count.to_be_bytes(),
            &contributor.contributor_id,
            &contributor.key_id,
            &(contributor.suite as u16).to_be_bytes(),
            &contributor.chain_head,
        ],
    )
}

fn verify_fixture_head(
    session_id: &[u8; 64],
    attempt: u16,
    schedule_commitment: &[u8; 64],
    round_count: u32,
    contributor: &ChainedContributor,
) -> Result<(), String> {
    let message = fixture_head_message(
        session_id,
        attempt,
        schedule_commitment,
        round_count,
        contributor,
    );
    match contributor.suite {
        PqSignatureSuite::MlDsa87 => {
            if contributor.public_key.len() != ML_DSA_87_PUBLIC_KEY_BYTES
                || contributor.head_signature.len() != ML_DSA_87_SIGNATURE_BYTES
            {
                return Err("fixture_ml_dsa_shape".into());
            }
            let encoded_key =
                MlDsaEncodedVerifyingKey::<MlDsa87>::try_from(contributor.public_key.as_slice())
                    .map_err(|_| "fixture_ml_dsa_key")?;
            let key = MlDsaVerifyingKey::<MlDsa87>::decode(&encoded_key);
            let signature =
                MlDsaSignature::<MlDsa87>::try_from(contributor.head_signature.as_slice())
                    .map_err(|_| "fixture_ml_dsa_signature")?;
            key.verify(&message, &signature)
                .map_err(|_| "fixture_ml_dsa_verify".into())
        }
        PqSignatureSuite::SlhDsaShake256f => {
            if contributor.public_key.len() != SLH_DSA_SHAKE_256F_PUBLIC_KEY_BYTES
                || contributor.head_signature.len() != SLH_DSA_SHAKE_256F_SIGNATURE_BYTES
            {
                return Err("fixture_slh_dsa_shape".into());
            }
            let key = SlhDsaVerifyingKey::<Shake256f>::try_from(contributor.public_key.as_slice())
                .map_err(|_| "fixture_slh_dsa_key")?;
            let signature =
                SlhDsaSignature::<Shake256f>::try_from(contributor.head_signature.as_slice())
                    .map_err(|_| "fixture_slh_dsa_signature")?;
            key.verify(&message, &signature)
                .map_err(|_| "fixture_slh_dsa_verify".into())
        }
    }
}

struct FixtureSession {
    session_id: [u8; 64],
    attempt: u16,
    schedule_commitment: [u8; 64],
    round_count: u32,
    round: u32,
    contributors: Vec<ChainedContributor>,
    chain_states: Vec<[u8; 64]>,
    transcript_root: [u8; 64],
}

impl FixtureSession {
    fn new(
        session_id: [u8; 64],
        attempt: u16,
        schedule_commitment: [u8; 64],
        round_count: u32,
        contributors: Vec<ChainedContributor>,
    ) -> Result<Self, String> {
        if attempt >= 16
            || round_count == 0
            || round_count > MAX_CHAIN_ROUNDS
            || contributors.len() < 2
            || contributors.windows(2).any(|pair| {
                pair[0].contributor_id >= pair[1].contributor_id || pair[0].key_id == pair[1].key_id
            })
        {
            return Err("fixture_session_shape".into());
        }
        if !contributors
            .iter()
            .any(|item| item.suite == PqSignatureSuite::MlDsa87)
            || !contributors
                .iter()
                .any(|item| item.suite == PqSignatureSuite::SlhDsaShake256f)
        {
            return Err("fixture_suite_diversity".into());
        }
        for contributor in &contributors {
            verify_fixture_head(
                &session_id,
                attempt,
                &schedule_commitment,
                round_count,
                contributor,
            )?;
        }
        let attempt_encoded = attempt.to_be_bytes();
        let round_count_encoded = round_count.to_be_bytes();
        let mut init_parts: Vec<&[u8]> = vec![
            &session_id,
            &attempt_encoded,
            &schedule_commitment,
            &round_count_encoded,
        ];
        let suites = contributors
            .iter()
            .map(|item| (item.suite as u16).to_be_bytes())
            .collect::<Vec<_>>();
        for (contributor, suite) in contributors.iter().zip(&suites) {
            init_parts.extend([
                contributor.contributor_id.as_slice(),
                contributor.key_id.as_slice(),
                suite.as_slice(),
                contributor.public_key.as_slice(),
                contributor.chain_head.as_slice(),
                contributor.head_signature.as_slice(),
            ]);
        }
        let transcript_root = fixture_hash(SESSION_INIT_DOMAIN, &init_parts);
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

    fn accept_round(
        &mut self,
        descriptor: ChainedRoundDescriptor,
        prover_message: &[u8],
        reveals: &[[u8; 64]],
    ) -> Result<ChainedChallenge, String> {
        if self.round == self.round_count
            || descriptor.output_count == 0
            || prover_message.is_empty()
            || prover_message.len() > MAX_PROVER_MESSAGE_BYTES
            || reveals.len() != self.contributors.len()
        {
            return Err("fixture_round_shape".into());
        }
        for (index, ((contributor, current), reveal)) in self
            .contributors
            .iter()
            .zip(&self.chain_states)
            .zip(reveals)
            .enumerate()
        {
            if fixture_chain_step(
                &self.session_id,
                self.attempt,
                &self.schedule_commitment,
                &contributor.contributor_id,
                self.round,
                reveal,
            ) != *current
            {
                return Err(format!(
                    "fixture_chain_reveal_invalid:{index}:{}",
                    self.round
                ));
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
        let seed = fixture_hash(ROUND_SEED_DOMAIN, &seed_parts);
        let mut field_elements = Vec::with_capacity(usize::from(descriptor.output_count));
        for draw in 0..u32::from(descriptor.output_count) {
            field_elements.push(
                sample_uniform_fp16(
                    &seed,
                    &self.session_id,
                    self.round,
                    draw,
                    DEFAULT_MAX_ATTEMPTS,
                )
                .map_err(|_| "fixture_sampling")?
                .element,
            );
        }
        let encoded_fields = field_elements
            .iter()
            .flat_map(|value| value.encode())
            .collect::<Vec<_>>();
        let transcript_root = fixture_hash(
            ROUND_AUDIT_DOMAIN,
            &[
                &self.transcript_root,
                &descriptor_encoded,
                prover_message,
                &seed,
                &encoded_fields,
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

pub struct BenchFixturePublicCoinCoordinator {
    session: FixtureSession,
    session_id: [u8; 64],
    attempt: u16,
    schedule_commitment: [u8; 64],
    contributors: Vec<ChainedContributor>,
    chains: Vec<Vec<[u8; 64]>>,
    rounds: Vec<ChainedRoundEvidence>,
}

impl BenchFixturePublicCoinCoordinator {
    pub fn new(
        session_id: [u8; 64],
        attempt: u16,
        schedule_commitment: [u8; 64],
        round_count: u32,
    ) -> Result<Self, String> {
        let suites = [PqSignatureSuite::MlDsa87, PqSignatureSuite::SlhDsaShake256f];
        let mut paired = Vec::with_capacity(suites.len());
        for (index, suite) in suites.into_iter().enumerate() {
            let contributor_id = fixture_id(b"contributor", &session_id, suite);
            let key_id = fixture_id(b"key", &session_id, suite);
            let mut chain = vec![
                [0_u8; 64];
                usize::try_from(round_count).map_err(|_| "fixture_round_count")?
                    + 1
            ];
            chain[usize::try_from(round_count).map_err(|_| "fixture_round_count")?] =
                fixture_hash(TAIL_DOMAIN, &[&session_id, &[index as u8]]);
            for round in (0..round_count).rev() {
                chain[usize::try_from(round).map_err(|_| "fixture_round")?] = fixture_chain_step(
                    &session_id,
                    attempt,
                    &schedule_commitment,
                    &contributor_id,
                    round,
                    &chain[usize::try_from(round + 1).map_err(|_| "fixture_round")?],
                );
            }
            let contributor = ChainedContributor {
                contributor_id,
                key_id,
                suite,
                public_key: Vec::new(),
                chain_head: chain[0],
                head_signature: Vec::new(),
            };
            paired.push((contributor, chain));
        }

        let ml_signing = MlDsaSigningKey::<MlDsa87>::from_seed(&Seed::from([0x41_u8; 32]));
        let slh_signing = SlhDsaSigningKey::<Shake256f>::slh_keygen_internal(
            &[0x53_u8; 32],
            &[0x61_u8; 32],
            &[0x79_u8; 32],
        );
        for (contributor, _) in &mut paired {
            match contributor.suite {
                PqSignatureSuite::MlDsa87 => {
                    contributor.public_key = ml_signing.verifying_key().encode().to_vec();
                    let message = fixture_head_message(
                        &session_id,
                        attempt,
                        &schedule_commitment,
                        round_count,
                        contributor,
                    );
                    contributor.head_signature = ml_signing.sign(&message).to_bytes().to_vec();
                }
                PqSignatureSuite::SlhDsaShake256f => {
                    contributor.public_key = slh_signing.verifying_key().to_bytes().to_vec();
                    let message = fixture_head_message(
                        &session_id,
                        attempt,
                        &schedule_commitment,
                        round_count,
                        contributor,
                    );
                    contributor.head_signature = slh_signing
                        .try_sign(&message)
                        .map_err(|_| "fixture_slh_dsa_sign")?
                        .to_bytes()
                        .to_vec();
                }
            }
        }
        paired.sort_by_key(|item| item.0.contributor_id);
        let (contributors, chains): (Vec<_>, Vec<_>) = paired.into_iter().unzip();
        let session = FixtureSession::new(
            session_id,
            attempt,
            schedule_commitment,
            round_count,
            contributors.clone(),
        )?;
        Ok(Self {
            session,
            session_id,
            attempt,
            schedule_commitment,
            contributors,
            chains,
            rounds: Vec::with_capacity(
                usize::try_from(round_count).map_err(|_| "fixture_round_count")?,
            ),
        })
    }

    pub fn challenge(
        &mut self,
        descriptor: ChainedRoundDescriptor,
        prover_message: &[u8],
    ) -> Result<Vec<Fp16>, String> {
        let round = usize::try_from(self.session.round).map_err(|_| "fixture_round")?;
        let reveals = self
            .chains
            .iter()
            .map(|chain| chain[round + 1])
            .collect::<Vec<_>>();
        let challenge = self
            .session
            .accept_round(descriptor, prover_message, &reveals)?;
        self.rounds.push(ChainedRoundEvidence {
            descriptor,
            prover_message: prover_message.to_vec(),
            reveals,
        });
        Ok(challenge.field_elements)
    }

    pub fn scalar_challenge(
        &mut self,
        descriptor: ChainedRoundDescriptor,
        prover_message: &[u8],
    ) -> Result<Fp16, String> {
        let values = self.challenge(descriptor, prover_message)?;
        values
            .as_slice()
            .try_into()
            .map(|[value]: [Fp16; 1]| value)
            .map_err(|_| "fixture_scalar_shape".into())
    }

    pub fn finish_bundle(self) -> Result<ChainedPublicCoinBundle, String> {
        if self.session.round != self.session.round_count {
            return Err("fixture_incomplete".into());
        }
        Ok(ChainedPublicCoinBundle {
            session_id: self.session_id,
            attempt: self.attempt,
            schedule_commitment: self.schedule_commitment,
            contributors: self.contributors,
            rounds: self.rounds,
            claimed_final_transcript_root: self.session.transcript_root,
        })
    }
}

pub fn verify_bench_fixture_bundle(
    bundle: &ChainedPublicCoinBundle,
) -> Result<Vec<ChainedChallenge>, String> {
    let round_count = u32::try_from(bundle.rounds.len()).map_err(|_| "fixture_round_count")?;
    let mut session = FixtureSession::new(
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
    if session.round != session.round_count
        || session.transcript_root != bundle.claimed_final_transcript_root
    {
        return Err("fixture_final_transcript_root".into());
    }
    Ok(challenges)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bl_pq512_crypto_core::chained_public_coin::verify_chained_public_coin_bundle;

    fn completed_bundle() -> ChainedPublicCoinBundle {
        let session_id = fixture_hash(b"TEST-SESSION\0", &[b"fixed"]);
        let schedule = fixture_hash(b"TEST-SCHEDULE\0", &[b"fixed"]);
        let mut coordinator =
            BenchFixturePublicCoinCoordinator::new(session_id, 0, schedule, 2).unwrap();
        for ordinal in 0..2 {
            coordinator
                .scalar_challenge(
                    ChainedRoundDescriptor {
                        kind: 0xB001,
                        ordinal,
                        output_count: 1,
                    },
                    &[ordinal as u8 + 1],
                )
                .unwrap();
        }
        coordinator.finish_bundle().unwrap()
    }

    #[test]
    fn fixture_authentication_replay_and_domain_separation_hold() {
        let fixture = completed_bundle();
        assert_eq!(verify_bench_fixture_bundle(&fixture).unwrap().len(), 2);
        assert!(verify_chained_public_coin_bundle(&fixture).is_err());

        let mut tampered = fixture;
        tampered.rounds[0].reveals[0][0] ^= 1;
        assert!(verify_bench_fixture_bundle(&tampered).is_err());
    }
}
