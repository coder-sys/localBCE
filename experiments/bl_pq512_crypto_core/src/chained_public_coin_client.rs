//! Local process boundary for deployment-shaped chained public-coin controls.
//!
//! Each child owns its signing seed and unrevealed chain tail.  The coordinator
//! verifies both category-5 PQ head signatures before accepting a reveal and
//! requests a reveal only after receiving the fixed prover message.

use std::{
    io::{Read, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    vec,
    vec::Vec,
};

use sha3::{Digest, Sha3_512};

use crate::{
    Fp16,
    chained_public_coin::{
        ChainedChallenge, ChainedContributor, ChainedPublicCoin, ChainedPublicCoinBundle,
        ChainedPublicCoinError, ChainedRoundDescriptor, ChainedRoundEvidence,
        ML_DSA_87_PUBLIC_KEY_BYTES, ML_DSA_87_SIGNATURE_BYTES, PqSignatureSuite,
        SLH_DSA_SHAKE_256F_PUBLIC_KEY_BYTES, SLH_DSA_SHAKE_256F_SIGNATURE_BYTES,
    },
};

const REQUEST_MAGIC: &[u8; 8] = b"BLPCSRQ1";
const RESPONSE_MAGIC: &[u8; 8] = b"BLPCSRS1";
const ROUND_MAGIC: &[u8; 8] = b"BLPCRND1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainedPublicCoinClientError {
    Spawn,
    Io,
    Protocol,
    PublicCoin,
    OutputCount,
    Incomplete,
    ChildExit,
}

impl From<ChainedPublicCoinError> for ChainedPublicCoinClientError {
    fn from(_: ChainedPublicCoinError) -> Self {
        Self::PublicCoin
    }
}

struct Service {
    contributor: ChainedContributor,
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
}

fn service_id(label: &[u8], session_id: &[u8; 64], suite: PqSignatureSuite) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(b"BL/PQ512/CHAIN-SERVICE-ID/v1\0");
    hash.update(label);
    hash.update(session_id);
    hash.update((suite as u16).to_be_bytes());
    hash.finalize().into()
}

fn read_exact<const N: usize>(
    input: &mut impl Read,
) -> Result<[u8; N], ChainedPublicCoinClientError> {
    let mut value = [0_u8; N];
    input
        .read_exact(&mut value)
        .map_err(|_| ChainedPublicCoinClientError::Io)?;
    Ok(value)
}

fn spawn_service(
    program: &Path,
    suite: PqSignatureSuite,
    session_id: &[u8; 64],
    attempt: u16,
    schedule_commitment: &[u8; 64],
    round_count: u32,
) -> Result<Service, ChainedPublicCoinClientError> {
    let contributor_id = service_id(b"contributor", session_id, suite);
    let key_id = service_id(b"key", session_id, suite);
    let mut child = Command::new(program)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|_| ChainedPublicCoinClientError::Spawn)?;
    let mut input = child
        .stdin
        .take()
        .ok_or(ChainedPublicCoinClientError::Spawn)?;
    let mut output = child
        .stdout
        .take()
        .ok_or(ChainedPublicCoinClientError::Spawn)?;
    input
        .write_all(
            &[
                REQUEST_MAGIC.as_slice(),
                &(suite as u16).to_be_bytes(),
                session_id,
                &attempt.to_be_bytes(),
                schedule_commitment,
                &round_count.to_be_bytes(),
                &contributor_id,
                &key_id,
            ]
            .concat(),
        )
        .map_err(|_| ChainedPublicCoinClientError::Io)?;
    input
        .flush()
        .map_err(|_| ChainedPublicCoinClientError::Io)?;
    if &read_exact::<8>(&mut output)? != RESPONSE_MAGIC
        || u16::from_be_bytes(read_exact::<2>(&mut output)?) != suite as u16
    {
        return Err(ChainedPublicCoinClientError::Protocol);
    }
    let public_key_length = usize::try_from(u32::from_be_bytes(read_exact::<4>(&mut output)?))
        .map_err(|_| ChainedPublicCoinClientError::Protocol)?;
    let signature_length = usize::try_from(u32::from_be_bytes(read_exact::<4>(&mut output)?))
        .map_err(|_| ChainedPublicCoinClientError::Protocol)?;
    let expected_lengths = match suite {
        PqSignatureSuite::MlDsa87 => (ML_DSA_87_PUBLIC_KEY_BYTES, ML_DSA_87_SIGNATURE_BYTES),
        PqSignatureSuite::SlhDsaShake256f => (
            SLH_DSA_SHAKE_256F_PUBLIC_KEY_BYTES,
            SLH_DSA_SHAKE_256F_SIGNATURE_BYTES,
        ),
    };
    if (public_key_length, signature_length) != expected_lengths {
        return Err(ChainedPublicCoinClientError::Protocol);
    }
    let chain_head = read_exact::<64>(&mut output)?;
    let mut public_key = vec![0_u8; public_key_length];
    let mut head_signature = vec![0_u8; signature_length];
    output
        .read_exact(&mut public_key)
        .and_then(|_| output.read_exact(&mut head_signature))
        .map_err(|_| ChainedPublicCoinClientError::Io)?;
    Ok(Service {
        contributor: ChainedContributor {
            contributor_id,
            key_id,
            suite,
            public_key,
            chain_head,
            head_signature,
        },
        child,
        input,
        output,
    })
}

pub struct ChainedPublicCoinCoordinator {
    coin: ChainedPublicCoin,
    services: Vec<Service>,
    session_id: [u8; 64],
    attempt: u16,
    schedule_commitment: [u8; 64],
    contributors: Vec<ChainedContributor>,
    rounds: Vec<ChainedRoundEvidence>,
}

impl ChainedPublicCoinCoordinator {
    pub fn spawn(
        program: &Path,
        session_id: [u8; 64],
        attempt: u16,
        schedule_commitment: [u8; 64],
        round_count: u32,
    ) -> Result<Self, ChainedPublicCoinClientError> {
        let mut services = [PqSignatureSuite::MlDsa87, PqSignatureSuite::SlhDsaShake256f]
            .into_iter()
            .map(|suite| {
                spawn_service(
                    program,
                    suite,
                    &session_id,
                    attempt,
                    &schedule_commitment,
                    round_count,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        services.sort_by_key(|service| service.contributor.contributor_id);
        let contributors: Vec<ChainedContributor> = services
            .iter()
            .map(|service| service.contributor.clone())
            .collect();
        let coin = ChainedPublicCoin::new(
            session_id,
            attempt,
            schedule_commitment,
            round_count,
            contributors.clone(),
        )?;
        Ok(Self {
            coin,
            services,
            session_id,
            attempt,
            schedule_commitment,
            contributors,
            rounds: Vec::with_capacity(usize::try_from(round_count).unwrap_or(0)),
        })
    }

    pub fn challenge(
        &mut self,
        descriptor: ChainedRoundDescriptor,
        prover_message: &[u8],
    ) -> Result<Vec<Fp16>, ChainedPublicCoinClientError> {
        Ok(self
            .challenge_with_evidence(descriptor, prover_message)?
            .field_elements)
    }

    /// Accept one round and retain the verifier-derived seed and transcript
    /// root alongside its sampled fields. Dependent staged protocols use this
    /// to derive OODS points without replaying or predicting a public-coin
    /// round; ordinary callers may continue using [`Self::challenge`].
    pub fn challenge_with_evidence(
        &mut self,
        descriptor: ChainedRoundDescriptor,
        prover_message: &[u8],
    ) -> Result<ChainedChallenge, ChainedPublicCoinClientError> {
        let round = self.coin.round();
        let message_digest: [u8; 64] = Sha3_512::digest(prover_message).into();
        let request = [
            ROUND_MAGIC.as_slice(),
            &round.to_be_bytes(),
            &message_digest,
        ]
        .concat();
        for service in &mut self.services {
            service
                .input
                .write_all(&request)
                .and_then(|_| service.input.flush())
                .map_err(|_| ChainedPublicCoinClientError::Io)?;
        }
        let mut reveals = Vec::with_capacity(self.services.len());
        for service in &mut self.services {
            reveals.push(read_exact::<64>(&mut service.output)?);
        }
        let challenge = self
            .coin
            .accept_round(descriptor, prover_message, &reveals)?;
        self.rounds.push(ChainedRoundEvidence {
            descriptor,
            prover_message: prover_message.to_vec(),
            reveals,
        });
        Ok(challenge)
    }

    pub fn scalar_challenge(
        &mut self,
        descriptor: ChainedRoundDescriptor,
        prover_message: &[u8],
    ) -> Result<Fp16, ChainedPublicCoinClientError> {
        let values = self.challenge(descriptor, prover_message)?;
        if values.len() != 1 {
            return Err(ChainedPublicCoinClientError::OutputCount);
        }
        Ok(values[0])
    }

    /// Return the coordinator-owned transcript root after the most recently
    /// accepted round.  The root is derived from the native coin state; it is
    /// not a prover-supplied value and is exposed so a dependent round can
    /// bind its `prior_transcript_root` before its own message is challenged.
    pub const fn transcript_root(&self) -> [u8; 64] {
        self.coin.transcript_root()
    }

    pub fn finish(self) -> Result<[u8; 64], ChainedPublicCoinClientError> {
        Ok(self.finish_bundle()?.claimed_final_transcript_root)
    }

    pub fn finish_bundle(
        mut self,
    ) -> Result<ChainedPublicCoinBundle, ChainedPublicCoinClientError> {
        if !self.coin.complete() {
            return Err(ChainedPublicCoinClientError::Incomplete);
        }
        for mut service in self.services.drain(..) {
            drop(service.input);
            if !service
                .child
                .wait()
                .map_err(|_| ChainedPublicCoinClientError::Io)?
                .success()
            {
                return Err(ChainedPublicCoinClientError::ChildExit);
            }
        }
        Ok(ChainedPublicCoinBundle {
            session_id: self.session_id,
            attempt: self.attempt,
            schedule_commitment: self.schedule_commitment,
            contributors: self.contributors.clone(),
            rounds: self.rounds.clone(),
            claimed_final_transcript_root: self.coin.transcript_root(),
        })
    }
}

impl Drop for ChainedPublicCoinCoordinator {
    fn drop(&mut self) {
        for service in &mut self.services {
            let _ = service.child.kill();
            let _ = service.child.wait();
        }
    }
}
