//! Nonactivating strict-PQ public-coin candidate built on BindingRootV2.
//!
//! The acceptance authentication in this module is a one-time Lamport
//! signature over a raw version-2 chain-head message. ML-DSA and SLH-DSA are
//! deliberately absent: they may remain provenance evidence elsewhere, but
//! receive no acceptance-security credit here.
//!
//! Every Lamport secret and every public-coin chain state is 128 bytes. The
//! message digest, public values, Merkle tree, challenge seed, message
//! bindings, and transcript roots all use the 128-byte dual-domain binding
//! substrate. This candidate is conditional on the explicit joint
//! ideal-sponge/independent-domain QROM assumption documented by
//! binding_root_v2. It is not a proof-suite selection or activation.
//! The repository proofSuiteId therefore remains null.
//!
//! The pure helpers use no operating-system entropy. Custody must supply
//! independently generated secrets and tails, destroy retained copies, pin
//! the exact governed verifier key before the statement, and atomically
//! consume every contributor/statement/attempt slot even when a started
//! session aborts. Statement identity, the global nonresetting sequence, and
//! the fixed two-lane contributor roster are verifier-owned, not caller
//! assertions. At least one of the two custody lanes must keep its chain
//! preimages hidden until each prover message is fixed.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec,
    vec::Vec,
};

use zeroize::Zeroize;

use sha3::{Digest, Sha3_512};

use crate::binding_root_v2::{
    BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES, BINDING_V2_BYTES, BindingDigestV2,
    BindingMerkleMultiProofV2, BindingMerkleTreeV2, BindingRoleV2, BindingRootV2,
    BindingRootV2Error,
};
use crate::field::Fp16;
use crate::sampler::{digest_mod_field_order, is_accepted};

pub const STRICT_PQ_PUBLIC_COIN_V2_VERSION: u16 = 2;
pub const STRICT_PQ_MAX_ATTEMPTS_V2: u8 = 4;
pub const STRICT_PQ_REQUIRED_CONTRIBUTORS_V2: usize = 2;
pub const STRICT_PQ_GENERIC_MAX_CONTRIBUTORS_V2: usize = 16;
pub const STRICT_PQ_GENERIC_MAX_ROUNDS_V2: u32 = 1_u32 << 16;
pub const STRICT_PQ_H4_MAX_ROUNDS_V2: u32 = 7_059;
pub const STRICT_PQ_MAX_BUNDLE_BYTES_V2: usize = 16 << 20;
pub const STRICT_PQ_MAX_FP16_OUTPUTS_V2: u16 = 4_096;
pub const STRICT_PQ_FP16_MAX_ATTEMPTS_V2: u16 = 16;

pub const STRICT_PQ_LAMPORT_POSITIONS_V2: usize = 1_024;
pub const STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2: usize = 2_048;
pub const STRICT_PQ_LAMPORT_SECRET_BYTES_V2: usize = 128;
pub const STRICT_PQ_LAMPORT_REVEAL_BYTES_V2: usize =
    STRICT_PQ_LAMPORT_POSITIONS_V2 * STRICT_PQ_LAMPORT_SECRET_BYTES_V2;
pub const STRICT_PQ_LAMPORT_FRONTIER_DIGESTS_V2: usize = 1_024;
pub const STRICT_PQ_LAMPORT_MULTIPROOF_BYTES_V2: usize = BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES
    + STRICT_PQ_LAMPORT_POSITIONS_V2 * 8
    + STRICT_PQ_LAMPORT_FRONTIER_DIGESTS_V2 * BINDING_V2_BYTES;
pub const STRICT_PQ_LAMPORT_SIGNATURE_HEADER_BYTES_V2: usize = 16;
pub const STRICT_PQ_LAMPORT_SIGNATURE_BYTES_V2: usize = STRICT_PQ_LAMPORT_SIGNATURE_HEADER_BYTES_V2
    + STRICT_PQ_LAMPORT_REVEAL_BYTES_V2
    + STRICT_PQ_LAMPORT_MULTIPROOF_BYTES_V2;

pub const STRICT_PQ_KEY_CONTEXT_BYTES_V2: usize = 356;
pub const STRICT_PQ_LAMPORT_PUBLIC_KEY_BYTES_V2: usize =
    STRICT_PQ_KEY_CONTEXT_BYTES_V2 + BINDING_V2_BYTES;
pub const STRICT_PQ_GOVERNED_KEY_HEADER_BYTES_V2: usize = 148;
pub const STRICT_PQ_GOVERNED_KEY_BYTES_V2: usize = STRICT_PQ_GOVERNED_KEY_HEADER_BYTES_V2
    + STRICT_PQ_REQUIRED_CONTRIBUTORS_V2 * STRICT_PQ_LAMPORT_PUBLIC_KEY_BYTES_V2;
pub const STRICT_PQ_HEAD_MESSAGE_BYTES_V2: usize =
    8 + 2 + 2 + STRICT_PQ_KEY_CONTEXT_BYTES_V2 + 64 + 64 + 4 + BINDING_V2_BYTES;
pub const STRICT_PQ_ANCHOR_BYTES_V2: usize =
    64 + 64 + BINDING_V2_BYTES + STRICT_PQ_LAMPORT_SIGNATURE_BYTES_V2;
pub const STRICT_PQ_BUNDLE_HEADER_BYTES_V2: usize = 288;
pub const STRICT_PQ_ROUND_DESCRIPTOR_BYTES_V2: usize = 8;
pub const STRICT_PQ_QUALIFYING_ROUND_BYTES_V2: usize = STRICT_PQ_ROUND_DESCRIPTOR_BYTES_V2
    + BINDING_V2_BYTES
    + STRICT_PQ_REQUIRED_CONTRIBUTORS_V2 * BINDING_V2_BYTES;
pub const STRICT_PQ_H4_MAX_BUNDLE_BYTES_V2: usize = STRICT_PQ_BUNDLE_HEADER_BYTES_V2
    + STRICT_PQ_REQUIRED_CONTRIBUTORS_V2 * STRICT_PQ_ANCHOR_BYTES_V2
    + STRICT_PQ_H4_MAX_ROUNDS_V2 as usize * STRICT_PQ_QUALIFYING_ROUND_BYTES_V2;
pub const STRICT_PQ_GENERIC_MAX_SHAPE_BYTES_V2: usize = STRICT_PQ_BUNDLE_HEADER_BYTES_V2
    + STRICT_PQ_GENERIC_MAX_CONTRIBUTORS_V2 * STRICT_PQ_ANCHOR_BYTES_V2
    + STRICT_PQ_GENERIC_MAX_ROUNDS_V2 as usize
        * (STRICT_PQ_ROUND_DESCRIPTOR_BYTES_V2
            + BINDING_V2_BYTES
            + STRICT_PQ_GENERIC_MAX_CONTRIBUTORS_V2 * BINDING_V2_BYTES);

// Conservative generic lifetime ledger: at most 2^64 statements, four
// attempts, sixteen parser-visible contributors, and 2^16 parser-visible
// rounds. The chain is a fixed-target second-preimage term after its signed
// head is fixed. The prover-message binding remains a generic-collision term
// because a malicious prover can prepare two messages before the honest
// reveal. The ceilings below cover the union of all remaining fixed-target
// roles as well as the Lamport/Merkle roles. The displayed advantage
// exponents use unit leading constants in that explicit ideal-query theorem;
// any larger concrete reduction constant must be charged before qualification.
pub const STRICT_PQ_GENERIC_OTS_INSTANCES_LOG2_V2: u32 = 70;
pub const STRICT_PQ_COLLISION_ROLE_COUNT_V2: u32 = 5;
pub const STRICT_PQ_LAMPORT_COLLISION_TARGET_LOG2_CEIL_V2: u32 = 73;
pub const STRICT_PQ_LAMPORT_PREIMAGE_TARGET_LOG2_V2: u32 = 81;
pub const STRICT_PQ_MESSAGE_BINDING_INSTANCES_LOG2_V2: u32 = 82;
pub const STRICT_PQ_CHAIN_TARGETS_LOG2_V2: u32 = 86;
pub const STRICT_PQ_COMPOSED_COLLISION_TARGET_LOG2_CEIL_V2: u32 = 83;
pub const STRICT_PQ_COMPOSED_PREIMAGE_TARGET_LOG2_CEIL_V2: u32 = 87;
pub const STRICT_PQ_Q128_COLLISION_BOUND_EXPONENT_V2: u32 = 557;
pub const STRICT_PQ_Q128_PREIMAGE_BOUND_EXPONENT_V2: u32 = 681;
pub const STRICT_PQ_Q128_COMBINED_BOUND_EXPONENT_V2: u32 = 556;
pub const STRICT_PQ_CONSERVATIVE_COLLISION_WORK_BITS_V2: u32 = 258;
pub const STRICT_PQ_CONSERVATIVE_PREIMAGE_WORK_BITS_V2: u32 = 425;

pub const STRICT_PQ_KEY_CONTEXT_MAGIC_V2: &[u8; 8] = b"BLLOTKC2";
pub const STRICT_PQ_LAMPORT_SIGNATURE_MAGIC_V2: &[u8; 8] = b"BLLOTS02";
pub const STRICT_PQ_HEAD_MESSAGE_MAGIC_V2: &[u8; 8] = b"BLHDMSG2";
pub const STRICT_PQ_GOVERNED_KEY_MAGIC_V2: &[u8; 8] = b"BLSPQVK2";
pub const STRICT_PQ_BUNDLE_MAGIC_V2: &[u8; 8] = b"BLSPQPC2";

pub const STRICT_PQ_LAMPORT_PUBLIC_VALUE_DOMAIN_V2: &[u8] =
    b"BL/PQ512/WAVE2/STRICT-PQ/LAMPORT-PUBLIC-VALUE/v2\0";
pub const STRICT_PQ_SECRET_UNIQUENESS_DOMAIN_V2: &[u8] =
    b"BL/PQ512/WAVE2/STRICT-PQ/SECRET-UNIQUENESS/v2\0";
pub const STRICT_PQ_HEAD_MESSAGE_HASH_DOMAIN_V2: &[u8] =
    b"BL/PQ512/WAVE2/STRICT-PQ/RAW-HEAD-MESSAGE/v2\0";
pub const STRICT_PQ_ROOT_SLOT_DOMAIN_V2: &[u8] = b"BL/PQ512/WAVE2/STRICT-PQ/ROOT-SLOT/v2\0";
pub const STRICT_PQ_GOVERNED_KEY_BINDING_DOMAIN_V2: &[u8] =
    b"BL/PQ512/WAVE2/STRICT-PQ/GOVERNED-KEY/v2\0";
pub const STRICT_PQ_CHAIN_STEP_DOMAIN_V2: &[u8] = b"BL/PQ512/WAVE2/STRICT-PQ/CHAIN-STEP/v2\0";
pub const STRICT_PQ_INITIAL_TRANSCRIPT_DOMAIN_V2: &[u8] =
    b"BL/PQ512/WAVE2/STRICT-PQ/TRANSCRIPT-INITIAL/v2\0";
pub const STRICT_PQ_PROVER_MESSAGE_DOMAIN_V2: &[u8] =
    b"BL/PQ512/WAVE2/STRICT-PQ/PROVER-MESSAGE/v2\0";
pub const STRICT_PQ_ROUND_SEED_DOMAIN_V2: &[u8] = b"BL/PQ512/WAVE2/STRICT-PQ/ROUND-SEED/v2\0";
pub const STRICT_PQ_TRANSCRIPT_ROOT_DOMAIN_V2: &[u8] =
    b"BL/PQ512/WAVE2/STRICT-PQ/TRANSCRIPT-ROOT/v2\0";
pub const STRICT_PQ_FP16_CHALLENGE_DOMAIN_V2: &[u8] =
    b"BL/PQ512/WAVE2/STRICT-PQ/FP16-CHALLENGE/v2\0";
pub const STRICT_PQ_FP16_TRANSCRIPT_DOMAIN_V2: &[u8] =
    b"BL/PQ512/WAVE2/STRICT-PQ/FP16-TRANSCRIPT/v2\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StrictPqH4ProfileV2 {
    K128 = 1,
    K512 = 3,
}

impl StrictPqH4ProfileV2 {
    pub const fn code(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StrictPqFp16PolicyV2 {
    Uniform = 1,
    Nonzero = 2,
    NonzeroNonone = 3,
    OodsOutsideFp8 = 4,
}

impl StrictPqFp16PolicyV2 {
    pub const fn code(self) -> u8 {
        self as u8
    }

    pub fn accepts(self, element: Fp16) -> bool {
        match self {
            Self::Uniform => true,
            Self::Nonzero => !element.is_zero(),
            Self::NonzeroNonone => !element.is_zero() && element != Fp16::ONE,
            Self::OodsOutsideFp8 => !element.is_in_fp8_subfield(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StrictPqPublicCoinV2Error {
    ArithmeticOverflow,
    Binding(BindingRootV2Error),
    Length,
    Magic,
    Version,
    Flags,
    Reserved,
    ZeroIdentifier,
    ZeroSecret,
    DuplicateSecret,
    SecretCount,
    AttemptOutOfRange,
    ContributorCount,
    ContributorOrder,
    DuplicateContributor,
    DuplicateKey,
    DuplicateRoot,
    RoundCount,
    Descriptor,
    ContextMismatch,
    SessionMismatch,
    ScheduleMismatch,
    AttemptMismatch,
    SignatureLength,
    SignatureProofLength,
    SignatureIndexMismatch,
    SignatureMismatch,
    AnchorMismatch,
    ChainMismatch,
    RoundMismatch,
    TranscriptMismatch,
    RawMessageCount,
    RootAlreadyUsed,
    SlotAlreadyUsed,
    BundleTooLarge,
    BundleLength,
    ChallengePolicyCount,
    ChallengeAttemptCapExhausted { draw: u16 },
}

impl From<BindingRootV2Error> for StrictPqPublicCoinV2Error {
    fn from(value: BindingRootV2Error) -> Self {
        Self::Binding(value)
    }
}

fn nonzero(value: &[u8]) -> bool {
    value.iter().any(|byte| *byte != 0)
}

fn typed_binding_hash(
    domain: &[u8],
    parts: &[&[u8]],
) -> Result<BindingDigestV2, StrictPqPublicCoinV2Error> {
    let part_count =
        u32::try_from(parts.len()).map_err(|_| StrictPqPublicCoinV2Error::ArithmeticOverflow)?;
    let mut capacity = domain
        .len()
        .checked_add(4)
        .ok_or(StrictPqPublicCoinV2Error::ArithmeticOverflow)?;
    for part in parts {
        capacity = capacity
            .checked_add(8)
            .and_then(|length| length.checked_add(part.len()))
            .ok_or(StrictPqPublicCoinV2Error::ArithmeticOverflow)?;
    }
    let mut payload = Vec::with_capacity(capacity);
    payload.extend_from_slice(domain);
    payload.extend_from_slice(&part_count.to_be_bytes());
    for part in parts {
        let length =
            u64::try_from(part.len()).map_err(|_| StrictPqPublicCoinV2Error::ArithmeticOverflow)?;
        payload.extend_from_slice(&length.to_be_bytes());
        payload.extend_from_slice(part);
    }
    let digest = BindingDigestV2::hash(BindingRoleV2::Payload, &payload);
    payload.zeroize();
    Ok(digest?)
}

/// Canonical key context.
///
/// statement_sequence is a globally nonresetting u64 lifetime counter, not a
/// per-epoch counter, and statement_id must be globally unique. The one-time
/// registry slot deliberately depends only on statement_id, contributor_id,
/// and attempt, so changing an epoch, schema, protocol candidate, sequence, or
/// key identifier cannot allocate a second root for the same logical slot.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct StrictPqKeyContextV2 {
    candidate_protocol_id: [u8; 64],
    schema_id: [u8; 64],
    epoch: u64,
    statement_sequence: u64,
    statement_id: [u8; 64],
    contributor_id: [u8; 64],
    key_id: [u8; 64],
    attempt: u8,
}

impl StrictPqKeyContextV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        candidate_protocol_id: [u8; 64],
        schema_id: [u8; 64],
        epoch: u64,
        statement_sequence: u64,
        statement_id: [u8; 64],
        contributor_id: [u8; 64],
        key_id: [u8; 64],
        attempt: u8,
    ) -> Result<Self, StrictPqPublicCoinV2Error> {
        if !nonzero(&candidate_protocol_id)
            || !nonzero(&schema_id)
            || epoch == 0
            || !nonzero(&statement_id)
            || !nonzero(&contributor_id)
            || !nonzero(&key_id)
        {
            return Err(StrictPqPublicCoinV2Error::ZeroIdentifier);
        }
        if attempt >= STRICT_PQ_MAX_ATTEMPTS_V2 {
            return Err(StrictPqPublicCoinV2Error::AttemptOutOfRange);
        }
        Ok(Self {
            candidate_protocol_id,
            schema_id,
            epoch,
            statement_sequence,
            statement_id,
            contributor_id,
            key_id,
            attempt,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(STRICT_PQ_KEY_CONTEXT_BYTES_V2);
        encoded.extend_from_slice(STRICT_PQ_KEY_CONTEXT_MAGIC_V2);
        encoded.extend_from_slice(&STRICT_PQ_PUBLIC_COIN_V2_VERSION.to_be_bytes());
        encoded.extend_from_slice(&0_u16.to_be_bytes());
        encoded.extend_from_slice(&self.candidate_protocol_id);
        encoded.extend_from_slice(&self.schema_id);
        encoded.extend_from_slice(&self.epoch.to_be_bytes());
        encoded.extend_from_slice(&self.statement_sequence.to_be_bytes());
        encoded.extend_from_slice(&self.statement_id);
        encoded.extend_from_slice(&self.contributor_id);
        encoded.extend_from_slice(&self.key_id);
        encoded.push(self.attempt);
        encoded.extend_from_slice(&[0_u8; 7]);
        debug_assert_eq!(encoded.len(), STRICT_PQ_KEY_CONTEXT_BYTES_V2);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, StrictPqPublicCoinV2Error> {
        if encoded.len() != STRICT_PQ_KEY_CONTEXT_BYTES_V2 {
            return Err(StrictPqPublicCoinV2Error::Length);
        }
        let mut reader = Reader::new(encoded);
        if reader.array::<8>()? != *STRICT_PQ_KEY_CONTEXT_MAGIC_V2 {
            return Err(StrictPqPublicCoinV2Error::Magic);
        }
        if reader.u16()? != STRICT_PQ_PUBLIC_COIN_V2_VERSION {
            return Err(StrictPqPublicCoinV2Error::Version);
        }
        if reader.u16()? != 0 {
            return Err(StrictPqPublicCoinV2Error::Flags);
        }
        let candidate_protocol_id = reader.array::<64>()?;
        let schema_id = reader.array::<64>()?;
        let epoch = reader.u64()?;
        let statement_sequence = reader.u64()?;
        let statement_id = reader.array::<64>()?;
        let contributor_id = reader.array::<64>()?;
        let key_id = reader.array::<64>()?;
        let attempt = reader.u8()?;
        if reader.take(7)?.iter().any(|byte| *byte != 0) {
            return Err(StrictPqPublicCoinV2Error::Reserved);
        }
        reader.finish()?;
        Self::new(
            candidate_protocol_id,
            schema_id,
            epoch,
            statement_sequence,
            statement_id,
            contributor_id,
            key_id,
            attempt,
        )
    }

    pub const fn candidate_protocol_id(&self) -> &[u8; 64] {
        &self.candidate_protocol_id
    }

    pub const fn schema_id(&self) -> &[u8; 64] {
        &self.schema_id
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn statement_sequence(&self) -> u64 {
        self.statement_sequence
    }

    pub const fn statement_id(&self) -> &[u8; 64] {
        &self.statement_id
    }

    pub const fn contributor_id(&self) -> &[u8; 64] {
        &self.contributor_id
    }

    pub const fn key_id(&self) -> &[u8; 64] {
        &self.key_id
    }

    pub const fn attempt(&self) -> u8 {
        self.attempt
    }

    fn same_statement_attempt(&self, other: &Self) -> bool {
        self.candidate_protocol_id == other.candidate_protocol_id
            && self.schema_id == other.schema_id
            && self.epoch == other.epoch
            && self.statement_sequence == other.statement_sequence
            && self.statement_id == other.statement_id
            && self.attempt == other.attempt
    }

    fn slot_id(&self) -> Result<[u8; BINDING_V2_BYTES], StrictPqPublicCoinV2Error> {
        let attempt = [self.attempt];
        Ok(typed_binding_hash(
            STRICT_PQ_ROOT_SLOT_DOMAIN_V2,
            &[&self.statement_id, &self.contributor_id, &attempt],
        )?
        .to_bytes())
    }
}

fn lamport_public_value_v2(
    context: &StrictPqKeyContextV2,
    position: u16,
    bit: u8,
    secret: &[u8; STRICT_PQ_LAMPORT_SECRET_BYTES_V2],
) -> Result<[u8; BINDING_V2_BYTES], StrictPqPublicCoinV2Error> {
    if usize::from(position) >= STRICT_PQ_LAMPORT_POSITIONS_V2 || bit > 1 {
        return Err(StrictPqPublicCoinV2Error::SignatureIndexMismatch);
    }
    let context_bytes = context.encode();
    let position_bytes = position.to_be_bytes();
    let bit_bytes = [bit];
    Ok(typed_binding_hash(
        STRICT_PQ_LAMPORT_PUBLIC_VALUE_DOMAIN_V2,
        &[&context_bytes, &position_bytes, &bit_bytes, secret],
    )?
    .to_bytes())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictPqLamportPublicKeyV2 {
    context: StrictPqKeyContextV2,
    root: BindingRootV2,
}

impl StrictPqLamportPublicKeyV2 {
    pub fn from_parts(
        context: StrictPqKeyContextV2,
        root: BindingRootV2,
    ) -> Result<Self, StrictPqPublicCoinV2Error> {
        if !nonzero(root.as_bytes()) {
            return Err(StrictPqPublicCoinV2Error::ZeroIdentifier);
        }
        Ok(Self { context, root })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = self.context.encode();
        encoded.extend_from_slice(self.root.as_bytes());
        debug_assert_eq!(encoded.len(), STRICT_PQ_LAMPORT_PUBLIC_KEY_BYTES_V2);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, StrictPqPublicCoinV2Error> {
        if encoded.len() != STRICT_PQ_LAMPORT_PUBLIC_KEY_BYTES_V2 {
            return Err(StrictPqPublicCoinV2Error::Length);
        }
        let context = StrictPqKeyContextV2::decode(&encoded[..STRICT_PQ_KEY_CONTEXT_BYTES_V2])?;
        let root = BindingRootV2::decode(&encoded[STRICT_PQ_KEY_CONTEXT_BYTES_V2..])?;
        Self::from_parts(context, root)
    }

    pub const fn context(&self) -> &StrictPqKeyContextV2 {
        &self.context
    }

    pub const fn root(&self) -> BindingRootV2 {
        self.root
    }
}

pub struct StrictPqLamportSecretKeyV2 {
    context: StrictPqKeyContextV2,
    secrets: Vec<[u8; STRICT_PQ_LAMPORT_SECRET_BYTES_V2]>,
    public_tree: BindingMerkleTreeV2,
}

impl Drop for StrictPqLamportSecretKeyV2 {
    fn drop(&mut self) {
        self.secrets.zeroize();
    }
}

impl StrictPqLamportSecretKeyV2 {
    pub fn keygen_from_supplied_secrets(
        context: StrictPqKeyContextV2,
        mut secrets: Vec<[u8; STRICT_PQ_LAMPORT_SECRET_BYTES_V2]>,
    ) -> Result<(Self, StrictPqLamportPublicKeyV2), StrictPqPublicCoinV2Error> {
        if secrets.len() != STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2 {
            secrets.zeroize();
            return Err(StrictPqPublicCoinV2Error::SecretCount);
        }
        let mut seen = BTreeSet::new();
        for secret in &secrets {
            if !nonzero(secret) {
                secrets.zeroize();
                return Err(StrictPqPublicCoinV2Error::ZeroSecret);
            }
            let uniqueness_digest =
                match typed_binding_hash(STRICT_PQ_SECRET_UNIQUENESS_DOMAIN_V2, &[secret]) {
                    Ok(digest) => digest.to_bytes(),
                    Err(error) => {
                        secrets.zeroize();
                        return Err(error);
                    }
                };
            if !seen.insert(uniqueness_digest) {
                secrets.zeroize();
                return Err(StrictPqPublicCoinV2Error::DuplicateSecret);
            }
        }
        let public_values = match (|| {
            let mut public_values = Vec::with_capacity(STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2);
            for position in 0..STRICT_PQ_LAMPORT_POSITIONS_V2 {
                let position_u16 = u16::try_from(position)
                    .map_err(|_| StrictPqPublicCoinV2Error::ArithmeticOverflow)?;
                for bit in 0..=1_u8 {
                    let index = position
                        .checked_mul(2)
                        .and_then(|value| value.checked_add(usize::from(bit)))
                        .ok_or(StrictPqPublicCoinV2Error::ArithmeticOverflow)?;
                    public_values.push(lamport_public_value_v2(
                        &context,
                        position_u16,
                        bit,
                        &secrets[index],
                    )?);
                }
            }
            Ok::<_, StrictPqPublicCoinV2Error>(public_values)
        })() {
            Ok(public_values) => public_values,
            Err(error) => {
                secrets.zeroize();
                return Err(error);
            }
        };
        let public_tree = match BindingMerkleTreeV2::from_payloads(&public_values) {
            Ok(tree) => tree,
            Err(error) => {
                secrets.zeroize();
                return Err(error.into());
            }
        };
        let public_key =
            match StrictPqLamportPublicKeyV2::from_parts(context.clone(), public_tree.root()) {
                Ok(public_key) => public_key,
                Err(error) => {
                    secrets.zeroize();
                    return Err(error);
                }
            };
        Ok((
            Self {
                context,
                secrets,
                public_tree,
            },
            public_key,
        ))
    }

    pub const fn context(&self) -> &StrictPqKeyContextV2 {
        &self.context
    }

    pub fn sign(
        mut self,
        message: &StrictPqHeadMessageV2,
    ) -> Result<StrictPqLamportSignatureV2, StrictPqPublicCoinV2Error> {
        if message.context() != &self.context {
            return Err(StrictPqPublicCoinV2Error::ContextMismatch);
        }
        let digest = message.digest()?;
        let selected_indices = selected_lamport_indices_v2(digest.as_bytes());
        let mut reveals = Vec::with_capacity(STRICT_PQ_LAMPORT_POSITIONS_V2);
        for &index in &selected_indices {
            let index_usize = usize::try_from(index)
                .map_err(|_| StrictPqPublicCoinV2Error::ArithmeticOverflow)?;
            let reveal = match self.secrets.get(index_usize) {
                Some(reveal) => *reveal,
                None => {
                    reveals.zeroize();
                    return Err(StrictPqPublicCoinV2Error::SignatureIndexMismatch);
                }
            };
            reveals.push(reveal);
        }
        let proof = match self.public_tree.prove(&selected_indices) {
            Ok(proof) => proof,
            Err(error) => {
                reveals.zeroize();
                return Err(error.into());
            }
        };
        self.secrets.zeroize();
        match StrictPqLamportSignatureV2::from_parts(reveals, proof) {
            Ok(signature) => Ok(signature),
            Err(error) => Err(error),
        }
    }
}

fn selected_lamport_indices_v2(digest: &[u8; BINDING_V2_BYTES]) -> Vec<u64> {
    let mut indices = Vec::with_capacity(STRICT_PQ_LAMPORT_POSITIONS_V2);
    for position in 0..STRICT_PQ_LAMPORT_POSITIONS_V2 {
        let byte = digest[position / 8];
        let bit = (byte >> (7 - (position % 8))) & 1;
        indices.push((position as u64) * 2 + u64::from(bit));
    }
    indices
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictPqLamportSignatureV2 {
    reveals: Vec<[u8; STRICT_PQ_LAMPORT_SECRET_BYTES_V2]>,
    proof: BindingMerkleMultiProofV2,
}

impl StrictPqLamportSignatureV2 {
    fn from_parts(
        mut reveals: Vec<[u8; STRICT_PQ_LAMPORT_SECRET_BYTES_V2]>,
        proof: BindingMerkleMultiProofV2,
    ) -> Result<Self, StrictPqPublicCoinV2Error> {
        if reveals.len() != STRICT_PQ_LAMPORT_POSITIONS_V2 {
            reveals.zeroize();
            return Err(StrictPqPublicCoinV2Error::SignatureLength);
        }
        if reveals.iter().any(|secret| !nonzero(secret)) {
            reveals.zeroize();
            return Err(StrictPqPublicCoinV2Error::ZeroSecret);
        }
        if proof.leaf_count() != STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2 as u64
            || proof.selected_indices().len() != STRICT_PQ_LAMPORT_POSITIONS_V2
            || proof.frontier_digests().len() != STRICT_PQ_LAMPORT_FRONTIER_DIGESTS_V2
        {
            reveals.zeroize();
            return Err(StrictPqPublicCoinV2Error::SignatureProofLength);
        }
        Ok(Self { reveals, proof })
    }

    pub fn encode(&self) -> Result<Vec<u8>, StrictPqPublicCoinV2Error> {
        let proof = self.proof.encode()?;
        if proof.len() != STRICT_PQ_LAMPORT_MULTIPROOF_BYTES_V2 {
            return Err(StrictPqPublicCoinV2Error::SignatureProofLength);
        }
        let mut encoded = Vec::with_capacity(STRICT_PQ_LAMPORT_SIGNATURE_BYTES_V2);
        encoded.extend_from_slice(STRICT_PQ_LAMPORT_SIGNATURE_MAGIC_V2);
        encoded.extend_from_slice(&STRICT_PQ_PUBLIC_COIN_V2_VERSION.to_be_bytes());
        encoded.extend_from_slice(&0_u16.to_be_bytes());
        encoded.extend_from_slice(&(STRICT_PQ_LAMPORT_MULTIPROOF_BYTES_V2 as u32).to_be_bytes());
        for reveal in &self.reveals {
            encoded.extend_from_slice(reveal);
        }
        encoded.extend_from_slice(&proof);
        if encoded.len() != STRICT_PQ_LAMPORT_SIGNATURE_BYTES_V2 {
            return Err(StrictPqPublicCoinV2Error::SignatureLength);
        }
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, StrictPqPublicCoinV2Error> {
        if encoded.len() != STRICT_PQ_LAMPORT_SIGNATURE_BYTES_V2 {
            return Err(StrictPqPublicCoinV2Error::SignatureLength);
        }
        let mut reader = Reader::new(encoded);
        if reader.array::<8>()? != *STRICT_PQ_LAMPORT_SIGNATURE_MAGIC_V2 {
            return Err(StrictPqPublicCoinV2Error::Magic);
        }
        if reader.u16()? != STRICT_PQ_PUBLIC_COIN_V2_VERSION {
            return Err(StrictPqPublicCoinV2Error::Version);
        }
        if reader.u16()? != 0 {
            return Err(StrictPqPublicCoinV2Error::Flags);
        }
        if reader.u32()? as usize != STRICT_PQ_LAMPORT_MULTIPROOF_BYTES_V2 {
            return Err(StrictPqPublicCoinV2Error::SignatureProofLength);
        }
        let mut reveals = Vec::with_capacity(STRICT_PQ_LAMPORT_POSITIONS_V2);
        for _ in 0..STRICT_PQ_LAMPORT_POSITIONS_V2 {
            reveals.push(reader.array::<STRICT_PQ_LAMPORT_SECRET_BYTES_V2>()?);
        }
        let proof =
            BindingMerkleMultiProofV2::decode(reader.take(STRICT_PQ_LAMPORT_MULTIPROOF_BYTES_V2)?)?;
        reader.finish()?;
        Self::from_parts(reveals, proof)
    }

    pub fn verify(
        &self,
        public_key: &StrictPqLamportPublicKeyV2,
        message: &StrictPqHeadMessageV2,
    ) -> Result<(), StrictPqPublicCoinV2Error> {
        if message.context() != public_key.context() {
            return Err(StrictPqPublicCoinV2Error::ContextMismatch);
        }
        let digest = message.digest()?;
        let expected_indices = selected_lamport_indices_v2(digest.as_bytes());
        if self.proof.selected_indices() != expected_indices {
            return Err(StrictPqPublicCoinV2Error::SignatureIndexMismatch);
        }
        let mut public_values = Vec::with_capacity(STRICT_PQ_LAMPORT_POSITIONS_V2);
        for (position, reveal) in self.reveals.iter().enumerate() {
            if !nonzero(reveal) {
                return Err(StrictPqPublicCoinV2Error::ZeroSecret);
            }
            let bit = u8::try_from(expected_indices[position] & 1)
                .map_err(|_| StrictPqPublicCoinV2Error::ArithmeticOverflow)?;
            public_values.push(lamport_public_value_v2(
                public_key.context(),
                u16::try_from(position)
                    .map_err(|_| StrictPqPublicCoinV2Error::ArithmeticOverflow)?,
                bit,
                reveal,
            )?);
        }
        self.proof
            .verify_payloads(&public_values, &public_key.root())
            .map_err(|_| StrictPqPublicCoinV2Error::SignatureMismatch)
    }

    pub fn selected_indices(&self) -> &[u64] {
        self.proof.selected_indices()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictPqHeadMessageV2 {
    context: StrictPqKeyContextV2,
    session_id: [u8; 64],
    schedule_commitment: [u8; 64],
    round_count: u32,
    chain_head: [u8; BINDING_V2_BYTES],
}

impl StrictPqHeadMessageV2 {
    pub fn new(
        context: StrictPqKeyContextV2,
        session_id: [u8; 64],
        schedule_commitment: [u8; 64],
        round_count: u32,
        chain_head: [u8; BINDING_V2_BYTES],
    ) -> Result<Self, StrictPqPublicCoinV2Error> {
        if !nonzero(&session_id) || !nonzero(&schedule_commitment) {
            return Err(StrictPqPublicCoinV2Error::ZeroIdentifier);
        }
        if round_count == 0 || round_count > STRICT_PQ_H4_MAX_ROUNDS_V2 {
            return Err(StrictPqPublicCoinV2Error::RoundCount);
        }
        Ok(Self {
            context,
            session_id,
            schedule_commitment,
            round_count,
            chain_head,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(STRICT_PQ_HEAD_MESSAGE_BYTES_V2);
        encoded.extend_from_slice(STRICT_PQ_HEAD_MESSAGE_MAGIC_V2);
        encoded.extend_from_slice(&STRICT_PQ_PUBLIC_COIN_V2_VERSION.to_be_bytes());
        encoded.extend_from_slice(&0_u16.to_be_bytes());
        encoded.extend_from_slice(&self.context.encode());
        encoded.extend_from_slice(&self.session_id);
        encoded.extend_from_slice(&self.schedule_commitment);
        encoded.extend_from_slice(&self.round_count.to_be_bytes());
        encoded.extend_from_slice(&self.chain_head);
        debug_assert_eq!(encoded.len(), STRICT_PQ_HEAD_MESSAGE_BYTES_V2);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, StrictPqPublicCoinV2Error> {
        if encoded.len() != STRICT_PQ_HEAD_MESSAGE_BYTES_V2 {
            return Err(StrictPqPublicCoinV2Error::Length);
        }
        let mut reader = Reader::new(encoded);
        if reader.array::<8>()? != *STRICT_PQ_HEAD_MESSAGE_MAGIC_V2 {
            return Err(StrictPqPublicCoinV2Error::Magic);
        }
        if reader.u16()? != STRICT_PQ_PUBLIC_COIN_V2_VERSION {
            return Err(StrictPqPublicCoinV2Error::Version);
        }
        if reader.u16()? != 0 {
            return Err(StrictPqPublicCoinV2Error::Flags);
        }
        let context = StrictPqKeyContextV2::decode(reader.take(STRICT_PQ_KEY_CONTEXT_BYTES_V2)?)?;
        let session_id = reader.array::<64>()?;
        let schedule_commitment = reader.array::<64>()?;
        let round_count = reader.u32()?;
        let chain_head = reader.array::<BINDING_V2_BYTES>()?;
        reader.finish()?;
        Self::new(
            context,
            session_id,
            schedule_commitment,
            round_count,
            chain_head,
        )
    }

    pub fn digest(&self) -> Result<BindingDigestV2, StrictPqPublicCoinV2Error> {
        let encoded = self.encode();
        typed_binding_hash(STRICT_PQ_HEAD_MESSAGE_HASH_DOMAIN_V2, &[&encoded])
    }

    pub const fn context(&self) -> &StrictPqKeyContextV2 {
        &self.context
    }

    pub const fn chain_head(&self) -> &[u8; BINDING_V2_BYTES] {
        &self.chain_head
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictPqGovernedVerifierKeyV2 {
    session_id: [u8; 64],
    schedule_commitment: [u8; 64],
    round_count: u32,
    contributors: Vec<StrictPqLamportPublicKeyV2>,
}

impl StrictPqGovernedVerifierKeyV2 {
    pub fn new(
        session_id: [u8; 64],
        schedule_commitment: [u8; 64],
        round_count: u32,
        contributors: Vec<StrictPqLamportPublicKeyV2>,
    ) -> Result<Self, StrictPqPublicCoinV2Error> {
        if !nonzero(&session_id) || !nonzero(&schedule_commitment) {
            return Err(StrictPqPublicCoinV2Error::ZeroIdentifier);
        }
        if round_count == 0 || round_count > STRICT_PQ_H4_MAX_ROUNDS_V2 {
            return Err(StrictPqPublicCoinV2Error::RoundCount);
        }
        if contributors.len() != STRICT_PQ_REQUIRED_CONTRIBUTORS_V2 {
            return Err(StrictPqPublicCoinV2Error::ContributorCount);
        }
        let first = contributors
            .first()
            .ok_or(StrictPqPublicCoinV2Error::ContributorCount)?;
        let mut contributor_ids = BTreeSet::new();
        let mut key_ids = BTreeSet::new();
        let mut roots = BTreeSet::new();
        let mut previous = None;
        for contributor in &contributors {
            if !first
                .context()
                .same_statement_attempt(contributor.context())
            {
                return Err(StrictPqPublicCoinV2Error::ContextMismatch);
            }
            let contributor_id = *contributor.context().contributor_id();
            if previous.is_some_and(|prior| prior >= contributor_id) {
                return Err(StrictPqPublicCoinV2Error::ContributorOrder);
            }
            previous = Some(contributor_id);
            if !contributor_ids.insert(contributor_id) {
                return Err(StrictPqPublicCoinV2Error::DuplicateContributor);
            }
            if !key_ids.insert(*contributor.context().key_id()) {
                return Err(StrictPqPublicCoinV2Error::DuplicateKey);
            }
            if !roots.insert(contributor.root().to_bytes()) {
                return Err(StrictPqPublicCoinV2Error::DuplicateRoot);
            }
        }
        Ok(Self {
            session_id,
            schedule_commitment,
            round_count,
            contributors,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(STRICT_PQ_GOVERNED_KEY_BYTES_V2);
        encoded.extend_from_slice(STRICT_PQ_GOVERNED_KEY_MAGIC_V2);
        encoded.extend_from_slice(&STRICT_PQ_PUBLIC_COIN_V2_VERSION.to_be_bytes());
        encoded.extend_from_slice(&0_u16.to_be_bytes());
        encoded.extend_from_slice(&(self.contributors.len() as u16).to_be_bytes());
        encoded.extend_from_slice(&0_u16.to_be_bytes());
        encoded.extend_from_slice(&self.round_count.to_be_bytes());
        encoded.extend_from_slice(&self.session_id);
        encoded.extend_from_slice(&self.schedule_commitment);
        for contributor in &self.contributors {
            encoded.extend_from_slice(&contributor.encode());
        }
        debug_assert_eq!(encoded.len(), STRICT_PQ_GOVERNED_KEY_BYTES_V2);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, StrictPqPublicCoinV2Error> {
        if encoded.len() != STRICT_PQ_GOVERNED_KEY_BYTES_V2 {
            return Err(StrictPqPublicCoinV2Error::Length);
        }
        let mut reader = Reader::new(encoded);
        if reader.array::<8>()? != *STRICT_PQ_GOVERNED_KEY_MAGIC_V2 {
            return Err(StrictPqPublicCoinV2Error::Magic);
        }
        if reader.u16()? != STRICT_PQ_PUBLIC_COIN_V2_VERSION {
            return Err(StrictPqPublicCoinV2Error::Version);
        }
        if reader.u16()? != 0 {
            return Err(StrictPqPublicCoinV2Error::Flags);
        }
        if usize::from(reader.u16()?) != STRICT_PQ_REQUIRED_CONTRIBUTORS_V2 {
            return Err(StrictPqPublicCoinV2Error::ContributorCount);
        }
        if reader.u16()? != 0 {
            return Err(StrictPqPublicCoinV2Error::Reserved);
        }
        let round_count = reader.u32()?;
        let session_id = reader.array::<64>()?;
        let schedule_commitment = reader.array::<64>()?;
        let mut contributors = Vec::with_capacity(STRICT_PQ_REQUIRED_CONTRIBUTORS_V2);
        for _ in 0..STRICT_PQ_REQUIRED_CONTRIBUTORS_V2 {
            contributors.push(StrictPqLamportPublicKeyV2::decode(
                reader.take(STRICT_PQ_LAMPORT_PUBLIC_KEY_BYTES_V2)?,
            )?);
        }
        reader.finish()?;
        Self::new(session_id, schedule_commitment, round_count, contributors)
    }

    pub const fn session_id(&self) -> &[u8; 64] {
        &self.session_id
    }

    pub const fn schedule_commitment(&self) -> &[u8; 64] {
        &self.schedule_commitment
    }

    pub const fn round_count(&self) -> u32 {
        self.round_count
    }

    pub fn contributors(&self) -> &[StrictPqLamportPublicKeyV2] {
        &self.contributors
    }

    pub fn attempt(&self) -> u8 {
        self.contributors[0].context().attempt()
    }

    pub fn binding(&self) -> Result<BindingDigestV2, StrictPqPublicCoinV2Error> {
        let encoded = self.encode();
        typed_binding_hash(STRICT_PQ_GOVERNED_KEY_BINDING_DOMAIN_V2, &[&encoded])
    }

    fn contributor(&self, contributor_id: &[u8; 64]) -> Option<&StrictPqLamportPublicKeyV2> {
        self.contributors
            .iter()
            .find(|candidate| candidate.context().contributor_id() == contributor_id)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StrictPqRootUseRegistryV2 {
    slots: BTreeMap<[u8; BINDING_V2_BYTES], [u8; BINDING_V2_BYTES]>,
    roots: BTreeSet<[u8; BINDING_V2_BYTES]>,
}

impl StrictPqRootUseRegistryV2 {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reserve_governed_key(
        &mut self,
        governed_key: &StrictPqGovernedVerifierKeyV2,
    ) -> Result<(), StrictPqPublicCoinV2Error> {
        let mut additions = Vec::with_capacity(governed_key.contributors().len());
        for contributor in governed_key.contributors() {
            let slot = contributor.context().slot_id()?;
            let root = contributor.root().to_bytes();
            if self.slots.contains_key(&slot) {
                return Err(StrictPqPublicCoinV2Error::SlotAlreadyUsed);
            }
            if self.roots.contains(&root) {
                return Err(StrictPqPublicCoinV2Error::RootAlreadyUsed);
            }
            additions.push((slot, root));
        }
        for (slot, root) in additions {
            self.slots.insert(slot, root);
            self.roots.insert(root);
        }
        Ok(())
    }

    pub fn reserved_root_count(&self) -> usize {
        self.roots.len()
    }
}

pub struct StrictPqChainV2 {
    head: [u8; BINDING_V2_BYTES],
    reveals: Vec<[u8; BINDING_V2_BYTES]>,
}

impl Drop for StrictPqChainV2 {
    fn drop(&mut self) {
        self.head.zeroize();
        self.reveals.zeroize();
    }
}

impl StrictPqChainV2 {
    pub const fn head(&self) -> &[u8; BINDING_V2_BYTES] {
        &self.head
    }

    pub fn reveals(&self) -> &[[u8; BINDING_V2_BYTES]] {
        &self.reveals
    }
}

pub fn chain_step_v2(
    public_key: &StrictPqLamportPublicKeyV2,
    session_id: &[u8; 64],
    schedule_commitment: &[u8; 64],
    total_rounds: u32,
    round_ordinal: u32,
    next_state: &[u8; BINDING_V2_BYTES],
) -> Result<[u8; BINDING_V2_BYTES], StrictPqPublicCoinV2Error> {
    if total_rounds == 0
        || total_rounds > STRICT_PQ_H4_MAX_ROUNDS_V2
        || round_ordinal >= total_rounds
    {
        return Err(StrictPqPublicCoinV2Error::RoundCount);
    }
    let context = public_key.context().encode();
    let total = total_rounds.to_be_bytes();
    let ordinal = round_ordinal.to_be_bytes();
    Ok(typed_binding_hash(
        STRICT_PQ_CHAIN_STEP_DOMAIN_V2,
        &[
            &context,
            session_id,
            schedule_commitment,
            &total,
            &ordinal,
            next_state,
        ],
    )?
    .to_bytes())
}

pub fn build_chain_from_supplied_tail_v2(
    public_key: &StrictPqLamportPublicKeyV2,
    session_id: &[u8; 64],
    schedule_commitment: &[u8; 64],
    total_rounds: u32,
    mut tail: [u8; BINDING_V2_BYTES],
) -> Result<StrictPqChainV2, StrictPqPublicCoinV2Error> {
    if total_rounds == 0 || total_rounds > STRICT_PQ_H4_MAX_ROUNDS_V2 {
        return Err(StrictPqPublicCoinV2Error::RoundCount);
    }
    let count =
        usize::try_from(total_rounds).map_err(|_| StrictPqPublicCoinV2Error::ArithmeticOverflow)?;
    let mut reveals = vec![[0_u8; BINDING_V2_BYTES]; count];
    reveals[count - 1] = tail;
    tail.zeroize();
    for round in (0..count - 1).rev() {
        reveals[round] = match chain_step_v2(
            public_key,
            session_id,
            schedule_commitment,
            total_rounds,
            u32::try_from(round + 1).map_err(|_| StrictPqPublicCoinV2Error::ArithmeticOverflow)?,
            &reveals[round + 1],
        ) {
            Ok(state) => state,
            Err(error) => {
                reveals.zeroize();
                return Err(error);
            }
        };
    }
    let head = match chain_step_v2(
        public_key,
        session_id,
        schedule_commitment,
        total_rounds,
        0,
        &reveals[0],
    ) {
        Ok(head) => head,
        Err(error) => {
            reveals.zeroize();
            return Err(error);
        }
    };
    Ok(StrictPqChainV2 { head, reveals })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictPqContributorAnchorV2 {
    contributor_id: [u8; 64],
    key_id: [u8; 64],
    chain_head: [u8; BINDING_V2_BYTES],
    signature: StrictPqLamportSignatureV2,
}

impl StrictPqContributorAnchorV2 {
    pub fn encode(&self) -> Result<Vec<u8>, StrictPqPublicCoinV2Error> {
        let signature = self.signature.encode()?;
        let mut encoded = Vec::with_capacity(STRICT_PQ_ANCHOR_BYTES_V2);
        encoded.extend_from_slice(&self.contributor_id);
        encoded.extend_from_slice(&self.key_id);
        encoded.extend_from_slice(&self.chain_head);
        encoded.extend_from_slice(&signature);
        if encoded.len() != STRICT_PQ_ANCHOR_BYTES_V2 {
            return Err(StrictPqPublicCoinV2Error::Length);
        }
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, StrictPqPublicCoinV2Error> {
        if encoded.len() != STRICT_PQ_ANCHOR_BYTES_V2 {
            return Err(StrictPqPublicCoinV2Error::Length);
        }
        let mut reader = Reader::new(encoded);
        let contributor_id = reader.array::<64>()?;
        let key_id = reader.array::<64>()?;
        let chain_head = reader.array::<BINDING_V2_BYTES>()?;
        let signature =
            StrictPqLamportSignatureV2::decode(reader.take(STRICT_PQ_LAMPORT_SIGNATURE_BYTES_V2)?)?;
        reader.finish()?;
        Ok(Self {
            contributor_id,
            key_id,
            chain_head,
            signature,
        })
    }

    pub const fn contributor_id(&self) -> &[u8; 64] {
        &self.contributor_id
    }

    pub const fn key_id(&self) -> &[u8; 64] {
        &self.key_id
    }

    pub const fn chain_head(&self) -> &[u8; BINDING_V2_BYTES] {
        &self.chain_head
    }

    pub const fn signature(&self) -> &StrictPqLamportSignatureV2 {
        &self.signature
    }
}

pub fn sign_chain_head_v2(
    secret_key: StrictPqLamportSecretKeyV2,
    governed_key: &StrictPqGovernedVerifierKeyV2,
    chain_head: [u8; BINDING_V2_BYTES],
) -> Result<StrictPqContributorAnchorV2, StrictPqPublicCoinV2Error> {
    let public_key = governed_key
        .contributor(secret_key.context().contributor_id())
        .ok_or(StrictPqPublicCoinV2Error::ContextMismatch)?;
    if public_key.context() != secret_key.context() {
        return Err(StrictPqPublicCoinV2Error::ContextMismatch);
    }
    let message = StrictPqHeadMessageV2::new(
        public_key.context().clone(),
        *governed_key.session_id(),
        *governed_key.schedule_commitment(),
        governed_key.round_count(),
        chain_head,
    )?;
    let contributor_id = *public_key.context().contributor_id();
    let key_id = *public_key.context().key_id();
    let signature = secret_key.sign(&message)?;
    Ok(StrictPqContributorAnchorV2 {
        contributor_id,
        key_id,
        chain_head,
        signature,
    })
}

fn verify_anchor_v2(
    governed_key: &StrictPqGovernedVerifierKeyV2,
    anchor: &StrictPqContributorAnchorV2,
) -> Result<(), StrictPqPublicCoinV2Error> {
    let public_key = governed_key
        .contributor(anchor.contributor_id())
        .ok_or(StrictPqPublicCoinV2Error::AnchorMismatch)?;
    if public_key.context().key_id() != anchor.key_id() {
        return Err(StrictPqPublicCoinV2Error::AnchorMismatch);
    }
    let message = StrictPqHeadMessageV2::new(
        public_key.context().clone(),
        *governed_key.session_id(),
        *governed_key.schedule_commitment(),
        governed_key.round_count(),
        *anchor.chain_head(),
    )?;
    anchor.signature.verify(public_key, &message)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StrictPqRoundDescriptorV2 {
    kind: u16,
    ordinal: u32,
    output_count: u16,
}

impl StrictPqRoundDescriptorV2 {
    pub fn new(
        kind: u16,
        ordinal: u32,
        output_count: u16,
    ) -> Result<Self, StrictPqPublicCoinV2Error> {
        if kind == 0 || output_count == 0 || output_count > STRICT_PQ_MAX_FP16_OUTPUTS_V2 {
            return Err(StrictPqPublicCoinV2Error::Descriptor);
        }
        Ok(Self {
            kind,
            ordinal,
            output_count,
        })
    }

    pub const fn encode(self) -> [u8; STRICT_PQ_ROUND_DESCRIPTOR_BYTES_V2] {
        let kind = self.kind.to_be_bytes();
        let ordinal = self.ordinal.to_be_bytes();
        let output_count = self.output_count.to_be_bytes();
        [
            kind[0],
            kind[1],
            ordinal[0],
            ordinal[1],
            ordinal[2],
            ordinal[3],
            output_count[0],
            output_count[1],
        ]
    }

    pub fn decode(
        encoded: &[u8; STRICT_PQ_ROUND_DESCRIPTOR_BYTES_V2],
    ) -> Result<Self, StrictPqPublicCoinV2Error> {
        Self::new(
            u16::from_be_bytes([encoded[0], encoded[1]]),
            u32::from_be_bytes([encoded[2], encoded[3], encoded[4], encoded[5]]),
            u16::from_be_bytes([encoded[6], encoded[7]]),
        )
    }

    pub const fn ordinal(self) -> u32 {
        self.ordinal
    }

    pub const fn kind(self) -> u16 {
        self.kind
    }

    pub const fn output_count(self) -> u16 {
        self.output_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StrictPqSampledFp16V2 {
    draw: u16,
    accepted_attempt: u16,
    digest: [u8; 64],
    element: Fp16,
}

impl StrictPqSampledFp16V2 {
    pub const fn draw(self) -> u16 {
        self.draw
    }

    pub const fn accepted_attempt(self) -> u16 {
        self.accepted_attempt
    }

    pub const fn digest(self) -> [u8; 64] {
        self.digest
    }

    pub const fn element(self) -> Fp16 {
        self.element
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictPqFp16ChallengeBatchV2 {
    profile: StrictPqH4ProfileV2,
    policy: StrictPqFp16PolicyV2,
    session_id: [u8; 64],
    attempt: u8,
    round_index: u32,
    descriptor: StrictPqRoundDescriptorV2,
    seed: [u8; BINDING_V2_BYTES],
    samples: Vec<StrictPqSampledFp16V2>,
}

impl StrictPqFp16ChallengeBatchV2 {
    pub const fn profile(&self) -> StrictPqH4ProfileV2 {
        self.profile
    }

    pub const fn policy(&self) -> StrictPqFp16PolicyV2 {
        self.policy
    }

    pub const fn descriptor(&self) -> StrictPqRoundDescriptorV2 {
        self.descriptor
    }

    pub const fn seed(&self) -> &[u8; BINDING_V2_BYTES] {
        &self.seed
    }

    pub fn samples(&self) -> &[StrictPqSampledFp16V2] {
        &self.samples
    }

    pub fn canonical_transcript_bytes(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(
            STRICT_PQ_FP16_TRANSCRIPT_DOMAIN_V2.len()
                + 2
                + 4
                + 4
                + STRICT_PQ_ROUND_DESCRIPTOR_BYTES_V2
                + 64
                + 2
                + BINDING_V2_BYTES
                + 2
                + self.samples.len() * (2 + 2 + 64 + 64),
        );
        encoded.extend_from_slice(STRICT_PQ_FP16_TRANSCRIPT_DOMAIN_V2);
        encoded.extend_from_slice(&STRICT_PQ_PUBLIC_COIN_V2_VERSION.to_be_bytes());
        encoded.extend_from_slice(&[self.profile.code(), self.policy.code(), self.attempt, 0]);
        encoded.extend_from_slice(&self.round_index.to_be_bytes());
        encoded.extend_from_slice(&self.descriptor.encode());
        encoded.extend_from_slice(&self.session_id);
        encoded.extend_from_slice(&(BINDING_V2_BYTES as u16).to_be_bytes());
        encoded.extend_from_slice(&self.seed);
        encoded.extend_from_slice(&(self.samples.len() as u16).to_be_bytes());
        for sample in &self.samples {
            encoded.extend_from_slice(&sample.draw.to_be_bytes());
            encoded.extend_from_slice(&sample.accepted_attempt.to_be_bytes());
            encoded.extend_from_slice(&sample.digest);
            encoded.extend_from_slice(&sample.element.encode());
        }
        encoded
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictPqFp16RoundOutputV2 {
    challenges: StrictPqFp16ChallengeBatchV2,
    transcript_root: [u8; BINDING_V2_BYTES],
}

impl StrictPqFp16RoundOutputV2 {
    pub const fn seed(&self) -> &[u8; BINDING_V2_BYTES] {
        self.challenges.seed()
    }

    pub const fn challenges(&self) -> &StrictPqFp16ChallengeBatchV2 {
        &self.challenges
    }

    pub const fn transcript_root(&self) -> &[u8; BINDING_V2_BYTES] {
        &self.transcript_root
    }
}

pub fn derive_strict_pq_fp16_challenges_v2(
    profile: StrictPqH4ProfileV2,
    policy: StrictPqFp16PolicyV2,
    session_id: &[u8; 64],
    attempt: u8,
    round_index: u32,
    descriptor: StrictPqRoundDescriptorV2,
    seed: &[u8; BINDING_V2_BYTES],
) -> Result<StrictPqFp16ChallengeBatchV2, StrictPqPublicCoinV2Error> {
    if !nonzero(session_id) {
        return Err(StrictPqPublicCoinV2Error::ZeroIdentifier);
    }
    if attempt >= STRICT_PQ_MAX_ATTEMPTS_V2 {
        return Err(StrictPqPublicCoinV2Error::AttemptOutOfRange);
    }
    if descriptor.ordinal() != round_index
        || (policy == StrictPqFp16PolicyV2::OodsOutsideFp8 && descriptor.output_count() != 1)
    {
        return Err(StrictPqPublicCoinV2Error::Descriptor);
    }

    let descriptor_bytes = descriptor.encode();
    let mut samples = Vec::with_capacity(usize::from(descriptor.output_count()));
    for draw in 0..descriptor.output_count() {
        let mut accepted = None;
        for accepted_attempt in 0..STRICT_PQ_FP16_MAX_ATTEMPTS_V2 {
            let mut hash = Sha3_512::new();
            hash.update(STRICT_PQ_FP16_CHALLENGE_DOMAIN_V2);
            hash.update(STRICT_PQ_PUBLIC_COIN_V2_VERSION.to_be_bytes());
            hash.update([profile.code(), policy.code(), attempt, 0]);
            hash.update(session_id);
            hash.update(round_index.to_be_bytes());
            hash.update(descriptor_bytes);
            hash.update(draw.to_be_bytes());
            hash.update(accepted_attempt.to_be_bytes());
            hash.update((BINDING_V2_BYTES as u16).to_be_bytes());
            hash.update(seed);
            let digest: [u8; 64] = hash.finalize().into();
            if !is_accepted(&digest) {
                continue;
            }
            let element = digest_mod_field_order(&digest);
            if !policy.accepts(element) {
                continue;
            }
            accepted = Some(StrictPqSampledFp16V2 {
                draw,
                accepted_attempt,
                digest,
                element,
            });
            break;
        }
        samples.push(
            accepted.ok_or(StrictPqPublicCoinV2Error::ChallengeAttemptCapExhausted { draw })?,
        );
    }
    Ok(StrictPqFp16ChallengeBatchV2 {
        profile,
        policy,
        session_id: *session_id,
        attempt,
        round_index,
        descriptor,
        seed: *seed,
        samples,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictPqRoundEvidenceV2 {
    descriptor: StrictPqRoundDescriptorV2,
    message_binding: [u8; BINDING_V2_BYTES],
    reveals: Vec<[u8; BINDING_V2_BYTES]>,
}

impl StrictPqRoundEvidenceV2 {
    pub const fn descriptor(&self) -> StrictPqRoundDescriptorV2 {
        self.descriptor
    }

    pub const fn message_binding(&self) -> &[u8; BINDING_V2_BYTES] {
        &self.message_binding
    }

    pub fn reveals(&self) -> &[[u8; BINDING_V2_BYTES]] {
        &self.reveals
    }
}

fn prover_message_binding_v2(
    governed_binding: &BindingDigestV2,
    descriptor: StrictPqRoundDescriptorV2,
    raw_message: &[u8],
) -> Result<[u8; BINDING_V2_BYTES], StrictPqPublicCoinV2Error> {
    let descriptor = descriptor.encode();
    Ok(typed_binding_hash(
        STRICT_PQ_PROVER_MESSAGE_DOMAIN_V2,
        &[governed_binding.as_bytes(), &descriptor, raw_message],
    )?
    .to_bytes())
}

fn round_seed_v2(
    governed_binding: &BindingDigestV2,
    prior_transcript_root: &[u8; BINDING_V2_BYTES],
    descriptor: StrictPqRoundDescriptorV2,
    message_binding: &[u8; BINDING_V2_BYTES],
    contributors: &[StrictPqLamportPublicKeyV2],
    reveals: &[[u8; BINDING_V2_BYTES]],
) -> Result<[u8; BINDING_V2_BYTES], StrictPqPublicCoinV2Error> {
    let descriptor = descriptor.encode();
    let mut ordered_reveals = Vec::with_capacity(contributors.len() * (64 + BINDING_V2_BYTES));
    for (contributor, reveal) in contributors.iter().zip(reveals) {
        ordered_reveals.extend_from_slice(contributor.context().contributor_id());
        ordered_reveals.extend_from_slice(reveal);
    }
    Ok(typed_binding_hash(
        STRICT_PQ_ROUND_SEED_DOMAIN_V2,
        &[
            governed_binding.as_bytes(),
            prior_transcript_root,
            &descriptor,
            message_binding,
            &ordered_reveals,
        ],
    )?
    .to_bytes())
}

fn next_transcript_root_v2(
    governed_binding: &BindingDigestV2,
    prior_transcript_root: &[u8; BINDING_V2_BYTES],
    descriptor: StrictPqRoundDescriptorV2,
    message_binding: &[u8; BINDING_V2_BYTES],
    round_seed: &[u8; BINDING_V2_BYTES],
    reveals: &[[u8; BINDING_V2_BYTES]],
    fp16_transcript: Option<&[u8]>,
) -> Result<[u8; BINDING_V2_BYTES], StrictPqPublicCoinV2Error> {
    let descriptor = descriptor.encode();
    let mut reveal_bytes = Vec::with_capacity(reveals.len() * BINDING_V2_BYTES);
    for reveal in reveals {
        reveal_bytes.extend_from_slice(reveal);
    }
    let base_parts: [&[u8]; 6] = [
        governed_binding.as_bytes(),
        prior_transcript_root,
        &descriptor,
        message_binding,
        round_seed,
        &reveal_bytes,
    ];
    let digest = if let Some(fp16_transcript) = fp16_transcript {
        typed_binding_hash(
            STRICT_PQ_TRANSCRIPT_ROOT_DOMAIN_V2,
            &[
                base_parts[0],
                base_parts[1],
                base_parts[2],
                base_parts[3],
                base_parts[4],
                base_parts[5],
                fp16_transcript,
            ],
        )?
    } else {
        typed_binding_hash(STRICT_PQ_TRANSCRIPT_ROOT_DOMAIN_V2, &base_parts)?
    };
    Ok(digest.to_bytes())
}

fn initial_transcript_root_v2(
    governed_key: &StrictPqGovernedVerifierKeyV2,
    anchors: &[StrictPqContributorAnchorV2],
) -> Result<[u8; BINDING_V2_BYTES], StrictPqPublicCoinV2Error> {
    let governed = governed_key.encode();
    let mut anchor_bytes =
        Vec::with_capacity(anchors.len().saturating_mul(STRICT_PQ_ANCHOR_BYTES_V2));
    for anchor in anchors {
        anchor_bytes.extend_from_slice(&anchor.encode()?);
    }
    Ok(typed_binding_hash(
        STRICT_PQ_INITIAL_TRANSCRIPT_DOMAIN_V2,
        &[&governed, &anchor_bytes],
    )?
    .to_bytes())
}

pub fn strict_pq_candidate_bundle_len_v2(
    contributor_count: usize,
    round_count: u32,
) -> Result<usize, StrictPqPublicCoinV2Error> {
    if contributor_count == 0 || contributor_count > STRICT_PQ_GENERIC_MAX_CONTRIBUTORS_V2 {
        return Err(StrictPqPublicCoinV2Error::ContributorCount);
    }
    if round_count == 0 || round_count > STRICT_PQ_GENERIC_MAX_ROUNDS_V2 {
        return Err(StrictPqPublicCoinV2Error::RoundCount);
    }
    let anchors = contributor_count
        .checked_mul(STRICT_PQ_ANCHOR_BYTES_V2)
        .ok_or(StrictPqPublicCoinV2Error::ArithmeticOverflow)?;
    let per_round = STRICT_PQ_ROUND_DESCRIPTOR_BYTES_V2
        .checked_add(BINDING_V2_BYTES)
        .and_then(|value| {
            contributor_count
                .checked_mul(BINDING_V2_BYTES)
                .and_then(|reveals| value.checked_add(reveals))
        })
        .ok_or(StrictPqPublicCoinV2Error::ArithmeticOverflow)?;
    STRICT_PQ_BUNDLE_HEADER_BYTES_V2
        .checked_add(anchors)
        .and_then(|value| {
            usize::try_from(round_count)
                .ok()
                .and_then(|rounds| rounds.checked_mul(per_round))
                .and_then(|rounds| value.checked_add(rounds))
        })
        .ok_or(StrictPqPublicCoinV2Error::ArithmeticOverflow)
}

pub fn strict_pq_bounded_bundle_len_v2(
    contributor_count: usize,
    round_count: u32,
) -> Result<usize, StrictPqPublicCoinV2Error> {
    let length = strict_pq_candidate_bundle_len_v2(contributor_count, round_count)?;
    if length > STRICT_PQ_MAX_BUNDLE_BYTES_V2 {
        return Err(StrictPqPublicCoinV2Error::BundleTooLarge);
    }
    Ok(length)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictPqPublicCoinBundleV2 {
    session_id: [u8; 64],
    schedule_commitment: [u8; 64],
    attempt: u8,
    anchors: Vec<StrictPqContributorAnchorV2>,
    rounds: Vec<StrictPqRoundEvidenceV2>,
    final_transcript_root: [u8; BINDING_V2_BYTES],
}

impl StrictPqPublicCoinBundleV2 {
    pub fn encode(&self) -> Result<Vec<u8>, StrictPqPublicCoinV2Error> {
        let contributor_count = self.anchors.len();
        let round_count = u32::try_from(self.rounds.len())
            .map_err(|_| StrictPqPublicCoinV2Error::ArithmeticOverflow)?;
        let exact_len = strict_pq_bounded_bundle_len_v2(contributor_count, round_count)?;
        if self.attempt >= STRICT_PQ_MAX_ATTEMPTS_V2 {
            return Err(StrictPqPublicCoinV2Error::AttemptOutOfRange);
        }
        let mut encoded = Vec::with_capacity(exact_len);
        encoded.extend_from_slice(STRICT_PQ_BUNDLE_MAGIC_V2);
        encoded.extend_from_slice(&STRICT_PQ_PUBLIC_COIN_V2_VERSION.to_be_bytes());
        encoded.extend_from_slice(&0_u16.to_be_bytes());
        encoded.extend_from_slice(&(STRICT_PQ_BUNDLE_HEADER_BYTES_V2 as u32).to_be_bytes());
        encoded.extend_from_slice(&(exact_len as u64).to_be_bytes());
        encoded.extend_from_slice(&(contributor_count as u16).to_be_bytes());
        encoded.push(self.attempt);
        encoded.push(0);
        encoded.extend_from_slice(&round_count.to_be_bytes());
        encoded.extend_from_slice(&self.session_id);
        encoded.extend_from_slice(&self.schedule_commitment);
        encoded.extend_from_slice(&self.final_transcript_root);
        for anchor in &self.anchors {
            encoded.extend_from_slice(&anchor.encode()?);
        }
        for round in &self.rounds {
            if round.reveals.len() != contributor_count {
                return Err(StrictPqPublicCoinV2Error::ContributorCount);
            }
            encoded.extend_from_slice(&round.descriptor.encode());
            encoded.extend_from_slice(&round.message_binding);
            for reveal in &round.reveals {
                encoded.extend_from_slice(reveal);
            }
        }
        if encoded.len() != exact_len {
            return Err(StrictPqPublicCoinV2Error::BundleLength);
        }
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, StrictPqPublicCoinV2Error> {
        if encoded.len() < STRICT_PQ_BUNDLE_HEADER_BYTES_V2
            || encoded.len() > STRICT_PQ_MAX_BUNDLE_BYTES_V2
        {
            return Err(StrictPqPublicCoinV2Error::BundleLength);
        }
        let mut reader = Reader::new(encoded);
        if reader.array::<8>()? != *STRICT_PQ_BUNDLE_MAGIC_V2 {
            return Err(StrictPqPublicCoinV2Error::Magic);
        }
        if reader.u16()? != STRICT_PQ_PUBLIC_COIN_V2_VERSION {
            return Err(StrictPqPublicCoinV2Error::Version);
        }
        if reader.u16()? != 0 {
            return Err(StrictPqPublicCoinV2Error::Flags);
        }
        if reader.u32()? as usize != STRICT_PQ_BUNDLE_HEADER_BYTES_V2 {
            return Err(StrictPqPublicCoinV2Error::BundleLength);
        }
        let declared_len = usize::try_from(reader.u64()?)
            .map_err(|_| StrictPqPublicCoinV2Error::ArithmeticOverflow)?;
        let contributor_count = usize::from(reader.u16()?);
        let attempt = reader.u8()?;
        if reader.u8()? != 0 {
            return Err(StrictPqPublicCoinV2Error::Reserved);
        }
        let round_count = reader.u32()?;
        if attempt >= STRICT_PQ_MAX_ATTEMPTS_V2 {
            return Err(StrictPqPublicCoinV2Error::AttemptOutOfRange);
        }
        let exact_len = strict_pq_bounded_bundle_len_v2(contributor_count, round_count)?;
        if declared_len != exact_len || encoded.len() != exact_len {
            return Err(StrictPqPublicCoinV2Error::BundleLength);
        }
        let session_id = reader.array::<64>()?;
        let schedule_commitment = reader.array::<64>()?;
        if !nonzero(&session_id) || !nonzero(&schedule_commitment) {
            return Err(StrictPqPublicCoinV2Error::ZeroIdentifier);
        }
        let final_transcript_root = reader.array::<BINDING_V2_BYTES>()?;

        let mut anchors = Vec::with_capacity(contributor_count);
        let mut previous = None;
        let mut key_ids = BTreeSet::new();
        for _ in 0..contributor_count {
            let anchor =
                StrictPqContributorAnchorV2::decode(reader.take(STRICT_PQ_ANCHOR_BYTES_V2)?)?;
            if previous.is_some_and(|prior| prior >= *anchor.contributor_id()) {
                return Err(StrictPqPublicCoinV2Error::ContributorOrder);
            }
            previous = Some(*anchor.contributor_id());
            if !key_ids.insert(*anchor.key_id()) {
                return Err(StrictPqPublicCoinV2Error::DuplicateKey);
            }
            anchors.push(anchor);
        }

        let round_capacity = usize::try_from(round_count)
            .map_err(|_| StrictPqPublicCoinV2Error::ArithmeticOverflow)?;
        let mut rounds = Vec::with_capacity(round_capacity);
        for ordinal in 0..round_count {
            let descriptor = StrictPqRoundDescriptorV2::decode(
                &reader.array::<STRICT_PQ_ROUND_DESCRIPTOR_BYTES_V2>()?,
            )?;
            if descriptor.ordinal() != ordinal {
                return Err(StrictPqPublicCoinV2Error::Descriptor);
            }
            let message_binding = reader.array::<BINDING_V2_BYTES>()?;
            let mut reveals = Vec::with_capacity(contributor_count);
            for _ in 0..contributor_count {
                reveals.push(reader.array::<BINDING_V2_BYTES>()?);
            }
            rounds.push(StrictPqRoundEvidenceV2 {
                descriptor,
                message_binding,
                reveals,
            });
        }
        reader.finish()?;
        Ok(Self {
            session_id,
            schedule_commitment,
            attempt,
            anchors,
            rounds,
            final_transcript_root,
        })
    }

    pub fn anchors(&self) -> &[StrictPqContributorAnchorV2] {
        &self.anchors
    }

    pub const fn session_id(&self) -> &[u8; 64] {
        &self.session_id
    }

    pub const fn schedule_commitment(&self) -> &[u8; 64] {
        &self.schedule_commitment
    }

    pub const fn attempt(&self) -> u8 {
        self.attempt
    }

    pub fn rounds(&self) -> &[StrictPqRoundEvidenceV2] {
        &self.rounds
    }

    pub const fn final_transcript_root(&self) -> &[u8; BINDING_V2_BYTES] {
        &self.final_transcript_root
    }
}

pub struct StrictPqTranscriptBuilderV2 {
    governed_key: StrictPqGovernedVerifierKeyV2,
    governed_binding: BindingDigestV2,
    anchors: Vec<StrictPqContributorAnchorV2>,
    rounds: Vec<StrictPqRoundEvidenceV2>,
    current_heads: Vec<[u8; BINDING_V2_BYTES]>,
    transcript_root: [u8; BINDING_V2_BYTES],
}

struct StrictPqPreparedRoundV2 {
    ordinal: u32,
    next_heads: Vec<[u8; BINDING_V2_BYTES]>,
    message_binding: [u8; BINDING_V2_BYTES],
    seed: [u8; BINDING_V2_BYTES],
    reveals: Vec<[u8; BINDING_V2_BYTES]>,
}

impl StrictPqTranscriptBuilderV2 {
    pub fn start(
        governed_key: &StrictPqGovernedVerifierKeyV2,
        anchors: Vec<StrictPqContributorAnchorV2>,
        registry: &mut StrictPqRootUseRegistryV2,
    ) -> Result<Self, StrictPqPublicCoinV2Error> {
        if anchors.len() != STRICT_PQ_REQUIRED_CONTRIBUTORS_V2 {
            return Err(StrictPqPublicCoinV2Error::ContributorCount);
        }
        for (public_key, anchor) in governed_key.contributors().iter().zip(&anchors) {
            if public_key.context().contributor_id() != anchor.contributor_id()
                || public_key.context().key_id() != anchor.key_id()
            {
                return Err(StrictPqPublicCoinV2Error::AnchorMismatch);
            }
            verify_anchor_v2(governed_key, anchor)?;
        }
        let transcript_root = initial_transcript_root_v2(governed_key, &anchors)?;
        let governed_binding = governed_key.binding()?;
        registry.reserve_governed_key(governed_key)?;
        let current_heads = anchors.iter().map(|anchor| *anchor.chain_head()).collect();
        Ok(Self {
            governed_key: governed_key.clone(),
            governed_binding,
            anchors,
            rounds: Vec::with_capacity(governed_key.round_count() as usize),
            current_heads,
            transcript_root,
        })
    }

    fn prepare_round(
        &self,
        descriptor: StrictPqRoundDescriptorV2,
        raw_prover_message: &[u8],
        reveals: Vec<[u8; BINDING_V2_BYTES]>,
    ) -> Result<StrictPqPreparedRoundV2, StrictPqPublicCoinV2Error> {
        let ordinal = u32::try_from(self.rounds.len())
            .map_err(|_| StrictPqPublicCoinV2Error::ArithmeticOverflow)?;
        if ordinal >= self.governed_key.round_count() || descriptor.ordinal() != ordinal {
            return Err(StrictPqPublicCoinV2Error::Descriptor);
        }
        if reveals.len() != STRICT_PQ_REQUIRED_CONTRIBUTORS_V2 {
            return Err(StrictPqPublicCoinV2Error::ContributorCount);
        }
        let mut next_heads = Vec::with_capacity(STRICT_PQ_REQUIRED_CONTRIBUTORS_V2);
        for ((public_key, current), reveal) in self
            .governed_key
            .contributors()
            .iter()
            .zip(&self.current_heads)
            .zip(&reveals)
        {
            let expected = chain_step_v2(
                public_key,
                self.governed_key.session_id(),
                self.governed_key.schedule_commitment(),
                self.governed_key.round_count(),
                ordinal,
                reveal,
            )?;
            if &expected != current {
                return Err(StrictPqPublicCoinV2Error::ChainMismatch);
            }
            next_heads.push(*reveal);
        }
        let message_binding =
            prover_message_binding_v2(&self.governed_binding, descriptor, raw_prover_message)?;
        let seed = round_seed_v2(
            &self.governed_binding,
            &self.transcript_root,
            descriptor,
            &message_binding,
            self.governed_key.contributors(),
            &reveals,
        )?;
        Ok(StrictPqPreparedRoundV2 {
            ordinal,
            next_heads,
            message_binding,
            seed,
            reveals,
        })
    }

    fn commit_prepared_round(
        &mut self,
        descriptor: StrictPqRoundDescriptorV2,
        prepared: StrictPqPreparedRoundV2,
        transcript_root: [u8; BINDING_V2_BYTES],
    ) {
        self.current_heads = prepared.next_heads;
        self.transcript_root = transcript_root;
        self.rounds.push(StrictPqRoundEvidenceV2 {
            descriptor,
            message_binding: prepared.message_binding,
            reveals: prepared.reveals,
        });
    }

    pub fn absorb_round(
        &mut self,
        descriptor: StrictPqRoundDescriptorV2,
        raw_prover_message: &[u8],
        reveals: Vec<[u8; BINDING_V2_BYTES]>,
    ) -> Result<[u8; BINDING_V2_BYTES], StrictPqPublicCoinV2Error> {
        let prepared = self.prepare_round(descriptor, raw_prover_message, reveals)?;
        let transcript_root = next_transcript_root_v2(
            &self.governed_binding,
            &self.transcript_root,
            descriptor,
            &prepared.message_binding,
            &prepared.seed,
            &prepared.reveals,
            None,
        )?;
        let seed = prepared.seed;
        self.commit_prepared_round(descriptor, prepared, transcript_root);
        Ok(seed)
    }

    pub fn absorb_fp16_round(
        &mut self,
        profile: StrictPqH4ProfileV2,
        policy: StrictPqFp16PolicyV2,
        descriptor: StrictPqRoundDescriptorV2,
        raw_prover_message: &[u8],
        reveals: Vec<[u8; BINDING_V2_BYTES]>,
    ) -> Result<StrictPqFp16RoundOutputV2, StrictPqPublicCoinV2Error> {
        let prepared = self.prepare_round(descriptor, raw_prover_message, reveals)?;
        let challenges = derive_strict_pq_fp16_challenges_v2(
            profile,
            policy,
            self.governed_key.session_id(),
            self.governed_key.attempt(),
            prepared.ordinal,
            descriptor,
            &prepared.seed,
        )?;
        let transcript_bytes = challenges.canonical_transcript_bytes();
        let transcript_root = next_transcript_root_v2(
            &self.governed_binding,
            &self.transcript_root,
            descriptor,
            &prepared.message_binding,
            &prepared.seed,
            &prepared.reveals,
            Some(&transcript_bytes),
        )?;
        self.commit_prepared_round(descriptor, prepared, transcript_root);
        Ok(StrictPqFp16RoundOutputV2 {
            challenges,
            transcript_root,
        })
    }

    pub fn finish(self) -> Result<StrictPqPublicCoinBundleV2, StrictPqPublicCoinV2Error> {
        if self.rounds.len() != self.governed_key.round_count() as usize {
            return Err(StrictPqPublicCoinV2Error::RoundCount);
        }
        let bundle = StrictPqPublicCoinBundleV2 {
            session_id: *self.governed_key.session_id(),
            schedule_commitment: *self.governed_key.schedule_commitment(),
            attempt: self.governed_key.attempt(),
            anchors: self.anchors,
            rounds: self.rounds,
            final_transcript_root: self.transcript_root,
        };
        bundle.encode()?;
        Ok(bundle)
    }
}

pub fn replay_strict_pq_public_coin_v2<M: AsRef<[u8]>>(
    governed_key: &StrictPqGovernedVerifierKeyV2,
    bundle: &StrictPqPublicCoinBundleV2,
    raw_prover_messages: &[M],
    registry: &mut StrictPqRootUseRegistryV2,
) -> Result<Vec<[u8; BINDING_V2_BYTES]>, StrictPqPublicCoinV2Error> {
    if &bundle.session_id != governed_key.session_id() {
        return Err(StrictPqPublicCoinV2Error::SessionMismatch);
    }
    if &bundle.schedule_commitment != governed_key.schedule_commitment() {
        return Err(StrictPqPublicCoinV2Error::ScheduleMismatch);
    }
    if bundle.attempt != governed_key.attempt() {
        return Err(StrictPqPublicCoinV2Error::AttemptMismatch);
    }
    if bundle.rounds.len() != governed_key.round_count() as usize {
        return Err(StrictPqPublicCoinV2Error::RoundCount);
    }
    if raw_prover_messages.len() != bundle.rounds.len() {
        return Err(StrictPqPublicCoinV2Error::RawMessageCount);
    }
    let mut builder =
        StrictPqTranscriptBuilderV2::start(governed_key, bundle.anchors.clone(), registry)?;
    let mut seeds = Vec::with_capacity(bundle.rounds.len());
    for (round, raw_message) in bundle.rounds.iter().zip(raw_prover_messages) {
        let seed = builder.absorb_round(
            round.descriptor,
            raw_message.as_ref(),
            round.reveals.clone(),
        )?;
        let rebuilt = builder
            .rounds
            .last()
            .ok_or(StrictPqPublicCoinV2Error::RoundMismatch)?;
        if rebuilt.message_binding != round.message_binding {
            return Err(StrictPqPublicCoinV2Error::RoundMismatch);
        }
        seeds.push(seed);
    }
    let rebuilt = builder.finish()?;
    if rebuilt != *bundle {
        return Err(StrictPqPublicCoinV2Error::TranscriptMismatch);
    }
    Ok(seeds)
}

pub fn replay_strict_pq_fp16_public_coin_v2<M: AsRef<[u8]>>(
    governed_key: &StrictPqGovernedVerifierKeyV2,
    bundle: &StrictPqPublicCoinBundleV2,
    profile: StrictPqH4ProfileV2,
    policies: &[StrictPqFp16PolicyV2],
    raw_prover_messages: &[M],
    registry: &mut StrictPqRootUseRegistryV2,
) -> Result<Vec<StrictPqFp16RoundOutputV2>, StrictPqPublicCoinV2Error> {
    if &bundle.session_id != governed_key.session_id() {
        return Err(StrictPqPublicCoinV2Error::SessionMismatch);
    }
    if &bundle.schedule_commitment != governed_key.schedule_commitment() {
        return Err(StrictPqPublicCoinV2Error::ScheduleMismatch);
    }
    if bundle.attempt != governed_key.attempt() {
        return Err(StrictPqPublicCoinV2Error::AttemptMismatch);
    }
    if bundle.rounds.len() != governed_key.round_count() as usize {
        return Err(StrictPqPublicCoinV2Error::RoundCount);
    }
    if raw_prover_messages.len() != bundle.rounds.len() {
        return Err(StrictPqPublicCoinV2Error::RawMessageCount);
    }
    if policies.len() != bundle.rounds.len() {
        return Err(StrictPqPublicCoinV2Error::ChallengePolicyCount);
    }
    let mut builder =
        StrictPqTranscriptBuilderV2::start(governed_key, bundle.anchors.clone(), registry)?;
    let mut outputs = Vec::with_capacity(bundle.rounds.len());
    for ((round, raw_message), policy) in
        bundle.rounds.iter().zip(raw_prover_messages).zip(policies)
    {
        let output = builder.absorb_fp16_round(
            profile,
            *policy,
            round.descriptor,
            raw_message.as_ref(),
            round.reveals.clone(),
        )?;
        let rebuilt = builder
            .rounds
            .last()
            .ok_or(StrictPqPublicCoinV2Error::RoundMismatch)?;
        if rebuilt.message_binding != round.message_binding {
            return Err(StrictPqPublicCoinV2Error::RoundMismatch);
        }
        outputs.push(output);
    }
    let rebuilt = builder.finish()?;
    if rebuilt != *bundle {
        return Err(StrictPqPublicCoinV2Error::TranscriptMismatch);
    }
    Ok(outputs)
}

struct Reader<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(encoded: &'a [u8]) -> Self {
        Self { encoded, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], StrictPqPublicCoinV2Error> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(StrictPqPublicCoinV2Error::ArithmeticOverflow)?;
        let value = self
            .encoded
            .get(self.offset..end)
            .ok_or(StrictPqPublicCoinV2Error::Length)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], StrictPqPublicCoinV2Error> {
        self.take(N)?
            .try_into()
            .map_err(|_| StrictPqPublicCoinV2Error::Length)
    }

    fn u8(&mut self) -> Result<u8, StrictPqPublicCoinV2Error> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, StrictPqPublicCoinV2Error> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    fn u32(&mut self) -> Result<u32, StrictPqPublicCoinV2Error> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, StrictPqPublicCoinV2Error> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }

    fn finish(&self) -> Result<(), StrictPqPublicCoinV2Error> {
        if self.offset != self.encoded.len() {
            return Err(StrictPqPublicCoinV2Error::Length);
        }
        Ok(())
    }
}
