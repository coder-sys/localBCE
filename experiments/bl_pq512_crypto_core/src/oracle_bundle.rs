//! Throughput-optimal oracle execution commitment with a linked audit tree.
//!
//! Each claim bundle has one exact 2,133-byte encoding. Authorization tokens
//! use the bijection between the canonical token language and `37^64` ranks,
//! giving a fixed 42-byte encoding without lossy compression. Execution hashes
//! are parallel per bundle; the ordered leaf vector is hashed once. The binary
//! audit tree reuses those exact leaf digests.

use core::fmt;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use sha3::{Digest, Sha3_512};

use crate::sha3_air::{
    KECCAK_ROUNDS, Sha3TraceError, for_each_sha3_512_trace_row, sha3_512_reference,
};

pub const AUTHORIZATIONS_PER_CLAIM: usize = 50;
pub const TOKEN_ENCODED_BYTES: usize = 42;
pub const AUTHORIZATION_FLAGS_BYTES: usize = 19;
pub const BUNDLE_BYTES: usize = 2_133;
pub const DIGEST_BYTES: usize = 64;
pub const RATE_BYTES: usize = 72;
pub const MAX_ORACLE_SLOTS: usize = 512;

const SCHEDULE_DOMAIN: &[u8] = b"BL/PQ512/WAVE1A/ORACLE-SHA3-SCHEDULE/v1\0";

const BUNDLE_MAGIC: &[u8; 8] = b"BLPQORB1";
const EXECUTION_ROOT_MAGIC: &[u8; 8] = b"BLPQOXR1";
const AUDIT_NODE_MAGIC: &[u8; 8] = b"BLPQOAN1";
const AUDIT_ROOT_MAGIC: &[u8; 8] = b"BLPQOAR1";
const FIRST_ALPHABET: &[u8; 36] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const TAIL_ALPHABET: &[u8; 37] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-";
const TOKEN_RADIX: u16 = 37;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OracleProfile {
    K128,
    K256,
    K512,
}

impl OracleProfile {
    pub const fn code(self) -> u8 {
        match self {
            Self::K128 => 1,
            Self::K256 => 2,
            Self::K512 => 3,
        }
    }

    pub const fn claim_slots(self) -> usize {
        match self {
            Self::K128 => 128,
            Self::K256 => 256,
            Self::K512 => 512,
        }
    }

    pub const fn tree_depth(self) -> usize {
        match self {
            Self::K128 => 7,
            Self::K256 => 8,
            Self::K512 => 9,
        }
    }

    fn from_code(code: u8) -> Result<Self, OracleBundleError> {
        match code {
            1 => Ok(Self::K128),
            2 => Ok(Self::K256),
            3 => Ok(Self::K512),
            _ => Err(OracleBundleError::UnknownProfile),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OracleFacts {
    pub eligibility_active: bool,
    pub provider_enrolled: bool,
    pub provider_not_suspended: bool,
    pub not_deceased: bool,
    pub duplicate_claim: bool,
    pub program_integrity_hold: bool,
}

impl OracleFacts {
    const fn is_zero(self) -> bool {
        !self.eligibility_active
            && !self.provider_enrolled
            && !self.provider_not_suspended
            && !self.not_deceased
            && !self.duplicate_claim
            && !self.program_integrity_hold
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleAuthorization {
    pub line_enabled: bool,
    pub required: bool,
    pub present: bool,
    pub token: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleBundle {
    pub profile: OracleProfile,
    pub slot_index: u32,
    pub slot_is_real: bool,
    pub facts: OracleFacts,
    pub authorizations: Vec<OracleAuthorization>,
}

impl OracleBundle {
    pub fn validate(&self) -> Result<(), OracleBundleError> {
        if usize::try_from(self.slot_index).map_err(|_| OracleBundleError::SlotIndex)?
            >= self.profile.claim_slots()
        {
            return Err(OracleBundleError::SlotIndex);
        }
        if self.authorizations.len() != AUTHORIZATIONS_PER_CLAIM {
            return Err(OracleBundleError::AuthorizationCount);
        }
        for authorization in &self.authorizations {
            encode_authorization_token(&authorization.token)?;
            if !authorization.line_enabled
                && (authorization.required
                    || authorization.present
                    || !authorization.token.is_empty())
            {
                return Err(OracleBundleError::DisabledAuthorizationNotZero);
            }
            if authorization.present && authorization.token.is_empty() {
                return Err(OracleBundleError::PresentTokenMissing);
            }
        }
        if !self.slot_is_real {
            if !self.facts.is_zero() {
                return Err(OracleBundleError::CoverFactsNotZero);
            }
            if self.authorizations.iter().any(|value| {
                value.line_enabled || value.required || value.present || !value.token.is_empty()
            }) {
                return Err(OracleBundleError::CoverAuthorizationNotZero);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OracleBundleError {
    TokenNotAscii,
    TokenNotCanonical,
    TokenRankNoncanonical,
    BundleLength,
    BundleMagic,
    UnknownProfile,
    SlotIndex,
    FactFlagsNoncanonical,
    AuthorizationFlagsNoncanonical,
    AuthorizationCount,
    DisabledAuthorizationNotZero,
    PresentTokenMissing,
    CoverFactsNotZero,
    CoverAuthorizationNotZero,
    BundleCount,
    BundleOrder,
    AuditSiblingCount,
    AuditSiblingLength,
    AuditRootMismatch,
    Trace(Sha3TraceError),
    CountOverflow,
    ExpectedExecutionRootInvalid,
}

impl fmt::Display for OracleBundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "oracle bundle error: {self:?}")
    }
}

impl core::error::Error for OracleBundleError {}

fn alphabet_index(alphabet: &[u8], value: u8) -> Option<u8> {
    alphabet
        .iter()
        .position(|candidate| *candidate == value)
        .and_then(|index| u8::try_from(index).ok())
}

fn multiply_add_rank(rank: &mut [u8; TOKEN_ENCODED_BYTES], add: u8) -> bool {
    let mut carry = u16::from(add);
    for value in rank.iter_mut().rev() {
        let next = u16::from(*value) * TOKEN_RADIX + carry;
        *value = next as u8;
        carry = next >> 8;
    }
    carry == 0
}

pub fn encode_authorization_token(
    token: &str,
) -> Result<[u8; TOKEN_ENCODED_BYTES], OracleBundleError> {
    if !token.is_ascii() {
        return Err(OracleBundleError::TokenNotAscii);
    }
    let raw = token.as_bytes();
    if raw.len() > 64 {
        return Err(OracleBundleError::TokenNotCanonical);
    }
    let mut rank = [0_u8; TOKEN_ENCODED_BYTES];
    if raw.is_empty() {
        return Ok(rank);
    }
    for (index, value) in raw.iter().enumerate() {
        let digit = if index == 0 {
            alphabet_index(FIRST_ALPHABET, *value)
                .map(|value| value + 1)
                .ok_or(OracleBundleError::TokenNotCanonical)?
        } else {
            alphabet_index(TAIL_ALPHABET, *value).ok_or(OracleBundleError::TokenNotCanonical)?
        };
        if !multiply_add_rank(&mut rank, digit) {
            return Err(OracleBundleError::TokenRankNoncanonical);
        }
    }
    Ok(rank)
}

fn divide_rank(rank: &mut [u8; TOKEN_ENCODED_BYTES]) -> u8 {
    let mut remainder = 0_u16;
    for value in rank {
        let combined = (remainder << 8) | u16::from(*value);
        *value = (combined / TOKEN_RADIX) as u8;
        remainder = combined % TOKEN_RADIX;
    }
    remainder as u8
}

pub fn decode_authorization_token(
    encoded: [u8; TOKEN_ENCODED_BYTES],
) -> Result<String, OracleBundleError> {
    if encoded.iter().all(|value| *value == 0) {
        return Ok(String::new());
    }
    let mut rank = encoded;
    let mut reversed = Vec::with_capacity(64);
    while rank.iter().any(|value| *value != 0) {
        if reversed.len() == 64 {
            return Err(OracleBundleError::TokenRankNoncanonical);
        }
        reversed.push(divide_rank(&mut rank));
    }
    let first = *reversed
        .last()
        .ok_or(OracleBundleError::TokenRankNoncanonical)?;
    if !(1..=36).contains(&first) {
        return Err(OracleBundleError::TokenRankNoncanonical);
    }
    let mut raw = Vec::with_capacity(reversed.len());
    raw.push(FIRST_ALPHABET[usize::from(first - 1)]);
    for digit in reversed[..reversed.len() - 1].iter().rev() {
        raw.push(TAIL_ALPHABET[usize::from(*digit)]);
    }
    let token = String::from_utf8(raw).map_err(|_| OracleBundleError::TokenNotAscii)?;
    if encode_authorization_token(&token)? != encoded {
        return Err(OracleBundleError::TokenRankNoncanonical);
    }
    Ok(token)
}

pub fn encode_oracle_bundle(bundle: &OracleBundle) -> Result<Vec<u8>, OracleBundleError> {
    bundle.validate()?;
    let mut fact_flags = u8::from(bundle.slot_is_real);
    fact_flags |= u8::from(bundle.facts.eligibility_active) << 1;
    fact_flags |= u8::from(bundle.facts.provider_enrolled) << 2;
    fact_flags |= u8::from(bundle.facts.provider_not_suspended) << 3;
    fact_flags |= u8::from(bundle.facts.not_deceased) << 4;
    fact_flags |= u8::from(bundle.facts.duplicate_claim) << 5;
    fact_flags |= u8::from(bundle.facts.program_integrity_hold) << 6;

    let mut authorization_flags = [0_u8; AUTHORIZATION_FLAGS_BYTES];
    for (index, authorization) in bundle.authorizations.iter().enumerate() {
        for (offset, enabled) in [
            authorization.line_enabled,
            authorization.required,
            authorization.present,
        ]
        .iter()
        .enumerate()
        {
            if *enabled {
                let bit = 3 * index + offset;
                authorization_flags[bit / 8] |= 1 << (bit % 8);
            }
        }
    }

    let mut out = Vec::with_capacity(BUNDLE_BYTES);
    out.extend_from_slice(BUNDLE_MAGIC);
    out.push(bundle.profile.code());
    out.extend_from_slice(&bundle.slot_index.to_be_bytes());
    out.push(fact_flags);
    out.extend_from_slice(&authorization_flags);
    for authorization in &bundle.authorizations {
        out.extend_from_slice(&encode_authorization_token(&authorization.token)?);
    }
    if out.len() != BUNDLE_BYTES {
        return Err(OracleBundleError::BundleLength);
    }
    Ok(out)
}

pub fn decode_oracle_bundle(encoded: &[u8]) -> Result<OracleBundle, OracleBundleError> {
    if encoded.len() != BUNDLE_BYTES {
        return Err(OracleBundleError::BundleLength);
    }
    if &encoded[..8] != BUNDLE_MAGIC {
        return Err(OracleBundleError::BundleMagic);
    }
    let profile = OracleProfile::from_code(encoded[8])?;
    let slot_index = u32::from_be_bytes(
        encoded[9..13]
            .try_into()
            .map_err(|_| OracleBundleError::BundleLength)?,
    );
    let fact_flags = encoded[13];
    if fact_flags & 0x80 != 0 {
        return Err(OracleBundleError::FactFlagsNoncanonical);
    }
    let authorization_flags = &encoded[14..14 + AUTHORIZATION_FLAGS_BYTES];
    if authorization_flags[AUTHORIZATION_FLAGS_BYTES - 1] & 0xc0 != 0 {
        return Err(OracleBundleError::AuthorizationFlagsNoncanonical);
    }
    let mut cursor = 14 + AUTHORIZATION_FLAGS_BYTES;
    let mut authorizations = Vec::with_capacity(AUTHORIZATIONS_PER_CLAIM);
    for index in 0..AUTHORIZATIONS_PER_CLAIM {
        let token_rank: [u8; TOKEN_ENCODED_BYTES] = encoded[cursor..cursor + TOKEN_ENCODED_BYTES]
            .try_into()
            .map_err(|_| OracleBundleError::BundleLength)?;
        cursor += TOKEN_ENCODED_BYTES;
        let bit = 3 * index;
        let flag = |offset: usize| -> bool {
            let selected = bit + offset;
            authorization_flags[selected / 8] & (1 << (selected % 8)) != 0
        };
        authorizations.push(OracleAuthorization {
            line_enabled: flag(0),
            required: flag(1),
            present: flag(2),
            token: decode_authorization_token(token_rank)?,
        });
    }
    if cursor != encoded.len() {
        return Err(OracleBundleError::BundleLength);
    }
    let bundle = OracleBundle {
        profile,
        slot_index,
        slot_is_real: fact_flags & 1 != 0,
        facts: OracleFacts {
            eligibility_active: fact_flags & (1 << 1) != 0,
            provider_enrolled: fact_flags & (1 << 2) != 0,
            provider_not_suspended: fact_flags & (1 << 3) != 0,
            not_deceased: fact_flags & (1 << 4) != 0,
            duplicate_claim: fact_flags & (1 << 5) != 0,
            program_integrity_hold: fact_flags & (1 << 6) != 0,
        },
        authorizations,
    };
    bundle.validate()?;
    if encode_oracle_bundle(&bundle)? != encoded {
        return Err(OracleBundleError::BundleLength);
    }
    Ok(bundle)
}

fn sha3(preimage: &[u8]) -> [u8; DIGEST_BYTES] {
    Sha3_512::digest(preimage).into()
}

fn audit_node(
    profile: OracleProfile,
    child_height: usize,
    position: usize,
    left: &[u8; DIGEST_BYTES],
    right: &[u8; DIGEST_BYTES],
) -> Result<[u8; DIGEST_BYTES], OracleBundleError> {
    let child_height = u8::try_from(child_height).map_err(|_| OracleBundleError::SlotIndex)?;
    let position = u16::try_from(position).map_err(|_| OracleBundleError::SlotIndex)?;
    let mut preimage = Vec::with_capacity(140);
    preimage.extend_from_slice(AUDIT_NODE_MAGIC);
    preimage.push(profile.code());
    preimage.push(child_height);
    preimage.extend_from_slice(&position.to_be_bytes());
    preimage.extend_from_slice(left);
    preimage.extend_from_slice(right);
    debug_assert_eq!(preimage.len(), 140);
    Ok(sha3(&preimage))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleCommitments {
    pub profile: OracleProfile,
    pub leaf_digests: Vec<[u8; DIGEST_BYTES]>,
    pub execution_root: [u8; DIGEST_BYTES],
    pub audit_root: [u8; DIGEST_BYTES],
    audit_levels: Vec<Vec<[u8; DIGEST_BYTES]>>,
}

pub fn build_oracle_commitments(
    profile: OracleProfile,
    bundles: &[OracleBundle],
) -> Result<OracleCommitments, OracleBundleError> {
    if bundles.len() != profile.claim_slots() {
        return Err(OracleBundleError::BundleCount);
    }
    let mut leaves = Vec::with_capacity(bundles.len());
    for (index, bundle) in bundles.iter().enumerate() {
        if bundle.profile != profile
            || usize::try_from(bundle.slot_index).map_err(|_| OracleBundleError::SlotIndex)?
                != index
        {
            return Err(OracleBundleError::BundleOrder);
        }
        leaves.push(sha3(&encode_oracle_bundle(bundle)?));
    }
    let mut execution_preimage = Vec::with_capacity(11 + DIGEST_BYTES * leaves.len());
    execution_preimage.extend_from_slice(EXECUTION_ROOT_MAGIC);
    execution_preimage.push(profile.code());
    execution_preimage.extend_from_slice(
        &u16::try_from(profile.claim_slots())
            .map_err(|_| OracleBundleError::BundleCount)?
            .to_be_bytes(),
    );
    for leaf in &leaves {
        execution_preimage.extend_from_slice(leaf);
    }
    let execution_root = sha3(&execution_preimage);

    let mut levels = vec![leaves.clone()];
    let mut current = leaves.clone();
    let mut child_height = 0;
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len() / 2);
        for (position, pair) in current.chunks_exact(2).enumerate() {
            next.push(audit_node(
                profile,
                child_height,
                position,
                &pair[0],
                &pair[1],
            )?);
        }
        levels.push(next.clone());
        current = next;
        child_height += 1;
    }
    if child_height != profile.tree_depth() {
        return Err(OracleBundleError::BundleCount);
    }
    let mut audit_preimage = Vec::with_capacity(76);
    audit_preimage.extend_from_slice(AUDIT_ROOT_MAGIC);
    audit_preimage.push(profile.code());
    audit_preimage.push(child_height as u8);
    audit_preimage.extend_from_slice(
        &u16::try_from(profile.claim_slots())
            .map_err(|_| OracleBundleError::BundleCount)?
            .to_be_bytes(),
    );
    audit_preimage.extend_from_slice(&current[0]);
    let audit_root = sha3(&audit_preimage);
    Ok(OracleCommitments {
        profile,
        leaf_digests: leaves,
        execution_root,
        audit_root,
        audit_levels: levels,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleAuditProof {
    pub profile: OracleProfile,
    pub position: usize,
    pub bundle: Vec<u8>,
    pub siblings: Vec<[u8; DIGEST_BYTES]>,
    pub audit_root: [u8; DIGEST_BYTES],
}

impl OracleCommitments {
    pub fn audit_proof(
        &self,
        bundle: &OracleBundle,
    ) -> Result<OracleAuditProof, OracleBundleError> {
        bundle.validate()?;
        let position =
            usize::try_from(bundle.slot_index).map_err(|_| OracleBundleError::SlotIndex)?;
        if bundle.profile != self.profile || position >= self.leaf_digests.len() {
            return Err(OracleBundleError::BundleOrder);
        }
        let encoded = encode_oracle_bundle(bundle)?;
        if sha3(&encoded) != self.leaf_digests[position] {
            return Err(OracleBundleError::BundleOrder);
        }
        let siblings = self.audit_levels[..self.audit_levels.len() - 1]
            .iter()
            .enumerate()
            .map(|(height, level)| level[(position >> height) ^ 1])
            .collect();
        Ok(OracleAuditProof {
            profile: self.profile,
            position,
            bundle: encoded,
            siblings,
            audit_root: self.audit_root,
        })
    }
}

pub fn verify_oracle_audit_proof(
    proof: &OracleAuditProof,
) -> Result<OracleBundle, OracleBundleError> {
    if proof.position >= proof.profile.claim_slots() {
        return Err(OracleBundleError::SlotIndex);
    }
    if proof.siblings.len() != proof.profile.tree_depth() {
        return Err(OracleBundleError::AuditSiblingCount);
    }
    let bundle = decode_oracle_bundle(&proof.bundle)?;
    if bundle.profile != proof.profile
        || usize::try_from(bundle.slot_index).map_err(|_| OracleBundleError::SlotIndex)?
            != proof.position
    {
        return Err(OracleBundleError::BundleOrder);
    }
    let mut value = sha3(&proof.bundle);
    let mut cursor = proof.position;
    for (child_height, sibling) in proof.siblings.iter().enumerate() {
        value = if cursor & 1 == 0 {
            audit_node(proof.profile, child_height, cursor >> 1, &value, sibling)?
        } else {
            audit_node(proof.profile, child_height, cursor >> 1, sibling, &value)?
        };
        cursor >>= 1;
    }
    let mut audit_preimage = Vec::with_capacity(76);
    audit_preimage.extend_from_slice(AUDIT_ROOT_MAGIC);
    audit_preimage.push(proof.profile.code());
    audit_preimage.push(proof.profile.tree_depth() as u8);
    audit_preimage.extend_from_slice(&(proof.profile.claim_slots() as u16).to_be_bytes());
    audit_preimage.extend_from_slice(&value);
    if sha3(&audit_preimage) != proof.audit_root {
        return Err(OracleBundleError::AuditRootMismatch);
    }
    Ok(bundle)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OracleCommitmentSchedule {
    pub bundle_bytes: usize,
    pub leaf_permutations: usize,
    pub execution_root_preimage_bytes: usize,
    pub execution_root_permutations: usize,
    pub proof_sponge_permutations: usize,
    pub proof_keccak_round_rows: usize,
    pub audit_sponge_permutations_outside_proof: usize,
    pub audit_proof_bytes: usize,
}

const fn permutations(preimage_bytes: usize) -> usize {
    preimage_bytes / RATE_BYTES + 1
}

pub const fn oracle_commitment_schedule(profile: OracleProfile) -> OracleCommitmentSchedule {
    let leaf_permutations = permutations(BUNDLE_BYTES);
    let execution_root_preimage_bytes = 11 + profile.claim_slots() * DIGEST_BYTES;
    let execution_root_permutations = permutations(execution_root_preimage_bytes);
    let proof_sponge_permutations =
        profile.claim_slots() * leaf_permutations + execution_root_permutations;
    OracleCommitmentSchedule {
        bundle_bytes: BUNDLE_BYTES,
        leaf_permutations,
        execution_root_preimage_bytes,
        execution_root_permutations,
        proof_sponge_permutations,
        proof_keccak_round_rows: proof_sponge_permutations * 24,
        audit_sponge_permutations_outside_proof: 2 * profile.claim_slots(),
        audit_proof_bytes: profile.tree_depth() * DIGEST_BYTES,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleScheduleReport {
    pub slots: u64,
    pub calls: u64,
    pub permutations: u64,
    pub keccak_round_rows: u64,
    pub execution_root: [u8; DIGEST_BYTES],
    pub commitment: [u8; DIGEST_BYTES],
}

fn trace_schedule_call(
    ordinal: u32,
    kind: u8,
    message: &[u8],
    commitment: &mut Sha3_512,
    permutations: &mut u64,
    rows: &mut u64,
) -> Result<[u8; DIGEST_BYTES], OracleBundleError> {
    let mut call_rows = 0_u64;
    let digest =
        for_each_sha3_512_trace_row(message, message.len(), |_, _, _, _, _, _| call_rows += 1)
            .map_err(OracleBundleError::Trace)?;
    if digest != sha3_512_reference(message) {
        return Err(OracleBundleError::BundleLength);
    }
    *permutations = permutations
        .checked_add((message.len() / RATE_BYTES + 1) as u64)
        .ok_or(OracleBundleError::CountOverflow)?;
    *rows = rows
        .checked_add(call_rows)
        .ok_or(OracleBundleError::CountOverflow)?;
    commitment.update(ordinal.to_be_bytes());
    commitment.update([kind]);
    let length = u16::try_from(message.len()).map_err(|_| OracleBundleError::CountOverflow)?;
    commitment.update(length.to_be_bytes());
    commitment.update(length.to_be_bytes());
    commitment.update(message);
    commitment.update(digest);
    Ok(digest)
}

pub fn evaluate_oracle_schedule(
    profile: OracleProfile,
    bundles: &[Vec<u8>],
    expected_execution_root: [u8; DIGEST_BYTES],
) -> Result<OracleScheduleReport, OracleBundleError> {
    if bundles.len() != profile.claim_slots() || bundles.len() > MAX_ORACLE_SLOTS {
        return Err(OracleBundleError::BundleCount);
    }
    let mut commitment = Sha3_512::new();
    commitment.update(SCHEDULE_DOMAIN);
    commitment.update([profile.code()]);
    commitment.update(
        u16::try_from(bundles.len())
            .map_err(|_| OracleBundleError::CountOverflow)?
            .to_be_bytes(),
    );
    let mut permutations = 0_u64;
    let mut rows = 0_u64;
    let mut ordinal = 0_u32;
    let mut leaf_digests = Vec::with_capacity(bundles.len());
    for (slot, encoded) in bundles.iter().enumerate() {
        let bundle = decode_oracle_bundle(encoded)?;
        if bundle.profile != profile
            || usize::try_from(bundle.slot_index).map_err(|_| OracleBundleError::SlotIndex)? != slot
        {
            return Err(OracleBundleError::BundleOrder);
        }
        leaf_digests.push(trace_schedule_call(
            ordinal,
            1,
            encoded,
            &mut commitment,
            &mut permutations,
            &mut rows,
        )?);
        ordinal = ordinal
            .checked_add(1)
            .ok_or(OracleBundleError::CountOverflow)?;
    }
    let mut root_message = Vec::with_capacity(11 + DIGEST_BYTES * leaf_digests.len());
    root_message.extend_from_slice(EXECUTION_ROOT_MAGIC);
    root_message.push(profile.code());
    root_message.extend_from_slice(
        &u16::try_from(profile.claim_slots())
            .map_err(|_| OracleBundleError::CountOverflow)?
            .to_be_bytes(),
    );
    for digest in &leaf_digests {
        root_message.extend_from_slice(digest);
    }
    let execution_root = trace_schedule_call(
        ordinal,
        2,
        &root_message,
        &mut commitment,
        &mut permutations,
        &mut rows,
    )?;
    if execution_root != expected_execution_root {
        return Err(OracleBundleError::ExpectedExecutionRootInvalid);
    }
    commitment.update(execution_root);
    if rows != permutations * u64::from(KECCAK_ROUNDS) {
        return Err(OracleBundleError::CountOverflow);
    }
    Ok(OracleScheduleReport {
        slots: u64::try_from(bundles.len()).map_err(|_| OracleBundleError::CountOverflow)?,
        calls: u64::from(ordinal) + 1,
        permutations,
        keccak_round_rows: rows,
        execution_root,
        commitment: commitment.finalize().into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_authorization() -> OracleAuthorization {
        OracleAuthorization {
            line_enabled: false,
            required: false,
            present: false,
            token: String::new(),
        }
    }

    fn cover(profile: OracleProfile, slot_index: u32) -> OracleBundle {
        OracleBundle {
            profile,
            slot_index,
            slot_is_real: false,
            facts: OracleFacts {
                eligibility_active: false,
                provider_enrolled: false,
                provider_not_suspended: false,
                not_deceased: false,
                duplicate_claim: false,
                program_integrity_hold: false,
            },
            authorizations: vec![zero_authorization(); AUTHORIZATIONS_PER_CLAIM],
        }
    }

    fn python_k128_vector() -> Vec<OracleBundle> {
        let mut bundles = (0..128)
            .map(|index| cover(OracleProfile::K128, index))
            .collect::<Vec<_>>();
        bundles[0].slot_is_real = true;
        bundles[0].facts = OracleFacts {
            eligibility_active: true,
            provider_enrolled: true,
            provider_not_suspended: true,
            not_deceased: true,
            duplicate_claim: false,
            program_integrity_hold: false,
        };
        bundles[0].authorizations[0].line_enabled = true;
        bundles
    }

    fn hex<const N: usize>(value: &str) -> [u8; N] {
        let raw = value.as_bytes();
        assert_eq!(raw.len(), 2 * N);
        let mut out = [0_u8; N];
        for index in 0..N {
            out[index] = (nibble(raw[2 * index]) << 4) | nibble(raw[2 * index + 1]);
        }
        out
    }

    fn nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid hex"),
        }
    }

    #[test]
    fn token_rank_matches_python_and_round_trips() {
        let expected = hex::<42>(
            "00000000000000000000000000000000000000000000000000000000000000056c16\
             95dce180233b59f0",
        );
        assert_eq!(
            encode_authorization_token("SYNTHETIC-AUTH-1").unwrap(),
            expected
        );
        assert_eq!(
            decode_authorization_token(expected).unwrap(),
            "SYNTHETIC-AUTH-1"
        );
        for token in ["", "A", "Z", "0", "9", "A-0-Z"] {
            let encoded = encode_authorization_token(token).unwrap();
            assert_eq!(decode_authorization_token(encoded).unwrap(), token);
        }
    }

    #[test]
    fn bundle_and_roots_match_python() {
        let bundles = python_k128_vector();
        let first = encode_oracle_bundle(&bundles[0]).unwrap();
        assert_eq!(first.len(), BUNDLE_BYTES);
        assert_eq!(decode_oracle_bundle(&first).unwrap(), bundles[0]);
        assert_eq!(
            sha3(&first),
            hex::<64>(
                "527e29630b5f563fa9a95d98887cdb3bb1b12289568c77507dd1efedc19de281\
                 f00cf148b721249c7eac6fe8753aaf6fa5bc7c338fff3520e6853b41adb3e299"
            )
        );
        let commitments = build_oracle_commitments(OracleProfile::K128, &bundles).unwrap();
        assert_eq!(
            commitments.execution_root,
            hex::<64>(
                "097648ef1243a0f78c1fc1a76e833c0e85dd29687fa977ea4cd43bdd10a7f0f6\
                 9f76540e9c33bf5c50f48cfb6bdd5ff87b8dbccb95aa30bef956364dc82b293f"
            )
        );
        assert_eq!(
            commitments.audit_root,
            hex::<64>(
                "0112f6bb14a02e7e546a61bd0c2b1bbf12e9e8e7ae327d535a7166ca6c377401\
                 0a3f60d8f6bbc5bfec5dbedcc8cd6525d9f190965d41b3fc134f564e76454899"
            )
        );
        for index in [0, 1, 64, 127] {
            let proof = commitments.audit_proof(&bundles[index]).unwrap();
            assert_eq!(verify_oracle_audit_proof(&proof).unwrap(), bundles[index]);
        }
    }

    #[test]
    fn schedule_matches_python() {
        assert_eq!(
            oracle_commitment_schedule(OracleProfile::K128),
            OracleCommitmentSchedule {
                bundle_bytes: 2_133,
                leaf_permutations: 30,
                execution_root_preimage_bytes: 8_203,
                execution_root_permutations: 114,
                proof_sponge_permutations: 3_954,
                proof_keccak_round_rows: 94_896,
                audit_sponge_permutations_outside_proof: 256,
                audit_proof_bytes: 448,
            }
        );
    }

    #[test]
    fn streamed_schedule_matches_commitment_and_rejects_wrong_root() {
        let bundles = python_k128_vector();
        let commitments = build_oracle_commitments(OracleProfile::K128, &bundles).unwrap();
        let encoded = bundles
            .iter()
            .map(|bundle| encode_oracle_bundle(bundle).unwrap())
            .collect::<Vec<_>>();
        let report =
            evaluate_oracle_schedule(OracleProfile::K128, &encoded, commitments.execution_root)
                .unwrap();
        assert_eq!(report.calls, 129);
        assert_eq!(report.permutations, 3_954);
        assert_eq!(report.keccak_round_rows, 94_896);
        let mut wrong_root = commitments.execution_root;
        wrong_root[0] ^= 1;
        assert_eq!(
            evaluate_oracle_schedule(OracleProfile::K128, &encoded, wrong_root),
            Err(OracleBundleError::ExpectedExecutionRootInvalid)
        );
    }

    #[test]
    fn malformed_bundle_and_path_fail_closed() {
        let bundles = python_k128_vector();
        let commitments = build_oracle_commitments(OracleProfile::K128, &bundles).unwrap();
        let mut malformed = encode_oracle_bundle(&bundles[0]).unwrap();
        malformed[0] ^= 1;
        assert_eq!(
            decode_oracle_bundle(&malformed),
            Err(OracleBundleError::BundleMagic)
        );
        let mut proof = commitments.audit_proof(&bundles[0]).unwrap();
        proof.siblings[0][0] ^= 1;
        assert_eq!(
            verify_oracle_audit_proof(&proof),
            Err(OracleBundleError::AuditRootMismatch)
        );
    }
}
