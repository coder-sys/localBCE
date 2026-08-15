//! Portable verifier boundary for the proof-native C0 typed-state relation.
//!
//! The wire object contains only the fixed selected proof package, its complete
//! authenticated dual-PQ transcript, and the transcript-bound public projection
//! and sidecar.  It never accepts an AIR execution, witness, commitment opening,
//! or commitment mask.

use alloc::vec::Vec;

use sha3::{Digest, Sha3_512};

use crate::air_ir::{AIR_PROGRAM_MAGIC, AirIrError, validate_air_program};
use crate::selected_proof_package::{
    PRIVATE_PROOF_PACKAGE_BYTES, PRIVATE_PROOF_PACKAGE_MAGIC, PRIVATE_PROOF_PACKAGE_VERSION,
    SelectedProofPackageError, verify_selected_proof_package,
};
use crate::selected_public_coin::{
    MAX_SELECTED_TRANSCRIPT_BYTES, SELECTED_TRANSCRIPT_MAGIC, SELECTED_TRANSCRIPT_VERSION,
    SelectedTranscriptError, verify_selected_public_coin_transcript,
};
use crate::{
    binding_root_v2::{BindingDigestV2, BindingRoleV2},
    field::M31,
};

pub const TYPED_STATE_PROOF_PACKAGE_MAGIC: &[u8; 8] = b"BLTSPK01";
pub const TYPED_STATE_PROOF_PACKAGE_VERSION: u16 = 1;
pub const TYPED_STATE_PROOF_PACKAGE_FLAGS: u16 = 0;
pub const TYPED_STATE_PUBLIC_OUTPUT_BYTES: usize = 384;
pub const TYPED_STATE_SIDECAR_BYTES: usize = 744;
pub const TYPED_STATE_PROOF_PACKAGE_PREFIX_BYTES: usize =
    8 + 2 + 2 + TYPED_STATE_PUBLIC_OUTPUT_BYTES + TYPED_STATE_SIDECAR_BYTES + 8 + 8;
pub const TYPED_STATE_PROOF_PACKAGE_BYTES: usize = TYPED_STATE_PROOF_PACKAGE_PREFIX_BYTES
    + PRIVATE_PROOF_PACKAGE_BYTES
    + MAX_SELECTED_TRANSCRIPT_BYTES;
pub const TYPED_STATE_PUBLIC_INPUT_COUNT: usize = 1_806;
pub const TYPED_STATE_OUTER_SIDECAR_BYTES: usize = 744;
pub const TYPED_STATE_OUTER_PUBLIC_FIELD_COUNT: usize = 12;
pub const TYPED_STATE_OUTER_PUBLIC_FIELD_BYTES: usize = 32;

const TYPED_STATE_SIDECAR_MAGIC: &[u8; 8] = b"BLTSSC01";
const TYPED_STATE_SIDECAR_VERSION: u16 = 1;
const TYPED_STATE_SIDECAR_FLAGS: u16 = 0;
const TYPED_STATE_PROGRAM_ID: &[u8] = b"BL-PQ512-C0-TYPED-STATE-AIR-v5";
const K128_PROFILE_LABEL: &[u8] = b"K128_CALIBRATION";
const K512_PROFILE_LABEL: &[u8] = b"K512_CALIBRATION";
const K128_PROFILE_CODE: u8 = 1;
const K512_PROFILE_CODE: u8 = 3;
const AUTHORITY_ROOT_COUNT: usize = 10;
const AUTHORITY_ROOT_OFFSET: usize = 3;
const AUTHORITY_PHASE_WIDTH: usize = AUTHORITY_ROOT_OFFSET + AUTHORITY_ROOT_COUNT * 64;
const SUMMARY_OFFSET: usize = 2 * AUTHORITY_PHASE_WIDTH;
const SETTLEMENT_ROOT_INDEX: usize = 0;
const ASSET_REGISTRY_ROOT_INDEX: usize = 1;
const SCOPE_ROOT_INDEX: usize = 2;
const BENEFIT_ROOT_INDEX: usize = 3;
const OBLIGATION_ROOT_INDEX: usize = 4;
const LEDGER_ROOT_INDEX: usize = 5;
const OPERATION_LOG_ROOT_INDEX: usize = 6;
const PAYMENT_ROOT_INDEX: usize = 7;
const REPLAY_ROOT_INDEX: usize = 8;
const STATE_ROOT_INDEX: usize = 9;

const PAYMENT_STATE_ROOT_DOMAIN: &[u8] = b"BL/PQ512/PAYMENT-MAP/STATE/v4";
const C0_STATE_ROOT_DOMAIN: &[u8] = b"BL/PQ512/C0/STATE-ROOT/v1\0";
const PROFILE_IDENTITY_DOMAIN: &[u8] = b"BL/PQ512/C0/TYPED-STATE-PROFILE/v1\0";
const PROGRAM_IDENTITY_DOMAIN: &[u8] = b"BL/PQ512/C0/TYPED-STATE-PROGRAM/v1\0";
const PROJECTION_DOMAIN: &[u8] = b"BL/PQ512/C0/TYPED-STATE-PROJECTION/v1\0";
const PROJECTION_DIGEST_DOMAIN: &[u8] = b"BL/PQ512/C0/TYPED-STATE-PROJECTION-DIGEST/v1\0";
const TRANSITION_DOMAIN: &[u8] = b"BL/PQ512/C0/TYPED-STATE-TRANSITION/v1\0";
const PROOF_DOMAIN: &[u8] = b"BL/PQ512/STATE-AIR-PROOF/v1\0";
const STATEMENT_EVIDENCE_DOMAIN: &[u8] = b"BL/PQ512/PRODUCTION-CANDIDATE/EVIDENCE/v1\0";
const OUTER_SIDECAR_MAGIC: &[u8; 8] = b"BLPQSC01";
const STARK252_PROJECTION_MODULUS_BE: [u8; 32] = [
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const STARK252_PRIME_BE: [u8; 32] = [
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

#[derive(Clone, Copy, Debug)]
pub struct TypedStateProofVerificationKey<'a> {
    /// Exact governed profile label (`K128_CALIBRATION` or `K512_CALIBRATION`).
    pub expected_profile_label: &'a [u8],
    /// SHA3-512 AIR program-binary commitment pinned by verifier configuration.
    pub expected_program_commitment: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedStatePublicBindings {
    /// Governed typed-profile code. This is distinct from the opaque outer `profileId`.
    pub governed_profile_code: u8,
    /// Exact governed typed-profile label authenticated by `profile_identity`.
    pub governed_profile_label: &'static str,
    pub profile_identity: [u8; 64],
    pub program_identity: [u8; 64],
    pub program_commitment: [u8; 64],
    /// Internal selected-proof suite identity; the outer application `proofSuiteId` stays null.
    pub proof_suite_id: [u8; 64],
    pub schedule_commitment: [u8; 64],
    pub session_id: [u8; 64],
    pub proof_package_commitment: [u8; 64],
    pub transcript_commitment: [u8; 64],
    pub public_input_digest: [u8; 64],
    pub projection_digest: [u8; 64],
    /// Typed-component projection. This is not the external Privacy V2 12-field ABI.
    pub public_outputs: [[u8; 32]; 12],
    pub epoch: u64,
    pub sequence_before: u64,
    pub sequence_after: u64,
    pub settlement_root_before: [u8; 64],
    pub settlement_root_after: [u8; 64],
    pub asset_registry_root_before: [u8; 64],
    pub asset_registry_root_after: [u8; 64],
    pub scope_root_before: [u8; 64],
    pub scope_root_after: [u8; 64],
    pub benefit_root_before: [u8; 64],
    pub benefit_root_after: [u8; 64],
    pub obligation_root_before: [u8; 64],
    pub obligation_root_after: [u8; 64],
    pub ledger_root_before: [u8; 64],
    pub ledger_root_after: [u8; 64],
    pub operation_log_root_before: [u8; 64],
    pub operation_log_root_after: [u8; 64],
    pub payment_root_before: [u8; 64],
    pub payment_root_after: [u8; 64],
    pub replay_root_before: [u8; 64],
    pub replay_root_after: [u8; 64],
    pub state_root_before: [u8; 64],
    pub state_root_after: [u8; 64],
    pub transition_commitment: [u8; 64],
}

/// Opaque typed-state authority for the v3 composition.  It is created only
/// by verifying the portable typed proof and its exact outer statement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedTypedStateV3 {
    governed_profile_code: u8,
    public_inputs_binding: BindingDigestV2,
    receipt_binding: BindingDigestV2,
}

impl VerifiedTypedStateV3 {
    pub const fn governed_profile_code(&self) -> u8 {
        self.governed_profile_code
    }
    pub const fn public_inputs_binding(&self) -> BindingDigestV2 {
        self.public_inputs_binding
    }
    pub const fn receipt_binding(&self) -> BindingDigestV2 {
        self.receipt_binding
    }

    #[cfg(test)]
    pub(crate) const fn synthetic_for_test(
        governed_profile_code: u8,
        public_inputs_binding: BindingDigestV2,
        receipt_binding: BindingDigestV2,
    ) -> Self {
        Self {
            governed_profile_code,
            public_inputs_binding,
            receipt_binding,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TypedStateProofPackageError {
    Length,
    Magic,
    Version,
    Flags,
    Truncated,
    Trailing,
    Identity,
    Program,
    PublicInput,
    PublicBinding,
    Sidecar,
    OuterStatement,
    Bundle,
    Air(AirIrError),
    Proof(SelectedProofPackageError),
    Transcript(SelectedTranscriptError),
}

impl From<AirIrError> for TypedStateProofPackageError {
    fn from(value: AirIrError) -> Self {
        Self::Air(value)
    }
}

impl From<SelectedProofPackageError> for TypedStateProofPackageError {
    fn from(value: SelectedProofPackageError) -> Self {
        Self::Proof(value)
    }
}

impl From<SelectedTranscriptError> for TypedStateProofPackageError {
    fn from(value: SelectedTranscriptError) -> Self {
        Self::Transcript(value)
    }
}

struct PortableSections<'a> {
    public_outputs: &'a [u8],
    sidecar: &'a [u8],
    proof_package: &'a [u8],
    transcript: &'a [u8],
}

struct Cursor<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(encoded: &'a [u8]) -> Self {
        Self { encoded, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], TypedStateProofPackageError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(TypedStateProofPackageError::Length)?;
        let value = self
            .encoded
            .get(self.offset..end)
            .ok_or(TypedStateProofPackageError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, TypedStateProofPackageError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| TypedStateProofPackageError::Truncated)?,
        ))
    }

    fn u32(&mut self) -> Result<usize, TypedStateProofPackageError> {
        usize::try_from(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| TypedStateProofPackageError::Truncated)?,
        ))
        .map_err(|_| TypedStateProofPackageError::Length)
    }

    fn u64(&mut self) -> Result<usize, TypedStateProofPackageError> {
        usize::try_from(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| TypedStateProofPackageError::Truncated)?,
        ))
        .map_err(|_| TypedStateProofPackageError::Length)
    }
}

fn decode_portable_sections(
    encoded: &[u8],
) -> Result<PortableSections<'_>, TypedStateProofPackageError> {
    if encoded.len() != TYPED_STATE_PROOF_PACKAGE_BYTES {
        return Err(TypedStateProofPackageError::Length);
    }
    let mut reader = Cursor::new(encoded);
    if reader.take(8)? != TYPED_STATE_PROOF_PACKAGE_MAGIC {
        return Err(TypedStateProofPackageError::Magic);
    }
    if reader.u16()? != TYPED_STATE_PROOF_PACKAGE_VERSION {
        return Err(TypedStateProofPackageError::Version);
    }
    if reader.u16()? != TYPED_STATE_PROOF_PACKAGE_FLAGS {
        return Err(TypedStateProofPackageError::Flags);
    }
    let public_outputs = reader.take(TYPED_STATE_PUBLIC_OUTPUT_BYTES)?;
    let sidecar = reader.take(TYPED_STATE_SIDECAR_BYTES)?;
    if reader.u64()? != PRIVATE_PROOF_PACKAGE_BYTES {
        return Err(TypedStateProofPackageError::Length);
    }
    let transcript_length = reader.u64()?;
    if transcript_length == 0 || transcript_length > MAX_SELECTED_TRANSCRIPT_BYTES {
        return Err(TypedStateProofPackageError::Length);
    }
    if reader.offset != TYPED_STATE_PROOF_PACKAGE_PREFIX_BYTES {
        return Err(TypedStateProofPackageError::Length);
    }
    let proof_package = reader.take(PRIVATE_PROOF_PACKAGE_BYTES)?;
    let transcript = reader.take(transcript_length)?;
    let padding = reader.take(MAX_SELECTED_TRANSCRIPT_BYTES - transcript_length)?;
    if padding.iter().any(|byte| *byte != 0) || reader.offset != encoded.len() {
        return Err(TypedStateProofPackageError::Trailing);
    }
    Ok(PortableSections {
        public_outputs,
        sidecar,
        proof_package,
        transcript,
    })
}

fn framed_hash(domain: &[u8], parts: &[&[u8]]) -> Result<[u8; 64], TypedStateProofPackageError> {
    let mut hash = Sha3_512::new();
    hash.update(domain);
    for part in parts {
        let length = u32::try_from(part.len()).map_err(|_| TypedStateProofPackageError::Length)?;
        hash.update(length.to_be_bytes());
        hash.update(part);
    }
    Ok(hash.finalize().into())
}

fn digest64(value: &[u8]) -> Result<[u8; 64], TypedStateProofPackageError> {
    let result: [u8; 64] = value
        .try_into()
        .map_err(|_| TypedStateProofPackageError::Sidecar)?;
    if !result.iter().any(|byte| *byte != 0) {
        return Err(TypedStateProofPackageError::Sidecar);
    }
    Ok(result)
}

fn parse_selected_statement(
    encoded: &[u8],
) -> Result<(&[u8], Vec<M31>), TypedStateProofPackageError> {
    if encoded.len() != PRIVATE_PROOF_PACKAGE_BYTES {
        return Err(TypedStateProofPackageError::Length);
    }
    let mut reader = Cursor::new(encoded);
    if reader.take(8)? != PRIVATE_PROOF_PACKAGE_MAGIC {
        return Err(TypedStateProofPackageError::Magic);
    }
    if reader.u16()? != PRIVATE_PROOF_PACKAGE_VERSION {
        return Err(TypedStateProofPackageError::Version);
    }
    let program_length = reader.u32()?;
    if program_length == 0 {
        return Err(TypedStateProofPackageError::Program);
    }
    let program = reader.take(program_length)?;
    let public_count = reader.u32()?;
    if public_count != TYPED_STATE_PUBLIC_INPUT_COUNT {
        return Err(TypedStateProofPackageError::PublicInput);
    }
    let mut public_inputs = Vec::with_capacity(public_count);
    for _ in 0..public_count {
        let value = u32::from_be_bytes(
            reader
                .take(4)?
                .try_into()
                .map_err(|_| TypedStateProofPackageError::Truncated)?,
        );
        public_inputs.push(
            M31::from_canonical(value).map_err(|_| TypedStateProofPackageError::PublicInput)?,
        );
    }
    Ok((program, public_inputs))
}

fn validate_program_id(encoded: &[u8]) -> Result<(), TypedStateProofPackageError> {
    let header_length = AIR_PROGRAM_MAGIC.len() + 2 + 64 + 2;
    if encoded.len() < header_length
        || encoded.get(..AIR_PROGRAM_MAGIC.len()) != Some(AIR_PROGRAM_MAGIC)
    {
        return Err(TypedStateProofPackageError::Program);
    }
    let length_offset = AIR_PROGRAM_MAGIC.len() + 2 + 64;
    let identifier_length = usize::from(u16::from_be_bytes(
        encoded[length_offset..length_offset + 2]
            .try_into()
            .map_err(|_| TypedStateProofPackageError::Program)?,
    ));
    let identifier_start = length_offset + 2;
    let identifier_end = identifier_start
        .checked_add(identifier_length)
        .ok_or(TypedStateProofPackageError::Length)?;
    if encoded.get(identifier_start..identifier_end) != Some(TYPED_STATE_PROGRAM_ID) {
        return Err(TypedStateProofPackageError::Program);
    }
    Ok(())
}

fn public_byte(values: &[M31], index: usize) -> Result<u8, TypedStateProofPackageError> {
    let value = values
        .get(index)
        .ok_or(TypedStateProofPackageError::PublicInput)?
        .as_u32();
    u8::try_from(value).map_err(|_| TypedStateProofPackageError::PublicInput)
}

fn public_digest(values: &[M31], start: usize) -> Result<[u8; 64], TypedStateProofPackageError> {
    let mut result = [0_u8; 64];
    for (offset, byte) in result.iter_mut().enumerate() {
        *byte = public_byte(values, start + offset)?;
    }
    if !result.iter().any(|byte| *byte != 0) {
        return Err(TypedStateProofPackageError::PublicBinding);
    }
    Ok(result)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParsedSidecar {
    profile_identity: [u8; 64],
    program_identity: [u8; 64],
    program_commitment: [u8; 64],
    state_roots: [[u8; 64]; 2],
    payment_roots: [[u8; 64]; 2],
    replay_roots: [[u8; 64]; 2],
    transition: [u8; 64],
    projection_digest: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParsedPublicBindings {
    sidecar: ParsedSidecar,
    authority_roots: [[[u8; 64]; AUTHORITY_ROOT_COUNT]; 2],
    epoch: u64,
    sequence_before: u64,
    sequence_after: u64,
}

fn governed_profile(
    profile_label: &[u8],
) -> Result<(u8, &'static str), TypedStateProofPackageError> {
    if profile_label == K128_PROFILE_LABEL {
        Ok((K128_PROFILE_CODE, "K128_CALIBRATION"))
    } else if profile_label == K512_PROFILE_LABEL {
        Ok((K512_PROFILE_CODE, "K512_CALIBRATION"))
    } else {
        Err(TypedStateProofPackageError::Identity)
    }
}

fn payment_state_root(
    epoch: u64,
    sequence: u64,
    next_slot_index: u16,
    authority_roots: &[[u8; 64]; AUTHORITY_ROOT_COUNT],
) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(PAYMENT_STATE_ROOT_DOMAIN);
    hash.update(epoch.to_be_bytes());
    hash.update(sequence.to_be_bytes());
    hash.update(next_slot_index.to_be_bytes());
    for root in &authority_roots[..PAYMENT_ROOT_INDEX] {
        hash.update(root);
    }
    hash.finalize().into()
}

fn subtract_be(left: &mut [u8; 32], right: &[u8; 32]) {
    let mut borrow = 0_u8;
    for index in (0..32).rev() {
        let (value, first_borrow) = left[index].overflowing_sub(right[index]);
        let (value, second_borrow) = value.overflowing_sub(borrow);
        left[index] = value;
        borrow = u8::from(first_borrow || second_borrow);
    }
    debug_assert_eq!(borrow, 0);
}

/// Exact compatibility alias used by the external Privacy V2 statement:
/// `OS2IP(digest) mod (STARK252_PRIME - 1) + 1`.
fn stark252_compatibility_alias(digest: &[u8; 64]) -> [u8; 32] {
    let mut remainder = [0_u8; 32];
    for byte in digest {
        for bit in (0..8).rev() {
            let mut carry = (byte >> bit) & 1;
            for value in remainder.iter_mut().rev() {
                let next_carry = *value >> 7;
                *value = (*value << 1) | carry;
                carry = next_carry;
            }
            debug_assert_eq!(carry, 0);
            if remainder >= STARK252_PROJECTION_MODULUS_BE {
                subtract_be(&mut remainder, &STARK252_PROJECTION_MODULUS_BE);
            }
        }
    }
    let mut carry = 1_u8;
    for value in remainder.iter_mut().rev() {
        let (sum, overflow) = value.overflowing_add(carry);
        *value = sum;
        carry = u8::from(overflow);
        if carry == 0 {
            break;
        }
    }
    debug_assert_eq!(carry, 0);
    remainder
}

fn outer_digest(
    sidecar: &[u8; TYPED_STATE_OUTER_SIDECAR_BYTES],
    start: usize,
) -> Result<[u8; 64], TypedStateProofPackageError> {
    sidecar[start..start + 64]
        .try_into()
        .map_err(|_| TypedStateProofPackageError::OuterStatement)
}

fn parse_sidecar(encoded: &[u8]) -> Result<ParsedSidecar, TypedStateProofPackageError> {
    if encoded.len() != TYPED_STATE_SIDECAR_BYTES
        || encoded.get(..8) != Some(TYPED_STATE_SIDECAR_MAGIC)
        || encoded.get(8..10) != Some(&TYPED_STATE_SIDECAR_VERSION.to_be_bytes())
        || encoded.get(10..12) != Some(&TYPED_STATE_SIDECAR_FLAGS.to_be_bytes())
        || encoded.get(12..16) != Some(&(TYPED_STATE_SIDECAR_BYTES as u32).to_be_bytes())
        || encoded[16 + 11 * 64..].iter().any(|byte| *byte != 0)
    {
        return Err(TypedStateProofPackageError::Sidecar);
    }
    let field = |index: usize| digest64(&encoded[16 + index * 64..16 + (index + 1) * 64]);
    Ok(ParsedSidecar {
        profile_identity: field(0)?,
        program_identity: field(1)?,
        program_commitment: field(2)?,
        state_roots: [field(3)?, field(4)?],
        payment_roots: [field(5)?, field(6)?],
        replay_roots: [field(7)?, field(8)?],
        transition: field(9)?,
        projection_digest: field(10)?,
    })
}

fn parse_public_bindings(
    profile_label: &[u8],
    program_commitment: &[u8; 64],
    public_inputs: &[M31],
    public_outputs: &[u8],
    sidecar_encoded: &[u8],
) -> Result<ParsedPublicBindings, TypedStateProofPackageError> {
    if public_inputs.len() != TYPED_STATE_PUBLIC_INPUT_COUNT
        || public_outputs.len() != TYPED_STATE_PUBLIC_OUTPUT_BYTES
    {
        return Err(TypedStateProofPackageError::PublicInput);
    }
    let sidecar = parse_sidecar(sidecar_encoded)?;
    let expected_profile_identity = framed_hash(PROFILE_IDENTITY_DOMAIN, &[profile_label])?;
    let expected_program_identity =
        framed_hash(PROGRAM_IDENTITY_DOMAIN, &[TYPED_STATE_PROGRAM_ID])?;
    if sidecar.profile_identity != expected_profile_identity
        || sidecar.program_identity != expected_program_identity
        || sidecar.program_commitment != *program_commitment
    {
        return Err(TypedStateProofPackageError::Identity);
    }

    let mut authority_roots = [[[0_u8; 64]; AUTHORITY_ROOT_COUNT]; 2];
    let mut epochs = [0_u64; 2];
    let mut sequences = [0_u64; 2];
    let mut next_slot_indices = [0_u16; 2];
    for phase in 0..2 {
        let base = phase * AUTHORITY_PHASE_WIDTH;
        epochs[phase] = u64::from(public_inputs[base].as_u32());
        sequences[phase] = u64::from(public_inputs[base + 1].as_u32());
        next_slot_indices[phase] = u16::try_from(public_inputs[base + 2].as_u32())
            .map_err(|_| TypedStateProofPackageError::PublicBinding)?;
        for root_index in 0..AUTHORITY_ROOT_COUNT {
            authority_roots[phase][root_index] = public_digest(
                public_inputs,
                base + AUTHORITY_ROOT_OFFSET + root_index * 64,
            )?;
        }
        let expected_payment = payment_state_root(
            epochs[phase],
            sequences[phase],
            next_slot_indices[phase],
            &authority_roots[phase],
        );
        if authority_roots[phase][PAYMENT_ROOT_INDEX] != expected_payment {
            return Err(TypedStateProofPackageError::PublicBinding);
        }
        let mut state_hash = Sha3_512::new();
        state_hash.update(C0_STATE_ROOT_DOMAIN);
        state_hash.update(authority_roots[phase][PAYMENT_ROOT_INDEX]);
        state_hash.update(authority_roots[phase][REPLAY_ROOT_INDEX]);
        let expected_state: [u8; 64] = state_hash.finalize().into();
        if authority_roots[phase][STATE_ROOT_INDEX] != expected_state {
            return Err(TypedStateProofPackageError::PublicBinding);
        }
    }
    let summary_replay_before = public_digest(public_inputs, SUMMARY_OFFSET)?;
    let summary_replay_after = public_digest(public_inputs, SUMMARY_OFFSET + 64)?;
    let payment_roots = [
        authority_roots[0][PAYMENT_ROOT_INDEX],
        authority_roots[1][PAYMENT_ROOT_INDEX],
    ];
    let replay_roots = [
        authority_roots[0][REPLAY_ROOT_INDEX],
        authority_roots[1][REPLAY_ROOT_INDEX],
    ];
    let state_roots = [
        authority_roots[0][STATE_ROOT_INDEX],
        authority_roots[1][STATE_ROOT_INDEX],
    ];
    if replay_roots != [summary_replay_before, summary_replay_after]
        || sidecar.payment_roots != payment_roots
        || sidecar.replay_roots != replay_roots
        || sidecar.state_roots != state_roots
    {
        return Err(TypedStateProofPackageError::PublicBinding);
    }

    let public_bytes = public_inputs
        .iter()
        .flat_map(|value| value.as_u32().to_be_bytes())
        .collect::<Vec<_>>();
    let mut projected = [[0_u8; 32]; 12];
    for (index, field) in projected.iter_mut().enumerate() {
        let index_byte = [index as u8];
        let digest = framed_hash(PROJECTION_DOMAIN, &[&index_byte, &public_bytes])?;
        field.copy_from_slice(&digest[..32]);
        if public_outputs[index * 32..(index + 1) * 32] != field[..] {
            return Err(TypedStateProofPackageError::PublicBinding);
        }
    }
    let projection_parts = projected
        .iter()
        .map(|field| field.as_slice())
        .collect::<Vec<_>>();
    let projection_digest = framed_hash(PROJECTION_DIGEST_DOMAIN, &projection_parts)?;
    if sidecar.projection_digest != projection_digest {
        return Err(TypedStateProofPackageError::PublicBinding);
    }

    let epoch = epochs[0];
    let sequence_before = sequences[0];
    let epoch_after = epochs[1];
    let sequence_after = sequences[1];
    if epoch == 0
        || epoch_after != epoch
        || sequence_before == u64::MAX
        || sequence_after != sequence_before + 1
        || next_slot_indices != [0, 0]
        || authority_roots[0][SETTLEMENT_ROOT_INDEX] != authority_roots[1][SETTLEMENT_ROOT_INDEX]
        || authority_roots[0][ASSET_REGISTRY_ROOT_INDEX]
            != authority_roots[1][ASSET_REGISTRY_ROOT_INDEX]
        || authority_roots[0][SCOPE_ROOT_INDEX] != authority_roots[1][SCOPE_ROOT_INDEX]
    {
        return Err(TypedStateProofPackageError::PublicBinding);
    }
    let epoch_bytes = epoch.to_be_bytes();
    let sequence_before_bytes = sequence_before.to_be_bytes();
    let sequence_after_bytes = sequence_after.to_be_bytes();
    let expected_transition = framed_hash(
        TRANSITION_DOMAIN,
        &[
            profile_label,
            &epoch_bytes,
            &sequence_before_bytes,
            &sequence_after_bytes,
            &state_roots[0],
            &state_roots[1],
            &payment_roots[0],
            &payment_roots[1],
        ],
    )?;
    if sidecar.transition != expected_transition {
        return Err(TypedStateProofPackageError::PublicBinding);
    }
    Ok(ParsedPublicBindings {
        sidecar,
        authority_roots,
        epoch,
        sequence_before,
        sequence_after,
    })
}

fn skip_signed_envelope(reader: &mut Cursor<'_>) -> Result<(), TypedStateProofPackageError> {
    reader.take(64)?;
    reader.take(64)?;
    let signature_length = reader.u32()?;
    if signature_length == 0 || signature_length > 64 << 10 {
        return Err(TypedStateProofPackageError::Bundle);
    }
    reader.take(signature_length)?;
    Ok(())
}

fn transcript_messages(
    encoded: &[u8],
) -> Result<Vec<([u8; 64], [u8; 64])>, TypedStateProofPackageError> {
    let mut reader = Cursor::new(encoded);
    if reader.take(8)? != SELECTED_TRANSCRIPT_MAGIC {
        return Err(TypedStateProofPackageError::Magic);
    }
    if reader.u16()? != SELECTED_TRANSCRIPT_VERSION {
        return Err(TypedStateProofPackageError::Version);
    }
    reader.take(64)?;
    reader.take(TYPED_STATE_PUBLIC_OUTPUT_BYTES)?;
    reader.take(TYPED_STATE_SIDECAR_BYTES)?;
    reader.take(64)?;
    reader.take(64)?;
    let contributor_count = usize::from(reader.u16()?);
    if !(2..=16).contains(&contributor_count) {
        return Err(TypedStateProofPackageError::Bundle);
    }
    for _ in 0..contributor_count {
        reader.take(64)?;
        reader.take(64)?;
        reader.take(2)?;
        let public_key_length = reader.u32()?;
        if public_key_length == 0 || public_key_length > 64 << 10 {
            return Err(TypedStateProofPackageError::Bundle);
        }
        reader.take(public_key_length)?;
    }
    let round_count = reader.u32()?;
    if round_count == 0 || round_count > 64 {
        return Err(TypedStateProofPackageError::Bundle);
    }
    let mut messages = Vec::with_capacity(round_count);
    for _ in 0..round_count {
        reader.take(8)?;
        let message_length = reader.u32()?;
        if message_length != 144 {
            return Err(TypedStateProofPackageError::Bundle);
        }
        let message = reader.take(message_length)?;
        let primary = message[16..80]
            .try_into()
            .map_err(|_| TypedStateProofPackageError::Bundle)?;
        let secondary = message[80..144]
            .try_into()
            .map_err(|_| TypedStateProofPackageError::Bundle)?;
        messages.push((primary, secondary));
        let commitment_count = usize::from(reader.u16()?);
        if commitment_count != contributor_count {
            return Err(TypedStateProofPackageError::Bundle);
        }
        for _ in 0..commitment_count {
            skip_signed_envelope(&mut reader)?;
        }
        let reveal_count = usize::from(reader.u16()?);
        if reveal_count != contributor_count {
            return Err(TypedStateProofPackageError::Bundle);
        }
        for _ in 0..reveal_count {
            skip_signed_envelope(&mut reader)?;
        }
        reader.take(64)?;
    }
    reader.take(64)?;
    if reader.offset != encoded.len() {
        return Err(TypedStateProofPackageError::Trailing);
    }
    Ok(messages)
}

fn verify_bundle_messages(
    transcript: &[u8],
    bundle: &crate::selected_challenge::SelectedChallengeBundle,
) -> Result<(), TypedStateProofPackageError> {
    let messages = transcript_messages(transcript)?;
    if messages.len() != bundle.fri_layer_roots.len() + 5
        || messages[0].0 != bundle.main_trace_root
        || messages[1].0 != bundle.interaction_trace_root
        || messages[2].0 != bundle.composition_root
        || messages[3].0 != bundle.oods_claims_commitment
        || messages[3].1 != bundle.fri_mask_root
        || messages[4].0 != bundle.fri_batch_derivation_commitment
        || messages[5..]
            .iter()
            .map(|message| message.0)
            .ne(bundle.fri_layer_roots.iter().copied())
    {
        return Err(TypedStateProofPackageError::Bundle);
    }
    Ok(())
}

/// Verify a fixed portable typed-state package and return only public bindings.
pub fn verify_typed_state_proof_package_v1(
    encoded: &[u8],
    key: TypedStateProofVerificationKey<'_>,
) -> Result<TypedStatePublicBindings, TypedStateProofPackageError> {
    let (governed_profile_code, governed_profile_label) =
        governed_profile(key.expected_profile_label)?;
    if !key
        .expected_program_commitment
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(TypedStateProofPackageError::Identity);
    }
    let sections = decode_portable_sections(encoded)?;
    let (program, public_inputs) = parse_selected_statement(sections.proof_package)?;
    validate_program_id(program)?;
    let report = validate_air_program(program)?;
    if report.public_input_count as usize != TYPED_STATE_PUBLIC_INPUT_COUNT
        || report.program_binary_commitment != key.expected_program_commitment
    {
        return Err(TypedStateProofPackageError::Program);
    }
    let parsed = parse_public_bindings(
        key.expected_profile_label,
        &report.program_binary_commitment,
        &public_inputs,
        sections.public_outputs,
        sections.sidecar,
    )?;

    let (proof_package_commitment, package) =
        verify_selected_proof_package(sections.proof_package, program, &public_inputs)?;
    if package.bundle.program_binary_commitment != report.program_binary_commitment {
        return Err(TypedStateProofPackageError::Bundle);
    }
    let transcript_commitment = verify_selected_public_coin_transcript(
        sections.transcript,
        sections.public_outputs,
        sections.sidecar,
        &package.bundle,
        program,
    )?;
    verify_bundle_messages(sections.transcript, &package.bundle)?;
    let expected_evidence = framed_hash(
        STATEMENT_EVIDENCE_DOMAIN,
        &[
            sections.public_outputs,
            sections.sidecar,
            &package.bundle.final_transcript_root,
            &package.bundle.schedule_commitment,
            &package.bundle.proof_suite_id,
        ],
    )?;
    if package.bundle.evidence_commitment != expected_evidence {
        return Err(TypedStateProofPackageError::Bundle);
    }

    let public_bytes = public_inputs
        .iter()
        .flat_map(|value| value.as_u32().to_be_bytes())
        .collect::<Vec<_>>();
    let public_input_digest = framed_hash(
        PROOF_DOMAIN,
        &[b"public-inputs", &public_bytes, sections.public_outputs],
    )?;
    let mut public_outputs = [[0_u8; 32]; 12];
    for (index, field) in public_outputs.iter_mut().enumerate() {
        field.copy_from_slice(&sections.public_outputs[index * 32..(index + 1) * 32]);
    }
    let sidecar = parsed.sidecar;
    let roots = parsed.authority_roots;
    Ok(TypedStatePublicBindings {
        governed_profile_code,
        governed_profile_label,
        profile_identity: sidecar.profile_identity,
        program_identity: sidecar.program_identity,
        program_commitment: sidecar.program_commitment,
        proof_suite_id: package.bundle.proof_suite_id,
        schedule_commitment: package.bundle.schedule_commitment,
        session_id: package.bundle.session_id,
        proof_package_commitment,
        transcript_commitment,
        public_input_digest,
        projection_digest: sidecar.projection_digest,
        public_outputs,
        epoch: parsed.epoch,
        sequence_before: parsed.sequence_before,
        sequence_after: parsed.sequence_after,
        settlement_root_before: roots[0][SETTLEMENT_ROOT_INDEX],
        settlement_root_after: roots[1][SETTLEMENT_ROOT_INDEX],
        asset_registry_root_before: roots[0][ASSET_REGISTRY_ROOT_INDEX],
        asset_registry_root_after: roots[1][ASSET_REGISTRY_ROOT_INDEX],
        scope_root_before: roots[0][SCOPE_ROOT_INDEX],
        scope_root_after: roots[1][SCOPE_ROOT_INDEX],
        benefit_root_before: roots[0][BENEFIT_ROOT_INDEX],
        benefit_root_after: roots[1][BENEFIT_ROOT_INDEX],
        obligation_root_before: roots[0][OBLIGATION_ROOT_INDEX],
        obligation_root_after: roots[1][OBLIGATION_ROOT_INDEX],
        ledger_root_before: roots[0][LEDGER_ROOT_INDEX],
        ledger_root_after: roots[1][LEDGER_ROOT_INDEX],
        operation_log_root_before: roots[0][OPERATION_LOG_ROOT_INDEX],
        operation_log_root_after: roots[1][OPERATION_LOG_ROOT_INDEX],
        payment_root_before: roots[0][PAYMENT_ROOT_INDEX],
        payment_root_after: roots[1][PAYMENT_ROOT_INDEX],
        replay_root_before: roots[0][REPLAY_ROOT_INDEX],
        replay_root_after: roots[1][REPLAY_ROOT_INDEX],
        state_root_before: roots[0][STATE_ROOT_INDEX],
        state_root_after: roots[1][STATE_ROOT_INDEX],
        transition_commitment: sidecar.transition,
    })
}

/// Cross-bind verifier-authenticated typed-state roots to the canonical outer statement.
///
/// The opaque outer `profileId` is supplied and compared separately from the
/// governed typed profile code/label. Direct equalities are settlement,
/// epoch/sequence, replay/nullifier, and payment roots. External ABI fields 1,
/// 3, and 4 are exact Stark252 compatibility aliases of settlement and replay;
/// field 9 is the alias of the outer sidecar batch commitment. The remaining
/// ABI fields are semantic/master-proof authorities and are deliberately not
/// equated to typed roots. In particular, `public_outputs` above is a private
/// typed-component projection grammar, not this external ABI.
pub fn verify_typed_state_outer_statement_v1(
    bindings: &TypedStatePublicBindings,
    layout_profile_code: u8,
    opaque_profile_id: &[u8; 64],
    public_fields: &[[u8; TYPED_STATE_OUTER_PUBLIC_FIELD_BYTES];
         TYPED_STATE_OUTER_PUBLIC_FIELD_COUNT],
    sidecar: &[u8; TYPED_STATE_OUTER_SIDECAR_BYTES],
) -> Result<(), TypedStateProofPackageError> {
    let governed = governed_profile(bindings.governed_profile_label.as_bytes())
        .map_err(|_| TypedStateProofPackageError::OuterStatement)?;
    let expected_profile_identity = framed_hash(
        PROFILE_IDENTITY_DOMAIN,
        &[bindings.governed_profile_label.as_bytes()],
    )?;
    if governed
        != (
            bindings.governed_profile_code,
            bindings.governed_profile_label,
        )
        || bindings.profile_identity != expected_profile_identity
        || layout_profile_code != bindings.governed_profile_code
        || !opaque_profile_id.iter().any(|byte| *byte != 0)
        || sidecar.get(..8) != Some(OUTER_SIDECAR_MAGIC)
        || sidecar.get(8..10) != Some(&1_u16.to_be_bytes())
        || sidecar.get(10..12) != Some(&0_u16.to_be_bytes())
        || sidecar.get(12..16) != Some(&(TYPED_STATE_OUTER_SIDECAR_BYTES as u32).to_be_bytes())
        || sidecar.get(16..80) != Some(opaque_profile_id)
        || sidecar[80..144].iter().any(|byte| *byte != 0)
    {
        return Err(TypedStateProofPackageError::OuterStatement);
    }
    for start in [16, 144, 208, 272, 360, 424, 488, 552, 616, 680] {
        if !sidecar[start..start + 64].iter().any(|byte| *byte != 0) {
            return Err(TypedStateProofPackageError::OuterStatement);
        }
    }

    let outer_settlement = outer_digest(sidecar, 272)?;
    let outer_replay_before = outer_digest(sidecar, 360)?;
    let outer_replay_after = outer_digest(sidecar, 424)?;
    let outer_payment_before = outer_digest(sidecar, 552)?;
    let outer_payment_after = outer_digest(sidecar, 616)?;
    let outer_batch = outer_digest(sidecar, 680)?;
    let outer_epoch = u64::from_be_bytes(
        sidecar[336..344]
            .try_into()
            .map_err(|_| TypedStateProofPackageError::OuterStatement)?,
    );
    let outer_sequence_before = u64::from_be_bytes(
        sidecar[344..352]
            .try_into()
            .map_err(|_| TypedStateProofPackageError::OuterStatement)?,
    );
    let outer_sequence_after = u64::from_be_bytes(
        sidecar[352..360]
            .try_into()
            .map_err(|_| TypedStateProofPackageError::OuterStatement)?,
    );
    if bindings.settlement_root_before != bindings.settlement_root_after
        || bindings.asset_registry_root_before != bindings.asset_registry_root_after
        || bindings.scope_root_before != bindings.scope_root_after
        || outer_settlement != bindings.settlement_root_before
        || outer_epoch != bindings.epoch
        || outer_sequence_before != bindings.sequence_before
        || outer_sequence_after != bindings.sequence_after
        || outer_replay_before != bindings.replay_root_before
        || outer_replay_after != bindings.replay_root_after
        || outer_payment_before != bindings.payment_root_before
        || outer_payment_after != bindings.payment_root_after
    {
        return Err(TypedStateProofPackageError::OuterStatement);
    }

    let mut protocol_version = [0_u8; 32];
    protocol_version[31] = 2;
    if public_fields[0] != protocol_version
        || public_fields
            .iter()
            .any(|field| *field >= STARK252_PRIME_BE)
        || public_fields[1] != stark252_compatibility_alias(&outer_settlement)
        || public_fields[3] != stark252_compatibility_alias(&outer_replay_before)
        || public_fields[4] != stark252_compatibility_alias(&outer_replay_after)
        || public_fields[9] != stark252_compatibility_alias(&outer_batch)
    {
        return Err(TypedStateProofPackageError::OuterStatement);
    }
    Ok(())
}

/// Verify the complete typed component and bind it to the same 448 byte-valued
/// M31 inputs used by the semantic v3 master-public composition: the ordered
/// 12×32 ABI bytes followed by sidecar strongGovernanceCommitment[64].
pub fn verify_typed_state_component_v3(
    encoded: &[u8],
    key: TypedStateProofVerificationKey<'_>,
    layout_profile_code: u8,
    opaque_profile_id: &[u8; 64],
    public_fields: &[[u8; TYPED_STATE_OUTER_PUBLIC_FIELD_BYTES];
         TYPED_STATE_OUTER_PUBLIC_FIELD_COUNT],
    sidecar: &[u8; TYPED_STATE_OUTER_SIDECAR_BYTES],
) -> Result<VerifiedTypedStateV3, TypedStateProofPackageError> {
    let bindings = verify_typed_state_proof_package_v1(encoded, key)?;
    verify_typed_state_outer_statement_v1(
        &bindings,
        layout_profile_code,
        opaque_profile_id,
        public_fields,
        sidecar,
    )?;
    let mut public_input_frame = b"BL/PQ512/WAVE2/SEMANTIC-V3-PUBLIC-INPUTS/v1\0".to_vec();
    public_input_frame.extend_from_slice(&448_u32.to_be_bytes());
    for byte in public_fields
        .iter()
        .flat_map(|field| field.iter())
        .chain(sidecar[488..552].iter())
    {
        public_input_frame.extend_from_slice(&u32::from(*byte).to_be_bytes());
    }
    let public_inputs_binding = BindingDigestV2::hash(BindingRoleV2::Payload, &public_input_frame)
        .map_err(|_| TypedStateProofPackageError::OuterStatement)?;
    let mut receipt = b"BL/PQ512/WAVE2/VERIFIED-TYPED-STATE-V3/v1\0".to_vec();
    receipt.push(bindings.governed_profile_code);
    receipt.extend_from_slice(bindings.program_commitment.as_slice());
    receipt.extend_from_slice(bindings.proof_package_commitment.as_slice());
    receipt.extend_from_slice(bindings.transcript_commitment.as_slice());
    receipt.extend_from_slice(bindings.transition_commitment.as_slice());
    receipt.extend_from_slice(public_inputs_binding.as_bytes());
    let receipt_binding = BindingDigestV2::hash(BindingRoleV2::Payload, &receipt)
        .map_err(|_| TypedStateProofPackageError::OuterStatement)?;
    Ok(VerifiedTypedStateV3 {
        governed_profile_code: bindings.governed_profile_code,
        public_inputs_binding,
        receipt_binding,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_state_proof_package_v1_size_is_exactly_derived() {
        assert_eq!(TYPED_STATE_PROOF_PACKAGE_PREFIX_BYTES, 1_156);
        assert_eq!(TYPED_STATE_PROOF_PACKAGE_BYTES, 83_887_236);
    }

    #[test]
    fn typed_state_proof_package_v1_rejects_before_inner_allocation() {
        let error = verify_typed_state_proof_package_v1(
            b"BLTSPK01",
            TypedStateProofVerificationKey {
                expected_profile_label: K512_PROFILE_LABEL,
                expected_program_commitment: [1_u8; 64],
            },
        )
        .expect_err("short package must fail");
        assert_eq!(error, TypedStateProofPackageError::Length);
    }

    #[test]
    fn typed_state_proof_package_v1_rejects_unpinned_profile_first() {
        let error = verify_typed_state_proof_package_v1(
            &[],
            TypedStateProofVerificationKey {
                expected_profile_label: b"K512_LOOKALIKE",
                expected_program_commitment: [1_u8; 64],
            },
        )
        .expect_err("unknown profile must fail");
        assert_eq!(error, TypedStateProofPackageError::Identity);
    }

    #[test]
    fn typed_state_proof_package_v1_sidecar_rejects_nonzero_reserved_bytes() {
        let mut sidecar = [0_u8; TYPED_STATE_SIDECAR_BYTES];
        sidecar[..8].copy_from_slice(TYPED_STATE_SIDECAR_MAGIC);
        sidecar[8..10].copy_from_slice(&TYPED_STATE_SIDECAR_VERSION.to_be_bytes());
        sidecar[12..16].copy_from_slice(&(TYPED_STATE_SIDECAR_BYTES as u32).to_be_bytes());
        for field in 0..11 {
            sidecar[16 + field * 64] = 1;
        }
        sidecar[TYPED_STATE_SIDECAR_BYTES - 1] = 1;
        assert_eq!(
            parse_sidecar(&sidecar),
            Err(TypedStateProofPackageError::Sidecar)
        );
    }

    #[test]
    fn typed_state_proof_package_v1_extracts_exact_public_roots() {
        fn put_digest(values: &mut [M31], start: usize, digest: &[u8; 64]) {
            for (offset, value) in digest.iter().enumerate() {
                values[start + offset] = M31::from_canonical(u32::from(*value)).unwrap();
            }
        }

        let profile = K512_PROFILE_LABEL;
        let program_commitment = [9_u8; 64];
        let mut authority_roots = [[[0_u8; 64]; AUTHORITY_ROOT_COUNT]; 2];
        let mut public_inputs = alloc::vec![M31::ZERO; TYPED_STATE_PUBLIC_INPUT_COUNT];
        for phase in 0..2 {
            let base = phase * AUTHORITY_PHASE_WIDTH;
            public_inputs[base] = M31::from_canonical(7).unwrap();
            public_inputs[base + 1] = M31::from_canonical(20 + phase as u32).unwrap();
            for root_index in 0..PAYMENT_ROOT_INDEX {
                let value = if root_index <= SCOPE_ROOT_INDEX {
                    10 + root_index as u8
                } else {
                    20 + (phase * 10 + root_index) as u8
                };
                authority_roots[phase][root_index] = [value; 64];
            }
            authority_roots[phase][PAYMENT_ROOT_INDEX] =
                payment_state_root(7, 20 + phase as u64, 0, &authority_roots[phase]);
            if phase == 0 {
                assert_eq!(
                    authority_roots[phase][PAYMENT_ROOT_INDEX],
                    [
                        0xb5, 0x88, 0x3b, 0xbb, 0xd9, 0xe0, 0x2a, 0x52, 0xe8, 0xb2, 0x24, 0x85,
                        0xc5, 0x6f, 0x50, 0xc8, 0x95, 0x9a, 0x61, 0xfb, 0x1a, 0x3c, 0x19, 0x3e,
                        0x66, 0x37, 0xbd, 0x2b, 0x31, 0xb8, 0x6a, 0x22, 0xe8, 0xdc, 0x6e, 0x3f,
                        0x3b, 0xa1, 0xd1, 0x62, 0xe3, 0x11, 0xa9, 0x40, 0x21, 0x28, 0x23, 0x4f,
                        0xd1, 0xa3, 0x81, 0xd3, 0x5c, 0x0c, 0x8d, 0x13, 0x53, 0xed, 0x8c, 0x19,
                        0x83, 0x55, 0x76, 0x2b,
                    ]
                );
            }
            authority_roots[phase][REPLAY_ROOT_INDEX] = [40 + phase as u8; 64];
            let mut state_hash = Sha3_512::new();
            state_hash.update(C0_STATE_ROOT_DOMAIN);
            state_hash.update(authority_roots[phase][PAYMENT_ROOT_INDEX]);
            state_hash.update(authority_roots[phase][REPLAY_ROOT_INDEX]);
            authority_roots[phase][STATE_ROOT_INDEX] = state_hash.finalize().into();
            for root_index in 0..AUTHORITY_ROOT_COUNT {
                put_digest(
                    &mut public_inputs,
                    base + AUTHORITY_ROOT_OFFSET + root_index * 64,
                    &authority_roots[phase][root_index],
                );
            }
        }
        put_digest(
            &mut public_inputs,
            SUMMARY_OFFSET,
            &authority_roots[0][REPLAY_ROOT_INDEX],
        );
        put_digest(
            &mut public_inputs,
            SUMMARY_OFFSET + 64,
            &authority_roots[1][REPLAY_ROOT_INDEX],
        );

        let public_bytes = public_inputs
            .iter()
            .flat_map(|value| value.as_u32().to_be_bytes())
            .collect::<Vec<_>>();
        let mut public_outputs = [0_u8; TYPED_STATE_PUBLIC_OUTPUT_BYTES];
        let mut projection = [[0_u8; 32]; 12];
        for (index, field) in projection.iter_mut().enumerate() {
            let index_byte = [index as u8];
            let digest = framed_hash(PROJECTION_DOMAIN, &[&index_byte, &public_bytes]).unwrap();
            field.copy_from_slice(&digest[..32]);
            public_outputs[index * 32..(index + 1) * 32].copy_from_slice(field);
        }
        let projection_parts = projection
            .iter()
            .map(|field| field.as_slice())
            .collect::<Vec<_>>();
        let projection_digest = framed_hash(PROJECTION_DIGEST_DOMAIN, &projection_parts).unwrap();
        let transition = framed_hash(
            TRANSITION_DOMAIN,
            &[
                profile,
                &7_u64.to_be_bytes(),
                &20_u64.to_be_bytes(),
                &21_u64.to_be_bytes(),
                &authority_roots[0][STATE_ROOT_INDEX],
                &authority_roots[1][STATE_ROOT_INDEX],
                &authority_roots[0][PAYMENT_ROOT_INDEX],
                &authority_roots[1][PAYMENT_ROOT_INDEX],
            ],
        )
        .unwrap();
        let fields = [
            framed_hash(PROFILE_IDENTITY_DOMAIN, &[profile]).unwrap(),
            framed_hash(PROGRAM_IDENTITY_DOMAIN, &[TYPED_STATE_PROGRAM_ID]).unwrap(),
            program_commitment,
            authority_roots[0][STATE_ROOT_INDEX],
            authority_roots[1][STATE_ROOT_INDEX],
            authority_roots[0][PAYMENT_ROOT_INDEX],
            authority_roots[1][PAYMENT_ROOT_INDEX],
            authority_roots[0][REPLAY_ROOT_INDEX],
            authority_roots[1][REPLAY_ROOT_INDEX],
            transition,
            projection_digest,
        ];
        let mut sidecar = alloc::vec![0_u8; TYPED_STATE_SIDECAR_BYTES];
        sidecar[..8].copy_from_slice(TYPED_STATE_SIDECAR_MAGIC);
        sidecar[8..10].copy_from_slice(&TYPED_STATE_SIDECAR_VERSION.to_be_bytes());
        sidecar[12..16].copy_from_slice(&(TYPED_STATE_SIDECAR_BYTES as u32).to_be_bytes());
        for (index, field) in fields.iter().enumerate() {
            sidecar[16 + index * 64..16 + (index + 1) * 64].copy_from_slice(field);
        }
        let parsed = parse_public_bindings(
            profile,
            &program_commitment,
            &public_inputs,
            &public_outputs,
            &sidecar,
        )
        .unwrap();
        assert_eq!(parsed.authority_roots, authority_roots);
        assert_eq!(parsed.sidecar.transition, transition);
        assert_eq!(parsed.epoch, 7);
        assert_eq!(parsed.sequence_before, 20);
        assert_eq!(parsed.sequence_after, 21);

        let mut component_mutation = public_inputs.clone();
        component_mutation[AUTHORITY_ROOT_OFFSET + BENEFIT_ROOT_INDEX * 64] =
            M31::from_canonical(99).unwrap();
        assert_eq!(
            parse_public_bindings(
                profile,
                &program_commitment,
                &component_mutation,
                &public_outputs,
                &sidecar,
            ),
            Err(TypedStateProofPackageError::PublicBinding)
        );
    }

    #[test]
    fn typed_state_proof_package_v1_maps_governed_profile_code_and_label() {
        assert_eq!(
            governed_profile(K128_PROFILE_LABEL),
            Ok((K128_PROFILE_CODE, "K128_CALIBRATION"))
        );
        assert_eq!(
            governed_profile(K512_PROFILE_LABEL),
            Ok((K512_PROFILE_CODE, "K512_CALIBRATION"))
        );
        assert_eq!(
            governed_profile(b"K256_DESIGN_POINT"),
            Err(TypedStateProofPackageError::Identity)
        );
    }

    #[test]
    fn typed_state_proof_package_v1_cross_binds_exact_outer_fields() {
        assert_eq!(
            stark252_compatibility_alias(&[0xff_u8; 64]),
            [
                0x07, 0xff, 0xd4, 0xab, 0x5e, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]
        );

        let opaque_profile_id = [90_u8; 64];
        let settlement = [10_u8; 64];
        let replay_before = [20_u8; 64];
        let replay_after = [21_u8; 64];
        let payment_before = [22_u8; 64];
        let payment_after = [23_u8; 64];
        let outer_batch = [24_u8; 64];
        let bindings = TypedStatePublicBindings {
            governed_profile_code: K128_PROFILE_CODE,
            governed_profile_label: "K128_CALIBRATION",
            profile_identity: framed_hash(PROFILE_IDENTITY_DOMAIN, &[K128_PROFILE_LABEL]).unwrap(),
            program_identity: [2_u8; 64],
            program_commitment: [3_u8; 64],
            proof_suite_id: [4_u8; 64],
            schedule_commitment: [5_u8; 64],
            session_id: [6_u8; 64],
            proof_package_commitment: [7_u8; 64],
            transcript_commitment: [8_u8; 64],
            public_input_digest: [9_u8; 64],
            projection_digest: [10_u8; 64],
            public_outputs: [[1_u8; 32]; 12],
            epoch: 7,
            sequence_before: 30,
            sequence_after: 31,
            settlement_root_before: settlement,
            settlement_root_after: settlement,
            asset_registry_root_before: [11_u8; 64],
            asset_registry_root_after: [11_u8; 64],
            scope_root_before: [12_u8; 64],
            scope_root_after: [12_u8; 64],
            benefit_root_before: [13_u8; 64],
            benefit_root_after: [14_u8; 64],
            obligation_root_before: [15_u8; 64],
            obligation_root_after: [16_u8; 64],
            ledger_root_before: [17_u8; 64],
            ledger_root_after: [18_u8; 64],
            operation_log_root_before: [19_u8; 64],
            operation_log_root_after: [25_u8; 64],
            payment_root_before: payment_before,
            payment_root_after: payment_after,
            replay_root_before: replay_before,
            replay_root_after: replay_after,
            state_root_before: [26_u8; 64],
            state_root_after: [27_u8; 64],
            transition_commitment: [28_u8; 64],
        };
        let mut sidecar = [0_u8; TYPED_STATE_OUTER_SIDECAR_BYTES];
        sidecar[..8].copy_from_slice(OUTER_SIDECAR_MAGIC);
        sidecar[8..10].copy_from_slice(&1_u16.to_be_bytes());
        sidecar[12..16].copy_from_slice(&(TYPED_STATE_OUTER_SIDECAR_BYTES as u32).to_be_bytes());
        sidecar[16..80].copy_from_slice(&opaque_profile_id);
        for (start, value) in [(144, 31_u8), (208, 32), (488, 33)] {
            sidecar[start..start + 64].fill(value);
        }
        sidecar[272..336].copy_from_slice(&settlement);
        sidecar[336..344].copy_from_slice(&bindings.epoch.to_be_bytes());
        sidecar[344..352].copy_from_slice(&bindings.sequence_before.to_be_bytes());
        sidecar[352..360].copy_from_slice(&bindings.sequence_after.to_be_bytes());
        sidecar[360..424].copy_from_slice(&replay_before);
        sidecar[424..488].copy_from_slice(&replay_after);
        sidecar[552..616].copy_from_slice(&payment_before);
        sidecar[616..680].copy_from_slice(&payment_after);
        sidecar[680..744].copy_from_slice(&outer_batch);

        let mut fields =
            [[0_u8; TYPED_STATE_OUTER_PUBLIC_FIELD_BYTES]; TYPED_STATE_OUTER_PUBLIC_FIELD_COUNT];
        fields[0][31] = 2;
        fields[1] = stark252_compatibility_alias(&settlement);
        fields[3] = stark252_compatibility_alias(&replay_before);
        fields[4] = stark252_compatibility_alias(&replay_after);
        fields[9] = stark252_compatibility_alias(&outer_batch);
        assert_eq!(
            verify_typed_state_outer_statement_v1(
                &bindings,
                K128_PROFILE_CODE,
                &opaque_profile_id,
                &fields,
                &sidecar,
            ),
            Ok(())
        );

        assert_eq!(
            verify_typed_state_outer_statement_v1(
                &bindings,
                K512_PROFILE_CODE,
                &opaque_profile_id,
                &fields,
                &sidecar,
            ),
            Err(TypedStateProofPackageError::OuterStatement)
        );
        let mut label_mutation = bindings.clone();
        label_mutation.governed_profile_label = "K512_CALIBRATION";
        assert_eq!(
            verify_typed_state_outer_statement_v1(
                &label_mutation,
                K128_PROFILE_CODE,
                &opaque_profile_id,
                &fields,
                &sidecar,
            ),
            Err(TypedStateProofPackageError::OuterStatement)
        );
        let mut alias_mutation = fields;
        alias_mutation[3][31] ^= 1;
        assert_eq!(
            verify_typed_state_outer_statement_v1(
                &bindings,
                K128_PROFILE_CODE,
                &opaque_profile_id,
                &alias_mutation,
                &sidecar,
            ),
            Err(TypedStateProofPackageError::OuterStatement)
        );
        let mut payment_mutation = sidecar;
        payment_mutation[552] ^= 1;
        assert_eq!(
            verify_typed_state_outer_statement_v1(
                &bindings,
                K128_PROFILE_CODE,
                &opaque_profile_id,
                &fields,
                &payment_mutation,
            ),
            Err(TypedStateProofPackageError::OuterStatement)
        );
    }
}
