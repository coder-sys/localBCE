//! Arithmetic boundary for the proof-native semantic/H4 bridge.
//!
//! This module deliberately does not parse proof bytes and does not turn a
//! caller boolean into verifier authority.  The eventual version-3 verifier
//! may call it only after the selected semantic verifier has authenticated the
//! semantic and quotient openings and the portable H4 verifier has
//! authenticated its sparse openings, input Booleanity, global padding, mask
//! inventory, and transcript order.  Its single job is to recheck the two
//! Circle-domain divisibility identities at the authenticated OODS point and
//! its Fp8 conjugate.

#[cfg(test)]
use alloc::vec::Vec;
use sha3::{Digest, Sha3_512};

use crate::{field::Fp16, master_commitments::Profile, oods::CirclePoint};

pub const SEMANTIC_H4_BRIDGE_DOMAIN: &[u8] =
    b"BL/PQ512/WAVE1A/SEMANTIC-H4-BRIDGE-VERIFIED-DIVISIBILITY/v3\0";
pub const SEMANTIC_H4_BRIDGE_CLAIMS_MAGIC: &[u8; 8] = b"BLB4DV01";
pub const SEMANTIC_H4_BRIDGE_CLAIMS_VERSION: u16 = 1;
pub const SEMANTIC_H4_BRIDGE_CLAIMS_HEADER_BYTES: usize = 20;
pub const SEMANTIC_H4_BRIDGE_CLAIMS_DIGEST_COUNT: usize = 22;
pub const SEMANTIC_H4_BRIDGE_CLAIMS_BYTES: usize = SEMANTIC_H4_BRIDGE_CLAIMS_HEADER_BYTES
    + SEMANTIC_H4_BRIDGE_CLAIMS_DIGEST_COUNT * 64
    + 4 * 64
    + 2 * (1 + 8 * 64);

const K128_BRIDGE_PROGRAM_COMMITMENT_HEX: &[u8; 128] =
    b"2b6c174d9ce183e1f6e5e2bc51e4c411f55ba5997aa2f87b81ca062c8473e33be60406d97d2dbd17958bf8fdbe89ab92b44cdb8acf48a09ca879310a635cd29f";
const K512_BRIDGE_PROGRAM_COMMITMENT_HEX: &[u8; 128] =
    b"b1962cd2423238664861bc6f2551c0da9b362febcfc9b48e5ac8b2dda613973d7ec080dd3ad4e5ffcc9978d3bd8b395a9677c9b7be0fefdfb9fdeed4b4d1c966";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BridgeEvaluationPair {
    pub at_point: Fp16,
    pub at_conjugate: Fp16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BridgeGroupClaims {
    pub witness_log_size: u8,
    /// Existing selected-Circle masked semantic opening `S + Z_H M_sem`.
    pub semantic_masked: BridgeEvaluationPair,
    /// Independent Construction-8.2 carrier opening `C`.
    pub semantic_carrier: BridgeEvaluationPair,
    /// Portable H4 opening `H + Z_H N`.
    pub h4_masked: BridgeEvaluationPair,
    /// Direct, pre-OODS degree-bounded coefficient vector evaluated by the verifier.
    pub quotient: BridgeEvaluationPair,
}

/// Inputs already authenticated by the component verifiers.
///
/// The type is crate-private so no outer application caller can construct a
/// success-shaped object. The complete H4 and selected-proof verifiers remain
/// responsible for creating it from proof bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedSemanticH4BridgeClaims {
    pub profile: Profile,
    pub bridge_program_commitment: [u8; 64],
    pub semantic_program_commitment: [u8; 64],
    pub h4_program_commitment: [u8; 64],
    pub semantic_main_root: [u8; 64],
    pub semantic_interaction_root: [u8; 64],
    pub semantic_composition_root: [u8; 64],
    pub h4_source_root: [u8; 64],
    /// Typed aggregate over C_message, C_digest, N_message, N_digest base roots.
    pub bridge_mask_base_aggregate_root: [u8; 64],
    /// Typed aggregate over the four independent response-pad roots.
    pub bridge_mask_pad_aggregate_root: [u8; 64],
    /// Typed aggregate over the four public randomized answer roots.
    pub bridge_mask_answer_aggregate_root: [u8; 64],
    pub message_direct_quotient_commitment: [u8; 64],
    pub digest_direct_quotient_commitment: [u8; 64],
    pub post_z_primitive_response_oracle_root: [u8; 64],
    pub post_z_primitive_claim_vector_commitment: [u8; 64],
    pub semantic_continuation_final_root: [u8; 64],
    pub composite_session_id: [u8; 64],
    pub composite_schedule_commitment: [u8; 64],
    pub parent_round_901_transcript_root: [u8; 64],
    pub parent_final_transcript_root: [u8; 64],
    pub h4_booleanity_receipt_commitment: [u8; 64],
    pub h4_global_padding_receipt_commitment: [u8; 64],
    pub bridge_privacy_ledger_commitment: [u8; 64],
    pub bridge_alpha: Fp16,
    pub completion_challenge: Fp16,
    pub oods_point: CirclePoint,
    pub message: BridgeGroupClaims,
    pub digest: BridgeGroupClaims,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedBridgeDivisibility {
    pub commitment: [u8; 64],
    pub profile: Profile,
    post_z_response_oracle_root: [u8; 64],
    post_z_claim_vector_commitment: [u8; 64],
    completion_challenge: Fp16,
}

impl VerifiedBridgeDivisibility {
    pub const fn profile(&self) -> Profile {
        self.profile
    }

    pub const fn commitment(&self) -> &[u8; 64] {
        &self.commitment
    }

    pub const fn post_z_response_oracle_root(&self) -> &[u8; 64] {
        &self.post_z_response_oracle_root
    }

    pub const fn post_z_claim_vector_commitment(&self) -> &[u8; 64] {
        &self.post_z_claim_vector_commitment
    }

    pub const fn completion_challenge(&self) -> Fp16 {
        self.completion_challenge
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticH4BridgeError {
    Encoding,
    UnsupportedProfile,
    ProgramIdentity,
    ZeroCommitment,
    ZeroChallenge,
    Point,
    Geometry,
    MessageDivisibility,
    DigestDivisibility,
}

fn profile_from_code(value: u8) -> Result<Profile, SemanticH4BridgeError> {
    match value {
        1 => Ok(Profile::K128Calibration),
        3 => Ok(Profile::K512Calibration),
        _ => Err(SemanticH4BridgeError::UnsupportedProfile),
    }
}

fn claim_digest(encoded: &[u8], offset: &mut usize) -> Result<[u8; 64], SemanticH4BridgeError> {
    let end = (*offset)
        .checked_add(64)
        .ok_or(SemanticH4BridgeError::Encoding)?;
    let value = encoded
        .get(*offset..end)
        .ok_or(SemanticH4BridgeError::Encoding)?;
    *offset = end;
    value
        .try_into()
        .map_err(|_| SemanticH4BridgeError::Encoding)
}

fn claim_field(encoded: &[u8], offset: &mut usize) -> Result<Fp16, SemanticH4BridgeError> {
    let bytes = claim_digest(encoded, offset)?;
    Fp16::decode(&bytes).map_err(|_| SemanticH4BridgeError::Encoding)
}

fn claim_group(
    encoded: &[u8],
    offset: &mut usize,
) -> Result<BridgeGroupClaims, SemanticH4BridgeError> {
    let witness_log_size = *encoded
        .get(*offset)
        .ok_or(SemanticH4BridgeError::Encoding)?;
    *offset = (*offset)
        .checked_add(1)
        .ok_or(SemanticH4BridgeError::Encoding)?;
    let mut pair = || -> Result<BridgeEvaluationPair, SemanticH4BridgeError> {
        Ok(BridgeEvaluationPair {
            at_point: claim_field(encoded, offset)?,
            at_conjugate: claim_field(encoded, offset)?,
        })
    };
    Ok(BridgeGroupClaims {
        witness_log_size,
        semantic_masked: pair()?,
        semantic_carrier: pair()?,
        h4_masked: pair()?,
        quotient: pair()?,
    })
}

#[cfg(test)]
fn encode_claim_group(output: &mut Vec<u8>, group: BridgeGroupClaims) {
    output.push(group.witness_log_size);
    for pair in [
        group.semantic_masked,
        group.semantic_carrier,
        group.h4_masked,
        group.quotient,
    ] {
        output.extend_from_slice(&pair.at_point.encode());
        output.extend_from_slice(&pair.at_conjugate.encode());
    }
}

#[cfg(test)]
fn encode_claims(claims: &AuthenticatedSemanticH4BridgeClaims) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(SEMANTIC_H4_BRIDGE_CLAIMS_BYTES);
    encoded.extend_from_slice(SEMANTIC_H4_BRIDGE_CLAIMS_MAGIC);
    encoded.extend_from_slice(&SEMANTIC_H4_BRIDGE_CLAIMS_VERSION.to_be_bytes());
    encoded.extend_from_slice(&[0_u8; 2]);
    encoded.push(claims.profile as u8);
    encoded.extend_from_slice(&[0_u8; 7]);
    for digest in [
        claims.bridge_program_commitment,
        claims.semantic_program_commitment,
        claims.h4_program_commitment,
        claims.semantic_main_root,
        claims.semantic_interaction_root,
        claims.semantic_composition_root,
        claims.h4_source_root,
        claims.bridge_mask_base_aggregate_root,
        claims.bridge_mask_pad_aggregate_root,
        claims.bridge_mask_answer_aggregate_root,
        claims.message_direct_quotient_commitment,
        claims.digest_direct_quotient_commitment,
        claims.post_z_primitive_response_oracle_root,
        claims.post_z_primitive_claim_vector_commitment,
        claims.semantic_continuation_final_root,
        claims.composite_session_id,
        claims.composite_schedule_commitment,
        claims.parent_round_901_transcript_root,
        claims.parent_final_transcript_root,
        claims.h4_booleanity_receipt_commitment,
        claims.h4_global_padding_receipt_commitment,
        claims.bridge_privacy_ledger_commitment,
    ] {
        encoded.extend_from_slice(&digest);
    }
    encoded.extend_from_slice(&claims.bridge_alpha.encode());
    encoded.extend_from_slice(&claims.completion_challenge.encode());
    encoded.extend_from_slice(&claims.oods_point.x.encode());
    encoded.extend_from_slice(&claims.oods_point.y.encode());
    encode_claim_group(&mut encoded, claims.message);
    encode_claim_group(&mut encoded, claims.digest);
    encoded
}

fn decode_claims(
    encoded: &[u8],
) -> Result<AuthenticatedSemanticH4BridgeClaims, SemanticH4BridgeError> {
    if encoded.len() != SEMANTIC_H4_BRIDGE_CLAIMS_BYTES
        || encoded.get(..8) != Some(SEMANTIC_H4_BRIDGE_CLAIMS_MAGIC)
        || encoded.get(8..10) != Some(&SEMANTIC_H4_BRIDGE_CLAIMS_VERSION.to_be_bytes())
        || encoded.get(10..12) != Some(&[0_u8; 2])
        || encoded.get(13..20) != Some(&[0_u8; 7])
    {
        return Err(SemanticH4BridgeError::Encoding);
    }
    let profile = profile_from_code(encoded[12])?;
    let mut offset = SEMANTIC_H4_BRIDGE_CLAIMS_HEADER_BYTES;
    let bridge_program_commitment = claim_digest(encoded, &mut offset)?;
    let semantic_program_commitment = claim_digest(encoded, &mut offset)?;
    let h4_program_commitment = claim_digest(encoded, &mut offset)?;
    let semantic_main_root = claim_digest(encoded, &mut offset)?;
    let semantic_interaction_root = claim_digest(encoded, &mut offset)?;
    let semantic_composition_root = claim_digest(encoded, &mut offset)?;
    let h4_source_root = claim_digest(encoded, &mut offset)?;
    let bridge_mask_base_aggregate_root = claim_digest(encoded, &mut offset)?;
    let bridge_mask_pad_aggregate_root = claim_digest(encoded, &mut offset)?;
    let bridge_mask_answer_aggregate_root = claim_digest(encoded, &mut offset)?;
    let message_direct_quotient_commitment = claim_digest(encoded, &mut offset)?;
    let digest_direct_quotient_commitment = claim_digest(encoded, &mut offset)?;
    let post_z_primitive_response_oracle_root = claim_digest(encoded, &mut offset)?;
    let post_z_primitive_claim_vector_commitment = claim_digest(encoded, &mut offset)?;
    let semantic_continuation_final_root = claim_digest(encoded, &mut offset)?;
    let composite_session_id = claim_digest(encoded, &mut offset)?;
    let composite_schedule_commitment = claim_digest(encoded, &mut offset)?;
    let parent_round_901_transcript_root = claim_digest(encoded, &mut offset)?;
    let parent_final_transcript_root = claim_digest(encoded, &mut offset)?;
    let h4_booleanity_receipt_commitment = claim_digest(encoded, &mut offset)?;
    let h4_global_padding_receipt_commitment = claim_digest(encoded, &mut offset)?;
    let bridge_privacy_ledger_commitment = claim_digest(encoded, &mut offset)?;
    let bridge_alpha = claim_field(encoded, &mut offset)?;
    let completion_challenge = claim_field(encoded, &mut offset)?;
    let oods_point = CirclePoint {
        x: claim_field(encoded, &mut offset)?,
        y: claim_field(encoded, &mut offset)?,
    };
    let message = claim_group(encoded, &mut offset)?;
    let digest = claim_group(encoded, &mut offset)?;
    if offset != encoded.len() {
        return Err(SemanticH4BridgeError::Encoding);
    }
    Ok(AuthenticatedSemanticH4BridgeClaims {
        profile,
        bridge_program_commitment,
        semantic_program_commitment,
        h4_program_commitment,
        semantic_main_root,
        semantic_interaction_root,
        semantic_composition_root,
        h4_source_root,
        bridge_mask_base_aggregate_root,
        bridge_mask_pad_aggregate_root,
        bridge_mask_answer_aggregate_root,
        message_direct_quotient_commitment,
        digest_direct_quotient_commitment,
        post_z_primitive_response_oracle_root,
        post_z_primitive_claim_vector_commitment,
        semantic_continuation_final_root,
        composite_session_id,
        composite_schedule_commitment,
        parent_round_901_transcript_root,
        parent_final_transcript_root,
        h4_booleanity_receipt_commitment,
        h4_global_padding_receipt_commitment,
        bridge_privacy_ledger_commitment,
        bridge_alpha,
        completion_challenge,
        oods_point,
        message,
        digest,
    })
}

fn expected_bridge_program(profile: Profile) -> Result<[u8; 64], SemanticH4BridgeError> {
    let encoded = match profile {
        Profile::K128Calibration => K128_BRIDGE_PROGRAM_COMMITMENT_HEX,
        Profile::K512Calibration => K512_BRIDGE_PROGRAM_COMMITMENT_HEX,
        Profile::K256DesignPoint => return Err(SemanticH4BridgeError::UnsupportedProfile),
    };
    let mut result = [0_u8; 64];
    for (index, byte) in result.iter_mut().enumerate() {
        let high = hex_nibble(encoded[2 * index])?;
        let low = hex_nibble(encoded[2 * index + 1])?;
        *byte = (high << 4) | low;
    }
    Ok(result)
}

fn hex_nibble(value: u8) -> Result<u8, SemanticH4BridgeError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(SemanticH4BridgeError::ProgramIdentity),
    }
}

fn expected_witness_logs(profile: Profile) -> Result<(u8, u8), SemanticH4BridgeError> {
    match profile {
        Profile::K128Calibration => Ok((23, 22)),
        Profile::K512Calibration => Ok((25, 24)),
        Profile::K256DesignPoint => Err(SemanticH4BridgeError::UnsupportedProfile),
    }
}

fn nonzero(value: &[u8; 64]) -> bool {
    value.iter().any(|byte| *byte != 0)
}

fn validate_point(point: CirclePoint) -> Result<(), SemanticH4BridgeError> {
    if point.x.square() + point.y.square() != Fp16::ONE
        || (point.x.is_in_fp8_subfield() && point.y.is_in_fp8_subfield())
    {
        return Err(SemanticH4BridgeError::Point);
    }
    Ok(())
}

/// Evaluate the canonical Circle witness-domain vanishing polynomial over
/// Fp16.  This is the exact extension-field lift of
/// `trace_mask::canonical_coset_vanishing`.
fn circle_vanishing_at(point: CirclePoint, log_size: u8) -> Result<Fp16, SemanticH4BridgeError> {
    if log_size == 0 || log_size > 30 {
        return Err(SemanticH4BridgeError::Geometry);
    }
    let mut value = point.x;
    for _ in 1..log_size {
        let squared = value.square();
        value = squared + squared - Fp16::ONE;
    }
    Ok(value)
}

fn conjugate(point: CirclePoint) -> CirclePoint {
    CirclePoint {
        x: point.x.conjugate(),
        y: point.y.conjugate(),
    }
}

fn verify_group(
    point: CirclePoint,
    claims: BridgeGroupClaims,
    expected_log_size: u8,
    error: SemanticH4BridgeError,
) -> Result<(), SemanticH4BridgeError> {
    if claims.witness_log_size != expected_log_size {
        return Err(SemanticH4BridgeError::Geometry);
    }
    let at_point = circle_vanishing_at(point, expected_log_size)?;
    let at_conjugate = circle_vanishing_at(conjugate(point), expected_log_size)?;
    let semantic_at_point =
        claims.semantic_masked.at_point + at_point * claims.semantic_carrier.at_point;
    let semantic_at_conjugate =
        claims.semantic_masked.at_conjugate + at_conjugate * claims.semantic_carrier.at_conjugate;
    if semantic_at_point - claims.h4_masked.at_point != at_point * claims.quotient.at_point
        || semantic_at_conjugate - claims.h4_masked.at_conjugate
            != at_conjugate * claims.quotient.at_conjugate
    {
        return Err(error);
    }
    Ok(())
}

fn receipt_commitment(claims: &AuthenticatedSemanticH4BridgeClaims) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(SEMANTIC_H4_BRIDGE_DOMAIN);
    hash.update([claims.profile as u8]);
    for digest in [
        &claims.bridge_program_commitment,
        &claims.semantic_program_commitment,
        &claims.h4_program_commitment,
        &claims.semantic_main_root,
        &claims.semantic_interaction_root,
        &claims.semantic_composition_root,
        &claims.h4_source_root,
        &claims.bridge_mask_base_aggregate_root,
        &claims.bridge_mask_pad_aggregate_root,
        &claims.bridge_mask_answer_aggregate_root,
        &claims.message_direct_quotient_commitment,
        &claims.digest_direct_quotient_commitment,
        &claims.post_z_primitive_response_oracle_root,
        &claims.post_z_primitive_claim_vector_commitment,
        &claims.semantic_continuation_final_root,
        &claims.composite_session_id,
        &claims.composite_schedule_commitment,
        &claims.parent_round_901_transcript_root,
        &claims.parent_final_transcript_root,
        &claims.h4_booleanity_receipt_commitment,
        &claims.h4_global_padding_receipt_commitment,
        &claims.bridge_privacy_ledger_commitment,
    ] {
        hash.update(digest);
    }
    hash.update(claims.bridge_alpha.encode());
    hash.update(claims.completion_challenge.encode());
    hash.update(claims.oods_point.x.encode());
    hash.update(claims.oods_point.y.encode());
    for group in [claims.message, claims.digest] {
        hash.update([group.witness_log_size]);
        for pair in [
            group.semantic_masked,
            group.semantic_carrier,
            group.h4_masked,
            group.quotient,
        ] {
            hash.update(pair.at_point.encode());
            hash.update(pair.at_conjugate.encode());
        }
    }
    hash.finalize().into()
}

/// Recheck the two masked bridge identities after component verification.
///
/// A returned value is only a divisibility receipt.  It is not a complete H4,
/// semantic, privacy, transcript, aggregate, production, or activation
/// result.
pub(crate) fn verify_authenticated_semantic_h4_bridge(
    claims: &AuthenticatedSemanticH4BridgeClaims,
) -> Result<VerifiedBridgeDivisibility, SemanticH4BridgeError> {
    let expected_program = expected_bridge_program(claims.profile)?;
    if claims.bridge_program_commitment != expected_program {
        return Err(SemanticH4BridgeError::ProgramIdentity);
    }
    let commitments = [
        &claims.semantic_program_commitment,
        &claims.h4_program_commitment,
        &claims.semantic_main_root,
        &claims.semantic_interaction_root,
        &claims.semantic_composition_root,
        &claims.h4_source_root,
        &claims.bridge_mask_base_aggregate_root,
        &claims.bridge_mask_pad_aggregate_root,
        &claims.bridge_mask_answer_aggregate_root,
        &claims.message_direct_quotient_commitment,
        &claims.digest_direct_quotient_commitment,
        &claims.post_z_primitive_response_oracle_root,
        &claims.post_z_primitive_claim_vector_commitment,
        &claims.semantic_continuation_final_root,
        &claims.composite_session_id,
        &claims.composite_schedule_commitment,
        &claims.parent_round_901_transcript_root,
        &claims.parent_final_transcript_root,
        &claims.h4_booleanity_receipt_commitment,
        &claims.h4_global_padding_receipt_commitment,
        &claims.bridge_privacy_ledger_commitment,
    ];
    if commitments.into_iter().any(|value| !nonzero(value)) {
        return Err(SemanticH4BridgeError::ZeroCommitment);
    }
    if claims.bridge_alpha == Fp16::ZERO {
        return Err(SemanticH4BridgeError::ZeroChallenge);
    }
    validate_point(claims.oods_point)?;
    let (message_log, digest_log) = expected_witness_logs(claims.profile)?;
    verify_group(
        claims.oods_point,
        claims.message,
        message_log,
        SemanticH4BridgeError::MessageDivisibility,
    )?;
    verify_group(
        claims.oods_point,
        claims.digest,
        digest_log,
        SemanticH4BridgeError::DigestDivisibility,
    )?;
    Ok(VerifiedBridgeDivisibility {
        commitment: receipt_commitment(claims),
        profile: claims.profile,
        post_z_response_oracle_root: claims.post_z_primitive_response_oracle_root,
        post_z_claim_vector_commitment: claims.post_z_primitive_claim_vector_commitment,
        completion_challenge: claims.completion_challenge,
    })
}

/// Decode the canonical post-Z bridge claims and run the native divisibility
/// verifier. The wire object is only untrusted input; this function is the
/// sole public path from serialized claims to a bridge receipt, and it never
/// accepts a caller-supplied receipt commitment or success flag.
pub fn verify_semantic_h4_bridge_claims_v1(
    encoded: &[u8],
) -> Result<VerifiedBridgeDivisibility, SemanticH4BridgeError> {
    let claims = decode_claims(encoded)?;
    verify_authenticated_semantic_h4_bridge(&claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oods::{OodsParameter, stereographic_circle_point};

    fn field(value: u32) -> Fp16 {
        Fp16::from_coefficients([value, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap()
    }

    fn point() -> CirclePoint {
        let mut coordinates = [0_u32; 16];
        coordinates[0] = 9;
        coordinates[8] = 1;
        let parameter =
            OodsParameter::try_from_element(Fp16::from_coefficients(coordinates).unwrap()).unwrap();
        stereographic_circle_point(parameter).unwrap()
    }

    fn honest_group(point: CirclePoint, log_size: u8, seed: u32) -> BridgeGroupClaims {
        let conjugate_point = conjugate(point);
        let quotient = BridgeEvaluationPair {
            at_point: field(seed + 1),
            at_conjugate: field(seed + 2),
        };
        let semantic_carrier = BridgeEvaluationPair {
            at_point: field(seed + 5),
            at_conjugate: field(seed + 6),
        };
        let h4_masked = BridgeEvaluationPair {
            at_point: field(seed + 3),
            at_conjugate: field(seed + 4),
        };
        let semantic_masked = BridgeEvaluationPair {
            at_point: h4_masked.at_point
                + circle_vanishing_at(point, log_size).unwrap()
                    * (quotient.at_point - semantic_carrier.at_point),
            at_conjugate: h4_masked.at_conjugate
                + circle_vanishing_at(conjugate_point, log_size).unwrap()
                    * (quotient.at_conjugate - semantic_carrier.at_conjugate),
        };
        BridgeGroupClaims {
            witness_log_size: log_size,
            semantic_masked,
            semantic_carrier,
            h4_masked,
            quotient,
        }
    }

    fn claims(profile: Profile) -> AuthenticatedSemanticH4BridgeClaims {
        let point = point();
        let (message_log, digest_log) = expected_witness_logs(profile).unwrap();
        AuthenticatedSemanticH4BridgeClaims {
            profile,
            bridge_program_commitment: expected_bridge_program(profile).unwrap(),
            semantic_program_commitment: [1; 64],
            h4_program_commitment: [2; 64],
            semantic_main_root: [3; 64],
            semantic_interaction_root: [4; 64],
            semantic_composition_root: [5; 64],
            h4_source_root: [6; 64],
            bridge_mask_base_aggregate_root: [7; 64],
            bridge_mask_pad_aggregate_root: [8; 64],
            bridge_mask_answer_aggregate_root: [9; 64],
            message_direct_quotient_commitment: [10; 64],
            digest_direct_quotient_commitment: [11; 64],
            post_z_primitive_response_oracle_root: [12; 64],
            post_z_primitive_claim_vector_commitment: [13; 64],
            semantic_continuation_final_root: [14; 64],
            composite_session_id: [15; 64],
            composite_schedule_commitment: [16; 64],
            parent_round_901_transcript_root: [17; 64],
            parent_final_transcript_root: [18; 64],
            h4_booleanity_receipt_commitment: [19; 64],
            h4_global_padding_receipt_commitment: [20; 64],
            bridge_privacy_ledger_commitment: [21; 64],
            bridge_alpha: field(22),
            completion_challenge: field(23),
            oods_point: point,
            message: honest_group(point, message_log, 20),
            digest: honest_group(point, digest_log, 40),
        }
    }

    #[test]
    fn both_profiles_and_both_conjugate_identities_verify() {
        for profile in [Profile::K128Calibration, Profile::K512Calibration] {
            let input = claims(profile);
            let receipt = verify_authenticated_semantic_h4_bridge(&input).unwrap();
            let encoded = encode_claims(&input);
            let decoded_receipt = verify_semantic_h4_bridge_claims_v1(&encoded).unwrap();
            assert_eq!(receipt.profile(), profile);
            assert_eq!(decoded_receipt, receipt);
            assert_eq!(
                receipt.post_z_response_oracle_root(),
                &input.post_z_primitive_response_oracle_root
            );
            assert_eq!(
                receipt.post_z_claim_vector_commitment(),
                &input.post_z_primitive_claim_vector_commitment
            );
            assert_eq!(receipt.completion_challenge(), input.completion_challenge);
            assert!(nonzero(receipt.commitment()));
        }
    }

    #[test]
    fn message_digest_conjugate_geometry_and_context_mutations_reject() {
        let original = claims(Profile::K128Calibration);

        let mut changed = original.clone();
        changed.message.semantic_masked.at_point =
            changed.message.semantic_masked.at_point + Fp16::ONE;
        assert_eq!(
            verify_authenticated_semantic_h4_bridge(&changed),
            Err(SemanticH4BridgeError::MessageDivisibility)
        );

        let mut changed = original.clone();
        changed.message.semantic_carrier.at_conjugate =
            changed.message.semantic_carrier.at_conjugate + Fp16::ONE;
        assert_eq!(
            verify_authenticated_semantic_h4_bridge(&changed),
            Err(SemanticH4BridgeError::MessageDivisibility)
        );

        let mut changed = original.clone();
        changed.digest.quotient.at_conjugate = changed.digest.quotient.at_conjugate + Fp16::ONE;
        assert_eq!(
            verify_authenticated_semantic_h4_bridge(&changed),
            Err(SemanticH4BridgeError::DigestDivisibility)
        );

        let mut changed = original.clone();
        changed.message.witness_log_size += 1;
        assert_eq!(
            verify_authenticated_semantic_h4_bridge(&changed),
            Err(SemanticH4BridgeError::Geometry)
        );

        let mut changed = original.clone();
        changed.bridge_program_commitment[0] ^= 1;
        assert_eq!(
            verify_authenticated_semantic_h4_bridge(&changed),
            Err(SemanticH4BridgeError::ProgramIdentity)
        );

        let mut changed = original;
        changed.h4_global_padding_receipt_commitment = [0; 64];
        assert_eq!(
            verify_authenticated_semantic_h4_bridge(&changed),
            Err(SemanticH4BridgeError::ZeroCommitment)
        );

        let mut changed = claims(Profile::K128Calibration);
        changed.bridge_alpha = Fp16::ZERO;
        assert_eq!(
            verify_authenticated_semantic_h4_bridge(&changed),
            Err(SemanticH4BridgeError::ZeroChallenge)
        );
    }

    #[test]
    fn unselected_profile_and_subfield_point_reject() {
        let mut input = claims(Profile::K128Calibration);
        input.profile = Profile::K256DesignPoint;
        assert_eq!(
            verify_authenticated_semantic_h4_bridge(&input),
            Err(SemanticH4BridgeError::UnsupportedProfile)
        );

        let mut input = claims(Profile::K128Calibration);
        input.oods_point = CirclePoint {
            x: Fp16::ONE,
            y: Fp16::ZERO,
        };
        assert_eq!(
            verify_authenticated_semantic_h4_bridge(&input),
            Err(SemanticH4BridgeError::Point)
        );
    }
}
