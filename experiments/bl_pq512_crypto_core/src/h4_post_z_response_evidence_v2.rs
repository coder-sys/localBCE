//! Serialized evidence for one strictly replayed H4 post-Z response.
//!
//! This is a transport seam, not an H4 acceptance receipt. Production calls
//! the native strict-PQ response replay first and records only identities from
//! that replay. Decoding returns untrusted evidence; it never constructs
//! `VerifiedStrictH4BridgeSourceResponseV2` or `VerifiedH4V2`.

#[cfg(test)]
use alloc::vec;
use alloc::vec::Vec;

use crate::binding_root_v2::{BINDING_V2_BYTES, BindingDigestV2, BindingRoleV2};
use crate::h4_bridge_source_response_v2::{
    H4_BRIDGE_SOURCE_RESPONSE_V2_BYTES, H4BridgeSourceResponseV2, H4BridgeSourceResponseV2Error,
    decode_h4_bridge_source_response_v2, encode_h4_bridge_source_response_v2,
    verify_strict_h4_bridge_source_response_v2,
};
use crate::h4_proof_package_v2::H4ProofProfileV2;
use crate::strict_pq_public_coin_v2::{StrictPqGovernedVerifierKeyV2, StrictPqRootUseRegistryV2};

pub const H4_POST_Z_RESPONSE_EVIDENCE_V2_MAGIC: &[u8; 8] = b"BLH4ZE02";
pub const H4_POST_Z_RESPONSE_EVIDENCE_V2_VERSION: u16 = 2;
pub const H4_POST_Z_RESPONSE_EVIDENCE_V2_HEADER_BYTES: usize =
    8 + 2 + 2 + 1 + 1 + 4 + 4 * BINDING_V2_BYTES + 128 + 4;
pub const H4_POST_Z_RESPONSE_EVIDENCE_V2_BYTES: usize =
    H4_POST_Z_RESPONSE_EVIDENCE_V2_HEADER_BYTES + H4_BRIDGE_SOURCE_RESPONSE_V2_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum H4PostZResponseEvidenceV2Error {
    Length,
    Magic,
    Version,
    Flags,
    Profile,
    ResponseLength,
    Identity,
    Binding,
    Key,
    Response(H4BridgeSourceResponseV2Error),
    Transcript(H4BridgeSourceResponseV2Error),
}

/// Evidence minted only after native strict-PQ response replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H4PostZResponseEvidenceV2 {
    pub profile: H4ProofProfileV2,
    pub context: BindingDigestV2,
    pub claim_vector_binding: BindingDigestV2,
    pub governed_key_binding: BindingDigestV2,
    pub response_binding: BindingDigestV2,
    pub first_ordinal: u32,
    pub final_transcript_root: [u8; 128],
    response_bytes: Vec<u8>,
}

impl H4PostZResponseEvidenceV2 {
    pub fn response_bytes(&self) -> &[u8] {
        &self.response_bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedH4PostZResponseEvidenceV2 {
    pub profile: H4ProofProfileV2,
    pub context: BindingDigestV2,
    pub claim_vector_binding: BindingDigestV2,
    pub governed_key_binding: BindingDigestV2,
    pub response_binding: BindingDigestV2,
    pub first_ordinal: u32,
    pub final_transcript_root: [u8; 128],
    pub response: H4BridgeSourceResponseV2,
}

fn profile_from_code(code: u8) -> Result<H4ProofProfileV2, H4PostZResponseEvidenceV2Error> {
    match code {
        1 => Ok(H4ProofProfileV2::K128),
        3 => Ok(H4ProofProfileV2::K512),
        _ => Err(H4PostZResponseEvidenceV2Error::Profile),
    }
}

fn nonzero(bytes: &[u8]) -> bool {
    bytes.iter().any(|byte| *byte != 0)
}

fn binding_nonzero(binding: BindingDigestV2) -> bool {
    nonzero(binding.as_bytes())
}

fn take<'a>(
    encoded: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], H4PostZResponseEvidenceV2Error> {
    let end = offset
        .checked_add(length)
        .ok_or(H4PostZResponseEvidenceV2Error::Length)?;
    let value = encoded
        .get(*offset..end)
        .ok_or(H4PostZResponseEvidenceV2Error::Length)?;
    *offset = end;
    Ok(value)
}

fn array<const N: usize>(
    encoded: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], H4PostZResponseEvidenceV2Error> {
    take(encoded, offset, N)?
        .try_into()
        .map_err(|_| H4PostZResponseEvidenceV2Error::Length)
}

/// Replay the current strict H4 response transcript and mint transport
/// evidence. This does not verify source/base RS openings, bridge GKR, mask
/// PCS, or complete H4; those remain inputs to `complete_h4_v2`.
#[allow(clippy::too_many_arguments)]
pub fn produce_h4_post_z_response_evidence_v2(
    encoded_bundle: &[u8],
    governed_key: &StrictPqGovernedVerifierKeyV2,
    profile: H4ProofProfileV2,
    response: &H4BridgeSourceResponseV2,
    context: BindingDigestV2,
    claim_vector_binding: BindingDigestV2,
    first_ordinal: u32,
    root_use_registry: &mut StrictPqRootUseRegistryV2,
) -> Result<H4PostZResponseEvidenceV2, H4PostZResponseEvidenceV2Error> {
    let response_bytes = encode_h4_bridge_source_response_v2(response)
        .map_err(H4PostZResponseEvidenceV2Error::Response)?;
    let verified = verify_strict_h4_bridge_source_response_v2(
        encoded_bundle,
        governed_key,
        profile,
        response,
        context,
        claim_vector_binding,
        first_ordinal,
        root_use_registry,
    )
    .map_err(H4PostZResponseEvidenceV2Error::Transcript)?;
    let governed_key_binding = governed_key
        .binding()
        .map_err(|_| H4PostZResponseEvidenceV2Error::Key)?;
    let response_binding = BindingDigestV2::hash(BindingRoleV2::Payload, &response_bytes)
        .map_err(|_| H4PostZResponseEvidenceV2Error::Binding)?;
    Ok(H4PostZResponseEvidenceV2 {
        profile,
        context,
        claim_vector_binding,
        governed_key_binding,
        response_binding,
        first_ordinal,
        final_transcript_root: *verified.final_transcript_root(),
        response_bytes,
    })
}

/// Encode replay-backed evidence with a fixed header and exact response body.
pub fn encode_h4_post_z_response_evidence_v2(
    evidence: &H4PostZResponseEvidenceV2,
) -> Result<Vec<u8>, H4PostZResponseEvidenceV2Error> {
    if evidence.response_bytes.len() != H4_BRIDGE_SOURCE_RESPONSE_V2_BYTES
        || !binding_nonzero(evidence.context)
        || !binding_nonzero(evidence.claim_vector_binding)
        || !binding_nonzero(evidence.governed_key_binding)
        || !binding_nonzero(evidence.response_binding)
        || !nonzero(&evidence.final_transcript_root)
    {
        return Err(H4PostZResponseEvidenceV2Error::Identity);
    }
    let mut encoded = Vec::with_capacity(H4_POST_Z_RESPONSE_EVIDENCE_V2_BYTES);
    encoded.extend_from_slice(H4_POST_Z_RESPONSE_EVIDENCE_V2_MAGIC);
    encoded.extend_from_slice(&H4_POST_Z_RESPONSE_EVIDENCE_V2_VERSION.to_be_bytes());
    encoded.extend_from_slice(&0_u16.to_be_bytes());
    encoded.push(evidence.profile.code());
    encoded.push(0);
    encoded.extend_from_slice(&evidence.first_ordinal.to_be_bytes());
    encoded.extend_from_slice(evidence.context.as_bytes());
    encoded.extend_from_slice(evidence.claim_vector_binding.as_bytes());
    encoded.extend_from_slice(evidence.governed_key_binding.as_bytes());
    encoded.extend_from_slice(evidence.response_binding.as_bytes());
    encoded.extend_from_slice(&evidence.final_transcript_root);
    encoded.extend_from_slice(
        &u32::try_from(evidence.response_bytes.len())
            .map_err(|_| H4PostZResponseEvidenceV2Error::ResponseLength)?
            .to_be_bytes(),
    );
    encoded.extend_from_slice(&evidence.response_bytes);
    if encoded.len() != H4_POST_Z_RESPONSE_EVIDENCE_V2_BYTES {
        return Err(H4PostZResponseEvidenceV2Error::Length);
    }
    Ok(encoded)
}

/// Decode evidence without minting any verified H4 or strict-response type.
pub fn decode_h4_post_z_response_evidence_v2(
    encoded: &[u8],
) -> Result<DecodedH4PostZResponseEvidenceV2, H4PostZResponseEvidenceV2Error> {
    if encoded.len() != H4_POST_Z_RESPONSE_EVIDENCE_V2_BYTES {
        return Err(H4PostZResponseEvidenceV2Error::Length);
    }
    if encoded.get(..8) != Some(H4_POST_Z_RESPONSE_EVIDENCE_V2_MAGIC) {
        return Err(H4PostZResponseEvidenceV2Error::Magic);
    }
    if u16::from_be_bytes(
        encoded[8..10]
            .try_into()
            .map_err(|_| H4PostZResponseEvidenceV2Error::Length)?,
    ) != H4_POST_Z_RESPONSE_EVIDENCE_V2_VERSION
    {
        return Err(H4PostZResponseEvidenceV2Error::Version);
    }
    if encoded[10..12] != [0_u8; 2] || encoded[13] != 0 {
        return Err(H4PostZResponseEvidenceV2Error::Flags);
    }
    let profile = profile_from_code(encoded[12])?;
    let first_ordinal = u32::from_be_bytes(
        encoded[14..18]
            .try_into()
            .map_err(|_| H4PostZResponseEvidenceV2Error::Length)?,
    );
    let mut offset = 18;
    let context = BindingDigestV2::decode(take(encoded, &mut offset, BINDING_V2_BYTES)?)
        .map_err(|_| H4PostZResponseEvidenceV2Error::Identity)?;
    let claim_vector_binding =
        BindingDigestV2::decode(take(encoded, &mut offset, BINDING_V2_BYTES)?)
            .map_err(|_| H4PostZResponseEvidenceV2Error::Identity)?;
    let governed_key_binding =
        BindingDigestV2::decode(take(encoded, &mut offset, BINDING_V2_BYTES)?)
            .map_err(|_| H4PostZResponseEvidenceV2Error::Identity)?;
    let response_binding = BindingDigestV2::decode(take(encoded, &mut offset, BINDING_V2_BYTES)?)
        .map_err(|_| H4PostZResponseEvidenceV2Error::Identity)?;
    let final_transcript_root = array::<128>(encoded, &mut offset)?;
    let response_length = u32::from_be_bytes(
        take(encoded, &mut offset, 4)?
            .try_into()
            .map_err(|_| H4PostZResponseEvidenceV2Error::Length)?,
    ) as usize;
    if response_length != H4_BRIDGE_SOURCE_RESPONSE_V2_BYTES
        || offset
            .checked_add(response_length)
            .ok_or(H4PostZResponseEvidenceV2Error::Length)?
            != encoded.len()
    {
        return Err(H4PostZResponseEvidenceV2Error::ResponseLength);
    }
    let response_bytes = take(encoded, &mut offset, response_length)?;
    let response = decode_h4_bridge_source_response_v2(response_bytes)
        .map_err(H4PostZResponseEvidenceV2Error::Response)?;
    let expected_response_binding = BindingDigestV2::hash(BindingRoleV2::Payload, response_bytes)
        .map_err(|_| H4PostZResponseEvidenceV2Error::Binding)?;
    if response_binding != expected_response_binding {
        return Err(H4PostZResponseEvidenceV2Error::Binding);
    }
    if !binding_nonzero(context)
        || !binding_nonzero(claim_vector_binding)
        || !binding_nonzero(governed_key_binding)
        || !binding_nonzero(response_binding)
        || !nonzero(&final_transcript_root)
    {
        return Err(H4PostZResponseEvidenceV2Error::Identity);
    }
    Ok(DecodedH4PostZResponseEvidenceV2 {
        profile,
        context,
        claim_vector_binding,
        governed_key_binding,
        response_binding,
        first_ordinal,
        final_transcript_root,
        response,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(value: u8) -> BindingDigestV2 {
        BindingDigestV2::hash(BindingRoleV2::Payload, &[value]).unwrap()
    }

    fn response() -> H4BridgeSourceResponseV2 {
        H4BridgeSourceResponseV2 {
            row_sumcheck_rounds: vec![
                [crate::field::Fp16::ZERO; 3];
                crate::h4_bridge_source_response_v2::H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS
            ],
            answer_coefficients: vec![
                crate::field::Fp16::ZERO;
                crate::h4_bridge_source_response_v2::H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS
            ],
            answer_binding: binding(9),
        }
    }

    #[test]
    fn evidence_roundtrips_and_rejects_body_binding_mutation() {
        let response_bytes = encode_h4_bridge_source_response_v2(&response()).unwrap();
        let evidence = H4PostZResponseEvidenceV2 {
            profile: H4ProofProfileV2::K128,
            context: binding(1),
            claim_vector_binding: binding(2),
            governed_key_binding: binding(3),
            response_binding: BindingDigestV2::hash(BindingRoleV2::Payload, &response_bytes)
                .unwrap(),
            first_ordinal: 40,
            final_transcript_root: [4_u8; 128],
            response_bytes,
        };
        let encoded = encode_h4_post_z_response_evidence_v2(&evidence).unwrap();
        assert_eq!(encoded.len(), H4_POST_Z_RESPONSE_EVIDENCE_V2_BYTES);
        let decoded = decode_h4_post_z_response_evidence_v2(&encoded).unwrap();
        assert_eq!(decoded.profile, H4ProofProfileV2::K128);
        assert_eq!(decoded.first_ordinal, 40);
        assert_eq!(decoded.context, binding(1));
        assert_eq!(decoded.response.answer_binding, binding(9));

        let mut changed = encoded;
        changed[H4_POST_Z_RESPONSE_EVIDENCE_V2_HEADER_BYTES + 20] ^= 1;
        assert_eq!(
            decode_h4_post_z_response_evidence_v2(&changed),
            Err(H4PostZResponseEvidenceV2Error::Binding)
        );
    }
}
