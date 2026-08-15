//! Canonical evidence identity for a natively verified v3 composite receipt.
//!
//! This is deliberately an evidence transport, not a verifier input.  The
//! encoder accepts only the opaque receipt returned by the native coordinator.
//! The decoder returns an explicitly untrusted record and has no conversion
//! into `VerifiedV3CompositeReceipt`.  A caller must replay the component
//! verifiers and compare their fresh native receipt before the record can be
//! used as evidence for a run or package.

use alloc::vec::Vec;

use crate::binding_root_v2::{BINDING_V2_BYTES, BindingDigestV2};
use crate::composite_parent_public_coin::VerifiedV3CompositeReceipt;
use crate::field::Fp16;

pub const V3_COMPOSITE_RECEIPT_V4_MAGIC: &[u8; 8] = b"BLV3RC04";
pub const V3_COMPOSITE_RECEIPT_V4_VERSION: u16 = 4;
pub const V3_COMPOSITE_RECEIPT_V4_HEADER_BYTES: usize = 20;
pub const V3_COMPOSITE_RECEIPT_V4_BYTES: usize = V3_COMPOSITE_RECEIPT_V4_HEADER_BYTES
    + 128 // strict-PQ final transcript root
    + 64 // parent session id
    + 4 * 64 // parent 900, 901, final roots and completion challenge
    + 4 * BINDING_V2_BYTES // semantic, H4, typed, decisive receipt bindings
    + 64; // parent divisibility receipt commitment

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum V3CompositeReceiptV4Error {
    Length,
    Magic,
    Version,
    Flags,
    Profile,
    Attempt,
    Reserved,
    Field,
    Identity,
}

/// The decoded bytes are never a native receipt.  This type is intentionally
/// named `Evidence` and exposes no accepting conversion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedV3CompositeReceiptV4 {
    pub profile_code: u8,
    pub attempt: u16,
    pub strict_final_transcript_root: [u8; 128],
    pub parent_session_id: [u8; 64],
    pub parent_round_900_transcript_root: [u8; 64],
    pub parent_round_901_transcript_root: [u8; 64],
    pub parent_final_transcript_root: [u8; 64],
    pub completion_challenge: Fp16,
    pub semantic_receipt_binding: BindingDigestV2,
    pub h4_receipt_binding: BindingDigestV2,
    pub typed_receipt_binding: BindingDigestV2,
    pub decisive_receipt_binding: BindingDigestV2,
    pub parent_divisibility_receipt_commitment: [u8; 64],
}

fn profile_code(value: u8) -> Result<(), V3CompositeReceiptV4Error> {
    match value {
        1 | 3 => Ok(()),
        _ => Err(V3CompositeReceiptV4Error::Profile),
    }
}

fn nonzero(value: &[u8]) -> bool {
    value.iter().any(|byte| *byte != 0)
}

fn binding_nonzero(value: &BindingDigestV2) -> bool {
    let bytes = value.as_bytes();
    nonzero(&bytes[..64]) && nonzero(&bytes[64..])
}

fn take<'a>(
    encoded: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], V3CompositeReceiptV4Error> {
    let end = offset
        .checked_add(length)
        .ok_or(V3CompositeReceiptV4Error::Length)?;
    let value = encoded
        .get(*offset..end)
        .ok_or(V3CompositeReceiptV4Error::Length)?;
    *offset = end;
    Ok(value)
}

fn array<const N: usize>(
    encoded: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], V3CompositeReceiptV4Error> {
    take(encoded, offset, N)?
        .try_into()
        .map_err(|_| V3CompositeReceiptV4Error::Length)
}

fn binding(
    encoded: &[u8],
    offset: &mut usize,
) -> Result<BindingDigestV2, V3CompositeReceiptV4Error> {
    BindingDigestV2::decode(take(encoded, offset, BINDING_V2_BYTES)?)
        .map_err(|_| V3CompositeReceiptV4Error::Identity)
}

/// Serialize only a receipt that was minted by the native v3 coordinator.
pub fn encode_verified_v3_composite_receipt(
    receipt: &VerifiedV3CompositeReceipt,
) -> Result<Vec<u8>, V3CompositeReceiptV4Error> {
    let parent = receipt.parent();
    let strict_root = receipt.strict_final_transcript_root();
    let session_id = *parent.session_id();
    let parent_roots = [
        *parent.round_900_transcript_root(),
        *parent.round_901_transcript_root(),
        *parent.final_transcript_root(),
    ];
    if !nonzero(strict_root)
        || !nonzero(&session_id)
        || parent_roots.iter().any(|root| !nonzero(root))
        || parent.completion_challenge().is_zero()
        || !binding_nonzero(&receipt.semantic_receipt_binding())
        || !binding_nonzero(&receipt.h4_receipt_binding())
        || !binding_nonzero(&receipt.typed_receipt_binding())
        || !binding_nonzero(&receipt.decisive_receipt_binding())
        || !nonzero(parent.bridge_divisibility_receipt_commitment())
    {
        return Err(V3CompositeReceiptV4Error::Identity);
    }
    let mut encoded = Vec::with_capacity(V3_COMPOSITE_RECEIPT_V4_BYTES);
    encoded.extend_from_slice(V3_COMPOSITE_RECEIPT_V4_MAGIC);
    encoded.extend_from_slice(&V3_COMPOSITE_RECEIPT_V4_VERSION.to_be_bytes());
    encoded.extend_from_slice(&0_u16.to_be_bytes());
    encoded.push(parent.profile() as u8);
    encoded.push(0);
    encoded.extend_from_slice(&parent.attempt().to_be_bytes());
    encoded.extend_from_slice(&0_u32.to_be_bytes());
    encoded.extend_from_slice(strict_root);
    encoded.extend_from_slice(&session_id);
    for root in parent_roots {
        encoded.extend_from_slice(&root);
    }
    encoded.extend_from_slice(&parent.completion_challenge().encode());
    for binding in [
        receipt.semantic_receipt_binding(),
        receipt.h4_receipt_binding(),
        receipt.typed_receipt_binding(),
        receipt.decisive_receipt_binding(),
    ] {
        encoded.extend_from_slice(binding.as_bytes());
    }
    encoded.extend_from_slice(parent.bridge_divisibility_receipt_commitment());
    if encoded.len() != V3_COMPOSITE_RECEIPT_V4_BYTES {
        return Err(V3CompositeReceiptV4Error::Length);
    }
    Ok(encoded)
}

/// Decode evidence bytes without minting any accepting or verified type.
pub fn decode_v3_composite_receipt_evidence(
    encoded: &[u8],
) -> Result<DecodedV3CompositeReceiptV4, V3CompositeReceiptV4Error> {
    if encoded.len() != V3_COMPOSITE_RECEIPT_V4_BYTES {
        return Err(V3CompositeReceiptV4Error::Length);
    }
    if encoded.get(..8) != Some(V3_COMPOSITE_RECEIPT_V4_MAGIC) {
        return Err(V3CompositeReceiptV4Error::Magic);
    }
    if u16::from_be_bytes(
        encoded[8..10]
            .try_into()
            .map_err(|_| V3CompositeReceiptV4Error::Length)?,
    ) != V3_COMPOSITE_RECEIPT_V4_VERSION
    {
        return Err(V3CompositeReceiptV4Error::Version);
    }
    if encoded[10..12] != [0_u8; 2] || encoded[13] != 0 || encoded[16..20] != [0_u8; 4] {
        return Err(V3CompositeReceiptV4Error::Flags);
    }
    let decoded_profile_code = encoded[12];
    profile_code(decoded_profile_code)?;
    let attempt = u16::from_be_bytes(
        encoded[14..16]
            .try_into()
            .map_err(|_| V3CompositeReceiptV4Error::Length)?,
    );
    if attempt >= 4 {
        return Err(V3CompositeReceiptV4Error::Attempt);
    }
    let mut offset = V3_COMPOSITE_RECEIPT_V4_HEADER_BYTES;
    let strict_final_transcript_root = array::<128>(encoded, &mut offset)?;
    let parent_session_id = array::<64>(encoded, &mut offset)?;
    let parent_round_900_transcript_root = array::<64>(encoded, &mut offset)?;
    let parent_round_901_transcript_root = array::<64>(encoded, &mut offset)?;
    let parent_final_transcript_root = array::<64>(encoded, &mut offset)?;
    let completion_challenge = Fp16::decode(take(encoded, &mut offset, 64)?)
        .map_err(|_| V3CompositeReceiptV4Error::Field)?;
    let semantic_receipt_binding = binding(encoded, &mut offset)?;
    let h4_receipt_binding = binding(encoded, &mut offset)?;
    let typed_receipt_binding = binding(encoded, &mut offset)?;
    let decisive_receipt_binding = binding(encoded, &mut offset)?;
    let parent_divisibility_receipt_commitment = array::<64>(encoded, &mut offset)?;
    if offset != encoded.len() {
        return Err(V3CompositeReceiptV4Error::Reserved);
    }
    if !nonzero(&strict_final_transcript_root)
        || !nonzero(&parent_session_id)
        || !nonzero(&parent_round_900_transcript_root)
        || !nonzero(&parent_round_901_transcript_root)
        || !nonzero(&parent_final_transcript_root)
        || completion_challenge.is_zero()
        || !binding_nonzero(&semantic_receipt_binding)
        || !binding_nonzero(&h4_receipt_binding)
        || !binding_nonzero(&typed_receipt_binding)
        || !binding_nonzero(&decisive_receipt_binding)
        || !nonzero(&parent_divisibility_receipt_commitment)
    {
        return Err(V3CompositeReceiptV4Error::Identity);
    }
    Ok(DecodedV3CompositeReceiptV4 {
        profile_code: decoded_profile_code,
        attempt,
        strict_final_transcript_root,
        parent_session_id,
        parent_round_900_transcript_root,
        parent_round_901_transcript_root,
        parent_final_transcript_root,
        completion_challenge,
        semantic_receipt_binding,
        h4_receipt_binding,
        typed_receipt_binding,
        decisive_receipt_binding,
        parent_divisibility_receipt_commitment,
    })
}
