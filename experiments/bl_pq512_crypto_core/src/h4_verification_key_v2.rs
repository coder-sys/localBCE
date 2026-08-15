//! Canonical serialization for the governed H4-v2 verification key.
//!
//! This is a transport boundary for already-governed verifier inputs. It does
//! not derive an expected aggregate binding from an untrusted package, create
//! proof material, or mint an accepting H4 receipt. The native H4 verifier
//! remains the authority after this key is decoded.

use alloc::vec::Vec;

use crate::binding_root_v2::{BINDING_V2_BYTES, BindingDigestV2, BindingRootV2Error};
use crate::h4_proof_package_v2::{
    H4AggregatePackageV2VerificationKey, H4ProofPackageV2Error, H4ProofProfileV2,
};
use crate::strict_pq_public_coin_v2::{
    STRICT_PQ_GOVERNED_KEY_BYTES_V2, StrictPqGovernedVerifierKeyV2, StrictPqPublicCoinV2Error,
};

pub const H4_VERIFICATION_KEY_V2_MAGIC: &[u8; 8] = b"BLH4VK02";
pub const H4_VERIFICATION_KEY_V2_VERSION: u16 = 2;
pub const H4_VERIFICATION_KEY_V2_HEADER_BYTES: usize = 20;
pub const H4_VERIFICATION_KEY_V2_BYTES: usize = H4_VERIFICATION_KEY_V2_HEADER_BYTES
    + 2 * 64
    + BINDING_V2_BYTES
    + 4 * BINDING_V2_BYTES
    + 2 * BINDING_V2_BYTES
    + STRICT_PQ_GOVERNED_KEY_BYTES_V2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum H4VerificationKeyV2Error {
    Length,
    Magic,
    Version,
    Flags,
    Profile,
    Reserved,
    Binding(BindingRootV2Error),
    StrictPublicCoin(StrictPqPublicCoinV2Error),
    Package(H4ProofPackageV2Error),
}

impl From<BindingRootV2Error> for H4VerificationKeyV2Error {
    fn from(value: BindingRootV2Error) -> Self {
        Self::Binding(value)
    }
}

impl From<StrictPqPublicCoinV2Error> for H4VerificationKeyV2Error {
    fn from(value: StrictPqPublicCoinV2Error) -> Self {
        Self::StrictPublicCoin(value)
    }
}

impl From<H4ProofPackageV2Error> for H4VerificationKeyV2Error {
    fn from(value: H4ProofPackageV2Error) -> Self {
        Self::Package(value)
    }
}

fn profile(code: u8) -> Result<H4ProofProfileV2, H4VerificationKeyV2Error> {
    match code {
        1 => Ok(H4ProofProfileV2::K128),
        3 => Ok(H4ProofProfileV2::K512),
        _ => Err(H4VerificationKeyV2Error::Profile),
    }
}

fn take<'a>(
    encoded: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], H4VerificationKeyV2Error> {
    let end = offset
        .checked_add(length)
        .ok_or(H4VerificationKeyV2Error::Length)?;
    let value = encoded
        .get(*offset..end)
        .ok_or(H4VerificationKeyV2Error::Length)?;
    *offset = end;
    Ok(value)
}

fn take_array<const N: usize>(
    encoded: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], H4VerificationKeyV2Error> {
    take(encoded, offset, N)?
        .try_into()
        .map_err(|_| H4VerificationKeyV2Error::Length)
}

fn take_binding(
    encoded: &[u8],
    offset: &mut usize,
) -> Result<BindingDigestV2, H4VerificationKeyV2Error> {
    Ok(BindingDigestV2::decode(take(
        encoded,
        offset,
        BINDING_V2_BYTES,
    )?)?)
}

/// Encode the complete governed H4-v2 verification key in one fixed grammar.
pub fn encode_h4_verification_key_v2(key: &H4AggregatePackageV2VerificationKey) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(H4_VERIFICATION_KEY_V2_BYTES);
    encoded.extend_from_slice(H4_VERIFICATION_KEY_V2_MAGIC);
    encoded.extend_from_slice(&H4_VERIFICATION_KEY_V2_VERSION.to_be_bytes());
    encoded.extend_from_slice(&0_u16.to_be_bytes());
    encoded.push(key.profile().code());
    encoded.push(0);
    encoded.extend_from_slice(&key.attempt().to_be_bytes());
    encoded.extend_from_slice(&0_u32.to_be_bytes());
    encoded.extend_from_slice(key.profile_identity());
    encoded.extend_from_slice(key.program_commitment());
    encoded.extend_from_slice(key.statement_binding().as_bytes());
    for binding in key.gkr_statement_bindings() {
        encoded.extend_from_slice(binding.as_bytes());
    }
    encoded.extend_from_slice(key.state_relation_source_binding().as_bytes());
    encoded.extend_from_slice(key.expected_aggregate_binding().as_bytes());
    encoded.extend_from_slice(&key.strict_public_coin_key().encode());
    debug_assert_eq!(encoded.len(), H4_VERIFICATION_KEY_V2_BYTES);
    encoded
}

/// Decode and revalidate the complete governed H4-v2 verification key.
pub fn decode_h4_verification_key_v2(
    encoded: &[u8],
) -> Result<H4AggregatePackageV2VerificationKey, H4VerificationKeyV2Error> {
    if encoded.len() != H4_VERIFICATION_KEY_V2_BYTES {
        return Err(H4VerificationKeyV2Error::Length);
    }
    if encoded.get(..8) != Some(H4_VERIFICATION_KEY_V2_MAGIC) {
        return Err(H4VerificationKeyV2Error::Magic);
    }
    if u16::from_be_bytes(
        encoded[8..10]
            .try_into()
            .map_err(|_| H4VerificationKeyV2Error::Length)?,
    ) != H4_VERIFICATION_KEY_V2_VERSION
    {
        return Err(H4VerificationKeyV2Error::Version);
    }
    if encoded[10..12] != [0_u8; 2] || encoded[13] != 0 || encoded[16..20] != [0_u8; 4] {
        return Err(H4VerificationKeyV2Error::Flags);
    }
    let mut offset = H4_VERIFICATION_KEY_V2_HEADER_BYTES;
    let profile = profile(encoded[12])?;
    let attempt = u16::from_be_bytes(
        encoded[14..16]
            .try_into()
            .map_err(|_| H4VerificationKeyV2Error::Length)?,
    );
    let profile_identity = take_array::<64>(encoded, &mut offset)?;
    let program_commitment = take_array::<64>(encoded, &mut offset)?;
    let statement_binding = take_binding(encoded, &mut offset)?;
    let mut gkr_statement_bindings = [BindingDigestV2::decode(&[0_u8; BINDING_V2_BYTES])?; 4];
    for binding in &mut gkr_statement_bindings {
        *binding = take_binding(encoded, &mut offset)?;
    }
    let state_relation_source_binding = take_binding(encoded, &mut offset)?;
    let expected_aggregate_binding = take_binding(encoded, &mut offset)?;
    let strict_key = StrictPqGovernedVerifierKeyV2::decode(take(
        encoded,
        &mut offset,
        STRICT_PQ_GOVERNED_KEY_BYTES_V2,
    )?)?;
    if offset != encoded.len() {
        return Err(H4VerificationKeyV2Error::Reserved);
    }
    if strict_key.attempt() as u16 != attempt {
        return Err(H4VerificationKeyV2Error::Profile);
    }
    H4AggregatePackageV2VerificationKey::new(
        profile,
        attempt,
        profile_identity,
        program_commitment,
        statement_binding,
        gkr_statement_bindings,
        state_relation_source_binding,
        expected_aggregate_binding,
        strict_key,
    )
    .map_err(Into::into)
}
