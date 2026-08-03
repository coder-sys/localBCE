//! Rust verifier for the nonactivating `TRANSPARENT_SHAKE256_1024` candidate.
//!
//! The candidate commits before the authenticated public coin with a 1,024-bit
//! SHAKE256 digest over the 512-bit statement, retry-stable attempt identity,
//! and a uniform 1,024-bit mask.  The later public coin is bound only in the
//! transcript identity; it does not alter the commitment bytes.
//!
//! This module is a cross-language KAT and parser boundary.  It is not a
//! proof-suite selection, H4 composition, activation, or production claim.

use alloc::vec::Vec;
use core::fmt;

use sha3::{
    Digest, Sha3_512, Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub const COMMITMENT_MAGIC: &[u8; 7] = b"BLTHC02";
pub const COMMITMENT_VERSION: u8 = 2;
pub const PARAMETER_IDENTITY: &[u8] = b"BL-PQ512-TRANSPARENT-SHAKE256-1024-V1";
pub const STATEMENT_BYTES: usize = 64;
pub const ATTEMPT_BYTES: usize = 64;
pub const MASK_BYTES: usize = 128;
pub const COMMITMENT_BYTES: usize = 128;
pub const PUBLIC_COIN_BYTES: usize = 64;

const COMMITMENT_DOMAIN: &[u8] = b"BL/PQ512/TRANSPARENT-SHAKE256-1024/COMMITMENT/v1\0";
const TRANSCRIPT_DOMAIN: &[u8] = b"BL/PQ512/TRANSPARENT-SHAKE256-1024/COIN-TRANSCRIPT/v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransparentHashCodeError {
    Length {
        label: &'static str,
        expected: usize,
        actual: usize,
    },
    Magic,
    Version,
    Parameter,
    Zero(&'static str),
    Trailing,
    OpeningMismatch,
}

impl fmt::Display for TransparentHashCodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "transparent hash-code error: {self:?}")
    }
}

impl core::error::Error for TransparentHashCodeError {}

fn exact<'a>(
    value: &'a [u8],
    label: &'static str,
    expected: usize,
) -> Result<&'a [u8], TransparentHashCodeError> {
    if value.len() != expected {
        return Err(TransparentHashCodeError::Length {
            label,
            expected,
            actual: value.len(),
        });
    }
    Ok(value)
}

fn nonzero(value: &[u8], label: &'static str) -> Result<(), TransparentHashCodeError> {
    if value.iter().all(|byte| *byte == 0) {
        return Err(TransparentHashCodeError::Zero(label));
    }
    Ok(())
}

fn part(hasher: &mut impl Update, value: &[u8]) {
    hasher.update(&(value.len() as u32).to_be_bytes());
    hasher.update(value);
}

fn commitment_digest(
    statement: &[u8; STATEMENT_BYTES],
    attempt_id: &[u8; ATTEMPT_BYTES],
    mask: &[u8; MASK_BYTES],
) -> [u8; COMMITMENT_BYTES] {
    let mut hasher = Shake256::default();
    hasher.update(COMMITMENT_DOMAIN);
    part(&mut hasher, PARAMETER_IDENTITY);
    part(&mut hasher, attempt_id);
    part(&mut hasher, statement);
    part(&mut hasher, mask);
    let mut output = [0_u8; COMMITMENT_BYTES];
    hasher.finalize_xof().read(&mut output);
    output
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransparentHashCodeCommitment {
    pub attempt_id: [u8; ATTEMPT_BYTES],
    pub commitment: [u8; COMMITMENT_BYTES],
}

impl TransparentHashCodeCommitment {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(
            COMMITMENT_MAGIC.len()
                + 2
                + PARAMETER_IDENTITY.len()
                + ATTEMPT_BYTES
                + COMMITMENT_BYTES,
        );
        encoded.extend_from_slice(COMMITMENT_MAGIC);
        encoded.push(COMMITMENT_VERSION);
        encoded.push(PARAMETER_IDENTITY.len() as u8);
        encoded.extend_from_slice(PARAMETER_IDENTITY);
        encoded.extend_from_slice(&self.attempt_id);
        encoded.extend_from_slice(&self.commitment);
        encoded
    }

    pub fn identity_512(&self) -> [u8; 64] {
        Sha3_512::digest(self.canonical_bytes()).into()
    }
}

pub fn commit(
    statement: &[u8; STATEMENT_BYTES],
    attempt_id: &[u8; ATTEMPT_BYTES],
    mask: &[u8; MASK_BYTES],
) -> TransparentHashCodeCommitment {
    TransparentHashCodeCommitment {
        attempt_id: *attempt_id,
        commitment: commitment_digest(statement, attempt_id, mask),
    }
}

pub fn verify_opening(
    commitment: &TransparentHashCodeCommitment,
    statement: &[u8],
    mask: &[u8],
) -> Result<(), TransparentHashCodeError> {
    let statement = exact(statement, "statement", STATEMENT_BYTES)?;
    nonzero(statement, "statement")?;
    let mask = exact(mask, "mask", MASK_BYTES)?;
    let statement: &[u8; STATEMENT_BYTES] = statement.try_into().expect("statement length");
    let mask: &[u8; MASK_BYTES] = mask.try_into().expect("mask length");
    if commit(statement, &commitment.attempt_id, mask) != *commitment {
        return Err(TransparentHashCodeError::OpeningMismatch);
    }
    Ok(())
}

pub fn bind_authenticated_public_coin(
    commitment: &TransparentHashCodeCommitment,
    public_coin: &[u8],
) -> Result<[u8; 64], TransparentHashCodeError> {
    let public_coin = exact(public_coin, "public_coin", PUBLIC_COIN_BYTES)?;
    nonzero(public_coin, "public_coin")?;
    let canonical = commitment.canonical_bytes();
    let mut hasher = Sha3_512::new();
    Digest::update(&mut hasher, TRANSCRIPT_DOMAIN);
    part(&mut hasher, &canonical);
    part(&mut hasher, public_coin);
    Ok(hasher.finalize().into())
}

pub fn parse_commitment(
    encoded: &[u8],
) -> Result<TransparentHashCodeCommitment, TransparentHashCodeError> {
    let fixed = COMMITMENT_MAGIC.len() + 2;
    if encoded.len() < fixed {
        return Err(TransparentHashCodeError::Length {
            label: "commitment",
            expected: fixed,
            actual: encoded.len(),
        });
    }
    if &encoded[..COMMITMENT_MAGIC.len()] != COMMITMENT_MAGIC {
        return Err(TransparentHashCodeError::Magic);
    }
    if encoded[COMMITMENT_MAGIC.len()] != COMMITMENT_VERSION {
        return Err(TransparentHashCodeError::Version);
    }
    let parameter_length = usize::from(encoded[COMMITMENT_MAGIC.len() + 1]);
    let parameter_start = fixed;
    let parameter_end = parameter_start + parameter_length;
    if parameter_end > encoded.len()
        || &encoded[parameter_start..parameter_end] != PARAMETER_IDENTITY
    {
        return Err(TransparentHashCodeError::Parameter);
    }
    let attempt_start = parameter_end;
    let attempt_end = attempt_start + ATTEMPT_BYTES;
    let commitment_end = attempt_end + COMMITMENT_BYTES;
    if commitment_end != encoded.len() {
        return Err(TransparentHashCodeError::Trailing);
    }
    let attempt_id: [u8; ATTEMPT_BYTES] = encoded[attempt_start..attempt_end]
        .try_into()
        .expect("attempt length");
    let commitment: [u8; COMMITMENT_BYTES] = encoded[attempt_end..commitment_end]
        .try_into()
        .expect("commitment length");
    nonzero(&attempt_id, "attempt_id")?;
    nonzero(&commitment, "commitment")?;
    Ok(TransparentHashCodeCommitment {
        attempt_id,
        commitment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATEMENT: [u8; 64] = [
        0xe0, 0xa5, 0x7f, 0x57, 0x4e, 0xd8, 0x0d, 0x3c, 0x8e, 0x56, 0xad, 0xbf, 0xb0, 0xf5, 0x01,
        0x46, 0x21, 0x71, 0x08, 0x85, 0xa9, 0x42, 0xb7, 0x87, 0xfc, 0x16, 0x70, 0xcc, 0x37, 0x0c,
        0xb1, 0x1f, 0x2c, 0xb0, 0x88, 0xb2, 0xa0, 0xd2, 0x7e, 0xb7, 0x87, 0x7e, 0x64, 0xfd, 0x14,
        0xf4, 0x96, 0xab, 0x6a, 0xd9, 0x70, 0x17, 0xab, 0x9e, 0x62, 0x6c, 0xd7, 0xac, 0x9d, 0x04,
        0xb6, 0x3c, 0xc8, 0xc6,
    ];
    const ATTEMPT: [u8; 64] = [
        0x76, 0x7f, 0x61, 0x57, 0xfd, 0xe2, 0x05, 0xaa, 0x6b, 0x44, 0x74, 0x9b, 0x78, 0xb6, 0x5e,
        0x57, 0xf1, 0xf5, 0x40, 0xf2, 0x5c, 0xcb, 0xbb, 0x00, 0x3e, 0x9d, 0x13, 0xb4, 0x13, 0xc5,
        0xcd, 0x18, 0x05, 0xe8, 0xfd, 0x94, 0xc3, 0x97, 0x56, 0xd9, 0x7e, 0x78, 0xef, 0x09, 0xfe,
        0x1f, 0x5a, 0xe4, 0x05, 0x4d, 0xd4, 0x82, 0x88, 0x2e, 0x52, 0xeb, 0x2a, 0xf0, 0x4e, 0x5e,
        0xbc, 0x91, 0x13, 0xea,
    ];
    const MASK: [u8; 128] = [
        0x3f, 0xc6, 0xf7, 0x5c, 0x44, 0x43, 0x71, 0x9c, 0x31, 0x8a, 0x14, 0xe4, 0x34, 0x6d, 0x49,
        0x19, 0xf1, 0x22, 0xed, 0xdb, 0x24, 0x2a, 0x88, 0x05, 0x2e, 0x06, 0xc9, 0xbb, 0xa3, 0x12,
        0x7f, 0x95, 0x70, 0xcc, 0x89, 0x96, 0xa8, 0x72, 0x84, 0x23, 0x98, 0x35, 0x9c, 0x82, 0x2c,
        0x8a, 0xc9, 0xf8, 0xa4, 0xd2, 0x46, 0xb5, 0xce, 0x6d, 0x9b, 0x4b, 0x31, 0x37, 0x80, 0x14,
        0x04, 0x5f, 0x24, 0xd4, 0x3f, 0xc6, 0xf7, 0x5c, 0x44, 0x43, 0x71, 0x9c, 0x31, 0x8a, 0x14,
        0xe4, 0x34, 0x6d, 0x49, 0x19, 0xf1, 0x22, 0xed, 0xdb, 0x24, 0x2a, 0x88, 0x05, 0x2e, 0x06,
        0xc9, 0xbb, 0xa3, 0x12, 0x7f, 0x95, 0x70, 0xcc, 0x89, 0x96, 0xa8, 0x72, 0x84, 0x23, 0x98,
        0x35, 0x9c, 0x82, 0x2c, 0x8a, 0xc9, 0xf8, 0xa4, 0xd2, 0x46, 0xb5, 0xce, 0x6d, 0x9b, 0x4b,
        0x31, 0x37, 0x80, 0x14, 0x04, 0x5f, 0x24, 0xd4,
    ];
    fn decode_hex<const N: usize>(encoded: &str) -> [u8; N] {
        assert_eq!(encoded.len(), N * 2);
        let mut output = [0_u8; N];
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&encoded[2 * index..2 * index + 2], 16).unwrap();
        }
        output
    }

    #[test]
    fn python_kat_roundtrips_and_binds_coin_separately() {
        let commitment = commit(&STATEMENT, &ATTEMPT, &MASK);
        assert_eq!(
            commitment.commitment,
            decode_hex::<128>(
                "65fbd02721e0b85ad575df94ed3ba946865648eece72fc50ca06eee2aa310c21085923020d05945f5aa668218dbd0931b31cb1b4d5f94ab3733c969b085c5e961ff71d8a52cc1b11183081c4eb4af404e13190c84b0da0f201ca41050f91c6e8053b0e415a708eda2d0491453e92501f42657e646b507eab13022d00d96d8420"
            )
        );
        assert_eq!(
            parse_commitment(&commitment.canonical_bytes()),
            Ok(commitment)
        );
        verify_opening(&commitment, &STATEMENT, &MASK).unwrap();
        let coin = [0x41_u8; PUBLIC_COIN_BYTES];
        assert_ne!(
            bind_authenticated_public_coin(&commitment, &coin).unwrap(),
            commitment.identity_512()
        );
    }

    #[test]
    fn malformed_opening_and_encoding_reject() {
        let commitment = commit(&STATEMENT, &ATTEMPT, &MASK);
        let mut changed = STATEMENT;
        changed[0] ^= 1;
        assert_eq!(
            verify_opening(&commitment, &changed, &MASK),
            Err(TransparentHashCodeError::OpeningMismatch)
        );
        let mut encoded = commitment.canonical_bytes();
        encoded.push(0);
        assert_eq!(
            parse_commitment(&encoded),
            Err(TransparentHashCodeError::Trailing)
        );
    }
}
