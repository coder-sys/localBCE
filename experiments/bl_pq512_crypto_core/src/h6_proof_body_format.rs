//! Independent Rust parser for the fixed H6 reference proof-body grammar.
//!
//! This parser is intentionally limited to the exact three-section grammar
//! used by the nonactivating simulator. It validates the out-of-band profile
//! identity, grammar digest, descriptor table, offsets, lengths, and payload
//! SHA3-512 identities before returning any section metadata.

use sha3::{Digest, Sha3_512};

pub const PROOF_MAGIC: [u8; 8] = *b"BLPQPF01";
pub const PROOF_VERSION: u16 = 1;
pub const PROOF_FLAGS: u16 = 0;
pub const PROOF_HEADER_BYTES: usize = 88;
pub const SECTION_DESCRIPTOR_BYTES: usize = 88;
pub const PROOF_SECTION_COUNT: usize = 3;
pub const PROOF_BODY_BYTES: usize = 736;
pub const PROOF_MAX_BYTES: usize = 2048;

const SECTION_CODES: [u32; PROOF_SECTION_COUNT] = [1, 2, 3];
const SECTION_LENGTHS: [u64; PROOF_SECTION_COUNT] = [64, 128, 192];
const SECTION_NAMES: [&[u8]; PROOF_SECTION_COUNT] =
    [b"semantic_air", b"state_relation", b"gkr_pcs_public_coin"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum H6ProofBodyFormatError {
    Profile,
    Length,
    Magic,
    Version,
    Flags,
    HeaderLength,
    DeclaredLength,
    GrammarDigest,
    SectionCode,
    SectionOrdinal,
    SectionOffset,
    SectionLength,
    SectionDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H6ProofBodySummary {
    pub grammar_digest: [u8; 64],
    pub section_digests: [[u8; 64]; PROOF_SECTION_COUNT],
}

fn digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u32).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn profile_identity(capacity: u16, label: &[u8]) -> [u8; 64] {
    digest(
        b"BL/PQ512/H6/SIMULATOR/IDENTITY/v1\0",
        &[&capacity.to_be_bytes(), label],
    )
}

pub fn grammar_digest(capacity: u16) -> Result<[u8; 64], H6ProofBodyFormatError> {
    if capacity != 128 && capacity != 512 {
        return Err(H6ProofBodyFormatError::Profile);
    }
    let identities = [
        profile_identity(capacity, b"profile"),
        profile_identity(capacity, b"suite-reference"),
        profile_identity(capacity, b"schema"),
        profile_identity(capacity, b"verifier"),
    ];
    let mut hasher = Sha3_512::new();
    hasher.update(b"BL/PQ512/PROOF-GRAMMAR/REFERENCE/v0");
    hasher.update(PROOF_MAGIC);
    hasher.update(PROOF_VERSION.to_be_bytes());
    hasher.update(PROOF_FLAGS.to_be_bytes());
    hasher.update((PROOF_HEADER_BYTES as u32).to_be_bytes());
    hasher.update((SECTION_DESCRIPTOR_BYTES as u32).to_be_bytes());
    for identity in identities {
        hasher.update(identity);
    }
    hasher.update((PROOF_SECTION_COUNT as u32).to_be_bytes());
    hasher.update((PROOF_MAX_BYTES as u64).to_be_bytes());
    for ((code, name), length) in SECTION_CODES
        .into_iter()
        .zip(SECTION_NAMES)
        .zip(SECTION_LENGTHS)
    {
        hasher.update(code.to_be_bytes());
        hasher.update((name.len() as u16).to_be_bytes());
        hasher.update(name);
        hasher.update(length.to_be_bytes());
        hasher.update(length.to_be_bytes());
    }
    Ok(hasher.finalize().into())
}

fn u32_at(encoded: &[u8], start: usize) -> u32 {
    u32::from_be_bytes(encoded[start..start + 4].try_into().unwrap())
}

fn u64_at(encoded: &[u8], start: usize) -> u64 {
    u64::from_be_bytes(encoded[start..start + 8].try_into().unwrap())
}

pub fn parse_h6_proof_body(
    encoded: &[u8],
    capacity: u16,
) -> Result<H6ProofBodySummary, H6ProofBodyFormatError> {
    if encoded.len() != PROOF_BODY_BYTES || encoded.len() > PROOF_MAX_BYTES {
        return Err(H6ProofBodyFormatError::Length);
    }
    if encoded[..8] != PROOF_MAGIC {
        return Err(H6ProofBodyFormatError::Magic);
    }
    if u16::from_be_bytes(encoded[8..10].try_into().unwrap()) != PROOF_VERSION {
        return Err(H6ProofBodyFormatError::Version);
    }
    if u16::from_be_bytes(encoded[10..12].try_into().unwrap()) != PROOF_FLAGS {
        return Err(H6ProofBodyFormatError::Flags);
    }
    if u32_at(encoded, 12) as usize != PROOF_HEADER_BYTES {
        return Err(H6ProofBodyFormatError::HeaderLength);
    }
    if u64_at(encoded, 16) as usize != PROOF_BODY_BYTES {
        return Err(H6ProofBodyFormatError::DeclaredLength);
    }
    let expected_grammar = grammar_digest(capacity)?;
    if encoded[24..88] != expected_grammar {
        return Err(H6ProofBodyFormatError::GrammarDigest);
    }

    let mut next_offset = PROOF_HEADER_BYTES + PROOF_SECTION_COUNT * SECTION_DESCRIPTOR_BYTES;
    let mut section_digests = [[0_u8; 64]; PROOF_SECTION_COUNT];
    for index in 0..PROOF_SECTION_COUNT {
        let descriptor = PROOF_HEADER_BYTES + index * SECTION_DESCRIPTOR_BYTES;
        if u32_at(encoded, descriptor) != SECTION_CODES[index] {
            return Err(H6ProofBodyFormatError::SectionCode);
        }
        if u32_at(encoded, descriptor + 4) as usize != index {
            return Err(H6ProofBodyFormatError::SectionOrdinal);
        }
        if u64_at(encoded, descriptor + 8) as usize != next_offset {
            return Err(H6ProofBodyFormatError::SectionOffset);
        }
        if u64_at(encoded, descriptor + 16) != SECTION_LENGTHS[index] {
            return Err(H6ProofBodyFormatError::SectionLength);
        }
        let data_start = next_offset;
        let data_end = data_start + SECTION_LENGTHS[index] as usize;
        let expected_digest: [u8; 64] = Sha3_512::digest(&encoded[data_start..data_end]).into();
        let encoded_digest: [u8; 64] = encoded[descriptor + 24..descriptor + 88]
            .try_into()
            .unwrap();
        if encoded_digest != expected_digest {
            return Err(H6ProofBodyFormatError::SectionDigest);
        }
        section_digests[index] = encoded_digest;
        next_offset = data_end;
    }
    if next_offset != PROOF_BODY_BYTES {
        return Err(H6ProofBodyFormatError::DeclaredLength);
    }
    Ok(H6ProofBodySummary {
        grammar_digest: expected_grammar,
        section_digests,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_and_length_bounds_are_strict() {
        assert_eq!(grammar_digest(128).unwrap().len(), 64);
        assert_eq!(grammar_digest(256), Err(H6ProofBodyFormatError::Profile));
        assert_eq!(
            parse_h6_proof_body(&[0_u8; PROOF_BODY_BYTES - 1], 128),
            Err(H6ProofBodyFormatError::Length)
        );
    }
}
