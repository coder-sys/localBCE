//! SHA3-512 rejection sampling into the frozen degree-16 field.
//!
//! This is a generic uniform field draw, not an OODS stereographic sampler.
//! A future OODS API must separately reject the Fp8 fixed subfield and reject
//! `t^2 = -1` before inverting `1+t^2`; this module intentionally exposes no
//! API that could be mistaken for performing those checks.

use core::fmt;

use sha3::{Digest, Sha3_512};

use crate::field::{EXTENSION_DEGREE, Fp16, M31_MODULUS};

/// Exact sampler magic.
pub const SAMPLE_MAGIC: &[u8; 8] = b"BLPQF16S";
/// Exact sampler encoding version.
pub const SAMPLE_VERSION: u16 = 1;
/// `BL/PQ512/v1/TRANSCRIPT/FIELD16-REJECTION-DRAW`.
pub const SAMPLE_DOMAIN_CODE: u16 = 776;
/// Frozen production attempt cap.
pub const DEFAULT_MAX_ATTEMPTS: u16 = 16;

// floor(2^512 / p^16) * p^16 = 65536 * p^16, exact big-endian.
const ACCEPTANCE_LIMIT: [u8; 64] = [
    0xff, 0xff, 0xff, 0xe0, 0x00, 0x00, 0x01, 0xdf, 0xff, 0xff, 0xee, 0x80, 0x00, 0x00, 0x71, 0xbf,
    0xff, 0xfd, 0xde, 0x00, 0x00, 0x07, 0xd1, 0xff, 0xff, 0xe9, 0xa8, 0x00, 0x00, 0x32, 0x45, 0xff,
    0xff, 0xa6, 0xa0, 0x00, 0x00, 0x7d, 0x1f, 0xff, 0xff, 0x77, 0x80, 0x00, 0x00, 0x71, 0xbf, 0xff,
    0xff, 0xba, 0x00, 0x00, 0x00, 0x1d, 0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
];

/// One accepted field draw and its audit metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SampledFp16 {
    /// Uniform field element.
    pub element: Fp16,
    /// Zero-based accepted attempt.
    pub accepted_attempt: u16,
    /// Exact accepted SHA3-512 digest.
    pub digest: [u8; 64],
}

/// Strict sampler input or bounded-rejection failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SampleError {
    /// The seed was not exactly 64 bytes.
    SeedLength { actual: usize },
    /// The session identifier was not exactly 64 bytes.
    SessionIdLength { actual: usize },
    /// At least one attempt is required.
    ZeroAttemptCap,
    /// Every fixed attempt was outside the unbiased acceptance interval.
    AttemptCapExhausted { attempts: u16 },
}

impl fmt::Display for SampleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SeedLength { actual } => {
                write!(formatter, "sampler seed must be 64 bytes, got {actual}")
            }
            Self::SessionIdLength { actual } => write!(
                formatter,
                "sampler session identifier must be 64 bytes, got {actual}"
            ),
            Self::ZeroAttemptCap => formatter.write_str("sampler attempt cap must be positive"),
            Self::AttemptCapExhausted { attempts } => {
                write!(formatter, "sampler exhausted {attempts} rejection attempts")
            }
        }
    }
}

impl core::error::Error for SampleError {}

/// Draws one unbiased field element using the exact typed SHA3-512 schedule.
///
/// A digest is accepted only below `floor(2^512 / p^16) * p^16`.
/// Rejected digests are never repaired by reduction.
pub fn sample_uniform_fp16(
    seed: &[u8],
    session_id: &[u8],
    round_index: u32,
    draw_index: u32,
    max_attempts: u16,
) -> Result<SampledFp16, SampleError> {
    if seed.len() != 64 {
        return Err(SampleError::SeedLength { actual: seed.len() });
    }
    if session_id.len() != 64 {
        return Err(SampleError::SessionIdLength {
            actual: session_id.len(),
        });
    }
    if max_attempts == 0 {
        return Err(SampleError::ZeroAttemptCap);
    }

    for attempt in 0..max_attempts {
        let mut hash = Sha3_512::new();
        hash.update(SAMPLE_MAGIC);
        hash.update(SAMPLE_VERSION.to_be_bytes());
        hash.update(SAMPLE_DOMAIN_CODE.to_be_bytes());
        hash.update(session_id);
        hash.update(seed);
        hash.update(round_index.to_be_bytes());
        hash.update(draw_index.to_be_bytes());
        hash.update(attempt.to_be_bytes());
        let digest: [u8; 64] = hash.finalize().into();
        if is_accepted(&digest) {
            return Ok(SampledFp16 {
                element: digest_mod_field_order(&digest),
                accepted_attempt: attempt,
                digest,
            });
        }
    }
    Err(SampleError::AttemptCapExhausted {
        attempts: max_attempts,
    })
}

pub(crate) const fn is_accepted(candidate: &[u8; 64]) -> bool {
    let mut index = 0;
    while index < candidate.len() {
        if candidate[index] < ACCEPTANCE_LIMIT[index] {
            return true;
        }
        if candidate[index] > ACCEPTANCE_LIMIT[index] {
            return false;
        }
        index += 1;
    }
    false
}

pub(crate) fn digest_mod_field_order(digest: &[u8; 64]) -> Fp16 {
    let mut words = [0_u32; 16];
    for (word, chunk) in words.iter_mut().zip(digest.chunks_exact(4)) {
        *word = u32::from_be_bytes(chunk.try_into().expect("chunks_exact yields four bytes"));
    }

    // Repeated long division gives little-endian base-p digits. Keeping the
    // first 16 digits is exactly reduction modulo p^16 after acceptance.
    let mut coefficients = [0_u32; EXTENSION_DEGREE];
    for coefficient in &mut coefficients {
        let mut remainder = 0_u64;
        for word in &mut words {
            let current = (remainder << 32) | u64::from(*word);
            *word = (current / u64::from(M31_MODULUS)) as u32;
            remainder = current % u64::from(M31_MODULUS);
        }
        *coefficient = remainder as u32;
    }
    match Fp16::from_coefficients(coefficients) {
        Ok(element) => element,
        Err(_) => unreachable!("long division remainders are canonical M31"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    const SESSION_HEX: &str = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f";
    const DIGEST_HEX: &str = "b53887ffd5b21c9bab7f9b28b27d078faa4fe18a945193ca5acadf045760fa8126707127b69426a96e2df08f9a1065a6a3264c1c079b1e47a3d89abd8766b9a4";
    const ELEMENT_HEX: &str = "15d7177b1ad17fb05a9a878b380e317a78ec80a6660d92d345d615e44cf2bb9a71ad89cf14261ad01e4f6ded387e22e718535ff63d09ad3e037aa017440b3e61";

    #[test]
    fn python_sampler_kat_matches_exactly() {
        let seed = decode_hex(SEED_HEX);
        let session = decode_hex(SESSION_HEX);
        let sampled = sample_uniform_fp16(&seed, &session, 3, 7, DEFAULT_MAX_ATTEMPTS).unwrap();
        assert_eq!(sampled.accepted_attempt, 0);
        assert_eq!(sampled.digest, decode_hex(DIGEST_HEX));
        assert_eq!(sampled.element.encode(), decode_hex(ELEMENT_HEX));
    }

    #[test]
    fn malformed_inputs_fail_closed() {
        assert_eq!(
            sample_uniform_fp16(&[0_u8; 63], &[0_u8; 64], 0, 0, 1),
            Err(SampleError::SeedLength { actual: 63 })
        );
        assert_eq!(
            sample_uniform_fp16(&[0_u8; 64], &[0_u8; 65], 0, 0, 1),
            Err(SampleError::SessionIdLength { actual: 65 })
        );
        assert_eq!(
            sample_uniform_fp16(&[0_u8; 64], &[0_u8; 64], 0, 0, 0),
            Err(SampleError::ZeroAttemptCap)
        );
    }

    #[test]
    fn acceptance_boundary_is_strict_and_has_no_modulo_repair() {
        assert!(!is_accepted(&ACCEPTANCE_LIMIT));
        let mut below = ACCEPTANCE_LIMIT;
        for byte in below.iter_mut().rev() {
            if *byte == 0 {
                *byte = 0xff;
            } else {
                *byte -= 1;
                break;
            }
        }
        assert!(is_accepted(&below));
        assert!(!is_accepted(&[0xff_u8; 64]));
        assert!(is_accepted(&[0_u8; 64]));
    }

    #[test]
    fn accepted_conversion_returns_canonical_coefficients() {
        let element = digest_mod_field_order(&[0xff_u8; 64]);
        assert!(
            element
                .coefficients()
                .into_iter()
                .all(|coefficient| coefficient < M31_MODULUS)
        );
    }

    fn decode_hex(value: &str) -> [u8; 64] {
        assert_eq!(value.len(), 128);
        let bytes = value.as_bytes();
        let mut decoded = [0_u8; 64];
        for (index, output) in decoded.iter_mut().enumerate() {
            *output = (nibble(bytes[index * 2]) << 4) | nibble(bytes[index * 2 + 1]);
        }
        decoded
    }

    const fn nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid test hex"),
        }
    }
}
