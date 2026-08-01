//! Typed Fp16/Fp8-excluding OODS parameter sampling.
//!
//! The authoritative public-coin round supplies the exact 64-byte seed. This
//! module rejection-samples uniformly from `Fp16 \\ Fp8`, records the accepted
//! digest and attempt, and exposes stereographic conversion only through a
//! validated parameter type.

use core::fmt;

use sha3::{Digest, Sha3_512};

use crate::field::Fp16;
use crate::sampler::{digest_mod_field_order, is_accepted};

/// Exact OODS sampler magic.
pub const OODS_SAMPLE_MAGIC: &[u8; 8] = b"BLPQOODS";
/// Exact OODS sampler encoding version.
pub const OODS_SAMPLE_VERSION: u16 = 1;
/// `BL/PQ512/v1/TRANSCRIPT/OODS-FP8-EXCLUDING-DRAW`.
pub const OODS_SAMPLE_DOMAIN_CODE: u16 = 779;
/// Frozen OODS rejection-attempt cap.
pub const OODS_DEFAULT_MAX_ATTEMPTS: u16 = 16;

/// A stereographic parameter statically separated from unrestricted Fp16.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OodsParameter(Fp16);

impl OodsParameter {
    /// Validates that `element` is outside the embedded Fp8 fixed subfield.
    pub const fn try_from_element(element: Fp16) -> Result<Self, OodsError> {
        if element.is_in_fp8_subfield() {
            Err(OodsError::FixedSubfield)
        } else {
            Ok(Self(element))
        }
    }

    /// Returns the validated field element.
    pub const fn element(self) -> Fp16 {
        self.0
    }
}

/// One accepted parameter and its deterministic audit metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SampledOodsParameter {
    /// Validated parameter outside Fp8.
    pub parameter: OodsParameter,
    /// Zero-based accepted rejection attempt.
    pub accepted_attempt: u16,
    /// Exact accepted SHA3-512 digest.
    pub digest: [u8; 64],
}

/// One point on `x^2 + y^2 = 1` over Fp16.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CirclePoint {
    /// First affine coordinate.
    pub x: Fp16,
    /// Second affine coordinate.
    pub y: Fp16,
}

/// Strict OODS input, rejection, or exceptional-denominator failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OodsError {
    /// The seed was not exactly 64 bytes.
    SeedLength { actual: usize },
    /// The session identifier was not exactly 64 bytes.
    SessionIdLength { actual: usize },
    /// At least one attempt is required.
    ZeroAttemptCap,
    /// The proposed parameter lies in the forbidden Fp8 fixed subfield.
    FixedSubfield,
    /// Every fixed rejection attempt failed.
    AttemptCapExhausted { attempts: u16 },
    /// `1 + t^2` was zero despite fixed-subfield exclusion.
    ExceptionalDenominator,
}

impl fmt::Display for OodsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SeedLength { actual } => {
                write!(
                    formatter,
                    "OODS sampler seed must be 64 bytes, got {actual}"
                )
            }
            Self::SessionIdLength { actual } => write!(
                formatter,
                "OODS sampler session identifier must be 64 bytes, got {actual}"
            ),
            Self::ZeroAttemptCap => {
                formatter.write_str("OODS sampler attempt cap must be positive")
            }
            Self::FixedSubfield => {
                formatter.write_str("OODS parameter is in the forbidden Fp8 fixed subfield")
            }
            Self::AttemptCapExhausted { attempts } => {
                write!(
                    formatter,
                    "OODS sampler exhausted {attempts} rejection attempts"
                )
            }
            Self::ExceptionalDenominator => {
                formatter.write_str("OODS stereographic denominator is zero")
            }
        }
    }
}

impl core::error::Error for OodsError {}

/// Draws one unbiased parameter from `Fp16 \\ Fp8`.
///
/// Out-of-range SHA3-512 digests and accepted digests mapping into Fp8 are
/// rejected without repair. The seed, session, round, and attempt are all
/// included in the exact typed draw.
pub fn sample_oods_parameter(
    seed: &[u8],
    session_id: &[u8],
    round_index: u32,
    max_attempts: u16,
) -> Result<SampledOodsParameter, OodsError> {
    if seed.len() != 64 {
        return Err(OodsError::SeedLength { actual: seed.len() });
    }
    if session_id.len() != 64 {
        return Err(OodsError::SessionIdLength {
            actual: session_id.len(),
        });
    }
    if max_attempts == 0 {
        return Err(OodsError::ZeroAttemptCap);
    }

    for attempt in 0..max_attempts {
        let mut hash = Sha3_512::new();
        hash.update(OODS_SAMPLE_MAGIC);
        hash.update(OODS_SAMPLE_VERSION.to_be_bytes());
        hash.update(OODS_SAMPLE_DOMAIN_CODE.to_be_bytes());
        hash.update(session_id);
        hash.update(seed);
        hash.update(round_index.to_be_bytes());
        hash.update(attempt.to_be_bytes());
        let digest: [u8; 64] = hash.finalize().into();
        if !is_accepted(&digest) {
            continue;
        }
        let element = digest_mod_field_order(&digest);
        let Ok(parameter) = OodsParameter::try_from_element(element) else {
            continue;
        };
        return Ok(SampledOodsParameter {
            parameter,
            accepted_attempt: attempt,
            digest,
        });
    }
    Err(OodsError::AttemptCapExhausted {
        attempts: max_attempts,
    })
}

/// Maps a validated parameter to the unit circle.
pub fn stereographic_circle_point(parameter: OodsParameter) -> Result<CirclePoint, OodsError> {
    let t = parameter.element();
    let one = Fp16::ONE;
    let two = one + one;
    let t_squared = t.square();
    let denominator_inverse = (one + t_squared)
        .inverse()
        .map_err(|_| OodsError::ExceptionalDenominator)?;
    Ok(CirclePoint {
        x: (one - t_squared) * denominator_inverse,
        y: (two * t) * denominator_inverse,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::M31_MODULUS;

    const SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    const SESSION_HEX: &str = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f";
    const DIGEST_HEX: &str = "4326d8b68340fda6d2f8df044e99b34c53d0d50610552743ca3333fd91b52da7e563887e9e2331db1301913496c60a6d83e45523950ecc55a703b78b1263df20";
    const ELEMENT_HEX: &str = "34a217725402998f1a71ff8d07cf38ad3e69e3c952161c07258a8f606f5717105dc47c0848a9ce81554f211c3ce71fc6283e110205a93c0818e2075b6c5f740d";
    const CIRCLE_X_HEX: &str = "1c4e2289412644940586e4090b17e33e7cb78a163fefd1031da14944533178b7065e6d3164a090272837ec9569eba7127b249cff2d4ea7d4187ca50243f8be00";
    const CIRCLE_Y_HEX: &str = "19ba3bef1c12e0fe7099de4b32b3c57d2aa4551532e4eed62b0b20430567069d35fe54f952282cad59bca0f2536fd4dd3df45a6c708b023a37e2530344879c53";

    #[test]
    fn python_oods_and_circle_kats_match_exactly() {
        let seed = decode_hex(SEED_HEX);
        let session = decode_hex(SESSION_HEX);
        let sampled = sample_oods_parameter(&seed, &session, 3, OODS_DEFAULT_MAX_ATTEMPTS).unwrap();
        assert_eq!(sampled.accepted_attempt, 0);
        assert_eq!(sampled.digest, decode_hex(DIGEST_HEX));
        assert_eq!(
            sampled.parameter.element().encode(),
            decode_hex(ELEMENT_HEX)
        );
        assert!(!sampled.parameter.element().is_in_fp8_subfield());
        assert_ne!(
            sampled.parameter.element(),
            sampled.parameter.element().conjugate()
        );

        let point = stereographic_circle_point(sampled.parameter).unwrap();
        assert_eq!(point.x.encode(), decode_hex(CIRCLE_X_HEX));
        assert_eq!(point.y.encode(), decode_hex(CIRCLE_Y_HEX));
        assert_eq!(point.x.square() + point.y.square(), Fp16::ONE);
    }

    #[test]
    fn fixed_subfield_and_malformed_inputs_fail_closed() {
        let fixed =
            Fp16::from_coefficients([1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert!(fixed.is_in_fp8_subfield());
        assert_eq!(
            OodsParameter::try_from_element(fixed),
            Err(OodsError::FixedSubfield)
        );
        assert_eq!(
            sample_oods_parameter(&[0_u8; 63], &[1_u8; 64], 0, 1),
            Err(OodsError::SeedLength { actual: 63 })
        );
        assert_eq!(
            sample_oods_parameter(&[0_u8; 64], &[1_u8; 65], 0, 1),
            Err(OodsError::SessionIdLength { actual: 65 })
        );
        assert_eq!(
            sample_oods_parameter(&[0_u8; 64], &[1_u8; 64], 0, 0),
            Err(OodsError::ZeroAttemptCap)
        );
    }

    #[test]
    fn upper_coefficient_boundary_is_exact() {
        let mut coefficients = [0_u32; 16];
        coefficients[8] = M31_MODULUS - 1;
        let outside = Fp16::from_coefficients(coefficients).unwrap();
        assert!(!outside.is_in_fp8_subfield());
        assert!(OodsParameter::try_from_element(outside).is_ok());
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
