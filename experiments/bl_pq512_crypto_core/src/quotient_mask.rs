//! Canonical two-component Circle quotient masking.
//!
//! This mirrors the Python plan and pointwise masking identity. It is a
//! nonactivating algebra/KAT surface, not prover integration or a simulator.

use sha3::{Digest, Sha3_512};

use crate::field::Fp16;
use crate::oods::CirclePoint;

/// Exact plan commitment domain.
pub const QUOTIENT_MASK_DOMAIN: &[u8] = b"BL/PQ512/WAVE1B/CANONICAL-CIRCLE-QUOTIENT-MASK/v1";
/// Number of doublings subtracted from the composition log-degree bound.
pub const CIRCLE_SPLIT_LOG_REDUCTION: u16 = 1;

/// Strict quotient-mask plan failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotientMaskError {
    /// A parameter was zero or inconsistent with the exact formulas.
    InvalidParameter,
    /// A profile identifier was empty, non-ASCII, or too long.
    InvalidProfileId,
}

/// Compute the exact nonactivating candidate plan commitment.
pub fn quotient_mask_plan_commitment(
    profile_id: &str,
    reduced_air_degree: u16,
    oods_query_count: u16,
    fri_query_count: u32,
) -> Result<[u8; 64], QuotientMaskError> {
    if profile_id.is_empty() || !profile_id.is_ascii() || profile_id.len() > u16::MAX as usize {
        return Err(QuotientMaskError::InvalidProfileId);
    }
    if reduced_air_degree == 0 || oods_query_count == 0 || fri_query_count == 0 {
        return Err(QuotientMaskError::InvalidParameter);
    }
    let trace_h = 2_u64
        .checked_mul(u64::from(reduced_air_degree))
        .and_then(|value| {
            value.checked_mul(16_u64 * u64::from(oods_query_count) + u64::from(fri_query_count))
        })
        .and_then(|value| value.checked_add(u64::from(fri_query_count)))
        .ok_or(QuotientMaskError::InvalidParameter)?;
    let quotient_h = u64::from(oods_query_count) + u64::from(fri_query_count);

    let mut hash = Sha3_512::new();
    hash.update(QUOTIENT_MASK_DOMAIN);
    hash.update((profile_id.len() as u16).to_be_bytes());
    hash.update(profile_id.as_bytes());
    hash.update(reduced_air_degree.to_be_bytes());
    hash.update(oods_query_count.to_be_bytes());
    hash.update(fri_query_count.to_be_bytes());
    hash.update(trace_h.to_be_bytes());
    hash.update(quotient_h.to_be_bytes());
    hash.update(16_u16.to_be_bytes());
    hash.update(2_u16.to_be_bytes());
    hash.update(CIRCLE_SPLIT_LOG_REDUCTION.to_be_bytes());
    hash.update([0_u8, 0_u8, 0_u8]);
    Ok(hash.finalize().into())
}

/// Derive the exact two-half Circle coefficient split factor.
///
/// This mirrors S-two's `oods_point.repeated_double(max_log_degree_bound - 1).x`
/// reconstruction rule while keeping the final AIR-derived bound explicit.
pub fn canonical_circle_split_factor(
    oods_point: CirclePoint,
    max_log_degree_bound: u16,
) -> Result<Fp16, QuotientMaskError> {
    if max_log_degree_bound < CIRCLE_SPLIT_LOG_REDUCTION
        || oods_point.x.square().add(oods_point.y.square()) != Fp16::ONE
    {
        return Err(QuotientMaskError::InvalidParameter);
    }
    let mut x = oods_point.x;
    let mut y = oods_point.y;
    let two = Fp16::from_coefficients([2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        .map_err(|_| QuotientMaskError::InvalidParameter)?;
    for _ in 0..max_log_degree_bound - CIRCLE_SPLIT_LOG_REDUCTION {
        (x, y) = (x.square().sub(y.square()), two.mul(x).mul(y));
    }
    debug_assert_eq!(x.square().add(y.square()), Fp16::ONE);
    Ok(x)
}

/// Preserve `left + split_factor * right` while randomizing both components.
pub fn mask_canonical_quotient_pair(
    left: Fp16,
    right: Fp16,
    split_factor: Fp16,
    mask: Fp16,
) -> (Fp16, Fp16) {
    let masked_left = left.add(split_factor.mul(mask));
    let masked_right = right.sub(mask);
    debug_assert_eq!(
        masked_left.add(split_factor.mul(masked_right)),
        left.add(split_factor.mul(right))
    );
    (masked_left, masked_right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oods::{sample_oods_parameter, stereographic_circle_point};

    fn fp16(value: u32) -> Fp16 {
        Fp16::from_coefficients([value, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap()
    }

    #[test]
    fn python_k512_plan_commitment_matches() {
        assert_eq!(
            quotient_mask_plan_commitment("K512_CALIBRATION", 2, 1, 926).unwrap(),
            hex64(
                "8b577a857db1f9ae09b0382039bf1af47bd7fbd0b4f42fb3643039233852b1ac\
                 d56887c45710fb42e733d12024c48ee0c6a334aebdc064fd86d341f1896e6f3a"
            )
        );
    }

    #[test]
    fn python_split_factor_kat_matches() {
        let seed: [u8; 64] = core::array::from_fn(|index| index as u8);
        let session_id: [u8; 64] = core::array::from_fn(|index| (index + 64) as u8);
        let sample = sample_oods_parameter(&seed, &session_id, 3, 16).unwrap();
        let point = stereographic_circle_point(sample.parameter).unwrap();
        assert_eq!(
            canonical_circle_split_factor(point, 21).unwrap().encode(),
            hex64(
                "2c2ef3f200470e3f16a140270c1f9e9a451cfd791cc2587f63d18d395ece5473\
                 2ccf39e70f9ab53e19e773cc623a1da32a4355f83810202c14a20e304f577f9e"
            )
        );
    }

    #[test]
    fn mask_identity_holds_for_zero_and_nonzero_split_factors() {
        let left = fp16(3);
        let right = fp16(5);
        let mask = fp16(11);
        for factor in [Fp16::ZERO, fp16(7)] {
            let joined = left.add(factor.mul(right));
            let (masked_left, masked_right) =
                mask_canonical_quotient_pair(left, right, factor, mask);
            assert_eq!(masked_left.add(factor.mul(masked_right)), joined);
            assert_ne!(masked_right, right);
        }
    }

    fn hex64(value: &str) -> [u8; 64] {
        let compact = value.replace([' ', '\n', '\r'], "");
        assert_eq!(compact.len(), 128);
        let mut decoded = [0_u8; 64];
        for (index, byte) in decoded.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16).unwrap();
        }
        decoded
    }
}
