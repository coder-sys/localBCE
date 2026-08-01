//! Native Circle trace masking with secret SHA3-512-derived M31 coefficients.
//!
//! For a trace polynomial `w` on the canonical domain `H`, this constructs
//! `w_hat(P) = w(P) + Z_H(P) * r(P)`.  The witness is unchanged on `H`, while
//! every committed extension evaluation depends on independently sampled
//! secret coefficients.  Sampling is explicit and separate from public coin.

use alloc::vec::Vec;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::circle_fft::{
    CircleFftError, bit_reverse_permute, coset_order_to_circle_domain_order,
    evaluate_circle_coefficients, evaluate_coefficients_at_point,
    evaluate_extension_circle_coefficients, interpolate_circle_evaluations,
    interpolate_extension_circle_evaluations,
};
use crate::circle_fri::{BaseCirclePoint, MAX_CIRCLE_DOMAIN_LOG_SIZE, canonic_circle_point};
use crate::field::{EXTENSION_DEGREE, FieldError, Fp16, M31, M31_MODULUS};

pub const TRACE_MASK_MAGIC: &[u8; 8] = b"BLPQMSK1";
pub const TRACE_MASK_VERSION: u16 = 1;
pub const TRACE_MASK_DOMAIN_CODE: u16 = 785;
pub const TRACE_MASK_FP16_DOMAIN_CODE: u16 = 786;
pub const TRACE_MASK_MAX_ATTEMPTS: u16 = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TraceMaskError {
    SeedLength { actual: usize },
    SessionLength { actual: usize },
    OracleIdLength { actual: usize },
    EmptyRandomizer,
    CountOverflow,
    AttemptCapExhausted { coefficient: u32 },
    TargetDomainTooSmall,
    CircleFft(CircleFftError),
    Field(FieldError),
}

impl From<CircleFftError> for TraceMaskError {
    fn from(value: CircleFftError) -> Self {
        Self::CircleFft(value)
    }
}

impl From<FieldError> for TraceMaskError {
    fn from(value: FieldError) -> Self {
        Self::Field(value)
    }
}

/// Draw independent unbiased M31 coefficients from one domain-separated XOF.
///
/// A single FIPS-202 SHAKE256 stream avoids one SHA3 permutation per
/// coefficient while retaining 128-bit post-quantum preimage security.  The
/// PCS and transcript continue to use full-width SHA3-512 commitments.
pub fn sample_trace_mask_coefficients(
    secret_seed: &[u8],
    session_id: &[u8],
    oracle_id: &[u8],
    count: usize,
) -> Result<Vec<M31>, TraceMaskError> {
    if secret_seed.len() != 64 {
        return Err(TraceMaskError::SeedLength {
            actual: secret_seed.len(),
        });
    }
    if session_id.len() != 64 {
        return Err(TraceMaskError::SessionLength {
            actual: session_id.len(),
        });
    }
    if oracle_id.len() != 64 {
        return Err(TraceMaskError::OracleIdLength {
            actual: oracle_id.len(),
        });
    }
    if count == 0 {
        return Err(TraceMaskError::EmptyRandomizer);
    }
    let count_u32 = u32::try_from(count).map_err(|_| TraceMaskError::CountOverflow)?;
    let acceptance_limit = u64::from(M31_MODULUS) * 2;
    let mut xof = Shake256::default();
    xof.update(TRACE_MASK_MAGIC);
    xof.update(&TRACE_MASK_VERSION.to_be_bytes());
    xof.update(&TRACE_MASK_DOMAIN_CODE.to_be_bytes());
    xof.update(session_id);
    xof.update(oracle_id);
    xof.update(secret_seed);
    xof.update(&count_u32.to_be_bytes());
    let mut reader = xof.finalize_xof();
    let mut coefficients = Vec::with_capacity(count);
    for coefficient in 0..count_u32 {
        let mut accepted = None;
        for _ in 0..TRACE_MASK_MAX_ATTEMPTS {
            let mut word = [0_u8; 4];
            reader.read(&mut word);
            let candidate = u64::from(u32::from_be_bytes(word));
            if candidate < acceptance_limit {
                accepted = Some(M31::from_canonical(
                    (candidate % u64::from(M31_MODULUS)) as u32,
                )?);
                break;
            }
        }
        coefficients.push(accepted.ok_or(TraceMaskError::AttemptCapExhausted { coefficient })?);
    }
    Ok(coefficients)
}

/// Draw uniform Fp16 mask coefficients from a separate domain-separated XOF.
pub fn sample_extension_trace_mask_coefficients(
    secret_seed: &[u8],
    session_id: &[u8],
    oracle_id: &[u8],
    count: usize,
) -> Result<Vec<Fp16>, TraceMaskError> {
    stream_extension_trace_mask_coefficients(secret_seed, session_id, oracle_id, count)?.collect()
}

/// Replay uniform Fp16 mask coefficients without retaining their vector.
///
/// Production callers must keep the fresh secret seed short-lived, never log
/// or persist it, and use a distinct session/oracle identity for every mask.
/// Reopening this iterator within the same proof reproduces the existing
/// canonical coefficient stream byte-for-byte.
pub fn stream_extension_trace_mask_coefficients(
    secret_seed: &[u8],
    session_id: &[u8],
    oracle_id: &[u8],
    count: usize,
) -> Result<impl Iterator<Item = Result<Fp16, TraceMaskError>>, TraceMaskError> {
    if secret_seed.len() != 64 {
        return Err(TraceMaskError::SeedLength {
            actual: secret_seed.len(),
        });
    }
    if session_id.len() != 64 {
        return Err(TraceMaskError::SessionLength {
            actual: session_id.len(),
        });
    }
    if oracle_id.len() != 64 {
        return Err(TraceMaskError::OracleIdLength {
            actual: oracle_id.len(),
        });
    }
    if count == 0 {
        return Err(TraceMaskError::EmptyRandomizer);
    }
    let count_u32 = u32::try_from(count).map_err(|_| TraceMaskError::CountOverflow)?;
    let acceptance_limit = u64::from(M31_MODULUS) * 2;
    let mut xof = Shake256::default();
    xof.update(TRACE_MASK_MAGIC);
    xof.update(&TRACE_MASK_VERSION.to_be_bytes());
    xof.update(&TRACE_MASK_FP16_DOMAIN_CODE.to_be_bytes());
    xof.update(session_id);
    xof.update(oracle_id);
    xof.update(secret_seed);
    xof.update(&count_u32.to_be_bytes());
    let mut reader = xof.finalize_xof();
    Ok((0..count_u32).map(move |coefficient| {
        let mut coordinates = [0_u32; EXTENSION_DEGREE];
        for coordinate in &mut coordinates {
            let mut accepted = None;
            for _ in 0..TRACE_MASK_MAX_ATTEMPTS {
                let mut word = [0_u8; 4];
                reader.read(&mut word);
                let candidate = u64::from(u32::from_be_bytes(word));
                if candidate < acceptance_limit {
                    accepted = Some((candidate % u64::from(M31_MODULUS)) as u32);
                    break;
                }
            }
            let Some(accepted) = accepted else {
                return Err(TraceMaskError::AttemptCapExhausted { coefficient });
            };
            *coordinate = accepted;
        }
        Fp16::from_coefficients(coordinates).map_err(TraceMaskError::from)
    }))
}

/// Evaluate the canonical `2^log_size`-point coset vanishing polynomial.
pub fn canonical_coset_vanishing(
    point: BaseCirclePoint,
    log_size: u8,
) -> Result<M31, TraceMaskError> {
    if log_size == 0 || log_size > MAX_CIRCLE_DOMAIN_LOG_SIZE {
        return Err(TraceMaskError::TargetDomainTooSmall);
    }
    let mut x = point.x;
    for _ in 1..log_size {
        x = x.square().double().sub(M31::ONE);
    }
    Ok(x)
}

/// Precompute the same witness-domain zeroifier on every target-domain point.
/// The result depends only on domain geometry and is reusable across columns.
pub(crate) fn canonical_coset_zeroifier_evaluations(
    trace_log_size: u8,
    target_log_size: u8,
) -> Result<Vec<M31>, TraceMaskError> {
    if trace_log_size == 0
        || target_log_size <= trace_log_size
        || target_log_size > MAX_CIRCLE_DOMAIN_LOG_SIZE
    {
        return Err(TraceMaskError::TargetDomainTooSmall);
    }
    (0..1_usize << target_log_size)
        .map(|fft_index| {
            let natural_index = crate::circle_fri::bit_reverse_index(fft_index, target_log_size)
                .map_err(|_| TraceMaskError::TargetDomainTooSmall)?;
            let point = canonic_circle_point(target_log_size, natural_index)
                .map_err(|_| TraceMaskError::TargetDomainTooSmall)?;
            canonical_coset_vanishing(point, trace_log_size)
        })
        .collect()
}

/// Evaluate one masked trace column on a larger canonical Circle domain.
pub fn mask_trace_column(
    natural_trace: &[M31],
    randomizer_coefficients: &[M31],
    target_log_size: u8,
) -> Result<Vec<M31>, TraceMaskError> {
    if randomizer_coefficients.is_empty() {
        return Err(TraceMaskError::EmptyRandomizer);
    }
    if natural_trace.len() < 2 || !natural_trace.len().is_power_of_two() {
        return Err(TraceMaskError::TargetDomainTooSmall);
    }
    let trace_log_size = natural_trace.len().ilog2() as u8;
    let randomizer_size = randomizer_coefficients.len().next_power_of_two();
    let minimum_coefficient_count = natural_trace
        .len()
        .checked_add(randomizer_size)
        .ok_or(TraceMaskError::CountOverflow)?;
    let minimum_log_size = minimum_coefficient_count.next_power_of_two().ilog2() as u8;
    if target_log_size < minimum_log_size || target_log_size > MAX_CIRCLE_DOMAIN_LOG_SIZE {
        return Err(TraceMaskError::TargetDomainTooSmall);
    }

    let zeroifiers = canonical_coset_zeroifier_evaluations(trace_log_size, target_log_size)?;
    mask_trace_column_with_zeroifiers(
        natural_trace,
        randomizer_coefficients,
        target_log_size,
        &zeroifiers,
    )
}

/// Mask one base-field column using a verifier-independent domain cache.
pub(crate) fn mask_trace_column_with_zeroifiers(
    natural_trace: &[M31],
    randomizer_coefficients: &[M31],
    target_log_size: u8,
    zeroifiers: &[M31],
) -> Result<Vec<M31>, TraceMaskError> {
    if randomizer_coefficients.is_empty()
        || natural_trace.len() < 2
        || !natural_trace.len().is_power_of_two()
        || zeroifiers.len() != 1_usize << target_log_size
    {
        return Err(TraceMaskError::TargetDomainTooSmall);
    }
    let randomizer_size = randomizer_coefficients.len().next_power_of_two();
    let minimum_coefficient_count = natural_trace
        .len()
        .checked_add(randomizer_size)
        .ok_or(TraceMaskError::CountOverflow)?;
    let minimum_log_size = minimum_coefficient_count.next_power_of_two().ilog2() as u8;
    if target_log_size < minimum_log_size || target_log_size > MAX_CIRCLE_DOMAIN_LOG_SIZE {
        return Err(TraceMaskError::TargetDomainTooSmall);
    }
    let mut bit_reversed_trace = coset_order_to_circle_domain_order(natural_trace)?;
    bit_reverse_permute(&mut bit_reversed_trace)?;
    let trace_coefficients = interpolate_circle_evaluations(&bit_reversed_trace)?;
    let trace_evaluations = evaluate_circle_coefficients(&trace_coefficients, target_log_size)?;

    let mut randomizer = randomizer_coefficients.to_vec();
    randomizer.resize(randomizer_size, M31::ZERO);
    let randomizer_evaluations = evaluate_circle_coefficients(&randomizer, target_log_size)?;
    let mut masked = Vec::with_capacity(trace_evaluations.len());
    for fft_index in 0..trace_evaluations.len() {
        let zeroifier = zeroifiers[fft_index];
        masked.push(
            trace_evaluations[fft_index].add(zeroifier.mul(randomizer_evaluations[fft_index])),
        );
    }
    Ok(masked)
}

/// Mask an Fp16 interaction/composition column with the same exact zeroifier.
pub fn mask_extension_trace_column(
    natural_trace: &[Fp16],
    randomizer_coefficients: &[Fp16],
    target_log_size: u8,
) -> Result<Vec<Fp16>, TraceMaskError> {
    if randomizer_coefficients.is_empty()
        || natural_trace.len() < 2
        || !natural_trace.len().is_power_of_two()
    {
        return Err(TraceMaskError::EmptyRandomizer);
    }
    let trace_log_size = natural_trace.len().ilog2() as u8;
    let randomizer_size = randomizer_coefficients.len().next_power_of_two();
    let minimum_count = natural_trace
        .len()
        .checked_add(randomizer_size)
        .ok_or(TraceMaskError::CountOverflow)?;
    if target_log_size < minimum_count.next_power_of_two().ilog2() as u8
        || target_log_size > MAX_CIRCLE_DOMAIN_LOG_SIZE
    {
        return Err(TraceMaskError::TargetDomainTooSmall);
    }
    let zeroifiers = canonical_coset_zeroifier_evaluations(trace_log_size, target_log_size)?;
    mask_extension_trace_column_with_zeroifiers(
        natural_trace,
        randomizer_coefficients,
        target_log_size,
        &zeroifiers,
    )
}

/// Mask one extension-field column using a shared base-field zeroifier cache.
pub(crate) fn mask_extension_trace_column_with_zeroifiers(
    natural_trace: &[Fp16],
    randomizer_coefficients: &[Fp16],
    target_log_size: u8,
    zeroifiers: &[M31],
) -> Result<Vec<Fp16>, TraceMaskError> {
    if randomizer_coefficients.is_empty()
        || natural_trace.len() < 2
        || !natural_trace.len().is_power_of_two()
        || zeroifiers.len() != 1_usize << target_log_size
    {
        return Err(TraceMaskError::EmptyRandomizer);
    }
    let randomizer_size = randomizer_coefficients.len().next_power_of_two();
    let minimum_count = natural_trace
        .len()
        .checked_add(randomizer_size)
        .ok_or(TraceMaskError::CountOverflow)?;
    if target_log_size < minimum_count.next_power_of_two().ilog2() as u8
        || target_log_size > MAX_CIRCLE_DOMAIN_LOG_SIZE
    {
        return Err(TraceMaskError::TargetDomainTooSmall);
    }
    let mut bit_reversed = coset_order_to_circle_domain_order(natural_trace)?;
    bit_reverse_permute(&mut bit_reversed)?;
    let trace_coefficients = interpolate_extension_circle_evaluations(&bit_reversed)?;
    let trace_evaluations =
        evaluate_extension_circle_coefficients(&trace_coefficients, target_log_size)?;
    let mut randomizer = randomizer_coefficients.to_vec();
    randomizer.resize(randomizer_size, Fp16::ZERO);
    let randomizer_evaluations =
        evaluate_extension_circle_coefficients(&randomizer, target_log_size)?;
    let mut masked = Vec::with_capacity(trace_evaluations.len());
    for fft_index in 0..trace_evaluations.len() {
        let zeroifier = Fp16::from_m31(zeroifiers[fft_index]);
        masked.push(
            trace_evaluations[fft_index].add(zeroifier.mul(randomizer_evaluations[fft_index])),
        );
    }
    Ok(masked)
}

/// Confirm directly that masking preserves every witness-domain value.
pub fn verify_trace_mask_preservation(
    natural_trace: &[M31],
    randomizer_coefficients: &[M31],
) -> Result<bool, TraceMaskError> {
    if natural_trace.len() < 2 || !natural_trace.len().is_power_of_two() {
        return Err(TraceMaskError::TargetDomainTooSmall);
    }
    let log_size = natural_trace.len().ilog2() as u8;
    let circle_order_trace = coset_order_to_circle_domain_order(natural_trace)?;
    let mut bit_reversed_trace = circle_order_trace.clone();
    bit_reverse_permute(&mut bit_reversed_trace)?;
    let trace_coefficients = interpolate_circle_evaluations(&bit_reversed_trace)?;
    let mut randomizer = randomizer_coefficients.to_vec();
    if randomizer.is_empty() {
        return Err(TraceMaskError::EmptyRandomizer);
    }
    randomizer.resize(randomizer.len().next_power_of_two(), M31::ZERO);
    for (natural_index, expected) in circle_order_trace.iter().copied().enumerate() {
        let point = canonic_circle_point(log_size, natural_index)
            .map_err(|_| TraceMaskError::TargetDomainTooSmall)?;
        let witness = evaluate_coefficients_at_point(&trace_coefficients, point)?;
        let mask = evaluate_coefficients_at_point(&randomizer, point)?;
        let zeroifier = canonical_coset_vanishing(point, log_size)?;
        if witness.add(zeroifier.mul(mask)) != expected || !zeroifier.is_zero() {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn sampled_masks_are_reproducible_separated_and_preserve_trace() {
        let seed = [7_u8; 64];
        let session = [11_u8; 64];
        let oracle = [13_u8; 64];
        let coefficients = sample_trace_mask_coefficients(&seed, &session, &oracle, 19).unwrap();
        assert_eq!(coefficients.len(), 19);
        assert_eq!(
            coefficients,
            sample_trace_mask_coefficients(&seed, &session, &oracle, 19).unwrap()
        );
        assert_ne!(
            coefficients,
            sample_trace_mask_coefficients(&seed, &session, &[14_u8; 64], 19).unwrap()
        );
        let trace = (0_u32..32)
            .map(|value| M31::from_canonical(value * value + 5).unwrap())
            .collect::<Vec<_>>();
        let extension =
            sample_extension_trace_mask_coefficients(&seed, &session, &oracle, 19).unwrap();
        assert_eq!(extension.len(), 19);
        let streamed = stream_extension_trace_mask_coefficients(&seed, &session, &oracle, 19)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(streamed, extension);
        assert_eq!(
            stream_extension_trace_mask_coefficients(&seed, &session, &oracle, 19)
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            extension
        );
        let extension_trace = trace
            .iter()
            .copied()
            .map(Fp16::from_m31)
            .collect::<Vec<_>>();
        let extension_masked =
            mask_extension_trace_column(&extension_trace, &extension, 8).unwrap();
        assert_eq!(extension_masked.len(), 256);
        assert!(verify_trace_mask_preservation(&trace, &coefficients).unwrap());
        let masked = mask_trace_column(&trace, &coefficients, 8).unwrap();
        let zeroifiers = canonical_coset_zeroifier_evaluations(5, 8).unwrap();
        assert_eq!(
            masked,
            mask_trace_column_with_zeroifiers(&trace, &coefficients, 8, &zeroifiers).unwrap()
        );
        assert_eq!(
            extension_masked,
            mask_extension_trace_column_with_zeroifiers(
                &extension_trace,
                &extension,
                8,
                &zeroifiers,
            )
            .unwrap()
        );
        let unmasked = {
            let mut bit_reversed = coset_order_to_circle_domain_order(&trace).unwrap();
            bit_reverse_permute(&mut bit_reversed).unwrap();
            let coefficients = interpolate_circle_evaluations(&bit_reversed).unwrap();
            evaluate_circle_coefficients(&coefficients, 8).unwrap()
        };
        assert_ne!(masked, unmasked);
        let masked_coefficients = interpolate_circle_evaluations(&masked).unwrap();
        let used = masked_coefficients
            .iter()
            .rposition(|value| !value.is_zero())
            .unwrap()
            + 1;
        assert!(used <= 64, "masked coefficient count {used} exceeded n+h");
    }

    #[test]
    fn malformed_entropy_and_underexpanded_domain_fail_closed() {
        assert_eq!(
            sample_trace_mask_coefficients(&[0_u8; 63], &[0_u8; 64], &[0_u8; 64], 1),
            Err(TraceMaskError::SeedLength { actual: 63 })
        );
        let trace = vec![M31::ZERO; 32];
        assert_eq!(
            mask_trace_column(&trace, &[M31::ONE; 19], 5),
            Err(TraceMaskError::TargetDomainTooSmall)
        );
    }
}
