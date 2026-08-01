//! Common multilinear-PCS boundary for the Boolean GKR input layer.
//!
//! This module freezes only the field, soundness, decoding, and claim shape
//! shared by an eventual PCS prover and the independent verifier. It does not
//! treat a raw Merkle root or the existing Circle PCS as a multilinear opening.

use alloc::{vec, vec::Vec};
use core::fmt;
use sha3::{Digest, Sha3_512};

use crate::field::Fp16;
use crate::sampler::{DEFAULT_MAX_ATTEMPTS, sample_uniform_fp16};

/// Frozen per-term theorem floor.
pub const MLPCS_SECURITY_BITS: u16 = 256;
/// Code rate `1 / 8`.
pub const MLPCS_LOG_INVERSE_RATE: u8 = 3;
/// Unique-decoding distance `(1 - 1/8) / 2 = 7/16`.
pub const MLPCS_UNIQUE_DISTANCE_NUMERATOR: u8 = 7;
/// Denominator of the frozen unique-decoding distance.
pub const MLPCS_UNIQUE_DISTANCE_DENOMINATOR: u8 = 16;
/// Retained conservative repetitions; exceeds the minimum for `(9/16)^q <= 2^-256`.
pub const MLPCS_UNIQUE_QUERY_COUNT: usize = 473;
/// The selected lane forbids proof-of-work/grinding.
pub const MLPCS_POW_BITS: u8 = 0;
/// `v2((2^31 - 1)^16 - 1)`.
pub const MLPCS_FP16_TWO_ADICITY: u8 = 35;
/// Production padded Boolean input has `2^21` evaluations.
pub const MLPCS_INPUT_LOG_SIZE: u8 = 21;
/// zkDeepFold extends `f` with an equally long random coefficient vector.
pub const MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE: u8 = MLPCS_INPUT_LOG_SIZE + 1;
/// Hidden polynomial plus rate-`1/8` codeword domain.
pub const MLPCS_LDE_LOG_SIZE: u8 = MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE + MLPCS_LOG_INVERSE_RATE;
/// Minimum `ell` satisfying `2^ell > 473 * 21^2`.
pub const MLPCS_AUXILIARY_MASK_VARIABLES: u8 = 18;
/// Auxiliary random polynomial plus the same rate-`1/8` encoding.
pub const MLPCS_AUXILIARY_LDE_LOG_SIZE: u8 =
    MLPCS_AUXILIARY_MASK_VARIABLES + MLPCS_LOG_INVERSE_RATE;
/// Number of main folds before the auxiliary codeword has matching geometry.
pub const MLPCS_AUXILIARY_INJECTION_FOLD: u8 = MLPCS_LDE_LOG_SIZE - MLPCS_AUXILIARY_LDE_LOG_SIZE;

// `((2^31 - 1)^16 - 1) / 2^35`, little-endian u32 words.
const FP16_TWO_ADIC_COFACTOR: [u32; 16] = [
    0xbfff_ffff,
    0x4000_0003,
    0x37ff_fff7,
    0xf000_000e,
    0xa3ff_ffee,
    0xd400_000f,
    0x48bf_fff4,
    0x3500_0006,
    0xfa3f_fffd,
    0xbbc0_0000,
    0x0e37_ffff,
    0xfdd0_0000,
    0x003b_ffff,
    0xfffc_0000,
    0x0000_1fff,
    0,
];
const ROOT_SEED_DOMAIN: &[u8] = b"BL/PQ512/MLPCS/FP16-TWO-ADIC-ROOT/SEED/v1";
const ROOT_SESSION_DOMAIN: &[u8] = b"BL/PQ512/MLPCS/FP16-TWO-ADIC-ROOT/SESSION/v1";
const ROOT_CANDIDATE_LIMIT: u32 = 16;

/// Exact public parameters admitted at the GKR-to-PCS boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MultilinearPcsParameters {
    pub security_bits: u16,
    pub log_inverse_rate: u8,
    pub unique_query_count: usize,
    pub pow_bits: u8,
}

impl MultilinearPcsParameters {
    /// Returns the sole admitted non-activating parameter record.
    pub const fn selected() -> Self {
        Self {
            security_bits: MLPCS_SECURITY_BITS,
            log_inverse_rate: MLPCS_LOG_INVERSE_RATE,
            unique_query_count: MLPCS_UNIQUE_QUERY_COUNT,
            pow_bits: MLPCS_POW_BITS,
        }
    }

    /// Rejects parameter drift and any grinding allowance.
    pub fn validate(self) -> Result<(), MultilinearPcsError> {
        if self != Self::selected() {
            return Err(MultilinearPcsError::ParameterMismatch);
        }
        Ok(())
    }
}

/// One arbitrary-point opening claim for a Boolean-hypercube evaluation table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultilinearOpeningClaim {
    pub point: Vec<Fp16>,
    pub value: Fp16,
}

/// Two terminal claims over the B=8-interpolated GKR input table.
///
/// `point` coordinates are ordered as low wire bits followed by high group
/// bits. The three shard bits occupy the gap at `wire_variables` in the
/// committed raw Boolean table and are combined by the degree-7 Lagrange
/// weights derived from `shard_query`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackedGkrInputClaims {
    pub claims: [MultilinearOpeningClaim; 2],
    pub shard_query: Fp16,
    pub wire_variables: u8,
}

/// One terminal claim over the B=8-interpolated semantic output table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackedGkrOutputClaim {
    pub claim: MultilinearOpeningClaim,
    pub shard_query: Fp16,
    pub wire_variables: u8,
}

/// Fail-closed common-boundary error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MultilinearPcsError {
    ParameterMismatch,
    EmptyEvaluationTable,
    EvaluationTableNotPowerOfTwo { length: usize },
    PackedLengthMismatch { expected: usize, actual: usize },
    NonZeroPackedPadding,
    PointDimensionMismatch { expected: usize, actual: usize },
    MaskLengthMismatch { expected: usize, actual: usize },
    TwoAdicRootUnavailable,
    DomainLogSizeUnsupported { log_size: u8 },
    FriLayerShape,
}

/// Append the equally long private coefficient mask required by zkDeepFold.
///
/// The appended half consists of coefficients containing the new highest
/// variable. Consequently evaluation at `point || 0` is exactly the original
/// polynomial evaluation, while every nonzero value of that variable mixes in
/// the private polynomial.
pub fn extend_multilinear_coefficients_with_mask(
    coefficients: &[Fp16],
    mask_coefficients: &[Fp16],
) -> Result<Vec<Fp16>, MultilinearPcsError> {
    if coefficients.is_empty() {
        return Err(MultilinearPcsError::EmptyEvaluationTable);
    }
    if !coefficients.len().is_power_of_two() {
        return Err(MultilinearPcsError::EvaluationTableNotPowerOfTwo {
            length: coefficients.len(),
        });
    }
    if mask_coefficients.len() != coefficients.len() {
        return Err(MultilinearPcsError::MaskLengthMismatch {
            expected: coefficients.len(),
            actual: mask_coefficients.len(),
        });
    }
    let mut extended = Vec::with_capacity(2 * coefficients.len());
    extended.extend_from_slice(coefficients);
    extended.extend_from_slice(mask_coefficients);
    Ok(extended)
}

/// Evaluate a multilinear polynomial supplied in monomial-coefficient order.
pub fn evaluate_multilinear_coefficients(
    coefficients: &[Fp16],
    point: &[Fp16],
) -> Result<Fp16, MultilinearPcsError> {
    if coefficients.is_empty() {
        return Err(MultilinearPcsError::EmptyEvaluationTable);
    }
    if !coefficients.len().is_power_of_two() {
        return Err(MultilinearPcsError::EvaluationTableNotPowerOfTwo {
            length: coefficients.len(),
        });
    }
    let expected = coefficients.len().ilog2() as usize;
    if point.len() != expected {
        return Err(MultilinearPcsError::PointDimensionMismatch {
            expected,
            actual: point.len(),
        });
    }
    let mut folded = coefficients.to_vec();
    let mut active = folded.len();
    for challenge in point {
        for index in 0..active / 2 {
            folded[index] = folded[2 * index] + *challenge * folded[2 * index + 1];
        }
        active /= 2;
    }
    Ok(folded[0])
}

/// Convert multilinear monomial coefficients to Boolean-hypercube values.
///
/// This is the inverse of the Möbius transform used by
/// [`interpolate_packed_boolean_hypercube`].
pub fn multilinear_coefficients_to_hypercube(
    coefficients: &[Fp16],
) -> Result<Vec<Fp16>, MultilinearPcsError> {
    if coefficients.is_empty() {
        return Err(MultilinearPcsError::EmptyEvaluationTable);
    }
    if !coefficients.len().is_power_of_two() {
        return Err(MultilinearPcsError::EvaluationTableNotPowerOfTwo {
            length: coefficients.len(),
        });
    }
    let mut evaluations = coefficients.to_vec();
    for coordinate in 0..coefficients.len().ilog2() {
        let half = 1_usize << coordinate;
        for block in evaluations.chunks_exact_mut(2 * half) {
            for index in 0..half {
                block[half + index] = block[half + index] + block[index];
            }
        }
    }
    Ok(evaluations)
}

impl fmt::Display for MultilinearPcsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "BL-PQ512 multilinear PCS error: {self:?}")
    }
}

impl core::error::Error for MultilinearPcsError {}

/// Deterministically derive a primitive `2^log_order` root in Fp16.
///
/// Candidates are uniform SHA3-512 rejection samples projected into the
/// 2-Sylow subgroup. The first candidate of exact order is selected.
pub fn derive_two_adic_root(log_order: u8) -> Result<Fp16, MultilinearPcsError> {
    if log_order == 0 || log_order > MLPCS_FP16_TWO_ADICITY {
        return Err(MultilinearPcsError::TwoAdicRootUnavailable);
    }
    let seed: [u8; 64] = Sha3_512::digest(ROOT_SEED_DOMAIN).into();
    let session: [u8; 64] = Sha3_512::digest(ROOT_SESSION_DOMAIN).into();
    for draw_index in 0..ROOT_CANDIDATE_LIMIT {
        let candidate = sample_uniform_fp16(&seed, &session, 0, draw_index, DEFAULT_MAX_ATTEMPTS)
            .map_err(|_| MultilinearPcsError::TwoAdicRootUnavailable)?
            .element
            .pow_words_le(&FP16_TWO_ADIC_COFACTOR);
        let mut root = candidate;
        for _ in log_order..MLPCS_FP16_TWO_ADICITY {
            root = root.square();
        }
        let mut full_power = root;
        for _ in 0..log_order {
            full_power = full_power.square();
        }
        let mut half_power = root;
        for _ in 1..log_order {
            half_power = half_power.square();
        }
        if full_power == Fp16::ONE && half_power != Fp16::ONE {
            return Ok(root);
        }
    }
    Err(MultilinearPcsError::TwoAdicRootUnavailable)
}

/// Evaluate coefficients over the selected power-of-two multiplicative
/// subgroup using a radix-2 NTT.
///
/// This scalar implementation is the independent algebra reference. It is not
/// the production throughput lane for the `2^25` hidden codeword.
pub fn evaluate_univariate_lde(
    coefficients: &[Fp16],
    log_inverse_rate: u8,
) -> Result<Vec<Fp16>, MultilinearPcsError> {
    if coefficients.is_empty() {
        return Err(MultilinearPcsError::EmptyEvaluationTable);
    }
    if !coefficients.len().is_power_of_two() {
        return Err(MultilinearPcsError::EvaluationTableNotPowerOfTwo {
            length: coefficients.len(),
        });
    }
    let coefficient_log_size = coefficients.len().ilog2() as u8;
    let log_size = coefficient_log_size
        .checked_add(log_inverse_rate)
        .ok_or(MultilinearPcsError::DomainLogSizeUnsupported { log_size: u8::MAX })?;
    if log_size > MLPCS_FP16_TWO_ADICITY {
        return Err(MultilinearPcsError::DomainLogSizeUnsupported { log_size });
    }
    let mut evaluations = vec![Fp16::ZERO; 1_usize << log_size];
    evaluations[..coefficients.len()].copy_from_slice(coefficients);
    ntt_in_place(&mut evaluations, derive_two_adic_root(log_size)?);
    Ok(evaluations)
}

/// Fold one multiplicative-subgroup FRI layer after an authenticated challenge.
///
/// Natural-order entries `i` and `i + n/2` are evaluations at `x` and `-x`.
pub fn fold_multiplicative_fri_layer(
    evaluations: &[Fp16],
    root: Fp16,
    challenge: Fp16,
) -> Result<Vec<Fp16>, MultilinearPcsError> {
    if evaluations.len() < 2 || !evaluations.len().is_power_of_two() {
        return Err(MultilinearPcsError::FriLayerShape);
    }
    let inverse_two = Fp16::ONE
        .add(Fp16::ONE)
        .inverse()
        .map_err(|_| MultilinearPcsError::FriLayerShape)?;
    let inverse_root = root
        .inverse()
        .map_err(|_| MultilinearPcsError::FriLayerShape)?;
    let half = evaluations.len() / 2;
    let mut inverse_x = Fp16::ONE;
    let mut folded = Vec::with_capacity(half);
    for index in 0..half {
        let at_x = evaluations[index];
        let at_negative_x = evaluations[index + half];
        let even = at_x.add(at_negative_x).mul(inverse_two);
        let odd = at_x.sub(at_negative_x).mul(inverse_two).mul(inverse_x);
        folded.push(even.add(challenge.mul(odd)));
        inverse_x = inverse_x.mul(inverse_root);
    }
    Ok(folded)
}

/// Fold one layer and optionally inject a same-domain auxiliary codeword.
///
/// The auxiliary term is added after the main even/odd fold, matching
/// `f^(i) = f_E^(i) + r_i f_O^(i) + gamma_i g` in DeepFold.BatchEval.
pub fn fold_multiplicative_batch_layer(
    evaluations: &[Fp16],
    root: Fp16,
    fold_challenge: Fp16,
    auxiliary: Option<(&[Fp16], Fp16)>,
) -> Result<Vec<Fp16>, MultilinearPcsError> {
    let mut folded = fold_multiplicative_fri_layer(evaluations, root, fold_challenge)?;
    if let Some((auxiliary_evaluations, mixing_challenge)) = auxiliary {
        if auxiliary_evaluations.len() != folded.len() {
            return Err(MultilinearPcsError::FriLayerShape);
        }
        for (value, mask) in folded.iter_mut().zip(auxiliary_evaluations.iter().copied()) {
            *value = *value + mixing_challenge * mask;
        }
    }
    Ok(folded)
}

/// Byte-identical bounded-worker implementation of one batch fold.
#[cfg(feature = "parallel")]
pub fn fold_multiplicative_batch_layer_parallel(
    evaluations: &[Fp16],
    root: Fp16,
    fold_challenge: Fp16,
    auxiliary: Option<(&[Fp16], Fp16)>,
    workers: usize,
) -> Result<Vec<Fp16>, MultilinearPcsError> {
    if evaluations.len() < 2
        || !evaluations.len().is_power_of_two()
        || workers == 0
        || auxiliary
            .as_ref()
            .is_some_and(|(values, _)| values.len() != evaluations.len() / 2)
    {
        return Err(MultilinearPcsError::FriLayerShape);
    }
    if workers == 1 || evaluations.len() < 1 << 15 {
        return fold_multiplicative_batch_layer(evaluations, root, fold_challenge, auxiliary);
    }
    let inverse_two = (Fp16::ONE + Fp16::ONE)
        .inverse()
        .map_err(|_| MultilinearPcsError::FriLayerShape)?;
    let inverse_root = root
        .inverse()
        .map_err(|_| MultilinearPcsError::FriLayerShape)?;
    let half = evaluations.len() / 2;
    let mut folded = vec![Fp16::ZERO; half];
    let chunk = half.div_ceil(workers.min(half));
    std::thread::scope(|scope| {
        for (chunk_ordinal, output) in folded.chunks_mut(chunk).enumerate() {
            let start = chunk_ordinal * chunk;
            let auxiliary =
                auxiliary.map(|(values, mixing)| (&values[start..start + output.len()], mixing));
            scope.spawn(move || {
                let mut inverse_x = inverse_root.pow_u32(start as u32);
                for (offset, destination) in output.iter_mut().enumerate() {
                    let index = start + offset;
                    let at_x = evaluations[index];
                    let at_negative_x = evaluations[index + half];
                    let even = (at_x + at_negative_x) * inverse_two;
                    let odd = (at_x - at_negative_x) * inverse_two * inverse_x;
                    *destination = even + fold_challenge * odd;
                    if let Some((values, mixing)) = auxiliary {
                        *destination = *destination + mixing * values[offset];
                    }
                    inverse_x = inverse_x * inverse_root;
                }
            });
        }
    });
    Ok(folded)
}

/// Byte-identical parallel batch fold that overwrites the lower half and
/// releases the upper half without allocating a second field layer.
#[cfg(feature = "parallel")]
pub fn fold_multiplicative_batch_layer_in_place_parallel(
    evaluations: &mut Vec<Fp16>,
    root: Fp16,
    fold_challenge: Fp16,
    auxiliary: Option<(&[Fp16], Fp16)>,
    workers: usize,
) -> Result<(), MultilinearPcsError> {
    if evaluations.len() < 2
        || !evaluations.len().is_power_of_two()
        || workers == 0
        || auxiliary
            .as_ref()
            .is_some_and(|(values, _)| values.len() != evaluations.len() / 2)
    {
        return Err(MultilinearPcsError::FriLayerShape);
    }
    let inverse_two = (Fp16::ONE + Fp16::ONE)
        .inverse()
        .map_err(|_| MultilinearPcsError::FriLayerShape)?;
    let inverse_root = root
        .inverse()
        .map_err(|_| MultilinearPcsError::FriLayerShape)?;
    let half = evaluations.len() / 2;
    let chunk = half.div_ceil(workers.min(half));
    let (lower, upper) = evaluations.split_at_mut(half);
    std::thread::scope(|scope| {
        for (chunk_ordinal, (output, negative)) in
            lower.chunks_mut(chunk).zip(upper.chunks(chunk)).enumerate()
        {
            let start = chunk_ordinal * chunk;
            let auxiliary =
                auxiliary.map(|(values, mixing)| (&values[start..start + output.len()], mixing));
            scope.spawn(move || {
                let mut inverse_x = inverse_root.pow_u32(start as u32);
                for (offset, (destination, at_negative_x)) in
                    output.iter_mut().zip(negative.iter().copied()).enumerate()
                {
                    let at_x = *destination;
                    let even = (at_x + at_negative_x) * inverse_two;
                    let odd = (at_x - at_negative_x) * inverse_two * inverse_x;
                    *destination = even + fold_challenge * odd;
                    if let Some((values, mixing)) = auxiliary {
                        *destination = *destination + mixing * values[offset];
                    }
                    inverse_x = inverse_x * inverse_root;
                }
            });
        }
    });
    evaluations.truncate(half);
    Ok(())
}

/// Verify one opened `x,-x` fold relation, with an optional injected value at
/// `x^2`. Merkle authentication remains a separate mandatory check.
pub fn verify_multiplicative_batch_fold(
    at_x: Fp16,
    at_negative_x: Fp16,
    inverse_x: Fp16,
    fold_challenge: Fp16,
    auxiliary_at_x_squared: Option<(Fp16, Fp16)>,
    expected_at_x_squared: Fp16,
) -> Result<bool, MultilinearPcsError> {
    let inverse_two = (Fp16::ONE + Fp16::ONE)
        .inverse()
        .map_err(|_| MultilinearPcsError::FriLayerShape)?;
    let even = (at_x + at_negative_x) * inverse_two;
    let odd = (at_x - at_negative_x) * inverse_two * inverse_x;
    let mut folded = even + fold_challenge * odd;
    if let Some((auxiliary, mixing_challenge)) = auxiliary_at_x_squared {
        folded = folded + mixing_challenge * auxiliary;
    }
    Ok(folded == expected_at_x_squared)
}

fn ntt_in_place(values: &mut [Fp16], root: Fp16) {
    let count = values.len();
    let log_size = count.ilog2();
    for index in 1..count {
        let reversed = index.reverse_bits() >> (usize::BITS - log_size);
        if index < reversed {
            values.swap(index, reversed);
        }
    }
    let mut length = 2;
    while length <= count {
        let stage_log = length.ilog2();
        let mut stage_root = root;
        for _ in stage_log..log_size {
            stage_root = stage_root.square();
        }
        for block in values.chunks_exact_mut(length) {
            let mut twiddle = Fp16::ONE;
            let half = length / 2;
            for index in 0..half {
                let left = block[index];
                let right = block[half + index].mul(twiddle);
                block[index] = left.add(right);
                block[half + index] = left.sub(right);
                twiddle = twiddle.mul(stage_root);
            }
        }
        if length == count {
            break;
        }
        length *= 2;
    }
}

/// Evaluate the unique multilinear extension of `evaluations` at `point`.
///
/// `evaluations` are ordered by the Boolean index whose least-significant bit
/// corresponds to `point[0]`. The implementation folds in place and retains no
/// second full-size field buffer.
pub fn evaluate_multilinear(
    evaluations: &[Fp16],
    point: &[Fp16],
) -> Result<Fp16, MultilinearPcsError> {
    if evaluations.is_empty() {
        return Err(MultilinearPcsError::EmptyEvaluationTable);
    }
    if !evaluations.len().is_power_of_two() {
        return Err(MultilinearPcsError::EvaluationTableNotPowerOfTwo {
            length: evaluations.len(),
        });
    }
    let expected = evaluations.len().ilog2() as usize;
    if point.len() != expected {
        return Err(MultilinearPcsError::PointDimensionMismatch {
            expected,
            actual: point.len(),
        });
    }

    let mut folded = evaluations.to_vec();
    let mut active = folded.len();
    for challenge in point {
        let one_minus = Fp16::ONE.sub(*challenge);
        for index in 0..active / 2 {
            let left = folded[2 * index];
            let right = folded[2 * index + 1];
            folded[index] = left.mul(one_minus).add(right.mul(*challenge));
        }
        active /= 2;
    }
    Ok(folded[0])
}

/// Evaluate a packed Boolean table without first expanding it to `Fp16`.
///
/// Bits are read least-significant-bit first. `evaluation_count` must describe
/// the complete power-of-two table, and unused high bits in the last byte must
/// be zero so that alternate encodings cannot represent the same statement.
pub fn evaluate_packed_boolean_multilinear(
    packed: &[u8],
    evaluation_count: usize,
    point: &[Fp16],
) -> Result<Fp16, MultilinearPcsError> {
    if evaluation_count == 0 {
        return Err(MultilinearPcsError::EmptyEvaluationTable);
    }
    if !evaluation_count.is_power_of_two() {
        return Err(MultilinearPcsError::EvaluationTableNotPowerOfTwo {
            length: evaluation_count,
        });
    }
    let expected_bytes = evaluation_count.div_ceil(8);
    if packed.len() != expected_bytes {
        return Err(MultilinearPcsError::PackedLengthMismatch {
            expected: expected_bytes,
            actual: packed.len(),
        });
    }
    let unused_bits = expected_bytes * 8 - evaluation_count;
    if unused_bits != 0 && packed[expected_bytes - 1] >> (8 - unused_bits) != 0 {
        return Err(MultilinearPcsError::NonZeroPackedPadding);
    }
    let expected_dimension = evaluation_count.ilog2() as usize;
    if point.len() != expected_dimension {
        return Err(MultilinearPcsError::PointDimensionMismatch {
            expected: expected_dimension,
            actual: point.len(),
        });
    }
    if evaluation_count == 1 {
        return Ok(if packed[0] & 1 == 0 {
            Fp16::ZERO
        } else {
            Fp16::ONE
        });
    }

    let first_challenge = point[0];
    let first_one_minus = Fp16::ONE.sub(first_challenge);
    let mut folded = Vec::with_capacity(evaluation_count / 2);
    for pair in 0..evaluation_count / 2 {
        let left_index = 2 * pair;
        let right_index = left_index + 1;
        let left = (packed[left_index / 8] >> (left_index % 8)) & 1;
        let right = (packed[right_index / 8] >> (right_index % 8)) & 1;
        folded.push(match (left, right) {
            (0, 0) => Fp16::ZERO,
            (0, 1) => first_challenge,
            (1, 0) => first_one_minus,
            (1, 1) => Fp16::ONE,
            _ => unreachable!("masked bits are Boolean"),
        });
    }

    let mut active = folded.len();
    for challenge in &point[1..] {
        let one_minus = Fp16::ONE.sub(*challenge);
        for index in 0..active / 2 {
            let left = folded[2 * index];
            let right = folded[2 * index + 1];
            folded[index] = left.mul(one_minus).add(right.mul(*challenge));
        }
        active /= 2;
    }
    Ok(folded[0])
}

/// Convert a packed Boolean-hypercube evaluation table to multilinear
/// monomial coefficients with an in-place Möbius transform.
///
/// Coefficient index bits use the same least-significant-coordinate ordering
/// as [`evaluate_multilinear`]. The returned field vector is the single
/// full-size allocation required by the later foldable-code encoder.
pub fn interpolate_packed_boolean_hypercube(
    packed: &[u8],
    evaluation_count: usize,
) -> Result<Vec<Fp16>, MultilinearPcsError> {
    if evaluation_count == 0 {
        return Err(MultilinearPcsError::EmptyEvaluationTable);
    }
    if !evaluation_count.is_power_of_two() {
        return Err(MultilinearPcsError::EvaluationTableNotPowerOfTwo {
            length: evaluation_count,
        });
    }
    let expected_bytes = evaluation_count.div_ceil(8);
    if packed.len() != expected_bytes {
        return Err(MultilinearPcsError::PackedLengthMismatch {
            expected: expected_bytes,
            actual: packed.len(),
        });
    }
    let unused_bits = expected_bytes * 8 - evaluation_count;
    if unused_bits != 0 && packed[expected_bytes - 1] >> (8 - unused_bits) != 0 {
        return Err(MultilinearPcsError::NonZeroPackedPadding);
    }

    let mut coefficients = (0..evaluation_count)
        .map(|index| {
            if (packed[index / 8] >> (index % 8)) & 1 == 0 {
                Fp16::ZERO
            } else {
                Fp16::ONE
            }
        })
        .collect::<Vec<_>>();
    for coordinate in 0..evaluation_count.ilog2() {
        let half = 1_usize << coordinate;
        for block in coefficients.chunks_exact_mut(2 * half) {
            for index in 0..half {
                block[half + index] = block[half + index].sub(block[index]);
            }
        }
    }
    Ok(coefficients)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::M31;

    fn fp(value: u32) -> Fp16 {
        Fp16::from_m31(M31::from_canonical(value).unwrap())
    }

    #[test]
    fn selected_parameters_are_exact_and_forbid_grinding() {
        assert_eq!(
            MultilinearPcsParameters::selected(),
            MultilinearPcsParameters {
                security_bits: 256,
                log_inverse_rate: 3,
                unique_query_count: 473,
                pow_bits: 0,
            }
        );
        assert_eq!(MultilinearPcsParameters::selected().validate(), Ok(()));
        assert_eq!(
            MultilinearPcsParameters {
                pow_bits: 1,
                ..MultilinearPcsParameters::selected()
            }
            .validate(),
            Err(MultilinearPcsError::ParameterMismatch)
        );
    }

    #[test]
    fn multilinear_evaluation_matches_two_variable_formula() {
        let evaluations = [fp(2), fp(5), fp(11), fp(17)];
        let point = [fp(3), fp(7)];
        let first = evaluations[0]
            .mul(Fp16::ONE.sub(point[0]))
            .add(evaluations[1].mul(point[0]));
        let second = evaluations[2]
            .mul(Fp16::ONE.sub(point[0]))
            .add(evaluations[3].mul(point[0]));
        let expected = first.mul(Fp16::ONE.sub(point[1])).add(second.mul(point[1]));
        assert_eq!(
            evaluate_multilinear(&evaluations, &point).unwrap(),
            expected
        );
    }

    #[test]
    fn multilinear_evaluation_rejects_shape_drift() {
        assert_eq!(
            evaluate_multilinear(&[Fp16::ZERO; 3], &[Fp16::ZERO]),
            Err(MultilinearPcsError::EvaluationTableNotPowerOfTwo { length: 3 })
        );
        assert_eq!(
            evaluate_multilinear(&[Fp16::ZERO; 4], &[Fp16::ZERO]),
            Err(MultilinearPcsError::PointDimensionMismatch {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn packed_boolean_evaluation_matches_generic_fold() {
        let evaluation_count = 64;
        let mut packed = [0_u8; 8];
        let evaluations: Vec<_> = (0..evaluation_count)
            .map(|index| {
                let bit = ((index * 13 + index / 3 + 1) % 7 < 3) as u8;
                packed[index / 8] |= bit << (index % 8);
                if bit == 0 { Fp16::ZERO } else { Fp16::ONE }
            })
            .collect();
        let point: Vec<_> = (0..6).map(|index| fp(index as u32 + 2)).collect();
        assert_eq!(
            evaluate_packed_boolean_multilinear(&packed, evaluation_count, &point).unwrap(),
            evaluate_multilinear(&evaluations, &point).unwrap()
        );
    }

    #[test]
    fn packed_boolean_evaluation_rejects_shape_drift() {
        assert_eq!(
            evaluate_packed_boolean_multilinear(&[0_u8; 1], 4, &[Fp16::ZERO; 2]),
            Ok(Fp16::ZERO)
        );
        assert_eq!(
            evaluate_packed_boolean_multilinear(&[0_u8; 2], 4, &[Fp16::ZERO; 2]),
            Err(MultilinearPcsError::PackedLengthMismatch {
                expected: 1,
                actual: 2,
            })
        );
        assert_eq!(
            evaluate_packed_boolean_multilinear(&[0b1111_0000], 4, &[Fp16::ZERO; 2]),
            Err(MultilinearPcsError::NonZeroPackedPadding)
        );
    }

    #[test]
    fn packed_boolean_interpolation_matches_multilinear_evaluation() {
        let packed = [0b1010_0110, 0b0110_1001];
        let point = [fp(2), fp(3), fp(5), fp(7)];
        let coefficients = interpolate_packed_boolean_hypercube(&packed, 16).unwrap();
        let mut coefficient_evaluation = Fp16::ZERO;
        for (index, coefficient) in coefficients.into_iter().enumerate() {
            let mut monomial = Fp16::ONE;
            for (coordinate, challenge) in point.iter().copied().enumerate() {
                if (index >> coordinate) & 1 == 1 {
                    monomial = monomial.mul(challenge);
                }
            }
            coefficient_evaluation = coefficient_evaluation.add(coefficient.mul(monomial));
        }
        assert_eq!(
            coefficient_evaluation,
            evaluate_packed_boolean_multilinear(&packed, 16, &point).unwrap()
        );
    }

    #[test]
    fn hidden_coefficient_extension_preserves_the_zero_slice() {
        let original = [fp(2), fp(3), fp(5), fp(7)];
        let mask = [fp(11), fp(13), fp(17), fp(19)];
        let extended = extend_multilinear_coefficients_with_mask(&original, &mask).unwrap();
        let point = [fp(23), fp(29)];
        let mut hidden_point = point.to_vec();
        hidden_point.push(Fp16::ZERO);
        assert_eq!(
            evaluate_multilinear_coefficients(&extended, &hidden_point).unwrap(),
            evaluate_multilinear_coefficients(&original, &point).unwrap()
        );
        hidden_point[2] = fp(31);
        assert_ne!(
            evaluate_multilinear_coefficients(&extended, &hidden_point).unwrap(),
            evaluate_multilinear_coefficients(&original, &point).unwrap()
        );
    }

    #[test]
    fn coefficient_to_hypercube_conversion_matches_both_evaluators() {
        let coefficients = [fp(2), fp(3), fp(5), fp(7), fp(11), fp(13), fp(17), fp(19)];
        let point = [fp(23), fp(29), fp(31)];
        let evaluations = multilinear_coefficients_to_hypercube(&coefficients).unwrap();
        assert_eq!(
            evaluate_multilinear_coefficients(&coefficients, &point).unwrap(),
            evaluate_multilinear(&evaluations, &point).unwrap()
        );
    }

    #[test]
    fn selected_lde_root_has_exact_order() {
        let root = derive_two_adic_root(MLPCS_LDE_LOG_SIZE).unwrap();
        let mut full_power = root;
        for _ in 0..MLPCS_LDE_LOG_SIZE {
            full_power = full_power.square();
        }
        let mut half_power = root;
        for _ in 1..MLPCS_LDE_LOG_SIZE {
            half_power = half_power.square();
        }
        assert_eq!(full_power, Fp16::ONE);
        assert_ne!(half_power, Fp16::ONE);
    }

    #[test]
    fn selected_hiding_geometry_is_minimal_and_exact() {
        assert_eq!(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE, 22);
        assert_eq!(MLPCS_LDE_LOG_SIZE, 25);
        let leakage_bound = MLPCS_UNIQUE_QUERY_COUNT * usize::from(MLPCS_INPUT_LOG_SIZE).pow(2);
        assert!((1_usize << MLPCS_AUXILIARY_MASK_VARIABLES) > leakage_bound);
        assert!((1_usize << (MLPCS_AUXILIARY_MASK_VARIABLES - 1)) <= leakage_bound);
        assert_eq!(MLPCS_AUXILIARY_LDE_LOG_SIZE, 21);
        assert_eq!(MLPCS_AUXILIARY_INJECTION_FOLD, 4);
    }

    #[test]
    fn scalar_ntt_matches_direct_univariate_evaluation() {
        let coefficients = [fp(2), fp(3), fp(5), fp(7)];
        let evaluations = evaluate_univariate_lde(&coefficients, 1).unwrap();
        let root = derive_two_adic_root(3).unwrap();
        let mut point = Fp16::ONE;
        for evaluation in evaluations {
            let expected = coefficients
                .iter()
                .rev()
                .fold(Fp16::ZERO, |value, coefficient| {
                    value.mul(point).add(*coefficient)
                });
            assert_eq!(evaluation, expected);
            point = point.mul(root);
        }
    }

    #[test]
    fn multiplicative_fri_fold_matches_folded_coefficients() {
        let coefficients = [fp(2), fp(3), fp(5), fp(7)];
        let challenge = fp(11);
        let evaluations = evaluate_univariate_lde(&coefficients, 1).unwrap();
        let folded = fold_multiplicative_fri_layer(
            &evaluations,
            derive_two_adic_root(3).unwrap(),
            challenge,
        )
        .unwrap();
        let expected_coefficients = [
            coefficients[0].add(challenge.mul(coefficients[1])),
            coefficients[2].add(challenge.mul(coefficients[3])),
        ];
        assert_eq!(
            folded,
            evaluate_univariate_lde(&expected_coefficients, 1).unwrap()
        );
    }

    #[test]
    fn multiplicative_batch_fold_injects_at_the_folded_domain() {
        let coefficients = [fp(2), fp(3), fp(5), fp(7)];
        let auxiliary_coefficients = [fp(11), fp(13)];
        let fold_challenge = fp(17);
        let mixing_challenge = fp(19);
        let evaluations = evaluate_univariate_lde(&coefficients, 1).unwrap();
        let auxiliary = evaluate_univariate_lde(&auxiliary_coefficients, 1).unwrap();
        let root = derive_two_adic_root(3).unwrap();
        let folded = fold_multiplicative_batch_layer(
            &evaluations,
            root,
            fold_challenge,
            Some((&auxiliary, mixing_challenge)),
        )
        .unwrap();
        let expected_coefficients = [
            coefficients[0]
                + fold_challenge * coefficients[1]
                + mixing_challenge * auxiliary_coefficients[0],
            coefficients[2]
                + fold_challenge * coefficients[3]
                + mixing_challenge * auxiliary_coefficients[1],
        ];
        assert_eq!(
            folded,
            evaluate_univariate_lde(&expected_coefficients, 1).unwrap()
        );

        let inverse_x = root.inverse().unwrap();
        assert!(
            verify_multiplicative_batch_fold(
                evaluations[1],
                evaluations[5],
                inverse_x,
                fold_challenge,
                Some((auxiliary[1], mixing_challenge)),
                folded[1],
            )
            .unwrap()
        );
        assert!(
            !verify_multiplicative_batch_fold(
                evaluations[1],
                evaluations[5],
                inverse_x,
                fold_challenge,
                Some((auxiliary[1], mixing_challenge)),
                folded[1] + Fp16::ONE,
            )
            .unwrap()
        );
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn parallel_batch_fold_matches_scalar_above_parallel_threshold() {
        let evaluations = (0..1 << 15)
            .map(|index| fp(1 + (index as u32 * 17) % 65_521))
            .collect::<Vec<_>>();
        let auxiliary = (0..1 << 14)
            .map(|index| fp(3 + (index as u32 * 29) % 65_519))
            .collect::<Vec<_>>();
        let root = derive_two_adic_root(15).unwrap();
        let challenge = fp(101);
        let mixing = fp(103);
        let scalar = fold_multiplicative_batch_layer(
            &evaluations,
            root,
            challenge,
            Some((&auxiliary, mixing)),
        )
        .unwrap();
        assert_eq!(
            fold_multiplicative_batch_layer_parallel(
                &evaluations,
                root,
                challenge,
                Some((&auxiliary, mixing)),
                4,
            )
            .unwrap(),
            scalar
        );
        let mut in_place = evaluations;
        fold_multiplicative_batch_layer_in_place_parallel(
            &mut in_place,
            root,
            challenge,
            Some((&auxiliary, mixing)),
            4,
        )
        .unwrap();
        assert_eq!(in_place, scalar);
    }
}
