//! Nonactivating replay reference for bounded-memory multilinear PCS layers.
//!
//! This module changes no transcript, commitment, proof, or verifier semantics.
//! It evaluates the existing hidden polynomial and every multiplicative-FRI
//! layer directly from replayable source values. The intended production source
//! is the canonical packed Boolean boundary plus the existing fresh,
//! domain-separated secret mask seed. No full evaluation, equality-weight,
//! mask-coefficient, codeword, or folded-layer vector is retained here.

use alloc::vec::Vec;

use crate::{
    field::Fp16,
    multilinear_pcs::{MultilinearPcsError, derive_two_adic_root},
};

/// Failure while replaying one value of the existing multilinear PCS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamingMlpcsError {
    Shape,
    Pcs(MultilinearPcsError),
}

impl From<MultilinearPcsError> for StreamingMlpcsError {
    fn from(value: MultilinearPcsError) -> Self {
        Self::Pcs(value)
    }
}

fn pow_usize(mut base: Fp16, mut exponent: usize) -> Fp16 {
    let mut result = Fp16::ONE;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = result * base;
        }
        base = base.square();
        exponent >>= 1;
    }
    result
}

fn equality_weight(index: usize, point: &[Fp16]) -> Fp16 {
    point
        .iter()
        .copied()
        .enumerate()
        .fold(Fp16::ONE, |weight, (coordinate, challenge)| {
            if index & (1_usize << coordinate) == 0 {
                weight * (Fp16::ONE - challenge)
            } else {
                weight * challenge
            }
        })
}

fn monomial_weight(index: usize, point: &[Fp16]) -> Fp16 {
    point
        .iter()
        .copied()
        .enumerate()
        .filter(|(coordinate, _)| index & (1_usize << coordinate) != 0)
        .fold(Fp16::ONE, |weight, (_, challenge)| weight * challenge)
}

/// Evaluate a Boolean-hypercube multilinear extension without retaining its
/// values or its equality-weight vector.
pub fn replayed_multilinear_evaluation<E>(
    variables: u8,
    point: &[Fp16],
    evaluation_at: E,
) -> Result<Fp16, StreamingMlpcsError>
where
    E: Fn(usize) -> Fp16,
{
    if point.len() != usize::from(variables) || usize::from(variables) >= usize::BITS as usize {
        return Err(StreamingMlpcsError::Shape);
    }
    let count = 1_usize << variables;
    Ok((0..count).fold(Fp16::ZERO, |sum, index| {
        sum + evaluation_at(index) * equality_weight(index, point)
    }))
}

/// Evaluate monomial-ordered coefficients without retaining the coefficients
/// or a power table.
pub fn replayed_monomial_evaluation<C>(
    variables: u8,
    point: &[Fp16],
    coefficient_at: C,
) -> Result<Fp16, StreamingMlpcsError>
where
    C: Fn(usize) -> Fp16,
{
    if point.len() != usize::from(variables) || usize::from(variables) >= usize::BITS as usize {
        return Err(StreamingMlpcsError::Shape);
    }
    let count = 1_usize << variables;
    Ok((0..count).fold(Fp16::ZERO, |sum, index| {
        sum + coefficient_at(index) * monomial_weight(index, point)
    }))
}

/// Replay one value from any layer of the existing hidden-polynomial FRI.
///
/// `fold_round` is the number of already accepted fold challenges. Round zero
/// is the initial LDE. The final supported round equals `variables + 1`, after
/// the appended mask half has also been folded. The result is algebraically
/// identical to materializing the hidden coefficients, running the NTT, and
/// applying the existing fold equations.
#[allow(clippy::too_many_arguments)]
pub fn replayed_fri_layer_value<E, M>(
    variables: u8,
    log_inverse_rate: u8,
    fold_challenges: &[Fp16],
    fold_round: usize,
    layer_index: usize,
    evaluation_at: E,
    mask_coefficient_at: M,
) -> Result<Fp16, StreamingMlpcsError>
where
    E: Fn(usize) -> Fp16,
    M: Fn(usize) -> Fp16,
{
    let variables = usize::from(variables);
    let hidden_log_size = variables.checked_add(1).ok_or(StreamingMlpcsError::Shape)?;
    if variables >= usize::BITS as usize
        || fold_round > hidden_log_size
        || fold_challenges.len() < fold_round
    {
        return Err(StreamingMlpcsError::Shape);
    }
    let lde_log_size = hidden_log_size
        .checked_add(usize::from(log_inverse_rate))
        .ok_or(StreamingMlpcsError::Shape)?;
    let layer_log_size = lde_log_size
        .checked_sub(fold_round)
        .ok_or(StreamingMlpcsError::Shape)?;
    if layer_log_size == 0
        || layer_log_size > u8::MAX as usize
        || layer_index >= (1_usize << layer_log_size)
    {
        return Err(StreamingMlpcsError::Shape);
    }

    let x = pow_usize(derive_two_adic_root(layer_log_size as u8)?, layer_index);
    let mut point = Vec::with_capacity(variables);
    point.extend_from_slice(&fold_challenges[..fold_round.min(variables)]);
    for coordinate in fold_round..variables {
        point.push(pow_usize(x, 1_usize << (coordinate - fold_round)));
    }

    let data = replayed_multilinear_evaluation(variables as u8, &point, &evaluation_at)?;
    let mask = replayed_monomial_evaluation(variables as u8, &point, &mask_coefficient_at)?;
    let mask_multiplier = if fold_round <= variables {
        pow_usize(x, 1_usize << (variables - fold_round))
    } else {
        fold_challenges[variables]
    };
    Ok(data + mask_multiplier * mask)
}

/// Exact retained-state formula for the replay engine itself.
///
/// This excludes caller-owned packed source bytes and the proof being emitted.
/// It includes one Fp16 point, a logarithmic SHA3-512 Merkle stack, and the two
/// 64-byte secret/session values needed to replay the existing mask stream.
pub const fn replay_engine_retained_bytes(variables: usize, lde_log_size: usize) -> usize {
    variables * 64 + (lde_log_size + 1) * 64 + 2 * 64
}

/// Exact number of source-term visits made by the current scalar replay when
/// every value in one FRI layer is generated.
///
/// Each output scans all `2^variables` data evaluations and all
/// `2^variables` mask coefficients. Processing outputs in bounded tiles
/// changes retained memory but does not change this count.
pub const fn replayed_layer_source_term_visits(
    variables: u8,
    log_inverse_rate: u8,
    fold_round: u8,
) -> Option<u128> {
    let hidden_log_size = variables as u32 + 1;
    if fold_round as u32 > hidden_log_size {
        return None;
    }
    let layer_log_size = hidden_log_size + log_inverse_rate as u32 - fold_round as u32;
    let exponent = variables as u32 + layer_log_size + 1;
    if exponent >= u128::BITS {
        None
    } else {
        Some(1_u128 << exponent)
    }
}

/// Recompute one degree-two product-sumcheck message from replayable
/// multilinear evaluations.
///
/// `accepted_challenges` fixes the already completed least-significant
/// variables. The remaining suffix is visited in canonical Boolean order. The
/// returned coefficients use the existing `c0 + t*c1 + t^2*c2` grammar.
pub fn replayed_product_round_coefficients<L, R>(
    variables: u8,
    accepted_challenges: &[Fp16],
    left_at: L,
    right_at: R,
) -> Result<[Fp16; 3], StreamingMlpcsError>
where
    L: Fn(&[Fp16]) -> Result<Fp16, StreamingMlpcsError>,
    R: Fn(&[Fp16]) -> Result<Fp16, StreamingMlpcsError>,
{
    let variables = usize::from(variables);
    let round = accepted_challenges.len();
    if variables == 0 || variables >= usize::BITS as usize || round >= variables {
        return Err(StreamingMlpcsError::Shape);
    }
    let suffix_variables = variables - round - 1;
    let suffix_count = 1_usize << suffix_variables;
    let mut point = Vec::with_capacity(variables);
    point.extend_from_slice(accepted_challenges);
    point.resize(variables, Fp16::ZERO);
    let mut coefficients = [Fp16::ZERO; 3];
    for suffix in 0..suffix_count {
        for coordinate in 0..suffix_variables {
            point[round + 1 + coordinate] = if suffix & (1_usize << coordinate) == 0 {
                Fp16::ZERO
            } else {
                Fp16::ONE
            };
        }
        point[round] = Fp16::ZERO;
        let left_zero = left_at(&point)?;
        let right_zero = right_at(&point)?;
        point[round] = Fp16::ONE;
        let left_delta = left_at(&point)? - left_zero;
        let right_delta = right_at(&point)? - right_zero;
        coefficients[0] = coefficients[0] + left_zero * right_zero;
        coefficients[1] = coefficients[1] + left_zero * right_delta + left_delta * right_zero;
        coefficients[2] = coefficients[2] + left_delta * right_delta;
    }
    Ok(coefficients)
}

fn prefix_folded_value<E>(
    round: usize,
    base_index: usize,
    accepted_challenges: &[Fp16],
    evaluation_at: &E,
) -> Fp16
where
    E: Fn(usize) -> Fp16,
{
    if round == 0 {
        return evaluation_at(base_index);
    }
    let half = 1_usize << (round - 1);
    let left = prefix_folded_value(round - 1, base_index, accepted_challenges, evaluation_at);
    let right = prefix_folded_value(
        round - 1,
        base_index + half,
        accepted_challenges,
        evaluation_at,
    );
    left + accepted_challenges[round - 1] * (right - left)
}

/// Recompute one degree-two product-sumcheck message with one canonical
/// sequential traversal of each source table and logarithmic call state.
///
/// Unlike [`replayed_product_round_coefficients`], this does not evaluate a
/// complete multilinear extension separately for every suffix assignment.
/// It folds each contiguous prefix block directly, so a round performs
/// `2 * 2^variables` source reads (one complete pass for each input table).
pub fn streamed_product_round_coefficients<L, R>(
    variables: u8,
    accepted_challenges: &[Fp16],
    left_at: L,
    right_at: R,
) -> Result<[Fp16; 3], StreamingMlpcsError>
where
    L: Fn(usize) -> Fp16,
    R: Fn(usize) -> Fp16,
{
    let variables = usize::from(variables);
    let round = accepted_challenges.len();
    if variables == 0
        || variables >= usize::BITS as usize
        || round >= variables
        || round >= usize::BITS as usize
    {
        return Err(StreamingMlpcsError::Shape);
    }
    let half_size = 1_usize << round;
    let block_size = half_size << 1;
    let source_count = 1_usize << variables;
    let mut coefficients = [Fp16::ZERO; 3];
    for block_start in (0..source_count).step_by(block_size) {
        let left_zero = prefix_folded_value(round, block_start, accepted_challenges, &left_at);
        let left_one = prefix_folded_value(
            round,
            block_start + half_size,
            accepted_challenges,
            &left_at,
        );
        let right_zero = prefix_folded_value(round, block_start, accepted_challenges, &right_at);
        let right_one = prefix_folded_value(
            round,
            block_start + half_size,
            accepted_challenges,
            &right_at,
        );
        let left_delta = left_one - left_zero;
        let right_delta = right_one - right_zero;
        coefficients[0] = coefficients[0] + left_zero * right_zero;
        coefficients[1] = coefficients[1] + left_zero * right_delta + left_delta * right_zero;
        coefficients[2] = coefficients[2] + left_delta * right_delta;
    }
    Ok(coefficients)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        field::M31,
        multilinear_batch_sumcheck::{fold_table, product_round_coefficients},
        multilinear_pcs::{
            evaluate_univariate_lde, fold_multiplicative_fri_layer,
            interpolate_packed_boolean_hypercube,
        },
        multilinear_pcs_query::{
            MLPCS_VALUES_PER_LEAF, build_recomputed_layer_opening, verify_layer_opening,
        },
    };

    fn fp(value: u32) -> Fp16 {
        Fp16::from_m31(M31::from_canonical(value).unwrap())
    }

    fn fixture() -> (Vec<Fp16>, Vec<Fp16>, Vec<Fp16>) {
        let packed = [0b1011_0010_u8, 0b0110_1101_u8];
        let evaluations = (0..16)
            .map(|index| fp(u32::from((packed[index / 8] >> (index % 8)) & 1)))
            .collect::<Vec<_>>();
        let coefficients = interpolate_packed_boolean_hypercube(&packed, 16).unwrap();
        let masks = (0..16)
            .map(|index| fp(index as u32 + 17))
            .collect::<Vec<_>>();
        let hidden = coefficients
            .iter()
            .copied()
            .chain(masks.iter().copied())
            .collect::<Vec<_>>();
        (evaluations, masks, hidden)
    }

    fn toy_linear_code_values(
        message: &[Fp16],
        value_count: usize,
    ) -> impl Iterator<Item = Fp16> + '_ {
        let mut accumulator = Fp16::ZERO;
        (0..value_count).map(move |index| {
            let left = message[index % message.len()];
            let right = message[(5 * index + 1) % message.len()];
            let third = message[(11 * index + 3) % message.len()];
            accumulator = accumulator + left + right + third;
            accumulator
        })
    }

    fn toy_linear_code_leaf_payloads(
        message: &[Fp16],
        value_count: usize,
    ) -> impl Iterator<Item = Vec<u8>> + '_ {
        let mut values = toy_linear_code_values(message, value_count);
        (0..value_count / MLPCS_VALUES_PER_LEAF).map(move |_| {
            let mut payload =
                Vec::with_capacity(MLPCS_VALUES_PER_LEAF * crate::field::FP16_ENCODED_LENGTH);
            for _ in 0..MLPCS_VALUES_PER_LEAF {
                payload.extend_from_slice(&values.next().unwrap().encode());
            }
            payload
        })
    }

    #[test]
    fn replayed_values_match_every_dense_fri_layer_exactly() {
        let (evaluations, masks, hidden) = fixture();
        let challenges = [fp(29), fp(31), fp(37), fp(41), fp(43)];
        let mut dense = evaluate_univariate_lde(&hidden, 1).unwrap();

        for round in 0..=5 {
            for (index, expected) in dense.iter().copied().enumerate() {
                assert_eq!(
                    replayed_fri_layer_value(
                        4,
                        1,
                        &challenges,
                        round,
                        index,
                        |index| evaluations[index],
                        |index| masks[index],
                    )
                    .unwrap(),
                    expected,
                    "round={round} index={index}",
                );
            }
            if round != 5 {
                let root = derive_two_adic_root(dense.len().ilog2() as u8).unwrap();
                dense = fold_multiplicative_fri_layer(&dense, root, challenges[round]).unwrap();
            }
        }
    }

    #[test]
    fn replayed_layer_has_identical_root_frontier_openings_and_rejection() {
        let (evaluations, masks, hidden) = fixture();
        let challenges = [fp(29), fp(31), fp(37), fp(41), fp(43)];
        let dense_initial = evaluate_univariate_lde(&hidden, 1).unwrap();
        let root = derive_two_adic_root(dense_initial.len().ilog2() as u8).unwrap();
        let dense = fold_multiplicative_fri_layer(&dense_initial, root, challenges[0]).unwrap();
        let selected = [0_usize, 17, 31];

        let dense_payloads = dense
            .chunks_exact(MLPCS_VALUES_PER_LEAF)
            .map(|values| {
                values
                    .iter()
                    .flat_map(|value| value.encode())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let (dense_root, dense_opening) =
            build_recomputed_layer_opening(dense.len(), &dense_payloads, &selected).unwrap();

        let replayed_payloads = (0..dense.len() / MLPCS_VALUES_PER_LEAF).map(|leaf| {
            (0..MLPCS_VALUES_PER_LEAF)
                .flat_map(|offset| {
                    replayed_fri_layer_value(
                        4,
                        1,
                        &challenges,
                        1,
                        leaf * MLPCS_VALUES_PER_LEAF + offset,
                        |index| evaluations[index],
                        |index| masks[index],
                    )
                    .unwrap()
                    .encode()
                })
                .collect::<Vec<_>>()
        });
        let (replayed_root, replayed_opening) =
            build_recomputed_layer_opening(dense.len(), replayed_payloads, &selected).unwrap();

        assert_eq!(replayed_root, dense_root);
        assert_eq!(replayed_opening.leaves, dense_opening.leaves);
        assert_eq!(
            replayed_opening.multiproof.frontier_bytes(),
            dense_opening.multiproof.frontier_bytes()
        );
        verify_layer_opening(&replayed_opening, &dense_root, dense.len(), &selected).unwrap();

        let mut forged = replayed_opening;
        forged.leaves[0].values[0] = forged.leaves[0].values[0] + Fp16::ONE;
        assert!(verify_layer_opening(&forged, &dense_root, dense.len(), &selected).is_err());
    }

    #[test]
    fn replay_engine_state_is_kilobytes_at_projected_full_widths() {
        assert_eq!(replay_engine_retained_bytes(28, 32), 4_032);
        assert_eq!(replay_engine_retained_bytes(30, 34), 4_288);
        assert!(replay_engine_retained_bytes(30, 34) < 5_000);
        assert_eq!(MLPCS_VALUES_PER_LEAF, 16);
    }

    #[test]
    fn tiling_does_not_cure_scalar_replay_work_at_full_scale() {
        // K128: 2^28 source values, 2^32 initial LDE values, and two
        // complete source scans (data and mask) per output.
        assert_eq!(
            replayed_layer_source_term_visits(28, 3, 0),
            Some(1_u128 << 61)
        );
        // K512: 2^30 source values, 2^34 initial LDE values, with the
        // same two scans per output.
        assert_eq!(
            replayed_layer_source_term_visits(30, 3, 0),
            Some(1_u128 << 65)
        );
        // Tiling can only change the output buffer. The source-term count
        // is a function of protocol geometry, not tile width.
        for _tile_values in [1_usize, 16, 1_024, 1 << 20] {
            assert_eq!(
                replayed_layer_source_term_visits(28, 3, 0),
                Some(2_305_843_009_213_693_952)
            );
        }
        assert_eq!(replayed_layer_source_term_visits(4, 1, 6), None);
    }

    #[test]
    fn two_pass_linear_encoder_replay_matches_dense_commitment_and_openings() {
        // This is an engineering-mechanics KAT, not a selected code or a
        // distance/soundness claim. It exercises the intended bounded-memory
        // shape: publish the root in one pass, then replay the identical
        // deterministic encoder once after queries are known.
        let message = (0..64)
            .map(|index| fp((37 * index + 19) % 101))
            .collect::<Vec<_>>();
        let value_count = 1_024;
        let selected = [0_usize, 17, 255, 511, 777, 1_023];

        let (published_root, _) = build_recomputed_layer_opening(
            value_count,
            toy_linear_code_leaf_payloads(&message, value_count),
            &[0],
        )
        .unwrap();
        let (replayed_root, opening) = build_recomputed_layer_opening(
            value_count,
            toy_linear_code_leaf_payloads(&message, value_count),
            &selected,
        )
        .unwrap();
        assert_eq!(replayed_root, published_root);
        verify_layer_opening(&opening, &published_root, value_count, &selected).unwrap();

        let dense = toy_linear_code_values(&message, value_count).collect::<Vec<_>>();
        let dense_payloads = dense
            .chunks_exact(MLPCS_VALUES_PER_LEAF)
            .map(|values| {
                values
                    .iter()
                    .flat_map(|value| value.encode())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let (dense_root, dense_opening) =
            build_recomputed_layer_opening(value_count, dense_payloads, &selected).unwrap();
        assert_eq!(dense_root, published_root);
        assert_eq!(dense_opening.leaves, opening.leaves);
        assert_eq!(
            dense_opening.multiproof.frontier_bytes(),
            opening.multiproof.frontier_bytes()
        );
    }

    #[test]
    fn base_generator_is_linear_under_general_fp16_challenges() {
        // The toy encoder uses only additions and base-field unit
        // coefficients. This KAT checks the scalar-extension identity that a
        // real M31-row encoder must preserve before it can interact with
        // general Fp16 verifier challenges.
        let left = (0..64)
            .map(|index| fp((13 * index + 7) % 97))
            .collect::<Vec<_>>();
        let right = (0..64)
            .map(|index| fp((29 * index + 11) % 103))
            .collect::<Vec<_>>();
        let alpha =
            Fp16::from_coefficients([2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53])
                .unwrap();
        let beta = Fp16::from_coefficients([
            59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131,
        ])
        .unwrap();
        let combined = left
            .iter()
            .copied()
            .zip(right.iter().copied())
            .map(|(left, right)| alpha * left + beta * right)
            .collect::<Vec<_>>();

        let encoded_combined = toy_linear_code_values(&combined, 1_024).collect::<Vec<_>>();
        let encoded_left = toy_linear_code_values(&left, 1_024);
        let encoded_right = toy_linear_code_values(&right, 1_024);
        for ((actual, left), right) in encoded_combined
            .into_iter()
            .zip(encoded_left)
            .zip(encoded_right)
        {
            assert_eq!(actual, alpha * left + beta * right);
        }
    }

    #[test]
    fn replayed_product_sumcheck_messages_match_dense_folds_exactly() {
        let variables = 5_u8;
        let left = (0..1_usize << variables)
            .map(|index| fp((13 * index as u32 + 7) % 97))
            .collect::<Vec<_>>();
        let right = (0..1_usize << variables)
            .map(|index| fp((19 * index as u32 + 11) % 101))
            .collect::<Vec<_>>();
        let challenges = [fp(3), fp(5), fp(7), fp(11), fp(13)];
        let mut dense_left = left.clone();
        let mut dense_right = right.clone();

        for round in 0..usize::from(variables) {
            let expected = product_round_coefficients(&dense_left, &dense_right).unwrap();
            let actual = replayed_product_round_coefficients(
                variables,
                &challenges[..round],
                |point| replayed_multilinear_evaluation(variables, point, |index| left[index]),
                |point| replayed_multilinear_evaluation(variables, point, |index| right[index]),
            )
            .unwrap();
            assert_eq!(actual, expected, "round={round}");
            fold_table(&mut dense_left, challenges[round]);
            fold_table(&mut dense_right, challenges[round]);
        }
        assert_eq!(
            dense_left[0],
            replayed_multilinear_evaluation(variables, &challenges, |index| left[index]).unwrap()
        );
        assert_eq!(
            dense_right[0],
            replayed_multilinear_evaluation(variables, &challenges, |index| right[index]).unwrap()
        );
    }

    #[test]
    fn streamed_product_sumcheck_messages_match_dense_with_exact_read_count() {
        use core::cell::Cell;

        let variables = 10_u8;
        let source_count = 1_usize << variables;
        let left = (0..source_count)
            .map(|index| fp((13 * index as u32 + 7) % 97))
            .collect::<Vec<_>>();
        let right = (0..source_count)
            .map(|index| fp((19 * index as u32 + 11) % 101))
            .collect::<Vec<_>>();
        let challenges = [
            fp(3),
            fp(5),
            fp(7),
            fp(11),
            fp(13),
            fp(17),
            fp(19),
            fp(23),
            fp(29),
            fp(31),
        ];
        let mut dense_left = left.clone();
        let mut dense_right = right.clone();

        for round in 0..usize::from(variables) {
            let expected = product_round_coefficients(&dense_left, &dense_right).unwrap();
            let left_reads = Cell::new(0_usize);
            let right_reads = Cell::new(0_usize);
            let actual = streamed_product_round_coefficients(
                variables,
                &challenges[..round],
                |index| {
                    left_reads.set(left_reads.get() + 1);
                    left[index]
                },
                |index| {
                    right_reads.set(right_reads.get() + 1);
                    right[index]
                },
            )
            .unwrap();
            assert_eq!(actual, expected, "round={round}");
            assert_eq!(left_reads.get(), source_count, "round={round}");
            assert_eq!(right_reads.get(), source_count, "round={round}");
            fold_table(&mut dense_left, challenges[round]);
            fold_table(&mut dense_right, challenges[round]);
        }
        assert_eq!(
            dense_left[0],
            replayed_multilinear_evaluation(variables, &challenges, |index| left[index]).unwrap()
        );
        assert_eq!(
            dense_right[0],
            replayed_multilinear_evaluation(variables, &challenges, |index| right[index]).unwrap()
        );
    }
}
