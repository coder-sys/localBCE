//! Circle-to-multilinear sparse-functional adapter.
//!
//! A selected Circle opening authenticates `sum_i lambda_z(i) * column[i]`.
//! The bridge GKR consumes the multilinear value of the same column at a
//! verifier point `r`.  This module connects the two without committing a
//! third copy of the column: a degree-two product sumcheck reduces the Circle
//! opening to `column_mle(r) * lambda_z_mle(r)`.  The latter factor is public
//! and is recomputed by interpolating the equality table at `r` in the exact
//! selected Circle basis and evaluating it at `z`.

use alloc::{vec, vec::Vec};

use crate::{
    binding_multilinear_pcs_v2::{
        BindingMultilinearPcsProofV2, BindingMultilinearPcsV2Error,
        VerifiedBindingMultilinearOpeningV2, binding_multilinear_root_v2,
        decode_binding_multilinear_pcs_proof_v2,
        encode_binding_multilinear_pcs_proof_v2, prove_binding_multilinear_opening_v2,
        verify_binding_multilinear_opening_v2,
    },
    binding_root_v2::{BindingDigestV2, BindingRoleV2, BindingRootV2},
    circle_fft::{
        bit_reverse_permute, circle_twiddles, evaluate_extension_coefficients_at_point,
        interpolate_extension_circle_evaluations, line_twiddle_layers,
    },
    circle_fri::canonic_circle_point,
    field::{Fp16, M31},
    oods::CirclePoint,
};

/// Commit a logical Circle-coset column before an OODS point exists.  The
/// basis conversion and first PCS layer are byte-identical to the later
/// functional prover, so a post-Z proof cannot substitute another column.
pub fn circle_coefficient_root_v3(
    mut logical_coset_rows: Vec<Fp16>,
    coefficient_context: BindingDigestV2,
) -> Result<BindingRootV2, CircleLagrangeSparseFunctionalError> {
    if logical_coset_rows.len() < 8 || !logical_coset_rows.len().is_power_of_two() {
        return Err(CircleLagrangeSparseFunctionalError::Shape);
    }
    coset_to_circle_in_place(&mut logical_coset_rows);
    bit_reverse_permute(&mut logical_coset_rows)
        .map_err(|_| CircleLagrangeSparseFunctionalError::Circle)?;
    let coefficients = interpolate_extension_circle_evaluations(&logical_coset_rows)
        .map_err(|_| CircleLagrangeSparseFunctionalError::Circle)?;
    binding_multilinear_root_v2(&coefficients, coefficient_context).map_err(Into::into)
}

pub const CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_MAGIC: &[u8; 8] = b"BLCLSF01";
pub const CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_VERSION: u16 = 1;
pub const CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_MAX_LOG_SIZE: u8 = 25;
pub const CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_HEADER_BYTES: usize = 16;
pub const CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_ROUND_BYTES: usize = 3 * 64;
pub const CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_MAX_BYTES: usize =
    CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_HEADER_BYTES
        + CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_MAX_LOG_SIZE as usize
            * CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_ROUND_BYTES;
pub const CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_V2_MAGIC: &[u8; 8] = b"BLCLSF02";
pub const CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_V2_VERSION: u16 = 2;
pub const CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_V2_HEADER_BYTES: usize = 16 + 64;
pub const CIRCLE_COEFFICIENT_MLE_V3_MAGIC: &[u8; 8] = b"BLCLSF03";
pub const CIRCLE_COEFFICIENT_MLE_V3_VERSION: u16 = 3;
pub const CIRCLE_COEFFICIENT_MLE_V3_HEADER_BYTES: usize = 16 + 64;
pub const CIRCLE_COEFFICIENT_MLE_V3_MAX_BYTES: usize = CIRCLE_COEFFICIENT_MLE_V3_HEADER_BYTES
    + CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_MAX_LOG_SIZE as usize
        * CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_ROUND_BYTES
    + 8
    + 2 * crate::binding_multilinear_pcs_v2::BINDING_MLPCS_V2_MAX_PROOF_BYTES;
const CIRCLE_COEFFICIENT_ROW_MLE_FUNCTIONAL_DOMAIN: &[u8] =
    b"BL/PQ512/WAVE2/CIRCLE-COEFFICIENT-ROW-MLE-FUNCTIONAL/v3\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircleLagrangeSparseFunctionalProof {
    /// Degree-two round polynomials, low coefficient first.
    pub rounds: Vec<[Fp16; 3]>,
}

/// Canonical accepting grammar. The claimed multilinear terminal is part of
/// the proof bytes and is checked by the product sumcheck; it is not supplied
/// as a caller-shaped authority object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircleLagrangeSparseFunctionalProofV2 {
    pub multilinear_value: Fp16,
    pub rounds: Vec<[Fp16; 3]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircleLagrangeSparseFunctionalError {
    Shape,
    Point,
    Algebra,
    Encoding,
    Circle,
    CoefficientPcs,
}

impl From<BindingMultilinearPcsV2Error> for CircleLagrangeSparseFunctionalError {
    fn from(_: BindingMultilinearPcsV2Error) -> Self {
        Self::CoefficientPcs
    }
}

/// Opaque Circle opening supplied only by the selected native verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedCircleOpening {
    value: Fp16,
    point: CirclePoint,
    log_size: u8,
}

/// Opaque multilinear terminal supplied only by the bridge-GKR source binder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedMultilinearTerminal {
    point: Vec<Fp16>,
    value: Fp16,
}

/// Select one OODS cell only from a completed native-128 FRI receipt.  The
/// claim/value ordinals are verifier-fixed bridge-layout indices; no caller
/// supplies the value or Circle point independently.
pub(crate) fn authenticated_circle_opening_from_verified_fri_v3(
    verified: &crate::fri_pipeline::VerifiedFriPipelineV3,
    claim_ordinal: usize,
    value_ordinal: usize,
    conjugate: bool,
) -> Result<AuthenticatedCircleOpening, CircleLagrangeSparseFunctionalError> {
    let claim = verified
        .claims()
        .get(claim_ordinal)
        .ok_or(CircleLagrangeSparseFunctionalError::Shape)?;
    let values = if conjugate {
        &claim.conjugate_values
    } else {
        &claim.values
    };
    let value = *values
        .get(value_ordinal)
        .ok_or(CircleLagrangeSparseFunctionalError::Shape)?;
    let point = if conjugate {
        let point = verified.query_point();
        CirclePoint {
            x: point.x.conjugate(),
            y: point.y.conjugate(),
        }
    } else {
        verified.query_point()
    };
    Ok(AuthenticatedCircleOpening {
        value,
        point,
        log_size: claim.log_size,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCircleLagrangeSparseFunctional {
    pub circle_value: Fp16,
    pub multilinear_value: Fp16,
    pub public_lagrange_mle: Fp16,
    pub multilinear_point: Vec<Fp16>,
}

/// Native-128 coefficient-anchored Circle-to-MLE proof.  The same first
/// coefficient root is used twice: once to prove equality with the selected
/// Circle OODS opening and once to authenticate the terminal of the linear
/// functional sumcheck.  This is the commitment-backed terminal missing from
/// the legacy BLCLSF01/02 algebra-only adapters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircleCoefficientMleProofV3 {
    pub row_multilinear_value: Fp16,
    pub functional_rounds: Vec<[Fp16; 3]>,
    pub circle_evaluation_opening: BindingMultilinearPcsProofV2,
    pub functional_terminal_opening: BindingMultilinearPcsProofV2,
}

/// Opaque result of the complete coefficient-anchored basis conversion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedCircleCoefficientMleV3 {
    coefficient_root: BindingRootV2,
    circle_opening: VerifiedBindingMultilinearOpeningV2,
    terminal_opening: VerifiedBindingMultilinearOpeningV2,
    multilinear_point: Vec<Fp16>,
    multilinear_value: Fp16,
    functional_binding: BindingDigestV2,
}

impl VerifiedCircleCoefficientMleV3 {
    pub(crate) const fn coefficient_root(&self) -> BindingRootV2 {
        self.coefficient_root
    }

    pub(crate) fn multilinear_point(&self) -> &[Fp16] {
        &self.multilinear_point
    }

    pub(crate) const fn multilinear_value(&self) -> Fp16 {
        self.multilinear_value
    }

    pub(crate) const fn functional_binding(&self) -> BindingDigestV2 {
        self.functional_binding
    }

    #[cfg(test)]
    pub(crate) fn synthetic_for_test(
        coefficient_root: BindingRootV2,
        multilinear_point: Vec<Fp16>,
        multilinear_value: Fp16,
    ) -> Self {
        let synthetic = VerifiedBindingMultilinearOpeningV2::synthetic_for_test(
            coefficient_root,
            multilinear_point.clone(),
            multilinear_value,
        );
        Self {
            coefficient_root,
            circle_opening: synthetic.clone(),
            terminal_opening: synthetic,
            multilinear_point,
            multilinear_value,
            functional_binding: BindingDigestV2::hash(
                BindingRoleV2::Payload,
                b"synthetic-circle-coefficient-functional",
            )
            .unwrap(),
        }
    }
}

fn row_mle_functional_binding(
    point: &[Fp16],
) -> Result<BindingDigestV2, CircleLagrangeSparseFunctionalError> {
    let mut encoded = CIRCLE_COEFFICIENT_ROW_MLE_FUNCTIONAL_DOMAIN.to_vec();
    encoded
        .push(u8::try_from(point.len()).map_err(|_| CircleLagrangeSparseFunctionalError::Shape)?);
    for coordinate in point {
        encoded.extend_from_slice(&coordinate.encode());
    }
    BindingDigestV2::hash(BindingRoleV2::Payload, &encoded)
        .map_err(|_| CircleLagrangeSparseFunctionalError::Encoding)
}

fn equality_table(point: &[Fp16]) -> Result<Vec<Fp16>, CircleLagrangeSparseFunctionalError> {
    if point.is_empty() || point.len() > usize::from(CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_MAX_LOG_SIZE)
    {
        return Err(CircleLagrangeSparseFunctionalError::Shape);
    }
    let size = 1usize
        .checked_shl(point.len() as u32)
        .ok_or(CircleLagrangeSparseFunctionalError::Shape)?;
    let mut values = vec![Fp16::ONE; size];
    let mut active = 1usize;
    for challenge in point {
        for index in (0..active).rev() {
            let value = values[index];
            values[index] = value * (Fp16::ONE - *challenge);
            values[active + index] = value * *challenge;
        }
        active *= 2;
    }
    Ok(values)
}

/// Apply the exact coset-row to Circle-domain permutation without allocating
/// a second field vector.  `mapping(source)` is the destination of `source`.
fn coset_to_circle_in_place(values: &mut [Fp16]) {
    let size = values.len();
    let half = size / 2;
    let destination = |source: usize| {
        if source & 1 == 0 {
            source >> 1
        } else {
            half + ((size - 1 - source) >> 1)
        }
    };
    let mut visited = vec![false; size];
    for start in 0..size {
        if visited[start] {
            continue;
        }
        let mut current = start;
        let mut carried = values[current];
        loop {
            visited[current] = true;
            let next = destination(current);
            core::mem::swap(&mut carried, &mut values[next]);
            current = next;
            if current == start {
                break;
            }
        }
    }
}

fn circle_to_coset_functional_in_place(values: &mut [Fp16]) {
    let size = values.len();
    let half = size / 2;
    let destination = |circle: usize| {
        if circle < half {
            circle << 1
        } else {
            size - 1 - ((circle - half) << 1)
        }
    };
    let mut visited = vec![false; size];
    for start in 0..size {
        if visited[start] {
            continue;
        }
        let mut current = start;
        let mut carried = values[current];
        loop {
            visited[current] = true;
            let next = destination(current);
            core::mem::swap(&mut carried, &mut values[next]);
            current = next;
            if current == start {
                break;
            }
        }
    }
}

fn transpose_inverse_layer(values: &mut [Fp16], layer: usize, twiddles: &[M31]) {
    for (block, twiddle) in twiddles.iter().copied().enumerate() {
        let twiddle = Fp16::from_m31(twiddle);
        for offset in 0..(1usize << layer) {
            let left_index = (block << (layer + 1)) + offset;
            let right_index = left_index + (1usize << layer);
            let left = values[left_index];
            let right = values[right_index];
            values[left_index] = left + twiddle * right;
            values[right_index] = left - twiddle * right;
        }
    }
}

/// Transpose one forward Circle-FFT butterfly layer.  The forward butterfly
/// is `(l,r) -> (l+t*r,l-t*r)`, hence its transpose is
/// `(l,r) -> (l+r,t*(l-r))`.
fn transpose_forward_layer(values: &mut [Fp16], layer: usize, twiddles: &[M31]) {
    for (block, twiddle) in twiddles.iter().copied().enumerate() {
        let twiddle = Fp16::from_m31(twiddle);
        for offset in 0..(1usize << layer) {
            let left_index = (block << (layer + 1)) + offset;
            let right_index = left_index + (1usize << layer);
            let left = values[left_index];
            let right = values[right_index];
            values[left_index] = left + right;
            values[right_index] = twiddle * (left - right);
        }
    }
}

/// Return the tensor-basis coefficient weights whose inner product with the
/// exact bit-reversed Circle coefficients equals the ordinary multilinear
/// evaluation of the logical coset-order rows at `multilinear_point`.
fn circle_row_functional_coefficient_weights(
    mut weights: Vec<Fp16>,
) -> Result<Vec<Fp16>, CircleLagrangeSparseFunctionalError> {
    if weights.len() < 8
        || !weights.len().is_power_of_two()
        || weights.len().trailing_zeros()
            > u32::from(CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_MAX_LOG_SIZE)
    {
        return Err(CircleLagrangeSparseFunctionalError::Point);
    }
    // If T maps logical rows to Circle coefficients, the desired coefficient
    // functional is T^{-T}*eq(r).  T^{-1} is the forward Circle FFT followed
    // by the inverse row-order permutations, so apply those operations in
    // transposed reverse order here.
    coset_to_circle_in_place(&mut weights);
    bit_reverse_permute(&mut weights).map_err(|_| CircleLagrangeSparseFunctionalError::Circle)?;
    let log_size = weights.len().trailing_zeros() as u8;
    let line_layers = line_twiddle_layers(log_size, false)
        .map_err(|_| CircleLagrangeSparseFunctionalError::Circle)?;
    let circle_layer = circle_twiddles(&line_layers[0])
        .map_err(|_| CircleLagrangeSparseFunctionalError::Circle)?;
    transpose_forward_layer(&mut weights, 0, &circle_layer);
    for (layer, twiddles) in line_layers.iter().enumerate() {
        transpose_forward_layer(&mut weights, layer + 1, twiddles);
    }
    Ok(weights)
}

fn circle_row_mle_coefficient_weights(
    multilinear_point: &[Fp16],
) -> Result<Vec<Fp16>, CircleLagrangeSparseFunctionalError> {
    circle_row_functional_coefficient_weights(equality_table(multilinear_point)?)
}

fn circle_coefficient_fold_coordinates(
    log_size: u8,
    point: CirclePoint,
) -> Result<Vec<Fp16>, CircleLagrangeSparseFunctionalError> {
    if !(3..=CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_MAX_LOG_SIZE).contains(&log_size)
        || point.x.square() + point.y.square() != Fp16::ONE
    {
        return Err(CircleLagrangeSparseFunctionalError::Point);
    }
    let mut mappings = Vec::with_capacity(usize::from(log_size));
    mappings.push(point.y);
    let mut x = point.x;
    for _ in 1..log_size {
        mappings.push(x);
        x = x.square() + x.square() - Fp16::ONE;
    }
    mappings.reverse();
    Ok(mappings)
}

fn circle_coefficient_mle_coordinates(
    log_size: u8,
    point: CirclePoint,
) -> Result<(Vec<Fp16>, Fp16), CircleLagrangeSparseFunctionalError> {
    let mappings = circle_coefficient_fold_coordinates(log_size, point)?;
    let mut scale = Fp16::ONE;
    let mut coordinates = Vec::with_capacity(mappings.len());
    // The Circle evaluator folds high tensor bits first, whereas the ordinary
    // Boolean MLE convention folds adjacent pairs (low bits first).
    for mapping in mappings.into_iter().rev() {
        let factor = Fp16::ONE + mapping;
        if factor.is_zero() {
            return Err(CircleLagrangeSparseFunctionalError::Point);
        }
        scale = scale * factor;
        coordinates.push(
            mapping
                * factor
                    .inverse()
                    .map_err(|_| CircleLagrangeSparseFunctionalError::Point)?,
        );
    }
    Ok((coordinates, scale))
}

fn logical_coset_row_circle_index(log_size: u8, row: usize) -> usize {
    let size = 1usize << log_size;
    if row & 1 == 0 {
        row >> 1
    } else {
        (size >> 1) + ((size - 1 - row) >> 1)
    }
}

/// Evaluate `<T^{-T}w,eq(s)>` without materializing either dense vector.
/// `T` is the exact logical-coset-row to bit-reversed Circle-coefficient
/// transform used by this module.  This is the verifier-side terminal needed
/// by sparse semantic gather maps; peak storage is O(log n).
pub(crate) fn circle_row_functional_dual_terminal_streaming<F>(
    log_size: u8,
    functional_challenges: &[Fp16],
    mut row_weight: F,
) -> Result<Fp16, CircleLagrangeSparseFunctionalError>
where
    F: FnMut(usize) -> Result<Fp16, CircleLagrangeSparseFunctionalError>,
{
    if usize::from(log_size) != functional_challenges.len()
        || !(3..=CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_MAX_LOG_SIZE).contains(&log_size)
    {
        return Err(CircleLagrangeSparseFunctionalError::Shape);
    }
    let rows = 1usize << log_size;
    let mut result = Fp16::ZERO;
    for row in 0..rows {
        let weight = row_weight(row)?;
        if weight.is_zero() {
            continue;
        }
        let point = canonic_circle_point(log_size, logical_coset_row_circle_index(log_size, row))
            .map_err(|_| CircleLagrangeSparseFunctionalError::Circle)?;
        let point = CirclePoint {
            x: Fp16::from_m31(point.x),
            y: Fp16::from_m31(point.y),
        };
        let (coordinates, scale) = circle_coefficient_mle_coordinates(log_size, point)?;
        let equality = functional_challenges.iter().zip(&coordinates).fold(
            Fp16::ONE,
            |product, (left, right)| {
                product * ((Fp16::ONE - *left) * (Fp16::ONE - *right) + *left * *right)
            },
        );
        result = result + weight * scale * equality;
    }
    Ok(result)
}

fn fold_boolean_low_first(values: &mut [Fp16], active: usize, challenge: Fp16) {
    for index in 0..active / 2 {
        let left = values[2 * index];
        values[index] = left + challenge * (values[2 * index + 1] - left);
    }
}

fn evaluate_boolean_multilinear(
    mut values: Vec<Fp16>,
    point: &[Fp16],
) -> Result<Fp16, CircleLagrangeSparseFunctionalError> {
    if values.len() != 1usize << point.len() || point.is_empty() {
        return Err(CircleLagrangeSparseFunctionalError::Shape);
    }
    let mut active = values.len();
    for challenge in point {
        fold_boolean_low_first(&mut values, active, *challenge);
        active /= 2;
    }
    Ok(values[0])
}

fn prove_inner_product_low_first(
    mut left: Vec<Fp16>,
    mut right: Vec<Fp16>,
    challenges: &[Fp16],
) -> Result<(Vec<[Fp16; 3]>, Fp16), CircleLagrangeSparseFunctionalError> {
    if left.len() != right.len() || left.len() != 1usize << challenges.len() || challenges.len() < 3
    {
        return Err(CircleLagrangeSparseFunctionalError::Shape);
    }
    let mut active = left.len();
    let mut rounds = Vec::with_capacity(challenges.len());
    for challenge in challenges {
        let mut round = [Fp16::ZERO; 3];
        for index in 0..active / 2 {
            let l0 = left[2 * index];
            let ld = left[2 * index + 1] - l0;
            let r0 = right[2 * index];
            let rd = right[2 * index + 1] - r0;
            round[0] = round[0] + l0 * r0;
            round[1] = round[1] + l0 * rd + ld * r0;
            round[2] = round[2] + ld * rd;
        }
        fold_boolean_low_first(&mut left, active, *challenge);
        fold_boolean_low_first(&mut right, active, *challenge);
        active /= 2;
        rounds.push(round);
    }
    Ok((rounds, left[0] * right[0]))
}

/// Exact O(n log n) transposed inverse-Circle-FFT construction of the public
/// Lagrange vector in logical coset-row order.
pub fn circle_lagrange_weights(
    log_size: u8,
    circle_point: CirclePoint,
) -> Result<Vec<Fp16>, CircleLagrangeSparseFunctionalError> {
    if !(3..=CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_MAX_LOG_SIZE).contains(&log_size)
        || circle_point.x.square() + circle_point.y.square() != Fp16::ONE
    {
        return Err(CircleLagrangeSparseFunctionalError::Point);
    }
    let mut mappings = Vec::with_capacity(usize::from(log_size));
    mappings.push(circle_point.y);
    let mut x = circle_point.x;
    for _ in 1..log_size {
        mappings.push(x);
        x = x.square() + x.square() - Fp16::ONE;
    }
    mappings.reverse();
    let mut weights = vec![Fp16::ONE];
    for mapping in mappings.iter().rev() {
        let previous = weights.len();
        weights.resize(2 * previous, Fp16::ZERO);
        for index in 0..previous {
            weights[previous + index] = weights[index] * *mapping;
        }
    }
    let inverse_size = Fp16::from_m31(
        M31::from_canonical(1u32 << log_size)
            .map_err(|_| CircleLagrangeSparseFunctionalError::Circle)?
            .inverse()
            .map_err(|_| CircleLagrangeSparseFunctionalError::Circle)?,
    );
    for weight in &mut weights {
        *weight = *weight * inverse_size;
    }
    let line_layers = line_twiddle_layers(log_size, true)
        .map_err(|_| CircleLagrangeSparseFunctionalError::Circle)?;
    let circle_layer = circle_twiddles(&line_layers[0])
        .map_err(|_| CircleLagrangeSparseFunctionalError::Circle)?;
    for (layer, twiddles) in line_layers.iter().enumerate().rev() {
        transpose_inverse_layer(&mut weights, layer + 1, twiddles);
    }
    transpose_inverse_layer(&mut weights, 0, &circle_layer);
    bit_reverse_permute(&mut weights).map_err(|_| CircleLagrangeSparseFunctionalError::Circle)?;
    circle_to_coset_functional_in_place(&mut weights);
    Ok(weights)
}

/// Recompute `MLE(lambda_z)(r)` in the exact selected row and Circle basis.
/// Peak storage is one `2^log_size` Fp16 vector plus a one-bit visited map.
pub fn circle_lagrange_mle_at_point(
    multilinear_point: &[Fp16],
    circle_point: CirclePoint,
) -> Result<Fp16, CircleLagrangeSparseFunctionalError> {
    if multilinear_point.len() < 3
        || multilinear_point.len() > usize::from(CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_MAX_LOG_SIZE)
        || circle_point.x.square() + circle_point.y.square() != Fp16::ONE
    {
        return Err(CircleLagrangeSparseFunctionalError::Point);
    }
    let mut evaluations = equality_table(multilinear_point)?;
    coset_to_circle_in_place(&mut evaluations);
    bit_reverse_permute(&mut evaluations)
        .map_err(|_| CircleLagrangeSparseFunctionalError::Circle)?;
    let coefficients = interpolate_extension_circle_evaluations(&evaluations)
        .map_err(|_| CircleLagrangeSparseFunctionalError::Circle)?;
    evaluate_extension_coefficients_at_point(&coefficients, circle_point)
        .map_err(|_| CircleLagrangeSparseFunctionalError::Circle)
}

fn evaluate_quadratic(coefficients: [Fp16; 3], point: Fp16) -> Fp16 {
    coefficients[0] + point * (coefficients[1] + point * coefficients[2])
}

pub fn encode_circle_lagrange_sparse_functional_proof(
    proof: &CircleLagrangeSparseFunctionalProof,
) -> Result<Vec<u8>, CircleLagrangeSparseFunctionalError> {
    if proof.rounds.len() < 3
        || proof.rounds.len() > usize::from(CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_MAX_LOG_SIZE)
    {
        return Err(CircleLagrangeSparseFunctionalError::Encoding);
    }
    let mut encoded = Vec::with_capacity(
        CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_HEADER_BYTES
            + proof.rounds.len() * CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_ROUND_BYTES,
    );
    encoded.extend_from_slice(CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_MAGIC);
    encoded.extend_from_slice(&CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_VERSION.to_be_bytes());
    encoded.push(proof.rounds.len() as u8);
    encoded.extend_from_slice(&[0_u8; 5]);
    for round in &proof.rounds {
        for coefficient in round {
            encoded.extend_from_slice(&coefficient.encode());
        }
    }
    Ok(encoded)
}

pub fn decode_circle_lagrange_sparse_functional_proof(
    encoded: &[u8],
) -> Result<CircleLagrangeSparseFunctionalProof, CircleLagrangeSparseFunctionalError> {
    if encoded.len() < CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_HEADER_BYTES
        || encoded.len() > CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_MAX_BYTES
        || encoded.get(..8) != Some(CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_MAGIC)
        || u16::from_be_bytes(
            encoded[8..10]
                .try_into()
                .map_err(|_| CircleLagrangeSparseFunctionalError::Encoding)?,
        ) != CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_VERSION
        || encoded[11..16] != [0_u8; 5]
    {
        return Err(CircleLagrangeSparseFunctionalError::Encoding);
    }
    let rounds = usize::from(encoded[10]);
    if !(3..=usize::from(CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_MAX_LOG_SIZE)).contains(&rounds)
        || encoded.len()
            != CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_HEADER_BYTES
                + rounds * CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_ROUND_BYTES
    {
        return Err(CircleLagrangeSparseFunctionalError::Encoding);
    }
    let mut offset = CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_HEADER_BYTES;
    let mut result = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let mut round = [Fp16::ZERO; 3];
        for coefficient in &mut round {
            *coefficient = Fp16::decode(&encoded[offset..offset + 64])
                .map_err(|_| CircleLagrangeSparseFunctionalError::Encoding)?;
            offset += 64;
        }
        result.push(round);
    }
    if offset != encoded.len() {
        return Err(CircleLagrangeSparseFunctionalError::Encoding);
    }
    Ok(CircleLagrangeSparseFunctionalProof { rounds: result })
}

pub fn encode_circle_lagrange_sparse_functional_proof_v2(
    proof: &CircleLagrangeSparseFunctionalProofV2,
) -> Result<Vec<u8>, CircleLagrangeSparseFunctionalError> {
    if proof.rounds.len() < 3
        || proof.rounds.len() > usize::from(CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_MAX_LOG_SIZE)
    {
        return Err(CircleLagrangeSparseFunctionalError::Encoding);
    }
    let mut encoded = Vec::with_capacity(
        CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_V2_HEADER_BYTES
            + proof.rounds.len() * CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_ROUND_BYTES,
    );
    encoded.extend_from_slice(CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_V2_MAGIC);
    encoded.extend_from_slice(&CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_V2_VERSION.to_be_bytes());
    encoded.push(proof.rounds.len() as u8);
    encoded.extend_from_slice(&[0_u8; 5]);
    encoded.extend_from_slice(&proof.multilinear_value.encode());
    for round in &proof.rounds {
        for coefficient in round {
            encoded.extend_from_slice(&coefficient.encode());
        }
    }
    Ok(encoded)
}

pub fn decode_circle_lagrange_sparse_functional_proof_v2(
    encoded: &[u8],
) -> Result<CircleLagrangeSparseFunctionalProofV2, CircleLagrangeSparseFunctionalError> {
    if encoded.len() < CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_V2_HEADER_BYTES
        || encoded.get(..8) != Some(CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_V2_MAGIC)
        || u16::from_be_bytes(
            encoded[8..10]
                .try_into()
                .map_err(|_| CircleLagrangeSparseFunctionalError::Encoding)?,
        ) != CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_V2_VERSION
        || encoded[11..16] != [0_u8; 5]
    {
        return Err(CircleLagrangeSparseFunctionalError::Encoding);
    }
    let rounds = usize::from(encoded[10]);
    if !(3..=usize::from(CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_MAX_LOG_SIZE)).contains(&rounds)
        || encoded.len()
            != CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_V2_HEADER_BYTES
                + rounds * CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_ROUND_BYTES
    {
        return Err(CircleLagrangeSparseFunctionalError::Encoding);
    }
    let multilinear_value = Fp16::decode(&encoded[16..80])
        .map_err(|_| CircleLagrangeSparseFunctionalError::Encoding)?;
    let mut offset = CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_V2_HEADER_BYTES;
    let mut result = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let mut round = [Fp16::ZERO; 3];
        for coefficient in &mut round {
            *coefficient = Fp16::decode(&encoded[offset..offset + 64])
                .map_err(|_| CircleLagrangeSparseFunctionalError::Encoding)?;
            offset += 64;
        }
        result.push(round);
    }
    Ok(CircleLagrangeSparseFunctionalProofV2 {
        multilinear_value,
        rounds: result,
    })
}

pub fn prove_circle_lagrange_sparse_functional(
    mut column_values: Vec<Fp16>,
    circle_point: CirclePoint,
    challenges: &[Fp16],
) -> Result<(CircleLagrangeSparseFunctionalProof, Fp16), CircleLagrangeSparseFunctionalError> {
    if column_values.len() != 1usize << challenges.len()
        || challenges.len() < 3
        || challenges.len() > usize::from(CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_MAX_LOG_SIZE)
    {
        return Err(CircleLagrangeSparseFunctionalError::Shape);
    }
    let mut circle_order = column_values.clone();
    coset_to_circle_in_place(&mut circle_order);
    bit_reverse_permute(&mut circle_order)
        .map_err(|_| CircleLagrangeSparseFunctionalError::Circle)?;
    let coefficients = interpolate_extension_circle_evaluations(&circle_order)
        .map_err(|_| CircleLagrangeSparseFunctionalError::Circle)?;
    let claimed = evaluate_extension_coefficients_at_point(&coefficients, circle_point)
        .map_err(|_| CircleLagrangeSparseFunctionalError::Circle)?;

    let size = column_values.len();
    let mut lagrange = circle_lagrange_weights(challenges.len() as u8, circle_point)?;

    let mut active = size;
    let mut rounds = Vec::with_capacity(challenges.len());
    for challenge in challenges {
        let mut round = [Fp16::ZERO; 3];
        for index in 0..active / 2 {
            let left_zero = column_values[2 * index];
            let left_delta = column_values[2 * index + 1] - left_zero;
            let right_zero = lagrange[2 * index];
            let right_delta = lagrange[2 * index + 1] - right_zero;
            round[0] = round[0] + left_zero * right_zero;
            round[1] = round[1] + left_zero * right_delta + left_delta * right_zero;
            round[2] = round[2] + left_delta * right_delta;
            column_values[index] = left_zero + *challenge * left_delta;
            lagrange[index] = right_zero + *challenge * right_delta;
        }
        active /= 2;
        rounds.push(round);
    }
    Ok((CircleLagrangeSparseFunctionalProof { rounds }, claimed))
}

pub fn prove_circle_lagrange_sparse_functional_v2(
    column_values: Vec<Fp16>,
    circle_point: CirclePoint,
    challenges: &[Fp16],
) -> Result<(CircleLagrangeSparseFunctionalProofV2, Fp16), CircleLagrangeSparseFunctionalError> {
    let mut folded = column_values.clone();
    let (proof, circle_value) =
        prove_circle_lagrange_sparse_functional(column_values, circle_point, challenges)?;
    let mut active = folded.len();
    for challenge in challenges {
        for index in 0..active / 2 {
            let left = folded[2 * index];
            folded[index] = left + *challenge * (folded[2 * index + 1] - left);
        }
        active /= 2;
    }
    Ok((
        CircleLagrangeSparseFunctionalProofV2 {
            multilinear_value: folded[0],
            rounds: proof.rounds,
        },
        circle_value,
    ))
}

pub(crate) fn verify_circle_lagrange_sparse_functional_v2(
    proof: &CircleLagrangeSparseFunctionalProofV2,
    circle: AuthenticatedCircleOpening,
    expected_multilinear_point: &[Fp16],
) -> Result<VerifiedCircleLagrangeSparseFunctional, CircleLagrangeSparseFunctionalError> {
    verify_circle_lagrange_sparse_functional(
        &CircleLagrangeSparseFunctionalProof {
            rounds: proof.rounds.clone(),
        },
        circle,
        AuthenticatedMultilinearTerminal {
            point: expected_multilinear_point.to_vec(),
            value: proof.multilinear_value,
        },
    )
}

pub(crate) fn verify_circle_lagrange_sparse_functional(
    proof: &CircleLagrangeSparseFunctionalProof,
    circle: AuthenticatedCircleOpening,
    terminal: AuthenticatedMultilinearTerminal,
) -> Result<VerifiedCircleLagrangeSparseFunctional, CircleLagrangeSparseFunctionalError> {
    if proof.rounds.len() != usize::from(circle.log_size)
        || terminal.point.len() != usize::from(circle.log_size)
        || proof.rounds.len() < 3
    {
        return Err(CircleLagrangeSparseFunctionalError::Shape);
    }
    let mut current = circle.value;
    for (round, challenge) in proof.rounds.iter().zip(&terminal.point) {
        if round[0] + round[0] + round[1] + round[2] != current {
            return Err(CircleLagrangeSparseFunctionalError::Algebra);
        }
        current = evaluate_quadratic(*round, *challenge);
    }
    let public_lagrange_mle = circle_lagrange_mle_at_point(&terminal.point, circle.point)?;
    if current != terminal.value * public_lagrange_mle {
        return Err(CircleLagrangeSparseFunctionalError::Algebra);
    }
    Ok(VerifiedCircleLagrangeSparseFunctional {
        circle_value: circle.value,
        multilinear_value: terminal.value,
        public_lagrange_mle,
        multilinear_point: terminal.point,
    })
}

pub fn encode_circle_coefficient_mle_proof_v3(
    proof: &CircleCoefficientMleProofV3,
) -> Result<Vec<u8>, CircleLagrangeSparseFunctionalError> {
    if proof.functional_rounds.len() < 3
        || proof.functional_rounds.len()
            > usize::from(CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_MAX_LOG_SIZE)
    {
        return Err(CircleLagrangeSparseFunctionalError::Encoding);
    }
    let circle = encode_binding_multilinear_pcs_proof_v2(&proof.circle_evaluation_opening)?;
    let terminal = encode_binding_multilinear_pcs_proof_v2(&proof.functional_terminal_opening)?;
    let mut out = Vec::with_capacity(
        CIRCLE_COEFFICIENT_MLE_V3_HEADER_BYTES
            + proof.functional_rounds.len() * CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_ROUND_BYTES
            + 8
            + circle.len()
            + terminal.len(),
    );
    out.extend_from_slice(CIRCLE_COEFFICIENT_MLE_V3_MAGIC);
    out.extend_from_slice(&CIRCLE_COEFFICIENT_MLE_V3_VERSION.to_be_bytes());
    out.push(proof.functional_rounds.len() as u8);
    out.extend_from_slice(&[0_u8; 5]);
    out.extend_from_slice(&proof.row_multilinear_value.encode());
    for round in &proof.functional_rounds {
        for coefficient in round {
            out.extend_from_slice(&coefficient.encode());
        }
    }
    out.extend_from_slice(
        &u32::try_from(circle.len())
            .map_err(|_| CircleLagrangeSparseFunctionalError::Encoding)?
            .to_be_bytes(),
    );
    out.extend_from_slice(&circle);
    out.extend_from_slice(
        &u32::try_from(terminal.len())
            .map_err(|_| CircleLagrangeSparseFunctionalError::Encoding)?
            .to_be_bytes(),
    );
    out.extend_from_slice(&terminal);
    if out.len() > CIRCLE_COEFFICIENT_MLE_V3_MAX_BYTES {
        return Err(CircleLagrangeSparseFunctionalError::Encoding);
    }
    Ok(out)
}

pub fn decode_circle_coefficient_mle_proof_v3(
    encoded: &[u8],
) -> Result<CircleCoefficientMleProofV3, CircleLagrangeSparseFunctionalError> {
    if encoded.len() < CIRCLE_COEFFICIENT_MLE_V3_HEADER_BYTES + 8
        || encoded.len() > CIRCLE_COEFFICIENT_MLE_V3_MAX_BYTES
        || encoded.get(..8) != Some(CIRCLE_COEFFICIENT_MLE_V3_MAGIC)
        || u16::from_be_bytes(
            encoded[8..10]
                .try_into()
                .map_err(|_| CircleLagrangeSparseFunctionalError::Encoding)?,
        ) != CIRCLE_COEFFICIENT_MLE_V3_VERSION
        || encoded[11..16] != [0_u8; 5]
    {
        return Err(CircleLagrangeSparseFunctionalError::Encoding);
    }
    let rounds = usize::from(encoded[10]);
    if !(3..=usize::from(CIRCLE_LAGRANGE_SPARSE_FUNCTIONAL_MAX_LOG_SIZE)).contains(&rounds) {
        return Err(CircleLagrangeSparseFunctionalError::Encoding);
    }
    let row_multilinear_value = Fp16::decode(&encoded[16..80])
        .map_err(|_| CircleLagrangeSparseFunctionalError::Encoding)?;
    let mut offset = CIRCLE_COEFFICIENT_MLE_V3_HEADER_BYTES;
    let mut functional_rounds = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let mut round = [Fp16::ZERO; 3];
        for coefficient in &mut round {
            *coefficient = Fp16::decode(
                encoded
                    .get(offset..offset + 64)
                    .ok_or(CircleLagrangeSparseFunctionalError::Encoding)?,
            )
            .map_err(|_| CircleLagrangeSparseFunctionalError::Encoding)?;
            offset += 64;
        }
        functional_rounds.push(round);
    }
    let take_u32 = |bytes: &[u8], cursor: &mut usize| {
        let end = cursor
            .checked_add(4)
            .ok_or(CircleLagrangeSparseFunctionalError::Encoding)?;
        let value = u32::from_be_bytes(
            bytes
                .get(*cursor..end)
                .ok_or(CircleLagrangeSparseFunctionalError::Encoding)?
                .try_into()
                .map_err(|_| CircleLagrangeSparseFunctionalError::Encoding)?,
        );
        *cursor = end;
        usize::try_from(value).map_err(|_| CircleLagrangeSparseFunctionalError::Encoding)
    };
    let circle_len = take_u32(encoded, &mut offset)?;
    let circle_end = offset
        .checked_add(circle_len)
        .ok_or(CircleLagrangeSparseFunctionalError::Encoding)?;
    let circle_evaluation_opening = decode_binding_multilinear_pcs_proof_v2(
        encoded
            .get(offset..circle_end)
            .ok_or(CircleLagrangeSparseFunctionalError::Encoding)?,
    )?;
    offset = circle_end;
    let terminal_len = take_u32(encoded, &mut offset)?;
    let terminal_end = offset
        .checked_add(terminal_len)
        .ok_or(CircleLagrangeSparseFunctionalError::Encoding)?;
    let functional_terminal_opening = decode_binding_multilinear_pcs_proof_v2(
        encoded
            .get(offset..terminal_end)
            .ok_or(CircleLagrangeSparseFunctionalError::Encoding)?,
    )?;
    if terminal_end != encoded.len() {
        return Err(CircleLagrangeSparseFunctionalError::Encoding);
    }
    Ok(CircleCoefficientMleProofV3 {
        row_multilinear_value,
        functional_rounds,
        circle_evaluation_opening,
        functional_terminal_opening,
    })
}

/// In-memory reference prover for the commitment-backed basis conversion.
/// Production code may stream the same inverse FFT and native-128 coefficient
/// PCS, but must preserve these exact roots, fold coordinates, and transcripts.
#[allow(clippy::too_many_arguments)]
pub fn prove_circle_coefficient_mle_v3(
    mut logical_coset_rows: Vec<Fp16>,
    circle_point: CirclePoint,
    multilinear_point: &[Fp16],
    functional_challenges: &[Fp16],
    coefficient_context: BindingDigestV2,
    circle_completion_coin: BindingDigestV2,
    functional_completion_coin: BindingDigestV2,
) -> Result<(CircleCoefficientMleProofV3, BindingRootV2), CircleLagrangeSparseFunctionalError> {
    if logical_coset_rows.len() != 1usize << multilinear_point.len()
        || multilinear_point.len() != functional_challenges.len()
        || multilinear_point.len() < 3
    {
        return Err(CircleLagrangeSparseFunctionalError::Shape);
    }
    let row_multilinear_value =
        evaluate_boolean_multilinear(logical_coset_rows.clone(), multilinear_point)?;
    let dual = circle_row_mle_coefficient_weights(multilinear_point)?;
    coset_to_circle_in_place(&mut logical_coset_rows);
    bit_reverse_permute(&mut logical_coset_rows)
        .map_err(|_| CircleLagrangeSparseFunctionalError::Circle)?;
    let coefficients = interpolate_extension_circle_evaluations(&logical_coset_rows)
        .map_err(|_| CircleLagrangeSparseFunctionalError::Circle)?;
    let (circle_coordinates, circle_scale) =
        circle_coefficient_mle_coordinates(multilinear_point.len() as u8, circle_point)?;
    let circle_evaluation_opening = prove_binding_multilinear_opening_v2(
        &coefficients,
        &circle_coordinates,
        coefficient_context,
        circle_completion_coin,
    )?;
    let coefficient_root = *circle_evaluation_opening
        .roots
        .first()
        .ok_or(CircleLagrangeSparseFunctionalError::Shape)?;
    let (functional_rounds, terminal) =
        prove_inner_product_low_first(coefficients.clone(), dual, functional_challenges)?;
    if functional_rounds
        .first()
        .map(|round| round[0] + round[0] + round[1] + round[2])
        != Some(row_multilinear_value)
    {
        return Err(CircleLagrangeSparseFunctionalError::Algebra);
    }
    let functional_terminal_opening = prove_binding_multilinear_opening_v2(
        &coefficients,
        functional_challenges,
        coefficient_context,
        functional_completion_coin,
    )?;
    let dual_terminal = evaluate_boolean_multilinear(
        circle_row_mle_coefficient_weights(multilinear_point)?,
        functional_challenges,
    )?;
    let direct_circle = evaluate_extension_coefficients_at_point(&coefficients, circle_point)
        .map_err(|_| CircleLagrangeSparseFunctionalError::Circle)?;
    if circle_evaluation_opening
        .terminal_values
        .iter()
        .any(|value| *value * circle_scale != direct_circle)
        || functional_terminal_opening.roots.first().copied() != Some(coefficient_root)
        || functional_terminal_opening
            .terminal_values
            .iter()
            .any(|value| *value * dual_terminal != terminal)
    {
        return Err(CircleLagrangeSparseFunctionalError::Algebra);
    }
    Ok((
        CircleCoefficientMleProofV3 {
            row_multilinear_value,
            functional_rounds,
            circle_evaluation_opening,
            functional_terminal_opening,
        },
        coefficient_root,
    ))
}

/// Prove an arbitrary verifier-fixed linear functional of the logical row
/// vector against the same coefficient root used for the selected Circle
/// opening. `row_weights` are not proof authority: the consuming verifier
/// must derive them from its governed sparse-map descriptor and pass the same
/// vector to [`verify_circle_coefficient_linear_v3`].
#[allow(clippy::too_many_arguments)]
pub fn prove_circle_coefficient_linear_v3(
    mut logical_coset_rows: Vec<Fp16>,
    circle_point: CirclePoint,
    row_weights: Vec<Fp16>,
    functional_challenges: &[Fp16],
    coefficient_context: BindingDigestV2,
    circle_completion_coin: BindingDigestV2,
    functional_completion_coin: BindingDigestV2,
) -> Result<(CircleCoefficientMleProofV3, BindingRootV2), CircleLagrangeSparseFunctionalError> {
    if logical_coset_rows.len() != row_weights.len()
        || !logical_coset_rows.len().is_power_of_two()
        || logical_coset_rows.len() != 1usize << functional_challenges.len()
        || functional_challenges.len() < 3
    {
        return Err(CircleLagrangeSparseFunctionalError::Shape);
    }
    let row_multilinear_value = logical_coset_rows
        .iter()
        .zip(&row_weights)
        .fold(Fp16::ZERO, |sum, (value, weight)| sum + *value * *weight);
    let dual = circle_row_functional_coefficient_weights(row_weights.clone())?;
    coset_to_circle_in_place(&mut logical_coset_rows);
    bit_reverse_permute(&mut logical_coset_rows)
        .map_err(|_| CircleLagrangeSparseFunctionalError::Circle)?;
    let coefficients = interpolate_extension_circle_evaluations(&logical_coset_rows)
        .map_err(|_| CircleLagrangeSparseFunctionalError::Circle)?;
    let (circle_coordinates, circle_scale) =
        circle_coefficient_mle_coordinates(functional_challenges.len() as u8, circle_point)?;
    let circle_evaluation_opening = prove_binding_multilinear_opening_v2(
        &coefficients,
        &circle_coordinates,
        coefficient_context,
        circle_completion_coin,
    )?;
    let coefficient_root = *circle_evaluation_opening
        .roots
        .first()
        .ok_or(CircleLagrangeSparseFunctionalError::Shape)?;
    let (functional_rounds, terminal) =
        prove_inner_product_low_first(coefficients.clone(), dual, functional_challenges)?;
    if functional_rounds
        .first()
        .map(|round| round[0] + round[0] + round[1] + round[2])
        != Some(row_multilinear_value)
    {
        return Err(CircleLagrangeSparseFunctionalError::Algebra);
    }
    let functional_terminal_opening = prove_binding_multilinear_opening_v2(
        &coefficients,
        functional_challenges,
        coefficient_context,
        functional_completion_coin,
    )?;
    let dual_terminal = evaluate_boolean_multilinear(
        circle_row_functional_coefficient_weights(row_weights)?,
        functional_challenges,
    )?;
    let direct_circle = evaluate_extension_coefficients_at_point(&coefficients, circle_point)
        .map_err(|_| CircleLagrangeSparseFunctionalError::Circle)?;
    if circle_evaluation_opening
        .terminal_values
        .iter()
        .any(|value| *value * circle_scale != direct_circle)
        || functional_terminal_opening.roots.first().copied() != Some(coefficient_root)
        || functional_terminal_opening
            .terminal_values
            .iter()
            .any(|value| *value * dual_terminal != terminal)
    {
        return Err(CircleLagrangeSparseFunctionalError::Algebra);
    }
    Ok((
        CircleCoefficientMleProofV3 {
            row_multilinear_value,
            functional_rounds,
            circle_evaluation_opening,
            functional_terminal_opening,
        },
        coefficient_root,
    ))
}

/// Verify a governed linear row functional.  The functional binding is
/// supplied separately so downstream batching can reject a valid proof for a
/// different semantic column/map even when its GKR terminal point is equal.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_circle_coefficient_linear_v3(
    proof: &CircleCoefficientMleProofV3,
    circle: AuthenticatedCircleOpening,
    expected_coefficient_root: BindingRootV2,
    expected_row_weights: Vec<Fp16>,
    expected_functional_binding: BindingDigestV2,
    functional_challenges: &[Fp16],
    coefficient_context: BindingDigestV2,
    circle_completion_coin: BindingDigestV2,
    functional_completion_coin: BindingDigestV2,
) -> Result<VerifiedCircleCoefficientMleV3, CircleLagrangeSparseFunctionalError> {
    if expected_row_weights.len() != 1usize << functional_challenges.len() {
        return Err(CircleLagrangeSparseFunctionalError::Shape);
    }
    let expected_dual_terminal = evaluate_boolean_multilinear(
        circle_row_functional_coefficient_weights(expected_row_weights)?,
        functional_challenges,
    )?;
    verify_circle_coefficient_linear_terminal_v3(
        proof,
        circle,
        expected_coefficient_root,
        expected_dual_terminal,
        expected_functional_binding,
        functional_challenges,
        coefficient_context,
        circle_completion_coin,
        functional_completion_coin,
    )
}

/// Low-memory verifier entry for a functional whose public dual terminal is
/// derived by a governed sparse-map implementation.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_circle_coefficient_linear_terminal_v3(
    proof: &CircleCoefficientMleProofV3,
    circle: AuthenticatedCircleOpening,
    expected_coefficient_root: BindingRootV2,
    expected_dual_terminal: Fp16,
    expected_functional_binding: BindingDigestV2,
    functional_challenges: &[Fp16],
    coefficient_context: BindingDigestV2,
    circle_completion_coin: BindingDigestV2,
    functional_completion_coin: BindingDigestV2,
) -> Result<VerifiedCircleCoefficientMleV3, CircleLagrangeSparseFunctionalError> {
    if proof.functional_rounds.len() != functional_challenges.len()
        || functional_challenges.len() < 3
        || expected_functional_binding
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(CircleLagrangeSparseFunctionalError::Shape);
    }
    let (circle_coordinates, circle_scale) =
        circle_coefficient_mle_coordinates(circle.log_size, circle.point)?;
    if usize::from(circle.log_size) != functional_challenges.len() {
        return Err(CircleLagrangeSparseFunctionalError::Shape);
    }
    let normalized_circle_value = circle.value
        * circle_scale
            .inverse()
            .map_err(|_| CircleLagrangeSparseFunctionalError::Point)?;
    let circle_opening = verify_binding_multilinear_opening_v2(
        &proof.circle_evaluation_opening,
        expected_coefficient_root,
        &circle_coordinates,
        normalized_circle_value,
        coefficient_context,
        circle_completion_coin,
    )?;
    let claimed_coefficient_terminal = *proof
        .functional_terminal_opening
        .terminal_values
        .first()
        .ok_or(CircleLagrangeSparseFunctionalError::Shape)?;
    let terminal_opening = verify_binding_multilinear_opening_v2(
        &proof.functional_terminal_opening,
        expected_coefficient_root,
        functional_challenges,
        claimed_coefficient_terminal,
        coefficient_context,
        functional_completion_coin,
    )?;
    let mut current = proof.row_multilinear_value;
    for (round, challenge) in proof.functional_rounds.iter().zip(functional_challenges) {
        if round[0] + round[0] + round[1] + round[2] != current {
            return Err(CircleLagrangeSparseFunctionalError::Algebra);
        }
        current = evaluate_quadratic(*round, *challenge);
    }
    if current != claimed_coefficient_terminal * expected_dual_terminal {
        return Err(CircleLagrangeSparseFunctionalError::Algebra);
    }
    Ok(VerifiedCircleCoefficientMleV3 {
        coefficient_root: expected_coefficient_root,
        circle_opening,
        terminal_opening,
        multilinear_point: functional_challenges.to_vec(),
        multilinear_value: proof.row_multilinear_value,
        functional_binding: expected_functional_binding,
    })
}

/// Verify the complete coefficient-anchored conversion.  `circle` must come
/// from the selected native-128 FRI verifier, while `expected_coefficient_root`
/// must have been fixed in the parent transcript before the OODS point.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_circle_coefficient_mle_v3(
    proof: &CircleCoefficientMleProofV3,
    circle: AuthenticatedCircleOpening,
    expected_coefficient_root: BindingRootV2,
    expected_multilinear_point: &[Fp16],
    functional_challenges: &[Fp16],
    coefficient_context: BindingDigestV2,
    circle_completion_coin: BindingDigestV2,
    functional_completion_coin: BindingDigestV2,
) -> Result<VerifiedCircleCoefficientMleV3, CircleLagrangeSparseFunctionalError> {
    if usize::from(circle.log_size) != expected_multilinear_point.len()
        || expected_multilinear_point.len() != functional_challenges.len()
        || proof.functional_rounds.len() != functional_challenges.len()
        || expected_multilinear_point.len() < 3
    {
        return Err(CircleLagrangeSparseFunctionalError::Shape);
    }
    let (circle_coordinates, circle_scale) =
        circle_coefficient_mle_coordinates(circle.log_size, circle.point)?;
    let normalized_circle_value = circle.value
        * circle_scale
            .inverse()
            .map_err(|_| CircleLagrangeSparseFunctionalError::Point)?;
    let circle_opening = verify_binding_multilinear_opening_v2(
        &proof.circle_evaluation_opening,
        expected_coefficient_root,
        &circle_coordinates,
        normalized_circle_value,
        coefficient_context,
        circle_completion_coin,
    )?;
    let claimed_coefficient_terminal = *proof
        .functional_terminal_opening
        .terminal_values
        .first()
        .ok_or(CircleLagrangeSparseFunctionalError::Shape)?;
    let terminal_opening = verify_binding_multilinear_opening_v2(
        &proof.functional_terminal_opening,
        expected_coefficient_root,
        functional_challenges,
        claimed_coefficient_terminal,
        coefficient_context,
        functional_completion_coin,
    )?;
    let mut current = proof.row_multilinear_value;
    for (round, challenge) in proof.functional_rounds.iter().zip(functional_challenges) {
        if round[0] + round[0] + round[1] + round[2] != current {
            return Err(CircleLagrangeSparseFunctionalError::Algebra);
        }
        current = evaluate_quadratic(*round, *challenge);
    }
    let dual_terminal = evaluate_boolean_multilinear(
        circle_row_mle_coefficient_weights(expected_multilinear_point)?,
        functional_challenges,
    )?;
    if current != claimed_coefficient_terminal * dual_terminal {
        return Err(CircleLagrangeSparseFunctionalError::Algebra);
    }
    Ok(VerifiedCircleCoefficientMleV3 {
        coefficient_root: expected_coefficient_root,
        circle_opening,
        terminal_opening,
        multilinear_point: expected_multilinear_point.to_vec(),
        multilinear_value: proof.row_multilinear_value,
        functional_binding: row_mle_functional_binding(expected_multilinear_point)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        binding_root_v2::BindingRoleV2, circle_fft::interpolate_extension_circle_evaluations,
        field::M31,
    };

    fn fp(value: u32) -> Fp16 {
        Fp16::from_m31(M31::from_canonical(value).unwrap())
    }

    #[test]
    fn circle_lagrange_adapter_accepts_and_rejects_mutations() {
        let values = (0..32).map(|i| fp(i * i + 7 * i + 3)).collect::<Vec<_>>();
        let challenges = (0..5).map(|i| fp(101 + 17 * i)).collect::<Vec<_>>();
        let base = crate::circle_fri::canonic_circle_point(6, 9).unwrap();
        let point = CirclePoint {
            x: Fp16::from_m31(base.x),
            y: Fp16::from_m31(base.y),
        };
        let (proof, claimed) =
            prove_circle_lagrange_sparse_functional(values.clone(), point, &challenges).unwrap();
        let encoded = encode_circle_lagrange_sparse_functional_proof(&proof).unwrap();
        assert_eq!(
            decode_circle_lagrange_sparse_functional_proof(&encoded).unwrap(),
            proof
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            decode_circle_lagrange_sparse_functional_proof(&trailing),
            Err(CircleLagrangeSparseFunctionalError::Encoding)
        );
        let mut folded = values;
        let mut active = folded.len();
        for challenge in &challenges {
            for index in 0..active / 2 {
                folded[index] = folded[2 * index] * (Fp16::ONE - *challenge)
                    + folded[2 * index + 1] * *challenge;
            }
            active /= 2;
        }
        let verified = verify_circle_lagrange_sparse_functional(
            &proof,
            AuthenticatedCircleOpening {
                value: claimed,
                point,
                log_size: 5,
            },
            AuthenticatedMultilinearTerminal {
                point: challenges.clone(),
                value: folded[0],
            },
        )
        .unwrap();
        assert_eq!(verified.circle_value, claimed);
        let source_values = (0..32).map(|i| fp(i * i + 7 * i + 3)).collect::<Vec<_>>();
        let (proof_v2, claimed_v2) =
            prove_circle_lagrange_sparse_functional_v2(source_values, point, &challenges).unwrap();
        assert_eq!(claimed_v2, claimed);
        assert_eq!(proof_v2.multilinear_value, folded[0]);
        let encoded_v2 = encode_circle_lagrange_sparse_functional_proof_v2(&proof_v2).unwrap();
        assert_eq!(
            decode_circle_lagrange_sparse_functional_proof_v2(&encoded_v2).unwrap(),
            proof_v2
        );
        verify_circle_lagrange_sparse_functional_v2(
            &proof_v2,
            AuthenticatedCircleOpening {
                value: claimed,
                point,
                log_size: 5,
            },
            &challenges,
        )
        .unwrap();
        let mut changed_v2 = proof_v2;
        changed_v2.multilinear_value = changed_v2.multilinear_value + Fp16::ONE;
        assert_eq!(
            verify_circle_lagrange_sparse_functional_v2(
                &changed_v2,
                AuthenticatedCircleOpening {
                    value: claimed,
                    point,
                    log_size: 5,
                },
                &challenges,
            ),
            Err(CircleLagrangeSparseFunctionalError::Algebra)
        );
        let mut direct = (0..32).map(|i| fp(i * i + 7 * i + 3)).collect::<Vec<_>>();
        coset_to_circle_in_place(&mut direct);
        bit_reverse_permute(&mut direct).unwrap();
        let direct = interpolate_extension_circle_evaluations(&direct).unwrap();
        assert_eq!(
            claimed,
            evaluate_extension_coefficients_at_point(&direct, point).unwrap()
        );

        let mut changed = proof.clone();
        changed.rounds[0][0] = changed.rounds[0][0] + Fp16::ONE;
        assert_eq!(
            verify_circle_lagrange_sparse_functional(
                &changed,
                AuthenticatedCircleOpening {
                    value: claimed,
                    point,
                    log_size: 5,
                },
                AuthenticatedMultilinearTerminal {
                    point: challenges,
                    value: folded[0],
                },
            ),
            Err(CircleLagrangeSparseFunctionalError::Algebra)
        );
    }

    #[test]
    fn coefficient_anchored_adapter_binds_circle_and_mle_to_one_root() {
        let rows = (0..32)
            .map(|index| fp(13 + 19 * index + index * index))
            .collect::<Vec<_>>();
        let mle_point = (0..5).map(|index| fp(101 + 7 * index)).collect::<Vec<_>>();
        let functional_challenges = (0..5).map(|index| fp(401 + 11 * index)).collect::<Vec<_>>();
        let base = crate::circle_fri::canonic_circle_point(6, 13).unwrap();
        let circle_point = CirclePoint {
            x: Fp16::from_m31(base.x),
            y: Fp16::from_m31(base.y),
        };
        let context =
            BindingDigestV2::hash(BindingRoleV2::Payload, b"coefficient-context").unwrap();
        let circle_coin = BindingDigestV2::hash(BindingRoleV2::Payload, b"circle-coin").unwrap();
        let functional_coin =
            BindingDigestV2::hash(BindingRoleV2::Payload, b"functional-coin").unwrap();
        let mut diagnostic_rows = rows.clone();
        coset_to_circle_in_place(&mut diagnostic_rows);
        bit_reverse_permute(&mut diagnostic_rows).unwrap();
        let diagnostic_coefficients =
            interpolate_extension_circle_evaluations(&diagnostic_rows).unwrap();
        let diagnostic_dual = circle_row_mle_coefficient_weights(&mle_point).unwrap();
        let diagnostic_inner = diagnostic_coefficients
            .iter()
            .zip(&diagnostic_dual)
            .fold(Fp16::ZERO, |sum, (left, right)| sum + *left * *right);
        let diagnostic_expected = evaluate_boolean_multilinear(rows.clone(), &mle_point).unwrap();
        assert_eq!(diagnostic_inner, diagnostic_expected);
        let dense_dual_terminal =
            evaluate_boolean_multilinear(diagnostic_dual.clone(), &functional_challenges).unwrap();
        let mle_weights = equality_table(&mle_point).unwrap();
        let streaming_dual_terminal =
            circle_row_functional_dual_terminal_streaming(5, &functional_challenges, |row| {
                Ok(mle_weights[row])
            })
            .unwrap();
        assert_eq!(streaming_dual_terminal, dense_dual_terminal);
        let (proof, root) = prove_circle_coefficient_mle_v3(
            rows.clone(),
            circle_point,
            &mle_point,
            &functional_challenges,
            context,
            circle_coin,
            functional_coin,
        )
        .unwrap();
        let encoded = encode_circle_coefficient_mle_proof_v3(&proof).unwrap();
        assert_eq!(
            decode_circle_coefficient_mle_proof_v3(&encoded).unwrap(),
            proof
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_circle_coefficient_mle_proof_v3(&trailing),
            Err(CircleLagrangeSparseFunctionalError::Encoding)
        );

        let mut circle_rows = rows.clone();
        coset_to_circle_in_place(&mut circle_rows);
        bit_reverse_permute(&mut circle_rows).unwrap();
        let coefficients = interpolate_extension_circle_evaluations(&circle_rows).unwrap();
        let circle_value =
            evaluate_extension_coefficients_at_point(&coefficients, circle_point).unwrap();
        let verified = verify_circle_coefficient_mle_v3(
            &proof,
            AuthenticatedCircleOpening {
                value: circle_value,
                point: circle_point,
                log_size: 5,
            },
            root,
            &mle_point,
            &functional_challenges,
            context,
            circle_coin,
            functional_coin,
        )
        .unwrap();
        assert_eq!(verified.coefficient_root(), root);
        assert_eq!(verified.multilinear_point(), mle_point);
        assert_eq!(verified.multilinear_value(), proof.row_multilinear_value);

        let row_weights = (0..32)
            .map(|index| fp(17 + 5 * index + index * index))
            .collect::<Vec<_>>();
        let linear_expected = rows
            .iter()
            .zip(&row_weights)
            .fold(Fp16::ZERO, |sum, (value, weight)| sum + *value * *weight);
        let functional_binding =
            BindingDigestV2::hash(BindingRoleV2::Payload, b"arbitrary-row-functional").unwrap();
        let precommitted_root = circle_coefficient_root_v3(rows.clone(), context).unwrap();
        let (linear, linear_root) = prove_circle_coefficient_linear_v3(
            rows,
            circle_point,
            row_weights.clone(),
            &functional_challenges,
            context,
            circle_coin,
            functional_coin,
        )
        .unwrap();
        assert_eq!(linear_root, root);
        assert_eq!(precommitted_root, linear_root);
        let linear_dual =
            circle_row_functional_dual_terminal_streaming(5, &functional_challenges, |row| {
                Ok(row_weights[row])
            })
            .unwrap();
        let verified_linear = verify_circle_coefficient_linear_terminal_v3(
            &linear,
            AuthenticatedCircleOpening {
                value: circle_value,
                point: circle_point,
                log_size: 5,
            },
            linear_root,
            linear_dual,
            functional_binding,
            &functional_challenges,
            context,
            circle_coin,
            functional_coin,
        )
        .unwrap();
        assert_eq!(verified_linear.functional_binding(), functional_binding);
        assert_eq!(verified_linear.multilinear_value(), linear_expected);

        let mut changed = proof.clone();
        changed.row_multilinear_value = changed.row_multilinear_value + Fp16::ONE;
        assert_eq!(
            verify_circle_coefficient_mle_v3(
                &changed,
                AuthenticatedCircleOpening {
                    value: circle_value,
                    point: circle_point,
                    log_size: 5,
                },
                root,
                &mle_point,
                &functional_challenges,
                context,
                circle_coin,
                functional_coin,
            ),
            Err(CircleLagrangeSparseFunctionalError::Algebra)
        );
        assert_eq!(
            verify_circle_coefficient_mle_v3(
                &proof,
                AuthenticatedCircleOpening {
                    value: circle_value,
                    point: circle_point,
                    log_size: 5,
                },
                BindingRootV2::decode(&[9_u8; 128]).unwrap(),
                &mle_point,
                &functional_challenges,
                context,
                circle_coin,
                functional_coin,
            ),
            Err(CircleLagrangeSparseFunctionalError::CoefficientPcs)
        );
    }
}
