//! Scalar degree-16 Circle-FRI fold primitives.
//!
//! Inputs use Circle-FFT bit-reversed order.  The first fold maps conjugate
//! circle points to their shared x-coordinate; later folds operate on the line
//! domain.  This module is intentionally not a complete FRI prover or a proof
//! suite selection.

use alloc::vec::Vec;

use crate::field::{FieldError, Fp16, M31};
use crate::oods::CirclePoint;

/// Base-field circle group order is `2^31`.
pub const M31_CIRCLE_LOG_ORDER: u8 = 31;
/// Frozen S-two M31 circle generator x-coordinate.
pub const M31_CIRCLE_GENERATOR_X: u32 = 2;
/// Frozen S-two M31 circle generator y-coordinate.
pub const M31_CIRCLE_GENERATOR_Y: u32 = 1_268_011_823;
/// Smallest accepted circle fold domain.
pub const MIN_CIRCLE_DOMAIN_LOG_SIZE: u8 = 2;
/// Largest interpolable circle domain over M31.
pub const MAX_CIRCLE_DOMAIN_LOG_SIZE: u8 = 30;

/// One canonical point on `x^2+y^2=1` over M31.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BaseCirclePoint {
    /// Canonical x-coordinate.
    pub x: M31,
    /// Canonical y-coordinate.
    pub y: M31,
}

impl BaseCirclePoint {
    /// Circle identity.
    pub const IDENTITY: Self = Self {
        x: M31::ONE,
        y: M31::ZERO,
    };
    /// Frozen full-order generator.
    pub fn generator() -> Self {
        Self {
            x: M31::from_canonical(M31_CIRCLE_GENERATOR_X)
                .expect("frozen generator x is canonical"),
            y: M31::from_canonical(M31_CIRCLE_GENERATOR_Y)
                .expect("frozen generator y is canonical"),
        }
    }

    /// Circle group addition.
    pub const fn add(self, rhs: Self) -> Self {
        Self {
            x: self.x.mul(rhs.x).sub(self.y.mul(rhs.y)),
            y: self.x.mul(rhs.y).add(self.y.mul(rhs.x)),
        }
    }

    /// Circle doubling.
    pub const fn double(self) -> Self {
        self.add(self)
    }

    /// Circle conjugation / group negation.
    pub const fn conjugate(self) -> Self {
        Self {
            x: self.x,
            y: self.y.neg(),
        }
    }

    /// Fixed public scalar multiplication.
    pub fn multiply(self, scalar: usize) -> Self {
        let mut result = Self::IDENTITY;
        let mut current = self;
        let mut remaining = scalar;
        while remaining != 0 {
            if remaining & 1 == 1 {
                result = result.add(current);
            }
            current = current.double();
            remaining >>= 1;
        }
        result
    }

    /// Returns whether the point satisfies the circle equation.
    pub const fn is_on_circle(self) -> bool {
        self.x.square().add(self.y.square()).as_u32() == 1
    }
}

/// Strict Circle-FRI primitive failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CircleFriError {
    /// The logarithmic domain size is unsupported.
    LogSizeInvalid { log_size: u8 },
    /// The index is outside the declared domain.
    IndexOutOfBounds { index: usize, log_size: u8 },
    /// Evaluation length is not a supported power of two.
    EvaluationSizeInvalid { size: usize },
    /// The requested fold count is invalid for the source domain.
    FoldCountInvalid { fold_count: u8, size: usize },
    /// A theorem-forbidden denominator was zero.
    ExceptionalDenominator,
    /// The OODS query was not on the circle.
    OodsQueryNotOnCircle,
    /// The OODS query lay in the forbidden fixed subfield.
    OodsQueryInFixedSubfield,
    /// The degree-corrected row had zero or inconsistent column counts.
    DegreeCorrectedColumnCountMismatch,
    /// A FRI batch did not have the declared rectangular domain shape.
    FriBatchShapeInvalid,
    /// The number of folding challenges did not equal the attached domains.
    FriChallengeCountMismatch,
    /// The independent batch-mask count did not equal the attached domains.
    FriBatchMaskCountMismatch,
    /// A batch mask did not provide exactly one value on the matching domain.
    FriBatchMaskShapeMismatch,
    /// Attached circle domains were not unique and strictly descending.
    FriDomainsNotStrictlyDescending,
    /// A prior line layer did not align with the next attached circle domain.
    FriPreviousLayerDomainMismatch,
    /// The frozen canonical-domain transition step did not reproduce index one.
    DomainStepMismatch,
    /// A lower-level field operation failed.
    Field(FieldError),
}

impl From<FieldError> for CircleFriError {
    fn from(value: FieldError) -> Self {
        Self::Field(value)
    }
}

/// Reverse exactly `log_size` low bits.
pub fn bit_reverse_index(index: usize, log_size: u8) -> Result<usize, CircleFriError> {
    if log_size == 0 || log_size > MAX_CIRCLE_DOMAIN_LOG_SIZE {
        return Err(CircleFriError::LogSizeInvalid { log_size });
    }
    let size = 1_usize << log_size;
    if index >= size {
        return Err(CircleFriError::IndexOutOfBounds { index, log_size });
    }
    Ok(index.reverse_bits() >> (usize::BITS - u32::from(log_size)))
}

fn point_from_index(index: usize) -> BaseCirclePoint {
    let mask = (1_usize << M31_CIRCLE_LOG_ORDER) - 1;
    BaseCirclePoint::generator().multiply(index & mask)
}

/// Return one canonical circle-domain point in natural order.
pub fn canonic_circle_point(
    log_size: u8,
    natural_index: usize,
) -> Result<BaseCirclePoint, CircleFriError> {
    if !(MIN_CIRCLE_DOMAIN_LOG_SIZE..=MAX_CIRCLE_DOMAIN_LOG_SIZE).contains(&log_size) {
        return Err(CircleFriError::LogSizeInvalid { log_size });
    }
    let size = 1_usize << log_size;
    if natural_index >= size {
        return Err(CircleFriError::IndexOutOfBounds {
            index: natural_index,
            log_size,
        });
    }
    let half_size = size >> 1;
    let initial_index = 1_usize << (M31_CIRCLE_LOG_ORDER - (log_size + 1));
    let step_index = 1_usize << (M31_CIRCLE_LOG_ORDER - (log_size - 1));
    let point = if natural_index < half_size {
        point_from_index(initial_index + natural_index * step_index)
    } else {
        point_from_index(initial_index + (natural_index - half_size) * step_index).conjugate()
    };
    debug_assert!(point.is_on_circle());
    Ok(point)
}

/// Return the natural-order transition step for a canonical circle domain.
pub fn circle_domain_step(log_size: u8) -> Result<BaseCirclePoint, CircleFriError> {
    if !(MIN_CIRCLE_DOMAIN_LOG_SIZE..=MAX_CIRCLE_DOMAIN_LOG_SIZE).contains(&log_size) {
        return Err(CircleFriError::LogSizeInvalid { log_size });
    }
    let step = point_from_index(1_usize << (M31_CIRCLE_LOG_ORDER - (log_size - 1)));
    let first = canonic_circle_point(log_size, 0)?;
    let second = canonic_circle_point(log_size, 1)?;
    if first.add(step) != second {
        return Err(CircleFriError::DomainStepMismatch);
    }
    Ok(step)
}

fn half_odds_line_x(log_size: u8, natural_index: usize) -> Result<M31, CircleFriError> {
    if log_size == 0 || log_size >= MAX_CIRCLE_DOMAIN_LOG_SIZE {
        return Err(CircleFriError::LogSizeInvalid { log_size });
    }
    let size = 1_usize << log_size;
    if natural_index >= size {
        return Err(CircleFriError::IndexOutOfBounds {
            index: natural_index,
            log_size,
        });
    }
    let initial_index = 1_usize << (M31_CIRCLE_LOG_ORDER - (log_size + 2));
    let step_index = 1_usize << (M31_CIRCLE_LOG_ORDER - log_size);
    Ok(point_from_index(initial_index + natural_index * step_index).x)
}

fn checked_log_size(size: usize, minimum: usize) -> Result<u8, CircleFriError> {
    if size < minimum || !size.is_power_of_two() {
        return Err(CircleFriError::EvaluationSizeInvalid { size });
    }
    let log_size = size.ilog2() as u8;
    if log_size > MAX_CIRCLE_DOMAIN_LOG_SIZE {
        return Err(CircleFriError::EvaluationSizeInvalid { size });
    }
    Ok(log_size)
}

/// Apply one conjugate-pair circle-to-line fold.
pub fn fold_circle_into_line(values: &[Fp16], alpha: Fp16) -> Result<Vec<Fp16>, CircleFriError> {
    let log_size = checked_log_size(values.len(), 1 << MIN_CIRCLE_DOMAIN_LOG_SIZE)?;
    let mut result = Vec::with_capacity(values.len() >> 1);
    for (pair_index, pair) in values.chunks_exact(2).enumerate() {
        result.push(fold_circle_pair(pair, pair_index, log_size, alpha)?);
    }
    Ok(result)
}

/// Fold one authenticated conjugate pair at its exact bit-reversed position.
pub fn fold_circle_pair(
    pair: &[Fp16],
    pair_index: usize,
    log_size: u8,
    alpha: Fp16,
) -> Result<Fp16, CircleFriError> {
    if pair.len() != 2 || log_size < MIN_CIRCLE_DOMAIN_LOG_SIZE {
        return Err(CircleFriError::EvaluationSizeInvalid { size: pair.len() });
    }
    let pair_count = 1_usize << (log_size - 1);
    if pair_index >= pair_count {
        return Err(CircleFriError::IndexOutOfBounds {
            index: pair_index,
            log_size: log_size - 1,
        });
    }
    let natural_index = bit_reverse_index(pair_index << 1, log_size)?;
    let point = canonic_circle_point(log_size, natural_index)?;
    if point.y.is_zero() {
        return Err(CircleFriError::ExceptionalDenominator);
    }
    let inverse_y = point.y.inverse()?;
    let f0 = pair[0].add(pair[1]);
    let f1 = pair[0].sub(pair[1]).mul(Fp16::from_m31(inverse_y));
    Ok(f0.add(alpha.mul(f1)))
}

/// Apply one line-domain fold in bit-reversed order.
pub fn fold_line(values: &[Fp16], alpha: Fp16) -> Result<Vec<Fp16>, CircleFriError> {
    let log_size = checked_log_size(values.len(), 2)?;
    if log_size >= MAX_CIRCLE_DOMAIN_LOG_SIZE {
        return Err(CircleFriError::EvaluationSizeInvalid { size: values.len() });
    }
    let mut result = Vec::with_capacity(values.len() >> 1);
    for (pair_index, pair) in values.chunks_exact(2).enumerate() {
        result.push(fold_line_pair(pair, pair_index, log_size, alpha)?);
    }
    Ok(result)
}

/// Fold one authenticated line-domain pair at its exact bit-reversed position.
pub fn fold_line_pair(
    pair: &[Fp16],
    pair_index: usize,
    log_size: u8,
    alpha: Fp16,
) -> Result<Fp16, CircleFriError> {
    if pair.len() != 2 || log_size == 0 || log_size >= MAX_CIRCLE_DOMAIN_LOG_SIZE {
        return Err(CircleFriError::EvaluationSizeInvalid { size: pair.len() });
    }
    let pair_count = 1_usize << (log_size - 1);
    if pair_index >= pair_count {
        return Err(CircleFriError::IndexOutOfBounds {
            index: pair_index,
            log_size: log_size - 1,
        });
    }
    let natural_index = bit_reverse_index(pair_index << 1, log_size)?;
    let x = half_odds_line_x(log_size, natural_index)?;
    if x.is_zero() {
        return Err(CircleFriError::ExceptionalDenominator);
    }
    let inverse_x = x.inverse()?;
    let f0 = pair[0].add(pair[1]);
    let f1 = pair[0].sub(pair[1]).mul(Fp16::from_m31(inverse_x));
    Ok(f0.add(alpha.mul(f1)))
}

/// Fold circle-to-line once, then square alpha for each line fold.
pub fn fold_circle_layer(
    values: &[Fp16],
    alpha: Fp16,
    fold_count: u8,
) -> Result<Vec<Fp16>, CircleFriError> {
    if fold_count == 0 || (1_usize << fold_count) > values.len() {
        return Err(CircleFriError::FoldCountInvalid {
            fold_count,
            size: values.len(),
        });
    }
    let mut result = fold_circle_into_line(values, alpha)?;
    let mut folding_alpha = alpha.square();
    for _ in 1..fold_count {
        result = fold_line(&result, folding_alpha)?;
        folding_alpha = folding_alpha.square();
    }
    Ok(result)
}

fn validate_oods_query_point(query: CirclePoint) -> Result<(), CircleFriError> {
    if query.x.square().add(query.y.square()) != Fp16::ONE {
        return Err(CircleFriError::OodsQueryNotOnCircle);
    }
    if query.x.is_in_fp8_subfield() && query.y.is_in_fp8_subfield() {
        return Err(CircleFriError::OodsQueryInFixedSubfield);
    }
    Ok(())
}

/// Evaluate the line through `Q` and its Fp16/Fp8 conjugate at `P`.
///
/// Since an accepted query is outside Fp8, the pair is distinct.  This line
/// cannot intersect the M31 circle domain at a third point.
pub fn conjugate_pair_zeroifier(
    domain_point: BaseCirclePoint,
    query: CirclePoint,
) -> Result<Fp16, CircleFriError> {
    validate_oods_query_point(query)?;
    let conjugate = CirclePoint {
        x: query.x.conjugate(),
        y: query.y.conjugate(),
    };
    if query == conjugate {
        return Err(CircleFriError::OodsQueryInFixedSubfield);
    }
    let point_x = Fp16::from_m31(domain_point.x);
    let point_y = Fp16::from_m31(domain_point.y);
    let zeroifier = query
        .y
        .sub(conjugate.y)
        .mul(point_x)
        .add(conjugate.x.sub(query.x).mul(point_y))
        .add(query.x.mul(conjugate.y))
        .sub(query.y.mul(conjugate.x));
    if zeroifier.is_zero() {
        return Err(CircleFriError::ExceptionalDenominator);
    }
    Ok(zeroifier)
}

fn two_point_claim_line(
    domain_point: BaseCirclePoint,
    query: CirclePoint,
    claim: Fp16,
    conjugate_query_claim: Fp16,
) -> Result<(Fp16, Fp16), CircleFriError> {
    let conjugate = CirclePoint {
        x: query.x.conjugate(),
        y: query.y.conjugate(),
    };
    let (query_coordinate, conjugate_coordinate, domain_coordinate) = if query.y != conjugate.y {
        (query.y, conjugate.y, Fp16::from_m31(domain_point.y))
    } else if query.x != conjugate.x {
        (query.x, conjugate.x, Fp16::from_m31(domain_point.x))
    } else {
        return Err(CircleFriError::OodsQueryInFixedSubfield);
    };
    let scale = conjugate_coordinate.sub(query_coordinate);
    let slope_numerator = conjugate_query_claim.sub(claim);
    let intercept_numerator = claim.mul(scale).sub(slope_numerator.mul(query_coordinate));
    Ok((
        scale,
        slope_numerator
            .mul(domain_coordinate)
            .add(intercept_numerator),
    ))
}

/// Original and quotient values jointly subjected to the low-degree test.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DegreeCorrectedRow {
    /// Original committed function values at one base-domain point.
    pub original_values: Vec<Fp16>,
    /// Corresponding Fp8-conjugate-pair quotient values.
    pub quotient_values: Vec<Fp16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DegreeCorrectionPlan {
    use_y_coordinate: bool,
    scale: Fp16,
    slopes: Vec<Fp16>,
    intercepts: Vec<Fp16>,
}

impl DegreeCorrectionPlan {
    pub(crate) fn new(
        query: CirclePoint,
        claimed_query_values: &[Fp16],
        claimed_conjugate_query_values: &[Fp16],
    ) -> Result<Self, CircleFriError> {
        if claimed_query_values.is_empty()
            || claimed_query_values.len() != claimed_conjugate_query_values.len()
        {
            return Err(CircleFriError::DegreeCorrectedColumnCountMismatch);
        }
        validate_oods_query_point(query)?;
        let conjugate = CirclePoint {
            x: query.x.conjugate(),
            y: query.y.conjugate(),
        };
        let (use_y_coordinate, query_coordinate, conjugate_coordinate) = if query.y != conjugate.y {
            (true, query.y, conjugate.y)
        } else if query.x != conjugate.x {
            (false, query.x, conjugate.x)
        } else {
            return Err(CircleFriError::OodsQueryInFixedSubfield);
        };
        let scale = conjugate_coordinate.sub(query_coordinate);
        let mut slopes = Vec::with_capacity(claimed_query_values.len());
        let mut intercepts = Vec::with_capacity(claimed_query_values.len());
        for (claim, conjugate_claim) in claimed_query_values
            .iter()
            .zip(claimed_conjugate_query_values)
        {
            let slope = conjugate_claim.sub(*claim);
            slopes.push(slope);
            intercepts.push(claim.mul(scale).sub(slope.mul(query_coordinate)));
        }
        Ok(Self {
            use_y_coordinate,
            scale,
            slopes,
            intercepts,
        })
    }
}

impl DegreeCorrectedRow {
    /// Returns original values followed by quotient values for the FRI batch.
    pub fn fri_batch_values(&self) -> Vec<Fp16> {
        self.original_values
            .iter()
            .chain(self.quotient_values.iter())
            .copied()
            .collect()
    }
}

/// Build the exact original-plus-quotient Protocol 4 row.
pub fn degree_corrected_row(
    domain_point: BaseCirclePoint,
    query: CirclePoint,
    original_values: &[Fp16],
    claimed_query_values: &[Fp16],
    claimed_conjugate_query_values: &[Fp16],
) -> Result<DegreeCorrectedRow, CircleFriError> {
    if original_values.is_empty()
        || original_values.len() != claimed_query_values.len()
        || original_values.len() != claimed_conjugate_query_values.len()
    {
        return Err(CircleFriError::DegreeCorrectedColumnCountMismatch);
    }
    let zeroifier_inverse = conjugate_pair_zeroifier(domain_point, query)?.inverse()?;
    degree_corrected_row_with_inverse(
        domain_point,
        query,
        original_values,
        claimed_query_values,
        claimed_conjugate_query_values,
        zeroifier_inverse,
    )
}

pub(crate) fn degree_corrected_row_with_inverse(
    domain_point: BaseCirclePoint,
    query: CirclePoint,
    original_values: &[Fp16],
    claimed_query_values: &[Fp16],
    claimed_conjugate_query_values: &[Fp16],
    zeroifier_inverse: Fp16,
) -> Result<DegreeCorrectedRow, CircleFriError> {
    if original_values.is_empty()
        || original_values.len() != claimed_query_values.len()
        || original_values.len() != claimed_conjugate_query_values.len()
        || zeroifier_inverse.is_zero()
    {
        return Err(CircleFriError::DegreeCorrectedColumnCountMismatch);
    }
    let plan =
        DegreeCorrectionPlan::new(query, claimed_query_values, claimed_conjugate_query_values)?;
    degree_corrected_row_with_plan(domain_point, original_values, zeroifier_inverse, &plan)
}

pub(crate) fn degree_corrected_row_with_plan(
    domain_point: BaseCirclePoint,
    original_values: &[Fp16],
    zeroifier_inverse: Fp16,
    plan: &DegreeCorrectionPlan,
) -> Result<DegreeCorrectedRow, CircleFriError> {
    if original_values.is_empty()
        || original_values.len() != plan.slopes.len()
        || original_values.len() != plan.intercepts.len()
        || zeroifier_inverse.is_zero()
    {
        return Err(CircleFriError::DegreeCorrectedColumnCountMismatch);
    }
    let coordinate = Fp16::from_m31(if plan.use_y_coordinate {
        domain_point.y
    } else {
        domain_point.x
    });
    let quotient_values = original_values
        .iter()
        .zip(&plan.slopes)
        .zip(&plan.intercepts)
        .map(|((original, slope), intercept)| {
            let claim_line = slope.mul(coordinate).add(*intercept);
            plan.scale
                .mul(*original)
                .sub(claim_line)
                .mul(zeroifier_inverse)
        })
        .collect::<Vec<_>>();
    Ok(DegreeCorrectedRow {
        original_values: original_values.to_vec(),
        quotient_values,
    })
}

/// Verify every original/quotient identity at one opened domain point.
pub fn verify_degree_corrected_row(
    domain_point: BaseCirclePoint,
    query: CirclePoint,
    row: &DegreeCorrectedRow,
    claimed_query_values: &[Fp16],
    claimed_conjugate_query_values: &[Fp16],
) -> Result<bool, CircleFriError> {
    if row.original_values.is_empty()
        || row.original_values.len() != row.quotient_values.len()
        || row.original_values.len() != claimed_query_values.len()
        || row.original_values.len() != claimed_conjugate_query_values.len()
    {
        return Err(CircleFriError::DegreeCorrectedColumnCountMismatch);
    }
    let zeroifier = conjugate_pair_zeroifier(domain_point, query)?;
    for (((original, quotient), claim), conjugate_claim) in row
        .original_values
        .iter()
        .zip(&row.quotient_values)
        .zip(claimed_query_values)
        .zip(claimed_conjugate_query_values)
    {
        let (scale, claim_line) =
            two_point_claim_line(domain_point, query, *claim, *conjugate_claim)?;
        if zeroifier.mul(*quotient) != scale.mul(*original).sub(claim_line) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// One equal-width Fp16 function batch on a canonical circle domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriDomainBatch {
    /// Base-two domain logarithm.
    pub log_size: u8,
    /// Rows in Circle-FFT bit-reversed order.
    pub rows: Vec<Vec<Fp16>>,
}

impl FriDomainBatch {
    /// Strictly validates the domain and rectangular nonempty row shape.
    pub fn new(log_size: u8, rows: Vec<Vec<Fp16>>) -> Result<Self, CircleFriError> {
        if !(MIN_CIRCLE_DOMAIN_LOG_SIZE..=MAX_CIRCLE_DOMAIN_LOG_SIZE).contains(&log_size) {
            return Err(CircleFriError::LogSizeInvalid { log_size });
        }
        if rows.len() != 1_usize << log_size || rows.first().is_none_or(Vec::is_empty) {
            return Err(CircleFriError::FriBatchShapeInvalid);
        }
        let column_count = rows[0].len();
        if rows.iter().any(|row| row.len() != column_count) {
            return Err(CircleFriError::FriBatchShapeInvalid);
        }
        Ok(Self { log_size, rows })
    }

    /// Exact equalized column count.
    pub fn column_count(&self) -> usize {
        self.rows[0].len()
    }
}

/// Batched circle domains and every inserted fold layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriCascade {
    /// Strictly descending input-domain logs; gaps are permitted.
    pub domain_log_sizes: Vec<u8>,
    /// Every fold-round circle log from the largest through the smallest input domain.
    pub fold_log_sizes: Vec<u8>,
    /// Number of functions batched at each input domain.
    pub batch_column_counts: Vec<usize>,
    /// Global batching-challenge exponent offset for each input domain.
    pub batch_power_offsets: Vec<usize>,
    /// Independent mask values committed before the batching challenge.
    pub batch_masks: Vec<Vec<Fp16>>,
    /// One random linear combination per input domain.
    pub batched_domains: Vec<Vec<Fp16>>,
    /// One unnormalized folding-with-insertion output per fold round.
    pub folded_layers: Vec<Vec<Fp16>>,
    /// Shared cross-domain batching coefficient.
    pub batch_coefficient: Fp16,
    /// One coefficient for each folding round.
    pub fold_coefficients: Vec<Fp16>,
}

impl FriCascade {
    /// Final plain line evaluation after the smallest attached domain is folded.
    pub fn final_line_evaluation(&self) -> &[Fp16] {
        &self.folded_layers[self.folded_layers.len() - 1]
    }
}

/// Batch one authenticated row with its independently committed mask.
pub fn batch_row(row: &[Fp16], mask: Fp16, coefficient: Fp16, power_offset: usize) -> Fp16 {
    let mut result = mask;
    let mut power = Fp16::ONE;
    for _ in 0..=power_offset {
        power = power.mul(coefficient);
    }
    for value in row {
        result = result.add(power.mul(*value));
        power = power.mul(coefficient);
    }
    result
}

/// Apply the typed BL-PQ512 multi-domain batching and folding schedule.
pub fn build_fri_cascade(
    batches: &[FriDomainBatch],
    batch_masks: &[FriDomainBatch],
    batch_coefficient: Fp16,
    fold_coefficients: &[Fp16],
) -> Result<FriCascade, CircleFriError> {
    if batches.is_empty() {
        return Err(CircleFriError::FriChallengeCountMismatch);
    }
    if batch_masks.len() != batches.len() {
        return Err(CircleFriError::FriBatchMaskCountMismatch);
    }
    for (index, batch) in batches.iter().enumerate() {
        FriDomainBatch::new(batch.log_size, batch.rows.clone())?;
        let mask = &batch_masks[index];
        FriDomainBatch::new(mask.log_size, mask.rows.clone())?;
        if mask.log_size != batch.log_size || mask.column_count() != 1 {
            return Err(CircleFriError::FriBatchMaskShapeMismatch);
        }
        if index != 0 && batches[index - 1].log_size <= batch.log_size {
            return Err(CircleFriError::FriDomainsNotStrictlyDescending);
        }
    }

    let first_log_size = batches[0].log_size;
    let last_input_log_size = batches[batches.len() - 1].log_size;
    let minimum_fold_count = usize::from(first_log_size - last_input_log_size + 1);
    if fold_coefficients.len() < minimum_fold_count
        || fold_coefficients.len() >= usize::from(first_log_size)
    {
        return Err(CircleFriError::FriChallengeCountMismatch);
    }
    let final_fold_log_size = first_log_size + 1 - fold_coefficients.len() as u8;
    let fold_log_sizes = (final_fold_log_size..=first_log_size)
        .rev()
        .collect::<Vec<_>>();

    let batch_column_counts = batches
        .iter()
        .map(FriDomainBatch::column_count)
        .collect::<Vec<_>>();
    let mut next_power_offset = 0_usize;
    let batch_power_offsets = batch_column_counts
        .iter()
        .map(|column_count| {
            let current = next_power_offset;
            next_power_offset += column_count;
            current
        })
        .collect::<Vec<_>>();

    let mut mask_domains = Vec::with_capacity(batches.len());
    let mut batched_domains = Vec::with_capacity(batches.len());
    for ((batch, mask_batch), power_offset) in
        batches.iter().zip(batch_masks).zip(&batch_power_offsets)
    {
        let mask = mask_batch.rows.iter().map(|row| row[0]).collect::<Vec<_>>();
        let batched = batch
            .rows
            .iter()
            .zip(&mask)
            .map(|(row, mask_value)| batch_row(row, *mask_value, batch_coefficient, *power_offset))
            .collect::<Vec<_>>();
        mask_domains.push(mask);
        batched_domains.push(batched);
    }

    let mut folded_layers = Vec::with_capacity(fold_log_sizes.len());
    let mut previous: Option<Vec<Fp16>> = None;
    for (fold_log_size, fold_coefficient) in fold_log_sizes.iter().zip(fold_coefficients) {
        let batch_index = batches
            .iter()
            .position(|batch| batch.log_size == *fold_log_size);
        let folded_previous = previous
            .as_ref()
            .map(|values| fold_line(values, *fold_coefficient))
            .transpose()?;
        let current = if let Some(index) = batch_index {
            let folded_batch = fold_circle_into_line(&batched_domains[index], *fold_coefficient)?;
            if let Some(folded_previous_values) = folded_previous {
                if folded_previous_values.len() != folded_batch.len() {
                    return Err(CircleFriError::FriPreviousLayerDomainMismatch);
                }
                let coefficient_squared = fold_coefficient.square();
                folded_previous_values
                    .into_iter()
                    .zip(folded_batch)
                    .map(|(prior, added)| coefficient_squared.mul(prior).add(added))
                    .collect()
            } else {
                // The largest attached domain is not pointlessly scaled by
                // alpha^2. This is the fail-safer S-two source ordering.
                folded_batch
            }
        } else {
            folded_previous.ok_or(CircleFriError::FriPreviousLayerDomainMismatch)?
        };
        folded_layers.push(current.clone());
        previous = Some(current);
    }
    Ok(FriCascade {
        domain_log_sizes: batches.iter().map(|batch| batch.log_size).collect(),
        fold_log_sizes,
        batch_column_counts,
        batch_power_offsets,
        batch_masks: mask_domains,
        batched_domains,
        folded_layers,
        batch_coefficient,
        fold_coefficients: fold_coefficients.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oods::{OodsParameter, stereographic_circle_point};
    use alloc::vec;

    fn fp16(value: u32) -> Fp16 {
        Fp16::from_coefficients([value, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap()
    }

    fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
        assert_eq!(value.len(), N * 2);
        let mut result = [0_u8; N];
        for (index, byte) in result.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
        }
        result
    }

    #[test]
    fn generator_and_domains_are_valid() {
        assert!(BaseCirclePoint::generator().is_on_circle());
        assert_eq!(
            BaseCirclePoint::generator().multiply(1_usize << M31_CIRCLE_LOG_ORDER),
            BaseCirclePoint::IDENTITY
        );
        for log_size in 2..=12 {
            let size = 1_usize << log_size;
            let step = circle_domain_step(log_size).unwrap();
            for index in 0..size {
                let point = canonic_circle_point(log_size, index).unwrap();
                assert!(point.is_on_circle());
                assert_eq!(
                    point,
                    canonic_circle_point(log_size, index ^ (size >> 1))
                        .unwrap()
                        .conjugate()
                );
                if index + 1 < (size >> 1) {
                    assert_eq!(
                        point.add(step),
                        canonic_circle_point(log_size, index + 1).unwrap()
                    );
                }
            }
        }
    }

    #[test]
    fn fold_shapes_and_constant_polynomial_hold() {
        let values = vec![Fp16::ONE; 16];
        let alpha = fp16(7);
        assert_eq!(
            fold_circle_into_line(&values, alpha).unwrap(),
            vec![fp16(2); 8]
        );
        assert_eq!(
            fold_circle_layer(&values, alpha, 3).unwrap(),
            vec![fp16(8); 2]
        );
    }

    #[test]
    fn fold_recovers_even_and_odd_linear_parts() {
        let log_size = 5;
        let alpha = fp16(7);
        let values = (0..1_usize << log_size)
            .map(|bit_reversed_index| {
                let natural_index = bit_reverse_index(bit_reversed_index, log_size).unwrap();
                let point = canonic_circle_point(log_size, natural_index).unwrap();
                fp16(
                    M31::from_canonical(3)
                        .unwrap()
                        .add(point.y.mul(M31::from_canonical(5).unwrap()))
                        .as_u32(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            fold_circle_into_line(&values, alpha).unwrap(),
            vec![fp16(2 * (3 + 7 * 5)); 1 << (log_size - 1)]
        );
    }

    #[test]
    fn python_nontrivial_fold_kat_matches() {
        let alpha =
            Fp16::from_coefficients([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
                .unwrap();
        let values = (0_u32..16)
            .map(|row| {
                let mut coefficients = [0_u32; 16];
                for (index, coefficient) in coefficients.iter_mut().enumerate() {
                    *coefficient = row * 17 + index as u32;
                }
                Fp16::from_coefficients(coefficients).unwrap()
            })
            .collect::<Vec<_>>();
        let folded = fold_circle_layer(&values, alpha, 3).unwrap();
        assert_eq!(folded.len(), 2);
        assert_eq!(
            folded[0].encode(),
            decode_hex::<64>(
                "097ed1dc3a42c8a13a44721b6f2360534881c04f649abc715261f41e2bafc942\
                 4ff4224726ef9b8d2932291d2edd6bab4541311b514f0584369194074208f2b8"
                    .replace(' ', "")
                    .as_str()
            )
        );
        assert_eq!(
            folded[1].encode(),
            decode_hex::<64>(
                "2ac12bdd24ef586746b4ec1462d3bf2b75f71775115b4c831ade0d0b76e75e23\
                 4c57464142869f891df14d4b5b0db4665f2f8aa74e1b75f824a56856334eb169"
                    .replace(' ', "")
                    .as_str()
            )
        );
    }

    #[test]
    fn malformed_fold_requests_fail_closed() {
        assert!(matches!(
            fold_circle_into_line(&[Fp16::ONE; 3], Fp16::ONE),
            Err(CircleFriError::EvaluationSizeInvalid { size: 3 })
        ));
        assert!(matches!(
            fold_circle_layer(&[Fp16::ONE; 4], Fp16::ONE, 3),
            Err(CircleFriError::FoldCountInvalid { .. })
        ));
    }

    #[test]
    fn degree_corrected_rows_test_original_and_quotient_together() {
        let parameter = OodsParameter::try_from_element(
            Fp16::from_coefficients([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
        )
        .unwrap();
        let query = stereographic_circle_point(parameter).unwrap();
        let domain_point = canonic_circle_point(5, 7).unwrap();
        let a = fp16(3);
        let b = fp16(5);
        let c = fp16(11);
        let original = a
            .add(b.mul(Fp16::from_m31(domain_point.x)))
            .add(c.mul(Fp16::from_m31(domain_point.y)));
        let claim = a.add(b.mul(query.x)).add(c.mul(query.y));
        let row = degree_corrected_row(
            domain_point,
            query,
            &[original],
            &[claim],
            &[claim.conjugate()],
        )
        .unwrap();
        let zeroifier = conjugate_pair_zeroifier(domain_point, query).unwrap();
        assert_eq!(domain_point.x.as_u32(), 280_947_147);
        assert_eq!(domain_point.y.as_u32(), 1_133_522_282);
        assert_eq!(
            zeroifier.encode(),
            decode_hex::<64>(
                "0000000000000000000000000000000000000000000000000000000000000000\
                 7d98644349b7efe87d24be7d50f10d1f3f988287076e173936ba15ae04e74137"
                    .replace(' ', "")
                    .as_str()
            )
        );
        assert_eq!(
            row.quotient_values[0].encode(),
            decode_hex::<64>(
                "7ffffffa00000000000000000000000000000000000000000000000000000000\
                 0000000000000000000000000000000000000000000000000000000000000000"
                    .replace(' ', "")
                    .as_str()
            )
        );
        assert_eq!(row.original_values, vec![original]);
        assert_eq!(row.quotient_values.len(), 1);
        assert!(
            verify_degree_corrected_row(domain_point, query, &row, &[claim], &[claim.conjugate()],)
                .unwrap()
        );
        let mut tampered = row.clone();
        tampered.quotient_values[0] = tampered.quotient_values[0].add(Fp16::ONE);
        assert!(
            !verify_degree_corrected_row(
                domain_point,
                query,
                &tampered,
                &[claim],
                &[claim.conjugate()],
            )
            .unwrap()
        );
        assert_eq!(
            row.fri_batch_values(),
            vec![original, row.quotient_values[0]]
        );
    }

    #[test]
    fn fixed_subfield_oods_query_and_bad_column_shapes_fail_closed() {
        let fixed_query = CirclePoint {
            x: Fp16::ONE,
            y: Fp16::ZERO,
        };
        assert_eq!(
            conjugate_pair_zeroifier(BaseCirclePoint::IDENTITY, fixed_query),
            Err(CircleFriError::OodsQueryInFixedSubfield)
        );
        let parameter = OodsParameter::try_from_element(
            Fp16::from_coefficients([0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
        )
        .unwrap();
        let query = stereographic_circle_point(parameter).unwrap();
        assert_eq!(
            degree_corrected_row(BaseCirclePoint::IDENTITY, query, &[], &[], &[]),
            Err(CircleFriError::DegreeCorrectedColumnCountMismatch)
        );
    }

    #[test]
    fn conjugate_claim_line_falls_back_to_x_when_y_is_fixed() {
        let w = Fp16::from_coefficients([0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let parameter_element = Fp16::ONE.add(w).mul(Fp16::ONE.sub(w).inverse().unwrap());
        let parameter = OodsParameter::try_from_element(parameter_element).unwrap();
        let query = stereographic_circle_point(parameter).unwrap();
        assert_eq!(query.y, query.y.conjugate());
        assert_ne!(query.x, query.x.conjugate());

        let domain_point = canonic_circle_point(5, 3).unwrap();
        let original = fp16(71);
        let claim = Fp16::from_coefficients([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
            .unwrap();
        let row = degree_corrected_row(
            domain_point,
            query,
            &[original],
            &[claim],
            &[claim.conjugate()],
        )
        .unwrap();
        assert!(
            verify_degree_corrected_row(domain_point, query, &row, &[claim], &[claim.conjugate()],)
                .unwrap()
        );
    }

    #[test]
    fn extension_function_second_query_claim_is_never_inferred() {
        let parameter = OodsParameter::try_from_element(
            Fp16::from_coefficients([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
        )
        .unwrap();
        let query = stereographic_circle_point(parameter).unwrap();
        let domain_point = canonic_circle_point(5, 9).unwrap();
        let original = fp16(37);
        let claim =
            Fp16::from_coefficients([1, 3, 5, 7, 9, 11, 13, 15, 2, 4, 6, 8, 10, 12, 14, 16])
                .unwrap();
        let explicit_second_claim = claim.conjugate().add(fp16(29));
        assert_ne!(explicit_second_claim, claim.conjugate());

        let row = degree_corrected_row(
            domain_point,
            query,
            &[original],
            &[claim],
            &[explicit_second_claim],
        )
        .unwrap();

        assert!(
            verify_degree_corrected_row(
                domain_point,
                query,
                &row,
                &[claim],
                &[explicit_second_claim],
            )
            .unwrap()
        );
        assert!(!verify_degree_corrected_row(
            domain_point,
            query,
            &row,
            &[claim],
            &[claim.conjugate()],
        )
        .unwrap());
    }

    #[test]
    fn multi_domain_batching_and_insertion_hold_on_constants() {
        let large = FriDomainBatch::new(4, vec![vec![fp16(2), fp16(11)]; 16]).unwrap();
        let small = FriDomainBatch::new(3, vec![vec![fp16(13), fp16(17)]; 8]).unwrap();
        let large_mask = FriDomainBatch::new(4, vec![vec![fp16(19)]; 16]).unwrap();
        let small_mask = FriDomainBatch::new(3, vec![vec![fp16(23)]; 8]).unwrap();
        let cascade = build_fri_cascade(
            &[large, small],
            &[large_mask, small_mask],
            fp16(3),
            &[fp16(5), fp16(7)],
        )
        .unwrap();
        let first_batched = 19 + 3 * 2 + 3_u32.pow(2) * 11;
        let second_batched = 23 + 3_u32.pow(3) * 13 + 3_u32.pow(4) * 17;
        let first_folded = 2 * first_batched;
        let second_folded = 7_u32.pow(2) * 2 * first_folded + 2 * second_batched;
        assert_eq!(cascade.batched_domains[0], vec![fp16(first_batched); 16]);
        assert_eq!(cascade.batched_domains[1], vec![fp16(second_batched); 8]);
        assert_eq!(cascade.batch_masks[0], vec![fp16(19); 16]);
        assert_eq!(cascade.batch_masks[1], vec![fp16(23); 8]);
        assert_eq!(cascade.domain_log_sizes, vec![4, 3]);
        assert_eq!(cascade.fold_log_sizes, vec![4, 3]);
        assert_eq!(cascade.batch_column_counts, vec![2, 2]);
        assert_eq!(cascade.batch_power_offsets, vec![0, 2]);
        assert_eq!(cascade.folded_layers[0], vec![fp16(first_folded); 8]);
        assert_eq!(cascade.folded_layers[1], vec![fp16(second_folded); 4]);
        assert_eq!(cascade.final_line_evaluation(), &[fp16(second_folded); 4]);
    }

    #[test]
    fn multi_domain_gaps_and_varying_widths_fold_exactly() {
        let large = FriDomainBatch::new(5, vec![vec![fp16(2), fp16(11)]; 32]).unwrap();
        let small = FriDomainBatch::new(3, vec![vec![fp16(13)]; 8]).unwrap();
        let tiny = FriDomainBatch::new(2, vec![vec![fp16(17), fp16(19), fp16(23)]; 4]).unwrap();
        let large_mask = FriDomainBatch::new(5, vec![vec![fp16(19)]; 32]).unwrap();
        let small_mask = FriDomainBatch::new(3, vec![vec![fp16(23)]; 8]).unwrap();
        let tiny_mask = FriDomainBatch::new(2, vec![vec![fp16(29)]; 4]).unwrap();
        let cascade = build_fri_cascade(
            &[large, small, tiny],
            &[large_mask, small_mask, tiny_mask],
            fp16(3),
            &[fp16(5), fp16(7), fp16(11), fp16(13)],
        )
        .unwrap();

        let first_batched = 19 + 3 * 2 + 3_u32.pow(2) * 11;
        let second_batched = 23 + 3_u32.pow(3) * 13;
        let third_batched = 29 + 3_u32.pow(4) * 17 + 3_u32.pow(5) * 19 + 3_u32.pow(6) * 23;
        let first_folded = 2 * first_batched;
        let gap_folded = 2 * first_folded;
        let second_folded = 11_u32.pow(2) * 2 * gap_folded + 2 * second_batched;
        let third_folded = 13_u32.pow(2) * 2 * second_folded + 2 * third_batched;

        assert_eq!(cascade.domain_log_sizes, vec![5, 3, 2]);
        assert_eq!(cascade.fold_log_sizes, vec![5, 4, 3, 2]);
        assert_eq!(cascade.batch_column_counts, vec![2, 1, 3]);
        assert_eq!(cascade.batch_power_offsets, vec![0, 2, 3]);
        assert_eq!(cascade.batched_domains[0], vec![fp16(first_batched); 32]);
        assert_eq!(cascade.batched_domains[1], vec![fp16(second_batched); 8]);
        assert_eq!(cascade.batched_domains[2], vec![fp16(third_batched); 4]);
        assert_eq!(
            cascade
                .folded_layers
                .iter()
                .map(Vec::len)
                .collect::<Vec<_>>(),
            vec![16, 8, 4, 2]
        );
        assert_eq!(cascade.folded_layers[0], vec![fp16(first_folded); 16]);
        assert_eq!(cascade.folded_layers[1], vec![fp16(gap_folded); 8]);
        assert_eq!(cascade.folded_layers[2], vec![fp16(second_folded); 4]);
        assert_eq!(cascade.folded_layers[3], vec![fp16(third_folded); 2]);
        assert_eq!(cascade.final_line_evaluation(), &[fp16(third_folded); 2]);
    }

    #[test]
    fn malformed_multi_domain_cascades_fail_closed() {
        let large = FriDomainBatch::new(4, vec![vec![fp16(1), fp16(2)]; 16]).unwrap();
        let skipped = FriDomainBatch::new(2, vec![vec![fp16(3), fp16(4)]; 4]).unwrap();
        let large_mask = FriDomainBatch::new(4, vec![vec![fp16(13)]; 16]).unwrap();
        let skipped_mask = FriDomainBatch::new(2, vec![vec![fp16(19)]; 4]).unwrap();
        assert_eq!(
            build_fri_cascade(
                &[skipped.clone(), large.clone()],
                &[skipped_mask.clone(), large_mask.clone()],
                fp16(5),
                &[fp16(7), fp16(11), fp16(13)]
            ),
            Err(CircleFriError::FriDomainsNotStrictlyDescending)
        );
        assert_eq!(
            build_fri_cascade(
                &[large.clone(), skipped],
                &[large_mask.clone(), skipped_mask],
                fp16(5),
                &[fp16(7), fp16(11)],
            ),
            Err(CircleFriError::FriChallengeCountMismatch)
        );
        assert_eq!(
            build_fri_cascade(core::slice::from_ref(&large), &[], fp16(5), &[fp16(7)],),
            Err(CircleFriError::FriBatchMaskCountMismatch)
        );
        let wide_mask = FriDomainBatch::new(4, vec![vec![fp16(1), fp16(2)]; 16]).unwrap();
        assert_eq!(
            build_fri_cascade(&[large], &[wide_mask], fp16(5), &[fp16(7)]),
            Err(CircleFriError::FriBatchMaskShapeMismatch)
        );
    }
}
