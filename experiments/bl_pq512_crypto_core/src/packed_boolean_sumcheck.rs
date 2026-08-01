//! `B=8` packed first-round reduction for data-parallel Boolean GKR.
//!
//! Eight privacy-padded circuit shards are packed into each `u8`. The
//! witness-independent interpolation/product table remains in M31; only
//! authenticated random weights and output coefficients occupy Fp16.

use core::fmt;

use alloc::{vec, vec::Vec};

use crate::field::{Fp16, M31, M31_MODULUS};

pub const PACK_BITS: usize = 8;
pub const MASK_COUNT: usize = 1 << PACK_BITS;
pub const PRODUCT_COUNT: usize = MASK_COUNT * MASK_COUNT;
pub const MASK_COEFFICIENTS: usize = PACK_BITS;
pub const PRODUCT_COEFFICIENTS: usize = 2 * PACK_BITS - 1;
pub const OUTPUT_COEFFICIENTS: usize = 3 * PACK_BITS;

pub type PackedBooleanCanonicalCoordinates = (Vec<[u32; 16]>, Vec<[u32; 16]>, Vec<[u32; 16]>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackedBooleanGate {
    And,
    Xor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackedBooleanError {
    Empty,
    Shape,
    Interpolation,
    WorkerCount,
    WorkerPanicked,
    AccumulatorShape,
    AccumulatorNonCanonical,
    Degree,
    Claim,
    SelectorZero,
}

impl fmt::Display for PackedBooleanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "packed Boolean sumcheck error: {self:?}")
    }
}

impl core::error::Error for PackedBooleanError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackedReductionReport {
    pub gates: usize,
    pub nonzero_product_buckets: usize,
    pub table_bytes: usize,
    pub accumulator_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackedFirstRoundBridge {
    pub gate_claim: Fp16,
    pub selector_at_challenge: Fp16,
}

pub struct PackedBooleanTable {
    mask_polynomials: [[M31; MASK_COEFFICIENTS]; MASK_COUNT],
    product_polynomials: Vec<[M31; PRODUCT_COEFFICIENTS]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackedBooleanAccumulators {
    product: Vec<Fp16>,
    left: [Fp16; MASK_COUNT],
    right: [Fp16; MASK_COUNT],
    gates: usize,
}

impl PackedBooleanAccumulators {
    fn zero() -> Self {
        Self {
            product: vec![Fp16::ZERO; PRODUCT_COUNT],
            left: [Fp16::ZERO; MASK_COUNT],
            right: [Fp16::ZERO; MASK_COUNT],
            gates: 0,
        }
    }

    fn add_gate(
        &mut self,
        gate: PackedBooleanGate,
        left: u8,
        right: u8,
        weight: Fp16,
    ) -> Result<(), PackedBooleanError> {
        self.gates = self.gates.checked_add(1).ok_or(PackedBooleanError::Shape)?;
        let product_index = usize::from(left) * MASK_COUNT + usize::from(right);
        match gate {
            PackedBooleanGate::And => {
                self.product[product_index] = self.product[product_index] + weight;
            }
            PackedBooleanGate::Xor => {
                self.product[product_index] = self.product[product_index] - weight - weight;
                self.left[usize::from(left)] = self.left[usize::from(left)] + weight;
                self.right[usize::from(right)] = self.right[usize::from(right)] + weight;
            }
        }
        Ok(())
    }

    #[cfg(feature = "parallel")]
    fn merge(&mut self, other: Self) -> Result<(), PackedBooleanError> {
        self.gates = self
            .gates
            .checked_add(other.gates)
            .ok_or(PackedBooleanError::Shape)?;
        for (target, value) in self.product.iter_mut().zip(other.product) {
            *target = *target + value;
        }
        for (target, value) in self.left.iter_mut().zip(other.left) {
            *target = *target + value;
        }
        for (target, value) in self.right.iter_mut().zip(other.right) {
            *target = *target + value;
        }
        Ok(())
    }

    /// Import canonical device-produced accumulator coordinates.
    ///
    /// The device is not trusted: every M31 coordinate and all public shapes
    /// are checked before the existing CPU finalizer consumes the values.
    pub fn from_canonical_coordinates(
        product: &[[u32; 16]],
        left: &[[u32; 16]],
        right: &[[u32; 16]],
        gates: usize,
    ) -> Result<Self, PackedBooleanError> {
        if gates == 0 {
            return Err(PackedBooleanError::Empty);
        }
        if product.len() != PRODUCT_COUNT || left.len() != MASK_COUNT || right.len() != MASK_COUNT {
            return Err(PackedBooleanError::AccumulatorShape);
        }
        fn decode(values: &[[u32; 16]]) -> Result<Vec<Fp16>, PackedBooleanError> {
            values
                .iter()
                .copied()
                .map(|coordinates| {
                    if coordinates
                        .iter()
                        .any(|coordinate| *coordinate >= M31_MODULUS)
                    {
                        return Err(PackedBooleanError::AccumulatorNonCanonical);
                    }
                    Fp16::from_coefficients(coordinates)
                        .map_err(|_| PackedBooleanError::AccumulatorNonCanonical)
                })
                .collect()
        }
        let product = decode(product)?;
        let left = decode(left)?
            .try_into()
            .map_err(|_| PackedBooleanError::AccumulatorShape)?;
        let right = decode(right)?
            .try_into()
            .map_err(|_| PackedBooleanError::AccumulatorShape)?;
        Ok(Self {
            product,
            left,
            right,
            gates,
        })
    }

    /// Return the exact canonical coordinates used by a differential backend.
    pub fn canonical_coordinates(&self) -> PackedBooleanCanonicalCoordinates {
        (
            self.product
                .iter()
                .map(|value| value.coefficients())
                .collect(),
            self.left.iter().map(|value| value.coefficients()).collect(),
            self.right
                .iter()
                .map(|value| value.coefficients())
                .collect(),
        )
    }
}

fn m31(value: usize) -> M31 {
    M31::from_canonical(value as u32).expect("B=8 interpolation point is canonical")
}

fn polynomial_mul_m31<const L: usize, const R: usize, const O: usize>(
    left: &[M31; L],
    right: &[M31; R],
) -> [M31; O] {
    let mut output = [M31::ZERO; O];
    for (left_index, left_value) in left.iter().copied().enumerate() {
        for (right_index, right_value) in right.iter().copied().enumerate() {
            output[left_index + right_index] =
                output[left_index + right_index] + left_value * right_value;
        }
    }
    output
}

fn lagrange_basis_m31() -> Result<[[M31; PACK_BITS]; PACK_BITS], PackedBooleanError> {
    let mut basis = [[M31::ZERO; PACK_BITS]; PACK_BITS];
    for (point, basis_polynomial) in basis.iter_mut().enumerate() {
        let mut polynomial = [M31::ZERO; PACK_BITS];
        polynomial[0] = M31::ONE;
        let mut degree = 0;
        let mut denominator = M31::ONE;
        for other in 0..PACK_BITS {
            if other == point {
                continue;
            }
            let root = m31(other);
            for coefficient in (0..=degree).rev() {
                polynomial[coefficient + 1] = polynomial[coefficient + 1] + polynomial[coefficient];
                polynomial[coefficient] = polynomial[coefficient] * -root;
            }
            degree += 1;
            denominator = denominator * (m31(point) - root);
        }
        let inverse = denominator
            .inverse()
            .map_err(|_| PackedBooleanError::Interpolation)?;
        for coefficient in &mut polynomial {
            *coefficient = *coefficient * inverse;
        }
        *basis_polynomial = polynomial;
    }
    Ok(basis)
}

impl PackedBooleanTable {
    pub fn build() -> Result<Self, PackedBooleanError> {
        let basis = lagrange_basis_m31()?;
        let mask_polynomials = core::array::from_fn(|mask| {
            let mut polynomial = [M31::ZERO; MASK_COEFFICIENTS];
            for (point, basis_polynomial) in basis.iter().enumerate() {
                if (mask >> point) & 1 == 1 {
                    for (coefficient, basis_coefficient) in
                        polynomial.iter_mut().zip(*basis_polynomial)
                    {
                        *coefficient = *coefficient + basis_coefficient;
                    }
                }
            }
            polynomial
        });
        let mut product_polynomials = vec![[M31::ZERO; PRODUCT_COEFFICIENTS]; PRODUCT_COUNT];
        for left in 0..MASK_COUNT {
            for right in 0..MASK_COUNT {
                product_polynomials[left * MASK_COUNT + right] = polynomial_mul_m31::<
                    MASK_COEFFICIENTS,
                    MASK_COEFFICIENTS,
                    PRODUCT_COEFFICIENTS,
                >(
                    &mask_polynomials[left],
                    &mask_polynomials[right],
                );
            }
        }
        Ok(Self {
            mask_polynomials,
            product_polynomials,
        })
    }

    pub const fn table_bytes(&self) -> usize {
        core::mem::size_of::<[[M31; MASK_COEFFICIENTS]; MASK_COUNT]>()
            + PRODUCT_COUNT * core::mem::size_of::<[M31; PRODUCT_COEFFICIENTS]>()
    }
}

fn lagrange_node_evaluations(query: Fp16) -> Result<[Fp16; PACK_BITS], PackedBooleanError> {
    let mut evaluations = [Fp16::ZERO; PACK_BITS];
    for (point, evaluation) in evaluations.iter_mut().enumerate() {
        let mut numerator = Fp16::ONE;
        let mut denominator = M31::ONE;
        for other in 0..PACK_BITS {
            if other == point {
                continue;
            }
            numerator = numerator * (query - Fp16::from_m31(m31(other)));
            denominator = denominator * (m31(point) - m31(other));
        }
        *evaluation = numerator.mul_by_m31(
            denominator
                .inverse()
                .map_err(|_| PackedBooleanError::Interpolation)?,
        );
    }
    Ok(evaluations)
}

pub fn packed_lagrange_node_weights(query: Fp16) -> Result<[Fp16; PACK_BITS], PackedBooleanError> {
    lagrange_node_evaluations(query)
}

fn lagrange_query_polynomial(
    query: Fp16,
    basis: &[[M31; PACK_BITS]; PACK_BITS],
) -> Result<[Fp16; PACK_BITS], PackedBooleanError> {
    let evaluations = lagrange_node_evaluations(query)?;
    let mut polynomial = [Fp16::ZERO; PACK_BITS];
    for (evaluation, basis_polynomial) in evaluations.into_iter().zip(basis) {
        for (coefficient, basis_coefficient) in polynomial.iter_mut().zip(basis_polynomial) {
            *coefficient = *coefficient + evaluation.mul_by_m31(*basis_coefficient);
        }
    }
    Ok(polynomial)
}

/// Coefficients of the packed bridge selector
/// `sum_i L_i(query) L_i(t)` over the eight fixed shard nodes.
pub fn packed_selector_polynomial(query: Fp16) -> Result<[Fp16; PACK_BITS], PackedBooleanError> {
    lagrange_query_polynomial(query, &lagrange_basis_m31()?)
}

pub fn evaluate_packed_lagrange_values(
    values: &[Fp16; PACK_BITS],
    point: Fp16,
) -> Result<Fp16, PackedBooleanError> {
    Ok(values
        .iter()
        .copied()
        .zip(lagrange_node_evaluations(point)?)
        .fold(Fp16::ZERO, |sum, (value, weight)| sum + value * weight))
}

/// Produce the degree-at-most-21 first packed-round polynomial.
pub fn reduce_packed_boolean_layer(
    table: &PackedBooleanTable,
    gates: &[PackedBooleanGate],
    left_words: &[u8],
    right_words: &[u8],
    equality_weights: &[Fp16],
    shard_query: Fp16,
) -> Result<([Fp16; OUTPUT_COEFFICIENTS], PackedReductionReport), PackedBooleanError> {
    if gates.len() != left_words.len()
        || gates.len() != right_words.len()
        || gates.len() != equality_weights.len()
    {
        return Err(PackedBooleanError::Shape);
    }

    reduce_packed_boolean_stream(
        table,
        gates
            .iter()
            .copied()
            .zip(left_words.iter().copied())
            .zip(right_words.iter().copied())
            .zip(equality_weights.iter().copied())
            .map(|(((gate, left), right), weight)| (gate, left, right, weight)),
        shard_query,
    )
}

/// Streaming form that never materializes a layer-sized Fp16 weight vector.
pub fn reduce_packed_boolean_stream(
    table: &PackedBooleanTable,
    gates: impl IntoIterator<Item = (PackedBooleanGate, u8, u8, Fp16)>,
    shard_query: Fp16,
) -> Result<([Fp16; OUTPUT_COEFFICIENTS], PackedReductionReport), PackedBooleanError> {
    let mut accumulators = PackedBooleanAccumulators::zero();
    for (gate, left, right, weight) in gates {
        accumulators.add_gate(gate, left, right, weight)?;
    }
    finish_packed_boolean_accumulators(table, accumulators, shard_query)
}

/// Deterministic indexed parallel form with private worker accumulators.
///
/// Gate ranges depend only on `gate_count` and `worker_count`. Results are
/// merged in ascending worker order, independent of thread scheduling.
#[cfg(feature = "parallel")]
pub fn reduce_packed_boolean_indexed_parallel<F>(
    table: &PackedBooleanTable,
    gate_count: usize,
    worker_count: usize,
    gate_at: F,
    shard_query: Fp16,
) -> Result<([Fp16; OUTPUT_COEFFICIENTS], PackedReductionReport), PackedBooleanError>
where
    F: Fn(usize) -> (PackedBooleanGate, u8, u8, Fp16) + Sync,
{
    if gate_count == 0 {
        return Err(PackedBooleanError::Empty);
    }
    if worker_count == 0 || worker_count > 256 {
        return Err(PackedBooleanError::WorkerCount);
    }
    let active_workers = worker_count.min(gate_count);
    let chunk = gate_count
        .checked_add(active_workers - 1)
        .ok_or(PackedBooleanError::Shape)?
        / active_workers;
    let accumulators = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(active_workers);
        for worker in 0..active_workers {
            let start = worker * chunk;
            let end = gate_count.min(start.saturating_add(chunk));
            let gate_at = &gate_at;
            handles.push(scope.spawn(move || {
                let mut local = PackedBooleanAccumulators::zero();
                for index in start..end {
                    let (gate, left, right, weight) = gate_at(index);
                    local.add_gate(gate, left, right, weight)?;
                }
                Ok::<_, PackedBooleanError>(local)
            }));
        }
        let mut merged = PackedBooleanAccumulators::zero();
        for handle in handles {
            let local = handle
                .join()
                .map_err(|_| PackedBooleanError::WorkerPanicked)??;
            merged.merge(local)?;
        }
        Ok::<_, PackedBooleanError>(merged)
    })?;
    finish_packed_boolean_accumulators(table, accumulators, shard_query)
}

/// Finalize a checked CPU or device-produced accumulator identically.
pub fn finish_packed_boolean_accumulators(
    table: &PackedBooleanTable,
    accumulators: PackedBooleanAccumulators,
    shard_query: Fp16,
) -> Result<([Fp16; OUTPUT_COEFFICIENTS], PackedReductionReport), PackedBooleanError> {
    if accumulators.gates == 0 {
        return Err(PackedBooleanError::Empty);
    }
    let mut combined = [Fp16::ZERO; PRODUCT_COEFFICIENTS];
    let mut nonzero_product_buckets = 0;
    for (weight, polynomial) in accumulators
        .product
        .iter()
        .copied()
        .zip(&table.product_polynomials)
    {
        if weight.is_zero() {
            continue;
        }
        nonzero_product_buckets += 1;
        for (coefficient, subfield_coefficient) in combined.iter_mut().zip(polynomial) {
            *coefficient = *coefficient + weight.mul_by_m31(*subfield_coefficient);
        }
    }
    for (weight, polynomial) in accumulators
        .left
        .into_iter()
        .zip(&table.mask_polynomials)
        .chain(accumulators.right.into_iter().zip(&table.mask_polynomials))
    {
        if weight.is_zero() {
            continue;
        }
        for (coefficient, subfield_coefficient) in combined.iter_mut().zip(polynomial) {
            *coefficient = *coefficient + weight.mul_by_m31(*subfield_coefficient);
        }
    }

    finish_packed_boolean_combined(
        combined,
        shard_query,
        accumulators.gates,
        nonzero_product_buckets,
        table.table_bytes(),
    )
}

/// Finish canonical combined degree-14 coefficients produced by an untrusted
/// accelerator. The verifier still checks the resulting packed bridge and all
/// following sparse rounds; the accelerator never supplies a challenge.
pub fn finish_packed_boolean_combined(
    combined: [Fp16; PRODUCT_COEFFICIENTS],
    shard_query: Fp16,
    gates: usize,
    nonzero_product_buckets: usize,
    table_bytes: usize,
) -> Result<([Fp16; OUTPUT_COEFFICIENTS], PackedReductionReport), PackedBooleanError> {
    if gates == 0 || nonzero_product_buckets > PRODUCT_COUNT {
        return Err(PackedBooleanError::AccumulatorShape);
    }
    let basis = lagrange_basis_m31()?;
    let query_polynomial = lagrange_query_polynomial(shard_query, &basis)?;
    let mut output = [Fp16::ZERO; OUTPUT_COEFFICIENTS];
    for (left_index, left) in combined.into_iter().enumerate() {
        for (right_index, right) in query_polynomial.iter().copied().enumerate() {
            output[left_index + right_index] = output[left_index + right_index] + left * right;
        }
    }
    Ok((
        output,
        PackedReductionReport {
            gates,
            nonzero_product_buckets,
            table_bytes,
            accumulator_bytes: PRODUCT_COUNT * core::mem::size_of::<Fp16>()
                + 2 * MASK_COUNT * core::mem::size_of::<Fp16>(),
        },
    ))
}

pub fn evaluate_packed_polynomial(coefficients: &[Fp16; OUTPUT_COEFFICIENTS], point: Fp16) -> Fp16 {
    coefficients
        .iter()
        .copied()
        .rev()
        .fold(Fp16::ZERO, |value, coefficient| value * point + coefficient)
}

/// Check the degree-21 packed opening move and derive the claim consumed by
/// the sparse adjacent-layer GKR control.
///
/// `bridge_challenge` must be released only after the packed polynomial is
/// committed by the interactive production transcript. This function checks
/// algebra only; it does not itself implement that message/coin schedule.
pub fn verify_packed_first_round_bridge(
    initial_claim: Fp16,
    polynomial: &[Fp16; OUTPUT_COEFFICIENTS],
    shard_query: Fp16,
    bridge_challenge: Fp16,
) -> Result<PackedFirstRoundBridge, PackedBooleanError> {
    if polynomial[OUTPUT_COEFFICIENTS - 2..]
        .iter()
        .any(|coefficient| !coefficient.is_zero())
    {
        return Err(PackedBooleanError::Degree);
    }
    let node_sum = (0..PACK_BITS).fold(Fp16::ZERO, |sum, node| {
        sum + evaluate_packed_polynomial(polynomial, Fp16::from_m31(m31(node)))
    });
    if node_sum != initial_claim {
        return Err(PackedBooleanError::Claim);
    }
    let query_weights = lagrange_node_evaluations(shard_query)?;
    let challenge_weights = lagrange_node_evaluations(bridge_challenge)?;
    let selector_at_challenge = query_weights
        .into_iter()
        .zip(challenge_weights)
        .fold(Fp16::ZERO, |sum, (left, right)| sum + left * right);
    let inverse = selector_at_challenge
        .inverse()
        .map_err(|_| PackedBooleanError::SelectorZero)?;
    Ok(PackedFirstRoundBridge {
        gate_claim: evaluate_packed_polynomial(polynomial, bridge_challenge) * inverse,
        selector_at_challenge,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp16(value: usize) -> Fp16 {
        Fp16::from_m31(m31(value))
    }

    #[test]
    fn subfield_table_and_packed_reduction_match_all_eight_direct_evaluations() {
        let table = PackedBooleanTable::build().unwrap();
        assert_eq!(table.table_bytes(), 3_940_352);
        let gates = [
            PackedBooleanGate::And,
            PackedBooleanGate::Xor,
            PackedBooleanGate::And,
            PackedBooleanGate::Xor,
        ];
        let left = [0b1010_0101, 0b1111_0000, 0b0011_1100, 0b0101_1010];
        let right = [0b1100_0011, 0b1001_0110, 0b1110_0001, 0b0011_0011];
        let weights = [fp16(11), fp16(13), fp16(17), fp16(19)];
        let (polynomial, report) =
            reduce_packed_boolean_layer(&table, &gates, &left, &right, &weights, fp16(29)).unwrap();
        assert_eq!(report.gates, 4);
        assert_eq!(report.accumulator_bytes, 4_227_072);

        let basis = lagrange_basis_m31().unwrap();
        let query_polynomial = lagrange_query_polynomial(fp16(29), &basis).unwrap();
        for shard in 0..PACK_BITS {
            let direct = (0..gates.len()).fold(Fp16::ZERO, |sum, gate| {
                let left_bit = (left[gate] >> shard) & 1;
                let right_bit = (right[gate] >> shard) & 1;
                let value = match gates[gate] {
                    PackedBooleanGate::And => left_bit & right_bit,
                    PackedBooleanGate::Xor => left_bit ^ right_bit,
                };
                sum + weights[gate].mul_by_m31(M31::from_canonical(u32::from(value)).unwrap())
            });
            let query_at_shard = query_polynomial
                .iter()
                .copied()
                .rev()
                .fold(Fp16::ZERO, |value, coefficient| {
                    value * fp16(shard) + coefficient
                });
            assert_eq!(
                evaluate_packed_polynomial(&polynomial, fp16(shard)),
                query_at_shard * direct
            );
        }
    }

    #[test]
    fn malformed_inputs_fail_closed() {
        let table = PackedBooleanTable::build().unwrap();
        assert_eq!(
            reduce_packed_boolean_layer(&table, &[], &[], &[], &[], Fp16::ONE),
            Err(PackedBooleanError::Empty)
        );
        assert_eq!(
            reduce_packed_boolean_layer(
                &table,
                &[PackedBooleanGate::And],
                &[],
                &[0],
                &[Fp16::ONE],
                Fp16::ONE
            ),
            Err(PackedBooleanError::Shape)
        );
    }

    #[test]
    fn canonical_accumulator_import_matches_cpu_and_rejects_malformed_device_output() {
        let table = PackedBooleanTable::build().unwrap();
        let mut cpu = PackedBooleanAccumulators::zero();
        for index in 0..4_097 {
            let mixed = (index as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
            cpu.add_gate(
                if index & 3 == 0 {
                    PackedBooleanGate::And
                } else {
                    PackedBooleanGate::Xor
                },
                mixed as u8,
                mixed.rotate_left(29) as u8,
                fp16((index & 255) + 1),
            )
            .unwrap();
        }
        let (product, left, right) = cpu.canonical_coordinates();
        let imported =
            PackedBooleanAccumulators::from_canonical_coordinates(&product, &left, &right, 4_097)
                .unwrap();
        assert_eq!(
            finish_packed_boolean_accumulators(&table, imported, fp16(29)).unwrap(),
            finish_packed_boolean_accumulators(&table, cpu, fp16(29)).unwrap()
        );

        let mut noncanonical = product.clone();
        noncanonical[0][0] = M31_MODULUS;
        assert_eq!(
            PackedBooleanAccumulators::from_canonical_coordinates(
                &noncanonical,
                &left,
                &right,
                4_097
            ),
            Err(PackedBooleanError::AccumulatorNonCanonical)
        );
        assert_eq!(
            PackedBooleanAccumulators::from_canonical_coordinates(
                &product[..PRODUCT_COUNT - 1],
                &left,
                &right,
                4_097
            ),
            Err(PackedBooleanError::AccumulatorShape)
        );
        assert_eq!(
            PackedBooleanAccumulators::from_canonical_coordinates(&product, &left, &right, 0),
            Err(PackedBooleanError::Empty)
        );
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn indexed_parallel_reduction_matches_serial_for_all_worker_counts() {
        let table = PackedBooleanTable::build().unwrap();
        let gate_count = 4_097;
        let gate_at = |index: usize| {
            let mixed = (index as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
            (
                if index & 3 == 0 {
                    PackedBooleanGate::And
                } else {
                    PackedBooleanGate::Xor
                },
                mixed as u8,
                mixed.rotate_left(29) as u8,
                fp16((index & 255) + 1),
            )
        };
        let serial =
            reduce_packed_boolean_stream(&table, (0..gate_count).map(gate_at), fp16(29)).unwrap();
        for workers in [1, 2, 4, 8, 16] {
            let parallel = reduce_packed_boolean_indexed_parallel(
                &table,
                gate_count,
                workers,
                gate_at,
                fp16(29),
            )
            .unwrap();
            assert_eq!(parallel, serial);
        }
        assert_eq!(
            reduce_packed_boolean_indexed_parallel(&table, gate_count, 0, gate_at, fp16(29)),
            Err(PackedBooleanError::WorkerCount)
        );
    }
}
