//! Small-polynomial zero-knowledge masks for the GKR composition.
//!
//! This module implements only the algebra from Libra Constructions 1 and 2.
//! Commitment, authenticated challenge ordering, and PCS openings remain
//! separate trust-critical layers.

use alloc::{vec, vec::Vec};

use crate::field::Fp16;

pub const LIBRA_LAYER_MASK_COEFFICIENTS: usize = 9;
pub const PACKED_BRIDGE_MASK_COEFFICIENTS: usize = 24;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GkrZkMaskError {
    Empty,
    Shape,
    Round,
    Sequence,
    Claim,
    Overflow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedMaskedSumcheckState {
    current_claim: Fp16,
    variable_degrees: Vec<usize>,
    rounds: Vec<Vec<Fp16>>,
    challenges: Vec<Fp16>,
    pending: Option<Vec<Fp16>>,
}

impl CommittedMaskedSumcheckState {
    pub fn new(
        raw_claim: Fp16,
        protocol_correction: Fp16,
        mask_boolean_sum: Fp16,
        rho: Fp16,
        variable_degrees: Vec<usize>,
    ) -> Result<Self, GkrZkMaskError> {
        if rho.is_zero() || variable_degrees.is_empty() || variable_degrees.contains(&0) {
            return Err(GkrZkMaskError::Shape);
        }
        Ok(Self {
            current_claim: raw_claim + protocol_correction + rho * mask_boolean_sum,
            rounds: Vec::with_capacity(variable_degrees.len()),
            challenges: Vec::with_capacity(variable_degrees.len()),
            variable_degrees,
            pending: None,
        })
    }

    pub fn current_claim(&self) -> Fp16 {
        self.current_claim
    }

    pub fn round_ordinal(&self) -> usize {
        self.challenges.len()
    }

    pub fn publish_round(
        &mut self,
        base_polynomial: &[Fp16],
        mask_polynomial: &[Fp16],
        rho: Fp16,
    ) -> Result<Vec<Fp16>, GkrZkMaskError> {
        let round = self.round_ordinal();
        if self.pending.is_some() || round >= self.variable_degrees.len() || rho.is_zero() {
            return Err(GkrZkMaskError::Sequence);
        }
        let coefficients = self.variable_degrees[round] + 1;
        if base_polynomial.len() > coefficients
            || mask_polynomial.len() > coefficients
            || base_polynomial.is_empty()
            || mask_polynomial.is_empty()
        {
            return Err(GkrZkMaskError::Shape);
        }
        let mut published = vec![Fp16::ZERO; coefficients];
        for (destination, coefficient) in published.iter_mut().zip(base_polynomial) {
            *destination = *coefficient;
        }
        for (destination, coefficient) in published.iter_mut().zip(mask_polynomial) {
            *destination = *destination + rho * *coefficient;
        }
        if polynomial_evaluation(&published, Fp16::ZERO)
            + polynomial_evaluation(&published, Fp16::ONE)
            != self.current_claim
        {
            return Err(GkrZkMaskError::Claim);
        }
        self.pending = Some(published.clone());
        Ok(published)
    }

    pub fn accept_authenticated_challenge(
        &mut self,
        challenge: Fp16,
    ) -> Result<(), GkrZkMaskError> {
        let published = self.pending.take().ok_or(GkrZkMaskError::Sequence)?;
        self.current_claim = polynomial_evaluation(&published, challenge);
        self.rounds.push(published);
        self.challenges.push(challenge);
        Ok(())
    }

    pub fn finish(
        self,
        base_oracle: Fp16,
        mask_evaluation: Fp16,
        rho: Fp16,
    ) -> Result<Vec<Vec<Fp16>>, GkrZkMaskError> {
        if self.pending.is_some()
            || self.challenges.len() != self.variable_degrees.len()
            || rho.is_zero()
        {
            return Err(GkrZkMaskError::Sequence);
        }
        if self.current_claim != base_oracle + rho * mask_evaluation {
            return Err(GkrZkMaskError::Claim);
        }
        Ok(self.rounds)
    }
}

/// Construction-1 mask with the exact degree of each sumcheck variable.
///
/// The selected fold order keeps the vanishing mask zero while any Boolean
/// suffix coordinate remains. Its ordinary `x`/`y` messages are therefore
/// quadratic, the final message on each side is cubic, and the extra `w`
/// message is quadratic. Keeping those actual partial-sum degrees explicit
/// avoids silently treating the complete protocol as quadratic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LibraVariableDegreeSumcheckMask {
    pub constant: Fp16,
    pub variable_coefficients: Vec<Vec<Fp16>>,
}

impl LibraVariableDegreeSumcheckMask {
    pub fn new(
        constant: Fp16,
        variable_coefficients: Vec<Vec<Fp16>>,
    ) -> Result<Self, GkrZkMaskError> {
        if variable_coefficients.is_empty()
            || variable_coefficients
                .iter()
                .any(|coefficients| coefficients.is_empty())
        {
            return Err(GkrZkMaskError::Empty);
        }
        Ok(Self {
            constant,
            variable_coefficients,
        })
    }

    pub fn coefficient_count(&self) -> usize {
        1 + self
            .variable_coefficients
            .iter()
            .map(Vec::len)
            .sum::<usize>()
    }

    pub fn variable_degrees(&self) -> Vec<usize> {
        self.variable_coefficients.iter().map(Vec::len).collect()
    }

    pub fn evaluate(&self, point: &[Fp16]) -> Result<Fp16, GkrZkMaskError> {
        if point.len() != self.variable_coefficients.len() {
            return Err(GkrZkMaskError::Shape);
        }
        Ok(self.variable_coefficients.iter().zip(point).fold(
            self.constant,
            |sum, (coefficients, coordinate)| {
                let mut power = *coordinate;
                coefficients.iter().fold(sum, |value, coefficient| {
                    let next = value + *coefficient * power;
                    power = power * *coordinate;
                    next
                })
            },
        ))
    }

    pub fn round_polynomial(
        &self,
        prefix: &[Fp16],
        round: usize,
    ) -> Result<Vec<Fp16>, GkrZkMaskError> {
        if round >= self.variable_coefficients.len() || prefix.len() != round {
            return Err(GkrZkMaskError::Round);
        }
        let remaining = self.variable_coefficients.len() - round - 1;
        let scale = power_of_two(remaining);
        let mut constant = self.constant;
        for (coefficients, coordinate) in self.variable_coefficients.iter().take(round).zip(prefix)
        {
            let mut power = *coordinate;
            for coefficient in coefficients {
                constant = constant + *coefficient * power;
                power = power * *coordinate;
            }
        }
        constant = constant * scale;
        if remaining != 0 {
            let suffix_scale = power_of_two(remaining - 1);
            for coefficients in self.variable_coefficients.iter().skip(round + 1) {
                constant = constant
                    + coefficients
                        .iter()
                        .fold(Fp16::ZERO, |sum, coefficient| sum + *coefficient)
                        * suffix_scale;
            }
        }
        let mut polynomial = Vec::with_capacity(self.variable_coefficients[round].len() + 1);
        polynomial.push(constant);
        polynomial.extend(
            self.variable_coefficients[round]
                .iter()
                .map(|coefficient| *coefficient * scale),
        );
        Ok(polynomial)
    }

    pub fn boolean_sum(&self) -> Fp16 {
        let variables = self.variable_coefficients.len();
        self.constant * power_of_two(variables)
            + self
                .variable_coefficients
                .iter()
                .flat_map(|coefficients| coefficients.iter())
                .fold(Fp16::ZERO, |sum, coefficient| sum + *coefficient)
                * power_of_two(variables - 1)
    }

    pub fn encode_coefficients(&self, destination: &mut Vec<Fp16>) {
        destination.push(self.constant);
        for coefficients in &self.variable_coefficients {
            destination.extend_from_slice(coefficients);
        }
    }
}

pub fn selected_libra_variable_degrees(
    input_variables: usize,
) -> Result<Vec<usize>, GkrZkMaskError> {
    if input_variables == 0 {
        return Err(GkrZkMaskError::Empty);
    }
    let mut degrees = Vec::with_capacity(2 * input_variables + 1);
    degrees.extend(core::iter::repeat_n(2, input_variables - 1));
    degrees.push(3);
    degrees.extend(core::iter::repeat_n(2, input_variables - 1));
    degrees.push(3);
    degrees.push(2);
    Ok(degrees)
}

/// `a0 + sum_j (a[j][0] x_j + a[j][1] x_j^2)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LibraSumcheckMask {
    pub constant: Fp16,
    pub variable_coefficients: Vec<[Fp16; 2]>,
}

impl LibraSumcheckMask {
    pub fn new(
        constant: Fp16,
        variable_coefficients: Vec<[Fp16; 2]>,
    ) -> Result<Self, GkrZkMaskError> {
        if variable_coefficients.is_empty() {
            return Err(GkrZkMaskError::Empty);
        }
        Ok(Self {
            constant,
            variable_coefficients,
        })
    }

    pub fn coefficient_count(&self) -> usize {
        1 + 2 * self.variable_coefficients.len()
    }

    pub fn evaluate(&self, point: &[Fp16]) -> Result<Fp16, GkrZkMaskError> {
        if point.len() != self.variable_coefficients.len() {
            return Err(GkrZkMaskError::Shape);
        }
        Ok(self.variable_coefficients.iter().zip(point).fold(
            self.constant,
            |sum, (coefficients, coordinate)| {
                sum + coefficients[0] * *coordinate + coefficients[1] * *coordinate * *coordinate
            },
        ))
    }

    /// Partial-sum quadratic published in one sumcheck round.
    pub fn round_polynomial(
        &self,
        prefix: &[Fp16],
        round: usize,
    ) -> Result<[Fp16; 3], GkrZkMaskError> {
        if round >= self.variable_coefficients.len() || prefix.len() != round {
            return Err(GkrZkMaskError::Round);
        }
        let remaining = self.variable_coefficients.len() - round - 1;
        let scale = power_of_two(remaining);
        let mut constant = self
            .variable_coefficients
            .iter()
            .take(round)
            .zip(prefix)
            .fold(self.constant, |sum, (coefficients, coordinate)| {
                sum + coefficients[0] * *coordinate + coefficients[1] * *coordinate * *coordinate
            })
            * scale;
        if remaining != 0 {
            let suffix_scale = power_of_two(remaining - 1);
            constant = constant
                + self
                    .variable_coefficients
                    .iter()
                    .skip(round + 1)
                    .fold(Fp16::ZERO, |sum, coefficients| {
                        sum + coefficients[0] + coefficients[1]
                    })
                    * suffix_scale;
        }
        Ok([
            constant,
            self.variable_coefficients[round][0] * scale,
            self.variable_coefficients[round][1] * scale,
        ])
    }

    pub fn boolean_sum(&self) -> Fp16 {
        let variables = self.variable_coefficients.len();
        let constant = self.constant * power_of_two(variables);
        let variable_scale = power_of_two(variables - 1);
        constant
            + self
                .variable_coefficients
                .iter()
                .fold(Fp16::ZERO, |sum, coefficients| {
                    sum + coefficients[0] + coefficients[1]
                })
                * variable_scale
    }

    pub fn encode_coefficients(&self, destination: &mut Vec<Fp16>) {
        destination.push(self.constant);
        for coefficients in &self.variable_coefficients {
            destination.extend_from_slice(coefficients);
        }
    }
}

/// Bivariate individual-degree-two `R(z_1, w)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LibraLayerMask {
    pub coefficients: [Fp16; LIBRA_LAYER_MASK_COEFFICIENTS],
}

impl LibraLayerMask {
    pub fn evaluate(&self, z_first: Fp16, w: Fp16) -> Fp16 {
        let z_powers = [Fp16::ONE, z_first, z_first * z_first];
        let w_powers = [Fp16::ONE, w, w * w];
        let mut value = Fp16::ZERO;
        for (z_degree, z_power) in z_powers.into_iter().enumerate() {
            for (w_degree, w_power) in w_powers.into_iter().enumerate() {
                value = value + self.coefficients[3 * z_degree + w_degree] * z_power * w_power;
            }
        }
        value
    }

    pub fn boolean_w_sum(&self, z_first: Fp16) -> Fp16 {
        self.evaluate(z_first, Fp16::ZERO) + self.evaluate(z_first, Fp16::ONE)
    }

    pub fn mask_evaluation(
        &self,
        raw_evaluation: Fp16,
        point: &[Fp16],
    ) -> Result<Fp16, GkrZkMaskError> {
        let first = *point.first().ok_or(GkrZkMaskError::Empty)?;
        Ok(raw_evaluation + boolean_vanishing(point) * self.boolean_w_sum(first))
    }

    pub fn fixed_first_polynomial(&self, z_first: Fp16) -> [Fp16; 3] {
        let z_powers = [Fp16::ONE, z_first, z_first * z_first];
        core::array::from_fn(|w_degree| {
            z_powers
                .iter()
                .copied()
                .enumerate()
                .fold(Fp16::ZERO, |sum, (z_degree, z_power)| {
                    sum + self.coefficients[3 * z_degree + w_degree] * z_power
                })
        })
    }
}

pub fn boolean_vanishing(point: &[Fp16]) -> Fp16 {
    point.iter().fold(Fp16::ONE, |product, coordinate| {
        product * *coordinate * (Fp16::ONE - *coordinate)
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LibraPriorLayerCorrection {
    pub w_polynomial: [Fp16; 3],
}

impl LibraPriorLayerCorrection {
    pub fn zero() -> Self {
        Self {
            w_polynomial: [Fp16::ZERO; 3],
        }
    }

    pub fn from_claims(
        mask: &LibraLayerMask,
        claims: &[(Fp16, Vec<Fp16>)],
    ) -> Result<Self, GkrZkMaskError> {
        if claims.is_empty() || claims.iter().any(|(_, point)| point.is_empty()) {
            return Err(GkrZkMaskError::Shape);
        }
        let mut w_polynomial = [Fp16::ZERO; 3];
        for (coefficient, point) in claims {
            let scale = *coefficient * boolean_vanishing(point);
            let polynomial = mask.fixed_first_polynomial(point[0]);
            for degree in 0..3 {
                w_polynomial[degree] = w_polynomial[degree] + scale * polynomial[degree];
            }
        }
        Ok(Self { w_polynomial })
    }

    /// Build the correction for a relay-free DAG reduction whose incoming
    /// claims can originate from different prior layer masks.
    pub fn from_indexed_claims(
        masks: &[LibraLayerMask],
        claims: &[(usize, Fp16, Vec<Fp16>)],
    ) -> Result<Self, GkrZkMaskError> {
        if claims.is_empty()
            || claims
                .iter()
                .any(|(layer, _, point)| *layer >= masks.len() || point.is_empty())
        {
            return Err(GkrZkMaskError::Shape);
        }
        let mut w_polynomial = [Fp16::ZERO; 3];
        for (layer, coefficient, point) in claims {
            let scale = *coefficient * boolean_vanishing(point);
            let polynomial = masks[*layer].fixed_first_polynomial(point[0]);
            for degree in 0..3 {
                w_polynomial[degree] = w_polynomial[degree] + scale * polynomial[degree];
            }
        }
        Ok(Self { w_polynomial })
    }

    pub fn evaluate(&self, w: Fp16) -> Fp16 {
        polynomial_evaluation(&self.w_polynomial, w)
    }

    pub fn boolean_sum(&self) -> Fp16 {
        self.evaluate(Fp16::ZERO) + self.evaluate(Fp16::ONE)
    }

    /// Partial-sum contribution of `eq((x,y), 0) * sum_w C(w)`.
    pub fn xy_round_polynomial(&self, prefix: &[Fp16]) -> [Fp16; 2] {
        let prefix_equality = prefix.iter().fold(Fp16::ONE, |value, coordinate| {
            value * (Fp16::ONE - *coordinate)
        });
        let constant = prefix_equality * self.boolean_sum();
        [constant, -constant]
    }

    /// Final `w`-round contribution after all `x,y` challenges.
    pub fn w_round_polynomial(&self, xy_point: &[Fp16]) -> [Fp16; 3] {
        let equality_zero = xy_point.iter().fold(Fp16::ONE, |value, coordinate| {
            value * (Fp16::ONE - *coordinate)
        });
        self.w_polynomial
            .map(|coefficient| coefficient * equality_zero)
    }
}

pub fn terminal_vanishing_coefficient(
    mask: &LibraLayerMask,
    prefix: &[Fp16],
) -> Result<Fp16, GkrZkMaskError> {
    let first = *prefix.first().ok_or(GkrZkMaskError::Empty)?;
    Ok(prefix.iter().fold(Fp16::ONE, |product, coordinate| {
        product * *coordinate * (Fp16::ONE - *coordinate)
    }) * mask.boolean_w_sum(first))
}

#[allow(clippy::too_many_arguments)]
pub fn terminal_extension_cubic(
    term_weights: &[Fp16],
    varying_labels: &[u32],
    opposite_labels: &[u32],
    formulas: &[u8],
    prefix_equality: &[Fp16],
    opposite_values: &[Fp16],
    fixed_opposite: Option<Fp16>,
    fixed_opposite_equality: Option<&[Fp16]>,
    varying_left: bool,
    vanishing_coefficient: Fp16,
) -> Result<[Fp16; 4], GkrZkMaskError> {
    let term_count = term_weights.len();
    if term_count == 0
        || varying_labels.len() != term_count
        || opposite_labels.len() != term_count
        || formulas.len() != term_count
        || prefix_equality.is_empty()
        || !prefix_equality.len().is_power_of_two()
        || fixed_opposite.is_none() && opposite_values.is_empty()
        || fixed_opposite.is_some()
            && fixed_opposite_equality
                .is_none_or(|weights| weights.is_empty() || !weights.len().is_power_of_two())
    {
        return Err(GkrZkMaskError::Shape);
    }
    let prefix_mask = prefix_equality.len() - 1;
    let final_bit = prefix_equality.len().ilog2();
    let two = Fp16::ONE + Fp16::ONE;
    let mut result = [Fp16::ZERO; 4];
    for index in 0..term_count {
        let varying_label = varying_labels[index] as usize;
        let opposite = if let Some(value) = fixed_opposite {
            value
        } else {
            *opposite_values
                .get(opposite_labels[index] as usize)
                .ok_or(GkrZkMaskError::Shape)?
        };
        let slope = gate_slope(formulas[index], varying_left, opposite)?;
        let opposite_factor = if fixed_opposite.is_some() {
            *fixed_opposite_equality
                .and_then(|weights| weights.get(opposite_labels[index] as usize))
                .ok_or(GkrZkMaskError::Shape)?
        } else {
            Fp16::ONE
        };
        let scale = term_weights[index]
            * prefix_equality[varying_label & prefix_mask]
            * opposite_factor
            * slope
            * vanishing_coefficient;
        if (varying_label >> final_bit) & 1 == 0 {
            result[1] = result[1] + scale;
            result[2] = result[2] - two * scale;
            result[3] = result[3] + scale;
        } else {
            result[2] = result[2] + scale;
            result[3] = result[3] - scale;
        }
    }
    Ok(result)
}

/// The same terminal extension as [`terminal_extension_cubic`], evaluated
/// directly from the repeated-pack claim factorization.
///
/// This avoids materializing one `Fp16` weight per repeated gate while keeping
/// the exact gate-slope algebra in one trust-critical implementation.
#[allow(clippy::too_many_arguments)]
pub fn terminal_extension_cubic_factored(
    claim_coefficients: &[Fp16],
    claim_wire_weights: &[&[Fp16]],
    claim_group_weights: &[&[Fp16]],
    input_width: usize,
    base_left: &[u32],
    base_right: &[u32],
    formulas: &[u8],
    prefix_equality: &[Fp16],
    opposite_values: &[Fp16],
    fixed_opposite: Option<Fp16>,
    fixed_opposite_equality: Option<&[Fp16]>,
    varying_left: bool,
    vanishing_coefficient: Fp16,
) -> Result<[Fp16; 4], GkrZkMaskError> {
    if claim_coefficients.is_empty()
        || claim_wire_weights.len() != claim_coefficients.len()
        || claim_group_weights.len() != claim_coefficients.len()
        || input_width == 0
        || !input_width.is_power_of_two()
        || base_left.is_empty()
        || base_right.len() != base_left.len()
        || formulas.len() != base_left.len()
        || claim_wire_weights
            .iter()
            .any(|weights| weights.len() != base_left.len())
        || claim_group_weights.is_empty()
        || claim_group_weights
            .iter()
            .any(|weights| weights.len() != claim_group_weights[0].len())
        || claim_group_weights[0].is_empty()
        || !claim_group_weights[0].len().is_power_of_two()
        || prefix_equality.is_empty()
        || !prefix_equality.len().is_power_of_two()
        || fixed_opposite.is_none()
            && opposite_values.len() != input_width * claim_group_weights[0].len()
        || fixed_opposite.is_some()
            && fixed_opposite_equality
                .is_none_or(|weights| weights.len() != input_width * claim_group_weights[0].len())
    {
        return Err(GkrZkMaskError::Shape);
    }
    let prefix_mask = prefix_equality.len() - 1;
    let final_bit = prefix_equality.len().ilog2();
    let two = Fp16::ONE + Fp16::ONE;
    let mut result = [Fp16::ZERO; 4];
    for group in 0..claim_group_weights[0].len() {
        let input_offset = group * input_width;
        for gate in 0..base_left.len() {
            let term_weight = claim_coefficients
                .iter()
                .zip(claim_wire_weights)
                .zip(claim_group_weights)
                .fold(
                    Fp16::ZERO,
                    |sum, ((coefficient, wire_weights), group_weights)| {
                        sum + *coefficient * wire_weights[gate] * group_weights[group]
                    },
                );
            let varying_base = if varying_left {
                base_left[gate]
            } else {
                base_right[gate]
            } as usize;
            let opposite_base = if varying_left {
                base_right[gate]
            } else {
                base_left[gate]
            } as usize;
            if varying_base >= input_width || opposite_base >= input_width {
                return Err(GkrZkMaskError::Shape);
            }
            let opposite = if let Some(value) = fixed_opposite {
                value
            } else {
                opposite_values[input_offset + opposite_base]
            };
            let slope = gate_slope(formulas[gate], varying_left, opposite)?;
            let varying_label = input_offset + varying_base;
            let opposite_factor = if fixed_opposite.is_some() {
                fixed_opposite_equality
                    .and_then(|weights| weights.get(input_offset + opposite_base))
                    .copied()
                    .ok_or(GkrZkMaskError::Shape)?
            } else {
                Fp16::ONE
            };
            let scale = term_weight
                * prefix_equality[varying_label & prefix_mask]
                * opposite_factor
                * slope
                * vanishing_coefficient;
            if (varying_label >> final_bit) & 1 == 0 {
                result[1] = result[1] + scale;
                result[2] = result[2] - two * scale;
                result[3] = result[3] + scale;
            } else {
                result[2] = result[2] + scale;
                result[3] = result[3] - scale;
            }
        }
    }
    Ok(result)
}

fn gate_slope(formula: u8, varying_left: bool, opposite: Fp16) -> Result<Fp16, GkrZkMaskError> {
    let two = Fp16::ONE + Fp16::ONE;
    match (formula, varying_left) {
        (0, _) => Ok(Fp16::ONE - two * opposite),
        (1, _) => Ok(opposite),
        (2, true) => Ok(-opposite),
        (2, false) => Ok(Fp16::ONE - opposite),
        (3, _) => Ok(two * opposite - Fp16::ONE),
        (4, true) | (5, false) => Ok(Fp16::ONE),
        (4, false) | (5, true) => Ok(Fp16::ZERO),
        (6, true) | (7, false) => Ok(-Fp16::ONE),
        (6, false) | (7, true) | (8 | 9, _) => Ok(Fp16::ZERO),
        _ => Err(GkrZkMaskError::Shape),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GkrZkLayerMaskLayout {
    pub sumcheck_offset: usize,
    pub sumcheck_coefficients: usize,
    pub layer_offset: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GkrZkMaskCommitmentLayout {
    pub layers: Vec<GkrZkLayerMaskLayout>,
    pub used_coefficients: usize,
    pub padded_coefficients: usize,
}

impl GkrZkMaskCommitmentLayout {
    pub fn new(sumcheck_variable_counts: &[usize]) -> Result<Self, GkrZkMaskError> {
        if sumcheck_variable_counts.is_empty() || sumcheck_variable_counts.contains(&0) {
            return Err(GkrZkMaskError::Empty);
        }
        let mut offset = 0_usize;
        let mut layers = Vec::with_capacity(sumcheck_variable_counts.len());
        for variables in sumcheck_variable_counts {
            let sumcheck_coefficients = variables
                .checked_mul(2)
                .and_then(|value| value.checked_add(1))
                .ok_or(GkrZkMaskError::Overflow)?;
            let layer_offset = offset
                .checked_add(sumcheck_coefficients)
                .ok_or(GkrZkMaskError::Overflow)?;
            layers.push(GkrZkLayerMaskLayout {
                sumcheck_offset: offset,
                sumcheck_coefficients,
                layer_offset,
            });
            offset = layer_offset
                .checked_add(LIBRA_LAYER_MASK_COEFFICIENTS)
                .ok_or(GkrZkMaskError::Overflow)?;
        }
        let padded_coefficients = offset
            .checked_next_power_of_two()
            .ok_or(GkrZkMaskError::Overflow)?;
        Ok(Self {
            layers,
            used_coefficients: offset,
            padded_coefficients,
        })
    }

    pub fn encode(
        &self,
        sumcheck_masks: &[LibraSumcheckMask],
        layer_masks: &[LibraLayerMask],
    ) -> Result<Vec<Fp16>, GkrZkMaskError> {
        if sumcheck_masks.len() != self.layers.len() || layer_masks.len() != self.layers.len() {
            return Err(GkrZkMaskError::Shape);
        }
        let mut encoded = Vec::with_capacity(self.padded_coefficients);
        for (ordinal, layout) in self.layers.iter().enumerate() {
            if encoded.len() != layout.sumcheck_offset
                || sumcheck_masks[ordinal].coefficient_count() != layout.sumcheck_coefficients
            {
                return Err(GkrZkMaskError::Shape);
            }
            sumcheck_masks[ordinal].encode_coefficients(&mut encoded);
            if encoded.len() != layout.layer_offset {
                return Err(GkrZkMaskError::Shape);
            }
            encoded.extend_from_slice(&layer_masks[ordinal].coefficients);
        }
        if encoded.len() != self.used_coefficients {
            return Err(GkrZkMaskError::Shape);
        }
        encoded.resize(self.padded_coefficients, Fp16::ZERO);
        Ok(encoded)
    }

    pub fn accumulate_sumcheck_evaluation(
        &self,
        destination: &mut [Fp16],
        layer: usize,
        point: &[Fp16],
        mixing: Fp16,
    ) -> Result<(), GkrZkMaskError> {
        let layout = self.linear_destination(destination, layer)?;
        let variables = (layout.sumcheck_coefficients - 1) / 2;
        if point.len() != variables {
            return Err(GkrZkMaskError::Shape);
        }
        destination[layout.sumcheck_offset] = destination[layout.sumcheck_offset] + mixing;
        for (ordinal, coordinate) in point.iter().copied().enumerate() {
            let offset = layout.sumcheck_offset + 1 + 2 * ordinal;
            destination[offset] = destination[offset] + mixing * coordinate;
            destination[offset + 1] = destination[offset + 1] + mixing * coordinate * coordinate;
        }
        Ok(())
    }

    pub fn accumulate_sumcheck_boolean_sum(
        &self,
        destination: &mut [Fp16],
        layer: usize,
        mixing: Fp16,
    ) -> Result<(), GkrZkMaskError> {
        let layout = self.linear_destination(destination, layer)?;
        let variables = (layout.sumcheck_coefficients - 1) / 2;
        destination[layout.sumcheck_offset] =
            destination[layout.sumcheck_offset] + mixing * power_of_two(variables);
        let variable_scale = mixing * power_of_two(variables - 1);
        for ordinal in 0..variables {
            let offset = layout.sumcheck_offset + 1 + 2 * ordinal;
            destination[offset] = destination[offset] + variable_scale;
            destination[offset + 1] = destination[offset + 1] + variable_scale;
        }
        Ok(())
    }

    pub fn accumulate_layer_evaluation(
        &self,
        destination: &mut [Fp16],
        layer: usize,
        z_first: Fp16,
        w: Fp16,
        mixing: Fp16,
    ) -> Result<(), GkrZkMaskError> {
        let layout = self.linear_destination(destination, layer)?;
        let z_powers = [Fp16::ONE, z_first, z_first * z_first];
        let w_powers = [Fp16::ONE, w, w * w];
        for (z_degree, z_power) in z_powers.into_iter().enumerate() {
            for (w_degree, w_power) in w_powers.into_iter().enumerate() {
                let offset = layout.layer_offset + 3 * z_degree + w_degree;
                destination[offset] = destination[offset] + mixing * z_power * w_power;
            }
        }
        Ok(())
    }

    pub fn accumulate_layer_boolean_w_sum(
        &self,
        destination: &mut [Fp16],
        layer: usize,
        z_first: Fp16,
        mixing: Fp16,
    ) -> Result<(), GkrZkMaskError> {
        self.accumulate_layer_evaluation(destination, layer, z_first, Fp16::ZERO, mixing)?;
        self.accumulate_layer_evaluation(destination, layer, z_first, Fp16::ONE, mixing)
    }

    fn linear_destination(
        &self,
        destination: &mut [Fp16],
        layer: usize,
    ) -> Result<GkrZkLayerMaskLayout, GkrZkMaskError> {
        if destination.len() != self.padded_coefficients {
            return Err(GkrZkMaskError::Shape);
        }
        self.layers.get(layer).copied().ok_or(GkrZkMaskError::Shape)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteGkrZkLayerMaskLayout {
    pub bridge_offset: usize,
    pub bridge_coefficients: usize,
    pub sumcheck_offset: usize,
    pub variable_degrees: Vec<usize>,
    pub layer_offset: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteGkrZkMaskCommitmentLayout {
    pub layers: Vec<CompleteGkrZkLayerMaskLayout>,
    pub used_coefficients: usize,
    pub padded_coefficients: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteGkrZkLeakageBudget {
    pub bridge_view_rank: usize,
    pub sumcheck_view_rank: usize,
    pub layer_view_rank: usize,
    pub aggregate_opening_rank: usize,
    pub total_rank: usize,
}

pub type CompleteGkrZkDecodedPrefix = (
    Vec<Vec<Fp16>>,
    Vec<LibraVariableDegreeSumcheckMask>,
    Vec<LibraLayerMask>,
);

impl CompleteGkrZkMaskCommitmentLayout {
    pub fn new(
        variable_degrees: &[Vec<usize>],
        bridge_coefficients: usize,
    ) -> Result<Self, GkrZkMaskError> {
        if variable_degrees.is_empty()
            || bridge_coefficients == 0
            || variable_degrees
                .iter()
                .any(|degrees| degrees.is_empty() || degrees.contains(&0))
        {
            return Err(GkrZkMaskError::Empty);
        }
        let mut offset = 0_usize;
        let mut layers = Vec::with_capacity(variable_degrees.len());
        for degrees in variable_degrees {
            let bridge_offset = offset;
            let sumcheck_offset = bridge_offset
                .checked_add(bridge_coefficients)
                .ok_or(GkrZkMaskError::Overflow)?;
            let sumcheck_coefficients = degrees
                .iter()
                .try_fold(1_usize, |sum, degree| sum.checked_add(*degree))
                .ok_or(GkrZkMaskError::Overflow)?;
            let layer_offset = sumcheck_offset
                .checked_add(sumcheck_coefficients)
                .ok_or(GkrZkMaskError::Overflow)?;
            layers.push(CompleteGkrZkLayerMaskLayout {
                bridge_offset,
                bridge_coefficients,
                sumcheck_offset,
                variable_degrees: degrees.clone(),
                layer_offset,
            });
            offset = layer_offset
                .checked_add(LIBRA_LAYER_MASK_COEFFICIENTS)
                .ok_or(GkrZkMaskError::Overflow)?;
        }
        let padded_coefficients = offset
            .checked_next_power_of_two()
            .ok_or(GkrZkMaskError::Overflow)?;
        Ok(Self {
            layers,
            used_coefficients: offset,
            padded_coefficients,
        })
    }

    pub fn encode(
        &self,
        bridge_masks: &[Vec<Fp16>],
        sumcheck_masks: &[LibraVariableDegreeSumcheckMask],
        layer_masks: &[LibraLayerMask],
    ) -> Result<Vec<Fp16>, GkrZkMaskError> {
        if bridge_masks.len() != self.layers.len()
            || sumcheck_masks.len() != self.layers.len()
            || layer_masks.len() != self.layers.len()
        {
            return Err(GkrZkMaskError::Shape);
        }
        let mut encoded = Vec::with_capacity(self.padded_coefficients);
        for (ordinal, layout) in self.layers.iter().enumerate() {
            if encoded.len() != layout.bridge_offset
                || bridge_masks[ordinal].len() != layout.bridge_coefficients
            {
                return Err(GkrZkMaskError::Shape);
            }
            encoded.extend_from_slice(&bridge_masks[ordinal]);
            if encoded.len() != layout.sumcheck_offset
                || sumcheck_masks[ordinal].variable_degrees() != layout.variable_degrees
            {
                return Err(GkrZkMaskError::Shape);
            }
            sumcheck_masks[ordinal].encode_coefficients(&mut encoded);
            if encoded.len() != layout.layer_offset {
                return Err(GkrZkMaskError::Shape);
            }
            encoded.extend_from_slice(&layer_masks[ordinal].coefficients);
        }
        if encoded.len() != self.used_coefficients {
            return Err(GkrZkMaskError::Shape);
        }
        encoded.resize(self.padded_coefficients, Fp16::ZERO);
        Ok(encoded)
    }

    pub fn decode_prefix(
        &self,
        coefficients: &[Fp16],
    ) -> Result<CompleteGkrZkDecodedPrefix, GkrZkMaskError> {
        if coefficients.len() < self.used_coefficients {
            return Err(GkrZkMaskError::Shape);
        }
        let mut bridge_masks = Vec::with_capacity(self.layers.len());
        let mut sumcheck_masks = Vec::with_capacity(self.layers.len());
        let mut layer_masks = Vec::with_capacity(self.layers.len());
        for layout in &self.layers {
            bridge_masks.push(coefficients[layout.bridge_offset..layout.sumcheck_offset].to_vec());
            let mut offset = layout.sumcheck_offset;
            let constant = coefficients[offset];
            offset += 1;
            let mut variable_coefficients = Vec::with_capacity(layout.variable_degrees.len());
            for degree in &layout.variable_degrees {
                variable_coefficients.push(coefficients[offset..offset + *degree].to_vec());
                offset += *degree;
            }
            if offset != layout.layer_offset {
                return Err(GkrZkMaskError::Shape);
            }
            sumcheck_masks.push(LibraVariableDegreeSumcheckMask::new(
                constant,
                variable_coefficients,
            )?);
            let layer_coefficients: [Fp16; LIBRA_LAYER_MASK_COEFFICIENTS] = coefficients
                [layout.layer_offset..layout.layer_offset + LIBRA_LAYER_MASK_COEFFICIENTS]
                .try_into()
                .map_err(|_| GkrZkMaskError::Shape)?;
            layer_masks.push(LibraLayerMask {
                coefficients: layer_coefficients,
            });
        }
        Ok((bridge_masks, sumcheck_masks, layer_masks))
    }

    /// Conservative independent-linear-observation budget for the complete
    /// GKR masking view. Construction 1 consumes one mask dimension per bridge
    /// or sumcheck view coordinate. Construction 2 exposes four independent
    /// evaluations per layer. The final batched PCS functional is charged one
    /// additional rank even though it aggregates those openings.
    pub fn leakage_budget(&self) -> Result<CompleteGkrZkLeakageBudget, GkrZkMaskError> {
        let bridge_view_rank = self.layers.iter().try_fold(0_usize, |sum, layer| {
            sum.checked_add(layer.bridge_coefficients)
        });
        let sumcheck_view_rank = self.layers.iter().try_fold(0_usize, |sum, layer| {
            layer
                .variable_degrees
                .iter()
                .try_fold(1_usize, |layer_sum, degree| layer_sum.checked_add(*degree))
                .and_then(|layer_rank| sum.checked_add(layer_rank))
        });
        let layer_view_rank = self.layers.len().checked_mul(4);
        let (bridge_view_rank, sumcheck_view_rank, layer_view_rank) = (
            bridge_view_rank.ok_or(GkrZkMaskError::Overflow)?,
            sumcheck_view_rank.ok_or(GkrZkMaskError::Overflow)?,
            layer_view_rank.ok_or(GkrZkMaskError::Overflow)?,
        );
        let aggregate_opening_rank = 1;
        let total_rank = bridge_view_rank
            .checked_add(sumcheck_view_rank)
            .and_then(|rank| rank.checked_add(layer_view_rank))
            .and_then(|rank| rank.checked_add(aggregate_opening_rank))
            .ok_or(GkrZkMaskError::Overflow)?;
        Ok(CompleteGkrZkLeakageBudget {
            bridge_view_rank,
            sumcheck_view_rank,
            layer_view_rank,
            aggregate_opening_rank,
            total_rank,
        })
    }

    pub fn accumulate_bridge_evaluation(
        &self,
        destination: &mut [Fp16],
        layer: usize,
        point: Fp16,
        mixing: Fp16,
    ) -> Result<(), GkrZkMaskError> {
        let layout = self.linear_destination(destination, layer)?;
        let mut power = Fp16::ONE;
        for offset in 0..layout.bridge_coefficients {
            destination[layout.bridge_offset + offset] =
                destination[layout.bridge_offset + offset] + mixing * power;
            power = power * point;
        }
        Ok(())
    }

    pub fn accumulate_sumcheck_evaluation(
        &self,
        destination: &mut [Fp16],
        layer: usize,
        point: &[Fp16],
        mixing: Fp16,
    ) -> Result<(), GkrZkMaskError> {
        let layout = self.linear_destination(destination, layer)?;
        if point.len() != layout.variable_degrees.len() {
            return Err(GkrZkMaskError::Shape);
        }
        destination[layout.sumcheck_offset] = destination[layout.sumcheck_offset] + mixing;
        let mut offset = layout.sumcheck_offset + 1;
        for (coordinate, degree) in point.iter().zip(&layout.variable_degrees) {
            let mut power = *coordinate;
            for _ in 0..*degree {
                destination[offset] = destination[offset] + mixing * power;
                offset += 1;
                power = power * *coordinate;
            }
        }
        Ok(())
    }

    pub fn accumulate_sumcheck_boolean_sum(
        &self,
        destination: &mut [Fp16],
        layer: usize,
        mixing: Fp16,
    ) -> Result<(), GkrZkMaskError> {
        let layout = self.linear_destination(destination, layer)?;
        let variables = layout.variable_degrees.len();
        destination[layout.sumcheck_offset] =
            destination[layout.sumcheck_offset] + mixing * power_of_two(variables);
        let coefficient_weight = mixing * power_of_two(variables - 1);
        let coefficient_count = layout.variable_degrees.iter().sum::<usize>();
        for offset in 0..coefficient_count {
            destination[layout.sumcheck_offset + 1 + offset] =
                destination[layout.sumcheck_offset + 1 + offset] + coefficient_weight;
        }
        Ok(())
    }

    pub fn accumulate_layer_evaluation(
        &self,
        destination: &mut [Fp16],
        layer: usize,
        z_first: Fp16,
        w: Fp16,
        mixing: Fp16,
    ) -> Result<(), GkrZkMaskError> {
        let layout = self.linear_destination(destination, layer)?;
        let z_powers = [Fp16::ONE, z_first, z_first * z_first];
        let w_powers = [Fp16::ONE, w, w * w];
        for (z_degree, z_power) in z_powers.into_iter().enumerate() {
            for (w_degree, w_power) in w_powers.into_iter().enumerate() {
                let offset = layout.layer_offset + 3 * z_degree + w_degree;
                destination[offset] = destination[offset] + mixing * z_power * w_power;
            }
        }
        Ok(())
    }

    pub fn accumulate_layer_boolean_w_sum(
        &self,
        destination: &mut [Fp16],
        layer: usize,
        z_first: Fp16,
        mixing: Fp16,
    ) -> Result<(), GkrZkMaskError> {
        self.accumulate_layer_evaluation(destination, layer, z_first, Fp16::ZERO, mixing)?;
        self.accumulate_layer_evaluation(destination, layer, z_first, Fp16::ONE, mixing)
    }

    fn linear_destination(
        &self,
        destination: &mut [Fp16],
        layer: usize,
    ) -> Result<&CompleteGkrZkLayerMaskLayout, GkrZkMaskError> {
        if destination.len() != self.padded_coefficients {
            return Err(GkrZkMaskError::Shape);
        }
        self.layers.get(layer).ok_or(GkrZkMaskError::Shape)
    }
}

pub fn inner_product(left: &[Fp16], right: &[Fp16]) -> Result<Fp16, GkrZkMaskError> {
    if left.len() != right.len() {
        return Err(GkrZkMaskError::Shape);
    }
    Ok(left
        .iter()
        .zip(right)
        .fold(Fp16::ZERO, |sum, (left, right)| sum + *left * *right))
}

/// Convert a linear functional on multilinear coefficients into the dual
/// functional on Boolean-hypercube evaluations.
pub fn coefficient_weights_to_hypercube_weights(
    coefficient_weights: &[Fp16],
) -> Result<Vec<Fp16>, GkrZkMaskError> {
    if coefficient_weights.is_empty() || !coefficient_weights.len().is_power_of_two() {
        return Err(GkrZkMaskError::Shape);
    }
    let mut weights = coefficient_weights.to_vec();
    for coordinate in 0..coefficient_weights.len().ilog2() {
        let half = 1_usize << coordinate;
        for block in weights.chunks_exact_mut(2 * half) {
            for index in 0..half {
                block[index] = block[index] - block[half + index];
            }
        }
    }
    Ok(weights)
}

fn power_of_two(exponent: usize) -> Fp16 {
    (0..exponent).fold(Fp16::ONE, |value, _| value + value)
}

pub fn polynomial_evaluation(coefficients: &[Fp16], point: Fp16) -> Fp16 {
    coefficients
        .iter()
        .rev()
        .fold(Fp16::ZERO, |value, coefficient| {
            value * point + *coefficient
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::M31;
    use crate::keccak_gkr_wiring::build_keccak_gkr_circuit;
    use crate::packed_boolean_sumcheck::OUTPUT_COEFFICIENTS;
    use alloc::vec;

    fn fp(value: u32) -> Fp16 {
        Fp16::from_m31(M31::from_canonical(value).unwrap())
    }

    fn quadratic_value(coefficients: [Fp16; 3], point: Fp16) -> Fp16 {
        coefficients[0] + point * (coefficients[1] + point * coefficients[2])
    }

    fn polynomial_value(coefficients: &[Fp16], point: Fp16) -> Fp16 {
        polynomial_evaluation(coefficients, point)
    }

    #[test]
    fn small_sumcheck_mask_has_exact_partial_sum_recurrence() {
        let mask = LibraSumcheckMask::new(
            fp(3),
            vec![[fp(5), fp(7)], [fp(11), fp(13)], [fp(17), fp(19)]],
        )
        .unwrap();
        let challenges = [fp(23), fp(29), fp(31)];
        let mut claim = mask.boolean_sum();
        for round in 0..3 {
            let polynomial = mask.round_polynomial(&challenges[..round], round).unwrap();
            assert_eq!(
                polynomial[0] + polynomial[0] + polynomial[1] + polynomial[2],
                claim
            );
            claim = quadratic_value(polynomial, challenges[round]);
        }
        assert_eq!(claim, mask.evaluate(&challenges).unwrap());
    }

    #[test]
    fn variable_degree_sumcheck_mask_has_exact_partial_sum_recurrence() {
        let mask = LibraVariableDegreeSumcheckMask::new(
            fp(3),
            vec![
                vec![fp(5), fp(7), fp(11), fp(13), fp(17)],
                vec![fp(19), fp(23), fp(29)],
                vec![fp(31), fp(37)],
            ],
        )
        .unwrap();
        let challenges = [fp(41), fp(43), fp(47)];
        let mut claim = mask.boolean_sum();
        for round in 0..challenges.len() {
            let polynomial = mask.round_polynomial(&challenges[..round], round).unwrap();
            assert_eq!(
                polynomial_value(&polynomial, Fp16::ZERO)
                    + polynomial_value(&polynomial, Fp16::ONE),
                claim
            );
            claim = polynomial_value(&polynomial, challenges[round]);
        }
        assert_eq!(claim, mask.evaluate(&challenges).unwrap());
    }

    #[test]
    fn committed_masked_sumcheck_enforces_publish_then_challenge() {
        let base = LibraVariableDegreeSumcheckMask::new(
            fp(3),
            vec![vec![fp(5), fp(7)], vec![fp(11), fp(13), fp(17)]],
        )
        .unwrap();
        let mask = LibraVariableDegreeSumcheckMask::new(
            fp(19),
            vec![vec![fp(23), fp(29)], vec![fp(31), fp(37), fp(41)]],
        )
        .unwrap();
        let rho = fp(43);
        let challenges = [fp(47), fp(53)];
        let mut state = CommittedMaskedSumcheckState::new(
            base.boolean_sum(),
            Fp16::ZERO,
            mask.boolean_sum(),
            rho,
            vec![2, 3],
        )
        .unwrap();
        assert_eq!(
            state.accept_authenticated_challenge(challenges[0]),
            Err(GkrZkMaskError::Sequence)
        );
        for round in 0..challenges.len() {
            state
                .publish_round(
                    &base.round_polynomial(&challenges[..round], round).unwrap(),
                    &mask.round_polynomial(&challenges[..round], round).unwrap(),
                    rho,
                )
                .unwrap();
            state
                .accept_authenticated_challenge(challenges[round])
                .unwrap();
        }
        let rounds = state
            .finish(
                base.evaluate(&challenges).unwrap(),
                mask.evaluate(&challenges).unwrap(),
                rho,
            )
            .unwrap();
        assert_eq!(rounds.len(), 2);
        assert_eq!(rounds[0].len(), 3);
        assert_eq!(rounds[1].len(), 4);
    }

    #[test]
    fn layer_mask_vanishes_exactly_on_the_boolean_domain() {
        let mask = LibraLayerMask {
            coefficients: core::array::from_fn(|index| fp(37 + index as u32)),
        };
        for point in [
            vec![Fp16::ZERO, Fp16::ZERO],
            vec![Fp16::ZERO, Fp16::ONE],
            vec![Fp16::ONE, Fp16::ZERO],
            vec![Fp16::ONE, Fp16::ONE],
        ] {
            assert_eq!(mask.mask_evaluation(fp(101), &point).unwrap(), fp(101));
        }
        assert_ne!(
            mask.mask_evaluation(fp(101), &[fp(2), fp(3)]).unwrap(),
            fp(101)
        );
    }

    #[test]
    fn prior_layer_correction_has_exact_bridge_xy_and_w_recurrence() {
        let mask = LibraLayerMask {
            coefficients: core::array::from_fn(|index| fp(43 + index as u32)),
        };
        let claims = [
            (fp(59), vec![fp(61), fp(67), fp(71)]),
            (fp(73), vec![fp(79), fp(83), fp(89)]),
        ];
        let correction = LibraPriorLayerCorrection::from_claims(&mask, &claims).unwrap();
        let expected = claims.iter().fold(Fp16::ZERO, |sum, (coefficient, point)| {
            sum + *coefficient * boolean_vanishing(point) * mask.boolean_w_sum(point[0])
        });
        assert_eq!(correction.boolean_sum(), expected);

        let xy_challenges = [fp(97), fp(101), fp(103), fp(107), fp(109), fp(113)];
        let mut claim = correction.boolean_sum();
        for round in 0..xy_challenges.len() {
            let polynomial = correction.xy_round_polynomial(&xy_challenges[..round]);
            assert_eq!(
                polynomial_evaluation(&polynomial, Fp16::ZERO)
                    + polynomial_evaluation(&polynomial, Fp16::ONE),
                claim
            );
            claim = polynomial_evaluation(&polynomial, xy_challenges[round]);
        }
        let w_polynomial = correction.w_round_polynomial(&xy_challenges);
        assert_eq!(
            polynomial_evaluation(&w_polynomial, Fp16::ZERO)
                + polynomial_evaluation(&w_polynomial, Fp16::ONE),
            claim
        );
        let prefix = [fp(127), fp(131)];
        let coefficient = terminal_vanishing_coefficient(&mask, &prefix).unwrap();
        let terminal = fp(137);
        assert_eq!(
            mask.mask_evaluation(fp(139), &[prefix[0], prefix[1], terminal])
                .unwrap(),
            fp(139) + coefficient * terminal * (Fp16::ONE - terminal)
        );
    }

    #[test]
    fn indexed_prior_layer_correction_matches_single_mask_reduction() {
        let mask = LibraLayerMask {
            coefficients: core::array::from_fn(|index| fp((700 + 19 * index) as u32)),
        };
        let claims = vec![
            (fp(801), vec![fp(811), fp(812), fp(813)]),
            (fp(821), vec![fp(831), fp(832), fp(833)]),
        ];
        let indexed = claims
            .iter()
            .cloned()
            .map(|(coefficient, point)| (0, coefficient, point))
            .collect::<Vec<_>>();
        assert_eq!(
            LibraPriorLayerCorrection::from_indexed_claims(core::slice::from_ref(&mask), &indexed)
                .unwrap(),
            LibraPriorLayerCorrection::from_claims(&mask, &claims).unwrap()
        );

        let mut malformed = indexed;
        malformed[0].0 = 1;
        assert_eq!(
            LibraPriorLayerCorrection::from_indexed_claims(&[mask], &malformed),
            Err(GkrZkMaskError::Shape)
        );
    }

    #[test]
    fn terminal_extension_cubic_matches_direct_gate_difference() {
        let weights = [fp(3), fp(5)];
        let varying = [0_u32, 2_u32];
        let opposite_labels = [0_u32, 1_u32];
        let formulas = [1_u8, 0_u8];
        let prefix_equality = [fp(7), fp(11)];
        let opposite_values = [fp(13), fp(17)];
        let vanishing = fp(19);
        let cubic = terminal_extension_cubic(
            &weights,
            &varying,
            &opposite_labels,
            &formulas,
            &prefix_equality,
            &opposite_values,
            None,
            None,
            true,
            vanishing,
        )
        .unwrap();
        for point in [fp(23), fp(29), fp(31), fp(37)] {
            let delta = vanishing * point * (Fp16::ONE - point);
            let expected = weights
                .iter()
                .zip(varying)
                .zip(opposite_labels)
                .zip(formulas)
                .fold(
                    Fp16::ZERO,
                    |sum, (((weight, varying_label), opposite_label), formula)| {
                        let bit = (varying_label >> 1) & 1;
                        let basis = if bit == 0 { Fp16::ONE - point } else { point };
                        sum + *weight
                            * prefix_equality[varying_label as usize & 1]
                            * basis
                            * gate_slope(formula, true, opposite_values[opposite_label as usize])
                                .unwrap()
                            * delta
                    },
                );
            assert_eq!(polynomial_evaluation(&cubic, point), expected);
        }
    }

    #[test]
    fn every_terminal_gate_slope_matches_an_independent_direct_difference() {
        fn gate(formula: u8, left: Fp16, right: Fp16) -> Fp16 {
            match formula {
                0 => left + right - left * right - left * right,
                1 => left * right,
                2 => right - left * right,
                3 => Fp16::ONE - left - right + left * right + left * right,
                4 => left,
                5 => right,
                6 => Fp16::ONE - left,
                7 => Fp16::ONE - right,
                8 => Fp16::ONE,
                9 => Fp16::ZERO,
                _ => unreachable!(),
            }
        }

        let zero = fp(101);
        let delta = fp(103);
        let opposite = fp(107);
        for formula in 0..=9 {
            for varying_left in [false, true] {
                let direct = if varying_left {
                    gate(formula, zero + delta, opposite) - gate(formula, zero, opposite)
                } else {
                    gate(formula, opposite, zero + delta) - gate(formula, opposite, zero)
                };
                assert_eq!(
                    direct,
                    gate_slope(formula, varying_left, opposite).unwrap() * delta,
                    "formula={formula} varying_left={varying_left}"
                );
            }
        }
        assert_eq!(gate_slope(10, true, opposite), Err(GkrZkMaskError::Shape));
    }

    #[test]
    fn factored_terminal_extension_matches_expanded_terms() {
        let coefficients = [fp(3), fp(5)];
        let first_wire = [fp(7), fp(11)];
        let second_wire = [fp(13), fp(17)];
        let first_group = [fp(19), fp(23)];
        let second_group = [fp(29), fp(31)];
        let wire_weights: [&[Fp16]; 2] = [&first_wire, &second_wire];
        let group_weights: [&[Fp16]; 2] = [&first_group, &second_group];
        let base_left = [0_u32, 2_u32];
        let base_right = [1_u32, 3_u32];
        let formulas = [1_u8, 0_u8];
        let prefix_equality = [fp(37), fp(41), fp(43), fp(47)];
        let opposite_values = (0..8).map(|index| fp(53 + index)).collect::<Vec<_>>();
        let vanishing = fp(67);
        let mut expanded_weights = Vec::new();
        let mut expanded_left = Vec::new();
        let mut expanded_right = Vec::new();
        let mut expanded_formulas = Vec::new();
        for group in 0..2 {
            for gate in 0..2 {
                expanded_weights.push(
                    coefficients[0] * first_wire[gate] * first_group[group]
                        + coefficients[1] * second_wire[gate] * second_group[group],
                );
                expanded_left.push((group * 4) as u32 + base_left[gate]);
                expanded_right.push((group * 4) as u32 + base_right[gate]);
                expanded_formulas.push(formulas[gate]);
            }
        }
        let expanded = terminal_extension_cubic(
            &expanded_weights,
            &expanded_left,
            &expanded_right,
            &expanded_formulas,
            &prefix_equality,
            &opposite_values,
            None,
            None,
            true,
            vanishing,
        )
        .unwrap();
        let factored = terminal_extension_cubic_factored(
            &coefficients,
            &wire_weights,
            &group_weights,
            4,
            &base_left,
            &base_right,
            &formulas,
            &prefix_equality,
            &opposite_values,
            None,
            None,
            true,
            vanishing,
        )
        .unwrap();
        assert_eq!(factored, expanded);

        let fixed = fp(71);
        let fixed_equality = (0..8).map(|index| fp(73 + index)).collect::<Vec<_>>();
        let expanded_fixed = terminal_extension_cubic(
            &expanded_weights,
            &expanded_right,
            &expanded_left,
            &expanded_formulas,
            &prefix_equality,
            &[],
            Some(fixed),
            Some(&fixed_equality),
            false,
            vanishing,
        )
        .unwrap();
        let factored_fixed = terminal_extension_cubic_factored(
            &coefficients,
            &wire_weights,
            &group_weights,
            4,
            &base_left,
            &base_right,
            &formulas,
            &prefix_equality,
            &[],
            Some(fixed),
            Some(&fixed_equality),
            false,
            vanishing,
        )
        .unwrap();
        assert_eq!(factored_fixed, expanded_fixed);
    }

    #[test]
    fn commitment_layout_is_contiguous_and_fixed_shape() {
        let layout = GkrZkMaskCommitmentLayout::new(&[4, 6]).unwrap();
        assert_eq!(layout.used_coefficients, (1 + 2 * 4 + 9) + (1 + 2 * 6 + 9));
        assert_eq!(layout.padded_coefficients, 64);
        assert_eq!(layout.layers[0].sumcheck_offset, 0);
        assert_eq!(layout.layers[1].sumcheck_offset, 18);
        let sumcheck_masks = [
            LibraSumcheckMask::new(fp(3), vec![[fp(5), fp(7)]; 4]).unwrap(),
            LibraSumcheckMask::new(fp(11), vec![[fp(13), fp(17)]; 6]).unwrap(),
        ];
        let layer_masks = [
            LibraLayerMask {
                coefficients: [fp(19); 9],
            },
            LibraLayerMask {
                coefficients: [fp(23); 9],
            },
        ];
        let encoded = layout.encode(&sumcheck_masks, &layer_masks).unwrap();
        assert_eq!(encoded.len(), 64);
        assert!(
            encoded[layout.used_coefficients..]
                .iter()
                .all(|value| value.is_zero())
        );

        let point = [fp(29), fp(31), fp(37), fp(41)];
        let mut weights = vec![Fp16::ZERO; layout.padded_coefficients];
        layout
            .accumulate_sumcheck_evaluation(&mut weights, 0, &point, fp(43))
            .unwrap();
        layout
            .accumulate_sumcheck_boolean_sum(&mut weights, 0, fp(47))
            .unwrap();
        layout
            .accumulate_layer_evaluation(&mut weights, 0, fp(53), fp(59), fp(61))
            .unwrap();
        layout
            .accumulate_layer_boolean_w_sum(&mut weights, 0, fp(67), fp(71))
            .unwrap();
        let expected = fp(43) * sumcheck_masks[0].evaluate(&point).unwrap()
            + fp(47) * sumcheck_masks[0].boolean_sum()
            + fp(61) * layer_masks[0].evaluate(fp(53), fp(59))
            + fp(71) * layer_masks[0].boolean_w_sum(fp(67));
        assert_eq!(inner_product(&encoded, &weights).unwrap(), expected);
        let hypercube =
            crate::multilinear_pcs::multilinear_coefficients_to_hypercube(&encoded).unwrap();
        let hypercube_weights = coefficient_weights_to_hypercube_weights(&weights).unwrap();
        assert_eq!(
            inner_product(&hypercube, &hypercube_weights).unwrap(),
            expected
        );
    }

    #[test]
    fn selected_keccak_chain_mask_geometry_is_exact() {
        let layers = build_keccak_gkr_circuit().unwrap();
        let variables = layers
            .iter()
            .map(|layer| 2 * (layer.input_width * 128).trailing_zeros() as usize)
            .collect::<Vec<_>>();
        let layout = GkrZkMaskCommitmentLayout::new(&variables).unwrap();
        assert_eq!(layout.layers.len(), 216);
        assert_eq!(variables.iter().sum::<usize>(), 7_920);
        assert_eq!(layout.used_coefficients, 18_000);
        assert_eq!(layout.padded_coefficients, 32_768);

        let degrees = layers
            .iter()
            .map(|layer| {
                selected_libra_variable_degrees((layer.input_width * 128).trailing_zeros() as usize)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let complete =
            CompleteGkrZkMaskCommitmentLayout::new(&degrees, PACKED_BRIDGE_MASK_COEFFICIENTS)
                .unwrap();
        assert_eq!(PACKED_BRIDGE_MASK_COEFFICIENTS, OUTPUT_COEFFICIENTS);
        assert_eq!(degrees.iter().map(Vec::len).sum::<usize>(), 8_136);
        assert_eq!(complete.used_coefficients, 24_048);
        assert_eq!(complete.padded_coefficients, 32_768);
        let leakage = complete.leakage_budget().unwrap();
        assert_eq!(leakage.bridge_view_rank, 5_184);
        assert_eq!(leakage.sumcheck_view_rank, 16_920);
        assert_eq!(leakage.layer_view_rank, 864);
        assert_eq!(leakage.aggregate_opening_rank, 1);
        assert_eq!(leakage.total_rank, 22_969);
        let deepfold_rank_bound = 473 * 21_usize.pow(2);
        assert_eq!(deepfold_rank_bound, 208_593);
        assert_eq!(deepfold_rank_bound + leakage.total_rank, 231_562);
        assert!(1_usize << 18 > deepfold_rank_bound + leakage.total_rank);

        let source = (0..complete.used_coefficients)
            .map(|index| fp(1 + index as u32 % 1_000_000))
            .collect::<Vec<_>>();
        let (bridges, sumchecks, layer_masks) = complete.decode_prefix(&source).unwrap();
        let encoded = complete.encode(&bridges, &sumchecks, &layer_masks).unwrap();
        assert_eq!(&encoded[..complete.used_coefficients], source);
        assert!(
            encoded[complete.used_coefficients..]
                .iter()
                .all(|value| value.is_zero())
        );
    }
}
