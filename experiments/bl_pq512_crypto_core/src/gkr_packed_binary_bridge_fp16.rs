//! Exact `B=16` first-round bridge for binary fan-in-two GKR over M31/Fp16.
//!
//! The sixteen Boolean instances are interpolated at the public nodes `0..15`.
//! A binary gate has degree at most 30 after interpolation. Multiplication by
//! the degree-15 packed equality selector therefore requires a complete
//! degree-45 message. This module is nonactivating algebra and deliberately
//! does not supply transcript scheduling or accelerator trust.

use core::fmt;

use crate::{
    field::Fp16,
    gkr_packed_bridge_fp16::{
        LagrangeBasis, PACKED_INSTANCES, evaluate, lagrange_basis, lagrange_evaluations,
    },
};

pub const PACKED_BINARY_RELATION_COEFFICIENTS: usize = 31;
pub const PACKED_BINARY_MESSAGE_COEFFICIENTS: usize = 46;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackedBinaryGate {
    Xor,
    NotLeftAndRight,
    NotXor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackedBinaryBridgeError {
    Empty,
    Shape,
}

impl fmt::Display for PackedBinaryBridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "packed binary bridge error: {self:?}")
    }
}

impl core::error::Error for PackedBinaryBridgeError {}

fn interpolate_pattern(basis: &LagrangeBasis, pattern: u16) -> [Fp16; PACKED_INSTANCES] {
    let mut polynomial = [Fp16::ZERO; PACKED_INSTANCES];
    for (position, basis_row) in basis.iter().enumerate() {
        if (pattern >> position) & 1 == 0 {
            continue;
        }
        for (coefficient, basis_coefficient) in polynomial.iter_mut().zip(basis_row.iter().copied())
        {
            *coefficient = *coefficient + basis_coefficient;
        }
    }
    polynomial
}

fn multiply<const L: usize, const R: usize, const O: usize>(
    left: &[Fp16; L],
    right: &[Fp16; R],
) -> [Fp16; O] {
    let mut output = [Fp16::ZERO; O];
    for (left_index, left_value) in left.iter().copied().enumerate() {
        for (right_index, right_value) in right.iter().copied().enumerate() {
            output[left_index + right_index] =
                output[left_index + right_index] + left_value * right_value;
        }
    }
    output
}

fn relation_polynomial(
    basis: &LagrangeBasis,
    gate: PackedBinaryGate,
    left_pattern: u16,
    right_pattern: u16,
) -> [Fp16; PACKED_BINARY_RELATION_COEFFICIENTS] {
    let left = interpolate_pattern(basis, left_pattern);
    let right = interpolate_pattern(basis, right_pattern);
    let product = multiply::<PACKED_INSTANCES, PACKED_INSTANCES, PACKED_BINARY_RELATION_COEFFICIENTS>(
        &left, &right,
    );
    let mut relation = [Fp16::ZERO; PACKED_BINARY_RELATION_COEFFICIENTS];
    match gate {
        PackedBinaryGate::Xor => {
            for coefficient in 0..PACKED_INSTANCES {
                relation[coefficient] = left[coefficient] + right[coefficient];
            }
            for (coefficient, product_coefficient) in product.into_iter().enumerate() {
                relation[coefficient] =
                    relation[coefficient] - product_coefficient - product_coefficient;
            }
        }
        PackedBinaryGate::NotLeftAndRight => {
            relation[..PACKED_INSTANCES].copy_from_slice(&right);
            for (coefficient, product_coefficient) in product.into_iter().enumerate() {
                relation[coefficient] = relation[coefficient] - product_coefficient;
            }
        }
        PackedBinaryGate::NotXor => {
            relation[0] = Fp16::ONE;
            for coefficient in 0..PACKED_INSTANCES {
                relation[coefficient] =
                    relation[coefficient] - left[coefficient] - right[coefficient];
            }
            for (coefficient, product_coefficient) in product.into_iter().enumerate() {
                relation[coefficient] =
                    relation[coefficient] + product_coefficient + product_coefficient;
            }
        }
    }
    relation
}

fn selector_polynomial(basis: &LagrangeBasis, query: Fp16) -> [Fp16; PACKED_INSTANCES] {
    let evaluations = lagrange_evaluations(basis, query);
    let mut polynomial = [Fp16::ZERO; PACKED_INSTANCES];
    for position in 0..PACKED_INSTANCES {
        for coefficient in 0..PACKED_INSTANCES {
            polynomial[coefficient] =
                polynomial[coefficient] + basis[position][coefficient] * evaluations[position];
        }
    }
    polynomial
}

/// Degree-fifteen packed-node selector whose values at nodes `0..15` are the
/// Lagrange coefficients for `query`.
pub fn packed_selector_polynomial(query: Fp16) -> [Fp16; PACKED_INSTANCES] {
    selector_polynomial(&lagrange_basis(), query)
}

/// Evaluate one sixteen-instance Boolean pattern at an authenticated packed
/// bridge challenge.
///
/// This is the exact source-table reduction paired with
/// [`packed_binary_round_message`]. It does not assume that the sixteen bits
/// are equal and therefore remains valid for real hash-bus groups.
pub fn evaluate_pattern(pattern: u16, point: Fp16) -> Fp16 {
    evaluate(&interpolate_pattern(&lagrange_basis(), pattern), point)
}

/// Construct the complete degree-45 first-round message.
///
/// `equality_weights[term][claim]` contains every equality factor except the
/// packed-node selector. The caller must publish the returned coefficients
/// before releasing the packed bridge challenge.
pub fn packed_binary_round_message<const CLAIMS: usize>(
    gates: &[PackedBinaryGate],
    left_patterns: &[u16],
    right_patterns: &[u16],
    equality_weights: &[[Fp16; CLAIMS]],
    output_queries: &[Fp16; CLAIMS],
) -> Result<[Fp16; PACKED_BINARY_MESSAGE_COEFFICIENTS], PackedBinaryBridgeError> {
    if gates.is_empty() {
        return Err(PackedBinaryBridgeError::Empty);
    }
    if gates.len() != left_patterns.len()
        || gates.len() != right_patterns.len()
        || gates.len() != equality_weights.len()
    {
        return Err(PackedBinaryBridgeError::Shape);
    }

    let basis = lagrange_basis();
    let selectors: [[Fp16; PACKED_INSTANCES]; CLAIMS] =
        core::array::from_fn(|claim| selector_polynomial(&basis, output_queries[claim]));
    let mut message = [Fp16::ZERO; PACKED_BINARY_MESSAGE_COEFFICIENTS];
    for term in 0..gates.len() {
        let relation = relation_polynomial(
            &basis,
            gates[term],
            left_patterns[term],
            right_patterns[term],
        );
        for claim in 0..CLAIMS {
            for relation_index in 0..PACKED_BINARY_RELATION_COEFFICIENTS {
                let weighted_relation = relation[relation_index] * equality_weights[term][claim];
                for selector_index in 0..PACKED_INSTANCES {
                    message[relation_index + selector_index] = message
                        [relation_index + selector_index]
                        + weighted_relation * selectors[claim][selector_index];
                }
            }
        }
    }
    Ok(message)
}

/// Construct the same degree-45 message through the 16-by-16 Boolean moment
/// basis instead of multiplying one pair of degree-15 polynomials per term.
///
/// This is the bounded reference for the production accelerator. Its live
/// algebraic state is `CLAIMS * (1 + 16 + 16 + 256)` Fp16 values and does not
/// allocate a `2^32` pattern-pair table. Every source term contributes only
/// to the lane moments selected by its two 16-bit patterns.
pub fn packed_binary_round_message_from_moments<const CLAIMS: usize>(
    gates: &[PackedBinaryGate],
    left_patterns: &[u16],
    right_patterns: &[u16],
    equality_weights: &[[Fp16; CLAIMS]],
    output_queries: &[Fp16; CLAIMS],
) -> Result<[Fp16; PACKED_BINARY_MESSAGE_COEFFICIENTS], PackedBinaryBridgeError> {
    if gates.is_empty() {
        return Err(PackedBinaryBridgeError::Empty);
    }
    if gates.len() != left_patterns.len()
        || gates.len() != right_patterns.len()
        || gates.len() != equality_weights.len()
    {
        return Err(PackedBinaryBridgeError::Shape);
    }

    let mut constants = [Fp16::ZERO; CLAIMS];
    let mut left_moments = [[Fp16::ZERO; PACKED_INSTANCES]; CLAIMS];
    let mut right_moments = [[Fp16::ZERO; PACKED_INSTANCES]; CLAIMS];
    let mut product_moments = [[[Fp16::ZERO; PACKED_INSTANCES]; PACKED_INSTANCES]; CLAIMS];

    for term in 0..gates.len() {
        let mut left = left_patterns[term];
        let mut left_nodes = [0_usize; PACKED_INSTANCES];
        let mut left_count = 0;
        while left != 0 {
            left_nodes[left_count] = left.trailing_zeros() as usize;
            left_count += 1;
            left &= left - 1;
        }
        let mut right = right_patterns[term];
        let mut right_nodes = [0_usize; PACKED_INSTANCES];
        let mut right_count = 0;
        while right != 0 {
            right_nodes[right_count] = right.trailing_zeros() as usize;
            right_count += 1;
            right &= right - 1;
        }

        for claim in 0..CLAIMS {
            let weight = equality_weights[term][claim];
            match gates[term] {
                PackedBinaryGate::Xor => {
                    for node in left_nodes[..left_count].iter().copied() {
                        left_moments[claim][node] = left_moments[claim][node] + weight;
                    }
                    for node in right_nodes[..right_count].iter().copied() {
                        right_moments[claim][node] = right_moments[claim][node] + weight;
                    }
                    for left_node in left_nodes[..left_count].iter().copied() {
                        for right_node in right_nodes[..right_count].iter().copied() {
                            product_moments[claim][left_node][right_node] =
                                product_moments[claim][left_node][right_node] - weight - weight;
                        }
                    }
                }
                PackedBinaryGate::NotLeftAndRight => {
                    for node in right_nodes[..right_count].iter().copied() {
                        right_moments[claim][node] = right_moments[claim][node] + weight;
                    }
                    for left_node in left_nodes[..left_count].iter().copied() {
                        for right_node in right_nodes[..right_count].iter().copied() {
                            product_moments[claim][left_node][right_node] =
                                product_moments[claim][left_node][right_node] - weight;
                        }
                    }
                }
                PackedBinaryGate::NotXor => {
                    constants[claim] = constants[claim] + weight;
                    for node in left_nodes[..left_count].iter().copied() {
                        left_moments[claim][node] = left_moments[claim][node] - weight;
                    }
                    for node in right_nodes[..right_count].iter().copied() {
                        right_moments[claim][node] = right_moments[claim][node] - weight;
                    }
                    for left_node in left_nodes[..left_count].iter().copied() {
                        for right_node in right_nodes[..right_count].iter().copied() {
                            product_moments[claim][left_node][right_node] =
                                product_moments[claim][left_node][right_node] + weight + weight;
                        }
                    }
                }
            }
        }
    }

    let basis = lagrange_basis();
    let selectors: [[Fp16; PACKED_INSTANCES]; CLAIMS] =
        core::array::from_fn(|claim| selector_polynomial(&basis, output_queries[claim]));
    let mut message = [Fp16::ZERO; PACKED_BINARY_MESSAGE_COEFFICIENTS];
    for claim in 0..CLAIMS {
        let mut relation = [Fp16::ZERO; PACKED_BINARY_RELATION_COEFFICIENTS];
        relation[0] = constants[claim];
        for node in 0..PACKED_INSTANCES {
            for coefficient in 0..PACKED_INSTANCES {
                relation[coefficient] = relation[coefficient]
                    + left_moments[claim][node] * basis[node][coefficient]
                    + right_moments[claim][node] * basis[node][coefficient];
            }
        }
        for left_node in 0..PACKED_INSTANCES {
            for right_node in 0..PACKED_INSTANCES {
                let moment = product_moments[claim][left_node][right_node];
                for left_coefficient in 0..PACKED_INSTANCES {
                    for right_coefficient in 0..PACKED_INSTANCES {
                        relation[left_coefficient + right_coefficient] = relation
                            [left_coefficient + right_coefficient]
                            + moment
                                * basis[left_node][left_coefficient]
                                * basis[right_node][right_coefficient];
                    }
                }
            }
        }
        for relation_index in 0..PACKED_BINARY_RELATION_COEFFICIENTS {
            for selector_index in 0..PACKED_INSTANCES {
                message[relation_index + selector_index] = message[relation_index + selector_index]
                    + relation[relation_index] * selectors[claim][selector_index];
            }
        }
    }
    Ok(message)
}

pub fn evaluate_message(message: &[Fp16; PACKED_BINARY_MESSAGE_COEFFICIENTS], point: Fp16) -> Fp16 {
    evaluate(message, point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{M31, M31_MODULUS};
    use alloc::vec::Vec;

    fn field(seed: u64) -> Fp16 {
        let mut state = seed ^ 0xa409_3822_299f_31d0;
        let coordinates = core::array::from_fn(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state as u32) % M31_MODULUS
        });
        Fp16::from_coefficients(coordinates).expect("canonical deterministic field element")
    }

    fn gate_at_node(gate: PackedBinaryGate, left: bool, right: bool) -> Fp16 {
        let left = if left { Fp16::ONE } else { Fp16::ZERO };
        let right = if right { Fp16::ONE } else { Fp16::ZERO };
        match gate {
            PackedBinaryGate::Xor => left + right - left * right - left * right,
            PackedBinaryGate::NotLeftAndRight => right - left * right,
            PackedBinaryGate::NotXor => Fp16::ONE - left - right + left * right + left * right,
        }
    }

    #[test]
    fn degree_forty_five_message_matches_all_nodes_and_challenge() {
        const CLAIMS: usize = 3;
        let gates = [
            PackedBinaryGate::Xor,
            PackedBinaryGate::NotLeftAndRight,
            PackedBinaryGate::NotXor,
            PackedBinaryGate::Xor,
        ];
        let left = [0xa53cu16, 0x0ff0, 0x81e7, 0x5aa5];
        let right = [0xc369u16, 0xf00f, 0x3c7e, 0xa55a];
        let weights: alloc::vec::Vec<[Fp16; CLAIMS]> = (0..gates.len())
            .map(|term| core::array::from_fn(|claim| field((1 + term * 101 + claim * 17) as u64)))
            .collect();
        let queries = core::array::from_fn(|claim| field((700 + claim * 31) as u64));
        let message =
            packed_binary_round_message(&gates, &left, &right, &weights, &queries).unwrap();
        assert_ne!(message[PACKED_BINARY_MESSAGE_COEFFICIENTS - 1], Fp16::ZERO);

        let basis = lagrange_basis();
        let node_sum = (0..PACKED_INSTANCES).fold(Fp16::ZERO, |sum, node| {
            sum + evaluate_message(
                &message,
                Fp16::from_m31(M31::from_canonical(node as u32).unwrap()),
            )
        });
        let expected_node_sum = (0..PACKED_INSTANCES).fold(Fp16::ZERO, |node_sum, node| {
            let claim_sum = (0..CLAIMS).fold(Fp16::ZERO, |claim_sum, claim| {
                let selector = lagrange_evaluations(&basis, queries[claim])[node];
                let term_sum = (0..gates.len()).fold(Fp16::ZERO, |term_sum, term| {
                    term_sum
                        + weights[term][claim]
                            * gate_at_node(
                                gates[term],
                                (left[term] >> node) & 1 == 1,
                                (right[term] >> node) & 1 == 1,
                            )
                });
                claim_sum + selector * term_sum
            });
            node_sum + claim_sum
        });
        assert_eq!(node_sum, expected_node_sum);

        let challenge = field(9_001);
        let at_challenge = lagrange_evaluations(&basis, challenge);
        let expected_at_challenge = (0..CLAIMS).fold(Fp16::ZERO, |claim_sum, claim| {
            let selector = (0..PACKED_INSTANCES).fold(Fp16::ZERO, |sum, position| {
                sum + lagrange_evaluations(&basis, queries[claim])[position]
                    * at_challenge[position]
            });
            let relation_sum = (0..gates.len()).fold(Fp16::ZERO, |sum, term| {
                let left_at_challenge =
                    evaluate(&interpolate_pattern(&basis, left[term]), challenge);
                let right_at_challenge =
                    evaluate(&interpolate_pattern(&basis, right[term]), challenge);
                let relation = match gates[term] {
                    PackedBinaryGate::Xor => {
                        left_at_challenge + right_at_challenge
                            - left_at_challenge * right_at_challenge
                            - left_at_challenge * right_at_challenge
                    }
                    PackedBinaryGate::NotLeftAndRight => {
                        right_at_challenge - left_at_challenge * right_at_challenge
                    }
                    PackedBinaryGate::NotXor => {
                        Fp16::ONE - left_at_challenge - right_at_challenge
                            + left_at_challenge * right_at_challenge
                            + left_at_challenge * right_at_challenge
                    }
                };
                sum + weights[term][claim] * relation
            });
            claim_sum + selector * relation_sum
        });
        assert_eq!(evaluate_message(&message, challenge), expected_at_challenge);
    }

    #[test]
    fn pattern_evaluation_matches_every_boolean_node_and_direct_interpolation() {
        let pattern = 0xa53c_u16;
        for node in 0..PACKED_INSTANCES {
            let point = Fp16::from_m31(M31::from_canonical(node as u32).unwrap());
            assert_eq!(
                evaluate_pattern(pattern, point),
                if (pattern >> node) & 1 == 0 {
                    Fp16::ZERO
                } else {
                    Fp16::ONE
                }
            );
        }
        let challenge = field(19_771);
        assert_eq!(
            evaluate_pattern(pattern, challenge),
            evaluate(&interpolate_pattern(&lagrange_basis(), pattern), challenge)
        );
    }

    #[test]
    fn claims_with_one_shared_packed_query_combine_before_the_bridge() {
        const CLAIMS: usize = 3;
        let gates = [
            PackedBinaryGate::Xor,
            PackedBinaryGate::NotLeftAndRight,
            PackedBinaryGate::NotXor,
        ];
        let left = [0xa53cu16, 0x0ff0, 0x81e7];
        let right = [0xc369u16, 0xf00f, 0x3c7e];
        let weights: alloc::vec::Vec<[Fp16; CLAIMS]> = (0..gates.len())
            .map(|term| core::array::from_fn(|claim| field((5 + term * 71 + claim * 29) as u64)))
            .collect();
        let shared_query = field(12_001);
        let separate =
            packed_binary_round_message(&gates, &left, &right, &weights, &[shared_query; CLAIMS])
                .unwrap();
        let combined_weights: alloc::vec::Vec<[Fp16; 1]> = weights
            .iter()
            .map(|term_weights| {
                [term_weights
                    .iter()
                    .copied()
                    .fold(Fp16::ZERO, |sum, weight| sum + weight)]
            })
            .collect();
        let combined =
            packed_binary_round_message(&gates, &left, &right, &combined_weights, &[shared_query])
                .unwrap();
        assert_eq!(separate, combined);
    }

    #[test]
    fn bounded_moment_bridge_matches_direct_polynomial_construction() {
        const CLAIMS: usize = 4;
        let mut gates = Vec::new();
        let mut left = Vec::new();
        let mut right = Vec::new();
        let mut weights = Vec::<[Fp16; CLAIMS]>::new();
        for term in 0..97 {
            gates.push(match term % 3 {
                0 => PackedBinaryGate::Xor,
                1 => PackedBinaryGate::NotLeftAndRight,
                _ => PackedBinaryGate::NotXor,
            });
            left.push((term as u16).wrapping_mul(0xa53d).rotate_left(3));
            right.push((term as u16).wrapping_mul(0xc36b).rotate_right(5));
            weights.push(core::array::from_fn(|claim| {
                field((50_000 + term * 101 + claim * 17) as u64)
            }));
        }
        let queries = core::array::from_fn(|claim| field((70_000 + claim * 131) as u64));
        let direct =
            packed_binary_round_message(&gates, &left, &right, &weights, &queries).unwrap();
        let bounded =
            packed_binary_round_message_from_moments(&gates, &left, &right, &weights, &queries)
                .unwrap();
        assert_eq!(bounded, direct);
    }

    #[test]
    fn rejects_empty_and_mismatched_shapes() {
        assert_eq!(
            packed_binary_round_message::<1>(&[], &[], &[], &[], &[Fp16::ONE]),
            Err(PackedBinaryBridgeError::Empty)
        );
        assert_eq!(
            packed_binary_round_message::<1>(
                &[PackedBinaryGate::Xor],
                &[],
                &[0],
                &[[Fp16::ONE]],
                &[Fp16::ONE],
            ),
            Err(PackedBinaryBridgeError::Shape)
        );
    }
}
