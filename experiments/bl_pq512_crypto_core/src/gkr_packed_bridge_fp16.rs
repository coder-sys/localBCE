//! Nonactivating exact `B=16` univariate bridge in the frozen M31/Fp16 field.
//!
//! The prover publishes the complete degree-30 coefficient vector before the
//! authenticated challenge. One Fp16 lane is sufficient for the frozen
//! soundness floor; no independent-lane amplification is used here.

use crate::field::{Fp16, M31};

pub const PACKED_INSTANCES: usize = 16;
pub const PACKED_MESSAGE_COEFFICIENTS: usize = 31;

pub type LagrangeBasis = [[Fp16; PACKED_INSTANCES]; PACKED_INSTANCES];

fn nodes() -> [Fp16; PACKED_INSTANCES] {
    core::array::from_fn(|index| {
        Fp16::from_m31(M31::from_canonical(index as u32).expect("small public node"))
    })
}

pub fn lagrange_basis() -> LagrangeBasis {
    let nodes = nodes();
    let mut basis = [[Fp16::ZERO; PACKED_INSTANCES]; PACKED_INSTANCES];
    for point in 0..PACKED_INSTANCES {
        let mut polynomial = [Fp16::ZERO; PACKED_INSTANCES];
        polynomial[0] = Fp16::ONE;
        let mut degree = 0;
        let mut denominator = Fp16::ONE;
        for other in 0..PACKED_INSTANCES {
            if other == point {
                continue;
            }
            let mut next = [Fp16::ZERO; PACKED_INSTANCES];
            for coefficient in 0..=degree {
                next[coefficient] = next[coefficient] - polynomial[coefficient] * nodes[other];
                next[coefficient + 1] = next[coefficient + 1] + polynomial[coefficient];
            }
            polynomial = next;
            degree += 1;
            denominator = denominator * (nodes[point] - nodes[other]);
        }
        let inverse = denominator
            .inverse()
            .expect("distinct public interpolation nodes");
        for coefficient in &mut polynomial {
            *coefficient = *coefficient * inverse;
        }
        basis[point] = polynomial;
    }
    basis
}

pub fn evaluate(polynomial: &[Fp16], point: Fp16) -> Fp16 {
    polynomial
        .iter()
        .rev()
        .fold(Fp16::ZERO, |value, coefficient| {
            value * point + *coefficient
        })
}

pub fn lagrange_evaluations(basis: &LagrangeBasis, point: Fp16) -> [Fp16; PACKED_INSTANCES] {
    core::array::from_fn(|position| evaluate(&basis[position], point))
}

fn equality_kernel(basis: &LagrangeBasis, query: Fp16) -> [Fp16; PACKED_INSTANCES] {
    let query_evaluations = lagrange_evaluations(basis, query);
    let mut polynomial = [Fp16::ZERO; PACKED_INSTANCES];
    for position in 0..PACKED_INSTANCES {
        for coefficient in 0..PACKED_INSTANCES {
            polynomial[coefficient] = polynomial[coefficient]
                + basis[position][coefficient] * query_evaluations[position];
        }
    }
    polynomial
}

pub fn packed_round_message<const CLAIMS: usize>(
    basis: &LagrangeBasis,
    position_weights: &[[Fp16; PACKED_INSTANCES]; CLAIMS],
    output_queries: &[Fp16; CLAIMS],
) -> [Fp16; PACKED_MESSAGE_COEFFICIENTS] {
    let mut message = [Fp16::ZERO; PACKED_MESSAGE_COEFFICIENTS];
    for claim in 0..CLAIMS {
        let kernel = equality_kernel(basis, output_queries[claim]);
        let mut relation = [Fp16::ZERO; PACKED_INSTANCES];
        for position in 0..PACKED_INSTANCES {
            for coefficient in 0..PACKED_INSTANCES {
                relation[coefficient] = relation[coefficient]
                    + position_weights[claim][position] * basis[position][coefficient];
            }
        }
        for left in 0..PACKED_INSTANCES {
            for right in 0..PACKED_INSTANCES {
                message[left + right] = message[left + right] + relation[left] * kernel[right];
            }
        }
    }
    message
}

pub fn evaluate_message(message: &[Fp16; PACKED_MESSAGE_COEFFICIENTS], point: Fp16) -> Fp16 {
    evaluate(message, point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::M31_MODULUS;

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

    #[test]
    fn basis_is_exact_on_all_sixteen_public_nodes() {
        let basis = lagrange_basis();
        let nodes = nodes();
        for (position, polynomial) in basis.iter().enumerate() {
            for (node, value) in nodes.iter().enumerate() {
                assert_eq!(
                    evaluate(polynomial, *value),
                    if position == node {
                        Fp16::ONE
                    } else {
                        Fp16::ZERO
                    }
                );
            }
        }
    }

    #[test]
    fn published_degree_thirty_message_matches_sum_and_challenge_claims() {
        const CLAIMS: usize = 3;
        let basis = lagrange_basis();
        let nodes = nodes();
        let position_weights: [[Fp16; PACKED_INSTANCES]; CLAIMS] = core::array::from_fn(|claim| {
            core::array::from_fn(|position| field((1 + claim * 97 + position * 11) as u64))
        });
        let output_queries: [Fp16; CLAIMS] =
            core::array::from_fn(|claim| field((3 + claim * 19) as u64));
        let challenge = field(701);
        let message = packed_round_message(&basis, &position_weights, &output_queries);
        assert_ne!(message[PACKED_MESSAGE_COEFFICIENTS - 1], Fp16::ZERO);

        let node_sum = nodes.iter().fold(Fp16::ZERO, |sum, node| {
            sum + evaluate_message(&message, *node)
        });
        let expected_sum = (0..CLAIMS).fold(Fp16::ZERO, |claim_sum, claim| {
            let query = lagrange_evaluations(&basis, output_queries[claim]);
            claim_sum
                + (0..PACKED_INSTANCES).fold(Fp16::ZERO, |position_sum, position| {
                    position_sum + position_weights[claim][position] * query[position]
                })
        });
        assert_eq!(node_sum, expected_sum);

        let at_challenge = lagrange_evaluations(&basis, challenge);
        let expected_challenge = (0..CLAIMS).fold(Fp16::ZERO, |claim_sum, claim| {
            let at_query = lagrange_evaluations(&basis, output_queries[claim]);
            let equality = (0..PACKED_INSTANCES).fold(Fp16::ZERO, |sum, position| {
                sum + at_query[position] * at_challenge[position]
            });
            let relation = (0..PACKED_INSTANCES).fold(Fp16::ZERO, |sum, position| {
                sum + position_weights[claim][position] * at_challenge[position]
            });
            claim_sum + equality * relation
        });
        assert_eq!(evaluate_message(&message, challenge), expected_challenge);
    }
}
