//! Nonactivating exact `B=16` univariate bridge for the binary-native GKR.
//!
//! Sixteen Boolean instances are represented at the distinct polynomial-basis
//! points `0..15` in `GF(2^128)`. The prover publishes the complete
//! degree-30 coefficient vector before the authenticated challenge. This
//! replaces four Boolean-coordinate rounds with one message/challenge round
//! without pre-sampling or reusing the challenge.

use crate::gf128::{Gf128, Gf128Triple};

pub const PACKED_INSTANCES: usize = 16;
pub const PACKED_MESSAGE_COEFFICIENTS: usize = 31;

pub type LagrangeBasis = [[Gf128; PACKED_INSTANCES]; PACKED_INSTANCES];

fn nodes() -> [Gf128; PACKED_INSTANCES] {
    core::array::from_fn(|index| Gf128::from_u128(index as u128))
}

pub fn lagrange_basis() -> LagrangeBasis {
    let nodes = nodes();
    let mut basis = [[Gf128::ZERO; PACKED_INSTANCES]; PACKED_INSTANCES];
    for point in 0..PACKED_INSTANCES {
        let mut polynomial = [Gf128::ZERO; PACKED_INSTANCES];
        polynomial[0] = Gf128::ONE;
        let mut degree = 0;
        let mut denominator = Gf128::ONE;
        for other in 0..PACKED_INSTANCES {
            if other == point {
                continue;
            }
            let mut next = [Gf128::ZERO; PACKED_INSTANCES];
            for coefficient in 0..=degree {
                next[coefficient] += polynomial[coefficient] * nodes[other];
                next[coefficient + 1] += polynomial[coefficient];
            }
            polynomial = next;
            degree += 1;
            denominator *= nodes[point] + nodes[other];
        }
        let inverse = denominator
            .inverse()
            .expect("distinct public interpolation nodes");
        for coefficient in &mut polynomial {
            *coefficient *= inverse;
        }
        basis[point] = polynomial;
    }
    basis
}

pub fn evaluate(polynomial: &[Gf128], point: Gf128) -> Gf128 {
    polynomial
        .iter()
        .rev()
        .fold(Gf128::ZERO, |value, coefficient| {
            value * point + *coefficient
        })
}

pub fn lagrange_evaluations(basis: &LagrangeBasis, point: Gf128) -> [Gf128; PACKED_INSTANCES] {
    core::array::from_fn(|position| evaluate(&basis[position], point))
}

fn equality_kernel(basis: &LagrangeBasis, query: Gf128) -> [Gf128; PACKED_INSTANCES] {
    let query_evaluations = lagrange_evaluations(basis, query);
    let mut polynomial = [Gf128::ZERO; PACKED_INSTANCES];
    for position in 0..PACKED_INSTANCES {
        for coefficient in 0..PACKED_INSTANCES {
            polynomial[coefficient] += basis[position][coefficient] * query_evaluations[position];
        }
    }
    polynomial
}

pub fn packed_round_message<const CLAIMS: usize>(
    basis: &LagrangeBasis,
    position_weights: &[[Gf128Triple; PACKED_INSTANCES]; CLAIMS],
    output_queries: &[[Gf128; 3]; CLAIMS],
) -> [Gf128Triple; PACKED_MESSAGE_COEFFICIENTS] {
    let mut message = [Gf128Triple::ZERO; PACKED_MESSAGE_COEFFICIENTS];
    for claim in 0..CLAIMS {
        for (lane, output_query) in output_queries[claim].iter().copied().enumerate() {
            let kernel = equality_kernel(basis, output_query);
            let mut relation = [Gf128::ZERO; PACKED_INSTANCES];
            for position in 0..PACKED_INSTANCES {
                let weight = position_weights[claim][position].0[lane];
                for coefficient in 0..PACKED_INSTANCES {
                    relation[coefficient] += weight * basis[position][coefficient];
                }
            }
            for left in 0..PACKED_INSTANCES {
                for right in 0..PACKED_INSTANCES {
                    message[left + right].0[lane] += relation[left] * kernel[right];
                }
            }
        }
    }
    message
}

pub fn evaluate_message(
    message: &[Gf128Triple; PACKED_MESSAGE_COEFFICIENTS],
    point: [Gf128; 3],
) -> Gf128Triple {
    Gf128Triple(core::array::from_fn(|lane| {
        message
            .iter()
            .rev()
            .fold(Gf128::ZERO, |value, coefficient| {
                value * point[lane] + coefficient.0[lane]
            })
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(seed: u128) -> Gf128 {
        Gf128::from_u128(
            seed.wrapping_mul(0x9e37_79b9_7f4a_7c15_d6e8_feb8_6659_fd93)
                ^ 0xa409_3822_299f_31d0_082e_fa98_ec4e_6c89,
        )
    }

    #[test]
    fn basis_is_exact_on_all_sixteen_public_nodes() {
        let basis = lagrange_basis();
        for (position, polynomial) in basis.iter().enumerate() {
            for node in 0..PACKED_INSTANCES {
                assert_eq!(
                    evaluate(polynomial, Gf128::from_u128(node as u128)),
                    if position == node {
                        Gf128::ONE
                    } else {
                        Gf128::ZERO
                    }
                );
            }
        }
    }

    #[test]
    fn published_degree_thirty_message_matches_sum_and_challenge_claims() {
        const CLAIMS: usize = 3;
        let basis = lagrange_basis();
        let position_weights: [[Gf128Triple; PACKED_INSTANCES]; CLAIMS] =
            core::array::from_fn(|claim| {
                core::array::from_fn(|position| {
                    Gf128Triple(core::array::from_fn(|lane| {
                        field((1 + claim * 97 + position * 11 + lane * 43) as u128)
                    }))
                })
            });
        let output_queries: [[Gf128; 3]; CLAIMS] = core::array::from_fn(|claim| {
            core::array::from_fn(|lane| field((3 + claim * 19 + lane * 29) as u128))
        });
        let challenge = core::array::from_fn(|lane| field((701 + lane * 101) as u128));
        let message = packed_round_message(&basis, &position_weights, &output_queries);
        assert_ne!(message[PACKED_MESSAGE_COEFFICIENTS - 1], Gf128Triple::ZERO);

        let node_sum = (0..PACKED_INSTANCES).fold(Gf128Triple::ZERO, |sum, node| {
            sum + evaluate_message(&message, [Gf128::from_u128(node as u128); 3])
        });
        let expected_sum = Gf128Triple(core::array::from_fn(|lane| {
            (0..CLAIMS).fold(Gf128::ZERO, |claim_sum, claim| {
                let query = lagrange_evaluations(&basis, output_queries[claim][lane]);
                claim_sum
                    + (0..PACKED_INSTANCES).fold(Gf128::ZERO, |position_sum, position| {
                        position_sum + position_weights[claim][position].0[lane] * query[position]
                    })
            })
        }));
        assert_eq!(node_sum, expected_sum);

        let expected_challenge = Gf128Triple(core::array::from_fn(|lane| {
            let at_challenge = lagrange_evaluations(&basis, challenge[lane]);
            (0..CLAIMS).fold(Gf128::ZERO, |claim_sum, claim| {
                let at_query = lagrange_evaluations(&basis, output_queries[claim][lane]);
                let equality = (0..PACKED_INSTANCES).fold(Gf128::ZERO, |sum, position| {
                    sum + at_query[position] * at_challenge[position]
                });
                let relation = (0..PACKED_INSTANCES).fold(Gf128::ZERO, |sum, position| {
                    sum + position_weights[claim][position].0[lane] * at_challenge[position]
                });
                claim_sum + equality * relation
            })
        }));
        assert_eq!(evaluate_message(&message, challenge), expected_challenge);
    }
}
