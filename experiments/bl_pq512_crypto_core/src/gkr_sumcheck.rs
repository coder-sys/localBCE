//! Interactive Fp16 degree-two sumcheck control for the Boolean-GKR plane.
//!
//! Challenges are supplied by the authenticated public-coin schedule. This
//! module deliberately contains no Fiat--Shamir transform.

use core::fmt;

use alloc::{vec, vec::Vec};

#[cfg(any(test, not(feature = "control_reference")))]
use crate::keccak_gkr_wiring::{
    KECCAK_GKR_LAYERS_PER_ROUND, packed_keccak_gkr_round_checkpoints,
    regenerate_packed_keccak_gkr_round_inputs,
};
#[cfg(feature = "parallel")]
use crate::packed_boolean_sumcheck::reduce_packed_boolean_indexed_parallel;
use crate::{
    field::Fp16,
    gkr_zk_mask::{
        CommittedMaskedSumcheckState, GkrZkMaskError, LibraLayerMask, LibraPriorLayerCorrection,
        LibraVariableDegreeSumcheckMask, polynomial_evaluation, terminal_vanishing_coefficient,
    },
    keccak_gkr_dag::{KeccakDagGateKind, KeccakDagLayer},
    keccak_gkr_wiring::{
        BooleanGate, BooleanGateKind, BooleanWire, KeccakGkrLayer, evaluate_keccak_gkr_layer,
    },
    packed_boolean_sumcheck::{
        PACK_BITS, PackedBooleanError, PackedBooleanGate, PackedBooleanTable,
        PackedReductionReport, evaluate_packed_lagrange_values, reduce_packed_boolean_layer,
        verify_packed_first_round_bridge,
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductSumcheckProof {
    pub rounds: Vec<[Fp16; 3]>,
    pub terminal_left: Fp16,
    pub terminal_right: Fp16,
}

#[cfg(test)]
mod relay_free_dag_tests {
    use super::*;
    use crate::{
        M31,
        keccak_gkr_dag::{
            KeccakDagGate, KeccakDagGateKind, KeccakDagLayer, KeccakDagSource,
            build_keccak_gkr_dag_round, evaluate_keccak_gkr_dag_round,
        },
    };

    fn fp16(value: usize) -> Fp16 {
        Fp16::from_m31(M31::from_canonical((value as u32 % 2_147_483_646) + 1).unwrap())
    }

    fn point(variables: usize, domain: usize) -> Vec<Fp16> {
        (0..variables)
            .map(|coordinate| fp16(17 + 97 * domain + 13 * coordinate))
            .collect()
    }

    fn source_index(source: KeccakDagSource) -> usize {
        match source {
            KeccakDagSource::RoundInput => 0,
            KeccakDagSource::Layer(index) => index + 1,
        }
    }

    struct CpuMaskedSharedGroupOracle {
        layer: KeccakDagLayer,
        left: Vec<Fp16>,
        right: Vec<Fp16>,
        claims: Vec<LayerOutputClaim>,
        output_weights: Vec<Vec<Fp16>>,
        prefixes: Vec<Fp16>,
        output_variables: usize,
        current_groups: usize,
        next_round: usize,
        mutate_round: Option<usize>,
        accelerate_wire: bool,
        group_challenges: Vec<Fp16>,
        wire_terms: Vec<SparseGateTerm>,
        left_factors: Vec<Fp16>,
        right_factors: Vec<Fp16>,
        right_group_folded: Vec<Fp16>,
        next_left_wire_round: usize,
        next_right_wire_round: usize,
        pending_wire_round: Option<(SharedGroupDagRoundKind, usize)>,
        mutate_wire_round: Option<(SharedGroupDagRoundKind, usize)>,
    }

    impl CpuMaskedSharedGroupOracle {
        fn new(
            layer: &KeccakDagLayer,
            group_count: usize,
            left: &[Fp16],
            right: &[Fp16],
            claims: &[LayerOutputClaim],
        ) -> Self {
            let output_variables = layer.padded_width.trailing_zeros() as usize;
            Self {
                layer: layer.clone(),
                left: left.to_vec(),
                right: right.to_vec(),
                claims: claims.to_vec(),
                output_weights: claims
                    .iter()
                    .map(|claim| equality_table(&claim.point[..output_variables]).unwrap())
                    .collect(),
                prefixes: vec![Fp16::ONE; claims.len()],
                output_variables,
                current_groups: group_count,
                next_round: 0,
                mutate_round: None,
                accelerate_wire: false,
                group_challenges: Vec::new(),
                wire_terms: Vec::new(),
                left_factors: Vec::new(),
                right_factors: Vec::new(),
                right_group_folded: Vec::new(),
                next_left_wire_round: 0,
                next_right_wire_round: 0,
                pending_wire_round: None,
                mutate_wire_round: None,
            }
        }

        fn with_wire_acceleration(mut self) -> Self {
            self.accelerate_wire = true;
            self
        }
    }

    impl MaskedSharedGroupOracle for CpuMaskedSharedGroupOracle {
        fn raw_group_round(
            &mut self,
            round: usize,
            expected_claim: Fp16,
        ) -> Result<[Fp16; 4], GkrZkMaskError> {
            if round != self.next_round {
                return Err(GkrZkMaskError::Sequence);
            }
            let mut raw = shared_group_round_polynomial(
                &self.layer,
                &self.left,
                &self.right,
                &self.claims,
                &self.output_weights,
                &self.prefixes,
                self.output_variables,
                round,
            )
            .map_err(|_| GkrZkMaskError::Shape)?;
            if self.mutate_round == Some(round) {
                raw[1] = raw[1] + Fp16::ONE;
            }
            if raw[0] + raw[0] + raw[1] + raw[2] + raw[3] != expected_claim {
                return Err(GkrZkMaskError::Claim);
            }
            Ok(raw)
        }

        fn accept_group_challenge(
            &mut self,
            round: usize,
            challenge: Fp16,
        ) -> Result<(), GkrZkMaskError> {
            if round != self.next_round || self.current_groups < 2 {
                return Err(GkrZkMaskError::Sequence);
            }
            for (claim_index, claim) in self.claims.iter().enumerate() {
                self.prefixes[claim_index] = self.prefixes[claim_index]
                    * equality_line_value(claim.point[self.output_variables + round], challenge);
            }
            self.left = fold_shared_group_axis(
                &self.left,
                self.layer.left_width,
                self.current_groups,
                challenge,
            )
            .map_err(|_| GkrZkMaskError::Shape)?;
            self.right = fold_shared_group_axis(
                &self.right,
                self.layer.right_width,
                self.current_groups,
                challenge,
            )
            .map_err(|_| GkrZkMaskError::Shape)?;
            self.current_groups /= 2;
            self.next_round += 1;
            self.group_challenges.push(challenge);
            Ok(())
        }

        fn folded_sources(&mut self) -> Result<(Vec<Fp16>, Vec<Fp16>), GkrZkMaskError> {
            if self.current_groups != 1 {
                return Err(GkrZkMaskError::Sequence);
            }
            if self.accelerate_wire {
                let effective = shared_group_effective_claims(
                    &self.claims,
                    self.output_variables,
                    &self.group_challenges,
                )
                .map_err(|_| GkrZkMaskError::Shape)?;
                self.wire_terms =
                    dag_layer_terms(&self.layer, &effective).map_err(|_| GkrZkMaskError::Shape)?;
                self.left_factors = vec![Fp16::ONE; self.wire_terms.len()];
                self.right_factors = vec![Fp16::ONE; self.wire_terms.len()];
                self.right_group_folded = self.right.clone();
            }
            Ok((self.left.clone(), self.right.clone()))
        }

        fn accelerates_wire_rounds(&self) -> bool {
            self.accelerate_wire
        }

        fn raw_wire_round(
            &mut self,
            kind: SharedGroupDagRoundKind,
            round: usize,
            masked_terminal_left: Option<Fp16>,
        ) -> Result<[Fp16; 3], GkrZkMaskError> {
            if !self.accelerate_wire || self.pending_wire_round.is_some() {
                return Err(GkrZkMaskError::Sequence);
            }
            let mut raw = [Fp16::ZERO; 3];
            match kind {
                SharedGroupDagRoundKind::LeftWire => {
                    if round != self.next_left_wire_round || masked_terminal_left.is_some() {
                        return Err(GkrZkMaskError::Sequence);
                    }
                    for (term_index, term) in self.wire_terms.iter().enumerate() {
                        let suffix = term.left >> (round + 1);
                        let zero = self.left[2 * suffix];
                        let delta = self.left[2 * suffix + 1] - zero;
                        let (gate_zero, gate_delta) = gate_line(
                            term.formula,
                            true,
                            zero,
                            delta,
                            self.right_group_folded[term.right],
                        );
                        let contribution = weighted_gate_quadratic(
                            term.output_weight * self.left_factors[term_index],
                            (term.left >> round) & 1,
                            gate_zero,
                            gate_delta,
                        );
                        for degree in 0..3 {
                            raw[degree] = raw[degree] + contribution[degree];
                        }
                    }
                }
                SharedGroupDagRoundKind::RightWire => {
                    if round != self.next_right_wire_round
                        || self.next_left_wire_round
                            != self.layer.left_width.trailing_zeros() as usize
                    {
                        return Err(GkrZkMaskError::Sequence);
                    }
                    let terminal = masked_terminal_left.ok_or(GkrZkMaskError::Sequence)?;
                    for (term_index, term) in self.wire_terms.iter().enumerate() {
                        let suffix = term.right >> (round + 1);
                        let zero = self.right[2 * suffix];
                        let delta = self.right[2 * suffix + 1] - zero;
                        let (gate_zero, gate_delta) =
                            gate_line(term.formula, false, zero, delta, terminal);
                        let contribution = weighted_gate_quadratic(
                            term.output_weight
                                * self.left_factors[term_index]
                                * self.right_factors[term_index],
                            (term.right >> round) & 1,
                            gate_zero,
                            gate_delta,
                        );
                        for degree in 0..3 {
                            raw[degree] = raw[degree] + contribution[degree];
                        }
                    }
                }
                SharedGroupDagRoundKind::Group => return Err(GkrZkMaskError::Sequence),
            }
            if self.mutate_wire_round == Some((kind, round)) {
                raw[1] = raw[1] + Fp16::ONE;
            }
            self.pending_wire_round = Some((kind, round));
            Ok(raw)
        }

        fn accept_wire_challenge(
            &mut self,
            kind: SharedGroupDagRoundKind,
            round: usize,
            challenge: Fp16,
        ) -> Result<(), GkrZkMaskError> {
            if self.pending_wire_round != Some((kind, round)) {
                return Err(GkrZkMaskError::Sequence);
            }
            match kind {
                SharedGroupDagRoundKind::LeftWire => {
                    for (factor, term) in self.left_factors.iter_mut().zip(&self.wire_terms) {
                        *factor = *factor * bit_basis(challenge, (term.left >> round) & 1);
                    }
                    fold_multilinear(&mut self.left, challenge);
                    self.next_left_wire_round += 1;
                }
                SharedGroupDagRoundKind::RightWire => {
                    for (factor, term) in self.right_factors.iter_mut().zip(&self.wire_terms) {
                        *factor = *factor * bit_basis(challenge, (term.right >> round) & 1);
                    }
                    fold_multilinear(&mut self.right, challenge);
                    self.next_right_wire_round += 1;
                }
                SharedGroupDagRoundKind::Group => return Err(GkrZkMaskError::Sequence),
            }
            self.pending_wire_round = None;
            Ok(())
        }
    }

    #[test]
    fn two_source_reference_proves_every_relay_free_dag_edge() {
        let round = 17;
        let layers = build_keccak_gkr_dag_round(round).unwrap();
        let mut round_input_bits = vec![false; 2_048];
        for (index, value) in round_input_bits[..1_600].iter_mut().enumerate() {
            let mixed = (index as u64 + 1)
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .rotate_left((index % 63 + 1) as u32);
            *value = mixed.count_ones() & 1 == 1;
        }
        let boolean_boundaries = evaluate_keccak_gkr_dag_round(&layers, &round_input_bits).unwrap();
        let round_input = round_input_bits
            .iter()
            .map(|value| if *value { Fp16::ONE } else { Fp16::ZERO })
            .collect::<Vec<_>>();
        let boundaries = boolean_boundaries
            .iter()
            .map(|boundary| {
                boundary
                    .iter()
                    .map(|value| if *value { Fp16::ONE } else { Fp16::ZERO })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let mut pending = vec![Vec::<LayerOutputClaim>::new(); layers.len() + 1];
        let output_point = point(
            layers.last().unwrap().padded_width.trailing_zeros() as usize,
            0,
        );
        pending[layers.len()].push(LayerOutputClaim {
            value: multilinear_evaluate(boundaries.last().unwrap(), &output_point).unwrap(),
            point: output_point,
            coefficient: Fp16::ONE,
        });

        let mut proofs = Vec::new();
        for layer_index in (0..layers.len()).rev() {
            let layer = &layers[layer_index];
            let left_index = source_index(layer.left_source);
            let right_index = source_index(layer.right_source);
            let left = if left_index == 0 {
                &round_input
            } else {
                &boundaries[left_index - 1]
            };
            let right = if right_index == 0 {
                &round_input
            } else {
                &boundaries[right_index - 1]
            };
            let claims = pending[layer_index + 1].clone();
            assert!(!claims.is_empty(), "layer={layer_index}");
            let left_variables = layer.left_width.trailing_zeros() as usize;
            let right_variables = layer.right_width.trailing_zeros() as usize;
            let challenges = point(left_variables + right_variables, layer_index + 1);
            let proof = prove_two_source_sparse_gkr_layer_reference(
                layer,
                left,
                right,
                &claims,
                &challenges,
            )
            .unwrap();
            verify_two_source_sparse_gkr_layer_reference(layer, &claims, &challenges, &proof)
                .unwrap();
            assert_eq!(
                proof.terminal_left,
                multilinear_evaluate(left, &challenges[..left_variables]).unwrap()
            );
            assert_eq!(
                proof.terminal_right,
                multilinear_evaluate(right, &challenges[left_variables..]).unwrap()
            );
            pending[left_index].push(LayerOutputClaim {
                point: challenges[..left_variables].to_vec(),
                value: proof.terminal_left,
                coefficient: fp16(1_000 + 2 * layer_index),
            });
            pending[right_index].push(LayerOutputClaim {
                point: challenges[left_variables..].to_vec(),
                value: proof.terminal_right,
                coefficient: fp16(1_001 + 2 * layer_index),
            });
            proofs.push((layer_index, claims, challenges, proof));
        }

        assert_eq!(proofs.len(), 7);
        assert_eq!(pending[0].len(), 4);
        for claim in &pending[0] {
            assert_eq!(
                multilinear_evaluate(&round_input, &claim.point).unwrap(),
                claim.value
            );
        }

        let (layer_index, claims, challenges, proof) = &proofs[0];
        let mut forged = proof.clone();
        forged.rounds[0][0] = forged.rounds[0][0] + Fp16::ONE;
        assert_eq!(
            verify_two_source_sparse_gkr_layer_reference(
                &layers[*layer_index],
                claims,
                challenges,
                &forged
            ),
            Err(ProductSumcheckError::Claim)
        );
    }

    #[test]
    fn shared_group_reduction_matches_the_full_boolean_relation() {
        let gates = vec![
            KeccakDagGate {
                left: 0,
                right: 1,
                kind: KeccakDagGateKind::Xor,
            },
            KeccakDagGate {
                left: 2,
                right: 3,
                kind: KeccakDagGateKind::NotLeftAndRight,
            },
            KeccakDagGate {
                left: 1,
                right: 2,
                kind: KeccakDagGateKind::XorConstant(true),
            },
            KeccakDagGate {
                left: 3,
                right: 0,
                kind: KeccakDagGateKind::XorConstant(false),
            },
        ];
        let layer = KeccakDagLayer {
            left_source: KeccakDagSource::RoundInput,
            right_source: KeccakDagSource::RoundInput,
            left_width: 4,
            right_width: 4,
            raw_width: 4,
            padded_width: 4,
            gates: gates.clone(),
        };
        let group_count = 4;
        let left_input = (0..group_count * layer.left_width)
            .map(|index| fp16(2_001 + 7 * index))
            .collect::<Vec<_>>();
        let right_input = (0..group_count * layer.right_width)
            .map(|index| fp16(3_001 + 11 * index))
            .collect::<Vec<_>>();
        let mut output = Vec::with_capacity(group_count * layer.padded_width);
        for group in 0..group_count {
            output.extend(
                evaluate_dag_arithmetic_layer(
                    &layer,
                    &left_input[group * layer.left_width..(group + 1) * layer.left_width],
                    &right_input[group * layer.right_width..(group + 1) * layer.right_width],
                )
                .unwrap(),
            );
        }
        let claims = (0..2)
            .map(|claim_index| {
                let claim_point = point(4, 30 + claim_index);
                LayerOutputClaim {
                    value: multilinear_evaluate(&output, &claim_point).unwrap(),
                    point: claim_point,
                    coefficient: fp16(4_001 + 13 * claim_index),
                }
            })
            .collect::<Vec<_>>();
        let group_challenges = point(2, 40);
        let wire_challenges = point(4, 41);
        let proof = prove_shared_group_dag_layer_reference(
            &layer,
            group_count,
            &left_input,
            &right_input,
            &claims,
            &group_challenges,
            &wire_challenges,
        )
        .unwrap();
        verify_shared_group_dag_layer_reference(
            &layer,
            group_count,
            &claims,
            &group_challenges,
            &wire_challenges,
            &proof,
        )
        .unwrap();

        let mut left_terminal_point = wire_challenges[..2].to_vec();
        left_terminal_point.extend_from_slice(&group_challenges);
        let mut right_terminal_point = wire_challenges[2..].to_vec();
        right_terminal_point.extend_from_slice(&group_challenges);
        assert_eq!(
            proof.wire_proof.terminal_left,
            multilinear_evaluate(&left_input, &left_terminal_point).unwrap()
        );
        assert_eq!(
            proof.wire_proof.terminal_right,
            multilinear_evaluate(&right_input, &right_terminal_point).unwrap()
        );

        // The pre-existing dense-label control proves the same Boolean
        // relation. Reusing the same group challenge on its two source labels
        // also yields the same two authenticated source openings.
        let mut repeated_gates = Vec::with_capacity(group_count * layer.padded_width);
        for group in 0..group_count {
            repeated_gates.extend(gates.iter().map(|gate| KeccakDagGate {
                left: group * layer.left_width + gate.left,
                right: group * layer.right_width + gate.right,
                kind: gate.kind,
            }));
        }
        let repeated_layer = KeccakDagLayer {
            left_source: KeccakDagSource::RoundInput,
            right_source: KeccakDagSource::RoundInput,
            left_width: group_count * layer.left_width,
            right_width: group_count * layer.right_width,
            raw_width: group_count * layer.raw_width,
            padded_width: group_count * layer.padded_width,
            gates: repeated_gates,
        };
        let mut dense_challenges = wire_challenges[..2].to_vec();
        dense_challenges.extend_from_slice(&group_challenges);
        dense_challenges.extend_from_slice(&wire_challenges[2..]);
        dense_challenges.extend_from_slice(&group_challenges);
        let dense = prove_two_source_sparse_gkr_layer_reference(
            &repeated_layer,
            &left_input,
            &right_input,
            &claims,
            &dense_challenges,
        )
        .unwrap();
        verify_two_source_sparse_gkr_layer_reference(
            &repeated_layer,
            &claims,
            &dense_challenges,
            &dense,
        )
        .unwrap();
        assert_eq!(dense.terminal_left, proof.wire_proof.terminal_left);
        assert_eq!(dense.terminal_right, proof.wire_proof.terminal_right);

        let mut forged = proof.clone();
        forged.group_rounds[0][0] = forged.group_rounds[0][0] + Fp16::ONE;
        assert_eq!(
            verify_shared_group_dag_layer_reference(
                &layer,
                group_count,
                &claims,
                &group_challenges,
                &wire_challenges,
                &forged,
            ),
            Err(ProductSumcheckError::Claim)
        );
    }

    #[test]
    fn uniform_group_reduction_is_byte_exact_with_generic_reference() {
        let layer = build_keccak_gkr_dag_round(7).unwrap()[6].clone();
        let group_count = 8_usize;
        let left_wire_values = (0..layer.left_width)
            .map(|index| fp16(5_001 + 3 * index))
            .collect::<Vec<_>>();
        let right_wire_values = (0..layer.right_width)
            .map(|index| fp16(7_001 + 5 * index))
            .collect::<Vec<_>>();
        let left_input = (0..group_count)
            .flat_map(|_| left_wire_values.iter().copied())
            .collect::<Vec<_>>();
        let right_input = (0..group_count)
            .flat_map(|_| right_wire_values.iter().copied())
            .collect::<Vec<_>>();
        let output =
            evaluate_dag_arithmetic_layer(&layer, &left_wire_values, &right_wire_values).unwrap();
        let output_variables = layer.padded_width.trailing_zeros() as usize;
        let group_variables = group_count.trailing_zeros() as usize;
        let claims = (0..3)
            .map(|claim_index| {
                let claim_point = point(output_variables + group_variables, 90 + claim_index);
                LayerOutputClaim {
                    value: multilinear_evaluate(&output, &claim_point[..output_variables]).unwrap(),
                    point: claim_point,
                    coefficient: fp16(9_001 + 17 * claim_index),
                }
            })
            .collect::<Vec<_>>();
        let group_challenges = point(group_variables, 100);
        let wire_challenges = point(
            layer.left_width.trailing_zeros() as usize
                + layer.right_width.trailing_zeros() as usize,
            101,
        );

        let generic = prove_shared_group_dag_layer_reference(
            &layer,
            group_count,
            &left_input,
            &right_input,
            &claims,
            &group_challenges,
            &wire_challenges,
        )
        .unwrap();
        let uniform = prove_uniform_shared_group_dag_layer_reference(
            &layer,
            group_count,
            &left_wire_values,
            &right_wire_values,
            &claims,
            &group_challenges,
            &wire_challenges,
        )
        .unwrap();
        assert_eq!(uniform, generic);
        let (interactive, interactive_groups, interactive_wires) =
            prove_uniform_shared_group_dag_layer_interactive(
                &layer,
                group_count,
                &left_wire_values,
                &right_wire_values,
                &claims,
                |kind, round, message| {
                    assert!(!message.is_empty());
                    Ok(match kind {
                        SharedGroupDagRoundKind::Group => group_challenges[round],
                        SharedGroupDagRoundKind::LeftWire => wire_challenges[round],
                        SharedGroupDagRoundKind::RightWire => {
                            wire_challenges[layer.left_width.trailing_zeros() as usize + round]
                        }
                    })
                },
            )
            .unwrap();
        assert_eq!(interactive, generic);
        assert_eq!(interactive_groups, group_challenges);
        assert_eq!(interactive_wires, wire_challenges);
        verify_shared_group_dag_layer_reference(
            &layer,
            group_count,
            &claims,
            &group_challenges,
            &wire_challenges,
            &uniform,
        )
        .unwrap();

        let mut forged = uniform;
        forged.group_rounds[1][1] = forged.group_rounds[1][1] + Fp16::ONE;
        assert_eq!(
            verify_shared_group_dag_layer_reference(
                &layer,
                group_count,
                &claims,
                &group_challenges,
                &wire_challenges,
                &forged,
            ),
            Err(ProductSumcheckError::Claim)
        );
    }

    #[test]
    fn native_masked_uniform_reduction_applies_left_delta_before_right_side() {
        let layer = build_keccak_gkr_dag_round(7).unwrap()[6].clone();
        let group_count = 8_usize;
        let left_wire_values = (0..layer.left_width)
            .map(|index| fp16(12_001 + 3 * index))
            .collect::<Vec<_>>();
        let right_wire_values = (0..layer.right_width)
            .map(|index| fp16(14_001 + 5 * index))
            .collect::<Vec<_>>();
        let output =
            evaluate_dag_arithmetic_layer(&layer, &left_wire_values, &right_wire_values).unwrap();
        let output_variables = layer.padded_width.trailing_zeros() as usize;
        let group_variables = group_count.trailing_zeros() as usize;
        let claim_point = point(output_variables + group_variables, 201);
        let claims = vec![LayerOutputClaim {
            value: multilinear_evaluate(&output, &claim_point[..output_variables]).unwrap(),
            point: claim_point,
            coefficient: fp16(15_001),
        }];
        let left_variables = layer.left_width.trailing_zeros() as usize;
        let right_variables = layer.right_width.trailing_zeros() as usize;
        let mut degrees = vec![3; group_variables];
        degrees.extend(core::iter::repeat_n(2, left_variables));
        *degrees.last_mut().unwrap() = 3;
        degrees.extend(core::iter::repeat_n(2, right_variables));
        *degrees.last_mut().unwrap() = 3;
        degrees.push(2);
        let sumcheck_mask = LibraVariableDegreeSumcheckMask::new(
            fp16(16_001),
            degrees
                .iter()
                .enumerate()
                .map(|(round, degree)| {
                    (0..*degree)
                        .map(|coefficient| fp16(16_101 + 31 * round + coefficient))
                        .collect()
                })
                .collect(),
        )
        .unwrap();
        let layer_mask = LibraLayerMask {
            coefficients: core::array::from_fn(|index| fp16(18_001 + 17 * index)),
        };
        let group_challenges = point(group_variables, 202);
        let wire_challenges = point(left_variables + right_variables, 203);
        let terminal_challenge = fp16(19_001);
        let mut group_seen = 0;
        let mut left_seen = 0;
        let mut right_seen = 0;
        let result = prove_masked_shared_group_dag_layer_interactive(
            &layer,
            group_count,
            &left_wire_values,
            &right_wire_values,
            &claims,
            &LibraPriorLayerCorrection::zero(),
            &sumcheck_mask,
            &layer_mask,
            fp16(19_101),
            |kind, round, published| {
                assert!(!published.is_empty());
                Ok(match kind {
                    SharedGroupDagRoundKind::Group => {
                        assert_eq!(round, group_seen);
                        group_seen += 1;
                        group_challenges[round]
                    }
                    SharedGroupDagRoundKind::LeftWire => {
                        assert_eq!(round, left_seen);
                        left_seen += 1;
                        wire_challenges[round]
                    }
                    SharedGroupDagRoundKind::RightWire => {
                        assert_eq!(round, right_seen);
                        right_seen += 1;
                        wire_challenges[left_variables + round]
                    }
                })
            },
            |published, _, _| {
                assert_eq!(published.len(), 3);
                Ok(terminal_challenge)
            },
        );
        assert!(
            result.is_ok(),
            "result={result:?} group_seen={group_seen} left_seen={left_seen} right_seen={right_seen}"
        );
        let proof = result.unwrap();
        assert_eq!(group_seen, group_variables);
        assert_eq!(left_seen, left_variables);
        assert_eq!(right_seen, right_variables);
        assert_eq!(proof.group_challenges, group_challenges);
        assert_eq!(proof.wire_challenges, wire_challenges);
        assert_eq!(proof.w_challenge, terminal_challenge);
        assert_ne!(proof.masked_terminal_left, proof.raw_terminal_left);
        assert_ne!(proof.masked_terminal_right, proof.raw_terminal_right);
        assert_eq!(proof.published_rounds.len(), degrees.len());

        let left_complete = (0..group_count * layer.left_width)
            .map(|index| fp16(31_001 + 7 * index))
            .collect::<Vec<_>>();
        let right_complete = (0..group_count * layer.right_width)
            .map(|index| fp16(41_001 + 11 * index))
            .collect::<Vec<_>>();
        let mut complete_output = Vec::with_capacity(group_count * layer.padded_width);
        for group in 0..group_count {
            complete_output.extend(
                evaluate_dag_arithmetic_layer(
                    &layer,
                    &left_complete[group * layer.left_width..(group + 1) * layer.left_width],
                    &right_complete[group * layer.right_width..(group + 1) * layer.right_width],
                )
                .unwrap(),
            );
        }
        let complete_point = point(output_variables + group_variables, 301);
        let complete_claims = vec![LayerOutputClaim {
            value: multilinear_evaluate(&complete_output, &complete_point).unwrap(),
            point: complete_point,
            coefficient: fp16(51_001),
        }];
        prove_shared_group_dag_layer_reference(
            &layer,
            group_count,
            &left_complete,
            &right_complete,
            &complete_claims,
            &group_challenges,
            &wire_challenges,
        )
        .unwrap();
        let mut complete_group_seen = 0;
        let mut complete_left_seen = 0;
        let mut complete_right_seen = 0;
        let complete_result = prove_masked_shared_group_dag_layer_interactive(
            &layer,
            group_count,
            &left_complete,
            &right_complete,
            &complete_claims,
            &LibraPriorLayerCorrection::zero(),
            &sumcheck_mask,
            &layer_mask,
            fp16(19_101),
            |kind, round, published| {
                assert!(!published.is_empty());
                Ok(match kind {
                    SharedGroupDagRoundKind::Group => {
                        complete_group_seen += 1;
                        group_challenges[round]
                    }
                    SharedGroupDagRoundKind::LeftWire => {
                        complete_left_seen += 1;
                        wire_challenges[round]
                    }
                    SharedGroupDagRoundKind::RightWire => {
                        complete_right_seen += 1;
                        wire_challenges[left_variables + round]
                    }
                })
            },
            |published, _, _| {
                assert_eq!(published.len(), 3);
                Ok(terminal_challenge)
            },
        );
        assert!(
            complete_result.is_ok(),
            "result={complete_result:?} group_seen={complete_group_seen} left_seen={complete_left_seen} right_seen={complete_right_seen}"
        );
        let complete = complete_result.unwrap();
        let left_point = wire_challenges[..left_variables]
            .iter()
            .chain(&group_challenges)
            .copied()
            .collect::<Vec<_>>();
        let right_point = wire_challenges[left_variables..]
            .iter()
            .chain(&group_challenges)
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(
            complete.raw_terminal_left,
            multilinear_evaluate(&left_complete, &left_point).unwrap()
        );
        assert_eq!(
            complete.raw_terminal_right,
            multilinear_evaluate(&right_complete, &right_point).unwrap()
        );

        let mut oracle = CpuMaskedSharedGroupOracle::new(
            &layer,
            group_count,
            &left_complete,
            &right_complete,
            &complete_claims,
        );
        let oracle_proof = prove_masked_shared_group_dag_layer_oracle_interactive(
            &layer,
            group_count,
            &mut oracle,
            &complete_claims,
            &LibraPriorLayerCorrection::zero(),
            &sumcheck_mask,
            &layer_mask,
            fp16(19_101),
            |kind, round, _| {
                Ok(match kind {
                    SharedGroupDagRoundKind::Group => group_challenges[round],
                    SharedGroupDagRoundKind::LeftWire => wire_challenges[round],
                    SharedGroupDagRoundKind::RightWire => wire_challenges[left_variables + round],
                })
            },
            |_, _, _| Ok(terminal_challenge),
        )
        .unwrap();
        assert_eq!(oracle_proof, complete);

        let mut wire_oracle = CpuMaskedSharedGroupOracle::new(
            &layer,
            group_count,
            &left_complete,
            &right_complete,
            &complete_claims,
        )
        .with_wire_acceleration();
        let wire_oracle_proof = prove_masked_shared_group_dag_layer_oracle_interactive(
            &layer,
            group_count,
            &mut wire_oracle,
            &complete_claims,
            &LibraPriorLayerCorrection::zero(),
            &sumcheck_mask,
            &layer_mask,
            fp16(19_101),
            |kind, round, _| {
                Ok(match kind {
                    SharedGroupDagRoundKind::Group => group_challenges[round],
                    SharedGroupDagRoundKind::LeftWire => wire_challenges[round],
                    SharedGroupDagRoundKind::RightWire => wire_challenges[left_variables + round],
                })
            },
            |_, _, _| Ok(terminal_challenge),
        )
        .unwrap();
        assert_eq!(wire_oracle_proof, complete);

        let mut forged_oracle = CpuMaskedSharedGroupOracle::new(
            &layer,
            group_count,
            &left_complete,
            &right_complete,
            &complete_claims,
        );
        forged_oracle.mutate_round = Some(0);
        assert_eq!(
            prove_masked_shared_group_dag_layer_oracle_interactive(
                &layer,
                group_count,
                &mut forged_oracle,
                &complete_claims,
                &LibraPriorLayerCorrection::zero(),
                &sumcheck_mask,
                &layer_mask,
                fp16(19_101),
                |kind, round, _| {
                    Ok(match kind {
                        SharedGroupDagRoundKind::Group => group_challenges[round],
                        SharedGroupDagRoundKind::LeftWire => wire_challenges[round],
                        SharedGroupDagRoundKind::RightWire => {
                            wire_challenges[left_variables + round]
                        }
                    })
                },
                |_, _, _| Ok(terminal_challenge),
            ),
            Err(GkrZkMaskError::Claim)
        );

        let mut forged_wire_oracle = CpuMaskedSharedGroupOracle::new(
            &layer,
            group_count,
            &left_complete,
            &right_complete,
            &complete_claims,
        )
        .with_wire_acceleration();
        forged_wire_oracle.mutate_wire_round = Some((SharedGroupDagRoundKind::LeftWire, 0));
        assert_eq!(
            prove_masked_shared_group_dag_layer_oracle_interactive(
                &layer,
                group_count,
                &mut forged_wire_oracle,
                &complete_claims,
                &LibraPriorLayerCorrection::zero(),
                &sumcheck_mask,
                &layer_mask,
                fp16(19_101),
                |kind, round, _| {
                    Ok(match kind {
                        SharedGroupDagRoundKind::Group => group_challenges[round],
                        SharedGroupDagRoundKind::LeftWire => wire_challenges[round],
                        SharedGroupDagRoundKind::RightWire => {
                            wire_challenges[left_variables + round]
                        }
                    })
                },
                |_, _, _| Ok(terminal_challenge),
            ),
            Err(GkrZkMaskError::Claim)
        );
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaskedProductSumcheckProof {
    pub rounds: Vec<[Fp16; 3]>,
    pub terminal_left: Fp16,
    pub terminal_right: Fp16,
    pub terminal_correction: Fp16,
}

/// One verifier claim about the multilinear extension of a layer.
///
/// Multiple claims are combined by authenticated public-coin coefficients.
/// This is the standard GKR claim-combination boundary; it avoids a
/// host-trusted reduction from two input-layer openings to one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LayerOutputClaim {
    pub point: Vec<Fp16>,
    pub value: Fp16,
    pub coefficient: Fp16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SparseLayerSumcheckProof {
    pub rounds: Vec<[Fp16; 3]>,
    pub terminal_left: Fp16,
    pub terminal_right: Fp16,
}

/// Reference proof for a relay-free DAG layer repeated across one shared group
/// axis.
///
/// `group_rounds` bind the common group coordinate before either source wire
/// label is introduced. Their degree is at most three: one equality factor
/// times one fan-in-two gate. `wire_proof` then binds the two source wire
/// labels and exposes two openings on the actual source boundaries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedGroupDagLayerProof {
    pub group_rounds: Vec<[Fp16; 4]>,
    pub wire_proof: SparseLayerSumcheckProof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaskedUniformSharedGroupDagLayerProof {
    pub base_rounds: Vec<Vec<Fp16>>,
    pub published_rounds: Vec<Vec<Fp16>>,
    pub group_challenges: Vec<Fp16>,
    pub wire_challenges: Vec<Fp16>,
    pub raw_terminal_left: Fp16,
    pub raw_terminal_right: Fp16,
    pub masked_terminal_left: Fp16,
    pub masked_terminal_right: Fp16,
    pub w_base: [Fp16; 3],
    pub w_published: Vec<Fp16>,
    pub w_challenge: Fp16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedGroupDagRoundKind {
    Group,
    LeftWire,
    RightWire,
}

/// Construction-2 cubic needed on the final left or right wire round of a
/// shared-group DAG layer.
///
/// Group challenges are supplied in transcript order, while the committed
/// source point remains `(wire, group)`. The helper reconstructs that exact
/// point ordering before evaluating the layer-mask vanishing coefficient.
#[allow(clippy::too_many_arguments)]
pub fn shared_group_terminal_extension_cubic(
    layer: &KeccakDagLayer,
    claims: &[LayerOutputClaim],
    group_challenges: &[Fp16],
    left_challenges: &[Fp16],
    right_challenges: &[Fp16],
    right_wire_values: &[Fp16],
    terminal_left: Option<Fp16>,
    layer_mask: &LibraLayerMask,
    varying_left: bool,
) -> Result<[Fp16; 4], GkrZkMaskError> {
    let output_variables = layer.padded_width.trailing_zeros() as usize;
    if right_wire_values.len() != layer.right_width {
        return Err(GkrZkMaskError::Shape);
    }
    let effective = shared_group_effective_claims(claims, output_variables, group_challenges)
        .map_err(|_| GkrZkMaskError::Shape)?;
    let terms = dag_layer_terms(layer, &effective).map_err(|_| GkrZkMaskError::Shape)?;
    let fixed_left_equality = if varying_left {
        None
    } else {
        Some(equality_table(left_challenges).map_err(|_| GkrZkMaskError::Shape)?)
    };
    Ok(shared_group_terminal_extension_cubic_from_terms(
        layer,
        &terms,
        group_challenges,
        left_challenges,
        right_challenges,
        right_wire_values,
        terminal_left,
        layer_mask,
        varying_left,
        fixed_left_equality.as_deref(),
    )?
    .0)
}

#[allow(clippy::too_many_arguments)]
fn shared_group_terminal_extension_cubic_from_terms(
    layer: &KeccakDagLayer,
    terms: &[SparseGateTerm],
    group_challenges: &[Fp16],
    left_challenges: &[Fp16],
    right_challenges: &[Fp16],
    right_wire_values: &[Fp16],
    terminal_left: Option<Fp16>,
    layer_mask: &LibraLayerMask,
    varying_left: bool,
    fixed_left_equality: Option<&[Fp16]>,
) -> Result<([Fp16; 4], Vec<Fp16>), GkrZkMaskError> {
    let left_variables = layer.left_width.trailing_zeros() as usize;
    let right_variables = layer.right_width.trailing_zeros() as usize;
    if terms.is_empty() || right_wire_values.len() != layer.right_width {
        return Err(GkrZkMaskError::Shape);
    }
    if varying_left {
        if left_challenges.len() + 1 != left_variables
            || !right_challenges.is_empty()
            || terminal_left.is_some()
        {
            return Err(GkrZkMaskError::Shape);
        }
        let prefix_equality = equality_table(left_challenges).map_err(|_| GkrZkMaskError::Shape)?;
        let source_prefix = left_challenges
            .iter()
            .chain(group_challenges)
            .copied()
            .collect::<Vec<_>>();
        let vanishing = terminal_vanishing_coefficient(layer_mask, &source_prefix)?;
        let prefix_mask = prefix_equality.len() - 1;
        let final_bit = prefix_equality.len().ilog2();
        let two = Fp16::ONE + Fp16::ONE;
        let mut cubic = [Fp16::ZERO; 4];
        for term in terms {
            let (_, slope) = gate_line(
                term.formula,
                true,
                Fp16::ZERO,
                Fp16::ONE,
                right_wire_values[term.right],
            );
            let scale =
                term.output_weight * prefix_equality[term.left & prefix_mask] * slope * vanishing;
            if (term.left >> final_bit) & 1 == 0 {
                cubic[1] = cubic[1] + scale;
                cubic[2] = cubic[2] - two * scale;
                cubic[3] = cubic[3] + scale;
            } else {
                cubic[2] = cubic[2] + scale;
                cubic[3] = cubic[3] - scale;
            }
        }
        Ok((cubic, prefix_equality))
    } else {
        if left_challenges.len() != left_variables
            || right_challenges.len() + 1 != right_variables
            || terminal_left.is_none()
        {
            return Err(GkrZkMaskError::Shape);
        }
        let prefix_equality =
            equality_table(right_challenges).map_err(|_| GkrZkMaskError::Shape)?;
        let left_equality = fixed_left_equality
            .filter(|weights| weights.len() == layer.left_width)
            .ok_or(GkrZkMaskError::Shape)?;
        let source_prefix = right_challenges
            .iter()
            .chain(group_challenges)
            .copied()
            .collect::<Vec<_>>();
        let vanishing = terminal_vanishing_coefficient(layer_mask, &source_prefix)?;
        let prefix_mask = prefix_equality.len() - 1;
        let final_bit = prefix_equality.len().ilog2();
        let fixed_left = terminal_left.ok_or(GkrZkMaskError::Shape)?;
        let two = Fp16::ONE + Fp16::ONE;
        let mut cubic = [Fp16::ZERO; 4];
        for term in terms {
            let (_, slope) = gate_line(term.formula, false, Fp16::ZERO, Fp16::ONE, fixed_left);
            let scale = term.output_weight
                * prefix_equality[term.right & prefix_mask]
                * left_equality[term.left]
                * slope
                * vanishing;
            if (term.right >> final_bit) & 1 == 0 {
                cubic[1] = cubic[1] + scale;
                cubic[2] = cubic[2] - two * scale;
                cubic[3] = cubic[3] + scale;
            } else {
                cubic[2] = cubic[2] + scale;
                cubic[3] = cubic[3] - scale;
            }
        }
        Ok((cubic, prefix_equality))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaskedSparseLayerSumcheckProof {
    pub rounds: Vec<[Fp16; 3]>,
    pub terminal_left: Fp16,
    pub terminal_right: Fp16,
    pub terminal_correction: Fp16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaskedGkrRoundError {
    Empty,
    Sequence,
    Claim,
    Incomplete,
}

/// Stateful masking boundary for sequential authenticated-public-coin use.
///
/// The caller must authenticate each challenge externally. This state only
/// enforces message-before-challenge ordering and carries the exact masking
/// correction into the terminal equation.
pub struct MaskedGkrRoundState {
    current_claim: Fp16,
    incoming_correction: Fp16,
    round_count: usize,
    accepted_challenges: usize,
    pending: Option<([Fp16; 3], [Fp16; 3])>,
    rounds: Vec<[Fp16; 3]>,
}

impl MaskedGkrRoundState {
    pub fn new(initial_claim: Fp16, round_count: usize) -> Result<Self, MaskedGkrRoundError> {
        if round_count == 0 {
            return Err(MaskedGkrRoundError::Empty);
        }
        Ok(Self {
            current_claim: initial_claim,
            incoming_correction: Fp16::ZERO,
            round_count,
            accepted_challenges: 0,
            pending: None,
            rounds: Vec::with_capacity(round_count),
        })
    }

    pub fn publish_masked_message(
        &mut self,
        raw: [Fp16; 3],
        mask: [Fp16; 2],
    ) -> Result<[Fp16; 3], MaskedGkrRoundError> {
        if self.pending.is_some() || self.accepted_challenges >= self.round_count {
            return Err(MaskedGkrRoundError::Sequence);
        }
        let raw_sum = raw[0] + raw[0] + raw[1] + raw[2];
        if raw_sum + self.incoming_correction != self.current_claim {
            return Err(MaskedGkrRoundError::Claim);
        }
        let correction = [
            mask[0],
            self.incoming_correction - mask[0] - mask[0] - mask[1],
            mask[1],
        ];
        let masked = [
            raw[0] + correction[0],
            raw[1] + correction[1],
            raw[2] + correction[2],
        ];
        self.pending = Some((masked, correction));
        Ok(masked)
    }

    pub fn accept_authenticated_challenge(
        &mut self,
        challenge: Fp16,
    ) -> Result<(), MaskedGkrRoundError> {
        let (masked, correction) = self.pending.take().ok_or(MaskedGkrRoundError::Sequence)?;
        self.current_claim = evaluate_quadratic(masked, challenge);
        self.incoming_correction = evaluate_quadratic(correction, challenge);
        self.rounds.push(masked);
        self.accepted_challenges += 1;
        Ok(())
    }

    pub fn finish(
        self,
        terminal_left: Fp16,
        terminal_right: Fp16,
    ) -> Result<MaskedSparseLayerSumcheckProof, MaskedGkrRoundError> {
        if self.pending.is_some() || self.accepted_challenges != self.round_count {
            return Err(MaskedGkrRoundError::Incomplete);
        }
        Ok(MaskedSparseLayerSumcheckProof {
            rounds: self.rounds,
            terminal_left,
            terminal_right,
            terminal_correction: self.incoming_correction,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SparseGkrChainProof {
    /// Proofs are ordered from the final layer back to the first layer.
    pub layers: Vec<SparseLayerSumcheckProof>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepeatedPackGkrChainProof {
    /// Proofs are ordered from the final layer back to the first layer.
    pub layers: Vec<RepeatedPackLayerGkrProof>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnePackLayerGkrProof {
    pub packed_polynomial: [Fp16; crate::packed_boolean_sumcheck::OUTPUT_COEFFICIENTS],
    pub sparse_layer: SparseLayerSumcheckProof,
}

pub type RepeatedPackLayerGkrProof = OnePackLayerGkrProof;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnePackLayerGkrError {
    Shape,
    Packed(PackedBooleanError),
    Gkr(ProductSumcheckError),
}

impl From<PackedBooleanError> for OnePackLayerGkrError {
    fn from(error: PackedBooleanError) -> Self {
        Self::Packed(error)
    }
}

impl From<ProductSumcheckError> for OnePackLayerGkrError {
    fn from(error: ProductSumcheckError) -> Self {
        Self::Gkr(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductSumcheckError {
    Empty,
    Shape,
    ChallengeCount,
    Claim,
    Terminal,
    Wiring,
    WorkerPanicked,
}

impl fmt::Display for ProductSumcheckError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "product sumcheck error: {self:?}")
    }
}

impl core::error::Error for ProductSumcheckError {}

fn log2_exact(length: usize) -> Result<usize, ProductSumcheckError> {
    if length == 0 || !length.is_power_of_two() {
        return Err(ProductSumcheckError::Shape);
    }
    Ok(length.trailing_zeros() as usize)
}

fn evaluate_quadratic(coefficients: [Fp16; 3], point: Fp16) -> Fp16 {
    coefficients[0] + point * (coefficients[1] + point * coefficients[2])
}

fn evaluate_cubic(coefficients: [Fp16; 4], point: Fp16) -> Fp16 {
    coefficients[0]
        + point * (coefficients[1] + point * (coefficients[2] + point * coefficients[3]))
}

fn equality_table(point: &[Fp16]) -> Result<Vec<Fp16>, ProductSumcheckError> {
    if point.len() >= usize::BITS as usize {
        return Err(ProductSumcheckError::Shape);
    }
    let size = 1_usize
        .checked_shl(point.len() as u32)
        .ok_or(ProductSumcheckError::Shape)?;
    let mut weights = Vec::with_capacity(size);
    weights.push(Fp16::ONE);
    for coordinate in point.iter().copied() {
        let old_len = weights.len();
        weights.resize(2 * old_len, Fp16::ZERO);
        for index in 0..old_len {
            let one = weights[index] * coordinate;
            weights[index + old_len] = one;
            weights[index] = weights[index] - one;
        }
    }
    Ok(weights)
}

fn extend_equality_table(mut weights: Vec<Fp16>, coordinate: Fp16) -> Vec<Fp16> {
    let old_len = weights.len();
    weights.resize(2 * old_len, Fp16::ZERO);
    for index in 0..old_len {
        let one = weights[index] * coordinate;
        weights[index + old_len] = one;
        weights[index] = weights[index] - one;
    }
    weights
}

pub fn multilinear_equality_table(point: &[Fp16]) -> Result<Vec<Fp16>, ProductSumcheckError> {
    equality_table(point)
}

fn multilinear_evaluate(values: &[Fp16], point: &[Fp16]) -> Result<Fp16, ProductSumcheckError> {
    if values.is_empty()
        || !values.len().is_power_of_two()
        || point.len() != values.len().trailing_zeros() as usize
    {
        return Err(ProductSumcheckError::Shape);
    }
    let mut folded = values.to_vec();
    for coordinate in point.iter().copied() {
        for index in 0..folded.len() / 2 {
            let zero = folded[2 * index];
            folded[index] = zero + coordinate * (folded[2 * index + 1] - zero);
        }
        folded.truncate(folded.len() / 2);
    }
    Ok(folded[0])
}

fn fold_multilinear(values: &mut Vec<Fp16>, coordinate: Fp16) {
    for index in 0..values.len() / 2 {
        let zero = values[2 * index];
        values[index] = zero + coordinate * (values[2 * index + 1] - zero);
    }
    values.truncate(values.len() / 2);
}

fn bit_basis(point: Fp16, bit: usize) -> Fp16 {
    if bit == 0 { Fp16::ONE - point } else { point }
}

fn equality_line_value(point: Fp16, query: Fp16) -> Fp16 {
    Fp16::ONE - point - query + point * query + point * query
}

fn equality_evaluate(point: &[Fp16], query: &[Fp16]) -> Result<Fp16, ProductSumcheckError> {
    if point.len() != query.len() {
        return Err(ProductSumcheckError::Shape);
    }
    Ok(point
        .iter()
        .copied()
        .zip(query.iter().copied())
        .fold(Fp16::ONE, |value, (coordinate, challenge)| {
            value * equality_line_value(coordinate, challenge)
        }))
}

#[derive(Clone, Copy)]
struct SparseGateTerm {
    output_weight: Fp16,
    left: usize,
    right: usize,
    formula: GateFormula,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GateFormula {
    Xor,
    And,
    NotLeftAndRight,
    NotXor,
    Left,
    Right,
    NotLeft,
    NotRight,
    One,
    Zero,
}

#[cfg(feature = "parallel")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SparseLayerGpuFixtureTerm {
    pub output_weight: Fp16,
    pub left: u32,
    pub right: u32,
    pub formula: u8,
}

#[cfg(feature = "parallel")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SparseLayerGpuFixture {
    pub input: Vec<Fp16>,
    pub terms: Vec<SparseLayerGpuFixtureTerm>,
    pub challenges: Vec<Fp16>,
    pub expected_rounds: Vec<[Fp16; 3]>,
    pub terminal_left: Fp16,
    pub terminal_right: Fp16,
}

#[cfg(all(not(feature = "parallel"), any(test, feature = "control_reference")))]
fn sum_sparse_terms(
    terms: &[SparseGateTerm],
    evaluate: impl Fn(usize, &SparseGateTerm) -> [Fp16; 3],
) -> Result<[Fp16; 3], ProductSumcheckError> {
    Ok(terms
        .iter()
        .enumerate()
        .fold([Fp16::ZERO; 3], |sum, (index, term)| {
            let value = evaluate(index, term);
            [sum[0] + value[0], sum[1] + value[1], sum[2] + value[2]]
        }))
}

#[cfg(all(feature = "parallel", any(test, feature = "control_reference")))]
fn sum_sparse_terms(
    terms: &[SparseGateTerm],
    evaluate: impl Fn(usize, &SparseGateTerm) -> [Fp16; 3] + Sync,
) -> Result<[Fp16; 3], ProductSumcheckError> {
    let workers = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .min(terms.len());
    if workers <= 1 || terms.len() < 4_096 {
        return Ok(terms
            .iter()
            .enumerate()
            .fold([Fp16::ZERO; 3], |sum, (index, term)| {
                let value = evaluate(index, term);
                [sum[0] + value[0], sum[1] + value[1], sum[2] + value[2]]
            }));
    }
    let chunk = terms.len().div_ceil(workers);
    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for worker in 0..workers {
            let start = worker * chunk;
            let end = terms.len().min(start + chunk);
            let evaluate = &evaluate;
            handles.push(scope.spawn(move || {
                terms[start..end]
                    .iter()
                    .enumerate()
                    .fold([Fp16::ZERO; 3], |sum, (offset, term)| {
                        let value = evaluate(start + offset, term);
                        [sum[0] + value[0], sum[1] + value[1], sum[2] + value[2]]
                    })
            }));
        }
        handles
            .into_iter()
            .try_fold([Fp16::ZERO; 3], |sum, handle| {
                let value = handle
                    .join()
                    .map_err(|_| ProductSumcheckError::WorkerPanicked)?;
                Ok([sum[0] + value[0], sum[1] + value[1], sum[2] + value[2]])
            })
    })
}

#[cfg(any(test, not(feature = "control_reference")))]
struct SparseTermBuckets {
    buckets: Vec<Vec<usize>>,
    #[cfg(feature = "parallel")]
    term_count: usize,
}

#[cfg(any(test, not(feature = "control_reference")))]
impl SparseTermBuckets {
    fn new(
        terms: &[SparseGateTerm],
        input_width: usize,
        index: impl Fn(&SparseGateTerm) -> usize,
    ) -> Result<Self, ProductSumcheckError> {
        if input_width < 2 || !input_width.is_power_of_two() {
            return Err(ProductSumcheckError::Shape);
        }
        let mut buckets = vec![Vec::new(); input_width / 2];
        for (term_index, term) in terms.iter().enumerate() {
            let value = index(term);
            if value >= input_width {
                return Err(ProductSumcheckError::Wiring);
            }
            buckets[value >> 1].push(term_index);
        }
        Ok(Self {
            buckets,
            #[cfg(feature = "parallel")]
            term_count: terms.len(),
        })
    }

    fn merge_for_next_round(&mut self) {
        let old = core::mem::take(&mut self.buckets);
        let mut merged = Vec::with_capacity(old.len() / 2);
        let mut iter = old.into_iter();
        while let Some(mut low) = iter.next() {
            if let Some(mut high) = iter.next() {
                low.append(&mut high);
            }
            merged.push(low);
        }
        self.buckets = merged;
    }
}

#[cfg(all(
    not(feature = "parallel"),
    any(test, not(feature = "control_reference"))
))]
fn sum_sparse_buckets(
    buckets: &SparseTermBuckets,
    terms: &[SparseGateTerm],
    evaluate: impl Fn(usize, usize, &SparseGateTerm) -> [Fp16; 3],
) -> Result<[Fp16; 3], ProductSumcheckError> {
    Ok(buckets
        .buckets
        .iter()
        .enumerate()
        .fold([Fp16::ZERO; 3], |sum, (suffix, bucket)| {
            bucket.iter().copied().fold(sum, |sum, term_index| {
                let value = evaluate(suffix, term_index, &terms[term_index]);
                [sum[0] + value[0], sum[1] + value[1], sum[2] + value[2]]
            })
        }))
}

#[cfg(all(feature = "parallel", any(test, not(feature = "control_reference"))))]
fn sum_sparse_buckets(
    buckets: &SparseTermBuckets,
    terms: &[SparseGateTerm],
    evaluate: impl Fn(usize, usize, &SparseGateTerm) -> [Fp16; 3] + Sync,
) -> Result<[Fp16; 3], ProductSumcheckError> {
    let workers = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .min(buckets.buckets.len());
    if workers <= 1 || buckets.term_count < 4_096 {
        return Ok(buckets.buckets.iter().enumerate().fold(
            [Fp16::ZERO; 3],
            |sum, (suffix, bucket)| {
                bucket.iter().copied().fold(sum, |sum, term_index| {
                    let value = evaluate(suffix, term_index, &terms[term_index]);
                    [sum[0] + value[0], sum[1] + value[1], sum[2] + value[2]]
                })
            },
        ));
    }
    let chunk = buckets.buckets.len().div_ceil(workers);
    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for worker in 0..workers {
            let start = worker * chunk;
            let end = buckets.buckets.len().min(start + chunk);
            let evaluate = &evaluate;
            handles.push(scope.spawn(move || {
                buckets.buckets[start..end].iter().enumerate().fold(
                    [Fp16::ZERO; 3],
                    |sum, (offset, bucket)| {
                        let suffix = start + offset;
                        bucket.iter().copied().fold(sum, |sum, term_index| {
                            let value = evaluate(suffix, term_index, &terms[term_index]);
                            [sum[0] + value[0], sum[1] + value[1], sum[2] + value[2]]
                        })
                    },
                )
            }));
        }
        handles
            .into_iter()
            .try_fold([Fp16::ZERO; 3], |sum, handle| {
                let value = handle
                    .join()
                    .map_err(|_| ProductSumcheckError::WorkerPanicked)?;
                Ok([sum[0] + value[0], sum[1] + value[1], sum[2] + value[2]])
            })
    })
}

fn normalize_gate(gate: BooleanGate) -> Result<(usize, usize, GateFormula), ProductSumcheckError> {
    let left = match gate.left {
        BooleanWire::Previous(index) => Some(index),
        BooleanWire::Constant(_) => None,
    };
    let right = match gate.right {
        BooleanWire::Previous(index) => Some(index),
        BooleanWire::Constant(_) => None,
    };
    let left_value = match gate.left {
        BooleanWire::Constant(value) => Some(value),
        BooleanWire::Previous(_) => None,
    };
    let right_value = match gate.right {
        BooleanWire::Constant(value) => Some(value),
        BooleanWire::Previous(_) => None,
    };
    let formula = match gate.kind {
        BooleanGateKind::Xor => match (left_value, right_value) {
            (None, None) => GateFormula::Xor,
            (None, Some(false)) => GateFormula::Left,
            (None, Some(true)) => GateFormula::NotLeft,
            (Some(false), None) => GateFormula::Right,
            (Some(true), None) => GateFormula::NotRight,
            (Some(left), Some(right)) => {
                if left ^ right {
                    GateFormula::One
                } else {
                    GateFormula::Zero
                }
            }
        },
        BooleanGateKind::And => match (left_value, right_value) {
            (None, None) => GateFormula::And,
            (None, Some(false)) | (Some(false), None) => GateFormula::Zero,
            (None, Some(true)) => GateFormula::Left,
            (Some(true), None) => GateFormula::Right,
            (Some(left), Some(right)) => {
                if left & right {
                    GateFormula::One
                } else {
                    GateFormula::Zero
                }
            }
        },
        BooleanGateKind::Relay => match left_value {
            None => GateFormula::Left,
            Some(false) => GateFormula::Zero,
            Some(true) => GateFormula::One,
        },
        BooleanGateKind::Zero => GateFormula::Zero,
    };
    Ok((left.unwrap_or(0), right.unwrap_or(0), formula))
}

fn gate_value(formula: GateFormula, left: Fp16, right: Fp16) -> Fp16 {
    match formula {
        GateFormula::Xor => left + right - (left * right + left * right),
        GateFormula::And => left * right,
        GateFormula::NotLeftAndRight => right - left * right,
        GateFormula::NotXor => Fp16::ONE - left - right + left * right + left * right,
        GateFormula::Left => left,
        GateFormula::Right => right,
        GateFormula::NotLeft => Fp16::ONE - left,
        GateFormula::NotRight => Fp16::ONE - right,
        GateFormula::One => Fp16::ONE,
        GateFormula::Zero => Fp16::ZERO,
    }
}

fn gate_line(
    formula: GateFormula,
    varying_left: bool,
    zero: Fp16,
    delta: Fp16,
    fixed: Fp16,
) -> (Fp16, Fp16) {
    match formula {
        GateFormula::Xor => {
            let twice_fixed = fixed + fixed;
            (
                zero + fixed - zero * twice_fixed,
                delta * (Fp16::ONE - twice_fixed),
            )
        }
        GateFormula::And => (zero * fixed, delta * fixed),
        GateFormula::NotLeftAndRight if varying_left => (fixed - zero * fixed, -(delta * fixed)),
        GateFormula::NotLeftAndRight => (zero * (Fp16::ONE - fixed), delta * (Fp16::ONE - fixed)),
        GateFormula::NotXor => {
            let twice_fixed = fixed + fixed;
            (
                Fp16::ONE - zero - fixed + zero * twice_fixed,
                delta * (twice_fixed - Fp16::ONE),
            )
        }
        GateFormula::Left if varying_left => (zero, delta),
        GateFormula::Left => (fixed, Fp16::ZERO),
        GateFormula::Right if varying_left => (fixed, Fp16::ZERO),
        GateFormula::Right => (zero, delta),
        GateFormula::NotLeft if varying_left => (Fp16::ONE - zero, -delta),
        GateFormula::NotLeft => (Fp16::ONE - fixed, Fp16::ZERO),
        GateFormula::NotRight if varying_left => (Fp16::ONE - fixed, Fp16::ZERO),
        GateFormula::NotRight => (Fp16::ONE - zero, -delta),
        GateFormula::One => (Fp16::ONE, Fp16::ZERO),
        GateFormula::Zero => (Fp16::ZERO, Fp16::ZERO),
    }
}

fn gate_quadratic_both(
    formula: GateFormula,
    left_zero: Fp16,
    left_delta: Fp16,
    right_zero: Fp16,
    right_delta: Fp16,
) -> [Fp16; 3] {
    let cross_linear = left_zero * right_delta + left_delta * right_zero;
    let cross_quadratic = left_delta * right_delta;
    match formula {
        GateFormula::Xor => [
            left_zero + right_zero - left_zero * right_zero - left_zero * right_zero,
            left_delta + right_delta - cross_linear - cross_linear,
            -cross_quadratic - cross_quadratic,
        ],
        GateFormula::And => [left_zero * right_zero, cross_linear, cross_quadratic],
        GateFormula::NotLeftAndRight => [
            right_zero - left_zero * right_zero,
            right_delta - cross_linear,
            -cross_quadratic,
        ],
        GateFormula::NotXor => [
            Fp16::ONE - left_zero - right_zero + left_zero * right_zero + left_zero * right_zero,
            -left_delta - right_delta + cross_linear + cross_linear,
            cross_quadratic + cross_quadratic,
        ],
        GateFormula::Left => [left_zero, left_delta, Fp16::ZERO],
        GateFormula::Right => [right_zero, right_delta, Fp16::ZERO],
        GateFormula::NotLeft => [Fp16::ONE - left_zero, -left_delta, Fp16::ZERO],
        GateFormula::NotRight => [Fp16::ONE - right_zero, -right_delta, Fp16::ZERO],
        GateFormula::One => [Fp16::ONE, Fp16::ZERO, Fp16::ZERO],
        GateFormula::Zero => [Fp16::ZERO; 3],
    }
}

fn equality_times_quadratic(
    equality_zero: Fp16,
    equality_delta: Fp16,
    quadratic: [Fp16; 3],
) -> [Fp16; 4] {
    [
        equality_zero * quadratic[0],
        equality_zero * quadratic[1] + equality_delta * quadratic[0],
        equality_zero * quadratic[2] + equality_delta * quadratic[1],
        equality_delta * quadratic[2],
    ]
}

fn weighted_gate_quadratic(
    weight: Fp16,
    bit: usize,
    gate_zero: Fp16,
    gate_delta: Fp16,
) -> [Fp16; 3] {
    if bit == 0 {
        [
            weight * gate_zero,
            weight * (gate_delta - gate_zero),
            -(weight * gate_delta),
        ]
    } else {
        [Fp16::ZERO, weight * gate_zero, weight * gate_delta]
    }
}

fn layer_terms(
    layer: &KeccakGkrLayer,
    claims: &[LayerOutputClaim],
) -> Result<Vec<SparseGateTerm>, ProductSumcheckError> {
    if claims.is_empty()
        || layer.gates.len() != layer.padded_width
        || layer.raw_width > layer.padded_width
        || !layer.input_width.is_power_of_two()
        || !layer.padded_width.is_power_of_two()
    {
        return Err(ProductSumcheckError::Shape);
    }
    let output_variables = layer.padded_width.trailing_zeros() as usize;
    if claims
        .iter()
        .any(|claim| claim.point.len() != output_variables)
        || claims.iter().all(|claim| claim.coefficient.is_zero())
    {
        return Err(ProductSumcheckError::Shape);
    }
    let claim_weights = claims
        .iter()
        .map(|claim| equality_table(&claim.point))
        .collect::<Result<Vec<_>, _>>()?;
    let mut terms = Vec::with_capacity(layer.raw_width.min(layer.gates.len()));
    for (output, gate) in layer.gates.iter().copied().enumerate() {
        let output_weight = claims
            .iter()
            .zip(&claim_weights)
            .fold(Fp16::ZERO, |weight, (claim, table)| {
                weight + claim.coefficient * table[output]
            });
        if output_weight.is_zero() {
            continue;
        }
        let (left, right, formula) = normalize_gate(gate)?;
        if left >= layer.input_width || right >= layer.input_width {
            return Err(ProductSumcheckError::Wiring);
        }
        if formula == GateFormula::Zero {
            continue;
        }
        terms.push(SparseGateTerm {
            output_weight,
            left,
            right,
            formula,
        });
    }
    if terms.is_empty() {
        return Err(ProductSumcheckError::Claim);
    }
    Ok(terms)
}

fn evaluate_arithmetic_layer(
    layer: &KeccakGkrLayer,
    input: &[Fp16],
) -> Result<Vec<Fp16>, ProductSumcheckError> {
    if input.len() != layer.input_width || layer.gates.len() != layer.padded_width {
        return Err(ProductSumcheckError::Shape);
    }
    layer
        .gates
        .iter()
        .copied()
        .map(|gate| {
            let (left, right, formula) = normalize_gate(gate)?;
            if left >= input.len() || right >= input.len() {
                return Err(ProductSumcheckError::Wiring);
            }
            Ok(gate_value(formula, input[left], input[right]))
        })
        .collect()
}

fn combined_claim(claims: &[LayerOutputClaim]) -> Fp16 {
    claims.iter().fold(Fp16::ZERO, |value, claim| {
        value + claim.coefficient * claim.value
    })
}

#[cfg(any(test, feature = "control_reference"))]
fn prove_sparse_terms_reference(
    input: &[Fp16],
    _initial_claim: Fp16,
    terms: &[SparseGateTerm],
    challenges: &[Fp16],
) -> Result<SparseLayerSumcheckProof, ProductSumcheckError> {
    let input_variables = log2_exact(input.len())?;
    if terms.is_empty() || challenges.len() != 2 * input_variables {
        return Err(ProductSumcheckError::ChallengeCount);
    }
    let mut left_factors = vec![Fp16::ONE; terms.len()];
    let mut right_factors = vec![Fp16::ONE; terms.len()];
    let mut left_folded = input.to_vec();
    let mut right_folded = input.to_vec();
    let mut rounds = Vec::with_capacity(2 * input_variables);

    for (round, challenge) in challenges[..input_variables].iter().copied().enumerate() {
        let coefficients = sum_sparse_terms(terms, |term_index, term| {
            let suffix = term.left >> (round + 1);
            let zero = left_folded[2 * suffix];
            let delta = left_folded[2 * suffix + 1] - zero;
            let (gate_zero, gate_delta) =
                gate_line(term.formula, true, zero, delta, input[term.right]);
            weighted_gate_quadratic(
                term.output_weight * left_factors[term_index],
                (term.left >> round) & 1,
                gate_zero,
                gate_delta,
            )
        })?;
        rounds.push(coefficients);
        for (factor, term) in left_factors.iter_mut().zip(terms) {
            *factor = *factor * bit_basis(challenge, (term.left >> round) & 1);
        }
        fold_multilinear(&mut left_folded, challenge);
    }
    let terminal_left = left_folded[0];

    for (offset, challenge) in challenges[input_variables..].iter().copied().enumerate() {
        let coefficients = sum_sparse_terms(terms, |term_index, term| {
            let suffix = term.right >> (offset + 1);
            let zero = right_folded[2 * suffix];
            let delta = right_folded[2 * suffix + 1] - zero;
            let (gate_zero, gate_delta) =
                gate_line(term.formula, false, zero, delta, terminal_left);
            weighted_gate_quadratic(
                term.output_weight * left_factors[term_index] * right_factors[term_index],
                (term.right >> offset) & 1,
                gate_zero,
                gate_delta,
            )
        })?;
        rounds.push(coefficients);
        for (factor, term) in right_factors.iter_mut().zip(terms) {
            *factor = *factor * bit_basis(challenge, (term.right >> offset) & 1);
        }
        fold_multilinear(&mut right_folded, challenge);
    }
    let proof = SparseLayerSumcheckProof {
        rounds,
        terminal_left,
        terminal_right: right_folded[0],
    };
    Ok(proof)
}

#[cfg(test)]
fn equality_weight_at(point: &[Fp16], index: usize) -> Result<Fp16, ProductSumcheckError> {
    if point.len() >= usize::BITS as usize || index >= (1_usize << point.len()) {
        return Err(ProductSumcheckError::Shape);
    }
    Ok(point
        .iter()
        .copied()
        .enumerate()
        .fold(Fp16::ONE, |weight, (variable, coordinate)| {
            weight * bit_basis(coordinate, (index >> variable) & 1)
        }))
}

#[cfg(test)]
fn replayed_prefix_value(
    input_width: usize,
    input_at: &impl Fn(usize) -> Fp16,
    prefix: &[Fp16],
    high_index: usize,
) -> Result<Fp16, ProductSumcheckError> {
    let variables = log2_exact(input_width)?;
    if prefix.len() > variables || high_index >= (input_width >> prefix.len()) {
        return Err(ProductSumcheckError::Shape);
    }
    let block = 1_usize << prefix.len();
    let first = high_index * block;
    (0..block).try_fold(Fp16::ZERO, |sum, low_index| {
        Ok(sum + input_at(first + low_index) * equality_weight_at(prefix, low_index)?)
    })
}

/// Test-only exact-replay feasibility oracle.
///
/// This intentionally retains neither folded input tables nor per-term factors.
/// It recomputes both from the canonical input and public challenges for every
/// round. The construction is slow by design; it exists only to determine
/// whether bounded retained state can preserve the exact current messages.
#[cfg(test)]
fn prove_sparse_terms_replayed(
    input_width: usize,
    input_at: impl Fn(usize) -> Fp16,
    term_slots: usize,
    term_at: impl Fn(usize) -> Result<Option<SparseGateTerm>, ProductSumcheckError>,
    challenges: &[Fp16],
) -> Result<SparseLayerSumcheckProof, ProductSumcheckError> {
    let input_variables = log2_exact(input_width)?;
    if term_slots == 0 || challenges.len() != 2 * input_variables {
        return Err(ProductSumcheckError::ChallengeCount);
    }
    let mut rounds = Vec::with_capacity(2 * input_variables);
    let mut active_terms = 0_usize;

    for round in 0..input_variables {
        let mut coefficients = [Fp16::ZERO; 3];
        for slot in 0..term_slots {
            let Some(term) = term_at(slot)? else {
                continue;
            };
            if term.left >= input_width || term.right >= input_width {
                return Err(ProductSumcheckError::Wiring);
            }
            if round == 0 {
                active_terms += 1;
            }
            let suffix = term.left >> (round + 1);
            let zero =
                replayed_prefix_value(input_width, &input_at, &challenges[..round], 2 * suffix)?;
            let one = replayed_prefix_value(
                input_width,
                &input_at,
                &challenges[..round],
                2 * suffix + 1,
            )?;
            let (gate_zero, gate_delta) =
                gate_line(term.formula, true, zero, one - zero, input_at(term.right));
            let factor =
                equality_weight_at(&challenges[..round], term.left & ((1_usize << round) - 1))?;
            let value = weighted_gate_quadratic(
                term.output_weight * factor,
                (term.left >> round) & 1,
                gate_zero,
                gate_delta,
            );
            for index in 0..3 {
                coefficients[index] = coefficients[index] + value[index];
            }
        }
        rounds.push(coefficients);
    }
    if active_terms == 0 {
        return Err(ProductSumcheckError::Claim);
    }
    let terminal_left =
        replayed_prefix_value(input_width, &input_at, &challenges[..input_variables], 0)?;

    for offset in 0..input_variables {
        let mut coefficients = [Fp16::ZERO; 3];
        for slot in 0..term_slots {
            let Some(term) = term_at(slot)? else {
                continue;
            };
            if term.left >= input_width || term.right >= input_width {
                return Err(ProductSumcheckError::Wiring);
            }
            let suffix = term.right >> (offset + 1);
            let zero = replayed_prefix_value(
                input_width,
                &input_at,
                &challenges[input_variables..input_variables + offset],
                2 * suffix,
            )?;
            let one = replayed_prefix_value(
                input_width,
                &input_at,
                &challenges[input_variables..input_variables + offset],
                2 * suffix + 1,
            )?;
            let (gate_zero, gate_delta) =
                gate_line(term.formula, false, zero, one - zero, terminal_left);
            let left_factor = equality_weight_at(&challenges[..input_variables], term.left)?;
            let right_factor = equality_weight_at(
                &challenges[input_variables..input_variables + offset],
                term.right & ((1_usize << offset) - 1),
            )?;
            let value = weighted_gate_quadratic(
                term.output_weight * left_factor * right_factor,
                (term.right >> offset) & 1,
                gate_zero,
                gate_delta,
            );
            for index in 0..3 {
                coefficients[index] = coefficients[index] + value[index];
            }
        }
        rounds.push(coefficients);
    }
    let terminal_right =
        replayed_prefix_value(input_width, &input_at, &challenges[input_variables..], 0)?;
    Ok(SparseLayerSumcheckProof {
        rounds,
        terminal_left,
        terminal_right,
    })
}

#[cfg(test)]
fn replayed_layer_term_at(
    layer: &KeccakGkrLayer,
    claims: &[LayerOutputClaim],
    output: usize,
) -> Result<Option<SparseGateTerm>, ProductSumcheckError> {
    if output >= layer.gates.len() {
        return Err(ProductSumcheckError::Shape);
    }
    let output_weight = claims.iter().try_fold(
        Fp16::ZERO,
        |weight, claim| -> Result<_, ProductSumcheckError> {
            Ok(weight + claim.coefficient * equality_weight_at(&claim.point, output)?)
        },
    )?;
    if output_weight.is_zero() {
        return Ok(None);
    }
    let (left, right, formula) = normalize_gate(layer.gates[output])?;
    if left >= layer.input_width || right >= layer.input_width {
        return Err(ProductSumcheckError::Wiring);
    }
    if formula == GateFormula::Zero {
        return Ok(None);
    }
    Ok(Some(SparseGateTerm {
        output_weight,
        left,
        right,
        formula,
    }))
}

#[cfg(test)]
fn replayed_retained_proof_bytes(input_width: usize) -> Result<usize, ProductSumcheckError> {
    let variables = log2_exact(input_width)?;
    Ok((6 * variables + 2) * core::mem::size_of::<Fp16>())
}

#[cfg(any(test, not(feature = "control_reference")))]
fn prove_sparse_terms_bucketed(
    input: &[Fp16],
    _initial_claim: Fp16,
    terms: &[SparseGateTerm],
    challenges: &[Fp16],
) -> Result<SparseLayerSumcheckProof, ProductSumcheckError> {
    let input_variables = log2_exact(input.len())?;
    if terms.is_empty() || challenges.len() != 2 * input_variables {
        return Err(ProductSumcheckError::ChallengeCount);
    }
    let mut left_factors = vec![Fp16::ONE; terms.len()];
    let mut right_factors = vec![Fp16::ONE; terms.len()];
    let mut left_folded = input.to_vec();
    let mut right_folded = input.to_vec();
    let mut left_buckets = SparseTermBuckets::new(terms, input.len(), |term| term.left)?;
    let mut right_buckets = SparseTermBuckets::new(terms, input.len(), |term| term.right)?;
    let mut rounds = Vec::with_capacity(2 * input_variables);

    for (round, challenge) in challenges[..input_variables].iter().copied().enumerate() {
        if left_buckets.buckets.len() != left_folded.len() / 2 {
            return Err(ProductSumcheckError::Shape);
        }
        let coefficients = sum_sparse_buckets(&left_buckets, terms, |suffix, term_index, term| {
            let zero = left_folded[2 * suffix];
            let delta = left_folded[2 * suffix + 1] - zero;
            let (gate_zero, gate_delta) =
                gate_line(term.formula, true, zero, delta, input[term.right]);
            weighted_gate_quadratic(
                term.output_weight * left_factors[term_index],
                (term.left >> round) & 1,
                gate_zero,
                gate_delta,
            )
        })?;
        rounds.push(coefficients);
        for bucket in &left_buckets.buckets {
            for term_index in bucket.iter().copied() {
                left_factors[term_index] = left_factors[term_index]
                    * bit_basis(challenge, (terms[term_index].left >> round) & 1);
            }
        }
        fold_multilinear(&mut left_folded, challenge);
        left_buckets.merge_for_next_round();
    }
    let terminal_left = left_folded[0];

    for (offset, challenge) in challenges[input_variables..].iter().copied().enumerate() {
        if right_buckets.buckets.len() != right_folded.len() / 2 {
            return Err(ProductSumcheckError::Shape);
        }
        let coefficients =
            sum_sparse_buckets(&right_buckets, terms, |suffix, term_index, term| {
                let zero = right_folded[2 * suffix];
                let delta = right_folded[2 * suffix + 1] - zero;
                let (gate_zero, gate_delta) =
                    gate_line(term.formula, false, zero, delta, terminal_left);
                weighted_gate_quadratic(
                    term.output_weight * left_factors[term_index] * right_factors[term_index],
                    (term.right >> offset) & 1,
                    gate_zero,
                    gate_delta,
                )
            })?;
        rounds.push(coefficients);
        for bucket in &right_buckets.buckets {
            for term_index in bucket.iter().copied() {
                right_factors[term_index] = right_factors[term_index]
                    * bit_basis(challenge, (terms[term_index].right >> offset) & 1);
            }
        }
        fold_multilinear(&mut right_folded, challenge);
        right_buckets.merge_for_next_round();
    }
    Ok(SparseLayerSumcheckProof {
        rounds,
        terminal_left,
        terminal_right: right_folded[0],
    })
}

fn prove_sparse_terms(
    input: &[Fp16],
    initial_claim: Fp16,
    terms: &[SparseGateTerm],
    challenges: &[Fp16],
) -> Result<SparseLayerSumcheckProof, ProductSumcheckError> {
    #[cfg(feature = "control_reference")]
    {
        prove_sparse_terms_reference(input, initial_claim, terms, challenges)
    }
    #[cfg(not(feature = "control_reference"))]
    {
        prove_sparse_terms_bucketed(input, initial_claim, terms, challenges)
    }
}

fn verify_sparse_terms(
    initial_claim: Fp16,
    input_width: usize,
    terms: &[SparseGateTerm],
    challenges: &[Fp16],
    proof: &SparseLayerSumcheckProof,
) -> Result<(), ProductSumcheckError> {
    let input_variables = log2_exact(input_width)?;
    if terms.is_empty()
        || challenges.len() != 2 * input_variables
        || proof.rounds.len() != challenges.len()
    {
        return Err(ProductSumcheckError::ChallengeCount);
    }
    let mut claim = initial_claim;
    for (round, challenge) in proof.rounds.iter().copied().zip(challenges.iter().copied()) {
        if round[0] + round[0] + round[1] + round[2] != claim {
            return Err(ProductSumcheckError::Claim);
        }
        claim = evaluate_quadratic(round, challenge);
    }
    let left_point = &challenges[..input_variables];
    let right_point = &challenges[input_variables..];
    let left_weights = equality_table(left_point)?;
    let right_weights = equality_table(right_point)?;
    let terminal =
        terms
            .iter()
            .try_fold(Fp16::ZERO, |sum, term| -> Result<_, ProductSumcheckError> {
                Ok(sum
                    + term.output_weight
                        * left_weights[term.left]
                        * right_weights[term.right]
                        * gate_value(term.formula, proof.terminal_left, proof.terminal_right))
            })?;
    if claim != terminal {
        return Err(ProductSumcheckError::Terminal);
    }
    Ok(())
}

fn verify_repeated_sparse_terms_factored(
    initial_claim: Fp16,
    layer: &KeccakGkrLayer,
    group_count: usize,
    claims: &[LayerOutputClaim],
    challenges: &[Fp16],
    proof: &SparseLayerSumcheckProof,
    terminal_correction: Fp16,
) -> Result<(), OnePackLayerGkrError> {
    let input_wire_variables = layer.input_width.trailing_zeros() as usize;
    let group_variables = group_count.trailing_zeros() as usize;
    let input_variables = input_wire_variables + group_variables;
    if claims.is_empty()
        || claims.iter().all(|claim| claim.coefficient.is_zero())
        || claims.iter().any(|claim| {
            claim.point.len() != layer.padded_width.trailing_zeros() as usize + group_variables
        })
        || challenges.len() != 2 * input_variables
        || proof.rounds.len() != challenges.len()
    {
        return Err(OnePackLayerGkrError::Shape);
    }
    let mut folded_claim = initial_claim;
    for (round, challenge) in proof.rounds.iter().copied().zip(challenges.iter().copied()) {
        if round[0] + round[0] + round[1] + round[2] != folded_claim {
            return Err(OnePackLayerGkrError::Gkr(ProductSumcheckError::Claim));
        }
        folded_claim = evaluate_quadratic(round, challenge);
    }
    let terminal = repeated_pack_terminal_gate_claim(
        layer,
        group_count,
        claims,
        &challenges[..input_variables],
        &challenges[input_variables..],
        proof.terminal_left,
        proof.terminal_right,
    )?;
    if folded_claim != terminal + terminal_correction {
        return Err(OnePackLayerGkrError::Gkr(ProductSumcheckError::Terminal));
    }
    Ok(())
}

/// Exact terminal wiring claim used by the repeated-pack GKR verifier.
///
/// This helper exposes the verifier's own terminal algebra for the randomized
/// GKR `w` round. It performs no transcript work and trusts no prover-supplied
/// wiring value.
pub fn repeated_pack_terminal_gate_claim(
    layer: &KeccakGkrLayer,
    group_count: usize,
    claims: &[LayerOutputClaim],
    left_point: &[Fp16],
    right_point: &[Fp16],
    terminal_left: Fp16,
    terminal_right: Fp16,
) -> Result<Fp16, OnePackLayerGkrError> {
    if group_count == 0
        || !group_count.is_power_of_two()
        || layer.input_width == 0
        || !layer.input_width.is_power_of_two()
        || layer.padded_width == 0
        || !layer.padded_width.is_power_of_two()
    {
        return Err(OnePackLayerGkrError::Shape);
    }
    let input_wire_variables = layer.input_width.trailing_zeros() as usize;
    let group_variables = group_count.trailing_zeros() as usize;
    let input_variables = input_wire_variables + group_variables;
    let output_wire_variables = layer.padded_width.trailing_zeros() as usize;
    if claims.is_empty()
        || claims.iter().all(|claim| claim.coefficient.is_zero())
        || claims
            .iter()
            .any(|claim| claim.point.len() != output_wire_variables + group_variables)
        || left_point.len() != input_variables
        || right_point.len() != input_variables
    {
        return Err(OnePackLayerGkrError::Shape);
    }

    let left_wire = equality_table(&left_point[..input_wire_variables])?;
    let left_group = equality_table(&left_point[input_wire_variables..])?;
    let right_wire = equality_table(&right_point[..input_wire_variables])?;
    let right_group = equality_table(&right_point[input_wire_variables..])?;
    let mut terminal = Fp16::ZERO;
    for claim in claims {
        let output_wire = equality_table(&claim.point[..output_wire_variables])?;
        let output_group = equality_table(&claim.point[output_wire_variables..])?;
        let group_factor = (0..group_count).fold(Fp16::ZERO, |sum, group| {
            sum + output_group[group] * left_group[group] * right_group[group]
        });
        let mut wire_factor = Fp16::ZERO;
        for (wire, gate) in layer
            .gates
            .iter()
            .copied()
            .enumerate()
            .take(layer.raw_width)
        {
            let (left, right, formula) = normalize_gate(gate)?;
            if left >= layer.input_width || right >= layer.input_width {
                return Err(OnePackLayerGkrError::Gkr(ProductSumcheckError::Wiring));
            }
            if formula != GateFormula::Zero {
                wire_factor = wire_factor
                    + output_wire[wire]
                        * left_wire[left]
                        * right_wire[right]
                        * gate_value(formula, terminal_left, terminal_right);
            }
        }
        terminal = terminal + claim.coefficient * group_factor * wire_factor;
    }
    Ok(terminal)
}

/// Nonactivating algebra control for one sparse fan-in-two GKR layer without
/// materializing its dense
/// `2^(2s)` wiring predicate.
///
/// The first `s` rounds bind the left input label and the next `s` bind the
/// right input label. Each round is degree at most two. The two terminal
/// values are deliberately left as input-layer polynomial claims: H3 must
/// open them through the same hiding PCS used by the rest of the proof.
///
/// This control accepts a completed challenge vector so deterministic KATs can
/// exercise the algebra. It is not a sound production transcript API: the
/// interactive prover must receive each authenticated public-coin challenge
/// only after committing the preceding masked message.
pub fn prove_sparse_gkr_layer(
    layer: &KeccakGkrLayer,
    input: &[Fp16],
    claims: &[LayerOutputClaim],
    challenges: &[Fp16],
) -> Result<SparseLayerSumcheckProof, ProductSumcheckError> {
    let input_variables = log2_exact(layer.input_width)?;
    if input.len() != layer.input_width || challenges.len() != 2 * input_variables {
        return Err(ProductSumcheckError::ChallengeCount);
    }
    let output = evaluate_arithmetic_layer(layer, input)?;
    for claim in claims {
        if multilinear_evaluate(&output, &claim.point)? != claim.value {
            return Err(ProductSumcheckError::Claim);
        }
    }
    let terms = layer_terms(layer, claims)?;
    prove_sparse_terms(input, combined_claim(claims), &terms, challenges)
}

/// Verify the nonactivating public-wiring algebra control. The caller must
/// separately authenticate
/// `terminal_left` and `terminal_right` as openings of the preceding layer.
pub fn verify_sparse_gkr_layer(
    layer: &KeccakGkrLayer,
    claims: &[LayerOutputClaim],
    challenges: &[Fp16],
    proof: &SparseLayerSumcheckProof,
) -> Result<(), ProductSumcheckError> {
    let terms = layer_terms(layer, claims)?;
    verify_sparse_terms(
        combined_claim(claims),
        layer.input_width,
        &terms,
        challenges,
        proof,
    )
}

fn dag_gate_formula(kind: KeccakDagGateKind) -> GateFormula {
    match kind {
        KeccakDagGateKind::Xor => GateFormula::Xor,
        KeccakDagGateKind::NotLeftAndRight => GateFormula::NotLeftAndRight,
        KeccakDagGateKind::XorConstant(false) => GateFormula::Xor,
        KeccakDagGateKind::XorConstant(true) => GateFormula::NotXor,
        KeccakDagGateKind::Zero => GateFormula::Zero,
    }
}

fn evaluate_dag_arithmetic_layer(
    layer: &KeccakDagLayer,
    left: &[Fp16],
    right: &[Fp16],
) -> Result<Vec<Fp16>, ProductSumcheckError> {
    if left.len() != layer.left_width
        || right.len() != layer.right_width
        || layer.gates.len() != layer.padded_width
        || layer.raw_width > layer.padded_width
    {
        return Err(ProductSumcheckError::Shape);
    }
    layer
        .gates
        .iter()
        .map(|gate| {
            if gate.left >= left.len() || gate.right >= right.len() {
                return Err(ProductSumcheckError::Wiring);
            }
            Ok(gate_value(
                dag_gate_formula(gate.kind),
                left[gate.left],
                right[gate.right],
            ))
        })
        .collect()
}

fn dag_layer_terms(
    layer: &KeccakDagLayer,
    claims: &[LayerOutputClaim],
) -> Result<Vec<SparseGateTerm>, ProductSumcheckError> {
    if claims.is_empty()
        || !layer.left_width.is_power_of_two()
        || !layer.right_width.is_power_of_two()
        || !layer.padded_width.is_power_of_two()
        || layer.gates.len() != layer.padded_width
        || layer.raw_width > layer.padded_width
    {
        return Err(ProductSumcheckError::Shape);
    }
    let output_variables = layer.padded_width.trailing_zeros() as usize;
    if claims
        .iter()
        .any(|claim| claim.point.len() != output_variables)
        || claims.iter().all(|claim| claim.coefficient.is_zero())
    {
        return Err(ProductSumcheckError::Shape);
    }
    let claim_weights = claims
        .iter()
        .map(|claim| equality_table(&claim.point))
        .collect::<Result<Vec<_>, _>>()?;
    let mut terms = Vec::with_capacity(layer.raw_width);
    for (output, gate) in layer.gates.iter().copied().enumerate() {
        let output_weight = claims
            .iter()
            .zip(&claim_weights)
            .fold(Fp16::ZERO, |weight, (claim, table)| {
                weight + claim.coefficient * table[output]
            });
        if output_weight.is_zero() || gate.kind == KeccakDagGateKind::Zero {
            continue;
        }
        if gate.left >= layer.left_width || gate.right >= layer.right_width {
            return Err(ProductSumcheckError::Wiring);
        }
        terms.push(SparseGateTerm {
            output_weight,
            left: gate.left,
            right: gate.right,
            formula: dag_gate_formula(gate.kind),
        });
    }
    if terms.is_empty() {
        return Err(ProductSumcheckError::Claim);
    }
    Ok(terms)
}

fn prove_two_source_sparse_terms_reference(
    left_input: &[Fp16],
    right_input: &[Fp16],
    terms: &[SparseGateTerm],
    challenges: &[Fp16],
) -> Result<SparseLayerSumcheckProof, ProductSumcheckError> {
    let left_variables = log2_exact(left_input.len())?;
    let right_variables = log2_exact(right_input.len())?;
    if terms.is_empty() || challenges.len() != left_variables + right_variables {
        return Err(ProductSumcheckError::ChallengeCount);
    }
    let mut left_factors = vec![Fp16::ONE; terms.len()];
    let mut right_factors = vec![Fp16::ONE; terms.len()];
    let mut left_folded = left_input.to_vec();
    let mut right_folded = right_input.to_vec();
    let mut rounds = Vec::with_capacity(challenges.len());

    for (round, challenge) in challenges[..left_variables].iter().copied().enumerate() {
        let mut coefficients = [Fp16::ZERO; 3];
        for (term_index, term) in terms.iter().enumerate() {
            let suffix = term.left >> (round + 1);
            let zero = left_folded[2 * suffix];
            let delta = left_folded[2 * suffix + 1] - zero;
            let (gate_zero, gate_delta) =
                gate_line(term.formula, true, zero, delta, right_input[term.right]);
            let value = weighted_gate_quadratic(
                term.output_weight * left_factors[term_index],
                (term.left >> round) & 1,
                gate_zero,
                gate_delta,
            );
            for coordinate in 0..3 {
                coefficients[coordinate] = coefficients[coordinate] + value[coordinate];
            }
        }
        rounds.push(coefficients);
        for (factor, term) in left_factors.iter_mut().zip(terms) {
            *factor = *factor * bit_basis(challenge, (term.left >> round) & 1);
        }
        fold_multilinear(&mut left_folded, challenge);
    }
    let terminal_left = left_folded[0];

    for (offset, challenge) in challenges[left_variables..].iter().copied().enumerate() {
        let mut coefficients = [Fp16::ZERO; 3];
        for (term_index, term) in terms.iter().enumerate() {
            let suffix = term.right >> (offset + 1);
            let zero = right_folded[2 * suffix];
            let delta = right_folded[2 * suffix + 1] - zero;
            let (gate_zero, gate_delta) =
                gate_line(term.formula, false, zero, delta, terminal_left);
            let value = weighted_gate_quadratic(
                term.output_weight * left_factors[term_index] * right_factors[term_index],
                (term.right >> offset) & 1,
                gate_zero,
                gate_delta,
            );
            for coordinate in 0..3 {
                coefficients[coordinate] = coefficients[coordinate] + value[coordinate];
            }
        }
        rounds.push(coefficients);
        for (factor, term) in right_factors.iter_mut().zip(terms) {
            *factor = *factor * bit_basis(challenge, (term.right >> offset) & 1);
        }
        fold_multilinear(&mut right_folded, challenge);
    }
    Ok(SparseLayerSumcheckProof {
        rounds,
        terminal_left,
        terminal_right: right_folded[0],
    })
}

/// Nonactivating reference proof for a relay-free DAG layer with two explicit
/// source boundaries.
///
/// This is the sound algebraic replacement for copied relay wires. Each
/// terminal is an opening claim on the actual source boundary. The completed
/// challenge vector is KAT input only; production must release every challenge
/// after the preceding masked message through authenticated public coin.
pub fn prove_two_source_sparse_gkr_layer_reference(
    layer: &KeccakDagLayer,
    left_input: &[Fp16],
    right_input: &[Fp16],
    claims: &[LayerOutputClaim],
    challenges: &[Fp16],
) -> Result<SparseLayerSumcheckProof, ProductSumcheckError> {
    let left_variables = log2_exact(layer.left_width)?;
    let right_variables = log2_exact(layer.right_width)?;
    if left_input.len() != layer.left_width
        || right_input.len() != layer.right_width
        || challenges.len() != left_variables + right_variables
    {
        return Err(ProductSumcheckError::ChallengeCount);
    }
    let output = evaluate_dag_arithmetic_layer(layer, left_input, right_input)?;
    for claim in claims {
        if multilinear_evaluate(&output, &claim.point)? != claim.value {
            return Err(ProductSumcheckError::Claim);
        }
    }
    let terms = dag_layer_terms(layer, claims)?;
    prove_two_source_sparse_terms_reference(left_input, right_input, &terms, challenges)
}

pub fn verify_two_source_sparse_gkr_layer_reference(
    layer: &KeccakDagLayer,
    claims: &[LayerOutputClaim],
    challenges: &[Fp16],
    proof: &SparseLayerSumcheckProof,
) -> Result<(), ProductSumcheckError> {
    let terms = dag_layer_terms(layer, claims)?;
    verify_two_source_sparse_terms_from_claim(
        combined_claim(claims),
        layer.left_width,
        layer.right_width,
        &terms,
        challenges,
        proof,
    )
}

fn verify_two_source_sparse_terms_from_claim(
    initial_claim: Fp16,
    left_width: usize,
    right_width: usize,
    terms: &[SparseGateTerm],
    challenges: &[Fp16],
    proof: &SparseLayerSumcheckProof,
) -> Result<(), ProductSumcheckError> {
    let left_variables = log2_exact(left_width)?;
    let right_variables = log2_exact(right_width)?;
    if challenges.len() != left_variables + right_variables
        || proof.rounds.len() != challenges.len()
    {
        return Err(ProductSumcheckError::ChallengeCount);
    }
    let mut claim = initial_claim;
    for (round, challenge) in proof.rounds.iter().copied().zip(challenges.iter().copied()) {
        if round[0] + round[0] + round[1] + round[2] != claim {
            return Err(ProductSumcheckError::Claim);
        }
        claim = evaluate_quadratic(round, challenge);
    }
    let left_weights = equality_table(&challenges[..left_variables])?;
    let right_weights = equality_table(&challenges[left_variables..])?;
    let terminal = terms.iter().fold(Fp16::ZERO, |sum, term| {
        sum + term.output_weight
            * left_weights[term.left]
            * right_weights[term.right]
            * gate_value(term.formula, proof.terminal_left, proof.terminal_right)
    });
    if claim != terminal {
        return Err(ProductSumcheckError::Terminal);
    }
    Ok(())
}

fn fold_shared_group_axis(
    values: &[Fp16],
    width: usize,
    groups: usize,
    challenge: Fp16,
) -> Result<Vec<Fp16>, ProductSumcheckError> {
    if groups < 2
        || !groups.is_power_of_two()
        || values.len()
            != width
                .checked_mul(groups)
                .ok_or(ProductSumcheckError::Shape)?
    {
        return Err(ProductSumcheckError::Shape);
    }
    let mut folded = Vec::with_capacity(values.len() / 2);
    for suffix in 0..groups / 2 {
        let zero_group = 2 * suffix * width;
        let one_group = zero_group + width;
        for wire in 0..width {
            let zero = values[zero_group + wire];
            folded.push(zero + challenge * (values[one_group + wire] - zero));
        }
    }
    Ok(folded)
}

fn shared_group_effective_claims(
    claims: &[LayerOutputClaim],
    output_variables: usize,
    group_challenges: &[Fp16],
) -> Result<Vec<LayerOutputClaim>, ProductSumcheckError> {
    claims
        .iter()
        .map(|claim| {
            if claim.point.len() != output_variables + group_challenges.len() {
                return Err(ProductSumcheckError::Shape);
            }
            Ok(LayerOutputClaim {
                point: claim.point[..output_variables].to_vec(),
                value: Fp16::ZERO,
                coefficient: claim.coefficient
                    * equality_evaluate(&claim.point[output_variables..], group_challenges)?,
            })
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn shared_group_round_polynomial(
    layer: &KeccakDagLayer,
    left_folded: &[Fp16],
    right_folded: &[Fp16],
    claims: &[LayerOutputClaim],
    output_weights: &[Vec<Fp16>],
    claim_prefixes: &[Fp16],
    output_variables: usize,
    round_index: usize,
) -> Result<[Fp16; 4], ProductSumcheckError> {
    let remaining_weights = claims
        .iter()
        .map(|claim| equality_table(&claim.point[output_variables + round_index + 1..]))
        .collect::<Result<Vec<_>, _>>()?;
    let mut coefficients = [Fp16::ZERO; 4];
    for (suffix, _) in remaining_weights[0].iter().enumerate() {
        let left_zero_group = 2 * suffix * layer.left_width;
        let left_one_group = left_zero_group + layer.left_width;
        let right_zero_group = 2 * suffix * layer.right_width;
        let right_one_group = right_zero_group + layer.right_width;
        for (output_index, gate) in layer.gates.iter().copied().enumerate() {
            if gate.kind == KeccakDagGateKind::Zero {
                continue;
            }
            if gate.left >= layer.left_width || gate.right >= layer.right_width {
                return Err(ProductSumcheckError::Wiring);
            }
            let left_zero = left_folded[left_zero_group + gate.left];
            let left_delta = left_folded[left_one_group + gate.left] - left_zero;
            let right_zero = right_folded[right_zero_group + gate.right];
            let right_delta = right_folded[right_one_group + gate.right] - right_zero;
            let gate_polynomial = gate_quadratic_both(
                dag_gate_formula(gate.kind),
                left_zero,
                left_delta,
                right_zero,
                right_delta,
            );
            for (claim_index, claim) in claims.iter().enumerate() {
                let group_coordinate = claim.point[output_variables + round_index];
                let base = claim.coefficient
                    * claim_prefixes[claim_index]
                    * remaining_weights[claim_index][suffix]
                    * output_weights[claim_index][output_index];
                let contribution = equality_times_quadratic(
                    base * (Fp16::ONE - group_coordinate),
                    base * (group_coordinate + group_coordinate - Fp16::ONE),
                    gate_polynomial,
                );
                for coordinate in 0..4 {
                    coefficients[coordinate] = coefficients[coordinate] + contribution[coordinate];
                }
            }
        }
    }
    Ok(coefficients)
}

/// Nonactivating reference prover for a relay-free DAG layer repeated over a
/// shared group axis.
///
/// Source tables are group-major: low index bits select the wire and high bits
/// select the group. The protocol binds each common group bit first with a
/// degree-three sumcheck, then binds the left and right wire labels with the
/// usual degree-two sparse reduction. This ordering preserves the nonlinear
/// gate inside each instance group and never averages a gate input on the host.
///
/// Completed challenges are KAT inputs only. Production must publish each
/// masked message before accepting its authenticated public-coin challenge.
pub fn prove_shared_group_dag_layer_reference(
    layer: &KeccakDagLayer,
    group_count: usize,
    left_input: &[Fp16],
    right_input: &[Fp16],
    claims: &[LayerOutputClaim],
    group_challenges: &[Fp16],
    wire_challenges: &[Fp16],
) -> Result<SharedGroupDagLayerProof, ProductSumcheckError> {
    let left_variables = log2_exact(layer.left_width)?;
    let right_variables = log2_exact(layer.right_width)?;
    let output_variables = log2_exact(layer.padded_width)?;
    let group_variables = log2_exact(group_count)?;
    if claims.is_empty()
        || claims.iter().all(|claim| claim.coefficient.is_zero())
        || group_challenges.len() != group_variables
        || wire_challenges.len() != left_variables + right_variables
        || left_input.len()
            != layer
                .left_width
                .checked_mul(group_count)
                .ok_or(ProductSumcheckError::Shape)?
        || right_input.len()
            != layer
                .right_width
                .checked_mul(group_count)
                .ok_or(ProductSumcheckError::Shape)?
        || layer.gates.len() != layer.padded_width
        || layer.raw_width > layer.padded_width
        || claims
            .iter()
            .any(|claim| claim.point.len() != output_variables + group_variables)
    {
        return Err(ProductSumcheckError::Shape);
    }

    let output_weights = claims
        .iter()
        .map(|claim| equality_table(&claim.point[..output_variables]))
        .collect::<Result<Vec<_>, _>>()?;
    let mut output = Vec::with_capacity(
        layer
            .padded_width
            .checked_mul(group_count)
            .ok_or(ProductSumcheckError::Shape)?,
    );
    for group in 0..group_count {
        output.extend(evaluate_dag_arithmetic_layer(
            layer,
            &left_input[group * layer.left_width..(group + 1) * layer.left_width],
            &right_input[group * layer.right_width..(group + 1) * layer.right_width],
        )?);
    }
    for claim in claims {
        if multilinear_evaluate(&output, &claim.point)? != claim.value {
            return Err(ProductSumcheckError::Claim);
        }
    }

    let mut current_claim = combined_claim(claims);
    let mut current_groups = group_count;
    let mut left_folded = left_input.to_vec();
    let mut right_folded = right_input.to_vec();
    let mut claim_prefixes = vec![Fp16::ONE; claims.len()];
    let mut group_rounds = Vec::with_capacity(group_variables);

    for (round_index, challenge) in group_challenges.iter().copied().enumerate() {
        let remaining_groups = current_groups / 2;
        let coefficients = shared_group_round_polynomial(
            layer,
            &left_folded,
            &right_folded,
            claims,
            &output_weights,
            &claim_prefixes,
            output_variables,
            round_index,
        )?;
        if coefficients[0] + coefficients[0] + coefficients[1] + coefficients[2] + coefficients[3]
            != current_claim
        {
            return Err(ProductSumcheckError::Claim);
        }
        group_rounds.push(coefficients);
        current_claim = evaluate_cubic(coefficients, challenge);
        for (claim_index, claim) in claims.iter().enumerate() {
            claim_prefixes[claim_index] = claim_prefixes[claim_index]
                * equality_line_value(claim.point[output_variables + round_index], challenge);
        }
        left_folded =
            fold_shared_group_axis(&left_folded, layer.left_width, current_groups, challenge)?;
        right_folded =
            fold_shared_group_axis(&right_folded, layer.right_width, current_groups, challenge)?;
        current_groups = remaining_groups;
    }
    if current_groups != 1
        || left_folded.len() != layer.left_width
        || right_folded.len() != layer.right_width
    {
        return Err(ProductSumcheckError::Shape);
    }

    let effective_claims =
        shared_group_effective_claims(claims, output_variables, group_challenges)?;
    let terms = dag_layer_terms(layer, &effective_claims)?;
    let wire_proof = prove_two_source_sparse_terms_reference(
        &left_folded,
        &right_folded,
        &terms,
        wire_challenges,
    )?;
    verify_two_source_sparse_terms_from_claim(
        current_claim,
        layer.left_width,
        layer.right_width,
        &terms,
        wire_challenges,
        &wire_proof,
    )?;
    Ok(SharedGroupDagLayerProof {
        group_rounds,
        wire_proof,
    })
}

/// Exact reference prover for a shared-group layer whose source wire tables
/// are identical in every group.
///
/// This is not a different verifier relation. It is an algebraically reduced
/// prover for the common KAT/zero-trace case: equality weights over every
/// untouched group suffix sum to one, while identical source rows have zero
/// slope along the group axis. The returned proof is accepted by
/// [`verify_shared_group_dag_layer_reference`] without a specialization flag.
pub fn prove_uniform_shared_group_dag_layer_reference(
    layer: &KeccakDagLayer,
    group_count: usize,
    left_wire_values: &[Fp16],
    right_wire_values: &[Fp16],
    claims: &[LayerOutputClaim],
    group_challenges: &[Fp16],
    wire_challenges: &[Fp16],
) -> Result<SharedGroupDagLayerProof, ProductSumcheckError> {
    let left_variables = log2_exact(layer.left_width)?;
    let right_variables = log2_exact(layer.right_width)?;
    let output_variables = log2_exact(layer.padded_width)?;
    let group_variables = log2_exact(group_count)?;
    if claims.is_empty()
        || claims.iter().all(|claim| claim.coefficient.is_zero())
        || left_wire_values.len() != layer.left_width
        || right_wire_values.len() != layer.right_width
        || group_challenges.len() != group_variables
        || wire_challenges.len() != left_variables + right_variables
        || claims
            .iter()
            .any(|claim| claim.point.len() != output_variables + group_variables)
    {
        return Err(ProductSumcheckError::Shape);
    }

    let output = evaluate_dag_arithmetic_layer(layer, left_wire_values, right_wire_values)?;
    for claim in claims {
        if multilinear_evaluate(&output, &claim.point[..output_variables])? != claim.value {
            return Err(ProductSumcheckError::Claim);
        }
    }

    let mut current_claim = combined_claim(claims);
    let mut prefixes = vec![Fp16::ONE; claims.len()];
    let mut group_rounds = Vec::with_capacity(group_variables);
    for (round_index, challenge) in group_challenges.iter().copied().enumerate() {
        let mut coefficients = [Fp16::ZERO; 4];
        for (claim_index, claim) in claims.iter().enumerate() {
            let coordinate = claim.point[output_variables + round_index];
            let base = claim.coefficient * prefixes[claim_index] * claim.value;
            coefficients[0] = coefficients[0] + base * (Fp16::ONE - coordinate);
            coefficients[1] = coefficients[1] + base * (coordinate + coordinate - Fp16::ONE);
            prefixes[claim_index] =
                prefixes[claim_index] * equality_line_value(coordinate, challenge);
        }
        if coefficients[0] + coefficients[0] + coefficients[1] != current_claim {
            return Err(ProductSumcheckError::Claim);
        }
        current_claim = evaluate_cubic(coefficients, challenge);
        group_rounds.push(coefficients);
    }

    let effective_claims =
        shared_group_effective_claims(claims, output_variables, group_challenges)?;
    let terms = dag_layer_terms(layer, &effective_claims)?;
    let wire_proof = prove_two_source_sparse_terms_reference(
        left_wire_values,
        right_wire_values,
        &terms,
        wire_challenges,
    )?;
    verify_two_source_sparse_terms_from_claim(
        current_claim,
        layer.left_width,
        layer.right_width,
        &terms,
        wire_challenges,
        &wire_proof,
    )?;
    Ok(SharedGroupDagLayerProof {
        group_rounds,
        wire_proof,
    })
}

/// Interactive form of
/// [`prove_uniform_shared_group_dag_layer_reference`].
///
/// The provider receives each raw message before returning its authenticated
/// challenge. It may publish a correctly masked extension of that message, but
/// must return the challenge bound to the published bytes. This function keeps
/// only the raw algebra; masking constraints and their PCS opening remain a
/// separate layer.
pub fn prove_uniform_shared_group_dag_layer_interactive(
    layer: &KeccakDagLayer,
    group_count: usize,
    left_wire_values: &[Fp16],
    right_wire_values: &[Fp16],
    claims: &[LayerOutputClaim],
    mut challenge_provider: impl FnMut(
        SharedGroupDagRoundKind,
        usize,
        &[Fp16],
    ) -> Result<Fp16, ProductSumcheckError>,
) -> Result<(SharedGroupDagLayerProof, Vec<Fp16>, Vec<Fp16>), ProductSumcheckError> {
    let left_variables = log2_exact(layer.left_width)?;
    let right_variables = log2_exact(layer.right_width)?;
    let output_variables = log2_exact(layer.padded_width)?;
    let group_variables = log2_exact(group_count)?;
    if claims.is_empty()
        || claims.iter().all(|claim| claim.coefficient.is_zero())
        || left_wire_values.len() != layer.left_width
        || right_wire_values.len() != layer.right_width
        || claims
            .iter()
            .any(|claim| claim.point.len() != output_variables + group_variables)
    {
        return Err(ProductSumcheckError::Shape);
    }
    let output = evaluate_dag_arithmetic_layer(layer, left_wire_values, right_wire_values)?;
    for claim in claims {
        if multilinear_evaluate(&output, &claim.point[..output_variables])? != claim.value {
            return Err(ProductSumcheckError::Claim);
        }
    }

    let mut current_claim = combined_claim(claims);
    let mut prefixes = vec![Fp16::ONE; claims.len()];
    let mut group_rounds = Vec::with_capacity(group_variables);
    let mut group_challenges = Vec::with_capacity(group_variables);
    for round_index in 0..group_variables {
        let mut coefficients = [Fp16::ZERO; 4];
        for (claim_index, claim) in claims.iter().enumerate() {
            let coordinate = claim.point[output_variables + round_index];
            let base = claim.coefficient * prefixes[claim_index] * claim.value;
            coefficients[0] = coefficients[0] + base * (Fp16::ONE - coordinate);
            coefficients[1] = coefficients[1] + base * (coordinate + coordinate - Fp16::ONE);
        }
        if coefficients[0] + coefficients[0] + coefficients[1] != current_claim {
            return Err(ProductSumcheckError::Claim);
        }
        let challenge =
            challenge_provider(SharedGroupDagRoundKind::Group, round_index, &coefficients)?;
        for (claim_index, claim) in claims.iter().enumerate() {
            prefixes[claim_index] = prefixes[claim_index]
                * equality_line_value(claim.point[output_variables + round_index], challenge);
        }
        current_claim = evaluate_cubic(coefficients, challenge);
        group_rounds.push(coefficients);
        group_challenges.push(challenge);
    }

    let effective_claims =
        shared_group_effective_claims(claims, output_variables, &group_challenges)?;
    let terms = dag_layer_terms(layer, &effective_claims)?;
    let mut left_factors = vec![Fp16::ONE; terms.len()];
    let mut right_factors = vec![Fp16::ONE; terms.len()];
    let mut left_folded = left_wire_values.to_vec();
    let mut right_folded = right_wire_values.to_vec();
    let mut wire_rounds = Vec::with_capacity(left_variables + right_variables);
    let mut wire_challenges = Vec::with_capacity(left_variables + right_variables);

    for round_index in 0..left_variables {
        let mut coefficients = [Fp16::ZERO; 3];
        for (term_index, term) in terms.iter().enumerate() {
            let suffix = term.left >> (round_index + 1);
            let zero = left_folded[2 * suffix];
            let delta = left_folded[2 * suffix + 1] - zero;
            let (gate_zero, gate_delta) = gate_line(
                term.formula,
                true,
                zero,
                delta,
                right_wire_values[term.right],
            );
            let value = weighted_gate_quadratic(
                term.output_weight * left_factors[term_index],
                (term.left >> round_index) & 1,
                gate_zero,
                gate_delta,
            );
            for coordinate in 0..3 {
                coefficients[coordinate] = coefficients[coordinate] + value[coordinate];
            }
        }
        if coefficients[0] + coefficients[0] + coefficients[1] + coefficients[2] != current_claim {
            return Err(ProductSumcheckError::Claim);
        }
        let challenge = challenge_provider(
            SharedGroupDagRoundKind::LeftWire,
            round_index,
            &coefficients,
        )?;
        for (factor, term) in left_factors.iter_mut().zip(&terms) {
            *factor = *factor * bit_basis(challenge, (term.left >> round_index) & 1);
        }
        fold_multilinear(&mut left_folded, challenge);
        current_claim = evaluate_quadratic(coefficients, challenge);
        wire_rounds.push(coefficients);
        wire_challenges.push(challenge);
    }
    let terminal_left = left_folded[0];

    for round_index in 0..right_variables {
        let mut coefficients = [Fp16::ZERO; 3];
        for (term_index, term) in terms.iter().enumerate() {
            let suffix = term.right >> (round_index + 1);
            let zero = right_folded[2 * suffix];
            let delta = right_folded[2 * suffix + 1] - zero;
            let (gate_zero, gate_delta) =
                gate_line(term.formula, false, zero, delta, terminal_left);
            let value = weighted_gate_quadratic(
                term.output_weight * left_factors[term_index] * right_factors[term_index],
                (term.right >> round_index) & 1,
                gate_zero,
                gate_delta,
            );
            for coordinate in 0..3 {
                coefficients[coordinate] = coefficients[coordinate] + value[coordinate];
            }
        }
        if coefficients[0] + coefficients[0] + coefficients[1] + coefficients[2] != current_claim {
            return Err(ProductSumcheckError::Claim);
        }
        let challenge = challenge_provider(
            SharedGroupDagRoundKind::RightWire,
            round_index,
            &coefficients,
        )?;
        for (factor, term) in right_factors.iter_mut().zip(&terms) {
            *factor = *factor * bit_basis(challenge, (term.right >> round_index) & 1);
        }
        fold_multilinear(&mut right_folded, challenge);
        current_claim = evaluate_quadratic(coefficients, challenge);
        wire_rounds.push(coefficients);
        wire_challenges.push(challenge);
    }
    let proof = SharedGroupDagLayerProof {
        group_rounds,
        wire_proof: SparseLayerSumcheckProof {
            rounds: wire_rounds,
            terminal_left,
            terminal_right: right_folded[0],
        },
    };
    verify_shared_group_dag_layer_reference(
        layer,
        group_count,
        claims,
        &group_challenges,
        &wire_challenges,
        &proof,
    )?;
    Ok((proof, group_challenges, wire_challenges))
}

/// Native Libra-masked interactive reduction for one shared-group DAG layer.
///
/// Source tables may either contain one row shared by every group (the
/// uniform fast path) or the complete group-major table. The latter is the
/// release path for real B=16 hash-bus data. The final-left Construction-2
/// delta is applied before the right reduction, exactly as required by the
/// nonlinear gate relation.
pub trait MaskedSharedGroupOracle {
    /// Return the raw cubic for the next group variable before its challenge.
    fn raw_group_round(
        &mut self,
        round: usize,
        expected_claim: Fp16,
    ) -> Result<[Fp16; 4], GkrZkMaskError>;

    /// Advance the private folded source only after authentication.
    fn accept_group_challenge(
        &mut self,
        round: usize,
        challenge: Fp16,
    ) -> Result<(), GkrZkMaskError>;

    /// Return the two source wire tables after all group variables are folded.
    fn folded_sources(&mut self) -> Result<(Vec<Fp16>, Vec<Fp16>), GkrZkMaskError>;

    /// Whether this oracle can return raw wire-round quadratics.
    ///
    /// The oracle remains untrusted: Rust applies all native masks, checks the
    /// masked recurrence, authenticates each challenge, and evaluates both
    /// source terminals independently from `folded_sources`.
    fn accelerates_wire_rounds(&self) -> bool {
        false
    }

    /// Return the raw quadratic for the next left- or right-wire variable.
    fn raw_wire_round(
        &mut self,
        _kind: SharedGroupDagRoundKind,
        _round: usize,
        _masked_terminal_left: Option<Fp16>,
    ) -> Result<[Fp16; 3], GkrZkMaskError> {
        Err(GkrZkMaskError::Sequence)
    }

    /// Advance the private wire state only after challenge authentication.
    fn accept_wire_challenge(
        &mut self,
        _kind: SharedGroupDagRoundKind,
        _round: usize,
        _challenge: Fp16,
    ) -> Result<(), GkrZkMaskError> {
        Err(GkrZkMaskError::Sequence)
    }
}

/// Stateful prover-only evaluation of the additive Libra sumcheck mask.
///
/// The public mask object and independent verifier remain stateless. This
/// accumulator only avoids rebuilding the accepted-prefix evaluation and
/// rescanning all future coefficients before every prover round.
struct LibraMaskRoundAccumulator<'a> {
    mask: &'a LibraVariableDegreeSumcheckMask,
    scales: Vec<Fp16>,
    prefix_evaluation: Fp16,
    future_coefficient_sum: Fp16,
    next_round: usize,
    pending: bool,
}

impl<'a> LibraMaskRoundAccumulator<'a> {
    fn new(mask: &'a LibraVariableDegreeSumcheckMask) -> Result<Self, GkrZkMaskError> {
        let variable_count = mask.variable_coefficients.len();
        if variable_count == 0
            || mask
                .variable_coefficients
                .iter()
                .any(|coefficients| coefficients.is_empty())
        {
            return Err(GkrZkMaskError::Empty);
        }
        let mut scales = vec![Fp16::ONE; variable_count];
        for round in (0..variable_count - 1).rev() {
            scales[round] = scales[round + 1] + scales[round + 1];
        }
        let future_coefficient_sum = mask
            .variable_coefficients
            .iter()
            .flatten()
            .fold(Fp16::ZERO, |sum, coefficient| sum + *coefficient);
        Ok(Self {
            mask,
            scales,
            prefix_evaluation: mask.constant,
            future_coefficient_sum,
            next_round: 0,
            pending: false,
        })
    }

    fn round_polynomial(&mut self, round: usize) -> Result<Vec<Fp16>, GkrZkMaskError> {
        if self.pending
            || round != self.next_round
            || round >= self.mask.variable_coefficients.len()
        {
            return Err(GkrZkMaskError::Sequence);
        }
        let coefficients = &self.mask.variable_coefficients[round];
        let current_coefficient_sum = coefficients
            .iter()
            .fold(Fp16::ZERO, |sum, coefficient| sum + *coefficient);
        self.future_coefficient_sum = self.future_coefficient_sum - current_coefficient_sum;

        let remaining = self.mask.variable_coefficients.len() - round - 1;
        let mut constant = self.prefix_evaluation * self.scales[round];
        if remaining != 0 {
            constant = constant + self.future_coefficient_sum * self.scales[round + 1];
        }
        let mut polynomial = Vec::with_capacity(coefficients.len() + 1);
        polynomial.push(constant);
        polynomial.extend(
            coefficients
                .iter()
                .map(|coefficient| *coefficient * self.scales[round]),
        );
        self.pending = true;
        Ok(polynomial)
    }

    fn accept_challenge(&mut self, challenge: Fp16) -> Result<(), GkrZkMaskError> {
        if !self.pending || self.next_round >= self.mask.variable_coefficients.len() {
            return Err(GkrZkMaskError::Sequence);
        }
        let mut power = challenge;
        for coefficient in &self.mask.variable_coefficients[self.next_round] {
            self.prefix_evaluation = self.prefix_evaluation + *coefficient * power;
            power = power * challenge;
        }
        self.next_round += 1;
        self.pending = false;
        Ok(())
    }

    fn finish(self) -> Result<Fp16, GkrZkMaskError> {
        if self.pending || self.next_round != self.mask.variable_coefficients.len() {
            return Err(GkrZkMaskError::Sequence);
        }
        Ok(self.prefix_evaluation)
    }
}

#[allow(clippy::too_many_arguments)]
fn prove_masked_shared_group_dag_layer_interactive_internal(
    layer: &KeccakDagLayer,
    group_count: usize,
    left_wire_values: &[Fp16],
    right_wire_values: &[Fp16],
    mut group_oracle: Option<&mut dyn MaskedSharedGroupOracle>,
    claims: &[LayerOutputClaim],
    prior_correction: &LibraPriorLayerCorrection,
    sumcheck_mask: &LibraVariableDegreeSumcheckMask,
    layer_mask: &LibraLayerMask,
    sumcheck_rho: Fp16,
    mut round_provider: impl FnMut(
        SharedGroupDagRoundKind,
        usize,
        &[Fp16],
    ) -> Result<Fp16, GkrZkMaskError>,
    mut terminal_provider: impl FnMut(&[Fp16], Fp16, Fp16) -> Result<Fp16, GkrZkMaskError>,
) -> Result<MaskedUniformSharedGroupDagLayerProof, GkrZkMaskError> {
    let left_variables = log2_exact(layer.left_width).map_err(|_| GkrZkMaskError::Shape)?;
    let right_variables = log2_exact(layer.right_width).map_err(|_| GkrZkMaskError::Shape)?;
    let output_variables = log2_exact(layer.padded_width).map_err(|_| GkrZkMaskError::Shape)?;
    let group_variables = log2_exact(group_count).map_err(|_| GkrZkMaskError::Shape)?;
    let variable_degrees = sumcheck_mask.variable_degrees();
    let expected_variables = group_variables + left_variables + right_variables + 1;
    let uniform_sources =
        left_wire_values.len() == layer.left_width && right_wire_values.len() == layer.right_width;
    let complete_sources = left_wire_values.len()
        == layer
            .left_width
            .checked_mul(group_count)
            .ok_or(GkrZkMaskError::Shape)?
        && right_wire_values.len()
            == layer
                .right_width
                .checked_mul(group_count)
                .ok_or(GkrZkMaskError::Shape)?;
    let oracle_sources = group_oracle.is_some();
    if claims.is_empty()
        || claims.iter().all(|claim| claim.coefficient.is_zero())
        || (!uniform_sources && !complete_sources && !oracle_sources)
        || claims
            .iter()
            .any(|claim| claim.point.len() != output_variables + group_variables)
        || variable_degrees.len() != expected_variables
        || variable_degrees[..group_variables]
            .iter()
            .any(|degree| *degree != 3)
        || variable_degrees[group_variables..expected_variables - 1]
            .iter()
            .enumerate()
            .any(|(round, degree)| {
                let final_left = round + 1 == left_variables;
                let final_right = round + 1 == left_variables + right_variables;
                *degree != if final_left || final_right { 3 } else { 2 }
            })
        || variable_degrees[expected_variables - 1] != 2
        || sumcheck_rho.is_zero()
    {
        return Err(GkrZkMaskError::Shape);
    }
    let output = if oracle_sources {
        None
    } else if uniform_sources {
        Some(
            evaluate_dag_arithmetic_layer(layer, left_wire_values, right_wire_values)
                .map_err(|_| GkrZkMaskError::Shape)?,
        )
    } else {
        let mut output = Vec::with_capacity(
            layer
                .padded_width
                .checked_mul(group_count)
                .ok_or(GkrZkMaskError::Shape)?,
        );
        for group in 0..group_count {
            output.extend(
                evaluate_dag_arithmetic_layer(
                    layer,
                    &left_wire_values[group * layer.left_width..(group + 1) * layer.left_width],
                    &right_wire_values[group * layer.right_width..(group + 1) * layer.right_width],
                )
                .map_err(|_| GkrZkMaskError::Shape)?,
            );
        }
        Some(output)
    };
    if let Some(output) = &output {
        for claim in claims {
            let point = if uniform_sources {
                &claim.point[..output_variables]
            } else {
                &claim.point
            };
            if multilinear_evaluate(output, point).map_err(|_| GkrZkMaskError::Shape)?
                != claim.value
            {
                return Err(GkrZkMaskError::Claim);
            }
        }
    }

    fn add(destination: &mut [Fp16], source: &[Fp16]) -> Result<(), GkrZkMaskError> {
        if source.len() > destination.len() {
            return Err(GkrZkMaskError::Shape);
        }
        for (destination, source) in destination.iter_mut().zip(source) {
            *destination = *destination + *source;
        }
        Ok(())
    }

    let raw_initial_claim = combined_claim(claims);
    let prior_boolean_sum = prior_correction.boolean_sum();
    let mut state = CommittedMaskedSumcheckState::new(
        raw_initial_claim,
        prior_boolean_sum,
        sumcheck_mask.boolean_sum(),
        sumcheck_rho,
        variable_degrees.clone(),
    )?;
    let mut mask_rounds = LibraMaskRoundAccumulator::new(sumcheck_mask)?;
    let mut prior_prefix_equality = Fp16::ONE;
    let mut base_rounds = Vec::with_capacity(expected_variables);
    let mut published_rounds = Vec::with_capacity(expected_variables);
    let mut group_challenges = Vec::with_capacity(group_variables);
    let mut wire_challenges = Vec::with_capacity(left_variables + right_variables);
    let mut prefixes = vec![Fp16::ONE; claims.len()];
    let mut raw_claim = raw_initial_claim;
    let output_weights = if oracle_sources {
        Vec::new()
    } else {
        claims
            .iter()
            .map(|claim| equality_table(&claim.point[..output_variables]))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| GkrZkMaskError::Shape)?
    };
    let mut current_groups = group_count;
    let mut left_folded = if oracle_sources {
        Vec::new()
    } else {
        left_wire_values.to_vec()
    };
    let mut right_folded = if oracle_sources {
        Vec::new()
    } else {
        right_wire_values.to_vec()
    };

    for round_index in 0..group_variables {
        let raw = if let Some(oracle) = group_oracle.as_deref_mut() {
            oracle.raw_group_round(round_index, raw_claim)?
        } else if uniform_sources {
            let mut raw = [Fp16::ZERO; 4];
            for (claim_index, claim) in claims.iter().enumerate() {
                let coordinate = claim.point[output_variables + round_index];
                let base = claim.coefficient * prefixes[claim_index] * claim.value;
                raw[0] = raw[0] + base * (Fp16::ONE - coordinate);
                raw[1] = raw[1] + base * (coordinate + coordinate - Fp16::ONE);
            }
            raw
        } else {
            shared_group_round_polynomial(
                layer,
                &left_folded,
                &right_folded,
                claims,
                &output_weights,
                &prefixes,
                output_variables,
                round_index,
            )
            .map_err(|_| GkrZkMaskError::Shape)?
        };
        if raw[0] + raw[0] + raw[1] + raw[2] + raw[3] != raw_claim {
            return Err(GkrZkMaskError::Claim);
        }
        let mut base = raw.to_vec();
        let prior_constant = prior_prefix_equality * prior_boolean_sum;
        add(&mut base, &[prior_constant, -prior_constant])?;
        let mask = mask_rounds.round_polynomial(round_index)?;
        let published = state.publish_round(&base, &mask, sumcheck_rho)?;
        let challenge = round_provider(SharedGroupDagRoundKind::Group, round_index, &published)?;
        state.accept_authenticated_challenge(challenge)?;
        mask_rounds.accept_challenge(challenge)?;
        prior_prefix_equality = prior_prefix_equality * (Fp16::ONE - challenge);
        for (claim_index, claim) in claims.iter().enumerate() {
            prefixes[claim_index] = prefixes[claim_index]
                * equality_line_value(claim.point[output_variables + round_index], challenge);
        }
        raw_claim = evaluate_cubic(raw, challenge);
        if let Some(oracle) = group_oracle.as_deref_mut() {
            oracle.accept_group_challenge(round_index, challenge)?;
        } else if !uniform_sources {
            left_folded =
                fold_shared_group_axis(&left_folded, layer.left_width, current_groups, challenge)
                    .map_err(|_| GkrZkMaskError::Shape)?;
            right_folded =
                fold_shared_group_axis(&right_folded, layer.right_width, current_groups, challenge)
                    .map_err(|_| GkrZkMaskError::Shape)?;
            current_groups /= 2;
        }
        base_rounds.push(base);
        published_rounds.push(published);
        group_challenges.push(challenge);
    }

    if let Some(oracle) = group_oracle.as_deref_mut() {
        (left_folded, right_folded) = oracle.folded_sources()?;
        current_groups = 1;
    }
    let accelerate_wire_rounds = group_oracle
        .as_deref()
        .is_some_and(MaskedSharedGroupOracle::accelerates_wire_rounds);

    let effective_claims =
        shared_group_effective_claims(claims, output_variables, &group_challenges)
            .map_err(|_| GkrZkMaskError::Shape)?;
    let terms = dag_layer_terms(layer, &effective_claims).map_err(|_| GkrZkMaskError::Shape)?;
    let mut left_factors = if accelerate_wire_rounds {
        Vec::new()
    } else {
        vec![Fp16::ONE; terms.len()]
    };
    let mut right_factors = if accelerate_wire_rounds {
        Vec::new()
    } else {
        vec![Fp16::ONE; terms.len()]
    };
    if left_folded.len() != layer.left_width
        || right_folded.len() != layer.right_width
        || (!uniform_sources && current_groups != 1)
    {
        return Err(GkrZkMaskError::Shape);
    }
    let right_group_folded = if accelerate_wire_rounds {
        Vec::new()
    } else {
        right_folded.clone()
    };
    let mut terminal_left_equality = None;
    let mut terminal_right_equality = None;

    for round_index in 0..left_variables {
        let raw = if accelerate_wire_rounds {
            group_oracle
                .as_deref_mut()
                .ok_or(GkrZkMaskError::Sequence)?
                .raw_wire_round(SharedGroupDagRoundKind::LeftWire, round_index, None)?
        } else {
            let mut raw = [Fp16::ZERO; 3];
            for (term_index, term) in terms.iter().enumerate() {
                let suffix = term.left >> (round_index + 1);
                let zero = left_folded[2 * suffix];
                let delta = left_folded[2 * suffix + 1] - zero;
                let (gate_zero, gate_delta) = gate_line(
                    term.formula,
                    true,
                    zero,
                    delta,
                    right_group_folded[term.right],
                );
                let contribution = weighted_gate_quadratic(
                    term.output_weight * left_factors[term_index],
                    (term.left >> round_index) & 1,
                    gate_zero,
                    gate_delta,
                );
                for degree in 0..3 {
                    raw[degree] = raw[degree] + contribution[degree];
                }
            }
            raw
        };
        if raw[0] + raw[0] + raw[1] + raw[2] != raw_claim {
            return Err(GkrZkMaskError::Claim);
        }
        let ordinal = group_variables + round_index;
        let mut base = vec![Fp16::ZERO; variable_degrees[ordinal] + 1];
        base[..3].copy_from_slice(&raw);
        let prior_constant = prior_prefix_equality * prior_boolean_sum;
        add(&mut base, &[prior_constant, -prior_constant])?;
        let mut final_prefix_equality = None;
        if round_index + 1 == left_variables {
            let (cubic, prefix_equality) = shared_group_terminal_extension_cubic_from_terms(
                layer,
                &terms,
                &group_challenges,
                &wire_challenges,
                &[],
                if accelerate_wire_rounds {
                    &right_folded
                } else {
                    &right_group_folded
                },
                None,
                layer_mask,
                true,
                None,
            )?;
            final_prefix_equality = Some(prefix_equality);
            add(&mut base, &cubic)?;
        }
        let mask = mask_rounds.round_polynomial(ordinal)?;
        let published = state.publish_round(&base, &mask, sumcheck_rho)?;
        let challenge = round_provider(SharedGroupDagRoundKind::LeftWire, round_index, &published)?;
        state.accept_authenticated_challenge(challenge)?;
        mask_rounds.accept_challenge(challenge)?;
        prior_prefix_equality = prior_prefix_equality * (Fp16::ONE - challenge);
        if let Some(prefix_equality) = final_prefix_equality {
            terminal_left_equality = Some(extend_equality_table(prefix_equality, challenge));
        }
        if accelerate_wire_rounds {
            group_oracle
                .as_deref_mut()
                .ok_or(GkrZkMaskError::Sequence)?
                .accept_wire_challenge(SharedGroupDagRoundKind::LeftWire, round_index, challenge)?;
        } else {
            for (factor, term) in left_factors.iter_mut().zip(&terms) {
                *factor = *factor * bit_basis(challenge, (term.left >> round_index) & 1);
            }
            fold_multilinear(&mut left_folded, challenge);
        }
        raw_claim = evaluate_quadratic(raw, challenge);
        base_rounds.push(base);
        published_rounds.push(published);
        wire_challenges.push(challenge);
    }
    let left_weights = terminal_left_equality
        .as_deref()
        .filter(|weights| weights.len() == layer.left_width)
        .ok_or(GkrZkMaskError::Shape)?;
    let raw_terminal_left = if accelerate_wire_rounds {
        left_folded
            .iter()
            .zip(left_weights)
            .fold(Fp16::ZERO, |sum, (value, weight)| sum + *value * *weight)
    } else {
        left_folded[0]
    };
    let left_point = wire_challenges[..left_variables]
        .iter()
        .chain(&group_challenges)
        .copied()
        .collect::<Vec<_>>();
    let left_delta = terminal_vanishing_coefficient(layer_mask, &left_point)?;
    let masked_terminal_left = raw_terminal_left + left_delta;

    for round_index in 0..right_variables {
        let raw = if accelerate_wire_rounds {
            group_oracle
                .as_deref_mut()
                .ok_or(GkrZkMaskError::Sequence)?
                .raw_wire_round(
                    SharedGroupDagRoundKind::RightWire,
                    round_index,
                    Some(masked_terminal_left),
                )?
        } else {
            let mut raw = [Fp16::ZERO; 3];
            for (term_index, term) in terms.iter().enumerate() {
                let suffix = term.right >> (round_index + 1);
                let zero = right_folded[2 * suffix];
                let delta = right_folded[2 * suffix + 1] - zero;
                let (gate_zero, gate_delta) =
                    gate_line(term.formula, false, zero, delta, masked_terminal_left);
                let contribution = weighted_gate_quadratic(
                    term.output_weight * left_factors[term_index] * right_factors[term_index],
                    (term.right >> round_index) & 1,
                    gate_zero,
                    gate_delta,
                );
                for degree in 0..3 {
                    raw[degree] = raw[degree] + contribution[degree];
                }
            }
            raw
        };
        let ordinal = group_variables + left_variables + round_index;
        let mut base = vec![Fp16::ZERO; variable_degrees[ordinal] + 1];
        base[..3].copy_from_slice(&raw);
        let prior_constant = prior_prefix_equality * prior_boolean_sum;
        add(&mut base, &[prior_constant, -prior_constant])?;
        let mut final_prefix_equality = None;
        if round_index + 1 == right_variables {
            let (cubic, prefix_equality) = shared_group_terminal_extension_cubic_from_terms(
                layer,
                &terms,
                &group_challenges,
                &wire_challenges[..left_variables],
                &wire_challenges[left_variables..],
                if accelerate_wire_rounds {
                    &right_folded
                } else {
                    &right_group_folded
                },
                Some(masked_terminal_left),
                layer_mask,
                false,
                terminal_left_equality.as_deref(),
            )?;
            final_prefix_equality = Some(prefix_equality);
            add(&mut base, &cubic)?;
        }
        let mask = mask_rounds.round_polynomial(ordinal)?;
        let published = state.publish_round(&base, &mask, sumcheck_rho)?;
        let challenge =
            round_provider(SharedGroupDagRoundKind::RightWire, round_index, &published)?;
        state.accept_authenticated_challenge(challenge)?;
        mask_rounds.accept_challenge(challenge)?;
        prior_prefix_equality = prior_prefix_equality * (Fp16::ONE - challenge);
        if let Some(prefix_equality) = final_prefix_equality {
            terminal_right_equality = Some(extend_equality_table(prefix_equality, challenge));
        }
        if accelerate_wire_rounds {
            group_oracle
                .as_deref_mut()
                .ok_or(GkrZkMaskError::Sequence)?
                .accept_wire_challenge(
                    SharedGroupDagRoundKind::RightWire,
                    round_index,
                    challenge,
                )?;
        } else {
            for (factor, term) in right_factors.iter_mut().zip(&terms) {
                *factor = *factor * bit_basis(challenge, (term.right >> round_index) & 1);
            }
            fold_multilinear(&mut right_folded, challenge);
        }
        base_rounds.push(base);
        published_rounds.push(published);
        wire_challenges.push(challenge);
    }
    let right_weights = terminal_right_equality
        .as_deref()
        .filter(|weights| weights.len() == layer.right_width)
        .ok_or(GkrZkMaskError::Shape)?;
    let raw_terminal_right = if accelerate_wire_rounds {
        right_folded
            .iter()
            .zip(right_weights)
            .fold(Fp16::ZERO, |sum, (value, weight)| sum + *value * *weight)
    } else {
        right_folded[0]
    };
    let right_point = wire_challenges[left_variables..]
        .iter()
        .chain(&group_challenges)
        .copied()
        .collect::<Vec<_>>();
    let right_delta = terminal_vanishing_coefficient(layer_mask, &right_point)?;
    let masked_terminal_right = raw_terminal_right + right_delta;

    let terminal_gate = terms.iter().fold(Fp16::ZERO, |sum, term| {
        sum + term.output_weight
            * left_weights[term.left]
            * right_weights[term.right]
            * gate_value(term.formula, masked_terminal_left, masked_terminal_right)
    });
    let mut xy_point = group_challenges.clone();
    xy_point.extend_from_slice(&wire_challenges);
    let mut w_base = prior_correction
        .w_polynomial
        .map(|coefficient| coefficient * prior_prefix_equality);
    w_base[0] = w_base[0] + terminal_gate;
    w_base[1] = w_base[1] - terminal_gate;
    let w_ordinal = expected_variables - 1;
    let w_mask = mask_rounds.round_polynomial(w_ordinal)?;
    let w_published = state.publish_round(&w_base, &w_mask, sumcheck_rho)?;
    let w_challenge = terminal_provider(&w_published, masked_terminal_left, masked_terminal_right)?;
    state.accept_authenticated_challenge(w_challenge)?;
    mask_rounds.accept_challenge(w_challenge)?;
    xy_point.push(w_challenge);
    let base_oracle = polynomial_evaluation(&w_base, w_challenge);
    let incremental_mask_oracle = mask_rounds.finish()?;
    let mask_oracle = sumcheck_mask.evaluate(&xy_point)?;
    if incremental_mask_oracle != mask_oracle {
        return Err(GkrZkMaskError::Claim);
    }
    let completed = state.finish(base_oracle, mask_oracle, sumcheck_rho)?;
    if completed.len() != expected_variables {
        return Err(GkrZkMaskError::Sequence);
    }
    base_rounds.push(w_base.to_vec());
    published_rounds.push(w_published.clone());
    Ok(MaskedUniformSharedGroupDagLayerProof {
        base_rounds,
        published_rounds,
        group_challenges,
        wire_challenges,
        raw_terminal_left,
        raw_terminal_right,
        masked_terminal_left,
        masked_terminal_right,
        w_base,
        w_published,
        w_challenge,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn prove_masked_shared_group_dag_layer_interactive(
    layer: &KeccakDagLayer,
    group_count: usize,
    left_wire_values: &[Fp16],
    right_wire_values: &[Fp16],
    claims: &[LayerOutputClaim],
    prior_correction: &LibraPriorLayerCorrection,
    sumcheck_mask: &LibraVariableDegreeSumcheckMask,
    layer_mask: &LibraLayerMask,
    sumcheck_rho: Fp16,
    round_provider: impl FnMut(SharedGroupDagRoundKind, usize, &[Fp16]) -> Result<Fp16, GkrZkMaskError>,
    terminal_provider: impl FnMut(&[Fp16], Fp16, Fp16) -> Result<Fp16, GkrZkMaskError>,
) -> Result<MaskedUniformSharedGroupDagLayerProof, GkrZkMaskError> {
    prove_masked_shared_group_dag_layer_interactive_internal(
        layer,
        group_count,
        left_wire_values,
        right_wire_values,
        None,
        claims,
        prior_correction,
        sumcheck_mask,
        layer_mask,
        sumcheck_rho,
        round_provider,
        terminal_provider,
    )
}

/// Prove one nonuniform shared-group layer without materializing either full
/// Fp16 source table in Rust. The oracle is untrusted: Rust checks every cubic
/// endpoint recurrence, releases each challenge only after publication, then
/// binds the returned folded sources through the unchanged wire-tail and
/// terminal checks.
///
/// The caller must bind the initial output claims to the authenticated output
/// boundary before invoking this reduction. The reduction itself binds those
/// claims to the two source openings through the complete sumcheck chain.
#[allow(clippy::too_many_arguments)]
pub fn prove_masked_shared_group_dag_layer_oracle_interactive(
    layer: &KeccakDagLayer,
    group_count: usize,
    group_oracle: &mut dyn MaskedSharedGroupOracle,
    claims: &[LayerOutputClaim],
    prior_correction: &LibraPriorLayerCorrection,
    sumcheck_mask: &LibraVariableDegreeSumcheckMask,
    layer_mask: &LibraLayerMask,
    sumcheck_rho: Fp16,
    round_provider: impl FnMut(SharedGroupDagRoundKind, usize, &[Fp16]) -> Result<Fp16, GkrZkMaskError>,
    terminal_provider: impl FnMut(&[Fp16], Fp16, Fp16) -> Result<Fp16, GkrZkMaskError>,
) -> Result<MaskedUniformSharedGroupDagLayerProof, GkrZkMaskError> {
    prove_masked_shared_group_dag_layer_interactive_internal(
        layer,
        group_count,
        &[],
        &[],
        Some(group_oracle),
        claims,
        prior_correction,
        sumcheck_mask,
        layer_mask,
        sumcheck_rho,
        round_provider,
        terminal_provider,
    )
}

pub fn shared_group_terminal_gate_claim(
    layer: &KeccakDagLayer,
    group_count: usize,
    claims: &[LayerOutputClaim],
    group_challenges: &[Fp16],
    wire_challenges: &[Fp16],
    terminal_left: Fp16,
    terminal_right: Fp16,
) -> Result<Fp16, ProductSumcheckError> {
    let output_variables = log2_exact(layer.padded_width)?;
    let group_variables = log2_exact(group_count)?;
    let left_variables = log2_exact(layer.left_width)?;
    let right_variables = log2_exact(layer.right_width)?;
    if group_challenges.len() != group_variables
        || wire_challenges.len() != left_variables + right_variables
    {
        return Err(ProductSumcheckError::Shape);
    }
    let effective = shared_group_effective_claims(claims, output_variables, group_challenges)?;
    let terms = dag_layer_terms(layer, &effective)?;
    let left_weights = equality_table(&wire_challenges[..left_variables])?;
    let right_weights = equality_table(&wire_challenges[left_variables..])?;
    Ok(terms.iter().fold(Fp16::ZERO, |sum, term| {
        sum + term.output_weight
            * left_weights[term.left]
            * right_weights[term.right]
            * gate_value(term.formula, terminal_left, terminal_right)
    }))
}

/// Verify the shared-group reference relation without trusting prover-supplied
/// wiring or group factors. The two terminal values remain PCS opening claims
/// at `(wire_challenge, group_challenge)` on the two source boundaries.
pub fn verify_shared_group_dag_layer_reference(
    layer: &KeccakDagLayer,
    group_count: usize,
    claims: &[LayerOutputClaim],
    group_challenges: &[Fp16],
    wire_challenges: &[Fp16],
    proof: &SharedGroupDagLayerProof,
) -> Result<(), ProductSumcheckError> {
    let output_variables = log2_exact(layer.padded_width)?;
    let group_variables = log2_exact(group_count)?;
    if claims.is_empty()
        || claims.iter().all(|claim| claim.coefficient.is_zero())
        || group_challenges.len() != group_variables
        || proof.group_rounds.len() != group_variables
        || claims
            .iter()
            .any(|claim| claim.point.len() != output_variables + group_variables)
    {
        return Err(ProductSumcheckError::Shape);
    }
    let mut current_claim = combined_claim(claims);
    for (round, challenge) in proof
        .group_rounds
        .iter()
        .copied()
        .zip(group_challenges.iter().copied())
    {
        if round[0] + round[0] + round[1] + round[2] + round[3] != current_claim {
            return Err(ProductSumcheckError::Claim);
        }
        current_claim = evaluate_cubic(round, challenge);
    }
    let effective_claims =
        shared_group_effective_claims(claims, output_variables, group_challenges)?;
    let terms = dag_layer_terms(layer, &effective_claims)?;
    verify_two_source_sparse_terms_from_claim(
        current_claim,
        layer.left_width,
        layer.right_width,
        &terms,
        wire_challenges,
        &proof.wire_proof,
    )
}

pub fn verify_masked_sparse_gkr_layer(
    layer: &KeccakGkrLayer,
    claims: &[LayerOutputClaim],
    challenges: &[Fp16],
    proof: &MaskedSparseLayerSumcheckProof,
) -> Result<(), ProductSumcheckError> {
    let terms = layer_terms(layer, claims)?;
    verify_masked_sparse_terms(
        combined_claim(claims),
        layer.input_width,
        &terms,
        challenges,
        proof,
    )
}

fn verify_masked_sparse_terms(
    initial_claim: Fp16,
    input_width: usize,
    terms: &[SparseGateTerm],
    challenges: &[Fp16],
    proof: &MaskedSparseLayerSumcheckProof,
) -> Result<(), ProductSumcheckError> {
    let input_variables = log2_exact(input_width)?;
    if challenges.len() != 2 * input_variables || proof.rounds.len() != challenges.len() {
        return Err(ProductSumcheckError::ChallengeCount);
    }
    let mut claim = initial_claim;
    for (round, challenge) in proof.rounds.iter().copied().zip(challenges.iter().copied()) {
        if round[0] + round[0] + round[1] + round[2] != claim {
            return Err(ProductSumcheckError::Claim);
        }
        claim = evaluate_quadratic(round, challenge);
    }
    let left_weights = equality_table(&challenges[..input_variables])?;
    let right_weights = equality_table(&challenges[input_variables..])?;
    let terminal = terms.iter().fold(Fp16::ZERO, |sum, term| {
        sum + term.output_weight
            * left_weights[term.left]
            * right_weights[term.right]
            * gate_value(term.formula, proof.terminal_left, proof.terminal_right)
    });
    if claim != terminal + proof.terminal_correction {
        return Err(ProductSumcheckError::Terminal);
    }
    Ok(())
}

pub fn verify_masked_repeated_sparse_layer(
    layer: &KeccakGkrLayer,
    group_count: usize,
    initial_claim: Fp16,
    claims: &[LayerOutputClaim],
    challenges: &[Fp16],
    proof: &MaskedSparseLayerSumcheckProof,
) -> Result<(), OnePackLayerGkrError> {
    let sparse = SparseLayerSumcheckProof {
        rounds: proof.rounds.clone(),
        terminal_left: proof.terminal_left,
        terminal_right: proof.terminal_right,
    };
    verify_repeated_sparse_terms_factored(
        initial_claim,
        layer,
        group_count,
        claims,
        challenges,
        &sparse,
        proof.terminal_correction,
    )?;
    Ok(())
}

/// Nonactivating algebra control for a complete adjacent-layer chain. It carries
/// the two terminal claims
/// backward with fresh authenticated public-coin mixing coefficients.
///
/// This establishes the GKR claim flow only. The two returned input claims
/// still have to be opened against the hiding input commitment.
/// Bulk challenges are KAT input, not a production message/coin schedule.
pub fn prove_sparse_gkr_chain(
    layers: &[KeccakGkrLayer],
    input: &[Fp16],
    output_point: &[Fp16],
    layer_challenges: &[Vec<Fp16>],
    claim_mix_challenges: &[Fp16],
) -> Result<(Fp16, SparseGkrChainProof, Vec<LayerOutputClaim>), ProductSumcheckError> {
    if layers.is_empty()
        || layer_challenges.len() != layers.len()
        || claim_mix_challenges.len() + 1 != layers.len()
        || input.len() != layers[0].input_width
    {
        return Err(ProductSumcheckError::Shape);
    }
    for pair in layers.windows(2) {
        if pair[0].padded_width != pair[1].input_width {
            return Err(ProductSumcheckError::Wiring);
        }
    }
    let mut boundaries = Vec::with_capacity(layers.len() + 1);
    boundaries.push(input.to_vec());
    for layer in layers {
        let output = evaluate_arithmetic_layer(
            layer,
            boundaries.last().ok_or(ProductSumcheckError::Shape)?,
        )?;
        boundaries.push(output);
    }
    let output_value = multilinear_evaluate(
        boundaries.last().ok_or(ProductSumcheckError::Shape)?,
        output_point,
    )?;
    let mut claims = vec![LayerOutputClaim {
        point: output_point.to_vec(),
        value: output_value,
        coefficient: Fp16::ONE,
    }];
    let mut proofs = Vec::with_capacity(layers.len());
    for layer_index in (0..layers.len()).rev() {
        let proof = prove_sparse_gkr_layer(
            &layers[layer_index],
            &boundaries[layer_index],
            &claims,
            &layer_challenges[layer_index],
        )?;
        let input_variables = layers[layer_index].input_width.trailing_zeros() as usize;
        let left_point = layer_challenges[layer_index][..input_variables].to_vec();
        let right_point = layer_challenges[layer_index][input_variables..].to_vec();
        let terminal_left = proof.terminal_left;
        let terminal_right = proof.terminal_right;
        proofs.push(proof);
        if layer_index == 0 {
            claims = vec![
                LayerOutputClaim {
                    point: left_point,
                    value: terminal_left,
                    coefficient: Fp16::ONE,
                },
                LayerOutputClaim {
                    point: right_point,
                    value: terminal_right,
                    coefficient: Fp16::ONE,
                },
            ];
        } else {
            let mix = claim_mix_challenges[layers.len() - 1 - layer_index];
            claims = vec![
                LayerOutputClaim {
                    point: left_point,
                    value: terminal_left,
                    coefficient: mix,
                },
                LayerOutputClaim {
                    point: right_point,
                    value: terminal_right,
                    coefficient: Fp16::ONE - mix,
                },
            ];
        }
    }
    Ok((output_value, SparseGkrChainProof { layers: proofs }, claims))
}

/// Verify the public wiring and claim flow for the nonactivating chain control.
///
/// The returned claims are the exact input-polynomial openings that the
/// containing hiding PCS must authenticate.
pub fn verify_sparse_gkr_chain(
    layers: &[KeccakGkrLayer],
    output_point: &[Fp16],
    expected_output_value: Fp16,
    layer_challenges: &[Vec<Fp16>],
    claim_mix_challenges: &[Fp16],
    proof: &SparseGkrChainProof,
) -> Result<Vec<LayerOutputClaim>, ProductSumcheckError> {
    if layers.is_empty()
        || proof.layers.len() != layers.len()
        || layer_challenges.len() != layers.len()
        || claim_mix_challenges.len() + 1 != layers.len()
    {
        return Err(ProductSumcheckError::Shape);
    }
    for pair in layers.windows(2) {
        if pair[0].padded_width != pair[1].input_width {
            return Err(ProductSumcheckError::Wiring);
        }
    }
    let mut claims = vec![LayerOutputClaim {
        point: output_point.to_vec(),
        value: expected_output_value,
        coefficient: Fp16::ONE,
    }];
    for (proof_index, layer_index) in (0..layers.len()).rev().enumerate() {
        let layer_proof = &proof.layers[proof_index];
        verify_sparse_gkr_layer(
            &layers[layer_index],
            &claims,
            &layer_challenges[layer_index],
            layer_proof,
        )?;
        let input_variables = layers[layer_index].input_width.trailing_zeros() as usize;
        let left_point = layer_challenges[layer_index][..input_variables].to_vec();
        let right_point = layer_challenges[layer_index][input_variables..].to_vec();
        if layer_index == 0 {
            claims = vec![
                LayerOutputClaim {
                    point: left_point,
                    value: layer_proof.terminal_left,
                    coefficient: Fp16::ONE,
                },
                LayerOutputClaim {
                    point: right_point,
                    value: layer_proof.terminal_right,
                    coefficient: Fp16::ONE,
                },
            ];
        } else {
            let mix = claim_mix_challenges[proof_index];
            claims = vec![
                LayerOutputClaim {
                    point: left_point,
                    value: layer_proof.terminal_left,
                    coefficient: mix,
                },
                LayerOutputClaim {
                    point: right_point,
                    value: layer_proof.terminal_right,
                    coefficient: Fp16::ONE - mix,
                },
            ];
        }
    }
    Ok(claims)
}

fn packed_wire_value(
    wire: BooleanWire,
    inputs: &[Vec<bool>; PACK_BITS],
) -> Result<u8, OnePackLayerGkrError> {
    match wire {
        BooleanWire::Previous(index) => {
            let mut packed = 0_u8;
            for (shard, input) in inputs.iter().enumerate() {
                let value = input.get(index).ok_or(OnePackLayerGkrError::Shape)?;
                packed |= u8::from(*value) << shard;
            }
            Ok(packed)
        }
        BooleanWire::Constant(value) => Ok(if value { u8::MAX } else { 0 }),
    }
}

fn interpolate_packed_inputs(
    inputs: &[Vec<bool>; PACK_BITS],
    point: Fp16,
) -> Result<Vec<Fp16>, OnePackLayerGkrError> {
    let width = inputs[0].len();
    if inputs.iter().any(|input| input.len() != width) {
        return Err(OnePackLayerGkrError::Shape);
    }
    (0..width)
        .map(|wire| {
            let values = core::array::from_fn(|shard| {
                if inputs[shard][wire] {
                    Fp16::ONE
                } else {
                    Fp16::ZERO
                }
            });
            evaluate_packed_lagrange_values(&values, point).map_err(Into::into)
        })
        .collect()
}

/// Nonactivating one-pack bridge from the degree-21 `B=8` opening move to the
/// sparse adjacent-layer GKR algebra control.
///
/// Production must commit `packed_polynomial`, then obtain
/// `bridge_challenge`, then run the sparse messages under sequential
/// authenticated public coin. This bulk-input API is only a deterministic KAT
/// for that algebra and remains unmasked.
pub fn prove_one_pack_keccak_layer_control(
    table: &PackedBooleanTable,
    layer: &KeccakGkrLayer,
    inputs: &[Vec<bool>; PACK_BITS],
    output_point: &[Fp16],
    shard_query: Fp16,
    bridge_challenge: Fp16,
    sparse_challenges: &[Fp16],
) -> Result<(Fp16, OnePackLayerGkrProof, PackedReductionReport), OnePackLayerGkrError> {
    if inputs.iter().any(|input| input.len() != layer.input_width)
        || output_point.len() != layer.padded_width.trailing_zeros() as usize
    {
        return Err(OnePackLayerGkrError::Shape);
    }
    let mut packed_gates = Vec::with_capacity(layer.padded_width);
    let mut left_words = Vec::with_capacity(layer.padded_width);
    let mut right_words = Vec::with_capacity(layer.padded_width);
    for gate in &layer.gates {
        packed_gates.push(match gate.kind {
            BooleanGateKind::And => PackedBooleanGate::And,
            BooleanGateKind::Xor | BooleanGateKind::Relay | BooleanGateKind::Zero => {
                PackedBooleanGate::Xor
            }
        });
        left_words.push(packed_wire_value(gate.left, inputs)?);
        right_words.push(packed_wire_value(gate.right, inputs)?);
    }
    let equality_weights = equality_table(output_point)?;
    let (packed_polynomial, report) = reduce_packed_boolean_layer(
        table,
        &packed_gates,
        &left_words,
        &right_words,
        &equality_weights,
        shard_query,
    )?;
    let shard_output_claims = inputs
        .iter()
        .map(|input| {
            let output = evaluate_keccak_gkr_layer(layer, input)
                .map_err(|_| ProductSumcheckError::Wiring)?;
            Ok::<Fp16, ProductSumcheckError>(
                output
                    .iter()
                    .copied()
                    .zip(equality_weights.iter().copied())
                    .fold(
                        Fp16::ZERO,
                        |sum, (value, weight)| {
                            if value { sum + weight } else { sum }
                        },
                    ),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let shard_output_claims: [Fp16; PACK_BITS] = shard_output_claims
        .try_into()
        .map_err(|_| OnePackLayerGkrError::Shape)?;
    let initial_claim = evaluate_packed_lagrange_values(&shard_output_claims, shard_query)?;
    let bridge = verify_packed_first_round_bridge(
        initial_claim,
        &packed_polynomial,
        shard_query,
        bridge_challenge,
    )?;
    let interpolated_input = interpolate_packed_inputs(inputs, bridge_challenge)?;
    let sparse_claim = LayerOutputClaim {
        point: output_point.to_vec(),
        value: bridge.gate_claim,
        coefficient: Fp16::ONE,
    };
    let sparse_layer = prove_sparse_gkr_layer(
        layer,
        &interpolated_input,
        &[sparse_claim],
        sparse_challenges,
    )?;
    Ok((
        initial_claim,
        OnePackLayerGkrProof {
            packed_polynomial,
            sparse_layer,
        },
        report,
    ))
}

pub fn verify_one_pack_keccak_layer_control(
    layer: &KeccakGkrLayer,
    expected_initial_claim: Fp16,
    output_point: &[Fp16],
    shard_query: Fp16,
    bridge_challenge: Fp16,
    sparse_challenges: &[Fp16],
    proof: &OnePackLayerGkrProof,
) -> Result<(), OnePackLayerGkrError> {
    let bridge = verify_packed_first_round_bridge(
        expected_initial_claim,
        &proof.packed_polynomial,
        shard_query,
        bridge_challenge,
    )?;
    let claim = LayerOutputClaim {
        point: output_point.to_vec(),
        value: bridge.gate_claim,
        coefficient: Fp16::ONE,
    };
    verify_sparse_gkr_layer(layer, &[claim], sparse_challenges, &proof.sparse_layer)?;
    Ok(())
}

fn repeated_input_width(
    layer: &KeccakGkrLayer,
    group_count: usize,
) -> Result<usize, OnePackLayerGkrError> {
    if group_count == 0
        || !group_count.is_power_of_two()
        || layer.gates.len() != layer.padded_width
        || layer.raw_width > layer.padded_width
        || !layer.input_width.is_power_of_two()
        || !layer.padded_width.is_power_of_two()
    {
        return Err(OnePackLayerGkrError::Shape);
    }
    layer
        .input_width
        .checked_mul(group_count)
        .ok_or(OnePackLayerGkrError::Shape)
}

fn repeated_layer_terms_for_claims(
    layer: &KeccakGkrLayer,
    group_count: usize,
    claims: &[LayerOutputClaim],
) -> Result<Vec<SparseGateTerm>, OnePackLayerGkrError> {
    let _ = repeated_input_width(layer, group_count)?;
    let output_width = layer
        .padded_width
        .checked_mul(group_count)
        .ok_or(OnePackLayerGkrError::Shape)?;
    let output_variables = output_width.trailing_zeros() as usize;
    if claims.is_empty()
        || claims
            .iter()
            .any(|claim| claim.point.len() != output_variables)
    {
        return Err(OnePackLayerGkrError::Shape);
    }
    let wire_variables = layer.padded_width.trailing_zeros() as usize;
    let claim_weights = claims
        .iter()
        .map(|claim| {
            Ok((
                equality_table(&claim.point[..wire_variables])?,
                equality_table(&claim.point[wire_variables..])?,
            ))
        })
        .collect::<Result<Vec<_>, ProductSumcheckError>>()?;
    let capacity = layer
        .raw_width
        .checked_mul(group_count)
        .ok_or(OnePackLayerGkrError::Shape)?;
    let mut terms = Vec::with_capacity(capacity);
    for group in 0..group_count {
        let input_offset = group * layer.input_width;
        for (wire, gate) in layer.gates.iter().copied().enumerate() {
            let output_weight = claims.iter().zip(claim_weights.iter()).fold(
                Fp16::ZERO,
                |sum, (claim, (wire_weights, group_weights))| {
                    sum + claim.coefficient * wire_weights[wire] * group_weights[group]
                },
            );
            if output_weight.is_zero() {
                continue;
            }
            let (left, right, formula) = normalize_gate(gate)?;
            if left >= layer.input_width || right >= layer.input_width {
                return Err(OnePackLayerGkrError::Gkr(ProductSumcheckError::Wiring));
            }
            if formula == GateFormula::Zero {
                continue;
            }
            terms.push(SparseGateTerm {
                output_weight,
                left: input_offset + left,
                right: input_offset + right,
                formula,
            });
        }
    }
    if terms.is_empty() {
        return Err(OnePackLayerGkrError::Gkr(ProductSumcheckError::Claim));
    }
    Ok(terms)
}

fn repeated_layer_terms(
    layer: &KeccakGkrLayer,
    group_count: usize,
    group_point: &[Fp16],
    output_point: &[Fp16],
) -> Result<Vec<SparseGateTerm>, OnePackLayerGkrError> {
    if group_point.len() != group_count.trailing_zeros() as usize
        || output_point.len() != layer.padded_width.trailing_zeros() as usize
    {
        return Err(OnePackLayerGkrError::Shape);
    }
    let mut point = Vec::with_capacity(output_point.len() + group_point.len());
    point.extend_from_slice(output_point);
    point.extend_from_slice(group_point);
    repeated_layer_terms_for_claims(
        layer,
        group_count,
        &[LayerOutputClaim {
            point,
            value: Fp16::ZERO,
            coefficient: Fp16::ONE,
        }],
    )
}

#[cfg(feature = "parallel")]
pub fn repeated_pack_sparse_layer_gpu_fixture(
    layer: &KeccakGkrLayer,
    groups: &[[Vec<bool>; PACK_BITS]],
    group_point: &[Fp16],
    output_point: &[Fp16],
    bridge_challenge: Fp16,
    challenges: &[Fp16],
) -> Result<SparseLayerGpuFixture, OnePackLayerGkrError> {
    if groups.is_empty()
        || !groups.len().is_power_of_two()
        || groups
            .iter()
            .flat_map(|group| group.iter())
            .any(|input| input.len() != layer.input_width)
    {
        return Err(OnePackLayerGkrError::Shape);
    }
    let mut input = Vec::with_capacity(repeated_input_width(layer, groups.len())?);
    for group in groups {
        input.extend(interpolate_packed_inputs(group, bridge_challenge)?);
    }
    let terms = repeated_layer_terms(layer, groups.len(), group_point, output_point)?;
    let input_variables = log2_exact(input.len())?;
    if challenges.len() != 2 * input_variables {
        return Err(OnePackLayerGkrError::Shape);
    }
    let complete = prove_sparse_terms(&input, Fp16::ZERO, &terms, challenges)?;
    let terms = terms
        .into_iter()
        .map(|term| {
            Ok(SparseLayerGpuFixtureTerm {
                output_weight: term.output_weight,
                left: u32::try_from(term.left).map_err(|_| OnePackLayerGkrError::Shape)?,
                right: u32::try_from(term.right).map_err(|_| OnePackLayerGkrError::Shape)?,
                formula: term.formula as u8,
            })
        })
        .collect::<Result<Vec<_>, OnePackLayerGkrError>>()?;
    Ok(SparseLayerGpuFixture {
        input,
        terms,
        challenges: challenges.to_vec(),
        expected_rounds: complete.rounds,
        terminal_left: complete.terminal_left,
        terminal_right: complete.terminal_right,
    })
}

#[cfg(feature = "parallel")]
pub fn repeated_pack_sparse_layer_claims_gpu_fixture(
    layer: &KeccakGkrLayer,
    groups: &[[Vec<bool>; PACK_BITS]],
    claims: &[LayerOutputClaim],
    bridge_challenge: Fp16,
    challenges: &[Fp16],
) -> Result<SparseLayerGpuFixture, OnePackLayerGkrError> {
    if groups.is_empty()
        || !groups.len().is_power_of_two()
        || groups
            .iter()
            .flat_map(|group| group.iter())
            .any(|input| input.len() != layer.input_width)
    {
        return Err(OnePackLayerGkrError::Shape);
    }
    let mut input = Vec::with_capacity(repeated_input_width(layer, groups.len())?);
    for group in groups {
        input.extend(interpolate_packed_inputs(group, bridge_challenge)?);
    }
    let terms = repeated_layer_terms_for_claims(layer, groups.len(), claims)?;
    let input_variables = log2_exact(input.len())?;
    if challenges.len() != 2 * input_variables {
        return Err(OnePackLayerGkrError::Shape);
    }
    let complete = prove_sparse_terms(&input, Fp16::ZERO, &terms, challenges)?;
    let terms = terms
        .into_iter()
        .map(|term| {
            Ok(SparseLayerGpuFixtureTerm {
                output_weight: term.output_weight,
                left: u32::try_from(term.left).map_err(|_| OnePackLayerGkrError::Shape)?,
                right: u32::try_from(term.right).map_err(|_| OnePackLayerGkrError::Shape)?,
                formula: term.formula as u8,
            })
        })
        .collect::<Result<Vec<_>, OnePackLayerGkrError>>()?;
    Ok(SparseLayerGpuFixture {
        input,
        terms,
        challenges: challenges.to_vec(),
        expected_rounds: complete.rounds,
        terminal_left: complete.terminal_left,
        terminal_right: complete.terminal_right,
    })
}

#[cfg(feature = "parallel")]
pub type RepeatedPackCompactLayerGeometry = (Vec<u32>, Vec<u32>, Vec<u8>);

#[cfg(feature = "parallel")]
pub fn repeated_pack_compact_layer_geometry(
    layer: &KeccakGkrLayer,
) -> Result<RepeatedPackCompactLayerGeometry, OnePackLayerGkrError> {
    let mut left = Vec::with_capacity(layer.raw_width);
    let mut right = Vec::with_capacity(layer.raw_width);
    let mut formula = Vec::with_capacity(layer.raw_width);
    for gate in layer.gates.iter().copied().take(layer.raw_width) {
        let (gate_left, gate_right, gate_formula) = normalize_gate(gate)?;
        left.push(u32::try_from(gate_left).map_err(|_| OnePackLayerGkrError::Shape)?);
        right.push(u32::try_from(gate_right).map_err(|_| OnePackLayerGkrError::Shape)?);
        formula.push(gate_formula as u8);
    }
    Ok((left, right, formula))
}

/// Exact graph-free repeated-circuit algebra control.
///
/// Groups occupy the high index bits and wires the low index bits. This keeps
/// the group-identity wiring inside the sparse GKR reduction; it does not use
/// the invalid shortcut of applying nonlinear gates after averaging groups.
/// Only sparse normalized terms are retained; no repeated gate graph or dense
/// wiring predicate is materialized.
#[allow(clippy::too_many_arguments)]
pub fn prove_repeated_pack_keccak_layer_control(
    table: &PackedBooleanTable,
    layer: &KeccakGkrLayer,
    groups: &[[Vec<bool>; PACK_BITS]],
    group_point: &[Fp16],
    output_point: &[Fp16],
    shard_query: Fp16,
    bridge_challenge: Fp16,
    sparse_challenges: &[Fp16],
) -> Result<(Fp16, RepeatedPackLayerGkrProof, PackedReductionReport), OnePackLayerGkrError> {
    if groups.is_empty()
        || !groups.len().is_power_of_two()
        || group_point.len() != groups.len().trailing_zeros() as usize
        || output_point.len() != layer.padded_width.trailing_zeros() as usize
        || groups
            .iter()
            .flat_map(|group| group.iter())
            .any(|input| input.len() != layer.input_width)
    {
        return Err(OnePackLayerGkrError::Shape);
    }
    let repeated_input_width = repeated_input_width(layer, groups.len())?;
    if sparse_challenges.len() != 2 * repeated_input_width.trailing_zeros() as usize {
        return Err(OnePackLayerGkrError::Shape);
    }

    let wire_weights = equality_table(output_point)?;
    let group_weights = equality_table(group_point)?;
    let gate_count = layer
        .padded_width
        .checked_mul(groups.len())
        .ok_or(OnePackLayerGkrError::Shape)?;
    let mut packed_gates = Vec::with_capacity(gate_count);
    let mut left_words = Vec::with_capacity(gate_count);
    let mut right_words = Vec::with_capacity(gate_count);
    let mut equality_weights = Vec::with_capacity(gate_count);
    for (group_index, inputs) in groups.iter().enumerate() {
        for (wire, gate) in layer.gates.iter().copied().enumerate() {
            packed_gates.push(match gate.kind {
                BooleanGateKind::And => PackedBooleanGate::And,
                BooleanGateKind::Xor | BooleanGateKind::Relay | BooleanGateKind::Zero => {
                    PackedBooleanGate::Xor
                }
            });
            left_words.push(packed_wire_value(gate.left, inputs)?);
            right_words.push(packed_wire_value(gate.right, inputs)?);
            equality_weights.push(group_weights[group_index] * wire_weights[wire]);
        }
    }
    let (packed_polynomial, report) = reduce_packed_boolean_layer(
        table,
        &packed_gates,
        &left_words,
        &right_words,
        &equality_weights,
        shard_query,
    )?;

    let mut group_output_claims = Vec::with_capacity(groups.len());
    for inputs in groups {
        let shard_claims = inputs
            .iter()
            .map(|input| {
                let output = evaluate_keccak_gkr_layer(layer, input)
                    .map_err(|_| ProductSumcheckError::Wiring)?;
                Ok::<Fp16, ProductSumcheckError>(
                    output
                        .iter()
                        .copied()
                        .zip(wire_weights.iter().copied())
                        .fold(
                            Fp16::ZERO,
                            |sum, (value, weight)| {
                                if value { sum + weight } else { sum }
                            },
                        ),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let shard_claims: [Fp16; PACK_BITS] = shard_claims
            .try_into()
            .map_err(|_| OnePackLayerGkrError::Shape)?;
        group_output_claims.push(evaluate_packed_lagrange_values(&shard_claims, shard_query)?);
    }
    let initial_claim = multilinear_evaluate(&group_output_claims, group_point)?;
    let bridge = verify_packed_first_round_bridge(
        initial_claim,
        &packed_polynomial,
        shard_query,
        bridge_challenge,
    )?;

    let mut interpolated_input = Vec::with_capacity(repeated_input_width);
    for inputs in groups {
        interpolated_input.extend(interpolate_packed_inputs(inputs, bridge_challenge)?);
    }
    let terms = repeated_layer_terms(layer, groups.len(), group_point, output_point)?;
    let sparse_layer = prove_sparse_terms(
        &interpolated_input,
        bridge.gate_claim,
        &terms,
        sparse_challenges,
    )?;
    Ok((
        initial_claim,
        RepeatedPackLayerGkrProof {
            packed_polynomial,
            sparse_layer,
        },
        report,
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_repeated_pack_keccak_layer_control(
    layer: &KeccakGkrLayer,
    group_count: usize,
    expected_initial_claim: Fp16,
    group_point: &[Fp16],
    output_point: &[Fp16],
    shard_query: Fp16,
    bridge_challenge: Fp16,
    sparse_challenges: &[Fp16],
    proof: &RepeatedPackLayerGkrProof,
) -> Result<(), OnePackLayerGkrError> {
    if group_count == 0
        || !group_count.is_power_of_two()
        || group_point.len() != group_count.trailing_zeros() as usize
    {
        return Err(OnePackLayerGkrError::Shape);
    }
    let bridge = verify_packed_first_round_bridge(
        expected_initial_claim,
        &proof.packed_polynomial,
        shard_query,
        bridge_challenge,
    )?;
    let repeated_input_width = repeated_input_width(layer, group_count)?;
    let terms = repeated_layer_terms(layer, group_count, group_point, output_point)?;
    verify_sparse_terms(
        bridge.gate_claim,
        repeated_input_width,
        &terms,
        sparse_challenges,
        &proof.sparse_layer,
    )?;
    Ok(())
}

/// Repeated-circuit bridge for one or more claims at a common shard query.
///
/// Each point is ordered as low wire bits followed by high group bits. This is
/// the boundary needed to carry the two terminal claims of one GKR layer into
/// the preceding layer without materializing a repeated gate graph.
#[allow(clippy::too_many_arguments)]
pub fn prove_repeated_pack_keccak_layer_claims_control(
    table: &PackedBooleanTable,
    layer: &KeccakGkrLayer,
    groups: &[[Vec<bool>; PACK_BITS]],
    claims: &[LayerOutputClaim],
    shard_query: Fp16,
    bridge_challenge: Fp16,
    sparse_challenges: &[Fp16],
) -> Result<(RepeatedPackLayerGkrProof, PackedReductionReport), OnePackLayerGkrError> {
    if groups.is_empty()
        || !groups.len().is_power_of_two()
        || groups
            .iter()
            .flat_map(|group| group.iter())
            .any(|input| input.len() != layer.input_width)
    {
        return Err(OnePackLayerGkrError::Shape);
    }
    let repeated_input_width = repeated_input_width(layer, groups.len())?;
    if sparse_challenges.len() != 2 * repeated_input_width.trailing_zeros() as usize {
        return Err(OnePackLayerGkrError::Shape);
    }
    let output_width = layer
        .padded_width
        .checked_mul(groups.len())
        .ok_or(OnePackLayerGkrError::Shape)?;
    let output_variables = output_width.trailing_zeros() as usize;
    let wire_variables = layer.padded_width.trailing_zeros() as usize;
    if claims.is_empty()
        || claims
            .iter()
            .any(|claim| claim.point.len() != output_variables)
    {
        return Err(OnePackLayerGkrError::Shape);
    }
    let claim_weights = claims
        .iter()
        .map(|claim| {
            Ok((
                equality_table(&claim.point[..wire_variables])?,
                equality_table(&claim.point[wire_variables..])?,
            ))
        })
        .collect::<Result<Vec<_>, ProductSumcheckError>>()?;

    let gate_count = layer
        .padded_width
        .checked_mul(groups.len())
        .ok_or(OnePackLayerGkrError::Shape)?;
    let mut packed_gates = Vec::with_capacity(gate_count);
    let mut left_words = Vec::with_capacity(gate_count);
    let mut right_words = Vec::with_capacity(gate_count);
    let mut equality_weights = Vec::with_capacity(gate_count);
    for (group_index, inputs) in groups.iter().enumerate() {
        for (wire, gate) in layer.gates.iter().copied().enumerate() {
            packed_gates.push(match gate.kind {
                BooleanGateKind::And => PackedBooleanGate::And,
                BooleanGateKind::Xor | BooleanGateKind::Relay | BooleanGateKind::Zero => {
                    PackedBooleanGate::Xor
                }
            });
            left_words.push(packed_wire_value(gate.left, inputs)?);
            right_words.push(packed_wire_value(gate.right, inputs)?);
            equality_weights.push(claims.iter().zip(claim_weights.iter()).fold(
                Fp16::ZERO,
                |sum, (claim, (wire_weights, group_weights))| {
                    sum + claim.coefficient * wire_weights[wire] * group_weights[group_index]
                },
            ));
        }
    }
    let (packed_polynomial, report) = reduce_packed_boolean_layer(
        table,
        &packed_gates,
        &left_words,
        &right_words,
        &equality_weights,
        shard_query,
    )?;
    let initial_claim = combined_claim(claims);
    let bridge = verify_packed_first_round_bridge(
        initial_claim,
        &packed_polynomial,
        shard_query,
        bridge_challenge,
    )?;

    let mut interpolated_input = Vec::with_capacity(repeated_input_width);
    for inputs in groups {
        interpolated_input.extend(interpolate_packed_inputs(inputs, bridge_challenge)?);
    }
    let terms = repeated_layer_terms_for_claims(layer, groups.len(), claims)?;
    let sparse_layer = prove_sparse_terms(
        &interpolated_input,
        bridge.gate_claim,
        &terms,
        sparse_challenges,
    )?;
    Ok((
        RepeatedPackLayerGkrProof {
            packed_polynomial,
            sparse_layer,
        },
        report,
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_repeated_pack_keccak_layer_claims_control(
    layer: &KeccakGkrLayer,
    group_count: usize,
    claims: &[LayerOutputClaim],
    shard_query: Fp16,
    bridge_challenge: Fp16,
    sparse_challenges: &[Fp16],
    proof: &RepeatedPackLayerGkrProof,
) -> Result<(), OnePackLayerGkrError> {
    let repeated_input_width = repeated_input_width(layer, group_count)?;
    if sparse_challenges.len() != 2 * repeated_input_width.trailing_zeros() as usize {
        return Err(OnePackLayerGkrError::Shape);
    }
    let bridge = verify_packed_first_round_bridge(
        combined_claim(claims),
        &proof.packed_polynomial,
        shard_query,
        bridge_challenge,
    )?;
    verify_repeated_sparse_terms_factored(
        bridge.gate_claim,
        layer,
        group_count,
        claims,
        sparse_challenges,
        &proof.sparse_layer,
        Fp16::ZERO,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn verify_masked_repeated_pack_keccak_layer_claims_control(
    layer: &KeccakGkrLayer,
    group_count: usize,
    claims: &[LayerOutputClaim],
    shard_query: Fp16,
    bridge_challenge: Fp16,
    sparse_challenges: &[Fp16],
    packed_polynomial: &[Fp16; crate::packed_boolean_sumcheck::OUTPUT_COEFFICIENTS],
    proof: &MaskedSparseLayerSumcheckProof,
) -> Result<(), OnePackLayerGkrError> {
    let bridge = verify_packed_first_round_bridge(
        combined_claim(claims),
        packed_polynomial,
        shard_query,
        bridge_challenge,
    )?;
    verify_masked_repeated_sparse_layer(
        layer,
        group_count,
        bridge.gate_claim,
        claims,
        sparse_challenges,
        proof,
    )
}

/// Exact packed first-round producer over a wire-major bit-packed boundary.
///
/// This is the production-shaped counterpart of
/// `prove_repeated_pack_keccak_layer_claims_control`: it avoids expanding
/// 1,024 Boolean instances into nested `Vec<bool>` values and leaves the
/// subsequent sparse rounds to the bounded untrusted worker.
#[cfg(feature = "parallel")]
#[allow(clippy::too_many_arguments)]
pub fn prove_repeated_pack_layer_bridge_parallel(
    table: &PackedBooleanTable,
    layer: &KeccakGkrLayer,
    packed_input: &[u64],
    instances: usize,
    claims: &[LayerOutputClaim],
    shard_query: Fp16,
    bridge_challenge: Fp16,
    worker_count: usize,
) -> Result<
    (
        [Fp16; crate::packed_boolean_sumcheck::OUTPUT_COEFFICIENTS],
        PackedReductionReport,
        Fp16,
    ),
    OnePackLayerGkrError,
> {
    if instances == 0
        || !instances.is_power_of_two()
        || !instances.is_multiple_of(PACK_BITS)
        || worker_count == 0
    {
        return Err(OnePackLayerGkrError::Shape);
    }
    let group_count = instances / PACK_BITS;
    if !group_count.is_power_of_two() {
        return Err(OnePackLayerGkrError::Shape);
    }
    let words = instances.div_ceil(64);
    if packed_input.len() != layer.input_width * words {
        return Err(OnePackLayerGkrError::Shape);
    }
    let output_variables = layer
        .padded_width
        .checked_mul(group_count)
        .ok_or(OnePackLayerGkrError::Shape)?
        .trailing_zeros() as usize;
    let wire_variables = layer.padded_width.trailing_zeros() as usize;
    if claims.is_empty()
        || claims
            .iter()
            .any(|claim| claim.point.len() != output_variables)
    {
        return Err(OnePackLayerGkrError::Shape);
    }
    let claim_weights = claims
        .iter()
        .map(|claim| {
            Ok((
                equality_table(&claim.point[..wire_variables])?,
                equality_table(&claim.point[wire_variables..])?,
            ))
        })
        .collect::<Result<Vec<_>, ProductSumcheckError>>()?;
    let gate_count = layer
        .padded_width
        .checked_mul(group_count)
        .ok_or(OnePackLayerGkrError::Shape)?;
    let packed_wire = |wire: BooleanWire, group: usize| -> u8 {
        match wire {
            BooleanWire::Previous(index) => {
                let bit = group * PACK_BITS;
                (packed_input[index * words + bit / 64] >> (bit % 64)) as u8
            }
            BooleanWire::Constant(value) => {
                if value {
                    u8::MAX
                } else {
                    0
                }
            }
        }
    };
    let gate_at = |index: usize| {
        let group = index / layer.padded_width;
        let wire = index % layer.padded_width;
        let gate = layer.gates[wire];
        let weight = claims.iter().zip(&claim_weights).fold(
            Fp16::ZERO,
            |sum, (claim, (wire_weights, group_weights))| {
                sum + claim.coefficient * wire_weights[wire] * group_weights[group]
            },
        );
        (
            match gate.kind {
                BooleanGateKind::And => PackedBooleanGate::And,
                BooleanGateKind::Xor | BooleanGateKind::Relay | BooleanGateKind::Zero => {
                    PackedBooleanGate::Xor
                }
            },
            packed_wire(gate.left, group),
            packed_wire(gate.right, group),
            weight,
        )
    };
    let (polynomial, report) = reduce_packed_boolean_indexed_parallel(
        table,
        gate_count,
        worker_count,
        gate_at,
        shard_query,
    )?;
    let bridge = verify_packed_first_round_bridge(
        combined_claim(claims),
        &polynomial,
        shard_query,
        bridge_challenge,
    )?;
    Ok((polynomial, report, bridge.gate_claim))
}

/// Exact graph-free repeated-circuit chain control.
///
/// `output_point` covers low wire bits followed by high group bits. Each
/// layer consumes the previous layer's bridge challenge as its shard query.
/// The returned two claims and shard query are the input openings that the
/// containing hiding commitment must authenticate.
#[allow(clippy::too_many_arguments)]
#[cfg(any(test, feature = "control_reference"))]
fn prove_repeated_pack_gkr_chain_reference(
    table: &PackedBooleanTable,
    layers: &[KeccakGkrLayer],
    input_groups: &[[Vec<bool>; PACK_BITS]],
    output_point: &[Fp16],
    output_shard_query: Fp16,
    bridge_challenges: &[Fp16],
    layer_sparse_challenges: &[Vec<Fp16>],
    claim_mix_challenges: &[Fp16],
) -> Result<(Fp16, RepeatedPackGkrChainProof, Vec<LayerOutputClaim>, Fp16), OnePackLayerGkrError> {
    if layers.is_empty()
        || input_groups.is_empty()
        || !input_groups.len().is_power_of_two()
        || bridge_challenges.len() != layers.len()
        || layer_sparse_challenges.len() != layers.len()
        || claim_mix_challenges.len() + 1 != layers.len()
        || input_groups
            .iter()
            .flat_map(|group| group.iter())
            .any(|input| input.len() != layers[0].input_width)
    {
        return Err(OnePackLayerGkrError::Shape);
    }
    for pair in layers.windows(2) {
        if pair[0].padded_width != pair[1].input_width {
            return Err(OnePackLayerGkrError::Gkr(ProductSumcheckError::Wiring));
        }
    }

    let mut boundaries = Vec::with_capacity(layers.len() + 1);
    boundaries.push(input_groups.to_vec());
    for layer in layers {
        let previous = boundaries.last().ok_or(OnePackLayerGkrError::Shape)?;
        let mut next = Vec::with_capacity(previous.len());
        for group in previous {
            let outputs = group
                .iter()
                .map(|input| {
                    evaluate_keccak_gkr_layer(layer, input)
                        .map_err(|_| OnePackLayerGkrError::Gkr(ProductSumcheckError::Wiring))
                })
                .collect::<Result<Vec<_>, _>>()?;
            next.push(
                outputs
                    .try_into()
                    .map_err(|_| OnePackLayerGkrError::Shape)?,
            );
        }
        boundaries.push(next);
    }

    let final_boundary = boundaries.last().ok_or(OnePackLayerGkrError::Shape)?;
    let output_width = layers
        .last()
        .ok_or(OnePackLayerGkrError::Shape)?
        .padded_width
        .checked_mul(input_groups.len())
        .ok_or(OnePackLayerGkrError::Shape)?;
    if output_point.len() != output_width.trailing_zeros() as usize {
        return Err(OnePackLayerGkrError::Shape);
    }
    let mut output_values = Vec::with_capacity(output_width);
    for group in final_boundary {
        output_values.extend(interpolate_packed_inputs(group, output_shard_query)?);
    }
    let output_value = multilinear_evaluate(&output_values, output_point)?;
    let mut claims = vec![LayerOutputClaim {
        point: output_point.to_vec(),
        value: output_value,
        coefficient: Fp16::ONE,
    }];
    let mut shard_query = output_shard_query;
    let mut proofs = Vec::with_capacity(layers.len());
    for (proof_index, layer_index) in (0..layers.len()).rev().enumerate() {
        let (proof, _) = prove_repeated_pack_keccak_layer_claims_control(
            table,
            &layers[layer_index],
            &boundaries[layer_index],
            &claims,
            shard_query,
            bridge_challenges[layer_index],
            &layer_sparse_challenges[layer_index],
        )?;
        let input_variables = repeated_input_width(&layers[layer_index], input_groups.len())?
            .trailing_zeros() as usize;
        let left_point = layer_sparse_challenges[layer_index][..input_variables].to_vec();
        let right_point = layer_sparse_challenges[layer_index][input_variables..].to_vec();
        let mix = if layer_index == 0 {
            Fp16::ONE
        } else {
            claim_mix_challenges[proof_index]
        };
        claims = vec![
            LayerOutputClaim {
                point: left_point,
                value: proof.sparse_layer.terminal_left,
                coefficient: mix,
            },
            LayerOutputClaim {
                point: right_point,
                value: proof.sparse_layer.terminal_right,
                coefficient: if layer_index == 0 {
                    Fp16::ONE
                } else {
                    Fp16::ONE - mix
                },
            },
        ];
        shard_query = bridge_challenges[layer_index];
        proofs.push(proof);
    }
    Ok((
        output_value,
        RepeatedPackGkrChainProof { layers: proofs },
        claims,
        shard_query,
    ))
}

#[cfg(any(test, not(feature = "control_reference")))]
fn pack_repeated_groups(
    input_groups: &[[Vec<bool>; PACK_BITS]],
    width: usize,
) -> Result<Vec<u64>, OnePackLayerGkrError> {
    let instances = input_groups
        .len()
        .checked_mul(PACK_BITS)
        .ok_or(OnePackLayerGkrError::Shape)?;
    let words = instances.div_ceil(64);
    let mut packed = vec![0_u64; width * words];
    for (group_index, group) in input_groups.iter().enumerate() {
        for (shard, input) in group.iter().enumerate() {
            if input.len() != width {
                return Err(OnePackLayerGkrError::Shape);
            }
            let instance = group_index * PACK_BITS + shard;
            for (wire, value) in input.iter().copied().enumerate() {
                packed[wire * words + instance / 64] |= u64::from(value) << (instance % 64);
            }
        }
    }
    Ok(packed)
}

#[cfg(any(test, not(feature = "control_reference")))]
fn unpack_repeated_groups(
    packed: &[u64],
    width: usize,
    group_count: usize,
) -> Result<Vec<[Vec<bool>; PACK_BITS]>, OnePackLayerGkrError> {
    let instances = group_count
        .checked_mul(PACK_BITS)
        .ok_or(OnePackLayerGkrError::Shape)?;
    let words = instances.div_ceil(64);
    if packed.len() != width * words {
        return Err(OnePackLayerGkrError::Shape);
    }
    Ok((0..group_count)
        .map(|group| {
            core::array::from_fn(|shard| {
                let instance = group * PACK_BITS + shard;
                (0..width)
                    .map(|wire| {
                        ((packed[wire * words + instance / 64] >> (instance % 64)) & 1) != 0
                    })
                    .collect()
            })
        })
        .collect())
}

#[allow(clippy::too_many_arguments)]
#[cfg(any(test, not(feature = "control_reference")))]
fn prove_repeated_pack_gkr_chain_checkpointed(
    table: &PackedBooleanTable,
    layers: &[KeccakGkrLayer],
    input_groups: &[[Vec<bool>; PACK_BITS]],
    output_point: &[Fp16],
    output_shard_query: Fp16,
    bridge_challenges: &[Fp16],
    layer_sparse_challenges: &[Vec<Fp16>],
    claim_mix_challenges: &[Fp16],
) -> Result<(Fp16, RepeatedPackGkrChainProof, Vec<LayerOutputClaim>, Fp16), OnePackLayerGkrError> {
    if layers.is_empty()
        || !layers.len().is_multiple_of(KECCAK_GKR_LAYERS_PER_ROUND)
        || input_groups.is_empty()
        || !input_groups.len().is_power_of_two()
        || bridge_challenges.len() != layers.len()
        || layer_sparse_challenges.len() != layers.len()
        || claim_mix_challenges.len() + 1 != layers.len()
        || input_groups
            .iter()
            .flat_map(|group| group.iter())
            .any(|input| input.len() != layers[0].input_width)
    {
        return Err(OnePackLayerGkrError::Shape);
    }
    for pair in layers.windows(2) {
        if pair[0].padded_width != pair[1].input_width {
            return Err(OnePackLayerGkrError::Gkr(ProductSumcheckError::Wiring));
        }
    }

    let instances = input_groups
        .len()
        .checked_mul(PACK_BITS)
        .ok_or(OnePackLayerGkrError::Shape)?;
    let packed_input = pack_repeated_groups(input_groups, layers[0].input_width)?;
    let checkpoints = packed_keccak_gkr_round_checkpoints(layers, &packed_input, instances)
        .map_err(|_| OnePackLayerGkrError::Gkr(ProductSumcheckError::Wiring))?;
    let final_boundary = unpack_repeated_groups(
        checkpoints.last().ok_or(OnePackLayerGkrError::Shape)?,
        layers
            .last()
            .ok_or(OnePackLayerGkrError::Shape)?
            .padded_width,
        input_groups.len(),
    )?;
    let output_width = layers
        .last()
        .ok_or(OnePackLayerGkrError::Shape)?
        .padded_width
        .checked_mul(input_groups.len())
        .ok_or(OnePackLayerGkrError::Shape)?;
    if output_point.len() != output_width.trailing_zeros() as usize {
        return Err(OnePackLayerGkrError::Shape);
    }
    let mut output_values = Vec::with_capacity(output_width);
    for group in &final_boundary {
        output_values.extend(interpolate_packed_inputs(group, output_shard_query)?);
    }
    let output_value = multilinear_evaluate(&output_values, output_point)?;
    let mut claims = vec![LayerOutputClaim {
        point: output_point.to_vec(),
        value: output_value,
        coefficient: Fp16::ONE,
    }];
    let mut shard_query = output_shard_query;
    let mut proofs = Vec::with_capacity(layers.len());
    let mut regenerated_round = usize::MAX;
    let mut round_inputs = Vec::new();
    for (proof_index, layer_index) in (0..layers.len()).rev().enumerate() {
        let round = layer_index / KECCAK_GKR_LAYERS_PER_ROUND;
        if round != regenerated_round {
            let start = round * KECCAK_GKR_LAYERS_PER_ROUND;
            round_inputs = regenerate_packed_keccak_gkr_round_inputs(
                &layers[start..start + KECCAK_GKR_LAYERS_PER_ROUND],
                &checkpoints[round],
                instances,
            )
            .map_err(|_| OnePackLayerGkrError::Gkr(ProductSumcheckError::Wiring))?;
            regenerated_round = round;
        }
        let packed_layer_input = round_inputs
            .get(layer_index % KECCAK_GKR_LAYERS_PER_ROUND)
            .ok_or(OnePackLayerGkrError::Shape)?;
        let layer_input = unpack_repeated_groups(
            packed_layer_input,
            layers[layer_index].input_width,
            input_groups.len(),
        )?;
        let (proof, _) = prove_repeated_pack_keccak_layer_claims_control(
            table,
            &layers[layer_index],
            &layer_input,
            &claims,
            shard_query,
            bridge_challenges[layer_index],
            &layer_sparse_challenges[layer_index],
        )?;
        let input_variables = repeated_input_width(&layers[layer_index], input_groups.len())?
            .trailing_zeros() as usize;
        let left_point = layer_sparse_challenges[layer_index][..input_variables].to_vec();
        let right_point = layer_sparse_challenges[layer_index][input_variables..].to_vec();
        let mix = if layer_index == 0 {
            Fp16::ONE
        } else {
            claim_mix_challenges[proof_index]
        };
        claims = vec![
            LayerOutputClaim {
                point: left_point,
                value: proof.sparse_layer.terminal_left,
                coefficient: mix,
            },
            LayerOutputClaim {
                point: right_point,
                value: proof.sparse_layer.terminal_right,
                coefficient: if layer_index == 0 {
                    Fp16::ONE
                } else {
                    Fp16::ONE - mix
                },
            },
        ];
        shard_query = bridge_challenges[layer_index];
        proofs.push(proof);
    }
    Ok((
        output_value,
        RepeatedPackGkrChainProof { layers: proofs },
        claims,
        shard_query,
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn prove_repeated_pack_gkr_chain_control(
    table: &PackedBooleanTable,
    layers: &[KeccakGkrLayer],
    input_groups: &[[Vec<bool>; PACK_BITS]],
    output_point: &[Fp16],
    output_shard_query: Fp16,
    bridge_challenges: &[Fp16],
    layer_sparse_challenges: &[Vec<Fp16>],
    claim_mix_challenges: &[Fp16],
) -> Result<(Fp16, RepeatedPackGkrChainProof, Vec<LayerOutputClaim>, Fp16), OnePackLayerGkrError> {
    #[cfg(feature = "control_reference")]
    {
        prove_repeated_pack_gkr_chain_reference(
            table,
            layers,
            input_groups,
            output_point,
            output_shard_query,
            bridge_challenges,
            layer_sparse_challenges,
            claim_mix_challenges,
        )
    }
    #[cfg(not(feature = "control_reference"))]
    {
        prove_repeated_pack_gkr_chain_checkpointed(
            table,
            layers,
            input_groups,
            output_point,
            output_shard_query,
            bridge_challenges,
            layer_sparse_challenges,
            claim_mix_challenges,
        )
    }
}

#[allow(clippy::too_many_arguments)]
pub fn verify_repeated_pack_gkr_chain_control(
    layers: &[KeccakGkrLayer],
    group_count: usize,
    output_point: &[Fp16],
    expected_output_value: Fp16,
    output_shard_query: Fp16,
    bridge_challenges: &[Fp16],
    layer_sparse_challenges: &[Vec<Fp16>],
    claim_mix_challenges: &[Fp16],
    proof: &RepeatedPackGkrChainProof,
) -> Result<(Vec<LayerOutputClaim>, Fp16), OnePackLayerGkrError> {
    if layers.is_empty()
        || group_count == 0
        || !group_count.is_power_of_two()
        || proof.layers.len() != layers.len()
        || bridge_challenges.len() != layers.len()
        || layer_sparse_challenges.len() != layers.len()
        || claim_mix_challenges.len() + 1 != layers.len()
    {
        return Err(OnePackLayerGkrError::Shape);
    }
    for pair in layers.windows(2) {
        if pair[0].padded_width != pair[1].input_width {
            return Err(OnePackLayerGkrError::Gkr(ProductSumcheckError::Wiring));
        }
    }
    let output_width = layers
        .last()
        .ok_or(OnePackLayerGkrError::Shape)?
        .padded_width
        .checked_mul(group_count)
        .ok_or(OnePackLayerGkrError::Shape)?;
    if output_point.len() != output_width.trailing_zeros() as usize {
        return Err(OnePackLayerGkrError::Shape);
    }

    let mut claims = vec![LayerOutputClaim {
        point: output_point.to_vec(),
        value: expected_output_value,
        coefficient: Fp16::ONE,
    }];
    let mut shard_query = output_shard_query;
    for (proof_index, layer_index) in (0..layers.len()).rev().enumerate() {
        let layer_proof = &proof.layers[proof_index];
        verify_repeated_pack_keccak_layer_claims_control(
            &layers[layer_index],
            group_count,
            &claims,
            shard_query,
            bridge_challenges[layer_index],
            &layer_sparse_challenges[layer_index],
            layer_proof,
        )?;
        let input_variables =
            repeated_input_width(&layers[layer_index], group_count)?.trailing_zeros() as usize;
        let mix = if layer_index == 0 {
            Fp16::ONE
        } else {
            claim_mix_challenges[proof_index]
        };
        claims = vec![
            LayerOutputClaim {
                point: layer_sparse_challenges[layer_index][..input_variables].to_vec(),
                value: layer_proof.sparse_layer.terminal_left,
                coefficient: mix,
            },
            LayerOutputClaim {
                point: layer_sparse_challenges[layer_index][input_variables..].to_vec(),
                value: layer_proof.sparse_layer.terminal_right,
                coefficient: if layer_index == 0 {
                    Fp16::ONE
                } else {
                    Fp16::ONE - mix
                },
            },
        ];
        shard_query = bridge_challenges[layer_index];
    }
    Ok((claims, shard_query))
}

pub fn product_sum(left: &[Fp16], right: &[Fp16]) -> Result<Fp16, ProductSumcheckError> {
    if left.is_empty() || left.len() != right.len() {
        return Err(ProductSumcheckError::Shape);
    }
    Ok(left
        .iter()
        .copied()
        .zip(right.iter().copied())
        .fold(Fp16::ZERO, |sum, (left, right)| sum + left * right))
}

pub fn prove_product_sumcheck(
    left: &[Fp16],
    right: &[Fp16],
    challenges: &[Fp16],
) -> Result<(Fp16, ProductSumcheckProof), ProductSumcheckError> {
    let round_count = log2_exact(left.len())?;
    if left.len() != right.len() || challenges.len() != round_count {
        return Err(ProductSumcheckError::ChallengeCount);
    }
    let initial_claim = product_sum(left, right)?;
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    let mut rounds = Vec::with_capacity(round_count);
    for challenge in challenges.iter().copied() {
        let mut coefficients = [Fp16::ZERO; 3];
        for index in 0..left.len() / 2 {
            let left_zero = left[2 * index];
            let left_delta = left[2 * index + 1] - left_zero;
            let right_zero = right[2 * index];
            let right_delta = right[2 * index + 1] - right_zero;
            coefficients[0] = coefficients[0] + left_zero * right_zero;
            coefficients[1] = coefficients[1] + left_zero * right_delta + right_zero * left_delta;
            coefficients[2] = coefficients[2] + left_delta * right_delta;
            left[index] = left_zero + challenge * left_delta;
            right[index] = right_zero + challenge * right_delta;
        }
        left.truncate(left.len() / 2);
        right.truncate(right.len() / 2);
        rounds.push(coefficients);
    }
    let proof = ProductSumcheckProof {
        rounds,
        terminal_left: left[0],
        terminal_right: right[0],
    };
    verify_product_sumcheck(initial_claim, challenges, &proof)?;
    Ok((initial_claim, proof))
}

pub fn verify_product_sumcheck(
    initial_claim: Fp16,
    challenges: &[Fp16],
    proof: &ProductSumcheckProof,
) -> Result<(), ProductSumcheckError> {
    if proof.rounds.is_empty() || proof.rounds.len() != challenges.len() {
        return Err(ProductSumcheckError::ChallengeCount);
    }
    let mut claim = initial_claim;
    for (coefficients, challenge) in proof.rounds.iter().copied().zip(challenges.iter().copied()) {
        let at_zero = coefficients[0];
        let at_one = coefficients[0] + coefficients[1] + coefficients[2];
        if at_zero + at_one != claim {
            return Err(ProductSumcheckError::Claim);
        }
        claim = evaluate_quadratic(coefficients, challenge);
    }
    if claim != proof.terminal_left * proof.terminal_right {
        return Err(ProductSumcheckError::Terminal);
    }
    Ok(())
}

/// Mask every transmitted round polynomial while preserving its Boolean sum.
///
/// `round_masks` are private prover randomness sampled independently of the
/// witness before the corresponding authenticated public-coin challenge.
/// This masks the sumcheck messages; terminal polynomial openings still need
/// the hiding PCS supplied by H3.
pub fn prove_masked_product_sumcheck(
    left: &[Fp16],
    right: &[Fp16],
    challenges: &[Fp16],
    round_masks: &[[Fp16; 2]],
) -> Result<(Fp16, MaskedProductSumcheckProof), ProductSumcheckError> {
    let round_count = log2_exact(left.len())?;
    if left.len() != right.len()
        || challenges.len() != round_count
        || round_masks.len() != round_count
    {
        return Err(ProductSumcheckError::ChallengeCount);
    }
    let initial_claim = product_sum(left, right)?;
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    let mut incoming_correction = Fp16::ZERO;
    let mut rounds = Vec::with_capacity(round_count);
    for ((challenge, mask), _) in challenges
        .iter()
        .copied()
        .zip(round_masks.iter().copied())
        .zip(0..round_count)
    {
        let mut coefficients = [Fp16::ZERO; 3];
        for index in 0..left.len() / 2 {
            let left_zero = left[2 * index];
            let left_delta = left[2 * index + 1] - left_zero;
            let right_zero = right[2 * index];
            let right_delta = right[2 * index + 1] - right_zero;
            coefficients[0] = coefficients[0] + left_zero * right_zero;
            coefficients[1] = coefficients[1] + left_zero * right_delta + right_zero * left_delta;
            coefficients[2] = coefficients[2] + left_delta * right_delta;
            left[index] = left_zero + challenge * left_delta;
            right[index] = right_zero + challenge * right_delta;
        }
        left.truncate(left.len() / 2);
        right.truncate(right.len() / 2);

        let correction = [
            mask[0],
            incoming_correction - mask[0] - mask[0] - mask[1],
            mask[1],
        ];
        coefficients = [
            coefficients[0] + correction[0],
            coefficients[1] + correction[1],
            coefficients[2] + correction[2],
        ];
        incoming_correction = evaluate_quadratic(correction, challenge);
        rounds.push(coefficients);
    }
    let proof = MaskedProductSumcheckProof {
        rounds,
        terminal_left: left[0],
        terminal_right: right[0],
        terminal_correction: incoming_correction,
    };
    verify_masked_product_sumcheck(initial_claim, challenges, &proof)?;
    Ok((initial_claim, proof))
}

pub fn verify_masked_product_sumcheck(
    initial_claim: Fp16,
    challenges: &[Fp16],
    proof: &MaskedProductSumcheckProof,
) -> Result<(), ProductSumcheckError> {
    if proof.rounds.is_empty() || proof.rounds.len() != challenges.len() {
        return Err(ProductSumcheckError::ChallengeCount);
    }
    let mut claim = initial_claim;
    for (coefficients, challenge) in proof.rounds.iter().copied().zip(challenges.iter().copied()) {
        if coefficients[0] + coefficients[0] + coefficients[1] + coefficients[2] != claim {
            return Err(ProductSumcheckError::Claim);
        }
        claim = evaluate_quadratic(coefficients, challenge);
    }
    if claim != proof.terminal_left * proof.terminal_right + proof.terminal_correction {
        return Err(ProductSumcheckError::Terminal);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::M31;
    use crate::keccak_circuit::KeccakLayerKind;
    use crate::keccak_gkr_wiring::build_keccak_gkr_round;
    use crate::packed_boolean_sumcheck::OUTPUT_COEFFICIENTS;

    fn fp16(value: u32) -> Fp16 {
        Fp16::from_m31(M31::from_canonical(value).unwrap())
    }

    #[test]
    fn degree_two_product_sumcheck_proves_and_rejects_mutations() {
        let left = (1..=16).map(fp16).collect::<Vec<_>>();
        let right = (17..=32).map(fp16).collect::<Vec<_>>();
        let challenges = [41, 43, 47, 53].map(fp16);
        let (claim, proof) = prove_product_sumcheck(&left, &right, &challenges).unwrap();
        verify_product_sumcheck(claim, &challenges, &proof).unwrap();

        let mut changed = proof.clone();
        changed.rounds[1][2] = changed.rounds[1][2] + Fp16::ONE;
        assert_eq!(
            verify_product_sumcheck(claim, &challenges, &changed),
            Err(ProductSumcheckError::Claim)
        );

        let mut changed = proof;
        changed.terminal_left = changed.terminal_left + Fp16::ONE;
        assert_eq!(
            verify_product_sumcheck(claim, &challenges, &changed),
            Err(ProductSumcheckError::Terminal)
        );
    }

    #[test]
    fn malformed_shapes_fail_closed() {
        assert_eq!(
            prove_product_sumcheck(&[], &[], &[]),
            Err(ProductSumcheckError::Shape)
        );
        assert_eq!(
            prove_product_sumcheck(&[Fp16::ONE; 3], &[Fp16::ONE; 3], &[]),
            Err(ProductSumcheckError::Shape)
        );
        assert_eq!(
            prove_product_sumcheck(&[Fp16::ONE; 2], &[Fp16::ONE; 2], &[]),
            Err(ProductSumcheckError::ChallengeCount)
        );
    }

    #[test]
    fn masked_messages_preserve_claims_and_reject_correction_mutations() {
        let left = (1..=16).map(fp16).collect::<Vec<_>>();
        let right = (17..=32).map(fp16).collect::<Vec<_>>();
        let challenges = [41, 43, 47, 53].map(fp16);
        let masks = [[61, 67], [71, 73], [79, 83], [89, 97]].map(|pair| pair.map(fp16));
        let (claim, proof) =
            prove_masked_product_sumcheck(&left, &right, &challenges, &masks).unwrap();
        verify_masked_product_sumcheck(claim, &challenges, &proof).unwrap();

        let (_, unmasked) = prove_product_sumcheck(&left, &right, &challenges).unwrap();
        assert_ne!(proof.rounds, unmasked.rounds);

        let mut changed = proof;
        changed.terminal_correction = changed.terminal_correction + Fp16::ONE;
        assert_eq!(
            verify_masked_product_sumcheck(claim, &challenges, &changed),
            Err(ProductSumcheckError::Terminal)
        );
    }

    #[test]
    fn bucketed_sparse_schedule_is_byte_identical_for_three_fixed_seeds() {
        fn encode(proof: &SparseLayerSumcheckProof) -> Vec<u8> {
            let mut encoded = Vec::with_capacity((3 * proof.rounds.len() + 2) * 64);
            for round in &proof.rounds {
                for coefficient in round {
                    encoded.extend_from_slice(&coefficient.encode());
                }
            }
            encoded.extend_from_slice(&proof.terminal_left.encode());
            encoded.extend_from_slice(&proof.terminal_right.encode());
            encoded
        }

        let layer = build_keccak_gkr_round(5).unwrap()[5].clone();
        for seed in [1_u64, 17, 123] {
            let input = (0..layer.input_width)
                .map(|index| {
                    let mixed = (index as u64 + seed).wrapping_mul(0x9e37_79b9_7f4a_7c15);
                    fp16(((mixed >> 32) as u32 % 2_147_483_646) + 1)
                })
                .collect::<Vec<_>>();
            let output = evaluate_arithmetic_layer(&layer, &input).unwrap();
            let output_variables = layer.padded_width.trailing_zeros() as usize;
            let input_variables = layer.input_width.trailing_zeros() as usize;
            let point = (0..output_variables)
                .map(|index| fp16(401 + seed as u32 + 7 * index as u32))
                .collect::<Vec<_>>();
            let claims = [LayerOutputClaim {
                value: multilinear_evaluate(&output, &point).unwrap(),
                point,
                coefficient: Fp16::ONE,
            }];
            let challenges = (0..2 * input_variables)
                .map(|index| fp16(701 + seed as u32 + 11 * index as u32))
                .collect::<Vec<_>>();
            let terms = layer_terms(&layer, &claims).unwrap();
            let initial_claim = combined_claim(&claims);
            let reference =
                prove_sparse_terms_reference(&input, initial_claim, &terms, &challenges).unwrap();
            let bucketed =
                prove_sparse_terms_bucketed(&input, initial_claim, &terms, &challenges).unwrap();
            assert_eq!(bucketed, reference);
            assert_eq!(encode(&bucketed), encode(&reference));
            verify_sparse_terms(
                initial_claim,
                layer.input_width,
                &terms,
                &challenges,
                &bucketed,
            )
            .unwrap();
        }
    }

    #[test]
    fn replayed_sparse_payload_is_kilobytes_at_projected_full_widths() {
        assert_eq!(replayed_retained_proof_bytes(1 << 26).unwrap(), 10_112);
        assert_eq!(replayed_retained_proof_bytes(1 << 28).unwrap(), 10_880);
    }

    #[test]
    fn replayed_sparse_real_keccak_layer_is_exact() {
        let seed = 1_u64;
        let layer = build_keccak_gkr_round(5).unwrap()[5].clone();
        let input = (0..layer.input_width)
            .map(|index| {
                let mixed = (index as u64 + seed).wrapping_mul(0x9e37_79b9_7f4a_7c15);
                fp16(((mixed >> 32) as u32 % 2_147_483_646) + 1)
            })
            .collect::<Vec<_>>();
        let output = evaluate_arithmetic_layer(&layer, &input).unwrap();
        let output_variables = layer.padded_width.trailing_zeros() as usize;
        let input_variables = layer.input_width.trailing_zeros() as usize;
        let point = (0..output_variables)
            .map(|index| fp16(401 + seed as u32 + 7 * index as u32))
            .collect::<Vec<_>>();
        let claims = [LayerOutputClaim {
            value: multilinear_evaluate(&output, &point).unwrap(),
            point,
            coefficient: Fp16::ONE,
        }];
        let challenges = (0..2 * input_variables)
            .map(|index| fp16(701 + seed as u32 + 11 * index as u32))
            .collect::<Vec<_>>();
        let terms = layer_terms(&layer, &claims).unwrap();
        let reference =
            prove_sparse_terms_reference(&input, combined_claim(&claims), &terms, &challenges)
                .unwrap();
        let replayed = prove_sparse_terms_replayed(
            input.len(),
            |index| input[index],
            layer.gates.len(),
            |output| replayed_layer_term_at(&layer, &claims, output),
            &challenges,
        )
        .unwrap();
        assert_eq!(replayed, reference);
        verify_sparse_terms(
            combined_claim(&claims),
            layer.input_width,
            &terms,
            &challenges,
            &replayed,
        )
        .unwrap();
    }

    #[test]
    fn sparse_keccak_layer_reduction_binds_real_wiring_and_two_output_claims() {
        let input = (0..2_048)
            .map(|index| {
                if ((index as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 63) == 1 {
                    Fp16::ONE
                } else {
                    Fp16::ZERO
                }
            })
            .collect::<Vec<_>>();

        for ordinal in [5, 8] {
            let layer = build_keccak_gkr_round(ordinal).unwrap()[ordinal].clone();
            let output = evaluate_arithmetic_layer(&layer, &input).unwrap();
            let output_variables = layer.padded_width.trailing_zeros() as usize;
            let input_variables = layer.input_width.trailing_zeros() as usize;
            let first_point = (0..output_variables)
                .map(|index| fp16(101 + index as u32))
                .collect::<Vec<_>>();
            let second_point = (0..output_variables)
                .map(|index| fp16(211 + 3 * index as u32))
                .collect::<Vec<_>>();
            let claims = vec![
                LayerOutputClaim {
                    value: multilinear_evaluate(&output, &first_point).unwrap(),
                    point: first_point,
                    coefficient: fp16(17),
                },
                LayerOutputClaim {
                    value: multilinear_evaluate(&output, &second_point).unwrap(),
                    point: second_point,
                    coefficient: fp16(19),
                },
            ];
            let challenges = (0..2 * input_variables)
                .map(|index| fp16(307 + 5 * index as u32))
                .collect::<Vec<_>>();
            let proof = prove_sparse_gkr_layer(&layer, &input, &claims, &challenges).unwrap();
            verify_sparse_gkr_layer(&layer, &claims, &challenges, &proof).unwrap();

            if ordinal == 5 {
                let mut state =
                    MaskedGkrRoundState::new(combined_claim(&claims), proof.rounds.len()).unwrap();
                assert_eq!(
                    state.accept_authenticated_challenge(challenges[0]),
                    Err(MaskedGkrRoundError::Sequence)
                );
                for (round_index, (round, challenge)) in proof
                    .rounds
                    .iter()
                    .copied()
                    .zip(challenges.iter().copied())
                    .enumerate()
                {
                    let mask = [
                        fp16(2_003 + 2 * round_index as u32),
                        fp16(2_004 + 2 * round_index as u32),
                    ];
                    state.publish_masked_message(round, mask).unwrap();
                    if round_index == 0 {
                        assert_eq!(
                            state.publish_masked_message(round, mask),
                            Err(MaskedGkrRoundError::Sequence)
                        );
                    }
                    state.accept_authenticated_challenge(challenge).unwrap();
                }
                let masked = state
                    .finish(proof.terminal_left, proof.terminal_right)
                    .unwrap();
                verify_masked_sparse_gkr_layer(&layer, &claims, &challenges, &masked).unwrap();
                let mut changed_masked = masked;
                changed_masked.terminal_correction = changed_masked.terminal_correction + Fp16::ONE;
                assert_eq!(
                    verify_masked_sparse_gkr_layer(&layer, &claims, &challenges, &changed_masked),
                    Err(ProductSumcheckError::Terminal)
                );
            }

            let mut changed = proof.clone();
            changed.rounds[1][2] = changed.rounds[1][2] + Fp16::ONE;
            assert_eq!(
                verify_sparse_gkr_layer(&layer, &claims, &challenges, &changed),
                Err(ProductSumcheckError::Claim)
            );

            let mut changed = proof;
            changed.terminal_left = changed.terminal_left + Fp16::ONE;
            assert_eq!(
                verify_sparse_gkr_layer(&layer, &claims, &challenges, &changed),
                Err(ProductSumcheckError::Terminal)
            );
        }
    }

    #[test]
    fn one_pack_bridge_matches_real_xor_and_and_constant_layers() {
        let table = PackedBooleanTable::build().unwrap();
        let shard_query = fp16(401);
        let bridge_challenge = fp16(409);

        for ordinal in [0, 5, 8] {
            let layer = build_keccak_gkr_round(ordinal).unwrap()[ordinal].clone();
            let inputs: [Vec<bool>; PACK_BITS] = core::array::from_fn(|shard| {
                (0..layer.input_width)
                    .map(|wire| {
                        ((wire as u64 + 17 * shard as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15)
                            >> 63)
                            == 1
                    })
                    .collect()
            });
            let output_point = (0..layer.padded_width.trailing_zeros() as usize)
                .map(|index| fp16(419 + 3 * index as u32))
                .collect::<Vec<_>>();
            let sparse_challenges = (0..2 * layer.input_width.trailing_zeros() as usize)
                .map(|index| fp16(503 + 5 * index as u32))
                .collect::<Vec<_>>();
            let (claim, proof, report) = prove_one_pack_keccak_layer_control(
                &table,
                &layer,
                &inputs,
                &output_point,
                shard_query,
                bridge_challenge,
                &sparse_challenges,
            )
            .unwrap();
            assert_eq!(report.gates, layer.padded_width);
            verify_one_pack_keccak_layer_control(
                &layer,
                claim,
                &output_point,
                shard_query,
                bridge_challenge,
                &sparse_challenges,
                &proof,
            )
            .unwrap();

            let mut changed = proof;
            changed.packed_polynomial[OUTPUT_COEFFICIENTS - 2] = Fp16::ONE;
            assert_eq!(
                verify_one_pack_keccak_layer_control(
                    &layer,
                    claim,
                    &output_point,
                    shard_query,
                    bridge_challenge,
                    &sparse_challenges,
                    &changed,
                ),
                Err(OnePackLayerGkrError::Packed(PackedBooleanError::Degree))
            );
        }
    }

    #[test]
    fn repeated_pack_baseline_preserves_group_identity_and_zero_padding() {
        let table = PackedBooleanTable::build().unwrap();
        let layer = build_keccak_gkr_round(5).unwrap()[5].clone();
        let groups = (0..4)
            .map(|group| {
                core::array::from_fn(|shard| {
                    (0..layer.input_width)
                        .map(|wire| {
                            group < 2
                                && ((wire as u64 + 29 * shard as u64 + 101 * group as u64 + 1)
                                    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                                    >> 63)
                                    == 1
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        let group_point = [fp16(607), fp16(613)];
        let output_point = (0..layer.padded_width.trailing_zeros() as usize)
            .map(|index| fp16(617 + 3 * index as u32))
            .collect::<Vec<_>>();
        let sparse_challenges = (0..2
            * (layer.input_width * groups.len()).trailing_zeros() as usize)
            .map(|index| fp16(701 + 5 * index as u32))
            .collect::<Vec<_>>();
        let shard_query = fp16(809);
        let bridge_challenge = fp16(811);
        let (claim, proof, report) = prove_repeated_pack_keccak_layer_control(
            &table,
            &layer,
            &groups,
            &group_point,
            &output_point,
            shard_query,
            bridge_challenge,
            &sparse_challenges,
        )
        .unwrap();
        assert_eq!(report.gates, groups.len() * layer.padded_width);
        verify_repeated_pack_keccak_layer_control(
            &layer,
            groups.len(),
            claim,
            &group_point,
            &output_point,
            shard_query,
            bridge_challenge,
            &sparse_challenges,
            &proof,
        )
        .unwrap();
    }

    #[test]
    fn repeated_pack_combines_two_expanded_output_claims() {
        let table = PackedBooleanTable::build().unwrap();
        let layer = build_keccak_gkr_round(5).unwrap()[5].clone();
        let groups = (0..2)
            .map(|group| {
                core::array::from_fn(|shard| {
                    (0..layer.input_width)
                        .map(|wire| {
                            ((wire as u64 + 31 * shard as u64 + 73 * group as u64 + 1)
                                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                                >> 63)
                                == 1
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        let shard_query = fp16(823);
        let bridge_challenge = fp16(827);
        let mut output_values = Vec::with_capacity(groups.len() * layer.padded_width);
        for inputs in &groups {
            let shard_outputs = inputs
                .iter()
                .map(|input| evaluate_keccak_gkr_layer(&layer, input).unwrap())
                .collect::<Vec<_>>();
            for values in (0..layer.padded_width).map(|wire| {
                core::array::from_fn(|shard| {
                    if shard_outputs[shard][wire] {
                        Fp16::ONE
                    } else {
                        Fp16::ZERO
                    }
                })
            }) {
                output_values.push(evaluate_packed_lagrange_values(&values, shard_query).unwrap());
            }
        }
        let output_variables = output_values.len().trailing_zeros() as usize;
        let first_point = (0..output_variables)
            .map(|index| fp16(829 + 3 * index as u32))
            .collect::<Vec<_>>();
        let second_point = (0..output_variables)
            .map(|index| fp16(881 + 5 * index as u32))
            .collect::<Vec<_>>();
        let mix = fp16(947);
        let claims = vec![
            LayerOutputClaim {
                value: multilinear_evaluate(&output_values, &first_point).unwrap(),
                point: first_point,
                coefficient: mix,
            },
            LayerOutputClaim {
                value: multilinear_evaluate(&output_values, &second_point).unwrap(),
                point: second_point,
                coefficient: Fp16::ONE - mix,
            },
        ];
        let sparse_challenges = (0..2
            * (layer.input_width * groups.len()).trailing_zeros() as usize)
            .map(|index| fp16(953 + 7 * index as u32))
            .collect::<Vec<_>>();
        let (proof, report) = prove_repeated_pack_keccak_layer_claims_control(
            &table,
            &layer,
            &groups,
            &claims,
            shard_query,
            bridge_challenge,
            &sparse_challenges,
        )
        .unwrap();
        assert_eq!(report.gates, groups.len() * layer.padded_width);
        #[cfg(feature = "parallel")]
        {
            let instances = groups.len() * PACK_BITS;
            let words = instances.div_ceil(64);
            let mut packed = vec![0_u64; layer.input_width * words];
            for (group, inputs) in groups.iter().enumerate() {
                for (shard, input) in inputs.iter().enumerate() {
                    let instance = group * PACK_BITS + shard;
                    for (wire, value) in input.iter().copied().enumerate() {
                        if value {
                            packed[wire * words + instance / 64] |= 1_u64 << (instance % 64);
                        }
                    }
                }
            }
            let (parallel_polynomial, parallel_report, parallel_claim) =
                prove_repeated_pack_layer_bridge_parallel(
                    &table,
                    &layer,
                    &packed,
                    instances,
                    &claims,
                    shard_query,
                    bridge_challenge,
                    2,
                )
                .unwrap();
            assert_eq!(parallel_polynomial, proof.packed_polynomial);
            assert_eq!(parallel_report, report);
            assert_eq!(
                parallel_claim,
                verify_packed_first_round_bridge(
                    combined_claim(&claims),
                    &proof.packed_polynomial,
                    shard_query,
                    bridge_challenge,
                )
                .unwrap()
                .gate_claim
            );
        }
        verify_repeated_pack_keccak_layer_claims_control(
            &layer,
            groups.len(),
            &claims,
            shard_query,
            bridge_challenge,
            &sparse_challenges,
            &proof,
        )
        .unwrap();
        let terminal = repeated_pack_terminal_gate_claim(
            &layer,
            groups.len(),
            &claims,
            &sparse_challenges[..sparse_challenges.len() / 2],
            &sparse_challenges[sparse_challenges.len() / 2..],
            proof.sparse_layer.terminal_left,
            proof.sparse_layer.terminal_right,
        )
        .unwrap();
        let folded_terminal = proof
            .sparse_layer
            .rounds
            .iter()
            .copied()
            .zip(sparse_challenges.iter().copied())
            .fold(
                verify_packed_first_round_bridge(
                    combined_claim(&claims),
                    &proof.packed_polynomial,
                    shard_query,
                    bridge_challenge,
                )
                .unwrap()
                .gate_claim,
                |_, (round, challenge)| evaluate_quadratic(round, challenge),
            );
        assert_eq!(terminal, folded_terminal);
        let bridge = verify_packed_first_round_bridge(
            combined_claim(&claims),
            &proof.packed_polynomial,
            shard_query,
            bridge_challenge,
        )
        .unwrap();
        let mut masked_state =
            MaskedGkrRoundState::new(bridge.gate_claim, proof.sparse_layer.rounds.len()).unwrap();
        for (round_index, (round, challenge)) in proof
            .sparse_layer
            .rounds
            .iter()
            .copied()
            .zip(sparse_challenges.iter().copied())
            .enumerate()
        {
            masked_state
                .publish_masked_message(
                    round,
                    [
                        fp16(1_301 + 2 * round_index as u32),
                        fp16(1_302 + 2 * round_index as u32),
                    ],
                )
                .unwrap();
            masked_state
                .accept_authenticated_challenge(challenge)
                .unwrap();
        }
        let masked = masked_state
            .finish(
                proof.sparse_layer.terminal_left,
                proof.sparse_layer.terminal_right,
            )
            .unwrap();
        verify_masked_repeated_sparse_layer(
            &layer,
            groups.len(),
            bridge.gate_claim,
            &claims,
            &sparse_challenges,
            &masked,
        )
        .unwrap();

        let mut changed = claims;
        changed[1].value = changed[1].value + Fp16::ONE;
        assert_eq!(
            verify_repeated_pack_keccak_layer_claims_control(
                &layer,
                groups.len(),
                &changed,
                shard_query,
                bridge_challenge,
                &sparse_challenges,
                &proof,
            ),
            Err(OnePackLayerGkrError::Packed(PackedBooleanError::Claim))
        );
    }

    #[test]
    fn repeated_pack_chain_carries_nonlinear_bridge_between_layers() {
        let table = PackedBooleanTable::build().unwrap();
        let round = build_keccak_gkr_round(7).unwrap();
        let layers = round.to_vec();
        let input_groups = vec![core::array::from_fn(|shard| {
            (0..layers[0].input_width)
                .map(|wire| {
                    ((wire as u64 + 37 * shard as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15)
                        >> 63)
                        == 1
                })
                .collect::<Vec<_>>()
        })];
        let output_variables = layers.last().unwrap().padded_width.trailing_zeros() as usize;
        let output_point = (0..output_variables)
            .map(|index| fp16(1009 + 3 * index as u32))
            .collect::<Vec<_>>();
        let layer_sparse_challenges = layers
            .iter()
            .enumerate()
            .map(|(layer_index, layer)| {
                (0..2 * layer.input_width.trailing_zeros() as usize)
                    .map(|index| fp16(1103 + 97 * layer_index as u32 + 5 * index as u32))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let bridge_challenges = (0..layers.len())
            .map(|index| fp16(1223 + 6 * index as u32))
            .collect::<Vec<_>>();
        let mix_challenges = (0..layers.len() - 1)
            .map(|index| fp16(1231 + 6 * index as u32))
            .collect::<Vec<_>>();
        let output_shard_query = fp16(1237);
        let (output_value, proof, terminal_claims, terminal_shard_query) =
            prove_repeated_pack_gkr_chain_checkpointed(
                &table,
                &layers,
                &input_groups,
                &output_point,
                output_shard_query,
                &bridge_challenges,
                &layer_sparse_challenges,
                &mix_challenges,
            )
            .unwrap();
        let reference = prove_repeated_pack_gkr_chain_reference(
            &table,
            &layers,
            &input_groups,
            &output_point,
            output_shard_query,
            &bridge_challenges,
            &layer_sparse_challenges,
            &mix_challenges,
        )
        .unwrap();
        assert_eq!(
            (
                output_value,
                proof.clone(),
                terminal_claims.clone(),
                terminal_shard_query
            ),
            reference
        );
        assert_eq!(
            verify_repeated_pack_gkr_chain_control(
                &layers,
                input_groups.len(),
                &output_point,
                output_value,
                output_shard_query,
                &bridge_challenges,
                &layer_sparse_challenges,
                &mix_challenges,
                &proof,
            )
            .unwrap(),
            (terminal_claims.clone(), terminal_shard_query)
        );

        let input_values =
            interpolate_packed_inputs(&input_groups[0], terminal_shard_query).unwrap();
        for claim in &terminal_claims {
            assert_eq!(
                multilinear_evaluate(&input_values, &claim.point).unwrap(),
                claim.value
            );
        }
    }

    #[test]
    fn sparse_layer_reduction_rejects_malformed_claim_geometry() {
        let layer = build_keccak_gkr_round(0).unwrap()[0].clone();
        let input = vec![Fp16::ZERO; layer.input_width];
        let claim = LayerOutputClaim {
            point: vec![Fp16::ONE],
            value: Fp16::ZERO,
            coefficient: Fp16::ONE,
        };
        let challenges = vec![fp16(313); 2 * layer.input_width.trailing_zeros() as usize];
        assert_eq!(
            prove_sparse_gkr_layer(&layer, &input, &[claim], &challenges),
            Err(ProductSumcheckError::Shape)
        );
    }

    #[test]
    fn sparse_chain_carries_two_claims_and_exposes_exact_input_openings() {
        let p = BooleanWire::Previous;
        let c = BooleanWire::Constant;
        let layers = vec![
            KeccakGkrLayer {
                kind: KeccakLayerKind::ThetaPairs,
                input_width: 4,
                raw_width: 4,
                padded_width: 4,
                gates: vec![
                    BooleanGate {
                        kind: BooleanGateKind::Xor,
                        left: p(0),
                        right: p(1),
                    },
                    BooleanGate {
                        kind: BooleanGateKind::And,
                        left: p(2),
                        right: p(3),
                    },
                    BooleanGate {
                        kind: BooleanGateKind::Relay,
                        left: p(1),
                        right: c(false),
                    },
                    BooleanGate {
                        kind: BooleanGateKind::Xor,
                        left: p(3),
                        right: c(true),
                    },
                ],
            },
            KeccakGkrLayer {
                kind: KeccakLayerKind::ThetaPairParity,
                input_width: 4,
                raw_width: 4,
                padded_width: 4,
                gates: vec![
                    BooleanGate {
                        kind: BooleanGateKind::And,
                        left: p(0),
                        right: p(1),
                    },
                    BooleanGate {
                        kind: BooleanGateKind::Xor,
                        left: p(2),
                        right: p(3),
                    },
                    BooleanGate {
                        kind: BooleanGateKind::Relay,
                        left: p(0),
                        right: c(false),
                    },
                    BooleanGate {
                        kind: BooleanGateKind::Zero,
                        left: c(false),
                        right: c(false),
                    },
                ],
            },
        ];
        let input = [Fp16::ONE, Fp16::ZERO, Fp16::ONE, Fp16::ONE];
        let output_point = [fp16(7), fp16(11)];
        let challenges = vec![
            vec![fp16(13), fp16(17), fp16(19), fp16(23)],
            vec![fp16(29), fp16(31), fp16(37), fp16(41)],
        ];
        let (output_value, proof, terminal_claims) =
            prove_sparse_gkr_chain(&layers, &input, &output_point, &challenges, &[fp16(43)])
                .unwrap();
        assert_eq!(
            verify_sparse_gkr_chain(
                &layers,
                &output_point,
                output_value,
                &challenges,
                &[fp16(43)],
                &proof
            )
            .unwrap(),
            terminal_claims
        );
        assert_eq!(terminal_claims.len(), 2);
        for claim in &terminal_claims {
            assert_eq!(
                multilinear_evaluate(&input, &claim.point).unwrap(),
                claim.value
            );
        }

        assert_eq!(
            verify_sparse_gkr_chain(
                &layers,
                &output_point,
                output_value + Fp16::ONE,
                &challenges,
                &[fp16(43)],
                &proof
            ),
            Err(ProductSumcheckError::Claim)
        );
    }
}
