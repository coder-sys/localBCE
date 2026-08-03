//! Uniform-group reference producer for the selected relay-free Keccak GKR.
//!
//! This module proves the actual seven-layer, twenty-four-round Keccak DAG for
//! the all-zero sixteen-shard KAT. Every group has the same wire row, so the
//! prover reduces the shared group axis algebraically instead of materializing
//! 8,192 duplicate rows. The proof is accepted by the ordinary shared-group
//! verifier; uniformity is a prover optimization, not a verifier assumption.
//!
//! The transcript emitted here is the raw GKR algebra boundary. Native Libra
//! masking and its aggregate committed opening are deliberately layered above
//! this module and must be present before complete-proof qualification.

use alloc::{vec, vec::Vec};

use crate::{
    field::{Fp16, M31},
    fp16_relay_free_gkr_schedule::{
        GKR_TRANSCRIPT_ROUNDS, SelectedGkrRoundKind, selected_gkr_mask_layout,
        selected_gkr_round_kind, selected_gkr_round_output_count,
    },
    fp16_relay_free_gkr_source::{GROUP_COUNT, KECCAK_F_ZERO},
    gkr_packed_binary_bridge_fp16::{
        PACKED_BINARY_MESSAGE_COEFFICIENTS, PackedBinaryGate, evaluate_message,
        packed_binary_round_message, packed_selector_polynomial,
    },
    gkr_packed_bridge_fp16::{evaluate, lagrange_basis, lagrange_evaluations},
    gkr_sumcheck::{
        LayerOutputClaim, MaskedSharedGroupOracle, MaskedUniformSharedGroupDagLayerProof,
        ProductSumcheckError, SharedGroupDagLayerProof, SharedGroupDagRoundKind,
        multilinear_equality_table, prove_masked_shared_group_dag_layer_interactive,
        prove_masked_shared_group_dag_layer_oracle_interactive,
        prove_uniform_shared_group_dag_layer_interactive, shared_group_terminal_gate_claim,
        verify_shared_group_dag_layer_reference,
    },
    gkr_zk_mask::{
        GkrZkMaskError, LibraPriorLayerCorrection, boolean_vanishing, inner_product,
        polynomial_evaluation,
    },
    keccak_gkr_dag::{
        KeccakDagGateKind, KeccakDagLayer, KeccakDagSource, build_keccak_gkr_dag_round,
        evaluate_keccak_gkr_dag_round,
    },
};

const STATE_BITS: usize = 1_600;
const PADDED_STATE_BITS: usize = 2_048;
#[cfg(test)]
const FP16_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UniformRelayFreeGkrError {
    Shape,
    Schedule,
    Coin,
    Algebra,
    Trace,
}

impl From<ProductSumcheckError> for UniformRelayFreeGkrError {
    fn from(_: ProductSumcheckError) -> Self {
        Self::Algebra
    }
}

fn map_mask_error(error: GkrZkMaskError) -> UniformRelayFreeGkrError {
    match error {
        GkrZkMaskError::Shape | GkrZkMaskError::Empty | GkrZkMaskError::Overflow => {
            UniformRelayFreeGkrError::Shape
        }
        GkrZkMaskError::Round | GkrZkMaskError::Sequence => UniformRelayFreeGkrError::Schedule,
        GkrZkMaskError::Claim => UniformRelayFreeGkrError::Algebra,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UniformRelayFreeClaim {
    pub shard_query: Fp16,
    pub point: Vec<Fp16>,
    pub value: Fp16,
    pub coefficient: Fp16,
}

/// Minimal untrusted accelerator boundary for a real nonuniform B16 trace.
///
/// The oracle never chooses a challenge or a mask. Rust checks the bridge node
/// sum and every group recurrence before releasing the corresponding
/// authenticated challenge, then performs the complete wire tail itself.
pub trait NonuniformRelayFreeGkrOracle: MaskedSharedGroupOracle {
    fn output_claim(
        &mut self,
        shard_query: Fp16,
        point: &[Fp16],
    ) -> Result<Fp16, UniformRelayFreeGkrError>;

    fn begin_layer(
        &mut self,
        keccak_round: usize,
        layer: usize,
        topology: &KeccakDagLayer,
        claims: &[UniformRelayFreeClaim],
    ) -> Result<[Fp16; PACKED_BINARY_MESSAGE_COEFFICIENTS], UniformRelayFreeGkrError>;

    fn accept_bridge_challenge(&mut self, challenge: Fp16) -> Result<(), UniformRelayFreeGkrError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UniformRelayFreeGkrRound {
    pub kind: SelectedGkrRoundKind,
    pub message: Vec<u8>,
    pub outputs: Vec<Fp16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UniformRelayFreeGkrLayerProof {
    pub keccak_round: usize,
    pub layer: usize,
    pub incoming_claims: Vec<UniformRelayFreeClaim>,
    pub effective_claims: Vec<LayerOutputClaim>,
    pub bridge_message: [Fp16; PACKED_BINARY_MESSAGE_COEFFICIENTS],
    pub bridge_challenge: Fp16,
    pub group_challenges: Vec<Fp16>,
    pub wire_challenges: Vec<Fp16>,
    pub sumcheck: SharedGroupDagLayerProof,
    pub terminal_challenge: Fp16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UniformRelayFreeGkrProof {
    pub output_claim: UniformRelayFreeClaim,
    pub input_claims: Vec<UniformRelayFreeClaim>,
    pub layers: Vec<UniformRelayFreeGkrLayerProof>,
    pub rounds: Vec<UniformRelayFreeGkrRound>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaskedUniformRelayFreeGkrLayerProof {
    pub keccak_round: usize,
    pub layer: usize,
    pub incoming_raw_claims: Vec<UniformRelayFreeClaim>,
    pub incoming_masked_values: Vec<Fp16>,
    pub incoming_mask_layers: Vec<Option<usize>>,
    pub bridge_rho: Fp16,
    pub sumcheck_rho: Fp16,
    pub raw_bridge: [Fp16; PACKED_BINARY_MESSAGE_COEFFICIENTS],
    pub public_bridge: [Fp16; PACKED_BINARY_MESSAGE_COEFFICIENTS],
    pub bridge_challenge: Fp16,
    pub reduction: MaskedUniformSharedGroupDagLayerProof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaskedUniformRelayFreeGkrProof {
    pub mask_commitment: [u8; 64],
    pub raw_output_claim: UniformRelayFreeClaim,
    pub raw_input_claims: Vec<UniformRelayFreeClaim>,
    pub masked_input_values: Vec<Fp16>,
    pub input_mask_layers: Vec<usize>,
    pub layers: Vec<MaskedUniformRelayFreeGkrLayerProof>,
    pub rounds: Vec<UniformRelayFreeGkrRound>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UniformGkrMaskFunctional {
    BridgeEvaluation {
        layer: usize,
        point: Fp16,
        scale: Fp16,
    },
    SumcheckBooleanSum {
        layer: usize,
        scale: Fp16,
    },
    SumcheckEvaluation {
        layer: usize,
        point: Vec<Fp16>,
        scale: Fp16,
    },
    LayerEvaluation {
        layer: usize,
        z_first: Fp16,
        w: Fp16,
        scale: Fp16,
    },
    LayerBooleanSum {
        layer: usize,
        z_first: Fp16,
        scale: Fp16,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UniformGkrMaskConstraint {
    pub functionals: Vec<UniformGkrMaskFunctional>,
    pub residual: Fp16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UniformGkrMaskBatch {
    pub challenge: Fp16,
    pub opening: Fp16,
    pub coefficient_weights: Vec<Fp16>,
    pub constraints: Vec<UniformGkrMaskConstraint>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MaskedPendingClaim {
    raw: UniformRelayFreeClaim,
    masked_value: Fp16,
    mask_layer: Option<usize>,
}

#[derive(Clone)]
struct UniformRoundTrace {
    layers: [KeccakDagLayer; 7],
    round_input: Vec<Fp16>,
    boundaries: Vec<Vec<Fp16>>,
}

fn append_field(message: &mut Vec<u8>, value: Fp16) {
    message.extend_from_slice(&value.encode());
}

fn append_claim(message: &mut Vec<u8>, claim: &UniformRelayFreeClaim) {
    append_field(message, claim.shard_query);
    message.extend_from_slice(&(claim.point.len() as u16).to_be_bytes());
    for coordinate in &claim.point {
        append_field(message, *coordinate);
    }
    append_field(message, claim.value);
}

fn request_round(
    rounds: &mut Vec<UniformRelayFreeGkrRound>,
    coin: &mut impl FnMut(
        SelectedGkrRoundKind,
        &[u8],
        u16,
    ) -> Result<Vec<Fp16>, UniformRelayFreeGkrError>,
    kind: SelectedGkrRoundKind,
    message: Vec<u8>,
) -> Result<Vec<Fp16>, UniformRelayFreeGkrError> {
    let ordinal = rounds.len() as u32;
    if selected_gkr_round_kind(ordinal) != Some(kind) {
        return Err(UniformRelayFreeGkrError::Schedule);
    }
    let output_count =
        selected_gkr_round_output_count(ordinal).ok_or(UniformRelayFreeGkrError::Schedule)?;
    let outputs = coin(kind, &message, output_count)?;
    if outputs.len() != usize::from(output_count) {
        return Err(UniformRelayFreeGkrError::Coin);
    }
    rounds.push(UniformRelayFreeGkrRound {
        kind,
        message,
        outputs: outputs.clone(),
    });
    Ok(outputs)
}

fn multilinear_evaluate(values: &[Fp16], point: &[Fp16]) -> Result<Fp16, UniformRelayFreeGkrError> {
    if values.is_empty()
        || !values.len().is_power_of_two()
        || point.len() != values.len().trailing_zeros() as usize
    {
        return Err(UniformRelayFreeGkrError::Shape);
    }
    let mut folded = values.to_vec();
    for coordinate in point {
        for index in 0..folded.len() / 2 {
            let zero = folded[2 * index];
            folded[index] = zero + *coordinate * (folded[2 * index + 1] - zero);
        }
        folded.truncate(folded.len() / 2);
    }
    Ok(folded[0])
}

fn build_zero_trace() -> Result<Vec<UniformRoundTrace>, UniformRelayFreeGkrError> {
    let mut round_input_bits = vec![false; PADDED_STATE_BITS];
    let mut trace = Vec::with_capacity(24);
    for round in 0..24 {
        let layers =
            build_keccak_gkr_dag_round(round).map_err(|_| UniformRelayFreeGkrError::Trace)?;
        let boolean_boundaries = evaluate_keccak_gkr_dag_round(&layers, &round_input_bits)
            .map_err(|_| UniformRelayFreeGkrError::Trace)?;
        let round_input = round_input_bits
            .iter()
            .map(|bit| if *bit { Fp16::ONE } else { Fp16::ZERO })
            .collect();
        let boundaries = boolean_boundaries
            .iter()
            .map(|boundary| {
                boundary
                    .iter()
                    .map(|bit| if *bit { Fp16::ONE } else { Fp16::ZERO })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        round_input_bits[..STATE_BITS].copy_from_slice(&boolean_boundaries[6][..STATE_BITS]);
        round_input_bits[STATE_BITS..].fill(false);
        trace.push(UniformRoundTrace {
            layers,
            round_input,
            boundaries,
        });
    }
    let final_state = core::array::from_fn(|lane| {
        (0..64).fold(0_u64, |value, bit| {
            value | (u64::from(round_input_bits[64 * lane + bit]) << bit)
        })
    });
    if final_state != KECCAK_F_ZERO {
        return Err(UniformRelayFreeGkrError::Trace);
    }
    Ok(trace)
}

fn source_values(trace: &UniformRoundTrace, source: KeccakDagSource) -> &[Fp16] {
    match source {
        KeccakDagSource::RoundInput => &trace.round_input,
        KeccakDagSource::Layer(index) => &trace.boundaries[index],
    }
}

fn gate_value(kind: KeccakDagGateKind, left: Fp16, right: Fp16) -> Fp16 {
    match kind {
        KeccakDagGateKind::Xor | KeccakDagGateKind::XorConstant(false) => {
            left + right - left * right - left * right
        }
        KeccakDagGateKind::NotLeftAndRight => right - left * right,
        KeccakDagGateKind::XorConstant(true) => {
            Fp16::ONE - left - right + left * right + left * right
        }
        KeccakDagGateKind::Subtract => {
            unreachable!("state-only field gate in Boolean Keccak evaluator")
        }
        KeccakDagGateKind::Zero => Fp16::ZERO,
    }
}

fn packed_gate(kind: KeccakDagGateKind) -> Option<PackedBinaryGate> {
    match kind {
        KeccakDagGateKind::Xor | KeccakDagGateKind::XorConstant(false) => {
            Some(PackedBinaryGate::Xor)
        }
        KeccakDagGateKind::NotLeftAndRight => Some(PackedBinaryGate::NotLeftAndRight),
        KeccakDagGateKind::XorConstant(true) => Some(PackedBinaryGate::NotXor),
        KeccakDagGateKind::Subtract => {
            unreachable!("state-only field gate in packed Boolean evaluator")
        }
        KeccakDagGateKind::Zero => None,
    }
}

fn boolean_pattern(value: Fp16) -> Result<u16, UniformRelayFreeGkrError> {
    if value == Fp16::ZERO {
        Ok(0)
    } else if value == Fp16::ONE {
        Ok(u16::MAX)
    } else {
        Err(UniformRelayFreeGkrError::Trace)
    }
}

fn bridge_message(
    layer: &KeccakDagLayer,
    left: &[Fp16],
    right: &[Fp16],
    claims: &[UniformRelayFreeClaim],
) -> Result<[Fp16; PACKED_BINARY_MESSAGE_COEFFICIENTS], UniformRelayFreeGkrError> {
    if claims.is_empty() || claims.len() > 4 {
        return Err(UniformRelayFreeGkrError::Shape);
    }
    let output_variables = layer.padded_width.trailing_zeros() as usize;
    let claim_weights = claims
        .iter()
        .map(|claim| {
            if claim.point.len() != output_variables + GROUP_COUNT.trailing_zeros() as usize {
                return Err(UniformRelayFreeGkrError::Shape);
            }
            multilinear_equality_table(&claim.point[..output_variables])
                .map_err(UniformRelayFreeGkrError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut gates = Vec::<PackedBinaryGate>::new();
    let mut left_patterns = Vec::<u16>::new();
    let mut right_patterns = Vec::<u16>::new();
    let mut weights = Vec::<[Fp16; 4]>::new();
    for (output, gate) in layer.gates[..layer.raw_width].iter().enumerate() {
        let Some(packed) = packed_gate(gate.kind) else {
            continue;
        };
        let left_pattern = boolean_pattern(left[gate.left])?;
        let right_pattern = boolean_pattern(right[gate.right])?;
        let class = gates
            .iter()
            .zip(&left_patterns)
            .zip(&right_patterns)
            .position(|((candidate, candidate_left), candidate_right)| {
                *candidate == packed
                    && *candidate_left == left_pattern
                    && *candidate_right == right_pattern
            })
            .unwrap_or_else(|| {
                gates.push(packed);
                left_patterns.push(left_pattern);
                right_patterns.push(right_pattern);
                weights.push([Fp16::ZERO; 4]);
                gates.len() - 1
            });
        for (claim_index, claim) in claims.iter().enumerate() {
            weights[class][claim_index] = weights[class][claim_index]
                + claim.coefficient * claim_weights[claim_index][output];
        }
    }
    let queries = core::array::from_fn(|index| {
        claims
            .get(index)
            .map_or(Fp16::ZERO, |claim| claim.shard_query)
    });
    packed_binary_round_message::<4>(&gates, &left_patterns, &right_patterns, &weights, &queries)
        .map_err(|_| UniformRelayFreeGkrError::Algebra)
}

/// Check the verifier-side endpoint of the packed B16 sumcheck without
/// reconstructing private source patterns.
///
/// The bridge is published before its challenge. Summing it at the sixteen
/// public interpolation nodes must recover the incoming combined claim. This
/// is the generic verifier boundary needed by the real nonuniform producer;
/// the uniform KAT additionally recomputes the complete bridge from its known
/// source row.
pub fn verify_packed_bridge_node_sum(
    claims: &[UniformRelayFreeClaim],
    message: &[Fp16; PACKED_BINARY_MESSAGE_COEFFICIENTS],
) -> Result<(), UniformRelayFreeGkrError> {
    if claims.is_empty() || claims.len() > 4 {
        return Err(UniformRelayFreeGkrError::Shape);
    }
    let node_sum = (0..16).try_fold(Fp16::ZERO, |sum, node| {
        let node = M31::from_canonical(node).map_err(|_| UniformRelayFreeGkrError::Shape)?;
        Ok::<_, UniformRelayFreeGkrError>(sum + evaluate_message(message, Fp16::from_m31(node)))
    })?;
    let claim = claims.iter().fold(Fp16::ZERO, |sum, claim| {
        sum + claim.coefficient * claim.value
    });
    if node_sum != claim {
        return Err(UniformRelayFreeGkrError::Algebra);
    }
    Ok(())
}

fn selector_evaluation(query: Fp16, point: Fp16) -> Fp16 {
    let basis = lagrange_basis();
    let at_query = lagrange_evaluations(&basis, query);
    basis
        .iter()
        .zip(at_query)
        .fold(Fp16::ZERO, |sum, (polynomial, weight)| {
            sum + evaluate(polynomial, point) * weight
        })
}

fn layer_output_values(
    layer: &KeccakDagLayer,
    left: &[Fp16],
    right: &[Fp16],
) -> Result<Vec<Fp16>, UniformRelayFreeGkrError> {
    if left.len() != layer.left_width || right.len() != layer.right_width {
        return Err(UniformRelayFreeGkrError::Shape);
    }
    layer
        .gates
        .iter()
        .map(|gate| {
            if gate.left >= left.len() || gate.right >= right.len() {
                return Err(UniformRelayFreeGkrError::Shape);
            }
            Ok(gate_value(gate.kind, left[gate.left], right[gate.right]))
        })
        .collect()
}

fn output_query_message() -> Vec<u8> {
    let mut message = b"BL/PQ512/WAVE2/UNIFORM-REAL-GKR/OUTPUT/v1\0".to_vec();
    for lane in KECCAK_F_ZERO {
        message.extend_from_slice(&lane.to_be_bytes());
    }
    message
}

fn masked_output_query_message(mask_commitment: &[u8; 64]) -> Vec<u8> {
    let mut message = b"BL/PQ512/WAVE2/UNIFORM-REAL-GKR/MASKED-OUTPUT/v1\0".to_vec();
    message.extend_from_slice(mask_commitment);
    for lane in KECCAK_F_ZERO {
        message.extend_from_slice(&lane.to_be_bytes());
    }
    message
}

fn masked_nonuniform_output_query_message(
    mask_commitment: &[u8; 64],
    statement_binding: &[u8; 64],
) -> Vec<u8> {
    let mut message = b"BL/PQ512/WAVE2/NONUNIFORM-REAL-GKR/MASKED-OUTPUT/v1\0".to_vec();
    message.extend_from_slice(mask_commitment);
    message.extend_from_slice(statement_binding);
    message
}

fn masked_claim_mix_message(
    keccak_round: usize,
    layer: usize,
    claims: &[MaskedPendingClaim],
) -> Vec<u8> {
    let mut message = b"BL/PQ512/WAVE2/UNIFORM-REAL-GKR/MASKED-CLAIM-MIX/v1\0".to_vec();
    message.extend_from_slice(&(keccak_round as u16).to_be_bytes());
    message.push(layer as u8);
    message.push(claims.len() as u8);
    for claim in claims {
        append_field(&mut message, claim.raw.shard_query);
        message.extend_from_slice(&(claim.raw.point.len() as u16).to_be_bytes());
        for coordinate in &claim.raw.point {
            append_field(&mut message, *coordinate);
        }
        append_field(&mut message, claim.masked_value);
    }
    message
}

fn claim_mix_message(
    keccak_round: usize,
    layer: usize,
    claims: &[UniformRelayFreeClaim],
) -> Vec<u8> {
    let mut message = b"BL/PQ512/WAVE2/UNIFORM-REAL-GKR/CLAIM-MIX/v1\0".to_vec();
    message.extend_from_slice(&(keccak_round as u16).to_be_bytes());
    message.push(layer as u8);
    message.push(claims.len() as u8);
    for claim in claims {
        append_claim(&mut message, claim);
    }
    message
}

fn polynomial_message(domain: &[u8], values: &[Fp16]) -> Vec<u8> {
    let mut message = domain.to_vec();
    message.extend_from_slice(&(values.len() as u16).to_be_bytes());
    for value in values {
        append_field(&mut message, *value);
    }
    message
}

fn push_source_claim(
    pending: &mut [Vec<Vec<UniformRelayFreeClaim>>],
    round: usize,
    source: KeccakDagSource,
    claim: UniformRelayFreeClaim,
    input_claims: &mut Vec<UniformRelayFreeClaim>,
) {
    match source {
        KeccakDagSource::Layer(index) => pending[round][index + 1].push(claim),
        KeccakDagSource::RoundInput if round > 0 => pending[round - 1][7].push(claim),
        KeccakDagSource::RoundInput => input_claims.push(claim),
    }
}

/// Produce the raw real-DAG transcript for the sixteen-shard all-zero KAT.
///
/// The callback must bind every message before returning exactly the requested
/// number of authenticated public-coin outputs.
pub fn prove_uniform_zero_trace(
    mut coin: impl FnMut(
        SelectedGkrRoundKind,
        &[u8],
        u16,
    ) -> Result<Vec<Fp16>, UniformRelayFreeGkrError>,
) -> Result<UniformRelayFreeGkrProof, UniformRelayFreeGkrError> {
    let trace = build_zero_trace()?;
    let mut rounds = Vec::with_capacity(GKR_TRANSCRIPT_ROUNDS as usize);
    let output = request_round(
        &mut rounds,
        &mut coin,
        SelectedGkrRoundKind::OutputQuery,
        output_query_message(),
    )?;
    let output_claim = UniformRelayFreeClaim {
        shard_query: output[0],
        point: output[1..25].to_vec(),
        value: multilinear_evaluate(&trace[23].boundaries[6], &output[1..12])?,
        coefficient: Fp16::ONE,
    };

    let mut pending = vec![vec![Vec::<UniformRelayFreeClaim>::new(); 8]; 24];
    pending[23][7].push(output_claim.clone());
    let mut input_claims = Vec::with_capacity(4);
    let mut layer_proofs = Vec::with_capacity(168);

    for round in (0..24).rev() {
        for layer_index in (0..7).rev() {
            let layer = &trace[round].layers[layer_index];
            let mut incoming = core::mem::take(&mut pending[round][layer_index + 1]);
            if incoming.is_empty() || incoming.len() > 4 {
                return Err(UniformRelayFreeGkrError::Shape);
            }
            let needs_mix = matches!(layer_index, 0 | 2 | 4) || (layer_index == 6 && round != 23);
            if needs_mix {
                let outputs = request_round(
                    &mut rounds,
                    &mut coin,
                    SelectedGkrRoundKind::ClaimMix,
                    claim_mix_message(round, layer_index, &incoming),
                )?;
                if outputs[0].is_zero() {
                    return Err(UniformRelayFreeGkrError::Coin);
                }
                let mut power = Fp16::ONE;
                for claim in &mut incoming {
                    claim.coefficient = power;
                    power = power * outputs[0];
                }
            } else {
                if incoming.len() != 1 {
                    return Err(UniformRelayFreeGkrError::Shape);
                }
                incoming[0].coefficient = Fp16::ONE;
            }

            let left = source_values(&trace[round], layer.left_source);
            let right = source_values(&trace[round], layer.right_source);
            let bridge = bridge_message(layer, left, right, &incoming)?;
            let bridge_outputs = request_round(
                &mut rounds,
                &mut coin,
                SelectedGkrRoundKind::PackedBridge,
                polynomial_message(b"BL/PQ512/WAVE2/UNIFORM-REAL-GKR/BRIDGE/v1\0", &bridge),
            )?;
            let bridge_challenge = bridge_outputs[0];
            let output_values = layer_output_values(layer, left, right)?;
            let output_variables = layer.padded_width.trailing_zeros() as usize;
            let effective_claims = incoming
                .iter()
                .map(|claim| {
                    Ok(LayerOutputClaim {
                        point: claim.point.clone(),
                        value: multilinear_evaluate(
                            &output_values,
                            &claim.point[..output_variables],
                        )?,
                        coefficient: claim.coefficient
                            * selector_evaluation(claim.shard_query, bridge_challenge),
                    })
                })
                .collect::<Result<Vec<_>, UniformRelayFreeGkrError>>()?;
            let bridge_value = evaluate_message(&bridge, bridge_challenge);
            let effective_value = effective_claims.iter().fold(Fp16::ZERO, |sum, claim| {
                sum + claim.coefficient * claim.value
            });
            if bridge_value != effective_value {
                return Err(UniformRelayFreeGkrError::Algebra);
            }

            let (sumcheck, group_challenges, wire_challenges) =
                prove_uniform_shared_group_dag_layer_interactive(
                    layer,
                    GROUP_COUNT,
                    left,
                    right,
                    &effective_claims,
                    |kind, _, coefficients| {
                        let selected_kind = match kind {
                            SharedGroupDagRoundKind::Group => SelectedGkrRoundKind::SharedGroup,
                            SharedGroupDagRoundKind::LeftWire
                            | SharedGroupDagRoundKind::RightWire => SelectedGkrRoundKind::Wire,
                        };
                        let outputs = request_round(
                            &mut rounds,
                            &mut coin,
                            selected_kind,
                            polynomial_message(
                                b"BL/PQ512/WAVE2/UNIFORM-REAL-GKR/SUMCHECK/v1\0",
                                coefficients,
                            ),
                        )
                        .map_err(|_| ProductSumcheckError::ChallengeCount)?;
                        Ok(outputs[0])
                    },
                )?;

            let mut terminal_claim = bridge_value;
            for (message, challenge) in sumcheck.group_rounds.iter().zip(&group_challenges) {
                terminal_claim = message.iter().rev().fold(Fp16::ZERO, |value, coefficient| {
                    value * *challenge + *coefficient
                });
            }
            for (message, challenge) in sumcheck.wire_proof.rounds.iter().zip(&wire_challenges) {
                terminal_claim = message.iter().rev().fold(Fp16::ZERO, |value, coefficient| {
                    value * *challenge + *coefficient
                });
            }
            let w_polynomial = [terminal_claim, -terminal_claim, Fp16::ZERO];
            let mut terminal_message = polynomial_message(
                b"BL/PQ512/WAVE2/UNIFORM-REAL-GKR/TERMINAL/v1\0",
                &w_polynomial,
            );
            append_field(&mut terminal_message, sumcheck.wire_proof.terminal_left);
            append_field(&mut terminal_message, sumcheck.wire_proof.terminal_right);
            let terminal_outputs = request_round(
                &mut rounds,
                &mut coin,
                SelectedGkrRoundKind::Terminal,
                terminal_message,
            )?;
            let group_point = group_challenges.clone();
            let left_variables = layer.left_width.trailing_zeros() as usize;
            let left_point = wire_challenges[..left_variables]
                .iter()
                .chain(&group_point)
                .copied()
                .collect();
            let right_point = wire_challenges[left_variables..]
                .iter()
                .chain(&group_point)
                .copied()
                .collect();
            push_source_claim(
                &mut pending,
                round,
                layer.left_source,
                UniformRelayFreeClaim {
                    shard_query: bridge_challenge,
                    point: left_point,
                    value: sumcheck.wire_proof.terminal_left,
                    coefficient: Fp16::ONE,
                },
                &mut input_claims,
            );
            push_source_claim(
                &mut pending,
                round,
                layer.right_source,
                UniformRelayFreeClaim {
                    shard_query: bridge_challenge,
                    point: right_point,
                    value: sumcheck.wire_proof.terminal_right,
                    coefficient: Fp16::ONE,
                },
                &mut input_claims,
            );
            layer_proofs.push(UniformRelayFreeGkrLayerProof {
                keccak_round: round,
                layer: layer_index,
                incoming_claims: incoming,
                effective_claims,
                bridge_message: bridge,
                bridge_challenge,
                group_challenges,
                wire_challenges,
                sumcheck,
                terminal_challenge: terminal_outputs[0],
            });
        }
    }
    if rounds.len() != GKR_TRANSCRIPT_ROUNDS as usize
        || layer_proofs.len() != 168
        || input_claims.len() != 4
        || input_claims.iter().any(|claim| claim.value != Fp16::ZERO)
    {
        return Err(UniformRelayFreeGkrError::Schedule);
    }
    Ok(UniformRelayFreeGkrProof {
        output_claim,
        input_claims,
        layers: layer_proofs,
        rounds,
    })
}

/// Produce the native Libra-masked real-DAG transcript. The supplied
/// commitment must bind `mask_coefficients` before the output-query challenge.
pub fn prove_masked_uniform_zero_trace(
    mask_commitment: [u8; 64],
    mask_coefficients: &[Fp16],
    mut coin: impl FnMut(
        SelectedGkrRoundKind,
        &[u8],
        u16,
    ) -> Result<Vec<Fp16>, UniformRelayFreeGkrError>,
) -> Result<MaskedUniformRelayFreeGkrProof, UniformRelayFreeGkrError> {
    let layout = selected_gkr_mask_layout().map_err(|_| UniformRelayFreeGkrError::Shape)?;
    if mask_coefficients.len() != layout.padded_coefficients {
        return Err(UniformRelayFreeGkrError::Shape);
    }
    let (bridge_masks, sumcheck_masks, layer_masks) = layout
        .decode_prefix(mask_coefficients)
        .map_err(|_| UniformRelayFreeGkrError::Shape)?;
    let trace = build_zero_trace()?;
    let mut rounds = Vec::with_capacity(GKR_TRANSCRIPT_ROUNDS as usize);
    let output = request_round(
        &mut rounds,
        &mut coin,
        SelectedGkrRoundKind::OutputQuery,
        masked_output_query_message(&mask_commitment),
    )?;
    if output[25].is_zero() || output[26].is_zero() {
        return Err(UniformRelayFreeGkrError::Coin);
    }
    let raw_output_claim = UniformRelayFreeClaim {
        shard_query: output[0],
        point: output[1..25].to_vec(),
        value: multilinear_evaluate(&trace[23].boundaries[6], &output[1..12])?,
        coefficient: Fp16::ONE,
    };
    let mut carried_rhos = [output[25], output[26]];
    let mut pending = vec![vec![Vec::<MaskedPendingClaim>::new(); 8]; 24];
    pending[23][7].push(MaskedPendingClaim {
        raw: raw_output_claim.clone(),
        masked_value: raw_output_claim.value,
        mask_layer: None,
    });
    let mut raw_input_claims = Vec::with_capacity(4);
    let mut masked_input_values = Vec::with_capacity(4);
    let mut input_mask_layers = Vec::with_capacity(4);
    let mut layer_proofs = Vec::with_capacity(168);
    let mut proof_index = 0_usize;

    for round in (0..24).rev() {
        for layer_index in (0..7).rev() {
            let layer = &trace[round].layers[layer_index];
            let mut incoming = core::mem::take(&mut pending[round][layer_index + 1]);
            if incoming.is_empty() || incoming.len() > 4 {
                return Err(UniformRelayFreeGkrError::Shape);
            }
            let needs_mix = matches!(layer_index, 0 | 2 | 4) || (layer_index == 6 && round != 23);
            let rhos = if needs_mix {
                let outputs = request_round(
                    &mut rounds,
                    &mut coin,
                    SelectedGkrRoundKind::ClaimMix,
                    masked_claim_mix_message(round, layer_index, &incoming),
                )?;
                if outputs[0].is_zero() || outputs[1].is_zero() || outputs[2].is_zero() {
                    return Err(UniformRelayFreeGkrError::Coin);
                }
                let mut power = Fp16::ONE;
                for claim in &mut incoming {
                    claim.raw.coefficient = power;
                    power = power * outputs[0];
                }
                [outputs[1], outputs[2]]
            } else {
                if incoming.len() != 1 {
                    return Err(UniformRelayFreeGkrError::Shape);
                }
                incoming[0].raw.coefficient = Fp16::ONE;
                carried_rhos
            };

            let prior_correction = if incoming[0].mask_layer.is_none() {
                if incoming.iter().any(|claim| claim.mask_layer.is_some()) {
                    return Err(UniformRelayFreeGkrError::Shape);
                }
                LibraPriorLayerCorrection::zero()
            } else {
                let indexed = incoming
                    .iter()
                    .map(|claim| {
                        Ok((
                            claim.mask_layer.ok_or(UniformRelayFreeGkrError::Shape)?,
                            claim.raw.coefficient,
                            claim.raw.point.clone(),
                        ))
                    })
                    .collect::<Result<Vec<_>, UniformRelayFreeGkrError>>()?;
                LibraPriorLayerCorrection::from_indexed_claims(&layer_masks, &indexed)
                    .map_err(map_mask_error)?
            };
            let raw_initial = incoming.iter().fold(Fp16::ZERO, |sum, claim| {
                sum + claim.raw.coefficient * claim.raw.value
            });
            let masked_initial = incoming.iter().fold(Fp16::ZERO, |sum, claim| {
                sum + claim.raw.coefficient * claim.masked_value
            });
            if raw_initial + prior_correction.boolean_sum() != masked_initial {
                return Err(UniformRelayFreeGkrError::Algebra);
            }

            let raw_claims = incoming
                .iter()
                .map(|claim| claim.raw.clone())
                .collect::<Vec<_>>();
            let left = source_values(&trace[round], layer.left_source);
            let right = source_values(&trace[round], layer.right_source);
            let raw_bridge = bridge_message(layer, left, right, &raw_claims)?;
            verify_packed_bridge_node_sum(&raw_claims, &raw_bridge)?;
            let mut public_bridge = raw_bridge;
            for claim in &incoming {
                let selector = packed_selector_polynomial(claim.raw.shard_query);
                let correction = claim.raw.coefficient * (claim.masked_value - claim.raw.value);
                for (coefficient, selector) in public_bridge.iter_mut().zip(selector) {
                    *coefficient = *coefficient + correction * selector;
                }
            }
            for (coefficient, mask) in public_bridge.iter_mut().zip(&bridge_masks[proof_index]) {
                *coefficient = *coefficient + rhos[0] * *mask;
            }
            let bridge_outputs = request_round(
                &mut rounds,
                &mut coin,
                SelectedGkrRoundKind::PackedBridge,
                polynomial_message(
                    b"BL/PQ512/WAVE2/UNIFORM-REAL-GKR/MASKED-BRIDGE/v1\0",
                    &public_bridge,
                ),
            )?;
            let bridge_challenge = bridge_outputs[0];
            let output_values = layer_output_values(layer, left, right)?;
            let output_variables = layer.padded_width.trailing_zeros() as usize;
            let effective_claims = raw_claims
                .iter()
                .map(|claim| {
                    Ok(LayerOutputClaim {
                        point: claim.point.clone(),
                        value: multilinear_evaluate(
                            &output_values,
                            &claim.point[..output_variables],
                        )?,
                        coefficient: claim.coefficient
                            * selector_evaluation(claim.shard_query, bridge_challenge),
                    })
                })
                .collect::<Result<Vec<_>, UniformRelayFreeGkrError>>()?;
            if evaluate_message(&raw_bridge, bridge_challenge)
                != effective_claims.iter().fold(Fp16::ZERO, |sum, claim| {
                    sum + claim.coefficient * claim.value
                })
            {
                return Err(UniformRelayFreeGkrError::Algebra);
            }
            let effective_prior = if incoming[0].mask_layer.is_none() {
                LibraPriorLayerCorrection::zero()
            } else {
                let indexed = incoming
                    .iter()
                    .zip(&effective_claims)
                    .map(|(incoming, effective)| {
                        Ok((
                            incoming.mask_layer.ok_or(UniformRelayFreeGkrError::Shape)?,
                            effective.coefficient,
                            effective.point.clone(),
                        ))
                    })
                    .collect::<Result<Vec<_>, UniformRelayFreeGkrError>>()?;
                LibraPriorLayerCorrection::from_indexed_claims(&layer_masks, &indexed)
                    .map_err(map_mask_error)?
            };

            let terminal_outputs = core::cell::RefCell::new(None::<Vec<Fp16>>);
            let transcript = core::cell::RefCell::new((&mut rounds, &mut coin));
            let reduction = prove_masked_shared_group_dag_layer_interactive(
                layer,
                GROUP_COUNT,
                left,
                right,
                &effective_claims,
                &effective_prior,
                &sumcheck_masks[proof_index],
                &layer_masks[proof_index],
                rhos[1],
                |kind, _, published| {
                    let selected = match kind {
                        SharedGroupDagRoundKind::Group => SelectedGkrRoundKind::SharedGroup,
                        SharedGroupDagRoundKind::LeftWire | SharedGroupDagRoundKind::RightWire => {
                            SelectedGkrRoundKind::Wire
                        }
                    };
                    let mut transcript = transcript.borrow_mut();
                    let (rounds, coin) = &mut *transcript;
                    let outputs = request_round(
                        rounds,
                        coin,
                        selected,
                        polynomial_message(
                            b"BL/PQ512/WAVE2/UNIFORM-REAL-GKR/MASKED-SUMCHECK/v1\0",
                            published,
                        ),
                    )
                    .map_err(|_| crate::gkr_zk_mask::GkrZkMaskError::Sequence)?;
                    Ok(outputs[0])
                },
                |published, terminal_left, terminal_right| {
                    let mut message = polynomial_message(
                        b"BL/PQ512/WAVE2/UNIFORM-REAL-GKR/MASKED-TERMINAL/v1\0",
                        published,
                    );
                    append_field(&mut message, terminal_left);
                    append_field(&mut message, terminal_right);
                    let mut transcript = transcript.borrow_mut();
                    let (rounds, coin) = &mut *transcript;
                    let outputs =
                        request_round(rounds, coin, SelectedGkrRoundKind::Terminal, message)
                            .map_err(|_| crate::gkr_zk_mask::GkrZkMaskError::Sequence)?;
                    let challenge = outputs[0];
                    *terminal_outputs.borrow_mut() = Some(outputs);
                    Ok(challenge)
                },
            )
            .map_err(map_mask_error)?;
            let terminal_outputs = terminal_outputs
                .into_inner()
                .ok_or(UniformRelayFreeGkrError::Schedule)?;
            let left_variables = layer.left_width.trailing_zeros() as usize;
            if terminal_outputs.len() == 3 {
                if terminal_outputs[1].is_zero() || terminal_outputs[2].is_zero() {
                    return Err(UniformRelayFreeGkrError::Coin);
                }
                carried_rhos = [terminal_outputs[1], terminal_outputs[2]];
            }

            let outgoing = [
                (
                    layer.left_source,
                    reduction.raw_terminal_left,
                    reduction.masked_terminal_left,
                    reduction.wire_challenges[..left_variables]
                        .iter()
                        .chain(&reduction.group_challenges)
                        .copied()
                        .collect(),
                ),
                (
                    layer.right_source,
                    reduction.raw_terminal_right,
                    reduction.masked_terminal_right,
                    reduction.wire_challenges[left_variables..]
                        .iter()
                        .chain(&reduction.group_challenges)
                        .copied()
                        .collect(),
                ),
            ];
            for (source, raw_value, masked_value, point) in outgoing {
                let claim = MaskedPendingClaim {
                    raw: UniformRelayFreeClaim {
                        shard_query: bridge_challenge,
                        point,
                        value: raw_value,
                        coefficient: Fp16::ONE,
                    },
                    masked_value,
                    mask_layer: Some(proof_index),
                };
                match source {
                    KeccakDagSource::Layer(index) => {
                        pending[round][index + 1].push(claim);
                    }
                    KeccakDagSource::RoundInput if round > 0 => {
                        pending[round - 1][7].push(claim);
                    }
                    KeccakDagSource::RoundInput => {
                        raw_input_claims.push(claim.raw);
                        masked_input_values.push(claim.masked_value);
                        input_mask_layers
                            .push(claim.mask_layer.ok_or(UniformRelayFreeGkrError::Shape)?);
                    }
                }
            }
            layer_proofs.push(MaskedUniformRelayFreeGkrLayerProof {
                keccak_round: round,
                layer: layer_index,
                incoming_raw_claims: raw_claims,
                incoming_masked_values: incoming.iter().map(|claim| claim.masked_value).collect(),
                incoming_mask_layers: incoming.iter().map(|claim| claim.mask_layer).collect(),
                bridge_rho: rhos[0],
                sumcheck_rho: rhos[1],
                raw_bridge,
                public_bridge,
                bridge_challenge,
                reduction,
            });
            proof_index += 1;
        }
    }
    if proof_index != 168
        || rounds.len() != GKR_TRANSCRIPT_ROUNDS as usize
        || raw_input_claims.len() != 4
        || raw_input_claims
            .iter()
            .any(|claim| claim.value != Fp16::ZERO)
    {
        return Err(UniformRelayFreeGkrError::Schedule);
    }
    Ok(MaskedUniformRelayFreeGkrProof {
        mask_commitment,
        raw_output_claim,
        raw_input_claims,
        masked_input_values,
        input_mask_layers,
        layers: layer_proofs,
        rounds,
    })
}

/// Produce the same native-masked transcript from an untrusted nonuniform
/// source oracle. The returned boundary claims must subsequently be bound to
/// the selected PCS in the same atomic coordinator.
pub fn prove_masked_nonuniform_trace(
    mask_commitment: [u8; 64],
    mask_coefficients: &[Fp16],
    statement_binding: [u8; 64],
    oracle: &mut dyn NonuniformRelayFreeGkrOracle,
    mut coin: impl FnMut(
        SelectedGkrRoundKind,
        &[u8],
        u16,
    ) -> Result<Vec<Fp16>, UniformRelayFreeGkrError>,
) -> Result<MaskedUniformRelayFreeGkrProof, UniformRelayFreeGkrError> {
    let layout = selected_gkr_mask_layout().map_err(|_| UniformRelayFreeGkrError::Shape)?;
    if mask_coefficients.len() != layout.padded_coefficients {
        return Err(UniformRelayFreeGkrError::Shape);
    }
    let (bridge_masks, sumcheck_masks, layer_masks) = layout
        .decode_prefix(mask_coefficients)
        .map_err(|_| UniformRelayFreeGkrError::Shape)?;
    let topologies = (0..24)
        .map(|round| build_keccak_gkr_dag_round(round).map_err(|_| UniformRelayFreeGkrError::Trace))
        .collect::<Result<Vec<_>, _>>()?;
    let mut rounds = Vec::with_capacity(GKR_TRANSCRIPT_ROUNDS as usize);
    let output = request_round(
        &mut rounds,
        &mut coin,
        SelectedGkrRoundKind::OutputQuery,
        masked_nonuniform_output_query_message(&mask_commitment, &statement_binding),
    )?;
    if output[25].is_zero() || output[26].is_zero() {
        return Err(UniformRelayFreeGkrError::Coin);
    }
    let raw_output_claim = UniformRelayFreeClaim {
        shard_query: output[0],
        point: output[1..25].to_vec(),
        value: oracle.output_claim(output[0], &output[1..25])?,
        coefficient: Fp16::ONE,
    };
    let mut carried_rhos = [output[25], output[26]];
    let mut pending = vec![vec![Vec::<MaskedPendingClaim>::new(); 8]; 24];
    pending[23][7].push(MaskedPendingClaim {
        raw: raw_output_claim.clone(),
        masked_value: raw_output_claim.value,
        mask_layer: None,
    });
    let mut raw_input_claims = Vec::with_capacity(4);
    let mut masked_input_values = Vec::with_capacity(4);
    let mut input_mask_layers = Vec::with_capacity(4);
    let mut layer_proofs = Vec::with_capacity(168);
    let mut proof_index = 0_usize;

    for round in (0..24).rev() {
        for layer_index in (0..7).rev() {
            let layer = &topologies[round][layer_index];
            let mut incoming = core::mem::take(&mut pending[round][layer_index + 1]);
            if incoming.is_empty() || incoming.len() > 4 {
                return Err(UniformRelayFreeGkrError::Shape);
            }
            let needs_mix = matches!(layer_index, 0 | 2 | 4) || (layer_index == 6 && round != 23);
            let rhos = if needs_mix {
                let outputs = request_round(
                    &mut rounds,
                    &mut coin,
                    SelectedGkrRoundKind::ClaimMix,
                    masked_claim_mix_message(round, layer_index, &incoming),
                )?;
                if outputs[0].is_zero() || outputs[1].is_zero() || outputs[2].is_zero() {
                    return Err(UniformRelayFreeGkrError::Coin);
                }
                let mut power = Fp16::ONE;
                for claim in &mut incoming {
                    claim.raw.coefficient = power;
                    power = power * outputs[0];
                }
                [outputs[1], outputs[2]]
            } else {
                if incoming.len() != 1 {
                    return Err(UniformRelayFreeGkrError::Shape);
                }
                incoming[0].raw.coefficient = Fp16::ONE;
                carried_rhos
            };

            let prior_correction = if incoming[0].mask_layer.is_none() {
                if incoming.iter().any(|claim| claim.mask_layer.is_some()) {
                    return Err(UniformRelayFreeGkrError::Shape);
                }
                LibraPriorLayerCorrection::zero()
            } else {
                let indexed = incoming
                    .iter()
                    .map(|claim| {
                        Ok((
                            claim.mask_layer.ok_or(UniformRelayFreeGkrError::Shape)?,
                            claim.raw.coefficient,
                            claim.raw.point.clone(),
                        ))
                    })
                    .collect::<Result<Vec<_>, UniformRelayFreeGkrError>>()?;
                LibraPriorLayerCorrection::from_indexed_claims(&layer_masks, &indexed)
                    .map_err(map_mask_error)?
            };
            let raw_initial = incoming.iter().fold(Fp16::ZERO, |sum, claim| {
                sum + claim.raw.coefficient * claim.raw.value
            });
            let masked_initial = incoming.iter().fold(Fp16::ZERO, |sum, claim| {
                sum + claim.raw.coefficient * claim.masked_value
            });
            if raw_initial + prior_correction.boolean_sum() != masked_initial {
                return Err(UniformRelayFreeGkrError::Algebra);
            }

            let raw_claims = incoming
                .iter()
                .map(|claim| claim.raw.clone())
                .collect::<Vec<_>>();
            let raw_bridge = oracle.begin_layer(round, layer_index, layer, &raw_claims)?;
            verify_packed_bridge_node_sum(&raw_claims, &raw_bridge)?;
            let mut public_bridge = raw_bridge;
            for claim in &incoming {
                let selector = packed_selector_polynomial(claim.raw.shard_query);
                let correction = claim.raw.coefficient * (claim.masked_value - claim.raw.value);
                for (coefficient, selector) in public_bridge.iter_mut().zip(selector) {
                    *coefficient = *coefficient + correction * selector;
                }
            }
            for (coefficient, mask) in public_bridge.iter_mut().zip(&bridge_masks[proof_index]) {
                *coefficient = *coefficient + rhos[0] * *mask;
            }
            let bridge_outputs = request_round(
                &mut rounds,
                &mut coin,
                SelectedGkrRoundKind::PackedBridge,
                polynomial_message(
                    b"BL/PQ512/WAVE2/UNIFORM-REAL-GKR/MASKED-BRIDGE/v1\0",
                    &public_bridge,
                ),
            )?;
            let bridge_challenge = bridge_outputs[0];
            oracle.accept_bridge_challenge(bridge_challenge)?;
            let output_variables = layer.padded_width.trailing_zeros() as usize;
            let mut effective_claims = raw_claims
                .iter()
                .map(|claim| LayerOutputClaim {
                    point: claim.point.clone(),
                    value: Fp16::ZERO,
                    coefficient: claim.coefficient
                        * selector_evaluation(claim.shard_query, bridge_challenge),
                })
                .collect::<Vec<_>>();
            let combined = evaluate_message(&raw_bridge, bridge_challenge);
            let carrier = effective_claims
                .iter()
                .position(|claim| !claim.coefficient.is_zero())
                .ok_or(UniformRelayFreeGkrError::Algebra)?;
            effective_claims[carrier].value = combined
                * effective_claims[carrier]
                    .coefficient
                    .inverse()
                    .map_err(|_| UniformRelayFreeGkrError::Algebra)?;
            if effective_claims.iter().any(|claim| {
                claim.point.len() != output_variables + GROUP_COUNT.trailing_zeros() as usize
            }) {
                return Err(UniformRelayFreeGkrError::Shape);
            }
            if combined
                != effective_claims.iter().fold(Fp16::ZERO, |sum, claim| {
                    sum + claim.coefficient * claim.value
                })
            {
                return Err(UniformRelayFreeGkrError::Algebra);
            }
            let effective_prior = if incoming[0].mask_layer.is_none() {
                LibraPriorLayerCorrection::zero()
            } else {
                let indexed = incoming
                    .iter()
                    .zip(&effective_claims)
                    .map(|(incoming, effective)| {
                        Ok((
                            incoming.mask_layer.ok_or(UniformRelayFreeGkrError::Shape)?,
                            effective.coefficient,
                            effective.point.clone(),
                        ))
                    })
                    .collect::<Result<Vec<_>, UniformRelayFreeGkrError>>()?;
                LibraPriorLayerCorrection::from_indexed_claims(&layer_masks, &indexed)
                    .map_err(map_mask_error)?
            };

            let terminal_outputs = core::cell::RefCell::new(None::<Vec<Fp16>>);
            let transcript = core::cell::RefCell::new((&mut rounds, &mut coin));
            let reduction = prove_masked_shared_group_dag_layer_oracle_interactive(
                layer,
                GROUP_COUNT,
                oracle,
                &effective_claims,
                &effective_prior,
                &sumcheck_masks[proof_index],
                &layer_masks[proof_index],
                rhos[1],
                |kind, _, published| {
                    let selected = match kind {
                        SharedGroupDagRoundKind::Group => SelectedGkrRoundKind::SharedGroup,
                        SharedGroupDagRoundKind::LeftWire | SharedGroupDagRoundKind::RightWire => {
                            SelectedGkrRoundKind::Wire
                        }
                    };
                    let mut transcript = transcript.borrow_mut();
                    let (rounds, coin) = &mut *transcript;
                    let outputs = request_round(
                        rounds,
                        coin,
                        selected,
                        polynomial_message(
                            b"BL/PQ512/WAVE2/UNIFORM-REAL-GKR/MASKED-SUMCHECK/v1\0",
                            published,
                        ),
                    )
                    .map_err(|_| crate::gkr_zk_mask::GkrZkMaskError::Sequence)?;
                    Ok(outputs[0])
                },
                |published, terminal_left, terminal_right| {
                    let mut message = polynomial_message(
                        b"BL/PQ512/WAVE2/UNIFORM-REAL-GKR/MASKED-TERMINAL/v1\0",
                        published,
                    );
                    append_field(&mut message, terminal_left);
                    append_field(&mut message, terminal_right);
                    let mut transcript = transcript.borrow_mut();
                    let (rounds, coin) = &mut *transcript;
                    let outputs =
                        request_round(rounds, coin, SelectedGkrRoundKind::Terminal, message)
                            .map_err(|_| crate::gkr_zk_mask::GkrZkMaskError::Sequence)?;
                    let challenge = outputs[0];
                    *terminal_outputs.borrow_mut() = Some(outputs);
                    Ok(challenge)
                },
            )
            .map_err(map_mask_error)?;
            let terminal_outputs = terminal_outputs
                .into_inner()
                .ok_or(UniformRelayFreeGkrError::Schedule)?;
            if terminal_outputs.len() == 3 {
                if terminal_outputs[1].is_zero() || terminal_outputs[2].is_zero() {
                    return Err(UniformRelayFreeGkrError::Coin);
                }
                carried_rhos = [terminal_outputs[1], terminal_outputs[2]];
            }

            let left_variables = layer.left_width.trailing_zeros() as usize;
            let outgoing = [
                (
                    layer.left_source,
                    reduction.raw_terminal_left,
                    reduction.masked_terminal_left,
                    reduction.wire_challenges[..left_variables]
                        .iter()
                        .chain(&reduction.group_challenges)
                        .copied()
                        .collect(),
                ),
                (
                    layer.right_source,
                    reduction.raw_terminal_right,
                    reduction.masked_terminal_right,
                    reduction.wire_challenges[left_variables..]
                        .iter()
                        .chain(&reduction.group_challenges)
                        .copied()
                        .collect(),
                ),
            ];
            for (source, raw_value, masked_value, point) in outgoing {
                let claim = MaskedPendingClaim {
                    raw: UniformRelayFreeClaim {
                        shard_query: bridge_challenge,
                        point,
                        value: raw_value,
                        coefficient: Fp16::ONE,
                    },
                    masked_value,
                    mask_layer: Some(proof_index),
                };
                match source {
                    KeccakDagSource::Layer(index) => {
                        pending[round][index + 1].push(claim);
                    }
                    KeccakDagSource::RoundInput if round > 0 => {
                        pending[round - 1][7].push(claim);
                    }
                    KeccakDagSource::RoundInput => {
                        raw_input_claims.push(claim.raw);
                        masked_input_values.push(claim.masked_value);
                        input_mask_layers
                            .push(claim.mask_layer.ok_or(UniformRelayFreeGkrError::Shape)?);
                    }
                }
            }
            layer_proofs.push(MaskedUniformRelayFreeGkrLayerProof {
                keccak_round: round,
                layer: layer_index,
                incoming_raw_claims: raw_claims,
                incoming_masked_values: incoming.iter().map(|claim| claim.masked_value).collect(),
                incoming_mask_layers: incoming.iter().map(|claim| claim.mask_layer).collect(),
                bridge_rho: rhos[0],
                sumcheck_rho: rhos[1],
                raw_bridge,
                public_bridge,
                bridge_challenge,
                reduction,
            });
            proof_index += 1;
        }
    }
    if proof_index != 168
        || rounds.len() != GKR_TRANSCRIPT_ROUNDS as usize
        || raw_input_claims.len() != 4
        || pending
            .iter()
            .flat_map(|round| round.iter())
            .any(|claims| !claims.is_empty())
    {
        return Err(UniformRelayFreeGkrError::Schedule);
    }
    Ok(MaskedUniformRelayFreeGkrProof {
        mask_commitment,
        raw_output_claim,
        raw_input_claims,
        masked_input_values,
        input_mask_layers,
        layers: layer_proofs,
        rounds,
    })
}

fn reconstruct_terminal_gate(
    layer: &MaskedUniformRelayFreeGkrLayerProof,
    topology: &KeccakDagLayer,
) -> Result<Fp16, UniformRelayFreeGkrError> {
    let effective = layer
        .incoming_raw_claims
        .iter()
        .map(|claim| LayerOutputClaim {
            point: claim.point.clone(),
            value: Fp16::ZERO,
            coefficient: claim.coefficient
                * selector_evaluation(claim.shard_query, layer.bridge_challenge),
        })
        .collect::<Vec<_>>();
    shared_group_terminal_gate_claim(
        topology,
        GROUP_COUNT,
        &effective,
        &layer.reduction.group_challenges,
        &layer.reduction.wire_challenges,
        layer.reduction.masked_terminal_left,
        layer.reduction.masked_terminal_right,
    )
    .map_err(|_| UniformRelayFreeGkrError::Algebra)
}

fn reconstruct_terminal_gates(
    proof: &MaskedUniformRelayFreeGkrProof,
    topologies: &[[KeccakDagLayer; 7]],
) -> Result<Vec<Fp16>, UniformRelayFreeGkrError> {
    let evaluate_layer =
        |layer: &MaskedUniformRelayFreeGkrLayerProof| -> Result<Fp16, UniformRelayFreeGkrError> {
            let topology = topologies
                .get(layer.keccak_round)
                .and_then(|round| round.get(layer.layer))
                .ok_or(UniformRelayFreeGkrError::Shape)?;
            reconstruct_terminal_gate(layer, topology)
        };

    #[cfg(feature = "parallel")]
    {
        let worker_count = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
            .min(proof.layers.len());
        let layers_per_worker = proof.layers.len().div_ceil(worker_count);
        let parts = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(worker_count);
            for worker in 0..worker_count {
                let start = worker * layers_per_worker;
                let end = (start + layers_per_worker).min(proof.layers.len());
                let layers = &proof.layers[start..end];
                let evaluate_layer = &evaluate_layer;
                handles.push(
                    scope.spawn(move || layers.iter().map(evaluate_layer).collect::<Vec<_>>()),
                );
            }
            handles
                .into_iter()
                .map(|handle| handle.join().map_err(|_| UniformRelayFreeGkrError::Trace))
                .collect::<Result<Vec<_>, _>>()
        })?;
        let mut gates = Vec::with_capacity(proof.layers.len());
        for part in parts {
            for gate in part {
                gates.push(gate?);
            }
        }
        Ok(gates)
    }

    #[cfg(not(feature = "parallel"))]
    proof.layers.iter().map(evaluate_layer).collect()
}

fn reconstruct_mask_constraints(
    proof: &MaskedUniformRelayFreeGkrProof,
) -> Result<Vec<UniformGkrMaskConstraint>, UniformRelayFreeGkrError> {
    if proof.layers.len() != 168
        || proof.raw_input_claims.len() != 4
        || proof.masked_input_values.len() != 4
        || proof.input_mask_layers.len() != 4
    {
        return Err(UniformRelayFreeGkrError::Shape);
    }
    let nodes = (0..16)
        .map(|node| {
            Ok(Fp16::from_m31(
                M31::from_canonical(node).map_err(|_| UniformRelayFreeGkrError::Shape)?,
            ))
        })
        .collect::<Result<Vec<_>, UniformRelayFreeGkrError>>()?;
    let topologies = (0..24)
        .map(|round| build_keccak_gkr_dag_round(round).map_err(|_| UniformRelayFreeGkrError::Trace))
        .collect::<Result<Vec<_>, _>>()?;
    let terminal_gates = reconstruct_terminal_gates(proof, topologies.as_ref())?;
    let mut constraints = Vec::with_capacity(3 * proof.layers.len() + 4);
    for (proof_index, layer) in proof.layers.iter().enumerate() {
        let masked_initial = layer
            .incoming_raw_claims
            .iter()
            .zip(&layer.incoming_masked_values)
            .fold(Fp16::ZERO, |sum, (claim, masked)| {
                sum + claim.coefficient * *masked
            });
        let public_node_sum = nodes.iter().copied().fold(Fp16::ZERO, |sum, node| {
            sum + polynomial_evaluation(&layer.public_bridge, node)
        });
        constraints.push(UniformGkrMaskConstraint {
            functionals: nodes
                .iter()
                .copied()
                .map(|point| UniformGkrMaskFunctional::BridgeEvaluation {
                    layer: proof_index,
                    point,
                    scale: layer.bridge_rho,
                })
                .collect(),
            residual: public_node_sum - masked_initial,
        });

        let first = layer
            .reduction
            .published_rounds
            .first()
            .ok_or(UniformRelayFreeGkrError::Shape)?;
        let first_sum =
            polynomial_evaluation(first, Fp16::ZERO) + polynomial_evaluation(first, Fp16::ONE);
        constraints.push(UniformGkrMaskConstraint {
            functionals: vec![
                UniformGkrMaskFunctional::SumcheckBooleanSum {
                    layer: proof_index,
                    scale: layer.sumcheck_rho,
                },
                UniformGkrMaskFunctional::BridgeEvaluation {
                    layer: proof_index,
                    point: layer.bridge_challenge,
                    scale: -layer.bridge_rho,
                },
            ],
            residual: first_sum
                - polynomial_evaluation(&layer.public_bridge, layer.bridge_challenge),
        });

        let effective = layer
            .incoming_raw_claims
            .iter()
            .map(|claim| LayerOutputClaim {
                point: claim.point.clone(),
                value: Fp16::ZERO,
                coefficient: claim.coefficient
                    * selector_evaluation(claim.shard_query, layer.bridge_challenge),
            })
            .collect::<Vec<_>>();
        let mut xy_point = layer.reduction.group_challenges.clone();
        xy_point.extend_from_slice(&layer.reduction.wire_challenges);
        let equality_zero = xy_point.iter().fold(Fp16::ONE, |value, coordinate| {
            value * (Fp16::ONE - *coordinate)
        });
        let mut full_point = xy_point.clone();
        full_point.push(layer.reduction.w_challenge);
        let mut functionals = vec![UniformGkrMaskFunctional::SumcheckEvaluation {
            layer: proof_index,
            point: full_point,
            scale: layer.sumcheck_rho,
        }];
        for ((effective, origin), incoming) in effective
            .iter()
            .zip(&layer.incoming_mask_layers)
            .zip(&layer.incoming_raw_claims)
        {
            if let Some(origin) = origin {
                functionals.push(UniformGkrMaskFunctional::LayerEvaluation {
                    layer: *origin,
                    z_first: incoming.point[0],
                    w: layer.reduction.w_challenge,
                    scale: equality_zero
                        * effective.coefficient
                        * boolean_vanishing(&incoming.point),
                });
            }
        }
        let terminal_gate = terminal_gates[proof_index];
        let last = layer
            .reduction
            .published_rounds
            .last()
            .ok_or(UniformRelayFreeGkrError::Shape)?;
        constraints.push(UniformGkrMaskConstraint {
            functionals,
            residual: polynomial_evaluation(last, layer.reduction.w_challenge)
                - (Fp16::ONE - layer.reduction.w_challenge) * terminal_gate,
        });
    }
    for ((raw, masked), origin) in proof
        .raw_input_claims
        .iter()
        .zip(&proof.masked_input_values)
        .zip(&proof.input_mask_layers)
    {
        constraints.push(UniformGkrMaskConstraint {
            functionals: vec![UniformGkrMaskFunctional::LayerBooleanSum {
                layer: *origin,
                z_first: raw.point[0],
                scale: boolean_vanishing(&raw.point),
            }],
            residual: *masked - raw.value,
        });
    }
    Ok(constraints)
}

fn mask_batch_message(constraints: &[UniformGkrMaskConstraint]) -> Vec<u8> {
    let mut message = b"BL/PQ512/WAVE2/GKR-MASK-BATCH/v1\0".to_vec();
    message.extend_from_slice(&(constraints.len() as u32).to_be_bytes());
    for constraint in constraints {
        append_field(&mut message, constraint.residual);
        message.extend_from_slice(&(constraint.functionals.len() as u16).to_be_bytes());
        for functional in &constraint.functionals {
            match functional {
                UniformGkrMaskFunctional::BridgeEvaluation {
                    layer,
                    point,
                    scale,
                } => {
                    message.push(0);
                    message.extend_from_slice(&(*layer as u32).to_be_bytes());
                    append_field(&mut message, *point);
                    append_field(&mut message, *scale);
                }
                UniformGkrMaskFunctional::SumcheckBooleanSum { layer, scale } => {
                    message.push(1);
                    message.extend_from_slice(&(*layer as u32).to_be_bytes());
                    append_field(&mut message, *scale);
                }
                UniformGkrMaskFunctional::SumcheckEvaluation {
                    layer,
                    point,
                    scale,
                } => {
                    message.push(2);
                    message.extend_from_slice(&(*layer as u32).to_be_bytes());
                    message.extend_from_slice(&(point.len() as u16).to_be_bytes());
                    for coordinate in point {
                        append_field(&mut message, *coordinate);
                    }
                    append_field(&mut message, *scale);
                }
                UniformGkrMaskFunctional::LayerEvaluation {
                    layer,
                    z_first,
                    w,
                    scale,
                } => {
                    message.push(3);
                    message.extend_from_slice(&(*layer as u32).to_be_bytes());
                    append_field(&mut message, *z_first);
                    append_field(&mut message, *w);
                    append_field(&mut message, *scale);
                }
                UniformGkrMaskFunctional::LayerBooleanSum {
                    layer,
                    z_first,
                    scale,
                } => {
                    message.push(4);
                    message.extend_from_slice(&(*layer as u32).to_be_bytes());
                    append_field(&mut message, *z_first);
                    append_field(&mut message, *scale);
                }
            }
        }
    }
    message
}

/// Append the independent aggregate mask-functional challenge and return the
/// exact committed-mask opening that downstream PCS must bind.
pub fn complete_uniform_gkr_mask_batch(
    proof: &mut MaskedUniformRelayFreeGkrProof,
    mask_coefficients: &[Fp16],
    mut coin: impl FnMut(
        SelectedGkrRoundKind,
        &[u8],
        u16,
    ) -> Result<Vec<Fp16>, UniformRelayFreeGkrError>,
) -> Result<UniformGkrMaskBatch, UniformRelayFreeGkrError> {
    let layout = selected_gkr_mask_layout().map_err(|_| UniformRelayFreeGkrError::Shape)?;
    if proof.rounds.len() != GKR_TRANSCRIPT_ROUNDS as usize
        || mask_coefficients.len() != layout.padded_coefficients
    {
        return Err(UniformRelayFreeGkrError::Shape);
    }
    let constraints = reconstruct_mask_constraints(proof)?;
    let outputs = request_round(
        &mut proof.rounds,
        &mut coin,
        SelectedGkrRoundKind::MaskBatch,
        mask_batch_message(&constraints),
    )?;
    let challenge = outputs[0];
    if challenge.is_zero() {
        return Err(UniformRelayFreeGkrError::Coin);
    }
    let (coefficient_weights, opening) =
        aggregate_mask_constraints(&layout, &constraints, challenge)?;
    let actual = inner_product(mask_coefficients, &coefficient_weights)
        .map_err(|_| UniformRelayFreeGkrError::Shape)?;
    if actual != opening {
        return Err(UniformRelayFreeGkrError::Algebra);
    }
    Ok(UniformGkrMaskBatch {
        challenge,
        opening,
        coefficient_weights,
        constraints,
    })
}

fn aggregate_mask_constraints(
    layout: &crate::gkr_zk_mask::CompleteGkrZkMaskCommitmentLayout,
    constraints: &[UniformGkrMaskConstraint],
    challenge: Fp16,
) -> Result<(Vec<Fp16>, Fp16), UniformRelayFreeGkrError> {
    if challenge.is_zero() {
        return Err(UniformRelayFreeGkrError::Coin);
    }
    let mut coefficient_weights = vec![Fp16::ZERO; layout.padded_coefficients];
    let mut opening = Fp16::ZERO;
    let mut power = Fp16::ONE;
    for constraint in constraints {
        for functional in &constraint.functionals {
            match functional {
                UniformGkrMaskFunctional::BridgeEvaluation {
                    layer,
                    point,
                    scale,
                } => layout
                    .accumulate_bridge_evaluation(
                        &mut coefficient_weights,
                        *layer,
                        *point,
                        power * *scale,
                    )
                    .map_err(|_| UniformRelayFreeGkrError::Shape)?,
                UniformGkrMaskFunctional::SumcheckBooleanSum { layer, scale } => layout
                    .accumulate_sumcheck_boolean_sum(
                        &mut coefficient_weights,
                        *layer,
                        power * *scale,
                    )
                    .map_err(|_| UniformRelayFreeGkrError::Shape)?,
                UniformGkrMaskFunctional::SumcheckEvaluation {
                    layer,
                    point,
                    scale,
                } => layout
                    .accumulate_sumcheck_evaluation(
                        &mut coefficient_weights,
                        *layer,
                        point,
                        power * *scale,
                    )
                    .map_err(|_| UniformRelayFreeGkrError::Shape)?,
                UniformGkrMaskFunctional::LayerEvaluation {
                    layer,
                    z_first,
                    w,
                    scale,
                } => layout
                    .accumulate_layer_evaluation(
                        &mut coefficient_weights,
                        *layer,
                        *z_first,
                        *w,
                        power * *scale,
                    )
                    .map_err(|_| UniformRelayFreeGkrError::Shape)?,
                UniformGkrMaskFunctional::LayerBooleanSum {
                    layer,
                    z_first,
                    scale,
                } => layout
                    .accumulate_layer_boolean_w_sum(
                        &mut coefficient_weights,
                        *layer,
                        *z_first,
                        power * *scale,
                    )
                    .map_err(|_| UniformRelayFreeGkrError::Shape)?,
            }
        }
        opening = opening + power * constraint.residual;
        power = power * challenge;
    }
    Ok((coefficient_weights, opening))
}

/// Reconstruct the aggregate mask functional without access to committed mask
/// coefficients. Downstream PCS must separately verify `batch.opening`.
pub fn verify_uniform_gkr_mask_batch(
    proof: &MaskedUniformRelayFreeGkrProof,
    batch: &UniformGkrMaskBatch,
) -> Result<(), UniformRelayFreeGkrError> {
    if proof.rounds.len() != GKR_TRANSCRIPT_ROUNDS as usize + 1
        || proof.rounds.last().is_none_or(|round| {
            round.kind != SelectedGkrRoundKind::MaskBatch
                || round.outputs.as_slice() != [batch.challenge]
        })
        || batch.challenge.is_zero()
    {
        return Err(UniformRelayFreeGkrError::Schedule);
    }
    let constraints = reconstruct_mask_constraints(proof)?;
    if constraints != batch.constraints
        || proof.rounds.last().unwrap().message != mask_batch_message(&constraints)
    {
        return Err(UniformRelayFreeGkrError::Algebra);
    }
    let layout = selected_gkr_mask_layout().map_err(|_| UniformRelayFreeGkrError::Shape)?;
    let (weights, opening) = aggregate_mask_constraints(&layout, &constraints, batch.challenge)?;
    if weights != batch.coefficient_weights || opening != batch.opening {
        return Err(UniformRelayFreeGkrError::Algebra);
    }
    Ok(())
}

/// Independently verify the native-masked real-DAG transcript, its raw trace
/// boundary, and the aggregate committed-mask opening statement. This verifier
/// never reads the prover's mask coefficients or private base polynomials.
pub fn verify_masked_uniform_zero_trace(
    proof: &MaskedUniformRelayFreeGkrProof,
    batch: &UniformGkrMaskBatch,
) -> Result<(), UniformRelayFreeGkrError> {
    verify_masked_trace_internal(
        proof,
        batch,
        &masked_output_query_message(&proof.mask_commitment),
        true,
    )
}

/// Independently verify a nonuniform transcript without reading the private
/// source. The caller must additionally verify the returned output/input
/// claims against the atomically bound PCS boundary.
pub fn verify_masked_nonuniform_trace(
    proof: &MaskedUniformRelayFreeGkrProof,
    batch: &UniformGkrMaskBatch,
    expected_statement_binding: [u8; 64],
) -> Result<(), UniformRelayFreeGkrError> {
    verify_masked_trace_internal(
        proof,
        batch,
        &masked_nonuniform_output_query_message(
            &proof.mask_commitment,
            &expected_statement_binding,
        ),
        false,
    )
}

fn verify_masked_trace_internal(
    proof: &MaskedUniformRelayFreeGkrProof,
    batch: &UniformGkrMaskBatch,
    expected_output_message: &[u8],
    verify_uniform_source: bool,
) -> Result<(), UniformRelayFreeGkrError> {
    if proof.layers.len() != 168
        || proof.rounds.len() != GKR_TRANSCRIPT_ROUNDS as usize + 1
        || proof.raw_input_claims.len() != 4
        || proof.masked_input_values.len() != 4
        || proof.input_mask_layers.len() != 4
        || proof.raw_input_claims.iter().any(|claim| {
            (verify_uniform_source && claim.value != Fp16::ZERO)
                || claim.coefficient != Fp16::ONE
                || claim.point.len() != 24
        })
    {
        return Err(UniformRelayFreeGkrError::Shape);
    }
    for (ordinal, round) in proof.rounds.iter().enumerate() {
        if selected_gkr_round_kind(ordinal as u32) != Some(round.kind)
            || selected_gkr_round_output_count(ordinal as u32)
                != u16::try_from(round.outputs.len()).ok()
        {
            return Err(UniformRelayFreeGkrError::Schedule);
        }
    }

    let trace = if verify_uniform_source {
        Some(build_zero_trace()?)
    } else {
        None
    };
    let topologies = (0..24)
        .map(|round| build_keccak_gkr_dag_round(round).map_err(|_| UniformRelayFreeGkrError::Trace))
        .collect::<Result<Vec<_>, _>>()?;
    let output_record = &proof.rounds[0];
    if output_record.message != expected_output_message
        || output_record.outputs[25].is_zero()
        || output_record.outputs[26].is_zero()
        || proof.raw_output_claim.shard_query != output_record.outputs[0]
        || proof.raw_output_claim.point != output_record.outputs[1..25]
        || proof.raw_output_claim.coefficient != Fp16::ONE
        || (verify_uniform_source
            && proof.raw_output_claim.value
                != multilinear_evaluate(
                    &trace.as_ref().ok_or(UniformRelayFreeGkrError::Trace)?[23].boundaries[6],
                    &proof.raw_output_claim.point[..11],
                )?)
    {
        return Err(UniformRelayFreeGkrError::Trace);
    }

    let mut carried_rhos = [output_record.outputs[25], output_record.outputs[26]];
    let mut pending = vec![vec![Vec::<MaskedPendingClaim>::new(); 8]; 24];
    pending[23][7].push(MaskedPendingClaim {
        raw: proof.raw_output_claim.clone(),
        masked_value: proof.raw_output_claim.value,
        mask_layer: None,
    });
    let mut reconstructed_raw_inputs = Vec::with_capacity(4);
    let mut reconstructed_masked_inputs = Vec::with_capacity(4);
    let mut reconstructed_input_layers = Vec::with_capacity(4);
    let mut transcript_ordinal = 1_usize;
    let mut proof_index = 0_usize;

    for round in (0..24).rev() {
        for layer_index in (0..7).rev() {
            let layer_proof = proof
                .layers
                .get(proof_index)
                .ok_or(UniformRelayFreeGkrError::Shape)?;
            if layer_proof.keccak_round != round || layer_proof.layer != layer_index {
                return Err(UniformRelayFreeGkrError::Schedule);
            }
            let layer = &topologies[round][layer_index];
            let mut incoming = core::mem::take(&mut pending[round][layer_index + 1]);
            if incoming.is_empty() || incoming.len() > 4 {
                return Err(UniformRelayFreeGkrError::Shape);
            }
            let needs_mix = matches!(layer_index, 0 | 2 | 4) || (layer_index == 6 && round != 23);
            let rhos = if needs_mix {
                let record = proof
                    .rounds
                    .get(transcript_ordinal)
                    .ok_or(UniformRelayFreeGkrError::Schedule)?;
                transcript_ordinal += 1;
                if record.kind != SelectedGkrRoundKind::ClaimMix
                    || record.message != masked_claim_mix_message(round, layer_index, &incoming)
                    || record.outputs.iter().any(|value| value.is_zero())
                {
                    return Err(UniformRelayFreeGkrError::Schedule);
                }
                let mut power = Fp16::ONE;
                for claim in &mut incoming {
                    claim.raw.coefficient = power;
                    power = power * record.outputs[0];
                }
                [record.outputs[1], record.outputs[2]]
            } else {
                if incoming.len() != 1 {
                    return Err(UniformRelayFreeGkrError::Shape);
                }
                incoming[0].raw.coefficient = Fp16::ONE;
                carried_rhos
            };
            if layer_proof.incoming_raw_claims
                != incoming
                    .iter()
                    .map(|claim| claim.raw.clone())
                    .collect::<Vec<_>>()
                || layer_proof.incoming_masked_values
                    != incoming
                        .iter()
                        .map(|claim| claim.masked_value)
                        .collect::<Vec<_>>()
                || layer_proof.incoming_mask_layers
                    != incoming
                        .iter()
                        .map(|claim| claim.mask_layer)
                        .collect::<Vec<_>>()
                || layer_proof.bridge_rho != rhos[0]
                || layer_proof.sumcheck_rho != rhos[1]
            {
                return Err(UniformRelayFreeGkrError::Algebra);
            }

            verify_packed_bridge_node_sum(
                &layer_proof.incoming_raw_claims,
                &layer_proof.raw_bridge,
            )?;
            let bridge_record = proof
                .rounds
                .get(transcript_ordinal)
                .ok_or(UniformRelayFreeGkrError::Schedule)?;
            transcript_ordinal += 1;
            if bridge_record.kind != SelectedGkrRoundKind::PackedBridge
                || bridge_record.message
                    != polynomial_message(
                        b"BL/PQ512/WAVE2/UNIFORM-REAL-GKR/MASKED-BRIDGE/v1\0",
                        &layer_proof.public_bridge,
                    )
                || bridge_record.outputs[0] != layer_proof.bridge_challenge
            {
                return Err(UniformRelayFreeGkrError::Schedule);
            }
            if verify_uniform_source {
                let trace = trace.as_ref().ok_or(UniformRelayFreeGkrError::Trace)?;
                let left = source_values(&trace[round], layer.left_source);
                let right = source_values(&trace[round], layer.right_source);
                let expected_raw_bridge =
                    bridge_message(layer, left, right, &layer_proof.incoming_raw_claims)?;
                if layer_proof.raw_bridge != expected_raw_bridge {
                    return Err(UniformRelayFreeGkrError::Algebra);
                }
                let output_variables = layer.padded_width.trailing_zeros() as usize;
                let output_values = layer_output_values(layer, left, right)?;
                let effective = layer_proof
                    .incoming_raw_claims
                    .iter()
                    .map(|claim| {
                        Ok(LayerOutputClaim {
                            point: claim.point.clone(),
                            value: multilinear_evaluate(
                                &output_values,
                                &claim.point[..output_variables],
                            )?,
                            coefficient: claim.coefficient
                                * selector_evaluation(
                                    claim.shard_query,
                                    layer_proof.bridge_challenge,
                                ),
                        })
                    })
                    .collect::<Result<Vec<_>, UniformRelayFreeGkrError>>()?;
                if evaluate_message(&expected_raw_bridge, layer_proof.bridge_challenge)
                    != effective.iter().fold(Fp16::ZERO, |sum, claim| {
                        sum + claim.coefficient * claim.value
                    })
                {
                    return Err(UniformRelayFreeGkrError::Algebra);
                }
            }

            let reduction = &layer_proof.reduction;
            let group_variables = GROUP_COUNT.trailing_zeros() as usize;
            let left_variables = layer.left_width.trailing_zeros() as usize;
            let right_variables = layer.right_width.trailing_zeros() as usize;
            let ordinary_rounds = group_variables + left_variables + right_variables;
            if reduction.published_rounds.len() != ordinary_rounds + 1
                || reduction.group_challenges.len() != group_variables
                || reduction.wire_challenges.len() != left_variables + right_variables
                || reduction.w_published != reduction.published_rounds[ordinary_rounds]
            {
                return Err(UniformRelayFreeGkrError::Shape);
            }
            for round_index in 0..ordinary_rounds {
                let published = &reduction.published_rounds[round_index];
                let (kind, challenge) = if round_index < group_variables {
                    (
                        SelectedGkrRoundKind::SharedGroup,
                        reduction.group_challenges[round_index],
                    )
                } else {
                    (
                        SelectedGkrRoundKind::Wire,
                        reduction.wire_challenges[round_index - group_variables],
                    )
                };
                let record = proof
                    .rounds
                    .get(transcript_ordinal)
                    .ok_or(UniformRelayFreeGkrError::Schedule)?;
                transcript_ordinal += 1;
                if record.kind != kind
                    || record.message
                        != polynomial_message(
                            b"BL/PQ512/WAVE2/UNIFORM-REAL-GKR/MASKED-SUMCHECK/v1\0",
                            published,
                        )
                    || record.outputs[0] != challenge
                {
                    return Err(UniformRelayFreeGkrError::Schedule);
                }
                if round_index > 0 {
                    let previous = &reduction.published_rounds[round_index - 1];
                    let previous_challenge = if round_index - 1 < group_variables {
                        reduction.group_challenges[round_index - 1]
                    } else {
                        reduction.wire_challenges[round_index - 1 - group_variables]
                    };
                    if polynomial_evaluation(published, Fp16::ZERO)
                        + polynomial_evaluation(published, Fp16::ONE)
                        != polynomial_evaluation(previous, previous_challenge)
                    {
                        return Err(UniformRelayFreeGkrError::Algebra);
                    }
                }
            }
            let previous = &reduction.published_rounds[ordinary_rounds - 1];
            let previous_challenge =
                reduction.wire_challenges[left_variables + right_variables - 1];
            if polynomial_evaluation(&reduction.w_published, Fp16::ZERO)
                + polynomial_evaluation(&reduction.w_published, Fp16::ONE)
                != polynomial_evaluation(previous, previous_challenge)
            {
                return Err(UniformRelayFreeGkrError::Algebra);
            }
            let mut terminal_message = polynomial_message(
                b"BL/PQ512/WAVE2/UNIFORM-REAL-GKR/MASKED-TERMINAL/v1\0",
                &reduction.w_published,
            );
            append_field(&mut terminal_message, reduction.masked_terminal_left);
            append_field(&mut terminal_message, reduction.masked_terminal_right);
            let terminal_record = proof
                .rounds
                .get(transcript_ordinal)
                .ok_or(UniformRelayFreeGkrError::Schedule)?;
            transcript_ordinal += 1;
            if terminal_record.kind != SelectedGkrRoundKind::Terminal
                || terminal_record.message != terminal_message
                || terminal_record.outputs[0] != reduction.w_challenge
            {
                return Err(UniformRelayFreeGkrError::Schedule);
            }
            if terminal_record.outputs.len() == 3 {
                if terminal_record.outputs[1].is_zero() || terminal_record.outputs[2].is_zero() {
                    return Err(UniformRelayFreeGkrError::Coin);
                }
                carried_rhos = [terminal_record.outputs[1], terminal_record.outputs[2]];
            }

            let left_point = reduction.wire_challenges[..left_variables]
                .iter()
                .chain(&reduction.group_challenges)
                .copied()
                .collect::<Vec<_>>();
            let right_point = reduction.wire_challenges[left_variables..]
                .iter()
                .chain(&reduction.group_challenges)
                .copied()
                .collect::<Vec<_>>();
            if verify_uniform_source {
                let trace = trace.as_ref().ok_or(UniformRelayFreeGkrError::Trace)?;
                let left = source_values(&trace[round], layer.left_source);
                let right = source_values(&trace[round], layer.right_source);
                if reduction.raw_terminal_left
                    != multilinear_evaluate(left, &reduction.wire_challenges[..left_variables])?
                    || reduction.raw_terminal_right
                        != multilinear_evaluate(
                            right,
                            &reduction.wire_challenges[left_variables..],
                        )?
                {
                    return Err(UniformRelayFreeGkrError::Algebra);
                }
            }
            for (source, raw_value, masked_value, point) in [
                (
                    layer.left_source,
                    reduction.raw_terminal_left,
                    reduction.masked_terminal_left,
                    left_point,
                ),
                (
                    layer.right_source,
                    reduction.raw_terminal_right,
                    reduction.masked_terminal_right,
                    right_point,
                ),
            ] {
                let claim = MaskedPendingClaim {
                    raw: UniformRelayFreeClaim {
                        shard_query: layer_proof.bridge_challenge,
                        point,
                        value: raw_value,
                        coefficient: Fp16::ONE,
                    },
                    masked_value,
                    mask_layer: Some(proof_index),
                };
                match source {
                    KeccakDagSource::Layer(index) => pending[round][index + 1].push(claim),
                    KeccakDagSource::RoundInput if round > 0 => {
                        pending[round - 1][7].push(claim);
                    }
                    KeccakDagSource::RoundInput => {
                        reconstructed_raw_inputs.push(claim.raw);
                        reconstructed_masked_inputs.push(claim.masked_value);
                        reconstructed_input_layers
                            .push(claim.mask_layer.ok_or(UniformRelayFreeGkrError::Shape)?);
                    }
                }
            }
            proof_index += 1;
        }
    }
    if proof_index != proof.layers.len()
        || transcript_ordinal != GKR_TRANSCRIPT_ROUNDS as usize
        || reconstructed_raw_inputs != proof.raw_input_claims
        || reconstructed_masked_inputs != proof.masked_input_values
        || reconstructed_input_layers != proof.input_mask_layers
        || pending
            .iter()
            .flat_map(|round| round.iter())
            .any(|claims| !claims.is_empty())
    {
        return Err(UniformRelayFreeGkrError::Schedule);
    }
    verify_uniform_gkr_mask_batch(proof, batch)
}

/// Independently verify the raw algebra and exact transcript schedule.
pub fn verify_uniform_zero_trace(
    proof: &UniformRelayFreeGkrProof,
) -> Result<(), UniformRelayFreeGkrError> {
    if proof.layers.len() != 168
        || proof.rounds.len() != GKR_TRANSCRIPT_ROUNDS as usize
        || proof.input_claims.len() != 4
        || proof
            .input_claims
            .iter()
            .any(|claim| claim.value != Fp16::ZERO)
    {
        return Err(UniformRelayFreeGkrError::Shape);
    }
    for (ordinal, round) in proof.rounds.iter().enumerate() {
        if selected_gkr_round_kind(ordinal as u32) != Some(round.kind)
            || selected_gkr_round_output_count(ordinal as u32)
                != u16::try_from(round.outputs.len()).ok()
        {
            return Err(UniformRelayFreeGkrError::Schedule);
        }
    }
    let trace = build_zero_trace()?;
    if proof.rounds[0].message != output_query_message()
        || proof.output_claim.shard_query != proof.rounds[0].outputs[0]
        || proof.output_claim.point != proof.rounds[0].outputs[1..25]
        || proof.output_claim.value
            != multilinear_evaluate(&trace[23].boundaries[6], &proof.output_claim.point[..11])?
    {
        return Err(UniformRelayFreeGkrError::Trace);
    }
    let mut pending = vec![vec![Vec::<UniformRelayFreeClaim>::new(); 8]; 24];
    pending[23][7].push(proof.output_claim.clone());
    let mut reconstructed_inputs = Vec::with_capacity(4);
    let mut transcript_ordinal = 1_usize;
    let mut proof_index = 0_usize;
    for round in (0..24).rev() {
        for layer_index in (0..7).rev() {
            let layer_proof = proof
                .layers
                .get(proof_index)
                .ok_or(UniformRelayFreeGkrError::Shape)?;
            proof_index += 1;
            if layer_proof.keccak_round != round || layer_proof.layer != layer_index {
                return Err(UniformRelayFreeGkrError::Schedule);
            }
            let layer = &trace[round].layers[layer_index];
            let mut incoming = core::mem::take(&mut pending[round][layer_index + 1]);
            let needs_mix = matches!(layer_index, 0 | 2 | 4) || (layer_index == 6 && round != 23);
            if needs_mix {
                let record = proof
                    .rounds
                    .get(transcript_ordinal)
                    .ok_or(UniformRelayFreeGkrError::Schedule)?;
                transcript_ordinal += 1;
                if record.kind != SelectedGkrRoundKind::ClaimMix
                    || record.message != claim_mix_message(round, layer_index, &incoming)
                    || record.outputs[0].is_zero()
                {
                    return Err(UniformRelayFreeGkrError::Schedule);
                }
                let mut power = Fp16::ONE;
                for claim in &mut incoming {
                    claim.coefficient = power;
                    power = power * record.outputs[0];
                }
            } else {
                if incoming.len() != 1 {
                    return Err(UniformRelayFreeGkrError::Shape);
                }
                incoming[0].coefficient = Fp16::ONE;
            }
            if layer_proof.incoming_claims != incoming {
                return Err(UniformRelayFreeGkrError::Algebra);
            }

            let left = source_values(&trace[round], layer.left_source);
            let right = source_values(&trace[round], layer.right_source);
            let expected_bridge = bridge_message(layer, left, right, &incoming)?;
            let bridge_record = proof
                .rounds
                .get(transcript_ordinal)
                .ok_or(UniformRelayFreeGkrError::Schedule)?;
            transcript_ordinal += 1;
            if expected_bridge != layer_proof.bridge_message
                || bridge_record.kind != SelectedGkrRoundKind::PackedBridge
                || bridge_record.message
                    != polynomial_message(
                        b"BL/PQ512/WAVE2/UNIFORM-REAL-GKR/BRIDGE/v1\0",
                        &expected_bridge,
                    )
                || bridge_record.outputs[0] != layer_proof.bridge_challenge
            {
                return Err(UniformRelayFreeGkrError::Schedule);
            }
            let output_variables = layer.padded_width.trailing_zeros() as usize;
            let output_values = layer_output_values(layer, left, right)?;
            let effective_claims = incoming
                .iter()
                .map(|claim| {
                    Ok(LayerOutputClaim {
                        point: claim.point.clone(),
                        value: multilinear_evaluate(
                            &output_values,
                            &claim.point[..output_variables],
                        )?,
                        coefficient: claim.coefficient
                            * selector_evaluation(claim.shard_query, layer_proof.bridge_challenge),
                    })
                })
                .collect::<Result<Vec<_>, UniformRelayFreeGkrError>>()?;
            if layer_proof.effective_claims != effective_claims
                || evaluate_message(&layer_proof.bridge_message, layer_proof.bridge_challenge)
                    != effective_claims.iter().fold(Fp16::ZERO, |sum, claim| {
                        sum + claim.coefficient * claim.value
                    })
            {
                return Err(UniformRelayFreeGkrError::Algebra);
            }
            for (message, challenge) in layer_proof
                .sumcheck
                .group_rounds
                .iter()
                .zip(&layer_proof.group_challenges)
            {
                let record = proof
                    .rounds
                    .get(transcript_ordinal)
                    .ok_or(UniformRelayFreeGkrError::Schedule)?;
                transcript_ordinal += 1;
                if record.kind != SelectedGkrRoundKind::SharedGroup
                    || record.message
                        != polynomial_message(
                            b"BL/PQ512/WAVE2/UNIFORM-REAL-GKR/SUMCHECK/v1\0",
                            message,
                        )
                    || record.outputs[0] != *challenge
                {
                    return Err(UniformRelayFreeGkrError::Schedule);
                }
            }
            for (message, challenge) in layer_proof
                .sumcheck
                .wire_proof
                .rounds
                .iter()
                .zip(&layer_proof.wire_challenges)
            {
                let record = proof
                    .rounds
                    .get(transcript_ordinal)
                    .ok_or(UniformRelayFreeGkrError::Schedule)?;
                transcript_ordinal += 1;
                if record.kind != SelectedGkrRoundKind::Wire
                    || record.message
                        != polynomial_message(
                            b"BL/PQ512/WAVE2/UNIFORM-REAL-GKR/SUMCHECK/v1\0",
                            message,
                        )
                    || record.outputs[0] != *challenge
                {
                    return Err(UniformRelayFreeGkrError::Schedule);
                }
            }
            verify_shared_group_dag_layer_reference(
                layer,
                GROUP_COUNT,
                &effective_claims,
                &layer_proof.group_challenges,
                &layer_proof.wire_challenges,
                &layer_proof.sumcheck,
            )?;

            let mut terminal_claim =
                evaluate_message(&layer_proof.bridge_message, layer_proof.bridge_challenge);
            for (message, challenge) in layer_proof
                .sumcheck
                .group_rounds
                .iter()
                .zip(&layer_proof.group_challenges)
            {
                terminal_claim = message.iter().rev().fold(Fp16::ZERO, |value, coefficient| {
                    value * *challenge + *coefficient
                });
            }
            for (message, challenge) in layer_proof
                .sumcheck
                .wire_proof
                .rounds
                .iter()
                .zip(&layer_proof.wire_challenges)
            {
                terminal_claim = message.iter().rev().fold(Fp16::ZERO, |value, coefficient| {
                    value * *challenge + *coefficient
                });
            }
            let w_polynomial = [terminal_claim, -terminal_claim, Fp16::ZERO];
            let mut terminal_message = polynomial_message(
                b"BL/PQ512/WAVE2/UNIFORM-REAL-GKR/TERMINAL/v1\0",
                &w_polynomial,
            );
            append_field(
                &mut terminal_message,
                layer_proof.sumcheck.wire_proof.terminal_left,
            );
            append_field(
                &mut terminal_message,
                layer_proof.sumcheck.wire_proof.terminal_right,
            );
            let terminal_record = proof
                .rounds
                .get(transcript_ordinal)
                .ok_or(UniformRelayFreeGkrError::Schedule)?;
            transcript_ordinal += 1;
            if terminal_record.kind != SelectedGkrRoundKind::Terminal
                || terminal_record.message != terminal_message
                || terminal_record.outputs[0] != layer_proof.terminal_challenge
            {
                return Err(UniformRelayFreeGkrError::Schedule);
            }
            let left_variables = layer.left_width.trailing_zeros() as usize;
            push_source_claim(
                &mut pending,
                round,
                layer.left_source,
                UniformRelayFreeClaim {
                    shard_query: layer_proof.bridge_challenge,
                    point: layer_proof.wire_challenges[..left_variables]
                        .iter()
                        .chain(&layer_proof.group_challenges)
                        .copied()
                        .collect(),
                    value: layer_proof.sumcheck.wire_proof.terminal_left,
                    coefficient: Fp16::ONE,
                },
                &mut reconstructed_inputs,
            );
            push_source_claim(
                &mut pending,
                round,
                layer.right_source,
                UniformRelayFreeClaim {
                    shard_query: layer_proof.bridge_challenge,
                    point: layer_proof.wire_challenges[left_variables..]
                        .iter()
                        .chain(&layer_proof.group_challenges)
                        .copied()
                        .collect(),
                    value: layer_proof.sumcheck.wire_proof.terminal_right,
                    coefficient: Fp16::ONE,
                },
                &mut reconstructed_inputs,
            );
        }
    }
    if transcript_ordinal != proof.rounds.len()
        || reconstructed_inputs != proof.input_claims
        || pending
            .iter()
            .flat_map(|round| round.iter())
            .any(|claims| !claims.is_empty())
    {
        return Err(UniformRelayFreeGkrError::Schedule);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{M31, M31_MODULUS};

    #[derive(Clone)]
    struct DeterministicCoin {
        state: u64,
    }

    impl DeterministicCoin {
        fn challenge(
            &mut self,
            kind: SelectedGkrRoundKind,
            message: &[u8],
            output_count: u16,
        ) -> Vec<Fp16> {
            let tag = match kind {
                SelectedGkrRoundKind::OutputQuery => 1,
                SelectedGkrRoundKind::ClaimMix => 2,
                SelectedGkrRoundKind::PackedBridge => 3,
                SelectedGkrRoundKind::SharedGroup => 4,
                SelectedGkrRoundKind::Wire => 5,
                SelectedGkrRoundKind::Terminal => 6,
                SelectedGkrRoundKind::MaskBatch => 7,
            };
            for byte in message {
                self.state = self
                    .state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(u64::from(*byte) + tag);
            }
            (0..output_count)
                .map(|index| {
                    self.state = self
                        .state
                        .wrapping_mul(2_862_933_555_777_941_757)
                        .wrapping_add(3_037_000_493 + u64::from(index));
                    let value = ((self.state as u32) % (M31_MODULUS - 1)) + 1;
                    Fp16::from_m31(M31::from_canonical(value).unwrap())
                })
                .collect()
        }
    }

    #[test]
    fn real_uniform_zero_trace_produces_all_168_layers_and_6072_raw_rounds() {
        let mut coin = DeterministicCoin {
            state: 0x243f_6a88_85a3_08d3,
        };
        let proof = prove_uniform_zero_trace(|kind, message, output_count| {
            Ok(coin.challenge(kind, message, output_count))
        })
        .unwrap();
        verify_uniform_zero_trace(&proof).unwrap();
        assert_eq!(proof.layers.len(), 168);
        assert_eq!(proof.rounds.len(), 6_072);
        assert_eq!(proof.input_claims.len(), 4);
        for (kind, expected) in [
            (SelectedGkrRoundKind::OutputQuery, 1),
            (SelectedGkrRoundKind::ClaimMix, 95),
            (SelectedGkrRoundKind::PackedBridge, 168),
            (SelectedGkrRoundKind::SharedGroup, 2_184),
            (SelectedGkrRoundKind::Wire, 3_456),
            (SelectedGkrRoundKind::Terminal, 168),
        ] {
            assert_eq!(
                proof
                    .rounds
                    .iter()
                    .filter(|round| round.kind == kind)
                    .count(),
                expected
            );
        }

        let mut forged = proof.clone();
        forged.layers[0].sumcheck.group_rounds[0][0] =
            forged.layers[0].sumcheck.group_rounds[0][0] + Fp16::ONE;
        assert!(verify_uniform_zero_trace(&forged).is_err());
    }

    #[test]
    fn native_masked_real_trace_produces_all_168_layers_and_exact_rounds() {
        let layout = selected_gkr_mask_layout().unwrap();
        let coefficients = (0..layout.padded_coefficients)
            .map(|index| {
                Fp16::from_m31(
                    M31::from_canonical(((31 * index + 20_003) as u32 % (M31_MODULUS - 1)) + 1)
                        .unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let mut coin = DeterministicCoin {
            state: 0x1319_8a2e_0370_7344,
        };
        let mut proof = prove_masked_uniform_zero_trace(
            [0x5a; 64],
            &coefficients,
            |kind, message, output_count| Ok(coin.challenge(kind, message, output_count)),
        )
        .unwrap();
        let batch = complete_uniform_gkr_mask_batch(
            &mut proof,
            &coefficients,
            |kind, message, output_count| Ok(coin.challenge(kind, message, output_count)),
        )
        .unwrap();
        verify_uniform_gkr_mask_batch(&proof, &batch).unwrap();
        verify_masked_uniform_zero_trace(&proof, &batch).unwrap();
        assert_eq!(
            verify_masked_nonuniform_trace(&proof, &batch, [0x71; 64]),
            Err(UniformRelayFreeGkrError::Trace)
        );
        assert_eq!(proof.layers.len(), 168);
        assert_eq!(proof.rounds.len(), 6_073);
        assert_eq!(batch.constraints.len(), 508);
        assert_eq!(
            inner_product(&coefficients, &batch.coefficient_weights).unwrap(),
            batch.opening
        );
        assert_eq!(proof.raw_input_claims.len(), 4);
        assert!(
            proof
                .raw_input_claims
                .iter()
                .all(|claim| claim.value == Fp16::ZERO)
        );
        assert!(proof.layers.iter().all(|layer| {
            layer.reduction.masked_terminal_left != layer.reduction.raw_terminal_left
                && layer.reduction.masked_terminal_right != layer.reduction.raw_terminal_right
        }));
        let mut forged_transcript = proof.clone();
        forged_transcript.layers[0].reduction.published_rounds[0][0] =
            forged_transcript.layers[0].reduction.published_rounds[0][0] + Fp16::ONE;
        assert_eq!(
            verify_masked_uniform_zero_trace(&forged_transcript, &batch),
            Err(UniformRelayFreeGkrError::Schedule)
        );
        assert_eq!(
            verify_masked_nonuniform_trace(&forged_transcript, &batch, [0x71; 64]),
            Err(UniformRelayFreeGkrError::Trace)
        );
        let mut forged_batch = batch;
        forged_batch.opening = forged_batch.opening + Fp16::ONE;
        assert_eq!(
            verify_uniform_gkr_mask_batch(&proof, &forged_batch),
            Err(UniformRelayFreeGkrError::Algebra)
        );
    }

    #[test]
    fn encoded_field_width_is_frozen() {
        assert_eq!(Fp16::ZERO.encode().len(), FP16_BYTES);
    }

    #[test]
    fn packed_bridge_node_sum_rejects_a_forged_polynomial() {
        let mut message = [Fp16::ZERO; PACKED_BINARY_MESSAGE_COEFFICIENTS];
        message[0] = Fp16::ONE;
        let claims = [UniformRelayFreeClaim {
            shard_query: Fp16::ONE,
            point: vec![Fp16::ZERO; 24],
            value: Fp16::from_m31(M31::from_canonical(16).unwrap()),
            coefficient: Fp16::ONE,
        }];
        verify_packed_bridge_node_sum(&claims, &message).unwrap();
        message[1] = Fp16::ONE;
        assert_eq!(
            verify_packed_bridge_node_sum(&claims, &message),
            Err(UniformRelayFreeGkrError::Algebra)
        );
    }
}
