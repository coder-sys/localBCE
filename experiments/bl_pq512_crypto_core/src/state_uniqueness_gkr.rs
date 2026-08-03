//! Proof-native high-cardinality key uniqueness for the custom H4 state lane.
//!
//! Every unordered pair of fixed-capacity rows is checked in both the before
//! and after state. A pair is active only when both presence bits are one.
//! Each 64-byte key is represented by the same injective two-Fp16 packing as
//! the compact state relation. For an active pair, a Boolean selector chooses
//! one of the two packed differences and an inverse witness proves that the
//! chosen difference is nonzero. Duplicate keys make both differences zero,
//! so no selector or inverse can satisfy the final zero claim.
//!
//! This deliberately uses bounded quadratic work as a differential control
//! instead of adding a sorted copy, permutation argument, or second lookup
//! backend. At the frozen 512-slot ceiling there are 130,816 pairs per phase.
//! The measured 512-slot control is too slow for H4 and is not the selected
//! route; the source alignment and two PCS terminals remain useful executable
//! evidence for a subquadratic successor. The reference prover accepts
//! completed challenges only for KATs; the interactive entry point releases
//! every challenge and claim-combination coefficient after the prior message.

use alloc::{vec, vec::Vec};
use core::fmt;

use crate::{
    field::{Fp16, M31, M31_MODULUS},
    gkr_sumcheck::{
        LayerOutputClaim, ProductSumcheckError, SparseLayerSumcheckProof, TwoSourceSparseRoundKind,
        prove_two_source_sparse_gkr_layer_interactive, prove_two_source_sparse_gkr_layer_reference,
        verify_two_source_sparse_gkr_layer_reference,
    },
    keccak_gkr_dag::{KeccakDagGate, KeccakDagGateKind, KeccakDagLayer, KeccakDagSource},
    multilinear_pcs::{MultilinearOpeningClaim, evaluate_multilinear},
    state_relation_gkr::{StateRelationEntry, StateRelationRow, pack_chunks},
};

pub const STATE_UNIQUENESS_MAX_CAPACITY: usize = 512;
pub const STATE_UNIQUENESS_ROW_WIDTH: usize = 128;
pub const STATE_UNIQUENESS_PHASES: usize = 2;
pub const STATE_UNIQUENESS_LAYER_COUNT: usize = 4;

const BEFORE_PRESENT_WIRE: usize = 1;
const BEFORE_KEY_WIRE: usize = 2;
const AFTER_PRESENT_WIRE: usize = 7;
const AFTER_KEY_WIRE: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateUniquenessLayout {
    pub capacity: usize,
    pub pair_count: usize,
    pub instance_count: usize,
    pub witness_base: usize,
    pub input_width: usize,
}

impl StateUniquenessLayout {
    pub fn new(capacity: usize) -> Result<Self, StateUniquenessGkrError> {
        if !(2..=STATE_UNIQUENESS_MAX_CAPACITY).contains(&capacity) || !capacity.is_power_of_two() {
            return Err(StateUniquenessGkrError::Capacity);
        }
        let pair_count = capacity
            .checked_mul(capacity - 1)
            .and_then(|value| value.checked_div(2))
            .ok_or(StateUniquenessGkrError::Shape)?;
        let instance_count = pair_count
            .checked_mul(STATE_UNIQUENESS_PHASES)
            .ok_or(StateUniquenessGkrError::Shape)?;
        let witness_base = capacity
            .checked_mul(STATE_UNIQUENESS_ROW_WIDTH)
            .ok_or(StateUniquenessGkrError::Shape)?;
        let used = witness_base
            .checked_add(
                instance_count
                    .checked_mul(2)
                    .ok_or(StateUniquenessGkrError::Shape)?,
            )
            .ok_or(StateUniquenessGkrError::Shape)?;
        let input_width = used
            .checked_next_power_of_two()
            .ok_or(StateUniquenessGkrError::Shape)?;
        Ok(Self {
            capacity,
            pair_count,
            instance_count,
            witness_base,
            input_width,
        })
    }

    fn state_index(self, row: usize, phase: usize, component: usize) -> usize {
        let phase_wire = if phase == 0 {
            [BEFORE_PRESENT_WIRE, BEFORE_KEY_WIRE, BEFORE_KEY_WIRE + 1]
        } else {
            [AFTER_PRESENT_WIRE, AFTER_KEY_WIRE, AFTER_KEY_WIRE + 1]
        };
        row * STATE_UNIQUENESS_ROW_WIDTH + phase_wire[component]
    }

    fn witness_index(self, pair: usize, phase: usize, component: usize) -> usize {
        self.witness_base + (phase * self.pair_count + pair) * 2 + component
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateUniquenessChallengeSet {
    pub output_point: Vec<Fp16>,
    /// One left/right challenge vector for each forward layer.
    pub layer_challenges: Vec<Vec<Fp16>>,
    /// Authenticated coefficients for the two claims emitted by each layer.
    pub input_coefficients: Vec<[Fp16; 2]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateUniquenessGkrProof {
    pub layout: StateUniquenessLayout,
    pub challenges: StateUniquenessChallengeSet,
    /// Proofs are stored in forward layer order.
    pub layers: Vec<SparseLayerSumcheckProof>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateUniquenessInputClaim {
    pub claim: MultilinearOpeningClaim,
    pub coefficient: Fp16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateUniquenessRoundKind {
    Left,
    Right,
    ClaimCombination,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateUniquenessGkrError {
    Capacity,
    DuplicateKey,
    Encoding,
    Shape,
    Gkr(ProductSumcheckError),
}

impl fmt::Display for StateUniquenessGkrError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "state uniqueness GKR error: {self:?}")
    }
}

impl core::error::Error for StateUniquenessGkrError {}

impl From<ProductSumcheckError> for StateUniquenessGkrError {
    fn from(error: ProductSumcheckError) -> Self {
        Self::Gkr(error)
    }
}

fn phase_entry(row: StateRelationRow, phase: usize) -> StateRelationEntry {
    if phase == 0 {
        row.operation_before
    } else {
        row.operation_after
    }
}

fn pair_rows(capacity: usize) -> impl Iterator<Item = (usize, usize)> {
    (0..capacity).flat_map(move |left| ((left + 1)..capacity).map(move |right| (left, right)))
}

/// Build the committed state-and-witness source consumed by the uniqueness
/// GKR. Honest construction rejects duplicates early, but verifier soundness
/// comes from the GKR constraints and PCS openings rather than this check.
pub fn build_state_uniqueness_source(
    rows: &[StateRelationRow],
    layout: StateUniquenessLayout,
) -> Result<Vec<Fp16>, StateUniquenessGkrError> {
    if rows.len() > layout.capacity {
        return Err(StateUniquenessGkrError::Capacity);
    }
    let mut source = vec![Fp16::ZERO; layout.input_width];
    let mut packed_keys = vec![[[Fp16::ZERO; 2]; STATE_UNIQUENESS_PHASES]; layout.capacity];
    let mut present = vec![[false; STATE_UNIQUENESS_PHASES]; layout.capacity];
    for (row_index, row) in rows.iter().copied().enumerate() {
        for phase in 0..STATE_UNIQUENESS_PHASES {
            let entry = phase_entry(row, phase);
            if usize::try_from(entry.index).ok() != Some(row_index)
                || !entry.present && (entry.key != [0; 64] || entry.value != [0; 64])
            {
                return Err(StateUniquenessGkrError::Encoding);
            }
            let key = pack_chunks(&entry.key).map_err(|_| StateUniquenessGkrError::Encoding)?;
            present[row_index][phase] = entry.present;
            packed_keys[row_index][phase] = key;
            source[layout.state_index(row_index, phase, 0)] =
                if entry.present { Fp16::ONE } else { Fp16::ZERO };
            source[layout.state_index(row_index, phase, 1)] = key[0];
            source[layout.state_index(row_index, phase, 2)] = key[1];
        }
    }

    for (pair, (left, right)) in pair_rows(layout.capacity).enumerate() {
        for phase in 0..STATE_UNIQUENESS_PHASES {
            if !(present[left][phase] && present[right][phase]) {
                continue;
            }
            let first = packed_keys[left][phase][0] - packed_keys[right][phase][0];
            let second = packed_keys[left][phase][1] - packed_keys[right][phase][1];
            let (selector, selected) = if !first.is_zero() {
                (Fp16::ONE, first)
            } else if !second.is_zero() {
                (Fp16::ZERO, second)
            } else {
                return Err(StateUniquenessGkrError::DuplicateKey);
            };
            source[layout.witness_index(pair, phase, 0)] = selector;
            source[layout.witness_index(pair, phase, 1)] = selected
                .inverse()
                .map_err(|_| StateUniquenessGkrError::Encoding)?;
        }
    }
    Ok(source)
}

fn gate(left: usize, right: usize, kind: KeccakDagGateKind) -> KeccakDagGate {
    KeccakDagGate { left, right, kind }
}

fn finish_layer(
    source: KeccakDagSource,
    width: usize,
    mut gates: Vec<KeccakDagGate>,
) -> Result<KeccakDagLayer, StateUniquenessGkrError> {
    if gates.is_empty() || !width.is_power_of_two() {
        return Err(StateUniquenessGkrError::Shape);
    }
    let raw_width = gates.len();
    let padded_width = raw_width
        .checked_next_power_of_two()
        .ok_or(StateUniquenessGkrError::Shape)?;
    gates.resize(padded_width, gate(0, 0, KeccakDagGateKind::Zero));
    Ok(KeccakDagLayer {
        left_source: source,
        right_source: source,
        left_width: width,
        right_width: width,
        raw_width,
        padded_width,
        gates,
    })
}

fn uniqueness_layers(
    layout: StateUniquenessLayout,
) -> Result<Vec<KeccakDagLayer>, StateUniquenessGkrError> {
    let mut first = Vec::with_capacity(layout.instance_count * 6);
    for (pair, (left, right)) in pair_rows(layout.capacity).enumerate() {
        for phase in 0..STATE_UNIQUENESS_PHASES {
            let left_present = layout.state_index(left, phase, 0);
            let left_key_0 = layout.state_index(left, phase, 1);
            let left_key_1 = layout.state_index(left, phase, 2);
            let right_present = layout.state_index(right, phase, 0);
            let right_key_0 = layout.state_index(right, phase, 1);
            let right_key_1 = layout.state_index(right, phase, 2);
            let selector = layout.witness_index(pair, phase, 0);
            let inverse = layout.witness_index(pair, phase, 1);
            first.extend([
                gate(left_key_0, right_key_0, KeccakDagGateKind::Subtract),
                gate(left_key_1, right_key_1, KeccakDagGateKind::Subtract),
                gate(left_present, right_present, KeccakDagGateKind::Multiply),
                gate(selector, selector, KeccakDagGateKind::RelayLeft),
                gate(inverse, inverse, KeccakDagGateKind::RelayLeft),
                gate(selector, selector, KeccakDagGateKind::Multiply),
            ]);
        }
    }
    let layer0 = finish_layer(KeccakDagSource::RoundInput, layout.input_width, first)?;

    let mut second = Vec::with_capacity(layout.instance_count * 6);
    for instance in 0..layout.instance_count {
        let base = instance * 6;
        second.extend([
            gate(base, base + 4, KeccakDagGateKind::Multiply),
            gate(base + 1, base + 4, KeccakDagGateKind::Multiply),
            gate(base + 2, base + 2, KeccakDagGateKind::RelayLeft),
            gate(base + 2, base + 3, KeccakDagGateKind::Multiply),
            gate(base + 3, base + 2, KeccakDagGateKind::NotLeftAndRight),
            gate(base + 3, base + 5, KeccakDagGateKind::Subtract),
        ]);
    }
    let layer1 = finish_layer(KeccakDagSource::Layer(0), layer0.padded_width, second)?;

    let mut third = Vec::with_capacity(layout.instance_count * 5);
    for instance in 0..layout.instance_count {
        let base = instance * 6;
        third.extend([
            gate(base, base + 2, KeccakDagGateKind::Subtract),
            gate(base + 1, base + 2, KeccakDagGateKind::Subtract),
            gate(base + 3, base + 3, KeccakDagGateKind::RelayLeft),
            gate(base + 4, base + 4, KeccakDagGateKind::RelayLeft),
            gate(base + 5, base + 5, KeccakDagGateKind::RelayLeft),
        ]);
    }
    let layer2 = finish_layer(KeccakDagSource::Layer(1), layer1.padded_width, third)?;

    let mut fourth = Vec::with_capacity(layout.instance_count * 3);
    for instance in 0..layout.instance_count {
        let base = instance * 5;
        fourth.extend([
            gate(base + 2, base, KeccakDagGateKind::Multiply),
            gate(base + 3, base + 1, KeccakDagGateKind::Multiply),
            gate(base + 4, base + 4, KeccakDagGateKind::RelayLeft),
        ]);
    }
    let layer3 = finish_layer(KeccakDagSource::Layer(2), layer2.padded_width, fourth)?;
    Ok(vec![layer0, layer1, layer2, layer3])
}

fn evaluate_gate(kind: KeccakDagGateKind, left: Fp16, right: Fp16) -> Fp16 {
    match kind {
        KeccakDagGateKind::Multiply => left * right,
        KeccakDagGateKind::Add => left + right,
        KeccakDagGateKind::RelayLeft => left,
        KeccakDagGateKind::NotLeftAndRight => right - left * right,
        KeccakDagGateKind::Subtract => left - right,
        KeccakDagGateKind::Zero => Fp16::ZERO,
        _ => unreachable!("Boolean gate in state uniqueness relation"),
    }
}

fn evaluate_layer(
    layer: &KeccakDagLayer,
    source: &[Fp16],
) -> Result<Vec<Fp16>, StateUniquenessGkrError> {
    if source.len() != layer.left_width || layer.left_width != layer.right_width {
        return Err(StateUniquenessGkrError::Shape);
    }
    layer
        .gates
        .iter()
        .map(|item| {
            let left = *source
                .get(item.left)
                .ok_or(StateUniquenessGkrError::Shape)?;
            let right = *source
                .get(item.right)
                .ok_or(StateUniquenessGkrError::Shape)?;
            Ok(evaluate_gate(item.kind, left, right))
        })
        .collect()
}

fn validate_challenges(
    layers: &[KeccakDagLayer],
    challenges: &StateUniquenessChallengeSet,
) -> Result<(), StateUniquenessGkrError> {
    if layers.len() != STATE_UNIQUENESS_LAYER_COUNT
        || challenges.layer_challenges.len() != layers.len()
        || challenges.input_coefficients.len() != layers.len()
        || challenges.output_point.len()
            != layers
                .last()
                .ok_or(StateUniquenessGkrError::Shape)?
                .padded_width
                .ilog2() as usize
        || challenges
            .input_coefficients
            .iter()
            .flatten()
            .any(|value| value.is_zero())
    {
        return Err(StateUniquenessGkrError::Shape);
    }
    for (layer, supplied) in layers.iter().zip(&challenges.layer_challenges) {
        let expected = layer.left_width.ilog2() as usize + layer.right_width.ilog2() as usize;
        if supplied.len() != expected {
            return Err(StateUniquenessGkrError::Shape);
        }
    }
    Ok(())
}

/// Deterministic challenge material for reproducible controls and resource
/// measurements only. It is never launch randomness or security evidence.
pub fn state_uniqueness_control_challenges(
    layout: StateUniquenessLayout,
) -> Result<StateUniquenessChallengeSet, StateUniquenessGkrError> {
    let layers = uniqueness_layers(layout)?;
    let mut counter = 101_u32;
    let mut next = || {
        let value = Fp16::from_m31(
            M31::from_canonical(counter % M31_MODULUS).expect("control counter remains canonical"),
        );
        counter += 1;
        value
    };
    Ok(StateUniquenessChallengeSet {
        output_point: (0..layers
            .last()
            .ok_or(StateUniquenessGkrError::Shape)?
            .padded_width
            .ilog2())
            .map(|_| next())
            .collect(),
        layer_challenges: layers
            .iter()
            .map(|layer| {
                (0..layer.left_width.ilog2() + layer.right_width.ilog2())
                    .map(|_| next())
                    .collect()
            })
            .collect(),
        input_coefficients: (0..layers.len()).map(|_| [next(), next()]).collect(),
    })
}

fn next_claims(
    layer: &KeccakDagLayer,
    proof: &SparseLayerSumcheckProof,
    challenges: &[Fp16],
    coefficients: [Fp16; 2],
) -> [LayerOutputClaim; 2] {
    let left_variables = layer.left_width.ilog2() as usize;
    [
        LayerOutputClaim {
            point: challenges[..left_variables].to_vec(),
            value: proof.terminal_left,
            coefficient: coefficients[0],
        },
        LayerOutputClaim {
            point: challenges[left_variables..].to_vec(),
            value: proof.terminal_right,
            coefficient: coefficients[1],
        },
    ]
}

/// Produce the reference GKR chain. Completed challenges are accepted only so
/// deterministic tests can exercise the algebra; they are not a launch API.
pub fn prove_state_uniqueness_gkr_control(
    source: &[Fp16],
    layout: StateUniquenessLayout,
    challenges: StateUniquenessChallengeSet,
) -> Result<StateUniquenessGkrProof, StateUniquenessGkrError> {
    if source.len() != layout.input_width {
        return Err(StateUniquenessGkrError::Shape);
    }
    let layers = uniqueness_layers(layout)?;
    validate_challenges(&layers, &challenges)?;
    let mut evaluations = Vec::with_capacity(layers.len() + 1);
    evaluations.push(source.to_vec());
    for layer in &layers {
        let output = evaluate_layer(layer, evaluations.last().expect("source exists"))?;
        evaluations.push(output);
    }
    let final_output = evaluations.last().ok_or(StateUniquenessGkrError::Shape)?;
    if evaluate_multilinear(final_output, &challenges.output_point)
        .map_err(|_| StateUniquenessGkrError::Shape)?
        != Fp16::ZERO
    {
        return Err(StateUniquenessGkrError::Gkr(ProductSumcheckError::Claim));
    }

    let mut pending = vec![LayerOutputClaim {
        point: challenges.output_point.clone(),
        value: Fp16::ZERO,
        coefficient: Fp16::ONE,
    }];
    let mut proofs = vec![None; layers.len()];
    for index in (0..layers.len()).rev() {
        let proof = prove_two_source_sparse_gkr_layer_reference(
            &layers[index],
            &evaluations[index],
            &evaluations[index],
            &pending,
            &challenges.layer_challenges[index],
        )?;
        pending = next_claims(
            &layers[index],
            &proof,
            &challenges.layer_challenges[index],
            challenges.input_coefficients[index],
        )
        .to_vec();
        proofs[index] = Some(proof);
    }
    Ok(StateUniquenessGkrProof {
        layout,
        challenges,
        layers: proofs
            .into_iter()
            .map(|proof| proof.expect("every layer proven"))
            .collect(),
    })
}

/// Produce the uniqueness chain while obtaining every sumcheck challenge and
/// preceding-layer claim-combination coefficient from an authenticated
/// message-first callback.
pub fn prove_state_uniqueness_gkr_interactive(
    source: &[Fp16],
    layout: StateUniquenessLayout,
    output_point: Vec<Fp16>,
    mut challenge: impl FnMut(
        StateUniquenessRoundKind,
        usize,
        usize,
        &[Fp16],
    ) -> Result<Fp16, StateUniquenessGkrError>,
) -> Result<StateUniquenessGkrProof, StateUniquenessGkrError> {
    if source.len() != layout.input_width {
        return Err(StateUniquenessGkrError::Shape);
    }
    let layers = uniqueness_layers(layout)?;
    if output_point.len()
        != layers
            .last()
            .ok_or(StateUniquenessGkrError::Shape)?
            .padded_width
            .ilog2() as usize
    {
        return Err(StateUniquenessGkrError::Shape);
    }
    let mut evaluations = Vec::with_capacity(layers.len() + 1);
    evaluations.push(source.to_vec());
    for layer in &layers {
        let output = evaluate_layer(layer, evaluations.last().expect("source exists"))?;
        evaluations.push(output);
    }
    if evaluate_multilinear(
        evaluations.last().expect("final output exists"),
        &output_point,
    )
    .map_err(|_| StateUniquenessGkrError::Shape)?
        != Fp16::ZERO
    {
        return Err(StateUniquenessGkrError::Gkr(ProductSumcheckError::Claim));
    }

    let mut pending = vec![LayerOutputClaim {
        point: output_point.clone(),
        value: Fp16::ZERO,
        coefficient: Fp16::ONE,
    }];
    let mut proofs = vec![None; layers.len()];
    let mut layer_challenges = vec![Vec::new(); layers.len()];
    let mut input_coefficients = vec![[Fp16::ZERO; 2]; layers.len()];
    for index in (0..layers.len()).rev() {
        let (layer_proof, supplied) = prove_two_source_sparse_gkr_layer_interactive(
            &layers[index],
            &evaluations[index],
            &evaluations[index],
            &pending,
            |kind, round, published| {
                let state_kind = match kind {
                    TwoSourceSparseRoundKind::Left => StateUniquenessRoundKind::Left,
                    TwoSourceSparseRoundKind::Right => StateUniquenessRoundKind::Right,
                };
                challenge(state_kind, index, round, published)
                    .map_err(|_| ProductSumcheckError::Claim)
            },
        )?;
        let published = [layer_proof.terminal_left, layer_proof.terminal_right];
        let coefficients = [
            challenge(
                StateUniquenessRoundKind::ClaimCombination,
                index,
                0,
                &published,
            )?,
            challenge(
                StateUniquenessRoundKind::ClaimCombination,
                index,
                1,
                &published,
            )?,
        ];
        if coefficients.iter().any(|value| value.is_zero()) {
            return Err(StateUniquenessGkrError::Shape);
        }
        pending = next_claims(&layers[index], &layer_proof, &supplied, coefficients).to_vec();
        proofs[index] = Some(layer_proof);
        layer_challenges[index] = supplied;
        input_coefficients[index] = coefficients;
    }
    let proof = StateUniquenessGkrProof {
        layout,
        challenges: StateUniquenessChallengeSet {
            output_point,
            layer_challenges,
            input_coefficients,
        },
        layers: proofs
            .into_iter()
            .map(|proof| proof.expect("every layer proven"))
            .collect(),
    };
    verify_state_uniqueness_gkr(&proof)?;
    Ok(proof)
}

pub fn verify_state_uniqueness_gkr(
    proof: &StateUniquenessGkrProof,
) -> Result<(), StateUniquenessGkrError> {
    let layers = uniqueness_layers(proof.layout)?;
    validate_challenges(&layers, &proof.challenges)?;
    if proof.layers.len() != layers.len() {
        return Err(StateUniquenessGkrError::Shape);
    }
    let mut pending = vec![LayerOutputClaim {
        point: proof.challenges.output_point.clone(),
        value: Fp16::ZERO,
        coefficient: Fp16::ONE,
    }];
    for index in (0..layers.len()).rev() {
        verify_two_source_sparse_gkr_layer_reference(
            &layers[index],
            &pending,
            &proof.challenges.layer_challenges[index],
            &proof.layers[index],
        )?;
        pending = next_claims(
            &layers[index],
            &proof.layers[index],
            &proof.challenges.layer_challenges[index],
            proof.challenges.input_coefficients[index],
        )
        .to_vec();
    }
    Ok(())
}

/// Return the two source openings that must be authenticated by the same PCS
/// commitment as the state lane.
pub fn state_uniqueness_input_claims(
    proof: &StateUniquenessGkrProof,
) -> Result<[StateUniquenessInputClaim; 2], StateUniquenessGkrError> {
    verify_state_uniqueness_gkr(proof)?;
    let first = proof.layers.first().ok_or(StateUniquenessGkrError::Shape)?;
    let layer_challenges = &proof.challenges.layer_challenges[0];
    let variables = proof.layout.input_width.ilog2() as usize;
    let coefficients = proof.challenges.input_coefficients[0];
    Ok([
        StateUniquenessInputClaim {
            claim: MultilinearOpeningClaim {
                point: layer_challenges[..variables].to_vec(),
                value: first.terminal_left,
            },
            coefficient: coefficients[0],
        },
        StateUniquenessInputClaim {
            claim: MultilinearOpeningClaim {
                point: layer_challenges[variables..].to_vec(),
                value: first.terminal_right,
            },
            coefficient: coefficients[1],
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{M31, M31_MODULUS};

    fn scalar(value: u32) -> Fp16 {
        Fp16::from_m31(M31::from_canonical(value % M31_MODULUS).unwrap())
    }

    fn entry(index: u32, seed: u8) -> StateRelationEntry {
        let mut key = [0_u8; 64];
        let mut value = [0_u8; 64];
        key[63] = seed;
        value[63] = seed.wrapping_add(41);
        StateRelationEntry {
            index,
            present: true,
            key,
            value,
        }
    }

    fn rows(capacity: usize) -> Vec<StateRelationRow> {
        (0..capacity)
            .map(|index| {
                let before = entry(index as u32, index as u8 + 1);
                let after = entry(index as u32, index as u8 + 17);
                StateRelationRow {
                    operation_before: before,
                    operation_after: after,
                    snapshot_before: before,
                    snapshot_after: after,
                }
            })
            .collect()
    }

    fn challenges(layout: StateUniquenessLayout) -> StateUniquenessChallengeSet {
        state_uniqueness_control_challenges(layout).unwrap()
    }

    #[test]
    fn pairwise_uniqueness_proves_and_exposes_two_pcs_claims() {
        let layout = StateUniquenessLayout::new(4).unwrap();
        assert_eq!(layout.pair_count, 6);
        assert_eq!(layout.instance_count, 12);
        let source = build_state_uniqueness_source(&rows(4), layout).unwrap();
        let proof =
            prove_state_uniqueness_gkr_control(&source, layout, challenges(layout)).unwrap();
        verify_state_uniqueness_gkr(&proof).unwrap();
        let claims = state_uniqueness_input_claims(&proof).unwrap();
        assert_eq!(
            claims[0].claim.point.len(),
            layout.input_width.ilog2() as usize
        );
        assert_eq!(
            claims[1].claim.point.len(),
            layout.input_width.ilog2() as usize
        );
        assert!(claims.iter().all(|claim| !claim.coefficient.is_zero()));
    }

    #[test]
    fn honest_builder_rejects_duplicate_present_keys_in_either_phase() {
        let layout = StateUniquenessLayout::new(4).unwrap();
        let mut duplicate = rows(4);
        duplicate[1].operation_after.key = duplicate[0].operation_after.key;
        duplicate[1].snapshot_after.key = duplicate[0].snapshot_after.key;
        assert_eq!(
            build_state_uniqueness_source(&duplicate, layout),
            Err(StateUniquenessGkrError::DuplicateKey)
        );
    }

    #[test]
    fn forged_duplicate_source_has_no_satisfying_existing_witness() {
        let layout = StateUniquenessLayout::new(4).unwrap();
        let mut source = build_state_uniqueness_source(&rows(4), layout).unwrap();
        for component in 1..=2 {
            source[layout.state_index(1, 0, component)] =
                source[layout.state_index(0, 0, component)];
        }
        assert_eq!(
            prove_state_uniqueness_gkr_control(&source, layout, challenges(layout)),
            Err(StateUniquenessGkrError::Gkr(ProductSumcheckError::Claim))
        );
    }

    #[test]
    fn selector_must_be_boolean_even_for_inactive_pairs() {
        let layout = StateUniquenessLayout::new(4).unwrap();
        let mut partial = rows(1);
        partial[0].operation_before = entry(0, 9);
        let mut source = build_state_uniqueness_source(&partial, layout).unwrap();
        source[layout.witness_index(0, 0, 0)] = scalar(2);
        assert_eq!(
            prove_state_uniqueness_gkr_control(&source, layout, challenges(layout)),
            Err(StateUniquenessGkrError::Gkr(ProductSumcheckError::Claim))
        );
    }

    #[test]
    fn interactive_uniqueness_releases_every_challenge_after_a_message() {
        let layout = StateUniquenessLayout::new(4).unwrap();
        let source = build_state_uniqueness_source(&rows(4), layout).unwrap();
        let fixed = challenges(layout);
        let mut supplied = fixed
            .layer_challenges
            .iter()
            .rev()
            .flat_map(|values| values.iter().copied().chain([scalar(1701), scalar(1703)]))
            .collect::<Vec<_>>()
            .into_iter();
        let mut messages = Vec::new();
        let proof = prove_state_uniqueness_gkr_interactive(
            &source,
            layout,
            fixed.output_point,
            |kind, layer, round, published| {
                assert!(!published.is_empty());
                messages.push((kind, layer, round, published.to_vec()));
                supplied.next().ok_or(StateUniquenessGkrError::Shape)
            },
        )
        .unwrap();
        assert!(supplied.next().is_none());
        verify_state_uniqueness_gkr(&proof).unwrap();
        let expected = proof
            .challenges
            .layer_challenges
            .iter()
            .map(Vec::len)
            .sum::<usize>()
            + 2 * STATE_UNIQUENESS_LAYER_COUNT;
        assert_eq!(messages.len(), expected);
        assert_eq!(
            messages
                .iter()
                .filter(|(kind, _, _, _)| { *kind == StateUniquenessRoundKind::ClaimCombination })
                .count(),
            2 * STATE_UNIQUENESS_LAYER_COUNT
        );
    }
}
