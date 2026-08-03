//! Linear-size state-key uniqueness candidate for the custom H4 lane.
//!
//! A public `beta`, sampled after the state commitment, compresses each
//! injective two-Fp16 key into `k0 + beta*k1`.  For one state phase define
//! `P(X) = product_i (present_i*(X-k_i) + 1-present_i)`.  Present keys are
//! unique exactly when `P` is square-free.  The prover commits bounded
//! coefficient tables `A,B` after `beta`, then receives `r` and proves
//! `A(r)P(r) + B(r)P'(r) = 1`.  A duplicate makes that polynomial identity
//! impossible; a false one-point identity has degree below `2*capacity` over
//! Fp16, comfortably above the frozen 256-bit floor at capacity 512.
//!
//! `P(r),P'(r)` are computed by a linear-size dual-number product tree.  Its
//! two virtual-leaf claims reduce to the already committed presence/key
//! columns.  The `A,B` evaluations reduce to four coefficient-table PCS
//! claims.  This module is a deterministic algebra/control boundary; launch
//! code must obtain beta, r, every sumcheck challenge, and every claim-mixing
//! coefficient from the authenticated message-first public coin.

use alloc::{collections::BTreeSet, vec, vec::Vec};
use core::fmt;

use crate::{
    field::{Fp16, M31, M31_MODULUS},
    gkr_sumcheck::{
        LayerOutputClaim, ProductSumcheckError, ProductSumcheckProof, SparseLayerSumcheckProof,
        TwoSourceSparseRoundKind, prove_product_sumcheck, prove_product_sumcheck_interactive,
        prove_two_source_sparse_gkr_layer_interactive, prove_two_source_sparse_gkr_layer_reference,
        verify_product_sumcheck, verify_two_source_sparse_gkr_layer_reference,
    },
    keccak_gkr_dag::{KeccakDagGate, KeccakDagGateKind, KeccakDagLayer, KeccakDagSource},
    multilinear_pcs::{MultilinearOpeningClaim, evaluate_multilinear},
    state_relation_gkr::{StateRelationEntry, StateRelationRow, pack_chunks},
};

pub const STATE_SQUAREFREE_MAX_CAPACITY: usize = 512;
pub const STATE_SQUAREFREE_PHASES: usize = 2;
pub const STATE_SQUAREFREE_STATE_GROUP_VARIABLES: usize = 12;

const BEFORE_PRESENT_WIRE: usize = 1;
const BEFORE_KEY_WIRE: usize = 2;
const AFTER_PRESENT_WIRE: usize = 7;
const AFTER_KEY_WIRE: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateSquarefreeLayout {
    pub capacity: usize,
    pub tree_layer_count: usize,
}

impl StateSquarefreeLayout {
    pub fn new(capacity: usize) -> Result<Self, StateSquarefreeGkrError> {
        if !(2..=STATE_SQUAREFREE_MAX_CAPACITY).contains(&capacity) || !capacity.is_power_of_two() {
            return Err(StateSquarefreeGkrError::Capacity);
        }
        Ok(Self {
            capacity,
            tree_layer_count: 2 * capacity.ilog2() as usize,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateSquarefreePhaseWitness {
    pub bezout_a: Vec<Fp16>,
    pub bezout_b: Vec<Fp16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateSquarefreeWitness {
    pub layout: StateSquarefreeLayout,
    pub beta: Fp16,
    pub phases: [StateSquarefreePhaseWitness; STATE_SQUAREFREE_PHASES],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateSquarefreeChallengeSet {
    pub root_coefficients: [[Fp16; 2]; STATE_SQUAREFREE_PHASES],
    pub tree_challenges: [Vec<Vec<Fp16>>; STATE_SQUAREFREE_PHASES],
    pub tree_input_coefficients: [Vec<[Fp16; 2]>; STATE_SQUAREFREE_PHASES],
    pub coefficient_challenges: [[Vec<Fp16>; 2]; STATE_SQUAREFREE_PHASES],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoefficientEvaluationProof {
    pub value: Fp16,
    pub challenges: Vec<Fp16>,
    pub sumcheck: ProductSumcheckProof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateSquarefreePhaseProof {
    pub product_at_r: Fp16,
    pub derivative_at_r: Fp16,
    pub tree_layers: Vec<SparseLayerSumcheckProof>,
    pub bezout_a: CoefficientEvaluationProof,
    pub bezout_b: CoefficientEvaluationProof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateSquarefreeGkrProof {
    pub layout: StateSquarefreeLayout,
    pub beta: Fp16,
    pub evaluation_point: Fp16,
    pub challenges: StateSquarefreeChallengeSet,
    pub phases: [StateSquarefreePhaseProof; STATE_SQUAREFREE_PHASES],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateSquarefreeInputClaims {
    /// Two virtual dual-leaf claims per phase.  Each is an affine function of
    /// state presence/key openings at the claim's row point.
    pub virtual_leaf_claims: [[LayerOutputClaim; 2]; STATE_SQUAREFREE_PHASES],
    /// A then B coefficient-table opening for each phase.
    pub coefficient_claims: [[MultilinearOpeningClaim; 2]; STATE_SQUAREFREE_PHASES],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateSquarefreeStateReduction {
    pub phase: u8,
    pub row_point: Vec<Fp16>,
    pub state_wires: [usize; 3],
    /// Constant, presence, key-0, and key-1 coefficients for the virtual
    /// leaf value at `row_point`.
    pub affine_coefficients: [Fp16; 4],
    pub expected_value: Fp16,
    pub gkr_coefficient: Fp16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateSquarefreeRoundKind {
    RootCombination,
    TreeLeft,
    TreeRight,
    TreeClaimCombination,
    BezoutA,
    BezoutB,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateSquarefreeGkrError {
    Capacity,
    DuplicateKey,
    CompressionCollision,
    Encoding,
    Shape,
    Polynomial,
    Claim,
    Gkr(ProductSumcheckError),
}

impl fmt::Display for StateSquarefreeGkrError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "state square-free GKR error: {self:?}")
    }
}

impl core::error::Error for StateSquarefreeGkrError {}

impl From<ProductSumcheckError> for StateSquarefreeGkrError {
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

fn scalar(value: usize) -> Result<Fp16, StateSquarefreeGkrError> {
    let canonical = u32::try_from(value).map_err(|_| StateSquarefreeGkrError::Polynomial)?;
    Ok(Fp16::from_m31(
        M31::from_canonical(canonical).map_err(|_| StateSquarefreeGkrError::Polynomial)?,
    ))
}

fn trim(polynomial: &mut Vec<Fp16>) {
    while polynomial.len() > 1 && polynomial.last() == Some(&Fp16::ZERO) {
        polynomial.pop();
    }
}

fn is_zero_polynomial(polynomial: &[Fp16]) -> bool {
    polynomial.iter().all(|value| value.is_zero())
}

fn polynomial_subtract(left: &[Fp16], right: &[Fp16]) -> Vec<Fp16> {
    let mut result = vec![Fp16::ZERO; left.len().max(right.len()).max(1)];
    for (index, value) in left.iter().copied().enumerate() {
        result[index] = result[index] + value;
    }
    for (index, value) in right.iter().copied().enumerate() {
        result[index] = result[index] - value;
    }
    trim(&mut result);
    result
}

fn polynomial_multiply(left: &[Fp16], right: &[Fp16]) -> Vec<Fp16> {
    if is_zero_polynomial(left) || is_zero_polynomial(right) {
        return vec![Fp16::ZERO];
    }
    let mut result = vec![Fp16::ZERO; left.len() + right.len() - 1];
    for (left_degree, left_value) in left.iter().copied().enumerate() {
        for (right_degree, right_value) in right.iter().copied().enumerate() {
            result[left_degree + right_degree] =
                result[left_degree + right_degree] + left_value * right_value;
        }
    }
    trim(&mut result);
    result
}

fn polynomial_divide(
    numerator: &[Fp16],
    denominator: &[Fp16],
) -> Result<(Vec<Fp16>, Vec<Fp16>), StateSquarefreeGkrError> {
    if is_zero_polynomial(denominator) {
        return Err(StateSquarefreeGkrError::Polynomial);
    }
    let mut remainder = numerator.to_vec();
    trim(&mut remainder);
    let mut quotient = if remainder.len() >= denominator.len() {
        vec![Fp16::ZERO; remainder.len() - denominator.len() + 1]
    } else {
        vec![Fp16::ZERO]
    };
    let denominator_lead = denominator
        .last()
        .copied()
        .ok_or(StateSquarefreeGkrError::Polynomial)?
        .inverse()
        .map_err(|_| StateSquarefreeGkrError::Polynomial)?;
    while !is_zero_polynomial(&remainder) && remainder.len() >= denominator.len() {
        let degree = remainder.len() - denominator.len();
        let factor = *remainder
            .last()
            .ok_or(StateSquarefreeGkrError::Polynomial)?
            * denominator_lead;
        quotient[degree] = quotient[degree] + factor;
        for (index, value) in denominator.iter().copied().enumerate() {
            remainder[index + degree] = remainder[index + degree] - factor * value;
        }
        trim(&mut remainder);
    }
    trim(&mut quotient);
    Ok((quotient, remainder))
}

fn derivative(polynomial: &[Fp16]) -> Result<Vec<Fp16>, StateSquarefreeGkrError> {
    if polynomial.len() <= 1 {
        return Ok(vec![Fp16::ZERO]);
    }
    (1..polynomial.len())
        .map(|degree| Ok(polynomial[degree] * scalar(degree)?))
        .collect()
}

fn bezout_for_squarefree(
    polynomial: &[Fp16],
) -> Result<(Vec<Fp16>, Vec<Fp16>), StateSquarefreeGkrError> {
    let mut old_r = polynomial.to_vec();
    let mut r = derivative(polynomial)?;
    let mut old_s = vec![Fp16::ONE];
    let mut s = vec![Fp16::ZERO];
    let mut old_t = vec![Fp16::ZERO];
    let mut t = vec![Fp16::ONE];
    while !is_zero_polynomial(&r) {
        let (quotient, remainder) = polynomial_divide(&old_r, &r)?;
        old_r = r;
        r = remainder;
        let next_s = polynomial_subtract(&old_s, &polynomial_multiply(&quotient, &s));
        old_s = s;
        s = next_s;
        let next_t = polynomial_subtract(&old_t, &polynomial_multiply(&quotient, &t));
        old_t = t;
        t = next_t;
    }
    trim(&mut old_r);
    if old_r.len() != 1 || old_r[0].is_zero() {
        return Err(StateSquarefreeGkrError::DuplicateKey);
    }
    let inverse = old_r[0]
        .inverse()
        .map_err(|_| StateSquarefreeGkrError::Polynomial)?;
    for value in &mut old_s {
        *value = *value * inverse;
    }
    for value in &mut old_t {
        *value = *value * inverse;
    }
    Ok((old_s, old_t))
}

fn compressed_entries(
    rows: &[StateRelationRow],
    layout: StateSquarefreeLayout,
    phase: usize,
    beta: Fp16,
) -> Result<Vec<Option<Fp16>>, StateSquarefreeGkrError> {
    if rows.len() > layout.capacity || beta.is_zero() {
        return Err(StateSquarefreeGkrError::Shape);
    }
    let mut exact = BTreeSet::new();
    let mut compressed = BTreeSet::new();
    let mut output = vec![None; layout.capacity];
    for (index, row) in rows.iter().copied().enumerate() {
        let entry = phase_entry(row, phase);
        if usize::try_from(entry.index).ok() != Some(index)
            || !entry.present && (entry.key != [0; 64] || entry.value != [0; 64])
        {
            return Err(StateSquarefreeGkrError::Encoding);
        }
        if !entry.present {
            continue;
        }
        if !exact.insert(entry.key) {
            return Err(StateSquarefreeGkrError::DuplicateKey);
        }
        let packed = pack_chunks(&entry.key).map_err(|_| StateSquarefreeGkrError::Encoding)?;
        let key = packed[0] + beta * packed[1];
        if !compressed.insert(key.encode()) {
            return Err(StateSquarefreeGkrError::CompressionCollision);
        }
        output[index] = Some(key);
    }
    Ok(output)
}

fn product_polynomial(entries: &[Option<Fp16>]) -> Vec<Fp16> {
    let mut polynomial = vec![Fp16::ONE];
    for key in entries.iter().flatten().copied() {
        let mut next = vec![Fp16::ZERO; polynomial.len() + 1];
        for (degree, coefficient) in polynomial.iter().copied().enumerate() {
            next[degree] = next[degree] - coefficient * key;
            next[degree + 1] = next[degree + 1] + coefficient;
        }
        polynomial = next;
    }
    polynomial
}

pub fn build_state_squarefree_witness(
    rows: &[StateRelationRow],
    layout: StateSquarefreeLayout,
    beta: Fp16,
) -> Result<StateSquarefreeWitness, StateSquarefreeGkrError> {
    let mut phases = Vec::with_capacity(STATE_SQUAREFREE_PHASES);
    for phase in 0..STATE_SQUAREFREE_PHASES {
        let entries = compressed_entries(rows, layout, phase, beta)?;
        let polynomial = product_polynomial(&entries);
        let (mut bezout_a, mut bezout_b) = bezout_for_squarefree(&polynomial)?;
        if bezout_a.len() > layout.capacity || bezout_b.len() > layout.capacity {
            return Err(StateSquarefreeGkrError::Polynomial);
        }
        bezout_a.resize(layout.capacity, Fp16::ZERO);
        bezout_b.resize(layout.capacity, Fp16::ZERO);
        phases.push(StateSquarefreePhaseWitness { bezout_a, bezout_b });
    }
    Ok(StateSquarefreeWitness {
        layout,
        beta,
        phases: phases
            .try_into()
            .map_err(|_| StateSquarefreeGkrError::Shape)?,
    })
}

fn gate(left: usize, right: usize, kind: KeccakDagGateKind) -> KeccakDagGate {
    KeccakDagGate { left, right, kind }
}

fn finish_layer(
    source: KeccakDagSource,
    input_width: usize,
    mut gates: Vec<KeccakDagGate>,
) -> Result<KeccakDagLayer, StateSquarefreeGkrError> {
    let raw_width = gates.len();
    let padded_width = raw_width
        .max(2)
        .checked_next_power_of_two()
        .ok_or(StateSquarefreeGkrError::Shape)?;
    gates.resize(padded_width, gate(0, 0, KeccakDagGateKind::Zero));
    Ok(KeccakDagLayer {
        left_source: source,
        right_source: source,
        left_width: input_width,
        right_width: input_width,
        raw_width,
        padded_width,
        gates,
    })
}

fn dual_product_layers(
    layout: StateSquarefreeLayout,
) -> Result<Vec<KeccakDagLayer>, StateSquarefreeGkrError> {
    let mut layers = Vec::with_capacity(layout.tree_layer_count);
    let mut items = layout.capacity;
    let mut input_width = 2 * items;
    while items > 1 {
        let parents = items / 2;
        let mut products = Vec::with_capacity(3 * parents);
        for parent in 0..parents {
            let base = 4 * parent;
            products.extend([
                gate(base, base + 2, KeccakDagGateKind::Multiply),
                gate(base + 1, base + 2, KeccakDagGateKind::Multiply),
                gate(base, base + 3, KeccakDagGateKind::Multiply),
            ]);
        }
        let product_layer = finish_layer(
            if layers.is_empty() {
                KeccakDagSource::RoundInput
            } else {
                KeccakDagSource::Layer(layers.len() - 1)
            },
            input_width,
            products,
        )?;
        input_width = product_layer.padded_width;
        layers.push(product_layer);

        let mut sums = Vec::with_capacity(2 * parents);
        for parent in 0..parents {
            let base = 3 * parent;
            sums.extend([
                gate(base, base, KeccakDagGateKind::RelayLeft),
                gate(base + 1, base + 2, KeccakDagGateKind::Add),
            ]);
        }
        let sum_layer = finish_layer(KeccakDagSource::Layer(layers.len() - 1), input_width, sums)?;
        input_width = sum_layer.padded_width;
        layers.push(sum_layer);
        items = parents;
    }
    if layers.len() != layout.tree_layer_count || input_width != 2 {
        return Err(StateSquarefreeGkrError::Shape);
    }
    Ok(layers)
}

fn evaluate_gate(kind: KeccakDagGateKind, left: Fp16, right: Fp16) -> Fp16 {
    match kind {
        KeccakDagGateKind::Multiply => left * right,
        KeccakDagGateKind::Add => left + right,
        KeccakDagGateKind::RelayLeft => left,
        KeccakDagGateKind::Zero => Fp16::ZERO,
        _ => unreachable!("Boolean gate in square-free product tree"),
    }
}

fn evaluate_layer(
    layer: &KeccakDagLayer,
    source: &[Fp16],
) -> Result<Vec<Fp16>, StateSquarefreeGkrError> {
    if source.len() != layer.left_width || layer.left_width != layer.right_width {
        return Err(StateSquarefreeGkrError::Shape);
    }
    layer
        .gates
        .iter()
        .map(|item| {
            let left = *source
                .get(item.left)
                .ok_or(StateSquarefreeGkrError::Shape)?;
            let right = *source
                .get(item.right)
                .ok_or(StateSquarefreeGkrError::Shape)?;
            Ok(evaluate_gate(item.kind, left, right))
        })
        .collect()
}

fn dual_leaves(entries: &[Option<Fp16>], evaluation_point: Fp16) -> Vec<Fp16> {
    let mut leaves = Vec::with_capacity(2 * entries.len());
    for entry in entries {
        match entry {
            Some(key) => leaves.extend([evaluation_point - *key, Fp16::ONE]),
            None => leaves.extend([Fp16::ONE, Fp16::ZERO]),
        }
    }
    leaves
}

fn powers(point: Fp16, length: usize) -> Vec<Fp16> {
    let mut current = Fp16::ONE;
    (0..length)
        .map(|_| {
            let output = current;
            current = current * point;
            output
        })
        .collect()
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

fn validate_challenges(
    layout: StateSquarefreeLayout,
    challenges: &StateSquarefreeChallengeSet,
) -> Result<Vec<KeccakDagLayer>, StateSquarefreeGkrError> {
    let layers = dual_product_layers(layout)?;
    for phase in 0..STATE_SQUAREFREE_PHASES {
        if challenges.tree_challenges[phase].len() != layers.len()
            || challenges.tree_input_coefficients[phase].len() != layers.len()
            || challenges.root_coefficients[phase]
                .iter()
                .any(|value| value.is_zero())
            || challenges.tree_input_coefficients[phase]
                .iter()
                .flatten()
                .any(|value| value.is_zero())
            || challenges.coefficient_challenges[phase]
                .iter()
                .any(|values| values.len() != layout.capacity.ilog2() as usize)
        {
            return Err(StateSquarefreeGkrError::Shape);
        }
        for (layer, supplied) in layers.iter().zip(&challenges.tree_challenges[phase]) {
            let expected = layer.left_width.ilog2() as usize + layer.right_width.ilog2() as usize;
            if supplied.len() != expected {
                return Err(StateSquarefreeGkrError::Shape);
            }
        }
    }
    Ok(layers)
}

pub fn state_squarefree_control_challenges(
    layout: StateSquarefreeLayout,
) -> Result<StateSquarefreeChallengeSet, StateSquarefreeGkrError> {
    let layers = dual_product_layers(layout)?;
    let mut counter = 4_001_u32;
    let mut next = || {
        let output = Fp16::from_m31(
            M31::from_canonical(counter % M31_MODULUS).expect("counter is canonical"),
        );
        counter += 1;
        output
    };
    let mut roots = [[Fp16::ZERO; 2]; STATE_SQUAREFREE_PHASES];
    let mut tree_challenges = [Vec::new(), Vec::new()];
    let mut tree_coefficients = [Vec::new(), Vec::new()];
    let mut coefficient_challenges = [[Vec::new(), Vec::new()], [Vec::new(), Vec::new()]];
    for phase in 0..STATE_SQUAREFREE_PHASES {
        roots[phase] = [next(), next()];
        tree_challenges[phase] = layers
            .iter()
            .map(|layer| {
                (0..layer.left_width.ilog2() + layer.right_width.ilog2())
                    .map(|_| next())
                    .collect()
            })
            .collect();
        tree_coefficients[phase] = (0..layers.len()).map(|_| [next(), next()]).collect();
        for table_challenges in &mut coefficient_challenges[phase] {
            *table_challenges = (0..layout.capacity.ilog2()).map(|_| next()).collect();
        }
    }
    Ok(StateSquarefreeChallengeSet {
        root_coefficients: roots,
        tree_challenges,
        tree_input_coefficients: tree_coefficients,
        coefficient_challenges,
    })
}

fn prove_coefficient_evaluation(
    coefficients: &[Fp16],
    point: Fp16,
    challenges: Vec<Fp16>,
) -> Result<CoefficientEvaluationProof, StateSquarefreeGkrError> {
    let (value, sumcheck) = prove_product_sumcheck(
        coefficients,
        &powers(point, coefficients.len()),
        &challenges,
    )?;
    Ok(CoefficientEvaluationProof {
        value,
        challenges,
        sumcheck,
    })
}

fn prove_phase(
    entries: &[Option<Fp16>],
    witness: &StateSquarefreePhaseWitness,
    evaluation_point: Fp16,
    phase: usize,
    layers: &[KeccakDagLayer],
    challenges: &StateSquarefreeChallengeSet,
) -> Result<StateSquarefreePhaseProof, StateSquarefreeGkrError> {
    let leaves = dual_leaves(entries, evaluation_point);
    let mut evaluations = Vec::with_capacity(layers.len() + 1);
    evaluations.push(leaves);
    for layer in layers {
        evaluations.push(evaluate_layer(
            layer,
            evaluations.last().expect("leaves exist"),
        )?);
    }
    let final_output = evaluations.last().ok_or(StateSquarefreeGkrError::Shape)?;
    if final_output.len() != 2 {
        return Err(StateSquarefreeGkrError::Shape);
    }
    let product_at_r = final_output[0];
    let derivative_at_r = final_output[1];
    let mut pending = vec![
        LayerOutputClaim {
            point: vec![Fp16::ZERO],
            value: product_at_r,
            coefficient: challenges.root_coefficients[phase][0],
        },
        LayerOutputClaim {
            point: vec![Fp16::ONE],
            value: derivative_at_r,
            coefficient: challenges.root_coefficients[phase][1],
        },
    ];
    let mut proofs = vec![None; layers.len()];
    for index in (0..layers.len()).rev() {
        let proof = prove_two_source_sparse_gkr_layer_reference(
            &layers[index],
            &evaluations[index],
            &evaluations[index],
            &pending,
            &challenges.tree_challenges[phase][index],
        )?;
        pending = next_claims(
            &layers[index],
            &proof,
            &challenges.tree_challenges[phase][index],
            challenges.tree_input_coefficients[phase][index],
        )
        .to_vec();
        proofs[index] = Some(proof);
    }
    let bezout_a = prove_coefficient_evaluation(
        &witness.bezout_a,
        evaluation_point,
        challenges.coefficient_challenges[phase][0].clone(),
    )?;
    let bezout_b = prove_coefficient_evaluation(
        &witness.bezout_b,
        evaluation_point,
        challenges.coefficient_challenges[phase][1].clone(),
    )?;
    if bezout_a.value * product_at_r + bezout_b.value * derivative_at_r != Fp16::ONE {
        return Err(StateSquarefreeGkrError::Claim);
    }
    Ok(StateSquarefreePhaseProof {
        product_at_r,
        derivative_at_r,
        tree_layers: proofs
            .into_iter()
            .map(|proof| proof.expect("every tree layer proven"))
            .collect(),
        bezout_a,
        bezout_b,
    })
}

pub fn prove_state_squarefree_gkr_control(
    rows: &[StateRelationRow],
    witness: &StateSquarefreeWitness,
    evaluation_point: Fp16,
    challenges: StateSquarefreeChallengeSet,
) -> Result<StateSquarefreeGkrProof, StateSquarefreeGkrError> {
    if evaluation_point.is_zero() || witness.beta.is_zero() {
        return Err(StateSquarefreeGkrError::Shape);
    }
    let layers = validate_challenges(witness.layout, &challenges)?;
    let mut phases = Vec::with_capacity(STATE_SQUAREFREE_PHASES);
    for phase in 0..STATE_SQUAREFREE_PHASES {
        let entries = compressed_entries(rows, witness.layout, phase, witness.beta)?;
        phases.push(prove_phase(
            &entries,
            &witness.phases[phase],
            evaluation_point,
            phase,
            &layers,
            &challenges,
        )?);
    }
    let proof = StateSquarefreeGkrProof {
        layout: witness.layout,
        beta: witness.beta,
        evaluation_point,
        challenges,
        phases: phases
            .try_into()
            .map_err(|_| StateSquarefreeGkrError::Shape)?,
    };
    verify_state_squarefree_gkr(&proof)?;
    Ok(proof)
}

type InteractivePhaseResult = (
    StateSquarefreePhaseProof,
    [Fp16; 2],
    Vec<Vec<Fp16>>,
    Vec<[Fp16; 2]>,
    [Vec<Fp16>; 2],
);

fn prove_phase_interactive(
    entries: &[Option<Fp16>],
    witness: &StateSquarefreePhaseWitness,
    evaluation_point: Fp16,
    phase: usize,
    layers: &[KeccakDagLayer],
    challenge: &mut impl FnMut(
        StateSquarefreeRoundKind,
        usize,
        usize,
        usize,
        &[Fp16],
    ) -> Result<Fp16, StateSquarefreeGkrError>,
) -> Result<InteractivePhaseResult, StateSquarefreeGkrError> {
    let leaves = dual_leaves(entries, evaluation_point);
    let mut evaluations = Vec::with_capacity(layers.len() + 1);
    evaluations.push(leaves);
    for layer in layers {
        evaluations.push(evaluate_layer(
            layer,
            evaluations.last().expect("leaves exist"),
        )?);
    }
    let final_output = evaluations.last().ok_or(StateSquarefreeGkrError::Shape)?;
    if final_output.len() != 2 {
        return Err(StateSquarefreeGkrError::Shape);
    }
    let product_at_r = final_output[0];
    let derivative_at_r = final_output[1];
    let published_root = [product_at_r, derivative_at_r];
    let root_coefficients = [
        challenge(
            StateSquarefreeRoundKind::RootCombination,
            phase,
            layers.len(),
            0,
            &published_root,
        )?,
        challenge(
            StateSquarefreeRoundKind::RootCombination,
            phase,
            layers.len(),
            1,
            &published_root,
        )?,
    ];
    if root_coefficients.iter().any(|value| value.is_zero()) {
        return Err(StateSquarefreeGkrError::Shape);
    }
    let mut pending = vec![
        LayerOutputClaim {
            point: vec![Fp16::ZERO],
            value: product_at_r,
            coefficient: root_coefficients[0],
        },
        LayerOutputClaim {
            point: vec![Fp16::ONE],
            value: derivative_at_r,
            coefficient: root_coefficients[1],
        },
    ];
    let mut proofs = vec![None; layers.len()];
    let mut tree_challenges = vec![Vec::new(); layers.len()];
    let mut tree_coefficients = vec![[Fp16::ZERO; 2]; layers.len()];
    for index in (0..layers.len()).rev() {
        let (layer_proof, supplied) = prove_two_source_sparse_gkr_layer_interactive(
            &layers[index],
            &evaluations[index],
            &evaluations[index],
            &pending,
            |kind, round, published| {
                let state_kind = match kind {
                    TwoSourceSparseRoundKind::Left => StateSquarefreeRoundKind::TreeLeft,
                    TwoSourceSparseRoundKind::Right => StateSquarefreeRoundKind::TreeRight,
                };
                challenge(state_kind, phase, index, round, published)
                    .map_err(|_| ProductSumcheckError::Claim)
            },
        )?;
        let published = [layer_proof.terminal_left, layer_proof.terminal_right];
        let coefficients = [
            challenge(
                StateSquarefreeRoundKind::TreeClaimCombination,
                phase,
                index,
                0,
                &published,
            )?,
            challenge(
                StateSquarefreeRoundKind::TreeClaimCombination,
                phase,
                index,
                1,
                &published,
            )?,
        ];
        if coefficients.iter().any(|value| value.is_zero()) {
            return Err(StateSquarefreeGkrError::Shape);
        }
        pending = next_claims(&layers[index], &layer_proof, &supplied, coefficients).to_vec();
        proofs[index] = Some(layer_proof);
        tree_challenges[index] = supplied;
        tree_coefficients[index] = coefficients;
    }

    let power_table = powers(evaluation_point, witness.bezout_a.len());
    let mut coefficient_challenges = [Vec::new(), Vec::new()];
    let mut coefficient_proofs = Vec::with_capacity(2);
    for (table, coefficients) in [&witness.bezout_a, &witness.bezout_b]
        .into_iter()
        .enumerate()
    {
        let value = coefficients
            .iter()
            .copied()
            .zip(power_table.iter().copied())
            .fold(Fp16::ZERO, |sum, (coefficient, power)| {
                sum + coefficient * power
            });
        let kind = if table == 0 {
            StateSquarefreeRoundKind::BezoutA
        } else {
            StateSquarefreeRoundKind::BezoutB
        };
        let (claimed, supplied, sumcheck) =
            prove_product_sumcheck_interactive(coefficients, &power_table, |round, published| {
                let mut message = Vec::with_capacity(if round == 0 { 4 } else { 3 });
                if round == 0 {
                    message.push(value);
                }
                message.extend_from_slice(published);
                challenge(kind, phase, layers.len(), round, &message)
                    .map_err(|_| ProductSumcheckError::Claim)
            })?;
        if claimed != value {
            return Err(StateSquarefreeGkrError::Claim);
        }
        coefficient_challenges[table] = supplied.clone();
        coefficient_proofs.push(CoefficientEvaluationProof {
            value,
            challenges: supplied,
            sumcheck,
        });
    }
    if coefficient_proofs[0].value * product_at_r + coefficient_proofs[1].value * derivative_at_r
        != Fp16::ONE
    {
        return Err(StateSquarefreeGkrError::Claim);
    }
    Ok((
        StateSquarefreePhaseProof {
            product_at_r,
            derivative_at_r,
            tree_layers: proofs
                .into_iter()
                .map(|proof| proof.expect("every tree layer proven"))
                .collect(),
            bezout_a: coefficient_proofs.remove(0),
            bezout_b: coefficient_proofs.remove(0),
        },
        root_coefficients,
        tree_challenges,
        tree_coefficients,
        coefficient_challenges,
    ))
}

/// Message-first square-free prover. `beta` must have been sampled after the
/// state commitment, and `evaluation_point` after the four A/B tables were
/// committed. Every later scalar is obtained only after its preceding
/// algebraic message is published.
pub fn prove_state_squarefree_gkr_interactive(
    rows: &[StateRelationRow],
    witness: &StateSquarefreeWitness,
    evaluation_point: Fp16,
    mut challenge: impl FnMut(
        StateSquarefreeRoundKind,
        usize,
        usize,
        usize,
        &[Fp16],
    ) -> Result<Fp16, StateSquarefreeGkrError>,
) -> Result<StateSquarefreeGkrProof, StateSquarefreeGkrError> {
    if evaluation_point.is_zero() || witness.beta.is_zero() {
        return Err(StateSquarefreeGkrError::Shape);
    }
    let layers = dual_product_layers(witness.layout)?;
    let mut phase_proofs = Vec::with_capacity(STATE_SQUAREFREE_PHASES);
    let mut roots = [[Fp16::ZERO; 2]; STATE_SQUAREFREE_PHASES];
    let mut tree_challenges = [Vec::new(), Vec::new()];
    let mut tree_coefficients = [Vec::new(), Vec::new()];
    let mut coefficient_challenges = [[Vec::new(), Vec::new()], [Vec::new(), Vec::new()]];
    for phase in 0..STATE_SQUAREFREE_PHASES {
        let entries = compressed_entries(rows, witness.layout, phase, witness.beta)?;
        let (phase_proof, root, tree, coefficients, coefficient_points) = prove_phase_interactive(
            &entries,
            &witness.phases[phase],
            evaluation_point,
            phase,
            &layers,
            &mut challenge,
        )?;
        phase_proofs.push(phase_proof);
        roots[phase] = root;
        tree_challenges[phase] = tree;
        tree_coefficients[phase] = coefficients;
        coefficient_challenges[phase] = coefficient_points;
    }
    let proof = StateSquarefreeGkrProof {
        layout: witness.layout,
        beta: witness.beta,
        evaluation_point,
        challenges: StateSquarefreeChallengeSet {
            root_coefficients: roots,
            tree_challenges,
            tree_input_coefficients: tree_coefficients,
            coefficient_challenges,
        },
        phases: phase_proofs
            .try_into()
            .map_err(|_| StateSquarefreeGkrError::Shape)?,
    };
    verify_state_squarefree_gkr(&proof)?;
    Ok(proof)
}

fn verify_coefficient_evaluation(
    proof: &CoefficientEvaluationProof,
    point: Fp16,
    length: usize,
) -> Result<MultilinearOpeningClaim, StateSquarefreeGkrError> {
    verify_product_sumcheck(proof.value, &proof.challenges, &proof.sumcheck)?;
    let public_terminal = evaluate_multilinear(&powers(point, length), &proof.challenges)
        .map_err(|_| StateSquarefreeGkrError::Shape)?;
    if proof.sumcheck.terminal_right != public_terminal {
        return Err(StateSquarefreeGkrError::Claim);
    }
    Ok(MultilinearOpeningClaim {
        point: proof.challenges.clone(),
        value: proof.sumcheck.terminal_left,
    })
}

pub fn verify_state_squarefree_gkr(
    proof: &StateSquarefreeGkrProof,
) -> Result<StateSquarefreeInputClaims, StateSquarefreeGkrError> {
    if proof.beta.is_zero() || proof.evaluation_point.is_zero() {
        return Err(StateSquarefreeGkrError::Shape);
    }
    let layers = validate_challenges(proof.layout, &proof.challenges)?;
    let mut virtual_claims = Vec::with_capacity(STATE_SQUAREFREE_PHASES);
    let mut coefficient_claims = Vec::with_capacity(STATE_SQUAREFREE_PHASES);
    for phase in 0..STATE_SQUAREFREE_PHASES {
        let phase_proof = &proof.phases[phase];
        if phase_proof.tree_layers.len() != layers.len()
            || phase_proof.bezout_a.challenges != proof.challenges.coefficient_challenges[phase][0]
            || phase_proof.bezout_b.challenges != proof.challenges.coefficient_challenges[phase][1]
        {
            return Err(StateSquarefreeGkrError::Shape);
        }
        let mut pending = vec![
            LayerOutputClaim {
                point: vec![Fp16::ZERO],
                value: phase_proof.product_at_r,
                coefficient: proof.challenges.root_coefficients[phase][0],
            },
            LayerOutputClaim {
                point: vec![Fp16::ONE],
                value: phase_proof.derivative_at_r,
                coefficient: proof.challenges.root_coefficients[phase][1],
            },
        ];
        for index in (0..layers.len()).rev() {
            verify_two_source_sparse_gkr_layer_reference(
                &layers[index],
                &pending,
                &proof.challenges.tree_challenges[phase][index],
                &phase_proof.tree_layers[index],
            )?;
            pending = next_claims(
                &layers[index],
                &phase_proof.tree_layers[index],
                &proof.challenges.tree_challenges[phase][index],
                proof.challenges.tree_input_coefficients[phase][index],
            )
            .to_vec();
        }
        let a_claim = verify_coefficient_evaluation(
            &phase_proof.bezout_a,
            proof.evaluation_point,
            proof.layout.capacity,
        )?;
        let b_claim = verify_coefficient_evaluation(
            &phase_proof.bezout_b,
            proof.evaluation_point,
            proof.layout.capacity,
        )?;
        if phase_proof.bezout_a.value * phase_proof.product_at_r
            + phase_proof.bezout_b.value * phase_proof.derivative_at_r
            != Fp16::ONE
        {
            return Err(StateSquarefreeGkrError::Claim);
        }
        virtual_claims.push(
            pending
                .try_into()
                .map_err(|_| StateSquarefreeGkrError::Shape)?,
        );
        coefficient_claims.push([a_claim, b_claim]);
    }
    Ok(StateSquarefreeInputClaims {
        virtual_leaf_claims: virtual_claims
            .try_into()
            .map_err(|_| StateSquarefreeGkrError::Shape)?,
        coefficient_claims: coefficient_claims
            .try_into()
            .map_err(|_| StateSquarefreeGkrError::Shape)?,
    })
}

/// Reduce every virtual dual-leaf terminal to three openings of the existing
/// state relation source.  High group coordinates are fixed to zero because
/// K128/K512 occupy the canonical prefix of the 4096-row H4 state lane.
pub fn state_squarefree_state_reductions(
    proof: &StateSquarefreeGkrProof,
) -> Result<[[StateSquarefreeStateReduction; 2]; STATE_SQUAREFREE_PHASES], StateSquarefreeGkrError>
{
    let claims = verify_state_squarefree_gkr(proof)?;
    let row_variables = proof.layout.capacity.ilog2() as usize;
    let mut phases = Vec::with_capacity(STATE_SQUAREFREE_PHASES);
    for phase in 0..STATE_SQUAREFREE_PHASES {
        let wires = if phase == 0 {
            [BEFORE_PRESENT_WIRE, BEFORE_KEY_WIRE, BEFORE_KEY_WIRE + 1]
        } else {
            [AFTER_PRESENT_WIRE, AFTER_KEY_WIRE, AFTER_KEY_WIRE + 1]
        };
        let mut reductions = Vec::with_capacity(2);
        for claim in &claims.virtual_leaf_claims[phase] {
            if claim.point.len() != row_variables + 1 {
                return Err(StateSquarefreeGkrError::Shape);
            }
            let wire = claim.point[0];
            let factor_weight = Fp16::ONE - wire;
            let mut row_point = claim.point[1..].to_vec();
            row_point.resize(STATE_SQUAREFREE_STATE_GROUP_VARIABLES, Fp16::ZERO);
            reductions.push(StateSquarefreeStateReduction {
                phase: phase as u8,
                row_point,
                state_wires: wires,
                affine_coefficients: [
                    factor_weight,
                    factor_weight * (proof.evaluation_point - Fp16::ONE) + wire,
                    -factor_weight,
                    -(factor_weight * proof.beta),
                ],
                expected_value: claim.value,
                gkr_coefficient: claim.coefficient,
            });
        }
        phases.push(
            reductions
                .try_into()
                .map_err(|_| StateSquarefreeGkrError::Shape)?,
        );
    }
    phases
        .try_into()
        .map_err(|_| StateSquarefreeGkrError::Shape)
}

/// Control-only readback for the PCS claims returned by the verifier.
pub fn verify_state_squarefree_control_openings(
    rows: &[StateRelationRow],
    witness: &StateSquarefreeWitness,
    proof: &StateSquarefreeGkrProof,
) -> Result<(), StateSquarefreeGkrError> {
    if witness.layout != proof.layout || witness.beta != proof.beta {
        return Err(StateSquarefreeGkrError::Shape);
    }
    let claims = verify_state_squarefree_gkr(proof)?;
    let reductions = state_squarefree_state_reductions(proof)?;
    for (phase, phase_reductions) in reductions.iter().enumerate() {
        let entries = compressed_entries(rows, proof.layout, phase, proof.beta)?;
        let leaves = dual_leaves(&entries, proof.evaluation_point);
        for (claim_index, claim) in claims.virtual_leaf_claims[phase].iter().enumerate() {
            if evaluate_multilinear(&leaves, &claim.point)
                .map_err(|_| StateSquarefreeGkrError::Shape)?
                != claim.value
            {
                return Err(StateSquarefreeGkrError::Claim);
            }
            let mut presence = vec![Fp16::ZERO; proof.layout.capacity];
            let mut key_0 = vec![Fp16::ZERO; proof.layout.capacity];
            let mut key_1 = vec![Fp16::ZERO; proof.layout.capacity];
            for (index, row) in rows.iter().copied().enumerate() {
                let entry = phase_entry(row, phase);
                if entry.present {
                    let packed =
                        pack_chunks(&entry.key).map_err(|_| StateSquarefreeGkrError::Encoding)?;
                    presence[index] = Fp16::ONE;
                    key_0[index] = packed[0];
                    key_1[index] = packed[1];
                }
            }
            let short_point =
                &phase_reductions[claim_index].row_point[..proof.layout.capacity.ilog2() as usize];
            let opened = [
                evaluate_multilinear(&presence, short_point)
                    .map_err(|_| StateSquarefreeGkrError::Shape)?,
                evaluate_multilinear(&key_0, short_point)
                    .map_err(|_| StateSquarefreeGkrError::Shape)?,
                evaluate_multilinear(&key_1, short_point)
                    .map_err(|_| StateSquarefreeGkrError::Shape)?,
            ];
            let reduction = &phase_reductions[claim_index];
            let reduced = reduction.affine_coefficients[0]
                + reduction.affine_coefficients[1] * opened[0]
                + reduction.affine_coefficients[2] * opened[1]
                + reduction.affine_coefficients[3] * opened[2];
            if reduced != reduction.expected_value {
                return Err(StateSquarefreeGkrError::Claim);
            }
        }
        for (table, coefficients) in [
            &witness.phases[phase].bezout_a,
            &witness.phases[phase].bezout_b,
        ]
        .into_iter()
        .enumerate()
        {
            let claim = &claims.coefficient_claims[phase][table];
            if evaluate_multilinear(coefficients, &claim.point)
                .map_err(|_| StateSquarefreeGkrError::Shape)?
                != claim.value
            {
                return Err(StateSquarefreeGkrError::Claim);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(value: u32) -> Fp16 {
        Fp16::from_m31(M31::from_canonical(value % M31_MODULUS).unwrap())
    }

    fn entry(index: usize, seed: u16) -> StateRelationEntry {
        let mut key = [0_u8; 64];
        let mut value = [0_u8; 64];
        key[62..].copy_from_slice(&seed.to_be_bytes());
        value[62..].copy_from_slice(&seed.wrapping_add(31).to_be_bytes());
        StateRelationEntry {
            index: index as u32,
            present: true,
            key,
            value,
        }
    }

    fn rows(capacity: usize) -> Vec<StateRelationRow> {
        (0..capacity)
            .map(|index| {
                let before = entry(index, index as u16 + 1);
                let after = entry(index, index as u16 + 101);
                StateRelationRow {
                    operation_before: before,
                    operation_after: after,
                    snapshot_before: before,
                    snapshot_after: after,
                }
            })
            .collect()
    }

    #[test]
    fn squarefree_control_proves_and_exposes_four_reduced_claims_per_phase() {
        let layout = StateSquarefreeLayout::new(8).unwrap();
        let rows = rows(8);
        let witness = build_state_squarefree_witness(&rows, layout, fp(17)).unwrap();
        let proof = prove_state_squarefree_gkr_control(
            &rows,
            &witness,
            fp(29),
            state_squarefree_control_challenges(layout).unwrap(),
        )
        .unwrap();
        let claims = verify_state_squarefree_gkr(&proof).unwrap();
        verify_state_squarefree_control_openings(&rows, &witness, &proof).unwrap();
        for phase in 0..STATE_SQUAREFREE_PHASES {
            assert_eq!(claims.virtual_leaf_claims[phase].len(), 2);
            assert_eq!(claims.coefficient_claims[phase].len(), 2);
        }
    }

    #[test]
    fn duplicate_present_key_is_rejected_before_witness_commitment() {
        let layout = StateSquarefreeLayout::new(8).unwrap();
        let mut duplicate = rows(8);
        duplicate[3].operation_after.key = duplicate[2].operation_after.key;
        duplicate[3].snapshot_after.key = duplicate[2].snapshot_after.key;
        assert_eq!(
            build_state_squarefree_witness(&duplicate, layout, fp(17)),
            Err(StateSquarefreeGkrError::DuplicateKey)
        );
    }

    #[test]
    fn forged_duplicate_cannot_satisfy_bezout_identity() {
        let layout = StateSquarefreeLayout::new(8).unwrap();
        let mut duplicate = rows(8);
        duplicate[3].operation_before.key = duplicate[2].operation_before.key;
        duplicate[3].snapshot_before.key = duplicate[2].snapshot_before.key;
        let entries = compressed_entries(&duplicate, layout, 0, fp(17)).unwrap_err();
        assert_eq!(entries, StateSquarefreeGkrError::DuplicateKey);

        let repeated = vec![Some(fp(5)), Some(fp(5)), None, None, None, None, None, None];
        let polynomial = product_polynomial(&repeated);
        assert_eq!(
            bezout_for_squarefree(&polynomial),
            Err(StateSquarefreeGkrError::DuplicateKey)
        );
    }

    #[test]
    fn mutation_of_tree_or_coefficient_terminal_rejects() {
        let layout = StateSquarefreeLayout::new(8).unwrap();
        let rows = rows(8);
        let witness = build_state_squarefree_witness(&rows, layout, fp(17)).unwrap();
        let proof = prove_state_squarefree_gkr_control(
            &rows,
            &witness,
            fp(29),
            state_squarefree_control_challenges(layout).unwrap(),
        )
        .unwrap();
        let mut tree = proof.clone();
        tree.phases[0].tree_layers[0].terminal_left =
            tree.phases[0].tree_layers[0].terminal_left + Fp16::ONE;
        assert!(verify_state_squarefree_gkr(&tree).is_err());
        let mut coefficient = proof;
        coefficient.phases[1].bezout_b.sumcheck.terminal_left =
            coefficient.phases[1].bezout_b.sumcheck.terminal_left + Fp16::ONE;
        assert!(verify_state_squarefree_gkr(&coefficient).is_err());
    }

    #[test]
    fn interactive_squarefree_releases_every_challenge_after_a_message() {
        let layout = StateSquarefreeLayout::new(8).unwrap();
        let rows = rows(8);
        let witness = build_state_squarefree_witness(&rows, layout, fp(17)).unwrap();
        let mut counter = 7_001_u32;
        let mut messages = Vec::new();
        let proof = prove_state_squarefree_gkr_interactive(
            &rows,
            &witness,
            fp(29),
            |kind, phase, layer, round, published| {
                assert!(!published.is_empty());
                messages.push((kind, phase, layer, round, published.len()));
                counter += 1;
                Ok(fp(counter))
            },
        )
        .unwrap();
        verify_state_squarefree_control_openings(&rows, &witness, &proof).unwrap();
        assert!(messages.iter().any(|message| {
            matches!(
                message.0,
                StateSquarefreeRoundKind::BezoutA | StateSquarefreeRoundKind::BezoutB
            ) && message.4 == 4
        }));
        assert_eq!(
            messages
                .iter()
                .filter(|message| message.0 == StateSquarefreeRoundKind::RootCombination)
                .count(),
            2 * STATE_SQUAREFREE_PHASES
        );
    }
}
