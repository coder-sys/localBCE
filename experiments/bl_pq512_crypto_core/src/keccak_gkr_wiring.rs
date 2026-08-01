//! Exact adjacent-layer wiring for the graph-free Keccak GKR circuit.

use alloc::{vec, vec::Vec};
use sha3::{Digest, Sha3_512};

use crate::keccak_circuit::{KeccakCircuitError, KeccakLayerKind, ROUND_LAYERS};
use crate::sha3_air::{ROTATION_OFFSETS, ROUND_CONSTANTS};

const STATE_BITS: usize = 1_600;
const COLUMN_BITS: usize = 320;
const WIRING_DOMAIN: &[u8] = b"BL/PQ512/KECCAK-GKR-WIRING/v1\0";
pub const KECCAK_GKR_LAYERS_PER_ROUND: usize = 9;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BooleanWire {
    Previous(usize),
    Constant(bool),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BooleanGateKind {
    Xor,
    And,
    Relay,
    Zero,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BooleanGate {
    pub kind: BooleanGateKind,
    pub left: BooleanWire,
    pub right: BooleanWire,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeccakGkrLayer {
    pub kind: KeccakLayerKind,
    pub input_width: usize,
    pub raw_width: usize,
    pub padded_width: usize,
    pub gates: Vec<BooleanGate>,
}

fn bit(x: usize, y: usize, z: usize) -> usize {
    64 * (x + 5 * y) + z
}

fn column(x: usize, z: usize) -> usize {
    64 * x + z
}

fn previous(index: usize) -> BooleanWire {
    BooleanWire::Previous(index)
}

fn xor(left: usize, right: usize) -> BooleanGate {
    BooleanGate {
        kind: BooleanGateKind::Xor,
        left: previous(left),
        right: previous(right),
    }
}

fn and(left: usize, right: usize) -> BooleanGate {
    BooleanGate {
        kind: BooleanGateKind::And,
        left: previous(left),
        right: previous(right),
    }
}

fn relay(index: usize) -> BooleanGate {
    BooleanGate {
        kind: BooleanGateKind::Relay,
        left: previous(index),
        right: BooleanWire::Constant(false),
    }
}

fn xor_constant(index: usize, value: bool) -> BooleanGate {
    BooleanGate {
        kind: BooleanGateKind::Xor,
        left: previous(index),
        right: BooleanWire::Constant(value),
    }
}

fn zero() -> BooleanGate {
    BooleanGate {
        kind: BooleanGateKind::Zero,
        left: BooleanWire::Constant(false),
        right: BooleanWire::Constant(false),
    }
}

fn finish_layer(
    ordinal: usize,
    input_width: usize,
    mut gates: Vec<BooleanGate>,
) -> Result<KeccakGkrLayer, KeccakCircuitError> {
    let descriptor = ROUND_LAYERS.get(ordinal).ok_or(KeccakCircuitError::Round)?;
    if gates.len() != descriptor.raw_width {
        return Err(KeccakCircuitError::Overflow);
    }
    gates.resize(descriptor.padded_width, zero());
    Ok(KeccakGkrLayer {
        kind: descriptor.kind,
        input_width,
        raw_width: descriptor.raw_width,
        padded_width: descriptor.padded_width,
        gates,
    })
}

fn rho_pi_inverse() -> Vec<usize> {
    let mut inverse = vec![usize::MAX; STATE_BITS];
    for (x, rotations) in ROTATION_OFFSETS.iter().enumerate() {
        for (y, rotation) in rotations.iter().copied().enumerate() {
            let destination_x = y;
            let destination_y = (2 * x + 3 * y) % 5;
            let rotation = rotation as usize;
            for z in 0..64 {
                let destination_z = (z + rotation) % 64;
                inverse[bit(destination_x, destination_y, destination_z)] = bit(x, y, z);
            }
        }
    }
    inverse
}

pub fn build_keccak_gkr_round(round: usize) -> Result<[KeccakGkrLayer; 9], KeccakCircuitError> {
    let round_constant = *ROUND_CONSTANTS
        .get(round)
        .ok_or(KeccakCircuitError::Round)?;

    let mut theta_pairs = Vec::with_capacity(2 * COLUMN_BITS + STATE_BITS);
    for x in 0..5 {
        for pair in 0..2 {
            for z in 0..64 {
                theta_pairs.push(xor(bit(x, 2 * pair, z), bit(x, 2 * pair + 1, z)));
            }
        }
    }
    theta_pairs.extend((0..STATE_BITS).map(relay));
    let layer0 = finish_layer(0, 2_048, theta_pairs)?;

    let mut pair_parity = Vec::with_capacity(COLUMN_BITS + STATE_BITS);
    for x in 0..5 {
        for z in 0..64 {
            pair_parity.push(xor(column(2 * x, z), column(2 * x + 1, z)));
        }
    }
    pair_parity.extend((0..STATE_BITS).map(|index| relay(2 * COLUMN_BITS + index)));
    let layer1 = finish_layer(1, layer0.padded_width, pair_parity)?;

    let mut column_parity = Vec::with_capacity(COLUMN_BITS + STATE_BITS);
    for x in 0..5 {
        for z in 0..64 {
            column_parity.push(xor(column(x, z), COLUMN_BITS + bit(x, 4, z)));
        }
    }
    column_parity.extend((0..STATE_BITS).map(|index| relay(COLUMN_BITS + index)));
    let layer2 = finish_layer(2, layer1.padded_width, column_parity)?;

    let mut delta = Vec::with_capacity(COLUMN_BITS + STATE_BITS);
    for x in 0..5 {
        for z in 0..64 {
            delta.push(xor(
                column((x + 4) % 5, z),
                column((x + 1) % 5, (z + 63) % 64),
            ));
        }
    }
    delta.extend((0..STATE_BITS).map(|index| relay(COLUMN_BITS + index)));
    let layer3 = finish_layer(3, layer2.padded_width, delta)?;

    let mut theta_state = Vec::with_capacity(STATE_BITS);
    for y in 0..5 {
        for x in 0..5 {
            for z in 0..64 {
                theta_state.push(xor(COLUMN_BITS + bit(x, y, z), column(x, z)));
            }
        }
    }
    let layer4 = finish_layer(4, layer3.padded_width, theta_state)?;

    let inverse = rho_pi_inverse();
    if inverse.contains(&usize::MAX) {
        return Err(KeccakCircuitError::Overflow);
    }
    let mut chi_and = Vec::with_capacity(2 * STATE_BITS);
    for y in 0..5 {
        for x in 0..5 {
            for z in 0..64 {
                chi_and.push(and(
                    inverse[bit((x + 1) % 5, y, z)],
                    inverse[bit((x + 2) % 5, y, z)],
                ));
            }
        }
    }
    chi_and.extend(inverse.iter().copied().map(relay));
    let layer5 = finish_layer(5, layer4.padded_width, chi_and)?;

    let mut chi_mask = Vec::with_capacity(2 * STATE_BITS);
    for y in 0..5 {
        for x in 0..5 {
            for z in 0..64 {
                chi_mask.push(xor(STATE_BITS + bit((x + 2) % 5, y, z), bit(x, y, z)));
            }
        }
    }
    chi_mask.extend((0..STATE_BITS).map(|index| relay(STATE_BITS + index)));
    let layer6 = finish_layer(6, layer5.padded_width, chi_mask)?;

    let chi_output = (0..STATE_BITS)
        .map(|index| xor(STATE_BITS + index, index))
        .collect();
    let layer7 = finish_layer(7, layer6.padded_width, chi_output)?;

    let iota = (0..STATE_BITS)
        .map(|index| {
            let constant = index < 64 && ((round_constant >> index) & 1) == 1;
            xor_constant(index, constant)
        })
        .collect();
    let layer8 = finish_layer(8, layer7.padded_width, iota)?;

    Ok([
        layer0, layer1, layer2, layer3, layer4, layer5, layer6, layer7, layer8,
    ])
}

pub fn build_keccak_gkr_circuit() -> Result<Vec<KeccakGkrLayer>, KeccakCircuitError> {
    let mut layers = Vec::with_capacity(24 * 9);
    for round in 0..24 {
        layers.extend(build_keccak_gkr_round(round)?);
    }
    if layers.len() != 216
        || layers
            .windows(2)
            .any(|pair| pair[0].padded_width != pair[1].input_width)
    {
        return Err(KeccakCircuitError::Overflow);
    }
    Ok(layers)
}

fn encode_wire(hash: &mut Sha3_512, wire: BooleanWire) {
    match wire {
        BooleanWire::Previous(index) => {
            hash.update([0]);
            hash.update(index.to_be_bytes());
        }
        BooleanWire::Constant(value) => hash.update([1, u8::from(value)]),
    }
}

/// Commit every gate, public constant, relay, and padding position.
pub fn keccak_gkr_wiring_commitment() -> Result<[u8; 64], KeccakCircuitError> {
    let mut hash = Sha3_512::new();
    hash.update(WIRING_DOMAIN);
    hash.update(24_u16.to_be_bytes());
    for round in 0..24 {
        hash.update((round as u16).to_be_bytes());
        for (ordinal, layer) in build_keccak_gkr_round(round)?.iter().enumerate() {
            hash.update((ordinal as u16).to_be_bytes());
            hash.update([layer.kind as u8]);
            hash.update(layer.input_width.to_be_bytes());
            hash.update(layer.raw_width.to_be_bytes());
            hash.update(layer.padded_width.to_be_bytes());
            for gate in &layer.gates {
                hash.update([match gate.kind {
                    BooleanGateKind::Xor => 0,
                    BooleanGateKind::And => 1,
                    BooleanGateKind::Relay => 2,
                    BooleanGateKind::Zero => 3,
                }]);
                encode_wire(&mut hash, gate.left);
                encode_wire(&mut hash, gate.right);
            }
        }
    }
    Ok(hash.finalize().into())
}

fn wire_value(wire: BooleanWire, input: &[bool]) -> Result<bool, KeccakCircuitError> {
    match wire {
        BooleanWire::Previous(index) => input
            .get(index)
            .copied()
            .ok_or(KeccakCircuitError::Overflow),
        BooleanWire::Constant(value) => Ok(value),
    }
}

pub fn evaluate_keccak_gkr_layer(
    layer: &KeccakGkrLayer,
    input: &[bool],
) -> Result<Vec<bool>, KeccakCircuitError> {
    if input.len() != layer.input_width || layer.gates.len() != layer.padded_width {
        return Err(KeccakCircuitError::Overflow);
    }
    layer
        .gates
        .iter()
        .map(|gate| {
            let left = wire_value(gate.left, input)?;
            let right = wire_value(gate.right, input)?;
            Ok(match gate.kind {
                BooleanGateKind::Xor => left ^ right,
                BooleanGateKind::And => left & right,
                BooleanGateKind::Relay => left,
                BooleanGateKind::Zero => false,
            })
        })
        .collect()
}

fn packed_wire_value(
    wire: BooleanWire,
    input: &[u64],
    words: usize,
    word: usize,
    constant_mask: u64,
) -> Result<u64, KeccakCircuitError> {
    match wire {
        BooleanWire::Previous(index) => input
            .get(index * words + word)
            .copied()
            .ok_or(KeccakCircuitError::Overflow),
        BooleanWire::Constant(value) => Ok(if value { constant_mask } else { 0 }),
    }
}

/// Evaluate one public Boolean layer over bit-packed independent permutations.
pub fn evaluate_packed_keccak_gkr_layer(
    layer: &KeccakGkrLayer,
    input: &[u64],
    instances: usize,
) -> Result<Vec<u64>, KeccakCircuitError> {
    if instances == 0 {
        return Err(KeccakCircuitError::Overflow);
    }
    let words = instances.div_ceil(64);
    if input.len() != layer.input_width * words || layer.gates.len() != layer.padded_width {
        return Err(KeccakCircuitError::Overflow);
    }
    let mut output = vec![0_u64; layer.padded_width * words];
    for (gate_index, gate) in layer.gates.iter().enumerate() {
        for word in 0..words {
            let constant_mask = if word + 1 < words || instances.is_multiple_of(64) {
                u64::MAX
            } else {
                (1_u64 << (instances % 64)) - 1
            };
            let left = packed_wire_value(gate.left, input, words, word, constant_mask)?;
            let right = packed_wire_value(gate.right, input, words, word, constant_mask)?;
            output[gate_index * words + word] = match gate.kind {
                BooleanGateKind::Xor => left ^ right,
                BooleanGateKind::And => left & right,
                BooleanGateKind::Relay => left,
                BooleanGateKind::Zero => 0,
            };
        }
    }
    Ok(output)
}

/// Retain only the packed circuit input and one packed state after each round.
///
/// The schedule always evaluates exactly nine public layers per round. No
/// witness value affects allocation, traversal, checkpoint selection, or
/// cleanup.
pub fn packed_keccak_gkr_round_checkpoints(
    layers: &[KeccakGkrLayer],
    input: &[u64],
    instances: usize,
) -> Result<Vec<Vec<u64>>, KeccakCircuitError> {
    if layers.is_empty()
        || !layers.len().is_multiple_of(KECCAK_GKR_LAYERS_PER_ROUND)
        || input.len() != layers[0].input_width * instances.div_ceil(64)
    {
        return Err(KeccakCircuitError::Overflow);
    }
    let mut checkpoints = Vec::with_capacity(layers.len() / KECCAK_GKR_LAYERS_PER_ROUND + 1);
    let mut values = input.to_vec();
    checkpoints.push(values.clone());
    for round_layers in layers.chunks_exact(KECCAK_GKR_LAYERS_PER_ROUND) {
        for layer in round_layers {
            values = evaluate_packed_keccak_gkr_layer(layer, &values, instances)?;
        }
        checkpoints.push(values.clone());
    }
    Ok(checkpoints)
}

/// Regenerate the nine packed inputs consumed by one round's reverse walk.
///
/// The returned entries are the round checkpoint followed by the first eight
/// layer outputs. The ninth output is the next retained checkpoint.
pub fn regenerate_packed_keccak_gkr_round_inputs(
    round_layers: &[KeccakGkrLayer],
    checkpoint: &[u64],
    instances: usize,
) -> Result<Vec<Vec<u64>>, KeccakCircuitError> {
    if round_layers.len() != KECCAK_GKR_LAYERS_PER_ROUND
        || checkpoint.len() != round_layers[0].input_width * instances.div_ceil(64)
    {
        return Err(KeccakCircuitError::Overflow);
    }
    let mut inputs = Vec::with_capacity(KECCAK_GKR_LAYERS_PER_ROUND);
    let mut values = checkpoint.to_vec();
    inputs.push(values.clone());
    for layer in &round_layers[..KECCAK_GKR_LAYERS_PER_ROUND - 1] {
        values = evaluate_packed_keccak_gkr_layer(layer, &values, instances)?;
        inputs.push(values.clone());
    }
    Ok(inputs)
}

/// Execute the exact 216-layer circuit and expose each packed layer boundary.
///
/// The callback slice is valid only for the duration of the call.
pub fn execute_packed_keccak_gkr_circuit(
    states: &mut [[u64; 25]],
    mut layer_boundary: impl FnMut(usize, usize, &KeccakGkrLayer, &[u64]),
) -> Result<(), KeccakCircuitError> {
    if states.is_empty() {
        return Err(KeccakCircuitError::Overflow);
    }
    let instances = states.len();
    let words = instances.div_ceil(64);
    let mut values = vec![0_u64; 2_048 * words];
    for (instance, state) in states.iter().enumerate() {
        let word = instance / 64;
        let bit_in_word = instance % 64;
        for (lane, value) in state.iter().copied().enumerate() {
            for z in 0..64 {
                values[(64 * lane + z) * words + word] |= ((value >> z) & 1) << bit_in_word;
            }
        }
    }
    for round in 0..24 {
        for (ordinal, layer) in build_keccak_gkr_round(round)?.iter().enumerate() {
            values = evaluate_packed_keccak_gkr_layer(layer, &values, instances)?;
            layer_boundary(round, ordinal, layer, &values);
        }
    }
    for (instance, state) in states.iter_mut().enumerate() {
        let word = instance / 64;
        let bit_in_word = instance % 64;
        for (lane, value) in state.iter_mut().enumerate() {
            *value = (0..64).fold(0_u64, |accumulator, z| {
                accumulator | (((values[(64 * lane + z) * words + word] >> bit_in_word) & 1) << z)
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keccak_circuit::execute_layered_keccak_round;
    use crate::sha3_air::keccak_f1600_round;

    fn state_bits(state: &[u64; 25]) -> Vec<bool> {
        let mut bits = vec![false; 2_048];
        for (lane, value) in state.iter().copied().enumerate() {
            for z in 0..64 {
                bits[64 * lane + z] = ((value >> z) & 1) == 1;
            }
        }
        bits
    }

    fn bits_state(bits: &[bool]) -> [u64; 25] {
        core::array::from_fn(|lane| {
            (0..64).fold(0_u64, |value, z| {
                value | (u64::from(bits[64 * lane + z]) << z)
            })
        })
    }

    #[test]
    fn all_nine_layers_match_the_independent_round() {
        for round in 0..24 {
            let original = core::array::from_fn(|lane| {
                (lane as u64 + 1)
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    .rotate_left(round as u32)
            });
            let mut expected = original;
            execute_layered_keccak_round(&mut expected, round).unwrap();
            let mut values = state_bits(&original);
            let layers = build_keccak_gkr_round(round).unwrap();
            for (ordinal, layer) in layers.iter().enumerate() {
                assert_eq!(layer.kind, ROUND_LAYERS[ordinal].kind);
                assert_eq!(layer.raw_width, ROUND_LAYERS[ordinal].raw_width);
                assert_eq!(layer.padded_width, ROUND_LAYERS[ordinal].padded_width);
                values = evaluate_keccak_gkr_layer(layer, &values).unwrap();
                assert!(values[layer.raw_width..].iter().all(|value| !value));
            }
            assert_eq!(bits_state(&values), expected);
        }
        let circuit = build_keccak_gkr_circuit().unwrap();
        assert_eq!(circuit.len(), 216);
        assert!(
            circuit
                .windows(2)
                .all(|pair| pair[0].padded_width == pair[1].input_width)
        );
    }

    #[test]
    fn invalid_round_and_shapes_fail_closed() {
        assert_eq!(build_keccak_gkr_round(24), Err(KeccakCircuitError::Round));
        let layer = build_keccak_gkr_round(0).unwrap()[0].clone();
        assert_eq!(
            evaluate_keccak_gkr_layer(&layer, &[false; 1]),
            Err(KeccakCircuitError::Overflow)
        );
        assert_ne!(keccak_gkr_wiring_commitment().unwrap(), [0_u8; 64]);
    }

    #[test]
    fn packed_all_layer_boundaries_match_scalar_keccak() {
        let mut observed: Vec<[u64; 25]> = (0..65)
            .map(|instance| {
                core::array::from_fn(|lane| {
                    (instance as u64 + 1)
                        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                        .rotate_left(lane as u32)
                })
            })
            .collect();
        let mut expected = observed.clone();
        let mut boundaries = 0;
        execute_packed_keccak_gkr_circuit(&mut observed, |round, ordinal, layer, values| {
            boundaries += 1;
            assert_eq!(values.len(), layer.padded_width * 2);
            assert_eq!(layer.kind, ROUND_LAYERS[ordinal].kind);
            if ordinal == 8 {
                for state in &mut expected {
                    keccak_f1600_round(state, round).unwrap();
                }
            }
        })
        .unwrap();
        assert_eq!(boundaries, 216);
        assert_eq!(observed, expected);
    }
}
