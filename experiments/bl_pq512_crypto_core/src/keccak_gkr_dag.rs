//! Relay-free Keccak round DAG for the repeated Boolean GKR candidate.
//!
//! The adjacent-layer control carries live state through explicit relay gates.
//! This candidate instead gives every layer two public source boundaries. A
//! GKR proof over the DAG must return one authenticated opening claim to each
//! source; no source value is trusted or copied by the host.

use alloc::{vec, vec::Vec};

use crate::{
    keccak_circuit::KeccakCircuitError,
    sha3_air::{ROTATION_OFFSETS, ROUND_CONSTANTS},
};

const STATE_BITS: usize = 1_600;
const COLUMN_BITS: usize = 320;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeccakDagSource {
    RoundInput,
    Layer(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeccakDagGateKind {
    Xor,
    NotLeftAndRight,
    XorConstant(bool),
    /// Field subtraction for non-Boolean statement relations.
    ///
    /// The selected Keccak plan never emits this gate.  It is kept in the
    /// shared DAG algebra so a proof-native state relation can compare packed
    /// canonical chunks without expanding every byte into Boolean wires.
    Subtract,
    Zero,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeccakDagGate {
    pub left: usize,
    pub right: usize,
    pub kind: KeccakDagGateKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeccakDagLayer {
    pub left_source: KeccakDagSource,
    pub right_source: KeccakDagSource,
    pub left_width: usize,
    pub right_width: usize,
    pub raw_width: usize,
    pub padded_width: usize,
    pub gates: Vec<KeccakDagGate>,
}

fn bit(x: usize, y: usize, z: usize) -> usize {
    64 * (x + 5 * y) + z
}

fn column(x: usize, z: usize) -> usize {
    64 * x + z
}

fn pair(x: usize, pair: usize, z: usize) -> usize {
    128 * x + 64 * pair + z
}

fn gate(left: usize, right: usize, kind: KeccakDagGateKind) -> KeccakDagGate {
    KeccakDagGate { left, right, kind }
}

fn finish_layer(
    left_source: KeccakDagSource,
    right_source: KeccakDagSource,
    left_width: usize,
    right_width: usize,
    mut gates: Vec<KeccakDagGate>,
) -> Result<KeccakDagLayer, KeccakCircuitError> {
    if gates.is_empty()
        || !left_width.is_power_of_two()
        || !right_width.is_power_of_two()
        || gates
            .iter()
            .any(|gate| gate.left >= left_width || gate.right >= right_width)
    {
        return Err(KeccakCircuitError::Overflow);
    }
    let raw_width = gates.len();
    let padded_width = raw_width.next_power_of_two();
    gates.resize(padded_width, gate(0, 0, KeccakDagGateKind::Zero));
    Ok(KeccakDagLayer {
        left_source,
        right_source,
        left_width,
        right_width,
        raw_width,
        padded_width,
        gates,
    })
}

fn rho_pi_inverse() -> Result<Vec<usize>, KeccakCircuitError> {
    let mut inverse = vec![usize::MAX; STATE_BITS];
    for (x, rotations) in ROTATION_OFFSETS.iter().enumerate() {
        for (y, rotation) in rotations.iter().copied().enumerate() {
            let destination_x = y;
            let destination_y = (2 * x + 3 * y) % 5;
            for z in 0..64 {
                let destination_z = (z + rotation as usize) % 64;
                inverse[bit(destination_x, destination_y, destination_z)] = bit(x, y, z);
            }
        }
    }
    if inverse.contains(&usize::MAX) {
        return Err(KeccakCircuitError::Overflow);
    }
    Ok(inverse)
}

/// Build the exact seven-layer relay-free DAG for one FIPS 202 Keccak round.
///
/// The layers are:
/// pair XOR, pair parity, five-row column parity, theta delta, theta state,
/// chi mask, and chi output plus iota.
pub fn build_keccak_gkr_dag_round(round: usize) -> Result<[KeccakDagLayer; 7], KeccakCircuitError> {
    let round_constant = *ROUND_CONSTANTS
        .get(round)
        .ok_or(KeccakCircuitError::Round)?;

    let mut pairs = Vec::with_capacity(2 * COLUMN_BITS);
    for x in 0..5 {
        for pair_index in 0..2 {
            for z in 0..64 {
                pairs.push(gate(
                    bit(x, 2 * pair_index, z),
                    bit(x, 2 * pair_index + 1, z),
                    KeccakDagGateKind::Xor,
                ));
            }
        }
    }
    let layer0 = finish_layer(
        KeccakDagSource::RoundInput,
        KeccakDagSource::RoundInput,
        2_048,
        2_048,
        pairs,
    )?;

    let mut pair_parity = Vec::with_capacity(COLUMN_BITS);
    for x in 0..5 {
        for z in 0..64 {
            pair_parity.push(gate(pair(x, 0, z), pair(x, 1, z), KeccakDagGateKind::Xor));
        }
    }
    let layer1 = finish_layer(
        KeccakDagSource::Layer(0),
        KeccakDagSource::Layer(0),
        layer0.padded_width,
        layer0.padded_width,
        pair_parity,
    )?;

    let mut column_parity = Vec::with_capacity(COLUMN_BITS);
    for x in 0..5 {
        for z in 0..64 {
            column_parity.push(gate(column(x, z), bit(x, 4, z), KeccakDagGateKind::Xor));
        }
    }
    let layer2 = finish_layer(
        KeccakDagSource::Layer(1),
        KeccakDagSource::RoundInput,
        layer1.padded_width,
        2_048,
        column_parity,
    )?;

    let mut delta = Vec::with_capacity(COLUMN_BITS);
    for x in 0..5 {
        for z in 0..64 {
            delta.push(gate(
                column((x + 4) % 5, z),
                column((x + 1) % 5, (z + 63) % 64),
                KeccakDagGateKind::Xor,
            ));
        }
    }
    let layer3 = finish_layer(
        KeccakDagSource::Layer(2),
        KeccakDagSource::Layer(2),
        layer2.padded_width,
        layer2.padded_width,
        delta,
    )?;

    let mut theta_state = Vec::with_capacity(STATE_BITS);
    for y in 0..5 {
        for x in 0..5 {
            for z in 0..64 {
                theta_state.push(gate(bit(x, y, z), column(x, z), KeccakDagGateKind::Xor));
            }
        }
    }
    let layer4 = finish_layer(
        KeccakDagSource::RoundInput,
        KeccakDagSource::Layer(3),
        2_048,
        layer3.padded_width,
        theta_state,
    )?;

    let inverse = rho_pi_inverse()?;
    let mut chi_mask = Vec::with_capacity(STATE_BITS);
    for y in 0..5 {
        for x in 0..5 {
            for z in 0..64 {
                chi_mask.push(gate(
                    inverse[bit((x + 1) % 5, y, z)],
                    inverse[bit((x + 2) % 5, y, z)],
                    KeccakDagGateKind::NotLeftAndRight,
                ));
            }
        }
    }
    let layer5 = finish_layer(
        KeccakDagSource::Layer(4),
        KeccakDagSource::Layer(4),
        layer4.padded_width,
        layer4.padded_width,
        chi_mask,
    )?;

    let mut output = Vec::with_capacity(STATE_BITS);
    for (index, input_index) in inverse.iter().copied().enumerate() {
        let constant = index < 64 && ((round_constant >> index) & 1) == 1;
        output.push(gate(
            input_index,
            index,
            KeccakDagGateKind::XorConstant(constant),
        ));
    }
    let layer6 = finish_layer(
        KeccakDagSource::Layer(4),
        KeccakDagSource::Layer(5),
        layer4.padded_width,
        layer5.padded_width,
        output,
    )?;

    Ok([layer0, layer1, layer2, layer3, layer4, layer5, layer6])
}

fn source_values<'a>(
    source: KeccakDagSource,
    round_input: &'a [bool],
    boundaries: &'a [Vec<bool>],
) -> Result<&'a [bool], KeccakCircuitError> {
    match source {
        KeccakDagSource::RoundInput => Ok(round_input),
        KeccakDagSource::Layer(index) => boundaries
            .get(index)
            .map(Vec::as_slice)
            .ok_or(KeccakCircuitError::Round),
    }
}

fn evaluate_gate(kind: KeccakDagGateKind, left: bool, right: bool) -> bool {
    match kind {
        KeccakDagGateKind::Xor => left ^ right,
        KeccakDagGateKind::NotLeftAndRight => !left & right,
        KeccakDagGateKind::XorConstant(constant) => left ^ right ^ constant,
        KeccakDagGateKind::Subtract => {
            unreachable!("field subtraction is not a Boolean Keccak gate")
        }
        KeccakDagGateKind::Zero => false,
    }
}

pub fn evaluate_keccak_gkr_dag_round(
    layers: &[KeccakDagLayer; 7],
    round_input: &[bool],
) -> Result<Vec<Vec<bool>>, KeccakCircuitError> {
    if round_input.len() != 2_048 {
        return Err(KeccakCircuitError::Overflow);
    }
    let mut boundaries = Vec::with_capacity(layers.len());
    for (index, layer) in layers.iter().enumerate() {
        if matches!(layer.left_source, KeccakDagSource::Layer(source) if source >= index)
            || matches!(layer.right_source, KeccakDagSource::Layer(source) if source >= index)
        {
            return Err(KeccakCircuitError::Round);
        }
        let left = source_values(layer.left_source, round_input, &boundaries)?;
        let right = source_values(layer.right_source, round_input, &boundaries)?;
        if left.len() != layer.left_width
            || right.len() != layer.right_width
            || layer.gates.len() != layer.padded_width
        {
            return Err(KeccakCircuitError::Overflow);
        }
        let values = layer
            .gates
            .iter()
            .map(|gate| evaluate_gate(gate.kind, left[gate.left], right[gate.right]))
            .collect::<Vec<_>>();
        if values[layer.raw_width..].iter().any(|value| *value) {
            return Err(KeccakCircuitError::Overflow);
        }
        boundaries.push(values);
    }
    Ok(boundaries)
}

fn evaluate_packed_gate(kind: KeccakDagGateKind, left: u16, right: u16) -> u16 {
    match kind {
        KeccakDagGateKind::Xor => left ^ right,
        KeccakDagGateKind::NotLeftAndRight => !left & right,
        KeccakDagGateKind::XorConstant(constant) => {
            left ^ right ^ if constant { u16::MAX } else { 0 }
        }
        KeccakDagGateKind::Subtract => {
            unreachable!("field subtraction is not a bit-sliced Keccak gate")
        }
        KeccakDagGateKind::Zero => 0,
    }
}

/// Evaluate all sixteen packed Boolean instances without materializing them
/// as sixteen separate traces.
pub fn evaluate_keccak_gkr_dag_round_b16(
    layers: &[KeccakDagLayer; 7],
    round_input: &[u16],
) -> Result<Vec<Vec<u16>>, KeccakCircuitError> {
    if round_input.len() != 2_048 {
        return Err(KeccakCircuitError::Overflow);
    }
    let mut boundaries = Vec::with_capacity(layers.len());
    for (index, layer) in layers.iter().enumerate() {
        if matches!(layer.left_source, KeccakDagSource::Layer(source) if source >= index)
            || matches!(layer.right_source, KeccakDagSource::Layer(source) if source >= index)
        {
            return Err(KeccakCircuitError::Round);
        }
        let left = match layer.left_source {
            KeccakDagSource::RoundInput => round_input,
            KeccakDagSource::Layer(source) => boundaries
                .get(source)
                .map(Vec::as_slice)
                .ok_or(KeccakCircuitError::Round)?,
        };
        let right = match layer.right_source {
            KeccakDagSource::RoundInput => round_input,
            KeccakDagSource::Layer(source) => boundaries
                .get(source)
                .map(Vec::as_slice)
                .ok_or(KeccakCircuitError::Round)?,
        };
        if left.len() != layer.left_width
            || right.len() != layer.right_width
            || layer.gates.len() != layer.padded_width
        {
            return Err(KeccakCircuitError::Overflow);
        }
        let values = layer
            .gates
            .iter()
            .map(|gate| evaluate_packed_gate(gate.kind, left[gate.left], right[gate.right]))
            .collect::<Vec<_>>();
        if values[layer.raw_width..].iter().any(|value| *value != 0) {
            return Err(KeccakCircuitError::Overflow);
        }
        boundaries.push(values);
    }
    Ok(boundaries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keccak_circuit::execute_layered_keccak_round;

    fn bits_from_state(state: &[u64; 25]) -> Vec<bool> {
        let mut bits = vec![false; 2_048];
        for (lane, value) in state.iter().copied().enumerate() {
            for z in 0..64 {
                bits[64 * lane + z] = ((value >> z) & 1) == 1;
            }
        }
        bits
    }

    fn state_from_bits(bits: &[bool]) -> [u64; 25] {
        core::array::from_fn(|lane| {
            (0..64).fold(0_u64, |value, z| {
                value | (u64::from(bits[64 * lane + z]) << z)
            })
        })
    }

    #[test]
    fn relay_free_geometry_is_exactly_one_third_of_control_terms() {
        let layers = build_keccak_gkr_dag_round(0).unwrap();
        assert_eq!(
            layers.iter().map(|layer| layer.raw_width).sum::<usize>(),
            6_400
        );
        assert_eq!(
            layers.iter().map(|layer| layer.padded_width).sum::<usize>(),
            8_704
        );
        assert_eq!(layers.len(), 7);
    }

    #[test]
    fn relay_free_round_matches_independent_keccak() {
        for case in 0_u64..10_000 {
            let round = (case as usize * 7) % 24;
            let mut expected = core::array::from_fn(|lane| {
                case.wrapping_add(1)
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    .rotate_left((lane as u32 * 11 + case as u32) & 63)
            });
            let input = bits_from_state(&expected);
            execute_layered_keccak_round(&mut expected, round).unwrap();
            let layers = build_keccak_gkr_dag_round(round).unwrap();
            let boundaries = evaluate_keccak_gkr_dag_round(&layers, &input).unwrap();
            assert_eq!(
                state_from_bits(boundaries.last().unwrap()),
                expected,
                "case={case} round={round}"
            );
        }
    }

    #[test]
    fn packed_b16_round_matches_all_sixteen_scalar_instances() {
        for case in 0_u64..100 {
            let round = (case as usize * 7) % 24;
            let states: [[u64; 25]; 16] = core::array::from_fn(|packed_lane| {
                core::array::from_fn(|lane| {
                    case.wrapping_add(1 + packed_lane as u64)
                        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                        .rotate_left((lane as u32 * 11 + case as u32) & 63)
                })
            });
            let mut packed = vec![0_u16; 2_048];
            for (packed_lane, state) in states.iter().enumerate() {
                for (lane, value) in state.iter().copied().enumerate() {
                    for bit in 0..64 {
                        packed[64 * lane + bit] |= (((value >> bit) & 1) as u16) << packed_lane;
                    }
                }
            }
            let layers = build_keccak_gkr_dag_round(round).unwrap();
            let packed_boundaries = evaluate_keccak_gkr_dag_round_b16(&layers, &packed).unwrap();
            for (packed_lane, state) in states.iter().enumerate() {
                let scalar =
                    evaluate_keccak_gkr_dag_round(&layers, &bits_from_state(state)).unwrap();
                for (packed_boundary, scalar_boundary) in packed_boundaries.iter().zip(scalar) {
                    for (packed_value, scalar_value) in
                        packed_boundary.iter().copied().zip(scalar_boundary)
                    {
                        assert_eq!((packed_value >> packed_lane) & 1, u16::from(scalar_value));
                    }
                }
            }
        }
    }
}
