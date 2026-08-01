//! Canonical public wiring plan for the 24-round, seven-layer B16 GKR worker.

use alloc::vec::Vec;

use sha3::{Digest, Sha3_512};

use crate::keccak_gkr_dag::{
    KeccakDagGate, KeccakDagGateKind, KeccakDagLayer, KeccakDagSource, build_keccak_gkr_dag_round,
};

pub const HASH_BUS_B16_GKR_PLAN_MAGIC: &[u8; 8] = b"BLGKP101";
pub const HASH_BUS_B16_GKR_PLAN_VERSION: u16 = 1;
pub const HASH_BUS_B16_GKR_ROUNDS: usize = 24;
pub const HASH_BUS_B16_GKR_LAYERS: usize = 7;
pub const MAX_HASH_BUS_B16_GKR_PLAN_BYTES: usize = 1 << 22;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashBusB16GkrPlanError {
    Encoding,
    Shape,
    Overflow,
    Plan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HashBusB16GkrPlan {
    pub rounds: Vec<[KeccakDagLayer; HASH_BUS_B16_GKR_LAYERS]>,
}

fn source_tag(source: KeccakDagSource) -> Result<u8, HashBusB16GkrPlanError> {
    match source {
        KeccakDagSource::RoundInput => Ok(0),
        KeccakDagSource::Layer(layer) if layer < HASH_BUS_B16_GKR_LAYERS => {
            u8::try_from(layer + 1).map_err(|_| HashBusB16GkrPlanError::Overflow)
        }
        KeccakDagSource::Layer(_) => Err(HashBusB16GkrPlanError::Shape),
    }
}

fn source_from_tag(tag: u8) -> Result<KeccakDagSource, HashBusB16GkrPlanError> {
    match tag {
        0 => Ok(KeccakDagSource::RoundInput),
        1..=7 => Ok(KeccakDagSource::Layer(usize::from(tag - 1))),
        _ => Err(HashBusB16GkrPlanError::Encoding),
    }
}

fn kind_tag(kind: KeccakDagGateKind) -> u8 {
    match kind {
        KeccakDagGateKind::Xor => 0,
        KeccakDagGateKind::NotLeftAndRight => 1,
        KeccakDagGateKind::XorConstant(false) => 2,
        KeccakDagGateKind::XorConstant(true) => 3,
        KeccakDagGateKind::Zero => 4,
    }
}

fn kind_from_tag(tag: u8) -> Result<KeccakDagGateKind, HashBusB16GkrPlanError> {
    match tag {
        0 => Ok(KeccakDagGateKind::Xor),
        1 => Ok(KeccakDagGateKind::NotLeftAndRight),
        2 => Ok(KeccakDagGateKind::XorConstant(false)),
        3 => Ok(KeccakDagGateKind::XorConstant(true)),
        4 => Ok(KeccakDagGateKind::Zero),
        _ => Err(HashBusB16GkrPlanError::Encoding),
    }
}

impl HashBusB16GkrPlan {
    pub fn selected() -> Result<Self, HashBusB16GkrPlanError> {
        let rounds = (0..HASH_BUS_B16_GKR_ROUNDS)
            .map(|round| {
                build_keccak_gkr_dag_round(round).map_err(|_| HashBusB16GkrPlanError::Plan)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let plan = Self { rounds };
        plan.validate()?;
        Ok(plan)
    }

    fn validate(&self) -> Result<(), HashBusB16GkrPlanError> {
        if self.rounds.len() != HASH_BUS_B16_GKR_ROUNDS {
            return Err(HashBusB16GkrPlanError::Shape);
        }
        for layers in &self.rounds {
            for (layer_index, layer) in layers.iter().enumerate() {
                if layer.raw_width == 0
                    || layer.raw_width > layer.padded_width
                    || !layer.left_width.is_power_of_two()
                    || !layer.right_width.is_power_of_two()
                    || !layer.padded_width.is_power_of_two()
                    || layer.gates.len() != layer.padded_width
                    || layer.gates.iter().any(|gate| {
                        gate.left >= layer.left_width || gate.right >= layer.right_width
                    })
                {
                    return Err(HashBusB16GkrPlanError::Shape);
                }
                for source in [layer.left_source, layer.right_source] {
                    if matches!(source, KeccakDagSource::Layer(index) if index >= layer_index) {
                        return Err(HashBusB16GkrPlanError::Shape);
                    }
                    source_tag(source)?;
                }
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, HashBusB16GkrPlanError> {
        self.validate()?;
        let mut output = Vec::new();
        output.extend_from_slice(HASH_BUS_B16_GKR_PLAN_MAGIC);
        output.extend_from_slice(&HASH_BUS_B16_GKR_PLAN_VERSION.to_be_bytes());
        output.push(u8::try_from(self.rounds.len()).map_err(|_| HashBusB16GkrPlanError::Overflow)?);
        output.push(HASH_BUS_B16_GKR_LAYERS as u8);
        for layers in &self.rounds {
            for layer in layers {
                output.push(source_tag(layer.left_source)?);
                output.push(source_tag(layer.right_source)?);
                for value in [
                    layer.left_width,
                    layer.right_width,
                    layer.raw_width,
                    layer.padded_width,
                ] {
                    output.extend_from_slice(
                        &u16::try_from(value)
                            .map_err(|_| HashBusB16GkrPlanError::Overflow)?
                            .to_be_bytes(),
                    );
                }
                for gate in &layer.gates {
                    output.extend_from_slice(
                        &u16::try_from(gate.left)
                            .map_err(|_| HashBusB16GkrPlanError::Overflow)?
                            .to_be_bytes(),
                    );
                    output.extend_from_slice(
                        &u16::try_from(gate.right)
                            .map_err(|_| HashBusB16GkrPlanError::Overflow)?
                            .to_be_bytes(),
                    );
                    output.push(kind_tag(gate.kind));
                }
            }
        }
        if output.len() > MAX_HASH_BUS_B16_GKR_PLAN_BYTES {
            return Err(HashBusB16GkrPlanError::Overflow);
        }
        Ok(output)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, HashBusB16GkrPlanError> {
        if encoded.len() > MAX_HASH_BUS_B16_GKR_PLAN_BYTES
            || encoded.get(..8) != Some(HASH_BUS_B16_GKR_PLAN_MAGIC)
            || encoded.get(8..10) != Some(HASH_BUS_B16_GKR_PLAN_VERSION.to_be_bytes().as_slice())
            || encoded.get(10) != Some(&(HASH_BUS_B16_GKR_ROUNDS as u8))
            || encoded.get(11) != Some(&(HASH_BUS_B16_GKR_LAYERS as u8))
        {
            return Err(HashBusB16GkrPlanError::Encoding);
        }
        let mut cursor = 12_usize;
        let mut rounds = Vec::with_capacity(HASH_BUS_B16_GKR_ROUNDS);
        for _ in 0..HASH_BUS_B16_GKR_ROUNDS {
            let mut layers = Vec::with_capacity(HASH_BUS_B16_GKR_LAYERS);
            for _ in 0..HASH_BUS_B16_GKR_LAYERS {
                let left_source = source_from_tag(read_u8(encoded, &mut cursor)?)?;
                let right_source = source_from_tag(read_u8(encoded, &mut cursor)?)?;
                let left_width = usize::from(read_u16(encoded, &mut cursor)?);
                let right_width = usize::from(read_u16(encoded, &mut cursor)?);
                let raw_width = usize::from(read_u16(encoded, &mut cursor)?);
                let padded_width = usize::from(read_u16(encoded, &mut cursor)?);
                let mut gates = Vec::with_capacity(padded_width);
                for _ in 0..padded_width {
                    gates.push(KeccakDagGate {
                        left: usize::from(read_u16(encoded, &mut cursor)?),
                        right: usize::from(read_u16(encoded, &mut cursor)?),
                        kind: kind_from_tag(read_u8(encoded, &mut cursor)?)?,
                    });
                }
                layers.push(KeccakDagLayer {
                    left_source,
                    right_source,
                    left_width,
                    right_width,
                    raw_width,
                    padded_width,
                    gates,
                });
            }
            rounds.push(
                layers
                    .try_into()
                    .map_err(|_| HashBusB16GkrPlanError::Shape)?,
            );
        }
        if cursor != encoded.len() {
            return Err(HashBusB16GkrPlanError::Encoding);
        }
        let plan = Self { rounds };
        plan.validate()?;
        Ok(plan)
    }

    pub fn commitment(&self) -> Result<[u8; 64], HashBusB16GkrPlanError> {
        Ok(Sha3_512::digest(self.encode()?).into())
    }
}

fn read_u8(encoded: &[u8], cursor: &mut usize) -> Result<u8, HashBusB16GkrPlanError> {
    let value = *encoded
        .get(*cursor)
        .ok_or(HashBusB16GkrPlanError::Encoding)?;
    *cursor = cursor
        .checked_add(1)
        .ok_or(HashBusB16GkrPlanError::Overflow)?;
    Ok(value)
}

fn read_u16(encoded: &[u8], cursor: &mut usize) -> Result<u16, HashBusB16GkrPlanError> {
    let end = cursor
        .checked_add(2)
        .ok_or(HashBusB16GkrPlanError::Overflow)?;
    let value = u16::from_be_bytes(
        encoded
            .get(*cursor..end)
            .ok_or(HashBusB16GkrPlanError::Encoding)?
            .try_into()
            .map_err(|_| HashBusB16GkrPlanError::Encoding)?,
    );
    *cursor = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_plan_round_trips_and_rejects_mutations() {
        let plan = HashBusB16GkrPlan::selected().unwrap();
        let encoded = plan.encode().unwrap();
        assert_eq!(HashBusB16GkrPlan::decode(&encoded).unwrap(), plan);
        assert_eq!(encoded.len(), 1_046_172);
        assert_eq!(
            plan.commitment().unwrap(),
            [
                0x8e, 0xd5, 0xe2, 0xd6, 0x2e, 0xee, 0x09, 0x39, 0x66, 0x6b, 0x8a, 0x99, 0xe4, 0xc0,
                0xef, 0xcf, 0xad, 0xff, 0x5f, 0xc2, 0x10, 0x9a, 0x12, 0x5d, 0x22, 0x22, 0x27, 0x5d,
                0x49, 0x1e, 0xac, 0x3b, 0x09, 0x3e, 0x67, 0x83, 0xa0, 0xb2, 0x00, 0x38, 0x0e, 0x63,
                0x0c, 0x71, 0x78, 0xca, 0xe4, 0x5d, 0x91, 0xf1, 0x30, 0x41, 0x37, 0x4a, 0xaf, 0xe7,
                0x0a, 0xf8, 0x94, 0xd2, 0xa0, 0xea, 0x9d, 0x1d,
            ]
        );

        let mut forged = encoded.clone();
        *forged.last_mut().unwrap() = 9;
        assert_eq!(
            HashBusB16GkrPlan::decode(&forged),
            Err(HashBusB16GkrPlanError::Encoding)
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            HashBusB16GkrPlan::decode(&trailing),
            Err(HashBusB16GkrPlanError::Encoding)
        );
    }
}
