//! Canonical varying-source adapter for the semantic/H4 bridge prover.
//!
//! This is producer-only plumbing.  It derives every bridge round-input cell
//! from the same semantic ports and packed Keccak boundary authenticated by
//! the accepting verifier.  It owns no transcript challenge or receipt.

use alloc::vec::Vec;
use sha3::{Digest, Sha3_512};

use crate::{
    field::{Fp16, M31},
    hash_bus::{
        GROUP_COUNT, HashBusDescriptor, PERMUTATIONS_PER_COPROCESSOR_SHARD,
        build_hash_bus_descriptor_with_state, hash_bus_permutation_slot,
    },
    hash_bus_b16_boundary::{HashBusB16BoundaryFile, HashBusB16Shard},
    hash_bus_snapshot::HashBusSnapshot,
    keccak_gkr_dag::{KeccakDagGateKind, KeccakDagSource},
    semantic_h4_bridge_gkr::{
        BLOCK_ACTIVE, BLOCK_INPUT_BITS_START, BLOCK_PREDECESSOR_BITS_START,
        BRIDGE_BLOCK_SOURCE_WIDTH, BRIDGE_DIGEST_SOURCE_WIDTH, BRIDGE_RATE_SOURCE_WIDTH,
        DIGEST_EXPECTED_BYTE, DIGEST_NEXT_ACTIVE_START, DIGEST_OUTPUT_BYTES_START, RATE_128,
        RATE_BIT_WEIGHTS_START, RATE_BLOCK_ACTIVE, RATE_FINAL_BYTE_SELECTOR, RATE_INPUT_BITS_START,
        RATE_LIVE, RATE_NEXT_BLOCK_ACTIVE, RATE_ONE, RATE_PREDECESSOR_BITS_START,
        RATE_PREVIOUS_LIVE, RATE_SIX, RATE_VALUE, SemanticBridgeBaseColumnV3,
        SemanticH4BridgeCircuit, SemanticH4BridgeProfile, semantic_h4_bridge_topologies,
    },
    wave1a_global_schedule::Profile as ScheduleProfile,
};

const RATE_BYTES: usize = 72;
const DIGEST_BYTES: usize = 64;
const KECCAK_STATE_BITS: usize = 1_600;
const CAPACITY_START: usize = 576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticH4BridgeBoundaryError {
    Shape,
    Source,
}

/// Read-only authority-free view of already-authenticated producer inputs.
pub trait SemanticH4BridgeBoundary {
    fn input_bit(
        &self,
        global_permutation: usize,
        wire: usize,
    ) -> Result<bool, SemanticH4BridgeBoundaryError>;

    fn output_bit(
        &self,
        global_permutation: usize,
        wire: usize,
    ) -> Result<bool, SemanticH4BridgeBoundaryError>;

    fn message_live(&self, row: usize) -> Result<bool, SemanticH4BridgeBoundaryError>;

    fn message_value(&self, row: usize) -> Result<u8, SemanticH4BridgeBoundaryError>;

    fn digest_value(&self, row: usize) -> Result<u8, SemanticH4BridgeBoundaryError>;
}

/// Compact concrete boundary used by the real bridge producer.
///
/// Keccak states remain in their canonical B16 representation. Message bytes
/// are retained once per call and are also the sole source of digest bytes.
/// No group-expanded field table is constructed.
pub struct PackedB16SemanticH4Boundary {
    descriptor: HashBusDescriptor,
    shards: Vec<HashBusB16Shard>,
    messages: Vec<Vec<u8>>,
    digests: Vec<[u8; DIGEST_BYTES]>,
}

impl PackedB16SemanticH4Boundary {
    pub const fn total_calls(&self) -> u64 {
        self.descriptor.total_calls
    }

    pub const fn total_permutations(&self) -> u64 {
        self.descriptor.total_permutations
    }

    pub fn expected_digest_byte(
        &self,
        call: usize,
        byte: usize,
    ) -> Result<u8, SemanticH4BridgeBoundaryError> {
        self.digests
            .get(call)
            .and_then(|digest| digest.get(byte))
            .copied()
            .ok_or(SemanticH4BridgeBoundaryError::Shape)
    }

    pub fn boundary_digest_byte(
        &self,
        call: usize,
        byte: usize,
    ) -> Result<u8, SemanticH4BridgeBoundaryError> {
        if byte >= DIGEST_BYTES {
            return Err(SemanticH4BridgeBoundaryError::Shape);
        }
        let mut call_base = 0_usize;
        let mut permutation = 0_usize;
        for run in &self.descriptor.runs {
            let blocks = usize::try_from(run.capacity / 72 + 1)
                .map_err(|_| SemanticH4BridgeBoundaryError::Shape)?;
            let count =
                usize::try_from(run.count).map_err(|_| SemanticH4BridgeBoundaryError::Shape)?;
            let end = call_base
                .checked_add(count)
                .ok_or(SemanticH4BridgeBoundaryError::Shape)?;
            if call < end {
                let message = self
                    .messages
                    .get(call)
                    .ok_or(SemanticH4BridgeBoundaryError::Shape)?;
                let active_blocks = (message.len() + RATE_BYTES) / RATE_BYTES;
                let final_permutation = permutation
                    .checked_add((call - call_base) * blocks)
                    .and_then(|value| value.checked_add(active_blocks - 1))
                    .ok_or(SemanticH4BridgeBoundaryError::Shape)?;
                let mut value = 0_u8;
                for bit in 0..8 {
                    if self.output_bit(final_permutation, 8 * byte + bit)? {
                        value |= 1 << bit;
                    }
                }
                return Ok(value);
            }
            call_base = end;
            permutation = permutation
                .checked_add(count * blocks)
                .ok_or(SemanticH4BridgeBoundaryError::Shape)?;
        }
        Err(SemanticH4BridgeBoundaryError::Shape)
    }

    pub fn from_snapshot(
        boundary_file: &mut HashBusB16BoundaryFile,
        snapshot: &HashBusSnapshot,
    ) -> Result<Self, SemanticH4BridgeBoundaryError> {
        let header = boundary_file.header();
        if !header.state_composed
            || !snapshot.state_composed
            || header.profile != snapshot.profile
            || header.semantic_program_commitment != snapshot.semantic_program_commitment
            || header.descriptor_commitment != snapshot.descriptor_commitment
            || header.semantic_port_commitment != snapshot.semantic_port_commitment
        {
            return Err(SemanticH4BridgeBoundaryError::Shape);
        }
        let profile = match snapshot.profile {
            ScheduleProfile::K128Calibration => SemanticH4BridgeProfile::K128,
            ScheduleProfile::K512Calibration => SemanticH4BridgeProfile::K512,
            ScheduleProfile::K256DesignPoint => {
                return Err(SemanticH4BridgeBoundaryError::Shape);
            }
        };
        let shards = (0..header.coprocessor_shards)
            .map(|shard| {
                boundary_file
                    .read_shard(shard)
                    .map_err(|_| SemanticH4BridgeBoundaryError::Source)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let messages = snapshot
            .messages
            .iter()
            .map(|message| message.message.clone())
            .collect();
        Self::new(profile, shards, messages)
    }

    pub fn new(
        profile: SemanticH4BridgeProfile,
        shards: Vec<HashBusB16Shard>,
        messages: Vec<Vec<u8>>,
    ) -> Result<Self, SemanticH4BridgeBoundaryError> {
        let schedule = match profile {
            SemanticH4BridgeProfile::K128 => ScheduleProfile::K128Calibration,
            SemanticH4BridgeProfile::K512 => ScheduleProfile::K512Calibration,
        };
        let descriptor = build_hash_bus_descriptor_with_state(schedule)
            .map_err(|_| SemanticH4BridgeBoundaryError::Shape)?;
        let expected_shards = usize::from(descriptor.coprocessor_shards);
        let values_per_plane = KECCAK_STATE_BITS
            .checked_mul(
                usize::try_from(GROUP_COUNT).map_err(|_| SemanticH4BridgeBoundaryError::Shape)?,
            )
            .ok_or(SemanticH4BridgeBoundaryError::Shape)?;
        if shards.len() != expected_shards
            || shards.iter().any(|shard| {
                shard.input.len() != values_per_plane || shard.output.len() != values_per_plane
            })
            || messages.len()
                != usize::try_from(descriptor.total_calls)
                    .map_err(|_| SemanticH4BridgeBoundaryError::Shape)?
        {
            return Err(SemanticH4BridgeBoundaryError::Shape);
        }

        let mut call = 0_usize;
        for run in &descriptor.runs {
            let capacity =
                usize::try_from(run.capacity).map_err(|_| SemanticH4BridgeBoundaryError::Shape)?;
            let count =
                usize::try_from(run.count).map_err(|_| SemanticH4BridgeBoundaryError::Shape)?;
            let end = call
                .checked_add(count)
                .ok_or(SemanticH4BridgeBoundaryError::Shape)?;
            if messages
                .get(call..end)
                .ok_or(SemanticH4BridgeBoundaryError::Shape)?
                .iter()
                .any(|message| message.len() > capacity)
            {
                return Err(SemanticH4BridgeBoundaryError::Shape);
            }
            call = end;
        }
        let digests = messages
            .iter()
            .map(|message| Sha3_512::digest(message).into())
            .collect();
        Ok(Self {
            descriptor,
            shards,
            messages,
            digests,
        })
    }

    fn packed_bit(
        &self,
        global_permutation: usize,
        wire: usize,
        output: bool,
    ) -> Result<bool, SemanticH4BridgeBoundaryError> {
        if wire >= KECCAK_STATE_BITS
            || global_permutation
                >= usize::try_from(self.descriptor.padded_permutations)
                    .map_err(|_| SemanticH4BridgeBoundaryError::Shape)?
        {
            return Err(SemanticH4BridgeBoundaryError::Shape);
        }
        let permutations_per_shard = usize::try_from(PERMUTATIONS_PER_COPROCESSOR_SHARD)
            .map_err(|_| SemanticH4BridgeBoundaryError::Shape)?;
        let groups =
            usize::try_from(GROUP_COUNT).map_err(|_| SemanticH4BridgeBoundaryError::Shape)?;
        let shard = global_permutation / permutations_per_shard;
        let local = global_permutation % permutations_per_shard;
        let packed_group = local / 16;
        let lane = local % 16;
        let plane = if output {
            &self
                .shards
                .get(shard)
                .ok_or(SemanticH4BridgeBoundaryError::Shape)?
                .output
        } else {
            &self
                .shards
                .get(shard)
                .ok_or(SemanticH4BridgeBoundaryError::Shape)?
                .input
        };
        let pattern = *plane
            .get(
                wire.checked_mul(groups)
                    .and_then(|offset| offset.checked_add(packed_group))
                    .ok_or(SemanticH4BridgeBoundaryError::Shape)?,
            )
            .ok_or(SemanticH4BridgeBoundaryError::Shape)?;
        Ok((pattern >> lane) & 1 == 1)
    }

    fn message_cell(&self, row: usize) -> Result<(bool, u8), SemanticH4BridgeBoundaryError> {
        let permutation = row / RATE_BYTES;
        let byte = row % RATE_BYTES;
        let slot = hash_bus_permutation_slot(
            &self.descriptor,
            u64::try_from(permutation).map_err(|_| SemanticH4BridgeBoundaryError::Shape)?,
        )
        .map_err(|_| SemanticH4BridgeBoundaryError::Shape)?
        .ok_or(SemanticH4BridgeBoundaryError::Shape)?;
        let position = usize::from(slot.block_index)
            .checked_mul(RATE_BYTES)
            .and_then(|offset| offset.checked_add(byte))
            .ok_or(SemanticH4BridgeBoundaryError::Shape)?;
        let message = self
            .messages
            .get(
                usize::try_from(slot.call_index)
                    .map_err(|_| SemanticH4BridgeBoundaryError::Shape)?,
            )
            .ok_or(SemanticH4BridgeBoundaryError::Shape)?;
        Ok(match message.get(position) {
            Some(value) => (true, *value),
            None => (false, 0),
        })
    }
}

impl SemanticH4BridgeBoundary for PackedB16SemanticH4Boundary {
    fn input_bit(
        &self,
        global_permutation: usize,
        wire: usize,
    ) -> Result<bool, SemanticH4BridgeBoundaryError> {
        self.packed_bit(global_permutation, wire, false)
    }

    fn output_bit(
        &self,
        global_permutation: usize,
        wire: usize,
    ) -> Result<bool, SemanticH4BridgeBoundaryError> {
        self.packed_bit(global_permutation, wire, true)
    }

    fn message_live(&self, row: usize) -> Result<bool, SemanticH4BridgeBoundaryError> {
        Ok(self.message_cell(row)?.0)
    }

    fn message_value(&self, row: usize) -> Result<u8, SemanticH4BridgeBoundaryError> {
        Ok(self.message_cell(row)?.1)
    }

    fn digest_value(&self, row: usize) -> Result<u8, SemanticH4BridgeBoundaryError> {
        let call = row / DIGEST_BYTES;
        let byte = row % DIGEST_BYTES;
        self.digests
            .get(call)
            .and_then(|digest| digest.get(byte))
            .copied()
            .ok_or(SemanticH4BridgeBoundaryError::Shape)
    }
}

pub struct SemanticH4BridgeBoundarySource<'a> {
    profile: SemanticH4BridgeProfile,
    descriptor: HashBusDescriptor,
    boundary: &'a dyn SemanticH4BridgeBoundary,
}

impl<'a> SemanticH4BridgeBoundarySource<'a> {
    pub fn new(
        profile: SemanticH4BridgeProfile,
        boundary: &'a dyn SemanticH4BridgeBoundary,
    ) -> Result<Self, SemanticH4BridgeBoundaryError> {
        let schedule = match profile {
            SemanticH4BridgeProfile::K128 => ScheduleProfile::K128Calibration,
            SemanticH4BridgeProfile::K512 => ScheduleProfile::K512Calibration,
        };
        let descriptor = build_hash_bus_descriptor_with_state(schedule)
            .map_err(|_| SemanticH4BridgeBoundaryError::Shape)?;
        Ok(Self {
            profile,
            descriptor,
            boundary,
        })
    }

    pub const fn profile(&self) -> SemanticH4BridgeProfile {
        self.profile
    }

    pub fn source_value(
        &self,
        circuit: SemanticH4BridgeCircuit,
        wire: usize,
        group: usize,
    ) -> Result<Fp16, SemanticH4BridgeBoundaryError> {
        match circuit {
            SemanticH4BridgeCircuit::Rate => self.rate_value(wire, group),
            SemanticH4BridgeCircuit::Inactive => self.inactive_value(wire, group),
            SemanticH4BridgeCircuit::Capacity => self.capacity_value(wire, group),
            SemanticH4BridgeCircuit::Digest => self.digest_source_value(wire, group),
        }
    }

    /// Evaluate every bridge layer for one group without retaining any other
    /// group. This is shared by streaming output claims and early GPU rounds.
    pub fn evaluate_group(
        &self,
        circuit: SemanticH4BridgeCircuit,
        group: usize,
    ) -> Result<Vec<Vec<Fp16>>, SemanticH4BridgeBoundaryError> {
        let topologies = semantic_h4_bridge_topologies();
        let layers = match circuit {
            SemanticH4BridgeCircuit::Rate => topologies.rate,
            SemanticH4BridgeCircuit::Inactive => topologies.inactive,
            SemanticH4BridgeCircuit::Capacity => topologies.capacity,
            SemanticH4BridgeCircuit::Digest => topologies.digest,
        };
        let source_width = match circuit {
            SemanticH4BridgeCircuit::Rate => BRIDGE_RATE_SOURCE_WIDTH,
            SemanticH4BridgeCircuit::Inactive | SemanticH4BridgeCircuit::Capacity => {
                BRIDGE_BLOCK_SOURCE_WIDTH
            }
            SemanticH4BridgeCircuit::Digest => BRIDGE_DIGEST_SOURCE_WIDTH,
        };
        let source = (0..source_width)
            .map(|wire| self.source_value(circuit, wire, group))
            .collect::<Result<Vec<_>, _>>()?;
        let mut rows = Vec::<Vec<Fp16>>::with_capacity(layers.len());
        for layer in &layers {
            let left = match layer.left_source {
                KeccakDagSource::RoundInput => source.as_slice(),
                KeccakDagSource::Layer(index) => rows
                    .get(index)
                    .ok_or(SemanticH4BridgeBoundaryError::Shape)?,
            };
            let right = match layer.right_source {
                KeccakDagSource::RoundInput => source.as_slice(),
                KeccakDagSource::Layer(index) => rows
                    .get(index)
                    .ok_or(SemanticH4BridgeBoundaryError::Shape)?,
            };
            rows.push(
                layer
                    .gates
                    .iter()
                    .map(|gate| {
                        let left = *left
                            .get(gate.left)
                            .ok_or(SemanticH4BridgeBoundaryError::Shape)?;
                        let right = *right
                            .get(gate.right)
                            .ok_or(SemanticH4BridgeBoundaryError::Shape)?;
                        Ok(evaluate_gate(gate.kind, left, right))
                    })
                    .collect::<Result<Vec<_>, SemanticH4BridgeBoundaryError>>()?,
            );
        }
        Ok(rows)
    }

    pub fn relation_value(
        &self,
        circuit: SemanticH4BridgeCircuit,
        group: usize,
    ) -> Result<Fp16, SemanticH4BridgeBoundaryError> {
        self.evaluate_group(circuit, group)?
            .last()
            .and_then(|row| row.first())
            .copied()
            .ok_or(SemanticH4BridgeBoundaryError::Shape)
    }

    /// Materialize one verifier-requested semantic base column with canonical
    /// zero padding. This is producer plumbing only; the functional proof
    /// binds the resulting values to the native semantic coefficient root.
    pub fn semantic_column_rows(
        &self,
        circuit: SemanticH4BridgeCircuit,
        column: SemanticBridgeBaseColumnV3,
        row_count: usize,
    ) -> Result<Vec<Fp16>, SemanticH4BridgeBoundaryError> {
        if row_count == 0 || !row_count.is_power_of_two() {
            return Err(SemanticH4BridgeBoundaryError::Shape);
        }
        (0..row_count)
            .map(|row| match column {
                SemanticBridgeBaseColumnV3::MessageLive => {
                    if row >= self.boundary_permutation_count()? * RATE_BYTES {
                        Ok(Fp16::ZERO)
                    } else {
                        Ok(from_bool(self.boundary.message_live(row)?))
                    }
                }
                SemanticBridgeBaseColumnV3::MessageValue => {
                    if circuit != SemanticH4BridgeCircuit::Rate {
                        return Err(SemanticH4BridgeBoundaryError::Shape);
                    }
                    if row >= self.boundary_permutation_count()? * RATE_BYTES {
                        Ok(Fp16::ZERO)
                    } else {
                        from_u32(u32::from(self.boundary.message_value(row)?))
                    }
                }
                SemanticBridgeBaseColumnV3::DigestValue => {
                    if circuit != SemanticH4BridgeCircuit::Digest {
                        return Err(SemanticH4BridgeBoundaryError::Shape);
                    }
                    if row >= self.boundary_call_count()? * DIGEST_BYTES {
                        Ok(Fp16::ZERO)
                    } else {
                        from_u32(u32::from(self.boundary.digest_value(row)?))
                    }
                }
            })
            .collect()
    }

    fn boundary_call_count(&self) -> Result<usize, SemanticH4BridgeBoundaryError> {
        usize::try_from(self.descriptor.total_calls)
            .map_err(|_| SemanticH4BridgeBoundaryError::Shape)
    }

    fn boundary_permutation_count(&self) -> Result<usize, SemanticH4BridgeBoundaryError> {
        usize::try_from(self.descriptor.total_permutations)
            .map_err(|_| SemanticH4BridgeBoundaryError::Shape)
    }

    fn rate_value(&self, wire: usize, group: usize) -> Result<Fp16, SemanticH4BridgeBoundaryError> {
        if wire >= BRIDGE_RATE_SOURCE_WIDTH {
            return Err(SemanticH4BridgeBoundaryError::Shape);
        }
        let permutation = group / RATE_BYTES;
        let byte = group % RATE_BYTES;
        let total = usize::try_from(self.descriptor.total_permutations)
            .map_err(|_| SemanticH4BridgeBoundaryError::Shape)?;
        if permutation >= total {
            return Ok(self.rate_constant(wire, false));
        }
        let slot = hash_bus_permutation_slot(&self.descriptor, permutation as u64)
            .map_err(|_| SemanticH4BridgeBoundaryError::Shape)?
            .ok_or(SemanticH4BridgeBoundaryError::Shape)?;
        let live = self.boundary.message_live(group)?;
        let value = self.boundary.message_value(group)?;
        let result = match wire {
            RATE_LIVE => from_bool(live),
            RATE_PREVIOUS_LIVE => {
                let predecessor = if byte > 0 || slot.block_index > 0 {
                    self.boundary.message_live(group - 1)?
                } else {
                    false
                };
                from_bool(predecessor)
            }
            RATE_BLOCK_ACTIVE => from_bool(
                slot.block_index == 0 || {
                    let prior_last = permutation
                        .checked_mul(RATE_BYTES)
                        .and_then(|value| value.checked_sub(1));
                    prior_last
                        .map(|row| self.boundary.message_live(row))
                        .transpose()?
                        .unwrap_or(false)
                },
            ),
            RATE_NEXT_BLOCK_ACTIVE => {
                from_bool(self.boundary.message_live(permutation * RATE_BYTES + 71)?)
            }
            RATE_VALUE => from_u32(u32::from(value))?,
            RATE_FINAL_BYTE_SELECTOR => from_bool(byte == 71),
            RATE_SIX => from_u32(6)?,
            RATE_128 => from_u32(128)?,
            RATE_ONE => Fp16::ONE,
            value if (RATE_INPUT_BITS_START..RATE_INPUT_BITS_START + 8).contains(&value) => {
                let bit = value - RATE_INPUT_BITS_START;
                from_bool(self.boundary.input_bit(permutation, 8 * byte + bit)?)
            }
            value
                if (RATE_PREDECESSOR_BITS_START..RATE_PREDECESSOR_BITS_START + 8)
                    .contains(&value) =>
            {
                let bit = value - RATE_PREDECESSOR_BITS_START;
                if slot.block_index == 0 {
                    Fp16::ZERO
                } else {
                    from_bool(self.boundary.output_bit(permutation - 1, 8 * byte + bit)?)
                }
            }
            value if (RATE_BIT_WEIGHTS_START..RATE_BIT_WEIGHTS_START + 8).contains(&value) => {
                from_u32(1 << (value - RATE_BIT_WEIGHTS_START))?
            }
            _ => Fp16::ZERO,
        };
        Ok(result)
    }

    fn rate_constant(&self, wire: usize, final_byte: bool) -> Fp16 {
        match wire {
            RATE_FINAL_BYTE_SELECTOR if final_byte => Fp16::ONE,
            RATE_SIX => from_u32(6).expect("small canonical constant"),
            RATE_128 => from_u32(128).expect("small canonical constant"),
            RATE_ONE => Fp16::ONE,
            value if (RATE_BIT_WEIGHTS_START..RATE_BIT_WEIGHTS_START + 8).contains(&value) => {
                from_u32(1 << (value - RATE_BIT_WEIGHTS_START)).expect("small canonical constant")
            }
            _ => Fp16::ZERO,
        }
    }

    fn inactive_value(
        &self,
        wire: usize,
        group: usize,
    ) -> Result<Fp16, SemanticH4BridgeBoundaryError> {
        if wire >= BRIDGE_BLOCK_SOURCE_WIDTH {
            return Err(SemanticH4BridgeBoundaryError::Shape);
        }
        let total = usize::try_from(self.descriptor.total_permutations)
            .map_err(|_| SemanticH4BridgeBoundaryError::Shape)?;
        if group >= total {
            return Ok(Fp16::ZERO);
        }
        let slot = hash_bus_permutation_slot(&self.descriptor, group as u64)
            .map_err(|_| SemanticH4BridgeBoundaryError::Shape)?
            .ok_or(SemanticH4BridgeBoundaryError::Shape)?;
        if wire == BLOCK_ACTIVE {
            return Ok(from_bool(
                slot.block_index == 0 || self.previous_block_live(group)?,
            ));
        }
        if wire < KECCAK_STATE_BITS {
            return Ok(from_bool(self.boundary.input_bit(group, wire)?));
        }
        Ok(Fp16::ZERO)
    }

    fn capacity_value(
        &self,
        wire: usize,
        group: usize,
    ) -> Result<Fp16, SemanticH4BridgeBoundaryError> {
        if wire >= BRIDGE_BLOCK_SOURCE_WIDTH {
            return Err(SemanticH4BridgeBoundaryError::Shape);
        }
        let total = usize::try_from(self.descriptor.total_permutations)
            .map_err(|_| SemanticH4BridgeBoundaryError::Shape)?;
        if group >= total {
            return Ok(Fp16::ZERO);
        }
        let slot = hash_bus_permutation_slot(&self.descriptor, group as u64)
            .map_err(|_| SemanticH4BridgeBoundaryError::Shape)?
            .ok_or(SemanticH4BridgeBoundaryError::Shape)?;
        if wire == BLOCK_ACTIVE {
            return Ok(from_bool(
                slot.block_index == 0 || self.previous_block_live(group)?,
            ));
        }
        if (BLOCK_INPUT_BITS_START..BLOCK_INPUT_BITS_START + 1_024).contains(&wire) {
            return Ok(from_bool(self.boundary.input_bit(
                group,
                CAPACITY_START + wire - BLOCK_INPUT_BITS_START,
            )?));
        }
        if (BLOCK_PREDECESSOR_BITS_START..BLOCK_PREDECESSOR_BITS_START + 1_024).contains(&wire) {
            if slot.block_index == 0 {
                return Ok(Fp16::ZERO);
            }
            return Ok(from_bool(self.boundary.output_bit(
                group - 1,
                CAPACITY_START + wire - BLOCK_PREDECESSOR_BITS_START,
            )?));
        }
        Ok(Fp16::ZERO)
    }

    fn digest_source_value(
        &self,
        wire: usize,
        group: usize,
    ) -> Result<Fp16, SemanticH4BridgeBoundaryError> {
        if wire >= BRIDGE_DIGEST_SOURCE_WIDTH {
            return Err(SemanticH4BridgeBoundaryError::Shape);
        }
        let call = group / DIGEST_BYTES;
        let byte = group % DIGEST_BYTES;
        let total_calls = usize::try_from(self.descriptor.total_calls)
            .map_err(|_| SemanticH4BridgeBoundaryError::Shape)?;
        if call >= total_calls {
            return Ok(Fp16::ZERO);
        }
        let (first_permutation, blocks) = self.call_geometry(call)?;
        let block_active = |block: usize| -> Result<bool, SemanticH4BridgeBoundaryError> {
            if block >= blocks {
                return Ok(false);
            }
            if block == 0 {
                return Ok(true);
            }
            self.boundary
                .message_live((first_permutation + block - 1) * RATE_BYTES + RATE_BYTES - 1)
        };
        let result = if wire < 1_024 {
            from_bool(block_active(wire)?)
        } else if (DIGEST_NEXT_ACTIVE_START..DIGEST_NEXT_ACTIVE_START + 1_024).contains(&wire) {
            from_bool(block_active(wire - DIGEST_NEXT_ACTIVE_START + 1)?)
        } else if (DIGEST_OUTPUT_BYTES_START..DIGEST_OUTPUT_BYTES_START + 1_024).contains(&wire) {
            let block = wire - DIGEST_OUTPUT_BYTES_START;
            if block >= blocks {
                Fp16::ZERO
            } else {
                let permutation = first_permutation + block;
                let mut value = 0_u32;
                for bit in 0..8 {
                    if self.boundary.output_bit(permutation, 8 * byte + bit)? {
                        value |= 1 << bit;
                    }
                }
                from_u32(value)?
            }
        } else if wire == DIGEST_EXPECTED_BYTE {
            from_u32(u32::from(self.boundary.digest_value(group)?))?
        } else {
            Fp16::ZERO
        };
        Ok(result)
    }

    fn previous_block_live(
        &self,
        permutation: usize,
    ) -> Result<bool, SemanticH4BridgeBoundaryError> {
        let prior = permutation
            .checked_mul(RATE_BYTES)
            .and_then(|value| value.checked_sub(1));
        prior
            .map(|row| self.boundary.message_live(row))
            .transpose()
            .map(|value| value.unwrap_or(false))
    }

    fn call_geometry(
        &self,
        wanted_call: usize,
    ) -> Result<(usize, usize), SemanticH4BridgeBoundaryError> {
        let mut call_base = 0_usize;
        let mut permutation = 0_usize;
        for run in &self.descriptor.runs {
            let blocks = usize::try_from(run.capacity / 72 + 1)
                .map_err(|_| SemanticH4BridgeBoundaryError::Shape)?;
            let count =
                usize::try_from(run.count).map_err(|_| SemanticH4BridgeBoundaryError::Shape)?;
            let call_end = call_base
                .checked_add(count)
                .ok_or(SemanticH4BridgeBoundaryError::Shape)?;
            if wanted_call < call_end {
                let call_in_run = wanted_call - call_base;
                return Ok((permutation + call_in_run * blocks, blocks));
            }
            call_base = call_end;
            permutation = permutation
                .checked_add(
                    count
                        .checked_mul(blocks)
                        .ok_or(SemanticH4BridgeBoundaryError::Shape)?,
                )
                .ok_or(SemanticH4BridgeBoundaryError::Shape)?;
        }
        Err(SemanticH4BridgeBoundaryError::Shape)
    }
}

fn evaluate_gate(kind: KeccakDagGateKind, left: Fp16, right: Fp16) -> Fp16 {
    match kind {
        KeccakDagGateKind::Xor => left + right - left * right - left * right,
        KeccakDagGateKind::NotLeftAndRight => right - left * right,
        KeccakDagGateKind::XorConstant(false) => left,
        KeccakDagGateKind::XorConstant(true) => Fp16::ONE - left,
        KeccakDagGateKind::Multiply => left * right,
        KeccakDagGateKind::Add => left + right,
        KeccakDagGateKind::RelayLeft => left,
        KeccakDagGateKind::Subtract => left - right,
        KeccakDagGateKind::Zero => Fp16::ZERO,
    }
}

fn from_bool(value: bool) -> Fp16 {
    if value { Fp16::ONE } else { Fp16::ZERO }
}

fn from_u32(value: u32) -> Result<Fp16, SemanticH4BridgeBoundaryError> {
    Ok(Fp16::from_m31(
        M31::from_canonical(value).map_err(|_| SemanticH4BridgeBoundaryError::Source)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    struct Fixture;

    impl SemanticH4BridgeBoundary for Fixture {
        fn input_bit(
            &self,
            permutation: usize,
            wire: usize,
        ) -> Result<bool, SemanticH4BridgeBoundaryError> {
            Ok((permutation + wire).is_multiple_of(2))
        }

        fn output_bit(
            &self,
            permutation: usize,
            wire: usize,
        ) -> Result<bool, SemanticH4BridgeBoundaryError> {
            Ok((permutation + wire).is_multiple_of(3))
        }

        fn message_live(&self, row: usize) -> Result<bool, SemanticH4BridgeBoundaryError> {
            Ok(row < 144)
        }

        fn message_value(&self, row: usize) -> Result<u8, SemanticH4BridgeBoundaryError> {
            Ok((row & 0xff) as u8)
        }

        fn digest_value(&self, row: usize) -> Result<u8, SemanticH4BridgeBoundaryError> {
            Ok((255 - (row & 0xff)) as u8)
        }
    }

    #[test]
    fn hand_rows_bind_semantic_ports_and_boundary_bits() {
        let source =
            SemanticH4BridgeBoundarySource::new(SemanticH4BridgeProfile::K128, &Fixture).unwrap();
        assert_eq!(
            source
                .source_value(SemanticH4BridgeCircuit::Rate, RATE_LIVE, 0)
                .unwrap(),
            Fp16::ONE
        );
        assert_eq!(
            source
                .source_value(SemanticH4BridgeCircuit::Rate, RATE_PREVIOUS_LIVE, 0)
                .unwrap(),
            Fp16::ZERO
        );
        assert_eq!(
            source
                .source_value(SemanticH4BridgeCircuit::Rate, RATE_VALUE, 37)
                .unwrap(),
            from_u32(37).unwrap()
        );
        assert_eq!(
            source
                .source_value(SemanticH4BridgeCircuit::Rate, RATE_INPUT_BITS_START, 0)
                .unwrap(),
            Fp16::ONE
        );
        assert_eq!(
            source
                .source_value(
                    SemanticH4BridgeCircuit::Rate,
                    RATE_PREDECESSOR_BITS_START,
                    0
                )
                .unwrap(),
            Fp16::ZERO
        );
        assert_eq!(
            source
                .source_value(SemanticH4BridgeCircuit::Rate, RATE_FINAL_BYTE_SELECTOR, 71)
                .unwrap(),
            Fp16::ONE
        );
        assert_eq!(
            source
                .source_value(SemanticH4BridgeCircuit::Capacity, BLOCK_INPUT_BITS_START, 0)
                .unwrap(),
            from_bool(CAPACITY_START.is_multiple_of(2))
        );
        assert_eq!(
            source
                .source_value(SemanticH4BridgeCircuit::Digest, DIGEST_EXPECTED_BYTE, 5)
                .unwrap(),
            from_u32(250).unwrap()
        );
    }

    #[test]
    fn padded_rows_are_zero_except_rate_public_constants() {
        let source =
            SemanticH4BridgeBoundarySource::new(SemanticH4BridgeProfile::K128, &Fixture).unwrap();
        let rate_group = 1usize << source.profile().rate_group_log();
        assert_eq!(
            source
                .source_value(SemanticH4BridgeCircuit::Rate, RATE_LIVE, rate_group - 1)
                .unwrap(),
            Fp16::ZERO
        );
        assert_eq!(
            source
                .source_value(SemanticH4BridgeCircuit::Rate, RATE_ONE, rate_group - 1)
                .unwrap(),
            Fp16::ONE
        );
        assert_eq!(
            source
                .source_value(SemanticH4BridgeCircuit::Inactive, 0, (1 << 19) - 1)
                .unwrap(),
            Fp16::ZERO
        );
    }

    #[test]
    fn packed_boundary_uses_wire_major_group_lane_mapping() {
        let descriptor =
            build_hash_bus_descriptor_with_state(ScheduleProfile::K128Calibration).unwrap();
        let groups = GROUP_COUNT as usize;
        let values = KECCAK_STATE_BITS * groups;
        let mut input = vec![0_u16; values];
        let mut output = vec![0_u16; values];
        input[7 * groups] = 1 | (1 << 15);
        output[9 * groups] = 1 << 3;
        let message_count = descriptor.total_calls as usize;
        let mut messages = vec![Vec::new(); message_count];
        messages[0] = b"abc".to_vec();
        let mut digests = vec![[0_u8; DIGEST_BYTES]; message_count];
        digests[0] = Sha3_512::digest(b"abc").into();
        let boundary = PackedB16SemanticH4Boundary {
            descriptor,
            shards: vec![HashBusB16Shard { input, output }],
            messages,
            digests,
        };
        assert!(boundary.input_bit(0, 7).unwrap());
        assert!(boundary.input_bit(15, 7).unwrap());
        assert!(!boundary.input_bit(1, 7).unwrap());
        assert!(boundary.output_bit(3, 9).unwrap());
        assert_eq!(boundary.message_cell(0).unwrap(), (true, b'a'));
        assert_eq!(boundary.message_cell(3).unwrap(), (false, 0));
        assert_eq!(
            boundary.digest_value(0).unwrap(),
            Sha3_512::digest(b"abc")[0]
        );
    }

    #[test]
    fn compact_group_evaluator_satisfies_hand_rate_relation() {
        struct ValidRateRow;
        impl SemanticH4BridgeBoundary for ValidRateRow {
            fn input_bit(
                &self,
                permutation: usize,
                wire: usize,
            ) -> Result<bool, SemanticH4BridgeBoundaryError> {
                Ok(!(permutation == 0 && wire < 8) && (permutation + wire).is_multiple_of(2))
            }
            fn output_bit(
                &self,
                permutation: usize,
                wire: usize,
            ) -> Result<bool, SemanticH4BridgeBoundaryError> {
                Ok((permutation + wire).is_multiple_of(3))
            }
            fn message_live(&self, row: usize) -> Result<bool, SemanticH4BridgeBoundaryError> {
                Ok(row < 72)
            }
            fn message_value(&self, row: usize) -> Result<u8, SemanticH4BridgeBoundaryError> {
                Ok(if row == 0 { 0 } else { (row & 0xff) as u8 })
            }
            fn digest_value(&self, row: usize) -> Result<u8, SemanticH4BridgeBoundaryError> {
                Ok((row & 0xff) as u8)
            }
        }
        let source =
            SemanticH4BridgeBoundarySource::new(SemanticH4BridgeProfile::K128, &ValidRateRow)
                .unwrap();
        let rows = source
            .evaluate_group(SemanticH4BridgeCircuit::Rate, 0)
            .unwrap();
        assert_eq!(rows.len(), 8);
        assert_eq!(rows.last().unwrap()[0], Fp16::ZERO);
    }
}
