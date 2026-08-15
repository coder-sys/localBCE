//! Proof-native compact state relation for the custom GKR boundary.
//!
//! The state witness is laid out as four canonical entries per fixed-capacity
//! row: operation-before, operation-after, snapshot-before, and
//! snapshot-after.  Each 64-byte field is split into 3-byte chunks and up to
//! sixteen chunks are packed into the coefficients of one Fp16 element.  The
//! relation therefore uses field-linear equality gates instead of expanding
//! the complete state file into a second Boolean Keccak circuit.
//!
//! The single shared-group layer proves, for every row, that operation and
//! snapshot entries agree, that the authenticated slot index matches the
//! canonical group position, that presence is Boolean, and that empty entries
//! contain no private bytes.  The two source boundaries are the same
//! canonical table at different wire points; the returned terminals are the
//! exact claims that a PCS boundary must bind.  This module is a proof-native
//! GKR control, not an activation or qualification decision.

use alloc::{collections::BTreeSet, vec, vec::Vec};
use core::fmt;

#[cfg(feature = "std")]
use std::path::Path;

use sha3::{Digest, Sha3_512};

use crate::{
    field::{Fp16, M31},
    fp16_relay_free_gkr_uniform::{UniformGkrMaskConstraint, UniformGkrMaskFunctional},
    gkr_sumcheck::{
        LayerOutputClaim, MaskedUniformSharedGroupDagLayerProof, ProductSumcheckError,
        SharedGroupDagLayerProof, prove_masked_shared_group_dag_layer_interactive,
        prove_shared_group_dag_layer_reference, shared_group_terminal_gate_claim,
        verify_shared_group_dag_layer_reference,
    },
    gkr_zk_mask::{
        GkrZkMaskError, LibraLayerMask, LibraPriorLayerCorrection, LibraVariableDegreeSumcheckMask,
        boolean_vanishing, polynomial_evaluation,
    },
    keccak_gkr_dag::{KeccakDagGate, KeccakDagGateKind, KeccakDagLayer, KeccakDagSource},
    multilinear_pcs::{
        MultilinearOpeningClaim, MultilinearPcsError, PackedGkrInputClaims, evaluate_multilinear,
    },
};

pub const STATE_RELATION_GROUP_COUNT: usize = 1 << 12;
pub const STATE_RELATION_SOURCE_WIDTH: usize = 1 << 6;
pub const STATE_RELATION_WIRE_VARIABLES: usize = 6;
pub const STATE_RELATION_GROUP_VARIABLES: usize = 12;
pub const STATE_RELATION_OUTPUT_WIDTH: usize = 1 << 5;
pub const STATE_RELATION_OUTPUT_VARIABLES: usize = 5;
pub const STATE_RELATION_CHUNK_BYTES: usize = 3;
pub const STATE_RELATION_CHUNK_COUNT: usize = 22;
pub const STATE_RELATION_ENTRY_WIDTH: usize = 1 + 1 + 2 * 2;
pub const STATE_RELATION_ROW_WIDTH: usize = 4 * STATE_RELATION_ENTRY_WIDTH;
pub const STATE_RELATION_ROW_INDEX_WIRE: usize = STATE_RELATION_ROW_WIDTH;
pub const STATE_RELATION_OUTPUT_RAW_WIDTH: usize =
    2 * STATE_RELATION_ENTRY_WIDTH + 2 + 2 * (STATE_RELATION_ENTRY_WIDTH - 2) + 4;
pub const STATE_RELATION_H4_WIRE_OFFSET: usize = 1_600;
pub const STATE_RELATION_H4_WIRE_VARIABLES: usize = 11;
pub const STATE_RELATION_H4_GROUP_VARIABLES: usize = 13;
pub const STATE_RELATION_H4_POINT_VARIABLES: usize = 24;
pub const STATE_RELATION_SOURCE_BYTES: usize =
    STATE_RELATION_GROUP_COUNT * STATE_RELATION_SOURCE_WIDTH * 64;
pub const STATE_RELATION_SOURCE_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/STATE-RELATION-SOURCE/v2\0";
pub const STATE_RELATION_TRANSCRIPT_DOMAIN: &[u8] =
    b"BL/PQ512/WAVE2/STATE-RELATION-TRANSCRIPT/v2\0";
pub const STATE_RELATION_OUTPUT_CHALLENGE_COUNT: u16 = 19;

const ENTRY_BYTES: usize = 64;
const FP16_COEFFICIENTS: usize = 16;
const ZERO_ENTRY: [u8; ENTRY_BYTES] = [0; ENTRY_BYTES];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateRelationEntry {
    /// The authenticated fixed-capacity slot index.  It is retained in the
    /// proof source instead of being dropped by the envelope adapter.
    pub index: u32,
    pub present: bool,
    pub key: [u8; ENTRY_BYTES],
    pub value: [u8; ENTRY_BYTES],
}

impl StateRelationEntry {
    pub const fn empty() -> Self {
        Self {
            index: 0,
            present: false,
            key: [0; ENTRY_BYTES],
            value: [0; ENTRY_BYTES],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateRelationRow {
    pub operation_before: StateRelationEntry,
    pub operation_after: StateRelationEntry,
    pub snapshot_before: StateRelationEntry,
    pub snapshot_after: StateRelationEntry,
}

impl StateRelationRow {
    pub const fn empty() -> Self {
        Self {
            operation_before: StateRelationEntry::empty(),
            operation_after: StateRelationEntry::empty(),
            snapshot_before: StateRelationEntry::empty(),
            snapshot_after: StateRelationEntry::empty(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateRelationGkrError {
    Capacity,
    DuplicateKey,
    Encoding,
    Shape,
    Evaluation,
    Gkr(ProductSumcheckError),
    Mask(GkrZkMaskError),
}

impl fmt::Display for StateRelationGkrError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "state relation GKR error: {self:?}")
    }
}

impl core::error::Error for StateRelationGkrError {}

impl From<ProductSumcheckError> for StateRelationGkrError {
    fn from(error: ProductSumcheckError) -> Self {
        Self::Gkr(error)
    }
}

impl From<GkrZkMaskError> for StateRelationGkrError {
    fn from(error: GkrZkMaskError) -> Self {
        Self::Mask(error)
    }
}

impl From<MultilinearPcsError> for StateRelationGkrError {
    fn from(_: MultilinearPcsError) -> Self {
        Self::Evaluation
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateRelationGkrProof {
    pub output_claim: LayerOutputClaim,
    pub group_challenges: Vec<Fp16>,
    pub wire_challenges: Vec<Fp16>,
    pub layer: SharedGroupDagLayerProof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaskedStateRelationGkrProof {
    pub output_claim: LayerOutputClaim,
    pub sumcheck_rho: Fp16,
    pub layer: MaskedUniformSharedGroupDagLayerProof,
}

/// Verifier-safe public view of the masked state-relation reduction.
///
/// Raw source rows, mask coefficients, base polynomials, and raw terminal
/// evaluations are intentionally absent.  The two raw terminal values enter
/// verification only as independently authenticated H4 PCS input claims.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicMaskedStateRelationGkrProof {
    pub output_claim: LayerOutputClaim,
    pub sumcheck_rho: Fp16,
    pub published_rounds: Vec<Vec<Fp16>>,
    pub group_challenges: Vec<Fp16>,
    pub wire_challenges: Vec<Fp16>,
    pub masked_terminal_left: Fp16,
    pub masked_terminal_right: Fp16,
    pub w_challenge: Fp16,
}

impl PublicMaskedStateRelationGkrProof {
    pub fn from_private(proof: &MaskedStateRelationGkrProof) -> Self {
        Self {
            output_claim: proof.output_claim.clone(),
            sumcheck_rho: proof.sumcheck_rho,
            published_rounds: proof.layer.published_rounds.clone(),
            group_challenges: proof.layer.group_challenges.clone(),
            wire_challenges: proof.layer.wire_challenges.clone(),
            masked_terminal_left: proof.layer.masked_terminal_left,
            masked_terminal_right: proof.layer.masked_terminal_right,
            w_challenge: proof.layer.w_challenge,
        }
    }
}

/// Canonical authenticated output-query message for the state relation.
pub fn state_relation_output_message(source_digest: [u8; 64]) -> Vec<u8> {
    let mut message = Vec::with_capacity(STATE_RELATION_TRANSCRIPT_DOMAIN.len() + 64 + 8);
    message.extend_from_slice(STATE_RELATION_TRANSCRIPT_DOMAIN);
    message.extend_from_slice(b"OUTPUT\0");
    message.extend_from_slice(&source_digest);
    message.extend_from_slice(&STATE_RELATION_OUTPUT_CHALLENGE_COUNT.to_be_bytes());
    message
}

/// Canonical authenticated sumcheck/terminal message for the state relation.
pub fn state_relation_round_message(
    source_digest: [u8; 64],
    kind: u16,
    round: usize,
    published: &[Fp16],
) -> Result<Vec<u8>, StateRelationGkrError> {
    let mut message = Vec::with_capacity(
        STATE_RELATION_TRANSCRIPT_DOMAIN.len() + 64 + 2 + 4 + published.len() * 64,
    );
    message.extend_from_slice(STATE_RELATION_TRANSCRIPT_DOMAIN);
    message.extend_from_slice(&source_digest);
    message.extend_from_slice(&kind.to_be_bytes());
    message.extend_from_slice(
        &u32::try_from(round)
            .map_err(|_| StateRelationGkrError::Shape)?
            .to_be_bytes(),
    );
    for value in published {
        message.extend_from_slice(&value.encode());
    }
    Ok(message)
}

/// Digest the exact verifier-safe state-relation public view.  Raw terminals
/// and source rows are absent; the two raw PCS values are bound separately by
/// the fixed H4 claim boundary.
pub fn public_state_relation_transcript_digest(
    source_digest: [u8; 64],
    proof: &PublicMaskedStateRelationGkrProof,
    shard_query: Fp16,
) -> Result<[u8; 64], StateRelationGkrError> {
    verify_public_masked_state_relation_gkr(proof)?;
    let mut hash = Sha3_512::new();
    hash.update(STATE_RELATION_TRANSCRIPT_DOMAIN);
    hash.update(source_digest);
    hash.update(shard_query.encode());
    hash.update(
        u32::try_from(proof.output_claim.point.len())
            .map_err(|_| StateRelationGkrError::Shape)?
            .to_be_bytes(),
    );
    for value in &proof.output_claim.point {
        hash.update(value.encode());
    }
    hash.update(proof.output_claim.value.encode());
    hash.update(proof.output_claim.coefficient.encode());
    hash.update(proof.sumcheck_rho.encode());
    for challenge in &proof.group_challenges {
        hash.update(challenge.encode());
    }
    for challenge in &proof.wire_challenges {
        hash.update(challenge.encode());
    }
    for round in &proof.published_rounds {
        for value in round {
            hash.update(value.encode());
        }
    }
    hash.update(proof.masked_terminal_left.encode());
    hash.update(proof.masked_terminal_right.encode());
    hash.update(proof.w_challenge.encode());
    Ok(hash.finalize().into())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateRelationH4InputClaim {
    pub boundary: u8,
    pub point: Vec<Fp16>,
    pub value: Fp16,
    pub shard_query: Fp16,
}

pub(crate) fn pack_chunks(bytes: &[u8; ENTRY_BYTES]) -> Result<[Fp16; 2], StateRelationGkrError> {
    let mut packed = [Fp16::ZERO; 2];
    for (pack_index, destination) in packed.iter_mut().enumerate() {
        let mut coefficients = [0_u32; FP16_COEFFICIENTS];
        for (coefficient, destination) in coefficients.iter_mut().enumerate() {
            let chunk = pack_index * FP16_COEFFICIENTS + coefficient;
            let offset = chunk * STATE_RELATION_CHUNK_BYTES;
            if offset >= bytes.len() {
                break;
            }
            let mut value = 0_u32;
            for byte in &bytes[offset..bytes.len().min(offset + STATE_RELATION_CHUNK_BYTES)] {
                value = (value << 8) | u32::from(*byte);
            }
            *destination = value;
        }
        *destination =
            Fp16::from_coefficients(coefficients).map_err(|_| StateRelationGkrError::Encoding)?;
    }
    Ok(packed)
}

fn pack_entry(
    entry: StateRelationEntry,
) -> Result<[Fp16; STATE_RELATION_ENTRY_WIDTH], StateRelationGkrError> {
    if !entry.present && (entry.key != ZERO_ENTRY || entry.value != ZERO_ENTRY) {
        return Err(StateRelationGkrError::Encoding);
    }
    let index = Fp16::from_m31(
        M31::from_canonical(entry.index).map_err(|_| StateRelationGkrError::Encoding)?,
    );
    let present = Fp16::from_m31(
        M31::from_canonical(u32::from(entry.present))
            .map_err(|_| StateRelationGkrError::Encoding)?,
    );
    let key = pack_chunks(&entry.key)?;
    let value = pack_chunks(&entry.value)?;
    Ok([index, present, key[0], key[1], value[0], value[1]])
}

fn scalar_u32(value: Fp16) -> Result<u32, StateRelationGkrError> {
    let coefficients = value.coefficients();
    if coefficients[1..]
        .iter()
        .any(|coefficient| *coefficient != 0)
    {
        return Err(StateRelationGkrError::Encoding);
    }
    Ok(coefficients[0])
}

fn unpack_chunks(packed: [Fp16; 2]) -> Result<[u8; ENTRY_BYTES], StateRelationGkrError> {
    let mut bytes = [0_u8; ENTRY_BYTES];
    for (pack_index, value) in packed.into_iter().enumerate() {
        for (coefficient, chunk_value) in value.coefficients().into_iter().enumerate() {
            let chunk = pack_index * FP16_COEFFICIENTS + coefficient;
            let offset = chunk * STATE_RELATION_CHUNK_BYTES;
            if offset >= ENTRY_BYTES {
                if chunk_value != 0 {
                    return Err(StateRelationGkrError::Encoding);
                }
                continue;
            }
            let width = (ENTRY_BYTES - offset).min(STATE_RELATION_CHUNK_BYTES);
            if (width < STATE_RELATION_CHUNK_BYTES && chunk_value >= 1 << (8 * width))
                || chunk_value >= 1 << 24
            {
                return Err(StateRelationGkrError::Encoding);
            }
            let encoded = chunk_value.to_be_bytes();
            bytes[offset..offset + width].copy_from_slice(&encoded[4 - width..]);
        }
    }
    Ok(bytes)
}

fn unpack_entry(
    source: &[Fp16],
    offset: usize,
) -> Result<StateRelationEntry, StateRelationGkrError> {
    let fields = source
        .get(offset..offset + STATE_RELATION_ENTRY_WIDTH)
        .ok_or(StateRelationGkrError::Shape)?;
    let present = match scalar_u32(fields[1])? {
        0 => false,
        1 => true,
        _ => return Err(StateRelationGkrError::Encoding),
    };
    let entry = StateRelationEntry {
        index: scalar_u32(fields[0])?,
        present,
        key: unpack_chunks([fields[2], fields[3]])?,
        value: unpack_chunks([fields[4], fields[5]])?,
    };
    if !entry.present && (entry.key != ZERO_ENTRY || entry.value != ZERO_ENTRY) {
        return Err(StateRelationGkrError::Encoding);
    }
    Ok(entry)
}

fn append_entry(
    destination: &mut [Fp16],
    cursor: &mut usize,
    entry: StateRelationEntry,
) -> Result<(), StateRelationGkrError> {
    let packed = pack_entry(entry)?;
    let end = cursor
        .checked_add(packed.len())
        .ok_or(StateRelationGkrError::Shape)?;
    if end > destination.len() {
        return Err(StateRelationGkrError::Shape);
    }
    destination[*cursor..end].copy_from_slice(&packed);
    *cursor = end;
    Ok(())
}

/// Encode the canonical state relation table in group-major / wire-minor order.
pub fn build_state_relation_source(
    rows: &[StateRelationRow],
) -> Result<Vec<Fp16>, StateRelationGkrError> {
    if rows.len() > STATE_RELATION_GROUP_COUNT {
        return Err(StateRelationGkrError::Capacity);
    }
    let mut source = vec![Fp16::ZERO; STATE_RELATION_GROUP_COUNT * STATE_RELATION_SOURCE_WIDTH];
    let mut seen = [
        BTreeSet::<[u8; ENTRY_BYTES]>::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
    ];
    for (group, row) in rows.iter().copied().enumerate() {
        let expected_index = u32::try_from(group).map_err(|_| StateRelationGkrError::Shape)?;
        for (phase, entry) in [
            row.operation_before,
            row.operation_after,
            row.snapshot_before,
            row.snapshot_after,
        ]
        .into_iter()
        .enumerate()
        {
            if entry.index != expected_index {
                return Err(StateRelationGkrError::Shape);
            }
            if entry.present && !seen[phase].insert(entry.key) {
                return Err(StateRelationGkrError::DuplicateKey);
            }
        }
        let start = group * STATE_RELATION_SOURCE_WIDTH;
        let end = start + STATE_RELATION_SOURCE_WIDTH;
        let destination = &mut source[start..end];
        let mut cursor = 0;
        append_entry(destination, &mut cursor, row.operation_before)?;
        append_entry(destination, &mut cursor, row.operation_after)?;
        append_entry(destination, &mut cursor, row.snapshot_before)?;
        append_entry(destination, &mut cursor, row.snapshot_after)?;
        let row_index = Fp16::from_m31(
            M31::from_canonical(expected_index).map_err(|_| StateRelationGkrError::Encoding)?,
        );
        if cursor >= destination.len() {
            return Err(StateRelationGkrError::Shape);
        }
        destination[cursor] = row_index;
        cursor += 1;
        if cursor != STATE_RELATION_ROW_INDEX_WIRE + 1 {
            return Err(StateRelationGkrError::Shape);
        }
    }
    Ok(source)
}

/// Recover the canonical bounded rows from the independently decoded H4 state
/// source. This is the inverse of `build_state_relation_source` for the active
/// profile prefix and lets post-commitment state subproofs consume the exact
/// committed representation instead of a second host-provided witness.
pub fn state_relation_rows_from_source(
    source: &[Fp16],
    capacity: usize,
) -> Result<Vec<StateRelationRow>, StateRelationGkrError> {
    if source.len() != STATE_RELATION_GROUP_COUNT * STATE_RELATION_SOURCE_WIDTH
        || capacity == 0
        || capacity > STATE_RELATION_GROUP_COUNT
    {
        return Err(StateRelationGkrError::Shape);
    }
    let mut rows = Vec::with_capacity(capacity);
    for group in 0..capacity {
        let row =
            &source[group * STATE_RELATION_SOURCE_WIDTH..(group + 1) * STATE_RELATION_SOURCE_WIDTH];
        let recovered = StateRelationRow {
            operation_before: unpack_entry(row, 0)?,
            operation_after: unpack_entry(row, STATE_RELATION_ENTRY_WIDTH)?,
            snapshot_before: unpack_entry(row, 2 * STATE_RELATION_ENTRY_WIDTH)?,
            snapshot_after: unpack_entry(row, 3 * STATE_RELATION_ENTRY_WIDTH)?,
        };
        let expected = u32::try_from(group).map_err(|_| StateRelationGkrError::Shape)?;
        if [
            recovered.operation_before.index,
            recovered.operation_after.index,
            recovered.snapshot_before.index,
            recovered.snapshot_after.index,
        ]
        .into_iter()
        .any(|index| index != expected)
            || scalar_u32(row[STATE_RELATION_ROW_INDEX_WIRE])? != expected
        {
            return Err(StateRelationGkrError::Shape);
        }
        rows.push(recovered);
    }
    if source[capacity * STATE_RELATION_SOURCE_WIDTH..]
        .iter()
        .any(|value| !value.is_zero())
    {
        return Err(StateRelationGkrError::Shape);
    }
    Ok(rows)
}

/// Encode the relation source in the wire-major order consumed by the H4
/// semantic initializer. The proof-native GKR source is group-major; keeping
/// this conversion here gives the H4 source lane and the native relation
/// verifier one canonical byte representation.
pub fn build_state_relation_wire_source(
    rows: &[StateRelationRow],
) -> Result<Vec<u8>, StateRelationGkrError> {
    let source = build_state_relation_source(rows)?;
    let mut encoded = Vec::with_capacity(STATE_RELATION_SOURCE_BYTES);
    for wire in 0..STATE_RELATION_SOURCE_WIDTH {
        for group in 0..STATE_RELATION_GROUP_COUNT {
            encoded.extend_from_slice(&source[group * STATE_RELATION_SOURCE_WIDTH + wire].encode());
        }
    }
    Ok(encoded)
}

pub fn state_relation_source_digest(encoded: &[u8]) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(STATE_RELATION_SOURCE_DOMAIN);
    hash.update((encoded.len() as u64).to_be_bytes());
    hash.update(encoded);
    hash.finalize().into()
}

#[cfg(feature = "std")]
pub fn read_state_relation_wire_source(
    path: &Path,
    expected_digest: [u8; 64],
) -> Result<Vec<Fp16>, StateRelationGkrError> {
    let encoded = std::fs::read(path).map_err(|_| StateRelationGkrError::Encoding)?;
    if encoded.len() != STATE_RELATION_SOURCE_BYTES
        || state_relation_source_digest(&encoded) != expected_digest
    {
        return Err(StateRelationGkrError::Encoding);
    }
    let mut source = vec![Fp16::ZERO; STATE_RELATION_GROUP_COUNT * STATE_RELATION_SOURCE_WIDTH];
    for wire in 0..STATE_RELATION_SOURCE_WIDTH {
        for group in 0..STATE_RELATION_GROUP_COUNT {
            let start = (wire * STATE_RELATION_GROUP_COUNT + group) * 64;
            let value = Fp16::decode(
                encoded[start..start + 64]
                    .try_into()
                    .map_err(|_| StateRelationGkrError::Encoding)?,
            )
            .map_err(|_| StateRelationGkrError::Encoding)?;
            source[group * STATE_RELATION_SOURCE_WIDTH + wire] = value;
        }
    }
    Ok(source)
}

fn relation_layer() -> KeccakDagLayer {
    let mut gates = Vec::with_capacity(STATE_RELATION_OUTPUT_RAW_WIDTH);

    // Four entries are laid out as operation-before, operation-after,
    // snapshot-before, snapshot-after.  Equality is field subtraction so a
    // packed chunk is zero exactly when all sixteen coefficients agree.
    for phase in 0..2 {
        let operation = phase * STATE_RELATION_ENTRY_WIDTH;
        let snapshot = (phase + 2) * STATE_RELATION_ENTRY_WIDTH;
        for field in 0..STATE_RELATION_ENTRY_WIDTH {
            gates.push(KeccakDagGate {
                left: operation + field,
                right: snapshot + field,
                kind: KeccakDagGateKind::Subtract,
            });
        }
    }

    // p(1-p) rejects non-Boolean presence values, and
    // field*(1-p) rejects private bytes in an empty slot.
    for phase in 0..2 {
        let operation = phase * STATE_RELATION_ENTRY_WIDTH;
        let present = operation + 1;
        gates.push(KeccakDagGate {
            left: present,
            right: present,
            kind: KeccakDagGateKind::NotLeftAndRight,
        });
        for field in 2..STATE_RELATION_ENTRY_WIDTH {
            gates.push(KeccakDagGate {
                left: present,
                right: operation + field,
                kind: KeccakDagGateKind::NotLeftAndRight,
            });
        }
    }

    // The row-index wire is canonical group-major position.  Every four
    // decoded entries must carry that same position, so an otherwise valid
    // permutation of state slots cannot pass the proof-native relation.
    for entry in 0..4 {
        gates.push(KeccakDagGate {
            left: entry * STATE_RELATION_ENTRY_WIDTH,
            right: STATE_RELATION_ROW_INDEX_WIRE,
            kind: KeccakDagGateKind::Subtract,
        });
    }

    debug_assert_eq!(gates.len(), STATE_RELATION_OUTPUT_RAW_WIDTH);
    gates.resize(
        STATE_RELATION_OUTPUT_WIDTH,
        KeccakDagGate {
            left: 0,
            right: 0,
            kind: KeccakDagGateKind::Zero,
        },
    );
    KeccakDagLayer {
        left_source: KeccakDagSource::RoundInput,
        right_source: KeccakDagSource::RoundInput,
        left_width: STATE_RELATION_SOURCE_WIDTH,
        right_width: STATE_RELATION_SOURCE_WIDTH,
        raw_width: STATE_RELATION_OUTPUT_RAW_WIDTH,
        padded_width: STATE_RELATION_OUTPUT_WIDTH,
        gates,
    }
}

fn evaluate_gate(kind: KeccakDagGateKind, left: Fp16, right: Fp16) -> Fp16 {
    match kind {
        KeccakDagGateKind::Subtract => left - right,
        KeccakDagGateKind::NotLeftAndRight => right - left * right,
        KeccakDagGateKind::Multiply => left * right,
        KeccakDagGateKind::Add => left + right,
        KeccakDagGateKind::RelayLeft => left,
        KeccakDagGateKind::Zero => Fp16::ZERO,
        _ => unreachable!("non-state gate in the compact state relation"),
    }
}

fn evaluate_output(
    layer: &KeccakDagLayer,
    source: &[Fp16],
) -> Result<Vec<Fp16>, StateRelationGkrError> {
    if source.len() != STATE_RELATION_GROUP_COUNT * STATE_RELATION_SOURCE_WIDTH {
        return Err(StateRelationGkrError::Shape);
    }
    let mut output = Vec::with_capacity(STATE_RELATION_GROUP_COUNT * STATE_RELATION_OUTPUT_WIDTH);
    for group in 0..STATE_RELATION_GROUP_COUNT {
        let row =
            &source[group * STATE_RELATION_SOURCE_WIDTH..(group + 1) * STATE_RELATION_SOURCE_WIDTH];
        for gate in &layer.gates {
            let left = row.get(gate.left).ok_or(StateRelationGkrError::Shape)?;
            let right = row.get(gate.right).ok_or(StateRelationGkrError::Shape)?;
            output.push(evaluate_gate(gate.kind, *left, *right));
        }
    }
    Ok(output)
}

fn validate_challenges(
    output_claim: &LayerOutputClaim,
    group_challenges: &[Fp16],
    wire_challenges: &[Fp16],
) -> Result<(), StateRelationGkrError> {
    if output_claim.coefficient != Fp16::ONE
        || output_claim.point.len()
            != STATE_RELATION_OUTPUT_VARIABLES + STATE_RELATION_GROUP_VARIABLES
        || group_challenges.len() != STATE_RELATION_GROUP_VARIABLES
        || wire_challenges.len() != 2 * STATE_RELATION_WIRE_VARIABLES
    {
        return Err(StateRelationGkrError::Shape);
    }
    Ok(())
}

/// Prove and independently verify the compact state relation against fixed
/// public-coin challenges.  The returned source terminals are the claims that
/// must be handed to the selected PCS before the H4 parent is accepted.
pub fn prove_state_relation_gkr(
    source: &[Fp16],
    output_claim: LayerOutputClaim,
    group_challenges: Vec<Fp16>,
    wire_challenges: Vec<Fp16>,
) -> Result<StateRelationGkrProof, StateRelationGkrError> {
    validate_challenges(&output_claim, &group_challenges, &wire_challenges)?;
    let layer = relation_layer();
    let output = evaluate_output(&layer, source)?;
    let expected = evaluate_multilinear(&output, &output_claim.point)?;
    if expected != output_claim.value {
        return Err(StateRelationGkrError::Gkr(ProductSumcheckError::Claim));
    }
    let proof = prove_shared_group_dag_layer_reference(
        &layer,
        STATE_RELATION_GROUP_COUNT,
        source,
        source,
        core::slice::from_ref(&output_claim),
        &group_challenges,
        &wire_challenges,
    )?;
    Ok(StateRelationGkrProof {
        output_claim,
        group_challenges,
        wire_challenges,
        layer: proof,
    })
}

/// Verify the state relation algebra without trusting the source table.  The
/// source openings returned by [`state_relation_input_claims`] are what bind
/// this relation to a PCS commitment.
pub fn verify_state_relation_gkr(
    proof: &StateRelationGkrProof,
) -> Result<(), StateRelationGkrError> {
    validate_challenges(
        &proof.output_claim,
        &proof.group_challenges,
        &proof.wire_challenges,
    )?;
    if !proof.output_claim.value.is_zero() {
        return Err(StateRelationGkrError::Gkr(ProductSumcheckError::Claim));
    }
    verify_shared_group_dag_layer_reference(
        &relation_layer(),
        STATE_RELATION_GROUP_COUNT,
        core::slice::from_ref(&proof.output_claim),
        &proof.group_challenges,
        &proof.wire_challenges,
        &proof.layer,
    )?;
    Ok(())
}

/// Convert the two same-table GKR terminals into the exact selected PCS input
/// claim shape.  The three packed shard variables are owned by the PCS; this
/// relation occupies the remaining six wire plus twelve group variables.
pub fn state_relation_input_claims(
    proof: &StateRelationGkrProof,
    shard_query: Fp16,
) -> Result<PackedGkrInputClaims, StateRelationGkrError> {
    validate_challenges(
        &proof.output_claim,
        &proof.group_challenges,
        &proof.wire_challenges,
    )?;
    let mut left_point =
        Vec::with_capacity(STATE_RELATION_WIRE_VARIABLES + STATE_RELATION_GROUP_VARIABLES);
    left_point.extend_from_slice(&proof.wire_challenges[..STATE_RELATION_WIRE_VARIABLES]);
    left_point.extend_from_slice(&proof.group_challenges);
    let mut right_point = Vec::with_capacity(left_point.len());
    right_point.extend_from_slice(&proof.wire_challenges[STATE_RELATION_WIRE_VARIABLES..]);
    right_point.extend_from_slice(&proof.group_challenges);
    Ok(PackedGkrInputClaims {
        claims: [
            MultilinearOpeningClaim {
                point: left_point,
                value: proof.layer.wire_proof.terminal_left,
            },
            MultilinearOpeningClaim {
                point: right_point,
                value: proof.layer.wire_proof.terminal_right,
            },
        ],
        shard_query,
        wire_variables: STATE_RELATION_WIRE_VARIABLES as u8,
    })
}

pub(crate) fn h4_state_point(local_point: &[Fp16]) -> Result<Vec<Fp16>, StateRelationGkrError> {
    if local_point.len() != STATE_RELATION_WIRE_VARIABLES + STATE_RELATION_GROUP_VARIABLES {
        return Err(StateRelationGkrError::Shape);
    }
    let mut point = Vec::with_capacity(STATE_RELATION_H4_POINT_VARIABLES);
    // H4 low coordinates are wire bits [0..11), followed by the low five
    // group bits. The state lane starts at wire 1600 = 25*64, so its upper
    // wire bits are fixed constants and its six low bits are the local point.
    point.extend_from_slice(&local_point[..STATE_RELATION_WIRE_VARIABLES]);
    for bit in 6..STATE_RELATION_H4_WIRE_VARIABLES {
        point.push(if (STATE_RELATION_H4_WIRE_OFFSET >> bit) & 1 == 1 {
            Fp16::ONE
        } else {
            Fp16::ZERO
        });
    }
    point.extend_from_slice(
        &local_point[STATE_RELATION_WIRE_VARIABLES..STATE_RELATION_WIRE_VARIABLES + 5],
    );
    point.extend_from_slice(&local_point[STATE_RELATION_WIRE_VARIABLES + 5..]);
    // The H4 source has 2^13 groups; the state lane occupies groups 0..2^12.
    point.push(Fp16::ZERO);
    if point.len() != STATE_RELATION_H4_POINT_VARIABLES {
        return Err(StateRelationGkrError::Shape);
    }
    Ok(point)
}

/// Lift the two local state terminals into the exact 24-coordinate H4 PCS
/// source geometry. Both claims live on boundary one, where the existing H4
/// row-batched PCS authenticates all relay-free input openings.
pub fn state_relation_h4_input_claims(
    proof: &StateRelationGkrProof,
    shard_query: Fp16,
) -> Result<[StateRelationH4InputClaim; 2], StateRelationGkrError> {
    let claims = state_relation_input_claims(proof, shard_query)?;
    Ok(core::array::from_fn(|index| StateRelationH4InputClaim {
        boundary: 1,
        point: h4_state_point(&claims.claims[index].point).expect("validated state point"),
        value: claims.claims[index].value,
        shard_query,
    }))
}

/// Authenticate a state GKR layer with the same interactive public coin used
/// by the H4 prelude. The output point is fixed only after the source lane is
/// committed by the caller; every group/wire polynomial message is published
/// to the callback before its challenge is released.
pub fn prove_state_relation_gkr_interactive(
    source: &[Fp16],
    output_point: Vec<Fp16>,
    mut challenge: impl FnMut(
        StateRelationRoundKind,
        usize,
        &[Fp16],
    ) -> Result<Fp16, StateRelationGkrError>,
) -> Result<StateRelationGkrProof, StateRelationGkrError> {
    let output_claim = LayerOutputClaim {
        point: output_point,
        value: Fp16::ZERO,
        coefficient: Fp16::ONE,
    };
    if output_claim.point.len() != STATE_RELATION_OUTPUT_VARIABLES + STATE_RELATION_GROUP_VARIABLES
    {
        return Err(StateRelationGkrError::Shape);
    }
    let layer = relation_layer();
    let output = evaluate_output(&layer, source)?;
    if evaluate_multilinear(&output, &output_claim.point)? != Fp16::ZERO {
        return Err(StateRelationGkrError::Gkr(ProductSumcheckError::Claim));
    }
    let (proof, group_challenges, wire_challenges) =
        crate::gkr_sumcheck::prove_shared_group_dag_layer_interactive(
            &layer,
            STATE_RELATION_GROUP_COUNT,
            source,
            source,
            core::slice::from_ref(&output_claim),
            |kind, round, published| {
                let state_kind = match kind {
                    crate::gkr_sumcheck::SharedGroupDagRoundKind::Group => {
                        StateRelationRoundKind::Group
                    }
                    crate::gkr_sumcheck::SharedGroupDagRoundKind::LeftWire
                    | crate::gkr_sumcheck::SharedGroupDagRoundKind::RightWire => {
                        StateRelationRoundKind::Wire
                    }
                };
                challenge(state_kind, round, published).map_err(|_| ProductSumcheckError::Claim)
            },
        )?;
    Ok(StateRelationGkrProof {
        output_claim,
        group_challenges,
        wire_challenges,
        layer: proof,
    })
}

/// Native witness-hiding state-relation reduction. The caller must source
/// `sumcheck_rho`, every round challenge, and the terminal challenge from the
/// authenticated message-first public coin after the mask commitment exists.
/// The returned raw terminals are prover-internal PCS claims; only the masked
/// terminals and published polynomials belong in the public transcript.
#[allow(clippy::too_many_arguments)]
pub fn prove_masked_state_relation_gkr_interactive(
    source: &[Fp16],
    output_point: Vec<Fp16>,
    sumcheck_mask: &LibraVariableDegreeSumcheckMask,
    layer_mask: &LibraLayerMask,
    sumcheck_rho: Fp16,
    mut challenge: impl FnMut(
        StateRelationRoundKind,
        usize,
        &[Fp16],
    ) -> Result<Fp16, StateRelationGkrError>,
    mut terminal_challenge: impl FnMut(&[Fp16], Fp16, Fp16) -> Result<Fp16, StateRelationGkrError>,
) -> Result<MaskedStateRelationGkrProof, StateRelationGkrError> {
    let output_claim = LayerOutputClaim {
        point: output_point,
        value: Fp16::ZERO,
        coefficient: Fp16::ONE,
    };
    if output_claim.point.len() != STATE_RELATION_OUTPUT_VARIABLES + STATE_RELATION_GROUP_VARIABLES
        || sumcheck_rho.is_zero()
    {
        return Err(StateRelationGkrError::Shape);
    }
    let layer = relation_layer();
    let output = evaluate_output(&layer, source)?;
    if evaluate_multilinear(&output, &output_claim.point)? != Fp16::ZERO {
        return Err(StateRelationGkrError::Gkr(ProductSumcheckError::Claim));
    }
    let reduction = prove_masked_shared_group_dag_layer_interactive(
        &layer,
        STATE_RELATION_GROUP_COUNT,
        source,
        source,
        core::slice::from_ref(&output_claim),
        &LibraPriorLayerCorrection::zero(),
        sumcheck_mask,
        layer_mask,
        sumcheck_rho,
        |kind, round, published| {
            let state_kind = match kind {
                crate::gkr_sumcheck::SharedGroupDagRoundKind::Group => {
                    StateRelationRoundKind::Group
                }
                crate::gkr_sumcheck::SharedGroupDagRoundKind::LeftWire
                | crate::gkr_sumcheck::SharedGroupDagRoundKind::RightWire => {
                    StateRelationRoundKind::Wire
                }
            };
            challenge(state_kind, round, published).map_err(|_| GkrZkMaskError::Sequence)
        },
        |published, left, right| {
            terminal_challenge(published, left, right).map_err(|_| GkrZkMaskError::Sequence)
        },
    )?;
    Ok(MaskedStateRelationGkrProof {
        output_claim,
        sumcheck_rho,
        layer: reduction,
    })
}

/// Verify the public masked recurrence and terminal gate without reading the
/// witness or mask coefficients. The caller must additionally verify the
/// aggregate committed-mask functional and the raw PCS input claims.
pub fn verify_masked_state_relation_gkr(
    proof: &MaskedStateRelationGkrProof,
) -> Result<(), StateRelationGkrError> {
    let reduction = &proof.layer;
    let ordinary_rounds = STATE_RELATION_GROUP_VARIABLES + 2 * STATE_RELATION_WIRE_VARIABLES;
    if proof.output_claim.value != Fp16::ZERO
        || proof.output_claim.coefficient != Fp16::ONE
        || proof.output_claim.point.len()
            != STATE_RELATION_OUTPUT_VARIABLES + STATE_RELATION_GROUP_VARIABLES
        || proof.sumcheck_rho.is_zero()
        || reduction.group_challenges.len() != STATE_RELATION_GROUP_VARIABLES
        || reduction.wire_challenges.len() != 2 * STATE_RELATION_WIRE_VARIABLES
        || reduction.published_rounds.len() != ordinary_rounds + 1
        || reduction.w_published != reduction.published_rounds[ordinary_rounds]
    {
        return Err(StateRelationGkrError::Shape);
    }
    for round in 1..reduction.published_rounds.len() {
        let previous_challenge = if round <= STATE_RELATION_GROUP_VARIABLES {
            reduction.group_challenges[round - 1]
        } else {
            reduction.wire_challenges[round - 1 - STATE_RELATION_GROUP_VARIABLES]
        };
        let previous = &reduction.published_rounds[round - 1];
        let current = &reduction.published_rounds[round];
        if polynomial_evaluation(current, Fp16::ZERO) + polynomial_evaluation(current, Fp16::ONE)
            != polynomial_evaluation(previous, previous_challenge)
        {
            return Err(StateRelationGkrError::Gkr(ProductSumcheckError::Claim));
        }
    }
    let _terminal_gate = shared_group_terminal_gate_claim(
        &relation_layer(),
        STATE_RELATION_GROUP_COUNT,
        core::slice::from_ref(&proof.output_claim),
        &reduction.group_challenges,
        &reduction.wire_challenges,
        reduction.masked_terminal_left,
        reduction.masked_terminal_right,
    )?;
    Ok(())
}

/// Verify the raw-free state-relation public recurrence.
pub fn verify_public_masked_state_relation_gkr(
    proof: &PublicMaskedStateRelationGkrProof,
) -> Result<(), StateRelationGkrError> {
    let ordinary_rounds = STATE_RELATION_GROUP_VARIABLES + 2 * STATE_RELATION_WIRE_VARIABLES;
    if proof.output_claim.value != Fp16::ZERO
        || proof.output_claim.coefficient != Fp16::ONE
        || proof.output_claim.point.len()
            != STATE_RELATION_OUTPUT_VARIABLES + STATE_RELATION_GROUP_VARIABLES
        || proof.sumcheck_rho.is_zero()
        || proof.group_challenges.len() != STATE_RELATION_GROUP_VARIABLES
        || proof.wire_challenges.len() != 2 * STATE_RELATION_WIRE_VARIABLES
        || proof.published_rounds.len() != ordinary_rounds + 1
    {
        return Err(StateRelationGkrError::Shape);
    }
    for (round, published) in proof.published_rounds.iter().enumerate() {
        let degree = if round < STATE_RELATION_GROUP_VARIABLES
            || round == STATE_RELATION_GROUP_VARIABLES + STATE_RELATION_WIRE_VARIABLES - 1
            || round == ordinary_rounds - 1
        {
            3
        } else {
            2
        };
        if published.len() != degree + 1 {
            return Err(StateRelationGkrError::Shape);
        }
    }
    for round in 1..proof.published_rounds.len() {
        let previous_challenge = if round <= STATE_RELATION_GROUP_VARIABLES {
            proof.group_challenges[round - 1]
        } else {
            proof.wire_challenges[round - 1 - STATE_RELATION_GROUP_VARIABLES]
        };
        let previous = &proof.published_rounds[round - 1];
        let current = &proof.published_rounds[round];
        if polynomial_evaluation(current, Fp16::ZERO) + polynomial_evaluation(current, Fp16::ONE)
            != polynomial_evaluation(previous, previous_challenge)
        {
            return Err(StateRelationGkrError::Gkr(ProductSumcheckError::Claim));
        }
    }
    shared_group_terminal_gate_claim(
        &relation_layer(),
        STATE_RELATION_GROUP_COUNT,
        core::slice::from_ref(&proof.output_claim),
        &proof.group_challenges,
        &proof.wire_challenges,
        proof.masked_terminal_left,
        proof.masked_terminal_right,
    )?;
    Ok(())
}

/// Construct the two verifier-safe H4 PCS claims after their raw values have
/// been authenticated by the package's fixed nineteen-claim boundary.
pub fn public_masked_state_relation_h4_input_claims(
    proof: &PublicMaskedStateRelationGkrProof,
    shard_query: Fp16,
    raw_values: [Fp16; 2],
) -> Result<[StateRelationH4InputClaim; 2], StateRelationGkrError> {
    verify_public_masked_state_relation_gkr(proof)?;
    let mut left_point =
        Vec::with_capacity(STATE_RELATION_WIRE_VARIABLES + STATE_RELATION_GROUP_VARIABLES);
    left_point.extend_from_slice(&proof.wire_challenges[..STATE_RELATION_WIRE_VARIABLES]);
    left_point.extend_from_slice(&proof.group_challenges);
    let mut right_point = Vec::with_capacity(left_point.len());
    right_point.extend_from_slice(&proof.wire_challenges[STATE_RELATION_WIRE_VARIABLES..]);
    right_point.extend_from_slice(&proof.group_challenges);
    let points = [left_point, right_point];
    Ok(core::array::from_fn(|index| StateRelationH4InputClaim {
        boundary: 1,
        point: h4_state_point(&points[index]).expect("validated state point"),
        value: raw_values[index],
        shard_query,
    }))
}

/// Reconstruct the state-relation portion of the complete committed-mask
/// functional without a source row, raw terminal, or mask coefficient.
pub fn public_masked_state_relation_constraints(
    proof: &PublicMaskedStateRelationGkrProof,
    mask_layer: usize,
    raw_values: [Fp16; 2],
) -> Result<Vec<UniformGkrMaskConstraint>, StateRelationGkrError> {
    verify_public_masked_state_relation_gkr(proof)?;
    let first = proof
        .published_rounds
        .first()
        .ok_or(StateRelationGkrError::Shape)?;
    let first_sum =
        polynomial_evaluation(first, Fp16::ZERO) + polynomial_evaluation(first, Fp16::ONE);
    let mut xy_point = proof.group_challenges.clone();
    xy_point.extend_from_slice(&proof.wire_challenges);
    let mut full_point = xy_point;
    full_point.push(proof.w_challenge);
    let terminal_gate = shared_group_terminal_gate_claim(
        &relation_layer(),
        STATE_RELATION_GROUP_COUNT,
        core::slice::from_ref(&proof.output_claim),
        &proof.group_challenges,
        &proof.wire_challenges,
        proof.masked_terminal_left,
        proof.masked_terminal_right,
    )?;
    let mut constraints = vec![
        UniformGkrMaskConstraint {
            functionals: vec![UniformGkrMaskFunctional::SumcheckBooleanSum {
                layer: mask_layer,
                scale: proof.sumcheck_rho,
            }],
            residual: first_sum,
        },
        UniformGkrMaskConstraint {
            functionals: vec![UniformGkrMaskFunctional::SumcheckEvaluation {
                layer: mask_layer,
                point: full_point,
                scale: proof.sumcheck_rho,
            }],
            residual: polynomial_evaluation(
                proof
                    .published_rounds
                    .last()
                    .ok_or(StateRelationGkrError::Shape)?,
                proof.w_challenge,
            ) - (Fp16::ONE - proof.w_challenge) * terminal_gate,
        },
    ];
    for (point, raw, masked) in [
        (
            proof.wire_challenges[..STATE_RELATION_WIRE_VARIABLES]
                .iter()
                .chain(&proof.group_challenges)
                .copied()
                .collect::<Vec<_>>(),
            raw_values[0],
            proof.masked_terminal_left,
        ),
        (
            proof.wire_challenges[STATE_RELATION_WIRE_VARIABLES..]
                .iter()
                .chain(&proof.group_challenges)
                .copied()
                .collect::<Vec<_>>(),
            raw_values[1],
            proof.masked_terminal_right,
        ),
    ] {
        constraints.push(UniformGkrMaskConstraint {
            functionals: vec![UniformGkrMaskFunctional::LayerBooleanSum {
                layer: mask_layer,
                z_first: point[0],
                scale: boolean_vanishing(&point),
            }],
            residual: masked - raw,
        });
    }
    Ok(constraints)
}

pub fn masked_state_relation_input_claims(
    proof: &MaskedStateRelationGkrProof,
    shard_query: Fp16,
) -> Result<PackedGkrInputClaims, StateRelationGkrError> {
    verify_masked_state_relation_gkr(proof)?;
    masked_state_relation_input_claims_unchecked(proof, shard_query)
}

pub fn masked_state_relation_input_claims_unchecked(
    proof: &MaskedStateRelationGkrProof,
    shard_query: Fp16,
) -> Result<PackedGkrInputClaims, StateRelationGkrError> {
    let mut left_point =
        Vec::with_capacity(STATE_RELATION_WIRE_VARIABLES + STATE_RELATION_GROUP_VARIABLES);
    left_point.extend_from_slice(&proof.layer.wire_challenges[..STATE_RELATION_WIRE_VARIABLES]);
    left_point.extend_from_slice(&proof.layer.group_challenges);
    let mut right_point = Vec::with_capacity(left_point.len());
    right_point.extend_from_slice(&proof.layer.wire_challenges[STATE_RELATION_WIRE_VARIABLES..]);
    right_point.extend_from_slice(&proof.layer.group_challenges);
    Ok(PackedGkrInputClaims {
        claims: [
            MultilinearOpeningClaim {
                point: left_point,
                value: proof.layer.raw_terminal_left,
            },
            MultilinearOpeningClaim {
                point: right_point,
                value: proof.layer.raw_terminal_right,
            },
        ],
        shard_query,
        wire_variables: STATE_RELATION_WIRE_VARIABLES as u8,
    })
}

pub fn masked_state_relation_h4_input_claims(
    proof: &MaskedStateRelationGkrProof,
    shard_query: Fp16,
) -> Result<[StateRelationH4InputClaim; 2], StateRelationGkrError> {
    let claims = masked_state_relation_input_claims(proof, shard_query)?;
    Ok(core::array::from_fn(|index| StateRelationH4InputClaim {
        boundary: 1,
        point: h4_state_point(&claims.claims[index].point).expect("validated state point"),
        value: claims.claims[index].value,
        shard_query,
    }))
}

pub fn masked_state_relation_h4_input_claims_unchecked(
    proof: &MaskedStateRelationGkrProof,
    shard_query: Fp16,
) -> Result<[StateRelationH4InputClaim; 2], StateRelationGkrError> {
    let claims = masked_state_relation_input_claims_unchecked(proof, shard_query)?;
    Ok(core::array::from_fn(|index| StateRelationH4InputClaim {
        boundary: 1,
        point: h4_state_point(&claims.claims[index].point).expect("validated state point"),
        value: claims.claims[index].value,
        shard_query,
    }))
}

pub fn masked_state_relation_constraints(
    proof: &MaskedStateRelationGkrProof,
    mask_layer: usize,
) -> Result<Vec<UniformGkrMaskConstraint>, StateRelationGkrError> {
    verify_masked_state_relation_gkr(proof)?;
    masked_state_relation_constraints_unchecked(proof, mask_layer)
}

pub fn masked_state_relation_constraints_unchecked(
    proof: &MaskedStateRelationGkrProof,
    mask_layer: usize,
) -> Result<Vec<UniformGkrMaskConstraint>, StateRelationGkrError> {
    let first = proof
        .layer
        .published_rounds
        .first()
        .ok_or(StateRelationGkrError::Shape)?;
    let first_sum =
        polynomial_evaluation(first, Fp16::ZERO) + polynomial_evaluation(first, Fp16::ONE);
    let mut xy_point = proof.layer.group_challenges.clone();
    xy_point.extend_from_slice(&proof.layer.wire_challenges);
    let mut full_point = xy_point;
    full_point.push(proof.layer.w_challenge);
    let terminal_gate = shared_group_terminal_gate_claim(
        &relation_layer(),
        STATE_RELATION_GROUP_COUNT,
        core::slice::from_ref(&proof.output_claim),
        &proof.layer.group_challenges,
        &proof.layer.wire_challenges,
        proof.layer.masked_terminal_left,
        proof.layer.masked_terminal_right,
    )?;
    let mut constraints = vec![
        UniformGkrMaskConstraint {
            functionals: vec![UniformGkrMaskFunctional::SumcheckBooleanSum {
                layer: mask_layer,
                scale: proof.sumcheck_rho,
            }],
            residual: first_sum,
        },
        UniformGkrMaskConstraint {
            functionals: vec![UniformGkrMaskFunctional::SumcheckEvaluation {
                layer: mask_layer,
                point: full_point,
                scale: proof.sumcheck_rho,
            }],
            residual: polynomial_evaluation(&proof.layer.w_published, proof.layer.w_challenge)
                - (Fp16::ONE - proof.layer.w_challenge) * terminal_gate,
        },
    ];
    for (point, raw, masked) in [
        (
            proof.layer.wire_challenges[..STATE_RELATION_WIRE_VARIABLES]
                .iter()
                .chain(&proof.layer.group_challenges)
                .copied()
                .collect::<Vec<_>>(),
            proof.layer.raw_terminal_left,
            proof.layer.masked_terminal_left,
        ),
        (
            proof.layer.wire_challenges[STATE_RELATION_WIRE_VARIABLES..]
                .iter()
                .chain(&proof.layer.group_challenges)
                .copied()
                .collect::<Vec<_>>(),
            proof.layer.raw_terminal_right,
            proof.layer.masked_terminal_right,
        ),
    ] {
        constraints.push(UniformGkrMaskConstraint {
            functionals: vec![UniformGkrMaskFunctional::LayerBooleanSum {
                layer: mask_layer,
                z_first: point[0],
                scale: boolean_vanishing(&point),
            }],
            residual: masked - raw,
        });
    }
    Ok(constraints)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateRelationRoundKind {
    Group,
    Wire,
}

pub fn relation_layer_for_tests() -> KeccakDagLayer {
    relation_layer()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(value: u32) -> Fp16 {
        Fp16::from_m31(M31::from_canonical(value).unwrap())
    }

    fn entry(seed: u8, present: bool) -> StateRelationEntry {
        let mut key = [0_u8; ENTRY_BYTES];
        let mut value = [0_u8; ENTRY_BYTES];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = seed.wrapping_add(index as u8);
        }
        for (index, byte) in value.iter_mut().enumerate() {
            *byte = seed.wrapping_mul(3).wrapping_add(index as u8);
        }
        StateRelationEntry {
            index: 0,
            present,
            key,
            value,
        }
    }

    fn row() -> StateRelationRow {
        let before = entry(7, true);
        let after = entry(19, true);
        StateRelationRow {
            operation_before: before,
            operation_after: after,
            snapshot_before: before,
            snapshot_after: after,
        }
    }

    fn challenges() -> (LayerOutputClaim, Vec<Fp16>, Vec<Fp16>) {
        let output_point = (0..STATE_RELATION_OUTPUT_VARIABLES + STATE_RELATION_GROUP_VARIABLES)
            .map(|index| scalar((index + 2) as u32))
            .collect();
        let output_claim = LayerOutputClaim {
            point: output_point,
            value: Fp16::ZERO,
            coefficient: Fp16::ONE,
        };
        let groups = (0..STATE_RELATION_GROUP_VARIABLES)
            .map(|index| scalar((index + 41) as u32))
            .collect();
        let wires = (0..2 * STATE_RELATION_WIRE_VARIABLES)
            .map(|index| scalar((index + 71) as u32))
            .collect();
        (output_claim, groups, wires)
    }

    #[test]
    fn packed_state_relation_has_fixed_source_and_output_geometry() {
        let source = build_state_relation_source(&[row()]).unwrap();
        assert_eq!(
            source.len(),
            STATE_RELATION_GROUP_COUNT * STATE_RELATION_SOURCE_WIDTH
        );
        assert_eq!(relation_layer().gates.len(), STATE_RELATION_OUTPUT_WIDTH);
        assert_eq!(STATE_RELATION_OUTPUT_RAW_WIDTH, 26);
    }

    #[test]
    fn valid_state_relation_proves_verifies_and_exposes_pcs_claims() {
        let source = build_state_relation_source(&[row()]).unwrap();
        let (claim, groups, wires) = challenges();
        let proof = prove_state_relation_gkr(&source, claim, groups, wires).unwrap();
        verify_state_relation_gkr(&proof).unwrap();
        let claims = state_relation_input_claims(&proof, scalar(13)).unwrap();
        let bridged =
            crate::gkr_pcs_bridge::bind_state_relation_gkr_terminals(&proof, scalar(13)).unwrap();
        assert_eq!(claims.wire_variables, STATE_RELATION_WIRE_VARIABLES as u8);
        assert_eq!(claims.claims[0].point.len(), 18);
        assert_eq!(claims.claims[1].point.len(), 18);
        assert_eq!(claims, bridged);
    }

    #[test]
    fn committed_source_recovers_the_exact_profile_rows() {
        let first = row();
        let mut second = StateRelationRow {
            operation_before: entry(31, true),
            operation_after: entry(43, true),
            snapshot_before: entry(31, true),
            snapshot_after: entry(43, true),
        };
        for entry in [
            &mut second.operation_before,
            &mut second.operation_after,
            &mut second.snapshot_before,
            &mut second.snapshot_after,
        ] {
            entry.index = 1;
        }
        let expected = vec![first, second];
        let source = build_state_relation_source(&expected).unwrap();
        assert_eq!(
            state_relation_rows_from_source(&source, expected.len()).unwrap(),
            expected
        );

        let mut malformed = source.clone();
        let mut coefficients = [0_u32; FP16_COEFFICIENTS];
        coefficients[0] = 1 << 24;
        malformed[2] = Fp16::from_coefficients(coefficients).unwrap();
        assert_eq!(
            state_relation_rows_from_source(&malformed, 2),
            Err(StateRelationGkrError::Encoding)
        );

        let mut nonzero_tail = source;
        nonzero_tail[2 * STATE_RELATION_SOURCE_WIDTH] = Fp16::ONE;
        assert_eq!(
            state_relation_rows_from_source(&nonzero_tail, 2),
            Err(StateRelationGkrError::Shape)
        );
    }

    #[test]
    fn interactive_state_relation_releases_every_public_coin_after_a_message() {
        let source = build_state_relation_source(&[row()]).unwrap();
        let (claim, _, _) = challenges();
        let mut messages = Vec::new();
        let proof =
            prove_state_relation_gkr_interactive(&source, claim.point, |kind, round, published| {
                messages.push((kind, round, published.to_vec()));
                Ok(scalar((messages.len() + 97) as u32))
            })
            .unwrap();
        verify_state_relation_gkr(&proof).unwrap();
        assert_eq!(
            messages.len(),
            STATE_RELATION_GROUP_VARIABLES + 2 * STATE_RELATION_WIRE_VARIABLES
        );
        assert!(
            messages
                .iter()
                .all(|(_, _, published)| !published.is_empty())
        );
    }

    #[test]
    fn masked_state_relation_hides_terminals_and_rejects_recurrence_mutation() {
        let source = build_state_relation_source(&[row()]).unwrap();
        let (claim, _, _) = challenges();
        let degrees =
            crate::fp16_relay_free_gkr_schedule::selected_state_composed_mask_variable_degrees(128)
                .unwrap()
                .remove(crate::fp16_relay_free_gkr_schedule::GKR_LAYERS as usize);
        let sumcheck_mask = LibraVariableDegreeSumcheckMask::new(
            scalar(1_001),
            degrees
                .iter()
                .enumerate()
                .map(|(variable, degree)| {
                    (0..*degree)
                        .map(|coefficient| scalar(1_101 + 7 * variable as u32 + coefficient as u32))
                        .collect()
                })
                .collect(),
        )
        .unwrap();
        let layer_mask = LibraLayerMask {
            coefficients: core::array::from_fn(|index| scalar(2_001 + index as u32)),
        };
        let round_count = core::cell::Cell::new(0_u32);
        let proof = prove_masked_state_relation_gkr_interactive(
            &source,
            claim.point,
            &sumcheck_mask,
            &layer_mask,
            scalar(3_001),
            |_, _, published| {
                assert!(!published.is_empty());
                round_count.set(round_count.get() + 1);
                Ok(scalar(3_101 + round_count.get()))
            },
            |published, left, right| {
                assert!(!published.is_empty());
                assert_ne!(left, Fp16::ZERO);
                assert_ne!(right, Fp16::ZERO);
                round_count.set(round_count.get() + 1);
                Ok(scalar(3_101 + round_count.get()))
            },
        )
        .unwrap();
        assert_eq!(round_count.get() as usize, degrees.len());
        assert_ne!(
            proof.layer.raw_terminal_left,
            proof.layer.masked_terminal_left
        );
        assert_ne!(
            proof.layer.raw_terminal_right,
            proof.layer.masked_terminal_right
        );
        verify_masked_state_relation_gkr(&proof).unwrap();
        let all_degrees =
            crate::fp16_relay_free_gkr_schedule::selected_state_composed_mask_variable_degrees(128)
                .unwrap();
        let relation_mask = crate::fp16_relay_free_gkr_schedule::GKR_LAYERS as usize;
        let all_sumcheck = all_degrees
            .iter()
            .enumerate()
            .map(|(layer, degrees)| {
                if layer == relation_mask {
                    return sumcheck_mask.clone();
                }
                LibraVariableDegreeSumcheckMask::new(
                    scalar(4_001 + layer as u32),
                    degrees
                        .iter()
                        .enumerate()
                        .map(|(variable, degree)| {
                            (0..*degree)
                                .map(|coefficient| {
                                    scalar(
                                        5_001
                                            + 101 * layer as u32
                                            + 5 * variable as u32
                                            + coefficient as u32,
                                    )
                                })
                                .collect()
                        })
                        .collect(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let all_layers = all_degrees
            .iter()
            .enumerate()
            .map(|(layer, _)| {
                if layer == relation_mask {
                    return layer_mask.clone();
                }
                LibraLayerMask {
                    coefficients: core::array::from_fn(|coefficient| {
                        scalar(6_001 + 11 * layer as u32 + coefficient as u32)
                    }),
                }
            })
            .collect::<Vec<_>>();
        let bridges = all_degrees
            .iter()
            .enumerate()
            .map(|(layer, _)| {
                (0..crate::gkr_packed_binary_bridge_fp16::PACKED_BINARY_MESSAGE_COEFFICIENTS)
                    .map(|coefficient| scalar(7_001 + 47 * layer as u32 + coefficient as u32))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let layout =
            crate::fp16_relay_free_gkr_schedule::selected_state_composed_mask_layout(128).unwrap();
        let encoded = layout.encode(&bridges, &all_sumcheck, &all_layers).unwrap();
        let constraints = masked_state_relation_constraints(&proof, relation_mask).unwrap();
        assert_eq!(constraints.len(), 4);
        let (weights, opening) =
            crate::fp16_relay_free_gkr_uniform::aggregate_gkr_mask_constraints(
                &layout,
                &constraints,
                scalar(8_001),
            )
            .unwrap();
        assert_eq!(
            crate::gkr_zk_mask::inner_product(&encoded, &weights).unwrap(),
            opening
        );

        let public = PublicMaskedStateRelationGkrProof::from_private(&proof);
        verify_public_masked_state_relation_gkr(&public).unwrap();
        let raw_values = [
            proof.layer.raw_terminal_left,
            proof.layer.raw_terminal_right,
        ];
        assert_eq!(
            public_masked_state_relation_constraints(&public, relation_mask, raw_values).unwrap(),
            constraints
        );
        let shard_query = scalar(8_101);
        assert_eq!(
            public_masked_state_relation_h4_input_claims(&public, shard_query, raw_values).unwrap(),
            masked_state_relation_h4_input_claims(&proof, shard_query).unwrap()
        );
        let mut forged_public = public;
        forged_public.published_rounds[1][0] = forged_public.published_rounds[1][0] + Fp16::ONE;
        assert!(verify_public_masked_state_relation_gkr(&forged_public).is_err());

        let mut forged = proof;
        forged.layer.published_rounds[1][0] = forged.layer.published_rounds[1][0] + Fp16::ONE;
        assert!(verify_masked_state_relation_gkr(&forged).is_err());
    }

    #[test]
    fn changed_operation_presence_is_rejected_by_the_state_gkr_claim() {
        let mut changed = row();
        changed.operation_before.present = false;
        assert_eq!(
            build_state_relation_source(&[changed]),
            Err(StateRelationGkrError::Encoding)
        );
    }

    #[test]
    fn changed_snapshot_chunk_is_rejected_by_the_state_gkr_claim() {
        let mut changed = row();
        changed.snapshot_after.value[0] ^= 1;
        let source = build_state_relation_source(&[changed]).unwrap();
        let (claim, groups, wires) = challenges();
        assert_eq!(
            prove_state_relation_gkr(&source, claim, groups, wires),
            Err(StateRelationGkrError::Gkr(ProductSumcheckError::Claim))
        );
    }

    #[test]
    fn changed_authenticated_index_is_rejected_by_the_state_gkr_claim() {
        let mut changed = row();
        changed.operation_before.index = 1;
        assert_eq!(
            build_state_relation_source(&[changed]),
            Err(StateRelationGkrError::Shape)
        );
    }

    #[test]
    fn row_permutation_is_rejected_by_the_canonical_index_wire() {
        let mut first = row();
        let mut second = row();
        for entry in [
            &mut second.operation_before,
            &mut second.operation_after,
            &mut second.snapshot_before,
            &mut second.snapshot_after,
        ] {
            entry.index = 1;
        }
        for entry in [
            &mut first.operation_before,
            &mut first.operation_after,
            &mut first.snapshot_before,
            &mut first.snapshot_after,
        ] {
            entry.index = 0;
        }
        assert_eq!(
            build_state_relation_source(&[second, first]),
            Err(StateRelationGkrError::Shape)
        );
    }

    #[test]
    fn duplicate_present_keys_are_rejected_before_source_commitment() {
        let mut first = row();
        let mut second = row();
        for entry in [
            &mut first.operation_before,
            &mut first.operation_after,
            &mut first.snapshot_before,
            &mut first.snapshot_after,
        ] {
            entry.index = 0;
        }
        for entry in [
            &mut second.operation_before,
            &mut second.operation_after,
            &mut second.snapshot_before,
            &mut second.snapshot_after,
        ] {
            entry.index = 1;
        }
        assert_eq!(
            build_state_relation_source(&[first, second]),
            Err(StateRelationGkrError::DuplicateKey)
        );
    }

    #[test]
    fn nonzero_empty_private_bytes_are_rejected_before_source_commitment() {
        let mut changed = row();
        changed.operation_before.present = false;
        changed.operation_before.key[0] = 1;
        assert_eq!(
            build_state_relation_source(&[changed]),
            Err(StateRelationGkrError::Encoding)
        );
    }

    #[test]
    fn verifier_rejects_nonzero_terminal_relation_claim() {
        let source = build_state_relation_source(&[row()]).unwrap();
        let (mut claim, groups, wires) = challenges();
        claim.value = scalar(1);
        assert_eq!(
            prove_state_relation_gkr(&source, claim, groups, wires),
            Err(StateRelationGkrError::Gkr(ProductSumcheckError::Claim))
        );
    }
}
