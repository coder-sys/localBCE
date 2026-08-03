//! Fail-closed binary client for the untrusted nonuniform B16 CUDA worker.

use alloc::{string::ToString, vec, vec::Vec};
use std::{
    collections::VecDeque,
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

use crate::{
    field::Fp16,
    fp16_relay_free_gkr_uniform::{
        NonuniformRelayFreeGkrOracle, UniformRelayFreeClaim, UniformRelayFreeGkrError,
    },
    gkr_packed_binary_bridge_fp16::{
        PACKED_BINARY_MESSAGE_COEFFICIENTS, packed_selector_polynomial,
    },
    gkr_packed_bridge_fp16::{evaluate, lagrange_basis, lagrange_evaluations},
    gkr_sumcheck::{MaskedSharedGroupOracle, SharedGroupDagRoundKind},
    gkr_zk_mask::GkrZkMaskError,
    keccak_gkr_dag::{
        KeccakDagGateKind, KeccakDagLayer, KeccakDagSource, build_keccak_gkr_dag_round,
    },
};

const READY: &[u8; 8] = b"BLGKRW05";
const PLAN: &[u8; 8] = b"BLGKRPL5";
const PLAN_ACCEPTED: &[u8; 8] = b"BLGKRPK5";
const OUTPUT_REQUEST: &[u8; 8] = b"BLGKRO05";
const OUTPUT_RESPONSE: &[u8; 8] = b"BLGKROK5";
const LAYER_REQUEST: &[u8; 8] = b"BLGKRL05";
const LAYER_RESPONSE: &[u8; 8] = b"BLGKRLK5";
const BRIDGE_CHALLENGE: &[u8; 8] = b"BLGKRB05";
const BRIDGE_ACCEPTED: &[u8; 8] = b"BLGKRBK5";
const GROUP_CHALLENGE: &[u8; 8] = b"BLGKRC05";
const GROUP_ACCEPTED: &[u8; 8] = b"BLGKRCK5";
const FOLDED_REQUEST: &[u8; 8] = b"BLGKRF05";
const FOLDED_RESPONSE: &[u8; 8] = b"BLGKRFK5";
const WIRE_REQUEST: &[u8; 8] = b"BLGKRWQ5";
const WIRE_RESPONSE: &[u8; 8] = b"BLGKRWR5";
const WIRE_CHALLENGE: &[u8; 8] = b"BLGKRWC5";
const WIRE_ACCEPTED: &[u8; 8] = b"BLGKRWA5";
const FINISH: &[u8; 8] = b"BLGKRFI5";
const FINISHED: &[u8; 8] = b"BLGKRDN5";
// A fresh process stays below the observed 54--57-layer Windows driver
// failure range while avoiding redundant CUDA/NVRTC reconstruction.
const LAYERS_PER_WORKER_PROCESS: usize = 48;
const TOTAL_GKR_LAYERS: usize = 24 * 7;

fn read_fields(
    reader: &mut impl Read,
    count: usize,
) -> Result<Vec<Fp16>, UniformRelayFreeGkrError> {
    let byte_count = count
        .checked_mul(64)
        .ok_or(UniformRelayFreeGkrError::Shape)?;
    let mut encoded = vec![0_u8; byte_count];
    reader
        .read_exact(&mut encoded)
        .map_err(|_| UniformRelayFreeGkrError::Trace)?;
    encoded
        .chunks_exact(64)
        .map(|field| Fp16::decode(field).map_err(|_| UniformRelayFreeGkrError::Trace))
        .collect()
}

fn encode_layer_plan(layer: &KeccakDagLayer) -> Result<Vec<u8>, UniformRelayFreeGkrError> {
    let source_tag = |source| match source {
        KeccakDagSource::RoundInput => Ok(0_u8),
        KeccakDagSource::Layer(index) => {
            u8::try_from(index + 1).map_err(|_| UniformRelayFreeGkrError::Shape)
        }
    };
    let left_width =
        u16::try_from(layer.left_width).map_err(|_| UniformRelayFreeGkrError::Shape)?;
    let right_width =
        u16::try_from(layer.right_width).map_err(|_| UniformRelayFreeGkrError::Shape)?;
    let raw_width = u16::try_from(layer.raw_width).map_err(|_| UniformRelayFreeGkrError::Shape)?;
    if layer.gates.len() < layer.raw_width {
        return Err(UniformRelayFreeGkrError::Shape);
    }
    let payload_bytes = layer
        .raw_width
        .checked_mul(5)
        .and_then(|bytes| bytes.checked_add(8))
        .ok_or(UniformRelayFreeGkrError::Shape)?;
    let mut encoded = Vec::with_capacity(payload_bytes);
    encoded.extend_from_slice(&[
        source_tag(layer.left_source)?,
        source_tag(layer.right_source)?,
    ]);
    encoded.extend_from_slice(&left_width.to_be_bytes());
    encoded.extend_from_slice(&right_width.to_be_bytes());
    encoded.extend_from_slice(&raw_width.to_be_bytes());
    for gate in &layer.gates[..layer.raw_width] {
        let kind = match gate.kind {
            KeccakDagGateKind::Xor => 0,
            KeccakDagGateKind::NotLeftAndRight => 1,
            KeccakDagGateKind::XorConstant(false) => 2,
            KeccakDagGateKind::XorConstant(true) => 3,
            KeccakDagGateKind::Zero => return Err(UniformRelayFreeGkrError::Shape),
            KeccakDagGateKind::Subtract
            | KeccakDagGateKind::Multiply
            | KeccakDagGateKind::RelayLeft => return Err(UniformRelayFreeGkrError::Shape),
        };
        encoded.extend_from_slice(
            &u16::try_from(gate.left)
                .map_err(|_| UniformRelayFreeGkrError::Shape)?
                .to_be_bytes(),
        );
        encoded.extend_from_slice(
            &u16::try_from(gate.right)
                .map_err(|_| UniformRelayFreeGkrError::Shape)?
                .to_be_bytes(),
        );
        encoded.push(kind);
    }
    if encoded.len() != payload_bytes {
        return Err(UniformRelayFreeGkrError::Shape);
    }
    Ok(encoded)
}

struct StandbyWorker {
    child: Child,
    writer: BufWriter<ChildStdin>,
    reader: BufReader<ChildStdout>,
}

pub struct HashBusB16GkrWorker {
    child: Child,
    writer: BufWriter<ChildStdin>,
    reader: BufReader<ChildStdout>,
    left_width: usize,
    right_width: usize,
    next_group_round: usize,
    next_left_wire_round: usize,
    next_right_wire_round: usize,
    wire_sources_ready: bool,
    pending_wire_round: Option<(SharedGroupDagRoundKind, usize)>,
    cached_group_message: Option<(usize, [Fp16; 4])>,
    cached_wire_message: Option<(SharedGroupDagRoundKind, usize, [Fp16; 3])>,
    group_requests: usize,
    current_layer: Option<(usize, usize)>,
    current_shard_queries: Vec<Fp16>,
    completed_layers: usize,
    same_sources: bool,
    standbys: VecDeque<StandbyWorker>,
    python: PathBuf,
    worker: PathBuf,
    boundary: PathBuf,
    shard: u16,
    remaining_standby_spawns: usize,
}

impl HashBusB16GkrWorker {
    fn spawn_standby(
        python: &Path,
        worker: &Path,
        boundary: &Path,
        shard: u16,
    ) -> Result<StandbyWorker, UniformRelayFreeGkrError> {
        let mut child = Command::new(python)
            .arg("-S")
            .arg(worker)
            .arg(boundary)
            .arg(shard.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|_| UniformRelayFreeGkrError::Trace)?;
        let stdin = child.stdin.take().ok_or(UniformRelayFreeGkrError::Trace)?;
        let stdout = child.stdout.take().ok_or(UniformRelayFreeGkrError::Trace)?;
        Ok(StandbyWorker {
            child,
            writer: BufWriter::with_capacity(1 << 20, stdin),
            reader: BufReader::with_capacity(1 << 20, stdout),
        })
    }

    pub fn spawn(
        python: &Path,
        worker: &Path,
        boundary: &Path,
        shard: u16,
    ) -> Result<Self, UniformRelayFreeGkrError> {
        if !python.is_file() || !worker.is_file() || !boundary.is_file() {
            return Err(UniformRelayFreeGkrError::Shape);
        }
        let mut child = Command::new(python)
            .arg("-S")
            .arg(worker)
            .arg(boundary)
            .arg(shard.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|_| UniformRelayFreeGkrError::Trace)?;
        let stdin = child.stdin.take().ok_or(UniformRelayFreeGkrError::Trace)?;
        let stdout = child.stdout.take().ok_or(UniformRelayFreeGkrError::Trace)?;
        let standby_count = TOTAL_GKR_LAYERS.div_ceil(LAYERS_PER_WORKER_PROCESS) - 1;
        let standbys = VecDeque::with_capacity(1);
        let mut result = Self {
            child,
            writer: BufWriter::with_capacity(1 << 20, stdin),
            reader: BufReader::with_capacity(1 << 20, stdout),
            left_width: 0,
            right_width: 0,
            next_group_round: 0,
            next_left_wire_round: 0,
            next_right_wire_round: 0,
            wire_sources_ready: false,
            pending_wire_round: None,
            cached_group_message: None,
            cached_wire_message: None,
            group_requests: 0,
            current_layer: None,
            current_shard_queries: Vec::new(),
            completed_layers: 0,
            same_sources: false,
            standbys,
            python: python.to_path_buf(),
            worker: worker.to_path_buf(),
            boundary: boundary.to_path_buf(),
            shard,
            remaining_standby_spawns: standby_count,
        };
        result.expect_magic(READY)?;
        result.write_magic(PLAN)?;
        for round in 0..24 {
            let layers =
                build_keccak_gkr_dag_round(round).map_err(|_| UniformRelayFreeGkrError::Trace)?;
            for layer in &layers {
                result.write_layer_plan(layer)?;
            }
        }
        result.flush()?;
        // Exactly one future context is useful. Starting all three future
        // workers at once only duplicates Python/CUDA residency and makes
        // their initialization contend with the active proof.
        result.expect_magic(PLAN_ACCEPTED)?;
        result.spawn_next_standby()?;
        Ok(result)
    }

    fn spawn_next_standby(&mut self) -> Result<(), UniformRelayFreeGkrError> {
        if self.remaining_standby_spawns == 0 {
            return Ok(());
        }
        if !self.standbys.is_empty() {
            return Err(UniformRelayFreeGkrError::Schedule);
        }
        self.standbys.push_back(Self::spawn_standby(
            &self.python,
            &self.worker,
            &self.boundary,
            self.shard,
        )?);
        self.remaining_standby_spawns -= 1;
        Ok(())
    }

    fn restart_child(&mut self) -> Result<(), UniformRelayFreeGkrError> {
        if self.left_width != 0
            || self.right_width != 0
            || self.wire_sources_ready
            || self.pending_wire_round.is_some()
            || self.cached_group_message.is_some()
            || self.cached_wire_message.is_some()
            || self.same_sources
        {
            return Err(UniformRelayFreeGkrError::Schedule);
        }
        self.write_magic(FINISH)?;
        self.flush()?;
        self.expect_magic(FINISHED)?;
        if !self
            .child
            .wait()
            .map_err(|_| UniformRelayFreeGkrError::Trace)?
            .success()
        {
            return Err(UniformRelayFreeGkrError::Trace);
        }

        let standby = self
            .standbys
            .pop_front()
            .ok_or(UniformRelayFreeGkrError::Schedule)?;
        self.child = standby.child;
        self.writer = standby.writer;
        self.reader = standby.reader;
        self.expect_magic(READY)?;
        self.write_magic(PLAN)?;
        for round in 0..24 {
            let layers =
                build_keccak_gkr_dag_round(round).map_err(|_| UniformRelayFreeGkrError::Trace)?;
            for layer in &layers {
                self.write_layer_plan(layer)?;
            }
        }
        self.flush()?;
        self.expect_magic(PLAN_ACCEPTED)?;
        self.spawn_next_standby()?;
        Ok(())
    }

    pub fn progress(&self) -> (Option<(usize, usize)>, usize, usize, usize) {
        (
            self.current_layer,
            self.completed_layers,
            self.group_requests,
            self.next_group_round,
        )
    }

    pub fn finish(mut self) -> Result<(), UniformRelayFreeGkrError> {
        if !self.standbys.is_empty() || self.remaining_standby_spawns != 0 {
            return Err(UniformRelayFreeGkrError::Schedule);
        }
        self.write_magic(FINISH)?;
        self.flush()?;
        self.expect_magic(FINISHED)?;
        if !self
            .child
            .wait()
            .map_err(|_| UniformRelayFreeGkrError::Trace)?
            .success()
        {
            return Err(UniformRelayFreeGkrError::Trace);
        }
        Ok(())
    }

    fn write_magic(&mut self, magic: &[u8; 8]) -> Result<(), UniformRelayFreeGkrError> {
        self.writer
            .write_all(magic)
            .map_err(|_| UniformRelayFreeGkrError::Trace)
    }

    fn expect_magic(&mut self, magic: &[u8; 8]) -> Result<(), UniformRelayFreeGkrError> {
        let mut actual = [0_u8; 8];
        self.reader
            .read_exact(&mut actual)
            .map_err(|_| UniformRelayFreeGkrError::Trace)?;
        if &actual != magic {
            return Err(UniformRelayFreeGkrError::Trace);
        }
        Ok(())
    }

    fn write_field(&mut self, value: Fp16) -> Result<(), UniformRelayFreeGkrError> {
        self.writer
            .write_all(&value.encode())
            .map_err(|_| UniformRelayFreeGkrError::Trace)
    }

    fn read_field(&mut self) -> Result<Fp16, UniformRelayFreeGkrError> {
        let mut encoded = [0_u8; 64];
        self.reader
            .read_exact(&mut encoded)
            .map_err(|_| UniformRelayFreeGkrError::Trace)?;
        Fp16::decode(&encoded).map_err(|_| UniformRelayFreeGkrError::Trace)
    }

    fn flush(&mut self) -> Result<(), UniformRelayFreeGkrError> {
        self.writer
            .flush()
            .map_err(|_| UniformRelayFreeGkrError::Trace)
    }

    fn write_claim(
        &mut self,
        claim: &UniformRelayFreeClaim,
    ) -> Result<(), UniformRelayFreeGkrError> {
        if claim.point.is_empty() || claim.point.len() > 24 {
            return Err(UniformRelayFreeGkrError::Shape);
        }
        self.write_field(claim.coefficient)?;
        self.write_field(claim.value)?;
        self.write_field(claim.shard_query)?;
        self.writer
            .write_all(&[
                u8::try_from(claim.point.len()).map_err(|_| UniformRelayFreeGkrError::Shape)?
            ])
            .map_err(|_| UniformRelayFreeGkrError::Trace)?;
        for coordinate in &claim.point {
            self.write_field(*coordinate)?;
        }
        for coefficient in packed_selector_polynomial(claim.shard_query) {
            self.write_field(coefficient)?;
        }
        Ok(())
    }

    fn write_layer_plan(&mut self, layer: &KeccakDagLayer) -> Result<(), UniformRelayFreeGkrError> {
        let encoded = encode_layer_plan(layer)?;
        self.writer
            .write_all(&encoded)
            .map_err(|_| UniformRelayFreeGkrError::Trace)
    }
}

impl NonuniformRelayFreeGkrOracle for HashBusB16GkrWorker {
    fn output_claim(
        &mut self,
        shard_query: Fp16,
        point: &[Fp16],
    ) -> Result<Fp16, UniformRelayFreeGkrError> {
        if point.len() != 24 {
            return Err(UniformRelayFreeGkrError::Shape);
        }
        self.write_magic(OUTPUT_REQUEST)?;
        self.write_field(shard_query)?;
        for coordinate in point {
            self.write_field(*coordinate)?;
        }
        for coefficient in packed_selector_polynomial(shard_query) {
            self.write_field(coefficient)?;
        }
        self.flush()?;
        self.expect_magic(OUTPUT_RESPONSE)?;
        self.read_field()
    }

    fn begin_layer(
        &mut self,
        keccak_round: usize,
        layer: usize,
        topology: &KeccakDagLayer,
        claims: &[UniformRelayFreeClaim],
    ) -> Result<[Fp16; PACKED_BINARY_MESSAGE_COEFFICIENTS], UniformRelayFreeGkrError> {
        if keccak_round >= 24
            || layer >= 7
            || claims.is_empty()
            || claims.len() > 4
            || self.left_width != 0
            || self.right_width != 0
            || self.wire_sources_ready
            || self.pending_wire_round.is_some()
            || self.cached_group_message.is_some()
            || self.cached_wire_message.is_some()
        {
            return Err(UniformRelayFreeGkrError::Shape);
        }
        if self.completed_layers != 0
            && self
                .completed_layers
                .is_multiple_of(LAYERS_PER_WORKER_PROCESS)
        {
            self.restart_child()?;
        }
        self.write_magic(LAYER_REQUEST)?;
        self.writer
            .write_all(&[
                u8::try_from(keccak_round).map_err(|_| UniformRelayFreeGkrError::Shape)?,
                u8::try_from(layer).map_err(|_| UniformRelayFreeGkrError::Shape)?,
                u8::try_from(claims.len()).map_err(|_| UniformRelayFreeGkrError::Shape)?,
            ])
            .map_err(|_| UniformRelayFreeGkrError::Trace)?;
        for claim in claims {
            self.write_claim(claim)?;
        }
        self.flush()?;
        self.expect_magic(LAYER_RESPONSE)?;
        let mut message = [Fp16::ZERO; PACKED_BINARY_MESSAGE_COEFFICIENTS];
        for coefficient in &mut message {
            *coefficient = self.read_field()?;
        }
        self.left_width = topology.left_width;
        self.right_width = topology.right_width;
        self.next_group_round = 0;
        self.next_left_wire_round = 0;
        self.next_right_wire_round = 0;
        self.wire_sources_ready = false;
        self.pending_wire_round = None;
        self.cached_group_message = None;
        self.cached_wire_message = None;
        self.group_requests = 0;
        self.current_layer = Some((keccak_round, layer));
        self.current_shard_queries = claims.iter().map(|claim| claim.shard_query).collect();
        self.same_sources = topology.left_source == topology.right_source;
        if self.same_sources && self.left_width != self.right_width {
            return Err(UniformRelayFreeGkrError::Shape);
        }
        Ok(message)
    }

    fn accept_bridge_challenge(&mut self, challenge: Fp16) -> Result<(), UniformRelayFreeGkrError> {
        if self.current_shard_queries.is_empty()
            || self.current_shard_queries.len() > 4
            || self.current_shard_queries.len() > usize::from(u8::MAX)
        {
            return Err(UniformRelayFreeGkrError::Shape);
        }
        let basis = lagrange_basis();
        let challenge_nodes = lagrange_evaluations(&basis, challenge);
        let selector_scales = self
            .current_shard_queries
            .iter()
            .map(|query| evaluate(&packed_selector_polynomial(*query), challenge))
            .collect::<Vec<_>>();
        self.write_magic(BRIDGE_CHALLENGE)?;
        self.write_field(challenge)?;
        self.writer
            .write_all(&[self.current_shard_queries.len() as u8])
            .map_err(|_| UniformRelayFreeGkrError::Trace)?;
        for scale in selector_scales {
            self.write_field(scale)?;
        }
        for value in challenge_nodes {
            self.write_field(value)?;
        }
        self.flush()?;
        self.expect_magic(BRIDGE_ACCEPTED)?;
        let mut message = [Fp16::ZERO; 4];
        for coefficient in &mut message {
            *coefficient = self.read_field()?;
        }
        self.cached_group_message = Some((0, message));
        Ok(())
    }
}

impl MaskedSharedGroupOracle for HashBusB16GkrWorker {
    fn raw_group_round(
        &mut self,
        round: usize,
        expected_claim: Fp16,
    ) -> Result<[Fp16; 4], GkrZkMaskError> {
        if round != self.next_group_round || round >= 13 {
            return Err(GkrZkMaskError::Sequence);
        }
        let (cached_round, result) = self
            .cached_group_message
            .take()
            .ok_or(GkrZkMaskError::Sequence)?;
        if cached_round != round {
            return Err(GkrZkMaskError::Sequence);
        }
        self.group_requests += 1;
        if result[0] + result[0] + result[1] + result[2] + result[3] != expected_claim {
            return Err(GkrZkMaskError::Claim);
        }
        Ok(result)
    }

    fn accept_group_challenge(
        &mut self,
        round: usize,
        challenge: Fp16,
    ) -> Result<(), GkrZkMaskError> {
        if round != self.next_group_round || round >= 13 || self.cached_group_message.is_some() {
            return Err(GkrZkMaskError::Sequence);
        }
        self.write_magic(GROUP_CHALLENGE)
            .map_err(|_| GkrZkMaskError::Sequence)?;
        self.writer
            .write_all(&[u8::try_from(round).map_err(|_| GkrZkMaskError::Shape)?])
            .map_err(|_| GkrZkMaskError::Sequence)?;
        self.write_field(challenge)
            .map_err(|_| GkrZkMaskError::Sequence)?;
        self.flush().map_err(|_| GkrZkMaskError::Sequence)?;
        self.expect_magic(GROUP_ACCEPTED)
            .map_err(|_| GkrZkMaskError::Sequence)?;
        self.next_group_round += 1;
        if self.next_group_round < 13 {
            let mut message = [Fp16::ZERO; 4];
            for coefficient in &mut message {
                *coefficient = self.read_field().map_err(|_| GkrZkMaskError::Sequence)?;
            }
            self.cached_group_message = Some((self.next_group_round, message));
        }
        Ok(())
    }

    fn folded_sources(&mut self) -> Result<(Vec<Fp16>, Vec<Fp16>), GkrZkMaskError> {
        if self.next_group_round != 13
            || self.left_width == 0
            || self.right_width == 0
            || self.wire_sources_ready
            || self.pending_wire_round.is_some()
            || self.cached_group_message.is_some()
            || self.cached_wire_message.is_some()
        {
            return Err(GkrZkMaskError::Sequence);
        }
        self.write_magic(FOLDED_REQUEST)
            .map_err(|_| GkrZkMaskError::Sequence)?;
        self.flush().map_err(|_| GkrZkMaskError::Sequence)?;
        self.expect_magic(FOLDED_RESPONSE)
            .map_err(|_| GkrZkMaskError::Sequence)?;
        let mut sources = read_fields(
            &mut self.reader,
            self.left_width
                .checked_add(if self.same_sources {
                    0
                } else {
                    self.right_width
                })
                .ok_or(GkrZkMaskError::Shape)?,
        )
        .map_err(|_| GkrZkMaskError::Sequence)?;
        let right = if self.same_sources {
            sources.clone()
        } else {
            sources.split_off(self.left_width)
        };
        let left = sources;
        let mut first_wire_message = [Fp16::ZERO; 3];
        for coefficient in &mut first_wire_message {
            *coefficient = self.read_field().map_err(|_| GkrZkMaskError::Sequence)?;
        }
        self.cached_wire_message = Some((SharedGroupDagRoundKind::LeftWire, 0, first_wire_message));
        self.wire_sources_ready = true;
        Ok((left, right))
    }

    fn accelerates_wire_rounds(&self) -> bool {
        true
    }

    fn raw_wire_round(
        &mut self,
        kind: SharedGroupDagRoundKind,
        round: usize,
        masked_terminal_left: Option<Fp16>,
    ) -> Result<[Fp16; 3], GkrZkMaskError> {
        if !self.wire_sources_ready || self.pending_wire_round.is_some() {
            return Err(GkrZkMaskError::Sequence);
        }
        let (side, expected_round, variable_count, terminal) = match kind {
            SharedGroupDagRoundKind::LeftWire => {
                if masked_terminal_left.is_some() || self.next_right_wire_round != 0 {
                    return Err(GkrZkMaskError::Sequence);
                }
                (
                    0_u8,
                    self.next_left_wire_round,
                    self.left_width.trailing_zeros() as usize,
                    Fp16::ZERO,
                )
            }
            SharedGroupDagRoundKind::RightWire => {
                if self.next_left_wire_round != self.left_width.trailing_zeros() as usize {
                    return Err(GkrZkMaskError::Sequence);
                }
                (
                    1_u8,
                    self.next_right_wire_round,
                    self.right_width.trailing_zeros() as usize,
                    masked_terminal_left.ok_or(GkrZkMaskError::Sequence)?,
                )
            }
            SharedGroupDagRoundKind::Group => return Err(GkrZkMaskError::Sequence),
        };
        if round != expected_round || round >= variable_count {
            return Err(GkrZkMaskError::Sequence);
        }
        if let Some((cached_kind, cached_round, result)) = self.cached_wire_message.take() {
            if cached_kind != kind || cached_round != round {
                return Err(GkrZkMaskError::Sequence);
            }
            self.pending_wire_round = Some((kind, round));
            return Ok(result);
        }
        self.write_magic(WIRE_REQUEST)
            .map_err(|_| GkrZkMaskError::Sequence)?;
        self.writer
            .write_all(&[
                side,
                u8::try_from(round).map_err(|_| GkrZkMaskError::Shape)?,
            ])
            .map_err(|_| GkrZkMaskError::Sequence)?;
        self.write_field(terminal)
            .map_err(|_| GkrZkMaskError::Sequence)?;
        self.flush().map_err(|_| GkrZkMaskError::Sequence)?;
        self.expect_magic(WIRE_RESPONSE)
            .map_err(|_| GkrZkMaskError::Sequence)?;
        let mut result = [Fp16::ZERO; 3];
        for coefficient in &mut result {
            *coefficient = self.read_field().map_err(|_| GkrZkMaskError::Sequence)?;
        }
        self.pending_wire_round = Some((kind, round));
        Ok(result)
    }

    fn accept_wire_challenge(
        &mut self,
        kind: SharedGroupDagRoundKind,
        round: usize,
        challenge: Fp16,
    ) -> Result<(), GkrZkMaskError> {
        if self.pending_wire_round != Some((kind, round)) || self.cached_wire_message.is_some() {
            return Err(GkrZkMaskError::Sequence);
        }
        let variable_count = match kind {
            SharedGroupDagRoundKind::LeftWire => self.left_width.trailing_zeros() as usize,
            SharedGroupDagRoundKind::RightWire => self.right_width.trailing_zeros() as usize,
            SharedGroupDagRoundKind::Group => return Err(GkrZkMaskError::Sequence),
        };
        let side = match kind {
            SharedGroupDagRoundKind::LeftWire => 0_u8,
            SharedGroupDagRoundKind::RightWire => 1_u8,
            SharedGroupDagRoundKind::Group => return Err(GkrZkMaskError::Sequence),
        };
        self.write_magic(WIRE_CHALLENGE)
            .map_err(|_| GkrZkMaskError::Sequence)?;
        self.writer
            .write_all(&[
                side,
                u8::try_from(round).map_err(|_| GkrZkMaskError::Shape)?,
            ])
            .map_err(|_| GkrZkMaskError::Sequence)?;
        self.write_field(challenge)
            .map_err(|_| GkrZkMaskError::Sequence)?;
        self.flush().map_err(|_| GkrZkMaskError::Sequence)?;
        self.expect_magic(WIRE_ACCEPTED)
            .map_err(|_| GkrZkMaskError::Sequence)?;
        self.pending_wire_round = None;
        match kind {
            SharedGroupDagRoundKind::LeftWire => self.next_left_wire_round += 1,
            SharedGroupDagRoundKind::RightWire => {
                self.next_right_wire_round += 1;
                if self.next_right_wire_round == self.right_width.trailing_zeros() as usize {
                    self.wire_sources_ready = false;
                    self.left_width = 0;
                    self.right_width = 0;
                    self.current_shard_queries.clear();
                    self.same_sources = false;
                    self.completed_layers += 1;
                }
            }
            SharedGroupDagRoundKind::Group => return Err(GkrZkMaskError::Sequence),
        }
        if round + 1 < variable_count {
            let mut message = [Fp16::ZERO; 3];
            for coefficient in &mut message {
                *coefficient = self.read_field().map_err(|_| GkrZkMaskError::Sequence)?;
            }
            self.cached_wire_message = Some((kind, round + 1, message));
        }
        Ok(())
    }
}

impl Drop for HashBusB16GkrWorker {
    fn drop(&mut self) {
        for mut standby in self.standbys.drain(..) {
            if standby.child.try_wait().ok().flatten().is_none() {
                let _ = standby.child.kill();
                let _ = standby.child.wait();
            }
        }
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn batch_field_reader_is_exact_and_fail_closed() {
        let fields = [Fp16::ZERO, Fp16::ONE];
        let encoded = fields
            .iter()
            .copied()
            .flat_map(Fp16::encode)
            .collect::<Vec<_>>();
        assert_eq!(
            read_fields(&mut Cursor::new(&encoded), fields.len()).unwrap(),
            fields
        );

        let mut noncanonical = vec![0_u8; 64];
        noncanonical[..4].copy_from_slice(&crate::field::M31_MODULUS.to_be_bytes());
        assert_eq!(
            read_fields(&mut Cursor::new(noncanonical), 1),
            Err(UniformRelayFreeGkrError::Trace)
        );
        assert_eq!(
            read_fields(
                &mut Cursor::new(&encoded[..encoded.len() - 1]),
                fields.len()
            ),
            Err(UniformRelayFreeGkrError::Trace)
        );
    }

    #[test]
    fn layer_plan_encoding_is_exact() {
        let layers = build_keccak_gkr_dag_round(0).unwrap();
        for (layer_index, layer) in layers.iter().enumerate() {
            let encoded = encode_layer_plan(layer).unwrap();
            assert_eq!(encoded.len(), 8 + 5 * layer.raw_width);
            let expected_source = |source| match source {
                KeccakDagSource::RoundInput => 0,
                KeccakDagSource::Layer(index) => index + 1,
            };
            assert_eq!(usize::from(encoded[0]), expected_source(layer.left_source));
            assert_eq!(usize::from(encoded[1]), expected_source(layer.right_source));
            assert_eq!(
                usize::from(u16::from_be_bytes(encoded[2..4].try_into().unwrap())),
                layer.left_width
            );
            assert_eq!(
                usize::from(u16::from_be_bytes(encoded[4..6].try_into().unwrap())),
                layer.right_width
            );
            assert_eq!(
                usize::from(u16::from_be_bytes(encoded[6..8].try_into().unwrap())),
                layer.raw_width
            );
            for (gate_index, gate) in layer.gates[..layer.raw_width].iter().enumerate() {
                let offset = 8 + 5 * gate_index;
                assert_eq!(
                    usize::from(u16::from_be_bytes(
                        encoded[offset..offset + 2].try_into().unwrap()
                    )),
                    gate.left,
                    "layer {layer_index} gate {gate_index} left"
                );
                assert_eq!(
                    usize::from(u16::from_be_bytes(
                        encoded[offset + 2..offset + 4].try_into().unwrap()
                    )),
                    gate.right,
                    "layer {layer_index} gate {gate_index} right"
                );
                let expected_kind = match gate.kind {
                    KeccakDagGateKind::Xor => 0,
                    KeccakDagGateKind::NotLeftAndRight => 1,
                    KeccakDagGateKind::XorConstant(false) => 2,
                    KeccakDagGateKind::XorConstant(true) => 3,
                    KeccakDagGateKind::Zero => panic!("selected plan contains a zero gate"),
                    KeccakDagGateKind::Subtract
                    | KeccakDagGateKind::Multiply
                    | KeccakDagGateKind::RelayLeft => {
                        panic!("selected plan contains a state-only field gate")
                    }
                };
                assert_eq!(
                    encoded[offset + 4],
                    expected_kind,
                    "layer {layer_index} gate {gate_index} kind"
                );
            }
        }
    }
}
