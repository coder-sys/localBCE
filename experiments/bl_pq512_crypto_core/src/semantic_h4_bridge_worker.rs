//! Fail-closed process boundary for the varying semantic/H4 accelerator.
//!
//! The child is an untrusted algebra engine. It receives authenticated source
//! paths and verifier-derived claims, but never chooses transcript challenges.
//! Rust checks every sumcheck recurrence and computes the wire tail natively.

use alloc::{string::ToString, vec, vec::Vec};
use std::{
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

use crate::{
    field::Fp16,
    gkr_sumcheck::{LayerOutputClaim, MaskedSharedGroupOracle, SharedGroupDagRoundKind},
    gkr_zk_mask::GkrZkMaskError,
    keccak_gkr_dag::{KeccakDagGateKind, KeccakDagLayer, KeccakDagSource},
    semantic_h4_bridge_gkr::{
        BRIDGE_BLOCK_GROUP_LOG, BRIDGE_DIGEST_GROUP_LOG, NonuniformSemanticH4BridgeOracle,
        SemanticH4BridgeCircuit, SemanticH4BridgeGkrError, SemanticH4BridgeProfile,
    },
};

const READY: &[u8; 8] = b"BLSHBW01";
const OUTPUT: &[u8; 8] = b"BLSHBO01";
const OUTPUT_OK: &[u8; 8] = b"BLSHBOA1";
const BEGIN: &[u8; 8] = b"BLSHBL01";
const BEGIN_OK: &[u8; 8] = b"BLSHBLA1";
const GROUP: &[u8; 8] = b"BLSHBG01";
const GROUP_OK: &[u8; 8] = b"BLSHBGA1";
const CHALLENGE: &[u8; 8] = b"BLSHBC01";
const CHALLENGE_OK: &[u8; 8] = b"BLSHBCA1";
const FOLDED: &[u8; 8] = b"BLSHBF01";
const FOLDED_OK: &[u8; 8] = b"BLSHBFA1";
const FINISH: &[u8; 8] = b"BLSHBX01";
const FINISHED: &[u8; 8] = b"BLSHBXA1";

fn circuit_code(circuit: SemanticH4BridgeCircuit) -> u8 {
    match circuit {
        SemanticH4BridgeCircuit::Rate => 1,
        SemanticH4BridgeCircuit::Inactive => 2,
        SemanticH4BridgeCircuit::Capacity => 3,
        SemanticH4BridgeCircuit::Digest => 4,
    }
}

fn profile_code(profile: SemanticH4BridgeProfile) -> u8 {
    match profile {
        SemanticH4BridgeProfile::K128 => 1,
        SemanticH4BridgeProfile::K512 => 3,
    }
}

pub struct SemanticH4BridgeWorker {
    child: Child,
    writer: BufWriter<ChildStdin>,
    reader: BufReader<ChildStdout>,
    active: bool,
    next_group_round: usize,
    group_rounds: usize,
    left_width: usize,
    right_width: usize,
    same_sources: bool,
    profile: SemanticH4BridgeProfile,
    finished: bool,
}

impl SemanticH4BridgeWorker {
    pub fn spawn(
        python: &Path,
        worker: &Path,
        boundary: &Path,
        snapshot: &Path,
        profile: SemanticH4BridgeProfile,
    ) -> Result<Self, SemanticH4BridgeGkrError> {
        if !python.is_file() || !worker.is_file() || !boundary.is_file() || !snapshot.is_file() {
            return Err(SemanticH4BridgeGkrError::Shape);
        }
        let mut child = Command::new(python)
            .arg("-S")
            .arg(worker)
            .arg(boundary)
            .arg(snapshot)
            .arg(profile_code(profile).to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|_| SemanticH4BridgeGkrError::Algebra)?;
        let stdin = child
            .stdin
            .take()
            .ok_or(SemanticH4BridgeGkrError::Algebra)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(SemanticH4BridgeGkrError::Algebra)?;
        let mut result = Self {
            child,
            writer: BufWriter::with_capacity(1 << 20, stdin),
            reader: BufReader::with_capacity(1 << 20, stdout),
            active: false,
            next_group_round: 0,
            group_rounds: 0,
            left_width: 0,
            right_width: 0,
            same_sources: false,
            profile,
            finished: false,
        };
        result.expect_magic(READY)?;
        Ok(result)
    }

    pub fn finish(mut self) -> Result<(), SemanticH4BridgeGkrError> {
        if self.active {
            return Err(SemanticH4BridgeGkrError::Schedule);
        }
        self.write_magic(FINISH)?;
        self.flush()?;
        self.expect_magic(FINISHED)?;
        if !self
            .child
            .wait()
            .map_err(|_| SemanticH4BridgeGkrError::Algebra)?
            .success()
        {
            return Err(SemanticH4BridgeGkrError::Algebra);
        }
        self.finished = true;
        Ok(())
    }

    fn write_magic(&mut self, magic: &[u8; 8]) -> Result<(), SemanticH4BridgeGkrError> {
        self.writer
            .write_all(magic)
            .map_err(|_| SemanticH4BridgeGkrError::Algebra)
    }

    fn expect_magic(&mut self, magic: &[u8; 8]) -> Result<(), SemanticH4BridgeGkrError> {
        let mut actual = [0_u8; 8];
        self.reader
            .read_exact(&mut actual)
            .map_err(|_| SemanticH4BridgeGkrError::Algebra)?;
        if &actual != magic {
            return Err(SemanticH4BridgeGkrError::Algebra);
        }
        Ok(())
    }

    fn write_field(&mut self, value: Fp16) -> Result<(), SemanticH4BridgeGkrError> {
        self.writer
            .write_all(&value.encode())
            .map_err(|_| SemanticH4BridgeGkrError::Algebra)
    }

    fn read_field(&mut self) -> Result<Fp16, SemanticH4BridgeGkrError> {
        let mut encoded = [0_u8; 64];
        self.reader
            .read_exact(&mut encoded)
            .map_err(|_| SemanticH4BridgeGkrError::Algebra)?;
        Fp16::decode(&encoded).map_err(|_| SemanticH4BridgeGkrError::Algebra)
    }

    fn flush(&mut self) -> Result<(), SemanticH4BridgeGkrError> {
        self.writer
            .flush()
            .map_err(|_| SemanticH4BridgeGkrError::Algebra)
    }

    fn write_claim(&mut self, claim: &LayerOutputClaim) -> Result<(), SemanticH4BridgeGkrError> {
        let length =
            u8::try_from(claim.point.len()).map_err(|_| SemanticH4BridgeGkrError::Shape)?;
        self.writer
            .write_all(&[length])
            .map_err(|_| SemanticH4BridgeGkrError::Algebra)?;
        self.write_field(claim.value)?;
        self.write_field(claim.coefficient)?;
        for value in &claim.point {
            self.write_field(*value)?;
        }
        Ok(())
    }

    fn write_topology(
        &mut self,
        topology: &KeccakDagLayer,
    ) -> Result<(), SemanticH4BridgeGkrError> {
        let source_code = |source| match source {
            KeccakDagSource::RoundInput => Ok(0_u8),
            KeccakDagSource::Layer(index) => {
                u8::try_from(index + 1).map_err(|_| SemanticH4BridgeGkrError::Shape)
            }
        };
        self.writer
            .write_all(&[
                source_code(topology.left_source)?,
                source_code(topology.right_source)?,
            ])
            .map_err(|_| SemanticH4BridgeGkrError::Algebra)?;
        for width in [
            topology.left_width,
            topology.right_width,
            topology.raw_width,
            topology.padded_width,
        ] {
            self.writer
                .write_all(
                    &u16::try_from(width)
                        .map_err(|_| SemanticH4BridgeGkrError::Shape)?
                        .to_be_bytes(),
                )
                .map_err(|_| SemanticH4BridgeGkrError::Algebra)?;
        }
        if topology.gates.len() != topology.padded_width {
            return Err(SemanticH4BridgeGkrError::Shape);
        }
        for gate in &topology.gates {
            let left = u16::try_from(gate.left).map_err(|_| SemanticH4BridgeGkrError::Shape)?;
            let right = u16::try_from(gate.right).map_err(|_| SemanticH4BridgeGkrError::Shape)?;
            let kind = match gate.kind {
                KeccakDagGateKind::Xor => 0,
                KeccakDagGateKind::NotLeftAndRight => 1,
                KeccakDagGateKind::XorConstant(false) => 2,
                KeccakDagGateKind::XorConstant(true) => 3,
                KeccakDagGateKind::Subtract => 4,
                KeccakDagGateKind::Multiply => 5,
                KeccakDagGateKind::Add => 6,
                KeccakDagGateKind::RelayLeft => 7,
                KeccakDagGateKind::Zero => 8,
            };
            self.writer
                .write_all(&left.to_be_bytes())
                .and_then(|_| self.writer.write_all(&right.to_be_bytes()))
                .and_then(|_| self.writer.write_all(&[kind]))
                .map_err(|_| SemanticH4BridgeGkrError::Algebra)?;
        }
        Ok(())
    }
}

impl NonuniformSemanticH4BridgeOracle for SemanticH4BridgeWorker {
    fn output_claim(
        &mut self,
        circuit: SemanticH4BridgeCircuit,
        point: &[Fp16],
    ) -> Result<Fp16, SemanticH4BridgeGkrError> {
        if self.active || point.is_empty() || point.len() > 32 {
            return Err(SemanticH4BridgeGkrError::Schedule);
        }
        self.write_magic(OUTPUT)?;
        self.writer
            .write_all(&[circuit_code(circuit), point.len() as u8])
            .map_err(|_| SemanticH4BridgeGkrError::Algebra)?;
        for value in point {
            self.write_field(*value)?;
        }
        self.flush()?;
        self.expect_magic(OUTPUT_OK)?;
        self.read_field()
    }

    fn begin_layer(
        &mut self,
        circuit: SemanticH4BridgeCircuit,
        layer_index: usize,
        topology: &KeccakDagLayer,
        claims: &[LayerOutputClaim],
    ) -> Result<(), SemanticH4BridgeGkrError> {
        if self.active || claims.is_empty() || claims.len() > 8 {
            return Err(SemanticH4BridgeGkrError::Schedule);
        }
        let group_rounds = claims[0]
            .point
            .len()
            .checked_sub(topology.padded_width.trailing_zeros() as usize)
            .ok_or(SemanticH4BridgeGkrError::Shape)?;
        let expected_group_rounds = match circuit {
            SemanticH4BridgeCircuit::Rate => usize::from(self.profile.rate_group_log()),
            SemanticH4BridgeCircuit::Inactive | SemanticH4BridgeCircuit::Capacity => {
                usize::from(BRIDGE_BLOCK_GROUP_LOG)
            }
            SemanticH4BridgeCircuit::Digest => usize::from(BRIDGE_DIGEST_GROUP_LOG),
        };
        if group_rounds != expected_group_rounds
            || claims
                .iter()
                .any(|claim| claim.point.len() != claims[0].point.len())
        {
            return Err(SemanticH4BridgeGkrError::Shape);
        }
        self.write_magic(BEGIN)?;
        self.writer
            .write_all(&[
                circuit_code(circuit),
                u8::try_from(layer_index).map_err(|_| SemanticH4BridgeGkrError::Shape)?,
                u8::try_from(claims.len()).map_err(|_| SemanticH4BridgeGkrError::Shape)?,
            ])
            .map_err(|_| SemanticH4BridgeGkrError::Algebra)?;
        self.write_topology(topology)?;
        for claim in claims {
            self.write_claim(claim)?;
        }
        self.flush()?;
        self.expect_magic(BEGIN_OK)?;
        self.active = true;
        self.next_group_round = 0;
        self.group_rounds = group_rounds;
        self.left_width = topology.left_width;
        self.right_width = topology.right_width;
        self.same_sources = topology.left_source == topology.right_source;
        Ok(())
    }
}

impl Drop for SemanticH4BridgeWorker {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

impl MaskedSharedGroupOracle for SemanticH4BridgeWorker {
    fn raw_group_round(
        &mut self,
        round: usize,
        expected_claim: Fp16,
    ) -> Result<[Fp16; 4], GkrZkMaskError> {
        if !self.active || round != self.next_group_round || round >= self.group_rounds {
            return Err(GkrZkMaskError::Sequence);
        }
        self.write_magic(GROUP)
            .map_err(|_| GkrZkMaskError::Sequence)?;
        self.writer
            .write_all(&[round as u8])
            .map_err(|_| GkrZkMaskError::Sequence)?;
        self.flush().map_err(|_| GkrZkMaskError::Sequence)?;
        self.expect_magic(GROUP_OK)
            .map_err(|_| GkrZkMaskError::Sequence)?;
        let mut result = [Fp16::ZERO; 4];
        for value in &mut result {
            *value = self.read_field().map_err(|_| GkrZkMaskError::Sequence)?;
        }
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
        if !self.active || round != self.next_group_round || round >= self.group_rounds {
            return Err(GkrZkMaskError::Sequence);
        }
        self.write_magic(CHALLENGE)
            .map_err(|_| GkrZkMaskError::Sequence)?;
        self.writer
            .write_all(&[round as u8])
            .map_err(|_| GkrZkMaskError::Sequence)?;
        self.write_field(challenge)
            .map_err(|_| GkrZkMaskError::Sequence)?;
        self.flush().map_err(|_| GkrZkMaskError::Sequence)?;
        self.expect_magic(CHALLENGE_OK)
            .map_err(|_| GkrZkMaskError::Sequence)?;
        self.next_group_round += 1;
        Ok(())
    }

    fn folded_sources(&mut self) -> Result<(Vec<Fp16>, Vec<Fp16>), GkrZkMaskError> {
        if !self.active || self.next_group_round != self.group_rounds {
            return Err(GkrZkMaskError::Sequence);
        }
        self.write_magic(FOLDED)
            .map_err(|_| GkrZkMaskError::Sequence)?;
        self.flush().map_err(|_| GkrZkMaskError::Sequence)?;
        self.expect_magic(FOLDED_OK)
            .map_err(|_| GkrZkMaskError::Sequence)?;
        let count = self
            .left_width
            .checked_add(if self.same_sources {
                0
            } else {
                self.right_width
            })
            .ok_or(GkrZkMaskError::Shape)?;
        let mut values = vec![Fp16::ZERO; count];
        for value in &mut values {
            *value = self.read_field().map_err(|_| GkrZkMaskError::Sequence)?;
        }
        let right = if self.same_sources {
            values.clone()
        } else {
            values.split_off(self.left_width)
        };
        self.active = false;
        self.left_width = 0;
        self.right_width = 0;
        Ok((values, right))
    }

    fn raw_wire_round(
        &mut self,
        _kind: SharedGroupDagRoundKind,
        _round: usize,
        _masked_terminal_left: Option<Fp16>,
    ) -> Result<[Fp16; 3], GkrZkMaskError> {
        Err(GkrZkMaskError::Sequence)
    }
}
