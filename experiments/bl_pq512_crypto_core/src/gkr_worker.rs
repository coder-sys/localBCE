//! Bounded process boundary for an untrusted sparse-GKR prover worker.
//!
//! The worker receives public geometry and private prover data, publishes one
//! round message, and only then receives that round's authenticated challenge.
//! It never supplies challenges and is not part of the verifier trust base.

use sha3::{Digest, Sha3_512};
use std::{
    ffi::OsString,
    fs::read,
    io::{Read, Write},
    path::Path,
    process::{Child, Command, Stdio},
    string::String,
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
    vec,
    vec::Vec,
};

use crate::{
    Fp16,
    field::M31_MODULUS,
    gkr_sumcheck::{
        MaskedGkrRoundError, MaskedGkrRoundState, MaskedSparseLayerSumcheckProof,
        SparseLayerGpuFixtureTerm,
    },
    packed_boolean_sumcheck::{
        OUTPUT_COEFFICIENTS, PRODUCT_COEFFICIENTS, PackedBooleanTable, PackedReductionReport,
        finish_packed_boolean_combined, verify_packed_first_round_bridge,
    },
};

const REQUEST_MAGIC: &[u8; 8] = b"BLGKRQ2\0";
const PACKED_REQUEST_MAGIC: &[u8; 8] = b"BLGKRQ3\0";
const COMPACT_REQUEST_MAGIC: &[u8; 8] = b"BLGKRQ4\0";
const LIBRA_COMPACT_REQUEST_MAGIC: &[u8; 8] = b"BLGKRQ5\0";
const LIBRA_POINT_COMPACT_REQUEST_MAGIC: &[u8; 8] = b"BLGKRQ6\0";
const RESPONSE_MAGIC: &[u8; 8] = b"BLGKRW2\0";
const PROCESS_MAGIC: &[u8; 8] = b"BLGKRP2\0";
const PINNED_CUDA_BUNDLE: [(&str, &str); 5] = [
    (
        "cuda_gkr_interactive_worker.py",
        "0cee129922c79d163cc1c0b219cf98c48d28bb3fd8b989c757977e58e45ff0aa38f73303269f82051bf5c5a77045a2db26ae17300c6604a0f475228e611eae39",
    ),
    (
        "cuda_fp16_tower_kat.py",
        "97a8638c3f4093b93f0c7fea04cda0a6a6bd63e693b717edc975de3db9416c58665205859d8da2b4c0b8c1a3a0e6198bcd4f487c5a291b6228528d8f89d14670",
    ),
    (
        "cuda_sparse_all_rounds_kat.py",
        "9e2f9463e11b36bd306938531d55f0a537db6003f67dcabc1b18b32dd1567340a0b1a4a7c8aa77d9a67cd20a7ca82ea98ddb574aee4163ba82de623afdb731c3",
    ),
    (
        "cuda_sparse_round_kat.py",
        "a4fa99cdf294ba09e5aeef4fe3ec600d7cae6d2e14abb5e569e62af81e05f953995c4e942d4684897085f0048b4cda3abfddffdf7449b944c324db22496a2bab",
    ),
    (
        "cuda_mlpcs_fold_worker.py",
        "4e83333596b004503a53bb8a061d9bb7f6687a078fe3e1774ea80179a2063c618ef600d57c16d959b43407fc7da8295d78907e37bd4be4aa619ef377b4a255a7",
    ),
];
const FP16_BYTES: usize = 64;
const ROUND_BYTES: usize = 3 * FP16_BYTES;
const TERMINAL_BYTES: usize = 2 * FP16_BYTES;
const ACCUMULATOR_BYTES: usize = (PRODUCT_COEFFICIENTS * 16 + 1) * 4;
pub const MAX_INPUTS: usize = 1 << 19;
pub const MAX_TERMS: usize = 409_600;
pub const MAX_ROUNDS: usize = 38;
pub const MAX_SESSIONS: usize = 216;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GkrWorkerError {
    Shape,
    Spawn,
    Io,
    Timeout,
    Protocol,
    NonCanonical,
    WorkerExit,
    RoundState,
    ChallengeProvider,
    LibraReady,
    LibraAccumulator,
    LibraBridge,
    LibraRound,
    LibraTerminal,
    WorkerIdentity,
}

fn sha3_512_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest: [u8; 64] = Sha3_512::digest(bytes).into();
    let mut encoded = String::with_capacity(128);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

pub fn verify_pinned_gkr_cuda_bundle(worker: &Path) -> Result<(), GkrWorkerError> {
    if worker.file_name().and_then(|name| name.to_str()) != Some(PINNED_CUDA_BUNDLE[0].0) {
        return Err(GkrWorkerError::WorkerIdentity);
    }
    let parent = worker.parent().ok_or(GkrWorkerError::WorkerIdentity)?;
    for (name, expected) in PINNED_CUDA_BUNDLE {
        let bytes = read(parent.join(name)).map_err(|_| GkrWorkerError::WorkerIdentity)?;
        if sha3_512_hex(&bytes) != expected {
            return Err(GkrWorkerError::WorkerIdentity);
        }
    }
    Ok(())
}

pub struct GkrWorkerRequest<'a> {
    pub input: &'a [Fp16],
    pub terms: &'a [SparseLayerGpuFixtureTerm],
}

pub struct GkrPackedWorkerRequest<'a> {
    pub packed_input: &'a [u64],
    pub instances: usize,
    pub input_width: usize,
    pub interpolation_weights: &'a [Fp16; 8],
    pub terms: &'a [SparseLayerGpuFixtureTerm],
}

pub struct GkrCompactClaimWeights<'a> {
    pub coefficient: Fp16,
    pub wire: &'a [Fp16],
    pub group: &'a [Fp16],
}

pub struct GkrCompactWorkerRequest<'a> {
    pub packed_input: &'a [u64],
    pub instances: usize,
    pub input_width: usize,
    pub interpolation_weights: &'a [Fp16; 8],
    pub raw_width: usize,
    pub base_left: &'a [u32],
    pub base_right: &'a [u32],
    pub base_formula: &'a [u8],
    pub claims: &'a [GkrCompactClaimWeights<'a>],
}

pub struct GkrCompactPointClaim<'a> {
    pub coefficient: Fp16,
    pub point: &'a [Fp16],
}

pub struct GkrCompactPointWorkerRequest<'a> {
    pub packed_input: &'a [u64],
    pub instances: usize,
    pub input_width: usize,
    pub raw_width: usize,
    pub claim_wire_variables: usize,
    pub base_left: &'a [u32],
    pub base_right: &'a [u32],
    pub base_formula: &'a [u8],
    pub claims: &'a [GkrCompactPointClaim<'a>],
}

pub struct GkrWorkerSession<'a> {
    pub request: GkrWorkerRequest<'a>,
    pub initial_claim: Fp16,
    pub challenges: &'a [Fp16],
    pub masks: &'a [[Fp16; 2]],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GkrLibraWorkerOutput {
    pub raw_rounds: Vec<[Fp16; 3]>,
    pub terminal_left: Fp16,
    pub terminal_right: Fp16,
}

struct PackedAccumulatorBinding<'a> {
    table: &'a PackedBooleanTable,
    expected_initial_claim: Fp16,
    shard_query: Fp16,
    bridge_challenge: Fp16,
    gates: usize,
}

pub type GkrBridgeProvider<'a> =
    dyn FnMut([Fp16; OUTPUT_COEFFICIENTS]) -> Result<Fp16, GkrWorkerError> + 'a;

pub type GkrLibraRoundProvider<'a> =
    dyn FnMut(usize, [Fp16; 3], [Fp16; 3]) -> Result<(Fp16, Option<Fp16>), GkrWorkerError> + 'a;

type PackedAccumulatorOutput = ([Fp16; OUTPUT_COEFFICIENTS], PackedReductionReport);
type EncodedSessionOutput = (
    MaskedSparseLayerSumcheckProof,
    Option<PackedAccumulatorOutput>,
);
type EncodedLibraSessionOutput = (GkrLibraWorkerOutput, Option<PackedAccumulatorOutput>);

struct EncodedSessionRequest<'a> {
    encoded_request: Vec<u8>,
    initial_claim: Option<Fp16>,
    accumulator_binding: Option<PackedAccumulatorBinding<'a>>,
    expect_accumulator: bool,
    post_accumulator_message: Option<Vec<u8>>,
    challenges: &'a [Fp16],
    masks: &'a [[Fp16; 2]],
    step_timeout: Duration,
}

enum WorkerFrame {
    Ready([u8; 8]),
    Accumulator(Vec<u8>),
    Round(Vec<u8>),
    Terminal([u8; TERMINAL_BYTES]),
    Failed,
}

enum ReaderCommand {
    Session {
        round_count: usize,
        accumulator: bool,
        round_bytes: usize,
    },
    Finish,
}

pub struct BoundedGkrWorker {
    child: Child,
    stdin: Option<Arc<Mutex<std::process::ChildStdin>>>,
    frame_receiver: mpsc::Receiver<WorkerFrame>,
    command_sender: mpsc::Sender<ReaderCommand>,
    reader: Option<thread::JoinHandle<()>>,
    sessions: usize,
    session_limit: usize,
}

fn validate_request(
    request: &GkrWorkerRequest<'_>,
    round_count: usize,
) -> Result<(), GkrWorkerError> {
    if request.input.is_empty()
        || !request.input.len().is_power_of_two()
        || request.input.len() > MAX_INPUTS
        || request.terms.is_empty()
        || request.terms.len() > MAX_TERMS
        || round_count == 0
        || round_count > MAX_ROUNDS
        || round_count != 2 * request.input.len().trailing_zeros() as usize
        || request.terms.iter().any(|term| {
            term.left as usize >= request.input.len()
                || term.right as usize >= request.input.len()
                || term.formula > 7
        })
    {
        return Err(GkrWorkerError::Shape);
    }
    Ok(())
}

fn append_fp16(output: &mut Vec<u8>, value: Fp16) {
    for coordinate in value.coefficients() {
        output.extend_from_slice(&coordinate.to_le_bytes());
    }
}

fn encode_request(
    request: &GkrWorkerRequest<'_>,
    round_count: usize,
) -> Result<Vec<u8>, GkrWorkerError> {
    validate_request(request, round_count)?;
    let capacity = 20_usize
        .checked_add(
            request
                .input
                .len()
                .checked_mul(FP16_BYTES)
                .ok_or(GkrWorkerError::Shape)?,
        )
        .and_then(|value| value.checked_add(request.terms.len().checked_mul(73)?))
        .ok_or(GkrWorkerError::Shape)?;
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(REQUEST_MAGIC);
    for count in [request.input.len(), request.terms.len(), round_count] {
        output.extend_from_slice(
            &u32::try_from(count)
                .map_err(|_| GkrWorkerError::Shape)?
                .to_le_bytes(),
        );
    }
    for value in request.input {
        append_fp16(&mut output, *value);
    }
    for term in request.terms {
        append_fp16(&mut output, term.output_weight);
    }
    for term in request.terms {
        output.extend_from_slice(&term.left.to_le_bytes());
    }
    for term in request.terms {
        output.extend_from_slice(&term.right.to_le_bytes());
    }
    for term in request.terms {
        output.push(term.formula);
    }
    Ok(output)
}

fn encode_packed_request(
    request: &GkrPackedWorkerRequest<'_>,
    round_count: usize,
) -> Result<Vec<u8>, GkrWorkerError> {
    if request.instances == 0
        || !request.instances.is_multiple_of(8)
        || !request.instances.is_power_of_two()
        || !request.input_width.is_power_of_two()
    {
        return Err(GkrWorkerError::Shape);
    }
    let groups = request.instances / 8;
    let input_count = request
        .input_width
        .checked_mul(groups)
        .ok_or(GkrWorkerError::Shape)?;
    let words = request.instances.div_ceil(64);
    if input_count == 0
        || input_count > MAX_INPUTS
        || round_count != 2 * input_count.trailing_zeros() as usize
        || request.packed_input.len() != request.input_width * words
        || request.terms.is_empty()
        || request.terms.len() > MAX_TERMS
        || request.terms.iter().any(|term| {
            term.left as usize >= input_count
                || term.right as usize >= input_count
                || term.formula > 7
        })
    {
        return Err(GkrWorkerError::Shape);
    }
    let mut output = Vec::new();
    output.extend_from_slice(PACKED_REQUEST_MAGIC);
    for count in [
        input_count,
        request.terms.len(),
        round_count,
        request.instances,
        request.input_width,
    ] {
        output.extend_from_slice(
            &u32::try_from(count)
                .map_err(|_| GkrWorkerError::Shape)?
                .to_le_bytes(),
        );
    }
    for value in request.packed_input {
        output.extend_from_slice(&value.to_le_bytes());
    }
    for weight in request.interpolation_weights {
        append_fp16(&mut output, *weight);
    }
    for term in request.terms {
        append_fp16(&mut output, term.output_weight);
    }
    for term in request.terms {
        output.extend_from_slice(&term.left.to_le_bytes());
    }
    for term in request.terms {
        output.extend_from_slice(&term.right.to_le_bytes());
    }
    for term in request.terms {
        output.push(term.formula);
    }
    Ok(output)
}

fn encode_compact_request(
    request: &GkrCompactWorkerRequest<'_>,
    round_count: usize,
) -> Result<Vec<u8>, GkrWorkerError> {
    encode_compact_request_with_magic(request, round_count, COMPACT_REQUEST_MAGIC)
}

fn encode_compact_request_with_magic(
    request: &GkrCompactWorkerRequest<'_>,
    round_count: usize,
    magic: &[u8; 8],
) -> Result<Vec<u8>, GkrWorkerError> {
    if request.instances == 0
        || !request.instances.is_multiple_of(8)
        || !request.instances.is_power_of_two()
        || !request.input_width.is_power_of_two()
        || request.raw_width == 0
        || request.claims.is_empty()
        || request.claims.len() > 2
    {
        return Err(GkrWorkerError::Shape);
    }
    let groups = request.instances / 8;
    let input_count = request
        .input_width
        .checked_mul(groups)
        .ok_or(GkrWorkerError::Shape)?;
    let term_count = request
        .raw_width
        .checked_mul(groups)
        .ok_or(GkrWorkerError::Shape)?;
    let words = request.instances.div_ceil(64);
    if input_count > MAX_INPUTS
        || term_count > MAX_TERMS
        || round_count != 2 * input_count.trailing_zeros() as usize
        || request.packed_input.len() != request.input_width * words
        || request.base_left.len() != request.raw_width
        || request.base_right.len() != request.raw_width
        || request.base_formula.len() != request.raw_width
        || request
            .base_left
            .iter()
            .chain(request.base_right)
            .any(|index| *index as usize >= request.input_width)
        || request.base_formula.iter().any(|formula| *formula > 7)
        || request
            .claims
            .iter()
            .any(|claim| claim.wire.len() != request.raw_width || claim.group.len() != groups)
    {
        return Err(GkrWorkerError::Shape);
    }
    let mut output = Vec::new();
    output.extend_from_slice(magic);
    for count in [
        input_count,
        term_count,
        round_count,
        request.instances,
        request.input_width,
        request.raw_width,
        request.claims.len(),
    ] {
        output.extend_from_slice(
            &u32::try_from(count)
                .map_err(|_| GkrWorkerError::Shape)?
                .to_le_bytes(),
        );
    }
    for value in request.packed_input {
        output.extend_from_slice(&value.to_le_bytes());
    }
    for claim in request.claims {
        append_fp16(&mut output, claim.coefficient);
    }
    for claim in request.claims {
        for weight in claim.wire {
            append_fp16(&mut output, *weight);
        }
    }
    for claim in request.claims {
        for weight in claim.group {
            append_fp16(&mut output, *weight);
        }
    }
    for index in request.base_left {
        output.extend_from_slice(&index.to_le_bytes());
    }
    for index in request.base_right {
        output.extend_from_slice(&index.to_le_bytes());
    }
    output.extend_from_slice(request.base_formula);
    Ok(output)
}

fn encode_point_compact_request(
    request: &GkrCompactPointWorkerRequest<'_>,
    round_count: usize,
) -> Result<Vec<u8>, GkrWorkerError> {
    if request.instances == 0
        || !request.instances.is_multiple_of(8)
        || !request.instances.is_power_of_two()
        || !request.input_width.is_power_of_two()
        || request.raw_width == 0
        || request.claims.is_empty()
        || request.claims.len() > 2
    {
        return Err(GkrWorkerError::Shape);
    }
    let groups = request.instances / 8;
    let input_count = request
        .input_width
        .checked_mul(groups)
        .ok_or(GkrWorkerError::Shape)?;
    let term_count = request
        .raw_width
        .checked_mul(groups)
        .ok_or(GkrWorkerError::Shape)?;
    let input_variables = input_count.trailing_zeros() as usize;
    let point_variables = request
        .claim_wire_variables
        .checked_add(groups.trailing_zeros() as usize)
        .ok_or(GkrWorkerError::Shape)?;
    let words = request.instances.div_ceil(64);
    if input_count > MAX_INPUTS
        || term_count > MAX_TERMS
        || round_count != 2 * input_variables
        || request.packed_input.len() != request.input_width * words
        || request.base_left.len() != request.raw_width
        || request.base_right.len() != request.raw_width
        || request.base_formula.len() != request.raw_width
        || request
            .base_left
            .iter()
            .chain(request.base_right)
            .any(|index| *index as usize >= request.input_width)
        || request.base_formula.iter().any(|formula| *formula > 7)
        || request.claim_wire_variables == 0
        || request.raw_width > (1_usize << request.claim_wire_variables)
        || request
            .claims
            .iter()
            .any(|claim| claim.point.len() != point_variables)
    {
        return Err(GkrWorkerError::Shape);
    }
    let mut output = Vec::new();
    output.extend_from_slice(LIBRA_POINT_COMPACT_REQUEST_MAGIC);
    for count in [
        input_count,
        term_count,
        round_count,
        request.instances,
        request.input_width,
        request.raw_width,
        request.claims.len(),
        request.claim_wire_variables,
    ] {
        output.extend_from_slice(
            &u32::try_from(count)
                .map_err(|_| GkrWorkerError::Shape)?
                .to_le_bytes(),
        );
    }
    for value in request.packed_input {
        output.extend_from_slice(&value.to_le_bytes());
    }
    for claim in request.claims {
        append_fp16(&mut output, claim.coefficient);
    }
    for claim in request.claims {
        for coordinate in claim.point {
            append_fp16(&mut output, *coordinate);
        }
    }
    for index in request.base_left {
        output.extend_from_slice(&index.to_le_bytes());
    }
    for index in request.base_right {
        output.extend_from_slice(&index.to_le_bytes());
    }
    output.extend_from_slice(request.base_formula);
    Ok(output)
}

fn encode_interpolation_weights(weights: &[Fp16; 8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(8 * FP16_BYTES);
    for weight in weights {
        append_fp16(&mut output, *weight);
    }
    output
}

fn decode_fp16(bytes: &[u8]) -> Result<Fp16, GkrWorkerError> {
    if bytes.len() != FP16_BYTES {
        return Err(GkrWorkerError::Protocol);
    }
    let mut coordinates = [0_u32; 16];
    for (coordinate, encoded) in coordinates.iter_mut().zip(bytes.chunks_exact(4)) {
        *coordinate = u32::from_le_bytes(encoded.try_into().map_err(|_| GkrWorkerError::Protocol)?);
    }
    if coordinates
        .iter()
        .any(|coordinate| *coordinate >= M31_MODULUS)
    {
        return Err(GkrWorkerError::NonCanonical);
    }
    Fp16::from_coefficients(coordinates).map_err(|_| GkrWorkerError::NonCanonical)
}

fn decode_combined(bytes: &[u8]) -> Result<([Fp16; PRODUCT_COEFFICIENTS], usize), GkrWorkerError> {
    if bytes.len() != ACCUMULATOR_BYTES {
        return Err(GkrWorkerError::Protocol);
    }
    let mut combined = [Fp16::ZERO; PRODUCT_COEFFICIENTS];
    for (value, encoded) in combined
        .iter_mut()
        .zip(bytes[..PRODUCT_COEFFICIENTS * FP16_BYTES].chunks_exact(FP16_BYTES))
    {
        *value = decode_fp16(encoded)?;
    }
    let count = u32::from_le_bytes(
        bytes[PRODUCT_COEFFICIENTS * FP16_BYTES..]
            .try_into()
            .map_err(|_| GkrWorkerError::Protocol)?,
    ) as usize;
    Ok((combined, count))
}

fn receive(
    receiver: &mpsc::Receiver<WorkerFrame>,
    timeout: Duration,
) -> Result<WorkerFrame, GkrWorkerError> {
    receiver.recv_timeout(timeout).map_err(|error| match error {
        mpsc::RecvTimeoutError::Timeout => GkrWorkerError::Timeout,
        mpsc::RecvTimeoutError::Disconnected => GkrWorkerError::Io,
    })
}

fn stop_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn wait_child(child: &mut Child, timeout: Duration) -> Result<(), GkrWorkerError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(GkrWorkerError::Shape)?;
    loop {
        match child.try_wait().map_err(|_| GkrWorkerError::Io)? {
            Some(status) if status.success() => return Ok(()),
            Some(_) => return Err(GkrWorkerError::WorkerExit),
            None if Instant::now() >= deadline => {
                stop_child(child);
                return Err(GkrWorkerError::Timeout);
            }
            None => thread::sleep(Duration::from_millis(2)),
        }
    }
}

fn write_with_timeout(
    stdin: &Arc<Mutex<std::process::ChildStdin>>,
    bytes: Vec<u8>,
    timeout: Duration,
) -> Result<(), GkrWorkerError> {
    let writer_stdin = Arc::clone(stdin);
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let result = writer_stdin
            .lock()
            .map_err(|_| ())
            .and_then(|mut output| output.write_all(&bytes).map_err(|_| ()));
        let _ = sender.send(result);
    });
    receiver
        .recv_timeout(timeout)
        .map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => GkrWorkerError::Timeout,
            mpsc::RecvTimeoutError::Disconnected => GkrWorkerError::Io,
        })?
        .map_err(|_| GkrWorkerError::Io)
}

impl BoundedGkrWorker {
    pub fn spawn(
        program: &Path,
        arguments: &[OsString],
        session_limit: usize,
        step_timeout: Duration,
    ) -> Result<Self, GkrWorkerError> {
        if session_limit == 0 || session_limit > MAX_SESSIONS || step_timeout.is_zero() {
            return Err(GkrWorkerError::Shape);
        }
        let stderr = if std::env::var_os("BL_GKR_WORKER_STDERR").is_some() {
            Stdio::inherit()
        } else {
            Stdio::null()
        };
        let mut child = Command::new(program)
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr)
            .spawn()
            .map_err(|_| GkrWorkerError::Spawn)?;
        let stdin = Arc::new(Mutex::new(child.stdin.take().ok_or(GkrWorkerError::Spawn)?));
        let mut stdout = child.stdout.take().ok_or(GkrWorkerError::Spawn)?;
        let (frame_sender, frame_receiver) = mpsc::channel();
        let (command_sender, command_receiver) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut ready = [0_u8; 8];
            if stdout.read_exact(&mut ready).is_err()
                || frame_sender.send(WorkerFrame::Ready(ready)).is_err()
            {
                let _ = frame_sender.send(WorkerFrame::Failed);
                return;
            }
            while let Ok(command) = command_receiver.recv() {
                let ReaderCommand::Session {
                    round_count,
                    accumulator,
                    round_bytes,
                } = command
                else {
                    return;
                };
                let mut session_ready = [0_u8; 8];
                if stdout.read_exact(&mut session_ready).is_err()
                    || frame_sender
                        .send(WorkerFrame::Ready(session_ready))
                        .is_err()
                {
                    let _ = frame_sender.send(WorkerFrame::Failed);
                    return;
                }
                if accumulator {
                    let mut encoded = vec![0_u8; ACCUMULATOR_BYTES];
                    if stdout.read_exact(&mut encoded).is_err()
                        || frame_sender
                            .send(WorkerFrame::Accumulator(encoded))
                            .is_err()
                    {
                        let _ = frame_sender.send(WorkerFrame::Failed);
                        return;
                    }
                }
                for _ in 0..round_count {
                    let mut round = vec![0_u8; round_bytes];
                    if stdout.read_exact(&mut round).is_err()
                        || frame_sender.send(WorkerFrame::Round(round)).is_err()
                    {
                        let _ = frame_sender.send(WorkerFrame::Failed);
                        return;
                    }
                }
                let mut terminal = [0_u8; TERMINAL_BYTES];
                if stdout.read_exact(&mut terminal).is_err()
                    || frame_sender.send(WorkerFrame::Terminal(terminal)).is_err()
                {
                    let _ = frame_sender.send(WorkerFrame::Failed);
                    return;
                }
            }
        });
        let mut worker = Self {
            child,
            stdin: Some(stdin),
            frame_receiver,
            command_sender,
            reader: Some(reader),
            sessions: 0,
            session_limit,
        };
        match receive(&worker.frame_receiver, step_timeout) {
            Ok(WorkerFrame::Ready(magic)) if &magic == PROCESS_MAGIC => {}
            Ok(_) => {
                stop_child(&mut worker.child);
                if let Some(reader) = worker.reader.take() {
                    let _ = reader.join();
                }
                return Err(GkrWorkerError::Protocol);
            }
            Err(error) => {
                stop_child(&mut worker.child);
                if let Some(reader) = worker.reader.take() {
                    let _ = reader.join();
                }
                return Err(error);
            }
        }
        write_with_timeout(
            worker.stdin.as_ref().ok_or(GkrWorkerError::Io)?,
            u32::try_from(session_limit)
                .map_err(|_| GkrWorkerError::Shape)?
                .to_le_bytes()
                .to_vec(),
            step_timeout,
        )?;
        Ok(worker)
    }

    pub fn run_session(
        &mut self,
        session: &GkrWorkerSession<'_>,
        step_timeout: Duration,
    ) -> Result<MaskedSparseLayerSumcheckProof, GkrWorkerError> {
        if self.sessions >= self.session_limit
            || step_timeout.is_zero()
            || session.challenges.len() != session.masks.len()
        {
            return Err(GkrWorkerError::Shape);
        }
        validate_request(&session.request, session.challenges.len())?;
        let encoded = encode_request(&session.request, session.challenges.len())?;
        self.run_encoded_session(EncodedSessionRequest {
            encoded_request: encoded,
            initial_claim: Some(session.initial_claim),
            accumulator_binding: None,
            expect_accumulator: false,
            post_accumulator_message: None,
            challenges: session.challenges,
            masks: session.masks,
            step_timeout,
        })
        .map(|(proof, _)| proof)
    }

    pub fn run_packed_session(
        &mut self,
        request: &GkrPackedWorkerRequest<'_>,
        initial_claim: Fp16,
        challenges: &[Fp16],
        masks: &[[Fp16; 2]],
        step_timeout: Duration,
    ) -> Result<MaskedSparseLayerSumcheckProof, GkrWorkerError> {
        if self.sessions >= self.session_limit
            || step_timeout.is_zero()
            || challenges.len() != masks.len()
        {
            return Err(GkrWorkerError::Shape);
        }
        let encoded = encode_packed_request(request, challenges.len())?;
        self.run_encoded_session(EncodedSessionRequest {
            encoded_request: encoded,
            initial_claim: Some(initial_claim),
            accumulator_binding: None,
            expect_accumulator: false,
            post_accumulator_message: None,
            challenges,
            masks,
            step_timeout,
        })
        .map(|(proof, _)| proof)
    }

    pub fn run_compact_session(
        &mut self,
        request: &GkrCompactWorkerRequest<'_>,
        initial_claim: Fp16,
        challenges: &[Fp16],
        masks: &[[Fp16; 2]],
        step_timeout: Duration,
    ) -> Result<MaskedSparseLayerSumcheckProof, GkrWorkerError> {
        if self.sessions >= self.session_limit
            || step_timeout.is_zero()
            || challenges.len() != masks.len()
        {
            return Err(GkrWorkerError::Shape);
        }
        let encoded = encode_compact_request(request, challenges.len())?;
        self.run_encoded_session(EncodedSessionRequest {
            encoded_request: encoded,
            initial_claim: Some(initial_claim),
            accumulator_binding: None,
            expect_accumulator: true,
            post_accumulator_message: Some(encode_interpolation_weights(
                request.interpolation_weights,
            )),
            challenges,
            masks,
            step_timeout,
        })
        .map(|(proof, _)| proof)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_compact_session_with_accumulator(
        &mut self,
        request: &GkrCompactWorkerRequest<'_>,
        table: &PackedBooleanTable,
        expected_initial_claim: Fp16,
        shard_query: Fp16,
        bridge_challenge: Fp16,
        challenges: &[Fp16],
        masks: &[[Fp16; 2]],
        step_timeout: Duration,
    ) -> Result<
        (
            MaskedSparseLayerSumcheckProof,
            [Fp16; OUTPUT_COEFFICIENTS],
            PackedReductionReport,
        ),
        GkrWorkerError,
    > {
        if self.sessions >= self.session_limit
            || step_timeout.is_zero()
            || challenges.len() != masks.len()
        {
            return Err(GkrWorkerError::Shape);
        }
        let encoded = encode_compact_request(request, challenges.len())?;
        let gates = request
            .raw_width
            .checked_mul(request.instances / 8)
            .ok_or(GkrWorkerError::Shape)?;
        let binding = PackedAccumulatorBinding {
            table,
            expected_initial_claim,
            shard_query,
            bridge_challenge,
            gates,
        };
        let (proof, packed) = self.run_encoded_session(EncodedSessionRequest {
            encoded_request: encoded,
            initial_claim: None,
            accumulator_binding: Some(binding),
            expect_accumulator: true,
            post_accumulator_message: Some(encode_interpolation_weights(
                request.interpolation_weights,
            )),
            challenges,
            masks,
            step_timeout,
        })?;
        let (polynomial, report) = packed.ok_or(GkrWorkerError::Protocol)?;
        Ok((proof, polynomial, report))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_compact_session_with_accumulator_challenge_provider(
        &mut self,
        request: &GkrCompactWorkerRequest<'_>,
        table: &PackedBooleanTable,
        expected_initial_claim: Fp16,
        shard_query: Fp16,
        bridge_challenge: Fp16,
        round_count: usize,
        masks: &[[Fp16; 2]],
        challenge_provider: &mut dyn FnMut(usize, [Fp16; 3]) -> Result<Fp16, GkrWorkerError>,
        step_timeout: Duration,
    ) -> Result<
        (
            MaskedSparseLayerSumcheckProof,
            [Fp16; OUTPUT_COEFFICIENTS],
            PackedReductionReport,
        ),
        GkrWorkerError,
    > {
        if self.sessions >= self.session_limit
            || step_timeout.is_zero()
            || round_count != masks.len()
        {
            return Err(GkrWorkerError::Shape);
        }
        let encoded = encode_compact_request(request, round_count)?;
        let gates = request
            .raw_width
            .checked_mul(request.instances / 8)
            .ok_or(GkrWorkerError::Shape)?;
        let binding = PackedAccumulatorBinding {
            table,
            expected_initial_claim,
            shard_query,
            bridge_challenge,
            gates,
        };
        let (proof, packed) = self.run_encoded_session_with_provider(
            encoded,
            None,
            Some(binding),
            true,
            Some(encode_interpolation_weights(request.interpolation_weights)),
            None,
            round_count,
            masks,
            challenge_provider,
            step_timeout,
        )?;
        let (polynomial, report) = packed.ok_or(GkrWorkerError::Protocol)?;
        Ok((proof, polynomial, report))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_compact_session_with_public_coin_providers(
        &mut self,
        request: &GkrCompactWorkerRequest<'_>,
        table: &PackedBooleanTable,
        expected_initial_claim: Fp16,
        shard_query: Fp16,
        round_count: usize,
        masks: &[[Fp16; 2]],
        bridge_provider: &mut dyn FnMut(
            [Fp16; OUTPUT_COEFFICIENTS],
        ) -> Result<Fp16, GkrWorkerError>,
        challenge_provider: &mut dyn FnMut(usize, [Fp16; 3]) -> Result<Fp16, GkrWorkerError>,
        step_timeout: Duration,
    ) -> Result<
        (
            MaskedSparseLayerSumcheckProof,
            [Fp16; OUTPUT_COEFFICIENTS],
            PackedReductionReport,
        ),
        GkrWorkerError,
    > {
        if self.sessions >= self.session_limit
            || step_timeout.is_zero()
            || round_count != masks.len()
        {
            return Err(GkrWorkerError::Shape);
        }
        let encoded = encode_compact_request(request, round_count)?;
        let gates = request
            .raw_width
            .checked_mul(request.instances / 8)
            .ok_or(GkrWorkerError::Shape)?;
        let binding = PackedAccumulatorBinding {
            table,
            expected_initial_claim,
            shard_query,
            bridge_challenge: Fp16::ZERO,
            gates,
        };
        let (proof, packed) = self.run_encoded_session_with_provider(
            encoded,
            None,
            Some(binding),
            true,
            None,
            Some(bridge_provider),
            round_count,
            masks,
            challenge_provider,
            step_timeout,
        )?;
        let (polynomial, report) = packed.ok_or(GkrWorkerError::Protocol)?;
        Ok((proof, polynomial, report))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_compact_libra_session_with_public_coin_providers(
        &mut self,
        request: &GkrCompactWorkerRequest<'_>,
        table: &PackedBooleanTable,
        expected_raw_initial_claim: Fp16,
        shard_query: Fp16,
        bridge_provider: &mut GkrBridgeProvider<'_>,
        round_provider: &mut GkrLibraRoundProvider<'_>,
        step_timeout: Duration,
    ) -> Result<
        (
            GkrLibraWorkerOutput,
            [Fp16; OUTPUT_COEFFICIENTS],
            PackedReductionReport,
        ),
        GkrWorkerError,
    > {
        if self.sessions >= self.session_limit || step_timeout.is_zero() {
            return Err(GkrWorkerError::Shape);
        }
        let input_count = request
            .input_width
            .checked_mul(request.instances / 8)
            .ok_or(GkrWorkerError::Shape)?;
        let round_count = 2 * input_count.trailing_zeros() as usize;
        let encoded =
            encode_compact_request_with_magic(request, round_count, LIBRA_COMPACT_REQUEST_MAGIC)?;
        let gates = request
            .raw_width
            .checked_mul(request.instances / 8)
            .ok_or(GkrWorkerError::Shape)?;
        let binding = PackedAccumulatorBinding {
            table,
            expected_initial_claim: expected_raw_initial_claim,
            shard_query,
            bridge_challenge: Fp16::ZERO,
            gates,
        };
        let (output, packed) = self.run_encoded_libra_session_with_provider(
            encoded,
            binding,
            bridge_provider,
            round_count,
            round_provider,
            step_timeout,
        )?;
        let (polynomial, report) = packed.ok_or(GkrWorkerError::Protocol)?;
        Ok((output, polynomial, report))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_compact_point_libra_session_with_public_coin_providers(
        &mut self,
        request: &GkrCompactPointWorkerRequest<'_>,
        table: &PackedBooleanTable,
        expected_raw_initial_claim: Fp16,
        shard_query: Fp16,
        bridge_provider: &mut GkrBridgeProvider<'_>,
        round_provider: &mut GkrLibraRoundProvider<'_>,
        step_timeout: Duration,
    ) -> Result<
        (
            GkrLibraWorkerOutput,
            [Fp16; OUTPUT_COEFFICIENTS],
            PackedReductionReport,
        ),
        GkrWorkerError,
    > {
        if self.sessions >= self.session_limit || step_timeout.is_zero() {
            return Err(GkrWorkerError::Shape);
        }
        let input_count = request
            .input_width
            .checked_mul(request.instances / 8)
            .ok_or(GkrWorkerError::Shape)?;
        let round_count = 2 * input_count.trailing_zeros() as usize;
        let encoded = encode_point_compact_request(request, round_count)?;
        let gates = request
            .raw_width
            .checked_mul(request.instances / 8)
            .ok_or(GkrWorkerError::Shape)?;
        let binding = PackedAccumulatorBinding {
            table,
            expected_initial_claim: expected_raw_initial_claim,
            shard_query,
            bridge_challenge: Fp16::ZERO,
            gates,
        };
        let (output, packed) = self.run_encoded_libra_session_with_provider(
            encoded,
            binding,
            bridge_provider,
            round_count,
            round_provider,
            step_timeout,
        )?;
        let (polynomial, report) = packed.ok_or(GkrWorkerError::Protocol)?;
        Ok((output, polynomial, report))
    }

    fn run_encoded_session(
        &mut self,
        request: EncodedSessionRequest<'_>,
    ) -> Result<EncodedSessionOutput, GkrWorkerError> {
        let EncodedSessionRequest {
            encoded_request,
            initial_claim,
            accumulator_binding,
            expect_accumulator,
            post_accumulator_message,
            challenges,
            masks,
            step_timeout,
        } = request;
        let mut challenge_index = 0_usize;
        let mut provider = |round: usize, _message: [Fp16; 3]| {
            if round != challenge_index {
                return Err(GkrWorkerError::ChallengeProvider);
            }
            let challenge = challenges
                .get(challenge_index)
                .copied()
                .ok_or(GkrWorkerError::ChallengeProvider)?;
            challenge_index += 1;
            Ok(challenge)
        };
        self.run_encoded_session_with_provider(
            encoded_request,
            initial_claim,
            accumulator_binding,
            expect_accumulator,
            post_accumulator_message,
            None,
            challenges.len(),
            masks,
            &mut provider,
            step_timeout,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn run_encoded_session_with_provider(
        &mut self,
        encoded_request: Vec<u8>,
        initial_claim: Option<Fp16>,
        accumulator_binding: Option<PackedAccumulatorBinding<'_>>,
        expect_accumulator: bool,
        post_accumulator_message: Option<Vec<u8>>,
        mut bridge_provider: Option<&mut GkrBridgeProvider<'_>>,
        round_count: usize,
        masks: &[[Fp16; 2]],
        challenge_provider: &mut dyn FnMut(usize, [Fp16; 3]) -> Result<Fp16, GkrWorkerError>,
        step_timeout: Duration,
    ) -> Result<EncodedSessionOutput, GkrWorkerError> {
        self.command_sender
            .send(ReaderCommand::Session {
                round_count,
                accumulator: expect_accumulator,
                round_bytes: ROUND_BYTES,
            })
            .map_err(|_| GkrWorkerError::Io)?;
        let stdin = self.stdin.as_ref().ok_or(GkrWorkerError::Io)?;
        write_with_timeout(stdin, encoded_request, step_timeout)?;
        match receive(&self.frame_receiver, step_timeout)? {
            WorkerFrame::Ready(magic) if &magic == RESPONSE_MAGIC => {}
            _ => return Err(GkrWorkerError::Protocol),
        }
        let accumulator_bytes = if expect_accumulator {
            let bytes = match receive(&self.frame_receiver, step_timeout)? {
                WorkerFrame::Accumulator(bytes) => bytes,
                _ => return Err(GkrWorkerError::Protocol),
            };
            Some(bytes)
        } else {
            None
        };
        let mut dynamic_post_accumulator_message = None;
        let packed = if let Some(binding) = accumulator_binding {
            let bytes = accumulator_bytes.ok_or(GkrWorkerError::Protocol)?;
            let (combined, nonzero_product_buckets) = decode_combined(&bytes)?;
            let (polynomial, report) = finish_packed_boolean_combined(
                combined,
                binding.shard_query,
                binding.gates,
                nonzero_product_buckets,
                binding.table.table_bytes(),
            )
            .map_err(|_| GkrWorkerError::Protocol)?;
            let bridge_challenge = if let Some(provider) = bridge_provider.as_mut() {
                let challenge = provider(polynomial)?;
                let weights =
                    crate::packed_boolean_sumcheck::packed_lagrange_node_weights(challenge)
                        .map_err(|_| GkrWorkerError::ChallengeProvider)?;
                dynamic_post_accumulator_message = Some(encode_interpolation_weights(&weights));
                challenge
            } else {
                binding.bridge_challenge
            };
            let bridge = verify_packed_first_round_bridge(
                binding.expected_initial_claim,
                &polynomial,
                binding.shard_query,
                bridge_challenge,
            )
            .map_err(|_| GkrWorkerError::Protocol)?;
            Some((bridge.gate_claim, (polynomial, report)))
        } else {
            None
        };
        let initial_claim = match (initial_claim, packed.as_ref()) {
            (Some(claim), None) => claim,
            (None, Some((claim, _))) => *claim,
            _ => return Err(GkrWorkerError::Protocol),
        };
        let post_accumulator_message =
            dynamic_post_accumulator_message.or(post_accumulator_message);
        match (expect_accumulator, post_accumulator_message) {
            (true, Some(message)) => write_with_timeout(stdin, message, step_timeout)?,
            (false, None) => {}
            _ => return Err(GkrWorkerError::Protocol),
        }
        let mut state = MaskedGkrRoundState::new(initial_claim, round_count)
            .map_err(|_| GkrWorkerError::RoundState)?;
        for (round, mask) in masks.iter().enumerate() {
            let bytes = match receive(&self.frame_receiver, step_timeout)? {
                WorkerFrame::Round(bytes) => bytes,
                _ => return Err(GkrWorkerError::Protocol),
            };
            let raw = [
                decode_fp16(&bytes[..FP16_BYTES])?,
                decode_fp16(&bytes[FP16_BYTES..2 * FP16_BYTES])?,
                decode_fp16(&bytes[2 * FP16_BYTES..ROUND_BYTES])?,
            ];
            let masked = state
                .publish_masked_message(raw, *mask)
                .map_err(|error| match error {
                    MaskedGkrRoundError::Claim => GkrWorkerError::Protocol,
                    _ => GkrWorkerError::RoundState,
                })?;
            let challenge = challenge_provider(round, masked)?;
            state
                .accept_authenticated_challenge(challenge)
                .map_err(|_| GkrWorkerError::RoundState)?;
            let mut encoded_challenge = Vec::with_capacity(FP16_BYTES);
            append_fp16(&mut encoded_challenge, challenge);
            write_with_timeout(stdin, encoded_challenge, step_timeout)?;
        }
        let terminal = match receive(&self.frame_receiver, step_timeout)? {
            WorkerFrame::Terminal(bytes) => bytes,
            _ => return Err(GkrWorkerError::Protocol),
        };
        let proof = state
            .finish(
                decode_fp16(&terminal[..FP16_BYTES])?,
                decode_fp16(&terminal[FP16_BYTES..])?,
            )
            .map_err(|_| GkrWorkerError::RoundState)?;
        self.sessions += 1;
        Ok((proof, packed.map(|(_, output)| output)))
    }

    #[allow(clippy::too_many_arguments)]
    fn run_encoded_libra_session_with_provider(
        &mut self,
        encoded_request: Vec<u8>,
        binding: PackedAccumulatorBinding<'_>,
        bridge_provider: &mut GkrBridgeProvider<'_>,
        round_count: usize,
        round_provider: &mut GkrLibraRoundProvider<'_>,
        step_timeout: Duration,
    ) -> Result<EncodedLibraSessionOutput, GkrWorkerError> {
        self.command_sender
            .send(ReaderCommand::Session {
                round_count,
                accumulator: true,
                round_bytes: 2 * ROUND_BYTES,
            })
            .map_err(|_| GkrWorkerError::Io)?;
        let stdin = self.stdin.as_ref().ok_or(GkrWorkerError::Io)?;
        write_with_timeout(stdin, encoded_request, step_timeout)?;
        match receive(&self.frame_receiver, step_timeout)? {
            WorkerFrame::Ready(magic) if &magic == RESPONSE_MAGIC => {}
            _ => return Err(GkrWorkerError::LibraReady),
        }
        let bytes = match receive(&self.frame_receiver, step_timeout)? {
            WorkerFrame::Accumulator(bytes) => bytes,
            _ => return Err(GkrWorkerError::LibraAccumulator),
        };
        let (combined, nonzero_product_buckets) = decode_combined(&bytes)?;
        let (polynomial, report) = finish_packed_boolean_combined(
            combined,
            binding.shard_query,
            binding.gates,
            nonzero_product_buckets,
            binding.table.table_bytes(),
        )
        .map_err(|_| GkrWorkerError::LibraAccumulator)?;
        let bridge_challenge = bridge_provider(polynomial)?;
        let weights =
            crate::packed_boolean_sumcheck::packed_lagrange_node_weights(bridge_challenge)
                .map_err(|_| GkrWorkerError::ChallengeProvider)?;
        let _bridge = verify_packed_first_round_bridge(
            binding.expected_initial_claim,
            &polynomial,
            binding.shard_query,
            bridge_challenge,
        )
        .map_err(|_| GkrWorkerError::LibraBridge)?;
        write_with_timeout(stdin, encode_interpolation_weights(&weights), step_timeout)?;

        let left_rounds = round_count / 2;
        let mut raw_rounds = Vec::with_capacity(round_count);
        for round in 0..round_count {
            let bytes = match receive(&self.frame_receiver, step_timeout)? {
                WorkerFrame::Round(bytes) => bytes,
                _ => return Err(GkrWorkerError::LibraRound),
            };
            let raw = [
                decode_fp16(&bytes[..FP16_BYTES])?,
                decode_fp16(&bytes[FP16_BYTES..2 * FP16_BYTES])?,
                decode_fp16(&bytes[2 * FP16_BYTES..ROUND_BYTES])?,
            ];
            if bytes.len() != 2 * ROUND_BYTES {
                return Err(GkrWorkerError::LibraRound);
            }
            let sensitivity = [
                decode_fp16(&bytes[ROUND_BYTES..ROUND_BYTES + FP16_BYTES])?,
                decode_fp16(&bytes[ROUND_BYTES + FP16_BYTES..ROUND_BYTES + 2 * FP16_BYTES])?,
                decode_fp16(&bytes[ROUND_BYTES + 2 * FP16_BYTES..])?,
            ];
            let (challenge, terminal_left_delta) = round_provider(round, raw, sensitivity)?;
            let is_final_left = round + 1 == left_rounds;
            if is_final_left != terminal_left_delta.is_some() {
                return Err(GkrWorkerError::ChallengeProvider);
            }
            let mut response = Vec::with_capacity(if is_final_left {
                2 * FP16_BYTES
            } else {
                FP16_BYTES
            });
            append_fp16(&mut response, challenge);
            if let Some(delta) = terminal_left_delta {
                append_fp16(&mut response, delta);
            }
            write_with_timeout(stdin, response, step_timeout)?;
            raw_rounds.push(raw);
        }
        let terminal = match receive(&self.frame_receiver, step_timeout)? {
            WorkerFrame::Terminal(bytes) => bytes,
            _ => return Err(GkrWorkerError::LibraTerminal),
        };
        self.sessions += 1;
        Ok((
            GkrLibraWorkerOutput {
                raw_rounds,
                terminal_left: decode_fp16(&terminal[..FP16_BYTES])?,
                terminal_right: decode_fp16(&terminal[FP16_BYTES..])?,
            },
            Some((polynomial, report)),
        ))
    }

    pub fn finish(mut self, timeout: Duration) -> Result<(), GkrWorkerError> {
        if self.sessions != self.session_limit {
            return Err(GkrWorkerError::Shape);
        }
        self.stdin.take();
        let _ = self.command_sender.send(ReaderCommand::Finish);
        let result = wait_child(&mut self.child, timeout);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        result
    }
}

impl Drop for BoundedGkrWorker {
    fn drop(&mut self) {
        self.stdin.take();
        let _ = self.command_sender.send(ReaderCommand::Finish);
        stop_child(&mut self.child);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

/// Run one or more sparse layers through one untrusted worker process.
///
/// `program` must be identity-pinned by the caller. Any error occurs before a
/// usable proof vector is returned, allowing the caller to restart the whole
/// job on the CPU or fail closed. Compilation and device setup are amortized
/// across at most 216 fixed-shape layer sessions.
pub fn run_bounded_gkr_worker_sessions(
    program: &Path,
    arguments: &[OsString],
    sessions: &[GkrWorkerSession<'_>],
    step_timeout: Duration,
) -> Result<Vec<MaskedSparseLayerSumcheckProof>, GkrWorkerError> {
    if sessions.is_empty() || sessions.len() > MAX_SESSIONS || step_timeout.is_zero() {
        return Err(GkrWorkerError::Shape);
    }
    let mut worker = BoundedGkrWorker::spawn(program, arguments, sessions.len(), step_timeout)?;
    let mut proofs = Vec::with_capacity(sessions.len());
    for session in sessions {
        proofs.push(worker.run_session(session, step_timeout)?);
    }
    worker.finish(step_timeout)?;
    Ok(proofs)
}

/// Single-session convenience wrapper.
#[allow(clippy::too_many_arguments)]
pub fn run_bounded_gkr_worker(
    program: &Path,
    arguments: &[OsString],
    request: &GkrWorkerRequest<'_>,
    initial_claim: Fp16,
    challenges: &[Fp16],
    masks: &[[Fp16; 2]],
    step_timeout: Duration,
) -> Result<MaskedSparseLayerSumcheckProof, GkrWorkerError> {
    let session = GkrWorkerSession {
        request: GkrWorkerRequest {
            input: request.input,
            terms: request.terms,
        },
        initial_claim,
        challenges,
        masks,
    };
    let mut proofs = run_bounded_gkr_worker_sessions(program, arguments, &[session], step_timeout)?;
    proofs.pop().ok_or(GkrWorkerError::Protocol)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    fn tiny_request() -> (Vec<Fp16>, Vec<SparseLayerGpuFixtureTerm>) {
        (
            vec![Fp16::ZERO, Fp16::ONE],
            vec![SparseLayerGpuFixtureTerm {
                output_weight: Fp16::ONE,
                left: 0,
                right: 1,
                formula: 0,
            }],
        )
    }

    #[test]
    fn worker_request_and_coordinate_bounds_fail_closed() {
        let (input, terms) = tiny_request();
        let request = GkrWorkerRequest {
            input: &input,
            terms: &terms,
        };
        assert_eq!(encode_request(&request, 2).unwrap().len(), 221);
        assert_eq!(encode_request(&request, 1), Err(GkrWorkerError::Shape));

        let mut noncanonical = [0_u8; FP16_BYTES];
        noncanonical[..4].copy_from_slice(&M31_MODULUS.to_le_bytes());
        assert_eq!(
            decode_fp16(&noncanonical),
            Err(GkrWorkerError::NonCanonical)
        );
    }

    #[test]
    fn pinned_cuda_bundle_identity_is_exact() {
        let cuda = Path::new(env!("CARGO_MANIFEST_DIR")).join("cuda");
        assert_eq!(
            verify_pinned_gkr_cuda_bundle(&cuda.join("cuda_gkr_interactive_worker.py")),
            Ok(())
        );
        assert_eq!(
            verify_pinned_gkr_cuda_bundle(&cuda.join("cuda_sparse_round_kat.py")),
            Err(GkrWorkerError::WorkerIdentity)
        );
    }

    #[cfg(windows)]
    #[test]
    fn malformed_and_stalled_workers_fail_closed() {
        let powershell = std::path::PathBuf::from(
            std::env::var_os("SystemRoot").expect("Windows has SystemRoot"),
        )
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
        let (input, terms) = tiny_request();
        let request = GkrWorkerRequest {
            input: &input,
            terms: &terms,
        };
        let challenges = [Fp16::ONE, Fp16::ONE];
        let masks = [[Fp16::ZERO; 2]; 2];
        let malformed = [
            OsString::from("-NoProfile"),
            OsString::from("-Command"),
            OsString::from(
                "$o=[Console]::OpenStandardOutput();$o.Write([byte[]](0,0,0,0,0,0,0,0))",
            ),
        ];
        assert_eq!(
            run_bounded_gkr_worker(
                &powershell,
                &malformed,
                &request,
                Fp16::ZERO,
                &challenges,
                &masks,
                // PowerShell startup can exceed two seconds when the complete
                // Rust suite saturates the host.  Give this case a startup
                // budget that isolates malformed framing from the separate
                // short-deadline timeout assertion below.
                Duration::from_secs(15),
            ),
            Err(GkrWorkerError::Protocol)
        );

        let stalled = [
            OsString::from("-NoProfile"),
            OsString::from("-Command"),
            OsString::from("Start-Sleep -Seconds 5"),
        ];
        assert_eq!(
            run_bounded_gkr_worker(
                &powershell,
                &stalled,
                &request,
                Fp16::ZERO,
                &challenges,
                &masks,
                Duration::from_millis(25),
            ),
            Err(GkrWorkerError::Timeout)
        );
    }
}
