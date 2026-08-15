use std::{
    cell::RefCell,
    env,
    fs::{File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Write},
    mem::size_of,
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::Arc,
    thread,
    time::Instant,
};

use bl_pq512_crypto_core::{
    chained_public_coin::{
        ChainedRoundDescriptor, decode_chained_public_coin_bundle,
        encode_chained_public_coin_bundle, verify_chained_public_coin_bundle,
    },
    chained_public_coin_client::ChainedPublicCoinCoordinator,
    field::Fp16,
    fp16_relay_free_gkr_schedule::{
        GKR_LAYERS, GKR_TRANSCRIPT_ROUNDS, H4_BOOLEANITY_PRELUDE_KIND, H4_BOOLEANITY_ROUNDS,
        H4_BOOLEANITY_SUMCHECK_KIND, H4_BOOLEANITY_TERMINAL_KIND, H4_BOOLEANITY_VARIABLES,
        H4_PADDING_PRELUDE_KIND, H4_PADDING_ROUNDS, H4_PADDING_SUMCHECK_KIND,
        H4_PADDING_TERMINAL_KIND, H4_PADDING_VARIABLES, STATE_COMPOSED_K128_ROUNDS,
        STATE_COMPOSED_K512_ROUNDS, STATE_RELATION_ROUNDS, SelectedGkrRoundKind,
        selected_booleanity_mask_layer, selected_padding_mask_layer,
        selected_state_composed_mask_layout, verify_selected_state_composed_public_coin_bundle,
    },
    fp16_relay_free_gkr_uniform::{
        UniformGkrMaskConstraint, UniformRelayFreeClaim, UniformRelayFreeGkrError,
        aggregate_gkr_mask_constraints, complete_uniform_gkr_mask_batch, gkr_mask_batch_message,
        prove_masked_nonuniform_trace, prove_masked_uniform_zero_trace,
        verify_masked_nonuniform_trace, verify_masked_uniform_zero_trace,
    },
    fp16_zk_rs_gkr_binding::GKR_CLAIM_COUNT,
    gkr_sumcheck::{
        LayerOutputClaim, MaskedSharedGroupOracle, SharedGroupDagRoundKind,
        prove_masked_shared_group_dag_layer_oracle_interactive,
    },
    gkr_zk_mask::{
        CommittedMaskedSumcheckState, GkrZkMaskError, LibraLayerMask, LibraPriorLayerCorrection,
        LibraVariableDegreeSumcheckMask, boolean_vanishing,
    },
    h4_differential_dump::{
        H4BufferAccess, write_h4_fp16_vector_dump, write_h4_path_dump, write_h4_u16_vector_dump,
    },
    h4_proof_package_v1::{
        H4_MASKED_SOURCE_FUNCTIONAL_BINDING_BYTES, H4_SOURCE_COEFFICIENT_POSITIONS,
        H4MaskedSourceFunctionalBinding, H4ProofProfile, VerifiedH4BooleanityAlgebraBoundary,
        VerifiedH4PaddingAlgebraBoundary, h4_booleanity_gate_layer, h4_booleanity_prelude_message,
        h4_booleanity_round_message, h4_booleanity_terminal_message,
        h4_booleanity_transcript_commitment, h4_padding_prelude_message, h4_padding_round_message,
        h4_padding_terminal_message, h4_padding_transcript_commitment,
        verify_h4_booleanity_algebra_boundary, verify_h4_padding_algebra_boundary,
    },
    h4_proof_package_v2::{
        H4ProofProfileV2, encode_h4_global_round_frame_v2, parse_h4_global_round_frame_v2,
    },
    hash_bus_b16_boundary::{HashBusB16BoundaryFile, HashBusB16Shard},
    hash_bus_b16_gkr_plan::HashBusB16GkrPlan,
    hash_bus_b16_gkr_worker::HashBusB16GkrWorker,
    state_relation_gkr::{
        PublicMaskedStateRelationGkrProof, STATE_RELATION_OUTPUT_CHALLENGE_COUNT,
        STATE_RELATION_TRANSCRIPT_DOMAIN, StateRelationGkrError, StateRelationRoundKind,
        masked_state_relation_constraints_unchecked,
        masked_state_relation_h4_input_claims_unchecked,
        prove_masked_state_relation_gkr_interactive, public_state_relation_transcript_digest,
        read_state_relation_wire_source, state_relation_output_message,
        state_relation_round_message, state_relation_rows_from_source,
        verify_masked_state_relation_gkr,
    },
    state_squarefree_gkr::{
        MaskedStateSquarefreeRoundKind, PublicMaskedStateSquarefreeGkrProof,
        STATE_SQUAREFREE_TRANSCRIPT_DOMAIN, StateSquarefreeCommittedLayerMask,
        StateSquarefreeGkrError, build_state_squarefree_witness,
        prove_masked_state_squarefree_composed, public_masked_state_squarefree_constraints,
        state_squarefree_authenticated_rounds, state_squarefree_beta_message,
        state_squarefree_layer_ordinal, state_squarefree_point_message,
        state_squarefree_round_message, verify_masked_state_squarefree_composed,
    },
    state_squarefree_pcs::{
        MASKED_STATE_SQUAREFREE_COEFFICIENT_CLAIMS, STATE_SQUAREFREE_COEFFICIENT_BLOCK,
        STATE_SQUAREFREE_COEFFICIENT_VARIABLES, STATE_SQUAREFREE_H4_CLAIMS,
        masked_state_squarefree_h4_input_claims_unchecked,
        masked_state_squarefree_public_pcs_coefficient_claims_unchecked,
    },
    strict_h4_interactive_coin::{FinishedStrictH4InteractiveCoin, StrictH4InteractiveCoin},
    strict_pq_public_coin_v2::StrictPqRoundDescriptorV2,
    wave1a_global_schedule::Profile,
};
use sha3::{Digest, Sha3_512};

const INPUT_MAGIC: &[u8; 8] = b"BLPCCN01";
const READY_MAGIC: &[u8; 8] = b"BLPCCRD1";
const ROUND_MAGIC: &[u8; 8] = b"BLPCCRQ1";
const RESPONSE_MAGIC: &[u8; 8] = b"BLPCCRS1";
const FINISH_MAGIC: &[u8; 8] = b"BLPCCFN1";
const GKR_READY_MAGIC: &[u8; 8] = b"BLPCCG01";
const SQUAREFREE_READY_MAGIC: &[u8; 8] = b"BLPCCB01";
const SQUAREFREE_BIND_MAGIC: &[u8; 8] = b"BLPCCB02";
const SQUAREFREE_WITNESS_MAGIC: &[u8; 8] = b"BLPCCW01";
const SQUAREFREE_COMMIT_MAGIC: &[u8; 8] = b"BLPCCC01";
const GKR_MASK_COEFFICIENTS: usize = 32_768;
const GKR_MASK_WORDS: usize = 64;
const GKR_MASK_WORD_VALUES: usize = 512;
const PCS_ROW_CHALLENGES: usize = 9;
const BASE_MASKS_PREFIX: &[u8] = b"BL/PQ512/FP16-ZK-RS/BASE-MASKS/v3";
const ANSWERS_PREFIX: &[u8] = b"BL/PQ512/FP16-ZK-RS/ANSWERS/v2";
const ANSWER_MAIN_BYTES: u64 = 67_584 * 64;
const ANSWER_ORDINARY_AUXILIARY_BYTES: u64 = 10 * 3_266 * 64;
const ANSWER_GKR_TENSOR_BYTES: u64 = 64 * 512 * 64;
const MAX_ROUNDS: u32 = 65_535;
const MAX_MESSAGE_LENGTH: usize = 1 << 20;
const STATE_RELATION_OUTPUT_KIND: u16 = 120;
const STATE_RELATION_GROUP_KIND: u16 = 121;
const STATE_RELATION_WIRE_KIND: u16 = 122;
const STATE_RELATION_TERMINAL_KIND: u16 = 123;
const STATE_SQUAREFREE_CLAIMS_DIGEST_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/STATE-SQUAREFREE-CLAIMS/v2\0";
const STATE_SQUAREFREE_BETA_KIND: u16 = 130;
const STATE_SQUAREFREE_POINT_KIND: u16 = 131;
const STATE_SQUAREFREE_MASKED_GROUP_KIND: u16 = 138;
const STATE_SQUAREFREE_MASKED_LEFT_KIND: u16 = 139;
const STATE_SQUAREFREE_MASKED_RIGHT_KIND: u16 = 140;
const STATE_SQUAREFREE_MASKED_TERMINAL_KIND: u16 = 141;
const STATE_SQUAREFREE_MASKED_MIX_KIND: u16 = 142;
const STATE_COMPOSED_MASK_BATCH_KIND: u16 = 143;
const PHASE_TELEMETRY_ENV: &str = "BL_BRIDGE_PHASE_TELEMETRY_PATH";

struct PhaseTelemetry {
    started: Instant,
    previous: Instant,
    writer: BufWriter<File>,
}

impl PhaseTelemetry {
    fn from_environment() -> Result<Option<Self>, String> {
        let Some(path) = env::var_os(PHASE_TELEMETRY_ENV) else {
            return Ok(None);
        };
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err("phase_telemetry_path_not_absolute".to_string());
        }
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
            .map_err(|error| format!("phase_telemetry_open:{}:{error}", path.display()))?;
        let now = Instant::now();
        let mut telemetry = Self {
            started: now,
            previous: now,
            writer: BufWriter::new(file),
        };
        telemetry.mark("process_start")?;
        Ok(Some(telemetry))
    }

    fn mark(&mut self, phase: &str) -> Result<(), String> {
        let now = Instant::now();
        writeln!(
            self.writer,
            "phase={phase} total_seconds={:.6} delta_seconds={:.6}",
            now.duration_since(self.started).as_secs_f64(),
            now.duration_since(self.previous).as_secs_f64(),
        )
        .and_then(|_| self.writer.flush())
        .map_err(|error| format!("phase_telemetry_write:{error}"))?;
        self.previous = now;
        Ok(())
    }

    fn metric(&mut self, name: &str, seconds: f64) -> Result<(), String> {
        writeln!(self.writer, "metric={name} seconds={seconds:.6}")
            .and_then(|_| self.writer.flush())
            .map_err(|error| format!("phase_telemetry_write:{error}"))
    }
}

fn mark_phase(telemetry: &mut Option<PhaseTelemetry>, phase: &str) -> Result<(), String> {
    if let Some(telemetry) = telemetry {
        telemetry.mark(phase)?;
    }
    Ok(())
}
const H4_BOOLEANITY_COMPONENT_VARIABLES: usize = 4;
const H4_BOOLEANITY_COEFFICIENT_VARIABLES: usize = 16;
const H4_BOOLEANITY_WORD_VARIABLES: usize = 9;
const H4_BOOLEANITY_SOURCE_VALUES_AFTER_COMPONENT_FOLD: usize =
    1 << (H4_BOOLEANITY_COEFFICIENT_VARIABLES + H4_BOOLEANITY_WORD_VARIABLES);
const H4_BOOLEANITY_MAX_FOLDED_TABLE_BYTES: usize = 1 << 31;
const H4_CUDA_READY: &[u8; 8] = b"BLH4CW01";
const H4_CUDA_INIT: &[u8; 8] = b"BLH4CI01";
const H4_CUDA_INIT_OK: &[u8; 8] = b"BLH4CK01";
const H4_CUDA_RAW: &[u8; 8] = b"BLH4CR01";
const H4_CUDA_RAW_OK: &[u8; 8] = b"BLH4CO01";
const H4_CUDA_ACCEPT: &[u8; 8] = b"BLH4CA01";
const H4_CUDA_ACCEPT_OK: &[u8; 8] = b"BLH4CY01";
const H4_CUDA_FOLDED: &[u8; 8] = b"BLH4CF01";
const H4_CUDA_FOLDED_OK: &[u8; 8] = b"BLH4CV01";
const H4_CUDA_FINISH: &[u8; 8] = b"BLH4CX01";
const H4_CUDA_FINISHED: &[u8; 8] = b"BLH4CZ01";

const STRICT_FINISH_MAGIC: &[u8; 8] = b"BLPCF2S1";
const STRICT_FINISH_FULL_FRAMES_MAGIC: &[u8; 8] = b"BLPCF2S2";

struct FinishedBridgeCoin {
    encoded_bundle: Vec<u8>,
    governed_key: Option<Vec<u8>>,
    raw_frames: Option<Vec<u8>>,
    replayed: Option<Vec<Vec<Fp16>>>,
}

trait BridgeCoin {
    fn challenge(
        &mut self,
        descriptor: ChainedRoundDescriptor,
        message: &[u8],
    ) -> Result<Vec<Fp16>, String>;

    fn finish(self: Box<Self>) -> Result<FinishedBridgeCoin, String>;
}

struct LegacyBridgeCoin {
    coordinator: Option<ChainedPublicCoinCoordinator>,
    round_count: u32,
}

impl BridgeCoin for LegacyBridgeCoin {
    fn challenge(
        &mut self,
        descriptor: ChainedRoundDescriptor,
        message: &[u8],
    ) -> Result<Vec<Fp16>, String> {
        self.coordinator
            .as_mut()
            .ok_or_else(|| "legacy_coin_finished".to_owned())?
            .challenge(descriptor, message)
            .map_err(|error| format!("{error:?}"))
    }

    fn finish(mut self: Box<Self>) -> Result<FinishedBridgeCoin, String> {
        let coordinator = self
            .coordinator
            .take()
            .ok_or_else(|| "legacy_coin_finished".to_owned())?;
        let bundle = coordinator
            .finish_bundle()
            .map_err(|error| format!("finish:{error:?}"))?;
        let encoded = encode_chained_public_coin_bundle(&bundle)
            .map_err(|error| format!("encode:{error:?}"))?;
        let decoded = decode_chained_public_coin_bundle(&encoded)
            .map_err(|error| format!("decode:{error:?}"))?;
        let replayed = match self.round_count {
            STATE_COMPOSED_K128_ROUNDS => {
                verify_selected_state_composed_public_coin_bundle(&decoded, 128)
                    .map_err(|error| format!("verify_selected_schedule:{error:?}"))?
            }
            STATE_COMPOSED_K512_ROUNDS => {
                verify_selected_state_composed_public_coin_bundle(&decoded, 512)
                    .map_err(|error| format!("verify_selected_schedule:{error:?}"))?
            }
            _ => verify_chained_public_coin_bundle(&decoded)
                .map_err(|error| format!("verify:{error:?}"))?,
        };
        Ok(FinishedBridgeCoin {
            encoded_bundle: encoded,
            governed_key: None,
            raw_frames: None,
            replayed: Some(
                replayed
                    .into_iter()
                    .map(|challenge| challenge.field_elements)
                    .collect(),
            ),
        })
    }
}

struct StrictBridgeCoin {
    coordinator: Option<StrictH4InteractiveCoin>,
    profile: H4ProofProfileV2,
}

impl BridgeCoin for StrictBridgeCoin {
    fn challenge(
        &mut self,
        descriptor: ChainedRoundDescriptor,
        message: &[u8],
    ) -> Result<Vec<Fp16>, String> {
        let strict_message = if message.starts_with(b"BLH4GR02") {
            let expected = StrictPqRoundDescriptorV2::new(
                descriptor.kind,
                descriptor.ordinal,
                descriptor.output_count,
            )
            .map_err(|error| format!("strict_descriptor:{error:?}"))?;
            parse_h4_global_round_frame_v2(message, self.profile, expected)
                .map_err(|error| format!("strict_global_frame:{error:?}"))?;
            message.to_vec()
        } else {
            let expected = StrictPqRoundDescriptorV2::new(
                descriptor.kind,
                descriptor.ordinal,
                descriptor.output_count,
            )
            .map_err(|error| format!("strict_descriptor:{error:?}"))?;
            encode_h4_global_round_frame_v2(self.profile, expected, &[message])
                .map_err(|error| format!("strict_global_frame_encode:{error:?}"))?
        };
        self.coordinator
            .as_mut()
            .ok_or_else(|| "strict_coin_finished".to_owned())?
            .challenge(descriptor, &strict_message)
            .map_err(|error| format!("{error:?}"))
    }

    fn finish(mut self: Box<Self>) -> Result<FinishedBridgeCoin, String> {
        let finished: FinishedStrictH4InteractiveCoin = self
            .coordinator
            .take()
            .ok_or_else(|| "strict_coin_finished".to_owned())?
            .finish()
            .map_err(|error| format!("finish:{error:?}"))?;
        let mut raw_frames = Vec::new();
        for frame in &finished.raw_messages {
            raw_frames.extend_from_slice(
                &u32::try_from(frame.len())
                    .map_err(|_| "strict_raw_frame_length".to_owned())?
                    .to_be_bytes(),
            );
            raw_frames.extend_from_slice(frame);
        }
        Ok(FinishedBridgeCoin {
            encoded_bundle: finished.encoded_bundle,
            governed_key: Some(finished.governed_key),
            raw_frames: Some(raw_frames),
            replayed: None,
        })
    }
}

fn strict_profile_for_rounds(round_count: u32) -> Result<H4ProofProfileV2, String> {
    match round_count {
        STATE_COMPOSED_K128_ROUNDS => Ok(H4ProofProfileV2::K128),
        STATE_COMPOSED_K512_ROUNDS => Ok(H4ProofProfileV2::K512),
        _ => Err("strict_profile_round_count".to_owned()),
    }
}

struct GkrPcsContext {
    commitment: [u8; 64],
    opening: Fp16,
    claim_challenge: Fp16,
    coefficient_weights: Vec<Fp16>,
    row_challenges: Vec<Fp16>,
    squarefree_claims_payload: Vec<u8>,
    squarefree_coefficient_root: [u8; 64],
}

struct SquarefreePrelude {
    claims: Vec<UniformRelayFreeClaim>,
    coefficient_claims: Vec<bl_pq512_crypto_core::multilinear_pcs::MultilinearOpeningClaim>,
    public_coefficient_claims: Vec<bl_pq512_crypto_core::multilinear_pcs::MultilinearOpeningClaim>,
    coefficient_root: [u8; 64],
    transcript_digest: [u8; 64],
    mask_constraints: Vec<UniformGkrMaskConstraint>,
    source_root: [u8; 64],
}

enum GkrPrelude {
    None,
    Uniform,
    Nonuniform {
        boundary: PathBuf,
        shard: u16,
        python: PathBuf,
        worker: PathBuf,
        eager: bool,
        state_source: Option<(PathBuf, [u8; 64])>,
    },
}

struct SplitEqualityWeights {
    low: Vec<Fp16>,
    high: Vec<Fp16>,
    low_mask: usize,
    low_variables: usize,
}

impl SplitEqualityWeights {
    fn new(point: &[Fp16]) -> Result<Self, GkrZkMaskError> {
        let low_variables = point.len() / 2;
        let low = equality_weights(&point[..low_variables])?;
        let high = equality_weights(&point[low_variables..])?;
        let low_mask = low.len().checked_sub(1).ok_or(GkrZkMaskError::Shape)?;
        Ok(Self {
            low,
            high,
            low_mask,
            low_variables,
        })
    }

    fn at(&self, index: usize) -> Result<Fp16, GkrZkMaskError> {
        let low = index & self.low_mask;
        let high = index >> self.low_variables;
        Ok(*self.low.get(low).ok_or(GkrZkMaskError::Shape)?
            * *self.high.get(high).ok_or(GkrZkMaskError::Shape)?)
    }
}

fn equality_weights(point: &[Fp16]) -> Result<Vec<Fp16>, GkrZkMaskError> {
    if point.len() >= usize::BITS as usize {
        return Err(GkrZkMaskError::Overflow);
    }
    let count = 1_usize
        .checked_shl(u32::try_from(point.len()).map_err(|_| GkrZkMaskError::Overflow)?)
        .ok_or(GkrZkMaskError::Overflow)?;
    // The selected GKR table convention is LSB-first: the first challenge
    // folds adjacent entries, and therefore occupies table bit zero.  Keep
    // this identical to h4_proof_package_v1::multilinear_weights; reversing
    // the coordinates preserves shape but breaks the authenticated claim
    // recurrence after the first fold.
    let mut weights = Vec::with_capacity(count);
    for word in 0..count {
        let mut weight = Fp16::ONE;
        for (bit, coordinate) in point.iter().copied().enumerate() {
            weight = weight
                * if word & (1_usize << bit) == 0 {
                    Fp16::ONE - coordinate
                } else {
                    coordinate
                };
        }
        weights.push(weight);
    }
    Ok(weights)
}

fn equality_line(coordinate: Fp16, point: Fp16) -> Fp16 {
    (Fp16::ONE - coordinate) * (Fp16::ONE - point) + coordinate * point
}

fn add_booleanity_line(
    destination: &mut [Fp16; 4],
    left: Fp16,
    right: Fp16,
    equality_coordinate: Fp16,
    scale: Fp16,
) {
    let delta = right - left;
    let product_0 = left * (left - Fp16::ONE);
    let product_1 = delta * (left + left - Fp16::ONE);
    let product_2 = delta * delta;
    let equality_0 = Fp16::ONE - equality_coordinate;
    let equality_1 = equality_coordinate + equality_coordinate - Fp16::ONE;
    destination[0] = destination[0] + scale * equality_0 * product_0;
    destination[1] = destination[1] + scale * (equality_0 * product_1 + equality_1 * product_0);
    destination[2] = destination[2] + scale * (equality_0 * product_2 + equality_1 * product_1);
    destination[3] = destination[3] + scale * equality_1 * product_2;
}

fn fold_component_pattern(pattern: u16, prefix: &[Fp16]) -> ([Fp16; 16], usize) {
    let mut values = core::array::from_fn(|component| {
        if pattern & (1_u16 << component) == 0 {
            Fp16::ZERO
        } else {
            Fp16::ONE
        }
    });
    let mut active = values.len();
    for challenge in prefix {
        for index in 0..active / 2 {
            let left = values[2 * index];
            values[index] = left + (values[2 * index + 1] - left) * *challenge;
        }
        active /= 2;
    }
    (values, active)
}

fn bounded_workers(items: usize) -> usize {
    thread::available_parallelism()
        .map_or(1, |value| value.get())
        .min(16)
        .min(items.max(1))
}

fn parallel_fold_table(values: &[Fp16], challenge: Fp16) -> Vec<Fp16> {
    assert!(values.len() >= 2 && values.len().is_power_of_two());
    let pairs = values.len() / 2;
    let workers = bounded_workers(pairs);
    let chunk_pairs = pairs.div_ceil(workers);
    let mut output = vec![Fp16::ZERO; pairs];
    thread::scope(|scope| {
        for (chunk_index, destination) in output.chunks_mut(chunk_pairs).enumerate() {
            let pair_start = chunk_index * chunk_pairs;
            scope.spawn(move || {
                for (local, value) in destination.iter_mut().enumerate() {
                    let source = 2 * (pair_start + local);
                    let left = values[source];
                    *value = left + (values[source + 1] - left) * challenge;
                }
            });
        }
    });
    output
}

/// Reconstruct the packed 16-coordinate source value at the canonical GPU
/// position. This is diagnostic-only and lets the differential compare the
/// same representation on both paths.
fn packed_pattern_value(pattern: u16) -> Fp16 {
    let mut coefficients = [0_u32; 16];
    for (coordinate, coefficient) in coefficients.iter_mut().enumerate() {
        *coefficient = u32::from((pattern >> coordinate) & 1);
    }
    Fp16::from_coefficients(coefficients).expect("packed pattern coefficients are canonical")
}

struct H4BooleanitySourceOracle {
    shard: HashBusB16Shard,
    equality_point: [Fp16; H4_BOOLEANITY_VARIABLES as usize],
    pattern_histogram: Vec<Fp16>,
    diagnostic_source_coefficients: Option<Vec<Fp16>>,
    diagnostic_source_vector: Option<Vec<Fp16>>,
    accepted_challenges: Vec<Fp16>,
    prefix_equality: Fp16,
    folded: Vec<Fp16>,
    active: usize,
    pending_round: Option<usize>,
    raw_round_seconds: Vec<f64>,
    accept_round_seconds: Vec<f64>,
    cuda: Option<H4BooleanityCudaWorker>,
    cuda_config: Option<(PathBuf, PathBuf, PathBuf, u16)>,
    final_folded_value: Option<Fp16>,
}

struct H4BooleanityCudaWorker {
    child: Child,
    writer: BufWriter<ChildStdin>,
    reader: BufReader<ChildStdout>,
}

impl H4BooleanityCudaWorker {
    fn spawn(
        python: &Path,
        worker: &Path,
        boundary: &Path,
        shard: u16,
        equality_point: &[Fp16; H4_BOOLEANITY_VARIABLES as usize],
        component_point: &[Fp16],
    ) -> Result<Self, GkrZkMaskError> {
        if !python.is_file()
            || !worker.is_file()
            || !boundary.is_file()
            || component_point.len() != 4
        {
            return Err(GkrZkMaskError::Shape);
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
            .map_err(|_| GkrZkMaskError::Shape)?;
        let writer =
            BufWriter::with_capacity(1 << 20, child.stdin.take().ok_or(GkrZkMaskError::Shape)?);
        let reader =
            BufReader::with_capacity(1 << 20, child.stdout.take().ok_or(GkrZkMaskError::Shape)?);
        let mut result = Self {
            child,
            writer,
            reader,
        };
        result.expect(H4_CUDA_READY)?;
        result.write(H4_CUDA_INIT)?;
        for coordinate in equality_point {
            result.write_field(*coordinate)?;
        }
        for challenge in component_point {
            result.write_field(*challenge)?;
        }
        result.flush()?;
        result.expect(H4_CUDA_INIT_OK)?;
        Ok(result)
    }

    fn write(&mut self, magic: &[u8; 8]) -> Result<(), GkrZkMaskError> {
        self.writer
            .write_all(magic)
            .map_err(|_| GkrZkMaskError::Sequence)
    }
    fn expect(&mut self, expected: &[u8; 8]) -> Result<(), GkrZkMaskError> {
        let mut actual = [0_u8; 8];
        self.reader
            .read_exact(&mut actual)
            .map_err(|_| GkrZkMaskError::Sequence)?;
        if &actual != expected {
            return Err(GkrZkMaskError::Sequence);
        }
        Ok(())
    }
    fn write_field(&mut self, value: Fp16) -> Result<(), GkrZkMaskError> {
        self.writer
            .write_all(&value.encode())
            .map_err(|_| GkrZkMaskError::Sequence)
    }
    fn read_field(&mut self) -> Result<Fp16, GkrZkMaskError> {
        let mut encoded = [0_u8; 64];
        self.reader
            .read_exact(&mut encoded)
            .map_err(|_| GkrZkMaskError::Sequence)?;
        Fp16::decode(&encoded).map_err(|_| GkrZkMaskError::Sequence)
    }
    fn flush(&mut self) -> Result<(), GkrZkMaskError> {
        self.writer.flush().map_err(|_| GkrZkMaskError::Sequence)
    }
    fn raw_round(
        &mut self,
        round: usize,
        equality: Fp16,
        prefix: Fp16,
    ) -> Result<[Fp16; 4], GkrZkMaskError> {
        self.write(H4_CUDA_RAW)?;
        self.writer
            .write_all(&[u8::try_from(round).map_err(|_| GkrZkMaskError::Shape)?])
            .map_err(|_| GkrZkMaskError::Sequence)?;
        self.write_field(equality)?;
        self.write_field(prefix)?;
        self.flush()?;
        self.expect(H4_CUDA_RAW_OK)?;
        let mut result = [Fp16::ZERO; 4];
        for value in &mut result {
            *value = self.read_field()?;
        }
        Ok(result)
    }
    fn accept(&mut self, round: usize, challenge: Fp16) -> Result<(), GkrZkMaskError> {
        self.write(H4_CUDA_ACCEPT)?;
        self.writer
            .write_all(&[u8::try_from(round).map_err(|_| GkrZkMaskError::Shape)?])
            .map_err(|_| GkrZkMaskError::Sequence)?;
        self.write_field(challenge)?;
        self.flush()?;
        self.expect(H4_CUDA_ACCEPT_OK)
    }
    fn folded(&mut self) -> Result<Fp16, GkrZkMaskError> {
        self.write(H4_CUDA_FOLDED)?;
        self.flush()?;
        self.expect(H4_CUDA_FOLDED_OK)?;
        self.read_field()
    }
    fn finish(mut self) -> Result<(), GkrZkMaskError> {
        self.write(H4_CUDA_FINISH)?;
        self.flush()?;
        self.expect(H4_CUDA_FINISHED)?;
        if !self
            .child
            .wait()
            .map_err(|_| GkrZkMaskError::Sequence)?
            .success()
        {
            return Err(GkrZkMaskError::Sequence);
        }
        Ok(())
    }
}

impl Drop for H4BooleanityCudaWorker {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

struct H4NativeDifferential {
    equality_point: Vec<Fp16>,
    booleanity_group_point: Vec<Fp16>,
    padding_sumcheck_point: Vec<Fp16>,
    source_coefficients: Vec<Fp16>,
    pattern_histogram: Vec<Fp16>,
    folded_source: Fp16,
    folded_source_minus_one: Fp16,
}

impl H4NativeDifferential {
    fn write_differential_dump(&self, row_challenges: &[Fp16]) -> Result<(), String> {
        let coefficient_weights = equality_weights(
            &self.equality_point[H4_BOOLEANITY_COMPONENT_VARIABLES
                ..H4_BOOLEANITY_COMPONENT_VARIABLES + H4_BOOLEANITY_COEFFICIENT_VARIABLES],
        )
        .map_err(|error| format!("native_coefficient_weights:{error:?}"))?;
        let word_weights = equality_weights(
            &self.equality_point
                [H4_BOOLEANITY_COMPONENT_VARIABLES + H4_BOOLEANITY_COEFFICIENT_VARIABLES..],
        )
        .map_err(|error| format!("native_word_weights:{error:?}"))?;
        if self.equality_point.len() != H4_BOOLEANITY_VARIABLES as usize
            || self.booleanity_group_point.len() != H4_BOOLEANITY_VARIABLES as usize
            || self.padding_sumcheck_point.len() != H4_PADDING_VARIABLES as usize
            || row_challenges.len() != PCS_ROW_CHALLENGES
        {
            return Err("native_differential_point_shape".to_string());
        }
        write_h4_fp16_vector_dump(
            "h4-native-source-coefficients.bin",
            "h4_hash_source_evaluation_vector",
            &self.source_coefficients,
        )?;
        write_h4_fp16_vector_dump(
            "h4-native-pattern-histogram.bin",
            "h4_pattern_histogram",
            &self.pattern_histogram,
        )?;
        write_h4_path_dump(
            "h4-native-path.txt",
            "native-source",
            &[
                ("equality_point", &self.equality_point),
                ("booleanity_group_point", &self.booleanity_group_point),
                ("padding_sumcheck_point", &self.padding_sumcheck_point),
                ("row_challenges", row_challenges),
            ],
            &[
                (
                    "h4_hash_source_evaluation_vector",
                    &self.source_coefficients,
                ),
                ("h4_pattern_histogram", &self.pattern_histogram),
            ],
            &[
                H4BufferAccess {
                    label: "input_patterns",
                    base_offset_bytes: 0,
                    element_stride_bytes: 2,
                    element_count: 1_600 * 8_192,
                    index_formula: "wire * 8192 + group",
                },
                H4BufferAccess {
                    label: "output_patterns",
                    base_offset_bytes: 0,
                    element_stride_bytes: 2,
                    element_count: 1_600 * 8_192,
                    index_formula: "wire * 8192 + group",
                },
                H4BufferAccess {
                    label: "coefficient_weights",
                    base_offset_bytes: 0,
                    element_stride_bytes: 64,
                    element_count: coefficient_weights.len() as u64,
                    index_formula: "group_low * 2048 + wire",
                },
                H4BufferAccess {
                    label: "word_weights",
                    base_offset_bytes: 0,
                    element_stride_bytes: 64,
                    element_count: word_weights.len() as u64,
                    index_formula: "global_word",
                },
                H4BufferAccess {
                    label: "h4_hash_source_evaluation_vector",
                    base_offset_bytes: 0,
                    element_stride_bytes: 64,
                    element_count: self.source_coefficients.len() as u64,
                    index_formula: "canonical_position = group_low * 2048 + wire; hash wires only",
                },
                H4BufferAccess {
                    label: "h4_pattern_histogram",
                    base_offset_bytes: 0,
                    element_stride_bytes: 64,
                    element_count: self.pattern_histogram.len() as u64,
                    index_formula: "pattern_histogram[pattern]",
                },
            ],
            &[
                ("folded_source", self.folded_source),
                ("folded_source_minus_one", self.folded_source_minus_one),
            ],
        )
    }
}

impl H4BooleanitySourceOracle {
    fn new(
        shard: HashBusB16Shard,
        equality_point: [Fp16; H4_BOOLEANITY_VARIABLES as usize],
        shard_index: u8,
    ) -> Result<Self, GkrZkMaskError> {
        let boundary_values = 1_600_usize
            .checked_mul(8_192)
            .ok_or(GkrZkMaskError::Overflow)?;
        if shard.input.len() != boundary_values || shard.output.len() != boundary_values {
            return Err(GkrZkMaskError::Shape);
        }
        let coefficient_weights = equality_weights(
            &equality_point[H4_BOOLEANITY_COMPONENT_VARIABLES
                ..H4_BOOLEANITY_COMPONENT_VARIABLES + H4_BOOLEANITY_COEFFICIENT_VARIABLES],
        )?;
        let word_weights = equality_weights(
            &equality_point
                [H4_BOOLEANITY_COMPONENT_VARIABLES + H4_BOOLEANITY_COEFFICIENT_VARIABLES..],
        )?;
        if coefficient_weights.len() != 1 << H4_BOOLEANITY_COEFFICIENT_VARIABLES
            || word_weights.len() != 1 << H4_BOOLEANITY_WORD_VARIABLES
        {
            return Err(GkrZkMaskError::Shape);
        }
        let mut pattern_histogram = vec![Fp16::ZERO; 1 << 16];
        for (global_word, word_weight) in word_weights.iter().copied().enumerate() {
            let boundary = global_word >> 8;
            let group_high = global_word & 0xff;
            let patterns = if boundary == 0 {
                &shard.input
            } else {
                &shard.output
            };
            for group_low in 0..32_usize {
                let group = (group_high << 5) | group_low;
                let position_base = group_low << 11;
                for wire in 0..1_600_usize {
                    let pattern = patterns[wire * 8_192 + group];
                    if pattern != 0 {
                        pattern_histogram[usize::from(pattern)] = pattern_histogram
                            [usize::from(pattern)]
                            + coefficient_weights[position_base | wire] * word_weight;
                    }
                }
            }
        }
        let diagnostic_source_coefficients = env::var_os("BL_CURRENT_H4_CAPTURE_DIR")
            .is_some()
            .then(|| pattern_histogram.clone());
        let diagnostic_source_vector = if env::var_os("BL_CURRENT_H4_CAPTURE_DIR").is_some() {
            let packed_patterns = (0..(1_u32 << 16))
                .map(|pattern| packed_pattern_value(pattern as u16))
                .collect::<Vec<_>>();
            let mut source_vector = vec![Fp16::ZERO; H4_SOURCE_COEFFICIENT_POSITIONS];
            for (global_word, word_weight) in word_weights.iter().copied().enumerate() {
                let boundary = global_word >> 8;
                let group_high = global_word & 0xff;
                let patterns = if boundary == 0 {
                    &shard.input
                } else {
                    &shard.output
                };
                for group_low in 0..32_usize {
                    let group = (group_high << 5) | group_low;
                    let position_base = group_low << 11;
                    for wire in 0..1_600_usize {
                        let pattern = patterns[wire * 8_192 + group];
                        let position = position_base | wire;
                        source_vector[position] = source_vector[position]
                            + packed_patterns[usize::from(pattern)] * word_weight;
                    }
                }
            }
            Some(source_vector)
        } else {
            None
        };
        if env::var_os("BL_CURRENT_H4_CAPTURE_DIR").is_some() {
            let input_name = format!("h4-native-input-patterns-shard-{shard_index:02}.bin");
            write_h4_u16_vector_dump(&input_name, "h4_input_patterns", &shard.input)
                .map_err(|_| GkrZkMaskError::Shape)?;
            let output_name = format!("h4-native-output-patterns-shard-{shard_index:02}.bin");
            write_h4_u16_vector_dump(&output_name, "h4_output_patterns", &shard.output)
                .map_err(|_| GkrZkMaskError::Shape)?;
        }
        Ok(Self {
            shard,
            equality_point,
            pattern_histogram,
            diagnostic_source_coefficients,
            diagnostic_source_vector,
            accepted_challenges: Vec::with_capacity(H4_BOOLEANITY_VARIABLES as usize),
            prefix_equality: Fp16::ONE,
            folded: Vec::new(),
            active: 0,
            pending_round: None,
            raw_round_seconds: Vec::with_capacity(H4_BOOLEANITY_VARIABLES as usize),
            accept_round_seconds: Vec::with_capacity(H4_BOOLEANITY_VARIABLES as usize),
            cuda: None,
            cuda_config: None,
            final_folded_value: None,
        })
    }

    fn configure_cuda(
        &mut self,
        python: &Path,
        worker: &Path,
        boundary: &Path,
        shard: u16,
    ) -> Result<(), GkrZkMaskError> {
        if self.cuda.is_some() || self.cuda_config.is_some() || !self.accepted_challenges.is_empty()
        {
            return Err(GkrZkMaskError::Sequence);
        }
        if !python.is_file() || !worker.is_file() || !boundary.is_file() {
            return Err(GkrZkMaskError::Shape);
        }
        self.cuda_config = Some((
            python.to_path_buf(),
            worker.to_path_buf(),
            boundary.to_path_buf(),
            shard,
        ));
        Ok(())
    }

    fn write_final_differential_dump(
        &self,
        folded_sources: (&[Fp16], &[Fp16]),
    ) -> Result<(), String> {
        let left = folded_sources
            .0
            .first()
            .copied()
            .ok_or_else(|| "native_folded_source_left".to_string())?;
        let right = folded_sources
            .1
            .first()
            .copied()
            .ok_or_else(|| "native_folded_source_right".to_string())?;
        write_h4_path_dump(
            "h4-native-final.txt",
            "native-source-final",
            &[
                ("equality_point", &self.equality_point),
                ("accepted_challenges", &self.accepted_challenges),
            ],
            &[],
            &[
                H4BufferAccess {
                    label: "input_patterns",
                    base_offset_bytes: 0,
                    element_stride_bytes: 2,
                    element_count: self.shard.input.len() as u64,
                    index_formula: "wire * 8192 + group",
                },
                H4BufferAccess {
                    label: "output_patterns",
                    base_offset_bytes: 0,
                    element_stride_bytes: 2,
                    element_count: self.shard.output.len() as u64,
                    index_formula: "wire * 8192 + group",
                },
            ],
            &[("folded_source", left), ("folded_source_minus_one", right)],
        )
    }

    fn component_round(&self, round: usize) -> Result<[Fp16; 4], GkrZkMaskError> {
        if round >= H4_BOOLEANITY_COMPONENT_VARIABLES || self.accepted_challenges.len() != round {
            return Err(GkrZkMaskError::Sequence);
        }
        let future_weights =
            equality_weights(&self.equality_point[round + 1..H4_BOOLEANITY_COMPONENT_VARIABLES])?;
        let mut result = [Fp16::ZERO; 4];
        for (pattern, histogram_weight) in self.pattern_histogram.iter().copied().enumerate() {
            if histogram_weight.is_zero() {
                continue;
            }
            let (values, active) =
                fold_component_pattern(pattern as u16, &self.accepted_challenges);
            if active / 2 != future_weights.len() {
                return Err(GkrZkMaskError::Shape);
            }
            let mut local = [Fp16::ZERO; 4];
            for suffix in 0..active / 2 {
                add_booleanity_line(
                    &mut local,
                    values[2 * suffix],
                    values[2 * suffix + 1],
                    self.equality_point[round],
                    future_weights[suffix],
                );
            }
            let scale = self.prefix_equality * histogram_weight;
            for degree in 0..4 {
                result[degree] = result[degree] + scale * local[degree];
            }
        }
        Ok(result)
    }

    fn folded_round(&self, round: usize) -> Result<[Fp16; 4], GkrZkMaskError> {
        if round < H4_BOOLEANITY_COMPONENT_VARIABLES
            || self.accepted_challenges.len() != round
            || self.active < 2
            || self.folded.len() < self.active
        {
            return Err(GkrZkMaskError::Sequence);
        }
        let future = SplitEqualityWeights::new(&self.equality_point[round + 1..])?;
        let pairs = self.active / 2;
        let workers = bounded_workers(pairs);
        let chunk_pairs = pairs.div_ceil(workers);
        let partials = thread::scope(|scope| {
            (0..workers)
                .map(|worker| {
                    let start = worker * chunk_pairs;
                    let end = pairs.min(start + chunk_pairs);
                    let folded = &self.folded;
                    let future = &future;
                    scope.spawn(move || -> Result<[Fp16; 4], GkrZkMaskError> {
                        let mut partial = [Fp16::ZERO; 4];
                        for suffix in start..end {
                            add_booleanity_line(
                                &mut partial,
                                folded[2 * suffix],
                                folded[2 * suffix + 1],
                                self.equality_point[round],
                                self.prefix_equality * future.at(suffix)?,
                            );
                        }
                        Ok(partial)
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|handle| handle.join().map_err(|_| GkrZkMaskError::Shape)?)
                .collect::<Result<Vec<_>, _>>()
        })?;
        let mut result = [Fp16::ZERO; 4];
        for partial in partials {
            for degree in 0..4 {
                result[degree] = result[degree] + partial[degree];
            }
        }
        Ok(result)
    }

    fn initialize_folded_source(&mut self) -> Result<(), GkrZkMaskError> {
        if self.accepted_challenges.len() != H4_BOOLEANITY_COMPONENT_VARIABLES {
            return Err(GkrZkMaskError::Sequence);
        }
        let words = 1_usize << H4_BOOLEANITY_WORD_VARIABLES;
        let values = H4_SOURCE_COEFFICIENT_POSITIONS
            .checked_mul(words)
            .ok_or(GkrZkMaskError::Overflow)?;
        let bytes = values
            .checked_mul(size_of::<Fp16>())
            .ok_or(GkrZkMaskError::Overflow)?;
        if bytes > H4_BOOLEANITY_MAX_FOLDED_TABLE_BYTES {
            return Err(GkrZkMaskError::Overflow);
        }
        let mut pattern_evaluations = vec![Fp16::ZERO; 1 << 16];
        for (pattern, evaluation) in pattern_evaluations.iter_mut().enumerate() {
            let (values, active) =
                fold_component_pattern(pattern as u16, &self.accepted_challenges);
            if active != 1 {
                return Err(GkrZkMaskError::Shape);
            }
            *evaluation = values[0];
        }
        self.folded
            .try_reserve_exact(values)
            .map_err(|_| GkrZkMaskError::Overflow)?;
        self.folded.resize(values, Fp16::ZERO);
        let workers = bounded_workers(words);
        let words_per_worker = words.div_ceil(workers);
        let values_per_word = H4_SOURCE_COEFFICIENT_POSITIONS;
        thread::scope(|scope| {
            for (chunk_index, destination) in self
                .folded
                .chunks_mut(words_per_worker * values_per_word)
                .enumerate()
            {
                let global_word_start = chunk_index * words_per_worker;
                let input = &self.shard.input;
                let output = &self.shard.output;
                let evaluations = &pattern_evaluations;
                scope.spawn(move || {
                    for (local_word, word) in destination.chunks_mut(values_per_word).enumerate() {
                        let group_high = global_word_start + local_word;
                        let boundary = group_high >> 8;
                        let group_high = group_high & 0xff;
                        let patterns = if boundary == 0 { input } else { output };
                        for group_low in 0..32_usize {
                            let group = (group_high << 5) | group_low;
                            let position_base = group_low << 11;
                            for wire in 0..1_600_usize {
                                let pattern = patterns[wire * 8_192 + group];
                                word[position_base | wire] = evaluations[usize::from(pattern)];
                            }
                        }
                    }
                });
            }
        });
        self.active = self.folded.len();
        self.pattern_histogram.clear();
        self.pattern_histogram.shrink_to_fit();
        Ok(())
    }
}

impl MaskedSharedGroupOracle for H4BooleanitySourceOracle {
    fn raw_group_round(
        &mut self,
        round: usize,
        expected_claim: Fp16,
    ) -> Result<[Fp16; 4], GkrZkMaskError> {
        if self.pending_round.is_some() || round != self.accepted_challenges.len() {
            return Err(GkrZkMaskError::Sequence);
        }
        let started = Instant::now();
        let polynomial = if round < H4_BOOLEANITY_COMPONENT_VARIABLES {
            self.component_round(round)?
        } else if let Some(cuda) = self.cuda.as_mut() {
            cuda.raw_round(round, self.equality_point[round], self.prefix_equality)?
        } else {
            self.folded_round(round)?
        };
        self.raw_round_seconds.push(started.elapsed().as_secs_f64());
        if polynomial[0] + polynomial[0] + polynomial[1] + polynomial[2] + polynomial[3]
            != expected_claim
        {
            return Err(GkrZkMaskError::Claim);
        }
        self.pending_round = Some(round);
        Ok(polynomial)
    }

    fn accept_group_challenge(
        &mut self,
        round: usize,
        challenge: Fp16,
    ) -> Result<(), GkrZkMaskError> {
        if self.pending_round != Some(round) || round != self.accepted_challenges.len() {
            return Err(GkrZkMaskError::Sequence);
        }
        let started = Instant::now();
        self.pending_round = None;
        self.prefix_equality =
            self.prefix_equality * equality_line(self.equality_point[round], challenge);
        self.accepted_challenges.push(challenge);
        if round + 1 == H4_BOOLEANITY_COMPONENT_VARIABLES {
            if let Some((python, worker, boundary, shard)) = self.cuda_config.take() {
                self.cuda = Some(H4BooleanityCudaWorker::spawn(
                    &python,
                    &worker,
                    &boundary,
                    shard,
                    &self.equality_point,
                    &self.accepted_challenges,
                )?);
                self.pattern_histogram.clear();
                self.pattern_histogram.shrink_to_fit();
            } else {
                self.initialize_folded_source()?;
            }
        } else if round >= H4_BOOLEANITY_COMPONENT_VARIABLES {
            if let Some(cuda) = self.cuda.as_mut() {
                cuda.accept(round, challenge)?;
            } else {
                self.folded = parallel_fold_table(&self.folded[..self.active], challenge);
                self.active = self.folded.len();
            }
        }
        self.accept_round_seconds
            .push(started.elapsed().as_secs_f64());
        Ok(())
    }

    fn folded_sources(&mut self) -> Result<(Vec<Fp16>, Vec<Fp16>), GkrZkMaskError> {
        if self.pending_round.is_some()
            || self.accepted_challenges.len() != H4_BOOLEANITY_VARIABLES as usize
        {
            return Err(GkrZkMaskError::Sequence);
        }
        if let Some(value) = self.final_folded_value {
            return Ok((vec![value, Fp16::ZERO], vec![value - Fp16::ONE, Fp16::ZERO]));
        }
        let value = if let Some(mut cuda) = self.cuda.take() {
            let value = cuda.folded()?;
            cuda.finish()?;
            value
        } else {
            if self.active != 1 {
                return Err(GkrZkMaskError::Sequence);
            }
            self.folded[0]
        };
        self.final_folded_value = Some(value);
        Ok((vec![value, Fp16::ZERO], vec![value - Fp16::ONE, Fp16::ZERO]))
    }
}

#[cfg(test)]
mod local_parallel_tests {
    use super::*;
    use bl_pq512_crypto_core::field::M31;
    use std::fs;

    fn scalar(value: u32) -> Fp16 {
        Fp16::from_m31(M31::from_canonical(value).unwrap())
    }

    #[test]
    fn parallel_fold_matches_hand_computed_four_value_example() {
        // At challenge 2: (1,2) -> 3 and (3,4) -> 5.
        let values = [scalar(1), scalar(2), scalar(3), scalar(4)];
        assert_eq!(
            parallel_fold_table(&values, scalar(2)),
            vec![scalar(3), scalar(5)]
        );
    }

    #[test]
    fn phase_telemetry_flushes_ordered_delta_and_total_times() {
        let path = env::temp_dir().join(format!(
            "blind-ledger-bridge-telemetry-{}-{}.log",
            std::process::id(),
            Instant::now().elapsed().as_nanos(),
        ));
        let now = Instant::now();
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut telemetry = PhaseTelemetry {
            started: now,
            previous: now,
            writer: BufWriter::new(file),
        };
        telemetry.mark("first").unwrap();
        telemetry.mark("second").unwrap();
        let payload = fs::read_to_string(&path).unwrap();
        fs::remove_file(&path).unwrap();
        let lines = payload.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("phase=first total_seconds="));
        assert!(lines[0].contains(" delta_seconds="));
        assert!(lines[1].starts_with("phase=second total_seconds="));
        assert!(lines[1].contains(" delta_seconds="));
    }
}

#[allow(clippy::too_many_arguments)]
fn produce_h4_booleanity_transcript(
    profile: H4ProofProfile,
    shard_index: u8,
    source_root: [u8; 64],
    mask_tensor_root: [u8; 64],
    statement_binding: [u8; 64],
    oracle: &mut dyn MaskedSharedGroupOracle,
    sumcheck_mask: &LibraVariableDegreeSumcheckMask,
    layer_mask: &LibraLayerMask,
    mut coin: impl FnMut(u16, &[u8], u16) -> Result<Vec<Fp16>, String>,
) -> Result<VerifiedH4BooleanityAlgebraBoundary, String> {
    let prelude_message = h4_booleanity_prelude_message(
        profile,
        shard_index,
        source_root,
        mask_tensor_root,
        statement_binding,
    )
    .map_err(|error| format!("booleanity_prelude_message:{error:?}"))?;
    let prelude_outputs = coin(
        H4_BOOLEANITY_PRELUDE_KIND,
        &prelude_message,
        u16::try_from(1 + H4_BOOLEANITY_VARIABLES)
            .map_err(|_| "booleanity_prelude_count".to_string())?,
    )?;
    if prelude_outputs.len() != 1 + H4_BOOLEANITY_VARIABLES as usize || prelude_outputs[0].is_zero()
    {
        return Err("booleanity_prelude_outputs".to_string());
    }
    let equality_point: [Fp16; H4_BOOLEANITY_VARIABLES as usize] = prelude_outputs[1..]
        .try_into()
        .map_err(|_| "booleanity_equality_point".to_string())?;
    let claim = LayerOutputClaim {
        point: equality_point.to_vec(),
        value: Fp16::ZERO,
        coefficient: Fp16::ONE,
    };
    struct TranscriptState<'a, F> {
        coin: &'a mut F,
        messages: Vec<Vec<u8>>,
        challenges: Vec<Fp16>,
        terminal_message: Option<Vec<u8>>,
        terminal_challenge: Option<Fp16>,
        failure: Option<String>,
    }
    let state = RefCell::new(TranscriptState {
        coin: &mut coin,
        messages: Vec::with_capacity(H4_BOOLEANITY_VARIABLES as usize + 2),
        challenges: Vec::with_capacity(H4_BOOLEANITY_VARIABLES as usize + 2),
        terminal_message: None,
        terminal_challenge: None,
        failure: None,
    });
    let proof_result = prove_masked_shared_group_dag_layer_oracle_interactive(
        &h4_booleanity_gate_layer(),
        1_usize << H4_BOOLEANITY_VARIABLES,
        oracle,
        core::slice::from_ref(&claim),
        &LibraPriorLayerCorrection::zero(),
        sumcheck_mask,
        layer_mask,
        prelude_outputs[0],
        |kind, round, published| {
            let message_round = match kind {
                SharedGroupDagRoundKind::Group => round,
                SharedGroupDagRoundKind::LeftWire => H4_BOOLEANITY_VARIABLES as usize + round,
                SharedGroupDagRoundKind::RightWire => H4_BOOLEANITY_VARIABLES as usize + 1 + round,
            };
            let message = h4_booleanity_round_message(message_round, published)
                .map_err(|_| GkrZkMaskError::Sequence)?;
            let mut context = state.borrow_mut();
            let outputs = match (context.coin)(H4_BOOLEANITY_SUMCHECK_KIND, &message, 1) {
                Ok(outputs) => outputs,
                Err(error) => {
                    context.failure = Some(error);
                    return Err(GkrZkMaskError::Sequence);
                }
            };
            if outputs.len() != 1 || outputs[0].is_zero() || outputs[0] == Fp16::ONE {
                return Err(GkrZkMaskError::Shape);
            }
            context.messages.push(message);
            context.challenges.push(outputs[0]);
            Ok(outputs[0])
        },
        |published, masked_left, masked_right| {
            let mut context = state.borrow_mut();
            let round_messages = context
                .messages
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>();
            let transcript_commitment = h4_booleanity_transcript_commitment(
                profile,
                shard_index,
                &prelude_message,
                &prelude_outputs,
                &round_messages,
                &context.challenges,
            )
            .map_err(|_| GkrZkMaskError::Sequence)?;
            let w_coefficients: [Fp16; 3] =
                published.try_into().map_err(|_| GkrZkMaskError::Shape)?;
            let message = h4_booleanity_terminal_message(
                profile,
                shard_index,
                source_root,
                mask_tensor_root,
                transcript_commitment,
                w_coefficients,
                masked_left,
                masked_right,
            )
            .map_err(|_| GkrZkMaskError::Sequence)?;
            let outputs = match (context.coin)(H4_BOOLEANITY_TERMINAL_KIND, &message, 1) {
                Ok(outputs) => outputs,
                Err(error) => {
                    context.failure = Some(error);
                    return Err(GkrZkMaskError::Sequence);
                }
            };
            if outputs.len() != 1 || outputs[0].is_zero() || outputs[0] == Fp16::ONE {
                return Err(GkrZkMaskError::Shape);
            }
            context.terminal_message = Some(message);
            context.terminal_challenge = Some(outputs[0]);
            Ok(outputs[0])
        },
    );
    let context = state.into_inner();
    let _proof = match proof_result {
        Ok(proof) => proof,
        Err(error) => {
            return Err(context
                .failure
                .unwrap_or_else(|| format!("booleanity_prove:{error:?}")));
        }
    };
    let terminal_message = context
        .terminal_message
        .ok_or_else(|| "booleanity_terminal_message".to_string())?;
    let terminal_challenge = context
        .terminal_challenge
        .ok_or_else(|| "booleanity_terminal_challenge".to_string())?;
    let round_messages = context
        .messages
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    verify_h4_booleanity_algebra_boundary(
        profile,
        shard_index,
        source_root,
        mask_tensor_root,
        statement_binding,
        &prelude_message,
        &prelude_outputs,
        &round_messages,
        &context.challenges,
        &terminal_message,
        terminal_challenge,
    )
    .map_err(|error| format!("booleanity_verify:{error:?}"))
}

#[allow(clippy::too_many_arguments)]
fn produce_h4_padding_transcript(
    profile: H4ProofProfile,
    shard_index: u8,
    source_root: [u8; 64],
    mask_tensor_root: [u8; 64],
    statement_binding: [u8; 64],
    sumcheck_mask: &LibraVariableDegreeSumcheckMask,
    layer_mask: &LibraLayerMask,
    mut coin: impl FnMut(u16, &[u8], u16) -> Result<Vec<Fp16>, String>,
) -> Result<VerifiedH4PaddingAlgebraBoundary, String> {
    let prelude_message = h4_padding_prelude_message(
        profile,
        shard_index,
        source_root,
        mask_tensor_root,
        statement_binding,
    )
    .map_err(|error| format!("padding_prelude_message:{error:?}"))?;
    let prelude_outputs = coin(
        H4_PADDING_PRELUDE_KIND,
        &prelude_message,
        u16::try_from(1 + H4_PADDING_VARIABLES).map_err(|_| "padding_prelude_count".to_string())?,
    )?;
    if prelude_outputs.len() != 1 + H4_PADDING_VARIABLES as usize || prelude_outputs[0].is_zero() {
        return Err("padding_prelude_outputs".to_string());
    }
    let _equality_point: [Fp16; H4_PADDING_VARIABLES as usize] = prelude_outputs[1..]
        .try_into()
        .map_err(|_| "padding_equality_point".to_string())?;
    let rho = prelude_outputs[0];
    let mut state = CommittedMaskedSumcheckState::new(
        Fp16::ZERO,
        Fp16::ZERO,
        sumcheck_mask.boolean_sum(),
        rho,
        vec![2; H4_PADDING_VARIABLES as usize],
    )
    .map_err(|error| format!("padding_state:{error:?}"))?;
    let mut messages = Vec::with_capacity(H4_PADDING_VARIABLES as usize);
    let mut challenges = Vec::with_capacity(H4_PADDING_VARIABLES as usize);
    for round in 0..H4_PADDING_VARIABLES as usize {
        let mask_polynomial = sumcheck_mask
            .round_polynomial(&challenges, round)
            .map_err(|error| format!("padding_mask_round:{error:?}"))?;
        let published = state
            .publish_round(&[Fp16::ZERO], &mask_polynomial, rho)
            .map_err(|error| format!("padding_publish:{error:?}"))?;
        let coefficients: [Fp16; 3] = published
            .try_into()
            .map_err(|_| "padding_round_shape".to_string())?;
        let message = h4_padding_round_message(round, coefficients)
            .map_err(|error| format!("padding_round_message:{error:?}"))?;
        let outputs = coin(H4_PADDING_SUMCHECK_KIND, &message, 1)?;
        if outputs.len() != 1 || outputs[0].is_zero() || outputs[0] == Fp16::ONE {
            return Err("padding_round_challenge".to_string());
        }
        state
            .accept_authenticated_challenge(outputs[0])
            .map_err(|error| format!("padding_accept:{error:?}"))?;
        messages.push(message);
        challenges.push(outputs[0]);
    }
    let mask_evaluation = sumcheck_mask
        .evaluate(&challenges)
        .map_err(|error| format!("padding_mask_evaluation:{error:?}"))?;
    state
        .finish(Fp16::ZERO, mask_evaluation, rho)
        .map_err(|error| format!("padding_finish:{error:?}"))?;
    let masked_terminal = boolean_vanishing(&challenges)
        * layer_mask.boolean_w_sum(
            *challenges
                .first()
                .ok_or_else(|| "padding_terminal_point".to_string())?,
        );
    let round_messages = messages.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let transcript_commitment = h4_padding_transcript_commitment(
        profile,
        shard_index,
        &prelude_message,
        &prelude_outputs,
        &round_messages,
        &challenges,
    )
    .map_err(|error| format!("padding_transcript:{error:?}"))?;
    let terminal_message = h4_padding_terminal_message(
        profile,
        shard_index,
        source_root,
        mask_tensor_root,
        transcript_commitment,
        masked_terminal,
    )
    .map_err(|error| format!("padding_terminal_message:{error:?}"))?;
    let terminal_outputs = coin(H4_PADDING_TERMINAL_KIND, &terminal_message, 1)?;
    if terminal_outputs.len() != 1 || terminal_outputs[0].is_zero() {
        return Err("padding_terminal_challenge".to_string());
    }
    verify_h4_padding_algebra_boundary(
        profile,
        shard_index,
        source_root,
        mask_tensor_root,
        statement_binding,
        &prelude_message,
        &prelude_outputs,
        &round_messages,
        &challenges,
        &terminal_message,
        terminal_outputs[0],
    )
    .map_err(|error| format!("padding_verify:{error:?}"))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ERR:{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut phase_telemetry = PhaseTelemetry::from_environment()?;
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if let [flag, boundary, shard] = arguments.as_slice()
        && flag == "--h4-pattern-stats"
    {
        let shard: u16 = shard
            .to_string_lossy()
            .parse()
            .map_err(|_| "pattern_stats_shard".to_string())?;
        let mut boundary = HashBusB16BoundaryFile::open(Path::new(boundary))
            .map_err(|error| format!("pattern_stats_boundary:{error:?}"))?;
        let shard = boundary
            .read_shard(shard)
            .map_err(|error| format!("pattern_stats_read:{error:?}"))?;
        let mut counts = vec![0_u64; 1 << 16];
        for pattern in shard.input.iter().chain(&shard.output) {
            counts[usize::from(*pattern)] += 1;
        }
        let distinct = counts.iter().filter(|count| **count != 0).count();
        let nonzero_distinct = counts
            .iter()
            .enumerate()
            .filter(|(pattern, count)| *pattern != 0 && **count != 0)
            .count();
        let nonzero_values = counts.iter().skip(1).sum::<u64>();
        println!("pattern_values={}", shard.input.len() + shard.output.len());
        println!("distinct_patterns={distinct}");
        println!("distinct_nonzero_patterns={nonzero_distinct}");
        println!("nonzero_pattern_values={nonzero_values}");
        return Ok(());
    }
    let gkr_prelude = match arguments.as_slice() {
        [] => GkrPrelude::None,
        [flag] if flag == "--gkr-prelude" => GkrPrelude::Uniform,
        [flag, boundary, shard, python, worker]
            if flag == "--gkr-prelude-nonuniform" || flag == "--gkr-prelude-nonuniform-eager" =>
        {
            GkrPrelude::Nonuniform {
                boundary: PathBuf::from(boundary),
                shard: shard
                    .to_string_lossy()
                    .parse()
                    .map_err(|_| "gkr_shard".to_string())?,
                python: PathBuf::from(python),
                worker: PathBuf::from(worker),
                eager: flag == "--gkr-prelude-nonuniform-eager",
                state_source: None,
            }
        }
        [flag, boundary, shard, python, worker, source, digest]
            if flag == "--gkr-prelude-nonuniform" || flag == "--gkr-prelude-nonuniform-eager" =>
        {
            GkrPrelude::Nonuniform {
                boundary: PathBuf::from(boundary),
                shard: shard
                    .to_string_lossy()
                    .parse()
                    .map_err(|_| "gkr_shard".to_string())?,
                python: PathBuf::from(python),
                worker: PathBuf::from(worker),
                eager: flag == "--gkr-prelude-nonuniform-eager",
                state_source: Some((
                    PathBuf::from(source),
                    parse_digest(digest.to_string_lossy().as_ref())?,
                )),
            }
        }
        _ => return Err("arguments".to_string()),
    };
    let strict_mode = std::env::var_os("BL_CURRENT_STRICT_H4").is_some_and(|value| value == "1");
    let service = std::env::current_exe()
        .map_err(|error| format!("current_exe:{error}"))?
        .parent()
        .ok_or_else(|| "executable_parent".to_string())?
        .join("chained_public_coin_service.exe");
    if !strict_mode && !service.is_file() {
        return Err(format!("service_missing:{}", service.display()));
    }
    let mut prepared_nonuniform = match &gkr_prelude {
        GkrPrelude::Nonuniform {
            boundary,
            shard,
            python,
            worker,
            eager: true,
            ..
        } => Some(prepare_nonuniform(boundary, *shard, python, worker)?),
        _ => None,
    };
    mark_phase(&mut phase_telemetry, "nonuniform_prepare")?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::with_capacity(1 << 20, stdin.lock());
    let mut writer = BufWriter::with_capacity(1 << 20, stdout.lock());
    if &read_exact::<8>(&mut reader)? != INPUT_MAGIC {
        return Err("input_magic".to_string());
    }
    let session_id = read_exact::<64>(&mut reader)?;
    let attempt = u16::from_be_bytes(read_exact::<2>(&mut reader)?);
    let schedule_commitment = read_exact::<64>(&mut reader)?;
    let round_count = u32::from_be_bytes(read_exact::<4>(&mut reader)?);
    if round_count == 0 || round_count > MAX_ROUNDS {
        return Err("round_count".to_string());
    }
    let strict_profile = strict_mode
        .then(|| strict_profile_for_rounds(round_count))
        .transpose()?;
    let gkr_input = if !matches!(gkr_prelude, GkrPrelude::None) {
        let commitment = read_exact::<64>(&mut reader)?;
        let coefficients = (0..GKR_MASK_COEFFICIENTS)
            .map(|_| {
                Fp16::decode(&read_exact::<64>(&mut reader)?)
                    .map_err(|error| format!("gkr_mask_coefficient:{error:?}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Some((commitment, coefficients))
    } else {
        None
    };
    mark_phase(&mut phase_telemetry, "input_read")?;
    let spawn_started = Instant::now();
    let mut coordinator: Box<dyn BridgeCoin> = if strict_mode {
        let profile = strict_profile_for_rounds(round_count)?;
        Box::new(StrictBridgeCoin {
            profile,
            coordinator: Some(
                StrictH4InteractiveCoin::new(
                    profile,
                    session_id,
                    attempt,
                    schedule_commitment,
                    round_count,
                )
                .map_err(|error| format!("strict_spawn:{error:?}"))?,
            ),
        })
    } else {
        Box::new(LegacyBridgeCoin {
            coordinator: Some(
                ChainedPublicCoinCoordinator::spawn(
                    &service,
                    session_id,
                    attempt,
                    schedule_commitment,
                    round_count,
                )
                .map_err(|error| format!("spawn:{error:?}"))?,
            ),
            round_count,
        })
    };
    mark_phase(&mut phase_telemetry, "coin_initialized")?;
    let mut emitted = Vec::with_capacity(round_count as usize);
    let mut first_external_ordinal = 0_u32;
    let mut gkr_pcs_context = None;
    let mut gkr_verification = None;
    let mut h4_differential_source = None;
    let mut state_relation_digest = [0_u8; 64];
    let mut state_relation_claims = [dummy_state_claim(), dummy_state_claim()];
    let mut squarefree_claims = vec![dummy_state_claim(); STATE_SQUAREFREE_H4_CLAIMS];
    let mut squarefree_coefficient_claims = Vec::new();
    let mut squarefree_public_coefficient_claims = Vec::new();
    let mut squarefree_coefficient_root = [0_u8; 64];
    if let Some((commitment, coefficients)) = gkr_input {
        let state_source = match &gkr_prelude {
            GkrPrelude::Nonuniform { state_source, .. } => state_source.as_ref(),
            _ => None,
        };
        let state_capacity_value = match (&gkr_prelude, state_source) {
            (GkrPrelude::Nonuniform { boundary, .. }, Some(_)) => state_capacity(boundary)?,
            _ => 128,
        };
        let squarefree_rounds = if state_source.is_some() {
            state_squarefree_authenticated_rounds(state_capacity_value)
                .ok_or_else(|| "squarefree_round_profile".to_string())?
        } else {
            0
        };
        let h4_source_relation_rounds = if state_source.is_some() {
            H4_BOOLEANITY_ROUNDS + H4_PADDING_ROUNDS
        } else {
            0
        };
        let expected_round_count = GKR_TRANSCRIPT_ROUNDS
            + 1
            + STATE_RELATION_ROUNDS
            + squarefree_rounds
            + h4_source_relation_rounds
            + 1
            + 13;
        if round_count != expected_round_count {
            return Err("gkr_round_count".to_string());
        }
        let state_mask_layout = selected_state_composed_mask_layout(state_capacity_value)
            .map_err(|error| format!("state_mask_layout:{error:?}"))?;
        let (_, state_sumcheck_masks, state_layer_masks) = state_mask_layout
            .decode_prefix(&coefficients)
            .map_err(|error| format!("state_mask_decode:{error:?}"))?;
        let mut ordinal = 0_u32;
        let mut h4_source_root = [0_u8; 64];
        let mut h4_source_boundaries = None;
        let (mut proof, statement_binding) = match &gkr_prelude {
            GkrPrelude::Uniform => (
                prove_masked_uniform_zero_trace(
                    commitment,
                    &coefficients,
                    |kind, message, output_count| {
                        let outputs = coordinator
                            .challenge(
                                ChainedRoundDescriptor {
                                    kind: gkr_round_code(kind),
                                    ordinal,
                                    output_count,
                                },
                                message,
                            )
                            .map_err(|_| UniformRelayFreeGkrError::Coin)?;
                        ordinal += 1;
                        Ok(outputs)
                    },
                )
                .map_err(|error| format!("gkr_prove:{error:?}"))?,
                None,
            ),
            GkrPrelude::Nonuniform {
                boundary,
                shard,
                python,
                worker,
                ..
            } => {
                let (mut oracle, statement_binding) =
                    if let Some(prepared) = prepared_nonuniform.take() {
                        prepared
                    } else {
                        prepare_nonuniform(boundary, *shard, python, worker)?
                    };
                let proof = prove_masked_nonuniform_trace(
                    commitment,
                    &coefficients,
                    statement_binding,
                    &mut oracle,
                    |kind, message, output_count| {
                        let outputs = coordinator
                            .challenge(
                                ChainedRoundDescriptor {
                                    kind: gkr_round_code(kind),
                                    ordinal,
                                    output_count,
                                },
                                message,
                            )
                            .map_err(|_| UniformRelayFreeGkrError::Coin)?;
                        ordinal += 1;
                        Ok(outputs)
                    },
                )
                .map_err(|error| format!("gkr_prove:{error:?}"))?;
                oracle
                    .finish()
                    .map_err(|error| format!("gkr_worker_finish:{error:?}"))?;
                (proof, Some(statement_binding))
            }
            GkrPrelude::None => return Err("gkr_prelude".to_string()),
        };
        mark_phase(&mut phase_telemetry, "nonuniform_gkr_proved")?;
        let batch = complete_uniform_gkr_mask_batch(
            &mut proof,
            &coefficients,
            |kind, message, output_count| {
                let outputs = coordinator
                    .challenge(
                        ChainedRoundDescriptor {
                            kind: gkr_round_code(kind),
                            ordinal,
                            output_count,
                        },
                        message,
                    )
                    .map_err(|_| UniformRelayFreeGkrError::Coin)?;
                ordinal += 1;
                Ok(outputs)
            },
        )
        .map_err(|error| format!("gkr_batch:{error:?}"))?;
        mark_phase(&mut phase_telemetry, "gkr_mask_batch_completed")?;
        if ordinal != GKR_TRANSCRIPT_ROUNDS + 1 {
            return Err("gkr_ordinal".to_string());
        }
        emitted.extend(proof.rounds.iter().map(|round| round.outputs.clone()));
        let state_source_digest =
            state_source.map_or([0_u8; 64], |(_, source_digest)| *source_digest);
        let source = if let Some((source_path, source_digest)) = state_source {
            read_state_relation_wire_source(source_path, *source_digest)
                .map_err(|error| format!("state_relation_source:{error:?}"))?
        } else {
            vec![Fp16::ZERO; 1 << 18]
        };
        mark_phase(&mut phase_telemetry, "state_source_read")?;
        let output_message = state_relation_output_message(state_source_digest);
        let output = coordinator
            .challenge(
                ChainedRoundDescriptor {
                    kind: STATE_RELATION_OUTPUT_KIND,
                    ordinal,
                    output_count: STATE_RELATION_OUTPUT_CHALLENGE_COUNT,
                },
                &output_message,
            )
            .map_err(|error| format!("state_relation_output_coin:{error:?}"))?;
        if output.len() != usize::from(STATE_RELATION_OUTPUT_CHALLENGE_COUNT) || output[0].is_zero()
        {
            return Err("state_relation_output_shape".to_string());
        }
        emitted.push(output.clone());
        let shard_query = output[0];
        let output_point = output[1..18].to_vec();
        let state_relation_rho = output[18];
        if state_relation_rho.is_zero() {
            return Err("state_relation_rho".to_string());
        }
        ordinal += 1;
        let state_proof = {
            let relation_coin = RefCell::new((&mut coordinator, &mut emitted, &mut ordinal));
            prove_masked_state_relation_gkr_interactive(
                &source,
                output_point,
                &state_sumcheck_masks[GKR_LAYERS as usize],
                &state_layer_masks[GKR_LAYERS as usize],
                state_relation_rho,
                |kind, round, published| {
                    let descriptor_kind = match kind {
                        StateRelationRoundKind::Group => STATE_RELATION_GROUP_KIND,
                        StateRelationRoundKind::Wire => STATE_RELATION_WIRE_KIND,
                    };
                    let message = state_relation_round_message(
                        state_source_digest,
                        descriptor_kind,
                        round,
                        published,
                    )?;
                    let mut context = relation_coin.borrow_mut();
                    let current_ordinal = *context.2;
                    let outputs = context
                        .0
                        .challenge(
                            ChainedRoundDescriptor {
                                kind: descriptor_kind,
                                ordinal: current_ordinal,
                                output_count: 1,
                            },
                            &message,
                        )
                        .map_err(|_| StateRelationGkrError::Shape)?;
                    if outputs.len() != 1 {
                        return Err(StateRelationGkrError::Shape);
                    }
                    context.1.push(outputs.clone());
                    *context.2 += 1;
                    Ok(outputs[0])
                },
                |published, left, right| {
                    let mut terminal = published.to_vec();
                    terminal.extend([left, right]);
                    let message = state_relation_round_message(
                        state_source_digest,
                        STATE_RELATION_TERMINAL_KIND,
                        0,
                        &terminal,
                    )?;
                    let mut context = relation_coin.borrow_mut();
                    let current_ordinal = *context.2;
                    let outputs = context
                        .0
                        .challenge(
                            ChainedRoundDescriptor {
                                kind: STATE_RELATION_TERMINAL_KIND,
                                ordinal: current_ordinal,
                                output_count: 1,
                            },
                            &message,
                        )
                        .map_err(|_| StateRelationGkrError::Shape)?;
                    if outputs.len() != 1 {
                        return Err(StateRelationGkrError::Shape);
                    }
                    context.1.push(outputs.clone());
                    *context.2 += 1;
                    Ok(outputs[0])
                },
            )
            .map_err(|error| format!("state_relation_prove:{error:?}"))?
        };
        verify_masked_state_relation_gkr(&state_proof)
            .map_err(|error| format!("state_relation_verify:{error:?}"))?;
        mark_phase(&mut phase_telemetry, "state_relation_proved_verified")?;
        let mut state_mask_constraints =
            masked_state_relation_constraints_unchecked(&state_proof, GKR_LAYERS as usize)
                .map_err(|error| format!("state_relation_masks:{error:?}"))?;
        if state_source.is_some() {
            let claims = masked_state_relation_h4_input_claims_unchecked(&state_proof, shard_query)
                .map_err(|error| format!("state_relation_claims:{error:?}"))?;
            state_relation_claims = claims.map(|claim| UniformRelayFreeClaim {
                shard_query: claim.shard_query,
                point: claim.point,
                value: claim.value,
                coefficient: Fp16::ONE,
            });
            state_relation_digest = public_state_relation_transcript_digest(
                state_source_digest,
                &PublicMaskedStateRelationGkrProof::from_private(&state_proof),
                shard_query,
            )
            .map_err(|error| format!("state_relation_transcript_digest:{error:?}"))?;
        }
        if let (GkrPrelude::Nonuniform { boundary, .. }, Some(_)) = (&gkr_prelude, state_source) {
            let booleanity_mask_layer = selected_booleanity_mask_layer(state_capacity_value)
                .map_err(|error| format!("booleanity_mask_layer:{error:?}"))?;
            let padding_mask_layer = selected_padding_mask_layer(state_capacity_value)
                .map_err(|error| format!("padding_mask_layer:{error:?}"))?;
            if padding_mask_layer != booleanity_mask_layer + 1
                || padding_mask_layer + 1 != state_sumcheck_masks.len()
                || state_sumcheck_masks.len() != state_layer_masks.len()
                || booleanity_mask_layer <= GKR_LAYERS as usize + 1
            {
                return Err("h4_source_mask_layout".to_string());
            }
            let squarefree = run_squarefree_prelude(
                &mut reader,
                &mut writer,
                coordinator.as_mut(),
                &mut emitted,
                &mut ordinal,
                &source,
                state_source_digest,
                boundary,
                shard_query,
                spawn_started.elapsed().as_secs_f64(),
                &state_sumcheck_masks[GKR_LAYERS as usize + 1..booleanity_mask_layer],
                &state_layer_masks[GKR_LAYERS as usize + 1..booleanity_mask_layer],
                &mut phase_telemetry,
            )?;
            mark_phase(&mut phase_telemetry, "squarefree_completed")?;
            state_mask_constraints.extend(squarefree.mask_constraints.clone());
            squarefree_claims = squarefree.claims;
            squarefree_coefficient_claims = squarefree.coefficient_claims;
            squarefree_public_coefficient_claims = squarefree.public_coefficient_claims;
            squarefree_coefficient_root = squarefree.coefficient_root;
            h4_source_root = squarefree.source_root;
            let mut hash = Sha3_512::new();
            hash.update(STATE_RELATION_TRANSCRIPT_DOMAIN);
            hash.update(state_relation_digest);
            hash.update(squarefree.transcript_digest);
            hash.update(squarefree_coefficient_root);
            state_relation_digest = hash.finalize().into();

            let statement_binding =
                statement_binding.ok_or_else(|| "h4_source_statement_binding".to_string())?;
            let (profile, shard_index) = match (&gkr_prelude, state_capacity_value) {
                (GkrPrelude::Nonuniform { shard, .. }, 128) => (
                    H4ProofProfile::K128,
                    u8::try_from(*shard).map_err(|_| "h4_source_shard".to_string())?,
                ),
                (GkrPrelude::Nonuniform { shard, .. }, 512) => (
                    H4ProofProfile::K512,
                    u8::try_from(*shard).map_err(|_| "h4_source_shard".to_string())?,
                ),
                _ => return Err("h4_source_profile".to_string()),
            };
            let mut boundary_file = HashBusB16BoundaryFile::open(boundary)
                .map_err(|error| format!("booleanity_boundary:{error:?}"))?;
            let boundary_shard = boundary_file
                .read_shard(u16::from(shard_index))
                .map_err(|error| format!("booleanity_boundary_shard:{error:?}"))?;
            mark_phase(&mut phase_telemetry, "h4_boundary_shard_read")?;

            let booleanity_prelude = h4_booleanity_prelude_message(
                profile,
                shard_index,
                h4_source_root,
                commitment,
                statement_binding,
            )
            .map_err(|error| format!("booleanity_prelude_preview:{error:?}"))?;
            let booleanity_outputs = coordinator
                .challenge(
                    ChainedRoundDescriptor {
                        kind: H4_BOOLEANITY_PRELUDE_KIND,
                        ordinal,
                        output_count: u16::try_from(1 + H4_BOOLEANITY_VARIABLES)
                            .map_err(|_| "booleanity_output_count".to_string())?,
                    },
                    &booleanity_prelude,
                )
                .map_err(|error| format!("booleanity_prelude_coin:{error:?}"))?;
            if booleanity_outputs.len() != 1 + H4_BOOLEANITY_VARIABLES as usize
                || booleanity_outputs[0].is_zero()
            {
                return Err("booleanity_prelude_shape".to_string());
            }
            emitted.push(booleanity_outputs.clone());
            ordinal += 1;
            let equality_point: [Fp16; H4_BOOLEANITY_VARIABLES as usize] = booleanity_outputs[1..]
                .try_into()
                .map_err(|_| "booleanity_equality_point".to_string())?;
            let mut booleanity_oracle =
                H4BooleanitySourceOracle::new(boundary_shard, equality_point, shard_index)
                    .map_err(|error| format!("booleanity_source_oracle:{error:?}"))?;
            if let GkrPrelude::Nonuniform { python, worker, .. } = &gkr_prelude {
                let cuda_worker = worker
                    .parent()
                    .ok_or_else(|| "booleanity_cuda_worker_parent".to_string())?
                    .join("cuda_h4_booleanity_worker.py");
                booleanity_oracle
                    .configure_cuda(python, &cuda_worker, boundary, u16::from(shard_index))
                    .map_err(|error| format!("booleanity_cuda_config:{error:?}"))?;
            }
            // The shared producer helper owns kind 144. The preview above is
            // replayed byte-for-byte through a one-shot closure so the source
            // oracle can be initialized from its authenticated equality point
            // without introducing a second challenge.
            let mut replay_prelude = Some(booleanity_outputs);
            let booleanity = produce_h4_booleanity_transcript(
                profile,
                shard_index,
                h4_source_root,
                commitment,
                statement_binding,
                &mut booleanity_oracle,
                &state_sumcheck_masks[booleanity_mask_layer],
                &state_layer_masks[booleanity_mask_layer],
                |kind, message, output_count| {
                    if kind == H4_BOOLEANITY_PRELUDE_KIND {
                        if message != booleanity_prelude || output_count != 30 {
                            return Err("booleanity_prelude_replay".to_string());
                        }
                        return replay_prelude
                            .take()
                            .ok_or_else(|| "booleanity_prelude_duplicate".to_string());
                    }
                    let outputs = coordinator
                        .challenge(
                            ChainedRoundDescriptor {
                                kind,
                                ordinal,
                                output_count,
                            },
                            message,
                        )
                        .map_err(|error| format!("booleanity_coin:{error:?}"))?;
                    emitted.push(outputs.clone());
                    ordinal += 1;
                    Ok(outputs)
                },
            )?;
            mark_phase(&mut phase_telemetry, "h4_booleanity_completed")?;
            if let Some(telemetry) = phase_telemetry.as_mut() {
                for (round, seconds) in booleanity_oracle.raw_round_seconds.iter().enumerate() {
                    telemetry.metric(&format!("h4_raw_round_{round:02}"), *seconds)?;
                }
                for (round, seconds) in booleanity_oracle.accept_round_seconds.iter().enumerate() {
                    telemetry.metric(&format!("h4_accept_round_{round:02}"), *seconds)?;
                }
            }
            if replay_prelude.is_some() {
                return Err("booleanity_prelude_unused".to_string());
            }
            let native_folded_sources = booleanity_oracle
                .folded_sources()
                .map_err(|error| format!("h4_differential_source_result:{error:?}"))?;
            booleanity_oracle
                .write_final_differential_dump((&native_folded_sources.0, &native_folded_sources.1))
                .map_err(|error| format!("h4_differential_dump:{error}"))?;
            let padding = produce_h4_padding_transcript(
                profile,
                shard_index,
                h4_source_root,
                commitment,
                statement_binding,
                &state_sumcheck_masks[padding_mask_layer],
                &state_layer_masks[padding_mask_layer],
                |kind, message, output_count| {
                    let outputs = coordinator
                        .challenge(
                            ChainedRoundDescriptor {
                                kind,
                                ordinal,
                                output_count,
                            },
                            message,
                        )
                        .map_err(|error| format!("padding_coin:{error:?}"))?;
                    emitted.push(outputs.clone());
                    ordinal += 1;
                    Ok(outputs)
                },
            )?;
            mark_phase(&mut phase_telemetry, "h4_padding_completed")?;
            let native_folded_source = native_folded_sources
                .0
                .first()
                .copied()
                .ok_or_else(|| "native_differential_folded_source".to_string())?;
            let native_folded_source_minus_one = native_folded_sources
                .1
                .first()
                .copied()
                .ok_or_else(|| "native_differential_folded_source_minus_one".to_string())?;
            h4_differential_source = Some(H4NativeDifferential {
                equality_point: equality_point.to_vec(),
                booleanity_group_point: booleanity_oracle.accepted_challenges.clone(),
                padding_sumcheck_point: Vec::new(),
                source_coefficients: booleanity_oracle
                    .diagnostic_source_vector
                    .clone()
                    .unwrap_or_default(),
                pattern_histogram: booleanity_oracle
                    .diagnostic_source_coefficients
                    .clone()
                    .unwrap_or_default(),
                folded_source: native_folded_source,
                folded_source_minus_one: native_folded_source_minus_one,
            });
            state_mask_constraints.extend(booleanity.mask_constraints().iter().cloned());
            state_mask_constraints.extend(padding.mask_constraints().iter().cloned());
            h4_source_boundaries = Some((profile, booleanity, padding));
        }
        let mut complete_mask_constraints = batch.constraints.clone();
        complete_mask_constraints.extend(state_mask_constraints);
        let complete_mask_message = gkr_mask_batch_message(&complete_mask_constraints);
        let complete_mask_output = coordinator
            .challenge(
                ChainedRoundDescriptor {
                    kind: STATE_COMPOSED_MASK_BATCH_KIND,
                    ordinal,
                    output_count: 1,
                },
                &complete_mask_message,
            )
            .map_err(|error| format!("state_mask_batch_coin:{error:?}"))?;
        if complete_mask_output.len() != 1 || complete_mask_output[0].is_zero() {
            return Err("state_mask_batch_shape".to_string());
        }
        emitted.push(complete_mask_output.clone());
        ordinal += 1;
        let complete_mask_challenge = complete_mask_output[0];
        let h4_masked_source_functional_binding =
            if let Some((profile, booleanity, padding)) = h4_source_boundaries.as_ref() {
                let binding = H4MaskedSourceFunctionalBinding::from_verified_boundaries(
                    *profile,
                    booleanity,
                    padding,
                    complete_mask_challenge,
                )
                .map_err(|error| format!("h4_source_functional_binding:{error:?}"))?;
                if let Some(differential) = h4_differential_source.as_mut() {
                    differential.padding_sumcheck_point = binding.padding_sumcheck_point().to_vec();
                }
                let binding = binding.encode();
                if binding.len() != H4_MASKED_SOURCE_FUNCTIONAL_BINDING_BYTES
                    || h4_source_root == [0_u8; 64]
                {
                    return Err("h4_source_functional_binding_shape".to_string());
                }
                Some(binding)
            } else {
                None
            };
        let (complete_mask_weights, complete_mask_opening) = aggregate_gkr_mask_constraints(
            &state_mask_layout,
            &complete_mask_constraints,
            complete_mask_challenge,
        )
        .map_err(|error| format!("state_mask_batch_aggregate:{error:?}"))?;
        mark_phase(&mut phase_telemetry, "composed_mask_aggregated")?;
        if bl_pq512_crypto_core::gkr_zk_mask::inner_product(&coefficients, &complete_mask_weights)
            .map_err(|error| format!("state_mask_batch_inner_product:{error:?}"))?
            != complete_mask_opening
        {
            return Err("state_mask_batch_opening".to_string());
        }
        let expected_external_ordinal = GKR_TRANSCRIPT_ROUNDS
            + 1
            + STATE_RELATION_ROUNDS
            + squarefree_rounds
            + h4_source_relation_rounds
            + 1;
        if ordinal != expected_external_ordinal {
            return Err(format!(
                "state_relation_ordinal:{ordinal}/{expected_external_ordinal}"
            ));
        }
        let proof = Arc::new(proof);
        let batch = Arc::new(batch);
        let verification_proof = Arc::clone(&proof);
        let verification_batch = Arc::clone(&batch);
        gkr_verification = Some(thread::spawn(move || match statement_binding {
            Some(binding) => {
                verify_masked_nonuniform_trace(&verification_proof, &verification_batch, binding)
            }
            None => verify_masked_uniform_zero_trace(&verification_proof, &verification_batch),
        }));
        let squarefree_public_claims_payload = squarefree_claims_payload(
            squarefree_coefficient_root,
            state_capacity_value,
            &squarefree_public_coefficient_claims,
        )?;
        gkr_pcs_context = Some(GkrPcsContext {
            commitment,
            opening: complete_mask_opening,
            claim_challenge: complete_mask_challenge,
            coefficient_weights: complete_mask_weights.clone(),
            row_challenges: Vec::with_capacity(PCS_ROW_CHALLENGES),
            squarefree_claims_payload: squarefree_public_claims_payload.clone(),
            squarefree_coefficient_root,
        });
        first_external_ordinal = ordinal;
        writer
            .write_all(GKR_READY_MAGIC)
            .and_then(|_| writer.write_all(&spawn_started.elapsed().as_secs_f64().to_be_bytes()))
            .and_then(|_| writer.write_all(&complete_mask_opening.encode()))
            .and_then(|_| writer.write_all(&complete_mask_challenge.encode()))
            .map_err(|error| format!("gkr_ready:{error}"))?;
        mark_phase(&mut phase_telemetry, "gkr_ready_emitted")?;
        for weight in &complete_mask_weights {
            writer
                .write_all(&weight.encode())
                .map_err(|error| format!("gkr_weight:{error}"))?;
        }
        write_gkr_claim(&mut writer, 0, &proof.raw_output_claim)?;
        for claim in &proof.raw_input_claims {
            write_gkr_claim(&mut writer, 1, claim)?;
        }
        for claim in &state_relation_claims {
            write_gkr_claim(&mut writer, 1, claim)?;
        }
        for claim in &squarefree_claims {
            write_gkr_claim(&mut writer, 1, claim)?;
        }
        writer
            .write_all(&state_relation_digest)
            .and_then(|_| writer.write_all(&squarefree_coefficient_root))
            .and_then(|_| {
                writer.write_all(
                    &u16::try_from(squarefree_coefficient_claims.len())
                        .map_err(|_| io::Error::other("squarefree_claim_count"))?
                        .to_be_bytes(),
                )
            })
            .and_then(|_| writer.write_all(&[0_u8; 6]))
            .map_err(|error| format!("state_relation_digest:{error}"))?;
        for claim in &squarefree_coefficient_claims {
            if claim.point.len() != STATE_SQUAREFREE_COEFFICIENT_VARIABLES {
                return Err("squarefree_coefficient_point".to_string());
            }
            writer
                .write_all(
                    &u16::try_from(claim.point.len())
                        .map_err(|_| "squarefree_coefficient_point".to_string())?
                        .to_be_bytes(),
                )
                .and_then(|_| writer.write_all(&[0_u8; 6]))
                .map_err(|error| format!("squarefree_coefficient_claim:{error}"))?;
            for value in &claim.point {
                writer
                    .write_all(&value.encode())
                    .map_err(|error| format!("squarefree_coefficient_claim:{error}"))?;
            }
            writer
                .write_all(&claim.value.encode())
                .map_err(|error| format!("squarefree_coefficient_claim:{error}"))?;
        }
        writer
            .write_all(&squarefree_public_claims_payload)
            .map_err(|error| format!("squarefree_public_claims_payload:{error}"))?;
        if let Some(binding) = h4_masked_source_functional_binding {
            writer
                .write_all(&binding)
                .map_err(|error| format!("h4_source_functional_binding:{error}"))?;
        }
        writer
            .flush()
            .map_err(|error| format!("gkr_flush:{error}"))?;
    } else {
        writer
            .write_all(READY_MAGIC)
            .and_then(|_| writer.write_all(&spawn_started.elapsed().as_secs_f64().to_be_bytes()))
            .and_then(|_| writer.flush())
            .map_err(|error| format!("ready:{error}"))?;
    }

    for expected_ordinal in first_external_ordinal..round_count {
        if &read_exact::<8>(&mut reader)? != ROUND_MAGIC {
            return Err(format!("round_magic:{expected_ordinal}"));
        }
        let descriptor = ChainedRoundDescriptor {
            kind: u16::from_be_bytes(read_exact::<2>(&mut reader)?),
            ordinal: u32::from_be_bytes(read_exact::<4>(&mut reader)?),
            output_count: u16::from_be_bytes(read_exact::<2>(&mut reader)?),
        };
        let message_length = usize::try_from(u32::from_be_bytes(read_exact::<4>(&mut reader)?))
            .map_err(|_| "message_length".to_string())?;
        if descriptor.ordinal != expected_ordinal
            || descriptor.output_count == 0
            || message_length == 0
            || message_length > MAX_MESSAGE_LENGTH
        {
            return Err(format!("round_shape:{expected_ordinal}"));
        }
        let mut message = vec![0_u8; message_length];
        reader
            .read_exact(&mut message)
            .map_err(|error| format!("round_message:{error}"))?;
        if let Some(context) = &gkr_pcs_context {
            validate_gkr_pcs_round(
                context,
                first_external_ordinal,
                descriptor,
                &message,
                strict_profile,
            )?;
        }
        let challenges = coordinator
            .challenge(descriptor, &message)
            .map_err(|error| format!("round_challenge:{error:?}"))?;
        if challenges.len() != usize::from(descriptor.output_count) {
            return Err(format!("challenge_count:{expected_ordinal}"));
        }
        emitted.push(challenges.clone());
        if descriptor.kind == 799 {
            let context = gkr_pcs_context
                .as_mut()
                .ok_or_else(|| "gkr_pcs_context".to_string())?;
            context.claim_challenge = challenges[0];
        }
        if descriptor.kind == 801 {
            let context = gkr_pcs_context
                .as_mut()
                .ok_or_else(|| "gkr_pcs_context".to_string())?;
            context.row_challenges.push(challenges[0]);
        }
        writer
            .write_all(RESPONSE_MAGIC)
            .and_then(|_| writer.write_all(&descriptor.ordinal.to_be_bytes()))
            .and_then(|_| writer.write_all(&descriptor.output_count.to_be_bytes()))
            .map_err(|error| format!("round_response:{error}"))?;
        for challenge in challenges {
            writer
                .write_all(&challenge.encode())
                .map_err(|error| format!("round_response:{error}"))?;
        }
        writer
            .flush()
            .map_err(|error| format!("round_flush:{error}"))?;
    }

    if let Some(verification) = gkr_verification {
        verification
            .join()
            .map_err(|_| "gkr_verify_panicked".to_string())?
            .map_err(|error| format!("gkr_verify:{error:?}"))?;
    }
    let finish_started = Instant::now();
    let finished = coordinator.finish()?;
    if let Some(replayed) = &finished.replayed {
        if replayed.len() != emitted.len()
            || replayed
                .iter()
                .zip(&emitted)
                .any(|(left, right)| left != right)
        {
            return Err("replay_mismatch".to_string());
        }
    }

    if let (Some(differential), Some(context)) =
        (h4_differential_source.as_ref(), gkr_pcs_context.as_ref())
    {
        if !differential.source_coefficients.is_empty() {
            differential.write_differential_dump(&context.row_challenges)?;
        }
    }
    let mut trailing = [0_u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(|error| format!("trailing:{error}"))?
        != 0
    {
        return Err("trailing_input".to_string());
    }
    writer
        .write_all(if finished.raw_frames.is_some() {
            STRICT_FINISH_FULL_FRAMES_MAGIC
        } else if finished.governed_key.is_some() {
            STRICT_FINISH_MAGIC
        } else {
            FINISH_MAGIC
        })
        .and_then(|_| {
            if let Some(governed_key) = &finished.governed_key {
                writer.write_all(
                    &u32::try_from(governed_key.len())
                        .map_err(|_| io::Error::other("governed_key_length"))?
                        .to_be_bytes(),
                )?;
                writer.write_all(
                    &u32::try_from(finished.encoded_bundle.len())
                        .map_err(|_| io::Error::other("bundle_length"))?
                        .to_be_bytes(),
                )?;
                if let Some(raw_frames) = &finished.raw_frames {
                    writer.write_all(
                        &u32::try_from(raw_frames.len())
                            .map_err(|_| io::Error::other("raw_frames_length"))?
                            .to_be_bytes(),
                    )?;
                }
                writer.write_all(governed_key)?;
                writer.write_all(&finished.encoded_bundle)?;
                if let Some(raw_frames) = &finished.raw_frames {
                    writer.write_all(raw_frames)?;
                }
                Ok(())
            } else {
                writer.write_all(
                    &u32::try_from(finished.encoded_bundle.len())
                        .map_err(|_| io::Error::other("bundle_length"))?
                        .to_be_bytes(),
                )?;
                writer.write_all(&finished.encoded_bundle)
            }
        })
        .and_then(|_| writer.write_all(&finish_started.elapsed().as_secs_f64().to_be_bytes()))
        .and_then(|_| writer.flush())
        .map_err(|error| format!("finish_output:{error}"))?;
    Ok(())
}

fn prepare_nonuniform(
    boundary: &Path,
    shard: u16,
    python: &Path,
    worker: &Path,
) -> Result<(HashBusB16GkrWorker, [u8; 64]), String> {
    let boundary_file = HashBusB16BoundaryFile::open(boundary)
        .map_err(|error| format!("gkr_boundary:{error:?}"))?;
    let plan_commitment = HashBusB16GkrPlan::selected()
        .and_then(|plan| plan.commitment())
        .map_err(|error| format!("gkr_plan:{error:?}"))?;
    let boundary_statement_binding = boundary_file
        .header()
        .gkr_statement_binding(shard, plan_commitment)
        .map_err(|error| format!("gkr_statement:{error:?}"))?;
    let statement_binding = match env::var("BL_H4_GKR_STATEMENT_BINDING") {
        Ok(encoded) => parse_digest(&encoded)?,
        Err(env::VarError::NotPresent) => boundary_statement_binding,
        Err(_) => return Err("gkr_statement_env".to_owned()),
    };
    let oracle = HashBusB16GkrWorker::spawn(python, worker, boundary, shard)
        .map_err(|error| format!("gkr_worker:{error:?}"))?;
    Ok((oracle, statement_binding))
}

fn state_capacity(boundary: &Path) -> Result<usize, String> {
    let file = HashBusB16BoundaryFile::open(boundary)
        .map_err(|error| format!("squarefree_boundary:{error:?}"))?;
    match file.header().profile {
        Profile::K128Calibration => Ok(128),
        Profile::K512Calibration => Ok(512),
        Profile::K256DesignPoint => Err("squarefree_profile_k256".to_string()),
    }
}

fn masked_squarefree_round_kind(kind: MaskedStateSquarefreeRoundKind) -> u16 {
    match kind {
        MaskedStateSquarefreeRoundKind::Group => STATE_SQUAREFREE_MASKED_GROUP_KIND,
        MaskedStateSquarefreeRoundKind::LeftWire => STATE_SQUAREFREE_MASKED_LEFT_KIND,
        MaskedStateSquarefreeRoundKind::RightWire => STATE_SQUAREFREE_MASKED_RIGHT_KIND,
        MaskedStateSquarefreeRoundKind::Terminal => STATE_SQUAREFREE_MASKED_TERMINAL_KIND,
        MaskedStateSquarefreeRoundKind::ClaimMix => STATE_SQUAREFREE_MASKED_MIX_KIND,
    }
}

fn squarefree_claims_payload(
    root: [u8; 64],
    capacity: usize,
    claims: &[bl_pq512_crypto_core::multilinear_pcs::MultilinearOpeningClaim],
) -> Result<Vec<u8>, String> {
    if claims.is_empty() && root == [0_u8; 64] {
        let mut payload = Vec::with_capacity(76);
        payload.extend_from_slice(b"BLSQCL00");
        payload.extend_from_slice(&root);
        payload.extend_from_slice(&[0_u8; 4]);
        return Ok(payload);
    }
    if claims.len() != MASKED_STATE_SQUAREFREE_COEFFICIENT_CLAIMS
        || !root.iter().any(|byte| *byte != 0)
        || !matches!(capacity, 128 | 512)
        || claims[0].point.len() != STATE_SQUAREFREE_COEFFICIENT_VARIABLES
        || claims
            .iter()
            .any(|claim| claim.point.len() != claims[0].point.len())
    {
        return Err("squarefree_claim_payload_shape".to_string());
    }
    let mut preimage = Vec::new();
    preimage.extend_from_slice(STATE_SQUAREFREE_CLAIMS_DIGEST_DOMAIN);
    preimage.extend_from_slice(&root);
    preimage.extend_from_slice(&(capacity as u16).to_be_bytes());
    preimage.extend_from_slice(&(claims.len() as u16).to_be_bytes());
    for claim in claims {
        preimage.extend_from_slice(&(claim.point.len() as u16).to_be_bytes());
        for coordinate in &claim.point {
            preimage.extend_from_slice(&coordinate.encode());
        }
        preimage.extend_from_slice(&claim.value.encode());
    }
    let digest: [u8; 64] = Sha3_512::digest(&preimage).into();
    let mut payload = Vec::with_capacity(140);
    payload.extend_from_slice(b"BLSQCL02");
    payload.extend_from_slice(&root);
    payload.extend_from_slice(&(capacity as u16).to_be_bytes());
    payload.extend_from_slice(&(claims.len() as u16).to_be_bytes());
    payload.extend_from_slice(&digest);
    Ok(payload)
}

#[allow(clippy::too_many_arguments)]
fn run_squarefree_prelude(
    reader: &mut impl Read,
    writer: &mut impl Write,
    coordinator: &mut dyn BridgeCoin,
    emitted: &mut Vec<Vec<Fp16>>,
    ordinal: &mut u32,
    source: &[Fp16],
    source_digest: [u8; 64],
    boundary: &Path,
    shard_query: Fp16,
    elapsed_seconds: f64,
    sumcheck_masks: &[bl_pq512_crypto_core::gkr_zk_mask::LibraVariableDegreeSumcheckMask],
    layer_masks: &[bl_pq512_crypto_core::gkr_zk_mask::LibraLayerMask],
    phase_telemetry: &mut Option<PhaseTelemetry>,
) -> Result<SquarefreePrelude, String> {
    let capacity = state_capacity(boundary)?;
    writer
        .write_all(SQUAREFREE_READY_MAGIC)
        .and_then(|_| writer.write_all(&elapsed_seconds.to_be_bytes()))
        .and_then(|_| writer.flush())
        .map_err(|error| format!("squarefree_ready:{error}"))?;
    if &read_exact::<8>(reader)? != SQUAREFREE_BIND_MAGIC {
        return Err("squarefree_bind_magic".to_string());
    }
    let initial_root = read_exact::<64>(reader)?;
    if !initial_root.iter().any(|byte| *byte != 0) {
        return Err("squarefree_initial_root".to_string());
    }
    mark_phase(phase_telemetry, "squarefree_initial_root_received")?;
    let beta_message = state_squarefree_beta_message(source_digest, initial_root, capacity)
        .map_err(|error| format!("squarefree_beta_message:{error:?}"))?;
    let beta_output = coordinator
        .challenge(
            ChainedRoundDescriptor {
                kind: STATE_SQUAREFREE_BETA_KIND,
                ordinal: *ordinal,
                output_count: 1,
            },
            &beta_message,
        )
        .map_err(|error| format!("squarefree_beta_coin:{error:?}"))?;
    if beta_output.len() != 1 || beta_output[0].is_zero() {
        return Err("squarefree_beta_shape".to_string());
    }
    emitted.push(beta_output.clone());
    *ordinal += 1;
    let beta = beta_output[0];
    let rows = state_relation_rows_from_source(source, capacity)
        .map_err(|error| format!("squarefree_rows:{error:?}"))?;
    let layout = bl_pq512_crypto_core::state_squarefree_gkr::StateSquarefreeLayout::new(capacity)
        .map_err(|error| format!("squarefree_layout:{error:?}"))?;
    let witness = build_state_squarefree_witness(&rows, layout, beta)
        .map_err(|error| format!("squarefree_witness:{error:?}"))?;
    mark_phase(phase_telemetry, "squarefree_witness_built")?;
    writer
        .write_all(SQUAREFREE_WITNESS_MAGIC)
        .and_then(|_| writer.write_all(&(capacity as u16).to_be_bytes()))
        .and_then(|_| writer.write_all(&[0_u8; 6]))
        .and_then(|_| writer.write_all(&beta.encode()))
        .map_err(|error| format!("squarefree_witness_header:{error}"))?;
    for coefficients in [
        &witness.phases[0].bezout_a,
        &witness.phases[0].bezout_b,
        &witness.phases[1].bezout_a,
        &witness.phases[1].bezout_b,
    ] {
        for index in 0..STATE_SQUAREFREE_COEFFICIENT_BLOCK {
            writer
                .write_all(
                    &coefficients
                        .get(index)
                        .copied()
                        .unwrap_or(Fp16::ZERO)
                        .encode(),
                )
                .map_err(|error| format!("squarefree_witness:{error}"))?;
        }
    }
    writer
        .flush()
        .map_err(|error| format!("squarefree_witness_flush:{error}"))?;
    mark_phase(phase_telemetry, "squarefree_witness_emitted")?;
    if &read_exact::<8>(reader)? != SQUAREFREE_COMMIT_MAGIC {
        return Err("squarefree_commit_magic".to_string());
    }
    let coefficient_root = read_exact::<64>(reader)?;
    if !coefficient_root.iter().any(|byte| *byte != 0) {
        return Err("squarefree_coefficient_root".to_string());
    }
    mark_phase(phase_telemetry, "squarefree_coefficient_root_received")?;
    let point_message =
        state_squarefree_point_message(source_digest, initial_root, coefficient_root, beta);
    let point_output = coordinator
        .challenge(
            ChainedRoundDescriptor {
                kind: STATE_SQUAREFREE_POINT_KIND,
                ordinal: *ordinal,
                output_count: u16::try_from(1 + sumcheck_masks.len())
                    .map_err(|_| "squarefree_mask_count".to_string())?,
            },
            &point_message,
        )
        .map_err(|error| format!("squarefree_point_coin:{error:?}"))?;
    if point_output.len() != 1 + sumcheck_masks.len()
        || point_output.iter().any(|value| value.is_zero())
        || sumcheck_masks.len() != layer_masks.len()
    {
        return Err("squarefree_point_shape".to_string());
    }
    emitted.push(point_output.clone());
    *ordinal += 1;
    let evaluation_point = point_output[0];
    let committed_masks = sumcheck_masks
        .iter()
        .cloned()
        .zip(layer_masks.iter().cloned())
        .zip(point_output[1..].iter().copied())
        .map(
            |((sumcheck, layer), sumcheck_rho)| StateSquarefreeCommittedLayerMask {
                sumcheck,
                layer,
                sumcheck_rho,
            },
        )
        .collect::<Vec<_>>();
    let mut transcript_hash = Sha3_512::new();
    transcript_hash.update(STATE_SQUAREFREE_TRANSCRIPT_DOMAIN);
    transcript_hash.update(source_digest);
    transcript_hash.update(initial_root);
    transcript_hash.update(coefficient_root);
    transcript_hash.update(beta.encode());
    for value in &point_output {
        transcript_hash.update(value.encode());
    }
    let proof = prove_masked_state_squarefree_composed(
        &rows,
        &witness,
        evaluation_point,
        &committed_masks,
        |kind, phase, layer_kind, layer, round, published, output_count| {
            let descriptor_kind = masked_squarefree_round_kind(kind);
            let layer = state_squarefree_layer_ordinal(layer_kind, layer)?;
            if kind == MaskedStateSquarefreeRoundKind::ClaimMix && output_count == 2 {
                let mut output = Vec::with_capacity(2);
                for coefficient in 0..2 {
                    let message = state_squarefree_round_message(
                        source_digest,
                        coefficient_root,
                        descriptor_kind,
                        phase,
                        layer,
                        round
                            .checked_add(coefficient)
                            .ok_or(StateSquarefreeGkrError::Shape)?,
                        published,
                    )?;
                    let challenge = coordinator
                        .challenge(
                            ChainedRoundDescriptor {
                                kind: descriptor_kind,
                                ordinal: *ordinal,
                                output_count: 1,
                            },
                            &message,
                        )
                        .map_err(|_| StateSquarefreeGkrError::Shape)?;
                    if challenge.len() != 1 {
                        return Err(StateSquarefreeGkrError::Shape);
                    }
                    transcript_hash.update(&message);
                    transcript_hash.update(challenge[0].encode());
                    emitted.push(challenge.clone());
                    *ordinal += 1;
                    output.push(challenge[0]);
                }
                Ok(output)
            } else {
                if output_count != 1 {
                    return Err(StateSquarefreeGkrError::Shape);
                }
                let message = state_squarefree_round_message(
                    source_digest,
                    coefficient_root,
                    descriptor_kind,
                    phase,
                    layer,
                    round,
                    published,
                )?;
                let output = coordinator
                    .challenge(
                        ChainedRoundDescriptor {
                            kind: descriptor_kind,
                            ordinal: *ordinal,
                            output_count: 1,
                        },
                        &message,
                    )
                    .map_err(|_| StateSquarefreeGkrError::Shape)?;
                if output.len() != 1 {
                    return Err(StateSquarefreeGkrError::Shape);
                }
                transcript_hash.update(&message);
                transcript_hash.update(output[0].encode());
                emitted.push(output.clone());
                *ordinal += 1;
                Ok(output)
            }
        },
    )
    .map_err(|error| format!("squarefree_prove:{error:?}"))?;
    verify_masked_state_squarefree_composed(&proof)
        .map_err(|error| format!("squarefree_verify:{error:?}"))?;
    let h4_claims = masked_state_squarefree_h4_input_claims_unchecked(source, &proof, shard_query)
        .map_err(|error| format!("squarefree_h4_claims:{error:?}"))?;
    let claims = h4_claims
        .into_iter()
        .map(|claim| UniformRelayFreeClaim {
            shard_query: claim.shard_query,
            point: claim.point,
            value: claim.value,
            coefficient: Fp16::ONE,
        })
        .collect::<Vec<_>>();
    if claims.len() != STATE_SQUAREFREE_H4_CLAIMS {
        return Err("squarefree_h4_claim_count".to_string());
    }
    let public_coefficient_claims =
        masked_state_squarefree_public_pcs_coefficient_claims_unchecked(&proof)
            .map_err(|error| format!("squarefree_public_coefficient_claims:{error:?}"))?
            .into_iter()
            .collect::<Vec<_>>();
    if public_coefficient_claims.len() != MASKED_STATE_SQUAREFREE_COEFFICIENT_CLAIMS {
        return Err("squarefree_public_coefficient_claim_shape".to_string());
    }
    let raw_state_leaf_values = core::array::from_fn(|phase| {
        core::array::from_fn(|claim| proof.state_leaf_claims[phase][claim].value)
    });
    let public_proof = PublicMaskedStateSquarefreeGkrProof::from_private(&proof)
        .map_err(|error| format!("squarefree_public_proof:{error:?}"))?;
    let mask_constraints =
        public_masked_state_squarefree_constraints(&public_proof, raw_state_leaf_values)
            .map_err(|error| format!("squarefree_mask_constraints:{error:?}"))?;
    Ok(SquarefreePrelude {
        claims,
        coefficient_claims: public_coefficient_claims.clone(),
        public_coefficient_claims,
        coefficient_root,
        transcript_digest: transcript_hash.finalize().into(),
        mask_constraints,
        source_root: initial_root,
    })
}

fn validate_gkr_pcs_round(
    context: &GkrPcsContext,
    first_external_ordinal: u32,
    descriptor: ChainedRoundDescriptor,
    message: &[u8],
    strict_profile: Option<H4ProofProfileV2>,
) -> Result<(), String> {
    let message = if let Some(profile) = strict_profile {
        let expected_descriptor = StrictPqRoundDescriptorV2::new(
            descriptor.kind,
            descriptor.ordinal,
            descriptor.output_count,
        )
        .map_err(|_| "gkr_pcs_global_descriptor".to_string())?;
        let frame = parse_h4_global_round_frame_v2(message, profile, expected_descriptor)
            .map_err(|_| "gkr_pcs_global_frame".to_string())?;
        if frame.shard_messages().len() != 1 {
            return Err("gkr_pcs_global_shard_count".to_string());
        }
        frame.shard_messages()[0]
    } else {
        message
    };
    let relative = descriptor
        .ordinal
        .checked_sub(first_external_ordinal)
        .ok_or_else(|| "gkr_pcs_ordinal".to_string())?;
    let expected_kind = match relative {
        0 => 799,
        1 => 800,
        2..=10 => 801,
        11 => 802,
        12 => 803,
        _ => return Err("gkr_pcs_round_count".to_string()),
    };
    let expected_output_count = if relative == 0 { 6 } else { 1 };
    if descriptor.kind != expected_kind || descriptor.output_count != expected_output_count {
        return Err(format!("gkr_pcs_descriptor:{relative}"));
    }
    match relative {
        0 => {
            let expected_length = 392 + context.squarefree_claims_payload.len();
            if message.len() != expected_length {
                return Err(format!(
                    "gkr_pcs_claim_length:{}/{}",
                    message.len(),
                    expected_length
                ));
            }
            if &message[..8] != b"BLT8GC06" {
                return Err("gkr_pcs_claim_magic".to_string());
            }
            if message[136..200] != context.commitment {
                return Err("gkr_pcs_claim_commitment".to_string());
            }
            if message[200..264] != context.opening.encode() {
                return Err("gkr_pcs_claim_opening".to_string());
            }
            if message[392..] != context.squarefree_claims_payload {
                return Err("gkr_pcs_claim_squarefree_payload".to_string());
            }
        }
        1 => {
            if message.len() != 456
                || &message[..8] != b"BLT8SO06"
                || message[136..200] != context.commitment
                || message[200..264] != context.opening.encode()
            {
                return Err("gkr_pcs_initial_message".to_string());
            }
        }
        2..=10 => {
            if context.row_challenges.len() != relative as usize - 2 {
                return Err("gkr_pcs_row_challenge_order".to_string());
            }
        }
        11 => {
            let expected_length = BASE_MASKS_PREFIX.len() + 6 * 64;
            if context.row_challenges.len() != PCS_ROW_CHALLENGES
                || message.len() != expected_length
                || !message.starts_with(BASE_MASKS_PREFIX)
            {
                return Err("gkr_pcs_base_message_shape".to_string());
            }
            let roots = BASE_MASKS_PREFIX.len();
            if message[roots + 128..roots + 192] != context.commitment {
                return Err("gkr_pcs_base_gkr_root".to_string());
            }
            if message[roots + 192..roots + 256] != context.squarefree_coefficient_root {
                return Err("gkr_pcs_base_squarefree_root".to_string());
            }
            let terminal_digest = gkr_terminal_digest(context)?;
            if message[roots + 256..roots + 320] != terminal_digest {
                return Err("gkr_pcs_terminal_digest".to_string());
            }
        }
        12 => {
            let expected_length = ANSWERS_PREFIX.len() + 3 * (8 + 64) + 64;
            if message.len() != expected_length || !message.starts_with(ANSWERS_PREFIX) {
                return Err("gkr_pcs_answer_message_shape".to_string());
            }
            let mut offset = ANSWERS_PREFIX.len();
            for expected_bytes in [
                ANSWER_MAIN_BYTES,
                ANSWER_ORDINARY_AUXILIARY_BYTES,
                ANSWER_GKR_TENSOR_BYTES,
            ] {
                let section_bytes = u64::from_be_bytes(
                    message[offset..offset + 8]
                        .try_into()
                        .map_err(|_| "gkr_pcs_answer_section_length".to_string())?,
                );
                offset += 8;
                let digest = &message[offset..offset + 64];
                offset += 64;
                if section_bytes != expected_bytes || !digest.iter().any(|byte| *byte != 0) {
                    return Err("gkr_pcs_answer_section".to_string());
                }
            }
            if !message[offset..offset + 64].iter().any(|byte| *byte != 0) {
                return Err("gkr_pcs_answer_tensor_root".to_string());
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn gkr_terminal_digest(context: &GkrPcsContext) -> Result<[u8; 64], String> {
    if context.coefficient_weights.len() != GKR_MASK_COEFFICIENTS
        || context.row_challenges.len() != PCS_ROW_CHALLENGES
    {
        return Err("gkr_terminal_shape".to_string());
    }
    let mut scale = Fp16::ONE;
    for _ in 0..GKR_CLAIM_COUNT {
        scale = scale * context.claim_challenge;
    }
    let mut hash = Sha3_512::new();
    for word in 0..GKR_MASK_WORDS {
        let start = word * GKR_MASK_WORD_VALUES;
        let mut layer = context.coefficient_weights[start..start + GKR_MASK_WORD_VALUES].to_vec();
        let mut active = GKR_MASK_WORD_VALUES;
        for challenge in &context.row_challenges {
            for index in 0..active / 2 {
                let left = layer[2 * index];
                let right = layer[2 * index + 1];
                layer[index] = left + (right - left) * *challenge;
            }
            active /= 2;
        }
        hash.update((layer[0] * scale).encode());
    }
    Ok(hash.finalize().into())
}

fn parse_digest(encoded: &str) -> Result<[u8; 64], String> {
    if encoded.len() != 128 {
        return Err("state_relation_digest_length".to_string());
    }
    let bytes = (0..64)
        .map(|index| {
            u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)
                .map_err(|_| "state_relation_digest_encoding".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let digest: [u8; 64] = bytes
        .try_into()
        .map_err(|_| "state_relation_digest_shape".to_string())?;
    if !digest.iter().any(|byte| *byte != 0) {
        return Err("state_relation_digest_zero".to_string());
    }
    Ok(digest)
}

fn dummy_state_claim() -> UniformRelayFreeClaim {
    UniformRelayFreeClaim {
        shard_query: Fp16::ONE,
        point: vec![Fp16::ZERO; 24],
        value: Fp16::ZERO,
        coefficient: Fp16::ONE,
    }
}

fn gkr_round_code(kind: SelectedGkrRoundKind) -> u16 {
    match kind {
        SelectedGkrRoundKind::OutputQuery => 100,
        SelectedGkrRoundKind::PackedBridge => 110,
        SelectedGkrRoundKind::SharedGroup => 111,
        SelectedGkrRoundKind::Wire => 112,
        SelectedGkrRoundKind::Terminal => 113,
        SelectedGkrRoundKind::ClaimMix => 114,
        SelectedGkrRoundKind::MaskBatch => 115,
    }
}

fn write_gkr_claim(
    writer: &mut impl Write,
    boundary: u32,
    claim: &UniformRelayFreeClaim,
) -> Result<(), String> {
    if claim.point.len() != 24 {
        return Err("gkr_claim_point".to_string());
    }
    writer
        .write_all(&boundary.to_be_bytes())
        .and_then(|_| writer.write_all(&claim.coefficient.encode()))
        .and_then(|_| writer.write_all(&claim.value.encode()))
        .and_then(|_| writer.write_all(&claim.shard_query.encode()))
        .map_err(|error| format!("gkr_claim:{error}"))?;
    for coordinate in &claim.point {
        writer
            .write_all(&coordinate.encode())
            .map_err(|error| format!("gkr_claim:{error}"))?;
    }
    Ok(())
}

fn read_exact<const N: usize>(reader: &mut impl Read) -> Result<[u8; N], String> {
    let mut value = [0_u8; N];
    reader
        .read_exact(&mut value)
        .map_err(|error| format!("read:{error}"))?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bl_pq512_crypto_core::{field::M31, multilinear_pcs::MultilinearOpeningClaim};

    fn field(value: u32) -> Fp16 {
        Fp16::from_m31(M31::from_canonical(value).unwrap())
    }

    #[derive(Default)]
    struct ZeroBooleanityOracle {
        accepted: usize,
        pending: bool,
    }

    impl MaskedSharedGroupOracle for ZeroBooleanityOracle {
        fn raw_group_round(
            &mut self,
            round: usize,
            expected_claim: Fp16,
        ) -> Result<[Fp16; 4], GkrZkMaskError> {
            if round != self.accepted || self.pending || !expected_claim.is_zero() {
                return Err(GkrZkMaskError::Sequence);
            }
            self.pending = true;
            Ok([Fp16::ZERO; 4])
        }

        fn accept_group_challenge(
            &mut self,
            round: usize,
            _challenge: Fp16,
        ) -> Result<(), GkrZkMaskError> {
            if round != self.accepted || !self.pending {
                return Err(GkrZkMaskError::Sequence);
            }
            self.pending = false;
            self.accepted += 1;
            Ok(())
        }

        fn folded_sources(&mut self) -> Result<(Vec<Fp16>, Vec<Fp16>), GkrZkMaskError> {
            if self.pending || self.accepted != H4_BOOLEANITY_VARIABLES as usize {
                return Err(GkrZkMaskError::Sequence);
            }
            Ok((vec![Fp16::ZERO; 2], vec![-Fp16::ONE, Fp16::ZERO]))
        }
    }

    fn deterministic_coin<'a>(
        kinds: &'a mut Vec<u16>,
    ) -> impl FnMut(u16, &[u8], u16) -> Result<Vec<Fp16>, String> + 'a {
        move |kind, message, output_count| {
            if message.is_empty() || output_count == 0 {
                return Err("test_coin_shape".to_string());
            }
            let ordinal = kinds.len();
            kinds.push(kind);
            Ok((0..usize::from(output_count))
                .map(|index| field(2 + (ordinal * 37 + index) as u32))
                .collect())
        }
    }

    #[test]
    fn booleanity_line_matches_two_variable_hand_calculation() {
        // Hand fixture f(0,0)=0, f(1,0)=1. With equality coordinate zero,
        // the first suffix contributes t(t-1)(1-t) = -t + 2t^2 - t^3.
        let mut polynomial = [Fp16::ZERO; 4];
        add_booleanity_line(
            &mut polynomial,
            Fp16::ZERO,
            Fp16::ONE,
            Fp16::ZERO,
            Fp16::ONE,
        );
        assert_eq!(polynomial[0], Fp16::ZERO);
        assert_eq!(polynomial[1], -Fp16::ONE);
        assert_eq!(polynomial[2], Fp16::ONE + Fp16::ONE);
        assert_eq!(polynomial[3], -Fp16::ONE);
        assert_eq!(
            polynomial[0] + polynomial[0] + polynomial[1] + polynomial[2] + polynomial[3],
            Fp16::ZERO
        );
    }

    #[test]
    fn squarefree_public_payload_is_fixed_size_and_hides_claim_values() {
        let root = [0x5a_u8; 64];
        let claims = [37_u32, 41_u32].map(|value| MultilinearOpeningClaim {
            point: vec![Fp16::ZERO; STATE_SQUAREFREE_COEFFICIENT_VARIABLES],
            value: field(value),
        });
        let payload = squarefree_claims_payload(root, 128, &claims).unwrap();
        assert_eq!(payload.len(), 140);
        assert_eq!(&payload[..8], b"BLSQCL02");
        assert_eq!(&payload[8..72], &root);
        assert_eq!(&payload[72..74], &128_u16.to_be_bytes());
        assert_eq!(&payload[74..76], &2_u16.to_be_bytes());
        for claim in &claims {
            assert!(
                !payload
                    .windows(64)
                    .any(|window| window == claim.value.encode())
            );
        }

        let mut changed = claims.clone();
        changed[0].value = changed[0].value + Fp16::ONE;
        assert_ne!(
            payload,
            squarefree_claims_payload(root, 128, &changed).unwrap()
        );
    }

    #[test]
    fn h4_source_rounds_and_raw_free_binding_roundtrip_deterministically() {
        let profile = H4ProofProfile::K128;
        let source_root = [0x31_u8; 64];
        let mask_root = [0x52_u8; 64];
        let statement_binding = [0x73_u8; 64];
        let layout = selected_state_composed_mask_layout(128).unwrap();
        let coefficients = (0..layout.padded_coefficients)
            .map(|index| field(2 + (index % 10_000) as u32))
            .collect::<Vec<_>>();
        let (_, sumcheck_masks, layer_masks) = layout.decode_prefix(&coefficients).unwrap();
        let booleanity_layer = selected_booleanity_mask_layer(128).unwrap();
        let padding_layer = selected_padding_mask_layer(128).unwrap();
        assert_eq!(padding_layer, booleanity_layer + 1);

        let mut booleanity_kinds = Vec::new();
        let mut oracle = ZeroBooleanityOracle::default();
        let booleanity = produce_h4_booleanity_transcript(
            profile,
            0,
            source_root,
            mask_root,
            statement_binding,
            &mut oracle,
            &sumcheck_masks[booleanity_layer],
            &layer_masks[booleanity_layer],
            deterministic_coin(&mut booleanity_kinds),
        )
        .unwrap();
        assert_eq!(booleanity_kinds.len(), H4_BOOLEANITY_ROUNDS as usize);
        assert_eq!(booleanity_kinds[0], H4_BOOLEANITY_PRELUDE_KIND);
        assert_eq!(
            booleanity_kinds.last().copied(),
            Some(H4_BOOLEANITY_TERMINAL_KIND)
        );

        let mut padding_kinds = Vec::new();
        let padding = produce_h4_padding_transcript(
            profile,
            0,
            source_root,
            mask_root,
            statement_binding,
            &sumcheck_masks[padding_layer],
            &layer_masks[padding_layer],
            deterministic_coin(&mut padding_kinds),
        )
        .unwrap();
        assert_eq!(padding_kinds.len(), H4_PADDING_ROUNDS as usize);
        assert_eq!(padding_kinds[0], H4_PADDING_PRELUDE_KIND);
        assert_eq!(
            padding_kinds.last().copied(),
            Some(H4_PADDING_TERMINAL_KIND)
        );

        let binding = H4MaskedSourceFunctionalBinding::from_verified_boundaries(
            profile,
            &booleanity,
            &padding,
            field(65_001),
        )
        .unwrap();
        let encoded = binding.encode();
        assert_eq!(encoded.len(), H4_MASKED_SOURCE_FUNCTIONAL_BINDING_BYTES);
        assert_eq!(&encoded[..8], b"BLH4SF01");
        assert_eq!(&encoded[16..80], &source_root);
        assert_eq!(&encoded[80..144], &mask_root);
        assert_eq!(
            H4MaskedSourceFunctionalBinding::decode(&encoded).unwrap(),
            binding
        );

        let claims = bl_pq512_crypto_core::h4_proof_package_v1::evaluate_h4_masked_source_functional_binding(
            &binding,
            &vec![Fp16::ZERO; 1 << H4_BOOLEANITY_COEFFICIENT_VARIABLES],
            &coefficients,
            &[Fp16::ZERO; H4_BOOLEANITY_WORD_VARIABLES],
        )
        .unwrap();
        assert_eq!(
            claims.masked_target(),
            claims.answer_main_functional() + claims.answer_mask_functional()
        );

        for offset in [16_usize, 80, 208, 2_064, 4_304, 4_495, 4_559] {
            let mut mutated = encoded.clone();
            mutated[offset] ^= 1;
            assert!(H4MaskedSourceFunctionalBinding::decode(&mutated).is_err());
        }
    }
}
