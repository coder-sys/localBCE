use std::{
    cell::{Cell, RefCell},
    ffi::OsString,
    fs::{File, read},
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use bl_pq512_crypto_core::field::{FP16_ENCODED_LENGTH, M31};
use bl_pq512_crypto_core::{
    Fp16,
    chained_public_coin::{
        ChainedPublicCoinBundle, ChainedRoundDescriptor, decode_chained_public_coin_bundle,
        encode_chained_public_coin_bundle,
    },
    gkr_pcs_bridge::bind_repeated_pack_gkr_terminals,
    gkr_sumcheck::{
        LayerOutputClaim, multilinear_equality_table, prove_repeated_pack_layer_bridge_parallel,
        repeated_pack_compact_layer_geometry, repeated_pack_terminal_gate_claim,
        verify_masked_repeated_pack_keccak_layer_claims_control,
    },
    gkr_worker::{
        BoundedGkrWorker, GkrCompactClaimWeights, GkrCompactPointClaim,
        GkrCompactPointWorkerRequest, GkrCompactWorkerRequest, GkrWorkerError,
        verify_pinned_gkr_cuda_bundle,
    },
    gkr_zk_mask::{
        CommittedMaskedSumcheckState, CompleteGkrZkMaskCommitmentLayout, LibraPriorLayerCorrection,
        PACKED_BRIDGE_MASK_COEFFICIENTS, boolean_vanishing,
        coefficient_weights_to_hypercube_weights, inner_product, polynomial_evaluation,
        selected_libra_variable_degrees, terminal_vanishing_coefficient,
    },
    keccak_gkr_wiring::{
        KECCAK_GKR_LAYERS_PER_ROUND, build_keccak_gkr_circuit, packed_keccak_gkr_round_checkpoints,
        regenerate_packed_keccak_gkr_round_inputs,
    },
    multilinear_pcs::{
        MLPCS_AUXILIARY_LDE_LOG_SIZE, MLPCS_AUXILIARY_MASK_VARIABLES,
        MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE, MLPCS_INPUT_LOG_SIZE, MLPCS_LDE_LOG_SIZE,
        MLPCS_LOG_INVERSE_RATE, MultilinearOpeningClaim, PackedGkrInputClaims,
        PackedGkrOutputClaim, evaluate_multilinear_coefficients, evaluate_univariate_lde,
        extend_multilinear_coefficients_with_mask, interpolate_packed_boolean_hypercube,
        multilinear_coefficients_to_hypercube,
    },
    multilinear_pcs_proof::{
        INTERACTIVE_DUAL_BOUNDARY_MLPCS_ROUNDS, SelectedMultilinearPcsProofError,
        prove_interactive_dual_boundary_multilinear_pcs_prepared,
        prove_interactive_dual_boundary_multilinear_pcs_prepared_with_gkr_mask_opening,
        verify_interactive_dual_boundary_multilinear_pcs,
        verify_interactive_dual_boundary_multilinear_pcs_with_gkr_mask_opening,
    },
    multilinear_pcs_query::{
        MLPCS_LEAF_PAYLOAD_BYTES, MLPCS_VALUES_PER_LEAF, PreparedDualBoundaryFoldCommitments,
    },
    packed_boolean_sumcheck::{
        OUTPUT_COEFFICIENTS, PACK_BITS, PackedBooleanTable, packed_lagrange_node_weights,
        packed_selector_polynomial, verify_packed_first_round_bridge,
    },
    sha3_air::keccak_f1600,
    trace_mask::sample_extension_trace_mask_coefficients,
};
#[cfg(not(feature = "bench_fixture_coin"))]
use bl_pq512_crypto_core::{
    chained_public_coin::verify_chained_public_coin_bundle as verify_active_public_coin_bundle,
    chained_public_coin_client::ChainedPublicCoinCoordinator as ActivePublicCoinCoordinator,
};
use sha3::{Digest, Sha3_512};

#[cfg(feature = "bench_fixture_coin")]
#[path = "support/gkr_coherent_chain_benchmark_fixture_coin.rs"]
mod gkr_coherent_chain_benchmark_fixture_coin;
#[cfg(feature = "bench_fixture_coin")]
use gkr_coherent_chain_benchmark_fixture_coin::{
    BenchFixturePublicCoinCoordinator as ActivePublicCoinCoordinator,
    verify_bench_fixture_bundle as verify_active_public_coin_bundle,
};

struct MeasuredPublicCoin {
    inner: ActivePublicCoinCoordinator,
    round_wait_ns: u128,
    round_wait_count: u32,
}

impl MeasuredPublicCoin {
    fn new(inner: ActivePublicCoinCoordinator) -> Self {
        Self {
            inner,
            round_wait_ns: 0,
            round_wait_count: 0,
        }
    }

    fn challenge(
        &mut self,
        descriptor: ChainedRoundDescriptor,
        prover_message: &[u8],
    ) -> Result<Vec<Fp16>, String> {
        let started = Instant::now();
        let result = self.inner.challenge(descriptor, prover_message);
        self.round_wait_ns = self
            .round_wait_ns
            .checked_add(started.elapsed().as_nanos())
            .ok_or("public_coin_wait_overflow")?;
        self.round_wait_count = self
            .round_wait_count
            .checked_add(1)
            .ok_or("public_coin_wait_count_overflow")?;
        result.map_err(|error| format!("{error:?}"))
    }

    fn scalar_challenge(
        &mut self,
        descriptor: ChainedRoundDescriptor,
        prover_message: &[u8],
    ) -> Result<Fp16, String> {
        let started = Instant::now();
        let result = self.inner.scalar_challenge(descriptor, prover_message);
        self.round_wait_ns = self
            .round_wait_ns
            .checked_add(started.elapsed().as_nanos())
            .ok_or("public_coin_wait_overflow")?;
        self.round_wait_count = self
            .round_wait_count
            .checked_add(1)
            .ok_or("public_coin_wait_count_overflow")?;
        result.map_err(|error| format!("{error:?}"))
    }

    fn finish_bundle(self) -> Result<ChainedPublicCoinBundle, String> {
        self.inner
            .finish_bundle()
            .map_err(|error| format!("{error:?}"))
    }
}

const DEFAULT_GROUP_COUNT: usize = 128;
const MAX_GROUP_COUNT: usize = DEFAULT_GROUP_COUNT;
#[cfg(test)]
const DEFAULT_INSTANCES: usize = DEFAULT_GROUP_COUNT * PACK_BITS;
const STATE_BITS: usize = 1_600;
const INPUT_MAGIC: &[u8; 8] = b"BLKGINP1";
const INPUT_VERSION: u16 = 1;
const MASK_ORACLE_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/GKR-PCS-MASK-ORACLE/v1\0";
const SPARSE_PUBLIC_COIN_SCHEDULE_DOMAIN: &[u8] =
    b"BL/PQ512/WAVE2/GKR-SPARSE-PUBLIC-COIN-SCHEDULE/v1\0";
const COMPLETE_PUBLIC_COIN_SCHEDULE_DOMAIN: &[u8] =
    b"BL/PQ512/WAVE2/COMPLETE-GKR-PCS-PUBLIC-COIN-SCHEDULE/v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
enum GkrMaskFunctional {
    BridgeEvaluation {
        layer: usize,
        point: Fp16,
        scale: Fp16,
    },
    SumcheckBooleanSum {
        layer: usize,
        scale: Fp16,
    },
    SumcheckEvaluation {
        layer: usize,
        point: Vec<Fp16>,
        scale: Fp16,
    },
    LayerEvaluation {
        layer: usize,
        z_first: Fp16,
        w: Fp16,
        scale: Fp16,
    },
    LayerBooleanSum {
        layer: usize,
        z_first: Fp16,
        scale: Fp16,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GkrMaskConstraint {
    functionals: Vec<GkrMaskFunctional>,
    residual: Fp16,
}

#[derive(Clone)]
struct StrictGkrLayerTranscript {
    proof_index: usize,
    layer_index: usize,
    incoming_claims: Vec<LayerOutputClaim>,
    shard_query: Fp16,
    bridge_rho: Fp16,
    sumcheck_rho: Fp16,
    public_bridge: [Fp16; OUTPUT_COEFFICIENTS],
    bridge_challenge: Fp16,
    rounds: Vec<Vec<Fp16>>,
    challenges: Vec<Fp16>,
    terminal_left: Fp16,
    terminal_right: Fp16,
    terminal_gate: Fp16,
}

fn accumulate_mask_functional(
    layout: &CompleteGkrZkMaskCommitmentLayout,
    destination: &mut [Fp16],
    functional: &GkrMaskFunctional,
    batching: Fp16,
) -> Result<(), String> {
    match functional {
        GkrMaskFunctional::BridgeEvaluation {
            layer,
            point,
            scale,
        } => layout.accumulate_bridge_evaluation(destination, *layer, *point, batching * *scale),
        GkrMaskFunctional::SumcheckBooleanSum { layer, scale } => {
            layout.accumulate_sumcheck_boolean_sum(destination, *layer, batching * *scale)
        }
        GkrMaskFunctional::SumcheckEvaluation {
            layer,
            point,
            scale,
        } => layout.accumulate_sumcheck_evaluation(destination, *layer, point, batching * *scale),
        GkrMaskFunctional::LayerEvaluation {
            layer,
            z_first,
            w,
            scale,
        } => {
            layout.accumulate_layer_evaluation(destination, *layer, *z_first, *w, batching * *scale)
        }
        GkrMaskFunctional::LayerBooleanSum {
            layer,
            z_first,
            scale,
        } => {
            layout.accumulate_layer_boolean_w_sum(destination, *layer, *z_first, batching * *scale)
        }
    }
    .map_err(|error| format!("gkr_mask_functional:{error:?}"))
}
const OUTPUT_QUERY_MESSAGE_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/GKR-OUTPUT-QUERY-MESSAGE/v1\0";

struct CompletePcsInputs {
    input_codeword: PathBuf,
    output_codeword: PathBuf,
}

fn read_codeword(path: &Path, log_size: u8) -> Result<Vec<Fp16>, String> {
    let value_count = 1_usize
        .checked_shl(u32::from(log_size))
        .ok_or("codeword_log_size")?;
    let expected_bytes = u64::try_from(value_count)
        .map_err(|_| "codeword_length")?
        .checked_mul(u64::try_from(FP16_ENCODED_LENGTH).map_err(|_| "codeword_length")?)
        .ok_or("codeword_length")?;
    let file = File::open(path).map_err(|_| "codeword_open")?;
    if file.metadata().map_err(|_| "codeword_metadata")?.len() != expected_bytes {
        return Err(format!(
            "codeword_length_mismatch:path={}:expected={expected_bytes}",
            path.display()
        ));
    }
    let mut reader = BufReader::with_capacity(16 << 20, file);
    let mut values = vec![Fp16::ZERO; value_count];
    let mut payload = [0_u8; MLPCS_LEAF_PAYLOAD_BYTES];
    for leaf in values.chunks_exact_mut(MLPCS_VALUES_PER_LEAF) {
        reader
            .read_exact(&mut payload)
            .map_err(|_| "codeword_read")?;
        for (value, encoded) in leaf
            .iter_mut()
            .zip(payload.chunks_exact(FP16_ENCODED_LENGTH))
        {
            *value = Fp16::decode(encoded).map_err(|_| "codeword_decode")?;
        }
    }
    let mut trailing = [0_u8; 1];
    if reader.read(&mut trailing).map_err(|_| "codeword_read")? != 0 {
        return Err("codeword_trailing_bytes".into());
    }
    Ok(values)
}

fn fp16(seed: u32) -> Fp16 {
    Fp16::from_coefficients(core::array::from_fn(|coefficient| {
        (u64::from(seed) + 65_537 * coefficient as u64).rem_euclid(2_147_483_647) as u32
    }))
    .expect("canonical control coordinate")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn mask_oracle_id(label: &[u8], permutations: usize, ordinal: usize) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(MASK_ORACLE_DOMAIN);
    hash.update((label.len() as u16).to_be_bytes());
    hash.update(label);
    hash.update((permutations as u64).to_be_bytes());
    hash.update((ordinal as u32).to_be_bytes());
    hash.finalize().into()
}

fn multilinear_evaluate(mut values: Vec<Fp16>, point: &[Fp16]) -> Result<Fp16, String> {
    if values.len() != 1_usize << point.len() {
        return Err("multilinear_shape".into());
    }
    for challenge in point {
        let half = values.len() / 2;
        for index in 0..half {
            values[index] =
                values[2 * index] + *challenge * (values[2 * index + 1] - values[2 * index]);
        }
        values.truncate(half);
    }
    Ok(values[0])
}

fn load_initial_boundary(
    path: &std::path::Path,
    permutations: usize,
    width: usize,
    instances: usize,
) -> Result<Vec<u64>, String> {
    let encoded = read(path).map_err(|_| "input_read_failed")?;
    decode_initial_boundary(&encoded, permutations, width, instances)
}

fn load_semantic_output_boundary(
    path: &std::path::Path,
    permutations: usize,
    width: usize,
    instances: usize,
) -> Result<Vec<u64>, String> {
    let mut encoded = read(path).map_err(|_| "semantic_output_read_failed")?;
    if encoded.len() < 16
        || encoded.get(..8) != Some(INPUT_MAGIC)
        || usize::from(u16::from_be_bytes(
            encoded[10..12].try_into().map_err(|_| "output_header")?,
        )) != permutations
    {
        return Err("semantic_output_header_invalid".into());
    }
    encoded[10..12].copy_from_slice(&(instances as u16).to_be_bytes());
    let packed = decode_initial_boundary(&encoded, instances, width, instances)?;

    let mut dummy = [0_u64; 25];
    keccak_f1600(&mut dummy);
    let words = instances.div_ceil(64);
    for wire in 0..width {
        let expected = if wire < STATE_BITS {
            (dummy[wire / 64] >> (wire % 64)) & 1
        } else {
            0
        };
        for instance in permutations..instances {
            let observed = (packed[wire * words + instance / 64] >> (instance % 64)) & 1;
            if observed != expected {
                return Err("semantic_output_dummy_lane_invalid".into());
            }
        }
    }
    Ok(packed)
}

fn decode_initial_boundary(
    encoded: &[u8],
    permutations: usize,
    width: usize,
    instances: usize,
) -> Result<Vec<u64>, String> {
    let words = instances.div_ceil(64);
    let payload_bytes = width
        .checked_mul(words)
        .and_then(|values| values.checked_mul(8))
        .ok_or("input_length_overflow")?;
    let expected_bytes = 16_usize
        .checked_add(payload_bytes)
        .ok_or("input_length_overflow")?;
    if encoded.len() != expected_bytes
        || encoded.get(..8) != Some(INPUT_MAGIC)
        || u16::from_be_bytes(encoded[8..10].try_into().map_err(|_| "input_header")?)
            != INPUT_VERSION
        || usize::from(u16::from_be_bytes(
            encoded[10..12].try_into().map_err(|_| "input_header")?,
        )) != permutations
        || usize::from(u16::from_be_bytes(
            encoded[12..14].try_into().map_err(|_| "input_header")?,
        )) != instances
        || usize::from(u16::from_be_bytes(
            encoded[14..16].try_into().map_err(|_| "input_header")?,
        )) != width
    {
        return Err("input_header_or_length_invalid".into());
    }
    let packed = encoded[16..]
        .chunks_exact(8)
        .map(|word| {
            Ok(u64::from_be_bytes(
                word.try_into().map_err(|_| "input_word_invalid")?,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let full_words = permutations / 64;
    let tail_bits = permutations % 64;
    for wire in 0..width {
        let base = wire * words;
        let tail_nonzero = if tail_bits == 0 {
            false
        } else {
            let active_tail_mask = (1_u64 << tail_bits) - 1;
            packed[base + full_words] & !active_tail_mask != 0
        };
        if tail_nonzero
            || packed[base + permutations.div_ceil(64)..base + words]
                .iter()
                .any(|word| *word != 0)
        {
            return Err("input_inactive_lane_nonzero".into());
        }
    }
    if packed[STATE_BITS * words..].iter().any(|word| *word != 0) {
        return Err("input_padding_wire_nonzero".into());
    }
    Ok(packed)
}

fn output_value(
    boundary: &[u64],
    width: usize,
    shard_query: Fp16,
    point: &[Fp16],
    instances: usize,
    group_count: usize,
) -> Result<Fp16, String> {
    let words = instances.div_ceil(64);
    let shard_weights =
        packed_lagrange_node_weights(shard_query).map_err(|error| format!("{error:?}"))?;
    let mut values = Vec::with_capacity(width * group_count);
    for group in 0..group_count {
        let bit = group * PACK_BITS;
        for wire in 0..width {
            let byte = (boundary[wire * words + bit / 64] >> (bit % 64)) as u8;
            values.push((0..PACK_BITS).fold(Fp16::ZERO, |sum, shard| {
                if byte & (1 << shard) != 0 {
                    sum + shard_weights[shard]
                } else {
                    sum
                }
            }));
        }
    }
    multilinear_evaluate(values, point)
}

fn add_polynomial(destination: &mut [Fp16], source: &[Fp16]) -> Result<(), String> {
    if source.len() > destination.len() {
        return Err("polynomial_degree_exceeded".into());
    }
    for (destination, source) in destination.iter_mut().zip(source) {
        *destination = *destination + *source;
    }
    Ok(())
}

fn bind_scaled_gkr_terminals(
    claims: &[LayerOutputClaim],
    shard_query: Fp16,
    wire_variables: u8,
    group_count: usize,
) -> Result<PackedGkrInputClaims, String> {
    let point_variables = usize::from(wire_variables)
        .checked_add(group_count.trailing_zeros() as usize)
        .ok_or("scaled_point_dimension_overflow")?;
    if claims.len() != 2 {
        return Err("scaled_terminal_claim_count".into());
    }
    if claims
        .iter()
        .any(|claim| claim.point.len() != point_variables)
    {
        return Err("scaled_terminal_point_dimension".into());
    }
    if claims.iter().any(|claim| claim.coefficient != Fp16::ONE) {
        return Err("scaled_terminal_coefficient".into());
    }
    Ok(PackedGkrInputClaims {
        claims: core::array::from_fn(|index| MultilinearOpeningClaim {
            point: claims[index].point.clone(),
            value: claims[index].value,
        }),
        shard_query,
        wire_variables,
    })
}

fn run() -> Result<(), String> {
    let group_count = std::env::var_os("BL_GKR_GROUP_COUNT")
        .map(|value| {
            value
                .to_string_lossy()
                .parse::<usize>()
                .map_err(|_| "group_count_invalid")
        })
        .transpose()?
        .unwrap_or(DEFAULT_GROUP_COUNT);
    if group_count == 0 || group_count > MAX_GROUP_COUNT || !group_count.is_power_of_two() {
        return Err("group_count_invalid".into());
    }
    let instances = group_count
        .checked_mul(PACK_BITS)
        .ok_or("instance_count_overflow")?;
    let mut arguments = std::env::args_os().skip(1);
    let python = PathBuf::from(arguments.next().ok_or("python_path_missing")?);
    let worker_script = arguments.next().ok_or("worker_path_missing")?;
    let runtime = arguments.next().ok_or("runtime_path_missing")?;
    let permutations = arguments
        .next()
        .ok_or("permutation_count_missing")?
        .to_string_lossy()
        .parse::<usize>()
        .map_err(|_| "permutation_count_invalid")?;
    let boundary_path = PathBuf::from(arguments.next().ok_or("boundary_path_missing")?);
    let entropy_path = arguments.next().ok_or("entropy_path_missing")?;
    let trailing = arguments.collect::<Vec<_>>();
    let (
        semantic_output_path,
        coefficient_path,
        output_coefficient_path,
        opening_path,
        complete_pcs_inputs,
    ) = match trailing.as_slice() {
        [] => (None, None, None, None, None),
        [output] => (Some(PathBuf::from(output)), None, None, None, None),
        [coefficient, opening] => (
            None,
            Some(PathBuf::from(coefficient)),
            None,
            Some(PathBuf::from(opening)),
            None,
        ),
        [output, coefficient, opening] => (
            Some(PathBuf::from(output)),
            Some(PathBuf::from(coefficient)),
            None,
            Some(PathBuf::from(opening)),
            None,
        ),
        [output, input_coefficient, output_coefficient, opening] => (
            Some(PathBuf::from(output)),
            Some(PathBuf::from(input_coefficient)),
            Some(PathBuf::from(output_coefficient)),
            Some(PathBuf::from(opening)),
            None,
        ),
        [
            output,
            input_coefficient,
            output_coefficient,
            opening,
            input_codeword,
            output_codeword,
        ] => (
            Some(PathBuf::from(output)),
            Some(PathBuf::from(input_coefficient)),
            Some(PathBuf::from(output_coefficient)),
            Some(PathBuf::from(opening)),
            Some(CompletePcsInputs {
                input_codeword: PathBuf::from(input_codeword),
                output_codeword: PathBuf::from(output_codeword),
            }),
        ),
        _ => {
            return Err(
                "usage: <python> <worker.py> <nvrtc-bin> <1..fixed-shape-instances> <boundary-input> ".to_string()
                    + "<entropy-input> [semantic-output-boundary] "
                    + "[input-coefficient-output [output-coefficient-output] opening-output] "
                    + "[input-codeword output-codeword]; optional BL_GKR_GROUP_COUNT=power-of-two<=128",
            );
        }
    };
    if !(1..=instances).contains(&permutations)
        || coefficient_path.is_some() != opening_path.is_some()
    {
        return Err(
            "usage: <python> <worker.py> <nvrtc-bin> <1..fixed-shape-instances> <boundary-input> "
                .to_string()
                + "<entropy-input> [semantic-output-boundary] "
                + "[input-coefficient-output [output-coefficient-output] opening-output] "
                + "[input-codeword output-codeword]; optional BL_GKR_GROUP_COUNT=power-of-two<=128",
        );
    }
    if group_count != DEFAULT_GROUP_COUNT && coefficient_path.is_some() {
        return Err("scaled_group_count_gkr_only".into());
    }
    if output_coefficient_path.is_some() && semantic_output_path.is_none() {
        return Err("semantic_output_required_for_output_coefficients".into());
    }
    if complete_pcs_inputs.is_some()
        && (semantic_output_path.is_none()
            || coefficient_path.is_none()
            || output_coefficient_path.is_none()
            || opening_path.is_none())
    {
        return Err("complete_pcs_requires_dual_boundary_artifacts".into());
    }
    let entropy = read(entropy_path).map_err(|_| "entropy_read_failed")?;
    if entropy.len() != 128 {
        return Err("entropy_length_invalid".into());
    }
    let (secret_seed, session_id) = entropy.split_at(64);
    if !secret_seed.iter().any(|byte| *byte != 0) || !session_id.iter().any(|byte| *byte != 0) {
        return Err("entropy_zero_invalid".into());
    }

    let total = Instant::now();
    let layers = build_keccak_gkr_circuit().map_err(|error| error.to_string())?;
    let input_boundary = load_initial_boundary(
        &boundary_path,
        permutations,
        layers[0].input_width,
        instances,
    )?;
    let boundary_started = Instant::now();
    let checkpoints = packed_keccak_gkr_round_checkpoints(&layers, &input_boundary, instances)
        .map_err(|error| error.to_string())?;
    let boundary_ns = boundary_started.elapsed().as_nanos();
    let checkpoint_payload_bytes = checkpoints
        .iter()
        .map(|checkpoint| checkpoint.len() * size_of::<u64>())
        .sum::<usize>();
    drop(input_boundary);

    let semantic_output = semantic_output_path
        .as_ref()
        .map(|path| {
            load_semantic_output_boundary(
                path,
                permutations,
                layers.last().ok_or("layer_missing")?.padded_width,
                instances,
            )
        })
        .transpose()?;
    if let Some(expected) = &semantic_output
        && checkpoints.last().ok_or("boundary_missing")? != expected
    {
        let actual = checkpoints.last().ok_or("boundary_missing")?;
        let mismatch = actual
            .iter()
            .zip(expected)
            .position(|(left, right)| left != right)
            .ok_or("semantic_output_boundary_length_mismatch")?;
        return Err(format!(
            "semantic_output_boundary_mismatch:word={mismatch}:actual={}:expected={}",
            actual[mismatch], expected[mismatch]
        ));
    }
    let sparse_round_count = layers.iter().try_fold(0_usize, |sum, layer| {
        sum.checked_add(2 * (layer.input_width * group_count).trailing_zeros() as usize)
            .ok_or("sparse_round_count_overflow")
    })?;
    let legacy_authenticated_gkr_round_count = sparse_round_count
        .checked_add(layers.len())
        .and_then(|count| count.checked_add(layers.len() - 1))
        .ok_or("authenticated_round_count_overflow")?;
    let strict_gkr_control = std::env::var_os("BL_STRICT_GKR_CONTROL").is_some();
    let strict_zk = complete_pcs_inputs.is_some() || strict_gkr_control;
    let authenticated_gkr_round_count = if strict_zk {
        legacy_authenticated_gkr_round_count
            .checked_add(2 * layers.len())
            .and_then(|count| count.checked_add(1))
            .ok_or("strict_gkr_round_count_overflow")?
    } else {
        legacy_authenticated_gkr_round_count
    };
    let strict_variable_degrees = layers
        .iter()
        .rev()
        .map(|layer| {
            selected_libra_variable_degrees(
                (layer.input_width * group_count).trailing_zeros() as usize
            )
            .map_err(|error| format!("gkr_zk_degrees:{error:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let strict_layout = CompleteGkrZkMaskCommitmentLayout::new(
        &strict_variable_degrees,
        PACKED_BRIDGE_MASK_COEFFICIENTS,
    )
    .map_err(|error| format!("gkr_zk_layout:{error:?}"))?;
    if strict_layout.padded_coefficients > (1_usize << MLPCS_AUXILIARY_MASK_VARIABLES) {
        return Err("gkr_zk_layout_exceeds_auxiliary_commitment".into());
    }
    let mut strict_auxiliary_coefficients = None;
    let mut strict_bridge_masks = None;
    let mut strict_sumcheck_masks = None;
    let mut strict_layer_masks = None;
    let mut strict_control_commitment: Option<[u8; 64]> = None;
    let (mut prepared_fold, mut auxiliary_hypercube) = if let Some(inputs) =
        complete_pcs_inputs.as_ref()
    {
        let auxiliary_coefficients = sample_extension_trace_mask_coefficients(
            secret_seed,
            session_id,
            &mask_oracle_id(b"pcs-auxiliary", permutations, 0),
            1_usize << MLPCS_AUXILIARY_MASK_VARIABLES,
        )
        .map_err(|error| format!("pcs_auxiliary_sampling_failed:{error:?}"))?;
        let (bridge_masks, sumcheck_masks, layer_masks) = strict_layout
            .decode_prefix(&auxiliary_coefficients)
            .map_err(|error| format!("gkr_zk_mask_decode:{error:?}"))?;
        let hypercube = multilinear_coefficients_to_hypercube(&auxiliary_coefficients)
            .map_err(|error| format!("auxiliary_hypercube:{error:?}"))?;
        let auxiliary = evaluate_univariate_lde(&auxiliary_coefficients, MLPCS_LOG_INVERSE_RATE)
            .map_err(|error| format!("auxiliary_lde:{error:?}"))?;
        strict_auxiliary_coefficients = Some(auxiliary_coefficients);
        strict_bridge_masks = Some(bridge_masks);
        strict_sumcheck_masks = Some(sumcheck_masks);
        strict_layer_masks = Some(layer_masks);
        let prepared = if std::env::var_os("BL_MLPCS_GPU_FOLD").is_some() {
            let gpu_worker =
                PathBuf::from(&worker_script).with_file_name("cuda_mlpcs_fold_worker.py");
            PreparedDualBoundaryFoldCommitments::prepare_files_gpu(
                inputs.input_codeword.clone(),
                inputs.output_codeword.clone(),
                auxiliary,
                python.clone(),
                gpu_worker,
                runtime.clone(),
            )
            .map_err(|error| format!("pcs_gpu_prepare:{error:?}"))?
        } else {
            PreparedDualBoundaryFoldCommitments::prepare_files(
                inputs.input_codeword.clone(),
                inputs.output_codeword.clone(),
                auxiliary,
            )
            .map_err(|error| format!("pcs_prepare:{error:?}"))?
        };
        (Some(prepared), Some(hypercube))
    } else {
        if strict_gkr_control {
            let auxiliary_coefficients = sample_extension_trace_mask_coefficients(
                secret_seed,
                session_id,
                &mask_oracle_id(b"pcs-auxiliary", permutations, 0),
                1_usize << MLPCS_AUXILIARY_MASK_VARIABLES,
            )
            .map_err(|error| format!("strict_control_auxiliary_sampling:{error:?}"))?;
            let (bridge_masks, sumcheck_masks, layer_masks) = strict_layout
                .decode_prefix(&auxiliary_coefficients)
                .map_err(|error| format!("strict_control_mask_decode:{error:?}"))?;
            let mut commitment = Sha3_512::new();
            commitment.update(b"BL/PQ512/WAVE2/STRICT-GKR-CONTROL-MASK-COMMITMENT/v1\0");
            for coefficient in &auxiliary_coefficients {
                commitment.update(coefficient.encode());
            }
            strict_control_commitment = Some(commitment.finalize().into());
            strict_auxiliary_coefficients = Some(auxiliary_coefficients);
            strict_bridge_masks = Some(bridge_masks);
            strict_sumcheck_masks = Some(sumcheck_masks);
            strict_layer_masks = Some(layer_masks);
        }
        (None, None)
    };
    let roots = prepared_fold
        .as_ref()
        .map(PreparedDualBoundaryFoldCommitments::roots);
    let authenticated_round_count = if complete_pcs_inputs.is_some() {
        authenticated_gkr_round_count
            .checked_add(1)
            .and_then(|count| {
                count.checked_add(
                    usize::try_from(INTERACTIVE_DUAL_BOUNDARY_MLPCS_ROUNDS)
                        .map_err(|_| "pcs_round_count")
                        .ok()?,
                )
            })
            .ok_or("complete_authenticated_round_count_overflow")?
    } else if strict_gkr_control {
        authenticated_gkr_round_count
            .checked_add(1)
            .ok_or("strict_control_authenticated_round_count_overflow")?
    } else {
        authenticated_gkr_round_count
    };
    let mut schedule_hash = Sha3_512::new();
    if let Some(roots) = roots {
        schedule_hash.update(COMPLETE_PUBLIC_COIN_SCHEDULE_DOMAIN);
        for root in roots {
            schedule_hash.update(root.as_bytes());
        }
        schedule_hash.update(INTERACTIVE_DUAL_BOUNDARY_MLPCS_ROUNDS.to_be_bytes());
        schedule_hash.update(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE.to_be_bytes());
        schedule_hash.update(MLPCS_LDE_LOG_SIZE.to_be_bytes());
        schedule_hash.update(MLPCS_AUXILIARY_LDE_LOG_SIZE.to_be_bytes());
    } else if let Some(commitment) = strict_control_commitment {
        schedule_hash.update(COMPLETE_PUBLIC_COIN_SCHEDULE_DOMAIN);
        schedule_hash.update(b"STRICT-GKR-CONTROL\0");
        schedule_hash.update(commitment);
    } else {
        schedule_hash.update(SPARSE_PUBLIC_COIN_SCHEDULE_DOMAIN);
    }
    schedule_hash.update((layers.len() as u32).to_be_bytes());
    schedule_hash.update((authenticated_round_count as u32).to_be_bytes());
    for layer in &layers {
        schedule_hash.update((layer.input_width as u32).to_be_bytes());
        schedule_hash.update((layer.raw_width as u32).to_be_bytes());
        schedule_hash.update((layer.padded_width as u32).to_be_bytes());
    }
    let schedule_commitment: [u8; 64] = schedule_hash.finalize().into();
    #[cfg(not(feature = "bench_fixture_coin"))]
    let public_coin_inner = {
        let service_path = std::env::current_exe()
            .map_err(|_| "public_coin_current_exe")?
            .parent()
            .ok_or("public_coin_exe_parent")?
            .join("chained_public_coin_service.exe");
        ActivePublicCoinCoordinator::spawn(
            &service_path,
            session_id
                .try_into()
                .map_err(|_| "public_coin_session_id")?,
            0,
            schedule_commitment,
            u32::try_from(authenticated_round_count).map_err(|_| "public_coin_round_count")?,
        )
        .map_err(|error| format!("public_coin_spawn:{error:?}"))?
    };
    #[cfg(feature = "bench_fixture_coin")]
    let public_coin_inner = ActivePublicCoinCoordinator::new(
        session_id
            .try_into()
            .map_err(|_| "public_coin_session_id")?,
        0,
        schedule_commitment,
        u32::try_from(authenticated_round_count).map_err(|_| "public_coin_round_count")?,
    )
    .map_err(|error| format!("bench_fixture_coin_init:{error}"))?;
    let public_coin = RefCell::new(MeasuredPublicCoin::new(public_coin_inner));
    let output_width = layers.last().ok_or("layer_missing")?.padded_width * group_count;
    let output_variables = output_width.trailing_zeros() as usize;
    let (output_shard_query, output_point, initial_public_coin_rounds) = if let Some(roots) = roots
    {
        let mut message = Vec::with_capacity(OUTPUT_QUERY_MESSAGE_DOMAIN.len() + 3 * 64 + 16);
        message.extend_from_slice(OUTPUT_QUERY_MESSAGE_DOMAIN);
        for root in roots {
            message.extend_from_slice(root.as_bytes());
        }
        message.extend_from_slice(&(permutations as u32).to_be_bytes());
        message.extend_from_slice(&(output_width as u32).to_be_bytes());
        message.extend_from_slice(&(layers.len() as u32).to_be_bytes());
        let output_count = u16::try_from(output_variables + 1).map_err(|_| "output_query_shape")?;
        let query = public_coin
            .borrow_mut()
            .challenge(
                ChainedRoundDescriptor {
                    kind: 0x1000,
                    ordinal: 0,
                    output_count,
                },
                &message,
            )
            .map_err(|error| format!("public_coin_output_query:{error:?}"))?;
        if query.len() != output_variables + 1 {
            return Err("public_coin_output_query_shape".into());
        }
        (query[0], query[1..].to_vec(), 1_u32)
    } else if let Some(commitment) = strict_control_commitment {
        let mut message =
            Vec::with_capacity(OUTPUT_QUERY_MESSAGE_DOMAIN.len() + commitment.len() + 16);
        message.extend_from_slice(OUTPUT_QUERY_MESSAGE_DOMAIN);
        message.extend_from_slice(&commitment);
        message.extend_from_slice(&(permutations as u32).to_be_bytes());
        message.extend_from_slice(&(output_width as u32).to_be_bytes());
        message.extend_from_slice(&(layers.len() as u32).to_be_bytes());
        let output_count = u16::try_from(output_variables + 1).map_err(|_| "output_query_shape")?;
        let query = public_coin
            .borrow_mut()
            .challenge(
                ChainedRoundDescriptor {
                    kind: 0x1000,
                    ordinal: 0,
                    output_count,
                },
                &message,
            )
            .map_err(|error| format!("strict_control_output_query:{error:?}"))?;
        if query.len() != output_variables + 1 {
            return Err("strict_control_output_query_shape".into());
        }
        (query[0], query[1..].to_vec(), 1_u32)
    } else {
        (
            fp16(10_001),
            (0..output_variables)
                .map(|index| {
                    if semantic_output.is_none() && matches!(index, 9 | 10) {
                        Fp16::ZERO
                    } else {
                        fp16(10_101 + 7 * index as u32)
                    }
                })
                .collect::<Vec<_>>(),
            0_u32,
        )
    };
    let expected_output = output_value(
        semantic_output
            .as_ref()
            .unwrap_or(checkpoints.last().ok_or("boundary_missing")?),
        layers.last().ok_or("layer_missing")?.padded_width,
        output_shard_query,
        &output_point,
        instances,
        group_count,
    )?;
    let table = PackedBooleanTable::build().map_err(|error| error.to_string())?;
    verify_pinned_gkr_cuda_bundle(Path::new(&worker_script))
        .map_err(|error| format!("gkr_cuda_bundle:{error:?}"))?;
    let worker_arguments = [OsString::from("-I"), worker_script, runtime]
        .into_iter()
        .collect::<Vec<_>>();
    let mut worker = BoundedGkrWorker::spawn(
        &python,
        &worker_arguments,
        layers.len(),
        Duration::from_secs(30),
    )
    .map_err(|error| format!("{error:?}"))?;
    let proof_started = Instant::now();
    let mut claims = vec![LayerOutputClaim {
        point: output_point.clone(),
        value: expected_output,
        coefficient: Fp16::ONE,
    }];
    let mut raw_claims = claims.clone();
    let mut gkr_mask_constraints = Vec::<GkrMaskConstraint>::new();
    let mut strict_layer_transcripts = Vec::<StrictGkrLayerTranscript>::new();
    let mut gkr_mask_hypercube_weights = None;
    let mut gkr_mask_opening = Fp16::ZERO;
    let mut shard_query = output_shard_query;
    let mut gpu_ns = 0_u128;
    let mut gpu_layer_ns = Vec::with_capacity(layers.len());
    let mut strict_bridge_provider_ns = 0_u128;
    let mut strict_round_provider_ns = 0_u128;
    let mut verify_ns = 0_u128;
    let mut parity_ns = 0_u128;
    let mut strict_mask_aggregate_ns = 0_u128;
    let mut cpu_gpu_packed_equal = false;
    let mut digest = Sha3_512::new();
    let public_coin_ordinal = Cell::new(initial_public_coin_rounds);
    let cpu_bridge_worker_count = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1);
    let mut regenerated_round = usize::MAX;
    let mut regenerated_round_inputs = Vec::new();
    let mut boundary_regeneration_ns = 0_u128;
    let mut regenerated_round_peak_bytes = 0_usize;
    for (proof_index, layer_index) in (0..layers.len()).rev().enumerate() {
        let round = layer_index / KECCAK_GKR_LAYERS_PER_ROUND;
        if round != regenerated_round {
            let regeneration_started = Instant::now();
            let first_layer = round * KECCAK_GKR_LAYERS_PER_ROUND;
            regenerated_round_inputs = regenerate_packed_keccak_gkr_round_inputs(
                &layers[first_layer..first_layer + KECCAK_GKR_LAYERS_PER_ROUND],
                checkpoints.get(round).ok_or("round_checkpoint_missing")?,
                instances,
            )
            .map_err(|error| error.to_string())?;
            boundary_regeneration_ns += regeneration_started.elapsed().as_nanos();
            regenerated_round_peak_bytes = regenerated_round_peak_bytes.max(
                regenerated_round_inputs
                    .iter()
                    .map(|boundary| boundary.len() * size_of::<u64>())
                    .sum(),
            );
            regenerated_round = round;
        }
        let layer_boundary = regenerated_round_inputs
            .get(layer_index % KECCAK_GKR_LAYERS_PER_ROUND)
            .ok_or("regenerated_layer_boundary_missing")?;
        let layer = &layers[layer_index];
        let input_variables = (layer.input_width * group_count).trailing_zeros() as usize;
        let sparse_rounds = 2 * input_variables;
        let wire_variables = layer.padded_width.trailing_zeros() as usize;
        let (base_left, base_right, base_formula) =
            repeated_pack_compact_layer_geometry(layer).map_err(|error| format!("{error:?}"))?;
        if strict_zk {
            let incoming_claims = claims.clone();
            let compact_point_claims = claims
                .iter()
                .map(|claim| GkrCompactPointClaim {
                    coefficient: claim.coefficient,
                    point: &claim.point,
                })
                .collect::<Vec<_>>();
            let point_request = GkrCompactPointWorkerRequest {
                packed_input: layer_boundary,
                instances,
                input_width: layer.input_width,
                raw_width: layer.raw_width,
                claim_wire_variables: wire_variables,
                base_left: &base_left,
                base_right: &base_right,
                base_formula: &base_formula,
                claims: &compact_point_claims,
            };
            let bridge_masks = strict_bridge_masks
                .as_ref()
                .ok_or("strict_bridge_masks_missing")?;
            let sumcheck_masks = strict_sumcheck_masks
                .as_ref()
                .ok_or("strict_sumcheck_masks_missing")?;
            let layer_masks = strict_layer_masks
                .as_ref()
                .ok_or("strict_layer_masks_missing")?;
            let bridge_mask = bridge_masks
                .get(proof_index)
                .ok_or("strict_bridge_mask_missing")?;
            let sumcheck_mask = sumcheck_masks
                .get(proof_index)
                .ok_or("strict_sumcheck_mask_missing")?;
            let layer_mask = layer_masks
                .get(proof_index)
                .ok_or("strict_layer_mask_missing")?;
            let prior_correction = if proof_index == 0 {
                LibraPriorLayerCorrection::zero()
            } else {
                LibraPriorLayerCorrection::from_claims(
                    &layer_masks[proof_index - 1],
                    &claims
                        .iter()
                        .map(|claim| (claim.coefficient, claim.point.clone()))
                        .collect::<Vec<_>>(),
                )
                .map_err(|error| format!("strict_prior_correction:{error:?}"))?
            };
            let raw_initial_claim = raw_claims.iter().fold(Fp16::ZERO, |sum, claim| {
                sum + claim.coefficient * claim.value
            });
            let masked_initial_claim = claims.iter().fold(Fp16::ZERO, |sum, claim| {
                sum + claim.coefficient * claim.value
            });
            if raw_initial_claim + prior_correction.boolean_sum() != masked_initial_claim {
                return Err(format!("strict_incoming_mask_relation:{proof_index}"));
            }
            let rho_message = [
                b"BL/PQ512/WAVE2/GKR-LIBRA-RHO/v1\0".as_slice(),
                &(proof_index as u32).to_be_bytes(),
                &(layer_index as u32).to_be_bytes(),
            ]
            .concat();
            let rho_ordinal = public_coin_ordinal.get();
            let rhos = public_coin
                .borrow_mut()
                .challenge(
                    ChainedRoundDescriptor {
                        kind: 0x1010,
                        ordinal: rho_ordinal,
                        output_count: 2,
                    },
                    &rho_message,
                )
                .map_err(|error| format!("strict_rho_public_coin:{error:?}"))?;
            public_coin_ordinal.set(rho_ordinal + 1);
            let [bridge_rho, sumcheck_rho]: [Fp16; 2] =
                rhos.try_into().map_err(|_| "strict_rho_shape")?;
            if bridge_rho.is_zero() || sumcheck_rho.is_zero() {
                return Err(format!("strict_zero_rho:{proof_index}"));
            }

            let public_bridge = RefCell::new(None);
            let bridge_challenge = Cell::new(None);
            let sumcheck_state = RefCell::new(None);
            let public_coin_error = RefCell::new(None);
            let terminal_left_delta = Cell::new(None);
            let correction_sum = prior_correction.boolean_sum();
            let bridge_selector = packed_selector_polynomial(shard_query)
                .map_err(|error| format!("strict_bridge_selector:{error:?}"))?;
            let mut bridge_provider = |raw_polynomial: [Fp16; OUTPUT_COEFFICIENTS]| {
                let bridge_provider_started = Instant::now();
                let mut polynomial = raw_polynomial;
                for (coefficient, selector) in polynomial.iter_mut().zip(bridge_selector) {
                    *coefficient = *coefficient + correction_sum * selector;
                }
                for (coefficient, mask) in polynomial.iter_mut().zip(bridge_mask) {
                    *coefficient = *coefficient + bridge_rho * *mask;
                }
                let mut message = Vec::with_capacity(OUTPUT_COEFFICIENTS * FP16_ENCODED_LENGTH);
                for value in polynomial {
                    message.extend_from_slice(&value.encode());
                }
                let ordinal = public_coin_ordinal.get();
                let challenge = match public_coin.borrow_mut().scalar_challenge(
                    ChainedRoundDescriptor {
                        kind: 0x1011,
                        ordinal,
                        output_count: 1,
                    },
                    &message,
                ) {
                    Ok(challenge) => challenge,
                    Err(error) => {
                        *public_coin_error.borrow_mut() = Some(format!("{error:?}"));
                        return Err(GkrWorkerError::ChallengeProvider);
                    }
                };
                public_coin_ordinal.set(ordinal + 1);
                let raw_gate_claim = verify_packed_first_round_bridge(
                    raw_initial_claim,
                    &raw_polynomial,
                    shard_query,
                    challenge,
                )
                .map_err(|_| GkrWorkerError::ChallengeProvider)?
                .gate_claim;
                let state = CommittedMaskedSumcheckState::new(
                    raw_gate_claim,
                    correction_sum,
                    sumcheck_mask.boolean_sum(),
                    sumcheck_rho,
                    sumcheck_mask.variable_degrees(),
                )
                .map_err(|_| GkrWorkerError::ChallengeProvider)?;
                *public_bridge.borrow_mut() = Some(polynomial);
                bridge_challenge.set(Some(challenge));
                *sumcheck_state.borrow_mut() = Some(state);
                strict_bridge_provider_ns += bridge_provider_started.elapsed().as_nanos();
                Ok(challenge)
            };
            let sparse_challenges = RefCell::new(Vec::with_capacity(sparse_rounds + 1));
            let public_rounds = RefCell::new(Vec::<Vec<Fp16>>::with_capacity(sparse_rounds + 1));
            let mut round_provider = |round: usize, raw: [Fp16; 3], sensitivity: [Fp16; 3]| {
                let round_provider_started = Instant::now();
                let prefix = sparse_challenges.borrow();
                if round != prefix.len() {
                    return Err(GkrWorkerError::ChallengeProvider);
                }
                let mut base = vec![Fp16::ZERO; strict_variable_degrees[proof_index][round] + 1];
                base[..3].copy_from_slice(&raw);
                add_polynomial(&mut base, &prior_correction.xy_round_polynomial(&prefix))
                    .map_err(|_| GkrWorkerError::ChallengeProvider)?;
                let final_left = round + 1 == input_variables;
                let final_right = round + 1 == sparse_rounds;
                if final_left || final_right {
                    let side_prefix = if final_left {
                        &prefix[..input_variables - 1]
                    } else {
                        &prefix[input_variables..sparse_rounds - 1]
                    };
                    let vanishing = terminal_vanishing_coefficient(layer_mask, side_prefix)
                        .map_err(|_| GkrWorkerError::ChallengeProvider)?;
                    let cubic = [
                        Fp16::ZERO,
                        sensitivity[0] * vanishing,
                        sensitivity[1] * vanishing,
                        sensitivity[2] * vanishing,
                    ];
                    add_polynomial(&mut base, &cubic)
                        .map_err(|_| GkrWorkerError::ChallengeProvider)?;
                }
                let mask = sumcheck_mask
                    .round_polynomial(&prefix, round)
                    .map_err(|_| GkrWorkerError::ChallengeProvider)?;
                let published = sumcheck_state
                    .borrow_mut()
                    .as_mut()
                    .ok_or(GkrWorkerError::ChallengeProvider)?
                    .publish_round(&base, &mask, sumcheck_rho)
                    .map_err(|_| GkrWorkerError::ChallengeProvider)?;
                drop(prefix);
                let mut message = Vec::with_capacity(published.len() * FP16_ENCODED_LENGTH);
                for value in &published {
                    message.extend_from_slice(&value.encode());
                }
                let ordinal = public_coin_ordinal.get();
                let challenge = match public_coin.borrow_mut().scalar_challenge(
                    ChainedRoundDescriptor {
                        kind: 0x1012,
                        ordinal,
                        output_count: 1,
                    },
                    &message,
                ) {
                    Ok(challenge) => challenge,
                    Err(error) => {
                        *public_coin_error.borrow_mut() = Some(format!("{error:?}"));
                        return Err(GkrWorkerError::ChallengeProvider);
                    }
                };
                public_coin_ordinal.set(ordinal + 1);
                sumcheck_state
                    .borrow_mut()
                    .as_mut()
                    .ok_or(GkrWorkerError::ChallengeProvider)?
                    .accept_authenticated_challenge(challenge)
                    .map_err(|_| GkrWorkerError::ChallengeProvider)?;
                public_rounds.borrow_mut().push(published);
                sparse_challenges.borrow_mut().push(challenge);
                let delta = if final_left {
                    let full_vanishing = terminal_vanishing_coefficient(
                        layer_mask,
                        &sparse_challenges.borrow()[..input_variables],
                    )
                    .map_err(|_| GkrWorkerError::ChallengeProvider)?;
                    terminal_left_delta.set(Some(full_vanishing));
                    Some(full_vanishing)
                } else {
                    None
                };
                strict_round_provider_ns += round_provider_started.elapsed().as_nanos();
                Ok((challenge, delta))
            };
            let gpu_started = Instant::now();
            let worker_result = worker.run_compact_point_libra_session_with_public_coin_providers(
                &point_request,
                &table,
                raw_initial_claim,
                shard_query,
                &mut bridge_provider,
                &mut round_provider,
                Duration::from_secs(30),
            );
            let (worker_output, raw_polynomial, _) = worker_result.map_err(|error| {
                public_coin_error.borrow_mut().take().unwrap_or_else(|| {
                    format!("strict_gkr_worker:{proof_index}:{layer_index}:{error:?}")
                })
            })?;
            let layer_gpu_ns = gpu_started.elapsed().as_nanos();
            gpu_ns += layer_gpu_ns;
            gpu_layer_ns.push(layer_gpu_ns);
            let bridge_challenge = bridge_challenge
                .get()
                .ok_or("strict_bridge_challenge_missing")?;
            let public_bridge = public_bridge
                .into_inner()
                .ok_or("strict_public_bridge_missing")?;
            let mut challenges = sparse_challenges.into_inner();
            let mut rounds = public_rounds.into_inner();
            if challenges[..input_variables]
                .first()
                .zip(challenges[input_variables..].first())
                .is_some_and(|(left, right)| left == right)
            {
                return Err(format!(
                    "strict_libra_equal_first_coordinates:{proof_index}"
                ));
            }
            let right_delta =
                terminal_vanishing_coefficient(layer_mask, &challenges[input_variables..])
                    .map_err(|error| format!("strict_right_terminal_mask:{error:?}"))?;
            let left_delta = terminal_left_delta
                .get()
                .ok_or("strict_left_terminal_mask_missing")?;
            let terminal_left = worker_output.terminal_left;
            let terminal_right = worker_output.terminal_right + right_delta;
            let raw_terminal_left = terminal_left - left_delta;
            let raw_terminal_right = worker_output.terminal_right;
            let terminal_gate = repeated_pack_terminal_gate_claim(
                layer,
                group_count,
                &claims,
                &challenges[..input_variables],
                &challenges[input_variables..],
                terminal_left,
                terminal_right,
            )
            .map_err(|error| format!("strict_terminal_gate:{error:?}"))?;
            let mut w_base = prior_correction.w_round_polynomial(&challenges);
            w_base[0] = w_base[0] + terminal_gate;
            w_base[1] = w_base[1] - terminal_gate;
            let w_mask = sumcheck_mask
                .round_polynomial(&challenges, sparse_rounds)
                .map_err(|error| format!("strict_w_mask:{error:?}"))?;
            let folded_base_claim = sumcheck_state
                .borrow()
                .as_ref()
                .ok_or("strict_sumcheck_state_missing")?
                .current_claim()
                - sumcheck_rho
                    * (polynomial_evaluation(&w_mask, Fp16::ZERO)
                        + polynomial_evaluation(&w_mask, Fp16::ONE));
            let w_base_sum = polynomial_evaluation(&w_base, Fp16::ZERO)
                + polynomial_evaluation(&w_base, Fp16::ONE);
            if folded_base_claim != w_base_sum {
                return Err(format!("strict_w_base_recurrence:{proof_index}"));
            }
            let w_published = sumcheck_state
                .borrow_mut()
                .as_mut()
                .ok_or("strict_sumcheck_state_missing")?
                .publish_round(&w_base, &w_mask, sumcheck_rho)
                .map_err(|error| format!("strict_w_publish:{error:?}"))?;
            let mut w_message = Vec::with_capacity((w_published.len() + 2) * FP16_ENCODED_LENGTH);
            for value in &w_published {
                w_message.extend_from_slice(&value.encode());
            }
            w_message.extend_from_slice(&terminal_left.encode());
            w_message.extend_from_slice(&terminal_right.encode());
            let w_ordinal = public_coin_ordinal.get();
            let w_challenge = public_coin
                .borrow_mut()
                .scalar_challenge(
                    ChainedRoundDescriptor {
                        kind: 0x1013,
                        ordinal: w_ordinal,
                        output_count: 1,
                    },
                    &w_message,
                )
                .map_err(|error| format!("strict_w_public_coin:{error:?}"))?;
            public_coin_ordinal.set(w_ordinal + 1);
            sumcheck_state
                .borrow_mut()
                .as_mut()
                .ok_or("strict_sumcheck_state_missing")?
                .accept_authenticated_challenge(w_challenge)
                .map_err(|error| format!("strict_w_challenge:{error:?}"))?;
            rounds.push(w_published.clone());
            challenges.push(w_challenge);
            let base_oracle = polynomial_evaluation(&w_base, w_challenge);
            let mask_oracle = sumcheck_mask
                .evaluate(&challenges)
                .map_err(|error| format!("strict_mask_oracle:{error:?}"))?;
            sumcheck_state
                .into_inner()
                .ok_or("strict_sumcheck_state_missing")?
                .finish(base_oracle, mask_oracle, sumcheck_rho)
                .map_err(|error| format!("strict_sumcheck_finish:{error:?}"))?;

            let first_sum = polynomial_evaluation(&rounds[0], Fp16::ZERO)
                + polynomial_evaluation(&rounds[0], Fp16::ONE);
            let shard_nodes = (0..PACK_BITS)
                .map(|node| {
                    Ok(Fp16::from_m31(
                        M31::from_canonical(node as u32)
                            .map_err(|_| "strict_shard_node_noncanonical")?,
                    ))
                })
                .collect::<Result<Vec<_>, String>>()?;
            let public_node_sum = shard_nodes.iter().copied().fold(Fp16::ZERO, |sum, node| {
                sum + polynomial_evaluation(&public_bridge, node)
            });
            gkr_mask_constraints.push(GkrMaskConstraint {
                functionals: shard_nodes
                    .iter()
                    .copied()
                    .map(|point| GkrMaskFunctional::BridgeEvaluation {
                        layer: proof_index,
                        point,
                        scale: bridge_rho,
                    })
                    .collect(),
                residual: public_node_sum - masked_initial_claim,
            });
            let selector_at_challenge = polynomial_evaluation(&bridge_selector, bridge_challenge);
            let selector_inverse = selector_at_challenge
                .inverse()
                .map_err(|_| "strict_bridge_selector_zero")?;
            gkr_mask_constraints.push(GkrMaskConstraint {
                functionals: vec![
                    GkrMaskFunctional::SumcheckBooleanSum {
                        layer: proof_index,
                        scale: sumcheck_rho,
                    },
                    GkrMaskFunctional::BridgeEvaluation {
                        layer: proof_index,
                        point: bridge_challenge,
                        scale: -bridge_rho * selector_inverse,
                    },
                ],
                residual: first_sum
                    - polynomial_evaluation(&public_bridge, bridge_challenge) * selector_inverse,
            });
            let equality_zero = challenges[..sparse_rounds]
                .iter()
                .fold(Fp16::ONE, |value, coordinate| {
                    value * (Fp16::ONE - *coordinate)
                });
            let mut final_functionals = vec![GkrMaskFunctional::SumcheckEvaluation {
                layer: proof_index,
                point: challenges.clone(),
                scale: sumcheck_rho,
            }];
            if proof_index != 0 {
                for claim in &claims {
                    final_functionals.push(GkrMaskFunctional::LayerEvaluation {
                        layer: proof_index - 1,
                        z_first: claim.point[0],
                        w: w_challenge,
                        scale: equality_zero * claim.coefficient * boolean_vanishing(&claim.point),
                    });
                }
            }
            gkr_mask_constraints.push(GkrMaskConstraint {
                functionals: final_functionals,
                residual: polynomial_evaluation(
                    rounds.last().ok_or("strict_w_round_missing")?,
                    w_challenge,
                ) - (Fp16::ONE - w_challenge) * terminal_gate,
            });
            strict_layer_transcripts.push(StrictGkrLayerTranscript {
                proof_index,
                layer_index,
                incoming_claims,
                shard_query,
                bridge_rho,
                sumcheck_rho,
                public_bridge,
                bridge_challenge,
                rounds: rounds.clone(),
                challenges: challenges.clone(),
                terminal_left,
                terminal_right,
                terminal_gate,
            });

            if proof_index == 0 {
                let parity_started = Instant::now();
                let (cpu_polynomial, _, _) = prove_repeated_pack_layer_bridge_parallel(
                    &table,
                    layer,
                    layer_boundary,
                    instances,
                    &raw_claims,
                    shard_query,
                    bridge_challenge,
                    cpu_bridge_worker_count,
                )
                .map_err(|error| format!("{error:?}"))?;
                parity_ns += parity_started.elapsed().as_nanos();
                if cpu_polynomial != raw_polynomial {
                    return Err("strict_cpu_gpu_raw_packed_polynomial_mismatch".into());
                }
                cpu_gpu_packed_equal = true;
            }
            for coefficient in public_bridge {
                digest.update(coefficient.encode());
            }
            for round in &rounds {
                for coefficient in round {
                    digest.update(coefficient.encode());
                }
            }
            digest.update(terminal_left.encode());
            digest.update(terminal_right.encode());

            let mix = if layer_index == 0 {
                Fp16::ONE
            } else {
                let mut message = Vec::new();
                for value in public_bridge {
                    message.extend_from_slice(&value.encode());
                }
                for round in &rounds {
                    for value in round {
                        message.extend_from_slice(&value.encode());
                    }
                }
                message.extend_from_slice(&terminal_left.encode());
                message.extend_from_slice(&terminal_right.encode());
                let ordinal = public_coin_ordinal.get();
                let challenge = public_coin
                    .borrow_mut()
                    .scalar_challenge(
                        ChainedRoundDescriptor {
                            kind: 0x1014,
                            ordinal,
                            output_count: 1,
                        },
                        &message,
                    )
                    .map_err(|error| format!("strict_mix_public_coin:{error:?}"))?;
                public_coin_ordinal.set(ordinal + 1);
                challenge
            };
            claims = vec![
                LayerOutputClaim {
                    point: challenges[..input_variables].to_vec(),
                    value: terminal_left,
                    coefficient: mix,
                },
                LayerOutputClaim {
                    point: challenges[input_variables..sparse_rounds].to_vec(),
                    value: terminal_right,
                    coefficient: if layer_index == 0 {
                        Fp16::ONE
                    } else {
                        Fp16::ONE - mix
                    },
                },
            ];
            raw_claims = vec![
                LayerOutputClaim {
                    point: claims[0].point.clone(),
                    value: raw_terminal_left,
                    coefficient: claims[0].coefficient,
                },
                LayerOutputClaim {
                    point: claims[1].point.clone(),
                    value: raw_terminal_right,
                    coefficient: claims[1].coefficient,
                },
            ];
            shard_query = bridge_challenge;
            continue;
        }
        let wire_tables = claims
            .iter()
            .map(|claim| {
                multilinear_equality_table(&claim.point[..wire_variables])
                    .map_err(|error| format!("{error:?}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let group_tables = claims
            .iter()
            .map(|claim| {
                multilinear_equality_table(&claim.point[wire_variables..])
                    .map_err(|error| format!("{error:?}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let compact_claims = claims
            .iter()
            .enumerate()
            .map(|(index, claim)| GkrCompactClaimWeights {
                coefficient: claim.coefficient,
                wire: &wire_tables[index][..layer.raw_width],
                group: &group_tables[index],
            })
            .collect::<Vec<_>>();
        let placeholder_interpolation_weights = [Fp16::ZERO; PACK_BITS];
        let request = GkrCompactWorkerRequest {
            packed_input: layer_boundary,
            instances,
            input_width: layer.input_width,
            interpolation_weights: &placeholder_interpolation_weights,
            raw_width: layer.raw_width,
            base_left: &base_left,
            base_right: &base_right,
            base_formula: &base_formula,
            claims: &compact_claims,
        };
        let sampled_masks = sample_extension_trace_mask_coefficients(
            secret_seed,
            session_id,
            &mask_oracle_id(b"gkr-layer", permutations, layer_index),
            2 * sparse_rounds,
        )
        .map_err(|error| format!("gkr_mask_sampling_failed:{error:?}"))?;
        let masks = sampled_masks
            .chunks_exact(2)
            .map(|pair| [pair[0], pair[1]])
            .collect::<Vec<_>>();
        let initial_claim = claims.iter().fold(Fp16::ZERO, |sum, claim| {
            sum + claim.coefficient * claim.value
        });
        let gpu_started = Instant::now();
        let mut sparse_challenges = Vec::with_capacity(sparse_rounds);
        let public_coin_error = RefCell::new(None);
        let bridge_challenge = Cell::new(None);
        let mut bridge_provider = |polynomial: [Fp16; OUTPUT_COEFFICIENTS]| {
            let mut encoded_message = Vec::with_capacity(polynomial.len() * 64);
            for value in polynomial {
                encoded_message.extend_from_slice(&value.encode());
            }
            let ordinal = public_coin_ordinal.get();
            let descriptor = ChainedRoundDescriptor {
                kind: 0x1001,
                ordinal,
                output_count: 1,
            };
            match public_coin
                .borrow_mut()
                .scalar_challenge(descriptor, &encoded_message)
            {
                Ok(challenge) => {
                    bridge_challenge.set(Some(challenge));
                    public_coin_ordinal.set(ordinal + 1);
                    Ok(challenge)
                }
                Err(error) => {
                    *public_coin_error.borrow_mut() = Some(format!("{error:?}"));
                    Err(GkrWorkerError::ChallengeProvider)
                }
            }
        };
        let worker_result = {
            let mut challenge_provider = |round: usize, message: [Fp16; 3]| {
                if round != sparse_challenges.len() {
                    return Err(GkrWorkerError::ChallengeProvider);
                }
                let mut encoded_message = Vec::with_capacity(3 * 64);
                for value in message {
                    encoded_message.extend_from_slice(&value.encode());
                }
                let descriptor = ChainedRoundDescriptor {
                    kind: 0x1002,
                    ordinal: public_coin_ordinal.get(),
                    output_count: 1,
                };
                match public_coin
                    .borrow_mut()
                    .scalar_challenge(descriptor, &encoded_message)
                {
                    Ok(challenge) => {
                        sparse_challenges.push(challenge);
                        public_coin_ordinal.set(public_coin_ordinal.get() + 1);
                        Ok(challenge)
                    }
                    Err(error) => {
                        *public_coin_error.borrow_mut() = Some(format!("{error:?}"));
                        Err(GkrWorkerError::ChallengeProvider)
                    }
                }
            };
            worker.run_compact_session_with_public_coin_providers(
                &request,
                &table,
                initial_claim,
                shard_query,
                sparse_rounds,
                &masks,
                &mut bridge_provider,
                &mut challenge_provider,
                Duration::from_secs(30),
            )
        };
        let (masked, polynomial, _) = worker_result.map_err(|error| {
            public_coin_error
                .borrow_mut()
                .take()
                .unwrap_or_else(|| format!("gkr_worker:{error:?}"))
        })?;
        let bridge_challenge = bridge_challenge
            .get()
            .ok_or("authenticated_bridge_challenge_missing")?;
        gpu_ns += gpu_started.elapsed().as_nanos();
        if proof_index == 0 {
            let parity_started = Instant::now();
            let (cpu_polynomial, _, _) = prove_repeated_pack_layer_bridge_parallel(
                &table,
                layer,
                layer_boundary,
                instances,
                &claims,
                shard_query,
                bridge_challenge,
                cpu_bridge_worker_count,
            )
            .map_err(|error| format!("{error:?}"))?;
            parity_ns += parity_started.elapsed().as_nanos();
            if cpu_polynomial != polynomial {
                return Err("cpu_gpu_packed_polynomial_mismatch".into());
            }
            cpu_gpu_packed_equal = true;
        }
        let verify_started = Instant::now();
        verify_masked_repeated_pack_keccak_layer_claims_control(
            layer,
            group_count,
            &claims,
            shard_query,
            bridge_challenge,
            &sparse_challenges,
            &polynomial,
            &masked,
        )
        .map_err(|error| format!("{error:?}"))?;
        verify_ns += verify_started.elapsed().as_nanos();
        for coefficient in polynomial {
            digest.update(coefficient.encode());
        }
        for round in &masked.rounds {
            for coefficient in round {
                digest.update(coefficient.encode());
            }
        }
        digest.update(masked.terminal_correction.encode());
        let mix = if layer_index == 0 {
            Fp16::ONE
        } else {
            let mut mix_message =
                Vec::with_capacity((OUTPUT_COEFFICIENTS + 3 * masked.rounds.len() + 3) * 64);
            for value in polynomial {
                mix_message.extend_from_slice(&value.encode());
            }
            for round in &masked.rounds {
                for value in round {
                    mix_message.extend_from_slice(&value.encode());
                }
            }
            for value in [
                masked.terminal_left,
                masked.terminal_right,
                masked.terminal_correction,
            ] {
                mix_message.extend_from_slice(&value.encode());
            }
            let ordinal = public_coin_ordinal.get();
            let challenge = public_coin
                .borrow_mut()
                .scalar_challenge(
                    ChainedRoundDescriptor {
                        kind: 0x1003,
                        ordinal,
                        output_count: 1,
                    },
                    &mix_message,
                )
                .map_err(|error| format!("public_coin_mix:{error:?}"))?;
            public_coin_ordinal.set(ordinal + 1);
            challenge
        };
        claims = vec![
            LayerOutputClaim {
                point: sparse_challenges[..input_variables].to_vec(),
                value: masked.terminal_left,
                coefficient: mix,
            },
            LayerOutputClaim {
                point: sparse_challenges[input_variables..].to_vec(),
                value: masked.terminal_right,
                coefficient: if layer_index == 0 {
                    Fp16::ONE
                } else {
                    Fp16::ONE - mix
                },
            },
        ];
        shard_query = bridge_challenge;
    }
    if strict_zk {
        let strict_mask_aggregate_started = Instant::now();
        let bottom_mask_layer = layers.len() - 1;
        for (masked, raw) in claims.iter().zip(&raw_claims) {
            if masked.point != raw.point || masked.coefficient != raw.coefficient {
                return Err("strict_bottom_claim_shape".into());
            }
            gkr_mask_constraints.push(GkrMaskConstraint {
                functionals: vec![GkrMaskFunctional::LayerBooleanSum {
                    layer: bottom_mask_layer,
                    z_first: masked.point[0],
                    scale: boolean_vanishing(&masked.point),
                }],
                residual: masked.value - raw.value,
            });
        }
        let online_constraints = std::mem::take(&mut gkr_mask_constraints);
        let mut reconstructed_constraints = Vec::with_capacity(online_constraints.len());
        let shard_nodes = (0..PACK_BITS)
            .map(|node| {
                Ok(Fp16::from_m31(
                    M31::from_canonical(node as u32)
                        .map_err(|_| "strict_replay_shard_node_noncanonical")?,
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        for transcript in &strict_layer_transcripts {
            let layer = layers
                .get(transcript.layer_index)
                .ok_or("strict_replay_layer_missing")?;
            let input_variables = (layer.input_width * group_count).trailing_zeros() as usize;
            let sparse_rounds = 2 * input_variables;
            let degrees = strict_variable_degrees
                .get(transcript.proof_index)
                .ok_or("strict_replay_degrees_missing")?;
            if transcript.rounds.len() != sparse_rounds + 1
                || transcript.challenges.len() != transcript.rounds.len()
                || transcript
                    .rounds
                    .iter()
                    .zip(degrees)
                    .any(|(round, degree)| round.len() != degree + 1)
            {
                return Err(format!(
                    "strict_replay_round_shape:{}",
                    transcript.proof_index
                ));
            }
            for round in 1..transcript.rounds.len() {
                let expected = polynomial_evaluation(
                    &transcript.rounds[round - 1],
                    transcript.challenges[round - 1],
                );
                let actual = polynomial_evaluation(&transcript.rounds[round], Fp16::ZERO)
                    + polynomial_evaluation(&transcript.rounds[round], Fp16::ONE);
                if expected != actual {
                    return Err(format!(
                        "strict_replay_sumcheck_recurrence:{}:{round}",
                        transcript.proof_index
                    ));
                }
            }
            let terminal_gate = repeated_pack_terminal_gate_claim(
                layer,
                group_count,
                &transcript.incoming_claims,
                &transcript.challenges[..input_variables],
                &transcript.challenges[input_variables..sparse_rounds],
                transcript.terminal_left,
                transcript.terminal_right,
            )
            .map_err(|error| format!("strict_replay_terminal_gate:{error:?}"))?;
            if terminal_gate != transcript.terminal_gate {
                return Err(format!(
                    "strict_replay_terminal_gate_mismatch:{}",
                    transcript.proof_index
                ));
            }
            let masked_initial_claim = transcript
                .incoming_claims
                .iter()
                .fold(Fp16::ZERO, |sum, claim| {
                    sum + claim.coefficient * claim.value
                });
            let public_node_sum = shard_nodes.iter().copied().fold(Fp16::ZERO, |sum, node| {
                sum + polynomial_evaluation(&transcript.public_bridge, node)
            });
            reconstructed_constraints.push(GkrMaskConstraint {
                functionals: shard_nodes
                    .iter()
                    .copied()
                    .map(|point| GkrMaskFunctional::BridgeEvaluation {
                        layer: transcript.proof_index,
                        point,
                        scale: transcript.bridge_rho,
                    })
                    .collect(),
                residual: public_node_sum - masked_initial_claim,
            });
            let selector = packed_selector_polynomial(transcript.shard_query)
                .map_err(|error| format!("strict_replay_bridge_selector:{error:?}"))?;
            let selector_inverse = polynomial_evaluation(&selector, transcript.bridge_challenge)
                .inverse()
                .map_err(|_| "strict_replay_bridge_selector_zero")?;
            let first_sum = polynomial_evaluation(&transcript.rounds[0], Fp16::ZERO)
                + polynomial_evaluation(&transcript.rounds[0], Fp16::ONE);
            reconstructed_constraints.push(GkrMaskConstraint {
                functionals: vec![
                    GkrMaskFunctional::SumcheckBooleanSum {
                        layer: transcript.proof_index,
                        scale: transcript.sumcheck_rho,
                    },
                    GkrMaskFunctional::BridgeEvaluation {
                        layer: transcript.proof_index,
                        point: transcript.bridge_challenge,
                        scale: -transcript.bridge_rho * selector_inverse,
                    },
                ],
                residual: first_sum
                    - polynomial_evaluation(&transcript.public_bridge, transcript.bridge_challenge)
                        * selector_inverse,
            });
            let equality_zero = transcript.challenges[..sparse_rounds]
                .iter()
                .fold(Fp16::ONE, |value, coordinate| {
                    value * (Fp16::ONE - *coordinate)
                });
            let mut final_functionals = vec![GkrMaskFunctional::SumcheckEvaluation {
                layer: transcript.proof_index,
                point: transcript.challenges.clone(),
                scale: transcript.sumcheck_rho,
            }];
            if transcript.proof_index != 0 {
                for claim in &transcript.incoming_claims {
                    final_functionals.push(GkrMaskFunctional::LayerEvaluation {
                        layer: transcript.proof_index - 1,
                        z_first: claim.point[0],
                        w: transcript.challenges[sparse_rounds],
                        scale: equality_zero * claim.coefficient * boolean_vanishing(&claim.point),
                    });
                }
            }
            reconstructed_constraints.push(GkrMaskConstraint {
                functionals: final_functionals,
                residual: polynomial_evaluation(
                    transcript
                        .rounds
                        .last()
                        .ok_or("strict_replay_w_round_missing")?,
                    transcript.challenges[sparse_rounds],
                ) - (Fp16::ONE - transcript.challenges[sparse_rounds])
                    * transcript.terminal_gate,
            });
        }
        let bottom_mask_layer = layers.len() - 1;
        for (masked, raw) in claims.iter().zip(&raw_claims) {
            reconstructed_constraints.push(GkrMaskConstraint {
                functionals: vec![GkrMaskFunctional::LayerBooleanSum {
                    layer: bottom_mask_layer,
                    z_first: masked.point[0],
                    scale: boolean_vanishing(&masked.point),
                }],
                residual: masked.value - raw.value,
            });
        }
        if reconstructed_constraints != online_constraints {
            return Err("strict_independent_constraint_reconstruction_mismatch".into());
        }
        gkr_mask_constraints = reconstructed_constraints;
        let mut batch_message = Vec::new();
        batch_message.extend_from_slice(b"BL/PQ512/WAVE2/GKR-MASK-BATCH/v1\0");
        batch_message.extend_from_slice(&(gkr_mask_constraints.len() as u32).to_be_bytes());
        for constraint in &gkr_mask_constraints {
            batch_message.extend_from_slice(&constraint.residual.encode());
            batch_message.extend_from_slice(&(constraint.functionals.len() as u16).to_be_bytes());
            for functional in &constraint.functionals {
                match functional {
                    GkrMaskFunctional::BridgeEvaluation {
                        layer,
                        point,
                        scale,
                    } => {
                        batch_message.push(0);
                        batch_message.extend_from_slice(&(*layer as u32).to_be_bytes());
                        batch_message.extend_from_slice(&point.encode());
                        batch_message.extend_from_slice(&scale.encode());
                    }
                    GkrMaskFunctional::SumcheckBooleanSum { layer, scale } => {
                        batch_message.push(1);
                        batch_message.extend_from_slice(&(*layer as u32).to_be_bytes());
                        batch_message.extend_from_slice(&scale.encode());
                    }
                    GkrMaskFunctional::SumcheckEvaluation {
                        layer,
                        point,
                        scale,
                    } => {
                        batch_message.push(2);
                        batch_message.extend_from_slice(&(*layer as u32).to_be_bytes());
                        batch_message.extend_from_slice(&(point.len() as u16).to_be_bytes());
                        for coordinate in point {
                            batch_message.extend_from_slice(&coordinate.encode());
                        }
                        batch_message.extend_from_slice(&scale.encode());
                    }
                    GkrMaskFunctional::LayerEvaluation {
                        layer,
                        z_first,
                        w,
                        scale,
                    } => {
                        batch_message.push(3);
                        batch_message.extend_from_slice(&(*layer as u32).to_be_bytes());
                        batch_message.extend_from_slice(&z_first.encode());
                        batch_message.extend_from_slice(&w.encode());
                        batch_message.extend_from_slice(&scale.encode());
                    }
                    GkrMaskFunctional::LayerBooleanSum {
                        layer,
                        z_first,
                        scale,
                    } => {
                        batch_message.push(4);
                        batch_message.extend_from_slice(&(*layer as u32).to_be_bytes());
                        batch_message.extend_from_slice(&z_first.encode());
                        batch_message.extend_from_slice(&scale.encode());
                    }
                }
            }
        }
        let ordinal = public_coin_ordinal.get();
        let batching = public_coin
            .borrow_mut()
            .scalar_challenge(
                ChainedRoundDescriptor {
                    kind: 0x1015,
                    ordinal,
                    output_count: 1,
                },
                &batch_message,
            )
            .map_err(|error| format!("strict_mask_batch_public_coin:{error:?}"))?;
        public_coin_ordinal.set(ordinal + 1);
        if batching.is_zero() {
            return Err("strict_mask_batch_zero".into());
        }
        let mut coefficient_weights = vec![Fp16::ZERO; strict_layout.padded_coefficients];
        let mut power = Fp16::ONE;
        for constraint in &gkr_mask_constraints {
            for functional in &constraint.functionals {
                accumulate_mask_functional(
                    &strict_layout,
                    &mut coefficient_weights,
                    functional,
                    power,
                )?;
            }
            gkr_mask_opening = gkr_mask_opening + power * constraint.residual;
            power = power * batching;
        }
        coefficient_weights.resize(1_usize << MLPCS_AUXILIARY_MASK_VARIABLES, Fp16::ZERO);
        let auxiliary_coefficients = strict_auxiliary_coefficients
            .as_ref()
            .ok_or("strict_auxiliary_coefficients_missing")?;
        let actual_opening = inner_product(auxiliary_coefficients, &coefficient_weights)
            .map_err(|error| format!("strict_mask_opening:{error:?}"))?;
        if actual_opening != gkr_mask_opening {
            return Err("strict_mask_aggregate_relation".into());
        }
        gkr_mask_hypercube_weights = Some(
            coefficient_weights_to_hypercube_weights(&coefficient_weights)
                .map_err(|error| format!("strict_mask_dual_weights:{error:?}"))?,
        );
        strict_mask_aggregate_ns = strict_mask_aggregate_started.elapsed().as_nanos();
    }
    let worker_finish_started = Instant::now();
    worker
        .finish(Duration::from_secs(30))
        .map_err(|error| format!("{error:?}"))?;
    let worker_finish_ns = worker_finish_started.elapsed().as_nanos();
    let gkr_public_coin_rounds = public_coin_ordinal.get();
    let terminal_claims = if strict_zk { &raw_claims } else { &claims };
    let input_wire_variables = layers[0].input_width.trailing_zeros() as u8;
    let packed_openings = if group_count == DEFAULT_GROUP_COUNT {
        bind_repeated_pack_gkr_terminals(terminal_claims, shard_query, input_wire_variables)
            .map_err(|error| format!("{error:?}"))?
    } else {
        bind_scaled_gkr_terminals(
            terminal_claims,
            shard_query,
            input_wire_variables,
            group_count,
        )?
    };
    for claim in &packed_openings.claims {
        let actual = output_value(
            checkpoints.first().ok_or("input_checkpoint_missing")?,
            layers[0].input_width,
            packed_openings.shard_query,
            &claim.point,
            instances,
            group_count,
        )?;
        if actual != claim.value {
            return Err("gkr_pcs_input_opening_mismatch".into());
        }
        digest.update(claim.value.encode());
    }
    if let (Some(coefficient_path), Some(opening_path)) =
        (coefficient_path.as_ref(), opening_path.as_ref())
    {
        let evaluation_count = 1_usize << MLPCS_INPUT_LOG_SIZE;
        let mut packed = vec![0_u8; evaluation_count / 8];
        let wire_count = layers[0].input_width;
        let words = instances.div_ceil(64);
        for group in 0..group_count {
            for shard in 0..PACK_BITS {
                let instance = group * PACK_BITS + shard;
                for wire in 0..wire_count {
                    if (checkpoints.first().ok_or("input_checkpoint_missing")?
                        [wire * words + instance / 64]
                        >> (instance % 64))
                        & 1
                        != 0
                    {
                        let index = wire + wire_count * (shard + PACK_BITS * group);
                        packed[index / 8] |= 1_u8 << (index % 8);
                    }
                }
            }
        }
        let coefficients = interpolate_packed_boolean_hypercube(&packed, evaluation_count)
            .map_err(|error| format!("{error:?}"))?;
        let masks = sample_extension_trace_mask_coefficients(
            secret_seed,
            session_id,
            &mask_oracle_id(b"pcs-main", permutations, 0),
            evaluation_count,
        )
        .map_err(|error| format!("pcs_mask_sampling_failed:{error:?}"))?;
        let hidden = extend_multilinear_coefficients_with_mask(&coefficients, &masks)
            .map_err(|error| format!("{error:?}"))?;
        let fold_challenges = (0..22)
            .map(|round| {
                Fp16::from_coefficients(core::array::from_fn(|coordinate| {
                    (((round + 1) * 131 + (coordinate + 3) * 977) % 2_147_483_647) as u32
                }))
                .expect("fold challenge coordinates are canonical")
            })
            .collect::<Vec<_>>();
        let expected_fold = evaluate_multilinear_coefficients(&hidden, &fold_challenges)
            .map_err(|error| format!("{error:?}"))?;
        let mut coefficient_output = BufWriter::with_capacity(
            16 << 20,
            File::create(coefficient_path).map_err(|e| e.to_string())?,
        );
        let mut endpoint_one = Fp16::ZERO;
        let mut endpoint_minus_one = Fp16::ZERO;
        for (index, value) in hidden.into_iter().enumerate() {
            coefficient_output
                .write_all(&value.encode())
                .map_err(|error| error.to_string())?;
            endpoint_one = endpoint_one + value;
            endpoint_minus_one = if index & 1 == 0 {
                endpoint_minus_one + value
            } else {
                endpoint_minus_one - value
            };
        }
        coefficient_output
            .flush()
            .map_err(|error| error.to_string())?;

        if let Some(output_coefficient_path) = output_coefficient_path.as_ref() {
            let mut packed_output = vec![0_u8; evaluation_count / 8];
            let output_boundary = semantic_output
                .as_ref()
                .ok_or("semantic_output_required_for_output_coefficients")?;
            let output_wire_count = layers.last().ok_or("layer_missing")?.padded_width;
            for group in 0..group_count {
                for shard in 0..PACK_BITS {
                    let instance = group * PACK_BITS + shard;
                    for wire in 0..output_wire_count {
                        if (output_boundary[wire * words + instance / 64] >> (instance % 64)) & 1
                            != 0
                        {
                            let index = wire + output_wire_count * (shard + PACK_BITS * group);
                            packed_output[index / 8] |= 1_u8 << (index % 8);
                        }
                    }
                }
            }
            let output_coefficients =
                interpolate_packed_boolean_hypercube(&packed_output, evaluation_count)
                    .map_err(|error| format!("{error:?}"))?;
            let output_masks = sample_extension_trace_mask_coefficients(
                secret_seed,
                session_id,
                &mask_oracle_id(b"pcs-output", permutations, 0),
                evaluation_count,
            )
            .map_err(|error| format!("pcs_output_mask_sampling_failed:{error:?}"))?;
            let output_hidden =
                extend_multilinear_coefficients_with_mask(&output_coefficients, &output_masks)
                    .map_err(|error| format!("{error:?}"))?;
            let output_expected_fold =
                evaluate_multilinear_coefficients(&output_hidden, &fold_challenges)
                    .map_err(|error| format!("{error:?}"))?;
            let mut output = BufWriter::with_capacity(
                16 << 20,
                File::create(output_coefficient_path).map_err(|error| error.to_string())?,
            );
            let mut output_endpoint_one = Fp16::ZERO;
            let mut output_endpoint_minus_one = Fp16::ZERO;
            for (index, value) in output_hidden.into_iter().enumerate() {
                output
                    .write_all(&value.encode())
                    .map_err(|error| error.to_string())?;
                output_endpoint_one = output_endpoint_one + value;
                output_endpoint_minus_one = if index & 1 == 0 {
                    output_endpoint_minus_one + value
                } else {
                    output_endpoint_minus_one - value
                };
            }
            output.flush().map_err(|error| error.to_string())?;
            let output_endpoint_path = output_coefficient_path.with_extension("endpoints");
            let mut endpoints = BufWriter::new(
                File::create(&output_endpoint_path).map_err(|error| error.to_string())?,
            );
            for value in [
                output_endpoint_one,
                output_endpoint_minus_one,
                output_expected_fold,
            ] {
                endpoints
                    .write_all(&value.encode())
                    .map_err(|error| error.to_string())?;
            }
            endpoints.flush().map_err(|error| error.to_string())?;
            println!(
                "output_coefficient_output={}",
                output_coefficient_path.display()
            );
            println!("output_endpoint_output={}", output_endpoint_path.display());
        }

        let mut opening_output =
            BufWriter::new(File::create(opening_path).map_err(|error| error.to_string())?);
        opening_output
            .write_all(b"BLGKPCS2")
            .map_err(|error| error.to_string())?;
        opening_output
            .write_all(&[
                packed_openings.wire_variables,
                packed_openings.claims[0].point.len() as u8,
                output_point.len() as u8,
                layers
                    .last()
                    .ok_or("layer_missing")?
                    .padded_width
                    .trailing_zeros() as u8,
            ])
            .map_err(|error| error.to_string())?;
        opening_output
            .write_all(&[0_u8; 4])
            .map_err(|error| error.to_string())?;
        opening_output
            .write_all(&packed_openings.shard_query.encode())
            .map_err(|error| error.to_string())?;
        for claim in &packed_openings.claims {
            for coordinate in &claim.point {
                opening_output
                    .write_all(&coordinate.encode())
                    .map_err(|error| error.to_string())?;
            }
            opening_output
                .write_all(&claim.value.encode())
                .map_err(|error| error.to_string())?;
        }
        opening_output
            .write_all(&output_shard_query.encode())
            .map_err(|error| error.to_string())?;
        for coordinate in &output_point {
            opening_output
                .write_all(&coordinate.encode())
                .map_err(|error| error.to_string())?;
        }
        opening_output
            .write_all(&expected_output.encode())
            .map_err(|error| error.to_string())?;
        opening_output
            .write_all(&endpoint_one.encode())
            .map_err(|error| error.to_string())?;
        opening_output
            .write_all(&endpoint_minus_one.encode())
            .map_err(|error| error.to_string())?;
        opening_output
            .write_all(&expected_fold.encode())
            .map_err(|error| error.to_string())?;
        opening_output.flush().map_err(|error| error.to_string())?;
        println!("coefficient_output={}", coefficient_path.display());
        println!("opening_output={}", opening_path.display());
    }
    let output_opening_claim = PackedGkrOutputClaim {
        claim: MultilinearOpeningClaim {
            point: output_point.clone(),
            value: expected_output,
        },
        shard_query: output_shard_query,
        wire_variables: layers
            .last()
            .ok_or("layer_missing")?
            .padded_width
            .trailing_zeros() as u8,
    };
    let interactive_pcs = if complete_pcs_inputs.is_some() {
        let input_coefficients = read_codeword(
            coefficient_path
                .as_deref()
                .ok_or("complete_input_coefficients_missing")?,
            MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE,
        )?;
        let input_hypercube = multilinear_coefficients_to_hypercube(&input_coefficients)
            .map_err(|error| format!("input_hypercube:{error:?}"))?;
        drop(input_coefficients);
        let output_coefficients = read_codeword(
            output_coefficient_path
                .as_deref()
                .ok_or("complete_output_coefficients_missing")?,
            MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE,
        )?;
        let output_hypercube = multilinear_coefficients_to_hypercube(&output_coefficients)
            .map_err(|error| format!("output_hypercube:{error:?}"))?;
        drop(output_coefficients);
        let auxiliary_hypercube = auxiliary_hypercube
            .take()
            .ok_or("complete_auxiliary_hypercube_missing")?;
        let prepared = prepared_fold
            .take()
            .ok_or("complete_prepared_commitments_missing")?;
        let mut pcs_challenge = |kind, _local_ordinal, message: &[u8]| {
            let ordinal = public_coin_ordinal.get();
            let value = public_coin
                .borrow_mut()
                .scalar_challenge(
                    ChainedRoundDescriptor {
                        kind,
                        ordinal,
                        output_count: 1,
                    },
                    message,
                )
                .map_err(|_| SelectedMultilinearPcsProofError::PublicCoin)?;
            public_coin_ordinal.set(ordinal + 1);
            Ok(value)
        };
        Some(if strict_zk {
            prove_interactive_dual_boundary_multilinear_pcs_prepared_with_gkr_mask_opening(
                input_hypercube,
                output_hypercube,
                auxiliary_hypercube,
                prepared,
                &packed_openings,
                &output_opening_claim,
                gkr_mask_hypercube_weights
                    .as_ref()
                    .ok_or("strict_gkr_mask_weights_missing")?
                    .clone(),
                gkr_mask_opening,
                session_id
                    .try_into()
                    .map_err(|_| "public_coin_session_id")?,
                &mut pcs_challenge,
            )
            .map_err(|error| format!("interactive_pcs:{error:?}"))?
        } else {
            prove_interactive_dual_boundary_multilinear_pcs_prepared(
                input_hypercube,
                output_hypercube,
                auxiliary_hypercube,
                prepared,
                &packed_openings,
                &output_opening_claim,
                session_id
                    .try_into()
                    .map_err(|_| "public_coin_session_id")?,
                &mut pcs_challenge,
            )
            .map_err(|error| format!("interactive_pcs:{error:?}"))?
        })
    } else {
        None
    };
    let public_coin = public_coin.into_inner();
    let public_coin_round_wait_ns = public_coin.round_wait_ns;
    let public_coin_round_wait_count = public_coin.round_wait_count;
    let public_coin_finish_started = Instant::now();
    let public_coin_bundle = public_coin
        .finish_bundle()
        .map_err(|error| format!("public_coin_finish:{error:?}"))?;
    let public_coin_finish_ns = public_coin_finish_started.elapsed().as_nanos();
    let public_coin_encode_started = Instant::now();
    let public_coin_encoded = encode_chained_public_coin_bundle(&public_coin_bundle)
        .map_err(|error| format!("public_coin_encode:{error:?}"))?;
    let public_coin_encode_ns = public_coin_encode_started.elapsed().as_nanos();
    let public_coin_bundle_hash_started = Instant::now();
    let public_coin_sha3_512: [u8; 64] = Sha3_512::digest(&public_coin_encoded).into();
    let public_coin_bundle_hash_ns = public_coin_bundle_hash_started.elapsed().as_nanos();
    let public_coin_decode_started = Instant::now();
    let decoded_public_coin = decode_chained_public_coin_bundle(&public_coin_encoded)
        .map_err(|error| format!("public_coin_decode:{error:?}"))?;
    let public_coin_decode_ns = public_coin_decode_started.elapsed().as_nanos();
    let public_coin_replay_started = Instant::now();
    let replayed_challenges = verify_active_public_coin_bundle(&decoded_public_coin)
        .map_err(|error| format!("public_coin_independent_replay:{error:?}"))?;
    let public_coin_replay_ns = public_coin_replay_started.elapsed().as_nanos();
    let sparse_public_coin_root = public_coin_bundle.claimed_final_transcript_root;
    if replayed_challenges.len() != authenticated_round_count {
        return Err("public_coin_replay_round_count_mismatch".into());
    }
    if usize::try_from(public_coin_ordinal.get()).map_err(|_| "public_coin_ordinal")?
        != authenticated_round_count
    {
        return Err("public_coin_round_count_mismatch".into());
    }
    if strict_zk {
        let initial = replayed_challenges
            .first()
            .ok_or("public_coin_output_query_missing")?;
        if initial.field_elements.first() != Some(&output_shard_query)
            || initial.field_elements.get(1..) != Some(output_point.as_slice())
        {
            return Err("public_coin_output_query_replay_mismatch".into());
        }
    }
    let mut pcs_proof_bytes = 0_usize;
    let mut pcs_proof_sha3_512 = [0_u8; 64];
    if let Some(interactive) = &interactive_pcs {
        let pcs_start = usize::try_from(gkr_public_coin_rounds).map_err(|_| "pcs_round_start")?;
        let pcs_rounds =
            usize::try_from(INTERACTIVE_DUAL_BOUNDARY_MLPCS_ROUNDS).map_err(|_| "pcs_rounds")?;
        let pcs_evidence = public_coin_bundle
            .rounds
            .get(pcs_start..pcs_start + pcs_rounds)
            .ok_or("pcs_public_coin_evidence_shape")?;
        if pcs_evidence
            .iter()
            .map(|round| round.prover_message.as_slice())
            .ne(interactive.prover_messages.iter().map(Vec::as_slice))
        {
            return Err("pcs_public_coin_message_replay_mismatch".into());
        }
        let pcs_challenges = replayed_challenges
            .get(pcs_start..pcs_start + pcs_rounds)
            .ok_or("pcs_public_coin_challenge_shape")?
            .iter()
            .map(|challenge| {
                challenge
                    .field_elements
                    .as_slice()
                    .try_into()
                    .map(|[value]: [Fp16; 1]| value)
                    .map_err(|_| "pcs_public_coin_scalar_shape")
            })
            .collect::<Result<Vec<_>, _>>()?;
        if strict_zk {
            verify_interactive_dual_boundary_multilinear_pcs_with_gkr_mask_opening(
                &interactive.pcs.proof,
                interactive.pcs.input_root,
                interactive.pcs.output_root,
                interactive.pcs.auxiliary_root,
                &packed_openings,
                &output_opening_claim,
                session_id
                    .try_into()
                    .map_err(|_| "public_coin_session_id")?,
                &pcs_challenges,
                &interactive.prover_messages,
                gkr_mask_hypercube_weights
                    .as_ref()
                    .ok_or("strict_gkr_mask_weights_missing")?,
                gkr_mask_opening,
            )
            .map_err(|error| format!("interactive_pcs_independent_verify:{error:?}"))?;
        } else {
            verify_interactive_dual_boundary_multilinear_pcs(
                &interactive.pcs.proof,
                interactive.pcs.input_root,
                interactive.pcs.output_root,
                interactive.pcs.auxiliary_root,
                &packed_openings,
                &output_opening_claim,
                session_id
                    .try_into()
                    .map_err(|_| "public_coin_session_id")?,
                &pcs_challenges,
                &interactive.prover_messages,
            )
            .map_err(|error| format!("interactive_pcs_independent_verify:{error:?}"))?;
        }
        let encoded = interactive
            .pcs
            .proof
            .encode(&interactive.challenges.queries)
            .map_err(|error| format!("pcs_proof_encode:{error:?}"))?;
        pcs_proof_bytes = encoded.len();
        pcs_proof_sha3_512 = Sha3_512::digest(&encoded).into();
    }
    let mut sorted_gpu_layer_ns = gpu_layer_ns.clone();
    sorted_gpu_layer_ns.sort_unstable();
    let gpu_layer_min_ns = sorted_gpu_layer_ns.first().copied().unwrap_or(0);
    let gpu_layer_median_ns = match sorted_gpu_layer_ns.len() {
        0 => 0,
        length if length % 2 == 1 => sorted_gpu_layer_ns[length / 2],
        length => {
            sorted_gpu_layer_ns[length / 2 - 1]
                .checked_add(sorted_gpu_layer_ns[length / 2])
                .ok_or("gpu_layer_median_overflow")?
                / 2
        }
    };
    let gpu_layer_max_ns = sorted_gpu_layer_ns.last().copied().unwrap_or(0);
    digest.update(public_coin_sha3_512);
    println!("permutations={permutations}");
    println!("group_count={group_count}");
    println!("fixed_shape_instances={instances}");
    println!("layers={}", layers.len());
    println!("boundary_ns={boundary_ns}");
    println!("round_checkpoint_count={}", checkpoints.len());
    println!("round_checkpoint_payload_bytes={checkpoint_payload_bytes}");
    println!("boundary_regeneration_ns={boundary_regeneration_ns}");
    println!("regenerated_round_peak_bytes={regenerated_round_peak_bytes}");
    println!("boundary_schedule_content_independent=true");
    println!("gpu_sparse_ns={gpu_ns}");
    println!("gpu_sparse_layer_count={}", gpu_layer_ns.len());
    println!("gpu_sparse_layer_min_ns={gpu_layer_min_ns}");
    println!("gpu_sparse_layer_median_ns={gpu_layer_median_ns}");
    println!("gpu_sparse_layer_max_ns={gpu_layer_max_ns}");
    println!("strict_bridge_provider_ns={strict_bridge_provider_ns}");
    println!("strict_round_provider_ns={strict_round_provider_ns}");
    println!("cpu_bridge_worker_count={cpu_bridge_worker_count}");
    println!("gpu_worker_count=1");
    println!("gpu_path_executed=true");
    println!("independent_layer_verify_ns={verify_ns}");
    println!("one_layer_cpu_gpu_parity_ns={parity_ns}");
    println!("strict_mask_aggregate_ns={strict_mask_aggregate_ns}");
    println!("worker_finish_ns={worker_finish_ns}");
    println!("public_coin_finish_ns={public_coin_finish_ns}");
    println!("public_coin_encode_ns={public_coin_encode_ns}");
    println!("public_coin_bundle_hash_ns={public_coin_bundle_hash_ns}");
    println!("public_coin_decode_ns={public_coin_decode_ns}");
    println!("public_coin_replay_ns={public_coin_replay_ns}");
    println!("public_coin_round_wait_ns={public_coin_round_wait_ns}");
    println!("public_coin_round_wait_count={public_coin_round_wait_count}");
    println!(
        "public_coin_round_wait_average_ns={}",
        public_coin_round_wait_ns / u128::from(public_coin_round_wait_count)
    );
    println!("proof_loop_ns={}", proof_started.elapsed().as_nanos());
    println!("total_ns={}", total.elapsed().as_nanos());
    println!("terminal_claims={}", claims.len());
    println!("coherent_chain_verified=true");
    println!("authenticated_gkr_internal_public_coin=true");
    println!("authenticated_public_coin=true");
    println!(
        "bench_fixture_coin={}",
        cfg!(feature = "bench_fixture_coin")
    );
    println!(
        "test_only_non_qualifying_coin={}",
        cfg!(feature = "bench_fixture_coin")
    );
    println!(
        "production_public_coin={}",
        !cfg!(feature = "bench_fixture_coin")
    );
    println!("complete_pcs_attached={}", interactive_pcs.is_some());
    println!("strict_gkr_control={strict_gkr_control}");
    println!("complete_proof_qualification=false");
    println!(
        "gkr_authenticated_public_coin_rounds={}",
        gkr_public_coin_rounds
    );
    println!(
        "complete_public_coin_root={}",
        hex(&sparse_public_coin_root)
    );
    println!("public_coin_independent_replay=true");
    println!("public_coin_bundle_bytes={}", public_coin_encoded.len());
    println!("public_coin_bundle_sha3_512={}", hex(&public_coin_sha3_512));
    println!("pcs_proof_bytes={pcs_proof_bytes}");
    println!("pcs_proof_sha3_512={}", hex(&pcs_proof_sha3_512));
    println!("pcs_independent_verify={}", interactive_pcs.is_some());
    println!("external_keccak_input=true");
    println!(
        "semantic_output_boundary_verified={}",
        semantic_output.is_some()
    );
    println!(
        "output_claim_digest_slice_only={}",
        semantic_output.is_none()
    );
    println!("output_claim_full_state={}", semantic_output.is_some());
    println!("native_sparse_masks_nonzero=true");
    println!("external_secret_masks=true");
    println!("cpu_gpu_packed_polynomial_equal={cpu_gpu_packed_equal}");
    println!("gkr_pcs_input_openings_equal=true");
    println!("proof_stream_sha3_512={:x}", digest.finalize());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("coherent GKR benchmark failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_input_rejects_inactive_lanes_and_padding_wires() {
        let permutations = 782;
        let width = 2_048;
        let words = DEFAULT_INSTANCES.div_ceil(64);
        let mut encoded = vec![0_u8; 16 + width * words * 8];
        encoded[..8].copy_from_slice(INPUT_MAGIC);
        encoded[8..10].copy_from_slice(&INPUT_VERSION.to_be_bytes());
        encoded[10..12].copy_from_slice(&(permutations as u16).to_be_bytes());
        encoded[12..14].copy_from_slice(&(DEFAULT_INSTANCES as u16).to_be_bytes());
        encoded[14..16].copy_from_slice(&(width as u16).to_be_bytes());
        assert!(decode_initial_boundary(&encoded, permutations, width, DEFAULT_INSTANCES).is_ok());
        encoded[10..12].copy_from_slice(&(DEFAULT_INSTANCES as u16).to_be_bytes());
        assert!(
            decode_initial_boundary(&encoded, DEFAULT_INSTANCES, width, DEFAULT_INSTANCES).is_ok()
        );
        encoded[10..12].copy_from_slice(&(permutations as u16).to_be_bytes());

        let inactive_offset = 16 + (permutations / 64) * 8;
        encoded[inactive_offset..inactive_offset + 8]
            .copy_from_slice(&(1_u64 << (permutations % 64)).to_be_bytes());
        assert_eq!(
            decode_initial_boundary(&encoded, permutations, width, DEFAULT_INSTANCES),
            Err("input_inactive_lane_nonzero".into())
        );
        encoded[inactive_offset..inactive_offset + 8].fill(0);

        let padding_offset = 16 + STATE_BITS * words * 8;
        encoded[padding_offset..padding_offset + 8].copy_from_slice(&1_u64.to_be_bytes());
        assert_eq!(
            decode_initial_boundary(&encoded, permutations, width, DEFAULT_INSTANCES),
            Err("input_padding_wire_nonzero".into())
        );
    }

    #[test]
    fn zero_high_wire_coordinates_restrict_output_claim_to_sha3_digest_bits() {
        let width = 2_048;
        let words = DEFAULT_INSTANCES.div_ceil(64);
        let baseline = vec![0_u64; width * words];
        let mut changed = baseline.clone();
        changed[512 * words] = 1;
        let mut point = (0..18)
            .map(|index| fp16(80_000 + index as u32))
            .collect::<Vec<_>>();
        point[9] = Fp16::ZERO;
        point[10] = Fp16::ZERO;
        let shard_query = fp16(81_000);
        assert_eq!(
            output_value(
                &baseline,
                width,
                shard_query,
                &point,
                DEFAULT_INSTANCES,
                DEFAULT_GROUP_COUNT,
            )
            .unwrap(),
            output_value(
                &changed,
                width,
                shard_query,
                &point,
                DEFAULT_INSTANCES,
                DEFAULT_GROUP_COUNT,
            )
            .unwrap()
        );
        point[9] = fp16(82_000);
        assert_ne!(
            output_value(
                &baseline,
                width,
                shard_query,
                &point,
                DEFAULT_INSTANCES,
                DEFAULT_GROUP_COUNT,
            )
            .unwrap(),
            output_value(
                &changed,
                width,
                shard_query,
                &point,
                DEFAULT_INSTANCES,
                DEFAULT_GROUP_COUNT,
            )
            .unwrap()
        );
    }

    #[test]
    fn scaled_terminal_binding_preserves_dynamic_group_dimension() {
        let claims = [
            LayerOutputClaim {
                point: vec![Fp16::ZERO; 15],
                value: Fp16::ONE,
                coefficient: Fp16::ONE,
            },
            LayerOutputClaim {
                point: vec![Fp16::ONE; 15],
                value: Fp16::ZERO,
                coefficient: Fp16::ONE,
            },
        ];
        let bound = bind_scaled_gkr_terminals(&claims, Fp16::ONE, 11, 16).unwrap();
        assert_eq!(bound.claims[0].point.len(), 15);
        assert_eq!(bound.wire_variables, 11);

        let mut wrong_dimension = claims.clone();
        wrong_dimension[1].point.pop();
        assert_eq!(
            bind_scaled_gkr_terminals(&wrong_dimension, Fp16::ONE, 11, 16),
            Err("scaled_terminal_point_dimension".into())
        );
    }
}
