use std::fs;
use std::fs::{OpenOptions, create_dir};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;
use std::time::{Duration, Instant as Clock};

use bl_pq512_crypto_core::air_composition::{
    add_logup_to_composition, build_air_composition_from_main, build_air_main_trace_oracle,
    prepare_logup_for_composition,
};
use bl_pq512_crypto_core::air_ir::{
    MAX_AIR_BINARY_BYTES, evaluate_air_execution, validated_execution_public_inputs,
};
use bl_pq512_crypto_core::air_logup::build_air_logup_oracle_at_evaluation_logs;
use bl_pq512_crypto_core::composition_mask::mask_composition_components;
use bl_pq512_crypto_core::deep_quotient::{build_deep_quotient_oracles, deep_claims_commitment};
use bl_pq512_crypto_core::field::Fp16;
use bl_pq512_crypto_core::fri_pipeline::{
    build_fri_mask_oracle, prove_fri_pipeline, start_interactive_fri,
};
use bl_pq512_crypto_core::h4_bridge_source_response_v2::H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS;
use bl_pq512_crypto_core::h4_post_z_producer::{
    H4PostZProducerError, produce_h4_post_z_response_from_fresh_projection_oracle,
};
use bl_pq512_crypto_core::h4_proof_package_v1::exact_queries as h4_exact_queries;
use bl_pq512_crypto_core::h4_proof_package_v2::H4_BRIDGE_RESPONSE_QUERY_DOMAIN_V2;
use bl_pq512_crypto_core::h4_proof_package_v2::H4ProofProfileV2;
use bl_pq512_crypto_core::h4_proof_package_v2::{H4SourceMaskProofV2, verify_h4_pre_alpha_v2};
use bl_pq512_crypto_core::h4_v2_completion::{
    H4PostZResponseInput, derive_h4_source_mask_coins_v3,
    prepare_h4_v2_from_serialized_post_z_with_keys,
};
use bl_pq512_crypto_core::h4_verification_key_v2::{
    H4_VERIFICATION_KEY_V2_BYTES, decode_h4_verification_key_v2,
};
use bl_pq512_crypto_core::oracle_commitment::{
    commit_air_oracles_with_precommitments, commit_interaction_trace_oracle,
    commit_main_trace_oracle,
};
use bl_pq512_crypto_core::proof_format::{
    decode_fri_pipeline_proof_v2, encode_fri_pipeline_proof_v2_with_attribution,
};
use bl_pq512_crypto_core::proof_parameters::{
    LOG_BLOWUP, QUERY_COUNT, QUOTIENT_MASK_COEFFICIENT_COUNT, TRACE_MASK_COEFFICIENT_COUNT,
    selected_proof_geometry,
};
use bl_pq512_crypto_core::resource_preflight::estimate_selected_prover_resources;
use bl_pq512_crypto_core::selected_challenge::{
    decode_selected_challenge_bundle, fri_batch_derivation_commitment,
    verify_selected_fri_pipeline_v2,
};
use bl_pq512_crypto_core::selected_public_coin_v3::{
    SEMANTIC_V3_PARENT_ANCHOR_COMMAND, SemanticV3ParentAnchorFrame,
};
use bl_pq512_crypto_core::semantic_fri_v3_producer::produce_semantic_fri_v3_from_legacy;
use bl_pq512_crypto_core::semantic_h4_bridge_gkr::{
    decode_public_masked_semantic_h4_bridge_gkr,
    produce_semantic_bridge_functional_inventory_from_air_v3,
    semantic_h4_post_z_context_from_pre_final_v3,
    verify_semantic_bridge_source_batch_from_program_v3, verify_strict_semantic_h4_bridge_gkr,
};
use bl_pq512_crypto_core::strict_pq_public_coin_v2::{
    StrictPqGovernedVerifierKeyV2, StrictPqRootUseRegistryV2,
};
use bl_pq512_crypto_core::v3_real_authority::{
    H4_FUNCTIONAL_INPUTS_FILE, H4_GKR_CONTEXT_FILE, H4_GKR_FIRST_ORDINAL_FILE, H4_GKR_KEY_FILE,
    H4_GKR_PROOF_FILE, H4_GKR_STRICT_BUNDLE_FILE, H4_MASK_INPUT_FILE,
    SEMANTIC_FRI_PARAMETERS_FILE, SEMANTIC_FRI_PROOF_FILE,
    encode_produced_h4_mask_input_v3, encode_semantic_bridge_functional_inputs_v3,
    publish_new_files,
};
use zeroize::Zeroize;

const WORKER_MAGIC: &[u8; 8] = b"BLPQSPW2";
#[cfg(any(test, feature = "test_entropy_injection"))]
const TEST_WORKER_MAGIC: &[u8; 8] = b"BLPQSPT2";

const ENTROPY_BYTES: usize = 64;
const MAX_ZERO_ENTROPY_RETRIES: usize = 8;
const POST_Z_REQUEST_MAGIC: &[u8; 8] = b"BLH4PZQ1";
const POST_Z_RESPONSE_MAGIC: &[u8; 8] = b"BLH4PZR1";
const POST_Z_WAIT_SECONDS: u64 = 21_600;
const POST_Z_OPENING_REQUEST_MAGIC: &[u8; 8] = b"BLH4OQ01";
const POST_Z_OPENING_RESPONSE_MAGIC: &[u8; 8] = b"BLH4OR01";
#[cfg(test)]
static WORKER_ENTROPY_DROP_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Per-attempt masking entropy owned exclusively by this worker process.
///
/// This type is intentionally neither `Clone` nor `Copy`. The public-coin
/// session identifier is not entropy: it remains an authenticated public
/// transcript field, while this private attempt nonce prevents a caller from
/// selecting or reusing the mask-derivation context.
struct WorkerEntropy {
    mask_seed: [u8; ENTROPY_BYTES],
    attempt_nonce: [u8; ENTROPY_BYTES],
}

impl WorkerEntropy {
    fn from_os() -> Result<Self, String> {
        let mut value = Self {
            mask_seed: [0_u8; ENTROPY_BYTES],
            attempt_nonce: [0_u8; ENTROPY_BYTES],
        };
        fill_nonzero_os_entropy(&mut value.mask_seed)?;
        fill_nonzero_os_entropy(&mut value.attempt_nonce)?;
        Ok(value)
    }

    #[cfg(any(test, feature = "test_entropy_injection"))]
    fn from_test_reader(reader: &mut impl Read) -> Result<Self, String> {
        let mut value = Self {
            mask_seed: [0_u8; ENTROPY_BYTES],
            attempt_nonce: [0_u8; ENTROPY_BYTES],
        };
        reader
            .read_exact(&mut value.mask_seed)
            .map_err(|_| "test_entropy_frame_truncated".to_string())?;
        reader
            .read_exact(&mut value.attempt_nonce)
            .map_err(|_| "test_entropy_frame_truncated".to_string())?;
        if !value.mask_seed.iter().any(|byte| *byte != 0)
            || !value.attempt_nonce.iter().any(|byte| *byte != 0)
        {
            return Err("test_entropy_zero".into());
        }
        Ok(value)
    }

    fn mask_seed(&self) -> &[u8; ENTROPY_BYTES] {
        &self.mask_seed
    }

    fn attempt_nonce(&self) -> &[u8; ENTROPY_BYTES] {
        &self.attempt_nonce
    }
}

impl Zeroize for WorkerEntropy {
    fn zeroize(&mut self) {
        self.mask_seed.zeroize();
        self.attempt_nonce.zeroize();
    }
}

impl Drop for WorkerEntropy {
    fn drop(&mut self) {
        self.zeroize();
        #[cfg(test)]
        WORKER_ENTROPY_DROP_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

fn fill_nonzero_os_entropy(destination: &mut [u8; ENTROPY_BYTES]) -> Result<(), String> {
    for _ in 0..MAX_ZERO_ENTROPY_RETRIES {
        getrandom::fill(destination).map_err(|_| "os_entropy_unavailable".to_string())?;
        if destination.iter().any(|byte| *byte != 0) {
            return Ok(());
        }
    }
    Err("os_entropy_repeated_zero".into())
}

fn maybe_inject_test_fault(phase: &str) -> Result<(), String> {
    #[cfg(feature = "test_entropy_injection")]
    if let Ok(request) = std::env::var("BL_PQ512_TEST_WORKER_FAULT") {
        if request == format!("error:{phase}") {
            return Err(format!("test_fault_{phase}"));
        }
        if request == format!("abort:{phase}") {
            std::process::abort();
        }
        if request == format!("stall:{phase}") {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
            }
        }
    }
    let _ = phase;
    Ok(())
}

fn decode_hex<const N: usize>(encoded: &str) -> Result<[u8; N], String> {
    if encoded.len() != N * 2 || !encoded.is_ascii() {
        return Err("hex_length".into());
    }
    let mut decoded = [0_u8; N];
    for (index, output) in decoded.iter_mut().enumerate() {
        let offset = index * 2;
        *output = u8::from_str_radix(&encoded[offset..offset + 2], 16)
            .map_err(|_| "hex_digit".to_string())?;
    }
    Ok(decoded)
}

fn decode_hex_vec(encoded: &str) -> Result<Vec<u8>, String> {
    if !encoded.len().is_multiple_of(2) || !encoded.is_ascii() {
        return Err("hex_length".into());
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = core::str::from_utf8(pair).map_err(|_| "hex_digit".to_string())?;
            u8::from_str_radix(text, 16).map_err(|_| "hex_digit".to_string())
        })
        .collect()
}

fn encode_hex(value: &[u8]) -> String {
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        use core::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn read_u32(reader: &mut impl Read) -> Result<usize, String> {
    let mut encoded = [0_u8; 4];
    reader
        .read_exact(&mut encoded)
        .map_err(|_| "initial_frame_truncated".to_string())?;
    usize::try_from(u32::from_be_bytes(encoded)).map_err(|_| "initial_length".into())
}

fn read_bounded(reader: &mut impl Read) -> Result<Vec<u8>, String> {
    let length = read_u32(reader)?;
    if length == 0 || length > MAX_AIR_BINARY_BYTES {
        return Err("initial_length".into());
    }
    let mut value = vec![0_u8; length];
    reader
        .read_exact(&mut value)
        .map_err(|_| "initial_frame_truncated".to_string())?;
    Ok(value)
}

fn read_command(reader: &mut impl BufRead) -> Result<Vec<String>, String> {
    let mut line = String::new();
    let count = reader
        .read_line(&mut line)
        .map_err(|_| "command_read".to_string())?;
    if count == 0 || line.len() > 1 << 20 {
        return Err("command_length".into());
    }
    let fields = line
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    Ok(fields)
}

fn command(reader: &mut impl BufRead, expected: &str) -> Result<Vec<String>, String> {
    let fields = read_command(reader)?;
    if fields.first().map(String::as_str) != Some(expected) {
        return Err(format!("command_order_expected_{expected}"));
    }
    Ok(fields)
}

fn field(encoded: &str) -> Result<Fp16, String> {
    Fp16::decode(&decode_hex::<64>(encoded)?).map_err(|_| "field_encoding".into())
}

fn emit(writer: &mut impl Write, line: &str) -> Result<(), String> {
    writeln!(writer, "{line}").map_err(|_| "response_write".to_string())?;
    writer.flush().map_err(|_| "response_flush".to_string())
}

fn read_worker_artifact(directory: &Path, name: &str, maximum: usize) -> Result<Vec<u8>, String> {
    let path = directory.join(name);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("{name}_metadata_{:?}", error.kind()))?;
    let length = usize::try_from(metadata.len()).map_err(|_| format!("{name}_length"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || length == 0 || length > maximum {
        return Err(format!("{name}_invalid"));
    }
    let encoded = fs::read(path).map_err(|error| format!("{name}_read_{:?}", error.kind()))?;
    if encoded.len() != length {
        return Err(format!("{name}_changed"));
    }
    Ok(encoded)
}

fn publish_projection_request(path: &Path, challenges: &[Fp16]) -> Result<(), String> {
    if !path.is_absolute() || challenges.len() != 9 || path.exists() {
        return Err("post_z_projection_request_shape".into());
    }
    let partial = PathBuf::from(format!("{}.partial", path.display()));
    if partial.exists() {
        return Err("post_z_projection_request_partial_exists".into());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(|error| format!("post_z_projection_request_open_{:?}", error.kind()))?;
    file.write_all(POST_Z_REQUEST_MAGIC)
        .and_then(|_| {
            for challenge in challenges {
                file.write_all(&challenge.encode())?;
            }
            file.sync_all()
        })
        .map_err(|error| format!("post_z_projection_request_write_{:?}", error.kind()))?;
    drop(file);
    fs::rename(partial, path)
        .map_err(|error| format!("post_z_projection_request_publish_{:?}", error.kind()))
}

fn wait_for_projection_response(path: &Path) -> Result<(Vec<Fp16>, Vec<Fp16>), String> {
    if !path.is_absolute() {
        return Err("post_z_projection_response_path".into());
    }
    let vector_bytes = H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS
        .checked_mul(64)
        .ok_or("post_z_projection_response_length")?;
    let expected = POST_Z_RESPONSE_MAGIC
        .len()
        .checked_add(2 * vector_bytes)
        .ok_or("post_z_projection_response_length")?;
    let deadline = Clock::now() + Duration::from_secs(POST_Z_WAIT_SECONDS);
    let encoded = loop {
        match fs::read(path) {
            Ok(value) => break value,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && Clock::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                return Err(format!(
                    "post_z_projection_response_read_{:?}",
                    error.kind()
                ));
            }
        }
    };
    if encoded.len() != expected || encoded.get(..8) != Some(POST_Z_RESPONSE_MAGIC) {
        return Err("post_z_projection_response_shape".into());
    }
    let decode = |bytes: &[u8]| {
        bytes
            .chunks_exact(64)
            .map(|field| {
                Fp16::decode(field).map_err(|_| "post_z_projection_response_field".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()
    };
    Ok((
        decode(&encoded[8..8 + vector_bytes])?,
        decode(&encoded[8 + vector_bytes..])?,
    ))
}

fn exchange_post_z_openings(
    request_path: &Path,
    response_path: &Path,
    response_seal: Fp16,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let positions = h4_exact_queries(
        &response_seal.encode(),
        H4_BRIDGE_RESPONSE_QUERY_DOMAIN_V2,
        bl_pq512_crypto_core::h4_proof_package_v2::H4_MAIN_CODE_VALUES,
        bl_pq512_crypto_core::h4_proof_package_v2::H4_MAIN_OPENINGS,
    )
    .map_err(|_| "post_z_opening_queries".to_string())?;
    if !request_path.is_absolute() || !response_path.is_absolute() || request_path.exists() {
        return Err("post_z_opening_paths".into());
    }
    let partial = PathBuf::from(format!("{}.partial", request_path.display()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(|error| format!("post_z_opening_request_open_{:?}", error.kind()))?;
    file.write_all(POST_Z_OPENING_REQUEST_MAGIC)
        .and_then(|_| {
            for position in &positions {
                file.write_all(&u32::try_from(*position).unwrap().to_be_bytes())?;
            }
            file.sync_all()
        })
        .map_err(|error| format!("post_z_opening_request_write_{:?}", error.kind()))?;
    drop(file);
    fs::rename(partial, request_path)
        .map_err(|error| format!("post_z_opening_request_publish_{:?}", error.kind()))?;
    let deadline = Clock::now() + Duration::from_secs(POST_Z_WAIT_SECONDS);
    let encoded = loop {
        match fs::read(response_path) {
            Ok(value) => break value,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && Clock::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(format!("post_z_opening_response_read_{:?}", error.kind())),
        }
    };
    if encoded.len() < 24 || encoded.get(..8) != Some(POST_Z_OPENING_RESPONSE_MAGIC) {
        return Err("post_z_opening_response_shape".into());
    }
    let source_len = usize::try_from(u64::from_be_bytes(
        encoded[8..16]
            .try_into()
            .map_err(|_| "post_z_opening_response_shape")?,
    ))
    .map_err(|_| "post_z_opening_response_shape")?;
    let base_len = usize::try_from(u64::from_be_bytes(
        encoded[16..24]
            .try_into()
            .map_err(|_| "post_z_opening_response_shape")?,
    ))
    .map_err(|_| "post_z_opening_response_shape")?;
    if source_len == 0 || base_len == 0 || 24 + source_len + base_len != encoded.len() {
        return Err("post_z_opening_response_shape".into());
    }
    Ok((
        encoded[24..24 + source_len].to_vec(),
        encoded[24 + source_len..].to_vec(),
    ))
}

fn produce_retained_semantic_functionals(
    directory: &Path,
    expected_context: &str,
    program: &[u8],
    composition: &bl_pq512_crypto_core::air_composition::AirCompositionOracle,
    native_v3: &bl_pq512_crypto_core::semantic_fri_v3_producer::ProducedSemanticFriV3,
) -> Result<
    (
        Vec<u8>,
        bl_pq512_crypto_core::semantic_h4_bridge_gkr::VerifiedStrictSemanticH4BridgeGkr,
        Vec<bl_pq512_crypto_core::semantic_h4_bridge_gkr::SemanticBridgeFunctionalProofInputV3>,
    ),
    String,
> {
    let context = bl_pq512_crypto_core::binding_root_v2::BindingDigestV2::decode(
        &decode_hex::<64>(expected_context)?,
    )
    .map_err(|error| format!("functional_context_{error:?}"))?;
    let supplied_context = read_worker_artifact(directory, H4_GKR_CONTEXT_FILE, 128)?;
    if supplied_context != context.as_bytes() {
        return Err("functional_context_mismatch".into());
    }
    let key = StrictPqGovernedVerifierKeyV2::decode(&read_worker_artifact(
        directory,
        H4_GKR_KEY_FILE,
        2 << 20,
    )?)
    .map_err(|error| format!("functional_key_{error:?}"))?;
    let proof = decode_public_masked_semantic_h4_bridge_gkr(&read_worker_artifact(
        directory,
        H4_GKR_PROOF_FILE,
        64 << 20,
    )?)
    .map_err(|error| format!("functional_gkr_{error:?}"))?;
    let ordinal_bytes = read_worker_artifact(directory, H4_GKR_FIRST_ORDINAL_FILE, 4)?;
    if ordinal_bytes.len() != 4 {
        return Err("functional_ordinal_length".into());
    }
    let first_ordinal = u32::from_be_bytes(
        ordinal_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "functional_ordinal_length".to_string())?,
    );
    let mut registry = StrictPqRootUseRegistryV2::new();
    let strict = verify_strict_semantic_h4_bridge_gkr(
        &read_worker_artifact(directory, H4_GKR_STRICT_BUNDLE_FILE, 64 << 20)?,
        &key,
        &proof,
        context,
        first_ordinal,
        &mut registry,
    )
    .map_err(|error| format!("functional_gkr_replay_{error:?}"))?;
    let inputs = produce_semantic_bridge_functional_inventory_from_air_v3(
        strict.verified_gkr(),
        program,
        TRACE_MASK_COEFFICIENT_COUNT,
        LOG_BLOWUP,
        &native_v3.verified,
        composition,
    )
    .map_err(|error| format!("functional_produce_{error:?}"))?;
    let encoded = encode_semantic_bridge_functional_inputs_v3(&inputs)
        .map_err(|error| format!("functional_encode_{error}"))?;
    Ok((encoded, strict, inputs))
}

fn publish_post_z_response(
    directory: &Path,
    produced: &bl_pq512_crypto_core::h4_post_z_producer::ProducedH4PostZResponse,
) -> Result<(), String> {
    let shards = directory.join("h4-shards");
    let shard = shards.join("0");
    let keys = directory.join("h4-post-z-keys");
    for path in [&shards, &shard, &keys] {
        create_dir(path).map_err(|error| format!("post_z_directory_{:?}", error.kind()))?;
    }
    let first_ordinal = produced.first_ordinal.to_be_bytes();
    publish_new_files(
        &shard,
        &[
            ("response.bin", produced.encoded_response.as_slice()),
            (
                "strict-bundle.bin",
                produced.encoded_strict_bundle.as_slice(),
            ),
            ("first-ordinal.bin", first_ordinal.as_slice()),
        ],
    )
    .map_err(|error| format!("post_z_publish_{error}"))?;
    publish_new_files(&keys, &[("0.bin", produced.governed_key.as_slice())])
        .map_err(|error| format!("post_z_key_publish_{error}"))
}

fn run() -> Result<(), String> {
    let total_started = Instant::now();
    let mut arguments = std::env::args_os();
    arguments.next();
    let native_v3_export_directory = match arguments.next() {
        None => None,
        Some(flag) if flag == "--native-v3-export" => arguments.next().map(PathBuf::from),
        Some(_) => return Err("worker_argument_shape".into()),
    };
    if arguments.next().is_some() {
        return Err("worker_argument_shape".into());
    }
    if let Some(directory) = native_v3_export_directory.as_ref()
        && (!directory.is_absolute() || !directory.is_dir())
    {
        return Err("native_v3_export_directory_invalid".into());
    }
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = BufWriter::new(stdout.lock());

    let mut magic = [0_u8; 8];
    reader
        .read_exact(&mut magic)
        .map_err(|_| "initial_frame_truncated".to_string())?;
    #[cfg(any(test, feature = "test_entropy_injection"))]
    let test_entropy_injection = &magic == TEST_WORKER_MAGIC;
    #[cfg(not(any(test, feature = "test_entropy_injection")))]
    let test_entropy_injection = false;
    if &magic != WORKER_MAGIC && !test_entropy_injection {
        return Err("initial_magic".into());
    }
    let program = read_bounded(&mut reader)?;
    let execution = read_bounded(&mut reader)?;
    let mut session_id = [0_u8; 64];
    reader
        .read_exact(&mut session_id)
        .map_err(|_| "initial_frame_truncated".to_string())?;
    if !session_id.iter().any(|byte| *byte != 0) {
        return Err("initial_entropy".into());
    }
    let entropy = if test_entropy_injection {
        #[cfg(any(test, feature = "test_entropy_injection"))]
        {
            WorkerEntropy::from_test_reader(&mut reader)?
        }
        #[cfg(not(any(test, feature = "test_entropy_injection")))]
        unreachable!("test entropy injection is absent from default builds")
    } else {
        WorkerEntropy::from_os()?
    };

    let main_started = Instant::now();
    evaluate_air_execution(&execution).map_err(|error| format!("execution_{error:?}"))?;
    let public_inputs = validated_execution_public_inputs(&execution)
        .map_err(|error| format!("public_inputs_{error:?}"))?;
    let geometry =
        selected_proof_geometry(&program).map_err(|error| format!("geometry_{error:?}"))?;
    let resources = estimate_selected_prover_resources(&program)
        .map_err(|error| format!("resource_preflight_{error:?}"))?;
    if resources.requires_streaming {
        return Err(format!(
            "streaming_worker_required:{}",
            resources.monolithic_live_bytes_lower_bound
        ));
    }

    let main = build_air_main_trace_oracle(
        &program,
        &execution,
        entropy.mask_seed(),
        entropy.attempt_nonce(),
        TRACE_MASK_COEFFICIENT_COUNT,
        LOG_BLOWUP,
    )
    .map_err(|error| format!("main_{error:?}"))?;
    let main_tree = commit_main_trace_oracle(&main).map_err(|error| format!("main_{error:?}"))?;
    let main_root = main_tree.root().into_bytes();
    let main_ms = main_started.elapsed().as_millis();
    emit(&mut writer, &format!("MAIN {}", encode_hex(&main_root)))?;
    maybe_inject_test_fault("after_main")?;

    let interaction = command(&mut reader, "INTERACTION")?;
    if interaction.len() != 3 {
        return Err("interaction_shape".into());
    }
    let beta = field(&interaction[1])?;
    let gamma = field(&interaction[2])?;
    let interaction_started = Instant::now();
    let table_evaluation_log_sizes = main
        .tables
        .iter()
        .map(|table| table.evaluation_log_size)
        .collect::<Vec<_>>();
    let mut logup = build_air_logup_oracle_at_evaluation_logs(
        &program,
        &execution,
        beta,
        gamma,
        entropy.mask_seed(),
        entropy.attempt_nonce(),
        TRACE_MASK_COEFFICIENT_COUNT,
        LOG_BLOWUP,
        &table_evaluation_log_sizes,
    )
    .map_err(|error| format!("logup_{error:?}"))?;
    prepare_logup_for_composition(
        &program,
        &main,
        &mut logup,
        entropy.mask_seed(),
        entropy.attempt_nonce(),
        TRACE_MASK_COEFFICIENT_COUNT,
    )
    .map_err(|error| format!("logup_prepare_{error:?}"))?;
    let interaction_tree = commit_interaction_trace_oracle(&main.program_binary_commitment, &logup)
        .map_err(|error| format!("interaction_{error:?}"))?
        .ok_or_else(|| "selected_suite_requires_interaction".to_string())?;
    let interaction_root = interaction_tree.root().into_bytes();
    let interaction_ms = interaction_started.elapsed().as_millis();
    emit(
        &mut writer,
        &format!("INTERACTION_ROOT {}", encode_hex(&interaction_root)),
    )?;

    let composition_command = command(&mut reader, "COMPOSITION")?;
    if composition_command.len() != 2 {
        return Err("composition_shape".into());
    }
    let alpha = field(&composition_command[1])?;
    let composition_started = Instant::now();
    let mut composition = build_air_composition_from_main(&program, &execution, alpha, main)
        .map_err(|error| format!("composition_{error:?}"))?;
    add_logup_to_composition(
        &program,
        &execution,
        &mut composition,
        &mut logup,
        beta,
        gamma,
        alpha,
        entropy.mask_seed(),
        entropy.attempt_nonce(),
        TRACE_MASK_COEFFICIENT_COUNT,
    )
    .map_err(|error| format!("composition_logup_{error:?}"))?;
    mask_composition_components(
        &mut composition,
        entropy.mask_seed(),
        entropy.attempt_nonce(),
        QUOTIENT_MASK_COEFFICIENT_COUNT,
    )
    .map_err(|error| format!("quotient_mask_{error:?}"))?;
    let oracles = commit_air_oracles_with_precommitments(
        main_tree,
        Some(interaction_tree),
        &composition,
        &logup,
    )
    .map_err(|error| format!("oracle_commitment_{error:?}"))?;
    let roots = oracles.roots();
    let composition_root = roots.composition.into_bytes();
    let composition_ms = composition_started.elapsed().as_millis();
    emit(
        &mut writer,
        &format!("COMPOSITION_ROOT {}", encode_hex(&composition_root)),
    )?;
    maybe_inject_test_fault("after_composition")?;

    let oods = read_command(&mut reader)?;
    let (query, v3_parent_anchor_commitment) = match oods.first().map(String::as_str) {
        Some("OODS") => {
            if oods.len() != 3 {
                return Err("oods_shape".into());
            }
            (
                bl_pq512_crypto_core::oods::CirclePoint {
                    x: field(&oods[1])?,
                    y: field(&oods[2])?,
                },
                None,
            )
        }
        Some(command) if command == SEMANTIC_V3_PARENT_ANCHOR_COMMAND => {
            let tokens = oods[1..].iter().map(String::as_str).collect::<Vec<_>>();
            let frame = SemanticV3ParentAnchorFrame::decode_command_tokens(&tokens)
                .map_err(|error| format!("v3_parent_anchor_{error:?}"))?;
            (frame.oods_point(), Some(frame.commitment()))
        }
        _ => return Err("command_order_expected_OODS_or_V3_PARENT_ANCHOR".into()),
    };
    let deep_started = Instant::now();
    let deep = build_deep_quotient_oracles(&composition, &logup, query)
        .map_err(|error| format!("deep_{error:?}"))?;
    let claims_commitment = deep_claims_commitment(
        &composition.program_binary_commitment,
        deep.query,
        &deep.claims,
        &main_root,
        Some(&interaction_root),
        &composition_root,
    )
    .map_err(|error| format!("claims_{error:?}"))?;
    let fri_mask = build_fri_mask_oracle(
        &deep,
        claims_commitment,
        entropy.mask_seed(),
        entropy.attempt_nonce(),
    )
    .map_err(|error| format!("fri_mask_{error:?}"))?;
    let fri_mask_root = fri_mask.mask_tree.root().into_bytes();
    let deep_ms = deep_started.elapsed().as_millis();
    let oods_roots = if let Some(anchor_commitment) = v3_parent_anchor_commitment {
        format!(
            "OODS_ROOTS {} {} {}",
            encode_hex(&claims_commitment),
            encode_hex(&fri_mask_root),
            encode_hex(&anchor_commitment)
        )
    } else {
        format!(
            "OODS_ROOTS {} {}",
            encode_hex(&claims_commitment),
            encode_hex(&fri_mask_root)
        )
    };
    emit(&mut writer, &oods_roots)?;

    let batch = command(&mut reader, "BATCH")?;
    if batch.len() != 2 {
        return Err("batch_shape".into());
    }
    let batch_coefficient = field(&batch[1])?;
    let fri_started = Instant::now();
    let batch_derivation = fri_batch_derivation_commitment(
        &composition.program_binary_commitment,
        &main_root,
        &interaction_root,
        &composition_root,
        &claims_commitment,
        &fri_mask_root,
        batch_coefficient,
    );
    let mut fri_builder = start_interactive_fri(&deep, fri_mask, batch_coefficient)
        .map_err(|error| format!("fri_start_{error:?}"))?;
    if fri_builder.fold_round_count() != geometry.fold_round_count {
        return Err("fri_geometry".into());
    }
    let fri_start_ms = fri_started.elapsed().as_millis();
    emit(
        &mut writer,
        &format!("BATCH_DERIVATION {}", encode_hex(&batch_derivation)),
    )?;

    let mut fold_ms = 0_u128;
    for ordinal in 0..geometry.fold_round_count {
        let fold = command(&mut reader, "FOLD")?;
        if fold.len() != 2 {
            return Err("fold_shape".into());
        }
        let fold_started = Instant::now();
        let root = fri_builder
            .fold_next(field(&fold[1])?)
            .map_err(|error| format!("fri_fold_{ordinal}_{error:?}"))?;
        fold_ms += fold_started.elapsed().as_millis();
        emit(
            &mut writer,
            &format!("LAYER {ordinal} {}", encode_hex(&root.into_bytes())),
        )?;
    }
    let fri = fri_builder
        .finish()
        .map_err(|error| format!("fri_finish_{error:?}"))?;

    let queries = command(&mut reader, "QUERIES")?;
    if queries.len() != QUERY_COUNT + 2 || queries[1].parse::<usize>().ok() != Some(QUERY_COUNT) {
        return Err("queries_shape".into());
    }
    let query_positions = queries[2..]
        .iter()
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| "query_index".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if query_positions
        .iter()
        .any(|value| *value >= geometry.query_domain_size)
    {
        return Err("query_range".into());
    }
    let openings_started = Instant::now();
    let proof = prove_fri_pipeline(
        &deep,
        &fri,
        &oracles,
        &composition,
        &logup,
        &query_positions,
    )
    .map_err(|error| format!("prove_{error:?}"))?;
    let encoded_proof = encode_fri_pipeline_proof_v2_with_attribution(&proof)
        .map_err(|error| format!("proof_encoding_{error:?}"))?;
    drop(proof);
    let native_v3 = native_v3_export_directory
        .as_ref()
        .map(|_| {
            produce_semantic_fri_v3_from_legacy(
                &program,
                TRACE_MASK_COEFFICIENT_COUNT,
                LOG_BLOWUP,
                &deep,
                &fri,
                &oracles,
                &logup,
                &query_positions,
                &public_inputs,
                alpha,
                beta,
                gamma,
            )
            .map_err(|error| format!("native_v3_produce_{error:?}"))
        })
        .transpose()?;
    let proof_bytes = encoded_proof.bytes.len();
    let attribution = encoded_proof.attribution;
    let attribution_total = attribution
        .total_bytes()
        .ok_or_else(|| "proof_attribution_overflow".to_string())?;
    if attribution_total != proof_bytes {
        return Err("proof_attribution_mismatch".into());
    }
    let openings_ms = openings_started.elapsed().as_millis();
    emit(
        &mut writer,
        &format!(
            "PROOF_READY {proof_bytes} grammar_version=2 header_bytes={} initial_index_bytes={} mask_opening_bytes={} main_opening_bytes={} interaction_opening_bytes={} composition_opening_bytes={} next_main_opening_bytes={} next_interaction_opening_bytes={} fri_layer_count_bytes={} fri_opened_value_bytes={} fri_log_size_bytes={} fri_merkle_metadata_bytes={} fri_path_digest_bytes={} query_count={} fri_layer_count={} fri_opened_value_count={} fri_path_digest_count={}",
            attribution.header_bytes,
            attribution.initial_index_bytes,
            attribution.mask_opening_bytes,
            attribution.main_opening_bytes,
            attribution.interaction_opening_bytes,
            attribution.composition_opening_bytes,
            attribution.next_main_opening_bytes,
            attribution.next_interaction_opening_bytes,
            attribution.fri_layer_count_bytes,
            attribution.fri_opened_value_bytes,
            attribution.fri_log_size_bytes,
            attribution.fri_merkle_metadata_bytes,
            attribution.fri_path_digest_bytes,
            attribution.query_count,
            attribution.fri_layer_count,
            attribution.fri_opened_value_count,
            attribution.fri_path_digest_count,
        ),
    )?;
    maybe_inject_test_fault("after_proof_ready")?;

    let mut post_z_context = None;
    let mut bundle_command = read_command(&mut reader)?;
    if bundle_command.first().map(String::as_str) == Some("POST_Z_CONTEXT") {
        if bundle_command.len() != 2 {
            return Err("post_z_context_shape".into());
        }
        let native = native_v3
            .as_ref()
            .ok_or_else(|| "post_z_context_native_fri_missing".to_string())?;
        let context = semantic_h4_post_z_context_from_pre_final_v3(
            &decode_hex::<128>(&bundle_command[1])?,
            query,
            &native.verified,
        )
        .map_err(|error| format!("post_z_context_{error:?}"))?;
        emit(
            &mut writer,
            &format!("POST_Z_CONTEXT_READY {}", encode_hex(context.as_bytes())),
        )?;
        post_z_context = Some(context);
        bundle_command = read_command(&mut reader)?;
    }
    if bundle_command.first().map(String::as_str) == Some("FUNCTIONALS") {
        if bundle_command.len() != 3 {
            return Err("functionals_shape".into());
        }
        let attempt = bundle_command[2]
            .parse::<u16>()
            .map_err(|_| "functionals_attempt".to_string())?;
        let directory = native_v3_export_directory
            .as_ref()
            .ok_or_else(|| "functionals_export_directory_missing".to_string())?;
        let native = native_v3
            .as_ref()
            .ok_or_else(|| "functionals_native_fri_missing".to_string())?;
        let (encoded, strict_gkr, functional_inputs) = produce_retained_semantic_functionals(
            directory,
            &bundle_command[1],
            &program,
            &composition,
            native,
        )?;
        publish_new_files(
            directory,
            &[(H4_FUNCTIONAL_INPUTS_FILE, encoded.as_slice())],
        )
        .map_err(|error| format!("functionals_publish_{error}"))?;
        emit(&mut writer, &format!("FUNCTIONALS_READY {}", encoded.len()))?;
        let request_path = std::env::var_os("BL_H4_POST_Z_PROJECTION_REQUEST_PATH")
            .map(PathBuf::from)
            .ok_or_else(|| "post_z_projection_request_path_missing".to_string())?;
        let response_path = std::env::var_os("BL_H4_POST_Z_PROJECTION_RESPONSE_PATH")
            .map(PathBuf::from)
            .ok_or_else(|| "post_z_projection_response_path_missing".to_string())?;
        let opening_request_path = std::env::var_os("BL_H4_POST_Z_OPENING_REQUEST_PATH")
            .map(PathBuf::from)
            .ok_or_else(|| "post_z_opening_request_path_missing".to_string())?;
        let opening_response_path = std::env::var_os("BL_H4_POST_Z_OPENING_RESPONSE_PATH")
            .map(PathBuf::from)
            .ok_or_else(|| "post_z_opening_response_path_missing".to_string())?;
        let context = post_z_context.ok_or_else(|| "post_z_context_missing".to_string())?;
        let produced = produce_h4_post_z_response_from_fresh_projection_oracle(
            H4ProofProfileV2::K128,
            0,
            attempt,
            session_id,
            strict_gkr.verified_gkr(),
            context,
            |claim_challenge| {
                verify_semantic_bridge_source_batch_from_program_v3(
                    strict_gkr.verified_gkr(),
                    &program,
                    TRACE_MASK_COEFFICIENT_COUNT,
                    LOG_BLOWUP,
                    &native.verified,
                    &functional_inputs,
                    claim_challenge,
                )
                .map_err(|_| H4PostZProducerError::Binding)
            },
            |projection_challenges, _construction_mix| {
                publish_projection_request(&request_path, projection_challenges)
                    .map_err(|_| H4PostZProducerError::Binding)?;
                wait_for_projection_response(&response_path)
                    .map_err(|_| H4PostZProducerError::Binding)
            },
        )
        .map_err(|error| format!("post_z_produce_{error:?}"))?;
        let (source_segment, base_segment) = exchange_post_z_openings(
            &opening_request_path,
            &opening_response_path,
            produced.strict.challenges().response_seal_challenge,
        )?;
        publish_post_z_response(directory, &produced)?;
        publish_new_files(
            &directory.join("h4-shards").join("0"),
            &[
                ("source-segment.bin", source_segment.as_slice()),
                ("base-segment.bin", base_segment.as_slice()),
            ],
        )
        .map_err(|error| format!("post_z_openings_publish_{error}"))?;
        emit(
            &mut writer,
            &format!(
                "POST_Z_READY {} {}",
                produced.encoded_response.len(),
                produced.encoded_strict_bundle.len()
            ),
        )?;
        bundle_command = read_command(&mut reader)?;
        if bundle_command.first().map(String::as_str) == Some("H4_COMPLETE") {
            if bundle_command.len() != 1 {
                return Err("h4_complete_shape".into());
            }
            let aggregate_path = std::env::var_os("BL_H4_AGGREGATE_PATH")
                .map(PathBuf::from).ok_or_else(|| "h4_aggregate_path_missing".to_string())?;
            let verification_key_path = std::env::var_os("BL_H4_VERIFICATION_KEY_PATH")
                .map(PathBuf::from).ok_or_else(|| "h4_verification_key_path_missing".to_string())?;
            let mask_path = std::env::var_os("BL_H4_MASK_COEFFICIENTS_PATH")
                .map(PathBuf::from).ok_or_else(|| "h4_mask_coefficients_path_missing".to_string())?;
            let key_bytes = fs::read(&verification_key_path)
                .map_err(|error| format!("h4_verification_key_read_{:?}", error.kind()))?;
            if key_bytes.len() != H4_VERIFICATION_KEY_V2_BYTES {
                return Err("h4_verification_key_length".into());
            }
            let key = decode_h4_verification_key_v2(&key_bytes)
                .map_err(|error| format!("h4_verification_key_{error:?}"))?;
            let mut aggregate = fs::File::open(&aggregate_path)
                .map_err(|error| format!("h4_aggregate_open_{:?}", error.kind()))?;
            let aggregate_bytes = aggregate.metadata()
                .map_err(|error| format!("h4_aggregate_metadata_{:?}", error.kind()))?.len();
            let mut root_registry = StrictPqRootUseRegistryV2::new();
            let pre_alpha = verify_h4_pre_alpha_v2(
                &mut aggregate, 0, aggregate_bytes, &key, &mut root_registry,
            ).map_err(|error| format!("h4_pre_alpha_{error:?}"))?;
            let semantic_batch = verify_semantic_bridge_source_batch_from_program_v3(
                strict_gkr.verified_gkr(), &program, TRACE_MASK_COEFFICIENT_COUNT, LOG_BLOWUP,
                &native.verified, &functional_inputs, produced.strict.challenges().claim_challenge,
            ).map_err(|error| format!("h4_semantic_batch_{error:?}"))?;
            let post_z_key = StrictPqGovernedVerifierKeyV2::decode(&produced.governed_key)
                .map_err(|error| format!("h4_post_z_key_{error:?}"))?;
            let input = H4PostZResponseInput {
                encoded_strict_bundle: &produced.encoded_strict_bundle,
                encoded_response: &produced.encoded_response,
                first_ordinal: produced.first_ordinal,
                source_segment: &source_segment,
                base_segment: &base_segment,
            };
            let prepared = prepare_h4_v2_from_serialized_post_z_with_keys(
                pre_alpha, &strict_gkr, &semantic_batch, context, &[&post_z_key], &[input],
                &root_registry,
            ).map_err(|error| format!("h4_post_z_prepare_{error:?}"))?;
            let coins = derive_h4_source_mask_coins_v3(&prepared)
                .map_err(|error| format!("h4_mask_coins_{error:?}"))?;
            let mask_bytes = fs::read(&mask_path)
                .map_err(|error| format!("h4_mask_read_{:?}", error.kind()))?;
            if mask_bytes.len() % 64 != 0 {
                return Err("h4_mask_coefficients_length".into());
            }
            let mask_coefficients = mask_bytes.chunks_exact(64)
                .map(|encoded| Fp16::decode(encoded).map_err(|_| "h4_mask_field".to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            let mask_proof = prepared.produce_source_mask_proof(
                &mask_coefficients, coins.batch_challenge, &coins.inner_product_challenges,
                coins.completion_coin,
            ).map_err(|error| format!("h4_mask_produce_{error:?}"))?;
            let encoded_mask = encode_produced_h4_mask_input_v3(mask_proof.clone())
                .map_err(|error| format!("h4_mask_encode_{error}"))?;
            prepared.complete_and_commit(
                H4SourceMaskProofV2 {
                    batch_challenge: mask_proof.batch_challenge,
                    inner_product_proof: &mask_proof.inner_product_proof,
                    inner_product_challenges: &mask_proof.inner_product_challenges,
                    pcs_proof: &mask_proof.pcs_proof,
                    expected_mask_root: mask_proof.expected_mask_root,
                    expected_context: mask_proof.expected_context,
                    completion_coin: mask_proof.completion_coin,
                },
                &mut root_registry,
            ).map_err(|error| format!("h4_complete_replay_{error:?}"))?;
            publish_new_files(directory, &[(H4_MASK_INPUT_FILE, encoded_mask.as_slice())])
                .map_err(|error| format!("h4_mask_publish_{error}"))?;
            emit(&mut writer, &format!("H4_COMPLETE_READY {}", encoded_mask.len()))?;
            bundle_command = read_command(&mut reader)?;
        }
    }
    if bundle_command.first().map(String::as_str) != Some("BUNDLE") {
        return Err("command_order_expected_BUNDLE".into());
    }
    if bundle_command.len() != 2 {
        return Err("bundle_shape".into());
    }
    let bundle_encoded = decode_hex_vec(&bundle_command[1])?;
    let bundle = decode_selected_challenge_bundle(&bundle_encoded)
        .map_err(|error| format!("bundle_{error:?}"))?;
    let layer_log_sizes = (2..=geometry.maximum_evaluation_log_size)
        .rev()
        .collect::<Vec<_>>();
    let decoded_proof = decode_fri_pipeline_proof_v2(
        &encoded_proof.bytes,
        &bundle.query_positions,
        &layer_log_sizes,
    )
    .map_err(|error| format!("proof_v2_decoding_{error:?}"))?;
    let verify_started = Instant::now();
    if !verify_selected_fri_pipeline_v2(
        &decoded_proof,
        &bundle,
        &program,
        &public_inputs,
        &deep.claims,
        fri.final_constant,
    )
    .map_err(|error| format!("verify_{error:?}"))?
    {
        return Err("proof_rejected".into());
    }
    if let (Some(directory), Some(native_v3)) =
        (native_v3_export_directory.as_ref(), native_v3.as_ref())
    {
        publish_new_files(
            directory,
            &[
                (SEMANTIC_FRI_PROOF_FILE, native_v3.encoded_proof.as_slice()),
                (
                    SEMANTIC_FRI_PARAMETERS_FILE,
                    native_v3.encoded_parameters.as_slice(),
                ),
            ],
        )
        .map_err(|error| format!("native_v3_publish_{error}"))?;
    }
    let verify_ms = verify_started.elapsed().as_millis();
    emit(
        &mut writer,
        &format!(
            "OK grammar_version=2 proof_bytes={proof_bytes} attribution_total={attribution_total} query_count={} trace_masks={} quotient_masks={} folds={} main_ms={main_ms} interaction_ms={interaction_ms} composition_ms={composition_ms} deep_ms={deep_ms} fri_start_ms={fri_start_ms} fold_compute_ms={fold_ms} openings_ms={openings_ms} verify_ms={verify_ms} worker_wall_ms={}",
            query_positions.len(),
            TRACE_MASK_COEFFICIENT_COUNT,
            QUOTIENT_MASK_COEFFICIENT_COUNT,
            geometry.fold_round_count,
            total_started.elapsed().as_millis()
        ),
    )
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ERR:{error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn worker_entropy_is_fresh_across_attempts() {
        let first = WorkerEntropy::from_os().unwrap();
        let second = WorkerEntropy::from_os().unwrap();
        assert_ne!(first.mask_seed(), second.mask_seed());
        assert_ne!(first.attempt_nonce(), second.attempt_nonce());
    }

    #[test]
    fn worker_entropy_zeroizes_both_owned_buffers() {
        let mut encoded = [0_u8; ENTROPY_BYTES * 2];
        encoded[..ENTROPY_BYTES].fill(0x5a);
        encoded[ENTROPY_BYTES..].fill(0xa5);
        let mut entropy = WorkerEntropy::from_test_reader(&mut Cursor::new(encoded)).unwrap();
        entropy.zeroize();
        assert_eq!(entropy.mask_seed(), &[0_u8; ENTROPY_BYTES]);
        assert_eq!(entropy.attempt_nonce(), &[0_u8; ENTROPY_BYTES]);
    }

    #[test]
    fn worker_entropy_drop_runs_during_panic_unwind() {
        let before = WORKER_ENTROPY_DROP_COUNT.load(std::sync::atomic::Ordering::SeqCst);
        let unwound = std::panic::catch_unwind(|| {
            let _entropy = WorkerEntropy::from_os().unwrap();
            panic!("bounded entropy drop test");
        });
        assert!(unwound.is_err());
        assert!(WORKER_ENTROPY_DROP_COUNT.load(std::sync::atomic::Ordering::SeqCst) > before);
    }
}
