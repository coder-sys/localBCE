use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::time::Instant;

use bl_pq512_crypto_core::air_ir::MAX_AIR_BINARY_BYTES;
use bl_pq512_crypto_core::deep_quotient::{DomainOodsClaims, deep_claims_commitment};
use bl_pq512_crypto_core::disk_air::build_disk_air_main_trace_oracle;
use bl_pq512_crypto_core::disk_composition::build_disk_air_composition_oracle;
use bl_pq512_crypto_core::disk_deep::build_disk_deep_quotient_plan;
use bl_pq512_crypto_core::disk_fri::{
    build_disk_fri_mask_oracle, prove_disk_fri_pipeline, start_disk_interactive_fri,
};
use bl_pq512_crypto_core::disk_logup::build_disk_air_logup_oracle_from_streaming;
use bl_pq512_crypto_core::field::{Fp16, M31};
use bl_pq512_crypto_core::proof_format::{
    decode_fri_pipeline_proof_v2, encode_fri_pipeline_proof_v2_with_attribution,
};
use bl_pq512_crypto_core::proof_parameters::{
    LOG_BLOWUP, QUERY_COUNT, QUOTIENT_MASK_COEFFICIENT_COUNT, TRACE_MASK_COEFFICIENT_COUNT,
    selected_proof_geometry,
};
use bl_pq512_crypto_core::resource_preflight::estimate_selected_streaming_scratch;
use bl_pq512_crypto_core::selected_challenge::{
    decode_selected_challenge_bundle, fri_batch_derivation_commitment,
    verify_selected_fri_pipeline_v2,
};
use bl_pq512_crypto_core::streaming_ir::{
    MAX_STREAMING_MANIFEST_BYTES, StreamingExecutionVerifier, decode_streaming_air_manifest,
};
use bl_pq512_crypto_core::streaming_store::StreamingScratchStore;
use sha3::{Digest, Sha3_512};

const WORKER_MAGIC: &[u8; 8] = b"BLPQSDW2";
const PRIVATE_PROOF_PACKAGE_MAGIC: &[u8; 8] = b"BLPQSPK1";
const PRIVATE_PROOF_PACKAGE_VERSION: u16 = 1;
const MAX_PRIVATE_PROOF_PACKAGE_BYTES: usize = 512 * 1024 * 1024;
const MAX_CHUNK_BYTES: usize = (1 << 22) + 1024;
const MAX_CHUNK_COUNT: usize = 1 << 20;

fn stage_nonce(session_id: &[u8; 64], program_commitment: &[u8; 64], stage: &[u8]) -> [u8; 32] {
    let mut hash = Sha3_512::new();
    hash.update(b"BL/PQ512/WAVE1B/STREAMING-WORKER-STAGE/v1\0");
    hash.update(session_id);
    hash.update(program_commitment);
    hash.update((stage.len() as u64).to_be_bytes());
    hash.update(stage);
    let digest: [u8; 64] = hash.finalize().into();
    let mut nonce = [0_u8; 32];
    nonce.copy_from_slice(&digest[..32]);
    nonce
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

fn read_u64(reader: &mut impl Read) -> Result<u64, String> {
    let mut encoded = [0_u8; 8];
    reader
        .read_exact(&mut encoded)
        .map_err(|_| "initial_frame_truncated".to_string())?;
    Ok(u64::from_be_bytes(encoded))
}

fn read_bounded(reader: &mut impl Read, maximum: usize) -> Result<Vec<u8>, String> {
    let length = read_u32(reader)?;
    if length == 0 || length > maximum {
        return Err("initial_length".into());
    }
    let mut value = vec![0_u8; length];
    reader
        .read_exact(&mut value)
        .map_err(|_| "initial_frame_truncated".to_string())?;
    Ok(value)
}

fn command(reader: &mut impl BufRead, expected: &str) -> Result<Vec<String>, String> {
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

fn push_u32(output: &mut Vec<u8>, value: usize) -> Result<(), String> {
    output.extend_from_slice(
        &u32::try_from(value)
            .map_err(|_| "private_proof_package_count".to_string())?
            .to_be_bytes(),
    );
    Ok(())
}

fn push_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    push_u32(output, value.len())?;
    output.extend_from_slice(value);
    Ok(())
}

fn encode_private_proof_package(
    program: &[u8],
    public_inputs: &[M31],
    bundle: &[u8],
    claims: &[DomainOodsClaims],
    final_constant: Fp16,
    proof: &[u8],
) -> Result<Vec<u8>, String> {
    if program.is_empty()
        || public_inputs.is_empty()
        || bundle.is_empty()
        || claims.is_empty()
        || proof.is_empty()
    {
        return Err("private_proof_package_empty".into());
    }
    let mut encoded = Vec::with_capacity(
        PRIVATE_PROOF_PACKAGE_MAGIC.len() + 2 + program.len() + bundle.len() + proof.len(),
    );
    encoded.extend_from_slice(PRIVATE_PROOF_PACKAGE_MAGIC);
    encoded.extend_from_slice(&PRIVATE_PROOF_PACKAGE_VERSION.to_be_bytes());
    push_bytes(&mut encoded, program)?;
    push_u32(&mut encoded, public_inputs.len())?;
    for value in public_inputs {
        encoded.extend_from_slice(&value.as_u32().to_be_bytes());
    }
    push_bytes(&mut encoded, bundle)?;
    push_u32(&mut encoded, claims.len())?;
    for claim in claims {
        if claim.values.is_empty() || claim.values.len() != claim.conjugate_values.len() {
            return Err("private_proof_package_claim_shape".into());
        }
        encoded.push(claim.log_size);
        push_u32(&mut encoded, claim.values.len())?;
        for value in &claim.values {
            encoded.extend_from_slice(&value.encode());
        }
        for value in &claim.conjugate_values {
            encoded.extend_from_slice(&value.encode());
        }
    }
    encoded.extend_from_slice(&final_constant.encode());
    encoded.extend_from_slice(
        &u64::try_from(proof.len())
            .map_err(|_| "private_proof_package_proof_length".to_string())?
            .to_be_bytes(),
    );
    encoded.extend_from_slice(proof);
    if encoded.len() > MAX_PRIVATE_PROOF_PACKAGE_BYTES {
        return Err("private_proof_package_too_large".into());
    }
    Ok(encoded)
}

fn write_private_proof_package(path: &std::path::Path, encoded: &[u8]) -> Result<(), String> {
    use std::fs::OpenOptions;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("private_proof_package_create:{error}"))?;
    file.write_all(encoded)
        .map_err(|error| format!("private_proof_package_write:{error}"))?;
    file.sync_all()
        .map_err(|error| format!("private_proof_package_sync:{error}"))?;
    Ok(())
}

fn run() -> Result<(), String> {
    let total_started = Instant::now();
    let mut arguments = std::env::args_os();
    arguments.next();
    let scratch_parent = arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "scratch_parent_missing".to_string())?;
    if !scratch_parent.is_absolute() || !scratch_parent.is_dir() {
        return Err("scratch_parent_invalid".into());
    }
    let proof_export_path = arguments.next().map(PathBuf::from);
    if arguments.next().is_some() {
        return Err("worker_argument_shape".into());
    }
    if let Some(path) = proof_export_path.as_ref()
        && (!path.is_absolute() || path.parent() != Some(scratch_parent.as_path()) || path.exists())
    {
        return Err("private_proof_package_path_invalid".into());
    }
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = BufWriter::new(stdout.lock());
    let mut magic = [0_u8; 8];
    reader
        .read_exact(&mut magic)
        .map_err(|_| "initial_frame_truncated".to_string())?;
    if &magic != WORKER_MAGIC {
        return Err("initial_magic".into());
    }
    let program = read_bounded(&mut reader, MAX_AIR_BINARY_BYTES)?;
    let manifest_encoded = read_bounded(&mut reader, MAX_STREAMING_MANIFEST_BYTES)?;
    let mut secret_seed = [0_u8; 64];
    let mut session_id = [0_u8; 64];
    reader
        .read_exact(&mut secret_seed)
        .map_err(|_| "initial_frame_truncated".to_string())?;
    reader
        .read_exact(&mut session_id)
        .map_err(|_| "initial_frame_truncated".to_string())?;
    if !secret_seed.iter().any(|byte| *byte != 0) || !session_id.iter().any(|byte| *byte != 0) {
        return Err("initial_entropy".into());
    }
    let manifest = decode_streaming_air_manifest(&manifest_encoded, &program)
        .map_err(|error| format!("manifest_{error:?}"))?;
    let reported_available_bytes = u128::from(read_u64(&mut reader)?);
    let raw_witness_bytes = manifest.tables.iter().try_fold(0_u128, |total, table| {
        table.columns.iter().try_fold(total, |subtotal, column| {
            let bytes = (column.value_count as u128)
                .checked_mul(4)
                .ok_or_else(|| "scratch_preflight_overflow".to_string())?;
            subtotal
                .checked_add(bytes)
                .ok_or_else(|| "scratch_preflight_overflow".to_string())
        })
    })?;
    let scratch = estimate_selected_streaming_scratch(&program, raw_witness_bytes)
        .map_err(|error| format!("scratch_preflight_{error:?}"))?;
    if reported_available_bytes < scratch.required_available_bytes {
        return Err(format!(
            "scratch_capacity_required_{}_available_{}",
            scratch.required_available_bytes, reported_available_bytes
        ));
    }
    let chunk_count = read_u32(&mut reader)?;
    if chunk_count == 0 || chunk_count > MAX_CHUNK_COUNT {
        return Err("chunk_count".into());
    }
    let program_commitment = manifest.program_binary_commitment;
    let store_nonce = stage_nonce(&session_id, &program_commitment, b"store");
    let mut verifier = StreamingExecutionVerifier::new(&manifest);
    let mut store = StreamingScratchStore::create(&scratch_parent, &store_nonce, &manifest)
        .map_err(|error| format!("store_{error:?}"))?;
    for _ in 0..chunk_count {
        let chunk = read_bounded(&mut reader, MAX_CHUNK_BYTES)?;
        verifier
            .absorb(&chunk)
            .map_err(|error| format!("stream_{error:?}"))?;
        store
            .absorb(&chunk)
            .map_err(|error| format!("store_{error:?}"))?;
    }
    verifier
        .finish()
        .map_err(|error| format!("stream_{error:?}"))?;
    let execution = store.finish().map_err(|error| format!("store_{error:?}"))?;
    let public_inputs = manifest.public_inputs.clone();
    let geometry =
        selected_proof_geometry(&program).map_err(|error| format!("geometry_{error:?}"))?;

    let main_started = Instant::now();
    let main = build_disk_air_main_trace_oracle(
        &program,
        &execution,
        &secret_seed,
        &session_id,
        TRACE_MASK_COEFFICIENT_COUNT,
        LOG_BLOWUP,
        &scratch_parent,
        &stage_nonce(&session_id, &program_commitment, b"main"),
    )
    .map_err(|error| format!("main_{error:?}"))?;
    let main_root = main.tree.root().into_bytes();
    let main_ms = main_started.elapsed().as_millis();
    emit(&mut writer, &format!("MAIN {}", encode_hex(&main_root)))?;

    let interaction = command(&mut reader, "INTERACTION")?;
    if interaction.len() != 3 {
        return Err("interaction_shape".into());
    }
    let beta = field(&interaction[1])?;
    let gamma = field(&interaction[2])?;
    let interaction_started = Instant::now();
    let table_logs = main
        .tables
        .iter()
        .map(|table| table.evaluation_log_size)
        .collect::<Vec<_>>();
    let logup = build_disk_air_logup_oracle_from_streaming(
        &program,
        &execution,
        beta,
        gamma,
        &secret_seed,
        &session_id,
        TRACE_MASK_COEFFICIENT_COUNT,
        LOG_BLOWUP,
        &table_logs,
        &scratch_parent,
        &stage_nonce(&session_id, &program_commitment, b"interaction"),
    )
    .map_err(|error| format!("logup_{error:?}"))?;
    let interaction_root = logup.tree.root().into_bytes();
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
    let composition = build_disk_air_composition_oracle(
        &program,
        &execution,
        &main,
        &logup,
        beta,
        gamma,
        alpha,
        &secret_seed,
        &session_id,
        TRACE_MASK_COEFFICIENT_COUNT,
        QUOTIENT_MASK_COEFFICIENT_COUNT,
        LOG_BLOWUP,
        &scratch_parent,
        &stage_nonce(&session_id, &program_commitment, b"composition"),
    )
    .map_err(|error| format!("composition_{error:?}"))?;
    let composition_root = composition.tree.root().into_bytes();
    let composition_ms = composition_started.elapsed().as_millis();
    emit(
        &mut writer,
        &format!("COMPOSITION_ROOT {}", encode_hex(&composition_root)),
    )?;

    let oods = command(&mut reader, "OODS")?;
    if oods.len() != 3 {
        return Err("oods_shape".into());
    }
    let query = bl_pq512_crypto_core::oods::CirclePoint {
        x: field(&oods[1])?,
        y: field(&oods[2])?,
    };
    let deep_started = Instant::now();
    let deep = build_disk_deep_quotient_plan(
        &main,
        &logup,
        &composition,
        query,
        &scratch_parent,
        &stage_nonce(&session_id, &program_commitment, b"deep"),
    )
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
    let fri_mask = build_disk_fri_mask_oracle(
        &deep,
        claims_commitment,
        &secret_seed,
        &session_id,
        &scratch_parent,
        &stage_nonce(&session_id, &program_commitment, b"fri-mask"),
    )
    .map_err(|error| format!("fri_mask_{error:?}"))?;
    let fri_mask_root = fri_mask.tree.root().into_bytes();
    let deep_ms = deep_started.elapsed().as_millis();
    emit(
        &mut writer,
        &format!(
            "OODS_ROOTS {} {}",
            encode_hex(&claims_commitment),
            encode_hex(&fri_mask_root)
        ),
    )?;

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
    let mut fri_builder = start_disk_interactive_fri(deep, fri_mask, batch_coefficient)
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
    let proof = prove_disk_fri_pipeline(&fri, &main, &logup, &composition, &query_positions)
        .map_err(|error| format!("prove_{error:?}"))?;
    let encoded_proof = encode_fri_pipeline_proof_v2_with_attribution(&proof)
        .map_err(|error| format!("proof_encoding_{error:?}"))?;
    drop(proof);
    let claims = fri.plan.claims.clone();
    let final_constant = fri.final_constant;
    drop(fri);
    drop(composition);
    drop(logup);
    drop(main);
    drop(execution);
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

    let bundle_command = command(&mut reader, "BUNDLE")?;
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
        &claims,
        final_constant,
    )
    .map_err(|error| format!("verify_{error:?}"))?
    {
        return Err("proof_rejected".into());
    }
    drop(decoded_proof);
    let verify_ms = verify_started.elapsed().as_millis();
    if let Some(path) = proof_export_path.as_ref() {
        let package = encode_private_proof_package(
            &program,
            &public_inputs,
            &bundle_encoded,
            &claims,
            final_constant,
            &encoded_proof.bytes,
        )?;
        write_private_proof_package(path, &package)?;
    }
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
