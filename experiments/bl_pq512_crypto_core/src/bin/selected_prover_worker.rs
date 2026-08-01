use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::time::Instant;

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

const WORKER_MAGIC: &[u8; 8] = b"BLPQSPW1";

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

fn run() -> Result<(), String> {
    let total_started = Instant::now();
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
    let program = read_bounded(&mut reader)?;
    let execution = read_bounded(&mut reader)?;
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
        &secret_seed,
        &session_id,
        TRACE_MASK_COEFFICIENT_COUNT,
        LOG_BLOWUP,
    )
    .map_err(|error| format!("main_{error:?}"))?;
    let main_tree = commit_main_trace_oracle(&main).map_err(|error| format!("main_{error:?}"))?;
    let main_root = main_tree.root().into_bytes();
    let main_ms = main_started.elapsed().as_millis();
    emit(&mut writer, &format!("MAIN {}", encode_hex(&main_root)))?;

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
        &secret_seed,
        &session_id,
        TRACE_MASK_COEFFICIENT_COUNT,
        LOG_BLOWUP,
        &table_evaluation_log_sizes,
    )
    .map_err(|error| format!("logup_{error:?}"))?;
    prepare_logup_for_composition(
        &program,
        &main,
        &mut logup,
        &secret_seed,
        &session_id,
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
        &secret_seed,
        &session_id,
        TRACE_MASK_COEFFICIENT_COUNT,
    )
    .map_err(|error| format!("composition_logup_{error:?}"))?;
    mask_composition_components(
        &mut composition,
        &secret_seed,
        &session_id,
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

    let oods = command(&mut reader, "OODS")?;
    if oods.len() != 3 {
        return Err("oods_shape".into());
    }
    let query = bl_pq512_crypto_core::oods::CirclePoint {
        x: field(&oods[1])?,
        y: field(&oods[2])?,
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
    let fri_mask = build_fri_mask_oracle(&deep, claims_commitment, &secret_seed, &session_id)
        .map_err(|error| format!("fri_mask_{error:?}"))?;
    let fri_mask_root = fri_mask.mask_tree.root().into_bytes();
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
        &deep.claims,
        fri.final_constant,
    )
    .map_err(|error| format!("verify_{error:?}"))?
    {
        return Err("proof_rejected".into());
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
