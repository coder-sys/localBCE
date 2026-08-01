use std::io::{self, Read};
use std::path::PathBuf;

use bl_pq512_crypto_core::air_composition::{
    add_logup_to_composition, build_air_composition_from_main, build_air_main_trace_oracle,
};
use bl_pq512_crypto_core::air_logup::{
    build_air_logup_oracle_at_evaluation_logs, build_air_logup_unmasked_at_evaluation_logs,
};
use bl_pq512_crypto_core::composition_mask::mask_composition_components;
use bl_pq512_crypto_core::deep_quotient::build_deep_quotient_oracles;
use bl_pq512_crypto_core::disk_air::build_disk_air_main_trace_oracle;
use bl_pq512_crypto_core::disk_composition::build_disk_air_composition_oracle;
use bl_pq512_crypto_core::disk_deep::build_disk_deep_quotient_plan;
use bl_pq512_crypto_core::disk_fri::{
    build_disk_fri_mask_oracle, prove_disk_fri_pipeline, start_disk_interactive_fri,
};
use bl_pq512_crypto_core::disk_logup::{
    build_disk_air_logup_oracle, build_disk_air_logup_oracle_from_streaming,
};
use bl_pq512_crypto_core::field::{Fp16, M31};
use bl_pq512_crypto_core::fri_pipeline::{
    build_fri_mask_oracle, prove_fri_pipeline, start_interactive_fri,
};
use bl_pq512_crypto_core::oods::{
    OODS_DEFAULT_MAX_ATTEMPTS, sample_oods_parameter, stereographic_circle_point,
};
use bl_pq512_crypto_core::oracle_commitment::{
    commit_air_oracles_with_precommitments, commit_interaction_trace_oracle,
    commit_main_trace_oracle,
};
use bl_pq512_crypto_core::proof_parameters::{
    LOG_BLOWUP, QUOTIENT_MASK_COEFFICIENT_COUNT, TRACE_MASK_COEFFICIENT_COUNT,
};
use bl_pq512_crypto_core::streaming_ir::{
    StreamingExecutionVerifier, decode_streaming_air_manifest,
};
use bl_pq512_crypto_core::streaming_store::StreamingScratchStore;

fn take_framed<'a>(encoded: &'a [u8], offset: &mut usize) -> Option<&'a [u8]> {
    let length_end = offset.checked_add(4)?;
    let length = usize::try_from(u32::from_be_bytes(
        encoded.get(*offset..length_end)?.try_into().ok()?,
    ))
    .ok()?;
    *offset = length_end;
    let end = offset.checked_add(length)?;
    let value = encoded.get(*offset..end)?;
    *offset = end;
    Some(value)
}

fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 15)] as char);
    }
    output
}

fn run() -> Result<String, String> {
    let scratch_parent = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| String::from("scratch_parent_missing"))?;
    let mut encoded = Vec::new();
    io::stdin()
        .take((1_u64 << 30) + 1)
        .read_to_end(&mut encoded)
        .map_err(|_| String::from("input_read_failed"))?;
    if encoded.len() > 1 << 30 {
        return Err(String::from("input_too_large"));
    }
    let mut offset = 0usize;
    let program =
        take_framed(&encoded, &mut offset).ok_or_else(|| String::from("program_frame"))?;
    let execution =
        take_framed(&encoded, &mut offset).ok_or_else(|| String::from("execution_frame"))?;
    let manifest_encoded =
        take_framed(&encoded, &mut offset).ok_or_else(|| String::from("manifest_frame"))?;
    let secret_seed =
        take_framed(&encoded, &mut offset).ok_or_else(|| String::from("seed_frame"))?;
    let session_id =
        take_framed(&encoded, &mut offset).ok_or_else(|| String::from("session_frame"))?;
    let manifest = decode_streaming_air_manifest(manifest_encoded, program)
        .map_err(|error| error.to_string())?;
    let mut store = StreamingScratchStore::create(&scratch_parent, &[0xa1; 32], &manifest)
        .map_err(|error| error.to_string())?;
    let mut verifier = StreamingExecutionVerifier::new(&manifest);
    while offset < encoded.len() {
        let chunk =
            take_framed(&encoded, &mut offset).ok_or_else(|| String::from("chunk_frame"))?;
        verifier.absorb(chunk).map_err(|error| error.to_string())?;
        store.absorb(chunk).map_err(|error| error.to_string())?;
    }
    verifier.finish().map_err(|error| error.to_string())?;
    let streamed = store.finish().map_err(|error| error.to_string())?;
    let disk = build_disk_air_main_trace_oracle(
        program,
        &streamed,
        secret_seed,
        session_id,
        TRACE_MASK_COEFFICIENT_COUNT,
        LOG_BLOWUP,
        &scratch_parent,
        &[0xb2; 32],
    )
    .map_err(|error| format!("disk_main:{error}"))?;
    let memory = build_air_main_trace_oracle(
        program,
        execution,
        secret_seed,
        session_id,
        TRACE_MASK_COEFFICIENT_COUNT,
        LOG_BLOWUP,
    )
    .map_err(|error| format!("{error:?}"))?;
    let memory_tree = commit_main_trace_oracle(&memory).map_err(|error| format!("{error:?}"))?;
    if disk.tree.root() != memory_tree.root() {
        return Err(String::from("disk_memory_root_mismatch"));
    }
    let domain_size = 1_usize << disk.tree.layout().maximum_log_size();
    let queries = [
        0,
        1,
        2,
        domain_size / 3,
        domain_size / 2,
        domain_size - 2,
        domain_size - 1,
    ];
    for query in queries {
        if disk.tree.proof(query).map_err(|error| error.to_string())?
            != memory_tree
                .proof(query)
                .map_err(|error| format!("{error:?}"))?
        {
            return Err(String::from("disk_memory_proof_mismatch"));
        }
    }
    let table_logs = memory
        .tables
        .iter()
        .map(|table| table.evaluation_log_size)
        .collect::<Vec<_>>();
    let beta = Fp16::from_m31(M31::from_canonical(31).map_err(|error| error.to_string())?);
    let gamma = Fp16::from_m31(M31::from_canonical(47).map_err(|error| error.to_string())?);
    let mut memory_logup = build_air_logup_oracle_at_evaluation_logs(
        program,
        execution,
        beta,
        gamma,
        secret_seed,
        session_id,
        TRACE_MASK_COEFFICIENT_COUNT,
        LOG_BLOWUP,
        &table_logs,
    )
    .map_err(|error| format!("{error:?}"))?;
    let unmasked_logup = build_air_logup_unmasked_at_evaluation_logs(
        program,
        execution,
        beta,
        gamma,
        secret_seed,
        session_id,
        TRACE_MASK_COEFFICIENT_COUNT,
        LOG_BLOWUP,
        &table_logs,
    )
    .map_err(|error| format!("{error:?}"))?;
    let disk_logup = build_disk_air_logup_oracle(
        program,
        &unmasked_logup,
        &memory.source_program_commitment,
        secret_seed,
        session_id,
        TRACE_MASK_COEFFICIENT_COUNT,
        LOG_BLOWUP,
        &scratch_parent,
        &[0xc3; 32],
    )
    .map_err(|error| format!("disk_logup:{error}"))?;
    let memory_logup_tree =
        commit_interaction_trace_oracle(&memory.program_binary_commitment, &memory_logup)
            .map_err(|error| format!("{error:?}"))?
            .ok_or_else(|| String::from("memory_logup_tree_missing"))?;
    if disk_logup.tree.root() != memory_logup_tree.root() {
        return Err(String::from("disk_memory_logup_root_mismatch"));
    }
    let streamed_logup = build_disk_air_logup_oracle_from_streaming(
        program,
        &streamed,
        beta,
        gamma,
        secret_seed,
        session_id,
        TRACE_MASK_COEFFICIENT_COUNT,
        LOG_BLOWUP,
        &table_logs,
        &scratch_parent,
        &[0xd4; 32],
    )
    .map_err(|error| error.to_string())?;
    if streamed_logup.tree.root() != memory_logup_tree.root()
        || streamed_logup.lookup_count != memory_logup.lookup_count
        || streamed_logup.side_count != memory_logup.side_count
        || streamed_logup.denominator_count != memory_logup.denominator_count
    {
        return Err(String::from("streamed_memory_logup_mismatch"));
    }
    let interaction_domain_size = 1_usize << disk_logup.tree.layout().maximum_log_size();
    for query in [
        0,
        1,
        interaction_domain_size / 3,
        interaction_domain_size / 2,
        interaction_domain_size - 1,
    ] {
        if disk_logup
            .tree
            .proof(query)
            .map_err(|error| error.to_string())?
            != memory_logup_tree
                .proof(query)
                .map_err(|error| format!("{error:?}"))?
        {
            return Err(String::from("disk_memory_logup_proof_mismatch"));
        }
    }
    let alpha = Fp16::from_m31(M31::from_canonical(59).map_err(|error| error.to_string())?);
    let disk_composition = build_disk_air_composition_oracle(
        program,
        &streamed,
        &disk,
        &streamed_logup,
        beta,
        gamma,
        alpha,
        secret_seed,
        session_id,
        TRACE_MASK_COEFFICIENT_COUNT,
        QUOTIENT_MASK_COEFFICIENT_COUNT,
        LOG_BLOWUP,
        &scratch_parent,
        &[0xe5; 32],
    )
    .map_err(|error| format!("disk_composition:{error}"))?;
    let mut memory_composition = build_air_composition_from_main(program, execution, alpha, memory)
        .map_err(|error| format!("{error:?}"))?;
    add_logup_to_composition(
        program,
        execution,
        &mut memory_composition,
        &mut memory_logup,
        beta,
        gamma,
        alpha,
        secret_seed,
        session_id,
        TRACE_MASK_COEFFICIENT_COUNT,
    )
    .map_err(|error| format!("{error:?}"))?;
    mask_composition_components(
        &mut memory_composition,
        secret_seed,
        session_id,
        QUOTIENT_MASK_COEFFICIENT_COUNT,
    )
    .map_err(|error| format!("memory_composition_mask:{error:?}"))?;
    let memory_oracles = commit_air_oracles_with_precommitments(
        memory_tree,
        Some(memory_logup_tree),
        &memory_composition,
        &memory_logup,
    )
    .map_err(|error| format!("{error:?}"))?;
    if disk_composition.tree.root() != memory_oracles.composition.root() {
        return Err(String::from("disk_memory_composition_root_mismatch"));
    }
    let composition_domain_size = 1_usize << disk_composition.tree.layout().maximum_log_size();
    for query in [
        0,
        1,
        composition_domain_size / 3,
        composition_domain_size / 2,
        composition_domain_size - 1,
    ] {
        if disk_composition
            .tree
            .proof(query)
            .map_err(|error| error.to_string())?
            != memory_oracles
                .composition
                .proof(query)
                .map_err(|error| format!("{error:?}"))?
        {
            return Err(String::from("disk_memory_composition_proof_mismatch"));
        }
    }
    let oods = sample_oods_parameter(&[0x6a; 64], &[0x7b; 64], 3, OODS_DEFAULT_MAX_ATTEMPTS)
        .map_err(|error| error.to_string())?;
    let query = stereographic_circle_point(oods.parameter).map_err(|error| error.to_string())?;
    let disk_deep = build_disk_deep_quotient_plan(
        &disk,
        &streamed_logup,
        &disk_composition,
        query,
        &scratch_parent,
        &[0xf6; 32],
    )
    .map_err(|error| format!("disk_deep:{error}"))?;
    let memory_deep = build_deep_quotient_oracles(&memory_composition, &memory_logup, query)
        .map_err(|error| format!("{error:?}"))?;
    if disk_deep.claims != memory_deep.claims {
        return Err(String::from("disk_memory_deep_claim_mismatch"));
    }
    let memory_masks = build_fri_mask_oracle(&memory_deep, [0x83; 64], secret_seed, session_id)
        .map_err(|error| format!("{error:?}"))?;
    if disk_deep
        .domains
        .iter()
        .map(|domain| domain.degree_bound)
        .ne(memory_masks.degree_bounds.iter().copied())
    {
        return Err(String::from("disk_memory_deep_degree_mismatch"));
    }
    let disk_deep_domain_count = disk_deep.domains.len();
    let disk_masks = build_disk_fri_mask_oracle(
        &disk_deep,
        [0x83; 64],
        secret_seed,
        session_id,
        &scratch_parent,
        &[0x17; 32],
    )
    .map_err(|error| error.to_string())?;
    if disk_masks.tree.root() != memory_masks.mask_tree.root() {
        return Err(String::from("disk_memory_fri_mask_root_mismatch"));
    }
    let mask_domain_size = 1_usize << disk_masks.tree.layout().maximum_log_size();
    for query_index in [0, 1, mask_domain_size / 2, mask_domain_size - 1] {
        if disk_masks
            .tree
            .proof(query_index)
            .map_err(|error| error.to_string())?
            != memory_masks
                .mask_tree
                .proof(query_index)
                .map_err(|error| format!("{error:?}"))?
        {
            return Err(String::from("disk_memory_fri_mask_proof_mismatch"));
        }
    }
    let batch_coefficient =
        Fp16::from_m31(M31::from_canonical(89).map_err(|error| error.to_string())?);
    let mut disk_fri = start_disk_interactive_fri(disk_deep, disk_masks, batch_coefficient)
        .map_err(|error| error.to_string())?;
    let mut memory_fri = start_interactive_fri(&memory_deep, memory_masks, batch_coefficient)
        .map_err(|error| format!("{error:?}"))?;
    if disk_fri.fold_round_count() != memory_fri.fold_round_count() {
        return Err(String::from("disk_memory_fri_round_count_mismatch"));
    }
    for round in 0..disk_fri.fold_round_count() {
        let coefficient = Fp16::from_m31(
            M31::from_canonical(101 + u32::try_from(round).map_err(|_| "round_overflow")?)
                .map_err(|error| error.to_string())?,
        );
        let disk_root = disk_fri
            .fold_next(coefficient)
            .map_err(|error| error.to_string())?;
        let memory_root = memory_fri
            .fold_next(coefficient)
            .map_err(|error| format!("{error:?}"))?;
        if disk_root != memory_root {
            return Err(String::from("disk_memory_fri_layer_root_mismatch"));
        }
    }
    let disk_fri = disk_fri.finish().map_err(|error| error.to_string())?;
    let memory_fri = memory_fri.finish().map_err(|error| format!("{error:?}"))?;
    if disk_fri.final_constant != memory_fri.final_constant {
        return Err(String::from("disk_memory_fri_final_mismatch"));
    }
    let proof_queries = [
        0,
        1,
        composition_domain_size / 2,
        composition_domain_size - 1,
    ];
    let disk_proof = prove_disk_fri_pipeline(
        &disk_fri,
        &disk,
        &streamed_logup,
        &disk_composition,
        &proof_queries,
    )
    .map_err(|error| error.to_string())?;
    let memory_proof = prove_fri_pipeline(
        &memory_deep,
        &memory_fri,
        &memory_oracles,
        &memory_composition,
        &memory_logup,
        &proof_queries,
    )
    .map_err(|error| format!("{error:?}"))?;
    if disk_proof != memory_proof {
        return Err(String::from("disk_memory_fri_proof_mismatch"));
    }
    Ok(format!(
        "OK root={} interaction_root={} composition_root={} deep_domains={} fri_layers={} tables={}",
        hex(&disk.tree.root().into_bytes()),
        hex(&disk_logup.tree.root().into_bytes()),
        hex(&disk_composition.tree.root().into_bytes()),
        disk_deep_domain_count,
        disk_fri.layers.len(),
        disk.tables.len()
    ))
}

fn main() {
    match run() {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}
