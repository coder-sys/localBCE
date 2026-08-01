use std::fs;
use std::path::PathBuf;

use bl_pq512_crypto_core::resource_preflight::{
    RESOURCE_PREFLIGHT_EVIDENCE_CLASS, RESOURCE_PREFLIGHT_MODEL_ID,
    estimate_selected_prover_resources, estimate_selected_streaming_scratch,
};

fn run() -> Result<(), String> {
    let program_path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| "program_path_missing".to_string())?;
    let raw_witness_bytes = std::env::args()
        .nth(2)
        .ok_or_else(|| "raw_witness_bytes_missing".to_string())?
        .parse::<u128>()
        .map_err(|_| "raw_witness_bytes_invalid".to_string())?;
    if !program_path.is_absolute() || !program_path.is_file() || raw_witness_bytes == 0 {
        return Err("input_invalid".to_string());
    }
    let program = fs::read(program_path).map_err(|_| "program_read".to_string())?;
    let memory = estimate_selected_prover_resources(&program)
        .map_err(|error| format!("memory_{error:?}"))?;
    let scratch = estimate_selected_streaming_scratch(&program, raw_witness_bytes)
        .map_err(|error| format!("scratch_{error:?}"))?;
    println!("evidence_class={RESOURCE_PREFLIGHT_EVIDENCE_CLASS}");
    println!("model_id={RESOURCE_PREFLIGHT_MODEL_ID}");
    println!("qualifies=false");
    println!("activation_allowed=false");
    println!(
        "modeled_main_evaluation_bytes={}",
        memory.main_evaluation_bytes
    );
    println!(
        "modeled_interaction_evaluation_bytes={}",
        memory.interaction_evaluation_bytes
    );
    println!(
        "modeled_composition_evaluation_bytes={}",
        memory.composition_evaluation_bytes
    );
    println!(
        "modeled_deep_evaluation_bytes={}",
        memory.deep_evaluation_bytes
    );
    println!("modeled_fri_mask_bytes={}", memory.fri_mask_bytes);
    println!("modeled_folded_layer_bytes={}", memory.folded_layer_bytes);
    println!(
        "modeled_monolithic_live_bytes_lower_bound={}",
        memory.monolithic_live_bytes_lower_bound
    );
    println!("modeled_maximum_domain_rows={}", memory.maximum_domain_rows);
    println!("requires_streaming={}", memory.requires_streaming);
    println!("modeled_raw_witness_bytes={}", scratch.raw_witness_bytes);
    println!(
        "modeled_persistent_oracle_bytes={}",
        scratch.persistent_oracle_bytes
    );
    println!(
        "modeled_peak_temporary_bytes={}",
        scratch.peak_temporary_bytes
    );
    println!(
        "modeled_filesystem_overhead_bytes={}",
        scratch.filesystem_overhead_bytes
    );
    println!("modeled_reserve_bytes={}", scratch.reserve_bytes);
    println!(
        "modeled_required_available_bytes={}",
        scratch.required_available_bytes
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("resource preflight failed: {error}");
        std::process::exit(1);
    }
}
