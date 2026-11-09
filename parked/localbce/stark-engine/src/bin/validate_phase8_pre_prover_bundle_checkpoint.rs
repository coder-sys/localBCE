use std::{env, fs, process};

use stark_engine::Phase8PreProverBundleCheckpoint;

fn main() {
    if let Err(errors) = run() {
        for error in errors {
            eprintln!("{error}");
        }
        process::exit(1);
    }
}

fn run() -> Result<(), Vec<String>> {
    let path = env::args().nth(1).ok_or_else(usage)?;

    let input_json =
        fs::read_to_string(&path).map_err(|err| vec![format!("could not read {path}: {err}")])?;
    let checkpoint: Phase8PreProverBundleCheckpoint =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid Phase 8 pre-prover bundle checkpoint JSON: {err}"
            )]
        })?;

    checkpoint.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_pre_prover_bundle_checkpoint_validation",
            "status": "ok",
            "path": path,
            "schema_version": checkpoint.schema_version,
            "source_schema_version": checkpoint.source_schema_version,
            "checkpoint_status": checkpoint.checkpoint_status,
            "artifacts": checkpoint.artifacts.len(),
            "all_artifacts_validated": checkpoint.all_artifacts_validated,
            "all_source_roots_bound": checkpoint.all_source_roots_bound,
            "production_hash_selected": checkpoint.production_hash_selected,
            "runtime_wiring_allowed": checkpoint.runtime_wiring_allowed,
            "proof_generation_enabled": checkpoint.proof_generation_enabled,
            "groth16_flow_unchanged": checkpoint.groth16_flow_unchanged,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec!["usage: validate_phase8_pre_prover_bundle_checkpoint <phase8_pre_prover_bundle_checkpoint.json>".to_string()]
}
