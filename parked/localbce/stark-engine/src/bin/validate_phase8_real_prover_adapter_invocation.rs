use std::{env, fs, process};

use stark_engine::real_prover::RealProverAdapterInvocation;

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
    let invocation: RealProverAdapterInvocation =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid Phase 8 real prover adapter invocation JSON: {err}"
            )]
        })?;

    invocation.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_real_prover_adapter_invocation_validation",
            "status": "ok",
            "path": path,
            "schema_version": invocation.schema_version,
            "source_schema_version": invocation.source_schema_version,
            "adapter_status": invocation.adapter_status,
            "feature_gate": invocation.feature_gate,
            "feature_enabled": invocation.feature_enabled,
            "blocker_status": invocation.blocker_status,
            "attempted_real_proof_generation": invocation.attempted_real_proof_generation,
            "emitted_real_proof_bytes": invocation.emitted_real_proof_bytes,
            "local_real_proof_verified": invocation.local_real_proof_verified,
            "runtime_wiring_allowed": invocation.runtime_wiring_allowed,
            "real_proof_generation_allowed": invocation.real_proof_generation_allowed,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: validate_phase8_real_prover_adapter_invocation <phase8_real_prover_adapter_invocation.json>"
            .to_string(),
    ]
}
