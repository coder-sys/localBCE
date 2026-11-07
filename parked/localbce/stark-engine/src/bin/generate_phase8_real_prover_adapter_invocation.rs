use std::{env, fs, process};

use stark_engine::real_prover::{RealProverAdapterInvocation, RealProverAttemptArtifact};

fn main() {
    if let Err(errors) = run() {
        for error in errors {
            eprintln!("{error}");
        }
        process::exit(1);
    }
}

fn run() -> Result<(), Vec<String>> {
    let mut args = env::args();
    let _binary = args.next();
    let attempt_artifact_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let input_json = fs::read_to_string(&attempt_artifact_path)
        .map_err(|err| vec![format!("could not read {attempt_artifact_path}: {err}")])?;
    let attempt_artifact: RealProverAttemptArtifact =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid Phase 8 real prover attempt artifact JSON: {err}"
            )]
        })?;

    let invocation = RealProverAdapterInvocation::from_attempt_artifact(&attempt_artifact)?;
    invocation.validate()?;

    let output_json = serde_json::to_string_pretty(&invocation).map_err(|err| {
        vec![format!(
            "could not serialize Phase 8 real prover adapter invocation JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_real_prover_adapter_invocation_generation",
            "status": "ok",
            "input": attempt_artifact_path,
            "output": output_path,
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
        "usage: generate_phase8_real_prover_adapter_invocation <phase8_real_prover_attempt_artifact.json> <phase8_real_prover_adapter_invocation.json>"
            .to_string(),
    ]
}
