use std::{env, fs, process};

use stark_engine::Phase8RealProofArtifactReadinessGate;

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
    let gate: Phase8RealProofArtifactReadinessGate =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid Phase 8 real proof artifact readiness gate JSON: {err}"
            )]
        })?;

    gate.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_real_proof_artifact_readiness_gate_validation",
            "status": "ok",
            "path": path,
            "schema_version": gate.schema_version,
            "source_schema_version": gate.source_schema_version,
            "readiness_status": gate.readiness_status,
            "target_artifact_schema_version": gate.target_artifact_schema_version,
            "transformation_gates": gate.transformation_gates.len(),
            "satisfied_gate_count": gate.satisfied_gate_count,
            "unsatisfied_gate_count": gate.unsatisfied_gate_count,
            "blockers": gate.blockers.len(),
            "real_proof_generation_allowed": gate.real_proof_generation_allowed,
            "real_artifact_emission_allowed": gate.real_artifact_emission_allowed,
            "runtime_cutover_allowed": gate.runtime_cutover_allowed,
            "on_chain_submission_allowed": gate.on_chain_submission_allowed,
            "groth16_flow_unchanged": gate.groth16_flow_unchanged,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: validate_phase8_real_proof_artifact_readiness_gate <phase8_real_proof_artifact_readiness_gate.json>"
            .to_string(),
    ]
}
