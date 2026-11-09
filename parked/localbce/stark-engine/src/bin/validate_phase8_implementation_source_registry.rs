use std::{env, fs, process};

use stark_engine::Phase8ImplementationSourceRegistry;

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
    let registry: Phase8ImplementationSourceRegistry =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid Phase 8 implementation source registry JSON: {err}"
            )]
        })?;

    registry.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_implementation_source_registry_validation",
            "status": "ok",
            "path": path,
            "schema_version": registry.schema_version,
            "source_schema_version": registry.source_schema_version,
            "registry_status": registry.registry_status,
            "planned_sources": registry.planned_sources.len(),
            "implementation_evidence_status": registry.implementation_evidence_status,
            "satisfied_gate_count": registry.satisfied_gate_count,
            "unsatisfied_gate_count": registry.unsatisfied_gate_count,
            "real_proof_generation_allowed": registry.real_proof_generation_allowed,
            "real_artifact_emission_allowed": registry.real_artifact_emission_allowed,
            "runtime_cutover_allowed": registry.runtime_cutover_allowed,
            "on_chain_submission_allowed": registry.on_chain_submission_allowed,
            "groth16_flow_unchanged": registry.groth16_flow_unchanged,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: validate_phase8_implementation_source_registry <phase8_implementation_source_registry.json>"
            .to_string(),
    ]
}
