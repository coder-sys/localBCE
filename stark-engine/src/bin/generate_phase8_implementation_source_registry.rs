use std::{env, fs, process};

use stark_engine::{Phase8ImplementationSourceRegistry, Phase8RealProofArtifactReadinessGate};

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
    let readiness_gate_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let gate_json = fs::read_to_string(&readiness_gate_path)
        .map_err(|err| vec![format!("could not read {readiness_gate_path}: {err}")])?;
    let gate: Phase8RealProofArtifactReadinessGate =
        serde_json::from_str(&gate_json).map_err(|err| {
            vec![format!(
                "invalid Phase 8 real proof artifact readiness gate JSON: {err}"
            )]
        })?;

    let registry = Phase8ImplementationSourceRegistry::from_readiness_gate(&gate)?;
    registry.validate()?;

    let output_json = serde_json::to_string_pretty(&registry).map_err(|err| {
        vec![format!(
            "could not serialize Phase 8 implementation source registry JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_implementation_source_registry_generation",
            "status": "ok",
            "input": readiness_gate_path,
            "output": output_path,
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
        "usage: generate_phase8_implementation_source_registry <phase8_real_proof_artifact_readiness_gate.json> <phase8_implementation_source_registry.json>"
            .to_string(),
    ]
}
