use std::{env, fs, process};

use stark_engine::{Phase8RealProofArtifactReadinessGate, Phase8RealProverBoundaryAdapterPlan};

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
    let boundary_adapter_plan_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let plan_json = fs::read_to_string(&boundary_adapter_plan_path).map_err(|err| {
        vec![format!(
            "could not read {boundary_adapter_plan_path}: {err}"
        )]
    })?;
    let plan: Phase8RealProverBoundaryAdapterPlan =
        serde_json::from_str(&plan_json).map_err(|err| {
            vec![format!(
                "invalid Phase 8 real prover boundary adapter plan JSON: {err}"
            )]
        })?;

    let gate = Phase8RealProofArtifactReadinessGate::from_boundary_adapter_plan(&plan)?;
    gate.validate()?;

    let output_json = serde_json::to_string_pretty(&gate).map_err(|err| {
        vec![format!(
            "could not serialize Phase 8 real proof artifact readiness gate JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_real_proof_artifact_readiness_gate_generation",
            "status": "ok",
            "input": boundary_adapter_plan_path,
            "output": output_path,
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
        "usage: generate_phase8_real_proof_artifact_readiness_gate <phase8_real_prover_boundary_adapter_plan.json> <phase8_real_proof_artifact_readiness_gate.json>"
            .to_string(),
    ]
}
