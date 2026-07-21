use std::{env, fs, process};

use stark_engine::Phase8RealProverBoundaryAdapterPlan;

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
    let plan: Phase8RealProverBoundaryAdapterPlan =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid Phase 8 real prover boundary adapter plan JSON: {err}"
            )]
        })?;

    plan.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_real_prover_boundary_adapter_plan_validation",
            "status": "ok",
            "path": path,
            "schema_version": plan.schema_version,
            "source_schema_version": plan.source_schema_version,
            "adapter_status": plan.adapter_status,
            "source_preview_prover": plan.source_preview_prover,
            "target_prover_status": plan.target_prover_status,
            "target_artifact_schema_version": plan.target_artifact_schema_version,
            "required_transformations": plan.required_transformations.len(),
            "blocked_runtime_cutover_conditions": plan.blocked_runtime_cutover_conditions.len(),
            "preview_artifact_reusable_for_runtime": plan.preview_artifact_reusable_for_runtime,
            "real_proof_generation_allowed": plan.real_proof_generation_allowed,
            "runtime_cutover_allowed": plan.runtime_cutover_allowed,
            "on_chain_submission_allowed": plan.on_chain_submission_allowed,
            "groth16_flow_unchanged": plan.groth16_flow_unchanged,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: validate_phase8_real_prover_boundary_adapter_plan <phase8_real_prover_boundary_adapter_plan.json>"
            .to_string(),
    ]
}
