use std::{env, fs, process};

use stark_engine::{
    Phase8RealProverBoundaryAdapterPlan, Phase8TestOnlyProverHarnessExecutionReport,
};

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
    let execution_report_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let report_json = fs::read_to_string(&execution_report_path)
        .map_err(|err| vec![format!("could not read {execution_report_path}: {err}")])?;
    let report: Phase8TestOnlyProverHarnessExecutionReport = serde_json::from_str(&report_json)
        .map_err(|err| {
            vec![format!(
                "invalid Phase 8 test-only prover harness execution report JSON: {err}"
            )]
        })?;

    let plan = Phase8RealProverBoundaryAdapterPlan::from_execution_report(&report)?;
    plan.validate()?;

    let output_json = serde_json::to_string_pretty(&plan).map_err(|err| {
        vec![format!(
            "could not serialize Phase 8 real prover boundary adapter plan JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_real_prover_boundary_adapter_plan_generation",
            "status": "ok",
            "input": execution_report_path,
            "output": output_path,
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
        "usage: generate_phase8_real_prover_boundary_adapter_plan <phase8_test_only_prover_harness_execution_report.json> <phase8_real_prover_boundary_adapter_plan.json>"
            .to_string(),
    ]
}
