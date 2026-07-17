use std::{env, fs, process};

use stark_engine::{Phase8RealProverImplementationChecklist, Phase8TestOnlyProverHarnessPlan};

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
    let checklist_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let checklist_json = fs::read_to_string(&checklist_path)
        .map_err(|err| vec![format!("could not read {checklist_path}: {err}")])?;
    let checklist: Phase8RealProverImplementationChecklist = serde_json::from_str(&checklist_json)
        .map_err(|err| vec![format!("invalid Phase 8 checklist JSON: {err}")])?;

    let plan = Phase8TestOnlyProverHarnessPlan::from_checklist(&checklist)?;
    plan.validate()?;

    let output_json = serde_json::to_string_pretty(&plan).map_err(|err| {
        vec![format!(
            "could not serialize Phase 8 test-only prover harness plan JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_test_only_prover_harness_plan_generation",
            "status": "ok",
            "input": checklist_path,
            "output": output_path,
            "schema_version": plan.schema_version,
            "source_schema_version": plan.source_schema_version,
            "harness_status": plan.harness_status,
            "selected_preview_prover": plan.selected_preview_prover,
            "execution_mode": plan.execution_mode,
            "required_inputs": plan.required_inputs.len(),
            "expected_outputs": plan.expected_outputs.len(),
            "feature_gate_required": plan.feature_gate_required,
            "test_only_proof_generation_allowed": plan.test_only_proof_generation_allowed,
            "runtime_cutover_allowed": plan.runtime_cutover_allowed,
            "on_chain_submission_allowed": plan.on_chain_submission_allowed,
            "groth16_flow_unchanged": plan.groth16_flow_unchanged,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: generate_phase8_test_only_prover_harness_plan <phase8_real_prover_implementation_checklist.json> <phase8_test_only_prover_harness_plan.json>"
            .to_string(),
    ]
}
