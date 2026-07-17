use std::{env, fs, process};

use stark_engine::Phase8TestOnlyProverHarnessPlan;

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
    let plan: Phase8TestOnlyProverHarnessPlan =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid Phase 8 test-only prover harness plan JSON: {err}"
            )]
        })?;

    plan.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_test_only_prover_harness_plan_validation",
            "status": "ok",
            "path": path,
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
        "usage: validate_phase8_test_only_prover_harness_plan <phase8_test_only_prover_harness_plan.json>"
            .to_string(),
    ]
}
