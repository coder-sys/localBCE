use std::{env, fs, process};

use stark_engine::{Phase8TestOnlyProverHarnessExecutionReport, Phase8TestOnlyProverHarnessPlan};

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
    let harness_plan_path = args.next().ok_or_else(usage)?;
    let complete_witness_candidate_path = args.next().ok_or_else(usage)?;
    let selected_prover_byte_encoding_plan_path = args.next().ok_or_else(usage)?;
    let checklist_path = args.next().ok_or_else(usage)?;
    let proof_preview_path = args.next().ok_or_else(usage)?;
    let proof_artifact_candidate_path = args.next().ok_or_else(usage)?;
    let settlement_boundary_artifact_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let plan_json = fs::read_to_string(&harness_plan_path)
        .map_err(|err| vec![format!("could not read {harness_plan_path}: {err}")])?;
    let plan: Phase8TestOnlyProverHarnessPlan = serde_json::from_str(&plan_json)
        .map_err(|err| vec![format!("invalid Phase 8 harness plan JSON: {err}")])?;

    let complete_witness_candidate = read_json_value(
        "complete Winterfell witness candidate",
        &complete_witness_candidate_path,
    )?;
    let selected_prover_byte_encoding_plan = read_json_value(
        "selected prover byte encoding plan",
        &selected_prover_byte_encoding_plan_path,
    )?;
    let checklist = read_json_value("Phase 8 checklist", &checklist_path)?;
    let proof_preview = read_json_value("Winterfell proof preview", &proof_preview_path)?;
    let proof_artifact_candidate = read_json_value(
        "STARK proof artifact candidate",
        &proof_artifact_candidate_path,
    )?;
    let settlement_boundary_artifact = read_json_value(
        "STARK settlement boundary artifact",
        &settlement_boundary_artifact_path,
    )?;

    let report = Phase8TestOnlyProverHarnessExecutionReport::from_artifact_json_values(
        &plan,
        &complete_witness_candidate,
        &selected_prover_byte_encoding_plan,
        &checklist,
        &proof_preview,
        &proof_artifact_candidate,
        &settlement_boundary_artifact,
    )?;

    let output_json = serde_json::to_string_pretty(&report).map_err(|err| {
        vec![format!(
            "could not serialize Phase 8 test-only prover harness execution report JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_test_only_prover_harness_execution_report_generation",
            "status": "ok",
            "input": harness_plan_path,
            "output": output_path,
            "schema_version": report.schema_version,
            "source_schema_version": report.source_schema_version,
            "execution_status": report.execution_status,
            "selected_preview_prover": report.selected_preview_prover,
            "feature_gate_used": report.feature_gate_used,
            "proof_preview_status": report.proof_preview_status,
            "proof_size_bytes": report.proof_size_bytes,
            "local_verification_status": report.local_verification_status,
            "runtime_cutover_allowed": report.runtime_cutover_allowed,
            "on_chain_submission_allowed": report.on_chain_submission_allowed,
            "groth16_flow_unchanged": report.groth16_flow_unchanged,
        })
    );

    Ok(())
}

fn read_json_value(label: &str, path: &str) -> Result<serde_json::Value, Vec<String>> {
    let json =
        fs::read_to_string(path).map_err(|err| vec![format!("could not read {label}: {err}")])?;
    serde_json::from_str(&json).map_err(|err| vec![format!("invalid {label} JSON: {err}")])
}

fn usage() -> Vec<String> {
    vec![
        "usage: generate_phase8_test_only_prover_harness_execution_report <phase8_test_only_prover_harness_plan.json> <complete_winterfell_witness_candidate.json> <selected_prover_byte_encoding_plan.json> <phase8_real_prover_implementation_checklist.json> <winterfell_proof_preview.json> <stark_proof_artifact_v1_candidate.json> <stark_settlement_boundary_artifact.json> <phase8_test_only_prover_harness_execution_report.json>"
            .to_string(),
    ]
}
