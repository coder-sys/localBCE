use std::{env, fs, process};

use stark_engine::Phase8TestOnlyProverHarnessExecutionReport;

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
    let report: Phase8TestOnlyProverHarnessExecutionReport = serde_json::from_str(&input_json)
        .map_err(|err| {
            vec![format!(
                "invalid Phase 8 test-only prover harness execution report JSON: {err}"
            )]
        })?;

    report.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_test_only_prover_harness_execution_report_validation",
            "status": "ok",
            "path": path,
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

fn usage() -> Vec<String> {
    vec![
        "usage: validate_phase8_test_only_prover_harness_execution_report <phase8_test_only_prover_harness_execution_report.json>"
            .to_string(),
    ]
}
