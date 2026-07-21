use std::{env, fs, process};

use stark_engine::Phase8EvidenceReadinessReport;

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
    let report: Phase8EvidenceReadinessReport =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid Phase 8 evidence readiness report JSON: {err}"
            )]
        })?;

    report.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_evidence_readiness_report_validation",
            "status": "ok",
            "path": path,
            "schema_version": report.schema_version,
            "source_schema_version": report.source_schema_version,
            "report_status": report.report_status,
            "target_artifact_schema_version": report.target_artifact_schema_version,
            "expected_transformation_count": report.expected_transformation_count,
            "populated_slot_count": report.populated_slot_count,
            "missing_slot_count": report.missing_slot_count,
            "missing_evidence_total": report.missing_evidence_total,
            "ready_transformation_count": report.ready_transformation_count,
            "blocked_transformation_count": report.blocked_transformation_count,
            "real_proof_generation_allowed": report.real_proof_generation_allowed,
            "real_artifact_emission_allowed": report.real_artifact_emission_allowed,
            "runtime_cutover_allowed": report.runtime_cutover_allowed,
            "on_chain_submission_allowed": report.on_chain_submission_allowed,
            "groth16_flow_unchanged": report.groth16_flow_unchanged,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: validate_phase8_evidence_readiness_report <phase8_evidence_readiness_report.json>"
            .to_string(),
    ]
}
