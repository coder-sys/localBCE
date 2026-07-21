use std::{env, fs, process};

use stark_engine::{Phase8EvidenceReadinessReport, Phase8ImplementationEvidenceSlots};

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
    let slots_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let slots_json = fs::read_to_string(&slots_path)
        .map_err(|err| vec![format!("could not read {slots_path}: {err}")])?;
    let slots: Phase8ImplementationEvidenceSlots =
        serde_json::from_str(&slots_json).map_err(|err| {
            vec![format!(
                "invalid Phase 8 implementation evidence slots JSON: {err}"
            )]
        })?;

    let report = Phase8EvidenceReadinessReport::from_evidence_slots(&slots)?;
    report.validate()?;

    let output_json = serde_json::to_string_pretty(&report).map_err(|err| {
        vec![format!(
            "could not serialize Phase 8 evidence readiness report JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_evidence_readiness_report_generation",
            "status": "ok",
            "input": slots_path,
            "output": output_path,
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
        "usage: generate_phase8_evidence_readiness_report <phase8_implementation_evidence_slots.json> <phase8_evidence_readiness_report.json>"
            .to_string(),
    ]
}
