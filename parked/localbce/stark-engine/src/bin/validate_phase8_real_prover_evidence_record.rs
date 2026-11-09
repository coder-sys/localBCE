use std::{env, fs, process};

use stark_engine::real_prover::RealProverEvidenceRecord;

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
    let record: RealProverEvidenceRecord = serde_json::from_str(&input_json).map_err(|err| {
        vec![format!(
            "invalid Phase 8 real prover evidence record JSON: {err}"
        )]
    })?;

    record.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_real_prover_evidence_record_validation",
            "status": "ok",
            "path": path,
            "schema_version": record.schema_version,
            "source_schema_version": record.source_schema_version,
            "evidence_status": record.evidence_status,
            "transformation_id": record.transformation_id,
            "planned_module": record.planned_module,
            "populated_evidence_count": record.populated_evidence_count,
            "missing_evidence_count": record.missing_evidence_count,
            "implementation_satisfied": record.implementation_satisfied,
            "test_only_bytes_are_evidence": record.test_only_bytes_are_evidence,
            "runtime_wiring_allowed": record.runtime_wiring_allowed,
            "real_proof_generation_allowed": record.real_proof_generation_allowed,
            "accepted_as_implementation_evidence": record.accepted_as_implementation_evidence,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: validate_phase8_real_prover_evidence_record <phase8_real_prover_evidence_record.json>"
            .to_string(),
    ]
}
