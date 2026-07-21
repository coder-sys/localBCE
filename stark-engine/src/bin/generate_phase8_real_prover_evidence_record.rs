use std::{env, fs, process};

use stark_engine::real_prover::{RealProverEvidenceRecord, TestOnlyProofBytes};

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
    let test_only_bytes_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let input_json = fs::read_to_string(&test_only_bytes_path)
        .map_err(|err| vec![format!("could not read {test_only_bytes_path}: {err}")])?;
    let proof_bytes: TestOnlyProofBytes = serde_json::from_str(&input_json)
        .map_err(|err| vec![format!("invalid Phase 8 test-only proof bytes JSON: {err}")])?;

    let record = RealProverEvidenceRecord::from_test_only_proof_bytes(&proof_bytes)?;
    record.validate()?;

    let output_json = serde_json::to_string_pretty(&record).map_err(|err| {
        vec![format!(
            "could not serialize Phase 8 real prover evidence record JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_real_prover_evidence_record_generation",
            "status": "ok",
            "input": test_only_bytes_path,
            "output": output_path,
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
        "usage: generate_phase8_real_prover_evidence_record <phase8_test_only_proof_bytes.json> <phase8_real_prover_evidence_record.json>"
            .to_string(),
    ]
}
