use std::{env, fs, process};

use stark_engine::real_prover::TestOnlyEvidenceSatisfactionRehearsalReport;

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
    let report: TestOnlyEvidenceSatisfactionRehearsalReport = serde_json::from_str(&input_json)
        .map_err(|err| {
            vec![format!(
                "invalid Phase 8 test-only evidence satisfaction rehearsal report JSON: {err}"
            )]
        })?;

    report.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_test_only_evidence_satisfaction_rehearsal_report_validation",
            "status": "ok",
            "path": path,
            "schema_version": report.schema_version,
            "rehearsal_status": report.rehearsal_status,
            "proof_bytes_fixture_shape_present": report.proof_bytes_fixture_shape_present,
            "validation_log_shape_present": report.validation_log_shape_present,
            "proof_bytes_digest_matches_log": report.proof_bytes_digest_matches_log,
            "claim_hash_matches": report.claim_hash_matches,
            "real_proof_verified": report.real_proof_verified,
            "real_evidence_slots_satisfied": report.real_evidence_slots_satisfied,
            "blocked_real_evidence_slot_count": report.blocked_real_evidence_slot_count,
            "runtime_cutover_allowed": report.runtime_cutover_allowed,
            "real_proof_generation_allowed": report.real_proof_generation_allowed,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: validate_phase8_test_only_evidence_satisfaction_rehearsal_report <phase8_test_only_evidence_satisfaction_rehearsal_report.json>"
            .to_string(),
    ]
}
