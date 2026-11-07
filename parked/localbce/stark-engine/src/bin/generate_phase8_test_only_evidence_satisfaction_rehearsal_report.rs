use std::{env, fs, process};

use stark_engine::real_prover::{
    TestOnlyEvidenceSatisfactionRehearsalReport, TestOnlyLocalRealProofValidationLogFixture,
    TestOnlyRealProofBytesFixture,
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
    let proof_fixture_path = args.next().ok_or_else(usage)?;
    let validation_log_fixture_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let proof_fixture_json = fs::read_to_string(&proof_fixture_path)
        .map_err(|err| vec![format!("could not read {proof_fixture_path}: {err}")])?;
    let proof_fixture: TestOnlyRealProofBytesFixture = serde_json::from_str(&proof_fixture_json)
        .map_err(|err| {
            vec![format!(
                "invalid Phase 8 test-only real proof bytes fixture JSON: {err}"
            )]
        })?;

    let validation_log_json = fs::read_to_string(&validation_log_fixture_path).map_err(|err| {
        vec![format!(
            "could not read {validation_log_fixture_path}: {err}"
        )]
    })?;
    let validation_log: TestOnlyLocalRealProofValidationLogFixture =
        serde_json::from_str(&validation_log_json).map_err(|err| {
            vec![format!(
                "invalid Phase 8 test-only local real proof validation log fixture JSON: {err}"
            )]
        })?;

    let report = TestOnlyEvidenceSatisfactionRehearsalReport::from_test_only_fixtures(
        &proof_fixture,
        &validation_log,
    )?;
    report.validate()?;

    let output_json = serde_json::to_string_pretty(&report).map_err(|err| {
        vec![format!(
            "could not serialize Phase 8 test-only evidence satisfaction rehearsal report JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_test_only_evidence_satisfaction_rehearsal_report_generation",
            "status": "ok",
            "proof_fixture": proof_fixture_path,
            "validation_log_fixture": validation_log_fixture_path,
            "output": output_path,
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
        "usage: generate_phase8_test_only_evidence_satisfaction_rehearsal_report <phase8_test_only_real_proof_bytes_fixture.json> <phase8_test_only_local_real_proof_validation_log_fixture.json> <phase8_test_only_evidence_satisfaction_rehearsal_report.json>"
            .to_string(),
    ]
}
