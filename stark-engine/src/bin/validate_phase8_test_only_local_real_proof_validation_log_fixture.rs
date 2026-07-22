use std::{env, fs, process};

use stark_engine::real_prover::TestOnlyLocalRealProofValidationLogFixture;

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
    let log_fixture: TestOnlyLocalRealProofValidationLogFixture = serde_json::from_str(&input_json)
        .map_err(|err| {
            vec![format!(
                "invalid Phase 8 test-only local real proof validation log fixture JSON: {err}"
            )]
        })?;

    log_fixture.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_test_only_local_real_proof_validation_log_fixture_validation",
            "status": "ok",
            "path": path,
            "schema_version": log_fixture.schema_version,
            "source_schema_version": log_fixture.source_schema_version,
            "log_status": log_fixture.log_status,
            "log_path": log_fixture.log_path,
            "prover_name": log_fixture.prover_name,
            "local_verification_status": log_fixture.local_verification_status,
            "test_only_fixture": log_fixture.test_only_fixture,
            "local_real_proof_verified": log_fixture.local_real_proof_verified,
            "accepted_as_complete_evidence": log_fixture.accepted_as_complete_evidence,
            "implementation_satisfied": log_fixture.implementation_satisfied,
            "runtime_wiring_allowed": log_fixture.runtime_wiring_allowed,
            "real_proof_generation_allowed": log_fixture.real_proof_generation_allowed,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: validate_phase8_test_only_local_real_proof_validation_log_fixture <phase8_test_only_local_real_proof_validation_log_fixture.json>"
            .to_string(),
    ]
}
