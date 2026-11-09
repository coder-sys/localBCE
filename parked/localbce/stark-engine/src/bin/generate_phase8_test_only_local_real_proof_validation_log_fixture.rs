use std::{env, fs, process};

use stark_engine::real_prover::{
    TestOnlyLocalRealProofValidationLogFixture, TestOnlyRealProofBytesFixture,
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
    let test_only_fixture_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let input_json = fs::read_to_string(&test_only_fixture_path)
        .map_err(|err| vec![format!("could not read {test_only_fixture_path}: {err}")])?;
    let fixture: TestOnlyRealProofBytesFixture =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid Phase 8 test-only real proof bytes fixture JSON: {err}"
            )]
        })?;

    let log_fixture = TestOnlyLocalRealProofValidationLogFixture::from_test_only_fixture(&fixture)?;
    log_fixture.validate()?;

    let output_json = serde_json::to_string_pretty(&log_fixture).map_err(|err| {
        vec![format!(
            "could not serialize Phase 8 test-only local real proof validation log fixture JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_test_only_local_real_proof_validation_log_fixture_generation",
            "status": "ok",
            "input": test_only_fixture_path,
            "output": output_path,
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
        "usage: generate_phase8_test_only_local_real_proof_validation_log_fixture <phase8_test_only_real_proof_bytes_fixture.json> <phase8_test_only_local_real_proof_validation_log_fixture.json>"
            .to_string(),
    ]
}
