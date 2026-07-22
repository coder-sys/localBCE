use std::{env, fs, process};

use stark_engine::real_prover::TestOnlyRealProofBytesFixture;

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
    let fixture: TestOnlyRealProofBytesFixture =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid Phase 8 test-only real proof bytes fixture JSON: {err}"
            )]
        })?;

    fixture.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_test_only_real_proof_bytes_fixture_validation",
            "status": "ok",
            "path": path,
            "schema_version": fixture.schema_version,
            "source_schema_version": fixture.source_schema_version,
            "fixture_status": fixture.fixture_status,
            "fixture_path": fixture.fixture_path,
            "proof_bytes_present": fixture.proof_bytes_present,
            "proof_bytes_length": fixture.proof_bytes_length,
            "test_only_fixture": fixture.test_only_fixture,
            "accepted_as_complete_evidence": fixture.accepted_as_complete_evidence,
            "implementation_satisfied": fixture.implementation_satisfied,
            "runtime_wiring_allowed": fixture.runtime_wiring_allowed,
            "real_proof_generation_allowed": fixture.real_proof_generation_allowed,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: validate_phase8_test_only_real_proof_bytes_fixture <phase8_test_only_real_proof_bytes_fixture.json>"
            .to_string(),
    ]
}
