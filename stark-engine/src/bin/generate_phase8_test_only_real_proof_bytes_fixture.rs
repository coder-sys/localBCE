use std::{env, fs, process};

use stark_engine::real_prover::{TestOnlyProofBytes, TestOnlyRealProofBytesFixture};

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
    let test_only_proof_bytes_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let input_json = fs::read_to_string(&test_only_proof_bytes_path).map_err(|err| {
        vec![format!(
            "could not read {test_only_proof_bytes_path}: {err}"
        )]
    })?;
    let bytes: TestOnlyProofBytes = serde_json::from_str(&input_json)
        .map_err(|err| vec![format!("invalid Phase 8 test-only proof bytes JSON: {err}")])?;

    let fixture = TestOnlyRealProofBytesFixture::from_test_only_proof_bytes(&bytes)?;
    fixture.validate()?;

    let output_json = serde_json::to_string_pretty(&fixture).map_err(|err| {
        vec![format!(
            "could not serialize Phase 8 test-only real proof bytes fixture JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_test_only_real_proof_bytes_fixture_generation",
            "status": "ok",
            "input": test_only_proof_bytes_path,
            "output": output_path,
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
        "usage: generate_phase8_test_only_real_proof_bytes_fixture <phase8_test_only_proof_bytes.json> <phase8_test_only_real_proof_bytes_fixture.json>"
            .to_string(),
    ]
}
