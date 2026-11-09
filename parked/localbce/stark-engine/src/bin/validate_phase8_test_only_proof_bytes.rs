use std::{env, fs, process};

use stark_engine::real_prover::TestOnlyProofBytes;

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
    let proof_bytes: TestOnlyProofBytes = serde_json::from_str(&input_json)
        .map_err(|err| vec![format!("invalid Phase 8 test-only proof bytes JSON: {err}")])?;

    proof_bytes.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_test_only_proof_bytes_validation",
            "status": "ok",
            "path": path,
            "schema_version": proof_bytes.schema_version,
            "source_schema_version": proof_bytes.source_schema_version,
            "byte_status": proof_bytes.byte_status,
            "transformation_id": proof_bytes.transformation_id,
            "claim_id": proof_bytes.claim_id,
            "claim_hash": proof_bytes.claim_hash,
            "byte_length": proof_bytes.byte_length,
            "runtime_wiring_allowed": proof_bytes.runtime_wiring_allowed,
            "real_proof_generation_allowed": proof_bytes.real_proof_generation_allowed,
            "accepted_as_implementation_evidence": proof_bytes.accepted_as_implementation_evidence,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: validate_phase8_test_only_proof_bytes <phase8_test_only_proof_bytes.json>"
            .to_string(),
    ]
}
