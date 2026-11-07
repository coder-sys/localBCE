use std::{env, process};

fn main() {
    if let Err(errors) = run() {
        for error in errors {
            eprintln!("{error}");
        }
        process::exit(1);
    }
}

#[cfg(feature = "winterfell-poc")]
fn run() -> Result<(), Vec<String>> {
    use std::fs;

    use stark_engine::winterfell_poc_adapter::WinterfellPocRealProofFixture;

    let path = env::args().nth(1).ok_or_else(usage)?;

    let input_json =
        fs::read_to_string(&path).map_err(|err| vec![format!("could not read {path}: {err}")])?;
    let fixture: WinterfellPocRealProofFixture =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid Winterfell PoC real proof fixture JSON: {err}"
            )]
        })?;

    fixture.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "winterfell_poc_real_proof_fixture_validation",
            "status": "ok",
            "path": path,
            "schema_version": fixture.schema_version,
            "fixture_status": fixture.fixture_status,
            "prover_name": fixture.prover_name,
            "prover_version": fixture.prover_version,
            "claim_id": fixture.claim_id,
            "claim_hash": fixture.claim_hash,
            "decision": fixture.decision,
            "failure_code": fixture.failure_code,
            "proof_bytes_len": fixture.proof_bytes_len,
            "proof_bytes_sha256": fixture.proof_bytes_sha256,
            "local_verification_status": fixture.local_verification_status,
            "verified": fixture.verified,
            "production_semantics_complete": fixture.production_semantics_complete,
            "runtime_wired": fixture.runtime_wired,
            "on_chain_submission": fixture.on_chain_submission,
            "accepted_as_runtime_evidence": fixture.accepted_as_runtime_evidence,
        })
    );

    Ok(())
}

#[cfg(not(feature = "winterfell-poc"))]
fn run() -> Result<(), Vec<String>> {
    let _ = env::args();
    Err(vec![
        "validate_winterfell_poc_real_proof_fixture requires --features winterfell-poc".to_string(),
        "usage: cargo run --features winterfell-poc --bin validate_winterfell_poc_real_proof_fixture -- <winterfell_poc_real_proof_fixture.json>"
            .to_string(),
    ])
}

#[cfg(feature = "winterfell-poc")]
fn usage() -> Vec<String> {
    vec![
        "usage: validate_winterfell_poc_real_proof_fixture <winterfell_poc_real_proof_fixture.json>"
            .to_string(),
    ]
}
