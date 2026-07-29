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

    use stark_engine::{
        WinterfellCompleteWitnessCandidate, winterfell_poc_adapter::WinterfellPocRealProofFixture,
    };

    let mut args = env::args();
    let _binary = args.next();
    let input_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let input_json = fs::read_to_string(&input_path)
        .map_err(|err| vec![format!("could not read {input_path}: {err}")])?;
    let candidate: WinterfellCompleteWitnessCandidate =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid complete Winterfell witness candidate JSON: {err}"
            )]
        })?;

    let fixture = WinterfellPocRealProofFixture::from_complete_candidate(&candidate)?;
    fixture.validate()?;

    let output_json = serde_json::to_string_pretty(&fixture).map_err(|err| {
        vec![format!(
            "could not serialize Winterfell PoC real proof fixture JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "winterfell_poc_real_proof_fixture_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
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
        "generate_winterfell_poc_real_proof_fixture requires --features winterfell-poc"
            .to_string(),
        "usage: cargo run --features winterfell-poc --bin generate_winterfell_poc_real_proof_fixture -- <complete_winterfell_witness_candidate.json> <winterfell_poc_real_proof_fixture.json>"
            .to_string(),
    ])
}

#[cfg(feature = "winterfell-poc")]
fn usage() -> Vec<String> {
    vec![
        "usage: generate_winterfell_poc_real_proof_fixture <complete_winterfell_witness_candidate.json> <winterfell_poc_real_proof_fixture.json>"
            .to_string(),
    ]
}
