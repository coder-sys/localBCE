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

    use stark_engine::winterfell_poc_adapter::StarkSettlementBoundaryArtifact;

    let path = env::args().nth(1).ok_or_else(usage)?;

    let input_json =
        fs::read_to_string(&path).map_err(|err| vec![format!("could not read {path}: {err}")])?;
    let artifact: StarkSettlementBoundaryArtifact =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid STARK settlement boundary artifact JSON: {err}"
            )]
        })?;

    artifact.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_settlement_boundary_artifact_validation",
            "status": "ok",
            "path": path,
            "schema_version": artifact.schema_version,
            "source_schema_version": artifact.source_schema_version,
            "artifact_status": artifact.artifact_status,
            "claim_id": artifact.claim_id,
            "claim_hash": artifact.claim_hash,
            "decision": artifact.decision,
            "failure_code": artifact.failure_code,
            "proof_verified": artifact.proof_verified,
            "proof_size_bytes": artifact.proof_size_bytes,
            "runtime_wired": artifact.runtime_wired,
            "on_chain_submission": artifact.on_chain_submission,
            "groth16_flow_unchanged": artifact.groth16_flow_unchanged,
            "settlement_contract_ready": artifact.settlement_contract_ready,
        })
    );

    Ok(())
}

#[cfg(not(feature = "winterfell-poc"))]
fn run() -> Result<(), Vec<String>> {
    let _ = env::args();
    Err(vec![
        "validate_stark_settlement_boundary_artifact requires --features winterfell-poc"
            .to_string(),
        "usage: cargo run --features winterfell-poc --bin validate_stark_settlement_boundary_artifact -- <stark_settlement_boundary_artifact.json>"
            .to_string(),
    ])
}

#[cfg(feature = "winterfell-poc")]
fn usage() -> Vec<String> {
    vec![
        "usage: validate_stark_settlement_boundary_artifact <stark_settlement_boundary_artifact.json>"
            .to_string(),
    ]
}
