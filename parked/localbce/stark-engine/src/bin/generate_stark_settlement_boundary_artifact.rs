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

    use stark_engine::winterfell_poc_adapter::WinterfellPocProofPreview;

    let mut args = env::args();
    let _binary = args.next();
    let input_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let input_json = fs::read_to_string(&input_path)
        .map_err(|err| vec![format!("could not read {input_path}: {err}")])?;
    let proof_preview: WinterfellPocProofPreview = serde_json::from_str(&input_json)
        .map_err(|err| vec![format!("invalid Winterfell proof preview JSON: {err}")])?;

    let artifact = proof_preview.to_settlement_boundary_artifact()?;
    artifact.validate()?;

    let output_json = serde_json::to_string_pretty(&artifact).map_err(|err| {
        vec![format!(
            "could not serialize STARK settlement boundary artifact JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_settlement_boundary_artifact_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
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
        "generate_stark_settlement_boundary_artifact requires --features winterfell-poc"
            .to_string(),
        "usage: cargo run --features winterfell-poc --bin generate_stark_settlement_boundary_artifact -- <winterfell_proof_preview.json> <stark_settlement_boundary_artifact.json>"
            .to_string(),
    ])
}

#[cfg(feature = "winterfell-poc")]
fn usage() -> Vec<String> {
    vec![
        "usage: generate_stark_settlement_boundary_artifact <winterfell_proof_preview.json> <stark_settlement_boundary_artifact.json>"
            .to_string(),
    ]
}
