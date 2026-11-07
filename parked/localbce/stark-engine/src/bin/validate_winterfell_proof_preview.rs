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

    let path = env::args().nth(1).ok_or_else(usage)?;

    let input_json =
        fs::read_to_string(&path).map_err(|err| vec![format!("could not read {path}: {err}")])?;
    let proof_preview: WinterfellPocProofPreview = serde_json::from_str(&input_json)
        .map_err(|err| vec![format!("invalid Winterfell proof preview JSON: {err}")])?;

    proof_preview.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "winterfell_poc_proof_preview_validation",
            "status": "ok",
            "path": path,
            "schema_version": proof_preview.schema_version,
            "source_schema_version": proof_preview.source_schema_version,
            "proof_status": proof_preview.proof_status,
            "claim_id": proof_preview.claim_id,
            "claim_hash": proof_preview.claim_hash,
            "decision": proof_preview.decision,
            "failure_code": proof_preview.failure_code,
            "proof_size_bytes": proof_preview.proof_size_bytes,
            "prove_ms": proof_preview.prove_ms,
            "verify_ms": proof_preview.verify_ms,
            "verified": proof_preview.verified,
            "winterfell_dependency_imported": proof_preview.winterfell_dependency_imported,
            "proof_generation": proof_preview.proof_generation_enabled,
            "runtime_wired": proof_preview.runtime_wired,
            "on_chain_submission": proof_preview.on_chain_submission,
        })
    );

    Ok(())
}

#[cfg(not(feature = "winterfell-poc"))]
fn run() -> Result<(), Vec<String>> {
    let _ = env::args();
    Err(vec![
        "validate_winterfell_proof_preview requires --features winterfell-poc".to_string(),
        "usage: cargo run --features winterfell-poc --bin validate_winterfell_proof_preview -- <winterfell_proof_preview.json>".to_string(),
    ])
}

#[cfg(feature = "winterfell-poc")]
fn usage() -> Vec<String> {
    vec!["usage: validate_winterfell_proof_preview <winterfell_proof_preview.json>".to_string()]
}
