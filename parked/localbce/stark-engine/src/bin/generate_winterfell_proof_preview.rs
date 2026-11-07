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
        WinterfellCompleteWitnessCandidate, winterfell_poc_adapter::WinterfellPocProofPreview,
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

    let proof_preview = WinterfellPocProofPreview::from_complete_candidate(&candidate)?;
    proof_preview.validate()?;

    let output_json = serde_json::to_string_pretty(&proof_preview).map_err(|err| {
        vec![format!(
            "could not serialize Winterfell proof preview JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "winterfell_poc_proof_preview_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
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
        "generate_winterfell_proof_preview requires --features winterfell-poc".to_string(),
        "usage: cargo run --features winterfell-poc --bin generate_winterfell_proof_preview -- <complete_winterfell_witness_candidate.json> <winterfell_proof_preview.json>".to_string(),
    ])
}

#[cfg(feature = "winterfell-poc")]
fn usage() -> Vec<String> {
    vec![
        "usage: generate_winterfell_proof_preview <complete_winterfell_witness_candidate.json> <winterfell_proof_preview.json>"
            .to_string(),
    ]
}
