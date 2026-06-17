use std::{env, fs, process};

use stark_engine::StarkBridgeInput;

fn main() {
    if let Err(errors) = run() {
        for error in errors {
            eprintln!("{error}");
        }
        process::exit(1);
    }
}

fn run() -> Result<(), Vec<String>> {
    let path = env::args().nth(1).ok_or_else(|| {
        vec!["usage: validate_bridge_input <stark_bridge_input.json>".to_string()]
    })?;

    let input_json =
        fs::read_to_string(&path).map_err(|err| vec![format!("could not read {path}: {err}")])?;
    let input: StarkBridgeInput = serde_json::from_str(&input_json)
        .map_err(|err| vec![format!("invalid bridge input JSON: {err}")])?;

    input.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_bridge_input_validation",
            "status": "ok",
            "path": path,
            "schema_version": input.schema_version,
            "producer": input.producer,
            "claim_hash": input.claim.claim_hash,
            "decision": input.adjudication.decision,
            "stark_proof_generated": input.proof_status.stark_proof_generated,
        })
    );

    Ok(())
}
