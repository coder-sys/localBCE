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
    let mut args = env::args();
    let _binary = args.next();
    let input_path = args.next().ok_or_else(|| {
        vec![
            "usage: generate_proof_intent <stark_bridge_input.json> <proof_intent.json>"
                .to_string(),
        ]
    })?;
    let output_path = args.next().ok_or_else(|| {
        vec![
            "usage: generate_proof_intent <stark_bridge_input.json> <proof_intent.json>"
                .to_string(),
        ]
    })?;

    if args.next().is_some() {
        return Err(vec![
            "usage: generate_proof_intent <stark_bridge_input.json> <proof_intent.json>"
                .to_string(),
        ]);
    }

    let input_json = fs::read_to_string(&input_path)
        .map_err(|err| vec![format!("could not read {input_path}: {err}")])?;
    let input: StarkBridgeInput = serde_json::from_str(&input_json)
        .map_err(|err| vec![format!("invalid bridge input JSON: {err}")])?;
    let intent = input.to_proof_intent()?;
    let output_json = serde_json::to_string_pretty(&intent)
        .map_err(|err| vec![format!("could not serialize proof intent JSON: {err}")])?;

    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_proof_intent_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": intent.schema_version,
            "source_schema_version": intent.source_schema_version,
            "claim_hash": intent.claim_hash,
            "decision": intent.decision,
            "prover_selected": intent.proof_readiness.prover_selected,
            "proof_generated": intent.proof_readiness.proof_generated,
        })
    );

    Ok(())
}
