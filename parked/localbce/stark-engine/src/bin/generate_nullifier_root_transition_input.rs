use std::{env, fs, process};

use stark_engine::{NullifierRootTransitionInput, StarkBridgeInput};

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
            "usage: generate_nullifier_root_transition_input <stark_bridge_input.json> <nullifier_root_transition_input.json>"
                .to_string(),
        ]
    })?;
    let output_path = args.next().ok_or_else(|| {
        vec![
            "usage: generate_nullifier_root_transition_input <stark_bridge_input.json> <nullifier_root_transition_input.json>"
                .to_string(),
        ]
    })?;

    if args.next().is_some() {
        return Err(vec![
            "usage: generate_nullifier_root_transition_input <stark_bridge_input.json> <nullifier_root_transition_input.json>"
                .to_string(),
        ]);
    }

    let input_json = fs::read_to_string(&input_path)
        .map_err(|err| vec![format!("could not read {input_path}: {err}")])?;
    let input: StarkBridgeInput = serde_json::from_str(&input_json)
        .map_err(|err| vec![format!("invalid bridge input JSON: {err}")])?;
    let transition = NullifierRootTransitionInput::from_bridge_input(&input)?;
    transition.validate()?;
    let output_json = serde_json::to_string_pretty(&transition).map_err(|err| {
        vec![format!(
            "could not serialize nullifier root transition input JSON: {err}"
        )]
    })?;

    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_nullifier_root_transition_input_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": transition.schema_version,
            "source_schema_version": transition.source_schema_version,
            "input_status": transition.input_status,
            "claim_id": transition.claim_id,
            "claim_hash": transition.claim_hash,
            "nullifier_candidate_present": transition.nullifier_candidate.is_some(),
            "nullifier_root_before_present": transition.nullifier_root_before.is_some(),
            "nullifier_root_after_present": transition.nullifier_root_after.is_some(),
            "transition_status": transition.transition_status,
            "root_generation_status": transition.root_generation_status,
            "root_generation": false,
            "proof_generation": false,
        })
    );

    Ok(())
}
