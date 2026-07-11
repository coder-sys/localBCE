use std::{env, fs, process};

use stark_engine::NullifierRootTransitionInput;

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
        vec![
            "usage: validate_nullifier_root_transition_input <nullifier_root_transition_input.json>"
                .to_string(),
        ]
    })?;

    let input_json =
        fs::read_to_string(&path).map_err(|err| vec![format!("could not read {path}: {err}")])?;
    let input: NullifierRootTransitionInput = serde_json::from_str(&input_json).map_err(|err| {
        vec![format!(
            "invalid nullifier root transition input JSON: {err}"
        )]
    })?;

    input.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_nullifier_root_transition_input_validation",
            "status": "ok",
            "path": path,
            "schema_version": input.schema_version,
            "source_schema_version": input.source_schema_version,
            "input_status": input.input_status,
            "claim_id": input.claim_id,
            "claim_hash": input.claim_hash,
            "nullifier_candidate_present": input.nullifier_candidate.is_some(),
            "nullifier_root_before_present": input.nullifier_root_before.is_some(),
            "nullifier_root_after_present": input.nullifier_root_after.is_some(),
            "transition_status": input.transition_status,
            "root_generation_status": input.root_generation_status,
            "root_generation": false,
            "proof_generation": false,
        })
    );

    Ok(())
}
