use std::{env, fs, process};

use stark_engine::{
    production_nullifier_root_transition::ProductionNullifierRootTransitionArtifactV1,
    production_nullifier_state::{
        acquire_production_nullifier_state_lock, load_production_nullifier_state,
        write_production_nullifier_state_atomic,
    },
};

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
    let state_path = args.next().ok_or_else(usage)?;
    let transition_path = args.next().ok_or_else(usage)?;
    let receipt_path = args.next().ok_or_else(usage)?;
    if args.next().is_some() {
        return Err(usage());
    }
    let _lock = acquire_production_nullifier_state_lock(&state_path)?;
    let mut state = load_production_nullifier_state(&state_path)?;
    let transition_json = fs::read_to_string(&transition_path)
        .map_err(|error| vec![format!("could not read {transition_path}: {error}")])?;
    let transition: ProductionNullifierRootTransitionArtifactV1 =
        serde_json::from_str(&transition_json)
            .map_err(|error| vec![format!("invalid transition JSON: {error}")])?;
    let receipt = state.apply_transition(&transition)?;
    write_production_nullifier_state_atomic(&state_path, &state)?;
    let receipt_json = serde_json::to_string_pretty(&receipt)
        .map_err(|error| vec![format!("could not serialize apply receipt: {error}")])?;
    fs::write(&receipt_path, format!("{receipt_json}\n"))
        .map_err(|error| vec![format!("could not write {receipt_path}: {error}")])?;
    println!(
        "{}",
        serde_json::json!({
            "event": "production_nullifier_transition_application",
            "status": "ok",
            "state": state_path,
            "transition": transition_path,
            "receipt": receipt_path,
            "claim_id": receipt.claim_id,
            "leaf_index": receipt.leaf_index,
            "generation_before": receipt.generation_before,
            "generation_after": receipt.generation_after,
            "root_before": receipt.root_before_bytes32,
            "root_after": receipt.root_after_bytes32,
            "transition_applied": receipt.transition_applied,
            "groth16_flow_unchanged": receipt.groth16_flow_unchanged,
        })
    );
    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: apply_production_nullifier_transition <nullifier_state.json> <transition.json> <receipt.json>"
            .to_string(),
    ]
}
