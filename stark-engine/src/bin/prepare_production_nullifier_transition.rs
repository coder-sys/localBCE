use std::{env, fs, process};

use stark_engine::{
    StarkBridgeInput,
    production_nullifier_state::{
        acquire_production_nullifier_state_lock, load_production_nullifier_state,
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
    let bridge_path = args.next().ok_or_else(usage)?;
    let state_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;
    if args.next().is_some() {
        return Err(usage());
    }
    let _lock = acquire_production_nullifier_state_lock(&state_path)?;
    let state = load_production_nullifier_state(&state_path)?;
    let bridge_json = fs::read_to_string(&bridge_path)
        .map_err(|error| vec![format!("could not read {bridge_path}: {error}")])?;
    let bridge: StarkBridgeInput = serde_json::from_str(&bridge_json)
        .map_err(|error| vec![format!("invalid StarkBridgeInput JSON: {error}")])?;
    let transition = state.prepare_transition(&bridge)?;
    let output_json = serde_json::to_string_pretty(&transition)
        .map_err(|error| vec![format!("could not serialize transition: {error}")])?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|error| vec![format!("could not write {output_path}: {error}")])?;
    println!(
        "{}",
        serde_json::json!({
            "event": "production_nullifier_transition_preparation",
            "status": "ok",
            "bridge_input": bridge_path,
            "state": state_path,
            "output": output_path,
            "claim_id": transition.claim_id,
            "claim_hash": transition.claim_hash,
            "leaf_index": transition.leaf_index,
            "generation_before": transition.state_generation_before,
            "generation_after": transition.state_generation_after,
            "root_before": transition.nullifier_root_before_bytes32,
            "root_after": transition.nullifier_root_after_bytes32,
            "transition_applied": transition.transition_applied,
            "groth16_flow_unchanged": transition.groth16_flow_unchanged,
        })
    );
    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: prepare_production_nullifier_transition <stark_bridge_input.json> <nullifier_state.json> <transition.json>"
            .to_string(),
    ]
}
