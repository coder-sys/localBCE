use std::{env, fs, process};

use stark_engine::production_nullifier_root_transition::ProductionNullifierRootTransitionArtifactV1;

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
    let path = args.next().ok_or_else(usage)?;
    if args.next().is_some() {
        return Err(usage());
    }

    let input_json = fs::read_to_string(&path)
        .map_err(|error| vec![format!("could not read {path}: {error}")])?;
    let artifact: ProductionNullifierRootTransitionArtifactV1 =
        serde_json::from_str(&input_json)
            .map_err(|error| vec![format!("invalid nullifier transition JSON: {error}")])?;
    artifact.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "production_nullifier_root_transition_validation",
            "status": "ok",
            "path": path,
            "schema_version": artifact.schema_version,
            "claim_id": artifact.claim_id,
            "claim_hash": artifact.claim_hash,
            "decision": artifact.decision,
            "nullifier": artifact.nullifier_bytes32,
            "nullifier_root_before": artifact.nullifier_root_before_bytes32,
            "nullifier_root_after": artifact.nullifier_root_after_bytes32,
            "tree_depth": artifact.tree_depth,
            "leaf_index": artifact.leaf_index,
            "transition_applied": artifact.transition_applied,
            "state_generation_before": artifact.state_generation_before,
            "state_generation_after": artifact.state_generation_after,
            "state_source_status": artifact.state_source_status,
            "air_binding_status": artifact.air_binding_status,
            "runtime_wired": artifact.runtime_wired,
            "groth16_flow_unchanged": artifact.groth16_flow_unchanged,
        })
    );
    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: validate_production_nullifier_root_transition <production_nullifier_root_transition.json>"
            .to_string(),
    ]
}
