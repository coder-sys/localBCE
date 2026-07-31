use std::{env, fs, process};

use stark_engine::{StarkBridgeInput, source_roots::ProductionClaimSourceRootArtifactV1};

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
    let input_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;
    if args.next().is_some() {
        return Err(usage());
    }

    let input_json = fs::read_to_string(&input_path)
        .map_err(|error| vec![format!("could not read {input_path}: {error}")])?;
    let bridge: StarkBridgeInput = serde_json::from_str(&input_json)
        .map_err(|error| vec![format!("invalid StarkBridgeInput JSON: {error}")])?;
    let artifact = ProductionClaimSourceRootArtifactV1::from_bridge_input(&bridge)?;
    let output_json = serde_json::to_string_pretty(&artifact)
        .map_err(|error| vec![format!("could not serialize claim-source root: {error}")])?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|error| vec![format!("could not write {output_path}: {error}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "production_claim_source_root_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": artifact.schema_version,
            "claim_id": artifact.claim_id,
            "claim_hash": artifact.claim_hash,
            "claim_source_root": artifact.claim_source_root_bytes32,
            "tree_depth": artifact.tree_depth,
            "leaf_index": artifact.leaf_index,
            "service_line_count": artifact.service_line_count,
            "diagnosis_count": artifact.diagnosis_count,
            "governance_status": artifact.governance_status,
            "air_binding_status": artifact.air_binding_status,
            "runtime_wired": artifact.runtime_wired,
            "groth16_flow_unchanged": artifact.groth16_flow_unchanged,
        })
    );
    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: generate_production_claim_source_root <stark_bridge_input.json> <production_claim_source_root.json>"
            .to_string(),
    ]
}
