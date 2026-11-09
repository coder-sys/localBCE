use std::{env, fs, process};

use stark_engine::{
    StarkBridgeInput, production_fee_schedule_root::ProductionFeeScheduleRootArtifactV1,
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
    let input_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;
    if args.next().is_some() {
        return Err(usage());
    }

    let input_json = fs::read_to_string(&input_path)
        .map_err(|error| vec![format!("could not read {input_path}: {error}")])?;
    let bridge: StarkBridgeInput = serde_json::from_str(&input_json)
        .map_err(|error| vec![format!("invalid StarkBridgeInput JSON: {error}")])?;
    let artifact = ProductionFeeScheduleRootArtifactV1::from_bridge_input(&bridge)?;
    let output_json = serde_json::to_string_pretty(&artifact)
        .map_err(|error| vec![format!("could not serialize fee-schedule root: {error}")])?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|error| vec![format!("could not write {output_path}: {error}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "production_fee_schedule_root_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": artifact.schema_version,
            "claim_id": artifact.claim_id,
            "claim_hash": artifact.claim_hash,
            "fee_schedule_root": artifact.fee_schedule_root_bytes32,
            "tree_depth": artifact.tree_depth,
            "leaf_index": artifact.leaf_index,
            "entry_count": artifact.entry_count,
            "matched_service_line_count": artifact.matched_service_line_count,
            "total_allowed_cents": artifact.total_allowed_cents,
            "total_charged_cents": artifact.total_charged_cents,
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
        "usage: generate_production_fee_schedule_root <stark_bridge_input.json> <production_fee_schedule_root.json>"
            .to_string(),
    ]
}
