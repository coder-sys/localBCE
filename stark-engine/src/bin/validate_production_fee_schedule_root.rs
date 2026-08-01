use std::{env, fs, process};

use stark_engine::production_fee_schedule_root::ProductionFeeScheduleRootArtifactV1;

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
    let artifact: ProductionFeeScheduleRootArtifactV1 = serde_json::from_str(&input_json)
        .map_err(|error| vec![format!("invalid fee-schedule root JSON: {error}")])?;
    artifact.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "production_fee_schedule_root_validation",
            "status": "ok",
            "path": path,
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
        "usage: validate_production_fee_schedule_root <production_fee_schedule_root.json>"
            .to_string(),
    ]
}
