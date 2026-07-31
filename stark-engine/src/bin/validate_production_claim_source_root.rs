use std::{env, fs, process};

use stark_engine::source_roots::ProductionClaimSourceRootArtifactV1;

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
    let artifact: ProductionClaimSourceRootArtifactV1 = serde_json::from_str(&input_json)
        .map_err(|error| vec![format!("invalid claim-source root JSON: {error}")])?;
    artifact.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "production_claim_source_root_validation",
            "status": "ok",
            "path": path,
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
        "usage: validate_production_claim_source_root <production_claim_source_root.json>"
            .to_string(),
    ]
}
