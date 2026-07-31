use std::{env, fs, process};

use stark_engine::production_proof_artifact::ProductionStarkProofArtifactV3;

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
    let artifact: ProductionStarkProofArtifactV3 = serde_json::from_str(&input_json)
        .map_err(|error| vec![format!("invalid production proof artifact JSON: {error}")])?;
    artifact.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "production_stark_proof_artifact_validation",
            "status": "ok",
            "path": path,
            "schema_version": artifact.schema_version,
            "claim_id": artifact.claim_id,
            "claim_hash": artifact.claim_hash,
            "decision": artifact.decision,
            "failure_code": artifact.failure_code,
            "public_input_count": artifact.public_inputs.count,
            "public_input_root": artifact.public_input_root_bytes32,
            "claim_source_root": artifact.claim_source_root_bytes32,
            "proof_size_bytes": artifact.proof.size_bytes,
            "proof_sha256": artifact.proof.sha256,
            "local_verification_status": artifact.local_verification_status,
            "locally_verified": artifact.locally_verified,
            "runtime_wired": artifact.runtime_wired,
            "on_chain_verifier_wired": artifact.on_chain_verifier_wired,
            "groth16_flow_unchanged": artifact.groth16_flow_unchanged,
        })
    );
    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: validate_production_stark_proof_artifact <production_stark_proof_artifact.json>"
            .to_string(),
    ]
}
