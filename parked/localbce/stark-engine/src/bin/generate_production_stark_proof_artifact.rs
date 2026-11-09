use std::{env, fs, process};

use stark_engine::{
    StarkBridgeInput,
    production_nullifier_root_transition::ProductionNullifierRootTransitionArtifactV1,
    production_proof_artifact::ProductionStarkProofArtifactV4,
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
    let transition_path = args.next();
    if args.next().is_some() {
        return Err(usage());
    }

    let input_json = fs::read_to_string(&input_path)
        .map_err(|error| vec![format!("could not read {input_path}: {error}")])?;
    let bridge: StarkBridgeInput = serde_json::from_str(&input_json)
        .map_err(|error| vec![format!("invalid StarkBridgeInput JSON: {error}")])?;
    let artifact = if let Some(transition_path) = transition_path.as_deref() {
        let transition_json = fs::read_to_string(transition_path)
            .map_err(|error| vec![format!("could not read {transition_path}: {error}")])?;
        let transition: ProductionNullifierRootTransitionArtifactV1 =
            serde_json::from_str(&transition_json)
                .map_err(|error| vec![format!("invalid nullifier transition JSON: {error}")])?;
        ProductionStarkProofArtifactV4::from_bridge_input_with_nullifier_transition(
            &bridge,
            &transition,
        )?
    } else {
        ProductionStarkProofArtifactV4::from_bridge_input(&bridge)?
    };
    let output_json = serde_json::to_string_pretty(&artifact)
        .map_err(|error| vec![format!("could not serialize proof artifact: {error}")])?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|error| vec![format!("could not write {output_path}: {error}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "production_stark_proof_artifact_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": artifact.schema_version,
            "claim_id": artifact.claim_id,
            "claim_hash": artifact.claim_hash,
            "decision": artifact.decision,
            "failure_code": artifact.failure_code,
            "public_input_count": artifact.public_inputs.count,
            "public_input_root": artifact.public_input_root_bytes32,
            "claim_source_root": artifact.claim_source_root_bytes32,
            "oracle_facts_root": artifact.oracle_facts_root_bytes32,
            "fee_schedule_root": artifact.fee_schedule_root_bytes32,
            "nullifier_root_before": artifact.nullifier_root_before_bytes32,
            "nullifier_root_after": artifact.nullifier_root_after_bytes32,
            "batch_root": artifact.batch_root_bytes32,
            "nullifier_state_source_status": artifact.nullifier_state_source_status,
            "nullifier_state_generation_before": artifact.nullifier_state_generation_before,
            "nullifier_state_generation_after": artifact.nullifier_state_generation_after,
            "proof_size_bytes": artifact.proof.size_bytes,
            "proof_sha256": artifact.proof.sha256,
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
        "usage: generate_production_stark_proof_artifact <stark_bridge_input.json> <production_stark_proof_artifact.json> [production_nullifier_transition.json]"
            .to_string(),
    ]
}
