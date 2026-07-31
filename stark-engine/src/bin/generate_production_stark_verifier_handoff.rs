use std::{env, fs, process};

use stark_engine::{
    production_proof_artifact::ProductionStarkProofArtifactV4,
    production_verifier_handoff::ProductionStarkVerifierHandoffV4,
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
    let artifact: ProductionStarkProofArtifactV4 = serde_json::from_str(&input_json)
        .map_err(|error| vec![format!("invalid production proof artifact JSON: {error}")])?;
    let handoff = ProductionStarkVerifierHandoffV4::from_proof_artifact(&artifact)?;
    let output_json = serde_json::to_string_pretty(&handoff)
        .map_err(|error| vec![format!("could not serialize verifier handoff: {error}")])?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|error| vec![format!("could not write {output_path}: {error}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "production_stark_verifier_handoff_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": handoff.schema_version,
            "interface_name": handoff.interface_name,
            "claim_id": handoff.source_artifact.claim_id,
            "claim_hash": handoff.source_artifact.claim_hash,
            "decision": handoff.source_artifact.decision,
            "failure_code": handoff.source_artifact.failure_code,
            "air_public_input_count": handoff.air_public_input_count,
            "public_input_root": handoff.public_input_root,
            "claim_source_root": handoff.claim_source_root,
            "oracle_facts_root": handoff.oracle_facts_root,
            "proof_size_bytes": handoff.proof_size_bytes,
            "proof_bytes_sha256": handoff.proof_bytes_sha256,
            "binding_digest_sha256": handoff.binding_digest_sha256,
            "unresolved_abi_fields": handoff.call_readiness.unresolved_abi_fields,
            "abi_call_ready": handoff.call_readiness.abi_call_ready,
            "runtime_wired": handoff.runtime_wired,
            "on_chain_verifier_wired": handoff.on_chain_verifier_wired,
            "groth16_flow_unchanged": handoff.groth16_flow_unchanged,
        })
    );
    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: generate_production_stark_verifier_handoff <production_stark_proof_artifact.json> <production_stark_verifier_handoff.json>"
            .to_string(),
    ]
}
