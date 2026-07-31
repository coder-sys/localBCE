use std::{env, fs, process};

use stark_engine::production_verifier_handoff::ProductionStarkVerifierHandoffV2;

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
    let handoff: ProductionStarkVerifierHandoffV2 = serde_json::from_str(&input_json)
        .map_err(|error| vec![format!("invalid production verifier handoff JSON: {error}")])?;
    handoff.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "production_stark_verifier_handoff_validation",
            "status": "ok",
            "path": path,
            "schema_version": handoff.schema_version,
            "interface_name": handoff.interface_name,
            "claim_id": handoff.source_artifact.claim_id,
            "claim_hash": handoff.source_artifact.claim_hash,
            "decision": handoff.source_artifact.decision,
            "failure_code": handoff.source_artifact.failure_code,
            "air_public_input_count": handoff.air_public_input_count,
            "public_input_root": handoff.public_input_root,
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
        "usage: validate_production_stark_verifier_handoff <production_stark_verifier_handoff.json>"
            .to_string(),
    ]
}
