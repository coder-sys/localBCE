use std::{env, fs, process};

use stark_engine::StarkBridgeInput;

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
        .map_err(|err| vec![format!("could not read {input_path}: {err}")])?;
    let input: StarkBridgeInput = serde_json::from_str(&input_json)
        .map_err(|err| vec![format!("invalid bridge input JSON: {err}")])?;

    let artifact = input.to_proof_artifact_v1_candidate()?;
    artifact.validate()?;

    let output_json = serde_json::to_string_pretty(&artifact).map_err(|err| {
        vec![format!(
            "could not serialize STARK proof artifact V1 candidate JSON: {err}"
        )]
    })?;

    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_proof_artifact_v1_candidate_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": artifact.schema_version,
            "source_schema_version": artifact.source_schema_version,
            "artifact_status": artifact.artifact_status,
            "claim_hash": artifact.claim_hash,
            "decision": artifact.decision,
            "failure_code": artifact.failure_code,
            "root_status": artifact.public_inputs.root_status,
            "proof_bytes_status": artifact.proof.proof_bytes_status,
            "proof_commitment_status": artifact.proof.proof_commitment_status,
            "verification_status": artifact.local_verification.verification_status,
            "solidity_abi_candidate": artifact.solidity_abi_candidate,
            "runtime_wired": artifact.runtime_wired,
            "on_chain_submission": artifact.on_chain_submission,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: generate_stark_proof_artifact_v1_candidate <stark_bridge_input.json> <stark_proof_artifact_v1_candidate.json>"
            .to_string(),
    ]
}
