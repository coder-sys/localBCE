use std::{env, fs, process};

use stark_engine::StarkProofArtifactV1Candidate;

fn main() {
    if let Err(errors) = run() {
        for error in errors {
            eprintln!("{error}");
        }
        process::exit(1);
    }
}

fn run() -> Result<(), Vec<String>> {
    let path = env::args().nth(1).ok_or_else(usage)?;

    let input_json =
        fs::read_to_string(&path).map_err(|err| vec![format!("could not read {path}: {err}")])?;
    let artifact: StarkProofArtifactV1Candidate =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid STARK proof artifact V1 candidate JSON: {err}"
            )]
        })?;

    artifact.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_proof_artifact_v1_candidate_validation",
            "status": "ok",
            "path": path,
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
        "usage: validate_stark_proof_artifact_v1_candidate <stark_proof_artifact_v1_candidate.json>"
            .to_string(),
    ]
}
