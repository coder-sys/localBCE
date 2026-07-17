use std::{env, fs, process};

use stark_engine::StarkProofArtifactV1BoundarySpec;

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
    let boundary_spec: StarkProofArtifactV1BoundarySpec = serde_json::from_str(&input_json)
        .map_err(|err| {
            vec![format!(
                "invalid STARK proof artifact V1 boundary spec JSON: {err}"
            )]
        })?;

    boundary_spec.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_proof_artifact_v1_boundary_spec_validation",
            "status": "ok",
            "path": path,
            "schema_version": boundary_spec.schema_version,
            "source_schema_version": boundary_spec.source_schema_version,
            "target_artifact_schema_version": boundary_spec.target_artifact_schema_version,
            "boundary_status": boundary_spec.boundary_status,
            "required_public_inputs": boundary_spec.required_public_inputs.len(),
            "required_proof_fields": boundary_spec.required_proof_fields.len(),
            "required_local_verification_fields": boundary_spec.required_local_verification_fields.len(),
            "solidity_abi_candidate": boundary_spec.solidity_abi_candidate,
            "runtime_wiring_status": boundary_spec.runtime_wiring_status,
            "groth16_flow_unchanged": boundary_spec.groth16_flow_unchanged,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: validate_stark_proof_artifact_v1_boundary_spec <stark_proof_artifact_v1_boundary_spec.json>"
            .to_string(),
    ]
}
