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
    let mut args = env::args();
    let _binary = args.next();
    let input_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let input_json = fs::read_to_string(&input_path)
        .map_err(|err| vec![format!("could not read {input_path}: {err}")])?;
    let candidate: StarkProofArtifactV1Candidate =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid STARK proof artifact V1 candidate JSON: {err}"
            )]
        })?;

    let boundary_spec = candidate.to_v1_boundary_spec()?;
    boundary_spec.validate()?;

    let output_json = serde_json::to_string_pretty(&boundary_spec).map_err(|err| {
        vec![format!(
            "could not serialize STARK proof artifact V1 boundary spec JSON: {err}"
        )]
    })?;

    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_proof_artifact_v1_boundary_spec_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
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
        "usage: generate_stark_proof_artifact_v1_boundary_spec <stark_proof_artifact_v1_candidate.json> <stark_proof_artifact_v1_boundary_spec.json>"
            .to_string(),
    ]
}
