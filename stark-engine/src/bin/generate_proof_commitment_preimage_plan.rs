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
    let mut args = env::args();
    let _binary = args.next();
    let input_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let input_json = fs::read_to_string(&input_path)
        .map_err(|err| vec![format!("could not read {input_path}: {err}")])?;
    let boundary_spec: StarkProofArtifactV1BoundarySpec = serde_json::from_str(&input_json)
        .map_err(|err| {
            vec![format!(
                "invalid STARK proof artifact V1 boundary spec JSON: {err}"
            )]
        })?;

    let plan = boundary_spec.to_proof_commitment_preimage_plan()?;
    plan.validate()?;

    let output_json = serde_json::to_string_pretty(&plan).map_err(|err| {
        vec![format!(
            "could not serialize proof commitment preimage plan JSON: {err}"
        )]
    })?;

    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "proof_commitment_preimage_plan_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": plan.schema_version,
            "source_schema_version": plan.source_schema_version,
            "plan_status": plan.plan_status,
            "hash_strategy": plan.hash_strategy,
            "canonical_encoding": plan.canonical_encoding,
            "ordered_components": plan.ordered_components.len(),
            "expected_component_count": plan.expected_component_count,
            "commitment_generation_status": plan.commitment_generation_status,
            "proof_commitment_present": plan.proof_commitment.is_some(),
            "groth16_flow_unchanged": plan.groth16_flow_unchanged,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: generate_proof_commitment_preimage_plan <stark_proof_artifact_v1_boundary_spec.json> <proof_commitment_preimage_plan.json>"
            .to_string(),
    ]
}
