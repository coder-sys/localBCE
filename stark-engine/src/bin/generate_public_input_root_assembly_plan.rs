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

    let plan = boundary_spec.to_public_input_root_assembly_plan()?;
    plan.validate()?;

    let output_json = serde_json::to_string_pretty(&plan).map_err(|err| {
        vec![format!(
            "could not serialize public input root assembly plan JSON: {err}"
        )]
    })?;

    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "public_input_root_assembly_plan_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": plan.schema_version,
            "source_schema_version": plan.source_schema_version,
            "plan_status": plan.plan_status,
            "hash_strategy": plan.hash_strategy,
            "canonical_encoding": plan.canonical_encoding,
            "ordered_fields": plan.ordered_fields.len(),
            "expected_field_count": plan.expected_field_count,
            "root_generation_status": plan.root_generation_status,
            "public_input_root_present": plan.public_input_root.is_some(),
            "groth16_flow_unchanged": plan.groth16_flow_unchanged,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: generate_public_input_root_assembly_plan <stark_proof_artifact_v1_boundary_spec.json> <public_input_root_assembly_plan.json>"
            .to_string(),
    ]
}
