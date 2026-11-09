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

    let expectations = boundary_spec.to_fixture_expectation_set()?;
    expectations.validate()?;

    let output_json = serde_json::to_string_pretty(&expectations).map_err(|err| {
        vec![format!(
            "could not serialize proof artifact fixture expectations JSON: {err}"
        )]
    })?;

    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "proof_artifact_fixture_expectations_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": expectations.schema_version,
            "source_schema_version": expectations.source_schema_version,
            "expectation_set_status": expectations.expectation_set_status,
            "expected_fixtures": expectations.expected_fixtures.len(),
            "groth16_flow_unchanged": expectations.groth16_flow_unchanged,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: generate_proof_artifact_fixture_expectations <stark_proof_artifact_v1_boundary_spec.json> <proof_artifact_fixture_expectations.json>"
            .to_string(),
    ]
}
