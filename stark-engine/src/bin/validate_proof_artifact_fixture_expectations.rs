use std::{env, fs, process};

use stark_engine::ProofArtifactFixtureExpectationSet;

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
    let expectations: ProofArtifactFixtureExpectationSet = serde_json::from_str(&input_json)
        .map_err(|err| {
            vec![format!(
                "invalid proof artifact fixture expectations JSON: {err}"
            )]
        })?;

    expectations.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "proof_artifact_fixture_expectations_validation",
            "status": "ok",
            "path": path,
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
        "usage: validate_proof_artifact_fixture_expectations <proof_artifact_fixture_expectations.json>"
            .to_string(),
    ]
}
