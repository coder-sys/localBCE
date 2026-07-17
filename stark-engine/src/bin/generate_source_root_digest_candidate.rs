use std::{env, fs, process};

use stark_engine::{
    ClaimSourceRootInput, FeeScheduleRootInput, NullifierRootTransitionInput, OracleFactsRootInput,
    SourceRootDigestCandidate,
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
        .map_err(|err| vec![format!("could not read {input_path}: {err}")])?;
    let candidate = source_root_digest_candidate_from_json(&input_json)?;
    candidate.validate()?;

    let output_json = serde_json::to_string_pretty(&candidate).map_err(|err| {
        vec![format!(
            "could not serialize source root digest candidate JSON: {err}"
        )]
    })?;

    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "source_root_digest_candidate_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": candidate.schema_version,
            "source_schema_version": candidate.source_schema_version,
            "source_root_kind": candidate.source_root_kind,
            "candidate_status": candidate.candidate_status,
            "hash_algorithm": candidate.hash_algorithm,
            "source_root_candidate": candidate.source_root_candidate,
            "root_generation_status": candidate.root_generation_status,
            "production_hash_selected": candidate.production_hash_selected,
            "runtime_wiring_allowed": candidate.runtime_wiring_allowed,
            "groth16_flow_unchanged": candidate.groth16_flow_unchanged,
        })
    );

    Ok(())
}

fn source_root_digest_candidate_from_json(
    input_json: &str,
) -> Result<SourceRootDigestCandidate, Vec<String>> {
    let value: serde_json::Value = serde_json::from_str(input_json)
        .map_err(|err| vec![format!("invalid source root input JSON: {err}")])?;
    let schema_version = value
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| vec!["source root input must include schema_version".to_string()])?;

    match schema_version {
        ClaimSourceRootInput::SCHEMA_VERSION => {
            let input: ClaimSourceRootInput = serde_json::from_str(input_json)
                .map_err(|err| vec![format!("invalid claim source root input JSON: {err}")])?;
            input.to_digest_candidate()
        }
        OracleFactsRootInput::SCHEMA_VERSION => {
            let input: OracleFactsRootInput = serde_json::from_str(input_json)
                .map_err(|err| vec![format!("invalid oracle facts root input JSON: {err}")])?;
            input.to_digest_candidate()
        }
        FeeScheduleRootInput::SCHEMA_VERSION => {
            let input: FeeScheduleRootInput = serde_json::from_str(input_json)
                .map_err(|err| vec![format!("invalid fee schedule root input JSON: {err}")])?;
            input.to_digest_candidate()
        }
        NullifierRootTransitionInput::SCHEMA_VERSION => {
            let input: NullifierRootTransitionInput =
                serde_json::from_str(input_json).map_err(|err| {
                    vec![format!(
                        "invalid nullifier root transition input JSON: {err}"
                    )]
                })?;
            input.to_digest_candidate()
        }
        _ => Err(vec![format!(
            "unsupported source root input schema_version: {schema_version}"
        )]),
    }
}

fn usage() -> Vec<String> {
    vec![
        "usage: generate_source_root_digest_candidate <source_root_input.json> <source_root_digest_candidate.json>"
            .to_string(),
    ]
}
