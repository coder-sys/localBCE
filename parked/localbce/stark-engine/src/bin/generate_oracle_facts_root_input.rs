use std::{env, fs, process};

use stark_engine::{OracleFactsRootInput, StarkBridgeInput};

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
    let input_path = args.next().ok_or_else(|| {
        vec![
            "usage: generate_oracle_facts_root_input <stark_bridge_input.json> <oracle_facts_root_input.json>"
                .to_string(),
        ]
    })?;
    let output_path = args.next().ok_or_else(|| {
        vec![
            "usage: generate_oracle_facts_root_input <stark_bridge_input.json> <oracle_facts_root_input.json>"
                .to_string(),
        ]
    })?;

    if args.next().is_some() {
        return Err(vec![
            "usage: generate_oracle_facts_root_input <stark_bridge_input.json> <oracle_facts_root_input.json>"
                .to_string(),
        ]);
    }

    let input_json = fs::read_to_string(&input_path)
        .map_err(|err| vec![format!("could not read {input_path}: {err}")])?;
    let input: StarkBridgeInput = serde_json::from_str(&input_json)
        .map_err(|err| vec![format!("invalid bridge input JSON: {err}")])?;
    let oracle = OracleFactsRootInput::from_bridge_input(&input)?;
    oracle.validate()?;
    let output_json = serde_json::to_string_pretty(&oracle).map_err(|err| {
        vec![format!(
            "could not serialize oracle facts root input JSON: {err}"
        )]
    })?;

    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_oracle_facts_root_input_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": oracle.schema_version,
            "source_schema_version": oracle.source_schema_version,
            "input_status": oracle.input_status,
            "claim_id": oracle.claim_id,
            "claim_hash": oracle.claim_hash,
            "source_manifest_present": oracle.source_manifest_id.is_some(),
            "facts": oracle.facts.len(),
            "attestation_refs": oracle.attestation_refs.len(),
            "root_generation_status": oracle.root_generation_status,
            "root_generation": false,
            "proof_generation": false,
        })
    );

    Ok(())
}
