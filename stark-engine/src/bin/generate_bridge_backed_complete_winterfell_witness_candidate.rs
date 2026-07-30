use std::{env, fs, process};

use stark_engine::{StarkBridgeInput, WinterfellCompleteWitnessCandidate};

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
        .map_err(|err| vec![format!("invalid StarkBridgeInput JSON: {err}")])?;

    let candidate = WinterfellCompleteWitnessCandidate::from_bridge_input_strict(&input)?;
    candidate.validate_bridge_backed()?;
    let output_json = serde_json::to_string_pretty(&candidate).map_err(|err| {
        vec![format!(
            "could not serialize bridge-backed complete Winterfell witness candidate: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "bridge_backed_complete_winterfell_witness_candidate_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": candidate.schema_version,
            "source_schema_version": candidate.source_schema_version,
            "candidate_status": candidate.candidate_status,
            "claim_id": candidate.claim_id,
            "claim_hash": candidate.claim_hash,
            "field_count": candidate.field_count,
            "all_fields_populated": candidate.all_fields_populated,
            "fixture_substitution": false,
            "winterfell_dependency_imported": candidate.winterfell_dependency_imported,
            "proof_generation": candidate.proof_generation_enabled,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: generate_bridge_backed_complete_winterfell_witness_candidate <stark_bridge_input.json> <complete_winterfell_witness_candidate.json>"
            .to_string(),
    ]
}
