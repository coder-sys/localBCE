use std::{env, fs, process};

use stark_engine::{WinterfellSourceDataFixture, WinterfellWitnessCandidate};

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
    let candidate_path = args.next().ok_or_else(|| {
        vec![
            "usage: generate_complete_winterfell_witness_candidate <winterfell_witness_candidate.json> <winterfell_source_data_fixture.json> <complete_winterfell_witness_candidate.json>"
                .to_string(),
        ]
    })?;
    let fixture_path = args.next().ok_or_else(|| {
        vec![
            "usage: generate_complete_winterfell_witness_candidate <winterfell_witness_candidate.json> <winterfell_source_data_fixture.json> <complete_winterfell_witness_candidate.json>"
                .to_string(),
        ]
    })?;
    let output_path = args.next().ok_or_else(|| {
        vec![
            "usage: generate_complete_winterfell_witness_candidate <winterfell_witness_candidate.json> <winterfell_source_data_fixture.json> <complete_winterfell_witness_candidate.json>"
                .to_string(),
        ]
    })?;

    if args.next().is_some() {
        return Err(vec![
            "usage: generate_complete_winterfell_witness_candidate <winterfell_witness_candidate.json> <winterfell_source_data_fixture.json> <complete_winterfell_witness_candidate.json>"
                .to_string(),
        ]);
    }

    let candidate_json = fs::read_to_string(&candidate_path)
        .map_err(|err| vec![format!("could not read {candidate_path}: {err}")])?;
    let candidate: WinterfellWitnessCandidate = serde_json::from_str(&candidate_json)
        .map_err(|err| vec![format!("invalid Winterfell witness candidate JSON: {err}")])?;

    let fixture_json = fs::read_to_string(&fixture_path)
        .map_err(|err| vec![format!("could not read {fixture_path}: {err}")])?;
    let fixture: WinterfellSourceDataFixture =
        serde_json::from_str(&fixture_json).map_err(|err| {
            vec![format!(
                "invalid Winterfell source data fixture JSON: {err}"
            )]
        })?;

    let complete = fixture.to_complete_witness_candidate(&candidate)?;
    complete.validate()?;
    let output_json = serde_json::to_string_pretty(&complete).map_err(|err| {
        vec![format!(
            "could not serialize complete Winterfell witness candidate JSON: {err}"
        )]
    })?;

    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "complete_winterfell_witness_candidate_generation",
            "status": "ok",
            "candidate_input": candidate_path,
            "fixture_input": fixture_path,
            "output": output_path,
            "schema_version": complete.schema_version,
            "source_schema_version": complete.source_schema_version,
            "candidate_status": complete.candidate_status,
            "claim_id": complete.claim_id,
            "claim_hash": complete.claim_hash,
            "field_count": complete.field_count,
            "all_fields_populated": complete.all_fields_populated,
            "winterfell_dependency_imported": complete.winterfell_dependency_imported,
            "proof_generation": complete.proof_generation_enabled,
        })
    );

    Ok(())
}
