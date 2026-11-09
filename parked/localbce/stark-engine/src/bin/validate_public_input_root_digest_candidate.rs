use std::{env, fs, process};

use stark_engine::PublicInputRootDigestCandidate;

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
    let candidate: PublicInputRootDigestCandidate =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid public input root digest candidate JSON: {err}"
            )]
        })?;

    candidate.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "public_input_root_digest_candidate_validation",
            "status": "ok",
            "path": path,
            "schema_version": candidate.schema_version,
            "source_schema_version": candidate.source_schema_version,
            "candidate_status": candidate.candidate_status,
            "hash_algorithm": candidate.hash_algorithm,
            "public_input_root_candidate": candidate.public_input_root_candidate,
            "root_generation_status": candidate.root_generation_status,
            "production_hash_selected": candidate.production_hash_selected,
            "runtime_wiring_allowed": candidate.runtime_wiring_allowed,
            "groth16_flow_unchanged": candidate.groth16_flow_unchanged,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: validate_public_input_root_digest_candidate <public_input_root_digest_candidate.json>"
            .to_string(),
    ]
}
