use std::{env, fs, process};

use stark_engine::PublicInputRootAssemblyPlan;

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
    let plan: PublicInputRootAssemblyPlan = serde_json::from_str(&input_json).map_err(|err| {
        vec![format!(
            "invalid public input root assembly plan JSON: {err}"
        )]
    })?;

    let candidate = plan.to_digest_candidate()?;
    candidate.validate()?;

    let output_json = serde_json::to_string_pretty(&candidate).map_err(|err| {
        vec![format!(
            "could not serialize public input root digest candidate JSON: {err}"
        )]
    })?;

    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "public_input_root_digest_candidate_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
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
        "usage: generate_public_input_root_digest_candidate <public_input_root_assembly_plan.json> <public_input_root_digest_candidate.json>"
            .to_string(),
    ]
}
