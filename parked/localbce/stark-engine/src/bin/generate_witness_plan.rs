use std::{env, fs, process};

use stark_engine::StarkProofIntent;

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
        vec!["usage: generate_witness_plan <proof_intent.json> <witness_plan.json>".to_string()]
    })?;
    let output_path = args.next().ok_or_else(|| {
        vec!["usage: generate_witness_plan <proof_intent.json> <witness_plan.json>".to_string()]
    })?;

    if args.next().is_some() {
        return Err(vec![
            "usage: generate_witness_plan <proof_intent.json> <witness_plan.json>".to_string(),
        ]);
    }

    let input_json = fs::read_to_string(&input_path)
        .map_err(|err| vec![format!("could not read {input_path}: {err}")])?;
    let intent: StarkProofIntent = serde_json::from_str(&input_json)
        .map_err(|err| vec![format!("invalid proof intent JSON: {err}")])?;
    let plan = intent.to_witness_plan();
    let output_json = serde_json::to_string_pretty(&plan)
        .map_err(|err| vec![format!("could not serialize witness plan JSON: {err}")])?;

    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_witness_plan_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": plan.schema_version,
            "source_schema_version": plan.source_schema_version,
            "claim_hash": plan.claim_hash,
            "decision": plan.decision,
            "witness_status": plan.witness_status,
            "constraint_groups": plan.constraint_groups.len(),
        })
    );

    Ok(())
}
