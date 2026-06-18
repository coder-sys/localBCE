use std::{env, fs, process};

use stark_engine::StarkWitnessPlan;

fn main() {
    if let Err(errors) = run() {
        for error in errors {
            eprintln!("{error}");
        }
        process::exit(1);
    }
}

fn run() -> Result<(), Vec<String>> {
    let path = env::args()
        .nth(1)
        .ok_or_else(|| vec!["usage: validate_witness_plan <witness_plan.json>".to_string()])?;

    let input_json =
        fs::read_to_string(&path).map_err(|err| vec![format!("could not read {path}: {err}")])?;
    let plan: StarkWitnessPlan = serde_json::from_str(&input_json)
        .map_err(|err| vec![format!("invalid witness plan JSON: {err}")])?;

    plan.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_witness_plan_validation",
            "status": "ok",
            "path": path,
            "schema_version": plan.schema_version,
            "source_schema_version": plan.source_schema_version,
            "claim_hash": plan.claim_hash,
            "decision": plan.decision,
            "failure_code": plan.failure_code,
            "constraint_groups": plan.constraint_groups.len(),
            "witness_status": plan.witness_status,
        })
    );

    Ok(())
}
