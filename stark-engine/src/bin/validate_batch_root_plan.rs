use std::{env, fs, process};

use stark_engine::BatchRootCompatibilityPlan;

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
        .ok_or_else(|| vec!["usage: validate_batch_root_plan <batch_root_plan.json>".to_string()])?;

    let input_json =
        fs::read_to_string(&path).map_err(|err| vec![format!("could not read {path}: {err}")])?;
    let plan: BatchRootCompatibilityPlan = serde_json::from_str(&input_json)
        .map_err(|err| vec![format!("invalid batch root plan JSON: {err}")])?;

    plan.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_batch_root_plan_validation",
            "status": "ok",
            "path": path,
            "schema_version": plan.schema_version,
            "source_schema_version": plan.source_schema_version,
            "plan_status": plan.plan_status,
            "target_fields": plan.target_fields.len(),
            "direct": plan.counts.direct,
            "partial": plan.counts.partial,
            "unmapped": plan.counts.unmapped,
            "root_generation": false,
            "proof_generation": false,
        })
    );

    Ok(())
}
