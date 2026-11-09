use std::{env, fs, process};

use stark_engine::SourceRootAggregationPlan;

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
    let plan: SourceRootAggregationPlan = serde_json::from_str(&input_json)
        .map_err(|err| vec![format!("invalid source root aggregation plan JSON: {err}")])?;

    plan.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "source_root_aggregation_plan_validation",
            "status": "ok",
            "path": path,
            "schema_version": plan.schema_version,
            "source_schema_version": plan.source_schema_version,
            "plan_status": plan.plan_status,
            "source_root_bindings": plan.source_root_bindings.len(),
            "expected_source_root_count": plan.expected_source_root_count,
            "all_source_roots_bound": plan.all_source_roots_bound,
            "root_generation_status": plan.root_generation_status,
            "production_hash_selected": plan.production_hash_selected,
            "runtime_wiring_allowed": plan.runtime_wiring_allowed,
            "groth16_flow_unchanged": plan.groth16_flow_unchanged,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: validate_source_root_aggregation_plan <source_root_aggregation_plan.json>"
            .to_string(),
    ]
}
