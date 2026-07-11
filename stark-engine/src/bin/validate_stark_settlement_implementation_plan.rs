use std::{env, process};

fn main() {
    if let Err(errors) = run() {
        for error in errors {
            eprintln!("{error}");
        }
        process::exit(1);
    }
}

#[cfg(feature = "winterfell-poc")]
fn run() -> Result<(), Vec<String>> {
    use std::fs;

    use stark_engine::winterfell_poc_adapter::StarkSettlementIntegrationImplementationPlan;

    let path = env::args().nth(1).ok_or_else(usage)?;

    let input_json =
        fs::read_to_string(&path).map_err(|err| vec![format!("could not read {path}: {err}")])?;
    let plan: StarkSettlementIntegrationImplementationPlan = serde_json::from_str(&input_json)
        .map_err(|err| {
            vec![format!(
                "invalid STARK settlement implementation plan JSON: {err}"
            )]
        })?;

    plan.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_settlement_implementation_plan_validation",
            "status": "ok",
            "path": path,
            "schema_version": plan.schema_version,
            "source_schema_version": plan.source_schema_version,
            "plan_status": plan.plan_status,
            "phases": plan.phases.len(),
            "blocked_by": plan.blocked_by.len(),
            "required_artifacts": plan.required_artifacts.len(),
            "safety_invariants": plan.safety_invariants.len(),
            "contract_modification_allowed": plan.contract_modification_allowed,
            "runtime_wired": plan.runtime_wired,
            "on_chain_submission": plan.on_chain_submission,
        })
    );

    Ok(())
}

#[cfg(not(feature = "winterfell-poc"))]
fn run() -> Result<(), Vec<String>> {
    let _ = env::args();
    Err(vec![
        "validate_stark_settlement_implementation_plan requires --features winterfell-poc"
            .to_string(),
        "usage: cargo run --features winterfell-poc --bin validate_stark_settlement_implementation_plan -- <stark_settlement_implementation_plan.json>"
            .to_string(),
    ])
}

#[cfg(feature = "winterfell-poc")]
fn usage() -> Vec<String> {
    vec![
        "usage: validate_stark_settlement_implementation_plan <stark_settlement_implementation_plan.json>"
            .to_string(),
    ]
}
