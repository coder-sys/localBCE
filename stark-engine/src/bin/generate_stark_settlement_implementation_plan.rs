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

    use stark_engine::winterfell_poc_adapter::StarkSettlementIntegrationGapReport;

    let mut args = env::args();
    let _binary = args.next();
    let input_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let input_json = fs::read_to_string(&input_path)
        .map_err(|err| vec![format!("could not read {input_path}: {err}")])?;
    let report: StarkSettlementIntegrationGapReport =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid STARK settlement integration gap report JSON: {err}"
            )]
        })?;

    let plan = report.to_settlement_implementation_plan()?;
    plan.validate()?;

    let output_json = serde_json::to_string_pretty(&plan).map_err(|err| {
        vec![format!(
            "could not serialize STARK settlement implementation plan JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_settlement_implementation_plan_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
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
        "generate_stark_settlement_implementation_plan requires --features winterfell-poc"
            .to_string(),
        "usage: cargo run --features winterfell-poc --bin generate_stark_settlement_implementation_plan -- <stark_settlement_integration_gap_report.json> <stark_settlement_implementation_plan.json>"
            .to_string(),
    ])
}

#[cfg(feature = "winterfell-poc")]
fn usage() -> Vec<String> {
    vec![
        "usage: generate_stark_settlement_implementation_plan <stark_settlement_integration_gap_report.json> <stark_settlement_implementation_plan.json>"
            .to_string(),
    ]
}
