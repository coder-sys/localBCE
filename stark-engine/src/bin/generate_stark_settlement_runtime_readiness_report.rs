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

    let mut args = env::args();
    let _binary = args.next();
    let input_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let input_json = fs::read_to_string(&input_path)
        .map_err(|err| vec![format!("could not read {input_path}: {err}")])?;
    let plan: StarkSettlementIntegrationImplementationPlan = serde_json::from_str(&input_json)
        .map_err(|err| {
            vec![format!(
                "invalid STARK settlement implementation plan JSON: {err}"
            )]
        })?;

    let report = plan.to_runtime_readiness_report()?;
    report.validate()?;

    let output_json = serde_json::to_string_pretty(&report).map_err(|err| {
        vec![format!(
            "could not serialize STARK settlement runtime readiness report JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_settlement_runtime_readiness_report_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": report.schema_version,
            "source_schema_version": report.source_schema_version,
            "readiness_status": report.readiness_status,
            "ready_for_runtime": report.ready_for_runtime,
            "ready_for_contract_changes": report.ready_for_contract_changes,
            "ready_for_on_chain_submission": report.ready_for_on_chain_submission,
            "satisfied_gates": report.satisfied_gates.len(),
            "unsatisfied_gates": report.unsatisfied_gates.len(),
            "required_evidence": report.required_evidence.len(),
            "next_review_actions": report.next_review_actions.len(),
            "human_approval_required": report.human_approval_required,
        })
    );

    Ok(())
}

#[cfg(not(feature = "winterfell-poc"))]
fn run() -> Result<(), Vec<String>> {
    let _ = env::args();
    Err(vec![
        "generate_stark_settlement_runtime_readiness_report requires --features winterfell-poc"
            .to_string(),
        "usage: cargo run --features winterfell-poc --bin generate_stark_settlement_runtime_readiness_report -- <stark_settlement_implementation_plan.json> <stark_settlement_runtime_readiness_report.json>"
            .to_string(),
    ])
}

#[cfg(feature = "winterfell-poc")]
fn usage() -> Vec<String> {
    vec![
        "usage: generate_stark_settlement_runtime_readiness_report <stark_settlement_implementation_plan.json> <stark_settlement_runtime_readiness_report.json>"
            .to_string(),
    ]
}
