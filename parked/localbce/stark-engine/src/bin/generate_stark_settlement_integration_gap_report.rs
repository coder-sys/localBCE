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

    use stark_engine::winterfell_poc_adapter::StarkSolidityVerifierInterfacePlan;

    let mut args = env::args();
    let _binary = args.next();
    let input_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let input_json = fs::read_to_string(&input_path)
        .map_err(|err| vec![format!("could not read {input_path}: {err}")])?;
    let plan: StarkSolidityVerifierInterfacePlan =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid STARK Solidity verifier interface plan JSON: {err}"
            )]
        })?;

    let report = plan.to_settlement_integration_gap_report()?;
    report.validate()?;

    let output_json = serde_json::to_string_pretty(&report).map_err(|err| {
        vec![format!(
            "could not serialize STARK settlement integration gap report JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_settlement_integration_gap_report_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": report.schema_version,
            "source_schema_version": report.source_schema_version,
            "report_status": report.report_status,
            "verifier_contract_gaps": report.verifier_contract_gaps.len(),
            "claims_registry_integration_gaps": report.claims_registry_integration_gaps.len(),
            "governance_gaps": report.governance_gaps.len(),
            "calldata_public_input_gaps": report.calldata_public_input_gaps.len(),
            "test_requirements": report.test_requirements.len(),
            "recommended_next_steps": report.recommended_next_steps.len(),
            "contract_modification_allowed": report.contract_modification_allowed,
            "runtime_wired": report.runtime_wired,
            "on_chain_submission": report.on_chain_submission,
        })
    );

    Ok(())
}

#[cfg(not(feature = "winterfell-poc"))]
fn run() -> Result<(), Vec<String>> {
    let _ = env::args();
    Err(vec![
        "generate_stark_settlement_integration_gap_report requires --features winterfell-poc"
            .to_string(),
        "usage: cargo run --features winterfell-poc --bin generate_stark_settlement_integration_gap_report -- <stark_solidity_verifier_interface_plan.json> <stark_settlement_integration_gap_report.json>"
            .to_string(),
    ])
}

#[cfg(feature = "winterfell-poc")]
fn usage() -> Vec<String> {
    vec![
        "usage: generate_stark_settlement_integration_gap_report <stark_solidity_verifier_interface_plan.json> <stark_settlement_integration_gap_report.json>"
            .to_string(),
    ]
}
