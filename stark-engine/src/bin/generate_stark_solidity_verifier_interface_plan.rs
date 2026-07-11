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

    use stark_engine::winterfell_poc_adapter::StarkSettlementBoundaryArtifact;

    let mut args = env::args();
    let _binary = args.next();
    let input_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let input_json = fs::read_to_string(&input_path)
        .map_err(|err| vec![format!("could not read {input_path}: {err}")])?;
    let artifact: StarkSettlementBoundaryArtifact =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid STARK settlement boundary artifact JSON: {err}"
            )]
        })?;

    let plan = artifact.to_solidity_verifier_interface_plan()?;
    plan.validate()?;

    let output_json = serde_json::to_string_pretty(&plan).map_err(|err| {
        vec![format!(
            "could not serialize STARK Solidity verifier interface plan JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_solidity_verifier_interface_plan_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": plan.schema_version,
            "source_schema_version": plan.source_schema_version,
            "interface_status": plan.interface_status,
            "interface_name": plan.interface_name,
            "solidity_inputs": plan.solidity_inputs.len(),
            "required_checks": plan.required_checks.len(),
            "unsupported_runtime_work": plan.unsupported_runtime_work.len(),
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
        "generate_stark_solidity_verifier_interface_plan requires --features winterfell-poc"
            .to_string(),
        "usage: cargo run --features winterfell-poc --bin generate_stark_solidity_verifier_interface_plan -- <stark_settlement_boundary_artifact.json> <stark_solidity_verifier_interface_plan.json>"
            .to_string(),
    ])
}

#[cfg(feature = "winterfell-poc")]
fn usage() -> Vec<String> {
    vec![
        "usage: generate_stark_solidity_verifier_interface_plan <stark_settlement_boundary_artifact.json> <stark_solidity_verifier_interface_plan.json>"
            .to_string(),
    ]
}
