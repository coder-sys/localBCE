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

    let path = env::args().nth(1).ok_or_else(usage)?;

    let input_json =
        fs::read_to_string(&path).map_err(|err| vec![format!("could not read {path}: {err}")])?;
    let plan: StarkSolidityVerifierInterfacePlan =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid STARK Solidity verifier interface plan JSON: {err}"
            )]
        })?;

    plan.validate_v1_candidate_alignment()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_verifier_abi_candidate_alignment_validation",
            "status": "ok",
            "path": path,
            "abi_candidate": StarkSolidityVerifierInterfacePlan::V1_CANDIDATE_INTERFACE_NAME,
            "schema_version": plan.schema_version,
            "source_schema_version": plan.source_schema_version,
            "interface_name": plan.interface_name,
            "function_signature": plan.function_signature,
            "solidity_inputs": plan.solidity_inputs.len(),
            "expected_solidity_inputs": StarkSolidityVerifierInterfacePlan::V1_CANDIDATE_INPUTS.len(),
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
        "validate_stark_verifier_abi_candidate_alignment requires --features winterfell-poc"
            .to_string(),
        "usage: cargo run --features winterfell-poc --bin validate_stark_verifier_abi_candidate_alignment -- <stark_solidity_verifier_interface_plan.json>"
            .to_string(),
    ])
}

#[cfg(feature = "winterfell-poc")]
fn usage() -> Vec<String> {
    vec![
        "usage: validate_stark_verifier_abi_candidate_alignment <stark_solidity_verifier_interface_plan.json>"
            .to_string(),
    ]
}
