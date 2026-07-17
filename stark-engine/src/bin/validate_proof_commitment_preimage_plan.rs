use std::{env, fs, process};

use stark_engine::ProofCommitmentPreimagePlan;

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
    let plan: ProofCommitmentPreimagePlan = serde_json::from_str(&input_json).map_err(|err| {
        vec![format!(
            "invalid proof commitment preimage plan JSON: {err}"
        )]
    })?;

    plan.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "proof_commitment_preimage_plan_validation",
            "status": "ok",
            "path": path,
            "schema_version": plan.schema_version,
            "source_schema_version": plan.source_schema_version,
            "plan_status": plan.plan_status,
            "hash_strategy": plan.hash_strategy,
            "canonical_encoding": plan.canonical_encoding,
            "ordered_components": plan.ordered_components.len(),
            "expected_component_count": plan.expected_component_count,
            "commitment_generation_status": plan.commitment_generation_status,
            "proof_commitment_present": plan.proof_commitment.is_some(),
            "groth16_flow_unchanged": plan.groth16_flow_unchanged,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: validate_proof_commitment_preimage_plan <proof_commitment_preimage_plan.json>"
            .to_string(),
    ]
}
