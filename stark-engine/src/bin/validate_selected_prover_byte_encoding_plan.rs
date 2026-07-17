use std::{env, fs, process};

use stark_engine::SelectedProverByteEncodingPlan;

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
    let plan: SelectedProverByteEncodingPlan =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid selected prover byte encoding plan JSON: {err}"
            )]
        })?;

    plan.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "selected_prover_byte_encoding_plan_validation",
            "status": "ok",
            "path": path,
            "schema_version": plan.schema_version,
            "source_schema_version": plan.source_schema_version,
            "plan_status": plan.plan_status,
            "selected_prover": plan.selected_prover,
            "proof_bytes_status": plan.proof_bytes_status,
            "binding_fields": plan.commitment_binding_fields.len(),
            "runtime_wiring_allowed": plan.runtime_wiring_allowed,
            "groth16_flow_unchanged": plan.groth16_flow_unchanged,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: validate_selected_prover_byte_encoding_plan <selected_prover_byte_encoding_plan.json>"
            .to_string(),
    ]
}
