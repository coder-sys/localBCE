use std::{env, fs, process};

use stark_engine::PublicInputRootAssemblyPlan;

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
    let plan: PublicInputRootAssemblyPlan = serde_json::from_str(&input_json).map_err(|err| {
        vec![format!(
            "invalid public input root assembly plan JSON: {err}"
        )]
    })?;

    plan.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "public_input_root_assembly_plan_validation",
            "status": "ok",
            "path": path,
            "schema_version": plan.schema_version,
            "source_schema_version": plan.source_schema_version,
            "plan_status": plan.plan_status,
            "hash_strategy": plan.hash_strategy,
            "canonical_encoding": plan.canonical_encoding,
            "ordered_fields": plan.ordered_fields.len(),
            "expected_field_count": plan.expected_field_count,
            "root_generation_status": plan.root_generation_status,
            "public_input_root_present": plan.public_input_root.is_some(),
            "groth16_flow_unchanged": plan.groth16_flow_unchanged,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: validate_public_input_root_assembly_plan <public_input_root_assembly_plan.json>"
            .to_string(),
    ]
}
