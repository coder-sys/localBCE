use std::{env, fs, process};

use stark_engine::{BatchRootCompatibilityPlan, StarkBridgeInput};

fn main() {
    if let Err(errors) = run() {
        for error in errors {
            eprintln!("{error}");
        }
        process::exit(1);
    }
}

fn run() -> Result<(), Vec<String>> {
    let mut args = env::args();
    let _binary = args.next();
    let input_path = args.next().ok_or_else(|| {
        vec![
            "usage: generate_batch_root_plan <stark_bridge_input.json> <batch_root_plan.json>"
                .to_string(),
        ]
    })?;
    let output_path = args.next().ok_or_else(|| {
        vec![
            "usage: generate_batch_root_plan <stark_bridge_input.json> <batch_root_plan.json>"
                .to_string(),
        ]
    })?;

    if args.next().is_some() {
        return Err(vec![
            "usage: generate_batch_root_plan <stark_bridge_input.json> <batch_root_plan.json>"
                .to_string(),
        ]);
    }

    let input_json = fs::read_to_string(&input_path)
        .map_err(|err| vec![format!("could not read {input_path}: {err}")])?;
    let input: StarkBridgeInput = serde_json::from_str(&input_json)
        .map_err(|err| vec![format!("invalid bridge input JSON: {err}")])?;
    let plan = BatchRootCompatibilityPlan::from_bridge_input(&input)?;
    plan.validate()?;
    let output_json = serde_json::to_string_pretty(&plan)
        .map_err(|err| vec![format!("could not serialize batch root plan JSON: {err}")])?;

    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_batch_root_plan_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": plan.schema_version,
            "source_schema_version": plan.source_schema_version,
            "plan_status": plan.plan_status,
            "target_fields": plan.target_fields.len(),
            "direct": plan.counts.direct,
            "partial": plan.counts.partial,
            "unmapped": plan.counts.unmapped,
            "root_generation": false,
            "proof_generation": false,
        })
    );

    Ok(())
}
