use std::{env, fs, process};

use stark_engine::{FeeScheduleRootInput, StarkBridgeInput};

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
            "usage: generate_fee_schedule_root_input <stark_bridge_input.json> <fee_schedule_root_input.json>"
                .to_string(),
        ]
    })?;
    let output_path = args.next().ok_or_else(|| {
        vec![
            "usage: generate_fee_schedule_root_input <stark_bridge_input.json> <fee_schedule_root_input.json>"
                .to_string(),
        ]
    })?;

    if args.next().is_some() {
        return Err(vec![
            "usage: generate_fee_schedule_root_input <stark_bridge_input.json> <fee_schedule_root_input.json>"
                .to_string(),
        ]);
    }

    let input_json = fs::read_to_string(&input_path)
        .map_err(|err| vec![format!("could not read {input_path}: {err}")])?;
    let input: StarkBridgeInput = serde_json::from_str(&input_json)
        .map_err(|err| vec![format!("invalid bridge input JSON: {err}")])?;
    let fee_schedule = FeeScheduleRootInput::from_bridge_input(&input)?;
    fee_schedule.validate()?;
    let output_json = serde_json::to_string_pretty(&fee_schedule).map_err(|err| {
        vec![format!(
            "could not serialize fee schedule root input JSON: {err}"
        )]
    })?;

    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_fee_schedule_root_input_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": fee_schedule.schema_version,
            "source_schema_version": fee_schedule.source_schema_version,
            "input_status": fee_schedule.input_status,
            "claim_id": fee_schedule.claim_id,
            "claim_hash": fee_schedule.claim_hash,
            "fee_schedule_present": fee_schedule.fee_schedule_id.is_some(),
            "entries": fee_schedule.entries.len(),
            "root_generation_status": fee_schedule.root_generation_status,
            "root_generation": false,
            "proof_generation": false,
        })
    );

    Ok(())
}
