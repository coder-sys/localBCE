use std::{env, fs, process};

use stark_engine::FeeScheduleRootInput;

fn main() {
    if let Err(errors) = run() {
        for error in errors {
            eprintln!("{error}");
        }
        process::exit(1);
    }
}

fn run() -> Result<(), Vec<String>> {
    let path = env::args().nth(1).ok_or_else(|| {
        vec!["usage: validate_fee_schedule_root_input <fee_schedule_root_input.json>".to_string()]
    })?;

    let input_json =
        fs::read_to_string(&path).map_err(|err| vec![format!("could not read {path}: {err}")])?;
    let input: FeeScheduleRootInput = serde_json::from_str(&input_json)
        .map_err(|err| vec![format!("invalid fee schedule root input JSON: {err}")])?;

    input.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_fee_schedule_root_input_validation",
            "status": "ok",
            "path": path,
            "schema_version": input.schema_version,
            "source_schema_version": input.source_schema_version,
            "input_status": input.input_status,
            "claim_id": input.claim_id,
            "claim_hash": input.claim_hash,
            "fee_schedule_present": input.fee_schedule_id.is_some(),
            "entries": input.entries.len(),
            "root_generation_status": input.root_generation_status,
            "root_generation": false,
            "proof_generation": false,
        })
    );

    Ok(())
}
