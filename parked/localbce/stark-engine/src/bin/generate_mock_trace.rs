use std::{env, fs, process};

use stark_engine::StarkWitnessPlan;

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
        vec!["usage: generate_mock_trace <witness_plan.json> <mock_trace.json>".to_string()]
    })?;
    let output_path = args.next().ok_or_else(|| {
        vec!["usage: generate_mock_trace <witness_plan.json> <mock_trace.json>".to_string()]
    })?;

    if args.next().is_some() {
        return Err(vec![
            "usage: generate_mock_trace <witness_plan.json> <mock_trace.json>".to_string(),
        ]);
    }

    let input_json = fs::read_to_string(&input_path)
        .map_err(|err| vec![format!("could not read {input_path}: {err}")])?;
    let plan: StarkWitnessPlan = serde_json::from_str(&input_json)
        .map_err(|err| vec![format!("invalid witness plan JSON: {err}")])?;
    let trace = plan.to_mock_trace()?;
    let output_json = serde_json::to_string_pretty(&trace)
        .map_err(|err| vec![format!("could not serialize mock trace JSON: {err}")])?;

    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_mock_trace_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": trace.schema_version,
            "source_schema_version": trace.source_schema_version,
            "claim_hash": trace.claim_hash,
            "rows": trace.rows.len(),
            "trace_status": trace.trace_status,
            "all_rows_satisfied": trace.rows.iter().all(|row| row.satisfied),
        })
    );

    Ok(())
}
