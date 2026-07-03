use std::{env, fs, process};

use stark_engine::StarkMockTrace;

fn main() {
    if let Err(errors) = run() {
        for error in errors {
            eprintln!("{error}");
        }
        process::exit(1);
    }
}

fn run() -> Result<(), Vec<String>> {
    let path = env::args()
        .nth(1)
        .ok_or_else(|| vec!["usage: validate_mock_trace <mock_trace.json>".to_string()])?;

    let input_json =
        fs::read_to_string(&path).map_err(|err| vec![format!("could not read {path}: {err}")])?;
    let trace: StarkMockTrace = serde_json::from_str(&input_json)
        .map_err(|err| vec![format!("invalid mock trace JSON: {err}")])?;

    trace.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_mock_trace_validation",
            "status": "ok",
            "path": path,
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
