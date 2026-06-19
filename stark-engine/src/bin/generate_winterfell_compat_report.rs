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
    let mut args = env::args();
    let _binary = args.next();
    let input_path = args.next().ok_or_else(|| {
        vec![
            "usage: generate_winterfell_compat_report <mock_trace.json> <compat_report.json>"
                .to_string(),
        ]
    })?;
    let output_path = args.next().ok_or_else(|| {
        vec![
            "usage: generate_winterfell_compat_report <mock_trace.json> <compat_report.json>"
                .to_string(),
        ]
    })?;

    if args.next().is_some() {
        return Err(vec![
            "usage: generate_winterfell_compat_report <mock_trace.json> <compat_report.json>"
                .to_string(),
        ]);
    }

    let input_json = fs::read_to_string(&input_path)
        .map_err(|err| vec![format!("could not read {input_path}: {err}")])?;
    let trace: StarkMockTrace = serde_json::from_str(&input_json)
        .map_err(|err| vec![format!("invalid mock trace JSON: {err}")])?;
    let report = trace.winterfell_poc_compatibility_report();
    let output_json = serde_json::to_string_pretty(&report).map_err(|err| {
        vec![format!(
            "could not serialize compatibility report JSON: {err}"
        )]
    })?;

    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "winterfell_poc_compatibility_report_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": report.schema_version,
            "source_schema_version": report.source_schema_version,
            "verdict": report.verdict,
            "mock_trace_rows": report.mock_trace_rows,
            "direct_compatible_fields": report.direct_compatible_fields.len(),
            "partial_fields": report.partial_fields.len(),
            "unmapped_fields": report.unmapped_fields.len(),
            "unsupported_winterfell_constraints": report.unsupported_winterfell_constraints.len(),
        })
    );

    Ok(())
}
