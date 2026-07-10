use std::{env, fs, process};

use stark_engine::BatchRootCompatibilityPlan;

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
            "usage: generate_batch_root_gap_report <batch_root_plan.json> <batch_root_gap_report.json>"
                .to_string(),
        ]
    })?;
    let output_path = args.next().ok_or_else(|| {
        vec![
            "usage: generate_batch_root_gap_report <batch_root_plan.json> <batch_root_gap_report.json>"
                .to_string(),
        ]
    })?;

    if args.next().is_some() {
        return Err(vec![
            "usage: generate_batch_root_gap_report <batch_root_plan.json> <batch_root_gap_report.json>"
                .to_string(),
        ]);
    }

    let input_json = fs::read_to_string(&input_path)
        .map_err(|err| vec![format!("could not read {input_path}: {err}")])?;
    let plan: BatchRootCompatibilityPlan = serde_json::from_str(&input_json)
        .map_err(|err| vec![format!("invalid batch root plan JSON: {err}")])?;
    let report = plan.to_gap_report()?;
    report.validate()?;
    let output_json = serde_json::to_string_pretty(&report).map_err(|err| {
        vec![format!(
            "could not serialize batch root gap report JSON: {err}"
        )]
    })?;

    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_batch_root_gap_report_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": report.schema_version,
            "source_schema_version": report.source_schema_version,
            "report_status": report.report_status,
            "direct_ready_fields": report.direct_ready_fields.len(),
            "partial_fields_requiring_normalization": report.partial_fields_requiring_normalization.len(),
            "unmapped_fields_requiring_source_data": report.unmapped_fields_requiring_source_data.len(),
            "unsupported_root_generation_tasks": report.unsupported_root_generation_tasks.len(),
            "recommended_next_steps": report.recommended_next_steps.len(),
            "root_generation": false,
            "proof_generation": false,
        })
    );

    Ok(())
}
