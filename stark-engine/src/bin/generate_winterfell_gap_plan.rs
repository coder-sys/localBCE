use std::{env, fs, process};

use stark_engine::WinterfellPocCompatibilityReport;

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
            "usage: generate_winterfell_gap_plan <winterfell_compat_report.json> <winterfell_gap_plan.json>"
                .to_string(),
        ]
    })?;
    let output_path = args.next().ok_or_else(|| {
        vec![
            "usage: generate_winterfell_gap_plan <winterfell_compat_report.json> <winterfell_gap_plan.json>"
                .to_string(),
        ]
    })?;

    if args.next().is_some() {
        return Err(vec![
            "usage: generate_winterfell_gap_plan <winterfell_compat_report.json> <winterfell_gap_plan.json>"
                .to_string(),
        ]);
    }

    let input_json = fs::read_to_string(&input_path)
        .map_err(|err| vec![format!("could not read {input_path}: {err}")])?;
    let report: WinterfellPocCompatibilityReport =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid Winterfell compatibility report JSON: {err}"
            )]
        })?;
    let plan = report.to_adapter_gap_plan();
    let output_json = serde_json::to_string_pretty(&plan)
        .map_err(|err| vec![format!("could not serialize gap plan JSON: {err}")])?;

    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "winterfell_adapter_gap_plan_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": plan.schema_version,
            "source_schema_version": plan.source_schema_version,
            "direct_ready_fields": plan.direct_ready_fields.len(),
            "partial_fields_requiring_normalization": plan.partial_fields_requiring_normalization.len(),
            "unmapped_fields_requiring_source_data": plan.unmapped_fields_requiring_source_data.len(),
            "unsupported_constraints_requiring_prover_work": plan.unsupported_constraints_requiring_prover_work.len(),
            "recommended_next_steps": plan.recommended_next_steps.len(),
        })
    );

    Ok(())
}
