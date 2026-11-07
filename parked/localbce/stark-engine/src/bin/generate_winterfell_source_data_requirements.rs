use std::{env, fs, process};

use stark_engine::WinterfellWitnessImplementationGapReport;

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
            "usage: generate_winterfell_source_data_requirements <winterfell_witness_gap_report.json> <winterfell_source_data_requirements.json>"
                .to_string(),
        ]
    })?;
    let output_path = args.next().ok_or_else(|| {
        vec![
            "usage: generate_winterfell_source_data_requirements <winterfell_witness_gap_report.json> <winterfell_source_data_requirements.json>"
                .to_string(),
        ]
    })?;

    if args.next().is_some() {
        return Err(vec![
            "usage: generate_winterfell_source_data_requirements <winterfell_witness_gap_report.json> <winterfell_source_data_requirements.json>"
                .to_string(),
        ]);
    }

    let input_json = fs::read_to_string(&input_path)
        .map_err(|err| vec![format!("could not read {input_path}: {err}")])?;
    let gap_report: WinterfellWitnessImplementationGapReport = serde_json::from_str(&input_json)
        .map_err(|err| vec![format!("invalid Winterfell witness gap report JSON: {err}")])?;
    let requirements = gap_report.to_source_data_requirements()?;
    requirements.validate()?;
    let output_json = serde_json::to_string_pretty(&requirements).map_err(|err| {
        vec![format!(
            "could not serialize Winterfell source data requirements JSON: {err}"
        )]
    })?;

    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "winterfell_source_data_requirements_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": requirements.schema_version,
            "source_schema_version": requirements.source_schema_version,
            "requirements_status": requirements.requirements_status,
            "claim_id": requirements.claim_id,
            "claim_hash": requirements.claim_hash,
            "required_fields_total": requirements.required_fields_total,
            "normalized_fields_total": requirements.normalized_fields_total,
            "source_data_fields_total": requirements.source_data_fields_total,
            "recommended_next_steps": requirements.recommended_next_steps.len(),
            "winterfell_dependency_imported": requirements.winterfell_dependency_imported,
            "proof_generation": requirements.proof_generation_enabled,
        })
    );

    Ok(())
}
