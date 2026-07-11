use std::{env, fs, process};

use stark_engine::{WinterfellSourceDataFixture, WinterfellSourceDataRequirements};

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
            "usage: generate_winterfell_source_data_fixture <winterfell_source_data_requirements.json> <winterfell_source_data_fixture.json>"
                .to_string(),
        ]
    })?;
    let output_path = args.next().ok_or_else(|| {
        vec![
            "usage: generate_winterfell_source_data_fixture <winterfell_source_data_requirements.json> <winterfell_source_data_fixture.json>"
                .to_string(),
        ]
    })?;

    if args.next().is_some() {
        return Err(vec![
            "usage: generate_winterfell_source_data_fixture <winterfell_source_data_requirements.json> <winterfell_source_data_fixture.json>"
                .to_string(),
        ]);
    }

    let input_json = fs::read_to_string(&input_path)
        .map_err(|err| vec![format!("could not read {input_path}: {err}")])?;
    let requirements: WinterfellSourceDataRequirements = serde_json::from_str(&input_json)
        .map_err(|err| {
            vec![format!(
                "invalid Winterfell source data requirements JSON: {err}"
            )]
        })?;
    let fixture = WinterfellSourceDataFixture::demo_from_requirements(&requirements)?;
    fixture.validate()?;
    let output_json = serde_json::to_string_pretty(&fixture).map_err(|err| {
        vec![format!(
            "could not serialize Winterfell source data fixture JSON: {err}"
        )]
    })?;

    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "winterfell_source_data_fixture_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": fixture.schema_version,
            "source_schema_version": fixture.source_schema_version,
            "fixture_status": fixture.fixture_status,
            "claim_id": fixture.claim_id,
            "claim_hash": fixture.claim_hash,
            "source_requirements_satisfied": fixture.source_requirements_satisfied.len(),
            "diagnosis_count": fixture.diagnosis_count,
            "service_line_count": fixture.service_line_count,
            "charge_cents": fixture.charge_cents,
            "max_charge_cents": fixture.max_charge_cents,
            "winterfell_dependency_imported": fixture.winterfell_dependency_imported,
            "proof_generation": fixture.proof_generation_enabled,
        })
    );

    Ok(())
}
