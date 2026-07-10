use std::{env, fs, process};

use stark_engine::{ClaimSourceRootInput, StarkBridgeInput};

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
            "usage: generate_claim_source_root_input <stark_bridge_input.json> <claim_source_root_input.json>"
                .to_string(),
        ]
    })?;
    let output_path = args.next().ok_or_else(|| {
        vec![
            "usage: generate_claim_source_root_input <stark_bridge_input.json> <claim_source_root_input.json>"
                .to_string(),
        ]
    })?;

    if args.next().is_some() {
        return Err(vec![
            "usage: generate_claim_source_root_input <stark_bridge_input.json> <claim_source_root_input.json>"
                .to_string(),
        ]);
    }

    let input_json = fs::read_to_string(&input_path)
        .map_err(|err| vec![format!("could not read {input_path}: {err}")])?;
    let input: StarkBridgeInput = serde_json::from_str(&input_json)
        .map_err(|err| vec![format!("invalid bridge input JSON: {err}")])?;
    let source = ClaimSourceRootInput::from_bridge_input(&input)?;
    source.validate()?;
    let output_json = serde_json::to_string_pretty(&source)
        .map_err(|err| vec![format!("could not serialize claim source root input JSON: {err}")])?;

    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_claim_source_root_input_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": source.schema_version,
            "source_schema_version": source.source_schema_version,
            "input_status": source.input_status,
            "claim_id": source.claim_id,
            "claim_hash": source.claim_hash,
            "claim_amount": source.claim_amount,
            "member_id_present": source.member_id.is_some(),
            "provider_npi_present": source.provider_npi.is_some(),
            "procedure_codes": source.procedure_codes.len(),
            "diagnosis_codes": source.diagnosis_codes.len(),
            "service_line_count_present": source.service_line_count.is_some(),
            "root_generation_status": source.root_generation_status,
            "root_generation": false,
            "proof_generation": false,
        })
    );

    Ok(())
}
