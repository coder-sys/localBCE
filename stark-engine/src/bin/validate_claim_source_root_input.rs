use std::{env, fs, process};

use stark_engine::ClaimSourceRootInput;

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
        vec!["usage: validate_claim_source_root_input <claim_source_root_input.json>".to_string()]
    })?;

    let input_json =
        fs::read_to_string(&path).map_err(|err| vec![format!("could not read {path}: {err}")])?;
    let input: ClaimSourceRootInput = serde_json::from_str(&input_json)
        .map_err(|err| vec![format!("invalid claim source root input JSON: {err}")])?;

    input.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "stark_claim_source_root_input_validation",
            "status": "ok",
            "path": path,
            "schema_version": input.schema_version,
            "source_schema_version": input.source_schema_version,
            "input_status": input.input_status,
            "claim_id": input.claim_id,
            "claim_hash": input.claim_hash,
            "claim_amount": input.claim_amount,
            "member_id_present": input.member_id.is_some(),
            "provider_npi_present": input.provider_npi.is_some(),
            "procedure_codes": input.procedure_codes.len(),
            "diagnosis_codes": input.diagnosis_codes.len(),
            "service_line_count_present": input.service_line_count.is_some(),
            "root_generation_status": input.root_generation_status,
            "root_generation": false,
            "proof_generation": false,
        })
    );

    Ok(())
}
