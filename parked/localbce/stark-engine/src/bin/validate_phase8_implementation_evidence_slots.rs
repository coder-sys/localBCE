use std::{env, fs, process};

use stark_engine::Phase8ImplementationEvidenceSlots;

fn main() {
    if let Err(errors) = run() {
        for error in errors {
            eprintln!("{error}");
        }
        process::exit(1);
    }
}

fn run() -> Result<(), Vec<String>> {
    let path = env::args().nth(1).ok_or_else(usage)?;

    let input_json =
        fs::read_to_string(&path).map_err(|err| vec![format!("could not read {path}: {err}")])?;
    let slots: Phase8ImplementationEvidenceSlots =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid Phase 8 implementation evidence slots JSON: {err}"
            )]
        })?;

    slots.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_implementation_evidence_slots_validation",
            "status": "ok",
            "path": path,
            "schema_version": slots.schema_version,
            "source_schema_version": slots.source_schema_version,
            "evidence_status": slots.evidence_status,
            "evidence_slots": slots.evidence_slots.len(),
            "populated_slot_count": slots.populated_slot_count,
            "missing_slot_count": slots.missing_slot_count,
            "real_proof_generation_allowed": slots.real_proof_generation_allowed,
            "real_artifact_emission_allowed": slots.real_artifact_emission_allowed,
            "runtime_cutover_allowed": slots.runtime_cutover_allowed,
            "on_chain_submission_allowed": slots.on_chain_submission_allowed,
            "groth16_flow_unchanged": slots.groth16_flow_unchanged,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: validate_phase8_implementation_evidence_slots <phase8_implementation_evidence_slots.json>"
            .to_string(),
    ]
}
