use std::{env, fs, process};

use stark_engine::{Phase8ImplementationEvidenceSlots, Phase8ImplementationSourceRegistry};

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
    let registry_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let registry_json = fs::read_to_string(&registry_path)
        .map_err(|err| vec![format!("could not read {registry_path}: {err}")])?;
    let registry: Phase8ImplementationSourceRegistry = serde_json::from_str(&registry_json)
        .map_err(|err| {
            vec![format!(
                "invalid Phase 8 implementation source registry JSON: {err}"
            )]
        })?;

    let slots = Phase8ImplementationEvidenceSlots::from_registry(&registry)?;
    slots.validate()?;

    let output_json = serde_json::to_string_pretty(&slots).map_err(|err| {
        vec![format!(
            "could not serialize Phase 8 implementation evidence slots JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_implementation_evidence_slots_generation",
            "status": "ok",
            "input": registry_path,
            "output": output_path,
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
        "usage: generate_phase8_implementation_evidence_slots <phase8_implementation_source_registry.json> <phase8_implementation_evidence_slots.json>"
            .to_string(),
    ]
}
