use std::{env, fs, process};

use stark_engine::{Phase8PreProverBundleCheckpoint, Phase8RealProverImplementationChecklist};

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
    let checkpoint_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let checkpoint_json = fs::read_to_string(&checkpoint_path)
        .map_err(|err| vec![format!("could not read {checkpoint_path}: {err}")])?;
    let checkpoint: Phase8PreProverBundleCheckpoint = serde_json::from_str(&checkpoint_json)
        .map_err(|err| vec![format!("invalid Phase 8 checkpoint JSON: {err}")])?;

    let checklist = Phase8RealProverImplementationChecklist::from_checkpoint(&checkpoint)?;
    checklist.validate()?;

    let output_json = serde_json::to_string_pretty(&checklist).map_err(|err| {
        vec![format!(
            "could not serialize Phase 8 real prover implementation checklist JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_real_prover_implementation_checklist_generation",
            "status": "ok",
            "input": checkpoint_path,
            "output": output_path,
            "schema_version": checklist.schema_version,
            "source_schema_version": checklist.source_schema_version,
            "checklist_status": checklist.checklist_status,
            "work_items": checklist.work_items.len(),
            "all_pre_prover_artifacts_validated": checklist.all_pre_prover_artifacts_validated,
            "runtime_cutover_allowed": checklist.runtime_cutover_allowed,
            "groth16_flow_unchanged": checklist.groth16_flow_unchanged,
            "completion_gate": checklist.completion_gate,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: generate_phase8_real_prover_implementation_checklist <phase8_pre_prover_bundle_checkpoint.json> <phase8_real_prover_implementation_checklist.json>"
            .to_string(),
    ]
}
