use std::{env, fs, process};

use stark_engine::Phase8RealProverImplementationChecklist;

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
    let checklist: Phase8RealProverImplementationChecklist = serde_json::from_str(&input_json)
        .map_err(|err| {
            vec![format!(
                "invalid Phase 8 real prover implementation checklist JSON: {err}"
            )]
        })?;

    checklist.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_real_prover_implementation_checklist_validation",
            "status": "ok",
            "path": path,
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
        "usage: validate_phase8_real_prover_implementation_checklist <phase8_real_prover_implementation_checklist.json>"
            .to_string(),
    ]
}
