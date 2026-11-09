use std::{env, fs, process};

use stark_engine::real_prover::RealProverEvidenceSummary;

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
    let summary: RealProverEvidenceSummary = serde_json::from_str(&input_json).map_err(|err| {
        vec![format!(
            "invalid Phase 8 real prover evidence summary JSON: {err}"
        )]
    })?;

    summary.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_real_prover_evidence_summary_validation",
            "status": "ok",
            "path": path,
            "schema_version": summary.schema_version,
            "summary_status": summary.summary_status,
            "declared_slot_count": summary.declared_slot_count,
            "satisfied_slot_count": summary.satisfied_slot_count,
            "missing_or_unsatisfied_slot_count": summary.missing_or_unsatisfied_slot_count,
            "blocker_count": summary.blocker_count,
            "all_slots_declared": summary.all_slots_declared,
            "all_slots_satisfied": summary.all_slots_satisfied,
            "implementation_satisfied": summary.implementation_satisfied,
            "runtime_cutover_allowed": summary.runtime_cutover_allowed,
            "real_proof_generation_allowed": summary.real_proof_generation_allowed,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec!["usage: validate_phase8_real_prover_evidence_summary <phase8_real_prover_evidence_summary.json>".to_string()]
}
