use std::{env, fs, process};

use stark_engine::real_prover::Phase8RealProverReadinessRollup;

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
    let rollup: Phase8RealProverReadinessRollup =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid Phase 8 real prover readiness rollup JSON: {err}"
            )]
        })?;

    rollup.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_real_prover_readiness_rollup_validation",
            "status": "ok",
            "path": path,
            "schema_version": rollup.schema_version,
            "rollup_status": rollup.rollup_status,
            "evidence_slots_declared": rollup.evidence_slots_declared,
            "evidence_slots_satisfied": rollup.evidence_slots_satisfied,
            "evidence_slots_blocked": rollup.evidence_slots_blocked,
            "remaining_blocker_count": rollup.remaining_blocker_count,
            "test_only_shapes_present": rollup.test_only_shapes_present,
            "real_evidence_complete": rollup.real_evidence_complete,
            "runtime_cutover_allowed": rollup.runtime_cutover_allowed,
            "real_proof_generation_allowed": rollup.real_proof_generation_allowed,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: validate_phase8_real_prover_readiness_rollup <phase8_real_prover_readiness_rollup.json>"
            .to_string(),
    ]
}
