use std::{env, fs, process};

use stark_engine::real_prover::LocalRealProofValidationLogPromotionPlan;

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
    let plan: LocalRealProofValidationLogPromotionPlan = serde_json::from_str(&input_json)
        .map_err(|err| {
            vec![format!(
                "invalid Phase 8 local real proof validation log promotion plan JSON: {err}"
            )]
        })?;

    plan.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_local_real_proof_validation_log_promotion_plan_validation",
            "status": "ok",
            "path": path,
            "schema_version": plan.schema_version,
            "promotion_status": plan.promotion_status,
            "target_evidence_slot": plan.target_evidence_slot,
            "required_condition_count": plan.required_condition_count,
            "current_validation_log_shape_present": plan.current_validation_log_shape_present,
            "current_digest_matches_fixture": plan.current_digest_matches_fixture,
            "current_claim_hash_matches_fixture": plan.current_claim_hash_matches_fixture,
            "slot_promotion_ready": plan.slot_promotion_ready,
            "runtime_cutover_allowed": plan.runtime_cutover_allowed,
            "real_proof_generation_allowed": plan.real_proof_generation_allowed,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: validate_phase8_local_real_proof_validation_log_promotion_plan <phase8_local_real_proof_validation_log_promotion_plan.json>"
            .to_string(),
    ]
}
