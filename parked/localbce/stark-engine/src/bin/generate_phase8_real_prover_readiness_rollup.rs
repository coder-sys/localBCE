use std::{env, fs, process};

use stark_engine::real_prover::{
    LocalRealProofValidationLogPromotionPlan, Phase8RealProverReadinessRollup,
    RealProofBytesFixturePromotionPlan, RealProverEvidenceSummary,
};

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
    let evidence_summary_path = args.next().ok_or_else(usage)?;
    let fixture_plan_path = args.next().ok_or_else(usage)?;
    let validation_log_plan_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let evidence_summary: RealProverEvidenceSummary =
        read_json(&evidence_summary_path, "real prover evidence summary")?;
    let fixture_plan: RealProofBytesFixturePromotionPlan =
        read_json(&fixture_plan_path, "proof bytes fixture promotion plan")?;
    let validation_log_plan: LocalRealProofValidationLogPromotionPlan = read_json(
        &validation_log_plan_path,
        "local validation log promotion plan",
    )?;

    let rollup = Phase8RealProverReadinessRollup::from_inputs(
        &evidence_summary,
        &fixture_plan,
        &validation_log_plan,
    )?;
    rollup.validate()?;

    let output_json = serde_json::to_string_pretty(&rollup).map_err(|err| {
        vec![format!(
            "could not serialize Phase 8 real prover readiness rollup JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_real_prover_readiness_rollup_generation",
            "status": "ok",
            "output": output_path,
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

fn read_json<T: serde::de::DeserializeOwned>(path: &str, label: &str) -> Result<T, Vec<String>> {
    let input_json =
        fs::read_to_string(path).map_err(|err| vec![format!("could not read {path}: {err}")])?;
    serde_json::from_str(&input_json)
        .map_err(|err| vec![format!("invalid Phase 8 {label} JSON: {err}")])
}

fn usage() -> Vec<String> {
    vec![
        "usage: generate_phase8_real_prover_readiness_rollup <phase8_real_prover_evidence_summary.json> <phase8_real_proof_bytes_fixture_promotion_plan.json> <phase8_local_real_proof_validation_log_promotion_plan.json> <phase8_real_prover_readiness_rollup.json>"
            .to_string(),
    ]
}
