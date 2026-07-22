use std::{env, fs, process};

use stark_engine::real_prover::{
    RealProofBytesFixturePromotionPlan, TestOnlyEvidenceSatisfactionRehearsalReport,
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
    let rehearsal_report_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let input_json = fs::read_to_string(&rehearsal_report_path)
        .map_err(|err| vec![format!("could not read {rehearsal_report_path}: {err}")])?;
    let report: TestOnlyEvidenceSatisfactionRehearsalReport =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid Phase 8 test-only evidence satisfaction rehearsal report JSON: {err}"
            )]
        })?;

    let plan = RealProofBytesFixturePromotionPlan::from_rehearsal_report(&report)?;
    plan.validate()?;

    let output_json = serde_json::to_string_pretty(&plan).map_err(|err| {
        vec![format!(
            "could not serialize Phase 8 real proof bytes fixture promotion plan JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_real_proof_bytes_fixture_promotion_plan_generation",
            "status": "ok",
            "input": rehearsal_report_path,
            "output": output_path,
            "schema_version": plan.schema_version,
            "promotion_status": plan.promotion_status,
            "target_evidence_slot": plan.target_evidence_slot,
            "required_condition_count": plan.required_condition_count,
            "current_fixture_shape_present": plan.current_fixture_shape_present,
            "current_validation_log_shape_present": plan.current_validation_log_shape_present,
            "current_digest_matches_log": plan.current_digest_matches_log,
            "slot_promotion_ready": plan.slot_promotion_ready,
            "runtime_cutover_allowed": plan.runtime_cutover_allowed,
            "real_proof_generation_allowed": plan.real_proof_generation_allowed,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: generate_phase8_real_proof_bytes_fixture_promotion_plan <phase8_test_only_evidence_satisfaction_rehearsal_report.json> <phase8_real_proof_bytes_fixture_promotion_plan.json>"
            .to_string(),
    ]
}
