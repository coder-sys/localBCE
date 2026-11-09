use std::{env, fs, process};

use stark_engine::real_prover::{
    LocalRealProofValidationLogEvidence, RealProofBytesFixtureEvidence, RealProverCodePathEvidence,
    RealProverEvidenceSummary, RealProverUnitTestsEvidence,
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
    let code_path_path = args.next().ok_or_else(usage)?;
    let unit_tests_path = args.next().ok_or_else(usage)?;
    let validation_log_path = args.next().ok_or_else(usage)?;
    let proof_fixture_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let code_path: RealProverCodePathEvidence = read_json(&code_path_path, "code path evidence")?;
    let unit_tests: RealProverUnitTestsEvidence =
        read_json(&unit_tests_path, "unit tests evidence")?;
    let validation_log: LocalRealProofValidationLogEvidence =
        read_json(&validation_log_path, "validation log evidence")?;
    let proof_fixture: RealProofBytesFixtureEvidence =
        read_json(&proof_fixture_path, "proof bytes fixture evidence")?;

    let summary = RealProverEvidenceSummary::from_evidence_slots(
        &code_path,
        &unit_tests,
        &validation_log,
        &proof_fixture,
    )?;
    summary.validate()?;

    let output_json = serde_json::to_string_pretty(&summary).map_err(|err| {
        vec![format!(
            "could not serialize Phase 8 real prover evidence summary JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_real_prover_evidence_summary_generation",
            "status": "ok",
            "output": output_path,
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

fn read_json<T: serde::de::DeserializeOwned>(path: &str, label: &str) -> Result<T, Vec<String>> {
    let input_json =
        fs::read_to_string(path).map_err(|err| vec![format!("could not read {path}: {err}")])?;
    serde_json::from_str(&input_json)
        .map_err(|err| vec![format!("invalid Phase 8 real prover {label} JSON: {err}")])
}

fn usage() -> Vec<String> {
    vec![
        "usage: generate_phase8_real_prover_evidence_summary <code_path_evidence.json> <unit_tests_evidence.json> <validation_log_evidence.json> <proof_bytes_fixture_evidence.json> <phase8_real_prover_evidence_summary.json>"
            .to_string(),
    ]
}
