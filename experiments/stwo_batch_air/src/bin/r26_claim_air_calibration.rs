use std::env;

use blind_ledger_stwo_batch_air::physical_claim_kernel::{
    run_calibration, CalibrationProfile, CalibrationShape, CALIBRATION_STATUS,
};
use blind_ledger_stwo_batch_air::security_boundary::{
    enforce_before_trace, ProofSecurityRequirement,
};

struct Options {
    profile: CalibrationProfile,
    shape: CalibrationShape,
    security_requirement: ProofSecurityRequirement,
}

fn parse_options() -> Result<Options, String> {
    let mut profile = CalibrationProfile::K128;
    let mut shape = CalibrationShape::Approval;
    let mut security_requirement = ProofSecurityRequirement::ValidityOnly;
    let mut profile_seen = false;
    let mut shape_seen = false;
    let mut security_seen = false;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| format!("missing value for {argument}"))?;
        match argument.as_str() {
            "--profile" if !profile_seen => {
                profile = CalibrationProfile::parse(&value)?;
                profile_seen = true;
            }
            "--shape" if !shape_seen => {
                shape = CalibrationShape::parse(&value)?;
                shape_seen = true;
            }
            "--security-mode" if !security_seen => {
                security_requirement = ProofSecurityRequirement::parse(&value)?;
                security_seen = true;
            }
            "--profile" | "--shape" | "--security-mode" => {
                return Err(format!("{argument} may be supplied only once"));
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    Ok(Options {
        profile,
        shape,
        security_requirement,
    })
}

fn run() -> Result<(), String> {
    let options = parse_options()?;
    // This guard must remain before fixture, row, trace, commitment, or proof
    // allocation. The kernel itself repeats the validity-only guard.
    enforce_before_trace(options.security_requirement)?;
    let report = run_calibration(options.profile, options.shape)?;

    println!("status={}", report.status);
    println!("security_scope={}", report.security_scope);
    println!("profile_id={}", report.profile_id);
    println!("fixture_shape={}", report.fixture_shape);
    println!("physical_air_rows={}", report.physical_air_rows);
    println!("physical_air_columns={}", report.physical_air_columns);
    println!("interaction_columns={}", report.interaction_columns);
    println!("air_constraints={}", report.air_constraints);
    println!(
        "public_total_plan_payable_cents={}",
        report.public_total_plan_payable_cents
    );
    println!(
        "proof_size_estimate_bytes={}",
        report.proof_size_estimate_bytes
    );
    println!(
        "fixture_and_trace_seconds={:.9}",
        report.fixture_and_trace_seconds
    );
    println!("twiddle_seconds={:.9}", report.twiddle_seconds);
    println!("commitment_seconds={:.9}", report.commitment_seconds);
    println!("interaction_seconds={:.9}", report.interaction_seconds);
    println!("prove_seconds={:.9}", report.prove_seconds);
    println!("verify_seconds={:.9}", report.verify_seconds);
    println!("witness_hiding={}", report.witness_hiding);
    println!("proofSuiteId={}", report.proof_suite_id.unwrap_or("null"));
    println!("activation={}", report.activation_allowed);
    println!("proof_discarded={}", report.proof_discarded);
    println!("proof_artifact_written={}", report.proof_artifact_written);
    println!("proof_verified=true");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!(
            "error: {error} status={CALIBRATION_STATUS} witness_hiding=false \
             proofSuiteId=null activation=false proof_discarded=true \
             proof_artifact_written=false"
        );
        std::process::exit(1);
    }
}
