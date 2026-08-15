//! Thin command-line boundary for one complete nonactivating v3 authority run.
//!
//! This binary is a verifier-owned replay boundary over a complete raw
//! witness.  The H4 and parent labels are replay routes only: they do not
//! generate witness bytes and must never be advertised as proof producers.
//! Keeping one native transaction preserves the least-TCB property while
//! making the missing witness-acquisition seam explicit.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use bl_pq512_crypto_core::v3_composite_envelope::V3ProfileLayout;
use bl_pq512_crypto_core::v3_real_authority::{
    REAL_AUTHORITY_EVIDENCE_FORMAT, REAL_AUTHORITY_HOST_PEAK_LIMIT_BYTES,
    REAL_AUTHORITY_SCRATCH_LIMIT_BYTES, REAL_AUTHORITY_TIMEOUT_SECONDS,
    REAL_AUTHORITY_WITNESS_FORMAT, RealAuthorityRunContract, RealWitness, TRUSTED_LAYOUT_FILE,
    run_real_authority_with_custody,
};

const USAGE: &str = "usage: v3_real_authority_run --role <orchestrator|h4-replay|parent-replay|outer-verifier> --witness-dir <absolute-dir> --evidence-dir <absolute-dir> --scratch-dir <absolute-dir> --custody-dir <absolute-dir> [--profile <K128_CALIBRATION|K512_CALIBRATION>]";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Role {
    Orchestrator,
    H4Replay,
    ParentReplay,
    OuterVerifier,
}

impl Role {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "orchestrator" => Ok(Self::Orchestrator),
            "h4-replay" => Ok(Self::H4Replay),
            "parent-replay" => Ok(Self::ParentReplay),
            "outer-verifier" => Ok(Self::OuterVerifier),
            _ => Err(format!("role_invalid:{value}")),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Orchestrator => "orchestrator",
            Self::H4Replay => "h4-replay",
            Self::ParentReplay => "parent-replay",
            Self::OuterVerifier => "outer-verifier",
        }
    }
}

fn required_value(args: &[String], index: &mut usize, flag: &str) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| format!("{flag}_value_missing"))
}

fn absolute_directory(value: String, label: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!("{label}_path_not_absolute"));
    }
    Ok(path)
}

fn run(args: &[String]) -> Result<(), String> {
    let mut role = None;
    let mut witness_dir = None;
    let mut evidence_dir = None;
    let mut scratch_dir = None;
    let mut custody_dir = None;
    let mut expected_profile = None;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--role" => role = Some(Role::parse(&required_value(args, &mut index, "--role")?)?),
            "--witness-dir" => {
                witness_dir = Some(absolute_directory(
                    required_value(args, &mut index, "--witness-dir")?,
                    "witness_dir",
                )?);
            }
            "--evidence-dir" => {
                evidence_dir = Some(absolute_directory(
                    required_value(args, &mut index, "--evidence-dir")?,
                    "evidence_dir",
                )?);
            }
            "--scratch-dir" => {
                scratch_dir = Some(absolute_directory(
                    required_value(args, &mut index, "--scratch-dir")?,
                    "scratch_dir",
                )?);
            }
            "--custody-dir" => {
                custody_dir = Some(absolute_directory(
                    required_value(args, &mut index, "--custody-dir")?,
                    "custody_dir",
                )?);
            }
            "--profile" => expected_profile = Some(required_value(args, &mut index, "--profile")?),
            _ => return Err(format!("{USAGE}")),
        }
        index += 1;
    }

    let role = role.ok_or_else(|| format!("{USAGE}"))?;
    let witness_dir = witness_dir.ok_or_else(|| format!("{USAGE}"))?;
    let evidence_dir = evidence_dir.ok_or_else(|| format!("{USAGE}"))?;
    let scratch_dir = scratch_dir.ok_or_else(|| format!("{USAGE}"))?;
    let custody_dir = custody_dir.ok_or_else(|| format!("{USAGE}"))?;
    if let Some(expected_profile) = expected_profile.as_deref() {
        let expected_code = match expected_profile {
            "K128_CALIBRATION" => 1,
            "K512_CALIBRATION" => 3,
            _ => return Err(format!("profile_invalid:{expected_profile}")),
        };
        let witness = RealWitness::open(&witness_dir).map_err(|error| error.to_string())?;
        let layout = V3ProfileLayout::decode_trusted(
            &witness
                .read_small(TRUSTED_LAYOUT_FILE)
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| format!("trusted_layout:{error:?}"))?;
        if layout.profile_code != expected_code {
            return Err(format!(
                "profile_mismatch:expected={expected_code}:actual={}",
                layout.profile_code
            ));
        }
    }
    let report =
        run_real_authority_with_custody(&witness_dir, &evidence_dir, &scratch_dir, &custody_dir)
            .map_err(|error| error.to_string())?;
    println!("status={}", report.status);
    println!("role={}", role.label());
    println!("profile_code={}", report.profile_code);
    println!("witness_format={REAL_AUTHORITY_WITNESS_FORMAT}");
    println!("evidence_format={REAL_AUTHORITY_EVIDENCE_FORMAT}");
    println!("proofSuiteId=null");
    println!("production_usable=false");
    println!("activation_allowed=false");
    println!("real_phi_or_payments=false");
    Ok(())
}

fn capabilities() {
    let contract = RealAuthorityRunContract::default();
    println!("status=V3_REAL_AUTHORITY_LANE_AVAILABLE_NONACTIVATING");
    println!("witness_format={}", contract.witness_format);
    println!("evidence_format={}", contract.evidence_format);
    println!("orchestrator_role=available_closed_witness_replay");
    println!("h4_producer_role=missing_witness_acquisition");
    println!("parent_producer_role=missing_witness_acquisition");
    println!("h4_replay_route=available_full_replay");
    println!("parent_replay_route=available_full_replay");
    println!("outer_verifier_role=available_accepting_over_complete_witness");
    println!("witness_acquisition=missing_complete_raw_witness");
    println!("h4_complete_post_z_replay=available");
    println!("parent_completion=available");
    println!("aggregate_verification=available");
    println!("host_peak_limit_bytes={REAL_AUTHORITY_HOST_PEAK_LIMIT_BYTES}");
    println!("scratch_limit_bytes={REAL_AUTHORITY_SCRATCH_LIMIT_BYTES}");
    println!("timeout_seconds={REAL_AUTHORITY_TIMEOUT_SECONDS}");
    println!("proofSuiteId=null");
    println!("production_usable=false");
    println!("activation_allowed=false");
}

fn main() -> ExitCode {
    let args = env::args().collect::<Vec<_>>();
    if args.len() == 2 && args[1] == "--capabilities" {
        capabilities();
        return ExitCode::SUCCESS;
    }
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ERR {error}");
            ExitCode::from(2)
        }
    }
}
