use std::{env, fs, path::PathBuf};

use anyhow::{bail, Context};
use blind_ledger_stark::{verify_claim, ClaimPublicInputs, Felt};
use serde::Deserialize;
use winterfell::Proof;

#[derive(Deserialize)]
struct PublicInputFile {
    commitment: String,
    decision: u32,
    failure_code: u32,
}

fn main() -> anyhow::Result<()> {
    let proof_path = env::args()
        .nth(1)
        .map(PathBuf::from)
        .context("usage: verify_artifact <proof.stark> <public.json>")?;
    let public_path = env::args()
        .nth(2)
        .map(PathBuf::from)
        .context("usage: verify_artifact <proof.stark> <public.json>")?;

    let proof_bytes = fs::read(&proof_path)
        .with_context(|| format!("failed to read proof {}", proof_path.display()))?;
    let proof = Proof::from_bytes(&proof_bytes).context("failed to parse Winterfell proof")?;

    let public: PublicInputFile = serde_json::from_slice(
        &fs::read(&public_path)
            .with_context(|| format!("failed to read public inputs {}", public_path.display()))?,
    )?;
    let commitment = public
        .commitment
        .parse::<u128>()
        .context("commitment is not a u128 field element")?;
    let commitment = Felt::try_from(commitment).map_err(|_| anyhow::anyhow!("invalid commitment"))?;
    if public.decision > 1 {
        bail!("decision must be 0 or 1");
    }
    if public.failure_code > 10 {
        bail!("failure_code must be 0..10");
    }

    let pub_inputs = ClaimPublicInputs {
        commitment,
        decision: Felt::from(public.decision),
        failure_code: Felt::from(public.failure_code),
    };
    let (verified, verify_duration) = verify_claim(proof, pub_inputs);
    println!(
        "{}",
        serde_json::json!({
            "proof": proof_path.display().to_string(),
            "public_inputs": public_path.display().to_string(),
            "verified": verified,
            "verify_us": verify_duration.as_micros()
        })
    );
    Ok(())
}

