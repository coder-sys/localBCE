use std::{env, time::Instant};

use bl_pq512_crypto_core::state_relation_gkr::{StateRelationEntry, StateRelationRow};
use bl_pq512_crypto_core::state_uniqueness_gkr::{
    StateUniquenessLayout, build_state_uniqueness_source, prove_state_uniqueness_gkr_control,
    state_uniqueness_control_challenges, state_uniqueness_input_claims,
    verify_state_uniqueness_gkr,
};

fn entry(index: usize, phase: u8) -> StateRelationEntry {
    let mut key = [0_u8; 64];
    let mut value = [0_u8; 64];
    key[56..].copy_from_slice(&(index as u64).to_be_bytes());
    key[55] = phase;
    value[56..].copy_from_slice(&((index as u64) + 1).to_be_bytes());
    StateRelationEntry {
        index: index as u32,
        present: true,
        key,
        value,
    }
}

fn run() -> Result<(), String> {
    let capacity = env::args()
        .nth(1)
        .unwrap_or_else(|| "128".to_string())
        .parse::<usize>()
        .map_err(|_| "capacity".to_string())?;
    let layout = StateUniquenessLayout::new(capacity).map_err(|error| format!("{error:?}"))?;
    let rows = (0..capacity)
        .map(|index| {
            let before = entry(index, 0);
            let after = entry(index, 1);
            StateRelationRow {
                operation_before: before,
                operation_after: after,
                snapshot_before: before,
                snapshot_after: after,
            }
        })
        .collect::<Vec<_>>();

    let source_started = Instant::now();
    let source = build_state_uniqueness_source(&rows, layout)
        .map_err(|error| format!("source:{error:?}"))?;
    let source_seconds = source_started.elapsed().as_secs_f64();
    let challenges = state_uniqueness_control_challenges(layout)
        .map_err(|error| format!("challenges:{error:?}"))?;
    let round_count = challenges
        .layer_challenges
        .iter()
        .map(Vec::len)
        .sum::<usize>()
        + 2 * challenges.input_coefficients.len();

    let prove_started = Instant::now();
    let proof = prove_state_uniqueness_gkr_control(&source, layout, challenges)
        .map_err(|error| format!("prove:{error:?}"))?;
    let prove_seconds = prove_started.elapsed().as_secs_f64();
    let verify_started = Instant::now();
    verify_state_uniqueness_gkr(&proof).map_err(|error| format!("verify:{error:?}"))?;
    let claims =
        state_uniqueness_input_claims(&proof).map_err(|error| format!("claims:{error:?}"))?;
    let verify_seconds = verify_started.elapsed().as_secs_f64();

    println!("evidence_class=MEASURED_CONTROL_NONACTIVATING");
    println!("capacity={capacity}");
    println!("pair_count={}", layout.pair_count);
    println!("phase_pair_instances={}", layout.instance_count);
    println!("source_fp16_elements={}", source.len());
    println!("source_bytes={}", source.len() * 64);
    println!("authenticated_rounds={round_count}");
    println!("pcs_input_claims={}", claims.len());
    println!("source_build_seconds={source_seconds:.6}");
    println!("prove_seconds={prove_seconds:.6}");
    println!("verify_seconds={verify_seconds:.6}");
    println!("verified=true");
    println!("activation_allowed=false");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("state_uniqueness_gkr_control_error={error}");
        std::process::exit(1);
    }
}
