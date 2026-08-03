use std::{env, time::Instant};

use bl_pq512_crypto_core::{
    field::{Fp16, M31, M31_MODULUS},
    state_relation_gkr::{StateRelationEntry, StateRelationRow},
    state_squarefree_gkr::{
        StateSquarefreeGkrError, StateSquarefreeLayout, build_state_squarefree_witness,
        prove_state_squarefree_gkr_interactive, verify_state_squarefree_control_openings,
        verify_state_squarefree_gkr,
    },
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
    let layout = StateSquarefreeLayout::new(capacity).map_err(|error| format!("{error:?}"))?;
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
    let beta = Fp16::from_m31(M31::from_canonical(65_537).map_err(|_| "beta".to_string())?);
    let evaluation_point =
        Fp16::from_m31(M31::from_canonical(131_071).map_err(|_| "point".to_string())?);

    let witness_started = Instant::now();
    let witness = build_state_squarefree_witness(&rows, layout, beta)
        .map_err(|error| format!("witness:{error:?}"))?;
    let witness_seconds = witness_started.elapsed().as_secs_f64();
    let prove_started = Instant::now();
    let mut challenge_counter = 200_003_u32;
    let mut message_count = 0_usize;
    let proof = prove_state_squarefree_gkr_interactive(
        &rows,
        &witness,
        evaluation_point,
        |_, _, _, _, published| {
            if published.is_empty() {
                return Err(StateSquarefreeGkrError::Shape);
            }
            message_count += 1;
            challenge_counter = (challenge_counter + 2) % M31_MODULUS;
            Ok(Fp16::from_m31(
                M31::from_canonical(challenge_counter)
                    .expect("control challenge remains canonical"),
            ))
        },
    )
    .map_err(|error| format!("prove:{error:?}"))?;
    // beta follows the state commitment and r follows the A/B commitment.
    let round_count = message_count + 2;
    let prove_seconds = prove_started.elapsed().as_secs_f64();
    let verify_started = Instant::now();
    let claims =
        verify_state_squarefree_gkr(&proof).map_err(|error| format!("verify:{error:?}"))?;
    verify_state_squarefree_control_openings(&rows, &witness, &proof)
        .map_err(|error| format!("openings:{error:?}"))?;
    let verify_seconds = verify_started.elapsed().as_secs_f64();

    println!("evidence_class=MEASURED_CONTROL_NONACTIVATING");
    println!("construction=FP16_SQUAREFREE_DUAL_PRODUCT_GKR_V1");
    println!("capacity={capacity}");
    println!("phase_count=2");
    println!("tree_layers_per_phase={}", layout.tree_layer_count);
    println!("authenticated_rounds={round_count}");
    println!(
        "virtual_leaf_claims={}",
        claims
            .virtual_leaf_claims
            .iter()
            .map(|phase| phase.len())
            .sum::<usize>()
    );
    println!(
        "coefficient_pcs_claims={}",
        claims
            .coefficient_claims
            .iter()
            .map(|phase| phase.len())
            .sum::<usize>()
    );
    println!("witness_fp16_elements={}", 4 * capacity);
    println!("witness_bytes={}", 4 * capacity * 64);
    println!("witness_build_seconds={witness_seconds:.6}");
    println!("prove_seconds={prove_seconds:.6}");
    println!("verify_seconds={verify_seconds:.6}");
    println!("verified=true");
    println!("activation_allowed=false");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("state_squarefree_gkr_control_error={error}");
        std::process::exit(1);
    }
}
