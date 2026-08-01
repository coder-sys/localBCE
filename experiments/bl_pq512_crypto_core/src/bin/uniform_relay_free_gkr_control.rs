use std::time::Instant;

use bl_pq512_crypto_core::{
    chained_public_coin::{
        ChainedRoundDescriptor, decode_chained_public_coin_bundle,
        encode_chained_public_coin_bundle, verify_chained_public_coin_bundle,
    },
    chained_public_coin_client::ChainedPublicCoinCoordinator,
    field::{Fp16, M31, M31_MODULUS},
    fp16_relay_free_gkr_schedule::{
        GKR_TRANSCRIPT_ROUNDS, SelectedGkrRoundKind, selected_gkr_mask_layout,
    },
    fp16_relay_free_gkr_uniform::{
        UniformRelayFreeGkrError, complete_uniform_gkr_mask_batch, prove_masked_uniform_zero_trace,
        verify_masked_uniform_zero_trace,
    },
};
use sha3::{Digest, Sha3_512};

fn round_code(kind: SelectedGkrRoundKind) -> u16 {
    match kind {
        SelectedGkrRoundKind::OutputQuery => 100,
        SelectedGkrRoundKind::PackedBridge => 110,
        SelectedGkrRoundKind::SharedGroup => 111,
        SelectedGkrRoundKind::Wire => 112,
        SelectedGkrRoundKind::Terminal => 113,
        SelectedGkrRoundKind::ClaimMix => 114,
        SelectedGkrRoundKind::MaskBatch => 115,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = std::env::current_exe()?
        .parent()
        .ok_or("control executable parent")?
        .join("chained_public_coin_service.exe");
    let session_id: [u8; 64] =
        Sha3_512::digest(b"BL/PQ512/WAVE2/UNIFORM-REAL-GKR/SESSION/v1").into();
    let schedule: [u8; 64] =
        Sha3_512::digest(b"BL/PQ512/WAVE2/UNIFORM-REAL-MASKED-GKR/SCHEDULE/v1").into();
    let layout = selected_gkr_mask_layout().map_err(|error| format!("{error:?}"))?;
    let mask_coefficients = (0..layout.padded_coefficients)
        .map(|index| {
            let value = ((31 * index + 20_003) as u32 % (M31_MODULUS - 1)) + 1;
            M31::from_canonical(value)
                .map(Fp16::from_m31)
                .map_err(|error| format!("{error:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut mask_hash = Sha3_512::new();
    mask_hash.update(b"BL/PQ512/WAVE2/UNIFORM-REAL-MASKED-GKR/COMMITMENT/v1\0");
    for coefficient in &mask_coefficients {
        mask_hash.update(coefficient.encode());
    }
    let mask_commitment: [u8; 64] = mask_hash.finalize().into();
    let total_started = Instant::now();
    let spawn_started = Instant::now();
    let mut coordinator = ChainedPublicCoinCoordinator::spawn(
        &service,
        session_id,
        0,
        schedule,
        GKR_TRANSCRIPT_ROUNDS + 1,
    )
    .map_err(|error| format!("{error:?}"))?;
    let spawn_seconds = spawn_started.elapsed().as_secs_f64();

    let prover_started = Instant::now();
    let mut ordinal = 0_u32;
    let mut proof = prove_masked_uniform_zero_trace(
        mask_commitment,
        &mask_coefficients,
        |kind, message, output_count| {
            let descriptor = ChainedRoundDescriptor {
                kind: round_code(kind),
                ordinal,
                output_count,
            };
            let outputs = coordinator
                .challenge(descriptor, message)
                .map_err(|_| UniformRelayFreeGkrError::Coin)?;
            ordinal += 1;
            Ok(outputs)
        },
    )
    .map_err(|error| format!("{error:?}"))?;
    let layer_prover_seconds = prover_started.elapsed().as_secs_f64();
    let mask_batch_started = Instant::now();
    let batch = complete_uniform_gkr_mask_batch(
        &mut proof,
        &mask_coefficients,
        |kind, message, output_count| {
            let descriptor = ChainedRoundDescriptor {
                kind: round_code(kind),
                ordinal,
                output_count,
            };
            let outputs = coordinator
                .challenge(descriptor, message)
                .map_err(|_| UniformRelayFreeGkrError::Coin)?;
            ordinal += 1;
            Ok(outputs)
        },
    )
    .map_err(|error| format!("{error:?}"))?;
    let mask_batch_seconds = mask_batch_started.elapsed().as_secs_f64();
    let prover_seconds = prover_started.elapsed().as_secs_f64();
    if ordinal != GKR_TRANSCRIPT_ROUNDS + 1 {
        return Err("real GKR transcript round count mismatch".into());
    }

    let bundle = coordinator
        .finish_bundle()
        .map_err(|error| format!("{error:?}"))?;
    let encoded = encode_chained_public_coin_bundle(&bundle)?;
    let decoded = decode_chained_public_coin_bundle(&encoded)?;
    let replay_started = Instant::now();
    let verified_rounds = verify_chained_public_coin_bundle(&decoded)?;
    let replay_seconds = replay_started.elapsed().as_secs_f64();
    let algebra_started = Instant::now();
    verify_masked_uniform_zero_trace(&proof, &batch).map_err(|error| format!("{error:?}"))?;
    let algebra_seconds = algebra_started.elapsed().as_secs_f64();
    let total_seconds = total_started.elapsed().as_secs_f64();

    println!("status=verified");
    println!("evidence_class=real_uniform_zero_trace_native_masked_gkr");
    println!("authenticated_chain_heads=true");
    println!("dual_pq_suites=true");
    println!("message_before_challenge=true");
    println!("independent_bundle_replay=true");
    println!("independent_gkr_algebra_verification=true");
    println!("keccak_rounds=24");
    println!("gkr_layers=168");
    println!("gkr_masked_rounds={ordinal}");
    println!("verified_rounds={}", verified_rounds.len());
    println!("final_input_claims={}", proof.raw_input_claims.len());
    println!("mask_constraints={}", batch.constraints.len());
    println!("mask_coefficients={}", mask_coefficients.len());
    println!("uniform_group_materializations=0");
    println!("bundle_mb={:.6}", encoded.len() as f64 / 1_000_000.0);
    println!("spawn_and_head_auth_seconds={spawn_seconds:.6}");
    println!("real_gkr_prover_seconds={prover_seconds:.6}");
    println!("real_gkr_layer_prover_seconds={layer_prover_seconds:.6}");
    println!("real_gkr_mask_batch_seconds={mask_batch_seconds:.6}");
    println!("independent_bundle_replay_seconds={replay_seconds:.6}");
    println!("independent_gkr_verify_seconds={algebra_seconds:.6}");
    println!("total_seconds={total_seconds:.6}");
    println!(
        "final_transcript_root={}",
        hex(&bundle.claimed_final_transcript_root)
    );
    println!("native_gkr_masking_attached=true");
    println!("aggregate_mask_opening_independently_verified=true");
    println!("pcs_attached=false");
    println!("complete_proof_qualification=false");
    Ok(())
}
