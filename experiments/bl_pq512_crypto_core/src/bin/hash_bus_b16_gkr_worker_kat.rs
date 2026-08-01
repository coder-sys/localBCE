use std::{path::PathBuf, time::Instant};

use bl_pq512_crypto_core::{
    chained_public_coin::{ChainedRoundDescriptor, verify_chained_public_coin_bundle},
    chained_public_coin_client::ChainedPublicCoinCoordinator,
    field::{Fp16, M31, M31_MODULUS},
    fp16_relay_free_gkr_schedule::{
        GKR_TRANSCRIPT_ROUNDS, SelectedGkrRoundKind, selected_gkr_mask_layout,
    },
    fp16_relay_free_gkr_uniform::{
        UniformRelayFreeGkrError, complete_uniform_gkr_mask_batch, prove_masked_nonuniform_trace,
        verify_masked_nonuniform_trace,
    },
    hash_bus_b16_boundary::HashBusB16BoundaryFile,
    hash_bus_b16_gkr_plan::HashBusB16GkrPlan,
    hash_bus_b16_gkr_worker::HashBusB16GkrWorker,
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let boundary = PathBuf::from(args.next().ok_or("missing B16 boundary path")?);
    let python = PathBuf::from(args.next().unwrap_or_else(|| "python".into()));
    let worker = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("cuda/cuda_hash_bus_b16_gkr_worker.py"));
    let shard = args
        .next()
        .map(|value| value.to_string_lossy().parse::<u16>())
        .transpose()?
        .unwrap_or(0);
    if args.next().is_some() {
        return Err("usage: hash_bus_b16_gkr_worker_kat BOUNDARY [PYTHON] [WORKER] [SHARD]".into());
    }

    let service = std::env::current_exe()?
        .parent()
        .ok_or("control executable parent")?
        .join("chained_public_coin_service.exe");
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
    mask_hash.update(b"BL/PQ512/WAVE2/NONUNIFORM-REAL-MASKED-GKR/KAT-MASK/v1\0");
    for coefficient in &mask_coefficients {
        mask_hash.update(coefficient.encode());
    }
    let mask_commitment: [u8; 64] = mask_hash.finalize().into();
    let session_id: [u8; 64] =
        Sha3_512::digest(b"BL/PQ512/WAVE2/NONUNIFORM-REAL-GKR/KAT-SESSION/v1").into();
    let schedule: [u8; 64] =
        Sha3_512::digest(b"BL/PQ512/WAVE2/NONUNIFORM-REAL-GKR/KAT-SCHEDULE/v1").into();

    let total_started = Instant::now();
    let boundary_header =
        HashBusB16BoundaryFile::open(&boundary).map_err(|error| format!("{error:?}"))?;
    let plan_commitment = HashBusB16GkrPlan::selected()
        .and_then(|plan| plan.commitment())
        .map_err(|error| format!("{error:?}"))?;
    let statement_binding = boundary_header
        .header()
        .gkr_statement_binding(shard, plan_commitment)
        .map_err(|error| format!("{error:?}"))?;
    let mut oracle = HashBusB16GkrWorker::spawn(&python, &worker, &boundary, shard)
        .map_err(|error| format!("{error:?}"))?;
    let worker_ready_seconds = total_started.elapsed().as_secs_f64();
    let mut coordinator = ChainedPublicCoinCoordinator::spawn(
        &service,
        session_id,
        0,
        schedule,
        GKR_TRANSCRIPT_ROUNDS + 1,
    )
    .map_err(|error| format!("{error:?}"))?;
    let mut ordinal = 0_u32;
    let mut public_coin_seconds = 0.0_f64;
    let prover_started = Instant::now();
    let proof_result = prove_masked_nonuniform_trace(
        mask_commitment,
        &mask_coefficients,
        statement_binding,
        &mut oracle,
        |kind, message, output_count| {
            let coin_started = Instant::now();
            let result = coordinator.challenge(
                ChainedRoundDescriptor {
                    kind: round_code(kind),
                    ordinal,
                    output_count,
                },
                message,
            );
            public_coin_seconds += coin_started.elapsed().as_secs_f64();
            let outputs = result.map_err(|_| UniformRelayFreeGkrError::Coin)?;
            ordinal += 1;
            Ok(outputs)
        },
    );
    let mut proof = match proof_result {
        Ok(proof) => proof,
        Err(error) => {
            let (layer, completed_layers, group_requests, group_round) = oracle.progress();
            eprintln!("prove_error={error:?}");
            eprintln!("accepted_coin_rounds={ordinal}");
            eprintln!("current_layer={layer:?}");
            eprintln!("completed_layers={completed_layers}");
            eprintln!("requested_group_rounds_in_layer={group_requests}");
            eprintln!("accepted_group_rounds_in_layer={group_round}");
            return Err(format!("{error:?}").into());
        }
    };
    let layer_prover_seconds = prover_started.elapsed().as_secs_f64();
    let batch = complete_uniform_gkr_mask_batch(
        &mut proof,
        &mask_coefficients,
        |kind, message, output_count| {
            let coin_started = Instant::now();
            let result = coordinator.challenge(
                ChainedRoundDescriptor {
                    kind: round_code(kind),
                    ordinal,
                    output_count,
                },
                message,
            );
            public_coin_seconds += coin_started.elapsed().as_secs_f64();
            let outputs = result.map_err(|_| UniformRelayFreeGkrError::Coin)?;
            ordinal += 1;
            Ok(outputs)
        },
    )
    .map_err(|error| format!("{error:?}"))?;
    let prover_seconds = prover_started.elapsed().as_secs_f64();
    if ordinal != GKR_TRANSCRIPT_ROUNDS + 1 {
        return Err("GKR transcript round count mismatch".into());
    }
    oracle.finish().map_err(|error| format!("{error:?}"))?;
    let bundle = coordinator
        .finish_bundle()
        .map_err(|error| format!("{error:?}"))?;

    let verify_started = Instant::now();
    let verified_rounds = verify_chained_public_coin_bundle(&bundle)?;
    verify_masked_nonuniform_trace(&proof, &batch, statement_binding)
        .map_err(|error| format!("{error:?}"))?;
    let mut forged_statement = statement_binding;
    forged_statement[0] ^= 1;
    if verify_masked_nonuniform_trace(&proof, &batch, forged_statement).is_ok() {
        return Err("forged semantic statement binding accepted".into());
    }
    let independent_verify_seconds = verify_started.elapsed().as_secs_f64();

    println!("status=verified");
    println!("evidence_class=real_nonuniform_b16_gkr_worker_kat");
    println!("boundary={}", boundary.display());
    println!("shard={shard}");
    println!("keccak_rounds=24");
    println!("gkr_layers={}", proof.layers.len());
    println!("authenticated_rounds={}", verified_rounds.len());
    println!("raw_input_claims={}", proof.raw_input_claims.len());
    println!("mask_constraints={}", batch.constraints.len());
    println!("semantic_statement_bound=true");
    println!("semantic_statement_mutation_rejected=true");
    println!("worker_ready_seconds={worker_ready_seconds:.6}");
    println!("real_gkr_layer_prover_seconds={layer_prover_seconds:.6}");
    println!("real_gkr_prover_seconds={prover_seconds:.6}");
    println!("public_coin_seconds={public_coin_seconds:.6}");
    println!("independent_verify_seconds={independent_verify_seconds:.6}");
    println!("total_seconds={:.6}", total_started.elapsed().as_secs_f64());
    println!("pcs_attached=false");
    println!("complete_proof_qualification=false");
    Ok(())
}
