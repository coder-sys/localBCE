use std::{
    cell::RefCell,
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::Instant,
};

use bl_pq512_crypto_core::{
    chained_public_coin::{
        ChainedRoundDescriptor, decode_chained_public_coin_bundle,
        encode_chained_public_coin_bundle, verify_chained_public_coin_bundle,
    },
    chained_public_coin_client::ChainedPublicCoinCoordinator,
    field::Fp16,
    fp16_relay_free_gkr_schedule::{
        GKR_LAYERS, GKR_TRANSCRIPT_ROUNDS, STATE_RELATION_ROUNDS, SelectedGkrRoundKind,
        selected_state_composed_mask_layout,
    },
    fp16_relay_free_gkr_uniform::{
        UniformGkrMaskConstraint, UniformRelayFreeClaim, UniformRelayFreeGkrError,
        aggregate_gkr_mask_constraints, complete_uniform_gkr_mask_batch, gkr_mask_batch_message,
        prove_masked_nonuniform_trace, prove_masked_uniform_zero_trace,
        verify_masked_nonuniform_trace, verify_masked_uniform_zero_trace,
    },
    fp16_zk_rs_gkr_binding::GKR_CLAIM_COUNT,
    hash_bus_b16_boundary::HashBusB16BoundaryFile,
    hash_bus_b16_gkr_plan::HashBusB16GkrPlan,
    hash_bus_b16_gkr_worker::HashBusB16GkrWorker,
    state_relation_gkr::{
        StateRelationGkrError, StateRelationRoundKind, masked_state_relation_constraints_unchecked,
        masked_state_relation_h4_input_claims_unchecked,
        prove_masked_state_relation_gkr_interactive, read_state_relation_wire_source,
        state_relation_rows_from_source, verify_masked_state_relation_gkr,
    },
    state_squarefree_gkr::{
        MaskedStateSquarefreeLayerKind, MaskedStateSquarefreeRoundKind,
        StateSquarefreeCommittedLayerMask, StateSquarefreeGkrError, build_state_squarefree_witness,
        masked_state_squarefree_constraints_unchecked, prove_masked_state_squarefree_composed,
        state_squarefree_authenticated_rounds, verify_masked_state_squarefree_composed,
    },
    state_squarefree_pcs::{
        MASKED_STATE_SQUAREFREE_COEFFICIENT_CLAIMS, STATE_SQUAREFREE_COEFFICIENT_BLOCK,
        STATE_SQUAREFREE_COEFFICIENT_VARIABLES, STATE_SQUAREFREE_H4_CLAIMS,
        masked_state_squarefree_coefficient_claims_unchecked,
        masked_state_squarefree_h4_input_claims_unchecked,
        masked_state_squarefree_public_pcs_coefficient_claims_unchecked,
    },
    wave1a_global_schedule::Profile,
};
use sha3::{Digest, Sha3_512};

const INPUT_MAGIC: &[u8; 8] = b"BLPCCN01";
const READY_MAGIC: &[u8; 8] = b"BLPCCRD1";
const ROUND_MAGIC: &[u8; 8] = b"BLPCCRQ1";
const RESPONSE_MAGIC: &[u8; 8] = b"BLPCCRS1";
const FINISH_MAGIC: &[u8; 8] = b"BLPCCFN1";
const GKR_READY_MAGIC: &[u8; 8] = b"BLPCCG01";
const SQUAREFREE_READY_MAGIC: &[u8; 8] = b"BLPCCB01";
const SQUAREFREE_BIND_MAGIC: &[u8; 8] = b"BLPCCB02";
const SQUAREFREE_WITNESS_MAGIC: &[u8; 8] = b"BLPCCW01";
const SQUAREFREE_COMMIT_MAGIC: &[u8; 8] = b"BLPCCC01";
const GKR_MASK_COEFFICIENTS: usize = 32_768;
const GKR_MASK_WORDS: usize = 64;
const GKR_MASK_WORD_VALUES: usize = 512;
const PCS_ROW_CHALLENGES: usize = 9;
const BASE_MASKS_PREFIX: &[u8] = b"BL/PQ512/FP16-ZK-RS/BASE-MASKS/v2";
const MAX_ROUNDS: u32 = 65_535;
const MAX_MESSAGE_LENGTH: usize = 1 << 20;
const STATE_RELATION_OUTPUT_COUNT: u16 = 19;
const STATE_RELATION_OUTPUT_KIND: u16 = 120;
const STATE_RELATION_GROUP_KIND: u16 = 121;
const STATE_RELATION_WIRE_KIND: u16 = 122;
const STATE_RELATION_TERMINAL_KIND: u16 = 123;
const STATE_RELATION_DIGEST_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/STATE-RELATION-TRANSCRIPT/v2\0";
const STATE_SQUAREFREE_TRANSCRIPT_DOMAIN: &[u8] =
    b"BL/PQ512/WAVE2/STATE-SQUAREFREE-TRANSCRIPT/v2\0";
const STATE_SQUAREFREE_CLAIMS_DIGEST_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/STATE-SQUAREFREE-CLAIMS/v2\0";
const STATE_SQUAREFREE_BETA_KIND: u16 = 130;
const STATE_SQUAREFREE_POINT_KIND: u16 = 131;
const STATE_SQUAREFREE_MASKED_GROUP_KIND: u16 = 138;
const STATE_SQUAREFREE_MASKED_LEFT_KIND: u16 = 139;
const STATE_SQUAREFREE_MASKED_RIGHT_KIND: u16 = 140;
const STATE_SQUAREFREE_MASKED_TERMINAL_KIND: u16 = 141;
const STATE_SQUAREFREE_MASKED_MIX_KIND: u16 = 142;
const STATE_COMPOSED_MASK_BATCH_KIND: u16 = 143;

struct GkrPcsContext {
    commitment: [u8; 64],
    opening: Fp16,
    claim_challenge: Fp16,
    coefficient_weights: Vec<Fp16>,
    row_challenges: Vec<Fp16>,
    squarefree_claims_payload: Vec<u8>,
    squarefree_coefficient_root: [u8; 64],
}

struct SquarefreePrelude {
    claims: Vec<UniformRelayFreeClaim>,
    coefficient_claims: Vec<bl_pq512_crypto_core::multilinear_pcs::MultilinearOpeningClaim>,
    public_coefficient_claims: Vec<bl_pq512_crypto_core::multilinear_pcs::MultilinearOpeningClaim>,
    coefficient_root: [u8; 64],
    transcript_digest: [u8; 64],
    mask_constraints: Vec<UniformGkrMaskConstraint>,
}

enum GkrPrelude {
    None,
    Uniform,
    Nonuniform {
        boundary: PathBuf,
        shard: u16,
        python: PathBuf,
        worker: PathBuf,
        eager: bool,
        state_source: Option<(PathBuf, [u8; 64])>,
    },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ERR:{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let gkr_prelude = match arguments.as_slice() {
        [] => GkrPrelude::None,
        [flag] if flag == "--gkr-prelude" => GkrPrelude::Uniform,
        [flag, boundary, shard, python, worker]
            if flag == "--gkr-prelude-nonuniform" || flag == "--gkr-prelude-nonuniform-eager" =>
        {
            GkrPrelude::Nonuniform {
                boundary: PathBuf::from(boundary),
                shard: shard
                    .to_string_lossy()
                    .parse()
                    .map_err(|_| "gkr_shard".to_string())?,
                python: PathBuf::from(python),
                worker: PathBuf::from(worker),
                eager: flag == "--gkr-prelude-nonuniform-eager",
                state_source: None,
            }
        }
        [flag, boundary, shard, python, worker, source, digest]
            if flag == "--gkr-prelude-nonuniform" || flag == "--gkr-prelude-nonuniform-eager" =>
        {
            GkrPrelude::Nonuniform {
                boundary: PathBuf::from(boundary),
                shard: shard
                    .to_string_lossy()
                    .parse()
                    .map_err(|_| "gkr_shard".to_string())?,
                python: PathBuf::from(python),
                worker: PathBuf::from(worker),
                eager: flag == "--gkr-prelude-nonuniform-eager",
                state_source: Some((
                    PathBuf::from(source),
                    parse_digest(digest.to_string_lossy().as_ref())?,
                )),
            }
        }
        _ => return Err("arguments".to_string()),
    };
    let service = std::env::current_exe()
        .map_err(|error| format!("current_exe:{error}"))?
        .parent()
        .ok_or_else(|| "executable_parent".to_string())?
        .join("chained_public_coin_service.exe");
    if !service.is_file() {
        return Err(format!("service_missing:{}", service.display()));
    }
    let mut prepared_nonuniform = match &gkr_prelude {
        GkrPrelude::Nonuniform {
            boundary,
            shard,
            python,
            worker,
            eager: true,
            ..
        } => Some(prepare_nonuniform(boundary, *shard, python, worker)?),
        _ => None,
    };
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::with_capacity(1 << 20, stdin.lock());
    let mut writer = BufWriter::with_capacity(1 << 20, stdout.lock());
    if &read_exact::<8>(&mut reader)? != INPUT_MAGIC {
        return Err("input_magic".to_string());
    }
    let session_id = read_exact::<64>(&mut reader)?;
    let attempt = u16::from_be_bytes(read_exact::<2>(&mut reader)?);
    let schedule_commitment = read_exact::<64>(&mut reader)?;
    let round_count = u32::from_be_bytes(read_exact::<4>(&mut reader)?);
    if round_count == 0 || round_count > MAX_ROUNDS {
        return Err("round_count".to_string());
    }
    let gkr_input = if !matches!(gkr_prelude, GkrPrelude::None) {
        let commitment = read_exact::<64>(&mut reader)?;
        let coefficients = (0..GKR_MASK_COEFFICIENTS)
            .map(|_| {
                Fp16::decode(&read_exact::<64>(&mut reader)?)
                    .map_err(|error| format!("gkr_mask_coefficient:{error:?}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Some((commitment, coefficients))
    } else {
        None
    };
    let spawn_started = Instant::now();
    let mut coordinator = ChainedPublicCoinCoordinator::spawn(
        &service,
        session_id,
        attempt,
        schedule_commitment,
        round_count,
    )
    .map_err(|error| format!("spawn:{error:?}"))?;
    let mut emitted = Vec::with_capacity(round_count as usize);
    let mut first_external_ordinal = 0_u32;
    let mut gkr_pcs_context = None;
    let mut gkr_verification = None;
    let mut state_relation_digest = [0_u8; 64];
    let mut state_relation_claims = [dummy_state_claim(), dummy_state_claim()];
    let mut squarefree_claims = vec![dummy_state_claim(); STATE_SQUAREFREE_H4_CLAIMS];
    let mut squarefree_coefficient_claims = Vec::new();
    let mut squarefree_public_coefficient_claims = Vec::new();
    let mut squarefree_coefficient_root = [0_u8; 64];
    if let Some((commitment, coefficients)) = gkr_input {
        let state_source = match &gkr_prelude {
            GkrPrelude::Nonuniform { state_source, .. } => state_source.as_ref(),
            _ => None,
        };
        let state_capacity_value = match (&gkr_prelude, state_source) {
            (GkrPrelude::Nonuniform { boundary, .. }, Some(_)) => state_capacity(boundary)?,
            _ => 128,
        };
        let squarefree_rounds = if state_source.is_some() {
            state_squarefree_authenticated_rounds(state_capacity_value)
                .ok_or_else(|| "squarefree_round_profile".to_string())?
        } else {
            0
        };
        let expected_round_count =
            GKR_TRANSCRIPT_ROUNDS + 1 + STATE_RELATION_ROUNDS + squarefree_rounds + 1 + 13;
        if round_count != expected_round_count {
            return Err("gkr_round_count".to_string());
        }
        let state_mask_layout = selected_state_composed_mask_layout(state_capacity_value)
            .map_err(|error| format!("state_mask_layout:{error:?}"))?;
        let (_, state_sumcheck_masks, state_layer_masks) = state_mask_layout
            .decode_prefix(&coefficients)
            .map_err(|error| format!("state_mask_decode:{error:?}"))?;
        let mut ordinal = 0_u32;
        let (mut proof, statement_binding) = match &gkr_prelude {
            GkrPrelude::Uniform => (
                prove_masked_uniform_zero_trace(
                    commitment,
                    &coefficients,
                    |kind, message, output_count| {
                        let outputs = coordinator
                            .challenge(
                                ChainedRoundDescriptor {
                                    kind: gkr_round_code(kind),
                                    ordinal,
                                    output_count,
                                },
                                message,
                            )
                            .map_err(|_| UniformRelayFreeGkrError::Coin)?;
                        ordinal += 1;
                        Ok(outputs)
                    },
                )
                .map_err(|error| format!("gkr_prove:{error:?}"))?,
                None,
            ),
            GkrPrelude::Nonuniform {
                boundary,
                shard,
                python,
                worker,
                ..
            } => {
                let (mut oracle, statement_binding) =
                    if let Some(prepared) = prepared_nonuniform.take() {
                        prepared
                    } else {
                        prepare_nonuniform(boundary, *shard, python, worker)?
                    };
                let proof = prove_masked_nonuniform_trace(
                    commitment,
                    &coefficients,
                    statement_binding,
                    &mut oracle,
                    |kind, message, output_count| {
                        let outputs = coordinator
                            .challenge(
                                ChainedRoundDescriptor {
                                    kind: gkr_round_code(kind),
                                    ordinal,
                                    output_count,
                                },
                                message,
                            )
                            .map_err(|_| UniformRelayFreeGkrError::Coin)?;
                        ordinal += 1;
                        Ok(outputs)
                    },
                )
                .map_err(|error| format!("gkr_prove:{error:?}"))?;
                oracle
                    .finish()
                    .map_err(|error| format!("gkr_worker_finish:{error:?}"))?;
                (proof, Some(statement_binding))
            }
            GkrPrelude::None => return Err("gkr_prelude".to_string()),
        };
        let batch = complete_uniform_gkr_mask_batch(
            &mut proof,
            &coefficients,
            |kind, message, output_count| {
                let outputs = coordinator
                    .challenge(
                        ChainedRoundDescriptor {
                            kind: gkr_round_code(kind),
                            ordinal,
                            output_count,
                        },
                        message,
                    )
                    .map_err(|_| UniformRelayFreeGkrError::Coin)?;
                ordinal += 1;
                Ok(outputs)
            },
        )
        .map_err(|error| format!("gkr_batch:{error:?}"))?;
        if ordinal != GKR_TRANSCRIPT_ROUNDS + 1 {
            return Err("gkr_ordinal".to_string());
        }
        emitted.extend(proof.rounds.iter().map(|round| round.outputs.clone()));
        let state_source_digest =
            state_source.map_or([0_u8; 64], |(_, source_digest)| *source_digest);
        let source = if let Some((source_path, source_digest)) = state_source {
            read_state_relation_wire_source(source_path, *source_digest)
                .map_err(|error| format!("state_relation_source:{error:?}"))?
        } else {
            vec![Fp16::ZERO; 1 << 18]
        };
        let output_message = state_relation_output_message(state_source_digest);
        let output = coordinator
            .challenge(
                ChainedRoundDescriptor {
                    kind: STATE_RELATION_OUTPUT_KIND,
                    ordinal,
                    output_count: STATE_RELATION_OUTPUT_COUNT,
                },
                &output_message,
            )
            .map_err(|error| format!("state_relation_output_coin:{error:?}"))?;
        if output.len() != usize::from(STATE_RELATION_OUTPUT_COUNT) || output[0].is_zero() {
            return Err("state_relation_output_shape".to_string());
        }
        emitted.push(output.clone());
        let shard_query = output[0];
        let output_point = output[1..18].to_vec();
        let state_relation_rho = output[18];
        if state_relation_rho.is_zero() {
            return Err("state_relation_rho".to_string());
        }
        ordinal += 1;
        let state_proof = {
            let relation_coin = RefCell::new((&mut coordinator, &mut emitted, &mut ordinal));
            prove_masked_state_relation_gkr_interactive(
                &source,
                output_point,
                &state_sumcheck_masks[GKR_LAYERS as usize],
                &state_layer_masks[GKR_LAYERS as usize],
                state_relation_rho,
                |kind, round, published| {
                    let descriptor_kind = match kind {
                        StateRelationRoundKind::Group => STATE_RELATION_GROUP_KIND,
                        StateRelationRoundKind::Wire => STATE_RELATION_WIRE_KIND,
                    };
                    let message = state_relation_round_message(
                        state_source_digest,
                        descriptor_kind,
                        round,
                        published,
                    );
                    let mut context = relation_coin.borrow_mut();
                    let current_ordinal = *context.2;
                    let outputs = context
                        .0
                        .challenge(
                            ChainedRoundDescriptor {
                                kind: descriptor_kind,
                                ordinal: current_ordinal,
                                output_count: 1,
                            },
                            &message,
                        )
                        .map_err(|_| StateRelationGkrError::Shape)?;
                    if outputs.len() != 1 {
                        return Err(StateRelationGkrError::Shape);
                    }
                    context.1.push(outputs.clone());
                    *context.2 += 1;
                    Ok(outputs[0])
                },
                |published, left, right| {
                    let mut terminal = published.to_vec();
                    terminal.extend([left, right]);
                    let message = state_relation_round_message(
                        state_source_digest,
                        STATE_RELATION_TERMINAL_KIND,
                        0,
                        &terminal,
                    );
                    let mut context = relation_coin.borrow_mut();
                    let current_ordinal = *context.2;
                    let outputs = context
                        .0
                        .challenge(
                            ChainedRoundDescriptor {
                                kind: STATE_RELATION_TERMINAL_KIND,
                                ordinal: current_ordinal,
                                output_count: 1,
                            },
                            &message,
                        )
                        .map_err(|_| StateRelationGkrError::Shape)?;
                    if outputs.len() != 1 {
                        return Err(StateRelationGkrError::Shape);
                    }
                    context.1.push(outputs.clone());
                    *context.2 += 1;
                    Ok(outputs[0])
                },
            )
            .map_err(|error| format!("state_relation_prove:{error:?}"))?
        };
        verify_masked_state_relation_gkr(&state_proof)
            .map_err(|error| format!("state_relation_verify:{error:?}"))?;
        let mut state_mask_constraints =
            masked_state_relation_constraints_unchecked(&state_proof, GKR_LAYERS as usize)
                .map_err(|error| format!("state_relation_masks:{error:?}"))?;
        if state_source.is_some() {
            let claims = masked_state_relation_h4_input_claims_unchecked(&state_proof, shard_query)
                .map_err(|error| format!("state_relation_claims:{error:?}"))?;
            state_relation_claims = claims.map(|claim| UniformRelayFreeClaim {
                shard_query: claim.shard_query,
                point: claim.point,
                value: claim.value,
                coefficient: Fp16::ONE,
            });
            state_relation_digest =
                state_relation_transcript_digest(state_source_digest, &state_proof, shard_query);
        }
        if let (GkrPrelude::Nonuniform { boundary, .. }, Some(_)) = (&gkr_prelude, state_source) {
            let squarefree = run_squarefree_prelude(
                &mut reader,
                &mut writer,
                &mut coordinator,
                &mut emitted,
                &mut ordinal,
                &source,
                state_source_digest,
                boundary,
                shard_query,
                spawn_started.elapsed().as_secs_f64(),
                &state_sumcheck_masks[GKR_LAYERS as usize + 1..],
                &state_layer_masks[GKR_LAYERS as usize + 1..],
            )?;
            state_mask_constraints.extend(squarefree.mask_constraints.clone());
            squarefree_claims = squarefree.claims;
            squarefree_coefficient_claims = squarefree.coefficient_claims;
            squarefree_public_coefficient_claims = squarefree.public_coefficient_claims;
            squarefree_coefficient_root = squarefree.coefficient_root;
            let mut hash = Sha3_512::new();
            hash.update(STATE_RELATION_DIGEST_DOMAIN);
            hash.update(state_relation_digest);
            hash.update(squarefree.transcript_digest);
            hash.update(squarefree_coefficient_root);
            state_relation_digest = hash.finalize().into();
        }
        let mut complete_mask_constraints = batch.constraints.clone();
        complete_mask_constraints.extend(state_mask_constraints);
        let complete_mask_message = gkr_mask_batch_message(&complete_mask_constraints);
        let complete_mask_output = coordinator
            .challenge(
                ChainedRoundDescriptor {
                    kind: STATE_COMPOSED_MASK_BATCH_KIND,
                    ordinal,
                    output_count: 1,
                },
                &complete_mask_message,
            )
            .map_err(|error| format!("state_mask_batch_coin:{error:?}"))?;
        if complete_mask_output.len() != 1 || complete_mask_output[0].is_zero() {
            return Err("state_mask_batch_shape".to_string());
        }
        emitted.push(complete_mask_output.clone());
        ordinal += 1;
        let complete_mask_challenge = complete_mask_output[0];
        let (complete_mask_weights, complete_mask_opening) = aggregate_gkr_mask_constraints(
            &state_mask_layout,
            &complete_mask_constraints,
            complete_mask_challenge,
        )
        .map_err(|error| format!("state_mask_batch_aggregate:{error:?}"))?;
        if bl_pq512_crypto_core::gkr_zk_mask::inner_product(&coefficients, &complete_mask_weights)
            .map_err(|error| format!("state_mask_batch_inner_product:{error:?}"))?
            != complete_mask_opening
        {
            return Err("state_mask_batch_opening".to_string());
        }
        let expected_external_ordinal =
            GKR_TRANSCRIPT_ROUNDS + 1 + STATE_RELATION_ROUNDS + squarefree_rounds + 1;
        if ordinal != expected_external_ordinal {
            return Err(format!(
                "state_relation_ordinal:{ordinal}/{expected_external_ordinal}"
            ));
        }
        let proof = Arc::new(proof);
        let batch = Arc::new(batch);
        let verification_proof = Arc::clone(&proof);
        let verification_batch = Arc::clone(&batch);
        gkr_verification = Some(thread::spawn(move || match statement_binding {
            Some(binding) => {
                verify_masked_nonuniform_trace(&verification_proof, &verification_batch, binding)
            }
            None => verify_masked_uniform_zero_trace(&verification_proof, &verification_batch),
        }));
        let squarefree_public_claims_payload = squarefree_claims_payload(
            squarefree_coefficient_root,
            state_capacity_value,
            &squarefree_public_coefficient_claims,
        )?;
        gkr_pcs_context = Some(GkrPcsContext {
            commitment,
            opening: complete_mask_opening,
            claim_challenge: complete_mask_challenge,
            coefficient_weights: complete_mask_weights.clone(),
            row_challenges: Vec::with_capacity(PCS_ROW_CHALLENGES),
            squarefree_claims_payload: squarefree_public_claims_payload.clone(),
            squarefree_coefficient_root,
        });
        first_external_ordinal = ordinal;
        writer
            .write_all(GKR_READY_MAGIC)
            .and_then(|_| writer.write_all(&spawn_started.elapsed().as_secs_f64().to_be_bytes()))
            .and_then(|_| writer.write_all(&complete_mask_opening.encode()))
            .and_then(|_| writer.write_all(&complete_mask_challenge.encode()))
            .map_err(|error| format!("gkr_ready:{error}"))?;
        for weight in &complete_mask_weights {
            writer
                .write_all(&weight.encode())
                .map_err(|error| format!("gkr_weight:{error}"))?;
        }
        write_gkr_claim(&mut writer, 0, &proof.raw_output_claim)?;
        for claim in &proof.raw_input_claims {
            write_gkr_claim(&mut writer, 1, claim)?;
        }
        for claim in &state_relation_claims {
            write_gkr_claim(&mut writer, 1, claim)?;
        }
        for claim in &squarefree_claims {
            write_gkr_claim(&mut writer, 1, claim)?;
        }
        writer
            .write_all(&state_relation_digest)
            .and_then(|_| writer.write_all(&squarefree_coefficient_root))
            .and_then(|_| {
                writer.write_all(
                    &u16::try_from(squarefree_coefficient_claims.len())
                        .map_err(|_| io::Error::other("squarefree_claim_count"))?
                        .to_be_bytes(),
                )
            })
            .and_then(|_| writer.write_all(&[0_u8; 6]))
            .map_err(|error| format!("state_relation_digest:{error}"))?;
        for claim in &squarefree_coefficient_claims {
            if claim.point.len() != STATE_SQUAREFREE_COEFFICIENT_VARIABLES {
                return Err("squarefree_coefficient_point".to_string());
            }
            writer
                .write_all(
                    &u16::try_from(claim.point.len())
                        .map_err(|_| "squarefree_coefficient_point".to_string())?
                        .to_be_bytes(),
                )
                .and_then(|_| writer.write_all(&[0_u8; 6]))
                .map_err(|error| format!("squarefree_coefficient_claim:{error}"))?;
            for value in &claim.point {
                writer
                    .write_all(&value.encode())
                    .map_err(|error| format!("squarefree_coefficient_claim:{error}"))?;
            }
            writer
                .write_all(&claim.value.encode())
                .map_err(|error| format!("squarefree_coefficient_claim:{error}"))?;
        }
        writer
            .write_all(&squarefree_public_claims_payload)
            .map_err(|error| format!("squarefree_public_claims_payload:{error}"))?;
        writer
            .flush()
            .map_err(|error| format!("gkr_flush:{error}"))?;
    } else {
        writer
            .write_all(READY_MAGIC)
            .and_then(|_| writer.write_all(&spawn_started.elapsed().as_secs_f64().to_be_bytes()))
            .and_then(|_| writer.flush())
            .map_err(|error| format!("ready:{error}"))?;
    }

    for expected_ordinal in first_external_ordinal..round_count {
        if &read_exact::<8>(&mut reader)? != ROUND_MAGIC {
            return Err(format!("round_magic:{expected_ordinal}"));
        }
        let descriptor = ChainedRoundDescriptor {
            kind: u16::from_be_bytes(read_exact::<2>(&mut reader)?),
            ordinal: u32::from_be_bytes(read_exact::<4>(&mut reader)?),
            output_count: u16::from_be_bytes(read_exact::<2>(&mut reader)?),
        };
        let message_length = usize::try_from(u32::from_be_bytes(read_exact::<4>(&mut reader)?))
            .map_err(|_| "message_length".to_string())?;
        if descriptor.ordinal != expected_ordinal
            || descriptor.output_count == 0
            || message_length == 0
            || message_length > MAX_MESSAGE_LENGTH
        {
            return Err(format!("round_shape:{expected_ordinal}"));
        }
        let mut message = vec![0_u8; message_length];
        reader
            .read_exact(&mut message)
            .map_err(|error| format!("round_message:{error}"))?;
        if let Some(context) = &gkr_pcs_context {
            validate_gkr_pcs_round(context, first_external_ordinal, descriptor, &message)?;
        }
        let challenges = coordinator
            .challenge(descriptor, &message)
            .map_err(|error| format!("round_challenge:{error:?}"))?;
        if challenges.len() != usize::from(descriptor.output_count) {
            return Err(format!("challenge_count:{expected_ordinal}"));
        }
        emitted.push(challenges.clone());
        if descriptor.kind == 799 {
            let context = gkr_pcs_context
                .as_mut()
                .ok_or_else(|| "gkr_pcs_context".to_string())?;
            context.claim_challenge = challenges[0];
        }
        if descriptor.kind == 801 {
            let context = gkr_pcs_context
                .as_mut()
                .ok_or_else(|| "gkr_pcs_context".to_string())?;
            context.row_challenges.push(challenges[0]);
        }
        writer
            .write_all(RESPONSE_MAGIC)
            .and_then(|_| writer.write_all(&descriptor.ordinal.to_be_bytes()))
            .and_then(|_| writer.write_all(&descriptor.output_count.to_be_bytes()))
            .map_err(|error| format!("round_response:{error}"))?;
        for challenge in challenges {
            writer
                .write_all(&challenge.encode())
                .map_err(|error| format!("round_response:{error}"))?;
        }
        writer
            .flush()
            .map_err(|error| format!("round_flush:{error}"))?;
    }

    if let Some(verification) = gkr_verification {
        verification
            .join()
            .map_err(|_| "gkr_verify_panicked".to_string())?
            .map_err(|error| format!("gkr_verify:{error:?}"))?;
    }
    let finish_started = Instant::now();
    let bundle = coordinator
        .finish_bundle()
        .map_err(|error| format!("finish:{error:?}"))?;
    let encoded =
        encode_chained_public_coin_bundle(&bundle).map_err(|error| format!("encode:{error:?}"))?;
    let decoded =
        decode_chained_public_coin_bundle(&encoded).map_err(|error| format!("decode:{error:?}"))?;
    let replayed =
        verify_chained_public_coin_bundle(&decoded).map_err(|error| format!("verify:{error:?}"))?;
    if replayed.len() != emitted.len()
        || replayed
            .iter()
            .zip(&emitted)
            .any(|(left, right)| left.field_elements != *right)
    {
        return Err("replay_mismatch".to_string());
    }
    let mut trailing = [0_u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(|error| format!("trailing:{error}"))?
        != 0
    {
        return Err("trailing_input".to_string());
    }
    writer
        .write_all(FINISH_MAGIC)
        .and_then(|_| {
            writer.write_all(
                &u32::try_from(encoded.len())
                    .map_err(|_| io::Error::other("bundle_length"))?
                    .to_be_bytes(),
            )
        })
        .and_then(|_| writer.write_all(&encoded))
        .and_then(|_| writer.write_all(&finish_started.elapsed().as_secs_f64().to_be_bytes()))
        .and_then(|_| writer.flush())
        .map_err(|error| format!("finish_output:{error}"))?;
    Ok(())
}

fn prepare_nonuniform(
    boundary: &Path,
    shard: u16,
    python: &Path,
    worker: &Path,
) -> Result<(HashBusB16GkrWorker, [u8; 64]), String> {
    let boundary_file = HashBusB16BoundaryFile::open(boundary)
        .map_err(|error| format!("gkr_boundary:{error:?}"))?;
    let plan_commitment = HashBusB16GkrPlan::selected()
        .and_then(|plan| plan.commitment())
        .map_err(|error| format!("gkr_plan:{error:?}"))?;
    let statement_binding = boundary_file
        .header()
        .gkr_statement_binding(shard, plan_commitment)
        .map_err(|error| format!("gkr_statement:{error:?}"))?;
    let oracle = HashBusB16GkrWorker::spawn(python, worker, boundary, shard)
        .map_err(|error| format!("gkr_worker:{error:?}"))?;
    Ok((oracle, statement_binding))
}

fn state_capacity(boundary: &Path) -> Result<usize, String> {
    let file = HashBusB16BoundaryFile::open(boundary)
        .map_err(|error| format!("squarefree_boundary:{error:?}"))?;
    match file.header().profile {
        Profile::K128Calibration => Ok(128),
        Profile::K512Calibration => Ok(512),
        Profile::K256DesignPoint => Err("squarefree_profile_k256".to_string()),
    }
}

fn masked_squarefree_round_kind(kind: MaskedStateSquarefreeRoundKind) -> u16 {
    match kind {
        MaskedStateSquarefreeRoundKind::Group => STATE_SQUAREFREE_MASKED_GROUP_KIND,
        MaskedStateSquarefreeRoundKind::LeftWire => STATE_SQUAREFREE_MASKED_LEFT_KIND,
        MaskedStateSquarefreeRoundKind::RightWire => STATE_SQUAREFREE_MASKED_RIGHT_KIND,
        MaskedStateSquarefreeRoundKind::Terminal => STATE_SQUAREFREE_MASKED_TERMINAL_KIND,
        MaskedStateSquarefreeRoundKind::ClaimMix => STATE_SQUAREFREE_MASKED_MIX_KIND,
    }
}

fn masked_squarefree_layer_ordinal(
    kind: MaskedStateSquarefreeLayerKind,
    topology: usize,
) -> Result<usize, StateSquarefreeGkrError> {
    let prefix = match kind {
        MaskedStateSquarefreeLayerKind::Identity => 0_usize,
        MaskedStateSquarefreeLayerKind::ProductTree => 1,
        MaskedStateSquarefreeLayerKind::CoefficientAdapter => 2,
        MaskedStateSquarefreeLayerKind::CoefficientTree => 3,
    };
    prefix
        .checked_shl(16)
        .and_then(|value| value.checked_add(topology))
        .ok_or(StateSquarefreeGkrError::Shape)
}

fn squarefree_message(
    source_digest: [u8; 64],
    coefficient_root: [u8; 64],
    kind: u16,
    phase: usize,
    layer: usize,
    round: usize,
    published: &[Fp16],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        STATE_SQUAREFREE_TRANSCRIPT_DOMAIN.len() + 2 * 64 + 2 + 4 * 4 + published.len() * 64,
    );
    message.extend_from_slice(STATE_SQUAREFREE_TRANSCRIPT_DOMAIN);
    message.extend_from_slice(&source_digest);
    message.extend_from_slice(&coefficient_root);
    message.extend_from_slice(&kind.to_be_bytes());
    for value in [phase, layer, round, published.len()] {
        message.extend_from_slice(
            &u32::try_from(value)
                .expect("bounded square-free transcript value")
                .to_be_bytes(),
        );
    }
    for value in published {
        message.extend_from_slice(&value.encode());
    }
    message
}

fn squarefree_claims_payload(
    root: [u8; 64],
    capacity: usize,
    claims: &[bl_pq512_crypto_core::multilinear_pcs::MultilinearOpeningClaim],
) -> Result<Vec<u8>, String> {
    if claims.is_empty() && root == [0_u8; 64] {
        let mut payload = Vec::with_capacity(76);
        payload.extend_from_slice(b"BLSQCL00");
        payload.extend_from_slice(&root);
        payload.extend_from_slice(&[0_u8; 4]);
        return Ok(payload);
    }
    if claims.len() != MASKED_STATE_SQUAREFREE_COEFFICIENT_CLAIMS
        || !root.iter().any(|byte| *byte != 0)
        || !matches!(capacity, 128 | 512)
        || claims[0].point.len() != STATE_SQUAREFREE_COEFFICIENT_VARIABLES
        || claims
            .iter()
            .any(|claim| claim.point.len() != claims[0].point.len())
    {
        return Err("squarefree_claim_payload_shape".to_string());
    }
    let mut preimage = Vec::new();
    preimage.extend_from_slice(STATE_SQUAREFREE_CLAIMS_DIGEST_DOMAIN);
    preimage.extend_from_slice(&root);
    preimage.extend_from_slice(&(capacity as u16).to_be_bytes());
    preimage.extend_from_slice(&(claims.len() as u16).to_be_bytes());
    for claim in claims {
        preimage.extend_from_slice(&(claim.point.len() as u16).to_be_bytes());
        for coordinate in &claim.point {
            preimage.extend_from_slice(&coordinate.encode());
        }
        preimage.extend_from_slice(&claim.value.encode());
    }
    let digest: [u8; 64] = Sha3_512::digest(&preimage).into();
    let mut payload = Vec::with_capacity(140);
    payload.extend_from_slice(b"BLSQCL02");
    payload.extend_from_slice(&root);
    payload.extend_from_slice(&(capacity as u16).to_be_bytes());
    payload.extend_from_slice(&(claims.len() as u16).to_be_bytes());
    payload.extend_from_slice(&digest);
    Ok(payload)
}

#[allow(clippy::too_many_arguments)]
fn run_squarefree_prelude(
    reader: &mut impl Read,
    writer: &mut impl Write,
    coordinator: &mut ChainedPublicCoinCoordinator,
    emitted: &mut Vec<Vec<Fp16>>,
    ordinal: &mut u32,
    source: &[Fp16],
    source_digest: [u8; 64],
    boundary: &Path,
    shard_query: Fp16,
    elapsed_seconds: f64,
    sumcheck_masks: &[bl_pq512_crypto_core::gkr_zk_mask::LibraVariableDegreeSumcheckMask],
    layer_masks: &[bl_pq512_crypto_core::gkr_zk_mask::LibraLayerMask],
) -> Result<SquarefreePrelude, String> {
    let capacity = state_capacity(boundary)?;
    writer
        .write_all(SQUAREFREE_READY_MAGIC)
        .and_then(|_| writer.write_all(&elapsed_seconds.to_be_bytes()))
        .and_then(|_| writer.flush())
        .map_err(|error| format!("squarefree_ready:{error}"))?;
    if &read_exact::<8>(reader)? != SQUAREFREE_BIND_MAGIC {
        return Err("squarefree_bind_magic".to_string());
    }
    let initial_root = read_exact::<64>(reader)?;
    if !initial_root.iter().any(|byte| *byte != 0) {
        return Err("squarefree_initial_root".to_string());
    }
    let mut beta_message =
        Vec::with_capacity(STATE_SQUAREFREE_TRANSCRIPT_DOMAIN.len() + 64 * 2 + 8);
    beta_message.extend_from_slice(STATE_SQUAREFREE_TRANSCRIPT_DOMAIN);
    beta_message.extend_from_slice(b"BETA\0");
    beta_message.extend_from_slice(&source_digest);
    beta_message.extend_from_slice(&initial_root);
    beta_message.extend_from_slice(&(capacity as u32).to_be_bytes());
    let beta_output = coordinator
        .challenge(
            ChainedRoundDescriptor {
                kind: STATE_SQUAREFREE_BETA_KIND,
                ordinal: *ordinal,
                output_count: 1,
            },
            &beta_message,
        )
        .map_err(|error| format!("squarefree_beta_coin:{error:?}"))?;
    if beta_output.len() != 1 || beta_output[0].is_zero() {
        return Err("squarefree_beta_shape".to_string());
    }
    emitted.push(beta_output.clone());
    *ordinal += 1;
    let beta = beta_output[0];
    let rows = state_relation_rows_from_source(source, capacity)
        .map_err(|error| format!("squarefree_rows:{error:?}"))?;
    let layout = bl_pq512_crypto_core::state_squarefree_gkr::StateSquarefreeLayout::new(capacity)
        .map_err(|error| format!("squarefree_layout:{error:?}"))?;
    let witness = build_state_squarefree_witness(&rows, layout, beta)
        .map_err(|error| format!("squarefree_witness:{error:?}"))?;
    writer
        .write_all(SQUAREFREE_WITNESS_MAGIC)
        .and_then(|_| writer.write_all(&(capacity as u16).to_be_bytes()))
        .and_then(|_| writer.write_all(&[0_u8; 6]))
        .and_then(|_| writer.write_all(&beta.encode()))
        .map_err(|error| format!("squarefree_witness_header:{error}"))?;
    for coefficients in [
        &witness.phases[0].bezout_a,
        &witness.phases[0].bezout_b,
        &witness.phases[1].bezout_a,
        &witness.phases[1].bezout_b,
    ] {
        for index in 0..STATE_SQUAREFREE_COEFFICIENT_BLOCK {
            writer
                .write_all(
                    &coefficients
                        .get(index)
                        .copied()
                        .unwrap_or(Fp16::ZERO)
                        .encode(),
                )
                .map_err(|error| format!("squarefree_witness:{error}"))?;
        }
    }
    writer
        .flush()
        .map_err(|error| format!("squarefree_witness_flush:{error}"))?;
    if &read_exact::<8>(reader)? != SQUAREFREE_COMMIT_MAGIC {
        return Err("squarefree_commit_magic".to_string());
    }
    let coefficient_root = read_exact::<64>(reader)?;
    if !coefficient_root.iter().any(|byte| *byte != 0) {
        return Err("squarefree_coefficient_root".to_string());
    }
    let mut point_message = Vec::with_capacity(STATE_SQUAREFREE_TRANSCRIPT_DOMAIN.len() + 3 * 64);
    point_message.extend_from_slice(STATE_SQUAREFREE_TRANSCRIPT_DOMAIN);
    point_message.extend_from_slice(b"POINT\0");
    point_message.extend_from_slice(&source_digest);
    point_message.extend_from_slice(&initial_root);
    point_message.extend_from_slice(&coefficient_root);
    point_message.extend_from_slice(&beta.encode());
    let point_output = coordinator
        .challenge(
            ChainedRoundDescriptor {
                kind: STATE_SQUAREFREE_POINT_KIND,
                ordinal: *ordinal,
                output_count: u16::try_from(1 + sumcheck_masks.len())
                    .map_err(|_| "squarefree_mask_count".to_string())?,
            },
            &point_message,
        )
        .map_err(|error| format!("squarefree_point_coin:{error:?}"))?;
    if point_output.len() != 1 + sumcheck_masks.len()
        || point_output.iter().any(|value| value.is_zero())
        || sumcheck_masks.len() != layer_masks.len()
    {
        return Err("squarefree_point_shape".to_string());
    }
    emitted.push(point_output.clone());
    *ordinal += 1;
    let evaluation_point = point_output[0];
    let committed_masks = sumcheck_masks
        .iter()
        .cloned()
        .zip(layer_masks.iter().cloned())
        .zip(point_output[1..].iter().copied())
        .map(
            |((sumcheck, layer), sumcheck_rho)| StateSquarefreeCommittedLayerMask {
                sumcheck,
                layer,
                sumcheck_rho,
            },
        )
        .collect::<Vec<_>>();
    let mut transcript_hash = Sha3_512::new();
    transcript_hash.update(STATE_SQUAREFREE_TRANSCRIPT_DOMAIN);
    transcript_hash.update(source_digest);
    transcript_hash.update(initial_root);
    transcript_hash.update(coefficient_root);
    transcript_hash.update(beta.encode());
    for value in &point_output {
        transcript_hash.update(value.encode());
    }
    let proof = prove_masked_state_squarefree_composed(
        &rows,
        &witness,
        evaluation_point,
        &committed_masks,
        |kind, phase, layer_kind, layer, round, published, output_count| {
            let descriptor_kind = masked_squarefree_round_kind(kind);
            let layer = masked_squarefree_layer_ordinal(layer_kind, layer)?;
            if kind == MaskedStateSquarefreeRoundKind::ClaimMix && output_count == 2 {
                let mut output = Vec::with_capacity(2);
                for coefficient in 0..2 {
                    let message = squarefree_message(
                        source_digest,
                        coefficient_root,
                        descriptor_kind,
                        phase,
                        layer,
                        round
                            .checked_add(coefficient)
                            .ok_or(StateSquarefreeGkrError::Shape)?,
                        published,
                    );
                    let challenge = coordinator
                        .challenge(
                            ChainedRoundDescriptor {
                                kind: descriptor_kind,
                                ordinal: *ordinal,
                                output_count: 1,
                            },
                            &message,
                        )
                        .map_err(|_| StateSquarefreeGkrError::Shape)?;
                    if challenge.len() != 1 {
                        return Err(StateSquarefreeGkrError::Shape);
                    }
                    transcript_hash.update(&message);
                    transcript_hash.update(challenge[0].encode());
                    emitted.push(challenge.clone());
                    *ordinal += 1;
                    output.push(challenge[0]);
                }
                Ok(output)
            } else {
                if output_count != 1 {
                    return Err(StateSquarefreeGkrError::Shape);
                }
                let message = squarefree_message(
                    source_digest,
                    coefficient_root,
                    descriptor_kind,
                    phase,
                    layer,
                    round,
                    published,
                );
                let output = coordinator
                    .challenge(
                        ChainedRoundDescriptor {
                            kind: descriptor_kind,
                            ordinal: *ordinal,
                            output_count: 1,
                        },
                        &message,
                    )
                    .map_err(|_| StateSquarefreeGkrError::Shape)?;
                if output.len() != 1 {
                    return Err(StateSquarefreeGkrError::Shape);
                }
                transcript_hash.update(&message);
                transcript_hash.update(output[0].encode());
                emitted.push(output.clone());
                *ordinal += 1;
                Ok(output)
            }
        },
    )
    .map_err(|error| format!("squarefree_prove:{error:?}"))?;
    verify_masked_state_squarefree_composed(&proof)
        .map_err(|error| format!("squarefree_verify:{error:?}"))?;
    let h4_claims = masked_state_squarefree_h4_input_claims_unchecked(source, &proof, shard_query)
        .map_err(|error| format!("squarefree_h4_claims:{error:?}"))?;
    let claims = h4_claims
        .into_iter()
        .map(|claim| UniformRelayFreeClaim {
            shard_query: claim.shard_query,
            point: claim.point,
            value: claim.value,
            coefficient: Fp16::ONE,
        })
        .collect::<Vec<_>>();
    if claims.len() != STATE_SQUAREFREE_H4_CLAIMS {
        return Err("squarefree_h4_claim_count".to_string());
    }
    let coefficient_claims = masked_state_squarefree_coefficient_claims_unchecked(&proof)
        .map_err(|error| format!("squarefree_coefficient_claims:{error:?}"))?
        .into_iter()
        .collect::<Vec<_>>();
    if coefficient_claims.len() != MASKED_STATE_SQUAREFREE_COEFFICIENT_CLAIMS {
        return Err("squarefree_coefficient_claim_count".to_string());
    }
    let public_coefficient_claims =
        masked_state_squarefree_public_pcs_coefficient_claims_unchecked(&proof)
            .map_err(|error| format!("squarefree_public_coefficient_claims:{error:?}"))?
            .into_iter()
            .collect::<Vec<_>>();
    if public_coefficient_claims.len() != MASKED_STATE_SQUAREFREE_COEFFICIENT_CLAIMS
        || public_coefficient_claims
            .iter()
            .zip(&coefficient_claims)
            .any(|(public, raw)| public.point != raw.point)
    {
        return Err("squarefree_public_coefficient_claim_shape".to_string());
    }
    let mask_constraints =
        masked_state_squarefree_constraints_unchecked(&proof, GKR_LAYERS as usize + 1)
            .map_err(|error| format!("squarefree_mask_constraints:{error:?}"))?;
    Ok(SquarefreePrelude {
        claims,
        coefficient_claims,
        public_coefficient_claims,
        coefficient_root,
        transcript_digest: transcript_hash.finalize().into(),
        mask_constraints,
    })
}

fn validate_gkr_pcs_round(
    context: &GkrPcsContext,
    first_external_ordinal: u32,
    descriptor: ChainedRoundDescriptor,
    message: &[u8],
) -> Result<(), String> {
    let relative = descriptor
        .ordinal
        .checked_sub(first_external_ordinal)
        .ok_or_else(|| "gkr_pcs_ordinal".to_string())?;
    let expected_kind = match relative {
        0 => 799,
        1 => 800,
        2..=10 => 801,
        11 => 802,
        12 => 803,
        _ => return Err("gkr_pcs_round_count".to_string()),
    };
    let expected_output_count = if relative == 0 { 6 } else { 1 };
    if descriptor.kind != expected_kind || descriptor.output_count != expected_output_count {
        return Err(format!("gkr_pcs_descriptor:{relative}"));
    }
    match relative {
        0 => {
            if message.len() != 392 + context.squarefree_claims_payload.len()
                || &message[..8] != b"BLT8GC06"
                || message[136..200] != context.commitment
                || message[200..264] != context.opening.encode()
                || message[392..] != context.squarefree_claims_payload
            {
                return Err("gkr_pcs_claim_message".to_string());
            }
        }
        1 => {
            if message.len() != 456
                || &message[..8] != b"BLT8SO06"
                || message[136..200] != context.commitment
                || message[200..264] != context.opening.encode()
            {
                return Err("gkr_pcs_initial_message".to_string());
            }
        }
        2..=10 => {
            if context.row_challenges.len() != relative as usize - 2 {
                return Err("gkr_pcs_row_challenge_order".to_string());
            }
        }
        11 => {
            let expected_length = BASE_MASKS_PREFIX.len() + 6 * 64;
            if context.row_challenges.len() != PCS_ROW_CHALLENGES
                || message.len() != expected_length
                || !message.starts_with(BASE_MASKS_PREFIX)
            {
                return Err("gkr_pcs_base_message_shape".to_string());
            }
            let roots = BASE_MASKS_PREFIX.len();
            if message[roots + 128..roots + 192] != context.commitment {
                return Err("gkr_pcs_base_gkr_root".to_string());
            }
            if message[roots + 192..roots + 256] != context.squarefree_coefficient_root {
                return Err("gkr_pcs_base_squarefree_root".to_string());
            }
            let terminal_digest = gkr_terminal_digest(context)?;
            if message[roots + 256..roots + 320] != terminal_digest {
                return Err("gkr_pcs_terminal_digest".to_string());
            }
        }
        12 => {}
        _ => unreachable!(),
    }
    Ok(())
}

fn gkr_terminal_digest(context: &GkrPcsContext) -> Result<[u8; 64], String> {
    if context.coefficient_weights.len() != GKR_MASK_COEFFICIENTS
        || context.row_challenges.len() != PCS_ROW_CHALLENGES
    {
        return Err("gkr_terminal_shape".to_string());
    }
    let mut scale = Fp16::ONE;
    for _ in 0..GKR_CLAIM_COUNT {
        scale = scale * context.claim_challenge;
    }
    let mut hash = Sha3_512::new();
    for word in 0..GKR_MASK_WORDS {
        let start = word * GKR_MASK_WORD_VALUES;
        let mut layer = context.coefficient_weights[start..start + GKR_MASK_WORD_VALUES].to_vec();
        let mut active = GKR_MASK_WORD_VALUES;
        for challenge in &context.row_challenges {
            for index in 0..active / 2 {
                let left = layer[2 * index];
                let right = layer[2 * index + 1];
                layer[index] = left + (right - left) * *challenge;
            }
            active /= 2;
        }
        hash.update((layer[0] * scale).encode());
    }
    Ok(hash.finalize().into())
}

fn parse_digest(encoded: &str) -> Result<[u8; 64], String> {
    if encoded.len() != 128 {
        return Err("state_relation_digest_length".to_string());
    }
    let bytes = (0..64)
        .map(|index| {
            u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)
                .map_err(|_| "state_relation_digest_encoding".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let digest: [u8; 64] = bytes
        .try_into()
        .map_err(|_| "state_relation_digest_shape".to_string())?;
    if !digest.iter().any(|byte| *byte != 0) {
        return Err("state_relation_digest_zero".to_string());
    }
    Ok(digest)
}

fn dummy_state_claim() -> UniformRelayFreeClaim {
    UniformRelayFreeClaim {
        shard_query: Fp16::ONE,
        point: vec![Fp16::ZERO; 24],
        value: Fp16::ZERO,
        coefficient: Fp16::ONE,
    }
}

fn state_relation_output_message(source_digest: [u8; 64]) -> Vec<u8> {
    let mut message = Vec::with_capacity(STATE_RELATION_DIGEST_DOMAIN.len() + 64 + 8);
    message.extend_from_slice(STATE_RELATION_DIGEST_DOMAIN);
    message.extend_from_slice(b"OUTPUT\0");
    message.extend_from_slice(&source_digest);
    message.extend_from_slice(&STATE_RELATION_OUTPUT_COUNT.to_be_bytes());
    message
}

fn state_relation_round_message(
    source_digest: [u8; 64],
    kind: u16,
    round: usize,
    published: &[Fp16],
) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(STATE_RELATION_DIGEST_DOMAIN.len() + 64 + 2 + 4 + published.len() * 64);
    message.extend_from_slice(STATE_RELATION_DIGEST_DOMAIN);
    message.extend_from_slice(&source_digest);
    message.extend_from_slice(&kind.to_be_bytes());
    message.extend_from_slice(
        &u32::try_from(round)
            .expect("state relation round fits u32")
            .to_be_bytes(),
    );
    for value in published {
        message.extend_from_slice(&value.encode());
    }
    message
}

fn state_relation_transcript_digest(
    source_digest: [u8; 64],
    proof: &bl_pq512_crypto_core::state_relation_gkr::MaskedStateRelationGkrProof,
    shard_query: Fp16,
) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(STATE_RELATION_DIGEST_DOMAIN);
    hash.update(source_digest);
    hash.update(shard_query.encode());
    hash.update(
        u32::try_from(proof.output_claim.point.len())
            .expect("state relation output point fits u32")
            .to_be_bytes(),
    );
    for value in &proof.output_claim.point {
        hash.update(value.encode());
    }
    hash.update(proof.output_claim.value.encode());
    hash.update(proof.output_claim.coefficient.encode());
    hash.update(proof.sumcheck_rho.encode());
    for challenge in &proof.layer.group_challenges {
        hash.update(challenge.encode());
    }
    for challenge in &proof.layer.wire_challenges {
        hash.update(challenge.encode());
    }
    for round in &proof.layer.published_rounds {
        for value in round {
            hash.update(value.encode());
        }
    }
    hash.update(proof.layer.masked_terminal_left.encode());
    hash.update(proof.layer.masked_terminal_right.encode());
    hash.update(proof.layer.w_challenge.encode());
    hash.finalize().into()
}

fn gkr_round_code(kind: SelectedGkrRoundKind) -> u16 {
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

fn write_gkr_claim(
    writer: &mut impl Write,
    boundary: u32,
    claim: &UniformRelayFreeClaim,
) -> Result<(), String> {
    if claim.point.len() != 24 {
        return Err("gkr_claim_point".to_string());
    }
    writer
        .write_all(&boundary.to_be_bytes())
        .and_then(|_| writer.write_all(&claim.coefficient.encode()))
        .and_then(|_| writer.write_all(&claim.value.encode()))
        .and_then(|_| writer.write_all(&claim.shard_query.encode()))
        .map_err(|error| format!("gkr_claim:{error}"))?;
    for coordinate in &claim.point {
        writer
            .write_all(&coordinate.encode())
            .map_err(|error| format!("gkr_claim:{error}"))?;
    }
    Ok(())
}

fn read_exact<const N: usize>(reader: &mut impl Read) -> Result<[u8; N], String> {
    let mut value = [0_u8; N];
    reader
        .read_exact(&mut value)
        .map_err(|error| format!("read:{error}"))?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bl_pq512_crypto_core::{field::M31, multilinear_pcs::MultilinearOpeningClaim};

    fn field(value: u32) -> Fp16 {
        Fp16::from_m31(M31::from_canonical(value).unwrap())
    }

    #[test]
    fn squarefree_public_payload_is_fixed_size_and_hides_claim_values() {
        let root = [0x5a_u8; 64];
        let claims = [37_u32, 41_u32].map(|value| MultilinearOpeningClaim {
            point: vec![Fp16::ZERO; STATE_SQUAREFREE_COEFFICIENT_VARIABLES],
            value: field(value),
        });
        let payload = squarefree_claims_payload(root, 128, &claims).unwrap();
        assert_eq!(payload.len(), 140);
        assert_eq!(&payload[..8], b"BLSQCL02");
        assert_eq!(&payload[8..72], &root);
        assert_eq!(&payload[72..74], &128_u16.to_be_bytes());
        assert_eq!(&payload[74..76], &2_u16.to_be_bytes());
        for claim in &claims {
            assert!(
                !payload
                    .windows(64)
                    .any(|window| window == claim.value.encode())
            );
        }

        let mut changed = claims.clone();
        changed[0].value = changed[0].value + Fp16::ONE;
        assert_ne!(
            payload,
            squarefree_claims_payload(root, 128, &changed).unwrap()
        );
    }
}
