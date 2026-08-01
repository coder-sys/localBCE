use std::{
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
    fp16_relay_free_gkr_schedule::{GKR_TRANSCRIPT_ROUNDS, SelectedGkrRoundKind},
    fp16_relay_free_gkr_uniform::{
        UniformRelayFreeClaim, UniformRelayFreeGkrError, complete_uniform_gkr_mask_batch,
        prove_masked_nonuniform_trace, prove_masked_uniform_zero_trace,
        verify_masked_nonuniform_trace, verify_masked_uniform_zero_trace,
    },
    hash_bus_b16_boundary::HashBusB16BoundaryFile,
    hash_bus_b16_gkr_plan::HashBusB16GkrPlan,
    hash_bus_b16_gkr_worker::HashBusB16GkrWorker,
};
use sha3::{Digest, Sha3_512};

const INPUT_MAGIC: &[u8; 8] = b"BLPCCN01";
const READY_MAGIC: &[u8; 8] = b"BLPCCRD1";
const ROUND_MAGIC: &[u8; 8] = b"BLPCCRQ1";
const RESPONSE_MAGIC: &[u8; 8] = b"BLPCCRS1";
const FINISH_MAGIC: &[u8; 8] = b"BLPCCFN1";
const GKR_READY_MAGIC: &[u8; 8] = b"BLPCCG01";
const GKR_MASK_COEFFICIENTS: usize = 32_768;
const GKR_MASK_WORDS: usize = 64;
const GKR_MASK_WORD_VALUES: usize = 512;
const PCS_ROW_CHALLENGES: usize = 9;
const BASE_MASKS_PREFIX: &[u8] = b"BL/PQ512/FP16-ZK-RS/BASE-MASKS/v2";
const MAX_ROUNDS: u32 = 65_535;
const MAX_MESSAGE_LENGTH: usize = 1 << 20;

struct GkrPcsContext {
    commitment: [u8; 64],
    opening: Fp16,
    claim_challenge: Fp16,
    coefficient_weights: Vec<Fp16>,
    row_challenges: Vec<Fp16>,
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
    if let Some((commitment, coefficients)) = gkr_input {
        if round_count != GKR_TRANSCRIPT_ROUNDS + 14 {
            return Err("gkr_round_count".to_string());
        }
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
        gkr_pcs_context = Some(GkrPcsContext {
            commitment,
            opening: batch.opening,
            claim_challenge: batch.challenge,
            coefficient_weights: batch.coefficient_weights.clone(),
            row_challenges: Vec::with_capacity(PCS_ROW_CHALLENGES),
        });
        emitted.extend(proof.rounds.iter().map(|round| round.outputs.clone()));
        first_external_ordinal = ordinal;
        writer
            .write_all(GKR_READY_MAGIC)
            .and_then(|_| writer.write_all(&spawn_started.elapsed().as_secs_f64().to_be_bytes()))
            .and_then(|_| writer.write_all(&batch.opening.encode()))
            .and_then(|_| writer.write_all(&batch.challenge.encode()))
            .map_err(|error| format!("gkr_ready:{error}"))?;
        for weight in &batch.coefficient_weights {
            writer
                .write_all(&weight.encode())
                .map_err(|error| format!("gkr_weight:{error}"))?;
        }
        write_gkr_claim(&mut writer, 0, &proof.raw_output_claim)?;
        for claim in &proof.raw_input_claims {
            write_gkr_claim(&mut writer, 1, claim)?;
        }
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
    if descriptor.kind != expected_kind || descriptor.output_count != 1 {
        return Err(format!("gkr_pcs_descriptor:{relative}"));
    }
    match relative {
        0 => {
            if message.len() != 456
                || &message[..8] != b"BLT8GC06"
                || message[136..200] != context.commitment
                || message[200..264] != context.opening.encode()
                || message[392..456] != context.claim_challenge.encode()
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
            let expected_length = BASE_MASKS_PREFIX.len() + 5 * 64;
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
            let terminal_digest = gkr_terminal_digest(context)?;
            if message[roots + 192..roots + 256] != terminal_digest {
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
    for _ in 0..5 {
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
