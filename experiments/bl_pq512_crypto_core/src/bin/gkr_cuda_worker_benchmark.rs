use std::{ffi::OsString, path::PathBuf, time::Duration, time::Instant};

use bl_pq512_crypto_core::{
    Fp16,
    gkr_sumcheck::{
        LayerOutputClaim, multilinear_equality_table,
        repeated_pack_sparse_layer_claims_gpu_fixture, repeated_pack_sparse_layer_gpu_fixture,
        repeated_pack_terminal_gate_claim,
    },
    gkr_worker::{
        BoundedGkrWorker, GkrCompactClaimWeights, GkrCompactPointClaim,
        GkrCompactPointWorkerRequest, GkrCompactWorkerRequest, GkrPackedWorkerRequest,
        GkrWorkerRequest, GkrWorkerSession, verify_pinned_gkr_cuda_bundle,
    },
    keccak_gkr_wiring::{build_keccak_gkr_round, evaluate_keccak_gkr_layer},
    packed_boolean_sumcheck::{
        PACK_BITS, PackedBooleanTable, evaluate_packed_lagrange_values,
        packed_lagrange_node_weights,
    },
};
use sha3::{Digest, Sha3_512};

fn fp16(seed: u32) -> Fp16 {
    Fp16::from_coefficients(core::array::from_fn(|coefficient| {
        (u64::from(seed) + 65_537 * coefficient as u64).rem_euclid(2_147_483_647) as u32
    }))
    .expect("benchmark coordinates are canonical")
}

fn append_fp16(output: &mut Vec<u8>, value: Fp16) {
    for coordinate in value.coefficients() {
        output.extend_from_slice(&coordinate.to_le_bytes());
    }
}

fn proof_digest(rounds: &[[Fp16; 3]], left: Fp16, right: Fp16) -> [u8; 64] {
    let mut encoded = Vec::with_capacity(rounds.len() * 192 + 128);
    for round in rounds {
        for coefficient in round {
            append_fp16(&mut encoded, *coefficient);
        }
    }
    append_fp16(&mut encoded, left);
    append_fp16(&mut encoded, right);
    Sha3_512::digest(encoded).into()
}

fn run() -> Result<(), String> {
    let mut arguments = std::env::args_os().skip(1);
    let python = PathBuf::from(
        arguments
            .next()
            .ok_or_else(|| "python_path_missing".to_string())?,
    );
    let worker = arguments
        .next()
        .ok_or_else(|| "worker_path_missing".to_string())?;
    let runtime = arguments
        .next()
        .ok_or_else(|| "nvrtc_runtime_path_missing".to_string())?;
    let permutations = arguments
        .next()
        .ok_or_else(|| "permutation_count_missing".to_string())?
        .to_string_lossy()
        .parse::<usize>()
        .map_err(|_| "permutation_count_invalid".to_string())?;
    let session_count = arguments
        .next()
        .map(|value| {
            value
                .to_string_lossy()
                .parse::<usize>()
                .map_err(|_| "session_count_invalid".to_string())
        })
        .transpose()?
        .unwrap_or(1);
    let ordinal = arguments
        .next()
        .map(|value| {
            value
                .to_string_lossy()
                .parse::<usize>()
                .map_err(|_| "layer_ordinal_invalid".to_string())
        })
        .transpose()?
        .unwrap_or(5);
    let mode = arguments
        .next()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "expanded".to_string());
    if !matches!(permutations, 782 | 894)
        || session_count == 0
        || session_count > 216
        || ordinal >= 9
        || !matches!(
            mode.as_str(),
            "expanded" | "packed" | "compact" | "compact2" | "libra" | "libra6"
        )
        || arguments.next().is_some()
    {
        return Err(
            "usage: <python> <worker.py> <nvrtc-bin> <782|894> [sessions] [layer] [expanded|packed|compact|compact2|libra|libra6]"
                .to_string(),
        );
    }

    let group_count = 128;
    let layer =
        build_keccak_gkr_round(ordinal).map_err(|error| error.to_string())?[ordinal].clone();
    let groups = (0..group_count)
        .map(|group| {
            core::array::from_fn(|shard| {
                let active = group * PACK_BITS + shard < permutations;
                (0..layer.input_width)
                    .map(|wire| {
                        active
                            && ((wire as u64 + 29 * shard as u64 + 101 * group as u64 + 1)
                                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                                >> 63)
                                == 1
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();
    let group_point = (0..group_count.trailing_zeros() as usize)
        .map(|index| fp16(607 + 6 * index as u32))
        .collect::<Vec<_>>();
    let output_point = (0..layer.padded_width.trailing_zeros() as usize)
        .map(|index| fp16(617 + 3 * index as u32))
        .collect::<Vec<_>>();
    let input_width = layer.input_width * group_count;
    let challenges = (0..2 * input_width.trailing_zeros() as usize)
        .map(|index| fp16(821 + 5 * index as u32))
        .collect::<Vec<_>>();
    let second_group_point = (0..group_count.trailing_zeros() as usize)
        .map(|index| fp16(701 + 7 * index as u32))
        .collect::<Vec<_>>();
    let second_output_point = (0..layer.padded_width.trailing_zeros() as usize)
        .map(|index| fp16(733 + 11 * index as u32))
        .collect::<Vec<_>>();
    let two_claims = [
        LayerOutputClaim {
            point: output_point.iter().chain(&group_point).copied().collect(),
            value: Fp16::ZERO,
            coefficient: fp16(907),
        },
        LayerOutputClaim {
            point: second_output_point
                .iter()
                .chain(&second_group_point)
                .copied()
                .collect(),
            value: Fp16::ZERO,
            coefficient: fp16(919),
        },
    ];
    let fixture = if mode == "compact2" {
        repeated_pack_sparse_layer_claims_gpu_fixture(
            &layer,
            &groups,
            &two_claims,
            fp16(811),
            &challenges,
        )
    } else {
        repeated_pack_sparse_layer_gpu_fixture(
            &layer,
            &groups,
            &group_point,
            &output_point,
            fp16(811),
            &challenges,
        )
    }
    .map_err(|error| format!("{error:?}"))?;
    let first = fixture
        .expected_rounds
        .first()
        .ok_or_else(|| "fixture_rounds_empty".to_string())?;
    let initial_claim = first[0] + first[0] + first[1] + first[2];
    let masks = vec![[Fp16::ZERO; 2]; challenges.len()];
    let request = GkrWorkerRequest {
        input: &fixture.input,
        terms: &fixture.terms,
    };
    let packed_instances = group_count * PACK_BITS;
    let packed_words_per_plane = packed_instances.div_ceil(64);
    let mut packed_input = vec![0_u64; layer.input_width * packed_words_per_plane];
    for (group, inputs) in groups.iter().enumerate() {
        for (shard, input) in inputs.iter().enumerate() {
            let instance = group * PACK_BITS + shard;
            for (wire, value) in input.iter().copied().enumerate() {
                if value {
                    packed_input[wire * packed_words_per_plane + instance / 64] |=
                        1_u64 << (instance % 64);
                }
            }
        }
    }
    let interpolation_weights =
        packed_lagrange_node_weights(fp16(811)).map_err(|error| format!("{error:?}"))?;
    let packed_request = GkrPackedWorkerRequest {
        packed_input: &packed_input,
        instances: packed_instances,
        input_width: layer.input_width,
        interpolation_weights: &interpolation_weights,
        terms: &fixture.terms,
    };
    let wire_weights =
        multilinear_equality_table(&output_point).map_err(|error| format!("{error:?}"))?;
    let group_weights =
        multilinear_equality_table(&group_point).map_err(|error| format!("{error:?}"))?;
    let second_wire_weights =
        multilinear_equality_table(&second_output_point).map_err(|error| format!("{error:?}"))?;
    let second_group_weights =
        multilinear_equality_table(&second_group_point).map_err(|error| format!("{error:?}"))?;
    let base_terms = fixture
        .terms
        .get(..layer.raw_width)
        .ok_or_else(|| "base_terms_missing".to_string())?;
    let base_left = base_terms.iter().map(|term| term.left).collect::<Vec<_>>();
    let base_right = base_terms.iter().map(|term| term.right).collect::<Vec<_>>();
    let base_formula = base_terms
        .iter()
        .map(|term| term.formula)
        .collect::<Vec<_>>();
    let compact_claims = [GkrCompactClaimWeights {
        coefficient: Fp16::ONE,
        wire: &wire_weights[..layer.raw_width],
        group: &group_weights,
    }];
    let compact_two_claims = [
        GkrCompactClaimWeights {
            coefficient: two_claims[0].coefficient,
            wire: &wire_weights[..layer.raw_width],
            group: &group_weights,
        },
        GkrCompactClaimWeights {
            coefficient: two_claims[1].coefficient,
            wire: &second_wire_weights[..layer.raw_width],
            group: &second_group_weights,
        },
    ];
    let compact_request = GkrCompactWorkerRequest {
        packed_input: &packed_input,
        instances: packed_instances,
        input_width: layer.input_width,
        interpolation_weights: &interpolation_weights,
        raw_width: layer.raw_width,
        base_left: &base_left,
        base_right: &base_right,
        base_formula: &base_formula,
        claims: &compact_claims,
    };
    let compact_two_request = GkrCompactWorkerRequest {
        packed_input: &packed_input,
        instances: packed_instances,
        input_width: layer.input_width,
        interpolation_weights: &interpolation_weights,
        raw_width: layer.raw_width,
        base_left: &base_left,
        base_right: &base_right,
        base_formula: &base_formula,
        claims: &compact_two_claims,
    };
    verify_pinned_gkr_cuda_bundle(PathBuf::from(&worker).as_path())
        .map_err(|error| format!("gkr_cuda_bundle:{error:?}"))?;
    let worker_arguments = [OsString::from("-I"), worker, runtime]
        .into_iter()
        .collect::<Vec<_>>();
    let session = GkrWorkerSession {
        request: GkrWorkerRequest {
            input: request.input,
            terms: request.terms,
        },
        initial_claim,
        challenges: &challenges,
        masks: &masks,
    };
    let started = Instant::now();
    let mut worker_client = BoundedGkrWorker::spawn(
        &python,
        &worker_arguments,
        session_count,
        Duration::from_secs(120),
    )
    .map_err(|error| format!("{error:?}"))?;
    if matches!(mode.as_str(), "libra" | "libra6") {
        if session_count != 1 {
            return Err("libra_mode_requires_one_session".to_string());
        }
        let shard_query = fp16(809);
        let bridge_challenge = fp16(811);
        let mut output_values = Vec::with_capacity(group_count * layer.padded_width);
        for inputs in &groups {
            let shard_outputs = inputs
                .iter()
                .map(|input| evaluate_keccak_gkr_layer(&layer, input))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?;
            for values in (0..layer.padded_width).map(|wire| {
                core::array::from_fn(|shard| {
                    if shard_outputs[shard][wire] {
                        Fp16::ONE
                    } else {
                        Fp16::ZERO
                    }
                })
            }) {
                output_values.push(
                    evaluate_packed_lagrange_values(&values, shard_query)
                        .map_err(|error| format!("{error:?}"))?,
                );
            }
        }
        let claim_point = output_point
            .iter()
            .chain(&group_point)
            .copied()
            .collect::<Vec<_>>();
        let output_weights =
            multilinear_equality_table(&claim_point).map_err(|error| format!("{error:?}"))?;
        let raw_output_claim = output_values
            .iter()
            .copied()
            .zip(output_weights)
            .fold(Fp16::ZERO, |sum, (value, weight)| sum + value * weight);
        let claims = [LayerOutputClaim {
            point: claim_point,
            value: raw_output_claim,
            coefficient: Fp16::ONE,
        }];
        let point_claims = [GkrCompactPointClaim {
            coefficient: claims[0].coefficient,
            point: &claims[0].point,
        }];
        let point_request = GkrCompactPointWorkerRequest {
            packed_input: &packed_input,
            instances: packed_instances,
            input_width: layer.input_width,
            raw_width: layer.raw_width,
            claim_wire_variables: output_point.len(),
            base_left: &base_left,
            base_right: &base_right,
            base_formula: &base_formula,
            claims: &point_claims,
        };
        let table = PackedBooleanTable::build().map_err(|error| error.to_string())?;
        let terminal_delta = fp16(12_345);
        let left_rounds = challenges.len() / 2;
        let mut bridge_provider = |_polynomial| -> Result<
            Fp16,
            bl_pq512_crypto_core::gkr_worker::GkrWorkerError,
        > { Ok(bridge_challenge) };
        let mut round_provider = |round: usize, _raw, _sensitivity| {
            let challenge = challenges
                .get(round)
                .copied()
                .ok_or(bl_pq512_crypto_core::gkr_worker::GkrWorkerError::ChallengeProvider)?;
            Ok((
                challenge,
                if round + 1 == left_rounds {
                    Some(terminal_delta)
                } else {
                    None
                },
            ))
        };
        let started = Instant::now();
        let (output, polynomial, report) = if mode == "libra6" {
            worker_client
                .run_compact_point_libra_session_with_public_coin_providers(
                    &point_request,
                    &table,
                    raw_output_claim,
                    shard_query,
                    &mut bridge_provider,
                    &mut round_provider,
                    Duration::from_secs(120),
                )
                .map_err(|error| format!("{error:?}"))?
        } else {
            worker_client
                .run_compact_libra_session_with_public_coin_providers(
                    &compact_request,
                    &table,
                    raw_output_claim,
                    shard_query,
                    &mut bridge_provider,
                    &mut round_provider,
                    Duration::from_secs(120),
                )
                .map_err(|error| format!("{error:?}"))?
        };
        worker_client
            .finish(Duration::from_secs(120))
            .map_err(|error| format!("{error:?}"))?;
        if output.raw_rounds[..left_rounds] != fixture.expected_rounds[..left_rounds] {
            return Err("libra_left_round_mismatch".to_string());
        }
        if output.terminal_left != fixture.terminal_left + terminal_delta {
            return Err("libra_terminal_left_delta_mismatch".to_string());
        }
        if output.terminal_right != fixture.terminal_right {
            return Err("libra_terminal_right_mismatch".to_string());
        }
        let right_point = &challenges[left_rounds..];
        let expected_terminal = repeated_pack_terminal_gate_claim(
            &layer,
            group_count,
            &claims,
            &challenges[..left_rounds],
            right_point,
            output.terminal_left,
            output.terminal_right,
        )
        .map_err(|error| format!("{error:?}"))?;
        let mut actual_terminal = None;
        for (round_index, (round, challenge)) in output.raw_rounds[left_rounds..]
            .iter()
            .copied()
            .zip(right_point.iter().copied())
            .enumerate()
        {
            if let Some(claim) = actual_terminal
                && round[0] + round[0] + round[1] + round[2] != claim
            {
                return Err(format!(
                    "libra_right_round_recurrence_mismatch:{round_index}"
                ));
            }
            actual_terminal = Some(round[0] + challenge * (round[1] + challenge * round[2]));
        }
        let actual_terminal =
            actual_terminal.ok_or_else(|| "libra_right_rounds_empty".to_string())?;
        if actual_terminal != expected_terminal {
            return Err("libra_right_terminal_claim_mismatch".to_string());
        }
        println!("permutations={permutations}");
        println!("layer_ordinal={ordinal}");
        println!("rounds={}", output.raw_rounds.len());
        println!("worker_ns={}", started.elapsed().as_nanos());
        println!("packed_gates={}", report.gates);
        println!("packed_polynomial_coefficients={}", polynomial.len());
        println!("libra_terminal_delta_nonzero=true");
        println!("libra_left_rounds_equal=true");
        println!("libra_terminal_left_delta_equal=true");
        println!("libra_terminal_right_equal=true");
        println!("libra_right_terminal_claim_equal=true");
        return Ok(());
    }
    let mut proof = None;
    for _ in 0..session_count {
        proof = Some(if mode == "compact2" {
            worker_client
                .run_compact_session(
                    &compact_two_request,
                    initial_claim,
                    &challenges,
                    &masks,
                    Duration::from_secs(30),
                )
                .map_err(|error| format!("{error:?}"))?
        } else if mode == "compact" {
            worker_client
                .run_compact_session(
                    &compact_request,
                    initial_claim,
                    &challenges,
                    &masks,
                    Duration::from_secs(30),
                )
                .map_err(|error| format!("{error:?}"))?
        } else if mode == "packed" {
            worker_client
                .run_packed_session(
                    &packed_request,
                    initial_claim,
                    &challenges,
                    &masks,
                    Duration::from_secs(30),
                )
                .map_err(|error| format!("{error:?}"))?
        } else {
            worker_client
                .run_session(&session, Duration::from_secs(30))
                .map_err(|error| format!("{error:?}"))?
        });
    }
    worker_client
        .finish(Duration::from_secs(30))
        .map_err(|error| format!("{error:?}"))?;
    let elapsed = started.elapsed();
    let proof = proof.ok_or_else(|| "worker_proof_missing".to_string())?;
    if proof.rounds != fixture.expected_rounds
        || proof.terminal_left != fixture.terminal_left
        || proof.terminal_right != fixture.terminal_right
        || proof.terminal_correction != Fp16::ZERO
    {
        return Err("cpu_gpu_proof_mismatch".to_string());
    }
    let digest = proof_digest(&proof.rounds, proof.terminal_left, proof.terminal_right);
    println!("permutations={permutations}");
    println!("terms={}", fixture.terms.len());
    println!("layer_ordinal={ordinal}");
    println!("rounds={}", proof.rounds.len());
    println!("sessions={session_count}");
    println!("input_mode={mode}");
    println!("worker_ns={}", elapsed.as_nanos());
    println!(
        "worker_ns_per_session={}",
        elapsed.as_nanos() / session_count as u128
    );
    println!("cpu_gpu_proof_equal=true");
    println!("terminal_correction_zero=true");
    println!("proof_sha3_512={}", hex(&digest));
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn main() {
    if let Err(error) = run() {
        eprintln!("GKR CUDA worker benchmark failed: {error}");
        std::process::exit(1);
    }
}
