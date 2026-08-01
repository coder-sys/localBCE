use std::{path::PathBuf, time::Duration, time::Instant};

use bl_pq512_crypto_core::{
    Fp16,
    gkr_sumcheck::{
        MaskedGkrRoundState, SparseLayerGpuFixture, multilinear_equality_table,
        repeated_pack_sparse_layer_gpu_fixture,
    },
    gkr_worker::{BoundedGkrWorker, GkrCompactClaimWeights, GkrCompactWorkerRequest},
    keccak_gkr_wiring::build_keccak_gkr_round,
    packed_boolean_sumcheck::{PACK_BITS, packed_lagrange_node_weights},
};
use sha3::{Digest, Sha3_512};

struct ChainCase {
    input_width: usize,
    raw_width: usize,
    packed_input: Vec<u64>,
    interpolation_weights: [Fp16; 8],
    wire_weights: Vec<Fp16>,
    group_weights: Vec<Fp16>,
    base_left: Vec<u32>,
    base_right: Vec<u32>,
    base_formula: Vec<u8>,
    fixture: SparseLayerGpuFixture,
    initial_claim: Fp16,
    masks: Vec<[Fp16; 2]>,
    expected_masked_rounds: Vec<[Fp16; 3]>,
    expected_terminal_correction: Fp16,
}

fn fp16(seed: u32) -> Fp16 {
    Fp16::from_coefficients(core::array::from_fn(|coefficient| {
        (u64::from(seed) + 65_537 * coefficient as u64).rem_euclid(2_147_483_647) as u32
    }))
    .expect("canonical benchmark coordinate")
}

fn build_case(permutations: usize, ordinal: usize) -> Result<ChainCase, String> {
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
    let input_count = layer.input_width * group_count;
    let challenges = (0..2 * input_count.trailing_zeros() as usize)
        .map(|index| fp16(821 + 5 * index as u32))
        .collect::<Vec<_>>();
    let fixture = repeated_pack_sparse_layer_gpu_fixture(
        &layer,
        &groups,
        &group_point,
        &output_point,
        fp16(811),
        &challenges,
    )
    .map_err(|error| format!("{error:?}"))?;
    let first = fixture
        .expected_rounds
        .first()
        .ok_or_else(|| "fixture_rounds_empty".to_string())?;
    let initial_claim = first[0] + first[0] + first[1] + first[2];
    let packed_instances = group_count * PACK_BITS;
    let words = packed_instances.div_ceil(64);
    let mut packed_input = vec![0_u64; layer.input_width * words];
    for (group, inputs) in groups.iter().enumerate() {
        for (shard, input) in inputs.iter().enumerate() {
            let instance = group * PACK_BITS + shard;
            for (wire, value) in input.iter().copied().enumerate() {
                if value {
                    packed_input[wire * words + instance / 64] |= 1_u64 << (instance % 64);
                }
            }
        }
    }
    let base_terms = fixture
        .terms
        .get(..layer.raw_width)
        .ok_or_else(|| "base_terms_missing".to_string())?;
    let masks = (0..challenges.len())
        .map(|round| {
            [
                fp16(1_301 + 2 * round as u32),
                fp16(1_302 + 2 * round as u32),
            ]
        })
        .collect::<Vec<_>>();
    let mut masked_state = MaskedGkrRoundState::new(initial_claim, fixture.expected_rounds.len())
        .map_err(|error| format!("{error:?}"))?;
    for ((round, challenge), mask) in fixture
        .expected_rounds
        .iter()
        .copied()
        .zip(challenges.iter().copied())
        .zip(masks.iter().copied())
    {
        masked_state
            .publish_masked_message(round, mask)
            .map_err(|error| format!("{error:?}"))?;
        masked_state
            .accept_authenticated_challenge(challenge)
            .map_err(|error| format!("{error:?}"))?;
    }
    let expected_masked = masked_state
        .finish(fixture.terminal_left, fixture.terminal_right)
        .map_err(|error| format!("{error:?}"))?;
    Ok(ChainCase {
        input_width: layer.input_width,
        raw_width: layer.raw_width,
        packed_input,
        interpolation_weights: packed_lagrange_node_weights(fp16(811))
            .map_err(|error| format!("{error:?}"))?,
        wire_weights: multilinear_equality_table(&output_point)
            .map_err(|error| format!("{error:?}"))?,
        group_weights: multilinear_equality_table(&group_point)
            .map_err(|error| format!("{error:?}"))?,
        base_left: base_terms.iter().map(|term| term.left).collect(),
        base_right: base_terms.iter().map(|term| term.right).collect(),
        base_formula: base_terms.iter().map(|term| term.formula).collect(),
        masks,
        expected_masked_rounds: expected_masked.rounds,
        expected_terminal_correction: expected_masked.terminal_correction,
        fixture,
        initial_claim,
    })
}

fn run() -> Result<(), String> {
    let mut arguments = std::env::args_os().skip(1);
    let python = PathBuf::from(arguments.next().ok_or("python_path_missing")?);
    let worker = arguments.next().ok_or("worker_path_missing")?;
    let runtime = arguments.next().ok_or("runtime_path_missing")?;
    let permutations = arguments
        .next()
        .ok_or("permutation_count_missing")?
        .to_string_lossy()
        .parse::<usize>()
        .map_err(|_| "permutation_count_invalid")?;
    if !matches!(permutations, 782 | 894) || arguments.next().is_some() {
        return Err("usage: <python> <worker.py> <nvrtc-bin> <782|894>".to_string());
    }
    let cases = (0..9)
        .map(|ordinal| build_case(permutations, ordinal))
        .collect::<Result<Vec<_>, _>>()?;
    let worker_arguments = [worker, runtime].into_iter().collect::<Vec<_>>();
    let started = Instant::now();
    let mut worker =
        BoundedGkrWorker::spawn(&python, &worker_arguments, 216, Duration::from_secs(30))
            .map_err(|error| format!("{error:?}"))?;
    let mut digest = Sha3_512::new();
    for _round in (0..24).rev() {
        for case in cases.iter().rev() {
            let claims = [GkrCompactClaimWeights {
                coefficient: Fp16::ONE,
                wire: &case.wire_weights[..case.raw_width],
                group: &case.group_weights,
            }];
            let request = GkrCompactWorkerRequest {
                packed_input: &case.packed_input,
                instances: 128 * PACK_BITS,
                input_width: case.input_width,
                interpolation_weights: &case.interpolation_weights,
                raw_width: case.raw_width,
                base_left: &case.base_left,
                base_right: &case.base_right,
                base_formula: &case.base_formula,
                claims: &claims,
            };
            let proof = worker
                .run_compact_session(
                    &request,
                    case.initial_claim,
                    &case.fixture.challenges,
                    &case.masks,
                    Duration::from_secs(30),
                )
                .map_err(|error| format!("{error:?}"))?;
            if proof.rounds != case.expected_masked_rounds
                || proof.terminal_left != case.fixture.terminal_left
                || proof.terminal_right != case.fixture.terminal_right
                || proof.terminal_correction != case.expected_terminal_correction
            {
                return Err("cpu_gpu_proof_mismatch".to_string());
            }
            for round in &proof.rounds {
                for coefficient in round {
                    for coordinate in coefficient.coefficients() {
                        digest.update(coordinate.to_le_bytes());
                    }
                }
            }
        }
    }
    worker
        .finish(Duration::from_secs(30))
        .map_err(|error| format!("{error:?}"))?;
    println!("permutations={permutations}");
    println!("sessions=216");
    println!("worker_ns={}", started.elapsed().as_nanos());
    println!("cpu_gpu_proof_equal=true");
    println!("proof_stream_sha3_512={:x}", digest.finalize());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("compact chain benchmark failed: {error}");
        std::process::exit(1);
    }
}
