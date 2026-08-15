use std::{
    io::{self, BufReader, BufWriter, Read, Write},
    thread,
    time::Instant,
};

use bl_pq512_crypto_core::{
    field::Fp16,
    fp16_zk_rs_gkr_binding::{
        BOUNDARY_VARIABLES, GKR_CLAIM_COUNT, PackedComponentClaim, bind_gkr_boundary_claims,
        claim_main_answer_target,
    },
    gkr_packed_bridge_fp16::PACKED_INSTANCES,
    gkr_sumcheck::LayerOutputClaim,
    h4_differential_dump::{H4BufferAccess, write_h4_fp16_vector_dump, write_h4_path_dump},
    h4_proof_package_v1::{
        H4_MASKED_SOURCE_FUNCTIONAL_BINDING_BYTES, H4MaskedSourceFunctionalBinding, H4ProofProfile,
        evaluate_h4_masked_source_functional_binding,
    },
    multilinear_pcs::MultilinearOpeningClaim,
    state_squarefree_gkr::public_masked_state_squarefree_gkr_mask_functional,
    state_squarefree_pcs::{
        MASKED_STATE_SQUAREFREE_COEFFICIENT_CLAIMS, STATE_SQUAREFREE_COEFFICIENT_VARIABLES,
        state_squarefree_coefficient_functional,
    },
};
use sha3::{Digest, Sha3_512};

const INPUT_MAGIC: &[u8; 8] = b"BLRSTA05";
const OUTPUT_MAGIC: &[u8; 8] = b"BLRSTO02";
const WORD_ROUNDS: usize = 9;
const MAIN_DIMENSION: usize = 67_584;
const SUMCHECK_AUXILIARY_WORDS: usize = 9;
const GKR_MASK_AUXILIARY_WORDS: usize = 64;
const NON_GKR_AUXILIARY_WORDS: usize = SUMCHECK_AUXILIARY_WORDS + 1;
const AUXILIARY_DIMENSION: usize = 3_266;
const AUXILIARY_MESSAGE_VALUES: usize = 2_048;
const GKR_MASK_MESSAGE_VALUES: usize = 512;
const FP16_BYTES: usize = 64;
const STATE_SQUAREFREE_CLAIMS_DIGEST_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/STATE-SQUAREFREE-CLAIMS/v2\0";

struct StateSquarefreeAnswerBinding {
    capacity: usize,
    coefficient_functional: Vec<Fp16>,
    gkr_mask_functional: Vec<Fp16>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ERR:{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let started = Instant::now();
    let stdin = io::stdin();
    let mut reader = BufReader::with_capacity(1 << 20, stdin.lock());
    let magic = read_array::<8>(&mut reader)?;
    if &magic != INPUT_MAGIC {
        return Err("input_magic".to_string());
    }
    let claim_challenge = read_fp16(&mut reader)?;
    let coordinate_challenge = read_fp16(&mut reader)?;
    let claims = (0..GKR_CLAIM_COUNT)
        .map(|_| read_claim(&mut reader))
        .collect::<Result<Vec<_>, _>>()?;
    let binding = bind_gkr_boundary_claims(&claims, claim_challenge, coordinate_challenge)
        .map_err(|error| format!("binding:{error:?}"))?;
    let challenges = (0..WORD_ROUNDS)
        .map(|_| read_fp16(&mut reader))
        .collect::<Result<Vec<_>, _>>()?;
    let gkr_relation_terminals = (0..GKR_MASK_AUXILIARY_WORDS)
        .map(|_| read_fp16(&mut reader))
        .collect::<Result<Vec<_>, _>>()?;
    let main_scale = read_fp16(&mut reader)?;
    let expected_squarefree_claims = read_squarefree_claims_payload(&mut reader)?;
    let state_squarefree = read_squarefree_binding(&mut reader, &expected_squarefree_claims)?;
    let h4_source_binding = H4MaskedSourceFunctionalBinding::decode(&read_array::<
        H4_MASKED_SOURCE_FUNCTIONAL_BINDING_BYTES,
    >(&mut reader)?)
    .map_err(|error| format!("h4_source_binding:{error:?}"))?;
    let main = (0..MAIN_DIMENSION)
        .map(|_| read_fp16(&mut reader))
        .collect::<Result<Vec<_>, _>>()?;
    let auxiliary = (0..NON_GKR_AUXILIARY_WORDS)
        .map(|_| {
            (0..AUXILIARY_DIMENSION)
                .map(|_| read_fp16(&mut reader))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    let gkr_mask = (0..GKR_MASK_AUXILIARY_WORDS)
        .map(|_| {
            (0..GKR_MASK_MESSAGE_VALUES)
                .map(|_| read_fp16(&mut reader))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut trailing = [0_u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(|error| format!("trailing:{error}"))?
        != 0
    {
        return Err("trailing_input".to_string());
    }

    let mut main_target =
        thread::scope(|scope| {
            let mut handles = Vec::with_capacity(GKR_CLAIM_COUNT);
            for claim_ordinal in 0..GKR_CLAIM_COUNT {
                let binding = &binding;
                let challenges = &challenges;
                let main = &main;
                handles.push(scope.spawn(move || {
                    claim_main_answer_target(binding, claim_ordinal, challenges, main)
                }));
            }
            let mut target = Fp16::ZERO;
            for handle in handles {
                target = target
                    + handle
                        .join()
                        .map_err(|_| "main_worker_panic".to_string())?
                        .map_err(|error| format!("main_target:{error:?}"))?;
            }
            Ok::<Fp16, String>(target)
        })?;
    let mut auxiliary_target = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(NON_GKR_AUXILIARY_WORDS + GKR_MASK_AUXILIARY_WORDS);
        for (coefficients, challenge) in auxiliary
            .iter()
            .take(SUMCHECK_AUXILIARY_WORDS)
            .zip(&challenges)
        {
            handles.push(scope.spawn(move || {
                polynomial_eval(&coefficients[..AUXILIARY_MESSAGE_VALUES], *challenge)
            }));
        }
        for (coefficients, relation_terminal) in gkr_mask.iter().zip(&gkr_relation_terminals) {
            let challenges = &challenges;
            handles.push(scope.spawn(move || {
                multilinear_evaluate(&coefficients[..GKR_MASK_MESSAGE_VALUES], challenges)
                    * *relation_terminal
                    * main_scale
            }));
        }
        let mut target = Fp16::ZERO;
        for handle in handles {
            target = target
                + handle
                    .join()
                    .map_err(|_| "auxiliary_worker_panic".to_string())?;
        }
        let raw_coefficient_opening = inner_product(
            &auxiliary
                .last()
                .ok_or_else(|| "squarefree_auxiliary_missing".to_string())?
                [..AUXILIARY_MESSAGE_VALUES],
            &state_squarefree.coefficient_functional,
        )?;
        let gkr_mask_opening = gkr_mask
            .iter()
            .zip(
                state_squarefree
                    .gkr_mask_functional
                    .chunks_exact(GKR_MASK_MESSAGE_VALUES),
            )
            .try_fold(Fp16::ZERO, |sum, (coefficients, functional)| {
                Ok::<Fp16, String>(
                    sum + inner_product(&coefficients[..GKR_MASK_MESSAGE_VALUES], functional)?,
                )
            })?;
        let squarefree_opening = raw_coefficient_opening + gkr_mask_opening;
        // `base_auxiliary` and `base_gkr_mask` are independently sampled
        // Construction-8.2 base masks.  Their square-free opening is not
        // required to equal the public target until the final combined
        // answer is checked by `fp16_zk_rs_answer_code_verify`; enforcing that
        // equality here rejects valid base masks before combination.
        target = target + squarefree_opening;
        Ok::<Fp16, String>(target)
    })?;
    if !matches!(
        (h4_source_binding.profile(), state_squarefree.capacity),
        (H4ProofProfile::K128, 128) | (H4ProofProfile::K512, 512)
    ) {
        return Err("h4_source_profile".to_string());
    }
    let flat_gkr_mask = gkr_mask.iter().flatten().copied().collect::<Vec<_>>();
    let hash_source_vector = main[..65_536]
        .iter()
        .copied()
        .enumerate()
        .map(|(position, value)| {
            if (position & ((1 << 11) - 1)) < 1_600 {
                value
            } else {
                Fp16::ZERO
            }
        })
        .collect::<Vec<_>>();
    write_h4_fp16_vector_dump(
        "h4-answer-source-coefficients.bin",
        "h4_hash_source_evaluation_vector",
        &hash_source_vector,
    )
    .map_err(|error| format!("h4_differential_dump:{error}"))?;
    write_h4_fp16_vector_dump(
        "h4-answer-main-source-coefficients.bin",
        "h4_main_source_coefficients",
        &main[..65_536],
    )
    .map_err(|error| format!("h4_differential_dump:{error}"))?;
    write_h4_fp16_vector_dump(
        "h4-answer-gkr-mask-coefficients.bin",
        "h4_gkr_mask_coefficients",
        &flat_gkr_mask,
    )
    .map_err(|error| format!("h4_differential_dump:{error}"))?;
    let h4_source_functionals = evaluate_h4_masked_source_functional_binding(
        &h4_source_binding,
        &main,
        &flat_gkr_mask,
        &challenges,
    )
    .map_err(|error| format!("h4_source_functionals:{error:?}"))?;
    let booleanity_group_point = h4_source_binding.booleanity_group_point();
    let padding_sumcheck_point = h4_source_binding.padding_sumcheck_point();
    write_h4_path_dump(
        "h4-answer-path.txt",
        "answer-target",
        &[
            ("booleanity_group_point", &booleanity_group_point),
            ("padding_sumcheck_point", &padding_sumcheck_point),
            ("row_challenges", &challenges),
        ],
        &[
            ("h4_hash_source_evaluation_vector", &hash_source_vector),
            ("h4_main_source_coefficients", &main[..65_536]),
            ("h4_gkr_mask_tensor", &flat_gkr_mask),
        ],
        &[
            H4BufferAccess {
                label: "h4_hash_source_evaluation_vector",
                base_offset_bytes: 0,
                element_stride_bytes: 64,
                element_count: 65_536,
                index_formula: "canonical_position = group_low * 2048 + wire; hash wires only",
            },
            H4BufferAccess {
                label: "h4_main_source_coefficients",
                base_offset_bytes: 0,
                element_stride_bytes: 64,
                element_count: 65_536,
                index_formula: "main[position]",
            },
            H4BufferAccess {
                label: "h4_gkr_mask_tensor",
                base_offset_bytes: 0,
                element_stride_bytes: 64,
                element_count: 32_768,
                index_formula: "gkr_mask[state * 512 + message]",
            },
        ],
        &[
            (
                "booleanity_left_challenge",
                h4_source_binding.booleanity_left_challenge(),
            ),
            (
                "booleanity_right_challenge",
                h4_source_binding.booleanity_right_challenge(),
            ),
            (
                "booleanity_w_challenge",
                h4_source_binding.booleanity_w_challenge(),
            ),
            (
                "answer_main_functional",
                h4_source_functionals.answer_main_functional(),
            ),
            (
                "answer_mask_functional",
                h4_source_functionals.answer_mask_functional(),
            ),
            ("masked_target", h4_source_functionals.masked_target()),
        ],
    )
    .map_err(|error| format!("h4_differential_dump:{error}"))?;
    main_target = main_target + h4_source_functionals.answer_main_functional();
    auxiliary_target =
        auxiliary_target + main_scale * h4_source_functionals.answer_mask_functional();
    let workers = thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    let total_target = main_target * main_scale + auxiliary_target;
    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());
    writer
        .write_all(OUTPUT_MAGIC)
        .and_then(|_| writer.write_all(&total_target.encode()))
        .and_then(|_| writer.write_all(&h4_source_functionals.masked_target().encode()))
        .and_then(|_| writer.write_all(&started.elapsed().as_secs_f64().to_be_bytes()))
        .and_then(|_| writer.write_all(&(workers as u32).to_be_bytes()))
        .and_then(|_| writer.flush())
        .map_err(|error| format!("output:{error}"))
}

fn polynomial_eval(coefficients: &[Fp16], point: Fp16) -> Fp16 {
    coefficients
        .iter()
        .copied()
        .rev()
        .fold(Fp16::ZERO, |value, coefficient| value * point + coefficient)
}

fn inner_product(left: &[Fp16], right: &[Fp16]) -> Result<Fp16, String> {
    if left.len() != right.len() {
        return Err("inner_product_shape".to_string());
    }
    Ok(left
        .iter()
        .copied()
        .zip(right)
        .fold(Fp16::ZERO, |sum, (value, weight)| sum + value * *weight))
}

fn read_squarefree_claims_payload(reader: &mut impl Read) -> Result<Vec<u8>, String> {
    let magic = read_array::<8>(reader)?;
    let remainder = if &magic == b"BLSQCL00" {
        68
    } else if &magic == b"BLSQCL02" {
        132
    } else {
        return Err("squarefree_claims_magic".to_string());
    };
    let mut payload = Vec::with_capacity(8 + remainder);
    payload.extend_from_slice(&magic);
    let mut tail = vec![0_u8; remainder];
    reader
        .read_exact(&mut tail)
        .map_err(|error| format!("squarefree_claims:{error}"))?;
    payload.extend_from_slice(&tail);
    Ok(payload)
}

fn read_squarefree_binding(
    reader: &mut impl Read,
    expected_claims_payload: &[u8],
) -> Result<StateSquarefreeAnswerBinding, String> {
    if &read_array::<8>(reader)? != b"BLSQAB02" {
        return Err("squarefree_binding_magic".to_string());
    }
    let claims_payload = read_squarefree_claims_payload(reader)?;
    if claims_payload != expected_claims_payload {
        return Err("squarefree_binding_claims".to_string());
    }
    let claims_magic = &claims_payload[..8];
    if claims_magic == b"BLSQCL00" {
        if claims_payload[8..] != [0_u8; 68] {
            return Err("squarefree_binding_zero".to_string());
        }
        for _ in 0..4 {
            let _ = read_fp16(reader)?;
        }
        return Ok(StateSquarefreeAnswerBinding {
            capacity: 0,
            coefficient_functional: vec![Fp16::ZERO; AUXILIARY_MESSAGE_VALUES],
            gkr_mask_functional: vec![
                Fp16::ZERO;
                GKR_MASK_AUXILIARY_WORDS * GKR_MASK_MESSAGE_VALUES
            ],
        });
    }
    if claims_magic != b"BLSQCL02" {
        return Err("squarefree_binding_claims_magic".to_string());
    }
    let root: [u8; 64] = claims_payload[8..72]
        .try_into()
        .map_err(|_| "squarefree_binding_root".to_string())?;
    let capacity = usize::from(u16::from_be_bytes(
        claims_payload[72..74]
            .try_into()
            .map_err(|_| "squarefree_binding_capacity".to_string())?,
    ));
    let count = usize::from(u16::from_be_bytes(
        claims_payload[74..76]
            .try_into()
            .map_err(|_| "squarefree_binding_count".to_string())?,
    ));
    let expected_digest: [u8; 64] = claims_payload[76..140]
        .try_into()
        .map_err(|_| "squarefree_binding_digest".to_string())?;
    if !root.iter().any(|byte| *byte != 0) || !matches!((capacity, count), (128, 2) | (512, 2)) {
        return Err("squarefree_binding_shape".to_string());
    }
    let mut claims = Vec::with_capacity(count);
    let mut digest_preimage = Vec::new();
    digest_preimage.extend_from_slice(STATE_SQUAREFREE_CLAIMS_DIGEST_DOMAIN);
    digest_preimage.extend_from_slice(&root);
    digest_preimage.extend_from_slice(&(capacity as u16).to_be_bytes());
    digest_preimage.extend_from_slice(&(count as u16).to_be_bytes());
    for phase in 0..count {
        let point_length = usize::from(u16::from_be_bytes(read_array::<2>(reader)?));
        if read_array::<6>(reader)? != [0_u8; 6]
            || point_length != STATE_SQUAREFREE_COEFFICIENT_VARIABLES
        {
            return Err("squarefree_binding_point".to_string());
        }
        let point = (0..STATE_SQUAREFREE_COEFFICIENT_VARIABLES)
            .map(|_| read_fp16(reader))
            .collect::<Result<Vec<_>, _>>()?;
        if (capacity == 128 && point[7..9].iter().any(|value| !value.is_zero()))
            || point[10] != if phase == 0 { Fp16::ZERO } else { Fp16::ONE }
        {
            return Err("squarefree_binding_padding".to_string());
        }
        let value = read_fp16(reader)?;
        digest_preimage.extend_from_slice(&(point_length as u16).to_be_bytes());
        for coordinate in &point {
            digest_preimage.extend_from_slice(&coordinate.encode());
        }
        digest_preimage.extend_from_slice(&value.encode());
        claims.push(MultilinearOpeningClaim { point, value });
    }
    if <[u8; 64]>::from(Sha3_512::digest(&digest_preimage)) != expected_digest {
        return Err("squarefree_binding_digest".to_string());
    }
    let mut mixing = vec![Fp16::ZERO; MASKED_STATE_SQUAREFREE_COEFFICIENT_CLAIMS];
    for value in &mut mixing {
        *value = read_fp16(reader)?;
    }
    let (coefficient_functional, coefficient_target) =
        state_squarefree_coefficient_functional(capacity, &claims, &mixing)
            .map_err(|error| format!("squarefree_binding:{error:?}"))?;
    let (gkr_mask_functional, masked_target) =
        public_masked_state_squarefree_gkr_mask_functional(capacity, &claims, &mixing)
            .map_err(|error| format!("squarefree_mask_binding:{error:?}"))?;
    if coefficient_target != masked_target {
        return Err("squarefree_binding_target".to_string());
    }
    Ok(StateSquarefreeAnswerBinding {
        capacity,
        coefficient_functional,
        gkr_mask_functional,
    })
}

fn multilinear_evaluate(values: &[Fp16], challenges: &[Fp16]) -> Fp16 {
    debug_assert_eq!(values.len(), 1_usize << challenges.len());
    let mut layer = values.to_vec();
    let mut active = layer.len();
    for challenge in challenges {
        for index in 0..active / 2 {
            let left = layer[2 * index];
            let right = layer[2 * index + 1];
            layer[index] = left + (right - left) * *challenge;
        }
        active /= 2;
    }
    layer[0]
}

fn read_array<const N: usize>(reader: &mut impl Read) -> Result<[u8; N], String> {
    let mut value = [0_u8; N];
    reader
        .read_exact(&mut value)
        .map_err(|error| format!("read:{error}"))?;
    Ok(value)
}

fn read_u32(reader: &mut impl Read) -> Result<u32, String> {
    Ok(u32::from_be_bytes(read_array::<4>(reader)?))
}

fn read_fp16(reader: &mut impl Read) -> Result<Fp16, String> {
    Fp16::decode(&read_array::<FP16_BYTES>(reader)?).map_err(|error| format!("fp16:{error:?}"))
}

fn read_claim(reader: &mut impl Read) -> Result<PackedComponentClaim, String> {
    let boundary = u8::try_from(read_u32(reader)?).map_err(|_| "boundary".to_string())?;
    let coefficient = read_fp16(reader)?;
    let value = read_fp16(reader)?;
    let shard_query = read_fp16(reader)?;
    let point = (0..BOUNDARY_VARIABLES)
        .map(|_| read_fp16(reader))
        .collect::<Result<Vec<_>, _>>()?;
    let mut component_evaluations = [Fp16::ZERO; PACKED_INSTANCES];
    for evaluation in &mut component_evaluations {
        *evaluation = read_fp16(reader)?;
    }
    Ok(PackedComponentClaim {
        boundary,
        claim: LayerOutputClaim {
            point,
            value,
            coefficient,
        },
        shard_query,
        component_evaluations,
    })
}
