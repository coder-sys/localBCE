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
    multilinear_pcs::MultilinearOpeningClaim,
    state_squarefree_pcs::{
        MASKED_STATE_SQUAREFREE_COEFFICIENT_CLAIMS, STATE_SQUAREFREE_COEFFICIENT_VARIABLES,
        state_squarefree_coefficient_functional,
    },
};

const INPUT_MAGIC: &[u8; 8] = b"BLRSTA02";
const OUTPUT_MAGIC: &[u8; 8] = b"BLRSTO01";
const WORD_ROUNDS: usize = 9;
const MAIN_DIMENSION: usize = 67_584;
const SUMCHECK_AUXILIARY_WORDS: usize = 9;
const GKR_MASK_AUXILIARY_WORDS: usize = 64;
const COMPLETE_AUXILIARY_WORDS: usize = SUMCHECK_AUXILIARY_WORDS + GKR_MASK_AUXILIARY_WORDS + 1;
const AUXILIARY_DIMENSION: usize = 3_266;
const AUXILIARY_MESSAGE_VALUES: usize = 2_048;
const GKR_MASK_MESSAGE_VALUES: usize = 512;
const FP16_BYTES: usize = 64;

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
    let (state_squarefree_functional, _) = read_squarefree_binding(&mut reader)?;
    let main = (0..MAIN_DIMENSION)
        .map(|_| read_fp16(&mut reader))
        .collect::<Result<Vec<_>, _>>()?;
    let auxiliary = (0..COMPLETE_AUXILIARY_WORDS)
        .map(|_| {
            (0..AUXILIARY_DIMENSION)
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

    let main_target =
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
    let auxiliary_target = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(COMPLETE_AUXILIARY_WORDS);
        for (coefficients, challenge) in auxiliary
            .iter()
            .take(SUMCHECK_AUXILIARY_WORDS)
            .zip(&challenges)
        {
            handles.push(scope.spawn(move || {
                polynomial_eval(&coefficients[..AUXILIARY_MESSAGE_VALUES], *challenge)
            }));
        }
        for (coefficients, relation_terminal) in auxiliary
            .iter()
            .skip(SUMCHECK_AUXILIARY_WORDS)
            .take(GKR_MASK_AUXILIARY_WORDS)
            .zip(&gkr_relation_terminals)
        {
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
        target = target
            + inner_product(
                &auxiliary
                    .last()
                    .ok_or_else(|| "squarefree_auxiliary_missing".to_string())?
                    [..AUXILIARY_MESSAGE_VALUES],
                &state_squarefree_functional,
            )?;
        Ok::<Fp16, String>(target)
    })?;
    let workers = thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());
    writer
        .write_all(OUTPUT_MAGIC)
        .and_then(|_| writer.write_all(&(main_target * main_scale + auxiliary_target).encode()))
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

fn read_squarefree_binding(reader: &mut impl Read) -> Result<(Vec<Fp16>, Fp16), String> {
    if &read_array::<8>(reader)? != b"BLSQAB01" {
        return Err("squarefree_binding_magic".to_string());
    }
    let capacity = usize::from(u16::from_be_bytes(read_array::<2>(reader)?));
    let count = usize::from(u16::from_be_bytes(read_array::<2>(reader)?));
    if read_array::<4>(reader)? != [0_u8; 4]
        || !matches!((capacity, count), (0, 0) | (128, 2) | (512, 2))
    {
        return Err("squarefree_binding_shape".to_string());
    }
    let mut claims = Vec::with_capacity(count);
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
        claims.push(MultilinearOpeningClaim {
            point,
            value: read_fp16(reader)?,
        });
    }
    let mixing_count = if count == 0 {
        4
    } else {
        MASKED_STATE_SQUAREFREE_COEFFICIENT_CLAIMS
    };
    let mut mixing = vec![Fp16::ZERO; mixing_count];
    for value in &mut mixing {
        *value = read_fp16(reader)?;
    }
    if capacity == 0 {
        return Ok((vec![Fp16::ZERO; AUXILIARY_MESSAGE_VALUES], Fp16::ZERO));
    }
    state_squarefree_coefficient_functional(capacity, &claims, &mixing)
        .map_err(|error| format!("squarefree_binding:{error:?}"))
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
