use std::{
    env,
    io::{self, BufReader, BufWriter, Read, Write},
    mem::size_of,
    thread,
    time::Instant,
};

use bl_pq512_crypto_core::{
    field::{Fp16, M31_MODULUS},
    fp16_zk_rs_gkr_binding::{
        BOUNDARY_VARIABLES, GKR_CLAIM_COUNT, PackedComponentClaim, bind_gkr_boundary_claims,
        claim_main_answer_target,
    },
    gkr_sumcheck::LayerOutputClaim,
    multilinear_pcs::MultilinearOpeningClaim,
    state_squarefree_pcs::{
        MASKED_STATE_SQUAREFREE_COEFFICIENT_CLAIMS, STATE_SQUAREFREE_COEFFICIENT_VARIABLES,
        state_squarefree_coefficient_functional,
    },
};
use getrandom::fill;
use sha3::{Digest, Sha3_512};

const INPUT_MAGIC: &[u8; 8] = b"BLRSCV04";
const OUTPUT_MAGIC: &[u8; 8] = b"BLRSCO01";
const GKR_MASK_OUTPUT_MAGIC: &[u8; 8] = b"BLRSMO01";
const MAIN_LOG: u32 = 17;
const MAIN_DIMENSION: u32 = 67_584;
const AUXILIARY_LOG: u32 = 13;
const AUXILIARY_DIMENSION: u32 = 3_266;
const COMPLETE_AUXILIARY_WORDS: u32 = 74;
const MAIN_QUERIES: u32 = 1_600;
const AUXILIARY_QUERIES: u32 = 1_218;
const FP16_ENCODED_LENGTH: usize = 64;
const COMPONENTS: usize = 16;
const WORD_SUMCHECK_ROUNDS: usize = 9;
const AUXILIARY_MESSAGE_VALUES: usize = 2_048;
const GKR_MASK_WORDS: usize = 64;
const GKR_MASK_MESSAGE_VALUES: usize = 512;

const GKR_MASK_VALUES: usize = GKR_MASK_WORDS * GKR_MASK_MESSAGE_VALUES;
const GKR_MASK_COORDINATES: usize = GKR_MASK_VALUES * COMPONENTS;
const GKR_MASK_PAYLOAD_BYTES: usize = GKR_MASK_VALUES * FP16_ENCODED_LENGTH;
const GKR_MASK_TREE_LEAVES: usize = 1 << AUXILIARY_LOG;
const GKR_MASK_BOUNDARY: u64 = 2;
const GKR_MASK_KIND: u64 = 67;
const GKR_MASK_MAX_SAMPLING_ATTEMPTS: u32 = 32;
const MAX_SAFE_WORKERS: usize = 16;
const PCS_MAGIC: &[u8; 8] = b"BLPQPCS1";
const PCS_VERSION: u16 = 1;
const SEGMENT_LEAF_DOMAIN: u16 = 516;
const MERKLE_NODE_DOMAIN: u16 = 514;
const MERKLE_ROOT_DOMAIN: u16 = 515;
const ROOT25_COORDINATES: [u32; 16] = [
    1_905_033_081,
    454_651_505,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
];
const COSET_COORDINATES: [u32; 16] = [2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

struct GkrMaskSample {
    coefficients: Vec<Fp16>,
    payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Geometry {
    main_log: u32,
    main_dimension: u32,
    auxiliary_log: u32,
    auxiliary_dimension: u32,
    auxiliary_words: u32,
    main_queries: u32,
    auxiliary_queries: u32,
}

impl Geometry {
    const PRODUCTION: Self = Self {
        main_log: MAIN_LOG,
        main_dimension: MAIN_DIMENSION,
        auxiliary_log: AUXILIARY_LOG,
        auxiliary_dimension: AUXILIARY_DIMENSION,
        auxiliary_words: COMPLETE_AUXILIARY_WORDS,
        main_queries: MAIN_QUERIES,
        auxiliary_queries: AUXILIARY_QUERIES,
    };

    fn read(reader: &mut impl Read) -> Result<Self, String> {
        Ok(Self {
            main_log: read_u32(reader)?,
            main_dimension: read_u32(reader)?,
            auxiliary_log: read_u32(reader)?,
            auxiliary_dimension: read_u32(reader)?,
            auxiliary_words: read_u32(reader)?,
            main_queries: read_u32(reader)?,
            auxiliary_queries: read_u32(reader)?,
        })
    }

    fn validate(self, allow_test_geometry: bool) -> Result<(), String> {
        if !allow_test_geometry && self != Self::PRODUCTION {
            return Err(format!("production_geometry:{self:?}"));
        }
        if self.main_log == 0
            || self.main_log > MAIN_LOG
            || self.auxiliary_log == 0
            || self.auxiliary_log > AUXILIARY_LOG
            || self.main_dimension == 0
            || self.main_dimension > (1_u32 << self.main_log)
            || self.auxiliary_dimension == 0
            || self.auxiliary_dimension > (1_u32 << self.auxiliary_log)
            || self.auxiliary_words == 0
            || self.auxiliary_words > COMPLETE_AUXILIARY_WORDS
            || self.main_queries == 0
            || self.main_queries > (1_u32 << self.main_log)
            || self.auxiliary_queries == 0
            || self.auxiliary_queries > (1_u32 << self.auxiliary_log)
        {
            return Err(format!("invalid_geometry:{self:?}"));
        }
        Ok(())
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ERR:{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [] => run_answer_code(false),
        [flag] if flag == "--test-geometry" => run_answer_code(true),
        [flag] if flag == "--gkr-mask-commit" => run_gkr_mask_commit(),
        _ => Err("arguments".to_string()),
    }
}

fn run_answer_code(allow_test_geometry: bool) -> Result<(), String> {
    let stdin = io::stdin();
    let mut reader = BufReader::with_capacity(1 << 20, stdin.lock());
    let mut magic = [0_u8; 8];
    reader
        .read_exact(&mut magic)
        .map_err(|error| format!("magic:{error}"))?;
    if &magic != INPUT_MAGIC {
        return Err("magic".to_string());
    }
    let geometry = Geometry::read(&mut reader)?;
    geometry.validate(allow_test_geometry)?;
    let main_queries = read_queries(
        &mut reader,
        geometry.main_queries as usize,
        1_usize << geometry.main_log,
        "main",
    )?;
    let auxiliary_queries = read_queries(
        &mut reader,
        geometry.auxiliary_queries as usize,
        1_usize << geometry.auxiliary_log,
        "auxiliary",
    )?;
    let claim_challenge = read_fp16(&mut reader)?;
    let coordinate_challenge = read_fp16(&mut reader)?;
    let mut claims = Vec::with_capacity(GKR_CLAIM_COUNT);
    for _ in 0..GKR_CLAIM_COUNT {
        claims.push(read_gkr_claim(&mut reader)?);
    }
    let binding = bind_gkr_boundary_claims(&claims, claim_challenge, coordinate_challenge)
        .map_err(|error| format!("gkr_binding:{error:?}"))?;
    let challenges = read_values(&mut reader, WORD_SUMCHECK_ROUNDS)?;
    let gkr_relation_terminals = read_values(&mut reader, GKR_MASK_WORDS)?;
    let main_scale = read_fp16(&mut reader)?;
    let (state_squarefree_functional, _) = read_squarefree_binding(&mut reader)?;
    let expected_target = read_fp16(&mut reader)?;
    let main_coefficients = read_values(&mut reader, geometry.main_dimension as usize)?;
    let mut auxiliary_coefficients = (0..geometry.auxiliary_words)
        .map(|_| read_values(&mut reader, geometry.auxiliary_dimension as usize))
        .collect::<Result<Vec<_>, _>>()?;
    let mut trailing = [0_u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(|error| format!("trailing:{error}"))?
        != 0
    {
        return Err("trailing_input".to_string());
    }

    let verify_started = Instant::now();
    {
        let main_coefficients_ref = &main_coefficients;
        let main_target = thread::scope(|scope| {
            let mut handles = Vec::with_capacity(GKR_CLAIM_COUNT);
            let binding = &binding;
            let challenges = &challenges;
            for claim_ordinal in 0..GKR_CLAIM_COUNT {
                handles.push(scope.spawn(move || {
                    claim_main_answer_target(
                        binding,
                        claim_ordinal,
                        challenges,
                        main_coefficients_ref,
                    )
                }));
            }
            let mut target = Fp16::ZERO;
            for handle in handles {
                target = target
                    + handle
                        .join()
                        .map_err(|_| "target_worker_panic".to_string())?
                        .map_err(|error| format!("target:{error:?}"))?;
            }
            Ok::<Fp16, String>(target)
        })?;
        let mut auxiliary_target = auxiliary_coefficients
            .iter()
            .take(WORD_SUMCHECK_ROUNDS)
            .zip(&challenges)
            .fold(Fp16::ZERO, |target, (coefficients, challenge)| {
                target + polynomial_eval(&coefficients[..AUXILIARY_MESSAGE_VALUES], *challenge)
            });
        if auxiliary_coefficients.len() != COMPLETE_AUXILIARY_WORDS as usize
            || gkr_relation_terminals.len() != GKR_MASK_WORDS
        {
            return Err("complete_auxiliary_shape".to_string());
        }
        for (coefficients, relation_terminal) in auxiliary_coefficients
            .iter()
            .skip(WORD_SUMCHECK_ROUNDS)
            .take(GKR_MASK_WORDS)
            .zip(&gkr_relation_terminals)
        {
            auxiliary_target = auxiliary_target
                + multilinear_evaluate(&coefficients[..GKR_MASK_MESSAGE_VALUES], &challenges)
                    * *relation_terminal
                    * main_scale;
        }
        auxiliary_target = auxiliary_target
            + inner_product(
                &auxiliary_coefficients
                    .last()
                    .ok_or_else(|| "squarefree_auxiliary_missing".to_string())?
                    [..AUXILIARY_MESSAGE_VALUES],
                &state_squarefree_functional,
            )?;
        let actual_target = main_target * main_scale + auxiliary_target;
        if actual_target != expected_target {
            return Err("answer_target".to_string());
        }
    }
    let worker_count = worker_count();
    let main_codeword = encode_codeword(&main_coefficients, geometry.main_log, worker_count)?;

    let auxiliary_count = auxiliary_coefficients.len();
    let auxiliary_codewords = thread::scope(|scope| {
        let auxiliary_workers = worker_count.min(auxiliary_count);
        let chunk_size = auxiliary_count.div_ceil(auxiliary_workers);
        let mut handles = Vec::with_capacity(auxiliary_workers);
        for chunk in auxiliary_coefficients.chunks_mut(chunk_size) {
            let log_code = geometry.auxiliary_log;
            handles.push(scope.spawn(move || {
                chunk
                    .iter_mut()
                    .map(|coefficients| encode_codeword(coefficients, log_code, 1))
                    .collect::<Result<Vec<_>, _>>()
            }));
        }
        let mut codewords = Vec::with_capacity(auxiliary_count);
        for handle in handles {
            codewords.extend(
                handle
                    .join()
                    .map_err(|_| "auxiliary_worker_panic".to_string())??,
            );
        }
        Ok::<Vec<Vec<Fp16>>, String>(codewords)
    });
    let auxiliary_codewords = auxiliary_codewords?;

    let stdout = io::stdout();
    let mut writer = BufWriter::with_capacity(1 << 20, stdout.lock());
    writer
        .write_all(OUTPUT_MAGIC)
        .and_then(|_| writer.write_all(&verify_started.elapsed().as_secs_f64().to_be_bytes()))
        .and_then(|_| writer.write_all(&(worker_count as u32).to_be_bytes()))
        .map_err(|error| format!("output_header:{error}"))?;
    for query in main_queries {
        writer
            .write_all(&main_codeword[query].encode())
            .map_err(|error| format!("main_output:{error}"))?;
    }
    for query in auxiliary_queries {
        for codeword in &auxiliary_codewords {
            writer
                .write_all(&codeword[query].encode())
                .map_err(|error| format!("auxiliary_output:{error}"))?;
        }
    }
    writer
        .flush()
        .map_err(|error| format!("output_flush:{error}"))?;
    Ok(())
}

fn run_gkr_mask_commit() -> Result<(), String> {
    let started = Instant::now();
    let workers = worker_count();
    let (coefficients, payload, sampling_attempts) = sample_gkr_mask()?;
    let codewords = encode_gkr_mask_codewords(&coefficients, workers)?;
    if codewords.len() != GKR_MASK_WORDS
        || codewords
            .iter()
            .any(|codeword| codeword.len() != GKR_MASK_TREE_LEAVES)
    {
        return Err("gkr_mask_codeword_shape".to_string());
    }
    let root = segment_root(&codewords, GKR_MASK_BOUNDARY, GKR_MASK_KIND, workers)?;
    let compute_seconds = started.elapsed().as_secs_f64();

    let stdout = io::stdout();
    let mut writer = BufWriter::with_capacity(1 << 20, stdout.lock());
    writer
        .write_all(GKR_MASK_OUTPUT_MAGIC)
        .and_then(|_| writer.write_all(&sampling_attempts.to_be_bytes()))
        .and_then(|_| writer.write_all(&compute_seconds.to_be_bytes()))
        .and_then(|_| writer.write_all(&(workers as u32).to_be_bytes()))
        .and_then(|_| writer.write_all(&root))
        .and_then(|_| writer.write_all(&payload))
        .and_then(|_| writer.flush())
        .map_err(|error| format!("gkr_mask_output:{error}"))
}

fn worker_count() -> usize {
    thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .min(MAX_SAFE_WORKERS)
}

fn sample_gkr_mask() -> Result<(Vec<Fp16>, Vec<u8>, u32), String> {
    let mut random = vec![0_u8; GKR_MASK_COORDINATES * size_of::<u32>()];
    for attempt in 1..=GKR_MASK_MAX_SAMPLING_ATTEMPTS {
        fill(&mut random).map_err(|error| format!("gkr_mask_csprng:{error}"))?;
        if let Some(sample) = decode_gkr_mask_randomness(&random)? {
            random.fill(0);
            return Ok((sample.coefficients, sample.payload, attempt));
        }
    }
    random.fill(0);
    Err("gkr_mask_sampling_attempts_exhausted".to_string())
}

fn decode_gkr_mask_randomness(random: &[u8]) -> Result<Option<GkrMaskSample>, String> {
    if random.len() != GKR_MASK_COORDINATES * size_of::<u32>() {
        return Err("gkr_mask_random_shape".to_string());
    }
    if random.chunks_exact(size_of::<u32>()).any(|encoded| {
        u32::from_ne_bytes(encoded.try_into().expect("exact chunk")) & M31_MODULUS == M31_MODULUS
    }) {
        return Ok(None);
    }

    let mut coefficients = Vec::with_capacity(GKR_MASK_VALUES);
    let mut payload = Vec::with_capacity(GKR_MASK_PAYLOAD_BYTES);
    for encoded_value in random.chunks_exact(FP16_ENCODED_LENGTH) {
        let mut coordinates = [0_u32; COMPONENTS];
        for (coordinate, encoded) in coordinates
            .iter_mut()
            .zip(encoded_value.chunks_exact(size_of::<u32>()))
        {
            *coordinate =
                u32::from_ne_bytes(encoded.try_into().expect("exact chunk")) & M31_MODULUS;
        }
        let value = Fp16::from_coefficients(coordinates)
            .map_err(|error| format!("gkr_mask_field:{error:?}"))?;
        payload.extend_from_slice(&value.encode());
        coefficients.push(value);
    }
    Ok(Some(GkrMaskSample {
        coefficients,
        payload,
    }))
}

fn encode_gkr_mask_codewords(
    coefficients: &[Fp16],
    workers: usize,
) -> Result<Vec<Vec<Fp16>>, String> {
    if coefficients.len() != GKR_MASK_VALUES {
        return Err("gkr_mask_coefficient_shape".to_string());
    }
    let active_workers = workers.clamp(1, GKR_MASK_WORDS);
    let words_per_chunk = GKR_MASK_WORDS.div_ceil(active_workers);
    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(active_workers);
        for coefficient_chunk in coefficients.chunks(words_per_chunk * GKR_MASK_MESSAGE_VALUES) {
            handles.push(scope.spawn(move || {
                coefficient_chunk
                    .chunks_exact(GKR_MASK_MESSAGE_VALUES)
                    .map(|word| encode_codeword(word, AUXILIARY_LOG, 1))
                    .collect::<Result<Vec<_>, _>>()
            }));
        }
        let mut codewords = Vec::with_capacity(GKR_MASK_WORDS);
        for handle in handles {
            codewords.extend(
                handle
                    .join()
                    .map_err(|_| "gkr_mask_encode_worker_panic".to_string())??,
            );
        }
        Ok(codewords)
    })
}

fn segment_root(
    codewords: &[Vec<Fp16>],
    boundary: u64,
    kind: u64,
    workers: usize,
) -> Result<[u8; 64], String> {
    if codewords.is_empty()
        || codewords
            .iter()
            .any(|codeword| codeword.len() != codewords[0].len())
        || !codewords[0].len().is_power_of_two()
    {
        return Err("segment_codeword_shape".to_string());
    }
    let leaf_count = codewords[0].len();
    let leaf_size = codewords
        .len()
        .checked_mul(FP16_ENCODED_LENGTH)
        .ok_or_else(|| "segment_leaf_size".to_string())?;
    let data_size = leaf_count
        .checked_mul(leaf_size)
        .ok_or_else(|| "segment_data_size".to_string())?;
    let active_workers = workers.clamp(1, leaf_count);
    let leaves_per_chunk = leaf_count.div_ceil(active_workers);
    let mut current = vec![[0_u8; 64]; leaf_count];
    thread::scope(|scope| {
        for (chunk_ordinal, output) in current.chunks_mut(leaves_per_chunk).enumerate() {
            let start = chunk_ordinal * leaves_per_chunk;
            scope.spawn(move || {
                let mut payload = vec![0_u8; leaf_size];
                for (offset, destination) in output.iter_mut().enumerate() {
                    let row = start + offset;
                    for (word, codeword) in codewords.iter().enumerate() {
                        let encoded = codeword[row].encode();
                        let target = word * FP16_ENCODED_LENGTH;
                        payload[target..target + FP16_ENCODED_LENGTH].copy_from_slice(&encoded);
                    }
                    *destination =
                        segment_leaf_hash(boundary, kind, data_size, leaf_size, row, &payload);
                }
                payload.fill(0);
            });
        }
    });

    while current.len() > 1 {
        let parent_count = current.len() / 2;
        let parents_per_chunk = parent_count.div_ceil(active_workers);
        let mut next = vec![[0_u8; 64]; parent_count];
        thread::scope(|scope| {
            for (chunk_ordinal, output) in next.chunks_mut(parents_per_chunk).enumerate() {
                let start = chunk_ordinal * parents_per_chunk;
                let input_start = 2 * start;
                let input_end = input_start + 2 * output.len();
                let input = &current[input_start..input_end];
                scope.spawn(move || {
                    for (destination, pair) in output.iter_mut().zip(input.chunks_exact(2)) {
                        *destination = hash_parts(MERKLE_NODE_DOMAIN, &[&pair[0], &pair[1]]);
                    }
                });
            }
        });
        current = next;
    }
    let leaf_count = u64::try_from(leaf_count).map_err(|_| "segment_leaf_count".to_string())?;
    Ok(hash_parts(
        MERKLE_ROOT_DOMAIN,
        &[&leaf_count.to_be_bytes(), &current[0]],
    ))
}

fn segment_leaf_hash(
    boundary: u64,
    kind: u64,
    data_size: usize,
    leaf_size: usize,
    leaf_index: usize,
    payload: &[u8],
) -> [u8; 64] {
    debug_assert_eq!(payload.len(), leaf_size);
    hash_parts(
        SEGMENT_LEAF_DOMAIN,
        &[
            &boundary.to_be_bytes(),
            &kind.to_be_bytes(),
            &(data_size as u64).to_be_bytes(),
            &(leaf_size as u64).to_be_bytes(),
            &(leaf_index as u64).to_be_bytes(),
            payload,
        ],
    )
}

fn hash_parts(domain: u16, parts: &[&[u8]]) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(PCS_MAGIC);
    hash.update(PCS_VERSION.to_be_bytes());
    hash.update(domain.to_be_bytes());
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

fn read_array<const N: usize>(reader: &mut impl Read) -> Result<[u8; N], String> {
    let mut encoded = [0_u8; N];
    reader
        .read_exact(&mut encoded)
        .map_err(|error| format!("read:{error}"))?;
    Ok(encoded)
}

fn read_u32(reader: &mut impl Read) -> Result<u32, String> {
    let mut encoded = [0_u8; 4];
    reader
        .read_exact(&mut encoded)
        .map_err(|error| format!("u32:{error}"))?;
    Ok(u32::from_be_bytes(encoded))
}

fn read_queries(
    reader: &mut impl Read,
    count: usize,
    bound: usize,
    label: &str,
) -> Result<Vec<usize>, String> {
    let queries = (0..count)
        .map(|_| read_u32(reader).map(|query| query as usize))
        .collect::<Result<Vec<_>, _>>()?;
    if queries.iter().any(|query| *query >= bound)
        || queries.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(format!("{label}_queries"));
    }
    Ok(queries)
}

fn read_fp16(reader: &mut impl Read) -> Result<Fp16, String> {
    let mut encoded = [0_u8; FP16_ENCODED_LENGTH];
    reader
        .read_exact(&mut encoded)
        .map_err(|error| format!("fp16_read:{error}"))?;
    Fp16::decode(&encoded).map_err(|error| format!("fp16_decode:{error:?}"))
}

fn read_values(reader: &mut impl Read, count: usize) -> Result<Vec<Fp16>, String> {
    (0..count).map(|_| read_fp16(reader)).collect()
}

fn read_gkr_claim(reader: &mut impl Read) -> Result<PackedComponentClaim, String> {
    let boundary = u8::try_from(read_u32(reader)?).map_err(|_| "gkr_boundary".to_string())?;
    let coefficient = read_fp16(reader)?;
    let value = read_fp16(reader)?;
    let shard_query = read_fp16(reader)?;
    let point = read_values(reader, BOUNDARY_VARIABLES)?;
    let mut component_evaluations = [Fp16::ZERO; COMPONENTS];
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

fn polynomial_eval(coefficients: &[Fp16], point: Fp16) -> Fp16 {
    coefficients
        .iter()
        .copied()
        .rev()
        .fold(Fp16::ZERO, |value, coefficient| value * point + coefficient)
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

fn root_for_log(log_code: u32) -> Result<Fp16, String> {
    if log_code == 0 || log_code > 25 {
        return Err(format!("root_log:{log_code}"));
    }
    let mut root =
        Fp16::from_coefficients(ROOT25_COORDINATES).map_err(|error| format!("root:{error:?}"))?;
    for _ in log_code..25 {
        root = root.square();
    }
    Ok(root)
}

fn frozen_coset() -> Result<Fp16, String> {
    Fp16::from_coefficients(COSET_COORDINATES).map_err(|error| format!("coset:{error:?}"))
}

fn encode_codeword(
    coefficients: &[Fp16],
    log_code: u32,
    workers: usize,
) -> Result<Vec<Fp16>, String> {
    let count = 1_usize << log_code;
    if coefficients.is_empty() || coefficients.len() > count {
        return Err("coefficient_count".to_string());
    }
    let coset = frozen_coset()?;
    let mut coset_power = Fp16::ONE;
    let mut values = vec![Fp16::ZERO; count];
    for (destination, coefficient) in values.iter_mut().zip(coefficients.iter().copied()) {
        *destination = coefficient * coset_power;
        coset_power = coset_power * coset;
    }
    ntt_in_place(&mut values, root_for_log(log_code)?, workers.max(1));
    Ok(values)
}

fn ntt_in_place(values: &mut [Fp16], root: Fp16, workers: usize) {
    let count = values.len();
    let log_size = count.ilog2();
    for index in 1..count {
        let reversed = index.reverse_bits() >> (usize::BITS - log_size);
        if index < reversed {
            values.swap(index, reversed);
        }
    }
    let mut length = 2;
    while length <= count {
        let stage_log = length.ilog2();
        let mut stage_root = root;
        for _ in stage_log..log_size {
            stage_root = stage_root.square();
        }
        let block_count = count / length;
        let active_workers = workers.min(block_count);
        if active_workers > 1 {
            let blocks_per_chunk = block_count.div_ceil(active_workers);
            let values_per_chunk = blocks_per_chunk * length;
            thread::scope(|scope| {
                for chunk in values.chunks_mut(values_per_chunk) {
                    scope.spawn(move || {
                        transform_blocks(chunk, length, stage_root);
                    });
                }
            });
        } else {
            transform_blocks(values, length, stage_root);
        }
        if length == count {
            break;
        }
        length *= 2;
    }
}

fn transform_blocks(values: &mut [Fp16], length: usize, stage_root: Fp16) {
    for block in values.chunks_exact_mut(length) {
        let mut twiddle = Fp16::ONE;
        let half = length / 2;
        for index in 0..half {
            let left = block[index];
            let right = block[half + index] * twiddle;
            block[index] = left + right;
            block[half + index] = left - right;
            twiddle = twiddle * stage_root;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pow(mut base: Fp16, mut exponent: usize) -> Fp16 {
        let mut result = Fp16::ONE;
        while exponent != 0 {
            if exponent & 1 == 1 {
                result = result * base;
            }
            base = base.square();
            exponent >>= 1;
        }
        result
    }

    #[test]
    fn coset_ntt_matches_direct_evaluation() {
        let coefficients = (0..7)
            .map(|index| {
                let mut coordinates = [0_u32; 16];
                coordinates[index % 16] = (17 + 29 * index) as u32;
                Fp16::from_coefficients(coordinates).unwrap()
            })
            .collect::<Vec<_>>();
        let encoded = encode_codeword(&coefficients, 4, 3).unwrap();
        let root = root_for_log(4).unwrap();
        let coset = frozen_coset().unwrap();
        for (index, actual) in encoded.into_iter().enumerate() {
            let point = coset * pow(root, index);
            let mut expected = Fp16::ZERO;
            let mut point_power = Fp16::ONE;
            for coefficient in coefficients.iter().copied() {
                expected = expected + coefficient * point_power;
                point_power = point_power * point;
            }
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn production_root_has_exact_orders() {
        for log_code in [AUXILIARY_LOG, MAIN_LOG] {
            let root = root_for_log(log_code).unwrap();
            assert_eq!(pow(root, 1_usize << log_code), Fp16::ONE);
            assert_ne!(pow(root, 1_usize << (log_code - 1)), Fp16::ONE);
        }
    }

    #[test]
    fn gkr_mask_randomness_is_exact_and_rejects_the_modulus() {
        let mut random = vec![0_u8; GKR_MASK_COORDINATES * size_of::<u32>()];
        random[..4].copy_from_slice(&M31_MODULUS.to_ne_bytes());
        assert!(decode_gkr_mask_randomness(&random).unwrap().is_none());

        random[..4].copy_from_slice(&(M31_MODULUS - 1).to_ne_bytes());
        let sample = decode_gkr_mask_randomness(&random).unwrap().unwrap();
        assert_eq!(sample.coefficients.len(), GKR_MASK_VALUES);
        assert_eq!(sample.payload.len(), GKR_MASK_PAYLOAD_BYTES);
        assert_eq!(&sample.payload[..4], &(M31_MODULUS - 1).to_be_bytes());
        assert!(sample.payload[4..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn typed_segment_root_is_parallel_exact_and_word_ordered() {
        let mut codewords = (0_u32..2)
            .map(|word| {
                (0_u32..4)
                    .map(|row| {
                        let mut coordinates = [0_u32; COMPONENTS];
                        coordinates[0] = 1 + 10 * word + row;
                        Fp16::from_coefficients(coordinates).unwrap()
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let root = segment_root(&codewords, GKR_MASK_BOUNDARY, GKR_MASK_KIND, 1).unwrap();
        assert_eq!(
            root,
            *b"\x0b\x8d\x03\xdd\x92\x81\x26\xda\xee\xa7\xf9\x75\x3f\xf4\x33\x40\
              \x9b\x2b\x1f\xdf\x62\xe4\xd1\xbe\x21\x57\x0e\x43\xc3\xd6\x55\x71\
              \x88\x00\x6a\xc3\x8c\x38\x81\x97\xf2\xf0\x0b\x5f\xe0\xa2\xd6\x17\
              \x64\xad\xbb\x4a\xcb\x8c\x1c\x2e\x4d\x52\xc2\xbf\xec\x7c\xc0\xd5"
        );
        assert_eq!(
            segment_root(&codewords, GKR_MASK_BOUNDARY, GKR_MASK_KIND, 4).unwrap(),
            root
        );
        codewords.swap(0, 1);
        assert_ne!(
            segment_root(&codewords, GKR_MASK_BOUNDARY, GKR_MASK_KIND, 4).unwrap(),
            root
        );
    }
}
