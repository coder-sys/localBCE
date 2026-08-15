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
use getrandom::fill;
use sha3::{Digest, Sha3_512};

const INPUT_MAGIC: &[u8; 8] = b"BLRSCV07";
const OUTPUT_MAGIC: &[u8; 8] = b"BLRSCO02";
const GKR_MASK_OUTPUT_MAGIC: &[u8; 8] = b"BLRSMO01";
const GKR_ANSWER_COMMIT_INPUT_MAGIC: &[u8; 8] = b"BLRSAC01";
const GKR_ANSWER_COMMIT_OUTPUT_MAGIC: &[u8; 8] = b"BLRSAO01";
const MAIN_LOG: u32 = 17;
const MAIN_DIMENSION: u32 = 67_584;
const AUXILIARY_LOG: u32 = 13;
const AUXILIARY_DIMENSION: u32 = 3_266;
const NON_GKR_AUXILIARY_WORDS: u32 = 10;
const MAIN_QUERIES: u32 = 1_600;
const AUXILIARY_QUERIES: u32 = 1_218;
const FP16_ENCODED_LENGTH: usize = 64;
const COMPONENTS: usize = 16;
const WORD_SUMCHECK_ROUNDS: usize = 9;
const AUXILIARY_MESSAGE_VALUES: usize = 2_048;
const GKR_MASK_WORDS: usize = 64;
const GKR_MASK_MESSAGE_VALUES: usize = 512;
const STATE_SQUAREFREE_CLAIMS_DIGEST_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/STATE-SQUAREFREE-CLAIMS/v2\0";

const GKR_MASK_VALUES: usize = GKR_MASK_WORDS * GKR_MASK_MESSAGE_VALUES;
const GKR_MASK_COORDINATES: usize = GKR_MASK_VALUES * COMPONENTS;
const GKR_MASK_PAYLOAD_BYTES: usize = GKR_MASK_VALUES * FP16_ENCODED_LENGTH;
const GKR_MASK_INNER_LOG: u32 = AUXILIARY_LOG;
const GKR_MASK_OUTER_LOG: u32 = 7;
const GKR_MASK_OUTER_CODE_VALUES: usize = 1 << GKR_MASK_OUTER_LOG;
const GKR_MASK_TREE_LEAVES: usize = 1 << (GKR_MASK_INNER_LOG + GKR_MASK_OUTER_LOG);
const GKR_MASK_BOUNDARY: u64 = 2;
const GKR_MASK_KIND: u64 = 67;
const GKR_MASK_ANSWER_KIND: u64 = 69;
const GKR_MASK_MAX_SAMPLING_ATTEMPTS: u32 = 32;
const STREAMING_MERKLE_HASH_BATCH: usize = 1 << 16;
const MAX_SAFE_WORKERS: usize = 16;
const PCS_MAGIC: &[u8; 8] = b"BLPQPCS1";
const PCS_VERSION: u16 = 1;
const SEGMENT_LEAF_DOMAIN: u16 = 516;
const MERKLE_NODE_DOMAIN: u16 = 514;
const MERKLE_ROOT_DOMAIN: u16 = 515;
const QUERY_DOMAIN: u16 = 524;
const GKR_MASK_OUTER_QUERY_DOMAIN: u16 = 526;
const GKR_MASK_OUTER_QUERY_LABEL: &[u8] = b"gkr_mask_outer_queries/v1";
const QUERY_MAX_DRAWS: u64 = 1 << 20;
const QUERY_MAX_RETRIES_PER_DRAW: u64 = 1 << 20;
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

struct StateSquarefreeAnswerBinding {
    capacity: usize,
    coefficient_functional: Vec<Fp16>,
    gkr_mask_functional: Vec<Fp16>,
    masked_target: Fp16,
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
        auxiliary_words: NON_GKR_AUXILIARY_WORDS,
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
            || self.auxiliary_words > NON_GKR_AUXILIARY_WORDS
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
        [flag] if flag == "--gkr-answer-commit" => run_gkr_answer_commit(),
        _ => Err("arguments".to_string()),
    }
}

fn run_gkr_answer_commit() -> Result<(), String> {
    let stdin = io::stdin();
    let mut reader = BufReader::with_capacity(1 << 20, stdin.lock());
    if read_array::<8>(&mut reader)? != *GKR_ANSWER_COMMIT_INPUT_MAGIC {
        return Err("gkr_answer_commit_magic".to_string());
    }
    let coefficients = (0..GKR_MASK_VALUES)
        .map(|_| read_fp16(&mut reader))
        .collect::<Result<Vec<_>, _>>()?;
    let mut trailing = [0_u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(|error| format!("gkr_answer_commit_trailing:{error}"))?
        != 0
    {
        return Err("gkr_answer_commit_trailing".to_string());
    }
    let started = Instant::now();
    let workers = worker_count();
    let tensor_codeword = encode_gkr_mask_tensor(&coefficients, workers)?;
    let root = streaming_single_codeword_root(
        &tensor_codeword,
        GKR_MASK_BOUNDARY,
        GKR_MASK_ANSWER_KIND,
        workers,
    )?;
    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());
    writer
        .write_all(GKR_ANSWER_COMMIT_OUTPUT_MAGIC)
        .and_then(|_| writer.write_all(&started.elapsed().as_secs_f64().to_be_bytes()))
        .and_then(|_| writer.write_all(&(workers as u32).to_be_bytes()))
        .and_then(|_| writer.write_all(&root))
        .and_then(|_| writer.flush())
        .map_err(|error| format!("gkr_answer_commit_output:{error}"))
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
    let query_seed = read_array::<64>(&mut reader)?;
    Fp16::decode(&query_seed).map_err(|error| format!("query_seed:{error:?}"))?;
    if main_queries
        != exact_queries(
            &query_seed,
            b"main_queries",
            1_usize << geometry.main_log,
            geometry.main_queries as usize,
        )?
        || auxiliary_queries
            != exact_queries(
                &query_seed,
                b"aux_queries",
                1_usize << geometry.auxiliary_log,
                geometry.auxiliary_queries as usize,
            )?
    {
        return Err("query_schedule".to_string());
    }
    let gkr_mask_queries = gkr_mask_tensor_queries(&query_seed, &auxiliary_queries)?;
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
    let expected_squarefree_claims = read_squarefree_claims_payload(&mut reader)?;
    let state_squarefree = read_squarefree_binding(&mut reader, &expected_squarefree_claims)?;
    let h4_source_binding = H4MaskedSourceFunctionalBinding::decode(&read_array::<
        H4_MASKED_SOURCE_FUNCTIONAL_BINDING_BYTES,
    >(&mut reader)?)
    .map_err(|error| format!("h4_source_binding:{error:?}"))?;
    let combination = read_fp16(&mut reader)?;
    let base_auxiliary_coefficients = (0..NON_GKR_AUXILIARY_WORDS)
        .map(|_| read_values(&mut reader, AUXILIARY_DIMENSION as usize))
        .collect::<Result<Vec<_>, _>>()?;
    let base_gkr_mask_coefficients = read_values(&mut reader, GKR_MASK_VALUES)?;
    let expected_target = read_fp16(&mut reader)?;
    let main_coefficients = read_values(&mut reader, geometry.main_dimension as usize)?;
    let mut auxiliary_coefficients = (0..geometry.auxiliary_words)
        .map(|_| read_values(&mut reader, geometry.auxiliary_dimension as usize))
        .collect::<Result<Vec<_>, _>>()?;
    let gkr_mask_coefficients = read_values(&mut reader, GKR_MASK_VALUES)?;
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
        let mut main_target = thread::scope(|scope| {
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
        if auxiliary_coefficients.len() != NON_GKR_AUXILIARY_WORDS as usize
            || gkr_relation_terminals.len() != GKR_MASK_WORDS
        {
            return Err("complete_auxiliary_shape".to_string());
        }
        if !matches!(
            (h4_source_binding.profile(), state_squarefree.capacity),
            (H4ProofProfile::K128, 128) | (H4ProofProfile::K512, 512)
        ) {
            return Err("h4_source_profile".to_string());
        }
        // Capture the two evaluator inputs before the independent square-free
        // gate.  A failed square-free check must not erase the differential
        // evidence needed to compare the known-good source path with the
        // answer-target path.
        let h4_source_functionals = evaluate_h4_masked_source_functional_binding(
            &h4_source_binding,
            &main_coefficients,
            &gkr_mask_coefficients,
            &challenges,
        )
        .map_err(|error| format!("h4_source_functionals:{error:?}"))?;
        let hash_source_vector = main_coefficients[..65_536]
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
        let flat_gkr_mask = gkr_mask_coefficients.clone();
        write_h4_fp16_vector_dump(
            "h4-native-source-coefficients.bin",
            "h4_hash_source_evaluation_vector",
            &hash_source_vector,
        )
        .map_err(|error| format!("h4_differential_dump:{error}"))?;
        write_h4_fp16_vector_dump(
            "h4-native-main-source-coefficients.bin",
            "h4_main_source_coefficients",
            &main_coefficients[..65_536],
        )
        .map_err(|error| format!("h4_differential_dump:{error}"))?;
        write_h4_fp16_vector_dump(
            "h4-native-gkr-mask-coefficients.bin",
            "h4_gkr_mask_coefficients",
            &flat_gkr_mask,
        )
        .map_err(|error| format!("h4_differential_dump:{error}"))?;
        let booleanity_group_point = h4_source_binding.booleanity_group_point();
        let padding_sumcheck_point = h4_source_binding.padding_sumcheck_point();
        write_h4_path_dump(
            "h4-native-path.txt",
            "masked-source-functional",
            &[
                ("booleanity_group_point", &booleanity_group_point),
                ("padding_sumcheck_point", &padding_sumcheck_point),
                ("row_challenges", &challenges),
            ],
            &[
                ("h4_hash_source_evaluation_vector", &hash_source_vector),
                ("h4_main_source_coefficients", &main_coefficients[..65_536]),
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
        for (coefficients, relation_terminal) in gkr_mask_coefficients
            .chunks_exact(GKR_MASK_MESSAGE_VALUES)
            .zip(&gkr_relation_terminals)
        {
            auxiliary_target = auxiliary_target
                + multilinear_evaluate(&coefficients[..GKR_MASK_MESSAGE_VALUES], &challenges)
                    * *relation_terminal
                    * main_scale;
        }
        let raw_coefficient_opening = inner_product(
            &auxiliary_coefficients
                .last()
                .ok_or_else(|| "squarefree_auxiliary_missing".to_string())?
                [..AUXILIARY_MESSAGE_VALUES],
            &state_squarefree.coefficient_functional,
        )?;
        let gkr_mask_opening = gkr_mask_coefficients
            .chunks_exact(GKR_MASK_MESSAGE_VALUES)
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
        let base_raw_coefficient_opening = inner_product(
            &base_auxiliary_coefficients
                .last()
                .ok_or_else(|| "base_squarefree_auxiliary_missing".to_string())?
                [..AUXILIARY_MESSAGE_VALUES],
            &state_squarefree.coefficient_functional,
        )?;
        let base_gkr_mask_opening = base_gkr_mask_coefficients
            .chunks_exact(GKR_MASK_MESSAGE_VALUES)
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
        let expected_squarefree_opening = base_raw_coefficient_opening
            + base_gkr_mask_opening
            + combination * state_squarefree.masked_target;
        if squarefree_opening != expected_squarefree_opening {
            return Err("squarefree_masked_target".to_string());
        }
        auxiliary_target = auxiliary_target + squarefree_opening;
        main_target = main_target + h4_source_functionals.answer_main_functional();
        auxiliary_target =
            auxiliary_target + main_scale * h4_source_functionals.answer_mask_functional();
        let actual_target = main_target * main_scale + auxiliary_target;
        if actual_target != expected_target {
            return Err(format!(
                "answer_target:actual={actual_target:?};expected={expected_target:?};delta={:?};main={main_target:?};auxiliary={auxiliary_target:?};scale={main_scale:?};combination={combination:?};squarefree={squarefree_opening:?};state_masked={:?};h4_masked={:?}",
                actual_target - expected_target,
                state_squarefree.masked_target,
                h4_source_functionals.masked_target(),
            ));
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
    let gkr_mask_tensor_codeword = encode_gkr_mask_tensor(&gkr_mask_coefficients, worker_count)?;
    let gkr_mask_tensor_root = streaming_single_codeword_root(
        &gkr_mask_tensor_codeword,
        GKR_MASK_BOUNDARY,
        GKR_MASK_ANSWER_KIND,
        worker_count,
    )?;

    let stdout = io::stdout();
    let mut writer = BufWriter::with_capacity(1 << 20, stdout.lock());
    writer
        .write_all(OUTPUT_MAGIC)
        .and_then(|_| writer.write_all(&verify_started.elapsed().as_secs_f64().to_be_bytes()))
        .and_then(|_| writer.write_all(&(worker_count as u32).to_be_bytes()))
        .and_then(|_| writer.write_all(&gkr_mask_tensor_root))
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
    for query in gkr_mask_queries {
        writer
            .write_all(&gkr_mask_tensor_codeword[query].encode())
            .map_err(|error| format!("gkr_mask_tensor_output:{error}"))?;
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
    let tensor_codeword = encode_gkr_mask_tensor(&coefficients, workers)?;
    if tensor_codeword.len() != GKR_MASK_TREE_LEAVES {
        return Err("gkr_mask_tensor_shape".to_string());
    }
    let root = streaming_single_codeword_root(
        &tensor_codeword,
        GKR_MASK_BOUNDARY,
        GKR_MASK_KIND,
        workers,
    )?;
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

fn encode_gkr_mask_tensor(coefficients: &[Fp16], workers: usize) -> Result<Vec<Fp16>, String> {
    if coefficients.len() != GKR_MASK_VALUES {
        return Err("gkr_mask_coefficient_shape".to_string());
    }
    let active_workers = workers.clamp(1, GKR_MASK_WORDS);
    let words_per_chunk = GKR_MASK_WORDS.div_ceil(active_workers);
    let inner_codewords = thread::scope(|scope| -> Result<Vec<Vec<Fp16>>, String> {
        let mut handles = Vec::with_capacity(active_workers);
        for coefficient_chunk in coefficients.chunks(words_per_chunk * GKR_MASK_MESSAGE_VALUES) {
            handles.push(scope.spawn(move || {
                coefficient_chunk
                    .chunks_exact(GKR_MASK_MESSAGE_VALUES)
                    .map(|word| encode_codeword(word, GKR_MASK_INNER_LOG, 1))
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
    })?;
    if inner_codewords.len() != GKR_MASK_WORDS
        || inner_codewords
            .iter()
            .any(|codeword| codeword.len() != 1 << GKR_MASK_INNER_LOG)
    {
        return Err("gkr_mask_inner_codeword_shape".to_string());
    }

    // The committed object is one bivariate tensor code, not 64 independently
    // opened inner codewords.  Coefficients are canonical state-major
    // `coefficients[state * 512 + word]`.  Leaves are canonical
    // `(inner_evaluation, outer_evaluation)` order.  At every inner domain
    // point, the 64 state evaluations become the coefficients of one
    // degree-<64 outer polynomial on the frozen 128-point coset.
    let inner_code_values = 1_usize << GKR_MASK_INNER_LOG;
    let mut tensor = vec![Fp16::ZERO; GKR_MASK_TREE_LEAVES];
    let active_workers = workers.clamp(1, inner_code_values);
    let inner_per_chunk = inner_code_values.div_ceil(active_workers);
    thread::scope(|scope| -> Result<(), String> {
        let mut handles = Vec::with_capacity(active_workers);
        for (chunk_ordinal, output) in tensor
            .chunks_mut(inner_per_chunk * GKR_MASK_OUTER_CODE_VALUES)
            .enumerate()
        {
            let inner_start = chunk_ordinal * inner_per_chunk;
            let inner_codewords = &inner_codewords;
            handles.push(scope.spawn(move || -> Result<(), String> {
                let mut outer_coefficients = vec![Fp16::ZERO; GKR_MASK_WORDS];
                for (local_inner, destination) in output
                    .chunks_exact_mut(GKR_MASK_OUTER_CODE_VALUES)
                    .enumerate()
                {
                    let inner = inner_start + local_inner;
                    for (coefficient, codeword) in
                        outer_coefficients.iter_mut().zip(inner_codewords)
                    {
                        *coefficient = codeword[inner];
                    }
                    let encoded = encode_codeword(&outer_coefficients, GKR_MASK_OUTER_LOG, 1)?;
                    destination.copy_from_slice(&encoded);
                }
                outer_coefficients.fill(Fp16::ZERO);
                Ok(())
            }));
        }
        for handle in handles {
            handle
                .join()
                .map_err(|_| "gkr_mask_outer_encode_worker_panic".to_string())??;
        }
        Ok(())
    })?;
    Ok(tensor)
}

fn streaming_single_codeword_root(
    codeword: &[Fp16],
    boundary: u64,
    kind: u64,
    workers: usize,
) -> Result<[u8; 64], String> {
    if codeword.is_empty() || !codeword.len().is_power_of_two() {
        return Err("segment_codeword_shape".to_string());
    }
    let leaf_count = codeword.len();
    let leaf_size = FP16_ENCODED_LENGTH;
    let data_size = leaf_count
        .checked_mul(leaf_size)
        .ok_or_else(|| "segment_data_size".to_string())?;
    let mut frontier: Vec<Option<[u8; 64]>> = vec![None; leaf_count.ilog2() as usize + 1];
    for (batch_ordinal, values) in codeword.chunks(STREAMING_MERKLE_HASH_BATCH).enumerate() {
        let batch_start = batch_ordinal * STREAMING_MERKLE_HASH_BATCH;
        let active_workers = workers.clamp(1, values.len());
        let leaves_per_chunk = values.len().div_ceil(active_workers);
        let mut hashes = vec![[0_u8; 64]; values.len()];
        thread::scope(|scope| {
            for (chunk_ordinal, output) in hashes.chunks_mut(leaves_per_chunk).enumerate() {
                let local_start = chunk_ordinal * leaves_per_chunk;
                let input = &values[local_start..local_start + output.len()];
                scope.spawn(move || {
                    for (offset, (destination, value)) in output.iter_mut().zip(input).enumerate() {
                        let leaf = batch_start + local_start + offset;
                        *destination = segment_leaf_hash(
                            boundary,
                            kind,
                            data_size,
                            leaf_size,
                            leaf,
                            &value.encode(),
                        );
                    }
                });
            }
        });
        for mut node in hashes {
            let mut level = 0_usize;
            loop {
                if let Some(left) = frontier[level].take() {
                    node = hash_parts(MERKLE_NODE_DOMAIN, &[&left, &node]);
                    level += 1;
                } else {
                    frontier[level] = Some(node);
                    break;
                }
            }
        }
    }
    let root_level = leaf_count.ilog2() as usize;
    if frontier[..root_level].iter().any(Option::is_some) {
        return Err("segment_streaming_frontier".to_string());
    }
    let root = frontier[root_level]
        .take()
        .ok_or_else(|| "segment_streaming_root".to_string())?;
    let leaf_count = u64::try_from(leaf_count).map_err(|_| "segment_leaf_count".to_string())?;
    Ok(hash_parts(
        MERKLE_ROOT_DOMAIN,
        &[&leaf_count.to_be_bytes(), &root],
    ))
}

#[cfg(test)]
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

fn exact_queries(
    state: &[u8; 64],
    label: &[u8],
    bound: usize,
    count: usize,
) -> Result<Vec<usize>, String> {
    if bound == 0 || count == 0 || count > bound || bound > u64::MAX as usize {
        return Err("query_geometry".to_string());
    }
    let bound_u64 = bound as u64;
    let threshold = ((1_u128 << 64) - u128::from(bound_u64)) % u128::from(bound_u64);
    let mut queries = Vec::with_capacity(count);
    let mut seen = std::collections::BTreeSet::new();
    let mut draw = 0_u64;
    while queries.len() < count {
        if draw >= QUERY_MAX_DRAWS {
            return Err("query_draw_limit".to_string());
        }
        let mut retry = 0_u64;
        loop {
            if retry >= QUERY_MAX_RETRIES_PER_DRAW {
                return Err("query_retry_limit".to_string());
            }
            let digest = hash_parts(
                QUERY_DOMAIN,
                &[state, label, &draw.to_be_bytes(), &retry.to_be_bytes()],
            );
            let random_word = u64::from_le_bytes(
                digest[..8]
                    .try_into()
                    .map_err(|_| "query_digest".to_string())?,
            );
            let product = u128::from(random_word) * u128::from(bound_u64);
            if (product & u128::from(u64::MAX)) >= threshold {
                let candidate =
                    usize::try_from(product >> 64).map_err(|_| "query_candidate".to_string())?;
                if seen.insert(candidate) {
                    queries.push(candidate);
                    break;
                }
            }
            retry = retry
                .checked_add(1)
                .ok_or_else(|| "query_retry".to_string())?;
        }
        draw = draw
            .checked_add(1)
            .ok_or_else(|| "query_draw".to_string())?;
    }
    queries.sort_unstable();
    Ok(queries)
}

fn gkr_mask_tensor_queries(state: &[u8; 64], inner: &[usize]) -> Result<Vec<usize>, String> {
    let mut queries = Vec::with_capacity(inner.len());
    for (ordinal, inner_query) in inner.iter().copied().enumerate() {
        let ordinal = u64::try_from(ordinal).map_err(|_| "gkr_mask_query_ordinal".to_string())?;
        let inner_u32 =
            u32::try_from(inner_query).map_err(|_| "gkr_mask_inner_query".to_string())?;
        let digest = hash_parts(
            GKR_MASK_OUTER_QUERY_DOMAIN,
            &[
                state,
                GKR_MASK_OUTER_QUERY_LABEL,
                &ordinal.to_be_bytes(),
                &inner_u32.to_be_bytes(),
            ],
        );
        let random_word = u64::from_le_bytes(
            digest[..8]
                .try_into()
                .map_err(|_| "gkr_mask_outer_query".to_string())?,
        );
        let outer =
            usize::try_from((u128::from(random_word) * GKR_MASK_OUTER_CODE_VALUES as u128) >> 64)
                .map_err(|_| "gkr_mask_outer_query".to_string())?;
        queries.push(
            inner_query
                .checked_mul(GKR_MASK_OUTER_CODE_VALUES)
                .and_then(|index| index.checked_add(outer))
                .ok_or_else(|| "gkr_mask_tensor_query".to_string())?,
        );
    }
    if queries.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("gkr_mask_tensor_query_order".to_string());
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
            gkr_mask_functional: vec![Fp16::ZERO; GKR_MASK_VALUES],
            masked_target: Fp16::ZERO,
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
        masked_target,
    })
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
        for log_code in [GKR_MASK_OUTER_LOG, AUXILIARY_LOG, MAIN_LOG] {
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

    #[test]
    fn streaming_single_codeword_root_matches_canonical_tree() {
        let codeword = (0_u32..256)
            .map(|row| {
                let mut coordinates = [0_u32; COMPONENTS];
                coordinates[(row as usize) % COMPONENTS] = row + 1;
                Fp16::from_coefficients(coordinates).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            streaming_single_codeword_root(&codeword, GKR_MASK_BOUNDARY, GKR_MASK_KIND, 4,)
                .unwrap(),
            segment_root(
                core::slice::from_ref(&codeword),
                GKR_MASK_BOUNDARY,
                GKR_MASK_KIND,
                4,
            )
            .unwrap()
        );
    }

    fn recover_old_slice_from_subgroup_openings(mut openings: Vec<Fp16>) -> Vec<Fp16> {
        assert_eq!(openings.len(), GKR_MASK_MESSAGE_VALUES);
        let inverse_root = root_for_log(9).unwrap().inverse().unwrap();
        ntt_in_place(&mut openings, inverse_root, 1);
        let mut count_coordinates = [0_u32; COMPONENTS];
        count_coordinates[0] = GKR_MASK_MESSAGE_VALUES as u32;
        let inverse_count = Fp16::from_coefficients(count_coordinates)
            .unwrap()
            .inverse()
            .unwrap();
        let inverse_coset = frozen_coset().unwrap().inverse().unwrap();
        let mut inverse_coset_power = Fp16::ONE;
        for value in &mut openings {
            *value = *value * inverse_count * inverse_coset_power;
            inverse_coset_power = inverse_coset_power * inverse_coset;
        }
        openings
    }

    #[test]
    fn retired_layout_attack_recovers_all_sixty_four_slices_from_512_openings() {
        let coefficients = (0_u32..GKR_MASK_MESSAGE_VALUES as u32)
            .map(|index| {
                let mut coordinates = [0_u32; COMPONENTS];
                coordinates[(index as usize) % COMPONENTS] = (17 + 65_537 * index) % M31_MODULUS;
                Fp16::from_coefficients(coordinates).unwrap()
            })
            .collect::<Vec<_>>();
        let old_codeword = encode_codeword(&coefficients, GKR_MASK_INNER_LOG, 1).unwrap();
        let subgroup_openings = (0..GKR_MASK_MESSAGE_VALUES)
            .map(|query| old_codeword[query << 4])
            .collect::<Vec<_>>();

        for state in 0_u32..GKR_MASK_WORDS as u32 {
            let mut scale_coordinates = [0_u32; COMPONENTS];
            scale_coordinates[0] = state + 1;
            let scale = Fp16::from_coefficients(scale_coordinates).unwrap();
            let recovered = recover_old_slice_from_subgroup_openings(
                subgroup_openings
                    .iter()
                    .copied()
                    .map(|opening| opening * scale)
                    .collect(),
            );
            assert_eq!(
                recovered,
                coefficients
                    .iter()
                    .copied()
                    .map(|coefficient| coefficient * scale)
                    .collect::<Vec<_>>()
            );
        }
        assert_eq!(GKR_MASK_WORDS * GKR_MASK_MESSAGE_VALUES, GKR_MASK_VALUES);
    }
}
