use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

use bl_pq512_crypto_core::chained_public_coin::{
    ChainedRoundDescriptor, decode_chained_public_coin_bundle, encode_chained_public_coin_bundle,
    verify_chained_public_coin_bundle,
};
use bl_pq512_crypto_core::chained_public_coin_client::ChainedPublicCoinCoordinator;
use bl_pq512_crypto_core::field::{FP16_ENCODED_LENGTH, Fp16, M31};
use bl_pq512_crypto_core::multilinear_pcs::{
    MLPCS_AUXILIARY_LDE_LOG_SIZE, MLPCS_AUXILIARY_MASK_VARIABLES, MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE,
    MLPCS_INPUT_LOG_SIZE, MLPCS_LDE_LOG_SIZE, MLPCS_UNIQUE_QUERY_COUNT, MultilinearOpeningClaim,
    PackedGkrInputClaims, PackedGkrOutputClaim, evaluate_multilinear,
    multilinear_coefficients_to_hypercube,
};
use bl_pq512_crypto_core::multilinear_pcs_proof::{
    AuthenticatedMultilinearPcsChallenges, DualBoundaryMultilinearPcsProof,
    INTERACTIVE_DUAL_BOUNDARY_MLPCS_ROUNDS, SelectedMultilinearPcsProof,
    SelectedMultilinearPcsProofError, prove_interactive_dual_boundary_multilinear_pcs,
    prove_selected_multilinear_pcs_control, verify_interactive_dual_boundary_multilinear_pcs,
    verify_selected_multilinear_pcs_proof,
};
use bl_pq512_crypto_core::packed_boolean_sumcheck::{PACK_BITS, packed_lagrange_node_weights};
use sha3::{Digest, Sha3_512};

const VALUES_PER_LEAF: usize = 16;
const LEAF_BYTES: usize = VALUES_PER_LEAF * FP16_ENCODED_LENGTH;
const M31_MODULUS: u64 = 2_147_483_647;
const INTERACTIVE_PCS_SCHEDULE_DOMAIN: &[u8] =
    b"BL/PQ512/WAVE2/INTERACTIVE-DUAL-MLPCS-SCHEDULE/v1\0";

fn fp(value: u32) -> Fp16 {
    Fp16::from_m31(M31::from_canonical(value).expect("control scalar is canonical"))
}

fn full_coefficient(index: usize) -> Fp16 {
    Fp16::from_coefficients(core::array::from_fn(|coordinate| {
        ((index as u64 * 1_140_071_481 + (coordinate as u64 + 1) * 977) % M31_MODULUS) as u32
    }))
    .expect("control coefficient is canonical")
}

fn auxiliary_hypercube() -> Vec<Fp16> {
    let coefficients = (0..1_usize << MLPCS_AUXILIARY_MASK_VARIABLES)
        .map(full_coefficient)
        .collect::<Vec<_>>();
    multilinear_coefficients_to_hypercube(&coefficients)
        .expect("selected auxiliary coefficient geometry is valid")
}

fn read_codeword_from_reader(
    reader: &mut dyn Read,
    log_size: u8,
) -> Result<Vec<Fp16>, Box<dyn std::error::Error>> {
    let value_count = 1_usize << log_size;
    let mut values = vec![Fp16::ZERO; value_count];
    let mut payload = [0_u8; LEAF_BYTES];
    for leaf in values.chunks_exact_mut(VALUES_PER_LEAF) {
        reader.read_exact(&mut payload)?;
        for (value, encoded) in leaf
            .iter_mut()
            .zip(payload.chunks_exact(FP16_ENCODED_LENGTH))
        {
            *value = Fp16::decode(encoded)?;
        }
    }
    let mut trailing = [0_u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err("codeword has trailing bytes".into());
    }
    Ok(values)
}

fn read_codeword(path: &Path, log_size: u8) -> Result<Vec<Fp16>, Box<dyn std::error::Error>> {
    let value_count = 1_usize << log_size;
    let expected_bytes = u64::try_from(value_count)?
        .checked_mul(u64::try_from(FP16_ENCODED_LENGTH)?)
        .ok_or("codeword byte length overflow")?;
    let file = File::open(path)?;
    if file.metadata()?.len() != expected_bytes {
        return Err(format!(
            "{} has {} bytes, expected {expected_bytes}",
            path.display(),
            file.metadata()?.len()
        )
        .into());
    }
    let mut reader = BufReader::with_capacity(16 << 20, file);
    read_codeword_from_reader(&mut reader, log_size)
}

fn read_cuda_codeword(
    python: &Path,
    worker: &Path,
    coefficient_path: &Path,
    opening_path: &Path,
) -> Result<Vec<Fp16>, Box<dyn std::error::Error>> {
    let mut child = Command::new(python)
        .arg(worker)
        .arg("25")
        .arg("main")
        .arg("-")
        .arg(coefficient_path)
        .arg(opening_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let mut reader = BufReader::with_capacity(
        16 << 20,
        child.stdout.take().ok_or("cuda worker stdout missing")?,
    );
    let values = read_codeword_from_reader(&mut reader, MLPCS_LDE_LOG_SIZE)?;
    drop(reader);
    if !child.wait()?.success() {
        return Err("cuda codeword worker failed".into());
    }
    Ok(values)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct GkrBoundaryClaims {
    input: PackedGkrInputClaims,
    output: PackedGkrOutputClaim,
}

fn read_openings(path: &Path) -> Result<GkrBoundaryClaims, Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut header = [0_u8; 16];
    reader.read_exact(&mut header)?;
    if &header[..8] != b"BLGKPCS2"
        || header[10] != 18
        || header[11] != 11
        || header[12..].iter().any(|byte| *byte != 0)
    {
        return Err("opening manifest header".into());
    }
    let wire_variables = header[8];
    let point_length = usize::from(header[9]);
    let mut encoded = [0_u8; FP16_ENCODED_LENGTH];
    reader.read_exact(&mut encoded)?;
    let shard_query = Fp16::decode(&encoded)?;
    let mut claims = Vec::with_capacity(2);
    for _ in 0..2 {
        let mut point = Vec::with_capacity(point_length);
        for _ in 0..point_length {
            reader.read_exact(&mut encoded)?;
            point.push(Fp16::decode(&encoded)?);
        }
        reader.read_exact(&mut encoded)?;
        claims.push(MultilinearOpeningClaim {
            point,
            value: Fp16::decode(&encoded)?,
        });
    }
    reader.read_exact(&mut encoded)?;
    let digest_shard_query = Fp16::decode(&encoded)?;
    let mut digest_point = Vec::with_capacity(usize::from(header[10]));
    for _ in 0..usize::from(header[10]) {
        reader.read_exact(&mut encoded)?;
        digest_point.push(Fp16::decode(&encoded)?);
    }
    reader.read_exact(&mut encoded)?;
    let digest_value = Fp16::decode(&encoded)?;
    for _ in 0..3 {
        reader.read_exact(&mut encoded)?;
        let _ = Fp16::decode(&encoded)?;
    }
    let mut trailing = [0_u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err("opening manifest trailing bytes".into());
    }
    Ok(GkrBoundaryClaims {
        input: PackedGkrInputClaims {
            claims: claims.try_into().map_err(|_| "opening claim count")?,
            shard_query,
            wire_variables,
        },
        output: PackedGkrOutputClaim {
            claim: MultilinearOpeningClaim {
                point: digest_point,
                value: digest_value,
            },
            shard_query: digest_shard_query,
            wire_variables: header[11],
        },
    })
}

fn interpolate_shards(evaluations: &[Fp16], shard_query: Fp16, wire_variables: u8) -> Vec<Fp16> {
    let wire_count = 1_usize << wire_variables;
    let group_count = evaluations.len() / (wire_count * PACK_BITS);
    let lagrange =
        packed_lagrange_node_weights(shard_query).expect("control shard query must interpolate");
    let mut interpolated = vec![Fp16::ZERO; wire_count * group_count];
    for group in 0..group_count {
        for wire in 0..wire_count {
            interpolated[group * wire_count + wire] =
                (0..PACK_BITS).fold(Fp16::ZERO, |sum, shard| {
                    let raw_index = wire + wire_count * (shard + PACK_BITS * group);
                    sum + lagrange[shard] * evaluations[raw_index]
                });
        }
    }
    interpolated
}

fn run_dual(arguments: &[std::ffi::OsString]) -> Result<(), Box<dyn std::error::Error>> {
    if arguments.len() != 7 && arguments.len() != 9 {
        return Err(
            "usage: mlpcs_complete_control_benchmark --dual <input-codeword|-> \
             <output-codeword|-> <aux-codeword> <input-coefficients> \
             <output-coefficients> <output-endpoints> <GKR-openings> \
             [cuda-python cuda-worker]"
                .into(),
        );
    }
    let input_path = Path::new(&arguments[0]);
    let output_path = Path::new(&arguments[1]);
    let auxiliary_path = Path::new(&arguments[2]);
    let input_coefficient_path = Path::new(&arguments[3]);
    let output_coefficient_path = Path::new(&arguments[4]);
    let output_endpoint_path = Path::new(&arguments[5]);
    let opening_path = Path::new(&arguments[6]);
    let cuda = (arguments.len() == 9).then(|| (Path::new(&arguments[7]), Path::new(&arguments[8])));
    let input_is_pipe = input_path == Path::new("-");
    let output_is_pipe = output_path == Path::new("-");
    if input_is_pipe != output_is_pipe || input_is_pipe != cuda.is_some() {
        return Err("dual CUDA argument shape invalid".into());
    }

    let load_started = Instant::now();
    let input_codeword = if let Some((python, worker)) = cuda {
        read_cuda_codeword(python, worker, input_coefficient_path, opening_path)?
    } else {
        read_codeword(input_path, MLPCS_LDE_LOG_SIZE)?
    };
    let output_codeword = if let Some((python, worker)) = cuda {
        read_cuda_codeword(
            python,
            worker,
            output_coefficient_path,
            output_endpoint_path,
        )?
    } else {
        read_codeword(output_path, MLPCS_LDE_LOG_SIZE)?
    };
    let auxiliary_codeword = read_codeword(auxiliary_path, MLPCS_AUXILIARY_LDE_LOG_SIZE)?;
    let load_seconds = load_started.elapsed().as_secs_f64();

    let hypercube_started = Instant::now();
    let input_coefficients =
        read_codeword(input_coefficient_path, MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE)?;
    let input_hypercube = multilinear_coefficients_to_hypercube(&input_coefficients)?;
    drop(input_coefficients);
    let output_coefficients =
        read_codeword(output_coefficient_path, MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE)?;
    let output_hypercube = multilinear_coefficients_to_hypercube(&output_coefficients)?;
    drop(output_coefficients);
    let auxiliary_hypercube = auxiliary_hypercube();
    let hypercube_seconds = hypercube_started.elapsed().as_secs_f64();

    let boundary_claims = read_openings(opening_path)?;
    let interpolated_input = interpolate_shards(
        &input_hypercube[..1_usize << MLPCS_INPUT_LOG_SIZE],
        boundary_claims.input.shard_query,
        boundary_claims.input.wire_variables,
    );
    for claim in &boundary_claims.input.claims {
        if evaluate_multilinear(&interpolated_input, &claim.point)? != claim.value {
            return Err("GKR opening does not match committed input".into());
        }
    }
    drop(interpolated_input);
    let interpolated_output = interpolate_shards(
        &output_hypercube[..1_usize << MLPCS_INPUT_LOG_SIZE],
        boundary_claims.output.shard_query,
        boundary_claims.output.wire_variables,
    );
    if evaluate_multilinear(&interpolated_output, &boundary_claims.output.claim.point)?
        != boundary_claims.output.claim.value
    {
        return Err("GKR opening does not match committed semantic output".into());
    }
    drop(interpolated_output);

    let mut session_id = [0_u8; 64];
    getrandom::fill(&mut session_id).map_err(|_| "public coin session entropy")?;
    let mut schedule_hash = Sha3_512::new();
    schedule_hash.update(INTERACTIVE_PCS_SCHEDULE_DOMAIN);
    schedule_hash.update(INTERACTIVE_DUAL_BOUNDARY_MLPCS_ROUNDS.to_be_bytes());
    schedule_hash.update(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE.to_be_bytes());
    schedule_hash.update(MLPCS_LDE_LOG_SIZE.to_be_bytes());
    schedule_hash.update(MLPCS_AUXILIARY_LDE_LOG_SIZE.to_be_bytes());
    schedule_hash.update((MLPCS_UNIQUE_QUERY_COUNT as u32).to_be_bytes());
    let schedule_commitment: [u8; 64] = schedule_hash.finalize().into();
    let service_path = std::env::current_exe()?
        .parent()
        .ok_or("public coin executable parent")?
        .join("chained_public_coin_service.exe");
    let mut public_coin = ChainedPublicCoinCoordinator::spawn(
        &service_path,
        session_id,
        0,
        schedule_commitment,
        INTERACTIVE_DUAL_BOUNDARY_MLPCS_ROUNDS,
    )
    .map_err(|error| format!("public coin spawn: {error:?}"))?;
    let mut issued_challenges =
        Vec::with_capacity(usize::try_from(INTERACTIVE_DUAL_BOUNDARY_MLPCS_ROUNDS)?);
    let prove_started = Instant::now();
    let interactive = prove_interactive_dual_boundary_multilinear_pcs(
        input_hypercube,
        output_hypercube,
        auxiliary_hypercube,
        input_codeword,
        output_codeword,
        auxiliary_codeword,
        &boundary_claims.input,
        &boundary_claims.output,
        session_id,
        |kind, ordinal, message| {
            let value = public_coin
                .scalar_challenge(
                    ChainedRoundDescriptor {
                        kind,
                        ordinal,
                        output_count: 1,
                    },
                    message,
                )
                .map_err(|_| SelectedMultilinearPcsProofError::PublicCoin)?;
            issued_challenges.push(value);
            Ok(value)
        },
    )?;
    let prove_and_internal_verify_seconds = prove_started.elapsed().as_secs_f64();
    let public_coin_bundle = public_coin
        .finish_bundle()
        .map_err(|error| format!("public coin finish: {error:?}"))?;
    if public_coin_bundle
        .rounds
        .iter()
        .map(|round| round.prover_message.as_slice())
        .ne(interactive.prover_messages.iter().map(Vec::as_slice))
    {
        return Err("public coin prover-message mismatch".into());
    }
    let public_coin_encoded = encode_chained_public_coin_bundle(&public_coin_bundle)?;
    let decoded_public_coin = decode_chained_public_coin_bundle(&public_coin_encoded)?;
    let replayed_challenges = verify_chained_public_coin_bundle(&decoded_public_coin)?;
    if replayed_challenges.len() != issued_challenges.len()
        || replayed_challenges
            .iter()
            .zip(&issued_challenges)
            .any(|(replayed, issued)| replayed.field_elements.as_slice() != [*issued])
    {
        return Err("independent public coin replay mismatch".into());
    }
    let public_coin_sha3_512: [u8; 64] = Sha3_512::digest(&public_coin_encoded).into();
    let challenges = interactive.challenges;
    let output = interactive.pcs;
    let encode_started = Instant::now();
    let encoded = output.proof.encode(&challenges.queries)?;
    let encode_seconds = encode_started.elapsed().as_secs_f64();
    let proof_sha3_512: [u8; 64] = Sha3_512::digest(&encoded).into();
    let independent_started = Instant::now();
    let decoded = DualBoundaryMultilinearPcsProof::decode(&encoded, &challenges.queries)?;
    let replayed_scalars = replayed_challenges
        .iter()
        .map(|replayed| replayed.field_elements[0])
        .collect::<Vec<_>>();
    let replayed_pcs_challenges = verify_interactive_dual_boundary_multilinear_pcs(
        &decoded,
        output.input_root,
        output.output_root,
        output.auxiliary_root,
        &boundary_claims.input,
        &boundary_claims.output,
        session_id,
        &replayed_scalars,
        &interactive.prover_messages,
    )?;
    if replayed_pcs_challenges != challenges {
        return Err("independent PCS challenge reconstruction mismatch".into());
    }
    let independent_verify_seconds = independent_started.elapsed().as_secs_f64();

    println!("status=verified");
    println!("semantic_input_bus_opening_verified=true");
    println!("semantic_output_bus_opening_verified=true");
    println!("two_initial_roots_shared_fri=true");
    println!("authenticated_public_coin=true");
    println!("public_coin_independent_replay=true");
    println!("public_coin_rounds={}", public_coin_bundle.rounds.len());
    println!("public_coin_bundle_bytes={}", public_coin_encoded.len());
    println!("public_coin_bundle_sha3_512={}", hex(&public_coin_sha3_512));
    println!("public_coin_session_id={}", hex(&session_id));
    println!(
        "public_coin_final_transcript_root={}",
        hex(&public_coin_bundle.claimed_final_transcript_root)
    );
    println!("load_seconds={load_seconds:.9}");
    println!("hypercube_seconds={hypercube_seconds:.9}");
    println!("prove_and_internal_verify_seconds={prove_and_internal_verify_seconds:.9}");
    println!("encode_seconds={encode_seconds:.9}");
    println!("independent_verify_seconds={independent_verify_seconds:.9}");
    println!("proof_bytes={}", encoded.len());
    println!("proof_sha3_512={}", hex(&proof_sha3_512));
    println!("input_root={}", hex(output.input_root.as_bytes()));
    println!("output_root={}", hex(output.output_root.as_bytes()));
    println!("auxiliary_root={}", hex(output.auxiliary_root.as_bytes()));
    println!(
        "opening_values={},{},{}",
        hex(&output.opening_values[0].encode()),
        hex(&output.opening_values[1].encode()),
        hex(&output.opening_values[2].encode())
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let supplied = std::env::args_os().skip(1).collect::<Vec<_>>();
    if supplied.first().is_some_and(|value| value == "--dual") {
        return run_dual(&supplied[1..]);
    }
    let mut arguments = supplied.into_iter();
    let main_path = arguments
        .next()
        .ok_or("usage: mlpcs_complete_control_benchmark <main-codeword> <aux-codeword>")?;
    let auxiliary_path = arguments.next().ok_or("auxiliary codeword missing")?;
    let coefficient_path = arguments.next().ok_or("main coefficients missing")?;
    let opening_path = arguments.next().ok_or("GKR openings missing")?;
    let cuda_python = arguments.next().map(std::path::PathBuf::from);
    let cuda_worker = arguments.next().map(std::path::PathBuf::from);
    if cuda_python.is_some() != cuda_worker.is_some() || arguments.next().is_some() {
        return Err("unexpected trailing argument".into());
    }

    let load_started = Instant::now();
    let main_codeword = match (&cuda_python, &cuda_worker) {
        (Some(python), Some(worker)) if Path::new(&main_path) == Path::new("-") => {
            read_cuda_codeword(
                python,
                worker,
                Path::new(&coefficient_path),
                Path::new(&opening_path),
            )?
        }
        (None, None) if Path::new(&main_path) != Path::new("-") => {
            read_codeword(Path::new(&main_path), MLPCS_LDE_LOG_SIZE)?
        }
        _ => return Err("cuda codeword argument shape invalid".into()),
    };
    let auxiliary_codeword =
        read_codeword(Path::new(&auxiliary_path), MLPCS_AUXILIARY_LDE_LOG_SIZE)?;
    let load_seconds = load_started.elapsed().as_secs_f64();

    let hypercube_started = Instant::now();
    let main_coefficients = read_codeword(
        Path::new(&coefficient_path),
        MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE,
    )?;
    let main_hypercube = multilinear_coefficients_to_hypercube(&main_coefficients)?;
    let auxiliary_hypercube = auxiliary_hypercube();
    let hypercube_seconds = hypercube_started.elapsed().as_secs_f64();

    let boundary_claims = read_openings(Path::new(&opening_path))?;
    let opening_claims = boundary_claims.input;
    let interpolated_input = interpolate_shards(
        &main_hypercube[..1_usize << MLPCS_INPUT_LOG_SIZE],
        opening_claims.shard_query,
        opening_claims.wire_variables,
    );
    for claim in &opening_claims.claims {
        if evaluate_multilinear(&interpolated_input, &claim.point)? != claim.value {
            return Err("GKR opening does not match committed input".into());
        }
    }
    let challenges = AuthenticatedMultilinearPcsChallenges {
        main_binding: fp(20_011),
        auxiliary_binding: fp(20_021),
        opening_mixing: fp(20_022),
        batch_mixing: fp(20_023),
        fold: (0..MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE)
            .map(|index| fp(30_001 + 2 * u32::from(index)))
            .collect(),
        auxiliary_mixing: fp(40_009),
        queries: (0..MLPCS_UNIQUE_QUERY_COUNT)
            .map(|index| (index * 65_537 + 17) % (1_usize << MLPCS_LDE_LOG_SIZE))
            .collect(),
    };

    let prove_started = Instant::now();
    let output = prove_selected_multilinear_pcs_control(
        main_hypercube,
        auxiliary_hypercube,
        main_codeword,
        auxiliary_codeword,
        &opening_claims,
        &challenges,
    )?;
    let prove_and_internal_verify_seconds = prove_started.elapsed().as_secs_f64();

    let encode_started = Instant::now();
    let encoded = output.proof.encode(&challenges.queries)?;
    let encode_seconds = encode_started.elapsed().as_secs_f64();
    let proof_sha3_512: [u8; 64] = Sha3_512::digest(&encoded).into();

    let independent_started = Instant::now();
    let decoded = SelectedMultilinearPcsProof::decode(&encoded, &challenges.queries)?;
    verify_selected_multilinear_pcs_proof(
        &decoded,
        output.main_root,
        output.auxiliary_root,
        &opening_claims,
        &challenges,
    )?;
    let independent_verify_seconds = independent_started.elapsed().as_secs_f64();

    println!("status=verified");
    println!(
        "digest_bus_claim_coordinates={}",
        boundary_claims.output.claim.point.len()
    );
    println!(
        "digest_bus_claim_shard_query={}",
        hex(&boundary_claims.output.shard_query.encode())
    );
    println!(
        "digest_bus_claim_value={}",
        hex(&boundary_claims.output.claim.value.encode())
    );
    println!("semantic_digest_bus_opening_verified=false");
    println!("load_seconds={load_seconds:.9}");
    println!("hypercube_seconds={hypercube_seconds:.9}");
    println!("prove_and_internal_verify_seconds={prove_and_internal_verify_seconds:.9}");
    println!("encode_seconds={encode_seconds:.9}");
    println!("independent_verify_seconds={independent_verify_seconds:.9}");
    println!("proof_bytes={}", encoded.len());
    println!("proof_sha3_512={}", hex(&proof_sha3_512));
    println!("main_root={}", hex(output.main_root.as_bytes()));
    println!("auxiliary_root={}", hex(output.auxiliary_root.as_bytes()));
    println!(
        "opening_values={},{}",
        hex(&output.opening_values[0].encode()),
        hex(&output.opening_values[1].encode())
    );
    Ok(())
}
