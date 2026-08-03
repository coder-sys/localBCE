use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

use bl_pq512_crypto_core::{
    air_ir::{
        AIR_PROGRAM_MAGIC, NamedExecutionTable, evaluate_air_execution, validate_air_program,
        validated_execution_named_tables, validated_execution_public_inputs,
        validated_execution_traces,
    },
    field::M31,
    hash_bus::{
        GROUP_COUNT, PERMUTATIONS_PER_COPROCESSOR_SHARD, build_hash_bus_descriptor,
        build_hash_bus_descriptor_with_state, state_root_capacity,
    },
    hash_bus_b16_boundary::{HashBusB16BoundaryFile, HashBusB16Shard},
    hash_bus_b16_gkr_plan::HashBusB16GkrPlan,
    hash_bus_source::KECCAK_STATE_BITS,
    ordered_map_schedule::build_ordered_map_batch_schedule,
    selected_proof_package::verify_selected_proof_package,
    sha3_air::{RATE_BYTES, for_each_sha3_512_permutation_boundary},
    state_relation_gkr::{
        StateRelationEntry, StateRelationRow, build_state_relation_wire_source,
        state_relation_source_digest,
    },
    wave1a_global_schedule::Profile,
};
use sha3::{Digest, Sha3_512};

const ATOMIC_PARENT_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/ATOMIC-SEMANTIC-PARENT/v3\0";
const ATOMIC_RECEIPT_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/ATOMIC-SEMANTIC-RECEIPT/v2\0";
const STATE_ROOT_DOMAIN: &[u8] = b"BL/PQ512/STATE-PLANE/ROOT/v1\0";
const STATE_MANIFEST_DOMAIN: &[u8] = b"BL/PQ512/STATE-PLANE/MANIFEST/v1\0";
const STATE_PROJECTION_DOMAIN: &[u8] = b"BL/PQ512/STATE-PLANE/PROJECTION/v1\0";
const STATE_TRANSITION_DOMAIN: &[u8] = b"BL/PQ512/STATE-PLANE/TRANSITION/v1\0";
const STATE_STATEMENT_DOMAIN: &[u8] = b"BL/PQ512/STATE-PLANE/STATEMENT/v1\0";
const HASH_PAD_TAG_DOMAIN: &[u8] = b"BL/PQ512/SHA3-HASH-PAD/TAG/v1\0";
const HASH_PAD_COMMITMENT_DOMAIN: &[u8] = b"BL/PQ512/SHA3-HASH-PAD/COMMITMENT/v1\0";
const STATE_PROOF_DOMAIN: &[u8] = b"BL/PQ512/STATE-PLANE/PROOF/v1\0";
const STATE_ATTEMPT_DOMAIN: &[u8] = b"BL/PQ512/STATE-PLANE/ATTEMPT/v1\0";
const STATE_RECEIPT_DOMAIN: &[u8] = b"BL/PQ512/STATE-PLANE/RECEIPT/v1\0";
const STATE_BINDING_DOMAIN: &[u8] = b"BL/PQ512/STATE-PLANE/H4-BINDING-INPUT/v1\0";
const STATE_AIR_FRAGMENT_DOMAIN: &[u8] = b"BL/PQ512/STATE-PLANE/AIR-FRAGMENT/v1\0";
const H4_COMPOSITION_DOMAIN: &[u8] = b"BL/PQ512/STATE-PLANE/H4-COMPOSITION/v1\0";
const COMPOSED_STATE_BINDING_DOMAIN: &[u8] = b"BL/PQ512/STATE-PLANE/H4-BINDING-INPUT/v2\0";
const COMPOSED_STATE_AIR_FRAGMENT_DOMAIN: &[u8] = b"BL/PQ512/STATE-PLANE/AIR-FRAGMENT/v2\0";
const COMPOSED_H4_COMPOSITION_DOMAIN: &[u8] = b"BL/PQ512/STATE-PLANE/H4-COMPOSITION/v2\0";
const STATE_AIR_PROOF_DOMAIN: &[u8] = b"BL/PQ512/STATE-AIR-PROOF/v1\0";
const EXECUTION_MANIFEST_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/EXECUTION-MANIFEST/v1\0";
const STATE_BINDING_MAGIC: &[u8] = b"BLSB01";
const STATE_AIR_FRAGMENT_MAGIC: &[u8] = b"BLSA01";
const STATE_MAGIC: &[u8] = b"BLSP01";
const COMMITMENT_MAGIC: &[u8] = b"BLHP01";
const STATE_VERSION: u8 = 1;
const STATE_BINDING_VERSION: u8 = 2;
const STATE_AIR_FRAGMENT_VERSION: u8 = 1;
const COMMITMENT_VERSION: u8 = 1;
const STATE_MAX_CAPACITY: u64 = 4_096;
const STATE_AIR_PACKED_CHUNK_BYTES: usize = 3;
const STATE_AIR_PACKED_CHUNKS: usize = 22;
const STATE_AIR_RELATION_COLUMNS: usize = 91;
const STATE_AIR_SNAPSHOT_COLUMNS: usize = 1 + 1 + (2 * STATE_AIR_PACKED_CHUNKS);
const STATE_BINDING_MAX_BYTES: u64 = 256 * 1024 * 1024;
const STATE_AIR_PROGRAM_ID: &[u8] = b"BL-PQ512-STATE-ROOT-AIR-v1";
const STATE_RELATION_AIR_PROGRAM_ID: &[u8] = b"BL-PQ512-STATE-RELATION-AIR-v2";
const STATE_AIR_COMPONENT_ID: &[u8] = b"BL-PQ512-STATE-AIR-PROOF-V1";
const TYPED_STATE_COMPONENT_ID: &[u8] = b"BL-PQ512-C0-TYPED-STATE-AIR-V1";
const TYPED_STATE_AIR_PROGRAM_ID: &[u8] = b"BL-PQ512-C0-TYPED-STATE-AIR-v3";
const TYPED_STATE_LOG_MESSAGE_LANES: usize = 64;
const TYPED_STATE_FRAGMENT_MAGIC: &[u8] = b"BLSA03";
const TYPED_STATE_PROOF_DOMAIN: &[u8] = b"BL/PQ512/STATE-AIR-PROOF/v1\0";
const TYPED_STATE_PROJECTION_DOMAIN: &[u8] = b"BL/PQ512/C0/TYPED-STATE-PROJECTION/v1\0";
const TYPED_STATE_PROJECTION_DIGEST_DOMAIN: &[u8] =
    b"BL/PQ512/C0/TYPED-STATE-PROJECTION-DIGEST/v1\0";
const TYPED_STATE_STATEMENT_DOMAIN: &[u8] = b"BL/PQ512/C0/TYPED-STATE-STATEMENT/v1\0";
const TYPED_STATE_TRANSITION_DOMAIN: &[u8] = b"BL/PQ512/C0/TYPED-STATE-TRANSITION/v1\0";
const TYPED_STATE_PUBLIC_COIN_DOMAIN: &[u8] = b"BL/PQ512/C0/TYPED-STATE-PUBLIC-COIN/v1\0";
const TYPED_STATE_COMMITMENT_DOMAIN: &[u8] = b"BL/PQ512/C0/TYPED-STATE-COMMITMENT/v1\0";
const TYPED_STATE_PROOF_IDENTITY_DOMAIN: &[u8] = b"BL/PQ512/C0/TYPED-STATE-PROOF/v1\0";
const TYPED_STATE_ATTEMPT_DOMAIN: &[u8] = b"BL/PQ512/C0/TYPED-STATE-ATTEMPT/v1\0";
const TYPED_STATE_RECEIPT_DOMAIN: &[u8] = b"BL/PQ512/C0/TYPED-STATE-RECEIPT/v1\0";
const TYPED_STATE_FRAGMENT_DOMAIN: &[u8] = b"BL/PQ512/C0/TYPED-STATE-FRAGMENT/v1\0";
const TYPED_STATE_COMPOSITION_DOMAIN: &[u8] = b"BL/PQ512/C0/TYPED-STATE-COMPOSITION/v1\0";
const TYPED_STATE_BINDING_DOMAIN: &[u8] = b"BL/PQ512/C0/TYPED-STATE-BINDING/v1\0";
const TYPED_STATE_VERIFIER_IDENTITY: &[u8] = b"BL/PQ512/C0/TYPED-STATE/INDEPENDENT-VERIFIER/v1\0";
const C0_STATE_ROOT_DOMAIN: &[u8] = b"BL/PQ512/C0/STATE-ROOT/v1\0";
const PAYMENT_STATE_DOMAIN: &[u8] = b"BL/PQ512/PAYMENT-MAP/STATE/v4";
const STATE_PARAMETER_IDENTITY: &[u8] = b"BL-PQ512-STATE-PLANE-V1";
const HASH_PAD_PARAMETER_IDENTITY: &[u8] = b"BL-PQ512-SHA3-HASH-PAD-V1";
const K128_SHARDS: u16 = 1;
const K128_FILE_BYTES: u64 = 52_429_015;
const K512_SHARDS: u16 = 4;
const K512_FILE_BYTES: u64 = 209_715_415;
const MAX_IDENTITY_FILE_BYTES: u64 = 16_000_000;
const MAX_CHILD_STDOUT: usize = 1 << 20;
const MAX_CHILD_STDERR: usize = 1 << 16;
const CUDA_DEPENDENCIES: [&str; 12] = [
    "cuda_fp16_zk_rs_interleaved_k128_prototype.py",
    "cuda_dag_packed_accumulator_benchmark.py",
    "cuda_fp16_tower_kat.py",
    "cuda_m31_brakedown_factor_benchmark.py",
    "cuda_m31_brakedown_k128_prototype.py",
    "cuda_m31_sha3_matrix_benchmark.py",
    "cuda_m31_segment_merkle.py",
    "cuda_pcs_sha3_merkle_benchmark.py",
    "cuda_sparse_round_kat.py",
    "cuda_dag_shared_group_fold_benchmark.py",
    "cuda_dag_shared_group_message_benchmark.py",
    "cuda_fp16_b16_binary_bridge_benchmark.py",
];
const NATIVE_EXECUTABLES: [&str; 8] = [
    "fp16_zk_rs_interleaved_verify.exe",
    "fp16_zk_rs_theorem8_1_transcript.exe",
    "fp16_zk_rs_spotcheck_verify.exe",
    "fp16_zk_rs_answer_code_verify.exe",
    "fp16_zk_rs_answer_target.exe",
    "fp16_zk_rs_row_sumcheck_prover.exe",
    "fp16_zk_rs_public_coin_bridge.exe",
    "chained_public_coin_service.exe",
];
const WORKER_CUDA_MODULES: [(&str, &str); 3] = [
    ("gkr_bridge_cuda_module", "hash-bus-gkr-bridge-sm89.cubin"),
    ("gkr_group_cuda_module", "hash-bus-gkr-group-sm89.cubin"),
    ("gkr_worker_cuda_module", "hash-bus-gkr-worker-sm89.cubin"),
];

struct ShardEvidence {
    wall_seconds: f64,
    host_peak_mb: f64,
    device_peak_mb: f64,
    scratch_mb: f64,
    stdout_digest: [u8; 64],
    bundle_digest: [u8; 64],
}

struct StateBindingVerification {
    typed_state: bool,
    state_profile: Vec<u8>,
    state_capacity: u64,
    before_snapshot: Vec<u8>,
    after_snapshot: Vec<u8>,
    statement: [u8; 64],
    binding_digest: [u8; 64],
    projection: [[u8; 32]; 12],
    projection_digest: [u8; 64],
    public_coin: [u8; 64],
    transition: [u8; 64],
    commitment: [u8; 64],
    proof: [u8; 64],
    verifier: [u8; 64],
    attempt: [u8; 64],
    receipt: [u8; 64],
    state_air_program: [u8; 64],
    state_air_execution: [u8; 64],
    state_air_fragment: [u8; 64],
    composition: [u8; 64],
    typed_state_root_before: [u8; 64],
    typed_state_root_after: [u8; 64],
    typed_air_execution: Option<Vec<u8>>,
    state_relation_rows: Option<Vec<StateRelationRow>>,
    state_relation_source_digest: [u8; 64],
}

struct PrivateStateRelationSource {
    path: PathBuf,
    digest: [u8; 64],
}

impl Drop for PrivateStateRelationSource {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ERR:{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if let [flag, path] = arguments.as_slice()
        && flag == "--verify-state-binding"
    {
        let verification = verify_state_binding(Path::new(path))?;
        println!("state_plane_binding_verified=true");
        println!(
            "state_plane_statement_sha3_512={}",
            hex(&verification.statement)
        );
        println!(
            "state_plane_binding_digest_sha3_512={}",
            hex(&verification.binding_digest)
        );
        return Ok(());
    }
    if let [flag, python, prototype, worker, cuda_module] = arguments.as_slice()
        && flag == "--print-execution-manifest"
    {
        let native_directory = env::current_exe()
            .map_err(|error| format!("current_exe:{error}"))?
            .parent()
            .ok_or_else(|| "native_directory".to_string())?
            .to_path_buf();
        let manifest = execution_manifest(
            Path::new(python),
            Path::new(prototype),
            Path::new(worker),
            &native_directory,
            Path::new(cuda_module),
        )?;
        println!("execution_manifest_sha3_512={}", hex(&manifest));
        return Ok(());
    }
    let [boundary, python, prototype, worker, statement] = arguments.as_slice() else {
        return Err(
            "usage:k512_atomic_semantic_prototype BOUNDARY PYTHON PROTOTYPE WORKER STATEMENT_SHA3_512"
                .to_string(),
        );
    };
    let boundary = PathBuf::from(boundary);
    let python = PathBuf::from(python);
    let prototype = PathBuf::from(prototype);
    let worker = PathBuf::from(worker);
    let statement_path = PathBuf::from(statement.as_os_str());
    for (label, path) in [
        ("boundary", boundary.as_path()),
        ("python", python.as_path()),
        ("prototype", prototype.as_path()),
        ("worker", worker.as_path()),
    ] {
        if !path.is_file() {
            return Err(format!("{label}_missing:{}", path.display()));
        }
    }
    let statement_argument = statement_path.to_string_lossy();
    let explicit_state_path = statement_argument
        .strip_prefix("state-file:")
        .map(Path::new);
    let state_binding = if let Some(path) = explicit_state_path {
        Some(verify_state_binding(path)?)
    } else if statement_path.is_file() {
        Some(verify_state_binding(&statement_path)?)
    } else {
        None
    };
    let statement = match state_binding.as_ref() {
        Some(binding) => binding.statement,
        None => decode_hex_64(&statement_argument, "statement")?,
    };
    if !statement.iter().any(|byte| *byte != 0) {
        return Err("statement_zero".to_string());
    }

    let mut boundary_file =
        HashBusB16BoundaryFile::open(&boundary).map_err(|error| format!("boundary:{error:?}"))?;
    let header = boundary_file.header().clone();
    let (expected_shards, expected_file_bytes, profile_name, latency_limit_seconds) =
        match header.profile {
            Profile::K128Calibration => (K128_SHARDS, K128_FILE_BYTES, "k128", 30.0),
            Profile::K512Calibration => (K512_SHARDS, K512_FILE_BYTES, "k512", 180.0),
            Profile::K256DesignPoint => return Err("boundary_profile".to_string()),
        };
    if header.coprocessor_shards != expected_shards || header.file_bytes != expected_file_bytes {
        return Err("boundary_shape".to_string());
    }
    if header.state_composed != state_binding.is_some() {
        return Err("state_hash_bus_composition_mode".to_string());
    }
    if let Some(binding) = state_binding.as_ref() {
        validate_state_profile_for_h4(header.profile, binding)?;
        verify_state_hash_bus_calls(&mut boundary_file, &header, binding)?;
    }
    let plan_commitment = HashBusB16GkrPlan::selected()
        .and_then(|plan| plan.commitment())
        .map_err(|error| format!("plan:{error:?}"))?;
    let native_directory = env::current_exe()
        .map_err(|error| format!("current_exe:{error}"))?
        .parent()
        .ok_or_else(|| "native_directory".to_string())?
        .to_path_buf();
    let cuda_module = PathBuf::from(
        env::var_os("BL_PRECOMPILED_CUDA_MODULE")
            .ok_or_else(|| "precompiled_cuda_module_env".to_string())?,
    );
    let execution_manifest = execution_manifest(
        &python,
        &prototype,
        &worker,
        &native_directory,
        &cuda_module,
    )?;
    let expected_manifest = decode_hex_64(
        &env::var("BL_EXECUTION_MANIFEST_SHA3_512")
            .map_err(|_| "execution_manifest_env".to_string())?,
        "execution_manifest",
    )?;
    if execution_manifest != expected_manifest {
        return Err(format!(
            "execution_manifest_mismatch:{}/{}",
            hex(&execution_manifest),
            hex(&expected_manifest)
        ));
    }
    let private_state_relation_source = state_binding
        .as_ref()
        .filter(|binding| !binding.typed_state)
        .map(write_private_state_relation_source)
        .transpose()?;
    let parent_binding = atomic_parent_binding(
        header.profile as u8,
        header.semantic_program_commitment,
        header.descriptor_commitment,
        header.semantic_port_commitment,
        header.coprocessor_shards,
        header.padded_permutations,
        header.live_wires,
        header.file_bytes,
        header.file_sha3_512,
        plan_commitment,
        execution_manifest,
        statement,
        state_binding.as_ref(),
    );
    let parent_hex = hex(&parent_binding);
    let file_hex = hex(&header.file_sha3_512);
    let expected_state_statement = state_binding
        .as_ref()
        .map(|binding| hex(&binding.statement));
    let expected_state_binding = state_binding
        .as_ref()
        .map(|binding| hex(&binding.binding_digest));

    let total_started = Instant::now();
    let mut evidence = Vec::with_capacity(usize::from(expected_shards));
    for shard in 0..expected_shards {
        let shard_started = Instant::now();
        let mut child = Command::new(&python);
        child
            .arg("-S")
            .arg(&prototype)
            .env("BL_HASH_BUS_B16_BOUNDARY", &boundary)
            .env("BL_HASH_BUS_B16_SHARD", shard.to_string())
            .env("BL_HASH_BUS_GKR_WORKER", &worker)
            .env("BL_ATOMIC_PARENT_BINDING", &parent_hex)
            .env("BL_NATIVE_RELEASE_DIR", &native_directory)
            .env(
                "BL_MULTIPROOF_VERIFIER",
                native_directory.join(NATIVE_EXECUTABLES[0]),
            )
            .env(
                "BL_SPOTCHECK_VERIFIER",
                native_directory.join(NATIVE_EXECUTABLES[2]),
            );
        if let Some(binding) = state_binding.as_ref() {
            child
                .env("BL_STATE_PLANE_STATEMENT_DIGEST", hex(&binding.statement))
                .env(
                    "BL_STATE_PLANE_BINDING_DIGEST",
                    hex(&binding.binding_digest),
                )
                .env(
                    "BL_STATE_PLANE_PROJECTION_DIGEST",
                    hex(&binding.projection_digest),
                )
                .env("BL_STATE_PLANE_PUBLIC_COIN", hex(&binding.public_coin))
                .env("BL_STATE_PLANE_TRANSITION_DIGEST", hex(&binding.transition))
                .env("BL_STATE_PLANE_COMMITMENT_DIGEST", hex(&binding.commitment))
                .env("BL_STATE_PLANE_PROOF_IDENTITY", hex(&binding.proof))
                .env("BL_STATE_PLANE_VERIFIER_IDENTITY", hex(&binding.verifier))
                .env("BL_STATE_PLANE_ATTEMPT_ID", hex(&binding.attempt))
                .env("BL_STATE_PLANE_RECEIPT_DIGEST", hex(&binding.receipt))
                .env(
                    "BL_STATE_PLANE_COMPOSITION_DIGEST",
                    hex(&binding.composition),
                )
                .env(
                    "BL_STATE_AIR_PROGRAM_COMMITMENT",
                    hex(&binding.state_air_program),
                )
                .env(
                    "BL_STATE_AIR_EXECUTION_COMMITMENT",
                    hex(&binding.state_air_execution),
                )
                .env(
                    "BL_STATE_AIR_FRAGMENT_DIGEST",
                    hex(&binding.state_air_fragment),
                );
            if binding.typed_state {
                child
                    .env("BL_TYPED_STATE_BINDING", "1")
                    .env(
                        "BL_TYPED_STATE_ROOT_BEFORE",
                        hex(&binding.typed_state_root_before),
                    )
                    .env(
                        "BL_TYPED_STATE_ROOT_AFTER",
                        hex(&binding.typed_state_root_after),
                    );
            } else {
                let source = private_state_relation_source
                    .as_ref()
                    .ok_or_else(|| "state_relation_source_missing".to_string())?;
                child
                    .env("BL_STATE_RELATION_SOURCE_PATH", source.path.as_os_str())
                    .env("BL_STATE_RELATION_SOURCE_SHA3_512", hex(&source.digest));
            }
            for (index, field) in binding.projection.iter().enumerate() {
                child.env(format!("BL_STATE_PLANE_PUBLIC_ABI_{index:02}"), hex(field));
            }
        }
        let output = child
            .output()
            .map_err(|error| format!("shard_spawn:{shard}:{error}"))?;
        if output.stdout.len() > MAX_CHILD_STDOUT || output.stderr.len() > MAX_CHILD_STDERR {
            return Err(format!("shard_output_bound:{shard}"));
        }
        if !output.status.success() || !output.stderr.is_empty() {
            return Err(format!(
                "shard_process:{shard}:status={:?}:stderr={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        let fields = parse_fields(&output.stdout)?;
        validate_shard_fields(
            &fields,
            shard,
            header.profile as u8,
            &file_hex,
            &parent_hex,
            expected_state_statement.as_deref(),
            expected_state_binding.as_deref(),
            state_binding.as_ref(),
        )?;
        let wall_seconds = parse_f64(&fields, "complete_process_wall_seconds")?;
        let host_peak_mb = parse_f64(&fields, "proof_phase_host_peak_mb")?
            .max(parse_f64(&fields, "parent_process_lifetime_host_peak_mb")?)
            .max(parse_f64(&fields, "native_verifier_peak_mb")?);
        let device_peak_mb = parse_f64(&fields, "tracked_device_peak_mb")?;
        let scratch_mb = parse_f64(&fields, "scratch_mb")?;
        if wall_seconds <= 0.0
            || host_peak_mb <= 0.0
            || host_peak_mb > 5_000.0
            || device_peak_mb <= 0.0
            || device_peak_mb > 5_000.0
            || !(0.0..5_000.0).contains(&scratch_mb)
        {
            return Err(format!("shard_resource_gate:{shard}"));
        }
        let bundle_digest = decode_hex_64(
            required(&fields, "public_coin_bundle_sha3_512")?,
            "bundle_digest",
        )?;
        evidence.push(ShardEvidence {
            wall_seconds,
            host_peak_mb,
            device_peak_mb,
            scratch_mb,
            stdout_digest: Sha3_512::digest(&output.stdout).into(),
            bundle_digest,
        });
        println!("shard_{shard}_verified=true");
        println!("shard_{shard}_proof_seconds={wall_seconds:.6}");
        println!(
            "shard_{shard}_coordinator_wall_seconds={:.6}",
            shard_started.elapsed().as_secs_f64()
        );
    }

    let receipt = match state_binding.as_ref() {
        Some(binding) => atomic_receipt_with_state(parent_binding, statement, binding, &evidence),
        None => atomic_receipt(parent_binding, statement, &evidence),
    };
    let total_seconds = total_started.elapsed().as_secs_f64();
    let peak_host_mb = evidence
        .iter()
        .map(|item| item.host_peak_mb)
        .fold(0.0_f64, f64::max);
    let peak_device_mb = evidence
        .iter()
        .map(|item| item.device_peak_mb)
        .fold(0.0_f64, f64::max);
    let peak_scratch_mb = evidence
        .iter()
        .map(|item| item.scratch_mb)
        .fold(0.0_f64, f64::max);
    println!("status=verified");
    println!("evidence_class={profile_name}_atomic_semantic_prototype");
    println!("atomic_parent_binding_sha3_512={parent_hex}");
    println!("atomic_statement_sha3_512={}", hex(&statement));
    println!("state_plane_binding_verified={}", state_binding.is_some());
    println!(
        "state_plane_binding_digest_sha3_512={}",
        state_binding
            .as_ref()
            .map_or_else(|| hex(&[0; 64]), |binding| hex(&binding.binding_digest))
    );
    println!("state_hash_bus_calls_verified={}", state_binding.is_some());
    println!("execution_manifest_sha3_512={}", hex(&execution_manifest));
    println!("semantic_hash_bus_file_sha3_512={file_hex}");
    println!(
        "ordered_shards={}",
        (0..expected_shards)
            .map(|shard| shard.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("complete_shard_proofs={expected_shards}");
    println!("sequential_single_gpu_execution=true");
    println!("parallel_gpu_images=0");
    println!("theorem_free_challenge_sharing=false");
    println!("atomic_acceptance_boundary=true");
    println!("all_shards_independently_verified=true");
    println!("atomic_receipt_sha3_512={}", hex(&receipt));
    println!("complete_process_wall_seconds={total_seconds:.6}");
    println!("peak_host_mb={peak_host_mb:.6}");
    println!("peak_device_mb={peak_device_mb:.6}");
    println!("scratch_mb={peak_scratch_mb:.6}");
    println!("latency_limit_seconds={latency_limit_seconds:.0}");
    println!(
        "complete_proof_latency_gate={}",
        total_seconds < latency_limit_seconds
    );
    println!("complete_proof_qualification=false");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn atomic_parent_binding(
    profile: u8,
    semantic_program_commitment: [u8; 64],
    descriptor_commitment: [u8; 64],
    semantic_port_commitment: [u8; 64],
    shards: u16,
    padded_permutations: u64,
    live_wires: u16,
    file_bytes: u64,
    file_digest: [u8; 64],
    plan_commitment: [u8; 64],
    execution_manifest: [u8; 64],
    statement: [u8; 64],
    state_binding: Option<&StateBindingVerification>,
) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(ATOMIC_PARENT_DOMAIN);
    hash.update([profile]);
    hash.update(semantic_program_commitment);
    hash.update(descriptor_commitment);
    hash.update(semantic_port_commitment);
    hash.update(shards.to_be_bytes());
    hash.update(padded_permutations.to_be_bytes());
    hash.update(live_wires.to_be_bytes());
    hash.update(file_bytes.to_be_bytes());
    hash.update(file_digest);
    hash.update(plan_commitment);
    hash.update(execution_manifest);
    hash.update(statement);
    update_state_context(&mut hash, state_binding);
    hash.finalize().into()
}

fn update_state_context(hash: &mut Sha3_512, state: Option<&StateBindingVerification>) {
    if let Some(state) = state {
        hash.update(state.statement);
        hash.update(state.binding_digest);
        hash.update(state.projection_digest);
        hash.update(state.public_coin);
        hash.update(state.transition);
        hash.update(state.commitment);
        hash.update(state.proof);
        hash.update(state.verifier);
        hash.update(state.attempt);
        hash.update(state.receipt);
        hash.update(state.composition);
        hash.update(state.state_air_program);
        hash.update(state.state_air_execution);
        hash.update(state.state_air_fragment);
        hash.update(state.state_relation_source_digest);
        for field in state.projection {
            hash.update(field);
        }
        if state.typed_state {
            hash.update([1_u8]);
            hash.update(state.typed_state_root_before);
            hash.update(state.typed_state_root_after);
        }
    } else {
        // Preserve the accepted no-state H4 parent identity.  The extended
        // state context is present only when a state binding is attached.
        hash.update([0; 64]);
    }
}

fn execution_manifest(
    python: &Path,
    prototype: &Path,
    worker: &Path,
    native_directory: &Path,
    cuda_module: &Path,
) -> Result<[u8; 64], String> {
    let cuda_directory = prototype
        .parent()
        .ok_or_else(|| "prototype_directory".to_string())?;
    if worker.parent() != Some(cuda_directory)
        || worker.file_name().and_then(|name| name.to_str())
            != Some("cuda_hash_bus_b16_gkr_worker.py")
        || prototype.file_name().and_then(|name| name.to_str())
            != Some("cuda_fp16_zk_rs_theorem8_1_k128_prototype.py")
    {
        return Err("execution_source_layout".to_string());
    }
    let mut files = vec![
        ("python", python.to_path_buf()),
        ("prototype", prototype.to_path_buf()),
        ("semantic_worker", worker.to_path_buf()),
        ("precompiled_cuda_module", cuda_module.to_path_buf()),
    ];
    let cuda_module_directory = cuda_module
        .parent()
        .ok_or_else(|| "cuda_module_directory".to_string())?;
    files.extend(
        WORKER_CUDA_MODULES
            .iter()
            .map(|(label, name)| (*label, cuda_module_directory.join(name))),
    );
    files.extend(
        CUDA_DEPENDENCIES
            .iter()
            .map(|name| (*name, cuda_directory.join(name))),
    );
    files.extend(
        NATIVE_EXECUTABLES
            .iter()
            .map(|name| (*name, native_directory.join(name))),
    );
    let mut hash = Sha3_512::new();
    hash.update(EXECUTION_MANIFEST_DOMAIN);
    hash.update((files.len() as u16).to_be_bytes());
    for (label, path) in files {
        let metadata = fs::metadata(&path)
            .map_err(|error| format!("execution_file:{label}:{}:{error}", path.display()))?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_IDENTITY_FILE_BYTES {
            return Err(format!(
                "execution_file_shape:{label}:{}:{}",
                path.display(),
                metadata.len()
            ));
        }
        let bytes = fs::read(&path)
            .map_err(|error| format!("execution_file_read:{label}:{}:{error}", path.display()))?;
        let label = label.as_bytes();
        let label_length = u16::try_from(label.len()).map_err(|_| "execution_label".to_string())?;
        hash.update(label_length.to_be_bytes());
        hash.update(label);
        hash.update(metadata.len().to_be_bytes());
        hash.update(Sha3_512::digest(&bytes));
    }
    Ok(hash.finalize().into())
}

fn atomic_receipt(
    parent_binding: [u8; 64],
    statement: [u8; 64],
    evidence: &[ShardEvidence],
) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(ATOMIC_RECEIPT_DOMAIN);
    hash.update(parent_binding);
    hash.update(statement);
    hash.update((evidence.len() as u16).to_be_bytes());
    for (shard, item) in evidence.iter().enumerate() {
        hash.update((shard as u16).to_be_bytes());
        hash.update(item.stdout_digest);
        hash.update(item.bundle_digest);
        hash.update(item.wall_seconds.to_bits().to_be_bytes());
        hash.update(item.host_peak_mb.to_bits().to_be_bytes());
        hash.update(item.device_peak_mb.to_bits().to_be_bytes());
        hash.update(item.scratch_mb.to_bits().to_be_bytes());
    }
    hash.finalize().into()
}

fn atomic_receipt_with_state(
    parent_binding: [u8; 64],
    statement: [u8; 64],
    state_binding: &StateBindingVerification,
    evidence: &[ShardEvidence],
) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(ATOMIC_RECEIPT_DOMAIN);
    hash.update(parent_binding);
    hash.update(statement);
    update_state_context(&mut hash, Some(state_binding));
    hash.update((evidence.len() as u16).to_be_bytes());
    for (shard, item) in evidence.iter().enumerate() {
        hash.update((shard as u16).to_be_bytes());
        hash.update(item.stdout_digest);
        hash.update(item.bundle_digest);
        hash.update(item.wall_seconds.to_bits().to_be_bytes());
        hash.update(item.host_peak_mb.to_bits().to_be_bytes());
        hash.update(item.device_peak_mb.to_bits().to_be_bytes());
        hash.update(item.scratch_mb.to_bits().to_be_bytes());
    }
    hash.finalize().into()
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(domain);
    for part in parts {
        hash.update(
            u32::try_from(part.len())
                .expect("state binding part length fits u32")
                .to_be_bytes(),
        );
        hash.update(part);
    }
    hash.finalize().into()
}

struct StateCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> StateCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize, label: &str) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| format!("state_binding_{label}_overflow"))?;
        if end > self.bytes.len() {
            return Err(format!("state_binding_{label}_truncated"));
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self, label: &str) -> Result<u8, String> {
        Ok(self.take(1, label)?[0])
    }

    fn u32(&mut self, label: &str) -> Result<u32, String> {
        Ok(u32::from_be_bytes(
            self.take(4, label)?.try_into().expect("u32 length"),
        ))
    }

    fn u64(&mut self, label: &str) -> Result<u64, String> {
        Ok(u64::from_be_bytes(
            self.take(8, label)?.try_into().expect("u64 length"),
        ))
    }

    fn array64(&mut self, label: &str) -> Result<[u8; 64], String> {
        Ok(self.take(64, label)?.try_into().expect("array64 length"))
    }

    fn text(&mut self, maximum: usize, label: &str) -> Result<Vec<u8>, String> {
        let length = usize::from(self.u8(label)?);
        if length == 0 || length > maximum {
            return Err(format!("state_binding_{label}_length"));
        }
        let value = self.take(length, label)?.to_vec();
        if !value.iter().all(u8::is_ascii) || value.contains(&0) {
            return Err(format!("state_binding_{label}_encoding"));
        }
        Ok(value)
    }

    fn done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct StateEntryWire {
    index: u64,
    present: bool,
    key: [u8; 64],
    value: [u8; 64],
}

fn to_state_relation_entry(entry: &StateEntryWire) -> StateRelationEntry {
    StateRelationEntry {
        index: u32::try_from(entry.index).expect("state capacity is bounded to u32"),
        present: entry.present,
        key: entry.key,
        value: entry.value,
    }
}

fn write_private_state_relation_source(
    state: &StateBindingVerification,
) -> Result<PrivateStateRelationSource, String> {
    let rows = state
        .state_relation_rows
        .as_deref()
        .ok_or_else(|| "state_relation_rows_missing".to_string())?;
    let encoded = build_state_relation_wire_source(rows)
        .map_err(|error| format!("state_relation_source_build:{error:?}"))?;
    let digest = state_relation_source_digest(&encoded);
    if digest != state.state_relation_source_digest {
        return Err("state_relation_source_digest_mismatch".to_string());
    }
    for suffix in 0_u32..1024 {
        let path = env::temp_dir().join(format!(
            "bl-pq512-state-relation-{}-{suffix}.bin",
            std::process::id()
        ));
        let mut file = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("state_relation_source_open:{error}")),
        };
        if let Err(error) = file.write_all(&encoded) {
            let _ = fs::remove_file(&path);
            return Err(format!("state_relation_source_write:{error}"));
        }
        if let Err(error) = file.sync_all() {
            let _ = fs::remove_file(&path);
            return Err(format!("state_relation_source_sync:{error}"));
        }
        return Ok(PrivateStateRelationSource { path, digest });
    }
    Err("state_relation_source_name_exhausted".to_string())
}

struct StateSnapshotWire {
    encoded: Vec<u8>,
    profile: Vec<u8>,
    parameter: Vec<u8>,
    capacity: u64,
    epoch: u64,
    sequence: u64,
    entries: Vec<StateEntryWire>,
    root: [u8; 64],
}

fn validate_snapshot_unique_keys(entries: &[StateEntryWire]) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for entry in entries.iter().filter(|entry| entry.present) {
        if !seen.insert(entry.key) {
            return Err("state_binding_snapshot_duplicate_key".to_string());
        }
    }
    Ok(())
}

fn parse_state_snapshot(encoded: &[u8]) -> Result<StateSnapshotWire, String> {
    let mut cursor = StateCursor::new(encoded);
    if cursor.take(6, "snapshot_magic")? != STATE_MAGIC {
        return Err("state_binding_snapshot_magic".to_string());
    }
    if cursor.u8("snapshot_version")? != STATE_VERSION {
        return Err("state_binding_snapshot_version".to_string());
    }
    let profile = cursor.text(64, "snapshot_profile")?;
    let parameter = cursor.text(64, "snapshot_parameter")?;
    let capacity = cursor.u64("snapshot_capacity")?;
    let epoch = cursor.u64("snapshot_epoch")?;
    let sequence = cursor.u64("snapshot_sequence")?;
    if capacity == 0 || capacity > STATE_MAX_CAPACITY {
        return Err("state_binding_snapshot_capacity".to_string());
    }
    let mut entries = Vec::with_capacity(capacity as usize);
    for expected_index in 0..capacity {
        let present = match cursor.u8("snapshot_entry_present")? {
            0 => false,
            1 => true,
            _ => return Err("state_binding_snapshot_entry_present".to_string()),
        };
        let index = cursor.u64("snapshot_entry_index")?;
        if index != expected_index {
            return Err("state_binding_snapshot_entry_index".to_string());
        }
        entries.push(StateEntryWire {
            index,
            present,
            key: cursor.array64("snapshot_entry_key")?,
            value: cursor.array64("snapshot_entry_value")?,
        });
        if !present
            && (entries.last().unwrap().key != [0; 64] || entries.last().unwrap().value != [0; 64])
        {
            return Err("state_binding_snapshot_empty_private_bytes".to_string());
        }
    }
    validate_snapshot_unique_keys(&entries)?;
    if !cursor.done() {
        return Err("state_binding_snapshot_trailing_bytes".to_string());
    }
    let root = hash_parts(STATE_ROOT_DOMAIN, &[encoded]);
    Ok(StateSnapshotWire {
        encoded: encoded.to_vec(),
        profile,
        parameter,
        capacity,
        epoch,
        sequence,
        entries,
        root,
    })
}

fn parse_state_operation(
    cursor: &mut StateCursor<'_>,
) -> Result<(u64, StateEntryWire, StateEntryWire, Vec<u8>), String> {
    let start = cursor.offset;
    let before_present = match cursor.u8("operation_before_present")? {
        0 => false,
        1 => true,
        _ => return Err("state_binding_operation_before_present".to_string()),
    };
    let before_index = cursor.u64("operation_before_index")?;
    let before = StateEntryWire {
        index: before_index,
        present: before_present,
        key: cursor.array64("operation_before_key")?,
        value: cursor.array64("operation_before_value")?,
    };
    let after_present = match cursor.u8("operation_after_present")? {
        0 => false,
        1 => true,
        _ => return Err("state_binding_operation_after_present".to_string()),
    };
    let after_index = cursor.u64("operation_after_index")?;
    let after = StateEntryWire {
        index: after_index,
        present: after_present,
        key: cursor.array64("operation_after_key")?,
        value: cursor.array64("operation_after_value")?,
    };
    if !before_present && (before.key != [0; 64] || before.value != [0; 64])
        || !after_present && (after.key != [0; 64] || after.value != [0; 64])
    {
        return Err("state_binding_operation_empty_private_bytes".to_string());
    }
    let encoded = cursor.bytes[start..cursor.offset].to_vec();
    if before_index != after_index {
        return Err("state_binding_operation_index_mismatch".to_string());
    }
    Ok((before_index, before, after, encoded))
}

fn packed_state_chunk(value: &[u8; 64], chunk: usize) -> u32 {
    let start = chunk * STATE_AIR_PACKED_CHUNK_BYTES;
    value[start..(start + STATE_AIR_PACKED_CHUNK_BYTES).min(value.len())]
        .iter()
        .fold(0_u32, |accumulator, byte| {
            (accumulator << 8) | u32::from(*byte)
        })
}

fn require_trace_value(value: M31, expected: u32, label: &str) -> Result<(), String> {
    if value.as_u32() != expected {
        return Err(format!("state_air_trace_{label}"));
    }
    Ok(())
}

fn verify_compact_state_trace(
    traces: &[Vec<Vec<M31>>],
    operations: &[(StateEntryWire, StateEntryWire)],
    before_snapshot: &[StateEntryWire],
    after_snapshot: &[StateEntryWire],
    before_root: &[u8; 64],
    after_root: &[u8; 64],
) -> Result<(), String> {
    let capacity = operations.len();
    if traces.len() != 4 {
        return Err("state_air_trace_table_count".to_string());
    }
    let relation = &traces[0];
    let before_slots = &traces[1];
    let after_slots = &traces[2];
    let roots = &traces[3];
    if relation.len() != STATE_AIR_RELATION_COLUMNS
        || relation.iter().any(|column| column.len() != capacity)
        || before_slots.len() != STATE_AIR_SNAPSHOT_COLUMNS
        || before_slots.iter().any(|column| column.len() != capacity)
        || after_slots.len() != STATE_AIR_SNAPSHOT_COLUMNS
        || after_slots.iter().any(|column| column.len() != capacity)
        || roots.len() != 65
        || roots.iter().any(|column| column.len() != 2)
    {
        return Err("state_air_trace_shape".to_string());
    }
    for (row, (before, after)) in operations.iter().enumerate() {
        require_trace_value(
            relation[0][row],
            u32::try_from(row).map_err(|_| "state_air_trace_index".to_string())?,
            "index",
        )?;
        for (entry, present_column, key_column, value_column, label) in [
            (before, 1_usize, 2_usize, 24_usize, "before"),
            (after, 46_usize, 47_usize, 69_usize, "after"),
        ] {
            require_trace_value(
                relation[present_column][row],
                u32::from(entry.present),
                &format!("{label}_present_{row}"),
            )?;
            for chunk in 0..STATE_AIR_PACKED_CHUNKS {
                require_trace_value(
                    relation[key_column + chunk][row],
                    packed_state_chunk(&entry.key, chunk),
                    &format!("{label}_key_{row}_{chunk}"),
                )?;
                require_trace_value(
                    relation[value_column + chunk][row],
                    packed_state_chunk(&entry.value, chunk),
                    &format!("{label}_value_{row}_{chunk}"),
                )?;
            }
        }
    }
    for (table, entries, label) in [
        (before_slots, before_snapshot, "before_snapshot"),
        (after_slots, after_snapshot, "after_snapshot"),
    ] {
        if entries.len() != capacity {
            return Err(format!("state_air_{label}_entry_count"));
        }
        for (row, entry) in entries.iter().enumerate() {
            require_trace_value(
                table[0][row],
                u32::try_from(row).map_err(|_| "state_air_trace_index".to_string())?,
                &format!("{label}_index_{row}"),
            )?;
            require_trace_value(
                table[1][row],
                u32::from(entry.present),
                &format!("{label}_present_{row}"),
            )?;
            for chunk in 0..STATE_AIR_PACKED_CHUNKS {
                require_trace_value(
                    table[2 + chunk][row],
                    packed_state_chunk(&entry.key, chunk),
                    &format!("{label}_key_{row}_{chunk}"),
                )?;
                require_trace_value(
                    table[2 + STATE_AIR_PACKED_CHUNKS + chunk][row],
                    packed_state_chunk(&entry.value, chunk),
                    &format!("{label}_value_{row}_{chunk}"),
                )?;
            }
        }
    }
    for (row, root) in [before_root, after_root].into_iter().enumerate() {
        require_trace_value(roots[0][row], row as u32, "root_call_index")?;
        for (byte, expected) in root.iter().copied().enumerate() {
            require_trace_value(roots[byte + 1][row], u32::from(expected), "root_byte")?;
        }
    }
    Ok(())
}

struct CommitmentWire {
    parameter: Vec<u8>,
    public_coin: [u8; 64],
    ciphertext: [u8; 64],
    tag: [u8; 64],
    digest: [u8; 64],
}

fn parse_commitment(encoded: &[u8]) -> Result<CommitmentWire, String> {
    let mut cursor = StateCursor::new(encoded);
    if cursor.take(6, "commitment_magic")? != COMMITMENT_MAGIC {
        return Err("state_binding_commitment_magic".to_string());
    }
    if cursor.u8("commitment_version")? != COMMITMENT_VERSION {
        return Err("state_binding_commitment_version".to_string());
    }
    let parameter = cursor.text(64, "commitment_parameter")?;
    let public_coin = cursor.array64("commitment_public_coin")?;
    let ciphertext = cursor.array64("commitment_ciphertext")?;
    let tag = cursor.array64("commitment_tag")?;
    let digest = cursor.array64("commitment_digest")?;
    if !cursor.done() {
        return Err("state_binding_commitment_trailing_bytes".to_string());
    }
    if parameter != HASH_PAD_PARAMETER_IDENTITY || digest == [0; 64] || tag == [0; 64] {
        return Err("state_binding_commitment_parameter".to_string());
    }
    Ok(CommitmentWire {
        parameter,
        public_coin,
        ciphertext,
        tag,
        digest,
    })
}

fn validate_state_air_program_id(encoded: &[u8], expected_program_id: &[u8]) -> Result<(), String> {
    let header_length = AIR_PROGRAM_MAGIC.len() + 2 + 64 + 2;
    if encoded.len() < header_length
        || encoded.get(..AIR_PROGRAM_MAGIC.len()) != Some(AIR_PROGRAM_MAGIC.as_slice())
    {
        return Err("state_binding_air_program_magic".to_string());
    }
    let length_offset = AIR_PROGRAM_MAGIC.len() + 2 + 64;
    let identifier_length = usize::from(u16::from_be_bytes(
        encoded[length_offset..length_offset + 2]
            .try_into()
            .expect("program identifier length"),
    ));
    let identifier_start = length_offset + 2;
    let identifier_end = identifier_start
        .checked_add(identifier_length)
        .ok_or_else(|| "state_binding_air_program_identifier_overflow".to_string())?;
    if encoded.get(identifier_start..identifier_end) != Some(expected_program_id) {
        return Err("state_binding_air_program_identifier".to_string());
    }
    Ok(())
}

fn verify_state_binding(path: &Path) -> Result<StateBindingVerification, String> {
    if path.is_symlink() {
        return Err("state_binding_symlink_forbidden".to_string());
    }
    let metadata = fs::metadata(path).map_err(|error| format!("state_binding_metadata:{error}"))?;
    if !metadata.is_file() || metadata.len() < 7 || metadata.len() > STATE_BINDING_MAX_BYTES {
        return Err("state_binding_file_shape".to_string());
    }
    let mut prefix = [0_u8; 7];
    fs::File::open(path)
        .map_err(|error| format!("state_binding_read:{error}"))?
        .read_exact(&mut prefix)
        .map_err(|error| format!("state_binding_read:{error}"))?;
    if prefix[..6] != STATE_BINDING_MAGIC[..] {
        return Err("state_binding_magic".to_string());
    }
    match prefix[6] {
        2 => verify_state_binding_v2(path),
        3 => verify_state_binding_v3(path),
        4 => verify_typed_state_binding_v4(path),
        _ => Err("state_binding_version".to_string()),
    }
}

fn verify_state_binding_v2(path: &Path) -> Result<StateBindingVerification, String> {
    if path.is_symlink() {
        return Err("state_binding_symlink_forbidden".to_string());
    }
    let metadata = fs::metadata(path).map_err(|error| format!("state_binding_metadata:{error}"))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > STATE_BINDING_MAX_BYTES {
        return Err("state_binding_file_shape".to_string());
    }
    let encoded = fs::read(path).map_err(|error| format!("state_binding_read:{error}"))?;
    let mut cursor = StateCursor::new(&encoded);
    if cursor.take(6, "binding_magic")? != STATE_BINDING_MAGIC {
        return Err("state_binding_magic".to_string());
    }
    if cursor.u8("binding_version")? != STATE_BINDING_VERSION {
        return Err("state_binding_version".to_string());
    }
    let before_length = usize::try_from(cursor.u32("before_length")?)
        .map_err(|_| "state_binding_before_length".to_string())?;
    let before = parse_state_snapshot(cursor.take(before_length, "before")?)?;
    let after_length = usize::try_from(cursor.u32("after_length")?)
        .map_err(|_| "state_binding_after_length".to_string())?;
    let after = parse_state_snapshot(cursor.take(after_length, "after")?)?;
    if before.profile != after.profile
        || before.parameter != after.parameter
        || before.capacity != after.capacity
        || before.epoch != after.epoch
        || after.sequence != before.sequence + 1
        || before.parameter != STATE_PARAMETER_IDENTITY
    {
        return Err("state_binding_snapshot_layout".to_string());
    }

    let operation_count = cursor.u64("operation_count")?;
    if operation_count != before.capacity {
        return Err("state_binding_operation_count".to_string());
    }
    let mut operations_encoded = Vec::new();
    let mut expected_after = before.entries.clone();
    for expected_index in 0..operation_count {
        let (index, operation_before, operation_after, operation_encoded) =
            parse_state_operation(&mut cursor)?;
        if index != expected_index || operation_before != before.entries[index as usize] {
            return Err("state_binding_operation_before".to_string());
        }
        expected_after[index as usize] = operation_after;
        operations_encoded.extend(operation_encoded);
    }
    if expected_after != after.entries {
        return Err("state_binding_operation_after".to_string());
    }

    let mut projection = Vec::with_capacity(12);
    for _ in 0..12 {
        let field: [u8; 32] = cursor
            .take(32, "projection")?
            .try_into()
            .expect("projection length");
        if field == [0; 32] {
            return Err("state_binding_projection_zero".to_string());
        }
        projection.push(field);
    }
    let public_coin = cursor.array64("public_coin")?;
    if public_coin == [0; 64] {
        return Err("state_binding_public_coin_zero".to_string());
    }
    let commitment_length = usize::try_from(cursor.u32("commitment_length")?)
        .map_err(|_| "state_binding_commitment_length".to_string())?;
    let commitment = parse_commitment(cursor.take(commitment_length, "commitment")?)?;
    let opening_statement = cursor.array64("opening_statement")?;
    let opening_mask = cursor.array64("opening_mask")?;
    if commitment.public_coin != public_coin {
        return Err("state_binding_commitment_public_coin".to_string());
    }
    if cursor.take(6, "air_fragment_magic")? != STATE_AIR_FRAGMENT_MAGIC {
        return Err("state_binding_air_fragment_magic".to_string());
    }
    if cursor.u8("air_fragment_version")? != STATE_AIR_FRAGMENT_VERSION {
        return Err("state_binding_air_fragment_version".to_string());
    }
    let air_program_length = usize::try_from(cursor.u32("air_program_length")?)
        .map_err(|_| "state_binding_air_program_length".to_string())?;
    if air_program_length == 0 {
        return Err("state_binding_air_program_empty".to_string());
    }
    let air_program = cursor.take(air_program_length, "air_program")?;
    let air_execution_length = usize::try_from(cursor.u32("air_execution_length")?)
        .map_err(|_| "state_binding_air_execution_length".to_string())?;
    if air_execution_length == 0 {
        return Err("state_binding_air_execution_empty".to_string());
    }
    let air_execution = cursor.take(air_execution_length, "air_execution")?;
    if !cursor.done() {
        return Err("state_binding_trailing_bytes".to_string());
    }
    validate_state_air_program_id(air_program, STATE_AIR_PROGRAM_ID)?;
    let air_program_report = validate_air_program(air_program)
        .map_err(|error| format!("state_binding_air_program:{error:?}"))?;
    let air_execution_report = evaluate_air_execution(air_execution)
        .map_err(|error| format!("state_binding_air_execution:{error:?}"))?;
    if air_program_report.source_program_commitment
        != air_execution_report.source_program_commitment
        || air_program_report.public_input_count != 128
    {
        return Err("state_binding_air_program_execution_identity".to_string());
    }
    let public_inputs = validated_execution_public_inputs(air_execution)
        .map_err(|error| format!("state_binding_air_public_inputs:{error:?}"))?;
    if public_inputs.len() != 128
        || public_inputs.iter().enumerate().any(|(index, value)| {
            let expected = if index < 64 {
                before.root[index]
            } else {
                after.root[index - 64]
            };
            value.as_u32() != u32::from(expected)
        })
    {
        return Err("state_binding_air_public_roots".to_string());
    }

    let operation_count_bytes = operation_count.to_be_bytes();
    let manifest = hash_parts(
        STATE_MANIFEST_DOMAIN,
        &[
            &before.root,
            &after.root,
            &operation_count_bytes,
            &operations_encoded,
        ],
    );
    let projection_parts = projection
        .iter()
        .map(|field| field.as_slice())
        .collect::<Vec<_>>();
    let projection_digest = hash_parts(STATE_PROJECTION_DOMAIN, &projection_parts);
    let mut transition_bytes = Vec::new();
    transition_bytes.extend(&before.profile);
    transition_bytes.extend(&before.parameter);
    transition_bytes.extend(before.capacity.to_be_bytes());
    transition_bytes.extend(before.epoch.to_be_bytes());
    transition_bytes.extend(before.sequence.to_be_bytes());
    transition_bytes.extend(after.sequence.to_be_bytes());
    transition_bytes.extend(before.root);
    transition_bytes.extend(after.root);
    transition_bytes.extend(manifest);
    transition_bytes.extend(projection_digest);
    let transition = hash_parts(STATE_TRANSITION_DOMAIN, &[&transition_bytes]);
    let statement = hash_parts(STATE_STATEMENT_DOMAIN, &[&transition_bytes, &transition]);
    if opening_statement != statement {
        return Err("state_binding_statement".to_string());
    }

    let mut expected_ciphertext = [0_u8; 64];
    for index in 0..64 {
        expected_ciphertext[index] = statement[index] ^ opening_mask[index];
    }
    if expected_ciphertext != commitment.ciphertext {
        return Err("state_binding_ciphertext".to_string());
    }
    let tag = hash_parts(
        HASH_PAD_TAG_DOMAIN,
        &[
            &commitment.parameter,
            &public_coin,
            &commitment.ciphertext,
            &statement,
            &opening_mask,
        ],
    );
    if tag != commitment.tag {
        return Err("state_binding_commitment_tag".to_string());
    }
    let commitment_digest = hash_parts(
        HASH_PAD_COMMITMENT_DOMAIN,
        &[
            &commitment.parameter,
            &public_coin,
            &commitment.ciphertext,
            &commitment.tag,
        ],
    );
    if commitment_digest != commitment.digest {
        return Err("state_binding_commitment_digest".to_string());
    }

    let verifier_identity: [u8; 64] =
        Sha3_512::digest(b"BL/PQ512/STATE-PLANE/INDEPENDENT-VERIFIER/v1\0").into();
    let proof = hash_parts(
        STATE_PROOF_DOMAIN,
        &[
            &statement,
            &transition,
            &commitment.digest,
            &verifier_identity,
        ],
    );
    let attempt = hash_parts(
        STATE_ATTEMPT_DOMAIN,
        &[
            &before.profile,
            &before.parameter,
            &before.epoch.to_be_bytes(),
            &before.sequence.to_be_bytes(),
            &before.root,
            &statement,
        ],
    );
    let receipt = hash_parts(
        STATE_RECEIPT_DOMAIN,
        &[
            &attempt,
            &transition,
            &commitment.digest,
            &proof,
            &verifier_identity,
        ],
    );
    let state_air_program = air_program_report.program_binary_commitment;
    let state_air_execution = air_execution_report.binary_commitment;
    let state_air_fragment = hash_parts(
        STATE_AIR_FRAGMENT_DOMAIN,
        &[
            &before.root,
            &after.root,
            &projection_digest,
            &statement,
            &transition,
            &commitment.digest,
            &proof,
            &verifier_identity,
            &attempt,
            &receipt,
            &state_air_program,
            &state_air_execution,
        ],
    );
    let composition = hash_parts(
        H4_COMPOSITION_DOMAIN,
        &[
            &statement,
            &transition,
            &projection_digest,
            &public_coin,
            &commitment.digest,
            &proof,
            &verifier_identity,
            &attempt,
            &receipt,
            &state_air_program,
            &state_air_execution,
            &state_air_fragment,
        ],
    );
    let binding_digest = hash_parts(
        STATE_BINDING_DOMAIN,
        &[
            &before.root,
            &after.root,
            &statement,
            &transition,
            &commitment.digest,
            &proof,
            &receipt,
            &composition,
            &state_air_fragment,
        ],
    );
    let projection: [[u8; 32]; 12] = projection
        .try_into()
        .map_err(|_| "state_binding_projection_count".to_string())?;
    Ok(StateBindingVerification {
        typed_state: false,
        state_profile: before.profile.clone(),
        state_capacity: before.capacity,
        before_snapshot: before.encoded,
        after_snapshot: after.encoded,
        statement,
        binding_digest,
        projection,
        projection_digest,
        public_coin,
        transition,
        commitment: commitment.digest,
        proof,
        verifier: verifier_identity,
        attempt,
        receipt,
        state_air_program,
        state_air_execution,
        state_air_fragment,
        composition,
        typed_state_root_before: [0; 64],
        typed_state_root_after: [0; 64],
        typed_air_execution: None,
        state_relation_rows: None,
        state_relation_source_digest: [0; 64],
    })
}

fn verify_state_binding_v3(path: &Path) -> Result<StateBindingVerification, String> {
    if path.is_symlink() {
        return Err("state_binding_symlink_forbidden".to_string());
    }
    let metadata = fs::metadata(path).map_err(|error| format!("state_binding_metadata:{error}"))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > STATE_BINDING_MAX_BYTES {
        return Err("state_binding_file_shape".to_string());
    }
    let encoded = fs::read(path).map_err(|error| format!("state_binding_read:{error}"))?;
    let mut cursor = StateCursor::new(&encoded);
    if cursor.take(6, "binding_magic")? != STATE_BINDING_MAGIC {
        return Err("state_binding_magic".to_string());
    }
    if cursor.u8("binding_version")? != 3 {
        return Err("state_binding_version".to_string());
    }
    let before_length = usize::try_from(cursor.u32("before_length")?)
        .map_err(|_| "state_binding_before_length".to_string())?;
    let before = parse_state_snapshot(cursor.take(before_length, "before")?)?;
    let after_length = usize::try_from(cursor.u32("after_length")?)
        .map_err(|_| "state_binding_after_length".to_string())?;
    let after = parse_state_snapshot(cursor.take(after_length, "after")?)?;
    if before.profile != after.profile
        || before.parameter != after.parameter
        || before.capacity != after.capacity
        || before.epoch != after.epoch
        || after.sequence != before.sequence + 1
        || before.parameter != STATE_PARAMETER_IDENTITY
    {
        return Err("state_binding_snapshot_layout".to_string());
    }

    let operation_count = cursor.u64("operation_count")?;
    if operation_count != before.capacity {
        return Err("state_binding_operation_count".to_string());
    }
    let mut operations_encoded = Vec::new();
    let mut operation_witness = Vec::with_capacity(operation_count as usize);
    let mut expected_after = before.entries.clone();
    for expected_index in 0..operation_count {
        let (index, operation_before, operation_after, operation_encoded) =
            parse_state_operation(&mut cursor)?;
        if index != expected_index || operation_before != before.entries[index as usize] {
            return Err("state_binding_operation_before".to_string());
        }
        expected_after[index as usize] = operation_after.clone();
        operation_witness.push((operation_before, operation_after));
        operations_encoded.extend(operation_encoded);
    }
    if expected_after != after.entries {
        return Err("state_binding_operation_after".to_string());
    }

    let mut projection = Vec::with_capacity(12);
    for _ in 0..12 {
        let field: [u8; 32] = cursor
            .take(32, "projection")?
            .try_into()
            .expect("projection length");
        if field == [0; 32] {
            return Err("state_binding_projection_zero".to_string());
        }
        projection.push(field);
    }
    let public_coin = cursor.array64("public_coin")?;
    if public_coin == [0; 64] {
        return Err("state_binding_public_coin_zero".to_string());
    }
    let commitment_length = usize::try_from(cursor.u32("commitment_length")?)
        .map_err(|_| "state_binding_commitment_length".to_string())?;
    let commitment = parse_commitment(cursor.take(commitment_length, "commitment")?)?;
    let opening_statement = cursor.array64("opening_statement")?;
    let opening_mask = cursor.array64("opening_mask")?;
    if commitment.public_coin != public_coin {
        return Err("state_binding_commitment_public_coin".to_string());
    }

    if cursor.take(6, "air_fragment_magic")? != b"BLSA02" {
        return Err("state_binding_air_fragment_magic".to_string());
    }
    if cursor.u8("air_fragment_version")? != 1 {
        return Err("state_binding_air_fragment_version".to_string());
    }
    let air_program_length = usize::try_from(cursor.u32("air_program_length")?)
        .map_err(|_| "state_binding_air_program_length".to_string())?;
    if air_program_length == 0 {
        return Err("state_binding_air_program_empty".to_string());
    }
    let air_program = cursor.take(air_program_length, "air_program")?;
    let air_execution_length = usize::try_from(cursor.u32("air_execution_length")?)
        .map_err(|_| "state_binding_air_execution_length".to_string())?;
    if air_execution_length == 0 {
        return Err("state_binding_air_execution_empty".to_string());
    }
    let air_execution = cursor.take(air_execution_length, "air_execution")?;
    let package_length = usize::try_from(cursor.u64("proof_package_length")?)
        .map_err(|_| "state_binding_proof_package_length".to_string())?;
    if package_length == 0 || package_length > STATE_BINDING_MAX_BYTES as usize {
        return Err("state_binding_proof_package_shape".to_string());
    }
    let proof_package = cursor.take(package_length, "proof_package")?;
    let component_id = cursor.text(128, "component_id")?;
    let component_program_id = cursor.text(128, "component_program_id")?;
    let proof_suite_id = cursor.array64("proof_suite_id")?;
    let schedule_commitment = cursor.array64("schedule_commitment")?;
    let transcript_root = cursor.array64("transcript_root")?;
    let evidence_commitment = cursor.array64("evidence_commitment")?;
    let package_commitment_field = cursor.array64("proof_package_commitment")?;
    let component_proof_identity = cursor.array64("component_proof_identity")?;
    let public_input_digest = cursor.array64("public_input_digest")?;
    let attribution_digest = cursor.array64("attribution_digest")?;
    let component_proof_bytes = cursor.u64("component_proof_bytes")?;
    if component_proof_bytes == 0 {
        return Err("state_binding_component_proof_size".to_string());
    }
    let worker_report_digest = cursor.array64("worker_report_digest")?;
    let canonical_length = usize::try_from(cursor.u32("component_canonical_length")?)
        .map_err(|_| "state_binding_component_canonical_length".to_string())?;
    let canonical_evidence = cursor.take(canonical_length, "component_canonical")?;
    if !cursor.done() {
        return Err("state_binding_trailing_bytes".to_string());
    }

    validate_state_air_program_id(air_program, STATE_RELATION_AIR_PROGRAM_ID)?;
    let air_program_report = validate_air_program(air_program)
        .map_err(|error| format!("state_binding_air_program:{error:?}"))?;
    let air_execution_report = evaluate_air_execution(air_execution)
        .map_err(|error| format!("state_binding_air_execution:{error:?}"))?;
    if air_program_report.source_program_commitment
        != air_execution_report.source_program_commitment
        || air_program_report.public_input_count != 128
    {
        return Err("state_binding_air_program_execution_identity".to_string());
    }
    let public_inputs = validated_execution_public_inputs(air_execution)
        .map_err(|error| format!("state_binding_air_public_inputs:{error:?}"))?;
    if public_inputs.len() != 128
        || public_inputs.iter().enumerate().any(|(index, value)| {
            let expected = if index < 64 {
                before.root[index]
            } else {
                after.root[index - 64]
            };
            value.as_u32() != u32::from(expected)
        })
    {
        return Err("state_binding_air_public_roots".to_string());
    }
    let traces = validated_execution_traces(air_execution)
        .map_err(|error| format!("state_binding_air_traces:{error:?}"))?;
    verify_compact_state_trace(
        &traces,
        &operation_witness,
        &before.entries,
        &after.entries,
        &before.root,
        &after.root,
    )?;

    let (package_commitment, package) =
        verify_selected_proof_package(proof_package, air_program, &public_inputs)
            .map_err(|error| format!("state_binding_proof_package:{error:?}"))?;
    let package_proof_bytes = u64::try_from(package.proof.len())
        .map_err(|_| "state_binding_proof_package_size".to_string())?;
    if package_commitment_field != package_commitment
        || component_id != STATE_AIR_COMPONENT_ID
        || component_program_id != STATE_RELATION_AIR_PROGRAM_ID
        || proof_suite_id != package.bundle.proof_suite_id
        || schedule_commitment != package.bundle.schedule_commitment
        || transcript_root != package.bundle.final_transcript_root
        || evidence_commitment != package.bundle.evidence_commitment
        || component_proof_bytes != package_proof_bytes
        || component_proof_identity == [0; 64]
        || public_input_digest == [0; 64]
        || attribution_digest == [0; 64]
        || worker_report_digest == [0; 64]
    {
        return Err("state_binding_proof_package_metadata".to_string());
    }
    let component_proof_identity_expected = hash_parts(
        STATE_AIR_PROOF_DOMAIN,
        &[
            b"proof-identity",
            &package_commitment,
            &package.bundle.proof_suite_id,
            &package.bundle.schedule_commitment,
            &package.bundle.final_transcript_root,
            &package.bundle.evidence_commitment,
            &package.bundle.main_trace_root,
            &package.bundle.interaction_trace_root,
            &package.bundle.composition_root,
            &package.bundle.oods_claims_commitment,
            &package.bundle.fri_mask_root,
            &package.bundle.fri_batch_derivation_commitment,
            &package
                .bundle
                .fri_layer_roots
                .iter()
                .flat_map(|root| root.iter().copied())
                .collect::<Vec<_>>(),
        ],
    );
    if component_proof_identity != component_proof_identity_expected {
        return Err("state_binding_component_proof_identity".to_string());
    }
    let mut public_input_bytes = Vec::with_capacity(public_inputs.len() * 4);
    for value in &public_inputs {
        public_input_bytes.extend_from_slice(&value.as_u32().to_be_bytes());
    }
    let projection_bytes = projection
        .iter()
        .flat_map(|field| field.iter().copied())
        .collect::<Vec<_>>();
    let expected_public_input_digest = hash_parts(
        STATE_AIR_PROOF_DOMAIN,
        &[b"public-inputs", &public_input_bytes, &projection_bytes],
    );
    if public_input_digest != expected_public_input_digest {
        return Err("state_binding_component_public_inputs".to_string());
    }
    let mut expected_canonical = Vec::new();
    expected_canonical.extend_from_slice(STATE_AIR_COMPONENT_ID);
    expected_canonical.push(0);
    expected_canonical.extend_from_slice(STATE_RELATION_AIR_PROGRAM_ID);
    expected_canonical.push(0);
    expected_canonical.extend_from_slice(&air_program_report.program_binary_commitment);
    expected_canonical.extend_from_slice(&air_execution_report.binary_commitment);
    expected_canonical.extend_from_slice(&package_commitment);
    expected_canonical.extend_from_slice(&proof_suite_id);
    expected_canonical.extend_from_slice(&schedule_commitment);
    expected_canonical.extend_from_slice(&transcript_root);
    expected_canonical.extend_from_slice(&evidence_commitment);
    expected_canonical.extend_from_slice(&component_proof_identity);
    expected_canonical.extend_from_slice(&public_input_digest);
    expected_canonical.extend_from_slice(&attribution_digest);
    expected_canonical.extend_from_slice(&component_proof_bytes.to_be_bytes());
    expected_canonical.extend_from_slice(&worker_report_digest);
    if canonical_evidence != expected_canonical {
        return Err("state_binding_component_canonical".to_string());
    }

    let operation_count_bytes = operation_count.to_be_bytes();
    let manifest = hash_parts(
        STATE_MANIFEST_DOMAIN,
        &[
            &before.root,
            &after.root,
            &operation_count_bytes,
            &operations_encoded,
        ],
    );
    let projection_parts = projection
        .iter()
        .map(|field| field.as_slice())
        .collect::<Vec<_>>();
    let projection_digest = hash_parts(STATE_PROJECTION_DOMAIN, &projection_parts);
    let mut transition_bytes = Vec::new();
    transition_bytes.extend(&before.profile);
    transition_bytes.extend(&before.parameter);
    transition_bytes.extend(before.capacity.to_be_bytes());
    transition_bytes.extend(before.epoch.to_be_bytes());
    transition_bytes.extend(before.sequence.to_be_bytes());
    transition_bytes.extend(after.sequence.to_be_bytes());
    transition_bytes.extend(before.root);
    transition_bytes.extend(after.root);
    transition_bytes.extend(manifest);
    transition_bytes.extend(projection_digest);
    let transition = hash_parts(STATE_TRANSITION_DOMAIN, &[&transition_bytes]);
    let statement = hash_parts(STATE_STATEMENT_DOMAIN, &[&transition_bytes, &transition]);
    if opening_statement != statement {
        return Err("state_binding_statement".to_string());
    }

    let mut expected_ciphertext = [0_u8; 64];
    for index in 0..64 {
        expected_ciphertext[index] = statement[index] ^ opening_mask[index];
    }
    if expected_ciphertext != commitment.ciphertext {
        return Err("state_binding_ciphertext".to_string());
    }
    let tag = hash_parts(
        HASH_PAD_TAG_DOMAIN,
        &[
            &commitment.parameter,
            &public_coin,
            &commitment.ciphertext,
            &statement,
            &opening_mask,
        ],
    );
    if tag != commitment.tag {
        return Err("state_binding_commitment_tag".to_string());
    }
    let commitment_digest = hash_parts(
        HASH_PAD_COMMITMENT_DOMAIN,
        &[
            &commitment.parameter,
            &public_coin,
            &commitment.ciphertext,
            &commitment.tag,
        ],
    );
    if commitment_digest != commitment.digest {
        return Err("state_binding_commitment_digest".to_string());
    }

    let verifier_identity: [u8; 64] =
        Sha3_512::digest(b"BL/PQ512/STATE-PLANE/INDEPENDENT-VERIFIER/v1\0").into();
    let proof = hash_parts(
        STATE_PROOF_DOMAIN,
        &[
            &statement,
            &transition,
            &commitment.digest,
            &verifier_identity,
        ],
    );
    let attempt = hash_parts(
        STATE_ATTEMPT_DOMAIN,
        &[
            &before.profile,
            &before.parameter,
            &before.epoch.to_be_bytes(),
            &before.sequence.to_be_bytes(),
            &before.root,
            &statement,
        ],
    );
    let receipt = hash_parts(
        STATE_RECEIPT_DOMAIN,
        &[
            &attempt,
            &transition,
            &commitment.digest,
            &proof,
            &verifier_identity,
        ],
    );
    let state_air_program = air_program_report.program_binary_commitment;
    let state_air_execution = air_execution_report.binary_commitment;
    let state_air_fragment = hash_parts(
        COMPOSED_STATE_AIR_FRAGMENT_DOMAIN,
        &[
            &before.root,
            &after.root,
            &projection_digest,
            &statement,
            &transition,
            &commitment.digest,
            &proof,
            &receipt,
            &state_air_program,
            &state_air_execution,
            &package_commitment,
            &component_proof_identity,
            canonical_evidence,
        ],
    );
    let composition = hash_parts(
        COMPOSED_H4_COMPOSITION_DOMAIN,
        &[
            &statement,
            &transition,
            &projection_digest,
            &public_coin,
            &commitment.digest,
            &proof,
            &receipt,
            &state_air_program,
            &state_air_execution,
            &package_commitment,
            &component_proof_identity,
            canonical_evidence,
            &state_air_fragment,
        ],
    );
    let binding_digest = hash_parts(
        COMPOSED_STATE_BINDING_DOMAIN,
        &[
            &before.root,
            &after.root,
            &statement,
            &transition,
            &commitment.digest,
            &proof,
            &receipt,
            &composition,
            &state_air_fragment,
        ],
    );
    let projection: [[u8; 32]; 12] = projection
        .try_into()
        .map_err(|_| "state_binding_projection_count".to_string())?;
    let state_relation_rows = operation_witness
        .iter()
        .enumerate()
        .map(
            |(index, (operation_before, operation_after))| StateRelationRow {
                operation_before: to_state_relation_entry(operation_before),
                operation_after: to_state_relation_entry(operation_after),
                snapshot_before: to_state_relation_entry(&before.entries[index]),
                snapshot_after: to_state_relation_entry(&after.entries[index]),
            },
        )
        .collect::<Vec<_>>();
    let state_relation_source = build_state_relation_wire_source(&state_relation_rows)
        .map_err(|error| format!("state_relation_source_build:{error:?}"))?;
    let state_relation_source_digest = state_relation_source_digest(&state_relation_source);
    Ok(StateBindingVerification {
        typed_state: false,
        state_profile: before.profile.clone(),
        state_capacity: before.capacity,
        before_snapshot: before.encoded,
        after_snapshot: after.encoded,
        statement,
        binding_digest,
        projection,
        projection_digest,
        public_coin,
        transition,
        commitment: commitment.digest,
        proof,
        verifier: verifier_identity,
        attempt,
        receipt,
        state_air_program,
        state_air_execution,
        state_air_fragment,
        composition,
        typed_state_root_before: [0; 64],
        typed_state_root_after: [0; 64],
        typed_air_execution: None,
        state_relation_rows: Some(state_relation_rows),
        state_relation_source_digest,
    })
}

fn typed_column<'a>(
    tables: &'a [NamedExecutionTable],
    table_name: &str,
    column_name: &str,
) -> Result<&'a Vec<M31>, String> {
    let table = tables
        .iter()
        .find(|table| table.name == table_name)
        .ok_or_else(|| format!("typed_state_table_missing:{table_name}"))?;
    table
        .columns
        .iter()
        .find(|(name, _)| name == column_name)
        .map(|(_, values)| values)
        .ok_or_else(|| format!("typed_state_column_missing:{table_name}:{column_name}"))
}

fn typed_byte(value: M31, label: &str) -> Result<u8, String> {
    let value = value.as_u32();
    u8::try_from(value).map_err(|_| format!("typed_state_byte:{label}"))
}

fn typed_u64(value: M31, _label: &str) -> Result<u64, String> {
    Ok(u64::from(value.as_u32()))
}

fn typed_bytes64(
    tables: &[NamedExecutionTable],
    table: &str,
    prefix: &str,
    row: usize,
) -> Result<[u8; 64], String> {
    let mut output = [0_u8; 64];
    for (index, destination) in output.iter_mut().enumerate() {
        let values = typed_column(tables, table, &format!("{prefix}_{index}"))?;
        *destination = typed_byte(
            *values
                .get(row)
                .ok_or_else(|| format!("typed_state_row:{table}:{prefix}:{row}"))?,
            prefix,
        )?;
    }
    Ok(output)
}

fn typed_u32_at(
    tables: &[NamedExecutionTable],
    table: &str,
    column: &str,
    row: usize,
) -> Result<u32, String> {
    typed_column(tables, table, column)?
        .get(row)
        .copied()
        .map(|value| value.as_u32())
        .ok_or_else(|| format!("typed_state_row:{table}:{column}:{row}"))
}

fn typed_map_table_name(prefix: &str, suffix: &str) -> String {
    if prefix.is_empty() {
        suffix.to_string()
    } else {
        format!("{prefix}__{suffix}")
    }
}

fn typed_map_leaf_message(
    tables: &[NamedExecutionTable],
    endpoint_table: &str,
    phase: &str,
    row: usize,
    map_domain: u8,
) -> Result<Vec<u8>, String> {
    let mut message = Vec::with_capacity(212);
    message.extend_from_slice(b"BL/PQ/MAP4\0");
    message.push(map_domain);
    for prefix in ["key", "value", "next_key"] {
        let field = format!("{phase}_{prefix}");
        message.extend_from_slice(&typed_bytes64(tables, endpoint_table, &field, row)?);
    }
    for index in 0..8 {
        message.push(typed_byte(
            *typed_column(
                tables,
                endpoint_table,
                &format!("{phase}_next_index_u64_{index}"),
            )?
            .get(row)
            .ok_or_else(|| {
                format!("typed_state_row:{endpoint_table}:{phase}_next_index_u64_{index}:{row}")
            })?,
            "map_next_index",
        )?);
    }
    if message.len() != 212 {
        return Err("typed_state_map_leaf_message_shape".to_string());
    }
    Ok(message)
}

fn typed_map_messages(
    tables: &[NamedExecutionTable],
    prefix: &str,
    operation_rows: u64,
) -> Result<Vec<Vec<u8>>, String> {
    let schedule = build_ordered_map_batch_schedule(operation_rows, 24)
        .map_err(|error| format!("typed_state_map_schedule:{error:?}"))?;
    let state_table = typed_map_table_name(prefix, "ordered_map_state");
    let endpoint_table = typed_map_table_name(prefix, "ordered_map_endpoint");
    let node_table = typed_map_table_name(prefix, "ordered_map_node");
    let map_domain = u8::try_from(typed_u32_at(tables, &state_table, "map_domain", 0)?)
        .map_err(|_| "typed_state_map_domain".to_string())?;
    let endpoint_rows = usize::try_from(schedule.position_rows)
        .map_err(|_| "typed_state_map_endpoint_rows".to_string())?;
    if typed_column(tables, &endpoint_table, "live")?.len() != endpoint_rows {
        return Err("typed_state_map_endpoint_shape".to_string());
    }

    let mut messages = Vec::with_capacity(usize::try_from(schedule.sha3_call_rows).unwrap_or(0));
    for phase in ["before", "after"] {
        let present = typed_column(tables, &endpoint_table, &format!("{phase}_present"))?;
        for row in 0..endpoint_rows {
            match present[row].as_u32() {
                0 => {}
                1 => messages.push(typed_map_leaf_message(
                    tables,
                    &endpoint_table,
                    phase,
                    row,
                    map_domain,
                )?),
                _ => return Err("typed_state_map_leaf_presence".to_string()),
            }
        }
    }
    let leaf_rows = usize::try_from(schedule.leaf_hash_rows)
        .map_err(|_| "typed_state_map_leaf_rows".to_string())?;
    if messages.len() > leaf_rows {
        return Err("typed_state_map_leaf_schedule_overflow".to_string());
    }
    let mut dummy_leaf = Vec::with_capacity(212);
    dummy_leaf.extend_from_slice(b"BL/PQ/MAP4\0");
    dummy_leaf.push(map_domain);
    dummy_leaf.extend_from_slice(&[0_u8; 64]);
    dummy_leaf.extend_from_slice(&[0_u8; 64]);
    dummy_leaf.extend_from_slice(&[0xff_u8; 64]);
    dummy_leaf.extend_from_slice(&1_u64.to_be_bytes());
    while messages.len() < leaf_rows {
        messages.push(dummy_leaf.clone());
    }

    let node_rows = usize::try_from(schedule.node_hash_rows)
        .map_err(|_| "typed_state_map_node_rows".to_string())?;
    let node_live = typed_column(tables, &node_table, "live")?;
    let node_height = typed_column(tables, &node_table, "height")?;
    if node_live.len() != node_rows || node_height.len() != node_rows {
        return Err("typed_state_map_node_shape".to_string());
    }
    let node_live_count = node_live.iter().filter(|value| value.as_u32() == 1).count();
    let mut node_messages = Vec::with_capacity(node_rows);
    for row in 0..node_rows {
        match node_live[row].as_u32() {
            0 => {}
            1 => {
                let height = u8::try_from(node_height[row].as_u32())
                    .map_err(|_| "typed_state_map_node_height".to_string())?;
                if height >= 64 {
                    return Err("typed_state_map_node_height".to_string());
                }
                let mut message = Vec::with_capacity(141);
                message.extend_from_slice(b"BL/PQ/MAP4\x01");
                message.push(map_domain);
                message.push(height);
                message.extend_from_slice(&typed_bytes64(tables, &node_table, "left", row)?);
                message.extend_from_slice(&typed_bytes64(tables, &node_table, "right", row)?);
                if message.len() != 141 {
                    return Err("typed_state_map_node_message_shape".to_string());
                }
                node_messages.push(message);
            }
            _ => return Err("typed_state_map_node_live".to_string()),
        }
    }
    if node_messages.len() != node_live_count {
        return Err("typed_state_map_node_live_prefix".to_string());
    }
    let mut dummy_node = Vec::with_capacity(141);
    dummy_node.extend_from_slice(b"BL/PQ/MAP4\x01");
    dummy_node.push(map_domain);
    dummy_node.push(0);
    dummy_node.extend_from_slice(&[0_u8; 128]);
    while node_messages.len() < node_rows {
        node_messages.push(dummy_node.clone());
    }
    messages.extend(node_messages);

    for (cursor_column, root_prefix) in [
        ("cursor_before", "inner_root_before"),
        ("cursor_after", "inner_root_after"),
    ] {
        let cursor = u64::from(typed_u32_at(tables, &state_table, cursor_column, 0)?);
        let inner_root = typed_bytes64(tables, &state_table, root_prefix, 0)?;
        let mut message = Vec::with_capacity(84);
        message.extend_from_slice(b"BL/PQ/MAP4\x02");
        message.push(map_domain);
        message.extend_from_slice(&cursor.to_be_bytes());
        message.extend_from_slice(&inner_root);
        if message.len() != 84 {
            return Err("typed_state_map_header_message_shape".to_string());
        }
        messages.push(message);
    }
    if messages.len() != usize::try_from(schedule.sha3_call_rows).unwrap_or(usize::MAX) {
        return Err("typed_state_map_call_count".to_string());
    }
    Ok(messages)
}

fn typed_place_message(
    messages: &mut [Option<Vec<u8>>],
    call_index: u32,
    message: Vec<u8>,
    label: &str,
) -> Result<(), String> {
    let slot = messages
        .get_mut(usize::try_from(call_index).map_err(|_| format!("{label}_call_index"))?)
        .ok_or_else(|| format!("{label}_call_index"))?;
    if slot.replace(message).is_some() {
        return Err(format!("{label}_call_duplicate"));
    }
    Ok(())
}

fn typed_digest_vector(
    tables: &[NamedExecutionTable],
    total_calls: usize,
) -> Result<Vec<[u8; 64]>, String> {
    let call_values = typed_column(tables, "sha3_digest_batch", "call_index")?;
    if call_values.len() != total_calls {
        return Err("typed_state_digest_call_count".to_string());
    }
    let mut digests = vec![[0_u8; 64]; total_calls];
    let mut seen = vec![false; total_calls];
    for row in 0..total_calls {
        let call = usize::try_from(call_values[row].as_u32())
            .map_err(|_| "typed_state_digest_call_index".to_string())?;
        if call >= total_calls || seen[call] {
            return Err("typed_state_digest_call_index".to_string());
        }
        digests[call] = typed_bytes64(tables, "sha3_digest_batch", "value", row)?;
        seen[call] = true;
    }
    if seen.iter().any(|value| !value) {
        return Err("typed_state_digest_call_missing".to_string());
    }
    Ok(digests)
}

fn typed_state_root_message(
    tables: &[NamedExecutionTable],
    phase: usize,
) -> Result<Vec<u8>, String> {
    if phase >= 2 {
        return Err("typed_state_root_phase".to_string());
    }
    let mut message = Vec::with_capacity(C0_STATE_ROOT_DOMAIN.len() + 128);
    message.extend_from_slice(C0_STATE_ROOT_DOMAIN);
    message.extend_from_slice(&typed_bytes64(
        tables,
        "typed_state_authority",
        "payment_root",
        phase,
    )?);
    message.extend_from_slice(&typed_bytes64(
        tables,
        "typed_state_authority",
        "replay_root",
        phase,
    )?);
    if message.len() != C0_STATE_ROOT_DOMAIN.len() + 128 {
        return Err("typed_state_root_message_shape".to_string());
    }
    Ok(message)
}

fn typed_state_hash_messages(
    tables: &[NamedExecutionTable],
    profile: Profile,
    typed_call_count: usize,
) -> Result<Vec<Vec<u8>>, String> {
    let slots = profile.claim_slots();
    let mut messages = vec![None; typed_call_count + 2];
    let map_specs = [
        ("", slots + 1),
        ("benefit", slots),
        ("obligation", slots),
        ("ledger", slots * 2),
    ];
    let mut cursor = 0_u32;
    for (prefix, operations) in map_specs {
        for message in typed_map_messages(tables, prefix, operations)? {
            typed_place_message(&mut messages, cursor, message, "typed_state_map")?;
            cursor = cursor
                .checked_add(1)
                .ok_or_else(|| "typed_state_map_call_index".to_string())?;
        }
    }
    let map_call_count =
        usize::try_from(cursor).map_err(|_| "typed_state_map_call_count".to_string())?;
    let key_call_values = typed_column(tables, "claim_payment_key_material", "call_index")?;
    let key_lengths = typed_column(tables, "claim_payment_key_material", "message_length")?;
    if key_call_values.len() != key_lengths.len() || key_call_values.len() != (slots * 4) as usize {
        return Err("typed_state_key_call_count".to_string());
    }
    for row in 0..key_call_values.len() {
        let call = key_call_values[row].as_u32();
        let length = usize::try_from(key_lengths[row].as_u32())
            .map_err(|_| "typed_state_key_message_length".to_string())?;
        if length == 0 || length > 169 || call < cursor {
            return Err("typed_state_key_message_shape".to_string());
        }
        let mut message = Vec::with_capacity(length);
        for index in 0..169 {
            let value = typed_byte(
                *typed_column(
                    tables,
                    "claim_payment_key_material",
                    &format!("message_byte_{index}"),
                )?
                .get(row)
                .ok_or_else(|| format!("typed_state_key_message_row:{row}"))?,
                "key_message",
            )?;
            if index < length {
                message.push(value);
            } else if value != 0 {
                return Err("typed_state_key_message_padding".to_string());
            }
        }
        typed_place_message(&mut messages, call, message, "typed_state_key")?;
    }

    let log_call_values = typed_column(tables, "typed_state_log_message_batch", "call_index")?;
    let log_positions = typed_column(tables, "typed_state_log_message_batch", "position_base")?;
    let log_live = (0..TYPED_STATE_LOG_MESSAGE_LANES)
        .map(|lane| {
            typed_column(
                tables,
                "typed_state_log_message_batch",
                &format!("live_{lane}"),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let log_values = (0..TYPED_STATE_LOG_MESSAGE_LANES)
        .map(|lane| {
            typed_column(
                tables,
                "typed_state_log_message_batch",
                &format!("value_{lane}"),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    if log_call_values.len() != log_positions.len()
        || log_live
            .iter()
            .any(|column| column.len() != log_call_values.len())
        || log_values
            .iter()
            .any(|column| column.len() != log_call_values.len())
    {
        return Err("typed_state_log_message_shape".to_string());
    }
    let mut grouped: BTreeMap<u32, Vec<(u32, u8)>> = BTreeMap::new();
    for row in 0..log_call_values.len() {
        let call = log_call_values[row].as_u32();
        let position_base = log_positions[row].as_u32();
        for lane in 0..TYPED_STATE_LOG_MESSAGE_LANES {
            let lane_position =
                u32::try_from(lane).map_err(|_| "typed_state_log_message_lane".to_string())?;
            let position = position_base
                .checked_add(lane_position)
                .ok_or_else(|| "typed_state_log_message_position".to_string())?;
            let live = log_live[lane][row].as_u32();
            let value = typed_byte(log_values[lane][row], "log_message")?;
            match (live, value) {
                (0, 0) => {}
                (0, _) => return Err("typed_state_log_message_padding".to_string()),
                (1, value) => grouped.entry(call).or_default().push((position, value)),
                _ => return Err("typed_state_log_message_live".to_string()),
            }
        }
    }
    if grouped.len() != (slots * 2) as usize {
        return Err("typed_state_log_call_count".to_string());
    }
    for (call, mut rows) in grouped {
        rows.sort_unstable_by_key(|(position, _)| *position);
        let mut message = Vec::new();
        for (index, (position, value)) in rows.iter().enumerate() {
            if usize::try_from(*position).ok() != Some(index) {
                return Err("typed_state_log_message_position".to_string());
            }
            message.push(*value);
        }
        if message.is_empty() {
            return Err("typed_state_log_message_empty".to_string());
        }
        typed_place_message(&mut messages, call, message, "typed_state_log")?;
    }

    for phase in 0..2 {
        let message = typed_state_root_message(tables, phase)?;
        typed_place_message(
            &mut messages,
            u32::try_from(typed_call_count + phase)
                .map_err(|_| "typed_state_root_call_index".to_string())?,
            message,
            "typed_state_root",
        )?;
    }
    if messages.iter().any(Option::is_none) {
        return Err(format!("typed_state_hash_message_missing:{map_call_count}"));
    }
    Ok(messages.into_iter().map(Option::unwrap).collect())
}

fn typed_hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    hash_parts(domain, parts)
}

fn verify_typed_root_interface(
    tables: &[NamedExecutionTable],
    root_call_offset: u32,
    roots: &[[u8; 64]; 2],
    payment_roots: &[[u8; 64]; 2],
    replay_roots: &[[u8; 64]; 2],
) -> Result<(), String> {
    let digest_call = typed_column(tables, "sha3_digest_batch", "call_index")?;
    let mut seen_digest = [false; 2];
    for phase in 0..2 {
        let expected = [
            C0_STATE_ROOT_DOMAIN,
            &payment_roots[phase],
            &replay_roots[phase],
        ]
        .concat();
        let message = typed_state_root_message(tables, phase)?;
        if message != expected {
            return Err(format!("typed_state_root_message:{phase}"));
        }
        let call = root_call_offset
            .checked_add(phase as u32)
            .ok_or_else(|| "typed_state_root_call_index".to_string())?;
        let mut digest_row = None;
        for row in 0..digest_call.len() {
            if digest_call[row].as_u32() != call {
                continue;
            }
            if digest_row.replace(row).is_some() {
                return Err(format!("typed_state_root_digest_duplicate:{phase}"));
            }
        }
        let row = digest_row.ok_or_else(|| format!("typed_state_root_digest_missing:{phase}"))?;
        if typed_bytes64(tables, "sha3_digest_batch", "value", row)? != roots[phase] {
            return Err(format!("typed_state_root_digest:{phase}"));
        }
        seen_digest[phase] = true;
    }
    if seen_digest != [true, true] {
        return Err("typed_state_root_digest_missing".to_string());
    }
    Ok(())
}

fn verify_typed_state_binding_v4(path: &Path) -> Result<StateBindingVerification, String> {
    let encoded = fs::read(path).map_err(|error| format!("state_binding_read:{error}"))?;
    let mut cursor = StateCursor::new(&encoded);
    if cursor.take(6, "binding_magic")? != STATE_BINDING_MAGIC || cursor.u8("binding_version")? != 4
    {
        return Err("state_binding_version".to_string());
    }
    let state_profile = cursor.text(64, "typed_profile")?;
    let state_capacity = cursor.u64("typed_capacity")?;
    let typed_state_root_before = cursor.array64("typed_root_before")?;
    let typed_state_root_after = cursor.array64("typed_root_after")?;
    let statement = cursor.array64("typed_statement")?;
    let binding_digest = cursor.array64("typed_binding")?;
    let mut projection = [[0_u8; 32]; 12];
    for field in &mut projection {
        *field = cursor
            .take(32, "typed_projection")?
            .try_into()
            .expect("typed projection length");
        if *field == [0; 32] {
            return Err("typed_state_projection_zero".to_string());
        }
    }
    let projection_digest = cursor.array64("typed_projection_digest")?;
    let public_coin = cursor.array64("typed_public_coin")?;
    let transition = cursor.array64("typed_transition")?;
    let commitment = cursor.array64("typed_commitment")?;
    let proof = cursor.array64("typed_proof")?;
    let verifier = cursor.array64("typed_verifier")?;
    let attempt = cursor.array64("typed_attempt")?;
    let receipt = cursor.array64("typed_receipt")?;
    let state_air_program = cursor.array64("typed_air_program")?;
    let state_air_execution = cursor.array64("typed_air_execution")?;
    let state_air_fragment = cursor.array64("typed_air_fragment")?;
    let composition = cursor.array64("typed_composition")?;
    if cursor.take(6, "typed_fragment_magic")? != TYPED_STATE_FRAGMENT_MAGIC
        || cursor.u8("typed_fragment_version")? != 1
    {
        return Err("typed_state_fragment_version".to_string());
    }
    let program_length = usize::try_from(cursor.u32("typed_program_length")?)
        .map_err(|_| "typed_program_length".to_string())?;
    if program_length == 0 || program_length > STATE_BINDING_MAX_BYTES as usize {
        return Err("typed_program_shape".to_string());
    }
    let air_program = cursor.take(program_length, "typed_air_program_bytes")?;
    let execution_length = usize::try_from(cursor.u32("typed_execution_length")?)
        .map_err(|_| "typed_execution_length".to_string())?;
    if execution_length == 0 || execution_length > STATE_BINDING_MAX_BYTES as usize {
        return Err("typed_execution_shape".to_string());
    }
    let air_execution = cursor.take(execution_length, "typed_air_execution_bytes")?;
    let package_length = usize::try_from(cursor.u64("typed_package_length")?)
        .map_err(|_| "typed_package_length".to_string())?;
    if package_length == 0 || package_length > STATE_BINDING_MAX_BYTES as usize {
        return Err("typed_package_shape".to_string());
    }
    let proof_package = cursor.take(package_length, "typed_proof_package")?;
    let component_id = cursor.text(128, "typed_component_id")?;
    let component_program_id = cursor.text(128, "typed_component_program_id")?;
    let proof_suite_id = cursor.array64("typed_proof_suite_id")?;
    let schedule_commitment = cursor.array64("typed_schedule_commitment")?;
    let transcript_root = cursor.array64("typed_transcript_root")?;
    let evidence_commitment = cursor.array64("typed_evidence_commitment")?;
    let package_commitment_field = cursor.array64("typed_package_commitment")?;
    let component_proof_identity = cursor.array64("typed_component_proof_identity")?;
    let public_input_digest = cursor.array64("typed_public_input_digest")?;
    let attribution_digest = cursor.array64("typed_attribution_digest")?;
    let component_proof_bytes = cursor.u64("typed_component_proof_bytes")?;
    let worker_report_digest = cursor.array64("typed_worker_report_digest")?;
    let canonical_length = usize::try_from(cursor.u32("typed_canonical_length")?)
        .map_err(|_| "typed_canonical_length".to_string())?;
    let canonical_evidence = cursor.take(canonical_length, "typed_canonical")?;
    if !cursor.done() {
        return Err("state_binding_trailing_bytes".to_string());
    }
    if state_capacity == 0
        || state_capacity > STATE_MAX_CAPACITY
        || state_capacity != 128 && state_capacity != 512
        || !state_profile.iter().all(u8::is_ascii)
        || component_id != TYPED_STATE_COMPONENT_ID
        || component_program_id != TYPED_STATE_AIR_PROGRAM_ID
    {
        return Err("typed_state_identity".to_string());
    }
    validate_state_air_program_id(air_program, TYPED_STATE_AIR_PROGRAM_ID)?;
    let air_program_report = validate_air_program(air_program)
        .map_err(|error| format!("typed_air_program:{error:?}"))?;
    let air_execution_report = evaluate_air_execution(air_execution)
        .map_err(|error| format!("typed_air_execution:{error:?}"))?;
    if air_program_report.source_program_commitment
        != air_execution_report.source_program_commitment
        || air_program_report.public_input_count != 1_806
        || air_program_report.program_binary_commitment != state_air_program
        || air_execution_report.binary_commitment != state_air_execution
    {
        return Err("typed_state_air_identity".to_string());
    }
    let public_inputs = validated_execution_public_inputs(air_execution)
        .map_err(|error| format!("typed_public_inputs:{error:?}"))?;
    if public_inputs.len() != 1_806 {
        return Err("typed_public_input_count".to_string());
    }
    let named = validated_execution_named_tables(
        air_execution,
        &[
            "typed_state_authority",
            "sha3_digest_batch",
            "typed_state_log_message_batch",
            "claim_payment_key_material",
            "ordered_map_state",
            "ordered_map_endpoint",
            "ordered_map_node",
            "benefit__ordered_map_state",
            "benefit__ordered_map_endpoint",
            "benefit__ordered_map_node",
            "obligation__ordered_map_state",
            "obligation__ordered_map_endpoint",
            "obligation__ordered_map_node",
            "ledger__ordered_map_state",
            "ledger__ordered_map_endpoint",
            "ledger__ordered_map_node",
        ],
    )
    .map_err(|error| format!("typed_named_tables:{error:?}"))?;
    let typed_call_count = typed_column(&named, "sha3_digest_batch", "call_index")?
        .len()
        .checked_sub(2)
        .ok_or_else(|| "typed_state_hash_bus_call_count".to_string())?;
    if typed_call_count == 0 {
        return Err("typed_state_hash_bus_call_count".to_string());
    }
    let authority = typed_column(&named, "typed_state_authority", "phase")?;
    if authority.len() != 2 {
        return Err("typed_authority_rows".to_string());
    }
    let mut payment_roots = [[0_u8; 64]; 2];
    let mut replay_roots = [[0_u8; 64]; 2];
    let mut observed_state_roots = [[0_u8; 64]; 2];
    for phase in 0..2 {
        if authority[phase].as_u32() != phase as u32 {
            return Err("typed_authority_phase".to_string());
        }
        payment_roots[phase] =
            typed_bytes64(&named, "typed_state_authority", "payment_root", phase)?;
        replay_roots[phase] = typed_bytes64(&named, "typed_state_authority", "replay_root", phase)?;
        observed_state_roots[phase] =
            typed_bytes64(&named, "typed_state_authority", "state_root", phase)?;
        let epoch = typed_u64(
            *typed_column(&named, "typed_state_authority", "epoch")?
                .get(phase)
                .ok_or_else(|| "typed_authority_epoch".to_string())?,
            "epoch",
        )?;
        let sequence = typed_u64(
            *typed_column(&named, "typed_state_authority", "sequence")?
                .get(phase)
                .ok_or_else(|| "typed_authority_sequence".to_string())?,
            "sequence",
        )?;
        let next_slot = typed_u64(
            *typed_column(&named, "typed_state_authority", "next_slot_index")?
                .get(phase)
                .ok_or_else(|| "typed_authority_cursor".to_string())?,
            "next_slot_index",
        )?;
        let settlement = typed_bytes64(&named, "typed_state_authority", "settlement", phase)?;
        let asset_registry =
            typed_bytes64(&named, "typed_state_authority", "asset_registry", phase)?;
        let scope = typed_bytes64(&named, "typed_state_authority", "scope", phase)?;
        let benefit = typed_bytes64(&named, "typed_state_authority", "benefit_root", phase)?;
        let obligation = typed_bytes64(&named, "typed_state_authority", "obligation_root", phase)?;
        let ledger = typed_bytes64(&named, "typed_state_authority", "ledger_root", phase)?;
        let operation_log =
            typed_bytes64(&named, "typed_state_authority", "operation_log_root", phase)?;
        let mut payment_message = Vec::new();
        payment_message.extend_from_slice(PAYMENT_STATE_DOMAIN);
        payment_message.extend_from_slice(&epoch.to_be_bytes());
        payment_message.extend_from_slice(&sequence.to_be_bytes());
        payment_message.extend_from_slice(
            &u16::try_from(next_slot)
                .map_err(|_| "typed_authority_cursor_width".to_string())?
                .to_be_bytes(),
        );
        for value in [
            settlement,
            asset_registry,
            scope,
            benefit,
            obligation,
            ledger,
            operation_log,
        ] {
            payment_message.extend_from_slice(&value);
        }
        let expected_payment: [u8; 64] = Sha3_512::digest(&payment_message).into();
        if expected_payment != payment_roots[phase] {
            return Err(format!("typed_payment_root:{phase}"));
        }
        let expected_state: [u8; 64] = Sha3_512::digest(
            [
                C0_STATE_ROOT_DOMAIN,
                &payment_roots[phase],
                &replay_roots[phase],
            ]
            .concat(),
        )
        .into();
        if expected_state != observed_state_roots[phase] {
            return Err(format!("typed_state_root:{phase}"));
        }
    }
    if observed_state_roots != [typed_state_root_before, typed_state_root_after]
        || typed_state_root_before == [0; 64]
        || typed_state_root_after == [0; 64]
    {
        return Err("typed_state_root_binding".to_string());
    }
    verify_typed_root_interface(
        &named,
        u32::try_from(typed_call_count).map_err(|_| "typed_state_root_call_offset".to_string())?,
        &observed_state_roots,
        &payment_roots,
        &replay_roots,
    )?;
    let public_bytes = public_inputs
        .iter()
        .flat_map(|value| value.as_u32().to_be_bytes())
        .collect::<Vec<_>>();
    for (index, field) in projection.iter().enumerate() {
        let expected = typed_hash(
            TYPED_STATE_PROJECTION_DOMAIN,
            &[&[index as u8], &public_bytes],
        );
        if field[..] != expected[..32] {
            return Err(format!("typed_projection:{index}"));
        }
    }
    let expected_projection_digest = typed_hash(
        TYPED_STATE_PROJECTION_DIGEST_DOMAIN,
        &projection
            .iter()
            .map(|field| field.as_slice())
            .collect::<Vec<_>>(),
    );
    if projection_digest != expected_projection_digest {
        return Err("typed_projection_digest".to_string());
    }
    let profile_capacity = state_capacity.to_be_bytes();
    let expected_statement = typed_hash(
        TYPED_STATE_STATEMENT_DOMAIN,
        &[
            &state_profile,
            &profile_capacity,
            &observed_state_roots[0],
            &observed_state_roots[1],
            &payment_roots[0],
            &payment_roots[1],
            &projection_digest,
            &state_air_program,
            &state_air_execution,
            &package_commitment_field,
        ],
    );
    if statement != expected_statement {
        return Err("typed_statement".to_string());
    }
    let epoch = typed_column(&named, "typed_state_authority", "epoch")?[0]
        .as_u32()
        .to_be_bytes();
    let sequence_before = typed_column(&named, "typed_state_authority", "sequence")?[0]
        .as_u32()
        .to_be_bytes();
    let sequence_after = typed_column(&named, "typed_state_authority", "sequence")?[1]
        .as_u32()
        .to_be_bytes();
    let expected_transition = typed_hash(
        TYPED_STATE_TRANSITION_DOMAIN,
        &[
            &state_profile,
            &epoch,
            &sequence_before,
            &sequence_after,
            &observed_state_roots[0],
            &observed_state_roots[1],
            &payment_roots[0],
            &payment_roots[1],
        ],
    );
    if transition != expected_transition {
        return Err("typed_transition".to_string());
    }
    let expected_public_coin = typed_hash(
        TYPED_STATE_PUBLIC_COIN_DOMAIN,
        &[&statement, &transition, &projection_digest],
    );
    if public_coin != expected_public_coin {
        return Err("typed_public_coin".to_string());
    }
    let expected_commitment = typed_hash(
        TYPED_STATE_COMMITMENT_DOMAIN,
        &[&statement, &public_coin, &package_commitment_field],
    );
    if commitment != expected_commitment {
        return Err("typed_commitment".to_string());
    }
    let expected_verifier: [u8; 64] = Sha3_512::digest(TYPED_STATE_VERIFIER_IDENTITY).into();
    if verifier != expected_verifier {
        return Err("typed_verifier".to_string());
    }
    if proof_package.len() < 10 {
        return Err("typed_proof_package_empty".to_string());
    }
    let (package_commitment, package) =
        verify_selected_proof_package(proof_package, air_program, &public_inputs)
            .map_err(|error| format!("typed_proof_package:{error:?}"))?;
    let package_proof_bytes =
        u64::try_from(package.proof.len()).map_err(|_| "typed_proof_package_size".to_string())?;
    if package_commitment != package_commitment_field
        || proof_suite_id != package.bundle.proof_suite_id
        || schedule_commitment != package.bundle.schedule_commitment
        || transcript_root != package.bundle.final_transcript_root
        || evidence_commitment != package.bundle.evidence_commitment
        || component_proof_bytes != package_proof_bytes
        || component_proof_identity == [0; 64]
        || public_input_digest == [0; 64]
        || attribution_digest == [0; 64]
        || worker_report_digest == [0; 64]
    {
        return Err("typed_proof_package_metadata".to_string());
    }
    let expected_component_proof_identity = hash_parts(
        TYPED_STATE_PROOF_DOMAIN,
        &[
            b"proof-identity",
            &package_commitment,
            &package.bundle.proof_suite_id,
            &package.bundle.schedule_commitment,
            &package.bundle.final_transcript_root,
            &package.bundle.evidence_commitment,
            &package.bundle.main_trace_root,
            &package.bundle.interaction_trace_root,
            &package.bundle.composition_root,
            &package.bundle.oods_claims_commitment,
            &package.bundle.fri_mask_root,
            &package.bundle.fri_batch_derivation_commitment,
            &package
                .bundle
                .fri_layer_roots
                .iter()
                .flatten()
                .copied()
                .collect::<Vec<_>>(),
        ],
    );
    if component_proof_identity != expected_component_proof_identity {
        return Err("typed_component_proof_identity".to_string());
    }
    let expected_public_input_digest = hash_parts(
        TYPED_STATE_PROOF_DOMAIN,
        &[
            b"public-inputs",
            &public_bytes,
            &projection.iter().flatten().copied().collect::<Vec<_>>(),
        ],
    );
    if public_input_digest != expected_public_input_digest {
        return Err("typed_public_input_digest".to_string());
    }
    let expected_proof = typed_hash(
        TYPED_STATE_PROOF_IDENTITY_DOMAIN,
        &[&statement, &component_proof_identity],
    );
    if proof != expected_proof {
        return Err("typed_proof_identity".to_string());
    }
    let expected_attempt = typed_hash(
        TYPED_STATE_ATTEMPT_DOMAIN,
        &[&state_profile, &statement, &proof, &attribution_digest],
    );
    if attempt != expected_attempt {
        return Err("typed_attempt".to_string());
    }
    let expected_receipt = typed_hash(
        TYPED_STATE_RECEIPT_DOMAIN,
        &[&statement, &commitment, &proof, &attempt],
    );
    if receipt != expected_receipt {
        return Err("typed_receipt".to_string());
    }
    let expected_fragment = typed_hash(
        TYPED_STATE_FRAGMENT_DOMAIN,
        &[
            &observed_state_roots[0],
            &observed_state_roots[1],
            &projection_digest,
            &statement,
            &transition,
            &commitment,
            &proof,
            &receipt,
            &state_air_program,
            &state_air_execution,
            &package_commitment,
            &component_proof_identity,
            canonical_evidence,
        ],
    );
    if state_air_fragment != expected_fragment {
        return Err("typed_fragment".to_string());
    }
    let expected_composition = typed_hash(
        TYPED_STATE_COMPOSITION_DOMAIN,
        &[
            &statement,
            &transition,
            &projection_digest,
            &public_coin,
            &commitment,
            &proof,
            &receipt,
            &state_air_program,
            &state_air_execution,
            &package_commitment,
            &component_proof_identity,
            canonical_evidence,
            &state_air_fragment,
        ],
    );
    if composition != expected_composition {
        return Err("typed_composition".to_string());
    }
    let expected_binding = typed_hash(
        TYPED_STATE_BINDING_DOMAIN,
        &[
            &observed_state_roots[0],
            &observed_state_roots[1],
            &statement,
            &commitment,
            &proof,
            &receipt,
            &composition,
            &state_air_fragment,
        ],
    );
    if binding_digest != expected_binding {
        return Err("typed_binding".to_string());
    }
    let expected_canonical = [
        TYPED_STATE_COMPONENT_ID,
        &[0_u8],
        TYPED_STATE_AIR_PROGRAM_ID,
        &[0_u8],
        &state_air_program,
        &state_air_execution,
        &package_commitment,
        &proof_suite_id,
        &schedule_commitment,
        &transcript_root,
        &evidence_commitment,
        &component_proof_identity,
        &public_input_digest,
        &attribution_digest,
        &component_proof_bytes.to_be_bytes(),
        &worker_report_digest,
    ]
    .concat();
    if canonical_evidence != expected_canonical {
        return Err("typed_canonical".to_string());
    }
    Ok(StateBindingVerification {
        typed_state: true,
        state_profile,
        state_capacity,
        before_snapshot: Vec::new(),
        after_snapshot: Vec::new(),
        statement,
        binding_digest,
        projection,
        projection_digest,
        public_coin,
        transition,
        commitment,
        proof,
        verifier,
        attempt,
        receipt,
        state_air_program,
        state_air_execution,
        state_air_fragment,
        composition,
        typed_state_root_before,
        typed_state_root_after,
        typed_air_execution: Some(air_execution.to_vec()),
        state_relation_rows: None,
        state_relation_source_digest: [0; 64],
    })
}

fn validate_state_profile_for_h4(
    profile: Profile,
    state: &StateBindingVerification,
) -> Result<(), String> {
    let (expected_profile, expected_capacity) = match profile {
        Profile::K128Calibration => (b"K128_CALIBRATION".as_slice(), 128_u64),
        Profile::K512Calibration => (b"K512_CALIBRATION".as_slice(), 512_u64),
        Profile::K256DesignPoint => return Err("state_boundary_profile".to_string()),
    };
    if state.state_profile != expected_profile || state.state_capacity != expected_capacity {
        return Err("state_boundary_profile_shape".to_string());
    }
    Ok(())
}

fn verify_state_hash_bus_calls(
    boundary: &mut HashBusB16BoundaryFile,
    header: &bl_pq512_crypto_core::hash_bus_b16_boundary::HashBusB16BoundaryHeader,
    state: &StateBindingVerification,
) -> Result<(), String> {
    if !header.state_composed {
        return Err("state_hash_bus_boundary_mode".to_string());
    }
    let base_descriptor = build_hash_bus_descriptor(header.profile)
        .map_err(|error| format!("state_hash_bus_base_descriptor:{error:?}"))?;
    let state_descriptor = build_hash_bus_descriptor_with_state(header.profile)
        .map_err(|error| format!("state_hash_bus_state_descriptor:{error:?}"))?;
    if state_descriptor.descriptor_commitment != header.descriptor_commitment
        || state_descriptor.total_calls != base_descriptor.total_calls + 2
    {
        return Err("state_hash_bus_descriptor_mismatch".to_string());
    }
    if state.typed_state {
        return verify_typed_state_hash_bus_calls(boundary, header, &base_descriptor, state);
    }
    let capacity = state_root_capacity(header.profile)
        .map_err(|error| format!("state_hash_bus_capacity:{error:?}"))?;
    let capacity = usize::try_from(capacity).map_err(|_| "state_hash_bus_capacity".to_string())?;
    let blocks_per_call = u64::try_from(capacity / usize::from(RATE_BYTES) + 1)
        .map_err(|_| "state_hash_bus_blocks".to_string())?;
    let snapshots = [&state.before_snapshot, &state.after_snapshot];
    let roots = [&state.before_snapshot, &state.after_snapshot];
    let expected_roots = [
        hash_parts(STATE_ROOT_DOMAIN, &[snapshots[0].as_slice()]),
        hash_parts(STATE_ROOT_DOMAIN, &[snapshots[1].as_slice()]),
    ];
    let mut cached_shard: Option<(u16, HashBusB16Shard)> = None;
    for (root_index, snapshot) in roots.into_iter().enumerate() {
        let mut message = Vec::with_capacity(STATE_ROOT_DOMAIN.len() + 4 + snapshot.len());
        message.extend_from_slice(STATE_ROOT_DOMAIN);
        message.extend_from_slice(
            &u32::try_from(snapshot.len())
                .map_err(|_| "state_hash_bus_message_length".to_string())?
                .to_be_bytes(),
        );
        message.extend_from_slice(snapshot);
        let call_start = base_descriptor
            .total_permutations
            .checked_add(
                u64::try_from(root_index)
                    .map_err(|_| "state_hash_bus_call_index".to_string())?
                    .checked_mul(blocks_per_call)
                    .ok_or_else(|| "state_hash_bus_call_index".to_string())?,
            )
            .ok_or_else(|| "state_hash_bus_call_index".to_string())?;
        let call_end = call_start
            .checked_add(blocks_per_call - 1)
            .ok_or_else(|| "state_hash_bus_call_end".to_string())?;
        let shard_id = u16::try_from(call_start / PERMUTATIONS_PER_COPROCESSOR_SHARD)
            .map_err(|_| "state_hash_bus_shard".to_string())?;
        if call_end / PERMUTATIONS_PER_COPROCESSOR_SHARD != u64::from(shard_id) {
            return Err("state_hash_bus_call_crosses_shard".to_string());
        }
        if cached_shard
            .as_ref()
            .map_or(true, |(cached_id, _)| *cached_id != shard_id)
        {
            let shard = boundary
                .read_shard(shard_id)
                .map_err(|error| format!("state_hash_bus_read_shard:{error:?}"))?;
            cached_shard = Some((shard_id, shard));
        }
        let mut mismatch = None;
        let digest = for_each_sha3_512_permutation_boundary(
            &message,
            capacity,
            |block_index, _, _, input, output| {
                if mismatch.is_some() {
                    return;
                }
                let global_index = call_start + u64::try_from(block_index).unwrap_or(u64::MAX);
                let (cached_id, shard) = cached_shard.as_ref().expect("cached state shard");
                if *cached_id
                    != u16::try_from(global_index / PERMUTATIONS_PER_COPROCESSOR_SHARD)
                        .unwrap_or(u16::MAX)
                {
                    mismatch = Some(format!("state_hash_bus_shard:{root_index}"));
                    return;
                }
                mismatch =
                    compare_state_bus_plane(&shard.input, input, global_index, root_index, "input")
                        .or_else(|| {
                            compare_state_bus_plane(
                                &shard.output,
                                output,
                                global_index,
                                root_index,
                                "output",
                            )
                        });
            },
        )
        .map_err(|error| format!("state_hash_bus_trace:{root_index}:{error:?}"))?;
        if digest != expected_roots[root_index] {
            return Err(format!("state_hash_bus_digest:{root_index}"));
        }
        if let Some(error) = mismatch {
            return Err(error);
        }
    }
    Ok(())
}

fn verify_typed_state_hash_bus_calls(
    boundary: &mut HashBusB16BoundaryFile,
    header: &bl_pq512_crypto_core::hash_bus_b16_boundary::HashBusB16BoundaryHeader,
    base_descriptor: &bl_pq512_crypto_core::hash_bus::HashBusDescriptor,
    state: &StateBindingVerification,
) -> Result<(), String> {
    let state_descriptor = build_hash_bus_descriptor_with_state(header.profile)
        .map_err(|error| format!("typed_state_hash_bus_descriptor:{error:?}"))?;
    if state_descriptor.descriptor_commitment != header.descriptor_commitment
        || state_descriptor.total_calls != base_descriptor.total_calls + 2
    {
        return Err("typed_state_hash_bus_descriptor_mismatch".to_string());
    }
    let execution = state
        .typed_air_execution
        .as_deref()
        .ok_or_else(|| "typed_state_hash_bus_execution_missing".to_string())?;
    let named = validated_execution_named_tables(
        execution,
        &[
            "typed_state_authority",
            "sha3_digest_batch",
            "typed_state_log_message_batch",
            "claim_payment_key_material",
            "ordered_map_state",
            "ordered_map_endpoint",
            "ordered_map_node",
            "benefit__ordered_map_state",
            "benefit__ordered_map_endpoint",
            "benefit__ordered_map_node",
            "obligation__ordered_map_state",
            "obligation__ordered_map_endpoint",
            "obligation__ordered_map_node",
            "ledger__ordered_map_state",
            "ledger__ordered_map_endpoint",
            "ledger__ordered_map_node",
        ],
    )
    .map_err(|error| format!("typed_state_hash_bus_named_tables:{error:?}"))?;
    let typed_call_count = typed_column(&named, "sha3_digest_batch", "call_index")?
        .len()
        .checked_sub(2)
        .ok_or_else(|| "typed_state_hash_bus_call_count".to_string())?;
    if typed_call_count == 0 {
        return Err("typed_state_hash_bus_call_count".to_string());
    }
    let typed_messages = typed_state_hash_messages(&named, header.profile, typed_call_count)?;
    let typed_digests = typed_digest_vector(
        &named,
        usize::try_from(state_descriptor.total_calls)
            .map_err(|_| "typed_state_hash_bus_digest_count".to_string())?,
    )?;
    let mut call_starts = Vec::<(u64, u64, u64)>::new();
    let mut call_index = 0_u64;
    let mut permutation = 0_u64;
    for run in &state_descriptor.runs {
        let blocks = run
            .capacity
            .checked_div(u64::from(RATE_BYTES))
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| "typed_state_hash_bus_blocks".to_string())?;
        for _ in 0..run.count {
            call_starts.push((call_index, permutation, run.capacity));
            call_index = call_index
                .checked_add(1)
                .ok_or_else(|| "typed_state_hash_bus_call_index".to_string())?;
            permutation = permutation
                .checked_add(blocks)
                .ok_or_else(|| "typed_state_hash_bus_permutation".to_string())?;
        }
    }
    let mut typed_global_indices = Vec::with_capacity(typed_call_count);
    let mut global = 0_u64;
    for run in &base_descriptor.runs {
        if run.component == "replay_map" || run.component == "payment" {
            for _ in 0..run.count {
                typed_global_indices.push(global);
                global = global
                    .checked_add(1)
                    .ok_or_else(|| "typed_state_hash_bus_call_index".to_string())?;
            }
        } else {
            global = global
                .checked_add(run.count)
                .ok_or_else(|| "typed_state_hash_bus_call_index".to_string())?;
        }
    }
    if typed_global_indices.len() != typed_call_count
        || call_starts.len() != state_descriptor.total_calls as usize
    {
        return Err("typed_state_hash_bus_mapping_shape".to_string());
    }
    let mut local_calls = typed_global_indices;
    local_calls.push(base_descriptor.total_calls);
    local_calls.push(base_descriptor.total_calls + 1);
    let mut cached_shard: Option<(u16, HashBusB16Shard)> = None;
    for (local_index, global_index) in local_calls.into_iter().enumerate() {
        let message = typed_messages
            .get(local_index)
            .ok_or_else(|| "typed_state_hash_bus_call_index".to_string())?;
        let digest = typed_digests
            .get(local_index)
            .ok_or_else(|| "typed_state_hash_bus_digest_index".to_string())?;
        let (_, call_start, capacity) = call_starts
            .get(global_index as usize)
            .copied()
            .ok_or_else(|| "typed_state_hash_bus_call_start".to_string())?;
        if message.len()
            > usize::try_from(capacity).map_err(|_| "typed_state_hash_bus_capacity".to_string())?
        {
            return Err(format!(
                "typed_state_hash_bus_message_overflow:{local_index}"
            ));
        }
        let blocks = capacity
            .checked_div(u64::from(RATE_BYTES))
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| "typed_state_hash_bus_blocks".to_string())?;
        let call_end = call_start
            .checked_add(blocks.saturating_sub(1))
            .ok_or_else(|| "typed_state_hash_bus_call_end".to_string())?;
        let shard_id = u16::try_from(call_start / PERMUTATIONS_PER_COPROCESSOR_SHARD)
            .map_err(|_| "typed_state_hash_bus_shard".to_string())?;
        if call_end / PERMUTATIONS_PER_COPROCESSOR_SHARD != u64::from(shard_id) {
            return Err(format!(
                "typed_state_hash_bus_call_crosses_shard:{local_index}"
            ));
        }
        if cached_shard
            .as_ref()
            .map_or(true, |(cached_id, _)| *cached_id != shard_id)
        {
            let shard = boundary
                .read_shard(shard_id)
                .map_err(|error| format!("typed_state_hash_bus_read_shard:{error:?}"))?;
            cached_shard = Some((shard_id, shard));
        }
        let mut mismatch = None;
        let expected_root = match local_index {
            index if index == typed_call_count => Some(state.typed_state_root_before),
            index if index == typed_call_count + 1 => Some(state.typed_state_root_after),
            _ => None,
        };
        let actual_digest = for_each_sha3_512_permutation_boundary(
            message,
            usize::try_from(capacity).map_err(|_| "typed_state_hash_bus_capacity".to_string())?,
            |block_index, _, _, input, output| {
                if mismatch.is_some() {
                    return;
                }
                let global_permutation =
                    call_start + u64::try_from(block_index).unwrap_or(u64::MAX);
                let (cached_id, shard) = cached_shard.as_ref().expect("typed shard cache");
                if *cached_id
                    != u16::try_from(global_permutation / PERMUTATIONS_PER_COPROCESSOR_SHARD)
                        .unwrap_or(u16::MAX)
                {
                    mismatch = Some(format!("typed_state_hash_bus_shard:{local_index}"));
                    return;
                }
                mismatch = compare_state_bus_plane(
                    &shard.input,
                    input,
                    global_permutation,
                    local_index,
                    "input",
                )
                .or_else(|| {
                    compare_state_bus_plane(
                        &shard.output,
                        output,
                        global_permutation,
                        local_index,
                        "output",
                    )
                });
            },
        )
        .map_err(|error| format!("typed_state_hash_bus_trace:{local_index}:{error:?}"))?;
        if actual_digest != *digest || expected_root.is_some_and(|root| root != *digest) {
            return Err(format!("typed_state_hash_bus_digest:{local_index}"));
        }
        if let Some(error) = mismatch {
            return Err(error);
        }
    }
    Ok(())
}

fn compare_state_bus_plane(
    plane: &[u16],
    state: &[u64; 25],
    global_index: u64,
    root_index: usize,
    boundary: &str,
) -> Option<String> {
    let within_shard = global_index % PERMUTATIONS_PER_COPROCESSOR_SHARD;
    let packed_lane = usize::try_from(within_shard % 16).ok()?;
    let group = usize::try_from(within_shard / 16).ok()?;
    let group_count = usize::try_from(GROUP_COUNT).ok()?;
    if plane.len() != KECCAK_STATE_BITS * group_count {
        return Some(format!(
            "state_hash_bus_plane_shape:{root_index}:{boundary}"
        ));
    }
    for wire in 0..KECCAK_STATE_BITS {
        let expected = ((state[wire / 64] >> (wire % 64)) & 1) as u16;
        let actual = (plane[wire * group_count + group] >> packed_lane) & 1;
        if actual != expected {
            return Some(format!(
                "state_hash_bus_mismatch:{root_index}:{boundary}:{global_index}:{wire}"
            ));
        }
    }
    None
}

fn parse_fields(stdout: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let decoded = std::str::from_utf8(stdout).map_err(|_| "stdout_utf8".to_string())?;
    let mut fields = BTreeMap::new();
    for line in decoded.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| "stdout_line".to_string())?;
        if key.is_empty()
            || value.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            || fields.insert(key.to_string(), value.to_string()).is_some()
        {
            return Err("stdout_field".to_string());
        }
    }
    if fields.is_empty() {
        return Err("stdout_empty".to_string());
    }
    Ok(fields)
}

fn validate_shard_fields(
    fields: &BTreeMap<String, String>,
    shard: u16,
    profile: u8,
    file_digest: &str,
    parent_binding: &str,
    state_statement_digest: Option<&str>,
    state_binding_digest: Option<&str>,
    state_binding: Option<&StateBindingVerification>,
) -> Result<(), String> {
    for key in [
        "sumcheck_chain_verified",
        "terminal_target_verified",
        "base_target_verified",
        "main_spotchecks_verified",
        "auxiliary_spotchecks_verified",
        "native_spotcheck_verifier_attached",
        "all_merkle_roots_independently_verified",
        "exact_candidate_soundness_parameter_ledger_closed",
        "implementation_theorem_binding_closed",
        "construction_8_2_hiding_simulator_gate_attached",
        "seven_claim_row_binding_attached",
        "gkr_mask_cpu_gpu_root_parity",
        "gkr_row_parameters_derived_in_rust",
        "component_rows_extracted_from_packed_semantic_source",
        "semantic_hash_bus_statement_bound",
        "gpu_compact_row_sumcheck_attached",
        "independent_final_answer_target_attached",
        "real_gkr_producer_attached",
        "independent_fp16_arithmetic_verifier_attached",
        "launch_authenticated_public_coin",
        "atomic_gkr_pcs_coordinator_attached",
        "atomic_gkr_pcs_verifier_attached",
        "complete_fresh_proof_independently_verified",
    ] {
        if required(fields, key)? != "true" {
            return Err(format!("shard_gate:{shard}:{key}"));
        }
    }
    for (key, expected) in [
        ("activation", "false"),
        ("proof_suite_id", "null"),
        ("paper_construction", "8.2"),
        ("gkr_claim_count", "7"),
        ("duplicate_full_source_replay", "false"),
        ("per_proof_merkle_mutation_replays", "false"),
        ("complete_pcs_qualification", "false"),
        ("complete_proof_qualification", "false"),
    ] {
        if required(fields, key)? != expected {
            return Err(format!("shard_value:{shard}:{key}"));
        }
    }
    if required(fields, "semantic_hash_bus_profile")? != profile.to_string()
        || required(fields, "semantic_hash_bus_shard")? != shard.to_string()
        || required(fields, "semantic_hash_bus_file_sha3_512")? != file_digest
        || required(fields, "atomic_parent_binding_sha3_512")? != parent_binding
    {
        return Err(format!("shard_binding:{shard}"));
    }
    validate_state_binding_fields(
        fields,
        shard,
        state_statement_digest,
        state_binding_digest,
        state_binding,
    )?;
    Ok(())
}

fn validate_state_binding_fields(
    fields: &BTreeMap<String, String>,
    shard: u16,
    expected_statement: Option<&str>,
    expected_binding: Option<&str>,
    expected_state: Option<&StateBindingVerification>,
) -> Result<(), String> {
    let zero = hex(&[0; 64]);
    let zero_field = hex(&[0; 32]);
    match (expected_statement, expected_binding, expected_state) {
        (Some(statement), Some(binding), Some(state)) => {
            if state.typed_state {
                if required(fields, "typed_state_component_verified")? != "true"
                    || required(fields, "state_plane_binding_attached")? != "true"
                    || required(fields, "state_hash_bus_calls_verified")? != "true"
                    || required(fields, "state_plane_statement_sha3_512")? != statement
                    || required(fields, "state_plane_binding_digest_sha3_512")? != binding
                    || required(fields, "state_plane_public_abi_count")? != "12"
                    || required(fields, "state_air_fragment_verified")? != "true"
                    || required(fields, "state_relation_gkr_attached")? != "false"
                    || required(fields, "state_relation_source_sha3_512")? != zero
                    || required(fields, "state_relation_gkr_digest_sha3_512")? != zero
                    || required(fields, "state_relation_interactive_verified")? != "false"
                    || required(fields, "state_plane_projection_digest_sha3_512")?
                        != hex(&state.projection_digest)
                    || required(fields, "state_plane_public_coin_sha3_512")?
                        != hex(&state.public_coin)
                    || required(fields, "state_plane_transition_digest_sha3_512")?
                        != hex(&state.transition)
                    || required(fields, "state_plane_commitment_digest_sha3_512")?
                        != hex(&state.commitment)
                    || required(fields, "state_plane_proof_identity_sha3_512")? != hex(&state.proof)
                    || required(fields, "state_plane_verifier_identity_sha3_512")?
                        != hex(&state.verifier)
                    || required(fields, "state_plane_attempt_id_sha3_512")? != hex(&state.attempt)
                    || required(fields, "state_plane_receipt_digest_sha3_512")?
                        != hex(&state.receipt)
                    || required(fields, "state_plane_composition_digest_sha3_512")?
                        != hex(&state.composition)
                    || required(fields, "state_air_program_commitment_sha3_512")?
                        != hex(&state.state_air_program)
                    || required(fields, "state_air_execution_commitment_sha3_512")?
                        != hex(&state.state_air_execution)
                    || required(fields, "state_air_fragment_digest_sha3_512")?
                        != hex(&state.state_air_fragment)
                {
                    return Err(format!("shard_state_binding:{shard}"));
                }
                for (index, field) in state.projection.iter().enumerate() {
                    if required(fields, &format!("state_plane_public_abi_{index:02}"))?
                        != hex(field)
                    {
                        return Err(format!("shard_state_binding:{shard}"));
                    }
                }
                return Ok(());
            }
            let state_relation_digest = decode_hex_64(
                required(fields, "state_relation_gkr_digest_sha3_512")?,
                "state_relation_gkr_digest",
            )?;
            if state_relation_digest == [0; 64] {
                return Err(format!("shard_state_binding:{shard}"));
            }
            if required(fields, "state_plane_binding_attached")? != "true"
                || required(fields, "state_hash_bus_calls_verified")? != "true"
                || required(fields, "state_plane_statement_sha3_512")? != statement
                || required(fields, "state_plane_binding_digest_sha3_512")? != binding
                || required(fields, "state_plane_public_abi_count")? != "12"
                || required(fields, "state_air_fragment_verified")? != "true"
                || required(fields, "state_plane_projection_digest_sha3_512")?
                    != hex(&state.projection_digest)
                || required(fields, "state_plane_public_coin_sha3_512")? != hex(&state.public_coin)
                || required(fields, "state_plane_transition_digest_sha3_512")?
                    != hex(&state.transition)
                || required(fields, "state_plane_commitment_digest_sha3_512")?
                    != hex(&state.commitment)
                || required(fields, "state_plane_proof_identity_sha3_512")? != hex(&state.proof)
                || required(fields, "state_plane_verifier_identity_sha3_512")?
                    != hex(&state.verifier)
                || required(fields, "state_plane_attempt_id_sha3_512")? != hex(&state.attempt)
                || required(fields, "state_plane_receipt_digest_sha3_512")? != hex(&state.receipt)
                || required(fields, "state_plane_composition_digest_sha3_512")?
                    != hex(&state.composition)
                || required(fields, "state_air_program_commitment_sha3_512")?
                    != hex(&state.state_air_program)
                || required(fields, "state_air_execution_commitment_sha3_512")?
                    != hex(&state.state_air_execution)
                || required(fields, "state_air_fragment_digest_sha3_512")?
                    != hex(&state.state_air_fragment)
                || required(fields, "state_relation_gkr_attached")? != "true"
                || required(fields, "state_relation_source_sha3_512")?
                    != hex(&state.state_relation_source_digest)
                || required(fields, "state_relation_interactive_verified")? != "true"
            {
                return Err(format!("shard_state_binding:{shard}"));
            }
            for (index, field) in state.projection.iter().enumerate() {
                if required(fields, &format!("state_plane_public_abi_{index:02}"))? != hex(field) {
                    return Err(format!("shard_state_binding:{shard}"));
                }
            }
        }
        (None, None, None) => {
            if required(fields, "state_plane_binding_attached")? != "false"
                || required(fields, "state_hash_bus_calls_verified")? != "false"
                || required(fields, "state_plane_statement_sha3_512")? != zero
                || required(fields, "state_plane_binding_digest_sha3_512")? != zero
                || required(fields, "state_plane_public_abi_count")? != "0"
                || required(fields, "state_air_fragment_verified")? != "false"
                || required(fields, "state_relation_gkr_attached")? != "false"
                || required(fields, "state_relation_source_sha3_512")? != zero
                || required(fields, "state_relation_gkr_digest_sha3_512")? != zero
                || required(fields, "state_relation_interactive_verified")? != "false"
            {
                return Err(format!("shard_state_binding:{shard}"));
            }
            for key in [
                "state_plane_projection_digest_sha3_512",
                "state_plane_public_coin_sha3_512",
                "state_plane_transition_digest_sha3_512",
                "state_plane_commitment_digest_sha3_512",
                "state_plane_proof_identity_sha3_512",
                "state_plane_verifier_identity_sha3_512",
                "state_plane_attempt_id_sha3_512",
                "state_plane_receipt_digest_sha3_512",
                "state_plane_composition_digest_sha3_512",
                "state_air_program_commitment_sha3_512",
                "state_air_execution_commitment_sha3_512",
                "state_air_fragment_digest_sha3_512",
            ] {
                if required(fields, key)? != zero {
                    return Err(format!("shard_state_binding:{shard}"));
                }
            }
            for index in 0..12 {
                if required(fields, &format!("state_plane_public_abi_{index:02}"))? != zero_field {
                    return Err(format!("shard_state_binding:{shard}"));
                }
            }
        }
        _ => return Err(format!("shard_state_binding_shape:{shard}")),
    }
    Ok(())
}

fn required<'a>(fields: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, String> {
    fields
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing:{key}"))
}

fn parse_f64(fields: &BTreeMap<String, String>, key: &str) -> Result<f64, String> {
    let value = required(fields, key)?
        .parse::<f64>()
        .map_err(|_| format!("number:{key}"))?;
    if !value.is_finite() {
        return Err(format!("number:{key}"));
    }
    Ok(value)
}

fn decode_hex_64(encoded: &str, label: &str) -> Result<[u8; 64], String> {
    if encoded.len() != 128 {
        return Err(format!("{label}_length"));
    }
    let mut output = [0_u8; 64];
    for (index, destination) in output.iter_mut().enumerate() {
        *destination = u8::from_str_radix(&encoded[2 * index..2 * index + 2], 16)
            .map_err(|_| format!("{label}_encoding"))?;
    }
    Ok(output)
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut output, "{byte:02x}").expect("string write");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use bl_pq512_crypto_core::{
        hash_bus_b16_boundary::{
            HASH_BUS_B16_HEADER_BYTES, HASH_BUS_B16_STATE_MAGIC, HASH_BUS_B16_STATE_VERSION,
        },
        hash_bus_source::{HashBusMessage, for_each_hash_bus_b16_group},
    };

    fn cuda_source(name: &str) -> Option<&'static str> {
        match name {
            "cuda_fp16_zk_rs_theorem8_1_k128_prototype.py" => Some(include_str!(
                "../../cuda/cuda_fp16_zk_rs_theorem8_1_k128_prototype.py"
            )),
            "cuda_hash_bus_b16_gkr_worker.py" => {
                Some(include_str!("../../cuda/cuda_hash_bus_b16_gkr_worker.py"))
            }
            "cuda_fp16_zk_rs_interleaved_k128_prototype.py" => Some(include_str!(
                "../../cuda/cuda_fp16_zk_rs_interleaved_k128_prototype.py"
            )),
            "cuda_dag_packed_accumulator_benchmark.py" => Some(include_str!(
                "../../cuda/cuda_dag_packed_accumulator_benchmark.py"
            )),
            "cuda_fp16_tower_kat.py" => Some(include_str!("../../cuda/cuda_fp16_tower_kat.py")),
            "cuda_m31_brakedown_factor_benchmark.py" => Some(include_str!(
                "../../cuda/cuda_m31_brakedown_factor_benchmark.py"
            )),
            "cuda_m31_brakedown_k128_prototype.py" => Some(include_str!(
                "../../cuda/cuda_m31_brakedown_k128_prototype.py"
            )),
            "cuda_m31_sha3_matrix_benchmark.py" => {
                Some(include_str!("../../cuda/cuda_m31_sha3_matrix_benchmark.py"))
            }
            "cuda_m31_segment_merkle.py" => {
                Some(include_str!("../../cuda/cuda_m31_segment_merkle.py"))
            }
            "cuda_pcs_sha3_merkle_benchmark.py" => {
                Some(include_str!("../../cuda/cuda_pcs_sha3_merkle_benchmark.py"))
            }
            "cuda_sparse_round_kat.py" => Some(include_str!("../../cuda/cuda_sparse_round_kat.py")),
            "cuda_dag_shared_group_fold_benchmark.py" => Some(include_str!(
                "../../cuda/cuda_dag_shared_group_fold_benchmark.py"
            )),
            "cuda_dag_shared_group_message_benchmark.py" => Some(include_str!(
                "../../cuda/cuda_dag_shared_group_message_benchmark.py"
            )),
            "cuda_fp16_b16_binary_bridge_benchmark.py" => Some(include_str!(
                "../../cuda/cuda_fp16_b16_binary_bridge_benchmark.py"
            )),
            _ => None,
        }
    }

    fn local_cuda_imports(source: &str) -> Vec<String> {
        source
            .lines()
            .filter_map(|line| {
                let line = line.trim_start();
                let module = if let Some(rest) = line.strip_prefix("from cuda_") {
                    rest.split_ascii_whitespace().next()
                } else if let Some(rest) = line.strip_prefix("import cuda_") {
                    rest.split(|character: char| {
                        character.is_ascii_whitespace() || character == ','
                    })
                    .next()
                } else {
                    None
                }?;
                Some(format!("cuda_{module}.py"))
            })
            .collect()
    }

    fn native_source(name: &str) -> Option<&'static str> {
        match name {
            "fp16_zk_rs_interleaved_verify.exe" => {
                Some(include_str!("fp16_zk_rs_interleaved_verify.rs"))
            }
            "fp16_zk_rs_theorem8_1_transcript.exe" => {
                Some(include_str!("fp16_zk_rs_theorem8_1_transcript.rs"))
            }
            "fp16_zk_rs_spotcheck_verify.exe" => {
                Some(include_str!("fp16_zk_rs_spotcheck_verify.rs"))
            }
            "fp16_zk_rs_answer_code_verify.exe" => {
                Some(include_str!("fp16_zk_rs_answer_code_verify.rs"))
            }
            "fp16_zk_rs_answer_target.exe" => Some(include_str!("fp16_zk_rs_answer_target.rs")),
            "fp16_zk_rs_row_sumcheck_prover.exe" => {
                Some(include_str!("fp16_zk_rs_row_sumcheck_prover.rs"))
            }
            "fp16_zk_rs_public_coin_bridge.exe" => {
                Some(include_str!("fp16_zk_rs_public_coin_bridge.rs"))
            }
            "chained_public_coin_service.exe" => {
                Some(include_str!("chained_public_coin_service.rs"))
            }
            _ => None,
        }
    }

    fn native_child_executables(source: &str) -> Vec<&str> {
        source
            .split(".join(\"")
            .skip(1)
            .filter_map(|suffix| suffix.split_once("\")").map(|(name, _)| name))
            .filter(|name| name.ends_with(".exe"))
            .collect()
    }

    #[test]
    fn execution_manifest_covers_transitive_local_python_imports() {
        let entrypoints = [
            "cuda_fp16_zk_rs_theorem8_1_k128_prototype.py",
            "cuda_hash_bus_b16_gkr_worker.py",
        ];
        let expected = entrypoints
            .into_iter()
            .chain(CUDA_DEPENDENCIES)
            .collect::<std::collections::BTreeSet<_>>();
        let mut pending = entrypoints.into_iter().collect::<Vec<_>>();
        let mut reached = std::collections::BTreeSet::new();
        while let Some(name) = pending.pop() {
            if !reached.insert(name) {
                continue;
            }
            let source = cuda_source(name).unwrap_or_else(|| panic!("unmanifested import: {name}"));
            for dependency in local_cuda_imports(source) {
                let dependency = expected
                    .get(dependency.as_str())
                    .copied()
                    .unwrap_or_else(|| panic!("unmanifested import: {dependency}"));
                pending.push(dependency);
            }
        }
        assert_eq!(reached, expected);
    }

    #[test]
    fn execution_manifest_covers_transitive_native_executables() {
        let entrypoints = &NATIVE_EXECUTABLES[..7];
        let expected = NATIVE_EXECUTABLES
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        let mut pending = entrypoints.to_vec();
        let mut reached = std::collections::BTreeSet::new();
        while let Some(name) = pending.pop() {
            if !reached.insert(name) {
                continue;
            }
            let source =
                native_source(name).unwrap_or_else(|| panic!("unmanifested executable: {name}"));
            for dependency in native_child_executables(source) {
                let dependency = expected
                    .get(dependency)
                    .copied()
                    .unwrap_or_else(|| panic!("unmanifested executable: {dependency}"));
                pending.push(dependency);
            }
        }
        assert_eq!(reached, expected);
    }

    #[test]
    fn parser_rejects_duplicate_and_noncanonical_fields() {
        assert_eq!(
            parse_fields(b"a=true\na=false\n").unwrap_err(),
            "stdout_field"
        );
        assert_eq!(parse_fields(b"A=true\n").unwrap_err(), "stdout_field");
        assert_eq!(parse_fields(b"a\n").unwrap_err(), "stdout_line");
    }

    #[test]
    fn state_snapshot_rejects_duplicate_present_keys() {
        let mut encoded = empty_state_snapshot(b"K128_CALIBRATION", 2, 0);
        let header =
            6 + 1 + 1 + b"K128_CALIBRATION".len() + 1 + b"BL-PQ512-STATE-PLANE-V1".len() + 24;
        let entry_width = 137;
        for index in 0..2 {
            let offset = header + index * entry_width;
            encoded[offset] = 1;
            encoded[offset + 1..offset + 9].copy_from_slice(&(index as u64).to_be_bytes());
            encoded[offset + 9..offset + 73].fill(0x41);
            encoded[offset + 73..offset + 137].fill(index as u8 + 1);
        }
        assert!(matches!(
            parse_state_snapshot(&encoded),
            Err(error) if error == "state_binding_snapshot_duplicate_key"
        ));
    }

    fn empty_state_snapshot(profile: &[u8], capacity: u64, sequence: u64) -> Vec<u8> {
        let mut encoded = Vec::new();
        let parameter = b"BL-PQ512-STATE-PLANE-V1";
        encoded.extend_from_slice(b"BLSP01");
        encoded.push(1);
        encoded.push(u8::try_from(profile.len()).unwrap());
        encoded.extend_from_slice(profile);
        encoded.push(u8::try_from(parameter.len()).unwrap());
        encoded.extend_from_slice(parameter);
        encoded.extend_from_slice(&capacity.to_be_bytes());
        encoded.extend_from_slice(&1_u64.to_be_bytes());
        encoded.extend_from_slice(&sequence.to_be_bytes());
        for index in 0..capacity {
            encoded.push(0);
            encoded.extend_from_slice(&index.to_be_bytes());
            encoded.extend_from_slice(&[0_u8; 128]);
        }
        encoded
    }

    fn write_state_bus_fixture(path: &Path, before: &[u8], after: &[u8]) {
        use std::io::{BufWriter, Write};

        let profile = Profile::K128Calibration;
        let base = build_hash_bus_descriptor(profile).unwrap();
        let descriptor = build_hash_bus_descriptor_with_state(profile).unwrap();
        let root_capacity = state_root_capacity(profile).unwrap();
        let root_before = [
            STATE_ROOT_DOMAIN,
            &u32::try_from(before.len()).unwrap().to_be_bytes(),
            before,
        ]
        .concat();
        let root_after = [
            STATE_ROOT_DOMAIN,
            &u32::try_from(after.len()).unwrap().to_be_bytes(),
            after,
        ]
        .concat();
        let empty_digest: [u8; 64] = Sha3_512::digest([]).into();
        let mut messages = Vec::with_capacity(descriptor.total_calls as usize);
        for run in &base.runs {
            for _ in 0..run.count {
                messages.push(HashBusMessage {
                    message: &[],
                    capacity: run.capacity,
                    digest: empty_digest,
                });
            }
        }
        messages.extend([
            HashBusMessage {
                message: &root_before,
                capacity: root_capacity,
                digest: Sha3_512::digest(&root_before).into(),
            },
            HashBusMessage {
                message: &root_after,
                capacity: root_capacity,
                digest: Sha3_512::digest(&root_after).into(),
            },
        ]);
        let file = std::fs::File::create(path).unwrap();
        let mut writer = BufWriter::with_capacity(1 << 20, file);
        writer.write_all(HASH_BUS_B16_STATE_MAGIC).unwrap();
        writer
            .write_all(&HASH_BUS_B16_STATE_VERSION.to_be_bytes())
            .unwrap();
        writer.write_all(&[Profile::K128Calibration as u8]).unwrap();
        writer.write_all(&[7_u8; 64]).unwrap();
        writer.write_all(&descriptor.descriptor_commitment).unwrap();
        writer.write_all(&[9_u8; 64]).unwrap();
        writer
            .write_all(&descriptor.coprocessor_shards.to_be_bytes())
            .unwrap();
        writer
            .write_all(&descriptor.padded_permutations.to_be_bytes())
            .unwrap();
        writer
            .write_all(&(KECCAK_STATE_BITS as u16).to_be_bytes())
            .unwrap();
        let values = KECCAK_STATE_BITS * GROUP_COUNT as usize;
        let mut input_plane = vec![0_u16; values];
        let mut output_plane = vec![0_u16; values];
        let mut group_index = 0_usize;
        for_each_hash_bus_b16_group(&descriptor, messages, |_, _, input, output| {
            for wire in 0..KECCAK_STATE_BITS {
                input_plane[wire * GROUP_COUNT as usize + group_index] = input[wire];
                output_plane[wire * GROUP_COUNT as usize + group_index] = output[wire];
            }
            group_index += 1;
            Ok(())
        })
        .unwrap();
        for plane in [&input_plane, &output_plane] {
            for pattern in plane {
                writer.write_all(&pattern.to_le_bytes()).unwrap();
            }
        }
        writer.flush().unwrap();
    }

    fn minimal_state_binding(before: Vec<u8>, after: Vec<u8>) -> StateBindingVerification {
        StateBindingVerification {
            typed_state: false,
            state_profile: b"K128_CALIBRATION".to_vec(),
            state_capacity: 128,
            before_snapshot: before,
            after_snapshot: after,
            statement: [1; 64],
            binding_digest: [2; 64],
            projection: [[3; 32]; 12],
            projection_digest: [4; 64],
            public_coin: [5; 64],
            transition: [6; 64],
            commitment: [7; 64],
            proof: [8; 64],
            verifier: [9; 64],
            attempt: [10; 64],
            receipt: [11; 64],
            state_air_program: [12; 64],
            state_air_execution: [13; 64],
            state_air_fragment: [14; 64],
            composition: [15; 64],
            typed_state_root_before: [0; 64],
            typed_state_root_after: [0; 64],
            typed_air_execution: None,
            state_relation_rows: None,
            state_relation_source_digest: [0; 64],
        }
    }

    #[test]
    fn state_hash_bus_root_calls_are_native_and_mutation_bound() {
        use std::io::{Read, Seek, SeekFrom, Write};

        let path = std::env::temp_dir().join(format!(
            "bl-state-hash-bus-native-{}.b16",
            std::process::id()
        ));
        let before = empty_state_snapshot(b"K128_CALIBRATION", 128, 0);
        let after = empty_state_snapshot(b"K128_CALIBRATION", 128, 1);
        write_state_bus_fixture(&path, &before, &after);
        let state = minimal_state_binding(before, after);
        let mut boundary = HashBusB16BoundaryFile::open(&path).unwrap();
        let header = boundary.header().clone();
        verify_state_hash_bus_calls(&mut boundary, &header, &state).unwrap();
        drop(boundary);

        let base = build_hash_bus_descriptor(Profile::K128Calibration).unwrap();
        let global_index = base.total_permutations;
        let group = global_index / 16;
        let offset = HASH_BUS_B16_HEADER_BYTES + (group * 2);
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        let mut encoded = [0_u8; 2];
        file.read_exact(&mut encoded).unwrap();
        let original_value = u16::from_le_bytes(encoded);
        let value = original_value ^ u16::MAX;
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&value.to_le_bytes()).unwrap();
        drop(file);

        let mut mutated = HashBusB16BoundaryFile::open(&path).unwrap();
        let mutated_value = mutated.read_shard(0).unwrap().input[group as usize];
        assert_eq!(mutated_value, value);
        assert_ne!(mutated_value, original_value);
        let mutated_header = mutated.header().clone();
        assert!(verify_state_hash_bus_calls(&mut mutated, &mutated_header, &state).is_err());
        drop(mutated);
        std::fs::remove_file(path).unwrap();
    }

    fn test_state_binding(seed: u8) -> StateBindingVerification {
        StateBindingVerification {
            typed_state: false,
            state_profile: b"K512_CALIBRATION".to_vec(),
            state_capacity: 512,
            before_snapshot: vec![seed; 8],
            after_snapshot: vec![seed.wrapping_add(1); 8],
            statement: [seed; 64],
            binding_digest: [seed.wrapping_add(1); 64],
            projection: [[seed.wrapping_add(2); 32]; 12],
            projection_digest: [seed.wrapping_add(3); 64],
            public_coin: [seed.wrapping_add(4); 64],
            transition: [seed.wrapping_add(5); 64],
            commitment: [seed.wrapping_add(6); 64],
            proof: [seed.wrapping_add(7); 64],
            verifier: [seed.wrapping_add(8); 64],
            attempt: [seed.wrapping_add(9); 64],
            receipt: [seed.wrapping_add(10); 64],
            state_air_program: [seed.wrapping_add(11); 64],
            state_air_execution: [seed.wrapping_add(12); 64],
            state_air_fragment: [seed.wrapping_add(13); 64],
            composition: [seed.wrapping_add(14); 64],
            typed_state_root_before: [0; 64],
            typed_state_root_after: [0; 64],
            typed_air_execution: None,
            state_relation_rows: None,
            state_relation_source_digest: [seed.wrapping_add(15); 64],
        }
    }

    #[test]
    fn parent_and_receipt_bind_every_input() {
        let state = test_state_binding(11);
        let changed_state = test_state_binding(12);
        let parent = atomic_parent_binding(
            3,
            [1; 64],
            [2; 64],
            [3; 64],
            4,
            524_288,
            1_600,
            K512_FILE_BYTES,
            [4; 64],
            [5; 64],
            [10; 64],
            [6; 64],
            Some(&state),
        );
        let changed = atomic_parent_binding(
            3,
            [1; 64],
            [2; 64],
            [3; 64],
            4,
            524_288,
            1_600,
            K512_FILE_BYTES,
            [4; 64],
            [5; 64],
            [10; 64],
            [7; 64],
            Some(&changed_state),
        );
        assert_ne!(parent, changed);
        let evidence = [ShardEvidence {
            wall_seconds: 1.0,
            host_peak_mb: 2.0,
            device_peak_mb: 3.0,
            scratch_mb: 0.0,
            stdout_digest: [8; 64],
            bundle_digest: [9; 64],
        }];
        assert_ne!(
            atomic_receipt_with_state(parent, [6; 64], &state, &evidence),
            atomic_receipt_with_state(changed, [6; 64], &changed_state, &evidence)
        );
    }

    #[test]
    fn state_binding_fields_are_exactly_replayed() {
        let state = test_state_binding(11);
        let statement = hex(&state.statement);
        let binding = hex(&state.binding_digest);
        let mut fields = BTreeMap::from([
            (
                "state_plane_binding_attached".to_string(),
                "true".to_string(),
            ),
            (
                "state_plane_statement_sha3_512".to_string(),
                statement.clone(),
            ),
            (
                "state_plane_binding_digest_sha3_512".to_string(),
                binding.clone(),
            ),
            (
                "state_hash_bus_calls_verified".to_string(),
                "true".to_string(),
            ),
            ("state_plane_public_abi_count".to_string(), "12".to_string()),
            (
                "state_air_fragment_verified".to_string(),
                "true".to_string(),
            ),
            (
                "state_plane_projection_digest_sha3_512".to_string(),
                hex(&state.projection_digest),
            ),
            (
                "state_plane_public_coin_sha3_512".to_string(),
                hex(&state.public_coin),
            ),
            (
                "state_plane_transition_digest_sha3_512".to_string(),
                hex(&state.transition),
            ),
            (
                "state_plane_commitment_digest_sha3_512".to_string(),
                hex(&state.commitment),
            ),
            (
                "state_plane_proof_identity_sha3_512".to_string(),
                hex(&state.proof),
            ),
            (
                "state_plane_verifier_identity_sha3_512".to_string(),
                hex(&state.verifier),
            ),
            (
                "state_plane_attempt_id_sha3_512".to_string(),
                hex(&state.attempt),
            ),
            (
                "state_plane_receipt_digest_sha3_512".to_string(),
                hex(&state.receipt),
            ),
            (
                "state_plane_composition_digest_sha3_512".to_string(),
                hex(&state.composition),
            ),
            (
                "state_air_program_commitment_sha3_512".to_string(),
                hex(&state.state_air_program),
            ),
            (
                "state_air_execution_commitment_sha3_512".to_string(),
                hex(&state.state_air_execution),
            ),
            (
                "state_air_fragment_digest_sha3_512".to_string(),
                hex(&state.state_air_fragment),
            ),
            (
                "state_relation_gkr_attached".to_string(),
                "true".to_string(),
            ),
            (
                "state_relation_source_sha3_512".to_string(),
                hex(&state.state_relation_source_digest),
            ),
            (
                "state_relation_gkr_digest_sha3_512".to_string(),
                hex(&[16; 64]),
            ),
            (
                "state_relation_interactive_verified".to_string(),
                "true".to_string(),
            ),
        ]);
        for (index, field) in state.projection.iter().enumerate() {
            fields.insert(format!("state_plane_public_abi_{index:02}"), hex(field));
        }
        assert!(
            validate_state_binding_fields(
                &fields,
                0,
                Some(&statement),
                Some(&binding),
                Some(&state),
            )
            .is_ok()
        );
        fields.insert(
            "state_plane_binding_digest_sha3_512".to_string(),
            hex(&[13; 64]),
        );
        assert_eq!(
            validate_state_binding_fields(
                &fields,
                0,
                Some(&statement),
                Some(&binding),
                Some(&state),
            )
            .unwrap_err(),
            "shard_state_binding:0"
        );
    }
}
