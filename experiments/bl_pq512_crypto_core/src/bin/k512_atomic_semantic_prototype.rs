use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

use bl_pq512_crypto_core::{
    hash_bus_b16_boundary::HashBusB16BoundaryFile, hash_bus_b16_gkr_plan::HashBusB16GkrPlan,
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
const EXECUTION_MANIFEST_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/EXECUTION-MANIFEST/v1\0";
const STATE_BINDING_MAGIC: &[u8] = b"BLSB01";
const STATE_MAGIC: &[u8] = b"BLSP01";
const COMMITMENT_MAGIC: &[u8] = b"BLHP01";
const STATE_VERSION: u8 = 1;
const COMMITMENT_VERSION: u8 = 1;
const STATE_MAX_CAPACITY: u64 = 4_096;
const STATE_BINDING_MAX_BYTES: u64 = 16 * 1024 * 1024;
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
    statement: [u8; 64],
    binding_digest: [u8; 64],
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

    let boundary_file =
        HashBusB16BoundaryFile::open(&boundary).map_err(|error| format!("boundary:{error:?}"))?;
    let header = boundary_file.header();
    let (expected_shards, expected_file_bytes, profile_name, latency_limit_seconds) =
        match header.profile {
            Profile::K128Calibration => (K128_SHARDS, K128_FILE_BYTES, "k128", 30.0),
            Profile::K512Calibration => (K512_SHARDS, K512_FILE_BYTES, "k512", 180.0),
            Profile::K256DesignPoint => return Err("boundary_profile".to_string()),
        };
    if header.coprocessor_shards != expected_shards || header.file_bytes != expected_file_bytes {
        return Err("boundary_shape".to_string());
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
    let state_binding_digest = state_binding
        .as_ref()
        .map(|binding| binding.binding_digest)
        .unwrap_or([0; 64]);
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
        state_binding_digest,
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
                );
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

    let receipt = match state_binding {
        Some(_) => {
            atomic_receipt_with_state(parent_binding, statement, state_binding_digest, &evidence)
        }
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
        hex(&state_binding_digest)
    );
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
    state_binding_digest: [u8; 64],
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
    hash.update(state_binding_digest);
    hash.finalize().into()
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
    state_binding_digest: [u8; 64],
    evidence: &[ShardEvidence],
) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(ATOMIC_RECEIPT_DOMAIN);
    hash.update(parent_binding);
    hash.update(statement);
    hash.update(state_binding_digest);
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

struct StateSnapshotWire {
    profile: Vec<u8>,
    parameter: Vec<u8>,
    capacity: u64,
    epoch: u64,
    sequence: u64,
    entries: Vec<StateEntryWire>,
    root: [u8; 64],
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
    if !cursor.done() {
        return Err("state_binding_snapshot_trailing_bytes".to_string());
    }
    let root = hash_parts(STATE_ROOT_DOMAIN, &[encoded]);
    Ok(StateSnapshotWire {
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

fn verify_state_binding(path: &Path) -> Result<StateBindingVerification, String> {
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
    if cursor.u8("binding_version")? != STATE_VERSION {
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
    if !cursor.done() {
        return Err("state_binding_trailing_bytes".to_string());
    }
    if commitment.public_coin != public_coin {
        return Err("state_binding_commitment_public_coin".to_string());
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
        ],
    );
    Ok(StateBindingVerification {
        statement,
        binding_digest,
    })
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
        "five_claim_row_binding_attached",
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
        ("gkr_claim_count", "5"),
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
    validate_state_binding_fields(fields, shard, state_statement_digest, state_binding_digest)?;
    Ok(())
}

fn validate_state_binding_fields(
    fields: &BTreeMap<String, String>,
    shard: u16,
    expected_statement: Option<&str>,
    expected_binding: Option<&str>,
) -> Result<(), String> {
    let zero = hex(&[0; 64]);
    match (expected_statement, expected_binding) {
        (Some(statement), Some(binding)) => {
            if required(fields, "state_plane_binding_attached")? != "true"
                || required(fields, "state_plane_statement_sha3_512")? != statement
                || required(fields, "state_plane_binding_digest_sha3_512")? != binding
            {
                return Err(format!("shard_state_binding:{shard}"));
            }
        }
        (None, None) => {
            if required(fields, "state_plane_binding_attached")? != "false"
                || required(fields, "state_plane_statement_sha3_512")? != zero
                || required(fields, "state_plane_binding_digest_sha3_512")? != zero
            {
                return Err(format!("shard_state_binding:{shard}"));
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
    fn parent_and_receipt_bind_every_input() {
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
            [11; 64],
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
            [11; 64],
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
            atomic_receipt(parent, [6; 64], &evidence),
            atomic_receipt(changed, [6; 64], &evidence)
        );
    }

    #[test]
    fn state_binding_fields_are_exactly_replayed() {
        let statement = hex(&[11; 64]);
        let binding = hex(&[12; 64]);
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
        ]);
        assert!(
            validate_state_binding_fields(&fields, 0, Some(&statement), Some(&binding),).is_ok()
        );
        fields.insert(
            "state_plane_binding_digest_sha3_512".to_string(),
            hex(&[13; 64]),
        );
        assert_eq!(
            validate_state_binding_fields(&fields, 0, Some(&statement), Some(&binding))
                .unwrap_err(),
            "shard_state_binding:0"
        );
    }
}
