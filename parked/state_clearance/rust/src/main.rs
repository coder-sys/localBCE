//! Narrow process boundary for the reviewed, locally built Lean semantic
//! artifact.  The adapter owns transport bounds, artifact identity, process
//! cleanup, and result grammar.  Lean remains the semantic authority.

use sha2::{Digest, Sha256};
use sha3::Sha3_512;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

const MAX_BUNDLE_BYTES: usize = 1_000_000;
const MAX_STATE_REQUEST_BYTES: usize = MAX_BUNDLE_BYTES + 3_110;
const MAX_KERNEL_STDOUT_BYTES: usize = 64 * 1024;
const MAX_KERNEL_STDERR_BYTES: usize = 8 * 1024;
const KERNEL_TIMEOUT: Duration = Duration::from_millis(2_000);
const KERNEL_CLEANUP_TIMEOUT: Duration = Duration::from_millis(250);
const KERNEL_ENV: &str = "BL_SEMANTIC_KERNEL_EXE";
const KERNEL_BUILD_ID: &str = "BLSK-BLCBND02-EXACT-V2";
const LEAN_TOOLCHAIN: &str = "leanprover/lean4:v4.33.1\n";
const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;

// These are the reviewed source/artifact readback identities.  A zero/empty
// value is deliberately not a wildcard.  Both pins predate the 2026-09-24
// merge into the one `lean/` workspace (source binding already did not match
// the pre-merge `lean/state` bytes); they fail closed until a reviewed guarded
// build of `blind_state_semantic_kernel` re-pins them.
const EXPECTED_ARTIFACT_SHA256: &str =
    "dc5f51ae2c913c434187e7b916c58c394789757e9a384f669cb9dd6913b66cc7";
const EXPECTED_SOURCE_BINDING_SHA256: &str =
    "c309301a4d891db315cfc37e9940688458131c3bd5f370987f136ef26eb09ed1";

// Fixed result identities are repeated here only for transport validation.
// The Lean artifact remains the semantic authority; State independently
// reconstructs every field against the original bundle before durable use.
const EXPECTED_PROFILE_ID: &str =
    "8b07c423294e2d2cecf320e495b56c31b5ecbd75f28cee5b166785e0de872619a0149b1e3dacd195207c7c2f34a9b46a8843ef8dd1c6fbac613aa66111d4163c";
const EXPECTED_SCHEMA_ID: &str =
    "febe60ad387ded7239ad1173fc428b5ced24c3122cc1e76ed823acc8e010b47d7abf2e0b34f7273725387cf5e2d0a38a3dc1682c49765d52543146e4e7119825";
const EXPECTED_PROGRAM_ID: &str =
    "62cd79cd3c28cbb2c554bdec4891de0e21efb8b0fdd5e9bab2c2c2771053239ef21999b134f9f055389220d30e3aedc3006f8cc98712fdcdec092782c0974c4d";
const EXPECTED_MODE_ID: &str =
    "86bbd7f04861486674f17d1b35a216bac87a66f29877675cbad5d55fda7a2cebfbeefc11ecce37d4c07787c2878db7ee97ec2be2672044f254800580f25654df";
const EXPECTED_EVALUATOR_ID: &str =
    "3c22febd7155fb9a30c469250bb46efbeb24d656bdbd03a85dccb2dd441a175147115cdf7ef5b752066be0860c17476ec2f8fbcffd884fa478a52906327fc87b";
const EXPECTED_CONTROL_SET_ID: &str =
    "27b5816c0a3454c2435d09879d6af9415d8d5473147a6a170ee930e755fe89e524940f45ca14b0365e4babd8d784e7bc403f3637ff7bcaa7e40f52896636456e";
const EXPECTED_RULE_ID: &str =
    "abd3fa90adec7bf4fb698ecc64484110b27fafd02c9419e7dfad6ce6cc79fd8d16171275a38de25a7b995bcd9043322c4f2363655cc01c6d0f5279e0f270d663";
const EXPECTED_PHASE0_BINDING: &str =
    "b55b99adcb9085039947a09e718169fe4b882c49f8a1bb7b8fc221ed518555203ed51565280ba0f25228a9f3f735b205a0abe6620c68c2e8963d4e8635aa8808";

const SOURCE_FILES: &[&str] = &[
    "StateKernel/ExactKernel.lean",
    "BlindLedger/Sha3.lean",
    "StateKernel/SemanticExecutable.lean",
    "StateKernel/Theorems.lean",
    "lakefile.toml",
    "lean-toolchain",
    "lake-manifest.json",
];

struct ArtifactIdentity {
    path: PathBuf,
    // The verified image stays open until `run_kernel` returns.  Windows
    // opens this handle without write/delete sharing, so a replacement or
    // rename cannot occur between verification and CreateProcess.
    file: File,
    artifact_sha256: String,
    source_binding_sha256: String,
}

struct KernelOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

enum WorkerDisposition<T> {
    Complete(T),
    Failed,
    Unresolved,
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

fn sha3_512_domain(domain: &str, parts: &[&[u8]]) -> String {
    let mut hasher = Sha3_512::new();
    hasher.update(domain.as_bytes());
    hasher.update([0u8]);
    for part in parts {
        hasher.update(part);
    }
    hex(&hasher.finalize())
}

fn lean_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..\\..\\lean")
}

fn expected_kernel_path(root: &Path) -> PathBuf {
    let filename = if cfg!(windows) {
        "blind_state_semantic_kernel.exe"
    } else {
        "blind_state_semantic_kernel"
    };
    root.join(".lake").join("build").join("bin").join(filename)
}

fn regular_non_symlink(path: &Path) -> Result<(), &'static str> {
    let link_metadata = fs::symlink_metadata(path).map_err(|_| "kernel-artifact-unavailable")?;
    if link_metadata.file_type().is_symlink() || !link_metadata.file_type().is_file() {
        return Err("kernel-artifact-not-regular-file");
    }
    Ok(())
}

fn open_verified_artifact(path: &Path) -> Result<File, &'static str> {
    regular_non_symlink(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_SHARE_READ only: deny write and delete while the verified
        // image is held.  The handle remains live through process launch.
        options.share_mode(0x0000_0001);
    }
    options
        .open(path)
        .map_err(|_| "kernel-artifact-unavailable")
}

fn source_binding(root: &Path) -> Result<String, &'static str> {
    let canonical_root = fs::canonicalize(root).map_err(|_| "kernel-source-unavailable")?;
    let toolchain =
        fs::read(root.join("lean-toolchain")).map_err(|_| "kernel-toolchain-unavailable")?;
    if toolchain != LEAN_TOOLCHAIN.as_bytes() {
        return Err("kernel-toolchain-mismatch");
    }

    let mut hasher = Sha256::new();
    for relative in SOURCE_FILES {
        let path = root.join(relative);
        regular_non_symlink(&path).map_err(|_| "kernel-source-unavailable")?;
        let canonical = fs::canonicalize(&path).map_err(|_| "kernel-source-unavailable")?;
        if !canonical.starts_with(&canonical_root) {
            return Err("kernel-source-outside-root");
        }
        let bytes = fs::read(&canonical).map_err(|_| "kernel-source-unavailable")?;
        hasher.update(relative.as_bytes());
        hasher.update([0u8]);
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    let digest = hex(&hasher.finalize());
    if digest != EXPECTED_SOURCE_BINDING_SHA256 {
        return Err("kernel-source-binding-mismatch");
    }
    Ok(digest)
}

fn kernel_artifact() -> Result<ArtifactIdentity, &'static str> {
    if env::var_os(KERNEL_ENV).is_some() {
        return Err("kernel-artifact-override-forbidden");
    }
    let root = lean_root();
    let canonical_root = fs::canonicalize(&root).map_err(|_| "kernel-source-unavailable")?;
    let source_binding_sha256 = source_binding(&root)?;
    let expected = expected_kernel_path(&canonical_root);
    regular_non_symlink(&expected)?;
    let canonical_artifact =
        fs::canonicalize(&expected).map_err(|_| "kernel-artifact-unavailable")?;
    if canonical_artifact != expected {
        return Err("kernel-artifact-location-mismatch");
    }
    let mut file = open_verified_artifact(&canonical_artifact)?;
    let metadata = file.metadata().map_err(|_| "kernel-artifact-unavailable")?;
    if metadata.len() > MAX_ARTIFACT_BYTES {
        return Err("kernel-artifact-too-large");
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| "kernel-artifact-unavailable")?;
    if bytes.len() as u64 > MAX_ARTIFACT_BYTES {
        return Err("kernel-artifact-too-large");
    }
    let artifact_sha256 = sha256_hex(&bytes);
    if artifact_sha256 != EXPECTED_ARTIFACT_SHA256 {
        return Err("kernel-artifact-binding-mismatch");
    }
    Ok(ArtifactIdentity {
        path: canonical_artifact,
        file,
        artifact_sha256,
        source_binding_sha256,
    })
}

fn read_limited<R: Read>(
    mut reader: R,
    limit: usize,
    overflow: Arc<AtomicBool>,
) -> Result<Vec<u8>, ()> {
    let mut result = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let count = reader.read(&mut buffer).map_err(|_| ())?;
        if count == 0 {
            return Ok(result);
        }
        if result.len().saturating_add(count) > limit {
            overflow.store(true, Ordering::Release);
            return Err(());
        }
        result.extend_from_slice(&buffer[..count]);
    }
}

fn cleanup_child_bounded_until(
    child: &mut Child,
    deadline: Instant,
) -> Result<ExitStatus, &'static str> {
    match child.try_wait() {
        Ok(Some(status)) => return Ok(status),
        Ok(None) => {}
        Err(_) => return Err("kernel-cleanup"),
    }
    if child.kill().is_err() {
        return match child.try_wait() {
            Ok(Some(status)) => Ok(status),
            Ok(None) | Err(_) => Err("kernel-cleanup"),
        };
    }
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(2));
            }
            Ok(None) | Err(_) => return Err("kernel-cleanup"),
        }
    }
}

fn cleanup_child_bounded(child: &mut Child) -> Result<ExitStatus, &'static str> {
    cleanup_child_bounded_until(child, Instant::now() + KERNEL_CLEANUP_TIMEOUT)
}

fn join_with_result<T: Send + 'static>(
    handle: thread::JoinHandle<()>,
    receiver: mpsc::Receiver<T>,
    deadline: Instant,
) -> WorkerDisposition<T> {
    let received = receiver.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    while !handle.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(2));
    }
    if !handle.is_finished() {
        // There is no portable thread cancellation primitive.  Record the
        // unresolved worker and let the process-level reject path own the
        // terminal failure; it must not block past the shared deadline.
        drop(handle);
        return WorkerDisposition::Unresolved;
    }
    if handle.join().is_err() {
        return WorkerDisposition::Failed;
    }
    match received {
        Ok(value) => WorkerDisposition::Complete(value),
        Err(_) => WorkerDisposition::Failed,
    }
}

fn run_kernel(artifact: &ArtifactIdentity, bundle: &[u8]) -> Result<KernelOutput, &'static str> {
    let overflow = Arc::new(AtomicBool::new(false));
    let write_failed = Arc::new(AtomicBool::new(false));
    let read_failed = Arc::new(AtomicBool::new(false));
    // Keep the verified image handle borrowed and alive through spawn.  On
    // Windows its share mode denies replacement/deletion; the child is
    // launched from the same path only while that identity lock is held.
    let _verified_handle = &artifact.file;
    let mut command = Command::new(&artifact.path);
    command
        .current_dir(lean_root())
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|_| "kernel-launch")?;
    let stdin = match child.stdin.take() {
        Some(value) => value,
        None => {
            return match cleanup_child_bounded(&mut child) {
                Ok(_) => Err("kernel-stdin-missing"),
                Err(error) => Err(error),
            };
        }
    };
    let stdout = match child.stdout.take() {
        Some(value) => value,
        None => {
            drop(stdin);
            return match cleanup_child_bounded(&mut child) {
                Ok(_) => Err("kernel-stdout-missing"),
                Err(error) => Err(error),
            };
        }
    };
    let stderr = match child.stderr.take() {
        Some(value) => value,
        None => {
            drop(stdin);
            drop(stdout);
            return match cleanup_child_bounded(&mut child) {
                Ok(_) => Err("kernel-stderr-missing"),
                Err(error) => Err(error),
            };
        }
    };

    let input = bundle.to_vec();
    let writer_failed = Arc::clone(&write_failed);
    let (writer_done_sender, writer_done_receiver) = mpsc::sync_channel(1);
    let writer = match thread::Builder::new()
        .name("semantic-kernel-writer".to_string())
        .spawn(move || {
            let mut stdin = stdin;
            if stdin.write_all(&input).is_err() {
                writer_failed.store(true, Ordering::Release);
            }
            drop(stdin);
            let _ = writer_done_sender.send(());
        }) {
        Ok(handle) => handle,
        Err(_) => {
            return match cleanup_child_bounded(&mut child) {
                Ok(_) => Err("kernel-thread-start"),
                Err(error) => Err(error),
            };
        }
    };
    let stdout_overflow = Arc::clone(&overflow);
    let stdout_failed = Arc::clone(&read_failed);
    let (stdout_done_sender, stdout_done_receiver) = mpsc::sync_channel(1);
    let stdout_reader = match thread::Builder::new()
        .name("semantic-kernel-stdout".to_string())
        .spawn(move || {
            let value = match read_limited(stdout, MAX_KERNEL_STDOUT_BYTES, stdout_overflow) {
                Ok(value) => Ok(value),
                Err(()) => {
                    stdout_failed.store(true, Ordering::Release);
                    Err(())
                }
            };
            let _ = stdout_done_sender.send(value);
        }) {
        Ok(handle) => handle,
        Err(_) => {
            let cleanup_deadline = Instant::now() + KERNEL_CLEANUP_TIMEOUT;
            let cleanup = cleanup_child_bounded_until(&mut child, cleanup_deadline);
            let writer_done = join_with_result(writer, writer_done_receiver, cleanup_deadline);
            if cleanup.is_err() || !matches!(&writer_done, WorkerDisposition::Complete(_)) {
                return Err("kernel-cleanup");
            }
            return Err("kernel-thread-start");
        }
    };
    let stderr_overflow = Arc::clone(&overflow);
    let stderr_failed = Arc::clone(&read_failed);
    let (stderr_done_sender, stderr_done_receiver) = mpsc::sync_channel(1);
    let stderr_reader = match thread::Builder::new()
        .name("semantic-kernel-stderr".to_string())
        .spawn(move || {
            let value = match read_limited(stderr, MAX_KERNEL_STDERR_BYTES, stderr_overflow) {
                Ok(value) => Ok(value),
                Err(()) => {
                    stderr_failed.store(true, Ordering::Release);
                    Err(())
                }
            };
            let _ = stderr_done_sender.send(value);
        }) {
        Ok(handle) => handle,
        Err(_) => {
            let cleanup_deadline = Instant::now() + KERNEL_CLEANUP_TIMEOUT;
            let cleanup = cleanup_child_bounded_until(&mut child, cleanup_deadline);
            let writer_done = join_with_result(writer, writer_done_receiver, cleanup_deadline);
            let stdout_done =
                join_with_result(stdout_reader, stdout_done_receiver, cleanup_deadline);
            if cleanup.is_err()
                || !matches!(&writer_done, WorkerDisposition::Complete(_))
                || !matches!(&stdout_done, WorkerDisposition::Complete(_))
            {
                return Err("kernel-cleanup");
            }
            return Err("kernel-thread-start");
        }
    };

    let deadline = Instant::now() + KERNEL_TIMEOUT;
    let mut forced_error: Option<&'static str> = None;
    loop {
        if overflow.load(Ordering::Acquire) {
            forced_error = Some("kernel-output-too-large");
            break;
        }
        if read_failed.load(Ordering::Acquire) {
            forced_error = Some("kernel-output-read");
            break;
        }
        if write_failed.load(Ordering::Acquire) {
            forced_error = Some("kernel-stdin-write");
            break;
        }
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(_) => {
                forced_error = Some("kernel-wait");
                break;
            }
        }
        if Instant::now() >= deadline {
            forced_error = Some("kernel-timeout");
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let cleanup_deadline = Instant::now() + KERNEL_CLEANUP_TIMEOUT;
    // Every started worker is dispositioned against this same deadline
    // before any terminal error is returned.  In particular, a child cleanup
    // failure cannot bypass the writer/stdout/stderr dispositions.
    let cleanup = cleanup_child_bounded_until(&mut child, cleanup_deadline);
    let writer_result = join_with_result(writer, writer_done_receiver, cleanup_deadline);
    let stdout_result = join_with_result(stdout_reader, stdout_done_receiver, cleanup_deadline);
    let stderr_result = join_with_result(stderr_reader, stderr_done_receiver, cleanup_deadline);
    let cleanup_failed = cleanup.is_err();
    let workers_failed = !matches!(&writer_result, WorkerDisposition::Complete(_))
        || !matches!(&stdout_result, WorkerDisposition::Complete(_))
        || !matches!(&stderr_result, WorkerDisposition::Complete(_));
    if cleanup_failed || workers_failed {
        return Err("kernel-cleanup");
    }
    let status = match cleanup {
        Ok(status) => status,
        Err(_) => return Err("kernel-cleanup"),
    };
    let writer_result = match writer_result {
        WorkerDisposition::Complete(value) => value,
        WorkerDisposition::Failed | WorkerDisposition::Unresolved => return Err("kernel-cleanup"),
    };
    let stdout_result = match stdout_result {
        WorkerDisposition::Complete(value) => value,
        WorkerDisposition::Failed | WorkerDisposition::Unresolved => return Err("kernel-cleanup"),
    };
    let stderr_result = match stderr_result {
        WorkerDisposition::Complete(value) => value,
        WorkerDisposition::Failed | WorkerDisposition::Unresolved => return Err("kernel-cleanup"),
    };
    let stdout = stdout_result.map_err(|_| "kernel-output-read")?;
    let stderr = stderr_result.map_err(|_| "kernel-output-read")?;
    let _ = writer_result;
    if let Some(error) = forced_error {
        return Err(error);
    }
    if write_failed.load(Ordering::Acquire) {
        return Err("kernel-stdin-write");
    }
    if read_failed.load(Ordering::Acquire) {
        return Err("kernel-output-read");
    }
    Ok(KernelOutput {
        status,
        stdout,
        stderr,
    })
}

fn field<'a>(fields: &'a [&'a str], index: usize, key: &str) -> Result<&'a str, &'static str> {
    let value = fields.get(index).ok_or("kernel-output-grammar")?;
    let (actual_key, actual_value) = value.split_once('=').ok_or("kernel-output-grammar")?;
    if actual_key != key {
        return Err("kernel-output-grammar");
    }
    Ok(actual_value)
}

fn read_stdin_bounded() -> Result<Vec<u8>, &'static str> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let mut input = Vec::new();
        let result = io::stdin()
            .lock()
            .take((MAX_STATE_REQUEST_BYTES + 1) as u64)
            .read_to_end(&mut input)
            .map(|_| input)
            .map_err(|_| "stdin-read");
        let _ = sender.send(result);
    });
    let result = match receiver.recv_timeout(KERNEL_TIMEOUT) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // A blocked OS stdin read cannot be portably cancelled from a
            // sibling Rust thread.  This is a terminal adapter boundary:
            // reject-and-exit so the process boundary reclaims the started
            // reader instead of returning to a long-lived caller with a live
            // thread.
            reject("stdin-timeout");
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => return Err("stdin-read"),
    };
    if reader.join().is_err() {
        return Err("stdin-read");
    }
    result
}

fn valid_hex_64(value: &str) -> bool {
    value.len() == 128 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_hex_32(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_u64_decimal(value: &str) -> bool {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return false;
    }
    value.bytes().all(|byte| byte.is_ascii_digit()) && value.parse::<u64>().is_ok()
}

fn validate_kernel_line(
    line: &str,
    bundle_len: usize,
    bundle_id: &str,
) -> Result<(), &'static str> {
    if line.is_empty() || line.contains(['\r', '\n']) {
        return Err("kernel-output-grammar");
    }
    let fields: Vec<&str> = line.split(';').collect();
    if fields.len() != 48 {
        return Err("kernel-output-field-count");
    }
    if fields[0] != "BL-SEMANTIC-KERNEL/2"
        || fields[1] != "schema=BLCBND02/v2"
        || fields[2] != "result=PASS"
    {
        return Err("kernel-output-grammar");
    }
    if field(&fields, 3, "kernel_build_id")? != KERNEL_BUILD_ID {
        return Err("kernel-output-build-id");
    }
    if field(&fields, 4, "bundle_id")? != bundle_id {
        return Err("kernel-output-bundle-id");
    }
    let policy = field(&fields, 5, "policy")?;
    let directive = field(&fields, 6, "directive")?;
    let reason = field(&fields, 7, "reason")?;
    if !matches!(policy, "PASS" | "MISSING" | "AMBIGUOUS" | "FAIL")
        || !matches!(
            reason,
            "VALID_CONTINUITY"
                | "AUTHORITATIVE_ABSENCE"
                | "EXPIRED_OR_TERMINATED"
                | "INCOMPLETE_OR_AMBIGUOUS"
                | "STALE_RULE_INTERVAL"
                | "CONTROL_INTERVAL"
        )
    {
        return Err("kernel-output-enum");
    }
    let expected_policy = match directive {
        "CLEAR" => "PASS",
        "HOLD" => "MISSING",
        "HUMAN_REVIEW" => "AMBIGUOUS",
        "BLOCK" | "EXCEPTION_APPROVED" => "FAIL",
        _ => return Err("kernel-output-enum"),
    };
    if policy != expected_policy {
        return Err("kernel-output-policy-directive");
    }
    let identity_keys = [
        "reason_id",
        "attempt_id",
        "profile_id",
        "schema_id",
        "program_id",
        "mode_id",
        "evaluator_id",
        "control_set_id",
        "rule_id",
        "phase0_receipt_binding",
        "request_id",
        "decision_id",
        "source_root",
        "completeness_id",
        "exception_id",
        "before_state_id",
        "after_state_id",
        "receipt_id",
        "join_id",
        "chronology_id",
        "replay_id",
        "decision_path_id",
    ];
    for (index, key) in (8..30).zip(identity_keys) {
        let value = field(&fields, index, key)?;
        if !valid_hex_64(value) || value != value.to_ascii_lowercase() {
            return Err("kernel-output-identity");
        }
    }
    let fixed_identities = [
        (10, "profile_id", EXPECTED_PROFILE_ID),
        (11, "schema_id", EXPECTED_SCHEMA_ID),
        (12, "program_id", EXPECTED_PROGRAM_ID),
        (13, "mode_id", EXPECTED_MODE_ID),
        (14, "evaluator_id", EXPECTED_EVALUATOR_ID),
        (15, "control_set_id", EXPECTED_CONTROL_SET_ID),
        (16, "rule_id", EXPECTED_RULE_ID),
        (17, "phase0_receipt_binding", EXPECTED_PHASE0_BINDING),
    ];
    for (index, key, expected) in fixed_identities {
        if field(&fields, index, key)? != expected {
            return Err("kernel-output-fixed-identity");
        }
    }
    let valid_reason = match directive {
        "CLEAR" => reason == "VALID_CONTINUITY",
        "HOLD" => reason == "AUTHORITATIVE_ABSENCE",
        "HUMAN_REVIEW" => matches!(
            reason,
            "INCOMPLETE_OR_AMBIGUOUS" | "STALE_RULE_INTERVAL" | "CONTROL_INTERVAL"
        ),
        "BLOCK" | "EXCEPTION_APPROVED" => reason == "EXPIRED_OR_TERMINATED",
        _ => false,
    };
    if !valid_reason {
        return Err("kernel-output-result-binding");
    }
    for (index, key) in [
        (30, "event_time"),
        (31, "observation_time"),
        (32, "rule_effective_time"),
        (33, "decision_time"),
        (34, "continuity_epoch"),
        (35, "sequence_before"),
        (36, "sequence_after"),
    ] {
        if !valid_u64_decimal(field(&fields, index, key)?) {
            return Err("kernel-output-time");
        }
    }
    if field(&fields, 34, "continuity_epoch")? != "7"
        || field(&fields, 35, "sequence_before")? != "0"
        || field(&fields, 36, "sequence_after")? != "1"
    {
        return Err("kernel-output-state-sequence");
    }
    for (index, key) in [
        (37, "before_audit_head"),
        (38, "after_audit_head"),
        (39, "before_continuity_root"),
        (40, "after_continuity_root"),
        (41, "audit_head_after"),
        (42, "continuity_root_after"),
    ] {
        let value = field(&fields, index, key)?;
        if !valid_hex_64(value) || value != value.to_ascii_lowercase() {
            return Err("kernel-output-state-identity");
        }
    }
    let reported_len = field(&fields, 43, "bundle_bytes")?
        .parse::<usize>()
        .map_err(|_| "kernel-output-bundle-size")?;
    if reported_len != bundle_len {
        return Err("kernel-output-bundle-size");
    }
    if field(&fields, 44, "proof_suite_id")? != "NONE"
        || field(&fields, 45, "proof_session_accepted")? != "false"
        || field(&fields, 46, "economic_mutation")? != "false"
        || field(&fields, 47, "replay_stateful")? != "false"
    {
        return Err("kernel-output-authority-flags");
    }
    Ok(())
}

struct StateRequestView<'a> {
    bundle: &'a [u8],
    bundle_len: usize,
    command_id: String,
    expected_revision: u64,
    current_sequence: u64,
    epoch: u64,
    ids_start: usize,
    continuity_roots_start: usize,
    prior_start: usize,
    prior_len: usize,
}

fn be_u64(value: &[u8]) -> Result<u64, &'static str> {
    let bytes: [u8; 8] = value.try_into().map_err(|_| "state-request-truncated")?;
    Ok(u64::from_be_bytes(bytes))
}

fn state_request_view(input: &[u8]) -> Result<StateRequestView<'_>, &'static str> {
    if input.len() < 16 || input.len() > MAX_STATE_REQUEST_BYTES {
        return Err("state-request-size");
    }
    if &input[..8] != b"BLSDRQ01" || input[8..10] != [0, 1] || input[10..12] != [0, 0] {
        return Err("state-request-header");
    }
    let bundle_len = u32::from_be_bytes(
        input[12..16]
            .try_into()
            .map_err(|_| "state-request-truncated")?,
    ) as usize;
    if bundle_len == 0 || bundle_len > MAX_BUNDLE_BYTES {
        return Err("state-request-bundle-size");
    }
    let bundle_start = 16usize;
    let mut offset = bundle_start
        .checked_add(bundle_len)
        .ok_or("state-request-size")?;
    let command_end = offset.checked_add(64).ok_or("state-request-size")?;
    let command = input.get(offset..command_end).ok_or("state-request-truncated")?;
    offset = command_end;
    let revision_end = offset.checked_add(8).ok_or("state-request-size")?;
    let expected_revision = be_u64(
        input
            .get(offset..revision_end)
            .ok_or("state-request-truncated")?,
    )?;
    offset = revision_end;
    let ids_start = offset;
    offset = offset.checked_add(9 * 64).ok_or("state-request-size")?;
    let numbers_start = offset;
    let numbers_a_end = offset.checked_add(3 * 8).ok_or("state-request-size")?;
    let numbers_a = input
        .get(offset..numbers_a_end)
        .ok_or("state-request-truncated")?;
    let epoch = be_u64(&numbers_a[..8])?;
    let current_sequence = be_u64(&numbers_a[8..16])?;
    let anti_epoch = be_u64(&numbers_a[16..24])?;
    if epoch != 7 || current_sequence != anti_epoch {
        return Err("state-request-current-epoch");
    }
    offset = numbers_a_end;
    let roots_a_end = offset.checked_add(4 * 64).ok_or("state-request-size")?;
    input
        .get(offset..roots_a_end)
        .ok_or("state-request-truncated")?;
    offset = roots_a_end;
    let numbers_b_end = offset.checked_add(3 * 8).ok_or("state-request-size")?;
    let numbers_b = input
        .get(offset..numbers_b_end)
        .ok_or("state-request-truncated")?;
    let direct_sequence = be_u64(&numbers_b[..8])?;
    let direct_count = be_u64(&numbers_b[8..16])?;
    let _direct_settled_batch_count = be_u64(&numbers_b[16..24])?;
    if current_sequence != direct_sequence || current_sequence != direct_count {
        return Err("state-request-current-revision");
    }
    offset = numbers_b_end;
    let roots_b_end = offset.checked_add(6 * 64).ok_or("state-request-size")?;
    input
        .get(offset..roots_b_end)
        .ok_or("state-request-truncated")?;
    offset = roots_b_end;
    let numbers_c_end = offset.checked_add(2 * 8).ok_or("state-request-size")?;
    let numbers_c = input
        .get(offset..numbers_c_end)
        .ok_or("state-request-truncated")?;
    let continuity_sequence = be_u64(&numbers_c[..8])?;
    let continuity_row_count = be_u64(&numbers_c[8..16])?;
    if current_sequence != continuity_sequence || current_sequence != continuity_row_count {
        return Err("state-request-continuity-revision");
    }
    offset = numbers_c_end;
    let continuity_roots_start = offset;
    let roots_c_end = offset.checked_add(3 * 64).ok_or("state-request-size")?;
    input
        .get(offset..roots_c_end)
        .ok_or("state-request-truncated")?;
    offset = roots_c_end;
    let prior_len_end = offset.checked_add(4).ok_or("state-request-size")?;
    let prior_len = u32::from_be_bytes(
        input
            .get(offset..prior_len_end)
            .ok_or("state-request-truncated")?
            .try_into()
            .map_err(|_| "state-request-truncated")?,
    ) as usize;
    if prior_len != 0 && prior_len != 1 + 1 + 64 + 16 * 64 + 9 * 8 + 6 * 64 {
        return Err("state-request-prior-size");
    }
    let exact_end = prior_len_end
        .checked_add(prior_len)
        .ok_or("state-request-size")?;
    if exact_end != input.len() {
        return Err("state-request-trailing-bytes");
    }
    let command_id = hex(command);
    if command_id.chars().all(|character| character == '0') {
        return Err("state-request-command-id");
    }
    Ok(StateRequestView {
        bundle: &input[bundle_start..bundle_start + bundle_len],
        bundle_len,
        command_id,
        expected_revision,
        current_sequence,
        epoch,
        ids_start,
        continuity_roots_start,
        prior_start: prior_len_end,
        prior_len,
    })
}

fn validate_state_kernel_line(line: &str, input: &[u8]) -> Result<(), &'static str> {
    if line.is_empty() || line.contains(['\r', '\n']) {
        return Err("state-kernel-output-grammar");
    }
    let view = state_request_view(input)?;
    let fields: Vec<&str> = line.split(';').collect();
    if fields.len() != 59 {
        return Err("state-kernel-output-field-count");
    }
    if fields[0] != "BL-STATE-SEMANTIC-KERNEL/1"
        || fields[1] != "schema=BLSDCLR01/v1"
        || fields[2] != "result=PASS"
    {
        return Err("state-kernel-output-header");
    }
    if field(&fields, 3, "kernel_build_id")? != "BLSK-BLSDCLR01-STATE-V1" {
        return Err("state-kernel-output-build-id");
    }
    let input_sha = sha3_512_domain("BL/DIRECT-STATE-OWNED/STATE-INPUT/v1", &[input]);
    if field(&fields, 4, "input_sha3_512")? != input_sha
        || field(&fields, 5, "command_id")? != view.command_id
        || field(&fields, 6, "expected_revision")? != view.expected_revision.to_string()
        || field(&fields, 7, "current_sequence")? != view.current_sequence.to_string()
    {
        return Err("state-kernel-output-request-binding");
    }
    let bundle_id = sha3_512_domain("BL/NATIVE-V3/CONTINUITY/BUNDLE/v2", &[view.bundle]);
    if field(&fields, 8, "bundle_id")? != bundle_id
        || field(&fields, 9, "bundle_bytes")? != view.bundle_len.to_string()
    {
        return Err("state-kernel-output-bundle-binding");
    }
    for (index, key) in [
        (4, "input_sha3_512"),
        (5, "command_id"),
        (8, "bundle_id"),
        (13, "reason_id"),
        (14, "request_id"),
        (15, "attempt_id"),
        (16, "decision_id"),
        (17, "join_id"),
        (18, "profile_id"),
        (19, "schema_id"),
        (20, "program_id"),
        (21, "mode_id"),
        (22, "evaluator_id"),
        (23, "control_set_id"),
        (24, "rule_id"),
        (25, "phase0_receipt_binding"),
        (26, "source_root"),
        (27, "completeness_id"),
        (28, "exception_id"),
        (29, "before_state_id"),
        (30, "after_state_id"),
        (31, "receipt_id"),
        (32, "chronology_id"),
        (33, "replay_id"),
        (34, "decision_path_id"),
        (35, "before_audit_head"),
        (36, "before_continuity_root"),
        (37, "after_audit_head"),
        (38, "after_continuity_root"),
        (39, "audit_head_after"),
        (40, "continuity_root_after"),
        (41, "evidence_request_id"),
        (42, "evidence_decision_id"),
        (43, "evidence_join_id"),
        (44, "evidence_receipt_id"),
        (45, "evidence_decision_path_id"),
        (58, "prior_operation_digest"),
    ] {
        let value = field(&fields, index, key)?;
        if !valid_hex_64(value) || value != value.to_ascii_lowercase() {
            return Err("state-kernel-output-identity");
        }
        if index != 58 && value.chars().all(|character| character == '0') {
            return Err("state-kernel-output-zero-identity");
        }
    }
    let fixed_identities = [
        (18, "profile_id", 0usize),
        (19, "schema_id", 1usize),
        (20, "program_id", 2usize),
        (21, "mode_id", 3usize),
        (22, "evaluator_id", 4usize),
        (23, "control_set_id", 5usize),
        (24, "rule_id", 6usize),
        (25, "phase0_receipt_binding", 7usize),
    ];
    for (output_index, key, request_index) in fixed_identities {
        let start = view.ids_start + request_index * 64;
        if field(&fields, output_index, key)? != hex(&input[start..start + 64]) {
            return Err("state-kernel-output-fixed-identity");
        }
    }
    let policy = field(&fields, 10, "policy")?;
    let directive = field(&fields, 11, "directive")?;
    let reason = field(&fields, 12, "reason")?;
    let expected_policy = match directive {
        "CLEAR" => "PASS",
        "HOLD" => "MISSING",
        "HUMAN_REVIEW" => "AMBIGUOUS",
        "BLOCK" | "EXCEPTION_APPROVED" => "FAIL",
        _ => return Err("state-kernel-output-directive"),
    };
    let valid_reason = match directive {
        "CLEAR" => reason == "VALID_CONTINUITY",
        "HOLD" => reason == "AUTHORITATIVE_ABSENCE",
        "HUMAN_REVIEW" => matches!(
            reason,
            "INCOMPLETE_OR_AMBIGUOUS" | "STALE_RULE_INTERVAL" | "CONTROL_INTERVAL"
        ),
        "BLOCK" | "EXCEPTION_APPROVED" => reason == "EXPIRED_OR_TERMINATED",
        _ => false,
    };
    if policy != expected_policy || !valid_reason {
        return Err("state-kernel-output-policy-reason");
    }
    let times = [
        field(&fields, 46, "event_time")?,
        field(&fields, 47, "observation_time")?,
        field(&fields, 48, "rule_effective_time")?,
        field(&fields, 49, "decision_time")?,
        field(&fields, 50, "continuity_epoch")?,
        field(&fields, 51, "sequence_before")?,
        field(&fields, 52, "sequence_after")?,
    ];
    for value in times {
        if !valid_u64_decimal(value) {
            return Err("state-kernel-output-number");
        }
    }
    let event = field(&fields, 46, "event_time")?.parse::<u64>().map_err(|_| "state-kernel-output-number")?;
    let observation = field(&fields, 47, "observation_time")?.parse::<u64>().map_err(|_| "state-kernel-output-number")?;
    let rule_effective = field(&fields, 48, "rule_effective_time")?.parse::<u64>().map_err(|_| "state-kernel-output-number")?;
    let decision = field(&fields, 49, "decision_time")?.parse::<u64>().map_err(|_| "state-kernel-output-number")?;
    let continuity_epoch = field(&fields, 50, "continuity_epoch")?.parse::<u64>().map_err(|_| "state-kernel-output-number")?;
    let sequence_before = field(&fields, 51, "sequence_before")?.parse::<u64>().map_err(|_| "state-kernel-output-number")?;
    let sequence_after = field(&fields, 52, "sequence_after")?.parse::<u64>().map_err(|_| "state-kernel-output-number")?;
    if !(rule_effective < event && event < observation && observation < decision)
        || continuity_epoch != view.epoch
        || sequence_after != sequence_before.checked_add(1).ok_or("state-kernel-output-overflow")?
    {
        return Err("state-kernel-output-chronology");
    }
    let disposition = field(&fields, 57, "disposition")?;
    let prior_digest = field(&fields, 58, "prior_operation_digest")?;
    let economic_mutation = field(&fields, 55, "economic_mutation")?;
    if field(&fields, 53, "proof_suite_id")? != "NONE"
        || field(&fields, 54, "proof_session_accepted")? != "false"
        || field(&fields, 56, "replay_stateful")? != "true"
        || economic_mutation != if matches!(directive, "CLEAR" | "EXCEPTION_APPROVED") { "true" } else { "false" }
    {
        return Err("state-kernel-output-authority-flags");
    }
    match disposition {
        "ACCEPT" => {
            if view.prior_len != 0
                || view.expected_revision != view.current_sequence
                || sequence_before != view.current_sequence
                || prior_digest.bytes().any(|byte| byte != b'0')
            {
                return Err("state-kernel-output-accept-binding");
            }
            if field(&fields, 15, "attempt_id")? != view.command_id {
                return Err("state-kernel-output-command-binding");
            }
            let current_state_id = hex(&input[view.continuity_roots_start..view.continuity_roots_start + 64]);
            let current_audit = hex(&input[view.continuity_roots_start + 64..view.continuity_roots_start + 128]);
            let current_root = hex(&input[view.continuity_roots_start + 128..view.continuity_roots_start + 192]);
            if field(&fields, 29, "before_state_id")? != current_state_id
                || field(&fields, 35, "before_audit_head")? != current_audit
                || field(&fields, 36, "before_continuity_root")? != current_root
            {
                return Err("state-kernel-output-before-state");
            }
        }
        "REPLAY" => {
            if view.prior_len == 0
                || view.expected_revision != sequence_before
                || view.current_sequence < sequence_after
            {
                return Err("state-kernel-output-replay-binding");
            }
            validate_state_prior_result(&fields, input, &view)?;
        }
        _ => return Err("state-kernel-output-disposition"),
    }
    Ok(())
}

fn validate_state_prior_result(
    fields: &[&str],
    input: &[u8],
    view: &StateRequestView<'_>,
) -> Result<(), &'static str> {
    let prior = input
        .get(view.prior_start..view.prior_start + view.prior_len)
        .ok_or("state-request-prior-truncated")?;
    let version = prior[0];
    let advanced = prior[1];
    if version > 1 || advanced > 1 {
        return Err("state-request-prior-flags");
    }
    let digest_bytes = &prior[2..66];
    if field(fields, 58, "prior_operation_digest")? != hex(digest_bytes) {
        return Err("state-kernel-output-prior-digest");
    }
    let operation_start = 66usize;
    let numbers_start = operation_start + 16 * 64;
    let state_ids_start = numbers_start + 9 * 8;
    let mut parts: Vec<&[u8]> = Vec::with_capacity(32);
    for index in 0..16 {
        let start = operation_start + index * 64;
        parts.push(&prior[start..start + 64]);
    }
    for index in 0..9 {
        let start = numbers_start + index * 8;
        parts.push(&prior[start..start + 8]);
    }
    for index in 0..6 {
        let start = state_ids_start + index * 64;
        parts.push(&prior[start..start + 64]);
    }
    let expected_digest = if version == 0 {
        sha3_512_domain("BL/DIRECT-STATE-OWNED/CLEARANCE-OPERATION/v1", &parts)
    } else {
        parts.push(&prior[1..2]);
        sha3_512_domain("BL/DIRECT-STATE-OWNED/CLEARANCE-OPERATION/STATE-V1", &parts)
    };
    if hex(digest_bytes) != expected_digest {
        return Err("state-kernel-output-prior-operation-digest");
    }
    let operation_ids = [
        (8, "bundle_id", 0usize),
        (31, "receipt_id", 1usize),
        (14, "request_id", 2usize),
        (15, "attempt_id", 3usize),
        (16, "decision_id", 4usize),
        (17, "join_id", 5usize),
        (26, "source_root", 6usize),
        (18, "profile_id", 7usize),
        (19, "schema_id", 8usize),
        (20, "program_id", 9usize),
        (21, "mode_id", 10usize),
        (22, "evaluator_id", 11usize),
        (23, "control_set_id", 12usize),
        (24, "rule_id", 13usize),
        (25, "phase0_receipt_binding", 14usize),
        (28, "exception_id", 15usize),
        (29, "before_state_id", 16usize),
        (30, "after_state_id", 17usize),
        (35, "before_audit_head", 18usize),
        (37, "after_audit_head", 19usize),
        (36, "before_continuity_root", 20usize),
        (38, "after_continuity_root", 21usize),
        (39, "audit_head_after", 19usize),
        (40, "continuity_root_after", 21usize),
    ];
    for (index, key, id_index) in operation_ids {
        let start = operation_start + id_index * 64;
        if field(fields, index, key)? != hex(&prior[start..start + 64]) {
            return Err("state-kernel-output-prior-identity");
        }
    }
    let operation_numbers = [
        (10, "policy", 0usize),
        (11, "directive", 1usize),
        (46, "event_time", 2usize),
        (47, "observation_time", 3usize),
        (48, "rule_effective_time", 4usize),
        (49, "decision_time", 5usize),
        (50, "continuity_epoch", 6usize),
        (51, "sequence_before", 7usize),
        (52, "sequence_after", 8usize),
    ];
    for (index, key, number_index) in operation_numbers {
        let start = numbers_start + number_index * 8;
        let expected = u64::from_be_bytes(
            prior[start..start + 8]
                .try_into()
                .map_err(|_| "state-request-prior-number")?,
        );
        if field(fields, index, key)? != expected.to_string() {
            return Err("state-kernel-output-prior-number");
        }
    }
    if field(fields, 15, "attempt_id")? != view.command_id
        || field(fields, 55, "economic_mutation")? != if advanced == 1 { "true" } else { "false" }
        || field(fields, 57, "disposition")? != "REPLAY"
    {
        return Err("state-kernel-output-prior-binding");
    }
    Ok(())
}

fn reject(error: &'static str) -> ! {
    eprintln!("BL-SEMANTIC-ADAPTER/2;result=REJECT;error={error}");
    std::process::exit(1)
}

fn main() {
    let input = match read_stdin_bounded() {
        Ok(value) => value,
        Err(error) => reject(error),
    };
    let state_request = input.starts_with(b"BLSDRQ01");
    if (!state_request && input.len() > MAX_BUNDLE_BYTES)
        || (state_request && input.len() > MAX_STATE_REQUEST_BYTES)
    {
        reject("bundle-too-large");
    }
    let artifact = match kernel_artifact() {
        Ok(value) => value,
        Err(error) => reject(error),
    };
    let output = match run_kernel(&artifact, &input) {
        Ok(value) => value,
        Err(error) => reject(error),
    };
    if !output.status.success() {
        reject("kernel-exit");
    }
    if !output.stderr.is_empty() {
        reject("kernel-stderr-on-success");
    }
    if output.stdout.last() != Some(&b'\n') {
        reject("kernel-output-newline");
    }
    let line_bytes = &output.stdout[..output.stdout.len() - 1];
    let line = match std::str::from_utf8(line_bytes) {
        Ok(value) => value,
        Err(_) => reject("kernel-output-not-utf8"),
    };
    if state_request {
        if validate_state_kernel_line(line, &input).is_err() {
            reject("state-kernel-output-invalid");
        }
        println!(
            "BL-STATE-SEMANTIC-ADAPTER/1;schema=BLSDCLR01/v1;result=PASS;artifact_sha256={};source_binding_sha256={};{}",
            artifact.artifact_sha256,
            artifact.source_binding_sha256,
            line.split(';').skip(3).collect::<Vec<_>>().join(";")
        );
    } else {
        let bundle_id = sha3_512_domain("BL/NATIVE-V3/CONTINUITY/BUNDLE/v2", &[&input]);
        if validate_kernel_line(line, input.len(), &bundle_id).is_err() {
            reject("kernel-output-invalid");
        }
        println!(
            "BL-SEMANTIC-ADAPTER/2;result=PASS;artifact_sha256={};source_binding_sha256={};schema=BLCBND02/v2;{}",
            artifact.artifact_sha256,
            artifact.source_binding_sha256,
            line.split(';').skip(3).collect::<Vec<_>>().join(";")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_request_fixture() -> Vec<u8> {
        let mut input = Vec::new();
        input.extend_from_slice(b"BLSDRQ01");
        input.extend_from_slice(&1u16.to_be_bytes());
        input.extend_from_slice(&[0, 0]);
        input.extend_from_slice(&4u32.to_be_bytes());
        input.extend_from_slice(b"test");
        input.extend_from_slice(&[0xA5; 64]);
        input.extend_from_slice(&0u64.to_be_bytes());
        input.extend_from_slice(&[0; 9 * 64]);
        input.extend_from_slice(&7u64.to_be_bytes());
        input.extend_from_slice(&0u64.to_be_bytes());
        input.extend_from_slice(&0u64.to_be_bytes());
        input.extend_from_slice(&[0; 4 * 64]);
        input.extend_from_slice(&0u64.to_be_bytes());
        input.extend_from_slice(&0u64.to_be_bytes());
        input.extend_from_slice(&0u64.to_be_bytes());
        input.extend_from_slice(&[0; 6 * 64]);
        input.extend_from_slice(&0u64.to_be_bytes());
        input.extend_from_slice(&0u64.to_be_bytes());
        input.extend_from_slice(&[0; 3 * 64]);
        input.extend_from_slice(&0u32.to_be_bytes());
        input
    }

    #[test]
    fn state_request_frame_binds_version_widths_and_sha3_domain() {
        let input = state_request_fixture();
        let view = state_request_view(&input).expect("well-formed request frame");
        assert_eq!(view.bundle, b"test");
        assert_eq!(view.command_id, "a5".repeat(64));
        assert_eq!(view.expected_revision, 0);
        assert_eq!(view.current_sequence, 0);
        assert_eq!(view.epoch, 7);
        assert_eq!(input.len(), 4 + 1_564);

        let mut expected = Sha3_512::new();
        expected.update(b"BL/DIRECT-STATE-OWNED/STATE-INPUT/v1");
        expected.update([0u8]);
        expected.update(&input);
        assert_eq!(
            sha3_512_domain("BL/DIRECT-STATE-OWNED/STATE-INPUT/v1", &[&input]),
            hex(&expected.finalize())
        );
    }

    #[test]
    fn state_request_frame_rejects_bad_tag_truncation_trailing_and_prior_width() {
        let input = state_request_fixture();

        let mut wrong_tag = input.clone();
        wrong_tag[0] ^= 1;
        assert_eq!(state_request_view(&wrong_tag).err(), Some("state-request-header"));

        let mut wrong_version = input.clone();
        wrong_version[9] = 2;
        assert_eq!(state_request_view(&wrong_version).err(), Some("state-request-header"));

        let mut truncated = input.clone();
        truncated.pop();
        assert_eq!(state_request_view(&truncated).err(), Some("state-request-truncated"));

        let mut trailing = input.clone();
        trailing.push(0);
        assert_eq!(state_request_view(&trailing).err(), Some("state-request-trailing-bytes"));

        let mut wrong_prior_width = input;
        let prior_length_offset = wrong_prior_width.len() - 4;
        wrong_prior_width[prior_length_offset + 3] = 1;
        assert_eq!(state_request_view(&wrong_prior_width).err(), Some("state-request-prior-size"));
    }

    fn valid_kernel_line(bundle_id: &str) -> String {
        let id = "a".repeat(128);
        format!(
            "BL-SEMANTIC-KERNEL/2;schema=BLCBND02/v2;result=PASS;kernel_build_id={build};bundle_id={bundle};policy=PASS;directive=CLEAR;reason=VALID_CONTINUITY;reason_id={id};attempt_id={id};profile_id={profile};schema_id={schema};program_id={program};mode_id={mode};evaluator_id={evaluator};control_set_id={control};rule_id={rule};phase0_receipt_binding={phase0};request_id={id};decision_id={id};source_root={id};completeness_id={id};exception_id={id};before_state_id={id};after_state_id={id};receipt_id={id};join_id={id};chronology_id={id};replay_id={id};decision_path_id={id};event_time=7000;observation_time=7001;rule_effective_time=6999;decision_time=7002;continuity_epoch=7;sequence_before=0;sequence_after=1;before_audit_head={id};after_audit_head={id};before_continuity_root={id};after_continuity_root={id};audit_head_after={id};continuity_root_after={id};bundle_bytes=4;proof_suite_id=NONE;proof_session_accepted=false;economic_mutation=false;replay_stateful=false",
            build = KERNEL_BUILD_ID,
            bundle = bundle_id,
            id = id,
            profile = EXPECTED_PROFILE_ID,
            schema = EXPECTED_SCHEMA_ID,
            program = EXPECTED_PROGRAM_ID,
            mode = EXPECTED_MODE_ID,
            evaluator = EXPECTED_EVALUATOR_ID,
            control = EXPECTED_CONTROL_SET_ID,
            rule = EXPECTED_RULE_ID,
            phase0 = EXPECTED_PHASE0_BINDING,
        )
    }

    #[test]
    fn output_grammar_binds_identity_keys_and_result_reason() {
        let bundle_id = "b".repeat(128);
        let line = valid_kernel_line(&bundle_id);
        assert!(validate_kernel_line(&line, 4, &bundle_id).is_ok());
        let forged_key = line.replacen("request_id=", "forged_id=", 1);
        assert_eq!(
            validate_kernel_line(&forged_key, 4, &bundle_id),
            Err("kernel-output-grammar")
        );
        let forged_reason =
            line.replacen("reason=VALID_CONTINUITY", "reason=EXPIRED_OR_TERMINATED", 1);
        assert_eq!(
            validate_kernel_line(&forged_reason, 4, &bundle_id),
            Err("kernel-output-result-binding")
        );
        let forged_bundle = line.replacen(&bundle_id, &"c".repeat(128), 1);
        assert_eq!(
            validate_kernel_line(&forged_bundle, 4, &bundle_id),
            Err("kernel-output-bundle-id")
        );
    }

    #[test]
    fn limited_reader_reports_overflow_without_allocating_unbounded_output() {
        let overflow = Arc::new(AtomicBool::new(false));
        assert_eq!(
            read_limited(&b"12345"[..], 4, Arc::clone(&overflow)),
            Err(())
        );
        assert!(overflow.load(Ordering::Acquire));
        let within = Arc::new(AtomicBool::new(false));
        assert_eq!(read_limited(&b"1234"[..], 4, within), Ok(b"1234".to_vec()));
    }

    #[test]
    fn cleanup_terminates_a_started_child_within_the_bound() {
        #[cfg(windows)]
        let mut child = Command::new("cmd")
            .args(["/C", "ping", "127.0.0.1", "-n", "30"])
            .spawn()
            .expect("cmd must be available on the Windows test host");
        #[cfg(not(windows))]
        let mut child = Command::new("sh")
            .args(["-c", "sleep 30"])
            .spawn()
            .expect("sh must be available on the test host");
        let started = Instant::now();
        let status = cleanup_child_bounded(&mut child).expect("child cleanup");
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(!status.success());
    }

    #[test]
    fn cleanup_reports_a_reader_that_never_completes() {
        let (sender, receiver) = mpsc::sync_channel::<()>(1);
        let handle = thread::spawn(|| {
            thread::sleep(Duration::from_millis(100));
        });
        let result = join_with_result(handle, receiver, Instant::now() + Duration::from_millis(5));
        drop(sender);
        assert!(matches!(result, WorkerDisposition::Unresolved));
    }

    #[test]
    fn cleanup_reports_a_panicked_reader() {
        let (sender, receiver) = mpsc::sync_channel::<()>(1);
        let handle = thread::spawn(|| panic!("synthetic reader fault"));
        drop(sender);
        assert!(matches!(
            join_with_result(
                handle,
                receiver,
                Instant::now() + Duration::from_millis(100)
            ),
            WorkerDisposition::Failed
        ));
    }

    #[test]
    fn cleanup_collects_later_workers_after_an_earlier_failure() {
        let (failed_sender, failed_receiver) = mpsc::sync_channel::<()>(1);
        let failed_handle = thread::spawn(|| panic!("synthetic reader fault"));
        drop(failed_sender);
        let (ok_sender, ok_receiver) = mpsc::sync_channel::<u8>(1);
        let ok_handle = thread::spawn(move || {
            let _ = ok_sender.send(7);
        });
        let deadline = Instant::now() + Duration::from_millis(100);
        let failed = join_with_result(failed_handle, failed_receiver, deadline);
        let completed = join_with_result(ok_handle, ok_receiver, deadline);
        assert!(matches!(failed, WorkerDisposition::Failed));
        assert!(matches!(completed, WorkerDisposition::Complete(7)));
    }

    #[cfg(windows)]
    #[test]
    fn verified_artifact_handle_denies_deterministic_replacement() {
        let artifact = kernel_artifact().expect("the reviewed artifact must be available");
        let replacement = artifact
            .path
            .with_extension(format!("replacement-test-{}", std::process::id()));
        assert!(!replacement.exists());
        let result = fs::rename(&artifact.path, &replacement);
        assert!(
            result.is_err(),
            "replacement unexpectedly succeeded: {result:?}"
        );
        assert!(!replacement.exists());
    }
}
