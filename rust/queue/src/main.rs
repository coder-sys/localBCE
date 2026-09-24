//! Bounded native transport for the statically linked Lean admission kernel.
//!
//! The adapter owns only process identity, byte bounds, timeout accounting,
//! and input/result binding. Admission decoding and semantics execute in the
//! linked Lean export; there is no child-process or dynamic-library fallback.

use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_INPUT_BYTES: usize = 1_000_000;
const MAX_RESULT_BYTES: usize = 216;
const ADMISSION_TIMEOUT: Duration = Duration::from_secs(3);
const BUILD_ID: &str = "BLAQ-ADMISSION-LEAN-LINKED-V2";
const LEAN_TOOLCHAIN: &[u8] = b"leanprover/lean4:v4.33.1\n";
const INPUT_BYTES: usize = 110;
const RESULT_BYTES: usize = 112;
const RESPONSE_BYTES: usize = 8 + 32 + 32 + 32 + RESULT_BYTES;
const MAX_COUNTER: u64 = 4_294_967_296;

// This digest is independently pinned to the project static archive, not the
// final adapter executable, so the response has no self-hash cycle.
const EXPECTED_LINKED_ARTIFACT_SHA256: &str =
    "86cedcae0f9758b75c7a4a4d3de5ca9c28b05b628e08b1868b26ca74584ca13c";
const EXPECTED_SOURCE_BINDING_SHA256: &str =
    "768f9d69ebb660875448088bfc1983862b2db46f69e773bde19b7ee0feb09de6";

const SOURCE_FILES: &[&str] = &[
    "Admission/Model.lean",
    "Admission/Library.lean",
    "Admission/Main.lean",
    "Admission/Checker.lean",
    "BlindLedger/Sha3.lean",
    "lakefile.toml",
    "lean-toolchain",
    "lake-manifest.json",
];

extern "C" {
    fn blind_ledger_native_initialize() -> i32;
    fn blind_ledger_native_run(
        input: *const u8,
        input_length: usize,
        output: *mut *mut u8,
        output_length: *mut usize,
    ) -> i32;
    fn blind_ledger_native_free(output: *mut u8, output_length: usize);
    fn blind_ledger_native_shutdown();
}

struct ArtifactIdentity {
    sha256: [u8; 32],
    source_binding_sha256: [u8; 32],
}

fn decode_hex(value: &str) -> Result<Vec<u8>, &'static str> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("identity-grammar");
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).ok_or("identity-grammar")?;
            let low = (pair[1] as char).to_digit(16).ok_or("identity-grammar")?;
            Ok(((high << 4) | low) as u8)
        })
        .collect()
}

fn parse_digest(value: &str) -> Result<[u8; 32], &'static str> {
    let bytes = decode_hex(value)?;
    bytes.try_into().map_err(|_| "identity-grammar")
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn lean_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..\\..\\lean\\queue")
}

fn linked_artifact_path(root: &Path) -> PathBuf {
    root.join(".lake\\build\\lib\\blind_ledger_admission_link.gnu.a")
}

fn regular_file(path: &Path, error: &'static str) -> Result<(), &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| error)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(error);
    }
    Ok(())
}

fn source_binding(root: &Path) -> Result<[u8; 32], &'static str> {
    let canonical_root = fs::canonicalize(root).map_err(|_| "source-unavailable")?;
    if canonical_root != root {
        return Err("source-root");
    }
    if fs::read(root.join("lean-toolchain")).map_err(|_| "toolchain-unavailable")?
        != LEAN_TOOLCHAIN
    {
        return Err("toolchain-mismatch");
    }
    let mut hasher = Sha256::new();
    for relative in SOURCE_FILES {
        let path = root.join(relative);
        regular_file(&path, "source-unavailable")?;
        let canonical = fs::canonicalize(&path).map_err(|_| "source-unavailable")?;
        if !canonical.starts_with(&canonical_root) || canonical != path {
            return Err("source-location");
        }
        let bytes = fs::read(&canonical).map_err(|_| "source-unavailable")?;
        hasher.update(relative.as_bytes());
        hasher.update([0]);
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    let native_boundary = Path::new(env!("CARGO_MANIFEST_DIR")).join("native_boundary.c");
    regular_file(&native_boundary, "native-boundary-unavailable")?;
    let native_boundary_root = fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")))
        .map_err(|_| "native-boundary-unavailable")?;
    let native_boundary = fs::canonicalize(&native_boundary)
        .map_err(|_| "native-boundary-unavailable")?;
    if !native_boundary.starts_with(&native_boundary_root) {
        return Err("native-boundary-location");
    }
    let native_boundary_bytes = fs::read(&native_boundary).map_err(|_| "native-boundary-unavailable")?;
    hasher.update(b"native_boundary.c");
    hasher.update([0]);
    hasher.update((native_boundary_bytes.len() as u64).to_be_bytes());
    hasher.update(native_boundary_bytes);
    let digest: [u8; 32] = hasher.finalize().into();
    if digest != parse_digest(EXPECTED_SOURCE_BINDING_SHA256)? {
        return Err("source-binding-mismatch");
    }
    Ok(digest)
}

fn linked_artifact() -> Result<ArtifactIdentity, &'static str> {
    let root = lean_root();
    let canonical_root = fs::canonicalize(&root).map_err(|_| "source-unavailable")?;
    let source_binding_sha256 = source_binding(&canonical_root)?;
    let expected_path = linked_artifact_path(&canonical_root);
    regular_file(&expected_path, "artifact-unavailable")?;
    let canonical_path = fs::canonicalize(&expected_path).map_err(|_| "artifact-unavailable")?;
    if canonical_path != expected_path {
        return Err("artifact-location");
    }
    let metadata = fs::metadata(&canonical_path).map_err(|_| "artifact-unavailable")?;
    if metadata.len() == 0 || metadata.len() > 16 * 1024 * 1024 {
        return Err("artifact-size");
    }
    let bytes = fs::read(&canonical_path).map_err(|_| "artifact-unavailable")?;
    let sha256 = sha256(&bytes);
    if sha256 != parse_digest(EXPECTED_LINKED_ARTIFACT_SHA256)? {
        return Err("artifact-binding-mismatch");
    }
    Ok(ArtifactIdentity {
        sha256,
        source_binding_sha256,
    })
}

fn little_u64(bytes: &[u8]) -> u64 {
    let mut value = 0u64;
    for (index, byte) in bytes.iter().enumerate() {
        value |= (*byte as u64) << (index * 8);
    }
    value
}

fn validate_result(result: &[u8]) -> Result<(), &'static str> {
    if result.len() != RESULT_BYTES || &result[..8] != b"BLADOUT1" || result[8] != 1 {
        return Err("result-grammar");
    }
    if result[9] > 1
        || result[10] > 4
        || !(1..=11).contains(&result[11])
        || result[12] > 5
        || result[13] > 4
        || result[14] > 3
        || result[15] > 4
    {
        return Err("result-enum");
    }
    for pair in result[16..].chunks_exact(16) {
        let used = little_u64(&pair[..8]);
        let cap = little_u64(&pair[8..]);
        if used > MAX_COUNTER || cap > MAX_COUNTER || used > cap {
            return Err("result-counter");
        }
    }
    Ok(())
}

fn read_stdin_bounded() -> Result<Vec<u8>, &'static str> {
    let mut input = Vec::new();
    io::stdin()
        .lock()
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|_| "stdin-read")?;
    if input.len() > MAX_INPUT_BYTES {
        return Err("input-too-large");
    }
    Ok(input)
}

fn run_linked(input: &[u8]) -> Result<Vec<u8>, &'static str> {
    let started = Instant::now();
    let mut output = std::ptr::null_mut();
    let mut output_length = 0usize;
    let status = unsafe {
        blind_ledger_native_run(
            input.as_ptr(),
            input.len(),
            &mut output,
            &mut output_length,
        )
    };
    if started.elapsed() > ADMISSION_TIMEOUT {
        if !output.is_null() {
            unsafe { blind_ledger_native_free(output, output_length) };
        }
        return Err("timeout");
    }
    if status != 0 || output.is_null() || output_length > MAX_RESULT_BYTES {
        if !output.is_null() {
            unsafe { blind_ledger_native_free(output, output_length) };
        }
        return Err("linked-run");
    }
    let bytes = unsafe { std::slice::from_raw_parts(output, output_length).to_vec() };
    unsafe { blind_ledger_native_free(output, output_length) };
    Ok(bytes)
}

fn reject<T>(error: &'static str) -> T {
    eprintln!("BL-ADMISSION-ADAPTER/2;result=REJECT;build_id={BUILD_ID};error={error}");
    std::process::exit(1)
}

fn main() {
    let input = read_stdin_bounded().unwrap_or_else(reject);
    if input.len() != INPUT_BYTES {
        reject::<()>("input-grammar");
    }
    let artifact = linked_artifact().unwrap_or_else(reject);
    if unsafe { blind_ledger_native_initialize() } != 0 {
        reject::<()>("linked-initialize");
    }
    let result = run_linked(&input);
    unsafe { blind_ledger_native_shutdown() };
    let result = result.unwrap_or_else(reject);
    validate_result(&result).unwrap_or_else(reject);

    let mut response = Vec::with_capacity(RESPONSE_BYTES);
    response.extend_from_slice(b"BLADAP01");
    response.extend_from_slice(&sha256(&input));
    response.extend_from_slice(&artifact.sha256);
    response.extend_from_slice(&artifact.source_binding_sha256);
    response.extend_from_slice(&result);
    io::stdout()
        .write_all(&response)
        .unwrap_or_else(|_| reject("adapter-output"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_validator_rejects_wrong_width_and_accepts_fixed_shape() {
        let mut result = vec![0u8; RESULT_BYTES];
        result[..8].copy_from_slice(b"BLADOUT1");
        result[8] = 1;
        result[9] = 1;
        result[10] = 0;
        result[11] = 1;
        assert!(validate_result(&result).is_ok());
        assert_eq!(validate_result(&result[..111]), Err("result-grammar"));
        result[10] = 9;
        assert_eq!(validate_result(&result), Err("result-enum"));
    }

    #[test]
    fn little_endian_round_trip_for_counter() {
        let value = 4_294_967_296u64;
        assert_eq!(little_u64(&value.to_le_bytes()), value);
    }
}
