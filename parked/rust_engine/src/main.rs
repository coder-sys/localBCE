//! Narrow one-process boundary for the reviewed, statically linked Lean
//! semantic kernel.  Rust owns bounded transport and result grammar; Lean
//! remains the semantic authority.

use sha3::Sha3_512;
use std::env;
use std::io::{self, Read};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

mod link_receipt {
    include!(concat!(env!("OUT_DIR"), "/link_receipt.rs"));
}

const MAX_BUNDLE_BYTES: usize = 1_000_000;
const MAX_KERNEL_OUTPUT_BYTES: usize = 64 * 1024;
const KERNEL_TIMEOUT: Duration = Duration::from_millis(2_000);
const KERNEL_BUILD_ID: &str = "BLSK-BLCBND02-EXACT-V2";
const KERNEL_ENV: &str = "BL_SEMANTIC_KERNEL_EXE";

// This is a source/toolchain declaration, not a runtime path.  The actual
// source, lockfile, compiler, archive, and generated-object identities are
// embedded in link_receipt.rs by build.rs and checked below.
const LEAN_TOOLCHAIN: &str = "leanprover/lean4:v4.33.1\n";

// These are reviewed hard pins.  They remain fail-closed until the complete
// static-link receipt and the outer final-executable pin have been reviewed.
const EXPECTED_LEAN_SOURCE_BINDING_SHA256: &str =
    "eae07e9685e736a962df125e96ec8d8a32338b2a89aa4dffd1b945bee0fb484b";
const EXPECTED_LEAN_OBJECTS_BINDING_SHA256: &str =
    "c885280105cd8e4c2bb5a8a117ab29518a68784ad283e851c90d66ee1fd545a7";
const EXPECTED_RUNTIME_LIBRARIES_BINDING_SHA256: &str =
    "2472568446e5a92dfdea0b0ba913e620898d859168aff557441176396cb4ca22";
const EXPECTED_LEAN_COMPILER_SHA256: &str =
    "af49bacfabaa1fea71332ca0feae0fa1a60912219d5902291adc79f905bffb8d";
const EXPECTED_NATIVE_COMPILER_SHA256: &str =
    "1aea18dca98f91a6a7c65532adc2567efc775904d2a4bd28bf06731bc2c3778c";
const EXPECTED_LLD_SHA256: &str =
    "675e59f33f11cb90500577f116082ed4a6214fcac3a1bad88d6323aa0373179f";
const EXPECTED_ARCHIVER_SHA256: &str =
    "ff7fcf456130e4fb58bc24f7cf0f2e7113ce96af534fc61f861c54a43e674a9d";
const EXPECTED_RUST_COMPILER_SHA256: &str =
    "acb138286bbe20c6cf3ec39a7e0a68c3fab0cd949baa2912cf466514d0d531ab";
const EXPECTED_RUST_LINKER_SHA256: &str =
    "1aea18dca98f91a6a7c65532adc2567efc775904d2a4bd28bf06731bc2c3778c";
const EXPECTED_RUST_TARGET_STD_MANIFEST_SHA256: &str =
    "3e18bbb8b5c6ad86b8faceefd9ac4fb934e857dd546b82216a084546f0ec1cbe";
const EXPECTED_RUST_TARGET_STD_BINDING_SHA256: &str =
    "7fc52762b8d5098e5283ffa754d30cb8fab4ff1027118ef1e8ae2f83d5ec094b";
const EXPECTED_WINDOWS_NTDLL_SHA256: &str =
    "a373f724ef6d8ea11a8b03de653ac1b4f111522f59a1f4b787ec9d93f31fe7c1";
const EXPECTED_NATIVE_BOUNDARY_OBJECT_SHA256: &str =
    "d1743448796ce4295ce5596407e3bad7ec5a5ae71ef071094f38856efcaaab82";
const EXPECTED_NATIVE_BUILD_CONFIG_SHA256: &str =
    "74049bdf6eeb1be100e3ac30077188af49f0c4eb539570406a583a26e7502180";
const EXPECTED_BUILD_RECEIPT_SHA256: &str =
    "255714610e0053d6611bde9f085bbd672562d576d10c4f94aadecfcfcc605b13";

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

const NATIVE_OK: i32 = 0;

extern "C" {
    fn blind_ledger_native_run(
        input: *const u8,
        input_len: usize,
        output: *mut *mut u8,
        output_len: *mut usize,
    ) -> i32;
    fn blind_ledger_native_free(output: *mut u8, output_len: usize);
    fn blind_ledger_native_shutdown();
}

struct LinkedArtifactIdentity {
    source_binding_sha256: &'static str,
    lean_objects_binding_sha256: &'static str,
    runtime_libraries_binding_sha256: &'static str,
    lean_compiler_sha256: &'static str,
    native_compiler_sha256: &'static str,
    archiver_sha256: &'static str,
    rust_compiler_sha256: &'static str,
    rust_linker_sha256: &'static str,
    native_boundary_object_sha256: &'static str,
    native_build_config_sha256: &'static str,
    build_receipt_sha256: &'static str,
}

struct NativeResponse {
    status: i32,
    output: Vec<u8>,
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

fn sha3_512_domain(domain: &str, parts: &[&[u8]]) -> String {
    use sha3::Digest;
    let mut hasher = Sha3_512::new();
    hasher.update(domain.as_bytes());
    hasher.update([0u8]);
    for part in parts {
        hasher.update(part);
    }
    hex(&hasher.finalize())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn linked_artifact() -> Result<LinkedArtifactIdentity, &'static str> {
    if !link_receipt::STATIC_LINKAGE {
        return Err("kernel-dynamic-linkage-forbidden");
    }
    let receipt = [
        link_receipt::LEAN_SOURCE_BINDING_SHA256,
        link_receipt::LEAN_OBJECTS_BINDING_SHA256,
        link_receipt::RUNTIME_LIBRARIES_BINDING_SHA256,
        link_receipt::LEAN_COMPILER_SHA256,
        link_receipt::NATIVE_COMPILER_SHA256,
        link_receipt::LLD_SHA256,
        link_receipt::ARCHIVER_SHA256,
        link_receipt::RUST_COMPILER_SHA256,
        link_receipt::RUST_LINKER_SHA256,
        link_receipt::RUST_TARGET_STD_MANIFEST_SHA256,
        link_receipt::RUST_TARGET_STD_BINDING_SHA256,
        link_receipt::WINDOWS_NTDLL_SHA256,
        link_receipt::NATIVE_BOUNDARY_OBJECT_SHA256,
        link_receipt::NATIVE_BUILD_CONFIG_SHA256,
        link_receipt::BUILD_RECEIPT_SHA256,
    ];
    if receipt.iter().any(|value| !is_sha256_hex(value)) {
        return Err("kernel-link-receipt-invalid");
    }
    if link_receipt::LEAN_SOURCE_BINDING_SHA256 != EXPECTED_LEAN_SOURCE_BINDING_SHA256 {
        return Err("kernel-source-binding-mismatch");
    }
    if link_receipt::LEAN_OBJECTS_BINDING_SHA256 != EXPECTED_LEAN_OBJECTS_BINDING_SHA256 {
        return Err("kernel-object-binding-mismatch");
    }
    if link_receipt::RUNTIME_LIBRARIES_BINDING_SHA256 != EXPECTED_RUNTIME_LIBRARIES_BINDING_SHA256 {
        return Err("kernel-runtime-binding-mismatch");
    }
    if link_receipt::LEAN_COMPILER_SHA256 != EXPECTED_LEAN_COMPILER_SHA256 {
        return Err("kernel-compiler-binding-mismatch");
    }
    if link_receipt::NATIVE_COMPILER_SHA256 != EXPECTED_NATIVE_COMPILER_SHA256 {
        return Err("kernel-native-compiler-binding-mismatch");
    }
    if link_receipt::LLD_SHA256 != EXPECTED_LLD_SHA256 {
        return Err("kernel-lld-binding-mismatch");
    }
    if link_receipt::ARCHIVER_SHA256 != EXPECTED_ARCHIVER_SHA256 {
        return Err("kernel-archiver-binding-mismatch");
    }
    if link_receipt::RUST_COMPILER_SHA256 != EXPECTED_RUST_COMPILER_SHA256 {
        return Err("kernel-rust-compiler-binding-mismatch");
    }
    if link_receipt::RUST_LINKER_SHA256 != EXPECTED_RUST_LINKER_SHA256 {
        return Err("kernel-rust-linker-binding-mismatch");
    }
    if link_receipt::RUST_TARGET_STD_MANIFEST_SHA256 != EXPECTED_RUST_TARGET_STD_MANIFEST_SHA256 {
        return Err("kernel-rust-target-std-manifest-binding-mismatch");
    }
    if link_receipt::RUST_TARGET_STD_BINDING_SHA256 != EXPECTED_RUST_TARGET_STD_BINDING_SHA256 {
        return Err("kernel-rust-target-std-binding-mismatch");
    }
    if link_receipt::WINDOWS_NTDLL_SHA256 != EXPECTED_WINDOWS_NTDLL_SHA256 {
        return Err("kernel-windows-ntdll-binding-mismatch");
    }
    if link_receipt::LEAN_TOOLCHAIN != LEAN_TOOLCHAIN {
        return Err("kernel-toolchain-binding-mismatch");
    }
    if link_receipt::NATIVE_BOUNDARY_OBJECT_SHA256 != EXPECTED_NATIVE_BOUNDARY_OBJECT_SHA256 {
        return Err("kernel-native-boundary-binding-mismatch");
    }
    if link_receipt::NATIVE_BUILD_CONFIG_SHA256 != EXPECTED_NATIVE_BUILD_CONFIG_SHA256 {
        return Err("kernel-native-build-config-mismatch");
    }
    if link_receipt::BUILD_RECEIPT_SHA256 != EXPECTED_BUILD_RECEIPT_SHA256 {
        return Err("kernel-link-build-receipt-mismatch");
    }
    Ok(LinkedArtifactIdentity {
        source_binding_sha256: link_receipt::LEAN_SOURCE_BINDING_SHA256,
        lean_objects_binding_sha256: link_receipt::LEAN_OBJECTS_BINDING_SHA256,
        runtime_libraries_binding_sha256: link_receipt::RUNTIME_LIBRARIES_BINDING_SHA256,
        lean_compiler_sha256: link_receipt::LEAN_COMPILER_SHA256,
        native_compiler_sha256: link_receipt::NATIVE_COMPILER_SHA256,
        archiver_sha256: link_receipt::ARCHIVER_SHA256,
        rust_compiler_sha256: link_receipt::RUST_COMPILER_SHA256,
        rust_linker_sha256: link_receipt::RUST_LINKER_SHA256,
        native_boundary_object_sha256: link_receipt::NATIVE_BOUNDARY_OBJECT_SHA256,
        native_build_config_sha256: link_receipt::NATIVE_BUILD_CONFIG_SHA256,
        build_receipt_sha256: link_receipt::BUILD_RECEIPT_SHA256,
    })
}

fn native_status_error(status: i32) -> &'static str {
    match status {
        1 => "kernel-native-invalid-argument",
        2 => "kernel-native-initialization",
        3 => "kernel-output-too-large",
        4 => "kernel-native-allocation",
        5 => "kernel-native-result-invalid",
        _ => "kernel-native-status",
    }
}

fn run_native(bundle: &[u8]) -> Result<Vec<u8>, &'static str> {
    if bundle.len() > MAX_BUNDLE_BYTES {
        return Err("bundle-too-large");
    }
    let input = bundle.to_vec();
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = thread::Builder::new()
        .name("semantic-kernel-native-call".to_string())
        .spawn(move || {
            let mut output = std::ptr::null_mut();
            let mut output_len = 0usize;
            let status = unsafe {
                blind_ledger_native_run(input.as_ptr(), input.len(), &mut output, &mut output_len)
            };
            let copied = if status == NATIVE_OK
                && !output.is_null()
                && output_len <= MAX_KERNEL_OUTPUT_BYTES
            {
                unsafe { std::slice::from_raw_parts(output, output_len).to_vec() }
            } else {
                Vec::new()
            };
            if !output.is_null() {
                unsafe { blind_ledger_native_free(output, output_len) };
            }
            let _ = sender.send(NativeResponse {
                status,
                output: copied,
            });
        })
        .map_err(|_| "kernel-thread-start")?;
    let response = match receiver.recv_timeout(KERNEL_TIMEOUT) {
        Ok(value) => value,
        Err(mpsc::RecvTimeoutError::Timeout) => return Err("kernel-timeout"),
        Err(mpsc::RecvTimeoutError::Disconnected) => return Err("kernel-native-worker"),
    };
    if worker.join().is_err() {
        unsafe { blind_ledger_native_shutdown() };
        return Err("kernel-native-worker");
    }
    unsafe { blind_ledger_native_shutdown() };
    if response.status != NATIVE_OK {
        return Err(native_status_error(response.status));
    }
    if response.output.len() > MAX_KERNEL_OUTPUT_BYTES {
        return Err("kernel-output-too-large");
    }
    Ok(response.output)
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
            .take((MAX_BUNDLE_BYTES + 1) as u64)
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

fn reject(error: &'static str) -> ! {
    eprintln!("BL-SEMANTIC-ADAPTER/2;result=REJECT;error={error}");
    std::process::exit(1)
}

fn main() {
    if env::var_os(KERNEL_ENV).is_some() {
        reject("kernel-artifact-override-forbidden");
    }
    let input = match read_stdin_bounded() {
        Ok(value) => value,
        Err(error) => reject(error),
    };
    if input.len() > MAX_BUNDLE_BYTES {
        reject("bundle-too-large");
    }
    let artifact = match linked_artifact() {
        Ok(value) => value,
        Err(error) => reject(error),
    };
    let bundle_id = sha3_512_domain("BL/NATIVE-V3/CONTINUITY/BUNDLE/v2", &[&input]);
    let output = match run_native(&input) {
        Ok(value) => value,
        Err(error) => reject(error),
    };
    let line = match std::str::from_utf8(&output) {
        Ok(value) => value,
        Err(_) => reject("kernel-output-not-utf8"),
    };
    if validate_kernel_line(line, input.len(), &bundle_id).is_err() {
        reject("kernel-output-invalid");
    }
    println!(
        "BL-SEMANTIC-ADAPTER/2;result=PASS;artifact_sha256={};artifact_role=native-link-build-receipt;build_receipt_sha256={};source_binding_sha256={};lean_object_binding_sha256={};runtime_library_binding_sha256={};lean_compiler_sha256={};native_compiler_sha256={};archiver_sha256={};rust_compiler_sha256={};rust_linker_sha256={};native_boundary_object_sha256={};native_build_config_sha256={};toolchain_id=leanprover/lean4:v4.33.1;schema=BLCBND02/v2;{}",
        artifact.build_receipt_sha256,
        artifact.build_receipt_sha256,
        artifact.source_binding_sha256,
        artifact.lean_objects_binding_sha256,
        artifact.runtime_libraries_binding_sha256,
        artifact.lean_compiler_sha256,
        artifact.native_compiler_sha256,
        artifact.archiver_sha256,
        artifact.rust_compiler_sha256,
        artifact.rust_linker_sha256,
        artifact.native_boundary_object_sha256,
        artifact.native_build_config_sha256,
        line.split(';').skip(3).collect::<Vec<_>>().join(";")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn receipt_values_are_exact_sha256_bindings() {
        assert!(!is_sha256_hex("UNPINNED"));
        assert!(is_sha256_hex(&"a".repeat(64)));
        assert!(!is_sha256_hex(&"a".repeat(63)));
        assert!(!is_sha256_hex(&"g".repeat(64)));
    }

    #[test]
    fn native_statuses_fail_closed() {
        assert_eq!(native_status_error(1), "kernel-native-invalid-argument");
        assert_eq!(native_status_error(5), "kernel-native-result-invalid");
        assert_eq!(native_status_error(99), "kernel-native-status");
    }

    #[test]
    fn native_boundary_preserves_bundle_bound() {
        assert_eq!(
            run_native(&vec![0u8; MAX_BUNDLE_BYTES + 1]),
            Err("bundle-too-large")
        );
    }
}
