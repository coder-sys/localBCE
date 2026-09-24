//! Versioned, bounded transport for the non-authoritative Queue lifecycle kernel.

use std::io::{self, Read, Write};
use std::ffi::CString;
use std::fs;
use sha2::{Digest, Sha256};

const MAX_INPUT_BYTES: usize = 16_384;
const MAX_OUTPUT_BYTES: usize = 32_768;
const MAX_HEX_BYTES: u64 = (MAX_OUTPUT_BYTES * 2) as u64;
const MAX_MANIFEST_BYTES: usize = 1_048_576;
const MANIFEST_HEADER: &str = "blind-ledger-lifecycle-source-manifest-v2\n";
const PROVENANCE_PREFIX: &str = "BL-LIFECYCLE-PROVENANCE/1";

#[repr(C)]
struct LeanObject {
    // Matches lean_object in the pinned Lean 4.33.1 lean.h header.
    _rc: i32,
    _cs_sz: u16,
    _other: u8,
    tag: u8,
}

extern "C" {
    static blind_ledger_lifecycle_source_manifest: u8;
    static blind_ledger_lifecycle_source_manifest_length: u64;
    fn lean_initialize_runtime_module();
    fn lean_io_mark_end_initialization();
    fn lean_init_task_manager();
    fn lean_finalize_task_manager();
    fn lean_mk_string(value: *const std::ffi::c_char) -> *mut LeanObject;
    fn lean_inc_ref_huge_n(value: *mut LeanObject, count: usize);
    fn lean_dec_ref_cold(value: *mut LeanObject);
    fn initialize_blind__ledger__admission__kernel_Admission_LifecycleKernel(
        builtin: u8,
    ) -> *mut LeanObject;
    fn blind_ledger_lifecycle_run_hex(input: *mut LeanObject) -> *mut LeanObject;
    fn blind_ledger_lifecycle_run_hex_size(input: *mut LeanObject) -> u64;
    fn blind_ledger_lifecycle_output_byte(output: *mut LeanObject, index: u64) -> u32;
}

fn valid_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_embedded_manifest() -> Result<String, &'static str> {
    let (length, pointer) = unsafe {
        (
            blind_ledger_lifecycle_source_manifest_length,
            std::ptr::addr_of!(blind_ledger_lifecycle_source_manifest),
        )
    };
    if length == 0 || length > MAX_MANIFEST_BYTES as u64 {
        return Err("manifest-size");
    }
    let bytes = unsafe { std::slice::from_raw_parts(pointer, length as usize) };
    let manifest = std::str::from_utf8(bytes).map_err(|_| "manifest-utf8")?;
    if !manifest.starts_with(MANIFEST_HEADER) || !manifest.ends_with('\n') || manifest.contains('\r') {
        return Err("manifest-format");
    }
    let mut previous_path: Option<&str> = None;
    let mut record_count = 0usize;
    for line in manifest[MANIFEST_HEADER.len()..].split_terminator('\n') {
        record_count += 1;
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 4 {
            return Err("manifest-record");
        }
        let path = fields[0];
        if path.is_empty()
            || !path.is_ascii()
            || path.starts_with('/')
            || path.contains('\\')
            || path.split('/').any(|part| part.is_empty() || part == "." || part == "..")
            || previous_path.is_some_and(|previous| previous >= path)
        {
            return Err("manifest-path");
        }
        previous_path = Some(path);
        for number in [fields[1], fields[2]] {
            let parsed = number.parse::<u64>().map_err(|_| "manifest-number")?;
            if parsed == 0 || parsed.to_string() != number {
                return Err("manifest-number");
            }
        }
        if !valid_lower_hex_digest(fields[3]) {
            return Err("manifest-digest");
        }
    }
    if record_count == 0 {
        return Err("manifest-record");
    }
    let expected = env!("BL_LIFECYCLE_SOURCE_MANIFEST_SHA256");
    if !valid_lower_hex_digest(expected) {
        return Err("manifest-build-pin");
    }
    let actual = format!("{:x}", Sha256::digest(bytes));
    if actual != expected {
        return Err("manifest-build-mismatch");
    }
    Ok(actual)
}

fn write_success_provenance(manifest_sha256: &str) -> Result<(), &'static str> {
    let executable = std::env::current_exe().map_err(|_| "provenance-executable-path")?;
    let bytes = fs::read(executable).map_err(|_| "provenance-executable-read")?;
    let executable_sha256 = format!("{:x}", Sha256::digest(&bytes));
    let line = format!(
        "{PROVENANCE_PREFIX};manifest_sha256={manifest_sha256};exe_size={};exe_sha256={executable_sha256}\n",
        bytes.len(),
    );
    let mut stderr = io::stderr().lock();
    stderr.write_all(line.as_bytes()).map_err(|_| "provenance-write")?;
    stderr.flush().map_err(|_| "provenance-write")
}

struct LeanOwned(*mut LeanObject);

impl LeanOwned {
    fn from_raw(value: *mut LeanObject) -> Option<Self> {
        if value.is_null() {
            None
        } else {
            Some(Self(value))
        }
    }

    fn clone_arg(&self) -> *mut LeanObject {
        unsafe { lean_inc_ref_huge_n(self.0, 1) };
        self.0
    }
}

impl Drop for LeanOwned {
    fn drop(&mut self) {
        // All outstanding clone_arg references have been consumed by Lean exports.
        unsafe { lean_dec_ref_cold(self.0) };
    }
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

fn encode_hex(input: &[u8]) -> CString {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = Vec::with_capacity(input.len() * 2);
    for byte in input {
        output.push(DIGITS[(byte >> 4) as usize]);
        output.push(DIGITS[(byte & 0x0f) as usize]);
    }
    CString::new(output).expect("hex output has no NUL")
}

fn initialize_lean() -> Result<(), &'static str> {
    unsafe {
        lean_initialize_runtime_module();
        let initialization =
            initialize_blind__ledger__admission__kernel_Admission_LifecycleKernel(1);
        if initialization.is_null() {
            return Err("lean-initialize");
        }
        let result_tag = (*initialization).tag;
        lean_dec_ref_cold(initialization);
        if result_tag != 0 {
            return Err("lean-initialize");
        }
        lean_io_mark_end_initialization();
        lean_init_task_manager();
    }
    Ok(())
}

fn run_linked(input: &[u8]) -> Result<Vec<u8>, &'static str> {
    let hex_input = encode_hex(input);
    unsafe {
        let lean_input = LeanOwned::from_raw(lean_mk_string(hex_input.as_ptr()))
            .ok_or("lean-input-allocation")?;
        let lean_output = LeanOwned::from_raw(blind_ledger_lifecycle_run_hex(lean_input.clone_arg()))
            .ok_or("lean-run")?;
        let length = blind_ledger_lifecycle_run_hex_size(lean_output.clone_arg());
        if length == 0 || length > MAX_HEX_BYTES {
            return Err("lean-output-size");
        }
        let mut output = Vec::with_capacity(length as usize / 2);
        let mut high_nibble: Option<u8> = None;
        for index in 0..length {
            let codepoint = blind_ledger_lifecycle_output_byte(lean_output.clone_arg(), index);
            if codepoint > 0x7f {
                return Err("lean-output-ascii");
            }
            let digit = match codepoint as u8 {
                b'0'..=b'9' => codepoint as u8 - b'0',
                b'a'..=b'f' => codepoint as u8 - b'a' + 10,
                _ => return Err("lean-output-hex"),
            };
            if let Some(high) = high_nibble.take() {
                output.push((high << 4) | digit);
                if output.len() > MAX_OUTPUT_BYTES {
                    return Err("output-too-large");
                }
            } else {
                high_nibble = Some(digit);
            }
        }
        if high_nibble.is_some() || output.is_empty() {
            return Err("lean-output-width");
        }
        Ok(output)
    }
}

fn execute() -> Result<(), &'static str> {
    let manifest_sha256 = validate_embedded_manifest()?;
    let input = read_stdin_bounded()?;
    initialize_lean()?;
    let output = run_linked(&input);
    unsafe { lean_finalize_task_manager() };
    let output = output?;
    write_success_provenance(&manifest_sha256)?;
    io::stdout()
        .lock()
        .write_all(&output)
        .map_err(|_| "stdout-write")
}

fn main() {
    if std::env::args_os().len() != 1 {
        eprintln!("BL-LIFECYCLE-ADAPTER/1;error=arguments");
        std::process::exit(2);
    }
    if let Err(error) = execute() {
        eprintln!("BL-LIFECYCLE-ADAPTER/1;error={error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_transport_is_lowercase_and_preserves_binary_bytes() {
        assert_eq!(encode_hex(&[0x00, 0x7f, 0xa5, 0xff]).as_bytes(), b"007fa5ff");
    }
}
