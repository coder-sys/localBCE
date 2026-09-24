use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const EXPECTED_LEAN_TOOLCHAIN: &str = "leanprover/lean4:v4.33.1\n";
const RUST_HOST_TOOLCHAIN: &str = "1.96.0-x86_64-pc-windows-msvc";
const RUST_TARGET: &str = "x86_64-pc-windows-gnu";
const RUST_TARGET_STD_MANIFEST: &str = "lib/rustlib/manifest-rust-std-x86_64-pc-windows-gnu";
const APPROVED_CARGO_ENCODED_RUSTFLAGS: &str = "-C\x1flink-self-contained=no\x1f-C\x1fpanic=abort";
const RUST_TARGET_STD_PACKAGE_XZ_SHA256: &str =
    "4502f0fdac8151b874723acb771cc5dca9a33df9f12a40081947909058bb46dc";
const WINDOWS_NTDLL_IMPORT: &str =
    r"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64\ntdll.lib";

/* These are deliberately hard pins, not values learned from the current
checkout.  They are filled only after the complete linked source/toolchain
receipt has been reviewed and read back. */
const PINNED_LEAN_SOURCE_BINDING_SHA256: &str =
    "eae07e9685e736a962df125e96ec8d8a32338b2a89aa4dffd1b945bee0fb484b";
const PINNED_LEAN_OBJECTS_BINDING_SHA256: &str =
    "c885280105cd8e4c2bb5a8a117ab29518a68784ad283e851c90d66ee1fd545a7";
const PINNED_RUNTIME_LIBRARIES_BINDING_SHA256: &str =
    "2472568446e5a92dfdea0b0ba913e620898d859168aff557441176396cb4ca22";
const PINNED_LEAN_COMPILER_SHA256: &str =
    "af49bacfabaa1fea71332ca0feae0fa1a60912219d5902291adc79f905bffb8d";
const PINNED_NATIVE_COMPILER_SHA256: &str =
    "1aea18dca98f91a6a7c65532adc2567efc775904d2a4bd28bf06731bc2c3778c";
const PINNED_LLD_SHA256: &str = "675e59f33f11cb90500577f116082ed4a6214fcac3a1bad88d6323aa0373179f";
const PINNED_ARCHIVER_SHA256: &str =
    "ff7fcf456130e4fb58bc24f7cf0f2e7113ce96af534fc61f861c54a43e674a9d";
const PINNED_RUST_COMPILER_SHA256: &str =
    "acb138286bbe20c6cf3ec39a7e0a68c3fab0cd949baa2912cf466514d0d531ab";
const PINNED_RUST_LINKER_SHA256: &str =
    "1aea18dca98f91a6a7c65532adc2567efc775904d2a4bd28bf06731bc2c3778c";
const PINNED_RUST_TARGET_STD_MANIFEST_SHA256: &str =
    "3e18bbb8b5c6ad86b8faceefd9ac4fb934e857dd546b82216a084546f0ec1cbe";
const PINNED_RUST_TARGET_STD_BINDING_SHA256: &str =
    "7fc52762b8d5098e5283ffa754d30cb8fab4ff1027118ef1e8ae2f83d5ec094b";
const PINNED_WINDOWS_NTDLL_SHA256: &str =
    "a373f724ef6d8ea11a8b03de653ac1b4f111522f59a1f4b787ec9d93f31fe7c1";
const PINNED_NATIVE_BOUNDARY_OBJECT_SHA256: &str =
    "d1743448796ce4295ce5596407e3bad7ec5a5ae71ef071094f38856efcaaab82";
const PINNED_NATIVE_BUILD_CONFIG_SHA256: &str =
    "74049bdf6eeb1be100e3ac30077188af49f0c4eb539570406a583a26e7502180";
const PINNED_BUILD_RECEIPT_SHA256: &str =
    "255714610e0053d6611bde9f085bbd672562d576d10c4f94aadecfcfcc605b13";

const LEAN_SOURCE_FILES: &[&str] = &[
    "BlindLedger/ExactKernel.lean",
    "BlindLedger/Sha3.lean",
    "BlindLedger/SemanticExecutable.lean",
    "BlindLedger/SemanticCli.lean",
    "BlindLedger/Theorems.lean",
    "BlindLedger/Checkpoint.lean",
    "BlindLedger/AxiomCheck.lean",
    "lakefile.toml",
    "lean-toolchain",
    "lake-manifest.json",
];

const LEAN_OBJECT_FILES: &[&str] = &[
    "ExactKernel.c.o.noexport",
    "Sha3.c.o.noexport",
    "Theorems.c.o.noexport",
    "SemanticExecutable.c.o.noexport",
];

const RUNTIME_LIBRARY_FILES: &[&str] = &[
    "lib/lean/libleanmanifest.a",
    "lib/lean/libleancpp.a",
    "lib/lean/libLean.a",
    "lib/lean/libStd.a",
    "lib/lean/libInit.a",
    "lib/lean/libleanrt.a",
    "lib/lean/libLake.a",
    "lib/libgmp.a",
    "lib/libuv.a",
    "lib/libmingw32.a",
    "lib/libmingwex.a",
    "lib/libmoldname.a",
    "lib/libmsvcrt.a",
    "lib/libkernel32.a",
    "lib/libunwind.a",
    "lib/libc++.a",
    "lib/libc++abi.a",
    "lib/libpthread.a",
    "lib/libssl.a",
    "lib/libcrypto.a",
    "lib/libicu.a",
    "lib/libpsapi.a",
    "lib/libuser32.a",
    "lib/libadvapi32.a",
    "lib/libiphlpapi.a",
    "lib/libuserenv.a",
    "lib/libws2_32.a",
    "lib/libdbghelp.a",
    "lib/libole32.a",
    "lib/libshell32.a",
    "lib/libcrypt32.a",
    "lib/libgdi32.a",
    "lib/libbcrypt.a",
    "lib/libm.a",
    "lib/clang/22/lib/windows/libclang_rt.builtins-x86_64.a",
];

const NATIVE_BUILD_CONFIG_FILES: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    ".cargo/config.toml",
    "native_boundary.c",
];

fn fail(message: impl AsRef<str>) -> ! {
    panic!("blind-ledger native link: {}", message.as_ref());
}

fn regular_file(path: &Path) {
    let metadata = fs::symlink_metadata(path)
        .unwrap_or_else(|error| fail(format!("missing file {}: {error}", path.display())));
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        fail(format!(
            "file is not a regular non-symlink: {}",
            path.display()
        ));
    }
}

fn regular_directory(path: &Path) {
    let metadata = fs::symlink_metadata(path)
        .unwrap_or_else(|error| fail(format!("missing directory {}: {error}", path.display())));
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        fail(format!(
            "directory is not a regular non-symlink: {}",
            path.display()
        ));
    }
}

fn canonical_path(path: &Path) -> PathBuf {
    fs::canonicalize(path)
        .unwrap_or_else(|error| fail(format!("canonical path failed {}: {error}", path.display())))
}

fn path_key(path: &Path) -> String {
    canonical_path(path)
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase()
}

fn require_same_path(label: &str, actual: &Path, expected: &Path, directory: bool) {
    if directory {
        regular_directory(actual);
        regular_directory(expected);
    } else {
        regular_file(actual);
        regular_file(expected);
    }
    if path_key(actual) != path_key(expected) {
        fail(format!(
            "{label} is not the approved path: actual={} expected={}",
            actual.display(),
            expected.display()
        ));
    }
}

fn reject_nonempty_environment(name: &str) {
    if let Some(value) = env::var_os(name) {
        if !value.is_empty() {
            fail(format!("ambient {name} override is forbidden"));
        }
    }
}

fn validate_invocation_environment(expected_linker: &Path) {
    for name in [
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTC",
        "CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUSTFLAGS",
        "CC",
        "CXX",
        "AR",
        "AS",
        "LD",
        "CFLAGS",
        "CXXFLAGS",
        "LDFLAGS",
        "LIBRARY_PATH",
        "CPATH",
        "C_INCLUDE_PATH",
        "CPLUS_INCLUDE_PATH",
        "SDKROOT",
        "CL",
    ] {
        reject_nonempty_environment(name);
    }
    if let Some(value) = env::var_os("RUSTFLAGS") {
        if !value.is_empty() {
            fail("ambient RUSTFLAGS override is forbidden");
        }
    }
    if let Some(value) = env::var("CARGO_ENCODED_RUSTFLAGS").ok() {
        if !value.is_empty() && value != APPROVED_CARGO_ENCODED_RUSTFLAGS {
            fail(format!("unapproved CARGO_ENCODED_RUSTFLAGS: {value:?}"));
        }
    }
    for name in ["RUSTC_LINKER", "CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER"] {
        if let Some(value) = env::var_os(name) {
            let actual = PathBuf::from(value);
            if !actual.is_absolute() {
                fail(format!("{name} must be an absolute path"));
            }
            require_same_path(name, &actual, expected_linker, false);
        }
    }
}

fn hash_records(records: impl IntoIterator<Item = (String, PathBuf)>) -> String {
    let mut hasher = Sha256::new();
    for (role, path) in records {
        regular_file(&path);
        let bytes = fs::read(&path)
            .unwrap_or_else(|error| fail(format!("read failed for {}: {error}", path.display())));
        hasher.update(role.as_bytes());
        hasher.update([0u8]);
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    hex(&hasher.finalize())
}

fn hash_one(path: &Path) -> String {
    regular_file(path);
    let bytes = fs::read(path)
        .unwrap_or_else(|error| fail(format!("read failed for {}: {error}", path.display())));
    hex(&Sha256::digest(bytes))
}

fn rust_target_std_records(sysroot: &Path, manifest: &Path) -> Vec<(String, PathBuf)> {
    let manifest_text = fs::read_to_string(manifest)
        .unwrap_or_else(|error| fail(format!("Rust GNU target std manifest read failed: {error}")));
    let mut records = vec![(
        "rust-target-std/manifest".to_string(),
        manifest.to_path_buf(),
    )];
    for line in manifest_text.lines() {
        let relative = line
            .strip_prefix("file:")
            .unwrap_or_else(|| fail("Rust GNU target std manifest contains a non-file record"));
        if relative.is_empty()
            || relative.contains("..")
            || !relative.starts_with("lib/rustlib/x86_64-pc-windows-gnu/")
        {
            fail(format!(
                "Rust GNU target std manifest path is outside the pinned target: {relative}"
            ));
        }
        records.push((
            format!("rust-target-std/{relative}"),
            sysroot.join(relative),
        ));
    }
    if records.len() < 2 {
        fail("Rust GNU target std manifest contains no files");
    }
    records
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

fn assert_pin(name: &str, expected: &str, actual: &str) {
    if expected != actual {
        fail(format!("{name} is not pinned; actual={actual}"));
    }
}

fn run_checked(command: &Path, args: &[String], cwd: &Path) {
    let output = Command::new(command)
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|error| fail(format!("could not run {}: {error}", command.display())));
    if !output.status.success() {
        fail(format!(
            "{} exited {}; stdout={} stderr={}",
            command.display(),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
}

fn checked_stdout(command: &Path, args: &[&str], cwd: &Path) -> String {
    let output = Command::new(command)
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|error| fail(format!("could not run {}: {error}", command.display())));
    if !output.status.success() {
        fail(format!(
            "{} exited {}; stdout={} stderr={}",
            command.display(),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout)
        .unwrap_or_else(|error| {
            fail(format!(
                "{} emitted non-UTF-8 output: {error}",
                command.display()
            ))
        })
        .trim()
        .to_string()
}

fn checked_diagnostics(command: &Path, args: &[&str], cwd: &Path) -> String {
    let output = Command::new(command)
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|error| fail(format!("could not run {}: {error}", command.display())));
    if !output.status.success() {
        fail(format!(
            "{} exited {}; stdout={} stderr={}",
            command.display(),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let mut diagnostics = String::from_utf8_lossy(&output.stdout).into_owned();
    diagnostics.push_str(&String::from_utf8_lossy(&output.stderr));
    diagnostics
}

fn normalized_driver_path(path: &Path) -> String {
    let mut value = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    if let Some(stripped) = value.strip_suffix(".exe") {
        value = stripped.to_string();
    }
    value
}

fn resolve_toolchain() -> PathBuf {
    if let Some(value) = env::var_os("LEAN_TOOLCHAIN_ROOT") {
        return PathBuf::from(value);
    }
    let user_profile = env::var_os("USERPROFILE")
        .unwrap_or_else(|| fail("USERPROFILE or LEAN_TOOLCHAIN_ROOT is required"));
    PathBuf::from(user_profile)
        .join(".elan")
        .join("toolchains")
        .join("leanprover--lean4---v4.33.1")
}

fn main() {
    println!("cargo:rerun-if-changed=native_boundary.c");
    println!("cargo:rerun-if-changed=src/main.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=Cargo.lock");
    println!("cargo:rerun-if-changed=.cargo/config.toml");
    for file in LEAN_SOURCE_FILES {
        println!("cargo:rerun-if-changed=../../lean/engine/{file}");
    }

    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").unwrap_or_else(|| fail("CARGO_MANIFEST_DIR is missing")),
    );
    let lean_root = manifest_dir.join("..").join("..").join("lean").join("engine");
    let target = env::var("TARGET").unwrap_or_else(|_| fail("TARGET is missing"));
    if target != RUST_TARGET {
        fail(format!("unexpected Rust target: {target}"));
    }
    let toolchain_root = resolve_toolchain();
    let lean = toolchain_root.join("bin").join("lean.exe");
    let lake = toolchain_root.join("bin").join("lake.exe");
    let clang = toolchain_root.join("bin").join("clang.exe");
    let llvm_ar = toolchain_root.join("bin").join("llvm-ar.exe");
    for path in [&lean, &lake, &clang, &llvm_ar] {
        regular_file(path);
    }
    validate_invocation_environment(&clang);

    let toolchain_file = lean_root.join("lean-toolchain");
    let toolchain_bytes = fs::read(&toolchain_file)
        .unwrap_or_else(|error| fail(format!("toolchain read failed: {error}")));
    if toolchain_bytes != EXPECTED_LEAN_TOOLCHAIN.as_bytes() {
        fail("lean-toolchain does not match leanprover/lean4:v4.33.1");
    }

    let source_binding = hash_records(
        LEAN_SOURCE_FILES
            .iter()
            .map(|relative| ((*relative).to_string(), lean_root.join(relative))),
    );
    assert_pin(
        "lean source binding",
        PINNED_LEAN_SOURCE_BINDING_SHA256,
        &source_binding,
    );

    let native_build_config_binding =
        hash_records(NATIVE_BUILD_CONFIG_FILES.iter().map(|relative| {
            (
                format!("native-build-config/{relative}"),
                manifest_dir.join(relative),
            )
        }));
    assert_pin(
        "native build configuration binding",
        PINNED_NATIVE_BUILD_CONFIG_SHA256,
        &native_build_config_binding,
    );

    run_checked(
        &lake,
        &[
            "-d".to_string(),
            lean_root.display().to_string(),
            "build".to_string(),
            "blind_semantic_kernel".to_string(),
            "BlindLedger.Checkpoint".to_string(),
        ],
        &manifest_dir,
    );

    let generated_root = lean_root
        .join(".lake")
        .join("build")
        .join("ir")
        .join("BlindLedger");
    let semantic_c = generated_root.join("SemanticExecutable.c");
    let semantic_c_text = fs::read_to_string(&semantic_c).unwrap_or_else(|error| {
        fail(format!(
            "generated SemanticExecutable.c read failed: {error}"
        ))
    });
    if !semantic_c_text.contains("blind_ledger_run_bytes")
        || !semantic_c_text
            .contains("initialize_blind__ledger__semantic__kernel_BlindLedger_SemanticExecutable")
        || semantic_c_text.contains("\nint main(")
    {
        fail("linked semantic module is missing the explicit export or contains an OS main");
    }

    let objects_binding = hash_records(LEAN_OBJECT_FILES.iter().map(|file| {
        (
            format!("lean-object/BlindLedger/{file}"),
            generated_root.join(file),
        )
    }));
    assert_pin(
        "lean object binding",
        PINNED_LEAN_OBJECTS_BINDING_SHA256,
        &objects_binding,
    );

    let runtime_binding = hash_records(RUNTIME_LIBRARY_FILES.iter().map(|relative| {
        (
            format!("lean-runtime/{relative}"),
            toolchain_root.join(relative),
        )
    }));
    assert_pin(
        "runtime library binding",
        PINNED_RUNTIME_LIBRARIES_BINDING_SHA256,
        &runtime_binding,
    );
    let compiler_binding = hash_one(&lean);
    assert_pin(
        "Lean compiler binding",
        PINNED_LEAN_COMPILER_SHA256,
        &compiler_binding,
    );
    let native_compiler_binding = hash_one(&clang);
    assert_pin(
        "native compiler binding",
        PINNED_NATIVE_COMPILER_SHA256,
        &native_compiler_binding,
    );
    let lld = toolchain_root.join("bin").join("ld.lld.exe");
    regular_file(&lld);
    let lld_binding = hash_one(&lld);
    assert_pin("selected lld binding", PINNED_LLD_SHA256, &lld_binding);
    let linker_probe = checked_diagnostics(
        &clang,
        &[
            "--target=x86_64-w64-windows-gnu",
            "-fuse-ld=lld",
            "-nostdlib",
            "-###",
            "-o",
            "NUL",
            "-x",
            "c",
            "NUL",
        ],
        &manifest_dir,
    );
    let selected_lld = normalized_driver_path(&lld);
    if !linker_probe
        .to_ascii_lowercase()
        .replace('\\', "/")
        .contains(&format!("\"{selected_lld}\""))
    {
        fail(format!(
            "pinned clang did not select the approved lld: expected={selected_lld} diagnostics={linker_probe}"
        ));
    }
    let archiver_binding = hash_one(&llvm_ar);
    assert_pin(
        "archiver binding",
        PINNED_ARCHIVER_SHA256,
        &archiver_binding,
    );
    let user_profile = env::var_os("USERPROFILE")
        .unwrap_or_else(|| fail("USERPROFILE is required for the pinned Rust toolchain"));
    let approved_rust_sysroot = PathBuf::from(user_profile)
        .join(".rustup")
        .join("toolchains")
        .join(RUST_HOST_TOOLCHAIN);
    let approved_rustc = approved_rust_sysroot.join("bin").join("rustc.exe");
    let rustc_command = PathBuf::from(
        env::var_os("RUSTC").unwrap_or_else(|| fail("RUSTC must name the approved rustc")),
    );
    if !rustc_command.is_absolute() {
        fail(format!(
            "RUSTC must be an absolute path: {}",
            rustc_command.display()
        ));
    }
    require_same_path(
        "executed Rust compiler",
        &rustc_command,
        &approved_rustc,
        false,
    );
    let rust_sysroot = PathBuf::from(checked_stdout(
        &rustc_command,
        &["--print", "sysroot"],
        &manifest_dir,
    ));
    require_same_path(
        "executed Rust sysroot",
        &rust_sysroot,
        &approved_rust_sysroot,
        true,
    );
    let rustc = rustc_command.clone();
    let rust_linker = toolchain_root.join("bin").join("clang.exe");
    let rust_target_std_manifest = rust_sysroot.join(RUST_TARGET_STD_MANIFEST);
    regular_file(&rustc);
    regular_file(&rust_linker);
    regular_file(&rust_target_std_manifest);
    let rustc_binding = hash_one(&rustc);
    assert_pin(
        "Rust compiler binding",
        PINNED_RUST_COMPILER_SHA256,
        &rustc_binding,
    );
    let rust_linker_binding = hash_one(&rust_linker);
    assert_pin(
        "Rust linker binding",
        PINNED_RUST_LINKER_SHA256,
        &rust_linker_binding,
    );
    let rust_target_std_manifest_binding = hash_one(&rust_target_std_manifest);
    assert_pin(
        "Rust GNU target std manifest binding",
        PINNED_RUST_TARGET_STD_MANIFEST_SHA256,
        &rust_target_std_manifest_binding,
    );
    let rust_target_std_binding = hash_records(rust_target_std_records(
        &rust_sysroot,
        &rust_target_std_manifest,
    ));
    assert_pin(
        "Rust GNU target std binding",
        PINNED_RUST_TARGET_STD_BINDING_SHA256,
        &rust_target_std_binding,
    );
    let windows_ntdll_import = PathBuf::from(WINDOWS_NTDLL_IMPORT);
    let windows_ntdll_binding = hash_one(&windows_ntdll_import);
    assert_pin(
        "Windows ntdll import binding",
        PINNED_WINDOWS_NTDLL_SHA256,
        &windows_ntdll_binding,
    );
    let compiler_rt = toolchain_root
        .join("lib")
        .join("clang")
        .join("22")
        .join("lib")
        .join("windows")
        .join("libclang_rt.builtins-x86_64.a");
    regular_file(&compiler_rt);
    println!("cargo:rerun-if-changed={}", windows_ntdll_import.display());
    println!("cargo:rerun-if-changed={}", compiler_rt.display());

    let output_dir =
        PathBuf::from(env::var_os("OUT_DIR").unwrap_or_else(|| fail("OUT_DIR is missing")));
    fs::create_dir_all(&output_dir)
        .unwrap_or_else(|error| fail(format!("create OUT_DIR failed: {error}")));
    /* Rust's GNU target asks clang for libntdll/libgcc/libgcc_eh by name.
    The approved Windows SDK import archive and Lean compiler-rt archive
    are copied into the build output under those exact GNU names, so the
    direct pinned clang linker receives the complete long argument vector
    without a command-shell filter or an alternate toolchain. */
    for (alias, source) in [
        ("libntdll.a", windows_ntdll_import.as_path()),
        ("libgcc.a", compiler_rt.as_path()),
        ("libgcc_eh.a", compiler_rt.as_path()),
    ] {
        let destination = output_dir.join(alias);
        fs::copy(source, &destination).unwrap_or_else(|error| {
            fail(format!(
                "linker alias copy failed {} -> {}: {error}",
                source.display(),
                destination.display()
            ))
        });
        if hash_one(&destination) != hash_one(source) {
            fail(format!(
                "linker alias copy verification failed: {}",
                destination.display()
            ));
        }
    }
    println!("cargo:rustc-link-search=native={}", output_dir.display());
    let native_object = output_dir.join("native_boundary.o");
    let include_root = toolchain_root.join("include");
    let clang_include = include_root.join("clang");
    run_checked(
        &clang,
        &[
            "-c".to_string(),
            "-o".to_string(),
            native_object.display().to_string(),
            manifest_dir.join("native_boundary.c").display().to_string(),
            "-I".to_string(),
            include_root.display().to_string(),
            "--target=x86_64-w64-windows-gnu".to_string(),
            "-fstack-clash-protection".to_string(),
            "-ffp-contract=off".to_string(),
            "-fdata-sections".to_string(),
            "-ffunction-sections".to_string(),
            "-Wno-unused-command-line-argument".to_string(),
            "--sysroot".to_string(),
            toolchain_root.display().to_string(),
            "-nostdinc".to_string(),
            "-isystem".to_string(),
            clang_include.display().to_string(),
            "-O3".to_string(),
            "-DNDEBUG".to_string(),
        ],
        &manifest_dir,
    );
    let native_object_binding = hash_one(&native_object);
    assert_pin(
        "native boundary object binding",
        PINNED_NATIVE_BOUNDARY_OBJECT_SHA256,
        &native_object_binding,
    );

    let mut receipt_hasher = Sha256::new();
    receipt_hasher.update(b"BL/SEMANTIC-KERNEL/NATIVE-LINK-RECEIPT/v1\0");
    for (role, value) in [
        ("source", source_binding.as_str()),
        ("toolchain", EXPECTED_LEAN_TOOLCHAIN),
        ("compiler", compiler_binding.as_str()),
        ("native-compiler", native_compiler_binding.as_str()),
        ("lld", lld_binding.as_str()),
        ("archiver", archiver_binding.as_str()),
        ("objects", objects_binding.as_str()),
        ("runtime", runtime_binding.as_str()),
        ("native-boundary", native_object_binding.as_str()),
        ("native-build-config", native_build_config_binding.as_str()),
        ("rustc", rustc_binding.as_str()),
        ("rust-linker", rust_linker_binding.as_str()),
        (
            "rust-target-std-manifest",
            rust_target_std_manifest_binding.as_str(),
        ),
        ("rust-target-std", rust_target_std_binding.as_str()),
        ("windows-ntdll-import", windows_ntdll_binding.as_str()),
        (
            "linker",
            "clang-gnu;ld.lld;compiler-rt;explicit-compiler-rt;msvcrt;link-self-contained=no;wholearchive-manifest;aliased-libgcc;lean-llvm-unwind;windows-ntdll-import",
        ),
        ("rust-host-toolchain", RUST_HOST_TOOLCHAIN),
        ("rust-target", RUST_TARGET),
        (
            "rust-target-std-package-xz",
            RUST_TARGET_STD_PACKAGE_XZ_SHA256,
        ),
        ("cflags", "clang-22.1.4;-O3;-DNDEBUG;-ffp-contract=off"),
    ] {
        receipt_hasher.update(role.as_bytes());
        receipt_hasher.update([0u8]);
        receipt_hasher.update(value.as_bytes());
        receipt_hasher.update([0u8]);
    }
    let build_receipt = hex(&receipt_hasher.finalize());
    assert_pin(
        "native link build receipt",
        PINNED_BUILD_RECEIPT_SHA256,
        &build_receipt,
    );

    let generated_manifest = format!(
        "pub const LEAN_SOURCE_BINDING_SHA256: &str = \"{source_binding}\";\n\
         pub const LEAN_OBJECTS_BINDING_SHA256: &str = \"{objects_binding}\";\n\
         pub const RUNTIME_LIBRARIES_BINDING_SHA256: &str = \"{runtime_binding}\";\n\
         pub const LEAN_COMPILER_SHA256: &str = \"{compiler_binding}\";\n\
         pub const NATIVE_BOUNDARY_OBJECT_SHA256: &str = \"{native_object_binding}\";\n\
         pub const NATIVE_BUILD_CONFIG_SHA256: &str = \"{native_build_config_binding}\";\n\
        pub const RUST_COMPILER_SHA256: &str = \"{rustc_binding}\";\n\
        pub const RUST_LINKER_SHA256: &str = \"{rust_linker_binding}\";\n\
         pub const RUST_TARGET_STD_MANIFEST_SHA256: &str = \"{rust_target_std_manifest_binding}\";\n\
         pub const RUST_TARGET_STD_BINDING_SHA256: &str = \"{rust_target_std_binding}\";\n\
         pub const WINDOWS_NTDLL_SHA256: &str = \"{windows_ntdll_binding}\";\n\
         pub const BUILD_RECEIPT_SHA256: &str = \"{build_receipt}\";\n\
         pub const STATIC_LINKAGE: bool = true;\n"
    );
    let generated_manifest =
        format!("{generated_manifest}pub const LLD_SHA256: &str = \"{lld_binding}\";\n");
    let generated_manifest = format!(
        "{generated_manifest}pub const NATIVE_COMPILER_SHA256: &str = \"{native_compiler_binding}\";\n"
    );
    let generated_manifest =
        format!("{generated_manifest}pub const ARCHIVER_SHA256: &str = \"{archiver_binding}\";\n");
    let generated_manifest = format!(
        "{generated_manifest}pub const LEAN_TOOLCHAIN: &str = \"leanprover/lean4:v4.33.1\\n\";\n"
    );
    fs::write(output_dir.join("link_receipt.rs"), generated_manifest)
        .unwrap_or_else(|error| fail(format!("write link receipt failed: {error}")));

    for file in LEAN_OBJECT_FILES {
        println!(
            "cargo:rustc-link-arg={}",
            generated_root.join(file).display()
        );
    }
    println!("cargo:rustc-link-arg={}", native_object.display());

    let lean_runtime = toolchain_root.join("lib").join("lean");
    let support_runtime = toolchain_root.join("lib");
    let archive = |directory: &Path, name: &str| {
        let path = directory.join(format!("lib{name}.a"));
        regular_file(&path);
        path
    };

    /* Keep the Lean linker order explicit.  In particular, the manifest is
    whole-archived so every generated module initializer is retained. */
    let manifest_archive = archive(&lean_runtime, "leanmanifest");
    println!("cargo:rustc-link-arg=-Wl,--whole-archive");
    println!("cargo:rustc-link-arg={}", manifest_archive.display());
    println!("cargo:rustc-link-arg=-Wl,--no-whole-archive");
    println!("cargo:rustc-link-arg=-Wl,--no-insert-timestamp");
    for name in [
        "gmp", "uv", "psapi", "user32", "advapi32", "iphlpapi", "userenv", "ws2_32", "dbghelp",
        "ole32", "shell32", "ssl", "crypto", "unwind",
    ] {
        println!(
            "cargo:rustc-link-arg={}",
            archive(&support_runtime, name).display()
        );
    }
    for name in ["crypt32", "gdi32"] {
        println!(
            "cargo:rustc-link-arg={}",
            archive(&support_runtime, name).display()
        );
    }
    for name in ["leancpp", "Lean"] {
        println!(
            "cargo:rustc-link-arg={}",
            archive(&lean_runtime, name).display()
        );
    }
    println!(
        "cargo:rustc-link-arg={}",
        archive(&lean_runtime, "Std").display()
    );
    for name in ["Init", "leanrt"] {
        println!(
            "cargo:rustc-link-arg={}",
            archive(&lean_runtime, name).display()
        );
    }
    for name in [
        "c++", "c++abi", "Lake", "gmp", "uv", "psapi", "user32", "advapi32",
    ] {
        println!(
            "cargo:rustc-link-arg={}",
            archive(
                if name == "Lake" {
                    &lean_runtime
                } else {
                    &support_runtime
                },
                name,
            )
            .display()
        );
    }
    for name in [
        "iphlpapi", "userenv", "ws2_32", "dbghelp", "ole32", "shell32", "ssl", "crypto", "crypt32",
        "gdi32", "icu", "m", "bcrypt", "pthread",
    ] {
        println!(
            "cargo:rustc-link-arg={}",
            archive(&support_runtime, name).display()
        );
    }
    println!("cargo:rustc-link-arg={}", compiler_rt.display());
    println!("cargo:rustc-link-arg=-Wl,--stack,104857600");
    println!("cargo:rustc-link-arg=-Wl,--gc-sections");
}
