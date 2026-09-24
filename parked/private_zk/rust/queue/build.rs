use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use sha2::{Digest, Sha256};

const LEAN_TOOLCHAIN: &str = r"C:\Users\neers\.elan\toolchains\leanprover--lean4---v4.33.1";
const PINNED_CARGO: &str = r"C:\Users\neers\.rustup\toolchains\1.96.0-x86_64-pc-windows-msvc\bin\cargo.exe";
const PINNED_CARGO_SHA256: &str = "122f18d28a63fa358f3db266abee1ff1d8aabf0ab7f2dd9ac38a38da99977ae5";
const PINNED_RUSTC: &str = r"C:\Users\neers\.rustup\toolchains\1.96.0-x86_64-pc-windows-msvc\bin\rustc.exe";
const PINNED_RUSTC_SHA256: &str = "acb138286bbe20c6cf3ec39a7e0a68c3fab0cd949baa2912cf466514d0d531ab";
const PINNED_GNU_MANIFEST: &str = r"C:\Users\neers\.rustup\toolchains\1.96.0-x86_64-pc-windows-msvc\lib\rustlib\manifest-rust-std-x86_64-pc-windows-gnu";
const PINNED_GNU_MANIFEST_SHA256: &str = "3e18bbb8b5c6ad86b8faceefd9ac4fb934e857dd546b82216a084546f0ec1cbe";
const PINNED_GNU_TARGET_BINDING_SHA256: &str = "7fc52762b8d5098e5283ffa754d30cb8fab4ff1027118ef1e8ae2f83d5ec094b";
const NTDLL: &str = r"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64\ntdll.lib";
const NTDLL_SHA256: &str = "a373f724ef6d8ea11a8b03de653ac1b4f111522f59a1f4b787ec9d93f31fe7c1";
const COMPILER_RT: &str = r"C:\Users\neers\.elan\toolchains\leanprover--lean4---v4.33.1\lib\clang\22\lib\windows\libclang_rt.builtins-x86_64.a";
const COMPILER_RT_SHA256: &str = "d7a2dd43582efe0b0cccd8c2f6cbabc85220c716573e2daffe212adaf40eefa6";
const PINNED_LEAN_SHA256: &str = "af49bacfabaa1fea71332ca0feae0fa1a60912219d5902291adc79f905bffb8d";
const PINNED_LAKE_SHA256: &str = "565c3976275d79e104421014b6229f4fcf4a8c8edfe164a43b344c91af6f496c";
const PINNED_LEAN_CLANG_SHA256: &str = "1aea18dca98f91a6a7c65532adc2567efc775904d2a4bd28bf06731bc2c3778c";
const PINNED_LEAN_LD_LLD_SHA256: &str = "675e59f33f11cb90500577f116082ed4a6214fcac3a1bad88d6323aa0373179f";
const PINNED_LLVM_AR_SHA256: &str = "ff7fcf456130e4fb58bc24f7cf0f2e7113ce96af534fc61f861c54a43e674a9d";
const PINNED_LEAN_OLEAN_TREE_SHA256: &str = "a76983027716a67e972e8e7d5c87d8d95c0ceb888a20f453d987843620a7354a";
const NATIVE_BOUNDARY_SHA256: &str = "0d7a7c78592c06c71f78fbbf550b5a2f10b2621746e5d4fcaba728d40abe0dd7";
const NATIVE_BOUNDARY_OBJECT_SHA256: &str = "9dcb694734e06f70dbc43aa184635ee0773057bc5a1be6a71a23e11a539548f8";
const LIBRARY_OBJECT_SHA256: &str = "9c6a72b3786abf4a634acc91505a722f82390a3688806398974c682dad89e479";
const MODEL_OBJECT_SHA256: &str = "60381d980e3c480a77b6605540e6c41b1eb72115db6f799331a7b4ab21bf39c8";
const SHA3_OBJECT_SHA256: &str = "4235c16065f03e69746217a30e5521ec8e3d815b54f93afcdb20ae8235577e3b";
const LINKED_ARCHIVE_SHA256: &str = "86cedcae0f9758b75c7a4a4d3de5ca9c28b05b628e08b1868b26ca74584ca13c";
const LEAN_CLANG: &str = r"C:\Users\neers\.elan\toolchains\leanprover--lean4---v4.33.1\bin\clang.exe";
const LEAN_LD_LLD: &str = r"C:\Users\neers\.elan\toolchains\leanprover--lean4---v4.33.1\bin\ld.lld.exe";
const LLVM_AR: &str = r"C:\Users\neers\.elan\toolchains\leanprover--lean4---v4.33.1\bin\llvm-ar.exe";
const LEAN_SOURCE_PINS: &[(&str, &str)] = &[
    ("Admission/Checker.lean", "7be017396c75984cdaf3177df27f34ea9664a1c059e7751d06047e6a19d77c8a"),
    ("Admission/Library.lean", "3a041219993a066a6b497732cbc29b4675e3fa8be6c3d0272c743e27e2869a04"),
    ("Admission/Lifecycle.lean", "531b42f971e7b76664edc88be79cc8812c3cbbf8d6beac04bc4f5702b44bf7f3"),
    ("Admission/LifecycleKernel.lean", "5b6d0b4c7109946f8a26c2ede19fc2b25447e373b50cf863bdcd04ec6488d8ac"),
    ("Admission/Main.lean", "f602eb8cd1bef8b00d80c67234f4c2e13909c3541e96d8491bedef2d00fdc8cf"),
    ("Admission/Model.lean", "62fd21803f0a6e336a0811611b7aa99ffd74e8f087a99b6fc645aa39833dc963"),
    ("BlindLedger/Sha3.lean", "820b2f95ca76690365d41abf893f77490100dfd0a54b2a84c6725cf77308719f"),
    ("lake-manifest.json", "ddd12b00929934da48bff83b9e21ac6db8034d5bfa91055b7071d3f4ef01fb4b"),
    ("lakefile.toml", "5d95d91abf55aee5ff79c211e2561338f52c54dd2e65f88b30d026454811f3cb"),
    ("lean-toolchain", "3aac669c7a910ec2389f4e4f921b605adf6ebf2d1e0c9b9cd0be4d33f3f5db71"),
];
const RUST_BUILD_INPUT_PINS: &[(&str, &str)] = &[
    (".cargo/config.toml", "385d15c7142267a1fdee1cda6ab13d41966b2e9557084828922f4a4ee3644e81"),
    ("Cargo.lock", "71a0c3f6903563c64a5c6a2c86433b32d448ebcf05c61acd9b126f5be28b9f45"),
    ("Cargo.toml", "f2482b21d1cffce02766460333af4fe0e3cbeea20d4be04c523868e6cafbe9d5"),
    ("native_boundary.c", "0d7a7c78592c06c71f78fbbf550b5a2f10b2621746e5d4fcaba728d40abe0dd7"),
    ("post_link_attest.py", "539b13ee96b900e91d85c540a1c7ccfa99a0b4895866788f4da73eb4b8afe545"),
    ("src/bin/lifecycle.rs", "5ff0f8189ac6ce826e1b4e526574da9b5be93dd9f55ca9e583067623f729a347"),
];
const LEAN_TOOL_PINS: &[(&str, &str)] = &[
    ("bin/clang.exe", PINNED_LEAN_CLANG_SHA256),
    ("bin/ld.lld.exe", PINNED_LEAN_LD_LLD_SHA256),
    ("bin/lake.exe", PINNED_LAKE_SHA256),
    ("bin/lean.exe", PINNED_LEAN_SHA256),
    ("bin/llvm-ar.exe", PINNED_LLVM_AR_SHA256),
];

const LIFECYCLE_MANIFEST_SYMBOL: &str = "blind_ledger_lifecycle_source_manifest";
const LIFECYCLE_SUPPORT_ARCHIVES_FIRST: &[&str] = &[
    "libgmp.a", "libuv.a", "libpsapi.a", "libuser32.a", "libadvapi32.a", "libiphlpapi.a",
    "libuserenv.a", "libws2_32.a", "libdbghelp.a", "libole32.a", "libshell32.a", "libssl.a",
    "libcrypto.a", "libunwind.a", "libcrypt32.a", "libgdi32.a",
];
const LIFECYCLE_LEAN_ARCHIVES: &[&str] = &[
    "libleancpp.a", "libLean.a", "libStd.a", "libInit.a", "libleanrt.a",
];
const LIFECYCLE_SUPPORT_ARCHIVES_MIDDLE: &[&str] = &["libc++.a", "libc++abi.a"];
const LIFECYCLE_SUPPORT_ARCHIVES_LAST: &[&str] = &[
    "libgmp.a", "libuv.a", "libpsapi.a", "libuser32.a", "libadvapi32.a", "libiphlpapi.a",
    "libuserenv.a", "libws2_32.a", "libdbghelp.a", "libole32.a", "libshell32.a", "libssl.a",
    "libcrypto.a", "libcrypt32.a", "libgdi32.a", "libicu.a", "libm.a", "libbcrypt.a",
    "libpthread.a",
];

#[derive(Clone)]
struct IdentityRecord {
    path: String,
    count: u64,
    length: u64,
    sha256: String,
}

fn sha256_hex(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }

fn verified_file(path: &Path, expected: &str) -> Vec<u8> {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    assert_eq!(sha256_hex(&bytes), expected, "identity mismatch for {}", path.display());
    bytes
}

fn regular_file_bytes(path: &Path) -> Vec<u8> {
    let metadata = fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("metadata {}: {error}", path.display()));
    assert!(metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "input is not a regular file: {}", path.display());
    fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn verified_regular_file(path: &Path, expected: &str) -> Vec<u8> {
    let bytes = regular_file_bytes(path);
    assert_eq!(sha256_hex(&bytes), expected, "identity mismatch for {}", path.display());
    bytes
}

fn identity_record(path: String, bytes: &[u8]) -> IdentityRecord {
    IdentityRecord {
        path,
        count: 1,
        length: bytes.len() as u64,
        sha256: sha256_hex(bytes),
    }
}

fn identity_record_from_path(path: String, source: &Path) -> IdentityRecord {
    let metadata = fs::symlink_metadata(source)
        .unwrap_or_else(|error| panic!("metadata {}: {error}", source.display()));
    assert!(metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "input is not a regular file: {}", source.display());
    let mut file = fs::File::open(source)
        .unwrap_or_else(|error| panic!("open {}: {error}", source.display()));
    let mut hasher = Sha256::new();
    let mut length = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)
            .unwrap_or_else(|error| panic!("read {}: {error}", source.display()));
        if read == 0 { break; }
        length = length.checked_add(read as u64).expect("input length overflow");
        hasher.update(&buffer[..read]);
    }
    IdentityRecord {
        path,
        count: 1,
        length,
        sha256: format!("{:x}", hasher.finalize()),
    }
}

fn text_identity_record(path: &str, value: &str) -> IdentityRecord {
    identity_record(path.to_string(), value.as_bytes())
}

fn collect_olean_records(root: &Path, directory: &Path, records: &mut Vec<IdentityRecord>) {
    let metadata = fs::symlink_metadata(directory)
        .unwrap_or_else(|error| panic!("metadata {}: {error}", directory.display()));
    assert!(metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "Lean import directory is not a regular directory: {}", directory.display());
    for entry in fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("read directory {}: {error}", directory.display()))
    {
        let entry = entry.unwrap_or_else(|error| panic!("read directory entry: {error}"));
        let path = entry.path();
        let kind = entry.file_type().unwrap_or_else(|error| panic!("file type {}: {error}", path.display()));
        assert!(!kind.is_symlink(), "symlink in Lean import tree: {}", path.display());
        if kind.is_dir() {
            collect_olean_records(root, &path, records);
        } else if kind.is_file() && path.extension().and_then(|value| value.to_str()) == Some("olean") {
            let relative = path.strip_prefix(root).expect("Lean import path containment");
            let relative = relative.to_str().expect("Lean import path UTF-8").replace('\\', "/");
            assert!(relative.is_ascii() && !relative.starts_with('/') && !relative.contains("../"),
                "non-canonical Lean import path: {relative}");
            records.push(identity_record(relative, &regular_file_bytes(&path)));
        }
    }
}

fn lean_olean_tree_identity(root: &Path) -> (u64, u64, String) {
    let mut records = Vec::new();
    collect_olean_records(root, root, &mut records);
    records.sort_by(|left, right| left.path.cmp(&right.path));
    assert!(!records.is_empty(), "Lean import tree contains no .olean files");
    let mut length = 0u64;
    let mut manifest = String::from("lean-olean-tree-v1\n");
    for record in &records {
        length = length.checked_add(record.length).expect("Lean import byte count overflow");
        manifest.push_str(&format!("{}\t{}\t{}\n", record.path, record.length, record.sha256));
    }
    (records.len() as u64, length, sha256_hex(manifest.as_bytes()))
}

fn render_source_manifest(records: &mut [IdentityRecord]) -> Vec<u8> {
    records.sort_by(|left, right| left.path.cmp(&right.path));
    assert!(records.windows(2).all(|pair| pair[0].path != pair[1].path),
        "duplicate lifecycle source manifest path");
    assert!(records.iter().all(|record| record.count > 0 && record.length > 0),
        "empty lifecycle source manifest record");
    let mut manifest = String::from("blind-ledger-lifecycle-source-manifest-v2\n");
    for record in records {
        manifest.push_str(&format!("{}\t{}\t{}\t{}\n",
            record.path, record.count, record.length, record.sha256));
    }
    manifest.into_bytes()
}

fn canonical_output_dir(path: &Path) -> PathBuf {
    let metadata = fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("metadata Cargo OUT_DIR {}: {error}", path.display()));
    assert!(metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "Cargo OUT_DIR is not a regular directory: {}", path.display());
    fs::canonicalize(path).unwrap_or_else(|error| panic!("canonicalize Cargo OUT_DIR {}: {error}", path.display()))
}

fn remove_generated_file(out_dir: &Path, name: &str) {
    let path = out_dir.join(name);
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            assert!(metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
                "generated path is not a regular file: {}", path.display());
            let canonical = fs::canonicalize(&path)
                .unwrap_or_else(|error| panic!("canonicalize generated file {}: {error}", path.display()));
            assert!(canonical.starts_with(out_dir), "generated path escaped Cargo OUT_DIR: {}", path.display());
            fs::remove_file(&path).unwrap_or_else(|error| panic!("remove generated file {}: {error}", path.display()));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("metadata generated file {}: {error}", path.display()),
    }
}

fn fresh_generated_dir(out_dir: &Path, name: &str) -> PathBuf {
    let path = out_dir.join(name);
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            assert!(metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
                "generated directory is not a regular directory: {}", path.display());
            let canonical = fs::canonicalize(&path)
                .unwrap_or_else(|error| panic!("canonicalize generated directory {}: {error}", path.display()));
            assert!(canonical.starts_with(out_dir), "generated directory escaped Cargo OUT_DIR: {}", path.display());
            fs::remove_dir_all(&path)
                .unwrap_or_else(|error| panic!("remove generated directory {}: {error}", path.display()));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("metadata generated directory {}: {error}", path.display()),
    }
    fs::create_dir(&path).unwrap_or_else(|error| panic!("create generated directory {}: {error}", path.display()));
    path
}

fn hash_records(records: impl IntoIterator<Item = (String, PathBuf)>) -> String {
    let mut hasher = Sha256::new();
    for (role, path) in records {
        let bytes = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        hasher.update(role.as_bytes());
        hasher.update([0]);
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    format!("{:x}", hasher.finalize())
}

fn rust_target_std_records(sysroot: &Path, manifest: &Path) -> Vec<(String, PathBuf)> {
    let manifest_text = fs::read_to_string(manifest).expect("GNU target manifest UTF-8");
    let mut records = vec![("rust-target-std/manifest".to_string(), manifest.to_path_buf())];
    for line in manifest_text.lines() {
        let relative = line.strip_prefix("file:").expect("GNU target manifest file record");
        assert!(relative.starts_with("lib/rustlib/x86_64-pc-windows-gnu/"), "GNU target manifest path outside pinned target");
        records.push((format!("rust-target-std/{relative}"), sysroot.join(relative)));
    }
    assert!(records.len() > 1, "GNU target manifest contains no files");
    records
}

fn verify_pinned_rust() -> Vec<IdentityRecord> {
    let cargo = PathBuf::from(env::var_os("CARGO").expect("CARGO must pin the build driver"));
    let expected_cargo = Path::new(PINNED_CARGO);
    assert_eq!(fs::canonicalize(&cargo).expect("canonical CARGO"),
        fs::canonicalize(expected_cargo).expect("canonical pinned CARGO"),
        "unsupported Cargo build driver");
    let cargo_bytes = verified_file(expected_cargo, PINNED_CARGO_SHA256);

    let rustc = PathBuf::from(env::var_os("RUSTC").expect("RUSTC must pin the host compiler"));
    let expected = Path::new(PINNED_RUSTC);
    assert_eq!(fs::canonicalize(&rustc).expect("canonical RUSTC"), fs::canonicalize(expected).expect("canonical pinned RUSTC"), "unsupported host compiler");
    let rustc_bytes = verified_file(expected, PINNED_RUSTC_SHA256);
    let manifest = Path::new(PINNED_GNU_MANIFEST);
    let manifest_bytes = verified_file(manifest, PINNED_GNU_MANIFEST_SHA256);
    let sysroot = expected.parent().unwrap().parent().unwrap();
    let target_std = rust_target_std_records(sysroot, manifest);
    let binding = hash_records(target_std.iter().cloned());
    assert_eq!(binding, PINNED_GNU_TARGET_BINDING_SHA256, "GNU target binding mismatch");
    let mut records = vec![
        identity_record("rust-toolchain/cargo.exe".to_string(), &cargo_bytes),
        identity_record("toolchain/rustc.exe".to_string(), &rustc_bytes),
        identity_record("toolchain/rust-std-manifest-x86_64-pc-windows-gnu".to_string(), &manifest_bytes),
        text_identity_record("toolchain/gnu-target-binding", &binding),
    ];
    for (role, path) in target_std {
        records.push(identity_record_from_path(role, &path));
    }
    records
}

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|error| panic!("required Cargo build setting {name}: {error}"))
}

fn verify_effective_cargo_settings() -> Vec<IdentityRecord> {
    let target = required_env("TARGET");
    let host = required_env("HOST");
    let profile = required_env("PROFILE");
    let opt_level = required_env("OPT_LEVEL");
    let debug = required_env("DEBUG");
    assert_eq!(target, "x86_64-pc-windows-gnu", "unsupported Cargo target");
    assert_eq!(host, "x86_64-pc-windows-msvc", "unsupported Cargo host");
    assert_eq!(profile, "release", "Lifecycle adapter must use the reviewed release profile");
    assert_eq!(opt_level, "3", "unsupported Cargo optimization level");
    assert_eq!(debug, "false", "debug information is not reviewed for this target");

    let encoded_rustflags = required_env("CARGO_ENCODED_RUSTFLAGS");
    let expected_rustflags = ["-C", "link-self-contained=no", "-C", "panic=abort"].join("\u{1f}");
    assert_eq!(encoded_rustflags, expected_rustflags, "unreviewed effective Rust flags");
    assert!(env::var_os("RUSTFLAGS").is_none(), "RUSTFLAGS override is not reviewed");

    let linker = PathBuf::from(required_env("RUSTC_LINKER"));
    let pinned_linker = Path::new(LEAN_CLANG);
    let canonical_linker = fs::canonicalize(&linker).expect("canonical effective linker");
    let canonical_pinned_linker = fs::canonicalize(pinned_linker).expect("canonical pinned linker");
    assert_eq!(canonical_linker, canonical_pinned_linker,
        "unsupported effective linker");
    let canonical_lld_source = fs::canonicalize(Path::new(LEAN_LD_LLD))
        .expect("canonical pinned GNU LLD path");
    let canonical_expected_lld = fs::canonicalize(
        Path::new(LEAN_TOOLCHAIN).join("bin").join("ld.lld.exe"),
    ).expect("canonical expected GNU LLD path");
    assert_eq!(canonical_lld_source, canonical_expected_lld,
        "unexpected pinned GNU LLD path");
    for name in ["CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER"] {
        if let Some(value) = env::var_os(name) {
            let value = PathBuf::from(value);
            assert_eq!(fs::canonicalize(&value).expect("canonical target linker override"),
                fs::canonicalize(pinned_linker).expect("canonical pinned linker"),
                "unreviewed linker override {name}");
        }
    }
    if let Some(value) = env::var_os("CARGO_BUILD_TARGET") {
        assert_eq!(value.to_string_lossy(), target, "unreviewed Cargo target override");
    }

    for name in [
        "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        "CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS",
        "CARGO_PROFILE_RELEASE_LTO", "CARGO_PROFILE_RELEASE_CODEGEN_UNITS",
        "CARGO_PROFILE_RELEASE_OPT_LEVEL", "CARGO_PROFILE_RELEASE_DEBUG",
        "CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS", "CARGO_PROFILE_RELEASE_PANIC",
        "CARGO_PROFILE_RELEASE_STRIP", "CARGO_PROFILE_RELEASE_INCREMENTAL",
        "CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS", "CARGO_PROFILE_RELEASE_SPLIT_DEBUGINFO",
        "CARGO_PROFILE_RELEASE_RPATH", "CARGO_BUILD_TARGET_DIR", "CARGO_BUILD_BUILD_DIR",
        "CARGO_BUILD_WARNINGS", "CARGO_INCREMENTAL", "RUSTC_BOOTSTRAP",
        "RUSTC_FORCE_INCREMENTAL", "CL", "_CL_", "CC", "CXX", "AR", "LLVM_AR",
        "LLVM_CLANG", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "CPATH",
        "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "LIBRARY_PATH", "CCC_OVERRIDE_OPTIONS",
        "INCLUDE", "LIB", "LEAN_PATH", "LEAN_SYSROOT", "LEAN_TOOLCHAIN_ROOT",
        "LLD_REPRODUCE",
    ] {
        assert!(env::var_os(name).is_none(), "unreviewed build override {name}");
    }
    for (name, _) in env::vars() {
        assert!(
            !name.starts_with("CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_"),
            "unreviewed Cargo build override {name}",
        );
    }

    for (name, expected) in [
        ("CARGO_CFG_TARGET_ARCH", "x86_64"),
        ("CARGO_CFG_TARGET_OS", "windows"),
        ("CARGO_CFG_TARGET_ENV", "gnu"),
        ("CARGO_CFG_TARGET_FAMILY", "windows"),
        ("CARGO_CFG_TARGET_POINTER_WIDTH", "64"),
        ("CARGO_CFG_TARGET_ENDIAN", "little"),
    ] {
        assert_eq!(required_env(name), expected, "unsupported effective target setting {name}");
    }

    let mut records = vec![
        text_identity_record("build/host", &host),
        text_identity_record("build/target", &target),
        text_identity_record("build/profile", &profile),
        text_identity_record("build/opt-level", &opt_level),
        text_identity_record("build/debug", &debug),
        text_identity_record("build/effective-rustflags", &encoded_rustflags),
        text_identity_record("build/linker", "toolchain/bin/clang.exe"),
        text_identity_record("build/target-arch", "x86_64"),
        text_identity_record("build/target-os", "windows"),
        text_identity_record("build/target-env", "gnu"),
        text_identity_record("build/target-family", "windows"),
        text_identity_record("build/target-pointer-width", "64"),
        text_identity_record("build/target-endian", "little"),
    ];
    for (name, value) in env::vars() {
        if name.starts_with("CARGO_FEATURE_") {
            panic!("unreviewed Cargo feature {name}");
        }
        if name.starts_with("CARGO_CFG_TARGET_") && !value.is_empty() {
            records.push(text_identity_record(
                &format!("build/cargo-cfg/{}", name["CARGO_CFG_".len()..].to_ascii_lowercase()),
                &value,
            ));
        }
    }
    for name in ["PATH", "SYSTEMROOT", "CARGO_HOME", "CARGO_TARGET_DIR", "TEMP", "TMP"] {
        if let Some(value) = env::var_os(name) {
            let value = value.to_string_lossy();
            if !value.is_empty() {
                records.push(text_identity_record(
                    &format!("build/environment/{}", name.to_ascii_lowercase()),
                    &value,
                ));
            }
        }
    }
    records
}

fn lifecycle_link_input_records(lean_toolchain: &Path, native_dir: &Path) -> Vec<IdentityRecord> {
    let support_lib = lean_toolchain.join("lib");
    let lean_lib = lean_toolchain.join("lib").join("lean");
    let mut records = Vec::new();
    for name in LIFECYCLE_SUPPORT_ARCHIVES_FIRST
        .iter()
        .chain(LIFECYCLE_SUPPORT_ARCHIVES_MIDDLE)
        .chain(LIFECYCLE_SUPPORT_ARCHIVES_LAST)
    {
        let role = format!("link-input/support/{name}");
        if !records.iter().any(|record: &IdentityRecord| record.path == role) {
            records.push(identity_record_from_path(role, &support_lib.join(name)));
        }
    }
    for name in LIFECYCLE_LEAN_ARCHIVES.iter().chain(["libLake.a"].iter()) {
        let role = format!("link-input/lean/{name}");
        records.push(identity_record_from_path(role, &lean_lib.join(name)));
    }
    for name in ["libgcc.a", "libgcc_eh.a", "libntdll.a"] {
        records.push(identity_record_from_path(
            format!("link-input/native/{name}"),
            &native_dir.join(name),
        ));
    }
    let selected_lld = native_dir.join("ld.lld.exe");
    verified_regular_file(&selected_lld, PINNED_LEAN_LD_LLD_SHA256);
    records.push(identity_record_from_path(
        "link-tool/ld.lld.exe".to_string(),
        &selected_lld,
    ));
    records
}

fn lifecycle_link_argument_manifest() -> Vec<u8> {
    let mut args = vec![
        "-Btoolchain/bin".to_string(),
        "-fuse-ld=lld".to_string(),
        "--ld-path=OUT_DIR:native_link_inputs/ld.lld.exe".to_string(),
        "-Wl,--reproduce=OUT_DIR:lifecycle_link_repro.v1.tar".to_string(),
        "-v".to_string(),
        "-Wl,--no-insert-timestamp".to_string(),
        format!("-Wl,--undefined={LIFECYCLE_MANIFEST_SYMBOL}"),
        "OUT_DIR:blind_ledger_lifecycle_link.gnu.a".to_string(),
    ];
    for name in LIFECYCLE_SUPPORT_ARCHIVES_FIRST {
        args.push(format!("toolchain/lib/{name}"));
    }
    for name in LIFECYCLE_LEAN_ARCHIVES {
        args.push(format!("toolchain/lib/lean/{name}"));
    }
    for name in LIFECYCLE_SUPPORT_ARCHIVES_MIDDLE {
        args.push(format!("toolchain/lib/{name}"));
    }
    args.push("toolchain/lib/lean/libLake.a".to_string());
    for name in LIFECYCLE_SUPPORT_ARCHIVES_LAST {
        args.push(format!("toolchain/lib/{name}"));
    }
    args.extend([
        "OUT_DIR:native_link_inputs/libgcc.a".to_string(),
        "OUT_DIR:native_link_inputs/libgcc_eh.a".to_string(),
        "OUT_DIR:native_link_inputs/libntdll.a".to_string(),
        "-Wl,--stack,104857600".to_string(),
        "-Wl,--gc-sections".to_string(),
    ]);
    let mut manifest = String::from("lifecycle-link-arguments-v3\nsearch-path\tOUT_DIR:native_link_inputs\n");
    for (index, argument) in args.iter().enumerate() {
        manifest.push_str(&format!("{index}\t{argument}\n"));
    }
    manifest.into_bytes()
}

fn verified_copy(source: &Path, destination: &Path, expected_sha256: &str) {
    let bytes = fs::read(source).unwrap_or_else(|error| panic!("read {}: {error}", source.display()));
    let digest = format!("{:x}", sha2::Sha256::digest(&bytes));
    assert_eq!(digest, expected_sha256, "identity mismatch for {}", source.display());
    fs::write(destination, bytes).unwrap_or_else(|error| panic!("write {}: {error}", destination.display()));
}

fn run_checked(command: &Path, args: &[String], cwd: &Path) {
    let output = Command::new(command).args(args).current_dir(cwd).output()
        .unwrap_or_else(|error| panic!("run {}: {error}", command.display()));
    if !output.status.success() {
        panic!("{} exited {}; stdout={} stderr={}", command.display(), output.status,
            String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    }
}

fn run_lake_checked(command: &Path, args: &[String], cwd: &Path, lean_toolchain: &Path) {
    let output = Command::new(command).args(args).current_dir(cwd)
        .env("LEAN_PATH", "")
        .env("LEAN_SYSROOT", lean_toolchain)
        .output()
        .unwrap_or_else(|error| panic!("run {}: {error}", command.display()));
    if !output.status.success() {
        panic!("{} exited {}; stdout={} stderr={}", command.display(), output.status,
            String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    }
}

fn verify_archive_members(archive: &Path, members: &[(&str, &Path)]) {
    let listing = Command::new(LLVM_AR).args(["t", &archive.display().to_string()]).output()
        .unwrap_or_else(|error| panic!("list {}: {error}", archive.display()));
    assert!(listing.status.success(), "archive member listing failed for {}", archive.display());
    let actual = String::from_utf8(listing.stdout).expect("archive listing UTF-8");
    let expected = members.iter().map(|(name, _)| *name).collect::<Vec<_>>().join("\n") + "\n";
    assert_eq!(actual, expected, "archive member set mismatch for {}", archive.display());
    for (name, path) in members {
        let extracted = Command::new(LLVM_AR).args(["p", &archive.display().to_string(), name]).output()
            .unwrap_or_else(|error| panic!("extract archive member {name}: {error}"));
        assert!(extracted.status.success(), "archive member extraction failed for {name}");
        assert_eq!(extracted.stdout, fs::read(path).expect("direct link object"), "archive member differs from direct link object: {name}");
    }
}

fn manifest_c_source(manifest: &[u8]) -> Vec<u8> {
    let mut source = format!(
        "__attribute__((used, section(\".rdata$BLLM\"))) const unsigned char {LIFECYCLE_MANIFEST_SYMBOL}[] = {{\n"
    );
    for (index, byte) in manifest.iter().enumerate() {
        if index % 16 == 0 {
            source.push_str("  ");
        }
        source.push_str(&format!("0x{byte:02x},"));
        if index % 16 == 15 || index + 1 == manifest.len() {
            source.push('\n');
        }
    }
    source.push_str(&format!(
        "}};\n__attribute__((used, section(\".rdata$BLLM\"))) const unsigned long long {LIFECYCLE_MANIFEST_SYMBOL}_length = {}ULL;\n",
        manifest.len()
    ));
    source.into_bytes()
}

fn file_identity(path: &Path) -> (u64, String) {
    let bytes = regular_file_bytes(path);
    (bytes.len() as u64, sha256_hex(&bytes))
}

fn build_lifecycle_archive(
    out_dir: &Path,
    lean_root: &Path,
    lean_toolchain: &Path,
    rust_root: &Path,
    rust_records: &[IdentityRecord],
    build_records: &[IdentityRecord],
    link_records: &[IdentityRecord],
    link_arguments: &[u8],
) -> PathBuf {
    let staged_root = fresh_generated_dir(out_dir, "lifecycle_lean_build");
    let mut records = Vec::new();
    let mut lean_inputs = Vec::new();
    for (relative, expected) in LEAN_SOURCE_PINS {
        let source_path = lean_root.join(relative);
        let bytes = verified_regular_file(&source_path, expected);
        let staged_path = staged_root.join(relative);
        fs::create_dir_all(staged_path.parent().expect("staged source parent"))
            .unwrap_or_else(|error| panic!("create staged source parent: {error}"));
        fs::write(&staged_path, &bytes)
            .unwrap_or_else(|error| panic!("write staged source {}: {error}", staged_path.display()));
        assert_eq!(regular_file_bytes(&staged_path), bytes,
            "staged Lean input differs from pinned source: {}", relative);
        records.push(identity_record(format!("lean/{relative}"), &bytes));
        lean_inputs.push((source_path, staged_path, *expected));
    }

    for (relative, expected) in RUST_BUILD_INPUT_PINS {
        let path = rust_root.join(relative);
        let bytes = verified_regular_file(&path, expected);
        records.push(identity_record(format!("rust/{relative}"), &bytes));
    }
    let build_script_path = rust_root.join("build.rs");
    let build_script_bytes = regular_file_bytes(&build_script_path);
    records.push(identity_record("rust/build.rs".to_string(), &build_script_bytes));

    for (relative, expected) in LEAN_TOOL_PINS {
        let path = lean_toolchain.join(relative);
        let bytes = verified_regular_file(&path, expected);
        records.push(identity_record(format!("toolchain/{relative}"), &bytes));
    }
    let lean_library = lean_toolchain.join("lib").join("lean");
    let (olean_count, olean_bytes, olean_sha256) = lean_olean_tree_identity(&lean_library);
    assert_eq!(olean_sha256, PINNED_LEAN_OLEAN_TREE_SHA256, "Lean .olean import tree identity mismatch");
    records.push(IdentityRecord {
        path: "toolchain/lib/lean-olean-tree-v1".to_string(),
        count: olean_count,
        length: olean_bytes,
        sha256: olean_sha256,
    });

    let lake = lean_toolchain.join("bin").join("lake.exe");
    run_lake_checked(&lake, &[
        "-d".to_string(), staged_root.display().to_string(), "build".to_string(),
        "Admission.Library".to_string(),
        "Admission.LifecycleKernel:o.export".to_string(),
        "Admission.Lifecycle:o".to_string(),
    ], rust_root, lean_toolchain);

    for (source_path, staged_path, expected) in &lean_inputs {
        verified_regular_file(source_path, expected);
        verified_regular_file(staged_path, expected);
    }
    for (relative, expected) in RUST_BUILD_INPUT_PINS {
        verified_regular_file(&rust_root.join(relative), expected);
    }
    assert_eq!(regular_file_bytes(&build_script_path), build_script_bytes,
        "build.rs changed during Lifecycle compilation");
    for (relative, expected) in LEAN_TOOL_PINS {
        verified_regular_file(&lean_toolchain.join(relative), expected);
    }
    let (olean_count_after, olean_bytes_after, olean_sha256_after) = lean_olean_tree_identity(&lean_library);
    assert_eq!(olean_count_after, olean_count, "Lean .olean count changed during Lifecycle compilation");
    assert_eq!(olean_bytes_after, olean_bytes, "Lean .olean byte count changed during Lifecycle compilation");
    assert_eq!(olean_sha256_after, PINNED_LEAN_OLEAN_TREE_SHA256,
        "Lean .olean import tree changed during Lifecycle compilation");

    let generated_root = staged_root.join(".lake").join("build").join("ir");
    let lifecycle_kernel_object = generated_root.join("Admission").join("LifecycleKernel.c.o.export");
    let lifecycle_object = generated_root.join("Admission").join("Lifecycle.c.o.noexport");
    let model_object = generated_root.join("Admission").join("Model.c.o.noexport");
    let sha3_object = generated_root.join("BlindLedger").join("Sha3.c.o.noexport");
    let (kernel_bytes, kernel_sha256) = file_identity(&lifecycle_kernel_object);
    let (lifecycle_bytes, lifecycle_sha256) = file_identity(&lifecycle_object);
    let (model_bytes, model_sha256) = file_identity(&model_object);
    let (sha3_bytes, sha3_sha256) = file_identity(&sha3_object);
    records.extend(rust_records.iter().cloned());
    records.extend(build_records.iter().cloned());
    records.extend(link_records.iter().cloned());
    records.push(identity_record(
        "build/lifecycle-link-arguments-v1".to_string(),
        link_arguments,
    ));
    for (role, path) in [
        ("build-output/lifecycle-kernel-object", &lifecycle_kernel_object),
        ("build-output/lifecycle-object", &lifecycle_object),
        ("build-output/model-object", &model_object),
        ("build-output/sha3-object", &sha3_object),
    ] {
        records.push(identity_record_from_path(role.to_string(), path));
    }

    let source_manifest = render_source_manifest(&mut records);
    let source_manifest_sha256 = sha256_hex(&source_manifest);
    let source_manifest_path = out_dir.join("lifecycle_lean_source_manifest.v2.txt");
    fs::write(&source_manifest_path, &source_manifest)
        .unwrap_or_else(|error| panic!("write lifecycle source manifest: {error}"));

    let manifest_build = fresh_generated_dir(out_dir, "lifecycle_manifest_object");
    let manifest_c = manifest_build.join("lifecycle_source_manifest.c");
    let manifest_object = manifest_build.join("lifecycle_source_manifest.o");
    let manifest_c_bytes = manifest_c_source(&source_manifest);
    fs::write(&manifest_c, &manifest_c_bytes)
        .unwrap_or_else(|error| panic!("write lifecycle manifest C source: {error}"));
    run_checked(Path::new(LEAN_CLANG), &[
        "-c".to_string(), "-o".to_string(), manifest_object.display().to_string(),
        manifest_c.display().to_string(), "--target=x86_64-w64-windows-gnu".to_string(),
        "-fdata-sections".to_string(), "-ffunction-sections".to_string(),
        "-fno-ident".to_string(), "-g0".to_string(), "-O2".to_string(), "-DNDEBUG".to_string(),
    ], rust_root);
    let (manifest_object_bytes, manifest_object_sha256) = {
        let bytes = regular_file_bytes(&manifest_object);
        (bytes.len() as u64, sha256_hex(&bytes))
    };
    assert_eq!(regular_file_bytes(&manifest_c), manifest_c_bytes,
        "generated manifest C input changed during compilation");

    let lifecycle_archive = out_dir.join("blind_ledger_lifecycle_link.gnu.a");
    remove_generated_file(out_dir, "blind_ledger_lifecycle_link.gnu.a");
    run_checked(Path::new(LLVM_AR), &[
        "rcsD".to_string(),
        lifecycle_archive.display().to_string(),
        lifecycle_kernel_object.display().to_string(),
        lifecycle_object.display().to_string(),
        model_object.display().to_string(),
        sha3_object.display().to_string(),
        manifest_object.display().to_string(),
    ], rust_root);
    verify_archive_members(&lifecycle_archive, &[
        ("LifecycleKernel.c.o.export", &lifecycle_kernel_object),
        ("Lifecycle.c.o.noexport", &lifecycle_object),
        ("Model.c.o.noexport", &model_object),
        ("Sha3.c.o.noexport", &sha3_object),
        ("lifecycle_source_manifest.o", &manifest_object),
    ]);

    assert_eq!(file_identity(&lifecycle_kernel_object), (kernel_bytes, kernel_sha256.clone()),
        "LifecycleKernel object changed after archive creation");
    assert_eq!(file_identity(&lifecycle_object), (lifecycle_bytes, lifecycle_sha256.clone()),
        "Lifecycle object changed after archive creation");
    assert_eq!(file_identity(&model_object), (model_bytes, model_sha256.clone()),
        "Model object changed after archive creation");
    assert_eq!(file_identity(&sha3_object), (sha3_bytes, sha3_sha256.clone()),
        "Sha3 object changed after archive creation");
    assert_eq!(file_identity(&manifest_object), (manifest_object_bytes, manifest_object_sha256.clone()),
        "lifecycle manifest object changed after archive creation");
    assert_eq!(regular_file_bytes(&source_manifest_path), source_manifest,
        "lifecycle source manifest changed during build");
    println!("cargo:rustc-env=BL_LIFECYCLE_SOURCE_MANIFEST_SHA256={source_manifest_sha256}");
    let (archive_bytes, archive_sha256) = file_identity(&lifecycle_archive);
    let receipt = format!(
        "blind-ledger-lifecycle-build-receipt-v2\nsource_manifest\t{}\t{}\nlifecycle_kernel_object\t{}\t{}\nlifecycle_object\t{}\t{}\nmodel_object\t{}\t{}\nsha3_object\t{}\t{}\nmanifest_object\t{}\t{}\nlifecycle_archive\t{}\t{}\n",
        source_manifest_sha256, source_manifest.len(),
        kernel_bytes, kernel_sha256,
        lifecycle_bytes, lifecycle_sha256,
        model_bytes, model_sha256,
        sha3_bytes, sha3_sha256,
        manifest_object_bytes, manifest_object_sha256,
        archive_bytes, archive_sha256,
    );
    let receipt_temp = out_dir.join("lifecycle_build_receipt.v2.txt.tmp");
    fs::write(&receipt_temp, receipt.as_bytes())
        .unwrap_or_else(|error| panic!("write temporary lifecycle build receipt: {error}"));
    fs::rename(&receipt_temp, out_dir.join("lifecycle_build_receipt.v2.txt"))
        .unwrap_or_else(|error| panic!("publish lifecycle build receipt: {error}"));
    lifecycle_archive
}

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let lean_root = manifest.join("..").join("..").join("lean").join("queue");
    let lean_toolchain = PathBuf::from(LEAN_TOOLCHAIN);
    let out_dir = canonical_output_dir(&PathBuf::from(env::var_os("OUT_DIR").expect("cargo OUT_DIR")));

    remove_generated_file(&out_dir, "lifecycle_build_receipt.v1.txt");
    remove_generated_file(&out_dir, "lifecycle_build_receipt.v1.txt.tmp");
    remove_generated_file(&out_dir, "lifecycle_build_receipt.v2.txt");
    remove_generated_file(&out_dir, "lifecycle_build_receipt.v2.txt.tmp");
    remove_generated_file(&out_dir, "lifecycle_lean_source_manifest.v1.txt");
    remove_generated_file(&out_dir, "lifecycle_lean_source_manifest.v2.txt");
    remove_generated_file(&out_dir, "lifecycle_link_arguments.v3.txt");
    remove_generated_file(&out_dir, "lifecycle_link_repro.v1.tar");
    remove_generated_file(&out_dir, "blind_ledger_lifecycle_link.gnu.a");

    let rust_records = verify_pinned_rust();
    let build_records = verify_effective_cargo_settings();
    for (relative, expected) in LEAN_SOURCE_PINS {
        verified_regular_file(&lean_root.join(relative), expected);
    }
    for (relative, expected) in RUST_BUILD_INPUT_PINS {
        verified_regular_file(&manifest.join(relative), expected);
    }
    for (relative, expected) in LEAN_TOOL_PINS {
        verified_regular_file(&lean_toolchain.join(relative), expected);
    }
    let lean_library = lean_toolchain.join("lib").join("lean");
    let (_, _, olean_sha256) = lean_olean_tree_identity(&lean_library);
    assert_eq!(olean_sha256, PINNED_LEAN_OLEAN_TREE_SHA256, "Lean .olean import tree identity mismatch");

    verified_file(&manifest.join("native_boundary.c"), NATIVE_BOUNDARY_SHA256);
    let lake = lean_toolchain.join("bin").join("lake.exe");
    run_lake_checked(&lake, &[
        "-d".to_string(), lean_root.display().to_string(), "build".to_string(),
        "Admission.Library".to_string(),
    ], &manifest, &lean_toolchain);
    let link_dir = lean_root.join(".lake\\build\\lib");
    let linked_archive = link_dir.join("blind_ledger_admission_link.gnu.a");
    if !linked_archive.is_file() {
        panic!("missing pinned GNU Lean static link archive {}; build it in the approved guarded build packet", linked_archive.display());
    }
    verified_file(&linked_archive, LINKED_ARCHIVE_SHA256);
    let generated_root = lean_root.join(".lake\\build\\ir");
    let library_object = generated_root.join("Admission\\Library.c.o.export");
    let model_object = generated_root.join("Admission\\Model.c.o.noexport");
    let sha3_object = generated_root.join("BlindLedger\\Sha3.c.o.noexport");
    verified_file(&library_object, LIBRARY_OBJECT_SHA256);
    verified_file(&model_object, MODEL_OBJECT_SHA256);
    verified_file(&sha3_object, SHA3_OBJECT_SHA256);
    let native_dir = fresh_generated_dir(&out_dir, "native_link_inputs");
    verified_copy(Path::new(LEAN_LD_LLD), &native_dir.join("ld.lld.exe"), PINNED_LEAN_LD_LLD_SHA256);
    verified_copy(Path::new(NTDLL), &native_dir.join("libntdll.a"), NTDLL_SHA256);
    verified_copy(Path::new(COMPILER_RT), &native_dir.join("libgcc.a"), COMPILER_RT_SHA256);
    verified_copy(Path::new(COMPILER_RT), &native_dir.join("libgcc_eh.a"), COMPILER_RT_SHA256);
    let link_records = lifecycle_link_input_records(&lean_toolchain, &native_dir);
    let link_arguments = lifecycle_link_argument_manifest();
    let link_arguments_path = out_dir.join("lifecycle_link_arguments.v3.txt");
    fs::write(&link_arguments_path, &link_arguments)
        .unwrap_or_else(|error| panic!("write Lifecycle link argument manifest: {error}"));
    assert_eq!(regular_file_bytes(&link_arguments_path), link_arguments,
        "Lifecycle link argument manifest changed during write");
    let lifecycle_archive = build_lifecycle_archive(
        &out_dir,
        &lean_root,
        &lean_toolchain,
        &manifest,
        &rust_records,
        &build_records,
        &link_records,
        &link_arguments,
    );
    let native_object = native_dir.join("native_boundary.o");
    run_checked(Path::new(LEAN_CLANG), &[
        "-c".to_string(), "-o".to_string(), native_object.display().to_string(),
        manifest.join("native_boundary.c").display().to_string(),
        "-I".to_string(), lean_toolchain.join("include").display().to_string(),
        "--target=x86_64-w64-windows-gnu".to_string(),
        "-fstack-clash-protection".to_string(), "-ffp-contract=off".to_string(),
        "-fdata-sections".to_string(), "-ffunction-sections".to_string(),
        "-Wno-unused-command-line-argument".to_string(),
        format!("--sysroot={}", lean_toolchain.display()), "-nostdinc".to_string(),
        "-isystem".to_string(), lean_toolchain.join("include\\clang").display().to_string(),
        "-O3".to_string(), "-DNDEBUG".to_string(),
    ], &manifest);
    verified_file(&native_object, NATIVE_BOUNDARY_OBJECT_SHA256);
    verify_archive_members(&linked_archive, &[
        ("Library.c.o.export", &library_object),
        ("Model.c.o.noexport", &model_object),
        ("Sha3.c.o.noexport", &sha3_object),
        ("native_boundary.o", &native_object),
    ]);
    println!("cargo:rerun-if-changed={}", manifest.join("native_boundary.c").display());
    println!("cargo:rerun-if-changed={}", linked_archive.display());
    for (relative, _) in LEAN_SOURCE_PINS {
        println!("cargo:rerun-if-changed={}", lean_root.join(relative).display());
    }
    for (relative, _) in RUST_BUILD_INPUT_PINS {
        println!("cargo:rerun-if-changed={}", manifest.join(relative).display());
    }
    for (relative, _) in LEAN_TOOL_PINS {
        println!("cargo:rerun-if-changed={}", lean_toolchain.join(relative).display());
    }
    println!("cargo:rerun-if-changed={}", lean_library.display());
    for path in [&library_object, &model_object, &sha3_object] {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    for variable in [
        "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_LINKER", "CARGO_BUILD_TARGET",
        "CARGO_BUILD_RUSTFLAGS", "CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER",
        "CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUSTFLAGS", "CARGO_PROFILE_RELEASE_LTO",
        "CARGO_PROFILE_RELEASE_CODEGEN_UNITS", "CARGO_PROFILE_RELEASE_OPT_LEVEL",
        "CARGO_PROFILE_RELEASE_DEBUG", "CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS",
        "CARGO_PROFILE_RELEASE_PANIC", "CARGO_PROFILE_RELEASE_STRIP",
        "CARGO_PROFILE_RELEASE_INCREMENTAL", "CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS",
        "CARGO_INCREMENTAL", "RUSTC_BOOTSTRAP", "RUSTC_FORCE_INCREMENTAL", "CL", "_CL_",
        "CC", "CXX", "AR", "LLVM_AR", "LLVM_CLANG", "CFLAGS", "CXXFLAGS", "CPPFLAGS",
        "LDFLAGS", "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "LIBRARY_PATH",
        "CCC_OVERRIDE_OPTIONS", "INCLUDE", "LIB", "LEAN_PATH", "LEAN_SYSROOT",
        "LEAN_TOOLCHAIN_ROOT", "PATH", "SYSTEMROOT", "CARGO_HOME", "CARGO_TARGET_DIR",
        "TEMP", "TMP", "LLD_REPRODUCE",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }
    let support_lib = lean_toolchain.join("lib");
    let lean_lib = lean_toolchain.join("lib").join("lean");
    for name in LIFECYCLE_SUPPORT_ARCHIVES_FIRST
        .iter()
        .chain(LIFECYCLE_SUPPORT_ARCHIVES_MIDDLE)
        .chain(LIFECYCLE_SUPPORT_ARCHIVES_LAST)
    {
        println!("cargo:rerun-if-changed={}", support_lib.join(name).display());
    }
    for name in LIFECYCLE_LEAN_ARCHIVES.iter().chain(["libLake.a"].iter()) {
        println!("cargo:rerun-if-changed={}", lean_lib.join(name).display());
    }
    println!("cargo:rerun-if-changed={NTDLL}");
    println!("cargo:rerun-if-changed={COMPILER_RT}");
    verified_regular_file(&native_dir.join("ld.lld.exe"), PINNED_LEAN_LD_LLD_SHA256);
    println!("cargo:rerun-if-changed={}", native_dir.join("ld.lld.exe").display());
    println!("cargo:rustc-link-search=native={}", native_dir.display());
    println!("cargo:rustc-link-arg=-B{}", lean_toolchain.join("bin").display());
    println!("cargo:rustc-link-arg=-fuse-ld=lld");
    println!("cargo:rustc-link-arg=--ld-path={}", native_dir.join("ld.lld.exe").display());
    println!("cargo:rustc-link-arg=-v");
    println!("cargo:rustc-link-arg=-Wl,--no-insert-timestamp");
    println!("cargo:rustc-link-arg-bin=lifecycle=-Wl,--undefined={LIFECYCLE_MANIFEST_SYMBOL}");
    println!("cargo:rustc-link-arg-bin=lifecycle={}", lifecycle_archive.display());
    println!("cargo:rustc-link-arg-bin=lifecycle=-Wl,--reproduce={}", out_dir.join("lifecycle_link_repro.v1.tar").display());
    for object in [&library_object, &model_object, &sha3_object, &native_object] {
        println!("cargo:rustc-link-arg-bin=blind_ledger_admission_adapter={}", object.display());
    }

    for archive in LIFECYCLE_SUPPORT_ARCHIVES_FIRST {
        println!("cargo:rustc-link-arg={}", support_lib.join(archive).display());
    }
    for archive in LIFECYCLE_LEAN_ARCHIVES {
        println!("cargo:rustc-link-arg={}", lean_lib.join(archive).display());
    }
    for archive in LIFECYCLE_SUPPORT_ARCHIVES_MIDDLE {
        println!("cargo:rustc-link-arg={}", support_lib.join(archive).display());
    }
    println!("cargo:rustc-link-arg={}", lean_lib.join("libLake.a").display());
    for archive in LIFECYCLE_SUPPORT_ARCHIVES_LAST {
        println!("cargo:rustc-link-arg={}", support_lib.join(archive).display());
    }
    println!("cargo:rustc-link-arg={}", native_dir.join("libgcc.a").display());
    println!("cargo:rustc-link-arg={}", native_dir.join("libgcc_eh.a").display());
    println!("cargo:rustc-link-arg={}", native_dir.join("libntdll.a").display());
    println!("cargo:rustc-link-arg=-Wl,--stack,104857600");
    println!("cargo:rustc-link-arg=-Wl,--gc-sections");
}
