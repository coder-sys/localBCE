# rr_gate_mldsa87: build recipe

The one ML-DSA-87 signer/verifier for gate checkpoints (AWS-LC through aws-lc-rs).
`app/right_rail_gate_signer.py` runs `target/release/rr_gate_mldsa87.exe` only if it
hashes to `rr_gate_mldsa87.sha256`.

Build: `powershell -NoProfile -File build.ps1` (under the guard, `-MinFree 4190433321`).
It prints the SHA-256 to pin. The inputs that fix the bytes:

- `rust-toolchain.toml`: rustc/cargo 1.96.0 (ac68faa20 2026-05-25), x86_64-pc-windows-msvc.
- `Cargo.lock`, built with `--locked --offline` from the crates.io cache.
- `.cargo/config.toml`: static CRT (imports only KERNEL32, ntdll and
  api-ms-win-core-synch) and `/Brepro`, so the PE timestamp and PDB GUID are content
  hashes, not the clock. The PDB path is the bare file name (rustc's default).
- `build.ps1` adds `--remap-path-prefix=<CARGO_HOME>=/cargo` for Rust source paths.

Proof (2026-09-26): builds from this directory and from a copy at
`C:\Users\neers\rrb\gate\signer-b\gate_mldsa87` gave byte-identical binaries,
SHA-256 `af8743c70690f85a983762f93ad9ded731e514e106bfdb8c9d1c1cd49fed116b`
(guard logs `gate-rr4-signA-a1`, `gate-rr4-signB-a1`).

Known limit: aws-lc-sys compiles C with `__FILE__` paths under CARGO_HOME (long and
8.3 forms); rustc's remap cannot reach them. A matching rebuild needs what this build
used: CARGO_HOME at `C:\Users\neers\.cargo` on a volume that generates the same 8.3
short names (a volume with 8.3 names off, or another short-name assignment, changes
the bytes), MSVC 14.44.35207, and Windows SDK/UCRT 10.0.26100.0. aws-lc-sys used its
cc builder (prebuilt assembly objects, no CMake cache); CMake 4.3.3 is installed but
was not invoked. Other machines are untested.
