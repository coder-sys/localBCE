# rr_gate_mldsa87: build recipe

ML-DSA-87 signer (FIPS 204 algorithm, non-validated AWS-LC): `keygen|public-key|sign <file>`
on a DPAPI-sealed seed (`sign` self-verifies), and `kat-*` modes for the ACVP vectors. `app/right_rail_gate_signer.py`
runs `target/release/rr_gate_mldsa87.exe` only if it hashes to `rr_gate_mldsa87.sha256`.

Build: `powershell -NoProfile -File build.ps1` (under the guard, `-MinFree 4029372048`).
It prints the SHA-256 to pin. Inputs that fix the bytes:

- `rust-toolchain.toml`: rustc/cargo 1.96.0 (ac68faa20 2026-05-25), x86_64-pc-windows-msvc.
- `Cargo.lock`, built with `--locked --offline` from the crates.io cache.
- `.cargo/config.toml`: static CRT (imports only KERNEL32, ntdll and
  api-ms-win-core-synch) and `/Brepro`, so the PE timestamp and PDB GUID are content
  hashes. The PDB path is the bare file name (rustc's default).
- `build.ps1` adds `--remap-path-prefix=<CARGO_HOME>=/cargo` for Rust source paths.

Two builds (2026-09-29; this directory and its copy `C:\Users\neers\rrb\archive\slim-20261003\gate\`) were
byte-identical, SHA-256 `bfe29b0c42c10b378e472b7873099fdaceab2ef980d73808547029f3cc98fc83`
(`pqm1-cargoa4-a1`, `pqm1-cargob4-a1`). Retired pins: `artifacts/gate-verify/PROVENANCE.txt`.

Known limit: rustc's remap cannot reach aws-lc-sys's C `__FILE__` paths under CARGO_HOME. Rebuilding needs CARGO_HOME at
`C:\Users\neers\.cargo` on a volume with the same 8.3 short names, MSVC 14.44.35207 and
Windows SDK/UCRT 10.0.26100.0 (cc builder, no CMake).
