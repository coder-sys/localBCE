# The reproducible build of rr_gate_mldsa87.exe (recipe: README.md). Prints the SHA-256 to pin.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot  # rustup reads rust-toolchain.toml from the current directory
$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $HOME '.cargo' }
cargo build --release --locked --offline --config "target.x86_64-pc-windows-msvc.rustflags=['--remap-path-prefix=$cargoHome=/cargo']"
if ($LASTEXITCODE) { exit $LASTEXITCODE }
(Get-FileHash target\release\rr_gate_mldsa87.exe -Algorithm SHA256).Hash.ToLower()
