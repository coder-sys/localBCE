# Cairo / STARK Stack Setup

This folder gives a cofounder a repeatable way to download the tooling needed to
build and test the Cairo/STARK parts of this repo without bloating the release
zip with binaries.

## What Gets Installed Or Verified

- Scarb/Cairo 2.18.0, pinned to the repo's current Cairo toolchain.
- Rust/Cargo, required by the local Rust STARK and rules-engine work.
- Ethereum Foundry (`forge`, `cast`, `anvil`) for Solidity contract tests.
- Starknet Foundry (`snforge`, `sncast`) through the official Starkup path on
  WSL/Linux, for the broader Cairo/Starknet development stack.

## Windows Quick Start

From the repo root in PowerShell:

```powershell
.\tooling\cairo-stark-stack\install-windows.ps1
.\tooling\cairo-stark-stack\verify-stack.ps1
```

Windows-native Scarb is supported. Starknet Foundry's documented Windows path is
WSL/Ubuntu, so use the WSL script for `snforge`/`sncast`.

## WSL / Ubuntu Quick Start

```bash
cd /mnt/c/path/to/localBCE-codex-dev
bash tooling/cairo-stark-stack/install-wsl-ubuntu.sh
```

Then open a new shell or source the printed profile files, and run:

```bash
scarb --version
snforge --version || true
forge --version
cargo --version
```

## Official References

- Scarb download docs: https://docs.swmansion.com/scarb/download
- Starknet environment setup: https://docs.starknet.io/build/quickstart/environment-setup
- Starknet Foundry book: https://foundry-rs.github.io/starknet-foundry/getting-started/installation.html
- Ethereum Foundry installer: https://getfoundry.sh/getting-started/installation

## Notes

- This folder does not vendor external binaries.
- `cairo-compile` and `cairo-run` are Cairo 0-era command names. This repo uses
  Cairo 1 through Scarb, so `scarb build`, `scarb test`, `scarb execute`,
  `scarb prove`, and `scarb verify` are the relevant commands.
- The current Cairo binding is a hardened library and test target. The old flat
  trusted-flag executable has intentionally been retired.
