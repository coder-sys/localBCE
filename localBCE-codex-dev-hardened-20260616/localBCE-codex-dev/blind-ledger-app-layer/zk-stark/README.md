# Blind Ledger STARK Core

Status: local STARK proof core, soundness-checked where runnable, pending
cryptographic audit and production verifier integration.

## What It Builds

- Winterfell-based transparent STARK proof core.
- G1-G10 normalized claim-gate checks.
- Public outputs for claim commitment, decision, and failure code.
- Rust verifier for local proof artifacts.

## Commands

```powershell
cargo +1.96.0-x86_64-pc-windows-msvc test
cargo +1.96.0-x86_64-pc-windows-msvc run --release -- outputs
cargo +1.96.0-x86_64-pc-windows-msvc run --release --bin verify_artifact -- outputs/proofs/approved.stark outputs/public/approved.json
```

## Boundary

This directory does not ship a production Ethereum verifier. The app-layer
settlement contract requires audited native STARK verifier artifacts and pinned
hashes before any live deployment.
