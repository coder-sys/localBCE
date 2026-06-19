# Cofounder Read

This zip is a hardened local Blind Ledger workspace for the Medi-Cal settlement
prototype. It is meant for review, local testing, and technical diligence. It is
not approved for real claims money until the remaining production blockers are
closed and independently audited.

## What This Package Is

The active architecture is native-STARK-first and fail-closed for production.
The old Groth16/Circom-style proof lanes are not present in the release zip, and
production readiness rejects legacy proof wrappers, dev-only Winterfell/f128
authority, test doubles, and unpinned verifier artifacts.

The package contains:

- `blind-ledger-app-layer/`: Python claim intake, batch orchestration, encrypted
  data availability, nullifier/accounting helpers, production readiness gates,
  the operator portal, Solidity contracts, Rust rules engine, Cairo binding
  work, and tests.
- `gov-rules-kg-prototype/`: government-rules knowledge-graph prototype and
  legal/source validation tests.
- `ops/`: production env template, governance config, oracle/source manifest,
  public-input schema, verifier pin manifest, monitoring events, launch blockers,
  and runbooks.
- `scripts/`: buildable-test runner and clean-release zip builder.
- `tooling/cairo-stark-stack/`: cofounder setup scripts for downloading and
  verifying the Cairo/STARK development stack.
- `third_party/forge-std/`: Foundry test library used by Solidity tests.

## Current Security Posture

Material improvements already in this package:

- Sorted-order Merkle path positions replace grindable hash-mod slot selection.
- Benefit accumulator updates require pinned before/after on-chain roots.
- Encrypted data availability uses per-epoch key derivation with epoch-bound AAD.
- Production readiness fails closed unless required governed roots, verifier
  hashes, key roots, and governance anchors are explicit.
- The Cairo toy interface was retired: no free eligibility/provider/auth flags,
  no 8-slot spent-nullifier list, no untagged `update_with(input)` commitment,
  and no hardcoded fee ceiling.
- Cairo build and tests are now part of the all-buildable check script.
- The operator portal is a local non-production review desk, with no production
  reset or test-double escape path in production mode.

Remaining production blockers:

- The hardened Cairo binding currently compiles and tests as a library, but the
  hardened executable/prover fixture for `HardenedClaimInput` still needs to be
  added and audited.
- A real native verifier artifact must be pinned and deployed; mock verifier
  behavior is not production authority.
- Oracle/source manifests, verifier pins, key custody, governance/multisig, and
  launch blockers must be ratified with production values.
- Independent cryptographic and security review is required before any live
  federal or state claims funds move.

## Install The Toolchain

For Windows, run PowerShell from the repo root:

```powershell
.\tooling\cairo-stark-stack\install-windows.ps1
```

Then verify:

```powershell
.\tooling\cairo-stark-stack\verify-stack.ps1
```

For the full Starknet Foundry stack on Windows, use WSL/Ubuntu and run:

```bash
cd /mnt/c/path/to/localBCE-codex-dev
bash tooling/cairo-stark-stack/install-wsl-ubuntu.sh
```

The Windows script installs pinned Scarb/Cairo 2.18.0 with checksum verification.
The WSL script installs the broader Starknet stack using the official Starkup
path, plus Rust and Ethereum Foundry where missing.

## Run The Checks

From the repo root:

```powershell
.\scripts\run_buildable_checks.ps1
```

Expected coverage:

- operational readiness manifest validation
- app-layer Python security and portal tests
- government-rules KG tests
- Cairo binding build and tests
- Forge/Solidity tests
- Rust rules-engine tests
- local STARK Rust tests

You can run just the Cairo lane:

```powershell
cd blind-ledger-app-layer\zk-cairo-sharp
scarb build
scarb test
```

## Run The Local Operator Portal

From `blind-ledger-app-layer/`:

```powershell
python -m uvicorn app.operator_portal:app --host 127.0.0.1 --port 8042
```

Open:

```text
http://127.0.0.1:8042/?fresh=claimsdesk
```

This is a local operator/auditor workflow for reviewing cleared claims, routed
claims, audit history, batch evidence, and readiness checks. It is not a live
production claims endpoint.

## Rebuild The Clean Zip

From the repo root:

```powershell
.\scripts\build_clean_release_zip.ps1
```

The packaging script refuses common junk and dangerous legacy artifacts, including
`node_modules`, build targets, Python caches, Foundry outputs, old proof wrappers,
mock deployment artifacts, and deleted proof-lane leftovers.

## What Not To Do

- Do not treat the current local verifier/mock verifier path as production
  finality.
- Do not reintroduce Circom/Groth16 wrapper lanes into production manifests.
- Do not ship generated `target`, `out`, `cache`, `broadcast`, `__pycache__`, or
  `.pytest_cache` directories.
- Do not use raw free-input facts for eligibility, provider status, authorization,
  nullifier state, fee schedule, or payment amount.

## Fast Status

The repo is much stronger than the original demo. It is now fail-closed by
default, rejects the legacy proof architecture, and includes reproducible local
checks. The remaining work is narrower but serious: wire the hardened Cairo
statement into an audited proving/verifier path and pin real production artifacts.
