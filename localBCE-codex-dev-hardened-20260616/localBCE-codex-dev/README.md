# localBCE Native STARK Workspace

This package is the hardened local Blind Ledger workspace after the legacy proof
architecture was removed from the active tree.

## Active Components

- `blind-ledger-app-layer/`: Python app layer, batch orchestration, STARK-field
  nullifier/accounting helpers, app tests, Solidity batch contracts, and the
  native STARK settlement contract.
- `blind-ledger-app-layer/operator_portal/`: static Medi-Cal operator interface
  served by `app.operator_portal`.
- `blind-ledger-app-layer/rules-engine-rust/`: Rust rules engine used by the
  app-layer batch path when built.
- `blind-ledger-app-layer/zk-stark/`: local STARK proof-core work and tests.
- `blind-ledger-app-layer/zk-cairo-sharp/`: Cairo-native binding prototype and
  constraint notes.
- `gov-rules-kg-prototype/`: governance/rules knowledge-graph prototype.
- `ops/`: production environment template, governance/source manifests, public
  input schema, verifier pin manifest, launch blockers, and runbooks.
- `scripts/`: buildable-check and clean-release packaging scripts.
- `third_party/forge-std/`: Foundry test library only.

## Removed Architecture

The old single-claim proof lane, setup ceremony artifacts, generated verifier,
adapter contracts, root orchestration demo, and wrapper-oriented zkVM lane have
been removed from this package. Reintroducing those artifacts should fail the
release packaging deny-list.

## Buildable Checks

Run the current check set from the repo root:

```powershell
.\scripts\run_buildable_checks.ps1
```

The script covers operational manifests, app-layer Python tests, KG tests,
app-layer Forge tests, the Rust rules engine, and the local STARK Rust tests.

## Release Zip

Build the clean zip:

```powershell
.\scripts\build_clean_release_zip.ps1
```

The script refuses common build caches, generated proof artifacts, deleted proof
lanes, and other package bloat.

## Production Status

This repo is materially safer than the old demo architecture, but it is still
not production-ready until an audited native STARK prover/verifier and matching
verifier artifact hash are supplied. Production configuration fails closed until
all required governance, oracle, key-custody, data-availability, and verifier
pins are explicit.
