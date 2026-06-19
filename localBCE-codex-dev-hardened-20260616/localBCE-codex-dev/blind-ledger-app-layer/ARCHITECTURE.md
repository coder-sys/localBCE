# Architecture

The active architecture is batch-first and native-STARK-only. The old
single-claim demo API, local JSON registry, legacy proof wrappers, generated
verifier adapters, and deployable test verifier doubles are no longer part of
the package.

## Batch Flow

```text
837 claim inputs
  -> parser and shared-context builder
  -> rules engine
  -> batch commitments and nullifier roots
  -> payment reconciliation root
  -> native STARK public-input binding
  -> Solidity batch registry / payment trigger
  -> 835 output and appeal routing
```

## Production Boundary

- Batch records store commitments and roots, not raw claim data.
- Nullifier roots advance authoritatively and reject stale competing batches.
- Payment roots are reconciled before settlement references can be emitted.
- Governance-controlled roots bind rulesets, claim sources, oracle facts,
  signer sets, fee schedules, and address books.
- Native STARK settlement requires an audited verifier artifact and pinned
  artifact hash before any live deployment.

## Built Components

- App-layer parser, shared-context builder, rules adapter, batch orchestrator,
  nullifier/commitment helpers, 835 generator, appeal routing, and readiness
  validators.
- Solidity batch registry, payment trigger, native STARK verifier interface,
  and native STARK settlement contract.
- Python, Foundry, and Rust tests for the buildable security surface.

## Launch Blockers

- Real audited native STARK prover/verifier artifacts.
- Production verifier pin manifest replacing
  `ops/verifier_artifact_pin.example.json`.
- Ratified oracle/source manifests and governed roots.
- Multisig/timelock validation, key custody, monitoring, and incident-response
  signoff.
