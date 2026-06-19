# Project State

Current state: native-STARK-only active architecture, fail-closed for production.

## What Exists

- Batch app flow with authoritative nullifier-root advancement and payment
  reconciliation.
- STARK-field Poseidon/nullifier helpers shared by the app-layer tests.
- Solidity batch registry/payment contracts plus native STARK settlement
  contracts and tests.
- Operational manifests and validators for production config, governance,
  source manifests, public inputs, verifier artifact pins, monitoring, and
  launch blockers.
- Buildable check script and bloat-checked release zip script.

## What Was Removed

The old single-claim proof contracts, generated verifier, adapter contracts,
setup ceremony files, root demo engine, and wrapper-oriented proof lanes are no
longer part of the active package.

## What Remains Blocked

Production launch still requires a real audited native STARK prover/verifier,
stable verifier artifact hash, source/oracle ratification, key custody, and
deployment governance. Test doubles are kept inside test files only.
