# Agent instructions for Blind Ledger

Blind Ledger is a database-backed, mandatory-zero-knowledge payment system. Treat proof, policy, state, signature, custody, and payment-transition code as trust-critical.

## Before editing

1. Work from this repository root.
2. Read `docs/DATABASE_ZK_ARCHITECTURE.md`, `docs/CURRENT_TECH_STACK.md`, `docs/PQ_ZK_SECURITY_ARCHITECTURE.md`, and `docs/IMPLEMENTATION_ROADMAP.md`.
3. After context loss, re-read this file, `CONTINUATION_MANDATE.md`, and the newest `STATE.md` section.
4. Use existing Python, Rust, Scarb, and CUDA installations. Keep generated outputs outside release archives.

## Current architecture boundary

- The application database is the operational source of truth.
- Private evidence that can authorize a payment requires a mandatory application ZK proof.
- The native verifier must accept before one atomic database transaction can consume nullifiers and update payment state.
- Government and oracle signatures authenticate provenance and authority; they do not prove that the underlying facts are true.
- No L2, rollup, sequencer, bridge, public data-availability layer, or Solidity settlement contract is part of the current design.
- Ethereum is not a Phase 0-2 dependency. A later design may checkpoint a compact signed state root or aggregate proof directly to Ethereum L1.

## Protected trust-critical paths

Do not edit these unless the owner explicitly authorizes the exact change:

- `zk-cairo-sharp/`
- `app/batch/nullifier.py`
- `app/batch/leaf.py`
- `app/batch/stark_binding.py`
- `app/batch/merkle.py`
- `app/batch/accumulators.py`
- `app/batch/batch_orchestrator.py`
- `app/oracle_attestation.py`
- `app/public_inputs.py`
- `app/canonical_encoding.py`

## Operational authority

`ops/` is canonical. `experiments/bl_pq512_crypto_foundation/ops_authority.py` freezes its exact regular-file set, lengths, and SHA3-512 identities. Never change policy bytes merely to make a check pass.

## Claims

The repository is nonactivating. `proofSuiteId` remains null and `production_usable=false`. Do not claim production readiness, independent audit acceptance, real-PHI safety, real-payment authorization, or Ethereum settlement without current raw evidence.
