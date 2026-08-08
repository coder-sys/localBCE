# Database + mandatory-ZK architecture

Status: authoritative through Phase 2  
Updated: 2026-08-08

## Product rule

No payment state transition occurs when private claim evidence is relevant unless a mandatory zero-knowledge proof has been accepted by the pinned native verifier and the resulting update commits in one atomic database transaction.

Ordinary provider-app preflight may check completeness and formatting locally. It does not create the authoritative proof and cannot authorize payment.

## Transaction boundary

For each batch, the service:

1. receives canonical signed source records and a fixed-shape proof envelope;
2. authenticates source identities, epochs, policy/ruleset roots, and proof-suite identity;
3. verifies the mandatory zero-knowledge proof with the native verifier;
4. opens or continues a serializable transaction;
5. rechecks the batch nonce, state-before roots, governance roots, and anti-rollback epoch;
6. rejects consumed nullifiers, stale roots, duplicates, or conflicting retries;
7. writes the state-after roots, payment commitments, and audit event;
8. commits once, or changes nothing.

Verifier acceptance alone never authorizes a payment. A database write without verifier acceptance is forbidden.

## What the proof establishes

The proof establishes that a hidden, fixed-shape witness satisfies the pinned claim program: source/signature checks included by the relation, policy and ruleset evaluation, replay protection, state transition, value conservation, and settlement commitment. It reveals only the frozen public fields and authenticated sidecar.

It cannot establish that an authorized source told the truth, that the policy was wise or lawful, or that database operators preserved availability. Those are governance and operational trust boundaries.

## Cryptographic requirements

- Mandatory application ZK for payment-relevant private evidence.
- Fixed 12-field Privacy V2 public ABI.
- Fixed-shape batching and privacy-safe error behavior.
- SHA3-512 authoritative commitments.
- M31/Fp16 proof arithmetic and the current GKR/Construction-8.2 candidate.
- Authenticated interactive public coin; Fiat-Shamir is not the launch-security assumption.
- ML-DSA-87 plus SLH-DSA-SHAKE-256f at Blind Ledger-controlled signing boundaries.
- Exact binding of proof, verifier, schema, policy, ruleset, source, state-before, state-after, and settlement identities.
- Fail-closed parsing, resource limits, retries, recovery, migration, and anti-rollback.

## Ethereum boundary

Ethereum is not a dependency through Phase 2. No L2, rollup, sequencer, bridge, Solidity settlement contract, or public data-availability layer is required.

A later phase may post one compact signed checkpoint or aggregate proof directly to Ethereum L1 on a fixed cadence. That checkpoint can add public timestamping and tamper evidence. It must not carry PHI, replace the operational database, or weaken mandatory application proof verification.

## Phase boundary

- Phase 0: freeze this architecture and threat model.
- Phase 1: preserve and reconcile the proof core, ABI, signed-source model, and direct state boundary.
- Phase 2: qualify the mandatory proof and atomic database transition locally with adversarial tests and reproducible evidence.
- Later: production database/custody integration, independent audit, operator activation, and optional L1 checkpoint design.

