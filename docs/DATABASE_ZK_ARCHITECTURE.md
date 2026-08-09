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
8. commits the database transition exactly once, or rolls it back; an uncertain response is resolved
   only by exact idempotent retry.

Verifier acceptance alone never authorizes a payment. A database write without verifier acceptance is forbidden.

## LB-006 local transactional reference

`app/production_boundary.py` defines the verifier-to-storage operation shape, while
`app/transactional_database_boundary.py` implements the Phase 2 SQLite reference. The reference
persists the exact verifier identities, sequence, strong nullifier root, strong payment-state root,
authenticated submitter, state binding, replay keys, and chained audit event in one
`BEGIN IMMEDIATE` transaction. The state binding authenticates the exact submitter; the audit event
stores only its domain-separated commitment and the verifier-authorized operation digest. Exact
retries return the original durable receipt; conflicting retries, stale roots, reused nullifier
roots, partial writes, configuration drift, and post-verification mutation fail closed.

After native receipt verification, `TransactionalSettlementV2` MAC-authenticates the operation with
a fresh per-settlement key bound once to that store. There is no deterministic public factory or
public storage-commit method. This closes the supported request-path bypass and mutation boundary;
it is not a claim that Python-private objects isolate malicious code already executing inside the
trusted application process.

When an external anti-rollback port is configured, it write-ahead reserves the exact expected and
next anchor states plus transition commitment before SQLite commit, then finalizes after commit. A
pre-commit failure leaves only that exact transition replayable. A post-commit finalization failure
returns an explicit indeterminate error; exact retry finalizes the reservation and returns the one
durable receipt without advancing state again. A competing transition or older database remains
fail closed. Delayed duplicate finalization remains idempotent even after a later transition. The
external port must make its snapshot, prepare, and finalize operations atomic, retain enough
finalized-transition history for idempotency, and be independently durable for this property to
carry into production.

The reference also exercises online backup, restore into a new database file, process restart,
append-only audit verification, and an external anti-rollback port. The native artifact identity is
the SHA3-512-domain-separated commitment to the exact verifier executable and AIR program bytes and
is rechecked before every invocation. A real Rust candidate proof reaches this database path in the
bounded end-to-end test.

This closes LB-006 only as local, synthetic, nonactivating Phase 2 evidence. SQLite is not selected
as the production database, the in-memory anti-rollback state machine is not durable custody, and no
production proof suite, PHI, payment rail, credential, audit acceptance, or activation is implied.

## LB-007 Privacy V2 migration reference

`app/privacy_v2_migration.py` and the schema-v2 extension of
`app/transactional_database_boundary.py` implement the local Privacy V2 migration boundary. A
fresh migration requires sealed OS-random evidence and acceptance by the pinned native verifier.
The database then rechecks the exact source configuration inside `BEGIN IMMEDIATE` and atomically
records the new profile, schema, verifier, epoch/domain, roots, state binding, migration ledger,
configuration history, and audit event. Old-profile races, conflicting retries, manually constructed
fresh evidence, reused rollback/recovery domains, partial writes, and restored older state fail
closed. An exact recorded retry may reconstruct its evidence after process restart and cannot
advance state twice.

The qualification lane uses a fixed 64 MiB version-2 proof package so public-coin query
de-duplication cannot expose a variable external proof length. Two real dual-PQ authenticated Rust
proofs from different private witnesses independently verified with identical public shape; one
committed through SQLite and the conflicting transition was rejected without a second state
advance. Public artifacts were scanned for the private amount, decision, PHI, claim, and replacement
values.

This closes LB-007 only for local, synthetic, nonactivating Phase 2 migration evidence. It does not
select a production proof suite, database, entropy authority, anti-rollback service, or custody
system, and it does not authorize real PHI or payments.

## What the selected proof must establish

The complete selected proof must establish that a hidden, fixed-shape witness satisfies the pinned
claim program: source/signature checks included by the relation, policy and ruleset evaluation,
replay protection, state transition, value conservation, and settlement commitment. It may reveal
only the frozen public fields and authenticated sidecar.

The current `BLPQENV1` version-2 native lane independently verifies one pinned selected AIR/FRI
package and its authenticated transcript. It does not yet contain the complete semantic-bus,
typed-state, H4/GKR/Construction-8.2, and proof-native equality composition. It is component and
LB-007 migration evidence, not the complete claim-proof theorem or an audit-pending release.

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
