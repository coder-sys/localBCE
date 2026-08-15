# Clearance database + conditional mandatory-ZK architecture

Status: authoritative transaction boundary; proof boundary is `NATIVE_V3_ARCHITECTURE.md`
Updated: 2026-08-14

## Product rule

Blind Ledger controls a state-local clearance decision; it does not adjudicate the full claim or
move money. The official processor and payment system retain those functions.
No payment state transition occurs inside Blind Ledger; it owns clearance state only.

When hidden evidence crosses the clearance trust boundary and affects an automated payment
directive, no clearance-state transition occurs unless a mandatory zero-knowledge proof has been
accepted by the pinned native verifier and the resulting update commits in one atomic database transaction.
When the state clearance service already lawfully holds all required evidence in
plaintext, it uses the same approved deterministic rule artifact and atomic state machine without
adding a purposeless ZK wrapper.

The verifier-owned automatic control set fixes `evidenceMode` as `PRIVATE_ZK` or
`DIRECT_STATE_OWNED` before request admission and binds the authorized proof verifier or direct
evaluator identity. They use distinct execution contexts. A caller cannot select the weaker mode,
and a missing or failed private proof can never retry as direct merely by changing a flag. The
native-v3 work in this repository qualifies only `PRIVATE_ZK`; a production direct evaluator is a
separate unselected trust-critical component.

Ordinary Provider App preflight may check completeness and formatting locally and may emit a small
state-verifiable receipt. It does not create a Blind Ledger clearance receipt and cannot authorize
payment.

The first commercial provider-continuity wedge is likewise read-only, but it belongs externally to
Mirror's Provider Trust Graph. It emits evidence findings, source coverage, remediation/retest,
parity, and transition artifacts rather than an operative Blind Ledger directive. The five-directive
five-directive continuity module is an internal clearance-semantics harness, not that external API.

## Production-shaped patch-in contract

The local database, export/restore, and support seams are production-shaped candidates for a
state-owned persistence and custody adapter. Their invariant interface is the canonical artifact
grammar, derived logical chain identity, immutable event/receipt roots, exact retry and recovery,
state-owned export/restore, and zero-PHI support boundary. A production adapter substitutes durable
custody, deployment, key/authentication, and operational controls while preserving those identities,
ordering, transactions, and fail-closed behavior. Qualification reruns the same independent
artifact/database checks, mutation/replay/recovery tests, resource gates, and canonical KATs; a
semantic or state-interface rewrite is architecture review, not integration.

This persistence seam can qualify for the read-only provider-continuity wedge independently of the
private-payment proof backend. The private clearance path still requires the Lean semantic kernel,
the theorem-qualified ZK backend, and a separately qualified production custody boundary. Current
qualification and nonclaims are authoritative in `STATE.md` and `CURRENT_TASK.md`.

## Transaction boundary

For each batch, the service:

1. receives a canonical native-v3 statement and fixed-profile proof envelope for the private-proof
   path;
2. selects verifier-owned source-registry, exact automatic-control-set, governance, schema, program,
   and candidate-suite context;
3. verifies the mandatory zero-knowledge proof with the native verifier;
4. opens or continues a serializable transaction;
5. rechecks the batch nonce, state-before roots, governance roots, and anti-rollback epoch;
6. rejects consumed nullifiers, stale roots, duplicates, or conflicting retries;
7. validates the proof-bound typed receipt and its underlying policy result, effective directive,
   exception authorization or sentinel, and exact amount/decision-path commitments;
8. submits the exact canonical semantic receipt and proposed transition to the executable Lean
   kernel; a missing kernel result, decoding error, theorem-version mismatch, or Rust/Lean
   disagreement rejects;
9. writes the state-after roots, clearance commitment, and audit event; economic clearance may
   advance only for `CLEAR` or a valid `EXCEPTION_APPROVED`;
10. commits the database transition exactly once, or rolls it back; an uncertain response is resolved
   only by exact idempotent retry.

Verifier acceptance alone is never interpreted as `CLEAR` and never proves that funds moved. A
private-path database write without verifier acceptance is forbidden. The official state payment
system consumes an accepted clearance directive and later returns the actual outcome to Mirror.

## Directive transition rules

| Effective directive | Required proof-bound condition | Clearance/economic mutation |
| --- | --- | --- |
| `CLEAR` | Underlying deterministic result is `CLEAR`; no exception is present. | Advance replay/audit state and exact authorized clearance state. |
| `HOLD` | A fixable deterministic requirement is missing and authoritative completeness/nonmembership covers that absence. | Advance replay/audit state only. |
| `HUMAN_REVIEW` | Judgment, ambiguity, incomplete evidence, unavailable authority, unresolved rule conflict, or additional evidence is required. | Advance replay/audit state only. |
| `BLOCK` | A selected deterministic prohibition holds, including any absence backed by authoritative completeness/nonmembership. | Advance replay/audit state only. |
| `EXCEPTION_APPROVED` | A registered signed state authorization covers the underlying result, subject, rule, amount, time, and scope. | Advance replay/audit state and only the clearance allowed by that authorization. |

The no-exception case uses a canonical domain-separated nonzero sentinel so every row has the same
shape. An emergency continuity action is a separate signed and expiring human override transaction,
not a parser fallback or a failed proof converted to `CLEAR`. Mirror records the underlying result,
override, final payment outcome, and any Blind Ledger failure.

The exact automatic control set is verifier-owned and binds rule order, priority/conflict handling,
directive mapping, scope, and effective interval. A prover cannot choose a favorable subset. Event,
observation, rule-effective, and decision times are distinct canonical values and remain stable
across retry. A negative fact cannot authorize `HOLD` or `BLOCK` merely because a record is absent
from an incomplete feed.

## Formal semantic boundary

Lean 4 is the approved executable authority for clearance meaning and the legal local transition.
The kernel covers bounded canonical semantic decoding, the five directives,
`policyResult`/`effectiveDirective` separation, control sets, authoritative absence, chronology,
governed exceptions, observation-only separation, replay, exact decision/access joins, and allowed
after-state. It does not own database serializability, durability, crash recovery, source truth, or
cryptographic proof soundness.

For `PRIVATE_ZK`, Rust cryptographic proof acceptance is necessary before the Lean check. For
`DIRECT_STATE_OWNED`, the Lean kernel evaluates the canonical governed plaintext input directly.
Both paths use distinct verifier-owned execution contexts, and no caller can select, downgrade, or
promote them. The database commits only a transition accepted by the appropriate cryptographic
boundary, the Lean kernel, and its own current-state/concurrency checks.

The kernel is not implemented. `LEAN_FORMAL_KERNEL.md` defines the required executable
correspondence, theorem manifest, axiom inventory, independent kernel check, and CI gates. Current
Python/Rust KAT agreement must not be described as deployed formal verification.

## Retained LB-006 local transactional reference

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

This reference is a local candidate evidence seam. The production persistence/custody adapter,
source authentication, and activation gates remain separately qualified; current status and
nonclaims are authoritative in `STATE.md`. The canonical transaction, retry, recovery, and
zero-PHI support interfaces are intended to remain unchanged.

## Retained LB-007 Privacy V2 migration reference

This is historical migration/regression evidence for the superseded Privacy V2 boundary. It is not
the native-v3 migration plan and does not constrain its statement or package shape.

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

The complete selected proof must establish that a hidden, fixed-profile witness satisfies the
pinned clearance program: membership in verifier-owned immutable source/governance registries,
policy and ruleset evaluation, the underlying result and effective five-value directive, any
exception authorization, exact ordered state reads/writes, replay protection, value conservation,
and the bound state/clearance transition. It may reveal only the canonical native-v3 statement;
the state-local typed directive is returned only in the proof-bound verifier receipt.

Governed ingestion verifies source signatures over exact canonical bytes once, before registry
publication. Repeating public signature verification inside every proof is unnecessary when private
membership in that authenticated registry is proved. A prover-supplied registry root is forbidden.

The retained `BLPQENV1` version-2 native lane independently verifies one pinned selected AIR/FRI
package and its authenticated transcript. It does not yet contain the complete semantic-bus,
typed-state, H4/GKR/Construction-8.2, and proof-native equality composition. It is component and
LB-007 migration evidence, not the complete claim-proof theorem or an audit-pending release.

It cannot establish that an authorized source told the truth, that the policy was wise or lawful, or that database operators preserved availability. Those are governance and operational trust boundaries.

## Cryptographic requirements

- Mandatory application ZK for an undisclosed payment-relevant assertion; no mandatory ZK ceremony
  when the state clearance boundary already owns all required plaintext evidence.
- Canonical fixed-profile native-v3 statement and privacy-safe observable behavior.
- SHA3-512 authoritative external identifiers over a proof-verified transparent PQ state
  commitment; no per-operation SHA3-tree requirement.
- A versioned, setup-free, non-ECC, natively hiding, independently verified proof backend with a
  CPU-only 16 GB consumer-laptop implementation.
- Transcript mode selected only with the exact backend theorem: QROM-covered Fiat-Shamir or a
  justified authenticated interactive coin.
- NIST-approved PQ signatures at Category 1 or stronger, algorithm-agile; stronger or dual
  signatures only when the deployment threat model requires them.
- Total per-proof statistical false acceptance at most `2^-128` after complete composition.
- Exact binding of proof, verifier, schema, policy, ruleset, source, underlying result, effective
  directive, exception authorization or sentinel, state-before, state-after, and clearance identities.
- One pinned executable Lean semantic/state-transition kernel linked fail-closed to the Rust
  verifier and database, with the required theorem/axiom/build gates.
- Fail-closed parsing, resource limits, retries, recovery, migration, and anti-rollback.
- At most 5,000,000,000 decimal bytes complete process-tree resident memory, scratch strictly below
  that value, and no proving-attributable swap/pagefile growth.

## External-chain boundary

Ethereum is not a dependency. No L2, rollup, sequencer, bridge, Solidity settlement contract, or
public data-availability layer is active.

A later phase may post one compact signed checkpoint or aggregate-proof commitment directly to
Ethereum L1 on a fixed governed cadence; one or two hours is a candidate operational interval, not
a frozen security parameter. The checkpoint binds the exact ordered accepted batch, control-set and
software identities, before/after state, prior checkpoint, exceptions, and interval. Full proofs
and audit material remain in state-controlled storage.

Posting a root proves public anchoring, not underlying correctness. Posting proof bytes does not
make Ethereum a verifier unless a separately qualified on-chain verifier checks the exact proof and
public inputs. Ethereum currently adds classical public timestamping and tamper evidence; it is not
the transparent post-quantum or non-ECC root of trust for Blind Ledger. The checkpoint must not
carry PHI, be the only durable copy, replace the operational database, authorize payment, or weaken
mandatory application verification.

## Phase boundary

- Phase 0: freeze native-v3 statement, typed five-directive receipt, source/exception-registry and
  state interfaces, threat model, and CPU baseline.
- Phase 1: accept the smallest complete native-v3 clearance proof and independent negative-test
  boundary, including wrong-directive and exception-authorization attacks.
- Phase 2: qualify fixed-profile batching and the atomic database transition locally with adversarial
  tests and reproducible complete-process evidence.
- Later: production database/custody integration, independent audit, operator activation, and
  optional L1 checkpoint design after its persistence, cost, verifier, key, and PQ-claim boundaries
  are separately qualified.
