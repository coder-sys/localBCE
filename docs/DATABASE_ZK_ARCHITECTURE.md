# Clearance database + conditional mandatory-ZK architecture

Status: authoritative transaction boundary; proof boundary is `NATIVE_V3_ARCHITECTURE.md`
Updated: 2026-08-14
Owner: this document defines the verifier-to-database, retry, recovery, migration, and
anti-rollback boundary. It does not select a backend or claim production persistence.

## Product rule

Blind Ledger controls a state-local clearance decision; it does not adjudicate the full claim or
move money. The official processor and payment system retain those functions.
No payment state transition occurs inside Blind Ledger; it owns clearance state only.

When an undisclosed payment-relevant assertion crosses the clearance trust boundary and affects
automation, no clearance-state transition occurs unless a mandatory zero-knowledge proof has been
accepted by the pinned native verifier and the resulting update commits in one atomic database transaction.
When the state clearance service already lawfully holds all required evidence in
plaintext, it uses the same approved deterministic rule artifact and atomic state machine without
adding a purposeless ZK wrapper.

The verifier-owned automatic control set fixes `evidenceMode` as `PRIVATE_ZK` or
`DIRECT_STATE_OWNED` before request admission and binds the authorized proof verifier or direct
evaluator identity. They use distinct execution contexts. A caller cannot select the weaker mode,
and a missing or failed private proof can never retry as direct merely by changing a flag. The
native-v3 private-clearance target is `PRIVATE_ZK`; the plaintext continuity harness is a separate
synthetic conformance path, and no production direct evaluator is selected.

Ordinary Provider App preflight may check completeness and formatting locally and may emit a small
state-verifiable receipt. It does not create a Blind Ledger clearance receipt and cannot authorize
payment.

The first commercial provider-continuity wedge is likewise read-only, but it belongs externally to
Mirror's Provider Trust Graph. It emits evidence findings, source coverage, remediation/retest,
parity, and transition artifacts rather than an operative Blind Ledger directive. The five-directive
continuity module is an internal clearance-semantics harness, not that external API.

## Production-shaped patch-in contract

The local database, export/restore, and support seams are production-shaped candidates for a
state-owned persistence and custody adapter. Their invariant interface is the canonical artifact
grammar, derived logical chain identity, immutable event/receipt roots, exact retry and recovery,
state-owned export/restore, and zero-PHI support boundary. A production adapter substitutes durable
custody, deployment, key/authentication, and operational controls while preserving those identities,
ordering, transactions, and fail-closed behavior. Qualification reruns the same independent
artifact/database checks, mutation/replay/recovery tests, resource gates, and canonical KATs; a
semantic or state-interface rewrite is architecture review, not integration.

This seam can qualify for the read-only wedge independently of the private-payment backend; the private clearance path still requires the later Lean, ZK, and custody gates. Status is in `STATE.md`.

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
8. reserves the exact canonical semantic receipt and proposed transition for the later mandatory
   Lean gate; the current nonactivating boundary has no Lean result, and any future missing result,
   decoding error, theorem-version mismatch, or Rust/Lean disagreement rejects;
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

The executable chronology is strict: `rule_effective < event < observation < decision`. These four
times are bound identically across the request, decision, verifier receipt, and exact retry. The
transaction admits one decision (`decision_index=0`) and exactly two accesses indexed `[0,1]`
(`access_count=2`); every access carries the matching `decision_id`. Reads occur at observation time,
and the clearance-state write occurs at decision time. The independent parser is the current checker
for the READ/WRITE row roles; the producer compatibility object is not semantic authority.

## Formal semantic boundary

Lean 4 is the later mandatory executable authority for clearance meaning and the legal local
transition. It is not an active dependency of the current synthetic transaction boundary: the kernel
is not implemented, linked, or production-qualified. Before direct or private clearance authority,
the future kernel must cover bounded decoding, the five directives, result separation, control sets,
authoritative absence, chronology, exceptions, observation-only separation, replay, exact joins, and
allowed after-state.

For a future `PRIVATE_ZK` path, Rust proof acceptance must precede the Lean check. For a future
direct path, the Lean kernel must evaluate the canonical governed plaintext input directly. These
are distinct verifier-owned execution contexts; no caller may select, downgrade, or promote them.
Current Python/Rust KATs and local database tests are evidence for the patch-in contract, not Lean
or production clearance authority.

`LEAN_FORMAL_KERNEL.md` defines the required executable correspondence, theorem manifest, axiom
inventory, independent kernel check, and CI gates. Current status and nonactivation remain in
`STATE.md` and `CURRENT_TASK.md`.

## Current recovery and compatibility evidence

`app/production_boundary.py` and `app/transactional_database_boundary.py` remain the tested local
owners of the current compatibility seam. They must preserve one atomic clearance-state mutation,
exact receipt identities, idempotent retry, concurrency rejection, anti-rollback, backup/restore,
migration, append-only audit, and zero-PHI support behavior.

The focused evidence is `tests/test_bl_pq512_production_boundary.py`,
`tests/test_bl_pq512_transactional_database_boundary.py`,
`tests/test_bl_pq512_transactional_privacy_v2_migration.py`,
`tests/attacks/test_bl_pq512_transactional_privacy_v2_migration_attacks.py`,
`tests/test_bl_pq512_built_audit_pending_release.py`, and the public-input, commitment, nullifier,
and custody tests named by the active-core map. These are synthetic compatibility regressions; they
do not select a proof backend or make historical package claims current.

The recovery contract is: reserve the exact expected and next anchors before commit, finalize after
commit, return an explicit indeterminate result on post-commit finalization failure, and resolve it
only by exact idempotent retry. Competing transitions, stale roots, older databases, partial writes,
and configuration drift fail closed. Backup/restore and restart must retain the same decision,
receipt, audit, and anti-rollback identities.

## What the selected proof must establish

No production proof is selected: the live verifier-selection sentinel is `proofSuiteId=null`,
`production_usable=false`, and `selection_status=UNSELECTED`. `DIRECT_STATE_OWNED` is a
verifier-owned synthetic continuity control-set identity, not a selected production evaluator.

The complete selected proof must establish that a hidden, fixed-profile witness satisfies the
pinned clearance program: membership in verifier-owned immutable source/governance registries,
policy and ruleset evaluation, the underlying result and effective five-value directive, any
exception authorization, exact ordered state reads/writes, replay protection, value conservation,
and the bound state/clearance transition. It may reveal only the canonical native-v3 statement;
the state-local typed directive is returned only in the proof-bound verifier receipt.

Governed ingestion verifies source signatures over exact canonical bytes once, before registry
publication. Repeating public signature verification inside every proof is unnecessary when private
membership in that authenticated registry is proved. A prover-supplied registry root is forbidden.

Retired backend implementations and detailed migration narratives remain available through Git
history and retained source archives. No current release or readiness path selects them; the live
verifier-selection contract remains explicitly `UNSELECTED` until an independently reviewed backend
is selected.

It cannot establish that an authorized source told the truth, that the policy was wise or lawful, or that database operators preserved availability. Those are governance and operational trust boundaries.

## Cryptographic requirements

- Mandatory application ZK when an undisclosed payment-relevant assertion crosses the clearance
  boundary and affects automation; no ceremony when the state boundary owns all required plaintext.
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

A committed later product phase may post one compact signed checkpoint or aggregate-proof commitment
directly to Ethereum L1. This is not a Phase 0-2 dependency, settlement role, L2, rollup, sequencer,
bridge, or payment rail. The posting cadence remains a governed deployment parameter and is not yet
fixed. The checkpoint binds the exact ordered accepted batch, control-set and software identities,
before/after state, prior checkpoint, exceptions, and interval. Full proofs and audit material remain
in state-controlled storage.

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
