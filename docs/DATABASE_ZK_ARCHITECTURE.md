# Clearance database + conditional mandatory-ZK architecture

Status: authoritative transaction boundary; proof boundary is `NATIVE_V3_ARCHITECTURE.md`
Updated: 2026-09-05
Owner: this document defines the verifier-to-database, retry, recovery, migration, and
anti-rollback boundary. It does not select a backend or claim production persistence.

## Boundary

Blind Ledger owns state-local clearance state; the incumbent adjudicates claims and the official
payment system moves money. Exactly three evidence modes are selected by a verifier-owned,
state-approved control set before admission, with no caller-selected downgrade or runtime fallback:
`DIRECT_STATE_OWNED` for lawfully held canonical plaintext, `AUTHORITATIVE_ASSERTION` for a
qualified operation-scoped source assertion, and `PRIVATE_ZK` for a hidden source-bound predicate.

This transaction boundary consumes only the mode-specific, non-dispositive evidence result. It
retains no source, proof, signature, or stable digest; it does not select a backend, reverify
destroyed artifacts, or treat a source signature as truth. The exact source-auth, representation,
zero-PHI, privacy, PQ, and resource contract is owned by
`docs/NATIVE_V3_ARCHITECTURE.md`. Hidden payment-relevant evidence requires the qualified
`PRIVATE_ZK` path; lawfully held plaintext uses `DIRECT_STATE_OWNED` without purposeless ceremony.

Provider App preflight and the read-only Mirror/Provider Trust Graph wedge may emit bounded evidence
artifacts, but neither creates a Blind Ledger clearance receipt or authorizes payment.

## Replacement boundary

The local database, export/restore, and support seams are production-shaped candidates for
state-owned persistence and custody adapters. A replacement must preserve canonical artifacts,
roots/order, exact retry/recovery, transactions, and zero-PHI support behavior; it must pass the
independent artifact/database, mutation, replay, recovery, resource, and KAT gates. This seam may
qualify for Mirror independently; private clearance still requires the Lean, Native-v3, and custody
gates recorded by their owners.

## Transaction boundary

### Queue/Proof Handoff Profile 11 clean break

The current Queue integration candidate is Profile 11 and remains unqualified, unselected,
nonactivating, and non-production. Profile 10 and earlier databases, artifact readers, filesystem
snapshot/refetch paths, proof-bound disposition receipts, migration, fallback, relabeling, and dual
acceptance are unsupported and fail closed. Native-v3 owns the exact Profile 11 identity, statement,
fingerprints, artifact pins, envelope/frame/IPC sizes, and complete-profile gates.

State creates exactly 100 fresh state-generated random 32-byte operation references per batch. Queue
data contains only those opaque references and positions, the state-issued allowlisted
assertion/profile/version, validity window, ordered batch root, optional source-registry root,
chronology/status/retry data, and qualification flags. Caller job IDs, paths, claimant/provider
identity, raw-data digests, acceptance bytes, and process-output hashes never enter the proof
workspace, Queue/State DB, WAL, receipts, events, exports, backups, logs, or errors.

The ownership chain is source-local prover -> optional aggregator -> independent verifier -> state
owner -> opaque-reference/directive outbox and ACK -> audit/recovery. State first issues the immutable
template, exact ordered references, and complete batch statement in `AWAITING_HANDOFF`, then computes
the ordered root. Queue accepts one exact mutable `bytearray`, copies it into a bounded single-use
handoff, clears the caller buffer, and moves to `QUEUED`; the verifier receives only that sealed
handoff. Timeout, crash, lease expiry, restart, transport failure, or ambiguity consumes it and
fails closed to `HELD` with `fresh_handoff_required`; retry needs a new state operation and handoff.
The handoff is volatile, and the deployed zero-PHI recoverability gate remains Native-v3-owned; the
current experimental handling does not establish destruction.

Before cryptographic acceptance, the state owner atomically reserves each theorem-relevant acceptance
unit against the selected profile's single lifetime budget. Queue V11 reserves exactly 101 units per
claimed batch. The reservation may record the operative key epoch for nested operational caps and
audit, but retries, post-challenge aborts, malformed candidate verification, crashes after
reservation, coordination loss, overflow, exhaustion, and ambiguous cardinality fail closed; no
reservation is refunded or reset by key rotation. Only a genuinely new, separately requalified
profile gets a separate budget, and any cross-profile or system-lifetime claim must union all
profiles explicitly. Native-v3 owns unit counting and the theorem ledger; this document owns
reservation and transaction semantics.

The database accepts only a mode-specific, non-dispositive evidence result. It never receives
`policyResult` or `effectiveDirective` from a verifier or source. The state owner resolves
`PASS`/`MISSING`/`AMBIGUOUS`/`FAIL` to exactly `CLEAR`, `HOLD`, `HUMAN_REVIEW`, `BLOCK`, or
`EXCEPTION_APPROVED`; proof or signature acceptance alone never creates `CLEAR`. A complete batch is
preflighted against one snapshot and atomically commits its composition rows, events, state roots,
and outbox rows; mixed `APPLIED`/`HELD` images, stale roots, duplicates, conflicting retries, partial
batches, and any Rust/Lean disagreement reject.

The current Profile 11 statement does not carry the complete proposed/authorized amount contract,
Lean is not linked, and the official receiver is synthetic. A breaking revision must fail closed
until a reviewed version binds the new amount and canonical state identifiers. For a future qualified
private batch, the service must select the governed source/control/schema/program context, native
verification must return only its allowlisted receipt, and consumed nullifiers, stale roots,
duplicates, and partial batches must reject. The state owner must resolve disposition and recheck
roots/epochs in one serializable transaction; the later Lean gate must accept the exact receipt and
transition; commit/rollback must be resolved only by exact idempotent retry without proof reuse.
Acceptance never proves that funds moved; the official payment system consumes the accepted state
directive and reports the outcome to Mirror.

## Directive transition rules

| Effective directive | Required state-owned condition (with accepted selected-mode evidence where applicable) | Clearance/economic mutation |
| --- | --- | --- |
| `CLEAR` | Accepted proof where required, state `policyResult=PASS`, and no state exception is present. | Advance replay/audit state and exact authorized clearance state. |
| `HOLD` | Accepted proof where required and state `policyResult=MISSING`; a fixable requirement is missing. | Advance replay/audit state only. |
| `HUMAN_REVIEW` | Accepted proof where required and state `policyResult=AMBIGUOUS`; judgment, ambiguity, or additional evidence is required. | Advance replay/audit state only. |
| `BLOCK` | Accepted proof where required and state `policyResult=FAIL` without state exception; a selected prohibition holds. | Advance replay/audit state only. |
| `EXCEPTION_APPROVED` | Accepted proof where required, state `policyResult=FAIL`, and a registered state exception authorizes the scoped override. | Advance replay/audit state and only the clearance allowed by that authorization. |

In the table, “accepted proof where required” applies only to `PRIVATE_ZK`; the direct state-owned
evaluation or authoritative source-signature/assertion result is the corresponding non-dispositive
evidence input in the other two modes. The state-owned `policyResult` and exception control still
determine the directive in every mode.

As a required contract, every admitted attempt uses the same fixed observable replay/audit shape
across all five directives, including `HOLD`, `HUMAN_REVIEW`, `BLOCK`, and `EXCEPTION_APPROVED`;
non-`CLEAR` outcomes do not skip or reshape replay/audit state. This requirement is not a claim
that the current experimental implementation is deployed or qualified.

The no-exception case uses a canonical domain-separated nonzero sentinel so every row has the same
shape. Operative `EXCEPTION_APPROVED` additionally requires a separately governed, signed, immutable
exception-authorization record bound to the exact rule, reason, approver authority, scope, amount,
and expiry, while preserving the underlying `policyResult`. Native proof acceptance remains
non-dispositive and cannot substitute for that authorization. An emergency continuity action is a
separate signed and expiring human override transaction, not a parser fallback or a failed proof
converted to `CLEAR`. Mirror records the underlying result, override, final payment outcome, and
any Blind Ledger failure.

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

Lean 4 is the authorized executable authority for clearance meaning and the legal local transition.
Lean source and an adapter exist in separate earlier semantic checkouts, but no accepted executable
Lean artifact is implemented and linked in this candidate's synthetic transaction boundary. Before
direct or private clearance authority,
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

`app/transactional_database_boundary.py` is the current local owner of the compatibility seam. It
must preserve one atomic clearance-state mutation, exact receipt identities, idempotent retry,
concurrency rejection, anti-rollback, backup/restore, explicit version handling, append-only audit,
and zero-PHI support behavior. The focused direct-state evidence is
`tests/test_direct_state_owned_clearance_v1.py`; it is synthetic compatibility evidence and does not
select a proof backend or imply production persistence.

The recovery contract is: reserve the exact expected and next anchors before commit, finalize after
commit, return an explicit indeterminate result on post-commit finalization failure, and resolve it
only by exact idempotent retry. Competing transitions, stale roots, older databases, partial writes,
and configuration drift fail closed. Backup/restore and restart must retain the same decision,
receipt, audit, and anti-rollback identities.

The integrated Cleanup source at commit `f53b4230bfa61a5fc87c17964d49e4c70cb92c12` intentionally
changes the transactional database boundary from schema version 3 to 4. Its version check rejects
an existing V3 direct-state-owned database or backup with `database_schema_version_mismatch` before
schema creation or PRAGMA work; it has no automatic migration, deletion, fallback, or compatibility
reader. This is an intentional nonactivating clean break. V3 source/backup byte preservation on
rejection and V4 retry/recovery are required integration evidence; no cross-version storage
compatibility, operational migration, production persistence, or real-data upgrade is claimed.

## Evidence and proof boundary

No production proof is selected: `proofSuiteId=null`, `production_usable=false`, and
`selection_status=UNSELECTED`. A future private proof may establish only its hidden assertion and
state-issued challenge; the verifier returns an opaque receipt. Policy/disposition, exception
approval, ordered reads/writes, replay, value conservation, and legal transition remain state/Lean
responsibilities, and no source identity or witness material may be revealed. Governed ingestion
checks source signatures over canonical bytes before registry publication; a prover-supplied root is
not authoritative. Retired backends remain history, not current release or readiness inputs.

## Native-v3 handoff

`docs/NATIVE_V3_ARCHITECTURE.md` is the sole authority for source-auth profiles, representation,
public allowlist, privacy/PQ, acceptance accounting, theorem composition, resource limits, and
zero-PHI recoverability. This document enforces their state-side consequences: one non-dispositive
evidence result, reservation before acceptance work, one atomic transaction, and fail-closed retry.

## Qualification measurement handoff

Native-v3 owns complete-profile measurement and exact resource rules. This boundary supplies only
independently attributable state-transaction and outbox/ACK evidence; component or cached results
cannot become complete-profile credit.

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

## Dependency boundary

The next semantic dependency is the authorized Lean workstream described in
`docs/LEAN_FORMAL_KERNEL.md`; the roadmap owns its order. This document owns the database
transaction, retry, recovery, migration, and checkpoint consequences and does not make a
production, proof-backend, payment, or activation claim.
