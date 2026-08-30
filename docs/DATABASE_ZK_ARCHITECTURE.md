# Clearance database + conditional mandatory-ZK architecture

Status: authoritative transaction boundary; proof boundary is `NATIVE_V3_ARCHITECTURE.md`
Updated: 2026-08-25
Owner: this document defines the verifier-to-database, retry, recovery, migration, and
anti-rollback boundary. It does not select a backend or claim production persistence.

## Product rule

Blind Ledger controls a state-local clearance decision; it does not adjudicate the full claim or
move money. The official processor and payment system retain those functions.
No payment state transition occurs inside Blind Ledger; it owns clearance state only.

Exactly three pre-admission evidence modes exist, selected by the state-approved verifier-owned
control set before request admission. There is no runtime fallback or downgrade between them:

1. `DIRECT_STATE_OWNED` evaluates canonical non-PHI facts that the state owner already lawfully
   holds; no signature or ZK wrapper is required merely to re-prove the state's own facts.
2. `AUTHORITATIVE_ASSERTION` consumes an operation-scoped, minimally disclosed derived assertion
   and its qualified source-signature result. That result establishes no disposition authority.
3. `PRIVATE_ZK` consumes a non-dispositive proof result for a hidden source-bound predicate under
   the Native-v3 source, statement, and representation contract.

The exact source-auth candidate/profile, private representation and raw-record link contract, source
artifact custody, and deployed zero-PHI recoverability gate are normative in
`docs/NATIVE_V3_ARCHITECTURE.md`. This transaction authority consumes only the resulting
mode-specific, non-dispositive evidence result and retains no source/proof/signature bytes or stable
digest. It does not select a backend, reverify destroyed source artifacts, or treat a source signature
as truth; signed unrelated dual commitments are not an equality bridge.

When an undisclosed payment-relevant assertion crosses the clearance trust boundary and affects
automation, only `PRIVATE_ZK` can satisfy that hidden-evidence requirement; no clearance-state
transition occurs unless the qualified verifier accepts the narrow assertion and the resulting
state-owned update commits in one atomic database transaction. When the state clearance service
already lawfully holds all required evidence in plaintext, `DIRECT_STATE_OWNED` uses the approved
deterministic rule artifact and atomic state machine without adding a purposeless ZK wrapper.
`AUTHORITATIVE_ASSERTION` has its own qualified source-signature profile and does not wait on a
private-proof backend. A caller cannot select a weaker mode, and a failed mode cannot retry under a
different mode by changing a flag.

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

### Queue/Proof Handoff Profile 9 clean break

The current Queue integration candidate is Profile 9 and remains unqualified, unselected,
nonactivating, and non-production. Profile 6/7/8 databases, artifact readers, filesystem
snapshot/refetch paths, and proof-bound disposition receipts are unsupported and fail closed; no
migration, compatibility reader, fallback, wrapper, relabeling, or dual path exists. Blind state creates a
exactly 100 fresh state-generated random 32-byte operation references for each batch. Durable queue
data contains only those opaque references, their immutable positions, the shared state-issued
allowlisted assertion/profile/version, bounded validity window, ordered batch root, optional
approved-source registry root, chronology/status/retry data, and qualification flags. Caller job IDs,
artifact/source paths, patient/provider/case identity,
raw-data digests, acceptance bytes, and process-output hashes are not queue fields.

The Profile 9 candidate ownership chain is source-local prover -> optional aggregator -> independent verifier ->
state owner -> opaque-reference/directive outbox and ACK -> audit/recovery. Admission is two phase:
the state first issues an immutable allowlisted shared template, exactly 100 ordered opaque
references, and one complete batch statement in `AWAITING_HANDOFF`; it computes one domain-separated
ordered root from the exact references and shared template. Only after issuance may a caller submit
the single-use readable binary stream for that exact ordered batch, transitioning it to `QUEUED`. The verifier receives that stream and the complete issued
statement, never an unrelated caller/reference argument. The verifier receives a
readable binary stream through one volatile single-use handoff. Native-v3 owns each selected
profile's envelope and process-tree safety constraints; there is no universal input-admission
allowance, and a not-yet-selected private profile remains inactive. No proof, source, signature,
commitment, or verifier output bytes are written to a proof workspace, DB, receipt, event, log, export,
backup, or error. Mutable staging is wiped where technically possible. The exact deployed zero-PHI
recoverability gate is
owned by Native-v3; current experimental handling does not establish destruction. A timeout, crash,
lease expiry, restart, transport failure, or ambiguity consumes the handoff and fails closed to
`HELD` with bounded `fresh_handoff_required`; retry requires a new state operation and fresh stream.

Before cryptographic acceptance work, the state owner atomically reserves each theorem-relevant
acceptance unit against the selected security profile's single deployment/authorization-lifetime
budget. The reservation may record the operative key epoch for nested operational signature, message,
and query caps and audit, but key rotation never creates, resets, or refunds the statistical budget.
Retries, post-challenge aborts, malformed candidate verifications, and crashes after reservation
consume that reservation and never refund it. Loss of trustworthy coordination, overflow, budget or
cap exhaustion, or ambiguous batch cardinality fails closed. Only a genuinely new, separately
requalified security profile can establish a separately scoped budget; any cross-profile or
system-lifetime claim must explicitly bound and union all profiles. Native-v3 owns the exact
acceptance-unit counting and theorem ledger; this document owns the reservation and state-transaction
semantics.

For the current unqualified Profile 9 handoff, Native-v3 owns the exact verifier receipt allowlist. The
database accepts only a mode-specific, non-dispositive evidence result; it never receives a
`policyResult` or `effectiveDirective` from the verifier or source. `DIRECT_STATE_OWNED` and
`AUTHORITATIVE_ASSERTION` use their separate mode-specific state-evaluation or qualified
source-signature/assertion result; none is a disposition. The state owner separately controls
`PASS`, `MISSING`, `AMBIGUOUS`, or `FAIL` and resolves exactly `CLEAR`, `HOLD`, `HUMAN_REVIEW`,
`BLOCK`, or `EXCEPTION_APPROVED`; proof or signature acceptance alone can never create `CLEAR`. A
complete promotion batch is preflighted against one state snapshot and commits all composition
rows, events, state roots, and outbox rows in one transaction. A mixed APPLIED/HELD persisted image
is independently rejected.

This Profile 9 boundary remains synthetic/experimental and unqualified: `proofSuiteId=null`,
`production_usable=false`, `activation=false`, no backend is selected or qualified, the final C
source-auth process binding and executable identity are pending, and the co-equal Native-v3
profile gates remain open. The accepted Rust protocol authority is commit
`28f9f6765efd22aba2135df842a757f8ef4468a3` with tree
`99b64f421ec5bd7679f9b44d06e04c745592a390`.

For a future qualified private batch, the service will:

1. receive a canonical native-v3 statement and fixed-profile proof envelope for the private-proof
   path;
2. select governed source-registry, automatic-control-set, governance, schema, program, and
   candidate-suite context;
3. verify the mandatory zero-knowledge proof with the native verifier, returning only the minimal
   allowlisted receipt;
4. let the state owner resolve its separate disposition control and preflight the complete ordered
   state chain against one snapshot;
5. open one serializable transaction only after preflight, rechecking state-before roots,
   governance roots, and anti-rollback epoch;
6. reject consumed nullifiers, stale roots, duplicates, conflicting retries, and partial batches;
7. pass only proof acceptance to the state owner; policy result, exception approval, effective
   directive, exact amount, and decision-path state remain state-owned rather than proof-supplied;
8. reserve the exact canonical state receipt and proposed transition for the later mandatory Lean
   gate; the current nonactivating boundary has no Lean result, and any future missing result,
   decoding error, theorem-version mismatch, or Rust/Lean disagreement rejects;
9. write state-after roots, the state-owned clearance commitment, and the audit event; economic
   clearance may advance only for `CLEAR` or a valid `EXCEPTION_APPROVED`;
10. commit the database transition exactly once, or roll it back; an uncertain response is resolved
    only by exact idempotent retry without proof reuse.

Verifier acceptance alone is never interpreted as `CLEAR` and never proves that funds moved. A
private-path database write without verifier acceptance is forbidden. The official state payment
system consumes an accepted clearance directive and later returns the actual outcome to Mirror.

## Current experimental application chain

The current nonactivating Profile 9 candidate implementation separates the source/prover, optional aggregation,
independent verifier, state-owned disposition, durable composition/outbox, and audit/recovery
owners. Queue promotion uses a one-use volatile handoff; it never refetches proof bytes. The
state owner, not the verifier, preserves `policyResult` separately from `effectiveDirective`, and
the opaque outbox cannot mutate payment, settlement, or official-system state.

This chain is not yet the production transaction described above. Its current native statement
does not carry the complete proposed/authorized amount contract, Lean is not linked, and the
official receiver is synthetic. The next breaking native revision must fail closed at the current
composition boundary; a separately reviewed composition version must then bind the new authorized
amount and canonical state identifiers rather than silently accepting the old grammar.

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
the public-input, commitment, nullifier,
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

The complete selected proof must eventually establish the hidden assertion and its authenticated
state-issued challenge under the future qualified contract. The verifier returns only proof
acceptance and a narrow opaque receipt; state-owned policy/disposition control, exception approval,
ordered state reads/writes, replay protection, value conservation, and the legal transition remain
state/Lean responsibilities. It may reveal no source identity or raw witness material.

Governed ingestion verifies source signatures over exact canonical bytes once, before registry
publication. Repeating public signature verification inside every proof is unnecessary when private
membership in that authenticated registry is proved. A prover-supplied registry root is forbidden.

Retired backend implementations and detailed migration narratives remain available through Git
history and retained source archives. No current release or readiness path selects them; the live
verifier-selection contract remains explicitly `UNSELECTED` until an independently reviewed backend
is selected.

It cannot establish that an authorized source told the truth, that the policy was wise or lawful, or that database operators preserved availability. Those are governance and operational trust boundaries.

## Native-v3 cryptographic authority

`docs/NATIVE_V3_ARCHITECTURE.md` is the sole authority for source-auth profiles, private
representation and raw-record linking, the strict public allowlist, cryptographic privacy/setup/PQ
requirements, finite acceptance accounting, theorem composition, exact resource limits, and the
deployed zero-PHI recoverability gate. This document does not restate those profile or mathematical
rules. The database instead enforces their state-side consequences: one mode-specific,
non-dispositive evidence result, atomic reservation before acceptance work, one atomic state
transaction, and fail-closed retry/recovery.

## Qualification measurement handoff

Native-v3 owns the complete-profile measurement boundary and exact SLO/resource rules. This
document supplies independently attributable evidence for the state-transaction and outbox/ACK
stages, while preserving atomicity, recovery, and zero-PHI semantics. Component or cached results
cannot be promoted to complete-profile credit.

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
  state interfaces, threat model, and the declared laptop-class state-side reference/resource
  baseline.
- Phase 1: accept the smallest complete native-v3 clearance proof and independent negative-test
  boundary, including wrong-directive and exception-authorization attacks.
- Phase 2: qualify fixed-profile batching and the atomic database transition locally with adversarial
  tests and reproducible complete-process evidence.
- Later: production database/custody integration, independent audit, operator activation, and
  optional L1 checkpoint design after its persistence, cost, verifier, key, and PQ-claim boundaries
  are separately qualified.
