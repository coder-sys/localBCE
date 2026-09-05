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
snapshot/refetch paths, and proof-bound disposition receipts are unsupported and fail closed; no
migration, compatibility reader, fallback, wrapper, relabeling, or dual path exists. Blind state creates
exactly 100 fresh state-generated random 32-byte operation references for each batch. Durable queue
data contains only those opaque references, their immutable positions, the shared state-issued
allowlisted assertion/profile/version, bounded validity window, ordered batch root, optional
approved-source registry root, chronology/status/retry data, and qualification flags. Caller job IDs,
artifact/source paths, patient/provider/case identity,
raw-data digests, acceptance bytes, and process-output hashes are not queue fields.

The Profile 11 candidate ownership chain is source-local prover -> optional aggregator -> independent verifier ->
state owner -> opaque-reference/directive outbox and ACK -> audit/recovery. Admission is two phase:
the state first issues an immutable allowlisted shared template, exactly 100 ordered opaque
references, and one complete batch statement in `AWAITING_HANDOFF`; it computes one domain-separated
ordered root from the exact references and shared template. Only after issuance may a caller submit
one exact mutable bytearray for that exact ordered batch; Queue copies it into a bounded,
memory-owned single-use handoff, clears the caller buffer, and transitions the batch to `QUEUED`.
The verifier receives that sealed handoff and the complete issued statement, never an unrelated
caller/reference argument. Native-v3 owns each selected
profile's envelope and process-tree safety constraints; there is no universal input-admission
allowance, and a not-yet-selected private profile remains inactive. No proof, source, signature,
commitment, verifier output, proof/signature/frame/statement bytes, exact proof/source digest, PHI,
temp/spill, or log bytes are written to a proof workspace, DB, WAL, receipt, event, export, backup,
or error. Authorized Queue/State DB, WAL, and commit writes remain limited to the state-owned fields
listed above. The owned handoff buffer is wiped in full on close. The exact deployed zero-PHI
recoverability gate is
owned by Native-v3; current experimental handling does not establish destruction. A timeout, crash,
lease expiry, restart, transport failure, or ambiguity consumes the handoff and fails closed to
`HELD` with bounded `fresh_handoff_required`; retry requires a new state operation and fresh
bytearray handoff.

Before cryptographic acceptance work, the state owner atomically reserves each theorem-relevant
acceptance unit against the selected security profile's single deployment/authorization-lifetime
budget. The reservation may record the operative key epoch for nested operational signature, message,
and query caps and audit, but key rotation never creates, resets, or refunds the statistical budget.
In Queue V11, one claimed batch reserves exactly 101 units. Retries, post-challenge aborts, malformed candidate verifications, and crashes after reservation
consume that reservation and never refund it. Loss of trustworthy coordination, overflow, budget or
cap exhaustion, or ambiguous batch cardinality fails closed. Only a genuinely new, separately
requalified security profile can establish a separately scoped budget; any cross-profile or
system-lifetime claim must explicitly bound and union all profiles. Native-v3 owns the exact
acceptance-unit counting and theorem ledger; this document owns the reservation and state-transaction
semantics.

For the current unqualified Profile 11 handoff, Native-v3 owns the exact verifier receipt allowlist. The
database accepts only a mode-specific, non-dispositive evidence result; it never receives a
`policyResult` or `effectiveDirective` from the verifier or source. `DIRECT_STATE_OWNED` and
`AUTHORITATIVE_ASSERTION` use their separate mode-specific state-evaluation or qualified
source-signature/assertion result; none is a disposition. The state owner separately controls
`PASS`, `MISSING`, `AMBIGUOUS`, or `FAIL` and resolves exactly `CLEAR`, `HOLD`, `HUMAN_REVIEW`,
`BLOCK`, or `EXCEPTION_APPROVED`; proof or signature acceptance alone can never create `CLEAR`. A
complete promotion batch is preflighted against one state snapshot and commits all composition
rows, events, state roots, and outbox rows in one transaction. A mixed APPLIED/HELD persisted image
is independently rejected.

The current Profile 11 Queue/Native proof boundary is mechanically interoperable at the handoff but
cryptographically unqualified: `proofSuiteId=null`, `production_usable=false`,
`activation=false`, no backend is selected or qualified, and the co-equal Native-v3 profile gates
remain open. Native-v3 is the sole authority for the exact current Profile 11 identity, statement
and fingerprints, artifact pins, and envelope/frame/IPC sizes. Proof acceptance yields only an opaque
scoped verification outcome and never `CLEAR`; State alone owns chronology, `policyResult`,
`effectiveDirective`, exceptions, disposition, retries, and economic state.

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

The current nonactivating Profile 11 candidate implementation separates the source/prover, optional aggregation,
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

Lean 4 is the authorized next executable authority for clearance meaning and the legal local
transition. It is not implemented, linked, or production-qualified in the current synthetic
transaction boundary. Before direct or private clearance authority,
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
