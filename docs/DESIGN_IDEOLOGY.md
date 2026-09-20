# Blind Ledger design ideology

Updated: 2026-09-20. Owner: independent design contract for the smallest
correct implementation, deterministic evidence, bounded resources, modular
ownership, and fail-closed execution. It cannot override `AGENTS.md`,
`CURRENT_TASK.md`, or `STATE.md`.

## Invariant first

Start with the property that must be true for a decision to be safe. Derive
the smallest implementation that makes that property executable and
independently checkable. A historical workflow, benchmark, digest, caller
boolean, or green gate is not authority merely because it exists.

Gates protect invariants but are not the invariants themselves. If evidence
shows a gate is stale, over-broad, or non-applicable, record its exact
predicate, protected failure mode, raw reason, replacement control, scope,
duration, and claim consequence. Never silently bypass a gate, accept a
malformed proof, weaken atomic mutation, or relabel a nonqualifying result.

## Small trusted core and modular interfaces

Prefer one canonical owner, a small trusted state machine, narrow versioned
interfaces, and independently reconstructed boundaries. Every module must state
what it owns, what it receives, what it may mutate, and which evidence proves
the boundary. Do not introduce a second ledger, speculative orchestration
layer, or duplicate receipt format to compensate for an unresolved contract.

For the current financial workflow, the Python v5 owner remains the sole
transaction authority. Mirror is a caller/read model; Continuity is a bounded
SHADOW/TEST handoff; Queue reservations and claimed-adjustment business state
remain separate. State owns rules, authority, policy transitions, and official
consequences.

## Evidence, authority, and state

Typed evidence, official determination, authorized action, dispatch/
acknowledgment, and cash/reporting completion are different facts. A receipt
binds the exact scope, revision, rule/control-pack identity, evidence
references/digests, authority, result fields, and digest domains it claims; it
does not become source truth or payment confirmation.

Missing, stale, malformed, ambiguous, or unauthorized authority fails closed.
No caller-selected fallback may downgrade a required evidence mode. Policy,
effective directives, exceptions, chronology, state mutation, and payment
remain state-owned even when a verifier or proof supplies an evidence result.

## Persistence, recovery, and retries

The durable transition is one atomic write of history, current projection, and
action/outbox identity. Every command has an explicit identity, expected
revision, canonical payload, and retry rule. Exact retries are duplicates;
changed identity or input is conflict. Recovery must prove behavior both when a
process exits before COMMIT and when the committed result is lost before the
caller receives it. Restart and independent verification are part of the
contract, not optional operational decoration.

Continuity restore is bounded and isolated. SHADOW is read-only; TEST is
non-live; dispatch and egress stay disabled; source bytes and owner identity
remain protected. A restored package is not allowed to promote itself into a
live writer or replace an existing identity. The current v5 restore uses a
private attempt directory and atomic no-replace publication, so cleanup can
remove only an owned attempt or an owned published identity; foreign
destinations and sidecars remain intact, and cleanup failures are visible.

## Determinism and adversarial simplicity

Use explicit inputs, integer amounts, versioned schemas, stable ordering,
bounded parsing, and manually derived expected values. Make corruption,
omission, duplication, replay, stale revision, wrong scope, cross-owner,
cross-period, and wrong-mode cases fail visibly. Prefer the simplest
falsifiable design; compare alternatives against mutation, replay, recovery,
resource, and whole-system evidence before adding machinery.

The accepted bounded Python v5 evidence follows the same rule: populated
evaluation receipts are independently reconstructed, determination failures
are checked for unchanged durable bytes, exact CLI retries are distinguished
from changed bindings, and the v2/v3/v4 matrix is labeled tag-only rejection
rather than historical-schema compatibility.

## Active Lean direction

The broader formal direction is to implement everything reasonably implementable
in Lean, with executable semantics and useful modularity. The first financial
step is an Engine extraction of the semantic core:

- a small trusted state and explicit deterministic state machines;
- narrow, versioned modular interfaces between evidence, policy, owner, and
  external systems;
- independent checks and fail-closed authority;
- explicit recovery, idempotency, and atomic history-projection-outbox
  properties; and
- a pinned executable Lean artifact linked to the working runtime only after
  refinement, theorem, adapter, mutation, KAT, and resource evidence exists.

The Python v5 owner remains the sole runtime transaction authority until that
evidence exists. Separate Lean/native checkouts, source adapters, generated
vectors, or differential tests do not themselves create formal authority.

## Bounded resources and privacy

Set finite record, payload, package, memory, and process limits. Measure the
complete path with separately attributable ingestion, owner transaction,
independent check, Continuity restore, and recovery evidence. A component
benchmark is not a system SLA; missing targets remain unknown.

Corporate support, monitoring, analytics, AI tools, contractors, and crash
dumps receive zero PHI and no persistent linkable claim fingerprint. Synthetic
reproduction is preferred. State owns rules, data, keys, histories,
interfaces, tests, and continuity export. Vendor compatibility is free and
replaceable; product economics do not depend on a share of denials,
recoveries, penalties, or savings.

## Claims and sequencing

Claims must be proportional to current raw evidence. The present financial
candidate is synthetic, local, nonactivating, nonpayment, and non-PHI with
`proofSuiteId=null`, `production_usable=false`, and `activation=false`.
Production qualification additionally requires state approval, authenticated
sources, custody, persistence/recovery, privacy/support, independent
assurance, formal linkage where applicable, and all profile-specific gates.

Implement in dependency order: stabilize the owner contract; independently
verify schema, history, retries, and recovery; finish the Lean semantic design;
link and qualify the formal boundary; then qualify custody, source, operations,
shadow use, and any activation. Do not let a later commercial or routing need
silently expand the current financial authority.
