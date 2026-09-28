# Blind Ledger design ideology

Updated: 2026-09-23. Owner: independent design contract for the smallest
correct implementation, deterministic evidence, bounded resources, modular
ownership, and fail-closed execution. Constitution Article XI is distilled from
it; the constitution wins any conflict.

For substantial workflow changes, assess staff effort, repeated evidence
requests, data movement, troubleshooting, installation/updates, recovery,
independent exit and reusable improvements. Compare a materially simpler
approach and demonstrate the chosen tradeoff in the affected workflow. Keep
routine fixes lightweight; cross-participant benefit needs an integrated
scenario, not a feature label.

## Invariant first

Start with the property that must be true for a decision to be safe. Derive
the smallest implementation that makes it executable and independently
checkable. A historical workflow, benchmark, digest, caller boolean or green
gate is not authority merely because it exists.

Gates protect invariants but aren't the invariants themselves. If evidence
shows a gate is stale, over-broad or non-applicable, record its exact
predicate, protected failure mode, raw reason, replacement control, scope,
duration and claim consequence. Never silently bypass a gate, accept a
malformed proof, weaken atomic mutation, or relabel a nonqualifying result.

## Small trusted core and modular interfaces

Prefer one canonical owner, a small trusted state machine, narrow versioned
interfaces and independently reconstructed boundaries. Every module states
what it owns, receives, may mutate, and which evidence proves the boundary.
No second ledger, speculative orchestration layer, or duplicate receipt
format to compensate for an unresolved contract.

In the financial workflow the owner is the only writer. Mirror is a
caller/read model; Continuity is a bounded SHADOW/TEST handoff. State owns
rules, authority, policy transitions and official consequences.

## Evidence, authority and state

Typed evidence, official determination, authorized action, dispatch/
acknowledgment and cash/reporting completion are different facts. A receipt
binds the exact scope, revision, rule/control-pack identity, evidence
references/digests, authority, result fields and digest domains it claims; it
is not source truth or payment confirmation.

Missing, stale, malformed, ambiguous or unauthorized authority fails closed.
No caller-selected fallback may downgrade a required evidence mode. Policy,
effective directives, exceptions, chronology, state mutation and payment stay
state-owned even when a verifier or proof supplies an evidence result.

## Persistence, recovery and retries

The durable transition is one atomic write of history, current projection
and action/outbox identity. Every command has explicit identity, expected
revision, canonical payload and a retry rule: exact retries are duplicates,
changed identity/input is conflict. Recovery must prove behavior both when a
process exits before COMMIT and when the committed result is lost before the
caller receives it — restart and independent verification are part of the
contract, not optional operational decoration.

Continuity restore is bounded and isolated: SHADOW read-only, TEST non-live,
dispatch/egress disabled, source bytes and owner identity protected. A
restored package cannot promote itself into a live writer or replace an
existing identity. Restore uses a private attempt directory and atomic
no-replace publication, so cleanup removes only an owned attempt or owned
published identity; foreign destinations and sidecars stay intact, and
cleanup failures are visible.

## Determinism and adversarial simplicity

Use explicit inputs, integer amounts, versioned schemas, stable ordering,
bounded parsing and manually derived expected values. Make corruption,
omission, duplication, replay, stale revision, wrong scope, cross-owner,
cross-period and wrong-mode cases fail visibly. Prefer the simplest
falsifiable design; compare alternatives against mutation, replay, recovery,
resource and whole-system evidence before adding machinery. A failed
determination must leave durable bytes unchanged; a version-tag rejection
test is not evidence of historical-schema compatibility.

## Lean direction

Implement everything reasonably implementable in Lean, with executable
semantics and useful modularity: a small trusted state and explicit
deterministic state machines; narrow, versioned modular interfaces between
evidence, policy, owner and external systems; independent checks and
fail-closed authority; explicit recovery, idempotency and atomic
history-projection-outbox properties; and a pinned executable Lean artifact
linked to the working runtime only after refinement, theorem, adapter,
mutation, KAT and resource evidence exists.

Source adapters, generated vectors or differential tests do not themselves
create formal authority.

## Bounded resources and privacy

Set finite record, payload, package, memory and process limits. Measure the
complete path with separately attributable ingestion, owner transaction,
independent check, Continuity restore and recovery evidence. A component
benchmark is not a system SLA; missing targets remain unknown.

Corporate support, monitoring, analytics, AI tools, contractors and crash
dumps receive zero PHI and no persistent linkable claim fingerprint.
Synthetic reproduction is preferred. State owns rules, data, keys, histories,
interfaces, tests and continuity export. Vendor compatibility is free and
replaceable; product economics don't depend on a share of denials,
recoveries, penalties or savings.

## Claims and sequencing

Claims must be proportional to current raw evidence; standing claims live in
`STATUS.md`.

Implement in dependency order: stabilize the owner contract; independently
verify schema, history, retries and recovery; complete and verify the Lean
semantic implementation and concrete adapter contract; link and qualify the
formal boundary; then qualify custody, source, operations, shadow use and
any activation. Don't let a later commercial or routing need silently expand
current financial authority.
