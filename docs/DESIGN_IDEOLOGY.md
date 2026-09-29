# Blind Ledger design ideology

Updated: 2026-09-23. Owner: independent design contract for the smallest
correct implementation, deterministic evidence, bounded resources, modular
ownership, and fail-closed execution. Constitution Article XI is distilled from
it; the constitution wins any conflict.

Assessing a substantial workflow change is Article XII. Routine fixes stay
lightweight; cross-participant benefit needs an integrated scenario, not a
feature label.

## Principles stated in Constitution Article XI

Invariant first, gates serving invariants (with the exact-predicate record for
changing one), one owner per truth with a small trusted core, narrow versioned
interfaces, deterministic explicit inputs, and adversarial simplicity are
Article XI.1-XI.2, XI.5, XI.7, XI.9 and XI.14; they are not restated here. What
this document adds: the financial owner is the only writer, Mirror is a
caller/read model, Continuity is a bounded SHADOW/TEST handoff, and State owns
rules, authority, policy transitions and official consequences. Every module
states what it owns, receives and may mutate, and what evidence proves the
boundary; no second ledger, speculative orchestration layer or duplicate
receipt format compensates for an unresolved contract. Corruption, omission,
duplication, replay, stale revision, wrong scope, cross-owner, cross-period and
wrong-mode cases must fail visibly. A failed determination leaves durable bytes
unchanged, and a version-tag rejection test is not evidence of
historical-schema compatibility.

## Evidence, authority and state

Facts stay separate (Article II). A receipt binds the exact scope, revision, rule/control-pack identity, evidence
references/digests, authority, result fields and digest domains it claims; it
is not source truth or payment confirmation.

Missing, stale, malformed, ambiguous or unauthorized authority fails closed
(XI.10), and no caller-selected fallback may downgrade a required evidence mode. Policy,
effective directives, exceptions, chronology, state mutation and payment stay
state-owned even when a verifier or proof supplies an evidence result.

## Persistence, recovery and retries

The durable transition and retry rules are Article III.2-III.3 (one atomic
write; an exact retry is a duplicate, changed identity or input a conflict).
Recovery must prove behavior both when a process exits before COMMIT and when
the committed result is lost before the caller receives it; restart and
independent verification are part of the contract, not operational decoration.

Continuity restore is bounded and isolated (`ARCHITECTURE.md`): SHADOW
read-only, TEST non-live, dispatch/egress disabled, source bytes and owner
identity protected, and cleanup removes only an owned attempt or published
identity, with cleanup failures visible.

## Lean direction

Implement everything reasonably implementable in Lean (Article XI.8): a small
trusted state and explicit state machines; independent checks and fail-closed
authority; explicit recovery, idempotency and atomic history-projection-outbox
properties; and a pinned executable Lean artifact linked to the working runtime
only after refinement, theorem, adapter, mutation, KAT and resource evidence
exists. Source adapters, generated vectors or differential tests do not
themselves create formal authority.

## Bounded resources and privacy

Set finite record, payload, package, memory and process limits. Measure the
complete path with separately attributable ingestion, owner transaction,
independent check, Continuity restore and recovery evidence. A component
benchmark is not a system SLA; missing targets remain unknown.

Corporate support, monitoring, analytics, AI tools, contractors and crash
dumps receive zero PHI and no persistent linkable claim fingerprint (Article IV).
Synthetic reproduction is preferred.

## Claims and sequencing

Implement in dependency order: stabilize the owner contract; independently
verify schema, history, retries and recovery; complete and verify the Lean
semantic implementation and concrete adapter contract; link and qualify the
formal boundary; then qualify custody, source, operations, shadow use and
any activation. Don't let a later commercial or routing need silently expand
current financial authority.
