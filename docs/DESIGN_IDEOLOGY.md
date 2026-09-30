# Blind Ledger design ideology

Updated: 2026-09-23. Owner: independent design contract for the smallest
correct implementation, deterministic evidence, bounded resources, modular
ownership, and fail-closed execution. Constitution Article XI is distilled from
it; the constitution wins any conflict and states the principles (invariants,
one owner per truth, narrow interfaces, formal means executed, fail-closed
authority). Assessing a substantial workflow change is Article XII. This document adds
only the following.

## Boundaries

The financial owner is the only writer, Mirror is a caller/read model,
Continuity is a bounded SHADOW/TEST handoff, and State owns rules, authority,
policy transitions and official consequences, even when a verifier or proof
supplies an evidence result. Every module states what it owns, receives and may
mutate, and what evidence proves the boundary; no second ledger, speculative
orchestration layer or duplicate receipt format compensates for an unresolved
contract. Corruption, omission, duplication, replay, stale revision, wrong
scope, cross-owner, cross-period and wrong-mode cases must fail visibly. A
failed determination leaves durable bytes unchanged, and a version-tag rejection
test is not evidence of historical-schema compatibility. A receipt binds the
exact scope, revision, rule/control-pack identity, evidence references/digests,
authority, result fields and digest domains it claims; it is not source truth or
payment confirmation. A pinned Lean artifact is linked to the working runtime
only after refinement, theorem, adapter, mutation, KAT and resource evidence
exists; adapters, generated vectors or differential tests do not themselves
create formal authority.

## Bounded resources

Set finite record, payload, package, memory and process limits. Measure the
complete path with separately attributable ingestion, owner transaction,
independent check, Continuity restore and recovery evidence. A component
benchmark is not a system SLA; missing targets remain unknown.

## Sequencing

Implement in dependency order: stabilize the owner contract; independently
verify schema, history, retries and recovery; complete and verify the Lean
semantic implementation and concrete adapter contract; link and qualify the
formal boundary; then qualify custody, source, operations, shadow use and any
activation. A later commercial or routing need never silently expands current
financial authority.
