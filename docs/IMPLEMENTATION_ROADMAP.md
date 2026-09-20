# RightRail implementation roadmap

Updated: 2026-09-19
Owner: dependency order for the synthetic financial workflow and its retained Blind Ledger/Mirror
boundaries. Native-v3, Lean, and activation remain separate future workstreams; this is not a
proof-backend selection or activation record.

This roadmap follows the smallest dependency chain that can produce a reconstructible, state-local
financial responsibility without creating a second ledger or weakening existing trust boundaries.
Rejected architectures are recorded separately and are not milestones.

## Active roadmap — financial workflow 2026-09-19

The committed parent before this CASE10 abrupt-process-boundary extension is branch
`rightrail-financial-workflow-20260913` at HEAD
`fb40e7ee7c31091e62aa74a32a30e9fb511741ca`, tree
`1c16d35c51f9a32925db1b3c3b5fb18e0febb425`. All evidence is synthetic and
nonactivating. The persisted owner/Continuity candidate is v4:
`RR/FINANCIAL/OWNER/v4` and `RR/FINANCIAL/CONTINUITY/v4`. Its immutable
`financial_identity` row binds restore provenance, mode/owner identity, source
package digest, genesis, and history anchor; identity replacement is blocked
after initial creation, restored LIVE/mismatched-owner contracts fail in both
validators, and the checker separates current-snapshot row binding from
restore-source anchor binding. Retained v2/v3 and prior v4
measurement artifacts remain immutable historical evidence.

1. **A — Documentation and pins.** The maintained Markdown records the current
   v4 identity, ownership, guard, TEST/non-live Continuity boundary, actual
   lock-workload evidence, historical measurement boundary, and protected
   paths. This is not a production acceptance record.
2. **B — Focused seams and source correction.** The four initial correctness
   blockers are addressed in the owner, independent checker, Mirror/CLI, and
   acceptance fixtures. Event header integrity, population lifecycle order,
   persisted imported-count binding, immutable restore provenance, and
   history-anchored TEST identity are explicit invariants. Current snapshots
   and restore sources are explicit verifier roles rather than one guessed
   continuity argument; restore-source verification remains anchored to the
   persisted source package after continuation rather than the target's newer
   current sequence/head.
3. **C — Guarded affected verification.** The final guard ran the focused
   harness compile and affected source suite. The retained prior correction
   result is `Ran 47 tests in 14.303s` followed by `OK`; the follow-on changed
   acceptance, independent-role, and retained-boundary gates were `21`, `2`,
   and `12` tests respectively, all `OK`. Raw child logs are retained by the
   guard.
4. **D — Same-owner Mirror and Continuity.** Default Continuity restore remains
   SHADOW/read-only. The explicit TEST restore has fixed identity, cannot open
   as LIVE, keeps dispatch/egress disabled, and Case 11 reaches H_P3_REPLACED
   after restart, verifies the original restore source at both continuation
   points, rejects the completed package as a wrong restore source, and does
   so without changing source bytes or redispatching a duplicate action
   identity.
5. **E — Candidate measurement and review.** The guarded v5 series completed at
   `work/financial-measurements-v5-r1` with 3 measured samples plus 1 warmup at
   each of sizes 5, 10, and 20, 12 owner databases and 12 TEST restore
   databases. Actual `_write()` wait/held medians were 2.019/7.188,
   1.815/6.052, and 1.708/6.597 ms. These are medians of three per-sample
   medians; transaction totals 36, 54, and 90 are sums of per-sample counts,
   with zero acquisition failures. All 9 measured TEST restores left
   source bytes unchanged. The synthetic contention diagnostic remains
   separately labeled and receives no actual-workload credit. This is a bounded
   observation, not an SLA. Native metrics remain pending and queue wait/age
   is not applicable. The financial owner’s CASE10 now also covers abrupt
   owned-child exit at the real owner write rollback boundary before COMMIT and
   at the committed-result-lost boundary after COMMIT, with restart, independent
   verification, same-identity retry, and unchanged duplicate effects over
   isolated synthetic SQLite stores. Its fault injection is test-local and adds
   no production hook. The
   selected Queue/Composition/Runtime/Mirror tests are separate retained
   integration evidence. Native verification-to-commit, Lean, whole-system,
   independent-audit, and production gates remain open. Earlier v2/v3/v4
   results and measurements are historical only.
   The financial owner still has no separate verification-attempt, lease,
   receipt-consumption, or reservation boundary. The next financial design
   decision is an owner-local plaintext binding from a determination to
   `obligations.current_evaluation_id` and its existing `evaluations` row,
   including revision, Control Pack, evidence, authority, and result-digest
   identities; API, retry/consumption, invalidation, recovery, and reservation
   ownership must be specified before implementation. Queue reservations stay
   separate and no native hospital-payment predicate is implied.

The first-state fixture is fixed at twenty hospitals and $1,000,000 total: H is $100,000 and the
other nineteen total $900,000. Hand-derived expected constants are required. The financial owner
must preserve evidence versus authority versus action versus acknowledgment versus cash/reporting
completion. It must not change the retained exact-100 protocol, source ownership/reservation,
queue/State/outbox atomicity, non-`CLEAR` economic guard, native/C/crypto/Lean artifacts, operations
policy, or archives.

Every implementation phase ends with exact Git identity, changed/untracked
paths, commands and raw trust-critical output, failures/warnings/skips, and
the next safe action. Missing production targets are recorded as unknown; the
retained native arithmetic floor is not a financial ingestion SLA. The next
safe action is the bounded Driver/Security review of the committed source
checkpoint, not another source refactor or a prose acceptance declaration.

## Retained Native-v3 release gate

`ops/launch_blockers.json` is the machine-readable launch-blocker authority; this section is its
current human-readable summary. The blockers are capability/profile-scoped: an activated
external-authority or `PRIVATE_ZK` profile must close the applicable PQ, privacy/soundness,
throughput, state-owner, formal-kernel, custody, and independent-audit gates, while
`DIRECT_STATE_OWNED` and `AUTHORITATIVE_ASSERTION` do not wait on a private-proof backend. The
current release remains unselected, `production_usable=false`, and inactive; no blocker is closed
by prose or a derived readiness field. Activation additionally requires official receiver and
government-connector evidence.

The v2 JSON records gate identity, classification, status, and evidence digest; it does not select an
evidence mode. The following applicability is part of this authority and prevents an open row from
being misread as a universal private-proof gate:

| Machine blocker | Applicable capability/profile |
| --- | --- |
| `BL-PROOF-SOUNDNESS` | `PRIVATE_ZK` only, including its exact privacy/soundness/composition ledger |
| `BL-PROOF-THROUGHPUT` | Every activated profile's complete declared path and reference resource profile |
| `BL-CLEARANCE-STATE-OWNER` | All three modes before automatic state disposition |
| `BL-FORMAL-KERNEL` | All automatic clearance modes before policy/transition authority |
| `BL-CUSTODY-OPERATIONS` | Every activated profile's source, key, persistence, and operational custody |
| `BL-INDEPENDENT-AUDIT` | Every activated profile and its independent reconstruction |
| `BL-OFFICIAL-RECEIVER` | Activation of any mode that emits an operative clearance directive |
| `BL-GOVERNMENT-CONNECTORS` | Activation of any mode using official external authority |

## Retained Native-v3 position

The current candidate is a nonactivating, unselected integration of the reviewed source/release
closure and Mirror observation boundary. `STATE.md` owns the measured release counts and retained
gate evidence; `CURRENT_TASK.md` owns the active bounded work and unresolved identities. This
roadmap does not create a second readiness record or change application trust boundaries, operations
bytes, verifier semantics, activation, or the read-only/nonpayment claim. Source-only harnesses and
generated/private artifacts remain outside release selection.

## Future formal dependency

The authorized next semantic dependency is the Lean formal kernel. Separate Lean source and a
transport adapter exist in earlier semantic workstreams, but no accepted executable artifact is
linked to this integration runtime and no formal credit exists here. Before any production direct
evaluator or private proof can authorize a clearance transition, the workstream must pin the project
and theorem statements, implement the evaluator and bounded decoder, prove the required semantic/
state properties, compile one pinned artifact behind a narrow Rust adapter, and pass theorem-manifest,
axiom, independent-kernel, KAT, mutation, and resource gates. `docs/LEAN_FORMAL_KERNEL.md` is the
exact authority; a separate model, differential test, or generated vector is not formal-verification
credit.

## Future implementation after theorem closure

1. Freeze the smallest complete narrow private statement/receipt and fixed evaluator profile.
2. Build a bounded-memory source-local prover and a genuinely independent state-side verifier;
   declare any exact prover/aggregator accelerator or hardware requirements in the complete profile.
3. Compose the narrow assertion-verification receipt into the separately verified atomic state
   transition and later Lean semantics. Keep state-held amounts, policyResult/effectiveDirective,
   chronology, exception, replay, retry, and after-state mutation state-owned; require SHA3 linkage
   only when the selected authoritative representation contract requires that relation.
4. Measure the complete profile at the Native-v3 qualification boundary, retaining separately
   attributable stage evidence for source-prover, optional aggregator, independent verifier,
   state transaction, and outbox/ACK. Component-only numbers receive no complete-profile credit.
5. Run focused positives, adversarial negatives, corruption/reorder/omission/duplicate cases, and
   cross-language KATs.
6. Only then consider a selected profile's independent audit, production database/key custody, PHI
   authorization, or activation; historical proof-layout and monolithic-gate names are not current
   qualification inputs.

## Mirror dependency ladder and claim levels

Mirror is the umbrella read-only evidence, reconciliation, and operational-visibility product;
Provider Trust Graph is its current narrow first wedge. The ladder below qualifies that wedge one
boundary at a time and does not make every later Mirror capability a prerequisite for the first
controlled use:

1. **Current synthetic Provider Trust Graph foundation.** Preserve the exact registered synthetic
   FHIR source contract at the source-side adapter, one sanitized-observation Ingress owner,
   independently reconstructed Core state, explicit Recovery publication ownership, graph identity
   binding, support sanitization, and fail-closed export/restore. Raw source bytes are not durable
   Mirror state and recovery cannot reverify destroyed source bytes. This is a synthetic candidate,
   not authenticated source or full Mirror.
2. **Finish V2 and governance composition.** Compose the multi-subject/profile graph with an
   equivalent multi-profile Control Pack approval and withdrawal lifecycle, preserving exact retry,
   lifecycle heads, independent verification, and read-only/nonpayment authority.
3. **Qualify one authenticated real-state source vertical slice.** Select one state-accessible
   provider class and scope, authenticate its source through a state-owned boundary, and rerun the
   canonical, mutation, completeness, remediation/retest, and recovery gates. No real source,
   signature, API, or custody choice is implied by this roadmap entry.
4. **Qualify state-side persistence, custody, support, privacy, and pilot operations.** Close the
   production database/custody, state-owned support sanitizer, privacy review, portability, recovery,
   monitoring, and operational runbook gates for that one vertical slice.
5. **Run a controlled read-only shadow pilot.** Compare the evidence product with the incumbent or
   reference boundary without payment authority, automatic clearance, or silent fallback. Record
   coverage, discrepancies, responsibility, remediation, rollback, and unresolved limitations.
6. **Expand later by measured need.** North Carolina can add responsibility, contract, and
   denominator views; Georgia can add transaction, money, and transition views; the State Value
   Ledger follows measured baselines and an approved counting-once authority. These are expansion
   dependencies, not blockers for the narrow first wedge unless a selected scope explicitly needs
   one.

Mirror claim levels are explicit:

- **Architecture-defined:** a repository-owned boundary, capability, and dependency contract.
- **Synthetic candidate:** deterministic local evidence using synthetic inputs and nonactivating
  operational seams.
- **Controlled shadow-pilot qualified:** one scoped, state-controlled read-only pilot has passed its
  source, privacy, recovery, support, parity, and operational gates.
- **Production qualified:** the scoped product has current state approval, authenticated sources,
  qualified persistence/custody, privacy and support evidence, independent assurance, and all
  applicable operational gates.

The current repository can define the full Mirror architecture and substantiate a synthetic
Provider Trust Graph candidate; it does not claim a controlled shadow pilot or production
qualification. The later views do not silently change the first wedge's claim level. Mirror never
emits an operative Blind Ledger clearance directive or creates an economic state transition. It
has no private-proof backend dependency. Any undisclosed payment-relevant assertion requiring a
private proof belongs to the separately governed Blind Ledger clearance profile, not Mirror's
read-only evidence/reconciliation authority.

Behavioral Twin output enters the State Control Pack only as a candidate. It cannot become an
automatic control until source authority, deterministic tests, state approval, exact scope, and
effective interval are frozen. Managed-care direct provider-payment gating remains a later separate
authority profile; initial managed-care work is observation, contract enforcement, reconciliation,
and state-authorized adjustments.

For the unselected `PRIVATE_ZK` profile keep `proofSuiteId=null`; `DIRECT_STATE_OWNED` and
`AUTHORITATIVE_ASSERTION` do not wait on or depend on a private-proof suite. Keep
`production_usable=false`, activation false, and real PHI/payments forbidden until every applicable
profile gate is honestly closed.
