# Native-v3 implementation roadmap

Updated: 2026-08-15
Owner: dependency order for Native-v3, the later Lean gate, and the nonpayment Mirror wedge. It is
not a proof-backend selection or activation record.

This roadmap follows the smallest dependency chain that can produce a trustworthy state-side
clearance system. Rejected architectures are recorded separately and are not milestones.

## Current release gate

`ops/launch_blockers.json` is the machine-readable launch-blocker authority; this section is its
current human-readable summary. Qualification is governed by the six ordered
`gate=qualification` identities (`BL-PROOF-SOUNDNESS`, `BL-PROOF-THROUGHPUT`,
`BL-CLEARANCE-STATE-OWNER`, `BL-FORMAL-KERNEL`, `BL-CUSTODY-OPERATIONS`, and
`BL-INDEPENDENT-AUDIT`). Activation additionally requires `BL-OFFICIAL-RECEIVER` and
`BL-GOVERNMENT-CONNECTORS`. The current release remains unselected, `production_usable=false`,
and inactive; no blocker is closed by prose or a derived readiness field.

## Completed foundation

1. Freeze the five directives and eleven statement identity fields.
2. Preserve `policyResult` separately from `effectiveDirective`.
3. Bind governed exception identity, event/observation/rule-effective/decision times, replay and
   retry identity, before/after state, and the exact decision/access join.
4. Implement cross-language Phase-0 KATs and fourteen negative mutation classes.
5. Implement the synthetic trust-boundary protocol profile and independent Rust parser/verifier.
6. Implement the synthetic read-only provider credential/enrollment continuity wedge with a fixed
   verifier-owned `DIRECT_STATE_OWNED` control set, authoritative absence evidence, all five
   directives, focused tests, independent parsing, and bounded direct-path telemetry.

## Later mandatory formal-kernel gate

This is not the current or next implementation stage. Complete the nonpayment commercial wedge and
operational foundations first. Do not start Lean implementation without explicit phase
authorization. Lean remains mandatory before a production direct evaluator or private proof can
authorize a clearance transition.

Before a production direct evaluator or private proof can authorize a clearance transition:

1. Pin a small Lean 4 project and freeze the semantic types and theorem statements against the
   existing Phase-0 and continuity V2 vectors.
2. Implement the executable five-directive evaluator, control-set selection, authoritative
   absence, chronology, exception, observation-only separation, replay, exact decision/access join,
   and legal state transition.
3. Implement bounded canonical semantic decoding and prove round-trip and injectivity properties.
4. Prove determinism, proof-acceptance separation, non-clear nonmutation, exact exception scope,
   wrong-control-set rejection, replay preservation, join uniqueness, and append-only checkpoint
   chaining.
5. Compile the Lean kernel to one pinned native artifact behind a narrow Rust adapter. Any
   Rust/Lean mismatch rejects.
6. Gate clean builds on the theorem manifest, admitted-axiom inventory, independent kernel check,
   cross-language KATs, mutation tests, and resource measurements.

`docs/LEAN_FORMAL_KERNEL.md` is the exact authority. A separate model, differential test, or
generated vector alone is not deployed formal-verification credit.

## Current private-proof blocker

The active Queue/Proof Handoff V7 boundary is a clean-break state-owned handoff, not a
qualified private-proof backend. State first issues a one-time opaque operation reference and
allowlisted statement in `AWAITING_HANDOFF`; for a batch it assigns the exact positions and
computes the ordered batch root from the issued references and canonical templates. Only then may
an explicit verifier-owned volatile stream be submitted for that exact issued statement and
consumed once within the
4,500,000,000-byte admission cap and no proof workspace or raw proof/source material is
durable. The verifier returns only a bounded proof-acceptance receipt, while the state owner
maps PASS/MISSING/AMBIGUOUS/FAIL plus state exception approval to CLEAR/HOLD/HUMAN_REVIEW/
BLOCK/EXCEPTION_APPROVED. Ordered batches are preflighted against one state snapshot and
applied atomically, with independent reconstruction and fail-closed retry/recovery. Old V6
databases are unsupported; no migration, compatibility reader, active backend, PQ qualification,
Lean completion, or product-throughput claim follows from this seam. The co-equal PQ, zero-PHI,
recovery, 100-in-35s, and complete-process-tree-under-5GB gates remain open.

Before selecting or implementing a private backend, close and review one complete theorem ledger
covering:

1. vector-commitment collapse and position binding;
2. concrete salted SHA3-512 leaf hiding and binding;
3. malicious-verifier zero knowledge;
4. semantic and state-relation composition;
5. abort, retry, replay, and union accounting; and
6. authenticated challenge generation and transcript composition.

The total statistical false-acceptance target must remain at least 128 bits after every composition
and union term. Promising components or ideal-model calculators do not close this gate.

## Next implementation after theorem closure

1. Freeze the smallest complete private statement and fixed evaluator profile.
2. Build one CPU-first, bounded-memory prover and a genuinely independent verifier.
3. Prove the business semantics and ordered state transition atomically, including exact SHA3-512
   roots, completeness/nonmembership, replay, exception, chronology, retry, and after-state
   mutation behavior.
4. Measure complete process-tree peak memory, scratch, pagefile, throughput, and latency from
   admitted canonical input through independent verification and atomic database application.
5. Run focused positives, adversarial negatives, corruption/reorder/omission/duplicate cases, and
   cross-language KATs.
6. Only then consider K128/K512 qualification, independent audit, production database/key custody,
   PHI authorization, or activation.

## Mirror dependency ladder and claim levels

Mirror is the umbrella read-only evidence, reconciliation, and operational-visibility product;
Provider Trust Graph is its current narrow first wedge. The ladder below qualifies that wedge one
boundary at a time and does not make every later Mirror capability a prerequisite for the first
controlled use:

1. **Current synthetic Provider Trust Graph foundation.** Preserve the exact registered synthetic
   FHIR source contract, one raw Ingress owner, independently reconstructed Core state, explicit
   Recovery publication ownership, graph identity binding, support sanitization, and fail-closed
   export/restore. This is a synthetic candidate, not authenticated source or full Mirror.
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
does not require a private-proof backend unless an undisclosed payment-relevant assertion crosses
its trust boundary and affects automation.

Behavioral Twin output enters the State Control Pack only as a candidate. It cannot become an
automatic control until source authority, deterministic tests, state approval, exact scope, and
effective interval are frozen. Managed-care direct provider-payment gating remains a later separate
authority profile; initial managed-care work is observation, contract enforcement, reconciliation,
and state-authorized adjustments.

Throughout all phases keep `proofSuiteId=null`, `production_usable=false`, activation false,
and real PHI/payments forbidden until every applicable gate is honestly closed.
