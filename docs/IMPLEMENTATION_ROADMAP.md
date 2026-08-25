# Native-v3 implementation roadmap

Updated: 2026-08-15
Owner: dependency order for Native-v3, the later Lean gate, and the nonpayment Mirror wedge. It is
not a proof-backend selection or activation record.

This roadmap follows the smallest dependency chain that can produce a trustworthy state-side
clearance system. Rejected architectures are recorded separately and are not milestones.

## Current release gate

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

## Completed foundation

1. Freeze the five directives and ten verifier-facing statement fields in the strict public
   allowlist; state-side context and audit identities remain outside that handoff.
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
qualified private-proof backend. State first issues a fresh one-time opaque 256-bit operation
reference and allowlisted statement in `AWAITING_HANDOFF`; for a batch it assigns the exact positions and
computes the ordered batch root from the issued references and canonical templates. Only then may
an explicit verifier-owned volatile stream be submitted for that exact issued statement and
consumed once within the selected profile's exact small envelope cap and no proof workspace or raw
proof/source material is durable. There is no universal input-admission allowance; the unselected
private profile remains inactive, and the complete process-tree peak must remain strictly below
5,000,000,000 bytes. The verifier returns only a bounded proof-acceptance receipt, while the state owner
maps PASS/MISSING/AMBIGUOUS/FAIL plus state exception approval to CLEAR/HOLD/HUMAN_REVIEW/
BLOCK/EXCEPTION_APPROVED. Ordered batches are preflighted against one state snapshot and
applied atomically, with independent reconstruction and fail-closed retry/recovery. Old V6
databases are unsupported; no migration, compatibility reader, active backend, PQ qualification,
Lean completion, or product-throughput claim follows from this seam. The co-equal PQ, zero-PHI,
recovery, 100 complete operations within 35 seconds p95, and complete-process-tree-under-5GB gates
remain open.

Before selecting or implementing a private backend, close and review one complete profile theorem
and composition ledger covering:

1. vector-commitment collapse and position binding;
2. concrete salted SHA3-512 leaf hiding and binding;
3. exact zero-knowledge/privacy for the actual adversary and transcript model: malicious-verifier
   privacy plus reset/abort/retry/session composition for interactive protocols, or the exact
   NIZK/Fiat-Shamir/QROM privacy and soundness model for noninteractive protocols;
4. semantic and state-relation composition;
5. abort, retry, replay, reset, and union accounting over the finite profile/key-epoch attempt
   ceiling; and
6. authenticated challenge generation and transcript composition.

Every qualified cryptographic profile/key epoch has a hard global ceiling of `2^32` cryptographic
acceptance attempts across all operations, retries, batches, instances, and verifier sessions
sharing that profile/epoch. Exceeding the ceiling or losing the trustworthy counter fails closed and
requires rotation and requalification; this is assurance accounting, not throughput. The exact
theorem ledger must prove the union of proof soundness/knowledge, commitment binding where
statistical, transcript/challenge collisions, enabled aggregation, operation-reference collisions,
abort/retry/reset, and every union factor over that full ceiling is at most `2^-128`. Equal
allocation across eight per-attempt classes requires at least 164 bits per event; use a 192-bit
per-proof/statistical engineering target unless an exact tighter ledger proves the complete bound.
The selected PQ primitive parameter sets must meet at least the declared NIST Category 1 comparison
floor; that floor is a broad reference-resource floor, not an exact proof-soundness theorem or a
`2^-128` forgery probability. Each suite declares its adversary work/query model, signature/oracle
counts, key lifetime, reduction loss, and whether its selected NIST category preserves the intended
128-bit product claim under the finite ceiling; a stronger category is used only when exact evidence
requires it. Fresh state-issued 256-bit operation references prevent cross-operation replay/binding
failures but do not replace proof soundness. No unbounded deployment-lifetime `2^-128` probability is
claimed. Promising components or ideal-model calculators do not close this gate.

## Next implementation after theorem closure

1. Freeze the smallest complete private statement and fixed evaluator profile.
2. Build a bounded-memory source-local prover and a genuinely independent state-side verifier;
   declare any exact prover/aggregator accelerator or hardware requirements in the complete profile.
3. Prove the business semantics and ordered state transition atomically, including exact SHA3-512
   roots, completeness/nonmembership, replay, exception, chronology, retry, and after-state
   mutation behavior.
4. Measure source-prover, optional-aggregator, independent-verifier, state-transaction, and
   outbox/ACK stages separately, plus complete process-tree peak memory, scratch, pagefile,
   throughput, and complete-profile latency from admitted canonical input through independent
   verification, atomic state transaction, and outbox/ACK. Any external official-source/ACK latency
   is measured and disclosed separately; component-only numbers receive no product credit.
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
