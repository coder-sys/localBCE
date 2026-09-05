# Native-v3 implementation roadmap

Updated: 2026-09-05
Owner: dependency order for Native-v3, the authorized Lean formal workstream, and the nonpayment Mirror wedge. It is
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

## Current integrated workstream

The integrated candidate now contains Cleanup's reviewed source closure and the operator's shared
privacy, release-policy, and documentation-governance delta. The executable map is 225 tracked paths:
193 current source, 3 explicitly retained compatibility modules, 3 source-only, and 26 excluded
generated/private paths. The default selection is 196 (193 + 3); 29 remain unselected. Prefix
membership is a classification hint only, and deleted compatibility entries are not retained in a
blanket keep map.

The final bounded gates are the privacy, builder, manifest, documentation, active-core/security,
direct-state, native boundary, operations-authority, qualification, strict-compilation, structural
privacy, and extracted-builder/readback checks. This workstream does not change application trust
boundaries, operations bytes, verifier semantics, activation, or the read-only/nonpayment claim.
Source-only harnesses, generated/private artifacts, and failed privacy gates remain excluded.

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

## Authorized formal-kernel workstream

The formal-kernel workstream is the next authorized semantic-authority dependency after the current
documentation/release integrity pass. No Lean implementation or deployed link exists in the current
candidate. Lean remains mandatory before a production direct evaluator or private proof can authorize
a clearance transition; this roadmap records the dependency and its gates without claiming that they
have passed.

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

The current Queue/Proof Handoff integration candidate is Profile 11 and defers to
`docs/DATABASE_ZK_ARCHITECTURE.md` for transaction semantics and
`docs/NATIVE_V3_ARCHITECTURE.md` for exact profile identity, mechanical pins, and qualification
gates; this roadmap records only dependency status. Profile 10 and earlier profiles are rejected
with no fallback, compatibility reader, relabeling, or dual acceptance. The current Profile 11
Queue/Native proof boundary is mechanically interoperable but cryptographically unqualified; it is
not a selected private-proof backend, and its clean-break, state-owned, non-dispositive, fail-closed
semantics do not establish an active backend, qualification, Lean completion, or product-throughput
claim. It remains `proofSuiteId=null`, `production_usable=false`, and `activation=false`; proof
acceptance yields only an opaque verification outcome and never `CLEAR`. State alone owns chronology,
`policyResult`, `effectiveDirective`, exceptions, disposition, retries, economic state, and outbox.

Before selecting or implementing a private backend, the complete profile must close the exact
source-binding, privacy/setup, PQ, acceptance-accounting, theorem-composition, zero-PHI deployment,
resource, and measurement gates defined normatively in `docs/NATIVE_V3_ARCHITECTURE.md`. This roadmap
owns their applicability and dependency order, not a second copy of their arithmetic or profile
requirements.

## Next implementation after theorem closure

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
