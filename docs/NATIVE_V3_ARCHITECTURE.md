# Native-v3 proof architecture

Updated: 2026-08-25
Status: production-shaped target architecture; current qualification status is authoritative in
`STATE.md` and `CURRENT_TASK.md`, and no backend is selected.
Owner: private-proof, security, state, privacy, and CPU qualification authority. The commercial
Mirror wedge is governed by its own read-only boundary and does not inherit private-proof claims.

This document is the active proof, security, state, and CPU qualification authority. The former
Privacy V2, BL-PQ512/H4, binary-field, Binius64, and decisive-composition narratives have been
retired; Git history and retained archives preserve their exact evidence.

## Product invariant

When evidence must remain hidden across the state clearance trust boundary and affects an automated
payment directive, a future qualified native verifier may accept one proof of the exact hidden
assertion and ordered state relation. Proof acceptance is only one input to the state owner: it does
not choose policy or directive. The state-owned result and database mutation must commit in one
fail-closed atomic transaction.

ZK is not required merely because data is sensitive. If the state clearance service already
lawfully holds every required fact in plaintext, the smallest correct mechanism is inspectable
deterministic evaluation over signed governed records. Native v3 is the mandatory path when an
undisclosed payment-relevant assertion crosses the clearance boundary and affects automation, not
ceremony around evidence the verifier already owns.

No L2, rollup, sequencer, bridge, Solidity ABI, or public data-availability layer is part of this
boundary. Ethereum is not a dependency.

## Current experimental engineering boundary

The current native-v3 proof and application code are experimental engineering only. The V7 queue
clean break uses a state-generated random 32-byte operation reference and one verifier-owned
volatile readable stream; it does not create a proof workspace or persist proof/source/signature/
commitment bytes, artifact digests, acceptance bytes, or process-output hashes. The exact
4,500,000,000-byte admission cap and complete process-tree peak below 5,000,000,000 bytes remain
required. A consumed, failed, expired, restarted, or ambiguous handoff becomes HELD and requires
a fresh state operation and fresh handoff. These controls do not close the theorem,
malicious-verifier/QROM, grinding, SHA3-512, Lean, deployment, or production-custody gates.
A future qualified contract may additionally bind a fresh source-attested `P`/signature and a
hiding commitment to the state challenge; that possibility is unimplemented and cannot supply a
current verifier receipt or state disposition.

The current statement grammar still lacks the complete proposed/authorized payment-amount binding
required by the typed receipt contract below, and its before/after state identifiers are not yet the
single canonical state-layout formula required for sequential production authority. A breaking,
versioned native statement revision must bind one hiding proposed-amount commitment, derive the
authorized commitment from the effective directive, and prove exact state continuity before this
lane can advance. Until then proof acceptance cannot authorize `CLEAR` or any economic action.

## Production-shaped patch-in contract

Native-v3 is the private-clearance plug-in behind a fixed business and state interface, not a
semantic rewrite. A qualified implementation must preserve the canonical five-directive grammar,
`policyResult`/`effectiveDirective` separation, governed control-set/order, authoritative
absence, four-time chronology, decision/access join, exception identity, roots, replay, and
fail-closed state transition. Productionization is qualification and substitution of the Lean
kernel, native verifier/backend, authenticated source/governance inputs, and production
database/custody adapters. Every substitution reruns the frozen KATs, independent verification,
mutation/replay/recovery, and complete resource gates. A component that changes those interfaces
is an architecture change and requires review. The current qualification record and the unresolved
private-proof terms remain in `STATE.md`; the read-only provider-continuity wedge does not wait for
this private-payment plug-in.

## Smallest complete system

1. Governed ingestion verifies each source signature over exact canonical bytes and inserts the
   resulting typed record commitment into an immutable authenticated registry.
2. The prover receives private registered records and constructs one fixed-profile ordered operation
   table. Padding and every clearance outcome have the same observable proof shape.
3. A future qualified proof binds the state-issued challenge and hidden assertion; it does not
   own state disposition or choose a policy/directive.
4. The independent verifier consumes the volatile stream and returns only proof acceptance, the
   opaque operation reference, bounded assertion/profile/version/order/resource fields, and
   qualification flags. Producers, transports, logs, and caller booleans have no acceptance
   authority, and the stream is never refetched.
5. The state owner separately resolves `PASS`/`MISSING`/`AMBIGUOUS`/`FAIL` plus state exception
   approval into exactly the five directives, then atomically applies the ordered state chain and
   opaque reference/directive outbox. The official state payment system, not the proof or Blind
   Ledger database, moves money.

Public signature verification is not repeated inside every proof when the proof instead establishes
membership in the verifier-owned immutable registry whose ingestion rule verified those exact signed
bytes. This moves repeat work to its natural owner; it does not trust a prover-supplied root.

## Clearance semantics and typed receipt

Native v3 preserves five fixed state directives: `CLEAR`, `HOLD`, `HUMAN_REVIEW`, `BLOCK`, and
`EXCEPTION_APPROVED`. A future qualified proof binds the hidden assertion and ordered state
relation, while the verifier returns proof acceptance only; proof acceptance is not itself a
directive and must never default to `CLEAR`.

- `CLEAR` means every selected deterministic automatic check passed.
- `HOLD` means a fixable deterministic requirement is missing.
- `HUMAN_REVIEW` means judgment, ambiguity, an unavailable authoritative fact, or additional
  evidence prevents automatic enforcement.
- `BLOCK` means a clear state-approved deterministic condition failed.
- `EXCEPTION_APPROVED` means a separately governed state official authorized a scoped override.

The state-owned operation row carries an underlying `policyResult`, an `effectiveDirective`, and
state-owned exception approval. The no-exception case uses a domain-separated sentinel. The state
owner maps `PASS` to `CLEAR`, `MISSING` to `HOLD`, `AMBIGUOUS` to `HUMAN_REVIEW`, `FAIL` without
exception to `BLOCK`, and `FAIL` with state exception approval to `EXCEPTION_APPROVED`. The proof
preserves no disposition authority, so a verifier or witness cannot erase or rewrite the state
decision trail.

The future public contract remains commitment-only and fixed-shape. The independent verifier
returns no directive, policy result, raw proof, source identity, or exact artifact fingerprint.
The state owner emits the separate state receipt and may release only the state-owned directive to
the official payment system. `HOLD`, `HUMAN_REVIEW`, and `BLOCK` do not advance economic clearance
state.

A verifier failure returns no receipt and no directive. Operational continuity may use a separately
authorized, signed, expiring human override recorded by Mirror; it is outside proof acceptance and
cannot relabel a failed proof as `CLEAR`.

## Governed rule and evidence boundary

The State Control Pack is the canonical rule source shared by Provider App, the state reference
engine, Mirror comparisons, and Blind Ledger. Blind Ledger never reauthors policy in a private proof.
Each enforceable rule artifact commits to its source authority, version, effective interval, scope,
required evidence, deterministic logic, explicit exceptions, conformance tests, state approval, and
supersession history. The registry leaf may commit to that canonical payload rather than duplicate
it, but its typed record kind and authority role must prevent a fact, rule, contract obligation, or
exception authorization from being substituted for another.

The verifier-owned governance snapshot resolves one exact `automaticControlSetId`: the ordered rule
identities, priority/conflict policy, directive mapping, transaction scope, and effective interval
that the state approved for automatic enforcement. The prover cannot omit an applicable rule,
choose a more favorable subset, or change the conflict policy. Unknown scope, overlapping rules
without a governed resolution, or a rule outside its effective interval yields `HUMAN_REVIEW` or a
fail-closed rejection according to the frozen control-set policy.

The commercial read-only provider-continuity wedge stops before this automatic-enforcement
boundary. It is a Mirror/Provider Trust Graph finding, remediation, parity, and transition product;
it does not create an operative `ClearanceDecisionRow`. The current synthetic plaintext continuity
module exercises future Blind Ledger semantics only as an internal conformance harness. A
Behavioral Twin extraction or Mirror finding is a candidate input to governance, never an approved
control merely because it describes incumbent behavior.

Mirror may supply evidence references and responsibility-boundary observations, but a Mirror label
is not truth by itself. Every fact used for automatic clearance must resolve to a verifier-owned
typed registry and the proof must establish the required record kind, authority, scope, validity
interval, and private membership. Missing or ambiguous authority yields `HUMAN_REVIEW`, never a
prover-invented fact.

Each evidence reference retains its authoritative source identity, record kind, exact subject and
scope, observation time, validity interval, population/completeness authority, provenance, and
integrity binding. Mirror may additionally retain visibility level, responsibility boundary, and
confidence for oversight, but those interpretive fields cannot supply automatic truth. Only the
verifier-owned governed source contract determines clearance eligibility.

Absence is a fact with its own authority. A missing authorization, enrollment, attachment, or other
record may produce `HOLD` or `BLOCK` only when the proof binds a complete authoritative snapshot,
bounded nonmembership proof, or signed closure/completeness assertion for the exact subject, scope,
and time. Absence from an incomplete feed yields `HUMAN_REVIEW`. The database authority owns the
strict relation `rule_effective < event < observation < decision` and exact decision/access join;
retries cannot change the bound rule or source snapshot.

## Native-v3 public statement

Native v3 uses a fixed, typed, canonical binary record. It is not the old 12-field `bytes32` ABI and
does not carry felt or Poseidon compatibility projections.

```text
protocolVersion
proofSuiteId                 // null until qualification and activation review
executionContextId           // SHA3-512 of profile, schema, program, verifier, candidate backend, and PRIVATE_ZK mode
settlementDomainId           // full-width typed identifier
epoch
sequenceBefore
sequenceAfter
stateBeforeId                // SHA3-512
stateAfterId                 // SHA3-512
governanceSnapshotId         // SHA3-512
automaticControlSetId        // SHA3-512 of ordered active rules, conflict policy, scope, directives, and effective interval
privateBatchCommitment       // SHA3-512
settlementCommitment         // SHA3-512 of the exact downstream clearance instruction; not proof of funds movement
```

The context registry retains the exact constituent identities for audit and upgrade. The proof
transcript absorbs the complete canonical statement before any challenge. Unknown versions,
contexts, suites, lengths, orderings, duplicates, alternate encodings, and trailing bytes fail
before untrusted-size allocation.

## Logical private tables

Keep business semantics separate from memory mechanics. Native v3 has two logical fixed-capacity
tables even if a qualified backend later fuses their physical trace after equivalence tests:

```text
ClearanceDecisionRow
  decisionIndex, decisionCount
  attemptId
  subjectCommitment
  proposedPaymentCommitment
  decisionPathCommitment       // ordered applicable rules, evidence, conflict resolution, and reasons
  authorizedAmountCommitment
  policyResult                  // state-owned disposition control result
  effectiveDirective             // resolved only by the state owner
  exceptionAuthorizationId     // governed identity or canonical no-exception sentinel

StateAccessRow
  decisionIndex, accessIndex, accessCount
  address, key
  valueBefore, valueAfter
  accessMode
```

The proof joins every state access to exactly one decision, proves chronological ordering, and
rejects orphaned, duplicated, reordered, or omitted rows. `decisionPathCommitment` is private and
selectively auditable; it gives every automatic directive a stable link to its source rule,
evidence, tests, and decision path without putting PHI in the public statement. A physical fusion
is an optimization only and cannot erase these logical bindings or their independent mutation tests.

## Lean semantic and transition authority

The approved target places the pure five-directive evaluator and legal local state transition in
an executable Lean 4 kernel. Lean covers bounded canonical semantic decoding, control-set
selection, authoritative completeness/nonmembership, chronology, exception eligibility,
observation-only separation, replay, decision/access joins, and allowed after-state. Rust remains
the cryptographic verifier and transcript/proof-envelope authority; the database remains the
concurrency, durability, and recovery authority.

A private proof can authorize no mutation unless the Rust verifier accepts and the state owner
accepts the minimal verifier receipt plus its own state-owned disposition/transition through the
Lean kernel. A direct state-owned evaluation uses the same Lean semantic relation over canonical
governed plaintext inputs. The deployed path must execute the proved definitions or have a
reviewed refinement proof to them; KAT agreement alone is not formal-verification credit. The full
theorem and build contract is `LEAN_FORMAL_KERNEL.md`.

## State and replay design

Native v3 separates three jobs:

- the semantic relation owns the exact fixed-capacity ordered operation table, five-directive
  clearance semantics, exception-authorization checks, and money/policy rules;
- a transparent post-quantum memory/state relation proves chronological reads, writes, uniqueness,
  replay rejection, and the before-to-after transition; and
- SHA3-512 authenticates stable endpoint identifiers instead of being recomputed at every internal
  state access.

The state interface is:

```text
stateId = SHA3-512(
  "BL/NATIVE-V3/STATE-ID/v1" || executionContextId || sequence ||
  stateLayoutId || capacity || length(stateCommitmentBytes) || stateCommitmentBytes
)
```

`stateCommitmentBytes` must be deterministic, canonically encoded, transparently constructed,
post-quantum binding, incrementally maintainable, and verified by the proof relation. No felt,
truncated digest, host comparison, or prover-supplied unchecked root may authorize state. The exact
commitment/memory theorem remains an implementation choice and must earn its claim with a small
complete proof before scale work.

## Proof-backend contract

The backend is replaceable behind one narrow interface. It must provide:

- a canonical fixed-profile statement and witness grammar;
- one complete clearance-semantic, source-membership, exception-authorization, memory, and
  state-transition theorem;
- native witness hiding for every committed/opened oracle and proof message;
- transparent setup with no trusted ceremony and no elliptic-curve dependency;
- a transcript construction covered by the backend's exact post-quantum theorem;
- an independent verifier returning typed outputs only after full verification;
- deterministic verification, bounded parsing, mutation/reorder/omission rejection, and exact
  resource telemetry; and
- streaming or bounded-frontier proving suitable for CPU-only execution.

Fiat-Shamir is allowed only when the exact construction has an applicable quantum-random-oracle
reduction and the implementation accounts for domain separation, oracle queries, retries, aborts,
and composition. An authenticated interactive coin is allowed only when its extra actor, custody,
round-trip, denial-of-service, and retry risks are justified by the deployment threat model. Neither
mode is a universal invariant; the leanest theorem-backed mode wins.

## Security target

- Every computational primitive and the composed system must meet at least the NIST post-quantum
  Category 1 baseline for its relevant attack model.
- Total per-proof statistical false-acceptance probability must be at most `2^-128` after all
  queries, repetitions, shards, components, bad events, and union bounds. Deployment-lifetime risk
  is calculated and reported separately.
- SHA3-512 remains the authoritative external identifier and provides margin; digest width alone is
  not proof-system security.
- Signatures are algorithm-agile and must use a NIST-approved PQ profile of at least Category 1.
  Two independent Category-5 signatures are required only by a documented custody/governance threat
  model or an actual National Security System profile, not by default inside every proof.
- No production claim is allowed without executable parameter accounting, exact theorem mapping,
  independent verification, malformed-proof tests, and side-channel review.

## Privacy and resource contract

- Proof, trace, operation count, errors, and externally visible schedule are fixed per selected
  deployment profile and independent of all five directives, exception presence, padding, and
  other private values.
- Exact proof bytes need not be 64 MiB. Choose the smallest fixed per-profile envelope that passes
  parser, leakage, and capacity tests.
- Fresh secret randomness is OS-CSPRNG-owned, domain-separated, never reused or logged, and zeroized
  after proving.
- Complete prover process-tree peak resident memory is at most 5,000,000,000 decimal bytes; scratch
  is strictly below that value; proving causes no swap or pagefile growth.
- A CPU-only implementation on a 16 GB consumer laptop is mandatory. A discrete GPU may accelerate
  the identical proof bytes but is optional, untrusted, and receives no correctness authority.
- Measurements begin at admitted canonical input and end after independent verification and the
  atomic receipt. Component or cached timings receive no complete-proof credit.

The first scale admission floor is 100 live operations in a fixed profile within 35 seconds p95 on
the pinned CPU-only reference host, with the complete resource and negative-test boundary. This is
an engineering floor inherited from the earlier campaign, not the final product SLA. Sustained
claims/second, p95 time-to-first decision, thermal throttling, energy, queue/cadence leakage, and
recovery are reported. A larger profile is forbidden until this boundary accepts and product volume
actually requires it.

## Implementation order

The Lean item below is a deferred formal gate, not the current or next implementation phase. The
nonpayment commercial wedge and operational foundations come first, and Lean work begins only after
explicit phase authorization. It still must close before production clearance or payment authority.

1. Freeze the canonical native-v3 statement, typed receipt, five-directive operation table,
   source/exception-registry contract, privacy adversary, and exact CPU reference host.
2. The five cross-language KATs cover `CLEAR`, `HOLD`, `HUMAN_REVIEW`, `BLOCK`, and governed
   `EXCEPTION_APPROVED`, with wrong-directive, exception, chronology, corruption, root, statement,
   and state-mutation negatives. The exception seal is synthetic-KAT-only.
3. At the later authorized formal gate, implement the Lean kernel, canonical decoder, theorem
   manifest, independent check, and narrow fail-closed Rust adapter against the frozen KATs.
4. Implement the smallest complete private fixture: one fact, rule, directive, chronological
   read/write, SHA3-512 endpoints, native proof, and independent verifier linked to Lean.
5. Require rejection of corruption, wrong bindings, reorder, omission, duplicate/replay, directive,
   exception, and after-state mutations plus complete resource telemetry.
6. Add fixed-profile batching and a streaming state/memory implementation. Optimize only the
   measured dominant complete-process stage.
7. Bind the typed receipt to the existing atomic database boundary and test retry, concurrency,
   rollback, crash, and recovery.
8. Meet the 100-live CPU floor, then freeze the machine-verifiable security ledger and proof-package
   grammar. Only then consider a larger profile, accelerator, aggregation, or production candidate.

## Retirement and deletion boundary

The old Privacy V2, fixed-shape, binary-field, H4/CUDA, L2/Starknet/Solidity, exact-package, and
unconditional dual-signature lanes are outside the active core. They remain read-only evidence until
their current property has a smaller replacement. Deletion requires an enumerated producer/consumer
and manifest scan, replacement tests, and one bounded change; historical performance is never
production credit. Do not begin another synthetic exact-K128 hash bakeoff, K512 campaign, or H4 repair before the replacement boundary is accepted.

## Current claim boundary

`STATE.md` owns qualification, nonactivation, resource, and private-proof status. Phase-0 KATs and
the synthetic exception seal are evidence only; no complete native-v3 proof, production signature,
or deployed formal-verification claim exists.
