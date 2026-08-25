# Blind Ledger architecture

Updated: 2026-08-24

Blind Ledger is RightRail's state-side payment-clearance product. It answers one narrow question:
may this proposed payment proceed under the deterministic rules the state has approved for
automatic enforcement? It does not adjudicate an entire claim, decide ambiguous medical policy,
move money, replace the official payment system, or act as an L2, rollup, blockchain execution
system, or Solidity application.

## RightRail system context

```text
State Control Pack -----> Provider App preflight
        |                       |
        |                       +---- small state-verifiable receipt when useful
        v
state reference engine --> Mirror <--- Switch boundary events and official results
                              |
                              +---- governed evidence for selected deterministic controls
                                                   |
                                                   v
                                             Blind Ledger
                                                   |
                                      state-local clearance directive
                                                   |
                                                   v
                                      existing state payment system
                                                   |
                                                   +---- actual result returns to Mirror
```

The State Control Pack owns approved rule artifacts. Mirror owns the evidence-backed account of
what happened. Blind Ledger consumes only the governed facts and deterministic rules selected for
automatic clearance. The existing processor remains the adjudicator and the existing payment
system remains the money mover. Provider App preflight and Mirror observation do not authorize a
payment.

The first recommended RightRail wedge is read-only provider-enrollment and credential continuity.
It can proceed without payment authority and without waiting for a production Blind Ledger proof
suite. Native-v3 remains a parallel synthetic R&D boundary for later narrow payment controls.

## Mirror product contract

Mirror is one of RightRail's three customer-facing products. It is the umbrella evidence,
reconciliation, and operational-visibility product that answers: what actually happened, who was
responsible, and what money moved? Mirror works from state-held data and state-controlled
boundaries first. Deep incumbent or vendor telemetry is optional precision, never a V1 dependency.

Mirror asks six questions:

1. What entered?
2. Which rule or obligation applied?
3. What did each responsibility boundary do?
4. What came out?
5. What was paid or reported?
6. Where did expected and actual behavior diverge?

Its evidence ladder has three visibility levels:

1. State-existing data.
2. State-controlled boundary observation.
3. Optional deep vendor telemetry.

Mirror states only what the evidence supports and exposes RightRail's own failures. Its eight
internal capability views are not separate products:

| Internal view | Meaning |
| --- | --- |
| Transaction Mirror | Trace available input through processor decision, payment, reporting, correction, and appeal against the State Control Pack or state reference. |
| Contract Mirror | Continuously test exact vendor obligations, populations, results, responsible party, exceptions, and remediation. |
| Money Mirror | Reconcile adjudicated claims, cash, encounters, voids, adjustments, capitation, withholds, state-directed payments, invoices, and reporting. |
| Transition Mirror | Compare incumbent and challenger behavior, unresolved differences, coverage, interface compatibility, export, continuity, and rollback readiness. |
| Denominator Ledger | Preserve the complete population before later systems narrow it. |
| Responsibility Graph and corrective-action runtime | Connect obligation to plan/delegate, interface, transaction, failure, corrective action, retest, evidence, and closure. |
| Provider Trust Graph | Maintain an authoritative evidence-backed view of provider identity, license, sanction/exclusion, ownership, affiliation, taxonomy, location, accreditation, credential, enrollment, effective dates, termination, and reverification. |
| State Value Ledger | Keep one evidence-backed baseline, intervention, calculation, category, and owner for each claimed dollar, counted once. |

North Carolina Provider Enrollment and Credential Continuity is the recommended read-only first
wedge, not an irreversible state selection. It is scoped to one provider class and scope, uses
authoritative state-accessible sources and relevant policy/contract tests, and requires
evidence-backed discrepancies, remediation/retest, parity/adapter/continuity artifacts, and zero
payment authority. Provider Trust Graph is a narrow first wedge of Mirror, never a rebranding of
the whole product. It remains distinct from Blind Ledger's operative clearance boundary and from
the broad `Continuity State`, which is a later state-owned operational handoff package.

## Product and promotion boundary

The first commercial wedge belongs externally to Mirror's Provider Trust Graph. It reports
evidence-backed findings, source coverage, discrepancies, remediation/retest status, parity cases,
and transition artifacts. It does not expose a Blind Ledger clearance receipt, create an operative
`ClearanceDecisionRow`, or authorize an economic mutation.

The current plaintext continuity module deliberately exercises the future five-directive Blind Ledger
semantics, but it is an internal conformance harness rather than the commercial wedge API. A future
versioned product boundary must keep these contracts distinct:

```text
authoritative source + policy/contract material
        |
        v
Mirror observation and Provider Trust Graph finding
        |
        +---- remediation, retest, parity, and transition evidence
        |
        v
candidate State Control Pack artifact
        |
        v
deterministic tests + state review/approval
        |
        +---- observation-only control
        |
        v
verifier-owned automaticControlSetId
        |
        v
Blind Ledger operative clearance eligibility
```

Behavioral Twin output enters only as a candidate. Historical incumbent behavior, compatibility
behavior, ambiguity, or a suspected defect cannot become state policy or automatic enforcement
without the explicit approval path above.

## Production-shaped patch-in contract

Blind Ledger and the Mirror/provider-continuity wedge are production-shaped, integration-ready
candidates. Their canonical business semantics and narrow artifact interfaces are intended to remain
invariant while production components are qualified and substituted: the five directives,
`policyResult`/`effectiveDirective` separation, verifier-owned control-set identity and rule order,
authoritative absence, the four distinct times, decision/access joins, exception identity, canonical
roots and ordering, immutable state transitions, retry/recovery behavior, and fail-closed parsing.
Productionization is qualification and adapter substitution, not an architectural replacement.

The fixed production plug-in seams are authenticated source adapters; real governance and
post-quantum signatures; production persistence and custody; state-owned deployment and support;
the executable Lean semantic kernel; and a theorem-qualified private-proof backend. The read-only
provider-continuity wedge may adopt the first four relevant Mirror seams without waiting for the
private-payment ZK backend. Blind Ledger's private clearance path still requires Lean, ZK, and
database/custody qualification. Every plug-in must pass the same canonical KATs, independent
verification, mutation/replay/recovery, and resource gates. An integration that changes the
canonical directives, result separation, roots/order, authoritative absence, four-time model,
decision/access join, exception identity, or fail-closed state semantics is not a patch-in and
requires architecture review.

| Current candidate seam | Production plug-in | Invariant interface | Qualification evidence |
| --- | --- | --- | --- |
| Mirror Provider Trust Graph source intake | Authenticated credential/enrollment source adapters | Canonical source coverage, provenance, completeness/nonmembership, findings, snapshots, and transitions | Graph independent verifier and focused mutation/rebound KATs |
| Governance Control Pack approval/withdrawal | Real governance custody and PQ signatures | External approval bytes, stage/root chain, source-contract and suite roots, observation-only flags | Governance KATs; Withdrawal V1 and lifecycle-head evidence is accepted as synthetic, local/current-Windows candidate evidence |
| Mirror Continuity V2/Restore V1 | Production database, custody, and deployment state store | Derived chain ID, immutable artifact/event/receipt roots, exact retry, export/restore, heads, and durable approval lifecycle head | 34/34 lifecycle/operational suite; local/current-Windows evidence is not a POSIX claim |
| Sanitized support boundary | State-owned deployment/support adapter | Allowlist-only diagnostics, bounded telemetry, zero-raw-identifier output | Support isolation and canary tests |
| Deferred Lean semantic target | Lean executable kernel and narrow native adapter | Canonical semantics, legal transition, replay, decision/access join, and after-state | Theorem/build/axiom and independent-kernel gates defined in `docs/LEAN_FORMAL_KERNEL.md` |
| Native-v3 private-proof seam | Theorem-qualified transparent PQ backend | Exact hidden-assertion statement, scoped receipt, state-owner binding, and complete security ledger | Six unresolved theorem/composition terms remain in the authoritative status record |
| Committed later checkpoint | Qualified Ethereum L1 checkpoint adapter | Additive ordered root/checkpoint binding only; no authority or payment mutation | Separate later cadence, verifier, key, custody, and PQ qualification; cadence is not fixed |

The term `Continuity State` is reserved for the broad state-owned operational handoff package:
in-flight claims, authorizations, appeals, provider applications, balances, exceptions,
configurations, interfaces, and unresolved work. A narrow provider-continuity audit root or
assessment state must not claim to implement that larger product capability.

## Pre-admission evidence modes

The verifier-owned control set selects exactly one evidence mode before admission. There is no
runtime fallback, caller-selected downgrade, or failed-proof conversion between modes.

| Mode | Evidence boundary and authority | Proof/signature meaning |
| --- | --- | --- |
| `DIRECT_STATE_OWNED` | The state owner evaluates canonical, non-PHI facts that it already lawfully holds. | No signature or ZK wrapper is required merely to re-prove the state's own facts. |
| `AUTHORITATIVE_ASSERTION` | A government-delegated authoritative source emits an operation-scoped, minimally disclosed derived assertion. | A qualified NIST-PQ signature authenticates source authority, provenance, and scope; it does not establish independent truth or source honesty and never selects disposition. |
| `PRIVATE_ZK` | The state independently verifies a predicate over hidden source-bound data. The source may sign one fresh randomized operation-scoped proof-native hiding commitment `P`; the proof binds its witness and predicate exactly to `P` and the current operation reference. | Proof acceptance establishes only the hidden assertion/predicate. It does not establish policy, state transition, chronology, directive, exception authority, outbox, or ACK. |

The state-approved control set fixes the mode, evaluator identity, profile, and source boundary before
a request is admitted. `policyResult` and `effectiveDirective` remain state-owned and distinct in all
three modes. Proof or signature acceptance never equals `CLEAR`. `proofSuiteId` belongs only to
`PRIVATE_ZK`; it remains null and unactivated until that complete private profile qualifies.

An undisclosed payment-relevant assertion affecting automation cannot receive authority from a
caller Boolean, host comparison, commitment alone, or a classical-only fallback. In
`AUTHORITATIVE_ASSERTION`, when the genuine source contract delegates canonicalization or derivation
to that source, the source signs the narrow operation-scoped assertion directly; that mode needs no
raw digest, dual commitment, or ZK wrapper. The signature establishes source authority, provenance,
and scope, not source truth or honesty. In `PRIVATE_ZK` with a source-attested witness, the source may
sign one fresh randomized operation-scoped proof-native hiding commitment `P`; the proof must bind its
witness and predicate to exactly `P` and the current `operation_ref`. That establishes source-attested
witness provenance plus predicate correctness, not independent raw-record correctness. If the state
requires independent raw-record-to-assertion verification, the proof must include the exact
canonicalization/link relation to the authoritative source representation. A signature over two
unrelated commitments only proves that the authorized key signed both bytes; it is not an equality
bridge. Exact in-circuit SHA3-512 is required only when the authoritative contract makes SHA3 the
representation that must be independently linked; otherwise a qualified proof-native representation
may be contracted. `P`, the canonical body, signature, and proof remain volatile and unlinkable, with
no stable digest. Blind Ledger never persists raw-data digests, deterministic claimant/provider hashes,
source capture, proof, signature, path, stdout/stderr, credentials, or stable cross-context
fingerprints. Blind rejects any claim that signed unrelated dual commitments bridge equality or that
destroyed artifacts remain independently recoverable. Official source custody and authorization remain
external audit dependencies.

### Current nonactivating authoritative-assertion candidate

The smallest current standardized source-auth candidate is
`sourceAuthProfileId=ML-DSA-44-PURE-HEDGED-V1`: FIPS 204 ML-DSA-44, pure rather than HashML-DSA,
with hedged signing and fixed context/domain `BL/SOURCE-AUTH/ASSERTION/v1`. Approved key-generation
RBG strength is at least 192 bits so the selected set retains its Category 2 claim. The signed body
is fixed-length-delimited and canonical, never JSON, and has no classical or algorithm fallback. It
contains only the exact state-issued 256-bit `operation_ref`, source authority/key/epoch, source
profile/rule/version, a bounded delegated-assertion enum/value, and a bounded validity interval.
It never contains a Blind directive, `policyResult`, `effectiveDirective`, exception, chronology,
state transition, payment amount, claimant/provider identity, raw-data digest, or other stable
fingerprint. This is a nonactivating candidate requirement, not module validation, HSM/FIPS custody
evidence, source truth, or production qualification.

Blind verifies the canonical body/signature ephemerally, destroys/discards those bytes after verification,
and persists only an opaque operation-scoped verification receipt/outcome plus qualified source-auth
profile/version/key epoch. Blind does not claim OS or crash-dump zeroization. The authoritative
source owns any lawful original retention. State recovery can prove only that Blind recorded a valid
verification at the time; it cannot reverify the original source signature from Blind storage alone.
A source-assisted later re-verification is a separate reacquisition event, not guaranteed recovery.
State audit/checkpoint PQ signatures may authenticate Blind's opaque receipt history, but do not
recreate or prove the original source signature. `proofSuiteId` remains `PRIVATE_ZK`-only and null.

`PRIVATE_ZK` preserves a no-secret/trusted-setup invariant. Deterministic, transparent, versioned
public parameters derived from reviewed standards or constants are allowed, but an activation
profile whose soundness or privacy depends on an unverified ceremony, toxic-waste destruction, or
hidden parameter custody is rejected. Every private profile requires an exact zero-knowledge/privacy
theorem for the actual adversary and transcript model: interactive protocols require
malicious-verifier privacy plus reset, abort, retry, and session composition; noninteractive
protocols require the exact NIZK or Fiat-Shamir/QROM privacy and soundness model instead.

## Clearance contract

The state-local verified receipt carries both the underlying deterministic result and the effective
directive. The fixed directive set is:

| Directive | Meaning | Automatic economic effect |
| --- | --- | --- |
| `CLEAR` | Every selected deterministic check passed. | May release exactly the committed amount to the official payment system. |
| `HOLD` | A fixable deterministic requirement is missing. | No release. |
| `HUMAN_REVIEW` | Judgment, ambiguity, unavailable authority, or additional evidence is required. | No automatic release. |
| `BLOCK` | A clear state-approved deterministic condition failed. | No release. |
| `EXCEPTION_APPROVED` | A scoped, current, authorized state override permits the payment despite the underlying result. | May release only within the override's exact scope, amount, and expiry. |

`EXCEPTION_APPROVED` is not a prover-selected escape hatch. It requires a separately governed,
signed, immutable exception-authorization record. The receipt preserves the underlying policy
result, rule, reason, approver authority, scope, and expiry so an override never erases the original
decision trail.

Every admitted attempt advances replay/audit state with one fixed observable shape, including
`HOLD`, `HUMAN_REVIEW`, and `BLOCK`. Economic clearance state changes only for `CLEAR` or a valid
`EXCEPTION_APPROVED`. A missing, malformed, stale, or failed proof produces no directive. A state
may operate a separately authorized emergency bypass for continuity, but that is a signed human
override recorded by Mirror, never a verifier failure relabelled as `CLEAR`.

## Private-proof path

```text
operation-scoped signed source assertion or source-bound commitment
        |
source-local custody and fixed-profile public statement
        |
fresh operation reference/challenge plus strict public allowlist
        |
private proof of the hidden source-bound assertion/predicate only
        |
independent native verifier
        |
opaque scoped verification receipt/outcome
        |
state-owned policy and transition evaluation
        |
one atomic clearance-state transaction and opaque outbox/ACK
```

The private proof relation does not own or emit policy result, effective directive, the five-directive
mapping, exception approval, state transition, chronology, outbox, or ACK. Lean and the clearance-state
transaction own those semantics. The public handoff contains only the one-time random operation
reference/challenge, assertion and profile versions, bounded validity window, ordered batch fields
when needed, and approved-source registry root when needed; it contains no names, claim numbers,
provider fingerprints, raw-data hashes, source paths, or stable cross-batch identifiers.

## Executable formal kernel

Lean 4 is the later mandatory target for the smallest executable semantic and legal state-transition
kernel; it is not active now. It owns the five-directive evaluator, `policyResult`/`effectiveDirective` separation,
control-set semantics, authoritative absence, chronology, governed exceptions, observation-only
separation, bounded canonical semantic decoding, replay, the exact decision/access join, and
allowed after-state.

Rust retains cryptographic proof acceptance, transcript and proof-envelope verification, and the
native operating boundary. The database retains concurrency, durability, recovery, and committed
operational state. For the private path, Rust proof acceptance and Lean semantic acceptance are
both necessary before the database may commit. For the direct path, the Lean kernel evaluates the
canonical governed plaintext input. Any disagreement rejects.

The Lean kernel is a deferred production plug-in, not a replacement for the canonical semantics.
Current qualification status is authoritative in `STATE.md` and `CURRENT_TASK.md`;
`docs/LEAN_FORMAL_KERNEL.md` defines the theorem manifest, executable correspondence, admitted
assumptions, CI gates, and implementation order.

## Authority boundaries

| Component | Establishes | Does not establish |
| --- | --- | --- |
| State Control Pack governance | Which deterministic rules and exceptions are approved, scoped, effective, tested, and eligible for automatic enforcement | That a source fact is honest or that an ambiguous policy question has one mechanical answer |
| Governed ingestion | Signature validity, signer authority, canonical bytes, validity interval, typed immutable registry membership | Real-world truth or policy wisdom |
| ZK proof | One hidden source-bound assertion/predicate opens its operation-scoped hiding commitment and is independently verified | Policy, state transition, chronology, directive, exception authority, outbox/ACK, source honesty, database durability, actual funds movement, or activation |
| Authoritative assertion | A qualified PQ signature authenticates an operation-scoped source assertion's authority, provenance, and scope | Independent truth, source honesty, policy, directive, state transition, or payment |
| Native verifier | Canonical parsing, transcript reconstruction, proof acceptance, and the narrow typed evidence receipt | Policy, directive, state transition, payment, or activation without the state owner and database |
| Blind Ledger database | Clearance state, concurrency, idempotency, recovery, and the accepted transition | Bank-account settlement or cryptographic truth without the native receipt |
| Official payment system | Actual disbursement under state authority | Proof correctness or independent operating truth |
| Mirror | Evidence-backed observation, reconciliation, responsibility attribution, and Blind Ledger's own failures | Facts beyond the evidence it actually receives |
| Lean semantic kernel target | Exact deterministic clearance meaning and legal local transition once implemented and linked | Source truth, policy wisdom, cryptographic soundness, database durability, or funds movement |
| Optional future checkpoint | Timestamped public commitment | Operational authority, source honesty, availability, or money movement |

## Operating, deployment, and commercial isolation

- RightRail corporate, ordinary support, monitoring, analytics, AI tools, contractors, crash dumps,
  and support tickets receive zero PHI and no persistent linkable claim fingerprint. Production
  diagnostics leave the state environment only through a bounded state-side sanitizer and use a
  synthetic reproduction where possible.
- Billing and covered-flow metering are downstream read-only observations. They cannot select a
  control, change a directive or exception, create a hold, influence remediation, or mutate
  clearance state. The same economic flow is counted once.
- The Switch owns compatibility and routing; Blind Ledger owns clearance. A route decision is not a
  clearance directive, and neither component moves money.
- Managed-care V1 is observation, contract enforcement, financial reconciliation, and
  state-authorized adjustment/withhold evidence. Direct gating of MCO-to-provider payments requires
  a later, separately approved authority and integration profile.
- Deployment authority advances only through observation, recommendation, flagging, human review,
  narrow deterministic controls, broader controls, and replacement routing. No caller can promote
  one rung to another. Excessive false holds, delay, or reliability failure invokes the governed
  fallback/bypass process and is recorded by Mirror.
- The state owns its rules, data, keys, histories, interfaces, tests, configurations, and continuity
  export. RightRail must remain replaceable without a proprietary operational dependency.

## Repository ownership and documentation map

The root authorities are `AGENTS.md` (execution), `CURRENT_TASK.md` (bounded work), `STATE.md`
(verified evidence), this file (system ownership), and `README.md` (entry route). The independent
design authority is `docs/DESIGN_IDEOLOGY.md`; the private-proof, database, Lean, Native-v3,
roadmap, dependency, rejection, and pending-domain-decision owners are linked from `README.md`.
Mirror's internal source-trust, custody, reconciliation, and recovery owner is
`docs/MIRROR_ARCHITECTURE.md`; this file retains only the whole-product role and cross-product
separation.

The following local documents have one component owner and one narrow purpose:

| Component | Local authority | Purpose |
| --- | --- | --- |
| Protected batch implementation | `app/batch/` source and focused tests | The code and tests own the retained compatibility format and pepper behavior; no separate legacy Markdown is current |
| Operations | [`ops/DEPLOYMENT_RUNBOOK.md`](ops/DEPLOYMENT_RUNBOOK.md), [`ops/KEY_CUSTODY_AND_ROTATION.md`](ops/KEY_CUSTODY_AND_ROTATION.md), [`ops/MONITORING_AUDIT_EVENTS.md`](ops/MONITORING_AUDIT_EVENTS.md), [`ops/PRODUCTION_CONFIG_CHECKLIST.md`](ops/PRODUCTION_CONFIG_CHECKLIST.md), [`ops/RISK_REGISTER.md`](ops/RISK_REGISTER.md) | Synthetic deployment, custody, monitoring, configuration, and risk procedures |
| Rejected architectures | [`docs/REJECTED_ARCHITECTURES.md`](docs/REJECTED_ARCHITECTURES.md) | Concise current prohibitions against restarting retired directions |
| Pending domain decision | [`docs/RARC_PENDING_DECISION.md`](docs/RARC_PENDING_DECISION.md) and `rarc_mapping.tsv` | Open mapping rows, source material, G8 split rationale, and required sign-off |

The release and documentation gates register every retained Markdown path. Markdown under retired
experiment or protected-proof lanes is forbidden; current prohibitions live only in
`docs/REJECTED_ARCHITECTURES.md`.

## Active target

- `docs/NATIVE_V3_ARCHITECTURE.md` is the private-proof, security, state, and resource qualification
  authority.
- `docs/DATABASE_ZK_ARCHITECTURE.md` owns the verifier-to-clearance-database transaction boundary.
- `docs/LEAN_FORMAL_KERNEL.md` owns the approved formal semantic/state-transition target and
  theorem gates; it is not implemented evidence yet.
- `app/production_boundary.py` and `app/transactional_database_boundary.py` are retained local,
  synthetic transaction references; they are not production selections.
- Full-width SHA3-512 identifiers remain externally authoritative.
- The proof backend must be transparent, post-quantum, non-ECC, independently verifiable, natively
  witness-hiding, and fixed-profile. Deterministic public parameters from reviewed standards or
  constants are allowed, but no secret/trusted setup, unverified ceremony, toxic-waste assumption,
  or hidden parameter custody may support activation. The independent state-side verifier and
  complete declared reference profile must meet the laptop-class 100/35 and strictly-below-
  5,000,000,000-byte gates. Source-local prover and optional-aggregator hardware may be declared
  separately, but their wall time/resources remain complete-profile evidence and component-only
  numbers receive no product credit.
- Activated external-authority and private-proof profiles require selected PQ primitive parameter
  sets at or above the declared NIST Category 1 comparison floor. That broad floor is not a generic
  proof-soundness theorem or an exact 128-bit proof; the complete proof/aggregate false-acceptance
  ledger must separately be at most `2^-128` after bounded attempts, fan-in, repetitions, batching,
  recursion/aggregation, and all composition. Source, authorization, configuration, and audit
  signatures are qualified PQ trust-boundary inputs; classical-only failure never downgrades.
- Every qualified cryptographic profile/key epoch has a hard global ceiling of `2^32` theorem-
  relevant acceptance opportunities, not merely process invocations, across all operations, retries,
  batches, hosts, tenants, instances, and verifier sessions sharing that profile/epoch. A batch or
  aggregate containing `n` independently false-able member statements conservatively consumes `n`
  member occurrences plus any separate aggregation event unless the exact selected theorem proves a
  smaller accounting unit. The state owner reserves each opportunity atomically before cryptographic
  acceptance work. Retries, aborts after challenge or verification begins, malformed candidate
  verifications, crashes after reservation, and other consumed reservations are never refunded.
  Exceeding the ceiling, overflow, cap exhaustion, ambiguous batch cardinality, or loss of trustworthy
  global coordination/counter state fails closed and requires rotation and requalification; this is
  assurance accounting, not throughput. The exact theorem ledger must cover the full globally reserved
  ceiling, apply the conservative member-plus-aggregation charge unless its exact theorem justifies
  less, and union proof soundness/knowledge, statistical commitment binding where applicable,
  transcript/challenge collisions, enabled aggregation, operation-reference collisions,
  abort/retry/reset, and every union factor to at most `2^-128`. Equal allocation across eight
  per-attempt classes requires at least 164 bits per event; use a 192-bit per-proof/statistical
  engineering target unless a tighter exact ledger proves the complete bound. Fresh state-issued
  256-bit operation references do not replace proof soundness, and no unbounded deployment-lifetime
  `2^-128` probability is claimed. Each suite's separate computational PQ ledger declares its
  adversary work/query model, signature/oracle counts, key lifetime, reduction loss, and whether the
  selected NIST category preserves the intended 128-bit product claim under the `2^32` ceiling;
  stronger categories are selected only when exact evidence requires them.
- RightRail corporate, routine support, monitoring, analytics, and AI systems receive zero PHI.

The rejected directions and their governing reasons are recorded once in
[`docs/REJECTED_ARCHITECTURES.md`](docs/REJECTED_ARCHITECTURES.md); they are not active owners,
release inputs, or qualification evidence.

Current qualification status, nonactivation flags, the process-tree ceiling, and the private-proof
blocker are authoritative in `STATE.md`; the current bounded phase is recorded in `CURRENT_TASK.md`.
