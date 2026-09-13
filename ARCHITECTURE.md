# Blind Ledger architecture

Updated: 2026-09-13

Blind Ledger is RightRail's state-side payment-clearance product. It answers one narrow question:
may this proposed payment proceed under the deterministic rules the state has approved for
automatic enforcement? It does not adjudicate an entire claim, decide ambiguous medical policy,
move money, replace the official payment system, or act as an L2, rollup, blockchain execution
system, or Solidity application.

## Current implementation boundary

This checkout is a synthetic, nonactivating candidate. The accepted source-admission and ownership
implementation is commit `1306e38901b73790dfb2a973b4ac44daf2ff6869`, tree
`1d04b16d29b2b298dc93817375cd258c9762b7ef`; its reviewed 100-operation path is evidence only.
Lean source and an adapter exist in separate earlier semantic checkouts, but no accepted executable
Lean artifact is linked to this runtime. The current State integration is a synthetic port, so
formal correspondence, theorem/axiom gates, PQ qualification, production readiness, and payment
authority remain open. See `STATE.md` for the exact current flags and retained evidence.

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
boundaries first. Raw source bytes are inspected only at the source boundary; durable Mirror state
begins with a sanitized observation and opaque verification receipt. Deep incumbent or vendor
telemetry is optional precision, never a V1 dependency.

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
| Provider Trust Graph | Maintain an evidence-backed view of provider identity, license, sanction/exclusion, ownership, affiliation, taxonomy, location, accreditation, credential, enrollment, effective dates, termination, and reverification. |
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

## Qualification and replacement seams

Blind Ledger and the Mirror/provider-continuity wedge are production-shaped candidates, not
qualified deployments. Productionization substitutes authenticated inputs, custody, persistence,
support, Lean, and the private-proof backend behind fixed interfaces; it does not rewrite the
five directives, result separation, ownership, roots/order, chronology, state transition, or
fail-closed behavior. The exact gates live with their component owners.

| Current boundary | Future replacement | Contract owner |
| --- | --- | --- |
| Mirror source observation, graph, export, and recovery | Authenticated source, state custody, support, and pilot operations | `docs/MIRROR_ARCHITECTURE.md` |
| Blind Ledger state transaction | Qualified database/custody adapter | `docs/DATABASE_ZK_ARCHITECTURE.md` |
| Lean semantic target | Pinned executable Lean artifact and narrow native adapter | `docs/LEAN_FORMAL_KERNEL.md` |
| Native-v3 private-proof boundary | Theorem-qualified PQ backend | `docs/NATIVE_V3_ARCHITECTURE.md` |
| Later public checkpoint | Governed Ethereum L1 checkpoint adapter | Database boundary owner; not a current dependency |

The term `Continuity State` is reserved for the broad state-owned operational handoff package:
in-flight claims, authorizations, appeals, provider applications, balances, exceptions,
configurations, interfaces, and unresolved work. A narrow provider-continuity assessment must not
claim to implement that larger capability.

## Authority and clearance boundaries

The state-approved control set selects exactly one evidence mode before admission: `DIRECT_STATE_OWNED`
for lawfully held canonical plaintext, `AUTHORITATIVE_ASSERTION` for a qualified operation-scoped
source assertion, or `PRIVATE_ZK` for a hidden source-bound predicate. There is no caller-selected
downgrade or runtime fallback. A signature or proof establishes only its scoped evidence result;
`policyResult`, `effectiveDirective`, exceptions, chronology, state mutation, and payment remain
state-owned. The exact private statement, source binding, privacy, PQ, and resource gates are owned by
`docs/NATIVE_V3_ARCHITECTURE.md`.

The fixed state-local directives are:

| Directive | Meaning | Automatic economic effect |
| --- | --- | --- |
| `CLEAR` | Every selected deterministic check passed. | May release the committed amount to the official payment system. |
| `HOLD` | A fixable deterministic requirement is missing. | No release. |
| `HUMAN_REVIEW` | Judgment, ambiguity, unavailable authority, or more evidence is required. | No automatic release. |
| `BLOCK` | A clear state-approved deterministic condition failed. | No release. |
| `EXCEPTION_APPROVED` | A separately governed current override authorizes a scoped exception. | May release only within its exact scope, amount, and expiry. |

Every admitted attempt advances replay/audit state. Only `CLEAR` or a valid
`EXCEPTION_APPROVED` may advance economic clearance state. A missing, malformed, stale, or failed
evidence result produces no directive. An emergency continuity action is a separately signed human
override recorded by Mirror, never a verifier failure relabelled as `CLEAR`.

The authority chain is:

| Owner | Provides | Cannot provide |
| --- | --- | --- |
| State Control Pack | Approved rules, scope, effective interval, tests, and exceptions | Source truth or an answer to an ambiguous policy question |
| Native verifier / source assertion | Canonical parsing and scoped evidence acceptance | Policy, directive, transition, payment, or activation |
| Lean target | Deterministic semantic meaning and legal local transition once implemented and linked | Source truth, cryptographic soundness, database durability, or funds movement |
| Blind Ledger database | Atomic clearance state, concurrency, idempotency, and recovery | Bank settlement or cryptographic truth without its evidence input |
| Mirror | Evidence-backed observation, reconciliation, responsibility, and RightRail failure records | Facts beyond received evidence or clearance authority |
| Official payment system | Actual disbursement under state authority | Proof correctness or independent operating truth |

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

The release and documentation gates register every retained Markdown path. Release selection uses
current-source lanes plus an explicit three-file compatibility closure; no retained prefix is a
keep map. Markdown under retired experiment or protected-proof lanes is forbidden; current
prohibitions live only in `docs/REJECTED_ARCHITECTURES.md`.

Rejected directions and their governing reasons are recorded once in
[`docs/REJECTED_ARCHITECTURES.md`](docs/REJECTED_ARCHITECTURES.md); they are not active owners,
release inputs, or qualification evidence. Exact technical gates and current qualification status
remain in their named owner documents, `STATE.md`, and `CURRENT_TASK.md`; this file does not create
a second readiness record.
