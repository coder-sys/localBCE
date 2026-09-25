# Next phase: from proven core to something people feel

Written 2026-09-24 by the lead engineer at the founder's direction. Governs the
build order after the core rebuild (`docs/CORE_REDESIGN.md`) and scorecard land.
Every item follows CONSTITUTION Article XII (who feels it, when, the measured
unit, the friction removed). The full production target stays in
`docs/RIGHTRAIL_FULL_STACK_TARGET.md`; this file is the order of work and the
honest gap, not a second target.

## 1. Honest position

Built (synthetic, single machine, one workflow):
- Blind Ledger financial owner and an independent checker for one recurring
  responsibility (obligations, offsets, corrections), with append-only history,
  tamper refusal on open, exact-retry handling, and Lean-proven correction rules
  (13 gated theorems, 32 test vectors).
- Continuity export/restore/verify and Switch shadow comparison, as engines
  without a staff-facing flow.
- A thin staff workspace (one page) and Mirror read model.
- Provider App checking core (rules and Lean model, no app); Provider Trust Graph
  read model and basic viewer on synthetic NC-Medicaid-shaped data.

Not built: rule authoring/approval/publishing, a real daily staff workspace,
director and audit reporting, any real-data connector (MCO payment reports,
X12 820/835, MMIS extracts), login/SSO and role administration, hosting, key
custody, backups and restore drills, monitoring and on-call, accessibility
conformance, security attestations, and any second workflow.

Rough share of a first sellable version: 20-25% (engineering estimate, not a
measurement). The built part is the part that is hardest to retrofit; the rest
is where customers feel the product.

## 2. Is this headed for production grade?

The core's safety design already exceeds what most state Medicaid financial
tooling has (proven rules, tamper evidence, single writer, exact retries,
independent re-check, tested exit). The code is a prototype: Python and SQLite
on one machine. Production grade additionally requires, per target doc
section 9: a multi-user hosted service with state SSO and storage-boundary
authorization; state-controlled key custody; restore-tested encrypted backups;
monitoring, incident runbooks and a human on call; measured capacity; real
connectors; WCAG 2.1 AA accessibility; third-party security attestation; and an
independent reviewer. A supplier cannot certify its own consequential work
(target doc 9, "Independent assurance"), so some of this needs outside people
(auditors, penetration testers, an implementation lead who has run Medicaid
finance). Engineering can build nearly all of the software; attestation, on-call
and state relationships need humans.

## 3. Build order (each item: role, moment, measured unit, friction)

1. **Scorecard** (in progress). Hospital H journey through the real staff path,
   per role; a test fails on any worsened unit. Makes Article XII automatic.
2. **Mirror as a real daily screen.** State analyst, each morning: open items
   with age, owner, amount gap, next action, and evidence on one screen. Units:
   time-to-answer "what is happening and who owns it", staff steps, repeated
   evidence requests. Friction: chasing records, reconstructing history.
   Built to Article XIII: a declared interaction model first, the screens
   generated from or checked against it, exhaustive pathway proofs per role,
   and a real-browser crawl that must match the model. The same model and
   checks then apply to every later screen (rule change, handover, simulator).
3. **Proven rule change ("policy memo to live rule").** Policy lead and finance
   approver, when policy changes. An assistant drafts the Control Pack rule and
   its Lean proof obligations from the policy text; Lean checks the proof; the
   history replay shows the rule's effect on past periods; a named person
   approves; the rule ships as a versioned release. A failed proof ships
   nothing. Units: implementation days per rule change, correction accuracy.
   Friction: long change orders and vendor change requests.
4. **Handover demo.** Replacement operator, on day one: restore the Continuity
   package, verify, and continue work with no lost item. Units:
   contractor-transition effort, unresolved-item age across the handover.
   Friction: hard to replace vendors.
5. **Assistant-built connector, proven in shadow.** Implementation lead, during
   onboarding: an assistant reads a source's layout and drafts the adapter;
   Switch runs it in shadow against real history until it reconciles to the
   cent; only then is it accepted. Units: implementation days, support effort.
   Friction: long implementations, missing data.
6. **Policy simulator.** Director, before a policy decision: replay history
   under a proposed rule and show dollars moved, providers affected, and likely
   disputes. Unit: decision-preparation time. Friction: decisions made blind.
7. **Contradiction finder.** Analyst, continuously: flags where a plan report,
   a remittance and a contract disagree, with evidence attached, as a normal
   ledger item. Units: unresolved-item age, repeated evidence requests.
   Friction: missing and untrustworthy data.
8. **Institutional memory.** New staff, any time: ask why a past decision was
   made; answers cite exact ledger records. Unit: time-to-answer. Friction:
   reconstructing history after turnover.
9. **Rule red team.** Policy lead, before each release: an adversarial assistant
   searches the draft rule for loopholes (split claims, timing games). Unit:
   post-release corrections. Friction: gaming discovered years later in audit.
10. **Cross-state benchmarks without sharing data.** Director, quarterly:
    comparisons against other states computed without raw data leaving any
    state (the parked private-proof track is the route). Network effect; only
    after a second state exists.

## 4. Rules for every AI-assisted feature

- The assistant suggests; Lean-proven rules decide; a named person approves.
  No model output changes financial state directly (CONSTITUTION: Lean decides,
  no silent fallback).
- Every suggestion passes a hard check before it counts: a Lean proof, a
  to-the-cent reconciliation, or a person's recorded approval. Failure means
  "nothing shipped", never "wrong thing shipped".
- Every suggestion, the model identity and version, and the accept/reject
  decision are recorded in the ledger history.
- No raw or identifying records go to an external AI service (target doc 9,
  "Privacy"). Assistants run inside the state's approved environment or only
  on non-sensitive material (public policy text, file layouts, synthetic data).
- We use existing foundation models; we do not train our own. There is no real
  data to train on, and the moat is the proven core, not a model.

## 5. Procurement and deployment: making the first "yes" small and fast

Principles (details and verified figures: see section 7):
- **Shadow first, read-only.** The first deployment reads files the state
  already produces, writes nothing to state systems, and moves no money. That
  shrinks the security review, the integration work, and the risk a buyer signs
  for.
- **Minimum data.** Where the responsibility works at payment and provider
  level rather than claim and patient level, stay there. Less sensitive data
  means lighter security, privacy and AI rules.
- **Deploy where the state already trusts.** A packaged, single-tenant
  deployment into the state's own government cloud tenant, or single-tenant
  hosting on an already-authorized platform, so the state reuses controls it
  has approved instead of reviewing a new vendor from zero.
- **Procurement kit, ready before the first call.** Security package, a
  third-party attestation plan, accessibility conformance report, contract
  language with tested exit rights and no outcome share, funding and
  certification language a state can reuse, and the synthetic supplier
  exercise (target doc 9) a state can run itself.
- **A small first purchase.** A fixed-fee, time-boxed shadow proof of value
  sized to fit fast purchase routes, converting to the full service on
  measured results from the scorecard.
- **Implementation as configuration.** Rules, connectors and reports are
  versioned configuration with proofs and shadow reconciliation, not custom
  code per state.

## 6. What will not be simple

- **Data access is contractual.** Managed care plans have little reason to hand
  over clean data; states often need contract amendments, which take time.
- **Data is late and messy, and history keeps changing.** Retroactive
  eligibility and adjustments rewrite past periods constantly. The append-only
  correction model fits this, but volume and ambiguity are real.
- **Policy is ambiguous.** Writing a rule as proven code forces decisions
  lawyers leave open. A proof shows the code matches the written rule, not that
  the rule matches the law's intent; people still own interpretation.
- **Incumbents.** Large fiscal agents and integrators will resist, or can be
  channels. Either way they shape timelines.
- **Procurement and politics.** Budget cycles, legislative sessions, protests,
  leadership turnover, federal funding approvals.
- **Security reviews** are long even for read-only tools.
- **People.** Staff trust, training, and changing a daily routine.
- **AI limits.** Automatic rule-and-proof drafting will fail on complex rules;
  sensitive data limits which models can be used; state AI policies vary.
- **Our capacity.** One founder and one AI engineer. Independent review,
  on-call, attestation and state relationships need more people.

## 7. Verified procurement and Medicaid facts

Pending: a sourced research pass (2026-09-24) on federal match and advance
planning rules, modular certification, security frameworks, fast purchase
routes, day-to-day Medicaid finance work, and state AI rules. Findings are
folded in here with sources when complete; until then section 5 is direction,
not a verified route.
