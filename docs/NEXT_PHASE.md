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

Desk research, 2026-09-24. Primary sources where possible; "[unconfirmed]"
marks a claim not verified against a primary source. Recheck before quoting to
a buyer: rules and dates move.

**Money and federal approval.**
- Federal match for Medicaid systems is 90% to build, 75% to run and 50% for
  other administration. States spent about $9.0B on these systems in FY2025,
  82% of it through contractors (MACPAC issue brief, July 2026).
- CMS must approve in advance any contract at the 90/75 match expected to
  exceed **$500K**, and any sole-source buy of $1M or more (45 CFR 95.611).
  MACPAC's brief says $5M; that figure is the regular-match threshold. Plan
  around $500K.
- CMS has 60 days to answer an advance planning document; no answer means
  provisional approval.
- The conditions for the enhanced match (42 CFR 433.112(b)) name what we built:
  - (b)(10): business rules separate from code, readable by people and machines
    (the Control Pack).
  - (b)(20): documentation that lets other contractors run the system (the
    Continuity handover).
  - (b)(13): reuse.
- Risk: the state owns software *developed* with the 90% match. License the
  platform commercially; deliver state-specific rules to the state.
- Certification outcomes that fit (CMS certification repository, SMC v2.0,
  October 2025): FM1 accurate payments including recoupments, FM4 capitation
  accuracy and error correction, FM5 recoupment tracking and aging, FM8
  financial reporting, PI6 recovery balances.
- Certification timeline: 6 months in production plus about 6 months of
  readiness preparation; after that the 75% run match applies retroactively.
- Whether a ledger overlay that processes no claims counts as a system module
  is decided state by state with CMS. The fallback is the 50% administrative
  match with no certification.

**Security and accessibility.**
- Every module is built to NIST 800-53: independent assessment every 2 years,
  a penetration test, a system security plan, annual disaster-recovery tests,
  and business associate agreements (CMS certification repository).
- ARC-AMPE replaced MARS-E (first deadline March 4, 2026). Build to NIST
  800-53 Rev5 Moderate with an ARC-AMPE crosswalk; that covers both.
- GovRAMP (formerly StateRAMP):
  - Core: 60 controls, no outside assessor, small fees; the fastest entry.
  - Ready or Authorized: 6–24 months [unconfirmed].
  - Texas TX-RAMP Provisional allows contracting for 18 months while full
    certification is pending.
- SOC 2: about $25K–$80K in year one; a Type II report takes 6–12 months
  [unconfirmed].
- WCAG 2.1 AA deadlines moved to April 26, 2027 (ADA Title II, FR 2026-07663)
  and May 11, 2027 (Section 504, FR 2026-09266). Buyers will ask for an
  accessibility conformance report from 2027. Article XIII already requires AA.

**Purchase routes.**
- NASPO ValuePoint's Medicaid cooperative contracts cover claims, provider,
  pharmacy and third-party liability, but no finance module.
- The NASPO Cloud & Software Solutions 2026–2036 contract took effect September
  16, 2026, with resellers such as Carahsoft and SHI. Whether resellers can add
  a new product after award is unconfirmed.
- Texas DIR runs a yearly solicitation cycle, published each September.
- California's SB/DVBE option allows buys under $250K from a certified small
  business after two quotes; California also runs innovation proofs of concept.
- No documented case was found of a startup winning a first Medicaid finance
  contract quickly. Fast-route timelines are estimates.

**What the work looks like and where money is lost.**
- Staff reconcile in Excel, SQL and SAS outside the claims system (state job
  postings).
- Directed payments are projected at about $110B a year, with no central record
  of what was actually paid (MACPAC, October 2024; GAO-24-106202).
- Documented losses:
  - $207.5M in capitation paid for dead enrollees in FY2022 (OIG
    A-04-23-09010, December 2025).
  - Massachusetts duplicate-ID capitation became unrecoverable after its
    reconciliation window closed (OIG with the state auditor, 2024).
  - CMS does not track whether states return the federal share of plan
    remittances (OIG OEI-03-23-00041, May 2025).
  - $764.7M in federal overpayments on the CMS-64 that CMS's reviews missed
    (OIG A-06-23-09006, June 2026).
- States must return the federal share of an overpayment within 1 year of
  discovery, recovered or not (42 CFR 433 Subpart F). Tracking discovery date
  and aging is a recurring audit failure.

**Dated triggers.**
- Directed-payment fields in federal claims data: due September 2026.
- Quarterly death-file checks and 6-month redeterminations for expansion
  adults: January 1, 2027, bringing more recoupments.
- Ban on post-payment reconciliation of directed payments: rating periods from
  July 9, 2027.
- Grandfathered directed payments step down: January 1, 2028.
- Proposed rule CMS-2449-P, if finalized: January 2028 and 2029.

Framing consequence: describe RightRail as tracking and correcting actual
payment obligations and pass-through accuracy, never as reconciling directed
payments after payment.

**AI rules.**
- No CMS rule on language models in Medicaid operations was found. The limits
  are HIPAA, state policies and state AI laws:
  - North Carolina, Pennsylvania and Illinois bar confidential data from
    public AI tools.
  - Texas TRAIGA, from January 2026.
  - Colorado SB 189, from January 2027.
- Section 4 already satisfies them: advisory only, inside the state's boundary,
  and no identifying data.

**Consequences for section 5, in order.**
1. The first purchase is a 60–90 day shadow pilot under $500K on provider- and
   plan-level data with no member data, bought through a small-purchase or
   proof-of-concept route. Estimate: 1–4 months to contract.
2. Sell against the dated triggers above, not "modernization".
3. Get listed through a NASPO reseller (1–3 months) and enter the Texas DIR
   cycle (6–12 months).
4. A ready-to-paste advance-planning and alternatives-analysis insert mapping
   RightRail to FM1/FM4/FM5/FM8/PI6 and 433.112(b)(10)/(13)/(20), with the
   licensing position. Estimate: 4–8 weeks to build once.
5. Security groundwork in parallel within about 6 months:
   - a business associate agreement template;
   - GovRAMP Core;
   - the NIST system security plan and a penetration test;
   - SOC 2 Type I;
   - the accessibility conformance report.
6. Subcontract under directed-payment consultants, integrators or an
   incumbent's partner program, pitched as a controls layer for the prime.
   Estimate: 1–3 months.

Timing (founder, 2026-09-24): no investor or government pitching before the end
of 2027; an institutional round comes first, then states. Paid attestations
(items 5 and the accessibility report) are therefore timed about 6 months
before the first pilot, not now. Until then the product is built so it would
pass them: access control, audit logging, backups, WCAG 2.1 AA.

Composite estimate for a first state, counted from the first pilot rather than
from today:
- months 0–3: pilot contracted;
- months 3–6: shadow results;
- months 6–12: production contract;
- months 12–18: certification.

A standalone RFP typically takes 12–24+ months.
