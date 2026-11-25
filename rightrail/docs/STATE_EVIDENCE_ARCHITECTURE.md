# The evidence model and how RightRail grows

Design target, not built; `STATUS.md` says what runs. Every effect described for a later stage is a design claim until
measured. Marks: (E) estimate, (RR) inference. Rollout order, speed bars, custody and cosign, bypass rules and standing
claims are owned elsewhere and only pointed to here: see `docs/RIGHTRAIL_FULL_STACK_TARGET.md` (TARGET) and
`CONSTITUTION.md`. This document owns the evidence model, the roles and what a state must do to adopt it (section 14).

## 1. The problem in one paragraph

A state Medicaid agency is not a payment processor; it already has one (the claims system, the fiscal agent, the
plans, the pharmacy benefit managers). It is a fiduciary that spends about $957B a year (FY2024 CMS-64) of mixed
federal and state money through intermediaries. The federal government pays its share only if the state can show that
each dollar met the conditions for it, and it checks years later (PERM, deferrals, disallowances, and from about FY2030
the §71106 penalty). The state's real problem is **proving entitlement to federal money, under audit after the fact,
from facts held by other parties, under rules that keep changing, with fewer staff.**

The architecture that fits keeps every fact with its source and its two times, makes each payment's justification one
rechecked record, runs rules as state-owned data, and sends each missing fact to whoever can supply it. RightRail's
decision core is already the right engine for this. What is missing is the layer of facts and time that feeds it.

The value is largest where the evidence is thinnest. Missing documentation is 77.17% of improper dollars in the
federal error measurement, and eligibility evidence is where the state has the least of it (the eligibility rule
requires claims data first, 42 CFR 435.557), so the record sells first as evidence, ahead of payment correctness. The
money a fee-for-service gate can reach is only about 5% of improper dollars (RR).

Success is measured by the work removed, not the proof held. The state stops rebuilding, chasing, recoding,
reconciling, reporting and re-procuring (section 2), and every role's day gets simpler (section 3, Constitution
Article XII).

## 2. What the state stops doing: the six wastes

Nearly all of the work the government spends the most time and money on falls into six kinds. Each exists for one
reason: nothing settled and recorded the payment, its evidence and its rule at the moment of decision. Figures are from
public audits, CMS data and state reports.

| Waste | Today | Why it exists | What ends it | Fate |
|---|---|---|---|---|
| **Rebuilding** | Rebuilding what happened after someone asks:<br>• PERM and MEQC file pulls (77.17% of improper dollars are missing documentation)<br>• deferral responses (Minnesota: three deferrals totalling $549.7M; California: $1.34B in one quarter), where most deferred dollars turn on provider paper and other state systems, not the claims record alone<br>• capitation base data rebuilt each cycle from three years of scattered data<br>• Georgia's 237,400 lines that did not reconcile<br>• waiver cost-neutrality and budget-neutrality baselines | The evidence was not kept with the payment | The warrant: evidence is made once, at decision time, and every later question is a query | Gone as work. The questions stay; the rebuilding does not |
| **Chasing** | Staff and contractors chasing missing documents, and:<br>• recoveries (NY: $52.2M where recovery work had not been initiated)<br>• MLR remittances (49% of 495 reports incomplete)<br>• plan fraud referrals<br>• EVV records after payment (Colorado: $8.07M refund, $45.7M under review) | Whoever holds the fact has no reason to send it | The cure router (section 6.8) turns the incentive around: the party that wants to be paid supplies the missing fact. The state chases less, but the federal clean-claim clocks (42 CFR 447.45) still run and held items still land on state staff | Gone for routine cases |
| **Recoding** | Rules rewritten in vendor code by change order:<br>• TN change-order cap from $103.6M to $417.0M<br>• GA 35 change requests, over 104,000 hours<br>• FL one change, 28,000 hours<br>• TX TIERS +118% with no new competition<br>• "all 56 programs" paying for the same federal change<br>• 101 NC and 88 OH county offices configured one by one | The rules live in vendor code | Rule packs: the state edits signed data, sees the dollar effect, and signs. A pack written once can be adopted by every state | Moved in. Change orders for policy logic are gone |
| **Reconciling** | Records from different systems compared afterwards:<br>• CMS-64 against T-MSIS (61.4% to 139.2% by state)<br>• subcontractor records against state records<br>• directed-payment spreadsheets reconciled months later<br>• recoupments as separate transactions (Ohio)<br>• sanction reports ($2,500 reported against $33.8M) | Each system keeps its own history | One ledger. Every report and every party's totals are views of the same records, so they agree by construction inside the ledger; flows outside it (plans, the claims system) still differ and are split by cause. Differences that come from outside are split by cause (section 8.2) | Gone inside the ledger |
| **Reporting** | Reports compiled by hand:<br>• prompt-pay reports<br>• monthly certification metrics, or the 75% match is lost<br>• vendor performance checks (Texas could not verify them; 11 of 15 noncompliance instances reported)<br>• averted-savings counts<br>• directed-payment provider-level reporting<br>• denial reporting (only 23 states and DC require it) | Facts are summed by hand from separate feeds | Every report is a derived view, recomputed by the open checker, so the state never self-reports a number that can be gamed | Gone as work |
| **Re-procuring and switching** | • NCTracks: over $600M to keep the old system to about 2029<br>• knowledge transfer that never happens (Michigan)<br>• three-year procurements<br>• protests that keep the incumbent in place | History and rules live inside the vendor | A state-owned open format, the open checker and replay: a successor reads the record and runs it | Shrunk, not removed: replay lowers the cost of testing a successor, while procurement (about three years), protests and certification (15 to 44 months) remain |

What remains is the work only people or law can do: policy; the actuarial opinion; clinical care; money movement;
prosecution; site visits; help for members; the eligibility worker's final decision (the caseworker and county office remain the decider; RightRail shows evidence side by side and records what was shown); federal approvals. The goal is
that state staff spend their time on these.

**At full scale (RR, each stated so it can be tested).**

1. The claims system shrinks to a data feed and a payment-file writer. Decision, evidence, history and reports move
   out of it, so the state buys a far smaller contract at its next re-procurement, about three years out.
2. The eligibility integrator shrinks to screens and case management. Eligibility rules and their evidence become
   state data. A policy change is a rule-pack edit, not a set of $849,000 change cycles.
3. PERM becomes a check of a record that already exists. The open checker recomputes the error rate continuously. The
   state could then ask CMS to accept the record in place of file pulls. That is CMS's decision; it is the end-state
   test, not a claim.
4. Fifty-six programs stop building the same thing. A signed pack for a federal rule (work hours, six-month renewals for
   expansion adults, death-file checks) is written once with its tests, and each state adopts it with its own parameters. This answers the
   state directors' association's complaint: "56 programs separately pay to develop substantially similar capabilities".
5. The call centre stops being how providers learn payment status. A provider sees why a payment waits and what settles
   it (Hawaii waits of 398 minutes).
6. Measurement turns honest without new staff. Every line records both directions (pay, hold, deny), recomputed by an
   open checker. Independently rechecked measures work (child support); self-reports tied to money get gamed (SNAP
   quality control: 42 of 53 states under-reported).

Each responsibility RightRail takes names, before go-live, the old tasks it retires and their measured baseline (TARGET
§1). Shrinkage is counted in staff hours and contract dollars retired.

## 3. What it feels like

Staff never see the machinery: assertions, the two times, read sets, belief, packs and warrants. Article XII.5 forbids
internal identifiers, digests or codes on screen. Article XII.8 sets the rule for work: what the system can fix, it fixes
and notes; what needs a person reaches them once per cause, with the reason, the money, the deadline, the owner and one
settling action.

| Role | Moment | Today | With this design | Measured unit (Article XII) |
|---|---|---|---|---|
| State program analyst | Monday morning | Pulls reports from several systems, reconciles by hand, guesses who owns what | Opens to "Two things need you", for example: "$4.2M waits on one cause: Plan B's October encounter file is missing 1,214 lines. Due Nov 20. [Send the plan the request]." Everything else fixed itself and is noted | Time to answer "what is happening and who owns it"; unresolved-item age |
| Finance approver | Signing a payment run or a bypass | A spreadsheet and trust | One screen: the total, what is held and why in plain words, the federal dollars at risk, and one Sign button | Decision-preparation time |
| Program director | A rule changes (a court ruling, a new law) | A change order, months of work, a vendor estimate | Edits the rule as data and sees, for example, "this changes 14,233 payments, +$1.2M, and these 3 providers most", then signs. It goes live the same day | Days to put a rule live |
| Auditor or CMS reviewer | A deferral or PERM question | Weeks of file pulls | Picks a line of the report, sees each dollar's conditions, sources and when they were known, and exports the pack | Repeated evidence requests; time to answer |
| Provider billing staff | A payment is held | Calls, waits, resubmits blind | Sees the one missing item and where to send it. The payment goes when it lands, with no call | Support effort; staff steps |
| Plan or vendor operations | Their data has a problem | Finds out months later in an audit | Gets one finding per cause, with the affected lines, as it happens | Correction accuracy |
| Caseworker | Deciding an eligibility case | Looks across several systems and the file for the evidence | Sees the evidence for the determination side by side, read-only: what each source said, when, and what is missing. The decision stays theirs, and the view records what was shown | Time to the decision; evidence requests per case |
| County office | A rule or source changes | Configures and re-trains one office at a time | Sees one finding per cause for its cases, with the evidence and the owner; settles it once | Findings per cause; days to settle |
| Replacement operator | Taking over | Months of knowledge transfer | Replays the record and gets the same results | Contractor-transition effort |

Rules this adds:

- **What reaches state staff (design goal; the code has 285 causes today, each with one action).** Only three kinds of hold: a conflict on a record the state owns, an authority request, or a
  cause with no outside owner. Everything with an outside owner goes to that owner. A machine fault, such as a stale
  registry or a dropped connection, is fixed by the system and noted, and never shown as work.
- **Grouped by cause.** One fix clears every line it settles, for example one plan's file, one provider's enrollment or
  one stale source.
- **Answer first.** Every screen leads with what is happening, the money, the deadline, who owns it and one action.
  Detail (the warrant, the sources, the times) is one step away for those who ask, mainly auditors.
- **Measured.** The synthetic demonstration measures these units per role, before and after. A mechanism that adds a
  staff step is a regression, however correct it is.

## 4. First principles: what must be true for one dollar

Every Medicaid dollar the state releases, and every dollar it claims from CMS, rests on the same seven conditions:

| # | Condition | Who holds the fact today | How it fails now |
|---|---|---|---|
| C1 | The person was eligible on the service date | The state eligibility system (often a vendor) | 4.42% PERM eligibility error, $27.0B; 77.17% of improper dollars are "insufficient documentation" |
| C2 | The service was covered and actually delivered | The provider, the EVV vendor, the plan's encounter | Personal care is the top fraud-conviction category; EVV "exists but does not verify" |
| C3 | The provider was qualified and alive, not excluded | State enrollment, NPPES, LEIE, the death file | $3.33B in screening and NPI errors (FY2025) |
| C4 | The price was right | The fee schedule, the plan contract, the state's pricer | Wrong rates, retroactive rate changes |
| C5 | No one else should pay first | TPL carriers, Medicare | Pay-and-chase |
| C6 | It was not paid already | Each system's own history | Duplicates across systems and states (at least $4.3B in multistate capitation, 2019-21) |
| C7 | It was claimed and reported correctly | CMS-64 and T-MSIS, rebuilt by hand | $2.76B deferred in two states in 2026 |

Three observations decide the architecture:

1. **No single party holds all seven.** Every condition is a join across systems owned by different parties. Errors live
   in the joins, which is why each system's own history disagrees.
2. **Every condition is judged twice:** when the money moves, and again later by an auditor who asks what was known
   then. Today the second judgment rebuilds the first from memory and paper, which is where "insufficient
   documentation" comes from.
3. **Every condition can change after the fact:** retroactive eligibility, a death reported late, a rate fixed upward, a
   claim voided, a rule struck by a court (D. Mass., Oct 29 2026). Truth arrives late in Medicaid; that is normal, not
   an error.

## 5. Ten ideas that shape everything

1. **Build the proof, not another payment system.** RightRail never moves money (Constitution I.4). Its product is the
   state's justification for each dollar, made at the moment of decision. The gate forces the justification to exist
   before money leaves, while the facts are fresh.
2. **One object serves every problem: the warrant.** One payment line (or member-month, encounter or determination),
   the seven conditions, each settled by cited facts, the rule version, the decision and the authority. A PERM answer, a
   deferral answer, a T-MSIS row, a recovery and a staff work item are all views of warrants.
3. **Two clocks.** Each fact has a *valid time* (when it was true) and a *known time* (when the state learned it).
   Diligence is judged at known time: was the decision right given what was known? Money is settled at valid time: what
   is owed now that more is known? Keeping the two apart turns retroactivity from chaos into a query, and turns
   "insufficient documentation" into a record of diligence.
4. **Read sets make reopening exact.** Each warrant records every fact key and date it consulted, including keys it
   found empty ("not on the death file as of load L"). When a fact arrives late or a rule is withdrawn, the affected
   warrants are exactly those whose read set touches it. A build system recompiles only what a changed file touches;
   this does the same for money.
5. **Documents stop being evidence.** Generating a convincing record is nearly free. What still costs a fraudster
   something is agreement between independent sources: the state's own eligibility system, the SSA death file, an EVV
   device, the bank remittance, the plan's encounter. Rules therefore name how strong a source must be, and when two
   independent sources must agree. Paperwork alone never satisfies a condition that money depends on.
6. **Rules are data in a small total language.** Medicaid rules are lookups (fee schedules, code lists, NCCI pairs),
   date-interval tests (enrollment spans, the IMD 15-day limit), counts and sums over a window of history (frequency
   limits, posting caps, duplicates), source-strength tests and clocks (prompt pay, timely filing). A language with only
   these pieces, and no loops, always terminates, and its per-line cost can be computed from the pack before the state
   signs it. That ends rule changes as vendor change orders and makes the speed bars (TARGET §12) a checked property of
   each pack.
7. **A hold is a missing fact with an owner.** Fail closed (TARGET §6) survives politically only if holds clear fast and
   without state staff, who are shrinking (mean 1,050 FTE per agency). Each hold names the missing fact and the party
   that can supply it, and the gate decides again the moment it arrives. The cure loop carries safety; it is not
   decoration on the screen.
8. **Managed care is not a separate product.** An encounter is a warrant on which no money moves. The same seven
   conditions run over a plan's encounters at OBSERVE authority (TARGET §3). The state's directed-payment dollars
   ($143.8B) are then released on proof that services were used, which 42 CFR 438.6(c)(2)(vii) already requires: an
   accepted encounter, or the hospital's own claim agreeing with the plan's 835 payment to it (section 7), and capitation is a warrant per member-month. The 54.6% of benefits inside plans becomes visible
   through data plans must already send (438.818).
9. **The federal claim is a derived view.** Each warrant carries its funding facts (eligibility group, FMAP). The
   quarterly CMS-64 becomes a sum over warrants, and every line drills down to evidence. Federal dollars at risk per
   hold (amount x FMAP) set the order in which work is done.
10. **RightRail must be replaceable to be trusted.** All state truth (facts, rule packs, warrants, money records) lives
    in an open format the state owns (Constitution VII). An open checker recomputes every warrant from facts and packs.
    A successor can replay the whole record. A vendor whose truth leaves with it is exactly what the state is trying to
    escape ($44.1B spent on eligibility and claims-system builds, 2008-18).

## 6. The architecture

### 6.1 Four record kinds, one writer, one store

There is one writer per shard, appending to one hash-chained log in one store. Today's two stores (the owner's, with
its 10,000-row cap, and the gate's flat store) become one.

| Record | What it says | Never | Key invariant |
|---|---|---|---|
| **Assertion** (fact) | Source S, at known time K, says P held over valid interval V. Includes the source file hash and offset; the source class; the producer and release that made the fact (a system, a model or a person, and whose affiliate it is); and the sender, channel and signing key it arrived under | Edited or deleted; a later assertion supersedes it | Append-only; K comes from the trusted clock (6.7). A model's output never alone supports an action against a member (Constitution I.3) |
| **Rule pack** | A state-signed, versioned set of rules, each citing its legal source, with test vectors and a cost bound | Changed in place; a new version is signed | Activated only by state signature; withdrawal is itself a record |
| **Warrant** | Line identity (Constitution III.3), conditions with verdicts, cited assertions, read set, pack version, decision, authority grant, known time | Rewritten; a later re-decision is a new warrant that links to the old one | Decision = interpreter(pack, belief at K, line); the checker recomputes it |
| **Money record** | Obligations, releases, settlements (835/ACH acknowledgment, Constitution II), federal claim lines, refunds, items lawfully recorded after payment. Also amounts the state's money depends on that move between other parties: a plan's recovery from its provider, a finding or sanction against a plan per rating period and cause, an MLR remittance, a risk-corridor or retroactive rate settlement per plan, rate cell and period, a drug rebate owed, and a provider-level adjustment that names no line | Moved without a warrant | Money is conserved: released + held + owed = obligated; each dollar is released at most once. A rebate or a provider-level adjustment is its own record: it may exceed a line's paid amount and is never netted into a release, and it is allocated to lines only where its source names them |

### 6.2 Belief: what the state knows, as of when

`belief(K, key, D)` is the state's view, at known time K, of a fact key (a member, provider or plan) on date D. It is a
deterministic function of the assertions with known time at or before K whose valid interval covers D, taken in
precedence order: source class first, then latest known time. Every source declares its coverage: which people,
places, fact kinds and periods it can see, and whether a load is a full file or a change file. A wage file that never
sees cash, gig or out-of-state work, an other-coverage file from listed carriers only, and a death file that lacks some
records are partial by nature. Belief has four results:

- **present**: the fact holds (for example, enrolled in group X).
- **absent**: a fresh source says no, and the key lies inside that source's declared coverage (for example, not on the
  death file as of the 11-02 load). An absence is only as good as the source's last load and its coverage.
- **unknown**: there is no fresh source whose coverage includes the key. A miss in a partial source is unknown, never
  absent. An unknown may support an exemption or a renewal; it never supports an action against a member.
- **conflict**: sources disagree on a fact that a money or coverage condition reads. This includes a registry or device
  record (class b or c) contradicting the state's own system (class a): precedence does not hide it. A conflict goes to
  the owner of the record in question (the office that made the determination, the plan, the registry), one item per
  pair of sources and cause.

A stale fact is never treated as current: it reads as unknown.

**What an unknown does depends on who can supply the fact.** Each pack condition names the fact's owner and says
whether the law makes the fact a condition of this payment:

1. *A payment condition the payee can cure* (an EVV visit, documentation, an NPI fix): the line holds and the cure goes
   to the payee.
2. *A payment condition owned by someone else* (a registry load, a plan's encounter, a pending determination): the line
   holds, grouped as one item per owner and cause. The payee sees the reason, the owner and the clock, and any other
   evidence the law accepts that the payee can supply itself (for directed payments, section 7). The owner, not the
   payee, is escalated before the clock runs out (6.8). The line never releases because a deadline arrives: paying on
   a stale fact or while the gate is down is reserved to the single-payment bypass in Constitution I.2.
3. *Not a payment condition*: a fact another office decides, such as work hours or an exemption (decided by the
   eligibility office), or a field a plan contract does not yet require, such as the ordering NPI on an encounter. Its
   absence never holds a payment line. The payment reads the decision that office has made, here the member's current
   enrollment, and the missing fact is one finding per office or plan, field and release, at OBSERVE. Coverage ends
   only through the office's own action with notice (42 CFR 431.211); payments before that date were lawful.
4. *Other coverage* that is not established when the claim arrives does not hold the claim; the law requires payment
   (42 CFR 433.139(c)), and coverage found later reopens the line (6.4).

Kinds 3 and 4 keep Constitution III.5: the payment decision reads only the facts the law makes payment conditions, and
those are present. A fact that is not a payment condition is not an input to the payment, so its absence is recorded as
a finding with an owner, never a silent default.

Source classes, strongest first: (a) the state's own system of record (eligibility determination, provider
enrollment); (b) independent registries (SSA death file, LEIE, NPPES, the PARIS interstate match, bank settlement);
(c) device and event records (EVV time and location, real-time NCPDP); (d) counterparty assertions (claims, encounters,
attestations); (e) uploaded documents. Rule packs state the minimum class, and any agreement needed, for each
condition, as the law sets it, including self-attestation where the law accepts it. Commercial wage data, other-program data and model output are named
sources with their measured error rate; they are class (d) unless the pack cites why they rank higher. Where an
independent source exists for a determination's key inputs (income, household, residency), the pack requires agreement
with it.

### 6.3 The rule interpreter (proved once)

Primitives:
- `lookup(table, key, date)`;
- `within(interval, date)`;
- `count` and `sum` over a bounded history window keyed by a tuple (member, provider, code, period);
- `has(kind, minClass, maxAge)`;
- `agree(kind, n independent sources)`;
- `clock(start event, days)`.

Each condition yields PASS, FAIL(reason) or UNKNOWN(fact kind, source, responsible party). The decision outcomes, and
how they map onto hold, review and block, are in TARGET §4 and §6; the authority bounds on holds (a hold only for
reasons the grant names, TARGET §3) apply unchanged.

Each rule names its applicability key: the service date, the application date, the member's first renewal on or after
a date, the state fiscal year, or the rating period, with named calendars and business days. It cites its legal source
by type, number, date and file hash, and carries its federal status (pending, approved, deemed) and the contract
version it relies on. A rule may run in record-only mode, deciding and recording without effect, below the flow's
authority level (a soft launch). A contested or pending parameter (an appealed court order, an unapproved preprint,
an ambiguous contract term) runs both readings; dollars that depend on it are tagged contingent, one item per rule,
preprint or term. Dated funding parameters (a service-specific match rate and its quarter count, an EVV match
reduction, the demonstration and its budget-neutrality category) are pack data cited by each warrant.

What is proved once, for every pack: termination, determinism, equality to the specification, a per-line cost bound
computed from the pack, and the release-once and authority invariants (the universal theorems are listed in TARGET
§9). The truth of a pack's content is not proved. That is the state's policy (Constitution I.1), tested by the pack's
own vectors and by shadow runs over history before the state signs (6.6).

Pricing stays out. The state's pricer (DRG and APC groupers, contract rates) is a source of class (a). Rules check its
output against bounds, such as a fee schedule ceiling or a directed-payment cap, and never reimplement it.

#### 6.3.1 First version: today's rules as signed data

The first version carries only what the first jobs need: the gate's fact rules (R1-R5 in GATE_RULES_V1) as data the
state signs, run by one Lean interpreter, so an audit folder and a replay can name the exact rules in force for a line.
The primitives above beyond these come with the packs that need them. Bytes: `conformance/RULESET_V1.md`. Model and
statements: `lean/BlindLedger/Gate/RuleSet/Spec.lean`.

Record. A rule set is a header, a list of legal sources, a maximum age per reference source, and up to 64 rules, then
a KEYSET/v2 signature block. The header names the state and tenant, a version chained to the previous version's digest
(as key sets chain), a signing window of at most 31 days (as an APPROVAL/v2 grant), an effective range over the line's
date, and the earlier versions this one ends. A rule names one reason, one legal source and one condition. The rule
set's digest is its identity: the next version's `prev`, the payment token leaf's `ruleVersion`, and what a decision
record cites.

Signers. A POLICY quorum of the shard's admitted key set: at least `kPolicy` distinct employees, each with a POLICY key
(role 6) live on the head's day (unrevoked and inside its validity window), sign the message. The state sets `kPolicy`
from 2 to 8 in its key set. A key set does not decode if one employee or one identity-provider subject holds both an
unrevoked POLICY key and an unrevoked key of any other role (ROSTER, SOURCE, APPROVER or any), or if unrevoked POLICY
keys do not map employees and subjects one to one, so the signers are distinct people under distinct subjects and none
of them can also manage keys, attach facts, release or bypass. Roster keys add and revoke POLICY keys but never sign a
rule set (the single state agency keeps policy authority, 42 CFR 431.10(e)). A key set with no POLICY key keeps its old bytes.

Two times. Valid time is the effective range over the line's date (the date of service, or the first day of a
capitation month). Known time is the batch that admitted the record: a rule set admitted in batch `kb` governs
decisions from batch `kb + 1` (a decision batch `B` reads as of `K = B − 1`, as fact records do). A later version
corrects an earlier one by ending its range, never by editing it: an end cuts the named version's range to a date, or
withdraws it for every date. Ends replace the separate rule withdrawal record of the fact-record design.

Conditions. A small tree language: AND, OR and NOT; the line's flow; whether its date is a calendar date; whether a
source was read and whether it is fresh at the rule set's maximum age; whether some row of a source names the line's
member or a party with a date before the line's date, or an interval holding it (optionally with the line's plan); and
whether the member's enrollment shows two plans in the line's month. Depth at most 8, at most 8 operands per node. The
interpreter is structural recursion over the tree, so it always ends; every node has a fixed cost (1, or 2 to 3 for the
index probes), the record's total is computed from its bytes, and a record over 1,024 units per line does not decode.
Maximum ages are from 1 day to the law's ceilings (deaths 90, provider deaths 90, exclusions 31) and, for enrollment,
the product's ceiling of 10 days; a record listing no enrollment age uses 4.

What stays fixed. A rule set may fire only the thirteen fact reasons. The release-once rules (the duplicate and
identity reasons against the released and unresolved sets and within the batch), the line's own date checks, the
staleness of the two sets, each reason's outcome class, which reasons a bypass may override, and the batch structure
stay in Lean, so release once is stated for every rule set, signed or not (`allow_clear_any`). So does the enrollment
guard: an enrollment feed older than the rule set's enrollment age sends the line to review (`STALE_ENROLLMENT`), never
to an allow (`enroll_stale_allow`), and the guard adds no hold reason (`enroll_stale_hold`: under a stale feed the hold
reasons equal those with no feed; a suppressed `MEMBER_NOT_ENROLLED` drops the near-key relaxation, so a later line of
the same member and month may hold on `CAP_MEMBER_MONTH_DUPLICATE`, fail closed). A capitation line that its
rule set finds not enrolled claims no member-month, as today.

Today's rules as data. Pack 1 is today's ages (90, 90, 31, 7 days) and thirteen conditions, cost 82 per line. Its
equality with today's rules on every read set, key list, line and reason (`pack1_fires`), once proved, carries every theorem
about the current rules to a gate that runs pack 1 (`pack1_decideBatch`).

Refused, in this order: a record that does not decode (any bound above, the cost bound included); another state or
tenant; a head day outside the signing window; not the next version, a wrong `prev`, or an earlier batch than the last
version; an end that names no version still in force or does not shorten it; an effective range that, after this
record's ends, shares a date with a range still in force; fewer than a POLICY quorum of signatures. A refused record
never runs (`admit_unsigned`, `reachable_signed`, `select_mem`).

Replay. A line decided as of known time `K` runs under the one rule set admitted by `K` whose range, after the ends
admitted by `K`, holds the line's date (`select_unique`, `select_iff`). A line with none is not decided and its
payment is not released until a rule set covers its date. Replay depends only on what was admitted by `K`
(`replay_congr`), so a rule set admitted later never changes a past answer (`replay_later`); with the same facts and
the same known time, the answer is the same. Every name in brackets in this section is a stated theorem; its proof is
a proof slice below.

What it replaces, in order. Nothing in Python decides today, and nothing in Python is replaced; Python gains a twin
codec that carries the bytes.
1. Lean: `Rules/Spec.lean` `fires` becomes the interpreter under pack 1 once `pack1_fires` is proved; every theorem
   stated over `decideBatch` keeps its statement.
2. The fast twins, each re-proved through the interpreter instead of through `fires`: `Rules/Fast.lean`, then the claim
   engine's row rules (`Flat/DecideRows.lean`), then the history engine (`Engine3`).
3. The token leaf's `ruleVersion` changes from the engine's build hash to the admitted rule set's digest; the payer's
   check against the grant's rule versions is unchanged.
4. The fact-record rule withdrawal record is dropped for ends.
`conformance/gate_rules_v1_ref.py` stays as the independent checker of pack 1.

Build slices. Implementation slices:
- I1, codec. `app/right_rail_ruleset_codec.py` and the Lean `decode` and `encode`, with a golden table of record
  digests in the model. Accepted when `tests/test_ruleset_v1_codec.py` passes in full.
- I2, admission and series. The authority section carries a rule set; the gate admits it with the key-set head and
  stores the series. Accepted by must-reject frames for each refusal above and a two-version series replayed at both
  known times.
- I3, pack 1 live. The rules worker runs `firesP` under the selected rule set; the leaf's `ruleVersion` is the
  rule set's digest. Accepted when the gate rules vectors and negative vectors pass unchanged with pack 1 signed, and
  the token tests check the new `ruleVersion`, including that a grant naming only the old build hash makes the payer
  refuse the token (the payment holds; it never pays under rules the grant did not name).
Proofs, all done with no `sorry` (`lean/BlindLedger/Gate/RuleSet/Spec.lean`; statement pin and axiom audit):
- P1, interpreter: `evalC_eq`, `evalC_le`, `run_bounded`, `dataFires_core`.
- P2, equality: `pack1_fires`, `pack1_decideBatch`, `allow_clear_any`; P2 gates I3.
- P3, bytes and admission: `decode_canonical`, `admit_signed`, `admit_unsigned`, `reachable_signed`.
- P4, selection and replay: `select_mem`, `select_unique`, `select_iff`, `replay_congr`, `replay_later`.

### 6.4 Reopen: exact, never a rewrite

When a superseding assertion arrives, or a pack version is withdrawn (for example, the frailty test vacated on
Oct 29):

1. Find the warrants whose read set intersects the changed keys and dates (an index from key and date to warrants).
2. Decide them again at the new known time.
3. Where the verdict changes, write a new warrant linked to the old one, plus a money record of the right kind:
   - **overpayment identified:** an obligation that tracks the 42 CFR 433.312 one-year federal refund clock, owed whether
     or not the state recovers. The record holds every discovery event that 42 CFR 433.316 counts, each as an assertion
     with its document hash, and the clock runs from the earliest that applies:
     - the state's first written notice to the provider naming an amount; the provider's written acknowledgment of an
       amount; or a formal recoupment begun without notice ((c)(1)-(3));
     - for fraud, the final written notice of the state's determination, only after a fraud unit or law-enforcement
       agency accepted the referral or filed an action; the federal adjustment waits until 30 days after a final judgment
       ((d));
     - where a federal review finds the state did not identify, notify or recoup, the date CMS first notified the state in
       writing with an amount ((e));
     - for a DSH payment, the date the independent audit was submitted to CMS, if earlier ((f)).

     An increase within the year opens a new year for the increase only; a decrease or a partial collection changes
     nothing ((g), (h)). Some cases are exempt (433.318). Every overpayment record shows its days remaining;
   - **underpayment owed:** for example, an upward retroactive rate. A retroactive capitation change settles as one record
     per plan, rate cell and rating period; the member-month warrants are re-decided automatically and never listed for
     staff;
   - **other coverage found after payment:** a recovery record against the original line, with the 60-day clock of
     42 CFR 433.139(d)(2);
   - **lawful after payment, recorded:** for example, retroactive eligibility, a 433.139 TPL pay-first case, or a payment
     made under a court order that is later lifted. The state decides any recovery.
4. The old warrant stays. It proves that the first decision was right on what was known then.

Reopening is a record and a finding for the state. RightRail issues no notice, recoupment or bypass (TARGET §6); the
state decides what to send.

Theorem to prove: re-deciding only the warrants whose read set touches the change gives the same result as re-deciding
all of them.

### 6.5 Readers: where facts enter

There is one reader per source format: 834, 820, 837 (claims and encounters), 835 (the state's, and each plan's to its
providers, with paid and allowed amounts and dates), NCPDP, EVV, the death file, LEIE, NPPES, PARIS, Do Not Pay, the
eligibility-system extract, marketplace account transfers, wage and other-program data, the plans' prior-authorization
decisions (CMS-0057-F interface, from Jan 1 2027), provider directories, provider licensure and screening, background
studies, service authorisations, assessments and plans of care, and the records other systems already keep
(eligibility evidence history, rule-engine traces), which are checked against the record rather than trusted. Provider
paper is read with its origin kept: who sent it, when, and for which line. Findings by others (OIG, auditors, courts,
fair-hearing decisions, CMS letters) enter as assertions too, and a repeat finding links to the earlier one. Each reader:
- treats its input as hostile and receipts the file by SHA3-512 when it arrives, with the sender, channel and signing
  key it came under;
- emits assertions that cite the file hash and record offset, with a source class, the producer and release, and the
  source's declared coverage (6.2);
- repairs, resolves or quarantines the worst rows, and refuses a whole file only when it is untrusted;
- has an independent verifier that rereads the file and recomputes the assertions.

The list of lossless repairs a reader may apply is an open decision (TARGET §13).

### 6.6 Rule-change impact before signature

A new pack version runs in shadow over a chosen history window first. The state sees which warrants would change,
where, and by how many dollars before it signs. This ends the vendor change order: the state edits data, sees the
effect and signs. The same mechanism lets a successor replay the record (Constitution VII) and gives the comparison the
authority ladder uses before a flow moves up a level (TARGET §3).

### 6.7 Known time is money-critical

Diligence is judged at known time, and the refund and prompt-pay clocks run from recorded events, so the clock that
stamps known time must not be the host's. Today the host supplies the date and the gate trusts it (`STATUS.md`). Known
time should come from a hardware counter bound to a signed time from the state or a witness. The custody work (counter,
witnesses, checkpoints; TARGET §7 and Constitution VII) gains a second purpose here: it anchors when the state knew.
The mechanism belongs to the custody design; safety still never depends on clocks (TARGET §7).

### 6.8 The cure router

Each UNKNOWN goes to its owner through one API that people and their software agents use alike. Every submission is
attributed to a person (Constitution I.3), and the gate decides again when the fact arrives:

| Missing | Owner |
|---|---|
| EVV visit, documentation, NPI fix | Provider |
| Encounter, or a fix to one; a field the plan contract requires | Plan, one item per plan, field, service category and month |
| Proof of use for a directed payment when the plan's encounter is missing | The hospital may cure it directly (section 7); the plan's gap stays the plan's finding |
| A stale registry | No one: an automatic refresh |
| A pending or disputed determination | The office that made it (county or state), one item per office and rule; the caseworker sees the evidence and decides |
| Other coverage | TPL carrier, after payment (6.2, 6.4) |
| A conflict on a record the state owns, or a bypass request | State staff (a conflict on another owner's record goes to that owner, 6.2) |

Holds are grouped by cause, so one fix clears every hold that shares it. Clocks come from the pack: 42 CFR 447.45
requires 90% of clean claims paid within 30 days and 99% within 90, so the gate tracks each hold against its clock and
escalates to the fact's owner, not the payee, before a breach. When the payee cannot cure a hold, the payee is told
who can and by when, and the item counts against the owner's measures.

Measures that replace lines per second as the objective:
- state staff minutes per $1M protected;
- median time to cure, by cause and by owner;
- the share of holds a person had to touch;
- the share of holds the payee could not cure, by owner;
- for each signer, the rates of release, denial and later reversal, with approver rotation;
- dollars averted, counted only from the final state of a line's identity chain after a set window, never at the hold.

### 6.9 Shards and whole-state facts

Shards are keyed by member (TARGET §8). Each holds that member's assertions and warrants. Provider, plan and table facts
are small. They are carried in every shard as signed, versioned reference sets, and a warrant cites the version it
used.

Some facts span members: per-provider directed-payment totals against their caps, posting caps across members,
multistate duplicates from PARIS, and household cost sharing against 5% of family income (from Oct 1 2028), keyed by a
household assertion from the eligibility record. These are computed by a deterministic merge at batch close, using commutative sums.
Theorem to prove: the merge over shards equals the whole-state computation. SQLite per shard remains the store
(TARGET §8).

### 6.10 What leaves the state's tenant

In a real deployment, facts with PHI stay in the state's tenant, and the checker runs there. A warrant carries minimal
fields and hashes. Today everything is synthetic, non-PHI and state-local (standing claims: Constitution VI.2).

## 7. One set of parts, every problem

| Problem | What solves it |
|---|---|
| Eligibility error and §71106 | A **determination warrant** built from eligibility-system output and the evidence it used: required verifications present, fresh and of class (a) or (b); key inputs agreeing with an independent source where one exists; six-month renewals; the office that decided. Work hours and exemptions (from Jan 2027) are conditions of eligibility that the office decides; they are never payment conditions, so a missing hours fact is one finding per office and release, and claims pay on the member's current enrollment (6.2). Terminations and denials get the same warrant: the ex parte attempt against named sources, contact attempts by kind, the notice text and its delivery, one reason code from the pack list, and the application clock. RightRail never determines (Constitution I.1); it records, recomputes the computable part of each determination, and sends a disagreement to the office as one finding per rule, release and office. It holds a closure only where a state grant says so. The checker recomputes the error rate in both directions continuously, instead of the state self-reporting it. Payment warrants cite the determination warrant, so a chain runs from dollar to determination to evidence. A struck rule (the frailty test) reopens exactly the determinations made under it, in the affected states only |
| Managed care and directed payments | A capitation warrant per member-month. Encounter warrants at OBSERVE give a verified base for rate setting and 438.818, with the plan's paid and allowed amounts from its 835; a zero or missing amount is a finding for the plan, grouped per plan. Encounter completeness is measured per plan, month and service category (inpatient, pharmacy, home care named). Directed-payment law conditions payment on use of services in the rating period (438.6(c)(2)(vii)), and an accepted encounter is one proof of use, not the only one. A directed-payment amount is released on either an accepted plan encounter or the hospital's own claim agreeing with the plan's 835 payment to it (two independent sources). A plan that sends no encounters makes a finding against the plan per category and month; it never stalls the hospital. The first directed-payment flow stays at OBSERVE for each plan and category until encounter acceptance is measured, and moves to HOLD only where the measured acceptance shows holds would clear within the payment schedule the preprint sets. Caps are tested on totals per hospital and rating period against the approved amount and a Medicare-equivalent price per service class from the pricer (§71116), never per line; the per-unit add-on is a signed preprint parameter. Plan recoveries, sanctions, remittances and corridor settlements are money records (6.1). Provider-level reporting to T-MSIS (438.6(c)(4)) is a by-product |
| Deferrals | Query the warrants behind a CMS-64 line and produce the pack: each dollar, its conditions, sources and known times |
| Home care and EVV | C2 requires agreement between the EVV visit and the claim (class d) on member, worker, time and place. Each visit carries how it was captured (device location, phone, fob, manual entry, location exception) and a reason code; only device capture is class (c), and an aggregator's copy keeps class (c) only if it carries the device record's own identifier and capture mode. Settings the law exempts from EVV (24-hour congregate settings, PACE) are pack applicability. Caregiver facts (exclusion, death) feed C3; OIG's checks become pack rules |
| FFS integrity | A claim warrant over C1-C6 with fee schedules, NCCI, TPL (433.139 carve-outs recorded) and frequency limits as pack data |
| Pharmacy | An NCPDP warrant at the counter within the batch window; NDC flags as conditions. Each drug line also gets a rebate record: invoiceable or excluded, a 340B duplicate-discount check against the HRSA file, the drug-class table version (a reclassification reopens every quarter it touched, one record per drug), and the utilization quarter apart from the collection quarter. Rebates are their own money kind and may exceed the amount paid. An outcome-based rebate is an open obligation on the claim, settled by the later outcome fact. Participation in a national pricing model and its federal-share rule are dated state parameters |
| Federal reporting | CMS-64 and T-MSIS are views of warrants and money records. Each view runs the receiver's published data-quality checks before it leaves. Every CMS-64 line shows the share drawn from the record and the share entered outside it, and ties out to the state treasury's disbursements, because two views of one record always agree. The recomputed error rate reports improper, unknown and held apart under a versioned measure definition; a held line never counts as proper. Payments that are not lines (supplemental and DSH payments, pools, grants, systems costs) get an aggregate warrant against their limit and approval |
| Staff capacity | The cure router; one item per cause; staff see conflicts and authority requests only |
| Vendor lock-in | Rule packs, the open format, the open checker and replay; shadow impact replaces change orders |
| Financing (provider taxes, deferral exposure) | A funding-source tag on each warrant, including the demonstration and its budget-neutrality category; federal exposure computed per hold. Taxes and transfers are paid in aggregate, so any per-line net-of-tax amount is labelled an estimate with its allocation rule |

## 8. The worst data: the design rule for garbage

### 8.1 The one principle

**Bad data is normal input, not an exception.** The system never holds a "true" table that bad data can corrupt. It
holds only receipts of what each source said, and computes belief from them. No file, however wrong, can damage state
truth; it can only add assertions, and every assertion carries its source, its file and its two times. Every response to
garbage is then one of four deterministic outcomes, the same ones as for good data: present, absent, unknown or
conflict, each with a reason, a cure owner and a reopen path.

1. **The raw file is the evidence; everything else is a cache.** Raw bytes are kept write-once by SHA3-512. Assertions,
   beliefs, warrants and views can all be recomputed from receipts plus signed packs. Our own bugs are recoverable: fix
   the reader, replay the receipts, and reopen the differences exactly.
2. **Absorb, never bounce.** Bad data is quarantined row by row, with a reason. A whole file is refused only when it is
   untrusted: it fails integrity, comes from an unknown sender, arrives out of sequence, or comes under a signing key
   the state has marked compromised. A new sender, a restarted sequence or a large drop that a state-signed transition
   record names is expected, not untrusted (8.2).
3. **Every disagreement is a finding for its source.** Findings are grouped by cause and sent to whoever owns the data
   (plan, vendor, county, provider). Over time the gate becomes the state's data-quality instrument; it never tidies
   data silently.

### 8.2 The failure families and the mechanism for each

| Family | Worst real form | Mechanism |
|---|---|---|
| **Identity** | One person under two IDs (a re-enrollment, a county system, another state). Two people under one ID (twins, a newborn billed under the mother, a reused SSN). Merges and splits made years later | Identity is an assertion, not a key. Links between IDs ("A and B are the same person from date D", "A was split into A and C") carry their source and both times. Warrants record the links they used in their read set, so a later merge or split reopens exactly the affected warrants. A PARIS or multistate match is a conflict, never an automatic answer |
| **Time** | A death reported 14 months late. Eligibility granted back three months. A rate raised retroactively for a year. Files that arrive out of order. A service date after the death date, before birth, or in the future | Valid time and known time (6.2). Files carry their sequence numbers. A gap makes the source stale from the gap onward, so belief turns unknown instead of silently wrong. A late fact reopens exactly the warrants it touches, and its money effect is an obligation (6.4). Impossible dates are rule reasons |
| **Full file vs change file** | A "full" 834 file that silently drops 40,000 members because of a vendor extract bug, read as 40,000 terminations | Absence counts as evidence only when the file declares itself full, passes its control totals, and the member lies inside the source's declared coverage (6.2). A member missing from a change file means nothing. An implausible drop between two full files (a pack threshold) that no transition record explains suspends the file as a source until a person confirms it. A source's own count is never enough to end anyone's coverage |
| **Planned change** | 250,000 members moved from plans to fee-for-service on one date. A plan leaves a state. The claims system changes vendor, restarts its sequences and renumbers claims. A recoupment arrives for a line paid before go-live | A state-signed **transition record**, entered ahead of the date, names the population or source, the date, the old and new producer, the sequence restart and a crosswalk from old to new claim numbers. A drop or a new sender that matches it is expected. During parallel running both feeds are read and every disagreement is one finding per cause. Void and replacement chains cross the cutover through the crosswalk, and a pre-go-live recoupment links to the signed legacy claim. Capitation and fee-for-service cannot both pay one member for the same month. A drop that does not match the record is still a broken feed |
| **Void and replace chains** | A replacement claim with no original. A void of a claim that was already voided. A chain that forms a cycle. A replacement in another system | Claim identity (Constitution III.3) links each frequency-code 7 or 8 to its original; a broken chain is a hold with a reason; the money effect goes through obligations, so a dollar can never be released twice |
| **Reference data** | A fee schedule loaded with a column shifted. A wrong NCCI edition. A provider shown active after termination ($50.3M paid to 584 terminated providers) | Each warrant cites the table version and row. A correction is a superseding assertion with a valid interval; reopen finds the warrants that read the bad rows; underpayments and overpayments become obligations. A shadow comparison of the new table against the old is shown before signature |
| **Source recall** | A vendor defect that ran for months, such as the 2023 ex parte household defect in 30 states (about 500,000 reinstated), or Colorado's 72 of 80 letters wrong | A state-signed **source recall** record says: source S, under version X, over valid interval V, is unreliable for fact kind K. It lowers that source's class for the interval, and reopen re-decides every warrant that relied on it. A data recall then works like a drug recall: exact, bounded and auditable. Systems already correct records one by one; what is new is recalling by source, version and interval and re-deciding exactly what relied on it |
| **Breached sender or channel** | A claims processor or file-transfer service is breached (Conduent 2025, MOVEit 2023). The breach is found months later, and two notices give different start dates | A state-signed **compromise record** names the sender, channel or signing key and an interval that starts at the earliest credible date. Every receipt records the channel it came under, so the record lists exactly which assertions, warrants and released payments relied on that channel in the interval. Files in the interval are re-read against an independent source: those that agree stand; disagreements are quarantined as one finding per cause, and reopen re-decides what relied on them. New files under the compromised key are refused until the sender is re-keyed; the state is never halted whole and the breached sender is never trusted whole. Released payments in the set become findings for the state, which decides any recovery |
| **Totals that do not tie** | CMS-64 vs T-MSIS (61% to 139% by state). A state total of $943.8B against $957.4B. Georgia's 237,400 lines that did not reconcile | Every external control total gets a computed counterpart from warrants and a **tie-out record**: the difference, split into buckets by cause (unwarranted, late, voided, outside the period, unknown), with the external total's stated period and as-of label. An unexplained remainder is a C7 hold on the report, not a footnote. Completeness is measured per plan, month and service category, and any view that depends on it (provider inactivity, the rate base, a demonstration measure) runs only where completeness passed. A pooled measure such as a loss ratio names its pooling level and shows the others beside it |
| **Fabrication** | Personal care billed for a dead person. One aide in two places at once. More than 24 hours billed in a day. AI-written notes | **Physical-impossibility rules** (time, place, life span, capacity) are certain and cheap, and they become pack rules. Money conditions need class (a)-(c) sources or agreement between independent sources (idea 5). Documents never satisfy them alone, except where the law accepts self-attestation for that condition and the pack cites it |
| **Gaming** | Self-reported compliance (Colorado's EVV). A plan's denial data "not valid nor reliable". Self-reported error rates tied to money (SNAP quality control) | Self-reports are class (d) at best. The checker recomputes the measure from line data. Each source gets a scorecard of its discrepancy rate over time, with the same cause buckets. That is the measure that works in child support: no payment for unreliable data |
| **Dark flows** | Plan-to-provider payments, supplemental payments and MLR remittances that never arrive as data | What never arrives cannot be verified. The design states this instead of hiding it: derived views show **warranted and unwarranted dollars** for each line of spend. Darkness becomes a measured number, and reducing it becomes a goal. Payments that are not lines (supplemental and DSH payments, pools, grants, systems costs) get an aggregate warrant against their limit and approval, which moves them out of the dark |
| **Rule reversal** | A court strikes a rule (the frailty test, Oct 29 2026). An interim final rule is replaced. A state plan amendment is approved retroactively | Withdrawing or restoring a pack version is a record that carries the order's citation, the states it covers and its time effect. The default is forward-only; reaching back to the rule's start needs the citation that says so. A preliminary order is tagged contingent, with both readings shown. Payments lawful under an order that is later lifted are recorded, and the state decides any recovery. Reopen is exact (6.4). Each changed verdict becomes an obligation or a recorded item |
| **Our own faults** | A reader bug. A rule-pack error. An engine bug. A corrupted store | An independent verifier rereads each file. Shadow runs come before signature. The independent checker recomputes decisions. The hash chain and witness detect tampering. Replay from receipts repairs everything. No fault of ours rewrites history; a fix produces new warrants linked to the old ones |
| **Source outage** | The eligibility system is down for three days during a renewal surge | Lines that depend on a stale or missing fact wait, grouped as one item for the outage and refreshed or retried automatically; each reopens on its own when the source returns. No standing or pre-signed stand-in lets a payment go on a stale fact (Constitution I.2, TARGET §6). Whether an outage should be allowed a signed stand-in source, to protect the prompt-pay clocks, would amend that rule and is not part of this design |

### 8.3 Why this holds for the worst cases

Every family reduces to the same three operations: add assertions (the log only grows); compute belief (a pure
function of the log and the known time); reopen by read set. Anything that goes wrong in the world is a set of
assertions, and the system's answer is deterministic, replayable and explained. Nothing needs a hand-edited database
row.

Proof targets added:
- **Absence:** an absence from a change file never changes belief.
- **Recall:** a source recall reopens exactly the warrants that read that source in the recalled interval.
- **Tie-out:** the cause buckets sum exactly to the difference.
- **Coverage:** a miss in a source never yields absent for a key outside the source's declared coverage.
- **Compromise:** a compromise record reopens exactly the warrants that read assertions received under that channel in
  its interval (the recall theorem, keyed by channel).

### 8.4 The worst data never becomes work per line (Article XII.9)

| Case | What a person does | Everything else |
|---|---|---|
| A full file drops 40,000 members | One confirmation for the whole file, shown as: "Plan B's file dropped 40,000 people, 9x the usual. Confirm or reject." | Until someone decides, the file counts as stale: lines that depend on the dropped members go to review, grouped as one item for the whole file, and all other lines proceed |
| A source recall | One signature | Every affected decision is re-decided on its own |
| A planned population move or vendor switch | One signature on the transition record, before the date | Matching drops and the new sender are expected; disagreements during parallel running are one finding per cause |
| A breached sender or channel | One signature on the compromise record | Interval files are re-read; agreeing files stand, the rest are quarantined and re-decided on their own |
| A fact only an office or a plan can supply (work hours, an ordering NPI, missing encounters) | Nothing for providers; the office or plan gets one finding per cause | Lines pay on the facts the law makes payment conditions; the owner's rate is measured |
| A conflict between sources | One item per pair of sources and cause, to the owner of the record, never one per line | - |
| A stale registry or an outage | Nothing | It is refreshed or retried automatically, and the fact is noted |
| A reader bug of ours | Nothing | It is fixed and replayed, and the differences reopen on their own |

## 9. The honest trust boundary

- **Proved:** the decision followed the state's signed rules on the cited facts, at the stated known time; money is
  conserved and released at most once; the authority was respected; reopening is exact; the shard merge is exact.
- **Recorded, not proved:** that each source said what the warrant cites (file hash and offset); each source's class and
  freshness.
- **Never claimed:** that a source told the truth. Corroboration rules reduce this risk; nothing removes it.

That is the statement to put in front of an auditor, and it is stronger than what a state has today.

## 10. How this fails, and second-order effects

1. **Holds explode on real data.** The largest risk is a fact the payee cannot supply: work hours from Jan 2027, ordering
   NPIs missing from encounters, inpatient encounters missing in 30 states. Facts another office decides never hold
   payment lines (6.2), and a directed payment has the hospital's own cure path (section 7). Each flow starts at
   OBSERVE; hold rates are measured per cause and per owner; a flow moves to HOLD only when its causes clear inside
   their clocks.
2. **States may not want a record of discovery.** Internal discovery does not start the 433.312 refund clock; the
   events in 433.316 do (6.4). One of them is CMS's written notice after a federal review finds the state did not
   identify, notify or recoup. A record of known overpayments with no notice sent is visible to auditors, and a federal
   reviewer who reads it and writes to the state starts the clock. The counterweights: the record shows what the state
   knew, and the notice it sends is still the state's decision; the record also proves diligence at known time, which
   is the PERM and deferral defence; and the chain of warrants turns "insufficient documentation" errors into
   documented ones. This is a real tension, to be named and not hidden.
3. **Plans resist encounter warrants.** No new authority over plans is claimed; the state already conditions its own
   directed payments on utilization and already requires encounters (438.818). CMS can defer FFP over bad encounter data
   (438.818(c)), so the state has its own reason.
4. **The language is too weak for some rule.** Pricing stays outside (6.3). A rule that truly needs more than the
   primitives is a sign of a pricer or a human judgment, not a reason to grow the language.
5. **Agents flood the cure API.** Conditions that money depends on accept only the class the law sets, usually (a)-(c)
   facts or agreement between sources; documents alone never satisfy them unless the law accepts self-attestation for
   that condition.
6. **Cross-shard rules are slow.** Reference sets are small and replicated, and aggregates merge once per batch.
7. **CMS reuses the record to cut a state's money.** The record shows only what was true; a state that can show its work
   does better under audit than one that cannot.

## 11. How hard each part is

| Part | Difficulty | Why |
|---|---|---|
| Records, the two times, reopen, the rule interpreter, one store | Hard engineering, clearly solvable | The core already exists. The real risks are the reach of the rule language and the proof effort |
| Readers on real files | Harder than it looks | Every input today is synthetic. Real 834, 837 and EVV files are messier than any seeded corpus. This is the largest technical unknown |
| Adoption: procurement, advance planning documents, certification, vendors | The hardest part | Procurement takes about three years and incumbents defend their business. This is not a code problem (section 14) |
| CMS accepting the record in place of file pulls | Outside RightRail's control | It is a federal decision. The record can only be made good enough that refusing it looks unreasonable |
| Problems that are not about information | Not solved by this | Low rates (72% of Medicare), workforce gaps, home-care waiting lists (649,905 people), politics. RightRail eases some indirectly and never claims to solve them |

**First principles: cut the part.**
- In raw materials, a payment decision is a few lookups and a signature, worth microseconds. Today it carries $41.3B a
  year of administration and a vendor industry around it. The split is not established; the part that is rebuilding, chasing, recoding,
  reconciling, reporting and re-procuring (section 2) is what RightRail targets, not deciding. Systems costs are $9.0B of it.
- Parts of RightRail's own design to cut: rules written as Lean code one at a time (replaced by one proved interpreter);
  two stores (one); a separate managed-care product (encounter warrants); proof effort spent per rule instead of on the
  interpreter and the money invariants. Speed work beyond the bars stays a parallel lane (TARGET §12).

**Test against reality early.** Public data with no personal health information exists now: exclusion lists (LEIE, SAM),
the provider registry (NPPES), State Drug Utilization Data and NADAC, CMS-64 tables, directed-payment preprints and MLR
reports. Once readers exist, running readers and warrants on these shows what breaks before any state does. The
standing claim is synthetic member, claim and payment data plus public non-PHI reference data (Constitution VI.2).
Such runs test readers and warrants only, report counts and failure kinds, never publish a list of named real
providers, and publish nothing from them.

**A federal claim that can be checked without trusting the state (design target).** CMS pays 64.7% of Medicaid and
checks it by sampling years later. If each CMS-64 line is a committed sum over warrants, CMS can check that the line
equals the sum of rule-passing warrants. With the private zero-knowledge track it could do so without seeing any
member's data. That track stays evidence-only and never blocks the core or the gate (TARGET §10, Constitution IX.4).

**Mechanism design over enforcement.** Penalties nobody collects fail, while carrots tied to independently rechecked
conditions work. So the cure router lets the party that supplies the fact be paid, and never makes a payee wait on
someone else's data: a hospital proves use of services with its own claim and the plan's payment to it, while a plan
that sends no encounters carries the finding and whatever its contract sets. Source scorecards make data quality
visible to the party that can fix it. Compliance becomes the fastest way to get paid.

**Providers' cost of billing.** Billing loss is 18% of revenue under Medicaid, against 4.7% under Medicare and 2.4%
under commercial plans (Dunn et al., FRBSF WP 2023-03). A provider who sees exactly what is missing and is paid when it
arrives keeps more of each dollar, and the state spends nothing more. The provider's cost of billing is a measured unit
for provider billing staff (Article XII).

## 12. From today's stack to this one (no rewrite)

What stays: the single writer; Lean decides, with an open checker; signed checkpoints and the payer's token check; fail
closed and the authority ladder; retry identity; shards and SQLite; post-quantum signatures; the custody work.

Each bridge keeps today's proofs valid:
1. **Warrant = today's decision plus citations.** Today's snapshots (enrollment, death file, exclusions) become
   assertions with file hashes, and the decision records its read set. Same decisions, more evidence.
2. **Belief over today's fact kinds.** Today's staleness and unverified reason codes become the absent and unknown
   states. Add known time from the trusted clock.
3. **Today's rules become the first rule pack.** Prove interpreter(first pack) = today's decision function, so every
   existing theorem about decisions carries over unchanged.
4. **One store.** The ledger moves onto the flat sharded store, and the 10,000-row cap goes, with the Lean bound raised
   under a proved limit. This is a format change, so it needs the Constitution XI.2 record.
5. **Readers**, starting from the earlier X12 intake kept in git history.
6. **The checker is made independent of engine code**, because outsiders trust the checker, not RightRail's proofs.

## 13. Build order

The engine work in flight lands first. Rollout order across payment flows is owned by TARGET §2 (FFS, then
capitation release, then directed payments); the build steps below are the evidence work that order needs.

| Step | Build | Retires |
|---|---|---|
| 1 | Warrant citations and read sets on today's decisions, with each receipt's channel and producer; the trusted known-time clock; the open correctness items in `STATUS.md`, including the exact-duplicate hold | Duplicate recovery, once they hold |
| 2 | One store for the gate and the ledger; belief with two times over today's fact kinds; reopen with the read-set theorem | Retroactive cases become representable |
| 3 | The rule interpreter, with today's rules as pack 1 and the equality theorem; shadow impact | Rule change orders |
| 4 | 837 FFS, 835, EVV, NCPDP and death-file readers, each with declared coverage; packs for fee schedules, NCCI, TPL, EVV; cure router with clocks | Pay-and-chase TPL, post-pay EVV audits, prompt-pay reports, recovery of FFS payments for dead members |
| 5 | Readers: 834, 820, PARIS, each with declared coverage; capitation warrant; the transition record, ahead of the January 2027 population moves and claims-system go-lives; the January 2027 death-file and address duties (date unconfirmed) | Capitation recovery for dead, moved or duplicate members |
| 6 | 837 encounter reader and each plan's 835 reader at OBSERVE; encounter acceptance measured per plan and service category; directed payments released on an accepted encounter or the hospital's claim agreeing with the plan's 835, moving to HOLD per plan and category only where acceptance is measured | Directed-payment spreadsheets and reconciliation |
| 7 | Determination warrant; the checker recomputes the eligibility error rate; reopen with the frailty case | PERM and MEQC file pulls (shrunk) |
| 8 | CMS-64 and deferral views at real scale; replay of the synthetic year by a second implementation | Deferral rebuilds, vendor switching cost |
| Lane | Speed and custody, continuing alongside | - |

Adoption additions, in this order: the state's measured baseline before go-live; observing every flow from the start while holds begin only with clear-fact, large-payee lines; the provider fast lane; encounter acceptance terms in the state's contracts; source-signed inputs; state-controlled federal disclosure; and the three gates before every payment passes through RightRail (section 14). The first packs apply exemptions automatically and run ex parte renewal first.

Two decisions stay with the people the constitution names, not with this design: any rule that lets a payment go on a
stale fact or while the gate is down would amend Constitution I.2, and format changes follow the XI.2 record.

## 14. Adoption: what a state must do and what slows it

What states ask for, and the part that answers it: one rule pack written once and adopted by many states, each with its
own parameters; state-owned rules in a readable format; one pack edit instead of changes to many systems; a dated,
signed statement of the state's understanding of a rule for audits; go-live on a signed provisional parameter, with an
exact reopen when final guidance lands; a replay on a second implementation as the transition test before
certification; and one item per cause for thin staff.

Three fears decide adoption:

1. **Holds that break provider payroll.** Clean lines pay, deterministic repairs pay, and only a line missing a named fact
   waits, inside the 42 CFR 447.45 clocks, with its owner told exactly what settles it.
2. **Better detection raises the measured error rate at first.** Each state sets its baseline before go-live, and errors
   found are reported against it.
3. **One more system to manage.** RightRail enters beside one responsibility, retires named tasks and brings no change-order
   stream (TARGET section 1).

Limits (RR, inference). Procurement takes about three years. Federal match for a new system is 50% until it is certified,
and certification comes 15 to 44 months after go-live. Switching is a procurement and certification matter as well as a
data one; replay lowers only the part of the cost that is knowledge transfer. A rule pack helps only systems that read it.
The pack library starts with what programs must build on deadline: work hours (January 1, 2027); six-month renewals for
expansion adults (renewals on or after January 1, 2027); address checks; death-file checks (date unconfirmed); immigrant
status match. Derived views for outcome-based certification metrics and vendor performance measures are recomputed by the
open checker. Plan-side claims depend on plan-side readers, and the member-advocate claim on notice and termination readers.

Pace. Observe every flow at once in year 1, since observation holds no money. Hold within months only where the payee is
large and the fact is clear: fee-for-service claims for dead members, excluded providers and exact duplicates (answered at
once, Constitution I.4). Do not hold small providers before the fast lane exists, disclose to CMS only by the state's
choice, or put the gate on every payment before the three gates below. Procurement, certification and contract cycles are the
real limits, not code.

Three gates before every payment passes through RightRail, because at full depth an outage could stop every payment:

1. A state release step that never depends on RightRail being up. If the gate is down the payer holds (TARGET section 6); a
   source outage sends affected lines to review with one item per cause (section 8.2).
2. A second certified implementation that can take over.
3. A release step the state owns, which RightRail can never block on its own.
