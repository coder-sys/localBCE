# RightRail Constitution

Adopted 2026-09-24. This is the supreme rule set for all RightRail work: every
product, module, agent, script, cleanup and release. It is distilled from the
founders' directives and the standing working rules. Where any other document
conflicts with this one, this one wins. The full-stack target
(`docs/RIGHTRAIL_FULL_STACK_TARGET.md`) elaborates it; it cannot weaken it.

## Preamble

RightRail gives a state agency that runs public benefit programs, Medicaid first,
a state-controlled operating layer for consequential responsibilities. It keeps
the approved rule, the evidence, the unresolved work, the decision and the
current handoff connected until the responsibility is complete — and it keeps
the state free to leave. In the end state, every payment the state routes
through RightRail passes its gate before the money goes out, under the state's
own signed authority; the state's payment systems still move the money.

## Article I — The state governs

1. The state owns policy, interpretation, population definition, approvers,
   exceptions and every consequential decision. RightRail prepares, records and
   follows through; it never decides for the state.
2. Any power to approve, hold, release or redirect an external action needs
   separate, explicit state authority. Expanding scope needs state approval.
   The inline payment gate may allow or hold a payment only to the extent a
   signed state authority grant permits, and it fails closed: a payment it
   does not allow does not go. There are two ways to release a held payment,
   both by named state employees on the state-signed roster and both verified
   before the payment goes. A bypass releases a single named payment: the
   employees sign an approval committing to exactly that payment. A release by
   cause releases the payments held for one cause: the employees sign one
   decision committing to the exact listed set of held payments that share
   that cause. A release by cause never covers a payment not on the list when
   it is signed, and never a future payment. Either obeys the same threshold,
   roster, separation and calendar rules as any release. There is no standing,
   time-window, fail-open or after-the-fact bypass or release, and RightRail
   cannot issue, extend or sign one. The gate ships off by default.
3. Human judgment stays human. A model output is a lead, never a determination.
4. Existing payment systems move money. RightRail never does. BLOCK remains a
   human or state action, never an automated one. A payment line that exactly
   repeats an already-paid line is not held for a person: it is answered at
   once, naming the earlier payment, and the sender can contest the answer in
   one step. A line that only resembles a paid line stays with a person.
   Answering an exact repeat this way is not a BLOCK: the line was already paid
   once, and the answer only names that payment.

## Article II — Facts stay separate

Evidence, evaluation, official determination, authorized action, dispatch,
receiver acknowledgment, cash and reporting are different facts with different
proof. None may stand in for another. An acknowledgment is not cash. A clean
report is not completeness. Two copies of one source are not corroboration.
Missing evidence is a visible status with an owner and a deadline — never a
silent default.

## Article III — One writer, exact history

1. Each responsibility has exactly one authoritative writer. UIs, connectors,
   verifiers, restores, shadows and candidates never become a second writer.
2. History, current projection and the action/outbox identity commit together,
   atomically.
3. Every command carries identity, expected revision and canonical input. An
   exact retry is a duplicate; changed meaning is a conflict. Crashes before
   commit and lost responses after commit both recover correctly.
4. Money is integer cents with explicit rounding. History is never rewound;
   corrections are new, linked facts.
5. Failure is closed and visible: missing, stale, malformed, unauthorized or
   over-limit input creates no partial change and loses no work.

## Article IV — Privacy is structural

1. Zero PHI at RightRail corporate. Sensitive data, keys and records stay in
   the state, provider or approved payer environment.
2. Outputs are built from approved fields for a named recipient, never by
   redacting a full dump. Hashes, filenames, error text, rare aggregates and
   timing are treated as potentially identifying.
3. Support works from approved packages and fictional reproductions.

## Article V — Lean decides, adapters commit

1. Executed decision logic belongs in Lean wherever practical: calculations,
   authority checks, transitions, retries, recovery sequencing, release rules.
   Python and other code are narrow adapters for storage, identity, network and
   cryptographic effects.
2. There is never a permanent duplicate policy implementation. When Lean fails,
   nothing silently falls back to another implementation.
3. A binary is only ever described as built from the exact source that built it.
   Proofs, tests and artifacts are bound to exact versions.
4. Theorem statements, independent expected answers and protected gates may not
   be weakened by the worker who benefits. Changes are explicit and reviewed.

## Article VI — Honest claims

1. Claim only what raw evidence shows. "Written" is not "ran"; "ran" is not
   "verified"; "verified locally" is not "qualified".
2. Current standing claims until their conditions are met:
   synthetic member, claim and payment data plus public non-PHI reference data;
   non-PHI, nonpayment, `proofSuiteId=null`, `production_usable=false`,
   `activation=false`.
3. Failures, skips and warnings are reported, never relabeled.
4. RightRail is in a planned pre-state build phase (no state engagement for
   at least a year). Building and proving the complete product on synthetic
   data is the plan, not a gap. Do not list the absence of a state, official
   receiver, real data or live payments as a blocker, caveat or limit of
   progress; keep the standing claims in VI.2 in the status file and move on.
5. Signatures are post-quantum only (ML-DSA or another NIST post-quantum
   algorithm). There is no RSA or ECDSA fallback, even if certification
   timing delays a pilot.

## Article VII — The state can always leave

1. The state owns or durably controls its rules, configurations, records,
   tests, interfaces, keys and continuity assets.
2. Continuity must let an independent operator actually continue the work —
   a readable file is not enough. Handoffs are exercised while the current
   service still works. Transfer fences the old writer; issued actions keep
   their identity.

## Article VIII — State-controlled economics

RightRail is paid for operating the service, at one published price for every
state, never by outcomes: no share of denials, recoveries, penalties, sanctions
or savings. No compatibility or certification fees for vendors, no exit fees, no
closed standards, no lobbying for barriers. Billing never gains operational
authority. The price schedule is in `docs/RIGHTRAIL_FULL_STACK_TARGET.md`
section 2, and changes to it need the founders' written approval. RightRail is
never the health plan or the drug-benefit manager, and never bids for a state's
claims or eligibility modules.

## Article IX — Small, single, measured

1. **One codebase.** All product code lives in this trunk (`rightrail-main`).
   Per-team copies of the same module are forbidden; a module has one home and
   one owner. Private zero-knowledge work is the one exception: it lives in
   its own repository, `rightrail-zk`; the trunk pins its verifier binary by
   hash, as it does for the engine.
2. Prefer existing primitives: typed data, Lean functions, narrow adapters,
   owner-local SQLite transactions, durable outboxes, ordinary files. No generic
   workflow engine, custom database, service-per-module, universal query
   engine or orchestration built before measured need. A new abstraction needs
   two real consumers.
3. **History never costs more.** Ordinary work scales with the change, not with
   total history. `tests/test_history_growth.py` counts SQLite steps, bytes
   hashed, evaluator frame bytes and peak Python memory for the listed owner
   operations and the gate pin at two history sizes, and fails when a count
   rises 5% over its pin or an unlisted count grows faster than log n. The
   counts that still grow are named exceptions on a dated list that only
   shrinks (`GROWS` in that test, each with its planned fix). No bound may
   become a way to block service as history grows. Every input, queue, report,
   export and proof has explicit bounds. Measure before claiming performance.
4. Build the whole planned product; never shrink it to fit today's state or one
   pilot's needs. Only the order in which work is shown and sold is chosen by what
   is ready. The private zero-knowledge evidence mode
   (PRIVATE_ZK) is an active prototype track (founder, 2026-09-25). It produces
   evidence only, never a hold or payment directive. It never blocks core, gate
   or product work, and the non-ZK evidence path ships first. No PRIVATE_ZK
   claim is made before a third-party audit.

## Article X — Lean process

1. Software over paperwork. `STATUS.md` holds current truth only — what runs,
   what is blocked, the next step — in a few lines; it keeps no change log,
   since `git log` is the log. Raw logs live in log files, not in markdown.
   No hash tables in status documents except the pinned-artifact list.
2. Heavy runs (builds, tests, provers) on a development machine go only through the guarded wrapper and under the guard and memory limits named in the driver root `AGENTS.md` (one source; no other document restates them). The wrapper is never bypassed or weakened there. CI and cloud runners use their own resource limits. The release producer is parked in `parked/` until a release is planned, and it moves to the wrapper before it runs again.
3. Never destroy uncommitted work, raw evidence, keys, or the only copy of
   anything. Deletions are recoverable first (Recycle Bin, Git bundle, archive).
4. Every session leaves a working increment and a clear next step.

## Article XI — How we build

These are binding working principles, not suggestions.

1. **Invariant first.** Start from the property that must hold for a decision
   to be safe, then build the smallest implementation that makes it executable
   and independently checkable. An existing workflow, benchmark, digest, caller
   boolean or green gate is not authority just because it exists.
2. **Gates serve invariants.** A gate can be stale, wrong or over-broad. A
   protected gate (Lean theorem statements, `artifacts/**`, the
   constitution-invariants test, wire formats, digest domains and the guard)
   changes only in the open, with a record of: the exact predicate; the
   invariant and failure it protects; the raw evidence it is unsuitable; the
   disposition (retain, replace, weaken, disable, suspend, relabel); the
   replacement control; scope and duration; and the claims withdrawn. A changed
   gate inherits none of the old assurance. Never bypass a gate silently or
   change policy bytes to get a pass. An ordinary test edit outside this list
   needs only a clear commit message. A re-pin that leaves every pinned
   executable's SHA-256 unchanged and only refreshes its source-manifest record
   is a record update, not a gate change: it still needs the live pin check and
   a clear commit message, not the full record.
3. **Disciplined creativity.** The current implementation is a hypothesis. When
   evidence shows it cannot meet the invariant, bound or throughput target,
   return to first principles for a materially simpler composition,
   representation, schedule or owner, and test the idea with the cheapest
   deterministic test. Novelty is not progress: the best solution is the
   smallest one that makes the required truth easier to verify, faster to
   produce and harder to misuse.
4. **Persistence.** Once work is authorized, carry it through its dependency
   chain. A passing substep, a failed preflight or a missing seam is the next
   step, not a stopping point. A blocked launch or blocked claim is not a
   blocked task; stop only when done, told to stop, unsafe, or out of safe work.
5. **One owner per truth; small trusted core.** Every trust-critical value has
   exactly one canonical owner; other layers carry a checked binding, never a
   competing copy. Producers, accelerators, workers, GPUs and convenience layers
   are untrusted: they may propose bytes, never authorize a receipt or mutation.
   Growing the trusted core needs a named invariant, owner, binding, attack test
   and evidence.
6. **Smallest complete boundary, then extend.** A boundary is complete, with an
   independent verifier, mutation and replay tests and resource and cleanup
   evidence, before it is composed with the next verified piece (build order:
   `ARCHITECTURE.md`, "Design rules beyond the Constitution"). Removing
   duplication, transport or ceremony is good engineering; removing privacy,
   exact binding, fail-closed parsing, independent verification, mutation
   coverage or resource accounting is not.
7. **Maximum modularity, minimum surface.** Each boundary has one owner, one
   narrow versioned contract, one testable failure surface and one trust class.
   Compose small complete parts rather than a monolith, but never split an
   atomic transition or a theorem where safety depends on seeing the whole.
   No hidden fallbacks, shared mutable state, implicit conversions or layers
   that add ceremony without replaceability. Each part can be replaced, tested
   and, where it decides, proved on its own against its contract, without
   changing any other part. A change that must touch several parts at once
   shows a boundary in the wrong place, and the boundary is fixed rather than
   worked around. A part's contract (inputs, outputs, failure cases, trust
   class) is written down where the part lives. Speed never buys a compromise
   on safety, verifiability or modularity, anywhere in the stack.
8. **Formal means executed.** A Lean definition counts only if it runs in the
   deployed path or has a reviewed refinement proof to what runs. A model plus
   matching examples is not verified code. Toolchains are pinned, admitted
   axioms enumerated, proofs checked independently, and theorem statements
   versioned as trust-critical interfaces. A proof never upgrades an unproved
   crypto assumption, a dishonest source or an unlawful policy.
9. **Deterministic and reproducible.** Inputs, encodings, toolchains, ordering
   and identities are canonical; needed entropy is explicit; what is needed to
   rebuild a result is recorded. A result that cannot be rebuilt or read back is
   an observation, not a system fact.
10. **Monotonic, fail-closed safety.** Unknown, missing, mismatched, timed-out,
    partial, stale, malformed or cleanup-failed state never creates authority.
    Epochs, identities and anti-rollback domains only move forward.
11. **Evidence has a class.** Every claim is labelled measured, independently
    verified, derived, projected, reference-only or unknown, is never stronger
    than its class, and is downgraded at once when its evidence weakens.
12. **Recovery before optimization.** Restart, retry, idempotency, rollback,
    cleanup and partial failure are designed before speed. Optimize only the
    measured dominant stage, keep the same semantics and security boundary, and
    rerun the adversarial checks afterwards.
13. **Explicit state machines.** Lifecycles are named states with legal
    transitions, guards, identities and epochs. Authority is never inferred from
    a boolean, file name, log line, process exit or caller-chosen status.
14. **Adversarial simplicity.** Prefer boring, inspectable mechanisms with few
    dependencies, explicit data flow, bounded parsers and obvious failure
    behavior. Cleverness, hidden automation, novel cryptography and extra
    abstraction are liabilities until a named benefit and executable tests earn
    their place.
15. **Privacy is measured.** Privacy is tested as a property, not asserted by a
    label: output shape, timing, memory, errors, logs, temp files, artifacts and
    retries must not depend on hidden values.
16. **Maximum auditability.** Every consequential decision can be replayed and
    explained afterwards by someone who does not trust RightRail. Each decision
    keeps one record, bound by hash, of its exact canonical inputs, the rule
    version, the program build that ran it, the authority it relied on and its
    result; an independent verifier rebuilds the same result from that record
    alone. Anything that can change a decision is in the record: a default, a
    fallback, a cache, a clock reading, a retry. The reason for every result
    reads in plain terms: which rule, which fact, which threshold. An auditor's
    question is answered from the record, not from logs, memory or a person.
    The record stays where the data stays (Article IV).

## Article XII — Felt value, design and staff first

Correctness that nobody feels is not a product. Everything RightRail builds
(screens, rules, checks, safeguards, failure handling and recovery) must make
staff work easier, faster and less confusing, and leave staff feeling in
control. Safety is never paid for with staff effort.

1. **Felt value, in writing, before work starts.** Every product, feature and
   priority decision names: who feels it (a named role: state program analyst,
   caseworker, county or local office staff, finance approver, program director,
   health plan or vendor operations, provider billing staff, auditor, replacement
   operator); when (the concrete daily or periodic
   moment it changes, such as Monday reconciliation, preparing an approval,
   answering an auditor, onboarding a new rule or replacing a contractor); what
   changes (the before and after in a measured unit: unresolved-item age,
   decision-preparation time, repeated evidence requests, staff steps,
   correction accuracy, implementation effort in days to put a new rule or
   program live, support effort, contractor-transition effort, and time to
   answer "what is actually happening and who owns it"); and the structural
   friction it removes beyond our own products (long implementation projects,
   difficulty replacing or disciplining vendors and plans, missing or
   untrustworthy operational data, repeated reconstruction of history, chasing
   counterparties for records).
2. Work that moves none of these units for any role is deprioritized, however
   elegant. Invisible correctness work is justified only by the felt outcome it
   protects, and is named as such.
3. A substantial workflow change also assesses staff effort, repeated evidence
   requests, data movement, troubleshooting, installation and updates,
   recovery, independent exit and reuse; it compares a materially simpler
   approach and shows the chosen tradeoff in the affected workflow.
4. **The scorecard.** The synthetic demonstration (the Hospital H cycle and
   later workflows) measures these units per role. A change that makes a
   measured unit worse is a regression, reviewed like a failing safety test; a
   prettier screen that adds staff steps is a regression; and a change that adds
   staff steps, confusion or waiting without giving staff something they can
   act on is a regression, however safe it is. The staff-facing surface (Mirror
   and the staff workspace) is held to the same standard as the owner: it runs,
   is tested, and is where value is demonstrated. A product-change description
   (not every `STATUS.md` entry) states its felt effect in one line, or says
   "none (infrastructure for: …)".
5. **The answer first, one primary action.** Every screen feels expensive, calm
   and obvious, the way the best consumer hardware does; restraint is the
   standard, and what is left out matters as much as what is added. Each screen
   leads with the one thing its role needs (what is happening, who owns it,
   what to do next) in plain words and exact figures; detail is one deliberate
   step away, never in the way. One primary action per screen; secondary
   actions are quiet. Nothing decorative, no jargon, and no internal
   identifiers, digests or codes shown to staff unless they asked for them.
6. **Restrained system.** One type family, a small fixed palette and spacing
   scale, tabular figures with amounts aligned to the cent, consistent words for
   the same thing everywhere, motion only to explain a change. Light and dark
   themes, and WCAG 2.1 AA accessibility, are part of done.
7. **Every pathway is proven.** The interface is defined by one declared
   interaction model: every screen, every control, every transition, and the
   backend call each control makes. Automated checks prove, exhaustively over
   that model and for every role:
   a. no dead control: every visible, enabled control leads to a defined result;
   b. no orphan screen: every screen is reachable from the start;
   c. no trap: from every screen and every error, the user can reach a
      meaningful next step or home;
   d. no dead connection: every control's backend call exists, and every
      response it can return (success, refusal, conflict, outage) has a defined,
      plain-language screen;
   e. no illogical path: a control a role can never use successfully is not
      shown to that role, and a finished action cannot be repeated by accident.
   A real-browser crawl then clicks every control in every reachable state and
   fails if the running interface differs from the declared model.
8. What the system can safely fix itself, it fixes and notes. It never hands
   staff a chore.
9. What needs a person reaches them once per cause, never once per line. It
   comes with the plain reason, the money at stake, the deadline, who owns it
   and one action that settles it.
10. Staff can always see what is happening, why, and what they can do about
    it. "Visible" means visible in the record and to the auditor, never silent.
    It never means a flood of alerts.

## Enforcement

- Reviewers reject changes that violate an article, however useful.
- Automated checks enforce what they can (one-writer boundary, retry identity,
  forbidden outputs, pinned artifacts, bounded inputs, protected tests); the
  rest is enforced in review.
- A worker may propose an exception with evidence; only the founders may grant
  it, in writing, with scope and expiry.

## Amendment

Only the founders amend this constitution. The written word of either founder
authorizes an amendment; its log entry quotes those words and names who gave
them. Amendments are explicit, dated edits
to this file with a one-line reason. Silence, convenience or a passing test is
never an amendment. Each amendment-log entry quotes the founders' own words that
authorize it. Git holds each amendment's full text and reasoning under the
commit named in its entry.

### Amendment log

Date | change (clauses) | founders' words | commit

- 2026-09-24 | XI added: the design ideology (2026-08-14, revised 2026-09-23) becomes binding engineering principles | none recorded (before the quote rule) | 82a20872
- 2026-09-24 | VI.4 added: the pre-state build phase is the plan, not a blocker | none recorded (before the quote rule) | 68e53d23
- 2026-09-24 | XII added: felt value (who, when, measured before/after, friction; demo is the scorecard) | "i cant keep asking u questions constantly... we need a solution" | bbd4fe04
- 2026-09-24 | XIII added: design and interaction integrity, every pathway proven | "think like Steve Jobs and Jony Ive" | 6b93be25
- 2026-09-25 | IX.4: private zero-knowledge un-parked, evidence only, never blocks core or gate | "whatever u want ... aligned with my ideologies fully" | 200df662
- 2026-09-25 | IX.1, I.2, I.4, X.1, X.2, XI.2, XII, Enforcement amended; VI.5 PQ-only added; former XI.16 (customer effect) folded into XII | "u have all auth"; PQ line: "our whole stack is supposed to be post quantum" | 71f9e6f9
- 2026-09-29 | X.2 names the live guard and wrapper | "doesn't compromise safety and accuracy do whatever u want" | bd090fb2, 2ec89a0b
- 2026-10-01 | X.2 one guard source; XI.2 unchanged-hash re-pin is a record update; entries quote the founders; release producer parked | "yes" | 46d6fd2c
- 2026-10-01 | IX.3 strengthened: deterministic growth test, shrink-only exception list | "stack doesnt get bloated or gets slower or vulenrable as history grows" | b02d2e5d, a36839b1
- 2026-10-06 | I.2: gate fails closed; bypass only per named, pre-verified payment | "make it all happen, the constiution change" | d1c2fa00
- 2026-10-27 | XI.16 added (maximum auditability); XI.7 extended (maximum modularity) | "draft the auditability amendment (and maximum modularity too)"; "sure" | 8d0de54a
- 2026-10-31 | XIV added: staff first in everything | "make their work easier faster and less confusing"; "sure do it" | d46da391
- 2026-11-05 | IX.3 names the `GROWS` list; 2026-09-29 entry's record pointer corrected | "im saying yes to these changes" | d8c95918
- 2026-11-06 | VI.2: tests may also read public non-PHI reference data | "Yes, public data"; "Yes, that text" | af472b15
- 2026-11-14 | I.2: release by cause, exact listed set, never standing or future | "Approve both" | 06435d1f, cd713f0e
- 2026-11-14 | I.4: exact duplicates answered at once, contestable in one step (reverses 2026-11-08) | "Approve both" | 06435d1f, cd713f0e
- 2026-11-22 | Restated: XIII and XIV merged into XII (number map below); preamble scope and end state; VIII state-controlled economics; IX.4 build scope; XII.1 roles; X.2; I.4 exact repeat; Amendment; XI.7 speed sentence | Neer: "sure"; "do it"; "Sure"; "Do em all" | this commit
  Number map: XIII.3-5 became XII.6, XII.7, XII.4; XIV.1-5 became XII.8-10 and XII.4. XI.6 build order moved to `ARCHITECTURE.md`; no rule removed.
