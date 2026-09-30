# RightRail Constitution

Adopted 2026-09-24. This is the supreme rule set for all RightRail work: every
product, module, agent, script, cleanup and release. It is distilled from the
founder's directives (final architecture directive, project-wide enforcement
supplement and runtime-convergence directive, 2026-09-23), the Sept 24
operating plan ("RightRail — State control, explained"), the design ideology,
and the standing agent rules. Where any other document conflicts with this
one, this one wins. The full-stack target (`docs/RIGHTRAIL_FULL_STACK_TARGET.md`)
elaborates it; it cannot weaken it.

## Preamble

RightRail gives a Medicaid agency a state-controlled operating layer for
consequential responsibilities. It keeps the approved rule, the evidence, the
unresolved work, the decision and the current handoff connected until the
responsibility is complete — and it keeps the state free to leave.

## Article I — The state governs

1. The state owns policy, interpretation, population definition, approvers,
   exceptions and every consequential decision. RightRail prepares, records and
   follows through; it never decides for the state.
2. Any power to approve, hold, release or redirect an external action needs
   separate, explicit state authority. Expanding scope needs state approval.
   The inline payment gate may allow or hold a payment only to the extent a
   signed state authority grant permits; its fail policy and any emergency
   bypass are themselves signed by the state; the gate ships off by default.
3. Human judgment stays human. A model output is a lead, never a determination.
4. Existing payment systems move money. RightRail never does. BLOCK remains a
   human or state action, never an automated one.

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
   synthetic, non-PHI, nonpayment, `proofSuiteId=null`,
   `production_usable=false`, `activation=false`.
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

## Article VIII — Neutral economics

RightRail is paid for operating the service (about $2M/year plus the marginal
10/7/5-basis-point covered-flow schedule, 5 bp floor; Provider App priced
separately), never by outcomes: no share of denials, recoveries, penalties,
sanctions or savings. No compatibility or certification fees for vendors, no
exit fees, no closed standards, no lobbying for barriers. Billing never gains
operational authority.

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
3. Ordinary work scales with the change, not with total history. Every input,
   queue, report, export and proof has explicit bounds. Measure before
   claiming performance.
4. Build what the plan needs now. The private zero-knowledge evidence mode
   (PRIVATE_ZK) is an active prototype track (founder, 2026-09-25). It produces
   evidence only, never a hold or payment directive. It never blocks core, gate
   or product work, and the non-ZK evidence path ships first. No PRIVATE_ZK
   claim is made before a third-party audit.

## Article X — Lean process

1. Software over paperwork. `STATUS.md` holds current truth only — what runs,
   what is blocked, the next step — in a few lines; it keeps no change log,
   since `git log` is the log. Raw logs live in log files, not in markdown.
   No hash tables in status documents except the pinned-artifact list.
2. Heavy runs (builds, tests, provers) on the laptop go through the guarded
   wrapper (`C:/Users/neers/rrb/tools/rr_guarded.ps1`, which runs the guard-host
   `work/rightrail-guard-host/native/guard/run_guarded_v7.ps1`) with its memory floor; it is
   never bypassed or weakened there. CI and cloud runners use their own
   resource limits. Exception: engine and release builds run under the preserved
   v4 guard (SHA-256 `57F9EC8A…99FB`, external copy
   `work/pq-wide-seed-native-20260913/build-filter-native/run_guarded_v4.ps1`)
   until a planned producer and kit move to v7.
3. Never destroy uncommitted work, raw evidence, keys, or the only copy of
   anything. Deletions are recoverable first (Recycle Bin, Git bundle, archive).
4. Every session leaves a working increment and a clear next step.

## Article XI — How we build (engineering ideology)

Distilled from `docs/DESIGN_IDEOLOGY.md` (2026-08-14 original and 2026-09-23
revision). These are binding working principles, not suggestions.

1. **Invariant first.** Start from the property that must be true for a decision
   to be safe, then build the smallest implementation that makes it executable
   and independently checkable. An existing workflow, benchmark, digest, caller
   boolean or green gate is not authority just because it exists.
2. **Gates serve invariants.** A gate can be stale, wrong or over-broad. For a
   protected gate — Lean theorem statements, `artifacts/**`, the
   constitution-invariants test, wire formats, digest domains and the guard —
   change it only in the open, recording: the exact predicate; the invariant
   and failure it protects; the raw evidence it is unsuitable; the disposition
   (retain, replace, weaken, disable, suspend, relabel); the replacement
   control; scope and duration; and the claims withdrawn. A changed gate
   inherits none of the old assurance. Never bypass a gate silently or change
   policy bytes to get a pass. An ordinary test edit outside this list needs
   only a clear commit message.
3. **Disciplined creativity.** The current implementation is a hypothesis. When
   evidence shows it cannot meet the invariant, bound or throughput target,
   return to first principles and look for a materially simpler composition,
   representation, schedule or owner. Make new ideas falsifiable with the
   cheapest deterministic test. Novelty is not progress; the best solution is the
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
6. **Smallest complete boundary, then extend.** Build in order: exact input and
   identity contract → bounded producer artifact → independent verifier →
   mutation and replay tests → resource and cleanup evidence → composition with
   the next verified piece. Removing duplication, transport or ceremony is good
   engineering; removing privacy, exact binding, fail-closed parsing,
   independent verification, mutation coverage or resource accounting is not.
7. **Maximum modularity, minimum surface.** Each boundary has one owner, one
   narrow versioned contract, one testable failure surface and one trust class.
   Compose small complete parts rather than a monolith, but never split an
   atomic transition or a theorem where safety depends on seeing the whole.
   No hidden fallbacks, shared mutable state, implicit conversions or layers
   that add ceremony without replaceability.
8. **Formal means executed.** A Lean definition counts only if it runs in the
   deployed path or has a reviewed refinement proof to what runs. A model plus
   matching examples is not verified code. Pin toolchains, enumerate admitted
   axioms, check proofs independently, and version theorem statements as
   trust-critical interfaces. A proof never upgrades an unproved crypto
   assumption, a dishonest source or an unlawful policy.
9. **Deterministic and reproducible.** Canonicalize inputs, encodings,
   toolchains, ordering and identities; make any needed entropy explicit;
   record what is needed to rebuild a result. A result that cannot be rebuilt or
   read back is an observation, not a system fact.
10. **Monotonic, fail-closed safety.** Unknown, missing, mismatched, timed-out,
    partial, stale, malformed or cleanup-failed state never creates authority.
    Epochs, identities and anti-rollback domains only move forward.
11. **Evidence has a class.** Every claim is labelled measured, independently
    verified, derived, projected, reference-only or unknown, and is never
    stronger than its class. When evidence weakens, the claim is downgraded
    immediately.
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
    abstraction are liabilities until they earn their place with a named benefit
    and executable tests.
15. **Privacy is measured.** Privacy is tested as a property — output shape,
    timing, memory, errors, logs, temp files, artifacts and retries must not
    depend on hidden values — not asserted by a label.

## Article XII — Felt value

Correctness that nobody feels is not a product. Every product, feature and
priority decision must answer, in writing, before work starts:

1. **Who feels it** — a named role (state program analyst, finance approver,
   program director, MCO/vendor operations, provider billing staff, auditor,
   replacement operator).
2. **When** — the concrete daily or periodic moment it changes (e.g. "Monday
   reconciliation", "preparing an approval", "answering an auditor",
   "onboarding a new rule", "replacing a contractor").
3. **What changes** — the before/after in one of the plan's measured units:
   unresolved-item age, decision-preparation time, repeated evidence
   requests, staff steps, correction accuracy, implementation effort (days
   to put a new rule or program live), support effort, contractor-transition
   effort, and time to answer "what is actually happening and who owns it".
4. **Friction targeted** — which structural pain it removes beyond our own
   products: long implementation projects, difficulty replacing or
   disciplining vendors and plans, missing or untrustworthy operational data,
   repeated reconstruction of history, and chasing counterparties for records.

Rules:
- Work that moves none of these units for any role is deprioritized, however
  elegant. Invisible correctness work is justified only by the felt outcome it
  protects, and is named as such.
- A substantial workflow change also assesses staff effort, repeated evidence
  requests, data movement, troubleshooting, installation and updates,
  recovery, independent exit and reuse; it compares a materially simpler
  approach and shows the chosen tradeoff in the affected workflow.
- The synthetic demonstration (the Hospital H cycle and later workflows) is
  the scorecard: it measures these units per role, and a change that makes a
  measured unit worse is a regression, reviewed like a failing safety test.
- The staff-facing surface (Mirror and the staff workspace) is held to the
  same standard as the owner: it runs, is tested, and is where value is
  demonstrated.
- A product-change description states its felt effect in one line, or says
  "none (infrastructure for: …)"; this is required in product-change
  descriptions, not in every STATUS.md entry.

## Article XIII — Design and interaction integrity

Every screen must feel expensive, calm and obvious, the way the best consumer
hardware does. Restraint is the standard: what is left out matters as much as
what is added.

1. **The answer first.** Each screen leads with the one thing its role needs
   (what is happening, who owns it, what to do next) in plain words and exact
   figures. Detail is one deliberate step away, never in the way.
2. **One primary action per screen.** Secondary actions are quiet. Nothing
   decorative, no jargon, no internal identifiers, digests or codes shown to
   staff unless they asked for them.
3. **Restrained system.** One type family, a small fixed palette and spacing
   scale, tabular figures with amounts aligned to the cent, consistent words for
   the same thing everywhere, motion only to explain a change. Light and dark
   themes, and WCAG 2.1 AA accessibility, are part of done.
4. **Every pathway is proven.** The interface is defined by one declared
   interaction model: every screen, every control, every transition, and the
   backend call each control makes. Automated checks prove, exhaustively over
   that model and for every role:
   - no dead control: every visible, enabled control leads to a defined result;
   - no orphan screen: every screen is reachable from the start;
   - no trap: from every screen and every error, the user can reach a
     meaningful next step or home;
   - no dead connection: every control's backend call exists, and every
     response it can return (success, refusal, conflict, outage) has a defined,
     plain-language screen;
   - no illogical path: a control a role can never use successfully is not
     shown to that role, and a finished action cannot be repeated by accident.
   A real-browser crawl then clicks every control in every reachable state and
   fails if the running interface differs from the declared model.
5. **Measured.** Design changes are judged by the Article XII scorecard; a
   prettier screen that adds staff steps is a regression.

## Enforcement

- Reviewers reject changes that violate an article, however useful.
- Automated checks enforce what they can (one-writer boundary, retry identity,
  forbidden outputs, pinned artifacts, bounded inputs, protected tests); the
  rest is enforced in review.
- A worker may propose an exception with evidence; only the founders may grant
  it, in writing, with scope and expiry.

## Amendment

Only the founders amend this constitution. Amendments are explicit, dated edits
to this file with a one-line reason. Silence, convenience or a passing test is
never an amendment.

### Amendment log

- 2026-09-24 — Article XI added at the founder's direction: the values and
  ideology in `docs/DESIGN_IDEOLOGY.md` (original 2026-08-14 and revised
  2026-09-23) are incorporated as binding engineering principles.
- 2026-09-24 — Article VI.4 added at the founder's direction: the pre-state
  build phase is the plan; missing state/receiver/real data is not a blocker.
- 2026-09-24 — Article XII added at the founder's direction: every product
  decision must name who feels it, when, the measured before/after, and the
  structural friction removed; the synthetic demo is the scorecard.
- 2026-09-24 — Article XIII added at the founder's direction: interfaces must
  feel expensive, restrained and intuitive, and every control and pathway is
  proven over a declared interaction model with no dead buttons, orphan
  screens, traps, dead connections or illogical paths.
- 2026-09-25 — Article IX.4 amended at the founder's direction: private
  zero-knowledge is un-parked as an active, evidence-only prototype track that
  never blocks core or gate work.
- 2026-09-25 — Articles IX.1, I.2, I.4, X.1, Enforcement, XI.2, XI.16/XII and
  X.2 amended, and a post-quantum-only signature line added to Article VI:
  ZK moves to its own repository (`rightrail-zk`) pinned by hash; the payment
  gate's authority, fail policy, emergency bypass and off-by-default state are
  named explicitly, and BLOCK stays human or state action; STATUS.md is
  current truth only, with no change log; the "every change names its
  articles" rule is dropped; the full 8-field gate-change record applies only
  to a named protected-paths list; XI.16 folds into Article XII, whose
  felt-value line applies to product-change descriptions, not every STATUS
  entry; and the guard memory floor applies to laptop runs, not CI/cloud.
  Decided by the lead under the founder's 2026-09-25 grant; founder decided
  the PQ-only line.
- 2026-09-29 — Article X.2 amended, founder-approved (grants cited), recorded by
  lead: it names the live guard (v7 through `rr_guarded.ps1`) and keeps v4 for
  engine and release builds. Grants: 2026-09-28 "2 is fine instead of 2.2";
  2026-09-28 "when im not actively using the laptop ... only 1 gb cap remains";
  2026-09-29 "As long as it doesn't compromise safety and accuracy do whatever u
  want"; standing 2026-09-25 "u have all auth". XI.2 record in
  `docs/CORE_REDESIGN.md`.
