# Blind Ledger design ideology

Updated: 2026-08-14
Owner: independent design contract for smallest-correct implementation, deterministic evidence,
bounded resources, modular ownership, and fail-closed execution. It cannot override `AGENTS.md`.

This is the working design contract for implementation and proof-run decisions. It explains how
the system should be built, not what a successful experiment is allowed to claim.

Operational gate and continuation authority is `AGENTS.md`, with bounded-work precedence in
`CURRENT_TASK.md` and evidence precedence in `STATE.md`. This design contract may explain those
rules but cannot override them.

## First principles

Start with the invariant that must be true for the decision to be safe, then derive the smallest
implementation that makes that invariant executable and independently checkable. A historical
workflow, a convenient gate, a benchmark, a host comparison, a caller boolean, or a digest is not
authority merely because it already exists.

Gates are executable controls for invariants, not the invariants themselves. A gate can be stale,
incorrect, over-broad, or non-applicable to a changed profile. When current evidence demonstrates
that, evolve the gate explicitly: retain it, replace it, weaken it, disable it, suspend it, or
relabel it. Record the exact predicate, the invariant and failure mode it protects, the raw
evidence that makes it unsuitable, the replacement or compensating control, the scope and duration,
and the claims that must be withdrawn or downgraded. Never silently bypass a gate or change a
policy byte to obtain a passing result. The goal is the smallest correct control that preserves
the intended invariant, not a cosmetically green run.

A changed gate does not inherit the old assurance. A weakened, disabled, or relabelled control may
support synthetic exploration or diagnosis, but the result remains nonqualifying until fresh
evidence supports the stronger claim. This does not authorize malformed proofs, skipped
independent verification, broken atomic mutation, unsafe resource use, real PHI, real payments, or
activation.

## Creative problem solving

Treat the current implementation as one hypothesis, not as the boundary of the solution space.
When measured evidence shows that an approach cannot meet the governing invariant, resource bound,
or throughput target, return to first principles and search for a materially simpler composition,
representation, schedule, or ownership boundary. Reuse a known-correct path, collapse duplicate
work, move computation to its natural owner, or replace ceremony with a smaller authenticated
contract when that preserves the same truth.

Creativity must remain disciplined: state the invariant, identify what is trusted, make the new
idea falsifiable with the cheapest deterministic test, and compare it against adversarial,
mutation, replay, resource, and whole-system evidence. Do not confuse novelty with progress, add
speculative layers without a measured need, or weaken a claim merely to preserve an attractive
design. The preferred creative solution is the smallest one that makes the required truth easier
to verify, faster to produce, and harder to misuse.

## Persistence is part of the design

Once an implementation, test, or run-preparation objective is authorized, work through its
dependency chain until the objective is complete. A substep passing, a boundary being reached, a
preflight failure, or a missing seam is information about the next step—not an automatic stopping
point. After every phase boundary, re-read the smallest current evidence needed, classify the
result, make the leanest correct change or perform the next safe check, and rerun the containing
verification. Stop only when the objective is complete, the user stops it, the next action is
unsafe or destructive without approval, a protected-path conflict exists, or no safe in-scope work
remains. A blocked run or blocked claim does not automatically mean the whole task is blocked.

## Authority and ownership

- The database owns Blind Ledger operational state and commits a clearance transition only after
  any required native proof
  acceptance in the same atomic transaction.
- The Rust verifier owns cryptographic proof acceptance, transcript replay, proof-envelope
  decoding, roots, targets, and public-input reconstruction.
- The approved executable Lean kernel owns canonical semantic decoding, the five-directive
  evaluator, and legal state-transition meaning once implemented and linked. Until then, the
  current Python/Rust paths are synthetic evidence rather than deployed formal authority.
- Python, CUDA, workers, and GPUs are untrusted producers or accelerators. They may propose bytes;
  they cannot authorize a receipt or a state mutation.
- Every trust-critical value has one canonical owner. Other layers carry a binding or a checked
  projection, never a competing source of truth.

## Smallest complete boundary

Build the leanest boundary that is complete at its own claim level, then extend it one boundary at
a time:

1. exact input and identity contract;
2. producer artifact with bounded grammar;
3. independent verifier returning an opaque receipt;
4. mutation and transcript tests;
5. resource and cleanup evidence;
6. composition with the next verified receipt.

Removing duplication, unnecessary transport, or stale process ceremony is good engineering. Removing
privacy, exact binding, fresh randomness, fixed shape, fail-closed parsing, independent verification,
mutation coverage, or resource accounting is not optimization.

## Maximum modularity

Maximize useful modularity and minimize hidden coupling. Each boundary should have one clear owner,
one narrow versioned contract, one independently testable failure surface, and one explicit trust
classification. Keep producers, canonical encoders, verifiers, state mutation, policy, resource
control, custody ports, and evidence packaging separable so one can be replaced or audited without
silently changing another layer's authority.

Prefer composition of small complete components over a monolith, but do not split a theorem or
atomic transition at a point where its security property depends on seeing the whole operation.
Bind every cross-module value and identity explicitly; do not rely on shared mutable state, hidden
fallbacks, implicit conversions, caller booleans, duplicated sources of truth, or transport details
that masquerade as verification. A module boundary is successful only when the isolated contract,
the composed contract, mutation behavior, failure behavior, and evidence identity all reconcile.

Maximum modularity also means minimum accidental surface area: avoid abstraction layers that add
ceremony without replaceability, obscure the authoritative owner, scatter security logic, or make
the smallest correct implementation harder to inspect. Keep the trusted core small, make
accelerators and experiments untrusted and replaceable, version interfaces when their claims change,
and test every seam adversarially.

## Production-shaped integration

The working system is a production-shaped, integration-ready candidate. Canonical semantics,
artifact grammar, roots/order, authority ownership, state transitions, retry/recovery, export, and
support boundaries are fixed interfaces. Authenticated source adapters, governance/PQ signatures,
production custody, state-owned deployment/support, the executable Lean kernel, and the
theorem-qualified private-proof backend are replacement seams. Qualification—not semantic rewrite—
is the intended path: every plug-in must pass the same KAT, independent-verification,
mutation/replay/recovery, and resource gates. If a plug-in changes directives, result separation,
authoritative absence, chronology, decision/access joins, exception identity, or fail-closed state
meaning, it is an architecture change. The read-only provider-continuity wedge can qualify its
source and operational adapters without waiting for private-payment ZK; the private clearance path
still requires Lean and theorem-qualified ZK/database-custody gates.

## Least trusted computing base

Minimize the code, state, and authority that can authorize proof acceptance or a clearance
transition.
The database owns operational state, the native verifier owns proof acceptance, and every producer,
accelerator, transport, and convenience layer is untrusted until its output crosses an independently
checked boundary. Keep the trusted core small, explicit, and auditable. Any expansion of the trusted
computing base requires a named invariant, an owner, a binding, an attack test, and retained evidence.

## Executable formal authority

Use Lean for the smallest pure kernel whose output can authorize a clearance semantic result or
legal state transition. The formal definition must either execute in the deployed path or have a
reviewed refinement proof to the deployed implementation. A separate model plus matching examples
does not make production code formally verified.

Lean owns business semantics, bounded canonical semantic decoding, control-set behavior,
authoritative absence, chronology, exceptions, observation-only separation, replay, exact
decision/access joins, and allowed after-state. Rust owns cryptographic proof acceptance and the
native operating boundary; the database owns concurrency, durability, and recovery. Any mismatch
between independently checked layers fails closed.

Keep the theorem kernel small, pin the toolchain and dependencies, enumerate admitted axioms, run
an independent kernel/environment check, and version theorem statements as trust-critical
interfaces. Formal proof never upgrades an unproved cryptographic assumption, dishonest source,
unlawful policy, unavailable database, or operational claim.

## Determinism and reproducibility

Make governed behavior reproducible wherever security permits, and make every necessary source of
entropy explicit. Canonicalize inputs, encodings, profiles, toolchains, schedules, identities, and
artifact order. Record the exact Git state, commands, environment, random-source contract, hashes,
and measurements needed to reconstruct a result. A result that cannot be rebuilt or independently
read back is evidence of an observation, not a durable system fact.

## Fail-closed and monotonic safety

Unknown, missing, mismatched, timed-out, partial, stale, malformed, or cleanup-failed state never
creates authority. Only an independently verified receipt may advance the state, and retries must
be idempotent rather than consume a nullifier twice. Epochs, identities, and anti-rollback domains
must move monotonically. A relaxed gate lowers the claim; it never upgrades a failure into a pass or
allows an unverified artifact to enter an atomic transition.

## Claims proportional to evidence

Every statement has an evidence class: measured, independently verified, derived, projected,
reference-only, or unknown. Report the class with the result and keep the claim no stronger than the
retained evidence. A component benchmark, cached proof, clean process exit, host comparison, or
caller assertion cannot become complete-proof credit by wording. When evidence weakens, downgrade
the claim immediately instead of preserving a prior label for convenience.

## Recovery before optimization

Design restart, retry, idempotency, rollback, cleanup, custody, and partial-failure behavior before
optimizing throughput. A proof or state transition is not complete if it cannot recover safely from
interruption. Optimize only the measured dominant stage, preserve the same canonical semantics and
security boundary, and rerun the containing mutation and adversarial checks after every optimization.

## Explicit state machines

Represent proof, payment, migration, profile, suite, and activation lifecycles as named states with
explicit legal transitions, guards, identities, and epochs. Do not infer authority from a Boolean,
file name, log line, process exit, or caller-selected status. Stale, replayed, concurrent, or
out-of-order transitions must be rejected at the state owner, and each accepted transition must
have one atomic mutation and one retained receipt.

## Adversarial simplicity

Prefer boring, inspectable mechanisms with few dependencies, explicit data flow, bounded parsers,
and obvious failure behavior. Treat cleverness, hidden automation, novel cryptography, implicit
fallbacks, and extra abstraction as liabilities until they earn their complexity through a named
benefit and executable tests. Remove ceremony that adds no assurance, but never remove a check,
binding, privacy property, mutation test, or evidence record merely because it is inconvenient.

## Privacy as a measurable property

Privacy is an observed noninterference property, not an intention or a field label. Measure and
test proof shape, trace shape, timing, memory/resource behavior, errors, logs, temporary files,
artifacts, cleanup, and retries for dependence on hidden witness values. Keep fixed-shape and
native-hiding claims tied to raw attack and telemetry evidence. Do not introduce real PHI, real
payments, or live credentials while proving the engineering boundary.

## Proof and evidence discipline

- Bind profile, statement, policy, ruleset, source, state-before, state-after, program, schedule,
  transcript, verifier, and artifact identities exactly.
- Parse and validate lengths, versions, order, commitments, and padding before allocating from
  untrusted sizes.
- Keep observable shape independent of the hidden witness.
- Treat measured, derived, projected, and unknown values as different evidence classes.
- Give no complete-proof credit to a component benchmark, cached proof, host-side equality, or
  internal verifier timing.
- Every accepted artifact gets mutation replays, raw verifier output, resource telemetry, cleanup
  status, and hashes retained with its run identity.
- A failed or incomplete run remains failed or incomplete. Silence, a timeout, and a clean process
  exit are not verification.

## Sequencing and scale

Use one fresh complete one-operation native-v3 proof to exercise the smallest governed clearance
profile and expose integration defects cheaply. Only after its producer, independent verifier,
five-directive semantics, transcript, mutations, resources, and evidence reconcile should the same
contract advance to the 100-live CPU profile. A larger profile is a dependent scale run, not an
independent shortcut around an unresolved tiny boundary. The old exact-K128/K512 workloads remain
rejected-layout evidence rather than active scale names.

Current qualification status and nonactivation gates are authoritative in `STATE.md` and
`CURRENT_TASK.md`; conditional ZK and committed later Ethereum L1 checkpointing never weaken the canonical
boundaries or become automatic dependencies of the read-only wedge.
