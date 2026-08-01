# Blind Ledger continuation mandate and product ideology

Updated: 2026-08-01

Status: mandatory agent-recovery and execution instruction. Read `AGENTS.md`, this file, the newest
section of `STATE.md`, `docs/CURRENT_TECH_STACK.md`, and the deterministic continuation contract
near the top of `docs/IMPLEMENTATION_ROADMAP.md` before resuming trust-critical work.
`WAVE2_HANDOFF_2026-07-26.md` is historical recovery evidence: its interrupted GPU-PCS boundary and
next-step language are superseded by the accepted H4 K128/K512 prototype and current Gate 2E plan.
Do not restore an old browser/PDF session or use a dated historical section as current authority.

This file records the owner's standing direction to persist through the entire internally buildable
roadmap. It does not override higher-priority system/developer instructions, `AGENTS.md`, an explicit
newer user instruction, a fail-closed security gate, or the exact authorization required for a
destructive or externally consequential action.

## 1. Terminal objective

Continue the active Blind Ledger work through all six internal engineering waves until the repository
meets `DEPLOYMENT_READY_AUDIT_PENDING`, unless the owner explicitly pauses, replaces, or narrows the
objective. The final independent security audit and operator-supplied live credentials/authorizations
remain outside internal engineering completion.

Do not treat a package, stage, prototype, benchmark, documentation pass, research pass, wave fragment,
or first successful proof as the terminal objective when later required work remains. At a milestone:

1. record exact evidence and remaining gaps;
2. update status without inflating completion;
3. identify the next dependency from the roadmap; and
4. continue immediately.

Do not stop merely because work is large, slow, difficult, unfamiliar, inefficient, requires another
iteration, crosses a context window, or reveals more work than expected. Do not convert a partial
result into a request for permission when the next action is safe, reversible, already authorized,
and inside the active roadmap.

## 2. Recovery after compaction or handoff

After every compaction, loss of context, or handoff:

1. read `AGENTS.md` completely;
2. read this file completely;
3. read the newest section of `STATE.md`, then `docs/CURRENT_TECH_STACK.md` completely;
4. read the deterministic continuation contract in `docs/IMPLEMENTATION_ROADMAP.md` and every
   specialized architecture document it names for the active gate;
   R01-R12 work always includes `docs/ETHEREUM_STRAWMAP_BASED_ROLLUP_COMPATIBILITY.md`;
5. read dated handoffs and historical sections only when provenance or a rejected decision is
   needed; never execute their old next-step language;
6. inspect `git status --short` and preserve every pre-existing user change;
7. reconstruct the active task from the newest user instruction, current plan, roadmap gate, exact
   source, tests, and sealed evidence--never from a vague conversational summary alone;
8. resume the last genuinely incomplete step rather than restarting completed work or returning a
   status-only answer; and
9. keep progressing through the next roadmap dependency after each verified milestone.

If the recorded plan and repository disagree, trust actual source, raw evidence, and fail-closed
tests. Reconcile the documentation; never weaken a check or invent evidence to make the record agree.

## 3. Persistence rule

For every problem discovered inside the authorized scope:

1. reproduce and classify it;
2. determine the root cause from source and raw evidence;
3. design the smallest safe correction consistent with the product ideology;
4. implement it;
5. test the correction and relevant adversarial cases;
6. update affected canonical documentation and evidence;
7. re-run the containing integrity gates; and
8. continue the active roadmap work.

A failed test, missing dependency, incompatible primitive, poor benchmark, broken prototype, upstream
limitation, stale document, dirty worktree, or rejected architecture is a problem to investigate and
solve or route around--not an automatic stopping point. Search primary literature, inspect upstream
source, construct an internal replacement, reduce the problem, or build a differential prototype as
appropriate. Preserve rejected evidence and keep moving.

Never weaken correctness, privacy, security, soundness, parsing, resource, benchmark, or activation
gates to create apparent progress. A candidate may be rejected; the product requirements may not.

## 4. Legitimate hard stops

Stop and report exact raw evidence only when continuing would require one of the following:

- contradicting a higher-priority instruction or the owner's newest instruction;
- guessing a trust-critical semantic, cryptographic, financial, state, migration, custody, or
  activation decision that cannot be derived from authoritative material;
- weakening or bypassing a fail-closed gate;
- an irreversible/destructive operation whose exact target or authorization is unclear;
- credentials, legal authority, money movement, live external-system access, or another material
  permission that was not supplied;
- a repeated external/environmental failure after safe in-scope alternatives have been exhausted; or
- a proven incompatibility between two non-negotiable requirements that requires the owner to choose.

Before declaring a blocker, exhaust safe local diagnosis, primary-source research, internal
implementation alternatives, compatible toolchains, clean-room prototypes, and reversible fixes.
Report the exact condition, commands/output, affected gate, attempted alternatives, and the smallest
decision or external change required. Resume automatically when that condition clears.

Normal commentary updates, benchmark reports, and milestone summaries are not stops. Continue work
after providing them unless user input is genuinely required.

## 5. Product ideology--apply to every decision

Evaluate every architectural, cryptographic, implementation, testing, operational, and documentation
decision against this ordered set of requirements. Re-read this section whenever choosing between
candidates.

1. **Maximum correctness, privacy, safety, and fail-closed behavior.** A fast incorrect or leaky
   system is a failure. Malformed, ambiguous, stale, downgraded, unauthenticated, or unsupported input
   must be rejected deterministically.
2. **Absolute post-quantum protection on every Blind Ledger-controlled boundary.** Do not rely on
   RSA, ECC, pairings, KZG, IPA, trusted setup, a classical wrapper, or an unqualified assumption for
   an authoritative Blind Ledger security claim. External Ethereum classical cryptography must remain
   explicitly isolated and must not be counted as end-to-end PQ protection.
3. **Maximum measured throughput inside the immutable safety bounds.** Attack dominant costs from
   first principles; eliminate duplicated work, unnecessary abstraction, memory traffic, serialization,
   hashing, conversions, and proof overhead. Do not add fashionable machinery or defensive bloat
   without a measured or theorem-required purpose.
4. **Laptop-first resource discipline with server-scale parallelism.** The reference Dell G15 must
   remain at or below 5,000,000,000 peak resident bytes, strictly below 5,000,000,000 scratch
   bytes, and use no swap. The hard
   p95 objectives are below 60 seconds for fixed-shape K128/100-live and below 180 seconds for
   K512/500-live under the complete fresh-proof benchmark. Designs must also expose deterministic,
   modular parallelism for future large CPU boxes rather than depending on extra RAM to rescue bloat.
5. **Maximum auditability.** Use canonical bounded formats, explicit domain separation, exact
   parameters, readable modules, independent verifiers, reproducible builds, KATs, mutation/attack
   tests, raw measurements, source identities, rejection records, and honest observed/inferred/
   projected labels. Never claim more than raw evidence proves.
6. **Maximum modularity and replaceability.** Separate claim semantics, state relation, commitment/
   PCS, transcript, hiding, verifier, custody, rollup, adapters, and operations behind narrow versioned
   interfaces. A primitive, government endpoint, oracle, or chain change must not require rewriting
   unrelated product layers.
7. **Seamless government API and oracle integration.** Use provider-neutral ports and versioned
   adapters with deterministic normalization, exact provenance, dual-PQ authority, freshness,
   completeness/absence evidence, retries, idempotency, local simulators, sandbox fixtures, and
   conformance tests. Vendor response objects never become core proof semantics.
8. **Complete internal buildability.** All 93 engineering packages must be finishable from this
   repository without an outside engineer, external prover, paper author, live credential, or future
   service. The only outside assurance dependency is the final independent audit of the completed
   release candidate.
9. **Strict privacy boundary.** Preserve fixed approval/denial/cover shape, native witness hiding,
   identical observable schedules and bounded proof grammar, and the exact ordered 12-field external
   ABI. Put no PHI, exact private amount, claim document, decision metadata, or private operational
   detail into public calldata, blobs, logs, proofs, errors, or telemetry.
10. **Frozen cryptographic floors.** Preserve authoritative SHA3-512 commitments/state identifiers,
    M31 base arithmetic with the reviewed degree-16 Fp16 challenge field, at least 256 bits of
    cryptographic security/encryption strength for every theorem/error term and the composed
    security ledger, authenticated interactive public coin with no launch
    Fiat--Shamir/QROM or grinding credit, and ML-DSA-87 plus SLH-DSA-SHAKE-256f on Blind
    Ledger-controlled authority/public-coin surfaces unless a strictly stronger fully reviewed profile
    replaces them.
11. **Frozen resource gate.** Complete K128 and K512 proving must use no more than
    5,000,000,000 peak resident bytes (5 GB decimal) on the reference laptop, with no swap
    dependency. Historical lower limits remain evidence of prior runs, not current acceptance gates.
12. **Atomic state and proof integrity.** Attempt/nullifier identity must be retry-stable. Membership,
    absence, uniqueness, ordering, money conservation, old/new state, commitment equality, proof,
    verifier identity, schema, parameters, migration, and settlement must be bound atomically with no
    host-trusted equality or reusable partial receipt.
13. **First-principles simplicity.** Prefer the smallest construction that satisfies the complete
    theorem and product boundary. Remove dead code, duplicate representations, speculative layers,
    obsolete artifacts, and dominated architectures only after resolving exact ownership and preserving
    required audit evidence.

Before accepting any design, ask in order:

- Is it correct and fail closed?
- Is every private value and metadata channel protected?
- Is every Blind Ledger-controlled trust boundary genuinely PQ under explicit assumptions?
- Does it preserve the sealed relation, retry identity, money, state, and exact ABI?
- Is it simpler, faster, or required by the theorem--and is that measured or explicitly pending?
- Can an independent reviewer reproduce and verify it?
- Can the component be replaced without infecting unrelated layers?
- Does it improve or preserve government/oracle interoperability?
- Does it fit the laptop gates and scale cleanly to a large CPU box?
- Are all claims labeled as measured, derived, projected, or unknown?

If any answer fails, redesign or reject the candidate and continue searching.

## 6. Research, downloads, and tools

Research and dependency acquisition are authorized when necessary for the roadmap, subject to these
rules:

- prefer primary papers, standards bodies, official project documentation, official release pages,
  and the upstream author's verified repository;
- do not download executables, archives, code, models, datasets, or dependencies from mirrors,
  aggregators, file-sharing sites, shortened links, forum attachments, or other untrusted sources;
- inspect existing local tools first and avoid redundant installations;
- pin the exact version/commit, verify publisher signatures or official hashes when available,
  compute local hashes, record source URL/license, and include retained dependencies in the lockfile,
  provenance record, SBOM, and offline/reproducible build boundary;
- inspect licenses and reject terms incompatible with the intended product or internal reproduction;
- isolate and review new cryptographic code before it enters a trust boundary;
- keep downloads, build caches, traces, witnesses, proofs, and temporary research artifacts outside
  protected source/release outputs unless they are intentional reviewed artifacts;
- never upload repository source, secrets, PHI, credentials, private witnesses, or unpublished proof
  artifacts to third-party services; and
- remove disposable artifacts safely after recording required evidence.

An unavailable or unsuitable upstream package means build or adapt the required component internally;
it does not make the roadmap depend on outside help.

## 7. Worktree, evidence, and communication discipline

- Treat the worktree as shared and preserve unrelated/pre-existing modifications. Never reset, clean,
  overwrite, or delete broad paths to simplify the task.
- Use the smallest correct change, follow existing patterns, and use `apply_patch` for manual edits.
- Never weaken tests, filters, gates, or measurements. Never silently skip work; record every skipped
  item with count and reason.
- Distinguish ran, passed, independently verified, selected, activated, and audited.
- Run focused tests during development, containing regression/attack tests after convergence, and
  exact integrity/readback checks before claiming completion.
- Maintain concise progress updates during long execution, but do not mistake communication for a
  terminal handoff. After an update, continue.
- At completion, report exact changed artifacts, raw verification results, remaining downstream work,
  and the next roadmap boundary. Mark a wave/package complete only when its written acceptance gates
  actually pass.

## 8. Current standing reminder

Current recorded position: progress is 6 of 93 packages complete, Wave 1 is sealed and
nonactivating, H4's manifest-bound one-run K128/K512 prototypes pass, Wave 2 remains active,
`proofSuiteId` is null, and real PHI/payments remain forbidden. Gate 2E is the next dependency: it
must select and atomically bind the committed state/PQ-commitment plane. H5 then runs the repeated
complete-proof p95/resource campaign; H6 closes proof-candidate qualification. Re-read `STATE.md`
and `docs/CURRENT_TECH_STACK.md` for current truth because these boundaries may advance while this
ideology and persistence mandate remain in force.
