# Blind Ledger implementation roadmap

Updated: 2026-08-01

Status: authoritative implementation sequence for the isolated architecture workspace.

Use `CURRENT_TECH_STACK.md` for the active code inventory and `REJECTED_ARCHITECTURES.md` for
non-executable alternatives. Dated sections below preserve evidence and sequencing decisions; only
the current execution boundary and still-open package gates authorize new work.

Current execution boundary: read the newest dated section of `../STATE.md`; the original transfer
record is `../WAVE2_HANDOFF_2026-07-26.md`. H4's manifest-bound semantic source, real 168-layer
native-masked GKR, Construction 8.2 PCS, authenticated public coin, atomic one/four-shard
coordinator, parser, and independent verifier now pass one fresh K128 and K512 attempt in
29.974129/120.460733 seconds. This closes H4's functional and one-run prototype-latency boundary,
not a numbered package or Wave 2. Gate 2E authenticated-state selection and atomic binding are the
next architecture dependency; H5's repeated p95/resource campaign and H6 suite qualification must
then close before 2F can qualify. `proofSuiteId=null`, activation=false, and the count of 6/93
remain unchanged.

Repository-layout readback also found 14 files in the app-root `ops/` compatibility mirror and no
required canonical sibling `../ops/`. This pre-existing gap causes readiness and attack suites to
fail closed before substantive assertions and remains part of open operations/release work. It does
not change H4 evidence or the 6/93 count. Recover the exact canonical sibling and prove recursive
byte identity; do not construct it from an assumed mirror or weaken path checks.

## Deterministic continuation contract

This section is the only current execution algorithm in this document. Dated sections below it are
evidence and design lineage. A successor must not execute a historical sentence such as “next,”
“remaining,” or “rerun” unless this section still names the same action.

### Current state machine

| Boundary | Current state | What is actually proved | What remains |
| --- | --- | --- | --- |
| Wave 1 | Sealed, synthetic, nonactivating | Exact bounded claim relation, fixed-shape traces, money/replay/payment semantics, SHA3 schedule, and ordered 12-field projection | Durable authoritative state, production adapters, and activation |
| H0-H3 | Prototype implementation complete | Exact bus, B16 Keccak/GKR, native GKR masks, Construction 8.2 mechanics, public coin, and independent component verification | Complete cross-module simulator/security ledger remains a containing H6 obligation |
| H4 | Prototype-accepted | One manifest-bound K128 and one four-shard K512 proof pass complete independent verification at 29.974129/120.460733 seconds | Does not include selected persistent state, repeated p95, final suite identity, production verifier, or activation |
| Gate 2E | Open and next | C0 correctness control and research plan exist | Implement candidates, select state relation/commitment, prove atomic binding and migration |
| H5 | Blocked on Gate 2E | One-run H4 timing establishes feasibility | Run the selected state-bound candidate: one warm-up plus ten measured unique proofs per profile |
| H6 | Blocked on Gate 2E and H5 | Current parser/KAT/mutation evidence exists | Close complete theorem/simulator, identity, reproducibility, attack, recovery, and qualification gates |
| Wave 3 | Blocked on H6 | Reference state/verifier/custody components exist | Production verifier, authoritative publication, custody, migration, rollback, and suite assignment |

The one legal next dependency chain is:

```text
recover/verify canonical ../ops when trusted material is available
    -> Gate 2E control and interface freeze
    -> Gate 2E state-relation candidates
    -> Gate 2E PQ-commitment candidates
    -> atomic state + H4 composition
    -> migration/recovery/attack closure
    -> Gate 2E selection
    -> H5 repeated complete-proof campaign
    -> H6 proof-candidate qualification
    -> Wave 3 production verifier/state/custody
```

The missing `../ops` tree blocks broad readiness evidence but does not authorize inventing policy
bytes and does not prevent isolated Gate 2E design/prototype work that does not claim a full
repository pass. Before any result is promoted beyond an isolated prototype, canonical ops identity
must be restored and all affected gates rerun.

### Required reasoning record for every change

Before editing a trust boundary, record in the change or `STATE.md`:

1. the invariant being protected or bottleneck being removed;
2. the authoritative producer and every downstream consumer;
3. public versus private inputs and outputs;
4. canonical encoding, domain, version, and size bounds;
5. concurrency, retry, crash, rollback, recovery, and partial-failure behavior;
6. adversarial substitutions or splices that must fail;
7. exact focused tests and containing gates;
8. resource effect in decimal bytes/MB and throughput effect at the complete boundary; and
9. rollback or rejection path if the candidate fails.

A step without a theorem, invariant, compatibility, audit, or measured-throughput purpose is bloat.
Delete it only after proving that no current producer, consumer, manifest identity, migration path,
negative test, or verifier invariant requires it.

## Gate 2E: exact current implementation plan

`BL_PQ512_COMMITTED_SPARSE_STATE_PLAN.md` owns the candidate theory. The sequence below owns
execution and prevents a successor from jumping from a paper benchmark to a selected state plane.

### 2E-0 - freeze the C0 control

Inputs:

- exact sealed K128/K512 synthetic fixtures;
- full-width replay/payment keys and values;
- canonical access order, duplicates, conflicts, denial, cover, and correction cases;
- old/new roots, operation log, append index, money totals, and ordered 12-field output; and
- current complete H4 manifest, timing, proof, and resource boundary.

Required output:

- one canonical fixture manifest with byte lengths and SHA3-512 identities;
- independently reproduced C0 membership, absence, sequential-update, and endpoint results;
- exact state-only and complete-boundary call/time/RSS/scratch/I/O measurements; and
- negative fixtures for stale reads, omitted/reordered writes, duplicate labels/nullifiers,
  collision, root substitution, and conflicting updates.

STOP if C0 does not reproduce the sealed relation. An alternative cannot repair a disagreement by
changing semantics, normalizing inputs, or redefining the root.

### 2E-1 - freeze narrow replaceable interfaces

Define separate bounded interfaces for:

- state layout and version;
- canonical key/value encoding;
- read membership and absence;
- ordered read/write access manifest;
- memory-consistency relation;
- commitment creation and opening;
- old/new state transition;
- SHA3-512 public state identifier;
- migration equivalence and rollback;
- transcript contribution;
- independent verification; and
- atomic receipt contribution.

Every interface requires an exact byte grammar, maximum size, domain separator, profile/parameter
identity, canonical decode rule, error family, and ownership statement. The state relation and PQ
commitment must remain replaceable modules; neither may reach into claim semantics or settlement.

### 2E-2 - implement scalar state-relation controls

Implement C1-C4 only far enough to answer correctness, privacy, asymptotic, and integration
questions. Each candidate must match C0 on the complete positive and negative corpus before SIMD,
CUDA, lattice compression, or complete-proof integration. Require deterministic scalar reference
outputs and an independent verifier. Reject a candidate immediately on semantic drift,
witness-dependent shape, global-state scan hidden behind setup, unbounded grammar, or host-trusted
equality.

### 2E-3 - screen PQ commitment backends

For each admitted commitment candidate, pin the exact paper/version/source/license, assumptions,
parameter generator, field mapping, rejection/abort distribution, knowledge/binding/hiding claims,
update model, proof grammar, and verifier. Build KATs and mutation tests before optimization.

Reject any backend that relies on pairings, KZG, IPA, RSA, ECC, trusted setup, Fiat--Shamir/QROM
credit, a designated verifier, an external service, an unsupported knowledge assumption, or a
security estimate below the frozen composed floor. A lattice label is not PQ evidence.

### 2E-4 - atomically compose the finalist

Bind in one transcript and receipt:

- sealed semantic program and port identities;
- fixed Claim Batch Access Manifest and conflict order;
- attempt/nullifier identity;
- state layout, epoch, capacity, and parameter identities;
- old commitment/root and new commitment/root;
- membership, absence, uniqueness, read/write order, and money conservation;
- H4 bus, native-masked GKR, Construction 8.2 PCS, public coin, and execution manifest;
- migration version where applicable;
- exact ordered 12-field projection and wide sidecar; and
- verifier/module identities.

No partial receipt is reusable. No host comparison may substitute for an in-proof equality. Change
any one bound field and require rejection before state acceptance.

### 2E-5 - close migration and failure semantics

Test genesis, old-layout-to-new-layout equivalence, checkpoint publication, conflicting-before-state
CAS, reorganization, rollback, restoration, partial write, crash before/after publication, corrupted
checkpoint, stale epoch, parameter rotation, verifier rotation, and mixed-profile rejection. Prove
that retries preserve attempt identity but use fresh proof randomness. Recovery must never accept an
unproved state or reinterpret old bytes under a new layout.

### 2E-6 - measure and select

Use staged measurement so rejected candidates do not consume a full H5 campaign:

1. repeated state-component measurements on identical fixtures;
2. one uncounted complete warm-up for each finalist/profile;
3. at least one fresh, externally monitored, independently verified complete K128 and K512 proof
   for each finalist that remains eligible; and
4. selection of the fastest candidate that passes every correctness, privacy, PQ, auditability,
   migration, host-memory, scratch, and no-swap gate.

Record p50/p95 only for sample sets large enough to define them honestly. Gate 2E selection is not
H5 qualification. If no alternative beats C0 at the complete boundary, select C0 and preserve exact
rejection evidence; asymptotic fashion is not a reason to ship a slower or less auditable design.

### 2E-7 - seal the selection handoff

The Gate 2E terminal record must contain:

- selected relation and commitment identities, parameters, source/lock/license hashes, and schema;
- exact theorem and composed-security status, with every unclosed H6 obligation enumerated;
- complete positive, mutation, attack, migration, rollback, and recovery results;
- state-only and complete-boundary measurements;
- rejected candidates with exact reasons and retained evidence;
- updated source ownership and proof/verifier dataflow;
- Git commit/tree, clean status, and protected-path readback; and
- the exact H5 command, environment, input-manifest generator, monitor, and STOP conditions.

Gate 2E closes only when the selected state plane is in the actual H4 parent, transcript, proof,
independent verifier, and atomic receipt. A document-only selection does not close it.

## H5: repeated complete-proof qualification campaign

H5 begins only after Gate 2E-7. It qualifies the exact selected state-bound candidate, not a cached
H4 proof and not an isolated GKR, PCS, or state benchmark.

### H5 prerequisites

- clean Git tree at the sealed Gate 2E commit;
- canonical `../ops` restored from trusted material and recursively byte-identical to `ops/`;
- locked/offline builds and manifest readback passing;
- driver System-log audit and a verified clean reset boundary;
- no later `nvlddmkm` Event 153 or Display Event 4101;
- exclusive host, sufficient physical/device headroom, no competing build/proof/cache scan;
- synthetic-only input allowlist and unique input manifest;
- external process-tree, pagefile, device, scratch, stdout/stderr, and driver monitor; and
- every focused, mutation, attack, parser, state, migration, and independent-verifier gate green.

### H5 run matrix

Run exactly 22 fresh launches unless a STOP condition ends the campaign:

| Profile | Warm-up | Measured unique attempts | Latency gate |
| --- | ---: | ---: | ---: |
| K128/100-live | 1 uncounted | 10 | p95 < 30.000000 s |
| K512/500-live | 1 uncounted | 10 | p95 < 180.000000 s |

“Fresh” means a new proof, masks, authenticated public-coin session, input identity, parent binding,
and receipt. Reviewed binaries, precompiled PTX, and immutable topology may be reused; witness,
proof, challenge, mask, query, opening, or partial-receipt caches may not.

Measure complete process time from admitted canonical input to successful independent verification
and atomic receipt. Record external-wrapper wall time separately. With ten measured attempts, use
the conservative nearest-rank definition: sort ascending and take element
`ceil(0.95 * 10) = 10`; therefore H5 p95 is the maximum of the ten accepted times. Do not average
away a slow or failed attempt.

For every attempt record input/fixture identity, proof and receipt hashes, wall/CPU time, stage
times, verifier time, proof bytes, peak internal/process-tree RSS, pagefile delta, tracked and total
device residency, scratch high-water mark, reads/writes, public-coin latency/retries, cleanup,
stdout/stderr hashes, driver-event interval, and every verifier flag. All memory units are decimal.

Any failed verifier, mutation, manifest, driver, no-swap, host/scratch, stderr, missing-telemetry, or
cleanup gate fails that attempt and stops the campaign for classification. It cannot be silently
discarded and replaced by an eleventh measurement.

### H5 throughput rule

Optimize the measured dominant complete-proof stage only. For each proposed optimization ask:

1. Is the work theorem-required or invariant-required?
2. If required, can it be fused, streamed, derived, batched, vectorized, or moved without changing
   transcript order or authority?
3. Does the independent verifier still reconstruct the same statement?
4. Does the containing benchmark improve rather than a microbenchmark alone?
5. Does it preserve or reduce memory, scratch, device residency, failure surface, and audit burden?

Reject an optimization that regresses the complete boundary, adds unverified device authority,
duplicates full source/state, introduces nondeterminism, shares nonlinear challenges without a
theorem, or increases live workers merely to hide startup latency.

## H6: proof-candidate qualification and seal

H6 consumes the exact H5 winner and must close all of the following before Wave 3 depends on it:

1. exact 256-bit composed theorem/error/abort/retry/multi-target ledger;
2. complete zero-knowledge simulator covering semantic AIR, state, GKR, PCS, public coin, malformed
   input, abort, retry, crash, retained artifacts, and repeated proofs;
3. fixed proof/sidecar/receipt grammar with bounded allocation and independent parser agreement;
4. downgrade, splice, replay, stale-state, migration, mutation, malformed-proof, and resource-DoS
   attack corpus;
5. cross-language KATs and authoritative Rust verification;
6. source, toolchain, dependency, license, SBOM, module, CUDA, schema, parameter, and manifest pins;
7. locked/offline reproducible builds and independent artifact readback;
8. H5 p95/resource/no-swap evidence and proof-size/verifier-cost thresholds;
9. side-channel, telemetry, zeroization, cleanup, and repeated-proof unlinkability evidence;
10. rollback/recovery and mixed-version behavior;
11. complete raw evidence manifest with no unexplained skip, warning, count drift, or failed gate;
12. explicit list of Wave 3 production-verifier/state/custody work that remains nonactivating.

H6 may mark the proof candidate qualified for Wave 3 integration. It must keep `proofSuiteId=null`
and activation false until the roadmap's authoritative verifier, state publication, custody,
migration, and activation packages close. H6 is not the final independent audit.

## Documentation and Git handoff discipline

At every 2E/H5/H6 phase boundary:

- update `STATE.md` first with raw evidence and honest labels;
- update `CURRENT_TECH_STACK.md` only when the active implementation changes;
- update this current-execution contract and the owning specialized architecture document;
- move dominated alternatives to `REJECTED_ARCHITECTURES.md` without leaving executable fallback
  code unless a current differential test imports it;
- update tests, SBOM, supply-chain pins, provenance, project map, quickstart, and known issues when
  affected;
- run stale-path/current-claim scans and documentation invariant tests;
- verify zero protected-path changes unless explicitly authorized;
- commit the smallest coherent verified phase with a clean worktree; and
- record commit, tree, exact commands, counts, failures, warnings, skips, resource evidence, risks,
  and the single next dependency.

Never create a model-specific memory file. The repository must be sufficient for a capable successor
with no chat context.

This roadmap records completed evidence and every currently identified package required to build a
technically deployable Blind Ledger release candidate: the private-claim/PQ core, government/oracle
integration layer, containing rollup, operations, and release evidence. It does not authorize real
PHI or production settlement and does not claim that the architecture is already implemented or
audited.

Read `docs/BASED_ZK_ROLLUP_ARCHITECTURE.md` for the containing system and
`docs/PQ_ZK_SECURITY_ARCHITECTURE.md` for the selected claim-proof security profile before using
this plan. `docs/DEPLOYMENT_READY_BUILD_CONTRACT.md` defines the authoritative boundary between
internal engineering completion, the single independent Security Audit Gate, and operator-supplied
activation inputs.
`docs/FRONTIER_THROUGHPUT_AND_ETHEREUM_ALIGNMENT.md` assigns state, scheduling, adapter,
formalization, and Ethereum-alignment work to existing Waves 2-6. It adds no package and changes no
status count.

## Count summary

The complete internally buildable program contains **93 explicitly listed engineering packages**
at the granularity used below. The former 78-row model mixed 73 engineering packages with five
external-audit workstreams and excluded the rollup and government-adapter build. That model is
superseded for current planning; sealed historical evidence is not rewritten.

| Group | Count |
| --- | ---: |
| Specification and security freeze | 12 |
| Fixed-shape semantics and claim AIR | 16 |
| Heterogeneous semantic-STARK/hash-coprocessor and native hiding | 12 |
| `BL-PQ512-v1` state, verifier, and custody integration | 12 |
| Cross-language, attack, leakage, and performance validation | 14 |
| Operations and release engineering | 7 |
| Government API and oracle adapters | 8 |
| Containing based rollup and end-to-end deployment | 12 |
| **Internal engineering total** | **93** |

Packages `S01`, `S03`, `S05`, `S06`, and `A12` are complete as documentation/application-
specification packages. R25 also completes `Z01` only as an isolated, verifier-clean, validity-only
baseline. Therefore **6 of 93 internal engineering packages are complete and 87 remain open**. This does not
close any private-proof, strict-PQ, state, custody, adapter, rollup, or release package.

The 2026-07-21 seal completes the current **Wave 1 claim relation and executable AIR** at its
synthetic, nonactivating boundary. Historical records called this boundary `Wave 1A`. It does not
increment the whole-product package count because the owning S/A/P/T packages also require the
strict-PQ proof, authoritative state, or broader convergence conditions listed below. Current
**Wave 2 strict-PQ proof and throughput recovery** is the active implementation boundary.

R33 supplied the narrower semantic-reference inventory, R34 corrected and resealed its payment
scope, and the R36 work then replaced the metadata-only handoff with explicit trace cells,
identities, lookups, SHA3 composition, and independent evaluators. “Semantic reference complete,”
“executable AIR complete,” and “private proof complete” remain three different claims.

The independent Security Audit Gate is not a package and is not included in the denominator. Live
credentials, government endpoints, governance enrollment, payment accounts, and legal authority
are operator activation inputs, not engineering packages and not excuses for an incomplete build.

## Plain-English delivery model

The 87 open packages are **not one run**. They are the full checklist for the finished product.
Execution uses bounded, reviewable waves; each wave changes one trust boundary, runs its focused
tests, then passes the complete convergence gates before the next boundary depends on it.
A wave is a milestone and may require many large runs; it is never an instruction to edit every
listed package at once.

| Wave | Outcome | Status and main packages |
| --- | --- | --- |
| 1. Claim relation and executable AIR | One bounded claim relation, canonical inputs, fixed approval/denial/cover work, exact money, replay/payment transitions, exact SHA3-512, and the 12-field output | **Complete and sealed, synthetic and nonactivating.** Historical label: Wave 1A. S/A/P/T semantic and AIR inputs. |
| 2. Strict-PQ proof and throughput recovery | Heterogeneous degree-16 semantic STARK plus shared-bus Boolean SHA3 coprocessor, authenticated public coin, native hiding, compact grammar, privacy-padded access manifest, state/conflict census, bounded-memory prover, complete K128/K512 proofs, and proof-level evidence | **Active.** H4 one-run prototypes pass; 2E, H5, H6, and final qualification remain open. Historical label: Wave 1B. Z02-Z12 and proof portions of P07-P12/T02-T14. |
| 3. Authoritative verifier, state, and custody | Final sidecar/verifier identities, measured authenticated-state topology, atomic tiered state, anti-rollback publication, custody, migrations, PQ checkpoints, and proof/verifier/state attacks | Open; depends on Wave 2. Historical label: Wave 1C. Remaining S/A/P/T state and custody packages. |
| 4. Government/oracle integrations and operations | Provider-neutral adapters, proof-carrying evidence capsules, FHIR/PAS/PDex profiles, simulators, conformance, isolation, monitoring, recovery, and reproducible operations | Open; I01-I08 and O01-O06/S11. |
| 5. Containing rollup | L2 verifier/state, rollup proof, Ethereum settlement, proof/data coupling, data availability, bridge, opaque FOCIL-compatible forced inclusion, exits, upgrades, recovery, and optional maturity-gated native-rollup adapter | Open; R01-R12. Draft EIPs are not dependencies. |
| 6. Release-candidate seal and deployment rehearsal | One-command sandbox deployment, multidimensional capacity control, shadow verification, formal-spine reconciliation, thresholds, full campaign, SBOM/readback, rollback, and audit packet | Open; O07-O12 plus every still-open convergence condition. |

The independent Security Audit Gate and later operator activation are **not a seventh engineering
wave**. The six numbered waves are internally buildable. The exact sealed output of Wave 6 goes to
one uncounted independent audit; live endpoints, credentials, accounts, signers, and legal authority
arrive only as operator activation inputs.

Historical evidence is not renamed or rewritten. For current planning, use this mapping:

| Historical label | Current wave |
| --- | --- |
| Wave 1A | Wave 1 - claim relation and executable AIR |
| Wave 1B | Wave 2 - strict-PQ proof and throughput recovery |
| Wave 1C | Wave 3 - authoritative verifier, state, and custody |

A run may close several packages only when their individual status conditions and shared convergence
gates all pass. It must never mark a whole wave complete merely because a prototype or fast benchmark
worked. This keeps progress parallel where safe without merging AIR semantics, proof cryptography,
state ownership, adapters, or rollup settlement into one unreviewable change.

Three different evidence/qualification bundles must not be confused:

- **Foundation bundle:** the authorized 17-item synthetic-only evidence run completed on 2026-07-15.
  It produced 16 draft/reference/prototype items and reran `T14`, but closed no package. Trust-
  critical choices remain provisional until independent review and their package-specific gates.
- **R24 S07-S12 pre-implementation freeze:** corrects the quantitative worksheet, permanently
  rejects the current suite, pins an exact nonactivatable candidate registry and 744-byte sidecar,
  repairs the discovered money-bound/parser mismatch, and writes the S10/S12 lifecycle/formal
  drafts and blocker ledger. It leaves `proofSuiteId=null`, generates no proof, and closes no
  additional package because the cryptographic and semantic dependencies remain open.
- **R25 local implementation wave:** implements and measures synthetic, nonactivating host
  semantics, logical schedules, payment/replay/state references, vectors, attacks, checked-money
  guards, and the S-two validity/security boundary. It closes only `Z01`; physical AIR, native
  witness hiding, the strict-PQ suite, authoritative state, and final audit remain open.
- **S09 internal construction slice:** selects an authoritative interactive public-coin direction,
  pins and executes the degree-16 tower/basis/encoding/rejection sampler, and implements a
  nonactivating PQ-verifier-port commit/reveal transcript with KAT and attack tests. It removes the
  upstream/QROM dependency from the launch architecture but closes no package because production
  PCS/FRI, the full schedule, retry governance, hiding, proof grammar, and module identities remain
  open.
- **R32 S09 cryptographic substrate:** adds a `no_std` Fp16/SHA3-512 Merkle Rust core, exact locked
  software PQ adapters, four-attempt suite-diverse retry/quarantine governance, a bounded
  `BLPQPF01` proof-grammar reference, and a fail-closed stop on unsafe generic OODS sampling. It
  keeps vendored S-two byte-stable, `proofSuiteId=null`, and activation false. It closes no package:
  final AIR dimensions, theorem-matched PCS/FRI, safe OODS, optimized/constant-time SIMD, durable
  challenge services, native hiding, final proof sections, and module identities remain open.
- **R33 Wave 1A semantic-reference completion:** replaces aggregate-only payment evidence with domain-separated
  SHA3-512 authenticated per-member benefit, unique provider-obligation, payer-reserve, and
  provider-payable maps. The current correction migrates those maps from 512-level key positions to
  depth-64 ordered positions retaining full 512-bit keys/values. Denial and cover update four
  precommitted zero-valued dummy leaves under the same four-upsert schedule, so they do not create
  durable throwaway records or allocator holes, and every slot
  appends a typed operation record. Its 16-table object is a metadata inventory that hashes host
  results; it does not bind a polynomial trace, and its K128/K256/K512 declarations are historical
  estimates rather than exact AIR dimensions. R36 is replacing it with executable constraints. All
  proof/challenge/commitment ports remain nonactivating, `proofSuiteId=null`, activation is false,
  and no proof is generated.
- **R34 Wave 1A corrective convergence:** rejects falsey non-mapping initial balance inputs and
  replaces the ambiguous member-only benefit namespace with a typed payer-authority/plan/benefit-
  period scope. The scope is SHA3-512 committed into the v2 payment-state root and every member-
  benefit key; scope drift, subclass commitment overrides, and committed-relation substitution fail
  closed. R34 also establishes
  this exact sealed source as a local Git baseline for reviewable future diffs. It does not close a
  proof or authoritative-state package.
- **R35 historical Wave 1B theorem-backend lineage:** now continued as current Wave 2. It implements authenticated
  Fp8-excluding OODS, scalar degree-corrected Circle-FRI, projection-consistent SHA3-512 mixed-
  domain commitments, exact unselected interface parameter sweeps, typed theorem messages, and the
  conservative pre-dense-schedule 16-table native-hiding worksheet. R35 additionally freezes a constructive direct
  hiding map, canonical quotient mask/source-aligned split rule, and a byte-oriented low-degree
  SHA3-512 round AIR. An AST-locked 52-callsite application inventory preserves the historical K128
  host-verifier envelope of 401,275 conservative AIR calls, 1,205,016 permutations, and 28,920,384
  Keccak round rows after restoring the pepper constraint. R35 then corrected a real semantic
  mismatch, then proved a better exact construction: all facts and authorization slots are encoded
  bijectively in one 2,133-byte bundle per claim. The proof hashes K bundles and one ordered root;
  an audit tree reuses the leaf digests. Earlier dynamic envelopes are audit-only. The current
  K128/K256/K512 claim-tree plus packed-oracle schedule uses 385/769/1,537 hashes,
  896/2,048/4,608 membership links, and 14,322/28,644/57,288 permutations. It has not fixed the
  non-dense application ports or selected a final rate or lookup-interaction packing. The successor
  kernel now generates and independently verifies a real 28,643,096-byte proof, but has not proved
  the complete K128 relation, completed the Circle simulator/native-hiding qualification, assigned
  a final module ID, or closed a package. These last sentences describe the R35 checkpoint, not the
  current implementation: H4 supersedes its active proof path with the manifest-bound 168-layer
  masked GKR and Construction 8.2 PCS prototype described in `docs/CURRENT_TECH_STACK.md`.
- **R26 interrupted private-proof-engine foundation wave:** its unsealed stage records report a
  narrow physical calibration AIR, strengthened nonactivating sidecar/verifier/replay/state
  references, 51 synthetic physical proof combinations, and a software/cross-language gate matrix.
  R26 never produced a
  terminal manifest or terminal seal. Its proof suite is explicitly rejected validity-only
  calibration. R28 later requalified the applicable current source and gates under its own terminal
  evidence; R26 itself remains unsealed and closes no additional package.
- **Final qualification bundle:** after the complete implementation exists, 16 automated gates can
  be combined into one fail-fast overnight qualification, organized as 12 sequential stages.

The accepted R24 pre-implementation freeze also authorizes a fourth, narrower activity: a
**synthetic local implementation-and-measurement wave**. That wave may build nonactivating semantic,
AIR, reference-state, parser, vector, attack, entropy-boundary, and measurement prototypes needed to
replace R24's remaining `TBD` inputs with evidence. It does not mean that S07-S12 are complete, and
it must not select a proof suite, assign `proofSuiteId`, claim witness hiding or strict-PQ security,
activate verifier/state, or count a package complete without its package-specific review evidence.
This distinction resolves the former ambiguity between "pre-implementation freeze accepted" and
"S07-S12 complete."

The final qualification bundle is **not runnable today**. The complete nonactivating Wave 1
executable relation and complete one-run H4 K128/K512 prototypes exist, but gate 2E has not selected
and bound the authoritative state plane, the complete simulator/composition ledger is not closed,
H5/H6 have not qualified the suite, and the final sidecar/verifier/state identities do not exist.

## Status definitions

| Status | Meaning |
| --- | --- |
| Complete | The stated package deliverable is finished and covered by current verified evidence; this does not close downstream implementation or assurance packages. |
| Qualified | A real isolated proof or test succeeded, but production integration remains open. |
| Selected | Architecture chosen; implementation and validation remain open. |
| Open | Required work has not been implemented. |
| Audit-pending | Internally implemented and qualified, but not eligible for production activation until the final independent audit accepts the exact release identity. |
| Activation input | Deployment-specific credential, endpoint, signer, account, or authorization supplied after engineering completion; not a package status. |

## Completed and qualified foundation

| Foundation | Status | Evidence and boundary |
| --- | --- | --- |
| Based validity-rollup decision | Complete as a decision | `docs/BASED_ZK_ROLLUP_ARCHITECTURE.md`; the rollup is not implemented. |
| 12-field Privacy V2 application ABI | Complete as an experimental interface | Python, Cairo, manifest, and Solidity share the count/order/types. This is not the complete strict-PQ verifier context. |
| RISC Zero commitment-envelope receipt | Qualified | Non-development receipt verified; 12 outputs matched Python; `1472.797364s` prove and `0.134665s` verify. It did not prove the complete claim. |
| Complete-claim RISC Zero profile | Stopped, not qualified | `191` segments, at least `199,229,440` cycles, and a `17.052680h` linear projection from 17 observed intervals. No complete receipt. |
| Existing Cairo/S-two statement | Qualified for validity and parity only | Verifier-clean off-chain proof: `89.0s`, `5,591,878` bytes, `43.5ms` verify, 12/12 Python outputs matched. It is not witness-hiding. |
| Six-column custom S-two AIR | Qualified prototype only | Fast decision/totals prototype. It omits claims, governed roots, nullifiers, the 12-field statement, witness hiding, and strict-PQ commitments. |
| `BL-PQ512-v1` architecture | Selected with current suite rejected | The application-specific M31 direction remains; R23 rejects QM31-only soundness and Blake2s-256, with a degree-16/SHA3-512 replacement still under review. |
| Synthetic foundation bundle | Completed as evidence only | The sealed R21 chain produced review inputs for S02-S06, S10-S11, A01-A06, P01-P02, and T01 and reran T14. It preserved the 12-field ABI and reported zero product semantic mismatches. It generated no proof, closed no package, left ten launch blockers open, and retained five Windows-only component gaps whose WSL equivalents passed. |
| R34 rollback regression inventory | Corrected Wave 1A semantic-reference collection and native convergence | 951 unique Python nodes plus 48 Rust rules, 48 RISC model, 26 S-two, 19 BL-PQ512 crypto/dimension Rust, 10 Cairo, and 23 Forge tests/declarations: 1,125 top-level entries. R30 remains the sealed Python supply-chain baseline; R34 is the semantic-reference rollback terminal. The 2026-07-21 executable-relation seal supersedes only its Wave 1A implementation status, not its historical counts. |

## Required order and hard dependency

```text
S03/S05/S06 application boundary
        |
        v
S07 budget + S08 rejection/envelope + S09 candidate families
        |
        v
pre-freeze A01/A05/A11/P05 normative design inputs
        |
        v
S02/S04/S10 reconciliation + S12 formal statement
        |
        +-------------------+-------------------+
        v                   v                   v
A01-A16 claim AIR     Z01-Z12 ZK core     P01-P06 PQ references
        \                   |                   /
         +------------------+------------------+
                            v
       R33 measured physical relation -> S09 concrete port instantiation
                            v
              A16 concrete AIR -> Z10 exact parameter revalidation
                            v
                      P07-P10 integration
                            v
                      T11-T14 convergence
                            v
                O01-O06/O12 release engineering
                            v
                 I01-I08 adapter integration
                            v
                 R01-R12 containing rollup
                            v
              DEPLOYMENT_READY_AUDIT_PENDING
                            v
        one independent Security Audit Gate (not counted)
                            v
              authorized operator activation
```

The A/P packages remain open while their normative choices feed the pre-code statement. This breaks
the old circular dependency without treating an unimplemented package as complete. Parameters are
validated twice: first against a conservative pre-code envelope, then against the measured A16 AIR
inside Z10. If `S07-S09` cannot establish the selected security target for the field, hash, PCS,
FRI, and Fiat-Shamir construction, cryptographic implementation, qualification, activation, and
security claims stop and the architecture returns to review. Synthetic nonactivating semantic,
reference, parser, vector, attack, and physical-AIR measurement work may continue only when it does
not select or imply those unresolved cryptographic choices and is explicitly recorded as
non-closing evidence for the review.

Package completion is counted from the **status column only**. An imperative such as "Complete the
review" in a work-description cell does not close that package. Every package whose status does not
begin with `Complete` remains in the outstanding count.

## Private-claim/PQ package inventory

### Specification and security freeze - 12 packages

| ID | Work package | Status and dependency |
| --- | --- | --- |
| S01 | Reconcile `AGENTS`, `STATE`, roadmap, backend decision, privacy statement, proving review, project map, and known issues. | Complete in this documentation update. Historical audit/provenance files remain unchanged. |
| S02 | Freeze the label and claim: "Privacy V2 12-field application ABI secured by `BL-PQ512-v1`." | Open; the application wording is frozen, but runtime/readiness configuration still identifies the legacy `CAIRO_STARK_NATIVE` lane and requires a coordinated implementation, configuration, mirror, and test migration. |
| S03 | Specify precisely that 12-field preservation means count/order/names/types and forbidden-field boundary, not obsolete formulas or denied-case KAT values. | Complete in `docs/BL_PQ512_FOUNDATION_SPEC.md`; exact manifest and structural tests preserve the boundary. |
| S04 | Specify the canonical authenticated proof sidecar and state plainly that it enlarges authenticated context outside `bytes32[12]`. | Open; R24 supplies an exact tested 744-byte local format candidate and R28 requalifies the strict nonactivating verifier/reference-state path, but suite/schema/artifact identity and payment qualification remain required. |
| S05 | Update the threat model for malicious provers, compromised workers, metadata inference, quantum attacks, parser disagreement, and governance. | Complete as a repository/application specification in `docs/BL_PQ512_THREAT_MODEL.md`; implementation packages and the final audit remain open. |
| S06 | Write a per-field security-notion table: equality, replay, target preimage, second preimage, arbitrary collision, hiding, or compatibility identifier. | Complete in `docs/BL_PQ512_FOUNDATION_SPEC.md`, including the attacker-influence, lifetime-target, authority, and consequence handoff to S07. |
| S07 | Produce the complete at-least-128-quantum-bit budget across AIR, FRI, PCS, transcript, roots, commitments, salts, encryption, and signatures. | Open. R24 corrects the worksheet as historical security-budget evidence. H4 fixes the executed GKR/Construction-8.2 dimensions, 6,086-round authenticated schedule, native mask counts, and dual-PQ public coin for one K128/K512 prototype. The complete composed theorem/error/abort ledger, semantic-STARK terms, state commitment, custody reductions, internal lifetime approval, and audit-ready evidence remain mandatory. |
| S08 | Prove or reject the M31 extension, challenge count, FRI parameters, grinding, and query count against `S07`. | Open. QM31/Blake2s/default Stwo parameters are conclusively rejected and their executable backend is removed. H4 exercises the selected degree-16 Fp16 GKR/Construction-8.2 lane with zero grinding credit, but H6 cannot select the suite until every final positive term and composition bound passes S07. |
| S09 | Select and pin the wide PCS/transcript/tree primitives, encodings, domain tags, and multi-target treatment. | Open. H4 pins and executes Construction 8.2 random-padded interleaved Reed--Solomon, SHA3-512 trees/transcript domains, exact accepted grammar, 6,086 authenticated rounds, and one/four-shard manifest binding. Durable PQ challenge custody, complete composition/simulator proof, final suite/module identities, reproducible release evidence, H5, and H6 remain open; `proofSuiteId=null`. |
| S10 | Specify genesis, migration, activation, rollback, epoch changes, and mixed-profile rejection. | Open; R24 supplies the lifecycle candidate and R28 requalifies frozen-registry, drift, replay, sequential-transition, and compare-and-swap reference work, but selected identities, durable authoritative state, payment semantics, migration, and final internal approval remain mandatory. |
| S11 | Pin upstream commits, compiler/toolchain versions, licenses, reproducible-build inputs, and SBOM. | Open; R30 closes the supported Python artifact boundary, while remaining compiler, standard-library, Cargo, Scarb, Foundry, OS/container, native-library, verifier, license, full-SBOM, and reproducible-release inputs remain open. |
| S12 | Freeze the complete formal statement, invariants, error taxonomy, and acceptance gates. | Open; R24 supplies a formal-statement draft and blocker ledger. R33 supplies historical host/reference evidence, and current Wave 1 seals the synthetic executable relation. S07-S11, complete low-degree application/hash/PCS expansion, native hiding, authoritative state, missing-data authority, and final internal review remain required. |

### Fixed-shape semantics and claim AIR - 16 packages

| ID | Work package | Status and dependency |
| --- | --- | --- |
| A01 | Freeze maximum batch, service-line, diagnosis, fact, policy-row, authorization, and tree-path capacities. | Open; R28 requalifies K128/K256/K512 calibration profiles but does not govern a release capacity. Internal business, performance, privacy, and security acceptance thresholds remain required. |
| A02 | Define a bounded, versioned witness schema with canonical serialization and rejection of extra/missing data. | Open; the Wave 1A structural decoder now executes the exact v0 schema subset, rejects duplicate/trailing/noninteger/extra/missing input, decodes multipart identifiers, and validates a full K128 fixture. The future transcript byte encoding and authenticated leaf/path decoding remain open. |
| A03 | Freeze canonical ordering, duplicate handling, text/number encoding, and range limits. | In progress overall; the sealed Wave 1A relation constrains fixed-slot positions, enabled counts, exact ordering/uniqueness, field-modulus, multipart, text, and money boundaries with cross-language KATs. Final proof/transcript parsers and deployment adapters remain Wave 1B/1C work. |
| A04 | Define enabled/dummy slots, cover values, domain separation, and no-real/dummy-collision rules. | In progress overall; Wave 1A seals fixed-length approval/denial/cover rows, v2 cover derivation, nonzero entropy, full-width collision rejection, exact domain separation, and authoritative dummy composition. Proof-byte equality and durable-state lifecycle tests remain downstream. |
| A05 | Define one trace schedule for approval, every denial, and padding with fixed rows, columns, queries, proof size, and operations. | In progress overall; Wave 1A now supplies executable witness-class-independent component traces and exact K128/K256/K512 global SHA3 call schedules. Wave 1B must derive fixed PCS/FRI queries and proof bytes from those measured dimensions. |
| A06 | Map all current adjudication failure gates and exact priority into the AIR. | In progress overall; Wave 1A seals all 13 raw gates, cover-effective gates, exact first-failure priority, candidate-allowed derivation, payment conservation, and authenticated source/oracle/policy links. Wave 1B must prove this relation. |
| A07 | Constrain canonical claim-source membership and authority. | In progress overall; Wave 1A seals the reversible 5,648-byte compact source, service ordering/uniqueness, dense SHA3 tree, streamed composition, and real ML-DSA-87 plus SLH-DSA-SHAKE-256f authority/epoch binding. Durable registries and live adapters remain Wave 1C work. |
| A08 | Constrain oracle facts, authorization validity, signer/epoch, and membership. | In progress overall; Wave 1A seals the packed oracle encoding, all fact/authorization links, execution/audit roots, streamed SHA3 schedule, and dual-PQ signer/epoch authority. Live oracle transport and operational governance remain Wave 1C work. |
| A09 | Constrain ruleset, fee policy, policy-row membership, and version authority. | In progress overall; Wave 1A seals the exact 13-gate taxonomy, governed ruleset/policy roots, one policy authentication per claim, version authority, and executable membership links. Durable registries remain Wave 1C work. |
| A10 | Constrain adjudication and exact first-failure ordering. | In progress overall; Wave 1A seals all derived gates, cover behavior, unique first failure, claimed outputs, u32 decomposition, fee arithmetic, conservation, and authenticated input links. Wave 1B must prove the sealed table. |
| A11 | Constrain integer money, overflow safety, value conservation, and the real payment/asset accumulator transition. | In progress overall; Wave 1A seals canonical values, checked carries, conservation, fixed four-upsert economics, endpoint multiproofs, sorted memory, payment keys/log, and global source binding. Durable state, rollover/migration, and recovery remain Wave 1C work. |
| A12 | Freeze nullifier semantics for approval, denial, duplicate attempts, corrections, revisions, and dummy slots. | Complete. `docs/BL_PQ512_A12_NULLIFIER_FREEZE.md` pins the exact real-attempt identity, original-only revision rule, cover context, byte grammar, sole authoritative SHA3-512 key, exact nonzero Stark252 compatibility projection, registry-lifetime pepper binding, atomic-migration-only rotation rule, and KATs. The composed host relation derives and verifies every key internally with `nullifier_derivations_authenticated=true`. This closes semantics, not A13/A15/A16 physical AIR or production state. |
| A13 | Implement the same number of authenticated state operations for every slot. | In progress overall; Wave 1A seals uniform replay, salt-use, four-upsert economic, and log schedules for approval, denial, and cover, including replay paths and the privacy-padded economic multiproof. Durable atomic state remains Wave 1C work. |
| A14 | Implement the ordered 12 compatibility outputs as projections of authoritative wide values. | In progress overall; Wave 1A seals all 384 ordered bytes, canonical fields, protocol v2, exact nonzero projections, and Rust/Python master/public parity. Historical Poseidon values remain adapter-only; proof and durable-state convergence remain downstream. |
| A15 | Implement SHA3-512 roots and master-commitment constraints over the same canonical records. | In progress overall; Wave 1A seals low-degree SHA3 expansion, full-width replay/payment/governance roots, salt-use, exact v2 master commitments, and global boundary links. Native hiding and authoritative durable-state parity remain Wave 1B/1C work. |
| A16 | Build the complete trace generator, AIR components, composition, prover/verifier harness, and constraint tests. | In progress overall; the executable Wave 1A trace generator, component AIRs, independent evaluators, lookup multisets, exact SHA3/projection constraints, global composition, Rust parity, and K128/K256/K512 schedules are sealed. The remaining portion of this package is the Wave 1B prover/verifier and proof-level attacks. |

### Heterogeneous semantic-STARK/hash-coprocessor and native hiding - 12 packages

| ID | Work package | Status and dependency |
| --- | --- | --- |
| Z01 | Create and pin an isolated Stwo fork and reproduce a verifier-clean non-ZK baseline. | Complete only as historical validity evidence from sealed R25. The incompatible executable fork is removed from the active tree; its exact source, lock, license, and rejection identities remain in `docs/REJECTED_ARCHITECTURES.md` and Git history. This is not a privacy, strict-PQ, full-claim, or production claim, fallback, or current dependency. |
| Z02 | Add OS-CSPRNG integration, deterministic-test-only separation, entropy failure handling, and zeroization. | Open. |
| Z03 | Mask every private semantic-AIR/bus polynomial and every Boolean-GKR/sumcheck message or terminal evaluation. | In progress. H4 implements and independently verifies 508 native GKR mask constraints per shard and the 73-word masked auxiliary plane. Complete semantic-AIR masking and the cross-module simulator remain open. |
| Z04 | Mask every auxiliary, interaction, lookup, LogUp, and permutation column, or eliminate those arguments. | Open. |
| Z05 | Randomize quotient/composition polynomials and every quotient split. | Open; R35 implements the canonical two-component kernel mask `left+phi*t,right-t`, freezes `h_q=n_oods+n_fri=927`, and matches the source split factor `phi(Q)=x([2^(L-1)]Q)` across Python/Rust. Final AIR-derived `L`, prover integration, full conditional simulator, and production randomness remain. |
| Z06 | Enforce disjoint trace and commitment/evaluation domains; prohibit unmasked openings. | Open. |
| Z07 | Inventory and mask every DEEP, FRI, neighboring-row, conjugate, bus, GKR/sumcheck, bridge, and implicit query. | In progress. H4 covers the selected GKR/sumcheck, five-claim bridge, PCS continuation, and accepted opening grammar. Semantic-STARK oracle coverage and the complete cross-module simulator remain open. |
| Z08 | Add the independent PCS batch mask committed before the batching challenge and preserve entropy through folding. | In progress. The retired Circle-FRI/BaseFold lane is not current architecture. H4 commits and verifies the selected Construction 8.2 random-padded auxiliary plane before dependent challenges; complete entropy provenance, zeroization, semantic-PCS composition, and simulator evidence remain open. |
| Z09 | Version and domain-separate the authoritative interactive public-coin transcript, binding all 12 fields and the full sidecar before challenges; keep Fiat-Shamir disabled. | In progress. H4 executes an exact 6,086-round transcript under ML-DSA-87 plus SLH-DSA-SHAKE-256f authentication and independently replays it. Durable challenge services, retry/crash governance, custody, and liveness evidence remain open. |
| Z10 | Qualify SHA3-512 commitments, Fp16 challenges, the semantic PCS, shared-bus hiding PCS, Boolean GKR, and query parameters. | Hard security gate, in progress. H4 freezes and independently verifies the current bus/circuit, Fp16 GKR, Construction 8.2 PCS, canonical grammar, K128/K512 resource use, and manifest binding. Gate 2E state composition, the complete theorem/simulator ledger, H5 repeated p95, H6 qualification, and the production verifier remain open. |
| Z11 | Produce a simulator/entropy analysis covering incompleteness, aborts, retries, malformed traces, and retained artifacts. | Open. H4 provides executable native masks and fail-closed transcript/worker behavior but does not by itself prove the complete interactive, semantic-STARK, state, abort, retry, and artifact-lifetime simulator. |
| Z12 | Update serialization and verification, fail closed on non-ZK mode, fuzz malformed proofs, and test repeated-proof unlinkability. | In progress. H4 accepts only the complete current grammar, independently verifies it, rejects 10/10 retired forms, and covers segment-32 Merkle mutations. Repeated-proof unlinkability, broad fuzzing, side channels, and production parser qualification remain open. |

### `BL-PQ512-v1` state, verifier, and custody integration - 12 packages

| ID | Work package | Status and dependency |
| --- | --- | --- |
| P01 | Define canonical SHA3-512 leaf, node, empty-root, length, type, position, and domain encodings; build reference implementations. | Open; Wave 1A extends the existing complete-tree reference through depth 16, adds a level-default sparse governed-map candidate, and pins K128 roots. Production domains/encodings still depend on S09 and complete review. |
| P02 | Derive legacy and wide trees independently from the same raw records; never hash only the legacy felt into the wide root. | Open overall; Wave 1A seals exact bulk/scalar legacy equivalence plus cross-language AIR-bound governed claim/oracle/policy/ruleset roots over shared raw records. Production state integration remains Wave 1C work. |
| P03 | Add authoritative 512-bit nullifier roots before/after and prove their transition. | Open; Wave 1A adds a synthetic depth-64 indexed predecessor/insertion multiproof and K128-plus-salt-use chain. A12 derivation is now authenticated and R33 assigns the transition exact physical-relation rows, but it is neither durable authoritative state nor a concrete STARK proof. |
| P04 | Add the wide governed-root registry, manifest/epoch binding, nullifier-key identifier, and PQ authorization. | Open; implement the provider-neutral registry, authorization policy, local governance simulator, and activation-config schema internally. Live signers and roots are activation inputs. |
| P05 | Add wide master batch/value commitments and fresh raw 512-bit secret salts. | Open overall; Wave 1A seals exact v2 master encodings and AIR links over all 12 fields, governance, replay, per-member/provider payment roots, slot nullifiers, raw 512-bit salt, and salt-use tag; obsolete aggregate payment roots are structurally absent. Native hiding and durable-state integration remain required. |
| P06 | Implement one canonical fixed-length proof-sidecar encoder/parser with no alternate encodings. | Open; R28 requalifies bounds, registry pins, and mutation coverage for the 744-byte candidate, which remains nonactivating and suite-unqualified. |
| P07 | Redesign the internal verifier interface to authenticate the exact 12 fields, sidecar, profile, schema, and artifact and return typed strong outputs. | Open; R28 requalifies a strict synthetic reference verifier returning canonical local typed outputs, not a STARK verifier or production interface. |
| P08 | Store and advance authoritative wide state atomically with the legacy compatibility root. | Open; R28 requalifies immutable snapshots, sequential batches, and lock/CAS serialization in memory, not durable authoritative state. |
| P09 | Implement genesis, migration, activation, upgrade, rollback, and recovery tests. | Open; depends on P03-P08. |
| P10 | Add stale-root, replay, mixed-profile, desynchronization, parser-differential, partial-update, and competing-before-state attacks. | Open; R28 requalifies candidate-sidecar mutation, replay, registry drift, capacity, sequential-transition, and same-CAS race tests, but complete proof/state attacks remain dependent on P03-P09. |
| P11 | Replace RSA-3072 witness wrapping with an approved hybrid post-quantum KEM/AES-256 construction and reject downgrade. | Open; freeze and implement the provider-neutral software/reference profile and KMS interface internally. Live KMS coordinates are activation inputs. |
| P12 | Add approved PQ signatures for governed roots, artifacts, and operational authorization plus HSM-facing abstractions. | Open; implement software/reference signing, provider-neutral HSM ports, downgrade rejection, rotation, and conformance tests internally. Live key handles and signers are activation inputs. |

### Cross-language, attack, leakage, and performance validation - 14 packages

| ID | Work package | Status and dependency |
| --- | --- | --- |
| T01 | Create one machine-readable vector schema covering private semantics, 12 compatibility outputs, and the wide sidecar. | Open; the foundation vector covers those three surfaces and R33 adds a machine-readable physical-dimension/program-commitment vector, but one final suite-qualified proof/vector schema still depends on current Wave 2. |
| T02 | Add approved-claim KATs across Python, Rust, Cairo, RISC Zero, custom AIR, proof, and verifier. | Open; current Wave 1 pins the Python K128 composed relation KAT, the prior Python/Rust/Cairo/RISC legacy differential still passes, and H4 supplies complete one-run K128/K512 prototype proofs. The final suite-qualified proof vectors and production verifier do not yet exist. |
| T03 | Add KATs for every denial code and exact reason priority. | Open; source count must be pinned. |
| T04 | Add dummy, padding, mixed, and all-denied fixed-shape KATs. | Open; current Wave 1 binds approval, denial, and cover under witness-class-independent component schedules, but final proof-byte/query equality awaits current Wave 2. |
| T05 | Add zero/minimum/maximum capacity and every boundary-value KAT. | Open. |
| T06 | Add duplicate, replay, retry, correction, revision, and nullifier KATs. | Open overall; A12 and the sealed physical AIR cover exact wide attempt/cover derivation, retry stability, duplicate/reserved/path mutation, pepper rotation, and original-only revision rejection cross-language. Correction/replacement/void authority, proof/verifier, and durable-state vectors remain open. |
| T07 | Add fabricated/stale/wrong policy, oracle, authorization, claim-source, signer, and epoch attacks. | Open; Wave 1A rejects governed source/oracle-economic/policy and exact membership-path forgeries in the Python reference; R33 adds payment-map and physical-slot/root forgeries. Stale signer/epoch and real-proof attacks remain open. |
| T08 | Add overflow, underflow, money mismatch, noncanonical field, serialization, and length attacks. | Open; Wave 1A covers duplicate-key, float, extra-field, count, chain, field-modulus, aggregate payment underflow/root mutation, and coercible V2 inputs. R33 adds payer-map underflow, duplicate obligation, and physical-program mutation rejection. Complete transcript and cross-language parser attacks remain open. |
| T09 | Add proof tampering, wrong profile/schema/artifact/domain/hash/root, and old-proof/new-input attacks. | Open; host/AIR, regression-kernel, and H4 proof/manifest/retired-format mutation coverage exists. Final suite grammar, sidecar, authoritative state, release artifact identity, and production verifier attacks remain open for full convergence. |
| T10 | Property-test and fuzz AIR constraints, proof parsers, verifiers, and wide-root/projection equivalence. | Open overall; current Wave 1 covers executable AIR mutations, projection arithmetic, sparse-tree order invariance, dense/sparse path mutation, deterministic program recomputation, and Rust parity. Final proof-parser/verifier fuzz convergence remains current Waves 2/3 work. |
| T11 | Scan proofs, logs, errors, crashes, and artifacts; test independent proofs of one witness for unlinkability. | Convergence gate. |
| T12 | Test trace size, proof size, queries, timing, cadence, root behavior, and failure behavior for inference. | Convergence gate; threshold frozen before run. |
| T13 | Measure exact stage time, rows/columns, memory, proof bytes, verifier time, and percentage attribution. | Measurement, not optimization. |
| T14 | Run every Python, attack, Rust, RISC model, custom-AIR, S-two, Cairo, Forge, clean-tree, and artifact gate. | Required after every convergence change. |

### Operations and release engineering - 7 packages

| ID | Work package | Status and dependency |
| --- | --- | --- |
| O01 | Implement and integrate a provider-neutral production KMS/HSM module supporting the selected PQ or hybrid algorithms. | Open; ship software/reference and standard provider interfaces plus conformance tests. Live provider enrollment is an activation input. |
| O02 | Enforce entropy health, salt/nonce reuse detection, zeroization, rotation, and destruction. | Open. |
| O03 | Build a hardened constant-time/no-co-tenant deployment profile and review secret-dependent branches, indices, allocation, and retries. | Open; containers/IaC, isolation controls, static/dynamic tests, and audit evidence are internal. Dedicated production capacity is an operator input. |
| O04 | Disable or secure swap, core dumps, crash files, temporary files, logs, backups, and diagnostics. | Open. |
| O05 | Implement fixed submission cadence, bounded queues, cover generation, and indistinguishable failure handling. | Open. |
| O06 | Add non-PHI monitoring, alerting, incident response, verifier rollback, and recovery drills. | Open. |
| O12 | Produce reproducible release evidence, pinned hashes, readback verification, deployment automation, and an explicit internal go/no-go. | Open; completion may produce `DEPLOYMENT_READY_AUDIT_PENDING`, never production authorization. |

### Government API and oracle adapters - 8 packages

| ID | Work package | Status and dependency |
| --- | --- | --- |
| I01 | Define the versioned provider-neutral adapter SDK, capability negotiation, canonical error model, and plugin isolation boundary. | Open; no core semantic code may depend on vendor response objects. |
| I02 | Implement government identity, tenant, authorization, mTLS/OAuth, PQ/hybrid transport-profile, and credential-injection ports with local simulators. | Open; live credentials are activation inputs. |
| I03 | Implement versioned claim-source and attachment adapters with exact-byte provenance, bounded streaming, content validation, and synthetic/sandbox fixtures. | Open. |
| I04 | Implement eligibility, coverage, enrollment, and provider-status adapters with freshness, signer, epoch, replay, and source-root binding. | Open. |
| I05 | Implement prior-authorization, diagnosis/procedure, and medical-document fact adapters without placing PHI in public logs, queues, or artifacts. | Open. |
| I06 | Implement fee-schedule, policy, ruleset, and governed-root adapters with deterministic normalization, dual control, version drift rejection, and rollback. | Open. |
| I07 | Implement payment, treasury, remittance, and reconciliation adapters with idempotency, amount conservation, failure recovery, and synthetic accounts. | Open; live accounts are activation inputs. |
| I08 | Build shared adapter conformance, contract, chaos, timeout/retry, circuit-breaker, audit-event, sandbox end-to-end, and hot-version migration tests. | Open; every production adapter must pass the same suite. |

### Containing based rollup and end-to-end deployment - 12 packages

| ID | Work package | Status and dependency |
| --- | --- | --- |
| R01 | Select, pin, vendor or reproducibly acquire, and license-inventory the exact EVM-compatible based-validity-rollup stack. | Open; the selection and integration are internal engineering decisions. |
| R02 | Build a deterministic local multi-node devnet and sandbox deployment with reproducible genesis, images, keys, and reset/recovery tooling. | Open. |
| R03 | Integrate the real claim-proof verifier and exact 12-field-plus-sidecar authenticated interface into L2 execution; remove trust-boundary mocks. | Open; depends on P07 and Z12. |
| R04 | Implement atomic L2 claim, nullifier, governed-root, payment, and authoritative wide-state transitions with replay and partial-update rejection. | Open; depends on P08-P10. |
| R05 | Implement and qualify the L2 state-transition prover that proves execution of the real claim verifier and settlement logic. | Open. |
| R06 | Implement and pin Ethereum L1 rollup verification, canonical state-root settlement, finalization, and verifier-artifact governance. | Open. |
| R07 | Implement based ordering, inclusion lists, L1 reorganization handling, duplicate/replay protection, and deterministic transaction derivation. | Open. |
| R08 | Implement non-PHI blob/calldata publication, availability sampling/monitoring, exact state reconstruction, retention, and corruption tests. | Open. |
| R09 | Implement bridge/escrow accounting, deposits, withdrawals, reconciliation, rate limits, and conservation tests without exposing private claim data. | Open. |
| R10 | Implement forced inclusion, censorship resistance, safe exits, liveness timeouts, and user recovery paths. | Open. |
| R11 | Implement governed upgrades, timelocks, emergency controls, rollback, disaster recovery, chain reorganization drills, and incompatible-version rejection. | Open. |
| R12 | Verify the synthetic claim-to-proof-to-L2-state-to-rollup-proof-to-Ethereum-finality path and produce one-command deployment/rollback evidence. | Open; depends on R01-R11 and all applicable core/adapter packages. |

## Final independent Security Audit Gate - not counted

The five former O07-O11 rows are audit workstreams, not engineering packages. They are executed as
one final gate after all 93 internal packages close:

1. AIR completeness and soundness;
2. witness hiding, selected PCS/GKR masking, authenticated interactive public coin, explicit
   absence of launch Fiat--Shamir/QROM credit, and strict-PQ analysis;
3. SHA3-512, dual-root/state, KEM/signature, and quantum-parameter review;
4. Rust/current proof core, CUDA untrusted-accelerator boundary, parser, verifier, contracts,
   rollup, bridge, and supply-chain security review;
5. privacy, side-channel, custody, operational review, and synthetic adversarial pilot.

Audit findings return to their owning package. No real PHI or payments are permitted until the gate
accepts the exact release identities and authorized operator activation is complete.

## Historical R24 parallel lanes - non-executable

This section records the 2026-07-16 allocation that led to later work. Its Stwo lane is removed and
rejected; it does not authorize restoring that backend or supersede the deterministic continuation
contract above.

After the R24 pre-implementation freeze is accepted, four local lanes may proceed concurrently as
synthetic, nonactivating implementation and measurement work while remaining separately reviewable.
This authorization is not an S07-S12 package pass. Trust-critical construction choices require
explicit internal review and evidence; they do not require an outside party to implement them.
The final independent audit validates the completed construction after the engineering packages
close.

| Lane | Packages | Count |
| --- | --- | ---: |
| Claim semantics and AIR | A01-A16 | 16 |
| S-two witness-hiding core | Z01-Z12 | 12 |
| PQ reference/state work before verifier integration | P01-P06 | 6 |
| Vector and attack scaffolding | T01-T10 | 10 |
| **Parallelizable implementation/scaffolding total** |  | **44** |

Parallelizable does not mean merge into one unreviewed patch. AIR semantics, PCS/FRI cryptography,
proof parsing/state, and independent validation must retain separate review boundaries.

### R25 local wave boundary

The owner authorized the next synthetic-only local wave on 2026-07-16. Its maximum safe combined
scope is:

- implement and measure the A01-A16 semantic and physical-AIR prototypes without presenting the
  provisional capacity or validity backend as production frozen;
- implement P01-P06 reference encodings, independent dual-root/state models, and the strict
  nonactivating sidecar/parser boundary;
- implement T01-T10 vectors, negative cases, property tests, parser/state attacks, and exact
  cross-language scaffolding wherever the corresponding semantic lane exists;
- reproduce and pin the Z01 validity baseline and implement Z02 entropy/fail-closed interfaces, plus
  static inventories and negative scaffolding for later Z work; and
- measure K128, K256, and K512 construction/AIR dimensions so the results can feed S08 and Z10
  revalidation.

R25 must leave `proofSuiteId=null`, `activationAllowed=false`, the current QM31/Blake2s/default suite
rejected, and all security/external-review gates open. It must stop rather than invent the
degree-16 tower, PCS/Circle-FRI parameters, QROM theorem/constants, native-hiding simulator, custody
profile, governance approval, or production verifier identity. Package status changes, if any, are
made only after terminal evidence is reconciled against each status cell; merely writing a
prototype does not close a package.

### R25 terminal result

The synthetic local wave is sealed at
`cache/implementation-runs/20260716T145548Z-local-implementation-wave-r25/terminal_manifest.json`
with status `PASS_LOCAL_NONACTIVATING_WITH_DECLARED_BLOCKERS`. It preserves the exact 12-field ABI,
keeps `proofSuiteId=null` and activation false, uses no real data or credentials, and does not run
the 124-proof campaign. Its durable result is:

- provisional K128/K256/K512 host semantics and equal logical schedules for approval, denial, and
  cover, with 13 exact ordered private gates, original-only attempt handling, checked money, and
  patient-responsibility-aware payable values;
- strict synthetic reference framing for payment state, a typed 257-operation K256 replay schedule,
  and an unambiguous split between the historical 434-byte internal state record and the sole
  744-byte candidate proof sidecar;
- a 20-case deterministic R25 corpus, all 8,191 nonempty denial subsets, and all 3,840 K256
  case/position placements, while proof/verifier lanes remain explicitly unavailable;
- 15 serial host-model measurements. The heaviest K512/full-capacity construction took
  `2.5877058s` and attributed `15.886984%` to fixture creation, `41.423886%` to logical trace,
  `42.246367%` to payment economics, and `0.442763%` to operation logging. Physical AIR rows and
  columns remain `null`, and these measurements generated no proof;
- one separate, narrow 1,024-row S-two validity proof with `0.118095s` proving and `0.000956s`
  verification, `witness_hiding=false`, and scope limited to aggregate decision/value conservation.
  No proof artifact was retained, and witness-hiding-required refused with
  `WITNESS_HIDING_UNAVAILABLE` before claim or trace allocation; and
- 770 unique Python nodes, 48 rules-Rust tests, 48 RISC model tests, 13 S-two tests, 10 Cairo
  declarations, and 23 Solidity tests, for 912 top-level tests/declarations with zero duplicate
  Python node IDs and zero cross-language product-semantic mismatches.

R25 closes only `Z01`. A01-A16, Z02-Z12, P01-P12, T01-T14, the remaining specification packages,
and all operations, adapter, rollup, and release packages retain their prior status. Host-model
speed is useful construction evidence, but it is not a complete-proof throughput measurement.

### R26 interrupted private-proof-engine foundation stage evidence

R26 is an authorized synthetic-only successor foundation wave recorded under
`cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/`, but it was interrupted
before final integrity reconciliation and terminal sealing. The directory contains a sealed initial
manifest and seven stage JSON records. It contains no `terminal_manifest.json` and no terminal seal;
searches found no moved copy or deletion record. R26 therefore supplies provisional recovery input,
not durable terminal qualification. It receives no package-closure credit. Its contemporaneous
mixed bookkeeping reported 5 of 78; under the corrected whole-product model that checkpoint was
**5 of 93 complete and 88 open**.

Its unsealed stage observations are:

- a narrow physical claim kernel covering 13-gate priority and limb payment conservation, measured
  over 51 profile/shape combinations with 267 trace columns, one interaction column, and 476
  constraints; every calibration proof verified and was discarded with zero proof artifacts;
- K128/K256/K512 average proving times of `0.051942850s`, `0.070609592s`, and `0.086222081s`, with
  maximum measured verification below `0.002576s` and maximum measured RSS of 7,252 KiB;
- an explicitly rejected security status: `witness_hiding=false`, the QM31/Blake2s/default path is
  not `BL-PQ512-v1`, fixture class is not proof-bound, and the kernel omits the 12-field statement,
  authenticated source/oracle/policy/nullifier state, SHA3-512 shadow state, and native hiding;
- strengthened synthetic candidate-sidecar, verifier, replay, payment, registry, and in-memory
  state references, including all-field mutations, bounded parsing/state, sequential transitions,
  and compare-and-swap race coverage; these are not a STARK verifier or authoritative state;
- a fresh hash-pinned exact differential in which all 12 public fields agree across Python,
  Rust/RISC Zero, and Cairo, and the separate Python/Cairo claim-semantics vector also agrees; and
- 801 unique Python nodes, 48 rules-Rust tests, 48 RISC model tests, 26 S-two tests, 10 Cairo
  declarations, and 23 Solidity tests: 956 top-level tests/declarations with zero duplicate Python
  node IDs and zero final semantic mismatch.

The first differential attempt failed before comparison because the execution mirror selected a
fresh Poseidon-helper target under an overlong workspace `TEMP` path. The first concurrent Cairo
build also panicked in a generated target with ``prelude` is not a core submodule``. The run stopped
and retained both failures. After explicit owner authorization, no source, manifest, dependency, or
tool version was changed: the existing run-owned Poseidon helper passed its exact known-answer test,
fresh serialized Cairo targets passed, and the complete differential and Cairo gates passed. These
are classified as build-path/concurrency defects, not discarded semantic failures.

The separate 1,024-claim legacy validity calibration reported `0.115831s` proving and `0.000197s`
verification with 4,084 KiB peak RSS. Its paired hiding-required command failed before allocation as
required. Neither this legacy proof nor the 51-proof kernel matrix is a complete private/PQ claim
proof. The 124-proof qualification campaign was not run because the cryptographic prerequisites do
not exist and the initial free-memory preflight was below 8 GiB.

R28 subsequently reproduced and terminally sealed the applicable observations, so they provide
partial evidence to S04, S10, S12, A01, A04-A06, A10-A11, A16, Z12, P03-P08, P10, and
T02-T10/T13-T14. Every one of those packages remains open under its existing closure conditions.

### R28/R29 terminal recovery and security evidence

R28 `20260718T134831Z-private-proof-engine-r28` terminally requalified the applicable R26 source
and gates without retroactively completing R26 or R27. It passed 956 unique top-level
tests/declarations across Python, Rust, RISC, S-two, Cairo, and Solidity; retained the rejected
validity-only calibration boundary and verified all 23 protected files unchanged. It closed no new
package; checkpoint progress was **5 of 93 complete and 88 open**.

R29 `20260718T154911Z-proving-evidence-r29` then closed the `R23-C02` software trust bypass at the
off-chain qualification boundary. A canonical SHA3-512 policy binds protected source, suite,
schema, tools, build, parameters, and distinct prover/verifier artifacts; legacy overrides and
child-authored equality are rejected. The source registry is intentionally
`DISABLED_NO_APPROVED_PQ_SUITE`, so no verifier, proof suite, settlement path, witness-hiding claim,
or strict-PQ proof was activated.

### R30 Python supply-chain remediation

R30 `20260718T170233Z-python-supply-chain-r30` closes validated finding `R25-C01` for the supported
CPython 3.14.4 Windows x86-64 and Linux x86-64/glibc >= 2.28 targets without upgrading the qualified
package graph. It supplies four complete platform/profile locks, 18 production and 26 development
packages, 52 reviewed platform artifact records with SHA-256 and SHA3-512, exact interpreter/pip
gates, an offline-only fail-closed installer, create-only install attestations, a reconciled
26-package SPDX SBOM, and a documented rotation contract. Fresh Windows and Linux environments
installed entirely from the reviewed wheelhouses and passed exact graph readback plus `pip check`.
A real reviewed wheel modified by one append was rejected before pip with exit `2`.

The locked Windows environment passed 690 non-attack tests plus 172 subtests, 149 attack tests plus
36 subtests, and the one exact Python/Rust/RISC/Cairo differential plus eight subtests. Linux passed
all 21 focused supply-chain tests, including the symlink bypass that the Windows account could not
construct. R30 changes no protected source and grants no roadmap package closure: it advances
S11/O12 evidence, while the wider compiler/OS/native/reproducible-build work and final audit remain
open. At that checkpoint the count stayed **5 of 93 complete and 88 open**.

The initial 2026-07-18 Wave 1A development slice advanced the first two continuation lanes without
claiming package closure. In addition to the structural witness and dual-root records, it recomputed
exact dense/sparse legacy/SHA3-512 paths, executes full-width depth-64 plus legacy depth-32 indexed
transitions, authenticates an aggregate payment state for every slot, and pins a K128 composed host
KAT across the ordered 12 fields and a wide batch commitment. At that historical slice the relation
still set `nullifier_derivations_authenticated=false` and `physical_air_constrained=false`; A12 and
R33 later remove those two local-foundation gaps without selecting a proof suite. The historical
slice created no proof artifact and kept activation false.

Before the S09 continuations, Wave 1A/A12 development convergence reported `739 passed`, `1 skipped`, `63 warnings`, and
`176` subtests in the non-attack lane; `1 passed` plus `8` subtests in the hash-pinned
Python/Rust/Cairo/RISC differential; and `152 passed`, `31 warnings`, plus `36` subtests in the
attack lane. The rules engine and RISC semantic model each pass 48 Rust tests. The one Windows skip
is the explicit account-capability case where the platform account cannot create a symlink. These
53 new top-level Python nodes raise the observed Python total from the sealed R30 baseline of 840 to
893 and the cross-surface inventory from 995 to 1,048. Only the exact A12 application-semantics
package closes; the remaining results are convergence evidence for still-open packages.

The A12 continuation then removes that opaque-nullifier boundary. Real attempts now derive only
from the governed source authority, source claim ID, and lifecycle tuple; mutable claim, retry,
batch, policy, oracle, payer/provider/member, domain/profile, and proof context is excluded. Covers
use a separately domain-separated profile/domain/epoch/batch/slot/fresh-nonce preimage. The legacy
Poseidon felt and strong SHA3-512 key are independently derived from the same exact byte preimage.
The verifier recomputes both lanes, the registry-lifetime pepper authority is commitment-bound, and
batch-level authority or pepper rotation fails closed pending a full atomic registry migration.
`nullifier_derivations_authenticated=true`, while `physical_air_constrained=false`,
`production_usable=false`, and `proofSuiteId=null` remain unchanged. This exact specification and
its application/Rust/Wave1A regression evidence close A12 only. Current progress is therefore
**6 of 93 complete and 87 open**.

The S09 construction continuation adds four non-attack and seven attack nodes for the pinned
degree-16 algebra and public-coin reference. Current collection is 745 non-attack plus 159 attack
nodes. After supplying the required run-owned RISC target and rebuilding the stale differential
binary offline/locked, reconciliation is `744 passed`, `1 skipped`, `63 warnings`, and `184`
subtests in the non-attack lane; `159 passed`, `31 warnings`, and `36` subtests in the attack lane;
and the exact Python/Rust/Cairo/RISC differential passes against a hash-pinned current binary. The
one skip is the explicit Windows account-capability symlink case. These results advance S08/S09
evidence but close no package, so the count remains **6 of 93 complete and 87 open**.

R32 then implements the next safe S09 substrate without editing vendored S-two. The isolated Rust
crate passes 17 field/Frobenius/encoding/sampler/SHA3-Merkle tests plus offline locked fmt, check,
`no_std` library check, and clippy gates. Its scalar benchmark reports about 1.05 million mixed Fp16
updates/second on this host, explicitly not proof throughput. The Python additions cover real
ML-DSA-87 and SLH-DSA-SHAKE-256f sign/verify, exact framing parity, four pre-burned attempts,
quarantine/no-reenrollment, parallel verification, header-first bounded proof parsing, and malformed
stream/section attacks. The existing public-coin OODS kind now aborts rather than use a generic Fp16
draw.

Independent math/integration review approves the tower as a nonactivating algebraic substrate but
stops numeric Circle-FRI selection: final AIR/table dimensions are theorem inputs, current S-two's
list-regime cross-domain layout and omitted degree correction cannot be promoted, and unrestricted
stereographic sampling misses the required Fp8 exclusion. The vendored repository's mandated
soundness-review skill/checklist was unavailable, so no soundness-critical vendor code was changed.
R32 closes no package; the count remains **6 of 93 complete and 87 open**.

The exact current R32 source collects 754 non-attack nodes, one cross-language differential, and
178 attack nodes. The broad lanes report `753 passed`, `1 skipped`, `63 warnings`, and `176`
subtests in `632.33s` for non-attack, plus `178 passed`, `31 warnings`, and `36` subtests in
`67.15s` for attack. The hash-pinned Python/Rust/Cairo/RISC differential and its eight subtests
passed in `12.58s` before its run-owned target was removed; every differential input remains
byte-unchanged. The focused S09 lane passes 40 tests, the Rust substrate passes 17 tests, and
protected paths plus vendored S-two remain byte-stable. These are nonactivating implementation and
regression results, not a completed proof suite.

R33 then completes the authorized Wave 1A semantic-reference boundary. The composed relation includes
domain-separated SHA3-512 authenticated benefit, provider-obligation, payer-reserve, and provider-
payable maps. The corrected reference uses depth-64 ordered positions with full-width keys/values;
approved slots update economic records, while denial and cover update four precommitted zero-valued
dummy leaves under the same operation schedule without allocating throwaway records. All slots
append a typed operation record. R33 also declared the following 16-table inventory
estimates. A later audit proved that the object does not contain an executable AIR, so these values
are historical only and are forbidden as theorem or performance inputs:

| Profile | Logical rows | Padded rows | Columns across tables | Constraints | Max degree | Message width | Commitment groups | Padded cells | Interface `D_eff` upper bound |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| K128 | 753,164 | 848,272 | 2,279 | 4,844 | 3 | 276 | 4 | 114,853,632 | 1,427,283,902,464 |
| K256 design point | 1,519,500 | 1,696,528 | 2,279 | 4,844 | 3 | 276 | 4 | 229,705,856 | 2,854,567,804,928 |
| K512 | 3,065,484 | 3,397,136 | 2,279 | 4,844 | 3 | 276 | 4 | 459,803,520 | 5,709,135,609,856 |

The metadata ledger has machine-readable KATs and Python/`no_std` Rust parity, but parity only proves
that both languages repeat the same declarations. It has no trace cells, constraint equations, or
independent evaluator and sets `physical_relation_constrained=false`. `proofSuiteId=null`, activation
and production use are false, no proof is generated, the rejected vendor kernel is untouched, and
the whole-product count remains **6 of 93 complete and 87 open**.

R34 corrects two model edges before Wave 1B begins. The initial provider-balance boundary now treats
only `None` as the empty default and rejects `[]`, `""`, `0`, and `False`. Member benefits now use a
typed SHA3-512 payer-authority/plan/benefit-period scope that is bound into the v2 composite state
and each member key; different scopes cannot alias and before/after scope drift is rejected. The old
R33 unscoped strong-batch KAT is retired rather than silently reused.

R35 begins Wave 1B from Git parent `4b7e023de7de71ac8c94dbb4d637f4d053bdd393`. Its exact
preimplementation rollback contains 609 files and 5,793,899 bytes; the Git archive SHA-256 is
`798ad10e3c5182afd7e3dec2072730c4951254c37df41c3e77630d18bbdff1aa`. The active implementation
currently has six unselected interface candidates with query counts
`926,567,463,421,402,393`, exact typed 22-round candidate schedules, mandatory pre-challenge FRI
batch-mask commitments, and a historical K512/blowup-2 trace-mask bound `h=4694`. The exact dense
SHA3 schedule requires that worksheet to be rerun before final parameter use. These results do not change
the package count or activation state. R35 subsequently adds the canonical quotient mask and
source-aligned split-factor rule plus a cross-language byte-oriented SHA3-512 AIR shape with a
1,632-column/1,024-lookup core and 1,704-column/1,096-first-round-lookup sponge envelope. Its new
The historical inventory first reconciled a K128 conservative host-verifier envelope to 401,275 AIR
calls, 1,205,016 permutations, and 28,920,384 Keccak round rows. That dynamic envelope is now
superseded for parameter use. The packed-oracle plus dense-claim topology is proved for all three
profiles at 14,322/28,644/57,288 permutations; fixed schedules for the
non-dense application ports, the
final split log-degree, lookup-interaction packing, and expanded FRI dimensions are still unselected.

## Current large run: Wave 2 strict-PQ proof and throughput recovery

Wave 2 consumes the sealed Wave 1 relation without reopening its meaning. Its controlling documents
are `docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md` and
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`. The architecture decision is now mandatory:
the M31 semantic AIR remains, but its six internal SHA3 tables leave the generic release PCS and
bind through one committed fixed-shape bus to an Fp16 Boolean GKR hash coprocessor. Hardware
acceleration follows the scalar circuit, theorem, masking, and independent-verifier gates.

The current nonactivating implementation blueprint is section 8.3 of
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`. It selects a seven-layer/B=16 GPU hash lane
running concurrently with a bounded CPU semantic-AIR lane and the Construction 8.2 random-padded
interleaved Reed--Solomon PCS. The exact GKR component sum plus segment-32 initial PCS mechanics is
28.3824358 seconds and leaves 1.6175642 seconds for every remaining complete-proof stage. This
is a historical pre-integration component subtotal, not the current complete-proof result or a
remaining-time budget. The exact ordered work is recorded in the dated corrections below, and the
2026-07-31 H4 section is the current proof-engine checkpoint.

Current Wave 2 gate status is:

| Gate | Current status |
| --- | --- |
| 2A | Open. H4 supplies exact one-run timing/resource evidence, but the frozen access/state census and qualification telemetry are not complete. |
| 2B | Open at the release boundary. The H4 grammar, parser, complete 20/36-tree formats, and retired-format rejection pass; final suite/state storage and parity evidence remain. |
| 2C | H3/H4 prototype sub-boundary passed; gate remains open for the complete simulator/security composition and suite-qualified evidence. |
| 2D | H4 functional and one-run 30/180-second prototype boundary passed; this does not close a package or the selected-state composition. |
| 2E | Open and next. Implement, select, and atomically bind the authenticated state/PQ-commitment plane before H5. |
| 2F | Open. After 2E, run H5's one warm-up plus ten unique batches per profile, close H6, and only then qualify K128/K512. |

All dated material below remains audit history. Where a historical paragraph says "current" or
"next," its statement is scoped to that dated checkpoint; this table and the newest dated section
supersede its execution status without rewriting its raw evidence.

Current evidence must be stated precisely:

- the hard reference-laptop latency requirements are input-to-independently-verified-output p95
  below 30 seconds for fixed-shape K128 with 100 live claims and below 180 seconds for fixed-shape
  K512 with 500 live claims. Qualification uses one uncounted warm-up and ten unique measured
  synthetic batches per profile with full masking, authenticated public coin, proof generation,
  parsing, and independent verification inside the timed boundary;

- the v1 dual-PQ-authenticated regression proof is **28,643,096 bytes**, with 945 queries and 15
  FRI layers. The authoritative `BLPQPRF2` grammar now encodes, decodes, and independently verifies
  one canonical global multiproof per layer plus canonical sibling and opened-row maps per
  cross-domain committed tree. The latest real run measured **6,755,933 bytes**, saving
  **21,887,163 bytes (76.41%)**
  while preserving all 945 authenticated query draws and opening values;
- two fresh worker runs took 50,070 ms and 47,178 ms. This is kernel evidence, not K128 throughput;
- the v1 FRI grammar carries 226,800 authentication-path digests and 28,350 opened extension values.
  For the exact same authenticated query list, a canonical global multiproof requires 8,118 path
  digests and 9,982 values. The implemented v2 result exceeds that payload-only projection slightly
  because it also removes repeated indices and metadata; exact v2 size varies with the authenticated
  random query set;
- the full K128 monolithic live lower bound is 9,034,606,313,472 bytes. The disk-streamed model instead
  requires 950,757,738,236 bytes of available scratch. The first number is rejected live memory, the
  second is scratch storage, and neither is proof size;
- replay plus payment state contribute 46,208 of K128's 46,858 SHA3 calls. SHA3/state topology and
  generic PCS expansion are therefore the dominant design targets;
- the 554-951 GB direct-SHA3-STARK paths are retired release architectures. Exact bit-packed storage
  for all 25 K128 Keccak state boundaries is 568,650,000 bytes; the `w=1,600` raw-state-layer
  baseline is 3,591,988,768 bytes and `w=2,048` is 4,407,205,408 bytes. Generated padded width and
  all overhead must be measured. Both raw all-Fp16 baselines leave bounded but unproven room under
  the current RAM limit before overhead. The hard qualification gate is no more than
  5,000,000,000 peak resident bytes,
  strictly below 5,000,000,000 scratch bytes, and no swap on the measured Dell G15 5535; these are
  qualification targets, not a completed K128 measurement.
- the new subfield-first streamed GKR candidate keeps full Fp16 verifier challenges but retains
  early bulk arrays in M31/small tower levels. At `w=1,600`, substituting four-byte M31 for only the
  two eligible early accumulator arrays projects the raw subtotal at 862,468,768 bytes instead of
  3,591,988,768. This excludes masks, cross terms, promoted tails, commitments, and allocator
  overhead and is not a completed resource measurement.
- specialized fixed-nonresidue tower multiplication is implemented in the scalar reference. It
  reduces an Fp16 multiplication from 192 to 81 M31 multiplications; all 95 Rust library tests and
  independent Python field vectors pass. Three-run scalar mixes improved 1.69x-1.80x across
  K128/K256/K512, but this receives no end-to-end proof-throughput credit.
- the certified hidden-state transition remains an unqualified architecture model, but its current
  K128 input is 782 Keccak permutations. Running the unchanged `B=8` packed Boolean first-round
  kernel at the generated 216-layer, 4,096-padded-width geometry processed 45,158,400 packed gates
  in a five-run median of 4.8015192 seconds (4.3895117-5.0110385 seconds), with 12,079,104 bytes
  measured peak resident memory and zero scratch. The output SHA3-512 digest was identical in every
  run. CPU/wall ratio 0.9767 and source inspection show that this control is single-threaded. This
  is phase-one kernel evidence, not a hidden-state theorem, complete proof, or K128 qualification.
  The deterministic indexed multicore implementation subsequently matched the serial polynomial
  and report at 1/2/4/8/16 workers. On a native release build, its five-run K128 phase-one median
  was 0.4439703 seconds at 16 workers versus 3.257033 seconds at one worker, a 7.336x reduction;
  maximum measured peak resident memory was 82,436,096 bytes and scratch was zero. All 30 scaling
  runs had one identical SHA3-512 output digest.
- grounding review found no exact hidden-state schema, transition manifest, hash-call schedule, or
  derivation artifact for the hard-coded 782/894 model inputs. The affine screen merely interpolates
  between them. They receive zero semantic or qualification credit, and no producer may label them
  certified until every trust boundary, call, and permutation is derived from the sealed relation.

Wave 2 has six closure gates:

1. **2A - cost truth and envelope freeze.** Exact v1 proof-section byte attribution is now emitted
   by the canonical encoder and verified on both regression proof paths. Complete independently
   scoped SHA3 inventory hardening and stage/resource telemetry; freeze K128/K512 workloads, the 30/180-second p95 latency gates,
   reference hardware classes, resource envelopes, repetition/variance rules, and the source-bound
   benchmark schema. Freeze the privacy-padded Claim
   Batch Access Manifest and publish the exact K128 state-call/conflict census. No estimated
   percentage may be promoted to a result. Before compiler expansion, cost K128/K512 anchors plus
   K1024/K2048 throughput-only projections from one explicit model; label every extrapolated point
   unqualified, preserve K128/K512 as the only release qualification profiles, and do not change
   the 256-bit security/encryption floor or 5,000,000,000-byte peak-RAM ceiling.
2. **2B - theorem-neutral grammar and storage de-duplication.** Build canonical adjacent-pair/global
   multiproofs, preserve all query multiplicities, remove permanent row-plus-column duplication,
   compare retained versus recomputed Merkle levels, and prove memory/disk/verifier byte parity.
   The authoritative v2 global-FRI and cross-domain sibling/value encoder/decoder/verifier plus
   both production-shaped workers are complete. Main, interaction, and composition disk oracles
   build tree leaves from bounded slabs across canonical columns without creating a full-domain row
   transpose, and reconstruct queried rows from those same columns. Cross-domain disk openings are
   deduplicated and batched through reused file handles. The deterministic public-geometry planner
   retains at most 256 MiB of levels per oracle or constructs the root and exact post-challenge
   frontier with a logarithmic hash stack and no level files; the root is rechecked and forced
   recomputation is byte-exact. Continue with remaining FFT/batching fusion, measured
   scratch/latency evidence, and the required memory-checking bake-off.
   Against the existing endpoint-multiproof/sorted-memory control, measure the admitted three-plane
   candidate: Shout-like read-only governed tables, Twist-like mutable replay/payment memory, and
   the unchanged Boolean GKR SHA3 plane. Preserve the exact SHA3-512 old/new-root bridge, CBAM,
   fixed padding, full-width keys/values, sequential equivalence, and atomic transcript.
3. **2C - shared-bus hash coprocessor.** Execute H0-H3: freeze the bus and byte-bit bridge, build the
   exact repeated Keccak circuit, retain an all-Fp16 interactive Boolean-GKR control, and implement
   the subfield-first streamed candidate with full Fp16 challenges. Then add native masking, hiding
   bus PCS, complete simulator, atomic verification, and independent verifier. Stop if promotion,
   masking, or streaming creates an unaccounted disclosure, any term misses 256 bits of
   cryptographic security/encryption, or the
   `<=5,000,000,000`-byte peak-RSS / `<5,000,000,000`-byte scratch / no-swap gate fails. The serial
   packed reducer remains the differential control;
   the deterministic indexed multicore reducer with private worker accumulators and canonical merge
   order now has byte-identical output and measured wall/CPU/RAM/scratch evidence at 1/2/4/8/16
   workers. Retain that evidence as the control while integrating later GKR rounds. The exact
   adjacent-layer sparse reduction, degree-21 packed-to-sparse bridge, fixed 128-pack group-identity
   wiring, and all nine Keccak layer kinds now have focused CPU algebra controls. The graph-free
   repeated-layer reducer now also combines multiple expanded group/wire
   claims and carries the two terminal claims backward across nonlinear adjacent layers with a
   fresh packed bridge. The focused chain boundary passes 3/3 tests, including exact final input
   openings and tampered-claim rejection; this is algebra evidence, not native hiding or a complete
   216-layer proof. The exact 24-round builder now emits all 216 adjacent layers and rejects any
   width discontinuity; its independent all-round wiring parity test passes. On the reference
   laptop, the optimized CPU control for one full-width Chi layer
   measured 15.4004847 seconds
   proving, 0.8374154 seconds independently verifying, 185,368,576-byte peak RSS, and zero scratch
   at both the 782-permutation K128 shape and the identical fixed 128-pack K512 shape. This rejects
   CPU-only sparse rounds as the qualification lane; it does not reject the GKR construction.
   The RTX 4060 remains an untrusted prover coprocessor behind the Rust verifier. A full-width
   409,600-term screen matched all 48 coefficients in every one of 36 sequential round messages,
   including the challenge-dependent factor/input folds and both terminal values. Warm complete
   layer boundaries, including device-to-host round messages and host coordinate checks, measured
   0.7671116 seconds for K128 and 0.7402966 seconds for K512 with 133,278,080 device bytes. The
   CUDA runtime remains an out-of-tree screen, not a selected backend or qualification result.
   The Rust side now has a fixed binary structure-of-arrays protocol, canonical coordinate and
   geometry bounds, message-before-challenge state enforcement, per-step timeout, multi-session
   process limit, and fail-closed cleanup. Its focused malformed/stalled worker controls pass 2/2.
   A real RTX 4060 K128 session matched every CPU round and terminal with SHA3-512 digest
   `8fe8e12d8160fc21300d7f0503f886fa3f005dc80e82f50abce2b96283f2661fa4983da45b26e32c5152bc6cd6b461ce14de1f1d49ce72648f396c6e0491f8ac`;
   K512 likewise matched with digest
   `f171b4941556ae094f33678a7bec574b760135ecfc9fbbf63e678b220212973353a4cf28bc88ab7ced9a8938ec22b349755de02491384c0a48858b7b5bddec9c`.
   Bulk layout reduced K128 from 4.9230036 to 2.3792617 seconds; the latest SHA3-validated warm-PTX
   run was 2.3454522 seconds. Its internal split was 0.3786699 seconds request parsing,
   0.7733006 context/PTX load, 0.0647099 device setup, and 0.6504006 interactive rounds. These
   honest boundaries expose setup costs omitted by the earlier 0.767-second kernel screen.
   The worker now keeps one bounded context alive across dependent sessions and frees every
   session allocation. Direct input decoding plus a device-side 48-coordinate reduction lowered
   the five-session worst-Chi boundary to 0.68720424 seconds per session with the same digest.
   Three-session measurements for layer ordinals 0-8 were respectively 0.578229033,
   0.618900400, 0.544006266, 0.611497900, 0.511578666, 0.699488833, 0.819741000,
   0.580185466, and 0.485333633 seconds. Their exact sum projects 130.775104728 seconds
   for 24 rounds before hiding/PCS, so the host-fed layout still fails K128 and receives no
   qualification credit. The compact follow-up now generates and retains all 216 bit-packed
   boundaries in 0.0519751-0.0667099 seconds and 61,341,696 bytes at 782 active permutations;
   the fixed 1,024-lane shape measured 0.0695777-0.0726403 seconds and 75,497,472 bytes. It sends
   bit-packed inputs plus compact equality factors and public base wiring, derives the repeated
   Fp16 term table on the untrusted GPU, and leaves the Rust interactive verifier authoritative.
   This reduced worst-Chi request parsing from roughly 0.33-0.35 seconds to
   0.0134-0.0182 seconds while preserving the exact CPU proof digest. A single persistent
   216-session chain then measured **33.2458796 seconds for K128/782** and
   **30.6132468 seconds for K512/894**. Every round and terminal matched its independently
   generated CPU reference; the proof-stream SHA3-512 digests were respectively
   `4a2f2873fa5f651d07cf7e8b12b796510790995edd9f64025c3c5a10de9d42196f5d64d2882cb04836caa547096e2c916c1eeea602d45145bd35749be09a6065`
   and
   `2572dea0c0d591a1e8a609d0c32cbc4e054a9a1301c79707c260edd17beaf1947d9386285ebb83f8547e0c38ed37b4068454a76d7e00df2a6e301659fceb328b`.
   Observed host peaks, including the deliberately retained CPU reference fixtures, were
   466,448,384 and 465,846,272 bytes. This clears the isolated GKR-stage latency/resource gate;
   it is not complete-proof qualification. The compact two-claim GPU derivation now independently
   matches the CPU proof, and the repeated-layer verifier accepts nonzero masked messages plus the
   exact terminal correction. Persistent 216-session nonzero-mask runs measured
   **30.9336388 seconds for K128/782** and **31.0194826 seconds for K512/894**, with exact
   masked-transcript digests
   `cd63ef80748613a0afba446d9eea9a1065e4bd8c87e03124cf4975c7059fd1669757198ad2c960dc1dd83868a3444de7e73982e47c54eec06790232a14c3c548`
   and
   `dfdb61b009b36a4c46b9e9bc5581425c7d2e3b2838ba10a7a91fdeb731791a5e3212b699e11960f9b6551015d124a852fe460d807b1276666a671fd9404ac4ca`.
   These deterministic masks are algebra/performance controls, not a simulator or production
   secret-randomness claim. Integration review subsequently found that these two chain harnesses
   used independent per-layer fixtures, so they retain GPU algebra value but no coherent-chain
   credit. The replacement harness carries two claims through all 216 evaluated boundaries,
   verifies every masked layer in Rust, checks exact CPU/GPU packed-polynomial parity, and binds the
   final openings to the raw `2^21` Boolean input table. It measured **42.8253168 seconds for
   K128/782** and **44.1804650 seconds for K512/894**, with combined host peaks of 3,241,021,440
   and 3,240,488,960 bytes. Both passed coherent-chain, native-mask, polynomial-parity, and
   GKR-to-PCS-opening checks. The resulting exact PCS inputs produced independently verified
   17,524,065-byte proofs: K128 production/internal verification took 20.7792086 seconds and
   independent verification 0.2230094 seconds; K512 took 20.7974853 and 0.2428490 seconds. Core
   scratch was 2,818,577,696 bytes. The joined harness now consumes the existing external
   64-byte-secret/64-byte-session boundary for domain-separated GKR and PCS masks and rejects a
   wrong-length input. Its challenges and initial Keccak states remain deterministic synthetic
   controls, so this is not authenticated public coin, the certified hidden-state relation, an
   atomic complete proof, simulator qualification, or K128/K512 qualification.
   Under the owner's former strict sub-3,000,000,000-byte peak-resident limit, both 3.24 GB
   coherent-chain runs are retained only as correctness/parity evidence and are not
   resource-qualified.
   A subsequent binding audit found that the measured initial output claim covered the complete
   final Keccak state and was prover-computed rather than authenticated by the semantic digest bus.
   The replacement interface now requires one canonical external Keccak-state file, rejects
   nonzero inactive lanes and padding wires, and fixes output wire variables 9 and 10 to zero so
   the claim covers exactly the first 512 SHA3-512 digest bits. Its two focused boundary tests pass.
   The preceding timings remain internal GKR algebra evidence only; fresh runs and exact
   message/digest-bus commitment openings are mandatory.
   Next package and identity-pin the currently out-of-tree CUDA/NVRTC
   adapter and execute the PCS-selection dependency below before completing H3. The present Circle
   PCS cannot authenticate an arbitrary multilinear GKR terminal opening merely because both use
   Fp16; treating a Circle evaluation as that opening is forbidden. Require complete proof bytes,
   independent verification,
   RAM/VRAM/scratch, simulator, and cleanup evidence. The earlier packed-accumulator KAT and
   21.9701 ms K128 measurement remain part of that required end-to-end boundary.
4. **2D - heterogeneous prover convergence.** Execute H4: remove SHA3 internal tables only from the
   release PCS, bind every sealed Wave 1 hash port to the shared bus, and prove the unchanged
   semantic AIR, bus, and coprocessor atomically. Finish scalar/SIMD/optional-GPU parity, grammar,
   parameter ledger, and leakage tests. Grinding receives zero credit.
5. **2E - committed sparse-state and PQ commitment selection.** Execute
   `docs/BL_PQ512_COMMITTED_SPARSE_STATE_PLAN.md`: retain the existing SHA3 endpoint-multiproof/
   sorted-memory path as the control; build persistent-memory, transparent-dictionary,
   touched-projection, and compact memory-consistency candidates behind one modular interface; and
   compare Jindo-style, Grand-Danois/Hachi-style, RoKoko-style, and transparent hash/code
   commitment paths. Preserve the sealed relation, fixed shape, exact 12-field ABI, SHA3-512
   authoritative state identifier, interactive dual-PQ public coin, native hiding, atomic
   verification, the 256-bit security/encryption floor, and migration/rollback safety. Select only
   from complete
   reference-laptop evidence; retaining the control with recorded rejection reasons is a valid
   gate result, but skipping the bake-off is not.
   **Ordering dependency:** execute the common multilinear PCS interface and S3 commitment
   prototypes immediately after the H2 GKR controls and before H3 bus-PCS composition. State
   relation prototypes C1-C4 remain in 2E; this dependency does not authorize a state redesign.
   H3 may consume only a backend that passes the exact field, 256-bit security/encryption, hiding,
   adaptive-opening,
   authenticated-public-coin, grammar, and independent-verifier gates. This resolves the prior
   circular order in which H3 required a hiding multilinear PCS before 2E selected one.
   The first bounded screen is complete. Released Hachi is rejected for H3 because it has no
   hiding/evaluation-hiding theorem and only 120/128-bit concrete parameters. Released Jindo is
   rejected because its otherwise relevant hiding and knowledge theorems are instantiated only at
   128-bit MSIS/MLWE security with a roughly 255-bit challenge field, SHAKE128 Fiat--Shamir, and no
   reproducible 256-bit parameter derivation. A 440-bit field alone does not upgrade its lattice
   assumptions. The sole active implementation candidate is therefore the transparent
   unique-decoding WHIR/BaseFold-style lane; conjectured-list-decoding parameters receive no
   credit. The retained legacy control used 392-bit query soundness and therefore 473 queries at
   rate `1/8`; this exceeds the current 256-bit floor but does not independently qualify the suite.
   The pinned upstream
   wrong-field/non-ZK 250-bit speed control at `2^21` coefficients measured 6.517491215 seconds
   prover, 0.027126784 seconds verifier, 1,051,504 proof bytes, and 1,415,452 KiB peak RSS. Its
   exact 392-bit configuration failed closed on the upstream approximately 254-bit field. Port only
   the required core to native Fp16, SHA3-512, authenticated interaction, forbidden grinding, and
   native hiding; do not vendor the prototype or activate it from the scaled 10.22-second/1.65-MB
   projection. The common packed-Boolean terminal evaluator now passes 5/5 focused tests and its
   five-run release medians at the shared `2^21` padded table are 0.6290573 seconds for K128/782
   and 0.6506879 seconds for K512/894; maximum observed process working set was 71,778,304 bytes
   and scratch was zero. This is an interface measurement, not an opening proof. A separate pinned
   upstream ZK speed control at 250 bits measured 27.8 seconds prover, 8,262.9 KiB proof,
   1.7 seconds verifier, and 1,647,972 KiB peak RSS, but it warned that internal
   5.37-16.40-bit PoW slots exceeded the requested zero-PoW policy. Its exact 392-bit invocation
   failed closed. The upstream wrapper is therefore measured only as a hiding-cost rejection
   control and receives no qualification or implementation credit. The then-primary zkDeepFold
   control geometry was corrected to `2^22` coefficients and a rate-`1/8` `2^25` codeword, plus a
   minimal 18-variable auxiliary mask polynomial. The exact-order Fp16 root, scalar NTT, packed
   interpolation, and geometry pass 9/9 focused tests. The RTX 4060 matches the CPU NTT at `2^10`
   and closed-form production endpoints at `2^25`; its five-run production NTT median is
   0.7593406 seconds using 2,281,701,376 device bytes. A 2 GiB device-to-host copy measured
   0.1700202 seconds. The 16-worker SHA3-512 Merkle builder is byte-identical to serial and reduced
   the full `2^21`-leaf commitment from 24.2561595 seconds serial to a five-run 3.0140306-second
   median, with 2,589,167,616-byte measured peak RSS and zero scratch. Continue with interactive
   folds, native-hiding simulation, proof grammar, and independent verification. All 22 pre-final
   fold-layer SHA3-512 roots have a five-run 6.9376924-second median. The canonical fixed-shape
   473-query leaf/frontier geometry currently contributes 16,729,216 bytes before round
   polynomials, auxiliary batching, and framing. These front-end controls do not select or qualify
   the PCS. The scalar multiplicative fold matches independently folded coefficients. The RTX 4060
   then completed all 22 folds in a five-run 0.0306100-second median and matched the closed-form
   final hidden-polynomial evaluation; the fold-capable allocation is 2,415,919,104 device bytes
   plus 1,408 challenge bytes.
   The native Fp16 lane now implements the exact three-claim different-size batch-sumcheck prelude,
   hidden and auxiliary polynomial algebra, a fixed fail-closed state machine, canonical
   verifier-derived query multiproofs, strict codecs, and an independent algebra verifier. Lifting
   the 18-variable auxiliary polynomial through the four ignored prefix variables uses an explicit
   `2^-4` normalization; this preserves the intended `r^2 c_aux` simulator term at the 22-variable
   batch boundary. Exact encoded sizes are 4,747 bytes for the prelude, 17,519,307 bytes for the
   fold/query segment, and 17,524,065 bytes combined. The parallel full-shape prelude control
   measured 4.1560122 seconds, 827,203,584 peak working-set bytes, and zero scratch, with byte-stable
   SHA3-512 output matching scalar execution. The focused multilinear suite passes 26/26, including
   above-threshold scalar/threaded primitive parity. These results do not select or qualify the PCS:
   connect production entropy and authenticated public-coin receipts, construct the committed
   layers and openings, finish the hiding/composition proof, emit complete proof bytes, and
   independently verify fresh K128/K512 proofs before closing 2E or entering 2F qualification.
   The full production-geometry PCS control constructs all 22 main openings plus the auxiliary
   opening, encodes 17,524,065 bytes, decodes them, and independently verifies them. The earlier
   18.1039767-second single-opening control is superseded: packed GKR ends in two claims and one
   degree-7 shard query. The corrected boundary binds both values with one authenticated mix and
   inserts the exact eight Lagrange shard weights between low wire and high group bits. It measured
   23.8805969 seconds for production plus internal verification, 0.2366557 seconds for independent
   decoded verification, 29.4130358 seconds total wall, 5,062,144,000 peak working-set bytes, and
   2,281,701,376 bounded input scratch bytes. Proof SHA3-512 was
   `25bb3d9c9b7b47a6ad0de599fdd7a2f53d696605085bd194ec09be455e6e9f1a6ea67594c9f92271a7ffd6e81a683fffd4c21104e0859c6b1ceac639d2556ef3`.
   The focused PCS suite passes 27/27 and the exact bridge passes 1/1. This remains
   completed-challenge synthetic control evidence; production entropy, authenticated interaction,
   the complete simulator/theorem ledger, and a coherent atomic GKR integration remained open.
   This zkDeepFold/BaseFold lane was superseded on 2026-07-29 by the selected Construction 8.2
   random-padded interleaved-RS PCS. Its modules and measurements are retained only as
   differential, resource-rejection, and regression evidence; they are not part of the active
   proof grammar, simulator argument, or qualification path.
   Its 5,062,144,000-byte peak also rejects that realization under the current RAM gate while
   preserving its algebra, proof-codec, and independent-verifier evidence.
   The semantic before/after extension now commits the input and full 1,600-bit output tables
   separately, releases their batching coefficient only after both roots, and shares the remaining
   21 FRI layers and one auxiliary hiding polynomial. Its fixed proof is 19,164,129 bytes rather
   than two independent 17.5-MiB proofs. A fresh 706-lane all-active semantic control independently
   recomputed every SHA3-512 digest, matched every GKR output state, and produced GKR stream digest
   `97fcfcdc39d12b60d9c454dc807c11a5461a3d9fbe020be6bea49d22097102d20ad7265ef42cb05e124041a8a711a396ef64b03a76297475c7b83d838b0d7cb8`.
   The independently decoded dual PCS verified proof SHA3-512
   `9395738ee7832ed09af614d013f45be34404d042498bea633ba267392eff02c6520b0bc83fce6825b0ef3adcbcfe6b620fb988e7b006fefd802dbae672006d23`.
   Parallelizing the formerly serial 33,554,432-element main-polynomial mix reduced dual
   fold/query time from 36.8921490 to 20.5858011 seconds without changing any proof byte, root, or
   opening. The latest PCS control measured 11.6279412 seconds load, 1.6752554 seconds hypercube
   conversion, 20.5858011 seconds fold/query, 8.6369783 seconds hiding prelude, 0.2097692 seconds
   internal verification, and 0.2453969 seconds independent decoded verification. A monitored
   predecessor measured 7,456,407,552 peak resident bytes and no 2-GiB codeword scratch files.
   Persistent CUDA buffers and device-generated sumcheck factors preserve the GKR digest and reduce
   the 216-session worker's post-compilation steady sum from 36.3096988 to 26.5765611 seconds.
   The predecessor remains historical performance/correctness evidence, not a feasible release
   realization under the current RAM gate.
   The GKR internal challenge path now uses two isolated reverse-SHA3-512-chain services with one
   native ML-DSA-87 or FIPS-205 SLH-DSA-SHAKE-256f signature per chain head. The Rust coordinator
   verifies both heads, requests every reveal only after its prover polynomial, checks all chain
   steps, and retains a strict replay bundle. A fresh 706-lane semantic control authenticated all
   216 packed-bridge, 7,920 sparse-sumcheck, and 215 inter-layer-mixing challenges: 8,351 rounds
   total. It independently decoded and replayed the 4,964,557-byte evidence bundle, whose SHA3-512
   was `1bc162abd35064827a55f6e32a9cb8adde8ac8bd90253367f2162d83129bc620ce92f748524dd8035e6de33d254b07b28c74d2453435626c95d767c7b115e063`.
   The complete run took 31.1512499 seconds and independently verified every GKR layer; its
   proof-stream SHA3-512 was
   `f74551cda4fe6b8a580c38bb09c4532872ddee3fa541650ca90241a83f10b9f8d95304931c68bde029254cb048aed6536c19e4357d711d69f6726f4db2d5c04f`.
   A cross-implementation gate rejected the old `pqcrypto` SPHINCS+ binding as
   `SignatureInvalid(SlhDsaShake256f)` under the native FIPS-205 verifier; it was not admitted into
   the new chain path. The native dual-PQ path and signature-tamper rejection pass.
   That GKR-only control deliberately prints `authenticated_public_coin=false`: its initial output
   query is not yet connected to the same authenticated session as the downstream PCS.
   The dual-boundary PCS now has a stateful publish-before-challenge implementation. It fixes the
   three initial roots before setup coins, fixes all three hiding bindings before the batch coin,
   publishes each hiding quadratic together with the corresponding FRI commitment before accepting
   their shared fold coin, fixes terminal values before the query coin, derives all 473 positions
   from that authenticated Fp16 coin with SHA3-512, and then recomputes every opening. The
   independent verifier reconstructs every canonical prover message from the decoded proof,
   independently replays the 30-round dual-PQ coin bundle, re-derives the query positions, and
   rejects any root, terminal, message, challenge, or opening mismatch. The first full-shape launch
   was correctly withheld because Windows reported only 3.96 GB free physical memory, below the
   mandatory 8 GB preflight floor; this is implemented but not measured proof evidence and does not
   close 2E or 2F. Rust passes 180/180 and the focused legacy semantic/392-bit Python test set
   remains 45/45; its name records the historical parameterization rather than the current floor.
   The coherent GKR executable now also has a complete-session path. It fixes the input, output, and
   fresh secret auxiliary roots first; derives the initial 20-element output query only afterward;
   carries one native dual-PQ chain through the 8,351 GKR rounds and 30 PCS rounds; and independently
   replays the initial query, canonical PCS messages, proof bytes, and final root. The PCS accepts
   the already-prepared commitments, so the roots used before the GKR query cannot be substituted
   before PCS. Two production codewords were generated on the RTX 4060 and passed their endpoint
   KATs; their SHA3-512 digests are
   `6ad7e56495706b429ce9f0aa2dd18e2b9c35feb85eeb09efe9eff6ad5b7a15931cdade4eb80d72dd3b2c3f7eed36d325e842f66f22149438a796743f25094df2`
   and
   `8f7458f29f9e23bfd007c16b496d71bfe232df1a79c2630b8c6b0204964f31ced3e8325335669646ddabf71ff29867cfa206fc8c43021d4543e5d61797b7ac66`.
   The bounded scratch set is 4,294,967,296 bytes. A complete launch remains withheld: the latest
   Windows sample reported only 3,388.456960 MB decimal free, below the then-current
   8,589.934592 MB decimal launch floor.
   No timing, memory, proof, or qualification claim is taken from the unrun path.
   That 8,589.934592 MB decimal free-RAM floor was conservative host headroom for a complete
   campaign, not the
   permitted prover peak: every qualifying process must still remain strictly below
   5,000,000,000 resident bytes.
   A first-principles leakage audit also found that the current masked GKR is not yet
   zero-knowledge. Its round quadratics are uniform over the correct two-dimensional affine space,
   but each signed layer transcript still publishes the two raw terminal evaluations. Downstream
   PCS cannot hide values already published. Masking those values with an unconstrained correction
   would destroy soundness. The required repair is a committed low-degree-extension construction,
   not another ad hoc scalar mask: Libra Construction 1 commits the sumcheck mask before the
   verifier's random linear-combination challenge, and Construction 2 masks each layer polynomial
   with a vanishing term and a constant-size bivariate degree-two polynomial. Blind Ledger must
   map those commitments and openings to the transparent Fp16/SHA3-512 PCS, retain authenticated
   interaction, and prove the exact simulator and soundness composition before the complete path
   may run for qualification.
   The compact Hint-MLWE hybrid is no longer an admitted state candidate at the screened
   `m1=13/16/24/32` ranks. The governed CBAM contains 641 K128 and 2,561 K512 ordered-map
   operations. An optimistic information-capacity lower bound that includes only each complete
   512-bit key and complete before/after values requires 15,384 coefficients (`m1>=61`) for K128
   and 61,464 (`m1>=241`) for K512, versus 8,192 coefficients at the largest screened `m1=32`.
   Paths, leaf links, indices, ordering/range auxiliaries, claim semantics, and hiding are omitted,
   so this is a strict rejection of the screened compact options rather than a final relation-size
   estimate or a rejection of every future lattice parameter set.
   The former 782/894 hidden-state workload pair is also superseded as an
   ungrounded model. Replacing only replay/payment state leaves 16,830 K128 and 67,098 K512
   permutations. Directly authenticating governed private input-column commitments can remove the
   claim-truth hashes while the proof still executes adjudication, but sealed deterministic A12
   nullifiers remain mandatory. The resulting pre-bridge lower bounds are 706 K128 and 2,674
   K512 permutations; random public nullifiers receive no credit because they change governed
   attempt identity. Fresh coherent controls measured 44.9440978 seconds for 706 permutations and
   three K512 shards of 1,024/1,024/626 at 41.3578001, 42.2068589, and 41.2675587 seconds,
   respectively (124.8322177 seconds total). Every shard passed Rust verification, CPU/GPU packed
   polynomial equality, native nonzero masks, and GKR-to-PCS input-opening equality. These remain
   zero-input performance controls with unauthenticated challenges, not semantic or qualification
   proofs.
   The file-backed K128 PCS continuation independently verified in 26.4 seconds after an
   18.1593535-second 2-GiB codeword write. A direct CUDA-to-Rust pipe removed that scratch file and
   reproduced the identical PCS proof SHA3-512
   `0e9f116d0949114c596a825bc78f3f49dcf9b24c57e53456e76a914d9140c64f6676b3411624285f5e97964d92e43ca1bd2fc78fcb8c42934d3028391db80f4c`;
   its codeword/auxiliary load took 4.5526592 seconds and complete PCS wall was 27.8 seconds.
   Scheduling the input commitment before the dependent GKR rounds remains required to overlap
   this work; sequential addition would miss K128.
   C1 sparse persistent memory is rejected at the frozen capacity. Its primary construction uses
   four length-`C` initial/final address/value vectors and estimates `7C+51A` verifier constraints.
   Blind Ledger's four `2^24` lanes give `C=2^26`, 17,179,869,184 raw Fp16 vector bytes, and
   469,794,739/469,892,659 constraints for K128/K512. The raw vectors already exceed the
   5,000,000,000-byte laptop gate, before its published forbidden Pedersen/Groth compiler, native
   hiding, or atomic
   composition.
   The remaining C2-C4 screens also fail closed on the current backend. IRONDICT's sparse update
   needs a homomorphic PCS; the active transparent PCS instead needs sixteen `2^22` shards for one
   `2^26` state polynomial. The strict RAM limit permits only one 2-GiB codeword at a time even
   while optimistically omitting every other allocation, giving GKR-plus-PCS floors of
   350.5187922 seconds for K128 and 430.4069121 seconds for K512, before zerocheck or hiding.
   Touched-projection RAM is not admitted: the primary near-linear-size branch has
   `O~(k^2)` projection work, giving 107,709,988,864 and 1,719,329,357,824 quadratic-scale
   operations at the minimum 512-bit-per-access K128/K512 schedules, while the alternative uses a
   superlinear global encoding and neither branch has concrete laptop parameters. Two-Shuffles
   requires full setup and teardown because Blind Ledger has `T << n`; its exact two-Fp16-value
   formula `5T+3n` gives 201,329,797/201,339,397 input gates and an optimistic
   935.8225016-second current-PCS floor. These are candidate-selection results, not permission to weaken capacity,
   hiding, state identity, or latency. The released Hachi and Jindo paths remain rejected by the
   earlier theorem/parameter gates; a new homomorphic backend receives no credit without a complete
   256-bit security/encryption hiding and knowledge proof plus measured laptop evidence.
6. **2F - complete K128/K512 strict-PQ latency proof.** Generate and independently verify complete
   fixed-shape K128 and K512 proofs, pass simulator/leakage/attack gates, and pass p95 below 30
   seconds for K128/100-live and below 180 seconds for K512/500-live over the frozen ten-run method.
   Record exact bytes, time, memory, scratch, I/O, and cleanup. `proofSuiteId` stays null and
   activation stays false until every required downstream identity and state gate also passes.
   Larger-batch measurements may inform throughput and latency policy only after these two profiles
   pass; they cannot substitute for either qualification run.

The frontier addendum now supplies the mandatory 2E candidate-selection workstream. CBAM,
deterministic conflict scheduling, state-call attribution, and formal hooks belong inside 2A-2F.
Wave 2 selects the state/commitment candidate from exact proof evidence; Wave 3 performs durable
deployment migration, custody, rollback, and operational convergence. WHIR/STIR or another outer-proof candidate is measured
only after the primary path completes K128 and must pass the identical PQ, hiding, theorem,
independent-verifier, and laptop gates.

VEIL is an H3 hiding-wrapper bake-off only; it does not supersede the current masking/simulator
work until the exact Fp16 interactive-public-coin composition passes. Neo/SuperNeo remain
post-K128 aggregation research. Hachi may run before K128 only as an isolated commitment candidate
inside 2E; aggregation use remains post-K128. Every lattice path requires its own Module-SIS/Ajtai
security ledger. None changes the six gates, package count, suite status, or Wave 2 completion criteria.

The 2026-07-26 preliminary mechanism-first frontier screen adds four coupled prototype lanes
without selecting them. Its 32 linked papers plus six named rejects are a breadth inventory, not
38 complete technical reviews or proof of frontier saturation; exact new-versus-repeated counts
remain unproved because the earlier pass did not preserve a deduplicated source ledger:

1. derive and KAT a Keccak-specific GKR layer manifest against the sealed 216-layer FIPS 202
   control, using only the specialized algebra and not Keccacheck's Groth16 wrapper;
2. derive the exact M31-to-Fp16 tower and implement tower/small-value/many-factor sumcheck as a
   parallel control, with no lost full-Fp16 challenge entropy and a complete recomputed error ledger;
3. implement one single-owner persistent worker that streams bounded GKR/code tiles, retains only
   compact authenticated messages/frontiers, and measures host RSS, device allocation, transfer,
   scratch, swap, stalls, and cleanup; and
4. bake off the current WHIR/BaseFold-style PCS against a jagged unequal-height layout and only
   proved-distance ERA/Block-Accumulate candidates that first pass exact Fp16 unique-decoding and
   256-bit security screens, then apply an independently reviewed native-ZK compiler to the winning
   complete
   transcript.

These lanes must be evaluated as one pipeline. A code with faster encoding can increase query
count, proof bytes, SHA3-512 hashing, or decoder memory; a jagged commitment adds algebra while
removing padding; persistent GPU state can reduce host RSS only if it does not create duplicate
host/device owners; and code switching expands both the soundness ledger and simulator surface.
The current 35.1399522-second K128 GKR control plus 27.8-second PCS control gives a
62.9399522-second sequential illustration, not a complete proof, and the current PCS exceeds the
new RAM gate. K512's three GKR controls total 124.8322177 seconds; adding three 27.8-second PCS
controls gives a 208.2322177-second scaling illustration, not measured K512 evidence. The combined
program must eliminate full-resident codewords and reduce total work; scheduling alone cannot
qualify either profile.

Wave 3 then finishes authoritative verifier/state/custody integration. The full T14 matrix and
124-proof campaign run against that exact Wave 3 candidate, not against a kernel. Waves 4-6 then
build adapters/operations, the containing rollup, and the one-command release candidate before the
uncounted independent audit.

Throughput selection is not “first version that fits.” After immutable security/privacy constraints
and the deployment envelope are frozen, all plausible safe candidates are measured, dominated
designs are rejected, and the highest-throughput feasible point is selected. Proof compression,
trace generation, a scalar field benchmark, or a toy proof cannot substitute for fixed-batch
end-to-end claims per second.

### 2026-07-29 Wave 2 PCS architecture correction

This subsection supersedes the BaseFold/26.859692-second/6,241-round Wave 2 checkpoint above where
they conflict. It does not close a gate or change `proofSuiteId=null`.

H3 now selects the nonactivating Construction 8.2 interleaved Reed--Solomon attempt in
`BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md` section 8.3. The exact main instance is length
131,072 with 65,536 message values, 2,048 random-padding values, proximity `5/32`, and 1,600
queries. Each of nine auxiliary instances is length 8,192 with 2,048 message values, 1,218
random-padding values, proximity `1/5`, and 1,218 queries. The current composed PCS ledger is
392.108419573 bits. Construction 7.2/8.2 hiding mechanics, conditioned sumcheck sampling, full
query derivation, and production query-view streaming pass an executable offline audit gate.

The selected proof topology remains the exact seven-layer/B=16 relay-free GKR with a concurrent
bounded semantic-AIR lane. Its measured component sum is 24.7958928 seconds. Segment-32 initial PCS
mechanics measured 3.586543 seconds at 191.533 MB host memory, 1,612.185152 MB device memory, and
0.000000 MB scratch. This creates a 28.3824358-second partial path and a 1.6175642-second unresolved
complete-proof envelope. Segment 16 remains a lower-memory fallback but is not the sub-30
throughput candidate.

The selected segment-32 launch preflight is architecture-specific. It requires at least
`max(1,000 MB decimal, 2 * latest measured complete-proof peak RSS)` free physical host memory,
at least 2,000 MB decimal free device memory, no competing build/prover process, and zero swap
growth during the run. Until a complete-proof peak exists, the 1,000 MB floor governs; the measured
191.533 MB component host peak is the supporting calibration. This replaces the earlier blanket
8,589.934592 MB decimal free-host-RAM floor for this selected bounded architecture only. It did not
relax the immutable 5,000,000,000-byte RSS, strictly-below-5,000,000,000-byte scratch, and no-swap
acceptance gates. The former 200 MB host and 1,800 MB device component-selection targets are
historical evidence only.

The corrected authenticated-public-coin schedule is 6,086 rounds: 6,072 GKR
transcript challenges, one independent post-GKR mask-functional batching challenge, and 13
downstream PCS rounds. The earlier 5,822 count omitted the theorem-required terminal-extension and
multi-claim reduction challenges as well as the independent aggregate mask-opening challenge. The
standalone PCS integration uses 14 rounds because it must authenticate the complete GKR claims
boundary before the claim, coordinate, source/mask, nine word, base, and query challenges. The real
dual-PQ coordinator executed and independently replayed all 6,086 exact-output descriptors in 1.551632 seconds
with a 4.494103 MB bundle. The complete producer has not yet occupied every descriptor, so this is
coordinator evidence, not complete-proof run evidence.

The first real relay-free producer now executes the exact all-zero sixteen-shard KAT without
materializing 8,192 duplicate groups. It proves and independently verifies all 24 Keccak rounds,
168 seven-layer DAG reductions, 95 claim mixes, 168 packed bridges, 2,184 group rounds, 3,456 wire
rounds, 168 terminal rounds, and the final four input claims through the live dual-PQ coordinator.
An externally sampled run used 52.457472 MB peak host memory, 0.000000 MB GPU memory, and completed
the 6,072 raw GKR rounds plus independent coin and algebra replay in 13.484277 seconds. Native
Libra masking, its aggregate opening, and PCS remain required before this becomes complete-proof
evidence.

The corrected selected Libra commitment uses 23,544 coefficients padded to 32,768. Its conservative
linear-observation budget is 7,728 bridge, 14,304 sumcheck, 672 layer, and one aggregate-opening
rank, totaling 22,705 below the 32,768 committed random coefficients. Of 5,808 sumcheck variables,
2,520 publish cubic messages and 3,288 publish quadratic messages.

The authoritative GKR/PCS boundary is now implemented in Rust:

- one output and four relay-free input claims are required, each with 24 coordinates, a packed
  value, a shard query, and sixteen component evaluations;
- low 16 coordinates select an RS-message coefficient and high eight select one of 256 messages on
  one of the two source boundaries;
- Rust derives five claim powers, sixteen coordinate-map coefficients, the initial target, compact
  quadratic chain, and independent final answer target;
- CUDA extracts the five-by-512-by-sixteen component rows directly from one live tile per public
  boundary and retains 12.058624 MB for 80 claim-component source/relation states plus 64 committed
  GKR-mask states, with no full source replay;
- the stream releases no word challenge until the committed claims, row parameters, and current
  quadratic message are fixed;
- claim, component, point, coefficient, dimension, zero-challenge, target, scale, ordinal, replay,
  Merkle, answer-code, and spot-check mutations fail closed; and
- Python no longer supplies an authoritative PCS target, row parameters, or final answer target.

H3 remains **open**, but the deterministic fixture boundary is gone: the real B=16 GKR producer,
64-codeword GKR-mask commitment, 73-word PCS answer, and exact same-chain coordinator are attached
and host verified. The sealed semantic AIR/bus, retry-stable atomic state/proof receipt, complete
cryptographic composition, and complete K128 verifier have not yet completed one independently
verified CUDA session together.

This 2026-07-29 remaining-work list and driver incident are closed historical evidence. The final
2026-07-31 H4 section supersedes them: clean-reset K128/K512 prototypes passed, and the active order
is Gate 2E state binding, composition/simulator closure, H5 repeated p95, then H6 qualification.
The current driver-integrity rule still requires a fresh System-log audit before every production
CUDA proof.

## Internally finishable build and external boundary

All **93 counted packages are internal engineering work**. None requires an outside person to
choose the construction, write code, supply a production-only dependency, or complete validation.
Trust-critical choices still require explicit internal review, exact evidence, and hard stop gates.

The only outside assurance dependency is the final independent Security Audit Gate. Government
endpoints and credentials, live oracle signers, HSM key handles, governance signers, payment
accounts, and legal authorization are activation inputs. Each has a local/sandbox implementation
and conformance contract so its absence never blocks building the deployment-ready candidate.

## Completed synthetic foundation bundle - 17 items

The explicitly authorized isolated synthetic-only foundation run completed on 2026-07-15 and
produced evidence for:

- S02-S06: profile wording, ABI/security-context distinction, threat model, and per-field notions;
- S10-S11: migration/rollback draft and toolchain/SBOM inventory;
- A01-A06: bounded-shape proposal, witness/encoding/dummy schedules, and current failure-gate map;
- P01-P02: SHA3-512 canonical reference encodings and dual-tree reference construction;
- T01: versioned vector schema;
- T14: complete current baseline regression rerun.

This is **17 bundle items**: 16 draft/reference/prototype items plus the `T14` regression rerun.
The immutable result is
`cache/foundation-runs/20260715T073140Z-foundation17-r21/terminal_manifest.json`, sealed by SHA-256
`7bcaf24f33130aea258a58286b8121c4c19a89d7f2c9c691a77ca633cc69006f`. The accepted chain contains
the synthetic foundation vector, raw gate output, source/tool/lock hashes, cross-language parity,
and the complete current regression baseline. At the time it sealed, the run closed none of these
packages: `S01` was the only closed package and 77 remained open. The later R23 security-freeze
reconciliation used that foundation evidence to close the application-specification packages S03,
S05, and S06; it did not retroactively change the R21 evidence or close a cryptographic package.

The bundle was permitted to produce review-ready drafts, isolated reference code, synthetic
vectors, and raw test evidence. Its evidence must not be used to:

- finalize S07-S09 cryptographic parameters;
- edit the S-two PCS/FRI implementation;
- edit live nullifier or settlement state;
- migrate any verifier state;
- install or upgrade dependencies;
- use real data;
- claim ZK, strict-PQ security, production readiness, or package closure without morning review.

The run was configured to stop on the first cross-language mismatch, source/hash drift, ops-mirror
mismatch, failed test, non-synthetic input, dependency problem, or unexpected artifact. It did not
auto-fix a trust-critical failure.

## R23 security-freeze reconciliation

The 2026-07-15 R23 run is the durable research and specification checkpoint for S03 and S05-S09.
Its controlling record is `docs/BL_PQ512_SECURITY_FREEZE.md`; its repository threat model is
`docs/BL_PQ512_THREAT_MODEL.md`; its hardening artifacts are under
`docs/security-freeze/BL-PQ512-v1/`. R23:

- closes S03, S05, and S06 as application-specification packages only;
- preserves the exact 12-field ABI and keeps every one-felt value non-authoritative for strict-PQ
  collision security;
- rejects the current QM31/Blake2s/default S-two configuration and rejects extra queries or grinding
  as repairs for its independent field/hash ceilings;
- records M31 degree-16 challenges plus full-width SHA3-512 as a conditional lead, not a selected or
  externally approved suite;
- keeps S02, S04, and S07-S12 open, including the canonical-operations, payment-state, formal-
  statement, reproducible-build, exact-AIR, QROM, native-hiding, and independent-review gates; and
- corrects the dependency order so pre-freeze A/P design inputs feed S04/S10/S12 and measured A16
  dimensions trigger exact Z10 parameter revalidation.

The sealed R23 run record belongs under
`cache/security-freeze-runs/20260715T202353Z-security-freeze-r23/`. Its terminal manifest is valid
only after every required regression, attack, Rust, Cairo, Solidity, privacy, release-builder,
source-integrity, rollback-integrity, and artifact-integrity gate has passed.

The accepted R23 qualification rerun passed those executable gates with zero product-semantic
mismatches: 538 non-attack Python tests, one exact Python/Rust/Cairo/RISC differential, 94 attack
tests, 44 rules-engine Rust tests on both platforms, 45 RISC-model tests on both platforms, four
S-two prototype tests on both platforms, the Poseidon known-answer test, nine Cairo declarations,
and 23 Forge tests. It also passed syntax/dependency hygiene and clean/negative privacy and release-
builder controls. It generated zero proofs. The 124-proof campaign was not run because the complete
AIR, native hiding layer, and reviewed proof suite do not exist and R23 rejects the current suite;
running that campaign would violate S07-S09 rather than advance the roadmap.

## R24 continuation through S12

R24 is controlled by `docs/BL_PQ512_S07_S12_PREIMPLEMENTATION_FREEZE.md`, the machine-readable
`docs/bl_pq512_suite_candidate_v1.json`, its strict schema, and the synthetic candidate sidecar
reference/attack tests. Its accepted synthetic-only executable matrix is recorded in
`cache/specification-runs/20260715T221859Z-s07-s12-freeze-r24/terminal_manifest.json` with an
adjacent SHA-256 seal. Failed and superseded attempts remain preserved as lineage. This is a sealed
local specification/reference qualification run, not proof-system or production qualification. R24:

- corrects the R23 algebra/query worksheet and preserves the hard rejection of the current
  QM31/Blake2s/default S-two configuration;
- freezes the candidate encoding, domain registry, modular suite structure, downgrade behavior,
  744-byte sidecar, and lifecycle without inventing a proof suite ID;
- makes the K256/full-512-nullifier/composite-payment/original-attempt-only normative inputs to the
  formal statement explicit;
- writes the complete S12 relation, invariant, error-family, and activation-gate draft;
- discovers and repairs the current cross-language money ceiling and decimal-rounding divergence,
  fee-policy and legacy-binding coercion, RISC zero-value parity, and the actual batch prefilter/root
  privacy path, with exact boundary regressions in Python, Rust, Cairo, and the RISC semantic model;
  and
- records the still-open missing-data, payment-state, revision, physical-AIR, QROM, native-hiding,
  supply-chain, and external-review blockers.

R24 closes no additional package. That is deliberate: a local draft cannot substitute for a final
AIR, complete proof implementation, payment-state parity, reproducible artifacts, or independent
cryptographic review. It generates no proof and does not make the 124-proof campaign runnable.

## Historical R24 final qualification design - non-executable

This pre-H4 design retains useful negative categories and campaign rationale. Do not run its
RISC Zero or Stwo commands: both executable backends are removed. The current Gate 2E/H5/H6
sequence, active source inventory, and 22-launch H5 matrix above supersede it.

After A01-A16, Z01-Z12, P01-P10, and T01-T10 exist and have been reviewed, one orchestrator should
run the following sequential stages. Builds and proofs are serialized; Cargo, Scarb, Forge, and
proof jobs must not compete for shared caches.

1. Verify workspace, reviewed rollback/source hashes, out-of-tree artifact root, clean source
   manifest, and canonical `ops` mirror.
2. Record pinned toolchains/dependencies and build sequentially, offline/locked, into unique reviewed
   target directories.
3. Enforce the exact 12-field shape, canonical felts, fixed sidecar, forbidden-output scan, and
   profile/schema/verifier pins.
4. Run exact-byte parity across Python, Rust, Cairo, RISC Zero, S-two, and the verifier.
5. Run SHA3-512 leaf/tree/governance/nullifier/master-commitment/sequence KATs everywhere applicable.
6. Run the 20 required negative categories listed below.
7. Run static ZK coverage, entropy, mask-reuse, development-mode, and parameter-assertion gates.
8. Generate and verify the 124-proof synthetic campaign.
9. Check repeat-proof unlinkability and exact fixed shape across the campaign.
10. Run independent-verifier readback, malformed-proof fuzzing, and atomic state simulations.
11. Run every regression suite and security gate.
12. Rehash source, scan all artifacts/logs, reconcile every count, and emit the raw terminal manifest.

The 16 automated gate categories are: rollback/hash snapshot, toolchain fingerprint, ops-mirror
parity, Python, separate attack rerun, Rust rules, RISC semantic model, AIR constraints, S-two ZK,
Cairo, Forge, differential KATs, fuzz/adversarial tests, privacy/artifact scans,
fixed-shape/performance profiling, and one complete synthetic proof campaign with independent
verification.

### Required 20 negative categories

1. Fabricated eligibility.
2. Suspended provider.
3. Missing prior authorization.
4. Changed fee row.
5. Stale legacy root.
6. Stale strong root.
7. Corrupted legacy path.
8. Corrupted strong path.
9. Payment mismatch.
10. Noncanonical felt.
11. Wrong settlement domain.
12. Wrong profile.
13. Wrong schema.
14. Old proof with changed private input.
15. Malformed or trailing sidecar data.
16. Legacy/wide witness divergence.
17. Reused attempt nullifier.
18. Reused cover nullifier.
19. Sequence replay.
20. Proof or verifier identity mutation.

### Required 124-proof campaign

- 30 proofs: one approved real claim plus `K-1` padding slots.
- 30 proofs: one denied real claim plus `K-1` padding slots.
- 30 proofs: one approved, one denied, remaining padding.
- 30 proofs: full-capacity mixed decisions with no padding.
- 4 edge proofs: all approved, all denied, maximum valid boundaries, and corrected-attempt
  transition.

Each repeated class uses identical synthetic semantics and fresh masking randomness. All intentional
public/strong state outputs must match within the repeated class; all 30 proof hashes and hiding
commitments must be pairwise distinct. Trace dimensions, oracle counts, FRI/query counts, proof and
sidecar lengths, and state-operation counts must match across all four main classes.

| Measured complete proof time | 124 serialized proofs |
| ---: | ---: |
| 30 seconds | 1 hour 2 minutes |
| 60 seconds | 2 hours 4 minutes |
| 90 seconds | 3 hours 6 minutes |
| 180 seconds | 6 hours 12 minutes |
| 300 seconds | 10 hours 20 minutes |

After the first four class proofs, project the remaining runtime against the frozen sleep-window
budget and stop cleanly if it will exceed the budget. Never fall back to the approximately 17-hour
complete RISC Zero path.

## Latest observed regression inventory

Current source collection on 2026-07-31 found 1,093 ordinary Python tests before the known missing
canonical `../ops` tree stopped collection, plus 396 attack tests collected cleanly. The missing
sibling is an environment/layout fail-closed condition, not a test deletion or semantic failure.
The active BL-PQ512 Rust library contains 264 tests with zero ignored after removing two
BaseFold-only self-tests with their isolated retired module; every remaining binary and doc-test
group passed in the H4 closure, and strict Clippy had zero warnings.

The standalone RISC Zero and Stwo backend-specific suites were removed with their unselected source
trees. Replacement architecture tests require those trees to remain absent and pin their exact
rejection identities in `REJECTED_ARCHITECTURES.md`. The V1-layer compaction equivalence, exact
two-claim GKR/PCS differential, and retired-format rejection KAT remain because they protect current
migration and fail-closed invariants. No active acceptance test was removed.

Older R26--R34 counts and timings are historical run evidence in `STATE.md`; they are not current
suite inventory. Successor manifests must record current collected, passed, failed, skipped, and
warning counts without treating a setup failure as semantic evidence.

## Historical Wave 2 checkpoint: bounded real-GKR/PCS join (2026-07-29)

The active join is no longer an 8 GB host design. It uses 12.058624 MB compact row state,
2.097152 MB GKR-mask coefficients, 33.554432 MB GKR-mask codewords, 15.258752 MB complete
auxiliary coefficients, and 38.273024 MB complete auxiliary codewords. The host v4 target KAT
peaked at 77.070 MB. A failed monitored complete launch reached 317.542400 MB process-tree RSS and
855.638016 MB GPU use before a driver fault; those are diagnostic lower bounds, not qualification
peaks.

The real 168-layer masked producer, 64-codeword GKR-mask commitment, 73-word answer, exact
6,086-round coordinator, independent target/answer verifier, and 20-tree segment-32 multiproof
verifier are implemented and pass their host/static gates. The complete proof remains open because
the first CUDA launch failed closed and produced `nvlddmkm` Event 153. The duplicated component
evaluation was replaced with one live-tile evaluation per boundary plus a public-message-only
broadcast. The same-chain mutation KAT also rejects a forged GKR-terminal digest before releasing
the base-mask challenge. After a clean driver reset, rerun exactly one externally monitored
segment-32 complete proof; require input-to-independent-verification below 30 seconds and every
printed verifier gate true. Do not infer completion from the host controls or failed-run memory
samples.

## Overnight preflight resource gate

The planning host was observed with 16 logical processors and 16,438.987325 MB decimal total RAM.
Earlier high-residency campaign planning used a blanket 8,589.935 MB decimal free-memory floor.
That historical floor is superseded for the selected bounded segment-32 architecture by its
measured host/device geometry; it is not a prover-memory allowance.

Preflight requires:

- an exclusive host;
- for the selected segment-32 architecture, at least
  `max(1,000 MB decimal, 2 * latest measured complete-proof peak RSS)` free physical host memory;
- with the current 706.523136 MB external process-tree peak, the host admission floor is
  1,413.046272 MB;
- at least 3,500 MB decimal free device memory, covering the current 2,770.337792 MB sampled
  K512 total residency with bounded operating headroom;
- an explicitly authorized out-of-source artifact directory with sufficient measured headroom;
- no competing Cargo, Scarb, Forge, prover, or antivirus scan on the target caches;
- a frozen wall-time budget and first-four-proof calibration stop; and
- external monitoring that rejects swap growth or either immutable 5,000,000,000-byte host/scratch
  gate.

This architecture-specific free-RAM admission floor is separate from the stricter process envelope.
The historical 200 MB host and 1,800 MB device component-selection targets are retained as dated
evidence, not current acceptance gates: the complete atomic process necessarily includes the
parent, native verifier, active worker, and one latency-required standby. The owner's later resource
direction explicitly accepts a low-hundreds-of-MB internal host image and bounded sub-5-GB device
residency. This does not change the 5,000,000,000-byte peak-resident limit, strictly-below-
5,000,000,000-byte scratch limit, or no-swap requirement.

## Overnight STOP conditions

Stop immediately, retain raw evidence, and make no automatic fix when:

1. Workspace, rollback, source, ops mirror, toolchain, dependency, or manifest hashes differ.
2. No authorized out-of-source artifact directory exists.
3. Input fails the strict synthetic allowlist or resembles real PHI.
4. Resource or projected wall-time budget fails.
5. The external ABI differs from the exact ordered 12 fields.
6. Python, Rust, Cairo, RISC Zero, S-two, or verifier output differs on any applicable byte, hash,
   root, decision, amount, commitment, rejection reason, or transition.
7. Agreement requires normalization, truncation, reordering, modulo repair, or ignored fields.
8. Any strong value derives only from a legacy felt rather than raw records or wide children.
9. Legacy and strong paths are not constrained to the same record and operation sequence.
10. Any committed oracle lacks masking, randomness is reused/deterministic/logged, or the independent
    FRI mask is absent.
11. Witness class changes trace/proof/state shape or error behavior.
12. A proof fails, an invalid mutation verifies, a regression fails, source changes during the run,
    or an artifact/privacy scan reports a hit.

Security mismatches, test failures, and proof failures receive no automatic retry. Only an external
host interruption may resume after human classification.

## Resumability and raw evidence

- Create an immutable run manifest containing source/tool hashes, vector IDs, stage count, and
  expected test counts.
- Store append-only raw stdout/stderr and per-stage result hashes outside the source tree.
- Mark a checkpoint complete only after verification and artifact scanning.
- Revalidate the complete manifest before resuming.
- Resume only after power loss, host interruption, or bounded time exhaustion.
- Never resume after a semantic/security mismatch without a reviewed new source version and run ID.
- Never resume an interrupted proof fragment or reuse its mask randomness; start a fresh proof
  attempt with fresh CSPRNG output.
- Set proof attempts to one. Retry behavior must not conceal crashes or witness-dependent failures.

## Work that must not run unattended

- Selection of field, hash, PCS, FRI, Fiat-Shamir, entropy, or quantum-security parameters.
- Final approval of attempt/revision/nullifier semantics or fixed capacity.
- Editing protected production code to repair a failed run.
- Live verifier-state migration, activation, rollback, or competing-before-state resolution.
- KMS/HSM changes, external signing ceremonies, governance changes, or production deployment.
- Independent cryptographic, implementation, privacy, side-channel, or operational audits.
- Dependency installation or upgrade.
- Destructive cleanup, publication, or external system mutation.
- Any real-data or PHI run.

## Containing-rollup completion boundary

The rollup is no longer deferred outside the roadmap. R01-R12 are counted internal packages. They
must replace mocks with the real verifier, authenticate the full statement and wide state, prove L2
execution, publish reconstructable non-PHI data, settle on Ethereum, and exercise sequencing,
reorganizations, bridge custody, forced inclusion, safe exits, upgrades, recovery, and finality.
`docs/BASED_ZK_ROLLUP_ARCHITECTURE.md` remains the architectural authority; this roadmap owns the
completion status.

## Production truth

Today Blind Ledger has verified experimental proof evidence, a real 12-field application ABI, a
selected claim-proof security architecture, the sealed Wave 1 relation, and manifest-bound H4
K128/K512 prototypes combining the real semantic source, native-masked GKR, Construction 8.2 PCS,
dual-PQ authenticated public coin, atomic coordinator, and independent verifier. It does not yet
have a selected authoritative state plane, H5 repeated qualification evidence, H6 suite identity,
a production claim verifier, a complete adapter platform, or an implemented based rollup. Current
internal progress is **6 of 93 packages complete and 87 open**. No real PHI is authorized. The next
legitimate product milestone is `DEPLOYMENT_READY_AUDIT_PENDING`, followed by the single independent
Security Audit Gate and authorized operator activation.

## 2026-07-30 Wave 2 H3 prototype closure

The ordered H3 items 1 and 2 in the 2026-07-29 correction are complete. One fresh segment-32 proof
completed through independent verification in 28.943126 seconds externally. Its contemporaneous
post-launch audit found zero new driver events, but a later System-log audit invalidated the reboot
as a clean driver-integrity boundary; this run therefore receives no reset or qualification credit.
Every printed cryptographic verifier gate was true, pagefile usage did not grow, and scratch was
0.000000 MB. The accepted 2026-07-31 H4 attempts supersede it.

Measured decimal resources were 311.537664 MB external process-tree RSS and 1,058.013184 MB sampled
GPU use. The row-state accounting is 7.864320 MB for claim component/source/relation state plus
4.194304 MB for GKR-mask source/relation state, or 12.058624 MB live joined state. The historical
200 MB host engineering target is not met and is not silently weakened; the immutable 5,000 MB
RSS, below-5,000 MB scratch, and no-swap gates pass.

H3's smallest correct real-GKR/native-mask/PCS/coordinator prototype is complete. Next is item 3:
bind the bounded semantic AIR, program/bus, state transition, retry identity, verifier identity,
roots, parameters, and ordered statement atomically. Do not run the warm-up-plus-ten H5 campaign
until the remaining composition boundary and the applicable resource decision are closed.
`proofSuiteId=null`, activation, `complete_pcs_qualification`, and
`complete_proof_qualification` remain false.

## 2026-07-30 Wave 2 H3 throughput refinement

The current theorem-neutral implementation removes host reconstruction and transfer bloat without
removing a security gate. Rust reconstructs each complete authenticated compact-row message from
three GPU source coefficients plus Rust-owned mask state; CUDA copies only 80 reduced boundary
component evaluations; GKR weights remain canonically packed; and four dead device buffers are
released at their last use.

The fresh post-warm-up segment-32 proof completed input-to-independent-verification in 24.749154
seconds externally and 24.392408 seconds in-process. It used 263.983104 MB external process-tree
RSS, 1,011.875840 MB sampled total GPU memory, 917.570560 MB tracked proof allocations, 0.000000 MB
scratch, no pagefile growth, and zero post-launch driver events. Every verifier and security flag
was true.

The historical 200 MB host engineering target is still not silently weakened. The measured peak is
now in the low hundreds of decimal MB and passes the immutable 5,000 MB RSS, below-5,000 MB scratch,
no-swap, and sub-30-second prototype gates. H4 atomic semantic-AIR/bus composition remains next;
H5's warm-up-plus-ten campaign and H6 suite qualification remain blocked on their written gates.

## 2026-07-30 Wave 2 H4 bounded semantic source

H4 now has a canonical cross-language semantic hash-bus snapshot and a Rust-verified B16 source
codec. K128 binds 46,858 exact calls and K512 binds 165,762 exact calls. Each 131,072-permutation
coprocessor shard stores only 1,600 live input wires and 1,600 live output wires; the 448 fixed-zero
padding wires are implicit. The exact source pair is 52.428800 MB per shard, so the canonical files
including their 215-byte header are 52.429015 MB for K128 and 209.715415 MB for four-shard K512.
The prior 67.108864 MB padded pair is superseded and must not be allocated.

The exact B16 group phase now publishes the first cubic message from compact `u16` patterns before
accepting the group challenge and folds directly to 4,096 groups. Its CPU/GPU message and fold KAT
passes. The full seven-layer control measured 0.605268 seconds per Keccak round, 229.822 MB host
peak, and 1,698.495 MB device state; the separate exact degree-45 bridge measured 0.496789 seconds
and 69.042880 MB. These component measurements do not close H4. The gate still requires the real
nonuniform producer, native masking, selected PCS, atomic one/four-shard coordinator, independent
verification, and complete K128/K512 measurements.

The K512 semantic source is now concrete. A fixture-only path that unnecessarily constructed the
retired physical SHA3 AIR was stopped at 9,218.748416 MB RSS and removed from K512 emission while
the K128 physical regression remained intact. The corrected one-test K512 build passed in
441.10 seconds at 3,873.902592 MB monitored peak and emitted the exact four-shard source. Rust
decoded 165,762 calls, produced the canonical 209.715415 MB boundary, and independently verified all
four 24-round/seven-layer traces in 4.023582 seconds.

The masked reducer now accepts an untrusted bounded group oracle without materializing the complete
Fp16 source in Rust. Rust retains message endpoints, adaptive challenge release, native masks, wire
tail, and terminal authority. Exact CPU-oracle parity and forged-message rejection pass. This closes
the bounded producer interface, not the production CUDA worker or H4 atomic proof.

## 2026-07-30 Wave 2 H4 K128 functional composition

The production worker is now attached to the semantic source, native masking, the selected
Construction 8.2 PCS, one authenticated 6,086-round coordinator, and the independent verifier.
The real K128 producer covers 168 layers, 6,073 GKR rounds, four relay-free input claims, and 508
mask constraints. Its output query binds the exact semantic boundary and selected plan, and a
statement-binding mutation is rejected.

One fresh monitored segment-32 K128 run exited zero with empty stderr and all independent
verification/mutation gates true. Exact process wall time was 120.670536 seconds; tracked GPU peak
was 969.999360 MB, monitored process-tree RSS was 536.928256 MB, scratch was 0.000000 MB, pagefile
did not grow, and the run added zero driver events. This closes the H4 K128 functional-attachment
substep only. It does not close H4 because the immutable sub-30-second K128 gate failed and the
atomic four-shard K512 proof remains open. The measured dominant stage is the 100.240849-second
authenticated real-GKR head. Optimize that stage without changing the theorem, transcript,
masking, source, or verifier; then rerun K128 before extending the same coordinator to K512.

## 2026-07-30 Wave 2 H4 real-wire remeasurement

The production worker now accelerates raw wire quadratics while Rust retains masking, challenge
order, terminal authority, transcript replay, and independent verification. A fresh complete K128
semantic proof passed every functional, mutation, hiding, coordinator, and verifier flag in
53.547306 seconds, including a 42.017007-second semantic GKR prelude and 4.692209 seconds of PCS
mechanics. Decimal resources were 295.625 MB proof-phase host peak, 253.977 MB parent lifetime
peak, 76.435 MB native-verifier peak, 969.999360 MB tracked device peak, and 0.000000 MB scratch.
This is a verified prototype and a failed latency qualification.

The next implementation is narrow: preserve the exact B16 relation and Construction 8.2 proof,
remove measured GKR overhead only when the containing benchmark improves, and attach K512's four
canonical shards sequentially on the one GPU under one atomic acceptance boundary. Sequential
execution reuses the bounded K128 memory image, avoids four-way VRAM/RAM duplication, and does not
assume that nonlinear traces may share challenges without a batching theorem. K128 remains required
below 30 seconds and K512 below 180 seconds before qualification.

zkDeepFold remains excluded from the active path. Its historical `mu=21`, `s=473` inequality is
only the superseded zkDeepFold simulator's interpolation-capacity condition; by itself it is not
hiding evidence, a composition theorem, or support for conjecture-dependent lower-query list
decoding. Construction 8.2 of ePrint 2026/391
remains selected until any alternative supplies the complete theorem mapping, error ledger,
implementation, and independently verified end-to-end measurement.

The first real K512 atomic coordinator passed all four ordered shard verifiers and emitted one
outer receipt. It used sequential single-GPU execution, 591.249408 MB peak process-tree RSS,
2,182.086656 MB sampled total GPU use, 0.000000 MB scratch, no pagefile growth, and zero driver
events. Its 222.600073-second in-process time fails the 180-second gate. Functional K512 attachment
is closed; the next throughput dependency remains the shared K128 GKR head, currently 42.017007
seconds of the 53.547306-second complete proof.

## 2026-07-30 Wave 2 H4 shared atomic coordinator and verifier narrowing

One coordinator now owns both canonical profiles: one K128 shard with a 30-second limit and four
ordered K512 shards with a 180-second limit. Its v2 parent/receipt binds the semantic file, plan,
caller statement, shard order, child proof bundles, and an execution manifest over the exact
Python/prototype/worker dependency closure, seven native verifiers, and precompiled PTX.

The newest K128 measurement is 54.955357 seconds in-process and 59.060426 seconds external, at
532.242432 MB process-tree RSS and zero pagefile growth or driver events. K512 is
220.583627/226.627989 seconds in-process/external; shard times are 55.221861, 54.467592,
53.685071, and 55.734525 seconds. Its external peaks are 547.127296 MB process-tree RSS and
2,182.086656 MB sampled total GPU, with zero pagefile growth or driver events. All functional
verification gates pass; both latency gates remain false.

Production verifiers now reject all pre-GKR-mask answer/spot-check formats and incomplete
16/19/32/35-tree schedules. The rejection KAT closed 10/10 retired cases, both complete 20/36-tree
Merkle KATs and the current V4/V2 KAT pass, and the stale V1 acceptance KAT is deleted. The full
optimized suite is 264 passed, 0 failed, 0 ignored, plus every binary group; strict Clippy has zero
warnings.

Keep the worker lifetime at 48 layers. A 56-layer attempt faulted at layer 54, emitted CUDA error
700, and caused `nvlddmkm` Event 153 record 229592. At that checkpoint H4 remained
throughput-open; the 2026-07-31 section below supersedes its latency status.

## 2026-07-31 Wave 2 H4 prototype latency closure

The manifest-bound H4 prototype now completes both canonical profiles through independent
verification under the exact same fail-closed one/four-shard coordinator. Execution manifest
SHA3-512 is
`51c23310274ccf7c4d7f9abe4ae7eba43266b335bd377b21cbf92409729b91e2a40a39787a157baa080c9d0516c7815af404a4d58d9e76747f652f57cd017ed6`.

The accepted K128 proof completed in 29.974129 seconds. The accepted four-shard K512 proof
completed in 120.460733 seconds, with shard proof times 31.567686, 30.679149, 31.019240, and
25.998881 seconds. Every shard and the outer receipt independently verified. Both accepted
attempts had empty stderr, 0.000000 MB scratch, zero pagefile growth, and zero driver events after
the verified `2026-07-31T05:06:01.7747420-06:00` reset boundary.

The final implementation keeps only one future 48-layer worker, uploads immutable topology once,
batches canonical plan transport, derives authenticated same-source aliases instead of copying
duplicate words, reads the semantic file once, and starts the local Python closure with `-S`.
Internal proof host peaks are 288.412 MB for K128 and 296.255 MB for K512; external process-tree
peaks are 681.607168 and 706.523136 MB. Per-proof tracked device state is 969.999360 MB and K512's
sampled total GPU residency is 2,770.337792 MB. All figures are decimal MB.

These measured results explicitly supersede the historical 200 MB host and 1,800 MB device
component-selection targets as acceptance criteria. They do not weaken the immutable 5,000 MB
host, below-5,000 MB scratch, or no-swap gates; the accepted implementation remains in the low
hundreds of MB internally and below 3,000 MB of sampled total GPU residency.

Containing H4 gates passed 266 optimized library tests. The active post-cleanup suite passes 264
tests with zero failures or ignored tests after the two isolated BaseFold-only tests were removed; every remaining
binary and doc-test group, strict all-target Clippy with zero warnings, seven host cryptographic
KATs, the complete 20-tree segment-32 mutation KAT, 10/10 retired-format rejections, and static
compilation of all 36 CUDA entry points.

This closes H4's functional and one-run 30/180-second prototype boundary. It does not close H5:
the required one uncounted warm-up plus ten unique K128 and K512 batches and p95/resource campaign
have not run. Gate 2E must first select and bind the authenticated state plane so H5 measures the
candidate eligible for H6. H6 suite qualification also remains open. `proofSuiteId=null`, activation=false,
`complete_pcs_qualification=false`, and `complete_proof_qualification=false` remain authoritative.
