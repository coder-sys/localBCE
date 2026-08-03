# Blind Ledger implementation roadmap

Updated: 2026-08-02

Status: authoritative current execution plan. This file contains no dated run narrative and no
executable fallback architecture. Historical roadmap text is preserved verbatim in
`history/IMPLEMENTATION_ROADMAP_THROUGH_2026-08-01.md`; rejected designs are governed only by
`REJECTED_ARCHITECTURES.md`.

## Authority and recovery order

When source and prose disagree, use this order:

1. executable source and fail-closed tests;
2. the newest verified section of `../STATE.md`;
3. `CURRENT_TECH_STACK.md` and `../ARCHITECTURE.md`;
4. this roadmap;
5. the specialized current architecture contracts;
6. `REJECTED_ARCHITECTURES.md` and `history/` for non-executable evidence only.

After compaction, read `../AGENTS.md`, `../CONTINUATION_MANDATE.md`, the newest `STATE.md`
section, `CURRENT_TECH_STACK.md`, this file, and the current document for the active gate. Never
derive a next action from a dated section in `STATE.md` or `history/`.

For any R01-R12 work, the specialized contract is
`ETHEREUM_STRAWMAP_BASED_ROLLUP_COMPATIBILITY.md`. Being an Ethereum-settled based validity
rollup is compulsory. Strawmap items are compatibility inputs selected by maturity and deployed
fork state; no Draft, Review, Stagnant, or research item may become a hidden release dependency.

## Frozen product boundary

Every package and optimization must preserve all of the following:

- the sealed Wave 1 relation and exact ordered 12-field compatibility ABI;
- fixed approval, denial, and cover shape with no PHI or exact private amount in public data;
- SHA3-512 authority, M31 base arithmetic, and reviewed degree-16 Fp16 challenges;
- authenticated interactive public coin using ML-DSA-87 and SLH-DSA-SHAKE-256f;
- no launch Fiat--Shamir, grinding credit, trusted setup, curves, RSA, pairings, KZG, or IPA;
- native witness hiding and at least 256 bits for every theorem/error term and composed ledger;
- an untrusted GPU with authoritative Rust parsing, recomputation, replay, and verification;
- no more than 5,000,000,000 decimal bytes host RSS, scratch strictly below that value, and no swap;
- complete-proof p95 below 30 seconds for K128/100-live and below 180 seconds for K512/500-live;
- retry-stable attempt identity with fresh proof randomness; and
- atomic binding of semantics, state, money, proof, verifier, schema, parameters, migration, and
  settlement.

No benchmark, implementation difficulty, or model limitation can waive an invariant.

## Current state

| Boundary | State | Verified evidence | Still required |
| --- | --- | --- | --- |
| Wave 1 | Sealed, synthetic, nonactivating | Exact fixed-shape semantics and global SHA3 schedule | Durable authoritative state and activation |
| H0-H3 | Prototype implementation complete | Exact bus, seven-layer B16 GKR, native masks, Construction 8.2 PCS, public coin, component verification | Containing simulator/security ledger in H6 |
| H4 | Prototype-accepted | Complete manifest-bound K128 and four-shard K512 proofs independently verified in 29.974129/120.460733 seconds; the compact state-AIR/FRI component passes native v3 envelope verification, and the full typed C0 AIR now has a native v4 readback seam that consumes its authority/root tables and maps all 46,210 calls into the canonical H4 bus | Reviewed state/PQ admission, full state relation inside H4 custom GKR/PCS, a resource-qualified typed proof, complete proof-native H4 composition, state-composed performance, repeated p95, final suite identity |
| Gate 2E | 2E-0/S0 through 2E-7/S7 reference boundaries plus terminal ledger implemented; no admission | C0 control, all 13 narrow interface descriptors/codecs, scalar C1-C4 controls, five-candidate dual-PQ S3 reference transcript, S4/S5 composition and migration references, S6/S7 rejection/handoff, terminal ledger, versioned state-root bus, native v2 compatibility and v3 proof-native state-component verification, compact AIR v2 fixed-snapshot lookup/mutation coverage, and the nonactivating two-state-claim H4 bridge are tested and documented | Admit a reviewed backend and complete the full state relation inside H4 GKR/PCS; close simulator/leakage/PQ blockers |
| H5 | Blocked on 2E | One-run H4 feasibility evidence | One warm-up plus ten unique measured proofs per profile |
| H6 | Blocked on 2E/H5 | Current parser, KAT, and mutation evidence | Theorem, simulator, attack, identity, reproducibility, and qualification seal |
| Waves 3-6 | Blocked on H6 | Reference components only | Production verifier/state/custody, adapters, rollup, operations, release |

Current progress is 6 of 93 engineering packages complete. `proofSuiteId=null`, activation is
false, real PHI and payments are forbidden, and the final independent audit has not begun.

The state-composed H4 bridge is an integration shape only: the state lane currently checks operation/
snapshot field equality, authenticated slot index/order, Boolean presence, and empty-slot zeroing;
the Rust source builder and native Rust/Python snapshot decoders reject duplicate present keys before
source commitment. Proof-native high-cardinality uniqueness, membership/absence, and money/state-
conservation semantics remain outside the custom GKR/PCS relation, and no state-composed performance
or qualification credit is recorded.

## Sole dependency chain

```text
verify the one tracked commit-bound ops authority
  -> Gate 2E-0 C0 control freeze
  -> Gate 2E-1 replaceable interfaces
  -> Gate 2E-2 scalar state-relation controls
  -> Gate 2E-3 PQ commitment screening
  -> Gate 2E-4 atomic finalist composition
  -> Gate 2E-5 migration and failure closure
  -> Gate 2E-6 complete-boundary measurement and selection
  -> Gate 2E-7 sealed handoff
  -> H5 repeated complete-proof campaign
  -> H6 proof-candidate qualification
  -> Wave 3 verifier/state/custody
  -> Wave 4 adapters/operations
  -> Wave 5 containing based rollup
  -> Wave 6 release-candidate seal
  -> independent Security Audit Gate
  -> separately authorized operator activation
```

The operational authority is now the one tracked `ops/` tree. Exact file-set, length, SHA3-512,
and symlink checks close the former sibling-layout blocker without copying or changing policy bytes.

## Gate 2E: exact current implementation plan

### 2E-0 - freeze the C0 control (S0 complete)

Inputs: sealed K128/K512 fixtures; full-width replay/payment keys and values; canonical ordered
accesses, duplicates, conflicts, denial, cover, and correction cases; old/new roots; operation log;
money totals; ordered 12-field output; current H4 manifest and resource record.

Outputs:

- one canonical fixture manifest with lengths and SHA3-512 identities;
- independently reproduced membership, absence, sequential-update, and endpoint results;
- state-only and complete-boundary time, RSS, scratch, and I/O measurements; and
- negative fixtures for stale reads, omitted/reordered writes, duplicate identities, collisions,
  root substitution, and conflicting updates.

STOP if C0 disagrees with the sealed relation. Never repair a candidate by changing semantics or
normalizing mismatched bytes.

Current S0 record: `experiments/bl_pq512_crypto_foundation/c0_control_fixture.py` and
`c0_control_measurement.py` freeze K128/K512 synthetic state, payment, ordered 12-field, H4, and
negative-case evidence. The focused C0 suite is 9/9 green. Fresh Windows-process measurements
were collected separately for each profile and boundary; decimal MB values are observed process
RSS, scratch is the explicit no-fixture-scratch boundary, and pagefile deltas are recorded as
observed usage deltas rather than a swap classification:

| Profile | Boundary | Seconds | Peak RSS MB | Scratch MB | Pagefile delta MB | Read/Write I/O MB |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| K128 | state-only | 3.074924 | 29.171712 | 0.000000 | 2.592768 | 0.000000 / 0.000000 |
| K128 | complete | 3.010325 | 29.708288 | 0.000000 | 3.010560 | 0.000000 / 0.000000 |
| K512 | state-only | 12.910909 | 37.777408 | 0.000000 | 6.602752 | 0.000000 / 0.000000 |
| K512 | complete | 13.353259 | 39.399424 | 0.000000 | 8.630272 | 0.000000 / 0.000000 |

The complete artifact lengths and SHA3-512 identities remain the frozen 11,217-byte K128 and
11,231-byte K512 manifests. This is C0 reference evidence only; it does not qualify H4, select a
state relation, set `proofSuiteId`, enable activation, or authorize real data.

### 2E-1 - freeze narrow replaceable interfaces (S1 complete)

Define separate bounded interfaces for state layout/version, key/value encoding, membership,
absence, ordered read/write manifest, memory consistency, commitment/opening, old/new transition,
SHA3-512 public identifier, migration/rollback, transcript contribution, independent verification,
and atomic receipt contribution.

Every interface must state producer, consumers, public/private fields, exact grammar, maximum
length, domain/version/parameter identity, canonical decode rule, error family, retry/crash
behavior, and mutation cases. State relation and commitment remain replaceable and cannot reach
into claim semantics or settlement.

Current S1 record: `experiments/bl_pq512_crypto_foundation/state_interface.py` defines 13 wire-coded
descriptors, one strict bounded `BLSI` envelope, and the strict `BLTR` old/new transition codec.
The interface module has no imports into claim, payment, application, settlement, or proof
implementations. Its focused and attack suites pass 22/22. This freezes ports only; it does not
select a commitment, bind H4, set `proofSuiteId`, enable activation, or authorize real data. S2
now supplies the separate scalar relation controls and parity evidence below.

### 2E-2 - implement scalar state-relation controls (S2 complete)

`experiments/bl_pq512_crypto_foundation/scalar_state_relation_controls.py` implements bounded,
synthetic-only scalar references for C1 dense persistent memory, C1 touched-sparse persistent
memory, C2 transparent index/value dictionary, C3 touched-projection RAM, and C4 compact
shuffle-based memory consistency. Each candidate recomputes the same fixed-shape four-lane
transition, membership/absence queries, update, money summary, candidate-specific state identities,
and a deterministic bounded witness. `independently_verify_candidate` replays the transition from
the input rather than trusting candidate roots or result fields.

`scalar_state_relation_parity.py` compares the candidate-independent boundary to the frozen C0
control for both K128/100-live and K512/500-live: replay/benefit/obligation/ledger operation and
access geometry, membership, absence, cursor behavior, approval/denial/cover/correction outcome
labels, and `(80, 80, 80)` plan/debit/credit totals. It also exercises stale read, omitted write,
reordered write, duplicate identity, key collision, conflicting update, and result-root
substitution. The public parity record SHA3-512 is
`fc99b31b333a6ec3a19cc55099bd612dcd1d7964115301bbcb9d512d8efe184bc320f04af65f3aa8417bf03fe368e05dddc1d2bd7fd2b2005280e777f0d496c4`.

Focused command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_scalar_state_relation_controls.py tests/attacks/test_bl_pq512_scalar_state_relation_controls_attacks.py
14 passed in 21.50s
```

The C1 dense capacity scan, C3 quadratic projection work, and C4 persistent initialization/scan
are derived scalar work counters, not measurements or throughput claims. No scalar candidate has
native hiding, a PQ commitment, H4 binding, migration proof, complete-proof timing, or selection
credit. The separate tracked-ops authority is verified.

Reject semantic drift, witness-dependent shape, an implicit global scan, unbounded grammar, or
host-trusted equality.

### 2E-3 - screen PQ commitment backends

For each candidate pin paper/version/source/license, assumptions, parameters and generator,
field mapping, abort/rejection distribution, binding/knowledge/hiding claims, update model, proof
grammar, verifier, and independent KATs.

Reject pairings, KZG, IPA, RSA, ECC, trusted setup, Fiat--Shamir/QROM credit, designated verifier,
external service, unsupported knowledge assumption, or any term below the frozen floor. A lattice
label is not security evidence.

Current S3 record: `experiments/bl_pq512_crypto_foundation/pq_commitment_screening.py` defines the
common fixed-width masked commitment/opening envelope, exact parameter identities, five screened
families, a dual-ML-DSA-87/SLH-DSA-SHAKE-256f authenticated public-coin round, and an independent
opening verifier. The reference envelope is synthetic and nonproduction. The three lattice
families lack pinned source/parameters/theorem evidence; the retired hash-pad control fails its
specific public-coin/quantum review; and `TRANSPARENT_SHAKE256_1024` has a reviewed candidate
ledger but still lacks complete H4 composition. Its exact `BLTHC02` grammar, SHAKE commitment,
coin-binding transcript identity, strict Rust parser, and Python/Rust KAT are now implemented as
reference evidence; they do not close the missing H4 composition, simulator, or leakage ledger.
All five descriptors fail closed. No candidate is admitted, selected, bound to H4, or assigned
`proofSuiteId`.

Focused command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_pq_commitment_screening.py tests/attacks/test_bl_pq512_pq_commitment_screening_attacks.py
8 passed in 3.27s
```

The timing is a test-run observation only; it is not a complete-proof or H5 measurement. Proceed to
2E-4/S4 atomic reference composition without treating the synthetic envelope as a qualified PCS.

### 2E-4 - atomically compose the finalist

One transcript and receipt must bind semantic program and ports, CBAM and conflict order,
attempt/nullifier identity, state layout/epoch/capacity/parameters, old/new commitment and root,
membership/absence/uniqueness/order/money, H4 proof stack, migration version, ordered 12-field
projection, wide sidecar, and all verifier/module identities.

No partial receipt is reusable and no host comparison substitutes for in-proof equality. Mutating
any bound field must reject before state acceptance.

Current S4 record: `experiments/bl_pq512_crypto_foundation/atomic_state_composition.py` keeps the
scalar relation candidate and the S3 commitment-backend identity as separate bound fields. It
independently replays S2, derives one fixed 12-field projection and BLTR transition, verifies the
S3 authenticated opening, and constructs a receipt binding the attempt, transition, deferred H4
reference identity, verifier identity, and commitment. The canonical relation payload hashes
private membership keys/values and absence keys rather than serializing them. The H4 identity is
explicitly deferred; `proofSuiteId` is null and activation is false.

Focused command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_atomic_state_composition.py tests/attacks/test_bl_pq512_atomic_state_composition_attacks.py
6 passed in 10.11s
```

The attack suite rejects transition-root, commitment, opening, projection, relation-candidate,
proof-identity, and relation-result mutations. This closes only the synthetic non-spliceable
composition/reference-receipt boundary. It does not select a relation or commitment, prove a
production PCS, close migration, or authorize state publication. Proceed to 2E-5/S5.

The follow-on state work now has two bounded implementation boundaries. The native coordinator
continues to consume the version-2 compatibility envelope, and it now also consumes the version-3
`BLSB01`/`BLSA02` envelope emitted by `state_air_proof.py`. Version 3 contains a compact packed
state-relation AIR, a private streamed dual-PQ FRI package, and a fixed evidence record. Rust
independently replays the all-slot transition, evaluates the compact AIR, compares every packed
trace column to the exact parsed operations, verifies the selected FRI package, checks the ordered
128-value root public input, and recomputes the state/AIR fragment and composition identities. The
v3 parent, authenticated interactive session/schedule, exact child proof grammar, and atomic
receipt bind the full transition, commitment, verifier, attempt, receipt, ordered 12-field
projection, compact AIR, package, and component identities. The separate hash-pad security review
still rejects the current candidate because its full 256-bit quantum binding/composition theorem
and commit-before-coin lifecycle are not closed; no backend is admitted, full custom-H4 GKR/PCS
composition remains open, and H5 remains blocked.

### 2E-5 - close migration and failure semantics

Test genesis, layout migration, checkpoint publication, conflicting CAS, reorganization, rollback,
restore, partial write, crash before/after publication, corrupted checkpoint, stale epoch,
parameter/verifier rotation, and mixed-profile rejection. Retries preserve attempt identity but use
fresh proof randomness. Old bytes are never reinterpreted under a new layout.

Current S5 record: `experiments/bl_pq512_crypto_foundation/state_migration_recovery.py` provides
immutable SHA3-512 checkpoints, independently verified S4 composition publication, store-owned
pending CAS records, reference migration equivalence, and monotonic rollback/recovery epochs.
Migration preserves the logical state root, state manifest, and sequence while rotating layout,
parameter, or verifier identities. Recovery accepts only a complete checkpoint already known to the
store; stale, corrupted, mixed-profile, downgraded, partial, and replayed records fail closed
without changing the current checkpoint. This is synthetic reference evidence, not a production
migration theorem or durable custody implementation.

Focused command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_state_migration_recovery.py tests/attacks/test_bl_pq512_state_migration_recovery_attacks.py
10 passed in 10.10s
```

Proceed to 2E-6/S6 repeated state-component evidence and 2E-7/S7 handoff. Do not treat the
reference equivalence record as complete-proof, backend-selection, H5, or activation evidence.

### 2E-6 - measure and select

1. Repeated state-component measurements on identical fixtures.
2. One uncounted complete warm-up for each finalist/profile.
3. At least one fresh externally monitored, independently verified complete K128 and K512 proof
   for every still-eligible finalist.
4. Select the fastest candidate passing every correctness, privacy, PQ, auditability, migration,
   host, scratch, and no-swap gate.

If no candidate beats C0 at the complete boundary, select C0 and retain exact rejection evidence.
Gate 2E selection is not H5 qualification.

Current S6/S7 record: `experiments/bl_pq512_crypto_foundation/gate_2e_selection.py` measures the
same synthetic S2/S3/S4 reference component twice for each of the five screened backends and both
K128/K512 profiles: 20 observations total. Each observation is independently verified at the
reference boundary, carries derived work separately from observed timing, records zero proof bytes,
and explicitly records that external complete-boundary monitoring was not run. S3 recomputation
rejects every backend, so no finalist receives a warm-up or complete-proof attempt. The decision
retains C0 as an unselected control with `selected_backend_id=null`, `proofSuiteId=null`, and
`C0_CONTROL_RETAINED_NO_ELIGIBLE_PQ_FINALIST`.

Focused command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_gate_2e_selection.py tests/attacks/test_bl_pq512_gate_2e_selection_attacks.py
6 passed in 34.04s
```

S7 emits an explicitly unsealed handoff with the no-admission, no-complete-boundary, deferred-H4,
complete-simulator, complete-leakage, and strict-PQ blockers. Tracked `ops/` authority is verified;
the former sibling-layout blocker is closed. Timing is retained as measured reference-component
evidence, not selection credit. No candidate is selected or activated.

The terminal Gate 2E ledger is now implemented in
`experiments/bl_pq512_crypto_foundation/gate_2e_terminal_ledger.py`. Its builder independently
replays the S4 composition and S5 checkpoints, verifies both C0 profile shapes and all seven C0
negative classes, checks the fixed 12-field boundary and public/private encoding boundary, and
recomputes the S6/S7 identities. It emits 11 ordered records and remains
`UNSEALED_BLOCKED_GATE_2E_TERMINAL_LEDGER` with
`ledger_digest_sha3_512=ce3bda2eb79b554cc56fc9631b40792068fd953d18fc945ea9a567a5b3caa0f8a57a2c9ab785361f4658903080aa02cce99f7a96c5291507d37af0192bb96d28`.
The exact remaining blockers are `complete_leakage_scan_missing`,
`complete_simulator_missing`, `h4_atomic_binding_deferred`, `no_backend_admitted`, and
`proof_suite_unselected`. A real nonactivating state plane is now independently replayable and
appears as `STATE_PLANE_IMPLEMENTED_H4_PENDING` when supplied to the ledger; the default recorded
context remains `STATE_PLANE_NOT_PROVIDED` until it is connected to the candidate admission run.
The terminal ledger is reference evidence only; it cannot select a backend, assign `proofSuiteId`,
bind H4, or authorize H5/H6.

### 2E-7 - seal the selection handoff

Record selected relation/commitment identities and parameters; source, lock, license, schema and
tool hashes; theorem status and remaining H6 obligations; all positive/negative/migration/recovery
results; component and complete measurements; rejected candidates; updated source/dataflow;
commit/tree/clean status/protected-path readback; and the exact H5 command, monitor, environment,
input generator, and STOP conditions.

2E closes only when the selected state plane is present in the H4 parent, transcript, proof,
independent verifier, and atomic receipt. The current versioned `BLHBSN02`/`BLHBB102` root-bus seam
and the v3 compact state-AIR/FRI component are prerequisite/native-consumption evidence for that
boundary, not its closure. The compact relation now algebraically links ordered operation rows to
both fixed-capacity snapshots through the v2 46-wide lookup grammar, and the H4 seam carries
authenticated slot indices with canonical row-order constraints. Native Rust and Python snapshot
decoders reject duplicate present keys. A separate `BL-PQ512-C0-TYPED-STATE-AIR-v1` component now
composes the ordered-map/payment authorities and verifies root/cursor, slot-order, money, fixed
asset-registry, and replay/payment hash-port mutations for the K128 C0 witness. The native
coordinator consumes its v4 AIR program/execution, verifies the authority/root bindings, and maps
its 46,210 calls to the canonical H4 bus; the base replay/payment bus remains 46,208 calls. The
full state relation is implemented at the typed semantic-AIR/H4 readback seam, but the selected
typed proof route is rejected by the immutable resource preflight. It is still not a selected
complete H4 GKR/PCS proof, no reviewed backend is admitted, and no manifest-bound H4 K128/K512
proof was run after the source change.

## H5: repeated complete-proof qualification campaign

Prerequisites: sealed clean 2E commit; canonical ops identity; locked/offline builds; execution
manifest readback; clean driver-reset boundary; exclusive host; synthetic unique inputs; external
process-tree, pagefile, device, scratch, stdout/stderr, and driver monitoring; all focused,
mutation, parser, state, migration, attack, and independent-verifier gates green.

The fail-closed preflight is implemented in
`experiments/bl_pq512_crypto_foundation/h5_qualification_preflight.py`. It independently replays
the unsealed Gate 2E terminal ledger, validates the reference hardware record, verifies the exact
tracked `ops/` SHA3-512 authority inventory, and freezes the
one-warm-up-plus-ten-unique-measured shape for both profiles (22 fresh launches total). The current
preflight is `BLOCKED_H5_PREFLIGHT` with digest
`5c6a04878f8268dfd4fb33b3583fd27f0aff8624f90f720a9f6b45fb8dff849538ee7aac6ea3d36d72971d1223bf595c9cec0d35f3230705047518c5741432e1`; tracked ops and the reduced 1.5% disk floor (7,310,026,937 bytes required) pass, the external monitor is not configured, and no complete-proof campaign has started. The native v3 compact state-AIR/FRI component, including its v2 fixed-snapshot lookup grammar, is implemented and independently verified, but full custom-H4 state composition, PQ commitment admission, and the complete simulator/leakage ledger remain open. No CUDA/prover launch receives H5 credit from this record. The immutable 5,000,000,000-byte RSS/scratch and zero-swap gates were not changed.

| Profile | Uncounted warm-up | Unique measured attempts | Conservative p95 gate |
| --- | ---: | ---: | ---: |
| K128/100-live | 1 | 10 | maximum of ten < 30.000000 s |
| K512/500-live | 1 | 10 | maximum of ten < 180.000000 s |

Each launch requires new input identity, proof, masks, authenticated public-coin session, parent,
and receipt. Reviewed binaries, PTX, and immutable topology may be reused; witnesses, challenges,
masks, openings, proof fragments, and partial receipts may not.

Record complete-process and wrapper time, stage times, verifier time, proof/receipt hashes and
bytes, internal and process-tree RSS, pagefile delta, tracked and total device residency, scratch,
I/O, public-coin latency/retries, cleanup, stdout/stderr hashes, driver interval, and every verifier
flag. A failed attempt stops the campaign for classification; it cannot be replaced silently.

Optimize only the measured dominant complete-proof stage. An optimization must preserve transcript
order and verifier reconstruction, improve the containing benchmark, and preserve or reduce
memory, scratch, residency, nondeterminism, and audit surface.

Run exactly 22 fresh launches unless a STOP condition ends the campaign. With ten measured
attempts, conservative nearest-rank p95 is element `ceil(0.95 * 10) = 10`, the maximum.

## H6: proof-candidate qualification and seal

H6 must close all twelve obligations:

1. exact 256-bit composed theorem/error/abort/retry/multi-target ledger;
2. complete simulator for semantic AIR, state, GKR, PCS, public coin, malformed input, abort,
   retry, crash, retained artifacts, and repeated proofs;
3. one bounded proof/sidecar/receipt grammar with independent parser agreement;
4. downgrade, splice, replay, stale-state, migration, mutation, malformed-proof, and resource-DoS corpus;
5. cross-language KATs and authoritative Rust verification;
6. source/toolchain/dependency/license/SBOM/module/CUDA/schema/parameter/manifest pins;
7. locked offline reproducible builds and independent artifact readback;
8. H5 latency/resource/no-swap evidence and proof/verifier thresholds;
9. side-channel, telemetry, zeroization, cleanup, and unlinkability evidence;
10. rollback, recovery, and mixed-version behavior;
11. complete evidence manifest with no unexplained skip, warning, drift, or failed gate; and
12. explicit nonactivating Wave 3 verifier/state/custody work.

H6 may mark the proof candidate qualified for Wave 3 integration. It must keep `proofSuiteId=null`;
it cannot activate production or claim audit completion.

The bounded preflight is implemented in
`experiments/bl_pq512_crypto_foundation/h6_qualification_preflight.py`. It independently replays
the blocked H5/2E context, validates the candidate registry remains
`CANDIDATE_UNQUALIFIED` with eight null module identities, and emits exactly twelve H6 obligation
records with explicit measured/derived/inferred/unknown labels. The current record is
`BLOCKED_H6_PREFLIGHT`: five records are blocked, five are open, and two are reference-only. The
preflight never launches a prover, closes an obligation, assigns `proofSuiteId`, or enables
activation; the H6 theorem, simulator, parser, attack, reproducibility, resource, side-channel,
rollback, and evidence gates remain open.

The focused H6 preflight/attack suite passes 6/6 in 30.02 seconds. The containing S1-S7,
terminal-ledger, H5-preflight, and H6-preflight suite passes 85/85 in 151.88 seconds; these are
qualification-ledger test observations, not complete-proof measurements.

## Whole-product package map

The 93-package denominator is fixed. Detailed closure criteria live in the owning specification or
architecture contract; this table prevents scope loss without mixing historical run narrative into
the execution plan.

| Group | IDs | Count | Current boundary |
| --- | --- | ---: | --- |
| Specification/security freeze | S01-S12 | 12 | S01/S03/S05/S06 complete; eight open |
| Fixed-shape semantics/AIR | A01-A16 | 16 | A12 complete; remaining packages open or partially evidenced |
| Heterogeneous proof/native hiding | Z01-Z12 | 12 | Z01 historical validity package complete; Z02-Z12 open/in progress |
| State/verifier/custody | P01-P12 | 12 | Open; Gate 2E supplies state selection inputs |
| Validation | T01-T14 | 14 | Open convergence gates with current partial KAT evidence |
| Operations/release | O01-O06, O12 | 7 | Open |
| Government/oracle adapters | I01-I08 | 8 | Open |
| Containing based rollup | R01-R12 | 12 | Open |
| Total |  | 93 | 6 complete, 87 open |

The independent Security Audit Gate is not counted. Credentials, live endpoints, accounts,
signers, and legal authority are activation inputs, not missing engineering packages.

All **93 counted packages are internal engineering work**. Packages `S01`, `S03`, `S05`, `S06`, and `A12` are complete as current specification/application packages. R25 closes only `Z01` as a
historical validity-baseline package. This is not a privacy, strict-PQ, full-claim, or production claim. Therefore **6 of 93 internal engineering packages are complete and 87 remain open**.

### Specification and security freeze - 12 packages

| ID | Current deliverable | Status |
| --- | --- | --- |
| S01 | Reconcile current instructions, architecture, roadmap, state, and issues. | Complete; current documentation contract is active. |
| S02 | Freeze the product label and runtime configuration for the selected suite. | Open; activation configuration remains unselected. |
| S03 | Freeze the exact 12-field compatibility meaning and forbidden public fields. | Complete; structural specification and tests pass. |
| S04 | Freeze the canonical authenticated sidecar outside the 12-field array. | Open; final state/suite identity is missing. |
| S05 | Maintain the malicious-prover, quantum, privacy, parser, worker, and governance threat model. | Complete as a repository specification. |
| S06 | Maintain the per-field security-notion and authority table. | Complete as a repository specification. |
| S07 | Close the complete 256-bit security/error/abort/multi-target budget. | Open; H6 composition remains. |
| S08 | Prove the selected field, challenge, PCS, query, and zero-grinding parameters. | Open; rejected defaults are recorded, positive closure remains. |
| S09 | Pin the selected PCS, transcript, tree, encoding, domains, and multi-target treatment. | Open; H4 is selected but `proofSuiteId=null`. |
| S10 | Freeze genesis, migration, activation, rollback, rotation, and mixed-version behavior. | Open; Gate 2E/H6 remain. |
| S11 | Pin toolchains, dependencies, licenses, SBOM, and reproducible inputs. | Open; Python subset evidence is incomplete for the whole release. |
| S12 | Freeze the complete formal statement, invariants, errors, and acceptance gates. | Open; Gate 2E/H6 remain. |

### Fixed-shape semantics and claim AIR - 16 packages

| ID | Current deliverable | Status |
| --- | --- | --- |
| A01 | Freeze release capacities and profiles. | Open; K128/K512 are proof profiles, not final business capacity approval. |
| A02 | Freeze bounded canonical witness serialization. | Open; final proof/state grammar remains. |
| A03 | Freeze ordering, duplicates, encodings, and ranges across adapters and proof. | Open; semantic core is sealed, deployment edges remain. |
| A04 | Freeze enabled/dummy/cover composition and collision rules. | Open; downstream proof equality remains. |
| A05 | Prove witness-class-independent trace, query, proof, and operation shape. | Open; H5/H6 remain. |
| A06 | Prove all adjudication gates and priority in the final proof. | Open; semantic relation is sealed, suite qualification remains. |
| A07 | Prove canonical claim-source membership and authority. | Open; durable registry and adapters remain. |
| A08 | Prove oracle facts, authorization, signer, epoch, and membership. | Open; durable authority and adapters remain. |
| A09 | Prove ruleset, policy, fee row, versions, and authority. | Open; durable registries remain. |
| A10 | Prove adjudication and exact first-failure ordering. | Open; final proof qualification remains. |
| A11 | Prove checked money, conservation, and payment transitions. | Open; selected durable state remains. |
| A12 | Freeze real/cover nullifier and revision semantics. | Complete; exact SHA3-512 identity and KATs are sealed. |
| A13 | Prove identical authenticated state-operation shape for all slots. | Open; Gate 2E state binding remains. |
| A14 | Prove the ordered 12 fields as projections of wide authoritative values. | Open; final verifier/state convergence remains. |
| A15 | Prove SHA3-512 roots and master commitments over canonical records. | Open; durable state and H6 remain. |
| A16 | Complete the trace, AIR, composition, prover, verifier, and attacks. | Open; Wave 1 semantics and H4 prototype are partial package evidence. |

### Heterogeneous semantic proof and native hiding - 12 packages

| ID | Current deliverable | Status |
| --- | --- | --- |
| Z01 | Preserve the isolated validity baseline and its rejection boundary. | Complete only as historical validity evidence; removed backend is not a dependency. |
| Z02 | Integrate OS CSPRNG, deterministic-test separation, entropy failure, and zeroization. | Open. |
| Z03 | Mask every private semantic/bus/GKR message and terminal. | Open; native GKR masks pass, complete semantic simulator remains. |
| Z04 | Mask or eliminate every auxiliary, lookup, permutation, and interaction column. | Open. |
| Z05 | Randomize quotient/composition polynomials and splits. | Open. |
| Z06 | Enforce disjoint trace/commitment/evaluation domains and forbid raw openings. | Open. |
| Z07 | Inventory and mask every DEEP/FRI/bus/GKR/bridge/implicit query. | Open; H4 subset exists. |
| Z08 | Commit independent PCS masks before batching and preserve folding entropy. | Open; H4 mechanics exist, simulator remains. |
| Z09 | Version and bind the dual-PQ interactive transcript and complete statement. | Open; H4 replay passes, durable service/custody remains. |
| Z10 | Qualify SHA3-512, Fp16, PCS, GKR, hiding, and query parameters. | Open hard security gate; H5/H6 remain. |
| Z11 | Prove the complete simulator including abort, retry, crash, and artifacts. | Open. |
| Z12 | Qualify serialization, fail-closed parsing, fuzzing, and unlinkability. | Open; current mutation/rejection evidence is partial. |

### State, verifier, and custody - 12 packages

| ID | Current deliverable | Status |
| --- | --- | --- |
| P01 | Freeze canonical SHA3-512 leaf/node/empty/type/position encodings. | Candidate v1 implemented nonactivating in `wave3_nullifier_authority.py`; production freeze/review remains open. |
| P02 | Derive legacy and wide state independently from identical raw records. | Candidate v1 implemented and tested from A12 raw bytes; production integration remains open. |
| P03 | Prove authoritative 512-bit nullifier roots and transitions. | Candidate depth-64 predecessor/insertion transition implemented and independently replayed; Gate 2E/H6 and production custody remain open. |
| P04 | Implement governed wide-root registry, epochs, identifiers, and PQ authority. | Open. |
| P05 | Implement wide master/value commitments and fresh 512-bit salts. | Open; durable state and hiding remain. |
| P06 | Freeze one fixed-length canonical sidecar encoder/parser. | Open; selected suite/state identity remains. |
| P07 | Implement the production verifier interface for 12 fields plus sidecar. | Open. |
| P08 | Atomically advance authoritative wide and compatibility state. | Open; Gate 2E/Wave 3 remain. |
| P09 | Implement genesis, migration, activation, upgrade, rollback, and recovery. | Open. |
| P10 | Close stale/replay/mixed-profile/parser/partial-update/race attacks. | Open. |
| P11 | Replace RSA witness wrapping with approved PQ KEM plus AES-256. | Open. |
| P12 | Implement PQ signatures and provider-neutral HSM interfaces. | Open. |

### Cross-language, attack, leakage, and performance validation - 14 packages

| ID | Current deliverable | Status |
| --- | --- | --- |
| T01 | Freeze one vector schema for semantics, 12 fields, sidecar, state, proof, and receipt. | Open. |
| T02 | Add approved-claim KATs across every authoritative implementation. | Open. |
| T03 | Add KATs for every denial and exact priority. | Open. |
| T04 | Add dummy, padding, mixed, and all-denied fixed-shape KATs. | Open. |
| T05 | Add zero/minimum/maximum capacity and boundary-value KATs. | Open. |
| T06 | Add duplicate/replay/retry/correction/revision/nullifier KATs. | Open. |
| T07 | Add fabricated/stale policy/oracle/source/signer/epoch attacks. | Open. |
| T08 | Add money, canonical-field, serialization, and length attacks. | Open. |
| T09 | Add proof/profile/schema/artifact/domain/root/rebinding attacks. | Open. |
| T10 | Property-test and fuzz AIR, parsers, verifiers, and projections. | Open. |
| T11 | Scan proofs/logs/errors/crashes/artifacts and test unlinkability. | Open convergence gate. |
| T12 | Test shape, cadence, timing, roots, queries, and failures for leakage. | Open convergence gate. |
| T13 | Measure complete stage time, dimensions, memory, bytes, and attribution. | Open measurement gate. |
| T14 | Run every applicable language, proof, attack, integrity, and artifact gate. | Open convergence gate. |

### Operations and release engineering - 7 packages

| ID | Current deliverable | Status |
| --- | --- | --- |
| O01 | Implement provider-neutral PQ/hybrid KMS/HSM support. | Open. |
| O02 | Enforce entropy health, reuse detection, zeroization, rotation, and destruction. | Open. |
| O03 | Build hardened constant-work, isolated deployment profiles. | Open. |
| O04 | Secure swap, dumps, temporary files, logs, backups, and diagnostics. | Open. |
| O05 | Implement fixed cadence, bounded queues, cover, and uniform failures. | Open. |
| O06 | Add non-PHI monitoring, incident response, rollback, and drills. | Open. |
| O12 | Produce reproducible release evidence, deployment automation, and go/no-go. | Open. |

### Government API and oracle adapters - 8 packages

| ID | Current deliverable | Status |
| --- | --- | --- |
| I01 | Define the versioned provider-neutral adapter SDK and isolation boundary. | Open. |
| I02 | Implement identity, tenant, authorization, transport, and credential ports with simulators. | Open. |
| I03 | Implement claim-source and attachment adapters with exact provenance and bounds. | Open. |
| I04 | Implement eligibility, coverage, enrollment, and provider-status adapters. | Open. |
| I05 | Implement authorization, diagnosis/procedure, and document-fact adapters privately. | Open. |
| I06 | Implement fee, policy, ruleset, and governed-root adapters. | Open. |
| I07 | Implement payment, treasury, remittance, and reconciliation adapters. | Open. |
| I08 | Build shared conformance, chaos, retry, migration, and sandbox tests. | Open. |

### Containing based rollup and end-to-end deployment - 12 packages

| ID | Current deliverable | Status |
| --- | --- | --- |
| R01 | Pin the deployed EL/CL fork specs, EVM, and exact EVM-compatible based-validity stack; record Strawmap feature maturity without depending on drafts. | Open. |
| R02 | Build a reproducible multi-node, multi-fork local deployment with parameterized slots, gas/blob schedules, BAL/data modes, and transaction formats. | Open. |
| R03 | Integrate the production claim verifier and exact 12-field-plus-sidecar boundary; bind rollup proof, chain/fork, verifier, suite, state, and DA identities. | Open. |
| R04 | Implement atomic claim/nullifier/root/payment/wide-state transitions including BAL/CBAM separation, keyed nonce/recent-root adapters, migration, and receipt. | Open. |
| R05 | Implement and qualify the L2 state-transition prover against every supported final fork rule with differential execution vectors. | Open. |
| R06 | Implement Ethereum verification, settlement, finality, fork-aware timing, and verifier governance; never equate preconfirmation/head with finality. | Open. |
| R07 | Implement compulsory based ordering without a privileged canonical sequencer; test ePBS/FOCIL withholding, inclusion, reorg, duplicate, nonce, and replay failures. | Open. |
| R08 | Implement non-PHI proof/data coupling, payload/blob/cell publication, partial fetch, reconstruction, retention, withholding, migration, and corruption tests. | Open. |
| R09 | Implement bridge/escrow accounting, deposits, finalized withdrawals, replay binding, and conservation. | Open. |
| R10 | Implement opaque bounded forced inclusion, censorship resistance, exits, reorg-safe recovery, and privacy preservation. | Open. |
| R11 | Implement versioned EIP/fork adapters, timelocks, downgrade rejection, emergency rollback, and disaster recovery. | Open. |
| R12 | Verify claim-to-proof-to-L2-to-finalized-Ethereum plus rollback on the pinned baseline and explicit future-fork profiles. | Open. |

#### R01-R12 L1-lockstep execution order

This is the deterministic upgrade algorithm for every supported Ethereum fork. Do not infer it
from an EIP title:

1. **R01 inventory and classify:** create the versioned `ethereum_compat_manifest` from final
   canonical fork sources. For each included change record INHERIT, L1-COMPAT, L2-PARITY, OPTIONAL,
   or RESEARCH; exact producer/consumer interfaces; source/client commits; and disabled features.
2. **R02 reproduce both sides:** run old-fork, boundary-block, new-fork and mixed-client fixtures
   with exact EL/CL/Engine/network/EVM/DA configuration.
3. **R03-R05 bind correctness:** update the L1 verifier/settlement boundary and, only where the
   compatibility profile requires it, L2 executor/state/prover/verifier semantics. Bind fork ID,
   proof, state, data and receipt; never use host-trusted equivalence.
4. **R06-R10 bind containing safety:** update finality/timing, based ordering, DA reconstruction,
   bridge accounting, forced inclusion, exits and recovery for the new fork. Inherited L1 behavior
   must still pass adversarial conformance before receiving latency/throughput credit.
5. **R11 activate atomically:** version, migrate and roll back all affected adapters as one governed
   manifest. Optional features remain rejected unless independently selected. Unknown or partial
   support pauses new batches and preserves safe exits from the last supported finalized state.
6. **R12 qualify:** before mainnet activation, run the full synthetic claim-to-finalized-Ethereum
   path, canonical upstream/differential vectors, reorg, withholding, corruption, privacy scan,
   resource/capacity measurement and one rollback on the exact release candidates.
7. **Post-fork reconcile:** compare observed canonical blocks, receipts, DA, finality and bridge
   conservation to the manifest before claiming any inherited benefit.

The 23-EIP impact/trigger matrix in
`ETHEREUM_STRAWMAP_BASED_ROLLUP_COMPATIBILITY.md` is the input contract for step 1. This sequence
adds no package and cannot mark an R package complete without its existing acceptance evidence.

## Final independent Security Audit Gate - not counted

The five former O07-O11 rows are audit workstreams, not engineering packages. After all 93
internal packages close, one independent gate reviews the exact theorem and AIR; hiding and PQ
composition; state, custody, parser, verifier, contracts, rollup, bridge, supply chain, privacy,
side channels, and operations. Findings return to their owning internal package.

## Wave completion map

| Wave | Outcome | Completion condition |
| --- | --- | --- |
| 1 | Claim relation and executable AIR | Sealed at synthetic nonactivating boundary |
| 2 | Strict-PQ proof and throughput | Gate 2E, H5, and H6 all pass |
| 3 | Verifier, state, custody | Production verifier/state publication/custody/migration/rollback pass |
| 4 | Adapters and operations | I01-I08 plus applicable O/S packages pass simulator and conformance gates |
| 5 | Containing rollup | R01-R12 pass claim-to-Ethereum synthetic finality and recovery |
| 6 | Release candidate | Reproducible one-command deployment, rollback, evidence, and audit packet pass |

## Change and Git discipline

Before editing a trust boundary record the invariant/bottleneck, producer and consumers,
public/private I/O, encoding/domain/version/bounds, concurrency/retry/crash/rollback behavior,
adversarial substitutions, tests, decimal resource effect, throughput effect, and rejection path.

At every phase boundary:

- update `STATE.md` with raw evidence;
- update `CURRENT_TECH_STACK.md` only if active implementation changed;
- update this roadmap and the owning current architecture contract;
- put rejected designs only in `REJECTED_ARCHITECTURES.md` and dated narrative only in `history/`;
- run stale-path, documentation-invariant, focused, containing, protected-path, and diff checks;
- commit the smallest coherent verified phase with a clean tree; and
- record commit, tree, commands, counts, failures, warnings, skips, resources, risks, and one next
  dependency.

## Historical evidence routing

- Chronological raw checkpoints: dated sections of `../STATE.md`.
- Verbatim former roadmap: `history/IMPLEMENTATION_ROADMAP_THROUGH_2026-08-01.md`.
- Rejected/dominated designs: `REJECTED_ARCHITECTURES.md`.
- Original transfer evidence: `../WAVE2_HANDOFF_2026-07-26.md`.
- Current implementation truth: `CURRENT_TECH_STACK.md`.

Historical material can explain a decision but can never authorize execution.
