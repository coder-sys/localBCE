# Blind Ledger implementation roadmap

Updated: 2026-08-06

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
- complete-proof p95 below 35 seconds for K128/100-live and below 180 seconds for K512/500-live;
- retry-stable attempt identity with fresh proof randomness; and
- atomic binding of semantics, state, money, proof, verifier, schema, parameters, migration, and
  settlement.

No benchmark, implementation difficulty, or model limitation can waive an invariant.

## Current state

| Boundary | State | Verified evidence | Still required |
| --- | --- | --- | --- |
| Wave 1 | Sealed, synthetic, nonactivating | Exact fixed-shape semantics and global SHA3 schedule | Durable authoritative state and activation |
| H0-H3 | Core implementation complete | Exact bus, seven-layer B16 GKR, native masks, Construction 8.2 PCS, public coin, component verification, and conditioned simulator mechanics | Production integration and later-wave acceptance |
| H4 | Candidate proof boundary complete, nonactivating | Nineteen-claim typed state relation and linear square-free uniqueness are composed into the custom GKR/PCS/public-coin/parent/receipt boundary; one-run H4 baselines are 29.974129 s K128 and 120.460733 s K512 | Production suite identity and downstream verifier/state/custody work |
| Gate 2E | Sealed nonactivating terminal context | Exact state-bound H4 parent/receipt replay, candidate admission evidence, leakage scan, canonical ops, and independent CPU/native replay | Production state-plane selection and downstream activation gates; `proofSuiteId` remains null |
| H5 | Qualified, nonactivating | Exact 22-launch campaign; p95 32.360845 s K128 and 148.861885 s K512; RSS/scratch/pagefile/driver/stderr gates pass | Production integration and final suite identity |
| H6 | Qualified candidate evidence, nonactivating | Exact 12-obligation evidence manifest; all twelve records closed; strict-PQ ledger, simulator, grammar/KATs, attack corpus, supply-chain, reproducible-build, privacy, migration, H5, and Wave 3 boundary evidence | Production verifier/state/custody, release, final audit, and suite activation |
| Waves 3-5 | Wave 3, Wave 4, and Wave 5 internal engineering complete, nonactivating | P01-P12, I01-I08/O01-O06/O12, and R01-R12 source, acceptance tests, and local/synthetic reference evidence are complete; no production selection | Production verifier/state/custody, HSM/FIPS custody qualification, whole-product release, audit |
| Native candidate verifier | Per-proof candidate boundary complete, nonactivating | Fresh synthetic proof accepted by the standalone Rust envelope/package/transcript verifier; Python selector requires the exact native `OK` receipt and emits `BUILT_AUDIT_PENDING` only for that proof | Production `INativeStarkVerifier`, exact settlement ABI, HSM/FIPS custody, external anti-rollback, release seal, final audit, and operator activation |

The native candidate boundary is intentionally separate from the global operational selection. A
nonzero per-proof `proofSuiteId` is now derived from the selected parameters, program commitment, and
public-coin schedule and is admitted only after the standalone Rust verifier emits a bound `OK`
receipt. The legacy `ops/launch_blockers.json` planning state remains `NOT_DEPLOYMENT_READY` and
`UNSELECTED` with `proofSuiteId=null`; no activation or production credit flows from the local
candidate record. The next boundary is whole-product production verifier/state/settlement and
custody/release qualification, followed by the independent audit.

The live Strawmap compatibility contract was refreshed on 2026-08-05 from 60 underlying links
(23 EIPs and 37 non-EIP links). It confirms that Wave 5 must bind deployed L1 sequencing, fork,
execution, data-availability, and finality behavior through versioned adapters; Draft, Stagnant,
research, and optional items remain rejected-by-default or observation-only.

The two-lane K512 optimization promotion checks were completed on 2026-08-05 as a nonactivating
candidate review. A fresh one-warmup/ten-measured campaign over eleven distinct state bindings
returned K512 p95 `101.798191` seconds, mean `101.193590` seconds, four independently verified
shards on every run, maximum reported host/device peaks `605.774000`/`1976.484224` MB, maximum
externally sampled candidate-tree RSS `1467.465728` MB, zero scratch, zero pagefile growth, zero
driver events, and zero stderr. One earlier warmup is retained as a failed attempt because its
strict monitor observed `2` MB pagefile growth; the campaign was rerun without weakening the gate.
Cancellation killed the complete coordinator/worker/bridge tree and a fresh recovery rerun passed.
The generic scheduler now fails closed when Windows/POSIX process-tree termination cannot be
confirmed, with its focused suite at `19 passed`; it remains a separate Cairo/encrypted-worker
path and does not silently route ordinary claim jobs to this native coordinator. The native
coordinator defaults to two lanes for the native K512 run, including when a suite-bound identity is
supplied; `BL_SHARD_CONCURRENCY=1` reproduces the sealed serial boundary. `proofSuiteId` remains
null for this candidate, activation remains false, and the sealed H5/H6 evidence receives no
retroactive credit from this execution-mode change. The dedicated
`experiments/bl_pq512_crypto_foundation/k512_parallel_campaign_evidence.py` validator now checks
the separate exact 11-launch two-lane evidence contract. It independently validates the captured
campaign as `QUALIFIED_K512_TWO_LANE_NONACTIVATING` with campaign digest
`be029710c5da9ab74eb1e19925da3c179bea889758619a2c3e43c85ff16753c250d3afb0c12a6856be9e9c151c58c69a78a4d67e40ab92ddacf2d863fca3c7ee`;
this qualifies the native execution mode only, never H5/H6 or production activation. The three
published Source-Complete archives were refreshed only to carry the substantive source/documentation
changes and are not qualification evidence.

The default-path verification itself is fail-closed: two fresh launches with no concurrency
override selected two lanes and independently verified four shards, but the external monitor
rejected pagefile growth of `305` MB and `18` MB. The no-swap gate was not relaxed, and these
launches do not qualify H5/H6 or production admission.

The current committed refresh was attempted in four fresh exact-campaign directories and did not
receive credit: `r3` warmup grew pagefile usage by `743` MB, `r4` run 1 grew it by `177` MB after
an initial `-15` MB decrease, `r5` warmup grew it by `30` MB, and `r6` warmup grew it by `303` MB.
Every failing proof itself returned `status=verified`, four independent shards, empty stderr, and
zero driver events; the external pagefile gate rejected the campaign. These artifacts remain
preserved outside the checkout as failed evidence. No resource gate was weakened.

Current progress is 93 of 93 engineering packages complete internally at the local/nonactivating
engineering boundary. Wave 4 I01-I08 and O01-O06/O12
pass the local/synthetic simulator and conformance boundary described in
`docs/WAVE4_ADAPTERS_AND_OPERATIONS.md`; Wave 5 R01-R12 now pass the local/synthetic based-rollup
boundary described in `docs/WAVE5_BASED_ROLLUP.md`. Both waves remain nonactivating.
`proofSuiteId=null`, activation is false, real PHI and payments are forbidden, and the final
independent audit has not begun.

The state-composed H4 bridge is an integration shape only: the state lane currently checks operation/
snapshot field equality, authenticated slot index/order, Boolean presence, and empty-slot zeroing;
the Rust source builder and native Rust/Python snapshot decoders reject duplicate present keys before
source commitment. Proof-native high-cardinality uniqueness, membership/absence, and money/state-
conservation semantics remain outside the custom GKR/PCS relation, and no state-composed performance
or qualification credit is recorded.
The all-pairs uniqueness GKR control is implemented and independently verifies both phases, but its
measured 512-slot prover time is 426.679855 seconds, so it is rejected by the unchanged 180-second
complete-proof ceiling. It remains a differential/attack oracle; the selected H4 relation must use
a subquadratic uniqueness construction.

The linear-size square-free successor now independently verifies both phases and rejects duplicate,
tree-terminal, coefficient-terminal, and challenge-order attacks. Its K128 control measured
0.042439/0.046355/0.023395 seconds and its K512 control measured
0.698637/0.237447/0.072302 seconds for witness/prove/verify, respectively. Production composition
uses 614/882 authenticated K128/K512 rounds and 32,768/131,072 witness bytes. Its four virtual leaf
terminals reduce to twelve openings of existing H4 state columns plus two grouped committed
Bezout-table claims. The complete grammar is CPU-verified; fresh GPU proof and leakage evidence are
still required before Gate 2E, H5, backend-selection, or activation credit.

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
specific public-coin/quantum review; and, at the S3 screening boundary,
`TRANSPARENT_SHAKE256_1024` was held for missing complete H4 composition. Its exact
`BLTHC02` grammar, SHAKE commitment, coin-binding transcript identity, strict Rust parser,
and Python/Rust KAT are implemented as reference evidence. The later qualified context records
bounded H4/H5/H6 candidate evidence for this clean-room path without selecting a production suite.
The S3 screening record retains all five descriptors as fail-closed at that boundary; no production
candidate is admitted or assigned `proofSuiteId`.

The typed envelope v5 implements the candidate's correct pre-coin ordering and raw-opening
verification path into the H4 transcript, parent, composition, and receipt. This specific envelope
route remains focused implementation/mutation evidence and retains its screening flag
`complete_composition_missing`; the later qualified H4/H5/H6 context is separate
nonactivating evidence and does not turn this route into a production suite.

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
still rejects the candidate at the pre-qualification screening boundary because its full 256-bit
quantum binding/composition theorem and commit-before-coin lifecycle are not closed; the later
qualified context admits the H4 candidate nonactivating. The exact H5 campaign and
bounded H6 candidate-evidence manifest are now recorded as closed nonactivating evidence; the
production verifier, durable state/custody, and suite selection remain open.

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

S7 emits an explicitly unsealed historical handoff with the no-admission, deferred-H4,
complete-leakage, and strict-PQ blockers. Tracked `ops/` authority is verified; the former
sibling-layout blocker is closed. Timing is retained as measured reference-component evidence, not
selection credit. The later qualified context admits the H4 candidate nonactivating; no candidate
is activated.

The terminal Gate 2E ledger is now implemented in
`experiments/bl_pq512_crypto_foundation/gate_2e_terminal_ledger.py`. Its builder independently
replays the S4 composition and S5 checkpoints, verifies both C0 profile shapes and all seven C0
negative classes, checks the fixed 12-field boundary and public/private encoding boundary, and
recomputes the S6/S7 identities. It emits 11 ordered records. The historical pre-campaign record remains
preserved as `UNSEALED_BLOCKED_GATE_2E_TERMINAL_LEDGER` with
`ledger_digest_sha3_512=11f028eac01f5a880769f0cae7871b9449064793eebfe46cf8f69603f8646091007575b62c0ecdf5114ae53e1c220a4fe057f77a6c3b156f3a221de978b50644`.
The latest qualified context is `SEALED_GATE_2E_TERMINAL_LEDGER` with no blockers,
`h4_parent_bound=true`, `complete_proof_verified=true`, `proof_suite_id=None`, and
`activation_allowed=false`. A real nonactivating state plane is independently replayable and is
bound in that qualified context. The selected candidate/admission identity remains nonactivating
while production verifier/state/custody and release identity remain open.
The terminal ledger closes its simulator records from the active Construction 8.2 hiding KAT,
state GKR/square-free relation, authenticated public-coin bridge, and native independent verifier;
the rejected Circle simulator is not an evidence source. The active PCS KAT verifies exact
production query rank, conditioned state-GKR mechanics, and fresh abort/retry randomness. The exact
H5 campaign and bounded H6 candidate-evidence manifest are the current qualification records. The
ledger is sealed nonactivating evidence; it does not assign `proofSuiteId` or activate production.

### 2E-7 - seal the selection handoff

Record selected relation/commitment identities and parameters; source, lock, license, schema and
tool hashes; theorem status and remaining H6 obligations; all positive/negative/migration/recovery
results; component and complete measurements; rejected candidates; updated source/dataflow;
commit/tree/clean status/protected-path readback; and the exact H5 command, monitor, environment,
input generator, and STOP conditions.

The production/activating 2E boundary closes only when the selected state plane is present in the
H4 parent, transcript, proof, independent verifier, and atomic receipt. The current versioned
`BLHBSN02`/`BLHBB102` root-bus seam
and the v3 compact state-AIR/FRI component are prerequisite/native-consumption evidence for that
boundary, not its closure. The compact relation now algebraically links ordered operation rows to
both fixed-capacity snapshots through the v2 46-wide lookup grammar, and the H4 seam carries
authenticated slot indices with canonical row-order constraints. Native Rust and Python snapshot
decoders reject duplicate present keys. The C0 typed-state component now
composes the ordered-map/payment authorities and verifies root/cursor, slot-order, money, fixed
asset-registry, and replay/payment hash-port mutations for the K128 C0 witness. The native
coordinator consumes the version-4 state-binding AIR program/execution, verifies the
authority/root bindings, and maps
its 46,210 calls to the canonical H4 bus; the base replay/payment bus remains 46,208 calls. This
is component evidence inside the sealed nonactivating candidate context, not production state
selection. The
current typed component is `BL-PQ512-C0-TYPED-STATE-AIR-v5` with 56 tables and 79 lookups; its
source bundle remains packed into 8-lane rows, operation/log preimages use 64-lane vector lookup
messages with fixed live bits, and root messages use the canonical authority root columns
directly. Duplicate key-sentinel lookup transport is replaced by local byte/inverse identities
tied to the existing byte-range proof. Fixed scalar-copy positions are grouped into eight vector
source messages and one masked bundle destination. The full state relation is implemented at the
typed semantic-AIR/H4 readback seam, but the generic typed proof route is rejected by the
immutable resource preflight (`qualifies=false`, `modeled_peak_scratch_bytes=14944264032`,
`scratch_gate_pass=false`, `route_status=REJECTED_CURRENT_PERSISTENT_ORACLE_LIFETIME`,
`modeled_required_available_bytes=22975297336`).
It is still not a selected complete H4 GKR/PCS proof, no reviewed backend is admitted, and no
proof-suite identity is selected. Fresh native state-composed evidence is now present after the
source change: an earlier K128 record measured `36.077706` seconds, while the later clean native
run measured `complete_process_wall_seconds=33.077384` with zero pagefile growth and zero
post-launch driver events, within the owner-approved strict 35-second single-run limit. K512
verified four sequential shards with `complete_process_wall_seconds=153.860446` against its
180-second limit. These are H4 feasibility records; the separate exact H5 campaign and bounded H6
candidate-evidence manifest are the current qualification records.

## H5: repeated complete-proof qualification campaign

Prerequisites: sealed clean 2E commit; canonical ops identity; locked/offline builds; execution
manifest readback; clean driver-reset boundary; owner-authorized Brave-open operation; synthetic
unique inputs; external
process-tree, pagefile, device, scratch, stdout/stderr, and driver monitoring; all focused,
mutation, parser, state, migration, attack, and independent-verifier gates green.

Owner-authorized exception: Brave may remain open for exploratory, diagnostic, and H5 GPU runs.
The exclusive-host disqualification is removed; Brave being open is not itself a failure and does
not withhold H5 timing, resource, or driver-integrity credit. Credited H5 launches retain the
no-pagefile-growth, bounded RSS/scratch, and zero post-launch driver-event requirements, along with
fresh-input, correctness, provenance, cleanup, and empty-stderr checks.

The fail-closed preflight is implemented in
`experiments/bl_pq512_crypto_foundation/h5_qualification_preflight.py`. It independently replays
the sealed Gate 2E terminal ledger, validates the reference hardware record, verifies the exact
tracked `ops/` SHA3-512 authority inventory, and validates the
one-warm-up-plus-ten-unique-measured shape for both profiles (22 fresh launches total). The
historical blocked preflight is retained as zero-launch evidence; the current
`9c8cd9e4836576487431af85e3c1ae2b458d44580c144ceeda971f500cd9be279910ea88045761f59699d7b67a8520920a17f07b33d173ce9270d0d064d31693` remains historical zero-launch evidence. The current exact campaign passed source validation with `campaign_run_count=22`, `campaign_failed_run_count=0`, K128 p95 `32.360845` seconds, K512 p95 `148.861885` seconds, maximum process-tree RSS `850837504` bytes, and maximum scratch `0` bytes. The campaign digest is `199a1b1c7e553b73597f1bd3192a72db732529599da68d820bf072e2e2ee3dabe1d7dda2d72efbd9fd23e17a6b2366f70d51ed96d9c152483d3f34165e7bedf5`, and the execution-manifest digest is `999aef8a16f97a52e6ce6ead7b7470eea2fdc50f32d13e95a3a1e021cd093aef42f8f5a2420cd3f4e35f77a42ff161f791888b5905ec3fcdf8cb8f8765992545`. All launches passed the required correctness, provenance, empty-stderr, cleanup, pagefile, driver-event, and independent-verification checks under the approved Brave-open exception. The campaign's prover source identity is `47ca7dab146b56a85ebbf9d2d2fe797c4fee2fae`; later parser-only corrections are not substituted for it. The immutable 5,000,000,000-byte RSS/scratch and zero-swap gates were not changed.

| Profile | Uncounted warm-up | Unique measured attempts | Conservative p95 gate |
| --- | ---: | ---: | ---: |
| K128/100-live | 1 | 10 | maximum of ten < 35.000000 s |
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
the sealed Gate 2E context and qualified H5 campaign, validates the candidate registry remains
nonactivating with null suite/module identities, and emits exactly twelve H6 obligation records
with explicit measured/derived/inferred/unknown labels. The pre-manifest record above is retained
as historical blocked evidence. The current candidate record is
`QUALIFIED_H6_NONACTIVATING`: all twelve records are `CLOSED`, the aggregate blocker tuple is
empty, the evidence-manifest digest is
`e79b7199ed15e5d9d3719f0d8de7dbaa01627e9fbe8cd4823d3768e6b0d84dd2bea94526b1516de8b8f3c920439572d003ee5372e95747011fde022924b319fe`, and the manifest source digest is
`478d54ee1a2f187fd023777b16b73ec011922bb039dc106d53fc23c48eaea30b3a153b72f73823863e9c561a6126e92555dbaabaabbb3fda4abb2fccac3895db`. The
preflight never launches a prover, assigns `proofSuiteId`, or enables activation.

The H6 evidence capture passed the exact focused grammar/KAT tests, the 31-file attack corpus
with 229 passing tests, cross-language/Python/Rust KATs, targeted source/toolchain/SBOM
readback, two clean offline release builds with identical independent artifact readback, the
exact H5 resource record, privacy/zeroization/cleanup scanning, migration/recovery, and the
nonactivating Wave 3 boundary. These are qualification-ledger observations for the bounded
candidate, not a production proof or final audit.

## Whole-product package map

The 93-package denominator is fixed. Detailed closure criteria live in the owning specification or
architecture contract; this table prevents scope loss without mixing historical run narrative into
the execution plan.

| Group | IDs | Count | Current boundary |
| --- | --- | ---: | --- |
| Specification/security freeze | S01-S12 | 12 | Complete internally, nonactivating; production suite identity and audit remain open |
| Fixed-shape semantics/AIR | A01-A16 | 16 | Complete internally, nonactivating; production proof/state acceptance remains open |
| Heterogeneous proof/native hiding | Z01-Z12 | 12 | Complete internally, nonactivating; production proof-suite qualification remains open |
| State/verifier/custody | P01-P12 | 12 | P01-P12 internal engineering packages complete nonactivating; production acceptance remains open |
| Validation | T01-T14 | 14 | Complete internally, nonactivating; production qualification and audit remain open |
| Operations/release | O01-O06, O12 | 7 | Complete internally, nonactivating: local PQ custody reference, isolated profile, non-PHI audit, fixed cadence, incident drill, and reproducible release evidence pass |
| Government/oracle adapters | I01-I08 | 8 | Complete internally, nonactivating: versioned provider-neutral SDK, dual-PQ capsules, local simulators, bounded retry/idempotency/circuit behavior, migration, and conformance pass |
| Containing based rollup | R01-R12 | 12 | Complete internally, nonactivating: local/synthetic claim-to-finalized-L1, DA, bridge, forced-inclusion, fork-migration, and rollback evidence pass |
| Total |  | 93 | 93 complete internally, 0 open; all remain nonactivating |

The independent Security Audit Gate is not counted. Credentials, live endpoints, accounts,
signers, and legal authority are activation inputs, not missing engineering packages.

All **93 counted packages are internal engineering work**. The current source, tests, and
`tools/remaining_internal_conformance.py` receipt close every S01-S12, A01-A16, Z01-Z12, T01-T14,
P01-P12, I01-I08, O01-O06/O12, and R01-R12 package internally and nonactivating. This is not a
privacy, strict-PQ production-suite, live-rollup, HSM/FIPS, or audit claim. The remaining boundary
is production acceptance and external assurance, not an unimplemented internal package.

The 2026-08-05 Wave 2 internal reference boundary adds local/synthetic evidence for the exact
12-field projection, the 744-byte candidate sidecar, fixed-shape K128/K512 schedules, bounded
`BLPQPF01` parsing, public-binding mutation rejection, and software-PQ-KMS roundtrip behavior. Its
receipt is in `tools/wave2_internal_conformance.py` and its profile is
`ops/wave2_internal_release_profile.json`. The broader internal closure receipt is in
`tools/remaining_internal_conformance.py`; both are explicitly nonactivating reference results.
They close the internal package ledger but do not close the production proof, native production
verifier, suite selection, HSM/FIPS authority, live rollup, release activation, or audit gates.

### Specification and security freeze - 12 packages

| ID | Current deliverable | Status |
| --- | --- | --- |
| S01 | Reconcile current instructions, architecture, roadmap, state, and issues. | Complete; current documentation contract is active. |
| S02 | Freeze the product label and runtime configuration for the selected suite. | Complete internally, nonactivating: the candidate label and fail-closed runtime configuration retain `proofSuiteId=null` and activation false. |
| S03 | Freeze the exact 12-field compatibility meaning and forbidden public fields. | Complete; structural specification and tests pass. |
| S04 | Freeze the canonical authenticated sidecar outside the 12-field array. | Complete internally, nonactivating: the exact sidecar/envelope grammar and identity binding are fixed; production suite identity remains unset. |
| S05 | Maintain the malicious-prover, quantum, privacy, parser, worker, and governance threat model. | Complete as a repository specification. |
| S06 | Maintain the per-field security-notion and authority table. | Complete as a repository specification. |
| S07 | Close the complete 256-bit security/error/abort/multi-target budget. | Complete internally, nonactivating: the composed security ledger, abort/retry, and multi-target accounting are recorded; production audit remains open. |
| S08 | Prove the selected field, challenge, PCS, query, and zero-grinding parameters. | Complete internally, nonactivating: candidate parameter identities, authenticated interaction, and no-grinding rules are KAT-tested; suite identity remains unset. |
| S09 | Pin the selected PCS, transcript, tree, encoding, domains, and multi-target treatment. | Complete internally, nonactivating: the H4 candidate grammar and transcript/tree/domain identities are pinned; no production suite is selected. |
| S10 | Freeze genesis, migration, activation, rollback, rotation, and mixed-version behavior. | Complete internally, nonactivating: lifecycle, migration, rollback, rotation, and mixed-version failure behavior pass local conformance; external authority remains open. |
| S11 | Pin toolchains, dependencies, licenses, SBOM, and reproducible inputs. | Complete internally, nonactivating: locked offline inputs, license/SBOM records, and reproducible local evidence are present; whole-product production release qualification remains open. |
| S12 | Freeze the complete formal statement, invariants, errors, and acceptance gates. | Complete internally, nonactivating: the formal statement, fixed boundary, rejection classes, resource gates, and activation blockers are recorded and tested. |

### Fixed-shape semantics and claim AIR - 16 packages

| ID | Current deliverable | Status |
| --- | --- | --- |
| A01 | Freeze release capacities and profiles. | Complete internally, nonactivating: K128/K512 fixed-shape profiles and resource bounds are frozen; business activation approval remains outside this boundary. |
| A02 | Freeze bounded canonical witness serialization. | Complete internally, nonactivating: canonical witness, proof-body, sidecar, and state encodings are fixed and mutation-tested. |
| A03 | Freeze ordering, duplicates, encodings, and ranges across adapters and proof. | Complete internally, nonactivating: cross-language ordering, duplicate, canonical-field, and range rules pass conformance. |
| A04 | Freeze enabled/dummy/cover composition and collision rules. | Complete internally, nonactivating: enabled, denial, cover, collision, and fixed-slot composition are bound and attack-tested. |
| A05 | Prove witness-class-independent trace, query, proof, and operation shape. | Complete internally, nonactivating: approval/denial/cover shapes, schedules, and bounded failure behavior are checked; production proof qualification remains open. |
| A06 | Prove all adjudication gates and priority in the final proof. | Complete internally, nonactivating: gate ordering and first-failure semantics are covered by the executable relation and KAT corpus. |
| A07 | Prove canonical claim-source membership and authority. | Complete internally, nonactivating: source roots, provenance, provider-neutral adapters, and local authority binding pass; production registry deployment remains open. |
| A08 | Prove oracle facts, authorization, signer, epoch, and membership. | Complete internally, nonactivating: dual-PQ oracle/authorization evidence, freshness, absence, epoch, and membership paths pass local conformance. |
| A09 | Prove ruleset, policy, fee row, versions, and authority. | Complete internally, nonactivating: governed policy/ruleset/fee identities, versions, and downgrade rejection are covered by the reference paths. |
| A10 | Prove adjudication and exact first-failure ordering. | Complete internally, nonactivating: exact adjudication order and public rejection uniformity pass executable and attack tests. |
| A11 | Prove checked money, conservation, and payment transitions. | Complete internally, nonactivating: private payment state, conservation, lanes, and atomic successor binding pass the local relation/KAT boundary. |
| A12 | Freeze real/cover nullifier and revision semantics. | Complete; exact SHA3-512 identity and KATs are sealed. |
| A13 | Prove identical authenticated state-operation shape for all slots. | Complete internally, nonactivating: fixed 256-slot state operations, hidden salt-use insertion, padding, and replay shape are checked. |
| A14 | Prove the ordered 12 fields as projections of wide authoritative values. | Complete internally, nonactivating: the exact ordered 12-field projection is recomputed and atomically bound to wide state/proof identities. |
| A15 | Prove SHA3-512 roots and master commitments over canonical records. | Complete internally, nonactivating: canonical SHA3-512 roots, commitments, state transitions, and independent recomputation pass KATs. |
| A16 | Complete the trace, AIR, composition, prover, verifier, and attacks. | Complete internally, nonactivating: source, Rust component boundaries, whole-product KATs, mutation/attack suites, and conformance receipts pass; production verifier admission remains open. |

### Heterogeneous semantic proof and native hiding - 12 packages

| ID | Current deliverable | Status |
| --- | --- | --- |
| Z01 | Preserve the isolated validity baseline and its rejection boundary. | Complete only as historical validity evidence; removed backend is not a dependency. |
| Z02 | Integrate OS CSPRNG, deterministic-test separation, entropy failure, and zeroization. | Complete internally, nonactivating: OS entropy, test separation, failure handling, and zeroization/reuse controls pass local checks. |
| Z03 | Mask every private semantic/bus/GKR message and terminal. | Complete internally, nonactivating: native masks, terminal hiding, and fixed-shape simulator paths are covered; production theorem audit remains open. |
| Z04 | Mask or eliminate every auxiliary, lookup, permutation, and interaction column. | Complete internally, nonactivating: auxiliary/lookup/permutation/interaction coverage and no-raw-opening checks pass the local boundary. |
| Z05 | Randomize quotient/composition polynomials and splits. | Complete internally, nonactivating: quotient/composition masks and split identities are fixed, replayed, and mutation-tested. |
| Z06 | Enforce disjoint trace/commitment/evaluation domains and forbid raw openings. | Complete internally, nonactivating: domain separation, canonical openings, and raw-private-value exclusion are checked. |
| Z07 | Inventory and mask every DEEP/FRI/bus/GKR/bridge/implicit query. | Complete internally, nonactivating: the query inventory, bus/GKR/FRI bridge binding, and mask coverage are recorded and tested. |
| Z08 | Commit independent PCS masks before batching and preserve folding entropy. | Complete internally, nonactivating: pre-challenge commitment ordering, independent masks, folding entropy, and mutation rejection pass. |
| Z09 | Version and bind the dual-PQ interactive transcript and complete statement. | Complete internally, nonactivating: dual-PQ transcript versions, statement identity, replay order, and no-launch-Fiat-Shamir rules are bound. |
| Z10 | Qualify SHA3-512, Fp16, PCS, GKR, hiding, and query parameters. | Complete internally, nonactivating: parameter KATs, security ledger, native component checks, and candidate H5/H6 evidence pass; production suite remains unselected. |
| Z11 | Prove the complete simulator including abort, retry, crash, and artifacts. | Complete internally, nonactivating: the bounded hiding simulator covers abort/retry, crash/recovery, artifacts, and observable shape. |
| Z12 | Qualify serialization, fail-closed parsing, fuzzing, and unlinkability. | Complete internally, nonactivating: canonical serialization, parser mutation/attack coverage, privacy scans, and unlinkability checks pass local evidence. |

### State, verifier, and custody - 12 packages

| ID | Current deliverable | Status |
| --- | --- | --- |
| P01 | Freeze canonical SHA3-512 leaf/node/empty/type/position encodings. | Complete internally, nonactivating: canonical depth-64 encodings and independent replay tests pass; production freeze/review remains open. |
| P02 | Derive legacy and wide state independently from identical raw records. | Complete internally, nonactivating: both derivations consume the exact A12 bytes and differential tests pass; production integration remains open. |
| P03 | Prove authoritative 512-bit nullifier roots and transitions. | Complete internally, nonactivating: predecessor/insertion transitions recompute both roots and reject stale/mutated witnesses; production custody remains open. |
| P04 | Implement governed wide-root registry, epochs, identifiers, and PQ authority. | Complete internally, nonactivating: canonical manifest-derived roots, durable append-only registry readback bound into state create/reopen/refresh, dual PQ authorization, and monotonic rotation pass; production governance remains open. |
| P05 | Implement wide master/value commitments and fresh 512-bit salts. | Complete internally, nonactivating: private batch/value commitments bind a fresh salt-use tag and hidden payment-root successor without serializing the salt or amount; production custody/hiding acceptance remains open. |
| P06 | Freeze one fixed-length canonical sidecar encoder/parser. | Complete internally, nonactivating: the exact 744-byte sidecar is wrapped by one strict sidecar/proof envelope and bound through the verifier context; selected suite identity remains open. |
| P07 | Implement the production verifier interface for 12 fields plus sidecar. | Complete internally, nonactivating: typed candidate outputs, exact identity binding, local Rust BLSB v2 component verification, and fail-closed inactive verification pass; no production `INativeStarkVerifier` or selected proof suite exists. |
| P08 | Atomically advance authoritative wide and compatibility state. | Complete internally, nonactivating: exact 256-slot A12 replay plus hidden salt-use insertion, private payment-root recomputation, full S10 tuple, proof/sidecar/state binding, atomic write/readback, and lock boundary pass; production custody remains open. |
| P09 | Implement genesis, migration, activation, upgrade, rollback, and recovery. | Complete internally, nonactivating: genesis, monotonic context migration/upgrade, known-checkpoint rollback, dual-PQ signed recovery anchor, and activation fail-closed tests pass; external recovery authority remains open. |
| P10 | Close stale/replay/mixed-profile/parser/partial-update/race attacks. | Complete internally, nonactivating: stale roots, batch replay, hidden salt reuse, mixed profiles, malformed/versioned state, write failure, lock, forged recovery, registry mutation, Rust binding mutation, and custody anti-rollback tests pass; production attack closure remains open. |
| P11 | Replace RSA witness wrapping with approved PQ KEM plus AES-256. | Complete internally, nonactivating: locked ML-KEM-1024/AES-256-GCM software/reference envelope keeps plaintext private and rejects key, version, flag, length, and tamper changes; HSM custody remains open. |
| P12 | Implement PQ signatures and provider-neutral HSM interfaces. | Complete internally, nonactivating: dual ML-DSA/SLH-DSA ports, conformance reporting, authority rotation, and downgrade/forgery rejection pass; HSM/FIPS qualification and production authority remain open. |

### Cross-language, attack, leakage, and performance validation - 14 packages

| ID | Current deliverable | Status |
| --- | --- | --- |
| T01 | Freeze one vector schema for semantics, 12 fields, sidecar, state, proof, and receipt. | Complete internally, nonactivating: the canonical whole-product vector schema and manifest cover every fixed boundary. |
| T02 | Add approved-claim KATs across every authoritative implementation. | Complete internally, nonactivating: approved-claim KATs pass across Python, Rust, and the local reference boundaries. |
| T03 | Add KATs for every denial and exact priority. | Complete internally, nonactivating: denial, priority, and first-failure KATs pass without changing public shape. |
| T04 | Add dummy, padding, mixed, and all-denied fixed-shape KATs. | Complete internally, nonactivating: dummy, cover, mixed, and all-denied vectors pass fixed-shape and privacy checks. |
| T05 | Add zero/minimum/maximum capacity and boundary-value KATs. | Complete internally, nonactivating: capacity, range, zero/minimum/maximum, and boundary vectors pass. |
| T06 | Add duplicate/replay/retry/correction/revision/nullifier KATs. | Complete internally, nonactivating: duplicate, replay, retry, correction, revision, and nullifier KATs pass. |
| T07 | Add fabricated/stale policy/oracle/source/signer/epoch attacks. | Complete internally, nonactivating: fabricated/stale authority, oracle, source, signer, and epoch attacks fail closed. |
| T08 | Add money, canonical-field, serialization, and length attacks. | Complete internally, nonactivating: money conservation, canonical-field, encoding, length, and parser attacks fail closed. |
| T09 | Add proof/profile/schema/artifact/domain/root/rebinding attacks. | Complete internally, nonactivating: proof/profile/schema/artifact/domain/root/rebinding and receipt-splicing attacks fail closed. |
| T10 | Property-test and fuzz AIR, parsers, verifiers, and projections. | Complete internally, nonactivating: property, mutation, parser, AIR, verifier, and projection coverage passes the local suite. |
| T11 | Scan proofs/logs/errors/crashes/artifacts and test unlinkability. | Complete internally, nonactivating: privacy/artifact scans and unlinkability checks pass; production side-channel audit remains open. |
| T12 | Test shape, cadence, timing, roots, queries, and failures for leakage. | Complete internally, nonactivating: fixed cadence, shape, root/query, timing, and uniform-failure checks pass. |
| T13 | Measure complete stage time, dimensions, memory, bytes, and attribution. | Complete internally, nonactivating: bounded H4/H5 and K512 two-lane candidate measurements are recorded without relaxing resource/no-swap gates. |
| T14 | Run every applicable language, proof, attack, integrity, and artifact gate. | Complete internally, nonactivating: the 1,733-test collection, bounded Python groups, Rust release gates, integrity checks, and archive inputs are reconciled. |

### Operations and release engineering - 7 packages

| ID | Current deliverable | Status |
| --- | --- | --- |
| O01 | Implement provider-neutral PQ/hybrid KMS/HSM support. | Complete internally, nonactivating: provider port and software ML-KEM-1024/AES-256-GCM reference pass conformance; live HSM/FIPS authority remains an activation/audit boundary. |
| O02 | Enforce entropy health, reuse detection, zeroization, rotation, and destruction. | Complete internally, nonactivating: root-only lifecycle, entropy sample, nonce guard, zeroization, monotonic rotation, and destruction pass. |
| O03 | Build hardened constant-work, isolated deployment profiles. | Complete internally, nonactivating: network/live-credential/swap/core-dump rejection and fixed resource profile pass. |
| O04 | Secure swap, dumps, temporary files, logs, backups, and diagnostics. | Complete internally, nonactivating: non-PHI append-only audit and generated/secret path rejection pass. |
| O05 | Implement fixed cadence, bounded queues, cover, and uniform failures. | Complete internally, nonactivating: exact-slot cover cadence, bounded queue, and one public rejection class pass. |
| O06 | Add non-PHI monitoring, incident response, rollback, and drills. | Complete internally, nonactivating: opaque event inventory and pause/recovery/resume drill pass. |
| O12 | Produce reproducible release evidence, deployment automation, and go/no-go. | Complete internally, nonactivating: offline conformance runner, explicit source allowlist, deterministic manifest, and fail-closed profile pass. |

### Government API and oracle adapters - 8 packages

| ID | Current deliverable | Status |
| --- | --- | --- |
| I01 | Define the versioned provider-neutral adapter SDK and isolation boundary. | Complete internally, nonactivating: `app/wave4_adapters.py` freezes the versioned identity/request/capsule ports and networkless boundary. |
| I02 | Implement identity, tenant, authorization, transport, and credential ports with simulators. | Complete internally, nonactivating: synthetic transport and handle-only credential ports pass bounded failure and secret-rejection tests. |
| I03 | Implement claim-source and attachment adapters with exact provenance and bounds. | Complete internally, nonactivating: source-byte commitments, schema/normalization identity, freshness, completeness, and bounds pass. |
| I04 | Implement eligibility, coverage, enrollment, and provider-status adapters. | Complete internally, nonactivating: each capability has a versioned synthetic provider and private-fact response path. |
| I05 | Implement authorization, diagnosis/procedure, and document-fact adapters privately. | Complete internally, nonactivating: private facts remain outside the signed public capsule and absence is authenticated. |
| I06 | Implement fee, policy, ruleset, and governed-root adapters. | Complete internally, nonactivating: governed capability identity, epoch, provenance, and downgrade rejection pass. |
| I07 | Implement payment, treasury, remittance, and reconciliation adapters. | Complete internally, nonactivating: payment-related facts are private in memory and public evidence contains only commitments/status. |
| I08 | Build shared conformance, chaos, retry, migration, and sandbox tests. | Complete internally, nonactivating: 22 capabilities pass authentication, idempotency, privacy, retry/circuit, migration, and sandbox checks. |

### Containing based rollup and end-to-end deployment - 12 packages

| ID | Current deliverable | Status |
| --- | --- | --- |
| R01 | Pin the deployed EL/CL fork specs, EVM, and exact EVM-compatible based-validity stack; record Strawmap feature maturity without depending on drafts. | Complete internally, nonactivating: versioned baseline/future-shadow manifest records all 23 EIPs, client/Engine/EVM pins, disabled optional features, and the external-classical boundary. |
| R02 | Build a reproducible multi-node, multi-fork local deployment with parameterized slots, gas/blob schedules, BAL/data modes, and transaction formats. | Complete internally, nonactivating: five-node EL/CL/L2 deterministic sandbox covers baseline and future-shadow profiles, fixed slots, gas/blob limits, BAL, transaction format, and commitment-only DA modes. |
| R03 | Integrate the production claim verifier and exact 12-field-plus-sidecar boundary; bind rollup proof, chain/fork, verifier, suite, state, and DA identities. | Complete internally at the synthetic integration boundary: exact ordered 12 fields, 744-byte sidecar, candidate suite, chain/fork/state/DA context, and fail-closed reference verifier binding pass; production ZK verifier selection remains open. |
| R04 | Implement atomic claim/nullifier/root/payment/wide-state transitions including BAL/CBAM separation, keyed nonce/recent-root adapters, migration, and receipt. | Complete internally, nonactivating: atomic state successor, replay/stale rejection, separate BAL/CBAM commitments, keyed nonce root, disabled recent-root adapter, and settlement binding pass. |
| R05 | Implement and qualify the L2 state-transition prover against every supported final fork rule with differential execution vectors. | Complete internally, nonactivating: deterministic transition proof and baseline/future-shadow differential vectors share one explicitly bound L2 semantics identity. |
| R06 | Implement Ethereum verification, settlement, finality, fork-aware timing, and verifier governance; never equate preconfirmation/head with finality. | Complete internally, nonactivating: head/safe/finalized distinction, finalized-only settlement, state/proof root equality, and dual-PQ governance approval pass. |
| R07 | Implement compulsory based ordering without a privileged canonical sequencer; test ePBS/FOCIL withholding, inclusion, reorg, duplicate, nonce, and replay failures. | Complete internally, nonactivating: L1-origin opaque ordering, inclusion-list withholding, deterministic duplicate/nonce checks, forced inclusion, and execution-validation gate pass without a sequencer input. |
| R08 | Implement non-PHI proof/data coupling, payload/blob/cell publication, partial fetch, reconstruction, retention, withholding, migration, and corruption tests. | Complete internally, nonactivating: fixed-size commitment cells, partial/reconstruction/retention/corruption checks, commitment-preserving DA migration, and proof/data binding pass. |
| R09 | Implement bridge/escrow accounting, deposits, finalized withdrawals, replay binding, and conservation. | Complete internally, nonactivating: commitment-shaped finalized deposits, delayed withdrawals, recipient/value binding, replay domains, and one-to-one accounting conservation pass. |
| R10 | Implement opaque bounded forced inclusion, censorship resistance, exits, reorg-safe recovery, and privacy preservation. | Complete internally, nonactivating: bounded opaque forced queue, inclusion enforcement, delayed safe exit, unknown-fork pause, and governed recovery pass. |
| R11 | Implement versioned EIP/fork adapters, timelocks, downgrade rejection, emergency rollback, and disaster recovery. | Complete internally, nonactivating: manifest-bound future-shadow activation, dual-PQ approval, timelock, unknown/partial pause, and emergency rollback to the pinned baseline pass. |
| R12 | Verify claim-to-proof-to-L2-to-finalized-Ethereum plus rollback on the pinned baseline and explicit future-fork profiles. | Complete internally, nonactivating: offline receipt covers synthetic claim, L2 proof, finalized L1 settlement, DA migration, bridge exit, future-shadow activation, unknown-fork pause, and rollback. |

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
`ETHEREUM_STRAWMAP_BASED_ROLLUP_COMPATIBILITY.md` is the input contract for step 1. The Wave 5
fixture exercises this sequence locally; it adds no package, does not claim deployed Ethereum
compatibility, and does not authorize activation.

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
| 4 | Adapters and operations | I01-I08 and O01-O06/O12 pass simulator and conformance gates; Wave 4 is internally complete and nonactivating |
| 5 | Containing rollup | R01-R12 pass claim-to-Ethereum synthetic finality and recovery | Complete internally, nonactivating |
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
