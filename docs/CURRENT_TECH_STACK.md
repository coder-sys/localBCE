# Blind Ledger current technical stack

Updated: 2026-08-02

Status: canonical current-stack index. If an older checkpoint conflicts with this file, `STATE.md`,
`ARCHITECTURE.md`, or `docs/IMPLEMENTATION_ROADMAP.md`, the newer current files win. Historical
measurements and rejected designs are evidence, never executable fallbacks.

Former active roadmap, throughput, coprocessor, optimization-review, and crate-README narratives
are physically isolated under `docs/history/`. They preserve provenance but are never part of the
active read order. `docs/REJECTED_ARCHITECTURES.md` owns rejection decisions.

The compulsory containing design is an Ethereum-settled based validity rollup. The complete live
Strawmap/EIP compatibility surface and maturity rules are in
`docs/ETHEREUM_STRAWMAP_BASED_ROLLUP_COMPATIBILITY.md`. That prospective outer-chain contract
classifies every item as INHERIT, L1-COMPAT, L2-PARITY, OPTIONAL, or RESEARCH and supplies the
lockstep fork lifecycle. It does not change the current H4 proof implementation or mark any
R01-R12 package complete.

## Current product boundary

Blind Ledger is a nonactivating zero-knowledge payment-system prototype. Wave 1 is the sealed
synthetic semantic relation. Wave 2 is the strict post-quantum proof and throughput-recovery wave.
Six of 93 engineering packages are complete. `proofSuiteId=null`, activation is false, and real
PHI or payments are forbidden.

Gate 2E-0/S0 is implemented as a synthetic C0 control fixture plus a separate fresh-process
measurement module. Gate 2E-1/S1 is implemented as 13 bounded descriptors plus strict
envelope/transition codecs with no claim or settlement imports. Gate 2E-2/S2 now has scalar C1
dense/sparse, C2 dictionary, C3 touched-projection, and C4 shuffle-consistency controls plus an
independent replay verifier and C0 differential parity harness. S2 freezes no state relation or
commitment: candidate roots remain differential identities, the commitment backend and proof suite
remain unselected, and activation is forbidden.

Gate 2E-3/S3 now has a common fixed-width masked commitment/opening reference, exact candidate
parameter identities, dual-PQ authenticated public-coin evidence, and an independent opening
verifier in `pq_commitment_screening.py`. Five descriptors are now screened: the three isolated
lattice families, the retired 512-bit hash-pad control, and the clean-room
`TRANSPARENT_SHAKE256_1024` reference candidate. All five remain rejected: the lattice families
lack pinned construction evidence, the retired hash-pad control fails its public-coin/quantum
composition review, and the new candidate is rejected only for `complete_composition_missing`.
This is screening evidence only; no PCS, state plane, H4 binding, or activation decision is closed.

Gate 2E-4/S4 now has a synthetic non-spliceable composition reference in
`atomic_state_composition.py`. It keeps the scalar relation candidate distinct from the screened
commitment-backend identity, independently replays S2, derives the fixed 12-field projection and
BLTR transition, verifies the S3 authenticated opening, and binds a deferred H4 identity,
independent-verifier identity, attempt identity, and receipt. The canonical relation payload
hashes private membership material instead of serializing raw keys. S4 focused and attack tests
pass 6/6. This is reference binding evidence only: no backend is admitted, no `proofSuiteId` is
set, and activation remains false.

Gate 2E-5/S5 now has a synthetic migration/recovery controller in
`state_migration_recovery.py`. It independently verifies S4 before preparing a state publication,
publishes only store-owned pending CAS records, preserves the logical state root/manifest/sequence
across a versioned layout/parameter/verifier migration, and restores only known complete
checkpoints at strictly newer epochs. Focused positive/attack tests pass 10/10. This is reference
failure/equivalence evidence only: no production migration theorem, durable custody, backend
selection, `proofSuiteId`, or activation is closed.

Gate 2E-6/S6 and 2E-7/S7 now have a reference measurement/selection ledger in
`gate_2e_selection.py`. It measures the identical synthetic S2/S3/S4 component twice for each
screened backend and both K128/K512 profiles, recomputes the S3 rejection reasons, and refuses to
grant timing credit when no backend is admitted. All five backends remain rejected; C0 is retained
as an unselected control, complete warm-up/complete-boundary runs are not authorized, and the
selection handoff is explicitly unsealed. The five-by-two-by-two observation count is 20 derived
reference observations. Focused positive/attack tests pass 6/6.

The terminal Gate 2E evidence boundary is now implemented in
`gate_2e_terminal_ledger.py`. It independently replays S4, derives S5 checkpoints, checks the
frozen C0 positive/negative parity and exact 12-field boundary, checks that raw private relation
material is absent from its public encoding, and binds the S6/S7 decision/handoff identities. It
rejects a caller-supplied state proof unless its independently replayed profile, parameter,
capacity, epoch, sequence, old/new roots, manifest, and exact ordered 12-field projection match
the independently replayed S4 transition and S5 checkpoints. This is a fail-closed pre-admission
check, not proof-native H4 equality or state-plane admission. It
records 11 ordered obligation records for atomic composition, the semantic/PCS/public-coin
simulator, fixed-shape leakage, state/proof receipt, migration, strict-PQ selection, canonical
ops, and independent verification. The ledger is reference-only and unsealed; its current blockers
are `no_backend_admitted`, `complete_simulator_missing`, `complete_leakage_scan_missing`,
`h4_atomic_binding_deferred`, and `proof_suite_unselected`. The ops obligation is closed.

The smallest real state boundary is implemented in
`experiments/bl_pq512_crypto_foundation/state_plane.py`. It owns fixed-shape SHA3-512 roots,
all-slot old/new replay, a 512-bit pad-masked SHA3 commitment, independent replay verification,
and crash-safe compare-and-swap publication. Its decoder rejects every presence byte except exact
`0` or `1`, requires byte-for-byte canonical re-encoding, and therefore rejects corrupted
persisted state before root comparison or publication. The native H4 coordinator accepts the
legacy `state-file:<path>` version-2 envelope and the new nonactivating version-3 envelope emitted
by `state_air_proof.py`. Version 3 carries a compact packed state-relation AIR, a private streamed
dual-PQ FRI package, and a fixed evidence record. Rust independently replays the transition,
evaluates the compact AIR, including the fixed-capacity before/after snapshot tables and their
46-wide operation-to-snapshot lookups, compares every packed trace column with the exact parsed
operations, checks the ordered 128-value roots, decodes/verifies the FRI package, and recomputes
the SHA3-512 state/AIR identities before constructing the v3 parent. This closes the native
state-file component boundary; it does not claim that the full state relation is inside the custom
H4 GKR/PCS proof. The v3 parent binds the full state statement, transition, commitment, verifier, attempt,
receipt, exact ordered 12-field projection, compact AIR/proof-package identities, and
fragment/composition digests. The authenticated interactive child session and schedule bind the
same state context before challenges; each child shard must echo the exact state proof grammar, and
the atomic receipt binds the same full context. The full state-root AIR remains available as the
version-2 compatibility path, while the compact path removes duplicate SHA3 Boolean traces and
keeps root hashing on H4's shared bus. Native v3 consumption is independently tested against a
real streamed proof and trace/package mutations. A versioned state-root bus bridge now appends
exactly two fixed-capacity SHA3 calls to the authenticated B16 source when a state binding is
supplied: `BLHBSN02`/version 2 snapshots and `BLHBB102`/version 2 boundaries use capacity
`claim_slots*137+512` (18,048 for K128 and 70,656 for K512), adding 266 and 1,040 live
permutations respectively. The base `BLHBSN01`/`BLHBB101` profile remains byte-compatible. No
reviewed PQ commitment backend is available, `proofSuiteId` remains null, and activation remains
closed.

## Gate 2E state-composed bus and candidate boundary

The smallest proof-native state seam currently implemented is the versioned hash-bus composition
in `experiments/bl_pq512_crypto_core/src/hash_bus.rs`,
`src/hash_bus_snapshot.rs`, `src/hash_bus_b16_boundary.rs`, and the snapshot-to-B16 converter.
It clones the accepted base descriptor and appends two root messages whose canonical body is
`STATE_ROOT_DOMAIN || len(snapshot.encoded).to_bytes(4,"big") || snapshot.encoded`. The resulting
live permutation totals are 113,996 for K128 and 412,446 for K512; exact cross-language descriptor
commitments are recorded in `STATE.md`. The B16 worker derives these totals from the descriptor
capacity rather than a duplicated constant, and a durable sparse-boundary test covers wire-major
packing and the Windows little-endian path. This is real authenticated source/child-boundary
coverage, not a new H4 proof or production CUDA result.

The clean-room PQ candidate is `TRANSPARENT_SHAKE256_1024`, parameter identity
`BL-PQ512-TRANSPARENT-SHAKE256-1024-V1`. It commits before the authenticated public coin with
SHAKE256-1024, a 128-byte mask, and a 128-byte commitment; its conservative ledger is 341-bit
quantum collision, 32-bit multi-target loss, 309-bit effective binding, and 480-bit effective
hiding. Its review decision is `REVIEWED_CANDIDATE_H4_COMPOSITION_OPEN`: the candidate is
reference-only and rejected solely because complete H4 composition, the full simulator, and the
cross-module leakage/security closure are not complete. The exact candidate grammar, SHAKE
commitment, coin-binding transcript identity, strict parser, and Python/Rust KAT now exist in
`transparent_hash_code_candidate.py` and `src/transparent_hash_code.rs`; this is implementation
parity evidence only and does not admit the backend. The old SHA3 hash-pad candidate remains
rejected for its own public-coin and 512-bit-collision deficiencies. No candidate is selected.

## Wave 3 P01-P03 candidate boundary

The first Wave 3 state work is now concrete but nonactivating in
`experiments/bl_pq512_crypto_foundation/wave3_nullifier_authority.py`. It accepts only the
frozen A12 attempt-v1 and cover-v2 preimages, derives the legacy felt with the independent
Poseidon path and the authoritative 512-bit key with SHA3-512 from those identical raw bytes,
and rejects historical cover-v1 framing. Its depth-64 sparse ordered tree binds leaf, empty,
node, and root type, position, height, entry count, and append index in canonical SHA3-512
preimages. A two-path predecessor/insertion witness recomputes both old and new wide roots;
the authority stages cloned legacy and wide trees and swaps them together only after independent
replay. Focused tests cover type/position binding, cover profile rejection, stale transitions,
path mutation, three committed transitions, and a 40-record stress chain.

This is candidate state evidence, not a production verifier, a proof-native transition, durable
anti-rollback custody, a Gate 2E selection, or a package-completion claim. `proofSuiteId` remains
null, activation remains false, the six-of-93 count is unchanged, and PHI/payments remain
forbidden. P04-P12 and the production integration gates remain open.

## Round 1 diagnostic implementation boundary

The proof-core DEEP path now has a verified LogUp geometry correction: only tables that participate
in a lookup are given a work domain at least as large as their committed evaluation domain. The
disk-backed DEEP column transforms use deterministic canonical merge order with a bounded maximum of
eight parallel workers and fail closed on worker panic or result-shape drift. A compact six-table,
three-lookup diagnostic then completed the selected Rust FRI verifier and Python authenticated-
transcript replay with `proof_bytes=17,352,533`, `query_count=945`, `fri_layers=15`, and measured
`worker_wall_ms=537,419`. The program was intentionally incomplete: it omitted the full SHA3 round
tables, the high-cardinality state-slot lookup, and proof-native H4 state equality. The result is
therefore implementation evidence only; it does not select a PQ backend, close Gate 2E, qualify
H4/H5/H6, set `proofSuiteId`, or permit activation. The derived resource model is not a resident
peak measurement, and the 537.419-second wall time misses the frozen K512 complete-proof target.

## Round 2 proof-native state component boundary

The compact state relation is now a real nonactivating proof component in
`experiments/fixed_shape_claim_air/state_relation_executable_air.py` and
`experiments/bl_pq512_crypto_foundation/state_air_proof.py`. It packs each 64-byte key/value
into 22 three-byte M31 chunks, keeps the two state roots as the only AIR public values, and links
each operation's before/after slot to a fixed-capacity 46-column snapshot table with a full-width
multiset lookup. The fixed index columns enforce one ordered row per slot; empty-slot zeroing and
presence boolean identities remain local constraints. SHA3 root evaluation stays on H4's already
authenticated state-root bus. The relation program identity is now
`BL-PQ512-STATE-RELATION-AIR-v2`. The v3 private envelope
(`BLSB01` version 3 / `BLSA02`) carries the compact program/execution, a bounded private
`BLPQSPK1` package, and a fixed digest-only evidence record. The native verifier checks the exact
old/new operation and snapshot columns against the parsed state witness before independently
verifying the selected v2 FRI proof and its dual-PQ challenge bundle. A public sidecar still contains only
fixed-width roots/digests and the ordered projection; private snapshots, operations, masks, trace,
claims, and proof bytes remain in the private envelope/package.

Measured fixture evidence on 2026-08-02 (capacity 8, not a K128/K512 qualification run):

```text
worker_result=STATE_AIR_PROOF_COMPONENT_VERIFIED_NONACTIVATING
program_id=BL-PQ512-STATE-RELATION-AIR-v2
program_commitment=9a9df7f23eaa1f31f276df87e681268a40a10f4629926826de20131194197ea9968874a216eaa978e9df4818ea5756b22b5991375db25f4564ee8f184c4e078c
execution_commitment=a4fc9c65ab0273d412bfd67d6b8ddf18de8255852893bd5ce986a9a37bbccb5140c6f202f3d26f7109e46979fad206498659536dcddac93a698d97a1f1ae3a48
package_commitment=bd07d54f37243c3b78e5ed3cec6ca4f0c1e2585798a032e424498c6e1db3a001a02e4776b312d193c868a35372fb05f325614a965172452c31c97de73ce9440a
proof_bytes=11616597
proof_package_bytes=11684436
binding_bytes=11741761
worker_and_python_replay=success
scratch_entries_after=0
native_state_file_verifier=success
snapshot_trace_mutation=ERR:state_binding_air_execution:LookupMultisetMismatch
```

This closes the native state-file component boundary, not Gate 2E admission. The full state
relation is still not algebraically composed inside the custom H4 GKR/PCS proof; the selected
commitment backend, complete simulator, leakage/security composition, repeated resource campaign,
and proof-suite admission remain open. `proofSuiteId=null`, activation remains false, H5 has not
started, and no production CUDA or real PHI/payment data was used.

## How a successor must interpret this repository

This file is deliberately model-independent. A successor must not infer the current design from
file age, benchmark names, historical section order, or remembered chat context. Apply this
precedence order whenever two statements appear to conflict:

1. executable source and fail-closed tests;
2. the newest verified section of `../STATE.md`;
3. this file and `../ARCHITECTURE.md`;
4. the current-execution section of `IMPLEMENTATION_ROADMAP.md`;
5. specialized current architecture contracts;
6. dated historical evidence; and
7. `REJECTED_ARCHITECTURES.md`, which can explain a rejection but can never authorize code.

Words have exact meanings:

| Term | Meaning |
| --- | --- |
| Implemented | Source exists and its focused tests pass. It may still be uncomposed or unqualified. |
| Verified | The named independent verifier or readback check ran successfully on the named artifact. |
| Measured | The value came from the recorded run and boundary; it is not a projection. |
| Prototype-accepted | One complete synthetic attempt passed the stated functional, verifier, latency, and resource gates. |
| Selected | The architecture decision is frozen for the next containing gate. Selection is not activation. |
| Qualified | Every repeated campaign, theorem, parser, mutation, reproducibility, and resource gate for the named scope passed. |
| Activated | Production configuration identifies the suite and permits real operation. This has not happened. |
| Audited | The final independent audit accepted the finished release candidate. This has not happened. |

If evidence supports only a weaker term, the stronger term is forbidden. In particular, H4 is
prototype-accepted, not H5-qualified, H6-qualified, activated, production-ready, or audited.

## Frozen system invariants

Every implementation and optimization must preserve all of the following simultaneously:

- exact Wave 1 approval, denial, cover, replay, revision, payment, and money-conservation semantics;
- the exact ordered 12-field external ABI, while keeping the full-width authenticated sidecar and
  proof metadata outside that compatibility array;
- fixed K128/K512 observable shape, fixed proof grammar, native witness hiding, and no PHI, exact
  private amounts, claim records, decision metadata, or private operational details in public data;
- SHA3-512 as the authoritative Blind Ledger hash, commitment/state identifier, transcript digest,
  manifest digest, and receipt digest;
- M31 base arithmetic with the reviewed degree-16 Fp16 challenge field;
- authenticated interactive public coin with no launch Fiat--Shamir, QROM, or grinding credit;
- ML-DSA-87 plus SLH-DSA-SHAKE-256f authentication on Blind Ledger-controlled authority and
  public-coin surfaces;
- at least 256 bits of cryptographic security/encryption strength for every individual term and the
  composed ledger;
- no RSA, ECC, pairing, KZG, IPA, trusted setup, external proving service, or host-trusted equality
  on a Blind Ledger-controlled proof boundary;
- at most 5,000,000,000 decimal bytes peak resident host memory, strictly below 5,000,000,000
  decimal bytes scratch, and no swap dependency;
- one authenticated 6,086-round schedule for the accepted state-free H4 baseline; the
  state-composed seven-claim shape is a separate 6,111-round nonactivating boundary until its
  complete semantics and qualification evidence exist;
- a stricter Wave 2 complete-proof p95 target below 30 seconds for K128/100-live and below 180
  seconds for K512/500-live. The older 60-second K128 product ceiling is not permission to weaken
  the selected 30-second engineering gate;
- an untrusted GPU: Rust-owned parsing, transcript replay, commitments, canonical decoding,
  mutations, answer/target checks, and final verification remain authoritative; and
- atomic binding of attempt identity, old/new state, membership/absence, uniqueness, ordering,
  money, semantic source, proof, verifier, schema, parameters, migration, and settlement.

No throughput result can waive an invariant. No conservative abstraction may remain merely because
it sounds safer: it must protect an identified invariant or be removed after dependency review.

The H4 prototype is functionally attached for both profiles:

| Boundary | Current value |
| --- | --- |
| Semantic source | Exact `BLHBB101` bounded hash-bus source |
| Hash proof | 24 Keccak rounds, 168 layers, seven-layer/B=16 relay-free nonuniform GKR |
| Claims | State-free hash bus: one output claim and four input claims (relay-free); state-composed H4: those five plus two state claims (seven total) |
| Native hiding | 508 GKR mask constraints per shard |
| PCS | Construction 8.2 random-padded interleaved Reed--Solomon, 73-word auxiliary plane |
| Authenticated schedule | State-free baseline: 6,073 hash-GKR rounds + 13 PCS rounds = 6,086; state-composed shape: +25 state-relation rounds = 6,111 |
| Public coin | ML-DSA-87 plus SLH-DSA-SHAKE-256f authenticated chain |
| Authority split | CUDA performs untrusted arithmetic; Rust parses, recomputes, replays, and verifies |
| K128 | One shard; 29.974129 seconds complete process; 288.412 MB internal host; 969.999360 MB tracked device; 0 MB scratch |
| K512 | Four ordered sequential shards on one GPU; 120.460733 seconds; 296.255 MB internal host; 969.999360 MB tracked per proof; 0 MB scratch |
| Manifest | `51c23310274ccf7c4d7f9abe4ae7eba43266b335bd377b21cbf92409729b91e2a40a39787a157baa080c9d0516c7815af404a4d58d9e76747f652f57cd017ed6` |

All memory values are decimal MB. These are accepted one-run H4 prototype measurements, not H5
p95 qualification or H6 suite activation.

The state-composed schedule is a fixed-shape integration boundary, not a qualification result. The
state lane uses the same H4 source polynomial at the fixed 64-wire lane beginning at wire 1,600,
two boundary-one PCS claims, and a private canonical source of exactly 16,777,216 bytes. The Rust
bridge verifies the 18-coordinate local state claims after lifting them into H4's 24-coordinate
source geometry. The compact proof-native seam now carries each authenticated slot index and
constrains it to the canonical group-major row position, so populated-row index/order mutations
fail closed. The native Rust state-binding parser and Python canonical snapshot decoder also
reject duplicate present keys. High-cardinality membership/absence, money/state conservation,
and the complete state relation inside the custom H4 GKR/PCS composition are still required in
Gate 2E. No state-composed K128/K512 performance or qualification credit is claimed.

## Exact accepted H4 profiles

Only two coordinator profiles are currently accepted. K256 remains a design/calibration point and
is rejected by the atomic coordinator.

| Property | K128 | K512 |
| --- | ---: | ---: |
| Live claims | 100 | 500 |
| Exact semantic SHA3 calls | 46,858 | 165,762 |
| Coprocessor shards | 1 | 4 |
| Padded permutations per shard | 131,072 | 131,072 |
| Live input wires per permutation | 1,600 | 1,600 |
| Implicit fixed-zero wires | 448 | 448 |
| Canonical `BLHBB101` bytes | 52,429,015 | 209,715,415 |
| Execution | one shard | four ordered shards, sequentially on one GPU |
| Complete-process result | 29.974129 s | 120.460733 s |

The `BLHBB101` header binds the profile, semantic program commitment, descriptor commitment,
semantic-port commitment, shard count, padded-permutation count, live-wire count, file length, and
SHA3-512 file identity. Each shard stores canonical input wires followed by output wires. Fixed-zero
padding is derived from the selected format and must not be serialized as another full source.

## Complete H4 proof flow

The accepted proof is one ordered state machine. Reordering or independently accepting a proper
subset is forbidden.

1. **Admit the exact profile.** Parse `BLHBB101` with bounded lengths and canonical encodings.
   Accept only the one-shard K128 or four-shard K512 shape and require a nonzero 64-byte caller
   application-statement digest.
2. **Read and bind the execution closure.** Hash the coordinator, Python entrypoint, Python
   dependency closure, semantic worker, seven native verifier executables, public-coin service, and
   three precompiled CUDA modules into the execution manifest. Both the external monitor and Rust
   coordinator must compute the expected manifest.
3. **Create the atomic parent binding.** Domain-separate and bind the profile, semantic program,
   descriptor, port map, source-file identity and geometry, selected B16 GKR plan, execution
   manifest, and caller statement. When `state-file:<path>` is supplied, append the independently
   verified state transition, commitment, verifier, attempt, receipt, exact 12-field projection,
   and executable-AIR identities as one state context.
4. **Process shards in canonical order.** K512 runs four full shard proofs sequentially. It may
   reuse bounded worker infrastructure but must not reuse nonlinear challenge streams, masks, proof
   fragments, or partial receipts between shards.
5. **Run the real hash coprocessor.** For each shard, prove 24 Keccak rounds as 168 explicit
   nonuniform layers under the seven-layer, B=16 relay-free plan. The hash GKR schedule contains
   exactly 6,073 authenticated challenge rounds.
6. **Run the state relation when state is supplied.** Authenticate the fixed state source, prove
   its 25-round interactive relation, and expose two state input claims in the same H4 PCS boundary.
   State-free runs execute the same 25-round shape with zero claims and zero source digest.
7. **Bind the PCS claims.** The state-free proof contains one output claim and four hash input
   claims; the state-composed shape adds two state claims for seven total. It must not reconstruct
   or replay a duplicate full hash source merely to prove the join.
8. **Apply native hiding.** Verify 508 native GKR mask constraints per shard and bind the GKR-mask
   row source/relation plus the selected auxiliary plane before dependent challenges.
9. **Continue into Construction 8.2 PCS.** Use the random-padded interleaved Reed--Solomon
   construction and the complete 73-word auxiliary plane. Exactly 13 PCS rounds follow the hash
   and state prelude: 6,086 rounds state-free or 6,111 rounds state-composed.
10. **Independently verify the shard.** Rust replays public coin, verifies signatures, parses every
   bounded section, recomputes authoritative SHA3-512 roots and targets, checks GKR recurrences and
   terminals, native masks, PCS openings, answer code, semantic boundary, and mutation gates.
11. **Create one outer receipt.** After every ordered shard independently verifies, hash the parent,
    caller statement, ordered shard evidence, stdout/bundle identities, timing/resource fields, and
    verifier results into one atomic receipt. When state is attached, the full state context is
    included as well. A missing, reordered, duplicated, stale, or partially verified shard rejects
    the complete attempt.

The Python/CUDA layer is an arithmetic oracle, not an authority. It may produce raw group cubics,
wire quadratics, boundary evaluations, folds, and device telemetry. Rust owns challenges, native
masks, recurrence state, terminal checks, canonical commitments, transcript replay, and acceptance.

## Current memory and concurrency design

The selected implementation is intentionally bounded and sequential where the theorem does not
authorize sharing:

| State or allocation | Decimal size |
| --- | ---: |
| Five-claim component/source/relation rows | 7.864320 MB |
| Simultaneously live GKR-mask row source/relation | 4.194304 MB |
| Total joined row state | 12.058624 MB |
| GKR-mask coefficients | 2.097152 MB |
| GKR-mask RS codewords | 33.554432 MB |
| Complete 73-word auxiliary coefficients | 15.258752 MB |
| Complete auxiliary codewords | 38.273024 MB |
| Immutable packed device topology | 3.225600 MB |

The coordinator keeps one active worker and prepares exactly one future 48-layer worker after the
active worker accepts its plan. Zero standby workers expose fresh-context startup latency; more than
one adds residency and contention without theorem or throughput value. A worker lifetime above 48
layers is forbidden by current evidence: the tested 56-layer lifetime faulted at layer 54 with CUDA
error 700 and an `nvlddmkm` Event 153.

The reference host exposes 16 logical CPU workers. CPU work may use up to the best safely measured
count, but deterministic partitioning and canonical merge order are mandatory. More workers receive
no credit unless complete-boundary wall time improves without increasing leakage, nondeterminism,
memory, scratch, or failure risk.

The H4 allocation is the regression baseline. Any Gate 2E/H5 change that materially exceeds
296.255 MB internal host memory, 706.523136 MB external process-tree RSS, 969.999360 MB tracked
per-proof device state, 2,770.337792 MB K512 sampled total device residency, or 0 MB scratch must
identify the theorem-required reason and demonstrate a complete-boundary throughput gain. The hard
host/scratch gates still govern even when a smaller H4 regression threshold is exceeded.

## Privacy and data-placement boundary

| Location | Allowed | Forbidden |
| --- | --- | --- |
| Government/private systems | Encrypted claim and patient records, private witness, custody keys, authorization policy | Public publication or unaudited third-party upload |
| Proving host | Fixed-shape synthetic/private witness under isolated execution, fresh masks, bounded temporary state | Swap, core dumps, witness-dependent logs/errors/shape, retained plaintext artifacts |
| Proof/transcript | Fixed grammar, commitments, roots, public challenges, minimum public statement | PHI, exact private amounts, claim documents, decision metadata, reusable randomness |
| L2/L1 public state | Ordered 12-field compatibility statement, versioned wide commitments, minimum financial state | Raw or encrypted PHI, private operational details, proof-worker telemetry |

H4 binds a nonzero caller statement digest but does not yet define the authoritative persistent
state plane. Gate 2E must prove that the selected state commitment and old/new transition are the
same transition produced by the sealed relation. Host comparison of two independently produced
roots is not sufficient.

## Fail-closed verifier order

An implementation may combine passes for performance only if the observable decision is identical
to this logical order:

1. check file existence, byte caps, exact profile, exact grammar version, and canonical integers;
2. reject unsupported K256, zero statement, unexpected shard count/size, extra bytes, and unknown
   proof sections before large allocation;
3. verify execution-manifest and parent-binding identities;
4. verify the dual-PQ public-coin head and replay all 6,086 state-free or 6,111 state-composed
   challenges in order;
5. verify semantic-source, selected-plan, claim, GKR recurrence/terminal, and native-mask bindings;
6. verify the complete PCS tree geometry, multiproofs, openings, answer code, and target;
7. verify every shard independently and in canonical order;
8. verify the outer atomic receipt and resource/latency admission result; and
9. emit acceptance only after every prior check succeeds.

Timeouts, child crashes, malformed stdout, stderr, missing telemetry, driver errors, pagefile growth,
manifest drift, and ambiguous error classification reject the attempt. A retry always starts a fresh
proof with fresh randomness; no proof fragment, challenge tail, mask, or partial receipt is resumed.

## Active source ownership

| Layer | Current source | Role |
| --- | --- | --- |
| Application and batching | `app/`, `rules-engine-rust/` | Canonical ingestion, policy, batch, and protected state-binding surfaces |
| Sealed semantic relation | `experiments/fixed_shape_claim_air/` | Nonactivating Wave 1 semantic producer and exact global SHA3 schedule |
| Authoritative proof core | `experiments/bl_pq512_crypto_core/` | Fp16, GKR, PCS, authenticated public coin, independent verifier, resource gates |
| Current GPU workers | `experiments/bl_pq512_crypto_core/cuda/cuda_hash_bus_b16_gkr_worker.py`, `cuda_fp16_zk_rs_interleaved_k128_prototype.py`, and their manifest-bound local verifier modules | Untrusted acceleration only |
| Historical semantic reference | `zk-cairo-sharp/` | Protected differential source; not the selected proof backend |
| Settlement shell | `contracts/` | Protected mock/test settlement boundary; no production `INativeStarkVerifier` exists |
| Operations | tracked `ops/` | Sole commit-bound policy/verifier authority with exact file-set, length, and SHA3-512 verification |

### Proof-core ownership map

| Responsibility | Authoritative source |
| --- | --- |
| Profile/global semantic schedule | `src/wave1a_global_schedule.rs`, `src/wave1a_dimensions.rs` |
| Canonical hash-bus source and codec | `src/hash_bus_b16_boundary.rs`, `src/hash_bus_b16_trace.rs`, `src/bin/hash_bus_snapshot_to_b16.rs` |
| Selected B16 plan and worker boundary | `src/hash_bus_b16_gkr_plan.rs`, `src/hash_bus_b16_gkr_worker.rs` |
| GKR schedule/source/proof logic | `src/fp16_relay_free_gkr_schedule.rs`, `src/fp16_relay_free_gkr_source.rs`, `src/fp16_relay_free_gkr_uniform.rs` |
| Native masks and GKR/PCS binding | `src/gkr_zk_mask.rs`, `src/fp16_zk_rs_gkr_binding.rs` |
| PCS transcript, proof, query, and multiproof | `src/multilinear_pcs_transcript.rs`, `src/multilinear_pcs_proof.rs`, `src/multilinear_pcs_query.rs`, `src/fri_layer_multiproof.rs` |
| Public coin | `src/chained_public_coin.rs`, `src/chained_public_coin_client.rs`, `src/bin/chained_public_coin_service.rs` |
| Atomic one/four-shard coordinator | `src/bin/k512_atomic_semantic_prototype.rs` |
| Current CUDA arithmetic worker | `cuda/cuda_hash_bus_b16_gkr_worker.py` plus manifest-bound local CUDA helpers |
| Complete prototype entrypoint | `cuda/cuda_fp16_zk_rs_theorem8_1_k128_prototype.py` |
| Independent verifier executables | `src/bin/fp16_zk_rs_*verify.rs`, answer/target binaries, row-sumcheck prover, and public-coin bridge |

Historical names such as `fri`, `brakedown`, `theorem8_1`, or `wave1b` do not by themselves make a
module obsolete. Remove or rename one only after tracing current imports, manifest identities,
tests, and verifier dependencies. Current execution still imports several historically named
helpers; name cleanup must never change proof bytes or silently drop an authenticated dependency.

## Evidence currently required to remain green

- 264 optimized Rust library tests, zero failures, zero ignored, plus every remaining binary and
  doc-test group;
- release format check, locked/offline build, no-default/no-std check, and strict all-target Clippy
  with warnings denied;
- seven host cryptographic KATs;
- complete accepted 20/36-tree proof geometries and segment-32 mutation rejection;
- 10/10 retired or incomplete format rejections;
- static compilation of 36 CUDA entry points;
- execution-manifest readback by both coordinator and external monitor;
- externally monitored complete proof with independent verification, no pagefile growth, zero
  scratch, and no driver event after the audited reset boundary; and
- protected-path and canonical-ops integrity gates.
- Gate 2E-2/S2 scalar positive/negative parity for both frozen profiles, including the independent
  verifier and all seven C0 negative classes.

The former sibling-ops collection stop is closed. Broad suites now resolve only the exact tracked
`ops/` authority and fail on any alternate root, file-set, length, digest, symlink, junction, or
Windows reparse-point mismatch; no outward copy or fallback tree is permitted.

## Current execution order

1. Admit and atomically bind a reviewed state relation/commitment plane into the H4 parent,
   transcript, proof grammar, independent verifier, and receipt; the terminal evidence ledger is
   now the fail-closed record of what remains open.
2. Run H5: one warm-up plus ten unique K128 and ten unique K512 proofs with external resource and
  driver monitoring; qualify p95 below 30/180 seconds.
3. Run H6 suite, parser, mutation, rollback, recovery, reproducibility, and activation gates.
4. Implement the production native verifier and containing L2/L1 settlement path in later roadmap
  packages.

The terminal ledger reference is implemented, but it is not the Gate 2E close: S6/S7 retained C0
without selecting a PQ backend because S3 admission is closed. Do not start the repeated H5
campaign until one state plane is selected and atomically bound into the H4 parent, transcript,
proof grammar, verifier, and receipt.

`experiments/bl_pq512_crypto_foundation/h5_qualification_preflight.py` now records that boundary
without launching a prover. It independently replays the terminal ledger, freezes one uncounted
warm-up plus ten unique measured launches for each K128/K512 profile (22 fresh launches total),
checks the tracked commit-bound `ops/` authority and reference-hardware readiness, and keeps cached
proofs, cached witnesses, automatic retry, activation, and `proofSuiteId` disabled. The current
record is `BLOCKED_H5_PREFLIGHT` with preflight digest
`5c6a04878f8268dfd4fb33b3583fd27f0aff8624f90f720a9f6b45fb8dff849538ee7aac6ea3d36d72971d1223bf595c9cec0d35f3230705047518c5741432e1`; it records
`VERIFIED_TRACKED_SHA3_512_AUTHORITY`, `READY` reference hardware, no campaign, no external monitor, and
the unresolved Gate 2E/H4/simulator/leakage/PQ blockers. The recorded 487,335,129,088-byte disk
now uses a literal 10x lower operational reserve: 15,000 ppm (1.5%), requiring 7,310,026,937
free bytes; the immutable 5,000,000,000-byte RSS/scratch, zero-swap, privacy, proof, and
activation gates are unchanged. This is a preflight ledger, not H5 measurement or qualification
evidence.

`experiments/bl_pq512_crypto_foundation/h6_qualification_preflight.py` now records the next
qualification boundary without launching a prover. It independently replays the H5/2E context,
validates the candidate registry's `CANDIDATE_UNQUALIFIED` state and eight null module identities,
and emits all twelve H6 obligations with explicit evidence classes. The current record is
`BLOCKED_H6_PREFLIGHT` with five blocked, five open, and two reference-only records; no obligation
is closed, `proofSuiteId` remains null, and activation remains false. Its focused/attack suite is
6/6 and the containing S1-S7, terminal-ledger, H5, and H6 set is 85/85; these are ledger-test
observations, not complete-proof qualification.

The current-source UDR/native-hiding KAT boundary was reconciled on 2026-08-02. The implementation
now derives the six unselected query candidates as `617/378/309/281/268/262` and the interface
per-term floor as `256` bits; stale test/vector expectations for the superseded `926/567/463/421/402/393`
and `384`-bit worksheet were corrected. This changes no proof-suite selection, state admission,
H4 binding, `proofSuiteId`, activation, or qualification claim. The registry's explicitly marked
superseded historical values remain historical evidence.

## Open boundaries and nonclaims

- Gate 2E has not selected authoritative persistent state or its PQ commitment. S2 scalar controls,
  S3 commitment envelopes, S4 atomic composition, and S5 migration/recovery are correctness and
  differential reference evidence only; S6/S7 timing is component-only and no candidate has reviewed
  native-hiding composition, complete proof composition, migration theorem, or complete-boundary
  measurement.
- The complete semantic-STARK/state/GKR/PCS zero-knowledge simulator and composed 256-bit ledger are
  not closed; the new terminal ledger records this as an explicit open obligation.
- H5 has not run one warm-up plus ten unique K128 and ten unique K512 complete proofs.
- H6 has not frozen `proofSuiteId`, final module identities, reproducible artifacts, custody, or the
  production parser/verifier.
- The tracked ops authority passes exact SHA3-512 inventory readback; this former blocker is closed.
- No production `INativeStarkVerifier` implementation exists; the Solidity test verifier is a mock.
- The containing based rollup, bridge, forced inclusion, data availability, exits, finality, and
  deployment rehearsal are not implemented.
- Blind Ledger-controlled boundaries are not yet end-to-end PQ because wider custody, transport,
  governance, backup, and recovery migration remains open.
- No real PHI, payment credentials, production activation, Ethereum-security, audit completion, or
  deployment-ready claim is authorized.

## Deliberately retained controls

The V1-layer compaction test, exact two-claim GKR/PCS differential, and retired-format rejection KAT
remain because they prove migration equivalence or fail-closed rejection. They do not expose a
fallback acceptance path. Any control that ceases to protect a current invariant must be removed
with its dependency and test evidence.

## Removed executable alternatives

The standalone RISC Zero and vendored Stwo experiments were removed from the active source tree on
2026-07-31 after confirming that no application or selected-proof module imported them. Their exact
evidence, source identities, rejection reasons, and recovery boundary are retained in
`docs/REJECTED_ARCHITECTURES.md` and Git history. They must not be restored as active dependencies.
