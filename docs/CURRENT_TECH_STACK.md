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
verifier in `pq_commitment_screening.py`. All four descriptors are rejected because reviewed exact
source/parameters, native-hiding theorem composition, or complete-proof evidence is missing. This
is screening evidence only; no PCS, state plane, H4 binding, or activation decision is closed.

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
grant timing credit when no backend is admitted. All four backends remain rejected; C0 is retained
as an unselected control, complete warm-up/complete-boundary runs are not authorized, and the
selection handoff is explicitly unsealed. Focused positive/attack tests pass 6/6.

The terminal Gate 2E evidence boundary is now implemented in
`gate_2e_terminal_ledger.py`. It independently replays S4, derives S5 checkpoints, checks the
frozen C0 positive/negative parity and exact 12-field boundary, checks that raw private relation
material is absent from its public encoding, and binds the S6/S7 decision/handoff identities. It
records 11 ordered obligation records for atomic composition, the semantic/PCS/public-coin
simulator, fixed-shape leakage, state/proof receipt, migration, strict-PQ selection, canonical
ops, and independent verification. The ledger is reference-only and unsealed; its current blockers
are `no_backend_admitted`, `complete_simulator_missing`, `complete_leakage_scan_missing`,
`h4_atomic_binding_deferred`, `canonical_ops_missing`, and `proof_suite_unselected`.

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
| Claims | One output plus four relay-free input claims |
| Native hiding | 508 GKR mask constraints per shard |
| PCS | Construction 8.2 random-padded interleaved Reed--Solomon, 73-word auxiliary plane |
| Authenticated schedule | 6,073 GKR rounds plus 13 PCS rounds = 6,086 |
| Public coin | ML-DSA-87 plus SLH-DSA-SHAKE-256f authenticated chain |
| Authority split | CUDA performs untrusted arithmetic; Rust parses, recomputes, replays, and verifies |
| K128 | One shard; 29.974129 seconds complete process; 288.412 MB internal host; 969.999360 MB tracked device; 0 MB scratch |
| K512 | Four ordered sequential shards on one GPU; 120.460733 seconds; 296.255 MB internal host; 969.999360 MB tracked per proof; 0 MB scratch |
| Manifest | `51c23310274ccf7c4d7f9abe4ae7eba43266b335bd377b21cbf92409729b91e2a40a39787a157baa080c9d0516c7815af404a4d58d9e76747f652f57cd017ed6` |

All memory values are decimal MB. These are accepted one-run H4 prototype measurements, not H5
p95 qualification or H6 suite activation.

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
   manifest, and caller statement.
4. **Process shards in canonical order.** K512 runs four full shard proofs sequentially. It may
   reuse bounded worker infrastructure but must not reuse nonlinear challenge streams, masks, proof
   fragments, or partial receipts between shards.
5. **Run the real hash coprocessor.** For each shard, prove 24 Keccak rounds as 168 explicit
   nonuniform layers under the seven-layer, B=16 relay-free plan. The GKR schedule contains exactly
   6,073 authenticated challenge rounds.
6. **Bind five relay-free claims.** The proof contains one output claim and four input claims. It
   must not reconstruct or replay a duplicate full source merely to prove the join.
7. **Apply native hiding.** Verify 508 native GKR mask constraints per shard and bind the GKR-mask
   row source/relation plus the selected auxiliary plane before dependent challenges.
8. **Continue into Construction 8.2 PCS.** Use the random-padded interleaved Reed--Solomon
   construction and the complete 73-word auxiliary plane. Exactly 13 PCS rounds follow GKR, making
   one authenticated 6,086-round schedule.
9. **Independently verify the shard.** Rust replays public coin, verifies signatures, parses every
   bounded section, recomputes authoritative SHA3-512 roots and targets, checks GKR recurrences and
   terminals, native masks, PCS openings, answer code, semantic boundary, and mutation gates.
10. **Create one outer receipt.** After every ordered shard independently verifies, hash the parent,
    caller statement, ordered shard evidence, stdout/bundle identities, timing/resource fields, and
    verifier results into one atomic receipt. A missing, reordered, duplicated, stale, or partially
    verified shard rejects the complete attempt.

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
4. verify the dual-PQ public-coin head and replay all 6,086 challenges in order;
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
| Operations | `ops/` plus required canonical sibling `../ops/` | Policy and verifier artifacts; the sibling canonical tree is currently absent in this workspace |

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

The current Python-wide suite cannot receive a clean pass while the canonical sibling `../ops/` is
absent. Do not copy `ops/` outward or skip mirror checks. Recover the authoritative sibling from
trusted material, prove recursive byte identity, and then rerun the complete ordinary and attack
lanes.

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
checks the actual canonical `../ops` tree and reference-hardware readiness, and keeps cached
proofs, cached witnesses, automatic retry, activation, and `proofSuiteId` disabled. The current
record is `BLOCKED_H5_PREFLIGHT` with preflight digest
`8eb296bb3946df2881402e86e7b4f7ba86018f7ff7140ed513266e3b0c65939a04aebe96f638131c69d5326e614a1dd57961ad1b103f748009b60bb4cd1dc435`; it records
`MISSING_CANONICAL_SIBLING`, `NOT_READY` reference hardware, no campaign, no external monitor,
and the unresolved Gate 2E/H4/simulator/leakage/PQ blockers. This is a preflight ledger, not H5
measurement or qualification evidence.

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
- The canonical sibling `../ops/` is missing, so broad readiness and policy-bound tests fail closed.
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
