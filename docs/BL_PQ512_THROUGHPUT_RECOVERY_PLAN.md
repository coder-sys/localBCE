# BL-PQ512 throughput and proof-size recovery plan

Updated: 2026-08-02

Status: current-only performance contract. Historical experiments, profiles, and intermediate
measurements are preserved verbatim in
`history/BL_PQ512_THROUGHPUT_RECOVERY_PLAN_THROUGH_2026-08-01.md`. Rejected performance designs are
non-executable and belong in `REJECTED_ARCHITECTURES.md`.

## 1. Objective

Maximize measured complete-proof throughput without weakening correctness, privacy, post-quantum
security, the sealed relation, fail-closed verification, or resource gates.

The only release qualification profiles are:

| Profile | Live claims | Complete-proof p95 | Campaign |
| --- | ---: | ---: | --- |
| K128 | 100 | < 30.000000 s | 1 uncounted warm-up + 10 unique measured attempts |
| K512 | 500 | < 180.000000 s | 1 uncounted warm-up + 10 unique measured attempts |

The timed boundary begins at admitted canonical input and ends only after independent verification
and the atomic receipt. GKR-only, PCS-only, state-only, cached-proof, or internal-verifier timings
receive zero complete-proof qualification credit.

## 2. Immutable gates

- At most 5,000,000,000 decimal bytes peak resident host memory.
- Scratch strictly below 5,000,000,000 decimal bytes.
- No swap or pagefile growth.
- Fixed proof grammar and witness-independent observable schedule.
- Native hiding and at least 256 bits for every individual and composed term.
- SHA3-512 authority, M31/Fp16 algebra, and authenticated dual-PQ interactive public coin.
- Authoritative Rust verification; GPU work is untrusted.
- Exact Wave 1 semantics, retry identity, money, state transition, and 12-field ABI.
- Fresh randomness and public-coin session for every proof attempt.
- Honest labels: measured, derived, projected, or unknown.

The current H4 resource envelope is a regression baseline, not permission to consume the hard
limit. Any material increase must identify a theorem-required allocation and demonstrate a faster
complete boundary.

## 3. Current accepted baseline

| Measurement | K128 | K512 |
| --- | ---: | ---: |
| Complete process | 29.974129 s | 120.460733 s |
| Internal host peak | 288.412 MB | 296.255 MB |
| External process-tree peak | 681.607168 MB | 706.523136 MB |
| Tracked device state per proof | 969.999360 MB | 969.999360 MB |
| Sampled total GPU residency | not promoted | 2,770.337792 MB |
| Scratch | 0.000000 MB | 0.000000 MB |
| Pagefile growth | zero | zero |

These are one-run, state-free H4 prototype measurements. Gate 2E state binding can change the
profile, so H5 must measure the selected state-bound candidate rather than reusing H4 results.

Current compact memory:

| State | Decimal MB |
| --- | ---: |
| Five-claim row plane | 7.864320 |
| GKR-mask row plane | 4.194304 |
| Total joined row state | 12.058624 |
| GKR-mask coefficients/codewords | 2.097152 / 33.554432 |
| Complete auxiliary coefficients/codewords | 15.258752 / 38.273024 |
| Immutable packed topology | 3.225600 |

No active architecture requires an 8 GB host preflight or multi-gigabyte row replay. Admission uses
the current measured envelope plus explicit headroom; acceptance always uses the immutable hard
gates.

## 4. First-principles optimization rule

For every measured dominant stage ask, in order:

1. Is the work required by the theorem, verifier, privacy boundary, compatibility, or auditability?
2. If not required, remove it after tracing every producer, consumer, manifest identity, test, and
   migration dependency.
3. If required, can it be fused, streamed, derived, tiled, batched, vectorized, or scheduled once?
4. Can ownership be reduced to one canonical representation or bounded frontier?
5. Can CPU and GPU overlap without changing challenge order or adding trusted device state?
6. Does the independent verifier reconstruct the identical statement and transcript?
7. Does the complete process improve, not merely a component benchmark?
8. Does memory, scratch, residency, nondeterminism, leakage, and failure surface improve or remain
   bounded?

Reject an optimization that duplicates a full source/state, adds an unverified GPU equality,
shares nonlinear challenges without a theorem, increases workers merely to hide startup, changes
proof shape by witness class, or moves cost outside the measured boundary.

## 5. Current throughput architecture

- Exact B=16 seven-layer nonuniform Keccak GKR.
- One output plus four relay-free input claims.
- Construction 8.2 random-padded interleaved-RS PCS.
- One live semantic tile per boundary and public-message-only broadcast.
- Same-source aliases instead of duplicate word transport.
- One-pass semantic source consumption.
- Canonical plan transport and immutable topology upload once per worker.
- One active plus exactly one future 48-layer worker.
- Sequential K512 shards on one GPU, each with an independent challenge stream.
- CUDA arithmetic overlapped only where transcript dependencies allow.
- Rust-owned masks, challenges, commitments, multiproofs, targets, replay, and acceptance.

Any replacement must beat this complete architecture while satisfying every immutable gate.

## 6. Gate 2E performance work

Throughput work now belongs to authenticated state selection. Use the candidate sequence in
`IMPLEMENTATION_ROADMAP.md` and theory in `BL_PQ512_COMMITTED_SPARSE_STATE_PLAN.md`.

For every candidate record:

- exact relation and commitment identities and parameters;
- state capacity, access count, touched set, conflict shape, and fixed padding;
- proof-theorem and security assumptions;
- state-only prove/verify time and bytes;
- complete K128/K512 process and wrapper time;
- internal/process-tree RSS, device state/residency, scratch, pagefile, and I/O;
- proof, receipt, manifest, stdout, and stderr hashes;
- mutation, migration, rollback, crash, retry, and independent-verifier results; and
- whether each value is measured, derived, projected, or unknown.

Screen scalar correctness before optimization. Run repeated state-component measurements, then one
uncounted complete warm-up and at least one fresh complete proof per finalist/profile. Select the
fastest fully compliant complete candidate. A paper number or microbenchmark cannot win.

## 7. H5 campaign method

Preflight:

- sealed clean Gate 2E commit and locked/offline build;
- canonical `../ops` restored from trusted material and recursively identical to `ops/`;
- execution manifest recomputed by coordinator and external monitor;
- exclusive host with no competing build/proof/cache scan;
- clean Windows driver-reset boundary and no later Event 153 or Display Event 4101;
- sufficient measured host/device headroom;
- strict synthetic input allowlist and unique manifest;
- external process-tree, pagefile, device, scratch, stdout/stderr, and System-log monitor; and
- every focused, parser, mutation, attack, state, migration, and independent-verifier gate green.

Run exactly 22 fresh launches unless a STOP condition fires. With ten measurements, nearest-rank
p95 is the maximum. Never average away a slow run, discard a failed attempt, or replace it with an
eleventh measurement.

Per attempt record:

- input identity and profile;
- proof and receipt identities and byte lengths;
- complete-process and external-wrapper time;
- every named stage and verifier time;
- internal and process-tree RSS;
- pagefile delta;
- tracked and total device residency;
- scratch high-water mark and I/O;
- public-coin latency, retry count, and authentication result;
- cleanup result;
- stdout/stderr hashes;
- driver-event interval; and
- every functional, security, mutation, and verifier flag.

## 8. STOP and redesign rules

Stop the current attempt and preserve raw evidence on:

- workspace, source, tool, lock, ops, manifest, parameter, or schema drift;
- nonsynthetic input or possible PHI;
- driver event after the audited reset boundary;
- swap/pagefile growth or a host/scratch/resource violation;
- child crash, timeout, malformed output, stderr, or missing telemetry;
- parser/verifier disagreement or any false acceptance;
- mutation, replay, splice, stale-state, rollback, or migration failure;
- witness-dependent shape or timing classification;
- incomplete cleanup or retained private artifact; or
- latency failure.

For an in-scope safely correctable failure: reproduce, classify, find the measured root cause,
implement the smallest correct fix, add the necessary regression/attack test, rerun containing
gates, update evidence, and continue. Never weaken a gate or resume a partial proof.

If latency fails, profile the complete process and redesign the measured dominant stage from first
principles. Do not tune unrelated components.

## 9. Explicitly excluded paths

- direct monolithic SHA3 AIR/STARK layouts;
- RISC Zero and the removed Stwo/QM31/Blake2s backend;
- BaseFold, zkDeepFold, Circle-FRI, and incomplete legacy grammars as active PCS paths;
- B=64, merged characteristic-two layers, and scalar full-source replay;
- conjecture-dependent query reductions;
- theorem-free K512 challenge sharing or four-way shard residency;
- a second full semantic source, row table, or codeword owner;
- host-trusted comparison of independently produced roots;
- increasing worker lifetime beyond the verified 48-layer bound; and
- treating VRAM capacity as proof of driver integrity.

Detailed rejection evidence is in `REJECTED_ARCHITECTURES.md`; verbatim former planning text is in
the `history/` file named at the top.

## 10. Verification commands and evidence

Exact commands evolve with Gate 2E. The sealed handoff must provide the literal commands and
environment for its selected commit. At minimum preserve:

- `cargo fmt --all -- --check`;
- locked/offline release check and no-default/no-std check;
- strict all-target Clippy with warnings denied;
- all optimized library, binary, and doc tests;
- seven host cryptographic KATs;
- complete tree/multiproof and segment-32 mutation KATs;
- 10/10 retired-format rejection;
- static CUDA compilation and manifest identity;
- independent proof and receipt verification; and
- documentation, protected-path, ops-identity, stale-path, and diff checks.

Report decimal MB only. Preserve raw output, hashes, counts, failures, warnings, skips, and
measurement boundaries. Do not claim qualification from an interrupted, cached, internally-only,
or state-free proof.

## 11. Current Gate 2E evidence and next action

Gate 2E-0/S0, Gate 2E-1/S1, and Gate 2E-2/S2 are complete for the synthetic control/interface/
relation boundary. S2 runs C1 dense/sparse, C2, C3, and C4 scalar controls through an independent
replay verifier and requires full C0 positive/negative parity for both profiles. Its C1 dense scan,
C3 quadratic projection counter, and C4 persistent-scan counter are derived risk labels, not
throughput measurements. The four S0 fresh-process measurements remain recorded in
`IMPLEMENTATION_ROADMAP.md` and `STATE.md`; pagefile usage deltas remain observed telemetry, not a
swap conclusion. Gate 2E-3/S3 now has a tested dual-PQ authenticated commitment-screening reference;
all four descriptors remain rejected because reviewed native-hiding and complete-proof evidence is
missing. Gate 2E-4/S4 now has a tested synthetic composition reference that independently replays
the scalar relation, verifies the screened opening, and binds the transition, deferred H4 identity,
verifier identity, and receipt; its focused/attack result is 6 passed in 10.11 seconds. This is not
complete-proof throughput evidence and does not admit a backend. Execute Gate 2E-5/S5 migration and
failure semantics next. Do not start H5 or another complete-proof backend bake-off.
