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
| K128 | 100 | < 35.000000 s | 1 uncounted warm-up + 10 unique measured attempts |
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
| Five-claim state-free row plane | 7.864320 |
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
- State-free hash bus: one output plus four relay-free input claims.
- State-composed H4 shape: the same five hash claims plus two fixed state claims, with 25 extra
  authenticated state-relation rounds and no new performance credit yet.
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

The state-composed source is a fixed 16,777,216-byte private canonical lane at H4 wire offset
1,600. The current fixed prelude is 6,113 rounds; complete state-composed totals are 6,727 for
K128 and 6,995 for K512. Each profile must receive its own complete-boundary resource and latency
run.

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
- tracked `ops/` exact file-set, length, SHA3-512, and symlink authority readback;
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
all five descriptors remain rejected: the three lattice families lack pinned reviewed evidence, the
old hash-pad control fails its public-coin/quantum review, and the new SHAKE256-1024 candidate lacks
complete H4 composition. Gate 2E-4/S4 now has a tested synthetic composition reference that independently replays
the scalar relation, verifies the screened opening, and binds the transition, deferred H4 identity,
verifier identity, and receipt; its focused/attack result is 6 passed in 10.11 seconds. This is not
complete-proof throughput evidence and does not admit a backend. Execute Gate 2E-5/S5 migration and
failure semantics are now recorded. Gate 2E-5/S5 has a tested synthetic migration/recovery controller with
10 focused positive/attack tests passing in 10.10 seconds. It is reference state-equivalence and
failure evidence only; it does not select a backend or qualify complete-proof throughput. Gate
2E-6/S6 and 2E-7/S7 now measure 20 repeated reference-component observations across five rejected
backends and two profiles, retain exact rejection evidence, and leave complete-boundary work
unauthorized; their focused/attack result is 6 passed in 34.04 seconds. The terminal ledger
reference is now implemented and independently rechecked: it has 11 ordered obligation records,
focused/attack result 7 passed in 29.70 seconds, containing S1-S7 plus ledger result 73 passed in
91.58 seconds, and status `UNSEALED_BLOCKED_GATE_2E_TERMINAL_LEDGER`. Its blockers remain no
backend admission, missing complete leakage evidence, deferred H4 binding, and unset
`proofSuiteId`. The tracked `ops/` authority is verified and the former sibling-layout blocker is closed.
The v5 typed C0 AIR remains the executable semantic/differential oracle and native H4 readback
seam, but its generic main/interaction/composition oracle lifetime is rejected as the complete
proof route. The exact K128 model retains 13,808,394,080 persistent bytes and 1,135,869,952 peak
temporary bytes, so `modeled_peak_scratch_bytes=14944264032`, `scratch_gate_pass=false`, and
`route_status=REJECTED_CURRENT_PERSISTENT_ORACLE_LIFETIME`. This is reference evidence only;
continue the selected custom H4 state-composition lane. Do not start H5 or another complete-proof
backend bake-off until a reviewed state plane is selected and atomically bound.

The first custom-lane uniqueness control checks every unordered pair in both phases and verified
with two PCS input claims. K128/128-slot proving measured 21.902903 seconds; K512/512-slot proving
measured 426.679855 seconds plus 38.789283 seconds verification, with a 67,108,864-byte source and
174 authenticated rounds. The quadratic route is rejected because uniqueness alone exceeds the
180-second complete-proof gate. Retain it as a differential oracle and implement a subquadratic
successor; do not tune the rejected route or grant H4/Gate 2E credit.

The first subquadratic successor control is `FP16_SQUAREFREE_DUAL_PRODUCT_GKR_V1`. It uses a
linear-size dual-number product tree and four bounded Bezout tables. Exact release measurements are:

| Capacity | Witness bytes | Authenticated scalar rounds | Witness build | Prove | Verify |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 128 | 32,768 | 370 | 0.042439 s | 0.046355 s | 0.023395 s |
| 512 | 131,072 | 546 | 0.698637 s | 0.237447 s | 0.072302 s |

Both controls independently verify and retain `activation_allowed=false`. These component times do
not include auxiliary/input PCS composition, parent serialization, or the complete H4 boundary.
The exact PCS composition control now packs the four tables into one fixed auxiliary codeword and
lifts the twelve state-column reductions into the existing H4 main geometry for both profiles.
Production still must retain/open that auxiliary tree, extend the parent transcript/grammar, and
independently verify the complete boundary before using the improvement in a complete-proof
projection or Gate 2E decision.

## 12. H5 qualification preflight boundary

`experiments/bl_pq512_crypto_foundation/h5_qualification_preflight.py` now provides a read-only,
fail-closed preflight for the next campaign. It independently replays the 11-record terminal
ledger, validates the recorded reference hardware, checks the one tracked commit-bound `ops/`
authority, and freezes exactly one uncounted warm-up plus ten unique measured
launches for each profile: 22 fresh launches total. It never starts CUDA, accepts cached proofs or
witnesses, substitutes a failed run, assigns `proofSuiteId`, or authorizes activation.

Current preflight evidence:

```text
status=BLOCKED_H5_PREFLIGHT
preflight_digest_sha3_512=9c8cd9e4836576487431af85e3c1ae2b458d44580c144ceeda971f500cd9be279910ea88045761f59699d7b67a8520920a17f07b33d173ce9270d0d064d31693
canonical_ops_status=VERIFIED_TRACKED_SHA3_512_AUTHORITY
reference_hardware_status=READY
fresh_launch_count=22
proofSuiteId=None
activation_allowed=False
```

The preflight focused/attack suite passed 6 tests in 44.60 seconds; the benchmark, S6/S7,
terminal-ledger, and preflight containing set passed 61 tests in 117.72 seconds. The complete
S1-S7 plus terminal-ledger and preflight set passed 79 tests in 175.33 seconds. These are test-run
times, not complete-proof measurements. The recorded reference disk is 487,335,129,088 bytes
with 59,091,513,344 bytes free; the operational reserve is now 15,000 ppm (1.5%), requiring
7,310,026,937 bytes. This does not change the immutable 5,000,000,000-byte RSS/scratch or
zero-swap gates.

## 13. H6 qualification preflight boundary

`experiments/bl_pq512_crypto_foundation/h6_qualification_preflight.py` is a non-launching
qualification ledger. It independently replays H5 and Gate 2E, validates the unselected suite
registry, and records all twelve H6 obligations without assigning timing or qualification credit.
The current record is `BLOCKED_H6_PREFLIGHT`: five obligations are blocked, five are open, and two
are reference-only, with 22 distinct blockers. No proof, witness, retry, state admission,
`proofSuiteId`, or activation path is accepted by this boundary.

Focused H6 preflight/attack verification passed `6 passed in 30.02s`; the containing S1-S7,
terminal-ledger, H5-preflight, and H6-preflight set passed `85 passed in 151.88s`. These are
qualification-ledger test times, not complete-proof measurements.
