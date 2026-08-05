# Proving optimization review

Updated: 2026-08-05

Status: current optimization policy. The former paper screen, intermediate arithmetic, and
superseded prototype sequence are preserved verbatim in
`history/PROVING_OPTIMIZATION_REVIEW_THROUGH_2026-08-01.md`. Rejected designs remain governed by
`REJECTED_ARCHITECTURES.md`.

## Current selected baseline

Blind Ledger currently uses the exact seven-layer B=16 Fp16 GKR hash coprocessor, one output plus
four relay-free hash input claims, native GKR masks, Construction 8.2 random-padded interleaved-RS
PCS, the 6,113-round fixed dual-PQ authenticated prelude, authoritative Rust verification, and
one/four-shard atomic coordination. The state-composed shape has nineteen fixed claims and reaches
6,727/6,995 K128/K512 rounds. The exact H5 campaign measured the complete state-boundary p95 at
32.360845 seconds for K128 and 148.861885 seconds for K512.

Complete one-run H4 evidence is 29.974129 seconds for K128 and 120.460733 seconds for K512.
Internal host peaks are 288.412/296.255 decimal MB; external process-tree peaks are
681.607168/706.523136 MB; tracked device state is 969.999360 MB per proof; K512 sampled total GPU
residency is 2,770.337792 MB; scratch and pagefile growth are zero.

These measurements are state-free H4 baseline evidence. Gate 2E is sealed nonactivating, H5 is
qualified for the exact 22-launch campaign, and H6 is qualified for the bounded candidate-evidence
scope. The current optimization dependencies are production state/verifier integration, resource
telemetry ownership, and the downstream Waves 3-6 gates; `proofSuiteId` remains null.

## Decision rule

Maximum measured throughput is subordinate to correctness, privacy, strict PQ security,
auditability, modularity, and complete independent verification.

For every proposed optimization:

1. identify the measured complete-proof bottleneck or theorem-required work;
2. trace its producer, all consumers, transcript dependency, allocation owner, and verifier check;
3. remove work with no theorem, invariant, compatibility, audit, or measured-throughput purpose;
4. otherwise fuse, stream, derive, tile, batch, vectorize, or overlap it without changing authority;
5. preserve exact proof bytes/statement or version the grammar and prove migration explicitly;
6. run scalar/reference parity, mutation/attack tests, and authoritative independent verification;
7. measure the complete boundary in decimal resources; and
8. retain the change only if the complete process improves without new leakage, nondeterminism,
   resource risk, or audit bloat.

A microbenchmark, paper claim, field kernel, encoder speedup, or internal verifier result is not an
optimization result until the containing proof improves.

## Current admitted work

### Gate 2E state relation and PQ commitment

Implement the C0 control and C1-C4 relation candidates behind the exact interfaces in
`IMPLEMENTATION_ROADMAP.md`. Screen PQ commitment candidates separately. Scalar correctness and
negative equivalence precede SIMD/CUDA/lattice work. Finalists receive state-only measurements,
then fresh complete K128/K512 proofs. Select the fastest candidate satisfying every theorem,
privacy, migration, independent-verifier, memory, scratch, and no-swap gate.

### H5 measured dominant-stage refinement

The exact 22-launch campaign is now complete and recorded above. If a future change affects the
complete process, profile only the measured dominant stage, rerun the containing campaign from a
new coherent commit, and retain every failed measurement; never replace or discard it.

### Server-scale parallelism

The reference path may use the best safely measured count from 16 logical CPU workers with
deterministic partitioning and canonical merge. Future large CPU boxes may scale independent
bounded work, but the laptop cannot depend on server RAM. Shared challenges still require a complete
batching theorem; independent shard proofs do not receive that shortcut.

An August 5, 2026 laptop experiment reconsidered the previously excluded parallel-shard mechanism
without sharing challenges or changing proof semantics. The coordinator launched at most two
independently bound shard workers, waited for the complete group, validated and committed outputs in
canonical shard order, conservatively summed concurrent resource peaks, and rejected any qualified
suite identity in parallel mode. On the same K512 boundary, state binding, binaries, and Brave-open
host, serial execution independently verified in `134.095254` seconds. The corrected two-lane,
nonqualifying confirmation independently verified in `104.094428` seconds, a `22.37%` wall-time
reduction, with `596.279` MB conservative host peak, `1,976.484224` MB conservative device peak,
zero scratch, and no pagefile growth. The finalized binary then independently verified a second
two-lane run in `100.412382` seconds with `5,284` MiB externally sampled total GPU residency and no
pagefile growth. The two nonqualifying confirmations average `102.253405` seconds, a `23.75%`
reduction from the serial control. The immutable 5 GB limit governs host RSS and scratch, not total
GPU residency; the latter remains mandatory telemetry. A four-lane run was rejected: it took
`128.583416` seconds,
reached `7,890` MiB externally sampled GPU residency, and grew pagefile usage by `126` MB. The
exploratory coordinator is therefore hard-capped at two lanes; the sealed H4/H5 execution remains
serial, while the unqualified native coordinator now defaults to two lanes. The sealed H5/H6 evidence
is unchanged. This default is nonactivating and does not turn the generic Cairo/encrypted-worker
scheduler into a native K512 scheduler.

### Promotion checks completed for the two-lane candidate

The fresh K512 campaign used one warmup plus ten measured launches over eleven distinct state
bindings, with no proof-suite identity supplied. All eleven state-binding checks and external
monitor runs passed: four shards independently verified, stderr was empty, driver events were
zero, scratch was zero, and pagefile growth was zero. Measured wall times were
`100.392184, 100.598097, 100.820600, 101.004053, 101.178240, 101.419610, 101.483205,
101.529263, 101.712457, 101.798191` seconds; p95 was `101.798191` seconds and mean was
`101.193590` seconds. Maximum reported host/device peaks were `605.774000`/`1976.484224` MB;
maximum externally sampled candidate-tree RSS was `1467.465728` MB and system GPU residency was
`5314` MiB. The first wrapper warmup is retained but excluded because its strict monitor observed
`2` MB pagefile growth; the corrected campaign did not relax that gate.

A live cancellation killed the coordinator, Python workers, and native bridge descendants with
Windows `taskkill /T /F`; a fresh rerun of the same binding independently verified all four shards
in `100.138295` seconds. The production scheduler review also closed the generic timeout gap by
adding fail-closed process-tree termination and a focused unit test (`19 passed`); failure to
confirm tree termination is now non-retryable. The native coordinator's default is now two lanes
without a qualified suite identity and serial with one; explicit parallel mode with a qualified
suite is rejected. The default remains nonactivating, receives no H5/H6 credit, does not change
sealed evidence, and does not activate a suite.

### Default decision recorded on 2026-08-05

The default change is intentionally limited to the native K512 coordinator. Ordinary queued claim
and encrypted-envelope jobs continue using their existing Cairo/isolated-worker backends because
their request schema does not contain the native boundary, state-binding, prototype, worker, and
execution-manifest inputs required by this coordinator. Routing them through the experimental path
would be an unverified semantic change, not an optimization. The coordinator therefore selects
two independent shard lanes automatically only for an unqualified native run; a qualified suite
selects serial execution, and an explicit qualified parallel request fails closed.

The rebuilt binary was then exercised twice with `BL_SHARD_CONCURRENCY` absent. Both launches
reported `shard_concurrency=2`, verified all four shards, returned `proof_suite_id=null`, and
passed the internal latency/resource checks (`107.919881` and `107.845533` seconds; internal
host `803.598`/`802.583` MB; device `1976.484224` MB; scratch `0`). The external no-swap gate
rejected both: the first recorded pagefile growth of `305` MB and the second `18` MB. Their
external process-tree peaks were `1700.524032`/`1697.595392` MB, GPU peaks were `5253`/`5429` MiB,
driver-event counts were `0`, and stderr bytes were `0`. These are default-path functional
checks plus resource failures, not qualification evidence; the no-swap gate remains unchanged.

## Not optimization knobs

- the sealed relation, retry identity, money, state equality, or ordered 12-field ABI;
- SHA3-512 authority or M31/Fp16 parameters;
- authenticated interactive public coin or zero grinding credit;
- native hiding and the complete 256-bit ledger;
- canonical parsing and independent Rust verification;
- the 5,000,000,000-byte host/scratch and no-swap gates;
- fixed observable shape; or
- driver-integrity admission.

Changing one requires a stronger complete theorem and explicit architecture review, not a
performance patch.

## Excluded active paths

RISC Zero, the removed Stwo/QM31/Blake2s backend, direct monolithic SHA3 AIR/STARK, BaseFold,
zkDeepFold, WHIR-style preselection controls, B=64, merged characteristic-two layers, scalar
full-source replay, conjecture-dependent decoding, trusted setup, curves, and theorem-free shard
parallelism are not current candidates.

Paper mechanisms may be reconsidered only through the rejection discipline: exact theorem mapping,
security ledger, source/license pin, independent implementation/verifier, complete simulator,
failure/migration behavior, and a measured complete-boundary advantage.

## Evidence required per optimization

- invariant or bottleneck statement;
- source/manifest identity and exact diff;
- public/private I/O and grammar effects;
- transcript and verifier equivalence;
- scalar/reference and cross-language KATs;
- mutation, malformed, retry, crash, rollback, and cleanup results;
- complete process and stage timings;
- host/process-tree RSS, device state/residency, scratch, I/O, and pagefile;
- proof/receipt/stdout/stderr hashes;
- driver interval; and
- measured/derived/projected/unknown label for every number.

The current active commands and STOP conditions come from the sealed phase handoff, not this policy
document. Chronological research and the complete former source table remain in the archived file.
