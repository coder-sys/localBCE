# Proving optimization review

Updated: 2026-08-02

Status: current optimization policy. The former paper screen, intermediate arithmetic, and
superseded prototype sequence are preserved verbatim in
`history/PROVING_OPTIMIZATION_REVIEW_THROUGH_2026-08-01.md`. Rejected designs remain governed by
`REJECTED_ARCHITECTURES.md`.

## Current selected baseline

Blind Ledger currently uses the exact seven-layer B=16 Fp16 GKR hash coprocessor, one output plus
four relay-free input claims, native GKR masks, Construction 8.2 random-padded interleaved-RS PCS,
one 6,086-round dual-PQ authenticated interactive schedule, authoritative Rust verification, and
one/four-shard atomic coordination.

Complete one-run H4 evidence is 29.974129 seconds for K128 and 120.460733 seconds for K512.
Internal host peaks are 288.412/296.255 decimal MB; external process-tree peaks are
681.607168/706.523136 MB; tracked device state is 969.999360 MB per proof; K512 sampled total GPU
residency is 2,770.337792 MB; scratch and pagefile growth are zero.

This baseline is prototype-accepted, not H5/H6-qualified. Gate 2E state selection and binding is the
only current optimization dependency.

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

After Gate 2E is sealed, run the 22-launch campaign. If a STOP or latency failure occurs, profile
the complete process and refine only the measured dominant stage. Rerun the containing campaign
from a new coherent commit; never replace or discard a failed measurement.

### Server-scale parallelism

The reference path may use the best safely measured count from 16 logical CPU workers with
deterministic partitioning and canonical merge. Future large CPU boxes may scale independent
bounded work, but the laptop cannot depend on server RAM. K512 shards remain sequential on one GPU
until a complete batching theorem authorizes shared challenges and measurement proves a benefit.

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
