# Archived BL-PQ512 throughput and proof-size recovery plan through 2026-08-01

Updated: 2026-07-31

Status: authoritative R&D and execution plan for the active strict-PQ proof wave. This document
does not select or activate a proof suite. `proofSuiteId` remains null, production use remains
forbidden, and real PHI or payment credentials remain forbidden.

## Current integration checkpoint

The exact transfer record remains `../WAVE2_HANDOFF_2026-07-26.md`; the newest dated
`../STATE.md` section is the current execution truth. The bounded recovery is complete at the H4
prototype boundary. The real semantic source, 168-layer/native-masked GKR, Construction 8.2 PCS,
6,086-round authenticated public coin, atomic one/four-shard coordinator, and independent Rust
verifier now complete together.

Under execution manifest
`51c23310274ccf7c4d7f9abe4ae7eba43266b335bd377b21cbf92409729b91e2a40a39787a157baa080c9d0516c7815af404a4d58d9e76747f652f57cd017ed6`,
fresh K128 and K512 prototypes passed in 29.974129 and 120.460733 seconds. Internal host peaks were
288.412/296.255 MB, external process-tree peaks were 681.607168/706.523136 MB, tracked per-proof
device state was 969.999360 MB, and scratch was 0.000000 MB. Both accepted attempts had zero
pagefile growth and zero post-reset driver events. These are decimal MB and one-run prototype
results, not the H5 p95 campaign.

The historical 200 MB host and 1,800 MB device component-selection targets are explicitly
superseded as acceptance criteria by the owner's later low-hundreds-of-MB host direction. They
remain dated evidence. The immutable 5,000 MB RSS, below-5,000 MB scratch, and no-swap gates are
unchanged.

The next architecture dependency is gate 2E: select and atomically bind the authenticated-state/PQ-
commitment plane used by the candidate that will be qualified. Only then run H5's one uncounted
warm-up plus ten unique K128 and K512 batches through independent verification, followed by H6 suite
qualification. The 256-bit security/encryption, simulator, privacy, 5,000,000,000-byte peak-RAM,
below-5,000,000,000-byte scratch, no-swap, and activation gates do not move.

The current integration checkpoint above and the newest dated section below control execution
status. Intermediate sections preserve chronological requirements and evidence; any use of
"current," "next," or "open" inside an older dated stage is scoped to that stage and is superseded
for status purposes without changing its raw measurement or rejection evidence.

### 2026-07-28 sub-30 architecture checkpoint

The owner's current engineering target is below 30 seconds for the complete fresh K128 proof,
including the semantic AIR, bus, GKR, PCS, authenticated coin, parsing, and independent
verification. The prior below-60-second K128 release gate remains a rejection floor, not the
architecture-selection target.

Section 8.2 of `BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md` is the controlling nonactivating
blueprint. It selects the exact seven-layer relay-free Fp16 DAG, B=16 packing, a concurrent bounded
M31 semantic-AIR CPU lane, the two-instance hiding BaseFold layout, one canonical GKR-message
record, and an atomic join.

The corrected five-repetition controls project 25.291229 seconds for the packed bridge plus all
shared-group messages/folds. After overlapping authenticated coin-head work with initial PCS
commitment work, the closed measured-component critical path is 26.859692 seconds and the unmeasured
envelope is 3.140308 seconds. Six stages remain open and receive no zero-cost credit: wire tail,
masks, PCS folds/multiproof construction, semantic-lane synchronization, atomic composition, and
production setup/transfers. This is sufficient to authorize implementation and measurement, not to
claim a complete-proof projection or qualification.

The six-layer ternary-theta candidate, merged degree-11 theta candidate, B=8, B=32, and B=64 are
rejected by exact arithmetic/packing screens. The selected seven-layer/B=16 schedule contains no
measured removable layer or packing bloat. PCS remains the largest theorem, hiding, memory-lifetime,
and integration risk even though its isolated arithmetic is fast.

### 2026-07-29 Construction 8.2 correction and live integration state

Historical status at this checkpoint: **SELECTED NONACTIVATING ATTEMPT ARCHITECTURE; COMPLETE FRESH
PROOF NOT YET RUN**. The current H4 result is in the 2026-07-31 section.

This checkpoint supersedes the 2026-07-28 BaseFold selection and its 26.859692-second accounting
where they conflict. The seven-layer/B=16 relay-free GKR topology remains selected. The PCS is now
Construction 8.2 of Chiesa--Fenzi--Weissenberg, ePrint 2026/391, instantiated over the existing
Fp16/M31 profile with random-padded interleaved Reed--Solomon codewords. The retained ePrint
2025/1828 Block-Accumulate paper is comparison evidence; it is not the selected PCS.

The current K128 construction is:

1. run the sealed non-hash M31 semantic AIR as a bounded CPU/SIMD stream concurrently with the hash
   lane;
2. prove the exact 168-layer, seven-layer-per-Keccak-round B=16 relay-free GKR on the untrusted GPU
   while Rust owns canonical messages and verification;
3. expose exactly two `2^24`-value GKR source boundaries as 512 interleaved Fp16 RS messages;
4. use a main RS code of length 131,072 with 65,536 message values, 2,048 random-padding values,
   and 1,600 queries;
5. use nine auxiliary RS codewords of length 8,192 with 2,048 message values, 1,218
   random-padding values, and 1,218 queries;
6. commit the fixed 35-tree segment-16 grammar, or the equivalent 19-tree segment-32 throughput
   grammar, with SHA3-512 canonical global multiproofs and independent Rust verification; and
7. authenticate one shared public-coin chain and atomically bind the exact GKR terminal claims,
   Construction 8.2 transcript, semantic program/bus, roots, parameters, verifier identity, and
   ordered 12-field statement.

The corrected shared schedule is 6,086 authenticated rounds: 6,072 GKR transcript rounds, one
independent aggregate mask-functional challenge, and 13 downstream PCS rounds. The earlier
6,241-round count included a stale BaseFold schedule, while the 5,821 and 5,822 counts omitted
required coordinate, terminal-extension, multi-claim, and mask-opening challenges. The
standalone PCS integration KAT uses 14 rounds because it must also authenticate the complete GKR
claims boundary before its two batching challenges. The real dual-PQ coordinator executed and
independently replayed all 6,086 descriptors; the complete producer has not yet occupied the
mask-batch and downstream PCS descriptors in that same session.

#### Current measured evidence

| Boundary | Result |
| --- | ---: |
| Exact B=16 GKR component sum | 24.7958928 seconds |
| Segment-16 initial PCS mechanics | 6.449925 seconds |
| Segment-16 proof-phase host peak | 164.966 MB |
| Segment-16 device allocation | 873.986048 MB |
| Segment-32 initial PCS mechanics | 3.586543 seconds |
| Segment-32 proof-phase host peak | 191.533 MB |
| Segment-32 device allocation | 1,612.185152 MB |
| Segment-32 initial-oracle multiproof | 14.347776 MB |
| Native 35-tree multiproof verification | 0.732555 seconds |
| Native complete answer-code verification | 0.293384 seconds isolated |
| Construction 8.2 hiding audit peak | 26.104 MB |
| Historical 5,821-round shared-coin control | 1.267659 seconds |
| Shared-coin bundle | 3.770467 MB |
| Five-claim host row-sumcheck integration | 20.386079 seconds |
| Host integration peak | 134.177 MB |
| Joined production GPU row state | 12.058624 MB |

All memory measurements above use decimal MB. Scratch was 0.000000 MB in the successful PCS
geometry controls. The segment-32 measurements passed the then-current 200 MB host and 1,800 MB
device component-selection screen. Those numbers are now historical evidence, not acceptance
gates, and the controls are not complete-proof resource qualification.

The selected segment-32 launch gate now follows this bounded architecture rather than the retired
blanket 8,589.935 MB decimal free-host-RAM campaign floor. Preflight requires at least
`max(1,000 MB decimal, 2 * latest measured complete-proof peak RSS)` free physical host memory and
at least 2,000 MB decimal free device memory. Until the first complete proof supplies its own peak,
the 1,000 MB host floor governs against the measured 191.533 MB component peak. External monitoring
must reject swap growth, a complete-proof host peak above the 200 MB engineering target, device use
above the 1,800 MB target, scratch at or above 5,000 MB, or RSS above 5,000 MB. This admission
correction changes no theorem, hiding, verification, or immutable resource gate.

The first actual uniform-zero-trace relay-free producer now gives a lower direct host calibration
than the earlier component envelope. Through the live dual-PQ coordinator and independent coin plus
GKR replay, all 168 real DAG layers and 6,072 raw GKR rounds completed in 13.484277 seconds at
52.457472 MB sampled peak host memory, 0.000000 MB device memory, and zero duplicate 8,192-group
materializations. This is real-GKR component evidence only: native masking, its aggregate PCS
opening, the downstream PCS, and the complete-proof monitor remain open.

The exact selected mask layout is 23,544 used coefficients padded to 32,768, with conservative
view rank 22,705. The rank consists of 7,728 bridge, 14,304 sumcheck, 672 layer, and one aggregate
opening observation. These values supersede the earlier pre-terminal-correction mask counts.

The security ledger gives 392.179996538 bits for the main code, 392.108419573 bits for the
auxiliary code, and 392.108419573 bits for their current composition. It now also accounts for the
five-claim batch, sixteen-coordinate batch, source/mask batch, and nine degree-two sumcheck rounds;
those algebraic terms are 491.830074988 bits or stronger. Random padding covers all 1,600 main
queries and all 1,218 auxiliary queries. The executable hiding audit checks the exact Construction
7.2/8.2 conditioned-view algebra and reports perfect query-view hiding for the tested relation. It
is an offline audit gate and contributes no proof-path time.

Rust now binds one output and four relay-free input claims. Every claim fixes one 24-coordinate
point, one packed value, one shard query, and sixteen committed component evaluations before the
claim and coordinate batching challenges. Rust derives the five claim powers, sixteen linearized
coordinate coefficients, initial target, compact quadratic chain, and independent final answer
target. CUDA extracts the required five-by-512-by-sixteen component rows directly from one live
tile per public boundary; it does not replay a full source table or retain a second codeword. The
joined 144-state row plane totals 12.058624 MB: 80 claim-component source/relation states plus 64
committed GKR-mask states. The complete auxiliary answer contains nine univariate sumcheck-mask
words and 64 multilinear GKR-mask words. The v4 stream and answer verifier reject malformed
dimensions, wrong boundaries, zero batching challenges, target/component/scale/GKR-terminal/
GKR-mask-answer mutations, ordinal drift, replay, and word-value/claim mismatches before accepting
the final target.

#### Complete-prototype gate

The complete H3 prototype now passes input-to-independent-verification in 24.749154 seconds after
one uncounted cold driver-JIT warm-up. The earlier 28.3824358-second GKR-plus-initial-PCS subtotal
predates the real 73-word join and remains historical component evidence. The real masked GKR
producer, exact same-chain coordinator, PCS, atomic parser, and independent verifier are attached.
H4 semantic-lane atomic composition and H5/H6 qualification remain open and receive no credit from
the H3 prototype result.

There is no first-principles reason to remove the seven DAG layers, B=16 packing, 512 interleaved
messages, 35/19 tree grammar, random padding, native masks, SHA3-512 roots, dual-PQ public coin, or
independent Rust verifiers: each is required by the circuit, memory segmentation, hiding theorem,
hash authority, or untrusted-GPU boundary. Actual removable bloat has been removed or prohibited:
no circular GPU verification, no Python field verifier on the hot path, no repeated Merkle paths,
no second transcript copy, no host-supplied PCS form, no duplicate full source replay, and no
simultaneous full dual-boundary codewords. Retained device Merkle trees use 288.357120 MB; a
separate 268.435456 MB row-major replay staging allocation is not tree storage. The retained trees
avoid a second full hash pass and remain purposeful until a measured replacement improves
complete-proof throughput.

The Windows boot at `2026-07-29 18:06:49 -06:00` did not clear the driver gate: ten later Event 153
records ended at `2026-07-29 23:16:18 -06:00`. A scoped NVIDIA reset was therefore performed at
`2026-07-30 09:02 -06:00` and followed by a clean PnP, `nvidia-smi`, and System-log audit. No failed
or pre-reset GPU run receives evidence credit.

## 1. Decision

The sealed claim relation is not being discarded. Its semantics, exact 12-field ABI, fixed-shape
privacy, SHA3-512 commitments, dual-PQ authority, replay protection, and economic conservation are
the correct safety boundary. The pre-recovery direct proof engine around that relation was not
release-feasible: it repeated Merkle authentication data, duplicated disk layouts, and applied a
generic wide-column PCS path to a SHA3-heavy relation. Those were engineering and proof-topology
problems, not reasons to weaken the statement.

The active wave therefore has two independent jobs:

1. make the proof encoding compact without changing a single checked value or security parameter;
2. make full K128 proving fit a frozen deployment envelope and maximize measured steady-state
   claims per second inside that envelope.

A smaller proof does not by itself prove faster generation. A streamed prover that fits on disk does
not by itself satisfy the throughput objective. Both gates must close independently.

The architecture bake-off produced the primary implementation path:
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`. Wave 2 keeps the sealed M31 semantic AIR but
removes its six internal SHA3 tables from the generic wide-column release PCS. One canonical
committed hash-call bus binds that AIR atomically to a data-parallel Boolean GKR/sumcheck
coprocessor over Fp16. The 554-951 GB direct-SHA3-STARK layouts are retired release architectures,
not fallbacks. H4 now passes the real bridge, native masking, Construction 8.2 PCS, atomic verifier,
one-run resource gates, and K128/K512 prototypes. This remains an implementation priority, not suite
activation: gate 2E, the complete simulator/security composition, H5, and H6 still have to pass
fail-closed qualification.

`docs/FRONTIER_THROUGHPUT_AND_ETHEREUM_ALIGNMENT.md` adds the next measured layer: a privacy-padded
access manifest, exact state/conflict census, deterministic conflict DAG, and authenticated-state
topology bake-off. These attack the 98.61% state-hash concentration without replacing a safe root
layout on conjecture. They add no package and are not a measured speedup.

`docs/BL_PQ512_COMMITTED_SPARSE_STATE_PLAN.md` makes that topology work a mandatory Wave 2
selection gate. The current endpoint-multiproof/sorted-memory SHA3 path remains the control while
persistent sparse memory, transparent dictionaries, touched-projection RAM, compact shuffle-based
memory consistency, and native-hiding PQ commitment backends are implemented and measured. No
candidate is selected by paper benchmark, asymptotic claim, or primitive name.

## 2. Non-negotiable constraints

Every candidate must preserve all of the following:

- M31 base arithmetic with the reviewed degree-16 extension construction;
- full-width SHA3-512 for the PCS, transcript receipts, authoritative commitments, and audit roots;
- standardized ML-DSA-87 and SLH-DSA-SHAKE-256f authentication on Blind Ledger-controlled
  public-coin and authority surfaces;
- no RSA, ECC, QM31-only ceiling, Blake2s-256 ceiling, launch Fiat-Shamir/QROM dependency, grinding
  credit, trusted setup, or outside proving service;
- at least the frozen 256-bit cryptographic security/encryption floor for every theorem/error-ledger
  term and the composed ledger;
- identical public shape, operation schedule, proof-section lengths, and error behavior for approval,
  every denial, and cover;
- fail-closed canonical parsing, bounded allocation, exact versioning, and mutation tests;
- the exact ordered 12-field external ABI, with no PHI or private operational metadata added;
- module identities, reproducible builds, exact KATs, cross-language parity, and reviewable evidence;
- an internally buildable sandbox and deployment candidate. The independent audit reviews the
  finished candidate; it does not design or implement it.

No performance result receives credit if it weakens one of these constraints.

## 3. Current measured and derived evidence

### 3.1 Real strict-PQ kernel proof

The current fixed-column regression kernel generates and independently verifies a real proof under
the dual authenticated public-coin flow.

| Item | Current evidence |
| --- | ---: |
| Proof bytes | 28,643,096 bytes (27.316 MiB) |
| Query count | 945 |
| FRI committed layers | 15 |
| Trace masks | 4,789 |
| Quotient masks | 946 |
| Fresh worker wall time, run 1 | 50,070 ms |
| Fresh worker wall time, run 2 | 47,178 ms |
| Run-2 main / interaction | 437 ms / 2,954 ms |
| Run-2 composition / DEEP | 13,248 ms / 12,219 ms |
| Run-2 FRI start / folds / openings | 2,011 ms / 284 ms / 224 ms |
| Run-2 independent verification | 940 ms |

The two runs are evidence for this kernel and this machine only. They are not K128 timings and are
not a stable production benchmark. The stage data shows that composition and DEEP work dominate the
measured cryptographic stages; opening construction is small. Proof compression is primarily a
bandwidth, parser, verifier-hash, and storage improvement until end-to-end measurements prove more.

The table above is the frozen v1 baseline. The authoritative `BLPQPRF2` path now encodes, decodes,
and independently verifies the same proof semantics with verifier-derived coordinates and one
canonical global multiproof per FRI layer. It also emits each repeated cross-domain sibling node and
opened row once per committed tree coordinate in canonical order, then reconstructs the individual
openings before verification. The latest real dual-PQ run measured 6,755,933 bytes, saving
21,887,163 bytes (76.41%). The
exact v2 byte count varies with the authenticated random query set;
the regression gate therefore enforces the v1 comparison, arithmetic consistency, and a
21,000,000-byte minimum saving instead of a false fixed compact size.
The production workers do not generate v1 merely to report this comparison: tests retain the
frozen baseline, live proving emits only v2, FRI compaction borrows the existing layer openings
without cloning their paths, and the original proof object is dropped before v2 decode/verification.

### 3.2 Exact kernel FRI redundancy

The v1 proof grammar stores a separate Merkle proof for the left and right member of every adjacent
FRI pair, for every query, in every layer. It also repeats the same opened values and paths when
different transcript queries converge on the same lower-layer positions.

For the exact authenticated query set used by the regression proof:

| Item | Current v1 | Canonical global multiproof model |
| --- | ---: | ---: |
| Transcript queries / unique initial positions | 945 / 938 | unchanged |
| FRI authentication-path digests | 226,800 | 8,118 |
| FRI opened extension values | 28,350 | 9,982 |
| Path-digest payload | 14,515,200 bytes | 519,552 bytes |
| Opened-value payload | 1,814,400 bytes | 638,848 bytes |

Pair-aware paths alone remove 8,164,800 bytes of repeated digest payload from this proof. A global
canonical FRI multiproof plus deduplicated opened values removes 15,171,200 bytes of current payload,
or 52.97% of the entire v1 proof, before accounting for the new grammar's smaller metadata and any
new bounded references. The arithmetic remainder, 13,471,896 bytes, is a payload-only projection,
not a promised final proof size. The first completed global-FRI-only v2 run measured 12,959,483
bytes. Canonical cross-domain sibling/value maps then reduced the same grammar class to 6,755,933
bytes on a real run: 517,312 FRI path-digest bytes, 636,544 FRI opened-value bytes, 15 layer
records, zero prover-supplied initial-index bytes, and exact reconciliation to total proof bytes.

This compression preserves all 945 transcript draws and their multiplicities. It changes neither
which positions are checked nor the committed roots, hash function, field, FRI folds, hiding masks,
or soundness ledger.

### 3.3 Full K128 resource failure

The complete K128 relation has 46,858 SHA3 calls in the exact six-segment schedule
`(516, 129, 1, 9,360, 36,848, 4)`. Replay and payment state account for 46,208 calls, or 98.61% of
the schedule. Any serious AIR recovery must therefore target authenticated state/hash topology and
the SHA3 proof path; micro-optimizing the four-call master segment cannot matter.

The current full-interface model reports:

| Monolithic family | Bytes |
| --- | ---: |
| Raw witness | 23,171,830,448 |
| Main evaluations | 269,215,596,544 |
| Interaction evaluations | 13,220,446,208 |
| Composition evaluations | 34,762,391,552 |
| DEEP evaluations | 8,710,864,764,928 |
| FRI masks | 2,248,146,944 |
| Largest folded layer | 4,294,967,296 |
| **Monolithic live lower bound** | **9,034,606,313,472** |

That approximately 9.03 TB value is a rejected monolithic live-memory lower bound. It is not proof
size and it is not the requirement of the disk-backed implementation.

The current disk-backed model reports:

| Streaming family | Bytes |
| --- | ---: |
| Persistent oracle files | 670,331,346,736 |
| Peak temporary files | 86,838,870,016 |
| Filesystem headroom | 189,292,554,188 |
| Fixed reserve | 4,294,967,296 |
| **Required available scratch** | **950,757,738,236** |

That approximately 950.76 GB value is scratch-storage capacity, not RAM. It is a rejected negative
baseline and exceeds the current local machine's available storage.

The estimator explicitly retains two copies of main, interaction, and composition evaluations.
Removing only that duplication would remove 317,198,434,304 persistent bytes and, under the same
25% headroom formula, reduce modeled required scratch to 554,259,695,356 bytes. This is a derived
design projection, not a measured implementation result. It proves that storage layout is a major
cost center; it does not close the resource gate and is no longer a release candidate.

## 4. Root causes

1. **Proof grammar duplication.** Adjacent pair paths are authenticated twice, and authentication
   is serialized independently per query instead of once per committed tree.
2. **Wide high-degree SHA3 AIR.** The selected safe Boolean SHA3 round table has 1,995 columns,
   2,843,250 K128 rows, and maximum degree 11. It dominates the raw witness and expands the
   composition/DEEP geometry.
3. **Generic extension-field expansion.** The current generic path conceptually lifts large base-
   field families into Fp16 and degree-corrected DEEP batches. Streaming prevents the whole object
   from residing in RAM but does not remove the arithmetic and I/O.
4. **Duplicated persistent layouts.** The disk plan retains row and column forms for each committed
   oracle family and stores full Merkle levels even when a later recomputation may be cheaper.
5. **State hashing dominates.** Payment plus replay is 98.61% of K128 SHA3 calls. The endpoint
   multiproof/sorted-memory relation already prevents naive repeated path authentication, so further
   reductions require a proved state/hash architecture change rather than deleting checks.
6. **Parameters are deliberately conservative.** The 945-query setting supplies the current
   per-term safety floor. It cannot be lowered merely because proofs are large.

## 5. Execution tracks

### Track A - exact cost observability

Implement a deterministic byte and resource attribution layer before changing the proof:

- encoded bytes by header, oracle, query, tree, FRI layer, field payload, and metadata;
- prover time, CPU time, peak RSS, read/write bytes, temporary high-water mark, and retained files by
  main, interaction, composition, DEEP, FRI, openings, serialization, and verification stage;
- SHA3 call, permutation, row, column, identity, lookup-message, and domain-log attribution by
  relation component;
- one stable JSON schema with exact source, program, parameter, hardware, and toolchain identities.

No optimization may claim a percentage improvement without baseline and candidate records from the
same benchmark protocol.

### Track B - theorem-neutral proof grammar v2

Build the highest-confidence reduction first:

1. one canonical adjacent-pair opening instead of two independent paths;
2. one sorted global multiproof per committed tree across all 945 query positions;
3. one copy of each opened value, with transcript query multiplicities mapped through bounded
   canonical references;
4. implied node ordering from roots, tree size, and authenticated query positions so attacker-
   supplied node indices are unnecessary where derivable;
5. strict counts, maximums, no trailing bytes, no duplicate canonical nodes, root reconstruction,
   and mutation/fuzz tests;
6. byte-exact memory/disk prover parity and an independent no-prover verifier implementation.

The v1 parser remains isolated for historical artifacts. No v1/v2 ambiguity or silent fallback is
allowed. The suite identity must bind the grammar version.

### Track C - bounded-memory prover layout

Prototype and measure these changes independently:

- keep one canonical evaluation layout rather than permanent row-plus-column copies;
- fuse FFT output, batching, Merkle leaf construction, and downstream consumption in bounded slabs;
- derive verifier-fixed columns on demand and never persist them merely for convenience;
- commit Merkle roots with a frontier, then either retain levels or recompute the exact global
  multiproof after queries arrive according to a deterministic measured planner;
- fuse base-to-Fp16 batching so the prover never materializes an all-column Fp16 object;
- make every scratch file content-addressed, length-bound, session-owned, zeroized/deleted on
  success or failure, and recoverable only through authenticated manifests.

The planner may choose retention or recomputation only from public geometry and declared hardware;
it may not branch on witness values or decision class.

Implementation status (2026-07-25): main, interaction, and composition oracles retain canonical
columns and build SHA3-512 leaves directly from bounded slabs across those files; they no longer
create full-domain construction row transposes. The disk FRI proof path globally deduplicates
required cross-domain indices and opens them in one handle-reusing batch. A
public-geometry planner computes exact Merkle-level bytes and retains at most 256 MiB per
cross-domain oracle; above that threshold it constructs the root and exact post-challenge frontier
from canonical columns using a logarithmic hash stack, rechecks the root, and opens the batch
without creating Merkle-level files. Forced recomputation is byte-exact to the in-memory control.
The derived frontier bound is `(QUERY_COUNT + 1) * maximum_log * 64` bytes. Remaining FFT/batching
fusion and measured K128 telemetry remain open.

### Track D - shared-bus Boolean hash coprocessor

The bake-off selected the shared-bus Boolean GKR hash coprocessor as the primary implementation
path. The release candidate must:

1. retain the direct Boolean and byte-lookup SHA3 AIRs as executable differential specifications,
   not as K128 release PCS layouts;
2. commit one canonical fixed-shape message/digest/ordinal/tag bus shared by the semantic AIR and
   hash coprocessor, with an in-circuit eight-bit-to-byte bridge;
3. prove all 113,730 K128 Keccak-f[1600] permutations in one data-parallel repeated Boolean circuit,
   while using the reviewed Fp16 field for GKR/sumcheck challenges;
4. mask every private bus, sumcheck, and terminal evaluation and prove a complete simulator for
   authenticated public coin, aborts, retries, and cross-module reductions;
5. commit every root before challenges and verify AIR, bus, and coprocessor atomically with no
   separately reusable receipt or host-trusted equality; and
6. pass no-swap limits of no more than 5,000,000,000 peak resident bytes and strictly below
   5,000,000,000 scratch bytes on the measured Dell G15 reference laptop before it may receive any
   throughput credit.

Post-hidden-state phase-one control (2026-07-25): the current unqualified K128 architecture model
contains 782 Keccak permutations. At the measured 216-layer, 4,096-padded-width circuit geometry,
the unchanged `B=8` packed reducer processed 45,158,400 gates in a five-run median of 4.8015192
seconds (range 4.3895117-5.0110385), with 12,079,104 bytes peak resident memory, zero scratch, and
one identical SHA3-512 output digest. The measured CPU/wall ratio was 0.9767 and the kernel loop is
serial. This confirms that the old 19-minute estimate cannot be carried into the hidden-state
workload; it does not qualify the hidden-state relation, masking, commitment, complete proof, or
either release profile.
The 2026-07-26 grounding review found no exact hidden-state schema, transition manifest, hash-call
schedule, or derivation artifact behind the hard-coded 782/894 inputs. The later affine model only
interpolates between those two constants. They remain useful workload prices, but receive zero
semantic or qualification credit and cannot drive the canonical external GKR input until the sealed
trust boundaries and every permutation are derived.

The next bounded execution block is: (1) publish one fail-closed K128/K512/K1024/K2048 workload
screen, with K1024/K2048 explicitly marked two-point affine projections; (2) retain the serial
reducer and add deterministic indexed 1/2/4/8/16-worker reductions with private accumulators and
canonical merge order; (3) require byte-identical polynomial/digest parity and measure wall/CPU,
peak resident memory, and scratch; then (4) profile before admitting tower-field or deeper SIMD
work. GPU remains an optional production backend after scalar parity. K128/K512 remain the only
qualification profiles, and every 256-bit security/encryption, privacy, transcript, and resource
gate remains
unchanged.

That bounded block completed on 2026-07-25. The affine model through the unqualified K128/K512
inputs is `permutations = 2234/3 + claims * 7/24`; fractional results are conservatively rounded
up before `B=8` packing. The implementation preserves the serial path, partitions only public gate
indices, uses private worker accumulators, and merges in ascending worker order. Its Rust
differential test passes at 1/2/4/8/16 workers. At the 45,158,400-gate K128 workload, five counted
native-release runs measured these medians:

| Workers | Reduction median | Gates/s median | Outer-wall median | Maximum peak resident bytes |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 3.257033 s | 13,864,889 | 3.313995 s | 12,128,256 |
| 2 | 1.474381 s | 30,628,726 | 1.528380 s | 21,118,976 |
| 4 | 0.848316 s | 53,232,987 | 0.882924 s | 29,876,224 |
| 8 | 0.545055 s | 82,851,043 | 0.582080 s | 47,398,912 |
| 16 | 0.443970 s | 101,714,912 | 0.504356 s | 82,436,096 |

All 30 runs exited successfully, used zero scratch, and produced the identical SHA3-512 polynomial
digest `b9405c999c4928e275b5d5f2c4219e03beba2fc637c6bce32554bc0771f449f5f191309d170e21e9e601d7be914cb3f766549926a74a2ceda088b3c2c1bd1124`.
The 16-worker kernel median is 7.336x faster than the one-worker native-build median.

The larger-batch rows below measure the packed phase-one gate load at 16 workers. Only the timing
is measured; K1024/K2048 permutation counts remain two-point projections. The last column is not a
measurement: it assumes phase one is 55-70% of pre-hiding proof time and hiding adds 15-30%, so its
range is `phase_one * 1.15 / 0.70` through `phase_one * 1.30 / 0.55`.

| Profile | Workload evidence | Permutations | Permutations/claim | Packed gates | Phase-one median | Maximum peak resident bytes | Projected GKR+PCS/FRI+hiding |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| K128 | architecture-model input, unqualified | 782 | 6.109375 | 45,158,400 | 0.443970 s | 82,436,096 | 0.729-1.049 s |
| K512 | architecture-model input, unqualified | 894 | 1.746094 | 51,609,600 | 0.490020 s | 82,427,904 | 0.805-1.158 s |
| K1024 | two-point affine projection, unqualified | 1,044 | 1.019531 | 60,364,800 | 0.555769 s | 82,440,192 | 0.913-1.314 s |
| K2048 | two-point affine projection, unqualified | 1,342 | 0.655273 | 77,414,400 | 0.690725 s | 82,440,192 | 1.135-1.633 s |

These results select deterministic multicore reduction for continued integration. They do not
select a hidden-state commitment, prove the hidden-state theorem, measure later sumcheck rounds or
PCS/FRI/hiding, or qualify any complete proof.

### RTX 4060 accumulator screen

An isolated CUDA screen was run on the reference laptop's NVIDIA GeForce RTX 4060 Laptop GPU
(compute capability 8.9, 8,188 MiB reported VRAM). The machine had the NVIDIA driver but no CUDA
toolkit. NVIDIA NVRTC 12.9.86 was therefore used from a temporary out-of-tree directory; it is not
an adopted build or runtime dependency.

The screen offloaded only packed accumulator construction. Its timed boundary included zeroing
8,454,144 accumulator bytes, 46 bounded kernel launches, synchronization, and copying all
accumulators back to host memory. NVRTC compilation and the later CPU polynomial finalization were
outside the boundary.

- a complete 4,097-gate CPU/GPU accumulator KAT matched all canonical accumulator words, with
  identical SHA3-512 digest
  `4ebc549eed10e15ef46c5ff67b6ce715cc0fd61157412735c6e05f3bbfeb5d805ce7cbd05c16617266866b4eda818628d6ffe3af7496d9335ba4fb6358a6f072`;
- at the 45,158,400-gate K128 workload, one warm-up plus five counted runs measured 21.9701 ms
  median, 21.3339 ms minimum, and 60.6702 ms maximum. Every run produced accumulator digest
  `d798c612a60e40183c55c6401c5febc8bdf3de6d5fd19db19edf397e60ff33266c1f18c33a2b1e904b27086c0defea6f6b96d8b630b9b833df55715ff0720498`;
- a separately sampled run increased whole-GPU memory use from 164 MiB baseline to 274 MiB peak,
  or 110 MiB incremental, while process peak resident memory was 18,747,392 bytes; and
- the 16-worker CPU control measured 55.7518 ms median at a fully populated 100,000-gate bucket set
  and 67.3319 ms at 1,000,000 gates. These totals still include their CPU accumulation work, so
  55.75-67.33 ms is a conservative surrogate, not an isolated measurement, for the dense serial
  polynomial tail.

Combining the GPU accumulator median with that observed dense-tail envelope projects
77.72-89.30 ms for hybrid phase one, or 4.97x-5.71x faster than the measured 0.4439703-second
16-worker CPU control. Applying the same unverified phase-one/commitment/hiding split projects
0.128-0.211 seconds for the GKR+PCS/FRI+hiding lane. Both figures are projections, not proof
measurements.

This screen admits a bounded hybrid integration experiment: import canonical GPU accumulator words
into the existing CPU finalizer, require complete K128 and K512 accumulator parity, require the
same final polynomial and SHA3-512 proof bytes as the serial control, then measure the full boundary
including compilation/caching policy, transfers, fallback, cleanup, and independent verification.
GPU output remains untrusted. Driver failure, timeout, malformed output, device loss, or parity
failure must fall back before proof construction or fail closed. No GPU result changes the
reference-laptop qualification profiles, security floor, or CPU-only verifier requirement.

### Repeated-pack sparse-round screen

The hidden-state workload was then connected to an exact graph-free repeated GKR layer control.
Eight Boolean executions share the degree-21 packed opening move; 128 packs remain in the
fixed-shape domain for both K128 and K512. Group identity is carried through the nonlinear wiring,
so the implementation does not apply AND after averaging groups. The full-width Chi layer contains
524,288 padded gate positions, 409,600 nonzero normalized terms, and 36 quadratic sumcheck rounds.

The first release CPU control measured 41.3972212 seconds proving for K128 and 41.4564861 seconds
for K512, with about 287 MB peak RSS and zero scratch. Direct quadratic-coefficient generation,
Boolean output evaluation, deterministic multicore term sums, linear-time equality tables, and
removal of duplicate prover-side verification reduced the K128 boundary to 15.4004847 seconds
proving, 0.8374154 seconds independently verifying, and 185,368,576-byte peak RSS. This is still
too slow for a CPU-only 216-layer proof.

An isolated RTX 4060 round worker was therefore screened with the same frozen Fp16 tower:

- 4,097 independent Fp16 CPU/GPU multiplications matched, followed by a 262,144-element batch at
  0.290300 ms median;
- a two-active/two-dummy real-Chi KAT matched all 48 first-round coordinates;
- the full K128 128-pack KAT matched all 48 coordinates in both the first message and the second
  message after applying the public challenge to the equality factor and folded input; and
- the complete full-width layer matched all 48 coordinates in every one of 36 sequential messages
  plus both terminal values for both 782-permutation K128 and 894-permutation K512 fixtures.

With warm NVRTC cache, the complete message/copy/host-check boundary measured 0.7671116 seconds for
K128 and 0.7402966 seconds for K512. Median individual round kernels were 1.5289 ms and 1.5028 ms;
maximums were 2.8366 ms and 2.5353 ms. The worker used 133,278,080 device bytes. These are
single-layer algebra measurements, not complete-proof timings. The screen did not yet implement
native masks, the authenticated public-coin transport, PCS/FRI, the all-nine-layer 24-round chain,
proof serialization, timeout/device-loss handling, or release cleanup. It therefore receives no
qualification credit. Promotion requires an untrusted bounded worker whose every message is checked
by the Rust verifier and whose failures fall back before proof construction or fail closed.

The graph-free CPU control now has the missing adjacent-layer claim flow: two expanded group/wire
claims are combined without materializing the repeated graph, each nonlinear predecessor receives
a fresh packed bridge, and the final two input claims are exposed for the hiding commitment. The
focused repeated-layer boundary passes 3/3 tests, including a two-layer nonlinear chain, exact
input-opening equality, and tampered-claim rejection. This closes only the algebraic chain gap; it
does not package the CUDA worker, add hiding/PCS, or measure a 216-layer proof. The circuit builder
now emits the exact 24-round, 216-layer sequence and checks every adjacent width; the independent
all-round wiring parity test passes.

The bounded Rust worker host is now implemented with a fixed structure-of-arrays request, canonical
Fp16 coordinate checks, K512 geometry ceilings, sequential message-before-challenge enforcement,
at most 216 sessions per process, per-step timeout, and fail-closed child cleanup. The two focused
worker tests reject malformed output and kill a stalled child. The out-of-tree CUDA adapter matched
all 36 CPU round messages and both terminals at K128 and K512. K128's exact proof-coordinate
SHA3-512 digest is
`8fe8e12d8160fc21300d7f0503f886fa3f005dc80e82f50abce2b96283f2661fa4983da45b26e32c5152bc6cd6b461ce14de1f1d49ce72648f396c6e0491f8ac`;
K512's is
`f171b4941556ae094f33678a7bec574b760135ecfc9fbbf63e678b220212973353a4cf28bc88ab7ced9a8938ec22b349755de02491384c0a48858b7b5bddec9c`.

The first honest process boundary was 4.9230036 seconds for K128. Bulk request layout reduced it to
2.3792617 seconds without changing the digest. A SHA3-512-validated warm PTX cache then measured
2.3454522 seconds; its internal profile was 0.3786699 seconds request parsing, 0.7733006 CUDA
context/PTX load, 0.0647099 device setup/copies, and 0.6504006 interactive rounds. The remaining
roughly 0.478 seconds was host serialization, pipe, and process overhead. This rejects launching a
fresh Python/NVRTC process per layer. The next bounded change is one identity-pinned worker/context
for all 216 sessions with nine cached public wiring layouts; the CUDA adapter and NVRTC dependency
remain out-of-tree and unselected until their provenance, cleanup, full-chain parity, hiding/PCS,
and complete resource gates pass.

The persistent dependent-session host and adapter now work: one context serves up to 216
message-checked sessions, and every session allocation is freed before the next. Replacing the
per-round 600-plus-KiB partial copy/Python reduction with one device-side 48-coordinate reduction
preserved every proof digest and reduced the five-session worst-Chi boundary to 0.687204240 seconds
per session; steady internal interactive rounds were 0.0869203-0.1008700 seconds. The refreshed
three-session ordinal 0-8 boundaries were 0.578229033, 0.618900400, 0.544006266, 0.611497900,
0.511578666, 0.699488833, 0.819741000, 0.580185466, and 0.485333633 seconds. Their
5.448962697-second nine-layer sum gives a 130.775104728-second 24-round projection before
hiding/PCS. That is a measured-shape projection, not a complete chain proof, and it fails the K128
target. The remaining dominant waste is sending and rebuilding roughly 60 MB of Fp16 input and
equality weights per layer. At 782 real permutations the complete padded 216-layer Boolean witness
is only about 57.7 MB before fixed 1,024-lane padding, so the next experiment retains those
bit-packed boundaries on device and derives equality weights from authenticated claim points
instead of transporting dense Fp16 arrays.

The bounded compact implementation removed that dense transport without changing the verifier
relation. Exact graph-free CPU generation plus retention of all 216 packed boundaries measured
51.9751-66.7099 ms and 61,341,696 bytes at 782 active permutations; the fixed 1,024-lane shape
measured 69.5777-72.6403 ms and 75,497,472 bytes. The worker now accepts packed inputs, compact
equality factors, and one copy of the public base wiring, derives the repeated Fp16 terms on the
untrusted RTX 4060, and remains challenge-subordinate to the Rust host. Worst-Chi request parsing
fell from roughly 330-350 ms to 13.4-18.2 ms with the exact prior SHA3-512 proof digest.

A new single-process chain harness precomputed nine independent CPU references, then measured the
actual 216 interactive GPU sessions under one persistent context. K128/782 completed in
33.2458796 seconds and K512/894 in 30.6132468 seconds. All 216 round-message vectors and terminals
matched the CPU controls. Proof-stream SHA3-512 digests were
`4a2f2873fa5f651d07cf7e8b12b796510790995edd9f64025c3c5a10de9d42196f5d64d2882cb04836caa547096e2c916c1eeea602d45145bd35749be09a6065`
and
`2572dea0c0d591a1e8a609d0c32cbc4e054a9a1301c79707c260edd17beaf1947d9386285ebb83f8547e0c38ed37b4068454a76d7e00df2a6e301659fceb328b`.
Observed host peaks, including the retained CPU reference fixtures, were 466,448,384 and
465,846,272 bytes. This passes the isolated GKR-stage K128/K512 laptop gate. It does not qualify a
complete proof: production two-claim compact derivation, native masks, hiding PCS/FRI, the complete
simulator, packaged CUDA/NVRTC provenance, VRAM/scratch/cleanup evidence, proof bytes, and
independent complete verification remain required.

The production two-claim compact derivation subsequently matched the complete CPU sparse proof for
a full-width Chi layer. The repeated sparse verifier now checks nonzero masked messages and their
terminal correction against the public repeated wiring. Full 216-session masked runs measured
30.9336388 seconds at K128/782 and 31.0194826 seconds at K512/894, with exact transcript digests
`cd63ef80748613a0afba446d9eea9a1065e4bd8c87e03124cf4975c7059fd1669757198ad2c960dc1dd83868a3444de7e73982e47c54eec06790232a14c3c548`
and
`dfdb61b009b36a4c46b9e9bc5581425c7d2e3b2838ba10a7a91fdeb731791a5e3212b699e11960f9b6551015d124a852fe460d807b1276666a671fd9404ac4ca`.
The deterministic KAT masks establish algebra and timing only; secret mask generation, commitment,
and the adaptive simulator remain open.

Integration review then found that both preceding 216-session harnesses proved independent
per-layer fixtures rather than carrying terminal claims through one coherent circuit. They remain
useful GPU algebra controls but receive no coherent-chain credit. The replacement harness evaluates
all 216 boundaries once, carries exactly two terminal claims backward through every layer, verifies
each masked sparse reduction in Rust, checks one exact CPU/GPU packed polynomial, and binds the
final two openings to the raw `2^21` Boolean input table. K128/782 measured 42.8253168 seconds with
SHA3-512 proof-stream digest
`5e0cd3e0805022de6344739507b04c123d87bf45733a95b914477b50ecde10a5c27ecdd188d9f45a92b0532e4a31e122a191face37e50a79f92527600319dfb4`;
K512/894 measured 44.1804650 seconds with digest
`13e24281b6c918ca35c5c612c90bb79a8a2508c216608017ce06f621539815142864530497c80a0a1d8378f47f2cbad110e5b8cd537a47b1e493d97fae4aa53c`.
Both passed coherent-chain, nonzero-mask, CPU/GPU-polynomial, and GKR-to-PCS-opening checks. Observed
combined host peaks were 3,241,021,440 and 3,240,488,960 bytes. The joined benchmark now requires
an external 64-byte secret seed and 64-byte nonzero session identifier and derives domain-separated
GKR and PCS masks with the existing SHAKE256 sampler; a wrong-length input fails closed. Its
challenge schedule is still deterministic and therefore explicitly not authenticated public coin.
Both peaks exceeded the owner's former strict 3,000,000,000-byte limit. Under the current
5,000,000,000-byte ceiling, the 3.24 GB controls fit the numeric RAM bound while the 5.06 GB and
higher realizations do not. They retain correctness and
parity evidence but receive no resource-qualification credit.

The exact resulting committed input was then proved by the native multilinear PCS, encoded,
decoded, and independently verified. K128 production plus internal verification measured
20.7792086 seconds and independent verification 0.2230094 seconds; its 17,524,065-byte proof has
SHA3-512 digest
`78f9bb5f9807ec671256e88dab6b2e5251b74a537d16c5ae04952f9ce07af518d39927d9a2fc75b4b75f079b0c18ae90928812f8f1983dd8f92619fe8c2fd4e2`.
K512 measured 20.7974853 and 0.2428490 seconds with proof digest
`a9331e826ca1017287a5a8f5512f96b33bda2715131ec26a30c65e9756f20c193a17042edcae2c4aad440f4dd50b1fc3cae11f076a3ad61096f1c42df5d5474a`.
Core scratch was 2,818,577,696 bytes. These are actual coherent GKR-to-PCS component results, but the
initial Keccak states still come from a synthetic fixed-shape generator. They are not the certified
hidden-state transition, an atomic proof, authenticated interaction, simulator qualification, or
K128/K512 qualification.

The next binding audit found that this coherent run's initial output evaluation covered the entire
1,600-bit final Keccak state and was computed by the prover harness rather than authenticated by the
semantic digest bus. The result remains valid internal GKR algebra evidence but is not yet a hash-bus
proof. The replacement interface removes the synthetic input generator, requires a canonical
fixed-size external Keccak-state file, rejects nonzero inactive lanes and the 448 padding wires, and
sets output wire variables 9 and 10 to zero so the initial GKR claim covers exactly the first 512
SHA3-512 digest bits. Its two focused boundary tests pass. Fresh K128/K512 timings and exact
message/digest-bus commitment openings are required; the old digests receive no credit for those
new boundaries.

H3 now has an explicit dependency on the common multilinear PCS and S3 commitment prototypes from
Track G. The existing Circle PCS is not a multilinear bus-opening proof and receives no bridge
credit. Run the Jindo, Hachi/Grand-Danois, and transparent fallback field/security/hiding screens
before composing terminal GKR claims with the bus. This reorders only the commitment dependency;
it does not activate any sparse-state redesign.

The bounded screen rejects both released lattice implementations for H3. Hachi's construction and
prototype provide Module-SIS binding but no commitment-hiding or evaluation-hiding theorem; its
released parameters also hard-code a degree-four extension and a 120-bit lattice-estimator target.
Jindo does prove commitment hiding, evaluation hiding, and relaxed knowledge soundness, but its
paper and implementation instantiate only 128-bit MSIS/MLWE security, use a roughly 255-bit
challenge field, SHAKE128 Fiat--Shamir, and a fixed `delta ~= 1.005` MSIS heuristic. The included
440-bit field arithmetic enlarges the challenge set but does not re-establish MSIS or MLWE hardness.
Neither candidate has a derivable, measured 256-bit security/encryption parameter set, so neither
advances to
implementation.

The admitted transparent control is now a unique-decoding WHIR/BaseFold-style multilinear PCS.
List-decoding/DeepFold parameters remain excluded because their smaller query count depends on the
unproved Reed--Solomon list-decoding conjecture. At rate `1/8`, the unique-decoding miss probability
is `9/16`, requiring `ceil(392 / -log2(9/16)) = 473` queries. A pinned upstream WHIR control at
commit `92652ca01e215548c98e11834e110c43994b94c1`, `2^21` coefficients, 250-bit security,
unique decoding, one evaluation, and SHA3-256 measured 6.517491215 seconds prover,
0.027126784 seconds verifier, 1,051,504 proof bytes, and 1,415,452 KiB peak RSS on the reference
laptop under WSL. The run warned that its one-bit PoW allowance was insufficient. The exact
392-bit invocation failed closed because the upstream maximum field is only about 254 bits.
Linear scaling of the 250-bit control gives a deliberately conservative 10.22-second and
1.65-MB pre-port ceiling, not qualification. H3 may use this lane only after a minimal native
Fp16, SHA3-512, authenticated-interactive, no-grinding, native-hiding port independently verifies
and passes the complete simulator and laptop gates.

The common boundary retains the legacy exact 392-bit, rate-`1/8`, 473-query, zero-PoW record. It
exceeds the current 256-bit floor but is not by itself complete qualification. The boundary
evaluates packed Boolean input tables directly at arbitrary Fp16 points. It rejects parameter,
length, dimension, and noncanonical-padding drift. The current ten focused multilinear/FRI tests
pass. At the shared
`2^21` padded input size, five release runs measured a 0.6290573-second K128/782 median and a
0.6506879-second K512/894 median. The maximum observed process working set was 71,778,304 bytes,
scratch was zero, and each profile's SHA3-512 result digest was stable across all five runs.
This authenticates no opening by itself; it is the measured GKR-terminal interface only.

Owner-policy reconciliation (2026-07-28): **473 unique queries is authoritative**. The owner
explicitly directed the implementation to preserve the current stronger source/proof/verifier
boundary after a later execution-order copy was found to say 378. The hashed execution-order input
remains unedited as provenance; its 378 sentence is a superseded transcription error, not an
alternative protocol. The separate 945 figure is the authenticated opening multiplicity
`2 * 473 - 1`, not a second unique-query count. No code, proof, verifier, fixture, rate, or security
calculation may translate between 378 and 473.

Lean-streaming feasibility update (2026-07-28; **NONACTIVATING**): the full PCS source geometry is
log 28 at K128 and log 30 at K512, because the committed Boolean table includes 2,048 wires,
eight shards, and every padded group. The repeated GKR worker's log-26/log-28 table is a different
object and must not be reused as the PCS dimension. Two packed source boundaries are therefore
67,108,864 bytes and 268,435,456 bytes respectively. The exact replay engine itself needs only
4,032/4,288 bytes, but scalar output-by-output replay is rejected for throughput: its initial layer
alone performs `2^61`/`2^65` data-or-mask source-term visits, and output tiling does not change
those counts.

The admitted lean shape is a bounded theorem-backed product-sumcheck plus a proved-distance
linear-time code, not scalar replay. Codeword commitment makes one deterministic canonical-order
pass; after authenticated verifier queries are fixed, one identical replay pass captures only the
queried leaves and canonical SHA3-512 frontier. The current nonactivating KATs prove dense/replayed
root and frontier equality, independent opening verification, scalar-extension linearity under
general Fp16 challenges, and exact dense/streamed product-sumcheck message equality with one read
of each source table per round. These are mechanics tests only. The code family, generator, rate,
concrete distance, extractor, 392-bit ledger, native hiding, and authenticated-public-coin mapping
remain selection gates, so this update grants no PCS replacement, qualification, or activation
credit.

The superseded zkDeepFold control required `f_ext = f || r`, so its hidden committed polynomial
has `2^22` Fp16 coefficients and its rate-`1/8` LDE has `2^25` elements; the earlier `2^24`
non-ZK geometry is not the hiding geometry. The auxiliary random polynomial has 18 variables,
the minimum satisfying `2^18 > 473 * 21^2`. That inequality and the following measurements are
historical control evidence, not a simulator theorem for the Construction 8.2
random-padded interleaved-RS PCS selected on 2026-07-29. The common boundary derived and verified an exact
order-`2^25` Fp16 root from SHA3-512; it lies in the Fp2 subfield, reducing each NTT twiddle
multiplication to eight Fp2 products. The scalar NTT matches direct evaluation and the focused
multilinear/geometry suite passes 9/9.

The native continuation now implements the three-claim different-size batch-sumcheck prelude,
strict message ordering, hidden and auxiliary polynomial algebra, canonical verifier-derived query
multiproofs, fixed-length codecs, and an independent algebra verifier. The 18-variable auxiliary
polynomial is lifted through four ignored prefix variables with exact `2^-4` normalization, keeping
the intended `r^2 c_aux` term at the 22-variable batch boundary. Encoded sizes are exactly 4,747
bytes for the prelude, 17,519,307 bytes for fold/query authentication, and 17,524,065 bytes for the
combined internal PCS proof. The fully parallel completed-challenge full-shape control measured
4.1560122 seconds, 827,203,584 peak working-set bytes, zero scratch, and the same SHA3-512 output as
the scalar control. The focused multilinear suite passes 26/26, including above-threshold
scalar/threaded parity. This remains a control rather than a qualification result: production
entropy, authenticated public-coin receipts, committed-layer proof production, the complete
hiding/composition theorem, and fresh end-to-end K128/K512 proofs are not yet complete.

The complete production-geometry PCS control builds every main and auxiliary commitment/opening,
emits exactly 17,524,065 bytes, decodes them, and independently verifies them. The earlier
18.1039767-second single-opening control is superseded because packed GKR ends in two claims plus a
degree-7 shard query. The corrected boundary combines both values after an authenticated mix and
inserts all eight Lagrange shard weights at the exact wire/shard/group bit positions. It measured
23.8805969 seconds for production plus internal verification, 0.2366557 seconds for independent
decoded verification, 29.4130358 seconds total wall, 5,062,144,000 peak working-set bytes, and
2,281,701,376 bounded input scratch bytes. Proof SHA3-512 was
`25bb3d9c9b7b47a6ad0de599fdd7a2f53d696605085bd194ec09be455e6e9f1a6ea67594c9f92271a7ffd6e81a683fffd4c21104e0859c6b1ceac639d2556ef3`.
The focused PCS suite passes 27/27 and the exact bridge passes 1/1. This does not close 2E/2F: the
run used a completed deterministic challenge schedule and synthetic masks, so production entropy,
dual-PQ authenticated interaction, the complete simulator/composition ledger, and a coherent
atomic GKR integration remain mandatory.
The measured peak rejects this realization under the current RAM gate without invalidating its
algebra, codec, or independent-verification evidence.

An untrusted RTX 4060 NTT control matched all 1,024 CPU outputs at `2^10`. At the actual `2^25`
hidden geometry it independently matched the closed-form `x=1` and `x=-1` evaluations and produced
one stable sample checksum. Five fresh runs measured a 0.7593406-second median for bit reversal plus
NTT, a 0.0780000-second median initialization, and approximately 0.0015 seconds for the 128 MiB
Fp2 root-power table. Device allocation was 2,281,701,376 bytes. One complete 2 GiB device-to-host
copy measured 0.1700202 seconds. These are encoding controls, not a hiding simulator or proof.

The multiplicative FRI fold equation now has an independent scalar coefficient/evaluation test.
The GPU performs all 22 production folds in a five-run 0.0306100-second median after the NTT; every
run ended in eight identical rate-`1/8` values and matched a closed-form evaluation of the complete
synthetic hidden multilinear polynomial. With both forward and inverse Fp2 power tables, the device
working allocation is 2,415,919,104 bytes plus 1,408 challenge bytes. The repeated full-shape
five-run medians were 0.8006791 seconds NTT, 0.1985334 seconds for a 2 GiB device-to-host copy,
0.0823684 seconds initialization, and 0.0034373 seconds root-table construction. The earlier
single-table NTT measurement remains a valid lower control; this larger run is the fold-capable
boundary.

The full SHA3-512 Merkle control uses 16 Fp16 elements per 1,024-byte leaf, hence `2^21` leaves.
The existing serial builder took 24.2561595 seconds. A bounded 16-worker builder now produces the
byte-identical root; its five-run median is 3.0140306 seconds, measured peak working set is
2,589,167,616 bytes, and scratch is zero. One focused serial/1-worker/4-worker equality test passes.
Building all 22 pre-final fold-layer roots at the exact halving geometry has a five-run
6.9376924-second median with stable first and last roots. For 473 maximally separated query paths,
canonical leaf/frontier de-duplication prices the fixed-shape opening payload at 16,729,216 bytes:
12,672,000 opened-leaf bytes, 4,055,808 frontier bytes, and 1,408 root bytes. This excludes the
round polynomials, two binding evaluations, auxiliary-polynomial batch opening, and framing, so it
is a lower boundary rather than a finished proof-size claim. The measured hidden-commitment front
end remains compatible with the latency gate, but it is not complete PCS qualification.

The pinned upstream ZK wrapper was also run as a wrong-field control with its required
`rs_in_order` feature. The exact 392-bit, zero-PoW invocation failed closed at the upstream
approximately 254-bit field. At 250 bits, `2^21` coefficients, unique decoding, rate `1/8`, one
evaluation, SHA3-256, and requested zero PoW, the wrapper reported a 27.8-second prover
(`6.0 + 21.8` seconds), 8,262.9 KiB proof, 1.7-second verifier, and 1,647,972 KiB peak RSS.
It also warned that more PoW was required and printed internal 5.37-16.40-bit grinding slots,
so the run receives zero security or no-grinding credit. Relative to the matching non-ZK speed
control, this historical wrapper makes hiding roughly 4.27x slower and 8.05x larger; those ratios
are measured upstream costs, not projections for the native Fp16 design. The source labels that
wrapper not fully ported, so it is a rejection/control datum rather than code to vendor.

The exact 25-state bit-packed K128 history is 568,650,000 bytes. With generated maximum layer width
`w`, two Fp16 accumulators contribute `2 * (113,730 * w / 8) * 64` bytes. The `w=1,600` raw-state
baseline plus `B=8` precomputation and the exact bus payload is 3,591,988,768 bytes; `w=2,048` is
4,407,205,408 bytes. These are parameterized capacity calculations, not an upper bound or an
implemented peak-RSS claim. The compiler must report `w`, and the measured hard gates control. The
5 GB scratch gate is 110.852x below the 554 GB projection and 190.152x below the 951 GB plan.

The current Binius64 benchmark is a scale control only. Its field, 96-bit/SHA-256 Fiat--Shamir
profile, and non-ZK benchmark relation fail the frozen product requirements. Byte-lookup,
narrower-row, and Ligero/Ligetron-style candidates remain differential or fail-closed research
fallbacks; none restores the retired hundreds-of-gigabytes design.

The all-Fp16 accumulator layout is now the control for a **subfield-first streamed GKR** candidate.
Verifier challenges and final soundness remain in Fp16. Early, high-volume prover arrays remain in
M31 or the smallest theorem-justified tower level and are promoted only after folding has reduced
their length. Deterministic read/write streams or bounded slabs may back those arrays; access order
must be public and data independent.

At `w=1,600`, replacing only the two eligible 64-byte Fp16 accumulator arrays with four-byte M31
arrays changes that term from 2,911,488,000 to 181,968,000 bytes and the raw-state subtotal from
3,591,988,768 to 862,468,768 bytes. This is a candidate working-set calculation, not a peak-RSS or
scratch result. Cross terms, masks, promoted tails, generated padding, commitments, and allocator
overhead must be measured. The existing hard gates do not move.

For state, first remove any remaining duplicate node work and compare retain/recompute batch
frontiers. A different tree, accumulator, page layout, or delayed rollup state transition is a
statement change and requires a written equivalence invariant, new KATs, attack tests, migration and
rollback semantics, and full measured evidence. SHA3-512 roots may not be replaced with Poseidon or
truncated commitments.

The admitted memory-proof bake-off is deliberately narrower than a state redesign. Compare the
existing endpoint-multiproof/sorted-memory control against a three-plane construction: Shout-like
read-only checking for immutable governed policy/oracle tables, Twist-like read/write checking for
replay/payment memory, and the selected Boolean GKR SHA3 coprocessor. Each candidate must consume
the same CBAM and preserve the exact old/new SHA3-512 root bridge, full-width keys/values, sequential
equivalence, fixed padding, and atomic transcript. Twist/Shout does not itself authenticate those
roots. No candidate advances on asymptotics or paper benchmarks; it needs complete K128 time,
memory, scratch, proof-byte, verifier, privacy, and attack evidence against the current control.

#### Phase 1 optimization design delta (2026-07-27)

This delta freezes design work for owner review. Numbers are tagged `MEASURED`,
`PROJECTED-FROM-SOURCE`, `PROJECTED-DESIGN`, or `ASSUMED`.

1. **Boundary divergence.** `FROZEN-TARGET` / `PROJECTED-FROM-SOURCE`: the exact 25-state
   bit-packed K128 history model is `568,650,000` bytes, not an observed process peak.
   `PROJECTED-FROM-SOURCE`: the current control retains 217 boundaries. Nested `Vec<bool>` carries
   `77,577,846,784` Boolean-payload bytes before metadata; the production-shaped packed `Vec<u64>`
   path still carries `9,697,230,848` payload bytes if all 217 boundaries are retained. These are
   different storage models and must not be conflated.
2. **Bucketed sumcheck.** `PROJECTED-DESIGN`: compile sparse terms into public, deterministic
   buckets grouped by the suffix of the bound index. Evaluate each bucket once per round, merge as
   the fold halves the index space, and carry the accumulated bit-basis weight as the bucket weight.
   Preserve canonical in-bucket order and increasing-index merges. Fixed fixture seeds must produce
   bit-identical round coefficients and byte-identical proof bytes against the serial reducer; this
   changes no transcript, soundness, hiding, or shape. Live authenticated coins must verify but need
   not produce identical bytes. `MEASURED`: the Phase 0 B=8 profile assigns only 3.022% of module
   samples to field multiplication, so this schedule receives no performance credit before
   measurement.
3. **Two-layer collapse.** **DESIGN-FROZEN-OWNER-RATIFIED-2026-07-28**:
   merged theta has intrinsic relation degree at most 11 and merged chi+iota has intrinsic relation
   degree 3. The nonconstant output-claim equality factor makes their claim-bound round-polynomial
   degrees 12 and 4, requiring 13 and 5 coefficients respectively. The owner approved this exact
   13/5 correction on 2026-07-28; it supersedes the earlier 12/4 estimate, and the equality factor
   must not be omitted or host-trusted. This is a new multi-factor sumcheck, not a descriptor edit.
   Current `prove_sparse_terms` is structurally fan-in 2; merged theta is fan-in 11 and merged chi+iota is
   fan-in 3. It needs new raw/padded descriptors (proposed 1,600/2,048 state widths), proof
   equations, codecs, transcript order, and masks. Order each Keccak round as theta
   message/challenge receipt(s)/terminal claim followed by chi+iota message/challenge
   receipt(s)/terminal claim; preserve message-before-reveal, dual-PQ authentication, and domain
   separation. `PROJECTED-FROM-SOURCE`: the current 216-layer K128 schedule projects 11,809 rounds.
   `PROJECTED-DESIGN`: 2,624 rounds for 48 layers and 1,984 if wire rounds halve from
   `2 * log2(width)` to `log2(width)` are historical planning placeholders only. They receive zero
   acceptance or calibration credit; exact authenticated-round and coin-round counts must be
   derived from each built schedule. Use 13/5 mask coefficients; account for
   `12 / |Fp16|`, approximately `2^-492`, before adding the remaining error terms. The owner
   explicitly ratified this Phase 2.4 implementation before the current execution handoff; every
   KAT, equivalence, transcript, mask, count, fixture-digest, and calibration gate remains
   fail closed.
4. **Boundary storage.** `PROJECTED-DESIGN`: retain the packed input plus 25 active-state
   checkpoints and regenerate each round's eight intra-round boundaries during the reverse walk.
   The walk, allocations, recomputation count, and cleanup are fixed and content independent.
   `PROJECTED-FROM-SOURCE`: 568,650,000 bytes covers the active-state payload only, not input,
   padding, masks, descriptors, allocator overhead, or the temporary round.
5. **M31 fast-path inventory.** `PROJECTED-FROM-SOURCE`: `field.rs::mul_by_m31` performs 16 base
   multiplies with data-independent timing and is used only by the packed kernel. Inventory
   `gate_line` constants, `weighted_gate_quadratic` bit weights, and existing table/accumulator/final
   assembly sites; accept only a proved M31 operand or fixed small wire constant. `MEASURED`:
   multiplication is 3.022% of module samples. Explicitly exclude `fold_multilinear`, whose
   verifier coordinates are general Fp16, and retain general Fp16 after interpolation and for
   terminal combinations unless a subfield operand is proved. Near-zero savings are acceptable.
6. **Streamed M31-symbol commitment.** **NONACTIVATING; OWNER-SIGNOFF-REQUIRED**.
   `PROJECTED-DESIGN`: commit the 1,600-bit input as M31 symbols under an M31-linear code with Fp16
   challenges, stream block encoding into per-column SHA3-512 accumulators, and hide with
   16 independent uniform M31 mask rows. There is no implementation or selection credit until the
   four ECCC 2025/2054 checks pass:
   **Σ/F decoupling through §4; symbol-wise distance over Σ; extractor recovers an M31 codeword; no
   reliance on near-capacity machinery** and the owner records them as passed. It may not alter the
   current bus or proof grammar.
7. **B=64 redesign.** **DESIGN-FROZEN-PENDING-OWNER-SIGNOFF** for production; a standalone
   nonprotocol measurement spike is preauthorized. `MEASURED`: the B=8 baseline is **468.017
   cycles/gate** (13,209,305,088 module cycles / 28,224,000 gate-instances). `PROJECTED-DESIGN`:
   pack 64 instances per word using an 8x8 tensor/factored representation; never construct a flat
   `2^64` table. Split-equality-factored weights must make the inner accumulation operate on
   counted bits before any Fp16 value is touched. Report exact operation counts and table bytes.
   Set `OUTPUT_COEFFICIENTS = 3 * B = 192` and the matching bridge-mask count to 192 only after
   owner approval. These dimensions affect the transcript. Account for `192 / |Fp16|`,
   approximately `2^-488`. The spike must report parity, cycles/gate, peak RSS, table bytes, and
   operation counts; it grants no production authorization.
8. **Evidence labels.** All Phase 1 numbers retain the labels above. `ASSUMED` values, if later
   introduced, receive no qualification credit until replaced by measurements or source-derived
   arithmetic. The detailed normative design is in
   `docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md` section 8.1. Items 1, 2, 4, and 5 and the
   standalone B=64 measurement spike are preauthorized to proceed. Item 3 was owner-ratified on
   2026-07-28. Item 6 and the production B=64 kernel still require separate explicit owner signoff.

### Track E - theorem and protocol research

The following are isolated research candidates, not selected dependencies:

- masked, space-efficient Boolean GKR and sumcheck over Blind Ledger Fp16;
- subfield-first sumcheck with full Fp16 verifier challenges, measured promotion rounds, and
  sequential read/write streaming over the frozen M31 quadratic tower;
- transparent Ligero/Ligetron-style space-efficient proofs if the GKR simulator or bus bridge fails;
- a complete blowup/rate/fold/query sweep under the exact Circle/DEEP-FRI and native-hiding ledger;
- STIR-style rate reduction and WHIR-style query reduction;
- BaseFold or Brakedown-style field-agnostic commitment alternatives;
- VEIL-style non-intrusive zero knowledge for the multilinear/GKR plane, without replacing the
  current masks until the exact Blind Ledger simulator and public-coin conditions pass;
- Neo/SuperNeo lattice folding experiments only after the base K128 proof is resource-feasible;
  Hachi commitment experiments may run earlier only inside mandatory gate 2E. Both require a
  separate Module-SIS/Ajtai parameter and custody review; and
- recursive or containing-rollup aggregation after the base proof is resource-feasible.

Small-characteristic and tower-field sumcheck are pre-K128 arithmetic-schedule candidates because
they attack the selected GKR's bulk field work without lowering the challenge field. Scribe and
Hobbit contribute streaming algorithms and space-accounting controls only. Their concrete proof
systems, commitments, Fiat--Shamir profiles, security statements, and parameters are not adopted.

A candidate advances only after it supplies M31/Fp16 compatibility, SHA3-512 commitments, the
interactive authenticated public-coin schedule, native zero knowledge, at least 256-bit
cryptographic security/encryption for every PQ theorem term and the composed ledger,
terms, canonical proof grammar, a no-trusted-setup story, and complete K128 measurements. A paper's
Fiat-Shamir/BCS compilation, random-oracle statement, smaller field, or 100/128-bit benchmark is not
Blind Ledger evidence.

### Track F - implementation acceleration

After Tracks B-D remove algorithmic waste:

- add SIMD Fp16/tower arithmetic with scalar parity KATs;
- vectorize the subfield-first M31 kernels first on the reference Ryzen AVX2 path, retain scalar
  parity, and promote to Fp2/Fp4/Fp8/Fp16 only where the frozen transcript requires it;
- parallelize independent tables, FFT slabs, Merkle subtrees, and proof sessions with deterministic
  output;
- add GPU backends only behind a scalar verifier and exact CPU/GPU differential suite;
- pipeline government/oracle adapters, witness preparation, proving, and verification without
  sharing private mutable state between sessions.

Hardware does not rescue an algorithm that still needs 9 TB live memory or one terabyte of scratch.

### Track G - committed sparse-state and PQ commitment replacement

Execute `docs/BL_PQ512_COMMITTED_SPARSE_STATE_PLAN.md` as a separately attributable bake-off. The
existing SHA3-512 endpoint-multiproof/sorted-memory construction is C0. C1-C4 cover public-coin
persistent sparse memory, a generic transparent dictionary relation, touched-projection RAM, and a
compact shuffle-based memory-consistency relation. Each relation uses the same state fixtures,
CBAM, conflict order, fixed padding, semantic outputs, and complete benchmark boundary.

The commitment layer is modular and independently replaceable. Jindo-style evaluation-hiding
lattice PCS is the leading hiding experiment; Grand Danois/Hachi-style and RoKoko-style candidates
are separate controls; a transparent hash/code construction remains the safety fallback. None is
called strict-PQ until its exact assumptions, parameters, adaptive binding, knowledge soundness,
hiding simulator, public-coin composition, grammar, and implementation pass review. Pairings, KZG,
IPA, trusted setup, designated verification, and launch Fiat--Shamir remain rejected.

A changed state commitment receives a new schema/profile and a domain-separated SHA3-512 state
identifier. It must prove exact equivalence to the sealed state transition and ship migration,
rollback, reorganization, crash, and independent-verifier evidence. It may not silently reinterpret
an existing Merkle root. Wave 2 selects the measured winner; Wave 3 makes that exact selection
durable and operational.

## 6. Throughput maximization rule

"Maximum throughput" has a precise release meaning:

The non-negotiable reference-laptop latency gates are input-to-independently-verified-output p95
below 30 seconds for fixed-shape K128 with 100 live claims and below 180 seconds for fixed-shape
K512 with 500 live claims. Qualification uses one uncounted warm-up and ten unique measured
synthetic batches per profile. All masking, authenticated public coin, proof generation, parsing,
and independent verification remain inside the timed boundary; cached witnesses/proofs, swap, or
weaker parameters invalidate the result.

1. freeze security/privacy constraints, K128 workload, reference hardware classes, latency and
   resource envelopes, benchmark procedure, and variance limits before tuning;
2. implement every safe candidate that can plausibly change an identified dominant cost center;
3. measure steady-state approved claims per second, fixed-batch latency, proof bytes, verifier time,
   peak RSS, scratch high-water mark, I/O, and failure cleanup;
4. discard any candidate that fails a hard constraint or is dominated on every relevant metric;
5. select the highest-throughput feasible point on the remaining measured frontier, with all rejected
   candidates and reasons retained in the audit record.

The project may not stop at the first implementation that merely fits. A faster result is rejected if
it weakens security, privacy, auditability, modularity, deterministic recovery, or adapter isolation.

## 7. Active Wave 2 gates

| Gate | Required closure evidence |
| --- | --- |
| 2A. Cost truth and envelope freeze | The independently scoped 79/79 SHA3 inventory, noncanonical-form attacks, and five-addition dynamic reconciliation are complete; the exact 28,643,096-byte v1 proof attribution is encoder-native and verified on monolithic and bounded-streaming regression proofs. The current K128 direct-SHA3 report is exact **derived-model** evidence (not telemetry), and C0 now has a fixed census plus a nonactivating per-job binding. Finish generated-backend resource measurement, proof-native CBAM authentication, and an externally captured provenance bundle; a self-hashed synthetic benchmark fixture never qualifies. Freeze the K128/100-live p95 <30 s and K512/500-live p95 <180 s input-to-verified gates, reference hardware, repetitions, variance, and resources. |
| 2B. Grammar and storage de-duplication | The authoritative `BLPQPRF2` encoder/decoder, global-FRI verifier, canonical cross-domain sibling/value maps, monolithic worker, and bounded-streaming worker are integrated. Decoded wire bytes are independently verified; all 945 authenticated query multiplicities and opening values remain; no prover-supplied global coordinates are accepted. The latest real run reduced 28,643,096 v1 bytes to 6,755,933 v2 bytes. Main, interaction, and composition disk oracles build SHA3-512 leaves directly from canonical column slabs without full-domain row transposes. Required disk openings are globally deduplicated and batched. The exact public-geometry planner retains at most 256 MiB of levels per oracle or constructs a logarithmic-stack/exact-query frontier without level files and rechecks the root; forced parity is byte-exact. Complete remaining FFT/batching fusion, remaining v1/v2 negative tests, measured scratch/latency parity, and the endpoint-multiproof control versus three-plane Shout-like/Twist-like memory-checking bake-off with an unchanged SHA3-512 root bridge. |
| 2C. Shared-bus hash coprocessor | H0-H3 bus/circuit freeze, exact byte-bit bridge, all-Fp16 control plus subfield-first streamed Boolean GKR bake-off, full Fp16 challenges, native masking, complete simulator, atomic authenticated-public-coin verification, independent verifier, and `<=5,000,000,000`-byte peak RSS / `<5,000,000,000`-byte scratch / no-swap preflight |
| 2D. Heterogeneous prover convergence | H4 integration removes SHA3 internals only from the release PCS; semantic AIR plus bus plus coprocessor prove the unchanged relation; scalar/subfield/SIMD/GPU parity; exact parameter/error ledger; fixed grammar and resource preflight pass |
| 2E. Committed sparse-state/PQ commitment selection | C0 control and C1-C4 candidates share one interface and identical fixtures; admitted PQ commitment backends have exact assumption/parameter/hiding ledgers and independent verifiers; atomic SHA3-512 state binding and migration attacks pass; complete reference-laptop evidence selects the fastest fully compliant candidate or records why C0 remains selected |
| 2F. Full K128/K512 strict-PQ latency proof | Complete fixed-shape K128 and K512 proofs generated and independently verified using the selected 2E state path; simulator and leakage gates pass; ten-run p95 <30 s for K128/100-live and <180 s for K512/500-live; exact bytes/times/resources recorded; no activation or PHI |

Wave 2 is complete only when all six gates pass. The 124-proof release campaign remains after the
authoritative verifier/state wave because it must test the exact final verifier, state, and sidecar.

## 8. Explicitly rejected shortcuts

- lowering 945 queries, blowup, field degree, hash width, or hiding entropy without a complete better
  theorem and full error ledger;
- counting grinding or unreviewed Fiat-Shamir/QROM arguments toward launch security;
- switching authoritative SHA3-512 roots to Poseidon, Blake, a truncated digest, or an unaudited
  arithmetization-oriented hash;
- removing denial/cover work, dummy state operations, canonical padding, or fixed proof lengths;
- trusting host deduplication, host-computed state roots, or prover-supplied multiproof indices without
  verifier reconstruction;
- treating the 28.6 MB kernel as a K128 proof or the 950.76 GB scratch model as proof bytes/RAM;
- declaring throughput from scalar field microbenchmarks, trace generation, proof compression, or a
  toy AIR;
- using an external proving service, outside engineer, live endpoint, or live credential to complete
  an internal roadmap package.

## 9. Primary research references

- [FRI, ICALP 2018](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ICALP.2018.14)
- [DEEP-FRI](https://arxiv.org/abs/1903.12243)
- [Circle STARKs, IACR 2024/278](https://eprint.iacr.org/2024/278.pdf)
- [A note on adding zero knowledge to STARKs, IACR 2024/1037](https://eprint.iacr.org/2024/1037.pdf)
- [Stwo official implementation](https://github.com/starkware-libs/stwo)
- [Twist and Shout, IACR 2025/105](https://eprint.iacr.org/2025/105)
- [VEIL, IACR 2026/683](https://eprint.iacr.org/2026/683)
- [Neo and SuperNeo, IACR 2026/242](https://eprint.iacr.org/2026/242)
- [Hachi, IACR 2026/156](https://eprint.iacr.org/2026/156)
- [Persistent/volatile memory AIPs, IACR 2024/979](https://eprint.iacr.org/2024/979.pdf)
- [Two Shuffles Make a RAM, USENIX Security 2024](https://www.usenix.org/system/files/usenixsecurity24-yang-yibin.pdf)
- [Projection-code and black-box ZK RAM](https://escholarship.org/content/qt9405r7n6/qt9405r7n6.pdf)
- [Batching-efficient RAM, IACR 2024/840](https://eprint.iacr.org/2024/840.pdf)
- [IRONDICT, USENIX Security 2026](https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_hafezi.pdf)
- [Jindo, IACR 2026/044](https://eprint.iacr.org/2026/044)
- [RoKoko, IACR 2026/575](https://eprint.iacr.org/2026/575)
- [Grand Danois, IACR 2026/1196](https://eprint.iacr.org/2026/1196)
- [Quantum oblivious LWE sampling, IACR 2024/030](https://eprint.iacr.org/2024/030)
- [Short accumulator/vector-commitment update lower bound, IACR 2025/1558](https://eprint.iacr.org/2025/1558)
- [Ethereum SSZ Merkle multiproof specification](https://ethereum.github.io/consensus-specs/ssz/merkle-proofs/)
- [STIR, IACR 2024/390](https://eprint.iacr.org/2024/390.pdf)
- [WHIR, IACR 2024/1586](https://eprint.iacr.org/2024/1586.pdf) and its
  [authors' explicitly non-production prototype](https://github.com/WizardOfMenlo/whir)
- [BaseFold, IACR 2023/1705](https://eprint.iacr.org/2023/1705.pdf)
- [Brakedown, IACR 2021/1043](https://eprint.iacr.org/2021/1043.pdf)
- [Plonky3's M31-capable Keccak AIR reference](https://github.com/Plonky3/Plonky3/tree/main/keccak-air)
- [NIST FIPS 202: SHA-3](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
- [Almost optimal succinct arguments for Boolean circuit on RAM, IACR 2024/839](https://eprint.iacr.org/2024/839)
- [GKR for Boolean Circuits with Sub-linear RAM Operations, IACR 2025/717](https://eprint.iacr.org/2025/717)
- [The Sum-Check Protocol over Fields of Small Characteristic, IACR 2024/1046](https://eprint.iacr.org/2024/1046)
- [Efficient SNARKs for Boolean Circuits via Sumcheck over Tower Fields, IACR 2025/594](https://eprint.iacr.org/2025/594)
- [Scribe: Low-memory SNARKs via Read-Write Streaming, USENIX Security 2026](https://www.usenix.org/conference/usenixsecurity26/presentation/baweja)
- [Hobbit: Space-Efficient zkSNARK with Optimal Prover Time, USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/pappas)
- [Sparrow, IACR 2024/1631](https://eprint.iacr.org/2024/1631)
- [Libra, IACR 2019/317](https://eprint.iacr.org/2019/317)
- [Ligetron, IEEE S&P 2024](https://doi.org/10.1109/SP54263.2024.00086)

These sources motivate candidates and review questions. None substitutes for Blind Ledger's exact
theorem, implementation, KATs, measurements, internal qualification, or final independent audit.

## 2026-07-29 bounded recovery point

The selected recovery path now uses the real 168-layer masked GKR producer and a 73-word compact
PCS auxiliary plane. Exact decimal allocations are 12.058624 MB compact row state, 2.097152 MB
GKR-mask coefficients, 33.554432 MB GKR-mask codewords, 15.258752 MB complete auxiliary
coefficients, and 38.273024 MB complete auxiliary codewords. The production target verifier peaks
at 77.070 MB host RSS. A failed monitored CUDA launch reached 317.542400 MB process-tree RSS and
855.638016 MB GPU use; this confirms that the current blocker is driver integrity, not the old
multi-GB host architecture, but it does not establish a complete-proof peak.

The exact host/static gates pass: 6,086-round real-GKR/PCS transcript replay, authenticated GKR
terminal-scale digest plus fail-closed digest mutation, v4 answer target and mutations, 20-tree
segment-32 multiproofs and mutations, strict Clippy, 252/252 optimized Rust tests, and 3.299008 MB
static PTX. The failed CUDA stage was redesigned from first principles to evaluate one live message
tile per boundary and broadcast only that public evaluation, removing 510 duplicate evaluations.
Do not launch it until a clean NVIDIA driver reset is confirmed. After reset, the recovery action is
one externally monitored complete segment-32 proof, followed by dominant-stage profiling only if
input-to-independent-verification is not below 30 seconds.

## 2026-07-30 initial recovery completion measurement

The selected segment-32 prototype completed a fresh proof through independent verification in
28.943126 seconds externally and 28.177317 seconds inside the proof process. Every production
attempt after the last recorded Event 153 had zero later `nvlddmkm` Event 153 and zero Display
events. A later raw-log audit found that the formerly cited `23:17:48` event was an AMD power-policy
event, not an NVIDIA reset; the scoped reset and refined measurement below supersede that reset
claim.

This initial monitored run used 311.537664 MB external process-tree RSS, 305.770 MB internally sampled
proof-phase host RSS, 1,058.013184 MB sampled total GPU memory, 956.738816 MB tracked device
allocations, 0.000000 MB scratch, and no pagefile growth. The compact claim component/source/relation
plane is 7.864320 MB; the additional GKR-mask source/relation row plane is 4.194304 MB, so the
simultaneously live joined row state is 12.058624 MB. Reporting one figure without this split is
ambiguous.

All independent sumcheck, target, answer-code, spot-check, Merkle-root, mutation, soundness,
theorem-binding, masking, public-coin, GKR, coordinator, and verifier flags were true. The final
static PTX is 3.298706 MB with SHA-256
`6B1F682A647754FEC44AC85E9136962E0591A45865BB2A928EBF180254BAFEA7`.
Strict Clippy passed with zero warnings, the optimized Rust suite passed 252/252 library tests plus
all binary/doc-test groups, all seven current host KATs passed, and the 20-tree segment-32 verifier
rejected every tested leaf, frontier, and root mutation.

The recovery/prototype boundary is therefore complete. `proofSuiteId=null`, activation,
`complete_pcs_qualification`, and `complete_proof_qualification` remain false. The retained v4
component-only authenticated-sumcheck harness is not a v6 gate because it has no committed GKR-mask
root/opening or mask-row relation; the v6 same-chain KAT supersedes it. H4 atomic semantic-AIR/bus
composition and the later warm-up-plus-ten qualification campaign remain separate work.

## 2026-07-30 theorem-neutral throughput and lifetime refinement

The hot path now transports only the three source-quadratic coefficients per sumcheck round from
the untrusted GPU process. Rust reconstructs the exact 2,048-coefficient masked message from its
authenticated mask coefficients and epsilon, then applies the unchanged degree-tail, chain,
canonical-encoding, public-coin, mask-evaluation, terminal, and independent-verification checks.
The legacy complete-message transport remains accepted for compatibility. An exact Rust parity test
proves both transports construct the same masked polynomial.

CUDA reduces the existing five boundary rows to the exact 80 component evaluations before the
device-to-host copy. GKR weights remain a canonical packed 32-bit word array instead of 32,768
Python tuple objects. Four dead answer/source buffers are released at their last use, removing
39.168256 MB from the tracked device peak. None of these changes removes a theorem object, query,
mask, mutation, verifier, or authenticated round.

After the scoped NVIDIA reset and one successful cold driver-JIT warm-up, the fresh externally
monitored proof at `cache/wave2-throughput-proof-20260730-090753.stdout.txt` passed independent
verification in 24.749154 seconds externally and 24.392408 seconds in-process. PCS mechanics were
17.741531 seconds, the authenticated coin head was 12.790189 seconds, compact row sumcheck was
0.468827 seconds, and openings were 2.846039 seconds.

Measured decimal resources were 263.983104 MB external process-tree RSS, 1,011.875840 MB sampled
total GPU use, 917.570560 MB tracked proof allocations, 0.000000 MB scratch, and no pagefile growth.
Post-launch driver-event count was zero. The current PTX is 3.387039 MB with SHA-256
`DA61A996AD551E98EDF835DCE52D22B08963ABFC5C8FD7E28F6D051EDF85111D`.

## 2026-07-30 H4 compact-source recovery point

The H4 source boundary no longer serializes padded circuit wires. `BLHBSN01` binds the exact
semantic messages, capacities, digests, program, descriptor, and semantic-port commitment;
`BLHBB101` emits each shard input-boundary then output-boundary in wire-major order. Only the 1,600
live wires are present. Exact sizes are 52.428800 MB per shard, 52.429015 MB for K128 including the
header, and 209.715415 MB for four-shard K512. The old 67.108864 MB padded pair is retired.

The corrected exact B16 group control eliminates the 3,304.930 MB full-source materialization. It
emits round zero directly from packed patterns and first materializes only the 4,096-group fold.
The independent differential KAT passes; measured device state is 1,698.495 MB and host peak is
229.822 MB. The seven-layer group phase measured 0.605268 seconds per Keccak round, while the
degree-45 bridge measured 0.496789 seconds. The 26.449361-second 24-round component sum excludes
wire-tail, masks, PCS, coordinator, semantic lane, and verification, so it is a profiling boundary,
not complete-proof evidence. Optimize only measured dominant work and preserve every theorem gate.

K512 source construction no longer allocates the retired full physical SHA3 AIR merely to emit the
selected semantic bus. The failed fixture attempt was killed at 9,218.748416 MB RSS. The corrected
build passed in 441.10 seconds at 3,873.902592 MB peak and produced the 41.508092 MB authenticated
snapshot. Rust converted it to the exact 209.715415 MB four-shard boundary and independently
verified all four Keccak traces in 4.023582 seconds.

The host masked reducer now exposes one bounded untrusted group-oracle interface. Every raw cubic
must satisfy the current claim before Rust authenticates it and releases the next challenge; after
thirteen group rounds, only the two group-folded wire tables cross back into the unchanged Rust
wire-tail/native-mask/terminal path. Full-table and oracle proofs are byte-identical in the exact
CPU KAT, and endpoint mutation fails closed. This is the production integration seam; the actual
CUDA process and complete proof remain unmeasured.

## 2026-07-30 H4 measured real-semantic complete-proof boundary

The actual CUDA worker and joined K128 proof are now measured. The real nonuniform producer covers
168 layers, 6,073 GKR rounds, four relay-free input claims, and 508 native mask constraints. The
one-plus-four PCS grammar, native GKR masking, exact packed semantic source, 6,086-round atomic
coordinator, answer-code verifier, and Merkle spot-check verifier completed together. The accepted
run exited zero with empty stderr in 120.670536 seconds in-process and 121.3716075 seconds under
the external monitor. All printed verification and mutation gates were true.

Decimal resources were 969.999360 MB tracked GPU allocation, 536.928256 MB monitored process-tree
RSS, 306.905 MB proof-phase host peak, 76.706 MB native-verifier peak, and 0.000000 MB scratch.
Pagefile usage did not increase and the run produced zero post-launch driver-integrity events.
This confirms the lean packed architecture stays in hundreds of MB on host and below 1,000 MB of
tracked device allocation; the earlier multi-GB source plans remain retired.

The dominant measured stage is not PCS encoding or verification. The semantic GKR prelude took
110.290992 seconds and its authenticated head took 100.240849 seconds. Initial commitments took
1.970797 seconds, direct two-boundary component projection 0.186602 seconds, compact row sumcheck
0.352382 seconds, coefficient folding 0.013684 seconds, independent answer-code verification
0.781273 seconds wall, and openings/spot-check verification 2.299571 seconds wall. The accepted
run's `pcs_mechanics_seconds=114.498084` label incorrectly included the 110.290992-second GKR
prelude; that reporting error is corrected in source and the old label receives no PCS-only
performance credit.

The next optimization target is therefore repeated worker context reconstruction/PTX compilation
around the reset-safe layer batches. Cache immutable compiled code and reconstruct only context-
owned buffers; do not remove authenticated rounds, masks, statement binding, resets required for
driver integrity, or independent checks. A fresh monitored K128 proof must pass below 30 seconds
before the four-shard K512 latency result can qualify.

## 2026-07-30 H4 real-wire profile and rejected-bloat ledger

The raw wire tail is now computed by the untrusted CUDA worker, while Rust independently retains
folded sources and verifies terminal evaluations, native masks, recurrences, transcript order, and
the complete proof. The fresh exact semantic proof independently verified in 53.547306 seconds.
Its 42.017007-second GKR prelude dominates the 4.692209-second PCS mechanics. Host peaks remain in
the low hundreds of decimal MB, tracked device allocation is 969.999360 MB, and scratch is
0.000000 MB.

The following exact candidates were measured and rejected: larger adaptive bridge tiles,
`__umulhi` M31 reduction, forced NVRTC vectorization, a 128-register ceiling, delayed B16
materialization, low/carry product histograms, group prefetch, warp reduction, multi-claim kernels,
and a direct bridge accumulator. None may be reintroduced without a containing measurement that
beats the accepted source while preserving its differential KATs.

The K512 prototype must reuse one bounded shard image sequentially and accept only after all four
canonical shard statements and complete proofs verify. This avoids four approximately
one-gigabyte GPU images and does not share adaptive challenges across nonlinear shard proofs
without an explicit batching theorem. One outer atomic receipt binds the complete four-shard file
digest, ordered shard ordinals, proof bundles, parameters, verifier identity, retry identity, and
ordered application statement.

zkDeepFold is closed as a documentation ambiguity. It is not active. The selected PCS is
Construction 8.2 from ePrint 2026/391. The older `2^18 > 473 * 21^2` calculation applies only to
the retired `mu=21`, `s=473` zkDeepFold control and correctly satisfies that construction's
simulator interpolation condition. It gives no composition credit for the selected PCS and no
query-reduction credit: using fewer list-decoding queries invokes the separate Reed--Solomon
list-decoding conjecture.

The measured K512 atomic coordinator verifies four complete shards sequentially and emits one
outer receipt. Exact shard proof times were 56.240250, 52.837966, 53.901788, and 58.130489 seconds;
total coordinator time was 222.600073 seconds. External peaks were 591.249408 MB process-tree RSS,
2,182.086656 MB sampled total GPU use, and 0.000000 MB scratch, with no pagefile growth or driver
event. This rejects parallel-image memory as the problem and identifies repeated K128 GKR work as
the latency cause. Preserve the atomic binding and redesign the shared GKR head; do not weaken
shard independence or PCS verification.

## Historical manifest-bound containing measurements

The one/four-shard coordinator now binds execution identity rather than trusting paths. Manifest
SHA3-512 covers the Python entrypoint, prototype, semantic worker and local dependency closure,
seven native verifier executables, and precompiled PTX; coordinator and monitor both reject a
mismatch. Fresh K128/K512 in-process times are 54.955357/220.583627 seconds and external times are
59.060426/226.627989 seconds. K512 shard times are 55.221861, 54.467592, 53.685071, and
55.734525 seconds. Decimal external process-tree peaks are 532.242432/547.127296 MB for K128/K512;
K512 sampled total GPU is 2,182.086656 MB. Both have zero pagefile growth, empty stderr, and zero
post-launch driver events.

The common per-shard semantic GKR head remains the latency problem. PCS-only work cannot close the
K128 deficit. The accepted worker lifetime stays 48 layers: a 56-layer experiment failed at layer
54 with CUDA error 700 and caused Event 153 record 229592; it is reverted and forbidden.

Only complete formats remain accepted. Ten retired encodings reject, both complete Merkle
geometries pass all mutation checks, the optimized suite passes 264/264 with zero ignored tests,
and strict Clippy is warning-free.

## 2026-07-31 H4 throughput recovery closure

The final implementation removes measured setup, transport, and residency work without removing a
theorem object or verifier:

- Rust encodes each canonical layer plan once; Python reads and validates the exact packed batch.
- The CUDA worker uploads the immutable 24-round/seven-layer topology once as 3.225600 MB of device
  geometry and switches plan pointers thereafter.
- Canonical same-source aliases are derived from authenticated topology, so the duplicate source
  transport is absent.
- The coordinator hashes the semantic file and captures the selected shard in one pass.
- Exactly one 48-layer standby worker overlaps fresh-context startup. More standby workers are
  residency/launch bloat; no standby reintroduces measured latency.
- Worker and proof Python processes start with `-S`, narrowing imports to the standard library and
  manifest-bound local modules.

The accepted K128 proof completed in 29.974129 seconds. Its external wrapper measured
681.607168 MB peak process-tree RSS, zero pagefile growth, zero driver events, and empty stderr.
The accepted K512 proof completed four independent ordered shards in 120.460733 seconds; its
external wrapper measured 706.523136 MB peak process-tree RSS, 2,770.337792 MB sampled total GPU,
zero pagefile growth, zero driver events, and empty stderr. Both reported 969.999360 MB tracked
per-proof device state and 0.000000 MB scratch.

Two immediately preceding attempts demonstrate that the gates remained fail closed. A K128 proof
at 30.150084 seconds failed the 30-second gate and also observed 2.097152 MB pagefile growth. A
cryptographically valid 121.195125-second K512 proof observed 1.048576 MB pagefile growth and was
rejected. Neither receives acceptance credit.

Containing H4 verification was 266/266 optimized library tests. After the 2026-07-31 cleanup removed
the isolated BaseFold module and its two self-tests, current containing verification is 264/264,
every remaining binary and
doc-test group, strict all-target Clippy with zero warnings, all seven host cryptographic KATs,
20-tree segment-32 verification with every tested mutation rejected, 10/10 retired-format
rejections, and static CUDA compilation of 36 entry points. The PTX is 3.494439 MB with SHA-256
`B1F826445F2630517E250CE4BBB5E694ADC61620BEED5684C6EE09197EBBEF73`.

H4's functional and single-run latency prototype boundary is closed. Gate 2E must next select and
bind the authenticated state plane; H5 and H6 remain open after it. Qualification and activation
remain false and `proofSuiteId` remains null.
