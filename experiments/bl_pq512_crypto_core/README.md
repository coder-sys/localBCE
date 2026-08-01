# BL-PQ512 crypto core

Current architecture checkpoint: the newest dated section of `../../STATE.md` and section 8.3 of
`../../docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md` supersedes the older merged-layer, B=64,
and BaseFold planning notes. The selected
nonactivating candidate is the exact seven-layer/B=16 Fp16 schedule with a concurrent bounded M31
semantic-AIR lane and the Construction 8.2 random-padded interleaved Reed--Solomon PCS. The real
masked producer and exact 6,086-round same-chain coordinator pass as one atomic semantic proof. The compact
claim-row plane is 7.864320 MB; the simultaneously live GKR-mask row plane is 4.194304 MB, for
12.058624 MB total joined row state. GKR-mask codewords use 33.554432 MB and complete auxiliary
codewords use 38.273024 MB. Under execution manifest
`51c23310274ccf7c4d7f9abe4ae7eba43266b335bd377b21cbf92409729b91e2a40a39787a157baa080c9d0516c7815af404a4d58d9e76747f652f57cd017ed6`,
fresh K128 and four-shard K512 prototypes independently verified in 29.974129 and 120.460733
seconds. Both accepted attempts used 0.000000 MB scratch, had zero pagefile growth, empty stderr,
and zero post-reset driver events. This is complete H4 prototype evidence, not state-plane
selection or the H5 ten-run qualification campaign.

The host coordinator KAT independently replays the honest dual-PQ bundle and rejects a forged
GKR-terminal digest before releasing the PCS base-mask challenge.

Current continuation checkpoint: read the newest dated section of `../../STATE.md` after
`../../WAVE2_HANDOFF_2026-07-26.md`. The corrected source evaluates one live commitment tile per
boundary and broadcasts only the public message evaluation, removing 510 theorem-redundant
evaluations without copying hiding coefficients. The real masked producer, same-chain coordinator,
PCS, and independent verifier now complete together below 30 seconds for K128 and below 180 seconds
for K512. Gate 2E state selection must precede H5; qualification and activation remain closed.

The current H4 implementation boundary is
`src/fp16_zk_rs_gkr_binding.rs`, `src/bin/fp16_zk_rs_theorem8_1_transcript.rs`,
`cuda/cuda_fp16_zk_rs_theorem8_1_k128_prototype.py`, and the exact B=16 GKR producer. Rust now
binds one output and four relay-free input claims, each with 24 coordinates and sixteen committed
component evaluations. Two authenticated challenges batch the five claims and sixteen coordinates.
The exact row relation folds 144 source/relation states across the 512 interleaved words in nine
quadratic rounds: 80 claim-component states plus 64 committed GKR-mask states. Its complete compact
GPU state is 12.058624 MB. Component extraction uses one live tile per public boundary because the
selected fixed zero-trace message is identical across that boundary's 256 interleavings; only the
hiding tail differs. Python no longer
supplies an authoritative linear form or target. CUDA performs untrusted field/RS arithmetic. Rust
remains authoritative for SHA3-512 roots, canonical values, row parameters, multiproofs,
answer-code arithmetic and target, transcript ordering, dual-PQ public-coin replay, and final
verification. The real GKR mask is committed as 64 dimension-512 auxiliary codewords, and the
answer plane contains 73 words: nine sumcheck masks plus those 64 GKR mask words. The complete
H4 prototype gate has passed. At the product level gate 2E must select and atomically bind the state
plane before this crate's remaining H5 repeated p95 campaign and H6 suite qualification.

Current Wave 2 role: this crate is the semantic-STARK/Fp16/SHA3-512 substrate for the heterogeneous
proof in `../../docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`. Its direct SHA3 AIR and disk-backed
wide prover remain differential/negative-baseline machinery. The active prototype uses the shared
bus, Boolean GKR coprocessor, native masks, and atomic verifier without reviving the retired
554-951 GB layouts; repeated qualification and final simulator/suite closure remain open.

This isolated crate implements the frozen scalar substrate from
`BL_PQ512_S09_INTERNAL_SOLUTION.md`:

- `p = 2^31 - 1` with canonical values only;
- `i^2 = -1`, `u^2 = 2+i`, `v^2 = u`, and `w^2 = v`;
- the flat basis `1,i,u,iu,v,iv,uv,iuv,w,iw,uw,iuw,vw,ivw,uvw,iuvw`;
- exact 64-byte, coefficient-wise big-endian encoding;
- SHA3-512 field and authenticated Fp8-excluding OODS rejection sampling with
  no modulo repair;
- full-width typed PCS Merkle and projection-consistent cross-domain trees;
- scalar Circle-to-line/line folds, conjugate-pair degree correction, gap-complete variable-width
  masked multi-domain FRI batching, typed FRI-mask commitments, and a cross-language K512/beta-1
  schedule KAT;
- independently derived degree-16 minimal polynomials, base-Circle translation, and the exact
  cross-language K512 direct trace-evaluation certificate commitment;
- the canonical two-component quotient-mask identity and exact repeated-doubling Circle split
  factor; and
- an independent byte-oriented SHA3-512 sponge/permutation, complete streamed round witnesses, and
  exact low-degree AIR-shape/trace commitments;
- Python-parity ordered-map fixed schedules plus streamed validation of every live and dummy hash
  call, including family order, padding messages, digests, and round counts; and
- streamed payment-operation and chained operation-log SHA3 with exact Python-parity K128 counts,
  final root, and schedule commitment; and
- fixed-capacity benefit/obligation/reserve/payable key hashing with exact K128 cross-language
  schedule commitment; and
- strict validation plus streamed SHA3 witnesses for the reversible compact K128 claim-source
  bundle/tree, with exact Python-parity root and schedule commitment; and
- strict validation plus streamed SHA3 witnesses for the packed K128 oracle bundles and ordered
  execution root, with exact Python-parity root and schedule commitment; and
- an independently typed, nonactivating Rust mirror of the K128/K256/K512
  Wave 1A physical-relation dimension ledger; and
- exact Python-parity cover-nullifier v2, hidden salt-use, authoritative master-commitment v2, and
  six-segment K128/K256/K512 global SHA3 call schedules. K128 fixes 46,858 calls without allocating
  a second owned copy of every Keccak row; and
- a selected staged AIR/LogUp/composition/OODS/DEEP/multi-domain-FRI prover, bounded proof grammar,
  independent verifier, real dual-PQ public-coin adapter, verifier-derived resource preflight,
  program-bound streamed witness/public-input manifests, owned scratch storage, bounded row
  transposition, and a byte-exact disk-backed cross-domain tree.

The cryptographic library remains `no_std` and uses `alloc` only for owned reference data; the
explicit `std` feature adds owned scratch and disk-backed prover infrastructure, while `parallel`
implies `std` and enables dependency-free scoped-thread acceleration. The payment-log, payment-key,
claim-source, and oracle stream binaries are strict local cross-language qualification harnesses;
they are not network services or production prover interfaces.

The PCS framing is `BLPQPCS1 || version:u16be || domain:u16be || body`.
Leaf bodies are `length:u64be || payload`, nodes are `left:64 || right:64`,
and roots are `leaf_count:u64be || top:64`. Empty hashing has an empty body.
Only nonempty power-of-two trees are accepted; the empty-domain primitive is
available for a future exact PCS layout but is not silently inserted.

`Fp16::frobenius` is deliberately a fixed-field-work reference: it performs
512 square-and-multiply-always steps and selects coefficients without branches.
Exponent construction depends only on the public power. This is auditable and
constant in field-operation count, but it is not an optimized Frobenius map and
does not claim constant-time machine code. The scalar tower is branch-minimized;
no SIMD, assembly, or `unsafe` is present. The regression kernel proof path is integrated and
independently verified. It is not the selected complete topology and remains a differential
control; the current heterogeneous K128/K512 prototype evidence is recorded below.

The OODS API rejects the Fp8 fixed subfield (`Frob^8(t) == t`, equivalently a
zero top `w` half) before stereographic inversion and carries the accepted
attempt as replayable evidence. The degree-correction API uses the point and
its Fp16/Fp8 conjugate, requires both claimed evaluations explicitly, and
deterministically handles both coordinate-separator cases. It never assumes an
arbitrary Fp16-coefficient function satisfies the base-field conjugate-claim
identity. These are exact scalar references, not production constant-time or
theorem-qualification evidence.

The direct hiding certificate covers both the OODS parameter and its trace-domain transition
translate plus concrete base-domain queries. The quotient module freezes the source-aligned split
factor and mask kernel. The selected split and interactive prover integration now exist; full
relation simulator composition and leakage qualification remain open.

Run the benchmark-style scalar workload with:

```text
cargo run --release --offline --locked --bin scalar-throughput
```

Its output compares the identical scalar square/multiply/add workload over M31 and Fp16 for
K128/K256/K512. It is a field-substrate diagnostic only, not a proof-throughput claim.

Run the cross-language dimension surface with:

```text
cargo run --offline --locked --bin wave1a-dimensions
```

That command prints exact relation-interface dimensions and program KATs. It
does not build or verify a proof and keeps the proof-suite ID unset.

Run the fixed K128 economic-map SHA3 trace workload with:

```text
cargo run --release --offline --locked --bin sha3-trace-throughput
```

It streams 36,080 calls, 74,208 permutations, and 1,780,992 round rows without
retaining the full trace. Its output is trace-generation throughput only, not
proof throughput.

Historical H4 source checkpoint: `hash_bus_snapshot` defines the fail-closed owned semantic-bus codec and
`hash_bus_snapshot_to_b16` converts it to `BLHBB101`. The converter stores each shard's input then
output boundary, wire-major, with 8,192 groups on the minor axis. Only 1,600 live wires are stored;
448 fixed-zero padding wires remain implicit. Exact canonical sizes are 52.429015 MB for K128 and
209.715415 MB for four-shard K512. The exact B16 group control now publishes the first cubic
message directly from compact patterns and folds to 4,096 groups; its CPU/GPU differential KAT
passes at 1,698.495 MB device state and 229.822 MB host peak. This is H4 component evidence, not a
complete semantic proof.

The real K512 semantic fixture now emits its selected bus without constructing the retired full
physical SHA3 AIR. Its one selected test passed in 441.10 seconds at 3,873.902592 MB externally
monitored peak. Rust converted 165,762 calls into the exact 209.715415 MB four-shard boundary and
the independent 16-worker executor verified every shard in 4.023582 seconds.

`MaskedSharedGroupOracle` is the narrow production seam for the nonuniform B16 group phase. An
untrusted worker publishes one raw cubic before each challenge and returns only the final two
group-folded source tables. Rust retains recurrence checks, adaptive challenge order, native Libra
masks, wire reductions, and terminal verification. The exact CPU oracle matches the complete-table
proof byte for byte and rejects a forged message.

Historical first-attachment checkpoint: the H4 K128 path attached that worker to the exact
`BLHBB101` source, native masking, the
Construction 8.2 PCS, a single authenticated 6,086-round coordinator, and the independent
answer-code/opening verifiers. The statement binding includes the semantic header, exact file
SHA3-512, selected shard, and GKR plan commitment. A fresh segment-32 run completed with every
verification and mutation flag true in 120.670536 seconds, at 969.999360 MB tracked GPU allocation,
536.928256 MB monitored process-tree RSS, and 0.000000 MB scratch. This is functional attachment
evidence only and is superseded by the final measurement below.

Historical raw-wire checkpoint: the accelerator was attached while Rust retained native masks,
recurrences, copied-source terminals, transcript replay, and the complete proof. The newest exact
semantic proof independently verified with every functional and mutation flag true in
53.547306 seconds. Its GKR prelude was 42.017007 seconds and PCS mechanics were 4.692209 seconds.
Decimal peaks were 295.625 MB proof-phase host, 253.977 MB parent lifetime, 76.435 MB native
verifier, 969.999360 MB tracked device allocation, and 0.000000 MB scratch. The older
24.749154-second H3 result is not H4 semantic-proof evidence.

At that historical checkpoint K128 remained above its 30-second gate. The first K512 implementation
uses four ordered complete shard proofs sequentially on one GPU with one atomic acceptance boundary,
avoiding four-way RAM/VRAM duplication and unsound theorem-free challenge sharing. zkDeepFold is
not selected; its `2^ell > s * mu^2` condition is valid only for its own simulator instantiation
and does not bind this system's composition. Construction 8.2 of ePrint 2026/391 remains
authoritative.

The historical first K512 coordinator attached all four ordered shard proofs and they independently
verified and the outer atomic receipt passed. Coordinator time was 222.600073 seconds, with
591.249408 MB external process-tree RSS, 2,182.086656 MB sampled total GPU use, 0.000000 MB
scratch, no pagefile growth, and no driver event. That result was functional evidence and failed
the latency gate; it is superseded by the final measurement below.

Historical manifest-bound checkpoint: one fail-closed coordinator handled exactly one K128 shard or four
ordered K512 shards. Its v2 parent/receipt includes a recomputed execution manifest over the Python
entrypoint, prototype and semantic-worker dependency closure, seven native verifiers, and
precompiled PTX. Fresh K128/K512 coordinator times are 54.955357/220.583627 seconds; external
times are 59.060426/226.627989 seconds. K128 external process-tree RSS is 532.242432 MB. K512
external process-tree RSS is 547.127296 MB and sampled total GPU is 2,182.086656 MB. Both have
empty stderr, zero pagefile growth, zero driver events, and all functional gates true. Their
30/180-second latency gates remain false.

Only complete formats remain accepted: 20/36 Merkle trees, V4 answer code, V2 standalone answer
target, and complete GKR-mask spot checks. Run:

```text
python cuda/fp16_zk_rs_retired_format_rejection_kat.py
```

It rejects 10/10 old or incomplete encodings. The stale V1 answer-code acceptance KAT is removed.
Both complete Merkle geometries and the V4/V2 KAT pass. The full optimized suite reports 264
library tests passed, zero failed, zero ignored, plus all binary groups; strict Clippy is clean.

Keep `LAYERS_PER_WORKER_PROCESS=48`. A measured increase to 56 failed at completed layer 54 with
CUDA error 700 and produced Event 153 record 229592. It was reverted and the driver reset before
the subsequent K512 proof.

Final H4 checkpoint: canonical layer plans are encoded and transported once, immutable geometry is
uploaded once per worker, same-source aliases are derived without duplicate word transport, the
semantic file is consumed in one pass, and exactly one future 48-layer worker overlaps
fresh-context startup. Worker and proof Python processes use `-S` and import only the standard
library plus manifest-bound local modules.

The final-manifest K128 proof took 29.974129 seconds with 288.412 MB internal host peak,
681.607168 MB external process-tree peak, 969.999360 MB tracked device state, and 0.000000 MB
scratch. Four K512 shards took 31.567686, 30.679149, 31.019240, and 25.998881 seconds and completed
atomically in 120.460733 seconds with 296.255 MB internal host peak, 706.523136 MB external
process-tree peak, 2,770.337792 MB externally sampled total GPU residency, and 0.000000 MB scratch.
Both accepted attempts had zero pagefile growth and zero driver events. All memory figures are
decimal MB.

The optimized library suite passes 266/266 with zero ignored tests; every binary and doc-test group
passes; strict all-target Clippy has zero warnings. Seven host cryptographic KATs pass. The
segment-32 KAT verifies all 20 trees and rejects every tested leaf/frontier/root mutation; the
retired-format KAT rejects 10/10 old or incomplete forms. Static compilation emits 36 CUDA entry
points in a 3.494439 MB PTX image with SHA-256
`B1F826445F2630517E250CE4BBB5E694ADC61620BEED5684C6EE09197EBBEF73`.

No additional test was removed in the final audit. The V1-layer compaction test remains a required
migration-equivalence check, the two-claim GKR/PCS bridge remains a nonproduction component
differential, and the retired-format KAT proves those older formats cannot enter the active
verifier. Gate 2E precedes H5; H5 and H6 remain open, qualification and activation stay false, and
`proofSuiteId` stays null.
