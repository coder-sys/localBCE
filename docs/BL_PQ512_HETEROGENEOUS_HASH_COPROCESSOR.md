# BL-PQ512 shared-bus Boolean hash coprocessor

Updated: 2026-08-02

Status: selected nonactivating Wave 2 architecture. Historical experiments and superseded
measurements are preserved in
`history/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR_THROUGH_2026-08-01.md`; rejected alternatives are
governed by `REJECTED_ARCHITECTURES.md` and cannot be used as fallbacks.

## 1. Decision

The sealed M31 semantic AIR and SHA3-512 hash calls form one heterogeneous proof:

1. the bounded CPU/SIMD semantic lane proves claim, ordering, payment, replay, and public-output
   semantics;
2. every SHA3 call crosses one canonical fixed-shape committed `BLHBB101` bus;
3. an Fp16 Boolean GKR coprocessor proves the exact FIPS 202 Keccak computations;
4. the state-free hash bus uses one output plus four relay-free input claims, while the current
   state-composed H4 shape adds two state claims to the same PCS boundary without replaying a
   duplicate full hash source;
5. native GKR masks and the Construction 8.2 PCS provide the selected hiding/commitment mechanics;
6. one dual-PQ authenticated interactive public-coin chain orders all challenges; and
7. one authoritative Rust verifier and atomic receipt accept or reject the complete statement.

The GPU is an untrusted arithmetic accelerator. It never owns transcript order, authoritative
commitments, parsing, canonical decoding, targets, answer codes, semantic equality, or acceptance.

## 2. Frozen invariants

- Exact Wave 1 relation and exact ordered 12-field compatibility ABI.
- Fixed K128/K512 observable shape and proof grammar.
- Native hiding; no PHI, exact private amount, claim record, decision metadata, or private
  operational detail in public bytes, logs, errors, or telemetry.
- SHA3-512 authority and M31/Fp16 algebra.
- Authenticated interactive public coin; zero Fiat--Shamir/QROM/grinding credit.
- ML-DSA-87 plus SLH-DSA-SHAKE-256f authentication on Blind Ledger-controlled challenge surfaces.
- At least 256 bits for every security/error term and the composed ledger.
- No trusted setup, RSA, ECC, pairings, KZG, IPA, external prover, or host-trusted equality.
- Host RSS at most 5,000,000,000 decimal bytes, scratch strictly below that value, and no swap.
- Complete-proof p95 below 35 seconds K128 and below 180 seconds K512.
- Independent authoritative verification of every shard and the outer receipt.

## 3. Exact accepted geometry

| Property | K128 | K512 |
| --- | ---: | ---: |
| Live claims | 100 | 500 |
| Semantic SHA3 calls | 46,858 | 165,762 |
| Canonical shards | 1 | 4 |
| Padded permutations per shard | 131,072 | 131,072 |
| Live input wires per permutation | 1,600 | 1,600 |
| Implicit fixed-zero wires | 448 | 448 |
| `BLHBB101` bytes | 52,429,015 | 209,715,415 |
| Execution | one complete shard | four complete ordered shards, sequential on one GPU |

Each shard proves 24 Keccak rounds as 168 explicit nonuniform layers under the seven-layer B=16
relay-free plan. Fixed-zero wires are derived from the format and are never serialized as a second
full source.

## 4. Algebra and claim boundary

The base field is M31 and verifier challenges live in the reviewed degree-16 Fp16 tower. The
coprocessor uses the exact seven-layer Keccak schedule and keeps full Fp16 verifier entropy.

The state-free hash bus exposes five relay-free claims:

- one output claim for the digest boundary; and
- four input claims covering the source boundary.

Each hash claim contains 24 coordinates, one packed value, one shard query, and sixteen committed
component evaluations. Low coordinates select the RS-message coefficient; high coordinates select
the interleaving and source boundary. Rust derives claim powers, coordinate-map coefficients,
initial target, compact quadratic chain, and final answer target.

The compact row relation contains 80 claim-component states and 64 committed GKR-mask states. It
folds 144 source/relation states across 512 interleaved words in nine quadratic rounds. Python or
CUDA cannot supply an authoritative row parameter, linear form, or target.

The current nonactivating state-GKR seam adds two boundary-one claims to the same H4 PCS geometry.
It uses a 64-wire lane at H4 wire offset 1,600, 4,096 fixed groups, and a canonical private
16,777,216-byte source. Its implemented relation covers operation/snapshot field equality, Boolean
presence, empty-slot zeroing, compressed-row equality, and linear square-free uniqueness for both
snapshots. The fixed boundary contains nineteen claims, but no state-composed H4 performance or
qualification credit is claimed.

The bounded all-pairs uniqueness GKR control is theorem-valid and emits two PCS terminals under
message-before-challenge interactive public coin, but it is not selected: measured release proving
took 21.902903 seconds for 128 slots and 426.679855 seconds for 512 slots. The K512 control alone
misses the 180-second complete-proof gate, so Gate 2E must use a subquadratic uniqueness relation.

The implemented successor is a linear-size square-free/derivative product GKR. Its message-first
control measured K512 witness/prove/verify at 0.698637/0.237447/0.072302 seconds with a
131,072-byte witness, versus 426.679855 seconds for the rejected pairwise prover. It reduces four
virtual leaves to twelve openings of the existing state lane and adds four Bezout coefficient-table
claims. `state_squarefree_pcs.rs` now verifies the exact fixed PCS composition: all four private
tables occupy one 2,048-message/1,218-random-value auxiliary codeword, and all twelve state
openings lift into the existing 24-coordinate H4 source geometry. K128 and K512 composition plus
coefficient/state mutations pass. The retained tree, parent transcript, fixed H4 grammar, and
independent production verifier are not yet wired, so no state-composed timing or selection credit
is taken.

## 5. Native hiding and PCS

Every shard verifies 508 native GKR mask constraints. The GKR mask is committed as 64
dimension-512 auxiliary codewords. The complete auxiliary answer plane contains 73 words: nine
sumcheck-mask words and 64 GKR-mask words.

The state-composed source lane is a separate fixed-shape addition and its canonical source is
16,777,216 bytes. Its end-to-end allocation and latency impact remain unmeasured; H5 must not
reuse the state-free resource record.

The selected PCS is Construction 8.2 random-padded interleaved Reed--Solomon:

- main instance: length 131,072; 65,536 message values; 2,048 random-padding values; proximity
  `5/32`; 1,600 queries;
- nine auxiliary instances: length 8,192; 2,048 message values; 1,218 random-padding values;
  proximity `1/5`; 1,218 queries; and
- current composed PCS ledger: 392.108419573 bits before the still-open complete H6 composition.

All roots and hiding bindings are fixed before their dependent batching or query challenges. Rust
reconstructs canonical messages, query positions, roots, openings, answer code, and target. The
accepted verifier recognizes only the complete 20-tree K128 and 36-tree K512 geometries; retired
or incomplete encodings fail closed.

Construction 8.2 is selected for H4 and Gate 2E composition. Selection is not H5/H6 qualification.

## 6. Authenticated schedule

The complete shard schedule has exactly:

| Segment | Rounds |
| --- | ---: |
| Hash GKR (state-free) | 6,073 |
| State relation and final mask batch | 27 |
| Square-free K128 | 614 |
| Square-free K512 | 882 |
| PCS | 13 |
| Fixed prelude through PCS | 6,113 |
| Combined state-composed K128 | 6,727 |
| Combined state-composed K512 | 6,995 |

The standalone PCS integration has 14 rounds because it must authenticate the complete GKR-claims
boundary before its continuation. The standalone and combined counts describe different protocol
boundaries and are not interchangeable.

The coordinator verifies both PQ-authenticated chain heads, releases each challenge only after the
corresponding prover message, checks every reverse-chain reveal, and retains replay evidence. A
retry starts a new proof and new chain; no challenge tail, mask, opening, or partial receipt is
resumed.

## 7. Memory and worker lifetime

| Live allocation | Decimal MB |
| --- | ---: |
| Five-claim state-free component/source/relation rows | 7.864320 |
| GKR-mask source/relation rows | 4.194304 |
| Total joined row state | 12.058624 |
| GKR-mask coefficients | 2.097152 |
| GKR-mask RS codewords | 33.554432 |
| Complete auxiliary coefficients | 15.258752 |
| Complete auxiliary codewords | 38.273024 |
| Immutable packed topology | 3.225600 |

The coordinator keeps one active worker and exactly one future 48-layer worker after plan
acceptance. Zero standby workers expose measured context-startup latency; more than one adds
unjustified residency and contention. A lifetime above 48 layers is forbidden by current evidence:
the 56-layer test faulted at layer 54 with CUDA error 700 and `nvlddmkm` Event 153.

Canonical plans are validated and transported once. Immutable topology is uploaded once per
worker. Same-source aliases replace duplicate word transport. The semantic file is read once.
Python workers start with `-S` and import only the standard library and manifest-bound local code.

## 8. Authority split and verifier order

CUDA may compute raw group cubics, wire quadratics, boundary evaluations, folds, and telemetry.
Rust owns topology, challenges, masks, recurrence state, terminal checks, canonical commitments,
SHA3-512 roots, parser bounds, transcript replay, query derivation, answer/target checks, mutations,
and final acceptance.

Logical verifier order:

1. enforce byte caps, profile, grammar, and canonical integers before large allocation;
2. reject K256, zero statement, wrong shard geometry, extra bytes, and unknown sections;
3. verify execution-manifest and parent identities;
4. verify dual-PQ chain heads and replay all 6,113 fixed-prelude, 6,727 K128, or 6,995 K512 challenges;
5. verify semantic source, selected plan, claims, GKR recurrences/terminals, and native masks;
6. verify PCS tree geometry, multiproofs, openings, answer code, and target;
7. independently verify every shard in canonical order;
8. verify outer receipt and resource/latency result; and
9. emit acceptance only after every prior step succeeds.

Timeout, crash, malformed stdout, stderr, missing telemetry, driver error, pagefile growth,
manifest drift, or ambiguous classification rejects the attempt.

## 8.3 Current selected H4 result

Execution manifest SHA3-512:

`51c23310274ccf7c4d7f9abe4ae7eba43266b335bd377b21cbf92409729b91e2a40a39787a157baa080c9d0516c7815af404a4d58d9e76747f652f57cd017ed6`

| Measurement | K128 | K512 |
| --- | ---: | ---: |
| Complete process | 29.974129 s | 120.460733 s |
| Internal host peak | 288.412 MB | 296.255 MB |
| External process-tree peak | 681.607168 MB | 706.523136 MB |
| Tracked per-proof device state | 969.999360 MB | 969.999360 MB |
| Sampled total GPU residency | not separately promoted | 2,770.337792 MB |
| Scratch | 0.000000 MB | 0.000000 MB |
| Pagefile growth | zero | zero |
| Post-reset driver events | zero | zero |

K512 shard proof times were 31.567686, 30.679149, 31.019240, and 25.998881 seconds. Every shard
and outer receipt independently verified with empty stderr under the verified
`2026-07-31T05:06:01.7747420-06:00` reset boundary.

This closes H4 functional and one-run prototype latency only. It does not select persistent state,
run H5 p95 qualification, close the simulator/security ledger, assign `proofSuiteId`, activate a
verifier, or authorize production.

## 8.4 Versioned state-composed bridge (nonactivating)

The state-bound source seam is versioned separately from the accepted state-free profile. A
`BLHBSN02`/version 2 snapshot is converted to a `BLHBB102`/version 2 boundary. The descriptor
clones the base hash-bus runs and appends exactly two SHA3 root calls whose message is
`STATE_ROOT_DOMAIN || len(snapshot.encoded).to_bytes(4,"big") || snapshot.encoded`.

The fixed state-root capacity is `claim_slots*137+512`: 18,048 for K128 and 70,656 for K512.
Those two calls add 502 and 1,964 live permutations, producing state-composed totals of 114,232
and 413,370 respectively. The state-free `BLHBSN01`/`BLHBB101` descriptor and bytes remain
byte-compatible. Rust independently verifies the exact input and output bit patterns of the two
appended calls before the child proof starts; the worker derives the totals from the descriptor and
has a durable wire-major/little-endian regression test.

This is proof-native source and child-boundary evidence. A separate nonactivating v3 state envelope
now adds the versioned `BL-PQ512-STATE-RELATION-AIR-v2` compact packed transition-AIR/streamed-FRI
component. Its two 46-wide multiset lookups bind ordered operation rows to the complete fixed
before/after snapshot tables; the native verifier also compares those columns with the exact state
witness and independently verifies the selected FRI package. It is still not a qualified H4 state
proof: the full state relation is not yet constrained inside the custom H4 GKR/PCS composition.
This component phase did not run a manifest-bound H4 qualification: the measured fixture was
capacity 8 only, so the state-free manifest above remains historical evidence for the accepted
prototype. Production CUDA, H5, `proofSuiteId`, and activation remain forbidden.

## 8.5 Current H4 state-GKR bridge (nonactivating)

The Rust state-GKR bridge now authenticates the compact relation in the same H4 PCS source
geometry: it uses a fixed 64-wire lane at wire offset 1,600, two boundary-one input claims, 26
state-relation rounds, one final mask batch, and 614/882 square-free rounds. The H4 row batch has
nineteen fixed claims and 6,727/6,995 total K128/K512 rounds; absent-state execution retains the
same public claim shape with zero state claims/source digest.

The current relation proves operation/snapshot field equality, authenticated slot index/order,
Boolean presence, and empty-slot zeroing. The native Rust binding parser and Python canonical
snapshot decoder reject duplicate present keys. High-cardinality membership/absence and
money/state-conservation semantics remain supplied by the typed state-AIR boundary. No
state-composed performance or qualification credit is claimed; the exact state source and
transcript are integration evidence only until those obligations and the Gate 2E
leakage/backend gates close; the complete conditioned simulator mechanics are now verified.

The separate C0 typed-state executable AIR now supplies the missing ordered-map/payment semantic
slice at its semantic-AIR boundary. It binds replay and payment roots/cursors, fixed slot
order, canonical money subtraction and debit/credit conservation, and composes both lanes' SHA3
ports through one contiguous interface-only bus. The verified K128 v5 shape is 56 tables, 79
lookups, 1,806 public inputs, and 46,210 exact calls: 46,208 replay/payment calls plus two C0
state-root calls. Its encoded program is 23,906,457 bytes, its execution is 148,684,533 bytes,
and its raw witness is 102,981,664 bytes. The v5 interface retains the 8-lane source bundle and
packs operation/log preimages into 64-lane vector lookup messages with fixed live bits, preserving
every call index, position, value, and byte obligation. It replaces the duplicate replay/payment
key-sentinel lookups with local byte/inverse identities tied to range-checked key bytes. It also
groups 41 fixed scalar-copy positions into eight vector source messages and one masked
bundle destination. Positive, root, money, compact-log, scalar-bundle, sentinel aggregate-bypass,
and fixed asset-registry mutation
rejection evidence passed. The native H4 coordinator consumes the full typed AIR execution,
independently verifies its authority/root tables, and maps every typed call to the canonical H4
boundary. The generic typed proof route remains rejected by the immutable resource preflight
(`modeled_peak_scratch_bytes=14944264032`, `scratch_gate_pass=false`,
`route_status=REJECTED_CURRENT_PERSISTENT_ORACLE_LIFETIME`,
`modeled_required_available_bytes=22975297336`, `qualifies=false`); this remains a nonactivating
seam with no Gate 2E, H5, H6, backend, or `proofSuiteId` credit.

## 9. Required green evidence

- 264 optimized Rust library tests, zero failures and zero ignored, plus every binary/doc-test group;
- format check, locked/offline builds, no-default/no-std check, strict all-target Clippy;
- seven host cryptographic KATs;
- complete 20/36-tree geometry tests and segment-32 mutation rejection;
- 10/10 retired-format rejections;
- static compilation of 36 CUDA entry points;
- manifest readback by coordinator and external monitor;
- externally monitored independent verification with zero pagefile growth and scratch; and
- no new driver event after the audited reset boundary.

Before a production CUDA proof, audit the Windows System log. Do not launch until a clean reset
boundary is established. This is a driver-integrity gate, not a VRAM-capacity gate.

## 10. Next dependency

Gate 2E must complete the state relation inside the H4 proof and select/admit a reviewed PQ
commitment, then atomically bind the state plane into the H4 parent, transcript, proof grammar,
independent verifier, and receipt. Only then does H5 run the exact 22-launch campaign and H6 close
the theorem/simulator/identity seal.

Do not start another proof-backend bake-off, revive BaseFold/zkDeepFold, run H5 on the state-free
H4 proof, increase worker lifetime, parallelize K512 shards without a theorem, duplicate source
state, or trust a GPU-computed equality.

## 11. Evidence routing

- Active implementation: `CURRENT_TECH_STACK.md` and the source ownership map there.
- Active execution: `IMPLEMENTATION_ROADMAP.md`.
- Chronological measurements: dated sections of `../STATE.md`.
- Verbatim former architecture: the `history/` file named at the top.
- Rejected alternatives: `REJECTED_ARCHITECTURES.md`.

Historical evidence can support a rejection or regression threshold but never authorize execution.
