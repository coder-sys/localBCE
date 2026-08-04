# BL-PQ512 crypto core

Updated: 2026-08-02

Status: authoritative implementation guide for the selected nonactivating H4 proof core. Former
checkpoint narrative is archived at
`../../docs/history/BL_PQ512_CRYPTO_CORE_README_THROUGH_2026-08-01.md`.

## Role

This crate implements the M31/Fp16/SHA3-512 proof substrate, shared-bus B16 Boolean GKR
coprocessor, native GKR hiding, Construction 8.2 PCS, authenticated public coin, canonical proof
grammar, atomic one/four-shard coordinator, and authoritative independent verifier.

It does not select persistent state, assign H5/H6 qualification, assign a suite identity, authorize
production activation, or provide Ethereum settlement. The native coordinator has a bounded
`--verify-state-binding` path and accepts `state-file:<path>` for both the version-2 compatibility
envelope and the nonactivating version-3 compact state-AIR/FRI envelope. Version 3 exports a
private streamed dual-PQ FRI package; native Rust replays the state, compares the compact trace
with exact operations, verifies the package, and recomputes the state/component/receipt identities
before the H4 parent uses that statement. The versioned state-root bus seam independently checks
the two appended state-root calls before child spawn. This is a real state-proof component
boundary, not yet the full state AIR inside the custom H4 GKR/PCS proof or a qualified backend.
Direct SHA3 AIR and other retained narrow controls are differential or fail-closed regression
machinery, not alternate proof backends.

## Current accepted profiles

| Property | K128 | K512 |
| --- | ---: | ---: |
| Live claims | 100 | 500 |
| Semantic SHA3 calls | 46,858 | 165,762 |
| Shards | 1 | 4 ordered sequential |
| Padded permutations/shard | 131,072 | 131,072 |
| Live input wires/permutation | 1,600 | 1,600 |
| `BLHBB101` bytes | 52,429,015 | 209,715,415 |
| Complete H4 process | 29.974129 s | 120.460733 s |

The state-composed formats are separate, nonactivating extensions: `BLHBSN02`/`BLHBB102` append
two root calls at capacity 18,048 (K128) or 70,656 (K512), adding 502 or 1,964 live permutations.
Their resulting descriptor totals are 114,232 and 413,370 live permutations. The original
`BLHBSN01`/`BLHBB101` source remains byte-compatible. The v3 compact state-AIR fixture was
independently verified at the native state-file boundary, but no new manifest-bound H4 K128/K512
proof was run after this source change.

The current fixed prelude uses 6,073 hash-GKR rounds, 26 state-relation rounds, one final mask
batch, and 13 PCS rounds: 6,113 combined. Square-free state composition adds 614 K128 or 882 K512
rounds. Both profiles retain nineteen fixed claims, reaching 6,727/6,995 total rounds. The
standalone PCS protocol uses 14 rounds because
its boundary authenticates the complete GKR claims before continuation. The state-composed shape
has no new manifest-bound K128/K512 performance or qualification credit.

## Trust boundary

CUDA performs untrusted field, group, wire, fold, and RS arithmetic. Rust owns canonical parsing,
SHA3-512 commitments and roots, topology, challenges, native masks, recurrence and terminal checks,
query derivation, multiproofs, answer code, target, dual-PQ replay, mutations, and acceptance.

Any timeout, crash, malformed output, stderr, missing telemetry, driver event, pagefile growth,
manifest drift, or verifier disagreement rejects the proof. A retry starts from fresh randomness;
no partial proof or challenge tail is resumed.

## Selected construction

- M31 base field and reviewed degree-16 Fp16 tower.
- SHA3-512 authoritative commitments, transcript domains, manifests, and receipts.
- Seven explicit B=16 Keccak layers repeated over 24 rounds and 168 layers.
- State-free hash bus: one output plus four relay-free input claims; state-composed H4 adds two
  state claims to the same PCS row binding.
- 508 native GKR mask constraints per shard.
- 80 claim-component plus 64 mask states in the compact row relation.
- Construction 8.2 random-padded interleaved Reed--Solomon PCS.
- Complete 73-word auxiliary plane.
- ML-DSA-87 plus SLH-DSA-SHAKE-256f authenticated interactive public coin.
- Complete-only 20-tree K128 and 36-tree K512 proof geometries.
- One atomic parent/receipt binding every ordered shard and the execution manifest.

## Current resource envelope

All values are decimal MB.

| Allocation/measurement | Value |
| --- | ---: |
| Five-claim state-free row state | 7.864320 |
| Simultaneous GKR-mask rows | 4.194304 |
| Total joined row state | 12.058624 |
| GKR-mask coefficients/codewords | 2.097152 / 33.554432 |
| Complete auxiliary coefficients/codewords | 15.258752 / 38.273024 |
| K128 internal/process-tree host | 288.412 / 681.607168 |
| K512 internal/process-tree host | 296.255 / 706.523136 |
| Tracked device state/proof | 969.999360 |
| K512 sampled total GPU residency | 2,770.337792 |
| Scratch | 0.000000 |

The hard gates remain 5,000 MB maximum host RSS, scratch strictly below 5,000 MB, and no swap.

## State-GKR composition seam

`src/state_relation_gkr.rs` proves a fixed compact relation over 4,096 groups and 64 source wires.
The H4 bridge places it at wire offset 1,600, lifts two local terminals into the exact 24-coordinate
H4 PCS geometry, and authenticates a canonical 16,777,216-byte private source. The implemented
relation checks operation/snapshot field equality, Boolean presence, and empty-slot zeroing. It is
not yet the complete state relation: operation order, uniqueness, membership/absence, and
money/state conservation remain Gate 2E obligations. State-free and state-composed transcripts
share one fixed public shape; the state-free branch carries zero state claims/source digest.

`src/state_uniqueness_gkr.rs` is an executable proof-native differential control for duplicate-key
rejection. It checks every unordered pair in both state phases, uses message-before-challenge
interactive sumchecks, and exposes two PCS input claims. It verified at 21.902903 seconds for 128
slots and 426.679855 seconds for 512 slots; the latter exceeds the complete 180-second ceiling by
itself. The quadratic construction is therefore rejected as the selected H4 route and is retained
only as a correctness/attack oracle for a subquadratic successor.

`src/state_squarefree_gkr.rs` is the linear-size successor candidate. After the state commitment,
an authenticated Fp16 `beta` compresses each injective two-Fp16 key; four bounded Bezout coefficient
tables are then committed before a fresh evaluation point. A dual-number product GKR proves
`P(r),P'(r)` and coefficient sumchecks prove `A(r)P(r)+B(r)P'(r)=1` for both state phases.
Every challenge is message-first. The verifier reduces four virtual leaves to twelve openings of the
existing presence/key columns and emits two grouped coefficient-table PCS claims. Release controls measured
0.042439/0.046355/0.023395 seconds for K128 and 0.698637/0.237447/0.072302 seconds for K512
(witness/prove/verify), with 32,768/131,072 witness bytes. This is verified component evidence, not
H4 credit by themselves: the production boundary now composes those tables and state openings, but
still requires exclusive-host proof and leakage qualification.

## Source ownership

| Responsibility | Source |
| --- | --- |
| Profile and semantic schedule | `src/wave1a_global_schedule.rs`, `src/wave1a_dimensions.rs` |
| B16 source and codec | `src/hash_bus.rs`, `src/hash_bus_snapshot.rs`, `src/hash_bus_b16_boundary.rs`, `src/hash_bus_b16_trace.rs`, `src/bin/hash_bus_snapshot_to_b16.rs` |
| Selected plan and worker seam | `src/hash_bus_b16_gkr_plan.rs`, `src/hash_bus_b16_gkr_worker.rs` |
| GKR schedule/source/proof | `src/fp16_relay_free_gkr_schedule.rs`, `src/fp16_relay_free_gkr_source.rs`, `src/fp16_relay_free_gkr_uniform.rs` |
| Native masks and GKR/PCS binding | `src/gkr_zk_mask.rs`, `src/fp16_zk_rs_gkr_binding.rs` |
| PCS transcript/proof/query | `src/multilinear_pcs_transcript.rs`, `src/multilinear_pcs_proof.rs`, `src/multilinear_pcs_query.rs` |
| Multiproofs | `src/fri_layer_multiproof.rs` |
| Public coin | `src/chained_public_coin.rs`, `src/chained_public_coin_client.rs`, `src/bin/chained_public_coin_service.rs` |
| Atomic coordinator | `src/bin/k512_atomic_semantic_prototype.rs` |
| CUDA arithmetic | `cuda/cuda_hash_bus_b16_gkr_worker.py` and manifest-bound local helpers |
| Complete prototype entry | `cuda/cuda_fp16_zk_rs_theorem8_1_k128_prototype.py` |
| Independent verification | `src/bin/fp16_zk_rs_*verify.rs` plus answer/target and public-coin binaries |

Historically named helpers may still be active dependencies. Never remove or rename one from its
name alone; trace imports, manifest identity, tests, codecs, and verifier consumers first.

## Worker rules

- `LAYERS_PER_WORKER_PROCESS=48` is mandatory under current evidence.
- Keep one active worker and exactly one future worker.
- Validate and transport a canonical plan once.
- Upload immutable topology once per worker.
- Read the semantic file once and derive same-source aliases.
- Start Python proof workers with `-S` and manifest-bound local imports only.
- Keep K512 shards sequential on one GPU with independent challenge streams.

Before any production CUDA proof, audit the Windows System log and establish a clean reset
boundary. The 56-layer experiment faulted at layer 54 and produced `nvlddmkm` Event 153; this is a
driver-integrity constraint, not a memory-capacity problem.

## Required verification

Run exact commands from the current sealed handoff. The containing gate includes:

```text
cargo fmt --all -- --check
cargo check --release --offline --locked --lib --no-default-features
cargo clippy --release --offline --locked --all-targets --features std,parallel -- -D warnings
cargo test --release --offline --locked --features std,parallel
```

Also require every binary and doc-test group, seven host cryptographic KATs, complete 20/36-tree
geometry checks, segment-32 mutation rejection, 10/10 retired-format rejection, static CUDA
compilation, execution-manifest readback, and independent proof/receipt verification.

The active optimized library baseline is 264/264 tests, zero ignored, with strict Clippy at zero
warnings. Counts must be re-collected after changes; never force them to match a stale number.

## Useful diagnostics

```text
cargo run --release --offline --locked --bin scalar-throughput
cargo run --offline --locked --bin wave1a-dimensions
cargo run --release --offline --locked --bin sha3-trace-throughput
python cuda/fp16_zk_rs_retired_format_rejection_kat.py
```

These are field, dimension, trace-generation, or rejection diagnostics. They are not complete-proof
throughput evidence.

## Current next dependency

The terminal Gate 2E composition/simulator/leakage/state-proof receipt ledger reference is now
implemented and tested, but it is deliberately unsealed. The complete state relation is now inside
the H4 proof boundary; Gate 2E must still admit a reviewed state/PQ commitment plane and seal it
into the H4 parent, transcript, proof grammar, independent verifier, and receipt. H5 then runs one warm-up plus ten
unique K128 and ten unique K512 proofs; H6 closes the theorem, simulator, parser, attack,
reproducibility, resource, and identity obligations.

The read-only H5 preflight now freezes that campaign boundary and returns
`BLOCKED_H5_PREFLIGHT`: 22 fresh launches are required, but the current terminal ledger is
unsealed, no state plane is selected, and no complete-proof
campaign or external monitor has run. The recorded reference hardware now meets the reduced
1.5% operational disk floor (7,310,026,937 bytes required); its refreshed preflight digest is
`9c8cd9e4836576487431af85e3c1ae2b458d44580c144ceeda971f500cd9be279910ea88045761f59699d7b67a8520920a17f07b33d173ce9270d0d064d31693`. This does not assign
`proofSuiteId`, authorize CUDA, or grant qualification credit.

`proofSuiteId=null`, activation is false, and real PHI/payments remain forbidden.

The fail-closed H6 preflight now records all twelve qualification obligations without claiming any
are closed. Its current record is `BLOCKED_H6_PREFLIGHT`; it replays the H5/2E evidence, confirms
the candidate suite registry remains `CANDIDATE_UNQUALIFIED` with eight null module identities,
and reports five blocked, five open, and two reference-only obligation records. This is evidence
boundary scaffolding only: no H5 launch, proof-suite selection, H4 state admission, or activation
credit is granted.
