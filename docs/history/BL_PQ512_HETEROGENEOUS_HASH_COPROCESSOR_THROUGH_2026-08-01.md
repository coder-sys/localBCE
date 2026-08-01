# Archived BL-PQ512 shared-bus Boolean hash coprocessor through 2026-08-01

Updated: 2026-08-01

Status: authoritative Wave 2 architecture and qualification contract. This selects an implementation
priority, not a production proof suite. `proofSuiteId` remains null, activation and real PHI/payment
use remain forbidden, and every unresolved theorem and measurement gate below remains fail closed.

`CURRENT_TECH_STACK.md` is the concise active inventory. `REJECTED_ARCHITECTURES.md` holds removed
and dominated alternatives. Earlier dated design stages in this file are evidence only wherever
section 8.3 or the 2026-07-31 H4 closure supersedes them.

Current evidence boundary: the newest dated section of `../STATE.md` supersedes the transfer-time
status in `../WAVE2_HANDOFF_2026-07-26.md`. The real semantic source, 168-layer GKR producer,
native masks, Construction 8.2 PCS, authenticated public coin, atomic one/four-shard coordinator,
and independent Rust verifier now complete together. Fresh manifest-bound K128 and K512 prototypes
passed in 29.974129 and 120.460733 seconds with zero scratch, zero accepted-attempt pagefile growth,
and zero post-reset driver events. The architecture remains nonactivating and unqualified: gate 2E
must select and bind the state plane before H5's warm-up-plus-ten p95 campaign, and H6 must then
close.

## 1. Decision

The 554-951 GB direct-SHA3-STARK scratch designs are retired as release candidates. They remain
negative baselines and may be used for differential tests, but neither is a fallback that the
product is allowed to ship.

Wave 2 will implement a heterogeneous proof with one shared committed boundary:

1. the sealed M31 semantic AIR continues to prove claim, policy, replay, money, state-transition,
   fixed-shape, and exact ordered 12-field ABI semantics;
2. the six internal SHA3 trace tables are removed from that AIR's generic wide-column PCS path;
3. every canonical SHA3 call is emitted to one fixed-shape hash-call bus;
4. one data-parallel Boolean circuit proves all Keccak-f[1600] permutations and SHA3-512
   absorb/padding/digest behavior as a dedicated coprocessor;
5. the AIR, bus, and coprocessor are committed before challenges and verified atomically in one
   dual-PQ-authenticated interactive public-coin session.

This is an architecture change, not storage compression. The dominant bit computation stops being
represented as 1,924 private M31 columns followed by generic composition, DEEP, and FRI expansion.
It becomes one repeated Boolean circuit whose instance bits are packed in machine words while its
soundness challenges remain in the reviewed degree-16 M31 extension field.

The name used below is **shared-bus Boolean GKR hash coprocessor**. "GKR" identifies the repeated-
circuit/sumcheck family; it does not import any paper's field, commitment, transcript, security
level, zero-knowledge claim, or Fiat--Shamir compiler.

Cross-wave throughput work is governed by
`docs/FRONTIER_THROUGHPUT_AND_ETHEREUM_ALIGNMENT.md`. Its access manifest, conflict DAG, and
state-topology bake-off surround this construction; they do not silently change its bus, theorem,
roots, or selected implementation priority.

## 2. Frozen product invariants

This pivot may change the physical proof topology only. It may not change:

- SHA3-512 as the authoritative application, state, proof-commitment, and audit digest;
- all 24 FIPS 202 Keccak-f[1600] rounds, padding, rate/capacity, byte order, call order, or digest;
- the K128 fixed-shape schedule of 46,858 calls and 113,730 permutations;
- approval, every denial, and cover work/length/error indistinguishability;
- replay, nullifier, economic-conservation, source/oracle/policy, or state-transition meaning;
- the exact ordered external 12 `bytes32` values or the authenticated wide sidecar;
- M31 base arithmetic and Fp16 challenges, the 256-bit per-term and composed cryptographic
  security/encryption floors,
  or native witness hiding;
- SHA3-512 commitments plus ML-DSA-87 and SLH-DSA-SHAKE-256f authentication on Blind
  Ledger-controlled public-coin and authority surfaces;
- no RSA, ECC, trusted setup, launch Fiat--Shamir/QROM dependency, grinding credit, outside prover,
  or host-trusted hash/state result;
- canonical parsing, bounded allocation, module identities, reproducible builds, KATs, attack
  tests, audit evidence, provider-neutral adapters, and fail-closed atomic acceptance.

Wave 1 stays sealed. Its physical SHA3 AIR remains the independent executable specification and
differential oracle; it is no longer presumed to be the release PCS layout.

## 3. Why the old design explodes

The exact K128 raw private-witness accounting is:

| SHA3 table | Raw private bytes |
| --- | ---: |
| Message | 98,262,720 |
| Digest interface | 11,995,648 |
| Digest byte | 11,995,648 |
| Round | 21,881,652,000 |
| Absorb | 1,059,963,600 |
| Digest Boolean | 107,960,832 |
| **Total** | **23,171,830,448** |

Those six tables account for the complete currently modeled raw private witness. The round table
alone has 2,843,250 rows, 1,995 total columns, 1,924 private columns, and maximum degree 11. The
generic prover then materializes main, interaction, composition, degree-corrected DEEP, masks, and
FRI objects. That produces the rejected 9,034,606,313,472-byte monolithic lower bound or the
950,757,738,236-byte disk plan. Removing duplicate row/column layouts still projects
554,259,695,356 bytes. The 550 GB result is therefore not a hardware recommendation; it is evidence
that the abstraction boundary is wrong.

## 4. Exact local geometry and hardware envelope

### 4.1 K128 hash geometry

| Item | Exact value |
| --- | ---: |
| Calls, six segments | `516, 129, 1, 9,360, 36,848, 4` |
| Calls total | 46,858 |
| Keccak-f[1600] permutations | 113,730 |
| Canonical message bytes | 7,996,042 |
| Canonical digest bytes | 2,998,912 |
| Message + digest bus payload | 10,994,954 bytes |
| One bit-packed 1,600-bit state over every permutation | 22,746,000 bytes |
| All 25 round-boundary states | 568,650,000 bytes |
| Exact chi nonlinear gates, before circuit-layering choices | 4,367,232,000 AND gates |

The 568,650,000-byte figure is not a complete prover measurement. It is the exact storage for all
initial-plus-24-round state bits, with no field-element expansion. It is 40.749x smaller than the
current raw private witness, 974.694x smaller than the 554 GB projection, and 1,671.956x smaller
than the 951 GB disk plan.

### 4.2 Measured development machine

Measured on 2026-07-22:

| Item | Value |
| --- | --- |
| Machine | Dell G15 5535 |
| CPU | AMD Ryzen 7 7840HS, 8 cores / 16 logical processors, 3,801 MHz reported maximum |
| Physical memory | 16,438,382,592 bytes |
| Discrete GPU | NVIDIA GeForce RTX 4060 Laptop GPU, compute capability 8.9, 8,188 MiB reported |
| Integrated GPU | AMD Radeon 780M |
| System disk | 487,335,129,088 bytes total; 59,091,513,344 bytes free at measurement |
| Rust | `rustc 1.96.0`, `cargo 1.96.0` for the Blind Ledger workspace |

This laptop is a required development/reference class. A design that needs 550 GB of scratch or
more than its physical memory fails before performance tuning.

### 4.3 First-pass working-set model

The Boolean-GKR paper's practical packing parameter `B=8` is retained as a research starting point
because its `2^(2B)` precomputation is bounded. Blind Ledger uses 64-byte canonical Fp16 elements.
Let `w` be the generated circuit's maximum padded wires per permutation, including intermediate
wires. A two-accumulator model contributes `2 * (113,730 * w / 8) * 64` bytes. At the raw
1,600-state-wire baseline, before compiler padding or intermediates, the model is:

| Component | Derived bytes |
| --- | ---: |
| 25 bit-packed state snapshots | 568,650,000 |
| Two `(113,730 * 1,600 / 8)` Fp16 accumulator arrays | 2,911,488,000 |
| `B=8`, `2^16`, `3B`-coefficient Fp16 precomputation | 100,663,296 |
| Exact message + digest payload | 10,994,954 |
| **`w=1,600` baseline subtotal** | **3,591,988,768** |

This is an arithmetic baseline, not a conservative upper bound or implemented peak-RSS result. The
compiler must report `w`; circuit wiring, zero-knowledge masks, commitment buffers, allocator
behavior, and semantic-AIR proving remain to be measured. For scale only, `w=2,048` gives
4,407,205,408 bytes and `w=4,096` gives 8,133,910,048 bytes under the same formula. No extrapolation
overrides the measured hard gates below.

The all-Fp16 accumulator term is the control for a subfield-first streamed layout. If the two
eligible early-round arrays remain four-byte M31 values until folding reduces their length, that
term is 181,968,000 bytes and the same raw subtotal is 862,468,768 bytes. This is a 16x reduction
for the accumulator term and 4.165x for the displayed subtotal. It is not an implemented peak:
cross terms, promoted tails, native masks, commitments, generated width, and stream buffers remain
to be measured and must fit the unchanged hard gates.

The release-candidate resource gates are:

- peak resident memory no more than **5,000,000,000 bytes** on the reference laptop;
- scratch high-water mark strictly below **5,000,000,000 bytes** with authenticated cleanup on every
  exit; this is at least 110.852x below the 554 GB projection and 190.152x below the 951 GB plan;
- no phase may depend on swap for correctness or normal completion;
- proof generation must pass with at least 15% disk headroom and 10% RAM headroom after measured
  operating-system/resident overhead;
- the stretch objective is a recompute/checkpoint schedule below 1 GB of scratch; it is not a
  closure claim until measured end to end.
- end-to-end input-to-independently-verified-output p95 below **30 seconds** for a fixed-shape K128
  batch with 100 live claims and below **180 seconds** for a fixed-shape K512 batch with 500 live
  claims, using one uncounted warm-up and ten unique measured synthetic batches per profile;
- cached witnesses/proofs, omitted masking or verification, weaker parameters, and swap-dependent
  runs receive no latency credit.

## 5. Shared hash-call bus

The bus is one committed object, not two privately constructed lists compared by the host. Its
profile-fixed schema contains, in canonical ordinal order:

- suite candidate, profile, global call ordinal, six-segment component tag, and component-local
  ordinal;
- hash family and domain tag, exact preimage capacity, exact governed length, live/padding selector,
  and FIPS 202 delimiter/padding form;
- every preimage byte, every digest byte, and canonical zero padding;
- source and destination port identities needed to bind the semantic AIR lookup arguments;
- fixed-shape dummy rows with the same serialized and proof grammar as live rows.

All lengths, maxima, tags, byte order, and row counts are verifier-derived from the suite/profile,
never prover-selected. The bus has one SHA3-512/Fp16 hiding-PCS commitment root.

The semantic AIR proves that every application hash port appears exactly once in this bus with the
right ordinal, bytes, digest destination, and live/padding semantics. The coprocessor includes the
byte/bit bridge: each byte is reconstructed from eight explicitly Boolean wires, and the fixed
circuit implements absorb, multi-rate padding, all 24 rounds, chaining, and 512-bit squeeze. Its
input and output claims terminate at openings of the same bus commitment.

The verifier rejects unless all of the following succeed under one session and suite candidate:

1. semantic AIR and its bus lookup/permutation arguments;
2. bus PCS binding, canonical shape, hiding openings, and byte/bit boundary;
3. masked Boolean-GKR/sumcheck proof of every SHA3 call;
4. all public-coin signatures, contribution evidence, round order, deadlines, retry burn records,
   and final audit root;
5. exact external ABI and authenticated sidecar binding.

There is no partial acceptance, separate hash receipt, host-computed root, or time window in which a
semantic proof can be paired with a different hash proof.

## 6. Proof and security construction

### 6.1 Algebra

AND is arithmetized as multiplication on Boolean wires and XOR as `x + y - 2xy` over the prime-
characteristic field. The repeated-circuit GKR and every bridge challenge are instantiated over the
existing Fp16 tower, whose cardinality is `((2^31 - 1)^16)` and whose bit length is
495.999999989. Machine-word bit slicing is a witness/prover representation only; it does not replace
Fp16 soundness with a 64- or 128-bit field.

The prover may nevertheless exploit the frozen tower internally. In the subfield-first candidate,
the verifier still samples uniform Fp16 challenges and the final claims remain Fp16 claims, while
early high-volume sums over Boolean/M31 witness values are computed in M31 or the smallest proven
subfield. Promotion occurs only after folding has reduced the live vector. No M31 challenge or
repetition receives security credit.

The current paper bound for a depth-`d`, pack-`B` Boolean GKR instance is proportional to
`d * (B + log(|C|/B)) / |F|`. A preliminary conservative substitution using `B=8`, 288 circuit
layers, and the exact 4,367,232,000 chi-AND count has a numerator of 10,944 and a bound of about
2^-482.58. A nonzero 24-variable multilinear bus difference tested at one uniform Fp16 point has
the preliminary Schwartz--Zippel bound 24/|Fp16|, about 2^-491.42.

These are feasibility calculations, not the final theorem ledger. The generated circuit's exact
depth, width, degrees, every sumcheck, claim reduction, bridge, PCS opening, retry, multi-session,
and hash/signature term must be union-bounded and each independent term must retain at least 392
bits before the suite can advance.

### 6.2 Zero knowledge

Unmasked GKR is ineligible. Wave 2 must implement and prove all three layers:

1. native hiding for the semantic AIR and shared bus PCS;
2. random low-degree masking polynomials for every sumcheck/GKR message and terminal evaluation;
3. a simulator for the complete adaptive authenticated-public-coin transcript, including the shared
   bus, aborts, burned attempts, retries, fixed proof length, and cross-module claim reductions.

No evaluation of an unmasked private bus polynomial may be revealed merely to make the bridge easy.
The implementation must produce indistinguishable simulated transcripts for approval, every denial,
and cover and must pass repeated-proof, chosen-challenge, malformed-mask, and cross-session leakage
attacks. "Standard masking" in a paper is research input, not closure evidence.

### 6.3 Post-quantum/public-coin boundary

The release path remains interactive. Every challenge is released after the exact preceding roots
and messages are committed and is derived from the existing bounded multi-contributor commit/reveal
protocol. SHA3-512 derives uniform Fp16 challenges by rejection sampling; ML-DSA-87 and
SLH-DSA-SHAKE-256f authenticate the services and receipts. The proof has no Fiat--Shamir or QROM
security dependency, no ECC/RSA/KZG/IPA commitment, no trusted setup, and no grinding credit.

## 7. What the research does and does not establish

Primary-source results establish that the topology is credible:

- Xie and Liu identify more-than-100x memory/time blow-up from converting Boolean bits to finite-
  field elements and specifically target many identical hash subcircuits with GKR;
- Hu et al. show word-RAM sublinear operations for data-parallel Boolean GKR and state that the
  optimization extends to prime fields;
- Sparrow demonstrates streaming, space-efficient sumcheck/GKR and small masking polynomials, with
  memory close to native computation in its experiments;
- Libra gives a concrete small-masking-polynomial zero-knowledge transformation for GKR;
- small-characteristic sumcheck retains full extension-field challenges while moving much of the
  prover's early multiplication work to the base field;
- tower sumcheck applies to prime-power extension towers and provides an explicit GKR formulation;
- Scribe demonstrates sequential read/write streaming with low random-access memory, while Hobbit
  provides a separate transparent, plausibly-PQ space-efficient control;
- Ligero/Ligetron demonstrates that transparent hash-based PQ zero knowledge can run with near-
  native memory, but its generic repeated-execution/proof-size tradeoff is a fallback, not the
  throughput lead.

None is adopted wholesale:

- the current Hu et al. construction explicitly says it is not zero knowledge and omits that proof;
- its earlier end-to-end Binius/Keccak comparison was withdrawn because the Keccak circuit size was
  wrong, so the reported 106x figure receives zero credit;
- Sparrow's complete system uses KZG/pairings and Fiat--Shamir;
- Libra uses a one-time trusted setup for its input commitment;
- Ligetron's published noninteractive form relies on a hash/random-oracle compilation and its
  generic WASM route is not the maximum-throughput Keccak circuit;
- current Binius64 uses a different binary-field/Fiat--Shamir/SHA-256/96-bit security profile and
  its benchmarked Binius64 relation is documented as not zero knowledge.
- Scribe's concrete group-commitment instantiations are not PQ, and Hobbit's own PCS, hash,
  Fiat--Shamir, proof grammar, and "plausibly post-quantum" claim do not meet Blind Ledger's frozen
  qualification by themselves.

The borrowed objects are algorithms and proof patterns. Blind Ledger must supply the exact Fp16,
SHA3-512, interactive, hiding, theorem, parser, and module composition.

## 8. Local control benchmark

An exact checkout of `binius-zk/binius64` revision
`3d71de3a09b35a6706eddf8b96a06024358f519b` was compiled under WSL2 Ubuntu with
`RUSTFLAGS=-Ctarget-cpu=native`, Rayon enabled, and the upstream independent Keccak benchmark. The
native Windows build failed in upstream `tracing-profile 0.10.11` because it imports Unix
`nix::sys::resource`; no Blind Ledger or upstream source was patched. Linux results were:

| Permutations | Witness median | Proof median | Combined median | Verify median | Proof bytes | Peak memory |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,365 | 69.075 ms | 944.57 ms | 1.0222 s | 56.477 ms | 276,992 | 246.51 MB |
| 4,096 | 203.14 ms | 1.5540 s | 1.8980 s | 302.35 ms | 352,992 | 491.04 MB |

The 3.0007x larger second circuit used 1.9920x peak memory and 1.8568x combined median time in this
two-point control. This is not a Blind Ledger benchmark, a full-K128 extrapolation, or security
evidence. The control is ineligible for adoption for the reasons above. It establishes only that a
dedicated word/Boolean Keccak proof has a commodity-laptop operating scale radically different from
the current generic wide SHA3 STARK.

### 8.1 Phase 1 optimization design freeze (2026-07-27)

Every number in this subsection is explicitly labeled. `MEASURED` means observed on the reference
laptop in the current source tree. `PROJECTED-FROM-SOURCE` means exact arithmetic from the current
constants and data structures but not an observed process peak. `PROJECTED-DESIGN` means a target
for an unimplemented design. `ASSUMED` means a planning assumption that must be replaced by
evidence before qualification.

#### 8.1.1 Boundary-model/code divergence

- `FROZEN-TARGET` / `PROJECTED-FROM-SOURCE`: the exact 25-state bit-packed K128 history model is
  `568,650,000` bytes; it is not an observed process peak.
- `PROJECTED-FROM-SOURCE`: the control prover retains the initial boundary plus all 216 generated
  layer boundaries, or 217 boundaries total. Its nested `Vec<bool>` representation has
  `77,577,846,784` bytes of Boolean payload at 131,072 padded instances, before `Vec` metadata and
  allocator overhead. Rust `Vec<bool>` is not a bit-packed specialization.
- `PROJECTED-FROM-SOURCE`: the production-shaped packed path avoids nested `Vec<bool>`, but retaining
  the same 217 boundaries as `Vec<u64>` still has `9,697,230,848` bytes of payload before metadata.
- `PROJECTED-DESIGN`: the recovery target is the 25 active round checkpoints plus the packed input,
  with intra-round boundaries regenerated as specified in section 8.1.4. The 568,650,000-byte
  frozen model and the 217-boundary control are therefore different storage models and must not be
  presented as the same implementation.

#### 8.1.2 Bucketed sumcheck schedule

`PROJECTED-DESIGN`: replace each full sparse-term rescan in a sumcheck round with a deterministic
bucket schedule. During descriptor compilation, group terms by the suffix of the bound index. Per
round, evaluate each bucket once, merge buckets as the fold halves the index space, and carry the
accumulated bit-basis weight as the bucket weight. Keep canonical term order within each bucket and
merge in increasing index order. Bucket membership, traversal, and merge order depend only on the
public circuit geometry; witness values and challenge values may not change the access schedule.

The serial indexed reducer remains the control. For fixed fixture seeds, the candidate must emit
byte-identical coefficient vectors at every round, an identical terminal claim, and byte-identical
proof bytes. This parity gate uses `bench_fixture_coin`; live authenticated public-coin runs are
required to verify but are not expected to have identical proof bytes. A mismatch rejects the
candidate rather than changing transcript order or field arithmetic. The invariant is that emitted
round-polynomial coefficients are bit-identical to the current implementation; scheduling has no
transcript, soundness, hiding, or shape effect.

`MEASURED`: the Phase 0 B=8 profile attributes 55.061% of in-module cycle samples to the fused
reducer/index/load/store bucket, 27.571% to field add/sub/reduce/construction, 12.474% to bucket
table lookup/update, and only 3.022% to field multiplication. Consequently this schedule is
theorem-neutral but currently has lower expected yield than a word-level redesign; no throughput
credit is assigned before measurement.

#### 8.1.3 Two-layer round collapse

Status: **SUPERSEDED-AND-REJECTED-BY-SECTION-8.2**. The owner explicitly approved the Phase 2.4
layer-collapse implementation before the current execution handoff. This ratification applies only
to the equations, descriptors, transcript order, mask sizing, and round-accounting work in this
section; it does not authorize section 8.1.6 or the production B=64 kernel.

`PROJECTED-DESIGN`: compile each Keccak round into two proof layers:

1. merged theta, intrinsic relation degree at most 11;
2. merged chi+iota, intrinsic relation degree 3.

The existing nonconstant output-claim equality factor raises the claim-bound round-polynomial
degrees to at most 12 and 4 respectively. Owner authorization on 2026-07-28 therefore fixes the
round messages and masks at 13 coefficients for theta and 5 coefficients for chi+iota. This 13/5
correction supersedes the earlier 12/4 estimate; the equality factor must not be omitted or
host-trusted.

This is a new multi-factor sumcheck, not a descriptor edit. It requires new merged-theta and
merged-chi+iota descriptors, new raw and padded widths, new prover/verifier equations, new codecs,
and new mask dimensions. Current `prove_sparse_terms` is structurally fan-in 2 because it binds
left inputs and then right inputs; that constraint is why theta is a five-layer ladder today.
Merged theta has fan-in 11 and merged chi+iota has fan-in 3, so the new kernel must bind all
wiring-shifted input-MLE factors together per round. The proposed descriptors each have raw
input/output state width 1,600 and padded input/output width 2,048; the compiler must freeze the
exact factor list and generated geometry before implementation.

Transcript order is fixed as: merged-theta polynomial message, its authenticated public-coin
challenge receipt(s), merged-theta terminal claim; then merged-chi+iota polynomial message, its
authenticated public-coin challenge receipt(s), and merged-chi+iota terminal claim. Every reveal
remains after the message it challenges, with the existing dual-PQ authentication and retry/abort
rules. No challenge may be reused across the two merged layers or across Keccak rounds.

- `PROJECTED-FROM-SOURCE`: the Phase 0 scaling law projects 11,809 authenticated rounds at K128 for
  the current 216-layer schedule.
- `PROJECTED-DESIGN`: 2,624 GKR rounds for 48 layers and 1,984 GKR rounds if the wire-variable
  rounds halve from `2 * log2(width)` to `log2(width)` are historical planning placeholders only.
  They receive zero acceptance or calibration credit; exact authenticated-round and coin-round
  counts must be derived from each built schedule.
- `PROJECTED-DESIGN`: merged-layer mask sizing is 13 coefficients for theta and 5 for chi+iota,
  or 13/5 coefficients, covering the claim-bound degrees 12 and 4. The owner approved this exact
  correction on 2026-07-28.
- `PROJECTED-DESIGN`: the largest individual degree contribution is bounded by
  `12 / |Fp16|`, approximately `2^-492`; the final ledger must still add every protocol error term.

The 2026-07-28 owner ratification authorizes implementation behind a build flag in the exact Phase
2.4 order. All KAT, equivalence, transcript, mask, count, fixture-digest, and calibration gates
remain fail closed.

#### 8.1.4 Boundary storage and deterministic recomputation

`PROJECTED-DESIGN`: retain the packed input and 25 active-state checkpoints: the input state and one
state after each of 24 Keccak rounds. During the reverse prover walk, regenerate the eight intra-round
boundaries for that round from its checkpoint, consume them in reverse order, and release them before
moving to the preceding round. Regeneration executes the same fixed eight-layer schedule for every
round and instance. Allocation size, read order, write order, recomputation count, and cleanup are
public and content independent; no witness bit may select a checkpoint or change the walk.

The target payload for the 25 active states remains `568,650,000` bytes (`PROJECTED-FROM-SOURCE`);
packed-input storage, padding, descriptors, masks, allocator overhead, and temporary regenerated
boundaries are additional and must be measured. This is not yet a peak-RSS claim.

#### 8.1.5 `mul_by_m31` inventory

`PROJECTED-FROM-SOURCE`: `field.rs::mul_by_m31` performs 16 base multiplies with data-independent
timing and is used only by the packed kernel. Inventory candidates are the `gate_line` formula
constants and `weighted_gate_quadratic` bit weights, plus the current Boolean-equality/table,
accumulator, and final-polynomial call sites. A site qualifies only when one operand is proved to
be in M31 or is a small fixed wire constant. `MEASURED`: Phase 0 attributes 3.022% of in-module
cycle samples to field multiplication, with most multiplication outside the per-gate fused loop.
The current `add_gate` path therefore is not general-Fp16-multiply dominated.

`fold_multilinear` is explicitly excluded from M31 fast-path conversion: verifier coordinates are
general Fp16 challenges, so its products must remain general Fp16 multiplication. Post-interpolation
and terminal-claim combination likewise remain general Fp16 unless a separate proof establishes a
subfield operand. Near-zero eligible `mul_by_m31` savings are an acceptable result and do not
justify changing the challenge field or transcript.

#### 8.1.6 Nonactivating streamed M31-symbol commitment lane

Status: **NONACTIVATING; OWNER-SIGNOFF-REQUIRED**.

`PROJECTED-DESIGN`: admit an isolated research lane that commits the 1,600-bit input layer as M31
symbols under an M31-linear code with Fp16 challenges. Block encoding streams in public order into
per-column SHA3-512 accumulators. Hiding uses mask rows realized as 16 independent uniform M31
rows. The lane may benchmark commitment construction, opening production, and extraction, but it
does not replace the current Fp16 bus, alter the proof grammar, or receive memory, soundness, or
throughput credit.

The lane remains blocked until the four ECCC 2025/2054 checks pass exactly: **Σ/F decoupling through §4;
symbol-wise distance over Σ; extractor recovers an M31 codeword; no reliance on near-capacity
machinery**. No implementation or selection credit is allowed before all four checks are documented
against the exact construction and the owner records them as passed.

#### 8.1.7 B=64 word redesign

Status: **SUPERSEDED-AND-REJECTED-BY-SECTION-8.2**. A standalone, nonprotocol measurement spike was
authorized and its result is retained below.

`MEASURED`: the direct Phase 0 PMU baseline for B=8 is 13,209,305,088 estimated module cycles over
28,224,000 gate-instances, or **468.017 cycles/gate**. D-cache misses are only a proxy on this
Windows/Ryzen system; no memory-stall cycle percentage is claimed.

`PROJECTED-DESIGN`: B=64 packs 64 instances per machine word and uses an 8x8 tensor/factored
representation. It must not allocate or index a flat `2^64` table. Split-equality-factored weights
make the inner accumulation operate on counted bits before any Fp16 value is touched; the spike
must report explicit operation counts and bounded table bytes. The coefficient and mask geometry
changes from the B=8 control: `OUTPUT_COEFFICIENTS = 3 * B = 192`, and the corresponding bridge
mask must also contain 192 coefficients. These are transcript-affecting dimensions and require
owner signoff before production use.

`PROJECTED-DESIGN`: the individual degree contribution is bounded by
`192 / |Fp16|`, approximately `2^-488`; the complete soundness ledger remains additive. The spike
must report scalar parity, fixed-seed coefficient parity, cycles/gate, peak RSS, table bytes, and
operation counts. Passing the spike does not authorize transcript, mask, codec, or production-path
changes.

#### 8.1.8 Evidence labels and Phase 1 stop

The values above are deliberately separated into `MEASURED`, `PROJECTED-FROM-SOURCE`,
`PROJECTED-DESIGN`, and `ASSUMED`. No projected value is a qualification result. Phase 1 ends with
this design freeze and the matching throughput-plan delta. Sections 8.1.1, 8.1.2, 8.1.4, and 8.1.5
and the standalone B=64 measurement spike are preauthorized to proceed. Section 8.1.3 was
owner-ratified on 2026-07-28. Section 8.1.6 and the production B=64 kernel still require separate
explicit owner signoff.

### 8.2 Sub-30-second K128 architecture correction (2026-07-28)

Status: **SELECTED NONACTIVATING IMPLEMENTATION BLUEPRINT; COMPLETE PROOF NOT YET PROJECTED OR
QUALIFIED**.

The owner's newer engineering target is below 30 seconds for the complete fresh K128 proof, not
merely for GKR. The older below-60-second K128 acceptance floor remains a release rejection floor;
it is not the current architecture-selection target. The timed object must include fresh witness
and commitments, authenticated public coin, masked semantic AIR, bus, GKR, PCS, canonical encoding,
parsing, and independent verification.

#### 8.2.1 Selected critical-path topology

1. Run the non-hash M31 semantic AIR as a bounded CPU/SIMD streaming lane. Freeze its exact K128
   table/lookup/PCS mapping before assigning any timing credit. It commits before challenges and
   runs concurrently with the GPU hash lane.
2. Run the exact seven-layer relay-free Keccak DAG on the untrusted GPU. The seven layers are the
   minimum fan-in-two schedule for five-input theta parity, delta, theta state, chi, and output/iota.
   Keep full unpredictable Fp16 challenges and authoritative Rust verification.
3. Use B=16 packing: one degree-30 packed bridge, thirteen shared-group rounds, and twenty-two
   left/right wire rounds per layer. The complete authenticated schedule is 168 layers and 6,241
   public-coin rounds.
4. Commit the GKR masks through one 32,768-coefficient auxiliary polynomial. The main transparent
   Fp16 BaseFold instance uses rate 1/2, log-domain 23, fold factor 3, 21 folds, and 640 queries.
   It has two sensitive codewords plus one fully random companion. The auxiliary instance uses
   log-domain 16, 15 folds, one sensitive codeword, and one fully random companion.
5. Use SHA3-512 roots, a disjoint multiplicative coset, subgroup-vanishing masks, one shared query
   phase, canonical global multiproofs, and a single canonical owner for every GKR message. The
   authenticated-coin record is the proof's GKR-message store; a second transcript copy is
   forbidden.
6. Join the semantic lane and hash lane only after both verify. The atomic join binds the exact
   semantic program, bus, roots, public-coin session, PCS parameters, ordered 12-field statement,
   and verifier identity. Either lane failing rejects the complete proof.

#### 8.2.2 Corrected timing evidence

The early exact-field/count arithmetic screen reported 19.428197 seconds for relation, fold, and a
simple packed-weight pass. That pass did not construct and reduce the degree-30 packed bridge. It is
therefore a lower-stage arithmetic screen, not the GKR budget.

The corrected B=16 controls ran five complete repetitions:

| Component | Evidence | K128 projection |
| --- | --- | ---: |
| Seven packed bridges per Keccak round | 1.960276 seconds over five repetitions | 9.409325 seconds |
| Thirteen group messages and folds for all seven layers | 3.308730 seconds over five repetitions | 15.881904 seconds |
| GKR group kernel subtotal | derived sum of the two measured controls | 25.291229 seconds |
| Initial main/aux Fp16 NTT allowance | measured production-endpoint KATs | 0.575709 seconds |
| Initial PCS fill and SHA3-512 roots | measured main roots plus conservative auxiliary allowance | 0.140000 seconds |
| Authenticated coin head | measured; overlapped with initial PCS work | 0.658779 seconds |
| Message-dependent coin acceptance | measured, sequential | 0.641352 seconds |
| Coin finish, codec, and independent replay | measured | 0.161591 seconds |
| Rust candidate-geometry PCS query verification | measured | 0.049811 seconds |

The reconciled closed critical path is 26.859692 seconds because coin-head authentication overlaps
the 0.715709-second initial PCS prelude. It leaves 3.140308 seconds for six explicitly open stages:
wire tail, masks, PCS folds/multiproof construction, final semantic-lane synchronization, atomic
composition, and production setup/transfers. The semantic AIR lane must finish no later than the GPU
lane. This is an **attempt gate**, not a complete-proof projection; none of the open stages is
counted as zero.

#### 8.2.3 Packing and layer-bloat decisions

| Candidate | Exact screen | Decision |
| --- | ---: | --- |
| Seven fan-in-two layers | 19.428197-second incomplete arithmetic projection | retain |
| Six layers with a degree-three theta gate | 20.969563-second incomplete arithmetic projection | reject; 1.541366 seconds slower |
| B=8 | 1.183142 seconds for one seven-layer group/bridge control | reject; more group work |
| B=16 | 0.661746 seconds group work plus 0.392055 seconds packed bridge per Keccak round | retain |
| B=32 | 2.410504 seconds for the packed bridge alone | reject |
| B=64 | 9.833333 seconds for the packed bridge alone and 604.757 MB device working set | reject |
| Merged degree-11 theta / degree-3 chi | 23.033731-second incomplete arithmetic projection | reject; higher degree, an invalid earlier characteristic-two shortcut, and slower than the seven-layer arithmetic screen |

The selected seven-layer/B=16 schedule contains no measured removable layer or packing bloat. The
remaining overhead is theorem- or privacy-required: full-Fp16 challenges, 640 queries, the 8,192
random-padding coefficients, independent main/aux random companions, two different-size PCS
instances, SHA3-512 roots, native masks, authenticated dual-PQ coin, and independent verification.

#### 8.2.4--8.2.5 retired resource and attempt boundary

The former BaseFold, 6,241-round, 200 MB host, and 1,800 MB device planning boundary is retired.
It is neither an acceptance gate nor a fallback. Section 8.3 replaces the PCS and transcript; the
2026-07-31 H4 closure supplies the current measurements. The immutable acceptance gates remain at
most 5,000 MB resident memory, strictly below 5,000 MB scratch, no swap, complete K128 below 30
seconds, and complete K512 below 180 seconds. Detailed rejection evidence is centralized in
`REJECTED_ARCHITECTURES.md`.

### 8.3 Construction 8.2 linear-time RS correction (2026-07-29)

Status: **SELECTED NONACTIVATING ATTEMPT ARCHITECTURE; SUPERSEDES SECTION 8.2 WHERE CONFLICTING**.

The seven-layer/B=16 GKR choice in section 8.2 remains correct. Its BaseFold PCS and
6,241-round transcript do not. The current PCS is Construction 8.2 of
Chiesa--Fenzi--Weissenberg, ePrint 2026/391, over random-padded interleaved Reed--Solomon
codewords. EPrint 2025/1828 Block-Accumulate remains an evaluated comparison, not the selected
construction.

The exact K128 PCS boundary is two `2^24`-value GKR source tables. Each table is split into 256
messages of 65,536 Fp16 values. The main RS instance has length 131,072, 2,048 independent random
padding values per message, proximity parameter `5/32`, and 1,600 queries. Nine auxiliary
codewords have length 8,192, 2,048 message values, 1,218 random padding values, proximity parameter
`1/5`, and 1,218 queries. The current soundness ledger is 392.179996538 bits for the main instance,
392.108419573 bits for the auxiliary instance, and 392.108419573 bits after their present
composition. The five-claim, sixteen-coordinate, source/mask, and nine-round quadratic-sumcheck
errors are explicitly included and are 491.830074988 bits or stronger.

Construction 8.2 contributes two row-batching challenges, one source/mask batching challenge, nine
masked-sumcheck rounds, and the base/query rounds. The verified combined public-coin schedule is
6,086 rounds: 6,073 GKR rounds, including the output query, packed bridges, shared-group and wire
reductions, coordinate binding, terminal extension, multi-claim binding, and mask opening, followed
by 13 downstream PCS rounds. The 14-round standalone PCS KAT additionally authenticates the
complete GKR claims boundary before its continuation. The older 5,821/5,822 counts omitted required
GKR challenges and are not valid schedules.

The canonical implementation boundary is:

1. the GKR verifier emits one output and four relay-free input claims; each fixes 24 coordinates,
   one packed value, one shard query, and sixteen component evaluations;
2. the low 16 coordinates select a coefficient within one RS message and the high eight select one
   of 256 interleaved messages on one of the two committed source boundaries;
3. Rust derives five claim powers, sixteen linearized coordinate coefficients, and the exact
   batched target from those claims and two authenticated batching challenges;
4. Construction 8.2 proves the resulting five-by-512 row relation with nine quadratic rounds over
   144 compact states: 80 claim-component source/relation states and 64 committed GKR-mask states;
5. Rust independently verifies canonical multiproofs, the complete answer code, spot checks,
   transcript ordering, dual-PQ public-coin replay, and every target; and
6. the final atomic verifier joins this result to the sealed semantic AIR/bus, exact program and
   parameter identities, ordered 12-field statement, old/new state, and retry-stable attempt.

The v4 stream protocol is fail closed at step 3: Python cannot choose the authoritative target or
row parameters. Claim-value, component, point, coefficient, dimension, zero-challenge, ordinal,
replay, target-scale, Merkle, answer, and spot-check mutations are rejected. CUDA extracts the
five-by-512-by-sixteen component rows from each live commitment tile. The component rows plus the
compact source/relation arrays and the 64 GKR-mask states total 12.058624 MB, and no full source
table is replayed. The executable now consumes the real producer's claims and mask commitment under
the exact same authenticated coordinator. The broader step-6 semantic/state atomic receipt remains
open.

The historical B=16 GKR component sum was 24.7958928 seconds. Segment-32 initial PCS mechanics measured
3.586543 seconds, 191.533 MB host memory, 1,612.185152 MB device memory, and 0.000000 MB scratch.
Their 28.3824358-second sequential sum predates the real 73-word join. It is retained as component
evidence and is not a remaining-time budget or complete-proof projection.

Segment 16 remains a nonselected lower-memory control at 164.966 MB host and 873.986048 MB device
memory; its 6.449925-second initial PCS mechanics cannot meet the sub-30 target alongside the
measured GKR body. Segment 32 is the implemented throughput geometry and has completed the
manifest-bound K128/K512 proofs after clean pre-launch Windows System-log audits.

For this selected bounded architecture, the launch admission floor is
`max(1,000 MB decimal, 2 * latest measured complete-proof peak RSS)` free physical host memory and
3,500 MB decimal free device memory. The current external process-tree peak is 706.523136 MB, so
the dynamic host floor is 1,413.046272 MB. This supersedes the
blanket 8,589.935 MB decimal free-host-RAM floor used by earlier high-residency campaigns. The
historical 200 MB host and 1,800 MB device component-selection targets are retained as dated
evidence, not current acceptance gates. The owner's later resource direction explicitly accepts
the measured low-hundreds-of-MB internal host image and bounded sub-5-GB device residency. The
5,000 MB immutable process/scratch gates, zero swap, zero default scratch, external monitoring,
and deterministic cleanup do not move.

The executable Construction 7.2/8.2 audit demonstrates the required conditioned-view algebra and
perfect random-padded RS query-view hiding for the tested relation at 26.104 MB host peak. It is an
offline simulator/audit gate and is excluded from proof time. The real GKR-to-PCS join, semantic
timing, atomic prototype receipt, and one fresh proof for each profile now pass. Qualification
remains closed until the broader state/composition ledger, H5 ten-run p95 campaign, and H6 pass.

The real all-zero B=16 relay-free GKR KAT now executes every one of the 168 selected DAG layers
without materializing the 8,192 identical group rows. A live ML-DSA-87 plus
SLH-DSA-SHAKE-256f public-coin run independently replayed 6,072 raw GKR rounds and the complete DAG
algebra in 13.484277 seconds at 52.457472 MB sampled host peak and 0.000000 MB device use. This
directly confirms that GKR host residency is tens of decimal MB for the uniform prototype. It does
not yet include native Libra masking or PCS and therefore is not a complete-proof resource result.

The selected native-mask commitment consumes 23,544 of 32,768 coefficients. Its conservative view
rank is 22,705: 7,728 bridge, 14,304 sumcheck, 672 layer, and one aggregate-opening observation.
The 5,808 sumcheck variables comprise 2,520 cubic and 3,288 quadratic message rounds.

No current component may convert the GPU into a trust boundary. SHA3-512 roots and transcript
digests, canonical decoding, public-coin authentication/replay, GKR/PCS target derivation,
multiproofs, answer-code verification, and final acceptance remain authoritative Rust work.

## 9. Mandatory implementation sequence

Current interpretation: H0-H4's executable prototype boundary is complete and independently
verified for one K128 and K512 attempt. The requirement bullets below remain design and
qualification obligations, not current next-step commands. Gate 2E must now bind authoritative
state; H5 then runs the repeated selected-candidate campaign; H6 closes the complete simulator,
security ledger, identities, reproducibility, and proof-candidate qualification. No dated checkpoint
below this section may override that order.

### H0 - freeze the bus and theorem worksheet

- freeze the bus schema, byte/bit bridge, generated circuit descriptor and exact maximum padded
  layer width `w`, module IDs, proof sections, atomic
  transcript order, and exact preliminary error ledger;
- retain the independently scoped 79/79 static source inventory, its 39 `AIR_REQUIRED` dispositions,
  exact phase-separated dynamic measurements for all five post-R36 additions, and fail-closed new-file
  and noncanonical-form attacks. The 24 pre-existing sites exposed by the wider source scope are
  explicitly classified but must not be double-counted over the exact global application schedule;
- produce adversarial equivalence tests between every sealed Wave 1 hash port and the bus;
- freeze the privacy-padded Claim Batch Access Manifest fields that cover hash ordinals, state-page
  dependencies, retry domains, resource bounds, and deterministic conflict edges; the current C0
  census and per-job binding are nonactivating controls only, so H3 must make critical fields
  proof-authenticated, verifier-reconstructible, and PHI-free;
- publish the exact K128 state-call and conflict census before accepting parallelism projections;
- freeze a nonactivating three-plane bake-off descriptor: Shout-like read-only governed tables,
  Twist-like mutable replay/payment memory, and the existing Boolean GKR SHA3 plane. Bind all three
  to the same CBAM, public coin, ordinals, fixed padding, and canonical SHA3-512 root bridge; the
  existing endpoint-multiproof/sorted-memory construction remains the control;
- reject the design if any host-trusted equality, witness-dependent shape, unmasked evaluation, or
  under-256-bit term remains.

### H1 - exact bit-sliced Keccak engine

- build a scalar FIPS 202 reference and `u64`, AVX2/AVX-512, and optional CUDA witness backends;
- compile the six-segment K128 schedule into one deterministic repeated circuit without storing a
  graph node per gate;
- prove byte-for-byte parity for every live/dummy call and measure native execution, circuit depth,
  maximum layer width, state/checkpoint memory, and failure cleanup;
- GPU output is never trusted: the scalar verifier and CPU/GPU differential KATs remain authoritative.

### H2 - Fp16 interactive Boolean GKR

- implement the selected `B=16` repeated-circuit sumcheck over the existing Fp16 scalar core;
- preserve the serial indexed reducer as the differential control and implement a deterministic
  multicore reducer with disjoint public-geometry ranges, private per-worker accumulators, and
  canonical worker-order merging; require identical coefficients and SHA3-512 output at
  1/2/4/8/16 workers and measure wall/CPU time, peak resident memory, and scratch at each point;
- retain that all-Fp16 prover as a differential control and implement a subfield-first candidate
  that keeps full Fp16 challenges while measuring M31/Fp2/Fp4/Fp8/Fp16 promotion schedules;
- add deterministic read/write streaming or bounded checkpoint recomputation and exact allocation,
  I/O, and cleanup telemetry; stream order may not depend on the witness;
- prove transcript/terminal-claim parity or supply the complete tower-GKR theorem adaptation, and
  reject the candidate if native masks force an unaccounted full-Fp16 materialization;
- prove/verify non-private KATs first, but keep them synthetic and nonactivating;
- fail if K128 cannot fit the 5,000 MB peak-resident / 5,000 MB scratch gates
  before zero-knowledge overhead.

H2 implementation evidence (2026-07-25): the indexed multicore reducer matches the serial
polynomial and report at 1/2/4/8/16 workers. At the unqualified 782-permutation K128 model,
five-counted-run native-release medians were 3.257033 seconds at one worker and 0.4439703 seconds at
16 workers, with a 16-worker maximum peak resident set of 82.436096 MB, zero scratch, and one
identical SHA3-512 digest across all 30 runs. This closes the first-round multicore experiment only;
later rounds, masks, PCS, simulator, and complete proof remain open.

An isolated RTX 4060 screen subsequently measured 21.9701 ms median for K128 packed accumulator
construction including zeroing, 46 launches, synchronization, and an 8.454144 MB device-to-host
copy. A complete 4,097-gate CPU/GPU accumulator KAT matched exactly. Sampled incremental GPU memory
was 115.343360 MB. The measured CPU dense-tail controls project 77.72-89.30 ms for a hybrid first round,
but GPU-to-final-polynomial parity has not been implemented or measured. Admit that integration
experiment behind the CPU control; do not select or qualify a GPU backend from this screen.

### H3 - native hiding and shared bus PCS

- implement masked GKR/sumcheck and the Fp16/SHA3-512 hiding bus PCS;
- compose the terminal GKR input/output claims with the exact same bus commitment used by the AIR;
- finish the simulator and leakage/abort/retry theorem, fixed grammar, mutation tests, and independent
  verifier before any throughput claim.
- evaluate VEIL only as an isolated alternative wrapper for the multilinear/GKR plane. It receives
  no selection credit until its exact Fp16, authenticated-interactive-public-coin, cross-module,
  abort/retry, SHA3-512, and 256-bit simulator/security obligations pass; the current masks remain the
  control.

### H4 - semantic AIR integration

- remove SHA3 internal round/absorb/digest tables from the release PCS manifest while preserving
  them as differential references;
- bind every application port to the bus, run full Wave 1 equivalence/attack tests, and verify that
  semantic rows, ABI, sidecar, state roots, and decision-class shape are unchanged;
- generate one atomic synthetic proof containing semantic AIR, bus, and hash-coprocessor sections.

### H5 - K128 convergence and maximization

- generate and independently verify complete K128 and K512 proofs on the reference laptop;
- maintain a throughput-only K1024/K2048 cost screen after the K128/K512 workload anchors; label
  extrapolated counts unqualified and never substitute a larger-batch result for either release
  qualification profile;
- record wall/CPU/GPU time, peak RSS/VRAM, scratch, reads/writes, proof bytes, verifier cost,
  challenge latency, retries, cleanup, and steady-state pipelined claims/second;
- pass the frozen p95 latency gates: K128 with 100 live claims below 30 seconds and K512 with 500
  live claims below 180 seconds, measured input-to-independent-verification over ten unique batches
  after one uncounted warm-up;
- add deterministic SIMD/CUDA and multi-session lanes only after scalar parity;
- compare every safe implementation point and select the highest-throughput point that passes all
  security, privacy, auditability, modularity, and resource gates.

### H6 - suite qualification

- substitute exact dimensions into the complete 256-bit security/encryption ledger and simulator
  theorem;
- freeze source/toolchain/module/proof grammar/verifier identities and cross-language KATs;
- keep `proofSuiteId=null` until all current Wave 2 gates and the downstream authoritative
  verifier/state/custody gates close. Wave 2 closure still does not authorize production.

Every H0-H6 implementation and qualification item is internal engineering. The later independent
audit reviews the finished candidate; it is not needed to invent or finish this construction.

## 10. Alternatives and stop conditions

| Candidate | Status |
| --- | --- |
| Current 9 TB monolithic / 951 GB streamed / 554 GB de-duplicated wide SHA3 STARK | Retired as release architectures; negative baselines only |
| Shared-bus Boolean GKR with all-Fp16 control and subfield-first streamed candidate | Primary implementation path; challenges and final soundness stay Fp16; unselected until H0-H6 pass |
| WHIR/STIR/other transparent outer PCS | Conditional post-K128 bake-off only; must adopt the complete Blind Ledger field/hash/hiding/public-coin/error profile and beat the primary path under identical gates |
| Shout-like read-only plus Twist-like read/write memory checking | Admitted H0/2B bake-off only; must beat the optimized endpoint-multiproof/sorted-memory control and preserve the canonical SHA3-512 root bridge |
| Persistent memory / transparent dictionary / projection RAM / Two-Shuffles relation | Mandatory Wave 2 gate 2E state-replacement bake-off under `docs/BL_PQ512_COMMITTED_SPARSE_STATE_PLAN.md`; published concrete backends are not adopted |
| Jindo / Grand Danois / Hachi / RoKoko-style commitment | Isolated gate 2E PCS candidates; each requires its own strict-PQ, hiding, field, grammar, migration, verifier, and laptop evidence |
| VEIL-style ZK wrapper | Admitted H3 research candidate only; not qualified for the current interactive Fp16 composition or simulator ledger |
| Neo/SuperNeo lattice folding | Quarantined post-K128 aggregation research; separate Module-SIS/Ajtai assumptions and parameters, never a silent base-proof replacement |
| Space-efficient Ligero/Ligetron-style hash proof | PQ/hash-based memory-safety fallback research if the GKR simulator/bridge fails; expected throughput/proof-size penalty must be measured |
| Current Binius64/Iron Spartan | Benchmark/control only; field, security, transcript, hash, and/or ZK profile fail the frozen requirements |
| Byte-lookup or narrower-row SHA3 AIR | Differential and small-profile fallback research only; cannot restore the retired hundreds-of-GB K128 design |
| Poseidon/Blake/truncated hash, ECC/KZG/IPA, trusted setup, outside prover, weaker field/query/hiding | Rejected |

The primary path stops cleanly if the exact bridge cannot be proven zero knowledge, any theorem
term misses 256 bits, atomic verification cannot be made fail closed, or measured K128 exceeds a
resource gate after bounded recomputation, or either frozen latency target is missed after all safe
optimization lanes are exhausted. It does not silently fall back to 550 GB, redefine the timed
boundary, or weaken a constraint to pass.

## 11. Primary sources

- [NIST FIPS 202, SHA-3 and Keccak-f[1600]](https://csrc.nist.gov/pubs/fips/202/final)
- [Almost optimal succinct arguments for Boolean circuit on RAM, IACR 2024/839](https://eprint.iacr.org/2024/839)
- [GKR for Boolean Circuits with Sub-linear RAM Operations, IACR 2025/717](https://eprint.iacr.org/2025/717)
- [The Sum-Check Protocol over Fields of Small Characteristic, IACR 2024/1046](https://eprint.iacr.org/2024/1046)
- [Efficient SNARKs for Boolean Circuits via Sumcheck over Tower Fields, IACR 2025/594](https://eprint.iacr.org/2025/594)
- [Scribe: Low-memory SNARKs via Read-Write Streaming, USENIX Security 2026](https://www.usenix.org/conference/usenixsecurity26/presentation/baweja)
- [Hobbit: Space-Efficient zkSNARK with Optimal Prover Time, USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/pappas)
- [Sparrow: Space-Efficient zkSNARK for Data-Parallel Circuits, IACR 2024/1631](https://eprint.iacr.org/2024/1631)
- [Twist and Shout, IACR 2025/105](https://eprint.iacr.org/2025/105)
- [VEIL, IACR 2026/683](https://eprint.iacr.org/2026/683)
- [Neo and SuperNeo, IACR 2026/242](https://eprint.iacr.org/2026/242)
- [Hachi, IACR 2026/156](https://eprint.iacr.org/2026/156)
- [Libra: Succinct Zero-Knowledge Proofs with Optimal Prover Computation, IACR 2019/317](https://eprint.iacr.org/2019/317)
- [Black-box time/space-efficient public-coin arguments from symmetric-key primitives, IACR 2022/1612](https://eprint.iacr.org/2022/1612)
- [Ligetron, IEEE Symposium on Security and Privacy 2024](https://doi.org/10.1109/SP54263.2024.00086)
- [Binius64 source at the locally measured revision](https://github.com/binius-zk/binius64/tree/3d71de3a09b35a6706eddf8b96a06024358f519b)

These sources establish feasibility, known techniques, and known traps. None substitutes for the
Blind Ledger theorem, implementation, exact K128 proof, internal qualification, or final independent
audit.

## 2026-07-29 H3 implementation checkpoint

The real native-masked GKR producer and downstream PCS now share one exact 6,086-round
authenticated dual-PQ schedule. The aggregate 32,768-coefficient GKR mask is committed as 64
dimension-512 RS codewords. Nine sumcheck-mask words plus those 64 GKR words form the 73-word
auxiliary answer. Rust distinguishes the nine univariate mask evaluations from the 64 multilinear
mask-table evaluations, derives the latter's relation terminals from authenticated GKR weights,
binds their SHA3-512 digest before the base-mask challenge, and independently verifies the answer
target and openings. A full same-chain mutation session rejects a forged terminal digest before
releasing that challenge.

This join uses 12.058624 MB compact row state, 33.554432 MB GKR-mask codewords, and 38.273024 MB
complete auxiliary codewords. The host verifier KAT peaks at 77.070 MB. The failed first complete
launch reached 317.542400 MB process-tree RSS and 855.638016 MB GPU use before CUDA error 700 and
`nvlddmkm` Event 153. The corrected source removes 510 duplicate fixed-message evaluations by
extracting one live commitment tile per boundary; it statically compiles but is unmeasured because
the production CUDA gate requires a clean driver reset. H3 and H5 remain open until the corrected
complete proof independently verifies below 30 seconds and the remaining simulator/qualification
gates close.

## 2026-07-30 H3 prototype closure

The corrected real-GKR/PCS path completed a fresh segment-32 proof through independent verification
in 28.943126 seconds externally after the `2026-07-29 23:17:48 -06:00` reboot. A later System-log
audit invalidated that reboot as a clean driver-integrity boundary, so this historical run receives
no reset or qualification credit; the accepted 2026-07-31 H4 attempts supersede it. The proof
process measured 28.177317 seconds. Its dominant authenticated GKR head was
12.724326 seconds, compact PCS row sumcheck was 3.348778 seconds, and independent opening lane was
2.740147 seconds. The complete PCS mechanics clock was 20.745883 seconds.

The run measured 311.537664 MB external process-tree RSS, 1,058.013184 MB sampled GPU use,
0.000000 MB scratch, no pagefile growth, and zero post-launch driver events. Its row-state split is
7.864320 MB for the five-claim component/source/relation plane plus 4.194304 MB for the GKR-mask
source/relation plane, 12.058624 MB simultaneously live. The GKR mask remains committed as
2.097152 MB of coefficients and 33.554432 MB of RS codewords; no duplicate full-source replay is
present.

This closes the smallest correct H3 real producer/native-mask/PCS/coordinator prototype. It does not
close H4 semantic-AIR/bus composition, the 200 MB historical engineering target, H5's
warm-up-plus-ten p95 campaign, H6 suite qualification, or activation. `proofSuiteId=null`,
`complete_pcs_qualification=false`, and `complete_proof_qualification=false` remain fail-closed.

## 2026-07-30 H3 throughput refinement

The theorem-neutral hot-path refinement sends three source-quadratic coefficients per compact-row
round and has Rust reconstruct the same complete masked polynomial from authenticated mask state.
It also reduces five existing boundary rows to 80 component evaluations on the untrusted GPU before
copyout, retains GKR weights as canonical packed words, and frees 39.168256 MB of dead device
buffers at their last use. Every round, mask, canonical message, public-coin challenge, mutation
gate, root, answer target, and independent verifier remains present.

After a scoped NVIDIA reset and a cold driver-JIT warm-up, a fresh segment-32 proof independently
verified in 24.749154 seconds externally and 24.392408 seconds in-process. PCS mechanics measured
17.741531 seconds; the authenticated coin head was 12.790189 seconds, compact row sumcheck was
0.468827 seconds, and openings were 2.846039 seconds.

External process-tree RSS was 263.983104 MB. Sampled total GPU use was 1,011.875840 MB and tracked
proof allocations were 917.570560 MB. Scratch was 0.000000 MB, pagefile use did not grow, and no
post-launch driver event occurred. The H3 prototype remains complete; H4, H5, H6, qualification,
and activation remain open.

## 2026-07-30 H4 nonuniform B16 source correction

The semantic coprocessor boundary is now explicit and byte-canonical. A snapshot authenticates the
exact ordered SHA3 calls and ports; Rust recomputes every digest and rejects descriptor, capacity,
commitment, length, and trailing-byte mutations. The B16 source omits 448 provably fixed-zero
padding wires and stores the 1,600 live wires wire-major. An input/output pair is 52.428800 MB per
131,072-permutation shard; complete files are 52.429015 MB for K128 and 209.715415 MB for K512.

The prior 3,304.930 MB B16 group allocation was implementation bloat, not theorem state. The exact
replacement computes the first cubic group message from compact patterns at the authenticated
degree-15 packed evaluation and folds directly to the half table. Its independent CPU/GPU message
and fold KAT passes. The corrected exact-geometry control uses 1,698.495 MB device state and
229.822 MB host peak and measures 0.605268 seconds for seven layers per Keccak round. The exact
degree-45 bridge remains 69.042880 MB and measured 0.496789 seconds per round. H4 still requires
the real producer/masks/PCS/coordinator/verifier join; neither component control receives proof
qualification credit.

K512 now has the same exact source boundary rather than a projection. Its selected semantic fixture
passed, Rust decoded 165,762 calls, the canonical four-shard file is 209.715415 MB, and an
independent 16-worker executor verified all four 24-round/seven-layer boundaries in 4.023582
seconds. The source-file SHA3-512 is
`39a529ab6c337d7753d32b8467c66267bf185e2d1490568f4ac21a0d658778d9aa811eb77d7393a6bd8ea098f49b96d351a7bf59237e0e22bed90841f8992c04`.

The masked GKR implementation now separates the untrusted group-axis accelerator from the trusted
Rust transcript with one purpose-built interface. The accelerator may return only the next raw
cubic, accept an authenticated challenge, and finally return the two group-folded sources. Rust
checks every endpoint and retains all masks, wire rounds, terminal extensions, and acceptance.
Exact parity with the complete nonuniform table and a forged-round rejection pass. The packed
bridge separately checks that its degree-45 message sums at the sixteen public nodes to the incoming
combined claim. These are required generic-verifier boundaries, not proof qualification.

## 2026-07-30 H4 K128 joined-producer evidence

The accelerator boundary is now exercised by the real 168-layer producer rather than only the
component controls. One K128 run completed 6,073 GKR rounds, four relay-free input claims, 508
native mask constraints, the Construction 8.2 PCS, and the independent verifier under one
authenticated 6,086-round schedule. The statement binding commits the exact `BLHBB101` file and
selected GKR plan; a binding mutation fails closed.

The accepted segment-32 run completed in 120.670536 seconds with all verification/mutation flags
true. Tracked GPU allocation was 969.999360 MB, monitored process-tree RSS was 536.928256 MB, and
scratch was 0.000000 MB. Compact row evaluation reads the 52.428800 MB packed shard directly and
retains both semantic boundaries through the ninth word fold; it does not reconstruct a full Fp16
source. H4 remains open because the 100.240849-second authenticated GKR head violates the K128
latency gate and the four-shard K512 coordinator has not yet been run.

## 2026-07-30 H4 real-wire and K512 atomicity decision

The nonuniform accelerator now supplies raw wire quadratics as well as raw group cubics. Rust
retains native masks, adaptive challenges, source copies, terminal evaluation, transcript replay,
and independent verification. The resulting exact K128 proof passed every functional and mutation
gate in 53.547306 seconds. The real GKR prelude consumed 42.017007 seconds; PCS mechanics consumed
4.692209 seconds. Decimal peaks were 295.625 MB for the proof phase, 253.977 MB for the parent
lifetime, 76.435 MB for the native verifier, 969.999360 MB tracked on the device, and 0.000000 MB
scratch. H4 therefore remains latency-open.

The first K512 coordinator is four ordered, complete shard proofs executed sequentially on the
single GPU and accepted atomically. Parallel four-image execution is resource bloat, while reusing
one challenge stream across nonlinear shards without an explicit batching theorem is unsound. The
atomic receipt binds the canonical 209.715415 MB file digest, shard order, every
statement/proof/bundle, parameters, verifier identity, retry identity, and application statement
before any state transition can be accepted.

zkDeepFold remains a rejected alternative, not an unresolved dependency. Construction 8.2 of
ePrint 2026/391 is selected. The historical `mu=21`, `s=473` inequality correctly satisfies the
zkDeepFold simulator's auxiliary-polynomial interpolation condition for that retired control. It
cannot substitute for the selected construction's hiding/composition mapping, exact error ledger,
implementation, or complete measurement, and it does not justify the conjecture-dependent
lower-query list-decoding lane.

The sequential K512 coordinator is now measured rather than projected. All four complete shard
proofs independently verified and the outer receipt bound their order and common application
statement. It used 591.249408 MB peak process-tree RSS, 2,182.086656 MB sampled total GPU use,
0.000000 MB scratch, no pagefile growth, and no driver event. Its 222.600073-second coordinator
time fails the 180-second gate. The atomic construction remains selected; the shared GKR producer
must become faster before either K128 or K512 can qualify.

### Historical manifest-bound atomic semantic evidence

One fail-closed coordinator now handles both supported profiles: one canonical K128 shard or four
ordered K512 shards executed sequentially on one GPU. Its parent/receipt bind the semantic file
and plan, caller statement, shard order and proof bundles, plus an execution manifest over the
Python/prototype/worker dependency closure, seven native verifiers, and precompiled PTX.

Fresh K128/K512 process times are 54.955357/220.583627 seconds. K512 shard times are 55.221861,
54.467592, 53.685071, and 55.734525 seconds. K512 externally sampled 2,182.086656 MB total GPU and
547.127296 MB process-tree RSS; K128 used 532.242432 MB process-tree RSS and reported
969.999360 MB tracked device allocation. Both had zero pagefile growth, empty stderr, and zero
driver events. Functional attachment is closed; 30/180-second throughput qualification is open.

All pre-mask and incomplete verifier formats are removed from the acceptance surface. A dedicated
KAT rejects 10/10 retired cases, while current 20/36-tree and V4/V2 paths pass. The 48-layer
Windows context boundary is mandatory: a 56-layer attempt failed at layer 54 with CUDA error 700
and Event 153 record 229592 and was reverted.

## 2026-07-31 H4 atomic prototype and latency closure

The real one-output/four-input GKR producer and atomic coordinator now meet both prototype latency
limits under execution manifest
`51c23310274ccf7c4d7f9abe4ae7eba43266b335bd377b21cbf92409729b91e2a40a39787a157baa080c9d0516c7815af404a4d58d9e76747f652f57cd017ed6`.
K128 independently verified in 29.974129 seconds. K512 independently verified four ordered shards
in 31.567686, 30.679149, 31.019240, and 25.998881 seconds and accepted their atomic receipt in
120.460733 seconds.

The hot path now has only purpose-bearing residency:

- canonical layer topology is prevalidated and transported in one exact batch;
- the worker uploads the immutable 24-round/seven-layer geometry once as 3.225600 MB of packed
  device arrays;
- same-source aliasing is derived from authenticated topology instead of retransmitting duplicate
  source words;
- one future 48-layer worker is prepared after the current worker accepts its plan; zero standby
  exposes context-start latency, while additional standbys add no theorem or measured throughput;
- Python uses `-S` because the manifest-bound processes use only the standard library and pinned
  local modules; and
- the semantic file is hashed and the selected shard captured in one pass.

K128/K512 internal host peaks were 288.412/296.255 MB; external process-tree peaks were
681.607168/706.523136 MB. Per-proof tracked device state was 969.999360 MB, while the K512 external
sampler observed 2,770.337792 MB total GPU residency across active/standby contexts. Both accepted
attempts used 0.000000 MB scratch and had no pagefile growth. These figures are decimal MB.

The H4 functional and one-run latency prototype is closed. Gate 2E must now select and bind the
authenticated state plane. H5 then requires one uncounted warm-up plus ten unique K128 and K512
batches, p95 measurement, and the complete recorded resource campaign. H6 and downstream
activation remain open. `proofSuiteId=null`,
`complete_pcs_qualification=false`, and `complete_proof_qualification=false` remain mandatory.
