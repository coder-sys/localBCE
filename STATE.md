# Blind Ledger state

Updated: 2026-08-02

## Current execution boundary

The authoritative clean transfer checkpoint is `WAVE2_HANDOFF_2026-07-26.md`; it is recovery
history, not the current PCS choice. No proof process remains running. The current nonactivating
blueprint is section 8.3 of `docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`: the exact
seven-layer/B=16 relay-free GKR plus Construction 8.2 random-padded interleaved Reed--Solomon PCS.
The owner's K128 target is below 30 seconds for the complete fresh proof through independent
verification, not only GKR.

The real uniform-zero-trace B=16 GKR producer, dual-PQ coordinator, and independent replay measured
13.484277 seconds at 52.457472 MB host and 0.000000 MB device use. Segment-32 initial PCS mechanics measured
3.586543 seconds, 191.533 MB host memory, 1,612.185152 MB device memory, and 0.000000 MB scratch.
Their 17.070820-second component sum leaves 12.929180 seconds below the target, but native GKR
masking, PCS attachment, semantic synchronization, setup/transfer, atomic join, parsing, and final
independent verification remain unmeasured as one proof. This is component evidence, not a
complete-proof projection or qualification.

The main RS instance has length 131,072, message length 65,536, random-padding length 2,048,
proximity `5/32`, and 1,600 queries. Nine auxiliary instances have length 8,192, message length
2,048, random-padding length 1,218, proximity `1/5`, and 1,218 queries. The current composed PCS
ledger is 392.108419573 bits. The corrected five-claim boundary uses one output and four
relay-free input claims. The corrected shared authenticated-public-coin schedule is 6,086 rounds;
the real dual-PQ coordinator executed and independently replayed all 6,086 descriptors, while the
complete producer still has not occupied the mask-batch and downstream PCS descriptors.

The remaining critical path is exact: replace the deterministic fixture claims with the actual
B=16 GKR producer in the same authenticated coordinator, bind the same committed RS source, run
the bounded semantic AIR concurrently, form one retry-stable atomic state/proof receipt, close the
complete composition/simulator/leakage ledger, and then run one fresh proof plus the warm-up and
ten unique K128 qualification proofs. The Windows GPU driver must be reset before that production
run. `proofSuiteId` remains null, activation remains false, and real PHI/payments remain forbidden.

Historical transfer-time verification (superseded by the current 2026-07-29 section below) was:
`cargo test --lib --all-features` passed 229/229 tests in 1,069.89 seconds;
`cargo clippy --all-targets --all-features -- -D warnings`,
`cargo clippy --lib --no-default-features -- -D warnings`, and
`cargo fmt --all -- --check` exited zero. Default-feature `cargo test --lib --no-run` also compiled
without warnings. A preceding feature-enabled run outlived its command wrapper and later returned
exit code 101 without recoverable test output; it receives no pass credit. The identical diagnostic
rerun with uncaptured output passed all 229 tests, including the previously load-sensitive worker
classification test.

The last successful strict K128-shaped GKR control used 782 permutations, 216 layers, 4,096 padded
width, and 8,785 authenticated rounds. It completed in 35.1399522 seconds, independently
reconstructed every public mask constraint and replayed the public coin, matched CPU/GPU packed
polynomials and GKR/PCS openings, and explicitly reported `complete_pcs_attached=false` and
`complete_proof_qualification=false`. The GPU FRI arithmetic control at `2^25` values measured
0.7698361 seconds for bit reversal plus NTT, 0.0293228 seconds for 22 folds, and 0.2328701 seconds
for a bounded 2 GiB device-to-host stream; those are component measurements only.

The current GPU PCS integration remains implemented in `src/mlpcs_gpu_worker.rs`,
`cuda/cuda_mlpcs_fold_worker.py`, and the multilinear PCS modules. Rust remains authoritative for
SHA3-512 roots, canonical decoding, multiproofs, transcript construction, and verification. The
corrected worker source pin is
`4e83333596b004503a53bb8a061d9bb7f6687a078fe3e1774ea80179a2063c618ef600d57c16d959b43407fc7da8295d78907e37bd4be4aa619ef377b4a255a7`.
The old handoff's 706-item resume sequence is retained as historical integration evidence but is
superseded as the immediate action by the owner's newer full-proof sub-30-second direction and the
ordered implementation gates above. No component control may claim complete-proof qualification.

Current Wave 1 (historically called Wave 1A) is sealed as a **synthetic, nonactivating executable
relation**. It now includes exact
claim-source arrays and dense SHA3 commitments, oracle and policy execution/audit roots, ruleset
commitment, real ML-DSA-87 plus SLH-DSA-SHAKE-256f claim-truth authority, full-width A12 attempt and
cover nullifiers, a replay-registry lifetime pepper commitment, a hidden master-salt reuse key,
depth-64 insert-only replay, three authenticated economic lanes, a chained operation log,
authoritative master commitments, and the unchanged 12-field compatibility ABI projected from
512-bit authorities.

The global SHA3 relation uses one canonical six-segment call schedule rather than cloning all
Keccak rows into a second Python trace. K128 contains exactly 46,858 calls at offsets/counts
`(0,516)`, `(516,129)`, `(645,1)`, `(646,9360)`, `(10006,36848)`, and `(46854,4)`; Python and
`no_std` Rust pin commitment
`2d2792d30f838618190a95817f44204308e2a0e7f460b71e48da779ccd2472cb11ae3342a2df9a52f01561c80aaa3d3fafa2d77271fd9eb4f6ee6270006e3aa6`.
Each segment retains its independently evaluated physical SHA3 AIR as an executable differential
specification. The Wave 2 release prover must consume the same schedule through one canonical
committed hash-call bus; it no longer commits those six SHA3 internal tables through the generic
wide-column semantic-AIR PCS.

Wave 1 closure evidence is 53/53 selected trust-critical Python tests after the focused payment
rerun, a 55,776-message global boundary evaluation plus replay-root attack, 78/78 Rust tests,
offline `cargo fmt`, and Clippy with warnings denied. The heaviest payment relation evaluates
112,485,087 identities and 220,993,014 lookup messages at degree three. This is not a proof,
durable production state, production verifier, proof-suite selection, or activation claim.
`proofSuiteId=null`, real PHI/payments remain forbidden, and Wave 2 is now the active boundary.

The current certified hidden-state transition is still an unqualified architecture model. Its K128
input of 782 Keccak permutations was run through the unchanged `B=8` packed Boolean first-round
kernel at the generated 216-layer, 4,096-padded-width geometry: 45,158,400 gates took a five-run
median of 4.8015192 seconds (4.3895117-5.0110385), peak resident memory was 12,079,104 bytes, scratch
was zero, and every run produced the same SHA3-512 digest. CPU/wall ratio 0.9767 and source
inspection establish that this control is single-threaded. This is phase-one evidence only.
K128/K512 remain the qualification profiles; the 256-bit security/encryption, privacy, transcript,
5,000,000,000-byte peak-RAM, scratch, and complete-proof gates do not move.
Workspace grounding on 2026-07-26 found no exact hidden-state schema, transition manifest, hash-call
schedule, or derivation artifact for the 782/894 constants. They occur as hard-coded unqualified
inputs in `relation_cost_screen.py`; the affine batch screen only interpolates between them. No
semantic producer may emit the new canonical GKR input from those constants, and they receive zero
qualification credit until the complete relation preserves the sealed trust boundaries and derives
every call and permutation.

The selected transparent multilinear-PCS implementation now has a fixed fail-closed prelude,
different-size three-claim batch sumcheck, exact hidden/auxiliary polynomial algebra, canonical
verifier-derived query multiproofs, strict fixed-length codecs, and an independent algebra
verifier. The auxiliary 18-variable polynomial is lifted through four ignored prefix variables
with an exact `2^-4` normalization so the 22-variable batch claim retains the simulator's
`r^2 c_aux` term. The prelude is 4,747 bytes; the fold/query segment is 17,519,307 bytes; and the
combined internal PCS proof is exactly 17,524,065 bytes. A full-shape completed-challenge control
measured 4.1560122 seconds, 827,203,584 peak working-set bytes, and zero scratch with the same
SHA3-512 digest as the scalar implementation. The focused parallel suite passes 26/26, including
above-threshold scalar/threaded parity for equality generation, dot products, round polynomials,
and folds. This is executable algebra and fixed-grammar evidence only: production entropy,
authenticated public-coin receipts, the complete simulator/composition theorem, a full proof
producer, and complete K128/K512 independent verification remain open.

The full production-geometry PCS control now constructs every committed layer and canonical
opening, emits the exact fixed proof, decodes it, and independently verifies it. The earlier
18.1039767-second single-opening control was superseded after integration review found that packed
GKR ends in two claims plus a degree-7 shard query. The corrected PCS right table now binds both
terminal values through one authenticated mix and inserts the exact eight Lagrange shard weights
between the low wire and high group bits. Its monitored run measured 23.8805969 seconds for
production plus internal verification, 0.2366557 seconds for independent decoded verification,
29.4130358 seconds total wall, 5,062,144,000 peak working-set bytes, and 2,281,701,376 bounded input
scratch bytes. The fixed 17,524,065 proof bytes had SHA3-512
`25bb3d9c9b7b47a6ad0de599fdd7a2f53d696605085bd194ec09be455e6e9f1a6ea67594c9f92271a7ffd6e81a683fffd4c21104e0859c6b1ceac639d2556ef3`.
The focused PCS suite passes 27/27 and the exact GKR-to-PCS bridge passes 1/1. This is still a
completed-challenge synthetic hiding control, not production entropy, authenticated interaction,
simulator/theorem qualification, or a coherent complete GKR-plus-PCS K128/K512 proof.

The earlier 30-33-second 216-session GKR reports used independent per-layer fixtures and are not
coherent-chain evidence. The corrected harness evaluates all 216 boundaries, carries two terminal
claims backward through the complete circuit, verifies every masked layer in Rust, checks exact
CPU/GPU packed-polynomial parity, and binds its two final openings to the raw `2^21` Boolean input.
It measured 42.8253168 seconds for K128/782 and 44.1804650 seconds for K512/894; combined host peaks
were 3,241,021,440 and 3,240,488,960 bytes. The exact resulting PCS inputs then produced
independently verified 17,524,065-byte proofs in 20.7792086 plus 0.2230094 seconds for K128 and
20.7974853 plus 0.2428490 seconds for K512. Core scratch was 2,818,577,696 bytes. The joined harness
now requires the existing external 64-byte secret and 64-byte session boundary for domain-separated
GKR and PCS masks and fails closed on wrong-length input. Its challenges and initial Keccak states
remain deterministic synthetic controls: this is actual coherent GKR-to-PCS component evidence,
not authenticated public coin, the certified hidden-state transition, an atomic complete proof,
simulator qualification, or K128/K512 qualification.

The owner subsequently set the release resource gate to no more than 5,000,000,000 peak resident
bytes, strictly below 5,000,000,000 scratch bytes, and no swap. The 3,241,021,440- and
3,240,488,960-byte coherent-chain runs retain their algebra, masking, parity, and opening evidence
but are not resource-qualified. The 5,062,144,000-byte PCS control and later
7,456,407,552-byte predecessor remain historical correctness/performance evidence only and are
rejected release realizations under the current RAM gate.

Binding review then found that the measured initial output claim covered the entire final Keccak
state and was computed inside the prover harness rather than authenticated by the semantic digest
bus. The measured run remains coherent internal GKR algebra evidence, not a hash-bus proof. The
replacement code requires a canonical external Keccak-state input, rejects nonzero inactive lanes
and padding wires, and fixes output wire coordinates 9 and 10 to zero so the claim covers exactly
the first 512 SHA3-512 digest bits. Two focused boundary tests pass. Fresh K128/K512 runs and exact
semantic message/digest-bus commitment openings remain required.

That bounded block is now implemented and measured. The indexed reducer partitions public gate
indices, uses private worker accumulators, merges in canonical worker order, and matches the serial
polynomial/report at 1/2/4/8/16 workers. At K128's 45,158,400 packed gates, five-counted-run native
medians were 3.257033 seconds at one worker and 0.4439703 seconds at 16 workers (7.336x faster);
maximum 16-worker peak resident memory was 82,436,096 bytes and scratch was zero. The 16-worker
K512 anchor median was 0.4900199 seconds. K1024 and K2048 use the explicitly unqualified two-point
affine permutation model and measured 0.5557694 and 0.6907252 seconds for their resulting packed
gate loads. These are first-round kernel results, not complete-proof or architecture qualification.

An isolated RTX 4060 accumulator screen also passed a complete 4,097-gate CPU/GPU accumulator KAT.
At K128's 45,158,400 packed gates it measured 21.9701 ms median across five counted runs, including
accumulator zeroing, 46 launches, synchronization, and an 8,454,144-byte device-to-host copy.
Sampled incremental GPU memory was 110 MiB. Combining this with measured dense CPU-tail controls
projects 77.72-89.30 ms for hybrid phase one, but full K128/K512 accumulator import,
final-polynomial parity, proof-byte parity, and complete-proof timing remain open. NVRTC was
temporary out-of-tree tooling and is not an adopted dependency.

Wave 2 is a strict-PQ proof **and throughput-recovery** wave, not merely “finish the existing
prover.” The v1 regression kernel proof was 28,643,096 bytes at 945 queries. The authoritative
`BLPQPRF2` encoder/decoder and independent verifier now replace its per-query FRI paths with one
canonical multiproof per FRI layer while reconstructing every coordinate from authenticated
verifier inputs. V2 also emits repeated cross-domain sibling nodes and opened rows only once per
committed tree coordinate in canonical order, then reconstructs every proof before verification.
The latest real dual-PQ run produced and independently verified a 6,755,933-byte v2 proof:
21,887,163 bytes smaller (76.41%)
than v1, with all 945 query draws, opening values, and multiplicities preserved. Compact size varies
slightly with the authenticated random query set; v1 remains a
historical comparison grammar, not a fallback. This is regression-kernel evidence, not K128 timing
or full Gate 2B closure.

The complete K128 resource failure is separate. The rejected monolithic path has a
9,034,606,313,472-byte live-memory lower bound; its disk-streaming model requires
950,757,738,236 bytes of scratch, and simple de-duplication still projects 554,259,695,356 bytes.
All three are retired release architectures, not fallbacks.

Wave 2 now implements a shared-bus Boolean GKR hash coprocessor. The sealed M31 semantic AIR proves
application/state/money/ABI semantics and binds every hash port to one committed bus; an Fp16
data-parallel Boolean circuit proves all 113,730 K128 Keccak-f[1600] permutations. Exact storage for
25 bit-packed state boundaries is 568,650,000 bytes. The `w=1,600` raw-state-layer baseline is
3,591,988,768 bytes, while `w=2,048` is 4,407,205,408 bytes; both raw baselines now exceed the
release RAM limit before generated padded width, masking, commitment, and allocator overhead. The
hard reference-laptop gates are no more than 5,000,000,000 peak resident bytes,
strictly below 5,000,000,000 scratch bytes, and no swap dependency. These are models and gates, not a
completed prover measurement. Native masking, complete simulator, exact 256-bit security/encryption
ledger,
atomic shared-bus verification, and full K128 proving remain open. The authoritative contracts are
`docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md` and
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`.

The current 2A control now exposes an exact K128 bus/resource report from the sealed schedule and
C0 census: 46,858 calls, 113,730 permutations, 7,996,042 preimage bytes, 10,994,954
message-plus-digest bytes, 568,650,000 bit-packed round-boundary bytes, and 4,367,232,000 chi AND
gates. It is explicitly `DERIVED_MODEL` evidence for the retired direct-SHA3 architecture; it does
not measure a generated backend, RSS, scratch, latency, I/O, or qualify a release. C0 also now has
a canonical fixed census and a separate nonactivating per-job binding to the masked private access
body plus batch/sidecar/state/attempt/retry/sequence identities. Canonical decoders are tested, but
native-hiding proof authentication remains a Wave 2 requirement.

The synthetic benchmark record is internally validated only. Its self-hashes cannot attest to a
worker execution, immutable source bundle, or OS resource counters, so qualification now fails
closed until an externally captured provenance bundle is implemented. Gate 2A therefore remains
open: generated-backend measurement, proof-native CBAM binding, and real provenance/telemetry are
still required.

Current focused verification for this boundary is 104/104 Python tests across the SHA3 inventory,
schedule/capacity, benchmark-fixture, resource-report, CBAM, and attack slices; the Rust canonical
multiproof suite is 6/6 and `cargo fmt --check` passes. These checks do not close Gate 2A or 2B.
The complete Rust library suite now passes 121/121, including the FRI-layer codec, v1 migration
bridge, exact work-domain coefficient-tail gate, batched disk openings, and forced Merkle-level
recomputation.

Gate 2B now has the authoritative v2 proof grammar, strict global-FRI wire format, and independent
v2 verifier in both monolithic and bounded-streaming workers. The encoded form carries no
prover-supplied query or FRI coordinates; it preserves ordered query multiplicities, authenticates
each global layer frontier once, rejects trailing bytes, and verifies the decoded bytes rather than
the prover's original in-memory object. Focused convergence evidence is 16/16 report/attack/real
proof checks plus the bounded-streaming real-proof check. FRI and cross-domain sibling/value
authentication are now globally deduplicated. Gate 2B remains open for fused-slab construction,
measured recompute-versus-retain resource/latency evidence, complete v1/v2 mutation coverage, and
the required endpoint-multiproof versus three-plane memory-checking bake-off.

The production-shaped workers no longer serialize the full v1 grammar for telemetry. The
28,643,096-byte v1 baseline remains frozen regression evidence, while live work emits only v2,
drops the original proof before decoding the wire proof, and compacts FRI layers through borrowed
slices rather than cloning every per-query Merkle path. This removes an avoidable 28.6 MB legacy
wire allocation plus a second path-heavy proof clone from each regression-kernel execution; no
latency credit is claimed until resource telemetry measures the change.

The bounded-streaming main, interaction, and composition commitments now use one canonical column
layout instead of permanent or construction-only row copies. SHA3-512 tree construction reads
bounded row slabs directly across those column files; no full-domain `.rows` transpose is created.
Queried row payloads are reconstructed from the same columns through persistent bounded file
handles. The in-memory and direct-column roots/openings are byte-identical in the focused
cross-language test. The derived resource preflight counts each canonical oracle layout once
rather than twice. This structurally advances Track C, but exact scratch high-water and latency
credit still require the external resource telemetry owned by Gate 2A.

Disk proof opening now gathers and deduplicates every required main, interaction, composition, and
mask index before I/O, then reuses one open handle per retained Merkle level and row source rather
than reopening files for each of 945 queries. A deterministic public-geometry planner retains at
most 256 MiB of Merkle levels per cross-domain oracle. Larger trees now construct their commitment
root and post-challenge global frontier in one canonical-column pass using only a logarithmic hash
stack plus the exact query frontier; no Merkle-level files are created. The reconstructed root is
checked before any opening is returned, and the forced-recompute test proves byte-exact root,
opening, duplicate-query, verification, and cleanup parity. The resource preflight bounds
recomputation by `(QUERY_COUNT + 1) * maximum_log * 64` bytes instead of a temporary full tree.
No K128 latency or scratch credit is claimed without telemetry. The production-shaped streaming
proof passes end to end after this change; the latest clean frontier rerun is
`1 passed in 119.73s`. This single fixture run is correctness evidence, not a K128 latency result.

The deterministic complete-composition evaluator now executes `BLPQPRF2` end to end. The prior
`CircleFft(TargetLogSizeTooSmall { source: 6, target: 5 })` failure was caused by an interpolation
container retaining an exactly zero high-degree tail. The evaluator now truncates only an
all-zero tail to the frozen work domain and rejects any nonzero coefficient above that domain.
The focused execution passes V2 proof encoding/verification, four proof mutations, and three parser
mutations; the dedicated zero-tail/nonzero-tail regression also passes. No degree, blowup, or
security gate was weakened.

The cross-wave frontier contract is `docs/FRONTIER_THROUGHPUT_AND_ETHEREUM_ALIGNMENT.md`. It adds a
privacy-padded access manifest, measured state-topology bake-off, deterministic conflict-DAG
scheduling, proof-carrying adapters, a formalization spine, and versioned Ethereum compatibility.
It adds no package: progress remains **6 of 93 complete and 87 open**. Its state-call projections
are not measured throughput, and draft Ethereum EIPs are not release dependencies.

The 2026-07-22 quick incorporation screen admitted, but did not select, three additional research
lanes inside existing gates: Shout-like read-only policy/oracle checking plus Twist-like mutable
replay/payment checking against the current endpoint-multiproof/sorted-memory control; VEIL as an
alternative multilinear/GKR hiding wrapper; and Neo/SuperNeo or Hachi initially only for post-K128
folding/aggregation research. The later mandatory 2E gate below now admits Hachi separately as an
isolated pre-K128 PCS candidate. All retain the SHA3-512 root bridge, Fp16 authenticated interactive
public coin, native hiding, 256-bit security/encryption floors, CBAM, fixed shape, and atomic
verification. The exact
state-only call-count ceiling is 72.09x, not an end-to-end speed claim. No package closed,
`proofSuiteId` remains null, and activation remains false.

The 2026-07-26 preliminary mechanism-first frontier screen admits a combined optimization program inside the
same gates: Keccak-specific GKR algebra; exact M31-to-Fp16 tower/small-value sumcheck; persistent
single-owner GPU execution with Rust-authoritative transcript and verification; a streamed jagged
PCS with a proved-distance Fp16 code; and native-ZK composition around the resulting transcript.
It also records explicit rejects for incompatible Groth16/KZG/SRS, Fiat--Shamir-only,
binary-field-only, conjectural list-decoding, distributed-server, withdrawn, and 128-bit-only
headline results. These are prototype lanes, not a selected suite or a throughput claim. The
current arithmetic controls remain 35.1399522 seconds for K128-shaped GKR plus 27.8 seconds for one
direct PCS if run sequentially, while the existing PCS realization fails the current
5,000,000,000-byte
gate. The source inventory is a breadth screen, not an exhaustive full-paper/citation/code review;
its exact genuinely-new-paper count is unproved because the earlier pass lacks a durable
deduplication ledger. No package closed, `proofSuiteId` remains null, and activation remains false.

The subsequent deep state-proof research is now mandatory Wave 2 gate 2E under
`docs/BL_PQ512_COMMITTED_SPARSE_STATE_PLAN.md`. The C0 SHA3 endpoint-multiproof/sorted-memory path
remains the control. C1-C4 add public-coin persistent sparse memory, an IRONDICT-derived transparent
dictionary relation, touched-projection RAM, and a Two-Shuffles-derived memory-consistency relation.
The commitment bake-off separately covers Jindo-style evaluation-hiding lattice PCS,
Grand-Danois/Hachi-style and RoKoko-style candidates, plus a transparent hash/code fallback. All
published KZG, pairing, Schnorr, structured-setup, random-oracle, concrete VOLE/two-party, and
designated-verifier dependencies are rejected. Wave 2 now has six gates: 2E selects from complete
evidence or records why C0 remains selected, and 2F performs the complete K128/K512 latency proof.
No candidate is implemented or selected by this documentation change; progress remains 6/93,
`proofSuiteId` remains null, and activation remains false.

## Compaction recovery order

After any context compaction or handoff, read these files before continuing trust-critical work:

Mandatory insertion: immediately after item 1 (`AGENTS.md`) and before item 2 (`STATE.md`), read
`CONTINUATION_MANDATE.md` completely. It controls persistence, ideology, recovery, safe download
policy, legitimate hard stops, and continuation through partial milestones.

1. `AGENTS.md`
2. `STATE.md`
3. `docs/IMPLEMENTATION_ROADMAP.md`
4. `docs/BASED_ZK_ROLLUP_ARCHITECTURE.md`
5. `docs/PRIVACY_STATEMENT_V2.md`
6. `docs/ZK_BACKEND_DECISION.md`
7. `docs/PRIVACY_V2_INTERNAL_AUDIT.md`
8. `docs/PQ_ZK_SECURITY_ARCHITECTURE.md`
9. `docs/BL_PQ512_FOUNDATION_SPEC.md`
10. `docs/BL_PQ512_SECURITY_FREEZE.md`
11. `docs/BL_PQ512_S09_INTERNAL_SOLUTION.md`
12. `docs/BL_PQ512_S07_S12_PREIMPLEMENTATION_FREEZE.md`
13. `docs/bl_pq512_suite_candidate_v1.json`
14. `docs/BL_PQ512_THREAT_MODEL.md`
15. `docs/security-freeze/BL-PQ512-v1/hardening.json`
16. `docs/FIXED_SHAPE_CLAIM_AIR_DRAFT.md`
17. `docs/SUPPLY_CHAIN_BASELINE.md`
18. `cache/implementation-runs/20260719T164339Z-wave1b-theorem-backend-r35/run_manifest.initial.json`
19. `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/run_manifest.initial.json`
20. `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/run_manifest.initial.sha256`
21. `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/00_freeze_toolchain_and_collection.json`
22. `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/01_official_upstream_cryptographic_implementability_review.json`
23. `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/02_physical_air_calibration_matrix.json`
24. `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/03_integrated_reference_hardening.json`
25. `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/04_regression_and_exact_differential.json`
26. `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/05_rust_platform_and_proof_gates.json`
27. `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/06_cairo_solidity_hygiene_and_privacy.json`
28. `cache/implementation-runs/20260716T145548Z-local-implementation-wave-r25/terminal_manifest.json`
29. `cache/implementation-runs/20260716T145548Z-local-implementation-wave-r25/terminal_sha256.txt`
30. `cache/implementation-runs/20260716T145548Z-local-implementation-wave-r25/run_manifest.initial.json`
31. `cache/implementation-runs/20260716T145548Z-local-implementation-wave-r25/stages/06_k128_k256_k512_measurement.json`
32. `cache/specification-runs/20260715T221859Z-s07-s12-freeze-r24/terminal_manifest.json`
33. `cache/specification-runs/20260715T221859Z-s07-s12-freeze-r24/terminal_sha256.txt`
34. `cache/specification-runs/20260715T221859Z-s07-s12-freeze-r24/run_manifest.initial.json`
35. `cache/specification-runs/20260715T221859Z-s07-s12-freeze-r24/stages/01a_s07_s08_math_correction.json`
36. `cache/specification-runs/20260715T221859Z-s07-s12-freeze-r24/stages/02a_money_boundary_correction.json`
37. `cache/security-freeze-runs/20260715T202353Z-security-freeze-r23/terminal_manifest.json`
38. `cache/foundation-runs/20260715T073140Z-foundation17-r21/terminal_manifest.json`
38. `docs/PHASE1_EXECUTION_LOG_2026-07-13.md`
39. `cache/security-scans/blind-ledger-app-layer/unversioned_20260713T112204Z/artifacts/fix_report.md`
40. `cache/implementation-runs/20260718T134831Z-private-proof-engine-r28/terminal_manifest.json`
41. `cache/implementation-runs/20260718T134831Z-private-proof-engine-r28/terminal_sha256.txt`
42. `cache/implementation-runs/20260718T154911Z-proving-evidence-r29/terminal_manifest.json`
43. `cache/implementation-runs/20260718T154911Z-proving-evidence-r29/terminal_manifest.sha256`
44. `cache/implementation-runs/20260718T170233Z-python-supply-chain-r30/terminal_manifest.json`
45. `cache/implementation-runs/20260718T170233Z-python-supply-chain-r30/terminal_sha256.txt`
46. `cache/implementation-runs/20260718T170233Z-python-supply-chain-r30/terminal_sha3_512.txt`
47. `cache/implementation-runs/20260719T013047Z-s09-public-coin-r31/terminal_manifest.json`
48. `cache/implementation-runs/20260719T013047Z-s09-public-coin-r31/terminal_sha256.txt`
49. `cache/implementation-runs/20260719T013047Z-s09-public-coin-r31/terminal_sha3_512.txt`
50. `cache/implementation-runs/20260719T034130Z-s09-crypto-core-r32/terminal_manifest.json`
51. `cache/implementation-runs/20260719T034130Z-s09-crypto-core-r32/terminal_sha256.txt`
52. `cache/implementation-runs/20260719T034130Z-s09-crypto-core-r32/terminal_sha3_512.txt`
53. `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/terminal_manifest.json`
54. `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/terminal_sha256.txt`
55. `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/terminal_sha3_512.txt`
56. `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/run_manifest.initial.json`
57. `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/stages/01_complete_relation_and_payment_maps.json`
58. `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/stages/02_physical_relation_dimensions_and_measurement.json`
59. `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/stages/03_final_convergence_and_integrity.json`

`docs/DEPLOYMENT_READY_BUILD_CONTRACT.md` and
`docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md` are inseparable companions to item 3 and must be read
immediately after the roadmap, before continuing to item 4. They define the internally finishable
build/audit boundary and the active Wave 2 cost/security gates; historical sealed run records do not.
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md` must then be read before item 4; it supersedes any
older suggestion that a 554-951 GB direct-SHA3-STARK layout is a safe release fallback.
`docs/FRONTIER_THROUGHPUT_AND_ETHEREUM_ALIGNMENT.md` must be read immediately after it; that addendum
owns cross-wave frontier work without changing the denominator or reopening Wave 1.

Every path in this list must exist before continuing. R26 deliberately has no terminal-manifest
entry here: the run was interrupted before terminal reconciliation and sealing. Its initial
manifest and stage JSON files are unsealed recovery inputs, not terminal evidence.

Do not reconstruct the current proof, privacy, or post-quantum decision from chat summaries.

## Current handoff status

This directory is a development and audit workspace, not a release staging tree. The 2026-07-22
cleanup removed rebuildable compiler output, caches, and redundant local source-rollbacks while
preserving Git history, sealed run/security records, and offline dependency inputs. Local rollback
directories are not authoritative evidence; reviewed Git identities plus sealed manifests are. A
release must be built separately from an exact reviewed allowlist.

The intended portable source layout is:

- Source root: `Blind Ledger Neer Version/blind-ledger-app-layer/`
- Canonical sibling ops artifacts: `Blind Ledger Neer Version/ops/`
- App-layer ops mirror: `Blind Ledger Neer Version/blind-ledger-app-layer/ops/`
- Vendored Forge dependency: `Blind Ledger Neer Version/third_party/forge-std/`

Any eventual package must exclude generated build directories, proof artifacts, caches, nested
archives, scratch/GPU build output, local rollback copies, and security-scan working material unless an
independent release manifest explicitly and safely requires an item.

## Security-audit status and continuation boundary

The latest **completed and durably recorded** deep security audit remains
`cache/security-scans/blind-ledger-app-layer/unversioned_20260713T112204Z/`. Its immutable
validation record contains 31 raw candidates, 29 reconciled groups, 16 validation survivors, and
10 raw candidate IDs that survived attack-path analysis. Deduplication leaves eight distinct final
families: four medium and four low, with no critical or high finding. The post-scan repair record
now shows all eight distinct families remediated at their stated software/application boundaries,
including fail-closed `R23-C02` qualification plumbing and the supported-platform `R25-C01` Python
artifact boundary. The proving-evidence
registry has no active policy digest, so no proof suite or verifier was activated. The decision
remains **RED/no-go**.

A later repeat deep review was stopped by the owner before its fourth discovery pass was
mechanically verified, reconciled, validated, and reported. Six fourth-pass reviewer jobs returned
successful process exits, but process success is not finding validation. The third pass had
introduced one new low-severity readiness-metadata **candidate**, which is why the saturation
procedure called for another pass. Do not call that candidate a confirmed vulnerability, do not
claim four-pass saturation, and do not treat unmerged reviewer output as a final finding list. All
known review/validator processes from the stopped attempt were terminated; no review job should be
assumed active.

The 2026-07-18 reconciliation searched the authorized workspace for those later reviewer receipts.
It found zero recoverable fourth-pass receipt files and no later completed scan directory. The six
process-exit statements exist only in this handoff record, so none can be promoted to verified
review evidence and no saturation or new-finding claim is authorized.

If that audit is resumed, reuse the completed fourth-pass reviewer output where recoverable. First
verify its receipts and coverage, then reconcile duplicates, validate only genuinely new
candidates, perform attack-path analysis only for validation survivors, and publish exact counts.
Do not rerun the expensive reviewer generation merely to recreate already available output. The
completed 2026-07-13 `validation_summary.md` and `fix_report.md` remain authoritative until a newer
scan completes its full reconciliation and validation workflow.

R28 recovery run `20260718T134831Z-private-proof-engine-r28` requalified the R26 inputs and closed
with a genuine terminal manifest and seal. R29 run
`20260718T154911Z-proving-evidence-r29` then remediated the R23-C02 code-level trust bypass: one
source-governed registry digest controls a canonical SHA3-512 policy; legacy tool overrides are
rejected; source, tools, parameters, suite, schema, build, and artifact identities are pinned; and
proof generation uses a distinct pinned verifier command. The registry remains
`DISABLED_NO_APPROVED_PQ_SUITE`, so this is fail-closed qualification plumbing, not a production
verifier or strict-PQ proof claim.

R30 run `20260718T170233Z-python-supply-chain-r30` closes `R25-C01` for CPython 3.14.4 on Windows
x86-64 and Linux x86-64/glibc >= 2.28. Four fully transitive locks govern 18 production and 26
development packages; the canonical manifest binds all 52 platform artifact records by filename,
size, official acquisition URL, embedded version, declared license, SHA-256, and SHA3-512. The
installer contains no network acquisition path, requires a fresh environment, fails closed on any
runtime/manifest/lock/wheel drift, runs isolated pip with `--no-index --require-hashes
--only-binary=:all: --no-deps`, checks the exact installed graph, and emits a create-only canonical
attestation. Fresh Windows and Linux offline installs and Linux symlink-bypass coverage passed. No
dependency version was upgraded, no protected source changed, and no roadmap package closed.

The 2026-07-18 Wave 1A relation recomputes exact legacy/SHA3-512 membership
paths for every fixed claim-source, oracle/authorization, sparse policy, and ruleset record.
`pq_strong_nullifier_reference.py` adds a full-width depth-64 indexed transition independent of the
legacy felt tree. `authenticated_payment_reference.py` advances an aggregate reserve/obligation/
paid/responsibility state and operation-log root for every approval, denial, and cover slot.
`wave1a_relation_reference.py` joins those paths with 128 legacy insertions, 128 strong slot
insertions, one context-free strong salt-use insertion, exact payment conservation, the ordered
12-field compatibility statement, and a SHA3-512 master batch commitment. The K128 KAT contains
one approval, one denial, and 126 covers and pins all 12 fields plus the wide governance and batch
commitments.

The A12 continuation removes the opaque-nullifier boundary. Real-attempt identity is exactly the
governed source authority, source claim ID, and original-attempt lifecycle tuple; mutable batch,
slot, claim, payer/provider/member, decision, policy/oracle, profile/domain, and proof context is
excluded. Covers use a separately domain-separated batch/slot/fresh-nonce preimage. The legacy
Poseidon felt and strong SHA3-512 value are independently derived from the same exact bytes, and the
relation verifier recomputes both lanes. A persisted authority-ID/pepper-commitment binding rejects
batch-level rotation unless a future full atomic replay-registry migration is implemented.

R33 completes the narrower Wave 1A semantic-reference foundation without activating it. The relation hard-codes
`nullifier_derivations_authenticated=true` and now composes full-width authenticated per-member
benefit, unique provider-obligation, funded payer-reserve, and provider-payable maps. Denial and
cover inserted reserved zero-valued records under the then-current four-operation schedule; every slot
appends one typed operation commitment. A
later line-by-line audit proved that the R33 16-table object is a declared inventory estimator, not
an executable AIR: it has table metadata and host recomputation but no trace cells, polynomial
identities, boundary/transition evaluator, lookup-multiset check, or serialized verifier statement.
It therefore reports `physical_relation_constrained=false`; its K128/K256/K512 dimensions and
program commitments are historical estimates, not theorem inputs. Source/oracle PQ signer/epoch
verification, executable low-degree application/SHA3/Poseidon constraints, PCS/FRI expansion,
native hiding, the strict-PQ proof suite, and authoritative durable state remain Wave 1A/1B/1C work.
`proofSuiteId=null`, activation is false, the external ABI is unchanged, only synthetic data was
used, and no proof artifact exists. A12 remains closed; the Wave 1A executable-AIR handoff is reopened.

R34 corrects two Wave 1A reference boundaries without changing that status. `BenefitScopeV1`
commits the payer authority, plan, inclusive benefit-period bounds, and fixed asset registry under a
separate SHA3-512 domain. The payment-map state domain is versioned to v2, the scope commitment is
present in the composite root and every member-benefit key, before/after scope drift is rejected,
and relation verification rejects scope substitution under an old commitment. Only `None` now
selects an empty initial provider-balance map; falsey non-mappings `[]`, `""`, `0`, and `False` fail
closed. The scope boundary requires the exact frozen `BenefitScopeV1` type, so a subclass cannot
override its commitment function. Durable authoritative publication of the scoped before-state
remains Wave 1C work.

The 2026-07-18 S09 internal construction slice removes the upstream/QROM design impasse without
promoting the rejected kernel. `docs/BL_PQ512_S09_INTERNAL_SOLUTION.md` selects an authoritative
PQ-authenticated interactive public-coin transcript and pins an executable M31 degree-16 tower,
64-byte encoding, exact irreducibility checks, SHA3-512 rejection sampler, typed commit/reveal state
machine, and audit-root reference. The focused foundation and attack gate reports `11 passed`.
Production arithmetic, SHA3-512 PCS/Circle-FRI, the complete challenge schedule, PQ signature
adapters, cross-session abort/retry governance, native hiding, proof grammar, and final identities
remain open. This slice closes no roadmap package: `proofSuiteId=null`, activation is false, no proof
was generated, and the whole-product count remains 6 of 93 complete.

R31 verification collected 745 non-attack and 159 attack nodes, 904 total. The first broad
non-attack invocation reported `743 passed`, `1 failed`, `1 skipped`, `63 warnings`, and `184`
subtests because the RISC differential correctly required an explicit run-owned target. A copied
R29 binary was then hash-pinned and rejected for semantic drift: current Python and Cairo agreed,
while that stale binary disagreed on six public fields. The current RISC model was rebuilt offline
and locked in the isolated R31 target; the exact differential then passed with eight subtests, and a
second run against the `129,297,728`-byte binary with SHA-256
`b5cb8119010867fbc13e454a25735eae8341007d541d4a5843c5f8fd155b8e01` passed without changing the
binary. Reconciliation therefore yields 744 passing non-attack nodes and the one explicit Windows
account-capability symlink skip. The attack lane reports `159 passed`, `31 warnings`, and `36`
subtests. Current top-level reconciliation is 903 passing plus one skipped across 904 Python nodes;
focused S09 tests are a subset, not additional nodes.
The verified `6,248`-file, `3,531,355,697`-byte generated RISC target was then removed from the
contained R31 directory; its current binary identity and offline rebuild command remain in the
terminal manifest.

R32 run `20260719T034130Z-s09-crypto-core-r32` completed from an exact 584-file rollback with initial
source identity SHA-256 `1950478d5c01df220c945f0e6b68fdd86aad754ca93a002900125da788220bd2`.
It adds an isolated `no_std` Rust Fp16/SHA3-512 substrate, exact locked software ML-DSA-87 and
SLH-DSA-SHAKE-256f adapters, a four-attempt suite-diverse retry/quarantine reference, and a strict
header-first bounded `BLPQPF01` proof-grammar reference. The combined focused S09 lane reports `40
passed`; the Rust crate reports `17 passed` and passes offline locked fmt/check/`no_std`/clippy.
Root scalar measurements are approximately 1.05 million mixed Fp16 updates/second and explicitly
are not proof throughput. The locked R30 Windows production/development wheelhouses still verify at
18/26 packages and include exact `pqcrypto==0.4.0` artifacts.

R32 also repairs one unsafe reference boundary: `OODS_POINT_PARAMETER` now aborts instead of using
the generic field sampler. Math review proves the frozen tower as a nonactivating algebraic substrate
but finds that the Fp16 two-point OODS sampler must reject the embedded Fp8 fixed subfield and that
numeric Circle-FRI constants cannot be selected until final AIR/table dimensions and a
degree-corrected theorem-matched cross-domain layout exist. Vendored S-two remains byte-stable; its
high-level engine is coupled to QM31 across 77 source files. The manual review is evidence, not the
vendored repository's unavailable mandated soundness-checklist sign-off. R32 therefore kept
`proofSuiteId=null`, activation false, physical AIR false, generated no proof, and closed no package.
R33 uses the R32 crate only for the independent dimension mirror and does not modify or promote
vendored S-two.

R33 final collection is 762 ordinary non-attack nodes, two exact differentials, and 180 attack
nodes: 944 unique Python nodes. The broad command that also includes the one-node physical-
dimension differential reports `762 passed`, `1 skipped`, `63 warnings`, and `176` subtests in
`596.19s`; the single skip is the explicit Windows account-capability case where the platform
account cannot create a symlink. The Python/`no_std` Rust physical-dimension differential separately
passes in `6.52s`. The corrected exact-source Python/Rust/Cairo/RISC differential and its eight
subtests pass in `886.00s`; a replay against the `129,297,728`-byte host passes in `14.49s`, with
SHA-256 `be1049e11c795cf7268b1fc00ed540a340538c273183d29c7512b1c9c5dfeafe` unchanged
before/after execution and SHA3-512
`fa5062189062958d544b771e6aa33896e0e9e0382d3f657db9438d7a77933138e9db22c66e166451b6e6aceb23bd8e8a472465bc9825f4c67bfa09891def91a3`.
The attack lane reports `180 passed`, `31 warnings`, and `36` subtests in `72.12s`.

The final native inventory is 48 rules-Rust, 48 RISC semantic-model, 26 S-two, 19 BL-PQ512
crypto/dimension, 10 Cairo, and 23 Forge tests: 174 native entries and 1,118 combined entries. All
current format, locked check/build, strict Clippy, executable-test, pinned-nightly RISC doctest,
Cairo build/test, and pinned-solc Forge gates pass. The Windows Rust 1.96.0 distribution still lacks
an applicable `rustdoc.exe`; the accepted RISC gate therefore runs all 48 executables on 1.96.0 and
the zero-doctest compile on the accepted pinned nightly, without skipping either surface.

The final run caught and fixed a stale RISC `PINNED_RULESET_ROOT_DECIMAL` after the pinned Rust
formatter changed the governed source-byte digest. The governed root, claim/oracle/policy roots,
commitments, and locked leaf/payment vectors now recompute exactly across Python, Rust/RISC, and
Cairo. The verified generated RISC target contained `6,249` files and `3,531,384,703` bytes and was
removed after the hash-pinned replay. R30 remains the sealed Python supply-chain baseline; R33 is
the prior nonactivating Wave 1A semantic-reference terminal and does not supersede R30's offline dependency boundary.

R34 run `20260719T142717Z-wave1a-corrective-r34` starts from an exact 609-file, 5,775,637-byte R33
rollback and reseals the corrected source. Current collection is 768 ordinary non-attack nodes, two
exact differentials, and 181 attack nodes: 951 unique Python nodes. The broad command that also
includes the physical-dimension differential reports `768 passed`, `1 skipped`, `63 warnings`, and
`176` subtests in `582.96s`; the one skip remains the Windows account-capability symlink case already
qualified by R30's locked Linux run. The exact-source Python/Rust/Cairo/RISC differential and eight
subtests pass in `698.92s` before the final scope-type-only hardening; its current-source hash-pinned
replay passes in `17.72s`. The final attack lane reports `181 passed`, `31 warnings`, and `36`
subtests in `86.25s`. The final corrected relation/payment/attack slice reports `19 passed` in
`53.07s`; an earlier broader physical/cross-language slice reports `27 passed` in `84.95s`.

All 174 native entries pass: 48 rules-Rust, 48 RISC semantic-model, 26 S-two, 19 BL-PQ512 crypto/
dimension, 10 Cairo, and 23 Forge, for 1,125 combined Python/native entries. Owned format,
locked/offline check or build, strict Clippy where applicable, executable tests, S-two integration/
doc compilation, Cairo build/test, and pinned-solc Forge gates pass. The cached 9,398,784-byte
`solc 0.8.24` has SHA-256
`580ee56b61bbcaad953117e1e4a0874d90e6af5cb4ce4359571d7da25f6620e9`. The Rust 1.96 Windows
distribution lacks `rustdoc.exe`; the BL-PQ512 crate has zero doctest fences, while all 19 executable
tests and every owned compiler/lint surface pass.

Git 2.54.0 is now active in this workspace. Initial commit
`84468714eb486b12d1f196a2d1b7622266a6d194` is a local neutral-identity baseline containing exactly
the 609 sealed R33 files. It has no remote and no pre-R33 provenance claim; the older July 10
repository was not attached because it tracked only 178 files and matched only 72 current files
byte-for-byte. R30 remains the sealed Python supply-chain baseline; R34 is the current corrected,
nonactivating Wave 1A semantic-reference terminal.

Wave 1A's semantic reference is complete after the R34 corrective seal, but its executable-AIR
handoff is reopened by the R36 architecture audit. R35 Wave 1B evidence remains based on Git parent
`4b7e023de7de71ac8c94dbb4d637f4d053bdd393`, with an exact 609-file/5,793,899-byte rollback and
Git-archive SHA-256
`798ad10e3c5182afd7e3dec2072730c4951254c37df41c3e77630d18bbdff1aa`.

R35 currently implements authenticated-attempt Fp8-excluding OODS, Python/`no_std` Rust scalar
Circle-FRI and conjugate-pair degree correction, projection-consistent SHA3-512 mixed-domain trees,
mandatory independent per-domain FRI batch masks committed before batching, six unselected
interface unique-decoding candidates, and exact typed theorem-message ordering. The K512/blowup-2
pre-dense-schedule native-hiding worksheet obtained `h=4694` over 2,191 private columns. Its 16 tables reduce to six
attached evaluation logs `(21,20,18,16,14,5)`, global trace-column power offsets
`(0,172,632,832,1144,2191)`, and all 17 fold logs `21..5`; Python and Rust bind that interface
schedule to SHA3-512 `c6a61a844f7a0d99e3088e348556467e2338dde8ffe5f7235e98dcc6fe3f0c71cfa47e8175fe9bd275f7222eea1b65e3d3efa4bc1a0d1302a32d01282e4ed52b`.
The exact dense SHA3 schedule supersedes those interface dimensions for final parameter use; the
registry now requires a native-hiding/FRI rerun and forbids treating `h=4694` as current.
Python and Rust now also derive the same direct Circle trace-evaluation certificate. For the K512
KAT it covers the degree-16 OODS parameter, its actual log-20 trace-domain translate, and 926
distinct base queries; its rank is 958, free dimension is 3,736, and SHA3-512 is
`79148ba5b5ee6655478cd478cf3dd159bb8d458d1b6dad0245ee2db0ba223d4c766e0764f9909d05cba9efd0ea98329f53a70618553bf53ea1cd3ead86b6fb04`.
R35 now also has a canonical two-component quotient mask with `h_q=927`, the exact source-aligned
split rule `x([2^(L-1)]Q)`, and cross-language plan SHA3-512
`8b577a857db1f9ae09b0382039bf1af47bd7fbd0b4f42fb3643039233852b1acd56887c45710fb42e733d12024c48ee0c6a334aebdc064fd86d341f1896e6f3a`.
The final AIR-derived `L` and prover integration remain open. A new byte-oriented SHA3-512 AIR
reference independently matches FIPS KATs in Python and Rust and freezes a 1,632-column/1,024-
lookup Keccak core plus 72 block columns/absorb lookups, giving a 1,704-column trace and maximum
1,096 lookups on a first-round row at composed degree 3. Shape SHA3-512 is
`824d0d5adb44dc5a7f61960f7ad61ccb5a34aff177a51616afd0de6b49bbb4adea54e216cb0d0ea5bbe59f4818468e6bc3deafec21bdeddb4db797d899784e1c`.
The first scoped application/reference inventory locked 48 SHA3-512 callsites and its isolated K128 physical-verifier
phase was later reconciled to 404,482 observed calls and a historical conservative envelope of 401,275
application-AIR calls, 1,205,016 SHA3-512 permutations, and 28,920,384 Keccak round rows after
restoring the pepper constraint. Canonical inventory SHA3-512 is
`b17a271256ae467773e5dcc0ee4432bd9cab46fcf5b6d986cf09f5da3f428bdcc5af594b20f85af956b008150a8af5c6580da7b453a8275c541ad0ab482fa27e`.
R36 proved that the required six facts and 50 authorization slots fit one exact 2,133-byte,
bijectively encoded bundle per claim. The proof hashes K bundles plus one ordered execution root;
the separate audit tree reuses those leaf digests outside the proof, and PQ governance attests both
roots. The earlier `51*K` path geometry and its K128 401,275-call/1,205,016-permutation host rerun
are retained only as superseded audit evidence. A new nonactivating compact claim-source candidate
reversibly encodes every source field in 5,648 bytes instead of the 8,525-byte generic reference
wrapper, uses fixed slot order, and hashes 140-byte nodes plus a 76-byte typed root. The combined
compact-source plus packed-oracle schedule costs 14,322/28,644/57,288 SHA3 permutations and
343,728/687,456/1,374,912 Keccak round rows at K128/K256/K512. The K128 claim-source lane independently
matches Python and Rust at 256 calls, 10,368 permutations, 248,832 rows, root
`8e587e518861a30bdca70bbaced6758d57b30921d03ea3bf6506478714f9efd0290c8706c32c2c1ba9480bf15c7e1285c56289e824e949017f3a312e978b32d3`,
and stream commitment
`30223f9c9297b9a68c75ff35ac59c88f8caf522e98cc7fc43816476cd5c4e1c6aa465c7d0b197fe79141631b14c2f8275b1323e7851e57d31ec7f87fc5e811fb`.
The executable source encoding now proves the `rank < 37^64` boundary, required nonempty ranks,
exact token/scalar bundle offsets, fixed header, real/cover and sequence rules, original-attempt
fields, count bounds, NPI digits, and NPI Luhn validity. Required/nonzero state is private trace data,
not a verifier-fixed column, and is linked to real-slot and line-identifier semantics. Its mixed K128
KAT evaluates 1,985,280 degree-2 identities and 4,807,424 lookup messages; program commitment is
`c602d5cd2918231582979eb418244b39f1fd39728b0a47a7504a48e4f0bd824012d8437832c27ddf70965a5f9122e0f6ad5f7ccd3a8e6abb8cd756bf67ae6138`.
The composed source-array relation now constrains exact diagnosis and service non-token bundle bytes,
diagnosis grammar/padding/count/strict `(length, ASCII bytes)` ordering and uniqueness, service live
prefix/count/procedure framing, line-ID presence, and original-line-index uniqueness. Its mixed K128
KAT evaluates 2,736,707 degree-2 identities and 5,217,246 lookup messages; program commitment is
`ca29e4dd3a3465ae053edb25dea5123fe15cb0c9fabebe4714a52c003dd31fc2dc757e1f893a119e3b36a4c0df0156beb87396a8bb14cc8cf292099b99c0d000`.
Full service-line sort ordering remains explicitly unconstrained until the existing canonical token
order is proved without adding a duplicate token decoder.
The executable packed-oracle encoding AIR binds all six fact bits, the complete four-byte slot index,
150 authorization bits with canonical unused-bit zeros, and all 6,400 K128 authorization ranks to
the exact 2,133-byte bundles. It also proves `present` iff the token rank is nonzero and keeps the
program commitment witness-independent. Its mixed K128 KAT evaluates 988,542 degree-2 identities
and 2,241,792 lookup messages; program commitment is
`6f9b6c0e4051acbc257f1e1762eba78506e59a6a393da48b7d752c86dc71d8e2280d4cbeb2b2dda0e44f8d5fe6ad29bd5b10734890aa8a070cea886a4a25aa02`.
The degree-2 claim/oracle composition now binds oracle real-state plus all six facts to the exact
adjudication slot and all 50 authorization rows to the exact service rows. Coherent standalone oracle
traces built from conflicting facts or authorization state fail only at those bridge lookups. The
mixed K128 composition evaluates 1,975,926 identities and 2,937,984 lookup messages; program
commitment is
`5d63849fb4fc2f687a08308c8e3f9adae8e43303012f71535a696f8b8bbbdd5e176ee86c601369b0a98dd90f6467f1935cc98ce642adf7f52f0180d2a618efba`.
This candidate does not mutate or promote the synthetic `REFERENCE/v0` roots. Diagnosis/service
service-line sort ordering, streamed-hash composition, source-authority signature/epoch, oracle
hash composition, and oracle signer/epoch remain open. At the R36 checkpoint, the static inventory
classified 50 live callsites, 25 AIR-required; its canonical SHA3-512 was
`d86734cefb1c6e3e89cc0c5a3d05547c08ac8243da2a09a2ce031d80a349ddf7b93c363e9a63b8b4de836abb7f3e74706167d1559f16db602fc48fba12739f3c`.
The current tree initially exposed 55 observed callsites versus those 50 dispositions, so that identity is
historical. H0 first classified those 55 callsites, 30 as `AIR_REQUIRED`, and dynamically remeasured
every addition rather than inferring a disposition. The four additions exercised by the K128 physical
trace are `_dummy_key` 512x169 bytes and member/obligation/payable key derivation 1x139/136/43
bytes; the cover-v2 helper is a phase-separated isolated 238-byte call because the composed replay
relation derives that same preimage internally. A subsequent independent scan of every `*.py` under
`app/batch` and `experiments/fixed_shape_claim_air` exposed 24 pre-existing sites that the
disposition-derived scope could never see. H0 now reconciles 79/79 callsites: 39 `AIR_REQUIRED`, five
public-precomputed, 21 host-evidence-only, 11 Wave-1C verifier-state, and three superseded-reference
sites. New governed files and alias, attribute, `hashlib.new`, dynamic-import, and dynamic-`getattr`
SHA3-512 forms fail closed. The current inventory SHA3-512 is
`618c06447efc67bca80ca9bb4c59a89970e7c42a26ea6a45a298c8dc8e1e8b2643f3c51a923d1b89ebb6a2311dc22edfffeea70471a9f97c5378b8a43fb607c2`.
The historical 51*K runtime envelope remains explicitly non-current and forbidden for parameter
selection; current K128 bus-mapping/resource evidence remains open.

The canonical v1 Rust proof encoder now returns a fail-closed 13-section byte attribution from the
same serialization pass. Fresh monolithic and bounded-streaming regression proofs both independently
verified and reconciled exactly to 28,643,096 bytes: header 146; initial indices 7,560; mask/main/
interaction/composition openings 2,111,130/2,012,850/2,475,900/2,957,850; next-main/
next-interaction 1,010,205/1,240,785; layer counts 945; FRI values 1,814,400; log sizes 14,175;
Merkle metadata 481,950; and FRI path digests 14,515,200. Structural counts are 945 queries,
14,175 layers, 28,350 Fp16 values, and 226,800 FRI path digests. Both proof paths passed in one
248.79-second two-test run. This is regression-kernel grammar evidence, not K128 latency evidence.

R36 also repaired the authoritative replay-state determinism gap: the depth-64 full-key ordered-map
root now authenticates `nextAppendIndex`, every insertion consumes exactly that cursor, and the
executable replay-header AIR constrains the cursor successor and exact SHA3-512 state roots. Inner
replay predecessor/insertion path AIR and final composition remain open. The economic maps have now
migrated off the historical 512-level key-positioned builder to the same depth-64 full-key ordered
construction. Full 512-bit values use typed 64-byte encodings; the allocator cursor is authenticated;
and approval, denial, and cover all execute one benefit, one obligation, two ledger, and one log
operation per slot. Inserts alone consume the allocator. Updates prove the current allocator leaf
empty but do not advance it. Four scope/domain/epoch-bound zero-valued dummy leaves are created once;
denial and cover update them instead of allocating permanent throwaway records. In the mixed K128
fixture this reduces durable economic allocations from 512 per batch to four actual inserts.

At the pre-closure R36 economic checkpoint, the production-shaped relation no longer repeated four complete paths per upsert. A reviewed
endpoint batch multiproof authenticates every read/write position once, while a sorted memory-access
chain proves exact equivalence to the sequential upsert semantics and duplicate behavior. The mixed
K128 fixture now has `128/128/256` operations, `3/3/5` authenticated positions, `64/64/63` proof
nodes, and `132/132/134` before-plus-after internal-node hashes: 398 total. Those observed counts are
not a privacy envelope. The governed physical candidate fixes 24-bit map shards and pads the three
K128 lanes to 34,026 node hashes, 2,048 leaf-hash slots, six headers, 36,080 SHA3-512 calls, and
74,208 Keccak permutations regardless of keys, insertion/update mix, or decision class. The cap and
exact bounds were executable and attack-tested. That continuation materialized and composed
the three ordered-map lanes with one shared byte table; durable shard rollover/migration and
full-profile global composition were still open at that checkpoint. The 2026-07-21 closure record
at the top of this file supersedes that global-composition status; durable rollover/migration remains
Wave 1C state work.
Fixed schedules for the non-dense application ports, interaction
packing, and the complete interactive simulator remain open. No proof has been generated, no final candidate has been selected, and
`proofSuiteId=null`, activation false, and the **6 of 93** package count remain unchanged.
The previously recorded R35/R36 Rust core run passed all 55 unit tests, zero-test binaries, and doctests under the exact
pinned 1.96.0 toolchain. The original long target path hit Windows linker error `LNK1104`; the
verified run used the short isolated target `C:\blpq-target`. Before the current continuation, the
combined executable-AIR Python lane passed 77 tests; new focused counts are recorded separately below.

R36's architecture audit proves the R33 object was metadata rather than AIR and fails it closed with
`physical_relation_constrained=false`. The repair now has an explicit M31 AST, fixed columns,
local/boundary/transition identities, weighted lookup multisets, canonical program/trace commitments,
and independent typed/serialized evaluators. Exact non-native Stark252 multiplication/linear tables
instantiate all 91 locked Starknet-Poseidon rounds. SHA3-512 now has fixed XOR8/AND-NOT8/SPLIT8
truth tables, padding, message binding, absorption, all 24 Keccak rounds, and multiblock transitions.
The claim-semantic slice constrains service aggregation, all 13 raw gates, cover-effective gates,
first-failure selection, claimed outputs, u32 limbs, and payment conservation. The new focused and
attack lane passes 35 tests in 16.88s; the prior physical-inventory and relation regression lane
passes 17 tests in 75.84s. Python compilation passes. Ruff was not installed and therefore supplied
no formatting/lint credit. Subsequent focused ordered-map, batch-multiproof, and payment-map lanes
pass 8, 4, and 13 tests respectively; these are overlapping focused counts, not a new full-suite
total. At that checkpoint this was real executable-AIR progress, not yet Wave 1A closure: canonical records,
bundle/policy/tree authentication, replay-path and batch-map global integration, privacy-padded full-profile
global composition, Rust evaluation parity, and K128/K256/K512 measurement remained open. All of
those Wave 1A items were subsequently closed by the authoritative 2026-07-21 record above.

The current continuation adds a fixed-schedule executable ordered-map batch AIR. It constrains
insert/update cursor semantics, sentinel exclusion, canonical 24-bit positions and below-M31 sort
gaps, sorted sequential memory, authenticated endpoint leaves, canonical proof/node topology, state
headers, and family-separated fixed hash ports in eight physical tables. Unused inverses and terminal
gaps are forced to zero, and the hashed eight-byte successor index is byte-for-byte tied to its
canonical bounded integer. The component optionally composes every live and dummy hash row with the
exact batched SHA3 AIR; only that composed instance reports `hashes_constrained=true`. At that
checkpoint the global relation still reported `physical_relation_constrained=false`.

The uncomposed three-operation KAT evaluates identically in typed and serialized interpreters and
passes 12 focused honest/attack tests. The bounded exact-composition KAT uses 136 SHA3 calls and 276
permutations; the Rust streaming path separately traverses the complete K128 economic schedule of
36,080 calls, 74,208 permutations, and 1,780,992 Keccak round rows. Python remains the transparent
specification path; retaining full K128 SHA3 object traces in Python is intentionally not the
throughput path.

Fresh Rust 1.96.0 qualification after the streaming SHA3, ordered-map, payment-log, claim-source,
and packed-oracle schedule changes reports `72 passed; 0 failed` plus all seven zero-test binary
targets. Locked
offline `cargo fmt --check` and strict
`cargo clippy --all-targets -- -D warnings` pass. Clippy initially rejected three needless range
loops in the round witness builder; the loops were rewritten with indexed iterators and the full
test gate was rerun without weakening the lint policy.

The packed-oracle execution hash path now streams independently in Rust and matches Python exactly
at K128: 129 calls, 3,954 permutations, and 94,896 Keccak rows. Execution root is
`64502aca9576c960ca69c767f6df3590ae5571d3a24ea38faebc0e8e7d4e8198ba35c274b91d24830c59f0b1809692288cdb3f45b1de7b9f6fcaa4192e86d5fa`;
stream commitment is
`109a0701e6c4758ea23053a183f34aae3d6761cd0192c6c2476581b23702607eb54cbba468b47db99a566e2d814c310d1e5802763cbc54769ea926c7ddb7fe49`.
This is bounded trace-generation parity; the streamed rows are not yet composed into the global AIR.

Python and Rust independently derive the K128 benefit/obligation/ledger schedule and bind the lane
domains plus all ten dimensions to
`1c390b67823fc6b71233d87d4082d48082b6f9ed3ff2f7c4d5e079f5b6bff947646b41c9714e263f29a1e3722a9cab8fa158091f00f77b1c7304a21182588683`.
The Rust attacks prove domain relabeling changes the commitment and empty/invalid requests fail
closed.

Rust also streams and validates every row in a fixed map hash-call schedule: family order, live
prefixes, canonical leaf/node padding messages, mandatory live headers, exact SHA3 digests, call/
permutation/round counts, and a cross-language call commitment. The 136-call KAT matches Python at
`a45ec62a23518d528dda98e20da49e513c2d7ac82e6ceb58637985a066190a563e776676816d21e784c88ad1084a560c565cd00bef82b83c0c4a91d37052fee0`;
digest, dummy-message, and header-liveness mutations fail closed.

The current payment composition namespaces the benefit, obligation, and ledger AIRs, replaces three
duplicated 256-row byte/property tables with one shared physical table, and binds all three endpoint
states in a 23-table map program. The K128 claim/payment composition adds one 128-row bridge and
constrains claim economics, approval/denial/cover shape, canonical fixed-width values, four exact
map-operation links, checked 64-bit benefit/reserve/payable carries, and authorization-use counting.
Its exact default KAT has 32 tables, 45 lookups, 30,047,077 evaluated identities, 41,373,848 lookup
messages, maximum degree three, program commitment
`eca09f6e8e529642c192add90de95c812bebc9a8e8f685d64e8e5c8a92c518f9cae2409be6102ce4f53b5158d7325705424ff01657a13a35b1b4b8cbbe27456d`,
and trace commitment
`de0e0cae8f659d6df42bf89f05c644287c3421e40dd4e21dda291312a7a57e612aaada6349f1e15dac84b4fc542786412072b4e5804754026327ba8c601154c3`.
At that checkpoint this closed neither key derivation nor the global relation; both were subsequently
closed at the Wave 1A boundary recorded above.

The audit operation preimage is versioned to v3 and commits the same 768 authenticated bytes as the
old design—four full keys plus four before/after values—without requiring redundant per-operation
Merkle roots that the endpoint multiproof deliberately eliminates. Python owned-trace construction
for all 256 K128 log hashes exceeded the 300-second bound and receives no throughput credit. The
Rust streaming path instead matches Python exactly at 128 slots, 256 calls, 1,920 permutations,
46,080 Keccak round rows, final log root
`ba30c667a959730fefb46620dd9ddc87db1aff60c0e85fe0ed29a4ce3faa84ca8d358aee405e14320bcd8b054156f72bc002213cd359c491938b83431535140a`,
and schedule commitment
`e9895d2e1655f9b77f7e3872754498ee6c9d5e45b9e39c8d6103c3f14c1c089f39a8ea5fb0f2367f9725ee1f06e9a6e53acbbdde42255530ba63799b04f8c25c`.
At that checkpoint the default Python component instance honestly retained
`operation_log_constrained=false`; the later global boundary composes its exact streamed schedule
without constructing a redundant owned K128 Python Keccak object graph.

Payment-key framing is now exposed once by the Python semantic reference and mirrored by a bounded
Rust fixed-privacy stream: benefit/reserve/payable capacities are 203 bytes and obligation capacity
is 216 bytes for every slot, independent of decision class. The actual K128 run matches at 512
calls, 1,664 permutations, 39,936 Keccak rows, and commitment
`6c84f07339e09e7f7ab6f10ba7f837fc1962411979b4712d62e734afaa9e4655e2087c120c6ec4d28bf01f3d8c2db62b6967a14f58a096961f68b9a8ff219841`.
At that checkpoint the bridge still reported `key_derivations_constrained=false`; the sealed global
relation now binds those messages and digests to the authenticated claim-source identity bytes.

Historical R36 continuation plan (steps 1-2 are now complete; steps 3-5 are Wave 1B work) was:

1. Replace the R33 metadata inventory with an executable, independently evaluable AIR: explicit
   trace cells, local/transition/boundary identities, lookup messages and multiset checks, canonical
   public binding, SHA3-512 expansion, and exact Starknet-Poseidon compatibility. The AIR must use
   one fixed claim-scoped oracle bundle, authenticate a policy payload once per claim, build the
   compact claim-source tree bottom-up once, and use depth-64 ordered full-key payment maps. Historical host
   recomputation counts and declared dimensions must not drive theorem parameters.
2. Reread and requalify the complete Wave 1A semantic relation against that executable AIR, remove
   duplicate aggregate-payment production work while retaining it only as an independent historical
   oracle, and freeze newly measured K128/K256/K512 dimensions.
3. Integrate the scalar sibling PCS/FRI references into the measured executable AIR. Apply the exact
   dense K128/K256/K512 schedules and fixed schedules for every non-dense application port, then select
   and mask the lookup-interaction packing and build the
   production prover/verifier, then rederive and select the rate/list/fold/
   query constants from the expanded dimensions. Add optimized scalar/SIMD Fp16 only behind exact
   scalar equivalence; do not reuse the rejected QM31/Blake2s/default profile.
4. Complete native hiding against the stable executable oracle inventory: substitute the final
   AIR-derived Circle split log-degree into the source-aligned quotient mask, freeze final SHA3/
   interaction dimensions, implement the full interactive simulator, then
   cover denominator/abort behavior, repeated-proof unlinkability, and
   side channels.
5. Complete S07-S09 only after exact concrete hash/PCS expansion, theorem/retry/hiding/parser
   substitution and internal
   review. Keep `proofSuiteId=null` until the suite qualifies as `BUILT_AUDIT_PENDING`.
6. Finish Wave 1C authoritative verifier/state convergence and the remaining proof-level T02-T10
   KATs/attacks after the Wave 1B suite exists.
7. Build the provider-neutral government/oracle adapter SDK and local/sandbox conformance suite so
   live credentials remain activation inputs rather than engineering blockers.
8. Finish non-Python S11/O12 reproducibility without weakening the closed offline Python boundary.
9. Integrate the real verifier/state interface into the counted R01-R12 rollup path and prove the
   complete synthetic claim-to-Ethereum-finality deployment before the independent audit.

Focused tests should run after small changes; the complete Python, attack, Rust, RISC, S-two,
Cairo, Forge, cross-language, privacy, artifact, source-integrity, and rollback gates run at each
convergence milestone. Any Python/Rust/Cairo/RISC/S-two/verifier semantic mismatch remains a hard
stop. The corrected whole-product roadmap count is **6 of 93 internal packages complete and 87
open**. The independent Security Audit Gate is separate and not counted.

## Trust-critical status

Protected paths remain source-only in this handoff. Do not edit the Cairo circuit, Solidity contracts, canonical encoding, public-input boundary, nullifier logic, Merkle logic, accumulators, STARK binding, oracle attestation, or batch orchestrator without explicit approval.

Protected circuit and contract redesign was explicitly authorized for the isolated Privacy V2 workspace on 2026-07-12. That authorization does not make the existing V1 boundary production-safe and does not permit weakening tests or proof binding.

## Target architecture status

The selected target is an Ethereum-settled, EVM-compatible based validity rollup. The decision and implementation sequence are locked in `docs/BASED_ZK_ROLLUP_ARCHITECTURE.md`.

The authoritative completed/remaining upgrade sequence and next large-run gates are maintained in
`docs/IMPLEMENTATION_ROADMAP.md`. `docs/DEPLOYMENT_READY_BUILD_CONTRACT.md` defines what internal
completion, audit-pending deployment readiness, the final independent audit, and operator
activation mean. Future implementation work must update those files and this handoff state together.

The selected claim-proof security direction is now `BL-PQ512-v1`, defined in
`docs/PQ_ZK_SECURITY_ARCHITECTURE.md`:

- preserve the external 12-field application ABI's count, order, names, types, and forbidden-field
  boundary, but not obsolete denied-case KAT values;
- preserve the sealed fixed-shape M31 semantic AIR rather than a general Cairo or RISC-V VM, remove
  its SHA3 internals only from the release PCS, and bind its exact hash ports to one committed bus;
- internally implement and qualify the masked Fp16 Boolean GKR SHA3 coprocessor plus native hiding
  for both modules under one authenticated interactive public-coin session, then submit the
  completed exact release to independent audit;
- make authenticated SHA3-512 proof metadata and verifier-maintained shadow state authoritative for
  strict post-quantum binding;
- make every real claim consume an attempt nullifier and every padding slot consume a cover
  nullifier so approval, denial, and padding have one public state-transition shape;
- retain RISC Zero, the existing Cairo program, and Python/Rust implementations as differential
  semantic oracles.

This is an architecture decision, not implementation or production evidence. R23 rejects the
current QM31/Blake2s/default S-two configuration for the strict post-quantum target and confirms that
extra FRI queries or grinding cannot repair its independent field/hash ceilings. M31 degree-16
challenges plus full-width SHA3-512 are the conditional lead, not a selected or externally reviewed
suite. Current S-two remains validity-only and forbidden for real PHI. No available backend in this
archive currently satisfies the selected witness-hiding and strict post-quantum profile.

The first major hardening and baseline-convergence run completed on 2026-07-13 to an explicit
**RED/no-go**. It repaired application and cross-language defects and established a current
synthetic regression baseline. It did not implement or qualify the complete fixed-shape AIR,
witness hiding, strict-PQ proof profile, production verifier, or release. Roadmap package `S01`
was the only closed package at that historical checkpoint; later R23 reconciliation closes S03,
S05, and S06 as application-specification packages only.

The authorized 17-item synthetic foundation bundle completed on 2026-07-15 as an evidence-only
engineering run. Its immutable R21 terminal manifest is
`cache/foundation-runs/20260715T073140Z-foundation17-r21/terminal_manifest.json`, sealed by SHA-256
`7bcaf24f33130aea258a58286b8121c4c19a89d7f2c9c691a77ca633cc69006f`. The bundle produced 16
draft/reference/prototype items and reran `T14`; it closed no additional roadmap package. The ten
historical v1 launch-blocker entries were open at that checkpoint. Five unavailable Windows-only tool components are recorded as required
platform gaps, with their WSL equivalents passing. Product semantic mismatches were zero, but no
proof or final proof was generated and no proof-throughput claim follows from this run.

The R23 security-freeze reconciliation is recorded in `docs/BL_PQ512_SECURITY_FREEZE.md` and
`docs/security-freeze/BL-PQ512-v1/`. It preserves the exact 12-field ABI, closes S03/S05/S06 only,
and leaves S02, S04, and S07-S12 open. Under the current whole-product denominator that checkpoint
represents 4 of 93 packages complete and 89 open; its sealed record retains the superseded mixed
count. Its fresh executable rerun reports zero product-semantic mismatches across every required
Python, attack, Rust, Cairo, Solidity, privacy, release-builder, and integrity gate. Five Windows-
only components remain unavailable and explicit; all five WSL counterparts pass. R23 generated no
proofs. The 124-proof campaign was skipped because the complete AIR, native witness hiding, and an
internally selected and qualified proof suite do not exist and the current suite is rejected.

The accepted R24 synthetic-only continuation through S12 is recorded in
`cache/specification-runs/20260715T221859Z-s07-s12-freeze-r24/terminal_manifest.json` and its
adjacent SHA-256 seal. Failed and superseded attempts remain preserved in the same run record. R24
preserves the exact 12-field ABI, keeps the existing QM31/Blake2s/default suite rejected, and leaves
the candidate `CANDIDATE_UNQUALIFIED`, nonactivatable, and `proofSuiteId=null`. Its executable gates
cover exact source and proof money grammar, checked aggregates, policy and legacy-binding coercion,
batch prefilter/root privacy behavior, private zero-value G8A denial, and structural total mismatch
or overflow across the applicable Python, Rust, Cairo, and RISC lanes. The full payment/benefit
relation, authenticated missing-data parity, revision authority, final AIR, QROM proof, native
hiding, supply-chain closure, and final audit remain open. R24 generated zero proofs, did not
run the 124-proof campaign, establishes no throughput or production claim, and closes no additional
roadmap package; current-model progress at that checkpoint was 4 of 93 complete and 89 open.

On 2026-07-16 the roadmap's next-wave ambiguity was corrected and the resulting R25 synthetic,
nonactivating local implementation-and-measurement wave completed. Its terminal record is
`cache/implementation-runs/20260716T145548Z-local-implementation-wave-r25/terminal_manifest.json`.
R25 adds provisional K128/K256/K512 host semantics, equal logical schedules, payment/replay/state
references, checked-money guards, deterministic vectors/properties, attack coverage, and an
explicit S-two validity/security boundary. It preserves the 12-field ABI, leaves
`proofSuiteId=null` and activation false, and uses only synthetic data. It closes only `Z01` as an
isolated verifier-clean validity baseline, so checkpoint progress was 5 of 93 complete and
88 open. Physical AIR, native witness hiding, strict-PQ parameters, authoritative state, adapters,
rollup integration, and the final audit remain open.

R25 measured 15 serial host-model profile/shape combinations. The heaviest K512/full-capacity model
took `2.5877058s`: `15.886984%` fixture construction, `41.423886%` logical trace,
`42.246367%` payment economics, and `0.442763%` operation logging, with a Python-tracemalloc peak of
`5,510,060` bytes. Physical AIR rows/columns are still `null`, and the host model generated zero
proofs. A separate narrow 1,024-row S-two validity proof verified in `0.118095s` proving and
`0.000956s` verification, but it has `witness_hiding=false`, binds only aggregate decision/value
conservation, retained no proof artifact, and is not full-claim or `BL-PQ512-v1` evidence.

R26 is an **interrupted and unsealed** synthetic-only private-proof-engine foundation continuation at
`cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/`. The directory contains its
sealed initial manifest and seven stage JSON records, but no `terminal_manifest.json` or terminal
seal. Searches found no moved copy or deletion record. Its source changes and stage records add a
narrow physical decision/payment AIR and stronger nonactivating candidate-sidecar, verifier,
replay, payment, and in-memory state references. R28 later revalidated the applicable inputs without
retroactively completing R26. R26 receives no package-closure credit, so that checkpoint remained
5 of 93 complete and 88 open. The
exact 12-field ABI is unchanged, `proofSuiteId` remains null, activation remains false, and all
recorded inputs are synthetic.

The unsealed R26 physical-stage record reports 51 verified-and-discarded validity-only calibration proofs across
K128/K256/K512. Every profile uses 267 physical trace columns, one interaction column, and 476
constraints. Average proving time is `0.051942850s`, `0.070609592s`, and `0.086222081s`
respectively; maximum measured verification is `0.002575530s`, and maximum measured RSS is 7,252
KiB. This kernel proves only 13-gate priority and limb payment conservation. It omits the ordered
12-field proof statement, authenticated source/oracle/policy/nullifier state, SHA3-512 shadow state,
native witness hiding, and the strict-PQ suite. It is labelled `REJECTED_VALIDITY_ONLY_CALIBRATION`;
all proofs were discarded and no proof artifact was written.

The unsealed R26 gate-stage records report 801 unique Python nodes, 48 rules-Rust tests, 48 RISC model tests,
26 S-two tests, 10 Cairo declarations, and 23 Forge tests: 956 top-level tests/declarations. The
hash-pinned exact differential matches all 12 fields across Python, Rust/RISC Zero, and Cairo and
matches the separate Python/Cairo claim-semantics vector. Initial Scarb and Poseidon-helper setup
failures occurred before semantic comparison and were retained. After explicit owner authorization,
fresh serialized short targets passed without source, manifest, dependency, or tool-version changes.
The 124-proof campaign was not run because the complete cryptographic prerequisites remain absent
and the initial free-memory preflight was below 8 GiB.

The audited pre-R25 cache cleanup is sealed at
`cache/maintenance-runs/20260716T140141Z-audited-cache-cleanup/terminal_manifest.json` with SHA-256
`9a1a2d0d9ab54de902918bea9959b36cdf96de38b52b214989fc39619b1e0e69`. It removed 47 verified
generated targets containing 209,100 files and 33,843,205,703 logical bytes while preserving source,
offline dependency seeds, directly referenced R20/R21 inputs, and the R21/R23/R24 seals. The local
rollback copies retained by that historical run were removed in the 2026-07-22 cleanup after Git
identity and the durable evidence boundary were confirmed.

Current implementation blockers:

- no production `INativeStarkVerifier` implementation exists in the repository;
- the Cairo V1 `BatchOutput` now has 12 values and `BatchOutputV2` preserves the exact ordered
  Privacy V2 12-field ABI, while the legacy V1 settlement surface still accepts 21 separately
  supplied values;
- the Solidity V1 test verifier ignores proof and public inputs; the V2 test verifier binds its
  supplied bytes with Keccak but is still not a STARK verifier;
- V1 publicly exposes exact approved/payment totals and stores claim ciphertext;
- no end-to-end claim-proof -> L2 verifier -> rollup proof -> Ethereum L1 verification run exists.
- R33 supplies a complete fixed-shape host semantic relation, exact 12-field composition, and
  authenticated source/payment/replay transitions, but its 16-table object is only a metadata
  inventory with host recomputation. It does not constrain a trace; its SHA3-512, Poseidon,
  challenge, commitment, PCS, and FRI ports remain abstract and no concrete theorem-matched proof
  backend or production verifier exists;
- no native S-two witness-hiding implementation or Circle-STARK-specific zero-knowledge simulator
  exists;
- no activated authoritative SHA3-512 shadow nullifier/governance/batch state or production proof-
  sidecar verifier exists; R24 provides only a tested, nonactivatable 744-byte candidate sidecar and
  reference parser;
- R34 now executes domain-separated authenticated payer/plan/period-scoped benefit, obligation,
  reserve, payable, operation-log, and replay-root transitions with equal-work denial/cover paths,
  but these remain synthetic references rather than concrete low-degree proof constraints or durable
  authoritative state;
- R33 computes and verifies full-width replay nonmembership/insertion chains, but no production P03
  state service, anti-rollback storage, or activated root authority exists;
- application nullifier validation requires a nonzero post-transition root and recomputes the
  transition; R33 also fixes uniform attempt/cover relation work, while concrete proof constraints
  and authoritative state integration remain Wave 1B/1C work;
- the current QM31 proof challenge field, Blake2s-256 Merkle/transcript, and default query/grinding
  profile are rejected for the selected strict 128-bit quantum target; R32 implements only an
  isolated degree-16/SHA3-512 substrate, not the theorem-matched PCS/FRI, hiding, verifier, or
  internally qualified `BUILT_AUDIT_PENDING` suite;
- the entropy boundary deliberately leaves the OS provider unwired and is disconnected from
  proof masks, so Z02-Z12 remain open;
- adjacent key wrapping and authorization still include classical RSA, P-256, and Ed25519 surfaces,
  so the full system is not end-to-end post-quantum.

R29's authoritative full Python lane reports `820 passed`, `216` subtests passed, `94` warnings,
and zero failures in `608.33s`. Its separately counted attack subset reports `145 passed`, `36`
subtests passed, and `31` warnings in `40.67s`; the new R23-C02 attack module contributes `16`
tests. The final hash-pinned Python/Rust/Cairo/RISC differential reports `1 passed` plus `8`
subtests in `18.96s`. These subset counts are not added to the full-suite count. The R29-owned RISC
host is `129315352` bytes with SHA-256
`b0f233ee0b67b0aba02407de5cd062d0b02e8a4a26c3097b695628d7e2b0de78` and SHA3-512
`b0763ce52b3145dd304d839ea724a361197618e4411b1623ce73780eac5b159ed3d9021a819f6ba51aabc5953a137124ed6e6419a933d85bc76dc776eb755989`.
The direct proof command failed closed with the disabled registry and wrote zero proof files. This
is a terminal software/security baseline only; it is not a complete-proof, witness-hiding,
strict-PQ, throughput, settlement, or production claim.

R30 adds 20 unique Python nodes and qualifies them inside the reviewed offline-installed dependency
environment. Its exact schedule is `690` non-attack tests plus `172` subtests, one differential plus
`8` subtests, and `149` attack tests plus `36` subtests: `840` unique top-level Python nodes and zero
accepted failures. The Windows account could not construct a symlink and skipped that one test in
the long lane; a fresh locked Linux environment subsequently passed all `21` focused supply-chain
tests including the symlink case. The exact differential reused a current-run-owned copy of the
R29/R28 model binary after SHA-256 readback matched
`b0f233ee0b67b0aba02407de5cd062d0b02e8a4a26c3097b695628d7e2b0de78`.

## Proof status

A local external CUDA proof run was recorded outside this archive on 2026-07-09:

- Proof path at time of run: `<external-workspace>/proofs/safeopts_execution162_cuda_finalgroup_proof.json` (local username/path redacted; artifact was never packaged)
- Proof SHA-256: `2e6a0d5edbf8884a6da4f5476298f06a3c5e95b4a8bb9934b24c0f6b06c3ea3f`
- Recorded wall time: `352.08s`

The external prover build and generated proof JSON are not packaged. Regenerate and verify in the current environment before making production proof claims.

A separate RISC Zero 3.0.5 Privacy V2 qualification ran locally on 2026-07-12:

- development mode disabled;
- receipt verified against the generated guest image;
- all 12 journal fields matched the Python-generated Poseidon KAT;
- proving time `1472.797364s`;
- verification time `0.134665s`.

This proves only the V2 commitment envelope. Full claim adjudication, fixed-size privacy controls,
payment state, Ethereum-compatible receipt compression, the L2 verifier, artifact pinning, and
independent audit remain open. No real PHI is authorized.

A later complete-claim RISC Zero profiling attempt did not finish a proof. Its raw progress data was:

- `191` segments;
- minimum `199,229,440` guest cycles;
- `17` completed segment intervals totaling `5,464` seconds;
- mean `321.411765` seconds per segment;
- linear projection `61,389.647059` seconds, or `17.052680` hours.

That is an interrupted-run projection, not a completed proof measurement. It disqualifies the
current generic RISC-V implementation as the production performance path but does not invalidate
RISC Zero's role as a semantic oracle.

The supported S-two simple-bootloader run remains verifier-clean off-chain evidence for the current
Cairo statement: `89.0` seconds total, `5,591,878` proof bytes, `43.5` milliseconds verification,
and all 12 inner outputs matched Python. It is not witness-hiding and is not `BL-PQ512-v1` evidence.

R25 also reproduced the isolated custom S-two validity baseline for 1,024 synthetic rows. The
optimized run reported `0.118095s` proving, `0.000956s` verification, and
`proof_verified=true`. Its explicit scope is `aggregate_decision_and_value_conservation_only` and
`witness_hiding=false`. The paired witness-hiding-required run exited nonzero with
`WITNESS_HIDING_UNAVAILABLE` before claim generation or trace allocation. Build time and the full
qualification-suite durations are not proof latency.

The unsealed R26 proof-stage record reports a repeat of that isolated 1,024-claim baseline at `0.115831s` proving, `0.000197s`
verification, and 4,084 KiB peak RSS. It also executed 51 narrow physical calibration proofs across
K128/K256/K512; their average proving times were `0.051942850s`, `0.070609592s`, and
`0.086222081s`. Every proof verified and was discarded, with zero proof artifacts. Both
hiding-required controls failed closed before trace/proof work. These executions have
`witness_hiding=false`, `proofSuiteId=null`, and activation forbidden; they are not the complete
12-field private/PQ claim proof. The final 124-proof campaign was skipped entirely: 124 skipped,
zero run, because the complete AIR, native hiding, strict-PQ suite, sidecar verifier, and
authoritative state do not exist and free-memory preflight failed the 8 GiB minimum.

## Test commands to preserve

```powershell
py -3.14 -m pytest -q --ignore=tests/attacks
py -3.14 -m pytest -q tests/attacks
cargo test --release --offline --locked --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml --features std,parallel
cargo clippy --release --offline --locked --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml --all-targets --features std,parallel -- -D warnings
```

Do not weaken tests, policy pins, or security checks to make a run pass.

## 2026-07-27 Phase 0 calibration and B=8 kernel profile — MEASURED

Scope: execution-order Phase 0 only. These measurements do not qualify a proof, change
`proofSuiteId=null`, or authorize production. The reduced geometry is 128 permutations rounded to
16 repeated-pack groups; the reference geometry is the existing 782-permutation control rounded to
128 groups. Both use the existing 216-layer coherent chain.

### Test-only authenticated-coin fixture

`bench_fixture_coin` is a new Cargo feature that is OFF by default. When enabled, the benchmark
uses fixed dual-PQ keys and fixed reverse chains under fixture-only head, chain, session, round-seed,
and audit domains. The production coordinator import and spawn are unreachable in that build, and
an independent fixture replay verifier checks the result. This fixture is **TEST-ONLY,
NON-QUALIFYING**; fixture challenges cannot validate under the production coin domains. The
production live-coin path remains the default.

The current source delta against the immutable transfer ZIP is exactly:

- modified `experiments/bl_pq512_crypto_core/Cargo.toml`;
- modified
  `experiments/bl_pq512_crypto_core/src/bin/gkr_coherent_chain_benchmark.rs`; and
- added
  `experiments/bl_pq512_crypto_core/src/bin/support/gkr_coherent_chain_benchmark_fixture_coin.rs`.

No protected path changed. Release/offline/locked builds passed with the feature both disabled and
enabled. One debug test invocation was excluded: repeated SLH signing exceeded the 428.613-second
command bound and the externally terminated child reported a broken pipe, with no assertion
failure. It was not rerun because the narrower release end-to-end fixture exercises the same
fixture/replay boundary without debug-build signing overhead.

### Five-run calibration

Exact build and run form:

```powershell
$env:CARGO_TARGET_DIR='C:\Users\neers\Documents\Codex\2026-07-27\he\work\cargo-target-phase0'
cargo build --release --locked --offline --features parallel --bin gkr_coherent_chain_benchmark
$env:CARGO_TARGET_DIR='C:\Users\neers\Documents\Codex\2026-07-27\he\work\cargo-target-phase0-fixture'
cargo build --release --locked --offline --features parallel,bench_fixture_coin --bin gkr_coherent_chain_benchmark
& 'C:\Users\neers\Documents\Codex\2026-07-27\he\work\run-phase0-calibration.ps1' -GroupCount 16 -Permutations 128 -Boundary 'C:\Users\neers\Documents\Codex\2026-07-27\he\work\gkr-128-boundary.bin' -Runs 5 -CoinMode Fixture
& 'C:\Users\neers\Documents\Codex\2026-07-27\he\work\run-phase0-calibration.ps1' -GroupCount 16 -Permutations 128 -Boundary 'C:\Users\neers\Documents\Codex\2026-07-27\he\work\gkr-128-boundary.bin' -Runs 5 -CoinMode Live
& 'C:\Users\neers\Documents\Codex\2026-07-27\he\work\run-phase0-calibration.ps1' -GroupCount 128 -Permutations 782 -Boundary 'C:\Users\neers\Documents\Codex\2026-07-27\he\work\gkr-128-boundary.bin' -Runs 5 -CoinMode Fixture
& 'C:\Users\neers\Documents\Codex\2026-07-27\he\work\run-phase0-calibration.ps1' -GroupCount 128 -Permutations 782 -Boundary 'C:\Users\neers\Documents\Codex\2026-07-27\he\work\gkr-128-boundary.bin' -Runs 5 -CoinMode Live
```

All 20 current runs exited zero, independently verified the chain, and wrote empty stderr. Five
earlier `g16` live runs are retained but excluded from this table because they predate the
coin-wait telemetry and were superseded by `g16-live`.

| Coin / geometry | Authenticated rounds | Total time, five-run range | Coin wait average, five-run range | Digest result |
| --- | ---: | ---: | ---: | --- |
| Fixture / 16 groups | 7,489 | 17.4900829-18.9870669 s | 32,740-35,119 ns/round | identical across all five: `c531f446cdf4f0df2af4cf33623fe88e456d8304ce342897a83989dda71fdc0c803b3ae7afe31c0dccd3ad22e43658320b2e4e1e746f17b6a0b342b6b4d596b6` |
| Live / 16 groups | 7,489 | 17.9300747-18.6981438 s | 135,454-143,860 ns/round | five distinct digests, as required |
| Fixture / 128 groups | 8,785 | 30.4336514-31.8402930 s | 32,853-35,571 ns/round | identical across all five: `62752652268cff727ec9b5c72f9a2b29f680538dc1beee585513dac90c1c40bd4c9b79a355da9243c25f8761fe842036a143fe6f6e79ec089495bc2465e73121` |
| Live / 128 groups | 8,785 | 31.8262444-33.1485694 s | 144,545-167,565 ns/round | five distinct digests, as required |

Maximum observed combined process RSS was 312,492,032 bytes and maximum observed GPU memory was
450 MiB. System-wide pagefile usage and page-read counters fluctuated, so this run does **not**
establish the release no-swap gate; process-level swap attribution remains unverified.

The measured round law is:

```text
rounds(group_variables) = 7,489 + 216 * 2 * (group_variables - 4)
```

The two anchors agree exactly: `8,785 - 7,489 = 1,296 = 216 * 2 * 3`. Therefore there are two
authenticated rounds per layer per group variable. K128's 113,730 permutations require 16,384
groups and 14 group variables, so the projected count is `11,809` rounds from either anchor,
18.02% of `MAX_CHAIN_ROUNDS = 65,535`. Label: **PROJECTED FROM TWO MEASURED ANCHORS**. Applying the
measured live-coin range of 135,454-167,565 ns per round projects about 1.60-1.98 seconds of pure
coin wait at 11,809 rounds, not the earlier assumed 6-12 seconds.

### Existing B=8 first-round profile

The sampled load is 5,644,800 packed gate-instances, exactly the historical
45,158,400-gate K128 control scaled by `16 / 128`. The binary was the existing standalone B=8
kernel, release-optimized with full debug information:

```powershell
$env:CARGO_TARGET_DIR='C:\Users\neers\Documents\Codex\2026-07-27\he\work\cargo-target-phase0-profile'
$env:CARGO_PROFILE_RELEASE_DEBUG='2'
cargo build --release --locked --offline --features parallel --bin packed_boolean_sumcheck_benchmark
wpr -start CPU -filemode
1..5 | ForEach-Object { & 'C:\Users\neers\Documents\Codex\2026-07-27\he\work\cargo-target-phase0-profile\release\packed_boolean_sumcheck_benchmark.exe' 5644800 1 }
wpr -stop 'C:\Users\neers\Documents\Codex\2026-07-27\he\work\phase0-b8-cpu-symbolized.etl'
.\work\samply-0.13.1\samply.exe import --save-only --output .\work\phase0-b8-profile-symbolized.json.gz --profile-name phase0-b8-reduced-five-run-symbolized --name packed_boolean_sumcheck_benchmark --symbol-dir .\work\cargo-target-phase0-profile\release --unstable-presymbolicate .\work\phase0-b8-cpu-symbolized.etl
wpr -start 'C:\Users\neers\Documents\Codex\2026-07-27\he\work\phase0-b8-pmc.wprp!Phase0Pmc' -filemode
1..5 | ForEach-Object { & 'C:\Users\neers\Documents\Codex\2026-07-27\he\work\cargo-target-phase0-profile\release\packed_boolean_sumcheck_benchmark.exe' 5644800 1 }
wpr -stop 'C:\Users\neers\Documents\Codex\2026-07-27\he\work\phase0-b8-pmc.etl'
tracerpt .\work\phase0-b8-pmc.etl -o .\work\phase0-b8-pmc-events.csv -of CSV -summary .\work\phase0-b8-pmc-summary.txt -y
& .\work\analyze-phase0-b8-pmc.ps1
```

The ordinary CPU sample had 3,455 main-thread samples, of which 3,344 resolved to project source
and 111 were unresolved/system. Its five reduction times were 646,586,800; 683,389,700;
738,327,900; 599,653,300; and 700,375,400 ns (median 683,389,700 ns). Every run emitted
SHA3-512
`6f3fb234856060a604661bbb30ee6987e55dc91e6a0d9d365e19a921c7449d7000d2c0e90a02e6107416fdbc379107a5a3ba1cc35e14b675e94bbb0dc894179b`.

The AMD PMU capture recorded 201,558 in-module `TotalCycles` overflow samples and 51,318
in-module `DcacheMisses` overflow samples across the five main threads, with zero ETL events lost.
Intervals were 65,536 cycles and 4,096 data-cache-miss events. This estimates 13,209,305,088
in-module cycles across 28,224,000 gate-instances, or **468.017 cycles per instance-gate**. A
separate five-run `QueryProcessCycleTime`/CPU-time clock derivation produced a median 485.304
cycles per instance-gate; the PMU overflow count is the direct figure used below.

| Mutually exclusive in-module category | Total-cycle samples | Share |
| --- | ---: | ---: |
| Fused reducer loop: bucket index/load/store plus compiler-inlined operations | 110,979 | 55.061% |
| Explicit field add/subtract/reduce/construction | 55,572 | 27.571% |
| Accumulator bucket-table lookup/update | 25,143 | 12.474% |
| Field multiplication | 6,091 | 3.022% |
| Table build/finalization | 3,754 | 1.862% |
| Allocation | 8 | 0.004% |
| Other symbolized module work | 11 | 0.005% |

The 12,452 main-thread cycle samples outside the benchmark module are reported separately and are
5.818% of all main-thread cycle samples. Compiler inlining makes the 55.061% fused-loop row
inseparable at source-line granularity; it contains Boolean/word/indexing work plus inlined
operations and must not be relabeled as pure arithmetic.

The PMU estimates 15.9129 `DcacheMisses` events per 1,000 in-module cycles. Miss-overflow samples
landed 45.125% in the fused reducer loop, 39.873% in explicit field add/sub/reduction, 12.736% in
bucket-table updates, 1.173% in table build/finalization, 1.087% in multiplication, and 0.002% in
allocation. This is a cache-miss proxy, **not a stall-cycle percentage**: the Ryzen/Windows HAL
exposes `DcacheMisses` but no memory-stall-cycle source, and sampled PMU interrupts can skid beyond
the causative load. Exact memory-stall cycles are therefore not separately observable in this
environment and are not invented here.

Decision: the existing reducer is **not multiplication-dominated**. There is no per-gate Fp16
multiplication in `add_gate`; the measured multiply share is 3.022% and is mostly fixed
`mul_by_m31` finalization. The kernel is near a word/indexing, bucket-memory, and Fp16-add/sub floor.
Consequently, a bucketing change justified as amortizing per-gate Fp16 multiplication is not
supported by this profile. The Phase 2.0 B=64 measurement spike remains pre-authorized, but its
value is lower and it must be judged against the measured 468.017-cycle B=8 figure.

PMU trace SHA-256:
`6DD634006EE8F6F695D2EAB72F6E3480F0AC7A1C54A7845AE325200D423F9A2F`.

## 2026-07-28 Phase 2.0 B=64 kernel spike — MEASURED, NONPROTOCOL

Scope: execution-order Phase 2.0 only. The spike is a standalone binary and is not wired into the
prover, verifier, transcript, masks, codec, or production build. It grants no protocol,
qualification, or activation credit.

### Source and construction

The source delta for this step is:

- modified `experiments/bl_pq512_crypto_core/Cargo.toml`; and
- added a standalone B=64 spike binary that was removed from the active tree on 2026-07-31 and
  remains recoverable only through Git history.

The candidate packs 64 instances per `u64`. It does not construct a flat `2^64` table. Each word is
split into eight 8-bit chunks. A 1,121,284-byte public table contains chunk evaluations over the
127 points needed for the degree-126 gate relation plus the 64- and 127-node interpolation bases.
The timed gate loop accumulates only M31 values in 256 deterministic fixture-weight classes; Fp16
is first used during final class weighting, interpolation, and multiplication by the degree-63
query polynomial. The M31 accumulator is 130,048 bytes. This is one concrete measurement candidate,
not a production-validity or general-equality-weight selection result.

The historical build commands are intentionally removed because the nonprotocol binary is no
longer an executable target.

The release build exited zero. It emitted three pre-existing library warnings: unused
`alloc::vec` in `merkle.rs`, unread `DualBoundaryFoldCommitmentProver::final_values`, and unused
`PackedBooleanAccumulators::merge` in the non-`parallel` build. The 4,097-word-gate self-check
exited zero and reported:

```text
mode=self_check
self_check_gates=4097
checked_lanes=64
degree_bound=189
parity=pass
```

One earlier formatting check is excluded. It passed `Cargo.toml` to `cargo fmt` as if it were Rust,
so rustfmt reported `expected item, found '['` after showing only formatting diffs for the new
binary. It changed no file. The new Rust file was then formatted directly as shown above.

### Full 782-permutation-shaped measurement

The full shape is 782 active permutations padded to 1,024 instances, 16 B=64 words, 44,100
word-gates per group, 705,600 word-gates total, and 45,158,400 represented Boolean
instance-gates. One uncounted warm-up exited zero. The five counted runs used Windows
`QueryProcessCycleTime`, sampled process working set every 5 ms, and required exit zero, empty
stderr, parsed timing, and a parsed digest:

| Run | Process cycles | Cycles / B=64 word-gate | Cycles / represented instance-gate | Reduction ns | Peak working set bytes |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 2,898,677,357 | 4,108.102830 | 64.189107 | 768,652,300 | 5,177,344 |
| 2 | 2,980,910,335 | 4,224.646166 | 66.010096 | 791,465,100 | 5,177,344 |
| 3 | 2,947,844,870 | 4,177.784680 | 65.277886 | 777,290,600 | 5,181,440 |
| 4 | 2,827,297,664 | 4,006.941134 | 62.608455 | 754,111,900 | 5,181,440 |
| 5 | 2,891,918,609 | 4,098.524106 | 64.039439 | 758,579,900 | 5,177,344 |

All five exited zero, wrote zero stderr bytes, and emitted SHA3-512
`5d0cd3b04c7a57fedd2714666bc1f2edace6f8eae92739b31ca4cfc645c4822a5a6cc80868472485259e5d766b45d7183d1458cab413c1c70ffecf335cc835ee`.
The medians are 2,898,677,357 process cycles, 4,108.102830 cycles per B=64 word-gate,
64.189107 cycles per represented Boolean instance-gate, and 768,652,300 reduction ns.

The exact timed-shape operation inventory printed by every run is:

```text
m31_table_lookups=1433779200
m31_chunk_accumulator_adds=1433779200
m31_relation_multiplies=89611200
m31_relation_and_accumulator_add_subs=291236400
```

One earlier five-process harness is excluded in full: five child processes exited zero, but the
PowerShell harness used the invalid literal `0UL` without fail-fast error handling. It therefore
printed null cycle/digest fields and zero derived values. Those five child executions are not
counted evidence. The corrected harness used `[UInt64]0`, fail-fast error handling, and
newline-robust parsing.

### Comparison and decision

The matching Phase 0 `QueryProcessCycleTime` B=8 median was 485.304 cycles per B=8 word-gate, or
60.663 cycles per represented Boolean instance-gate after dividing by eight. The B=64 median of
64.189107 is approximately 5.81% slower on that matching basis. The direct Phase 0 PMU figure was
468.017 cycles per B=8 word-gate, or 58.502125 per represented instance-gate; the B=64 process-cycle
median is approximately 9.72% slower than that differently instrumented reference. The direct-PMU
comparison is reported separately because module PMU samples and whole-process cycle counts are not
identical instruments.

Decision: this concrete B=64 tensor/evaluation design does **not** beat the B=8 kernel decisively.
It is rejected as the basis for Phase 2.6. No production B=64 implementation, transcript change, or
mask resize is authorized by this result.

### Mandatory post-step calibration rerun — PARTIAL, FAIL-CLOSED

Both exact release builds from Phase 0 exited zero. The reduced fixture and live commands completed
all ten requested runs:

- fixture: five exits zero, 7,489 authenticated rounds each, 16.7450216-17.2917339 seconds,
  29,996-30,930 ns average coin wait, maximum combined RSS 229,724,160 bytes, and the same fixed
  digest
  `c531f446cdf4f0df2af4cf33623fe88e456d8304ce342897a83989dda71fdc0c803b3ae7afe31c0dccd3ad22e43658320b2e4e1e746f17b6a0b342b6b4d596b6`;
- live: five exits zero, 7,489 authenticated rounds each, 17.5047252-17.7371130 seconds,
  130,679-132,050 ns average coin wait, maximum combined RSS 238,505,984 bytes, and five distinct
  digests as required.

System paging-file usage remained 5.9668216630823956% before and after each reduced run, but page-read
counters were nonzero; these controls still do not establish process-level no-swap evidence.

Both reference-shape commands failed closed on run 1 before any authenticated round:

```text
coherent GKR benchmark failed: input_header_or_length_invalid
```

The recorded boundary
`C:\Users\neers\Documents\Codex\2026-07-27\he\work\gkr-128-boundary.bin` is 32,784 bytes, SHA-256
`59412B4FDF2E53ADAE36628C7EBD9BC1C00A4930701415ABC23B3A821095BC76`, and has the exact header
`version=1, permutations=128, instances=128, width=2048`. That is the valid reduced-shape boundary.
The 782-permutation / 128-group command requires `permutations=782`, `instances=1024`,
`width=2048`, and 262,160 total bytes. One immutable boundary cannot satisfy both recorded commands.
The authoritative Phase 0 command record contains no boundary-regeneration step between the reduced
and reference runs.

Counts: two reference run-1 attempts failed with exit code 1 and zero rounds; the remaining eight
requested reference runs were skipped because each mode failed closed at its first run. No boundary
was rewritten or synthesized. The post-step calibration is therefore not complete, and continuation
requires an authoritative reference-boundary generation command or exact approved fixture.

### Owner-approved reference-fixture resolution — COMPLETE

On 2026-07-28 the owner explicitly approved generating a separately named zero-input reference
fixture. `work/generate-gkr-782-zero-boundary.ps1` generated and byte-for-byte read back
`work/gkr-782-zero-boundary.bin` with:

```text
length=262160
version=1
permutations=782
instances=1024
width=2048
payload_nonzero_bytes=0
sha256=29FAEC8DD71C30E79C973CCCAC0A86282AA8D0CEE3D876BAB3B39ED06EDE359C
```

Two generator attempts are excluded: Windows PowerShell rejected numeric literals containing
underscores before writing; the next attempt wrote the correct bytes but its readback check used an
unavailable `.AsSpan()` API. A third attempt used generic-call syntax that Windows PowerShell could
not parse; a following `Format-Hex` masked that script error by resetting the outer shell status.
The final generator uses `StructuralEqualityComparer`, outer fail-fast handling, full payload-zero
inspection, SHA-256 readback, and exited zero.

The five reference fixture runs then all exited zero, independently verified, used 8,785
authenticated rounds, emitted empty benchmark stderr, and reproduced fixed SHA3-512
`62752652268cff727ec9b5c72f9a2b29f680538dc1beee585513dac90c1c40bd4c9b79a355da9243c25f8761fe842036a143fe6f6e79ec089495bc2465e73121`.
Total time was 29.4654328-30.0514209 seconds, average coin wait was 30,527-31,379 ns, and maximum
combined RSS was 304,816,128 bytes.

The five reference live runs all exited zero, independently verified, used 8,785 authenticated
rounds, emitted empty benchmark stderr, and produced five distinct digests as required. Total time
was 30.5434522-31.7827307 seconds, average coin wait was 137,724-145,597 ns, and maximum combined
RSS was 312,795,136 bytes.

One outer fixture-set guard is excluded: all five fixture records were successful, but
`run-phase0-calibration.ps1` left `$LASTEXITCODE=1` from its final `nvidia-smi` cleanup, so the outer
shell incorrectly threw `g128_fixture_calibration_failed` after the completed set. The live set was
run separately and both sets were accepted from their five per-run JSON records, not the stale
shell variable.

The required post-Phase-2.0 calibration is now complete: 20 successful current runs, 10 fixture
digests internally stable by shape, 10 live digests fresh, and zero benchmark failures on the
approved shape-correct fixtures. Page-read counters and system paging-file usage still do not prove
the process-level no-swap release gate.

## 2026-07-28 Phase 2.1 bucketed sparse-sumcheck schedule — COMPLETE

Scope: execution-order Phase 2.1 only. `experiments/bl_pq512_crypto_core/src/gkr_sumcheck.rs`
now groups sparse terms by the current folded-table suffix, loads each suffix's zero/delta pair once,
and deterministically merges adjacent suffix buckets after each round. The public
`prove_sparse_terms` wrapper selects this implementation by default. The prior implementation is
retained only for tests and the non-default `control_reference` Cargo feature; release builds
therefore compile one selected path rather than dispatching at runtime.

The optimization preserves the transcript and proof representation. This exact fixed-seed check was
run:

```text
$env:CARGO_TARGET_DIR='C:\Users\neers\Documents\Codex\2026-07-27\he\work\cargo-target-phase2'; cargo test --release --locked --offline --features parallel gkr_sumcheck::tests::bucketed_sparse_schedule_is_byte_identical_for_three_fixed_seeds -- --exact --nocapture
```

It constructed the actual ordinal-5 Keccak layer for seeds 1, 17, and 123, compared the reference
and bucketed proof values and flattened encoded bytes, and verified each proof. Raw decisive output:

```text
test gkr_sumcheck::tests::bucketed_sparse_schedule_is_byte_identical_for_three_fixed_seeds ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 191 filtered out; finished in 0.83s
```

`cargo fmt --check` exited zero. The optimized fixture build with features
`parallel,bench_fixture_coin` and the control build with features
`parallel,bench_fixture_coin,control_reference` both exited zero and were warning-clean. An initial
focused build exposed two dead-code warnings in the control path; an initial control build exposed
four symmetric dead-code warnings in the bucketed path. The `cfg` boundaries were narrowed so each
release binary compiles only its selected implementation, and both builds were rerun warning-clean.
One calibration launcher attempt is excluded: it invoked Cargo from the workspace root, printed
`error: could not find Cargo.toml`, and started zero benchmark runs. The corrected launcher built
from `experiments/bl_pq512_crypto_core`.

### Mandatory post-step Phase-0 calibration

The four exact Phase-0 calibration shapes were rerun sequentially, five times each. All 20 benchmark
processes exited zero, all benchmark stderr files were empty, and the results below were parsed from
the 20 per-run JSON records:

| Set | Rounds | Total seconds min / median / max | Average coin-wait ns min / median / max | Maximum combined RSS bytes | Digests |
| --- | ---: | ---: | ---: | ---: | --- |
| 16 fixture | 7,489 | 16.4594007 / 16.5314242 / 16.6250736 | 29,208 / 29,725 / 30,266 | 229,707,776 | 1 fixed |
| 16 live | 7,489 | 17.0799285 / 17.2251522 / 17.3767730 | 123,898 / 125,500 / 127,953 | 238,518,272 | 5 distinct |
| 128 fixture, 782 permutations | 8,785 | 28.5243543 / 28.6891337 / 29.1840821 | 28,418 / 28,835 / 29,162 | 303,046,656 | 1 fixed |
| 128 live, 782 permutations | 8,785 | 29.3643872 / 29.5131941 / 29.6318235 | 119,995 / 120,890 / 122,656 | 312,778,752 | 5 distinct |

The reduced fixture digest remained exactly:

```text
c531f446cdf4f0df2af4cf33623fe88e456d8304ce342897a83989dda71fdc0c803b3ae7afe31c0dccd3ad22e43658320b2e4e1e746f17b6a0b342b6b4d596b6
```

The approved reference-shape fixture digest remained exactly:

```text
62752652268cff727ec9b5c72f9a2b29f680538dc1beee585513dac90c1c40bd4c9b79a355da9243c25f8761fe842036a143fe6f6e79ec089495bc2465e73121
```

Against the immediately preceding post-Phase-2.0 calibration, the measured total-time range endpoints
changed as follows: 16 fixture minimum -1.705706% and maximum -3.855370%; 16 live minimum
-2.426754% and maximum -2.031559%; reference fixture minimum -3.193839% and maximum -2.886182%;
reference live minimum -3.860287% and maximum -6.767534%. The preceding record did not retain
per-run values, so no before/after median delta is claimed. These wall-time improvements are
directionally consistent across all four sets, but they are calibration measurements rather than a
formal causal attribution benchmark.

Decision: Phase 2.1 is accepted. The three fixed-seed reference comparison, both fixed-fixture
full-chain digests, authenticated-round counts, live freshness checks, and verifier checks all
passed without a protocol-byte change.

## 2026-07-28 Phase 2.2 packed 25-checkpoint reverse walk — COMPLETE

`keccak_gkr_wiring.rs` now retains the packed input plus one packed post-round state for each of 24
rounds (25 checkpoints total). During the reverse walk it regenerates the first eight outputs of
the selected public nine-layer round, consumes the resulting nine layer inputs in reverse, and
releases that round before selecting the previous public checkpoint. Loop bounds, allocation sizes,
checkpoint indices, traversal, recomputation count, and cleanup depend only on the public 24x9
schedule and fixed instance count; no witness bit is inspected by the schedule. The coherent worker
requests already accepted a single packed `&[u64]` and retained no history, so their protocol was
unchanged. The nested retained-history chain remains available only as the differential reference.

The focused nine-layer chain test compared checkpointed and retained-history output values, proof
objects, terminal claims, and shard queries exactly, then verified the result:

```text
test gkr_sumcheck::tests::repeated_pack_chain_carries_nonlinear_bridge_between_layers ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 191 filtered out; finished in 3.06s
```

Both optimized feature selections built successfully. The first control-reference build emitted one
unused-import warning; the checkpoint imports were feature-gated and the control build was rerun
warning-clean. `cargo fmt --all --check` exited zero.

The mandatory current-binary calibration produced 20 accepted runs:

| Set | Total seconds min / median / max | Coin-wait ns min / median / max | Peak RSS bytes | Checkpoint / regenerated payload bytes |
| --- | ---: | ---: | ---: | ---: |
| 16 fixture | 16.0106338 / 16.1671940 / 16.1814998 | 29,365 / 29,652 / 30,341 | 221,913,088 | 819,200 / 393,216 |
| 16 live | 16.4784861 / 16.6330969 / 18.1296692 | 115,653 / 118,532 / 119,704 | 230,899,712 | 819,200 / 393,216 |
| 128 fixture, 782 permutations | 28.5384410 / 28.7301281 / 29.0360657 | 27,868 / 28,374 / 29,015 | 241,598,464 | 6,553,600 / 3,145,728 |
| 128 live, 782 permutations | 29.4346981 / 29.6835940 / 29.7491915 | 119,340 / 121,163 / 121,990 | 250,220,544 | 6,553,600 / 3,145,728 |

All 20 exited zero with empty benchmark stderr. Fixture digests remained exactly
`c531f446cdf4f0df2af4cf33623fe88e456d8304ce342897a83989dda71fdc0c803b3ae7afe31c0dccd3ad22e43658320b2e4e1e746f17b6a0b342b6b4d596b6`
and
`62752652268cff727ec9b5c72f9a2b29f680538dc1beee585513dac90c1c40bd4c9b79a355da9243c25f8761fe842036a143fe6f6e79ec089495bc2465e73121`;
live sets each had five distinct digests. Rounds stayed 7,489 and 8,785.

Against Phase 2.1, peak RSS changed by -7,794,688 bytes (16 fixture), -7,618,560 (16 live),
-61,448,192 (reference fixture), and -62,558,208 (reference live). Timing-range endpoint changes
were -2.726%/-2.668%, -3.521%/+4.333% (one slow live run), +0.049%/-0.507%, and
+0.239%/+0.396%, respectively; no speedup is claimed.

Ten earlier live runs are excluded because the live target had not been rebuilt and their stdout
contained no checkpoint telemetry. The corrected launcher was then rebuilt and rerun. Two
PowerShell summarizer attempts failed after the replacement runs completed (one parse-time variable
syntax error before any work; one relative-path read error after all runs); the accepted results
were independently parsed from the completed per-run JSON and stdout files.

Decision: Phase 2.2 is accepted. Proof bytes/digests, verifier claims, authenticated rounds, and live
freshness were preserved while reference-shape peak RSS fell by about 61-63 MB.

## 2026-07-28 Phase 2.3 `mul_by_m31` routing inventory — COMPLETE

Scope: execution-order Phase 2.3 and design item 1.5 only. The inventory counts syntactic
multiplication operations in the named active B=8 sparse-GKR and packed-finalization paths. It
separately excludes the nonprotocol B=64 spike and test-only code so those sites cannot inflate the
production count.

### Complete routing inventory

`Fp16::mul_by_m31` performs 16 canonical M31 coordinate multiplications. Four production call sites
qualify, and all four were already routed before this phase:

1. `packed_boolean_sumcheck.rs::lagrange_node_evaluations`: the inverse Lagrange denominator is M31;
2. `packed_boolean_sumcheck.rs::lagrange_query_polynomial`: each basis coefficient is M31;
3. `packed_boolean_sumcheck.rs::finish_packed_boolean_accumulators`: product-polynomial
   coefficients are M31; and
4. the same finalizer's left/right mask-polynomial coefficients are M31.

The named candidate inventory contains 12 nonqualifying multiplication operations:

- one in `equality_table`: the coordinate is a general authenticated Fp16 challenge;
- one hard-excluded `fold_multilinear` operation: the verifier coordinate is general Fp16;
- four in `gate_line`: `zero`, `delta`, and `fixed` are post-interpolation/general Fp16 values;
- five in `weighted_gate_quadratic`: `weight`, `gate_zero`, and `gate_delta` are general Fp16; and
- one in `finish_packed_boolean_combined`: both the combined coefficient and query-polynomial
  coefficient are general Fp16.

Boolean packed-table accumulation in `PackedBooleanAccumulators::add_gate` contains zero field
multiplications: it uses only Fp16 add/subtract operations and public u8 indexing. The M31 table
coefficients are consumed later by the two already-routed finalizer call sites above.

Counts: four qualifying production sites, all already routed; 12 nonqualifying named-path
operations; zero unresolved sites; zero new routing changes. Four `mul_by_m31` call sites in the
standalone B=64 nonprotocol spike and one test-only direct-evaluation call site are excluded from
the production count. Post-interpolation values and all transcript challenges remain Fp16. No
operation was forced through the base-field path.

### Algebraic identity and focused checks

The only source change in the crate is a deterministic randomized algebraic-identity KAT in
`src/field.rs`. It compares `value.mul_by_m31(scalar)` with
`value * Fp16::from_m31(scalar)` for 4,096 deterministic-random Fp16/base-field pairs plus the
M31 edge scalars zero, one, and negative one: 4,099 exact comparisons.

Exact focused command:

```powershell
$env:CARGO_TARGET_DIR='C:\Users\neers\Documents\Codex\2026-07-27\he\work\cargo-target-phase2'
cargo test --release --locked --offline --features parallel field::tests::mul_by_m31_matches_generic_fp16_product_for_random_vectors -- --exact --nocapture
```

Decisive output:

```text
test field::tests::mul_by_m31_matches_generic_fp16_product_for_random_vectors ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 192 filtered out
```

The existing packed subfield/direct-evaluation parity KAT also passed:

```text
test packed_boolean_sumcheck::tests::subfield_table_and_packed_reduction_match_all_eight_direct_evaluations ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 192 filtered out
```

`cargo fmt --all --check` exited zero. The two focused tests were launched concurrently against one
Cargo target and emitted `Blocking waiting for file lock on package cache` and
`Blocking waiting for file lock on build directory`; both completed successfully. All subsequent
builds and calibration sets were serialized. Both required release builds exited zero and were
warning-clean:

- fixture target `cargo-target-phase0-fixture`, features `parallel,bench_fixture_coin`; and
- live target `cargo-target-phase0`, feature `parallel`.

### Mandatory post-step Phase-0 calibration

All four exact calibration sets were run sequentially, five times each, using the approved reduced
and 782-permutation boundaries. All 20 benchmark processes exited zero; all 20 benchmark stderr
files were empty; all stdout records reported `coherent_chain_verified=true`,
`public_coin_independent_replay=true`, and `round_checkpoint_count=25`.

| Set | Rounds | Total seconds min / median / max | Average coin-wait ns min / median / max | Maximum combined RSS bytes | Digests |
| --- | ---: | ---: | ---: | ---: | --- |
| 16 fixture | 7,489 | 17.5466941 / 18.4194603 / 18.6621273 | 32,686 / 36,953 / 38,358 | 223,899,648 | 1 fixed |
| 16 live | 7,489 | 18.1646651 / 18.2729101 / 18.7221510 | 160,491 / 161,201 / 167,440 | 233,594,880 | 5 distinct |
| 128 fixture, 782 permutations | 8,785 | 30.1829535 / 30.6373566 / 31.3070360 | 32,540 / 34,132 / 34,898 | 243,818,496 | 1 fixed |
| 128 live, 782 permutations | 8,785 | 31.6038960 / 32.4675923 / 34.4025865 | 166,320 / 172,299 / 195,588 | 252,448,768 | 5 distinct |

The reduced fixture digest remained exactly:

```text
c531f446cdf4f0df2af4cf33623fe88e456d8304ce342897a83989dda71fdc0c803b3ae7afe31c0dccd3ad22e43658320b2e4e1e746f17b6a0b342b6b4d596b6
```

The approved reference-shape fixture digest remained exactly:

```text
62752652268cff727ec9b5c72f9a2b29f680538dc1beee585513dac90c1c40bd4c9b79a355da9243c25f8761fe842036a143fe6f6e79ec089495bc2465e73121
```

Against Phase 2.2 medians, total time changed by +2.2522663 seconds / +13.931% for 16 fixture,
+1.6398132 seconds / +9.859% for 16 live, +1.9072285 seconds / +6.638% for reference fixture, and
+2.7839983 seconds / +9.379% for reference live. No production hot-path routing changed, so no
causal slowdown or speedup is attributed to Phase 2.3; these are exact current calibration
measurements.

System paging-file usage changed during some live runs and page-read counters were nonzero in all
sets. As in the preceding phases, these measurements do not establish the process-level no-swap
release gate. Requested calibration runs skipped: zero. Benchmark failures: zero. KAT mismatches:
zero. Fixture-digest mismatches: zero.

Decision: Phase 2.3 is accepted with the measured near-zero routing result. Every qualifying
production site was already routed, no additional site safely qualifies, and proof bytes/digests,
round counts, checkpoint counts, verification, and live freshness were preserved.

## 2026-07-28 Phase 2.4 owner ratification — RECORDED

The owner explicitly approved the two-layer Keccak-round collapse before the current execution
handoff. `docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md` item 3 and
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md` section 8.1.3 now record
`DESIGN-FROZEN-OWNER-RATIFIED-2026-07-28`. The ratification is limited to Phase 2.4 and does not
authorize the nonactivating streamed M31-symbol commitment or the rejected production B=64 kernel.

Implementation remains ordered and fail closed: first a standalone multi-factor sumcheck module and
naive-reference random-input KATs; only after those KATs pass may the two-layer schedule be added
behind a build flag. The 216-layer schedule remains the control.

## 2026-07-28 Phase 2.4 multi-factor kernel — KAT COMPLETE; SCHEDULE HARD STOP

The first ordered Phase 2.4 step is implemented as its own
`experiments/bl_pq512_crypto_core/src/multi_factor_sumcheck.rs` module. It supports one to 11
publicly wired multilinear factors, low-bit-first rounds, explicit message-before-authenticated-
challenge state, exact terminal-factor verification, and no Fiat--Shamir path.

The exact random-input KAT command was:

```powershell
$env:CARGO_TARGET_DIR='C:\Users\neers\Documents\Codex\2026-07-27\he\work\cargo-target-phase2'
cargo test --release --locked --offline --features parallel multi_factor_sumcheck::tests::random_shifted_mle_rounds_match_naive_reference_exactly -- --exact --nocapture
```

Decisive raw output:

```text
test multi_factor_sumcheck::tests::random_shifted_mle_rounds_match_naive_reference_exactly ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 194 filtered out; finished in 0.20s
```

That KAT covers 12 deterministic-random cases over fan-in 1, 3, and 11. For every round it evaluates
the product of independently shifted MLEs naively at every integer interpolation node, independently
interpolates the result, and compares every coefficient exactly. It also compares every terminal
factor to an independent MLE evaluation and runs the sequential verifier.

The fail-closed shape/order KAT also passed:

```text
test multi_factor_sumcheck::tests::malformed_shapes_and_transcript_order_fail_closed ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 194 filtered out
```

`cargo fmt --all --check` exited zero.

### Hard-stop condition: frozen degree/mask count omits the output-claim factor

No two-layer schedule, build flag, mask resize, transcript change, or control-path change was
implemented. Exact source inspection found that the ratified 12/4 coefficient requirement is one
coefficient short for both merged layers under the existing GKR claim-binding invariant:

- `gkr_sumcheck.rs::layer_terms` constructs the output-claim equality table and assigns an
  `output_weight` to every gate;
- `gkr_sumcheck.rs::weighted_gate_quadratic` multiplies that affine bit-basis weight by the
  partially bound gate polynomial; and
- the existing fan-in-two path therefore emits a quadratic, not linear, round polynomial.

The same invariant applied to a merged layer adds one affine equality-weight factor. A merged-theta
parity product has 11 affine input factors, so its claim-bound round polynomial has degree 12 and
requires 13 coefficients. A merged chi+iota relation has degree 3, so its claim-bound round
polynomial has degree 4 and requires 5 coefficients. The minimal witness is direct:

```text
theta: (x * x * x * x * x * x * x * x * x * x * x) * x = x^12
chi:   (x * x * x) * x = x^4
```

The final `* x` is the nonconstant output-claim equality factor. Omitting it would leave the output
claim host-trusted; forcing 12/4 coefficients would truncate a potentially nonzero highest-degree
term. Increasing the masks to 13/5 would contradict the explicit handoff requirement to resize for
degree 11/12 coefficients and degree 3/4 coefficients. This is an unresolved trust-critical design
conflict, so execution stops before schedule implementation rather than improvising a protocol
change.

Counts at stop: standalone kernel KAT failures zero; malformed/order KAT failures zero; schedule
files changed zero; build flags added zero; control layers deleted zero; forward-equivalence inputs
run zero because the schedule is blocked before implementation; full-chain comparisons run zero for
the same reason; Phase 2.4 calibration runs skipped 20 because no candidate schedule exists to
calibrate.

## 2026-07-28 Phase 2.4 13/5 owner correction — AUTHORIZED; PRIOR STOP CLEARED

The owner explicitly approved 13/5 and directed Phase 2.4 and subsequent authorized roadmap work to
continue. The intrinsic merged-theta and merged-chi+iota relations remain degree at most 11 and
degree 3. The existing nonconstant output-claim equality factor raises the claim-bound
round-polynomial degrees to at most 12 and 4, so the authoritative round-message and mask sizes are
13 coefficients for theta and 5 coefficients for chi+iota.

This exact 13/5 authorization supersedes the execution order's earlier 12/4 estimate and clears the
hard stop above without removing or host-trusting the equality factor.
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md` section 8.1.3 and
`docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md` item 3 record the correction. The standalone
multi-factor-kernel KAT remains the completed first Phase 2.4 step. The next action is to implement
the two-layer schedule behind a build flag alongside the unchanged 216-layer control, resize masks
to 13/5 before enabling it, and derive authenticated and coin-round counts from the built schedule
rather than accepting the projected 2,624 or 1,984 figures.

Because the first automatic context compaction occurred immediately after the authorization, no
schedule source, build flag, or mask implementation was changed in this bounded recovery step.
Forward-equivalence inputs run in this step: zero. Full-chain comparisons run in this step: zero.
Phase 2.4 calibration runs in this step: zero. These are deferred, not waived, and all Phase 2.4
acceptance gates remain fail closed.

## 2026-07-28 Priority-Zero checkpoint and full-scale table audit — DIAGNOSIS COMPLETE

This audit was performed before any Phase 2.4 schedule implementation. It reconciles the measured
243,818,496-byte reference-fixture peak with the earlier multi-gigabyte projections and inventories
the multiplicative/exponential tables in the active coherent GKR plus PCS path. No checkpoint-memory
change, protocol change, build flag, schedule change, or mask change was made in this audit.

### Actual benchmark and checkpoint path

The real coherent-chain benchmark uses the packed round-checkpoint path, not the nested-Boolean
retained-history control:

- `src/bin/gkr_coherent_chain_benchmark.rs:616-631` builds the 216-layer circuit, loads a packed
  boundary, calls `packed_keccak_gkr_round_checkpoints`, sums each checkpoint's
  `len() * size_of::<u64>()`, and drops the original boundary.
- `src/keccak_gkr_wiring.rs:375-395` returns `Vec<Vec<u64>>`: one packed input plus one packed
  post-round state for each of 24 Keccak rounds. Therefore `round_checkpoint_count=25` means 25
  separately allocated inner `Vec<u64>` buffers plus one outer `Vec` with capacity 25.
- Each retained checkpoint has dimensions
  `2,048 padded wires * ceil(padded_instances / 64) u64 words`; exact payload is
  `2,048 * padded_instances / 8` bytes.
- `src/keccak_gkr_wiring.rs:402-419` regenerates only one round for the reverse walk. It returns nine
  separately allocated packed `Vec<u64>` inputs: the checkpoint plus the first eight layer outputs.
  The sum of their padded wire widths is 24,576, so the exact simultaneous payload is
  `24,576 * padded_instances / 8` bytes. The ninth output is the next retained checkpoint and is not
  duplicated into this regeneration vector.
- The strict production-shaped benchmark sends each regenerated packed layer boundary and compact
  points to `GkrCompactPointWorkerRequest`
  (`src/bin/gkr_coherent_chain_benchmark.rs:991-1008`). The host factored-equality construction at
  lines 1510-1531 belongs to the non-strict control branch.

The measured reference fixture uses 782 real permutations padded to 1,024 instances, not the
113,730-permutation global K128 schedule. Its exact retained checkpoint payload is
`25 * 2,048 * 1,024 / 8 = 6,553,600` bytes and its exact one-round regeneration payload is
`24,576 * 1,024 / 8 = 3,145,728` bytes. Both equal the telemetry already recorded above. The
243,818,496-byte peak RSS is a combined process measurement and is not a checkpoint-payload
measurement; the checkpoints account for only 6,553,600 bytes of that peak.

### Reconciliation of the three earlier storage models

The nine current padded output widths sum to 24,576 per Keccak round. Across 24 rounds plus the
2,048-wire input boundary, full retention has
`2,048 + 24 * 24,576 = 591,872` wire positions per padded instance.

| Model | Exact K128 formula | Bytes | Actual status |
| --- | ---: | ---: | --- |
| Nested `Vec<bool>` full retention | `591,872 * 131,072` | 77,577,846,784 | Implemented only by `prove_repeated_pack_gkr_chain_reference`, compiled for tests or feature `control_reference`; not used by the benchmark/default checkpoint path. This is byte-per-Rust-`bool` payload before nested-vector metadata and allocator overhead. |
| Hypothetical packed full retention | `591,872 * 131,072 / 8` | 9,697,230,848 | Projection of packing every one of the 217 boundaries while retaining them all; no such allocation is made by the checkpoint benchmark. |
| Earlier raw-active checkpoint model | `25 * 113,730 * 1,600 / 8` | 568,650,000 | Hypothetical raw-state model. It omits both permutation padding to 131,072 and state-wire padding from 1,600 to 2,048, so it is not the current source allocation. |
| Current-source K128 checkpoints | `25 * 2,048 * 131,072 / 8` | 838,860,800 | Projected allocation of the implemented checkpoint function at the canonical global K128 geometry. |
| Current-source K512 checkpoints | `25 * 2,048 * 524,288 / 8` | 3,355,443,200 | Projected allocation at 411,406 permutations padded to 524,288 instances. |

`src/gkr_sumcheck.rs:2146-2196` proves the old 77.6-GB source: the feature-gated reference function
stores every boundary as nested `Vec<[Vec<bool>; 8]>`. The default function at lines 2320-2449
packs and checkpoints, regenerates one round at a time, and temporarily unpacks one layer for the
host control prover. `prove_repeated_pack_gkr_chain_control` selects the retained reference only
under feature `control_reference` at lines 2453-2489.

Decision: the numbers reconcile. They describe different geometry and different retention paths.
No checkpoint-memory fix is justified for the measured reference benchmark. However, the current
source's projected K512 checkpoint payload (3,355,443,200 bytes) plus one regenerated round
(1,610,612,736 bytes) is 4,966,055,936 payload bytes before worker, runtime, transcript, masks,
proof, and allocator overhead, so the existing checkpoint representation is not qualified for the
5,000,000,000-byte complete K512 gate.

### Active GKR equality and dense-worker inventory

`Fp16` is 16 nested canonical `u32` coordinates (`src/field.rs:77-79`, 170-175, 257-263,
347-352, and 438-444), so every host/device `Fp16` table below uses 64 bytes per element.

| Allocation | Producer and consumers | Dimensions / exact formula | Reference allocation | K128 projection | K512 projection | Lifetime |
| --- | --- | --- | ---: | ---: | ---: | --- |
| Host GKR equality table | `gkr_sumcheck.rs:232-254`; consumed by sparse-term/layer claim construction | `2^point_variables * 64` bytes | Factored wire/group tables; at most two claims, raw wire 3,200 gives 409,600 bytes and 128 groups gives 16,384 bytes | Wire 409,600; group 2,097,152 | Wire 409,600; group 8,388,608 | Temporary per layer/claim in host control paths |
| GPU compact wire equality | CUDA `derive_equality_table`, lines 55-82; consumed by compact term-weight derivation | `claim_count * raw_width * 64` | 409,600 bytes at two claims and raw width 3,200 | 409,600 | 409,600 | Persistent session slot, reused/grown |
| GPU compact group equality | Same producer/consumer | `claim_count * group_count * 64` | 16,384 bytes | 2,097,152 | 8,388,608 | Persistent session slot, reused/grown |
| Expanded GKR input | packed-input expansion, CUDA lines 1064-1097; consumed by folding | `input_width * group_count * 64` | maximum `524,288 * 64 = 33,554,432` | `67,108,864 * 64 = 4,294,967,296` | `268,435,456 * 64 = 17,179,869,184` | Persistent session slot, reused/grown |
| Term weights | compact weight derivation, CUDA lines 892-907; consumed by round reduction | `raw_width * group_count * 64` | `409,600 * 64 = 26,214,400` | `52,428,800 * 64 = 3,355,443,200` | `209,715,200 * 64 = 13,421,772,800` | Persistent session slot, reused/grown |
| Left/right term indices | compact derivation, CUDA lines 893-894 | two tables, each `term_count * 4` | 1,638,400 each | 209,715,200 each | 838,860,800 each | Persistent session slots, reused/grown |
| Gate formula | compact derivation, CUDA line 895 | `term_count` bytes | 409,600 | 52,428,800 | 209,715,200 | Persistent session slot, reused/grown |
| Left/right factors | CUDA lines 1099-1124; consumed and folded through authenticated rounds | two tables, each `term_count * 64` | 26,214,400 each | 3,355,443,200 each | 13,421,772,800 each | Persistent session slots, reused/grown |
| Fold A/B | CUDA lines 1126-1128; alternating folding buffers | two tables, each `input_count * 64` | 33,554,432 each | 4,294,967,296 each | 17,179,869,184 each | Persistent session slots, reused/grown |

The Rust request encoder computes `input_count=input_width*groups` and
`term_count=raw_width*groups` at `src/gkr_worker.rs:461-469`. The reference shape reaches the
existing caps exactly: `input_count=4,096*128=524,288` and
`term_count=3,200*128=409,600`. Lines 476-482 reject larger requests before transport. Therefore
the measured 243-MB benchmark exercises only the capped reference geometry; the current worker does
not execute canonical K128 or K512. Raising the caps alone is forbidden because the dense buffers
above independently exceed the 5-GB gate.

The GKR equality lookup is already split/factored by wire and group variables and is small relative
to the dense expanded-input, term-weight, factor, and fold buffers. Replacing only this equality
table would neither make K128 executable nor make K512 fit. The required future correction is a
streamed/factored sparse-round architecture that also avoids materializing the multiplicative
`input_width*groups` and `raw_width*groups` buffers. It must receive differential KATs before any
performance claim.

### PCS exponential table inventory

`src/multilinear_batch_sumcheck.rs:100-116` and 435-469 produce equality vectors with
`2^point_variables` `Fp16` elements. The current PCS constants are fixed at input log 21, hidden
polynomial log 22, and LDE log 25 (`src/multilinear_pcs.rs:28-33`); this is the 1,024-instance by
2,048-wire reference boundary, not canonical K128/K512.

| Allocation | Producer and consumers | Exact formula | Current log-21 allocation | K128 log-28 projection | K512 log-30 projection | Lifetime |
| --- | --- | --- | ---: | ---: | ---: | --- |
| Packed-input base equality | `packed_opening_weights`, transcript lines 683-748 | each `2^(input_log-3) * 64`; two claims | 16,777,216 each | 2,147,483,648 each | 8,589,934,592 each | Temporary while constructing weights |
| Packed-output base equality | `packed_output_weights`, lines 781-834 | `2^(input_log-3) * 64` | 16,777,216 | 2,147,483,648 | 8,589,934,592 | Temporary while constructing weights |
| Packed opening/output weights | same functions; consumed by opening checks and batch sumcheck | each `2 * 2^input_log * 64` | 268,435,456 each | 34,359,738,368 each | 137,438,953,472 each | Retained in prepared PCS prelude |
| Main binding equality | prelude lines 1233-1252 and analogous combined-prelude path | `2^(input_log+1) * 64` | 268,435,456 each | 34,359,738,368 each | 137,438,953,472 each | Temporary, then folded into retained weights |
| Main input/output evaluation vectors | prelude inputs; consumed by opening checks and batch sumcheck | each `2^(input_log+1) * 64` | 268,435,456 each | 34,359,738,368 each | 137,438,953,472 each | Retained through prelude/sumcheck |

These tables are genuinely exponential, but the current constants and artifacts describe only the
reduced/reference PCS. A simple constant change does not create a full K128/K512 PCS: it would
materialize 34.36-GB or 137.44-GB vectors. Streaming only the equality generator is also
insufficient because the output weight and evaluation vectors are equally large. The required
change crosses equality generation, packed weight construction, opening accumulation, evaluation
storage, and sumcheck folding. No local PCS equality edit is made without an end-to-end
order-preserving design and differential proof/verifier KAT.

### Separate semantic AIR lookup representation

The selected semantic AIR prover is not called by `gkr_coherent_chain_benchmark` and is not indexed
by the Keccak permutation count. Its in-memory LogUp producer
`air_logup.rs::build_air_logup_oracle*` retains, per lookup/table interaction, `sides` inverse
columns of `trace_rows` Fp16 elements, one `trace_rows` accumulator, `sides` masked evaluation
columns of `2^evaluation_log_size` Fp16 elements, and one masked accumulator of that size. Exact
payload is
`64 * ((sides+1)*trace_rows + (sides+1)*2^evaluation_log_size)` bytes per interaction.
`air_composition.rs` consumes these columns; `oracle_commitment.rs:431-445` clones masked columns
into the interaction commitment constructor. The disk-selected path in `disk_logup.rs` builds the
natural inverse columns one interaction at a time, writes masked evaluation files, and retains file
metadata/tree state rather than every evaluation column.

There is no authoritative mapping from K128/K512 claim-slot profiles to one fixed semantic AIR
program's per-table `trace_rows`, `sides`, and `evaluation_log_size` in the coherent-chain benchmark;
therefore numeric K128/K512 LogUp bytes are not inferred here. Reduced/reference allocation is also
not measured by the coherent GKR benchmark. This separate pipeline is recorded rather than silently
counted as zero; its complete-proof resource qualification remains open.

### Audit decision and next boundary

The 243,818,496-byte measurement and the 77,577,846,784/9,697,230,848-byte projections reconcile
exactly. The large projections are not dead arithmetic, but they describe feature-gated or
hypothetical full-retention paths at canonical K128 geometry, not the exercised benchmark
allocation. The actual measured benchmark uses 25 packed checkpoints and one-round temporary
regeneration.

Priority-Zero diagnostic result: no checkpoint-memory source change is warranted. Full-scale
qualification is nevertheless blocked by demonstrated dense GKR-worker and PCS-vector
architectures, not by GKR equality lookup. Phase 2.4 may proceed at the existing approved
reference/control geometry behind a build flag, but no resulting benchmark may be labeled
full-K128, full-K512, or complete-proof qualification until those separately recorded full-scale
memory blockers are redesigned and measured under the 5-GB/no-swap gate.

## 2026-07-28 Phase 2.4 merged-wiring audit — HARD STOP BEFORE SCHEDULE IMPLEMENTATION

After the Priority-Zero memory diagnosis, the next Phase 2.4 action was exact source reconciliation
of the completed standalone multi-factor kernel with the ratified Keccak merged-layer wiring. That
reconciliation exposed two trust-critical incompatibilities. No two-layer descriptor, schedule,
build flag, mask, codec, transcript, prover, verifier, or control path was changed.

### The completed kernel cannot represent the frozen Keccak wiring

`multi_factor_sumcheck.rs:1-6` defines a factor as `f(x xor s)` for one constant public XOR shift.
`ShiftedMultilinearFactor` contains only an evaluation vector and that one `xor_shift`
(lines 15-19), and the prover constructs each factor table exactly as
`evaluations[index ^ xor_shift]` (lines 222-228). A constant XOR shift is a bijection of the
hypercube indices.

Merged theta is not such a shift. The theta output at `(x,y,z)` includes each source row of the
column parity at `(x-1,z)` and `(x+1,z-1)`. For a fixed source row, changing output `y` maps
different output indices to the same input index. Using the authoritative source layout
`bit(x,y,z)=64*(x+5*y)+z` from `keccak_gkr_wiring.rs:44-46`, the exact counterexample is:

```text
Factor                     Output  OutputIndex InputIndex RequiredXorShift
theta C[x-1,z], source y=0 (0,0,0)           0        256              256
theta C[x-1,z], source y=0 (0,1,0)         320        256               64
chi B[x+1,y,z]             (0,0,0)           0         64               64
chi B[x+1,y,z]             (1,0,0)          64        128              192
```

One factor would require two different XOR shifts (256 and 64) for the first two theta outputs.
It is also non-bijective because both outputs consume input index 256. The chi neighbor
permutation is bijective, but modulo-five `x` translation is not a constant XOR shift in the frozen
flattening: the two shown outputs require shifts 64 and 192. The existing nine-layer source confirms
the authoritative mappings at `keccak_gkr_wiring.rs:136-185` for theta and lines 187-227 for
rho/pi, chi, and iota.

Materializing a caller-prepermuted/repeated factor table would make the standalone polynomial KAT
pass, but its terminal value would be an opening of a new derived table, not an authenticated
opening of the committed input boundary. Accepting it would host-trust the wiring. Fixing that
requires a new authenticated wiring/permutation argument, additional committed derived tables, or
a generalized high-fan-in sparse GKR with explicitly verified terminal reductions. None of those
protocols, transcript effects, proof codecs, round counts, or mask/leakage effects is frozen by the
current authorization.

### The completed kernel also omits the claim-bound factor count

`MAX_MULTI_FACTORS` is 11 (`multi_factor_sumcheck.rs:13`), validation rejects more than 11
(lines 47-55), and the deterministic randomized KAT covers factor counts only 1, 3, and 11
(lines 346-405). The corrected theta message has 13 coefficients because the 11 intrinsic input
factors plus the nonconstant output-claim equality factor produce 12 multiplicative factors and
degree 12. The existing module therefore cannot emit or verify the authorized claim-bound
13-coefficient message. Raising the cap to 12 would be necessary but not sufficient; it would not
solve the non-XOR wiring and terminal-authentication problem above.

### Stop decision and counts

The architecture document itself says the collapse is a new multi-factor sumcheck, requires new
descriptors/equations/codecs/masks, and requires the compiler to freeze the exact factor list and
generated geometry before implementation. The current standalone kernel's factor representation is
not that exact factor list for Keccak.

Continuing would require inventing a trust-critical wiring argument and transcript beyond the
ratified design, so Phase 2.4 stops before source implementation. This is not the earlier 12/4
issue; the 13/5 correction remains authoritative.

Counts at this stop:

- Priority-Zero source/allocation diagnosis completed: one;
- checkpoint-memory fixes made: zero;
- standalone kernel source changes made after its accepted KAT: zero;
- two-layer schedule files changed: zero;
- build flags added: zero;
- mask dimensions changed: zero;
- 216-layer control files changed: zero;
- 10,000-case forward KAT inputs run: zero because no sound merged descriptor exists;
- full-chain proof/verifier comparisons run: zero for the same reason;
- Phase 2.4 calibration runs: zero because no candidate can be enabled;
- protected-path edits: zero.

The smallest decision needed is an owner-ratified proof topology for arbitrary merged Keccak wiring:
either (a) generalized high-fan-in sparse GKR with exact terminal reductions and measured round
accounting, (b) committed derived-factor tables plus their authenticated wiring proof, or (c) a
different exact index encoding together with a proof that every theta/chi factor is a verified
hypercube-affine map. A constant-XOR-shift kernel is disproven for the current frozen wire encoding.

Post-diagnosis verification reran both existing standalone-kernel gates without changing source:

```text
test multi_factor_sumcheck::tests::random_shifted_mle_rounds_match_naive_reference_exactly ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 194 filtered out; finished in 0.19s

test multi_factor_sumcheck::tests::malformed_shapes_and_transcript_order_fail_closed ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 194 filtered out; finished in 0.00s
```

`cargo fmt --all --check` exited zero with empty output. These results verify that the existing
constant-XOR kernel remains internally passing; they do not cure or qualify the Keccak wiring gap.

## 2026-07-28 bounded-replay GKR feasibility spike

The owner authorized a narrow feasibility signal before replanning the memory roadmap. The spike
changes only `experiments/bl_pq512_crypto_core/src/gkr_sumcheck.rs` under `#[cfg(test)]`; production
code, the 216-layer control, Phase 2.4 wiring, proof codecs, masks, transcript code, PCS code, build
flags, protected paths, and activation state are unchanged.

The test-only exact-replay prover retains neither the folded input vectors nor the per-term
left/right factor vectors. For each sparse round it regenerates the required partially evaluated
input value from an indexed canonical input oracle, recomputes equality factors from the accepted
challenge prefix and the gate index, and regenerates each sparse gate term and output-claim weight
from the frozen Keccak layer and claim point. It deliberately trades time for bounded retained
state.

One real Keccak sparse layer was compared against the existing reference prover. Every round
coefficient and both terminal values were equal because the complete `SparseLayerSumcheckProof`
objects compared equal; the existing verifier accepted the replayed proof.

```text
test gkr_sumcheck::tests::replayed_sparse_real_keccak_layer_is_exact ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 196 filtered out; finished in 83.49s
```

The replay path retains only the emitted per-layer proof vector as input width grows. Its exact
payload formula is `(6 * log2(input_width) + 2) * 64` bytes: 10,112 bytes at the projected K128
`2^26` repeated input width and 10,880 bytes at the projected K512 `2^28` repeated input width.
The focused assertion passed:

```text
test gkr_sumcheck::tests::replayed_sparse_payload_is_kilobytes_at_projected_full_widths ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 196 filtered out; finished in 0.00s
```

The unchanged three-seed bucketed/reference byte-equivalence control also passed:

```text
test gkr_sumcheck::tests::bucketed_sparse_schedule_is_byte_identical_for_three_fixed_seeds ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 196 filtered out; finished in 0.94s
```

`cargo fmt --all --check` exited zero with empty output.

Decision: this is a **positive GKR feasibility signal**, not a full memory qualification. It proves
that the dense folded-input and per-term factor tables are not required to preserve the exact
current sparse-layer proof messages. It does not measure full K128/K512 RSS, stream the packed input
source, cover the packed first-round accumulator, exercise masking/authenticated interaction across
the complete chain, solve the exponential PCS vectors/codewords, satisfy latency, or cure the
separate Phase 2.4 merged-Keccak wiring hard stop. The 83.49-second single-layer result also proves
that naive scalar replay is not a performance candidate; future work must add bounded tiles or a
streaming product-sumcheck without restoring size-proportional retention.

## 2026-07-28 streamed PCS entry-gate audit — HARD STOP BEFORE IMPLEMENTATION

The owner next required the PCS memory problem to be solved with all constraints and tests. The
authoritative execution order permits only one relevant bounded-memory commitment lane at Phase
1.6 and states: streamed M31-symbol input-layer commitment under an M31-linear code, Fp16
challenges, per-column SHA3-512 accumulation, and 16 independent uniform M31 hiding rows. It
explicitly requires four ECCC 2025/2054 checks and says **no implementation, no qualification
credit** until the owner records them as passed. The same order forbids changing the query count,
rate, digest size, SHA3-512 authority, M31/Fp16 field profile, or mask structure.

The official current paper was retrieved from ECCC TR25-166 revision 1:

```text
URL: https://eccc.weizmann.ac.il/report/2025/166/revision/1/download/
Bytes: 1,265,761
SHA-256: 8F2A31305B000527BCB7DBCA41A2AA91B0AC0457B3AD2C7345BE4E7D762BA526
Title: Optimal Proximity Gaps for Subspace-Design Codes and (Random) Reed-Solomon Codes
Authors: Rohan Goyal; Venkatesan Guruswami
Revision date: 2026-03-24
```

The paper's Definition 2.4 requires an `F`-additive code to have alphabet `Sigma = F^s` and to be
linear over the same field `F`. Section 4 states that all codes used there are `F`-additive. This
does not directly validate the Phase-1.6 wording:

1. A bare M31-linear code over M31 symbols is not closed under multiplication by a general Fp16
   verifier challenge. Therefore the Sigma/F decoupling check fails for that literal construction.
2. A possible repair is scalar extension: encode 16 M31 rows with one common M31 generator, pack
   the 16 symbols at each position in the canonical Fp16 basis, and treat the result as
   `C tensor_M31 Fp16`. That object is Fp16-linear. For such an exact construction, a nonzero Fp16
   codeword decomposes into 16 M31 codewords and its Fp16-symbol support is the union of their
   supports, so its symbol distance is at least the base code's distance.
3. The same scalar-extension argument would make an extracted Fp16 codeword decompose into 16 M31
   codewords only if the exact code uses the same M31 generator in every row and the extractor is
   proved for that scalar-extended code.
4. Avoiding near-capacity machinery is possible in principle by staying inside a proved
   unique-decoding radius, but it cannot be checked numerically until the exact code family,
   generator, rate, distance, block length, and extractor are frozen.

No exact M31-linear code family, generator, subspace-design parameters, block geometry, distance,
or extractor is selected in the execution order or repository for this lane. The paper proves its
Section-4 results for specified subspace-design code families; it does not make every M31-linear
code eligible. Consequently checks 2–4 above are conditional, not passed, and no sound test vector
or full-scale memory formula exists yet.

There is also a direct frozen-parameter conflict. The execution order's absolute prohibitions say
`No change to query count (stays 378)`, while the actual current source at
`experiments/bl_pq512_crypto_core/src/multilinear_pcs.rs:23` sets
`MLPCS_UNIQUE_QUERY_COUNT: usize = 473`. The current query codec, selected-opening geometry, proof
fixtures, and security comments use 473. Query count affects soundness, proof grammar, proof bytes,
and memory, so neither value may be silently selected or translated. The execution order itself
says any transcript ambiguity must stop at the nearest gate.

Stop decision: implementing a streamed PCS now would require inventing the exact code and its
knowledge-extraction/security interpretation, changing a trust-critical commitment topology before
the explicit owner gate, or weakening the gate. None is permitted. Existing reduced PCS tests
remain control evidence only and cannot qualify the missing construction.

Counts at this stop:

- official primary papers inspected: one;
- Phase-1.6 entry checks unconditionally passed: zero of four;
- conditional scalar-extension repair arguments identified: three;
- exact eligible M31-linear code families frozen: zero;
- streamed PCS source files changed: zero;
- PCS parameters/query/rate/masks changed: zero;
- PCS differential KATs added: zero because there is no approved construction to test;
- full K128/K512 PCS memory runs: zero for the same reason;
- protected-path edits: zero.

The smallest owner decision is to ratify an exact M31-linear code family and the scalar-extension
interpretation above, with its generator, block geometry, proved distance, unique-decoding bound,
and extractor, or to reject Phase 1.6 and authorize a different bounded-memory PCS topology. The
owner must also explicitly resolve whether 378 in the execution-order prohibition is superseded by
the implemented 473-query candidate or whether the source and every dependent proof/security
artifact must be redesigned back to 378. Only after both decisions can implementation and the
required root/opening/verifier/hiding/mutation/full-scale resource tests begin.

## 2026-07-28 PCS owner resolution and bounded-replay feasibility — POSITIVE, NOT ACTIVATED

The owner explicitly authorized the safest constraint-preserving resolution after the stop above:
retain the implemented 473-query source/proof/verifier boundary, preserve correctness, privacy,
strict-PQ security, proof compatibility, modularity, the 5,000,000,000-byte gates, and maximum
government auditability, and continue without waiting for another engineer. Therefore 473
supersedes the isolated `stays 378` sentence in the immutable execution-order input. The order file
remains byte-for-byte unchanged at its expected SHA-256
`C81D39A5153C35C0ACBEB0E40823707445EB813024F24DC832E249317F5C3F77` for provenance. The canonical
reconciliation is also recorded in `docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md`. Existing source,
proof grammar, verifier, fixtures, rate `1/8`, zero-PoW rule, and 473-query security calculation are
unchanged. The separate 945 authenticated-opening multiplicity is `2 * 473 - 1`; it is not a
contradictory unique-query count.

First-principles source tracing found a lower-risk memory lane than prematurely selecting the
unresolved Phase-1.6 M31 code. The existing hidden polynomial can be evaluated at every initial or
folded FRI position directly from:

- the canonical packed Boolean boundary;
- the existing fresh 64-byte secret mask seed, session, and domain-separated oracle ID; and
- the already authenticated fold challenges.

For fold round `r`, each source coordinate is evaluated at the already-fixed challenge for
coordinates below `r` and at the appropriate power of the current domain point above `r`. The data
term is the multilinear extension of the packed Boolean table. The mask term is the existing
monomial mask polynomial multiplied by the unchanged appended-high-variable factor. This is an
algebraic replay of the current Fp16 hidden polynomial, not a new code, field, transcript, hiding
scheme, proof format, or verifier rule.

An isolated nonactivating module, `src/streaming_mlpcs.rs`, now implements that exact replay
reference. It retains no full evaluation, equality-weight, mask-coefficient, codeword, or folded
layer vector. Its exact internal retained-state formula is
`64 * variables + 64 * (lde_log_size + 1) + 128` bytes: 4,032 bytes for projected K128
`variables=28, lde_log_size=32`, and 4,288 bytes for projected K512
`variables=30, lde_log_size=34`. These figures exclude caller-owned packed source bytes and the
proof being emitted. Two packed Boolean boundaries require 67,108,864 bytes at K128 and 268,435,456
bytes at K512. The generalized current fixed-query grammar projects approximately 32,786,571
batched fold-query bytes at K128 and 36,974,219 bytes at K512. Retaining encoded proof plus one
decoded copy is therefore tens of megabytes, not kilobytes; claiming total PCS memory of only a few
kilobytes would be false. The architecture target is no gigabyte-scale object, not a physically
impossible value below its own proof bytes.

The differential replay tests passed:

```text
running 4 tests
test streaming_mlpcs::tests::replay_engine_state_is_kilobytes_at_projected_full_widths ... ok
test streaming_mlpcs::tests::replayed_product_sumcheck_messages_match_dense_folds_exactly ... ok
test streaming_mlpcs::tests::replayed_layer_has_identical_root_frontier_openings_and_rejection ... ok
test streaming_mlpcs::tests::replayed_values_match_every_dense_fri_layer_exactly ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 197 filtered out; finished in 0.07s
```

The first test covers the derived K128/K512 retained-engine bytes. The second requires identical
degree-two product-sumcheck messages at every round and identical terminal values without retaining
the prelude's folded tables. The third requires identical SHA3-512 roots, canonical Merkle frontier
bytes, and opened values, then mutates one value and requires independent authentication failure.
The fourth compares every position in every fold layer, including the final constant layer, against
the current materialized NTT-and-fold control.

The active file/worker opening function also contained a genuine avoidable full-layer allocation:
`build_stream_layer_opening` streamed payload slabs but retained one 64-byte hash for every leaf.
It now feeds the existing one-pass `build_recomputed_layer_opening`, whose retained state is the
exact query frontier plus a logarithmic SHA3-512 stack. The existing file-backed parity and
noncanonical-value rejection control passed unchanged:

```text
running 1 test
test multilinear_pcs_query::tests::file_backed_opening_and_mix_match_memory_and_reject_noncanonical_values ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 199 filtered out; finished in 0.05s
```

`trace_mask.rs` now also exposes a replay iterator over the existing domain-separated SHAKE256 Fp16
mask stream. The existing vector sampler collects that iterator, so the entropy source, rejection
sampling, domains, coefficient order, and bytes are unchanged. The exact mask KAT requires two
independent replay passes to equal the existing vector and passed:

```text
running 1 test
test trace_mask::tests::sampled_masks_are_reproducible_separated_and_preserve_trace ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 200 filtered out; finished in 0.00s
```

The containing release/locked/offline/parallel library suite and no-default-features build passed:

```text
running 201 tests
...
test result: ok. 201 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 87.81s
```

```text
cargo check --release --locked --offline --no-default-features --lib
Finished `release` profile [optimized] target(s) in 6.85s
```

The no-default-features check emitted four pre-existing warnings: unused `vec` in `merkle.rs`,
unused `SparseTermBuckets::term_count`, unused non-parallel
`DualBoundaryFoldCommitmentProver::final_values`, and unused non-parallel
`PackedBooleanAccumulators::merge`. No new replay/PCS warning was emitted. `cargo fmt --all --check`
exited zero with empty output.

Worker-count reconciliation: each of the four current five-run Phase-0 calibration sets printed
`cpu_bridge_worker_count=16` and `gpu_worker_count=1`. Thus every one of the 20 accepted calibration
runs used the machine's 16 logical CPU workers for the CPU bridge and one single-owner GPU worker.
The group counts 16 and 128 are packed workload geometry, not worker counts. Older retained
calibration output contains the same worker lines; it is not mixed into the current 20-run set.

This is a **positive PCS memory-feasibility signal and one real allocation removal**, not complete
PCS qualification. The replay reference is not yet wired through mask streaming, prelude
sum-products, publish-before-challenge root construction, every opening regeneration, or the
complete GKR-plus-PCS prover. K128/K512 peak RSS has not been measured, and naive single-value replay
trades substantial time for memory. The owner explicitly removed speed as the current priority, so
that trade is admissible for the memory feasibility gate but not for later latency qualification.
The unresolved scalar-extended M31 code remains a separate nonactivating throughput candidate and
still receives zero qualification credit until its four ECCC checks pass.

Changed nonprotected source files in this step:

- `experiments/bl_pq512_crypto_core/src/lib.rs`;
- `experiments/bl_pq512_crypto_core/src/streaming_mlpcs.rs`;
- `experiments/bl_pq512_crypto_core/src/multilinear_pcs_query.rs`;
- `experiments/bl_pq512_crypto_core/src/trace_mask.rs`;
- `docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md`;
- `STATE.md`.

Protected-path edits: zero. PCS parameters changed: zero. Proof/verifier grammar changed: zero.
Activation changes: zero.

## 2026-07-28 lean-streaming speed audit — MECHANICS PASS, CODE SELECTION OPEN

The bounded-replay spike was extended only inside the nonactivating
`src/streaming_mlpcs.rs` module and its tests. This audit corrects one full-scale projection,
rejects scalar output-by-output replay as a throughput architecture, and tests the two bounded
mechanisms needed by a replacement. It changes no field, code rate, query count, transcript,
commitment, proof grammar, verifier, hiding rule, GKR schedule, protected path, or activation state.

### Full-scale geometry correction

The earlier PCS replay paragraph incorrectly reused the repeated GKR worker dimensions
`2^26`/`2^28`. Those are `4,096 * group_count` Fp16 worker-table dimensions. The PCS producer at
`src/bin/gkr_coherent_chain_benchmark.rs:2016-2131` instead commits the full Boolean shard
dimension: `2,048 wires * 8 shards * group_count`, agreeing with the prior allocation audit's
PCS input logs 28/30 at `STATE.md:1880-1891`.

The corrected projections are:

| Quantity | K128 | K512 |
| --- | ---: | ---: |
| PCS data variables | 28 | 30 |
| Hidden-polynomial log size | 29 | 31 |
| Rate-1/8 LDE log size | 32 | 34 |
| Replay-engine internal state | 4,032 bytes | 4,288 bytes |
| Two packed Boolean source boundaries | 67,108,864 bytes | 268,435,456 bytes |
| Generalized batched fold/query proof | 32,786,571 bytes | 36,974,219 bytes |

The proof projection advances by 4,187,648 bytes for every two added input variables, matching the
current fixed 473-query canonical frontier geometry. It remains a projection, not an encoded
full-scale proof.

### Scalar replay is a rejected speed architecture

`replayed_fri_layer_value` scans all data evaluations and all mask coefficients for each output.
The exact initial-layer source-term visits are therefore
`2 * 2^input_log * 2^lde_log`: `2^61 = 2,305,843,009,213,693,952` at K128 and
`2^65 = 36,893,488,147,419,103,232` at K512. Output tiling changes retained bytes but not either
count. Even an impossible optimistic rate of one trillion complete source-term visits per second
would require about 640.51 hours for K128 and 10,248.19 hours for K512 for this first layer alone;
one real visit actually contains multiple Fp16 operations. Scalar replay is retained only as a
differential oracle.

The exact count gate passed:

```text
running 1 test
test streaming_mlpcs::tests::tiling_does_not_cure_scalar_replay_work_at_full_scale ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 201 filtered out; finished in 0.00s
```

### Two-pass codeword mechanics

A test-only deterministic linear encoder exercised the intended bounded shape:

1. stream codeword leaves in canonical order and publish the SHA3-512 root;
2. receive verifier-derived queries;
3. replay the same encoder once, capture only queried leaves and the canonical Merkle frontier;
4. independently verify the opening.

The replayed root, dense-control root, opened leaves, and exact frontier bytes were equal. The
test retains one leaf payload plus the logarithmic Merkle stack/frontier, not a codeword. A second
KAT used two general non-base Fp16 scalars and proved
`Encode(alpha*x + beta*y) = alpha*Encode(x) + beta*Encode(y)` for a generator containing only
base-field unit coefficients. This validates the scalar-extension engineering identity, not the
toy code's distance, extractor, or security.

```text
test streaming_mlpcs::tests::two_pass_linear_encoder_replay_matches_dense_commitment_and_openings ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 203 filtered out; finished in 0.00s

test streaming_mlpcs::tests::base_generator_is_linear_under_general_fp16_challenges ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 203 filtered out; finished in 0.00s
```

### Sequential product-sumcheck mechanics

The prior replayed product-sumcheck evaluator recomputed a complete multilinear evaluation for
each suffix point. The new `streamed_product_round_coefficients` folds each contiguous accepted-
challenge prefix block directly. For every round it reads each of the two source tables exactly
once, retains only logarithmic recursion state and three coefficients, and emits the identical
degree-two message. The 10-variable KAT compared every round with the dense fold control, asserted
exactly `2^10` reads from each source at every round, and compared both terminal values.

```text
test streaming_mlpcs::tests::streamed_product_sumcheck_messages_match_dense_with_exact_read_count ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 204 filtered out; finished in 0.02s
```

This simple implementation is `O(N log N)` work for a complete product sumcheck. It is the readable
differential baseline, not the final throughput kernel. The primary TCC 2025 result “Time-Space
Trade-Offs for Sumcheck” gives product-multilinear prover time
`O(N * (log log N + k))` with `O(N^(1/k))` space; its exact adaptation to Blind Ledger's sparse
repeated Keccak relation, masks, and authenticated message order remains to be implemented and
differentially tested.

### Lean candidate and remaining hard gate

The smallest architecture still capable of satisfying both memory and latency is:

- deterministic packed-source streams;
- a theorem-backed sublinear-space product-sumcheck rather than scalar evaluation replay;
- a proved-distance, linear-time encodable code emitted in canonical order;
- one pre-query root pass and one post-query opening pass, with bounded parallel Merkle tiles;
- M31-row/base-generator arithmetic promoted through the frozen basis to full Fp16 challenges;
- streaming proof emission and independent streaming verification;
- unchanged SHA3-512 authority and authenticated interactive public coin.

The IACR papers “Query-Optimal IOPPs for Linear-Time Encodable Codes” (2025/1588) and
“Field-Agnostic SNARKs with Small Proofs via Encode-Repeat-Accumulate (ERA) Codes” (2026/864)
establish that linear prover time and `O(lambda)` query complexity are available for suitable
linear-time codes. The Block-Accumulate paper (2025/1828) supplies a faster-code comparison but
does not by itself freeze a Blind Ledger PCS. No paper benchmark receives local throughput credit.

The cryptographic code lane is **not selected**. The exact generator, rate, concrete minimum
distance, block/interleaving geometry, 392-bit error ledger, round-by-round extractor, native
hiding composition, and authenticated-public-coin transcript mapping are not yet frozen. Therefore
the four Phase-1.6 ECCC/code checks still do not all pass, and replacing the current PCS would be a
trust-critical invention. The two-pass and sumcheck KATs are a positive architecture-mechanics
signal, not full PCS feasibility, complete K128/K512 proof evidence, or qualification.

Changed nonprotected source in this audit: `src/streaming_mlpcs.rs`. Protected-path edits: zero.
PCS parameters changed: zero. Proof/verifier grammar changed: zero. Activation changes: zero.

### Containing verification

The complete release/locked/offline/parallel library suite passed after the corrected 28/30-variable
geometry and all three new mechanics KATs were present:

```text
running 205 tests
...
test gkr_sumcheck::tests::replayed_sparse_real_keccak_layer_is_exact has been running for over 60 seconds
...
test result: ok. 205 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 84.69s
```

`cargo fmt --all --check` exited zero with empty output. The no-default-features build also passed:

```text
cargo check --release --locked --offline --no-default-features --lib
warning: `bl_pq512_crypto_core` (lib) generated 4 warnings
Finished `release` profile [optimized] target(s) in 7.33s
```

The four warnings are the same pre-existing unused import/field/method findings recorded above.
Strict Clippy reproduced the same 29 pre-existing findings and emitted no finding for
`streaming_mlpcs.rs`:

```text
error: could not compile `bl_pq512_crypto_core` (lib) due to 29 previous errors
```

This archived workspace has no usable Git metadata: `git rev-parse --show-toplevel` fails from the
workspace and every ancestor, while `C:\Users\neers\Documents\Codex\.git` exists as an empty
directory. Therefore a Git diff/HEAD assertion cannot be produced from this copy. Exact current
SHA-256 values before this paragraph was appended were:

```text
38CA1810506B56E06A730C04F2A496352A51F542972B4C9E73D826B24D50D5C9  STATE.md
41FE8E7C2B54A943929722E3D0F2F19456333A20D272B8591E8B90D73C74983A  docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md
FC6D1C045730873AEECE6EF64D4F926D051CD9B92245B54D0EDC717FBFEA7196  experiments/bl_pq512_crypto_core/src/streaming_mlpcs.rs
```

### Documentation consistency correction

Two architecture documents still described the old 2,624/1,984 round projections with wording that
could be read as an instruction to use them. Both now state that these are historical planning
placeholders only, receive zero acceptance or calibration credit, and must be replaced by exact
authenticated-round and coin-round counts derived from each built schedule. The 13/5 mask sizes
remain authoritative. This is a documentation-only reconciliation; no schedule, build flag, mask,
proof, verifier, fixture, or source parameter changed.

## 2026-07-28 strict-Clippy cleanup - COMPLETE

The owner directed that Clippy cleanup precede the next memory decision. The existing strict
parallel-library command initially failed on 29 findings. The cleanup used behavior-preserving Rust
refactors rather than disabling or weakening the lint gate:

- named aliases replaced repeated protocol tuple/callback types;
- one private worker session and one public verifier expectation set became named records;
- feature-specific fields, methods, and imports are now compiled only with their consumers;
- iterator, lifetime, conversion, divisibility, and borrow simplifications preserve the same order
  and values;
- Keccak rho/pi loops now iterate the frozen rotation table directly;
- the test-only fixture-coin module moved under `src/bin/support/`, preventing Cargo from
  auto-discovering it as an empty standalone binary while preserving its existing feature-gated
  inclusion in `gkr_coherent_chain_benchmark`.

No new lint allowance or suppression was added, and no lint gate was downgraded or removed. No
field, code rate, query count, challenge, transcript, commitment, proof grammar, verifier equation,
hiding rule, GKR schedule, mask size, fixture value, activation flag, or protected path changed.

Final strict lint evidence:

```text
cargo clippy --release --locked --offline --features parallel --lib --message-format short -- -D warnings
Finished `release` profile [optimized] target(s) in 8.05s

cargo clippy --release --locked --offline --features parallel --all-targets --message-format short -- -D warnings
Finished `release` profile [optimized] target(s) in 0.46s

cargo clippy --release --locked --offline --all-features --all-targets --message-format short -- -D warnings
Finished `release` profile [optimized] target(s) in 11.68s

cargo clippy --release --locked --offline --no-default-features --lib --message-format short -- -D warnings
Finished `release` profile [optimized] target(s) in 6.15s
```

All four commands exited zero with zero warnings and zero Clippy findings. `cargo fmt --all --check`
also exited zero with empty output.

The final containing library suite passed:

```text
running 205 tests
...
test gkr_sumcheck::tests::replayed_sparse_real_keccak_layer_is_exact has been running for over 60 seconds
test gkr_sumcheck::tests::replayed_sparse_real_keccak_layer_is_exact ... ok

test result: ok. 205 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 84.25s
```

The moved fixture module's own feature-gated benchmark tests also passed:

```text
running 4 tests
test tests::scaled_terminal_binding_preserves_dynamic_group_dimension ... ok
test tests::canonical_input_rejects_inactive_lanes_and_padding_wires ... ok
test tests::zero_high_wire_coordinates_restrict_output_claim_to_sha3_digest_bits ... ok
test gkr_coherent_chain_benchmark_fixture_coin::tests::fixture_authentication_replay_and_domain_separation_hold ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.52s
```

Current SHA-256 values for the 19 changed nonprotected Rust files are:

```text
5DDBF12C5D0A2B715532C876290B153030549B0F92133D014B3A20B035378BAC  src/cross_domain.rs
1328CC1D99370E439B4465C30F66B6908C5608BE914BBF15F36A519674DF8336  src/fri_layer_multiproof.rs
4CBA220442469A722463E2A82705C2261F0C4688A632FB586340DC1A3EC7E2F2  src/gkr_sumcheck.rs
0256AA7187F904FA56B0FA1ADF98DA82935D6261AD91B9760957BAE8DC7F347C  src/gkr_worker.rs
7D3145E3D9265C79F8268AE33A670BCA9194C39AA3DA2AA449A0085C2E40FE9F  src/gkr_zk_mask.rs
AFABD9BA510B3F0E817EFD64B901905A4F87D2ADFD6D06A3CBD401241915144A  src/keccak_gkr_wiring.rs
3BA89E8AC08FE2C0B74E5C140CA05F5FDD7C810B250C578A27A52B27DCF3E3D5  src/merkle.rs
64D46CDB2D61482612636AC0DC4F7616C0A4B9B8400AA629B682325F320F8681  src/merkle_multiproof.rs
869108206E833CA5B99D3CDFB436A940E46F432B3102C6168DB8F1D0B4D277B4  src/multilinear_pcs_proof.rs
E1208842599B4AB586D099E9DFBDF975018DBE999CBCBD94B93DCB97F787DCBE  src/multilinear_pcs_query.rs
650FDCD827B5C3D65A6D51E83468A0FDDCB6D3278B1BCDA097B4C61DE473B17A  src/multilinear_pcs_transcript.rs
1ABDF71269F9185C66B5F918B36AE50E179829F95DE586133AA3F46EF30CB6A6  src/packed_boolean_sumcheck.rs
F3508C857FAA197AABDC76EBA6E4DE4FF24071C8C319E2D547DCAE0350F09A5A  src/sha3_coprocessor.rs
EF1C0C0B637DEF2870607639371019E047789DCDA4EC3E537BF160EB02C3C723  src/streaming_mlpcs.rs
F364EDD1A95DFBEB97175C29EA868EB6C39D6377254E210C3F7FD4544ED0D405  src/bin/gkr_coherent_chain_benchmark.rs
8F305DEFA8C6627562D878929215F8DF63F501BD4CED669CCCE5EF077B4DA5D3  src/bin/support/gkr_coherent_chain_benchmark_fixture_coin.rs
27DCFF67091399DF45B0525274F454A2CFE2B58B7DBC789F1BCE2674C3F97765  src/bin/gkr_compact_chain_benchmark.rs
66FEFB1B27DFDE0A27AA8E9B8A8178DF7D5A0E93313A31811D89E5DB3D8AA016  src/bin/gkr_cuda_worker_benchmark.rs
838FB591AB163BC0EC4C22970B1E89E3D1EE86E28D3DB093F20F5291BF216238  removed B=64 spike (Git history)
```

Protected-path edits: zero. Skipped Clippy findings: zero. Remaining Clippy warnings: zero.
Activation changes: zero.

## 2026-07-29 Construction 8.2 PCS correction and GKR-binding hardening

The 2026-07-28 BaseFold selection, 26.859692-second partial accounting, and 6,241-round schedule are
superseded where they conflict with this checkpoint. The seven-layer/B=16 relay-free GKR remains
selected. The nonactivating PCS attempt is now Construction 8.2 of ePrint 2026/391 over
random-padded interleaved Reed--Solomon codewords. EPrint 2025/1828 Block-Accumulate remains
comparison evidence only.

The exact K128 main instance is length 131,072, message length 65,536, random-padding length 2,048,
proximity `5/32`, and 1,600 queries. Nine auxiliary instances have length 8,192, message length
2,048, random-padding length 1,218, proximity `1/5`, and 1,218 queries. The measured current
security ledger is 392.179996538 bits main, 392.108419573 bits auxiliary, and 392.108419573 bits
composed.

The exact GKR component sum is 24.7958928 seconds. The successful segment-32 PCS control measured
3.586543 seconds for initial mechanics, 191.533 MB host peak, 1,612.185152 MB device allocation,
14.347776 MB initial-oracle multiproof, and 0.000000 MB scratch. The 28.3824358-second partial sum
leaves 1.6175642 seconds for every still-open stage and is not a complete-proof projection.
Segment 16 measured 6.449925 seconds, 164.966 MB host, and 873.986048 MB device; it is the
lower-memory fallback, not the current sub-30 throughput candidate.

The exact shared public-coin schedule is 5,821 rounds: 5,809 GKR and 12 PCS. The isolated
5,821-round dual-PQ control passed message-before-challenge ordering, ML-DSA-87 and
SLH-DSA-SHAKE-256f authentication, canonical encoding/decoding, independent replay, and replay
rejection in 1.267659 seconds with a 3.770467 MB bundle.

The GKR/PCS boundary is implemented in `src/fp16_zk_rs_gkr_binding.rs`. It accepts exactly two
unmixed 24-coordinate GKR claims, treats the low 16 coordinates as the coefficient point and the
high eight as the 256-word point, and derives the exact 512-word linear form plus batched target.
Its two focused Rust tests pass and reject claim count, point dimension, mixed coefficient, word
value, and target mutations.

`src/bin/fp16_zk_rs_theorem8_1_transcript.rs` stream protocol v3 now reads those GKR claims and the
authenticated batching challenge. It derives the linear form in Rust and verifies all 512 word
evaluations before releasing the first sumcheck challenge. It no longer accepts an authoritative
target or linear form from Python.

The production-geometry host integration KAT passed:

```text
kat=fp16_zk_rs_authenticated_sumcheck_v2
rounds=13
input_payload_mb=1.215944
sumcheck_message_mb=1.179648
public_coin_bundle_mb=1.243457
public_coin_head_auth_seconds=0.509042
native_sumcheck_compute_seconds=0.068330
public_coin_finish_replay_seconds=0.039969
integration_wall_seconds=0.862441
sampled_python_bridge_transcript_host_peak_mb=38.920
challenge_digest=653caaa0d60edf4b6897d03db2c15d2de9b3a352848ee5bb72afbcf7938a7a110bbded3b5fd3d79b234435a78d4826477dfdde890812db6309b3d65c4a8d76bd
ml_dsa_87_head_authenticated=true
slh_dsa_shake_256f_head_authenticated=true
message_before_challenge=true
sumcheck_chain_and_terminal_verified=true
independent_bundle_replay=true
sumcheck_ordinal_mutation_rejected=true
gkr_claims_authenticated_before_batch_challenge=true
gkr_linear_form_derived_in_rust=true
claimed_gkr_target_bound_before_sumcheck_challenge=true
gkr_claim_target_mutation_rejected=true
gkr_linear_form_mutation_rejected=true
launch_fiat_shamir=false
grinding_credit=false
complete_pcs_qualification=false
complete_proof_qualification=false
```

The standalone KAT uses 13 rounds because it separately authenticates the fixture GKR terminal
batch. In the real combined chain that round is already one of the 5,809 GKR rounds, so the exact
combined schedule remains 5,821.

`cuda/cuda_fp16_zk_rs_theorem8_1_k128_prototype.py` now computes full multilinear evaluations of
the committed fixture messages at two 16-coordinate coefficient points, builds two exact
24-coordinate fixture GKR claims, authenticates their batching message with the real dual-PQ
public coin, and sends only the claims, batching challenge, masks, and word values to Rust.
Its regenerated PTX is 2.042239 MB with SHA-256
`5DA70C0B7CBE84F34F8DEA49654C05E720AB1788DAD456A43ACC7A2166455610`.
This is binding and compilation evidence only; the actual B=16 GKR producer is still not joined.

The segment-32 geometry is now a durable source option rather than an ephemeral edit.
`BL_ZK_RS_INTERLEAVINGS_PER_SEGMENT` accepts only 16 or 32, the theorem grammar derives 35 or 19
trees, and the native verifier derives leaf size, data size, boundary, kind, and auxiliary
ordinals from the accepted grammar. Both cross-process KATs pass:

```text
segment-16: segment_count=35; proof_fixture_mb=57.710544;
verify_compute_seconds=0.688713; mutation_compute_seconds=0.618240;
fixture_build_and_verify_wall_seconds=2.904666

segment-32: segment_count=19; proof_fixture_mb=55.960528;
verify_compute_seconds=0.596635; mutation_compute_seconds=0.332884;
fixture_build_and_verify_wall_seconds=2.073357

all_roots_verified=true
all_leaf_mutations_rejected=true
all_frontier_mutations_rejected=true
all_root_mutations_rejected=true
proof_system_qualification=false
```

Construction 7.2/8.2 hiding mechanics, conditioned sumcheck sampling, exact query derivation, and
production query-view streaming pass the executable offline audit. The audit used 26.104 MB host
peak and is excluded from proof time. Native multiproof, answer-code, spot-check, semantic
transcript, public-coin, and mutation controls pass independently. These controls do not qualify a
complete proof.

Current open trust boundaries are:

1. replace deterministic fixture GKR claims with the actual B=16 GKR producer in the same
   authenticated coordinator;
2. bind the same committed RS source to those claims, not merely an equivalent regenerated fixture;
3. run the bounded semantic AIR concurrently and atomically join program/bus, roots, parameters,
   verifier identity, state/retry identity, and ordered 12-field statement;
4. close the complete GKR+PCS+coin+dual-PQ+retry error/security composition and full leakage
   boundary; and
5. run one fresh segment-32 K128 proof, then the required warm-up and ten unique p95 proofs.

Six `nvlddmkm` driver errors were recorded between 2026-07-29 08:37 and 09:05. A production GPU run
is unsafe until the driver is reset. No failed or pre-reset run receives qualification credit.
CPU/source verification and NVRTC PTX compilation remain safe. `proofSuiteId=null`, activation is
false, protected-path edits are zero, and complete proof qualification remains false.

Containing regression after the correction first reproduced the historical PowerShell startup
classification race: 233 Rust tests passed and
`gkr_worker::tests::malformed_and_stalled_workers_fail_closed` received `Err(Timeout)` instead of
the intended malformed-frame `Err(Protocol)`. The protocol did not accept anything. The test used
the same two-second deadline both for starting PowerShell and classifying the returned frame, so
full-suite host contention could consume the entire malformed-frame deadline before PowerShell
wrote its eight invalid bytes. The malformed case now has a 15-second startup/frame budget while
the separate stalled-worker case retains its 25-millisecond timeout. No parser, protocol, or
fail-closed check was weakened.

The focused worker attack passed five consecutive reruns. The containing release library suite
then passed:

```text
test result: ok. 234 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;
finished in 84.84s
```

Strict `cargo clippy --locked --offline --features parallel --all-targets -- -D warnings` initially
found one pre-existing `needless_range_loop` in `src/gkr_packed_binary_bridge_fp16.rs` and one
`manual_div_ceil` in `src/bin/fp16_zk_rs_theorem8_1_transcript.rs`. Both received mechanical,
semantics-preserving iterator/arithmetic corrections. The three exact B=16 bridge tests passed, and
the full strict Clippy gate then exited zero with no warnings. `cargo fmt --all --check` and
`cargo check --locked --offline --no-default-features --lib` also exit zero.

The fresh complete CPU KAT pass reports:

- Construction 8.2 hiding audit: 53.130368 MB simulated view, 24.662 MB host peak, every algebra,
  rank, distinctness, randomness-coverage, and conditioned-view flag true;
- answer-code verifier: 6.217900 MB production payload, 0.306343 seconds wall, 56.381 MB combined
  host peak, correct codewords and coefficient mutation checks true;
- authenticated GKR/PCS sumcheck v2: 13 rounds, 1.215944 MB input, 1.179648 MB sumcheck messages,
  1.243457 MB coin bundle, 0.882804 seconds wall, 38.859 MB host peak, all binding/order/replay
  mutations rejected;
- segment-16 and segment-32 native multiproof grammars: 35 and 19 trees, every root accepted and
  every leaf/frontier/root mutation rejected; and
- exact architecture coin control: 5,821/5,821 rounds independently replayed, 3.770467 MB bundle,
  and 1.336846 seconds total.

The security ledger still correctly prints
`iopp_implementation_complete=false`,
`canonical_communication_grammar_closed=false`,
`complete_simulator_implementation_verified=false`,
`cryptographic_composition_ledger_closed=false`, and
`complete_proof_qualification=false`. Those flags remain open because the actual GKR producer,
semantic/atomic join, and fresh full GPU proof have not run.

### Post-boundary-change containing reverification

The GKR/PCS binder now rejects a zero batching challenge in addition to malformed, mixed,
wrong-dimension, wrong-value, and wrong-target claims. After that final fail-closed change, the
complete release/locked/offline/parallel library suite passed again:

```text
test result: ok. 234 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;
finished in 84.42s
```

The production transcript binary was rebuilt, and the fresh authenticated host integration KAT
passed with 13 rounds, 1.215944 MB input, 1.179648 MB sumcheck messages, 1.243457 MB public-coin
bundle, 0.907082 seconds wall, and 38.908 MB host peak. ML-DSA-87 and
SLH-DSA-SHAKE-256f head authentication, message-before-challenge ordering, independent replay,
terminal-chain verification, and claim/target/form/ordinal mutation rejection were all true.
`complete_pcs_qualification=false` and `complete_proof_qualification=false` remained correctly
false.

At 2026-07-29 11:00 local time, the machine's last boot was 2026-07-29 02:33, before all six
`nvlddmkm` Event 153 errors recorded from 08:37 through 09:05. The required driver reset therefore
has not occurred. No production GPU proof was launched.

## 2026-07-29 transfer reconciliation and five-claim compact PCS correction

The ZIP-derived transfer intentionally omitted cache content and Git metadata. The 42 recovery paths
were treated as a recoverable transfer omission, not a contradiction. The authorized read-only
candidate root was
`C:\Users\neers\Documents\Codex\2026-07-08\you-are-working-on-the-blind\blind-ledger-claude-architecture-workspace\Blind Ledger Neer Version\blind-ledger-app-layer`;
the destination root was this active source tree. Every candidate and destination SHA-256 matches:

| Relative path under both roots | Expected SHA-256 | Actual SHA-256 | Result |
| --- | --- | --- | --- |
| `cache/foundation-runs/20260715T073140Z-foundation17-r21/terminal_manifest.json` | `7BCAF24F33130AEA258A58286B8121C4C19A89D7F2C9C691A77CA633CC69006F` | `7BCAF24F33130AEA258A58286B8121C4C19A89D7F2C9C691A77CA633CC69006F` | MATCH |
| `cache/implementation-runs/20260716T145548Z-local-implementation-wave-r25/run_manifest.initial.json` | `F874E3FD2B4694552A9EFA6891BFE5A89AD3B235E16A3F7A3C2801E109B5797C` | `F874E3FD2B4694552A9EFA6891BFE5A89AD3B235E16A3F7A3C2801E109B5797C` | MATCH |
| `cache/implementation-runs/20260716T145548Z-local-implementation-wave-r25/stages/06_k128_k256_k512_measurement.json` | `97495AFDE110B20A37C6ABA5AA62281FE96A91FD9A89A859CC4CE991743A306F` | `97495AFDE110B20A37C6ABA5AA62281FE96A91FD9A89A859CC4CE991743A306F` | MATCH |
| `cache/implementation-runs/20260716T145548Z-local-implementation-wave-r25/terminal_manifest.json` | `0B2560B3CE041513AA488AC47B13A25D48A99D53D444355DDDEB26B220104D14` | `0B2560B3CE041513AA488AC47B13A25D48A99D53D444355DDDEB26B220104D14` | MATCH |
| `cache/implementation-runs/20260716T145548Z-local-implementation-wave-r25/terminal_sha256.txt` | `F2F516EF2ED386E62D201620A5D3F0AA865DC24E057F2EC34BD2F0EC5744D685` | `F2F516EF2ED386E62D201620A5D3F0AA865DC24E057F2EC34BD2F0EC5744D685` | MATCH |
| `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/run_manifest.initial.json` | `E9D15D33BF1FDB9F904BE792DA7B79852EAF4F1F645A101DA9F52E0F6DB88048` | `E9D15D33BF1FDB9F904BE792DA7B79852EAF4F1F645A101DA9F52E0F6DB88048` | MATCH |
| `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/run_manifest.initial.sha256` | `E1FBA869F2522FC8953BA1DB4CC3440DF8E3996D087F5A9F82379D8AA616A106` | `E1FBA869F2522FC8953BA1DB4CC3440DF8E3996D087F5A9F82379D8AA616A106` | MATCH |
| `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/00_freeze_toolchain_and_collection.json` | `33C813F5FC080D9D5F1260C5BCFFBD1933E02F415A3EE7A05B1802B71ABBB0D0` | `33C813F5FC080D9D5F1260C5BCFFBD1933E02F415A3EE7A05B1802B71ABBB0D0` | MATCH |
| `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/01_official_upstream_cryptographic_implementability_review.json` | `194C992AE1B19D4927555F7190040CD279C2DF52330DA637E017F74DD59EF2B3` | `194C992AE1B19D4927555F7190040CD279C2DF52330DA637E017F74DD59EF2B3` | MATCH |
| `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/02_physical_air_calibration_matrix.json` | `AF1EB0A6E8D9F8AA5BFDDCB6DD530DD7BDE56F443159A373C506969AB70AD3B2` | `AF1EB0A6E8D9F8AA5BFDDCB6DD530DD7BDE56F443159A373C506969AB70AD3B2` | MATCH |
| `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/03_integrated_reference_hardening.json` | `4E0347BD44C931454DC011653D4E7D3C03BB1951E379205F02CBC7089ECC18C1` | `4E0347BD44C931454DC011653D4E7D3C03BB1951E379205F02CBC7089ECC18C1` | MATCH |
| `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/04_regression_and_exact_differential.json` | `A90E4BBED649765E3B240BB761355D7DAA68E40E1C6146D59DFBDF4FFF1410C3` | `A90E4BBED649765E3B240BB761355D7DAA68E40E1C6146D59DFBDF4FFF1410C3` | MATCH |
| `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/05_rust_platform_and_proof_gates.json` | `A9A92ADB62F3CDBD6EF0DB30A4C8A370E4126858B6FAEE115E7E3BAB6E920EA1` | `A9A92ADB62F3CDBD6EF0DB30A4C8A370E4126858B6FAEE115E7E3BAB6E920EA1` | MATCH |
| `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/06_cairo_solidity_hygiene_and_privacy.json` | `B5154A40B19AD0532CC933A4C66AFD60496B5BBF3020F245F0609CFDD388F7C2` | `B5154A40B19AD0532CC933A4C66AFD60496B5BBF3020F245F0609CFDD388F7C2` | MATCH |
| `cache/implementation-runs/20260718T134831Z-private-proof-engine-r28/terminal_manifest.json` | `AF78DF6039AD80FA8240952B7129143A63A201170BD17D8E79D15C2CF8C2302F` | `AF78DF6039AD80FA8240952B7129143A63A201170BD17D8E79D15C2CF8C2302F` | MATCH |
| `cache/implementation-runs/20260718T134831Z-private-proof-engine-r28/terminal_sha256.txt` | `F0EF95A6FA948BBB937C036C7E980404381271512D60912E080F66DC1B8300C1` | `F0EF95A6FA948BBB937C036C7E980404381271512D60912E080F66DC1B8300C1` | MATCH |
| `cache/implementation-runs/20260718T154911Z-proving-evidence-r29/terminal_manifest.json` | `D80EEAEAFDF552409D683618CCB6E61A150389B22802DDC1F4701B15D4246872` | `D80EEAEAFDF552409D683618CCB6E61A150389B22802DDC1F4701B15D4246872` | MATCH |
| `cache/implementation-runs/20260718T154911Z-proving-evidence-r29/terminal_manifest.sha256` | `F0E29EE8BF91C8804D60B36DBA8F3CA398E50F9BF29B24FDBBDF3689CF6AC32C` | `F0E29EE8BF91C8804D60B36DBA8F3CA398E50F9BF29B24FDBBDF3689CF6AC32C` | MATCH |
| `cache/implementation-runs/20260718T170233Z-python-supply-chain-r30/terminal_manifest.json` | `B0176C5FB5B49DD584D10B0B3E2F668AF42EC2C5CD4D18A31B4A7D53DAA95A9D` | `B0176C5FB5B49DD584D10B0B3E2F668AF42EC2C5CD4D18A31B4A7D53DAA95A9D` | MATCH |
| `cache/implementation-runs/20260718T170233Z-python-supply-chain-r30/terminal_sha256.txt` | `8B04EEAFBB6437A0AC28805DF32CCD7D5CD3A141DD024F4986F0CE21519F6158` | `8B04EEAFBB6437A0AC28805DF32CCD7D5CD3A141DD024F4986F0CE21519F6158` | MATCH |
| `cache/implementation-runs/20260718T170233Z-python-supply-chain-r30/terminal_sha3_512.txt` | `EFFD5A31FFFF6DC8185178ED2176BD1A67CEBDE44B210CD286F515ECCEE5DB5C` | `EFFD5A31FFFF6DC8185178ED2176BD1A67CEBDE44B210CD286F515ECCEE5DB5C` | MATCH |
| `cache/implementation-runs/20260719T013047Z-s09-public-coin-r31/terminal_manifest.json` | `F7A60D3E00BF09181EDDC21E42FC9D51AACF5CDB6D410C294B90551185956FF8` | `F7A60D3E00BF09181EDDC21E42FC9D51AACF5CDB6D410C294B90551185956FF8` | MATCH |
| `cache/implementation-runs/20260719T013047Z-s09-public-coin-r31/terminal_sha256.txt` | `839261D0B906A8D5E24C54B363EE076B75840E446573093D1F97154E079A4344` | `839261D0B906A8D5E24C54B363EE076B75840E446573093D1F97154E079A4344` | MATCH |
| `cache/implementation-runs/20260719T013047Z-s09-public-coin-r31/terminal_sha3_512.txt` | `E3E8DF8E03EDE5833432653D434197B8CAD79A91810EE08BAFA851B363E23298` | `E3E8DF8E03EDE5833432653D434197B8CAD79A91810EE08BAFA851B363E23298` | MATCH |
| `cache/implementation-runs/20260719T034130Z-s09-crypto-core-r32/terminal_manifest.json` | `02858710479D2DDC75ACEB278CBC89452FB532C9F79FC48453560A7F44765598` | `02858710479D2DDC75ACEB278CBC89452FB532C9F79FC48453560A7F44765598` | MATCH |
| `cache/implementation-runs/20260719T034130Z-s09-crypto-core-r32/terminal_sha256.txt` | `054AFDFB7515537BE28B8BE0434F387D811AE5A4DECAEFF280EFB850639A9965` | `054AFDFB7515537BE28B8BE0434F387D811AE5A4DECAEFF280EFB850639A9965` | MATCH |
| `cache/implementation-runs/20260719T034130Z-s09-crypto-core-r32/terminal_sha3_512.txt` | `47324E16BB1C4DF4D91214FB0E2010F2470844C7A177D44DBE7EE9AE5041BD17` | `47324E16BB1C4DF4D91214FB0E2010F2470844C7A177D44DBE7EE9AE5041BD17` | MATCH |
| `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/run_manifest.initial.json` | `CF22526CA2EB6A33B3BDECDC7B292FB61858ECF7DC099478CDF7E798FDD9B065` | `CF22526CA2EB6A33B3BDECDC7B292FB61858ECF7DC099478CDF7E798FDD9B065` | MATCH |
| `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/stages/01_complete_relation_and_payment_maps.json` | `DD4260155290F246D526124D466EACA6B9A01153D8523857D08094FFF1812B34` | `DD4260155290F246D526124D466EACA6B9A01153D8523857D08094FFF1812B34` | MATCH |
| `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/stages/02_physical_relation_dimensions_and_measurement.json` | `9E4FD3AABDAEA4FBD8F03003038F51AC8470BDF2D4861BB0F7CF25BC27E9F580` | `9E4FD3AABDAEA4FBD8F03003038F51AC8470BDF2D4861BB0F7CF25BC27E9F580` | MATCH |
| `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/stages/03_final_convergence_and_integrity.json` | `0A3207075B72571E6DDAF32B96C3ED5D8852882F7996B79F1281E48DEFFBD114` | `0A3207075B72571E6DDAF32B96C3ED5D8852882F7996B79F1281E48DEFFBD114` | MATCH |
| `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/terminal_manifest.json` | `38D01BA36A92026E99A52C62BE2E8A1625DD0E5BA93C44BCBB73EC35D22CACFE` | `38D01BA36A92026E99A52C62BE2E8A1625DD0E5BA93C44BCBB73EC35D22CACFE` | MATCH |
| `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/terminal_sha256.txt` | `380266F5656F66D337FA7B75E0EF1B28339C457399C18AB8D13987FB7BEE18C5` | `380266F5656F66D337FA7B75E0EF1B28339C457399C18AB8D13987FB7BEE18C5` | MATCH |
| `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/terminal_sha3_512.txt` | `066838A35C54FCBCC4BB06FA3109ED8697499923E70EDA8AC5141B626E44A40C` | `066838A35C54FCBCC4BB06FA3109ED8697499923E70EDA8AC5141B626E44A40C` | MATCH |
| `cache/implementation-runs/20260719T164339Z-wave1b-theorem-backend-r35/run_manifest.initial.json` | `8E6F1A6A428F4A30E785ACB024648222790BCB71D936978AF5FE988B3079B8E4` | `8E6F1A6A428F4A30E785ACB024648222790BCB71D936978AF5FE988B3079B8E4` | MATCH |
| `cache/security-freeze-runs/20260715T202353Z-security-freeze-r23/terminal_manifest.json` | `298A3F627D6E58D7800A0FF8329CAD92796F164445C93543E0BF5F1F0B3D0E48` | `298A3F627D6E58D7800A0FF8329CAD92796F164445C93543E0BF5F1F0B3D0E48` | MATCH |
| `cache/security-scans/blind-ledger-app-layer/unversioned_20260713T112204Z/artifacts/fix_report.md` | `3F583D5C2CC36F4400910F1A388B1834BB0F79F17013A01456E24D646C6A4EAA` | `3F583D5C2CC36F4400910F1A388B1834BB0F79F17013A01456E24D646C6A4EAA` | MATCH |
| `cache/specification-runs/20260715T221859Z-s07-s12-freeze-r24/run_manifest.initial.json` | `B16DF11B1194D9B01CB22BDE319CDFFA9EDBD7793B26EEC34E39D67BD64B0FAB` | `B16DF11B1194D9B01CB22BDE319CDFFA9EDBD7793B26EEC34E39D67BD64B0FAB` | MATCH |
| `cache/specification-runs/20260715T221859Z-s07-s12-freeze-r24/stages/01a_s07_s08_math_correction.json` | `C96E58C6BE5EFC12DE7692A5B26C471BCFE63D26A754D3AD481C13B67A682A79` | `C96E58C6BE5EFC12DE7692A5B26C471BCFE63D26A754D3AD481C13B67A682A79` | MATCH |
| `cache/specification-runs/20260715T221859Z-s07-s12-freeze-r24/stages/02a_money_boundary_correction.json` | `C3DB548BF59016446CB617C0AF479EF25C4D9EB52272F8AEE02F33A046BA548A` | `C3DB548BF59016446CB617C0AF479EF25C4D9EB52272F8AEE02F33A046BA548A` | MATCH |
| `cache/specification-runs/20260715T221859Z-s07-s12-freeze-r24/terminal_manifest.json` | `05B98E3C94F3154C548D6834C8C16201F59EA7A724CA1C3E7AD43176B970BF7E` | `05B98E3C94F3154C548D6834C8C16201F59EA7A724CA1C3E7AD43176B970BF7E` | MATCH |
| `cache/specification-runs/20260715T221859Z-s07-s12-freeze-r24/terminal_sha256.txt` | `986FFE85F4B326B4B86122AD19469133F82BB270FCB481885E7081ADD2130E43` | `986FFE85F4B326B4B86122AD19469133F82BB270FCB481885E7081ADD2130E43` | MATCH |

The active cache contains exactly 42 files totaling 0.236711 MB. All 28 JSON files parse. All nine
SHA-256 sidecars and four SHA3-512 sidecars reconcile with their governing manifests. No candidate
was accepted by filename alone, no file required regeneration, and no backup generation was
rotated.

The earlier exactly-two-claim PCS boundary was incorrect for the relay-free seven-layer DAG. The
correct boundary is one output claim plus four `RoundInput` claims. Each claim fixes one
24-coordinate point, packed value, shard query, and sixteen component evaluations before two
authenticated batching challenges. The corrected implementation is:

- `src/fp16_zk_rs_gkr_binding.rs`: five-claim/two-boundary binding, sixteen-coordinate linearized
  map, and independent final answer target;
- `src/fp16_zk_rs_row_sumcheck.rs`: exact compact source/relation folding, including cross terms;
- `src/bin/fp16_zk_rs_row_sumcheck_prover.rs`: serial and bounded 16-worker host reference plus
  parameter mode;
- `src/bin/fp16_zk_rs_theorem8_1_transcript.rs`: v4 publish-before-challenge stream;
- `src/bin/fp16_zk_rs_answer_target.rs`: independent production-shape target evaluator;
- `src/bin/fp16_zk_rs_answer_code_verify.rs`: v3 epsilon/main-scale target enforcement; and
- `cuda/cuda_fp16_zk_rs_theorem8_1_k128_prototype.py`: component extraction fused into live
  commitment tiles and compact GPU row message/fold/terminal kernels.

The component rows, compact source state, and compact relation state are each 2.621440 MB, for
7.864320 MB total. No duplicate full source replay or second full codeword is introduced. The
standalone authenticated schedule is 14 rounds. The corrected planned combined schedule is 5,822
rounds, adding the previously omitted coordinate-batching challenge; it remains source-derived
until the real coordinator runs.

Static NVRTC compilation, which does not load the GPU driver, passes. The PTX is 3.202943 MB,
SHA-256 `44AEE2D3C889014F936F8913495FBA24114B20CE7038E28A978FE0F7E2E52742`, and contains all six
required entries: coefficient weights, component evaluation, row initialization, quadratic
message, fold, and terminal.

The production-geometry v3 answer-target KAT passed on 16 logical CPU workers with a 6.232512 MB
input, 0.459017 seconds wall, 0.406895 seconds native verify/encode, and 33.112 MB native host peak.
It accepted the correct Construction 7.2 target and rejected target, answer, epsilon/main-scale, and
GKR-point mutations.

The v2 numerical security ledger now includes the five-claim batch at 493.999999989 bits,
sixteen-coordinate batch at 492.093109394 bits, source/mask batch at 495.999999989 bits, and nine
degree-two row-sumcheck rounds at 491.830074988 bits. The composed IOPP floor remains
392.108419573 bits because the auxiliary spot-check term dominates.

The production PCS source prototype is now internally consistent, but it still generates
deterministic fixture claims from the same committed source. The actual seven-layer GKR producer and
atomic semantic/state coordinator are not attached. Production GPU execution also remains blocked
until a clean NVIDIA driver reset; the memory design is not the blocker.

### Containing verification after the compact correction

The first strict Clippy run found four equivalent `round >= variables + 1` comparisons and one
test-only complex return type. They were corrected mechanically to `round > variables` and one
local type alias. No check was suppressed. The affected focused tests and the containing gates then
passed:

```text
cargo fmt --all -- --check
exit=0

cargo check --locked --offline --no-default-features --lib
exit=0

cargo clippy --locked --offline --all-targets --features parallel -- -D warnings
exit=0; warnings=0

cargo test --release --locked --offline --features parallel
test result: ok. 238 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;
all binary and doc-test groups also exited zero
```

The fresh five-claim host integration passed with 14 authenticated rounds, 1.193564 MB input,
2.635356 MB row-source input, 6.232448 MB answer-target input, 1.179648 MB sumcheck messages,
1.240824 MB public-coin bundle, 21.413325 seconds wall, and 134.996 MB host peak. The CPU row prover
used the available 16 logical workers and took 7.453513 seconds; it is a correctness reference, not
the intended production-throughput path. Both PQ chain heads authenticated, the message-before-
challenge order and independent replay passed, the exact source/relation cross terms and final
answer target matched, and ordinal, claim-target, and component mutations were rejected.

All seven focused host KATs passed. The nontrivial v3 answer-target gate used 16 workers and rejected
target, answer, main-scale, and GKR-point mutations. The hiding audit generated a 53.130368 MB
conditioned view at 27.963 MB host peak and passed its algebra, rank, query-coverage, and coupling
checks. The answer-code verifier passed its 6.217900 MB production mechanics at 57.278 MB combined
host peak. Segment 16 and selected segment 32 independently verified 35-tree and 19-tree grammars;
segment 32 used a 55.960528 MB fixture and rejected every leaf, frontier, and root mutation.

The final static NVRTC build remained 3.202943 MB with SHA-256
`44AEE2D3C889014F936F8913495FBA24114B20CE7038E28A978FE0F7E2E52742`.
Python AST parsing and standard-library symbol analysis found no unresolved global names in the five
changed prototype/KAT/ledger modules. Ruff and Pyflakes were not installed, so zero third-party
Python lint commands were run; this was not substituted for the executed AST, protocol, mutation,
or Rust gates.

The final Windows System audit still reports last boot `2026-07-29 02:33:01` and six
`nvlddmkm` Event 153 errors since that boot, from `08:37:54` through `09:05:18`. There is no
post-error reset. Launching a production CUDA proof would therefore violate the explicit unsafe-
resource stop gate. The next permitted action after a clean reset is the actual five-claim GKR
producer/coordinator join and one externally monitored segment-32 complete proof; no sub-30-second
or complete-proof claim is made before that run independently verifies.

## 2026-07-29 selected-architecture resource admission and schedule correction

The owner explicitly replaced the blanket 8-GiB free-host-RAM launch floor for the selected bounded
segment-32 architecture with a calibration tied to its actual footprint. The active preflight now
requires at least `max(1,000 MB decimal, 2 * latest measured complete-proof peak RSS)` free physical
host memory and at least 2,000 MB decimal free device memory. Until a complete proof supplies its own
peak, the 1,000 MB host floor governs against the 191.533 MB measured component peak. Samples during
this continuation ranged from 4,569.681920 MB to 5,066.506240 MB free physical host memory and pass
that admission floor. The immutable acceptance limits remain no more than 5,000 MB process RSS,
strictly below 5,000 MB scratch, and no swap. The 200 MB host and 1,800 MB device engineering
targets also remain fail-closed redesign triggers. All memory values here use decimal MB.

The exact selected component evidence remains 191.533 MB host, 1,612.185152 MB device,
7.864320 MB compact component/source/relation row state, 14.347776 MB initial-oracle multiproof,
26.104 MB hiding-audit host peak, and 0.000000 MB scratch. These are component measurements, not a
complete-proof resource qualification.

First-principles replay of the existing complete masked producer found that the prior 5,822-round
plan omitted theorem-required challenges. The corrected source-derived schedule is 6,086
authenticated rounds: 6,072 GKR transcript challenges, one independent post-GKR aggregate
mask-functional batching challenge, and 13 downstream PCS challenges. The schedule and control
tests and the real dual-PQ coordinator pass at 6,086, but the complete producer has not yet occupied
the mask-batch and downstream PCS descriptors in that same session.

The prior driver-integrity block is also cleared: Windows last boot is
`2026-07-29 18:06:49 -06:00`, with no subsequent `nvlddmkm`/Display reset event in the verified
post-boot audit. A fresh System-log audit remains mandatory immediately before the production CUDA
proof. `proofSuiteId=null`, activation is false, protected-path edits remain zero, and no
complete-proof or sub-30 qualification claim is made.

## 2026-07-29 real uniform relay-free GKR and exact coordinator ABI

The real all-zero sixteen-shard producer now executes the actual 24-round, seven-layer relay-free
Keccak DAG. It uses the ordinary shared-group verifier relation while algebraically eliminating
8,192 duplicate uniform group rows. Through a live dual-PQ authenticated coordinator it produced
and independently replayed exactly 6,072 raw GKR rounds: one output query, 95 claim mixes, 168
packed bridges, 2,184 shared-group messages, 3,456 wire messages, and 168 terminal messages. All
168 layer reductions independently verified, the final boundary contained exactly four zero-input
claims, and a mutated group message was rejected.

The externally sampled run reported:

```text
status=verified
authenticated_chain_heads=true
dual_pq_suites=true
message_before_challenge=true
independent_bundle_replay=true
independent_gkr_algebra_verification=true
gkr_raw_rounds=6072
verified_rounds=6072
gkr_layers=168
final_input_claims=4
uniform_group_materializations=0
bundle_mb=3.382242
peak_host_mb=52.457472
device_mb=0.000000
real_gkr_prover_seconds=10.532918
independent_bundle_replay_seconds=0.147625
independent_gkr_verify_seconds=2.211572
total_seconds=13.484277
```

This is real-GKR component evidence, not a complete proof. The raw producer is now attached to the
atomic dual-PQ coordinator, but native Libra masking, the independent aggregate mask opening, and
the downstream PCS are not yet attached to this producer.

The exact coordinator ABI no longer uses the legacy 28-output placeholder. The output-query round
returns 27 field elements: one shard query, 24 output-point coordinates, bridge rho, and sumcheck
rho. Claim-mix responses return their mixing scalar plus the two rhos. A terminal response returns
three elements only when it carries the next no-mix layer's two rhos; all other selected GKR
responses return one. The standalone bridge KAT exercised a three-element vector response through
both PQ suites and independently replayed it.

The corrected Libra schedule has 2,520 cubic and 3,288 quadratic variables. Its commitment uses
23,544 coefficients padded to 32,768. Conservative leakage rank is 7,728 bridge plus 14,304
sumcheck plus 672 layer plus one aggregate opening, totaling 22,705. The new indexed prior-layer
correction supports relay-free claims originating from different layer masks and matches the old
single-mask formula exactly in its parity test.

The active selected-architecture resource admission remains 1,000 MB free host and 2,000 MB free
device until complete-proof calibration. The measured real-GKR peak of 52.457472 MB reinforces,
rather than relaxes, the 200 MB host engineering target. Native GKR masking, PCS attachment, a
fresh pre-launch Windows System-log audit, and one externally monitored complete segment-32 proof
remain mandatory before any complete-proof or sub-30 qualification claim.

### Containing verification after the real-GKR integration

The exact-output 6,086-round coordinator control independently replayed both PQ chains with a
4.494103 MB bundle in 1.551632 seconds. The optimized containing Rust suite passed:

```text
test result: ok. 249 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;
finished in 89.22s
```

All binary and doc-test groups exited zero. Strict Clippy with `-D warnings` exited zero with no
warnings, `cargo fmt --all -- --check` exited zero, and the locked offline no-default-features
library check exited zero. The public-coin bridge vector KAT returned three field elements on its
first round, authenticated both PQ heads, independently replayed the bundle, and rejected the
round-order mutation. No production CUDA proof was launched because the real producer still lacks
native masking and PCS; the mandatory pre-launch System-log audit therefore was not consumed.

## 2026-07-29 real-GKR/PCS join, bounded memory, and renewed driver gate

The real native-masked 168-layer GKR producer is now joined to PCS in one exact 6,086-round
authenticated session: 6,073 GKR rounds including the aggregate mask batch, followed by 13 PCS
rounds. The PCS commits the 32,768 GKR mask coefficients as 64 dimension-512 auxiliary RS
codewords. The final auxiliary answer has 73 words: nine ordinary sumcheck masks plus 64 GKR mask
words. Its target evaluates the first nine as univariate mask polynomials and the last 64 as
512-value multilinear tables at the common nine row challenges, multiplied by their independently
derived relation terminals and epsilon. The invalid extra-main-codeword shortcut remains rejected.

Exact decimal memory geometry is:

| Live object | Decimal MB |
| --- | ---: |
| Component rows plus 144 source/relation row states | 12.058624 |
| GKR mask coefficients | 2.097152 |
| GKR mask RS codewords | 33.554432 |
| Complete 73-word auxiliary coefficients | 15.258752 |
| Complete 73-word auxiliary RS codewords | 38.273024 |

The production-geometry v4 target/answer KAT used all 16 logical workers, peaked at 77.070 MB host
RSS, independently verified both main and GKR-mask targets/openings, and rejected target, answer,
epsilon, GKR-point, GKR-relation-terminal, and GKR-mask-answer mutations. The 20-tree segment-32
multiproof KAT used a 66.021784 MB fixture, verified every root, and rejected every leaf, frontier,
and root mutation. The real-GKR same-chain coordinator verified all 6,086 descriptors, reused the
GKR mask root, recomputed the 64 relation terminals from the authenticated GKR coefficient weights,
bound their SHA3-512 digest into the base-mask challenge, and independently replayed its 4.324934 MB
dual-PQ bundle. A second complete host session mutated that digest and was rejected fail closed with
`ERR:gkr_pcs_terminal_digest` before the base-mask challenge was released.

Static NVRTC compilation passes at 3.299008 MB PTX with SHA-256
`219ec2ed5343ec9f9d0c136c774bfea581d02d4a0080266c0f430f85a843ac7c`.
Strict Clippy passes with zero warnings. The optimized containing suite passes 252/252 library
tests, every binary group, and doc tests; the latest main group finished in 91.17 seconds.

The first externally monitored production launch did not complete a proof. It failed closed with:

```text
RuntimeError: compact_component_multilinear_evaluations_sync:700
```

No proof stdout was emitted. Before failure, external monitoring measured 317.542400 MB
process-tree RSS, 855.638016 MB total GPU use, 5,347.966976 MB minimum free physical RAM, zero scratch,
and a 2 MB system pagefile-usage delta. These are failed-run diagnostics, not complete-proof peaks.
Windows subsequently recorded `nvlddmkm` Event 153 at `2026-07-29 21:46:13 -06:00`, record
229363. The mandatory production CUDA gate is closed until a clean driver reset.

The failed component stage redundantly evaluated the same fixed public message across all 512
interleavings. The corrected source extracts one actual live commitment tile per boundary and
broadcasts only that boundary's public message evaluation across its 256 high-word positions; the
hiding tail is neither copied nor omitted from its commitment. This removes 510 duplicate
evaluations and still performs no full-source replay. The corrected kernel statically compiles, but
it has not run because the post-failure driver gate forbids production CUDA before reset.

`proofSuiteId=null`, activation remains false, real PHI/payments remain forbidden, and
complete-proof/sub-30 qualification remains open. The immediate next action after a clean reset is
one externally monitored segment-32 run of the corrected source. Do not run any production CUDA
path before a fresh System-log audit confirms zero post-reset `nvlddmkm`/Display events.

## 2026-07-30 complete real-GKR/PCS prototype verification

The authoritative workspace remains
`C:\Users\neers\Documents\Codex\2026-07-27\he\work\Blind-Ledger-Wave2-Workspace-2026-07-26`.
Its missing `.git` metadata is expected. No replacement workspace was created or extracted.

The Windows reboot boundary is `2026-07-29 23:17:48 -06:00`. Every production attempt after that
boundary had zero `nvlddmkm` Event 153 and zero Display events. The installed NVIDIA 610.88 driver
remained healthy. The final preflight observed 5,562.892288 MB free host memory and 8,342.470656 MB
free device memory.

The complete nonactivating K128 prototype now joins all of the following in one fresh proof:

- the real 24-round, 168-layer, seven-layer/B=16 relay-free GKR producer;
- native Libra masking and its independently checked aggregate committed opening;
- one output plus four relay-free input claims;
- five-claim/sixteen-coordinate quadratic PCS row binding;
- the 73-word Construction 8.2 random-padded interleaved Reed--Solomon auxiliary plane;
- the exact 6,086-round authenticated same-chain schedule: 6,073 GKR rounds and 13 PCS continuation
  rounds;
- ML-DSA-87 and SLH-DSA-SHAKE-256f chain-head authentication;
- authoritative Rust row parameters, answer code, targets, SHA3-512 Merkle roots, mutations,
  transcript replay, and final verification; and
- one atomic GKR/PCS coordinator and verifier with no duplicate full-source replay.

The final externally monitored run is
`cache/wave2-final-proof-20260730-005825.stdout.txt`. Raw decisive measurements were:

```text
process_exit=0
external_input_to_output_seconds=28.943126
complete_process_wall_seconds=28.177317
pcs_mechanics_seconds=20.745883
public_coin_head_auth_seconds=12.724326
compact_row_sumcheck_seconds=3.348778
opening_seconds=2.740147
peak_process_tree_decimal_mb=311.537664
proof_phase_host_peak_mb=305.770
parent_process_lifetime_host_peak_mb=247.575
native_verifier_peak_mb=78.733
max_gpu_used_decimal_mb_sample=1058.013184
tracked_device_peak_mb=956.738816
scratch_mb=0.000000
pagefile_before_mb=226
pagefile_peak_mb=226
pagefile_after_mb=226
post_launch_display_event_count=0
```

Every printed verifier flag was true, including independent sumcheck/terminal/base targets, main
and auxiliary spot checks, native spot-check attachment, every Merkle root, every leaf/frontier/root
mutation, the exact soundness ledger, theorem binding, Construction 8.2 hiding simulator gate,
five-claim binding, Rust-derived parameters, live-tile component extraction, no duplicate full
source replay, independent answer target, real GKR producer, authenticated launch coin, atomic
coordinator, atomic verifier, and complete fresh-proof independent verification. Stderr was empty.

The compact row-state wording is now explicit. Five-claim component rows plus claim source/relation
rows occupy 7.864320 MB. GKR-mask source/relation row state occupies another 4.194304 MB while it is
live. The joined total is therefore 12.058624 MB. The other exact device objects remain 2.097152 MB
of GKR-mask coefficients, 33.554432 MB of GKR-mask codewords, 15.258752 MB of complete auxiliary
coefficients, and 38.273024 MB of complete auxiliary codewords.

The accepted latency changes were deliberately narrow:

- defer GKR algebra replay until it can overlap PCS work, but require it before bundle completion;
- overlap the authenticated real-GKR prelude with independent PCS sampling/commitments;
- carry the Rust-authenticated mask evaluation instead of reevaluating the full mask in Python;
- increase bounded SHA3 leaf batches from 1,024 to 8,192 leaves without changing leaf bytes,
  domains, roots, or verification;
- use a measured hybrid release: machine-native thin-LTO binaries for GKR/field arithmetic and
  generic binaries for the faster SHA3/Merkle verifier lane; and
- parallelize independent spot-check query arithmetic across at most 16 logical workers while
  preserving canonical error order and decoding every Fp16 value.

Rejected experiments remain rejected: parallel CUDA row reduction regressed due JIT/launch cost,
CUBIN loading did not reduce context/module time, public-coin contributor fanout gave no measurable
gain, and sparse-bucket masked GKR regressed the isolated layer prover.

Containing verification is current:

```text
cargo fmt --all -- --check
exit=0

cargo clippy --release --offline --locked --all-targets --features std,parallel -- -D warnings
exit=0; warnings=0

cargo test --release --offline --locked --features std,parallel
test result: ok. 252 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;
all binary and doc-test groups exited zero
```

All seven current host gates passed: semantic theorem KAT, v4 answer-target KAT, answer-code KAT,
hiding/simulator KAT, public-coin bridge KAT, v6 same-chain bridge KAT, and the v2 security ledger.
The retained v4 component-only authenticated-sumcheck harness was skipped because it predates the v6
committed GKR-mask root/opening and mask-row relation; changing only its magic would be incorrect.
The 20-tree segment-32 KAT verified all roots and rejected every leaf, frontier, and root mutation.
Static CUDA compilation produced 3.298706 MB with SHA-256
`6B1F682A647754FEC44AC85E9136962E0591A45865BB2A928EBF180254BAFEA7`.

The requested real-GKR/coordinator/PCS prototype is complete. This does not close H4's bounded
semantic-AIR/bus atomic composition, the historical 200 MB host engineering target, the
warm-up-plus-ten p95 campaign, K512, H6 suite qualification, or activation. The immutable 5,000 MB
RSS, below-5,000 MB scratch, and no-swap gates passed. `proofSuiteId=null`, activation=false,
`complete_pcs_qualification=false`, and `complete_proof_qualification=false` remain correct.

## 2026-07-30 H3 theorem-neutral throughput refinement

The prior `2026-07-29 23:17:48 -06:00` reset label was not supported by the raw Windows System
log. The OS boot was `2026-07-29 18:06:49.5003470 -06:00`, and ten later `nvlddmkm` Event 153
records ended at `2026-07-29 23:16:18.3322898 -06:00`. The event at 23:17:50 was an AMD
power-policy event, not an NVIDIA device reset. A scoped `nvidia-smi --gpu-reset -i 0` at
approximately `2026-07-30 09:02 -06:00` reported a successful RTX 4060 driver restart. The
subsequent PnP status was `OK`, `nvidia-smi` exited zero, and the post-reset System log contained
zero Event 153 and zero Display 4101 records.

The complete-prototype hot path received only theorem-neutral representation, transfer, and
lifetime changes:

- CUDA reduces the existing five boundary rows to the exact 80 component evaluations before
  device-to-host copyout;
- public-coin GKR weights remain one canonical packed 32-bit word array rather than 32,768 Python
  field-element tuples;
- Python sends the three exact source-quadratic coefficients per compact-row round, while Rust
  reconstructs the same 2,048-coefficient masked message from authenticated mask state and epsilon;
- the legacy full-message transport remains accepted, and a Rust parity test proves both transports
  construct the same polynomial; and
- complete auxiliary source, folded source, main answer, and auxiliary answer device buffers are
  released at their final use, removing 39.168256 MB from the tracked device peak.

No theorem object, hiding randomness, query, authenticated round, SHA3-512 root, canonical parse,
degree-tail check, sumcheck-chain check, answer target, mutation test, public-coin replay, or
independent verifier was removed.

The first post-reset proof was a successful cold driver-JIT warm-up. It independently verified with
exit zero and empty stderr, but its 9.920482-second driver-JIT load made in-process wall time
30.685591 seconds, so it receives no sub-30 latency credit. Its raw output is
`cache/wave2-throughput-proof-20260730-090635.stdout.txt`.

The qualifying complete-prototype measurement is
`cache/wave2-throughput-proof-20260730-090753.stdout.txt`, SHA-256
`1047F02D40428F95E7E30A232A484878231AA58AC2612ED6946A374B63DEBE36`.
Raw decisive output was:

```text
external_input_to_output_seconds=24.749154
wrapper_exit_code=0
complete_process_wall_seconds=24.392408
pcs_mechanics_seconds=17.741531
public_coin_head_auth_seconds=12.790189
compact_row_sumcheck_seconds=0.468827
opening_seconds=2.846039
external_peak_process_tree_mb=263.983104
external_peak_gpu_mb=1011.875840
tracked_device_peak_mb=917.570560
scratch_mb=0.000000
pagefile_current_before_mb=220.200960
pagefile_current_after_mb=220.200960
post_launch_driver_event_count=0
stderr_sha256=E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
exit_record=0
```

Every proof flag was true: sumcheck chain, terminal and base targets, main and auxiliary spot checks,
native spot-check verifier attachment, all Merkle roots, all tested Merkle mutations, exact
soundness ledger, theorem binding, Construction 8.2 hiding simulator gate, five-claim row binding,
Rust-derived parameters, live-tile component extraction, no duplicate full-source replay, compact
GPU row sumcheck, independent final answer target, real GKR producer, nonfixture GKR claims,
independent Fp16 verifier, authenticated launch coin, atomic coordinator, atomic verifier, and fresh
complete-proof independent verification.

Containing verification on the current files is:

```text
cargo fmt --all -- --check
exit=0

cargo clippy --release --offline --locked --all-targets --features std,parallel -- -D warnings
exit=0; warnings=0

cargo test --release --offline --locked --features std,parallel
main library group: 252 passed; 0 failed; 0 ignored
all binary and doc-test groups: exit=0

source_quadratic_transport_matches_complete_masked_message
1 passed; 0 failed
```

All seven host cryptographic gates pass on the current files: semantic theorem, v4 answer target,
answer code, Construction 8.2 hiding/simulator, public-coin bridge, 6,086-round v6 same-chain bridge,
and v2 security ledger. The same-chain mutation rejected a forged GKR terminal digest before the
base-mask challenge. The updated static PTX is 3.387039 MB with SHA-256
`DA61A996AD551E98EDF835DCE52D22B08963ABFC5C8FD7E28F6D051EDF85111D`.

The H3 real-GKR/native-mask/PCS/coordinator prototype remains complete and is now measured at
24.749154 seconds with low-hundreds-of-MB host use and about 1.012 GB sampled total GPU use. H4
semantic-AIR/bus atomic composition, the historical 200 MB host engineering target, H5's
warm-up-plus-ten K128/K512 campaign, H6, qualification, and activation remain open.
`proofSuiteId=null`, `complete_pcs_qualification=false`, and
`complete_proof_qualification=false` remain fail-closed.

## 2026-07-30 H4 real-bus GKR boundary checkpoint

The H3 24.749154-second uniform-zero run is not K128 or K512 semantic proof evidence. H4 remains the
campaign gate. The exact semantic schedules contain 46,858 calls / 113,730 Keccak permutations for
K128 and 165,762 calls / 411,406 permutations for K512. At the selected B=16 and 8,192-group
geometry, K128 occupies one 131,072-permutation coprocessor shard and K512 occupies four such
shards. The release semantic program now retains only the SHA3 message/digest ports and excludes
the internal SHA3 tables; the v2 bus descriptor binds those exact live counts and authenticated
dummy tails.

The host algebra now accepts complete group-major, nonuniform source tables in the native
Libra-masked shared-group reducer. Every group round checks the complete cubic recurrence, folds the
source group axis only after the authenticated challenge, and preserves the full group-folded right
boundary through both terminal-mask extensions. A nonuniform KAT independently evaluates both
terminal openings on the original source tables. The B=16 bridge also exposes exact evaluation of
an arbitrary 16-bit pattern at the authenticated packed challenge. These changes passed four
relay-free DAG tests, four B=16 bridge tests, the optimized 168-layer uniform regression, formatting,
and strict library Clippy with zero warnings.

This checkpoint does not complete H4. The remaining binding is the production producer/coordinator:
stream the real semantic messages into one bounded 52.428800 MB input/output shard pair with the
448 fixed-zero padding wires implicit, produce
the nonuniform bridge and masked layer messages using the existing group-capable GPU worker without
trusting its arithmetic, bind all one/four shards atomically to the semantic-port and bus
commitments, and independently verify the resulting K128 and K512 proofs. No H5 timing campaign or
qualification credit is allowed before that composition passes.

## 2026-07-30 DeepFold selection reconciliation

The current source and canonical documents were reconciled against the 2026-07-29 PCS selection.
zkDeepFold is not the active H3/H4 outer PCS. The selected nonactivating construction is
Construction 8.2 of ePrint 2026/391 with random-padded interleaved Reed--Solomon codewords. The
older multilinear-PCS/DeepFold implementation remains nonproduction differential, rejection, and
resource-control evidence while its shared utility dependencies are audited.

The DeepFold Appendix E condition `2^18 > 473 * 21^2` is the simulator's interpolation-capacity
condition for the superseded `mu=21` zkDeepFold control; `473` is that control's unique-decoding
query count. The inequality is genuine hiding evidence for that exact PCS instantiation under
DeepFold's stated simulator definition. It is not a unique-decoding theorem, and it does not prove
hiding for the selected 73-word Construction 8.2 auxiliary plane, native Libra-masked GKR, or
their atomic composition. No proof code, theorem gate, test, round, query, or mutation check was
removed in this reconciliation.

## 2026-07-30 H4 bounded semantic source and exact B16 group phase

The semantic hash-bus boundary is now an owned, fail-closed cross-language snapshot rather than an
implicit test iterator. `BLHBSN01` binds the profile, semantic-program commitment, v2 descriptor
commitment, semantic-port commitment, exact ordered messages, capacities, and every SHA3-512
digest. Rust rederives the descriptor, recomputes every digest and the semantic-port commitment,
rejects trailing bytes, and freezes the same K128 encoded SHA3-512 digest as Python:

`b3575b160e3d870671d23cd864f1dfedd7cefa87721f68598434c7bc36cd64a0f387c29babe0034dbb5ee496587eef208cc11581d3cc1d58038a4ffd224dc623`.

The canonical `BLHBB101` conversion retains only the 1,600 live Keccak wires. The 448 circuit
padding wires are fixed zero by the circuit definition and are not serialized. Per coprocessor
shard, the input and output pair is therefore 52.428800 MB; including the 215-byte header, the
canonical K128 file is 52.429015 MB and the four-shard K512 file is 209.715415 MB. Each shard is
stored input-boundary then output-boundary, wire-major with the 8,192 groups as the minor axis.
No duplicate full-source replay or padded-wire allocation is present.

The exact B16 group kernel no longer materializes the old 8,192-group Fp16 source plane. It
publishes the first cubic group message directly from compact `u16` patterns using the exact
degree-15 Lagrange lookup at the authenticated packed challenge, then folds directly into the
half-sized 4,096-group table. Independent CPU calculations matched both the first message and the
first fold. At full K128 geometry the corrected seven-layer group phase measured 0.605268 seconds
per Keccak round, 229.822 MB host peak, and 1,698.495 MB calculated device working set. The
separate exact degree-45 B16 bridge KAT measured 0.496789 seconds per round with 69.042880 MB of
device state. Their 24-round component projections are 14.526432 and 11.922929 seconds
respectively. These are exact-geometry component controls, not a complete proof or latency credit.

The post-reset production gate remained clean before both GPU controls:
`POST_RESET_DRIVER_EVENT_COUNT=0`; NVIDIA 610.88 reported healthy with 7,956 MB free. H4 remains
open until the real snapshot, nonuniform producer, native masking, Construction 8.2 PCS, atomic
one/four-shard coordinator, and independent verifier complete together for K128 and K512.

The real K128 Wave 1A fixture subsequently emitted an 11.554884 MB snapshot; its complete physical
assembly test passed in 172.60 seconds. Rust decoded and recomputed all 46,858 messages, converted
113,730 live permutations plus the authenticated dummy tail, and emitted the exact 52.429015 MB
boundary with SHA3-512
`c21e9de67b45804506d660cf7493042eb0d1ca2abfcbe37ba06a27debe2987324b94c9f1cfdc8084442bd94d4acec5ec572c096bce4f291508fb6b2cbeab11d3`.
The bound commitments are:

- semantic program:
  `ee7df84a8af74f983fc1519437b28f09de1cb5f1067ffd7e0205b280910f6f9019b6b25f29268402099b7b834e35961216f0f082d9ded230e9b840c579a775f5`;
- descriptor:
  `d7b979425eee9ac48804c27f0d90e1e67083a9f85c038f4b735067c57d23b6d859841f4f97470168d6f48079fa788e4b8e2b0abe63ac51819975cd64996e80dd`;
- semantic port:
  `59266af9796a0440d9505edcb2cd1008c16eb4954660e0f011e315b3ee497ff0dfe5e83049635c92a063bbcc681dfe15caae23cc6f2efa7fa54c2b4646a66e50`.

The independent 16-worker Rust bit-sliced executor then evaluated all 24 rounds and seven layers
for every one of the 8,192 B16 groups and matched the complete output boundary. Shard execution
verification took 0.500318 seconds and total file-open/hash/decode/verification took 0.958477
seconds. This closes the real semantic source and trace boundary, not the GKR/PCS composition.

## 2026-07-30 H4 K512 source and bounded masked-group seam

The first K512 snapshot attempt exposed test-only representation bloat: the Python fixture built the
retired full physical SHA3 AIR even though H4 consumes only the semantic-bus program. That process
was terminated at 9,218.748416 MB RSS before it emitted an artifact. It receives no correctness or
resource credit. The K128 physical-assembly regression remains unchanged; K512 snapshot emission now
skips only that irrelevant retired representation.

The corrected K512 semantic build passed its one selected test in 441.10 seconds with empty stderr.
External monitoring observed 3,873.902592 MB peak process-tree RSS, below the 4,500 MB run guard and
the immutable 5,000 MB gate. This is fixture-generation evidence, not prover peak evidence. It
emitted a 41.508092 MB snapshot with SHA3-512
`7b05e56c22c04a3b62f5683032db979946347db8b5660964863e1abcb6db5acb8d9a7302c5e14a06d082f70e254cdc5424dcc19e6d4d1e2bb92f87ccf3c832ae`.

Rust decoded all 165,762 exact calls and converted all four shards to the canonical 209.715415 MB
`BLHBB101` boundary. Its SHA3-512 is
`39a529ab6c337d7753d32b8467c66267bf185e2d1490568f4ac21a0d658778d9aa811eb77d7393a6bd8ea098f49b96d351a7bf59237e0e22bed90841f8992c04`.
The bound K512 commitments are:

- semantic program:
  `618c0945731e170d8bca259f5d5933acfc84379acc751b562cc2c74b450e9a8e91c223045b6cb49a6ee26eaf903821590dbb6bfe4ad49f41116eeb2d4d291387`;
- descriptor:
  `c8328a2c76c3c2c4fbedbc723a2250dcf6ee0b9f198f15241113860a628788cead865b1372b4877101f56023e47deb5f372fa6d54e0ccd5352c25332e325eb91`;
- semantic port:
  `1c225d43e7376dc11abfda70ae70d3a3a06faeacbe4172b61f1592b0ffc21de828863c66cc08e80b33c79b169d65063946fbaf8a5785a740aa4e555881f4ac09`.

The independent 16-worker Rust executor decoded 104,857,600 patterns and verified all four complete
24-round/seven-layer Keccak boundaries in 4.023582 seconds. Per-shard execution times were
0.582480, 0.487975, 0.588844, and 0.498446 seconds.

The native masked shared-group reducer now has a narrow untrusted-oracle seam. Rust checks every
cubic endpoint recurrence, authenticates each published message before releasing its challenge,
then runs the unchanged wire tail, terminal extension, native masks, and terminal checks over the
returned group-folded sources. A CPU oracle produced a byte-identical proof to the complete
nonuniform source-table path; a forged first group message was rejected. The packed B16 bridge now
also enforces its verifier-side sixteen-node sum endpoint independently of source reconstruction,
and rejects a forged degree-45 polynomial. Focused tests pass and strict library Clippy has zero
warnings. The CUDA worker, atomic one/four-shard coordinator, selected PCS join, and complete
K128/K512 proof measurements remain open.

## 2026-07-30 H4 real-GKR/semantic-PCS K128 integration checkpoint

The real nonuniform K128 producer now runs all 168 layers and 6,073 GKR rounds, emits four
relay-free input claims, and enforces 508 native mask constraints. Its standalone component KAT
completed in 104.778552 seconds. The output-query transcript is no longer a uniform-zero fixture:
it binds the `BLHBB101` header, profile, semantic-program/descriptor/semantic-port commitments,
shard count, padded permutation count, live-wire count, exact file size and SHA3-512, selected
shard, and selected GKR-plan commitment. A changed statement binding is rejected.

The same authenticated coordinator now joins that producer to the selected Construction 8.2 PCS
in one 6,086-round schedule. The PCS reads the exact packed semantic shard once, keeps the 448
fixed-zero wires implicit, and does not replay a full Fp16 source. Two integration defects failed
closed and were corrected before receiving proof credit: the canonical file is input-then-output
while the PCS grammar is output-then-input, and compact row source states must retain both
boundaries through the ninth non-Boolean fold even though each claim relation is supported on only
one boundary.

After those corrections, one fresh externally monitored segment-32 K128 proof completed through
independent verification. The proof process exited zero in 120.670536 seconds with empty stderr;
the monitor measured 121.3716075 seconds. Every sumcheck, terminal, base target, answer-code,
main/auxiliary spot-check, Merkle-root, mutation, theorem-binding, hiding, public-coin, real-GKR,
atomic coordinator, and independent-verifier flag printed `true`. The stdout is 3,660 bytes with
SHA-256
`837D45EBD1DAC01E5E52F65B8C7FD8C9547F982D117C3CD4B28FC996A14057B9`;
the semantic file digest is
`c21e9de67b45804506d660cf7493042eb0d1ca2abfcbe37ba06a27debe2987324b94c9f1cfdc8084442bd94d4acec5ec572c096bce4f291508fb6b2cbeab11d3`.

Exact decimal resource evidence is 969.999360 MB tracked device peak, 536.928256 MB monitored
process-tree RSS, 306.905 MB proof-phase host peak, 76.706 MB native-verifier peak, 0.000000 MB
scratch, and no pagefile increase. The prelaunch System-log audit had zero NVIDIA Event 153 or
Display Event 4101 after the confirmed `2026-07-30T13:19:50-06:00` reset boundary, and the proof
added zero such events.

This is functional K128 composition evidence, not latency or suite qualification. The measured
semantic GKR prelude was 110.290992 seconds and the authenticated public-coin head itself was
100.240849 seconds; it is the dominant stage. The run's printed `pcs_mechanics_seconds` included
that prelude because of a reporting-label defect; source accounting is corrected for subsequent
runs and no PCS-only claim is taken from that number. `complete_pcs_qualification` and
`complete_proof_qualification` remain false because K128 exceeds 30 seconds and atomic four-shard
K512 has not yet completed. The next bounded action is theorem-neutral elimination of repeated
worker PTX compilation/reset reconstruction, followed by a fresh proof and only then the K512
four-shard coordinator.

## 2026-07-30 H4 real-wire complete-proof remeasurement

The nonuniform worker now supplies raw group cubics and raw wire quadratics through the narrow
untrusted-accelerator interface. Rust still owns native masks, recurrences, authenticated challenge
release, copied-source terminal evaluation, transcript replay, and independent verification. The
CPU and accelerated oracles produce byte-identical proofs, and a forged first wire message is
rejected. The worker owner closes and verifies the child, performs the scoped reset plus health
check, and starts a fresh process every 48 completed layers; no proof fragment or randomness is
resumed.

One fresh exact K128 semantic proof completed with every printed verification and mutation flag
true:

```text
complete_process_wall_seconds=53.547306
semantic_gkr_prelude_wall_seconds=42.017007
public_coin_head_auth_seconds=41.169864
pcs_mechanics_seconds=4.692209
opening_seconds=2.616566
independent_answer_code_wall_seconds=0.775580
proof_phase_host_peak_mb=295.625
native_verifier_peak_mb=76.435
parent_process_lifetime_host_peak_mb=253.977
tracked_device_peak_mb=969.999360
scratch_mb=0.000000
complete_fresh_proof_independently_verified=true
complete_proof_qualification=false
```

This supersedes the 120.670536-second functional measurement but does not pass the below-30-second
K128 engineering gate. The measured dominant stage is the 168-layer, 6,073-round GKR prelude; PCS
is not the current wall-clock dominant stage. A standalone producer profile verified all 168
layers in 48.207612 seconds total, including 39.470330 seconds in the layer prover,
0.674716 seconds in public-coin work, and 2.554319 seconds in independent verification. Zero
NVIDIA/Display events followed the verified reset boundary.

Rejected exact experiments remain out of the source: a 32-bit `__umulhi` M31 reduction, forced
device vectorization, a 128-register cap, delayed second B16 group materialization, a 32-bit
low/carry product histogram, larger adaptive bridge tiles, group-message prefetch, warp reduction,
multi-claim factoring, and the direct bridge accumulator. Each regressed its containing
measurement or increased live device state without sufficient throughput credit.

zkDeepFold is not selected. The selected PCS remains Construction 8.2 of ePrint 2026/391 with
random-padded interleaved Reed--Solomon codewords. The historical
`2^18 > 473 * 21^2` inequality satisfies zkDeepFold's auxiliary-polynomial simulator condition for
the superseded `mu=21`, `s=473` control. It does not establish system composition, apply to the
selected PCS, or justify the conjecture-dependent lower-query list-decoding lane. No alternative
receives active-path credit without its complete theorem mapping, exact parameter ledger,
implementation, and independent end-to-end verification.

H4 remains open on two measured requirements: redesign K128 below 30 seconds without weakening the
proof, and attach the canonical four-shard K512 source to one fail-closed atomic acceptance
boundary below 180 seconds. `proofSuiteId=null`, activation=false,
`complete_pcs_qualification=false`, and `complete_proof_qualification=false` remain authoritative.

## 2026-07-30 H4 K512 atomic four-shard evidence

The complete K512 coordinator now executes four ordered, independently verified shard proofs
sequentially on one GPU and accepts them under one outer SHA3-512 parent binding and receipt. The
binding covers the canonical 209.715415 MB `BLHBB101` file, selected GKR plan, shard order, and a
caller-supplied application-statement digest; every shard's authenticated public-coin session
includes the same parent binding. No nonlinear challenge stream is shared between shards.

The four shard verifiers passed at 56.240250, 52.837966, 53.901788, and 58.130489 seconds. The
coordinator completed in 222.600073 seconds and the external monitor in 227.826116 seconds.
External process-tree RSS peaked at 591.249408 MB, sampled total GPU use at 2,182.086656 MB, and
scratch at 0.000000 MB. Pagefile use decreased by 2.097152 MB rather than growing. The fresh
scoped NVIDIA reset was healthy and no `nvlddmkm` Event 153 or Display Event 4101 occurred after
reset or launch. The atomic receipt is
`ce4c537f624c5fab7884619b5e5ab65cf0d361d696b41e33a71c43d706a590398a414d4c287119e25355e09d07b0c937be909e476482172a63266fe4a2da6d70`.

This closes functional K512 attachment but not its latency gate: 222.600073 seconds exceeds 180.
The same measured GKR head that leaves K128 at 53.547306 seconds dominates all four shards.
Qualification and activation remain false.

## 2026-07-30 H4 manifest-bound K128/K512 atomic checkpoint

K128 and K512 now use one fail-closed coordinator. It accepts only the canonical one-shard K128 or
four-shard K512 `BLHBB101` shape, a nonzero caller statement, ordered sequential single-GPU shard
proofs, and complete independent verification. The v2 parent and receipt bind an execution
manifest covering the Python entrypoint, exact prototype/semantic-worker dependency closure, seven
native verifier executables, and precompiled PTX. The external monitor recomputes and pins the
same manifest before launch.

Fresh manifest-bound K128 evidence is 54.955357 seconds in-process and 59.060426 seconds external,
532.242432 MB external process-tree RSS, 969.999360 MB child-tracked device state, zero pagefile
growth, empty stderr, and zero driver events. Receipt:
`0217093734fa76a0ae7680ec9f58ebae2145bba0fc4e2945413cc9dbc26322ea2444c12ef56e1a1d6fa620e43cd31832c1a9906b1fca8ac9cc690f73640a4f70`.

Fresh K512 shard times are 55.221861, 54.467592, 53.685071, and 55.734525 seconds;
coordinator/external totals are 220.583627/226.627989 seconds. External peaks are 547.127296 MB
process-tree RSS and 2,182.086656 MB sampled total GPU, with zero pagefile growth, empty stderr,
and zero driver events. Receipt:
`8a3456a9afc715b44543135355490142acb69c0a494fe7f5486f0f375848a35e5c2b4225e261d9ac1471fbf11f1bad5904585cf101063f8fa7bc03b653548822`.
Both runs passed all functional gates and failed only their 30/180-second latency gates.

The verifier surface is narrower. Only complete 20/36-tree proofs, complete 73-word GKR-mask
auxiliaries, V4 answer code, and V2 standalone answer targets are accepted. A new KAT rejected all
10 retired/incomplete forms; the stale V1 answer-code acceptance KAT was removed. Both current
Merkle geometries pass every mutation check. The optimized all-target suite passed 264 library
tests plus every binary group, with zero failures and zero ignored tests; strict all-target Clippy
passed with zero warnings.

The Windows context limit remains a resource-integrity gate. Raising the worker boundary from 48
to 56 failed closed at completed layer 54 with CUDA error 700 and produced `nvlddmkm` Event 153
record 229592. The change was reverted, the bridge rebuilt, and the driver reset. Neither 56 nor a
single 168-layer context is allowed. Qualification, activation, and `proofSuiteId` remain
false/false/null.

## 2026-07-31 H4 complete K128/K512 prototype and latency closure

The authoritative workspace remains
`C:\Users\neers\Documents\Codex\2026-07-27\he\work\Blind-Ledger-Wave2-Workspace-2026-07-26`;
its missing `.git` metadata was expected at handoff. After the owner's explicit 2026-07-31 request
to use Git, the workspace was initialized in place without creating or extracting another
workspace. The recovery root checkpoint is commit
`20c409b6f546085120542e294e1868e878c56cf8`, tree
`367a4672073f31e71520888cbf73f50b8918c796`: 998 source/documentation files and 11.942784 MB.
Generated targets, caches, the NVIDIA installer, NVRTC wheel/runtime, and NVRTC cache total about
2.27 GB; they remain preserved on disk under narrow ignore rules and were not committed as source.
No remote was configured and nothing was pushed. The verified Windows driver-reset boundary is
`2026-07-31T05:06:01.7747420-06:00`. Every final proof audit found zero later `nvlddmkm` Event 153
and zero Display Event 4101. NVIDIA 610.88 reported the RTX 4060 healthy.

The complete semantic prototype now attaches, for both K128 and K512:

- the exact `BLHBB101` semantic source and all bound program/descriptor/port identities;
- the real 24-round, 168-layer, seven-layer/B=16 relay-free nonuniform GKR producer;
- one output plus four relay-free input claims, 6,073 GKR rounds, and 508 native mask constraints
  per shard;
- the five-claim/sixteen-coordinate compact row relation and 73-word Construction 8.2
  random-padded interleaved Reed--Solomon auxiliary plane;
- exactly 13 PCS continuation rounds, for one verified 6,086-round authenticated schedule;
- ML-DSA-87 and SLH-DSA-SHAKE-256f public-coin head authentication;
- authoritative Rust topology, masking, recurrence, endpoint, canonical parse, SHA3-512 root,
  answer-code, target, mutation, replay, and final verification; and
- one execution-manifest-bound atomic coordinator: one K128 shard or four ordered K512 shards
  sequentially on one GPU with no theorem-free challenge sharing.

The final execution manifest is:

`51c23310274ccf7c4d7f9abe4ae7eba43266b335bd377b21cbf92409729b91e2a40a39787a157baa080c9d0516c7815af404a4d58d9e76747f652f57cd017ed6`.

The final throughput changes are theorem-neutral and purpose-minimal. Rust prevalidates and encodes
each canonical layer plan as one exact batch; Python reads and validates the same batch. The worker
uploads all immutable 24-round/seven-layer topology once as 3.225600 MB of packed device geometry.
Authenticated same-source aliases are derived rather than retransmitted. The coordinator hashes
the semantic file and captures the selected shard in one pass. Exactly one future 48-layer worker
is prepared after the active worker accepts its plan: zero standby exposes measured fresh-context
latency, while additional standbys add residency and startup contention without proof or throughput
purpose. Worker and proof Python processes use `-S` because the manifest-bound closure uses only
the standard library and pinned local modules.

The accepted fresh K128 evidence is
`C:\Users\neers\Documents\Codex\2026-07-29\continue-blind-ledger-wave-2-from\work\h4\k128-final-manifest-complete-v2.stdout.txt`.
Its decisive raw values are:

```text
shard_0_verified=true
shard_0_proof_seconds=29.610331
shard_0_coordinator_wall_seconds=29.973616
execution_manifest_sha3_512=51c23310274ccf7c4d7f9abe4ae7eba43266b335bd377b21cbf92409729b91e2a40a39787a157baa080c9d0516c7815af404a4d58d9e76747f652f57cd017ed6
semantic_hash_bus_file_sha3_512=c21e9de67b45804506d660cf7493042eb0d1ca2abfcbe37ba06a27debe2987324b94c9f1cfdc8084442bd94d4acec5ec572c096bce4f291508fb6b2cbeab11d3
atomic_parent_binding_sha3_512=2c644e1526c5f2623f48e7371750699f429ea875a6af3a82e3c5ab9172d7340e5006bb42feb569352d4d05f63ec5c4996f5666a5805e6f2f8108eac4f355be83
atomic_receipt_sha3_512=c2b5b0ad8a35ac6ffc74f17ab8f7489328486b43a6b65bfd7fa6d09eeaf1ca5b797bf385d41e44c50c44652594e2bd0bdde9be9bca3e94a8510a86ef09e6f8bd
complete_process_wall_seconds=29.974129
peak_host_mb=288.412000
peak_device_mb=969.999360
scratch_mb=0.000000
complete_proof_latency_gate=true
all_shards_independently_verified=true
```

The external K128 wrapper exited zero in 34.1839105 seconds including monitoring overhead. It
measured 681.607168 MB peak process-tree RSS, unchanged 1,045.430272 MB pagefile CurrentUsage,
zero driver events, 1,356 stdout bytes with SHA-256
`F268AB662715DD879E4F550CCEC08A4EFFE6E31D0CC41FF1815212632D119E4B`, and empty stderr.

The accepted fresh K512 evidence is
`C:\Users\neers\Documents\Codex\2026-07-29\continue-blind-ledger-wave-2-from\work\h4\k512-final-manifest-complete-v2.stdout.txt`.
Its decisive raw values are:

```text
shard_0_verified=true
shard_0_proof_seconds=31.567686
shard_1_verified=true
shard_1_proof_seconds=30.679149
shard_2_verified=true
shard_2_proof_seconds=31.019240
shard_3_verified=true
shard_3_proof_seconds=25.998881
execution_manifest_sha3_512=51c23310274ccf7c4d7f9abe4ae7eba43266b335bd377b21cbf92409729b91e2a40a39787a157baa080c9d0516c7815af404a4d58d9e76747f652f57cd017ed6
semantic_hash_bus_file_sha3_512=39a529ab6c337d7753d32b8467c66267bf185e2d1490568f4ac21a0d658778d9aa811eb77d7393a6bd8ea098f49b96d351a7bf59237e0e22bed90841f8992c04
atomic_parent_binding_sha3_512=3015a21648506d665a3fc38deb85413db71c3b8f1b765cf78c971959bb3987cc8acbbcaabe93b41f07680cadee8b5759175198781c4490e04ab93d5222dc5bdb
atomic_receipt_sha3_512=6c0a41d8a198b9d414cc5ee154540cc232cd66482e1342782db01a34b5a552a5ee3a635ef336907d0465d2ce581f170d786fe8371437b54bcf7077c9ef139671
complete_process_wall_seconds=120.460733
peak_host_mb=296.255000
peak_device_mb=969.999360
scratch_mb=0.000000
complete_proof_latency_gate=true
all_shards_independently_verified=true
```

The external K512 wrapper exited zero in 125.7846276 seconds including monitoring overhead. It
measured 706.523136 MB peak process-tree RSS, 2,770.337792 MB sampled total GPU residency,
unchanged 1,046.478848 MB pagefile CurrentUsage, zero driver events, 1,655 stdout bytes with
SHA-256 `3D1CC8F1D0BF22CBA997035D6DC8B1F6A46ED7F4D0BCF12776DF8671BB26AD9E`,
and empty stderr.

The owner's later resource direction explicitly supersedes the historical 200 MB host and
1,800 MB device component-selection targets as acceptance criteria. They remain dated evidence,
not hidden failures. The current objective is a low-hundreds-of-MB internal host image and bounded
device residency within the immutable 5,000 MB host, below-5,000 MB scratch, and no-swap gates.
The accepted 288.412/296.255 MB internal host and 969.999360 MB per-proof tracked device results
meet that objective; K512's 2,770.337792 MB external total includes simultaneous CUDA contexts.

The resource and latency gates remained fail closed. A preceding final-manifest K128 proof was
cryptographically valid but completed in 30.150084 seconds and observed 2.097152 MB pagefile
growth; its wrapper exited one. A preceding cryptographically valid K512 proof completed in
121.195125 seconds but observed 1.048576 MB pagefile growth; its wrapper also exited one. Neither
attempt receives acceptance credit.

Final containing verification is:

```text
cargo fmt --all -- --check
exit=0

cargo clippy --release --offline --locked --all-targets --features std,parallel -- -D warnings
exit=0; warnings=0

cargo test --release --offline --locked --features std,parallel
main library group: 266 passed; 0 failed; 0 ignored
every binary and doc-test group: exit=0

cargo check --release --offline --locked --lib --no-default-features
exit=0
```

All seven current host cryptographic KATs pass. The segment-32 verifier checks all 20 authenticated
trees and rejects every tested leaf, frontier, and root mutation. The retired-format KAT rejects
10/10 old or incomplete encodings. Static CUDA compilation emitted 36 entry points in
3.494439 MB with SHA-256
`B1F826445F2630517E250CE4BBB5E694ADC61620BEED5684C6EE09197EBBEF73`.

The final test-purpose audit listed 266 library tests and found zero ignored tests. The
`v1_layer_openings_compact_to_the_same_global_frontier` case remains because it proves migration
equivalence to the canonical global frontier. The exact two-claim `gkr_pcs_bridge` tests remain as
nonproduction coherent-chain differential controls; the active five-claim verifier cannot accept
their format. The retired-format KAT is required negative evidence. No additional test was removed;
the stale V1 answer-code acceptance KAT had already been deleted when the acceptance surface was
narrowed. The new exact batched-plan encoder/parser tests are required for the final transport.

zkDeepFold is fully reconciled and remains off the active path. The inequality
`2^18 > 473 * 21^2` is only the retired `mu=21`, `s=473` zkDeepFold simulator's interpolation
condition. It gives no hiding, composition, query-reduction, implementation, or measurement credit
to the selected Construction 8.2 PCS.

The complete requested K128/K512 prototype is now attached and passes the one-run 30/180-second
latency, correctness, independent-verification, driver, scratch, RSS, and no-pagefile-growth gates.
This closes H4's functional and prototype-latency boundary. H5's warm-up-plus-ten p95/resource
campaign and H6 suite qualification remain open. Therefore `proofSuiteId=null`, activation=false,
`complete_pcs_qualification=false`, and `complete_proof_qualification=false` remain correct.

## 2026-07-31 current-stack and retired-source cleanup

The active source and documentation surface now has one concise entrypoint,
`docs/CURRENT_TECH_STACK.md`, and one non-executable rejection ledger,
`docs/REJECTED_ARCHITECTURES.md`. The standalone RISC Zero and vendored Stwo experiments were not
imported by the application or selected proof crate. Their 259 tracked source/vendor files and two
backend-specific test files were removed. Exact source, lock, license, measurement, and rejection
identities remain in the rejection ledger and Git history. The two originally ignored RISC lockfiles
were moved intact to `cache/retired-source-locks/20260731-risc0/`; their SHA-256 values remain
`2D4B81A46864741474432DE6C01FCE0AAA119E7D10F96B29788CB3C0A7C084A7` and
`F8B76FE443668B989FC71C2C310755CC5A79F8C14F292B92F44DEFFD4B1342C6`.

Inside `bl_pq512_crypto_core`, five standalone BaseFold benchmark/ledger binaries, the isolated
BaseFold hiding module, and the B=64 nonprotocol spike binary had no current importer and were
removed. The unreferenced 2026-07-13 archive manifest for a different package name/layout was also
removed. In total the cleanup deletes 269 tracked files and 50,648 lines. The Construction 8.2
implementation, five-claim verifier, native masks, authenticated coordinator, migration-equivalence
test, two-claim differential controls, and retired-format rejection KAT remain unchanged.

Post-cleanup containing Rust verification is 264/264 optimized library tests with zero failures and
zero ignored tests; every remaining binary and doc-test group passed. Format, strict all-target
Clippy with warnings denied, and release no-default/no-std check all exit zero. The prior 266-test
count included the removed isolated BaseFold module's two self-tests and is historical.

Current Python collection finds 1,093 ordinary tests before the known absent canonical sibling
`../ops` stops collection. The full attack run completed 351 passes and 45 failures with one warning
and 10 passing subtests; every failure reached a protected batch/policy path that attempted to read
the absent `../ops/policy_spec_v1.yaml`. The focused foundation/security cleanup slice passes 14
tests with one canonical-ops mirror test deselected. The roadmap contract passes two tests and its
third test fails closed only because `../ops/launch_blockers.json` is absent. No check was weakened
to bypass that layout condition.

A broad ordinary run excluding the already-uncollectable `tests/test_batch_layer.py` remained
CPU-active through the 3,604.1-second command-wrapper timeout and finished immediately afterward,
but its terminal summary was no longer recoverable from the wrapper. The pytest cache recorded the
same missing-`../ops` families plus the previously observed attack failures. The run receives no
pass-count credit; focused gates and Rust containing gates above have complete terminal output.

H4 proof evidence and manifest identity do not change. Gate 2E state selection and atomic binding,
composition/simulator closure, H5 repeated p95, and H6 qualification remain the active order.

## 2026-08-01 model-independent technical handoff

The current architecture and execution plan no longer depend on a model remembering chat context or
inferring status from dated evidence. Documentation implementation commit
`238ed83729bd1b8fa7d4e061c2982eab2b4a5c54`, tree
`ed329dc9160b9b37def6bd031b384c7ccddf7ce7`, adds 695 lines and removes 50 across nine files.
Protected-path changes are zero.

`docs/CURRENT_TECH_STACK.md` is now the complete active-stack contract. It defines evidence terms,
frozen invariants, exact K128/K512 geometry, the ordered ten-step H4 proof flow, Rust/CUDA authority
split, decimal memory and concurrency model, privacy placement, fail-closed verifier order, exact
source ownership, required green evidence, execution order, and explicit nonclaims. Its source
readback checked 22 named authoritative files with zero missing. Rust/Python constant readback
reconciled 46,858/165,762 semantic calls, 52,429,015/209,715,415 `BLHBB101` bytes, one/four shards,
1,600 live wires, 131,072 padded permutations per shard, 6,073 GKR rounds, and 6,086 combined rounds.

The deterministic continuation contract near the top of `docs/IMPLEMENTATION_ROADMAP.md` is the
sole current execution algorithm. It contains:

- an explicit current-state matrix and authority rule for historical sections;
- a single dependency chain from Gate 2E through H5, H6, and Wave 3;
- Gate 2E stages 2E-0 through 2E-7 with inputs, outputs, interfaces, mutations, migration/failure
  semantics, finalist measurement, selection, and terminal-handoff requirements;
- an exact H5 matrix of one uncounted warm-up plus ten measured unique attempts for each profile,
  22 fresh launches total, with conservative ten-sample nearest-rank p95 equal to the maximum;
- complete measurement fields, driver/resource/no-swap/independent-verifier STOP rules, and
  first-principles throughput criteria; and
- twelve H6 theorem, simulator, parser, attack, identity, reproducibility, resource, side-channel,
  recovery, and evidence-seal obligations.

Gate 2E and H5 are now unambiguous. Candidate screening uses repeated state-component measurements,
then one uncounted complete warm-up and at least one fresh complete K128/K512 proof per eligible
finalist. Gate 2E selects and atomically binds the state plane. The separate H5
warm-up-plus-ten-per-profile campaign then qualifies the exact selected candidate. A candidate
paper number, state microbenchmark, or Gate 2E finalist run cannot receive H5 p95 credit.

Instruction-level contradictions were removed:

- `AGENTS.md` now records that the architecture requires two ops trees but this workspace is missing
  canonical `../ops`; it forbids constructing it from the app mirror;
- `CONTINUATION_MANDATE.md` makes the July handoff historical, preserves the full ideology, and
  names the current context-recovery order;
- historical R24 parallel/overnight plans are labeled non-executable and cannot restore removed
  RISC Zero or Stwo backends;
- the H0-H6 architecture says H0-H4's executable prototype boundary is complete while containing
  simulator/security obligations remain for H6; and
- the Rust crate-level documentation now describes the actual H4 proof core instead of the obsolete
  statement that it is not a proof system.

Verification after the change:

```text
py -3.14 -m pytest -q tests/test_foundation_spec.py
10 passed in 0.27s

py -3.14 -m pytest -q tests/test_security_freeze_spec.py -k "not app_layer_ops_is_an_exact_recursive_mirror_of_canonical_ops"
5 passed, 1 deselected in 0.09s

py -3.14 -m pytest -q tests/test_deployment_ready_roadmap_contract.py
2 passed, 1 failed in 0.21s
failure: FileNotFoundError for canonical ../ops/launch_blockers.json

cargo fmt --all -- --check
exit=0

cargo check --release --offline --locked --lib --no-default-features
exit=0

cargo clippy --release --offline --locked --all-targets --features std,parallel -- -D warnings
exit=0; warnings=0

git diff --check
exit=0

active stale-current claim scan
hits=0

authoritative source-path readback
checked=22; missing=0
```

The one deselection and one roadmap failure have the same pre-existing reason: canonical `../ops`
is absent. No test, mirror check, protected path, or policy byte was changed to bypass it. H4 proof
evidence, execution manifest, measured resources, and activation status are unchanged. No CUDA proof
was run during this documentation phase.

The exact next implementation action is Gate 2E-0 followed by 2E-1: freeze the C0 state fixtures and
complete-boundary control record, then define narrow canonical state-layout, relation, commitment,
opening, transition, migration, transcript, independent-verifier, and receipt interfaces. Do not
start with a lattice optimization, another proof backend, or H5.

## 2026-08-02 active/history documentation separation

The active handoff no longer interleaves dated execution language with current instructions. Five
former active documents were preserved line-for-line under `docs/history/` except for an explicit
`Archived` title marker:

- the 2,072-line implementation roadmap;
- the 1,365-line throughput-recovery plan;
- the 1,022-line heterogeneous-coprocessor architecture;
- the 427-line proving-optimization review; and
- the 254-line proof-core README.

Readback compared every archived line after the title against Git commit `e640e88`; all five bodies
were equal. `docs/history/README.md` makes the archive non-executable and routes current work back
to the active contracts. `docs/REJECTED_ARCHITECTURES.md` now indexes the detailed archived
provenance without restoring a rejected path.

The active replacements are current-only:

| Document | Active lines | Purpose |
| --- | ---: | --- |
| `docs/IMPLEMENTATION_ROADMAP.md` | 424 before final evidence append | Exact authority, invariants, 2E-0 through 2E-7, H5/H6, all 93 package rows, waves, Git discipline |
| `docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md` | 225 | Complete-boundary optimization and H5 measurement/STOP contract |
| `docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md` | 220 | Selected construction, geometry, schedule, authority, memory, verifier, H4 evidence |
| `docs/PROVING_OPTIMIZATION_REVIEW.md` | 108 | Current optimization policy and excluded paths |
| `experiments/bl_pq512_crypto_core/README.md` | 148 | Current crate role, sources, worker rules, commands, and next dependency |

Stale tests that required R24/R25/R26 narrative inside the active roadmap were corrected to test
current security/package invariants and archived provenance separately. A new test rejects seven
known dated-execution headings from every active handoff file and requires all five archives and
the archive authority warning.

Verification:

```text
py -3.14 -m pytest -q tests/test_foundation_spec.py \
  tests/test_security_freeze_spec.py \
  tests/test_deployment_ready_roadmap_contract.py \
  -k "not app_layer_ops_is_an_exact_recursive_mirror_of_canonical_ops and not launch_blocker_manifest_has_only_one_external_assurance_dependency"
18 passed, 2 deselected in 0.41s

py -3.14 -m pytest -q tests/test_deployment_ready_roadmap_contract.py
2 passed, 1 failed in 0.20s
failure: FileNotFoundError for trusted canonical ../ops/launch_blockers.json

cargo fmt --all -- --check
exit=0

cargo check --release --offline --locked --lib --no-default-features
exit=0

cargo clippy --release --offline --locked --all-targets --features std,parallel -- -D warnings
exit=0; warnings=0

git diff --check
exit=0

active dated-heading scan
hits=0

archived body readback against e640e88
5/5 equal after title
```

The one full-roadmap failure is the same pre-existing fail-closed canonical-ops condition. No ops
tree, policy byte, protected path, proof source, proof byte, execution manifest, or activation state
changed. No CUDA proof was launched. H4 evidence and the exact Gate 2E-0 then 2E-1 implementation
boundary remain unchanged.

## 2026-08-01 complete Ethereum Strawmap compatibility contract

The containing architecture is now unambiguous: Blind Ledger is an Ethereum-settled,
EVM-compatible **based validity rollup by compulsory design**. Ethereum ordering is canonical, no
permanent privileged sequencer may own canonical history, every accepted L2 transition requires
the Blind Ledger claim proof and containing rollup validity proof, and public Ethereum DA is
fixed-shape non-PHI only. Draft Ethereum features are versioned compatibility adapters, never
hidden release dependencies.

Implementation commit `c4b2bd86ce26f5900314d7836f2d629754886c0b`, tree
`90cb5dd9d90f2902f797e0585b98178f87a52d86`, adds 437 lines and removes 28 across 20 files.
Protected-path changes are zero.

`docs/ETHEREUM_STRAWMAP_BASED_ROLLUP_COMPATIBILITY.md` records the live
`strawmap.org`/Google Drawing snapshot, not a PDF or screenshot. The Drawing identifier is
`1GkcGfQv9kxgrYQMyu0BYGcZya0gIDG_wQ7GsFJEsdzY`, its label said updated Jul 29, 2026, and the
fetched SVG SHA-256 is
`6514BA52E8EABDDE9162F460E3BAAC52BA0DBA62BA5AA0EAE546FBCB6C7163C8`.
All 23 linked EIPs were fetched from canonical `ethereum/EIPs`; the sorted
`filename:SHA-256` manifest hashes to
`D18D3AB07B30535E647B2E23665958A229934C99318371C61E0C567650561AB2`.

The exact linked set is EIPs 7503, 7732, 7773, 7805, 7919, 7928, 7938, 7999, 8007, 8025,
8070, 8077, 8079, 8081, 8136, 8141, 8142, 8184, 8198, 8200, 8250, 8272, and 8297.
The contract distinguishes Review, Draft, Stagnant, shipped/final, and research maturity; maps
every EIP to an exact Blind Ledger decision; includes the linked primary specification, GitHub,
Ethereum Research, PQ, leanVM/leanXMSS/leanMultisig, ethp2p, evm-asm, and RISC-V sources; and
assigns all consensus, data, execution, PQ, privacy, networking, latency, and throughput
through-lines to existing R01-R12 packages.

The stale active EIP-7707 access-list reference was removed. EIP-7928 BAL is the current Review
compatibility surface. The reason EIP-7707 must not be used remains in the rejection ledger.
BAL is explicitly not the private fixed-padded CBAM. EIP-7503 wormholes, EIP-8184 LUCID,
EIP-8025 optional execution proofs, EIP-8079 native rollups, and Ethereum leanVM are explicitly
forbidden from substituting for Blind Ledger privacy, strict-PQ authority, mandatory validity, or
the selected inner proof.

R01-R12 remain 12 open packages and the total stays 6/93 complete. Their rows now require a pinned
deployed baseline, multi-fork fixtures, proof/verifier/fork/data identity, BAL/CBAM separation,
keyed-nonce and recent-root semantics, final-fork differential proving, fork-aware finality,
ePBS/FOCIL adversarial based ordering, payload/blob/cell reconstruction, finalized bridge
accounting, opaque forced inclusion, fail-closed versioned adapters, and baseline plus future-fork
end-to-end tests. No rollup, production verifier, native-rollup adapter, or Ethereum-security claim
was implemented or activated by this documentation phase.

Verification:

```text
py -3.14 -m pytest -q tests/test_foundation_spec.py
12 passed in 0.20s

py -3.14 -m pytest -q tests/test_foundation_spec.py \
  tests/test_security_freeze_spec.py \
  tests/test_deployment_ready_roadmap_contract.py \
  -k "not app_layer_ops_is_an_exact_recursive_mirror_of_canonical_ops and not launch_blocker_manifest_has_only_one_external_assurance_dependency"
19 passed, 2 deselected in 0.40s

py -3.14 -m pytest -q tests/test_deployment_ready_roadmap_contract.py
2 passed, 1 failed in 0.21s
failure: FileNotFoundError for trusted canonical ../ops/launch_blockers.json

cargo fmt --all -- --check
exit=0

cargo check --release --offline --locked --lib --no-default-features
exit=0 (isolated C:\tmp target used because the pre-existing source-tree cargo lock denied access)

cargo clippy --release --offline --locked --all-targets --features std,parallel -- -D warnings
exit=0; warnings=0

git diff --check
exit=0

Strawmap contract readback
23 EIP rows; 23 unique; 12 R01-R12 rows; 48 HTTPS links; 0 PDF authority links

active stale EIP-7707 reference scan
hits=0
```

No CUDA proof was launched. H4 evidence, proof bytes, execution manifest, resource measurements,
`proofSuiteId=null`, activation=false, the missing canonical `../ops` condition, and the next
Gate 2E-0 then 2E-1 code boundary are unchanged.

## 2026-08-01 L1-lockstep impact and activation clarification

The Strawmap contract no longer requires a successor to infer whether an Ethereum change is
automatic, mandatory, optional, or irrelevant to the L2. Implementation commit
`e5932847c4d4f8fe92ca15484957472bd1a7db3d`, tree
`9f5e394ca2e33523e51148e1a7c5dd8f7c20a8c5`, adds 194 lines and removes five across 13 files.
Protected-path changes are zero.

Every one of the 23 linked EIPs now has an exact impact class, inherited L1 effect, direct Blind
Ledger work, activation trigger, and R01-R12 owner. The five classes are:

- `INHERIT`: L1 supplies the consensus/timing/network property, but BL must update and test its
  observer, finality, reorg, DA, monitoring and capacity assumptions before claiming the benefit;
- `L1-COMPAT`: BL directly changes a parser, producer, Engine/network/DA adapter, L1 transaction,
  settlement contract assumption, receipt, proof/data binding, or monitoring surface;
- `L2-PARITY`: when the selected EVM-compatibility profile mirrors a final L1 execution change,
  the L2 executor, state-transition prover, gas/trace/witness logic, independent verifier and
  receipts change atomically;
- `OPTIONAL`: the baseline does not need the feature and rejects it until R11 selection,
  migration, rollback, security/privacy/PQ review, interoperability and measured benefit pass; and
- `RESEARCH`: no code, capacity, security or release credit.

The deterministic lockstep lifecycle is now explicit in both the compatibility contract and active
roadmap: discover; freeze an exact `ethereum_compat_manifest`; reproduce old/boundary/new and
mixed-client cases; implement affected R02-R11 boundaries; run canonical/differential/adversarial
tests; rehearse complete R12 finality and rollback; activate the fork-bound manifest atomically;
and reconcile post-fork canonical receipts, DA, finality and conservation. Unknown or partial fork
support pauses new batch acceptance/publication while preserving the reviewed exit/recovery path
from the last supported finalized state.

The architecture now states the critical separation directly: Blind Ledger does not reimplement L1
consensus, but inherited behavior is never zero work; DA/Engine/network changes require direct
publisher/reconstruction integration; L1 execution changes require settlement compatibility and
conditional L2 prover parity; optional transaction/privacy/native-proof features remain disabled.
This preserves compulsory based sequencing while moving with finalized L1 behavior instead of
against it.

Verification:

```text
py -3.14 -m pytest -q tests/test_foundation_spec.py
12 passed in 0.31s

py -3.14 -m pytest -q tests/test_foundation_spec.py \
  tests/test_security_freeze_spec.py \
  tests/test_deployment_ready_roadmap_contract.py \
  -k "not app_layer_ops_is_an_exact_recursive_mirror_of_canonical_ops and not launch_blocker_manifest_has_only_one_external_assurance_dependency"
19 passed, 2 deselected in 0.42s

git diff --check
exit=0

impact matrix readback
23 EIPs; 23 unique; every row has an impact class and R01-R12 owner
```

No code implementation, package status, H4 evidence, activation state, proof-suite identity, or
Gate 2E ordering changed. R01-R12 and the compatibility manifest remain future implementation work.

## 2026-08-01 Gate 2E-0/S0 C0 control freeze

The synthetic C0 control is now frozen at the current Gate 2E-0 boundary. The implementation is
`experiments/bl_pq512_crypto_foundation/c0_control_fixture.py`; its fresh-process measurement
boundary is `c0_control_measurement.py`. The exact K128/K512 manifest lengths remain 11,217 and
11,231 bytes with SHA3-512 identities:

```text
K128 74c6812c830f9d53d556712b2c08700dae11fd95777a82b01f498743de6e738d2accc6319c7870425debc668b401a92a20e88bcc96c591c8bebb74dc3b496d83
K512 5d45ffed375d27d64762d6c03ec832e894e6d34fc057f78d8b6885f9441c9835fe0e9999f46807ac083c69c12e2481f8e457d09d825b19506b02fc6a44793d20
```

The focused command
`py -3.14 -m pytest -q tests/test_bl_pq512_c0_control_fixture.py tests/test_bl_pq512_c0_control_measurement.py`
passed 9/9 in 32.37 seconds under the equivalent Python 3.14.4 launcher. Each measurement below
was a separate fresh process with the explicit synthetic environment; all values are decimal MB:

| Profile | Boundary | Seconds | Peak RSS MB | Scratch MB | Pagefile delta MB | Read/Write I/O MB |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| K128 | state-only | 3.074924 | 29.171712 | 0.000000 | 2.592768 | 0.000000 / 0.000000 |
| K128 | complete | 3.010325 | 29.708288 | 0.000000 | 3.010560 | 0.000000 / 0.000000 |
| K512 | state-only | 12.910909 | 37.777408 | 0.000000 | 6.602752 | 0.000000 / 0.000000 |
| K512 | complete | 13.353259 | 39.399424 | 0.000000 | 8.630272 | 0.000000 / 0.000000 |

The complete boundary returned the exact frozen manifest identities above. Scratch is zero because
the fixture invokes no scratch API and the measured process recorded zero read/write transfer I/O.
Pagefile values are observed process usage deltas and are not evidence of swap absence; H5 still
requires external pagefile/swap monitoring. The negative corpus covers stale reads, omitted and
reordered writes, duplicate identity, collision, root substitution, and conflicting updates.

This closes only the synthetic C0 control record. `proofSuiteId=null`, activation remains false,
real PHI/payments remain forbidden, the trusted canonical `../ops` launch-blocker state is still
absent, H4 remains one-run prototype evidence, and no production CUDA path was run. S1/2E-1 narrow
replaceable interfaces is the next implementation boundary.

## 2026-08-01 Gate 2E-1/S1 narrow interface freeze

S1 is now implemented and tested in
`experiments/bl_pq512_crypto_foundation/state_interface.py`. The module defines exactly 13 bounded,
wire-coded descriptors: state layout, key/value encoding, membership, absence, ordered access
manifest, memory consistency, commitment/opening, old/new transition, SHA3-512 public identifier,
migration/rollback, transcript contribution, independent verification, and atomic receipt. Each
descriptor carries its producer, consumers, public/private fields, grammar, maximum length,
domain/version/parameter identity, canonical decode rule, error family, retry behavior, crash
behavior, and mutation cases.

The S1 source SHA-256 is
`811363691DACCA11913705D3CEBB14CA93158824493EF46EC75DEC2A9BE01297`. The descriptor readback
is 13 interfaces with wire codes 1 through 13; the `BLSI` header is 8 bytes with a 4,096-byte
maximum payload. A representative K128 `BLTR` transition encodes to 329 bytes and begins with
`424c545201`.

The generic `BLSI` envelope has an 8-byte header and a 4,096-byte maximum payload. The concrete
`BLTR` transition codec requires fixed-width nonzero SHA3-512 roots/digests, explicit profile and
parameter identities, and `sequence_after = sequence_before + 1`; it rejects truncation, trailing
bytes, retyping, parameter substitution, root substitution, and sequence replay. The
`sha3_512_public_identifier` port hashes its domain/version/parameter identity and bounded source
tuple with SHA3-512. The module imports no claim, payment, application, settlement, or proof
implementation.

Focused verification:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_state_interface.py tests/attacks/test_bl_pq512_state_interface_attacks.py
22 passed in 0.15s
```

This completes only the S1 interface boundary. C1-C4 scalar state-relation controls, commitment
selection, H4 binding, migration closure, H5/H6 qualification, `proofSuiteId`, activation, and
production deployment remain open. The trusted canonical `../ops` launch-blocker state remains
absent, and no production CUDA path was run. The next roadmap boundary is Gate 2E-2/S2.

## 2026-08-01 Gate 2E-2/S2 scalar C1-C4 controls — COMPLETE

Gate 2E-2/S2 is now implemented at the scalar synthetic-reference boundary. The new
`experiments/bl_pq512_crypto_foundation/scalar_state_relation_controls.py` module contains C1 dense
and touched-sparse persistent-memory controls, C2 transparent index/value dictionary, C3
touched-projection RAM, and C4 compact shuffle-based memory consistency. Each control replays the
same bounded four-lane transition, membership/absence queries, update, money summary, and fixed
shape; each exposes candidate-specific derived work counters and an independent verifier that
rebuilds the transition rather than trusting candidate roots or result fields. C1 dense, C1 sparse,
C2, C3, and C4 are all controls; no candidate is selected, committed to H4, or activated.

`experiments/bl_pq512_crypto_foundation/scalar_state_relation_parity.py` is the only C0 bridge. It
compares candidate-independent semantic parity for both frozen profiles: replay/benefit/obligation/
ledger operation, access, position, and proof-node geometry; membership and absence; cursor and
state/update-change behavior; representative approved/duplicate/conflict/denial/cover/correction
outcomes; and `(80, 80, 80)` plan/debit/credit totals. Candidate-specific roots are not host-compared
to C0 roots. The bounded parity record SHA3-512 is
`fc99b31b333a6ec3a19cc55099bd612dcd1d7964115301bbcb9d512d8efe184bc320f04af65f3aa8417bf03fe368e05dddc1d2bd7fd2b2005280e777f0d496c4`.

The focused S2 command and raw result were:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_scalar_state_relation_controls.py tests/attacks/test_bl_pq512_scalar_state_relation_controls_attacks.py
14 passed in 21.50s
```

The containing S1/S2 command and raw result were:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_scalar_state_relation_controls.py tests/attacks/test_bl_pq512_scalar_state_relation_controls_attacks.py tests/test_bl_pq512_state_interface.py tests/attacks/test_bl_pq512_state_interface_attacks.py
36 passed in 24.67s
```

The C1 dense full-capacity scan, C3 touched-projection quadratic online counter, and C4
initialization/persistent-scan counter are derived scalar work labels, not measured timings,
throughput, memory, security, or selection evidence. The full ordinary Python lane was attempted
and failed closed during collection with:

```text
FileNotFoundError: [Errno 2] No such file or directory: 'C:\\Users\\neers\\Documents\\Codex\\2026-07-27\\he\\work\\Blind-Ledger-Wave2-Workspace-2026-07-26\\..\\ops\\policy_spec_v1.yaml'
```

No mirror was copied and no check was weakened. The ordinary Python lane failed closed during
collection on the missing canonical `../ops/policy_spec_v1.yaml`. A full `tests/attacks` rerun
reached 100% progress but exited 1 after 182.2 seconds; its failures include the same exact missing
canonical path. The bounded S2 attack suite above passed. `proofSuiteId=null`, activation remains
false, real PHI/payments remain forbidden, the canonical `../ops` launch blocker remains absent, and
no production CUDA path ran. Gate 2E-3/S3 native-hiding PQ commitment screening is the next
boundary.

## 2026-08-01 Gate 2E-3/S3 PQ commitment screening — REFERENCE COMPLETE, NO ADMISSION

Gate 2E-3/S3 is implemented at the bounded synthetic screening boundary. The new
`experiments/bl_pq512_crypto_foundation/pq_commitment_screening.py` module defines a common
fixed-width masked commitment/opening envelope, exact descriptor and parameter identities for the
Jindo-style lattice, Module-SIS, RoKoko-style lattice, and transparent hash/code families, a
dual-ML-DSA-87/SLH-DSA-SHAKE-256f authenticated public-coin round, and an independent opening
verifier. The envelope uses SHA3-512 reference masking only; it is not a lattice PCS, complete
zero-knowledge proof, H4 binding, or production/activation path.

All four descriptors reject closed. The three lattice descriptors lack pinned primary source,
parameters, license, and reviewed theorem evidence. The transparent hash/code descriptor has the
internal 512-bit parameter reference and 256-bit labels but still lacks reviewed native-hiding
composition and complete-proof evidence. No candidate is admitted, selected, assigned
`proofSuiteId`, or activated.

Focused command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_pq_commitment_screening.py tests/attacks/test_bl_pq512_pq_commitment_screening_attacks.py
8 passed in 3.27s
```

This is reference test-run timing, not complete-proof or H5 evidence. The next bounded boundary is
Gate 2E-4/S4 atomic composition: independently replay the S2 relation, bind the S3 transcript and
transition, and reject every field mutation before any state acceptance.

## 2026-08-01 Gate 2E-4/S4 atomic composition - REFERENCE COMPLETE, NO ADMISSION

Gate 2E-4/S4 is implemented at the bounded synthetic composition boundary in
`experiments/bl_pq512_crypto_foundation/atomic_state_composition.py`. The composition keeps the S2
relation candidate separate from the S3 commitment-backend identity; independently replays the S2
candidate; derives one fixed 12-field projection, layout identity, old/new aggregate roots,
manifest, and strict `BLTR` transition; verifies the S3 authenticated public-coin opening; and
binds the deferred H4 reference identity, independent verifier identity, attempt identity,
commitment, transition, and receipt. The canonical relation payload hashes private membership
keys/values and absence keys rather than serializing raw private keys. The H4 binding is explicitly
deferred, `proofSuiteId=null`, activation is false, and no backend or relation is selected.

Focused command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_atomic_state_composition.py tests/attacks/test_bl_pq512_atomic_state_composition_attacks.py
6 passed in 10.11s
```

The attack suite rejects transition-root, commitment, opening, projection, relation-candidate,
proof-identity, and relation-result mutations. This closes only a synthetic non-spliceable
composition/reference-receipt boundary. It is not a production proof, PCS, H4 acceptance,
migration proof, H5 measurement, selection, or activation result. The next bounded boundary is
Gate 2E-5/S5 migration, rollback, recovery, and failure semantics.

## 2026-08-02 Gate 2E-5/S5 migration and failure semantics - REFERENCE COMPLETE, NO ADMISSION

Gate 2E-5/S5 is implemented at the synthetic state-plane boundary in
`experiments/bl_pq512_crypto_foundation/state_migration_recovery.py`. It defines immutable
SHA3-512 checkpoints, independently verifies the S4 composition before preparing publication,
publishes only store-owned pending compare-and-swap records, and keeps the current checkpoint
unchanged on every rejected operation. Migration preserves the logical state root, state manifest,
and sequence while rotating the layout, parameter, and verifier identities at exactly the next
epoch. Rollback and recovery restore only complete checkpoints already known to the store and
advance to a strictly newer epoch, so old transition attempts cannot replay. The reference
equivalence record is not a production migration theorem and old private bytes are never
reinterpreted under a new layout.

Focused command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_state_migration_recovery.py tests/attacks/test_bl_pq512_state_migration_recovery_attacks.py
10 passed in 10.10s
```

The positive and attack corpus covers composition publication, crash before publication, conflicting
CAS, root/manifest substitution, identity downgrade, layout/parameter/verifier rotation, rollback,
recovery, stale epoch/sequence, corrupted and unknown checkpoints, partial/self-consistent forged
records, and mixed K128/K512 profiles. This is reference failure/equivalence evidence only; no
durable custody, production migration proof, backend selection, H5 measurement, `proofSuiteId`, or
activation is closed. The next bounded boundary is Gate 2E-6/S6 component evidence and Gate
2E-7/S7 selection/handoff.

## 2026-08-02 Gate 2E-6/S6 and Gate 2E-7/S7 reference bake-off and handoff - NO ADMISSION

`experiments/bl_pq512_crypto_foundation/gate_2e_selection.py` now measures the identical synthetic
S2/S3/S4 reference component twice for each of the four screened commitment backends and both frozen
K128/K512 profiles: 16 observations total. Each record independently verifies the scalar relation,
authenticated reference opening, and S4 receipt; observed timing, verifier timing, and derived work
are labeled separately, proof bytes are zero, and external complete-boundary monitoring is explicitly
`NOT_RUN_NO_ELIGIBLE_FINALIST`.

S3 recomputation rejects every backend, so no candidate receives a complete warm-up or complete-proof
attempt. S7 retains `C0_CONTROL` as an unselected control with
`selection_status=C0_CONTROL_RETAINED_NO_ELIGIBLE_PQ_FINALIST`, `selected_backend_id=null`,
`proofSuiteId=null`, and activation false. The handoff is explicitly unsealed and records
`no_backend_admitted`, `complete_boundary_not_authorized`, `h4_atomic_binding_deferred`, and the
missing canonical `../ops` blocker. Timing is reference-component evidence only and receives no
selection credit.

Focused command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_gate_2e_selection.py tests/attacks/test_bl_pq512_gate_2e_selection_attacks.py
6 passed in 34.04s
```

This closes only the S6/S7 synthetic measurement/rejection/handoff boundary. It does not select a
PQ backend, close complete composition/simulator/leakage/state-proof receipt obligations, qualify
H5, assign `proofSuiteId`, authorize activation, or establish production throughput. The next
bounded boundary is the complete composition/simulator/leakage/state-proof receipt ledger.

## 2026-08-02 Gate 2E terminal composition/simulator/leakage/state-proof receipt ledger - REFERENCE COMPLETE, BLOCKED

The terminal evidence boundary is now implemented in
`experiments/bl_pq512_crypto_foundation/gate_2e_terminal_ledger.py`. It independently replays the
S4 composition, derives and checks the S5 before/after checkpoints, verifies both frozen C0 profile
shapes and the exact seven positive/negative parity classes, checks the fixed 12-field public
boundary, confirms that raw private relation keys/values are absent from the public ledger, and
recomputes the S6/S7 selection and handoff identities. The ledger contains 11 ordered obligation
records and serializes only bounded public identities, statuses, sources, and blocker labels.

The ledger is deliberately unsealed:

```text
status=UNSEALED_BLOCKED_GATE_2E_TERMINAL_LEDGER
ledger_digest_sha3_512=2cbc9e48ea14e4e6dfeae9eebe46c34ad4ed551d63f946fcb696abc480c407d5893f7d29acd7349858e6ed9f496db121c1d00940504bc050f264502eae098964
canonical_bytes=388
canonical_sha256=ac0331a2631361e85631095a8cc039004cb39bdcc0ad6d52883051f60c40d66d
source_sha256=98d959e0a614dd6938c1d3d47a3f127f68f6b9be1fb841a8fb26030a72386381
blockers=canonical_ops_missing,complete_leakage_scan_missing,complete_simulator_missing,h4_atomic_binding_deferred,no_backend_admitted,proof_suite_unselected
proofSuiteId=null
activation_allowed=false
```

Focused command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_gate_2e_terminal_ledger.py tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py
7 passed in 29.70s
```

Containing S1-S7 plus terminal-ledger command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_state_interface.py tests/attacks/test_bl_pq512_state_interface_attacks.py tests/test_bl_pq512_scalar_state_relation_controls.py tests/attacks/test_bl_pq512_scalar_state_relation_controls_attacks.py tests/test_bl_pq512_pq_commitment_screening.py tests/attacks/test_bl_pq512_pq_commitment_screening_attacks.py tests/test_bl_pq512_atomic_state_composition.py tests/attacks/test_bl_pq512_atomic_state_composition_attacks.py tests/test_bl_pq512_state_migration_recovery.py tests/attacks/test_bl_pq512_state_migration_recovery_attacks.py tests/test_bl_pq512_gate_2e_selection.py tests/attacks/test_bl_pq512_gate_2e_selection_attacks.py tests/test_bl_pq512_gate_2e_terminal_ledger.py tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py
73 passed in 91.58s
```

This closes only the synthetic terminal ledger/reference replay. It does not close the complete
semantic/state/PCS simulator, side-channel or unlinkability campaign, strict-PQ security ledger,
reviewed state/commitment admission, H4 parent/transcript/proof/verifier binding, canonical ops
identity, H5, H6, `proofSuiteId`, activation, or production throughput. The next authorized
boundary is a reviewed replacement state/commitment admission path or, while that remains absent,
the fail-closed H5/H6 preflight and qualification ledger; no complete-proof run receives credit
from this reference record.

## 2026-08-02 H5 qualification preflight - BLOCKED

The bounded H5 qualification preflight is now implemented in
`experiments/bl_pq512_crypto_foundation/h5_qualification_preflight.py`. It independently replays
the terminal Gate 2E context, validates the reference hardware record, checks the actual canonical
`../ops` tree against the app-layer mirror without creating or copying files, and freezes the exact
campaign shape: one uncounted warm-up plus ten unique measured launches for each K128/K512 profile,
22 fresh launches total. It never starts CUDA or accepts cached proofs, cached witnesses, retries,
partial-campaign substitution, `proofSuiteId`, or activation.

The current preflight record is:

```text
status=BLOCKED_H5_PREFLIGHT
ledger_digest_sha3_512=2cbc9e48ea14e4e6dfeae9eebe46c34ad4ed551d63f946fcb696abc480c407d5893f7d29acd7349858e6ed9f496db121c1d00940504bc050f264502eae098964
preflight_digest_sha3_512=8eb296bb3946df2881402e86e7b4f7ba86018f7ff7140ed513266e3b0c65939a04aebe96f638131c69d5326e614a1dd57961ad1b103f748009b60bb4cd1dc435
protocol_id_sha3_512=a9aea0f7e884e867e10d93267038ee40500564cb68f7b5779fc40ec8a3fd43c05172ef955a0145d3da4db8da8f43799465917db2ebec57de7376ad3d7911d215
canonical_ops_status=MISSING_CANONICAL_SIBLING
reference_hardware_status=NOT_READY
fresh_launch_count=22
proofSuiteId=None
activation_allowed=False
blockers=gate_2e_ledger_unsealed,state_plane_unselected,h4_atomic_binding_deferred,complete_simulator_missing,complete_leakage_scan_missing,strict_pq_security_ledger_open,proof_suite_unselected,canonical_ops_missing,reference_hardware_not_ready,h5_campaign_not_started,h5_external_monitor_not_configured,h5_source_readback_not_captured,h5_no_qualified_evidence
```

Focused preflight and attack verification:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_h5_qualification_preflight.py tests/attacks/test_bl_pq512_h5_qualification_preflight_attacks.py
6 passed in 44.60s
```

Containing evidence:

```text
benchmark + S6/S7 + terminal ledger + H5 preflight: 61 passed in 117.72s
S1-S7 + terminal ledger + H5 preflight: 79 passed in 175.33s
git diff --check: exit 0
py_compile: exit 0
```

This does not run H5, close Gate 2E, select a state/commitment backend, close H6, assign
`proofSuiteId`, activate, or establish production throughput. The exact canonical sibling
`../ops` remains absent and the reference hardware is not ready because its recorded free disk
(`59,091,513,344` bytes) is below the required headroom (`73,100,269,364` bytes). The next safe
boundary is reviewed state/commitment admission and atomic H4 binding; no complete-proof launch
receives credit before those gates close.

## 2026-08-02 H6 qualification preflight - BLOCKED

The bounded H6 qualification preflight is now implemented in
`experiments/bl_pq512_crypto_foundation/h6_qualification_preflight.py`. It independently replays
the blocked H5/terminal Gate 2E context, reads the actual candidate registry without modifying it,
and requires `CANDIDATE_UNQUALIFIED`, eight null module identities, `proofSuiteId=None`, and
`activation_allowed=False`. It records all twelve H6 obligations with explicit evidence classes;
five records are `BLOCKED`, five are `OPEN`, and two are `REFERENCE_ONLY`.

Raw H6 preflight record:

```text
status=BLOCKED_H6_PREFLIGHT
obligation_count=12
blocked_record_count=5
open_record_count=5
reference_only_record_count=2
blocker_count=24
blockers=no_backend_admitted,proof_suite_unselected,strict_pq_security_ledger_open,complete_simulator_missing,proof_grammar_unselected,h4_atomic_binding_deferred,attack_corpus_incomplete,cross_language_verifier_kats_open,source_toolchain_dependency_sbom_open,offline_reproducible_builds_open,gate_2e_ledger_unsealed,state_plane_unselected,complete_leakage_scan_missing,canonical_ops_missing,reference_hardware_not_ready,h5_campaign_not_started,h5_external_monitor_not_configured,h5_source_readback_not_captured,h5_no_qualified_evidence,side_channel_unlinkability_open,production_migration_theorem_open,complete_evidence_manifest_missing,h6_no_qualified_evidence,wave3_verifier_state_custody_open
h5_preflight_digest_sha3_512=8eb296bb3946df2881402e86e7b4f7ba86018f7ff7140ed513266e3b0c65939a04aebe96f638131c69d5326e614a1dd57961ad1b103f748009b60bb4cd1dc435
suite_registry_digest_sha3_512=307439093721aeaa9a70ef00d546f06af5f50b73781f9f19b8b02cca8c3d36ee1ef36e9981d49a59d10d8d7768fec079d40e05b6c008d7913c9caf4cc52cf974
suite_registry_canonical_digest_sha3_512=d082aaec00392f6ae7c7c37a52b6b18ab0fccd5fb08654ec9e326d8c20dd355e13f02b240577823f18b06f50aa165d25f5479d2ba1067beb80dd20ab9d6724e0
preflight_digest_sha3_512=680d73501851b316d969f811e23aa04985cacfce04df5bea8bd1b6e8553ddd07f12e08d89c79915a80c86f175eb9973cd3825e8ce7e09e2b4122cee44bcd24d7
proofSuiteId=None
activation_allowed=False
```

Focused command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_h6_qualification_preflight.py tests/attacks/test_bl_pq512_h6_qualification_preflight_attacks.py
6 passed in 30.02s
```

Containing Gate 2E/H5/H6 command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_state_interface.py tests/attacks/test_bl_pq512_state_interface_attacks.py tests/test_bl_pq512_scalar_state_relation_controls.py tests/attacks/test_bl_pq512_scalar_state_relation_controls_attacks.py tests/test_bl_pq512_pq_commitment_screening.py tests/attacks/test_bl_pq512_pq_commitment_screening_attacks.py tests/test_bl_pq512_atomic_state_composition.py tests/attacks/test_bl_pq512_atomic_state_composition_attacks.py tests/test_bl_pq512_state_migration_recovery.py tests/attacks/test_bl_pq512_state_migration_recovery_attacks.py tests/test_bl_pq512_gate_2e_selection.py tests/attacks/test_bl_pq512_gate_2e_selection_attacks.py tests/test_bl_pq512_gate_2e_terminal_ledger.py tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py tests/test_bl_pq512_h5_qualification_preflight.py tests/attacks/test_bl_pq512_h5_qualification_preflight_attacks.py tests/test_bl_pq512_h6_qualification_preflight.py tests/attacks/test_bl_pq512_h6_qualification_preflight_attacks.py
85 passed in 151.88s (0:02:31)
```

This is evidence-boundary scaffolding only. It does not close any H6 obligation, admit a state or
commitment backend, bind H4, run H5, assign `proofSuiteId`, enable activation, or establish
production throughput.

## 2026-08-02 current-source UDR/native-hiding reconciliation - VERIFIED, NO ADMISSION

The current implementation and its machine-readable nonactivating interface vector had drifted
from stale expectations retained from the superseded worksheet. The source-derived values are now
aligned in the focused tests and vector: the six unselected query candidates are
`617/378/309/281/268/262`, the corresponding mask degrees are `3149/1954/1609/1469/1404/1374`,
the K512 rate-half randomizer count is `6,899,459`, the entropy lower bound is `206,983,770` bits,
the extension-row count is `3`, and the interface per-term floor is `256` bits. The registry's
explicitly marked superseded historical values were not rewritten.

Focused command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_native_hiding_parameters.py tests/attacks/test_bl_pq512_native_hiding_parameters_attacks.py tests/test_bl_pq512_unique_decoding_parameters.py
15 passed in 0.91s
```

Containing current algebra/hiding command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_unique_decoding_parameters.py tests/attacks/test_bl_pq512_unique_decoding_parameters_attacks.py tests/test_bl_pq512_native_hiding_parameters.py tests/attacks/test_bl_pq512_native_hiding_parameters_attacks.py tests/test_bl_pq512_theorem_schedule.py tests/attacks/test_bl_pq512_theorem_schedule_attacks.py tests/test_bl_pq512_circle_fri.py tests/attacks/test_bl_pq512_circle_fri_attacks.py tests/test_bl_pq512_circle_hiding_simulator.py tests/attacks/test_bl_pq512_circle_hiding_simulator_attacks.py tests/test_bl_pq512_circle_quotient_masking.py tests/attacks/test_bl_pq512_circle_quotient_masking_attacks.py
62 passed in 59.43s
```

This is a source/vector consistency correction only. It does not select a commitment backend,
claim a native-hiding theorem, bind state into H4, run H5, assign `proofSuiteId`, enable
activation, or convert any historical worksheet into qualification evidence.

The admission audit remains blocked by the actual current evidence: all four Gate 2E commitment
descriptors reject for missing reviewed exact source/parameters/theorem or complete composition;
the Rust H4 core binds a semantic hash-bus statement but does not prove the persistent
replay/payment state transition; and the available state implementations are explicitly synthetic
references. At the time of this audit the canonical sibling `../ops` was absent and the old
15%-reserve record showed `59,091,513,344` free bytes versus `73,100,269,364` required, so the
exact H5 22-launch campaign was not started.

## 2026-08-02 operational disk-floor correction - VERIFIED, H5 STILL BLOCKED

The recorded reference hardware had 59,091,513,344 free bytes on a 487,335,129,088-byte
system disk. The prior 150,000-ppm (15%) operational reserve required 73,100,269,364 bytes and
blocked the preflight. First-principles sizing of the current H4 artifact envelope showed that
this reserve was a policy floor rather than the proof resource limit, so the floor was reduced by
exactly 10x to 15,000 ppm (1.5%), requiring 7,310,026,937 bytes. The immutable 5,000,000,000-byte
peak-RSS limit, strictly-below-5,000,000,000-byte scratch limit, zero-swap rule, p95 limits,
privacy/shape/ABI rules, PQ requirements, proof binding, `proofSuiteId`, and activation state
were not changed.

Changed boundary files are the benchmark validator/schema, recorded hardware capture, canonical
synthetic fixture self-hashes, and their focused/attack expectations. The benchmark boundary
passed:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_benchmark_evidence.py tests/attacks/test_bl_pq512_benchmark_evidence_attacks.py
42 passed in 0.45s
```

The H5/H6 preflight boundary passed 12 tests in 86.66 seconds. Its refreshed public state is:

```text
h5_status=BLOCKED_H5_PREFLIGHT
h5_preflight_digest_sha3_512=cdd2a4ec4728d0ca76539e0a348eaf54df840fc0b4a93a40ec587182a7abfbf77631e3db3a5bcb4ed2a847532cd2655f43fe99559912e2d931951efa9a062e03
canonical_ops_status=MISSING_CANONICAL_SIBLING
reference_hardware_status=READY
fresh_launch_count=22
h6_status=BLOCKED_H6_PREFLIGHT
h6_preflight_digest_sha3_512=a8d7fbfdc1ad3585a004da3ca2ef37790fb7ded0bed8e7b99b978a8716480ad074ca0b52c6b317c59eeb4274fac114c490781f9d76d3f5278cb909ce57f989b5
proofSuiteId=None
activation_allowed=False
```

This removes only `reference_hardware_not_ready`; no package is newly qualified. State/commitment
admission, atomic H4 binding, the missing trusted canonical `../ops` sibling, complete simulator
and leakage evidence, H5 execution, H6 qualification, `proofSuiteId`, and activation remain
closed or blocked as recorded above.

## 2026-08-02 state-plane implementation and native H4 binding seam - VERIFIED, ADMISSION STILL OPEN

The missing real state boundary is no longer only a synthetic S2/S4 reference. The new
`experiments/bl_pq512_crypto_foundation/state_plane.py` implements fixed-width SHA3-512 roots over
every bounded slot, an exact all-slot old/new transition relation, a 512-bit pad-masked SHA3
commitment tied to the authenticated public-coin digest, independent replay verification, and
crash-safe cross-process compare-and-swap publication. Its public dictionary and receipt expose
digests and identities only; private keys, values, operations, and openings remain in the private
replay object.

The native `k512_atomic_semantic_prototype` now accepts `state-file:<path>` and independently
recomputes the envelope before binding its statement into the existing H4 parent. It also binds the
recomputed state binding digest into the native atomic receipt. The diagnostic
`--verify-state-binding` path is nonactivating and does not claim a state AIR or a qualified proof
suite.

Focused state-plane command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_state_plane.py tests/attacks/test_bl_pq512_state_plane_attacks.py
9 passed in 0.19s
```

Native Rust formatting/unit boundary:

```text
cargo fmt --all -- --check
exit 0
cargo test --offline --locked --features std --bin k512_atomic_semantic_prototype
4 passed; 0 failed
```

Python/Rust K128-shape cross-language readback matched exactly:

```text
state_plane_binding_verified=true
state_plane_statement_sha3_512=f3c37c25e22d3e4d7b2500b553151bae34bca8fc84ecea1606af8532149cebfc13f33e014fa3c0a9c4505eacbcb303118965885416a8e634a3c461eb0517a0c7
state_plane_binding_digest_sha3_512=c648d0382061c791c4cf599f0fa8d0a7d7b647ddf9b6fceb600254686a3287cf13aec483a2e26c8a0a8cdb76ea3de7c149c9da2362695ae2c019f2810d8a5ffb
```

Mutating the envelope failed closed with `ERR:state_binding_snapshot_layout`. The Gate 2E ledger
records `STATE_PLANE_IMPLEMENTED_H4_PENDING` when supplied with this proof, but the current default
preflight context remains `STATE_PLANE_NOT_PROVIDED`; no proof suite or activation state changed.
The current ledger digest is
`91e65c9c4dfb3e173e2b2792d96422e272516cb43e62a77520145e981edc2dcd58d6e148ceca74fab5c1bd662cf65cc1c804e9ae707f9b5a91207e4db98a40c9`.

The refreshed default preflight remains:

```text
h5_status=BLOCKED_H5_PREFLIGHT
h5_preflight_digest_sha3_512=f3da98dae8c2cbcb9d80dec755247b64f53b97e258e480d1f89a3e6be9d7a1f2120331fc9b5111a25e133cf43d48b79cff58016fd595e0669262d87a64e2aa24
canonical_ops_status=MISSING_CANONICAL_SIBLING
reference_hardware_status=READY
fresh_launch_count=22
h6_status=BLOCKED_H6_PREFLIGHT
h6_preflight_digest_sha3_512=87c914f7c007fbe6615d51f7a19e81c4adad894147704af40801475093b91d2d9a9a94e9c0f1604d31d0eb86ed937f42d104a49a12c947cfc72a8e3605e7d554
proofSuiteId=None
activation_allowed=False
```

This is real implementation progress, not Gate 2E closure: the four existing PQ descriptors still
reject, the native H4 AIR does not yet constrain the persistent state relation itself, the complete
hiding/composition theorem and simulator remain open, the trusted canonical `../ops` sibling is
still unavailable, and H5 has not launched. No production CUDA, PHI, or payments are authorized.

## 2026-08-02 state-binding hardening, state-root AIR, and hash-pad security review - VERIFIED, NO ADMISSION

The native state seam is now stricter. The v3 atomic parent includes the state-binding digest;
each child shard receives the exact state statement and binding digest through dedicated
environment inputs; the child emits exact `state_plane_*` fields; and the Rust coordinator rejects
missing, zero, mismatched, or legacy state metadata before recording shard evidence. The digest is
also retained in the state-aware atomic receipt. Legacy non-state execution requires explicit
false/zero state fields and remains nonactivating.

The new
`experiments/fixed_shape_claim_air/state_plane_executable_air.py` is a real composable AIR
fragment, not a host-only check. It constrains every fixed-capacity old/new slot, boolean presence,
empty-slot zeroing, dynamic slot bytes to both canonical snapshot encodings, both encodings to
executable SHA3-512 message AIR, and each SHA3 digest to ordered public before/after root bytes.
`compose_state_plane_air` namespaces and merges that fragment into one executable AIR instance.
It does not yet include the full transition/manifest/projection/hash-pad receipt relation, and the
native H4 coordinator does not yet consume the fragment; those remain admission work.

Raw focused verification:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_state_plane.py tests/attacks/test_bl_pq512_state_plane_attacks.py tests/test_bl_pq512_state_plane_executable_air.py tests/attacks/test_bl_pq512_state_plane_executable_air_attacks.py tests/test_bl_pq512_hash_pad_security_review.py tests/attacks/test_bl_pq512_hash_pad_security_review_attacks.py tests/test_bl_pq512_pq_commitment_screening.py tests/attacks/test_bl_pq512_pq_commitment_screening_attacks.py tests/test_bl_pq512_gate_2e_terminal_ledger.py tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py tests/test_bl_pq512_h5_qualification_preflight.py tests/attacks/test_bl_pq512_h5_qualification_preflight_attacks.py tests/test_bl_pq512_h6_qualification_preflight.py tests/attacks/test_bl_pq512_h6_qualification_preflight_attacks.py
45 passed in 164.27s (0:02:44)

Set-Location experiments/bl_pq512_crypto_core; cargo fmt --all -- --check
exit 0
cargo test --offline --locked --features std --bin k512_atomic_semantic_prototype
5 passed; 0 failed
```

The composed state AIR was also accepted by the independent Rust AIR evaluator:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_state_plane_executable_air.py::test_rust_independent_evaluator_accepts_composed_state_air
1 passed in 47.28s
```

The digest-bound review in
`docs/BL_PQ512_HASH_PAD_COMMITMENT_SECURITY_REVIEW.md` rejects the current hash-pad candidate
for Gate 2E: its full 256-bit quantum binding/composition theorem and commit-before-coin lifecycle
are not closed, and no generic SHA3 collision/QROM/Fiat-Shamir/grinding credit is taken. This
replaces the vague `unreviewed` state with a specific negative decision; it does not admit a
backend. `proofSuiteId=None`, activation remains false, H5 remains unlaunched, and the trusted
canonical `../ops` sibling remains an external fail-closed blocker.

Review/screening readback with the explicit synthetic test environment:

```text
review_digest_sha3_512=24cdd3790d6aeab257491a3c089a267ebc21fcb9ce5968617df469442e36fabd10957097ed84421189919f74d27a8abb7c0a4f11c613138e4142fe1717931b63
transparent_screen_reasons=strict_pq_assumption_not_reviewed,native_hiding_theorem_unreviewed,authenticated_public_coin_composition_unreviewed,implementation_not_complete_reviewed_reference,complete_composition_missing,hash_pad_security_review_rejected
```

## 2026-08-02 tracked operational authority migration - VERIFIED, OPS BLOCKER CLOSED

The old two-copy operational layout is retired. The owner's checkout-only source-of-truth rule is
now implemented directly: tracked `ops/` is the sole policy/verifier authority, and the one
policy-hashing call site resolves `ops/policy_spec_v1.yaml`. No policy bytes, verifier pins, or
operational artifacts changed, and no sibling directory or outward copy was created.

`ops_authority.py` independently requires the exact 14 regular files, exact lengths, and exact
SHA3-512 identities. Missing, extra, modified, or symlinked material rejects. The terminal Gate 2E
ledger performs that readback, closes only `CANONICAL_OPS_IDENTITY`, and removes only the ops
blocker. Its remaining blockers are exactly:

```text
complete_leakage_scan_missing
complete_simulator_missing
h4_atomic_binding_deferred
no_backend_admitted
proof_suite_unselected
```

Current identities:

```text
terminal_ledger_digest_sha3_512=ce3bda2eb79b554cc56fc9631b40792068fd953d18fc945ea9a567a5b3caa0f8a57a2c9ab785361f4658903080aa02cce99f7a96c5291507d37af0192bb96d28
h5_preflight_digest_sha3_512=5c6a04878f8268dfd4fb33b3583fd27f0aff8624f90f720a9f6b45fb8dff849538ee7aac6ea3d36d72971d1223bf595c9cec0d35f3230705047518c5741432e1
canonical_ops_status=VERIFIED_TRACKED_SHA3_512_AUTHORITY
```

The H5 campaign remains unlaunched because Gate 2E/state/PQ/simulator/leakage/H4 prerequisites are
still open. `proofSuiteId=None`, activation is false, and no real PHI, payments, or production CUDA
is authorized.

The ruleset commitment preserves the historical v1 artifact label while resolving bytes only from
tracked `ops/`. This prevents a packaging-only path migration from changing retry-stable ruleset
and downstream leaf identities. The containing policy/Gate 2E/H5/H6 suite passed:

```text
py -3.14 -m pytest -q tests/test_security_freeze_spec.py tests/test_batch_layer.py tests/test_bl_pq512_gate_2e_terminal_ledger.py tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py tests/test_bl_pq512_h5_qualification_preflight.py tests/attacks/test_bl_pq512_h5_qualification_preflight_attacks.py tests/test_bl_pq512_h6_qualification_preflight.py tests/attacks/test_bl_pq512_h6_qualification_preflight_attacks.py
55 passed, 20 expected local-dev fallback warnings in 160.55s (0:02:40)
```

## 2026-08-02 Wave 2 continuation security remediation - VERIFIED, NO ADMISSION

A diff-scoped security audit reviewed all 16 source-like files changed from
`1efe11badd8d03e183624528d246279b80662eeb` through
`8b5f58c35127a5e3f7403ccd9fd3b7ebfdda382d`. Three defects were reproduced:
an unrelated but internally valid state proof could be mixed into the terminal receipt evidence,
an alternate NTFS junction could be accepted as an operations authority root, and a non-boolean
persisted-state presence byte could be normalized before CAS. Attack-path policy suppressed all
three from the external reportable set because the demonstrated paths require local
developer/operator-equivalent control and create no current privilege escalation. That policy
classification did not grant correctness credit; all three were remediated.

`StateSnapshot.decode` now accepts only exact `0` or `1` presence bytes and requires the decoded
snapshot to re-encode byte-for-byte. `FileStateStore.publish` therefore rejects corrupted bytes
before root comparison or publication. `verify_ops_authority` now accepts only the exact tracked
`ops/` path and rejects symlink, junction, or Windows reparse redirection on the checkout root,
operations root, and every authority file. The terminal ledger now rejects a supplied state proof
unless its independently replayed profile, parameter identity, capacity, epoch, sequences, roots,
manifest, and exact ordered projection match the independently replayed S4 transition and S5
checkpoints.

Pre-fix reproduction:

```text
5 failed in 17.35s
```

Post-fix focused security closure:

```text
py -3.14 -m pytest -q -p no:cacheprovider tests/test_bl_pq512_state_plane.py::test_state_snapshot_rejects_noncanonical_presence_byte tests/test_bl_pq512_state_plane.py::test_file_store_rejects_noncanonical_persisted_state_before_cas tests/test_bl_pq512_gate_2e_terminal_ledger.py::test_terminal_ledger_rejects_unrelated_state_plane_proof tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py::test_alternate_ops_authority_root_is_rejected tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py::test_ops_authority_junction_root_is_rejected
5 passed in 17.10s
```

Containing state/AIR/Gate-2E/H5/H6/security-freeze verification:

```text
py -3.14 -m pytest -q -p no:cacheprovider tests/test_bl_pq512_state_plane.py tests/attacks/test_bl_pq512_state_plane_attacks.py tests/test_bl_pq512_state_plane_executable_air.py tests/attacks/test_bl_pq512_state_plane_executable_air_attacks.py tests/test_bl_pq512_gate_2e_terminal_ledger.py tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py tests/test_bl_pq512_h5_qualification_preflight.py tests/test_bl_pq512_h6_qualification_preflight.py tests/test_security_freeze_spec.py
36 passed in 150.58s (0:02:30)
```

This closes the three audited software defects only. The supplied state-proof check remains a
host-side fail-closed precondition and receives no H4 proof credit. The full state transition AIR,
reviewed PQ commitment, complete simulator/leakage ledger, proof-native H4 composition, H5 campaign,
and H6 qualification remain open. `proofSuiteId=None`, activation is false, H5 remains unlaunched,
and no production CUDA, real PHI, or real payment is authorized.

## 2026-08-02 Wave 2 continuation native state-AIR prerequisite - VERIFIED, NONACTIVATING

Preflight before mutation was exact: checkout `C:\Users\neers\Documents\Codex\2026-07-27\he\work\Blind-Ledger-Wave2-Workspace-2026-07-26`, branch `main`,
`HEAD=d0f5ec239788a6e9b4151a54a3e69788c6161a6c`, tree
`df04563e08eeb98dd21bb0a8ca706ef64c23d084`, clean worktree. The protected paths and canonical
`ops/` authority were not edited.

The smallest implementable H4 prerequisite now crosses the real producer-to-authority path.
`state_plane_executable_air.py` adds an explicit ordered all-slot operation table and lookups to
the before/after slot tables. `StateTransitionProof.binding_bytes` emits a version-2 `BLSB01`
envelope containing the executable AIR program and execution under `BLSA01`/version 1. Native Rust
`verify_state_binding` independently replays the transition, validates the exact
`BL-PQ512-STATE-ROOT-AIR-v1` program identity, evaluates the complete AIR execution through
`air_ir`, checks the ordered 128-value root public input, recomputes AIR program/execution,
fragment, composition, transition, commitment, verifier, attempt, and receipt identities, and
only then returns the state context to parent construction. The v3 parent, authenticated
interactive session/schedule, exact child proof grammar, and atomic receipt bind the full state
context, including all 12 ordered 32-byte projection fields and the AIR identities. The child is
untrusted and its exact echoes are independently compared by Rust.

Measured/generated KAT identities:

```text
K128-shaped state capacity=128 binding bytes: 103216467
state AIR program commitment: 1f01d105c86846e28b2584303cefa9e0126de100bce1e5461b94a24a5060c4ed9a0e5b9a2875ee4e62dfefe4d1878f2e400110776a311a9fe2bc4781123f9b19
state AIR execution commitment: 828eb5cd80d97bf00c8c5aa1845cbf71e797bfe78fbaa855427ae41421a1e3b2827f3a80df859bab4967536aebe19af67e9fb22e551966c87fb7c4662e4a7baf
state AIR fragment digest: 0a90647bece8d53443b4b52cfa0c534bd921132a039d4025046ffe7e29b7866e6088be49c4a0fbaab5ccdadb5c0c817559974e10020d399bbcdf308bea735d7e
H4 composition digest: 6a974615e750e0e1307902433581eabff6a547d2a4d263eae84816fd63f366b6adb2682dd4bf8abb38d76f03e5b7c2c560ea28ed28d0303ffbc33adfdc5f67a5
state binding digest: 9470549cac80649a0ced45ff17efa0a3441b1052b7476655f1f29d6807155b87d285f99737f8a5fa2a910093592dba930fcc37d02ae24b9c6f86f2ceddb35a49
```

Focused verification:

```text
py -3.14 -m pytest -q -p no:cacheprovider tests/test_bl_pq512_state_plane.py::test_native_state_binding_kat_is_stable_for_the_k128_shape
1 passed in 115.94s (0:01:55)

py -3.14 -m pytest -q -p no:cacheprovider tests/test_bl_pq512_state_plane_native.py
3 passed in 52.61s

py -3.14 -m pytest -q -p no:cacheprovider tests/test_bl_pq512_state_plane_executable_air.py tests/attacks/test_bl_pq512_state_plane_executable_air_attacks.py
6 passed in 92.09s (0:01:32)

cargo +1.96.0 test --offline --locked --features std --bin k512_atomic_semantic_prototype
5 passed; 0 failed
```

Containing state/AIR/Gate-2E/H5/H6/security-freeze verification:

```text
py -3.14 -m pytest -q -p no:cacheprovider tests/test_bl_pq512_state_plane.py tests/attacks/test_bl_pq512_state_plane_attacks.py tests/test_bl_pq512_state_plane_executable_air.py tests/attacks/test_bl_pq512_state_plane_executable_air_attacks.py tests/test_bl_pq512_state_plane_native.py tests/test_bl_pq512_gate_2e_terminal_ledger.py tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py tests/test_bl_pq512_h5_qualification_preflight.py tests/test_bl_pq512_h6_qualification_preflight.py tests/test_security_freeze_spec.py
40 passed in 342.99s (0:05:42)
```

The first capacity-128 attempt was correctly rejected by the initial 64 MiB envelope cap with
`StatePlaneError: state_plane_binding_envelope_too_large`; the cap was raised to an explicit
256 MiB bound, and the 103,216,467-byte KAT then passed. The first `cargo fmt --all -- --check`
also correctly reported mechanical formatting differences; `cargo fmt --all` was run and the
check subsequently passed. These are recorded failures, not skipped gates.

This slice remains nonactivating. No reviewed PQ backend is admitted; the SHA3 hash-pad candidate
remains rejected for the missing full 256-bit quantum binding/composition theorem and
commit-before-coin lifecycle; native AIR evaluation is not a proof-native H4 PCS/ZK composition;
the complete simulator/leakage ledger, H5 repeated campaign, H6 qualification, authoritative
state selection, `proofSuiteId`, activation, production CUDA, real PHI, and real payments remain
closed. H5 was not launched.

## 2026-08-01 Wave 2 round 1 composition geometry and bounded DEEP parallelism - VERIFIED, NONADMITTING

The exact pre-mutation checkout was `C:\Users\neers\Documents\Codex\2026-07-27\he\work\Blind-Ledger-Wave2-Workspace-2026-07-26`, branch `main`,
`HEAD=6ebe9d0db54388140a4fc65e96218414022cba3b`, tree
`cd0791a3833bf99e204798ad43905736632d88ec`, with a clean worktree. The three edited Rust files
were not protected paths; no protected path or tracked `ops/` authority file was changed.

The first compact six-table diagnostic reached the native composition boundary and failed closed.
The raw worker boundary was:

```text
MAIN f58c01c5ccc56397868147ce0f94d0f607537e91e850c27fc4ea7b78092db31d58569dc40ecefb82e043ce161db9958e28660d6b6f9ad383007dd9437ce12f58
INTERACTION_ROOT f2dd9c376169090df4be7468882ef18435120c21f90d286a96b5c26a958a1fef6b64959e5cc46116f4318d2f87be598f00f26515f78b98691722f17bcdbd556b
composition_line=b''
final_returncode=2 stderr=b'ERR:composition_Shape\n'
scratch_removed=True
```

Source and file-boundary inspection identified the cause: a low-degree table participating in
LogUp had inverse/accumulator columns committed on the larger evaluation domain while its
degree-derived composition work domain was smaller; the disk-backed DEEP materializer correctly
rejected that shape. `air_composition.rs` and `oracle_commitment.rs` now raise only lookup-backed
tables to at least their evaluation-domain log size. Tables with no lookup side retain their
smaller degree-derived work domain. `disk_deep.rs` now maps independent column transforms through
a bounded maximum of eight workers, restores the original column order, detects duplicate/missing
results, and converts a worker panic to `WorkerPanic`; the non-parallel path remains sequential.

The compact candidate's resource preflight was a derived model, not a resident-peak measurement:

```text
program_bytes=181198
raw_witness_bytes=95688
evidence_class=DERIVED_MODEL
model_id=GENERIC_AIR_ORACLE_LAYOUT_V1
qualifies=false
activation_allowed=false
modeled_main_evaluation_bytes=170917888
modeled_interaction_evaluation_bytes=50331648
modeled_composition_evaluation_bytes=100663296
modeled_deep_evaluation_bytes=5771362304
modeled_fri_mask_bytes=4194304
modeled_folded_layer_bytes=8388608
modeled_monolithic_live_bytes_lower_bound=6105858048
modeled_maximum_domain_rows=65536
requires_streaming=true
modeled_raw_witness_bytes=95688
modeled_persistent_oracle_bytes=347174152
modeled_peak_temporary_bytes=208404480
modeled_filesystem_overhead_bytes=138894658
modeled_reserve_bytes=4294967296
modeled_required_available_bytes=4989440586
preflight_exit=0
```

The first serial complete compact attempt was stopped by the bounded wrapper timeout after the
composition correction was applied: `Exit code: 124`, `command timed out after 904058 milliseconds`.
The exact validated cleanup boundary was `scratch_file_count_before_cleanup=1399`,
`scratch_bytes_before_cleanup=351368961`, followed by stopping only the validated worker/Python/
launcher process IDs and removing only the exact owned scratch directory.

The first full-Rust test launcher was initially pointed at the checkout root rather than the crate
directory and failed before test execution with:

```text
cargo : error: could not find `Cargo.toml` in
`C:\Users\neers\Documents\Codex\2026-07-27\he\work\Blind-Ledger-Wave2-Workspace-2026-07-26` or any parent directory
```

The launcher was confirmed gone and the exact locked/offline command was rerun from
`experiments/bl_pq512_crypto_core`; no test result was taken from the failed setup command.

With bounded DEEP parallelism, the same compact diagnostic completed and both verification layers
passed. The Python orchestrator replayed the authenticated transcript and the Rust worker ran its
selected FRI verifier:

```text
status=success
program_bytes=201725
proof_bytes=17352533
grammar_version=2
evidence_count=20
query_count=945
fri_layers=15
worker_report=OK grammar_version=2 proof_bytes=17352533 attribution_total=17352533 query_count=945 trace_masks=4789 quotient_masks=946 folds=15 main_ms=18917 interaction_ms=23799 composition_ms=112846 deep_ms=243333 fri_start_ms=94844 fold_compute_ms=2421 openings_ms=19063 verify_ms=5725 worker_wall_ms=537419
scratch_entries_inside_context=0
scratch_context_removed=true
```

This is measured diagnostic evidence for the proof-path implementation, not a production proof or
admitted backend. Its program retained `state_slots`, `state_operations`,
`state_snapshot_encoding`, `state_roots`, `sha3_message_batch`, and `sha3_digest_batch`, with
three lookup relations. It intentionally did not retain the high-cardinality
`state_slots_to_snapshot_encoding` relation, full SHA3 round tables, or the proof-native H4 state
transition/equality composition. Therefore it does not prove the complete state/hash relation,
does not close Gate 2E, and its `worker_wall_ms=537419` is a measured failure against the frozen
K512 complete-proof p95 target below 180 seconds. It is not H5 credit, and H5 was not launched.

Containing verification for this slice was:

```text
cargo +1.96.0 fmt --all -- --check
exit 0
cargo +1.96.0 test --offline --locked --features parallel disk_deep::tests::deep_column_map_restores_canonical_order
1 passed; 0 failed; 0 ignored; 0 measured; 264 filtered out
py -3.14 -m pytest -q -p no:cacheprovider tests/test_bl_pq512_selected_prover_integration.py
2 passed in 139.66s (0:02:19)
```

The complete Rust crate gate then passed, including the new unit test, all library
tests, remaining binary groups, and doc-tests:

```text
cargo +1.96.0 test --offline --locked --features parallel
test result: ok. 265 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1137.57s
all remaining binary groups and doc-tests: test result: ok; 0 failed
```

The containing state/AIR/Gate-2E/H5/H6/security-freeze suite also passed after the documentation
update:

```text
py -3.14 -m pytest -q -p no:cacheprovider tests/test_bl_pq512_state_plane.py tests/attacks/test_bl_pq512_state_plane_attacks.py tests/test_bl_pq512_state_plane_executable_air.py tests/attacks/test_bl_pq512_state_plane_executable_air_attacks.py tests/test_bl_pq512_state_plane_native.py tests/test_bl_pq512_gate_2e_terminal_ledger.py tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py tests/test_bl_pq512_h5_qualification_preflight.py tests/test_bl_pq512_h6_qualification_preflight.py tests/test_security_freeze_spec.py
40 passed in 325.19s (0:05:25)
```

No reviewed PQ backend was admitted, `proofSuiteId` remains null, activation remains false, and
the complete simulator, leakage ledger, proof-native H4 composition, H5 campaign, and H6
qualification remain open. No production CUDA, real PHI, or real payments are authorized.

Post-commit readback for this verified phase: implementation commit
`274d956e40ffe61c385c188a5f9dc301cb6a3e60`, tree
`68c522422f0f63007c4c5b8df79fcebd426f27f6`, branch `main`, with no status entries immediately
after the commit. The documentation-only seal that records this readback is the next commit;
the proof, geometry, and DEEP implementation are unchanged by that seal.

## 2026-08-02 Wave 3 P01-P03 nullifier-authority candidate - IMPLEMENTED, NONACTIVATING

The first concrete Wave 3 run began without promoting synthetic reference helpers or changing
the Gate 2E/H5/H6 dependency chain. `experiments/bl_pq512_crypto_foundation/wave3_nullifier_authority.py`
is a new nonactivating candidate boundary. It accepts only the A12 attempt-v1 (`BLPQNF01`,
domain 257) and cover-v2 (`BLPQNF02`, domain 514) canonical preimages. It independently computes
the legacy Poseidon felt from the raw preimage chunks and the authoritative full SHA3-512 key
from the same raw bytes; caller-supplied wide digests are rejected by exact re-derivation.

P01 is represented by a depth-64 sparse ordered tree with explicit canonical SHA3-512 frames for
leaf, empty subtree, node, and root items. Every frame binds item type, record type, physical
position, child height, and the root's entry count/next append index. Empty subtrees are
position-bound and no 2**64 logical array is materialized. P03 uses the existing append-indexed
ordered-tree invariant: an authenticated predecessor update and fresh append slot produce a
two-path witness that independently recomputes both old and new 512-bit roots. A corner case where
the new append slot shares a subtree with the current successor is covered by the verifier's
authenticated insertion path; the verifier does not assume the whole branch is empty.

The in-memory authority stages cloned wide and legacy trees and swaps both roots together after
the transition verifier passes. It is not durable anti-rollback custody, a production verifier,
proof-native H4 composition, a Gate 2E admission, or an activation path. P04-P12 remain open;
the repository remains at 6/93 complete, `proofSuiteId=null`, activation=false, and no real PHI or
payments are authorized.

Trust-critical verification for this phase:

```text
py -3.14 -m pytest -q -p no:cacheprovider tests/test_bl_pq512_wave3_nullifier_authority.py
6 passed in 0.22s
py -3.14 -m pytest -q -p no:cacheprovider tests/test_bl_pq512_wave3_nullifier_authority.py tests/test_pq_strong_nullifier_reference.py tests/test_a12_nullifier_derivation.py tests/attacks/test_pq_state_reference_attacks.py
34 passed, 10 subtests passed in 0.50s
py -3.14 -m py_compile experiments/bl_pq512_crypto_foundation/wave3_nullifier_authority.py tests/test_bl_pq512_wave3_nullifier_authority.py
exit 0
git diff --check
exit 0
40-record transition stress: status=success, stress_records=40, stress_sequence=40, stress_root_bytes=64
```

The environment has no `ruff` module (`No module named ruff`); no lint result is claimed. No
production verifier command was run, no proof artifact was generated, no package was marked
complete, and no activation input changed. The first containing run passed 113 tests and 16
subtests but found one existing documentation-contract mismatch in
`test_current_stack_and_roadmap_form_a_context_free_execution_contract`: the committed state plan
was missing the exact required phrase `Bind the selected state plane into` followed by
`the actual H4 parent`. The smallest fix added that explicit admission-boundary sentence; the
affected `tests/test_foundation_spec.py` rerun passed `12 passed in 0.20s`.

After the final A12 body-validation hardening, the containing command and raw result were:

```text
py -3.14 -m pytest -q -p no:cacheprovider tests/test_bl_pq512_wave3_nullifier_authority.py tests/test_bl_pq512_state_plane.py tests/attacks/test_bl_pq512_state_plane_attacks.py tests/test_bl_pq512_state_plane_executable_air.py tests/attacks/test_bl_pq512_state_plane_executable_air_attacks.py tests/test_bl_pq512_state_plane_native.py tests/test_bl_pq512_gate_2e_terminal_ledger.py tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py tests/test_bl_pq512_h5_qualification_preflight.py tests/test_bl_pq512_h6_qualification_preflight.py tests/test_security_freeze_spec.py tests/test_foundation_spec.py
58 passed in 302.45s (0:05:02)
```

No production verifier command was run, no proof artifact was generated, no package was marked
complete, and no activation input changed. Durable custody and verifier work remain downstream of
Gate 2E/H6.

## 2026-08-02 Wave 3 Git/archive/hygiene seal - VERIFIED, NONACTIVATING

The candidate and its documentation were committed on `main` as
`261e5bbe0740ce6c655dbe3dab8af85f7277cf81`, tree
`b81fb8f8ad35ccf41b4b68248f9b7defadaff64b`. The source checkout was clean immediately after that
commit. No remote push was performed.

The deterministic archive was built from that exact commit in a separate staging directory. The
privacy gate selected 767 of 784 tracked files and excluded 17 without weakening the gate:

```text
tracked_paths=784
privacy_safe_paths=767
privacy_excluded_paths=17
exclude_reason_count=2 reason=release JSON failed the structural privacy gate
exclude_reason_count=5 reason=release payload contains an opaque non-text file
exclude_reason_count=10 reason=release payload failed the structural privacy gate
```

Excluded paths were `STATE.md`, `WAVE2_HANDOFF_2026-07-26.md`, `app/operational_readiness.py`,
`docs/security-freeze/BL-PQ512-v1/hardening.json`, `sample_claim_input.json`,
`schemas/bl_pq512_witness_v0.schema.json`, `tests/attacks/test_proving_evidence_policy_attacks.py`,
`tests/test_build_release_archive.py`, `tests/test_measure_proving.py`,
`tests/test_privacy_artifact_scan.py`, `tools/measure_proving.py`, `tools/privacy_artifact_scan.py`,
and the five `portal_shared/fonts/*.woff2` files. The exclusions are recorded because those files
contain deliberate privacy-test fixtures, historical host paths, sensitive JSON fields, or opaque
font bytes; they were not edited to make packaging pass.

The first file-path invocation of the builder failed before archive validation with
`ModuleNotFoundError: No module named 'tools'` and created no ZIP. Running the same builder as the
repository module corrected only the import surface and then passed deterministic capture and
readback:

```text
py -3.14 -m tools.build_release_archive --source-root <separate-stage> --manifest <stage>/APP_RELEASE_FILE_MANIFEST.json --output <outputs>/blind-ledger-wave3-p01-p03-candidate-2026-08-02.zip
{"archive_bytes":10745658,"archive_sha256":"7e39b2d453c1c14fc3e72a1e8cecc3f79c6bdc1d223fcbc1f3b032e29f095592","builder_version":"blind-ledger-release-archive-v1","entry_count":768,"manifest_sha256":"ffffd7c1d7e665b7a9f050a72143f7467f67df5b0d4cc0eefcddd85796ea9a03","payload_bytes":10438366,"payload_file_count":767,"receipt_version":1}
```

The resulting ZIP is outside the source checkout at
`C:\Users\neers\Documents\Codex\2026-08-01\files-mentioned-by-the-user-continue\outputs\blind-ledger-wave3-p01-p03-candidate-2026-08-02.zip`.
Independent readback reported `zip_entry_count=768`, `zip_crc_result=None`, first entry
`Blind-Ledger-Release/RELEASE_FILE_MANIFEST.json`, last entry
`Blind-Ledger-Release/zk-cairo-sharp/src/lib.cairo`, and manifest SHA-256
`ffffd7c1d7e665b7a9f050a72143f7467f67df5b0d4cc0eefcddd85796ea9a03`.
`tests/test_build_release_archive.py` passed `18 passed, 54 subtests passed in 0.99s`.

Generated bloat cleanup was bounded to exact generated paths. The first purge removed 16 targets
and `11,338,995,599` bytes, including the 9.25 GB Rust target, 1.47 GB runtime/proof cache, and
615 MB secondary Cargo target. The final purge removed the separate archive staging directory and
two regenerated Python-cache targets: 3 targets and `10,681,750` bytes. Both purges left zero
remaining selected targets and zero `.pyc` files. The tracked `_handoff_support` source file was
retained. Git remains nonactivating: `proofSuiteId=null`, activation=false, 6/93 complete, and no
real PHI or payments.

## 2026-08-02 Gate 2E state-root bus and reviewed PQ candidate - VERIFIED, NONADMITTING

This continuation started from the sealed Wave 3 parent `c4ef6e9` in the authoritative checkout
`C:\Users\neers\Documents\Codex\2026-07-27\he\work\Blind-Ledger-Wave2-Workspace-2026-07-26`.
The protected paths were not edited. No PHI, payment credential, production CUDA, proof artifact,
activation input, or `proofSuiteId` value was introduced.

The smallest real state composition seam is now versioned and authenticated at the H4 hash-bus
source boundary. `BLHBSN02`/version 2 snapshots and `BLHBB102`/version 2 B16 boundaries clone the
accepted base descriptor and append exactly two state-root SHA3 calls. The root message is exactly:

```text
STATE_ROOT_DOMAIN || len(snapshot.encoded).to_bytes(4,"big") || snapshot.encoded
```

The fixed state-root capacity is `claim_slots*137+512`: K128 is 18,048 and K512 is 70,656. The
two calls therefore add 266 and 1,040 live permutations, producing exact state-composed live
permutation totals of 113,996 and 412,446. The state-free `BLHBSN01`/`BLHBB101` descriptor and
bytes remain byte-compatible. The Rust coordinator independently checks the exact packed input and
output bit patterns of both appended root calls before child spawn; the worker derives the totals
from the descriptor rather than a duplicated profile constant.

Cross-language descriptor KATs are:

```text
K128 descriptor_commitment=d5aa3a35136e28134f63a120f7f73c1ed3fc35e482efa618c6ba054aef5838e0552aa907ca69ebc2ef1af2b9b499bda48539f51ee04e3c43e10cfc5221e03c89
K512 descriptor_commitment=31e17d270d51334ec5e2dbaab0fd7433c8a406785de7f5f23210f53cf965694b95d51c661654fb3c04788c43b2abd3df82259d069be10ada046f8bbce7c84480
```

The manual Python-to-Rust state-boundary readback used only synthetic zero data and was removed
after verification. Its raw identities and converter output were:

```text
snapshot_bytes=3596853
snapshot_sha3_512=3c372bb345a54583f5fd008789cdbf1f97789f3d7a22737889af279a87d3d5a01eae119bc4cbba1040d2ace5a189b79861e5a266604003ae001fc90e066918a8
profile=K128Calibration
semantic_program_commitment=0707070707070707070707070707070707070707070707070707070707070707
descriptor_commitment=d5aa3a35136e28134f63a120f7f73c1ed3fc35e482efa618c6ba054aef5838e0552aa907ca69ebc2ef1af2b9b499bda48539f51ee04e3c43e10cfc5221e03c89
semantic_port_commitment=20c15042ded22d0e402e67f0479bf13cda1dbfc3efb5899ef00bd2720ca58ab34f03a5ec0f2991b834aafa4306351c9aa668393ee591b986fd2409869a045153
coprocessor_shards=1
groups=8192
live_wires_per_boundary=1600
output_bytes=52429015
output_decimal_mb=52.429015
output_sha3_512=ba41dbc5787f4b55f9ba6323a0226c86739b54319c99b4aaa84345471d8acc5afc15acb9f4793c92e0fdae37c826b68e9353fd796beb671c8ddc403562364ceb
inspect_padded_permutations=131072
inspect_decoded_patterns=26214400
inspect_file_bytes=52429015
inspect_boundary_verified=true
```

The B16 worker correction was exact and regression-tested: the initial derived state totals
`114232/413370` were wrong and were corrected to `113996/412446`; a critical indentation defect
that nested `shard_start`/`shard_permutations` under the non-little-endian branch was also fixed.
The durable worker test covers the state header, wire-major packed geometry, and the Windows
little-endian path.

The new clean-room candidate is `TRANSPARENT_SHAKE256_1024` with parameter identity
`BL-PQ512-TRANSPARENT-SHAKE256-1024-V1`. It commits before the later authenticated public coin
using SHAKE256-1024, a 128-byte mask, and a 128-byte commitment. Its explicit conservative ledger
is:

```text
output_bits=1024
quantum_collision_bits=341
quantum_preimage_bits=512
multi_target_loss_bits=32
effective_binding_bits=309
effective_hiding_bits=480
required_security_bits=256
review_decision=REVIEWED_CANDIDATE_H4_COMPOSITION_OPEN
```

The S3 registry now exercises five candidates. The three lattice descriptors remain unpinned;
the old `TRANSPARENT_HASH_CODE` remains rejected for its public-coin lifecycle, generic 512-bit
quantum-collision floor, and missing composition; the new candidate is rejected solely for
`complete_composition_missing`. No candidate is admitted or selected.

Two test-only fixture defects were reproduced and corrected rather than hidden. The first native
state-bus fixture wrote group-major payload bytes and failed with:

```text
state_hash_bus_mismatch:0:input:113730:3
```

It was corrected to the authenticated file wire-major layout. The next mutation assertion used a
group-sized offset instead of the wire-major `header + group*2` offset; that test-only offset was
corrected, and the final mutation-bound native test passed.

Final verification for this slice:

```text
py -3.14 -m pytest -q -p no:cacheprovider tests/test_bl_pq512_pq_commitment_screening.py tests/attacks/test_bl_pq512_pq_commitment_screening_attacks.py tests/test_bl_pq512_atomic_state_composition.py tests/attacks/test_bl_pq512_atomic_state_composition_attacks.py tests/test_bl_pq512_state_migration_recovery.py tests/attacks/test_bl_pq512_state_migration_recovery_attacks.py tests/test_bl_pq512_gate_2e_selection.py tests/attacks/test_bl_pq512_gate_2e_selection_attacks.py tests/test_bl_pq512_gate_2e_terminal_ledger.py tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py tests/test_bl_pq512_h5_qualification_preflight.py tests/attacks/test_bl_pq512_h5_qualification_preflight_attacks.py tests/test_bl_pq512_h6_qualification_preflight.py tests/attacks/test_bl_pq512_h6_qualification_preflight_attacks.py
52 passed in 157.35s (0:02:37)

py -3.14 -m pytest -q -p no:cacheprovider tests/test_bl_pq512_transparent_hash_code_candidate.py tests/test_bl_pq512_hash_bus_worker_boundary.py
4 passed in 0.40s

py -3.14 -m pytest -q -p no:cacheprovider tests/test_foundation_spec.py tests/test_deployment_ready_roadmap_contract.py
15 passed in 0.23s

py -3.14 -m pytest -q -p no:cacheprovider tests/test_security_freeze_spec.py
6 passed in 0.09s

py -3.14 -m pytest -q -p no:cacheprovider tests/test_fixed_shape_foundation_spec.py
14 passed in 0.09s

cargo +1.96.0 fmt --all -- --check
exit 0

cargo +1.96.0 check --offline --locked --features parallel
Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.17s

git diff --check
exit 0
```

Generated-output cleanup was bounded to eight exact paths and removed `9,322,207,536` bytes:
`C:\blpq-target` (12,630 files, 4,941,808,695 bytes),
`C:\tmp\blpq-target-wave2` (2,812 files, 2,031,237,199 bytes), the synthetic state-boundary
temporary directory (2 files, 56,025,868 bytes), the crate-local Cargo target (4,278 files,
2,290,296,387 bytes), and four Python `__pycache__` directories (90 files, 2,839,387 bytes).
All eight exact paths were verified missing after removal. No tracked source, policy, release, or
protected path was deleted.

The first Rust invocation from the repository root failed before doing work because that directory
has no `Cargo.toml`:

```text
error: could not find `Cargo.toml` in `C:\Users\neers\Documents\Codex\2026-07-27\he\work\Blind-Ledger-Wave2-Workspace-2026-07-26` or any parent directory
```

The exact same commands passed from `experiments/bl_pq512_crypto_core`, the owning crate. This was
an invocation-directory correction, not a source or gate failure. Earlier native/Rust readbacks
also remain green: the hash-bus snapshot tests were `2 passed; 0 failed; 264 filtered out; finished
in 34.25s`, the full coordinator binary was `6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered
out; finished in 106.66s`, and the Rust library hash-bus suite was `9 passed; 0 failed; 257 filtered
out; finished in 70.95s`.

The current CUDA prototype and worker source changed after the accepted state-free manifest
`51c23310274ccf7c4d7f9abe4ae7eba43266b335bd377b21cbf92409729b91e2a40a39787a157baa080c9d0516c7815af404a4d58d9e76747f652f57cd017ed6`.
The required current release native executables/cubins are not present in this checkout, so the
manifest could not be recomputed and no CUDA proof was launched. The manifest and 29.974129/120.460733
second H4 results remain state-free historical prototype evidence only.

This phase therefore closes a real authenticated state-root bus prerequisite and a reviewed
reference candidate, but it does not close Gate 2E. The full state relation is still not inside
the custom H4 GKR/PCS proof; the complete semantic/state/GKR/PCS simulator, leakage scan, strict-PQ
composition ledger, candidate admission, H5's exact one-warm-up-plus-ten-per-profile campaign
(22 fresh launches), H6 qualification, and all later Wave 3+ work remain open. `proofSuiteId=null`,
activation=false, no PHI/payments are authorized, and no production CUDA was run.

Post-implementation readback before the documentation-only handoff commit:

```text
commit=6a2a7ec124fca97a4b6dfbeb1125e71e737944e6
tree=30e9bdfc4901f30e8a9636a1c1796f3fac3958d1
git status --short
(empty)

## 2026-08-02 Gate 2E state-bus/candidate archive readback - VERIFIED, NONACTIVATING

The deterministic archive source was the clean implementation commit
`969b03ba579487cc8ab5f708e4d9509dc32a34a0`, tree
`e92e4b8b911cabd8fec6071fa91fb81b61bd3708`. The staged privacy gate selected 770 of 787 tracked
files and excluded 17 without weakening the gate:

```text
tracked_paths=787
privacy_safe_paths=770
privacy_excluded_paths=17
exclude_reason_count=2 reason=release JSON failed the structural privacy gate
exclude_reason_count=5 reason=release path has a forbidden generated or archive suffix
exclude_reason_count=10 reason=release payload failed the structural privacy gate
```

Excluded paths were `app/operational_readiness.py`,
`docs/security-freeze/BL-PQ512-v1/hardening.json`, the five
`portal_shared/fonts/*.woff2` files, `sample_claim_input.json`,
`schemas/bl_pq512_witness_v0.schema.json`,
`tests/attacks/test_proving_evidence_policy_attacks.py`,
`tests/test_build_release_archive.py`, `tests/test_measure_proving.py`,
`tests/test_privacy_artifact_scan.py`, `tools/measure_proving.py`,
`tools/privacy_artifact_scan.py`, `STATE.md`, and `WAVE2_HANDOFF_2026-07-26.md`. These are
recorded exclusions from the unchanged structural/privacy gate, not source edits.

The first staging attempt failed before archive validation because PowerShell text-coerced the
binary tar pipeline:

```text
staged_tracked_files=2
tar.exe: Damaged tar archive (bad header checksum)
```

The failed stage contained 2 files and 25,438 bytes and was removed exactly. Re-running with
`git archive --format=tar --output=<tar>` preserved the bytes and staged all 787 tracked files.
The first builder attempt then failed closed on generated manifest order:

```text
release_status=blocked reason=release file entries must be strictly path-sorted
```

The generated manifest was sorted by its exact POSIX `path` field and rebuilt. No output ZIP was
created by either failed attempt.

Final builder receipt:

```text
{"archive_bytes":10813201,"archive_sha256":"d76cb8bc0f42e51a14d048b2ad19f473ae7966d282473dc5aa44f4de36a2f9b4","builder_version":"blind-ledger-release-archive-v1","entry_count":771,"manifest_sha256":"56d28508042aabecb254bae1b7b8ae0425deaf50ddf470e5b0862e1961976aeb","payload_bytes":10500773,"payload_file_count":770,"receipt_version":1}
```

The ZIP is outside the checkout at
`C:\Users\neers\Documents\Codex\2026-08-01\files-mentioned-by-the-user-continue\outputs\blind-ledger-wave2-state-bus-pq-candidate-2026-08-02.zip`.

Independent readback was:

```text
zip_entry_count=771
zip_crc_result=None
first_entry=Blind-Ledger-Release/RELEASE_FILE_MANIFEST.json
last_entry=Blind-Ledger-Release/zk-cairo-sharp/src/lib.cairo
manifest_sha256=56d28508042aabecb254bae1b7b8ae0425deaf50ddf470e5b0862e1961976aeb
manifest_payload_file_count=770
manifest_payload_bytes=10500773
manifest_entries_match=True
archive_bytes=10813201
archive_sha256=d76cb8bc0f42e51a14d048b2ad19f473ae7966d282473dc5aa44f4de36a2f9b4
```

`py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_build_release_archive.py` passed
`18 passed, 54 subtests passed in 1.01s`. The exact generated tar and staging paths were then
removed: 22,411,909 bytes total, with both paths verified missing. The final source checkout was
not changed by archive creation; no remote push was performed. The archive is a nonactivating
source/test/docs artifact only: `proofSuiteId=null`, activation=false, no PHI/payments, and no
production CUDA.
```

## 2026-08-02 Repository-root cleanup and three-archive refresh - VERIFIED, NONACTIVATING

The active source/document/test cleanup was committed before archive creation as
`c84efa7591e43b2a440145db73cbae9ef0624242`, tree
`4ce8e369a7186e74fc9700763aae6b9e5d22706e`. No protected path was edited. The active checkout is
the repository root; tracked `ops/` remains the sole operational authority.

The stale active documentation and path references were corrected in `README.md`, `ARCHITECTURE.md`,
`PROJECT_MAP.md`, `QUICKSTART.md`, `docs/ARCHITECTURE_TECHNICAL.md`,
`docs/BL_PQ512_COMMITTED_SPARSE_STATE_PLAN.md`,
`experiments/bl_pq512_crypto_foundation/README.md`, `ops/DEPLOYMENT_RUNBOOK.md`, and
`ops/PRODUCTION_CONFIG_CHECKLIST.md`. The changes remove nested app-root, sibling-ops, missing-ops,
obsolete four-candidate, stale Forge-vendor, and historical collection-count claims from active
guidance. The active source/test corrections were `app/operator_portal.py`,
`app/policy_spec.py`, `app/production_readiness.py`,
`experiments/bl_pq512_crypto_foundation/gate_2e_selection.py`,
`ops/native_stark_public_inputs_v1.json`, `ops/verifier_artifact_pin.example.json`,
`tests/attacks/test_harder_attack_surface_hunt.py`,
`tests/test_evidence_and_public_inputs.py`, and `tests/test_operational_readiness.py`.
The V1 21-field artifact remains an intentional legacy/compatibility control; only its stale source
path was corrected and its exact SHA256/SHA3-512 identities were resealed.

The active stale-reference scan returned no nested `blind-ledger-app-layer`, sibling `../ops`,
missing-canonical-ops, old four-candidate, or external `third_party/forge` references. Retained
matches are intentional and were not edited: the `AGENTS.md` prohibition, current closed-blocker
notes in `KNOWN_ISSUES.md` and `docs/CURRENT_TECH_STACK.md`, the generic sibling-copy prohibition
in `docs/ARCHITECTURE_TECHNICAL.md`, dated historical evidence in
`docs/PHASE1_EXECUTION_LOG_2026-07-13.md`, protected historical provenance in
`zk-cairo-sharp/SECURITY_ATTACK_NOTES.md`, the legacy-marker rejection in
`app/operational_readiness.py`, its matching rejection fixture in
`tests/test_production_readiness.py`, the SPDX package identifier in
`tests/test_foundation_spec.py`, and the protected batch label in
`app/batch/batch_orchestrator.py`.

No stale test file was removed (`0`). The retained V1, Circle-FRI, Cairo, rejection, and fixture
tests protect current compatibility, migration, differential, or fail-closed boundaries; deleting
them would remove evidence rather than remove dead behavior. The two stale test-root calculations
were corrected. Ordinary collection was `1205 tests collected in 6.40s`; attack collection was
`448 tests collected`. The full attack lane passed `448 passed, 31 warnings, 36 subtests passed in
448.59s (0:07:28)`. The final bounded active-source/readiness/Gate-2E lane passed `142 passed, 7
warnings, 8 subtests passed in 80.91s (0:01:20)`. The ordinary full execution lane was attempted
but timed out with exit `124` after `1078570 ms` without a pytest summary; it receives no pass
credit. The exact pytest process check found `remaining_exact_processes=0` after cleanup.
Warnings were the expected local-dev rules-engine fallback and the existing Starlette/httpx
deprecation warning; no warning was promoted to a pass or silently suppressed.

Bounded generated bloat cleanup removed `19` files and `5,443,857` bytes from exact targets:
`experiments/bl_pq512_crypto_core/cuda/nvrtc-cache` (`1` file, `5,202,967` bytes),
`app/__pycache__` (`3`, `19,844`), `app/batch/__pycache__` (`5`, `137,961`), and
`tests/attacks/__pycache__` (`10`, `83,085`). Earlier parent-work cleanup removed the exact
recorded generated targets totaling `3,657` files and `3,646,692,083` bytes. The live
`experiments/bl_pq512_crypto_core/cuda/cuda_nvrtc` runtime remains (`11` files,
`187,059,841` bytes) because the current CUDA source directly loads `nvrtc64_120_0.dll`; it is
not disposable cache. No `.pyc` or selected temporary proof/witness artifact remains.

The release builder staged the exact source commit and selected `770` of `787` tracked files after
the unchanged structural privacy gate excluded `17` paths. The first builder attempt failed closed
with `source root contains missing, unknown, or unlisted entries` because the excluded files were
still physically present in the staging root; exactly those `17` staging files were removed, no
source file was removed, and the builder then passed. The deterministic archive test passed
`18 passed, 54 subtests passed in 0.85s`. A first post-replacement readback command had a shell
quoting syntax error and wrote nothing; the literal-script readback below passed independently.

All three current output ZIPs now contain the identical bytes from source commit
`c84efa7591e43b2a440145db73cbae9ef0624242`:

```text
blind-ledger-wave2-state-bus-pq-candidate-2026-08-02.zip
blind-ledger-wave3-p01-p03-candidate-2026-08-02.zip
blind-ledger-current-clean-2026-08-02.zip

archive_bytes=10783587
archive_sha256=2b3da27068e1ddba0a78bab10e1a824081d23de93168bd81e1332227985359e9
zip_entry_count=771
zip_crc_result=None
manifest_sha256=f03ef370ef48e36731eeb81651ac349ebebd1f4c906cda836c06be343af9560e
manifest_payload_file_count=770
manifest_payload_bytes=10501210
entries_match=True
all_three_byte_identical=True
```

The ZIPs are outside the source checkout at
`C:\Users\neers\Documents\Codex\2026-08-01\files-mentioned-by-the-user-continue\outputs`.
The old two archives were replaced only after fresh builder and independent readback success. The
exact temporary stage (`771` files, `10,616,535` bytes), tar (`1` file, `11,765,760` bytes), and
superseded-archive backup (`2` files, `21,558,859` bytes) were then removed and each path verified
missing. No remote push was performed.

The repository remains nonactivating: `proofSuiteId=null`, activation=false, six of 93 packages
complete, no H5/H6 qualification, no production CUDA proof, and no real PHI or payments.

Final post-ledger readback passed `33 passed, 54 subtests passed in 1.01s` for operational
readiness, roadmap/security contracts, and the deterministic archive builder. Git status is empty,
`git diff --check` is clean, `verify_ops_authority()` returns
`VERIFIED_TRACKED_SHA3_512_AUTHORITY`, active source/doc stale hits are limited to the four
intentional safeguards/provenance classes recorded above, and all three archive readbacks still
report `match=True` and `all_three_byte_identical=True`.

## 2026-08-02 Round 2 compact state-AIR/FRI composition - VERIFIED, NONACTIVATING

This continuation corrected the actual proof-native state boundary rather than stopping at the
earlier digest-only state-AIR seam. The live checkout remained
`C:\Users\neers\Documents\Codex\2026-07-27\he\work\Blind-Ledger-Wave2-Workspace-2026-07-26`.
Protected paths were not edited. No PHI, payment credential, production CUDA, activation input, or
`proofSuiteId` value was introduced.

The compact relation in
`experiments/fixed_shape_claim_air/state_relation_executable_air.py` packs each 64-byte key/value
into 22 three-byte M31 chunks, retains boolean presence and empty-slot zeroing identities, and
keeps the two 64-byte state roots as the only public AIR values. H4's existing authenticated
state-root SHA3 calls remain the hash relation; the compact FRI component does not duplicate their
Boolean SHA3 traces. The native `air_ir` verifier now exposes validated execution columns, and the
H4 coordinator compares every packed relation/root column with the exact parsed state operations
before it accepts the component.

The streamed worker now exports a private `BLPQSPK1` package containing the verifier-visible AIR
program, public inputs, selected challenge bundle, DEEP claims, final FRI constant, and canonical
v2 proof bytes. `state_air_proof.py` validates the package grammar and commitment, emits the v3
`BLSB01`/`BLSA02` state envelope, and binds the component evidence into the v2-separated fragment,
composition, parent, authenticated transcript, child grammar, and receipt contexts. The public
sidecar remains digest-only; private snapshots, operations, masks, trace, claims, and proof bytes
are not placed in public outputs.

Exact implementation verification:

```text
py -3.14 -m py_compile experiments/bl_pq512_crypto_foundation/state_air_proof.py experiments/fixed_shape_claim_air/state_relation_executable_air.py experiments/bl_pq512_crypto_foundation/selected_prover_orchestrator.py
exit=0

py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_state_relation_executable_air.py
..                                                                       [100%]
2 passed in 0.26s

py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_state_plane_native.py
...                                                                      [100%]
3 passed in 81.65s (0:01:21)

cargo +1.96.0 fmt --all -- --check
exit 0

cargo +1.96.0 check --offline --locked --features parallel --bin selected_streaming_prover_worker --bin k512_atomic_semantic_prototype
Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.80s
```

The first combined Python diagnostic also included the known expensive full state-envelope lane
and timed out after `120000 ms` without a pytest summary; it receives no pass credit. The exact
pytest process cleanup reported `stopped_exact_pytest_processes=1` and
`remaining_pytest_processes=0`. The compact lane above was rerun in isolation and passed.

The real streamed dual-PQ fixture used capacity 8 only; it was not a K128/K512 qualification run:

```text
status STATE_AIR_PROOF_COMPONENT_VERIFIED_NONACTIVATING
program 6f6965838ce9f3a369027dc0b94259c0cb812c38edf3ee05bf2c964be082ee0f60db581d6972819db70b8cc5843d9c924dbbff0e6d1612d3b24ea12983dbcc81
execution d6a95ffd77ae4a6219544b4b84e8d1029b902242bd41ab52906349159d314e1e4c80b4515407ae4b02d4ba33a352fdc7f31bda7ecd61a1671cb0882fd1535208
package 0d8c52e2e47430d565f6660b9fea7a0b229c314305eb1fc797cd2615f5d995f169f9cffe942a866cfcfcc63e7535bfe1047a76b032d0da73128b63f1e2b4e2ac
suite c2cd70b801dcd7665ca7b40cbf4d0599baf2e9eb7143f2260019a0cc2817c4aa9332c91912072f7e57644f25993d5e700633a261b4801a465c6e1920e1c8ae2b
schedule 67445bd618b1d38e6530e76934078866e163f18245f402a14066fa4540524a363ed1cd3290a313244c84164382fbe734b4accc1a09f52b254964d62cfaafec71
transcript 4fc66ae754fdc20a75d019077041fb0fc4d25e1a0c403869e22ddca78fd369a98ead4ce4ad0a788beb348ff1109ccd71941fe95852552cef5cf247c36ba9c4c1
proof_identity 9020f05dfe960a1b9b2a9b359666f376ca77c45131dc8af82226af383fb6721c2b69890429477a2954b6ac6ced0695a4fecb140c1b34037c28772ebf3de3c1b6
proof_bytes 8324389
package_bytes 8370223
evidence_canonical_bytes 771
binding_bytes 8407706
worker_and_python_replay success
scratch_entries_after 0
```

Independent native H4 state-file verification of that exact envelope:

```text
& k512_atomic_semantic_prototype.exe --verify-state-binding blpq-state-air-binding-v3-20260802.bin
state_plane_binding_verified=true
state_plane_statement_sha3_512=f839410300674014ed4204e116c4b4c6b297e0d9603a55629a6b9c2d7cad651f72aecac54d2911693c435fbd5b8009d4b92c374db80446daa785c18490301760
state_plane_binding_digest_sha3_512=b0d1366b13e832d4438b56db703ce8c28174fcab218e6d4032921284b89a5842ed72b8b5b23b78368ad05f7a3ead8a59d78b7e3603b65e5de44fc64c4e768b32
exit=0
```

Adversarial native readback was fail-closed:

```text
trace mutation exit=2
ERR:state_air_trace_after_key_0_0
package mutation exit=2
ERR:state_binding_proof_package:Rejected
mutation_files_remaining=0
```

This closes the native state-file proof component boundary, not Gate 2E. The full state relation
is still not algebraically composed inside the custom H4 GKR/PCS proof; no reviewed commitment
backend is admitted, the complete simulator/leakage/security composition is open, H5's exact 22
launches have not started, H6 is open, `proofSuiteId=null`, activation=false, no production CUDA
proof was run, and no real PHI/payments are authorized.

Final source verification for this continuation, before the archive refresh:

```text
py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_state_relation_executable_air.py tests/test_bl_pq512_state_plane_executable_air.py tests/test_bl_pq512_selected_proof_parameters.py
........                                                                 [100%]
8 passed in 297.47s (0:04:57)

py -3.14 -B -m pytest -q -p no:cacheprovider -k "not native_state_binding_kat" tests/test_bl_pq512_state_plane.py
.......                                                                  [100%]
7 passed, 1 deselected in 0.17s

cargo +1.96.0 fmt --all -- --check
exit=0

cargo +1.96.0 check --offline --locked --features parallel --bin selected_streaming_prover_worker --bin k512_atomic_semantic_prototype
Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.93s

git diff --check
exit=0
```

The full Rust library-test batch was attempted in an external target and timed out after
`604046 ms` without a test summary; it receives no pass credit, and exact process cleanup found
`remaining_target_test_processes=0`. An earlier Python command named the nonexistent
`tests/test_bl_pq512_selected_prover_parameters.py`; it ran `no tests ran in 0.00s` and is not
evidence. The corrected lanes above are the credited results. No stale test file was removed:
`0`; existing tests remain because they cover compatibility, mutation, and fail-closed behavior.

## 2026-08-02 Final compact-state source/archive/hygiene seal - VERIFIED, NONACTIVATING

The implementation, tests, and active documentation were committed on `main` as
`561cacb893e54ca9638228a8cffd1fdf732130d6`, tree
`67b31a69d48690a4644cc9c7733bce0634c829b0`. The staged protected-path check reported
`protected_path_changes=0`; the source checkout was clean after that commit. No remote push was
performed.

The first complete output refresh was rebuilt from that exact implementation commit in a separate
stage. After the documentation-only seal `deb2bf0d21e929c8ceb71b62489ae015d2425673`, the same
stage/allowlist was rebuilt from that sealed tree; the final outputs below produced the identical
receipt. The privacy/allowlist gate selected 774 payload files from 791 tracked files and excluded
the same 17 deliberate privacy/opaque-fixture paths used by the existing release policy. The
builder produced identical receipts for all three:

```text
archive_bytes=10889447
archive_sha256=08b638a02e5dd875201f4362afa5c74713d7c0fff0fd54a27bbbf9da7edb19ca
builder_version=blind-ledger-release-archive-v1
zip_entry_count=775
manifest_sha256=ed55cf0ce27ef25c0a2e419f64f72951676153c482630836e83ccca8165081b4
manifest_payload_file_count=774
manifest_payload_bytes=10575278
```

The final independent readback of each output reported `zip_crc_result=None`,
`manifest_entries_match=True`, `forbidden_entries=0`, and
`all_three_byte_identical=True`. The four new state-component source/test files are present in
each archive; no `.bin`, `.zip`, `.pyc`, `.pyo`, log, target, scratch, or proof directory entry is
present. `tests/test_build_release_archive.py` passed `18 passed, 54 subtests passed in 0.97s`.
The first post-replacement readback wrapper passed the literal `$args` token and therefore failed
before reading a ZIP; it changed no artifact. The corrected readback above is the credited result.

After readback, bounded cleanup removed exactly 14 generated targets containing 4,141 files and
2,362,002,793 bytes: source/external Cargo targets, native proof/test targets, proof binding,
scratch, archive staging/tar, superseded archive backups, and Python cache directories. Final
checks report zero `__pycache__` directories and zero `.pyc`/`.pyo` files. The runtime CUDA
package was retained intentionally: 11 files, 187,059,841 bytes under
`experiments/bl_pq512_crypto_core/cuda/cuda_nvrtc`; it is loaded by the source and is not a
disposable cache.

The repository remains nonactivating: `proofSuiteId=null`, activation=false, six of 93 packages
complete, no H5/H6 qualification, no production CUDA proof, and no real PHI/payments. The full
state relation inside custom H4 GKR/PCS, reviewed backend admission, complete simulator/leakage
composition, and H5's exact 22 launches remain the next real blockers; this seal does not claim
Gate 2E completion.
