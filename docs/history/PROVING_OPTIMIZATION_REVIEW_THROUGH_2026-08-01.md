# Archived proving optimization review through 2026-08-01

Updated: 2026-07-31

This review classifies proposed proving optimizations against the source in this archive. Its
historical sections deliberately excluded hardware and GPU work. The current controlling recovery
plan permits accelerators only after algorithmic waste is removed and scalar/SIMD parity is pinned.
Estimates without measurements are not treated as facts.

The product objective in `docs/DEPLOYMENT_READY_BUILD_CONTRACT.md` is maximum measured throughput
subject to correctness, privacy, strict-PQ security, auditability, and modularity. Proof, verifier,
rollup, deployment, and benchmark engineering are internal; the final independent audit reviews the
completed exact release rather than choosing or implementing optimizations.

`docs/FRONTIER_THROUGHPUT_AND_ETHEREUM_ALIGNMENT.md` governs new state-topology, conflict-scheduling,
outer-proof, and adapter/rollup research. H4 now supplies complete one-run K128/K512 prototype
evidence, but gate 2E state selection, H5/H6 qualification, and downstream implementation remain
open. Structural projections must not be mixed with measured H4 or historical results below.

`docs/BL_PQ512_COMMITTED_SPARSE_STATE_PLAN.md` now makes state replacement a mandatory measured
Wave 2 gate. The current SHA3-512 endpoint-multiproof/sorted-memory construction remains C0; C1-C4
cover persistent sparse memory, a transparent dictionary relation, touched-projection RAM, and a
compact shuffle-based memory relation. Native-hiding PQ commitment candidates are evaluated through
a separate interface. No paper speedup or primitive label is an optimization result.

## Current strict-PQ proof/resource decision (supersedes prospective status below)

The current 2026-07-31 result supersedes the 2026-07-28 projection wherever they conflict. The
manifest-bound real semantic source, 168-layer native-masked GKR, Construction 8.2 random-padded
interleaved-RS PCS, 6,086-round authenticated public coin, atomic one/four-shard coordinator, and
independent Rust verifier pass together. K128/K512 complete in 29.974129/120.460733 seconds;
internal host peaks are 288.412/296.255 MB, external process-tree peaks are
681.607168/706.523136 MB, per-proof tracked device state is 969.999360 MB, and scratch is
0.000000 MB. These are H4 one-run prototype results. Gate 2E must select and bind the state plane
before H5; H5's repeat campaign and H6 remain open.

### Historical 2026-07-28 selection screen

`docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md` is the controlling prospective optimization plan and
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md` is the selected implementation priority. The
older Cairo, RISC Zero, validity-only S-two, and six-column measurements below remain historical
evidence; none describes the current complete relation or proves release throughput.

The 2026-07-28 first-principles screen selects the seven-layer/B=16 Fp16 schedule and rejects
six-layer ternary theta, merged degree-11 theta, B=8, B=32, and B=64. The corrected GKR
measured-component projection is 25.291229 seconds; the earlier 19.428197-second arithmetic screen
omitted exact packed-bridge construction/reduction and must not be used as the GKR budget. With
authenticated coin-head work overlapped with initial PCS work, the closed critical path is
26.859692 seconds and six stages remain open inside 3.140308 seconds. Section 8.2 of the
heterogeneous-coprocessor document is the complete nonactivating decision and bloat review. No
complete-proof projection or qualification is claimed.

The current degree-16/SHA3-512 regression kernel generates and independently verifies a real
dual-PQ-authenticated proof:

| Evidence | Exact result |
| --- | ---: |
| Proof size | 28,643,096 bytes |
| Queries / committed FRI layers | 945 / 15 |
| Fresh worker wall, two runs | 50,070 ms / 47,178 ms |
| Run-2 composition / DEEP | 13,248 ms / 12,219 ms |
| Run-2 opening construction / verification | 224 ms / 940 ms |

The v1 grammar authenticates the left and right member of every adjacent FRI pair with two separate
Merkle paths and serializes openings per query. On the exact query set, v1 carries 226,800 FRI path
digests and 28,350 opened values. A canonical global multiproof for the same query positions and
multiplicities needs 8,118 path digests and 9,982 values. That removes 15,171,200 bytes of existing
payload before new bounded metadata. It is a design measurement, not an implemented v2 result. It
does not change roots, values, queries, folds, hiding, hash, field, transcript, or theorem terms.

Proof size is not the main K128 proving blocker. The complete relation's rejected monolithic lower
bound is 9,034,606,313,472 live bytes. The current disk-streamed model requires
950,757,738,236 bytes of available scratch, including 670,331,346,736 persistent oracle bytes,
86,838,870,016 peak temporary bytes, 189,292,554,188 filesystem headroom, and a
4,294,967,296-byte reserve. The first figure is memory, the second is disk capacity, and neither is
proof size.

The estimator retains two copies of main, interaction, and composition evaluations. Removing that
duplication alone removes 317,198,434,304 persistent bytes and gives a same-formula projection of
554,259,695,356 required scratch. That projection is not yet measured and still does not close the
deployment envelope.

The 554-951 GB direct-SHA3-STARK layouts are retired release architectures. Exact storage of all 25
bit-packed K128 Keccak state boundaries is 568,650,000 bytes. The `w=1,600` raw-state-layer
shared-bus-GKR baseline is 3,591,988,768 bytes and `w=2,048` is 4,407,205,408 bytes. Generated padded
width and all overhead remain unmeasured. Both raw baselines leave bounded but unproven room under
the current limit before overhead. The hard qualification gates are no more than
5,000,000,000 peak RSS and strictly
below 5,000,000,000 scratch with no swap on the reference laptop; these are models, not an
implemented result.

The 2026-07-22 frontier pass adds a subfield-first streamed GKR candidate without lowering the
challenge field. At `w=1,600`, replacing only the two eligible early 64-byte Fp16 accumulator arrays
with four-byte M31 arrays projects a raw subtotal of 862,468,768 bytes. The optimized scalar tower
also replaces generic fixed-nonresidue multiplication, reducing an Fp16 multiply from 192 to 81
M31 multiplications. All 95 Rust library tests and the independent Python field vectors pass;
three-run field mixes improved 1.69x-1.80x. Neither the memory calculation nor field benchmark is a
K128 proof result. Full Fp16 challenges, native masking, cross terms, promoted tails, commitments,
streaming I/O, and the complete simulator remain closure work.

The current execution order is:

1. retain H4's exact manifest, grammar, mutation, resource, and independent-verification evidence;
2. implement and select the committed sparse-state/PQ-commitment candidate against C0 under
   identical fixtures, security, privacy, migration, independent-verifier, and laptop gates;
3. bind the selected state, statement, retry identity, roots, parameters, verifier identity, and
   proof atomically and close the complete simulator/security composition;
4. run H5's one uncounted warm-up plus ten unique K128 and K512 batches and require p95 below
   30/180 seconds with all resource gates inside the measured boundary; and
5. close H6 suite qualification without changing `proofSuiteId=null` or activation until every
   downstream identity gate permits the lifecycle transition.

Query count, degree-16 security, SHA3-512, authenticated interactive public coin, fixed-shape work,
and native hiding are not optimization knobs unless a complete stronger theorem and error ledger
replace the current construction. GPU or external proving is not a substitute for algorithmic
resource recovery.

## 2026-07-26 preliminary mechanism-first frontier screen

This preliminary screen reviewed recent proof-system work by the resource or theorem mechanism it changes,
rather than by reported benchmark rank. Published end-to-end numbers are not Blind Ledger
projections. A candidate is useful only to the extent that its mechanism can preserve the sealed
statement, authoritative SHA3-512, the M31/Fp16 field profile, authenticated interactive public
coin, native privacy, the 256-bit security/encryption ledger, atomic independent verification, and the
strict
reference-Dell envelope.

The inventory below contains 32 uniquely linked ePrint papers plus six additional named rejects.
That is a breadth screen, not 38 complete technical reviews. Several sources or mechanisms were
already present in the earlier research pass; no durable before/after source ledger exists from
which to claim an exact new-paper count. Most candidates were assessed from abstracts and selected
technical sections, while only a smaller subset received deeper theorem or implementation reading.
The citation graphs, full proofs, revision histories, reference implementations, parameter scripts,
and composition counterexamples have not yet been exhaustively traced. This section therefore
defines high-value research and prototype hypotheses, not frontier saturation or an architecture
selection.

The most important consequence of the new envelope is structural. A resident 2-GiB PCS codeword
alone leaves about 2.85 GB below the 5,000,000,000-byte process ceiling for Rust,
transcript state, Merkle authentication, GKR state, masks, GPU staging, allocator fragmentation,
and the verifier. Faster arithmetic on the same full-resident layout cannot qualify. The release
design must stream or recompute code tiles, keep one owner for each live buffer, and retain only
compact messages and authenticated query frontiers. An internal engineering target of at most
2.4 GB for all managed prover buffers reserves 600 MB for runtime and unplanned overhead, but this
is a design budget, not a relaxation or substitute for the measured 5,000,000,000-byte gate.

### Admitted combined architecture lanes

1. **Keccak-specialized tower-streamed GKR.** Preserve FIPS 202 SHA3-512 and the committed hash bus,
   but replace the generic 216-layer execution representation with a Keccacheck-derived algebraic
   schedule: the `+/-1` Boolean basis makes XOR multiplicative, while rotations use closed-form or
   interpolated wiring polynomials. Combine that circuit specialization with M31-to-Fp16
   tower-field sumcheck, fixed tower-basis early rounds, small-value/many-factor sumcheck, and
   decomposition of the equality tensor. Full unpredictable Fp16 challenges remain mandatory at
   every round where the current soundness ledger requires them; fixed-basis rounds receive no
   independent challenge-entropy credit.
2. **Persistent, single-owner heterogeneous execution.** Keep the active GKR polynomial or bounded
   tile on the GPU, send only compact round messages to authoritative Rust, and use a bounded CPU
   tail where it is cheaper than a launch. Chimera supplies the persistent-state and chunking
   pattern; TensorZKP supplies an exact-matrix-multiplication formulation worth testing on tensor
   cores. Neither permits floating-point approximation, duplicate host/device ownership, a
   GPU-authored transcript, or a verifier shortcut. Every accelerated boundary needs exact
   M31/Fp16 known-answer parity.
3. **Streamed jagged code PCS.** Commit differently sized GKR layers, semantic columns, masks, and
   auxiliaries without padding each one to the largest domain. Evaluate Jagged PCS against the
   current transparent WHIR/BaseFold-style control, then encode bounded tiles with the current code
   or an ERA/Block-Accumulate candidate. Build one SHA3-512 Merkle frontier while the tile is live,
   discard it after its authenticated contribution is fixed, and retain only the query frontier.
   Every alternative code must pass an exact Fp16, unique-decoding, 256-bit query/error ledger;
   list-decoding or correlated-agreement headline parameters receive no credit.
4. **Native-ZK composition around the combined plane.** Keccacheck's base protocol is not
   zero-knowledge and its compact wrapper uses Groth16, so only its Keccak algebra is admissible.
   VEIL, constrained-interleaved-code ZK IOPPs, and black-box ZK composition are separate candidates
   for hiding the tower-GKR and streamed PCS. The winning construction must simulate a malicious
   verifier, authenticated public-coin retries and aborts, terminal evaluations, retained
   frontiers, and atomic composition with the semantic AIR. Libra-style committed masking remains
   the control until that exact simulator passes.
5. **Repeated-opening accumulation only after the base path fits.** FICS/FACS, SwitchFold, and
   code-switching can reduce repeated opening work or proof bytes, but add generator-MLE claims,
   composition state, and a larger simulator surface. They are admitted only as a measured
   base-PCS optimization or post-K128 aggregation lane, never as a substitute for one complete
   K128 proof under the native ledger.

These lanes are complementary, not independent paper swaps. Circuit specialization reduces the
amount of GKR work. Tower/small-value sumcheck reduces the cost and live width of the remaining
work. Persistent bounded execution removes transfers and duplicate ownership. Jagged streaming
removes padding and the resident codeword. Native-ZK composition then closes the privacy boundary
over that exact combined transcript. Selecting only the fastest item from any one row would leave a
different bottleneck or violate a hard requirement.

### Primary-source disposition

| Source | Mechanism retained for Blind Ledger | Boundary or rejection |
| --- | --- | --- |
| [2025/594](https://eprint.iacr.org/2025/594), efficient sumcheck over tower fields | A direct structural fit to an M31 base with a degree-16 extension, subject to deriving and testing the exact tower. Fixed-basis early rounds can avoid unnecessary top-field work. | Not a complete native-ZK or composition proof. The exact Fp16 tower, basis, round schedule, and soundness union bound must be rederived. |
| [2025/1117](https://eprint.iacr.org/2025/1117) and [2026/587](https://eprint.iacr.org/2026/587), faster sumcheck | Small-value tables, equality-tensor decomposition, many-factor products, and small-space streaming. | Reported Spartan/Jolt/Shout speedups are not K128/K512 forecasts. |
| [2026/762](https://eprint.iacr.org/2026/762), monomial/projective sumcheck | A subtraction-free basis and projective evaluation may reduce arithmetic. | Any restricted challenge-set optimization is rejected where the Fp16 soundness floor requires a full random challenge. |
| [2026/1388](https://eprint.iacr.org/2026/1388), Chimera | Persistent GPU polynomial state, memory-aware chunks, compact host messages, and a CPU tail. | Its Spartan pipeline and measurements are not this proof, field, privacy layer, or laptop. |
| [2025/717](https://eprint.iacr.org/2025/717), Boolean GKR with sublinear RAM operations | Packed-bit univariate representations and Boolean precomputation are prototype-worthy. | Its PCS is binary-field oriented; the paper removed an earlier end-to-end Binius/Keccak comparison because the circuit size was wrong. No such number is imported. |
| [2025/1764](https://eprint.iacr.org/2025/1764), Keccacheck | Keccak-specific layering, the `+/-1` basis, rotation wiring, and instance batching. | The base protocol is not ZK; the compact construction relies on Groth16 and other incompatible wrapper choices. Only the core algebra is admitted. |
| [2026/1250](https://eprint.iacr.org/2026/1250), TensorZKP | Express exact finite-field sumcheck/code work as matrix multiplication with asynchronous staging. | No approximate floating-point arithmetic and no transfer of transcript authority to the GPU. Published field/hardware results do not transfer. |
| [2025/2301](https://eprint.iacr.org/2025/2301), SIMD Spielman encoding | Cache layout, slicing, lazy reduction, and vectorized code kernels. | Server AVX-512 measurements do not qualify the Dell path. |
| [2024/1970](https://eprint.iacr.org/2024/1970), Scribe; [2024/1631](https://eprint.iacr.org/2024/1631), Sparrow; [2025/611](https://eprint.iacr.org/2025/611), small-space CPU proving | Read-write streaming, sublinear-space sumcheck, recomputation, and pass planning. | Their HyperPlonk/Jolt/curve-backed complete constructions are not adopted. The streaming mechanisms need a hash-based Fp16 implementation. |
| [2025/917](https://eprint.iacr.org/2025/917), Jagged PCS | One commitment for columns of unequal height can remove padding and duplicate oracle commitments. | The paper does not provide Blind Ledger's native hiding. Its additional per-element algebra wins only if measured total trace-area and root savings exceed it. |
| [2026/864](https://eprint.iacr.org/2026/864), ERA codes; [2025/1828](https://eprint.iacr.org/2025/1828), Block-Accumulate codes | Provable linear-time code families with attractive CPU/GPU encoding and memory claims. | Admit only a proved-distance, unique-decoding Fp16 parameterization at the exact 256-bit security ledger. Aggressive or conjectural settings are forbidden. |
| [2026/310](https://eprint.iacr.org/2026/310), Bolt; [2026/258](https://eprint.iacr.org/2026/258), Lightning; [2026/939](https://eprint.iacr.org/2026/939), quasi-Abelian codes | Code-construction ideas and a wider PCS bake-off. | Current reported fields, distance/speed trades, or hardware do not directly match the required Fp16/256-bit profile. No headline result is credited. |
| [2025/2065](https://eprint.iacr.org/2025/2065), TensorSwitch; [2025/870](https://eprint.iacr.org/2025/870), proximity gaps | Code switching and correlated-agreement analysis clarify potential and risk. | List-decoding/correlated-agreement gains are excluded until an exact theorem closes the 256-bit security ledger; unique decoding remains the release control. |
| [2025/737](https://eprint.iacr.org/2025/737), FICS/FACS; [2025/1588](https://eprint.iacr.org/2025/1588), query-optimal IOPPs; [2026/1489](https://eprint.iacr.org/2026/1489), SwitchFold | Repeated-opening accumulation, lossy batching, and code-agnostic switching may reduce later PCS work. | Interactive-core mapping, native hiding, complete knowledge soundness, generator-MLE overhead, and actual peak memory remain open. |
| [2026/683](https://eprint.iacr.org/2026/683), VEIL; [2026/391](https://eprint.iacr.org/2026/391), ZK IOPPs for constrained interleaved codes; [2026/307](https://eprint.iacr.org/2026/307), ZK IOP composition | Nonintrusive multilinear hiding, round-by-round knowledge soundness, ZK code-switch/sumcheck relations, and composable straight-line simulation. | Each must be instantiated over the exact interactive Fp16/SHA3-512 transcript and malicious-verifier model. Paper proof size and overhead are not qualification evidence. |
| [2025/247](https://eprint.iacr.org/2025/247), LatticeFold+; [2026/242](https://eprint.iacr.org/2026/242), Neo/SuperNeo; [2026/1317](https://eprint.iacr.org/2026/1317), ProtogaLattice; [2025/1903](https://eprint.iacr.org/2025/1903), Serval | Future post-quantum folding/aggregation and lattice-PCS research. | Published 128-bit or random-oracle profiles do not satisfy the 256-bit security/encryption floor. These cannot rescue the base K128 path and remain post-K128 unless separately requalified. |
| [2025/358](https://eprint.iacr.org/2025/358), memory-checking lower bound | Prevents a false search for constant-query authenticated RAM without changing the model; focus remains touched work, batching, topology, and proof composition. | No weakening of authoritative SHA3 state, fixed capacity, or access privacy follows from the lower bound. |
| [2025/946](https://eprint.iacr.org/2025/946), LogUp* | Small static tables and avoiding unnecessary numerator arrays may help byte/range subrelations. | It cannot replace the dynamic replay/payment memory argument. |

Explicit rejects from the same sweep include KZG/pairing/SRS constructions such as Mercury and
Samaritan; FHE-oriented “blind PCS” whose privacy and custody layer is not native witness hiding;
distributed server systems such as Veloz and UltraFold that do not solve the reference-laptop
envelope; and LiLAC, whose ePrint entry is withdrawn. A paper's post-quantum label, transparent
commitment, or small proof is insufficient when its transcript, decoding theorem, privacy compiler,
license, verifier, or resource model conflicts with the release contract.

### Required prototype sequence and decision gates

1. Derive a Keccak-specific layer manifest from the sealed FIPS 202 call schedule and prove
   bit-for-bit equality against the current 216-layer control. Record exact gates, layers, rotations,
   bulk bytes, and terminal claims before measuring performance.
2. Derive the exact M31-to-Fp16 tower used by the release candidate. Implement the tower-field and
   small-value sumcheck as a parallel control, retaining full-Fp16 authenticated challenges wherever
   required. Recompute the complete degree, challenge-entropy, abort/retry, and union-bound ledger.
3. Implement a single-owner persistent worker with an explicit lifetime map. Measure host RSS,
   device allocation, pinned staging, transfers, scratch, swap, stalls, and cleanup at every stage.
   No host codeword or GKR layer may survive merely for convenience.
4. Run a common-fixture PCS bake-off: current WHIR/BaseFold-style code, jagged commitment layout,
   and only those ERA/Block-Accumulate variants that first pass exact Fp16 unique-decoding and
   256-bit security screens. Measure encoding, roots, openings, proof bytes, verification, RSS,
   scratch, and
   SHA3 calls; reject any local win that increases the full pipeline.
5. Apply and independently review the native-ZK compiler to the exact winning transcript. Test
   malicious verifier choices, aborts, retries, malformed and duplicate openings, retained
   artifacts, terminal leakage, and atomic semantic-AIR/bus verification.
6. Only then run complete K128. K512 may use deterministic shards or overlap only under one global
   resource owner and the same fixed-shape/privacy/security contract. Neither profile receives
   projected latency or qualification credit before ten unique end-to-end runs.

The current arithmetic illustrates the gap but is not a composed proof measurement: the 35.1399522
second K128 GKR control plus the 27.8 second direct PCS control is 62.9399522 seconds if run
sequentially, already above the 60-second target, and the PCS realization exceeds the new RAM
limit. The three K512 GKR controls total 124.8322177 seconds; adding three copies of the K128 PCS
time would be a 208.2322177-second scaling illustration, not a measured K512 proof. The combined
architecture must therefore reduce work and overlap safe stages while eliminating full-resident
oracles. Scheduling alone cannot close both latency and memory.

## Later architecture decision (2026-07-13)

`docs/PQ_ZK_SECURITY_ARCHITECTURE.md` now selects the sealed application-specific M31 AIR as the
semantic module and `docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md` selects the shared-bus Fp16
Boolean GKR SHA3 coprocessor as the physical hash module. This supersedes the approval status of the
"M31 custom AIR" row below and retires the direct-SHA3-STARK release layout, but it does not
supersede any measurement, warning, or trust-boundary statement in this review.

The existing prototype remains only a six-column decision/totals AIR using `Blake2sChannel`,
`Blake2sMerkleHasher`, and QM31. It does not implement the complete claim, authoritative SHA3-512
state, witness hiding, or strict-PQ parameter analysis. All performance results in this document
remain prototype evidence and must not be projected onto the selected complete architecture.

## Already implemented

| Proposal | Current evidence |
| --- | --- |
| Persistent witness-side Poseidon helper | `app/batch/poseidon.py` keeps a server process alive, batches rows, caches single hashes, and retries once with a fresh worker if the process dies. The hash implementation and known-answer value are unchanged. |
| Batch-invariant fee-policy verification | `zk-cairo-sharp/src/lib.cairo::adjudicate_batch` calls `verify_batch_policy_dictionary` once before its claim loop. |
| Distinct fee-row dictionary | `app/batch/stark_binding.py::_rewrite_batch_policy_dictionaries` deduplicates `(procedure, allowed amount, TAR requirement)` rows and claims reference them by index. |
| Monolithic batch statement | `batch_main` proves the claims and ordered nullifier-root chain in one statement. The single-claim entrypoint remains because Cairo KATs execute it directly. |
| Witness/prove profiling | `tools/measure_proving.py` separates witness, execute, prove, and per-stage timings. `--witness-only` profiles large synthetic batches without starting a proof. |
| Cairo function-step profiling | `tools/profile_cairo_execution.py` accepts only its internally generated, hash-pinned one-claim synthetic fixture under explicit local/test opt-ins. It profiles a temporary circuit copy, reports aggregate resource/function timing only, verifies the protected source manifest is unchanged, and deletes raw witness, trace, and profile artifacts. |

## Safe work completed in the isolated review workspace

- Restart and retry the failed Poseidon request once when the persistent helper exits.
- Preserve fail-closed behavior if both the initial worker and restarted worker fail.
- Detect Scarb available only inside WSL instead of reporting it absent.
- Add a repeatable persistent-versus-one-shot Poseidon benchmark that requires byte-identical outputs.
- Add a repeatable Cairo function-step profiler that never edits the protected circuit source.
- Stage WSL proof execution in temporary Linux-native storage, record proof size/hash, and delete the validated temporary path after the run.
- Align portal contract tests with the shared local font stylesheet.

## Measured evidence from this workspace

Measurements were captured on 2026-07-10 with the current source and installed Scarb 2.18.0 toolchain.

| Run | Witness | Execute | Prove | Relevant result |
| --- | ---: | ---: | ---: | --- |
| 1 claim, full proof | 0.106396 s | 93.086414 s | 140.681949 s | Proof generation succeeded; prove was 99.92% of witness plus prove time. |
| 100 claims, witness only | 2.186370 s | Not run | Not run | Final witness construction was 1.916105 s, or 87.64% of witness time. |
| Poseidon, 256 rows x 20 requests | 0.253999 s persistent | Not applicable | 1.104458 s one-shot | Outputs were identical; persistent plumbing was 4.35x faster for this benchmark. |
| 1 claim, WSL-native manual proof | Not included | 12.455880 s | 123.938360 s | Source manifest matched; proof bytes and SHA-256 matched the earlier proof. |
| 1 claim, WSL-native repeat through `measure_proving.py` | 0.245336 s, plus 0.476558 s staging | 11.810917 s | 170.311082 s | Proof bytes and SHA-256 matched; proof time showed substantial run-to-run variation. |

These measurements do not support the transcript's claimed 10x to 100x end-to-end improvements. They show that process reuse materially improves witness hashing while the actual one-claim wall clock is dominated by Cairo execution and proof generation.

Moving generated Scarb execution/proof data from the Windows-mounted source tree to WSL-native temporary storage consistently reduced the execute phase from 93.086414 seconds to about 12 seconds in the observed runs. The prove phase varied from 123.938360 to 170.311082 seconds in the native-storage runs, so no storage-driven cryptographic proving speedup is claimed. Against the earlier 233.768363-second execute-plus-prove total, the two native-storage totals were 136.394240 and 182.121999 seconds, a measured 22% to 42% wall-clock reduction in these runs. More alternating trials under controlled thermal/load conditions are required before treating that range as a stable benchmark.

### One-claim Cairo execution profile

The profiled execution used the same one-claim `batch_main` witness shape as the successful proof. Profiling was performed on a temporary source-identical circuit copy; only that copy's `Scarb.toml` enabled Sierra and function debug data.

| Resource | Measured count |
| --- | ---: |
| Cairo steps | 10,462 |
| Poseidon builtin instances | 394 |
| Range-check builtin instances | 1,143 |
| Maximum memory address | 25,482 |
| Memory holes | 137 |

| Function or operation | Step attribution | Interpretation |
| --- | ---: | --- |
| `verify_transition_matches_claim` | 5,029 cumulative steps, 48.07% | Claim-to-nullifier binding plus the full nullifier transition. |
| `verify_nullifier_transition` | 4,821 cumulative steps, 46.08% | The full approved-claim indexed-tree transition. |
| `verify_nullifier_two_leaf_transition` | 4,788 cumulative steps, 45.77% | The two-leaf predecessor/insertion multiproof inside the transition. |
| `verify_poseidon_merkle_path` | 2,923 cumulative steps, 27.94% | Ordinary governed-root Merkle membership paths, separate from the nullifier multiproof. |
| `adjudicate_multi_line_phase3_with_roots` | 2,261 cumulative steps, 21.61% | Claim-specific adjudication and root binding. |
| `verify_batch_policy_dictionary` | 832 cumulative steps, 7.95% | Batch-level policy dictionary verification. |
| `U128DivRem::div_rem` | 2,332 flat steps, 22.29% | Path-index `% 2` and `/ 2` arithmetic is a measured hotspot. |
| Poseidon `HashStateImpl::update` plus `finalize` | 2,324 flat steps, 22.21% | Directly attributed Poseidon state work; this does not include every surrounding Merkle-control step. |

Cumulative function values include their callees and therefore must not be added blindly. `cairo-profiler` attributes the 394 Poseidon builtin samples to the execution root rather than individual functions, so this run does not support a claim that hashing is exactly 80 percent of proving work. It does support the narrower conclusions that the live nullifier transition is about 46 percent of Cairo execution steps for this input, direct Poseidon state operations are about 22 percent, and path-index division/remainder is another major hotspot. Execution-step percentages are not proof-time percentages because the prover can assign different costs to opcodes, builtins, commitments, and FRI work.

The successful one-claim proof was 13,865,776 bytes with SHA-256 `2e6a0d5edbf8884a6da4f5476298f06a3c5e95b4a8bb9934b24c0f6b06c3ea3f`. This records proof generation, not production-verifier acceptance; no production verifier was run in this workspace.

## Component liveness and integration status

"Defined," "covered by tests," and "used by the live settlement path" are different states. The repo-wide call-site search produced this classification:

| Component | Current status | Evidence and consequence |
| --- | --- | --- |
| Cairo `batch_main` aggregation | Live proving path | `build_monolithic_batch_input_witness` targets `blind_ledger_cairo_adjudication::batch_main`, which adjudicates all claims and enforces the ordered nullifier-root chain. |
| Python `AggregationWitness` / `verify_aggregation` | Test-only harness | Its only callers are in `tests/test_stark_field_foundation.py`; it is not managed proof aggregation and is not called by batch submission. |
| `app/batch/encrypted_da.py` | Tested helper, unwired | Encryption, decryption, and encrypted-bundle-root functions are called only by tests. The live batch builder separately computes a field named `encrypted_claim_data_root` from claim records. No runtime caller of `encrypt_claim_data` was found. |
| Settlement encrypted payload binding | Contract boundary present, assembly gap remains | `StarkBatchSettlement` requires `sha256(encryptedPayload) == encryptedClaimDataRoot`, but no runtime bridge in this archive was found that builds that encrypted payload through `encrypted_da.py`. |
| Python and Cairo epoch-nullifier functions | Tested reference/KAT layer | Python callers are tests, and Cairo callers are generated boundary KATs/source guards. `batch_main` instead proves sequential indexed-tree transitions for approved claims. |
| Cairo `claim_main` | Compatibility/KAT executable | It is invoked by `tests/test_multi_line_claim_facts_binding_kats.py`; production proof tooling targets `batch_main`. Removing it would break executable KAT coverage but would not shorten `batch_main` proofs. |
| Managed external proving | Rejected from the core architecture | Government-controlled proving and settlement remain the required deployment model. Settlement directly calls the pinned `INativeStarkVerifier.verifyStark`; no external proving service or fact registry is part of the runtime path. |
| LogUp and prover parallelism | Upstream prover facilities, not app switches | Stwo/Stwo Cairo already use lookup arguments, SIMD, and Rayon internally. Mapping Blind Ledger comparisons to a custom LogUp table or claims to explicit trace lanes requires AIR/prover work and verifier review. |

## Deferred trust-critical proposals

These are not ordinary optimizations. Each changes the proved statement, commitment format,
execution model, or double-spend construction and therefore requires explicit internal approval,
new known-answer vectors, internal adversarial review, and verifier compatibility work. The final
exact release later enters the independent audit.

| Proposal | Why it is deferred |
| --- | --- |
| Raw two-to-one internal-node hashing or Poseidon2 | Changes Merkle roots and every dependent commitment. Leaf tagging alone is not a substitute for a complete domain-separation and collision-resistance analysis. |
| Field packing | Changes serialization and potentially claim, policy, payment, batch, or public-input commitments. |
| Batched nullifier insertion | The current circuit proves an ordered root transition for each approved claim. Replacing it changes the double-spend security boundary and concurrency semantics. |
| Parallel recursive adjudication/ledger split | No recursive verifier or binding proof exists in this archive. It must prove that the independently adjudicated approved set exactly equals the sequential ledger insertion set. |
| Epoch proof caching | Requires a recursive proof interface, epoch lifecycle, stale-proof rejection, and verifier support that are not present here. |
| Managed external proof settlement | Rejected for the government-controlled core because it adds an outside availability, privacy, governance, and upgrade dependency. |
| LogUp or data-parallel trace layout | Upstream Stwo has LogUp, SIMD, and parallel proving, but the current trust root is a Cairo program compiled to the Cairo VM. A Blind Ledger-specific lookup or lane-oriented AIR is a circuit/prover redesign, not a Python or Cairo compiler switch. |
| M31 custom AIR | Replaces the Cairo VM statement with a hand-written constraint system and becomes a new trust root requiring a full equivalence specification and audit. |
| Binius64 | Benchmark/control only; its current field, 96-bit/SHA-256 Fiat--Shamir profile, and non-ZK benchmark path fail the frozen suite requirements. |
| Shared-bus Boolean GKR over Fp16 | Selected Wave 2 implementation priority, not an activated suite. H4 passes the exact bridge, native masking, Construction 8.2 PCS, atomic verifier, one-run resources, and K128/K512 prototypes; gate 2E, complete simulator/security composition, H5, and H6 remain. |

The later owner-approved architecture decision permits design and qualification of the M31 custom
AIR path. Source implementation still requires the protected-change authorization, equivalence
specification, new KATs, full regression gates, internal review, and final-audit boundary described here and in
`docs/PQ_ZK_SECURITY_ARCHITECTURE.md`.

## Rejected or unsupported claims

- The measured one-claim execution attributes 46.08 percent of Cairo steps to the full nullifier transition and 22.21 percent directly to Poseidon update/finalize operations. It does not establish 58 percent nullifiers, 80 percent hashing, or equivalent proof-time shares.
- No measurement establishes a 2x, 10x, 20x, or 100x end-to-end improvement.
- External shared proving and recursive proof composition are not interchangeable, and a project name is not evidence that settlement uses an outside proving service.
- `AggregationWitness`, `encrypted_da.py`, epoch-nullifier references, and `claim_main` are not unreferenced, but only `claim_main` participates in executable KATs; none is part of the live `batch_main` settlement flow described above.
- Filling a power-of-two trace tier may improve throughput, but changing batch sizing is an operational and latency policy decision and is outside the authorized scope.

## Required evidence before future cryptographic optimization

1. Record witness, execute, prove, trace-size, memory, and proof-size measurements for representative claim counts.
2. Preserve all existing known-answer vectors and attack tests, or explicitly version and independently review every changed commitment.
3. Write the old and new statements as precise invariants, including nullifier ordering and cross-batch replay behavior.
4. Prove public-input and verifier compatibility before settlement integration.
5. Complete internal cryptographic qualification before merging the new trust root and obtain final
   independent-audit acceptance before production activation.

## 2026-07-13 architecture and qualification timing

The approximately `17.052680`-hour complete-claim RISC Zero number is a linear projection from an
interrupted general-VM run with at least `199,229,440` guest cycles. It is not a completed proof
measurement. It disqualifies that general-purpose execution path as the intended production
proving architecture; it does not measure the selected heterogeneous proof.

The replacement six-column, 1024-row S-two prototype measured `11.584ms` mean internal
prove-plus-verify time, including `0.299ms` mean verification. That prototype omits the complete
claim semantics, governed roots, nullifiers, exact 12-field statement, witness hiding,
authoritative SHA3-512 state, and strict-PQ transcript/PCS. It is evidence that the narrow
architecture can be fast, not a final proof-time claim.

One software-test optimization moved the expensive production-source walk behind already
conclusive fail-closed readiness gates. Focused readiness tests fell from `97.21s` to `0.22s`, a
`99.773686%` reduction (`99.774%` rounded) and `441.863636x` speedup, while an open launch blocker
still makes production readiness false. This changes regression latency only; it does not change
proof generation.

The final non-attack Python lane took `602.04s`. Its separately measured complete Python/Cairo/RISC
semantic differential took `160.65s`, equal to `26.684273%` of that wall time under a simple ratio.
The historical `112.04s` 10,000-case Poseidon path-index measurement would equal `18.610059%` of
the final wall time if its duration was unchanged; because it was not re-timed independently in the
final run, that percentage is conditional. Together those two checks would conditionally account
for `45.294333%`. They are convergence/qualification costs, not proof stages.

Full regression, duplicate platform builds, dirty-tree privacy scanning, and the future 124-proof
campaign must not be used as per-edit feedback. Focused tests should run per edit, language suites
at language boundaries, heavy semantic/property differentials after commitment or encoding
changes, and every gate only for a final candidate. Acceptance criteria remain unchanged. The
124-proof campaign must wait for the complete AIR, hiding layer, wide state, strict-PQ parameters,
and independent verifier.


## Superseding verified proof result (2026-07-10)

Any earlier statement in this document that no verifier was run, or that the standalone proof with SHA-256 `2e6a0d5edbf8884a6da4f5476298f06a3c5e95b4a8bb9934b24c0f6b06c3ea3f` was verified, is superseded by this section. The installed Scarb standalone verifier rejects both Blind Ledger and trivial standalone executions with `ECDSA segment is not empty`; that artifact is generation-only and must not be treated as valid.

A supported simple-bootloader run using an upstream `Cairo1Executable` task generated and verified a one-claim `batch_main` proof. The proof is 5,591,878 bytes with SHA-256 `20801b8071e6fead23db5d6c3c2a2e239d33e1475756c104d3c76da9b61b0fb4`. The upstream verifier completed successfully, and all 12 inner batch outputs matched the Python witness exactly. Observed timing was 3.32 seconds for Cairo execution, 85.2 seconds for the prove/verify/serialize section, 43.5 milliseconds for verification, and 89.0 seconds total for the bootloader command.

This is a verifier-clean off-chain Stwo proof under proving-utils commit `0a97f45a15809e7b5a821b7adc49212af7b399f1` and stwo-cairo commit `ffd4a4e8d101abbf916db1977e2ac32b52b0fbe9`. It is not yet evidence that the pinned settlement verifier accepts this proof encoding or the bootloader output frame; that boundary still requires an explicit contract-level compatibility test. The artifact and machine-readable provenance are stored outside the application source under `blind-ledger-claude-architecture-workspace/proof-runs/bootloader-batch1/`.

