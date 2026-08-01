# Blind Ledger architecture

Updated: 2026-07-31

The current execution checkpoint is the newest dated section of `STATE.md`; the original transfer
boundary remains `WAVE2_HANDOFF_2026-07-26.md`. The RTX 4060 is an untrusted field-arithmetic
accelerator, while Rust retains authoritative SHA3-512 commitment, transcript, canonical decoding,
multiproof, answer-code, target, public-coin replay, and verification duties. The real 168-layer
masked GKR producer, native masks, Construction 8.2 PCS, and exact 6,086-round same-chain
coordinator now pass as one manifest-bound semantic prototype. Under the verified
`2026-07-31T05:06:01.7747420-06:00` driver-reset boundary, fresh K128 and four-shard K512 proofs
completed through independent verification in 29.974129 and 120.460733 seconds. Both accepted
attempts had zero pagefile growth, zero scratch, empty stderr, and zero later
`nvlddmkm` Event 153 or Display Event 4101. This closes the H4 one/four-shard prototype and latency
boundary, not H5's warm-up-plus-ten p95 campaign, H6 suite qualification, or activation.
`proofSuiteId=null` remains unchanged.

The selected bounded join does not require multi-gigabyte host state. The five-claim component
rows plus claim source/relation rows are 7.864320 MB decimal. The simultaneously live GKR-mask row
source/relation state is 4.194304 MB, making 12.058624 MB total joined row state. The GKR mask uses
2.097152 MB of coefficients and 33.554432 MB of auxiliary RS codewords; the complete 73-word
auxiliary plane uses 15.258752 MB of coefficients and 38.273024 MB of codewords. Final K128/K512
internal proof host peaks were 288.412/296.255 MB; external process-tree peaks were
681.607168/706.523136 MB because the monitor includes the parent, native verifier, active worker,
and exactly one future standby. Per-proof tracked device state was 969.999360 MB. The K512
external sampler observed 2,770.337792 MB total GPU residency across live CUDA contexts. Scratch
was 0.000000 MB and pagefile CurrentUsage did not grow. These are complete-prototype measurements,
not the warm-up-plus-ten qualification campaign.

Cross-wave state, scheduling, adapter-evidence, formalization, and Ethereum compatibility are
governed by `docs/FRONTIER_THROUGHPUT_AND_ETHEREUM_ALIGNMENT.md`. It assigns work to existing
packages rather than creating a second roadmap.

The canonical target design is `docs/BASED_ZK_ROLLUP_ARCHITECTURE.md`. Blind Ledger targets an Ethereum-settled, EVM-compatible based validity rollup. This document describes the current source layout; it must not be read as evidence that the target rollup or production verifier is already implemented.

`docs/DEPLOYMENT_READY_BUILD_CONTRACT.md` defines the whole-product completion boundary. All 93
roadmap packages—including the proof/state core, adapters, rollup, deployment, and release
evidence—are internal engineering. One final independent Security Audit Gate follows completion;
live credentials and authorizations are operator activation inputs.

The current inner claim-proof target is heterogeneous, not Cairo-only or one monolithic S-two
proof: the sealed M31 semantic AIR binds every SHA3 port through one committed fixed-shape bus to an
Fp16 Boolean GKR hash coprocessor. The authoritative contract is
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`. Cairo, RISC Zero, and the direct SHA3 AIR remain
semantic/differential references; the 554-951 GB direct-SHA3-STARK layouts are retired.

## System shape

Blind Ledger is organized as a source-first app-layer handoff:

```text
Blind Ledger Neer Version/
  ops/                         canonical operational artifacts
  third_party/forge-std/        vendored Solidity test dependency
  blind-ledger-app-layer/       application source root
```

Run application, test, and measurement commands from `blind-ledger-app-layer/` unless a tool specifically requires another directory.

## Components

| Component | Path | Role |
| --- | --- | --- |
| Python app layer | `app/` | Ingestion, adjudication wiring, canonical encoding, batch assembly, and portal helpers. |
| Batch core | `app/batch/` | Nullifiers, leaves, Merkle tree, accumulators, public-input binding, STARK handoff, and Poseidon helper integration. |
| Rules engine | `rules-engine-rust/` plus Python adapter/fallback | Policy adjudication. Local Python fallback is for tests/benchmarks only, not production adjudication. |
| Claim-proof references | `zk-cairo-sharp/`, `experiments/fixed_shape_claim_air/`, `experiments/bl_pq512_crypto_core/` | Cairo is historical semantic evidence; the sealed M31 AIR is the semantic module; Wave 2 builds the shared-bus Boolean hash coprocessor, mandatory committed sparse-state/PQ-commitment bake-off, and atomic verifier. |
| Solidity contracts | `contracts/` | Verifier and settlement-facing on-chain code. Protected from casual edits. |
| Operations | `ops/` and `../ops/` | Policy spec, verifier pin manifest, deployment config, and readiness artifacts. |
| Tests | `tests/` and `tests/attacks/` | Known-answer, readiness, integration, and attack-regression checks. |
| Tools | `tools/` | Measurement and utility scripts. |
| Integration ports | future I01-I08 modules | Provider-neutral government, oracle, KMS/HSM, governance, and payment contracts with local simulators and shared conformance tests. |
| Containing rollup | future R01-R12 modules | Based sequencing, L2 verifier/state execution, validity proof, data availability, Ethereum settlement, bridge, exits, upgrades, and recovery. |

## Data and proof flow

1. Provider or test input supplies claim data.
2. The Python app parses and canonicalizes claim facts.
3. The rules-engine path adjudicates policy facts and emits batch-ready decisions.
4. Batch assembly creates leaves, nullifiers, roots, and public inputs.
5. The heterogeneous claim proof verifies the semantic AIR, shared hash-call bus, and Boolean SHA3
   coprocessor atomically under authenticated interactive public coin.
6. Settlement/verifier code consumes the pinned verifier artifacts and public-input boundary.

The current step 6 is incomplete: Cairo `batch_main` returns 12 values, while the V1 settlement contract accepts a separate 21-value caller-supplied array, and the repository contains no production `INativeStarkVerifier` implementation. The target design requires one exact proof-authenticated output ABI before any state transition can settle.

## Target rollup layers

| Layer | Responsibility |
| --- | --- |
| Ethereum L1 | Based sequencing, public rollup data availability, rollup proof verification, canonical state root, bridge/escrow, forced inclusion, and finality. |
| Blind Ledger L2 | EVM execution, claim-proof verification, governed roots, nullifiers, accumulators, and private-payment commitments. |
| Government private systems | PHI storage, KMS/HSM custody, private witnesses, proving, selective audit access, retention, and crypto-erasure. |

Robinhood Chain is an Arbitrum optimistic L2 with a dedicated sequencer; it is an operational comparison, not the selected security model. Taiko-style based sequencing is the closer reference.

Hash, commitment, root, nullifier, and proof-related values are trust-critical. Do not change their construction without known-answer tests and explicit approval.

## Proving optimization boundary

The implemented, deferred, and rejected optimization proposals are tracked in
`docs/PROVING_OPTIMIZATION_REVIEW.md`. The shared-bus Boolean coprocessor is the selected Wave 2
implementation priority, not an activated suite. Hash replacement, field changes, recursive
decomposition, or batched-nullifier semantic changes remain new trust roots rather than routine
performance patches.

The current nonactivating sub-30-second K128 implementation is section 8.3 of
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`: a bounded CPU/SIMD semantic-AIR lane runs
concurrently with the exact seven-layer/B=16 Fp16 GPU hash lane. One output and four relay-free
input claims bind its two committed source boundaries to the Construction 8.2 random-padded
interleaved Reed--Solomon PCS through a compact five-claim/sixteen-coordinate quadratic row
sumcheck, one authenticated public coin, and one atomic verifier join. The joined row state is
7.864320 MB for the five-claim component/source/relation plane plus 4.194304 MB for the GKR-mask
row plane, 12.058624 MB total, and is extracted from live commitment tiles without a second full
source replay. The real producer, native mask, 73-word auxiliary plane, exact 6,086-round
coordinator, PCS openings, and independent verifier now pass together. The final fresh proof
measured 29.974129 seconds for K128 and 120.460733 seconds for four-shard K512 inside the atomic
coordinator. `complete_proof_qualification=false` remains correct until the H5 campaign and H6
qualification gates close.

The reference Dell release envelope is no more than 5,000,000,000 peak resident bytes, strictly
below 5,000,000,000 scratch bytes, and no swap. The 3.24 GB coherent-chain measurements remain
correctness/parity controls rather than complete resource-qualified runs because they do not measure
the complete proof pipeline. The 5.06-7.46 GB PCS realizations and both raw all-Fp16 GKR baselines
are rejected before overhead. Subfield-first
promotion, bounded streaming, recomputation, and single-owner buffer lifetimes are therefore
mandatory architecture properties, not optional tuning.

The admitted frontier refinement is a combined architecture, not a new proof-suite selection:
Keccak-specific GKR algebra over the unchanged FIPS 202 relation; an exact M31-to-Fp16 tower and
small-value sumcheck; persistent bounded GPU execution with authoritative Rust transcript and
verification; and a streamed jagged code PCS whose tiles do not survive their commitment/frontier
stage. Native-ZK compilation, exact 256-bit security/encryption and unique-decoding parameters, and
atomic verification
remain mandatory. The research sources, incompatible dependencies, second-order effects, and
prototype order are recorded in `docs/PROVING_OPTIMIZATION_REVIEW.md`. No paper benchmark changes
the current suite, latency evidence, or release status.

The state plane remains unselected: `docs/BL_PQ512_COMMITTED_SPARSE_STATE_PLAN.md` requires the
current SHA3-512 endpoint-multiproof path and all admitted sparse-state/PQ-commitment candidates to
be implemented and measured before the complete K128/K512 proof gate.

The next measured boundary is authenticated state: 46,208 of 46,858 K128 SHA3 calls arise from
replay/payment state. Current maps remain authoritative while a versioned topology bake-off,
privacy-padded access manifest, and deterministic conflict DAG are tested. Structural call-count
projections are not proof-throughput results.

## Operational artifact layout

Two `ops` locations are present intentionally:

- `../ops/` is required by code that hashes policy artifacts using a sibling path from the app layer.
- `ops/` inside this directory is a compatibility mirror for readiness tests and app-root tooling.

The contents must remain byte-identical. Do not edit policy YAML or verifier pin files to hide layout failures.

## Proof artifacts

This source archive excludes generated Scarb targets, execution traces, and proof JSON. Regenerate proofs locally when needed and record the raw command output and hashes. See `PROOF_PROVENANCE.md` for the latest recorded external proof note.

## Toolchain note

Agents should check existing installations before installing anything. If Python, Rust, Scarb, Foundry, or CUDA are already installed and working, use them. Install only missing Python packages into a local virtual environment unless explicitly told otherwise.

## H4 semantic hash-coprocessor proof boundary

The K128 semantic hash-bus statement is bound atomically to the canonical boundary header, all
three semantic commitments, exact file shape and SHA3-512, selected shard, and selected nonuniform
GKR plan. The real producer, native masks, Construction 8.2 PCS, and independent verifier share one
authenticated schedule. Compact PCS evaluation may reorder the private in-process input/output
view to its output/input grammar, but it must authenticate the unchanged canonical file and retain
both source boundaries through the non-Boolean word fold. Fixed-zero padding stays implicit and no
full Fp16 source replay is allowed.

## Current H4 measurement

The exact semantic B16 source, real 168-layer producer, native masking, Construction 8.2 PCS, and
6,086-round coordinator now pass independent verification together under execution manifest
`51c23310274ccf7c4d7f9abe4ae7eba43266b335bd377b21cbf92409729b91e2a40a39787a157baa080c9d0516c7815af404a4d58d9e76747f652f57cd017ed6`.
The accepted fresh K128 proof measured 29.974129 seconds. Four ordered K512 shards reused the same
bounded one-GPU design and completed atomically in 120.460733 seconds. The older
53.547306/220.583627-second measurements are retained only as superseded profiling evidence.

Final decimal internal host peaks are 288.412 MB for K128 and 296.255 MB for K512. External
process-tree peaks are 681.607168 and 706.523136 MB; per-proof tracked device allocation is
969.999360 MB and K512's externally sampled total GPU residency is 2,770.337792 MB. Both accepted
attempts used 0.000000 MB scratch and had zero pagefile growth. K512 remains sequential; four-way
image duplication and theorem-free challenge sharing are prohibited.

The historical 200 MB host and 1,800 MB device component-selection targets are not current
acceptance gates. The owner's later resource direction replaces them with the measured
low-hundreds-of-MB internal host objective while preserving the immutable 5,000 MB host,
below-5,000 MB scratch, and no-swap gates. This supersession is explicit; the older measurements
remain dated audit evidence.

## 2026-07-30 atomic semantic execution boundary

The active H4 prototype has one acceptance boundary for both profiles. K128 is one canonical B16
shard; K512 is four ordered canonical B16 shards proven sequentially on one GPU. Each shard has
its own nonlinear authenticated challenge stream and complete independent verification. An outer
v2 SHA3-512 parent/receipt binds semantic commitments and file digest, selected GKR plan, caller
statement, shard order and child proof bundles, and an execution manifest covering the exact
Python/prototype/worker dependency closure, seven native verifier executables, and precompiled
PTX. Path existence alone is not identity evidence.

The verifier accepts only the complete theorem shape: 20 or 36 authenticated trees, 73 auxiliary
words including all 64 GKR-mask words, V4 answer code, and V2 standalone answer target. Pre-mask
and incomplete encodings are invalid, not compatibility formats.

The worker is an untrusted accelerator. Rust owns topology, native masking, recurrence and endpoint
checks, challenge release, copied-source terminal evaluation, transcript replay, and final
verification. Windows requires a fresh process every 48 completed layers; larger batches are
forbidden because a 56-layer test faulted at layer 54. Canonical layer plans are sent in one
prevalidated batch, immutable geometry is uploaded once per worker, and exactly one future worker
is kept ready. Zero standby would expose fresh-context latency; more than one is unmeasured
residency/launch bloat. Python starts with `-S` because the manifest-bound workers use only the
standard library and local pinned modules.

The newest complete K128/K512 proofs pass all functional and 30/180-second prototype gates at
29.974129/120.460733 seconds. Qualification remains closed because one successful attempt is not
the required warm-up-plus-ten p95 campaign and H6 suite qualification has not run.
