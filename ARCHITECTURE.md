# Blind Ledger architecture

Updated: 2026-08-05

Canonical navigation: `docs/CURRENT_TECH_STACK.md` defines the current implementation inventory;
`docs/REJECTED_ARCHITECTURES.md` is the only rejection ledger. Historical measurements in other
documents never override this architecture or re-enable removed code.

For context-free continuation, use the deterministic continuation contract near the top of
`docs/IMPLEMENTATION_ROADMAP.md`. It names the sole current dependency chain and supplies explicit
Gate 2E, H5, and H6 inputs, outputs, tests, measurements, STOP conditions, and handoff fields. Dated
sections in any architecture document preserve evidence; their old “next step” language is not an
execution instruction.

The current execution checkpoint is the newest dated section of `STATE.md`; the original transfer
boundary remains `WAVE2_HANDOFF_2026-07-26.md`. The RTX 4060 is an untrusted field-arithmetic
accelerator, while Rust retains authoritative SHA3-512 commitment, transcript, canonical decoding,
multiproof, answer-code, target, public-coin replay, and verification duties. The real 168-layer
masked GKR producer, native masks, Construction 8.2 PCS, and authenticated same-chain coordinator
pass as the sealed H4 prototype. Gate 2E is sealed nonactivating; H5 passed the exact 22-launch
campaign; and H6 closed the twelve bounded candidate-evidence records. `proofSuiteId=null`,
activation is false, and production verifier/state/custody, rollup, and final audit work remain
open. Wave 4 adapter and operations engineering is now complete internally in a local/synthetic,
nonactivating boundary. The 29.974129/120.460733-second K128/K512 values below are the H4 baseline,
not the H5 p95 record.

The selected state-free bounded join does not require multi-gigabyte host state. The five-claim component
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

Cross-wave state, scheduling, adapter-evidence, and formalization are governed by
`docs/FRONTIER_THROUGHPUT_AND_ETHEREUM_ALIGNMENT.md`. The complete live Ethereum Strawmap
snapshot, all 23 linked EIPs, non-EIP upgrade through-lines, maturity rules, and exact R01-R12
consequences are governed by `docs/ETHEREUM_STRAWMAP_BASED_ROLLUP_COMPATIBILITY.md`. Both assign
work to existing packages rather than creating a second roadmap.

The canonical target design is `docs/BASED_ZK_ROLLUP_ARCHITECTURE.md`. Blind Ledger **is designed
as an Ethereum-settled, EVM-compatible based validity rollup**; this is compulsory, not an optional
future mode. Ethereum canonical ordering, mandatory validity, non-PHI public DA, and no permanent
privileged sequencer are frozen R01-R12 invariants. This document describes the current source
layout; it must not be read as evidence that the target rollup or production verifier is already
implemented.

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

This checkout is already the application source root:

```text
repository root/
  app/                         application and portal code
  experiments/                 sealed relation and proof prototypes
  ops/                         canonical operational artifacts
  contracts/                   protected settlement shell
  tests/                       ordinary and attack regression suites
```

Run application, test, and measurement commands from this repository root unless a tool
specifically requires another directory, such as the Rust crate or `zk-cairo-sharp/`.

## Components

| Component | Path | Role |
| --- | --- | --- |
| Python app layer | `app/` | Ingestion, adjudication wiring, canonical encoding, batch assembly, and portal helpers. |
| Batch core | `app/batch/` | Nullifiers, leaves, Merkle tree, accumulators, public-input binding, STARK handoff, and Poseidon helper integration. |
| Rules engine | `rules-engine-rust/` plus Python adapter/fallback | Policy adjudication. Local Python fallback is for tests/benchmarks only, not production adjudication. |
| Claim-proof references | `zk-cairo-sharp/`, `experiments/fixed_shape_claim_air/`, `experiments/bl_pq512_crypto_core/` | Cairo is historical semantic evidence; the sealed M31 AIR is the semantic module; Wave 2 builds the shared-bus Boolean hash coprocessor, mandatory committed sparse-state/PQ-commitment bake-off, and atomic verifier. |
| Wave 3 internal verifier/state/custody | `experiments/bl_pq512_crypto_foundation/wave3_nullifier_authority.py`, `wave3_verifier_state_custody.py`, and `wave3_full_internal.py` | Nonactivating internal P01-P12 boundary: A12-derived dual roots, fixed 256-slot batch replay plus hidden salt-use insertion, canonical 744-byte proof envelope, full S10 state tuple, private payment-root recomputation, durable governed registry bound into state creation/reopen/refresh, local Rust-authoritative binding port, recovery/migration/rollback, and digest-only custody evidence. Production verifier, HSM/FIPS, external anti-rollback, and activation remain open. |
| Solidity contracts | `contracts/` | Verifier and settlement-facing on-chain code. Protected from casual edits. |
| Operations | `ops/` | Sole commit-bound policy spec, verifier pin manifest, deployment config, and readiness authority. |
| Tests | `tests/` and `tests/attacks/` | Known-answer, readiness, integration, and attack-regression checks. |
| Tools | `tools/` | Measurement and utility scripts. |
| Integration ports | `app/wave4_adapters.py`, `app/wave4_operations.py` | Provider-neutral government/oracle/payment ports, dual-PQ provenance, local simulators, isolated operations, and shared conformance tests; production activation remains disabled. |
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

The current nonactivating sub-35-second K128 implementation is section 8.3 of
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`: a bounded CPU/SIMD semantic-AIR lane runs
concurrently with the exact seven-layer/B=16 Fp16 GPU hash lane. The hash proof has one output
and four relay-free input claims. The state-composed shape adds two relation and twelve square-free
state claims to the same Construction 8.2 random-padded interleaved Reed--Solomon PCS through the fixed nineteen-claim row
binding, one authenticated public coin, and one atomic verifier join. The joined row state is
7.864320 MB for the five-claim component/source/relation plane plus 4.194304 MB for the GKR-mask
row plane, 12.058624 MB total, and is extracted from live commitment tiles without a second full
source replay. The real producer, native mask, 73-word auxiliary plane, 6,113-round fixed prelude,
PCS openings, and independent verifier pass together. State composition adds 614/882 square-free
rounds and reaches 6,727/6,995 for K128/K512. CPU integration and conditioned simulator mechanics
pass, but the H4 baseline is not itself H5/H6 evidence. The exact H5 campaign and bounded H6
candidate-evidence manifest are recorded separately, while production identity and activation
remain closed. The final fresh state-free proof measured 29.974129 seconds for K128 and 120.460733
seconds for four-shard K512 inside the atomic coordinator.

The reference Dell release envelope is no more than 5,000,000,000 peak resident bytes, scratch
strictly below 5,000,000,000 bytes, and no swap. The selected bounded implementation uses
288.412/296.255 MB internal host memory, 681.607168/706.523136 MB external process-tree RSS,
969.999360 MB tracked device state per proof, 2,770.337792 MB sampled total K512 GPU residency,
and zero scratch. Bounded streaming, recomputation, and single-owner buffer lifetimes are mandatory
architecture properties.

No alternative PCS, code, sumcheck, or accelerator lane is currently admitted. The current
optimization policy is `docs/PROVING_OPTIMIZATION_REVIEW.md`; former paper screens and prototype
orders are quarantined under `docs/history/`. A new candidate must re-enter through exact theorem,
privacy, PQ, independent-verifier, resource, migration, and complete-boundary measurement gates.

The production state plane remains unselected: `docs/BL_PQ512_COMMITTED_SPARSE_STATE_PLAN.md`
keeps the SHA3-512 endpoint-multiproof path and sparse-state/PQ-commitment alternatives behind one
replaceable interface. The nonactivating Gate 2E context and H5/H6 candidate evidence are complete,
but they do not authorize a production state layout.

The native state boundary now has a nonactivating v3 component path in
`experiments/bl_pq512_crypto_foundation/state_air_proof.py`: a compact packed transition AIR,
private streamed dual-PQ FRI package, and native exact-witness cross-check. This is real
component-verification evidence and is bound by the v3 state envelope before the H4 parent,
transcript, child grammar, and receipt. It does not turn the unselected state plane into a selected
backend, and it does not claim the full state relation is algebraically inside the custom H4 GKR/PCS
proof; the simulator and candidate-evidence records are complete in the bounded H6 manifest.
Production state/custody, suite identity, and activation remain open.

The current native H4 state-GKR seam is implemented in
`experiments/bl_pq512_crypto_core/src/state_relation_gkr.rs` and its public-coin bridge. It binds a
fixed 64-wire state lane at H4 wire offset 1,600, two boundary-one PCS claims, and a canonical
16,777,216-byte private source. The relation currently covers operation/snapshot field equality,
Boolean presence, and empty-slot zeroing only; full operation order, uniqueness, membership/absence,
and money/state conservation remain production-state obligations. This is an authenticated
integration slice. By itself it is not state admission, a production verifier, or activation
evidence.

The next measured boundary is authenticated state: 46,208 of 46,858 K128 SHA3 calls arise from
replay/payment state. Current maps remain authoritative while a versioned topology bake-off,
privacy-padded access manifest, and deterministic conflict DAG are tested. Structural call-count
projections are not proof-throughput results.

The C0 typed-state executable component now closes the missing semantic slice at its own AIR
boundary. It composes the ordered-map replay and payment-map authorities, binds lane roots and
cursors, enforces fixed slot order, canonical money subtraction, and debit/credit conservation,
and exposes replay/payment SHA3 ports through one canonical interface composer. Its K128 readback
is `BL-PQ512-C0-TYPED-STATE-AIR-v1` with 60 tables, 93 lookups, 1,806 public inputs, and 46,210
exact hash calls. The two added calls are the C0 state-root calls; the base H4 replay/payment bus
remains 46,208 calls. Positive and split mutation checks passed, including fixed binding of every
asset-registry byte. The native H4 coordinator consumes the full typed AIR program/execution,
replays its authority/root interfaces, and maps all 46,210 typed calls to the canonical H4 bus,
including the two appended state-root calls. The selected typed AIR proof route then failed the
immutable resource preflight, so this is an implemented nonactivating readback seam. It receives
no production-suite or activation credit.

## Operational artifact layout

Tracked `ops/` is the sole repository authority. Its exact 14-file regular-file inventory, lengths,
and SHA3-512 identities are frozen in `ops_authority.py`; policy hashing uses the same tracked path.
Sibling copies, mirrors, symlinks, and fallback resolution are rejected so one mutable copy cannot
silently outrank another. Policy bytes and verifier pins remain trust-critical reviewed material.

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
6,086-round state-free coordinator now passes independent verification together under execution manifest
`51c23310274ccf7c4d7f9abe4ae7eba43266b335bd377b21cbf92409729b91e2a40a39787a157baa080c9d0516c7815af404a4d58d9e76747f652f57cd017ed6`.
The accepted fresh K128 proof measured 29.974129 seconds. Four ordered K512 shards reused the same
bounded one-GPU design and completed atomically in 120.460733 seconds.

Final decimal internal host peaks are 288.412 MB for K128 and 296.255 MB for K512. External
process-tree peaks are 681.607168 and 706.523136 MB; per-proof tracked device allocation is
969.999360 MB and K512's externally sampled total GPU residency is 2,770.337792 MB. Both accepted
attempts used 0.000000 MB scratch and had zero pagefile growth. This sealed H4/qualified-suite
baseline is serial; the active native coordinator now defaults to two independent lanes, and its
captured exact two-lane campaign now passes the dedicated execution-mode evidence validator as
nonactivating evidence. The validator records 11 launches, p95 `101.798191` seconds, maximum
external RSS `1467465728` bytes, maximum GPU residency `5314` MiB, zero scratch, and no positive
pagefile growth. Current-commit refresh attempts remain rejected when the host pagefile grows;
they receive no qualification or production credit.

The active regression objective is low-hundreds-of-MB internal host use while preserving the
immutable 5,000 MB host, below-5,000 MB scratch, and no-swap gates.

### Native K512 default decision (2026-08-05)

The native atomic K512 coordinator now selects two independent shard lanes by default for the
native execution boundary, including suite-bound runs. `BL_SHARD_CONCURRENCY=1` is the explicit
serial fallback. Each lane retains its own authenticated challenge stream and proof; the
coordinator waits for the complete group, verifies every shard, and commits the receipt in
canonical order. This is a nonactivating native execution mode; the generic Cairo/encrypted-worker
queue is a separate input boundary and is not silently rerouted to this coordinator.

Two fresh no-override launches selected two lanes and independently verified all four shards, but
the external monitor rejected pagefile growth of `305` MB and `18` MB. This preserves the no-swap
gate: the code-level default is present, while those launches are not production-admission or
qualification evidence.

## Atomic semantic execution boundary

The active H4 prototype has one acceptance boundary for both profiles. K128 is one canonical B16
shard; K512 is four ordered canonical B16 shards. The native coordinator may run at most two
independent lanes concurrently, while each shard retains its own nonlinear authenticated challenge
stream and complete independent verification. An outer
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

The newest complete K128/K512 proofs pass all functional and 30/180-second H4 prototype gates at
29.974129/120.460733 seconds. The separate exact H5 p95 campaign passed, and the bounded H6
candidate-evidence manifest closed all twelve records. Production use remains closed because
`proofSuiteId` is still null and the production verifier/state/custody and audit gates remain
unfinished.
