# Blind Ledger app layer

Start with `docs/CURRENT_TECH_STACK.md`, `ARCHITECTURE.md`, the newest section of `STATE.md`, and
`docs/IMPLEMENTATION_ROADMAP.md`. `WAVE2_HANDOFF_2026-07-26.md` is transfer history, not the current
PCS or execution boundary. Rejected paths are isolated in `docs/REJECTED_ARCHITECTURES.md`.

Blind Ledger is a zero-knowledge payment-system prototype with a Python application layer, Rust
policy/rules engine, sealed M31 semantic relation, Rust-authoritative Fp16/GKR/PCS verifier,
untrusted CUDA acceleration, and a protected Solidity settlement shell. Cairo is a historical
differential reference, not the selected proof backend.

## Plain-English current status

As of 2026-08-06, the Wave 2 candidate evidence is complete without being activated:

- Gate 2E has a sealed, nonactivating state-bound proof context.
- H5 passed the exact 22-launch campaign: K128 p95 was 32.360845 seconds and K512 p95 was
  148.861885 seconds, with the required verification and resource checks passing.
- H6 closed all twelve candidate-evidence obligations, including the strict-PQ ledger, parser/KAT,
  attack, supply-chain, reproducibility, privacy, migration, and Wave 3-boundary records.
- Wave 5 R01-R12 now passes the local/synthetic based-rollup boundary: exact 12-field-plus-sidecar
  binding, L2 transition proof fixture, finalized-only settlement, commitment-only DA, based ordering,
  bridge, forced inclusion, exit delay, fork migration, and rollback.
- The local native→Privacy V2→based-rollup seam now passes: Rust derives the lossless 108-limb
  projection, local settlement publishes only after native receipt checks, and a commitment-only
  cross-layer receipt binds the rollup handoff.
- Production is still disabled: global `proofSuiteId=null`, activation is false, deployed
  verifier/state/custody, HSM/FIPS authority, whole-product release authorization, and final audit
  are still unfinished, and real PHI/payments remain forbidden.

The native K512 experiment now defaults to two independent shard lanes. A separate fail-closed
validator now qualifies the captured two-lane execution mode as nonactivating evidence while
keeping the unchanged no-pagefile-growth gate, `proofSuiteId=null`, H5/H6 separation, and
production activation false. Current-host refresh attempts that grew the pagefile remain rejected.

The complete product roadmap is internally complete at the local/synthetic boundary: **93 of 93
engineering packages are complete and 0 are open**. Wave 3 P01-P12, Wave 4 I01-I08/O01-O06/O12,
and Wave 5 R01-R12 are complete as internal nonactivating engineering at their local/synthetic
boundaries. Current Wave 1, historically called Wave 1A, is sealed as a nonactivating
executable relation. Current Wave 2, historically called Wave 1B, is the strict-PQ proof and
throughput-recovery wave. The only external assurance dependency is one final independent Security
Audit Gate after all six internal waves. This repository is not yet a deployment-ready candidate
and real PHI/payments are forbidden. See `docs/DEPLOYMENT_READY_BUILD_CONTRACT.md` for the exact
build/audit boundary and `docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md` for the active proof/resource
plan. `docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md` is the authoritative Wave 2 architecture:
the 554-951 GB direct-SHA3-STARK layouts are retired and replaced as the implementation priority by
a shared-bus Boolean hash coprocessor, still subject to complete theorem, privacy, and K128 gates.

`docs/BL_PQ512_COMMITTED_SPARSE_STATE_PLAN.md` owns mandatory Wave 2 gate 2E: implement and select
between the existing SHA3-512 state-proof control and persistent sparse-state/dictionary/RAM
relations with separately qualified native-hiding PQ commitments. Complete K128/K512 qualification
is gate 2F. No state candidate is selected or activated by that plan.

`docs/FRONTIER_THROUGHPUT_AND_ETHEREUM_ALIGNMENT.md` adds the next cross-wave work: attack the
dominant state-proof cost, safely schedule independent claims, bind government/oracle evidence, and
stay compatible with Ethereum's direction. It adds no package, makes no unmeasured speed claim,
preserves strict-PQ/privacy bounds, and keeps draft EIPs optional.

`docs/ETHEREUM_STRAWMAP_BASED_ROLLUP_COMPATIBILITY.md` is the complete current Ethereum
compatibility contract. It records all 23 live-map EIPs and every planned consensus/data/execution/
PQ/privacy through-line, with maturity gates and R01-R12 ownership. Blind Ledger's
Ethereum-settled based-validity architecture is compulsory; draft features remain optional
adapters and public Ethereum data remains non-PHI. Its INHERIT/L1-COMPAT/L2-PARITY/OPTIONAL/
RESEARCH classes explain which benefits arrive through L1, which require direct L2 work, and when
each change becomes actionable.

This checkout is the source root and sole operational source of truth. Tracked `ops/` is the sole
commit-bound policy and verifier authority. Its exact file set, lengths, and SHA3-512 identities
are checked; do not create a sibling mirror or fallback copy. The release builder may add a
`Blind-Ledger-Release/` ZIP wrapper, but it does not create another source root.

The checkout does not include the external `forge-std` dependency expected by the Solidity
Foundry configuration. A Forge run receives no release or production credit unless that reviewed
dependency is explicitly provisioned and its source identity is recorded.

## Start here

1. Read `AGENTS.md` and `CONTINUATION_MANDATE.md` for protected paths and trust-critical rules.
2. Read `docs/CURRENT_TECH_STACK.md` for the only current stack and status boundary.
3. Read `docs/IMPLEMENTATION_ROADMAP.md`, `docs/DEPLOYMENT_READY_BUILD_CONTRACT.md`, `docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md`, and `docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md` for current progress and gates.
4. Read `docs/BASED_ZK_ROLLUP_ARCHITECTURE.md` for the containing architecture and verifier gap.
5. Read `QUICKSTART.md`, `PROJECT_MAP.md`, and `PROOF_PROVENANCE.md` before execution or evidence claims.

## Current architecture

- Claims enter through Python ingestion and portal/API helpers.
- Claim facts are resolved into canonical records and adjudicated through the rules-engine path.
- Batch construction commits to canonical claim facts, nullifiers, Merkle roots, and public inputs.
- The sealed relation under `experiments/fixed_shape_claim_air/` supplies semantic constraints and the exact hash schedule.
- `experiments/bl_pq512_crypto_core/` supplies the current Fp16/GKR/Construction-8.2 proof, authenticated public coin, independent verifier, and resource gates.
- CUDA performs untrusted arithmetic; Rust remains authoritative for parsing, commitments, transcript replay, mutation checks, and final verification.
- `app/production_boundary.py` and `app/wave5_native_boundary.py` connect the Rust receipt to the
  exact local Privacy V2 settlement and based-rollup claim context; `app/local_stack_candidate.py`
  emits only commitment/lifecycle metadata for that synthetic handoff.
- Protected Cairo code remains a differential reference. Solidity contains no production native verifier and cannot yet settle the current proof.
- Operational manifests under `ops/` pin policy and verifier artifacts.

## Target L2 architecture

Blind Ledger is an Ethereum-settled, EVM-compatible based validity rollup by compulsory design.
Ethereum provides canonical sequencing, public data availability, settlement, and finality; Blind
Ledger claim proofs verify inside the L2; a rollup validity proof authenticates the resulting L2
state transition on Ethereum L1. Patient and claim records remain in government-controlled
encrypted storage and are represented publicly only by commitments.

The target production L2 is not yet deployed. The repository now contains a local/synthetic
based-rollup boundary plus a native claim adapter and exact local Privacy V2 settlement seam, but it
has no deployed production `INativeStarkVerifier`; the protected V1 Solidity path still has its
caller-supplied public-input schema and remains outside this local change. See
`docs/BASED_ZK_ROLLUP_ARCHITECTURE.md` and `KNOWN_ISSUES.md`.

Government APIs, oracles, KMS/HSMs, governance, and payment systems are integrated through
versioned provider-neutral adapters. The finished release must include local simulators, sandbox
fixtures, and conformance tests; live endpoints, credentials, key handles, signers, and accounts are
operator activation inputs, not unfinished engineering.

Generated build/proof outputs are not included in this archive.
