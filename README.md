# Blind Ledger app layer

For the current clean task transfer, start with `WAVE2_HANDOFF_2026-07-26.md`. It records the exact
verified Wave 2 boundary, external artifact digests, dirty-tree status, source reading order, and
smallest safe resume sequence. Do not restore older browser/PDF state or infer a complete proof from
the interrupted GPU-PCS run.

Blind Ledger is a zero-knowledge payment-system prototype with a Python app layer, Rust policy/rules engine, Cairo proof circuit, and Solidity verifier/settlement code.

The complete product roadmap is internally finishable: **6 of 93 engineering packages are complete
and 87 are open**. Current Wave 1, historically called Wave 1A, is sealed as a nonactivating
executable relation. Current Wave 2, historically called Wave 1B, is the strict-PQ proof and
throughput-recovery wave. The only external assurance dependency is one final independent Security
Audit Gate after all six internal waves. This repository is not yet a deployment-ready candidate
and real PHI/payments are forbidden. See `docs/DEPLOYMENT_READY_BUILD_CONTRACT.md` for the exact
build/audit boundary and `docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md` for the active proof/resource
plan. `docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md` is the authoritative Wave 2 architecture:
the 554-951 GB direct-SHA3-STARK layouts are retired and replaced as the implementation priority by
a shared-bus Boolean hash coprocessor, still subject to complete theorem, privacy, and K128 gates.

`docs/BL_PQ512_COMMITTED_SPARSE_STATE_PLAN.md` adds mandatory Wave 2 gate 2E: implement and select
between the existing SHA3-512 state-proof control and persistent sparse-state/dictionary/RAM
relations with separately qualified native-hiding PQ commitments. The complete K128/K512 proof is
gate 2F. No candidate is selected or activated by that plan.

`docs/FRONTIER_THROUGHPUT_AND_ETHEREUM_ALIGNMENT.md` adds the next cross-wave work: attack the
dominant state-proof cost, safely schedule independent claims, bind government/oracle evidence, and
stay compatible with Ethereum's direction. It adds no package, makes no unmeasured speed claim,
preserves strict-PQ/privacy bounds, and keeps draft EIPs optional.

This directory is the source root for day-to-day work. The archive root also contains sibling directories used by this source tree:

| Sibling path | Purpose |
| --- | --- |
| `../ops/` | Canonical policy and verifier artifacts for code paths that resolve operational files outside the app root. |
| `../third_party/forge-std/` | Vendored Forge standard library for Solidity tests. |

`ops/` inside this directory is an intentional compatibility mirror of `../ops/`. Keep the two copies byte-identical when repackaging.

## Start here

1. Read `AGENTS.md` for protected paths and trust-critical rules.
2. Read `docs/IMPLEMENTATION_ROADMAP.md`, `docs/DEPLOYMENT_READY_BUILD_CONTRACT.md`, `docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md`, `docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`, and `docs/FRONTIER_THROUGHPUT_AND_ETHEREUM_ALIGNMENT.md` for current progress, release boundaries, and active/prospective proof architecture.
3. Read `docs/BASED_ZK_ROLLUP_ARCHITECTURE.md` for the canonical target architecture and current verifier gap.
4. Read `QUICKSTART.md` for environment checks and test commands.
5. Read `PROJECT_MAP.md` for folder ownership and edit risk.
6. Read `PROOF_PROVENANCE.md` before making claims about proof artifacts.

## Current architecture

- Claims enter through Python ingestion and portal/API helpers.
- Claim facts are resolved into canonical records and adjudicated through the rules-engine path.
- Batch construction commits to canonical claim facts, nullifiers, Merkle roots, and public inputs.
- The Cairo circuit under `zk-cairo-sharp/` proves the batch computation.
- Solidity contracts under `contracts/` hold verifier/settlement-facing code.
- Operational manifests under `ops/` pin policy and verifier artifacts.

## Target L2 architecture

Blind Ledger targets an Ethereum-settled, EVM-compatible based validity rollup. Ethereum provides canonical sequencing, public data availability, settlement, and finality; Blind Ledger claim proofs verify inside the L2; a rollup validity proof authenticates the resulting L2 state transition on Ethereum L1. Patient and claim records remain in government-controlled encrypted storage and are represented publicly only by commitments.

This target is not yet implemented. The current repository has no production `INativeStarkVerifier` implementation, and the current Cairo output does not match the settlement contract's caller-supplied public-input schema. See `docs/BASED_ZK_ROLLUP_ARCHITECTURE.md` and `KNOWN_ISSUES.md`.

Government APIs, oracles, KMS/HSMs, governance, and payment systems are integrated through
versioned provider-neutral adapters. The finished release must include local simulators, sandbox
fixtures, and conformance tests; live endpoints, credentials, key handles, signers, and accounts are
operator activation inputs, not unfinished engineering.

Generated build/proof outputs are not included in this archive.
